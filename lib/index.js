/**
 * dsh-model-proxy —— DSH 模型代理插件（宿主一半）。
 *
 * 契约（对着本机 DSH 0.2.1-rc.2 实际在跑的 dsh-http-proxy / dsh-session-pulse 核实）：
 * - Cordis 插件：`export const name` / `export function apply(ctx, config)`
 * - 设置：`ctx.inject(['settings'], (c) => c.settings.installSection(ctx, NS, Schema, base, hooks))`
 * - 路由：`ctx.webServer.register({ kind:'prefix', path, handler })` + `ctx.effect(() => dispose)`
 * - 热更新：`ctx.on('settings/updated', ...)`
 *
 * 只做两件事：
 * 1. 把 `globalThis.fetch` 换成一个「按规则选代理」的包装（直连请求原样透传给原 fetch）；
 * 2. 提供一个同源只读诊断路由，给设置页的状态面板用。
 *
 * 退出时（`ctx.effect` 的 dispose）恢复原 fetch、关闭所有连接池——不残留任何东西。
 *
 * @module dsh-model-proxy
 */

import z from '@deepseek-ai/schemastery';
import { DEFAULT_SAFETY, normalizeConfig } from './core/config.js';
import { ExitPool } from './core/dispatcher.js';
import { redactMessage } from './core/match.js';
import { defaultRulesFor, suggestedHosts } from './core/presets.js';
import { createRoutingFetch } from './core/route.js';
import { compileRuleset, explainDecision } from './core/rules.js';
import { readSystemProxy } from './core/system-proxy.js';

/** 设置命名空间（同时也是插件短名）。 */
export const NS = 'model-proxy';
export const name = 'model-proxy';
export const ROUTE_PATH = '/dsh-model-proxy';

/** 支持的代理协议（设置页 schema 与校验共用）。 */
export const PROXY_SCHEMES = ['http', 'https', 'socks', 'socks4', 'socks4a', 'socks5', 'socks5h'];

/** 设置 schema：字段尽量扁平，便于设置页与本插件的校验共用一份定义。 */
export const Config = z.object({
	mode: z.union([z.const('off'), z.const('rule'), z.const('system'), z.const('custom')]).default('rule'),
	defaultAction: z.string().default('direct'),
	proxy: z.string().default(''),
	proxyUri: z.string().default(''),
	proxyType: z.union([z.const('http'), z.const('https'), z.const('socks5'), z.const('socks5h'), z.const('socks4'), z.const('socks4a')]).default('http'),
	proxyHost: z.string().default(''),
	proxyPort: z.natural().default(0),
	proxyUser: z.string().default(''),
	proxyPassword: z.string().role('secret').default(''),
	proxyHosts: z.array(z.string()).default([]),
	excludeHosts: z.array(z.string()).default([]),
	allowInsecureUpstream: z.boolean().default(false),
	extendToTools: z.boolean().default(false),
	enabled: z.boolean().default(true),
});

/**
 * 校验并归一化设置。**在任何写库处调用**：写坏的值不会被接受，
 * 也不会让插件在运行时出错（解析失败 → 保持直连）。
 * @param {any} raw
 * @param {{base?: object}} [options]
 */
export function assertValid(raw, options = {}) {
	const config = normalizeConfig(raw, options.base ?? DEFAULT_SAFETY);
	const problems = [];
	if (config.mode !== 'off') {
		if (config.mode === 'custom' && config.proxyUris.length === 0) {
			problems.push('mode=custom 需要填写代理地址（proxyUri 或 proxy）');
		}
		for (const uri of config.proxyUris) {
			try {
				const url = new URL(uri);
				const scheme = url.protocol.replace(/:$/, '').toLowerCase();
				if (!PROXY_SCHEMES.includes(scheme)) problems.push(`代理协议 "${scheme}" 不支持；支持: ${PROXY_SCHEMES.join(', ')}`);
			} catch {
				problems.push('代理地址不是合法 URL');
			}
		}
		for (const host of config.forceProxyHosts) {
			if (!isPlausibleHostEntry(host)) problems.push(`代理域名 "${host}" 不合法`);
		}
	}
	if (problems.length > 0) throw new Error(`${NS}: ${problems.join('；')}`);
	return config;
}

function isPlausibleHostEntry(entry) {
	if (typeof entry !== 'string') return false;
	const text = entry.trim();
	if (text.length === 0 || text.length > 253) return false;
	return /^[*.a-z0-9_:/\-\[\]]+$/i.test(text);
}

/**
 * 从设置值构造本插件的运行时配置（携带安全常量）。
 * @param {object} raw 设置值
 * @param {object} base 组合层的 base 配置（cordis.patch.yml 里可给）
 */
export function runtimeConfig(raw, base) {
	return normalizeConfig(raw, base);
}

/**
 * 把设置值编译成「一条代理出口 + 一套规则」。
 * 设置页的字段是扁平的：一个代理 + 要代理的域名 / 排除的域名。
 * 这等价于完整配置里的 proxies[0] + rules，从而让 UI 极简、能力不打折。
 * @param {object} config
 */
export function deriveFromSettings(config) {
	/** @type {object[]} */
	const proxies = [];
	if (config.mode === 'system') {
		proxies.push({ id: 'system', type: 'system', label: '系统代理' });
	} else if (config.mode === 'custom') {
		const proxy = {
			id: 'custom',
			type: config.proxyType === 'socks' ? 'socks5' : config.proxyType,
		};
		if (config.proxyUri !== '') Object.assign(proxy, { uri: config.proxyUri });
		else Object.assign(proxy, { host: config.proxyHost, port: config.proxyPort });
		if (config.proxyUser !== '') Object.assign(proxy, { username: config.proxyUser, password: config.proxyPassword });
		proxies.push(proxy);
	} else if (config.mode === 'rule') {
		// rule 模式下代理来源：显式代理地址，否则系统代理
		if (config.proxyUris.length > 0 || config.proxyHost !== '') {
			const proxy = { id: 'route', type: config.proxyType === 'socks' ? 'socks5' : config.proxyType };
			if (config.proxyUri !== '') Object.assign(proxy, { uri: config.proxyUri });
			else Object.assign(proxy, { host: config.proxyHost, port: config.proxyPort });
			if (config.proxyUser !== '') Object.assign(proxy, { username: config.proxyUser, password: config.proxyPassword });
			proxies.push(proxy);
		} else {
			proxies.push({ id: 'system', type: 'system', label: '系统代理' });
		}
	}
	const exitId = proxies[0]?.id ?? 'system';

	// 规则：显式规则优先；没填任何规则时用预设（境外模型走代理、国内直连）
	const rules = [];
	const excluded = new Set(config.excludeHosts.map((host) => host.toLowerCase()));
	for (const host of config.excludeHosts) {
		rules.push({ match: { type: normalizeEntryType(host), value: host }, action: 'direct' });
	}
	const explicit = config.forceProxyHosts.filter((host) => !excluded.has(host.toLowerCase()));
	if (explicit.length > 0) {
		for (const host of explicit) rules.push({ match: { type: normalizeEntryType(host), value: host }, action: exitId });
	} else {
		for (const rule of defaultRulesFor(exitId)) {
			const value = String(rule.match.value).toLowerCase().replace(/^\./, '');
			if (excluded.has(value)) continue;
			rules.push(rule);
		}
	}

	return {
		mode: config.mode === 'rule' ? 'rule' : config.mode,
		default: config.defaultAction || 'direct',
		proxies,
		chains: [],
		rules,
		byProvider: config.byProvider,
		forceDirectHosts: config.forceDirectHosts,
		noProxy: { extra: config.noProxyExtra },
		policy: { allowInsecureUpstream: config.allowInsecureUpstream, logLevel: config.logLevel },
		enforcedRedirects: config.enforcedRedirects,
		/** 供诊断页展示 */
		meta: { exitId, proxyCount: proxies.length, ruleCount: rules.length, usedPreset: explicit.length === 0 },
	};
}

function normalizeEntryType(host) {
	return host.trim().startsWith('*') || host.trim().startsWith('.') ? 'suffix' : 'domain';
}

/**
 * Cordis 入口。
 * @param {any} ctx Cordis 上下文
 * @param {any} config 组合层配置（cordis.patch.yml 的 config，通常为空）
 */
export function apply(ctx, config) {
	/** @type {() => object} */
	let current = () => config ?? {};
	const base = config ?? {};
	let disposed = false;

	const originalFetch = globalThis.fetch;
	let active;
	/** 最近一次自检/运行状态（诊断页读取） */
	const status = {
		path: 'A',
		active: false,
		mode: 'off',
		exitId: undefined,
		usedPreset: false,
		ruleCount: 0,
		since: undefined,
		lastError: undefined,
		lastSelfCheck: undefined,
		watchedFetch: false,
	};
	let warnings = [];

	const logger = safeLogger(ctx);

	const build = (rawSettings) => {
		const normalized = normalizeConfig(rawSettings, base);
		const derived = deriveFromSettings(normalized);
		const ruleset = compileRuleset(derived);
		const pool = new ExitPool({ config: derived });
		const routing = createRoutingFetch({
			getRuleset: () => ruleset,
			pool,
			originalFetch,
			onEvent: (event) => logEvent(logger, normalized, event),
		});
		return { normalized, derived, ruleset, pool, routing };
	};

	const deactivate = () => {
		if (active === undefined) return;
		const previous = active;
		active = undefined;
		if (revealedFetch !== undefined) globalThis.fetch = revealedFetch;
		status.active = false;
		status.exitId = undefined;
		previous.pool.close().catch(() => {});
	};

	/** 「真直连」的 fetch：第一次启用时锁定，之后所有切换都回到它。 */
	let revealedFetch;

	const activate = (rawSettings) => {
		if (disposed) return;
		let built;
		try {
			// 全新一切：上一轮的规则集/连接池在切换成功后才释放
			built = build(rawSettings);
		} catch (error) {
			// 配置坏了 → 绝不阻断 DSH：保持原状（无则直连），把原因记下来
			status.lastError = redactMessage(error?.message ?? String(error));
			status.lastSelfCheck = { at: Date.now(), ok: false, error: status.lastError };
			logger.warn(`%s: 配置无效，保持当前状态（%s）`, NS, status.lastError);
			return;
		}
		const { normalized } = built;
		if (!normalized.enabled || normalized.mode === 'off' || built.derived.proxies.length === 0) {
			deactivate();
			status.mode = normalized.mode;
			status.lastError = undefined;
			status.lastSelfCheck = { at: Date.now(), ok: true, note: 'disabled' };
			return;
		}
		// 锁定"真直连"的 fetch：只在第一次启用时记录
		if (revealedFetch === undefined) revealedFetch = originalFetch;
		const previous = active;
		active = built;
		globalThis.fetch = built.routing.fetch;
		status.active = true;
		status.mode = normalized.mode;
		status.exitId = built.derived.meta.exitId;
		status.usedPreset = built.derived.meta.usedPreset;
		status.ruleCount = built.derived.meta.ruleCount;
		status.since = Date.now();
		status.lastError = undefined;
		status.lastSelfCheck = { at: Date.now(), ok: true };
		warnings = collectWarnings(normalized, built);
		if (previous !== undefined) previous.pool.close().catch(() => {});
		logger.info(
			'%s: 已启用（模式=%s，出口=%s，规则 %d 条%s）',
			NS,
			normalized.mode,
			status.exitId,
			status.ruleCount,
			status.usedPreset ? '，使用内置预设' : '',
		);
		for (const warning of warnings) logger.warn('%s: %s', NS, warning);
	};

	// ── 启动：先自检，再启用 ──────────────────────────────────
	status.watchedFetch = typeof originalFetch === 'function';
	if (!status.watchedFetch) {
		status.path = 'B';
		status.lastError = '当前运行时没有全局 fetch，无法按 Path A 拦截';
		logger.warn('%s: %s', NS, status.lastError);
	} else {
		activate(current());
	}

	ctx.effect(() => () => {
		disposed = true;
		deactivate();
	}, `${NS}: fetch routing`);

	// ── 设置接入（没有 settings 服务的部署自动跳过） ─────────────
	try {
		ctx.inject(['settings'], (settingsCtx) => {
			try {
				settingsCtx.settings.installSection(ctx, NS, Config, base, {
					setSource: (source) => {
						current = source;
					},
					onChange: () => activate(current()),
					validate: (value) => assertValid(value, { base }),
				});
				settingsCtx.on('settings/updated', (namespace) => {
					if (String(namespace) === NS) activate(current());
				});
			} catch (error) {
				status.lastError = redactMessage(error?.message ?? String(error));
				logger.warn('%s: 设置服务接入失败，改用组合层配置（%s）', NS, status.lastError);
			}
		});
	} catch (error) {
		logger.warn('%s: settings 服务不可用（%s）', NS, redactMessage(error?.message ?? String(error)));
	}

	// ── 同源只读诊断路由 ────────────────────────────────────
	/** 诊断快照：**不含**任何域名、URL、凭据。 */
	const snapshot = () => {
		const built = active;
		return {
			ok: true,
			status: {
				...status,
				lastError: status.lastError === undefined ? undefined : redactMessage(status.lastError),
			},
			mode: status.mode,
			exitId: status.exitId,
			warnings,
			health: built === undefined ? {} : built.routing.health.summary(),
			stats: built === undefined ? { decisions: 0, proxied: 0, rejected: 0, failed: 0 } : built.routing.stats,
			progress: {
				active: status.active,
				preset: status.usedPreset ? 'overseas-via-proxy' : 'custom-rules',
				ruleCount: status.ruleCount,
			},
			diagnostics: {
				systemProxy: (() => {
					const result = readSystemProxy();
					return { status: result.status, detail: result.detail };
				})(),
				path: status.path,
				node: process.versions?.node ?? '',
			},
			suggestions: suggestedHosts(),
		};
	};

	try {
		ctx.effect(
			() =>
				ctx.webServer.register({
					kind: 'prefix',
					path: ROUTE_PATH,
					handler: (req, res) => handleDiagnostics(req, res, snapshot),
				}),
			`${NS}: diagnostics route`,
		);
	} catch (error) {
		logger.warn('%s: webServer 不可用，诊断页关闭（%s）', NS, redactMessage(error?.message ?? String(error)));
	}
}

// ── 诊断路由 ────────────────────────────────────────────────────

function isLoopbackHostname(hostname) {
	if (hostname === 'localhost' || hostname === '[::1]') return true;
	const parts = hostname.split('.');
	return parts.length === 4 && parts[0] === '127' && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

/** 与 DSH 其它插件同款：只接受同源/回环请求。 */
export function isTrustedRequest(req) {
	const hostHeader = req?.headers?.host;
	if (typeof hostHeader !== 'string' || hostHeader === '') return false;
	let hostUrl;
	try {
		hostUrl = new URL(`http://${hostHeader}`);
	} catch {
		return false;
	}
	if (!isLoopbackHostname(hostUrl.hostname)) return false;
	const origin = req?.headers?.origin;
	if (typeof origin === 'string' && origin !== 'null') {
		try {
			if (new URL(origin).host !== hostUrl.host) return false;
		} catch {
			return false;
		}
	}
	return true;
}

/**
 * 处理诊断请求。只有 `GET <ROUTE_PATH>/status` 一个只读端点。
 * @param {any} req
 * @param {any} res
 * @param {() => object} snapshot
 */
export function handleDiagnostics(req, res, snapshot) {
	const send = (code, body) => {
		res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
		res.end(JSON.stringify(body));
	};
	if (!isTrustedRequest(req)) {
		send(403, { ok: false, error: 'forbidden' });
		return;
	}
	if (req.method !== 'GET') {
		send(405, { ok: false, error: 'method not allowed' });
		return;
	}
	let pathname = '';
	try {
		pathname = new URL(req.url ?? '/', 'http://x').pathname;
	} catch {
		pathname = '';
	}
	const endpoint = pathname.slice(ROUTE_PATH.length).replace(/^\/+/, '');
	if (endpoint !== 'status') {
		send(404, { ok: false, error: 'not found' });
		return;
	}
	try {
		send(200, snapshot());
	} catch (error) {
		send(500, { ok: false, error: redactMessage(error?.message ?? String(error)) });
	}
}

// ── 辅助 ────────────────────────────────────────────────────────

function safeLogger(ctx) {
	const logger = ctx?.logger;
	const wrap = (level) => (message, ...args) => {
		try {
			if (typeof logger?.[level] === 'function') logger[level](message, ...args);
		} catch {
			/* 日志失败不影响主流程 */
		}
	};
	return { info: wrap('info'), warn: wrap('warn'), debug: wrap('debug'), error: wrap('error') };
}

function collectWarnings(config, built) {
	const out = [];
	if (config.policy.allowInsecureUpstream) out.push('已允许明文 http 目标经代理：API Key 将以明文经过代理，仅在你清楚风险时使用');
	if (config.policy.logLevel === 'debug') out.push('日志级别为 debug：会记录目标主机名');
	if (built.derived.meta.usedPreset) out.push('未填写「只代理这些域名」，正在使用内置预设（境外模型域名走代理、国内直连）');
	if (config.mode === 'custom' && built.derived.proxies[0]?.type === 'http' && String(built.derived.proxies[0]?.uri ?? '').startsWith('http://')) {
		out.push('代理本身是明文 http：到代理这一跳未加密，建议使用 https 或 socks5 代理');
	}
	return out;
}

function logEvent(logger, config, event) {
	const level = config.policy?.logLevel ?? 'info';
	if (level === 'off') return;
	if (event.type === 'proxy:error') {
		logger.warn('%s: 代理错误 exit=%s class=%s', NS, event.exitId ?? '-', event.class ?? 'UNKNOWN');
		return;
	}
	if (event.type === 'proxy:decision' || event.type === 'proxy:failover' || event.type === 'proxy:exit-unavailable') {
		if (level !== 'debug') return;
		logger.debug('%s: %s %s', NS, event.type, redactMessage(JSON.stringify(event)));
	}
}

export { explainDecision };
