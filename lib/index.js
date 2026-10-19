/**
 * dsh-model-proxy —— DSH 模型代理插件（宿主一半）。
 *
 * 契约（对着本机 DSH 0.2.1-rc.2 上实际在跑的 @copylee/dsh-proxy@0.4.5 与
 * @linxin666/dsh-client-ui-git-graph@0.4.7 核实）：
 * - Cordis 插件：`export const name` / `export const Config` / `export function apply(ctx, config)`
 * - 设置：宿主按 `Config` schema 生成设置页；标了 `.volatile()` 的字段以**活引用**下发，
 *   用 `config.<field>.get()` 读，`ctx.on('loader/volatile-update', ...)` 接收提交。
 *   0.2.x 已移除 `settings` 服务与 `installSection`，客户端侧也没有 `settingsScope`。
 * - 路由：`ctx.inject(['webServer'], (c) => c.effect(() => c.webServer.register({ ... })))`
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

/**
 * 设置 schema：字段尽量扁平，便于设置页与本插件的校验共用一份定义。
 *
 * 每个字段都标 `.volatile()`：宿主据此把该字段以「活引用」下发给插件，设置页的
 * 写入会以 `loader/volatile-update` 事件到达，不需要重启，也不需要 `settings` 服务。
 */
export const Config = z.object({
	mode: z.union([z.const('off'), z.const('rule'), z.const('system'), z.const('custom')]).default('rule').volatile(),
	defaultAction: z.string().default('direct').volatile(),
	proxy: z.string().default('').volatile(),
	proxyUri: z.string().default('').volatile(),
	proxyType: z.union([z.const('http'), z.const('https'), z.const('socks5'), z.const('socks5h'), z.const('socks4'), z.const('socks4a')]).default('http').volatile(),
	proxyHost: z.string().default('').volatile(),
	proxyPort: z.natural().default(0).volatile(),
	proxyUser: z.string().default('').volatile(),
	proxyPassword: z.string().role('secret').default('').volatile(),
	proxyHosts: z.array(z.string()).default([]).volatile(),
	excludeHosts: z.array(z.string()).default([]).volatile(),
	allowInsecureUpstream: z.boolean().default(false).volatile(),
	extendToTools: z.boolean().default(false).volatile(),
	// 关掉插件用 `mode: 'off'`，不再单独留一个语义重复的 `enabled` 开关。
	logLevel: z.union([z.const('silent'), z.const('error'), z.const('warn'), z.const('info'), z.const('debug')]).default('info').volatile(),
});

/** `Config` 的字段名，用于过滤 `loader/volatile-update` 的路径。 */
const CONFIG_KEYS = new Set(Object.keys(Config.dict ?? {}));

/**
 * 读一个可能被宿主包装成活引用的配置字段。
 * 活引用带 `.get()`；组合层直接给的普通值原样返回。
 * @param {any} value
 * @param {any} fallback
 */
function readField(value, fallback) {
	if (value === undefined || value === null) return fallback;
	if (typeof value.get === 'function') {
		try {
			const live = value.get();
			return live === undefined || live === null ? fallback : live;
		} catch {
			return fallback;
		}
	}
	return value;
}

/**
 * 把宿主下发的行配置（活引用或普通值）摊平成一份普通设置对象，
 * 交给 `normalizeConfig`。**不读任何活引用的副作用**，纯读取。
 * @param {any} config 宿主交给 `apply` 的行配置
 */
export function readSettings(config) {
	const row = config ?? {};
	return {
		mode: readField(row.mode, 'rule'),
		defaultAction: readField(row.defaultAction, 'direct'),
		proxy: readField(row.proxy, ''),
		proxyUri: readField(row.proxyUri, ''),
		proxyType: readField(row.proxyType, 'http'),
		proxyHost: readField(row.proxyHost, ''),
		proxyPort: readField(row.proxyPort, 0),
		proxyUser: readField(row.proxyUser, ''),
		proxyPassword: readField(row.proxyPassword, ''),
		proxyHosts: readField(row.proxyHosts, []),
		excludeHosts: readField(row.excludeHosts, []),
		allowInsecureUpstream: readField(row.allowInsecureUpstream, false),
		extendToTools: readField(row.extendToTools, false),
		logLevel: readField(row.logLevel, 'info'),
	};
}

/**
 * 校验并归一化设置。**在任何写库处调用**：写坏的值不会被接受，
 * 也不会让插件在运行时出错（解析失败 → 保持直连）。
 * @param {any} raw
 * @param {{base?: object}} [options]
 */
export function assertValid(raw, options = {}) {
	const config = normalizeConfig(raw, options.base ?? DEFAULT_SAFETY);
	const problems = [];
	// 代理地址写成 `127.0.0.1:7890` 时必须同时给了协议（proxyType 或 proxy 的 scheme），
	// 否则 normalizeUriList 会把它认成 scheme=127.0.0.1 的 URL，直到 DNS 阶段才炸。
	const bareUri = typeof config.proxyUri === 'string' ? config.proxyUri.trim() : '';
	const typeDefaulted = raw?.proxyType === undefined || raw?.proxyType === null;
	// 界面只给 proxyUri 时（proxy 为空），裸 host:port + 没选协议 = 写法缺协议，
	// 按上面这条更具体的规则报错，避免同时报两条.
	const bareNeedsScheme = bareUri !== '' && !/^[a-z][a-z0-9+.-]*:\/\//i.test(bareUri) && typeDefaulted && String(config.proxy ?? '').trim() === '';
	if (bareNeedsScheme) {
		problems.push(`代理地址 "${bareUri}" 缺少协议前缀：请写成 socks5h://${bareUri} 或先选择代理协议`);
	}
	if (config.mode !== 'off') {
		if (config.mode === 'custom' && config.proxyUris.length === 0) {
			problems.push('mode=custom 需要填写代理地址（proxyUri 或 proxy）');
		}
		for (const uri of config.proxyUris) {
			if (bareNeedsScheme && uri === bareUri) continue;
			try {
				const url = new URL(uri);
				const scheme = url.protocol.replace(/:$/, '').toLowerCase();
				if (!PROXY_SCHEMES.includes(scheme)) problems.push(`代理协议 "${scheme}" 不支持；支持: ${PROXY_SCHEMES.join(', ')}`);
			} catch {
				problems.push(`代理地址 "${uri}" 不是合法 URL（需要 scheme://host:port）`);
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
 * @param {any} config 宿主解析后的行配置：`.volatile()` 字段是活引用，用 `readField` 读
 */
export function apply(ctx, config) {
	/** @type {() => object} */
	let current = () => readSettings(config);
	/** 安全常量是组合层的 base，永远不取自用户可写的行配置。 */
	const base = DEFAULT_SAFETY;
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
			// 写入时校验：0.2.x 的设置页由宿主按 schema 生成，只校验形状，
			// 业务规则（mode=custom 必须填地址等）得靠这里把关。
			assertValid(rawSettings);
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
		if (normalized.mode === 'off' || built.derived.proxies.length === 0) {
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

	// ── 设置：宿主按 Config 生成的设置页提交后，重新编译规则 ─────────
	// 0.2.x 没有 `settings` 服务，也没有 installSection：`Config` 的 `.volatile()` 字段
	// 就是设置面，提交以 `loader/volatile-update` 事件到达，值从活引用上重读。
	try {
		ctx.effect(() => {
			const dispose = ctx.on('loader/volatile-update', (paths) => {
				try {
					const touched = Array.isArray(paths) ? paths : [];
					const ours = touched.length === 0 || touched.some((path) => CONFIG_KEYS.has(String(path?.[0] ?? '')));
					if (ours) activate(current());
				} catch (error) {
					logger.warn('%s: 设置热更新失败（%s）', NS, redactMessage(error?.message ?? String(error)));
				}
			});
			return () => {
				try {
					dispose?.();
				} catch {
					/* 卸载期失败不影响主流程 */
				}
			};
		}, `${NS}: settings-committed reactivation`);
	} catch (error) {
		logger.warn('%s: 无法订阅设置热更新，改动需重启生效（%s）', NS, redactMessage(error?.message ?? String(error)));
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

	// 诊断路由：webServer 是可选服务，用 ctx.inject 声明依赖，缺了就自然不注册。
	try {
		ctx.inject(['webServer'], (serverCtx) => {
			serverCtx.effect(
				() =>
					serverCtx.webServer.register({
						kind: 'prefix',
						path: ROUTE_PATH,
						handler: (req, res) => handleDiagnostics(req, res, snapshot),
					}),
				`${NS}: diagnostics route`,
			);
		});
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
