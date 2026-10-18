/**
 * 规则引擎：把一次请求的目标（URL + provider id）决策成「直连 / 走某个出口 / 拒绝」。
 *
 * 设计约束（来自框架文档）：
 * - **纯函数**：给定 URL 与已归一化的 Ruleset，输出决策与命中原因，不读环境、不发网络。
 * - **可解释**：每个决策带 `because`（命中层级）与 `index`（规则序号），供 `/model-proxy explain`。
 * - **默认安全**：强制直连网段不可被覆盖；未匹配时回落到 default，而 default 默认是 direct。
 *
 * @module dsh-model-proxy/core/rules
 */

import { compileHostSet, isAlwaysDirect, ipInCidr, normalizeHostEntry, parseCidr } from './match.js';

/** 决策动作。 */
export const ACTION = Object.freeze({ DIRECT: 'direct', REJECT: 'reject', EXIT: 'exit' });

/**
 * 把配置里的一条规则归一化。
 * 支持两种写法：
 * - `{ "match": { "type": "domain", "value": "*.openai.com" }, "action": "exitId" }`
 * - `{ "match": { "type": "suffix", "value": ".openai.com" }, "action": "direct" }`
 * action 取值：`direct` / `reject` / 一个出口（proxies[].id 或 chain[].id）。
 * @param {any} raw
 * @returns {{type:string, host?:string, regex?:RegExp, reason?:string}|undefined}
 */
export function normalizeRule(raw) {
	if (raw === null || typeof raw !== 'object') return undefined;
	const match = raw.match ?? {};
	const type = String(match.type ?? 'domain').toLowerCase();
	const value = match.value;
	const action = typeof raw.action === 'string' ? raw.action.trim() : '';
	if (action === '') return undefined;
	let compiled;
	switch (type) {
		case 'domain':
		case 'suffix':
		case 'host': {
			const normalized = normalizeHostEntry(value);
			if (normalized === undefined) return undefined;
			compiled = { host: normalized };
			break;
		}
		case 'regex': {
			if (typeof value !== 'string' || value.length === 0 || value.length > 512) return undefined;
			try {
				compiled = { regex: new RegExp(value, 'i') };
			} catch {
				return undefined;
			}
			break;
		}
		case 'cidr': {
			// CIDR 仍按网段判定；这里只接受字符串，实际比较在 isAlwaysDirect / cidr 分支完成
			if (typeof value !== 'string') return undefined;
			compiled = { host: value.trim().toLowerCase() };
			break;
		}
		default:
			return undefined;
	}
	return { type, value: typeof value === 'string' ? value : '', action, ...compiled };
}

/**
 * 编译一份配置为可复用的 Ruleset。调用方（宿主插件）在配置变更时重建一次。
 *
 * @param {object} config 已通过 schema 校验的配置
 * @param {object} [options]
 * @param {string[]} [options.disabledRuleHosts] 需要屏蔽的规则（健康检查退化用）
 * @returns {Ruleset}
 */
export function compileRuleset(config, options = {}) {
	const exits = new Map();
	for (const proxy of config.proxies ?? []) {
		if (proxy?.id) exits.set(proxy.id, { kind: 'proxy', id: proxy.id, proxy });
	}
	for (const chain of config.chains ?? []) {
		if (chain?.id) exits.set(chain.id, { kind: 'chain', id: chain.id, chain });
	}

	const rules = [];
	let index = 0;
	for (const raw of config.rules ?? []) {
		const rule = normalizeRule(raw);
		if (rule === undefined) continue;
		const action = resolveAction(rule.action, exits);
		rules.push({ ...rule, index: index++, action, raw });
	}

	const forcedDirect = compileHostSet([...(config.forceDirectHosts ?? []), ...(config.noProxy?.extra ?? [])]);
	const byProvider = new Map();
	for (const [provider, spec] of Object.entries(config.byProvider ?? {})) {
		if (spec === undefined || spec === null) continue;
		const use = typeof spec === 'string' ? spec : spec.use;
		if (typeof use !== 'string' || use.trim() === '') continue;
		byProvider.set(provider, use.trim());
	}

	return {
		mode: config.mode ?? 'rule',
		defaultAction: resolveAction(config.default ?? 'direct', exits),
		defaultExitId: defaultExitOf(config, exits),
		rules,
		exits,
		byProvider,
		forcedDirect,
		disabledRuleHosts: new Set(options.disabledRuleHosts ?? []),
		allowInsecureUpstream: config.policy?.allowInsecureUpstream === true,
		enforcedRedirects: config.enforcedRedirects ?? [],
	};
}

/**
 * system / custom 模式下的默认出口：优先 `default`，否则取第一个声明的出口。
 * @param {object} config
 * @param {Map<string, object>} exits
 */
function defaultExitOf(config, exits) {
	const resolved = resolveAction(config.default ?? '', exits);
	if (resolved.kind === ACTION.EXIT) return resolved.exitId;
	const first = exits.values().next();
	return first.done === true ? undefined : first.value.id;
}

/**
 * 把 action 文本解析成动作对象。
 * @param {string} text
 * @param {Map<string, object>} exits
 */
export function resolveAction(text, exits) {
	const value = typeof text === 'string' ? text.trim() : '';
	if (value === '') return { kind: ACTION.REJECT, reason: '空动作' };
	const lower = value.toLowerCase();
	if (lower === 'direct') return { kind: ACTION.DIRECT };
	if (lower === 'reject' || lower === 'block' || lower === 'deny') return { kind: ACTION.REJECT };
	const id = value.startsWith('proxy:') ? value.slice(6) : value;
	const exit = exits.get(id);
	if (exit === undefined) return { kind: ACTION.REJECT, reason: `未定义的出口 "${value}"` };
	return { kind: ACTION.EXIT, exitId: exit.id };
}

/**
 * 从 fetch 的 input 提取绝对 URL 字符串。兼容 string / URL / Request。
 * @param {any} input
 */
export function urlOf(input) {
	if (typeof input === 'string') return input;
	if (input instanceof URL) return input.href;
	if (input !== null && typeof input === 'object' && typeof input.url === 'string') return input.url;
	return '';
}

/**
 * 核心决策。**纯函数**。
 * @param {string|URL|Request} input
 * @param {Ruleset} ruleset
 * @param {string} [providerId] 可选的 provider 标识（来自 fetch 调用点标注）
 * @returns {{
 *   action: 'direct'|'reject'|'exit',
 *   exitId?: string,
 *   because: string,
 *   ruleIndex?: number,
 *   url?: string,
 *   host?: string,
 *   port?: number,
 *   protocol?: string,
 *   rejectReason?: string
 * }}
 */
export function decide(input, ruleset, providerId) {
	const raw = urlOf(input);
	let parsed;
	try {
		parsed = new URL(raw);
	} catch {
		// 无法解析的 URL 一律直连：不把不确定的东西送进代理
		return { action: ACTION.DIRECT, because: 'unparsable-url', url: raw };
	}
	const host = parsed.hostname.toLowerCase();
	const port = parsed.port === '' ? defaultPort(parsed.protocol) : Number(parsed.port);
	const base = { url: raw, host, port, protocol: parsed.protocol.replace(/:$/, '') };

	// 1) 插件关闭
	if (ruleset.mode === 'off') return { ...base, action: ACTION.DIRECT, because: 'mode-off' };

	// 2) 强制直连（不可覆盖）
	if (isAlwaysDirect(host)) return { ...base, action: ACTION.DIRECT, because: 'always-direct' };
	if (ruleset.forcedDirect.has(host)) return { ...base, action: ACTION.DIRECT, because: 'forced-direct' };

	// 3) 明文出站闸门：非 https 目标默认拒绝（防 API Key 明文经代理）
	if (!ruleset.allowInsecureUpstream && base.protocol !== 'https') {
		return { ...base, action: ACTION.REJECT, because: 'insecure-upstream', rejectReason: `模型请求必须走 https，收到 ${base.protocol}:` };
	}

	// 4) provider 维度覆盖
	if (typeof providerId === 'string' && providerId !== '' && ruleset.byProvider.has(providerId)) {
		const action = resolveAction(ruleset.byProvider.get(providerId), ruleset.exits);
		return finish(base, action, `provider:${providerId}`, undefined);
	}

	// 5) 规则列表（first-match wins）
	for (const rule of ruleset.rules) {
		if (ruleset.disabledRuleHosts.size > 0 && rule.host !== undefined && ruleset.disabledRuleHosts.has(rule.host)) continue;
		if (!ruleMatches(rule, host, parsed)) continue;
		return finish(base, rule.action, 'rule', rule.index);
	}

	// 6) 模式默认
	if (ruleset.mode === 'system' || ruleset.mode === 'custom') {
		return { ...base, action: ACTION.EXIT, exitId: ruleset.defaultExitId, because: `mode-${ruleset.mode}` };
	}

	// 7) rule 模式的默认动作
	return finish(base, ruleset.defaultAction, 'default', undefined);
}

function finish(base, action, because, ruleIndex) {
	if (action.kind === ACTION.DIRECT) return { ...base, action: ACTION.DIRECT, because, ruleIndex };
	if (action.kind === ACTION.EXIT) return { ...base, action: ACTION.EXIT, exitId: action.exitId, because, ruleIndex };
	return { ...base, action: ACTION.REJECT, because, ruleIndex, rejectReason: action.reason ?? '被拒绝规则命中' };
}

function ruleMatches(rule, host, parsed) {
	if (rule.regex !== undefined) return rule.regex.test(host);
	if (rule.host === undefined) return false;
	// CIDR 类型：交给 match 模块
	if (rule.type === 'cidr') {
		const cidr = parseCidr(rule.host);
		return cidr !== undefined && ipInCidr(host, cidr);
	}
	if (rule.host.startsWith('.')) {
		const domain = rule.host.slice(1);
		return host === domain || host.endsWith(`.${domain}`) || host.endsWith(`-${domain}`);
	}
	return host === rule.host;
}

function defaultPort(protocol) {
	switch (protocol) {
		case 'https:':
			return 443;
		case 'http:':
			return 80;
		case 'wss:':
			return 443;
		case 'ws:':
			return 80;
		default:
			return 0;
	}
}

/**
 * 把决策转成人类可读的一条说明（用于 explain 与日志）。
 * @param {ReturnType<typeof decide>} decision
 */
export function explainDecision(decision) {
	const target = decision.host === undefined ? decision.url ?? '(无法解析)' : `${decision.host}:${decision.port}`;
	const ruleText = decision.ruleIndex !== undefined ? ` 规则#${decision.ruleIndex}` : '';
	switch (decision.action) {
		case ACTION.DIRECT:
			return `${target} → 直连（${decision.because}${ruleText}）`;
		case ACTION.EXIT:
			return `${target} → 出口 ${decision.exitId}（${decision.because}${ruleText}）`;
		default:
			return `${target} → 拒绝（${decision.because}${ruleText}）：${decision.rejectReason ?? ''}`;
	}
}
