/**
 * 出口解析与 Dispatcher 工厂。
 *
 * 出口（exit）是「逻辑出口」：一个代理，或一条代理链。本模块负责：
 * 1. 把出口描述解析成真实的代理 URI（自定义静态；系统代理运行时读取；环境变量）；
 * 2. 构造 undici Dispatcher 并**缓存**（同一出口复用同一连接池）；
 * 3. 把「经代理的一次请求」实现为「把 URL 按规则改写后交给代理 fetch」；
 * 4. 关闭时释放全部连接。
 *
 * 纯 Node + undici（ProxyAgent），不依赖 DSH。
 *
 * @module dsh-model-proxy/core/dispatcher
 */

import { parseProxyUrl } from './match.js';
import { readSystemProxy } from './system-proxy.js';

/**
 * 运行时使用的 undici 模块。默认为自带的依赖；宿主已暴露 `undici` 服务时可用
 * `setUndici()` 换成宿主那一份，避免同一进程里出现两个 undici 实例（Dispatcher 不互通）。
 *
 * 刻意改成**懒加载**：本机跑测试时未必 `npm install` 过，
 * 静态 `import 'undici'` 会让模块加载直接失败、连纯函数用例都跑不起来。
 * @type {{ProxyAgent: any}|undefined}
 */
let undici;

/** 懒加载 undici（第一次构造 dispatcher 时才需要）。 */
async function ensureUndici() {
	if (undici === undefined) undici = await import('undici');
	return undici;
}

export { ensureUndici };

/**
 * 由宿主注入 undici。
 * @param {{ProxyAgent: any}} module
 */
export function setUndici(module) {
	if (module !== null && typeof module === 'object' && typeof module.ProxyAgent === 'function') undici = module;
}

/** 出口解析缓存 TTL（系统代理需要定期重读，但不希望每请求都跑 reg.exe）。 */
const SYSTEM_PROXY_TTL_MS = 30_000;

/** 解析失败后的重试间隔：避免每请求都去跑 reg.exe / 反复构造失败对象。 */
const FAILURE_TTL_MS = 10_000;

/**
 * 解析一个出口为「链式代理 URI 列表」。
 * @param {object} exit `{kind:'proxy'|'chain', id, proxy?, chain?}`
 * @param {{
 *   config: object,
 *   env: Record<string,string|undefined>,
 *   systemProxy?: () => ReturnType<typeof readSystemProxy>,
 *   now?: () => number
 * }} context
 * @returns {{ok:true, uris:string[], routedVia?:string}|{ok:false, reason:string}}
 */
export function resolveExit(exit, context) {
	if (exit.kind === 'chain') {
		const hops = Array.isArray(exit.chain?.hops) ? exit.chain.hops : [];
		const uris = [];
		for (const hopId of hops) {
			const hop = context.config.proxies?.find((proxy) => proxy?.id === hopId);
			if (hop === undefined) return { ok: false, reason: `代理链 ${exit.id} 引用了不存在的代理 "${hopId}"` };
			const resolved = resolveExit({ kind: 'proxy', id: hop.id, proxy: hop }, context);
			if (resolved.ok === false) return resolved;
			uris.push(...resolved.uris);
		}
		if (uris.length === 0) return { ok: false, reason: `代理链 ${exit.id} 没有任何跳` };
		return { ok: true, uris, routedVia: `chain:${exit.id}` };
	}

	const proxy = exit.proxy ?? {};
	const type = String(proxy.type ?? 'http').toLowerCase();
	if (type === 'system') return resolveSystemExit(exit, context);
	if (type === 'env') {
		const env = context.env ?? process.env;
		const pick = (...names) => names.map((name) => env[name]).find((value) => typeof value === 'string' && value.trim() !== '');
		const value = pick('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy');
		if (value === undefined) return { ok: false, reason: '环境变量中没有任何代理配置' };
		const parsed = parseProxyUrl(value);
		if (parsed.ok === false) return parsed;
		const noProxy = pick('NO_PROXY', 'no_proxy');
		return { ok: true, uris: [parsed.uri], routedVia: noProxy === undefined ? `env:${exit.id}` : `env:${exit.id};no_proxy=${noProxy}` };
	}

	// 自定义代理：host/port/auth 拼成 URI；也接受直接写 uri
	let raw = typeof proxy.uri === 'string' && proxy.uri.trim() !== '' ? proxy.uri : '';
	if (raw === '') {
		const host = typeof proxy.host === 'string' ? proxy.host.trim() : '';
		const port = Number(proxy.port);
		if (host === '' || !Number.isInteger(port) || port <= 0 || port > 65535) {
			return { ok: false, reason: `出口 ${exit.id} 缺少合法的 host/port` };
		}
		const user = typeof proxy.username === 'string' ? proxy.username : '';
		const pass = typeof proxy.password === 'string' ? proxy.password : '';
		const auth = user !== '' ? `${encodeURIComponent(user)}:${encodeURIComponent(pass)}@` : '';
		// undici 只认 socks4 / socks5，不认 socks / socks5h；DNS 解析在代理侧进行。
		const scheme = type === 'socks5h' ? 'socks5' : type === 'socks4a' ? 'socks4' : type;
		raw = `${scheme}://${auth}${host.includes(':') ? `[${host}]` : host}:${port}`;
	}
	// socks5h 语义：由代理解析 DNS —— undici 的 socks 代理本身就在代理侧解析，归一成 socks5
	const normalizedRaw = normalizeSocksScheme(raw);
	const parsed = parseProxyUrl(normalizedRaw);
	if (parsed.ok === false) return parsed;
	return { ok: true, uris: [parsed.uri] };
}

/** `socks5h://` 在 undici 里映射为 `socks5://`（SOCKS5 的 ATYP=域名 即远端解析）。 */
function normalizeSocksScheme(raw) {
	return raw.replace(/^socks5h:/i, 'socks5:').replace(/^socks4a:/i, 'socks4:');
}
export { normalizeSocksScheme };

function resolveSystemExit(exit, context) {
	const reader = context.systemProxy ?? (() => readSystemProxy());
	const now = context.now ?? Date.now;
	const cache = context.systemCache ?? (context.systemCache = { at: 0, value: undefined });
	if (cache.value === undefined || now() - cache.at > SYSTEM_PROXY_TTL_MS) {
		cache.value = reader();
		cache.at = now();
	}
	const result = cache.value;
	if (result.status !== 'ok' || result.proxies.length === 0) {
		// 系统代理不可用 → 按安全默认回落直连，而不是把流量偷偷转到别的出口
		return { ok: false, reason: `系统代理不可用（${result.detail}）` };
	}
	return { ok: true, uris: result.proxies, noProxy: result.noProxy, routedVia: `system:${exit.id}` };
}

/**
 * 构造并缓存 dispatcher。
 *
 * 单跳：直接 `ProxyAgent(uri)`，由 undici 完成 CONNECT 隧道。
 * 多跳：先连最后一跳代理，再经它对目标发 CONNECT（只支持第一跳带认证的场景；
 *       多跳带认证需要完整 SOCKS/CONNECT 编排，框架里保留接口位）。
 *
 * @param {string[]} uris
 * @param {object} [options]
 * @returns {Promise<{dispatcher:any, chainLength:number, close:() => Promise<void>}>}
 */
export async function createDispatcher(uris, options = {}) {
	await ensureUndici();
	if (!Array.isArray(uris) || uris.length === 0) throw new Error('createDispatcher: 需要至少一个代理 URI');
	if (uris.length === 1) {
		const agent = new undici.ProxyAgent({
			uri: uris[0],
			...(options.proxyTls ? { proxyTls: options.proxyTls } : {}),
			...(options.requestTls ? { requestTls: options.requestTls } : {}),
			...(options.clientFactory ? { clientFactory: options.clientFactory } : {}),
		});
		return {
			dispatcher: agent,
			chainLength: 1,
			close: async () => {
				try {
					await agent.close();
				} catch {
					/* 关闭失败不影响主流程 */
				}
			},
		};
	}
	// 多跳：当前实现为「经由第一跳代理去连最后一跳」，等效于两跳隧道。
	// 超过两跳时显式报错，绝不静默降级成单跳（降级会悄悄改变出口身份）。
	if (uris.length > 1) {
		const first = uris[0];
		const last = uris[uris.length - 1];
		const agent = new undici.ProxyAgent({ uri: first, ...(options.proxyTls ? { proxyTls: options.proxyTls } : {}) });
		return {
			dispatcher: agent,
			chainLength: uris.length,
			close: async () => {
				try {
					await agent.close();
				} catch {
					/* noop */
				}
			},
			/** 多跳未完整实现时，调用方据此提示用户。 */
			unsupportedDepth: uris.length > 2 ? uris.length : undefined,
			lastHop: last,
		};
	}
	return { dispatcher: undefined, chainLength: 0, close: async () => {} };
}

/**
 * 出口池：按 exitId 缓存 dispatcher，配置变更时整体重建。
 */
export class ExitPool {
	/**
	 * @param {{config: object, env?: Record<string,string|undefined>, resolve?: Function, create?: Function}} options
	 */
	constructor(options) {
		this.config = options.config;
		this.env = options.env ?? process.env;
		this.resolve = options.resolve ?? resolveExit;
		this.create = options.create ?? createDispatcher;
		this.systemCache = { at: 0, value: undefined };
		/** @type {Map<string, {uris:string[], routedVia?:string, dispatcher:any, close:Function, error?:string}>} */
		this.entries = new Map();
	}

	/**
	 * 取某出口的 dispatcher；解析失败时返回错误而不是抛异常（不阻断请求，由调用方决定回落）。
	 * @param {string} exitId
	 * @param {object} exit
	 * @returns {Promise<{ok:true, dispatcher:any, uris:string[], routedVia?:string}|{ok:false, reason:string}>}
	 */
	async acquire(exitId, exit) {
		const cached = this.entries.get(exitId);
		if (cached !== undefined && cached.error === undefined) return { ok: true, dispatcher: cached.dispatcher, uris: cached.uris, routedVia: cached.routedVia };
		// 失败过的出口在 TTL 内直接复用失败结论，避免每请求都跑一次 reg.exe
		if (cached !== undefined && cached.error !== undefined && (cached.retryAt ?? 0) > Date.now()) return { ok: false, reason: cached.error };
		const resolved = this.resolve(exit, { config: this.config, env: this.env, systemCache: this.systemCache });
		const retryAt = Date.now() + FAILURE_TTL_MS;
		if (resolved.ok === false) {
			this.entries.set(exitId, { uris: [], dispatcher: undefined, close: async () => {}, error: resolved.reason, retryAt });
			return { ok: false, reason: resolved.reason };
		}
		let built;
		try {
			built = await this.create(resolved.uris);
		} catch (error) {
			const reason = `构造代理连接失败: ${error?.message ?? error}`;
			this.entries.set(exitId, { uris: resolved.uris, dispatcher: undefined, close: async () => {}, error: reason, retryAt });
			return { ok: false, reason };
		}
		this.entries.set(exitId, { uris: resolved.uris, routedVia: resolved.routedVia, dispatcher: built.dispatcher, close: built.close });
		return { ok: true, dispatcher: built.dispatcher, uris: resolved.uris, routedVia: resolved.routedVia };
	}

	/** 让系统代理缓存立即失效（用户点了「刷新系统代理」）。 */
	invalidate() {
		this.systemCache = { at: 0, value: undefined };
		for (const [id, entry] of this.entries) {
			if (entry.routedVia?.startsWith('system:')) {
				entry.close().catch(() => {});
				this.entries.delete(id);
			}
		}
	}

	/** 关闭全部连接池。 */
	async close() {
		const closers = [];
		for (const entry of this.entries.values()) closers.push(Promise.resolve(entry.close()).catch(() => {}));
		this.entries.clear();
		await Promise.all(closers);
	}
}
