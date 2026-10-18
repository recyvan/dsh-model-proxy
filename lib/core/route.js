/**
 * 请求路由：把 `fetch` 包装成「按决策选择 dispatcher」的 fetch。
 *
 * - 直连请求：原样交给原生 fetch，不加任何参数（零开销、零行为变化）。
 * - 代理请求：注入 `dispatcher` 后交给原生 fetch。
 * - 拒绝请求：直接抛错，不发起任何网络请求。
 * - 记录每次决策的**元数据**（出口 id / 成败 / 耗时），不记录 body、不记录 path。
 *
 * 纯 Node（依赖全局 fetch），不依赖 DSH，可单测。
 *
 * @module dsh-model-proxy/core/route
 */

import { ACTION, decide, explainDecision, urlOf } from './rules.js';

/** 捕获真实的 globalThis.fetch，避免插件自身的包装形成自引用。 */
const nativeFetch = globalThis.fetch;

/** 健康统计：滑动窗口里只存计数，不存请求内容。 */
export class HealthTracker {
	/**
	 * @param {{windowMs?:number, failoverAfter?:number, cooldownMs?:number}} [options]
	 */
	constructor(options = {}) {
		this.windowMs = options.windowMs ?? 300_000;
		this.failoverAfter = options.failoverAfter ?? 3;
		this.cooldownMs = options.cooldownMs ?? 60_000;
		/** @type {Map<string, {results:Array<{at:number, ok:boolean}>, degradedUntil:number}>} */
		this.byExit = new Map();
	}

	/** @param {string} exitId @param {boolean} ok */
	record(exitId, ok) {
		const entry = this.byExit.get(exitId) ?? { results: [], degradedUntil: 0 };
		const now = Date.now();
		entry.results.push({ at: now, ok });
		entry.results = entry.results.filter((item) => now - item.at <= this.windowMs);
		if (!ok) {
			const tail = entry.results.slice(-this.failoverAfter);
			if (tail.length === this.failoverAfter && tail.every((item) => item.ok === false)) entry.degradedUntil = now + this.cooldownMs;
		} else {
			entry.degradedUntil = 0;
		}
		this.byExit.set(exitId, entry);
	}

	/** @param {string} exitId */
	isDegraded(exitId) {
		const entry = this.byExit.get(exitId);
		if (entry === undefined) return false;
		if (entry.degradedUntil === 0) return false;
		if (Date.now() > entry.degradedUntil) {
			entry.degradedUntil = 0;
			return false;
		}
		return true;
	}

	/** 导出只含计数的摘要（**不含**任何主机名/路径）。 */
	summary() {
		const out = {};
		for (const [exitId, entry] of this.byExit) {
			const total = entry.results.length;
			const failures = entry.results.filter((item) => item.ok === false).length;
			out[exitId] = { total, failures, degraded: this.isDegraded(exitId) };
		}
		return out;
	}

	reset() {
		this.byExit.clear();
	}
}

/** 环形缓冲：只保留最近 N 条决策**元数据**。 */
export class DecisionLog {
	/** @param {number} [size] */
	constructor(size = 200) {
		this.size = size;
		this.items = [];
	}

	/** @param {{at?:number, action:string, exitId?:string, host?:string, ok?:boolean, ms?:number, because?:string, ruleIndex?:number}} item */
	push(item) {
		this.items.push({ at: item.at ?? Date.now(), ...item });
		if (this.items.length > this.size) this.items.splice(0, this.items.length - this.size);
	}

	/** @param {number} [count] */
	tail(count = 20) {
		return this.items.slice(-count);
	}

	clear() {
		this.items.length = 0;
	}
}

/**
 * 构造路由 fetch。
 *
 * @param {object} options
 * @param {() => import('./rules.js').Ruleset} options.getRuleset 每次调用取最新规则（热更新）
 * @param {import('./dispatcher.js').ExitPool} options.pool
 * @param {Function} options.originalFetch 直连用的 fetch（默认 globalThis.fetch）
 * @param {(decision:any) => string} [options.providerOf] 从 fetch 调用点推断 provider id（默认不推断）
 * @param {HealthTracker} [options.health]
 * @param {DecisionLog} [options.log]
 * @param {(event:object) => void} [options.onEvent] 结构化事件回调（宿主写日志用）
 * @returns {{\n *   fetch: (input:any, init?:any) => Promise<any>,\n *   decideOnly: (input:any) => any,\n *   health: HealthTracker,\n *   log: DecisionLog,\n *   stats: {decisions:number, proxied:number, rejected:number, failed:number, lastError?:string}\n * }}
 */
export function createRoutingFetch(options) {
	const health = options.health ?? new HealthTracker();
	const log = options.log ?? new DecisionLog();
	const originalFetch = options.originalFetch ?? globalThis.fetch;
	const providerOf = options.providerOf;
	const onEvent = options.onEvent;
	const stats = { decisions: 0, proxied: 0, rejected: 0, failed: 0, lastError: undefined };
	const pool = options.pool;
	const byExit = (ruleset, exitId) => ruleset.exits.get(exitId);

	const decideOnly = (input, providerId) => decide(input, options.getRuleset(), providerId);

	/**
	 * @param {any} input
	 * @param {any} [init]
	 */
	const routedFetch = async (input, init) => {
		stats.decisions += 1;
		const ruleset = options.getRuleset();
		let providerId;
		if (typeof providerOf === 'function') {
			try {
				providerId = providerOf(input);
			} catch {
				providerId = undefined;
			}
		}
		const decision = decide(input, ruleset, providerId);

		if (decision.action === ACTION.REJECT) {
			stats.rejected += 1;
			const error = new Error(`dsh-model-proxy 已拒绝该请求：${explainDecision(decision)}`);
			error.code = 'EMODELPROXYREJECT';
			log.push({ action: 'reject', host: decision.host, because: decision.because, ruleIndex: decision.ruleIndex, ok: false });
			emit(onEvent, { type: 'proxy:reject', decision });
			throw error;
		}

		if (decision.action === ACTION.DIRECT) {
			log.push({ action: 'direct', host: decision.host, because: decision.because, ruleIndex: decision.ruleIndex, ok: true });
			return originalFetch(input, init);
		}

		// 走出口
		const started = Date.now();
		let effectiveExitId = decision.exitId;
		let exit = byExit(ruleset, effectiveExitId);
		if (exit === undefined) {
			const error = new Error(`dsh-model-proxy: 出口 "${effectiveExitId}" 不存在，拒绝发送`);
			error.code = 'EMODELPROXYNOEXIT';
			stats.failed += 1;
			stats.lastError = error.message;
			emit(onEvent, { type: 'proxy:error', decision, reason: error.message });
			throw error;
		}

		// 熔断：该出口已降级 → 按安全默认回到直连（而不是偷偷换到别的出口）
		if (health.isDegraded(effectiveExitId)) {
			log.push({ action: 'direct', host: decision.host, because: 'failover-direct', exitId: effectiveExitId, ok: true });
			emit(onEvent, { type: 'proxy:failover', from: effectiveExitId, to: 'direct' });
			return originalFetch(input, init);
		}

		const acquired = await pool.acquire(effectiveExitId, exit);
		if (acquired.ok === false) {
			// 出口不可解析（例如系统代理被关闭）→ 回落直连，并明确记录原因
			log.push({ action: 'direct', host: decision.host, because: 'exit-unavailable', exitId: effectiveExitId, ok: true });
			emit(onEvent, { type: 'proxy:exit-unavailable', exitId: effectiveExitId, reason: acquired.reason });
			return originalFetch(input, init);
		}

		stats.proxied += 1;
		const requestInit = { ...(init ?? {}) };
		requestInit.dispatcher = acquired.dispatcher;
		try {
			// 用宿主原生 fetch 发请求：它支持非标准的 `dispatcher` 字段（DSH 同款做法），
			// 因此不需要把 undici 作为运行时依赖。
			const response = await nativeFetch(input, requestInit);
			const ms = Date.now() - started;
			health.record(effectiveExitId, response.status < 500 || response.status === 429 || response.status === 401 || response.status === 403);
			log.push({ action: 'exit', exitId: effectiveExitId, host: decision.host, because: decision.because, ruleIndex: decision.ruleIndex, ok: true, ms });
			emit(onEvent, { type: 'proxy:decision', exitId: effectiveExitId, ...metaOf(decision), ms });
			return response;
		} catch (error) {
			const ms = Date.now() - started;
			stats.failed += 1;
			stats.lastError = error?.message ?? String(error);
			health.record(effectiveExitId, false);
			log.push({ action: 'exit', exitId: effectiveExitId, host: decision.host, because: decision.because, ok: false, ms });
			emit(onEvent, { type: 'proxy:error', exitId: effectiveExitId, class: classify(error), ms });
			throw error;
		}
	};

	return { fetch: routedFetch, decideOnly, health, log, stats, urlOf };
}

function metaOf(decision) {
	return { because: decision.because, ruleIndex: decision.ruleIndex, host: decision.host, port: decision.port };
}

/** 错误分类：不把错误消息原文带进事件（消息里常含完整 URL）。 */
export function classify(error) {
	// `fetch failed` 的原始错误码在 cause 里；先取 cause 再取外层，
	// 否则最外层的 code 可能只是 `UND_ERR_*` 之类，看不出真实原因。
	const code = error?.cause?.code ?? error?.code ?? '';
	if (typeof code === 'string' && code !== '') return code;
	const message = String(error?.cause?.message ?? error?.message ?? '');
	if (/timeout|timed out|ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT/i.test(message)) return 'TIMEOUT';
	if (/certificate|self.signed|CERT_/i.test(message)) return 'CERT';
	if (/ECONNREFUSED|ECONNRESET|ENOTFOUND|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|socket hang up/i.test(message)) return 'NETWORK';
	if (/proxy/i.test(message)) return 'PROXY';
	return 'UNKNOWN';
}

function emit(onEvent, event) {
	if (typeof onEvent !== 'function') return;
	try {
		onEvent(event);
	} catch {
		/* 事件回调失败绝不影响请求 */
	}
}
