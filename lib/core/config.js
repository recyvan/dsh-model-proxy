/**
 * 配置归一化。**所有入口都经过这里**（设置页写入、组合层 base 配置、热更新）。
 *
 * 关键规则（对应安全文档的「防线 0」）：
 * - `forceDirectHosts` / `noProxy.extra` 只能**追加**，永远不会移除强制直连项；
 * - `enforcedRedirects` 由插件内部注入，忽略用户配置中的同名键，防止规则被整体劫持；
 * - 任何字段类型不对 → 回落到安全默认，而不是抛错让插件整个挂掉。
 *
 * @module dsh-model-proxy/core/config
 */

import { ALWAYS_DIRECT_CIDRS, ALWAYS_DIRECT_SUFFIXES } from './match.js';

/** 不可覆盖的安全常量。 */
export const DEFAULT_SAFETY = Object.freeze({
	/** 强制直连后缀（只增不减） */
	forceDirectSuffixes: ALWAYS_DIRECT_SUFFIXES,
	/** 强制直连网段（只增不减） */
	forceDirectCidrs: ALWAYS_DIRECT_CIDRS,
	/** 插件内部注入的重定向（用户配置无法移除） */
	enforcedRedirects: ['console.anthropic.com', 'api.anthropic.com/oauth/token'],
	/** 默认日志级别：只记出口与成败，不记域名 */
	logLevel: 'info',
});

const MODES = new Set(['off', 'rule', 'system', 'custom']);

/**
 * 把任意输入归一化成「扁平设置」结构。
 * @param {any} raw
 * @param {object} [base] 组合层配置（cordis.patch.yml 的 config）
 * @returns {{
 *   enabled:boolean, mode:'off'|'rule'|'system'|'custom', defaultAction:string,
 *   proxy:string, proxyUri:string, proxyType:string, proxyHost:string, proxyPort:number,
 *   proxyUser:string, proxyPassword:string, proxyUris:string[],
 *   forceProxyHosts:string[], excludeHosts:string[],
 *   forceDirectHosts:string[], noProxyExtra:string[],
 *   byProvider:Record<string,string>, enforcedRedirects:Array,
 *   policy:{allowInsecureUpstream:boolean, logLevel:string, logHeaders:boolean},
 *   extendToTools:boolean
 * }}
 */
export function normalizeConfig(raw, base = DEFAULT_SAFETY) {
	const source = raw !== null && typeof raw === 'object' ? raw : {};
	const pick = (...keys) => {
		for (const key of keys) {
			if (source[key] !== undefined && source[key] !== null) return source[key];
		}
		return undefined;
	};
	const strings = (...keys) => {
		const value = pick(...keys);
		if (Array.isArray(value)) return value.filter((item) => typeof item === 'string' && item.trim() !== '').map((item) => item.trim());
		if (typeof value === 'string' && value.trim() !== '') return value.split(/[,\s]+/).filter(Boolean);
		return [];
	};

	const modeRaw = String(pick('mode') ?? 'rule').toLowerCase();
	const mode = MODES.has(modeRaw) ? modeRaw : 'rule';
	const proxyTypeRaw = String(pick('proxyType') ?? 'http').toLowerCase();
	const proxyType = proxyTypeRaw === 'socks' ? 'socks5' : proxyTypeRaw;

	const proxyUri = typeof pick('proxyUri') === 'string' ? pick('proxyUri').trim() : '';
	const proxyHost = typeof pick('proxyHost') === 'string' ? pick('proxyHost').trim() : '';
	const proxyPort = Number(pick('proxyPort') ?? 0);

	// proxy 与 proxyUri 是同一件事的两个入口；proxy 支持多个（逗号分隔），用于简单故障切换
	const rawProxyList = typeof pick('proxy') === 'string' ? pick('proxy').trim() : '';
	const proxyUris = normalizeUriList(rawProxyList, proxyUri, proxyType, proxyHost, proxyPort);

	const forceDirectHosts = [...new Set([...strings('forceDirectHosts'), ...(base.forceDirectSuffixes ?? []), ...(base.forceDirectCidrs ?? [])])];
	const noProxyExtra = [...new Set(strings('noProxyExtra', 'noProxy'))];

	const allowInsecureUpstream = pick('allowInsecureUpstream') === true;

	return {
		enabled: pick('enabled') !== false,
		mode,
		defaultAction: typeof pick('defaultAction') === 'string' && pick('defaultAction').trim() !== '' ? pick('defaultAction').trim() : 'direct',
		proxy: rawProxyList,
		proxyUri,
		proxyType,
		proxyHost,
		proxyPort: Number.isInteger(proxyPort) && proxyPort >= 0 && proxyPort <= 65535 ? proxyPort : 0,
		proxyUser: typeof pick('proxyUser') === 'string' ? pick('proxyUser') : '',
		proxyPassword: typeof pick('proxyPassword') === 'string' ? pick('proxyPassword') : '',
		proxyUris,
		forceProxyHosts: strings('proxyHosts', 'forceProxyHosts'),
		excludeHosts: strings('excludeHosts'),
		forceDirectHosts,
		noProxyExtra,
		byProvider: normalizeByProvider(pick('byProvider')),
		enforcedRedirects: Array.isArray(base.enforcedRedirects) ? base.enforcedRedirects : DEFAULT_SAFETY.enforcedRedirects,
		policy: {
			allowInsecureUpstream,
			logLevel: normalizeLogLevel(pick('logLevel') ?? base.logLevel ?? DEFAULT_SAFETY.logLevel),
			logHeaders: false,
		},
		extendToTools: pick('extendToTools') === true,
	};
}

function normalizeUriList(rawProxyList, proxyUri, proxyType, proxyHost, proxyPort) {
	const uris = [];
	if (proxyUri !== '') uris.push(proxyUri);
	if (rawProxyList !== '') {
		for (const part of rawProxyList.split(/[,\s]+/)) {
			const uri = part.trim();
			if (uri === '') continue;
			if (!uris.includes(uri)) uris.push(/^[a-z][a-z0-9+.-]*:\/\//i.test(uri) ? uri : `${schemeOf(proxyType)}://${uri}`);
		}
	}
	if (uris.length === 0 && proxyHost !== '' && proxyPort > 0) {
		uris.push(`${schemeOf(proxyType)}://${proxyHost}:${proxyPort}`);
	}
	return uris;
}

function schemeOf(proxyType) {
	switch (proxyType) {
		case 'socks5':
		case 'socks5h':
			return 'socks5';
		case 'socks4':
		case 'socks4a':
			return 'socks4';
		case 'https':
			return 'https';
		default:
			return 'http';
	}
}

function normalizeByProvider(value) {
	const out = {};
	if (value === null || typeof value !== 'object') return out;
	for (const [key, spec] of Object.entries(value)) {
		if (typeof spec === 'string' && spec.trim() !== '') out[key] = spec.trim();
		else if (spec !== null && typeof spec === 'object' && typeof spec.use === 'string' && spec.use.trim() !== '') out[key] = spec.use.trim();
	}
	return out;
}

function normalizeLogLevel(value) {
	const text = String(value).toLowerCase();
	return ['off', 'error', 'info', 'debug'].includes(text) ? text : 'info';
}

/**
 * 构造一份可直接交给 `compileRuleset` 的完整配置（高级用法：脚本/测试直接调）。
 * @param {object} settings
 * @param {object} [base]
 */
export function buildDefaultConfig(settings = {}, base = DEFAULT_SAFETY) {
	return normalizeConfig(settings, base);
}
