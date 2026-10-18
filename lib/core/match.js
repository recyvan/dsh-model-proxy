/**
 * 纯逻辑：主机匹配、网段判定、代理 URL 解析、脱敏、系统代理读取。
 *
 * 本模块**不依赖 DSH**，只依赖 Node 内置模块（以及可选注入的 execSync），
 * 因此可以脱离宿主单独跑测试（见 test/run-all.mjs）。
 *
 * @module dsh-model-proxy/core
 */

// ── 域名 / 主机条目 ────────────────────────────────────────────────

/**
 * 把用户填的一条主机条目规范成匹配用的形式。接受：
 * - 纯域名 `api.openai.com`
 * - `域名:端口`（端口丢弃，本插件不按端口分流）
 * - 完整 URL（取其 hostname）
 * - 通配/后缀 `*.openai.com` 或 `.openai.com` → 统一存成 `.openai.com`
 * - IPv4 / IPv6 字面量（IPv6 去掉方括号）
 * @param {unknown} entry 原始条目
 * @returns {string|undefined} 规范化结果；空或非法返回 undefined
 */
export function normalizeHostEntry(entry) {
	if (typeof entry !== 'string') return undefined;
	const trimmed = entry.trim().toLowerCase();
	if (trimmed.length === 0) return undefined;
	// 完整 URL
	if (/^[a-z][a-z0-9+.-]*:\/\//.test(trimmed)) {
		try {
			return stripPort(new URL(trimmed).hostname);
		} catch {
			return undefined;
		}
	}
	let bare = trimmed;
	// 去掉路径部分（只处理非 IPv6 情形）
	if (!bare.startsWith('[') && bare.includes('/')) bare = bare.split('/')[0];
	// 后缀 / 通配条目先判：`.example.com` 或 `*.example.com` → 统一成 `.example.com`
	if (bare.startsWith('*.')) {
		const domain = bare.slice(2);
		return domain.length > 0 && !domain.startsWith('.') ? `.${domain}` : undefined;
	}
	if (bare.startsWith('.')) {
		const domain = bare.slice(1);
		return domain.length > 0 && !domain.startsWith('.') ? `.${domain}` : undefined;
	}
	// IPv6 字面量：去掉方括号（判定网段时用）
	if (bare.startsWith('[')) {
		const close = bare.indexOf(']');
		return close > 0 ? bare.slice(1, close) : undefined;
	}
	// host:port（恰好一个冒号时视为端口；多个冒号 = 裸 IPv6）
	const colons = bare.split(':').length - 1;
	if (colons === 1) bare = bare.split(':')[0];
	if (bare.endsWith('.')) bare = bare.slice(0, -1);
	return bare.length > 0 ? bare : undefined;
}
function stripPort(hostname) {
	if (hostname.startsWith('[')) {
		const close = hostname.indexOf(']');
		return close > 0 ? hostname.slice(1, close) : hostname;
	}
	return hostname;
}

/**
 * 一个条目是否匹配给定主机名。
 * 后缀条目（以 `.` 开头）同时匹配裸域、子域与连字符拼接的区域化主机
 * （如 `us-central1-aiplatform.googleapis.com`），与 dsh-http-proxy 的行为一致。
 *
 * 入参可以是**原始条目**（`*.openai.com`、`https://api.x.com/path`）或已规范化的条目，
 * 函数自己会先规范化，避免调用方漏掉这一步导致静默不匹配。
 * @param {string} hostname 小写主机名
 * @param {string} entry 原始或规范化条目
 */
export function hostMatches(hostname, entry) {
	const normalized = normalizeHostEntry(String(entry ?? ''));
	if (normalized === undefined) return false;
	const h = stripPort(String(hostname ?? '').toLowerCase());
	if (h === '') return false;
	if (normalized.startsWith('.')) {
		const domain = normalized.slice(1);
		return h === domain || h.endsWith(`.${domain}`) || h.endsWith(`-${domain}`);
	}
	return h === normalized;
}

/** 把一组条目编译成判定器。 */
export function compileHostSet(entries) {
	const hosts = new Set();
	for (const entry of entries ?? []) {
		const normalized = normalizeHostEntry(entry);
		if (normalized !== undefined) hosts.add(normalized);
	}
	return {
		hosts,
		has(hostname) {
			if (hostname === '') return false;
			const h = stripPort(hostname.toLowerCase());
			if (hosts.has(h)) return true;
			for (const entry of hosts) {
				if (entry.startsWith('.') && hostMatches(h, entry)) return true;
			}
			return false;
		},
	};
}

// ── 网段（强制直连 / SSRF 防护） ──────────────────────────────────

/** 永远不可覆盖的直连域名（RFC 私有域 + 本机名）。 */
export const ALWAYS_DIRECT_SUFFIXES = ['.local', '.lan', '.internal', '.home', '.corp', '.localdomain', '.test', '.invalid', '.example'];

/** 永远不可覆盖的直连网段（IPv4 + IPv6 私有/环回/链路本地/组播/保留）。 */
export const ALWAYS_DIRECT_CIDRS = [
	'0.0.0.0/8',
	'10.0.0.0/8',
	'100.64.0.0/10',
	'127.0.0.0/8',
	'169.254.0.0/16',
	'172.16.0.0/12',
	'192.0.0.0/24',
	'192.168.0.0/16',
	'198.18.0.0/15',
	'224.0.0.0/4',
	'240.0.0.0/4',
	'::1/128',
	'::/128',
	'fc00::/7',
	'fe80::/10',
	'ff00::/8',
];

/**
 * IPv4 点分十进制 → 32 位整数；非法返回 undefined。
 * @param {string} ip
 */
export function ipv4ToInt(ip) {
	const parts = ip.split('.');
	if (parts.length !== 4) return undefined;
	let out = 0;
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return undefined;
		const n = Number(part);
		if (n > 255) return undefined;
		out = (out << 8) | n;
	}
	return out >>> 0;
}

/** IPv6 → 16 字节数组；非法返回 undefined。支持 `::` 压缩与内嵌 IPv4。 */
export function ipv6ToBytes(ip) {
	let text = ip.toLowerCase();
	// 去掉 zone id
	const zone = text.indexOf('%');
	if (zone >= 0) text = text.slice(0, zone);
	// 内嵌 IPv4：a:b:c:d:e:f:1.2.3.4
	const lastColon = text.lastIndexOf(':');
	if (text.includes('.') && lastColon >= 0) {
		const v4 = ipv4ToInt(text.slice(lastColon + 1));
		if (v4 === undefined) return undefined;
		const hi = ((v4 >>> 16) & 0xffff).toString(16);
		const lo = (v4 & 0xffff).toString(16);
		text = `${text.slice(0, lastColon + 1)}${hi}:${lo}`;
	}
	const halves = text.split('::');
	if (halves.length > 2) return undefined;
	const parseGroup = (segment) => (segment === '' ? [] : segment.split(':'));
	let head = parseGroup(halves[0]);
	let tail = halves.length === 2 ? parseGroup(halves[1]) : [];
	if (halves.length === 1) {
		if (head.length !== 8) return undefined;
	} else {
		if (head.length + tail.length > 7) return undefined;
		head = [...head, ...new Array(8 - head.length - tail.length).fill('0'), ...tail];
		tail = [];
	}
	const groups = head;
	const bytes = [];
	for (const group of groups) {
		if (!/^[0-9a-f]{1,4}$/.test(group)) return undefined;
		const n = parseInt(group, 16);
		bytes.push((n >> 8) & 0xff, n & 0xff);
	}
	return bytes.length === 16 ? bytes : undefined;
}

/**
 * 解析 CIDR 为 { family, base, bits }。IPv4 → 32 位整数；IPv6 → 字节数组。
 * @param {string} cidr
 */
export function parseCidr(cidr) {
	if (typeof cidr !== 'string') return undefined;
	const [addrPart, bitsPart] = cidr.trim().split('/');
	const bits = Number(bitsPart);
	if (!Number.isInteger(bits)) return undefined;
	if (addrPart.includes(':')) {
		const bytes = ipv6ToBytes(addrPart);
		if (bytes === undefined || bits < 0 || bits > 128) return undefined;
		return { family: 6, base: bytes, bits };
	}
	const base = ipv4ToInt(addrPart);
	if (base === undefined || bits < 0 || bits > 32) return undefined;
	return { family: 4, base, bits };
}

/**
 * 主机字面量是否落在某 CIDR 内。
 * @param {string} ip 主机字面量（IPv4 或 IPv6，可带方括号）
 * @param {{family:number,base:any,bits:number}} cidr
 */
export function ipInCidr(ip, cidr) {
	const text = stripPort(String(ip).toLowerCase());
	if (text.includes(':')) {
		const bytes = ipv6ToBytes(text);
		if (bytes === undefined || cidr.family !== 6) return false;
		return bytesMatchPrefix(bytes, cidr.base, cidr.bits);
	}
	const value = ipv4ToInt(text);
	if (value === undefined || cidr.family !== 4) return false;
	if (cidr.bits === 0) return true;
	const mask = cidr.bits === 32 ? 0xffffffff : (~((1 << (32 - cidr.bits)) - 1)) >>> 0;
	return (value & mask) >>> 0 === (cidr.base & mask) >>> 0;
}

function bytesMatchPrefix(bytes, base, bits) {
	const fullBytes = Math.floor(bits / 8);
	for (let i = 0; i < fullBytes; i++) if (bytes[i] !== base[i]) return false;
	const rest = bits % 8;
	if (rest === 0) return true;
	const mask = (0xff << (8 - rest)) & 0xff;
	return (bytes[fullBytes] & mask) === (base[fullBytes] & mask);
}

/** 主机名是否是 IP 字面量。 */
export function isIpLiteral(hostname) {
	const text = stripPort(String(hostname).toLowerCase());
	return ipv4ToInt(text) !== undefined || ipv6ToBytes(text) !== undefined;
}

/**
 * 主机是否是「强制直连」目标（本机 / 私有网段 / 私有域 / IP 字面量里的私有地址）。
 * 该判定**不可被用户规则覆盖**。
 * @param {string} hostname
 * @param {{cidrs?: Array}} [extra] 额外的强制直连网段（来自配置，只增不减）
 */
export function isAlwaysDirect(hostname, extra) {
	const h = stripPort(String(hostname).toLowerCase());
	if (h === '') return true;
	if (h === 'localhost') return true;
	if (ALWAYS_DIRECT_SUFFIXES.some((suffix) => h.endsWith(suffix))) return true;
	// 只有落在私有/保留网段内的 IP 才强制直连；公网 IP 允许用户显式走代理，
	// 否则「用 IP 直连境外模型端点」和 CIDR 规则都会失效。
	const cidrs = [...ALWAYS_DIRECT_CIDRS, ...(extra?.cidrs ?? [])];
	for (const raw of cidrs) {
		const cidr = typeof raw === 'string' ? parseCidr(raw) : raw;
		if (cidr !== undefined && ipInCidr(h, cidr)) return true;
	}
	return false;
}

// ── 代理 URL ────────────────────────────────────────────────────

/** undici ProxyAgent 支持的 scheme。 */
export const SUPPORTED_PROXY_SCHEMES = ['http', 'https', 'socks', 'socks4', 'socks4a', 'socks5', 'socks5h'];

/**
 * 解析代理 URL，并做安全校验。
 * @param {string} raw
 * @param {{allowUserinfo?: boolean}} [options]
 * @returns {{ok:true, url:URL, scheme:string, uri:string, hasAuth:boolean}|{ok:false, error:string}}
 */
export function parseProxyUrl(raw, options = {}) {
	if (typeof raw !== 'string' || raw.trim().length === 0) return { ok: false, error: '代理地址为空' };
	let url;
	try {
		url = new URL(raw.trim());
	} catch {
		return { ok: false, error: `代理地址不是合法 URL: ${redactUrlText(raw)}` };
	}
	const scheme = url.protocol.replace(/:$/, '').toLowerCase();
	if (!SUPPORTED_PROXY_SCHEMES.includes(scheme)) {
		return { ok: false, error: `不支持的代理协议 "${scheme}"；支持: ${SUPPORTED_PROXY_SCHEMES.join(', ')}` };
	}
	if (url.hostname === '') return { ok: false, error: '代理地址缺少主机名' };
	// 代理地址不应带路径，`URL.toString()` 会给无路径地址补一个尾部 `/`，这里统一去掉，
	// 让 uri 与用户输入一致（也便于日志与对账）。
	const origin = `${url.protocol}//${url.username !== '' ? `${url.username}${url.password !== '' ? `:${url.password}` : ''}@` : ''}${url.host}`;
	if (url.username !== '' || url.password !== '') {
		if (options.allowUserinfo === false) return { ok: false, error: '不允许在代理地址中内嵌凭据' };
		return { ok: true, url, scheme, uri: origin, hasAuth: true };
	}
	return { ok: true, url, scheme, uri: origin, hasAuth: false };
}

// ── 脱敏 ────────────────────────────────────────────────────────

/** 需要脱敏的请求头名（小写）。插件本身从不读取它们，此处只服务于错误信息。 */
export const REDACT_HEADERS = ['authorization', 'x-api-key', 'api-key', 'cookie', 'set-cookie', 'proxy-authorization', 'x-goog-api-key'];

/** 把 URL 中的 userinfo 与查询串抹掉，只保留 scheme://host[:port]/path。 */
export function redactUrlText(text) {
	return String(text)
		.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/\s@]+@/gi, '$1***@')
		.replace(/([?&](?:key|token|api_?key|access_token|sig|signature)=)[^&\s]+/gi, '$1***');
}

/** 对任意错误消息做脱敏（系统错误经常把完整 URL 拼进 message）。 */
export function redactMessage(message) {
	if (typeof message !== 'string') return '';
	return (
		redactUrlText(message)
			// 认证头值：`Authorization: Bearer xxx` / `Bearer xxx`
			.replace(/\b(Bearer|Basic|Token)\s+[A-Za-z0-9\-._~+/=]{3,}/gi, '$1 ***')
			// 常见密钥前缀
			.replace(/\b(sk|ak|ghp|xox[baprs])[-_][A-Za-z0-9_-]{10,}\b/g, '***')
	);
}

// ── 系统代理（Windows / 环境变量） ──────────────────────────────

/**
 * 解析 Windows 注册表 `ProxyServer` 字段。
 * 形如 `127.0.0.1:7890`、`http=1.2.3.4:8080;https=1.2.3.4:8443;ftp=...`、`socks=127.0.0.1:1080`。
 * @param {string} value
 * @returns {string[]} 候选代理 URI（按 http > https > socks 优先）
 */
export function parseWindowsProxyServer(value) {
	if (typeof value !== 'string' || value.trim() === '') return [];
	const text = value.trim();
	if (!text.includes('=')) {
		const uri = withScheme(text);
		return uri === undefined ? [] : [uri];
	}
	const map = new Map();
	for (const part of text.split(';')) {
		const eq = part.indexOf('=');
		if (eq <= 0) continue;
		const key = part.slice(0, eq).trim().toLowerCase();
		const target = part.slice(eq + 1).trim();
		if (target !== '') map.set(key, withScheme(target, key));
	}
	const ordered = [];
	for (const key of ['http', 'https', 'socks', 'socks5']) {
		const uri = map.get(key);
		if (uri !== undefined) ordered.push(uri);
	}
	if (ordered.length === 0) for (const uri of map.values()) ordered.push(uri);
	return ordered;
}
function withScheme(target, hint) {
	const trimmed = target.trim();
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
	if (hint === 'socks' || hint === 'socks5') return `socks5://${trimmed}`;
	return `http://${trimmed}`;
}

/**
 * 解析 Windows `ProxyOverride` / 标准 `NO_PROXY` 字符串为后缀条目。
 * `<local>` 代表所有无点主机名。
 * @param {string} value
 * @returns {{suffixes:string[], localMatch:boolean}}
 */
export function parseNoProxyList(value) {
	const suffixes = [];
	let localMatch = false;
	if (typeof value !== 'string') return { suffixes, localMatch };
	for (const raw of value.split(/[;,\s]+/)) {
		const token = raw.trim().toLowerCase();
		if (token === '') continue;
		if (token === '<local>' || token === '<-loopback>' || token === '<-loopback>') {
			localMatch = true;
			continue;
		}
		if (token === '*') continue; // 通配由 elsewhere 处理，这里忽略
		const normalized = normalizeHostEntry(token);
		if (normalized !== undefined) suffixes.push(normalized);
	}
	return { suffixes, localMatch };
}

/** 从形如 `http://user:pass@1.2.3.4:8080` 的代理 URI 中推测出代理主机（用于 NO_PROXY 自排除，防回环）。 */
export function proxyHostOf(uri) {
	try {
		return new URL(uri).hostname;
	} catch {
		return '';
	}
}

// ── 环境变量代理 ────────────────────────────────────────────────

/**
 * 从环境变量读取代理设置（遵循 DSH 自带约定与业界惯例）。
 * @param {Record<string,string|undefined>} env
 * @returns {{http?:string, https?:string, all?:string, noProxy:string}|undefined}
 */
export function readEnvProxy(env) {
	const pick = (...names) => {
		for (const name of names) {
			const value = env[name];
			if (typeof value === 'string' && value.trim() !== '') return value.trim();
		}
		return undefined;
	};
	const http = pick('HTTP_PROXY', 'http_proxy');
	const https = pick('HTTPS_PROXY', 'https_proxy');
	const all = pick('ALL_PROXY', 'all_proxy');
	if (http === undefined && https === undefined && all === undefined) return undefined;
	return { http, https, all, noProxy: pick('NO_PROXY', 'no_proxy') ?? '' };
}
