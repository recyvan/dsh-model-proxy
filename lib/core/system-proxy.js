/**
 * 系统代理读取。**只读**——本插件从不修改系统代理设置。
 *
 * Windows：读 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
 * （`ProxyEnable` / `ProxyServer` / `ProxyOverride`）。读取方式可注入，
 * 因为某些受限环境（沙箱）无法 spawn 子进程：
 * - `commandRunner`：默认 `execFileSync`（执行 `reg.exe query`），失败即止
 * - `registryProvider`：优先使用（测试/嵌入时可直接给定项值）
 *
 * 非 Windows 平台：退回环境变量（由调用方处理），本模块返回 `unsupported`。
 *
 * @module dsh-model-proxy/core/system-proxy
 */

import { parseNoProxyList, parseWindowsProxyServer } from './match.js';

export const INTERNET_SETTINGS_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

/**
 * 解析 `reg.exe query` 的文本输出（`    ProxyEnable    REG_DWORD    0x1`）。
 * @param {string} text
 * @returns {Record<string,string>}
 */
export function parseRegQueryOutput(text) {
	const values = {};
	for (const line of String(text).split(/\r?\n/)) {
		const match = /^\s{2,}(\S+)\s+(REG_[A-Z_]+)\s+(.*)$/.exec(line);
		if (match === null) continue;
		values[match[1]] = match[3].trim();
	}
	return values;
}

/** `0x1` / `1` → true。 */
function regBool(value) {
	if (typeof value !== 'string') return false;
	return value.trim().toLowerCase() === '0x1' || value.trim() === '1';
}

/**
 * 从注册表项值推出系统代理。
 * @param {Record<string,string>} values
 * @returns {{enabled:boolean, proxies:string[], override:string}}
 */
export function systemProxyFromRegistryValues(values) {
	const enabled = regBool(values.ProxyEnable);
	const server = typeof values.ProxyServer === 'string' ? values.ProxyServer : '';
	const override = typeof values.ProxyOverride === 'string' ? values.ProxyOverride : '';
	if (!enabled || server.trim() === '') return { enabled: false, proxies: [], override };
	return { enabled: true, proxies: parseWindowsProxyServer(server), override };
}

/**
 * 读取系统代理。
 * @param {object} [options]
 * @param {() => Record<string,string>} [options.registryProvider] 直接提供注册表值
 * @param {(file:string, args:string[]) => string} [options.commandRunner] 执行 `reg.exe` 的方式
 * @param {string} [options.platform] 覆盖 platform（测试用）
 * @returns {{status:'ok'|'disabled'|'unsupported'|'unavailable', proxies:string[], noProxy:{suffixes:string[],localMatch:boolean}|null, detail:string}}
 */
export function readSystemProxy(options = {}) {
	const platform = options.platform ?? process.platform;
	if (platform !== 'win32') {
		return { status: 'unsupported', proxies: [], noProxy: null, detail: `平台 ${platform} 的系统代理读取未实现，请改用环境变量或自定义代理` };
	}
	let values;
	if (typeof options.registryProvider === 'function') {
		try {
			values = options.registryProvider();
		} catch (error) {
			return { status: 'unavailable', proxies: [], noProxy: null, detail: `读取注册表失败: ${error?.message ?? error}` };
		}
	} else {
		const runner = options.commandRunner ?? defaultCommandRunner();
		if (typeof runner !== 'function') {
			return { status: 'unavailable', proxies: [], noProxy: null, detail: '当前环境无法执行子进程（reg.exe），系统代理不可读' };
		}
		try {
			const output = runner('reg.exe', ['query', INTERNET_SETTINGS_KEY]);
			values = parseRegQueryOutput(output);
		} catch (error) {
			return { status: 'unavailable', proxies: [], noProxy: null, detail: `执行 reg.exe 失败: ${error?.message ?? error}` };
		}
	}
	const parsed = systemProxyFromRegistryValues(values ?? {});
	if (!parsed.enabled) return { status: 'disabled', proxies: [], noProxy: null, detail: '系统代理未启用' };
	return {
		status: 'ok',
		proxies: parsed.proxies,
		noProxy: parseNoProxyList(parsed.override),
		detail: parsed.proxies.length === 0 ? '系统代理已启用但 ProxyServer 为空' : `系统代理: ${parsed.proxies.map(maskUri).join(', ')}`,
	};
}

function maskUri(uri) {
	try {
		const url = new URL(uri);
		if (url.username !== '' || url.password !== '') {
			url.username = '***';
			url.password = '';
		}
		return url.toString();
	} catch {
		return uri;
	}
}

/** `execFileSync` 只在小写导入时才存在，这里延迟取用，便于不支持的环境静默跳过。 */
function defaultCommandRunner() {
	try {
		// 动态导入在 ESM 里是异步的；这里用 createRequire 同步拿内置模块
		const { execFileSync } = process.getBuiltinModule('node:child_process');
		return (file, args) => execFileSync(file, args, { encoding: 'utf8', windowsHide: true, timeout: 3000 });
	} catch {
		return undefined;
	}
}
