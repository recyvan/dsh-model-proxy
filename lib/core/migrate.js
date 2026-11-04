/**
 * 设置迁移。
 *
 * 为什么需要它：`Config` 的字段会随版本演进。宿主把「没有这个键」当成「用默认值」，
 * 所以**删掉一个字段并不会报错**——老用户的显式设置会被默认值覆盖，而且毫无提示。
 * 已经发生过一次：2.0 把 `enabled` 合并进了 `mode: 'off'`，任何靠 `enabled: false`
 * 关掉插件的人，升级后会发现代理又开着了。
 *
 * 这里把「旧形状 → 新形状」的换算集中成纯函数，调用方拿到的永远是当前版本的结构；
 * 发生过哪些换算会返回给调用方，由它写日志/显示在设置页上——迁移必须是**可见**的。
 *
 * @module dsh-model-proxy/core/migrate
 */

/** 当前设置结构的版本号。加字段不必加版本；改变字段语义时必须加。 */
export const SCHEMA_VERSION = 2;

/**
 * 把任意版本的扁平设置换算成当前版本。
 *
 * 纯函数、幂等：同一份输入跑两次结果相同，且第二次不会再有变更。
 * 只处理**已知**的演进，未知键原样保留（可能是组合层配置或未来版本写的）。
 *
 * @param {object} raw 扁平设置（通常是 `readSettings()` 的结果）
 * @returns {{value: object, changes: string[]}} changes 是机器可读的变更码
 */
export function migrateSettings(raw) {
	const value = raw !== null && typeof raw === 'object' ? { ...raw } : {};
	/** @type {string[]} */
	const changes = [];

	// 1) `enabled` → `mode: 'off'`（0.2.x 及更早的开关）
	//    只有显式 false 才需要换算；true 是当年的默认值，直接丢掉即可。
	if (value.enabled === false) {
		if (value.mode !== 'off') {
			value.mode = 'off';
			changes.push('enabled-false-to-mode-off');
		}
	}
	if ('enabled' in value) {
		delete value.enabled;
		if (changes.length > 0) changes.push('drop-enabled');
	}

	// 2) 域名清单：逗号分隔的字符串 → 数组。
	//    `normalizeConfig` 两种都吃，但落盘形状要统一，否则设置页读回来是字符串。
	for (const key of ['proxyHosts', 'excludeHosts']) {
		const raw0 = value[key];
		if (typeof raw0 === 'string') {
			value[key] = raw0
				.split(/[,\s]+/)
				.map((item) => item.trim())
				.filter((item) => item !== '');
			changes.push(`string-list-to-array:${key}`);
		}
	}

	// 3) 代理地址：只有 `proxyHost`/`proxyPort` 的老写法 → 合成 `proxyUri`，
	//    让设置页能直接显示与编辑。
	if (typeof value.proxyUri === 'string' && value.proxyUri.trim() === '') {
		const host = typeof value.proxyHost === 'string' ? value.proxyHost.trim() : '';
		const port = Number(value.proxyPort);
		if (host !== '' && Number.isInteger(port) && port > 0 && port <= 65535) {
			const scheme = typeof value.proxyType === 'string' && value.proxyType.trim() !== '' ? value.proxyType.trim() : 'http';
			value.proxyUri = `${scheme}://${host}:${port}`;
			changes.push('host-port-to-uri');
		}
	}

	value.schemaVersion = SCHEMA_VERSION;
	return { value, changes };
}
