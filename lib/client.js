window.__ModuleLoader__.load({
	id: 'dsh-model-proxy',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		// dsh-model-proxy 设置页（客户端一半）：模型 API 出口代理。
		//
		// 契约同 @copylee/dsh-proxy@0.4.5（在 DSH 0.2.1-rc.2 上实测可用的第三方插件）：
		// 客户端**没有** `settingsScope` 服务，读写走 `ctx.remote.settings`：
		//   读：`await ctx.remote.settings.describe()` → `namespaces.find(n => n.ns === NS)`
		//   写：`await ctx.remote.settings.mutate(NS, ops, revision)`
		//   订阅：`ctx.remote.$on('settings/document-updated', ns => ...)`
		// 挂载点用 `settings.section`（设置里独立一页），不是 `settings.plugin.item`。
		'use strict';
		var React = require('react');

		var h = React.createElement;
		var useState = React.useState;
		var useEffect = React.useEffect;
		var useCallback = React.useCallback;
		var useRef = React.useRef;

		/**
		 * 中英文字典。**唯一真源是 lib/i18n.js**：这里是它的内联副本，
		 * 因为客户端入口是 IIFE，运行时 require 不到本地模块。
		 * test/run-all.mjs 的 i18n 组会核对两份 key 集合完全一致。
		 */
		var MESSAGES = {
	zh: {
		sectionLabel: '模型代理',
		title: '模型代理',
		intro: '让境外模型 API 经代理访问；清单之外的请求保持直连。',
		loading: '读取设置中…',
		loadFailed: '读取设置失败：{error}',
		namespaceMissing: '本部署没有向页面暴露 model-proxy 设置命名空间：请确认插件已启用，或在 cordis.patch.yml 里配置。',
		readOnly: '当前页面只能读取设置（非回环访问或设置只读），改动请在桌面端进行。',
		fieldMode: '模式',
		modeRule: '规则分流（推荐）：只让指定域名走代理',
		modeSystem: '跟随系统代理：全部模型请求走系统代理',
		modeCustom: '自定义代理：全部模型请求走下方代理',
		modeOff: '关闭：全部直连',
		modeHint: '规则分流下，未命中规则的请求直连；系统 / 自定义模式下，未命中规则的请求才走代理。',
		fieldProxyType: '代理协议',
		proxyTypeHint: '能访问到境外 API 的代理。国内直连被污染时优先 SOCKS5h。',
		fieldProxyUri: '代理地址',
		proxyUriHint: '只填 host:port 时按上面的协议自动补全。不要把密码写进保存的配置里，如需认证请在代理程序侧放行本机。',
		fieldProxyHosts: '只代理这些域名',
		fieldExcludeHosts: '排除域名',
		hostsEmpty: '还没有条目。留空 = 使用内置预设（境外模型域名走代理）。',
		hostsAdd: '添加',
		hostsAddPlaceholder: 'api.openai.com 或 *.openai.com',
		hostsRemove: '移除 {host}',
		hostsRestorePreset: '恢复内置预设',
		hostsHint: '支持精确主机名、通配符（*.openai.com）与后缀写法。',
		excludeHint: '优先级最高，永远直连（本机、内网与 .local 等已强制直连，无需填写）。',
		fieldInsecure: '允许明文 http 目标（不推荐：API Key 会以明文经过代理）',
		fieldLogLevel: '日志级别',
		logSilent: 'silent：不输出',
		logError: 'error：只输出错误',
		logWarn: 'warn：错误与警告',
		logInfo: 'info：默认',
		logDebug: 'debug：含目标主机名，排查用',
		logHint: 'debug 会把目标主机名写进日志；平时保持 info。',
		statusTitle: '运行状态',
		statusLoading: '读取中…',
		statusFailed: '读取状态失败：{error}',
		statusPath: '路径 {path}',
		statusExit: '出口 {exit}',
		statusRules: '规则 {count}',
		statusCounts: '请求 代理 {proxied} / 直连 {direct}',
		statusLastError: ' · 最近错误：{error}',
		statusSystemProxy: '系统代理：{status} — {detail}',
		degraded: '⚠ 出口 {exit} 已降级（连续失败 {failures} 次），当前回落直连；恢复后会自动重新启用。',
		probeButton: '测试代理',
		probeRunning: '测试中…',
		probeOk: '✓ 连通（{ms} ms，HTTP {status}，经 {via}）',
		probeFail: '✗ 不通（{ms} ms，{via}）：{failure}',
		probeHint: '让当前出口真实访问一次固定目标，只回报结果分类，不回报主机名。',
		save: '保存',
		saving: '保存中…',
		saved: '已保存 ✓ 下一次请求生效',
		saveFailed: '保存失败：{error}',
		active: '插件运行中',
		inactive: '插件未启用',
	},
	en: {
		sectionLabel: 'Model Proxy',
		title: 'Model Proxy',
		intro: 'Routes model API traffic through a proxy; requests outside the list stay direct.',
		loading: 'Reading settings…',
		loadFailed: 'Could not read settings: {error}',
		namespaceMissing: 'This deployment does not expose the model-proxy settings namespace: check that the plugin is enabled, or configure it in cordis.patch.yml.',
		readOnly: 'This page can only read settings (non-loopback access or read-only settings). Change them on the desktop app.',
		fieldMode: 'Mode',
		modeRule: 'Rule-based (recommended): only the listed domains use the proxy',
		modeSystem: 'Follow the system proxy: every model request goes through it',
		modeCustom: 'Custom proxy: every model request uses the proxy below',
		modeOff: 'Off: everything connects directly',
		modeHint: 'In rule mode, requests that match no rule go direct; in system/custom mode, only unmatched requests go direct.',
		fieldProxyType: 'Proxy protocol',
		proxyTypeHint: 'A proxy that can reach the overseas API. Prefer SOCKS5h when local DNS is polluted.',
		fieldProxyUri: 'Proxy address',
		proxyUriHint: 'A bare host:port is completed from the protocol above. Do not store a password in the saved settings; let your proxy accept loopback connections instead.',
		fieldProxyHosts: 'Proxy only these domains',
		fieldExcludeHosts: 'Exclude domains',
		hostsEmpty: 'No entries yet. Empty means the built-in preset (overseas model domains go through the proxy).',
		hostsAdd: 'Add',
		hostsAddPlaceholder: 'api.openai.com or *.openai.com',
		hostsRemove: 'Remove {host}',
		hostsRestorePreset: 'Restore built-in preset',
		hostsHint: 'Accepts exact hosts, wildcards (*.openai.com) and suffix notation.',
		excludeHint: 'Takes precedence over everything and is always direct (loopback, private ranges and .local are already forced direct).',
		fieldInsecure: 'Allow plaintext http targets (not recommended: the API key would cross the proxy in clear text)',
		fieldLogLevel: 'Log level',
		logSilent: 'silent: off',
		logError: 'error: errors only',
		logWarn: 'warn: errors and warnings',
		logInfo: 'info: default',
		logDebug: 'debug: includes target hostnames, for troubleshooting',
		logHint: 'debug writes target hostnames to the log; keep it at info normally.',
		statusTitle: 'Status',
		statusLoading: 'Reading…',
		statusFailed: 'Could not read status: {error}',
		statusPath: 'path {path}',
		statusExit: 'exit {exit}',
		statusRules: 'rules {count}',
		statusCounts: 'proxied {proxied} / direct {direct}',
		statusLastError: ' · last error: {error}',
		statusSystemProxy: 'System proxy: {status} — {detail}',
		degraded: '⚠ Exit {exit} is degraded (failed {failures} times in a row) and is currently bypassed to direct; it re-enables itself once healthy.',
		probeButton: 'Test proxy',
		probeRunning: 'Testing…',
		probeOk: '✓ Reachable ({ms} ms, HTTP {status}, via {via})',
		probeFail: '✗ Unreachable ({ms} ms, {via}): {failure}',
		probeHint: 'Sends one real request through the current exit and reports only the outcome class, never the hostname.',
		save: 'Save',
		saving: 'Saving…',
		saved: 'Saved ✓ takes effect on the next request',
		saveFailed: 'Save failed: {error}',
		active: 'Plugin active',
		inactive: 'Plugin not enabled',
	},
};

		/** 极简插值：把 {name} 换成参数值；缺参数时保留原样便于发现。 */
		function interpolate(template, params) {
			if (params === undefined || params === null) return template;
			return String(template).replace(/\{(\w+)\}/g, function (match, key) {
				return params[key] === undefined || params[key] === null ? match : String(params[key]);
			});
		}

		/** 没有 locale 服务时的兜底：按中文渲染。 */
		function makeFallbackT() {
			return function (key, params) {
				var table = MESSAGES.zh;
				return interpolate(table[key] === undefined ? key : table[key], params);
			};
		}

		var NS = 'model-proxy';
		var ROUTE = '/dsh-model-proxy';
		/** 需要的客户端服务：槽位 + remote（settings 读写）+ locale（文案）。 */
		var inject = ['slots', 'remote', 'remote.settings', 'locale'];

		// ── 样式（一次性注入，带插件标记去重） ──────────────────
		var CSS = [
			'.mp-page{display:flex;flex-direction:column;gap:2px;max-width:720px}',
			'.mp-title{margin:0 0 4px;font-size:16px;font-weight:600;color:var(--dsw-alias-label-primary)}',
			'.mp-desc{color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:1.6;margin:0 0 8px}',
			'.mp-field{display:flex;flex-direction:column;gap:6px;padding:12px 0}',
			'.mp-field+.mp-field{border-top:1px solid var(--dsw-alias-border-l2)}',
			'.mp-label{display:flex;align-items:center;gap:8px;color:var(--dsw-alias-label-primary);font-size:13px;font-weight:500}',
			'.mp-input,.mp-select{border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);height:34px;font:inherit;color:var(--dsw-alias-label-primary);border-radius:8px;padding:0 12px;font-size:13px;width:100%;box-sizing:border-box}',
			'.mp-hint{color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:1.6;margin:0}',
			'.mp-warn{color:#b26a00;font-size:12px;line-height:1.6;margin:0}',
			'.mp-err{color:#c2182f;font-size:12px;margin:0}',
			'.mp-ok{color:#2f9e44;font-size:12px;margin:0}',
			'.mp-actions{display:flex;align-items:center;gap:10px;padding-top:12px}',
			'.mp-btn{appearance:none;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-primary);border-radius:8px;padding:0 14px;height:32px;font:inherit;font-size:13px;cursor:pointer}',
			'.mp-btn--primary{background:var(--dsw-alias-label-primary,#1f1e1d);color:var(--dsw-alias-bg-layer-3,#fff);border-color:transparent;font-weight:500}',
			'.mp-btn--primary:hover:not(:disabled){opacity:.88}',
			'.mp-btn:disabled{opacity:.5;cursor:default}',
			'.mp-tag{display:inline-block;border:1px solid var(--dsw-alias-border-l2);border-radius:4px;padding:0 5px;font-size:11px;color:var(--dsw-alias-label-secondary);margin-right:4px}',
			'.mp-hosts{display:flex;flex-direction:column;gap:8px}',
			'.mp-tags{display:flex;flex-wrap:wrap;gap:6px}',
			'.mp-tagchip{display:inline-flex;align-items:center;gap:4px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);border-radius:6px;padding:2px 4px 2px 8px;font-size:12px;color:var(--dsw-alias-label-primary)}',
			'.mp-tagchip code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}',
			'.mp-tagchip-x{appearance:none;border:0;background:transparent;color:var(--dsw-alias-label-tertiary);cursor:pointer;font-size:14px;line-height:1;padding:0 4px;border-radius:4px}',
			'.mp-tagchip-x:hover:not(:disabled){color:#c2182f}',
			'.mp-tagchip-x:disabled{opacity:.4;cursor:default}',
			'.mp-hosts-add{display:flex;gap:8px;align-items:center}',
			'.mp-hosts-add .mp-input{flex:1 1 auto}',
			'.mp-hosts-add .mp-btn{flex:0 0 auto;white-space:nowrap}',
		].join('');

		function installStyles() {
			if (typeof document === 'undefined') return;
			if (document.querySelector('style[data-plugin="dsh-model-proxy"]') !== null) return;
			var tag = document.createElement('style');
			tag.dataset.plugin = 'dsh-model-proxy';
			tag.textContent = CSS;
			document.head.appendChild(tag);
		}

		// ── 表单值与设置层之间的转换 ───────────────────────────
		function fromValue(value) {
			var v = value || {};
			return {
				mode: typeof v.mode === 'string' ? v.mode : 'rule',
				proxyType: typeof v.proxyType === 'string' ? v.proxyType : 'http',
				proxyUri: typeof v.proxyUri === 'string' ? v.proxyUri : '',
				proxyHosts: joinList(v.proxyHosts),
				excludeHosts: joinList(v.excludeHosts),
				allowInsecureUpstream: v.allowInsecureUpstream === true,
				logLevel: typeof v.logLevel === 'string' ? v.logLevel : 'info',
			};
		}

		function joinList(list) {
			return Array.isArray(list) ? list.join(', ') : typeof list === 'string' ? list : '';
		}

		function splitList(text) {
			return String(text || '')
				.split(/[,\s]+/)
				.map(function (part) {
					return part.trim();
				})
				.filter(function (part) {
					return part.length > 0;
				});
		}

		/** 表单 → `settings.mutate` 的操作列表（空值走 unset，回落到 schema 默认）。 */
		function buildOps(draft) {
			var ops = [];
			var setOrUnset = function (key, value, isEmpty) {
				ops.push(isEmpty ? { op: 'unset', path: [key] } : { op: 'set', path: [key], value: value });
			};
			var proxyUri = String(draft.proxyUri || '').trim();
			var proxyHosts = splitList(draft.proxyHosts);
			var excludeHosts = splitList(draft.excludeHosts);
			setOrUnset('mode', draft.mode, false);
			setOrUnset('proxyType', draft.proxyType, false);
			setOrUnset('proxyUri', proxyUri, proxyUri === '');
			setOrUnset('proxyHosts', proxyHosts, proxyHosts.length === 0);
			setOrUnset('excludeHosts', excludeHosts, excludeHosts.length === 0);
			setOrUnset('allowInsecureUpstream', draft.allowInsecureUpstream === true, draft.allowInsecureUpstream !== true);
			setOrUnset('logLevel', draft.logLevel || 'info', !draft.logLevel);
			return ops;
		}

		/** remote.* 的返回值是 `{ ok, value }` 或 `{ ok: false, error }`。 */
		function unwrap(result) {
			if (result && result.ok) return result.value;
			var message = result && result.error && result.error.message ? result.error.message : '设置读写失败';
			throw new Error(message);
		}

		// ── 设置通道 ───────────────────────────────────────────
		function createApi(ctx) {
			return {
				load: function () {
					return Promise.resolve(ctx.remote.settings.describe()).then(function (described) {
						var settings = unwrap(described) || {};
						var list = settings.namespaces || [];
						var view = null;
						for (var i = 0; i < list.length; i += 1) {
							if (list[i] && list[i].ns === NS) {
								view = list[i];
								break;
							}
						}
						return {
							writable: settings.writable !== false && view !== null,
							view: view,
							value: view && view.value ? view.value : null,
							revision: view ? view.revision : undefined,
						};
					});
				},
				save: function (draft, revision) {
					return Promise.resolve(ctx.remote.settings.mutate(NS, buildOps(draft), revision)).then(unwrap);
				},
				subscribe: function (listener) {
					try {
						var off = typeof ctx.remote.$on === 'function' ? ctx.remote.$on('settings/document-updated', function (ns) { if (ns === NS) listener(); }) : null;
						return typeof off === 'function' ? off : function () {};
					} catch (error) {
						return function () {};
					}
				},
				/** 同源只读诊断快照（宿主那一半的 /status 路由）。 */
				status: function () {
					return fetch(ROUTE + '/status', { headers: { accept: 'application/json' }, credentials: 'same-origin' }).then(function (response) {
						if (!response.ok) throw new Error('HTTP ' + response.status);
						return response.json();
					});
				},
				/**
				 * 连通性自检：POST /probe。宿主那边只接受 POST——它真的会发网络请求，
				 * 做成 GET 就能被同源页面用 <img src> 之类的方式顺手触发。
				 */
				probe: function () {
					return fetch(ROUTE + '/probe', {
						method: 'POST',
						headers: { accept: 'application/json' },
						credentials: 'same-origin',
					}).then(function (response) {
						if (!response.ok) throw new Error('HTTP ' + response.status);
						return response.json();
					});
				},
			};
		}

		/** 一个「标签 + 控件 + 说明」字段。 */
		function makeField(label, control, hint) {
			return h(
				'div',
				{ className: 'mp-field' },
				label === null ? null : h('div', { className: 'mp-label' }, label),
				control,
				hint ? h('p', { className: 'mp-hint' }, hint) : null,
			);
		}

		// ── 设置页 ─────────────────────────────────────────────
		function ModelProxySection(props) {
			var api = props.api;
			/** 文案函数由 apply() 注入（ctx.locale.bind 或中文兜底）。 */
			var t = props.t;

			var statePair = useState({ loading: true, error: '', writable: false, view: null });
			var state = statePair[0];
			var setState = statePair[1];

			var draftPair = useState(null);
			var draft = draftPair[0];
			var setDraft = draftPair[1];
			var dirtyRef = useRef(false);

			var savePair = useState({ saving: false, saved: false, failed: '' });
			var saveInfo = savePair[0];
			var setSaveInfo = savePair[1];

			var livePair = useState({ loading: false, data: null, error: '' });
			var live = livePair[0];
			var setLive = livePair[1];

			/** 连通性自检的状态：{ running, result }。 */
			var probePair = useState({ running: false, result: null });
			var probeInfo = probePair[0];
			var setProbeInfo = probePair[1];
			/** 域名 tag 编辑器的输入框草稿：{ proxyHosts: '', excludeHosts: '' }。 */
			var inputPair = useState({ proxyHosts: '', excludeHosts: '' });
			var hostInput = inputPair[0];
			var setHostInput = inputPair[1];

			var refreshStatus = useCallback(
				function () {
					return api
						.status()
						.then(function (data) {
							setLive({ loading: false, data: data, error: '' });
						})
						.catch(function (error) {
							setLive({ loading: false, data: null, error: String(error && error.message ? error.message : error) });
						});
				},
				[api],
			);

			var load = useCallback(
				function (reset) {
					return api
						.load()
						.then(function (result) {
							setState({ loading: false, error: '', writable: result.writable, view: result.view });
							if (reset === true || dirtyRef.current !== true) {
								setDraft(fromValue(result.value));
								dirtyRef.current = false;
							}
						})
						.catch(function (error) {
							setState({ loading: false, error: String(error && error.message ? error.message : error), writable: false, view: null });
						});
				},
				[api],
			);

			useEffect(
				function () {
					load(true);
					var off = api.subscribe(function () {
						load(false);
					});
					return function () {
						try {
							off();
						} catch (error) {
							/* noop */
						}
					};
				},
				[api, load],
			);

			useEffect(
				function () {
					refreshStatus();
				},
				[refreshStatus],
			);

			var form = draft || fromValue(null);

			function edit(fieldName, value) {
				setDraft(function (previous) {
					var next = Object.assign({}, previous || fromValue(null));
					next[fieldName] = value;
					return next;
				});
				dirtyRef.current = true;
				setSaveInfo({ saving: false, saved: false, failed: '' });
			}

			function save() {
				var view = state.view;
				if (view === null || view === undefined) return;
				setSaveInfo({ saving: true, saved: false, failed: '' });
				api
					.save(form, view.revision)
					.then(function () {
						dirtyRef.current = false;
						setSaveInfo({ saving: false, saved: true, failed: '' });
						return load(true);
					})
					.then(function () {
						return refreshStatus();
					})
					.catch(function (error) {
						setSaveInfo({ saving: false, saved: false, failed: String(error && error.message ? error.message : error) });
					});
			}

			/** 连通性自检：让后端用当前出口真发一次请求。 */
			function runProbe() {
				setProbeInfo({ running: true, result: null });
				api
					.probe()
					.then(function (result) {
						setProbeInfo({ running: false, result: result });
					})
					.catch(function (error) {
						setProbeInfo({
							running: false,
							result: { ok: false, ms: 0, via: '-', failure: String(error && error.message ? error.message : error) },
						});
					});
			}

			/**
			 * 域名 tag 编辑器：每个条目一个可删的标签 + 一个输入框。
			 * 比逗号分隔的文本框好在：不会因为多打一个逗号就产生空条目，
			 * 删错不用回溯整串文本，已有条目一眼看得全。
			 */
			function hostEditor(fieldName) {
				var list = form[fieldName] || [];
				function commit(next) {
					edit(fieldName, next);
				}
				function append() {
					var raw = String(hostInput[fieldName] || '').trim();
					if (raw === '') return;
					var additions = splitList(raw);
					var next = list.slice();
					for (var i = 0; i < additions.length; i += 1) {
						if (next.indexOf(additions[i]) === -1) next.push(additions[i]);
					}
					commit(next);
					setHostInput(Object.assign({}, hostInput, { [fieldName]: '' }));
				}
				return h(
					'div',
					{ className: 'mp-hosts' },
					list.length === 0
						? h('p', { className: 'mp-hint', style: { margin: 0 } }, t('hostsEmpty'))
						: h(
								'div',
								{ className: 'mp-tags' },
								list.map(function (host, index) {
									return h(
										'span',
										{ className: 'mp-tagchip', key: fieldName + '-' + String(index) },
										h('code', null, host),
										h(
											'button',
											{
												type: 'button',
												className: 'mp-tagchip-x',
												disabled: !writable,
												title: t('hostsRemove', { host: host }),
												'aria-label': t('hostsRemove', { host: host }),
												onClick: function () {
													commit(
														list.filter(function (item) {
															return item !== host;
														}),
													);
												},
											},
											'×',
										),
									);
								}),
							),
					h(
						'div',
						{ className: 'mp-hosts-add' },
						h('input', {
							className: 'mp-input',
							type: 'text',
							placeholder: t('hostsAddPlaceholder'),
							value: hostInput[fieldName] || '',
							disabled: !writable,
							onChange: function (event) {
								setHostInput(Object.assign({}, hostInput, { [fieldName]: event.target.value }));
							},
							onKeyDown: function (event) {
								if (event.key === 'Enter') {
									event.preventDefault();
									append();
								}
							},
						}),
						h(
							'button',
							{
								type: 'button',
								className: 'mp-btn',
								disabled: !writable || String(hostInput[fieldName] || '').trim() === '',
								onClick: append,
							},
							t('hostsAdd'),
						),
						fieldName === 'proxyHosts'
							? h(
									'button',
									{
										type: 'button',
										className: 'mp-btn',
										disabled: !writable || list.length === 0,
										onClick: function () {
											commit([]);
										},
									},
									t('hostsRestorePreset'),
								)
							: null,
					),
				);
			}

			var writable = state.writable === true;
			var data = live.data;
			var active = !!(data && data.status && data.status.active);
			var suggestions = (data && data.suggestions) || [];
			var showProxy = form.mode !== 'system' && form.mode !== 'off';
			// health 形如 { [exitId]: { total, failures, degraded } }：只把降级的挑出来显示，
			// 否则一次出口故障就是静默直连，用户看不出流量已经不走代理了。
			var degradedExits = [];
			var health = (data && data.health) || {};
			Object.keys(health).forEach(function (exitId) {
				var entry = health[exitId];
				if (entry && entry.degraded === true) degradedExits.push({ exitId: exitId, failures: entry.failures || 0 });
			});

			return h(
				'div',
				{ className: 'mp-page' },
				h('h2', { className: 'mp-title' }, t('title')),
				h('p', { className: 'mp-desc' }, t('intro')),
				state.loading ? h('p', { className: 'mp-hint' }, t('loading')) : null,
				state.error ? h('p', { className: 'mp-err' }, t('loadFailed', { error: state.error })) : null,
				state.loading === false && state.error === '' && state.view === null ? h('p', { className: 'mp-err' }, t('namespaceMissing')) : null,
				state.view !== null && !writable ? h('p', { className: 'mp-hint' }, t('readOnly')) : null,
				makeField(
					t('fieldMode'),
					h(
						'select',
						{
							className: 'mp-select',
							value: form.mode,
							disabled: !writable,
							onChange: function (event) {
								edit('mode', event.target.value);
							},
						},
						h('option', { value: 'rule' }, t('modeRule')),
						h('option', { value: 'system' }, t('modeSystem')),
						h('option', { value: 'custom' }, t('modeCustom')),
						h('option', { value: 'off' }, t('modeOff')),
					),
					t('modeHint'),
				),
				showProxy
					? makeField(
							t('fieldProxyType'),
							h(
								'select',
								{
									className: 'mp-select',
									value: form.proxyType,
									disabled: !writable,
									onChange: function (event) {
										edit('proxyType', event.target.value);
									},
								},
								h('option', { value: 'http' }, 'HTTP'),
								h('option', { value: 'https' }, 'HTTPS'),
								h('option', { value: 'socks5' }, 'SOCKS5'),
								h('option', { value: 'socks5h' }, 'SOCKS5H'),
								h('option', { value: 'socks4' }, 'SOCKS4'),
							),
							t('proxyTypeHint'),
						)
					: null,
				showProxy
					? makeField(
							t('fieldProxyUri'),
							h('input', {
								className: 'mp-input',
								type: 'text',
								placeholder: 'socks5h://127.0.0.1:7890',
								value: form.proxyUri,
								disabled: !writable,
								onChange: function (event) {
									edit('proxyUri', event.target.value);
								},
							}),
							t('proxyUriHint'),
						)
					: null,
				showProxy
					? makeField(
							t('fieldProxyHosts'),
							hostEditor('proxyHosts'),
							t('hostsHint') + (suggestions.length > 0 ? ' (' + suggestions.slice(0, 4).join(' / ') + ' …)' : ''),
						)
					: null,
				showProxy ? makeField(t('fieldExcludeHosts'), hostEditor('excludeHosts'), t('excludeHint')) : null,
				makeField(
					null,
					h(
						'label',
						{ style: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 } },
						h('input', {
							type: 'checkbox',
							checked: form.allowInsecureUpstream,
							disabled: !writable,
							onChange: function (event) {
								edit('allowInsecureUpstream', event.target.checked);
							},
						}),
						t('fieldInsecure'),
					),
				),
				makeField(
					t('fieldLogLevel'),
					h(
						'select',
						{
							className: 'mp-select',
							value: form.logLevel,
							disabled: !writable,
							onChange: function (event) {
								edit('logLevel', event.target.value);
							},
						},
						h('option', { value: 'silent' }, t('logSilent')),
						h('option', { value: 'error' }, t('logError')),
						h('option', { value: 'warn' }, t('logWarn')),
						h('option', { value: 'info' }, t('logInfo')),
						h('option', { value: 'debug' }, t('logDebug')),
					),
					t('logHint'),
				),
				h(
					'div',
					{ className: 'mp-field' },
					h('p', { className: 'mp-hint' }, t('statusTitle')),
					live.loading ? h('p', { className: 'mp-hint' }, t('statusLoading')) : null,
					live.error ? h('p', { className: 'mp-err' }, t('statusFailed', { error: live.error })) : null,
					data
						? h(
								'p',
								{ className: 'mp-hint' },
								h('span', { className: 'mp-tag' }, t('statusPath', { path: String(data.diagnostics && data.diagnostics.path) })),
								h('span', { className: 'mp-tag' }, t('statusExit', { exit: data.status && data.status.exitId ? data.status.exitId : '-' })),
								h('span', { className: 'mp-tag' }, t('statusRules', { count: String(data.progress && data.progress.ruleCount) })),
								h(
									'span',
									{ className: 'mp-tag' },
									t('statusCounts', {
										proxied: String(data.stats && data.stats.proxied),
										direct: String((data.stats && data.stats.decisions) - (data.stats && data.stats.proxied) - (data.stats && data.stats.rejected)),
									}),
								),
								data.status && data.status.lastError ? t('statusLastError', { error: data.status.lastError }) : '',
							)
						: null,
					data && data.diagnostics
						? h(
								'p',
								{ className: 'mp-hint' },
								t('statusSystemProxy', {
									status: String(data.diagnostics.systemProxy.status),
									detail: String(data.diagnostics.systemProxy.detail),
								}),
							)
						: null,
					degradedExits.length > 0
						? h(
								'div',
								null,
								degradedExits.map(function (entry, index) {
									return h(
										'p',
										{ className: 'mp-warn', key: 'degraded-' + String(index) },
										t('degraded', { exit: entry.exitId, failures: String(entry.failures) }),
									);
								}),
							)
						: null,
					data && data.warnings && data.warnings.length > 0
						? h(
								'div',
								null,
								data.warnings.map(function (warning, index) {
									return h('p', { className: 'mp-warn', key: String(index) }, '⚠ ' + warning);
								}),
							)
						: null,
					h(
						'div',
						{ style: { display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginTop: 8 } },
						h(
							'button',
							{
								type: 'button',
								className: 'mp-btn',
								disabled: probeInfo.running || state.view === null,
								onClick: runProbe,
							},
							probeInfo.running ? t('probeRunning') : t('probeButton'),
						),
						probeInfo.result
							? h(
									'p',
									{ className: probeInfo.result.ok ? 'mp-ok' : 'mp-err', style: { margin: 0 } },
									probeInfo.result.ok
										? t('probeOk', { ms: String(probeInfo.result.ms), status: String(probeInfo.result.status), via: String(probeInfo.result.via) })
										: t('probeFail', {
												ms: String(probeInfo.result.ms),
												via: String(probeInfo.result.via || '-'),
												failure: String(probeInfo.result.failure || probeInfo.result.error || ''),
											}),
								)
							: null,
					),
					t('probeHint'),
				),
				h(
					'div',
					{ className: 'mp-actions' },
					h(
						'button',
						{ type: 'button', className: 'mp-btn mp-btn--primary', disabled: !writable || saveInfo.saving, onClick: save },
						saveInfo.saving ? t('saving') : t('save'),
					),
					saveInfo.saved ? h('span', { className: 'mp-ok' }, t('saved')) : null,
					saveInfo.failed ? h('span', { className: 'mp-err' }, t('saveFailed', { error: saveInfo.failed })) : null,
					data ? h('span', { className: 'mp-hint' }, active ? t('active') : t('inactive')) : null,
				),
			);
		}

		// ── 挂载：设置里独立一页 ────────────────────────────────
		function apply(ctx) {
			try {
				if (typeof ctx.effect === 'function') {
					ctx.effect(function () {
						installStyles();
						return function () {
							if (typeof document === 'undefined') return;
							var tag = document.querySelector('style[data-plugin="dsh-model-proxy"]');
							if (tag !== null && tag.parentNode !== null) tag.parentNode.removeChild(tag);
						};
					}, 'dsh-model-proxy: styles');
				} else {
					installStyles();
				}
			} catch (error) {
				installStyles();
			}

			// 注册中英文字典。两种语言都必须给（宿主编译器会校验）。
			try {
				if (ctx.locale !== undefined && typeof ctx.locale.register === 'function') {
					var off = ctx.locale.register(NS, MESSAGES);
					if (typeof ctx.effect === 'function') {
						ctx.effect(function () {
							return function () {
								try {
									off?.();
								} catch (error) {
									/* 卸载期失败不影响主流程 */
								}
							};
						}, 'dsh-model-proxy: locale dictionary');
					}
				}
			} catch (error) {
				/* locale 不可用 → 走下面的中文兜底，页面仍然可用 */
			}

			/**
			 * 文案函数：优先用宿主的 locale，其次中文兜底。
			 * 每次渲染都重新 bind，这样切换语言能立刻生效。
			 */
			function bindT() {
				try {
					if (ctx.locale !== undefined && typeof ctx.locale.bind === 'function') {
						var bound = ctx.locale.bind(NS);
						if (typeof bound === 'function') return bound;
					}
				} catch (error) {
					/* 落到兜底 */
				}
				return makeFallbackT();
			}

			var api = createApi(ctx);
			ctx.slots.inject('settings.section', function () {
				return ctx.slots.register(
					{
						name: 'settings.section',
						id: NS,
						order: 61,
						label: function () {
							return bindT()('sectionLabel');
						},
					},
					function () {
						return h(ModelProxySection, { api: api, t: bindT() });
					},
				);
			});
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	},
});
