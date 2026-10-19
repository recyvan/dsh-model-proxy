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

		var NS = 'model-proxy';
		var ROUTE = '/dsh-model-proxy';
		/** 需要的客户端服务：槽位 + remote 命名空间（settings 读写）。 */
		var inject = ['slots', 'remote', 'remote.settings'];

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
				h('h2', { className: 'mp-title' }, '模型代理'),
				h('p', { className: 'mp-desc' }, '让境外模型 API 经代理访问；网页搜索、页面抓取、MCP 和工具调用等其它请求保持直连。'),
				state.loading ? h('p', { className: 'mp-hint' }, '读取设置中…') : null,
				state.error ? h('p', { className: 'mp-err' }, '读取设置失败：' + state.error) : null,
				state.loading === false && state.error === '' && state.view === null
					? h('p', { className: 'mp-err' }, '本部署没有向页面暴露 model-proxy 设置命名空间：请确认插件已启用，或在 cordis.patch.yml 里配置。')
					: null,
				state.view !== null && !writable ? h('p', { className: 'mp-hint' }, '当前页面只能读取设置（非回环访问或设置只读），改动请在桌面端进行。') : null,
				makeField(
					'模式',
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
						h('option', { value: 'rule' }, '规则分流（推荐）：只让指定域名走代理'),
						h('option', { value: 'system' }, '跟随系统代理：全部模型请求走系统代理'),
						h('option', { value: 'custom' }, '自定义代理：全部模型请求走下方代理'),
						h('option', { value: 'off' }, '关闭：全部直连'),
					),
					'规则分流下，未命中规则的请求直连；系统 / 自定义模式下，未命中规则的请求才走代理。',
				),
				showProxy
					? makeField(
							'代理协议',
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
								h('option', { value: 'socks5h' }, 'SOCKS5H（代理侧解析 DNS，抗污染）'),
								h('option', { value: 'socks4' }, 'SOCKS4'),
							),
							'能访问到境外 API 的代理。国内直连被污染时优先 SOCKS5h。',
						)
					: null,
				showProxy
					? makeField(
							'代理地址',
							h('input', {
								className: 'mp-input',
								type: 'text',
								placeholder: 'socks5h://127.0.0.1:7890 或 127.0.0.1:7890',
								value: form.proxyUri,
								disabled: !writable,
								onChange: function (event) {
									edit('proxyUri', event.target.value);
								},
							}),
							'只填 host:port 时按上面的协议自动补全。不要把密码写进保存的配置里，如需认证请在代理程序侧放行本机。',
						)
					: null,
				showProxy
					? makeField(
							'只代理这些域名',
							h('input', {
								className: 'mp-input',
								type: 'text',
								placeholder: '留空 = 内置预设（境外模型域名走代理、国内直连）',
								value: form.proxyHosts,
								disabled: !writable,
								onChange: function (event) {
									edit('proxyHosts', event.target.value);
								},
							}),
							'逗号分隔。支持 api.openai.com、*.openai.com、.aiplatform.googleapis.com。' +
								(suggestions.length > 0 ? ' 可选：' + suggestions.slice(0, 6).join(' / ') + ' …' : ''),
						)
					: null,
				showProxy
					? makeField(
							'排除域名',
							h('input', {
								className: 'mp-input',
								type: 'text',
								placeholder: 'api.deepseek.com, *.corp.example',
								value: form.excludeHosts,
								disabled: !writable,
								onChange: function (event) {
									edit('excludeHosts', event.target.value);
								},
							}),
							'优先级最高，永远直连（本机、内网与 .local 等已强制直连，无需填写）。',
						)
					: null,
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
						'允许明文 http 目标（不推荐：API Key 会以明文经过代理）',
					),
				),
				makeField(
					'日志级别',
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
						h('option', { value: 'silent' }, 'silent：不输出'),
						h('option', { value: 'error' }, 'error：只输出错误'),
						h('option', { value: 'warn' }, 'warn：错误与警告'),
						h('option', { value: 'info' }, 'info：默认'),
						h('option', { value: 'debug' }, 'debug：含目标主机名，排查用'),
					),
					'debug 会把目标主机名写进日志；平时保持 info。',
				),
				h(
					'div',
					{ className: 'mp-field' },
					h('p', { className: 'mp-hint' }, '运行状态'),
					live.loading ? h('p', { className: 'mp-hint' }, '读取中…') : null,
					live.error ? h('p', { className: 'mp-err' }, '读取状态失败：' + live.error) : null,
					data
						? h(
								'p',
								{ className: 'mp-hint' },
								h('span', { className: 'mp-tag' }, '路径 ' + String(data.diagnostics && data.diagnostics.path)),
								h('span', { className: 'mp-tag' }, '出口 ' + String(data.status && data.status.exitId ? data.status.exitId : '-')),
								h('span', { className: 'mp-tag' }, '规则 ' + String(data.progress && data.progress.ruleCount)),
								h(
									'span',
									{ className: 'mp-tag' },
									'请求 代理 ' + String(data.stats && data.stats.proxied) + ' / 直连 ' + String((data.stats && data.stats.decisions) - (data.stats && data.stats.proxied) - (data.stats && data.stats.rejected)),
								),
								data.status && data.status.lastError ? ' · 最近错误：' + data.status.lastError : '',
							)
						: null,
					data && data.diagnostics ? h('p', { className: 'mp-hint' }, '系统代理：' + String(data.diagnostics.systemProxy.status) + ' — ' + String(data.diagnostics.systemProxy.detail)) : null,
					degradedExits.length > 0
						? h(
								'div',
								null,
								degradedExits.map(function (entry, index) {
									return h(
										'p',
										{ className: 'mp-warn', key: 'degraded-' + String(index) },
										'⚠ 出口 ' + entry.exitId + ' 已降级（连续失败 ' + String(entry.failures) + ' 次），当前回落直连；恢复后会自动重新启用。',
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
				),
				h(
					'div',
					{ className: 'mp-actions' },
					h(
						'button',
						{ type: 'button', className: 'mp-btn mp-btn--primary', disabled: !writable || saveInfo.saving, onClick: save },
						saveInfo.saving ? '保存中…' : '保存',
					),
					saveInfo.saved ? h('span', { className: 'mp-ok' }, '已保存 ✓ 下一次请求生效') : null,
					saveInfo.failed ? h('span', { className: 'mp-err' }, '保存失败：' + saveInfo.failed) : null,
					data ? h('span', { className: 'mp-hint' }, active ? '插件运行中' : '插件未启用') : null,
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

			var api = createApi(ctx);
			ctx.slots.inject('settings.section', function () {
				return ctx.slots.register(
					{
						name: 'settings.section',
						id: NS,
						order: 61,
						label: function () {
							return '模型代理';
						},
					},
					function () {
						return h(ModelProxySection, { api: api });
					},
				);
			});
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	},
});
