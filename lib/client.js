window.__ModuleLoader__.load({
	id: 'dsh-model-proxy',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		// dsh-model-proxy 设置卡片：模型 API 出口代理。
		// 契约同 dsh-http-proxy / dsh-session-pulse：settings.plugin.item 槽位 + settingsScope 命名空间读写。
		'use strict';
		var React = require('react');

		var h = React.createElement;
		var useState = React.useState;
		var useEffect = React.useEffect;
		var useMemo = React.useMemo;

		var NS = 'model-proxy';
		var ROUTE = '/dsh-model-proxy';
		var inject = ['slots', 'settingsScope'];

		// ── 样式（一次性注入，带插件标记去重） ──────────────────
		var CSS = [
			'.mp-card{border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);border-radius:12px;list-style:none}',
			'.mp-header{appearance:none;width:100%;font:inherit;color:inherit;text-align:left;cursor:pointer;background:0 0;border:0;border-radius:12px;display:flex;align-items:center;gap:12px;padding:14px 16px}',
			'.mp-headText{display:flex;flex-direction:column;flex:1;gap:4px;min-width:0}',
			'.mp-name{color:var(--dsw-alias-label-primary);font-size:15px;font-weight:600}',
			'.mp-desc{color:var(--dsw-alias-label-tertiary);font-size:13px}',
			'.mp-badge{border-radius:999px;padding:1px 8px;font-size:11px;font-weight:500;flex:none;background:var(--dsw-alias-bg-module-platform);color:var(--dsw-alias-label-secondary)}',
			'.mp-badge--on{background:rgba(47,158,68,.14);color:#2f9e44}',
			'.mp-body{border-top:1px solid var(--dsw-alias-border-l2);margin:0 16px;padding-bottom:10px}',
			'.mp-field{display:flex;flex-direction:column;gap:6px;padding:12px 0}',
			'.mp-field+.mp-field{border-top:1px solid var(--dsw-alias-border-l2)}',
			'.mp-label{display:flex;align-items:center;gap:8px;color:var(--dsw-alias-label-primary);font-size:13px;font-weight:500}',
			'.mp-label small{color:var(--dsw-alias-label-tertiary);font-weight:400}',
			'.mp-input,.mp-select{border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);height:34px;font:inherit;color:var(--dsw-alias-label-primary);border-radius:8px;padding:0 12px;font-size:13px;width:100%;box-sizing:border-box}',
			'.mp-row{display:flex;gap:8px}',
			'.mp-row>*{flex:1}',
			'.mp-hint{color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:1.6;margin:0}',
			'.mp-warn{color:#b26a00;font-size:12px;line-height:1.6;margin:0}',
			'.mp-err{color:#c2182f;font-size:12px;margin:0}',
			'.mp-actions{display:flex;align-items:center;gap:10px;padding-top:12px}',
			'.mp-status{font-size:12px;color:var(--dsw-alias-label-tertiary)}',
			'.mp-status--ok{color:#2f9e44}',
			'.mp-btn{appearance:none;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-primary);border-radius:8px;padding:0 14px;height:32px;font:inherit;font-size:13px;cursor:pointer}',
			'.mp-btn--primary{background:var(--dsw-alias-brand-primary);color:#fff;border-color:transparent}',
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

		// ── 表单状态 ───────────────────────────────────────────
		function fromValue(value) {
			var v = value || {};
			return {
				mode: typeof v.mode === 'string' ? v.mode : 'rule',
				proxyType: typeof v.proxyType === 'string' ? v.proxyType : 'http',
				proxyUri: typeof v.proxyUri === 'string' ? v.proxyUri : '',
				proxy: typeof v.proxy === 'string' ? v.proxy : '',
				proxyHosts: joinList(v.proxyHosts),
				excludeHosts: joinList(v.excludeHosts),
				allowInsecureUpstream: v.allowInsecureUpstream === true,
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

		// ── 状态面板：读诊断路由（同源只读） ───────────────────
		function useStatus(open) {
			var state = useState({ loading: false, data: null, error: '' });
			var pair = state;
			useEffect(
				function () {
					if (!open) return undefined;
					var cancelled = false;
					pair[1]({ loading: true, data: null, error: '' });
					fetch(ROUTE + '/status', { headers: { accept: 'application/json' } })
						.then(function (response) {
							if (!response.ok) throw new Error('HTTP ' + response.status);
							return response.json();
						})
						.then(function (data) {
							if (!cancelled) pair[1]({ loading: false, data: data, error: '' });
						})
						.catch(function (error) {
							if (!cancelled) pair[1]({ loading: false, data: null, error: String(error && error.message ? error.message : error) });
						});
					return function () {
						cancelled = true;
					};
				},
				[open],
			);
			return pair[0];
		}

		// ── 卡片 ───────────────────────────────────────────────
		function ModelProxyCard(props) {
			var openState = useState(false);
			var open = openState[0];
			var setOpen = openState[1];

			var scopeRef = React.useRef(null);
			var scopeState = useState(null);
			var setScope = scopeState[1];

			var draftState = useState(null);
			var draft = draftState[0];

			var saveState = useState({ saving: false, saved: false, failed: '' });
			var saveInfo = saveState[0];
			var setSaveInfo = saveState[1];

			useEffect(
				function () {
					var disposers = [];
					try {
						var bound = props.settingsScope.bind({ namespace: NS });
						scopeRef.current = bound;
						setScope(bound);
						setDraft(fromValue(bound.getSnapshot().value));
						disposers.push(
							bound.subscribe(function () {
								var snapshot = bound.getSnapshot();
								if (snapshot && snapshot.status === 'ready') setDraft(fromValue(snapshot.value));
							}),
						);
					} catch (error) {
						scopeRef.current = null;
						setScope(null);
					}
					return function () {
						for (var i = 0; i < disposers.length; i += 1) {
							try {
								disposers[i]();
							} catch (error) {
								/* noop */
							}
						}
					};
				},
				[props.settingsScope],
			);

			var status = useStatus(open);
			var writable = scope !== null && scope.getSnapshot && scope.getSnapshot().writable !== false;
			var form = draft || fromValue(null);

			function edit(fieldName, value) {
				setDraft(function (previous) {
					var next = Object.assign({}, previous || fromValue(null));
					next[fieldName] = value;
					return next;
				});
				setSaveInfo({ saving: false, saved: false, failed: '' });
			}

			function save() {
				var bound = scopeRef.current;
				if (bound === null) return;
				setSaveInfo({ saving: true, saved: false, failed: '' });
				var writes = [];
				function setOrUnset(key, value, isEmpty) {
					writes.push(isEmpty ? bound.unset(key) : bound.set(key, value));
				}
				var proxyUris = splitList(form.proxyUri);
				var proxyHosts = splitList(form.proxyHosts);
				var excludeHosts = splitList(form.excludeHosts);
				setOrUnset('mode', form.mode, false);
				setOrUnset('proxyType', form.proxyType, false);
				setOrUnset('proxyUri', proxyUris[0], proxyUris.length === 0);
				setOrUnset('proxy', proxyUris.slice(1).join(', '), proxyUris.length <= 1);
				setOrUnset('proxyHosts', proxyHosts, proxyHosts.length === 0);
				setOrUnset('excludeHosts', excludeHosts, excludeHosts.length === 0);
				setOrUnset('allowInsecureUpstream', form.allowInsecureUpstream, form.allowInsecureUpstream === false);
				Promise.all(writes)
					.then(function () {
						setSaveInfo({ saving: false, saved: true, failed: '' });
					})
					.catch(function (error) {
						setSaveInfo({ saving: false, saved: false, failed: String(error && error.message ? error.message : error) });
					});
			}

			var data = status.data;
			var active = !!(data && data.status && data.status.active);
			var suggestions = (data && data.suggestions) || [];
			var field = makeField;

			return h(
				'li',
				{ className: 'mp-card' },
				h(
					'button',
					{
						type: 'button',
						className: 'mp-header',
						'aria-expanded': open,
						onClick: function () {
							setOpen(!open);
						},
					},
					h(
						'span',
						{ className: 'mp-headText' },
						h('span', { className: 'mp-name' }, '模型代理（Model Proxy）'),
						h('span', { className: 'mp-desc' }, '让境外模型 API 经代理访问；Web 搜索、MCP 等其它请求保持直连。'),
					),
					data
						? h('span', { className: active ? 'mp-badge mp-badge--on' : 'mp-badge' }, active ? '已启用 · ' + String(data.mode || '') : '未启用')
						: null,
					h('span', { className: 'mp-badge' }, open ? '收起' : '展开'),
				),
				open
					? h(
							'div',
							{ className: 'mp-body' },
							scope === null
								? h('p', { className: 'mp-err' }, '设置服务不可用：本部署未向页面提供 settingsScope，请改用配置层（cordis.patch.yml）设置。')
								: null,
							field(
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
							form.mode === 'system' || form.mode === 'off'
								? null
								: field(
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
											h('option', { value: 'socks5h' }, 'SOCKS5h（代理侧解析 DNS，抗污染）'),
											h('option', { value: 'socks4' }, 'SOCKS4'),
										),
										'能访问到境外 API 的代理。国内直连被污染时优先 SOCKS5h。',
									),
							form.mode === 'system' || form.mode === 'off'
								? null
								: field(
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
									),
							form.mode === 'system' || form.mode === 'off'
								? null
								: field(
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
									),
							form.mode === 'system' || form.mode === 'off'
								? null
								: field(
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
									),
							field(
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
							data && data.warnings && data.warnings.length > 0
								? h(
										'div',
										{ className: 'mp-field' },
										data.warnings.map(function (warning, index) {
											return h('p', { className: 'mp-warn', key: String(index) }, '⚠ ' + warning);
										}),
									)
								: null,
							h(
								'div',
								{ className: 'mp-field' },
								h('p', { className: 'mp-hint' }, '运行状态'),
								status.loading ? h('p', { className: 'mp-hint' }, '读取中…') : null,
								status.error ? h('p', { className: 'mp-err' }, '读取状态失败：' + status.error) : null,
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
							),
							h(
								'div',
								{ className: 'mp-actions' },
								h(
									'button',
									{ type: 'button', className: 'mp-btn mp-btn--primary', disabled: !writable || saveInfo.saving, onClick: save },
									saveInfo.saving ? '保存中…' : '保存',
								),
								saveInfo.saved ? h('span', { className: 'mp-status mp-status--ok' }, '已保存 ✓ 下一次请求生效') : null,
								saveInfo.failed ? h('span', { className: 'mp-err' }, '保存失败：' + saveInfo.failed) : null,
								status.data ? h('span', { className: 'mp-status' }, status.data.status && status.data.status.active ? '插件运行中' : '插件未启用') : null,
							),
						)
					: null,
			);
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

		// ── 挂载 ───────────────────────────────────────────────
		function apply(ctx) {
			try {
				if (typeof ctx.effect === 'function') {
					ctx.effect(function () {
						installStyles();
					}, 'dsh-model-proxy: styles');
				} else {
					installStyles();
				}
			} catch (error) {
				installStyles();
			}
			ctx.slots.inject('settings.plugin.item', function () {
				return ctx.slots.register(
					{
						name: 'settings.plugin.item',
						key: NS,
						registrant: 'dsh-model-proxy',
						inject: function () {
							return {
								settingsScope: ctx.settingsScope,
							};
						},
					},
					ModelProxyCard,
				);
			});
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	},
});
