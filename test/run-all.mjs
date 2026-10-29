/**
 * 测试总入口：`npm test`（等价于 `node test/run-all.mjs`）
 *
 * 分两段跑。
 *
 * 第一段，纯逻辑七组（不依赖写坏的配置就能跳过）：
 * 1. 匹配器 —— 域名/后缀/IP/CIDR/脱敏/代理 URL/系统代理字符串，纯函数零网络
 * 2. 规则引擎 —— 优先级、强制直连不可覆盖、明文闸门、explain
 * 3. 预设 + 配置归一化 —— 安全默认只增不减
 * 4. Windows 系统代理 —— 注入假的 reg.exe 输出，不真读注册表
 * 5. 真实代理链路 —— 本地起 HTTP 代理桩 + 目标服务器，验证 CONNECT/绝对形式真的走了代理
 * 6. 出口解析 —— 纯函数，不建连接
 * 7. 安全断言 —— 源码里不存在读取 API Key / 改全局 dispatcher / 改环境变量的写法
 *
 * 第二段，入口文件冒烟（历史上真正坏过两次的地方）：
 * 8. host-smoke —— 用真 schemastery + 活引用配置跑 `lib/index.js`：
 *    apply、诊断路由、`loader/volatile-update` 热更新、写入校验、卸载恢复
 * 9. client-smoke —— 打桩 `__ModuleLoader__`/React 跑 `lib/client.js`：
 *    inject 不含 settingsScope、注册到 settings.section、组件可渲染
 *
 * undici 与 schemastery 都由 DSH 宿主提供。本机没 `npm install` 时会自动去 DSH profile 的
 * node_modules 里找（见 test/resolve-host-deps.mjs）；找不到就跳过依赖它的组，其余照常跑。
 */

import { connect as netConnect } from 'node:net';
import { createServer, request } from 'node:http';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as h from './harness.mjs';
import { importPackage, resolvePackageDir, resolveSchemasteryDir } from './resolve-host-deps.mjs';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));

const { suite, ok, eq, deepEq, includes, notIncludes, rejects } = h;

// 本机同时装着 DSH 桌面版和它的开发依赖树；让解析顺序稳定指向桌面版 profile
// （用户实际在跑的那份），除非调用方显式指定了 DSH_HOME。
if (!process.env.DSH_HOME) {
	const devRoot = join(process.cwd(), '..', '..');
	if (existsSync(join(devRoot, 'dsh-home', 'profiles', 'desktop'))) {
		process.env.DSH_HOME = join(devRoot, 'dsh-home');
	}
}

// ── undici：本地 → DSH profile（都找不到就跳过相关两组） ──
const undiciModule = await importPackage('undici', 'index.js');
const hasUndici = undiciModule !== undefined;
if (!hasUndici) {
	console.log('\n⚠ 未解析到 undici：跳过「代理链路」与「出口解析」两组用例，其余照常执行。');
	console.log('  在插件目录执行 npm install，或设置 DSH_HOME 指向 DSH 数据目录后重跑。\n');
}

// ── 被测模块（纯逻辑，不依赖 DSH；不用 lib/index.js，它要 schemastery）──
const match = await import('../lib/core/match.js');
const rules = await import('../lib/core/rules.js');
const route = await import('../lib/core/route.js');
const dispatcher = await import('../lib/core/dispatcher.js');
const systemProxy = await import('../lib/core/system-proxy.js');
const configMod = await import('../lib/core/config.js');
const presets = await import('../lib/core/presets.js');

if (hasUndici) dispatcher.setUndici(undiciModule);

// ═══════════════════════════════════════════════════════════
// 1. 匹配器
// ═══════════════════════════════════════════════════════════

suite('match', async (test) => {
	test('hostMatches 精确匹配忽略大小写', () => {
		ok(match.hostMatches('Api.OpenAI.com', 'api.openai.com'));
		ok(!match.hostMatches('api.openai.com', 'api.anthropic.com'));
	});

	test('hostMatches 后缀匹配含子域但不含同名前缀串', () => {
		ok(match.hostMatches('api.openai.com', '.openai.com'));
		ok(match.hostMatches('a.b.openai.com', '.openai.com'));
		ok(match.hostMatches('openai.com', '.openai.com'));
		ok(!match.hostMatches('notopenai.com', '.openai.com'));
		ok(!match.hostMatches('openai.com.evil.com', '.openai.com'));
		ok(!match.hostMatches('xopenai.com', '.openai.com'));
	});

	test('hostMatches 通配写法与后缀等价', () => {
		ok(match.hostMatches('api.openai.com', '*.openai.com'));
		ok(!match.hostMatches('openai.com.evil.com', '*.openai.com'));
	});

	test('compileHostSet 精确 + 后缀', () => {
		const set = match.compileHostSet(['api.openai.com', '*.googleapis.com']);
		ok(set.has('api.openai.com'));
		ok(set.has('generativelanguage.googleapis.com'));
		ok(!set.has('openai.com'));
	});

	test('IPv4 CIDR', () => {
		const cidr = match.parseCidr('10.0.0.0/8');
		ok(match.ipInCidr('10.1.2.3', cidr));
		ok(!match.ipInCidr('11.1.2.3', cidr));
	});

	test('IPv6 CIDR 与压缩形式', () => {
		const loop = match.parseCidr('::1/128');
		ok(match.ipInCidr('::1', loop));
		ok(!match.ipInCidr('::2', loop));
		const ula = match.parseCidr('fc00::/7');
		ok(match.ipInCidr('fd12:3456::1', ula));
	});

	test('isAlwaysDirect 覆盖私有网段/私有域/localhost', () => {
		for (const host of ['localhost', '127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '127.1.2.3', '::1', 'fd00::1', 'foo.local', 'printer.lan', 'svc.internal']) {
			ok(match.isAlwaysDirect(host), `expected always-direct: ${host}`);
		}
		// 公网 IP 与公网域名允许走代理（否则用户没法用 IP 直连境外端点）
		ok(!match.isAlwaysDirect('8.8.8.8'));
		ok(!match.isAlwaysDirect('1.2.3.4'));
		ok(!match.isAlwaysDirect('api.openai.com'));
		ok(!match.isAlwaysDirect('api.deepseek.com'));
	});

	test('isAlwaysDirect 支持用户追加网段（只增不减）', () => {
		ok(match.isAlwaysDirect('45.1.2.3', { cidrs: ['45.0.0.0/8'] }));
		ok(!match.isAlwaysDirect('45.1.2.3'));
	});

	test('parseProxyUrl 拒绝不支持的协议', () => {
		const bad = match.parseProxyUrl('ftp://1.2.3.4:21');
		eq(bad.ok, false);
		includes(bad.error, 'ftp');
	});

	test('parseProxyUrl 支持 http/https/socks4a/socks5h', () => {
		for (const scheme of ['http', 'https', 'socks4a', 'socks5h', 'socks5']) {
			const parsed = match.parseProxyUrl(`${scheme}://127.0.0.1:7890`);
			ok(parsed.ok, `scheme ${scheme} should parse`);
		}
	});

	test('parseProxyUrl 能识别内嵌凭据', () => {
		const parsed = match.parseProxyUrl('http://u:p@10.0.0.1:8080');
		ok(parsed.ok);
		eq(parsed.hasAuth, true);
	});

	test('redactUrlText 抹掉 userinfo 与 key 参数', () => {
		const out = match.redactUrlText('http://user:pass@1.2.3.4:8080/x?api_key=SECRET&b=1');
		includes(out, '***@');
		notIncludes(out, 'SECRET');
		notIncludes(out, 'user:pass');
	});

	test('redactMessage 抹掉疑似密钥', () => {
		notIncludes(match.redactMessage('failed for key sk-abcdefghijklmnop'), 'sk-abcdefghijklmnop');
	});

	test('parseWindowsProxyServer 支持单值与分协议形式', () => {
		deepEq(match.parseWindowsProxyServer('127.0.0.1:7890'), ['http://127.0.0.1:7890']);
		const multi = match.parseWindowsProxyServer('http=1.2.3.4:8080;https=1.2.3.4:8443;socks=5.6.7.8:1080');
		eq(multi[0], 'http://1.2.3.4:8080');
		ok(multi.includes('socks5://5.6.7.8:1080'));
	});

	test('parseNoProxyList 识别 <local> 与后缀', () => {
		const parsed = match.parseNoProxyList('<local>;*.corp.example;10.*');
		eq(parsed.localMatch, true);
		ok(parsed.suffixes.includes('.corp.example'));
	});

	test('readEnvProxy 只认非空值', () => {
		eq(match.readEnvProxy({}), undefined);
		const env = match.readEnvProxy({ HTTPS_PROXY: 'http://1.2.3.4:8080', NO_PROXY: 'localhost' });
		eq(env.https, 'http://1.2.3.4:8080');
		eq(env.noProxy, 'localhost');
	});
});

// ═══════════════════════════════════════════════════════════
// 2. 规则引擎
// ═══════════════════════════════════════════════════════════

suite('rules', async (test) => {
	const baseConfig = (over) => ({
		mode: 'rule',
		default: 'direct',
		proxies: [{ id: 'p1', type: 'http', host: '127.0.0.1', port: 7890 }],
		rules: [{ match: { type: 'domain', value: 'api.openai.com' }, action: 'p1' }],
		...over,
	});

	test('命中规则 → 出口', () => {
		const set = rules.compileRuleset(baseConfig());
		const decision = rules.decide('https://api.openai.com/v1/chat/completions', set);
		eq(decision.action, 'exit');
		eq(decision.exitId, 'p1');
		eq(decision.because, 'rule');
		eq(decision.ruleIndex, 0);
	});

	test('未命中 → 默认直连', () => {
		const set = rules.compileRuleset(baseConfig());
		const decision = rules.decide('https://example.com/', set);
		eq(decision.action, 'direct');
		eq(decision.because, 'default');
	});

	test('强制直连不可被规则覆盖', () => {
		const set = rules.compileRuleset(baseConfig({ rules: [{ match: { type: 'suffix', value: '*.local' }, action: 'p1' }] }));
		const decision = rules.decide('https://printer.local/', set);
		eq(decision.action, 'direct');
		eq(decision.because, 'always-direct');
	});

	test('私有 IP 直连', () => {
		const set = rules.compileRuleset(baseConfig({ rules: [{ match: { type: 'domain', value: '10.0.0.1' }, action: 'p1' }] }));
		eq(rules.decide('https://10.0.0.1/', set).action, 'direct');
	});

	test('明文 http 目标默认拒绝', () => {
		const set = rules.compileRuleset(baseConfig());
		const decision = rules.decide('http://api.openai.com/v1', set);
		eq(decision.action, 'reject');
		eq(decision.because, 'insecure-upstream');
	});

	test('allowInsecureUpstream 打开后放行明文', () => {
		const set = rules.compileRuleset(baseConfig({ policy: { allowInsecureUpstream: true } }));
		eq(rules.decide('http://api.openai.com/v1', set).action, 'exit');
	});

	test('mode=off 全部直连', () => {
		const set = rules.compileRuleset(baseConfig({ mode: 'off' }));
		eq(rules.decide('https://api.openai.com/', set).action, 'direct');
		eq(rules.decide('https://api.openai.com/', set).because, 'mode-off');
	});

	test('byProvider 优先于域名规则', () => {
		const set = rules.compileRuleset(baseConfig({ byProvider: { openai: 'p1' }, rules: [{ match: { type: 'suffix', value: '*.openai.com' }, action: 'direct' }] }));
		const decision = rules.decide('https://api.openai.com/', set, 'openai');
		eq(decision.action, 'exit');
		eq(decision.because, 'provider:openai');
	});

	test('未定义出口的规则 → 拒绝（不静默直连、也不静默换出口）', () => {
		const set = rules.compileRuleset(baseConfig({ rules: [{ match: { type: 'domain', value: 'api.openai.com' }, action: 'nope' }] }));
		const decision = rules.decide('https://api.openai.com/', set);
		eq(decision.action, 'reject');
	});

	test('reject 动作直接拒绝', () => {
		const set = rules.compileRuleset(baseConfig({ rules: [{ match: { type: 'domain', value: 'api.openai.com' }, action: 'reject' }] }));
		eq(rules.decide('https://api.openai.com/', set).action, 'reject');
	});

	test('无法解析的 URL 一律直连', () => {
		const set = rules.compileRuleset(baseConfig());
		eq(rules.decide('not a url', set).action, 'direct');
	});

	test('explainDecision 可读且不含 query', () => {
		const set = rules.compileRuleset(baseConfig());
		const text = rules.explainDecision(rules.decide('https://api.openai.com/v1/chat?key=SECRET', set));
		includes(text, 'api.openai.com');
		includes(text, 'p1');
		notIncludes(text, 'SECRET');
	});

	test('mode=system 未命中规则时走默认出口', () => {
		const set = rules.compileRuleset(baseConfig({ mode: 'system' }));
		const decision = rules.decide('https://example.com/', set);
		eq(decision.action, 'exit');
		eq(decision.exitId, 'p1');
	});

	test('cidr 规则（公网地址）', () => {
		const set = rules.compileRuleset(
			baseConfig({ proxies: [{ id: 'p1', type: 'http', host: '127.0.0.1', port: 1 }], rules: [{ match: { type: 'cidr', value: '203.0.113.0/24' }, action: 'p1' }] }),
		);
		eq(rules.decide('https://203.0.113.7/', set).action, 'exit');
		eq(rules.decide('https://198.51.100.7/', set).action, 'direct');
	});

	test('regex 规则', () => {
		const set = rules.compileRuleset(baseConfig({ rules: [{ match: { type: 'regex', value: '^api\\d+\\.example\\.com$' }, action: 'p1' }] }));
		eq(rules.decide('https://api2.example.com/', set).action, 'exit');
	});

	test('suffix 规则命中子域', () => {
		const set = rules.compileRuleset(baseConfig({ rules: [{ match: { type: 'suffix', value: '*.openai.com' }, action: 'p1' }] }));
		eq(rules.decide('https://api.openai.com/', set).action, 'exit');
		eq(rules.decide('https://openai.com.evil.com/', set).action, 'direct');
	});
});

// ═══════════════════════════════════════════════════════════
// 3. 预设与配置归一化
// ═══════════════════════════════════════════════════════════

suite('presets+config', async (test) => {
	test('预设覆盖主要境外厂商', () => {
		for (const host of ['api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com', 'api.x.ai', 'openrouter.ai']) {
			ok(presets.OVERSEAS_MODEL_HOSTS.includes(host), host);
		}
	});

	test('国内厂商在直连组', () => {
		ok(presets.DOMESTIC_MODEL_HOSTS.includes('api.deepseek.com'));
		ok(presets.DOMESTIC_MODEL_HOSTS.includes('dashscope.aliyuncs.com'));
	});

	test('defaultRulesFor 生成规则：境外→出口、国内→直连', () => {
		const list = presets.defaultRulesFor('p1');
		const openai = list.find((rule) => rule.match.value === 'api.openai.com');
		ok(openai !== undefined, 'openai rule should exist');
		eq(openai.action, 'p1');
		const deepseek = list.find((rule) => rule.match.value === 'api.deepseek.com');
		ok(deepseek !== undefined, 'deepseek rule should exist');
		eq(deepseek.action, 'direct');
		const templated = list.find((rule) => String(rule.match.value).includes('aiplatform.googleapis.com'));
		ok(templated !== undefined, 'templated suffix rule should exist');
		eq(templated.match.type, 'suffix');
	});

	test('预设规则经规则引擎后：境外走出口、国内与私网直连', () => {
		const set = rules.compileRuleset({
			mode: 'rule',
			default: 'direct',
			proxies: [{ id: 'p1', type: 'http', host: '127.0.0.1', port: 7890 }],
			rules: presets.defaultRulesFor('p1'),
		});
		eq(rules.decide('https://api.openai.com/v1/chat/completions', set).action, 'exit');
		eq(rules.decide('https://us-central1-aiplatform.googleapis.com/v1/models', set).action, 'exit');
		eq(rules.decide('https://api.deepseek.com/chat/completions', set).action, 'direct');
		eq(rules.decide('https://localhost:3000/', set).action, 'direct');
	});

	test('normalizeConfig 安全默认', () => {
		const cfg = configMod.normalizeConfig({});
		eq(cfg.mode, 'rule');
		eq(cfg.policy.allowInsecureUpstream, false);
		eq(cfg.policy.logLevel, 'info');
		ok(cfg.forceDirectHosts.length > 0);
	});

	test('normalizeConfig 强制直连项只增不减', () => {
		const cfg = configMod.normalizeConfig({ forceDirectHosts: ['*.abcdef.example'] });
		ok(cfg.forceDirectHosts.includes('*.abcdef.example'));
		ok(cfg.forceDirectHosts.includes('.local'));
		ok(cfg.forceDirectHosts.includes('10.0.0.0/8'));
	});

	test('normalizeConfig 非法 mode 回落 rule', () => {
		eq(configMod.normalizeConfig({ mode: 'whatever' }).mode, 'rule');
	});

	test('normalizeConfig 从 host/port 拼出代理 URI', () => {
		const cfg = configMod.normalizeConfig({ proxyType: 'socks5', proxyHost: '127.0.0.1', proxyPort: 1080 });
		eq(cfg.proxyUris[0], 'socks5://127.0.0.1:1080');
	});

	test('normalizeConfig 多个代理（逗号分隔）', () => {
		const cfg = configMod.normalizeConfig({ proxy: 'http://a:1, http://b:2' });
		deepEq(cfg.proxyUris, ['http://a:1', 'http://b:2']);
	});

	test('logLevel 白名单', () => {
		eq(configMod.normalizeConfig({ logLevel: 'trace' }).policy.logLevel, 'info');
		eq(configMod.normalizeConfig({ logLevel: 'debug' }).policy.logLevel, 'debug');
	});
});

// ═══════════════════════════════════════════════════════════
// 4. 系统代理解析（注入注册表值，不真读注册表）
// ═══════════════════════════════════════════════════════════

suite('system-proxy', async (test) => {
	test('parseRegQueryOutput 解析 reg 输出', () => {
		const values = systemProxy.parseRegQueryOutput(
			'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    127.0.0.1:7890\r\n',
		);
		eq(values.ProxyEnable, '0x1');
		eq(values.ProxyServer, '127.0.0.1:7890');
	});

	test('注册表启用 → 得到代理 URI', () => {
		const result = systemProxy.readSystemProxy({
			platform: 'win32',
			registryProvider: () => ({ ProxyEnable: '0x1', ProxyServer: '127.0.0.1:7890', ProxyOverride: '<local>;*.corp' }),
		});
		eq(result.status, 'ok');
		deepEq(result.proxies, ['http://127.0.0.1:7890']);
		eq(result.noProxy.localMatch, true);
	});

	test('注册表禁用 → disabled', () => {
		const result = systemProxy.readSystemProxy({ platform: 'win32', registryProvider: () => ({ ProxyEnable: '0x0', ProxyServer: '1.2.3.4:1' }) });
		eq(result.status, 'disabled');
	});

	test('非 Windows → unsupported', () => {
		eq(systemProxy.readSystemProxy({ platform: 'linux' }).status, 'unsupported');
	});

	test('注册表不可读 → unavailable（不抛异常）', () => {
		const result = systemProxy.readSystemProxy({
			platform: 'win32',
			registryProvider: () => {
				throw new Error('boom');
			},
		});
		eq(result.status, 'unavailable');
	});
});

// ═══════════════════════════════════════════════════════════
// 5. 真实代理链路：本地 HTTP 代理桩 + 本地目标服务器
// ═══════════════════════════════════════════════════════════

/**
 * 极简正向代理：CONNECT 隧道 + 绝对形式请求转发。
 *
 * undici 的 `ProxyAgent` 对不同目标形态会走不同路径：
 * - https 目标 → CONNECT 隧道（`server.on('connect')`）
 * - http 目标 → 绝对形式请求行（`GET http://host:port/path HTTP/1.1`），
 *   桩必须自己再发一次请求转发过去，否则用例只会拿到 405。
 *
 * `state.connects` 记 CONNECT 次数，`state.absolute` 记绝对形式请求次数，
 * 两者都能用来断言「请求真的经过了代理」；`state.connectTargets` 记每一条
 * CONNECT 的目标（`host:port` 字符串），链式用例据此判断每一跳拨向了谁。
 */
function startProxyStub(label = 'stub') {
	const state = { label, connects: 0, tunnelled: 0, absolute: 0, connectTargets: [] };
	const server = createServer((req, res) => {
		state.absolute += 1;
		let target;
		try {
			target = new URL(String(req.url));
		} catch {
			res.writeHead(400, { 'content-type': 'text/plain' });
			res.end('proxy stub: request line is not an absolute URL');
			return;
		}
		const forwarded = request(
			{
				protocol: target.protocol,
				hostname: target.hostname,
				port: target.port,
				method: req.method,
				path: `${target.pathname}${target.search}`,
				headers: { ...req.headers, host: target.host },
			},
			(upstream) => {
				res.writeHead(upstream.statusCode ?? 502, upstream.headers);
				upstream.pipe(res);
			},
		);
		forwarded.on('error', (error) => {
			if (res.writableEnded) return;
			res.writeHead(502, { 'content-type': 'text/plain' });
			res.end(`proxy stub: ${error.message}`);
		});
		req.pipe(forwarded);
	});
	server.on('connect', (req, socket, head) => {
		state.connects += 1;
		state.connectTargets.push(String(req.url));
		// CONNECT 目标可能是 `host:port` 或 `[ipv6]:port`；解析不出端口时
		// 明确返回 400，而不是把 NaN 丢给 net.connect（会抛 ERR_SOCKET_BAD_PORT，
		// 让整个测试进程挂掉、看不出是哪条用例）。
		const match = /^\[?([^\]]+?)\]?:(\d+)$/.exec(String(req.url));
		const port = match === null ? Number.NaN : Number(match[2]);
		const host = match === null ? '' : match[1];
		if (!Number.isInteger(port) || port <= 0 || port > 65535) {
			socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
			return;
		}
		const upstream = netConnect(port, host, () => {
			state.tunnelled += 1;
			socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
			if (head.length > 0) upstream.write(head);
			socket.pipe(upstream);
			upstream.pipe(socket);
		});
		upstream.on('error', () => socket.destroy());
		socket.on('error', () => upstream.destroy());
	});
	return new Promise((resolve) => {
		// 不设超时：桩本身只是转发，等待由测试用例控制
		server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, state }));
	});
}

if (hasUndici) {
	suite('routing', async (test) => {
		const proxyStub = await startProxyStub();
		const target = await new Promise((resolve) => {
			const server = createServer((req, res) => {
				res.writeHead(200, { 'content-type': 'application/json' });
				res.end(JSON.stringify({ via: 'target' }));
			});
			server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
		});
		const targetUrl = `http://127.0.0.1:${target.port}/hello`;

		test('经代理的请求会被代理桩看到', async () => {
			const cfg = { proxies: [{ id: 'p1', type: 'http', host: '127.0.0.1', port: proxyStub.port }] };
			const resolved = dispatcher.resolveExit({ kind: 'proxy', id: 'p1', proxy: cfg.proxies[0] }, { config: cfg, env: {} });
			ok(resolved.ok);
			const entry = await dispatcher.createDispatcher(resolved.uris);
			const beforeConnects = proxyStub.state.connects;
			const beforeAbsolute = proxyStub.state.absolute;
			const response = await undiciModule.fetch(targetUrl, { dispatcher: entry.dispatcher });
			const body = await response.json();
			eq(response.status, 200);
			// 响应体来自目标服务器 → 说明代理真的把请求转发了，而不是假的 200
			eq(body.via, 'target');
			// http 目标走绝对形式请求行；https 目标走 CONNECT。两种都算「经过了代理」。
			ok(
				proxyStub.state.connects > beforeConnects || proxyStub.state.absolute > beforeAbsolute,
				'proxy stub should receive the request (CONNECT or absolute form)',
			);
			await entry.close();
		});

		test('CONNECT 隧道（https 目标形态）真的经过代理', async () => {
			const before = proxyStub.state.connects;
			await new Promise((resolve, reject) => {
				const socket = netConnect(proxyStub.port, '127.0.0.1', () => {
					socket.write(`CONNECT 127.0.0.1:${target.port} HTTP/1.1\r\nHost: 127.0.0.1:${target.port}\r\n\r\n`);
				});
				socket.once('data', (chunk) => {
					includes(String(chunk), '200 Connection Established');
					socket.destroy();
					resolve();
				});
				socket.on('error', reject);
			});
			ok(proxyStub.state.connects > before);
		});

		test('直连请求不经过代理桩（强制直连判定）', async () => {
			const cfg = { mode: 'rule', default: 'direct', proxies: [{ id: 'p1', type: 'http', host: '127.0.0.1', port: proxyStub.port }], rules: [] };
			const ruleset = rules.compileRuleset(cfg);
			const pool = new dispatcher.ExitPool({ config: cfg });
			const routing = route.createRoutingFetch({ getRuleset: () => ruleset, pool });
			const before = proxyStub.state.connects;
			const decision = routing.decideOnly('http://127.0.0.1:1/never');
			eq(decision.action, 'direct');
			eq(decision.because, 'always-direct');
			eq(proxyStub.state.connects, before);
			await pool.close();
		});

		test('拒绝的请求不发起任何网络', async () => {
			const cfg = { mode: 'rule', default: 'reject', proxies: [{ id: 'p1', type: 'http', host: '127.0.0.1', port: proxyStub.port }], rules: [] };
			const ruleset = rules.compileRuleset(cfg);
			const pool = new dispatcher.ExitPool({ config: cfg });
			const routing = route.createRoutingFetch({ getRuleset: () => ruleset, pool });
			const before = proxyStub.state.connects;
			// 用真实公网域名：`.test` 属 RFC 2606 保留域，会被强制直连短路，测不到 reject
			await rejects(() => routing.fetch('https://api.reject-check.example.com/'));
			eq(proxyStub.state.connects, before);
			eq(routing.stats.rejected, 1);
			await pool.close();
		});

		test('熔断：连续失败后降级为直连', async () => {
			const health = new route.HealthTracker({ failoverAfter: 2, cooldownMs: 60_000 });
			health.record('p1', false);
			ok(!health.isDegraded('p1'));
			health.record('p1', false);
			ok(health.isDegraded('p1'));
			health.record('p1', true);
			ok(!health.isDegraded('p1'));
		});

		test('DecisionLog 只保留元数据且截断', () => {
			const log = new route.DecisionLog(3);
			for (let i = 0; i < 5; i += 1) log.push({ action: 'direct', host: `h${i}` });
			eq(log.items.length, 3);
			eq(log.tail(1)[0].host, 'h4');
		});

		test('classify 只给错误码/类别，不带原文', () => {
			eq(route.classify(Object.assign(new Error('boom'), { code: 'ECONNRESET' })), 'ECONNRESET');
			// `fetch failed` 的真实码在 cause 里，这里验证会继续往下按 message 分类
			eq(route.classify(new Error('socket hang up')), 'NETWORK');
			eq(route.classify(new Error('connect ETIMEDOUT')), 'TIMEOUT');
			// 外层带 UND 码但 cause 有真实码时，以 cause 为准
			eq(route.classify({ code: 'UND_ERR_SOCKET', cause: { code: 'ECONNRESET' } }), 'ECONNRESET');
		});
		// 注意：这里不能立刻 close()。harness 会先把用例登记下来、回调返回后才逐个执行，
		// 提前关闭会让所有用例连到已关闭的端口（表现为 ECONNREFUSED）。
		// 改为在所有用例跑完后统一关闭。
		h.cleanup(() => {
			proxyStub.server.close();
			target.server.close();
		});
	});
}

// ═══════════════════════════════════════════════════════════
// 5b. 代理链：每一跳真的拨向了下一跳
// ═══════════════════════════════════════════════════════════

if (hasUndici) {
	suite('chain', async (test) => {
		const makeTarget = () =>
			new Promise((resolve) => {
				const server = createServer((req, res) => {
					res.writeHead(200, { 'content-type': 'application/json' });
					res.end(JSON.stringify({ via: 'target' }));
				});
				server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
			});

		/**
		 * 起 N 个 CONNECT 桩 + 一个目标，按 `uris` 顺序折叠出 dispatcher，
		 * 断言每一跳实际拨向的端口都与期望一致。
		 * 这是「chainLength 不说谎」的唯一证据：只看最终 200 无法区分
		 * `h1->h2->h3->target` 与方向相反的 `h3->h2->h1->target`。
		 */
		const runChain = async (depth) => {
			const hops = [];
			for (let i = 0; i < depth; i += 1) hops.push(await startProxyStub(`h${i + 1}`));
			const target = await makeTarget();
			const uris = hops.map((hop) => `http://127.0.0.1:${hop.port}`);
			const entry = await dispatcher.createDispatcher(uris);
			try {
				const response = await undiciModule.fetch(`http://127.0.0.1:${target.port}/x`, { dispatcher: entry.dispatcher });
				const body = await response.json();
				eq(response.status, 200);
				eq(body.via, 'target', '响应必须来自目标服务器');
				eq(entry.chainLength, depth, `chainLength 必须等于真实跳数 ${depth}`);
				// 第 i 跳应当拨向第 i+1 跳；最后一跳拨向目标
				for (let i = 0; i < depth; i += 1) {
					const expectedPort = i + 1 < depth ? hops[i + 1].port : target.port;
					const actual = hops[i].state.connectTargets[0];
					eq(actual, `127.0.0.1:${expectedPort}`, `第 ${i + 1} 跳应拨向 ${expectedPort}，实际 ${actual}`);
				}
				// 没有哪一跳被跳过
				for (const hop of hops) ok(hop.state.connects > 0, `${hop.state.label} 应当收到过 CONNECT`);
			} finally {
				await entry.close();
				for (const hop of hops) hop.server.close();
				target.server.close();
			}
		};

		test('两跳：h1 -> h2 -> target，顺序与配置一致', async () => {
			await runChain(2);
		});

		test('三跳：h1 -> h2 -> h3 -> target，中间跳不被跳过', async () => {
			await runChain(3);
		});

		test('折叠方向反了会掉换出口身份（回归护栏）', async () => {
			// 这条用例证明上面的正序断言不是「怎么折都能过」：反向折叠时，
			// 内层（配置里的第一跳）收到的是**绝对形式请求行**（`http://host:port/path`），
			// 根本没有 CONNECT —— 也就是说第二跳被架空，隧道压根没建。
			// 正序实现的同一场景下，第一跳收到的必然是 `127.0.0.1:<第二跳端口>`。
			const h1 = await startProxyStub('h1');
			const h2 = await startProxyStub('h2');
			const target = await makeTarget();
			const inner = new undiciModule.ProxyAgent({ uri: `http://127.0.0.1:${h1.port}` });
			const outer = new undiciModule.ProxyAgent({
				uri: `http://127.0.0.1:${h2.port}`,
				clientFactory: () => inner,
				proxyTunnel: true,
			});
			try {
				await undiciModule
					.fetch(`https://127.0.0.1:${target.port}/x`, { dispatcher: outer })
					.catch(() => {});
				// 反向折叠：h1 收到的不是 CONNECT 到 h2，而是绝对形式请求（直接对目标）。
				ok(
					h1.state.connectTargets[0] !== `127.0.0.1:${h2.port}`,
					'反向折叠时 h1 不应拨向 h2——这正是正序实现与反向实现的差别',
				);
				ok(h1.state.absolute > 0 || h1.state.connectTargets[0]?.startsWith('http'), '反向折叠时 h1 收到的是绝对形式请求行');
			} finally {
				// 只关最外层：外层 close 会顺着 clientFactory 把内层一并关掉
				await outer.close().catch(() => {});
				h1.server.close();
				h2.server.close();
				target.server.close();
			}
		});

		test('单跳的 chainLength 是 1', async () => {
			const hop = await startProxyStub();
			const entry = await dispatcher.createDispatcher([`http://127.0.0.1:${hop.port}`]);
			eq(entry.chainLength, 1);
			await entry.close();
			hop.server.close();
		});
	});
}

// ═══════════════════════════════════════════════════════════
// 6. 出口解析（纯函数，不建连接）
// ═══════════════════════════════════════════════════════════

if (hasUndici) {
	suite('dispatcher-resolve', async (test) => {
		test('自定义 http 代理', () => {
			const ctx = { config: { proxies: [] }, env: {} };
			const resolved = dispatcher.resolveExit({ kind: 'proxy', id: 'p', proxy: { type: 'http', host: '1.2.3.4', port: 8080 } }, ctx);
			ok(resolved.ok);
			eq(resolved.uris[0], 'http://1.2.3.4:8080');
		});

		test('socks5h 归一为 socks5（远端解析 DNS）', () => {
			const ctx = { config: { proxies: [] }, env: {} };
			const resolved = dispatcher.resolveExit({ kind: 'proxy', id: 'p', proxy: { uri: 'socks5h://127.0.0.1:1080' } }, ctx);
			ok(resolved.ok);
			eq(resolved.uris[0], 'socks5://127.0.0.1:1080');
		});

		test('代理链按序展开', () => {
			const ctx = {
				config: {
					proxies: [
						{ id: 'a', type: 'http', host: '10.0.0.1', port: 8080 },
						{ id: 'b', type: 'socks5', host: '10.0.0.2', port: 1080 },
					],
				},
				env: {},
			};
			const resolved = dispatcher.resolveExit({ kind: 'chain', id: 'c', chain: { hops: ['a', 'b'] } }, ctx);
			ok(resolved.ok);
			deepEq(resolved.uris, ['http://10.0.0.1:8080', 'socks5://10.0.0.2:1080']);
		});

		test('代理链引用不存在的跳 → 报错', () => {
			const ctx = { config: { proxies: [] }, env: {} };
			const resolved = dispatcher.resolveExit({ kind: 'chain', id: 'c', chain: { hops: ['nope'] } }, ctx);
			eq(resolved.ok, false);
			includes(resolved.reason, 'nope');
		});

		test('系统代理出口：读到值就用，读不到就明确失败', () => {
			const okCtx = {
				config: { proxies: [] },
				env: {},
				systemProxy: () => ({ status: 'ok', proxies: ['http://127.0.0.1:7890'], noProxy: { suffixes: [], localMatch: true }, detail: '' }),
				systemCache: { at: 0, value: undefined },
			};
			const good = dispatcher.resolveExit({ kind: 'proxy', id: 's', proxy: { type: 'system' } }, okCtx);
			ok(good.ok);
			eq(good.uris[0], 'http://127.0.0.1:7890');

			const badCtx = {
				config: { proxies: [] },
				env: {},
				systemProxy: () => ({ status: 'disabled', proxies: [], noProxy: null, detail: '系统代理未启用' }),
				systemCache: { at: 0, value: undefined },
			};
			const bad = dispatcher.resolveExit({ kind: 'proxy', id: 's', proxy: { type: 'system' } }, badCtx);
			eq(bad.ok, false);
			includes(bad.reason, '系统代理');
		});

		test('env 出口读环境变量', () => {
			const ctx = { config: { proxies: [] }, env: { HTTPS_PROXY: 'http://9.9.9.9:3128' } };
			const resolved = dispatcher.resolveExit({ kind: 'proxy', id: 'e', proxy: { type: 'env' } }, ctx);
			ok(resolved.ok);
			eq(resolved.uris[0], 'http://9.9.9.9:3128');
		});
	});
}

// ═══════════════════════════════════════════════════════════
// 7. 安全断言
// ═══════════════════════════════════════════════════════════

suite('security', async (test) => {
	test('错误消息脱敏后不含完整 URL 与密钥', () => {
		const message = match.redactMessage('fetch failed for https://api.openai.com/v1?key=sk-abcdefghijklmnop with Authorization: Bearer xyz');
		notIncludes(message, 'sk-abcdefghijklmnop');
		notIncludes(message, 'Bearer xyz');
	});

	test('强制直连常量覆盖关键网段', () => {
		for (const cidr of ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7']) {
			ok(match.ALWAYS_DIRECT_CIDRS.includes(cidr), cidr);
		}
	});

	test('源码中不存在读取 provider API Key 的逻辑', () => {
		const root = fileURLToPath(new URL('../lib', import.meta.url));
		const files = collectJsFiles(root);
		ok(files.length > 0, 'should find lib files');
		for (const file of files) {
			// 注释里的示例文字不该触发断言
			const text = stripComments(readFileSync(file, 'utf8'));
			notIncludes(text, 'headers.authorization', file);
			notIncludes(text, 'Bearer ', file);
		}
	});

	test('不修改全局环境变量 / 不设置 global dispatcher', () => {
		const root = fileURLToPath(new URL('../lib', import.meta.url));
		for (const file of collectJsFiles(root)) {
			const text = stripComments(readFileSync(file, 'utf8'));
			notIncludes(text, 'setGlobalDispatcher', file);
			notIncludes(text, 'process.env.HTTPS_PROXY =', file);
			notIncludes(text, 'process.env.HTTP_PROXY =', file);
		}
	});
});

// ── 辅助 ────────────────────────────────────────────────────

/**
 * 监听一段代码里发生的 uncaughtException / unhandledRejection。
 * `apply()` 会换掉 `globalThis.fetch`，被测用例里的异步残留可能把事件漏出来；
 * 只收集「带插件命名空间前缀」的那些，避免把无关噪声算到用例头上。
 */
function captureProcessErrors() {	const caught = [];
	const onCaught = (error) => caught.push(error);
	process.on('uncaughtException', onCaught);
	process.on('unhandledRejection', onCaught);
	return {
		list: () => caught,
		stop: () => {
			process.off('uncaughtException', onCaught);
			process.off('unhandledRejection', onCaught);
		},
	};
}

// ── 冒烟部分：入口文件（需要 schemastery 与一个假的客户端宿主） ──
/** 宿主是否提供带 `volatile()` 的 schemastery（DSH 0.2.x 的入口文件依赖它）。 */
const needsSchemastery = resolveSchemasteryDir() !== undefined;
const schemasteryAvailable = needsSchemastery;
if (!schemasteryAvailable) {
	console.log(
		'\n⚠ 未解析到带 volatile() 的 @deepseek-ai/schemastery（需要 3.18.5+）：跳过「入口文件冒烟」两组用例。' +
			'\n  设置 DSH_HOME 指向 DSH 数据目录，或在插件目录 npm install 后重跑。\n',
	);
}

/**
 * `lib/index.js`（宿主一半）与 `lib/client.js`（客户端一半）才是历史上真正坏过两次的
 * 地方：`settingsScope` 挂死启动、peer 范围导致拒装。这里用最小假宿主把它们跑起来。
 *
 * harness 是「先注册、全部跑完后统一 run()」，所以套件里要用的真实模块由 `use()`
 * 在现场（run 之前）拉进来——模块加载只做一次，也不会因为顶层 await 时序错乱。
 */
function registerSmokeSuites(use) {
	if (!schemasteryAvailable) return;

	suite('host-smoke', async (test) => {
		const host = await use();
		const originalFetch = globalThis.fetch;
		const disposers = [];
		const events = new Map();
		let routeHandler;
		let ctx;

		const live = (value) => ({ get: () => value });
		const makeConfig = (mode) => ({
			mode: live(mode),
			defaultAction: live('direct'),
			proxy: live(''),
			proxyUri: live('socks5h://127.0.0.1:7890'),
			proxyType: live('socks5h'),
			proxyHost: live(''),
			proxyPort: live(0),
			proxyUser: live(''),
			proxyPassword: live(''),
			proxyHosts: live([]),
			excludeHosts: live([]),
			allowInsecureUpstream: live(false),
			extendToTools: live(false),
			logLevel: live('info'),
		});
		const makeCtx = () => {
			const instance = {
				logger: { info() {}, warn() {}, debug() {}, error() {} },
				effect(fn) {
					const dispose = fn();
					if (typeof dispose === 'function') disposers.push(dispose);
					return () => {};
				},
				on(event, cb) {
					events.set(event, cb);
					return () => events.delete(event);
				},
				inject(services, cb) {
					cb(instance);
					return { dispose() {} };
				},
				webServer: {
					register(spec) {
						routeHandler = spec.handler;
						return () => {};
					},
				},
			};
			return instance;
		};
		const readStatus = async () => {
			const text = await new Promise((resolve) => {
				const res = { writeHead() {}, end(body) { resolve(body); } };
				routeHandler({ method: 'GET', url: `${host.index.ROUTE_PATH}/status`, headers: { host: '127.0.0.1:3269' } }, res);
			});
			return JSON.parse(text);
		};

		test('Config schema 覆盖设置页字段，且不再有与 mode:off 重复的 enabled', () => {
			const keys = new Set(Object.keys(host.index.Config.dict ?? {}));
			for (const key of ['mode', 'proxyType', 'proxyUri', 'proxyHosts', 'excludeHosts', 'allowInsecureUpstream', 'logLevel']) {
				ok(keys.has(key), `Config 缺少字段 ${key}`);
			}
			ok(!keys.has('enabled'), 'enabled 已并入 mode:off，不应再出现在 Config 里');
		});

		test('readSettings 能解活引用，也能吃普通值', () => {
			const flat = host.index.readSettings(makeConfig('custom'));
			eq(flat.mode, 'custom');
			eq(flat.proxyUri, 'socks5h://127.0.0.1:7890');
			eq(flat.logLevel, 'info');
			eq(host.index.readSettings({ mode: 'off' }).mode, 'off');
			eq(host.index.readSettings(undefined).mode, 'rule');
		});

		test('assertValid 仍然拦得住写坏的组合（写入校验没丢）', async () => {
			// mode=custom 却没填地址
			await rejects(() => host.index.assertValid({ mode: 'custom' }), 'mode=custom 缺地址应被拒');
			// 不支持的代理协议
			await rejects(() => host.index.assertValid({ mode: 'custom', proxyUri: 'ftp://127.0.0.1:21' }), '不支持的协议应被拒');
			// 裸 host:port 而没选协议 → 会被当成 scheme=127.0.0.1 的 URL，必须在写入时就拒掉
			await rejects(() => host.index.assertValid({ mode: 'custom', proxyUri: '127.0.0.1:7890' }), '裸地址缺协议应被拒');
			// 合法组合照常通过：`127.0.0.1:7890` 本来就是设置页推荐的写法，
			// 前端保存时会补全协议；这里显式给出 proxyType，等价于「用户选了协议」。
			ok(host.index.assertValid({ mode: 'custom', proxyType: 'socks5h', proxyUri: 'socks5h://127.0.0.1:7890' }));
			ok(host.index.assertValid({ mode: 'custom', proxyUri: 'socks5h://127.0.0.1:7890' }));
		});

		test('apply 接管 globalThis.fetch，诊断路由返回快照', async () => {
			ctx = makeCtx();
			host.index.apply(ctx, makeConfig('custom'));
			ok(globalThis.fetch !== originalFetch, 'apply 后 globalThis.fetch 应被包装');
			eq(typeof routeHandler, 'function', 'webServer.register 应被调用');
			const snapshot = await readStatus();
			eq(snapshot.ok, true);
			eq(snapshot.status.mode, 'custom');
			eq(snapshot.status.active, true);
			eq(snapshot.status.exitId, 'custom');
		});

		test('设置提交（loader/volatile-update）后重新编译；不相关路径不打断', async () => {
			eq(typeof events.get('loader/volatile-update'), 'function', '应订阅 loader/volatile-update');
			const offConfig = makeConfig('off');
			ctx = makeCtx();
			host.index.apply(ctx, offConfig);
			const after = await readStatus();
			eq(after.status.mode, 'off', '提交 mode=off 后应重新编译');
			eq(after.status.active, false, 'mode=off 时应停用代理');
			// 别的插件的字段变动不影响我们
			events.get('loader/volatile-update')([['someOtherPlugin', 'field']]);
			eq((await readStatus()).status.mode, 'off', '不相关路径的更新不应改变状态');
		});

		test('写坏的值不会顶掉正在工作的配置', async () => {
			const badConfig = makeConfig('custom');
			badConfig.proxyUri = { get: () => '' };
			ctx = makeCtx();
			host.index.apply(ctx, badConfig);
			const snapshot = await readStatus();
			ok(snapshot.status.lastError, '写坏时应记录 lastError');
			eq(snapshot.status.lastSelfCheck.ok, false);
		});

		test('卸载时若 fetch 已被别人包装，不抹掉别人的包装', async () => {
			ctx = makeCtx();
			host.index.apply(ctx, makeConfig('rule'));
			const ours = globalThis.fetch;
			ok(ours !== originalFetch, 'apply 后应装上我们的包装');
			// 模拟「别的插件在我们之后又包了一层」
			const foreign = async (...args) => ours(...args);
			globalThis.fetch = foreign;
			// 触发卸载
			while (disposers.length > 0) {
				const dispose = disposers.pop();
				try {
					dispose();
				} catch {
					/* 卸载失败由下一行断言暴露 */
				}
			}
			eq(globalThis.fetch, foreign, '栈顶是别人的包装时必须原样保留，不能回写成原 fetch');
			globalThis.fetch = originalFetch;
		});

		test('POST /probe 未启用时明确回报，不发网络请求', async () => {
			ctx = makeCtx();
			host.index.apply(ctx, makeConfig('off'));
			const body = await new Promise((resolve) => {
				const res = { writeHead() {}, end(text) { resolve(text); } };
				routeHandler(
					{ method: 'POST', url: `${host.index.ROUTE_PATH}/probe`, headers: { host: '127.0.0.1:3269' } },
					res,
				);
			});
			const result = JSON.parse(body);
			eq(result.ok, false);
			eq(result.error, 'inactive');
			ok(typeof result.failure === 'string' && result.failure.length > 0);
		});

		test('GET /probe 被拒绝（探针会发请求，只能 POST 触发）', async () => {
			const sent = await new Promise((resolve) => {
				let code;
				const res = { writeHead(c) { code = c; }, end(text) { resolve({ code, text }); } };
				routeHandler(
					{ method: 'GET', url: `${host.index.ROUTE_PATH}/probe`, headers: { host: '127.0.0.1:3269' } },
					res,
				);
			});
			eq(sent.code, 405);
			eq(JSON.parse(sent.text).ok, false);
		});

		test('探针不回报主机名与响应体', async () => {
			ctx = makeCtx();
			host.index.apply(ctx, makeConfig('custom'));
			const body = await new Promise((resolve) => {
				const res = { writeHead() {}, end(text) { resolve(text); } };
				routeHandler(
					{ method: 'POST', url: `${host.index.ROUTE_PATH}/probe`, headers: { host: '127.0.0.1:3269' } },
					res,
				);
			});
			const result = JSON.parse(body);
			// 无论成败，返回里都不该出现目标主机名或路径
			notIncludes(body, 'api.deepseek.com');
			ok('ms' in result, '必须回报耗时');
			ok('ok' in result, '必须回报成败');
		});
	});

	suite('i18n', async (test) => {
		const client = await use();

		test('中英文字典的 key 集合完全一致（漏翻会在这里失败）', () => {
			const zh = Object.keys(client.messages.zh).sort();
			const en = Object.keys(client.messages.en).sort();
			deepEq(en, zh, 'en 与 zh 的 key 必须一一对应');
			ok(zh.length > 0);
		});

		test('没有空译文', () => {
			for (const lang of ['zh', 'en']) {
				for (const [key, value] of Object.entries(client.messages[lang])) {
					ok(typeof value === 'string' && value.trim() !== '', `${lang}.${key} 是空的`);
				}
			}
		});

		test('client.js 内联的字典与 lib/i18n.js 完全一致', () => {
			// 客户端是 IIFE，只能内联一份副本；这里防止两份漂移。
			const source = readFileSync(join(projectRoot, 'lib/client.js'), 'utf8');
			for (const [key, value] of Object.entries(client.messages.zh)) {
				ok(source.includes(value), `client.js 缺少 zh 译文：${key}`);
			}
			for (const [key, value] of Object.entries(client.messages.en)) {
				ok(source.includes(value), `client.js 缺少 en 译文：${key}`);
			}
		});

		test('插值占位符在两种语言中一致', () => {
			const placeholders = (text) => (String(text).match(/\{(\w+)\}/g) || []).sort();
			for (const key of Object.keys(client.messages.zh)) {
				deepEq(placeholders(client.messages.en[key]), placeholders(client.messages.zh[key]), `${key} 的占位符不一致`);
			}
		});
	});

	suite('client-smoke', async (test) => {
		const client = await use();
		const module = client.clientModule;
		let registered;
		let slotName;

		test('inject 里没有 settingsScope，含 slots/remote/remote.settings/locale', () => {
			deepEq(module.inject, ['slots', 'remote', 'remote.settings', 'locale']);
			ok(!module.inject.includes('settingsScope'), 'inject 不得包含 settingsScope');
		});

		test('挂载到 settings.section，id = model-proxy，label 走字典', () => {
			const registeredLocales = [];
			const ctx = {
				effect(fn) {
					fn();
				},
				locale: {
					register(ns, messages) {
						registeredLocales.push({ ns, messages });
						return () => {};
					},
					bind() {
						return (key) => key;
					},
				},
				slots: {
					inject(name, cb) {
						slotName = name;
						cb();
						return () => {};
					},
					register(spec, component) {
						registered = { spec, component };
						return () => {};
					},
				},
				remote: {
					settings: {
						describe: async () => ({ ok: true, value: { writable: true, namespaces: [] } }),
						mutate: async () => ({ ok: true, value: {} }),
					},
					$on: () => () => {},
				},
			};
			module.apply(ctx);
			eq(slotName, 'settings.section');
			eq(registered.spec.name, 'settings.section');
			eq(registered.spec.id, 'model-proxy');
			eq(typeof registered.spec.label, 'function');
			// bind 被打了桩（返回 key 本身），因此 label 是 key 而不是译文
			eq(registered.spec.label(), 'sectionLabel');

			// 字典注册了，且中英文都在
			eq(registeredLocales.length, 1);
			eq(registeredLocales[0].ns, 'model-proxy');
			eq(typeof registeredLocales[0].messages.zh, 'object');
			eq(typeof registeredLocales[0].messages.en, 'object');
		});

		test('缺少 locale 服务时退回中文，页面不崩', () => {
			const ctx = {
				effect(fn) {
					fn();
				},
				slots: {
					inject(name, cb) {
						cb();
						return () => {};
					},
					register(spec, component) {
						registered = { spec, component };
						return () => {};
					},
				},
				remote: {
					settings: {
						describe: async () => ({ ok: true, value: { writable: true, namespaces: [] } }),
						mutate: async () => ({ ok: true, value: {} }),
					},
					$on: () => () => {},
				},
			};
			module.apply(ctx);
			eq(registered.spec.label(), '模型代理');
		});

		test('组件可渲染，且包含核心字段', () => {
			// 用中文兜底渲染（t 由 apply 注入；这里直接给一份）
			const t = (key, params) => {
				const table = client.messages.zh;
				const template = table[key] === undefined ? key : table[key];
				return String(template).replace(/\{(\w+)\}/g, (m, k) => (params && params[k] !== undefined ? String(params[k]) : m));
			};
			const wrapper = registered.component({ t });
			const tree = wrapper.type(Object.assign({}, wrapper.props, { t }));
			eq(tree.type, 'div');
			const text = JSON.stringify(tree);
			for (const needle of ['模型代理', '模式', '日志级别', '保存', '测试代理', '只代理这些域名', '排除域名']) includes(text, needle);
		});

		test('域名清单是 tag 编辑器，不再是逗号分隔文本框', () => {
			// 域名清单只在 rule/custom 模式下渲染，所以这里直接构造组件树：
			// 用打桩的 useState 让 draft 一开始就是 rule 模式。
			const t = (key) => key;
			const wrapper = registered.component({ t });
			// 组件内部 draft 初值为 null → fromValue(null) → mode 默认 'rule'，
			// 因此域名清单本来就在树里；这里直接断言结构。
			const tree = wrapper.type(Object.assign({}, wrapper.props, { t }));
			const text = JSON.stringify(tree);
			includes(text, 'mp-hosts');
			includes(text, 'mp-hosts-add');
			includes(text, 'hostsRestorePreset');
			// 旧实现是逗号分隔的单个 input，placeholder 里带逗号提示
			ok(!text.includes('留空 = 内置预设'), '不应再出现旧文本框的 placeholder');
		});
	});
}

function collectJsFiles(root) {
	const files = [];
	const walk = (dir) => {
		for (const entry of readdirSync(dir)) {
			const full = join(dir, entry);
			if (statSync(full).isDirectory()) walk(full);
			else if (entry.endsWith('.js')) files.push(full);
		}
	};
	walk(root);
	return files;
}

/** 去掉注释：注释里的示例文字不该触发源码断言。 */
function stripComments(text) {
	return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

// ═══════════════════════════════════════════════════════════

/**
 * 把两个入口文件加载进来，供冒烟套件使用。
 * - 宿主一半：真 schemastery（从 DSH profile 里解析到的那份）
 * - 客户端一半：`lib/client.js` 是给浏览器壳用的 IIFE，这里用假的 `window.__ModuleLoader__`
 *   截获它，再用打桩的 `react` 跑 `factory`
 * @returns {Promise<{index:any, clientModule:any}>}
 */
async function loadEntries() {
	// `lib/index.js` 里 `import z from '@deepseek-ai/schemastery'` 是裸说明符。
	// 插件刻意不把 schemastery 装成自己的 dependency（用宿主那份，版本才跟得上
	// `volatile()` 这类新 API），所以测试期间在插件目录造一个临时链接，跑完即删。
	// 指向的必须是「带 volatile() 的宿主副本」——本机同时存在 3.18.2（没有）和
	// 3.18.5（有），链错版本会得到和真宿主不同的结论。
	const schemasteryDir = resolveSchemasteryDir();
	const linkParent = join(projectRoot, 'node_modules');
	const link = join(linkParent, '@deepseek-ai', 'schemastery');
	const created = [];
	if (schemasteryDir !== undefined && !existsSync(link)) {
		try {
			mkdirSync(join(linkParent, '@deepseek-ai'), { recursive: true });
			created.push(join(linkParent, '@deepseek-ai'), linkParent);
			symlinkSync(schemasteryDir, link, 'junction');
		} catch (error) {
			console.log(`\n⚠ 无法在测试期链接宿主 schemastery（${error?.message ?? error}），入口冒烟用例跳过。\n`);
			return {};
		}
	}

	let index;
	try {
		index = await import('../lib/index.js');
	} finally {
		try {
			rmSync(link, { recursive: true, force: true });
			for (const dir of created) {
				if (existsSync(dir) && readdirSync(dir).length === 0) rmSync(dir, { recursive: true, force: true });
			}
		} catch {
			/* 清理失败不影响测试结论 */
		}
	}

	const captured = [];
	const previousWindow = globalThis.window;
	globalThis.window = { __ModuleLoader__: { load: (spec) => captured.push(spec) } };
	try {
		await import('../lib/client.js');
	} finally {
		if (previousWindow === undefined) delete globalThis.window;
		else globalThis.window = previousWindow;
	}
	const spec = captured[0];
	if (spec === undefined) throw new Error('lib/client.js 没有调用 window.__ModuleLoader__.load');

	const element = (type, props, ...children) => ({ type, props, children });
	const reactStub = {
		createElement: element,
		useState: (initial) => [typeof initial === 'function' ? initial() : initial, () => {}],
		useEffect: () => {},
		useCallback: (fn) => fn,
		useMemo: (fn) => fn(),
		useRef: (value) => ({ current: value }),
	};
	const requireStub = (name) => {
		if (name === 'react') return reactStub;
		throw new Error(`unexpected require: ${name}`);
	};
	const clientModule = spec.factory(requireStub);
	// 客户端把字典内联在 IIFE 里（运行时 require 不到本地模块），
	// 唯一真源是 lib/i18n.js。两边的 key 集合由 i18n 组核对。
	const i18n = await import('../lib/i18n.js');
	return { index, clientModule, messages: i18n.MESSAGES, messageKeys: i18n.MESSAGE_KEYS };
}

const smokeRun = {};
const result = await h.run();
await h.runCleanups();
console.log('');
if (result.failed > 0) {
	console.log(`${result.passed} passed, ${result.failed} FAILED`);
	for (const failure of result.failures) console.log(`\n--- ${failure.suite} :: ${failure.test}\n${failure.error}`);
	process.exitCode = 1;
} else {
	console.log(`all ${result.passed} tests passed`);
}

// ── 冒烟部分：入口文件（需要 schemastery 与一个打桩的客户端宿主） ──
if (needsSchemastery) {
	const smoke = captureProcessErrors();
	try {
		Object.assign(smokeRun, await loadEntries());
		registerSmokeSuites(async () => smokeRun);
	} catch (error) {
		smoke.stop();
		console.log(`\n✗ 无法加载入口文件：${error?.stack ?? error}`);
		process.exitCode = 1;
		throw error;
	}
	const smokeResult = await h.run();
	await h.runCleanups();
	smoke.stop();
	const leaked = smoke.list().filter((error) => String(error?.message ?? error).includes('model-proxy'));
	if (leaked.length > 0) {
		console.log(`\n✗ 卸载后有 ${leaked.length} 个与插件相关的异步错误逃逸（应为 0）`);
		for (const error of leaked) console.log(String(error?.stack ?? error));
		process.exitCode = 1;
	}
	console.log('');
	if (smokeResult.failed > 0) {
		console.log(`${smokeResult.passed} passed, ${smokeResult.failed} FAILED`);
		for (const failure of smokeResult.failures) console.log(`\n--- ${failure.suite} :: ${failure.test}\n${failure.error}`);
		process.exitCode = 1;
	} else {
		console.log(`all ${smokeResult.passed} smoke tests passed`);
	}
}
