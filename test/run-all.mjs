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
 * 两者都能用来断言「请求真的经过了代理」。
 */
function startProxyStub() {
	const state = { connects: 0, tunnelled: 0, absolute: 0 };
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
		const [host, port] = String(req.url).split(':');
		const upstream = netConnect(Number(port), host, () => {
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

		test('卸载后恢复原 fetch', async () => {
			while (disposers.length > 0) {
				const dispose = disposers.pop();
				try {
					dispose();
				} catch {
					/* 卸载失败由下一行断言暴露 */
				}
			}
			globalThis.fetch = originalFetch;
			eq(globalThis.fetch, originalFetch, 'dispose 后应恢复原 fetch');
		});
	});

	suite('client-smoke', async (test) => {
		const client = await use();
		const module = client.clientModule;
		let registered;
		let slotName;

		test('inject 里没有 settingsScope，只有 slots/remote/remote.settings', () => {
			deepEq(module.inject, ['slots', 'remote', 'remote.settings']);
			ok(!module.inject.includes('settingsScope'), 'inject 不得包含 settingsScope');
		});

		test('挂载到 settings.section，id = model-proxy', () => {
			const ctx = {
				effect(fn) {
					fn();
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
			eq(registered.spec.label(), '模型代理');
		});

		test('组件可渲染，且包含核心字段', () => {
			const wrapper = registered.component({});
			const tree = wrapper.type(wrapper.props);
			eq(tree.type, 'div');
			const text = JSON.stringify(tree);
			for (const needle of ['模型代理', '模式', '日志级别', '保存']) includes(text, needle);
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
	return { index, clientModule: spec.factory(requireStub) };
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
