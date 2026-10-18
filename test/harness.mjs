/**
 * 迷你测试框架：不依赖 node:test / 任何第三方包，`node test/run-all.mjs` 直接跑。
 *
 * 之所以自带：这个插件刻意压到「零测试依赖」——测试本身也不该引入供应链。
 *
 * @module dsh-model-proxy/test/harness
 */

const suites = [];
/** 所有套件跑完后执行一次的清理函数（关服务器、释放连接等）。 */
const cleanups = [];

/** 注册一组用例。 */
export function suite(title, fn) {
	suites.push({ title, fn });
}

/**
 * 注册一个「全部套件跑完后」执行的清理函数。
 * 用于关闭在 suite 回调里启动的服务器——不能在回调里立即关闭，
 * 因为 harness 是先收集用例、回调返回后才逐个执行。
 * @param {() => void|Promise<void>} fn
 */
export function cleanup(fn) {
	cleanups.push(fn);
}

/** 断言：真值。 */
export function ok(value, message) {
	if (!value) throw new Error(`expected truthy: ${message ?? '(no message)'}`);
}

/** 断言：相等（浅比较原始值）。 */
export function eq(actual, expected, message) {
	if (actual !== expected) throw new Error(`${message ?? 'eq failed'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

/** 断言：深相等（JSON 比较，够用且无依赖）。 */
export function deepEq(actual, expected, message) {
	const a = JSON.stringify(actual);
	const b = JSON.stringify(expected);
	if (a !== b) throw new Error(`${message ?? 'deepEq failed'}: expected ${b}, got ${a}`);
}

/** 断言：包含子串。 */
export function includes(haystack, needle, message) {
	if (!String(haystack).includes(needle)) throw new Error(`${message ?? 'includes failed'}: ${JSON.stringify(needle)} not in ${JSON.stringify(String(haystack).slice(0, 400))}`);
}

/** 断言：不包含子串。 */
export function notIncludes(haystack, needle, message) {
	if (String(haystack).includes(needle)) throw new Error(`${message ?? 'notIncludes failed'}: found ${JSON.stringify(needle)}`);
}

/** 断言：抛错/拒绝。 */
export async function rejects(fn, message) {
	let threw = false;
	try {
		await fn();
	} catch {
		threw = true;
	}
	if (!threw) throw new Error(`${message ?? 'rejects failed'}: expected a rejection/throw`);
}

/**
 * 运行所有已注册的套件。
 * @returns {Promise<{passed:number, failed:number, failures:Array<{suite:string, test:string, error:string}>}>}
 */
export async function run() {
	let passed = 0;
	const failures = [];
	for (const { title, fn } of suites) {
		const tests = [];
		await fn((label, testFn) => tests.push({ label, testFn }));
		for (const { label, testFn } of tests) {
			try {
				await testFn();
				passed += 1;
				console.log(`  \u2713 ${title} :: ${label}`);
			} catch (error) {
				failures.push({ suite: title, test: label, error: error?.stack ?? String(error) });
				console.log(`  \u2717 ${title} :: ${label}`);
			}
		}
	}
	return { passed, failed: failures.length, failures };
}

/** 执行全部已注册的清理函数（`run()` 之后调用，或在 finally 里调用）。 */
export async function runCleanups() {
	for (const fn of cleanups) {
		try {
			await fn();
		} catch {
			/* 清理失败不影响测试结论 */
		}
	}
	cleanups.length = 0;
}
