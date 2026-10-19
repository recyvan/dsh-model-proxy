/**
 * 测试专用：解析 DSH 宿主已安装的 `undici`。
 *
 * 为什么需要它：`undici` 由 DSH 宿主提供（宿主自己就在用）。但**测试**跑在宿主进程之外，
 * 本机 node 不一定能解析到它。所以测试不去 npm install，而是按顺序找：
 *
 * 1. 插件自己的 `node_modules/`（跑过 `npm install` 就用它）
 * 2. `$DSH_HOME/profiles/{web,desktop}/node_modules/`
 * 3. `~/.dsh/profiles/{web,desktop}/node_modules/`
 *
 * @module dsh-model-proxy/test/resolve-host-deps
 */

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = fileURLToPath(new URL('..', import.meta.url));

/** 候选的 node_modules 根目录（按优先级）。 */
function candidateRoots() {
	// 插件自己装了就用它；没有则用宿主 profile 的那份（版本随 DSH 走）。
	const roots = [join(here, 'node_modules')];
	const dshHomes = [process.env.DSH_HOME, join(homedir(), '.dsh')].filter(Boolean);
	for (const home of dshHomes) {
		for (const profile of ['web', 'desktop']) {
			roots.push(join(home, 'profiles', profile, 'node_modules'));
			// 桌面版会把运行时依赖摊到 profile 根目录下，两个都看一下
			roots.push(join(home, 'profiles', profile, 'node_modules', '.pnpm', 'node_modules'));
		}
		roots.push(join(home, 'node_modules'));
	}
	// `E:\DeepseekHarness\node_modules` 这类「DSH_HOME 的兄弟目录」：桌面版自带的依赖树，
	// 里面可能是开发期版本（例如 schemastery 3.18.2 没有 `volatile`），
	// 因此排在 profile 之后，只在前面全都找不到时才用。
	const dshHome = process.env.DSH_HOME;
	if (dshHome) roots.push(join(dshHome, '..', 'node_modules'));
	return [...new Set(roots)];
}

/**
 * 按优先级解析一个包目录；**只有最靠前的候选才代表宿主真实在跑的那份**。
 *
 * 有 `require` 条件时按它挑最近的版本：桌面版与 web profile 可能装着不同版本
 * （例如 schemastery 3.18.2 没有 `volatile()`，3.18.5 才有），
 * 拿错版本会让「插件在真宿主上能跑」这个结论失效。
 * @param {string} packageName
 * @param {{require?: (entry: {version?: string, dir: string}) => boolean}} [options]
 * @returns {string|undefined}
 */
export function resolvePackageDir(packageName, options = {}) {
	const matched = [];
	let first;
	for (const root of candidateRoots()) {
		const dir = join(root, packageName);
		if (!existsSync(join(dir, 'package.json'))) continue;
		if (first === undefined) first = dir;
		if (typeof options.require !== 'function') return dir;
		let version;
		try {
			version = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version;
		} catch {
			continue;
		}
		if (options.require({ version, dir })) return dir;
		matched.push(`${version}@${dir}`);
	}
	// 都不满足：返回第一个存在的，让调用方在报告里看到「拿到了什么」
	return options.require === undefined ? first : first;
}

/**
 * 解析 schemastery，优先挑带 `volatile()` 的那份（DSH 0.2.x 依赖它）。
 * @returns {string|undefined}
 */
export function resolveSchemasteryDir() {
	const withVolatile = (version) => {
		try {
			const [major, minor = 0, patch = 0] = String(version).split('-')[0].split('.').map(Number);
			return major > 3 || (major === 3 && (minor > 18 || (minor === 18 && patch >= 5)));
		} catch {
			return false;
		}
	};
	return resolvePackageDir('@deepseek-ai/schemastery', { require: (entry) => withVolatile(entry.version) });
}

/**
 * 读一个候选包的版本号，用于在测试里断言「跑的是宿主那份」。
 * @param {string} packageName
 * @returns {string|undefined}
 */
export function packageVersion(packageName) {
	const dir = resolvePackageDir(packageName);
	if (dir === undefined) return undefined;
	try {
		return JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version;
	} catch {
		return undefined;
	}
}

/**
 * 动态导入一个包**指定的那份目录**（不经过 Node 的裸说明符解析），
 * 用于「必须拿到宿主那份、不能被别的副本顶掉」的场景。
 * @param {string} dir 包目录（可来自 `resolveSchemasteryDir`）
 * @param {string} entry 入口文件（相对包目录）
 * @returns {Promise<any|undefined>}
 */
export async function importFromDir(dir, entry) {
	if (dir === undefined) return undefined;
	try {
		return await import(pathToFileURL(join(dir, entry)).href);
	} catch {
		return undefined;
	}
}

/**
 * 动态导入一个包：先常规解析，失败再去候选根目录按路径导入。
 * 都失败时返回 `undefined`（调用方据此跳过相关用例），而不是让整个测试进程崩掉。
 * @param {string} packageName
 * @param {string} entry 入口文件（相对包目录）
 * @returns {Promise<any|undefined>}
 */
export async function importPackage(packageName, entry) {
	try {
		return await import(packageName);
	} catch {
		/* 本地没装，继续找宿主那份 */
	}
	const dir = resolvePackageDir(packageName);
	if (dir === undefined) return undefined;
	try {
		return await import(pathToFileURL(join(dir, entry)).href);
	} catch {
		return undefined;
	}
}
