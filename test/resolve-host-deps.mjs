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

import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = fileURLToPath(new URL('..', import.meta.url));

/** 候选的 node_modules 根目录（按优先级）。 */
function candidateRoots() {
	const roots = [join(here, 'node_modules')];
	const dshHomes = [process.env.DSH_HOME, join(homedir(), '.dsh')].filter(Boolean);
	for (const home of dshHomes) {
		for (const profile of ['web', 'desktop']) roots.push(join(home, 'profiles', profile, 'node_modules'));
		roots.push(join(home, 'node_modules'));
	}
	return [...new Set(roots)];
}

/**
 * 解析一个包到它的目录。
 * @param {string} packageName
 * @returns {string|undefined}
 */
export function resolvePackageDir(packageName) {
	for (const root of candidateRoots()) {
		const dir = join(root, packageName);
		if (existsSync(join(dir, 'package.json'))) return dir;
	}
	return undefined;
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
