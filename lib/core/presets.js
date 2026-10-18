/**
 * 内置预设：模型 API 域名表。
 *
 * 这张表**刻意复用 dsh-http-proxy 已在本机验证过的清单**（它在用户的 DSH 0.2.1 里
 * 实际跑着），并补齐常见的境外/国内模型网关。用户可用 `autoDetect` 追加自己的 baseURL 域名。
 *
 * 分成三组，是为了让默认策略「境外走代理、国内直连」开箱即用：
 * - `OVERSEAS`：境外模型 API，默认走代理
 * - `DOMESTIC`：国内模型 API，默认直连（否则绕一圈反而更慢、且无必要）
 * - `TEMPLATED`：区域化/资源化端点，用后缀匹配
 *
 * @module dsh-model-proxy/core/presets
 */

/** 境外模型 API 主机（精确匹配）。 */
export const OVERSEAS_MODEL_HOSTS = [
	'api.anthropic.com',
	'api.openai.com',
	'chatgpt.com',
	'api.x.ai',
	'api.groq.com',
	'api.mistral.ai',
	'api.cerebras.ai',
	'api.together.ai',
	'api.fireworks.ai',
	'api.deepinfra.com',
	'api.perplexity.ai',
	'api.cohere.ai',
	'api.cohere.com',
	'api.voyageai.com',
	'api.jina.ai',
	'api.huggingface.co',
	'router.huggingface.co',
	'integrate.api.nvidia.com',
	'inference.baseten.co',
	'ai-gateway.vercel.sh',
	'gateway.ai.cloudflare.com',
	'api.cloudflare.com',
	'api.individual.githubcopilot.com',
	'openrouter.ai',
	'api.openrouter.ai',
	'generativelanguage.googleapis.com',
	'api.replicate.com',
	'api.sambanova.ai',
	'api.lingyiwanwu.com',
	'api.novita.ai',
	'api.hyperbolic.xyz',
	'api.anyscale.com',
	'api.gladia.io',
	'api.elevenlabs.io',
	'api.assemblyai.com',
	'api.deepgram.com',
	'api.rev.ai',
];

/** 区域化/资源化端点（后缀匹配，连字符拼接的区域主机一并命中）。 */
export const TEMPLATED_MODEL_SUFFIXES = ['.aiplatform.googleapis.com', '.openai.azure.com', '.anthropic.azure.com'];

/** 国内模型 API 主机（默认直连）。 */
export const DOMESTIC_MODEL_HOSTS = [
	'api.deepseek.com',
	'api.moonshot.cn',
	'api.moonshot.ai',
	'api.kimi.com',
	'open.bigmodel.cn',
	'api.minimaxi.com',
	'api.minimax.io',
	'api.minimax.chat',
	'api.xiaomimimo.com',
	'api.baichuan-ai.com',
	'api.lingyiwanwu.com',
	'dashscope.aliyuncs.com',
	'api.siliconflow.cn',
	'api.stepfun.com',
	'ark.cn-beijing.volces.com',
	'qianfan.baidubce.com',
	'openapi.hunyuan.cloud.tencent.com',
	'api.ant-ling.com',
	'api.z.ai',
	'token-plan-cn.xiaomimimo.com',
	'token-plan.cn-beijing.maas.aliyuncs.com',
];

/** 官方 DeepSeek 适配器默认域名（永远直连：它本身在国内可达）。 */
export const DEEPSEEK_HOST = 'api.deepseek.com';

/**
 * 默认规则包：`mode: rule` + `default: direct` 下，把境外模型域名送进指定出口。
 * @param {string} exitId 目标出口 id
 * @returns {Array<{match:{type:string,value:string}, action:string}>}
 */
export function defaultRulesFor(exitId) {
	return [
		...TEMPLATED_MODEL_SUFFIXES.map((value) => ({ match: { type: 'suffix', value: `*${value}` }, action: exitId })),
		...OVERSEAS_MODEL_HOSTS.map((value) => ({ match: { type: 'domain', value }, action: exitId })),
		...DOMESTIC_MODEL_HOSTS.map((value) => ({ match: { type: 'domain', value }, action: 'direct' })),
	];
}

/** 供设置页下拉推荐的主机清单（去重、排序）。 */
export function suggestedHosts() {
	return [...new Set([DEEPSEEK_HOST, ...OVERSEAS_MODEL_HOSTS, ...DOMESTIC_MODEL_HOSTS, ...TEMPLATED_MODEL_SUFFIXES.map((suffix) => `*${suffix}`)])].sort();
}
