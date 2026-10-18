# dsh-model-proxy

[English](README.md) | 中文

把 DeepSeek Harness 的**模型 API 请求**送进代理，让第三方海外模型服务在国内网络下可用；
**其余请求一律直连**——网页搜索、抓取页面、MCP 服务和工具调用都不会经过代理。

- 不修改 harness 的任何文件；卸载后行为与安装前完全一致
- 支持**系统代理**、**自定义代理**（`http` / `https` / `socks4` / `socks4a` / `socks5` / `socks5h`）或环境变量代理
- **全局**或**按域名**分流；域名规则支持精确主机名、通配符和后缀
- 三条安全约束，配置无法放宽（见下文）

---

## 安装

```bash
dsh plugin --profile <你的 profile> add github:recyvan/dsh-model-proxy
```

安装后重启 DSH——宿主部分是在 harness 进程内加载的。

---

## 配置

打开 **设置 → 插件配置 → “Model Proxy”**。

| 字段 | 含义 |
| --- | --- |
| 模式 | `rule`（推荐）/ `system` / `custom` / `off` |
| 代理协议 | http / https / socks5 / socks5h / socks4 |
| 代理地址 | `socks5h://127.0.0.1:7890`，或直接写 `127.0.0.1:7890`（协议按“代理协议”字段补齐） |
| 仅代理这些域名 | 留空 = 内置预设；填写 = 只代理这些（逗号分隔，如 `*.openai.com`、`.aiplatform.googleapis.com`） |
| 排除域名 | 始终直连，优先级最高 |

改动在下一个请求生效，不需要重启。

### 三种常见配法

**A. Clash / V2Ray 在 `127.0.0.1:7890`，只代理海外 API**
模式 = `rule`，协议 = `http`，地址 = `127.0.0.1:7890`，域名列表留空。
预设会把 OpenAI / Anthropic / Gemini / xAI / Groq / OpenRouter 等送进代理，
DeepSeek、DashScope、智谱、Kimi 等国内服务保持直连。

**B. 跟随 Windows 系统代理**
模式 = `system`。插件每 30 秒重读一次
`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`，跟随系统里的改动。

**C. 全部走代理，只留少数例外**
模式 = `custom`，填好地址，把例外域名写进“排除域名”。

### 国内访问海外 API 的注意事项

- **DNS 污染**：优先用 `socks5h`（由代理解析 DNS），或让你的代理客户端接管 DNS。
- **明文 `http` 默认被拒绝**——API Key 不应该以明文穿过代理。确实需要时，在设置卡片里勾选对应选项。
- 代理必须监听回环地址；请在代理客户端里打开本地/局域网监听。

---

## 验证

1. 设置卡片显示实时状态：`path A · exit route · N rules · proxied x / direct y`。
2. `http://127.0.0.1:<port>/dsh-model-proxy/status` 返回同一份快照的 JSON
   （仅限回环 / 同源访问）。
3. `node test/run-all.mjs`——测试套件零依赖。

---

## 安全约束

无论怎么配置都成立，也是规则引擎最先检查的内容：

1. **强制直连**——回环地址、私有网段（`10/8`、`172.16/12`、`192.168/16`、
   `169.254/16`、`fc00::/7` 等）、`localhost` 以及 `.local`/`.lan`/`.internal` 这类名字
   永远不会走代理。用户规则可以新增条目，但不能删掉这些。
2. **明文闸门**——非 `https` 的模型请求在打开任何 socket 之前就被拒绝，除非显式开启该选项
   （此时卡片会持续显示警告）。
3. **数据最小化**——插件以流的方式透传请求和响应体；从不解析它们、从不写入磁盘，
   也从不读取 `Authorization` 或任何厂商的 API Key。默认日志只记录出口标识和错误类别，
   不含主机名、不含路径、不含请求体。

出口失败时回落到**直连**，绝不换到另一个出口：悄悄把流量挪到别的出口，等于在用户
不知情的情况下改变出网身份。

---

## 开发

```
lib/index.js       Cordis 宿主入口——唯一接触 harness API 的文件
lib/client.js      设置卡片（`__ModuleLoader__` 浏览器入口）
lib/core/*         纯逻辑，不依赖 harness，可独立测试
test/run-all.mjs   零依赖测试套件
```

运行时依赖只有 `undici`；`@deepseek-ai/schemastery` 是由宿主提供的 peer。

---

## 限制

- 只覆盖通过 **`fetch`** 发出的模型请求。`transport: websocket` 流式传输和各厂商原生 SDK
  通道（例如 Amazon Bedrock）不走 `fetch`，这里代理不到——这类请用 harness 自带的环境变量代理。
- 分流按**域名**进行。若某个域名同时承载模型 API 和其他流量，它的全部流量都会进代理；
  把这类域名写进“排除域名”。
- 代理凭据只能写在代理地址里（`http://user:pass@host:port`），会以明文保存在设置中。
  建议让代理直接接受回环连接、不做认证。
- 目前只有单跳代理是完整接通的；`lib/core/dispatcher.js` 里存在多跳链式接口，
  但交给 undici 的只有第一跳。

---

## 卸载

```bash
dsh plugin --profile <你的 profile> remove dsh-model-proxy
dsh --profile <你的 profile>
```

卸载后 DSH 恢复完全直连——没有配置残留，也不再有监听端口。

## 许可证

MIT
