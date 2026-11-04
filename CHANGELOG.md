# Changelog

本文件记录各版本的行为变更。格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

---

## [2.1.0] — 2026-11-04

### 新增

- **设置迁移，而且看得见**：`lib/core/migrate.js` 把旧形状换算成当前版本——
  `enabled: false` → `mode: 'off'`（否则升级后你关掉的代理会悄悄重新打开）、
  逗号分隔的域名清单 → 数组、`proxyHost`/`proxyPort` → `proxyUri`，并写入
  `schemaVersion`。发生换算时记进 `status.migrations`，设置页提示「请保存一次」；
  不保存也不会错，只是每次启动都重新换算一次。换算幂等：同一份输入第二次无变更。
- **CI**：`.github/workflows/test.yml`，每次推送在 Node 22 / 24 上
  `npm ci` → 逐文件 `node --check` → 跑全套（纯逻辑 + 两个入口文件冒烟）。

### 变更

- `Config` 新增 `schemaVersion`；设置页保存时一并写回。
- `package.json` 声明 `engines.node >= 22.19`（宿主自己声明的下限）。
- 提交 `package-lock.json`，CI 用 `npm ci`，依赖版本不再随 npm 漂移。

### 修复（测试自身）

- **测试收尾会删掉 `node_modules/@deepseek-ai/schemastery`**。清理逻辑无条件
  `rmSync` 那个路径，`npm install` 之后跑一次测试就把真目录删了——删掉之后
  测试会安静地改用宿主那份，问题因此一直被掩盖。现在只删测试自己造的临时链接。
- **删掉「反向折叠」护栏用例**。它断言的是 undici 内部的调用时序，不是本插件的
  契约，实测同一份代码时而通过时而失败。正序方向由两跳/三跳用例逐跳断言端口锁定，
  另加一条「配置里的每一跳都真的收到 CONNECT」，不允许空转的配置项。

---

## [2.0.0] — 2026-10-29

### 修复

- **代理链真的按顺序走每一跳**（此前是假的）。
  `lib/core/dispatcher.js` 只把 `uris[0]` 交给了 undici，却回报
  `chainLength = uris.length`——诊断页显示走了三跳，实际只有一跳。
  现在把上一跳的 `ProxyAgent` 作为下一跳的 `clientFactory`，CONNECT 沿链路
  逐跳转发。折叠方向由 `test/run-all.mjs` 的 `chain` 组用三个真实 CONNECT 桩锁定：
  每一跳实际拨向的端口必须等于下一跳的端口。
- **多跳一卸载就抛 `UND_ERR_DESTROYED`**。旧实现逐个 `close()` 每一层，
  而外层关闭时已经把内层一并关了。现在只关最外层。
- **卸载时不再抹掉别人的 `fetch` 包装**。只有在栈顶仍是我们的包装时才恢复原
  `fetch`；否则保留现场并记一条警告。多个插件同时替换 `fetch` 时这是真实风险。
- **`/probe` 的 POST 永远返回 405**。方法校验写在端点解析之前，导致探针
  这条路由根本无法触发。

### 新增

- **锁文件里的代理链写什么就走什么**：两跳、三跳都有实测用例，
  另有反向折叠的护栏用例，确保「只看最终 200」的判断不会被误当作正确。
- **连通性自检**：设置页的「测试代理」按钮 → `POST /dsh-model-proxy/probe`。
  让当前出口真实访问一次固定目标，回报耗时、HTTP 状态与失败分类，
  **不回报主机名与响应体**。探针只接受 POST——它会发网络请求，
  暴露成 GET 就可能被同源页面用 `<img src>` 触发。
- **设置页支持中英文**：按 `ctx.locale.register(ns, { zh, en })` 注册字典，
  消费侧用 `ctx.locale.bind(ns)`。缺少 `locale` 服务时退回中文，页面照常可用。
  字典唯一真源是 `lib/i18n.js`，客户端内联一份副本——`i18n` 测试组核对两边
  key 集合、空译文与 `{placeholder}` 是否一致，防止漏翻与漂移。
- **域名清单改为标签编辑器**：逐个添加/删除，回车即添加，带「恢复内置预设」。
  取代原来那个逗号分隔的文本框（多打一个逗号就会产生空条目）。

### 变更

- 设置页 `label` 改为从字典读取（英文环境显示 `Model Proxy`）。
- `Config` 移除 `enabled`（与 `mode: 'off'` 语义重复）。

### 已知边界（2.0 不做）

- 只覆盖走 `fetch` 的请求。`transport: websocket` 流式传输、厂商原生 SDK 通道，
  以及 harness 自己的网页抓取工具（自建 `undici` agent）看不到、也代理不到。
- 分流按**域名**。同一域名同时承载模型 API 与其它流量时，只能整体取舍。
- 代理凭据只能内嵌在地址里（`http://user:pass@host:port`），以明文保存在设置中。

---

## [1.0.0 / 0.2.0] — 2026-10-19

- 迁移到 DSH 0.2.x 的设置契约：去掉客户端 `settingsScope`，
  改用 `remote.settings` 读写 + `Config` 的 `.volatile()` 字段，
  设置页挂到 `settings.section`。
- 恢复写入期校验（`assertValid` 接进 `loader/volatile-update`）。
- 保存按钮改用随主题反转的颜色对，修复暗色主题下看不清。
- 修好常红的代理链路用例；新增宿主/客户端两个入口文件的冒烟测试。
- `@deepseek-ai/schemastery` / `undici` 改为 peer，预发布范围写成显式分支。
