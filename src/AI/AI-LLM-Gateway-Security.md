# LLM Gateway 信任边界

{{#include ../banners/hacktricks-training.md}}

LLM gateway 负责模型路由，通常还持有 provider 凭据，因此普通 API 调用方不应继承配置权限或 provider 级别的权限。对 LiteLLM 1.77.7 版本的 gateway 评估揭示了两个独立边界：用于管理配置的 UI 会话授权，以及用于推理的调用方提供的路由配置。报告的问题已在 1.83.9 版本中修复。<sup>[[1]](#references)</sup>

## UI 路由分类不等于授权

在评估的 LiteLLM 版本中，UI 登录密钥属于 `litellm-dashboard` team。无论用户角色如何，授权逻辑都会根据 team 标识符将密钥分类为 UI token。随后，UI 路由检查会接受任何以 allowlist 前缀开头的路由。因此，`/config` 条目也会匹配管理路由 `/config/update`。该 handler 只要求通用身份验证，并未单独要求 `PROXY_ADMIN`，于是权限较低的 UI 会话获得了配置写入权限。<sup>[[1]](#references)</sup>

这不同于 proxy/backend 路径规范化不一致：授权代码和 handler 对*同一个*路由的权限要求存在分歧。<sup>[[1]](#references)</sup> 评估 gateway 时，应对照检查 token 分类、精确的路由和方法匹配，以及 handler 自身的角色检查。<sup>[[1]](#references)</sup> 另请参阅 [web API 授权](../pentesting-web/web-api-pentesting.md)、[401/403 绕过](../pentesting-web/403-and-401-bypasses.md)和 [proxy 前缀豁免](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys)，了解相关但不同的边界。

## 配置写入的影响不止于配置存储

同一个 LiteLLM 配置更新接口接受环境变量值，并将其应用于运行中的进程。一个使用方将 `UI_LOGO_PATH` 视为 `FileResponse` 的本地路径，但没有验证该路径是否指向 logo；另一个使用方在非 SSO 登录期间读取 `UI_USERNAME` 和 `UI_PASSWORD`，并在二者匹配时授予 `PROXY_ADMIN`。因此，配置写入权限可能根据下游使用方的不同，同时导致本地文件泄露和管理身份变更。响应的媒体类型并不能证明所提供的文件是图片。<sup>[[1]](#references)</sup>

Pass-through endpoint 配置是另一个下游 sink。初始化过程接受远程 S3/GCS adapter 目标，下载 Python 模块，并使用 `importlib` 的 `exec_module` 导入这些模块。模块导入会在使用 adapter 实例之前执行顶层代码；仅限制对 adapter 的调用并不能消除这一执行边界。应将其视为由配置控制的代码加载，而非模型文件反序列化。<sup>[[1]](#references)</sup> 关于单独的文件读取原语，请参阅[文件包含和路径遍历](../pentesting-web/file-inclusion/)。

## 每个请求的模型路由可能泄露 gateway 凭据

LiteLLM 的客户端凭据功能接受 LLM 请求中的 `user_config` 对象。评估的路由会根据该对象创建临时的 `litellm.Router`，其中包括模型列表和 provider `api_base`。由调用方控制的 provider 目标可以接收 gateway 发出的 completion 请求及配置的 provider 身份验证头。对顶层 `api_base` 或 `api_key` 字段的限制并未涵盖这条独立的嵌套配置路径。这是一个携带凭据的 SSRF 边界，而非 prompt injection 问题。<sup>[[1]](#references)</sup>

进行授权的 gateway 评估时，应将所有可能构造 router 或 provider client 的路径（包括每个请求的配置）与常规配置路由使用的目标和凭据策略进行对比。<sup>[[1]](#references)</sup> [SSRF 指南](../pentesting-web/ssrf-server-side-request-forgery/)介绍了一般的服务端目标控制；gateway 特有的缺陷在于，允许信任度较低的请求对象选择目标，同时复用特权出站凭据。<sup>[[1]](#references)</sup>

## Guardrail 注册可能绕过仅限 UI 的沙箱

Gateway 的代码测试路径和代码注册路径可能采用不同的验证方式。在 v1.82.0 之前的 LiteLLM 中，UI 自定义 guardrail 测试会拒绝危险语法，并使用 `__builtins__ = {}` 执行；但 `POST /guardrails` 会通过 `exec(compile(...), exec_globals)` 编译提交的 `custom_code`，且没有进行上述任一检查。若 globals 字典中缺少 `__builtins__`，Python 会自动插入内置对象，因此模块级导入和命令会在 guardrail 注册时运行，早于任何推理调用。之后，`apply_guardrail` callback 可能会通过其 block reason 暴露存储的结果。<sup>[[2]](#references)[[3]](#references)</sup>

进行授权测试时，应对比测试 handler 和注册 handler，而不要假设 UI 沙箱测试成功就能证明注册过程安全。报告中修复前的请求格式如下：<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

注册 endpoint 也接受普通 API keys，因为它缺少 `PROXY_ADMIN` 检查。在未配置 master key 或 JWT/OAuth2 authentication 的情况下，修复前的 auth handler 会将 `PROXY_ADMIN` 分配给匿名请求。修复将无认证时的角色改为 `INTERNAL_USER`，添加了 guardrail admin 检查，并在注册期间验证和限制 builtins。这些角色和代码执行边界与 [MCP token-fallback 问题](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session)彼此独立。<sup>[[2]](#references)[[3]](#references)</sup>

## Admin pass-through 路由可代理 cloud metadata

LiteLLM 的 pass-through endpoint 功能允许管理员配置 HTTP 目标，并可选择追加子路径。与上文按请求进行的 `user_config` 路由问题不同，这需要**配置写入权限**；该功能本身旨在信任管理员。在报告的部署中，目标地址未针对私有或 link-local 地址进行检查。<sup>[[2]](#references)[[4]](#references)</sup> 在 v1.83.0 之前，普通认证密钥也可以访问 `/config/update`，因为该 endpoint 缺少管理员角色检查；相关的配置写入边界请参阅 [UI 路由分类](#ui-route-classification-is-not-authorization)。<sup>[[2]](#references)[[6]](#references)</sup>

拥有该权限，且 proxy 可以通过网络访问 EC2 metadata 时，类似下面的路由会通过 gateway 暴露 metadata。`include_subpath` 标志会将 `/meta/meta-data/iam/security-credentials/` 映射到 `/latest/` 下。<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

[Cloud SSRF 指南](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws)介绍了 IMDSv2 token 交换；此路由必须允许其 `PUT` 请求并转发两个 metadata header。<sup>[[5]](#references)</sup> LiteLLM 的通用 pass-through header 处理会在转发前剥除 `x-pass-` 前缀，因此 `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` 和 `x-pass-X-aws-ec2-metadata-token: <token>` 可用于提供这些 header。<sup>[[2]](#references)[[7]](#references)</sup> 代理必须能够访问 IMDS，token 响应必须通过配置的 hop limit，并且 token 请求不得携带 `X-Forwarded-For`。<sup>[[5]](#references)</sup> 此网关特有的变化是**由管理员控制的持久路由加上请求 header 转发**。

## References

- [1] [Check Point Research — LLM Gateway 出错时：LiteLLM 的调查发现](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — 毫无防备：从认证绕过到云环境失陷，攻破 LiteLLM](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — 修复 custom code guardrail 中的未认证 RCE 和 sandbox escape](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — 创建 Pass Through Endpoints](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Instance Metadata Service Version 2 的工作原理](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [LiteLLM 公告 — 不受限制的代理配置端点](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [LiteLLM pass-through header 转发实现](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
