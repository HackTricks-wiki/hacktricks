# LLM Gateway 信任边界

{{#include ../banners/hacktricks-training.md}}

LLM gateway 负责模型路由，通常还持有 provider 凭据，因此普通 API 调用方不能继承配置或 provider 级别的权限。针对 LiteLLM 1.77.7 版本的 gateway 评估展示了两个不同的边界：用于管理配置的 UI 会话授权，以及用于推理的调用方提供的路由配置。报告中的问题已在 1.83.9 版本修复。<sup>[[1]](#references)</sup>

## UI 路由分类不等于授权

在评估的 LiteLLM 版本中，UI 登录密钥属于 `litellm-dashboard` 团队。无论用户的角色是什么，授权逻辑都会根据团队标识将密钥归类为 UI token。随后，UI 路由检查会接受任何以允许列表中的前缀开头的路由。因此，`/config` 条目也会匹配管理用的 `/config/update` 处理程序。该处理程序只要求通用身份验证，并未单独要求 `PROXY_ADMIN`，因此低权限 UI 会话得以访问配置写入功能。<sup>[[1]](#references)</sup>

这不同于代理/后端路径规范化不一致：授权代码和处理程序对*同一路由*的权限判断不一致。<sup>[[1]](#references)</sup> 审查 gateway 时，应对照检查 token 分类、精确的路由和方法匹配，以及处理程序自身的角色检查。<sup>[[1]](#references)</sup> 另请参阅 [web API 授权](../pentesting-web/web-api-pentesting.md)、[401/403 绕过](../pentesting-web/403-and-401-bypasses.md)和[代理前缀豁免](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys)，了解相关但不同的边界。

## 配置写入的影响不止于配置存储

同一个 LiteLLM 配置更新功能会接受环境变量值，并将其应用到运行中的进程。一个使用方将 `UI_LOGO_PATH` 作为 `FileResponse` 的本地路径使用，却没有验证它是否指向 logo；另一个使用方则会在非 SSO 登录期间读取 `UI_USERNAME` 和 `UI_PASSWORD`，并在两者匹配时赋予 `PROXY_ADMIN`。因此，配置写入权限可能因下游使用方而导致本地文件泄露或管理身份变更。响应的媒体类型并不能证明所提供的文件是图像。<sup>[[1]](#references)</sup>

透传端点配置是另一个下游接收点。初始化时接受远程 S3/GCS 适配器目标，下载 Python 模块，并通过 `importlib` 的 `exec_module` 导入这些模块。在使用适配器实例之前，导入操作就会执行顶层代码；仅限制适配器的调用并不能消除这一执行边界。应将其视为由配置控制的代码加载，而不是模型文件反序列化。<sup>[[1]](#references)</sup> 关于独立的文件读取原语，请参阅[文件包含与路径遍历](../pentesting-web/file-inclusion/)。

## 每请求模型路由可能 leak gateway 凭据

LiteLLM 的客户端凭据功能允许在 LLM 请求中提供 `user_config` 对象。评估中的路由会根据该对象创建临时的 `litellm.Router`，其中包括模型列表和 provider 的 `api_base`。由调用方控制的 provider 目标可能接收到 gateway 发出的 completion 请求及已配置的 provider 身份验证标头。对顶层 `api_base` 或 `api_key` 字段的限制并未覆盖这条独立的嵌套配置路径。这是一个携带凭据的 SSRF 边界，而非 prompt-injection 问题。<sup>[[1]](#references)</sup>

在经过授权的 gateway 评估中，应将所有可能创建 router 或 provider client 的路径（包括每请求配置）与常规配置路由所使用的目标和凭据策略逐一对照。<sup>[[1]](#references)</sup> [SSRF 指南](../pentesting-web/ssrf-server-side-request-forgery/)介绍了通用的服务端目标控制；gateway 特有的失效在于：允许信任度较低的请求对象选择目标，同时复用高权限的出站凭据。<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — LLM Gateway 出错时：LiteLLM 的安全发现](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
