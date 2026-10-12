# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

Burp Intruder 包含以下内置 payload 生成器和转换功能：<sup>[[1]](#references)</sup>

- **Simple list：** 使用配置的字符串列表作为 payload。
- **Runtime file：** 在运行时逐行读取 payload。适用于大型列表，因为 Burp 不会将整个文件加载到内存中。
- **Case modification：** 生成未修改的值、小写和大写形式、`Propername`（首字母大写，其余字母小写）或 `ProperName`（首字母大写，其余字符保持不变）。Burp 会丢弃重复结果。
- **Numbers：** 在配置的范围内生成连续数字或随机数字。
- **Brute forcer：** 根据所选字符集和最小/最大长度生成所有排列。

## 扩展和配套工具

- **Collabfiltrator** 会生成可执行命令并通过 DNS 查询将命令输出外传至 Burp Collaborator 的 payload。<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** 可导出 Burp 发现的问题，以用于其他报告工作流。<sup>[[3]](#references)</sup>
- **HTTP Script Generator** 可将 HTTP 请求转换为多种语言的脚本。<sup>[[4]](#references)</sup>

## 使用 Session Switcher 进行多会话授权测试

[Session Switcher](https://github.com/doyensec/burp-session-switcher) 是一款适用于 Burp Suite `2025.5+` 的 Java 扩展，可将 cookies 和不常见的 headers 保存为具名凭据配置文件。在可编辑的请求编辑器（包括 Repeater 或被拦截的 Proxy 请求）中选择配置文件时，请求中的身份验证信息会被替换。这是辅助重放的工具，**并非授权绕过**：可用它以不同账户发送相同请求，检查水平访问权限、垂直角色边界、租户隔离，以及作为[web 测试方法](../pentesting-web/web-vulnerabilities-methodology.md)一部分的 [IDOR/BOLA](../pentesting-web/idor.md)。<sup>[[5]](#references)[[8]](#references)</sup>

### 可重复的身份差异测试工作流

以下工作流将资源/操作与执行操作的身份作为独立测试变量，以减少因 token 过期或浏览器会话错误造成的误判。<sup>[[5]](#references)[[8]](#references)</sup>

1. 在单独的浏览器配置文件或容器中，登录代表各个相关用户、角色和租户的测试账户。
2. 打开一个携带某个身份 cookies 和 headers 的请求，选择 **Sessions > New**，并为配置文件设置明确的名称，例如 `tenant-a-user` 或 `tenant-b-admin`。对每个测试身份重复此步骤。
3. 将待测请求发送到 Repeater，在不更改其 method、endpoint、parameters 或 object identifier 的情况下重放请求，只切换所选 session。比较响应数据和可观察到的状态变化，而不只是状态码。
4. 对象级检查时，重放一个请求：请求中使用属于账户 A 的对象，同时选择账户 B 的配置文件。功能级检查时，使用权限较低的配置文件重放相同的特权操作。
5. 重新身份验证或 token 轮换后，使用当前浏览器请求中的 **Update**，或者在再次比较前配置 Auto Update 规则。

### 捕获和注入语义

测试前请检查更新/注入模式，因为混合了两个身份凭据的请求会使比较结果失效。当前默认设置会将请求中的所有 cookies 镜像到配置文件中，只更新已存储的不常见 headers，将所选配置文件的 cookies 镜像到目标请求中（删除目标请求已有的 cookies），并添加配置文件中的 headers。选择器可限定为精确子域、顶级应用域（默认）或所有已保存的配置文件。<sup>[[7]](#references)</sup>

- **Mirror** 适用于完整 cookie 集合决定身份，且必须删除目标请求中的过期 cookies 的情况。
- **Update existing** 可跟踪轮换值，而不会从浏览器流量中学习无关 cookies 或 headers。
- **Add all** 会保留配置文件或请求中已有的额外值；请确认没有残留来自上一个 session 的身份凭据。
- **Do nothing** 可在某类凭据无关时，排除 cookies 或 headers 的配置文件更新。

### 基于 Proxy 的 session 同步

Auto Update 规则会将 Proxy 流量关联到已保存的配置文件，并更新其 cookies/headers。优先使用稳定的识别条件，例如专用请求 header、特定配置文件的 `User-Agent` 标记、用于识别的 cookie、`X-PwnFox-Color` 或 JWT claim；同时结合范围/域/路径条件，避免无关应用更新该配置文件。单条规则中的所有条件会按顺序进行逻辑 `AND` 判断，因此应将限制性较强的检查放在前面；要实现 `OR`，可创建多条指向同一配置文件的规则。也支持否定匹配。<sup>[[6]](#references)</sup>

对于每条匹配规则，可分别为 cookies 和 headers 选择 **Mirror request**、**Add all**、**Update existing** 或 **Do nothing**。仅匹配请求的规则会在 Proxy 收到请求时运行；添加响应状态、响应 header 或响应正文条件后，会延迟到收到响应时才进行评估。可使用高亮颜色标记匹配的流量，便于确认每个浏览器身份只更新其对应的配置文件。<sup>[[6]](#references)</sup>

已保存的配置文件存储在 Burp 项目中，JSON 项目数据导出文件也包含这些 session 及其 cookies 和 headers。请将这两类文件视为有效凭据材料，限制对它们的访问权限，并在测试结束后删除已存储的扩展数据。<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [PortSwigger 文档 - Burp Intruder payload 类型](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Session Switcher 源码和使用文档](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Session Switcher Auto Update 规则](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Session Switcher 设置](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher：简化 Burp Suite 中的多会话授权测试](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
