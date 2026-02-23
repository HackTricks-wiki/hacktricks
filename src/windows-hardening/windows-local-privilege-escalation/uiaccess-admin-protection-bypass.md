# 通过 UIAccess 绕过 Admin Protection

{{#include ../../banners/hacktricks-training.md}}

## 概述
- Windows AppInfo 暴露了 `RAiLaunchAdminProcess` 用于生成 UIAccess 进程（用于可访问性）。UIAccess 绕过大多数 User Interface Privilege Isolation (UIPI) 的消息过滤，使可访问性软件能够操作更高 IL 的 UI。
- 直接启用 UIAccess 需要通过 `NtSetInformationToken(TokenUIAccess)` 并拥有 **SeTcbPrivilege**，因此低权限的调用者依赖该 service。service 在对目标二进制设置 UIAccess 之前会执行三项检查：
  - 嵌入的 manifest 包含 `uiAccess="true"`。
  - 由 Local Machine root store 信任的任何证书签名（不要求 EKU/Microsoft）。
  - 位于系统驱动器上的管理员专用路径（例如 `C:\Windows`、`C:\Windows\System32`、`C:\Program Files`，但排除了特定可写子路径）。
- `RAiLaunchAdminProcess` 在启动 UIAccess 时不弹出同意提示（否则可访问性工具无法驱动该提示）。

## 令牌塑形和完整性级别
- 如果检查通过，AppInfo 会**复制调用者令牌**、启用 UIAccess，并提升 Integrity Level (IL)：
  - 限制的管理员用户（用户属于 Administrators 但运行被过滤） ➜ **High IL**。
  - 非管理员用户 ➜ IL 提高 **+16 级**，上限为 **High**（从不分配 System IL）。
- 如果调用者令牌已经有 UIAccess，则 IL 保持不变。
- “棘轮”技巧：UIAccess 进程可以在自身上禁用 UIAccess，使用 `RAiLaunchAdminProcess` 重新启动，从而再获得一次 +16 IL 的增量。Medium➜High 需要 255 次重启（噪声大，但可行）。

## 为什么 UIAccess 能实现 Admin Protection 绕过
- UIAccess 允许低 IL 的进程向更高 IL 的窗口发送窗口消息（绕过 UIPI 过滤）。在 IL 相同的情况下，经典的 UI 原语如 `SetWindowsHookEx` **确实允许代码注入/DLL 加载** 到任何拥有窗口的进程（包括 COM 使用的 message-only windows）。
- Admin Protection 以**有限用户身份**但在 **High IL** 下静默启动 UIAccess 进程。一旦任意代码在该 High-IL 的 UIAccess 进程内运行，攻击者就可以注入到桌面上的其他 High-IL 进程（甚至属于不同用户），破坏原本的隔离。

## 安全目录验证的弱点 (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo 通过 `GetFinalPathNameByHandle` 解析所提供的路径，然后对硬编码的根/排除项应用**字符串允许/拒绝检查**。这种简单化验证带来多类绕过：
- **目录命名流**：被排除的可写目录（例如 `C:\Windows\tracing`）可以通过对目录本身使用命名流来绕过，例如 `C:\Windows\tracing:file.exe`。字符串检查看到的是 `C:\Windows\`，因此会忽略被排除的子路径。
- **位于允许根下的可写文件/目录**：`CreateProcessAsUser` **不要求 `.exe` 扩展名**。在允许根下覆盖任何可写文件为可执行负载可行，或者将签名的 `uiAccess="true"` EXE 复制到任何可写的子目录（例如存在时的更新遗留物如 `Tasks_Migrated`）即可通过安全路径检查。
- **将 MSIX 放入 `C:\Program Files\WindowsApps`（已修复）**：非管理员用户可以安装签名的 MSIX 包到 `WindowsApps`，该路径此前未被排除。将 UIAccess 二进制打包到 MSIX 中并通过 `RAiLaunchAdminProcess` 启动，会产生无提示的 High-IL UIAccess 进程。Microsoft 已通过排除该路径进行缓解；`uiAccess` 限制的 MSIX 能力本身也已要求管理员安装。

## 攻击流程（无提示获得 High IL）
1. 获取/构建一个**签名的 UIAccess 二进制**（manifest 中 `uiAccess="true"`）。
2. 将其放置到 AppInfo 允许的路径（或滥用上述路径验证边缘情况/可写工件）。
3. 调用 `RAiLaunchAdminProcess` 以 **静默** 启动它，带有 UIAccess + 提升的 IL。
4. 从该 High-IL 立足点，使用 **窗口钩子/DLL 注入** 或其他同 IL 原语针对桌面上的另一个 High-IL 进程，完全攻破管理员上下文。

## 列举候选可写路径
运行 PowerShell 辅助工具，以从所选令牌的视角发现名义上安全根目录内的可写/可覆盖对象：
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 以管理员身份运行以获得更广的可见性；将 `-ProcessId` 设置为低权限进程以镜像该令牌的访问权限。
- 在使用带有 `RAiLaunchAdminProcess` 的候选项之前，手动筛选以排除已知不允许的子目录。

## 参考资料
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
