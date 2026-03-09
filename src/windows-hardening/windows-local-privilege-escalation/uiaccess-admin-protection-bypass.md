# 通过 UIAccess 绕过 Admin Protection

{{#include ../../banners/hacktricks-training.md}}

## 概述
- Windows AppInfo 暴露了 `RAiLaunchAdminProcess` 用于启动 UIAccess 进程（为无障碍功能设计）。UIAccess 绕过大多数 User Interface Privilege Isolation (UIPI) 消息过滤，以便无障碍软件可以驱动更高 IL 的 UI。
- 直接启用 UIAccess 需要调用 `NtSetInformationToken(TokenUIAccess)` 并拥有 **SeTcbPrivilege**，因此低权限调用者依赖该服务。服务在设置 UIAccess 之前对目标二进制执行三个检查：
  - 嵌入的 manifest 包含 `uiAccess="true"`。
  - 由本地机器根存储中受信任的任意证书签名（不要求 EKU/Microsoft）。
  - 位于系统盘上的仅管理员路径（例如 `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`，排除特定可写子路径）。
- `RAiLaunchAdminProcess` 在启动 UIAccess 时不执行同意提示（否则无障碍工具将无法驱动提示窗口）。

## Token shaping and integrity levels
- 如果检查通过，AppInfo **复制调用者 token**，启用 UIAccess，并提高 Integrity Level (IL)：
  - Limited admin user（用户属于 Administrators 但以受限方式运行） ➜ **High IL**。
  - 非管理员用户 ➜ IL 增加 **+16 级**，上限为 **High**（不会分配 System IL）。
- 如果调用者 token 已有 UIAccess，则 IL 保持不变。
- “Ratchet” 技巧：UIAccess 进程可以在自身禁用 UIAccess，随后通过 `RAiLaunchAdminProcess` 重新启动，从而再获得一次 +16 IL 增量。Medium➜High 需要 255 次重启（噪音大，但可行）。

## Why UIAccess enables an Admin Protection escape
- UIAccess 允许低 IL 进程向更高 IL 的窗口发送窗口消息（绕过 UIPI 过滤）。在 **相同 IL** 时，经典的 UI 原语如 `SetWindowsHookEx` **确实允许代码注入/DLL 加载** 到拥有窗口的任意进程（包括 COM 使用的 **message-only windows**）。
- Admin Protection 在 **High IL** 下以受限用户身份静默启动 UIAccess 进程。一旦任意代码在该 High-IL UIAccess 进程中运行，攻击者就能注入到桌面上的其他 High-IL 进程（甚至属于不同用户的进程），破坏本应存在的隔离。

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- 在 Windows 10 1803+，该 API 被移入 Win32k（`NtUserGetWindowProcessHandle`），并可以使用调用者提供的 `DesiredAccess` 打开进程句柄。内核路径使用 `ObOpenObjectByPointer(..., KernelMode, ...)`，这会绕过正常的用户模式访问检查。
- 实际先决条件：目标窗口必须位于相同桌面，且 UIPI 检查必须通过。历史上，具有 UIAccess 的调用者可以绕过 UIPI 失败并仍获取内核模式句柄（已修复为 CVE-2023-41772）。
- 影响：窗口句柄成为获取强大进程句柄的一种能力（常见为 `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`），这些是调用者通常无法打开的。这使跨沙箱访问成为可能，并且如果目标暴露任何窗口（包括 message-only 窗口），可能破坏 Protected Process / PPL 边界。
- 实际滥用流程：枚举或定位 HWND（例如 `EnumWindows`/`FindWindowEx`），解析所属 PID（`GetWindowThreadProcessId`），调用 `GetProcessHandleFromHwnd`，然后使用返回的句柄进行内存读写或代码劫持原语。
- 修复后行为：UIAccess 在 UIPI 失败时不再授予内核模式打开权限，允许的访问权被限制为传统 hook 集；Windows 11 24H2 增加了进程保护检查并通过特性标志提供更安全的路径。全系统禁用 UIPI（`EnforceUIPI=0`）会削弱这些保护。

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo 通过 `GetFinalPathNameByHandle` 解析提供的路径，然后对硬编码的根/排除项应用 **字符串允许/拒绝检查**。这种简单的验证产生多类绕过：
- **Directory named streams**：被排除的可写目录（例如 `C:\Windows\tracing`）可以通过在目录本身上使用命名流绕过，例如 `C:\Windows\tracing:file.exe`。字符串检查看到 `C:\Windows\` 并忽略了被排除的子路径。
- **Writable file/directory inside an allowed root**：`CreateProcessAsUser` **不要求有 `.exe` 扩展名**。在允许的根下覆盖任何可写文件为可执行负载即可生效，或者将已签名且包含 `uiAccess="true"` 的 EXE 复制到任何可写子目录（例如存在时的更新残留 `Tasks_Migrated`）也能让其通过安全路径检查。
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**：非管理员可以安装签名的 MSIX 包到 `WindowsApps`，该路径此前未被排除。将 UIAccess 二进制打包在 MSIX 中，然后通过 `RAiLaunchAdminProcess` 启动，会产生一个**无提示的 High-IL UIAccess 进程**。Microsoft 已通过将该路径排除来缓解；`uiAccess` 受限的 MSIX 能力本身也要求管理员安装。

## Attack workflow (High IL without a prompt)
1. 获取/构建一个**已签名的 UIAccess 二进制**（manifest 包含 `uiAccess="true"`）。
2. 将其放置在 AppInfo 的允许列表接受的位置（或滥用上述路径验证边缘情况/可写工件）。
3. 调用 `RAiLaunchAdminProcess` 以 **静默** 启动它，带有 UIAccess + 提升的 IL。
4. 从该 High-IL 立足点，使用 **window hooks/DLL injection** 或其他同 IL 原语，针对桌面上的另一个 High-IL 进程，完全控制管理员上下文。

## Enumerating candidate writable paths
运行 PowerShell helper 从所选 token 的视角发现名义上安全根内的可写/可覆盖对象：
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 以管理员身份运行以获得更广泛的可见性；将 `-ProcessId` 设置为低权限进程以镜像该令牌的访问。
- 在使用带有 `RAiLaunchAdminProcess` 的候选项之前，手动过滤以排除已知的不允许的子目录。

## References
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
