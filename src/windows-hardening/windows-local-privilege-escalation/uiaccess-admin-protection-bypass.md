# 通过 UIAccess 绕过 Admin Protection

{{#include ../../banners/hacktricks-training.md}}

## 概述
- Windows AppInfo 暴露 `RAiLaunchAdminProcess`，用于生成 UIAccess 进程（旨在提供辅助功能）。UIAccess 会绕过大多数 User Interface Privilege Isolation (UIPI) 消息过滤，使辅助功能软件能够操作更高 IL 的 UI。
- 直接启用 UIAccess 需要使用 **SeTcbPrivilege** 调用 `NtSetInformationToken(TokenUIAccess)`，因此低权限调用者依赖该服务。该服务会在设置 UIAccess 前对目标 binary 执行三项检查：
- 嵌入式 manifest 包含 `uiAccess="true"`。
- 由 Local Machine 根存储中信任的任意证书签名（不要求 EKU/Microsoft）。
- 位于系统驱动器上的仅管理员可写入路径中（例如 `C:\Windows`、`C:\Windows\System32`、`C:\Program Files`，但排除特定可写入子路径）。
- `RAiLaunchAdminProcess` 对 UIAccess 启动不会显示 consent prompt（否则辅助功能工具将无法操作该 prompt）。<sup>[[1]](#references)</sup>

## Token shaping 和完整性级别
- 如果检查成功，AppInfo 会 **复制调用者 token**、启用 UIAccess，并提升 Integrity Level (IL)：
- 受限管理员用户（用户属于 Administrators，但正在以过滤后的权限运行）➜ **High IL**。
- 非管理员用户 ➜ IL 增加 **+16 个级别**，最高为 **High**（永远不会分配 System IL）。
- 如果调用者 token 已具有 UIAccess，则 IL 保持不变。
- “Ratchet” 技巧：UIAccess 进程可以禁用自身的 UIAccess，通过 `RAiLaunchAdminProcess` 重新启动，并再次获得 +16 个 IL 增量。从 Medium➜High 需要重新启动 255 次（动静较大，但可行）。<sup>[[1]](#references)</sup>

## UIAccess 为何能够实现 Admin Protection escape
- UIAccess 允许较低 IL 的进程向较高 IL 的窗口发送窗口消息（绕过 UIPI filters）。在 **相同 IL** 下，经典 UI 原语（如 `SetWindowsHookEx`）**确实允许 code injection/DLL loading** 到任何拥有窗口的进程中（包括 COM 使用的 **message-only windows**）。
- Admin Protection 会以 **受限用户的身份**启动 UIAccess 进程，但将其设置为 **High IL**，且不会显示提示。任意 code 在该 High-IL UIAccess 进程中运行后，攻击者即可注入桌面上的其他 High-IL 进程（甚至属于不同用户的进程），破坏原本预期的隔离。<sup>[[1]](#references)</sup>

## HWND-to-process handle 原语（`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`）
- 在 Windows 10 1803+ 中，该 API 移入 Win32k（`NtUserGetWindowProcessHandle`），并可使用调用者提供的 `DesiredAccess` 打开进程句柄。内核路径使用 `ObOpenObjectByPointer(..., KernelMode, ...)`，从而绕过正常的 user-mode access checks。<sup>[[2]](#references)</sup>
- 实际前提：目标窗口必须位于同一 desktop 上，并且 UIPI checks 必须通过。历史上，具有 UIAccess 的调用者可以绕过 UIPI failure，仍然获得 kernel-mode handle（已通过 CVE-2023-41772 修复）。
- 影响：窗口句柄成为一种 **capability**，可用于获取调用者通常无法打开的强大进程句柄（通常包括 `PROCESS_DUP_HANDLE`、`PROCESS_VM_READ`、`PROCESS_VM_WRITE`、`PROCESS_VM_OPERATION`）。这使得 cross-sandbox access 成为可能；如果目标暴露任何窗口（包括 message-only windows），还可能突破 Protected Process / PPL 边界。
- 实际滥用流程：枚举或定位 HWND（例如使用 `EnumWindows`/`FindWindowEx`），解析其所属 PID（`GetWindowThreadProcessId`），调用 `GetProcessHandleFromHwnd`，然后使用返回的句柄执行 memory read/write 或 code-hijack 原语。
- 修复后的行为：UIAccess 不再在 UIPI failure 时授予 kernel-mode opens，允许的 access rights 被限制为 legacy hook set；Windows 11 24H2 增加了 process-protection checks 和由 feature flag 控制的更安全路径。全系统禁用 UIPI（`EnforceUIPI=0`）会削弱这些保护。<sup>[[2]](#references)</sup>

## Secure-directory validation 弱点（AppInfo `AiCheckSecureApplicationDirectory`）
AppInfo 通过 `GetFinalPathNameByHandle` 解析给定路径，然后针对硬编码的 roots/exclusions 执行 **字符串 allow/deny checks**。这种简单验证会导致多类 bypass：
- **Directory named streams**：可以在被排除的可写目录（例如 `C:\Windows\tracing`）本身上使用 named stream 绕过检查，例如 `C:\Windows\tracing:file.exe`。字符串检查会看到 `C:\Windows\`，但会遗漏被排除的子路径。
- **允许的 root 内的可写文件/目录**：`CreateProcessAsUser` **不要求 `.exe` 扩展名**。覆盖允许 root 下的任意可写文件并写入 executable payload 即可，或者将已签名且包含 `uiAccess="true"` 的 EXE 复制到任意可写子目录（例如存在时的更新残留目录 `Tasks_Migrated`），即可通过 secure-path check。
- **将 MSIX 放入 `C:\Program Files\WindowsApps`（已修复）**：非管理员可以安装已签名的 MSIX package，使其落入 `WindowsApps`，而该路径当时未被排除。在 MSIX 内打包 UIAccess binary，然后通过 `RAiLaunchAdminProcess` 启动，可以得到一个 **无需 prompt 的 High-IL UIAccess 进程**。Microsoft 已通过排除此路径进行缓解；`uiAccess` restricted MSIX capability 本身已经要求管理员安装。<sup>[[1]](#references)</sup>

## Attack workflow（无 prompt 获得 High IL）
1. 获取/构建一个 **已签名的 UIAccess binary**（manifest `uiAccess="true"`）。
2. 将其放置到 AppInfo allowlist 接受的位置（或如上所述滥用 path-validation edge case/writable artifact）。
3. 调用 `RAiLaunchAdminProcess`，以 **静默方式**启动它，并获得 UIAccess + elevated IL。
4. 从该 High-IL foothold 出发，使用 **window hooks/DLL injection** 或其他 same-IL primitives，攻击桌面上的另一个 High-IL 进程，从而完全 compromise admin context。<sup>[[1]](#references)</sup>

## 枚举候选可写入路径
运行 PowerShell helper，从指定 token 的视角发现名义上安全 roots 内可写入/可覆盖的对象：<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 以 Administrator 身份运行以获得更广泛的可见性；将 `-ProcessId` 设置为低权限进程，以模拟该令牌的访问权限。
- 在使用候选项调用 `RAiLaunchAdminProcess` 之前，手动筛选并排除已知的不允许子目录。

## 相关内容

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## 参考资料

- [1] [通过滥用 UI Access 绕过 Administrator Protection](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) 深入解析](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
