# 通过 UIAccess 绕过管理员保护

{{#include ../../banners/hacktricks-training.md}}

## 概述
- Windows AppInfo 暴露了用于启动辅助功能 UIAccess 应用的内部 `RAiLaunchAdminProcess` 路径。UIAccess 允许在 User Interface Privilege Isolation (UIPI) 边界之间进行选定的交互；它并不是绕过所有进程安全边界的通用方法。<sup>[[1]](#references)[[3]](#references)</sup>
- 直接启用 UIAccess 需要使用 **SeTcbPrivilege** 调用 `NtSetInformationToken(TokenUIAccess)`，因此低权限调用者依赖该服务。该服务会在设置 UIAccess 前对目标二进制文件执行三项检查：
- 嵌入式 manifest 包含 `uiAccess="true"`。
- 由 Local Machine 根证书存储中信任的任意证书签名（不要求 EKU/Microsoft）。
- 位于系统驱动器上仅管理员可写入的路径中（例如 `C:\Windows`、`C:\Windows\System32`、`C:\Program Files`，同时排除特定的可写子路径）。
- `RAiLaunchAdminProcess` 启动 UIAccess 应用时不会显示 consent prompt（否则辅助功能工具将无法操作该提示）。<sup>[[1]](#references)</sup>

## Token shaping 与完整性级别
- 如果检查成功，AppInfo 会**复制调用者 token**、启用 UIAccess，并提升 Integrity Level (IL)：
- 受限管理员用户（用户属于 Administrators，但正在运行过滤后的 token）➜ **High IL**。
- 非管理员用户 ➜ IL 增加 **+16 个级别**，最高达到 **High**（不会分配 System IL）。
- 如果调用者 token 已具有 UIAccess，则 IL 保持不变。
- “Ratchet” 技巧：UIAccess 进程可以先禁用自身的 UIAccess，再通过 `RAiLaunchAdminProcess` 重新启动，从而再次获得 +16 个 IL 增量。Medium➜High 需要重新启动 255 次（动静较大，但可行）。<sup>[[1]](#references)</sup>

## UIAccess 为何能实现 Admin Protection escape
- UIAccess 允许低 IL 进程向高 IL 窗口发送窗口消息（绕过 UIPI filters）。在**相同 IL** 下，经典 UI 原语（例如 `SetWindowsHookEx`）确实允许向拥有窗口的任意进程中注入代码/加载 DLL（包括 COM 使用的 **message-only windows**）。
- Admin Protection 会以**受限用户的身份**启动 UIAccess 进程，但将其运行在 **High IL**，且不会显示提示。任意代码一旦在该 High-IL UIAccess 进程中运行，攻击者便可向桌面上的其他 High-IL 进程（即使属于不同用户）执行注入，从而破坏预期的隔离。<sup>[[1]](#references)</sup>

## HWND 到进程句柄原语（`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`）
- 在 Windows 10 1803 及更高版本中，该 API 移入 Win32k（`NtUserGetWindowProcessHandle`），并可使用调用者提供的 `DesiredAccess` 打开进程句柄。内核路径使用 `ObOpenObjectByPointer(..., KernelMode, ...)`，从而绕过常规的 user-mode 访问检查。<sup>[[2]](#references)</sup>
- 实际前提：目标窗口必须位于同一 desktop 上，并且 UIPI 检查必须通过。从历史上看，具有 UIAccess 的调用者可以绕过 UIPI failure，仍然获得 kernel-mode 句柄（该问题已通过 CVE-2023-41772 修复）。
- 历史影响：窗口句柄成为一种进程访问**能力**，可用于获取调用者通常无法获得的 `PROCESS_DUP_HANDLE`、`PROCESS_VM_READ`、`PROCESS_VM_WRITE` 或 `PROCESS_VM_OPERATION` 等权限。在文档化修复发布前，只要目标暴露窗口（包括 message-only window），该问题就可能跨越 sandbox 和 protected-process 边界。<sup>[[2]](#references)</sup>
- 实际滥用流程：枚举或定位 HWND（例如 `EnumWindows`/`FindWindowEx`），解析所属 PID（`GetWindowThreadProcessId`），调用 `GetProcessHandleFromHwnd`，然后使用返回的句柄执行内存读写或代码劫持原语。
- 修复后的行为：UIPI failure 时，UIAccess 不再授予 kernel-mode opens，允许的访问权限也被限制为 legacy hook set；Windows 11 24H2 增加了 process-protection checks 和由 feature flag 控制的更安全路径。全局禁用 UIPI（`EnforceUIPI=0`）会削弱这些保护。<sup>[[2]](#references)</sup>

## Secure-directory validation 弱点（AppInfo `AiCheckSecureApplicationDirectory`）
AppInfo 通过 `GetFinalPathNameByHandle` 解析所提供的路径，然后针对硬编码的根路径/排除项执行**字符串 allow/deny checks**。这种简单的验证方式会产生多类 bypass：
- **Directory named streams**：可写目录（例如 `C:\Windows\tracing`）可以通过该目录自身的 named stream 绕过，例如 `C:\Windows\tracing:file.exe`。字符串检查会看到 `C:\Windows\`，却遗漏被排除的子路径。
- **允许根路径中的可写文件/目录**：`CreateProcessAsUser` **不要求 `.exe` 扩展名**。覆盖允许根路径下的任意可写文件并写入 executable payload 即可，或者将已签名且带有 `uiAccess="true"` 的 EXE 复制到任意可写子目录（例如存在时的 update leftovers，如 `Tasks_Migrated`），即可通过 secure-path check。
- **将 MSIX 放入 `C:\Program Files\WindowsApps`（已修复）**：非管理员可以安装已签名的 MSIX package，并使其落入 `WindowsApps`，而该路径当时未被排除。在 MSIX 中打包 UIAccess binary，然后通过 `RAiLaunchAdminProcess` 启动，即可获得一个**无提示的 High-IL UIAccess 进程**。Microsoft 已通过排除该路径进行缓解；`uiAccess` restricted MSIX capability 本身已经要求管理员安装。<sup>[[1]](#references)</sup>

## 攻击流程（无提示获得 High IL）
1. 获取/构建一个**已签名的 UIAccess binary**（manifest 为 `uiAccess="true"`）。进行实际 assessment 时，应使用实验室明确授权的 trust material 和路径进行测试；不要将攻击者证书添加到生产机器的 Local Machine 根证书存储中。
2. 将其放置在 AppInfo allowlist 接受的位置（或如上所述，滥用 path-validation edge case/可写 artifact）。
3. 调用 `RAiLaunchAdminProcess`，以 **UIAccess + elevated IL** 静默启动它。
4. 从该 High-IL foothold 出发，使用 **window hooks/DLL injection** 或其他 same-IL 原语，针对桌面上的另一个 High-IL 进程，从而完全 compromise admin context。<sup>[[1]](#references)</sup>

## 枚举候选可写路径
运行 PowerShell helper，从所选 token 的视角，发现名义上安全的根路径中可写/可覆盖的对象：<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 以 Administrator 身份运行以获得更广泛的可见性；将 `-ProcessId` 设置为低权限进程，以模拟该 token 的访问权限。
- 在使用候选项调用 `RAiLaunchAdminProcess` 之前，手动筛选并排除已知不允许的子目录。

## 相关内容

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [通过滥用 UI Access 绕过 Administrator Protection](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) 深入分析](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — UIAccess applications](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
