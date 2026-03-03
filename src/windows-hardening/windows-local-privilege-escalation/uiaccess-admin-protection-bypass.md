# 管理员保护绕过（通过 UIAccess）

{{#include ../../banners/hacktricks-training.md}}

## 概览
- Windows AppInfo 暴露了 `RAiLaunchAdminProcess` 来生成 UIAccess 进程（用于辅助功能）。UIAccess 绕过大多数 User Interface Privilege Isolation (UIPI) 的消息过滤，使可访问性软件能够操作更高 IL 的 UI。
- 直接启用 UIAccess 需要通过 `NtSetInformationToken(TokenUIAccess)` 并具有 **SeTcbPrivilege**，因此低权限调用者依赖该 service。service 在为目标二进制设置 UIAccess 之前执行三项检查：
- 嵌入的 manifest 包含 `uiAccess="true"`。
- 由任何受 Local Machine 根证书存储信任的证书签名（无 EKU/Microsoft 要求）。
- 位于系统盘上的管理员专用路径（例如 `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`，排除特定的可写子路径）。
- `RAiLaunchAdminProcess` 对 UIAccess 启动不执行同意提示（否则辅助功能工具将无法驱动提示）。

## Token shaping 和 完整性等级
- 如果检查通过，AppInfo 会**复制调用者 token**，启用 UIAccess，并提升完整性等级 (IL)：
- 受限的管理员用户（用户属于 Administrators 但运行被过滤） ➜ **High IL**。
- 非管理员用户 ➜ IL 增加 **+16 级**，直到 **High** 上限（System IL 永远不会分配）。
- 如果调用者 token 已有 UIAccess，则 IL 保持不变。
- “棘轮” 技巧：UIAccess 进程可以在自身上禁用 UIAccess，通过 `RAiLaunchAdminProcess` 重新启动，并再次获得 +16 IL 的增量。Medium➜High 需要 255 次重启（很吵但可行）。

## 为什么 UIAccess 导致 Admin Protection 绕过
- UIAccess 允许低 IL 进程向高 IL 窗口发送窗口消息（绕过 UIPI 过滤）。在 **相同 IL** 时，经典的 UI 原语如 `SetWindowsHookEx` **确实允许代码注入/加载 DLL** 到拥有窗口的任何进程（包括 COM 使用的 message-only 窗口）。
- Admin Protection 在 **High IL** 下以**受限用户的身份**静默地启动 UIAccess 进程。一旦任意代码在该 High-IL UIAccess 进程中运行，攻击者就能注入到桌面上的其他 High-IL 进程（即使属于不同用户），破坏预期的隔离。

## HWND 到进程句柄 原语 (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- 在 Windows 10 1803+，该 API 转移到 Win32k（`NtUserGetWindowProcessHandle`），并能使用调用者提供的 `DesiredAccess` 打开进程句柄。内核路径使用 `ObOpenObjectByPointer(..., KernelMode, ...)`，这会绕过正常的用户模式访问检查。
- 实际前提条件：目标窗口必须在相同桌面上，且 UIPI 检查必须通过。历史上，带有 UIAccess 的调用者可以在 UIPI 失败时仍绕过并获取内核模式句柄（已修复，见 CVE-2023-41772）。
- 影响：窗口句柄成为获取强大进程句柄的**能力**（常见为 `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`），这些是调用者通常无法打开的。这使得跨沙箱访问成为可能，并且如果目标暴露任何窗口（包括 message-only 窗口），可以突破 Protected Process / PPL 边界。
- 实际滥用流程：枚举或定位 HWND（例如 `EnumWindows`/`FindWindowEx`），解析所属 PID（`GetWindowThreadProcessId`），调用 `GetProcessHandleFromHwnd`，然后使用返回的句柄进行内存读写或代码劫持原语。
- 修复后行为：UIAccess 在 UIPI 失败时不再授予内核模式打开，允许的访问权限被限制为传统钩子集合；Windows 11 24H2 增加了进程保护检查和带特性开关的更安全路径。系统范围禁用 UIPI（`EnforceUIPI=0`）会削弱这些保护。

## 安全目录验证弱点（AppInfo `AiCheckSecureApplicationDirectory`）
AppInfo 通过 `GetFinalPathNameByHandle` 解析所提供的路径，然后对硬编码的根/排除项应用**字符串允许/拒绝检查**。这种简单验证导致多类绕过：
- **目录命名流**：被排除的可写目录（例如 `C:\Windows\tracing`）可以通过在目录本身上使用命名流绕过，例如 `C:\Windows\tracing:file.exe`。字符串检查看到的是 `C:\Windows\`，并会遗漏被排除的子路径。
- **允许根下的可写文件/目录**：`CreateProcessAsUser` **不要求 `.exe` 扩展名**。在允许根下覆写任何可写文件为可执行有效载荷可生效，或将已签名且包含 `uiAccess="true"` 的 EXE 复制到任何可写子目录（例如存在的更新遗留目录如 `Tasks_Migrated`）也能通过安全路径检查。
- **将 MSIX 安装到 `C:\Program Files\WindowsApps`（已修复）**：非管理员可以安装签名的 MSIX 包到 `WindowsApps`，该路径此前未被排除。将 UIAccess 二进制打包到 MSIX 并通过 `RAiLaunchAdminProcess` 启动，会产生一个**无提示的 High-IL UIAccess 进程**。Microsoft 已通过排除此路径来缓解；此外，`uiAccess` 受限的 MSIX 能力本身已要求管理员安装。

## 攻击工作流（无提示获得 High IL）
1. 获取/构建一个**已签名的 UIAccess 二进制**（manifest 含 `uiAccess="true"`）。
2. 将其放置在 AppInfo 的允许列表接受的路径（或利用上文所述的路径验证边缘情况/可写工件）。
3. 调用 `RAiLaunchAdminProcess` 静默生成它，带 UIAccess + 被提升的 IL。
4. 从该 High-IL 立足点，使用 **窗口钩子/DLL 注入** 或其他相同 IL 原语定位桌面上的另一个 High-IL 进程，完全攻陷管理员上下文。

## 枚举候选可写路径
运行 PowerShell helper 以从所选 token 的视角发现名义上安全根目录内的可写/可覆写对象：
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 以管理员身份运行以获得更广泛的可见性；将 `-ProcessId` 设置为低权限进程以镜像该 token 的访问权限。
- 在使用带有 `RAiLaunchAdminProcess` 的候选项之前，手动过滤以排除已知的不允许的子目录。

## References
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
