# 通过 UIAccess 绕过 Admin Protection

{{#include ../../banners/hacktricks-training.md}}

## 概述
- Windows AppInfo 暴露了 `RAiLaunchAdminProcess` 来生成 UIAccess 进程（用于辅助功能）。UIAccess 绕过大多数 User Interface Privilege Isolation (UIPI) 的消息过滤，使辅助功能软件能够驱动更高 IL 的 UI。
- 直接启用 UIAccess 需要 `NtSetInformationToken(TokenUIAccess)` 并具有 **SeTcbPrivilege**，因此低权限调用者依赖该服务。该服务在设置 UIAccess 之前对目标二进制执行三项检查：
  - 嵌入的 manifest 包含 `uiAccess="true"`。
  - 由 Local Machine 根存储信任的任意证书签名（不要求 EKU/Microsoft）。
  - 位于系统盘上仅管理员可用的路径（例如 `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`，但排除特定可写子路径）。
- `RAiLaunchAdminProcess` 对 UIAccess 启动不弹出同意提示（否则辅助工具无法驱动该提示）。

## 令牌塑造与完整性级别
- 如果检查通过，AppInfo **复制调用者令牌**，启用 UIAccess，并提升完整性级别 (IL)：
  - 受限管理员用户（用户属于 Administrators 但运行被过滤） ➜ **High IL**。
  - 非管理员用户 ➜ IL 增加 **+16 级**，上限为 **High**（不会分配 System IL）。
- 如果调用者令牌已经具有 UIAccess，则 IL 保持不变。
- “棘轮”技巧：UIAccess 进程可以在自身上禁用 UIAccess，然后通过 `RAiLaunchAdminProcess` 重新启动，从而再获得 +16 IL 的提升。Medium➜High 需要 255 次重启（噪声大，但可行）。

## 为什么 UIAccess 会导致绕过 Admin Protection
- UIAccess 允许较低 IL 的进程向较高 IL 的窗口发送窗口消息（绕过 UIPI 过滤）。在 **相同 IL** 下，经典的 UI 原语如 `SetWindowsHookEx` **确实允许代码注入/加载 DLL** 到任何拥有窗口的进程（包括 COM 使用的 **message-only windows**）。
- Admin Protection 会在 **受限用户身份** 下但以 **High IL** 静默地启动 UIAccess 进程。一旦任意代码在该 High-IL 的 UIAccess 进程内运行，攻击者可以向桌面上的其他 High-IL 进程注入（甚至属于不同用户的进程），从而破坏预期的隔离。

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- 在 Windows 10 1803 及更高版本，该 API 迁移到 Win32k（`NtUserGetWindowProcessHandle`），并且可以使用调用者提供的 `DesiredAccess` 打开进程句柄。内核路径使用 `ObOpenObjectByPointer(..., KernelMode, ...)`，从而绕过正常的用户模式访问检查。
- 实际前提条件：目标窗口必须在相同桌面上，且 UIPI 检查必须通过。历史上，具有 UIAccess 的调用者可以在 UIPI 失败的情况下绕过并仍然获得内核模式句柄（已作为 CVE-2023-41772 修复）。
- 影响：窗口句柄变成获取强大进程句柄的**能力**（常见为 `PROCESS_DUP_HANDLE`、`PROCESS_VM_READ`、`PROCESS_VM_WRITE`、`PROCESS_VM_OPERATION`），这些是调用者通常无法打开的。这使得跨沙箱访问成为可能，并且如果目标暴露任何窗口（包括 message-only windows），可破坏 Protected Process / PPL 的边界。
- 实际滥用流程：枚举或定位 HWND（例如 `EnumWindows`/`FindWindowEx`），解析拥有者 PID（`GetWindowThreadProcessId`），调用 `GetProcessHandleFromHwnd`，然后使用返回的句柄进行内存读/写或代码劫持原语。
- 修复后行为：UIAccess 不再在 UIPI 失败时授予内核模式打开，允许的访问权限被限制为传统的 hook 集；Windows 11 24H2 增加了进程保护检查和受功能标志控制的更安全路径。全局禁用 UIPI（`EnforceUIPI=0`）会削弱这些防护。

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo 通过 `GetFinalPathNameByHandle` 解析所提供的路径，然后对硬编码的根/排除项执行 **字符串允许/拒绝检查**。多种绕过类别源自这种简单的验证：
- **Directory named streams**：被排除的可写目录（例如 `C:\Windows\tracing`）可以通过在目录本身上使用命名流来绕过，例如 `C:\Windows\tracing:file.exe`。字符串检查只看到 `C:\Windows\` 并遗漏被排除的子路径。
- **Writable file/directory inside an allowed root**：`CreateProcessAsUser` **不要求 `.exe` 扩展名**。在允许根目录下覆盖任意可写文件为可执行负载即可，或者将签名的 `uiAccess="true"` EXE 复制到任何可写子目录（例如存在时的更新残留 `Tasks_Migrated`）也能通过安全路径检查。
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**：非管理员可以安装签名的 MSIX 包并放置到 `WindowsApps`，该路径当时未被排除。将 UIAccess 二进制打包到 MSIX 中并通过 `RAiLaunchAdminProcess` 启动，会产生一个**无提示的 High-IL UIAccess 进程**。Microsoft 通过将该路径列入排除项进行了缓解；`uiAccess` 限制的 MSIX 能力本身也已要求管理员安装。

## Attack workflow (High IL without a prompt)
1. 获取/构建一个 **signed UIAccess binary**（manifest `uiAccess="true"`）。
2. 将其放置在 AppInfo 的允许列表接受的位置（或利用上述路径验证的边缘情况/可写残留物）。
3. 调用 `RAiLaunchAdminProcess` 以 **silently** 生成带有 UIAccess 和提升 IL 的进程。
4. 从该 High-IL 立足点，使用 **window hooks/DLL injection** 或其他同 IL 原语针对桌面上的另一个 High-IL 进程，完全攻破管理员上下文。

## 枚举候选可写路径
运行 PowerShell 助手，从所选令牌的视角发现名义上安全根目录下的可写/可覆盖对象：
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 以管理员身份运行以获得更广的可见性；将 `-ProcessId` 设置为低权限进程以镜像该令牌的访问权限。
- 在使用带有 `RAiLaunchAdminProcess` 的候选项之前，手动过滤以排除已知的不允许的子目录。

## 相关

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## 参考资料
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
