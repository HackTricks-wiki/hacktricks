# Kernel-Mode 文件访问检查绕过

{{#include ../../banners/hacktricks-training.md}}

## 易受攻击的驱动程序模式

驱动程序仅通过模拟调用者，并不能保留调用者的安全边界。内核模式下打开对象通常会绕过访问检查。`OBJ_KERNEL_HANDLE` 只会让生成的句柄可从内核模式访问。当驱动程序代表用户模式打开或操作对象时，还必须使用 `OBJ_FORCE_ACCESS_CHECK`，以便 Object Manager 根据有效令牌检查请求的访问权限。<sup>[[3]](#references)[[4]](#references)</sup>

审计文件处理 IOCTL 和创建回调时，检查是否存在以下流程：<sup>[[3]](#references)[[4]](#references)</sup>

1. 用户模式提供路径、源句柄、所需访问权限或操作类型。
2. 驱动程序模拟调用者，但调用 `IoCreateFileEx`、`ZwCreateFile` 或类似例程时未使用 `OBJ_FORCE_ACCESS_CHECK`。
3. 内核专用的文件或目录句柄被保存到每个句柄对应的状态中。
4. 后续操作根据受攻击者影响的状态（例如首次打开时请求的访问掩码）决定是否进行模拟。
5. 特权分支使用 `BypassAccessCheck` 信息类执行重命名或链接操作。

这是一个**confused-deputy 文件原语**，不一定涉及内存破坏。一种特别危险的状态反转是“请求写入时进行模拟；未请求写入时则保持特权”。在这种设计中，故意只请求读取权限就能解锁权限更强的路径。<sup>[[3]](#references)</sup>

## vSMB 示例：特权根目录加特权重命名

`storvsp.sys` 实现了 Virtual Server Message Block (vSMB)。启用 **Virtual Machine Platform** 功能后，用户模式可以通过 `\\.\STORVSP` 访问 `\Device\STORVSP`。vSMB 文件系统路径的形式为 `\\.\STORVSP\VSMB\??\C:\path`。CVE-2025-59517 和 CVE-2025-64673 展示了两个不一致的访问控制决策如何将此接口变成本地权限提升途径。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

源代码中的函数与 CVE 对应关系来自对已修补二进制文件的逆向工程，而非 Microsoft 源代码。研究人员提醒，这两个标识符可能对应的是相反的函数。<sup>[[3]](#references)</sup>

### 1. 创建以受保护目录为根目录的只读共享

易受攻击的创建路径会将请求的权限记录在 `HasReadAccess`、`HasWriteAccess` 和 `HasAppendAccess` 等持久标志中。随后，它使用 `OBJ_KERNEL_HANDLE` 打开后端路径，但未使用 `OBJ_FORCE_ACCESS_CHECK`。因此，即使尝试进行模拟，文件打开操作也不会遵循调用者的 NTFS 权限。<sup>[[3]](#references)[[4]](#references)</sup>

只请求 `FILE_READ_DATA`。这样会使 `HasWriteAccess` 保持未设置，同时仍能获得一个内部根目录位于受保护目录的共享：<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

重要的 artifact 不是 user-mode 的 System32 目录句柄，而是与 driver state 关联的 vSMB device handle，其中包含一个特权 kernel root handle。<sup>[[3]](#references)</sup>

### 2. 利用 state mismatch 替换受保护文件

IOCTL `0x240330` 接受一个源文件句柄、一个信息类，以及一个可变长度的信息缓冲区：<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

存在漏洞的处理程序接受 `FileRenameInformation`、`FileLinkInformation` 和 `FileRenameInformationEx`。对于普通重命名路径，它会将父路径与最后一个组件分开，然后相对于已存储的根句柄打开父目录。该打开操作同样使用 `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE`，但没有使用 `OBJ_FORCE_ACCESS_CHECK`。如果重命名结构中攻击者提供的 `RootDirectory` 非零，则会被拒绝，因此驱动程序会提供自己的特权目录句柄。<sup>[[3]](#references)</sup>

在 stage 1 中**不请求写入权限**，就会进入可利用分支：<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`：模拟已保存的根安全上下文。
- `HasWriteAccess == 0`：跳过模拟，并将 `FileRenameInformation` 或 `FileRenameInformationEx` 转换为对应的 `BypassAccessCheck` 变体。

处理程序将攻击者提供的源句柄复制到 `PsInitialSystemProcess` 中，将其引用为文件对象，在重命名结构中设置特权目标目录句柄，然后调用 `ZwSetInformationFile`。因此，当 `ReplaceIfExists = TRUE` 时，调用者控制的文件可以替换受保护根目录下的现有文件。<sup>[[3]](#references)</sup>

审查类似处理程序时，应跟踪每个分支中的**句柄来源和安全上下文**。输入验证、整数溢出检查、`IO_STOP_ON_SYMLINK` 以及限制接受的信息类，都无法弥补特权根句柄与绕过访问检查操作组合带来的风险。<sup>[[3]](#references)</sup>

## 从受保护写入到 SYSTEM 执行

当特权进程之后加载被替换的模块时，受保护文件替换原语就能转化为代码执行。在演示的利用链中，目标文件是 `C:\Windows\System32\wuapi.dll`。激活本地服务器 COM 类 `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}`，并指定接口 `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}`，然后调用 `IWaaSRemediation::LaunchDetectionOnly()`，即可使 SYSTEM 进程加载该 DLL。<sup>[[3]](#references)</sup>

此 COM 调用是一个**激活触发器**，而不是 [COM registry hijacking](com-hijacking.md)。文件原语负责放置模块，特权加载器则负责执行。对于其他受保护写入利用链，在选择目标之前，应确定确切的映像、DLL 路径、签名策略、位数、导出函数以及可靠的触发方式。有关通用的加载器分析流程，请参阅[将任意文件写入串联为 DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)。<sup>[[3]](#references)</sup>

### 将 Session 0 令牌移至交互式桌面

由服务加载的 payload 通常在 Session 0 中执行。若要创建交互式进程，它可以通过 `WTSGetActiveConsoleSessionId` 获取当前活动的控制台会话，启用所需的令牌权限，将当前 SYSTEM 令牌复制为主令牌，并将其 `TokenSessionId` 设置为活动会话。随后，`CreateProcessAsUserW` 使用该令牌，并将 `STARTUPINFO.lpDesktop` 设置为 `L"winsta0\\default"`。<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

在此场景中，设置 token 的会话 ID 需要 `SeTcbPrivilege`。交互式窗口站和桌面也必须授予该 token 访问权限。有关更广泛的 token 复制工作流，请参阅 [从 Session 0 复制 token](sedebug-+-seimpersonate-copy-token.md)。<sup>[[3]](#references)[[5]](#references)</sup>

## 补丁和审查指南

Microsoft 于 2025 年 12 月发布的更新修复了所演示的攻击链。逆向工程发现，修补后的 vSMB 创建路径会拒绝不受信任的调用方在未请求 `FILE_WRITE_DATA` 的情况下请求共享根目录。相关操作也增加了强制访问检查。这会在非特权调用方获取特权根目录之前阻止状态反转。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

对于驱动程序代码，请遵循以下规则：<sup>[[3]](#references)[[4]](#references)</sup>

- 代表用户模式请求打开对象时，添加 `OBJ_FORCE_ACCESS_CHECK`。不要将 `OBJ_KERNEL_HANDLE` 视为授权控制。<sup>[[4]](#references)</sup>
- 捕获并验证请求者模式和有效主体上下文。不要让请求的权限决定进入更高权限的执行分支。
- 使用正确的对象类型、访问掩码和 `UserMode` 验证用户句柄。将句柄复制到系统进程中，并不能验证请求操作是否具有相应权限。
- 让目标解析相对于受信任句柄进行，但要确保该受信任句柄本身是在执行请求者访问检查的情况下打开的。
- 避免在由用户驱动的操作中使用 `File*BypassAccessCheck` 类。如果内部代码确实需要使用它们，应使用独立于用户可控访问标志的授权决策来限制该路径。
- 为受影响的系统安装补丁。加载 `storvsp.sys` 的 Virtual Machine Platform 会涉及此漏洞攻击面。<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - 从 Virtual Share 到 Physical Shell：利用 Windows 不一致的访问控制实现 LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - 对象句柄](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - CreateProcessAsUserW 函数](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
