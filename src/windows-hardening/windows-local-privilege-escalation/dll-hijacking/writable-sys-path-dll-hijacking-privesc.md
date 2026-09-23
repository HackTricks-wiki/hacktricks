# 可写系统 PATH + DLL Hijacking 权限提升

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

如果你可以**写入系统范围 `PATH` 中的某个目录**（而不仅仅是你的用户 `PATH`），则可能能够在系统上**提升权限**。

当权限更高的 service 或 process 尝试加载一个在更早搜索位置中不存在的 DLL，并最终搜索可写的系统 `PATH` 目录时，就可以通过 **DLL hijacking** 滥用这一点。

可写的 Machine `PATH` 条目只是一个**原语**，并不能证明可以执行代码。对于使用标准搜索顺序的未打包应用程序，在重定向、API sets、SxS、已加载模块列表、KnownDLLs、应用程序目录和 Windows 目录以及当前目录之后，才会搜索 `PATH`。完整路径或 `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` 策略可能会完全排除 `PATH`。<sup>[[4]](#references)</sup>

有关 **DLL hijacking** 的更多信息，请参阅：

{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

首先，**识别一个以更高权限运行的 process**，该 process 会尝试**从可写的系统 `PATH` 目录加载 DLL**。

请记住，此技术依赖于 **Machine/System PATH** 条目，而不仅仅是你的 **User PATH**。因此，在 Procmon 上花费时间之前，值得先枚举 **Machine PATH** 条目，并检查哪些条目可写：<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
ACL 文本可能会产生误导，因为组成员身份、拒绝 ACE 和继承的权限都会影响结果。在获得授权的测试中，create/delete probe 会检查**当前 token 的有效访问权限**（该操作具有侵入性，可能触发告警）：<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### 确认目标的有效 `PATH`

从注册表读取的 Machine `PATH` 是配置数据；loader 使用的是**目标进程**的 environment block。每个进程都拥有一个 environment block，子进程通常会继承其父进程环境的副本。因此，长时间运行的 service 可能保留较旧的值，而使用自定义 environment 启动的 service 也可能与 shell 中看到的值不同。将目标 PID 对该确切目录执行的 Procmon probe 视为事实依据；在 lab 中修改 `PATH` 后，重启相关 process tree 或 reboot，然后再判断是否未发生 lookup。<sup>[[5]](#references)</sup>

这类情况的问题在于，这些进程可能已经在运行。要识别 services 尝试加载但失败的 DLLs，请尽早启动 Procmon（在进程启动之前），然后：

> [!WARNING]
> 将 user-writable directory 添加到 Machine `PATH` **会创建易受攻击的条件**。只能在隔离的 research VM 中执行此操作，以确认哪些 privileged processes 会访问 `PATH`；在 assessed host 上，应在不更改系统配置的情况下监控现有的 writable entry。<sup>[[1]](#references)</sup>

- **Create** 文件夹 `C:\privesc_hijacking`，并将路径 `C:\privesc_hijacking` 添加到 **System Path env variable**。你可以**手动**完成，也可以使用 **PS**：
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- 启动 **`procmon`**，进入 **`Options`** --> **`Enable boot logging`**，并在提示框中按 **`OK`**。
- 然后**重启**。计算机重新启动后，**`procmon`** 将尽快开始**记录**事件。
- **Windows** **启动后，再次执行 `procmon`**，它会告诉你它一直在运行，并**询问是否要将**事件**存储**到文件中。选择**是**，并**将事件存储到文件中**。
- **文件****生成后，关闭已打开的 **`procmon`** 窗口，然后**打开事件文件**。
- 添加以下**过滤器**，查找所有**进程尝试从可写 System Path 文件夹加载的** DLL：

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging 仅适用于启动过早、无法通过其他方式观察的服务。** 如果你可以**按需触发目标服务/程序**（例如与其 COM 接口交互、重启服务或重新启动 scheduled task），通常更快的做法是使用过滤器（例如 **`Path contains .dll`**、**`Result is NAME NOT FOUND`** 和 **`Path begins with <writable_machine_path>`**）进行普通 Procmon 捕获。

### Missed DLLs

在一台免费的**虚拟（vmware）Windows 11 计算机**中运行此操作后，我得到了以下结果：

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

在此情况下，忽略 `.exe` 结果。缺失 DLL 的探测来自：

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

以下示例使用了本文中介绍的、[**滥用 `WptsExtensions.dll` 进行权限提升**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)的技术。<sup>[[3]](#references)</sup>

### Other candidates worth triaging

`WptsExtensions.dll` 是一个很好的示例，但它并不是特权服务中反复出现的唯一 **phantom DLL**。现代 hunting 规则和公开的 hijack catalog 仍会跟踪以下名称：<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | 客户端系统上的经典 **SYSTEM** 候选项。当可写目录位于 **Machine PATH** 中，且服务在启动期间探测该 DLL 时很有用。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | 在**服务器版本**上很有意思，因为该服务以 **SYSTEM** 身份运行，并且在某些 build 中可由**普通用户按需触发**，因此比只能通过重启触发的情况更好。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常首先获得 **`NT AUTHORITY\LOCAL SERVICE`**。这通常仍然足够，因为该 token 具有 **`SeImpersonatePrivilege`**，所以你可以将其与 [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) 链接使用。 |

将这些名称视为**筛选提示**，而不是保证成功的目标：它们取决于 **SKU/build**，并且 Microsoft 可能会在不同版本之间更改相关行为。关键在于寻找**会遍历 Machine PATH 的特权服务中的缺失 DLL**，尤其是当服务可以**无需重启即可再次触发**时。

### Validate a candidate before weaponizing it

单独一个 `NAME NOT FOUND` 事件并不足够。在放置 payload 之前，验证完整的链条：<sup>[[1]](#references)[[4]](#references)</sup>

1. 该事件属于预期的 **PID、command line、service account 和 integrity level**，并且缺失路径正是可写的 Machine `PATH` 目录。
2. 对于相同的 DLL basename，没有更早的目录返回 `SUCCESS`，并且该 module 未通过 loaded-module list、KnownDLLs、redirection 或 SxS manifest 得到满足。
3. 当低权限用户调用预期 trigger 时，该探测会重复出现。仅在启动时进行的查找可以使用，但在实际操作上远不如按需触发的查找。
4. payload 的 architecture 与进程匹配。如果应用程序之后会解析 exports，则 proxy 合法 DLL 或导出预期的 symbols；参见 [Creating and compiling DLLs](README.md#creating-and-compiling-dlls)。
5. 首先使用无害的 canary DLL，记录 PID、身份和 timestamp。在 Procmon 中，要求从植入路径成功执行 **`Load Image`**，而不是假设之前的文件探测会导致执行。

### Exploitation

要**提升权限**，劫持 **`WptsExtensions.dll`**。在知道**路径**和**名称**后，生成恶意 DLL。

你可以[**尝试使用以下任一示例**](README.md#creating-and-compiling-dlls)。你可以运行诸如以下 payload：获取 rev shell、添加用户、执行 beacon……

> [!WARNING]
> 注意，**并非所有服务都以** **`NT AUTHORITY\SYSTEM`** 身份运行。有些服务以 **`NT AUTHORITY\LOCAL SERVICE`** 身份运行，其**权限更少**，因此滥用此类服务可能无法让你创建新用户。\
> 不过，该账户具有 **`SeImpersonatePrivilege`** 用户权限，因此你可以使用 [**Potato suite 提升权限**](../roguepotato-and-printspoofer.md)。在这种情况下，reverse shell 比尝试创建用户更合适。

**Task Scheduler** 服务通常以 **`NT AUTHORITY\SYSTEM`** 身份运行，但请验证实际部署情况，不要仅根据服务名称推断执行身份：<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
在**生成恶意 DLL**后（_在我的案例中，我使用了 x64 rev shell 并成功获得 shell，但由于它来自 msfvenom，Defender 将其终止了_），将其以 **WptsExtensions.dll** 的名称保存到可写的 System Path 中，然后**重启**计算机（或重启服务，或采取其他必要措施以重新运行受影响的服务/程序）。

服务重新启动后，**DLL 应会被加载并执行**（你可以**再次使用** **Procmon** 技巧，检查**库是否按预期加载**）。

> [!NOTE]
> 在触发之前规划清理步骤。服务可能会持续映射 DLL 并锁定文件，直到服务停止；对于 `WptsExtensions.dll`，停止 Task Scheduler 需要提升权限。在获得预期上下文后，安全地停止目标、删除 payload，并还原任何仅用于 lab 的 `PATH` 修改。<sup>[[1]](#references)</sup>

### Remediation / detection

从每个 Machine `PATH` 目录中移除权限过宽的写入授权，并删除过时的条目。开发人员应通过完整路径加载受信任的库，或使用 `SetDefaultDllDirectories` / `LoadLibraryEx` 搜索标志限制解析范围。Defender 可以将 Machine `PATH` 的变更与特权进程从非系统、用户可写目录加载 DLL 的行为进行关联。<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking（解释版）](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [为持久化或权限提升而加载的可疑 DLL](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows 权限提升](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Dynamic-link library 搜索顺序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
