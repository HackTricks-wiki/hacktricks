# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

如果你可以**写入系统范围 `PATH` 中的某个目录**（而不仅仅是你的用户 `PATH`），就有可能在系统上**提升权限**。

当权限更高的服务或进程尝试加载一个在更早搜索位置中不存在的 DLL，最终搜索到可写的系统 `PATH` 目录时，就可以通过 **DLL hijacking** 进行滥用。

有关 **DLL hijacking** 的更多信息，请参阅：


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a Missing DLL

首先，**识别一个进程**：该进程以**更高权限**运行，并且尝试从可写的系统 `PATH` 目录中**加载 DLL**。

请记住，此技术依赖于 **Machine/System PATH** 条目，而不仅仅是你的 **User PATH**。因此，在 Procmon 上花费时间之前，值得先枚举 **Machine PATH** 条目，并检查其中哪些目录可写：<sup>[[1]](#references)</sup>
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
这些情况下的问题是，这些进程可能已经在运行。要识别服务尝试加载但失败的 DLL，请尽早启动 Procmon（在进程启动之前），然后：

- **创建**文件夹 `C:\privesc_hijacking`，并将路径 `C:\privesc_hijacking` 添加到**系统 Path 环境变量**中。你可以**手动**完成，也可以使用 **PS**：
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
- 然后**重启**。计算机重启后，**`procmon`** 将尽快开始**记录**事件。
- **Windows** **启动后，再次执行 `procmon`**，它会告诉你此前一直在运行，并**询问是否要将**事件**保存**到文件中。选择**是**，并**将事件保存到文件**。
- **文件**生成后，关闭打开的 **`procmon`** 窗口，然后**打开事件文件**。
- 添加以下**筛选器**，查找所有**进程尝试从可写 System Path 文件夹加载的** DLL：

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging 仅适用于启动过早、否则无法观察的服务**。如果你可以**按需触发目标服务/程序**（例如与其 COM 接口交互、重启服务或重新启动计划任务），通常更快的方法是使用包含 **`Path contains .dll`**、**`Result is NAME NOT FOUND`** 和 **`Path begins with <writable_machine_path>`** 等筛选器，进行一次普通的 Procmon 捕获。

### Missed Dlls

在一台免费的**虚拟（vmware）Windows 11 计算机**上运行此操作时，我得到了以下结果：

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

在此情况下，忽略 `.exe` 结果。缺失 DLL 的探测来自：

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

下面的示例使用了本文中介绍的、关于[**滥用 `WptsExtensions.dll` 进行 privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)的技术。<sup>[[3]](#references)</sup>

### Other candidates worth triaging

`WptsExtensions.dll` 是一个很好的示例，但它并不是特权服务中反复出现的唯一 **phantom DLL**。现代 hunting 规则和公开的 hijack catalog 仍在追踪以下名称：<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | 客户端系统中的经典 **SYSTEM** 候选项。当可写目录位于 **Machine PATH** 中，并且服务在启动期间探测该 DLL 时，这个候选项很有价值。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | 在**服务器版本**中值得关注，因为该服务以 **SYSTEM** 身份运行，并且在某些 build 中，**普通用户可以按需触发**它，因此比只能通过重启触发的情况更好。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常首先获得 **`NT AUTHORITY\LOCAL SERVICE`**。这通常仍然足够，因为该 token 具有 **`SeImpersonatePrivilege`**，因此你可以将其与 [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) 链接使用。 |

请将这些名称视为**筛选提示**，而不是保证成功的目标：它们取决于 **SKU/build**，Microsoft 也可能在不同版本之间更改相关行为。重要结论是：寻找**会遍历 Machine PATH 的特权服务中缺失的 DLL**，尤其要关注那些可以**无需重启即可再次触发**的服务。

### Exploitation

要**提升权限**，请劫持 **`WptsExtensions.dll`**。确定**路径**和**名称**后，生成恶意 DLL。

你可以[**尝试使用这些示例中的任意一个**](#creating-and-compiling-dlls)。你可以运行诸如以下的 payload：获取 rev shell、添加用户、执行 beacon……

> [!WARNING]
> 请注意，**并非所有服务都以** **`NT AUTHORITY\SYSTEM`** 身份运行。有些服务以 **`NT AUTHORITY\LOCAL SERVICE`** 身份运行，其**权限更少**，因此滥用其中某些服务可能无法创建新用户。\
> 但是，该账户拥有 **`SeImpersonatePrivilege`** 用户权限，因此你可以使用 [**Potato suite 提升权限**](../roguepotato-and-printspoofer.md)。在这种情况下，与尝试创建用户相比，reverse shell 是更好的选择。

在撰写本文时，**Task Scheduler** 服务以 **Nt AUTHORITY\SYSTEM** 身份运行。

**生成恶意 DLL** 后（_在我的案例中，我使用了 x64 rev shell，并成功获得 shell，但 Defender 将其终止了，因为它来自 msfvenom_），将其以 **WptsExtensions.dll** 为名保存到可写的 System Path 中，然后**重启**计算机（或者重启服务，或采取其他必要措施来重新运行受影响的服务/程序）。

服务重新启动后，应当会**加载并执行 DLL**（你可以**重用** **procmon** 技巧，检查该 **library 是否按预期加载**）。

## References

- [1] [Windows DLL Hijacking（希望）得到澄清](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [为持久化或 privilege escalation 加载的可疑 DLL](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows privilege escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
