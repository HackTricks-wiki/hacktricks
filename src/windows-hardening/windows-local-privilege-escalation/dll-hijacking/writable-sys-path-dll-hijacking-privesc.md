# Writable Sys Path +DLL Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

如果你可以**写入系统范围 `PATH` 中的某个目录**（而不仅仅是你的用户 `PATH`），则可能能够在系统上**提升权限**。

当权限更高的 service 或 process 尝试加载一个在更早搜索位置中不存在的 DLL，并最终搜索可写的系统 `PATH` 目录时，就可以通过 **DLL hijacking** 利用这一点。

有关 **DLL hijacking** 的更多信息，请参阅：


{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

首先，**识别一个以更高权限运行的 process**，该 process 会尝试**从可写的系统 `PATH` 目录加载 DLL**。

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
在这些情况下，问题在于这些进程可能已经在运行。要识别服务尝试加载但失败的 DLL，请尽早启动 Procmon（在进程启动之前），然后：

- **创建**文件夹 `C:\privesc_hijacking`，并将路径 `C:\privesc_hijacking` 添加到 **System Path 环境变量**中。你可以**手动**完成，也可以使用 **PS**：
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
- 启动 **`procmon`**，转到 **`Options`** --> **`Enable boot logging`**，并在提示中按 **`OK`**。
- 然后**重启**。计算机重新启动后，**`procmon`** 会尽快开始**记录**事件。
- **Windows** **启动后，再次执行 `procmon`**，它会提示程序一直在运行，并**询问是否要将**事件**保存**到文件中。选择**是**，并**将事件保存到文件中**。
- **文件**生成**后，关闭打开的 **`procmon`** 窗口，然后**打开事件文件**。
- 添加以下**过滤器**，以查找所有**进程尝试从可写 System Path 文件夹加载的** DLL：

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging 仅适用于启动过早、无法通过其他方式观察的服务**。如果可以**按需触发目标服务/程序**（例如与其 COM interface 交互、重启服务或重新启动 scheduled task），通常更快的做法是保留一次普通的 Procmon 捕获，并使用类似 **`Path contains .dll`**、**`Result is NAME NOT FOUND`** 和 **`Path begins with <writable_machine_path>`** 的过滤器。

### 未发现的 DLL

在一台免费的**虚拟（vmware）Windows 11 计算机**上运行此操作时，我得到了以下结果：

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

在此情况下，忽略 `.exe` 结果。缺失 DLL 的探测来自：

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

以下示例使用了本文介绍的、关于[**滥用 `WptsExtensions.dll` 进行 privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)的技术。<sup>[[3]](#references)</sup>

### 值得进一步筛选的其他候选项

`WptsExtensions.dll` 是一个很好的例子，但它并不是特权服务中反复出现的唯一 **phantom DLL**。现代 hunting 规则和公开的 hijack catalogs 仍在跟踪以下名称：<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | 客户端系统上的经典 **SYSTEM** 候选项。当可写目录位于 **Machine PATH** 中，并且服务在启动期间探测该 DLL 时，效果较好。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | 在 **server editions** 上很有意思，因为该服务以 **SYSTEM** 身份运行，并且在某些 build 中可以由普通用户**按需触发**，因此比只能通过重启触发的情况更好。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常首先获得 **`NT AUTHORITY\LOCAL SERVICE`**。这通常仍然足够，因为该 token 具有 **`SeImpersonatePrivilege`**，所以可以将其与 [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) 链接使用。 |

应将这些名称视为**筛选提示**，而不是必然成功的目标：它们取决于 **SKU/build**，并且 Microsoft 可能会在不同 release 之间改变行为。重要的是寻找**会遍历 Machine PATH 的特权服务中的缺失 DLL**，尤其是当服务可以**在不重启的情况下再次触发**时。

### 利用

要**提升权限**，劫持 **`WptsExtensions.dll`**。知道**路径**和**名称**后，生成恶意 DLL。

你可以[**尝试使用这些示例中的任意一个**](#creating-and-compiling-dlls)。你可以运行以下 payload：获取 rev shell、添加用户、执行 beacon……

> [!WARNING]
> 请注意，**并非所有服务都以** **`NT AUTHORITY\SYSTEM`** **身份运行**。有些服务以 **`NT AUTHORITY\LOCAL SERVICE`** 身份运行，它的**权限更少**，因此滥用这些服务之一可能无法创建新用户。\
> 不过，该账户具有 **`SeImpersonatePrivilege`** 用户权限，因此可以使用 [**Potato suite 提升权限**](../roguepotato-and-printspoofer.md)。在这种情况下，reverse shell 比尝试创建用户更合适。

撰写本文时，**Task Scheduler** 服务以 **Nt AUTHORITY\SYSTEM** 身份运行。

**生成恶意 Dll** 后（_我使用的是 x64 rev shell，成功获得了 shell，但 Defender 终止了它，因为它来自 msfvenom_），将其以 **WptsExtensions.dll** 为名保存到可写的 System Path 中，然后**重启**计算机（或者重启服务，或采取其他必要操作以重新运行受影响的服务/程序）。

服务重新启动后，**dll 应会被加载并执行**（可以**重新使用** **procmon** 技巧，检查该 **library 是否按预期加载**）。

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
