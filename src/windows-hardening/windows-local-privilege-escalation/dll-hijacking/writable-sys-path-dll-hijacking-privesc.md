# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

如果你发现自己可以**写入 System Path 文件夹**（注意，如果你可以写入 User Path 文件夹，这种方法将无法奏效），那么你可能可以在系统中**提升权限**。

为此，你可以滥用 **Dll Hijacking**：劫持一个由权限**高于你的**服务或进程加载的 library。由于该服务加载的 Dll 可能根本不存在于整个系统中，因此它会尝试从你可以写入的 System Path 中加载该 Dll。

有关 **什么是 Dll Hijackig** 的更多信息，请查看：


{{#ref}}
./
{{#endref}}

## 使用 Dll Hijacking 进行 Privesc

### 查找缺失的 Dll

首先，你需要**识别一个进程**：该进程以**高于你的权限**运行，并且尝试从你可以写入的 System Path 中**加载 Dll**。

请记住，此技术依赖于 **Machine/System PATH** 条目，而不仅仅是你的 **User PATH**。因此，在 Procmon 上花费时间之前，值得先枚举 **Machine PATH** 条目，并检查其中哪些条目可写：<sup>[[1]](#references)</sup>
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
在这些情况下，问题可能是这些进程已经在运行。要查找服务缺少哪些 Dlls，你需要尽快启动 procmon（在进程加载之前）。因此，要查找缺少的 `.dll`，请执行以下操作：

- **创建**文件夹 `C:\privesc_hijacking`，并将路径 `C:\privesc_hijacking` 添加到 **System Path env variable** 中。你可以**手动**完成，也可以使用 **PS**：
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
- 启动 **`procmon`**，然后前往 **`Options`** --> **`Enable boot logging`**，并在提示框中按 **`OK`**。
- 然后**重启**。计算机重启后，**`procmon`** 会尽快开始**记录**事件。
- **Windows** **启动后，再次执行 `procmon`**，它会提示自己一直在运行，并**询问你是否要将事件保存**到文件中。选择 **yes**，并**将事件保存到文件中**。
- **文件**生成后，关闭已打开的 **`procmon`** 窗口，然后**打开事件文件**。
- 添加以下**过滤器**，即可找到所有某些**进程尝试从可写 System Path 文件夹加载的 Dll**：

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging 仅适用于启动过早、无法通过其他方式观察的服务**。如果你可以**按需触发目标服务/程序**（例如与其 COM 接口交互、重启服务或重新启动 scheduled task），通常更快的方法是使用过滤器进行普通的 Procmon 捕获，例如 **`Path contains .dll`**、**`Result is NAME NOT FOUND`** 和 **`Path begins with <writable_machine_path>`**。

### 未捕获的 Dll

在一台免费的**虚拟（vmware）Windows 11 机器**上运行此操作时，我得到了以下结果：

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

在这种情况下，.exe 没有用处，因此忽略它们；未捕获的 DLL 来自：

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

找到这些之后，我发现了一篇有趣的博客文章，它还解释了如何[**滥用 WptsExtensions.dll 进行 privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)。这正是我们**现在要做的事情**。<sup>[[3]](#references)</sup>

### 其他值得进行 triage 的候选项

`WptsExtensions.dll` 是一个很好的例子，但它并不是出现在特权服务中的唯一重复出现的**phantom DLL**。现代 hunting 规则和公开的 hijack catalog 仍会跟踪以下名称：<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | 客户端系统上经典的 **SYSTEM** 候选项。当可写目录位于 **Machine PATH** 中，并且服务在启动期间探测该 DLL 时，效果很好。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | 在**服务器版本**上很有意思，因为该服务以 **SYSTEM** 身份运行，并且在某些 build 中可以由普通用户**按需触发**，因此优于只能通过重启触发的情况。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常首先获得 **`NT AUTHORITY\LOCAL SERVICE`**。这通常仍然足够，因为该 token 具有 **`SeImpersonatePrivilege`**，因此你可以将其与 [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) 链接使用。 |

请将这些名称视为**triage 提示**，而不是保证成功的目标：它们取决于 **SKU/build**，Microsoft 也可能在不同版本之间更改其行为。重要的是，要寻找会遍历 Machine PATH 的特权服务中的**缺失 DLL**，尤其是当该服务可以在**无需重启的情况下重新触发**时。

### 利用

因此，为了**提升权限**，我们将劫持库 **WptsExtensions.dll**。有了**路径**和**名称**后，我们只需要**生成恶意 dll**。

你可以[**尝试使用这些示例中的任意一个**](#creating-and-compiling-dlls)。你可以运行诸如以下 payload：获取 rev shell、添加用户、执行 beacon……

> [!WARNING]
> 注意，**并非所有服务都以** **`NT AUTHORITY\SYSTEM`** **身份运行**，有些服务还会以 **`NT AUTHORITY\LOCAL SERVICE`** 身份运行；后者的**权限更少**，你将**无法通过滥用其权限创建新用户**。\
> 不过，该用户拥有 **`seImpersonate`** privilege，因此你可以使用[ **potato suite 提升权限**](../roguepotato-and-printspoofer.md)。所以在这种情况下，rev shell 比尝试创建用户更好。

在撰写本文时，**Task Scheduler** 服务以 **Nt AUTHORITY\SYSTEM** 身份运行。

**生成恶意 Dll** 后（_我使用的是 x64 rev shell，并成功获得了 shell，但由于它来自 msfvenom，Defender 将其终止_），将其以 **WptsExtensions.dll** 为名保存到可写的 System Path 中，然后**重启**计算机（或者重启服务，或采取其他措施重新运行受影响的服务/程序）。

服务重新启动后，**dll 应该会被加载并执行**（你可以**重复使用** **procmon** 技巧来检查该**库是否按预期加载**）。

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
