# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

如果你发现你可以在 **System Path** 文件夹中**写入**（注意：如果你只能在 **User Path** 文件夹中写入，这个方法不会起作用），那么你可能可以在系统中**提升权限**。

为此，你可以利用 **Dll Hijacking**，通过它你将**劫持一个被加载的 library**，该 library 是由一个比你拥有**更高权限**的 service 或 process 加载的；而且因为这个 service 正在加载一个可能在整个系统中都不存在的 Dll，它会尝试从你可以写入的 **System Path** 中加载它。

更多关于 **what is Dll Hijackig** 的信息请查看：


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

你首先需要做的是，**识别一个以比你更高权限运行的 process**，并且它正试图从你可以写入的 **System Path** 中**加载一个 Dll**。

请记住，这种技术依赖于 **Machine/System PATH** 条目，而不仅仅是你的 **User PATH**。因此，在 Procmon 上花时间之前，最好先枚举 **Machine PATH** 条目，并检查哪些是可写的：
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
在这种情况下，问题是这些进程很可能已经在运行。要找出缺少哪些 Dll，你需要尽快启动 procmon（在进程加载之前）。因此，要查找缺少的 .dll，请执行：

- **创建** 文件夹 `C:\privesc_hijacking`，并将路径 `C:\privesc_hijacking` 添加到 **System Path env variable**。你可以**手动**完成，或者使用 **PS**：
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
- 启动 **`procmon`**，然后进入 **`Options`** --> **`Enable boot logging`**，并在提示中按 **`OK`**。
- 接着，**重启**。当计算机重启后，**`procmon`** 会尽快开始**记录**事件。
- 一旦 **Windows** **启动完成，再次执行 `procmon`**，它会告诉你它一直在运行，并会**询问你是否要将**这些事件**保存**到文件中。选择 **yes**，并**将事件保存到文件**。
- **文件**生成后，**关闭**已打开的 **`procmon`** 窗口，并**打开事件文件**。
- 添加这些**过滤器**，你就会找到所有某些**进程尝试从可写的 System Path 文件夹加载的 Dlls**：

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging 只在那些启动得太早、否则无法观察到的 services 上才需要。** 如果你可以**按需触发目标 service/program**（例如，通过与它的 COM interface 交互、重启 service，或重新启动一个 scheduled task），通常更快的做法是保持普通的 Procmon capture，并使用诸如 **`Path contains .dll`**、**`Result is NAME NOT FOUND`** 和 **`Path begins with <writable_machine_path>`** 之类的过滤器。

### Missed Dlls

在一台免费的 **virtual (vmware) Windows 11 machine** 上运行这个，我得到了这些结果：

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

在这种情况下，这些 .exe 没什么用，所以忽略它们，缺失的 DLL 来自：

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

找到这个之后，我发现了这篇有趣的 blog post，它也解释了如何 [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)。这正是我们**现在要做的**。

### Other candidates worth triaging

`WptsExtensions.dll` 是一个很好的例子，但它并不是唯一会出现在提权服务中的反复出现的 **phantom DLL**。现代 hunting 规则和公开的 hijack catalog 仍然会跟踪诸如以下名称：

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | 典型的 **SYSTEM** 候选项，适用于 client systems。适合 writable directory 位于 **Machine PATH**，且 service 在启动时会探测该 DLL 的情况。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | 在 **server editions** 上很有意思，因为该 service 以 **SYSTEM** 运行，并且在某些 builds 中可由普通用户**按需触发**，这比只能靠重启的情况更好。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常先拿到 **`NT AUTHORITY\LOCAL SERVICE`**。这通常已经足够，因为该 token 拥有 **`SeImpersonatePrivilege`**，所以你可以把它和 [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) 串联起来。 |

把这些名字当作**排查线索**，而不是保证成功的结果：它们**取决于 SKU/build**，而且 Microsoft 可能会在不同版本之间改变行为。关键结论是：去寻找**会遍历 Machine PATH 的高权限 services 中缺失的 DLL**，尤其是那些可以**无需重启即可重新触发**的 service。

### Exploitation

所以，要**提升权限**，我们将劫持 library **WptsExtensions.dll**。有了**path**和**name**之后，我们只需要**生成恶意 dll**。

你可以[**尝试使用这些示例中的任意一个**](#creating-and-compiling-dlls)。你可以运行这样的 payload：拿一个 rev shell，添加用户，执行 beacon...

> [!WARNING]
> 注意，并不是**所有的 service 都以** **`NT AUTHORITY\SYSTEM`** 运行，有些也以 **`NT AUTHORITY\LOCAL SERVICE`** 运行，这样的权限**更少**，你**无法**通过滥用其权限来创建新用户。\
> 不过，该用户拥有 **`seImpersonate`** privilege，所以你可以使用[ **potato suite 来提升权限**](../roguepotato-and-printspoofer.md)。因此，在这种情况下，rev shell 比尝试创建用户更合适。

在撰写本文时，**Task Scheduler** service 以 **Nt AUTHORITY\SYSTEM** 运行。

在**生成恶意 Dll**之后（_在我的例子中，我使用了 x64 rev shell 并拿到了 shell，但 defender 把它杀掉了，因为它来自 msfvenom_），把它以 **WptsExtensions.dll** 的名字保存到可写的 System Path 中，然后**重启**电脑（或者重启 service，或者做任何能重新运行受影响的 service/program 的事情）。

当 service 重新启动时，**dll 应该会被加载并执行**（你可以**重复使用** **procmon** 技巧来检查该 **library 是否按预期被加载**）。

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
