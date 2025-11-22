# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

如果你发现你可以在一个 System Path 文件夹中写入（注意：如果你只能写入 User Path 文件夹则此方法不起作用），那么你可能能够 **escalate privileges** 到系统中。

为此你可以滥用 **Dll Hijacking**，即通过在具有比你更高权限的服务或进程加载的库中进行劫持。因为该服务正在加载的 Dll 很可能在整个系统中都不存在，服务会尝试从你可写的 System Path 加载它，从而被你劫持。

关于 **what is Dll Hijackig** 的更多信息请查看：


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### 寻找缺失的 Dll

首先你需要识别一个以比你更高权限运行并尝试从你可写的 System Path **load a Dll** 的进程。

问题是这些进程很可能已经在运行。要找出哪些服务缺失 Dll，你需要尽早启动 procmon（在进程被加载之前）。因此，要查找缺失的 .dll，请执行：

- **Create** 文件夹 `C:\privesc_hijacking`，并将路径 `C:\privesc_hijacking` 添加到 **System Path env variable**。你可以手动完成，或者使用 **PS**：
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
- 启动 **`procmon`**，进入 **`Options`** --> **`Enable boot logging`**，在提示中按 **`OK`**。
- 然后，**重启**。计算机重启后 **`procmon`** 会尽快开始**记录**事件。
- 一旦 **Windows** 启动后再次**运行 `procmon`**，它会提示它已在运行并会**询问是否将事件保存到文件**。选择 **yes** 并**将事件保存到文件**。
- **文件生成后**，关闭打开的 **`procmon`** 窗口并**打开事件文件**。
- 添加以下**过滤器**，你就会找到所有某些**进程尝试从可写的 System Path 文件夹加载的 Dll**：

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Missed Dlls

在一台免费的虚拟机（vmware）Windows 11 上运行时我得到以下结果：

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

在这种情况下 .exe 文件无用，请忽略它们，未加载的 DLL 来自：

| 服务                            | Dll                | 命令行                                                               |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

找到这些之后，我发现了一篇有趣的博客文章，也解释了如何 [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)。这正是我们接下来要做的。

### Exploitation

因此，为了**提升权限**我们将劫持库 **WptsExtensions.dll**。得到其**路径**和**名称**后，我们只需**生成恶意 dll**。

你可以[**尝试使用这些示例中的任意一个**](#creating-and-compiling-dlls)。可以运行的 payload 示例：获取 rev shell、添加用户、执行 beacon 等等...

> [!WARNING]
> 注意并非所有服务都以 **`NT AUTHORITY\SYSTEM`** 运行，有些也以 **`NT AUTHORITY\LOCAL SERVICE`** 运行，这种运行权限**更低**，你**无法滥用其权限创建新用户**。\
> 但是，该用户具有 **`seImpersonate`** 权限，因此你可以使用[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md)。因此，在这种情况下，获取 rev shell 往往比尝试创建用户更合适。

在撰写本文时 **Task Scheduler** 服务以 **Nt AUTHORITY\SYSTEM** 运行。

生成恶意 Dll 后（我在自己的测试中使用了 x64 rev shell 并得到了一个 shell，但 defender 因为它来自 msfvenom 而将其阻止），将其以名称 **WptsExtensions.dll** 保存到可写的 System Path 中，然后**重启**计算机（或重启服务，或采取其它措施以重新运行受影响的服务/程序）。

当服务重新启动时，该 **dll 应该会被加载并执行**（你可以重用 **procmon** 技巧来检查库是否按预期加载）。

{{#include ../../../banners/hacktricks-training.md}}
