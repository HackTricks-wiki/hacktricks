# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory**는 **네트워크 관리자**가 **도메인**, **사용자**, 및 **객체**를 효율적으로 생성하고 관리할 수 있도록 하는 기본 기술로 작동합니다. 이는 확장 가능하도록 설계되어, 많은 수의 사용자를 관리 가능한 **그룹** 및 **하위 그룹**으로 조직하고, 다양한 수준에서 **접근 권한**을 제어할 수 있게 합니다.

**Active Directory**의 구조는 세 가지 주요 계층으로 구성됩니다: **도메인**, **트리**, 및 **포리스트**. **도메인**은 공통 데이터베이스를 공유하는 **사용자** 또는 **장치**와 같은 객체의 모음을 포함합니다. **트리**는 공유 구조로 연결된 이러한 도메인 그룹이며, **포리스트**는 여러 트리의 모음을 나타내며, **신뢰 관계**를 통해 상호 연결되어 조직 구조의 최상위 계층을 형성합니다. 각 수준에서 특정 **접근** 및 **통신 권한**을 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다:

1. **디렉토리** – Active Directory 객체와 관련된 모든 정보를 저장합니다.
2. **객체** – 디렉토리 내의 엔티티를 나타내며, **사용자**, **그룹**, 또는 **공유 폴더**를 포함합니다.
3. **도메인** – 디렉토리 객체의 컨테이너 역할을 하며, 여러 도메인이 **포리스트** 내에서 공존할 수 있으며, 각 도메인은 자체 객체 모음을 유지합니다.
4. **트리** – 공통 루트 도메인을 공유하는 도메인 그룹입니다.
5. **포리스트** – Active Directory의 조직 구조의 정점으로, 여러 트리로 구성되며 이들 간에 **신뢰 관계**가 있습니다.

**Active Directory Domain Services (AD DS)**는 네트워크 내에서 중앙 집중식 관리 및 통신을 위한 다양한 서비스를 포함합니다. 이러한 서비스는 다음과 같습니다:

1. **도메인 서비스** – 데이터 저장을 중앙 집중화하고 **사용자**와 **도메인** 간의 상호작용을 관리하며, **인증** 및 **검색** 기능을 포함합니다.
2. **인증서 서비스** – 안전한 **디지털 인증서**의 생성, 배포 및 관리를 감독합니다.
3. **경량 디렉토리 서비스** – **LDAP 프로토콜**을 통해 디렉토리 지원 애플리케이션을 지원합니다.
4. **디렉토리 연합 서비스** – 여러 웹 애플리케이션에서 단일 세션으로 사용자를 인증할 수 있는 **싱글 사인온** 기능을 제공합니다.
5. **권한 관리** – 저작권 자료를 보호하기 위해 무단 배포 및 사용을 규제하는 데 도움을 줍니다.
6. **DNS 서비스** – **도메인 이름**의 해석에 필수적입니다.

자세한 설명은 다음을 확인하세요: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD를 **공격하는 방법**을 배우려면 **Kerberos 인증 프로세스**를 잘 **이해**해야 합니다.\
[**작동 방식을 아직 모른다면 이 페이지를 읽어보세요.**](kerberos-authentication.md)

## Cheat Sheet

AD를 열거/악용하기 위해 실행할 수 있는 명령어를 빠르게 확인하려면 [https://wadcoms.github.io/](https://wadcoms.github.io)로 가세요.

> [!WARNING]
> Kerberos 통신은 작업 수행을 위해 **정확한 도메인 이름(FQDN)**을 요구합니다. IP 주소로 머신에 접근하려고 하면 **NTLM을 사용하고 Kerberos를 사용하지 않습니다**.

## Recon Active Directory (No creds/sessions)

AD 환경에 접근할 수 있지만 자격 증명/세션이 없는 경우 다음을 수행할 수 있습니다:

- **네트워크 펜테스트:**
- 네트워크를 스캔하고 머신과 열린 포트를 찾아 **취약점을 악용**하거나 **자격 증명을 추출**하려고 시도합니다 (예: [프린터는 매우 흥미로운 대상이 될 수 있습니다](ad-information-in-printers.md)).
- DNS를 열거하면 도메인 내의 주요 서버에 대한 정보(웹, 프린터, 공유, VPN, 미디어 등)를 얻을 수 있습니다.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 이를 수행하는 방법에 대한 더 많은 정보는 일반 [**펜테스팅 방법론**](../../generic-methodologies-and-resources/pentesting-methodology.md)을 참조하세요.
- **smb 서비스에서 null 및 Guest 접근 확인** (이것은 최신 Windows 버전에서는 작동하지 않습니다):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB 서버를 열거하는 방법에 대한 더 자세한 가이드는 여기에서 확인할 수 있습니다:

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap 열거**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP을 열거하는 방법에 대한 더 자세한 가이드는 여기에서 확인할 수 있습니다 (특히 **익명 접근**에 주의하세요):

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **네트워크 오염**
- [**Responder로 서비스를 가장하여 자격 증명 수집**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**릴레이 공격을 악용하여 호스트에 접근**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- [**악성 UPnP 서비스 노출로 자격 증명 수집**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 내부 문서, 소셜 미디어, 서비스(주로 웹)에서 사용자 이름/이름을 추출하고 공개적으로 이용 가능한 자료에서도 추출합니다.
- 회사 직원의 전체 이름을 찾으면 다양한 AD **사용자 이름 규칙**을 시도해 볼 수 있습니다 (**[이것을 읽어보세요](https://activedirectorypro.com/active-directory-user-naming-convention/)**). 가장 일반적인 규칙은: _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _무작위 문자와 3 무작위 숫자_ (abc123)입니다.
- 도구:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **익명 SMB/LDAP 열거:** [**펜테스팅 SMB**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**펜테스팅 LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute 열거**: **유효하지 않은 사용자 이름이 요청되면** 서버는 **Kerberos 오류** 코드 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_를 사용하여 응답하며, 이를 통해 사용자 이름이 유효하지 않음을 확인할 수 있습니다. **유효한 사용자 이름**은 **AS-REP** 응답에서 **TGT**를 유도하거나 _KRB5KDC_ERR_PREAUTH_REQUIRED_ 오류를 유도하여 사용자가 사전 인증을 수행해야 함을 나타냅니다.
- **MS-NRPC에 대한 인증 없음**: 도메인 컨트롤러의 MS-NRPC(넷로곤) 인터페이스에 대해 auth-level = 1 (인증 없음)을 사용합니다. 이 방법은 MS-NRPC 인터페이스에 바인딩한 후 `DsrGetDcNameEx2` 함수를 호출하여 자격 증명 없이 사용자 또는 컴퓨터가 존재하는지 확인합니다. [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 도구는 이러한 유형의 열거를 구현합니다. 연구 결과는 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)에서 확인할 수 있습니다.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) 서버**

네트워크에서 이러한 서버 중 하나를 발견하면 **사용자 열거를 수행할 수 있습니다**. 예를 들어, 도구 [**MailSniper**](https://github.com/dafthack/MailSniper)를 사용할 수 있습니다:
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
> 사용자 이름 목록은 [**이 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)와 이곳 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))에서 찾을 수 있습니다.
>
> 그러나, 이 전에 수행했어야 할 정찰 단계에서 **회사의 직원 이름**을 알고 있어야 합니다. 이름과 성이 있으면 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 스크립트를 사용하여 잠재적인 유효 사용자 이름을 생성할 수 있습니다.

### 하나 이상의 사용자 이름 알기

좋습니다, 유효한 사용자 이름이 있지만 비밀번호가 없다면... 다음을 시도해 보세요:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성이 **없다면**, 해당 사용자에 대한 **AS_REP 메시지를 요청**할 수 있으며, 이 메시지는 사용자의 비밀번호 파생으로 암호화된 데이터를 포함합니다.
- [**Password Spraying**](password-spraying.md): 발견된 각 사용자에 대해 가장 **일반적인 비밀번호**를 시도해 보세요. 어떤 사용자가 나쁜 비밀번호를 사용하고 있을 수 있습니다(비밀번호 정책을 염두에 두세요!).
- OWA 서버를 **스프레이**하여 사용자 메일 서버에 접근을 시도할 수도 있습니다.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS 중독

네트워크의 **프로토콜을 중독**하여 **해시**를 **획득**할 수 있습니다:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM 릴레이

액티브 디렉토리를 열거하는 데 성공했다면, **더 많은 이메일과 네트워크에 대한 더 나은 이해**를 갖게 될 것입니다. NTLM [**릴레이 공격**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)을 강제로 수행하여 AD 환경에 접근할 수 있습니다.

### NTLM 자격 증명 훔치기

**null 또는 guest 사용자**로 다른 PC나 공유에 **접근**할 수 있다면, **파일을 배치**할 수 있습니다(예: SCF 파일). 이 파일이 접근되면 **당신에 대한 NTLM 인증을 트리거**하여 **NTLM 챌린지를 훔칠 수 있습니다**:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## 자격 증명/세션으로 액티브 디렉토리 열거하기

이 단계에서는 **유효한 도메인 계정의 자격 증명이나 세션을 손상시켜야 합니다.** 유효한 자격 증명이나 도메인 사용자로서의 쉘이 있다면, **이전에 제시된 옵션들이 여전히 다른 사용자를 손상시키는 옵션임을 기억해야 합니다.**

인증된 열거를 시작하기 전에 **Kerberos 더블 홉 문제**가 무엇인지 알아야 합니다.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 열거

계정을 손상시키는 것은 **전체 도메인을 손상시키기 위한 큰 단계**입니다. 이제 **액티브 디렉토리 열거**를 시작할 수 있습니다:

[**ASREPRoast**](asreproast.md)와 관련하여, 이제 모든 가능한 취약한 사용자를 찾을 수 있으며, [**Password Spraying**](password-spraying.md)와 관련하여 손상된 계정의 비밀번호, 빈 비밀번호 및 새로운 유망한 비밀번호를 시도할 수 있습니다.

- [**CMD를 사용하여 기본 정찰 수행**](../basic-cmd-for-pentesters.md#domain-info)
- [**powershell을 사용하여 정찰**](../basic-powershell-for-pentesters/index.html)할 수도 있으며, 이는 더 은밀합니다.
- [**powerview 사용**](../basic-powershell-for-pentesters/powerview.md)하여 더 자세한 정보를 추출할 수 있습니다.
- 액티브 디렉토리에서 정찰을 위한 또 다른 훌륭한 도구는 [**BloodHound**](bloodhound.md)입니다. 이는 **그리 은밀하지는 않지만**(사용하는 수집 방법에 따라 다름), **그것에 대해 신경 쓰지 않는다면** 꼭 시도해 보세요. 사용자가 RDP할 수 있는 위치, 다른 그룹으로의 경로 등을 찾을 수 있습니다.
- **기타 자동화된 AD 열거 도구는:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD의 DNS 레코드**](ad-dns-records.md)도 흥미로운 정보를 포함할 수 있습니다.
- 디렉토리를 열거하는 데 사용할 수 있는 **GUI 도구**는 **SysInternal** Suite의 **AdExplorer.exe**입니다.
- **ldapsearch**를 사용하여 LDAP 데이터베이스에서 _userPassword_ 및 _unixUserPassword_ 필드에서 자격 증명을 찾거나 _Description_을 검색할 수 있습니다. cf. [PayloadsAllTheThings의 AD 사용자 주석에서 비밀번호](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)에서 다른 방법을 확인하세요.
- **Linux**를 사용하는 경우, [**pywerview**](https://github.com/the-useless-one/pywerview)를 사용하여 도메인을 열거할 수 있습니다.
- 자동화 도구로는:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **모든 도메인 사용자 추출하기**

Windows에서 도메인 사용자 이름을 얻는 것은 매우 쉽습니다(`net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`를 사용할 수 있습니다.

> 이 열거 섹션이 작아 보일 수 있지만, 이는 모든 것 중에서 가장 중요한 부분입니다. 링크를 확인하세요(주로 cmd, powershell, powerview 및 BloodHound 링크), 도메인을 열거하는 방법을 배우고 편안해질 때까지 연습하세요. 평가 중에는 DA로 가는 길을 찾거나 아무것도 할 수 없다고 결정하는 중요한 순간이 될 것입니다.

### Kerberoast

Kerberoasting은 사용자 계정에 연결된 서비스에서 사용되는 **TGS 티켓**을 얻고, 그 암호화를 크랙하는 것을 포함합니다—이는 사용자 비밀번호를 기반으로 하며—**오프라인**에서 이루어집니다.

자세한 내용은:

{{#ref}}
kerberoast.md
{{#endref}}

### 원격 연결 (RDP, SSH, FTP, Win-RM 등)

일단 자격 증명을 얻으면, **어떤 머신**에 접근할 수 있는지 확인할 수 있습니다. 이를 위해 **CrackMapExec**를 사용하여 포트 스캔에 따라 여러 서버에 다양한 프로토콜로 연결을 시도할 수 있습니다.

### 로컬 권한 상승

정상 도메인 사용자로서 자격 증명이나 세션을 손상시키고, 이 사용자로 **도메인 내의 어떤 머신에 접근**할 수 있다면, **로컬에서 권한을 상승시키고 자격 증명을 찾는 방법을 찾아야 합니다.** 이는 로컬 관리자 권한이 있어야만 **다른 사용자의 해시를 메모리(LSASS)와 로컬(SAM)에서 덤프할 수 있기 때문입니다.**

이 책에는 [**Windows에서의 로컬 권한 상승**](../windows-local-privilege-escalation/index.html)에 대한 완전한 페이지와 [**체크리스트**](../checklist-windows-privilege-escalation.md)가 있습니다. 또한, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)를 사용하는 것을 잊지 마세요.

### 현재 세션 티켓

현재 사용자에게 **예상치 못한 리소스에 접근할 수 있는 권한을 주는** **티켓**을 찾는 것은 매우 **가능성이 낮지만**, 확인해 볼 수 있습니다:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

활성 디렉토리를 열거하는 데 성공했다면 **더 많은 이메일과 네트워크에 대한 더 나은 이해**를 갖게 될 것입니다. NTLM [**릴레이 공격**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**을 강제할 수 있을지도 모릅니다.**

### 컴퓨터 공유에서 자격 증명 찾기 | SMB 공유

기본 자격 증명을 얻었으니 **AD 내부에서 공유되고 있는 흥미로운 파일을 찾을 수 있는지 확인해야 합니다**. 수동으로 할 수 있지만 매우 지루하고 반복적인 작업입니다(수백 개의 문서를 확인해야 하는 경우 더더욱).

[**사용할 수 있는 도구에 대해 알아보려면 이 링크를 따르세요.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM 자격 증명 훔치기

다른 PC나 공유에 **접근할 수 있다면**, **파일을 배치**할 수 있습니다(예: SCF 파일). 이 파일이 어떤 방식으로든 접근되면 **당신에 대한 NTLM 인증을 트리거**하여 **NTLM 챌린지를 훔쳐서 크랙할 수 있습니다**:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점은 인증된 사용자가 **도메인 컨트롤러를 손상시킬 수 있게** 했습니다.

{{#ref}}
printnightmare.md
{{#endref}}

## 권한 상승: 특권 자격 증명/세션을 통한 Active Directory

**다음 기술을 수행하려면 일반 도메인 사용자로는 부족하며, 특별한 권한/자격 증명이 필요합니다.**

### 해시 추출

운 좋게도 [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 포함하여 릴레이, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [로컬에서 권한 상승](../windows-local-privilege-escalation/index.html) 등을 통해 **로컬 관리자** 계정을 **손상시킬 수 있었다면**.\
그런 다음, 메모리와 로컬에서 모든 해시를 덤프할 시간입니다.\
[**해시를 얻는 다양한 방법에 대한 이 페이지를 읽어보세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 해시 전달

**사용자의 해시를 얻으면**, 이를 사용하여 **사용자를 가장할 수 있습니다**.\
해시를 사용하여 **NTLM 인증을 수행하는** **도구**를 사용해야 하며, **또는** 새로운 **sessionlogon**을 생성하고 **LSASS** 내부에 그 **해시를 주입**할 수 있습니다. 그러면 **NTLM 인증이 수행될 때** 그 **해시가 사용됩니다**. 마지막 옵션이 mimikatz가 하는 것입니다.\
[**자세한 정보는 이 페이지를 읽어보세요.**](../ntlm/index.html#pass-the-hash)

### 해시 우회/키 전달

이 공격은 **사용자 NTLM 해시를 사용하여 Kerberos 티켓을 요청하는 것**을 목표로 하며, 일반적인 NTLM 프로토콜을 통한 해시 전달의 대안입니다. 따라서, NTLM 프로토콜이 비활성화되고 **Kerberos만 인증 프로토콜로 허용되는 네트워크에서 특히 유용할 수 있습니다**.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### 티켓 전달

**티켓 전달(PTT)** 공격 방법에서 공격자는 **사용자의 인증 티켓을 훔칩니다**. 이 훔친 티켓은 **사용자를 가장하는 데 사용되어**, 네트워크 내의 리소스와 서비스에 대한 무단 접근을 얻습니다.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### 자격 증명 재사용

**로컬 관리자**의 **해시** 또는 **비밀번호**가 있다면, 이를 사용하여 다른 **PC에 로컬로 로그인**해 보아야 합니다.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이 방법은 상당히 **시끄럽고** **LAPS**가 이를 **완화**할 수 있습니다.

### MSSQL 남용 및 신뢰 링크

사용자가 **MSSQL 인스턴스에 접근할 수 있는 권한**이 있다면, MSSQL 호스트에서 **명령을 실행**하거나 (SA로 실행 중인 경우) NetNTLM **해시**를 **탈취**하거나 **릴레이 공격**을 수행할 수 있습니다.\
또한, MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰받는 경우, 사용자가 신뢰받는 데이터베이스에 대한 권한을 가지고 있다면, **신뢰 관계를 사용하여 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 연결될 수 있으며, 사용자가 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수 있는 시점이 있을 수 있습니다.\
**데이터베이스 간의 링크는 포리스트 신뢰를 넘어 작동합니다.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### 제약 없는 위임

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성을 가진 컴퓨터 객체를 발견하고 해당 컴퓨터에서 도메인 권한이 있다면, 해당 컴퓨터에 로그인하는 모든 사용자의 TGT를 메모리에서 덤프할 수 있습니다.\
따라서 **도메인 관리자가 컴퓨터에 로그인하면**, 그의 TGT를 덤프하고 [Pass the Ticket](pass-the-ticket.md)를 사용하여 그를 가장할 수 있습니다.\
제약된 위임 덕분에 **프린트 서버를 자동으로 손상시킬 수 있습니다** (희망적으로 DC일 것입니다).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### 제약된 위임

사용자 또는 컴퓨터가 "제약된 위임"을 허용받으면, **특정 서비스에 접근하기 위해 어떤 사용자를 가장할 수 있습니다**.\
그런 다음, 이 사용자/컴퓨터의 **해시를 손상시키면** **모든 사용자를 가장할 수 있습니다** (도메인 관리자 포함) 특정 서비스에 접근할 수 있습니다.

{{#ref}}
constrained-delegation.md
{{#endref}}

### 리소스 기반 제약 위임

원격 컴퓨터의 Active Directory 객체에 대한 **쓰기** 권한을 가지면 **상승된 권한**으로 코드 실행을 달성할 수 있습니다:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### ACL 남용

손상된 사용자는 **도메인 객체에 대한 흥미로운 권한**을 가질 수 있으며, 이는 사용자가 **측면 이동**/**권한 상승**을 할 수 있게 해줍니다.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### 프린터 스풀러 서비스 남용

도메인 내에서 **스풀 서비스가 수신 대기 중인** 것을 발견하면, 이를 **남용하여 새로운 자격 증명을 획득하고** **권한을 상승**시킬 수 있습니다.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 제3자 세션 남용

**다른 사용자**가 **손상된** 머신에 **접근**하면, 메모리에서 **자격 증명을 수집**하고 심지어 **그들의 프로세스에 비콘을 주입**하여 그들을 가장할 수 있습니다.\
일반적으로 사용자는 RDP를 통해 시스템에 접근하므로, 여기에서 제3자 RDP 세션에 대한 몇 가지 공격을 수행하는 방법을 제공합니다:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인에 가입된 컴퓨터에서 **로컬 관리자 비밀번호**를 관리하는 시스템을 제공하여, 비밀번호가 **무작위화**, 고유하며 자주 **변경**되도록 보장합니다. 이러한 비밀번호는 Active Directory에 저장되며, ACL을 통해 권한이 있는 사용자만 접근할 수 있습니다. 이러한 비밀번호에 접근할 수 있는 충분한 권한이 있다면, 다른 컴퓨터로 피벗하는 것이 가능해집니다.

{{#ref}}
laps.md
{{#endref}}

### 인증서 도난

**손상된 머신에서 인증서를 수집하는 것**은 환경 내에서 권한을 상승시키는 방법이 될 수 있습니다:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 인증서 템플릿 남용

**취약한 템플릿**이 구성되어 있다면, 이를 남용하여 권한을 상승시킬 수 있습니다:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 높은 권한 계정으로의 포스트 익스플로잇

### 도메인 자격 증명 덤프

**도메인 관리자** 또는 더 나아가 **엔터프라이즈 관리자** 권한을 얻으면, **도메인 데이터베이스**를 **덤프**할 수 있습니다: _ntds.dit_.

[**DCSync 공격에 대한 더 많은 정보는 여기에서 찾을 수 있습니다**](dcsync.md).

[**NTDS.dit를 훔치는 방법에 대한 더 많은 정보는 여기에서 찾을 수 있습니다**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 권한 상승을 위한 지속성

앞서 논의된 몇 가지 기술은 지속성에 사용될 수 있습니다.\
예를 들어, 다음과 같이 할 수 있습니다:

- 사용자를 [**Kerberoast**](kerberoast.md)에 취약하게 만들기

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 사용자를 [**ASREPRoast**](asreproast.md)에 취약하게 만들기

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 사용자에게 [**DCSync**](#dcsync) 권한 부여하기

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### 실버 티켓

**실버 티켓 공격**은 특정 서비스에 대한 **정당한 티켓 부여 서비스 (TGS) 티켓**을 **NTLM 해시**를 사용하여 생성합니다 (예: **PC 계정의 해시**). 이 방법은 **서비스 권한에 접근하기 위해** 사용됩니다.

{{#ref}}
silver-ticket.md
{{#endref}}

### 골든 티켓

**골든 티켓 공격**은 공격자가 Active Directory (AD) 환경에서 **krbtgt 계정의 NTLM 해시**에 접근하는 것을 포함합니다. 이 계정은 모든 **티켓 부여 티켓 (TGT)**에 서명하는 데 사용되기 때문에 특별합니다. 이는 AD 네트워크 내에서 인증하는 데 필수적입니다.

공격자가 이 해시를 얻으면, 그들이 선택한 모든 계정에 대한 **TGT**를 생성할 수 있습니다 (실버 티켓 공격).

{{#ref}}
golden-ticket.md
{{#endref}}

### 다이아몬드 티켓

이들은 일반적인 골든 티켓 탐지 메커니즘을 **우회하는 방식으로 위조된 골든 티켓**과 같습니다.

{{#ref}}
diamond-ticket.md
{{#endref}}

### **인증서 계정 지속성**

**계정의 인증서를 보유하거나 요청할 수 있는 것**은 사용자의 계정에 지속할 수 있는 매우 좋은 방법입니다 (비밀번호를 변경하더라도):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **인증서 도메인 지속성**

**인증서를 사용하여 도메인 내에서 높은 권한으로 지속하는 것도 가능합니다:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder 그룹

Active Directory의 **AdminSDHolder** 객체는 **특권 그룹**(예: 도메인 관리자 및 엔터프라이즈 관리자)의 보안을 보장하기 위해 이러한 그룹에 표준 **액세스 제어 목록 (ACL)**을 적용하여 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정하여 일반 사용자에게 전체 액세스를 부여하면, 해당 사용자는 모든 특권 그룹에 대한 광범위한 제어를 얻게 됩니다. 이 보안 조치는 보호를 위한 것이지만, 면밀히 모니터링되지 않으면 불필요한 접근을 허용할 수 있습니다.

[**AdminDSHolder 그룹에 대한 더 많은 정보는 여기에서 찾을 수 있습니다.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM 자격 증명

모든 **도메인 컨트롤러 (DC)** 내에는 **로컬 관리자** 계정이 존재합니다. 이러한 머신에서 관리자 권한을 얻으면, **mimikatz**를 사용하여 로컬 관리자 해시를 추출할 수 있습니다. 이후, 이 비밀번호를 **사용할 수 있도록** 레지스트리 수정을 해야 하며, 이를 통해 로컬 관리자 계정에 원격으로 접근할 수 있습니다.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL 지속성

특정 도메인 객체에 대해 **사용자에게** **특별 권한**을 부여하여 사용자가 **미래에 권한을 상승**시킬 수 있도록 할 수 있습니다.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### 보안 설명자

**보안 설명자**는 **객체**가 **객체**에 대해 가진 **권한**을 **저장**하는 데 사용됩니다. 객체의 **보안 설명자**에 **조금만 변경**을 가하면, 특권 그룹의 구성원이 되지 않고도 해당 객체에 대한 매우 흥미로운 권한을 얻을 수 있습니다.

{{#ref}}
security-descriptors.md
{{#endref}}

### 스켈레톤 키

**LSASS**를 메모리에서 변경하여 모든 도메인 계정에 접근할 수 있는 **유니버설 비밀번호**를 설정합니다.

{{#ref}}
skeleton-key.md
{{#endref}}

### 사용자 정의 SSP

[SSP (Security Support Provider)가 무엇인지 여기에서 알아보세요.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자신의 **SSP**를 생성하여 **명확한 텍스트**로 머신에 접근하는 데 사용되는 **자격 증명**을 **캡처**할 수 있습니다.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD에 **새 도메인 컨트롤러**를 등록하고 이를 사용하여 지정된 객체에 **속성**(SIDHistory, SPNs...)을 **푸시**합니다. 이 과정에서 **수정**에 대한 **로그**를 남기지 않습니다. **DA** 권한이 필요하며 **루트 도메인** 내에 있어야 합니다.\
잘못된 데이터를 사용하면, 매우 불쾌한 로그가 나타날 수 있습니다.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS 지속성

이전에 **LAPS 비밀번호를 읽을 수 있는 충분한 권한**이 있을 경우 권한을 상승시키는 방법에 대해 논의했습니다. 그러나 이러한 비밀번호는 **지속성을 유지하는 데도 사용될 수 있습니다**.\
확인해 보세요:

{{#ref}}
laps.md
{{#endref}}

## 포리스트 권한 상승 - 도메인 신뢰

Microsoft는 **포리스트**를 보안 경계로 간주합니다. 이는 **단일 도메인을 손상시키는 것이 전체 포리스트가 손상될 수 있음을 의미합니다**.

### 기본 정보

[**도메인 신뢰**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 리소스에 접근할 수 있도록 하는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템 간의 연결을 생성하여 인증 검증이 원활하게 흐를 수 있도록 합니다. 도메인이 신뢰를 설정하면, 특정 **키**를 교환하고 유지하여 신뢰의 무결성을 보장합니다.

일반적인 시나리오에서 사용자가 **신뢰된 도메인**의 서비스에 접근하려면, 먼저 자신의 도메인 DC에서 **인터-렐름 TGT**라는 특별한 티켓을 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **키**로 암호화됩니다. 사용자는 이 TGT를 **신뢰된 도메인의 DC**에 제시하여 서비스 티켓(**TGS**)을 받습니다. 신뢰된 도메인의 DC가 인터-렐름 TGT를 성공적으로 검증하면, TGS를 발급하여 사용자가 서비스에 접근할 수 있도록 합니다.

**단계**:

1. **도메인 1**의 **클라이언트 컴퓨터**가 **NTLM 해시**를 사용하여 **도메인 컨트롤러 (DC1)**에서 **티켓 부여 티켓 (TGT)**을 요청하는 것으로 프로세스가 시작됩니다.
2. 클라이언트가 성공적으로 인증되면 DC1이 새로운 TGT를 발급합니다.
3. 클라이언트는 **도메인 2**의 리소스에 접근하기 위해 DC1에서 **인터-렐름 TGT**를 요청합니다.
4. 인터-렐름 TGT는 두 방향 도메인 신뢰의 일환으로 DC1과 DC2 간에 공유된 **신뢰 키**로 암호화됩니다.
5. 클라이언트는 인터-렐름 TGT를 **도메인 2의 도메인 컨트롤러 (DC2)**로 가져갑니다.
6. DC2는 공유된 신뢰 키를 사용하여 인터-렐름 TGT를 검증하고, 유효한 경우 클라이언트가 접근하려는 도메인 2의 서버에 대한 **티켓 부여 서비스 (TGS)**를 발급합니다.
7. 마지막으로 클라이언트는 이 TGS를 서버에 제시하여 도메인 2의 서비스에 접근합니다. 이 TGS는 서버의 계정 해시로 암호화되어 있습니다.

### 다양한 신뢰

**신뢰는 1방향 또는 2방향**일 수 있다는 점에 유의해야 합니다. 2방향 옵션에서는 두 도메인이 서로를 신뢰하지만, **1방향** 신뢰 관계에서는 한 도메인이 **신뢰받는** 도메인이고 다른 도메인이 **신뢰하는** 도메인입니다. 마지막 경우, **신뢰받는 도메인에서 신뢰하는 도메인 내부의 리소스에만 접근할 수 있습니다**.

도메인 A가 도메인 B를 신뢰하면, A는 신뢰하는 도메인이고 B는 신뢰받는 도메인입니다. 또한, **도메인 A**에서는 이것이 **아웃바운드 신뢰**가 되고, **도메인 B**에서는 **인바운드 신뢰**가 됩니다.

**다양한 신뢰 관계**

- **부모-자식 신뢰**: 이는 동일한 포리스트 내에서 일반적인 설정으로, 자식 도메인은 자동으로 부모 도메인과 2방향 전이 신뢰를 가집니다. 본질적으로, 이는 인증 요청이 부모와 자식 간에 원활하게 흐를 수 있음을 의미합니다.
- **크로스 링크 신뢰**: "단축 신뢰"라고도 하며, 자식 도메인 간에 설정되어 참조 프로세스를 가속화합니다. 복잡한 포리스트에서는 인증 참조가 일반적으로 포리스트 루트로 올라갔다가 대상 도메인으로 내려가야 합니다. 크로스 링크를 생성함으로써 여정을 단축할 수 있으며, 이는 지리적으로 분산된 환경에서 특히 유용합니다.
- **외부 신뢰**: 이는 서로 다른, 관련 없는 도메인 간에 설정되며 본질적으로 비전이적입니다. [Microsoft의 문서](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에 따르면, 외부 신뢰는 현재 포리스트와 연결되지 않은 도메인에서 리소스에 접근하는 데 유용합니다. 보안은 외부 신뢰와 함께 SID 필터링을 통해 강화됩니다.
- **트리 루트 신뢰**: 이러한 신뢰는 포리스트 루트 도메인과 새로 추가된 트리 루트 간에 자동으로 설정됩니다. 일반적으로 자주 발생하지 않지만, 트리 루트 신뢰는 포리스트에 새로운 도메인 트리를 추가하는 데 중요하며, 이를 통해 고유한 도메인 이름을 유지하고 2방향 전이성을 보장합니다. [Microsoft의 가이드](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에서 더 많은 정보를 찾을 수 있습니다.
- **포리스트 신뢰**: 이 유형의 신뢰는 두 포리스트 루트 도메인 간의 2방향 전이 신뢰로, SID 필터링을 적용하여 보안 조치를 강화합니다.
- **MIT 신뢰**: 이러한 신뢰는 비 Windows, [RFC4120 준수](https://tools.ietf.org/html/rfc4120) Kerberos 도메인과 설정됩니다. MIT 신뢰는 좀 더 전문화되어 있으며, Windows 생태계 외부의 Kerberos 기반 시스템과의 통합이 필요한 환경에 맞춰져 있습니다.

#### **신뢰 관계의 다른 차이점**

- 신뢰 관계는 **전이적**일 수 있습니다 (A가 B를 신뢰하고, B가 C를 신뢰하면, A가 C를 신뢰함) 또는 **비전이적**일 수 있습니다.
- 신뢰 관계는 **양방향 신뢰**(서로를 신뢰함) 또는 **일방향 신뢰**(한 쪽만 다른 쪽을 신뢰함)로 설정될 수 있습니다.

### 공격 경로

1. **신뢰 관계를 열거**합니다.
2. 어떤 **보안 주체**(사용자/그룹/컴퓨터)가 **다른 도메인의 리소스**에 **접근**할 수 있는지 확인합니다. ACE 항목이나 다른 도메인의 그룹에 속해 있을 수 있습니다. **도메인 간의 관계**를 찾아보세요 (신뢰가 이 목적을 위해 생성되었을 가능성이 높습니다).
3. 이 경우 kerberoast가 또 다른 옵션이 될 수 있습니다.
4. **계정을 손상시켜** 도메인 간에 **피벗**할 수 있습니다.

공격자는 다음 세 가지 주요 메커니즘을 통해 다른 도메인의 리소스에 접근할 수 있습니다:

- **로컬 그룹 구성원 자격**: 주체는 서버의 "관리자" 그룹과 같은 머신의 로컬 그룹에 추가될 수 있으며, 이를 통해 해당 머신에 대한 상당한 제어를 부여받습니다.
- **외부 도메인 그룹 구성원 자격**: 주체는 외부 도메인 내의 그룹의 구성원이 될 수도 있습니다. 그러나 이 방법의 효과는 신뢰의 성격과 그룹의 범위에 따라 달라집니다.
- **액세스 제어 목록 (ACL)**: 주체는 **ACL**에 지정될 수 있으며, 특히 **DACL** 내의 **ACE**로서 특정 리소스에 대한 접근을 제공합니다. ACL, DACL 및 ACE의 메커니즘에 대해 더 깊이 파고들고자 하는 분들을 위해, "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)"라는 백서가 귀중한 자료입니다.

### 외부 사용자/그룹 권한 찾기

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**를 확인하여 도메인 내의 외부 보안 주체를 찾을 수 있습니다. 이는 **외부 도메인/포리스트**의 사용자/그룹이 될 것입니다.

이 정보를 **Bloodhound**에서 확인하거나 powerview를 사용하여 확인할 수 있습니다:
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
도메인 신뢰를 열거하는 다른 방법:
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
> **2개의 신뢰할 수 있는 키**가 있습니다. 하나는 _Child --> Parent_를 위한 것이고, 다른 하나는 _Parent_ --> _Child_를 위한 것입니다.\
> 현재 도메인에서 사용된 키를 확인하려면 다음을 사용하세요:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History 주입을 악용하여 자식/부모 도메인에서 엔터프라이즈 관리자 권한을 상승시킵니다:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### 쓰기 가능한 Configuration NC 악용

Configuration Naming Context (NC)를 악용하는 방법을 이해하는 것은 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 구성 데이터의 중앙 저장소 역할을 합니다. 이 데이터는 숲 내 모든 도메인 컨트롤러(DC)에 복제되며, 쓰기 가능한 DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 **DC에서 SYSTEM 권한**이 필요하며, 가능하면 자식 DC에서 수행해야 합니다.

**루트 DC 사이트에 GPO 연결**

Configuration NC의 Sites 컨테이너에는 AD 숲 내 모든 도메인에 가입된 컴퓨터의 사이트에 대한 정보가 포함되어 있습니다. 모든 DC에서 SYSTEM 권한으로 작업함으로써 공격자는 GPO를 루트 DC 사이트에 연결할 수 있습니다. 이 작업은 이러한 사이트에 적용된 정책을 조작하여 루트 도메인을 손상시킬 수 있습니다.

자세한 정보는 [SID 필터 우회](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)에 대한 연구를 탐색할 수 있습니다.

**숲 내 모든 gMSA 손상**

공격 벡터는 도메인 내 특권 gMSA를 대상으로 하는 것입니다. gMSA의 비밀번호를 계산하는 데 필수적인 KDS Root 키는 Configuration NC 내에 저장됩니다. 모든 DC에서 SYSTEM 권한을 사용하면 KDS Root 키에 접근하고 숲 내 모든 gMSA의 비밀번호를 계산할 수 있습니다.

자세한 분석은 [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)에 대한 논의에서 확인할 수 있습니다.

**스키마 변경 공격**

이 방법은 새로운 특권 AD 객체의 생성을 기다리는 인내가 필요합니다. SYSTEM 권한을 가진 공격자는 AD 스키마를 수정하여 모든 클래스에 대해 모든 사용자에게 완전한 제어 권한을 부여할 수 있습니다. 이는 새로 생성된 AD 객체에 대한 무단 접근 및 제어로 이어질 수 있습니다.

추가 읽기는 [스키마 변경 신뢰 공격](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)에서 확인할 수 있습니다.

**ADCS ESC5를 통한 DA에서 EA로**

ADCS ESC5 취약점은 공인 키 인프라(PKI) 객체에 대한 제어를 목표로 하여 숲 내 모든 사용자로 인증할 수 있는 인증서 템플릿을 생성합니다. PKI 객체는 Configuration NC에 위치하므로, 쓰기 가능한 자식 DC를 손상시키면 ESC5 공격을 실행할 수 있습니다.

자세한 내용은 [ESC5를 통한 DA에서 EA로](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)에서 읽을 수 있습니다. ADCS가 없는 시나리오에서는 공격자가 필요한 구성 요소를 설정할 수 있으며, 이는 [자식 도메인 관리자에서 엔터프라이즈 관리자까지 상승](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)에서 논의됩니다.

### 외부 숲 도메인 - 단방향(수신) 또는 양방향
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
이 시나리오에서 **귀하의 도메인은 외부 도메인에 의해 신뢰받고 있습니다**. 이로 인해 **정해지지 않은 권한**을 갖게 됩니다. 귀하는 **귀하의 도메인에서 외부 도메인에 대해 어떤 주체가 어떤 접근 권한을 가지고 있는지** 찾아야 하며, 그 후 이를 악용하려고 시도해야 합니다:

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
이 시나리오에서 **귀하의 도메인**은 **다른 도메인**의 주체에게 **특권**을 **신뢰**하고 있습니다.

그러나 **도메인이 신뢰**될 때, 신뢰하는 도메인은 **예측 가능한 이름**을 가진 **사용자**를 **생성**하고 **신뢰된 비밀번호**를 **비밀번호로 사용**합니다. 이는 **신뢰하는 도메인의 사용자에 접근하여 신뢰된 도메인에 들어가** 이를 열거하고 더 많은 특권을 상승시키려는 것이 가능하다는 것을 의미합니다:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

신뢰된 도메인을 타협하는 또 다른 방법은 도메인 신뢰의 **반대 방향**에 생성된 [**SQL 신뢰 링크**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 그리 흔하지 않습니다).

신뢰된 도메인을 타협하는 또 다른 방법은 **신뢰된 도메인에서 접근할 수 있는** 머신에서 대기하여 **RDP**를 통해 로그인하는 것입니다. 그런 다음 공격자는 RDP 세션 프로세스에 코드를 주입하고 **피해자의 원래 도메인에 접근**할 수 있습니다.\
게다가, 만약 **피해자가 하드 드라이브를 마운트**했다면, 공격자는 **RDP 세션** 프로세스에서 **하드 드라이브의 시작 폴더에 백도어**를 저장할 수 있습니다. 이 기술은 **RDPInception**이라고 불립니다.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 도메인 신뢰 남용 완화

### **SID 필터링:**

- SID 히스토리 속성을 활용한 공격의 위험은 SID 필터링으로 완화되며, 이는 모든 상호 숲 신뢰에서 기본적으로 활성화되어 있습니다. 이는 Microsoft의 입장에 따라 숲을 보안 경계로 간주하고, 숲 내 신뢰가 안전하다는 가정에 기반합니다.
- 그러나 주의할 점이 있습니다: SID 필터링은 애플리케이션과 사용자 접근을 방해할 수 있어 가끔 비활성화될 수 있습니다.

### **선택적 인증:**

- 상호 숲 신뢰의 경우, 선택적 인증을 사용하면 두 숲의 사용자들이 자동으로 인증되지 않도록 보장합니다. 대신, 신뢰하는 도메인이나 숲 내의 도메인 및 서버에 접근하기 위해서는 명시적인 권한이 필요합니다.
- 이러한 조치가 쓰기 가능한 구성 명명 컨텍스트(NC)의 악용이나 신뢰 계정에 대한 공격으로부터 보호하지 않는다는 점에 유의해야 합니다.

[**ired.team에서 도메인 신뢰에 대한 더 많은 정보.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 일반적인 방어

[**자격 증명을 보호하는 방법에 대해 더 알아보세요.**](../stealing-credentials/credentials-protections.md)

### **자격 증명 보호를 위한 방어 조치**

- **도메인 관리자 제한**: 도메인 관리자는 도메인 컨트롤러에만 로그인할 수 있도록 제한하는 것이 좋으며, 다른 호스트에서의 사용은 피해야 합니다.
- **서비스 계정 권한**: 보안을 유지하기 위해 서비스는 도메인 관리자(DA) 권한으로 실행되어서는 안 됩니다.
- **임시 권한 제한**: DA 권한이 필요한 작업의 경우, 그 기간을 제한해야 합니다. 이는 다음과 같이 수행할 수 있습니다: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **기만 기술 구현**

- 기만을 구현하는 것은 비밀번호가 만료되지 않거나 위임을 위해 신뢰된 것으로 표시된 유사 사용자 또는 컴퓨터와 같은 함정을 설정하는 것을 포함합니다. 구체적인 접근 방식은 특정 권한을 가진 사용자를 생성하거나 높은 권한 그룹에 추가하는 것입니다.
- 실용적인 예로는 다음과 같은 도구를 사용하는 것입니다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 기만 기술 배포에 대한 더 많은 정보는 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있습니다.

### **기만 식별**

- **사용자 객체의 경우**: 의심스러운 지표에는 비정상적인 ObjectSID, 드문 로그인, 생성 날짜 및 낮은 잘못된 비밀번호 수가 포함됩니다.
- **일반 지표**: 잠재적인 기만 객체의 속성을 진짜 객체의 속성과 비교하면 불일치가 드러날 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)와 같은 도구는 이러한 기만을 식별하는 데 도움을 줄 수 있습니다.

### **탐지 시스템 우회**

- **Microsoft ATA 탐지 우회**:
- **사용자 열거**: ATA 탐지를 방지하기 위해 도메인 컨트롤러에서 세션 열거를 피합니다.
- **티켓 가장하기**: 티켓 생성을 위해 **aes** 키를 사용하면 NTLM으로 다운그레이드하지 않아 탐지를 피할 수 있습니다.
- **DCSync 공격**: ATA 탐지를 피하기 위해 비도메인 컨트롤러에서 실행하는 것이 좋으며, 도메인 컨트롤러에서 직접 실행하면 경고가 발생합니다.

## 참고 문헌

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
