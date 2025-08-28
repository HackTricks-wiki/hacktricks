# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory**는 네트워크 관리자가 네트워크 내에서 **도메인**, **사용자**, 및 **객체**를 효율적으로 생성하고 관리할 수 있게 해주는 기본 기술입니다. 대규모로 확장되도록 설계되어 많은 수의 사용자를 관리 가능한 **그룹**과 **하위 그룹**으로 조직화하고 다양한 수준에서 **액세스 권한**을 제어할 수 있습니다.

**Active Directory**의 구조는 세 가지 주요 계층으로 구성됩니다: **domains**, **trees**, 그리고 **forests**. **Domain**은 공통 데이터베이스를 공유하는 **users**나 **devices**와 같은 객체들의 모음입니다. **Trees**는 공통 구조로 연결된 이러한 도메인들의 그룹이며, **forest**는 여러 트리들의 모음으로 **trust relationships**을 통해 상호 연결되어 조직 구조의 최상위 계층을 형성합니다. 각 계층에서 특정 **access** 및 **communication rights**를 지정할 수 있습니다.

**Active Directory**의 핵심 개념은 다음과 같습니다:

1. **Directory** – Active Directory 객체에 관한 모든 정보를 보관합니다.
2. **Object** – 디렉터리 내의 엔티티를 나타내며, 여기에는 **users**, **groups**, 또는 **shared folders**가 포함됩니다.
3. **Domain** – 디렉터리 객체의 컨테이너 역할을 하며, 여러 도메인이 하나의 **forest** 내에 공존할 수 있고 각 도메인은 자체 객체 컬렉션을 유지합니다.
4. **Tree** – 공통 루트 도메인을 공유하는 도메인들의 그룹입니다.
5. **Forest** – Active Directory에서 조직 구조의 최정점으로, 여러 트리로 구성되며 그들 사이에 **trust relationships**가 존재합니다.

**Active Directory Domain Services (AD DS)**는 네트워크 내 중앙 집중식 관리 및 통신에 필수적인 다양한 서비스를 포함합니다. 이러한 서비스에는 다음이 포함됩니다:

1. **Domain Services** – 데이터를 중앙에 저장하고 **users**와 **domains** 간의 상호작용을 관리하며 **authentication** 및 **search** 기능을 제공합니다.
2. **Certificate Services** – 보안 **digital certificates**의 생성, 배포 및 관리를 감독합니다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 디렉터리 지원 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 여러 웹 애플리케이션에 대해 **single-sign-on** 기능을 제공하여 한 번의 세션으로 인증을 수행합니다.
5. **Rights Management** – 저작권 자료의 무단 배포 및 사용을 규제하여 보호하는 데 도움을 줍니다.
6. **DNS Service** – **domain names** 해석에 필수적입니다.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not Kerberos**.

## Recon Active Directory (No creds/sessions)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

- **Pentest the network:**
- Scan the network, find machines and open ports and try to **exploit vulnerabilities** or **extract credentials** from them (for example, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerating DNS could give information about key servers in the domain as web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Take a look to the General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) to find more information about how to do this.
- **Check for null and Guest access on smb services** (this won't work on modern Windows versions):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- A more detailed guide on how to enumerate a SMB server can be found here:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- A more detailed guide on how to enumerate LDAP can be found here (pay **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extract usernames/names from internal documents, social media, services (mainly web) inside the domain environments and also from the publicly available.
- If you find the complete names of company workers, you could try different AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). The most common conventions are: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) and [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages.
- **Kerbrute enum**: When an **invalid username is requested** the server will respond using the **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response or the error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicating that the user is required to perform pre-authentication.
- **No Authentication against MS-NRPC**: Using auth-level = 1 (No authentication) against the MS-NRPC (Netlogon) interface on domain controllers. The method calls the `DsrGetDcNameEx2` function after binding MS-NRPC interface to check if the user or computer exists without any credentials. The [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implements this type of enumeration. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버 중 하나를 찾았다면 해당 서버에 대해 **user enumeration against it**을 수행할 수도 있습니다. 예를 들어, [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다:
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

이미 유효한 사용자 이름은 알고 있지만 비밀번호는 모를 때, 다음을 시도해 보세요:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성이 **없다면**, 해당 사용자에 대해 AS_REP 메시지를 요청할 수 있으며, 이 메시지에는 사용자의 비밀번호에서 파생된 키로 암호화된 데이터가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견된 각 사용자에 대해 가장 **일반적인 비밀번호들**을 시도해 보세요. 일부 사용자가 취약한 비밀번호를 사용하고 있을 수 있습니다(비밀번호 정책을 염두에 두세요!).
- OWA 서버를 **spray**하여 사용자의 메일 서버 접근을 시도할 수도 있습니다.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

네트워크의 일부 프로토콜을 poisoning하여 crack할 수 있는 challenge hashes를 얻을 수 있을지도 모릅니다:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory를 열거할 수 있게 되면 더 많은 이메일 정보와 네트워크에 대한 이해를 얻을 수 있습니다. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 강제하여 AD 환경에 접근할 수 있을지도 모릅니다.

### Steal NTLM Creds

**null or guest user**로 다른 PC나 공유에 접근할 수 있다면, SCF 파일과 같은 파일을 배치할 수 있습니다. 누군가 이 파일에 접근하면 당신을 대상으로 NTLM 인증이 트리거되어 NTLM challenge를 얻어 이를 크래킹할 수 있습니다:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## 자격증명/세션으로 Active Directory 열거

이 단계에서는 유효한 도메인 계정의 자격증명이나 세션을 **획득(또는 탈취)** 했어야 합니다. 도메인 사용자로서 유효한 자격증명이나 쉘을 가지고 있다면, 앞서 제시된 옵션들 또한 다른 사용자를 타깃으로 삼는 데 여전히 유효하다는 점을 기억하세요.

인증된 열거를 시작하기 전에 **Kerberos double hop problem**이 무엇인지 알고 있어야 합니다.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 열거

계정을 탈취하는 것은 도메인 전체를 공격하기 위한 큰 출발점입니다. 이제 Active Directory 열거를 시작할 수 있습니다:

ASREPRoast의 경우 이제 취약한 모든 사용자를 찾을 수 있고, Password Spraying의 경우 탈취한 계정의 비밀번호, 빈 비밀번호, 또는 새로 유력한 비밀번호들을 모든 사용자에 대해 시도해볼 수 있습니다.

- 기본 recon을 수행하려면 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)를 사용할 수 있습니다.
- 더 은밀하게는 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)을 사용할 수 있습니다.
- 더 상세한 정보를 추출하려면 [**use powerview**](../basic-powershell-for-pentesters/powerview.md)를 사용할 수 있습니다.
- Active Directory recon에 매우 유용한 도구로 [**BloodHound**](bloodhound.md)가 있습니다. 수집 방법에 따라 **매우 은밀하지 않을 수 있으나**, 은밀성을 신경쓰지 않는다면 반드시 사용해 보세요. 사용자들이 RDP 접속 가능한 곳, 그룹 간 경로 등을 찾을 수 있습니다.
- **다른 자동화된 AD 열거 도구:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD의 DNS 레코드**](ad-dns-records.md)는 흥미로운 정보를 포함하고 있을 수 있습니다.
- GUI로 디렉터리를 열거하려면 **SysInternal** Suite의 **AdExplorer.exe**를 사용할 수 있습니다.
- ldapsearch로 LDAP 데이터베이스를 검색해 _userPassword_ & _unixUserPassword_ 필드 또는 _Description_에서 자격증명을 찾아볼 수 있습니다. 다른 방법은 PayloadsAllTheThings의 "Password in AD User comment"를 참조하세요: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment
- **Linux**를 사용하는 경우 [**pywerview**](https://github.com/the-useless-one/pywerview)로 도메인을 열거할 수 있습니다.
- 자동화 도구로는 다음을 시도해 볼 수 있습니다:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)

- **모든 도메인 사용자 추출**

Windows에서 모든 도메인 사용자 이름을 얻는 것은 매우 쉽습니다 (`net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`). Linux에서는 `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>` 등을 사용할 수 있습니다.

> 이 열거 섹션이 짧아 보이더라도 전체에서 가장 중요한 부분입니다. 링크들(특히 cmd, powershell, powerview 및 BloodHound)을 확인하고 도메인 열거 방법을 배우고 충분히 익숙해질 때까지 연습하세요. 평가 중에 이것이 DA로 가는 길을 찾거나 더 이상 할 수 있는 것이 없다고 판단하는 핵심 순간이 됩니다.

### Kerberoast

Kerberoasting은 사용자 계정에 연동된 서비스가 사용하는 **TGS tickets**를 획득하고, 해당 티켓의 암호화(사용자 비밀번호 기반)를 **오프라인**으로 크랙하는 기법입니다.

자세한 내용은 다음을 참조하세요:

{{#ref}}
kerberoast.md
{{#endref}}

### 원격 연결 (RDP, SSH, FTP, Win-RM, 등)

자격증명을 얻었다면 특정 **머신**에 접근 가능한지 확인해 보세요. 포트 스캔 결과에 따라 여러 서버에 서로 다른 프로토콜로 연결을 시도하려면 **CrackMapExec**를 사용할 수 있습니다.

### Local Privilege Escalation

일반 도메인 사용자 자격증명이나 세션을 탈취했고 해당 사용자로 도메인 내 어떤 머신에 접근할 수 있다면, 로컬 권한 상승을 시도하고 자격증명을 찾아 약탈해야 합니다. 로컬 관리자 권한이 있어야만 다른 사용자의 해시를 메모리(LSASS)나 로컬(SAM)에서 덤프할 수 있기 때문입니다.

이 책에는 [**Windows의 local privilege escalation**](../windows-local-privilege-escalation/index.html)에 관한 전체 페이지와 [**체크리스트**](../checklist-windows-privilege-escalation.md)가 있습니다. 또한 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)를 사용하는 것을 잊지 마세요.

### Current Session Tickets

현재 사용자에게 예기치 않은 리소스에 대한 접근 권한을 주는 **tickets**가 있을 가능성은 매우 **낮지만**, 확인해 볼 수 있습니다:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **더 많은 이메일과 네트워크에 대한 더 나은 이해**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Now that you have some basic credentials you should check if you can **찾아보세요** any **AD 내부에서 공유되고 있는 흥미로운 파일들**. 수동으로 할 수도 있지만 매우 지루하고 반복적인 작업입니다(수백 개의 문서를 확인해야 한다면 더더욱 그렇습니다).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **다른 PC나 공유에 접근할 수 있다면** you could **파일을 배치할 수 있습니다** (예: SCF 파일) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **도메인 컨트롤러를 침해**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**다음 기법들은 일반 도메인 사용자만으로는 충분하지 않으며, 이러한 공격을 수행하려면 특정 권한/자격 증명이 필요합니다.**

### Hash extraction

Hopefully you have managed to **로컬 관리자 계정 일부를 탈취** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**사용자의 hash를 확보하면**, 이를 사용해 해당 사용자를 **가장할 수 있습니다.**\
해당 hash를 사용해 NTLM 인증을 수행하는 **도구**를 사용하거나, 새로운 sessionlogon을 생성하고 그 hash를 **LSASS**에 주입하여 이후 발생하는 모든 NTLM 인증에 그 hash가 사용되게 할 수 있습니다. 마지막 옵션이 mimikatz가 하는 방식입니다.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **사용자 NTLM hash를 이용해 Kerberos 티켓을 요청하는 것**으로, 일반적인 NTLM 기반 Pass The Hash의 대안입니다. 따라서 NTLM 프로토콜이 비활성화되어 있고 인증 프로토콜로 Kerberos만 허용되는 네트워크에서 특히 **유용할 수 있습니다.**


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the Pass The Ticket (PTT) attack method, attackers **사용자의 인증 티켓을 훔치며**, 암호나 해시 값을 훔치는 대신 그 티켓을 사용해 사용자를 가장하여 네트워크 내 리소스와 서비스를 무단으로 접근합니다.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **로컬 관리자** you should try to **다른 PC에 로컬로 로그인**해 보세요.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이는 꽤 **noisy**하며 **LAPS**가 이를 **mitigate**할 수 있다는 점을 유의하세요.

### MSSQL Abuse & Trusted Links

사용자가 **access MSSQL instances** 권한을 갖고 있다면, MSSQL 호스트에서 (SA로 실행 중인 경우) **명령을 실행**하거나 NetNTLM **hash**를 **탈취**하거나 심지어 **relay** **attack**을 수행할 수 있습니다.\
또한, MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰(trusted, database link)되고 있는 경우, 사용자가 신뢰된 데이터베이스에 대한 권한을 가지고 있다면 **신뢰 관계를 이용해 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 체인으로 연결될 수 있으며, 결국 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수 있습니다.\
**데이터베이스 간의 링크는 포리스트 트러스트를 넘어 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

서드파티 인벤토리 및 배포 스위트는 종종 자격 증명 및 코드 실행으로 접근할 수 있는 강력한 경로를 노출합니다. 참고:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성을 가진 Computer 객체를 찾았고 해당 컴퓨터에 대한 도메인 권한이 있다면, 그 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 해당 컴퓨터에 로그인하면**, [Pass the Ticket](pass-the-ticket.md)를 사용해 그의 TGT를 덤프하고 그를 가장할 수 있습니다.\
constrained delegation 덕분에 **Print Server를 자동으로 침해**할 수도 있습니다(운이 좋다면 DC일 수도 있습니다).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자나 컴퓨터가 "Constrained Delegation"에 허용되어 있다면, 그 계정은 **특정 컴퓨터의 일부 서비스에 대해 어떤 사용자든지 가장하여 접근할 수 있습니다**.\
따라서 이 사용자/컴퓨터의 **해시를 탈취**하면 (심지어 domain admins일지라도) 일부 서비스에 접근하기 위해 **어떤 사용자로도 가장할 수 있습니다**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대해 **WRITE** 권한을 가지면 **권한 상승된 코드 실행**을 획득할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

침해된 사용자가 일부 도메인 객체에 대해 **흥미로운 권한**을 가지고 있을 수 있으며, 이는 이후에 **횡적 이동**이나 **권한 상승**을 가능하게 할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

도메인 내에서 **Spool 서비스가 리스닝 중인 것을 발견**하면, 이는 **새로운 자격증명을 획득**하고 **권한을 상승**시키는 데 **악용될 수 있습니다**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**다른 사용자들이** **침해된** 기계에 **접근**하는 경우, 메모리에서 자격증명을 **수집**하거나 그들의 프로세스에 **beacon을 주입**하여 그들을 가장할 수 있습니다.\
보통 사용자는 RDP로 시스템에 접근하므로, 타사 RDP 세션에 대해 수행할 수 있는 몇 가지 공격 방법은 다음과 같습니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인에 조인된 컴퓨터의 **로컬 Administrator 비밀번호**를 관리하는 시스템을 제공하여, 비밀번호가 **무작위화되고**, 고유하며 자주 **변경**되도록 보장합니다. 이러한 비밀번호는 Active Directory에 저장되며 접근은 ACL을 통해 허가된 사용자로만 제한됩니다. 이 비밀번호들에 접근할 수 있는 충분한 권한이 있다면 다른 컴퓨터로의 피벗이 가능해집니다.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

침해된 기계에서 **certificate를 수집**하는 것은 환경 내부에서 권한을 상승시키는 방법이 될 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**취약한 템플릿**이 구성되어 있다면 이를 악용해 권한을 상승시킬 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

한 번 **Domain Admin** 또는 더 좋은 **Enterprise Admin** 권한을 얻으면, 도메인 데이터베이스인 _ntds.dit_을 **덤프**할 수 있습니다.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

앞서 논의된 일부 기법은 영속성(persistence)에도 사용될 수 있습니다.\
예를 들어 다음과 같은 작업을 할 수 있습니다:

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

**Silver Ticket attack**은 특정 서비스에 대해 합법적인 Ticket Granting Service (TGS) 티켓을 생성하는데, 예를 들어 **PC 계정의 NTLM hash**를 사용합니다. 이 방법은 **서비스 권한에 접근**하기 위해 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**은 공격자가 Active Directory 환경에서 **krbtgt 계정의 NTLM hash**에 접근하는 것을 포함합니다. 이 계정은 모든 **TGT**를 서명하는 데 사용되므로 AD 네트워크에서 인증에 필수적입니다.

공격자가 이 해시를 획득하면, 어떤 계정에 대해서도 **TGT를 생성**할 수 있습니다 (Silver ticket 공격과 유사하게).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이는 일반적인 golden tickets 탐지 메커니즘을 **우회하도록 위조된 golden ticket과 유사한 티켓들**입니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

계정의 **certificate를 보유하거나 이를 요청할 수 있는 경우**, 사용자가 비밀번호를 변경하더라도 해당 사용자 계정에 **영속적으로 접근**할 수 있는 매우 좋은 방법입니다:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificate를 사용하는 방법으로 도메인 내부에서 높은 권한으로 영속성**을 유지하는 것도 가능합니다:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** 객체는 **Domain Admins** 및 **Enterprise Admins** 같은 **권한 있는 그룹**의 보안을 보장하기 위해 표준 **ACL**을 적용하여 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있습니다; 공격자가 AdminSDHolder의 ACL을 수정하여 일반 사용자에게 전체 접근 권한을 부여하면, 그 사용자는 모든 권한 있는 그룹에 대해 광범위한 제어 권한을 얻게 됩니다. 이 보안 조치는 적절히 모니터링되지 않으면 오히려 권한 남용을 초래할 수 있습니다.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller (DC)** 내부에는 **로컬 관리자** 계정이 존재합니다. 해당 머신에서 관리자 권한을 얻으면, **mimikatz**를 사용해 로컬 Administrator hash를 추출할 수 있습니다. 이후에는 이 비밀번호의 사용을 **활성화**하기 위한 레지스트리 수정을 수행하여 로컬 Administrator 계정에 원격으로 접근할 수 있게 합니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 도메인 객체에 대해 **특수 권한을 사용자에게 부여**하면, 해당 사용자가 **미래에 권한을 상승**할 수 있도록 할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors**는 객체가 다른 객체에 대해 가지는 **권한을 저장**하는 데 사용됩니다. 개체의 security descriptor를 **작게 변경하기만 해도**, 해당 객체에 대해 특이한 권한을 얻을 수 있어, 반드시 권한 있는 그룹의 구성원이 될 필요가 없습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

메모리에서 **LSASS**를 변경하여 **범용 비밀번호(skeleton key)**를 설정하면 모든 도메인 계정에 접근할 수 있게 됩니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자신만의 **SSP**를 만들어 머신에 접근하는 데 사용되는 **credentials를 평문으로 캡처**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

새로운 **Domain Controller**를 AD에 등록하고 이를 사용해 지정된 객체들에 대해 (SIDHistory, SPNs...) **속성을 푸시**합니다. 이 과정은 변경에 관한 **로그를 남기지 않습니다**. DA 권한과 루트 도메인 내부 접근이 필요합니다.\
잘못된 데이터를 사용하면 눈에 띄는 로그가 발생할 수 있다는 점에 유의하세요.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 LAPS 비밀번호를 읽을 수 있는 충분한 권한이 있으면 권한 상승을 할 수 있다고 설명했습니다. 하지만 이 비밀번호들은 **영속성 유지**에도 사용할 수 있습니다.\
참고:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft는 **Forest**를 보안 경계로 봅니다. 이는 **하나의 도메인을 침해하면 전체 Forest가 침해될 가능성이 있다**는 것을 의미합니다.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 자원에 접근할 수 있게 해주는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템 간 연계를 생성하여 인증 검증이 원활하게 흐르도록 합니다. 도메인들이 트러스트를 설정하면, 해당 트러스트의 무결성에 중요한 특정 **keys**를 각자의 **Domain Controllers (DCs)**에 교환 및 유지합니다.

일반적인 시나리오에서 사용자가 **trusted domain**의 서비스에 접근하려면, 먼저 자신의 도메인 DC로부터 **inter-realm TGT**를 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **key**로 암호화됩니다. 사용자는 이 inter-realm TGT를 **trusted domain의 DC**에 제시하여 서비스 티켓(**TGS**)을 얻습니다. trusted domain의 DC가 inter-realm TGT를 검증하면 TGS를 발급하여 사용자가 서비스에 접근할 수 있게 합니다.

**Steps**:

1. **Domain 1**의 **클라이언트 컴퓨터**가 **NTLM hash**를 사용하여 **Domain Controller (DC1)**로부터 **Ticket Granting Ticket (TGT)**를 요청합니다.
2. 클라이언트가 인증되면 DC1은 새로운 TGT를 발급합니다.
3. 클라이언트는 **Domain 2**의 자원에 접근하기 위해 DC1로부터 **inter-realm TGT**를 요청합니다.
4. inter-realm TGT는 두 도메인 간의 양방향 도메인 트러스트의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**에 제시합니다.
6. DC2는 공유된 trust key를 사용해 inter-realm TGT를 검증하고, 유효하면 클라이언트가 접근하려는 Domain 2 내 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로 클라이언트는 이 TGS를 서버에 제시하며, 해당 TGS는 서버 계정 해시로 암호화되어 Domain 2의 서비스에 접근할 수 있게 합니다.

### Different trusts

트러스트는 **일방향(one way)** 또는 **양방향(two ways)**이 될 수 있다는 점을 유의하세요. 양방향 옵션에서는 두 도메인이 서로를 신뢰하지만, **일방향** 트러스트 관계에서는 한 도메인이 **trusted**이고 다른 도메인이 **trusting** 도메인입니다. 후자의 경우 **trusted 도메인에서만 trusting 도메인의 자원에 접근할 수 있습니다**.

만약 Domain A가 Domain B를 신뢰한다면, A는 trusting 도메인이고 B는 trusted 도메인입니다. 또한 **Domain A**에서는 이것이 **Outbound trust**가 되고, **Domain B**에서는 **Inbound trust**가 됩니다.

**Different trusting relationships**

- **Parent-Child Trusts**: 동일 포리스트 내에서 흔한 구성으로, 자식 도메인은 자동으로 부모 도메인과 양방향 전이적(transitive) 트러스트를 가집니다. 이는 부모와 자식 간에 인증 요청이 원활하게 흐를 수 있음을 의미합니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 하며, 자식 도메인 간에 설정되어 레퍼럴 프로세스를 단축합니다. 복잡한 포리스트에서는 인증 레퍼럴이 포리스트 루트까지 올라갔다가 대상 도메인으로 내려가야 하는데, cross-link를 생성하면 이 경로를 단축할 수 있어 지리적으로 분산된 환경에서 유리합니다.
- **External Trusts**: 서로 관련이 없는 다른 도메인 간에 설정되며 비전이적(non-transitive)입니다. Microsoft 문서에 따르면 외부 트러스트는 포리스트 트러스트로 연결되지 않은 외부 도메인의 자원에 접근할 때 유용합니다. 외부 트러스트는 SID 필터링을 통해 보안을 강화합니다.
- **Tree-root Trusts**: 포리스트 루트 도메인과 새로 추가된 tree root 간에 자동으로 설정됩니다. 자주 접하지는 않지만, 새 도메인 트리를 포리스트에 추가할 때 중요하며 두 도메인 간 양방향 전이성을 보장합니다.
- **Forest Trusts**: 두 포리스트 루트 도메인 간의 양방향 전이적 트러스트로, SID 필터링을 적용해 보안을 강화합니다.
- **MIT Trusts**: 비-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos 도메인과 설정되는 트러스트입니다. MIT trusts는 Windows 생태계 밖의 Kerberos 기반 시스템과의 통합이 필요한 환경에 적합합니다.

#### Other differences in **trusting relationships**

- 트러스트 관계는 **전이적(transitive)**일 수도 있고 **비전이적(non-transitive)**일 수도 있습니다 (예: A가 B를 신뢰하고 B가 C를 신뢰하면 A가 C를 신뢰하게 되는 경우).
- 트러스트 관계는 **양방향**(서로 신뢰) 또는 **일방향**(한쪽만 신뢰)으로 설정될 수 있습니다.

### Attack Path

1. **신뢰 관계 열거(enumerate)**
2. 어떤 **security principal**(user/group/computer)이 **다른 도메인의 자원에 접근할 수 있는지** ACE 엔트리나 다른 도메인의 그룹 멤버십을 통해 확인합니다. **도메인 간 관계**를 찾아보세요(트러스트가 이 목적을 위해 생성되었을 가능성이 큽니다).
1. 이 경우 kerberoast도 또 다른 옵션이 될 수 있습니다.
3. 도메인 간으로 **피벗할 수 있는 계정들을 침해(compromise)** 합니다.

다른 도메인의 자원에 접근할 수 있는 공격자는 주로 세 가지 메커니즘을 통해 접근할 수 있습니다:

- **Local Group Membership**: 프린터 서버 같은 서버의 “Administrators” 그룹에 주체가 추가되어 있으면 해당 머신에 대한 강력한 제어권을 가질 수 있습니다.
- **Foreign Domain Group Membership**: 주체가 외부 도메인의 그룹의 멤버일 수도 있습니다. 그러나 이 방법의 효과는 트러스트의 성격 및 그룹의 범위에 따라 다릅니다.
- **Access Control Lists (ACLs)**: 주체가 **ACL**, 특히 **DACL** 내의 **ACE**로 지정되어 특정 자원에 접근할 수 있도록 설정될 수 있습니다. ACL, DACL, ACE의 메커니즘을 더 깊이 파고들고 싶다면, "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" 백서가 유용한 자료입니다.

### Find external users/groups with permissions

외부 보안 주체(foreign security principals)를 찾으려면 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**을 확인하세요. 이 항목들은 **외부 도메인/포리스트**의 사용자/그룹입니다.

이것은 Bloodhound에서 확인하거나 powerview를 사용하여 확인할 수 있습니다:
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
> 신뢰된 키가 **2개** 있습니다. 하나는 _Child --> Parent_ 용이고 다른 하나는 _Parent_ --> _Child_ 용입니다.\
> 다음 명령으로 현재 도메인에서 사용 중인 키를 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection을 악용하여 트러스트를 통해 child/parent 도메인에서 Enterprise admin으로 권한 상승:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)이 어떻게 악용될 수 있는지 이해하는 것은 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 포리스트 전반의 구성 데이터를 저장하는 중앙 저장소 역할을 합니다. 이 데이터는 포리스트 내 모든 Domain Controller (DC)에 복제되며, 쓰기 가능한 DC는 Configuration NC의 쓰기 가능한 복사본을 보유합니다. 이를 악용하려면 **DC에서의 SYSTEM 권한**(가능하면 child DC에서)이 필요합니다.

**Link GPO to root DC site**

Configuration NC의 Sites 컨테이너에는 AD 포리스트 내 도메인에 가입된 모든 컴퓨터의 사이트 정보가 포함되어 있습니다. 어떤 DC에서든 SYSTEM 권한으로 작업하면 공격자는 GPO를 root DC 사이트에 연결할 수 있습니다. 이 작업은 해당 사이트에 적용되는 정책을 조작하여 루트 도메인을 잠재적으로 손상시킬 수 있습니다.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

공격 벡터로 도메인 내 권한 있는 gMSA를 노릴 수 있습니다. gMSA의 비밀번호를 계산하는 데 필요한 KDS Root key는 Configuration NC에 저장되어 있습니다. 어떤 DC에서든 SYSTEM 권한을 얻으면 KDS Root key에 접근하여 포리스트 전반의 어떤 gMSA든 비밀번호를 계산할 수 있습니다.

Detailed analysis and step-by-step guidance can be found in:

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

이 방법은 인내심을 요구하며, 새로운 권한 있는 AD 객체가 생성되기를 기다려야 합니다. SYSTEM 권한을 가진 공격자는 AD Schema를 수정하여 모든 클래스에 대해 임의 사용자에게 전체 제어 권한을 부여할 수 있습니다. 이는 새로 생성되는 AD 객체들에 대한 무단 접근 및 제어로 이어질 수 있습니다.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 취약점은 PKI 객체에 대한 제어를 목표로 하여 포리스트 내의 모든 사용자로 인증할 수 있는 인증서 템플릿을 생성하게 합니다. PKI 객체는 Configuration NC에 위치하므로, 쓰기 가능한 child DC를 침해하면 ESC5 공격을 수행할 수 있습니다.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). ADCS가 없는 환경에서는 공격자가 필요한 구성 요소를 직접 설정할 수 있는 방법에 대해 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)에서 논의하고 있습니다.

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
이 시나리오에서는 **당신의 도메인이 신뢰된 상태입니다** 외부 도메인에 의해 신뢰되어 그 도메인에 대해 **명확히 정의되지 않은 권한**을 부여받습니다. 당신은 **자신의 도메인 내 어떤 프린시펄(Principal)이 외부 도메인에 대해 어떤 접근 권한을 가지는지** 찾아내고, 이를 악용해 보아야 합니다:

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

이 시나리오에서는 **your domain**이(가) **different domains**의 프린시펄에게 일부 **privileges**를 신뢰하고 있습니다.

하지만 신뢰하는 도메인에 의해 **domain is trusted** 상태가 되면, 신뢰된 도메인은 **predictable name**을 가진 **user**를 생성하고 그 **password**로 **trusted password**를 사용합니다. 이는 **trusting domain**의 사용자를 통해 **trusted domain** 내부에 접근해 열거(enumerate)하고 더 높은 권한으로 상승을 시도할 수 있음을 의미합니다:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

trusted domain를 침해하는 또 다른 방법은 도메인 트러스트의 **opposite direction**으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 흔하지 않습니다).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**

trusted domain를 침해하는 또 다른 방법은 **user from the trusted domain can access**하여 **RDP**로 로그인할 수 있는 머신에서 기다리는 것입니다. 그런 다음 공격자는 RDP 세션 프로세스에 코드를 주입하여 거기서부터 **access the origin domain of the victim**할 수 있습니다.\
또한 **victim mounted his hard drive** 상태라면, 공격자는 **RDP session** 프로세스에서 하드 드라이브의 **startup folder**에 **backdoors**를 저장할 수 있습니다. 이 기법은 **RDPInception**이라고 불립니다.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- The risk of attacks leveraging the SID history attribute across forest trusts is mitigated by SID Filtering, which is activated by default on all inter-forest trusts. This is underpinned by the assumption that intra-forest trusts are secure, considering the forest, rather than the domain, as the security boundary as per Microsoft's stance.
- However, there's a catch: SID filtering might disrupt applications and user access, leading to its occasional deactivation.

### **SID Filtering:**

- forest 간 트러스트에서 SID history 속성을 악용한 공격 위험은 SID Filtering으로 완화됩니다. SID Filtering은 모든 inter-forest 트러스트에서 기본적으로 활성화되어 있습니다. 이는 Microsoft의 관점대로 도메인(domain) 대신 포리스트(forest)를 보안 경계로 간주하여 intra-forest 트러스트가 안전하다는 가정에 기반합니다.
- 다만 주의할 점은 SID filtering이 애플리케이션 및 사용자 접근을 방해할 수 있어 때때로 비활성화되는 경우가 있다는 것입니다.

### **Selective Authentication:**

- For inter-forest trusts, employing Selective Authentication ensures that users from the two forests are not automatically authenticated. Instead, explicit permissions are required for users to access domains and servers within the trusting domain or forest.
- It's important to note that these measures do not safeguard against the exploitation of the writable Configuration Naming Context (NC) or attacks on the trust account.

### **Selective Authentication:**

- inter-forest 트러스트의 경우 Selective Authentication을 사용하면 두 포리스트의 사용자가 자동으로 인증되지 않도록 보장합니다. 대신, 사용자가 trusting domain 또는 forest 내의 도메인 및 서버에 접근하려면 명시적 권한이 필요합니다.
- 이러한 조치들이 writable Configuration Naming Context (NC)의 악용이나 trust account에 대한 공격을 방지하지는 못한다는 점을 유의해야 합니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

## 몇 가지 일반적인 방어책

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: It is recommended that Domain Admins should only be allowed to login to Domain Controllers, avoiding their use on other hosts.
- **Service Account Privileges**: Services should not be run with Domain Admin (DA) privileges to maintain security.
- **Temporal Privilege Limitation**: For tasks requiring DA privileges, their duration should be limited. This can be achieved by: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **자격증명 보호를 위한 방어 조치**

- **Domain Admins Restrictions**: Domain Admins 계정은 다른 호스트에서 사용하는 것을 피하고 오직 Domain Controllers에만 로그인하도록 제한하는 것이 권장됩니다.
- **Service Account Privileges**: 보안을 위해 서비스는 Domain Admin (DA) 권한으로 실행되어서는 안 됩니다.
- **Temporal Privilege Limitation**: DA 권한이 필요한 작업의 경우 해당 권한 부여 시간을 제한해야 합니다. 예를 들어 다음과 같이 설정할 수 있습니다: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementing deception involves setting traps, like decoy users or computers, with features such as passwords that do not expire or are marked as Trusted for Delegation. A detailed approach includes creating users with specific rights or adding them to high privilege groups.
- A practical example involves using tools like: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Deception 기법 구현**

- Deception을 구현하려면 비활성화되지 않는 암호 설정이나 Trusted for Delegation로 표시된 계정 같은 유인 계정(예: decoy users 또는 computers)을 배치하는 등의 함정을 설정합니다. 구체적인 접근법으로는 특정 권한을 가진 사용자를 생성하거나 고권한 그룹에 추가하는 방법이 있습니다.
- 실용적인 예로는 다음과 같은 도구 사용이 있습니다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- deception 기법 배포에 대한 자세한 내용은 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있습니다.

### **Identifying Deception**

- **For User Objects**: Suspicious indicators include atypical ObjectSID, infrequent logons, creation dates, and low bad password counts.
- **General Indicators**: Comparing attributes of potential decoy objects with those of genuine ones can reveal inconsistencies. Tools like [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) can assist in identifying such deceptions.

### **Deception 식별**

- **For User Objects**: 의심스러운 지표로는 비정상적인 ObjectSID, 드문 로그온, 생성일자, 낮은 bad password 카운트 등이 있습니다.
- **General Indicators**: 잠재적 유인 객체의 속성을 실제 객체와 비교하면 불일치가 드러날 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)와 같은 도구가 이러한 deception 식별에 도움이 됩니다.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Avoiding session enumeration on Domain Controllers to prevent ATA detection.
- **Ticket Impersonation**: Utilizing **aes** keys for ticket creation helps evade detection by not downgrading to NTLM.
- **DCSync Attacks**: Executing from a non-Domain Controller to avoid ATA detection is advised, as direct execution from a Domain Controller will trigger alerts.

### **탐지 시스템 우회**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 탐지를 피하기 위해 Domain Controllers에서 세션 열거(session enumeration)를 피합니다.
- **Ticket Impersonation**: 티켓 생성 시 **aes** 키를 사용하면 NTLM으로 강등되지 않아 탐지를 회피하는 데 도움이 됩니다.
- **DCSync Attacks**: 직행으로 Domain Controller에서 실행하면 경보가 발생하므로, ATA 탐지를 피하려면 non-Domain Controller에서 실행하는 것이 권장됩니다.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
