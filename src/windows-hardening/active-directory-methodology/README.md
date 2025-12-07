# Active Directory 방법론

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 네트워크 내에서 **도메인**, **사용자**, 및 **객체**를 효율적으로 생성하고 관리할 수 있게 해주는 기본 기술입니다. 확장 가능하도록 설계되어 많은 수의 사용자를 관리 가능한 **그룹**과 **하위 그룹**으로 조직하고 다양한 수준에서 **접근 권한**을 제어할 수 있습니다.

**Active Directory**의 구조는 주로 세 가지 계층으로 구성됩니다: **domains**, **trees**, 그리고 **forests**. **domain**은 공통 데이터베이스를 공유하는 **users**나 **devices**와 같은 객체들의 집합을 포함합니다. **trees**는 공통 구조로 연결된 이러한 도메인들의 그룹이며, **forest**는 여러 trees가 **trust relationships**로 상호 연결된 조직 구조의 최상위 계층을 나타냅니다. 각 계층에서 특정 **access** 및 **communication rights**를 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다:

1. **Directory** – Active Directory 객체와 관련된 모든 정보를 저장합니다.
2. **Object** – 디렉터리 내의 엔티티를 나타내며, **users**, **groups**, 또는 **shared folders** 등이 포함됩니다.
3. **Domain** – 디렉터리 객체를 담는 컨테이너로, 여러 **domains**이 하나의 **forest** 내에 공존할 수 있으며 각 도메인은 자체 객체 컬렉션을 유지합니다.
4. **Tree** – 공통 루트 도메인을 공유하는 도메인들의 그룹입니다.
5. **Forest** – Active Directory의 조직 구조에서 최상위에 위치하며, 여러 **trees**와 그들 간의 **trust relationships**로 구성됩니다.

**Active Directory Domain Services (AD DS)**는 네트워크 내 중앙 관리 및 통신을 위해 중요한 다양한 서비스를 포함합니다. 이러한 서비스들은 다음을 포함합니다:

1. **Domain Services** – 데이터 저장을 중앙화하고 **users**와 **domains** 간의 상호작용을 관리하며 **authentication**과 **search** 기능을 제공합니다.
2. **Certificate Services** – 안전한 **digital certificates**의 생성, 배포 및 관리를 감독합니다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 디렉터리 지원 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 여러 웹 애플리케이션에 대해 **single-sign-on** 기능을 제공하여 사용자가 한 세션으로 인증할 수 있게 합니다.
5. **Rights Management** – 저작권 자료를 보호하고 무단 배포 및 사용을 규제하는 데 도움을 줍니다.
6. **DNS Service** – **domain names** 해석에 매우 중요합니다.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

만약 AD 환경에 접근은 가능하지만 자격 증명/세션이 전혀 없다면 다음을 시도할 수 있습니다:

- **Pentest the network:**
- 네트워크를 스캔하여 머신과 열려 있는 포트를 찾고 **취약점 exploit**을 시도하거나 거기서 **credentials**를 추출해 보세요 (예: [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS 열거는 도메인 내의 웹, 프린터, shares, vpn, media 등 중요한 서버에 대한 정보를 제공할 수 있습니다.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 이와 관련해 더 많은 정보를 원하면 일반 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)를 참고하세요.
- **Check for null and Guest access on smb services** (이 방법은 최신 Windows 버전에서는 작동하지 않을 수 있습니다):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB 서버를 열거하는 방법에 대한 보다 자세한 가이드는 다음에서 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP 열거에 대한 보다 자세한 가이드는 다음에서 확인할 수 있습니다 (특히 **anonymous access**에 주의하세요):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- [**Responder**로 서비스를 가장하여]('../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md') 자격 증명을 수집합니다.
- [**relay attack**을 악용하여 호스트에 접근합니다](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack).
- [**evil-S**로 가짜 UPnP 서비스를 노출하여 자격 증명을 수집합니다](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 내부 문서, 소셜 미디어, 도메인 환경 내부의 서비스(주로 웹) 및 공개적으로 이용 가능한 곳에서 사용자 이름/이름을 추출합니다.
- 회사 직원의 전체 이름을 찾으면 다양한 AD **username conventions**을 시도해 볼 수 있습니다 ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). 가장 일반적인 규칙은: _NameSurname_, _Name.Surname_, _NamSur_ (각각 3글자), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3개의 _random letters와 3개의 random numbers_ (abc123).
- 도구:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 및 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 페이지를 확인하세요.
- **Kerbrute enum**: **invalid username**가 요청되면 서버는 **Kerberos error** 코드 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_로 응답하여 해당 사용자 이름이 잘못되었음을 알 수 있게 합니다. **Valid usernames**는 AS-REP에서 **TGT**를 반환하거나 _KRB5KDC_ERR_PREAUTH_REQUIRED_ 오류를 일으켜 사용자가 pre-authentication을 요구받는다는 것을 나타냅니다.
- **No Authentication against MS-NRPC**: 도메인 컨트롤러의 MS-NRPC (Netlogon) 인터페이스에 대해 auth-level = 1 (No authentication)을 사용합니다. 이 방법은 MS-NRPC 인터페이스를 바인딩한 후 `DsrGetDcNameEx2` 함수를 호출하여 자격 증명 없이 사용자 또는 컴퓨터가 존재하는지 확인합니다. 이 유형의 열거를 구현한 도구는 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)입니다. 관련 연구는 [여기](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)에서 확인할 수 있습니다.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

네트워크에서 이러한 서버 중 하나를 발견했다면 해당 서버에 대한 **user enumeration against it**를 수행할 수도 있습니다. 예를 들어 [**MailSniper**](https://github.com/dafthack/MailSniper):
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

### Knowing one or several usernames

자, 유효한 username은 이미 알고 있지만 비밀번호는 모르는 상태라면... 다음을 시도하세요:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성을 **가지고 있지 않으면**, 해당 사용자에 대해 AS_REP 메시지를 요청할 수 있으며 이 메시지에는 사용자의 비밀번호 파생값으로 암호화된 일부 데이터가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견된 각 사용자에 대해 가장 **일반적인 비밀번호**들을 시도해 보세요. 일부 사용자가 취약한 비밀번호를 사용하고 있을 수 있습니다(비밀번호 정책을 고려하세요!).
- 또한 사용자들의 메일 서버 접근을 시도하기 위해 **spray OWA servers**도 노려볼 수 있습니다.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

네트워크의 일부 프로토콜을 **poisoning**하여 크래킹할 수 있는 챌린지 **해시**를 얻을 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory를 열거하는 데 성공하면 더 많은 이메일과 네트워크에 대한 더 나은 이해를 얻게 됩니다. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 강제해 AD 환경에 접근할 수 있을지도 모릅니다.

### Steal NTLM Creds

null or guest user로 다른 PC나 공유에 접근할 수 있다면, **place files**(like a SCF file)을 배치해 누군가 해당 파일에 접근하면 t**rigger an NTLM authentication against you** 하도록 유도하여 **steal** the **NTLM challenge**을 획득해 크랙할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

이 단계에서는 유효한 도메인 계정의 자격증명이나 세션을 확보해야 합니다. 도메인 사용자로서 유효한 자격증명이나 셸을 가지고 있다면, 이전에 제시된 옵션들은 여전히 다른 사용자를 침해하는 데 사용할 수 있다는 점을 기억하세요.

인증된 열거를 시작하기 전에 **Kerberos double hop problem**이 무엇인지 알아야 합니다.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

계정을 확보하는 것은 전체 도메인을 침해하기 위한 **중요한 첫걸음**입니다. 이제 **Active Directory Enumeration**을 시작할 수 있기 때문입니다:

[**ASREPRoast**](asreproast.md)에 관해서는 이제 가능한 모든 취약 사용자를 찾을 수 있으며, [**Password Spraying**](password-spraying.md)에 관해서는 모든 사용자 이름의 **목록**을 얻어 침해된 계정의 비밀번호, 빈 비밀번호 및 잠재적인 새 비밀번호들을 시도해 볼 수 있습니다.

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)을 사용해 기본 recon을 수행할 수 있습니다.
- 또한 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)을 사용하면 더 은밀합니다.
- 또한 [**use powerview**](../basic-powershell-for-pentesters/powerview.md)를 사용해 보다 자세한 정보를 추출할 수 있습니다.
- Active Directory recon에 유용한 또 다른 도구는 [**BloodHound**](bloodhound.md)입니다. 사용하는 수집 방법에 따라 **매우 은밀하지 않을 수 있지만**, **그 점이 중요하지 않다면** 꼭 사용해 보세요. 사용자가 RDP 가능한 위치나 다른 그룹으로의 경로 등을 찾을 수 있습니다.
- **다른 자동화된 AD 열거 도구들:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md)는 흥미로운 정보를 포함하고 있을 수 있습니다.
- 디렉터리를 열거할 때 사용할 수 있는 GUI 도구로는 **SysInternal** Suite의 **AdExplorer.exe**가 있습니다.
- **ldapsearch**로 LDAP 데이터베이스를 검색하여 _userPassword_ 및 _unixUserPassword_ 필드나 _Description_에서 자격증명을 찾아볼 수 있습니다. 다른 방법은 cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- **Linux**를 사용 중이라면 [**pywerview**](https://github.com/the-useless-one/pywerview)로 도메인을 열거할 수도 있습니다.
- 또한 다음과 같은 자동화 도구들을 시도할 수 있습니다:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)

- **Extracting all domain users**

Windows에서는 `net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`로 도메인 사용자 이름을 쉽게 얻을 수 있습니다. Linux에서는 `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`를 사용할 수 있습니다.

> 이 Enumeration 섹션이 짧게 보일지라도 이 부분이 가장 중요합니다. 링크들(특히 cmd, powershell, powerview, BloodHound)을 확인하고, 도메인 열거 방법을 배우며 익숙해질 때까지 연습하세요. 평가 중에 이 순간이 DA로 가는 길을 찾거나 더 이상 할 수 있는 것이 없는지 판단하는 핵심이 됩니다.

### Kerberoast

Kerberoasting은 사용자 계정에 연결된 서비스가 사용하는 **TGS tickets**를 얻고, 사용자 비밀번호에 기반한 암호화를 **오프라인**에서 크랙하는 기법입니다.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

자격증명을 얻었다면 어떤 **machine**에 접근 권한이 있는지 확인해 보세요. 포트 스캔 결과에 따라 여러 서버에 다양한 프로토콜로 접속을 시도하려면 **CrackMapExec**를 사용할 수 있습니다.

### Local Privilege Escalation

일반 도메인 사용자로서 자격증명이나 세션을 확보했고 해당 사용자로 도메인의 어떤 머신에든 **접근**할 수 있다면, 로컬 권한 상승과 자격증명 획득을 시도해야 합니다. 로컬 관리자 권한이 있어야만 메모리(LSASS)와 로컬(SAM)에서 다른 사용자의 해시를 **dump**할 수 있기 때문입니다.

이 책에는 [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html)와 [**checklist**](../checklist-windows-privilege-escalation.md)에 대한 페이지가 있습니다. 또한 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 사용을 잊지 마세요.

### Current Session Tickets

현재 사용자의 세션에서 예기치 않은 리소스에 접근할 수 있는 권한을 주는 **tickets**를 발견할 가능성은 매우 **낮지만**, 확인해 볼 수는 있습니다:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### 컴퓨터 공유에서 Creds 찾기 | SMB Shares

Now that you have some basic credentials you should check if you can **find** any **interesting files being shared inside the AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

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

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이 내용은 상당히 **노이즈가 많으며** **LAPS**가 이를 **완화**할 수 있다는 점에 유의하세요.

### MSSQL Abuse & Trusted Links

사용자가 **MSSQL instances에 접근할 권한**이 있으면, (호스트가 SA로 실행 중인 경우) MSSQL 호스트에서 **명령을 실행**하거나 NetNTLM **hash**를 **탈취**하거나 심지어 **relay** **attack**을 수행할 수 있습니다.\
또한, 한 MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰(데이터베이스 링크)되어 있는 경우, 사용자가 신뢰된 데이터베이스에 대한 권한을 가지고 있으면 **신뢰 관계를 이용해 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 체인으로 연결될 수 있으며 결국 사용자가 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수도 있습니다.\
**데이터베이스 간 링크는 forest trusts를 가로질러서도 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

서드파티 인벤토리 및 배포 스위트는 종종 자격증명과 코드 실행으로 이어지는 강력한 경로를 노출합니다. 상세 내용 참조:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

만약 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성을 가진 Computer 객체를 찾고 그 컴퓨터에서 도메인 권한을 가지고 있다면, 그 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 해당 컴퓨터에 로그인하면**, 그의 TGT를 덤프하여 [Pass the Ticket](pass-the-ticket.md)를 사용해 그를 가장할 수 있습니다.\
constrained delegation 덕분에 **Print Server를 자동으로 탈취**할 수도 있습니다(운이 좋으면 DC일 것입니다).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자 또는 컴퓨터가 "Constrained Delegation"에 허용되어 있으면 해당 대상 컴퓨터의 일부 서비스에 접근하기 위해 **임의의 사용자를 대리**할 수 있습니다.\
그런 다음 해당 사용자/컴퓨터의 **hash를 탈취**하면 (심지어 domain admins도) **임의의 사용자를 대리**하여 일부 서비스를 이용할 수 있게 됩니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대해 **WRITE** 권한을 가지면 **권한 상승된 상태에서 코드 실행**을 달성할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

탈취된 사용자는 일부 도메인 객체에 대해 흥미로운 **권한**을 가지고 있을 수 있으며, 이는 이후에 횡적이동/권한 **상승**을 가능하게 할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

도메인 내에서 **Spool 서비스가 리스닝 중인 것을 발견**하면 이를 **악용**하여 **새로운 자격증명 획득** 및 **권한 상승**을 할 수 있습니다.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

다른 사용자가 **탈취된 기계에 접근**하면, 메모리에서 **자격증명 수집**을 하거나 심지어 **그들의 프로세스에 beacons를 주입**하여 그들을 가장할 수 있습니다.\
대부분의 사용자는 RDP로 시스템에 접근하므로, 타사 RDP 세션에 대해 몇 가지 공격을 수행하는 방법은 다음을 참조하세요:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인에 가입된 컴퓨터의 **로컬 Administrator 비밀번호**를 관리하는 시스템을 제공하며, 비밀번호가 **무작위화**, 고유화되고 자주 **변경**되도록 보장합니다. 이 비밀번호들은 Active Directory에 저장되며, 접근은 권한이 있는 사용자에게만 ACL을 통해 제어됩니다. 이 비밀번호에 접근할 충분한 권한이 있으면 다른 컴퓨터로의 피벗이 가능합니다.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

탈취된 머신에서 **인증서 수집**은 환경 내부에서 **권한 상승**을 달성하는 방법이 될 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

취약한 템플릿이 구성되어 있으면 이를 악용하여 권한 상승을 할 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 고권한 계정으로 수행하는 사후 활동

### Dumping Domain Credentials

한번 **Domain Admin** 또는 더 나아가 **Enterprise Admin** 권한을 획득하면, 도메인 데이터베이스인 _ntds.dit_을 **덤프**할 수 있습니다.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

앞서 논의한 몇몇 기법은 지속성(persistence)을 위해 사용될 수 있습니다.\
예를 들어 다음과 같은 작업이 가능합니다:

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

**Silver Ticket attack**은 특정 서비스에 대해 합법적인 Ticket Granting Service (TGS) 티켓을 생성하는 방법으로, 예를 들어 **PC account의 NTLM hash**를 사용하여 서비스 권한에 접근하는 데 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**은 공격자가 Active Directory 환경에서 **krbtgt 계정의 NTLM hash**에 접근하는 것을 포함합니다. 이 계정은 모든 **Ticket Granting Tickets (TGTs)**에 서명하는 데 사용되므로 AD 네트워크 내 인증에 필수적입니다.

공격자가 이 해시를 얻으면, 원하는 어떤 계정에 대해서도 **TGTs**를 생성할 수 있습니다 (Silver ticket attack 참조).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diamond tickets는 일반적인 golden tickets 탐지 메커니즘을 **우회하도록 위조된** golden tickets와 유사합니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

계정의 인증서를 보유하거나 인증서를 요청할 수 있는 권한이 있다면, 사용자가 비밀번호를 변경하더라도 해당 사용자 계정에 **지속성**을 유지하는 매우 좋은 방법입니다:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

인증서를 사용하면 도메인 내부에서 **높은 권한으로 지속성**을 유지하는 것도 가능합니다:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** 객체는 **Domain Admins**나 **Enterprise Admins** 같은 특권 그룹들의 보안을 유지하기 위해 표준 **ACL**을 적용하여 이러한 그룹에 대한 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정하여 일반 사용자에게 전체 접근 권한을 부여하면, 그 사용자는 모든 특권 그룹을 광범위하게 제어할 수 있게 됩니다. 이 보안 조치는 모니터링이 제대로 되지 않으면 오히려 권한 남용을 허용할 수 있습니다.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller (DC)**에는 로컬 관리자 계정이 존재합니다. 해당 머신에서 관리자 권한을 얻으면, **mimikatz**를 사용해 로컬 Administrator hash를 추출할 수 있습니다. 그 후 이 비밀번호를 사용 가능하도록 레지스트리를 수정하면 원격에서 로컬 Administrator 계정으로 접근할 수 있습니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 도메인 객체에 대해 일부 **특수 권한**을 **사용자에게 부여**하여 향후 그 사용자가 권한을 상승시킬 수 있도록 할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors**는 객체가 가지고 있는 **권한**을 **저장**하는 데 사용됩니다. 만약 객체의 security descriptor를 **조금만 변경**할 수 있다면, 해당 객체에 대해 특권 그룹의 멤버가 아니더라도 매우 흥미로운 권한을 얻을 수 있습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS의 메모리를 변경하여 모든 도메인 계정에 대해 **범용 비밀번호**를 설정함으로써 접근을 허용합니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자체 **SSP**를 만들어 머신에 접근할 때 사용되는 **자격증명(평문)**을 캡처할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

새로운 Domain Controller를 AD에 등록하고 이를 사용해 지정된 객체들에 대해 SIDHistory, SPNs 등 속성을 **로그를 남기지 않고** 푸시합니다. 이 공격에는 DA 권한이 필요하며 루트 도메인 내부에 있어야 합니다.\
잘못된 데이터를 사용하면 아주 보기 안 좋은 로그가 남을 수 있다는 점을 유의하세요.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

이전에 LAPS 비밀번호를 읽을 수 있는 충분한 권한이 있으면 권한 상승이 가능하다고 논의했습니다. 그러나 이 비밀번호들은 또한 **지속성**을 유지하는 데 사용될 수 있습니다.\
자세한 내용은 다음을 확인하세요:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft는 **Forest**를 보안 경계로 간주합니다. 이는 **단일 도메인을 침해하면 전체 Forest가 침해될 가능성**이 있음을 의미합니다.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **domain**의 사용자가 다른 **domain**의 리소스에 접근할 수 있도록 하는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템 간에 연결을 생성하여 인증 검증이 원활하게 흐르도록 합니다. 도메인들이 신뢰를 설정할 때, 그들은 신뢰의 무결성에 중요한 특정 **keys**를 각자의 **Domain Controllers (DCs)**에 교환하고 보관합니다.

일반적인 시나리오에서, 사용자가 **trusted domain**의 서비스에 접근하려면 먼저 자신의 도메인 DC로부터 **inter-realm TGT**라는 특별한 티켓을 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **key**로 암호화됩니다. 사용자는 이 TGT를 **trusted domain의 DC**에 제출하여 서비스 티켓(**TGS**)을 얻습니다. trusted domain의 DC가 inter-realm TGT를 검증하면, 요청된 서비스에 대한 TGS를 발급하여 사용자가 서비스에 접근할 수 있게 합니다.

**절차**:

1. **Domain 1**의 클라이언트 컴퓨터가 자신의 **NTLM hash**를 사용해 **Domain Controller (DC1)**에 **Ticket Granting Ticket (TGT)**을 요청합니다.
2. 클라이언트 인증이 성공하면 DC1은 새로운 TGT를 발급합니다.
3. 클라이언트는 **Domain 2**의 리소스에 접근하기 위해 DC1로부터 **inter-realm TGT**를 요청합니다.
4. inter-realm TGT는 양방향 도메인 신뢰의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**에 제시합니다.
6. DC2는 공유된 trust key를 사용해 inter-realm TGT를 검증하고 유효하면 클라이언트가 접근하려는 Domain 2의 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로 클라이언트는 이 TGS를 해당 서버에 제시하며, 이 TGS는 서버 계정 해시로 암호화되어 서비스 접근을 허용합니다.

### Different trusts

신뢰는 **단방향** 또는 **양방향**일 수 있다는 점을 주의하세요. 양방향인 경우 두 도메인이 서로를 신뢰하지만, **단방향** 신뢰 관계에서는 한 도메인이 **trusted**이고 다른 도메인이 **trusting** 도메인이 됩니다. 이 경우 **trusted 도메인에서 trusting 도메인 내부의 리소스만 접근**할 수 있습니다.

만약 Domain A가 Domain B를 신뢰하면, A는 trusting 도메인이고 B는 trusted 도메인입니다. 또한 **Domain A**에서는 이것이 **Outbound trust**로 나타나고, **Domain B**에서는 **Inbound trust**로 나타납니다.

**다양한 신뢰 관계**

- **Parent-Child Trusts**: 동일한 포리스트 내에서 일반적인 설정으로, 자식 도메인은 자동으로 부모 도메인과 양방향 전이적 신뢰(two-way transitive trust)를 가집니다. 이는 부모와 자식 간에 인증 요청이 원활하게 흐를 수 있음을 의미합니다.
- **Cross-link Trusts**: "shortcut trusts"라고 불리며, 자식 도메인들 사이에 설정되어 레퍼럴 과정을 단축합니다. 복잡한 포리스트에서는 인증 레퍼럴이 포리스트 루트까지 올라갔다가 목표 도메인으로 내려가야 할 수 있는데, cross-link를 생성하면 이 경로가 단축됩니다.
- **External Trusts**: 서로 관련이 없는 다른 도메인들 사이에 설정되는 비전이전(non-transitive) 신뢰입니다. Microsoft 문서에 따르면 외부 신뢰는 포리스트 신뢰로 연결되지 않은 외부 도메인의 리소스 접근에 유용합니다. 보안은 SID 필터링으로 강화됩니다.
- **Tree-root Trusts**: 포리스트 루트 도메인과 새로 추가된 tree root 사이에 자동으로 설정되는 신뢰입니다. 자주 보이는 것은 아니지만, 새로운 도메인 트리를 포리스트에 추가할 때 중요합니다.
- **Forest Trusts**: 두 포리스트 루트 도메인 간의 양방향 전이적 신뢰로, SID 필터링을 통해 보안을 강화합니다.
- **MIT Trusts**: 비-Windows의, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos 도메인과 설정되는 신뢰입니다. Kerberos 기반 시스템과의 통합이 필요한 환경에서 사용됩니다.

#### Other differences in **trusting relationships**

- 신뢰 관계는 **전이적(transitive)**일 수도 있고 **비전이적(non-transitive)**일 수도 있습니다 (예: A가 B를 신뢰하고 B가 C를 신뢰하면 A가 C를 신뢰하게 되는 경우).
- 신뢰 관계는 **양방향**으로 설정되거나 **단방향**으로 설정될 수 있습니다.

### Attack Path

1. **신뢰 관계 열거(enumerate)**
2. 어떤 **security principal**(user/group/computer)이 **다른 도메인의 리소스에 접근할 수 있는지** 확인하세요—ACE 항목이나 해당 도메인의 그룹 멤버십 여부로 확인할 수 있습니다. **도메인 간 관계**를 찾아보세요(신뢰는 아마 이를 위해 생성되었을 가능성이 큽니다).
1. 이 경우 kerberoast도 또 다른 옵션이 될 수 있습니다.
3. 도메인을 통해 **피벗(pivot)**할 수 있는 **계정들을 탈취(compromise)**하세요.

공격자가 다른 도메인의 리소스에 접근할 수 있는 주된 메커니즘은 세 가지입니다:

- **Local Group Membership**: 원격 서버의 “Administrators” 그룹 같은 로컬 그룹에 주체(principal)가 추가되어 해당 머신에 대한 상당한 제어권을 부여받을 수 있습니다.
- **Foreign Domain Group Membership**: 주체가 외부 도메인의 그룹 멤버일 수도 있습니다. 다만 이 방법의 효과는 신뢰의 성격과 그룹의 범위(scope)에 따라 달라집니다.
- **Access Control Lists (ACLs)**: 주체가 특히 **DACL 내의 ACE**로 지정되어 특정 리소스에 대한 접근 권한을 가질 수 있습니다. ACLs, DACLs, ACEs의 메커니즘을 더 깊이 이해하려면 whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”를 참고하세요.

### Find external users/groups with permissions

도메인에서 외부 보안 주체를 찾으려면 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**을 확인하세요. 이들은 **외부 도메인/포리스트**의 사용자/그룹입니다.

Bloodhound나 powerview를 사용하여 이것을 확인할 수 있습니다:
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
> 신뢰된 키가 **2개** 있으며, 하나는 _Child --> Parent_ 용이고 다른 하나는 _Parent_ --> _Child_ 용입니다.\
> 현재 도메인에서 사용 중인 키를 다음으로 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

신뢰를 악용해 SID-History injection으로 child/parent domain에 대해 Enterprise admin으로 권한을 상승시킵니다:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)가 어떻게 악용될 수 있는지 이해하는 것은 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 포리스트 전체의 구성 데이터를 중앙에서 저장하는 저장소 역할을 합니다. 이 데이터는 포리스트 내의 모든 Domain Controller (DC)에 복제되며, writable DC는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 **DC에서 SYSTEM privileges**, 가능하면 child DC 권한이 필요합니다.

**Link GPO to root DC site**

Configuration NC의 Sites container에는 AD 포리스트 내 모든 도메인 가입 컴퓨터들의 사이트 정보가 포함됩니다. 어떤 DC에서든 SYSTEM privileges로 작업하면 공격자는 GPO를 root DC site에 링크할 수 있습니다. 이 조작은 해당 사이트에 적용되는 정책을 변조하여 root domain을 잠재적으로 손상시킬 수 있습니다.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

공격 벡터는 도메인 내의 권한 있는 gMSA를 노리는 것입니다. gMSA의 비밀번호를 계산하는 데 필요한 KDS Root key는 Configuration NC에 저장됩니다. 어떤 DC에서든 SYSTEM privileges를 획득하면 KDS Root key에 접근해 포리스트 전체의 어떤 gMSA 비밀번호든 계산할 수 있습니다.

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

이 방법은 인내가 필요하며, 새로운 권한 있는 AD 객체의 생성까지 기다려야 합니다. SYSTEM privileges를 가진 공격자는 AD Schema를 수정하여 모든 클래스에 대해 특정 사용자에게 완전한 제어 권한을 부여할 수 있습니다. 이는 새로 생성되는 AD 객체들에 대한 무단 접근 및 제어로 이어질 수 있습니다.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 취약점은 PKI 객체에 대한 제어를 목표로 하며, 이를 통해 포리스트 내 어떤 사용자로서도 인증할 수 있는 certificate template을 생성할 수 있습니다. PKI 객체들이 Configuration NC에 존재하기 때문에, writable child DC를 손상시키면 ESC5 공격을 실행할 수 있습니다.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) 또는 양방향
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
이 시나리오에서는 **외부 도메인이 귀하의 도메인을 신뢰**하며 그로 인해 귀하에게 해당 도메인에 대해 **확인되지 않은 권한**을 부여합니다. 귀하는 **자신의 도메인 내 어떤 주체(principals)가 외부 도메인에 대해 어떤 접근 권한을 가지고 있는지** 찾아낸 다음 이를 악용하려 시도해야 합니다:

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
In this scenario **귀하의 도메인**은 **다른 도메인**에 속한 principal에게 일부 **권한**을 **부여(trusting)**하고 있습니다.

하지만, **도메인이 신뢰된(trusted)** 경우, 신뢰된 도메인은 **예측 가능한 이름**을 가진 **사용자 계정**을 생성하고 그 계정의 **비밀번호**로 신뢰된 비밀번호를 설정합니다. 즉, **trusting 도메인의 사용자를 이용해 신뢰된 도메인에 접근**하여 해당 도메인을 열거하고 추가 권한 상승을 시도할 수 있습니다:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

신뢰된 도메인을 침해하는 또 다른 방법은 도메인 트러스트와 반대 방향으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾는 것입니다(이는 흔하지 않습니다).

신뢰된 도메인의 사용자가 **RDP**로 로그인할 수 있는 머신에서 대기하는 것도 또 다른 방법입니다. 그런 다음 공격자는 RDP 세션 프로세스에 코드를 주입하여 거기서 **피해자의 원래 도메인(origin domain of the victim)**에 접근할 수 있습니다. 게다가, **피해자가 자신의 하드 드라이브를 마운트한 상태**라면, 공격자는 **RDP 세션** 프로세스에서 하드 드라이브의 **시작 폴더(startup folder of the hard drive)**에 **backdoors**를 저장할 수 있습니다. 이 기술은 **RDPInception**이라고 불립니다.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 도메인 신뢰 남용 완화

### **SID Filtering:**

- SID history 속성을 이용한 공격 위험은 **SID Filtering**으로 완화됩니다. SID Filtering은 모든 inter-forest 신뢰에서 기본적으로 활성화되어 있습니다. 이는 Microsoft의 입장대로 보안 경계를 도메인이 아닌 forest로 간주하여 intra-forest 신뢰가 안전하다고 가정하는 데 기반합니다.
- 그러나 함정이 하나 있습니다: SID filtering은 애플리케이션과 사용자 접근을 방해할 수 있어 때때로 비활성화되기도 합니다.

### **Selective Authentication:**

- inter-forest 신뢰의 경우 **Selective Authentication**을 사용하면 두 포리스트의 사용자가 자동으로 인증되지 않습니다. 대신, 사용자가 신뢰하는 도메인 또는 포리스트 내의 도메인과 서버에 접근하려면 명시적인 권한이 필요합니다.
- 이러한 조치들은 writable Configuration Naming Context (NC)의 악용이나 trust account에 대한 공격으로부터 보호하지 못한다는 점을 유의해야 합니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)은 bloodyAD-style LDAP primitives를 on-host implant(예: Adaptix C2) 내부에서 완전히 실행되는 x64 Beacon Object Files로 재구현합니다. 운영자는 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`로 패키지를 컴파일하고, `ldap.axs`를 로드한 다음 비콘에서 `ldap <subcommand>`를 호출합니다. 모든 트래픽은 현재 로그인 보안 컨텍스트를 통해 LDAP(389)에서 signing/sealing 또는 LDAPS(636)에서 자동 인증서 신뢰로 전송되므로 socks 프록시나 디스크 아티팩트가 필요하지 않습니다.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers`는 단축 이름/OU 경로를 전체 DN으로 해석하고 해당 객체들을 덤프합니다.
- `get-object`, `get-attribute`, and `get-domaininfo`는 임의의 속성(보안 설명자 포함)과 `rootDSE`에서 포리스트/도메인 메타데이터를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd`는 roasting candidates, delegation 설정, 그리고 기존 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 디스크립터를 LDAP에서 직접 노출합니다.
- `get-acl` and `get-writable --detailed`는 DACL을 파싱하여 trustees, 권한(GenericAll/WriteDACL/WriteOwner/attribute writes) 및 상속을 나열해 ACL 권한 상승을 위한 즉각적인 대상들을 제공합니다.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 은 운영자가 OU 권한이 있는 위치에 새 principals 또는 machine accounts 를 배치할 수 있게 합니다. `add-groupmember`, `set-password`, `add-attribute`, 및 `set-attribute` 는 write-property 권한을 획득한 즉시 대상자를 직접 탈취합니다.
- ACL-focused 명령어들(`add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, 및 `add-dcsync`) 은 어떤 AD 객체에서든 WriteDACL/WriteOwner 를 password reset, group membership 제어, 또는 DCSync replication privileges 로 변환하며 PowerShell/ADSI 아티팩트를 남기지 않습니다. `remove-*` 대응 명령어들은 주입된 ACE들을 정리합니다.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` 은 손상된 사용자를 즉시 Kerberoastable 하게 만듭니다; `add-asreproastable` (UAC 토글)은 비밀번호를 건드리지 않고 AS-REP roasting 대상으로 표시합니다.
- Delegation 매크로들(`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) 은 비콘에서 `msDS-AllowedToDelegateTo`, UAC 플래그, 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity` 를 재작성하여 constrained/unconstrained/RBCD 공격 경로를 열어주며 원격 PowerShell 또는 RSAT이 불필요하게 만듭니다.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` 는 제어되는 principal 의 SID history 에 privileged SIDs 를 주입합니다 (see [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS 상에서 은밀한 접근 상속을 제공합니다.
- `move-object` 는 컴퓨터나 사용자의 DN/OU 를 변경하여 공격자가 기존에 delegation 권한이 있는 OU 로 자산을 끌어와 `set-password`, `add-groupmember`, 또는 `add-spn` 등을 남용하기 전에 위치를 옮길 수 있게 해줍니다.
- 범위가 좁은 제거 명령들(`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, 등)은 운영자가 자격증명이나 영속성을 수집한 후 신속히 롤백할 수 있게 하여 탐지 텔레메트리를 최소화합니다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 몇 가지 일반적인 방어

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Credential Protection을 위한 방어 조치**

- **Domain Admins Restrictions**: Domain Admins 는 가능한 한 Domain Controllers 에만 로그인하도록 제한하고 다른 호스트에서의 사용을 피하는 것이 권장됩니다.
- **Service Account Privileges**: 서비스는 보안 유지를 위해 Domain Admin (DA) 권한으로 실행되어서는 안 됩니다.
- **Temporal Privilege Limitation**: DA 권한을 필요로 하는 작업의 경우 지속 시간을 제한해야 합니다. 예시: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Deception 구현은 미끼 사용자나 컴퓨터 같은 함정을 설정하는 것을 포함하며, 비밀번호 만료 없음 또는 Trusted for Delegation 으로 표시된 계정과 같은 특징을 가질 수 있습니다. 자세한 접근법에는 특정 권한을 가진 사용자를 생성하거나 고권한 그룹에 추가하는 작업이 포함됩니다.
- 실무 예시: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception 기법 배포에 대한 자세한 내용은 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) 에서 확인할 수 있습니다.

### **Deception 식별하기**

- **For User Objects**: 의심스러운 징후로는 비정상적인 ObjectSID, 드문 로그온, 생성 날짜, 낮은 bad password 카운트 등이 있습니다.
- **General Indicators**: 잠재적 decoy 객체의 속성을 진짜 객체와 비교하면 불일치를 발견할 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 같은 도구가 이러한 deception 식별에 도움이 됩니다.

### **탐지 시스템 우회**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 탐지를 피하기 위해 Domain Controllers 에서 세션 열거를 피합니다.
- **Ticket Impersonation**: 티켓 생성에 **aes** 키를 사용하면 NTLM으로 강등하지 않아 탐지를 회피하는데 도움이 됩니다.
- **DCSync Attacks**: Domain Controller 가 아닌 곳에서 실행하면 ATA 탐지를 피할 수 있습니다. Domain Controller 에서 직접 실행하면 경보를 유발합니다.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
