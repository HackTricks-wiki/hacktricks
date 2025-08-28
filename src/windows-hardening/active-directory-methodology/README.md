# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 네트워크 내에서 **network administrators**가 **domains**, **users**, 및 **objects**를 효율적으로 생성하고 관리할 수 있게 해주는 기본 기술입니다. 대규모로 확장되도록 설계되어 많은 수의 사용자를 관리 가능한 **groups** 및 **subgroups**로 조직하고 다양한 수준에서 **access rights**를 제어할 수 있습니다.

**Active Directory**의 구조는 주로 세 가지 계층으로 구성됩니다: **domains**, **trees**, 그리고 **forests**. **Domain**은 공통 데이터베이스를 공유하는 **users**나 **devices**와 같은 객체들의 모음입니다. **Trees**는 공통 구조로 연결된 도메인들의 그룹이고, **forest**는 서로 **trust relationships**로 연결된 여러 trees의 집합으로 조직 구조의 최상위를 형성합니다. 각 계층에서 특정 **access** 및 **communication rights**를 지정할 수 있습니다.

**Active Directory**의 주요 개념은 다음과 같습니다:

1. **Directory** – Active Directory 객체와 관련된 모든 정보를 저장합니다.
2. **Object** – 디렉토리 내의 엔티티를 의미하며, 예로는 **users**, **groups**, 또는 **shared folders**가 있습니다.
3. **Domain** – 디렉토리 객체의 컨테이너로 작동하며, 여러 도메인이 **forest** 내에 공존할 수 있고 각 도메인은 자체 객체 컬렉션을 가집니다.
4. **Tree** – 공통 루트 도메인을 공유하는 도메인들의 그룹입니다.
5. **Forest** – Active Directory에서 조직 구조의 최상위로, 여러 trees와 그 사이의 **trust relationships**로 구성됩니다.

**Active Directory Domain Services (AD DS)**는 중앙 집중식 관리와 네트워크 내 통신을 위해 필수적인 여러 서비스를 포함합니다. 이 서비스들은 다음과 같습니다:

1. **Domain Services** – 데이터를 중앙화하여 저장하고 **users**와 **domains** 간의 상호작용(예: **authentication**, **search**)을 관리합니다.
2. **Certificate Services** – 안전한 **digital certificates**의 생성, 배포 및 관리를 담당합니다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 디렉토리 기반 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 여러 웹 애플리케이션에 대해 **single-sign-on**으로 사용자 인증을 제공합니다.
5. **Rights Management** – 저작권 자료의 무단 배포 및 사용을 제어하여 보호하는 데 도움을 줍니다.
6. **DNS Service** – **domain names**의 해석에 필수적입니다.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

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

### 사용자 열거

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

네트워크에서 이러한 서버 중 하나를 발견했다면 **user enumeration against it**도 수행할 수 있습니다. 예를 들어, 도구 [**MailSniper**](https://github.com/dafthack/MailSniper):
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

이미 유효한 사용자 이름은 알고 있지만 비밀번호가 없는 경우... 다음을 시도해보세요:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성을 **가지고 있지 않다면**, 해당 사용자에 대해 **AS_REP message를 요청**할 수 있습니다. 이 메시지에는 사용자의 비밀번호에서 유도된 값으로 암호화된 일부 데이터가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견된 각 사용자에 대해 가장 **일반적인 비밀번호**들을 시도해보세요. 일부 사용자가 취약한 비밀번호를 사용하고 있을 수 있습니다(비밀번호 정책을 염두에 두세요!).
- 또한 사용자의 메일 서버에 접근하기 위해 **OWA servers를 spray**할 수도 있습니다.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

네트워크의 일부 프로토콜을 **poisoning**하여 크랙할 수 있는 몇몇 챌린지 **해시**를 **획득**할 수 있을지도 모릅니다:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory를 열거하는 데 성공하면 **더 많은 이메일 주소와 네트워크에 대한 더 나은 이해**를 얻을 수 있습니다. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 강제하여 AD 환경에 접근할 수도 있습니다.

### Steal NTLM Creds

null 또는 guest 사용자로 다른 PC나 공유에 **접근**할 수 있다면, SCF 파일과 같은 파일을 **배치**할 수 있습니다. 누군가가 해당 파일에 접근하면 당신을 대상으로 하는 NTLM 인증이 **trigger**되어, 이를 통해 크랙 가능한 **NTLM challenge**를 **탈취**할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

이 단계에서는 유효한 도메인 계정의 credentials 또는 세션을 **탈취(compromised)**한 상태여야 합니다. 도메인 사용자로서 유효한 credentials나 셸을 가지고 있다면, 앞서 제시된 옵션들은 여전히 다른 사용자를 탈취하는 데 사용할 수 있다는 것을 기억하세요.

인증된 열거를 시작하기 전에 **Kerberos double hop problem**이 무엇인지 알아야 합니다.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

계정을 탈취했다는 것은 전체 도메인을 공격하기 시작하는 데 있어 **큰 진전**입니다. 이제 **Active Directory Enumeration**을 시작할 수 있기 때문입니다:

[**ASREPRoast**](asreproast.md)와 관련해서는 이제 가능한 모든 취약한 사용자를 찾을 수 있고, [**Password Spraying**](password-spraying.md)과 관련해서는 모든 사용자 이름의 **목록**을 얻어 탈취된 계정의 비밀번호, 빈 비밀번호, 또는 유망한 새 비밀번호를 시도해볼 수 있습니다.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- 디렉터리를 열거하는 데 사용할 수 있는 **GUI 툴**은 **SysInternal** Suite의 **AdExplorer.exe**입니다.
- ldapsearch로 LDAP 데이터베이스를 검색하여 _userPassword_ & _unixUserPassword_ 필드나 _Description_에서 자격증명을 찾아보세요. 다른 방법은 cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- 다음과 같은 자동화 도구도 시도할 수 있습니다:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows에서는 `net user /domain`, `Get-DomainUser` 또는 `wmic useraccount get name,sid`로 모든 도메인 사용자 이름을 얻는 것이 매우 쉽습니다. Linux에서는 `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 또는 `enum4linux -a -u "user" -p "password" <DC IP>`를 사용할 수 있습니다.

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting은 사용자 계정에 연결된 서비스가 사용하는 **TGS tickets**를 획득하고, 사용자 비밀번호에 기반한 암호화를 **오프라인으로** 크랙하는 것을 포함합니다.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

일단 자격증명을 얻었다면 어떤 **machine**에 접근할 수 있는지 확인해보세요. 포트 스캔 결과에 따라 여러 서버에 대해 다양한 프로토콜로 연결을 시도하기 위해 **CrackMapExec**를 사용할 수 있습니다.

### Local Privilege Escalation

일반 도메인 사용자로서 credentials 또는 세션을 탈취했고, 이 사용자로 도메인의 어떤 머신에든 **접근**할 수 있다면 로컬에서 권한을 상승시키고 자격증명을 수집하는 방법을 찾아보세요. 로컬 관리자 권한이 있어야만 메모리(LSASS)나 로컬(SAM)에서 다른 사용자들의 해시를 덤프할 수 있습니다.

이 책에는 [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html)에 관한 전체 페이지와 [**checklist**](../checklist-windows-privilege-escalation.md)가 있습니다. 또한, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)를 사용하는 것을 잊지 마세요.

### Current Session Tickets

현재 사용자 세션에서 예기치 않은 리소스에 접근할 수 있는 권한을 주는 **tickets**를 찾을 가능성은 매우 **낮습니다**, 그러나 확인해볼 수 있습니다:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **더 많은 이메일과 네트워크에 대한 더 나은 이해**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Computer Shares | SMB Shares에서 Creds를 찾기

이제 기본 credentials가 있으니 AD 내부에서 공유되고 있는 **흥미로운 파일**을 **찾을 수 있는지** 확인해야 합니다. 수동으로 할 수도 있지만 매우 지루하고 반복적인 작업입니다(특히 수백 개의 문서를 확인해야 할 경우 더 그렇습니다).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

다른 PC나 공유에 **접근할 수 있다면**, SCF 파일과 같은 파일을 **배치할 수 있습니다**. 누군가 그 파일에 접근하면 **당신을 대상으로 NTLM 인증을 트리거**하여 **NTLM challenge**를 **탈취**해 크랙할 수 있습니다:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점은 인증된 사용자가 **domain controller를 침해할 수 있게** 했습니다.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

운 좋게도 [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying 포함), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) 등을 사용해 **local admin 계정 일부의 권한을 획득**했을 것입니다.  
그런 다음 메모리와 로컬에서 모든 해시를 덤프할 시간입니다.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.  
이 해시를 사용해 **NTLM 인증을 수행하는** tool을 사용하거나, 새로운 **sessionlogon**을 생성하고 그 **해시를 LSASS 내부에 주입(inject)**할 수 있습니다. 그러면 어떤 **NTLM 인증**이 수행될 때 그 **해시가 사용**됩니다. 마지막 옵션은 mimikatz가 하는 방법입니다.  
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

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이것은 상당히 **노이즈가 크며** **LAPS**가 **완화**할 수 있다는 점에 유의하세요.

### MSSQL 오용 및 신뢰된 링크

사용자가 **MSSQL 인스턴스에 접근할 권한**이 있다면, MSSQL 호스트에서 **명령을 실행**(SA로 실행 중인 경우), NetNTLM **hash**를 **탈취**하거나 심지어 **relay** **attack**을 수행할 수 있습니다.\
또한, MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰(database link)되어 있는 경우, 사용자가 신뢰된 데이터베이스에 대한 권한을 가지고 있으면 **신뢰 관계를 이용해 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 체인으로 연결될 수 있으며, 결국 사용자가 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수도 있습니다.\
**데이터베이스 간의 링크는 forest trust를 가로질러서도 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 자산/배포 플랫폼 오용

서드파티 인벤토리 및 배포 스위트는 종종 자격증명과 코드 실행으로 접근할 수 있는 강력한 경로를 노출합니다. 참고:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

만약 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성을 가진 Computer 객체를 발견하고 그 컴퓨터에 대한 도메인 권한을 가지고 있다면, 그 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 컴퓨터에 로그인**하면, 그의 TGT를 덤프하여 [Pass the Ticket](pass-the-ticket.md)를 사용해 그의 권한을 가장할 수 있습니다.\
constrained delegation 덕분에 **Print Server를 자동으로 장악**할 수도 있습니다(운이 좋으면 DC일 것입니다).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자나 컴퓨터가 "Constrained Delegation"으로 허용되어 있다면, 해당 컴퓨터의 일부 서비스에 접근하기 위해 **어떤 사용자든 가장**할 수 있습니다.\
그런 다음 이 사용자/컴퓨터의 **hash를 탈취**하면, 일부 서비스에 접근하기 위해 **어떤 사용자든 가장**할 수 있게 되어 (심지어 domain admins도 포함) 권한 상승이 가능합니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대해 **WRITE** 권한을 갖고 있으면 **권한 상승된 상태로 코드 실행**을 얻을 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

탈취된 사용자는 **특정 도메인 객체에 대해 흥미로운 권한**을 가지고 있을 수 있으며, 이를 통해 이후에 **횡적 이동/권한 상승**이 가능해질 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

도메인 내에서 **Spool 서비스가 리스닝 중인 것**을 발견하면, 이를 **악용**하여 **새로운 자격증명을 획득**하고 **권한을 상승**시킬 수 있습니다.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 타 사용자 세션 오용

**다른 사용자들이** **침해된** 머신에 **접속**하면, 메모리에서 **자격증명 수집**이 가능하고 심지어 그들의 프로세스에 **beacon을 주입**해 그들을 가장할 수도 있습니다.\
대부분의 사용자는 RDP로 시스템에 접근하므로, 타 사용자 RDP 세션에 대해 수행할 수 있는 몇 가지 공격 방법은 다음과 같습니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인에 가입된 컴퓨터의 **로컬 Administrator 비밀번호**를 관리하기 위한 시스템을 제공하여, 비밀번호가 **무작위화**, 고유화되고 자주 **변경**되도록 보장합니다. 이 비밀번호들은 Active Directory에 저장되며 접근은 ACL을 통해 승인된 사용자로 제한됩니다. 이러한 비밀번호에 접근할 수 있는 충분한 권한을 획득하면 다른 컴퓨터로의 피벗이 가능해집니다.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

침해된 머신에서 **certificates를 수집**하는 것은 환경 내 권한 상승의 한 방법이 될 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**취약한 템플릿**이 설정되어 있다면 이를 악용해 권한 상승이 가능할 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 고권한 계정으로의 사후 활동

### Dumping Domain Credentials

한 번 **Domain Admin** 또는 더 나아가 **Enterprise Admin** 권한을 얻으면, 도메인 데이터베이스인 _ntds.dit_을 **덤프**할 수 있습니다.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

앞서 논의한 몇몇 기법은 영속성(persistence)으로도 사용될 수 있습니다.\
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

**Silver Ticket attack**은 특정 서비스에 대해 합법적인 Ticket Granting Service (TGS) 티켓을 생성하는 것으로, 예를 들어 **PC account의 NTLM hash**를 사용해 서비스 권한에 접근하는 방식입니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**은 공격자가 Active Directory 환경에서 **krbtgt 계정의 NTLM hash**를 얻는 것을 포함합니다. 이 계정은 모든 **Ticket Granting Ticket (TGT)**을 서명하는 데 사용되므로 AD 네트워크 내 인증에 필수적입니다.

공격자가 이 hash를 얻으면, 어떤 계정에 대해서도 **TGTs**를 생성할 수 있습니다 (Silver ticket attack과 유사한 활용).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이는 일반적인 golden ticket 탐지 메커니즘을 **우회하도록 위조된 golden ticket과 유사한 것들**입니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

계정의 **certificates를 보유하거나 요청할 수 있는 능력**은(심지어 사용자가 비밀번호를 변경하더라도) 해당 사용자 계정에 대해 영속성을 유지하는 매우 좋은 방법입니다:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificates를 사용하면 도메인 내에서 고권한으로도 영속성을 유지**할 수 있습니다:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** 객체는 **Domain Admins** 및 **Enterprise Admins**와 같은 **권한 있는 그룹**의 보안을 보장하기 위해 표준 **Access Control List (ACL)**을 이러한 그룹에 적용하여 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정하여 일반 사용자에게 전체 접근 권한을 부여하면, 해당 사용자는 모든 권한 있는 그룹에 대한 광범위한 제어권을 얻게 됩니다. 이 보안 기능은 면밀히 모니터링되지 않으면 오히려 무단 접근을 허용할 수 있습니다.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller (DC)** 내부에는 **로컬 관리자** 계정이 존재합니다. 해당 머신에서 관리자 권한을 획득하면, **mimikatz**를 사용해 로컬 Administrator hash를 추출할 수 있습니다. 이후 이 비밀번호의 사용을 가능하게 하기 위해 레지스트리 수정을 수행해야 하며, 이를 통해 로컬 Administrator 계정에 원격으로 접근할 수 있게 됩니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 도메인 객체에 대해 **특별 권한**을 사용자에게 **부여**하여, 해당 사용자가 **향후 권한 상승**을 할 수 있도록 만들 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors**는 객체가 가지고 있는 **권한**을 **저장**하는 데 사용됩니다. 객체의 security descriptor에 **작은 변경**을 가하는 것만으로도, 해당 객체에 대해 특권 그룹의 구성원이 아니어도 매우 흥미로운 권한을 얻을 수 있습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

메모리에서 **LSASS**를 변경하여 **범용 비밀번호**를 설정하면, 모든 도메인 계정에 대한 접근 권한을 부여할 수 있습니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자신만의 **SSP**를 만들어 머신에 접근할 때 사용되는 자격증명을 평문(clear text)으로 **포착**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

이는 AD에 **새로운 Domain Controller**를 등록하고 이를 사용해 특정 객체들에 대해 SIDHistory, SPNs 등을 **로그를 남기지 않고** 푸시하는 기법입니다. 이 동작을 위해서는 **DA** 권한과 루트 도메인 내부에 위치해야 합니다.\
단, 잘못된 데이터를 사용하면 보기 흉한 로그가 생성될 수 있다는 점에 유의하세요.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 **LAPS 비밀번호를 읽을 수 있는 충분한 권한**이 있을 때 권한 상승 방법에 대해 논의했습니다. 하지만 이러한 비밀번호는 **영속성 유지**에도 사용될 수 있습니다.\
참조:


{{#ref}}
laps.md
{{#endref}}

## 포리스트 권한 상승 - 도메인 트러스트

Microsoft는 **Forest**를 보안 경계로 봅니다. 이는 **단일 도메인을 침해하는 것이 전체 Forest의 침해로 이어질 수 있다**는 것을 의미합니다.

### 기본 정보

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 리소스에 접근할 수 있게 하는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템 간에 연결을 생성하여 인증 검증이 원활하게 흐르도록 합니다. 도메인들이 트러스트를 설정하면, 그들은 신뢰의 무결성에 중요한 특정 **키**들을 그들의 **Domain Controllers (DCs)** 내에 교환·저장합니다.

일반적인 시나리오에서 사용자가 **trusted domain**의 서비스에 접근하려면, 먼저 자신의 도메인 DC에서 **inter-realm TGT**라는 특별한 티켓을 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **키**로 암호화됩니다. 사용자는 이 TGT를 **trusted domain의 DC**에 제시하여 서비스 티켓(**TGS**)을 얻습니다. trusted domain의 DC가 inter-realm TGT를 검증하면, 해당 서비스에 대한 TGS를 발급하여 사용자의 서비스 접근을 허용합니다.

**절차**:

1. **Domain 1**의 **클라이언트 컴퓨터**가 자신의 **NTLM hash**를 사용해 **Domain Controller (DC1)**에 **Ticket Granting Ticket (TGT)**을 요청합니다.
2. 클라이언트가 성공적으로 인증되면 DC1은 새로운 TGT를 발급합니다.
3. 클라이언트는 **Domain 2**의 리소스에 접근하기 위해 DC1에서 **inter-realm TGT**를 요청합니다.
4. inter-realm TGT는 양방향 도메인 트러스트의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 inter-realm TGT를 **Domain 2의 Domain Controller (DC2)**에게 제출합니다.
6. DC2는 공유된 trust key를 사용해 inter-realm TGT를 검증하고, 유효하면 클라이언트가 접근하려는 Domain 2의 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로 클라이언트는 이 TGS를 서버에 제시하며, 이 TGS는 서버의 계정 해시로 암호화되어 있어 Domain 2의 서비스에 접근할 수 있게 됩니다.

### 다양한 트러스트

중요한 점은 **트러스트는 단방향이거나 양방향일 수 있다**는 것입니다. 양방향 옵션에서는 두 도메인이 서로를 신뢰하지만, **단방향** 트러스트 관계에서는 한 도메인이 **trusted**이고 다른 하나가 **trusting** 도메인입니다. 이 경우에는 **trusted 도메인에서만 trusting 도메인의 리소스에 접근할 수 있습니다**.

예를 들어 Domain A가 Domain B를 신뢰하면, A는 trusting 도메인이고 B는 trusted 도메인입니다. 또한, **Domain A**에서는 이것이 **Outbound trust**이고, **Domain B**에서는 **Inbound trust**가 됩니다.

**다양한 신뢰 관계 유형**

- **Parent-Child Trusts**: 동일 포리스트 내의 일반적인 설정으로, 자식 도메인은 자동으로 부모 도메인과 양방향 전이적(transitive) 트러스트를 갖습니다. 이는 부모와 자식 간에 인증 요청이 원활하게 흐를 수 있음을 의미합니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 불리며, 자식 도메인 간에 설정되어 참조 과정을 빠르게 합니다. 복잡한 포리스트에서는 인증 참조가 포리스트 루트까지 올라갔다가 대상 도메인으로 내려가야 하는데, cross-link를 만들면 이 경로를 단축할 수 있습니다.
- **External Trusts**: 서로 관련이 없는 다른 도메인 간에 설정되는 비전이전(non-transitive) 트러스트입니다. [Microsoft의 문서](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)에 따르면 외부 트러스트는 포리스트 트러스트로 연결되어 있지 않은 외부 도메인의 리소스 접근에 유용합니다. 외부 트러스트는 SID 필터링으로 보안이 강화됩니다.
- **Tree-root Trusts**: 포리스트 루트 도메인과 새로 추가된 트리 루트 간에 자동으로 설정되는 트러스트입니다. 자주 마주치지는 않지만, 새로운 도메인 트리를 포리스트에 추가할 때 중요합니다. 자세한 내용은 [Microsoft 가이드](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)를 참조하세요.
- **Forest Trusts**: 두 포리스트 루트 도메인 간의 양방향 전이적 트러스트로, SID 필터링을 통해 보안이 강화됩니다.
- **MIT Trusts**: 비-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos 도메인과 설정되는 트러스트입니다. MIT trusts는 Windows 생태계 밖의 Kerberos 기반 시스템과 통합해야 하는 환경에 특화되어 있습니다.

#### 신뢰 관계의 기타 차이점

- 트러스트 관계는 또한 **전이적(transitive)**일 수 있고(예: A가 B를 신뢰하고 B가 C를 신뢰하면 A는 C를 신뢰함) **비전이적(non-transitive)**일 수도 있습니다.
- 트러스트 관계는 **상호(bidirectional)**로 설정되거나 **단방향(one-way)**으로 설정될 수 있습니다.

### 공격 경로

1. **신뢰 관계 열거**
2. **어떤 security principal**(user/group/computer)이 **다른 도메인의 리소스에 접근**할 수 있는지 확인합니다. ACE 항목이나 다른 도메인의 그룹 구성원 여부로 판단하세요. **도메인 간의 관계**를 찾아보세요(트러스트가 이를 위해 생성되었을 가능성 있음).
1. 이 경우 kerberoast도 또 다른 옵션이 될 수 있습니다.
3. 도메인 간 **피벗**할 수 있는 **계정들을 탈취**합니다.

공격자는 다른 도메인의 리소스에 접근하기 위해 다음 세 가지 주요 메커니즘을 통해 접근할 수 있습니다:

- **Local Group Membership**: 원격 머신의 “Administrators” 그룹과 같은 로컬 그룹에 principal이 추가될 수 있으며, 이는 해당 머신에 대한 상당한 제어권을 부여합니다.
- **Foreign Domain Group Membership**: principal이 외부 도메인의 그룹 구성원일 수도 있습니다. 다만 이 방법의 효과는 트러스트의 성격과 그룹의 범위에 따라 달라집니다.
- **Access Control Lists (ACLs)**: principal이 **ACL**, 특히 **DACL** 내의 **ACE**로 지정되어 특정 리소스에 접근 권한을 부여받을 수 있습니다. ACL, DACL 및 ACE의 메커니즘에 대해 더 깊이 알고자 한다면, 백서 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”가 유용한 자료입니다.

### 권한을 가진 외부 사용자/그룹 찾기

도메인에서 외부 보안 주체(foreign security principals)를 찾으려면 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 를 확인할 수 있습니다. 이는 **외부 도메인/포리스트**의 사용자/그룹일 것입니다.

이 항목은 **Bloodhound**에서 확인하거나 powerview를 사용하여 확인할 수 있습니다:
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
> **2개의 trusted keys**가 있으며, 하나는 _Child --> Parent_용이고 다른 하나는 _Parent_ --> _Child_용입니다.\
> 현재 도메인에서 사용되는 키는 다음 명령으로 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection을 이용해 trust를 악용하여 child/parent 도메인에 대해 Enterprise admin으로 권한 상승:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)를 어떻게 악용할 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 포리스트 전체의 구성 데이터를 저장하는 중앙 저장소 역할을 합니다. 이 데이터는 포리스트 내의 모든 Domain Controller (DC)로 복제되며, 쓰기 가능한 DC(writable DC)는 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 **DC에서의 SYSTEM 권한**(가능하면 child DC)이 필요합니다.

**GPO를 root DC site에 연결하기**

Configuration NC의 Sites 컨테이너에는 AD 포리스트 내 모든 도메인 가입 컴퓨터의 site 정보가 포함되어 있습니다. 어떤 DC에서든 SYSTEM 권한으로 작업하면 공격자는 GPO를 root DC site에 연결할 수 있습니다. 이 작업은 해당 site에 적용되는 정책을 조작하여 root 도메인을 잠재적으로 손상시킬 수 있습니다.

자세한 내용은 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) 연구를 참고하세요.

**포리스트 내의 어떤 gMSA도 탈취하기**

공격 벡터 중 하나는 도메인 내의 권한 있는 gMSA를 표적으로 삼는 것입니다. gMSA의 비밀번호를 계산하는 데 필요한 KDS Root key는 Configuration NC에 저장됩니다. 어떤 DC에서든 SYSTEM 권한을 가지면 KDS Root key에 접근하여 포리스트 전역의 어떤 gMSA에 대해서도 비밀번호를 계산할 수 있습니다.

자세한 분석 및 단계별 가이드는 다음을 참조하세요:

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

보완적인 delegated MSA 공격 (BadSuccessor – migration attributes 악용):

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

추가 외부 연구: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

이 방법은 인내를 요구하며, 새로운 권한 있는 AD 객체가 생성될 때까지 기다려야 합니다. SYSTEM 권한이 있으면 공격자는 AD Schema를 수정하여 특정 사용자에게 모든 클래스에 대한 완전한 제어 권한을 부여할 수 있습니다. 이는 새로 생성되는 AD 객체에 대한 무단 접근 및 제어로 이어질 수 있습니다.

자세한 내용은 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)를 참고하세요.

**From DA to EA with ADCS ESC5**

ADCS ESC5 취약점은 PKI 객체를 제어하여 포리스트 내의 임의 사용자로 인증할 수 있는 certificate template을 생성하는 것을 목표로 합니다. PKI 객체는 Configuration NC에 위치하므로, 쓰기 가능한 child DC를 탈취하면 ESC5 공격을 실행할 수 있습니다.

이와 관련한 자세한 내용은 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)를 참조하세요. ADCS가 없는 환경에서는 공격자가 필요한 구성 요소를 직접 설정할 수도 있으며, 이에 대해서는 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)를 참고하세요.

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
이 시나리오에서는 외부 domain가 귀하의 domain을 신뢰하여 귀하에게 해당 domain에 대한 **undetermined permissions**을 부여합니다. 귀하는 귀하의 domain에 속한 어떤 **principals**가 외부 domain에 대해 어떤 **access**를 갖고 있는지 찾아낸 다음, 이를 악용하려고 시도해야 합니다:

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
In this scenario **귀하의 도메인**은 **다른 도메인**의 주체에 몇몇 **권한**을 **신뢰(trusting)** 하고 있습니다.

하지만, **신뢰되는 도메인(domain is trusted)** 은 신뢰하는 도메인에 의해 **예측 가능한 이름을 가진 사용자(create a user)** 를 생성하고, 그 비밀번호로 **trusted password** 를 사용합니다. 즉, **신뢰하는 도메인의 사용자에 접근(access a user from the trusting domain to get inside the trusted one)** 하여 신뢰된 도메인 내부를 열람하고 권한 상승을 시도할 수 있다는 의미입니다:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

또 다른 방법은 도메인 신뢰의 **반대 방향(opposite direction)** 으로 생성된 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)를 찾아 신뢰된 도메인을 침해하는 것입니다(이 방법은 자주 발생하지 않습니다).

또 다른 방법으로는 **신뢰된 도메인 사용자(user from the trusted domain)가 접근할 수 있는** 머신에서 대기하다가 그 사용자가 **RDP**로 로그인하는 순간을 노리는 것입니다. 그런 다음 공격자는 RDP 세션 프로세스에 코드를 주입하여 그곳에서 **피해자의 원래 도메인(origin domain of the victim)** 에 접근할 수 있습니다.\
게다가, 만약 **피해자가 자신의 하드 드라이브를 마운트(mounted his hard drive)** 해두었다면, 공격자는 **RDP 세션** 프로세스에서 하드 드라이브의 **startup folder**에 **backdoors**를 저장할 수 있습니다. 이 기법은 **RDPInception**이라 불립니다.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 도메인 신뢰 악용 완화

### **SID Filtering:**

- SID history 속성을 이용한 포리스트 간 공격 위험은 SID Filtering으로 완화되며, 이는 모든 포리스트 간 신뢰(inter-forest trusts)에서 기본적으로 활성화됩니다. 이는 Microsoft의 관점에서 보안 경계를 도메인이 아닌 포리스트(forest)로 간주한다는 가정에 기반합니다.
- 그러나 주의할 점은 SID filtering이 애플리케이션과 사용자 접근을 방해할 수 있어 때때로 비활성화되는 경우가 있다는 것입니다.

### **Selective Authentication:**

- 포리스트 간 신뢰에서는 Selective Authentication을 사용하면 두 포리스트의 사용자가 자동으로 인증되지 않도록 하여, 신뢰하는 도메인/포리스트 내의 도메인 및 서버에 접근하려면 명시적인 권한이 필요합니다.
- 다만, 이러한 조치들이 writable Configuration Naming Context (NC)의 악용이나 신뢰 계정(trust account)에 대한 공격을 방지하지는 못한다는 점에 유의해야 합니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 일반적인 방어책

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins는 Domain Controllers에만 로그인하도록 허용하고 다른 호스트에서는 사용하지 않도록 권장합니다.
- **Service Account Privileges**: 보안 유지를 위해 서비스는 Domain Admin (DA) 권한으로 실행해서는 안 됩니다.
- **Temporal Privilege Limitation**: DA 권한이 필요한 작업에 대해서는 권한 지속 시간을 제한해야 합니다. 예시 명령: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Deception(속임수) 구현은 만우(미끼) 사용자나 컴퓨터를 설정하는 것으로, 만료되지 않는 비밀번호나 Trusted for Delegation로 표시된 계정 같은 속성을 갖게 하는 등의 함정 설치를 포함합니다. 상세한 접근법은 특정 권한을 가진 사용자를 생성하거나 고권한 그룹에 추가하는 것을 포함합니다.
- 실용적인 예시는 다음과 같은 도구 사용을 포함합니다: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- deception 기법 배포에 대한 자세한 내용은 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있습니다.

### **Identifying Deception**

- **For User Objects**: 의심스러운 지표로는 비정상적인 ObjectSID, 드문 로그온(infrequent logons), 생성 날짜, 낮은 잘못된 비밀번호 시도 수(bad password counts) 등이 있습니다.
- **General Indicators**: 잠재적 미끼 객체의 속성을 진짜 객체의 속성과 비교하면 불일치를 발견할 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 같은 도구가 이러한 속임수를 식별하는 데 도움을 줄 수 있습니다.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 탐지를 피하기 위해 Domain Controllers에서의 세션 열람(session enumeration)을 피합니다.
- **Ticket Impersonation**: 티켓 생성 시 **aes** 키를 사용하면 NTLM으로 강등하지 않아 탐지를 회피하는 데 유리합니다.
- **DCSync Attacks**: DCSync는 Domain Controller가 아닌 곳에서 실행하여 ATA 탐지를 피하는 것이 권장되며, Domain Controller에서 직접 실행하면 경고가 발생합니다.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
