# Active Directory Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n grondliggende tegnologie wat netwerkadministrateurs toelaat om doeltreffend **domains**, **users**, en **objects** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, wat die organisering van 'n groot aantal gebruikers in hanteerbare **groups** en **subgroups** vergemaklik, terwyl **access rights** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domains**, **trees**, en **forests**. 'n **Domain** sluit 'n versameling objeke in, soos **users** of **devices**, wat 'n gemeenskaplike databasis deel. **Trees** is groepe van hierdie domains wat verbind is deur 'n gedeelde struktuur, en 'n **forest** verteenwoordig die versameling van verskeie trees, gekoppel deur **trust relationships**, wat die boonste laag van die organisasiestruktuur vorm. Spesifieke **access** en **communication rights** kan op elkeen van hierdie vlakke aangewys word.

Sleutelkonsepte binne **Active Directory** sluit in:

1. **Directory** – Huisves alle inligting rakende Active Directory-objekte.
2. **Object** – Dui entiteite binne die directory aan, insluitende **users**, **groups**, of **shared folders**.
3. **Domain** – Dien as 'n houer vir directory-objekte, met die vermoë dat meerdere domains binne 'n **forest** kan bestaan, elk met hul eie versameling objeke.
4. **Tree** – 'n Groepering van domains wat 'n gemeenskaplike root domain deel.
5. **Forest** – Die hoogste vlak van die organisasie in Active Directory, saamgestel uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat 'n reeks dienste wat kritiek is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domain Services** – Sentreer datastoor en bestuur interaksies tussen **users** en **domains**, insluitend **authentication** en **search** funksies.
2. **Certificate Services** – Beheer die skep, verspreiding, en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-enabled toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on** vermoëns om gebruikers oor meerdere webtoepassings in een sessie te verifieer.
5. **Rights Management** – Help om kopieregmateriaal te beskerm deur ongeoorloofde verspreiding en gebruik te beheer.
6. **DNS Service** – Krities vir die resolusie van **domain names**.

Vir 'n meer gedetaileerde verduideliking kyk: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om 'n **AD** aan te val, moet jy die **Kerberos authentication process** baie goed verstaan.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Spiekbrief

Jy kan baie by [https://wadcoms.github.io/](https://wadcoms.github.io) kry om vinnig 'n oorsig te hê van watter opdragte jy kan uitvoer om 'n AD te enumerate/exploit.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** vir die uitvoering van aksies. As jy probeer om toegang tot 'n masjien te kry via die IP-adres, **sal dit NTLM gebruik en nie Kerberos nie**.

## Recon Active Directory (No creds/sessions)

As jy net toegang tot 'n AD-omgewing het maar jy het geen credentials/sessies nie, kan jy:

- **Pentest the network:**
- Scan die netwerk, vind masjiene en oop poorte en probeer om **vulnerabilities** te **exploit** of **extract credentials** daaruit (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS-enumerasie kan inligting gee oor sleutelbedieners in die domain soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die Algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit sal nie op moderne Windows-weergawes werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB-bediener te enumerate kan hier gevind word:


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
- Versamel credentials deur [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Verkry toegang tot 'n host deur [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Onttrek gebruikersname/namens uit interne dokumente, sosiale media, dienste (veral web) binne die domain-omgewings en ook van publiek beskikbare bronne.
- As jy die volle name van maatskappywerkers vind, kan jy verskillende AD **username conventions** probeer ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die mees algemene konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elk), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruikerenumerasie

- **Anonymous SMB/LDAP enum:** Kyk die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **invalid username is requested** sal die bediener antwoord met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons toelaat om te bepaal dat die gebruikersnaam ongeldig was. **Valid usernames** sal óf 'n **TGT in 'n AS-REP** reaksie óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_ ontlok, wat aandui dat die gebruiker pre-authentication moet verrig.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon) koppelvlak op domain controllers. Die metode roep die `DsrGetDcNameEx2` funksie aan nadat dit aan die MS-NRPC koppelvlak gebind het om te kontroleer of die gebruiker of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implementeer hierdie tipe enumerasie. Die navorsing kan hier gevind word [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie servers in die netwerk gevind het, kan jy ook **user enumeration against it** uitvoer. Byvoorbeeld, jy kan die tool [**MailSniper**](https://github.com/dafthack/MailSniper):
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

### As jy een of meer gebruikersname ken

Ok, jy weet dus dat jy reeds 'n geldige gebruikersnaam het maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As 'n gebruiker **nie die attribuut** _DONT_REQ_PREAUTH_ **het nie** kan jy 'n AS_REP boodskap vir daardie gebruiker versoek wat data sal bevat wat deur 'n afleiding van die gebruiker se wagwoord versleuteld is.
- [**Password Spraying**](password-spraying.md): Probeer die mees **algemene wagwoorde** met elk van die ontdekte gebruikers; dalk gebruik 'n gebruiker 'n swak wagwoord (onthou die wagwoordbeleid!).
- Let daarop dat jy ook **OWA servers kan spray** om toegang tot die gebruikers se mail servers te probeer kry.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy mag in staat wees om challenge hashes te verkry om te crack deur poisoning van sekere netwerkprotokolle:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

As jy daarin geslaag het om die Active Directory te enumereer sal jy meer e-posadresse en 'n beter begrip van die netwerk hê. Jy mag in staat wees om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) te forceer om toegang tot die AD-omgewing te kry.

### Steal NTLM Creds

As jy toegang tot ander rekenaars of shares het met die **null** of **guest** gebruiker, kan jy lêers plaas (soos 'n SCF file) wat, as dit op een of ander wyse geopen word, 'n **NTLM authentication** teenoor jou sal trigger sodat jy die **NTLM challenge** kan steel om dit te crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerasie van Active Directory MET credentials/sessie

Vir hierdie fase moet jy die **credentials of 'n sessie van 'n geldige domain account** gekompromitteer hê. As jy geldige credentials of 'n shell as 'n domain user het, moet jy onthou dat die opsies wat vroeër gegee is steeds opsies is om ander gebruikers te kompromitteer.

Voordat jy met die geauthentiseerde enumerasie begin, moet jy weet wat die **Kerberos double hop problem** is.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasie

Om 'n rekening te kompromitteer is 'n groot stap om die hele domein te begin kompromitteer, omdat jy in staat sal wees om die **Active Directory Enumeration** te begin:

Wat [**ASREPRoast**](asreproast.md) betref, kan jy nou elke moontlike kwesbare gebruiker vind; en wat [**Password Spraying**](password-spraying.md) betref kan jy 'n **lys van al die gebruikersname** kry en die wagwoord van die gekompromitteerde rekening probeer, leë wagwoorde en nuwe veelbelovende wagwoorde.

- Jy kan die [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) gebruik
- Jy kan ook [**powershell for recon**](../basic-powershell-for-pentesters/index.html) gebruik wat meer onopvallend sal wees
- Jy kan ook [**use powerview**](../basic-powershell-for-pentesters/powerview.md) gebruik om meer gedetailleerde inligting te onttrek
- Nog 'n wonderlike tool vir recon in 'n Active Directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy** (afhangend van die versamelmetodes wat jy gebruik nie), maar **as dit jou nie omgee** nie, moet jy dit beslis probeer. Vind waar gebruikers RDP kan, vind paaie na ander groepe, ens.
- **Ander geoutomatiseerde AD enumerasie-instrumente is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) aangesien dit interessante inligting kan bevat.
- 'n **instrument met 'n GUI** wat jy kan gebruik om die directory te enumerasieer is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook in die LDAP-databasis soek met **ldapsearch** om na credentials te kyk in velde _userPassword_ & _unixUserPassword_, of selfs in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- As jy **Linux** gebruik, kan jy die domein ook enumereer met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook geoutomatiseerde gereedskap probeer soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Dit is baie maklik om al die domeingebruikersname van Windows te bekom (`net user /domain`, `Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumerasie-afdeling klein, dit is die belangrikste deel van alles. Gaan na die skakels (veral dié van cmd, powershell, powerview en BloodHound), leer hoe om 'n domein te enumereer en oefen totdat jy gemaklik voel. Tydens 'n assessment sal dit die sleutel oomblik wees om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS tickets** wat deur dienste wat aan gebruikersrekeninge verbonde is gebruik word, en die kraking van hul enkripsie — wat gebaseer is op gebruikerswagwoorde — offline.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy sommige credentials verkry het, kan jy kyk of jy toegang tot enige masjien het. Daarvoor kan jy **CrackMapExec** gebruik om te probeer verbind met verskeie bedieners oor verskillende protokolle, ooreenkomstig jou port scans.

### Local Privilege Escalation

As jy credentials of 'n sessie as 'n gewone domain user gekompromitteer het en jy het met hierdie gebruiker toegang tot enige masjien in die domein, moet jy probeer om plaaslik jou voorregte te eskaleer en loot vir credentials. Dit is omdat slegs met plaaslike administrateur-voorregte jy in staat sal wees om hashes van ander gebruikers te dump uit geheue (LSASS) en lokaal (SAM).

Daar is 'n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en 'n [**checklist**](../checklist-windows-privilege-escalation.md). Moenie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie onwaarskynlik dat jy tickets in die huidige gebruiker sal vind wat jou toestemming gee om onvoorsiene hulpbronne te bereik, maar jy kan kyk:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy daarin geslaag het om die Active Directory te enumereer sal jy **meer e-posadresse en 'n beter begrip van die netwerk** hê. Jy mag in staat wees om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Soek na Creds in Computer Shares | SMB Shares

Nou dat jy 'n paar basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige, herhalende taak (veral as jy honderde dokumente kry wat jy moet nagaan).

[**Volg hierdie skakel om te leer oor gereedskap wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander PCs of shares kan kry, kan jy lêers plaas (soos 'n SCF file) wat, as dit op een of ander manier geopen word, 'n **NTLM authentication teen jou sal veroorsaak** sodat jy die **NTLM challenge** kan **steal** om dit te krak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwetsbaarheid het enige geauthentiseerde gebruiker in staat gestel om die **domain controller** te kompromitteer.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende techniques is 'n gewone domain user nie genoeg nie; jy benodig spesiale privileges/credentials om hierdie attacks uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **lokale admin** rekening te kompromitteer met behulp van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Dan is dit tyd om al die hashes in geheue en plaaslik te dump.  
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om hom/haar te **impersonate**.  
Jy moet 'n **tool** gebruik wat die **NTLM authentication met daardie hash sal uitvoer**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** in **LSASS** inject, sodat wanneer enige **NTLM authentication** uitgevoer word, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.  
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie attack mik daarop om die **user NTLM hash te gebruik om Kerberos tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor NTLM-protokol. Daarom kan dit veral **nuttig wees in netwerke waar die NTLM protocol gedeaktiveer is** en slegs **Kerberos as authentication protocol toegelaat word**.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** attack-metode steel aanvallers 'n gebruiker se **authentication ticket** in plaas van hul wagwoord of hash-waardes. Hierdie gesteelde ticket word dan gebruik om die gebruiker te **impersonate**, en sodoende ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk te verkry.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van 'n **local administrator** het, moet jy probeer om daarmee **login locally** op ander **PCs**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let daarop dat dit redelik **ruisend** is en **LAPS** dit sou **verminder**.

### MSSQL Abuse & Trusted Links

As 'n gebruiker die voorregte het om **MSSQL instances te toegang**, kan hy/sy dit gebruik om **opdragte uit te voer** op die MSSQL-host (as dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay attack** uit te voer.\
As 'n MSSQL-instantie deur 'n ander MSSQL-instantie vertrou word (database link) en die gebruiker het voorregte oor die vertroude databasis, sal die gebruiker die **vertrouensverhouding kan gebruik om ook navrae in die ander instansie uit te voer**. Hierdie trusts kan geketting word en op 'n stadium kan die gebruiker 'n foutief ge-konfigureerde databasis vind waar hy/sy opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Derdeparty-inventaris- en implementeringssuite ontbloot dikwels kragtige paaie na credentials en kode-uitvoering. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer-objek vind met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) en jy het domeinvoorregte op die rekenaar, sal jy TGT's uit die geheue kan dump van elke gebruiker wat op daardie rekenaar aanmeld.\
Dus, as 'n **Domain Admin op die rekenaar aanmeld**, kan jy sy TGT dump en hom imiteer met [Pass the Ticket](pass-the-ticket.md).\
Danksy constrained delegation kan jy selfs **outomaties 'n Print Server kompromitteer** (hopelik is dit 'n DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As 'n gebruiker of rekenaar vir "Constrained Delegation" toegelaat is, kan dit **enige gebruiker imiteer om toegang tot sekere dienste op 'n rekenaar te kry**.\
Indien jy die **hash kompromitteer** van hierdie gebruiker/rekenaar, kan jy **enige gebruiker imiteer** (insluitend Domain Admins) om toegang tot sommige dienste te verkry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Om **WRITE**-voorregte op 'n Active Directory-objek van 'n afgeleë rekenaar te hê, maak dit moontlik om kode-uitvoering met **verhoogde voorregte** te bekom:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die gekompromitteerde gebruiker kan sommige **interessante voorregte oor bepaalde domeinobjekte** hê wat jou toelaat om lateraal te **beweg** of voorregte te **eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Om 'n **Spool service wat luister** binne die domein te ontdek, kan **misbruik** word om **nuwe credentials te bekom** en **voorregte te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **ander gebruikers** toegang tot die **gekompromitteerde** masjien het, is dit moontlik om **credentials uit geheue te versamel** en selfs **beacons in hul prosesse in te spuit** om hulle te imiteer.\
Gewoonlik sal gebruikers die stelsel via RDP gebruik, dus hier is hoe om 'n paar aanvalle oor derdeparty RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** voorsien 'n stelsel om die **lokale Administrator-wagwoord** op domain-joined rekenaars te bestuur, sodat dit **gerandomiseer**, uniek en gereeld **verander** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACL's slegs aan gemagtigde gebruikers beheer. Met voldoende toestemming om hierdie wagwoorde te lees, word pivoting na ander rekenaars moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Versameling van sertifikate** van die gekompromitteerde masjien kan 'n manier wees om voorregte binne die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **kwesbare templates** gekonfigureer is, kan dit misbruik word om voorregte te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin** of, nog beter, **Enterprise Admin** voorregte kry, kan jy die **domeindatabasis** dump: _ntds.dit_.

[**Meer inligting oor die DCSync-aanval is hier te vind**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel is hier te vind**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke hierbo beskryf kan gebruik word vir persistentie.\
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

Die **Silver Ticket aanval** skep 'n **legitieme Ticket Granting Service (TGS) ticket** vir 'n spesifieke diens deur die gebruik van die **NTLM hash** (bv. die **hash van die PC-rekening**). Hierdie metode word gebruik om **toegang tot die diens se voorregte** te kry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket aanval** behels dat 'n aanvaller toegang kry tot die **NTLM hash van die krbtgt-rekening** in 'n Active Directory-omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir verifikasie binne die AD-netwerk.

Sodra die aanvaller hierdie hash bekom, kan hulle **TGTs** vir enige rekening skep wat hulle kies (Silver ticket-aanval).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hierdie is soos golden tickets, maar vervals op 'n manier wat **algemene opsporingsmeganismes vir golden tickets omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om sertifikate van 'n rekening te hê of dit te kan versoek** is 'n uitstekende manier om in die gebruiker se rekening te kan bly (selfs as hy/sy die wagwoord verander):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Om sertifikate te gebruik is ook moontlik om met hoë voorregte in die domein persistentie te handhaaf:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-objek in Active Directory verseker die sekuriteit van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te verhoed. Hierdie funksie kan egter misbruik word; as 'n aanvaller die AdminSDHolder se ACL wysig om volle toegang aan 'n gewone gebruiker te gee, kry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie sekuriteitsmaatreël, bedoel om te beskerm, kan dus teëgewerk word en ongewensde toegang moontlik maak tensy dit noukeurig gemonitor word.

[**Meer inligting oor AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In elke **Domain Controller (DC)** bestaan daar 'n **lokale administrateur**-rekening. Deur adminregte op so 'n masjien te verkry, kan die lokale Administrator-hash met **mimikatz** geëkstraheer word. Daarna is 'n registerwysiging nodig om die gebruik van hierdie wagwoord te **aktiveer**, wat afstandstoegang tot die plaaslike Administrator-rekening moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan sommige **spesiale voorregte** aan 'n **gebruiker** gee oor spesifieke domeinobjekte wat die gebruiker in staat sal stel om in die toekoms **voorregte te eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **regsituasie** wat 'n **object** oor 'n ander **object** het, te **stoor**. As jy 'n klein verandering in die **security descriptor** van 'n objek kan maak, kan jy baie interessante voorregte oor daardie objek bekom sonder om lid van 'n bevoorregte groep te hoef te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in geheue om 'n **universale wagwoord** te vestig, wat toegang tot alle domeinrekeninge gee.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Leer wat 'n SSP (Security Support Provider) is hier.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **credentials** wat gebruik word om op die masjien aan te meld in **clair teks** te **vang**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **nuwe Domain Controller** in die AD en gebruik dit om attributte (SIDHistory, SPNs...) op gespesifiseerde objekte te **push** **sonder** om logs van die **wysigings** te laat. Jy **behoort DA**-voorregte te hê en binne die **root domain** te wees.\
Let wel: as jy verkeerde data gebruik, sal leliker logs voorkom.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hierbo het ons bespreek hoe om voorregte te eskaleer as jy **genoeg toestemming het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **persistentie** te handhaaf.\
Kyk:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domein moontlik tot die kompromittering van die hele Forest kan lei**.

### Basic Information

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domein** toelaat om hulpbronne in 'n ander **domein** te gebruik. Dit skep 'n skakel tussen die verifikasiestelsels van die twee domeine, wat verifikasie-verkeer laat vloei. Wanneer domeine 'n trust opstel, ruil en stoor hulle spesifieke **sleutels** binne hul **Domain Controllers (DCs)** wat kritiek is vir die trust se integriteit.

In 'n tipiese scenario, as 'n gebruiker 'n diens in die **vertroude domein** wil bereik, moet hulle eers 'n spesiale ticket, bekend as 'n **inter-realm TGT**, van hul eie domein se DC aanvra. Hierdie TGT is met 'n gedeelde **sleutel** versleuteld wat albei domeine deel. Die gebruiker bied dan hierdie TGT by die **DC van die vertroude domein** aan om 'n diens-ticket (**TGS**) te kry. Nadat die vertroude domein se DC die inter-realm TGT suksesvol geverifieer het, gee dit 'n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **Kliëntrekenaar** in **Domein 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** van sy **Domain Controller (DC1)** te versoek.
2. DC1 gee 'n nuwe TGT uit as die kliënt suksesvol geverifieer word.
3. Die kliënt versoek dan 'n **inter-realm TGT** van DC1, wat benodig word om hulpbronne in **Domein 2** te bereik.
4. Die inter-realm TGT is versleuteld met 'n **trust key** wat tussen DC1 en DC2 gedeel word as deel van die tweerigting domeintrust.
5. Die kliënt neem die inter-realm TGT na **Domein 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, indien geldig, gee dit 'n **Ticket Granting Service (TGS)** vir die bediener in Domein 2 wat die kliënt wil gebruik.
7. Laastens, die kliënt bied hierdie TGS aan die bediener, wat met die bediener se rekeninghash versleuteld is, om toegang tot die diens in Domein 2 te kry.

### Different trusts

Dit is belangrik om te let dat **'n trust eenrigting of tweerigting kan wees**. In die tweerigting opsie vertrou beide domeine mekaar, maar in 'n **eenrigting** trust is een van die domeine die **trusted** en die ander die **trusting** domein. In laasgenoemde geval sal **jy slegs hulpbronne binne die trusting domein van die trusted domein af kan krap**.

As Domein A Domein B vertrou, is A die trusting domein en B die trusted een. Verder sal dit in **Domein A** as 'n **Outbound trust** verskyn; en in **Domein B** as 'n **Inbound trust**.

**Verskillende trusting-verhoudings**

- **Parent-Child Trusts**: 'n Algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n tweerigting transitive trust met sy ouer-domein hê. Dit beteken dat verifikasie-versoeke naatloos tussen ouer en kind kan vloei.
- **Cross-link Trusts**: Ook genoem "shortcut trusts", word tussen child domains ingestel om verwysingsprosesse te versnel. In komplekse forests moet verifikasie-verwysings tipies na die boswortel gaan en dan na die teiken-domein af. Cross-links verkort die pad, wat veral in geografies verspreide omgewings nuttig is.
- **External Trusts**: Hierdie word tussen verskillende, unrelated domeine ingestel en is nie-transitief van aard nie. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig om hulpbronne in 'n domein buite die huidige forest te bereik wat nie deur 'n forest trust verbind is nie. Sekuriteit word versterk deur SID-filtering met external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties tussen die forest root domain en 'n nuut toegevoegde tree root ingestel. Alhoewel nie gereeld voorgekom nie, is tree-root trusts belangrik vir die byvoeging van nuwe domeinboome tot 'n forest, wat hulle toelaat om 'n unieke domeinnaam te behou en tweerigting-transitiviteit te verseker. Meer inligting is beskikbaar in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie tipe trust is 'n tweerigting transitive trust tussen twee forest root domeine, en implementeer ook SID-filtering om sekuriteitsmaatreëls te verbeter.
- **MIT Trusts**: Hierdie trusts word met nie-Windows, [RFC4120-kompatible](https://tools.ietf.org/html/rfc4120) Kerberos-domeine ingestel. MIT trusts is meer gespesialiseerd en bedien omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem benodig.

#### Ander verskille in **trusting relationships**

- 'n trustverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dan A vertrou C) of **nie-transitief**.
- 'n trustverhouding kan gestel word as **bidirectionele trust** (albei vertrou mekaar) of as **eenrigting trust** (slegs een daarvan vertrou die ander).

### Attack Path

1. **Enumereer** die trusting-verhoudings
2. Kontroleer of enige **security principal** (user/group/computer) **toegang** tot hulpbronne van die **ander domein** het, moontlik deur ACE-inskrywings of deur lidmaatskap in groepe van die ander domein. Soek na **verhoudings oor domeine** (die trust is waarskynlik daarvoor geskep).
1. [**Kerberoast**](kerberoast.md) in hierdie geval kan 'n ander opsie wees.
3. **Kompromitteer** die **rekeninge** wat deur die domeine kan **pivot**.

Aanvallers kan deur drie primêre meganismes toegang tot hulpbronne in 'n ander domein kry:

- **Local Group Membership**: Principals kan bygevoeg word tot plaaslike groepe op masjiene, soos die "Administrators" groep op 'n bediener, wat hulle groot beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook lede wees van groepe binne die buitelandse domein. Die doeltreffendheid hiervan hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan in 'n **ACL** spesifiseer wees, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne gee. Vir dieper insig in die meganika van ACLs, DACLs en ACEs, is die whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n onskatbare hulpbron.

### Find external users/groups with permissions

Jy kan kyk by **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** om buitelandse security principals in die domein te vind. Dit sal gebruikers/groepe uit **'n eksterne domein/forest** wees.

Jy kan dit in **Bloodhound** nagaan of met powerview:
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
> Daar is **2 vertroude sleutels**, een vir _Child --> Parent_ en nog een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domein gebruik word, sien met:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaleer as Enterprise admin na die child/parent domein deur die trust met SID-History injection te misbruik:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Dit is van kardinale belang om te verstaan hoe die Configuration Naming Context (NC) uitgebuit kan word. Die Configuration NC dien as 'n sentrale bewaarplek vir konfigurasiedata oor 'n forest in Active Directory (AD) omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, met skryfbare DCs wat 'n skryfbare kopie van die Configuration NC onderhou. Om dit te misbruik, moet 'n mens **SYSTEM privileges on a DC**, by voorkeur 'n child DC hê.

**Link GPO to root DC site**

Die Sites-behouer van die Configuration NC bevat inligting oor die sites van alle domein-gekoppelde rekenaars binne die AD-forest. Deur met SYSTEM-privileges op enige DC te werk, kan aanvallers GPOs aan die root DC-sites koppel. Hierdie aksie kan die root domain moontlik kompromitteer deur die beleide wat op hierdie sites toegepas word, te manipuleer.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Een aanvalsvector behels die teiken van bevoorregte gMSA's binne die domein. Die KDS Root key, noodsaaklik vir die berekening van gMSA-wagwoorde, word binne die Configuration NC gestoor. Met SYSTEM-privileges op enige DC is dit moontlik om by die KDS Root key uit te kom en die wagwoorde vir enige gMSA oor die hele forest te bereken.

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

Hierdie metode vereis geduld en die afwagting van die skepping van nuwe bevoorregte AD-objekte. Met SYSTEM-privileges kan 'n aanvaller die AD Schema wysig om enige user volle beheer oor alle klasses te gee. Dit kan lei tot ongemagtigde toegang en beheer oor nuut geskepte AD-objekte.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 kwesbaarheid mik op beheer oor Public Key Infrastructure (PKI) objek­te om 'n sertifikaatsjabloon te skep wat verifikasie as enige gebruiker binne die forest moontlik maak. Aangesien PKI-objekte in die Configuration NC woon, stel die kompromittering van 'n skryfbare child DC in staat om ESC5-aanvalle uit te voer.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Eksterne Forest Domain - One-Way (Inbound) or bidirectional
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
In hierdie scenario word **jou domain vertrou** deur 'n eksterne een wat jou **onbepaalde permissions** daaroor gee. Jy moet uitvind **watter principals van jou domain watter toegang tot die eksterne domain het** en dan probeer om dit te exploit:


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
In hierdie scenario **jou domein** vertrou sekere **privileges** aan 'n prinsipaal van 'n **ander domein**.

Wanneer 'n **domain is trusted** deur die vertrouende domein, skep die vertroude domein egter 'n **user** met 'n **voorspelbare naam** wat as **password die vertroude paswoord** gebruik. Dit beteken dat dit moontlik is om **'n user van die vertrouende domein te benader om die vertroude een binne te gaan** om dit te enumereer en te probeer meer privileges te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog 'n manier om die vertroude domein te kompromiteer is om 'n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **omgekeerde rigting** van die domeintrust geskep is (wat nie baie algemeen is nie).

Nog 'n manier om die vertroude domein te kompromiteer is om in 'n masjien te wag waar 'n **user from the trusted domain can access** om via **RDP** in te log. Dan kan die attacker kode in die RDP session-proses injekteer en **access the origin domain of the victim** van daar af.\
Verder, as die **victim mounted his hard drive**, kan die attacker vanaf die **RDP session**-proses **backdoors** in die **startup folder of the hard drive** plaas. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigering van misbruik van domeinvertroue

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history-attribuut oor forest trusts benut, word verminder deur SID Filtering, wat standaard geaktiveer is op alle inter-forest trusts. Dit berus op die aanname dat intra-forest trusts veilig is, aangesien die forest eerder as die domain as die sekuriteitsgrens beskou word volgens Microsoft se standpunt.
- Daar is egter 'n vangst: SID filtering kan toepassings en user-toegang ontwrig, wat soms lei tot die deaktivering daarvan.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat users van die twee forests nie outomaties geauthentikeer word nie. In plaas daarvan is eksplisiete toestemmings benodig vir users om toegang tot domeine en bedieners binne die vertrouende domain of forest te kry.
- Dit is belangrik om te let dat hierdie maatreëls nie beskerming bied teen die uitbuiting van die writable Configuration Naming Context (NC) of aanvalle op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algemene Verdedigings

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om op Domain Controllers aan te meld, en dat hul gebruik op ander hosts vermy word.
- **Service Account Privileges**: Dienste moet nie met Domain Admin (DA) privileges uitgevoer word nie om sekuriteit te handhaaf.
- **Temporal Privilege Limitation**: Vir take wat DA privileges vereis, moet die duur daarvan beperk word. Dit kan bereik word met: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementering van deception behels die stel van lokvalle, soos decoy users of computers, met kenmerke soos passwords wat nie verval nie of wat as Trusted for Delegation gemerk is. 'n Gedetaileerde benadering sluit in die skep van users met spesifieke regte of om hulle by hoë-privilegie-groepe te voeg.
- 'n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die implementering van deception-tegnieke is beskikbaar by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdagte aanduidings sluit in atipiese ObjectSID, seldsame aanmeldings, skeppingsdatums, en lae slegte-wagwoord-tellings.
- **General Indicators**: Deur eienskappe van potensiële decoy-objekte met daardie van werklike objekte te vergelyk, kan teenstrydighede onthul word. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke deceptions te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy sessie-ensomering op Domain Controllers om ATA-detectie te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes** sleutels vir ticket-creation help om detectie te ontduik deur nie na NTLM af te gradeer nie.
- **DCSync Attacks**: Voer dit uit vanaf 'n nie-Domain Controller om ATA-detectie te vermy, aangesien direkte uitvoering vanaf 'n Domain Controller waarskuwings sal veroorsaak.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
