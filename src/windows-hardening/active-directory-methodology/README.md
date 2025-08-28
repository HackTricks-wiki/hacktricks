# Active Directory Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n grondliggende tegnologie wat **network administrators** in staat stel om doeltreffend **domains**, **users**, en **objects** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, wat die ordening van 'n groot aantal **users** in hanteerbare **groups** en **subgroups** vergemaklik, terwyl **access rights** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domains**, **trees**, en **forests**. 'n **Domain** beklemtoon 'n versameling van objects, soos **users** of **devices**, wat 'n gemeenskaplike databasis deel. **Trees** is groepe van hierdie domains wat deur 'n gedeelde struktuur verbind is, en 'n **forest** verteenwoordig die versameling van verskeie trees, onderling verbonden deur **trust relationships**, wat die hoogste laag van die organisatoriese struktuur vorm. Spesifieke **access** en **communication rights** kan op elk van hierdie vlakke aangewys word.

Sleutelkonsepte in **Active Directory** sluit in:

1. **Directory** – Berg alle inligting wat betrekking het op Active Directory objects.
2. **Object** – Dui entiteite in die directory aan, insluitend **users**, **groups**, of **shared folders**.
3. **Domain** – Dien as 'n houer vir directory objects, met die vermoë dat meerdere domains binne 'n **forest** kan voortbestaan, elk met hul eie versameling objects.
4. **Tree** – 'n Groepering van domains wat 'n gemeenskaplike root domain deel.
5. **Forest** – Die hoogste vlak van die organisatoriese struktuur in Active Directory, saamgestel uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvatt 'n reeks dienste wat kritiek is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domain Services** – Sentraliseer data berging en bestuur interaksies tussen **users** en **domains**, insluitend **authentication** en **search** funksies.
2. **Certificate Services** – Beheer die skep, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-enabled toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on** vermoëns om users oor meerder webtoepassings in een sessie te autentiseer.
5. **Rights Management** – Help om kopiereg-beskermde materiaal te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS Service** – Krities vir die oplos van **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om **attack an AD** sal jy die **Kerberos authentication process** baie goed moet **understand**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Spiekbrief

Jy kan baie by [https://wadcoms.github.io/](https://wadcoms.github.io) kry om 'n vinnige oorsig te hê van watter commands jy kan gebruik om 'n AD te enumerate/exploit.

> [!WARNING]
> Kerberos-kommunikasie **requires a full qualifid name (FQDN)** om aksies uit te voer. As jy probeer om toegang te kry tot 'n masjien deur die IP-adres, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

As jy net toegang tot 'n AD-omgewing het maar geen credentials/sessies nie, kan jy:

- **Pentest the network:**
- Scan die netwerk, vind masjiene en oop poorte en probeer **exploit vulnerabilities** of **extract credentials** daaruit (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS-ontleding kan inligting gee oor sleutelbedieners in die domain soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die Algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) om meer inligting te kry oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit gaan nie op moderne Windows weergawes werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Verdere gedetailleerde gids oor hoe om 'n SMB-bediener te enum kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om LDAP te enum kan hier gevind word (gee **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Versamel credentials deur [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Kry toegang tot 'n host deur [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Onttrek usernames/names uit interne dokumente, social media, Dienste (hoofsaaklik web) binne die domain-omgewings en ook vanaf openbare bronne.
- As jy die volle name van maatskappy werknemers vind, kan jy verskeie AD **username conventions** probeer ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die mees algemene konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elkeen), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Gereedskap:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **invalid username is requested** sal die bediener antwoord met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons toelaat om te bepaal dat die username ongeldig was. **Valid usernames** sal óf die **TGT in a AS-REP** reaksie oplewer óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_, wat aandui dat die user pre-authentication moet uitvoer.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon) koppelvlak op domain controllers. Die metode roep die `DsrGetDcNameEx2` funksie aan nadat die MS-NRPC koppelvlak gebind is om te kontroleer of die user of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implementeer hierdie tipe enumeration. Die navorsing kan hier gevind word [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie servers in die netwerk vind, kan jy ook **user enumeration against it** uitvoer. Byvoorbeeld, jy kan die tool [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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
> Jy behoort egter die **name van die mense wat by die maatskappy werk** te hê van die recon-stap wat jy voorheen moes uitvoer. Met die voor- en vanname kan jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige gebruikersname te genereer.

### Wanneer jy een of meer gebruikersname ken

Ok, dus jy weet jy het reeds 'n geldige gebruikersnaam maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As 'n gebruiker **nie** die attribuut _DONT_REQ_PREAUTH_ het nie, kan jy 'n AS_REP message vir daardie gebruiker versoek wat data sal bevat wat geënkripteer is deur 'n afleiding van die gebruiker se wagwoord.
- [**Password Spraying**](password-spraying.md): Probeer die mees **algemene wagwoorde** vir elke ontdekte gebruiker; dalk gebruik 'n gebruiker 'n swak wagwoord (hou die wagwoordbeleid in gedagte!).
- Let wel dat jy ook **spray OWA servers** kan gebruik om toegang tot die gebruikers se mail servers te probeer kry.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy kan dalk sekere challenge **hashes** bekom om deur poisoning van sekere netwerkprotokolle te kraak:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

As jy daarin geslaag het om die Active Directory te enumerate sal jy **meer e-posadresse en 'n beter begrip van die netwerk** hê. Jy kan dalk NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) afdwing om toegang tot die AD-omgewing te kry.

### Steal NTLM Creds

As jy ander rekenaars of shares kan betree met die **null** of **guest user**, kan jy lêers plaas (soos 'n SCF file) wat, as dit op een of ander manier geraak word, 'n NTLM-authentisering teen jou sal trigger sodat jy die **NTLM challenge** kan steel om dit te kraak:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Vir hierdie fase moet jy die **credentials of 'n sessie van 'n geldige domeinrekening** gekompromitteer hê. As jy geldige credentials of 'n shell as 'n domeingebruiker het, **onthou dat die opsies hierbo steeds opsies is om ander gebruikers te kompromitteer**.

Voordat jy met die geauthentiseerde enumerasie begin, moet jy weet wat die **Kerberos double hop problem** is.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasie

Die kompromittering van 'n rekening is 'n **groot stap om die hele domein te begin kompromitteer**, omdat jy dan die **Active Directory enumerasie** kan begin:

Met betrekking tot [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike kwesbare gebruiker vind, en met betrekking tot [**Password Spraying**](password-spraying.md) kan jy 'n **lys van alle gebruikersname** kry en die wagwoord van die gekompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde probeer.

- Jy kan die [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) gebruik
- Jy kan ook [**powershell for recon**](../basic-powershell-for-pentesters/index.html) gebruik, wat minder sigbaar (meer stealthy) sal wees
- Jy kan ook [**use powerview**](../basic-powershell-for-pentesters/powerview.md) om meer gedetaileerde inligting te onttrek
- Nog 'n uitstekende hulpmiddel vir recon in 'n Active Directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy** nie (afhangend van die versamelmetodes wat jy gebruik), maar **as dit jou nie pla nie**, moet jy dit beslis probeer. Vind waar gebruikers kan RDP, vind paaie na ander groepe, ens.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Kyk na [**DNS records of the AD**](ad-dns-records.md) aangesien dit interessante inligting kan bevat.
- 'n hulpmiddel met 'n GUI wat jy kan gebruik om die directory te enumerate is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook in die LDAP-databasis soek met **ldapsearch** om na credentials te soek in velde _userPassword_ & _unixUserPassword_, of selfs in _Description_. Sien [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- As jy **Linux** gebruik, kan jy die domein ook deursoek met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook geautomatiseerde gereedskap probeer soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Uittrekking van alle domeingebruikers**

Dit is baie maklik om al die domeingebruikersname vanaf Windows te bekom (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Alhoewel hierdie Enumerasie-afdeling klein lyk, is dit die belangrikste deel van alles. Gaan die skakels deur (veral dié van cmd, powershell, powerview en BloodHound), leer hoe om 'n domein te enumerate en oefen totdat jy gemaklik voel. Tydens 'n assessment, sal dit die sleutel oomblik wees om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS tickets** wat deur dienste gebruik word wat aan gebruikersrekeninge gekoppel is, en die kraking van hul enkripsie — wat gebaseer is op gebruikerswagwoorde — **offline**.

Meer hieroor in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy sekere credentials het, kan jy kyk of jy toegang tot enige **machine** het. Hiervan kan jy **CrackMapExec** gebruik om te probeer verbind met verskeie servers oor verskillende protokolle, ooreenkomstig jou portskanderings.

### Local Privilege Escalation

As jy gekompromitteerde credentials of 'n sessie as 'n gewone domeingebruiker het en jy met hierdie gebruiker toegang tot **enige machine in die domein** het, moet jy probeer om plaaslik jou voorregte te verhoog en kredensiale te plunder. Dit is omdat slegs met plaaslike administrateurvoorregte jy die **hashes van ander gebruikers** in geheue (LSASS) en plaaslik (SAM) kan dump.

Daar is 'n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en 'n [**checklist**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige gebruiker sal vind wat jou toestemming gee om toegang tot onverwagte hulpbronne te kry, maar jy kan dit nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy daarin geslaag het om die Active Directory te enumereer, sal jy **meer e-posadresse en 'n beter begrip van die netwerk** hê. Jy mag daarin slaag om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** af te dwing.**

### Looks for Creds in Computer Shares | SMB Shares

Nou dat jy 'n paar basiese credentials het, moet jy check of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit manueel doen, maar dit is 'n baie vervelige, herhalende taak (veral as jy honderde docs vind wat jy moet nagaan).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander rekenaars of shares kan kry, kan jy **place files** (soos 'n SCF file) wat, as dit op een of ander manier geopen word, t**rigger an NTLM authentication against you** sodat jy **steal** die **NTLM challenge** kan kry om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde gebruiker toegelaat om die **domain controller** te kompromiteer.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende tegnieke is 'n gewone domeingebruiker nie genoeg nie; jy het spesiale voorregte/credentials nodig om hierdie aanvalle uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **local admin** rekening te kompromiteer deur gebruik te maak van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in geheue en plaaslik uit te haal.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om as daardie gebruiker **impersonate**.\
Jy moet 'n **tool** gebruik wat die **NTLM authentication using** daardie **hash** sal uitvoer, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** in **LSASS** inject, sodat wanneer enige **NTLM authentication is performed**, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval poog om die **user NTLM hash te gebruik om Kerberos tickets aan te vra**, as 'n alternatief tot die algemene Pass The Hash oor NTLM-protokol. Dit kan veral **nuttig wees in netwerke waar NTLM-protokol gedeaktiveer is** en slegs **Kerberos as autentiseringsprotokol** toegelaat word.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** aanvalsmethode steel aanvallers 'n gebruiker se autentiseringsticket in plaas van hulle wagwoord of hash-waardes. Hierdie gesteelde ticket word dan gebruik om die gebruiker te **impersonate**, en ongeskikte toegang tot hulpbronne en dienste binne die netwerk te verkry.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van 'n **local administrator** het, moet jy probeer om plaaslik by ander **PCs** daarmee aan te meld.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let wel dat dit nogal **opvallend** is en **LAPS** dit **sal verminder**.

### MSSQL Abuse & Trusted Links

As 'n gebruiker toestemming het om **MSSQL instances te benader**, kan hy dit gebruik om **opdragte uit te voer** op die MSSQL-gasheer (as dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay attack** uit te voer.\
Ook, as 'n MSSQL-instance deur 'n ander MSSQL-instance vertrou word (database link). As die gebruiker regte oor die vertroude databasis het, sal hy die **vertrouensverhouding kan gebruik om ook navrae in die ander instance uit te voer**. Hierdie vertroue kan geketting word en op 'n stadium kan die gebruiker 'n verkeerd gekonfigureerde databasis vind waar hy opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Derdeparty-inventaris- en deployment-suite gee dikwels magtige paaie na credentials en code execution. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer-object vind met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) en jy het domain privileges op die rekenaar, sal jy TGTs uit die geheue van elke gebruiker wat op die rekenaar aanmeld kan dump.\
Dus, as 'n **Domain Admin op die rekenaar aanmeld**, sal jy sy TGT kan dump en hom kan impersonate met [Pass the Ticket](pass-the-ticket.md).\
Dankie aan constrained delegation kan jy selfs **outomaties 'n Print Server kompromitteer** (hopelik sal dit 'n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As 'n gebruiker of rekenaar vir "Constrained Delegation" toegelaat is, sal dit in staat wees om **enige gebruiker te impersonate om toegang tot sekere dienste op 'n rekenaar te kry**.\
Dan, as jy die **hash van hierdie gebruiker/rekenaar kompromitteer**, sal jy in staat wees om **enige gebruiker te impersonate** (selfs domain admins) om toegang tot sommige dienste te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Om **WRITE**-toestemming op 'n Active Directory-objek van 'n veraf rekenaar te hê, maak dit moontlik om code execution met **verhoogde voorregte** te bekom:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die gekompromitteerde gebruiker kan sommige **interessante voorregte oor sekere domain-objekte** hê wat jou toelaat om laterale beweging/voorregte op te gradeer.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Om 'n **Spool service wat luister** binne die domein te ontdek, kan **misbruik** word om **nuwe credentials te bekom** en **voorregte te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **ander gebruikers** die **gekompromitteerde** masjien **gebruik**, is dit moontlik om **credentials uit die geheue te versamel** en selfs **beacons in hul prosesse te inject** om hulle te impersonate.\
Gewoonlik sal gebruikers die stelsel via RDP betree, so hier is hoe om 'n paar aanvalle oor derdeparty RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** verskaf 'n stelsel om die **local Administrator password** op domain-joined rekenaars te bestuur, wat verseker dat dit **gerandomiseer**, uniek en gereeld **verander** word. Hierdie passwords word in Active Directory gestoor en toegang word deur ACLs tot gemagtigde gebruikers beperk. Met voldoende toestemmings om hierdie passwords te lees, word pivoting na ander rekenaars moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Versameling van certificates** van die gekompromitteerde masjien kan 'n manier wees om voorregte in die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **kwesbare templates** gekonfigureer is, is dit moontlik om hulle te misbruik om voorregte te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin** of nog beter **Enterprise Admin** voorregte kry, kan jy die **domeindatabasis** dump: _ntds.dit_.

[**Meer inligting oor DCSync attack is hier te vind**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel is hier te vind**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke vroeër bespreek kan gebruik word vir persistentie.\
Byvoorbeeld kan jy:

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

Die **Silver Ticket attack** skep 'n **legitieme Ticket Granting Service (TGS) ticket** vir 'n spesifieke diens deur die gebruik van die **NTLM hash** (byvoorbeeld, die **hash van die PC account**). Hierdie metode word gebruik om **toegang tot daardie diens se voorregte** te kry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket attack** behels dat 'n aanvaller toegang kry tot die **NTLM hash van die krbtgt account** in 'n Active Directory-omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir verifikasie binne die AD-netwerk.

Sodra die aanvaller hierdie hash bekom, kan hulle **TGTs** skep vir enige rekening wat hulle kies (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hierdie is soos golden tickets wat vervals word op 'n wyse wat **algemene golden ticket-detektiemeganismes omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om certificates van 'n rekening te hê of dit te kan versoek** is 'n baie goeie manier om in die gebruiker se rekening te bly (selfs al verander hy sy wagwoord):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Die gebruik van certificates maak dit ook moontlik om met hoë voorregte binne die domein persistent te bly:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-object in Active Directory verseker die sekuriteit van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter misbruik word; as 'n aanvaller die AdminSDHolder se ACL wysig om volle toegang aan 'n gewone gebruiker te gee, kry daardie gebruiker uitgebreide beheer oor al die bevoorregte groepe. Hierdie sekuriteitsmaatreël, bedoel om te beskerm, kan dus teengesteld werk en ongerechtigde toegang moontlik maak tensy dit noukeurig gemonitor word.

[**Meer inligting oor AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In elke **Domain Controller (DC)** bestaan daar 'n **local administrator**-rekening. Deur adminregte op so 'n masjien te kry, kan die local Administrator-hash met **mimikatz** uitgehaal word. Daarna is 'n registerwysiging nodig om **die gebruik van hierdie wagwoord te aktiveer**, wat remote toegang tot die local Administrator-rekening toelaat.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan **spesiale toestemmings** aan 'n **gebruiker** gee oor spesifieke domein-objekte wat die gebruiker sal toelaat om in die toekoms **voorregte op te gradeer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **toestemmings** wat 'n **objek** oor 'n ander **objek** het, te **stoor**. As jy net 'n **klein verandering** in die **security descriptor** van 'n objek kan maak, kan jy baie interessante voorregte oor daardie objek bekom sonder om 'n lid van 'n bevoorregte groep te hoef te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Wysig **LSASS** in geheue om 'n **universele wagwoord** te stel, wat toegang tot alle domeinrekeninge gee.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Leer wat 'n SSP (Security Support Provider) is hier.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **credentials in clear text te capture** wat gebruik word om die masjien te betree.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **nuwe Domain Controller** in die AD en gebruik dit om **attribure** (SIDHistory, SPNs...) op gespesifiseerde voorwerpe **te push** **sonder** om enige **logs** oor die **wysigings** te laat. Jy **behoort DA**-voorregte te hê en binne die **root domain** te wees.\
Let daarop dat as jy verkeerde data gebruik, baie lelike logs kan voorkom.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vreër het ons bespreek hoe om voorregte te eskaleer as jy **genoeg toestemming het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **persistentie te handhaaf**.\
Kyk:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft sien die **Forest** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domein moontlik kan lei tot die kompromittering van die hele Forest**.

### Basic Information

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domain** in staat stel om hulpbronne in 'n ander **domain** te gebruik. Dit skep 'n skakeling tussen die verifikasiestelsels van die twee domeine, sodat verifikasie-vloei naatloos kan gebeur. Wanneer domeine 'n trust opstel, ruil hulle spesifieke **sleutels** uit en hou dit by hul **Domain Controllers (DCs)**, wat belangrik is vir die trust se integriteit.

In 'n tipiese scenario, as 'n gebruiker 'n diens in 'n **vertroude domein** wil bereik, moet hy eers 'n spesiale kaartjie genaamd 'n **inter-realm TGT** by sy eie domein se DC aansoek doen. Hierdie TGT is geënkripteer met 'n gedeelde **sleutel** wat albei domeine ooreengekom het. Die gebruiker neem dan hierdie TGT na die **DC van die vertroude domein** om 'n dienstitel (**TGS**) te kry. Nadat die vertroude domein se DC die inter-realm TGT suksesvol geverifieer het, gee dit 'n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **client computer** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** by sy **Domain Controller (DC1)** aan te vra.
2. DC1 gee 'n nuwe TGT uit as die kliënt suksesvol geverifieer is.
3. Die kliënt vra dan 'n **inter-realm TGT** van DC1 aan, wat nodig is om hulpbronne in **Domain 2** te bereik.
4. Die inter-realm TGT is geënkripteer met 'n **trust key** wat tussen DC1 en DC2 gedeel word as deel van die tweerigting domain trust.
5. Die kliënt neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, as dit geldig is, gee dit 'n **Ticket Granting Service (TGS)** uit vir die bediener in Domain 2 wat die kliënt wil toegang gee.
7. Uiteindelik bied die kliënt hierdie TGS aan die bediener aan, wat met die bediener se account hash geënkripteer is, om toegang tot die diens in Domain 2 te kry.

### Different trusts

Dit is belangrik om te let dat **'n trust 1-rigting of 2-rigting kan wees**. In die 2-rigting opsie sal beide domeine mekaar vertrou, maar in die **1-rigting** trustverhouding sal een van die domeine die **vertroude** en die ander die **trusting** domein wees. In laasgenoemde geval kan **jy slegs hulpbronne binne die trusting domein vanaf die trusted een** benader.

As Domain A Domain B vertrou, is A die trusting domein en B die trusted een. Verder sal dit in **Domain A** as 'n **Outbound trust** verskyn; en in **Domain B** as 'n **Inbound trust**.

**Verskillende vertrouensverhoudings**

- **Parent-Child Trusts**: Dit is 'n algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n tweerigting transitive trust met sy parent domain het. Dit beteken basies dat verifikasievrae naatloos tussen die parent en child kan vloei.
- **Cross-link Trusts**: Verwys na "shortcut trusts", dit word tussen child domains ingestel om referral-prosesse te versnel. In komplekse forests moet verifikasie-na verwysings tipies tot by die forest root en dan af na die teikendomein reis. Deur cross-links te skep, word die reis verkort, wat veral in geografies verspreide omgewings nuttig is.
- **External Trusts**: Hierdie word tussen verskillende, nie-verwante domeine opgestel en is nie-transitief van aard nie. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig vir toegang tot hulpbronne in 'n domein buite die huidige forest wat nie deur 'n forest trust verbind is nie. Sekuriteit word versterk deur SID filtering met external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties gevestig tussen die forest root domain en 'n nuut-bygevoegde tree root. Alhoewel hulle nie algemeen voorkom nie, is tree-root trusts belangrik vir die toevoeging van nuwe domain trees tot 'n forest, wat hulle toelaat om 'n unieke domeinnaam te behou en twee-weg transitivity te verseker. Meer inligting is beskikbaar in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie tipe trust is 'n tweerigting transitive trust tussen twee forest root domains, wat ook SID filtering gebruik om sekuriteitsmaatreëls te verbeter.
- **MIT Trusts**: Hierdie trusts word met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-domeine gevestig. MIT trusts is meer gespesialiseerd en bedien omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem benodig.

#### Ander verskille in **vertrouensverhoudings**

- 'n trustverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dan vertrou A C) of **nie-transitief**.
- 'n trustverhouding kan opgestel word as **bidirectional trust** (albei vertrou mekaar) of as **one-way trust** (slegs een vertrou die ander).

### Attack Path

1. **Enumereer** die trusting-verhoudings
2. Kyk of enige **security principal** (user/group/computer) **toegang** het tot hulpbronne van die **ander domein**, dalk deur ACE-inskrywings of deur in groepe van die ander domein te wees. Soek na **verhoudings oor domeine heen** (die trust is waarskynlik hiervoor geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Kompromitteer** die **rekeninge** wat deur domeine kan **pivot**.

Aanvallers kan toegang tot hulpbronne in 'n ander domein kry deur drie primêre meganismes:

- **Local Group Membership**: Principals kan by plaaslike groepe op masjiene gevoeg word, soos die “Administrators” groep op 'n bediener, wat hulle beduidende beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook lede wees van groepe binne die buitedomein. Die doeltreffendheid van hierdie metode hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan in 'n **ACL** gespesifiseer wees, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne verleen. Vir diegene wat die meganika van ACLs, DACLs, en ACEs dieper wil ondersoek, is die whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n waardevolle hulpbron.

### Find external users/groups with permissions

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om buite-sekuriteitsbeginsels in die domein te vind. Hierdie sal gebruikers/groepe uit **'n eksterne domein/forest** wees.

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
> Daar is **2 vertroude sleutels**, een vir _Child --> Parent_ en nog een vir _Parent_ --> _Child_.\
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

#### Exploit writeable Configuration NC

Om te verstaan hoe die Configuration Naming Context (NC) uitgebuit kan word, is van kardinale belang. Die Configuration NC dien as 'n sentrale bewaarplek vir konfigurasiedata oor 'n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, met writable DCs wat 'n writable kopie van die Configuration NC handhaaf. Om dit te misbruik, moet mens **SYSTEM privileges on a DC** hê, by voorkeur op 'n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites container sluit inligting in oor alle domain-joined computers se sites binne die AD forest. Deur met SYSTEM privileges op enige DC te werk, kan aanvallers GPOs koppel aan die root DC sites. Hierdie aksie kan potensieel die root domain kompromitteer deur beleid te manipuleer wat op daardie sites toegepas word.

Vir diepgaande inligting kan mens navorsing oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) ondersoek.

**Compromise any gMSA in the forest**

'n Aanvalsvektor behels die teiken van bevoorregte gMSAs binne die domain. Die KDS Root key, noodsaaklik vir die berekening van gMSAs se wagwoorde, word gestoor binne die Configuration NC. Met SYSTEM privileges op enige DC is dit moontlik om by die KDS Root key uit te kom en die wagwoorde vir enige gMSA oor die forest te bereken.

Gedetailleerde ontleding en stapsgewyse riglyne is te vinde in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementêre gedelegeerde MSA-aanval (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende eksterne navorsing: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Hierdie metode vereis geduld en wag vir die skep van nuwe bevoorregte AD-objekte. Met SYSTEM privileges kan 'n aanvaller die AD Schema wysig om enige gebruiker volledige beheer oor alle klasse te gee. Dit kan lei tot ongemagtigde toegang en beheer oor nuutgeskrewe AD-objekte.

Verder leesstof is beskikbaar oor [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 kwesbaarheid mik op beheer oor Public Key Infrastructure (PKI)-objekte om 'n sertifikaattemplate te skep wat autentisering as enige gebruiker binne die forest moontlik maak. Aangesien PKI-objekte in die Configuration NC woon, maak die kompromittering van 'n writable child DC die uitvoering van ESC5-aanvalle moontlik.

Meer besonderhede hieroor is beskikbaar in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's sonder ADCS het die aanvaller die vermoë om die nodige komponente op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In hierdie scenario word jou **domain** deur 'n **external** een vertrou, wat jou **onbepaalde permissies** daaroor gee. Jy sal moet uitvind **watter principals van jou domain watter toegang oor die external domain het** en dan probeer om dit uit te buite:

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
In hierdie scenario **your domain** is **trusting** some **privileges** to principal from a **different domains**.

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

- Die risiko van aanvalle wat die SID history attribuut oor inter-forest trusts misbruik, word verminder deur SID Filtering, wat standaard op alle inter-forest trusts geaktiveer is. Dit berus op die aanname dat intra-forest trusts veilig is, en beskou die forest, eerder as die domain, as die veiligheidsgrens volgens Microsoft se standpunt.
- Daar is egter ’n vangst: SID filtering kan toepassings en gebruikerstoegang ontwrig, wat soms tot deaktivering daarvan lei.

### **Selective Authentication:**

- Vir inter-forest trusts verseker Selective Authentication dat gebruikers van die twee forests nie outomaties geauthentiseer word nie. In plaas daarvan is eksplisiete toestemmings nodig sodat gebruikers toegang tot domains en servers binne die trusting domain of forest kan kry.
- Dit is belangrik om op te let dat hierdie maatreëls nie beskerming bied teen die uitbuiting van die writable Configuration Naming Context (NC) of aanvalle op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Beperkings vir Domain Admins**: Dit word aanbeveel dat Domain Admins slegs op Domain Controllers mag aanmeld, en dat hulle nie op ander hosts gebruik word nie.
- **Service Account Privileges**: Services moet nie met Domain Admin (DA) voorregte uitgevoer word om sekuriteit te handhaaf nie.
- **Tydelike beperking van voorregte**: Vir take wat DA-voorregte benodig, moet hul duur beperk word. Dit kan bereik word met: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementering van misleiding behels die opstel van lokvalle, soos decoy users of computers, met kenmerke soos wagwoorde wat nie verstryk nie of wat as Trusted for Delegation gemerk is. ’n Gedetailleerde benadering sluit die skep van users met spesifieke regte of die toevoeging van hulle tot hoog-privilege groepe in.
- ’n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van misleidingstegnieke is te vinde by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdagte aanwysers sluit abnormale ObjectSID, ongereelde aanmeldings, skeppingsdatums, en lae aantalle slegte wagwoorde in.
- **General Indicators**: Deur attributte van potensiële decoy-objekte met dié van egte objek te vergelyk kan inkonsekwensies opgespoor word. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleiding te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy sessie-enumerasie op Domain Controllers om ATA-detektering te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes** sleutels vir ticket-creation help om deteksie te ontduik deur nie na NTLM af te gradeer nie.
- **DCSync Attacks**: Dit word aanbeveel om vanaf ’n nie-Domain Controller uit te voer om ATA-detektering te vermy, aangesien direkte uitvoering vanaf ’n Domain Controller waarskuwings sal veroorsaak.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
