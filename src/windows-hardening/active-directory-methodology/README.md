# Active Directory Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n fundamentele tegnologie wat **netwerkadministrateurs** in staat stel om doeltreffend **domeine**, **gebruikers**, en **items** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, wat die organisering van 'n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe** vergemaklik, terwyl **toegangsregte** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **trees**, en **forests**. 'n **Domein** sluit 'n versameling items in, soos **gebruikers** of **toestelle**, wat 'n gemeenskaplike databasis deel. **Trees** is groepe van hierdie domeine wat deur 'n gedeelde struktuur gekoppel is, en 'n **forest** verteenwoordig die versameling van meervoudige trees, onderling verbind deur **trust relationships**, wat die boonste laag van die organisasie-struktuur vorm. Spesifieke **toegangs**- en **kommunikasie-regte** kan op elk van hierdie vlakke aangewys word.

Sleutelbegrippe binne **Active Directory** sluit in:

1. **Directory** – Huisves alle inligting wat verband hou met Active Directory-items.
2. **Object** – Dui entiteite in die directory aan, insluitend **gebruikers**, **groepe**, of **gedeelde gidse**.
3. **Domain** – Dien as 'n houer vir directory-items, met die vermoë vir verskeie domeine om koeksisterend binne 'n **forest** te bestaan, elk met hul eie versameling items.
4. **Tree** – 'n Groepering van domeine wat 'n gemeenskaplike root-domein deel.
5. **Forest** – Die hoogste vlak van organisasie in Active Directory, saamgestel uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvatt 'n reeks dienste wat krities is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domain Services** – Sentrale berging van data en bestuur van interaksies tussen **gebruikers** en **domeine**, insluitend **authentication** en **search** funksionaliteit.
2. **Certificate Services** – Oorsee die skepping, verspreiding, en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-enabled toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on** vermoëns om gebruikers oor veelvuldige webtoepassings in een sessie te verifieer.
5. **Rights Management** – Help om kopieregmateriaal te beskerm deur onbevoegde verspreiding en gebruik te reguleer.
6. **DNS Service** – Krities vir die oplossing van **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om **attack an AD** moet jy die **Kerberos authentication process** baie goed verstaan.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (Geen creds/sessies)

As jy net toegang tot 'n AD-omgewing het maar geen credentials/sessies besit nie, kan jy:

- **Pentest the network:**
- Scan die netwerk, vind masjiene en oop poorte en probeer **exploit vulnerabilities** of **extract credentials** vanaf hulle (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS-enumerasie kan inligting gee oor sleutelbedienaars in die domein soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die Algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit werk nie op moderne Windows weergawes nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB-bediener te enumereer is te vinde hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om LDAP te enumereer is te vinde hier (let **spesifiek op die anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Versamel credentials deur [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Verkry toegang tot 'n gasheer deur [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Trek gebruikersname/names uit interne dokumente, sosialemedia, dienste (hoofsaaklik web) binne die domeinomgewings en ook vanaf publiek beskikbare bronne.
- As jy die volledige name van maatskappy-werkers vind, kan jy verskillende AD **username conventions** probeer (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Die mees algemene konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elkeen), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruikerenumerasie

- **Anonymous SMB/LDAP enum:** Kyk die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **invalid username is requested** sal die bediener reageer met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons toelaat om te bepaal dat die gebruikersnaam ongeldig was. **Valid usernames** sal óf die **TGT in a AS-REP** reaksie uitlok, óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_, wat aandui dat die gebruiker vooraf-verifikasie moet doen.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon) koppelvlak op domain controllers. Die metode roep die `DsrGetDcNameEx2` funksie aan nadat die MS-NRPC koppelvlak gebind is om te kontroleer of die gebruiker of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implementeer hierdie tipe enumerasie. Die navorsing is te vinde [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Bediener**

As jy een van hierdie bedieners in die netwerk vind, kan jy ook **user enumeration** daarteen uitvoer. Byvoorbeeld, jy kan die hulpmiddel [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Jy kan lyste van gebruikersname vind in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) en in hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jy behoort egter die **name van die persone wat by die maatskappy werk** te hê vanuit die recon-stap wat jy vooraf moes gedoen het. Met die voor- en vannaam kan jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige gebruikersname te genereer.

### Knowing one or several usernames

Ok, jy weet dus al ’n geldige username maar het geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As ’n gebruiker **nie die attribuut** _DONT_REQ_PREAUTH_ het nie, kan jy ’n **AS_REP message** vir daardie gebruiker versoek wat data sal bevat wat deur ’n afleiding van die gebruiker se wagwoord geënkripteer is.
- [**Password Spraying**](password-spraying.md): Probeer die mees **algemene passwords** op elkeen van die ontdekte gebruikers; miskien gebruik iemand ’n swak password (hou die password policy in gedagte!).
- Let ook dat jy **OWA servers kan spray** om toegang tot gebruikers se mail servers te probeer kry.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy kan dalk sekere challenge **hashes** bekom om te kraak deur sommige protokolle van die netwerk te **poison**:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

As jy daarin geslaag het om die Active Directory te enumeraat, sal jy **meer e-posadresse en ’n beter begrip van die netwerk** hê. Jy kan dalk NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) afdwing om toegang tot die AD-omgewing te kry.

### Steal NTLM Creds

As jy toegang tot ander PCs of shares kan kry met die **null** of **guest** user, kan jy **lêers plaas** (bv. ’n SCF-lêer) wat, as dit op ’n of ander manier geopen word, ’n **NTLM authentication teen jou sal trigger** sodat jy die **NTLM challenge** kan steel om dit te kraak:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Vir hierdie fase moet jy die **credentials of ’n sessie van ’n geldige domain account** gekompromiseer hê. As jy geldige credentials of ’n shell as ’n domain user het, onthou dat die opsies wat vroeër genoem is steeds opsies is om ander gebruikers te kompromitteer.

Voordat jy met geauthentiseerde enumerasie begin, moet jy weet wat die **Kerberos double hop problem** is.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Om ’n account te kompromitteer is ’n **groot stap om die hele domain te begin kompromitteer**, want jy sal dan in staat wees om met die **Active Directory Enumeration** te begin:

Met betrekking tot [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike kwesbare gebruiker vind, en met betrekking tot [**Password Spraying**](password-spraying.md) kan jy ’n **lys van al die gebruikersname** kry en die password van die gekompromitteerde account, leë wagwoorde en nuwe belowende passwords probeer.

- Jy kan die [**CMD gebruik vir basiese recon**](../basic-cmd-for-pentesters.md#domain-info)
- Jy kan ook [**powershell vir recon**](../basic-powershell-for-pentesters/index.html) gebruik wat meer stealthy sal wees
- Jy kan ook [**use powerview**](../basic-powershell-for-pentesters/powerview.md) om meer gedetaileerde inligting te onttrek
- Nog ’n uitstekende tool vir recon in Active Directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy** nie (afhangend van die collection-metodes wat jy gebruik), maar as jy nie omgee nie, behoort jy dit beslis te probeer. Vind waar gebruikers RDP kan, vind paaie na ander groups, ens.
- **Ander geoutomatiseerde AD enumeration tools is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) kan interessante inligting bevat.
- ’n **GUI tool** wat jy kan gebruik om die directory te enumeraat is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook die LDAP-databasis deursoek met **ldapsearch** om na credentials in velde _userPassword_ & _unixUserPassword_ te kyk, of selfs na _Description_. sien [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- As jy **Linux** gebruik, kan jy die domain ook enumeraat met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook geoutomatiseerde tools probeer soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Dit is baie maklik om al die domain usernames vanaf Windows te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumeration-afdeling klein, dit is die belangrikste deel van alles. Toegang die skakels (hoofsaaklik dié van cmd, powershell, powerview en BloodHound), leer hoe om ’n domain te enumeraat en oefen totdat jy gemaklik voel. Tydens ’n assessment sal dit die sleutel oomblik wees om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS tickets** wat deur services wat aan user accounts gekoppel is gebruik word, en die off-line kraak van hul enkripsie — wat gebaseer is op user passwords.

Meer hieroor in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy sommige credentials bekom het, kan jy kyk of jy toegang tot enige **masjien** het. Hiervoor kan jy **CrackMapExec** gebruik om te probeer koppel op verskeie servers met verskillende protokolle, ooreenkomstig jou port scans.

### Local Privilege Escalation

As jy credentials of ’n sessie as ’n gewone domain user gekompromitteer het en jy het met hierdie user toegang tot enige masjien in die domain, moet jy probeer om plaaslik privileges te eskaleer en na credentials te loot. Dit is omdat slegs met local administrator privileges jy hashes van ander gebruikers in geheue (LSASS) en plaaslik (SAM) kan dump.

Daar is ’n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en ’n [**checklist**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** by die huidige user sal vind wat jou toestemming gee om onverwante resources te betree, maar jy kan dit nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy daarin slaag om die Active Directory te enumereer sal jy **meer e-posse en 'n beter begrip van die netwerk** hê. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Nou dat jy 'n paar basiese inlogbesonderhede het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige en herhalende taak (veral as jy honderde dokumente vind wat jy moet nagaan).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander PCs of shares kan kry, kan jy lêers plaas (soos 'n SCF file) wat, as dit op eniger tyd geopen word, 'n NTLM authentication teen jou sal uitlok sodat jy die **NTLM challenge** kan **steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geauthentiseerde gebruiker in staat gestel om die **domain controller** te kompromitteer.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende tegnieke is 'n gewone domain user nie genoeg nie; jy benodig spesiale voorregte/inlogbesonderhede om hierdie aanvalle uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **local admin**-rekening te kompromitteer deur gebruik te maak van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Dan is dit tyd om al die hashes in geheue en plaaslik uit te trek.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om die gebruiker te **imiteren**.  
Jy moet 'n **tool** gebruik wat die **NTLM authentication** met daardie **hash** sal **uitvoer**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** in **LSASS** **inject** sodat wanneer enige **NTLM authentication** uitgevoer word, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval poog om die **gebruikers NTLM hash te gebruik om Kerberos tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor die NTLM-protokol. Dit kan veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos as authentication protocol toegelaat word**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** aanvalsmethode steel aanvallers 'n gebruiker se **authentication ticket** in plaas van hul wagwoord of hash-waardes. Hierdie gesteelde ticket word dan gebruik om die gebruiker te **imiteren**, en sodoende ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk te verkry.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van 'n **local administrator** het, moet jy probeer om **lokaal aan te meld** op ander **PCs** daarmee.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Neem asseblief kennis dat dit redelik **luidrugtig** is en **LAPS** dit sou **versag**.

### MSSQL Abuse & Trusted Links

Indien 'n gebruiker voorregte het om toegang tot **MSSQL-instances** te hê, kan hy dit gebruik om **opdragte op die MSSQL-gasheer uit te voer** (as dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay attack** uit te voer.\
Verder, as 'n MSSQL-instance deur 'n ander MSSQL-instance vertrou word (database link), en die gebruiker voorregte oor die vertroude databasis het, sal hy in staat wees om **die vertrouensverhouding te gebruik om ook navrae in die ander instance uit te voer**. Hierdie vertroue kan aaneengeskakel word en uiteindelik kan die gebruiker 'n verkeerd gekonfigureerde databasis vind waar hy opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Derdeparty-inventaris- en ontplooiingsuites open dikwels kragtige paaie na credentials en code execution. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die gekompromitteerde gebruiker kan moontlik sekere **belangrike voorregte oor sommige domain objects** hê wat jou later kan toelaat om lateraal te **beweeg** of voorregte te **escalate**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Om 'n **Spool service wat luister** binne die domain te ontdek, kan **misbruik** word om **nuwe credentials te bekom** en **voorregte te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **ander gebruikers** die **gekompromitteerde** masjien **toegang** kry, is dit moontlik om **credentials uit geheue te versamel** en selfs **beacons in hul prosesse in te spuit** om hulle te impersonate.\
Gebruikers kom gewoonlik via RDP op die stelsel, so hier is hoe om 'n paar aanvalle oor derdeparty RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** verskaf 'n stelsel om die **lokale Administrator-wagwoord** op domain-joined computers te bestuur, wat verseker dat dit **gerandomiseer**, uniek en gereeld **verander** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs tot slegs gemagtigde gebruikers beheer. Met genoegsame permisse om hierdie wagwoorde te lees, word pivoting na ander computers moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Die versameling van sertifikate** vanaf die gekompromitteerde masjien kan 'n manier wees om voorregte binne die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Indien **kwesbare templates** gekonfigureer is, is dit moontlik om dit te misbruik om voorregte te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

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

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-voorwerp in Active Directory verseker die sekuriteit van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter misbruik word; as 'n aanvaller die AdminSDHolder se ACL wysig om volle toegang aan 'n gewone gebruiker te gee, kry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie sekuriteitsmaatreël, bedoel om te beskerm, kan dus omgedraai word en ongerechtigde toegang moontlik maak tensy dit noukeurig gemonitor word.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permisse** wat 'n **object** oor 'n **object** het te **stoor**. As jy net 'n **klein verandering** in die **security descriptor** van 'n voorwerp kan maak, kan jy baie interessante voorregte oor daardie voorwerp verkry sonder om lid van 'n bevoorregte groep te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: This is a common setup within the same forest, where a child domain automatically has a two-way transitive trust with its parent domain. Essentially, this means that authentication requests can flow seamlessly between the parent and the child.
- **Cross-link Trusts**: Referred to as "shortcut trusts," these are established between child domains to expedite referral processes. In complex forests, authentication referrals typically have to travel up to the forest root and then down to the target domain. By creating cross-links, the journey is shortened, which is especially beneficial in geographically dispersed environments.
- **External Trusts**: These are set up between different, unrelated domains and are non-transitive by nature. According to [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts are useful for accessing resources in a domain outside of the current forest that isn't connected by a forest trust. Security is bolstered through SID filtering with external trusts.
- **Tree-root Trusts**: These trusts are automatically established between the forest root domain and a newly added tree root. While not commonly encountered, tree-root trusts are important for adding new domain trees to a forest, enabling them to maintain a unique domain name and ensuring two-way transitivity. More information can be found in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: This type of trust is a two-way transitive trust between two forest root domains, also enforcing SID filtering to enhance security measures.
- **MIT Trusts**: These trusts are established with non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts are a bit more specialized and cater to environments requiring integration with Kerberos-based systems outside the Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
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
Ander maniere om enumerate domain trusts:
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
> Jy kan die een wat deur die huidige domein gebruik word sien met:
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

Dit is noodsaaklik om te verstaan hoe die Configuration Naming Context (NC) misbruik kan word. Die Configuration NC dien as 'n sentrale bewaarplek vir konfigurasiedata oor 'n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) in die forest gerepliseer, en skryfbare DCs hou 'n skryfbare kopie van die Configuration NC. Om dit te misbruik, moet mens **SYSTEM privileges op 'n DC** hê, by voorkeur 'n child DC.

**Link GPO to root DC site**

Die Sites-container van die Configuration NC bevat inligting oor die sites van alle domein-aangeslote rekenaars binne die AD-forest. Deur met SYSTEM-privileges op enige DC te werk, kan aanvalleerders GPOs aan die root DC-sites koppel. Hierdie aksie kan die root-domein moontlik kompromitteer deur die beleid wat op hierdie sites toegepas word te manipuleer.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

'n Aanvalsvektor behels die teiken van bevoorregte gMSAs binne die domein. Die KDS Root key, noodsaaklik vir die berekening van gMSA-wagwoorde, is gestoor in die Configuration NC. Met SYSTEM-privileges op enige DC is dit moontlik om by die KDS Root key te kom en die wagwoorde van enige gMSA oor die hele forest te bereken.

Gedetaileerde ontleding en stap-vir-stap leiding kan gevind word in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende gedelegeerde MSA-aanval (BadSuccessor – misbruik van migrasie-attribuutte):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende eksterne navorsing: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Hierdie metode vereis geduld — wag vir die skepping van nuwe bevoorregte AD-objekte. Met SYSTEM-privileges kan 'n aanvaller die AD Schema wysig om enige gebruiker volledige beheer oor alle klasse te gee. Dit kan lei tot ongemagtigde toegang en beheer oor nuut geskepte AD-objekte.

More information is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 kwesbaarheid mik op beheer oor Public Key Infrastructure (PKI)-objekte om 'n sertifikaattemplate te skep wat verifikasie as enige gebruiker binne die forest moontlik maak. Omdat PKI-objekte in die Configuration NC woon, maak die kompromittering van 'n skryfbare child DC die uitvoering van ESC5-aanvalle moontlik.

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
In hierdie scenario **jou domein word vertrou** deur 'n eksterne een wat jou **onbepaalde permissies** daaroor gee. Jy sal moet uitvind **watter principals van jou domein watter toegang tot die eksterne domein het** en dit dan probeer uitbuit:

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
In hierdie scenario **jou domein** vertrou sekere **voorregte** aan ’n prinsipaal van ’n **ander domein**.

Echter, wanneer ’n **domein vertrou** word deur die vertroulike domein, skep die vertroude domein ’n **gebruiker** met ’n **voorspelbare naam** wat as **wagwoord die vertroude wagwoord** gebruik. Dit beteken dat dit moontlik is om ’n **gebruiker van die vertroulike domein te gebruik om toegang tot die vertroude domein te kry** om dit te enumereer en te probeer om meer voorregte te eskaleer:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog ’n manier om die vertroude domein te kompromitteer is om ’n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

Nog ’n manier om die vertroude domein te kompromitteer is om in ’n masjien te wag waar ’n **gebruiker van die vertroude domein toegang kan kry** deur te konnekteer via **RDP**. Die aanvaller kan dan kode in die RDP-sessieproses inject en **toegang tot die oorspronklike domein van die slachtoffer** van daar af kry.\
Bo en behalwe, as die **slachtoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP-sessie** proses **backdoors** in die **opstartmap van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigasie van domeinvertrouensmisbruik

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history attribuut oor forest trusts uitbuit, word verminder deur SID Filtering, wat standaard geaktiveer is op alle inter-forest trusts. Dit berus op die aanname dat intra-forest trusts veilig is, en beskou die forest eerder as die sekuriteitsgrens as die domein, volgens Microsoft se standpunt.
- Daar is egter ’n vangst: SID filtering kan toepassings en gebruikers toegang ontwrig, wat soms tot die deaktivering daarvan lei.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat gebruikers van die twee forests nie outomaties geauthentikeer word nie. In plaas daarvan is eksplisiete toestemmings nodig sodat gebruikers toegang tot domeine en bedieners binne die vertroulike domein of forest kan kry.
- Dit is belangrik om te let dat hierdie maatreëls nie beskerming bied teen die uitbuiting van die writable Configuration Naming Context (NC) of aanvalle op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-gebaseerde AD-misbruik vanaf On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-styl LDAP-primitiwiteite as x64 Beacon Object Files wat heeltemal binne ’n on-host implant (bv. Adaptix C2) loop. Operateurs kompileer die pakket met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon aan. Alle verkeer gebruik die huidige aanmeldsekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met outo sertifikaatvertroue, sodat geen socks-proxies of skyfartefakte benodig word nie.

### Implant-kant LDAP-enumerasie

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` los kort name/OU-paaie op na volle DNs en dump die ooreenstemmende objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` trek arbitrêre attribuutte (insluitend security descriptors) asook die forest/domain metadata vanaf `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` blootlê roasting candidates, delegation settings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP.
- `get-acl` and `get-writable --detailed` ontleed die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/attribute writes), en erfenis te lys, wat onmiddellike teikens vir ACL privilege-escalasie gee.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) maak dit vir die operateur moontlik om nuwe principals of machine accounts te stage waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` hijack targets direk sodra write-property-regte gevind word.
- ACL-focused commands soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD-object in wagwoordresets, groepledebeheer, of DCSync-repliseringsprivilegies sonder om PowerShell/ADSI-artifakte te laat. `remove-*` teenhangers ruim ingespuite ACEs op.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` maak ’n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC toggle) merk dit vir AS-REP roasting sonder om die wagwoord aan te raak.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) skryf `msDS-AllowedToDelegateTo`, UAC flags, of `msDS-AllowedToActOnBehalfOfOtherIdentity` van die beacon oor, wat constrained/unconstrained/RBCD-aanvalsweë moontlik maak en die behoefte aan remote PowerShell of RSAT uitvee.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injects privileged SIDs in ’n beheerde principal se SID history (sien [SID-History Injection](sid-history-injection.md)), wat stilweg toegangserwing oor LDAP/LDAPS verskaf.
- `move-object` verander die DN/OU van rekenaars of gebruikers, wat ’n aanvaller toelaat om bates na OUs te trek waar gedelegeerde regte reeds bestaan voordat hulle `set-password`, `add-groupmember`, of `add-spn` misbruik.
- Nougespekteerde verwyderingskommando’s (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) laat vinnige rollback toe nadat die operateur kredensiële of persistentie verwerf het, en minimaliseer telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Leer meer oor hoe om credentials te beskerm hier.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om by Domain Controllers aan te meld en dat hul gebruik op ander hosts vermy word.
- **Service Account Privileges**: Dienste moet nie met Domain Admin (DA) bevoegdhede uitgevoer word nie om sekuriteit te handhaaf.
- **Temporal Privilege Limitation**: Vir take wat DA-bevoegdhede vereis, moet die duur daarvan beperk word. Dit kan bereik word met: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementering van misleiding behels die opstel van lokvalle, soos lokgebruikers of lokrekenaars, met eienskappe soos wagwoorde wat nooit verstryk nie of gemerk as Trusted for Delegation. ’n Gedetaileerde benadering sluit in die skep van gebruikers met spesifieke regte of die toevoeging daarvan aan hoë-privilegie groepe.
- ’n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van misleidingstegnieke is beskikbaar by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdagte aanduidings sluit in atypiese ObjectSID, seldsame aanmeldings, skeppingsdatums, en lae bad password counts.
- **General Indicators**: Die vergelyking van attribuut‑waardes van potensiële lokobjekte met dié van egte objekke kan inkonsekwenthede openbaar. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleiding te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy sessie-enumerasie op Domain Controllers om ATA-detectie te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes** sleutels vir ticket-skepping help om opsporing te ontduik deur nie te downgrade na NTLM nie.
- **DCSync Attacks**: Dit word aanbeveel om vanaf ’n nie‑Domain Controller uit te voer om ATA-detectie te vermy, aangesien direkte uitvoering vanaf ’n Domain Controller waarskuwings sal veroorsaak.

## Verwysings

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
