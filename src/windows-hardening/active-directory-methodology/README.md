# Active Directory Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n fundamentele tegnologie, wat **netwerkadministrateurs** in staat stel om doeltreffend **domeine**, **gebruikers**, en **objekte** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, wat die organisasie van 'n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe** vergemaklik, terwyl **toegangsregte** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **bome**, en **woude**. 'n **domein** omvat 'n versameling van objekte, soos **gebruikers** of **toestelle**, wat 'n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur 'n gedeelde struktuur verbind is, en 'n **woud** verteenwoordig die versameling van verskeie bome, wat deur **vertrouensverhoudings** met mekaar verbind is, wat die boonste laag van die organisatoriese struktuur vorm. Spesifieke **toegang** en **kommunikasie regte** kan op elk van hierdie vlakke aangewys word.

Belangrike konsepte binne **Active Directory** sluit in:

1. **Gids** – Bevat alle inligting rakende Active Directory objekte.
2. **Objek** – Verwys na entiteite binne die gids, insluitend **gebruikers**, **groepe**, of **gedeelde vouers**.
3. **Domein** – Dien as 'n houer vir gidsobjekte, met die vermoë dat verskeie domeine binne 'n **woud** saam kan bestaan, elk met sy eie objekversameling.
4. **Boom** – 'n Groepering van domeine wat 'n gemeenskaplike worteldomein deel.
5. **Woud** – Die hoogtepunt van organisatoriese struktuur in Active Directory, saamgestel uit verskeie bome met **vertrouensverhoudings** tussen hulle.

**Active Directory Domein Dienste (AD DS)** omvat 'n reeks dienste wat krities is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domein Dienste** – Sentraliseer data berging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **verifikasie** en **soek** funksies.
2. **Sertifikaat Dienste** – Toesig oor die skepping, verspreiding, en bestuur van veilige **digitale sertifikate**.
3. **Liggewig Gids Dienste** – Ondersteun gids-geaktiveerde toepassings deur die **LDAP protokol**.
4. **Gids Federasie Dienste** – Verskaf **enkele aanmelding** vermoëns om gebruikers oor verskeie webtoepassings in 'n enkele sessie te verifieer.
5. **Regte Bestuur** – Help om kopiereg materiaal te beskerm deur die ongeoorloofde verspreiding en gebruik daarvan te reguleer.
6. **DNS Diens** – Krities vir die resolusie van **domeinnames**.

Vir 'n meer gedetailleerde verduideliking, kyk: [**TechTerms - Active Directory Definisie**](https://techterms.com/definition/active_directory)

### **Kerberos Verifikasie**

Om te leer hoe om 'n **AD** aan te val, moet jy die **Kerberos verifikasie proses** baie goed **begryp**.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan baie na [https://wadcoms.github.io/](https://wadcoms.github.io) gaan om 'n vinnige oorsig te kry van watter opdragte jy kan uitvoer om 'n AD te evalueer/exploit.

> [!WARNING]
> Kerberos kommunikasie **vereis 'n volle gekwalifiseerde naam (FQDN)** om aksies uit te voer. As jy probeer om toegang tot 'n masjien te verkry deur die IP adres, **sal dit NTLM gebruik en nie kerberos nie**.

## Recon Active Directory (Geen krediete/sessies)

As jy net toegang het tot 'n AD omgewing maar jy het geen krediete/sessies nie, kan jy:

- **Pentest die netwerk:**
- Skandeer die netwerk, vind masjiene en oop poorte en probeer om **kwesbaarhede** te **ontgin** of **krediete** daaruit te **onttrek** (byvoorbeeld, [drukkers kan baie interessante teikens wees](ad-information-in-printers.md)).
- Die opsporing van DNS kan inligting oor sleutelbedieners in die domein gee soos web, drukkers, gedeeltes, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die Algemene [**Pentesting Metodologie**](../../generic-methodologies-and-resources/pentesting-methodology.md) om meer inligting te vind oor hoe om dit te doen.
- **Kontroleer vir null en Gaste toegang op smb dienste** (dit sal nie werk op moderne Windows weergawes nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB bediener te evalueer kan hier gevind word:

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Evalueer Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om LDAP te evalueer kan hier gevind word (gee **spesiale aandag aan die anonieme toegang**):

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Besoedel die netwerk**
- Versamel krediete [**deur dienste te vervang met Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Verkry toegang tot die gasheer deur [**die relay aanval te misbruik**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel krediete **deur** [**valse UPnP dienste met evil-S bloot te stel**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Trek gebruikersname/names uit interne dokumente, sosiale media, dienste (hoofsaaklik web) binne die domein omgewings en ook uit die publiek beskikbaar.
- As jy die volledige name van maatskappywerkers vind, kan jy verskillende AD **gebruikersnaam konvensies** probeer (**[**lees dit**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die mees algemene konvensies is: _NaamVan_, _Naam.Van_, _NamVan_ (3 letters van elkeen), _Nam.Van_, _NVaan_, _N.Van_, _VanNaam_, _Van.Naam_, _VanN_, _Van.N_, 3 _ewekansige letters en 3 ewekansige nommers_ (abc123).
- Gereedskap:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruikersevaluering

- **Anonieme SMB/LDAP enum:** Kontroleer die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **ongeldige gebruikersnaam aangevra** word, sal die bediener reageer met die **Kerberos fout** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons in staat stel om te bepaal dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal of die **TGT in 'n AS-REP** antwoord of die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_ uitlok, wat aandui dat die gebruiker verplig is om vooraf-verifikasie te doen.
- **Geen Verifikasie teen MS-NRPC**: Gebruik auth-level = 1 (Geen verifikasie) teen die MS-NRPC (Netlogon) koppelvlak op domeinbeheerder. Die metode roep die `DsrGetDcNameEx2` funksie aan nadat dit aan die MS-NRPC koppelvlak gekoppel is om te kontroleer of die gebruiker of rekenaar bestaan sonder enige krediete. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) gereedskap implementeer hierdie tipe evaluering. Die navorsing kan [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) gevind word.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Bediening**

As jy een van hierdie bedieners in die netwerk gevind het, kan jy ook **gebruikersenumerasie teen dit** uitvoer. Byvoorbeeld, jy kan die hulpmiddel [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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
> Jy kan lyste van gebruikersname vind in [**hierdie github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jy behoort egter die **name van die mense wat by die maatskappy werk** te hê van die rekonsiliasie stap wat jy voorheen gedoen het. Met die naam en van kan jy die skrip [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige gebruikersname te genereer.

### Om een of verskeie gebruikersname te ken

Goed, so jy weet jy het reeds 'n geldige gebruikersnaam maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As 'n gebruiker **nie** die attribuut _DONT_REQ_PREAUTH_ het nie, kan jy **'n AS_REP boodskap** vir daardie gebruiker aan vra wat sekere data bevat wat deur 'n afgeleide van die gebruiker se wagwoord geënkripteer is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die mees **gewone wagwoorde** met elkeen van die ontdekte gebruikers, dalk gebruik 'n gebruiker 'n slegte wagwoord (hou die wagwoordbeleid in gedagte!).
- Let daarop dat jy ook **OWA bedieners kan spray** om toegang tot die gebruikers se posbedieners te probeer kry.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Vergiftiging

Jy mag in staat wees om **uitdaging **hashes** te **verkry** om **vergiftiging** van sommige protokolle van die **netwerk** te krake:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

As jy daarin geslaag het om die aktiewe gids te enumereer, sal jy **meer e-posse en 'n beter begrip van die netwerk** hê. Jy mag in staat wees om NTLM [**relay-aanvalle**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) te dwing om toegang tot die AD omgewing te kry.

### Steel NTLM Krediete

As jy **ander PC's of gedeeltes** met die **null of gas gebruiker** kan **toegang** kry, kan jy **lêers** (soos 'n SCF-lêer) plaas wat, as dit op een of ander manier toegang verkry, 'n **NTLM-authentisering teen jou** sal **aktiveer** sodat jy die **NTLM-uitdaging** kan **steel** om dit te kraak:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumereer Aktiewe Gids MET krediete/sessie

Vir hierdie fase moet jy **die krediete of 'n sessie van 'n geldige domeinrekening gecompromitteer het.** As jy 'n paar geldige krediete of 'n shell as 'n domein gebruiker het, **moet jy onthou dat die opsies wat voorheen gegee is steeds opsies is om ander gebruikers te kompromitteer**.

Voordat jy met die geverifieerde enumerasie begin, moet jy weet wat die **Kerberos dubbele hop probleem** is.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasie

Om 'n rekening te kompromitteer is 'n **groot stap om die hele domein te begin kompromitteer**, want jy gaan in staat wees om die **Aktiewe Gids Enumerasie te begin:**

Ten opsigte van [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike kwesbare gebruiker vind, en ten opsigte van [**Password Spraying**](password-spraying.md) kan jy 'n **lys van al die gebruikersname** kry en die wagwoord van die gecompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde probeer.

- Jy kan die [**CMD gebruik om 'n basiese rekonsiliasie te doen**](../basic-cmd-for-pentesters.md#domain-info)
- Jy kan ook [**powershell vir rekonsiliasie gebruik**](../basic-powershell-for-pentesters/index.html) wat meer stil sal wees
- Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
- 'n Ander wonderlike hulpmiddel vir rekonsiliasie in 'n aktiewe gids is [**BloodHound**](bloodhound.md). Dit is **nie baie stil nie** (afhangende van die versamelingsmetodes wat jy gebruik), maar **as jy nie omgee** daaroor nie, moet jy dit beslis probeer. Vind waar gebruikers RDP kan, vind pad na ander groepe, ens.
- **Ander geoutomatiseerde AD enumerasie hulpmiddels is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS rekords van die AD**](ad-dns-records.md) aangesien dit dalk interessante inligting kan bevat.
- 'n **hulpmiddel met GUI** wat jy kan gebruik om die gids te enumereer is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook in die LDAP-databasis soek met **ldapsearch** om na krediete in die velde _userPassword_ & _unixUserPassword_, of selfs vir _Description_ te kyk. cf. [Wagwoord in AD Gebruiker kommentaar op PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- As jy **Linux** gebruik, kan jy ook die domein enumereer met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook probeer om geoutomatiseerde hulpmiddels soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle domein gebruikers onttrek**

Dit is baie maklik om al die domein gebruikersname van Windows te verkry (`net user /domain`, `Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Alhoewel hierdie Enumerasie afdeling klein lyk, is dit die belangrikste deel van alles. Toegang die skakels (hoofsaaklik die een van cmd, powershell, powerview en BloodHound), leer hoe om 'n domein te enumereer en oefen totdat jy gemaklik voel. Tydens 'n assessering sal dit die sleutelmoment wees om jou pad na DA te vind of om te besluit dat daar niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS kaartjies** wat deur dienste wat aan gebruikersrekeninge gekoppel is, gebruik word en die kraken van hul enkripsie—wat gebaseer is op gebruikerswagwoorde—**aflyn**.

Meer hieroor in:

{{#ref}}
kerberoast.md
{{#endref}}

### Afgeleë verbinding (RDP, SSH, FTP, Win-RM, ens)

Sodra jy 'n paar krediete verkry het, kan jy kyk of jy toegang tot enige **masjien** het. Hiervoor kan jy **CrackMapExec** gebruik om te probeer om op verskeie bedieners met verskillende protokolle aan te sluit, ooreenkomstig jou poort skanderings.

### Plaaslike Privilege Escalation

As jy gecompromitteerde krediete of 'n sessie as 'n gewone domein gebruiker het en jy het **toegang** met hierdie gebruiker tot **enige masjien in die domein**, moet jy probeer om jou pad te vind om **privileges plaaslik te verhoog en krediete te soek**. Dit is omdat jy slegs met plaaslike administrateurprivileges in staat sal wees om **hashes van ander gebruikers** in geheue (LSASS) en plaaslik (SAM) te **dump**.

Daar is 'n volledige bladsy in hierdie boek oor [**plaaslike privilege escalasie in Windows**](../windows-local-privilege-escalation/index.html) en 'n [**kontrolelys**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Huidige Sessie Kaartjies

Dit is baie **onwaarskynlik** dat jy **kaartjies** in die huidige gebruiker sal vind wat jou toestemming gee om **onverwagte hulpbronne** te benader, maar jy kan kyk:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy daarin geslaag het om die aktiewe gids te evalueer, sal jy **meer e-posse en 'n beter begrip van die netwerk** hê. Jy mag dalk in staat wees om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** af te dwing.**

### Soek na Kredensiale in Rekenaar Aandele | SMB Aandele

Nou dat jy 'n paar basiese kredensiale het, moet jy kyk of jy enige **interessante lêers kan vind wat binne die AD gedeel word**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige herhalende taak (en meer as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om meer te leer oor gereedskap wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steel NTLM Kredensiale

As jy **toegang tot ander rekenaars of aandele** kan kry, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, as dit op een of ander manier toegang verkry, **'n NTLM-authentisering teen jou sal aktiveer**, sodat jy die **NTLM-uitdaging** kan steel om dit te kraak:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde gebruiker toegelaat om die **domeinbeheerder te kompromitteer**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory MET bevoorregte kredensiale/sessie

**Vir die volgende tegnieke is 'n gewone domein gebruiker nie genoeg nie, jy het spesiale voorregte/kredensiale nodig om hierdie aanvalle uit te voer.**

### Hash ekstraksie

Hopelik het jy daarin geslaag om 'n **lokale admin** rekening te **kompromitteer** deur [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitend relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [bevoorregte plaaslike eskalasie](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om **te verteenwoordig**.\
Jy moet 'n **gereedskap** gebruik wat die **NTLM-authentisering met** daardie **hash** sal **uitvoer**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** binne die **LSASS** **inspuit**, sodat wanneer enige **NTLM-authentisering uitgevoer word**, daardie **hash gebruik sal word.** Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval is daarop gemik om **die gebruiker se NTLM-hash te gebruik om Kerberos-tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor NTLM-protokol. Daarom kan dit veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos toegelaat word** as authentikasieprotokol.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** aanvalmetode, **steel aanvallers 'n gebruiker se authentikasieticket** in plaas van hul wagwoord of hash waardes. Hierdie gesteelde kaartjie word dan gebruik om die **gebruiker te verteenwoordig**, wat ongeoorloofde toegang tot hulpbronne en dienste binne 'n netwerk verkry.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Kredensiale Hergebruik

As jy die **hash** of **wagwoord** van 'n **lokale administrateur** het, moet jy probeer om **lokale aanmelding** te doen op ander **PC's** daarmee.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let daarop dat dit baie **luidrugtig** is en **LAPS** dit sou **verlig**.

### MSSQL Misbruik & Vertroude Skakels

As 'n gebruiker bevoegdhede het om **MSSQL instansies te benader**, kan hy dit gebruik om **opdragte** in die MSSQL gasheer uit te voer (as dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay** **aanval** uit te voer.\
Ook, as 'n MSSQL instansie vertrou (databasis skakel) deur 'n ander MSSQL instansie. As die gebruiker bevoegdhede oor die vertroude databasis het, sal hy in staat wees om **die vertrouensverhouding te gebruik om navrae ook in die ander instansie uit te voer**. Hierdie vertroue kan geketting word en op 'n sekere punt mag die gebruiker 'n verkeerd geconfigureerde databasis vind waar hy opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor bosvertroue.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Onbeperkte Afvaardiging

As jy enige rekenaarobjek met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) vind en jy het domein bevoegdhede op die rekenaar, sal jy in staat wees om TGT's uit die geheue van elke gebruiker wat op die rekenaar aanmeld, te dump.\
So, as 'n **Domein Admin op die rekenaar aanmeld**, sal jy in staat wees om sy TGT te dump en hom na te boots met [Pass the Ticket](pass-the-ticket.md).\
Dankie aan beperkte afvaardiging kan jy selfs **automaties 'n Drukbediener kompromitteer** (hopelik sal dit 'n DC wees).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Beperkte Afvaardiging

As 'n gebruiker of rekenaar toegelaat word vir "Beperkte Afvaardiging" sal dit in staat wees om **enige gebruiker na te boots om toegang tot sekere dienste in 'n rekenaar te verkry**.\
Dan, as jy die **hash** van hierdie gebruiker/rekenaar **kompromitteer**, sal jy in staat wees om **enige gebruiker** (selfs domein admins) na te boots om toegang tot sekere dienste te verkry.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Hulpbronne-gebaseerde Beperkte Afvaardiging

Om **WRITE** bevoegdheid op 'n Active Directory objek van 'n afstandlike rekenaar te hê, stel die verkryging van kode-uitvoering met **verhoogde bevoegdhede** moontlik:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Toestemmings/ACLs Misbruik

Die gekompromitteerde gebruiker kan 'n paar **interessante bevoegdhede oor sekere domeinobjekte** hê wat jou kan laat **beweeg** lateraal/**verhoog** bevoegdhede.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Drukspooler diens misbruik

Die ontdekking van 'n **Spool diens wat luister** binne die domein kan **misbruik** word om **nuwe geloofsbriewe** te **verkry** en **bevoegdhede te verhoog**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Derdeparty sessies misbruik

As **ander gebruikers** **toegang** tot die **gekompromitteerde** masjien het, is dit moontlik om **geloofsbriewe uit die geheue te versamel** en selfs **beacons in hul prosesse in te spuit** om hulle na te boots.\
Gewoonlik sal gebruikers die stelsel via RDP benader, so hier is hoe om 'n paar aanvalle oor derdeparty RDP-sessies uit te voer:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied 'n stelsel vir die bestuur van die **lokale Administrateur wagwoord** op domein-verbonden rekenaars, wat verseker dat dit **randomiseer**, uniek is, en gereeld **verander**. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs slegs aan gemagtigde gebruikers beheer. Met voldoende bevoegdhede om toegang tot hierdie wagwoorde te verkry, word dit moontlik om na ander rekenaars te pivot.

{{#ref}}
laps.md
{{#endref}}

### Sertifikaat Diefstal

**Die versameling van sertifikate** van die gekompromitteerde masjien kan 'n manier wees om bevoegdhede binne die omgewing te verhoog:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Sertifikaat Templates Misbruik

As **kwetsbare templates** geconfigureer is, is dit moontlik om hulle te misbruik om bevoegdhede te verhoog:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitatie met hoë bevoegdheid rekening

### Dumping Domein Geloofsbriewe

Sodra jy **Domein Admin** of selfs beter **Enterprise Admin** bevoegdhede kry, kan jy die **domein databasis** dump: _ntds.dit_.

[**Meer inligting oor DCSync aanval kan hier gevind word**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel kan hier gevind word**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistensie

Sommige van die tegnieke wat voorheen bespreek is, kan vir persistensie gebruik word.\
Byvoorbeeld, jy kan:

- Maak gebruikers kwesbaar vir [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Maak gebruikers kwesbaar vir [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Gee [**DCSync**](#dcsync) bevoegdhede aan 'n gebruiker

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silwer Kaart

Die **Silwer Kaart aanval** skep 'n **legitieme Ticket Granting Service (TGS) kaart** vir 'n spesifieke diens deur die **NTLM hash** te gebruik (byvoorbeeld, die **hash van die PC rekening**). Hierdie metode word gebruik om **toegang tot die diensbevoegdhede** te verkry.

{{#ref}}
silver-ticket.md
{{#endref}}

### Goue Kaart

'n **Goue Kaart aanval** behels dat 'n aanvaller toegang verkry tot die **NTLM hash van die krbtgt rekening** in 'n Active Directory (AD) omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir autentisering binne die AD netwerk.

Sodra die aanvaller hierdie hash verkry, kan hulle **TGTs** vir enige rekening wat hulle kies skep (Silwer kaart aanval).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamant Kaart

Hierdie is soos goue kaarte wat op 'n manier vervals is wat **algemene goue kaart opsporingsmeganismes omseil**.

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Sertifikate Rekening Persistensie**

**Om sertifikate van 'n rekening te hê of in staat te wees om hulle aan te vra** is 'n baie goeie manier om in die gebruikersrekening te kan volhard (selfs as hy die wagwoord verander):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Sertifikate Domein Persistensie**

**Om sertifikate te gebruik is ook moontlik om met hoë bevoegdhede binne die domein te volhard:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Groep

Die **AdminSDHolder** objek in Active Directory verseker die sekuriteit van **bevoegde groepe** (soos Domein Admins en Enterprise Admins) deur 'n standaard **Toegang Beheer Lys (ACL)** oor hierdie groepe toe te pas om ongewenste veranderinge te voorkom. Hierdie kenmerk kan egter misbruik word; as 'n aanvaller die AdminSDHolder se ACL aanpas om volle toegang aan 'n gewone gebruiker te gee, kry daardie gebruiker uitgebreide beheer oor al die bevoegde groepe. Hierdie sekuriteitsmaatreël, wat bedoel is om te beskerm, kan dus omgekeerd werk, wat ongewenste toegang toelaat tensy dit noukeurig gemonitor word.

[**Meer inligting oor AdminDSHolder Groep hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Geloofsbriewe

Binne elke **Domein Beheerder (DC)** bestaan 'n **lokale administrateur** rekening. Deur admin regte op so 'n masjien te verkry, kan die lokale Administrateur hash met **mimikatz** uitgehaal word. Daarna is 'n registerwysiging nodig om **die gebruik van hierdie wagwoord** moontlik te maak, wat vir afstandlike toegang tot die lokale Administrateur rekening toelaat.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistensie

Jy kan **spesiale toestemmings** aan 'n **gebruiker** oor sekere spesifieke domeinobjekte gee wat die gebruiker sal laat **bevoegdhede in die toekoms verhoog**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Sekuriteitsbeskrywings

Die **sekuriteitsbeskrywings** word gebruik om die **toestemmings** wat 'n **objek** oor 'n **objek** het, te **stoor**. As jy net 'n **klein verandering** in die **sekuriteitsbeskrywing** van 'n objek kan maak, kan jy baie interessante bevoegdhede oor daardie objek verkry sonder om 'n lid van 'n bevoegde groep te wees.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skelet Sleutel

Verander **LSASS** in geheue om 'n **universale wagwoord** te vestig, wat toegang tot alle domein rekeninge verleen.

{{#ref}}
skeleton-key.md
{{#endref}}

### Pasgemaakte SSP

[Leer wat 'n SSP (Security Support Provider) hier is.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **in duidelike teks** die **geloofsbriewe** wat gebruik word om toegang tot die masjien te verkry, te **vang**.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **nuwe Domein Beheerder** in die AD en gebruik dit om **attribuutte** (SIDHistory, SPNs...) op gespesifiseerde objek te **druk** **sonder** om enige **logs** rakende die **wysigings** te laat. Jy **het DA** bevoegdhede nodig en moet binne die **worteldomein** wees.\
Let daarop dat as jy verkeerde data gebruik, sal daar baie lelike logs verskyn.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistensie

Voorheen het ons bespreek hoe om bevoegdhede te verhoog as jy **genoeg toestemming het om LAPS wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **persistensie te handhaaf**.\
Kyk:

{{#ref}}
laps.md
{{#endref}}

## Bos Bevoegdheid Verhoging - Domein Vertroue

Microsoft beskou die **Bos** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domein potensieel kan lei tot die hele Bos wat gecompromitteer word**.

### Basiese Inligting

'n [**domein vertroue**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domein** in staat stel om toegang tot hulpbronne in 'n ander **domein** te verkry. Dit skep essensieel 'n skakel tussen die autentiseringstelsels van die twee domeine, wat autentisering verifikasies naatloos laat vloei. Wanneer domeine 'n vertroue opstel, ruil hulle spesifieke **sleutels** uit en hou dit binne hul **Domein Beheerders (DCs)**, wat noodsaaklik is vir die integriteit van die vertroue.

In 'n tipiese scenario, as 'n gebruiker 'n diens in 'n **vertroude domein** wil benader, moet hulle eers 'n spesiale kaart aan vra wat bekend staan as 'n **inter-realm TGT** van hul eie domein se DC. Hierdie TGT is versleuteld met 'n gedeelde **sleutel** wat albei domeine ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die vertroude domein** aan om 'n diens kaart (**TGS**) te verkry. Na suksesvolle validasie van die inter-realm TGT deur die vertroude domein se DC, stel dit 'n TGS uit, wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **klient rekenaar** in **Domein 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** van sy **Domein Beheerder (DC1)** aan te vra.
2. DC1 stel 'n nuwe TGT uit as die klient suksesvol geverifieer word.
3. Die klient vra dan 'n **inter-realm TGT** van DC1 aan, wat nodig is om toegang tot hulpbronne in **Domein 2** te verkry.
4. Die inter-realm TGT is versleuteld met 'n **vertrouensleutel** wat tussen DC1 en DC2 as deel van die twee-rigting domein vertroue gedeel word.
5. Die klient neem die inter-realm TGT na **Domein 2 se Domein Beheerder (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde vertrouensleutel en, indien geldig, stel 'n **Ticket Granting Service (TGS)** uit vir die bediener in Domein 2 wat die klient wil benader.
7. Laastens bied die klient hierdie TGS aan die bediener aan, wat versleuteld is met die bediener se rekening hash, om toegang tot die diens in Domein 2 te verkry.

### Verskillende vertroue

Dit is belangrik om op te let dat **'n vertroue 1 rigting of 2 rigtings kan wees**. In die 2 rigtings opsies, sal albei domeine mekaar vertrou, maar in die **1 rigting** vertrouensverhouding sal een van die domeine die **vertroude** en die ander die **vertrouende** domein wees. In die laaste geval, **sal jy slegs in staat wees om toegang tot hulpbronne binne die vertrouende domein van die vertroude een te verkry**.

As Domein A Domein B vertrou, is A die vertrouende domein en B is die vertroude een. Boonop, in **Domein A**, sal dit 'n **Uitgaande vertroue** wees; en in **Domein B**, sal dit 'n **Inkomende vertroue** wees.

**Verskillende vertrouensverhoudings**

- **Ouers-Kind Vertroue**: Dit is 'n algemene opstelling binne dieselfde bos, waar 'n kind domein outomaties 'n twee-rigting transitive vertroue met sy ouerdomein het. Essensieel beteken dit dat autentisering versoeke naatloos tussen die ouer en die kind kan vloei.
- **Kruiskoppel Vertroue**: Bekend as "kortpad vertroue," word hierdie tussen kind domeine gevestig om verwysingsprosesse te versnel. In komplekse bosse moet autentisering verwysings tipies tot by die boswortel reis en dan af na die teiken domein. Deur kruiskoppels te skep, word die reis verkort, wat veral voordelig is in geografies verspreide omgewings.
- **Buitelandse Vertroue**: Hierdie word tussen verskillende, nie-verwante domeine opgestel en is van nature nie-transitief. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), is buitelandse vertroue nuttig om toegang tot hulpbronne in 'n domein buite die huidige bos te verkry wat nie deur 'n bosvertroue verbind is nie. Sekuriteit word versterk deur SID filtrering met buitelandse vertroue.
- **Boomwortel Vertroue**: Hierdie vertroue word outomaties gevestig tussen die bosworteldomein en 'n nuut bygevoegde boomwortel. Alhoewel dit nie algemeen teëgekom word nie, is boomwortel vertroue belangrik vir die byvoeging van nuwe domein bome aan 'n bos, wat hulle in staat stel om 'n unieke domeinnaam te handhaaf en twee-rigting transitiwiteit te verseker. Meer inligting kan in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) gevind word.
- **Bos Vertroue**: Hierdie tipe vertroue is 'n twee-rigting transitive vertroue tussen twee bosworteldomeine, wat ook SID filtrering afdwing om sekuriteitsmaatreëls te verbeter.
- **MIT Vertroue**: Hierdie vertroue word gevestig met nie-Windows, [RFC4120-kompatible](https://tools.ietf.org/html/rfc4120) Kerberos domeine. MIT vertroue is 'n bietjie meer gespesialiseerd en dien omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows ekosisteem vereis.

#### Ander verskille in **vertrouensverhoudings**

- 'n Vertrouensverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dan A vertrou C) of **nie-transitief** wees.
- 'n Vertrouensverhouding kan as **bidireksionele vertroue** (albei vertrou mekaar) of as **een-rigting vertroue** (slegs een van hulle vertrou die ander) opgestel word.

### Aanvalspad

1. **Enumerate** die vertrouensverhoudings
2. Kyk of enige **sekuriteitsbeginsel** (gebruiker/groep/rekenaar) **toegang** tot hulpbronne van die **ander domein** het, dalk deur ACE inskrywings of deur in groepe van die ander domein te wees. Soek na **verhoudings oor domeine** (die vertroue is waarskynlik hiervoor geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Kompromitteer** die **rekeninge** wat deur domeine kan **pivot**.

Aanvallers kan toegang tot hulpbronne in 'n ander domein verkry deur drie primêre meganismes:

- **Plaaslike Groep Lidmaatskap**: Beginsels mag by plaaslike groepe op masjiene gevoeg word, soos die “Administrators” groep op 'n bediener, wat hulle beduidende beheer oor daardie masjien verleen.
- **Buitelandse Domein Groep Lidmaatskap**: Beginsels kan ook lede van groepe binne die buitelandse domein wees. Die doeltreffendheid van hierdie metode hang egter af van die aard van die vertroue en die omvang van die groep.
- **Toegang Beheer Lyste (ACLs)**: Beginsels mag in 'n **ACL** gespesifiseer word, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne bied. Vir diegene wat die meganika van ACLs, DACLs, en ACEs verder wil verken, is die witpapier getiteld “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n onontbeerlike hulpbron.

### Vind eksterne gebruikers/groepe met toestemmings

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om buitelandse sekuriteitsbeginsels in die domein te vind. Hierdie sal gebruikers/groepe van **'n eksterne domein/bos** wees.

Jy kan dit in **Bloodhound** of met powerview nagaan:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Kind-naar-Ouder woud voorregte eskalasie
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
Ander maniere om domein vertroue te tel:
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
> U kan die een wat deur die huidige domein gebruik word, met:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injectie

Verhoog as Enterprise admin na die kind/ouer domein deur die vertroue met SID-History injectie te misbruik:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit skryfbare Konfigurasie NC

Om te verstaan hoe die Konfigurasie Naam Konteks (NC) misbruik kan word, is van kardinale belang. Die Konfigurasie NC dien as 'n sentrale berging vir konfigurasie data oor 'n woud in Active Directory (AD) omgewings. Hierdie data word na elke Domein Beheerder (DC) binne die woud gerepliceer, met skryfbare DC's wat 'n skryfbare kopie van die Konfigurasie NC handhaaf. Om dit te misbruik, moet 'n mens **SYSTEM regte op 'n DC** hê, verkieslik 'n kind DC.

**Koppel GPO aan wortel DC webwerf**

Die Konfigurasie NC se Sites hou inligting oor alle domein-verbonden rekenaars se webwerwe binne die AD woud. Deur met SYSTEM regte op enige DC te werk, kan aanvallers GPO's aan die wortel DC webwerwe koppel. Hierdie aksie kan die worteldomein potensieel in gevaar stel deur beleid wat op hierdie webwerwe toegepas word, te manipuleer.

Vir diepgaande inligting kan 'n mens navorsing oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) verken.

**Kompromitteer enige gMSA in die woud**

'n Aanvalsvector behels die teiken van bevoorregte gMSA's binne die domein. Die KDS Root sleutel, wat noodsaaklik is vir die berekening van gMSA se wagwoorde, word binne die Konfigurasie NC gestoor. Met SYSTEM regte op enige DC, is dit moontlik om toegang tot die KDS Root sleutel te verkry en die wagwoorde vir enige gMSA oor die woud te bereken.

Gedetailleerde analise en stap-vir-stap leiding kan gevind word in:

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Addisionele eksterne navorsing: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema verandering aanval**

Hierdie metode vereis geduld, terwyl daar gewag word vir die skepping van nuwe bevoorregte AD-objekte. Met SYSTEM regte kan 'n aanvaller die AD Schema wysig om enige gebruiker volledige beheer oor alle klasse te verleen. Dit kan lei tot ongemagtigde toegang en beheer oor nuutgeskepte AD-objekte.

Verdiepende leesstof is beskikbaar oor [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Van DA na EA met ADCS ESC5**

Die ADCS ESC5 kwesbaarheid teiken beheer oor Publieke Sleutel Infrastruktuur (PKI) objekte om 'n sertifikaat sjabloon te skep wat autentisering as enige gebruiker binne die woud moontlik maak. Aangesien PKI objekte in die Konfigurasie NC woon, stel die kompromittering van 'n skryfbare kind DC die uitvoering van ESC5-aanvalle in staat.

Meer besonderhede hieroor kan gelees word in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's waar ADCS ontbreek, het die aanvaller die vermoë om die nodige komponente op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Eksterne Woud Domein - Eenrigting (Inkomend) of bidireksioneel
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
In hierdie scenario **word jou domein vertrou** deur 'n eksterne een wat jou **onbepaalde regte** oor dit gee. Jy sal moet uitvind **watter principals van jou domein watter toegang oor die eksterne domein het** en dan probeer om dit te benut:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterne Bosdomein - Eenrigting (Uitgaand)
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
In hierdie scenario **jou domein** is **vertrou** op sommige **privileges** aan 'n hoof van 'n **ander domeine**.

Echter, wanneer 'n **domein vertrou** word deur die vertrouende domein, skep die vertroude domein **n gebruiker** met 'n **voorspelbare naam** wat as **wagwoord die vertroude wagwoord** gebruik. Dit beteken dat dit moontlik is om **toegang te verkry tot 'n gebruiker van die vertrouende domein om binne die vertroude een te kom** om dit te evalueer en te probeer om meer privileges te verhoog:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

'n Ander manier om die vertroude domein te kompromitteer, is om 'n [**SQL vertroude skakel**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

'n Ander manier om die vertroude domein te kompromitteer, is om te wag op 'n masjien waar 'n **gebruiker van die vertroude domein toegang kan verkry** om in te log via **RDP**. Dan kan die aanvaller kode in die RDP-sessieproses inspuit en **toegang verkry tot die oorspronklike domein van die slagoffer** van daar.\
Boonop, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller **terugdeure** in die **opstartgids van die hardeskyf** stoor vanuit die **RDP-sessie** proses. Hierdie tegniek word **RDPInception** genoem.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigering van domeinvertrou misbruik

### **SID Filtrering:**

- Die risiko van aanvalle wat die SID-geskiedenisattribuut oor woudvertroue benut, word gemitigeer deur SID Filtrering, wat standaard geaktiveer is op alle inter-woudvertroue. Dit is gebaseer op die aanname dat intra-woudvertroue veilig is, met die woud, eerder as die domein, as die sekuriteitsgrens volgens Microsoft se standpunt.
- Daar is egter 'n vang: SID filtrering kan toepassings en gebruikers toegang ontwrig, wat lei tot die af en toe deaktivering daarvan.

### **Selektiewe Verifikasie:**

- Vir inter-woudvertroue, verseker die gebruik van Selektiewe Verifikasie dat gebruikers van die twee woude nie outomaties geverifieer word nie. In plaas daarvan is eksplisiete toestemmings nodig vir gebruikers om toegang te verkry tot domeine en bedieners binne die vertrouende domein of woud.
- Dit is belangrik om te noem dat hierdie maatreëls nie beskerm teen die uitbuiting van die skryfbare Konfigurasie Naam Konteks (NC) of aanvalle op die vertrou rekening nie.

[**Meer inligting oor domeinvertroue in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Sommige Algemene Verdedigings

[**Leer meer oor hoe om kredensiale te beskerm hier.**](../stealing-credentials/credentials-protections.md)

### **Defensiewe Maatreëls vir Kredensiaalbeskerming**

- **Domein Administrateurs Beperkings**: Dit word aanbeveel dat Domein Administrateurs slegs toegelaat word om in te log op Domein Beheerders, en dat hulle nie op ander gasheer gebruik word nie.
- **Diensrekening Privileges**: Dienste moet nie met Domein Administrateur (DA) privileges gedra word nie om sekuriteit te handhaaf.
- **Tydelike Privilege Beperking**: Vir take wat DA privileges vereis, moet die duur daarvan beperk word. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementering van Misleidingstegnieke**

- Die implementering van misleiding behels die opstelling van lokvalle, soos lokgebruikers of rekenaars, met kenmerke soos wagwoorde wat nie verval nie of as Vertrou vir Delegasie gemerk is. 'n Gedetailleerde benadering sluit in om gebruikers met spesifieke regte te skep of hulle aan hoëprivilege groepe toe te voeg.
- 'n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die implementering van misleidingstegnieke kan gevind word by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van Misleiding**

- **Vir Gebruikerobjekte**: Verdagte aanduiders sluit ongewone ObjectSID, ongewone aanmeldings, skeppingsdatums, en lae slegte wagwoord tellings in.
- **Algemene Aanduiders**: Die vergelyking van eienskappe van potensiële lokobjekte met dié van werklike kan inkonsekwensies onthul. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleidings te identifiseer.

### **Om Ontdekkingsisteme te Omseil**

- **Microsoft ATA Ontdekking Omseiling**:
- **Gebruiker Enumerasie**: Vermy sessie-evaluasie op Domein Beheerders om ATA ontdekking te voorkom.
- **Tiket Vervalsing**: Die gebruik van **aes** sleutels vir tiket skepping help om ontdekking te ontduik deur nie na NTLM af te gradeer nie.
- **DCSync Aanvalle**: Dit word aanbeveel om van 'n nie-Domein Beheerder uit te voer om ATA ontdekking te vermy, aangesien direkte uitvoering vanaf 'n Domein Beheerder waarskuwings sal aktiveer.

## Verwysings

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
