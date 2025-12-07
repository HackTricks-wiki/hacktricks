# Metodologija Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** služi kao osnovna tehnologija koja omogućava **mrežnim administratorima** efikasno kreiranje i upravljanje **domenima**, **korisnicima** i **objektima** unutar mreže. Dizajniran je za skaliranje, olakšavajući organizovanje velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **pristupnih prava** na različitim nivoima.

Struktura **Active Directory** se sastoji od tri glavna sloja: **domeni**, **stabla** i **šume**. **Domen** obuhvata kolekciju objekata, poput **korisnika** ili **uređaja**, koji dele zajedničku bazu podataka. **Stabla** su grupe ovih domena povezane zajedničkom strukturom, dok **šuma** predstavlja skup više stabala, međusobno povezanih kroz **trust relationships**, formirajući najviši nivo organizacione strukture. Specifična **pristupna** i **komunikaciona prava** mogu se dodeliti na svakom od ovih nivoa.

Ključni pojmovi unutar **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije koje se odnose na Active Directory objekte.
2. **Object** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe**, ili **deljene foldere**.
3. **Domain** – Služi kao kontejner za objekte direktorijuma, pri čemu više domena može koegzistirati unutar jedne **šume**, svaki sa sopstvenom kolekcijom objekata.
4. **Tree** – Grupisanje domena koja dele zajednički root domen.
5. **Forest** – Najviši nivo organizacione strukture u Active Directory, sastavljen od više stabala sa **trust relationships** među njima.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa koji su kritični za centralizovano upravljanje i komunikaciju unutar mreže. Ti servisi obuhvataju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući **authentication** i **search** funkcionalnosti.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje sigurnim **digitalnim sertifikatima**.
3. **Lightweight Directory Services** – Podržava aplikacije koje koriste direktorijum putem **LDAP protocol**.
4. **Directory Federation Services** – Pruža **single-sign-on** mogućnosti za autentikaciju korisnika preko više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti autorskih materijala regulisanjem njihove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Ključan za rešavanje **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ako imate pristup AD okruženju, ali nemate nikakve kredencijale/sesije, možete:

- **Pentest the network:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **eksploatišete ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracija DNS-a može dati informacije o ključnim serverima u domenu kao što su web, printers, shares, vpn, media, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako to uraditi.
- **Check for null and Guest access on smb services** (ovo neće raditi na modernim verzijama Windows-a):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič o tome kako enumerisati SMB server možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič o tome kako enumerisati LDAP možete pronaći ovde (obrati **posebnu pažnju na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sakupite kredencijale **imajući ulogu servisa uz Responder** (gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md))
- Pristupite hostu **abusing the relay attack** ([**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack))
- Sakupite kredencijale **izlažući** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Ekstrahujte korisnička imena/ime i prezime iz internih dokumenata, društvenih mreža, servisa (pretežno web) unutar domen okruženja, kao i iz javno dostupnih izvora.
- Ako nađete puna imena zaposlenih u kompaniji, možete pokušati različite konvencije AD **username**-a (**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Proverite [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) stranice.
- **Kerbrute enum**: Kada se zahteva **nevažeće korisničko ime**, server će odgovoriti koristeći **Kerberos error** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili **TGT in a AS-REP** odgovor ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da korisnik mora izvršiti pre-authentication.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controller-ima. Metoda poziva funkciju `DsrGetDcNameEx2` nakon bindovanja MS-NRPC interfejsa da proveri da li korisnik ili računar postoji bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje se može naći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako na mreži pronađete jedan od ovih servera, možete takođe izvršiti **user enumeration against it**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Možete naći liste korisničkih imena u [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i u ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena ljudi koji rade u kompaniji** iz recon koraka koji ste ranije izvršili. Sa imenom i prezimenom možete koristiti skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalna validna korisnička imena.

### Knowing one or several usernames

Ok, dakle znate da već imate važeće korisničko ime ali nemate lozinke... Onda pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_ možete **request a AS_REP message** za tog korisnika koja će sadržati podatke enkriptovane derivatom lozinke tog korisnika.
- [**Password Spraying**](password-spraying.md): Pokušajte najčešće **passwords** za svakog od otkrivenih korisnika, možda neki korisnik koristi lošu lozinku (imajte na umu password policy!).
- Imajte u vidu da takođe možete **spray OWA servers** da pokušate da dođete do pristupa korisničkim mail serverima.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **dohvatite** neke challenge **hashes** za crack-ovanje tako što ćete poison-ovati neke protokole u **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više email-ova i bolji uvid u network**. Možda ćete moći da primorate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) da biste dobili pristup AD env.

### Steal NTLM Creds

Ako možete da **pristupite drugim PC-jevima ili share-ovima** koristeći **null or guest user** možete **postaviti fajlove** (npr. SCF file) koji, ako se nekako pristupi, će t**rigger an NTLM authentication against you** tako da možete **steal** NTLM challenge i crack-ovati ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Za ovu fazu morate biti kompromitovali credentials ili session validnog domain account-a. Ako imate neke validne kredencijale ili shell kao domain user, **imajte na umu da su opcije date ranije i dalje dostupne za kompromitovanje drugih korisnika**.

Pre nego što počnete authenticated enumeration trebalo bi da znate šta je Kerberos double hop problem.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitovanje naloga je **velik korak ka kompromitovanju celog domena**, zato što ćete moći da započnete **Active Directory Enumeration:**

Što se tiče [**ASREPRoast**](asreproast.md) sada možete pronaći sve moguće ranjive korisnike, i kad je reč o [**Password Spraying**](password-spraying.md) možete dobiti **listu svih korisničkih imena** i pokušati password kompromitovanog naloga, prazne lozinke i nove obećavajuće lozinke.

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

Vrlo je lako dobiti sva korisnička imena domena iz Windows-a (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ovaj deo Enumeration deluje kratak, ovo je najvažniji deo svega. Otvorite linkove (posebno one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok ne budete sigurni. Tokom procene, ovo će biti ključni trenutak da pronađete put do DA ili da odlučite da se ništa ne može uraditi.

### Kerberoast

Kerberoasting podrazumeva dobijanje **TGS tickets** koje koriste servisi vezani za korisničke naloge i crack-ovanje njihove enkripcije — koja je zasnovana na korisničkim lozinkama — **offline**.

Više o ovome u:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Kada dobijete neke kredencijale možete proveriti da li imate pristup nekom **machine**. U tu svrhu možete koristiti **CrackMapExec** da pokušate povezivanje na više servera putem različitih protokola, u skladu sa vašim port scan-ovima.

### Local Privilege Escalation

Ako ste kompromitovali kredencijale ili session kao običan domain user i imate **access** ovim user-om na **bilo koju mašinu u domenu**, trebalo bi da pokušate da pronađete način za **escalate privileges locally i loot-ovanje kredencijala**. Samo sa lokalnim administrator privilegijama bićete u mogućnosti da **dump hashes drugih korisnika** iz memorije (LSASS) i lokalno (SAM).

Postoji kompletna stranica u ovoj knjizi o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) i [**checklist**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Veoma je **malo verovatno** da ćete pronaći **tickets** u trenutnom korisniku koji vam daju dozvolu za pristup neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da naterate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Traži Creds in Computer Shares | SMB Shares

Sada kada imate neke osnovne credentials treba da proverite da li možete da **nađete** bilo koje **interesantne fajlove koji se dele unutar AD**. Možete to uraditi ručno, ali je to veoma dosadan i repetitivan zadatak (a još gore ako nađete stotine dokumenata koje treba proveriti).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete da **pristupite drugim PCs ili shares** možete **postaviti fajlove** (kao SCF file) koji, ako se nekako pristupi, će **okinuti NTLM authentication against you** tako da možete **steal** the **NTLM challenge** da ga crack-ujete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala bilo kom autentifikovanom korisniku da **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Za sledeće tehnike običan domain user nije dovoljan — potrebne su vam posebne privileges/credentials da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **kompromitujete neki local admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga koristiti da se predstavite kao on.\
Treba da koristite neki **tool** koji će **izvršiti NTLM authentication koristeći** taj **hash**, **ili** možete da kreirate novu **sessionlogon** i **inject**-ujete taj **hash** unutar **LSASS**, tako da kada se izvrši bilo koja **NTLM authentication**, taj **hash će biti korišćen.** Poslednja opcija je ono što radi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **koristi korisnikov NTLM hash za zahtev Kerberos tickets**, kao alternativa uobičajenom Pass The Hash preko NTLM protokola. Stoga, ovo može biti posebno **korisno u mrežama gde je NTLM protocol onemogućen** i gde je dozvoljen samo **Kerberos** kao autentifikacioni protokol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **steal a user's authentication ticket** umesto njihove lozinke ili hash vrednosti. Ovaj ukradeni ticket se potom koristi da se **predstavljaju kao korisnik**, dobijajući neautorizovan pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **password** od **local administrator**-a, trebalo bi da pokušate da se **login locally** na druge **PCs** koristeći ga.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **zvučno** i da bi **LAPS** to **ublažio**.

### MSSQL zloupotreba i pouzdane veze

Ako korisnik ima privilegije da **pristupi MSSQL instancama**, mogao bi ih iskoristiti za **izvršavanje komandi** na MSSQL hostu (ako se pokreće kao SA), **ukrasti** NetNTLM **hash** ili čak izvesti **relay** **attack**.\
Takođe, ako je MSSQL instanca poverena (database link) od strane druge MSSQL instance. Ako korisnik ima privilegije nad poverenom bazom, biće u mogućnosti da **iskoristi poverenje da izvršava upite i u drugoj instanci**. Ova poverenja se mogu lančati i u nekom trenutku korisnik može pronaći pogrešno konfigurisan bazu gde može izvršavati komande.\
**Veze između baza rade čak i preko forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zloupotreba IT asset/deployment platformi

Third-party inventory and deployment suites često izlažu moćne puteve do kredencijala i izvršenja koda. Vidi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domen privilegije na tom računaru, moći ćete da dump-ujete TGTs iz memorije svakog korisnika koji se prijavi na računar.\
Dakle, ako se **Domain Admin prijavi na računar**, moći ćete da dump-ujete njegov TGT i da ga impersonirate koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation mogli biste čak **automatski kompromitovati Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljeno "Constrained Delegation" biće u stanju da **impersonira bilo kog korisnika da pristupi nekim servisima na računaru**.\
Zatim, ako **compromise the hash** ovog korisnika/računara bićete u mogućnosti da **impersonate any user** (čak i domain admins) da pristupite nekim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju na Active Directory objektu udaljenog računara omogućava postizanje izvršenja koda sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Kompromitovani korisnik može imati neke **zanimljive privilegije nad određenim domen objektima** koje bi vam omogućile da **move** lateralno/**escalate** privilegije.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Otkrivanje **Spool servisa koji osluškuje** unutar domena može se **zloupotrebiti** da se **dobiju novi kredencijali** i **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ako **drugi korisnici** **pristupaju** **kompromitovanom** računaru, moguće je **prikupljati kredencijale iz memorije** pa čak i **inject beacons u njihove procese** kako biste ih impersonirali.\
Obično korisnici pristupaju sistemu preko RDP-a, pa ovde imate kako izvesti par napada nad third party RDP sesijama:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **lokalnim Administrator lozinkama** na domain-joined računarima, osiguravajući da su **nasumične**, jedinstvene i često **menjane**. Ove lozinke se čuvaju u Active Directory i pristup kontrolišu ACL-ovi samo za autorizovane korisnike. Sa dovoljnim privilegijama za pristup ovim lozinkama, postaje moguće pivot-ovati na druge računare.


{{#ref}}
laps.md
{{#endref}}

### Krađa sertifikata

**Prikupljanje sertifikata** sa kompromitovanog računara može biti način za eskalaciju privilegija unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Zloupotreba Certificate Templates

Ako su konfigurirani **ranjivi templates** moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation sa nalogom visokih privilegija

### Dump-ovanje domen kredencijala

Kada dobijete **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možete **dump-ovati** **domain bazu podataka**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kao persistencija

Neke od tehnika diskutovanih ranije mogu se koristiti za persistenciju.\
Na primer, možete:

- Učiniti korisnike ranjivim na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Učiniti korisnike ranjivim na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Dodeliti [**DCSync**](#dcsync) privilegije korisniku

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

The **Silver Ticket attack** kreira **legitiman Ticket Granting Service (TGS) ticket** za specifičan servis koristeći **NTLM hash** (na primer, **hash PC account-a**). Ova metoda se koristi za **pristup privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** podrazumeva da napadač dobije pristup **NTLM hash-u krbtgt account-a** u Active Directory (AD) okruženju. Ovaj account je poseban jer se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su suštinski za autentikaciju unutar AD mreže.

Kada napadač dobije ovaj hash, može kreirati **TGTs** za bilo koji account koji izabere (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su kao golden tickets, falsifikovani na način koji **zaobilazi uobičajene mehanizme detekcije golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Imati sertifikate naloga ili biti u mogućnosti da ih zahtevaš** je veoma dobar način da se održi persistencija u korisničkom nalogu (čak i ako on promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenjem sertifikata takođe je moguće održavati persistenciju sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory osigurava sigurnost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardnog **Access Control List (ACL)** na ove grupe kako bi se sprečile neautorizovane izmene. Međutim, ova funkcionalnost može biti zloupotrebljena; ako napadač izmeni AdminSDHolder-ov ACL da dodeli puna prava običnom korisniku, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova bezbednosna mera, koja je namenjena zaštiti, može tako postati vektor za neovlašćen pristup ukoliko nije pažljivo nadgledana.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller (DC)** postoji lokalni administrator nalog. Dobijanjem admin prava na takvoj mašini, lokalni Administrator hash se može izvući korišćenjem **mimikatz**. Nakon toga je potrebna izmena registra da bi se **omogućila upotreba ove lozinke**, dozvoljavajući daljinski pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** neke **specijalne privilegije** korisniku nad određenim domen objektima koje će tom korisniku omogućiti da **eskalira privilegije u budućnosti**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **permisija** koje **objekat** ima **nad** nekim drugim objektom. Ako možete samo **napraviti** malu izmenu u **security descriptor-u** objekta, možete dobiti vrlo interesantne privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da biste uspostavili **univerzalnu lozinku**, koja daje pristup svim domen nalozima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati sopstveni **SSP** da **uhvatite** u **clear text** **kredencijale** korišćene za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD i koristi ga da **push-uje atribute** (SIDHistory, SPNs...) na specificirane objekte **bez** ostavljanja **logova** u vezi sa **izmjenama**. Potrebne su DA privilegije i da budete unutar **root domain-a**.\
Napomena: ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo govorili o tome kako eskalirati privilegije ako imate **dovoljne dozvole za čitanje LAPS lozinki**. Međutim, ove lozinke se takođe mogu koristiti za **održavanje persistencije**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft smatra **Forest** sigurnosnom granicom. To implicira da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja celog Foresta**.

### Osnovne informacije

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. U suštini, on uspostavlja vezu između autentikacionih sistema ta dva domena, dozvoljavajući da validacije autentikacije teku bez prekida. Kada domeni uspostave trust, oni razmenjuju i čuvaju specifične **ključeve** unutar svojih **Domain Controller-a (DCs)**, koji su ključni za integritet tog poverenja.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domain-u**, on prvo mora da zatraži specijalni tiket poznat kao **inter-realm TGT** od DC-a svog domena. Ovaj TGT je enkriptovan sa zajedničkim **kljućem** koji su oba domena usaglasila. Korisnik tada predstavlja ovaj TGT **DC-u trusted domain-a** kako bi dobio servis tiket (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a trusted domena, on izdaje TGS, dajući korisniku pristup servisu.

**Koraci**:

1. Klijent računar u **Domain 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan sa **trust key** koji dele DC1 i DC2 kao deo two-way domain trust.
5. Klijent odnosi inter-realm TGT na **Domain 2's Domain Controller (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći svoj shared trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kojem klijent želi da pristupi.
7. Na kraju, klijent predaje ovaj TGS serveru, koji je enkriptovan sa hash-om serverovog naloga, da bi dobio pristup servisu u Domain 2.

### Različita trusts

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U two-way opciji, oba domena će jedno drugo verovati, ali u **one-way** trust relaciji jedan od domena će biti **trusted**, a drugi **trusting** domen. U poslednjem slučaju, **moći ćete pristupiti resursima unutar trusting domena sa trusted domena**.

Ako Domain A trust-uje Domain B, A je trusting domain a B je trusted. Štaviše, u **Domain A**, ovo bi bio **Outbound trust**; i u **Domain B**, ovo bi bio **Inbound trust**.

**Različiti tipovi trusting relacija**

- **Parent-Child Trusts**: Ovo je uobičajena konfiguracija unutar istog foresta, gde child domain automatski ima two-way transitive trust sa svojim parent domenom. U suštini, ovo znači da autentikacioni zahtevi mogu da teku između parent-a i child-a bez prekida.
- **Cross-link Trusts**: Poznati kao "shortcut trusts", uspostavljaju se između child domena kako bi se ubrzao proces referisanja. U kompleksnim forestima, autentikacioni zahtevi obično moraju putovati do forest root-a pa potom naniže do ciljanog domena. Kreiranjem cross-linkova, putovanje se skraćuje, što je posebno korisno u geografski rasprostranjenim okruženjima.
- **External Trusts**: Postavljaju se između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domenu izvan trenutnog foresta koji nije povezan forest trust-om. Bezbednost se pojačava SID filtering-om sa external trusts.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novo dodatog tree root-a. Iako se retko sreću, tree-root trusts su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveni domain name i osiguravaju two-way transitivity. Više informacija može se pronaći u [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ova vrsta trust-a je two-way transitive trust između dva forest root domena, takođe primenjujući SID filtering radi poboljšanja bezbednosti.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trusts su nešto specijalizovaniji i služe za integraciju sa Kerberos-based sistemima van Windows ekosistema.

#### Druge razlike u **trusting relationships**

- Trust relationship može biti i **transitive** (A trust B, B trust C, onda A trust C) ili **non-transitive**.
- Trust relationship može biti podešen kao **bidirectional trust** (oba se međusobno veruju) ili kao **one-way trust** (samo jedan veruje drugom).

### Attack Path

1. **Enumeriši** trusting relacije
2. Proveri da li neki **security principal** (user/group/computer) ima **pristup** resursima **drugog domena**, možda kroz ACE unose ili članstvom u grupama drugog domena. Traži **relacije preko domena** (trust je verovatno kreiran zbog toga).
1. kerberoast u ovom slučaju može biti još jedna opcija.
3. **Kompromituj** **naloge** koji mogu **pivot-ovati** kroz domene.

Napadači mogu pristupiti resursima u drugom domenu kroz tri glavna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao npr. “Administrators” grupu na serveru, dajući im značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti navedeni u **ACL-u**, posebno kao entiteti u **ACE-ovima** unutar **DACL-a**, dajući im pristup specifičnim resursima. Za one koji žele dublje da istraže mehaniku ACL-ova, DACL-ova i ACE-ova, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Pronađi eksterne korisnike/grupe sa permisijama

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domenu. Ovo će biti user/group iz **eksternog domena/foresta**.

Možete ovo proveriti u **Bloodhound** ili koristeći powerview:
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
Drugi načini za enumerate domain trusts:
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
> Postoje **2 trusted keys**, jedna za _Child --> Parent_ i druga za _Parent_ --> _Child_.\
> Možete dobiti onu koju koristi trenutni domen pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalirajte na Enterprise admin u child/parent domenu zloupotrebom trusta pomoću SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Eksploatisanje writeable Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može eksploatisati je ključno. Configuration NC služi kao centralni repozitorij konfiguracionih podataka kroz forest u Active Directory (AD) okruženjima. Ti podaci se repliciraju na svaki Domain Controller (DC) unutar foresta, pri čemu writable DCs održavaju writable kopiju Configuration NC. Za eksploataciju, potrebno je imati **SYSTEM privilegije na DC-u**, poželjno na child DC-u.

**Link GPO to root DC site**

Sites kontejner Configuration NC-a uključuje informacije o lokacijama (sites) svih računara pridruženih domenu unutar AD foresta. Radeći sa SYSTEM privilegijama na bilo kojem DC-u, napadači mogu linkovati GPO-e na root DC sites. Ova akcija potencijalno kompromituje root domen manipulisanjem politikama koje se primenjuju na te site-ove.

Za detaljnije informacije možete istražiti rad na [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan vektor napada uključuje ciljanje privilegovanih gMSA unutar domena. KDS Root key, neophodan za izračunavanje lozinki gMSA, čuva se unutar Configuration NC. Sa SYSTEM privilegijama na bilo kojem DC-u moguće je pristupiti KDS Root key-ju i izračunati lozinke za bilo koji gMSA kroz forest.

Detaljna analiza i korak-po-korak uputstva nalaze se u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarni delegated MSA napad (BadSuccessor – zloupotreba migration atributa):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatna spoljašnja istraživanja: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ova metoda zahteva strpljenje — čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema da bi dao bilo kom korisniku potpuni control nad svim klasama. To može dovesti do neovlašćenog pristupa i kontrole nad novokreiranim AD objektima.

Za dalje čitanje pogledajte [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad PKI objektima kako bi se kreirao certificate template koji omogućava autentifikaciju kao bilo koji korisnik unutar foresta. Pošto PKI objekti borave u Configuration NC, kompromitovanje writable child DC-a omogućava izvođenje ESC5 napada.

Više detalja može se pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS, napadač ima mogućnost da postavi potrebne komponente, kao što je diskutovano u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
U ovom scenariju **vaš domen je poveren** od strane eksternog domena, što vam daje **neodređena dopuštenja** nad njim. Moraćete da utvrdite **koji principals vašeg domena imaju koji pristup eksternom domenu** i zatim pokušate da to iskoristite:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni Forest Domain - Jednosmerno (Outbound)
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
U ovom scenariju **vaš domen** **dodeljuje** neke **privilegije** principalu iz **drugog domena**.

Međutim, kada je **domen poveren** od strane domena koji veruje, povereni domen **kreira korisnika** sa **predvidivim imenom** koji kao **lozinku koristi poverenu lozinku**. To znači da je moguće **pristupiti korisniku iz domena koji veruje da biste ušli u povereni domen** kako biste ga enumerisali i pokušali da eskalirate više privilegija:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Još jedan način da se kompromituje povereni domen je pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnoj smeru** poverenja domena (što nije često).

Drugi način da se kompromituje povereni domen je čekati na mašini na koju se može prijaviti **korisnik iz poverenog domena** putem **RDP**. Zatim napadač može ubaciti kod u proces **RDP session** i odatle **pristupiti izvornom domenu žrtve**.\
Nadalje, ako je **žrtva montirala svoj hard disk**, iz procesa **RDP session** napadač može ostaviti **backdoors** u **startup folder of the hard drive**. Ova tehnika se naziva **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigacija zloupotrebe poverenja domena

### **SID Filtering:**

- Rizik napada koji koriste atribut SID History preko poverenja između šuma ublažava SID Filtering, koji je po defaultu aktiviran na svim međušumskim poverenjima. Ovo se zasniva na pretpostavci da su intra-šumska poverenja bezbedna, smatrajući šumu, a ne domen, granicom bezbednosti, u skladu sa Microsoftovim stanovištem.
- Međutim, postoji problem: SID filtering može ometati aplikacije i pristup korisnika, što dovodi do povremenog isključivanja te opcije.

### **Selective Authentication:**

- Za međušumska poverenja, upotreba Selective Authentication osigurava da korisnici iz dve šume nisu automatski autentifikovani. Umesto toga, potrebna su eksplicitna odobrenja da bi korisnici imali pristup domenima i serverima unutar domena ili šume koja veruje.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja writable Configuration Naming Context (NC) ili od napada na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponovo implementira bloodyAD-style LDAP primitive kao x64 Beacon Object Files koje rade u potpunosti unutar on-host implanta (npr., Adaptix C2). Operateri kompajliraju paket sa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitaju `ldap.axs`, i zatim pozovu `ldap <subcommand>` iz beacona. Sav saobraćaj koristi trenutni kontekst bezbednosti prijave preko LDAP (389) sa signing/sealing ili LDAPS (636) uz automatsko poveravanje sertifikata, tako da nisu potrebni socks proxyji ili artefakti na disku.

### LDAP enumeracija sa strane implanta

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` rešavaju kratka imena/OU putanje u pune DN-ove i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` vade proizvoljne atribute (uključujući security descriptors) plus metadata šume/domena iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` otkrivaju roasting candidates, delegation settings, i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskriptore direktno iz LDAP-a.
- `get-acl` and `get-writable --detailed` parsiraju DACL da navedu trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) i nasleđivanje, dajući neposredne ciljeve za ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) омогућавају оператору да постави нове принципале или machine accounts где год постоје OU права. `add-groupmember`, `set-password`, `add-attribute`, и `set-attribute` директно преузимају циљеве чим су пронађена `write-property` права.
- ACL-фокусиране команде као што су `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, и `add-dcsync` преводе WriteDACL/WriteOwner на било који AD објекат у ресетовање лозинки, контролу чланства у групи или DCSync репликацијске привилегије без остављања PowerShell/ADSI артефаката. `remove-*` пари очисте убациване ACE-ове.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` одмах чине kompromitovanog корисника Kerberoastable; `add-asreproastable` (UAC toggle) означава корисника за AS-REP roasting без додиривања лозинке.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) преписују `msDS-AllowedToDelegateTo`, UAC флаге, или `msDS-AllowedToActOnBehalfOfOtherIdentity` из beacona, омогућавајући constrained/unconstrained/RBCD путеве напада и елиминишући потребу за remote PowerShell или RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` убризгава привилеговане SIDs у SID history контролисаног принципала (видети [SID-History Injection](sid-history-injection.md)), пружајући прикривено наслеђивање приступа у потпуности преко LDAP/LDAPS.
- `move-object` мења DN/OU рачунара или корисника, дозвољавајући нападачу да превуче ресурсе у OU где већ постоје делегирана права пре злоупотребе `set-password`, `add-groupmember`, или `add-spn`.
- Строго ограничене команде за уклањање (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, итд.) дозвољавају брз rollback након што оператор убере креденцијале или постави перзистенцију, минимизирајући телеметрију.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Saznajte više o tome како zaštititi kredencijale ovde.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Препоручује се да Domain Admins имају дозволу за пријаву само на Domain Controller-има, избегавајући њихово коришћење на другим хостовима.
- **Service Account Privileges**: Servisi не би требало да се покрећу са Domain Admin (DA) привилегијама ради одржавања сигурности.
- **Temporal Privilege Limitation**: За задатке који захтевају DA привилегије, треба ограничити трајање. Ово се може остварити командом: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Имплементација deception-а подразумева постављање замки, као што су decoy корисници или рачунари, са карактеристикама као што су passwords that do not expire или означени као Trusted for Delegation. Детаљан приступ укључује креирање корисника са специфичним правима или додавање у високо-привилеговане групе.
- Практичан пример укључује коришћење алата као што је: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Више о deploy-у deception техника може се наћи на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Сумњиви индикатори укључују нетипичан ObjectSID, ретке prijave, датуме креирања и низак број погрешних лозинки.
- **General Indicators**: Упоређивање атрибута потенцијалних decoy објеката са истинским може открити неконзистентности. Алати попут [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) могу помоћи у идентификацији таквих дејстава.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Избегавање session enumeration на Domain Controller-има како би се спречило ATA детектовање.
- **Ticket Impersonation**: Коришћење **aes** кључева за креирање тикета помаже у бекству од детекције тако што се не деградује на NTLM.
- **DCSync Attacks**: Покретање са non-Domain Controller-а ради избегавања ATA детекције је препоручљиво, јер директно покретање са Domain Controller-а покреће аларме.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
