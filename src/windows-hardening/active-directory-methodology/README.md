# Active Directory Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** služi kao osnovna tehnologija, omogućavajući **mrežnim administratorima** da efikasno kreiraju i upravljaju **domenima**, **korisnicima** i **objektima** unutar mreže. Dizajnirana je da se skalira, olakšavajući organizaciju velikog broja korisnika u upravljive **grupe** i **podgrupe**, dok kontroliše **prava pristupa** na različitim nivoima.

Struktura **Active Directory** se sastoji od tri osnovna sloja: **domeni**, **drveće** i **šume**. **Domen** obuhvata kolekciju objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Drveće** su grupe ovih domena povezane zajedničkom strukturom, a **šuma** predstavlja kolekciju više drveća, međusobno povezanih kroz **odnos poverenja**, formirajući najviši sloj organizacione strukture. Specifična **prava pristupa** i **komunikacije** mogu se odrediti na svakom od ovih nivoa.

Ključni koncepti unutar **Active Directory** uključuju:

1. **Direktorijum** – Sadrži sve informacije koje se odnose na Active Directory objekte.
2. **Objekat** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe** ili **deljene foldere**.
3. **Domen** – Služi kao kontejner za objekte direktorijuma, sa mogućnošću da više domena koegzistira unutar jedne **šume**, pri čemu svaki održava svoju kolekciju objekata.
4. **Drveće** – Grupa domena koja deli zajednički korenski domen.
5. **Šuma** – Vrhunska organizaciona struktura u Active Directory, sastavljena od više drveća sa **odnosima poverenja** među njima.

**Active Directory Domain Services (AD DS)** obuhvata niz usluga koje su ključne za centralizovano upravljanje i komunikaciju unutar mreže. Ove usluge uključuju:

1. **Domen usluge** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući **autentifikaciju** i **pretragu** funkcionalnosti.
2. **Usluge sertifikata** – Nadgleda kreiranje, distribuciju i upravljanje sigurnim **digitalnim sertifikatima**.
3. **Lagana direktorijska usluga** – Podržava aplikacije omogućene direktorijumom putem **LDAP protokola**.
4. **Usluge federacije direktorijuma** – Pruža mogućnosti **jednostavnog prijavljivanja** za autentifikaciju korisnika preko više web aplikacija u jednoj sesiji.
5. **Upravljanje pravima** – Pomaže u zaštiti autorskih materijala regulisanjem njihove neovlašćene distribucije i korišćenja.
6. **DNS usluga** – Ključna za rešavanje **domen imena**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Definicija Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos autentifikacija**

Da biste naučili kako da **napadnete AD**, potrebno je da **razumete** veoma dobro **proces autentifikacije Kerberos**.\
[**Pročitajte ovu stranicu ako još uvek ne znate kako to funkcioniše.**](kerberos-authentication.md)

## Cheat Sheet

Možete posetiti [https://wadcoms.github.io/](https://wadcoms.github.io) da biste imali brzi pregled komandi koje možete koristiti za enumeraciju/eksploataciju AD.

## Recon Active Directory (Bez kredencijala/sesija)

Ako imate pristup AD okruženju, ali nemate nikakve kredencijale/sesije, možete:

- **Pentestovati mrežu:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **eksploatišete ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [štampači bi mogli biti veoma zanimljivi ciljevi](ad-information-in-printers.md)).
- Enumeracija DNS-a može dati informacije o ključnim serverima u domenu kao što su web, štampači, deljenja, vpn, mediji, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte opštu [**Pentesting metodologiju**](../../generic-methodologies-and-resources/pentesting-methodology.md) da biste pronašli više informacija o tome kako to uraditi.
- **Proverite pristup bez kredencijala i gostujući pristup na smb uslugama** (ovo neće raditi na modernim verzijama Windows-a):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič o tome kako da enumerišete SMB server možete pronaći ovde:

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumeracija Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič o tome kako da enumerišete LDAP možete pronaći ovde (obratite **posebnu pažnju na anonimni pristup**):

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Trovanje mreže**
- Prikupite kredencijale [**imitujući usluge sa Responder-om**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite hostu [**zloupotrebom napada relaya**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Prikupite kredencijale **izlažući** [**lažne UPnP usluge sa evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izvucite korisnička imena/ime iz internih dokumenata, društvenih mreža, usluga (pretežno web) unutar domena i takođe iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih u kompaniji, možete pokušati različite AD **konvencije korisničkih imena** (**[pročitajte ovo](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Najčešće konvencije su: _ImePrezime_, _Ime.Prezime_, _ImePrz_ (3 slova od svakog), _Ime.Prz_, _IPrezime_, _I.Prezime_, _PrezimeIme_, _Prezime.Ime_, _PrezimeI_, _Prezime.I_, 3 _nasumična slova i 3 nasumična broja_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonimna SMB/LDAP enumeracija:** Proverite [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) stranice.
- **Kerbrute enumeracija**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti koristeći **Kerberos grešku** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, omogućavajući nam da utvrdimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili **TGT u AS-REP** odgovoru ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da je korisnik obavezan da izvrši pre-autentifikaciju.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
- **OWA (Outlook Web Access) Server**

Ako pronađete jedan od ovih servera u mreži, možete takođe izvršiti **enumeraciju korisnika protiv njega**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Možete pronaći liste korisničkih imena u [**ovoj github repozitorijumu**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* i ovom ([**statistički verovatna korisnička imena**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebali biste imati **ime ljudi koji rade u kompaniji** iz koraka rekognosciranja koji ste trebali izvršiti pre ovoga. Sa imenom i prezimenom mogli biste koristiti skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalna validna korisnička imena.

### Poznavanje jednog ili više korisničkih imena

U redu, znate da već imate validno korisničko ime, ali nemate lozinke... Pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_, možete **zatražiti AS_REP poruku** za tog korisnika koja će sadržati neke podatke šifrovane derivacijom lozinke korisnika.
- [**Password Spraying**](password-spraying.md): Pokušajmo sa najviše **uobičajenim lozinkama** za svakog od otkrivenih korisnika, možda neki korisnik koristi lošu lozinku (imajte na umu politiku lozinki!).
- Imajte na umu da možete i **spray OWA servere** da pokušate da dobijete pristup korisničkim mail serverima.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Trovanje

Možda ćete moći da **dobijete** neke izazove **hash-eve** da razbijete **trovanjem** nekih protokola **mreže**:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTML Preusmeravanje

Ako ste uspeli da enumerišete aktivni direktorijum, imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da primorate NTML [**preusmeravanje napada**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* da dobijete pristup AD okruženju.

### Ukrasti NTLM Kredencijale

Ako možete **pristupiti drugim računarima ili deljenjima** sa **null ili gost korisnikom**, mogli biste **postaviti datoteke** (kao što je SCF datoteka) koje, ako se nekako pristupe, će **pokrenuti NTML autentifikaciju protiv vas** tako da možete **ukrasti** **NTLM izazov** da ga razbijete:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumeracija Aktivnog Direktorijuma SA kredencijalima/sesijom

Za ovu fazu morate imati **kompromitovane kredencijale ili sesiju validnog domen korisnika.** Ako imate neke validne kredencijale ili shell kao domen korisnik, **trebalo bi da se setite da su opcije date ranije još uvek opcije za kompromitovanje drugih korisnika**.

Pre nego što započnete autentifikovanu enumeraciju, trebali biste znati šta je **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracija

Kompromitovanje naloga je **veliki korak ka kompromitovanju celog domena**, jer ćete moći da započnete **Enumeraciju Aktivnog Direktorijuma:**

Što se tiče [**ASREPRoast**](asreproast.md), sada možete pronaći svakog mogućeg ranjivog korisnika, a što se tiče [**Password Spraying**](password-spraying.md), možete dobiti **listu svih korisničkih imena** i pokušati lozinku kompromitovanog naloga, prazne lozinke i nove obećavajuće lozinke.

- Možete koristiti [**CMD za osnovno rekognosciranje**](../basic-cmd-for-pentesters.md#domain-info)
- Takođe možete koristiti [**powershell za rekognosciranje**](../basic-powershell-for-pentesters/index.html) što će biti diskretnije
- Takođe možete [**koristiti powerview**](../basic-powershell-for-pentesters/powerview.md) da izvučete detaljnije informacije
- Još jedan neverovatan alat za rekognosciranje u aktivnom direktorijumu je [**BloodHound**](bloodhound.md). Nije **veoma diskretan** (u zavisnosti od metoda prikupljanja koje koristite), ali **ako vam to nije važno**, svakako biste trebali probati. Pronađite gde korisnici mogu RDP, pronađite put do drugih grupa, itd.
- **Ostali automatski alati za AD enumeraciju su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS zapisi AD-a**](ad-dns-records.md) jer mogu sadržati zanimljive informacije.
- **Alat sa GUI** koji možete koristiti za enumeraciju direktorijuma je **AdExplorer.exe** iz **SysInternal** Suite.
- Takođe možete pretraživati u LDAP bazi podataka sa **ldapsearch** da tražite kredencijale u poljima _userPassword_ & _unixUserPassword_, ili čak za _Description_. cf. [Lozinka u AD korisničkom komentaru na PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristite **Linux**, takođe možete enumerisati domen koristeći [**pywerview**](https://github.com/the-useless-one/pywerview).
- Takođe možete probati automatske alate kao:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Ekstrakcija svih korisnika domena**

Veoma je lako dobiti sva korisnička imena domena iz Windows-a (`net user /domain`, `Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ovaj deo o enumeraciji izgleda mali, ovo je najvažniji deo svega. Pristupite linkovima (pretežno onima o cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok se ne osećate prijatno. Tokom procene, ovo će biti ključni trenutak da pronađete svoj put do DA ili da odlučite da ništa ne može biti učinjeno.

### Kerberoast

Kerberoasting uključuje dobijanje **TGS karata** koje koriste usluge povezane sa korisničkim nalozima i razbijanje njihove enkripcije—koja se zasniva na korisničkim lozinkama—**offline**.

Više o ovome u:

{{#ref}}
kerberoast.md
{{#endref}}

### Daljinska konekcija (RDP, SSH, FTP, Win-RM, itd.)

Kada dobijete neke kredencijale, možete proveriti da li imate pristup bilo kojoj **mašini**. U tom smislu, mogli biste koristiti **CrackMapExec** da pokušate povezivanje na nekoliko servera sa različitim protokolima, u skladu sa vašim skeniranjem portova.

### Lokalno Eskaliranje Privilegija

Ako ste kompromitovali kredencijale ili sesiju kao običan domen korisnik i imate **pristup** sa ovim korisnikom do **bilo koje mašine u domenu**, trebali biste pokušati da pronađete način da **eskalirate privilegije lokalno i tražite kredencijale**. To je zato što samo sa lokalnim administratorskim privilegijama možete **dumpovati hash-eve drugih korisnika** u memoriji (LSASS) i lokalno (SAM).

Postoji cela stranica u ovoj knjizi o [**lokalnom eskaliranju privilegija u Windows-u**](../windows-local-privilege-escalation/index.html) i [**checklist**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Trenutne Sesijske Karte

Veoma je **malo verovatno** da ćete pronaći **karte** u trenutnom korisniku **koje vam daju dozvolu za pristup** neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Ako ste uspeli da enumerišete aktivni direktorijum, imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da izvršite NTML [**relay napade**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Traži kredencijale u deljenim računarima**

Sada kada imate neke osnovne kredencijale, trebalo bi da proverite da li možete **pronaći** bilo koje **zanimljive datoteke koje se dele unutar AD**. To možete uraditi ručno, ali je to veoma dosadan i ponavljajući zadatak (a još više ako pronađete stotine dokumenata koje treba da proverite).

[**Pratite ovaj link da saznate više o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Ukradi NTLM kredencijale

Ako možete **pristupiti drugim računarima ili deljenjima**, mogli biste **postaviti datoteke** (kao što je SCF datoteka) koje, ako se nekako pristupe, **pokrenu NTML autentifikaciju protiv vas**, tako da možete **ukrasti** **NTLM izazov** da ga razbijete:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućila bilo kojem autentifikovanom korisniku da **kompromituje kontroler domena**.

{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacija privilegija na Active Directory SA privilegovanim kredencijalima/sesiji

**Za sledeće tehnike običan korisnik domena nije dovoljan, potrebne su vam posebne privilegije/kredencijali da biste izvršili ove napade.**

### Ekstrakcija hašova

Nadamo se da ste uspeli da **kompromitujete neki lokalni admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Zatim, vreme je da izvučete sve hašove iz memorije i lokalno.\
[**Pročitajte ovu stranicu o različitim načinima dobijanja hašova.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate haš korisnika**, možete ga koristiti da **imituje**.\
Trebalo bi da koristite neki **alat** koji će **izvršiti** **NTLM autentifikaciju koristeći** taj **haš**, **ili** možete kreirati novu **sessionlogon** i **ubaciti** taj **haš** unutar **LSASS**, tako da kada se izvrši bilo koja **NTLM autentifikacija**, taj **haš će biti korišćen.** Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **iskoristi NTLM haš korisnika za zahtev Kerberos karata**, kao alternativu uobičajenom Pass The Hash preko NTLM protokola. Stoga, ovo bi moglo biti posebno **korisno u mrežama gde je NTLM protokol onemogućen** i gde je samo **Kerberos dozvoljen** kao autentifikacioni protokol.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu autentifikacionu kartu korisnika** umesto njihovih lozinki ili haš vrednosti. Ova ukradena karta se zatim koristi da **imitira korisnika**, stičući neovlašćen pristup resursima i uslugama unutar mreže.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponovna upotreba kredencijala

Ako imate **haš** ili **lozinku** lokalnog **administrator**-a, trebalo bi da pokušate da se **prijavite lokalno** na druge **PC**-e sa njom.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi **LAPS** to **ublažio**.

### MSSQL Abuse & Trusted Links

Ako korisnik ima privilegije za **pristup MSSQL instancama**, mogao bi biti u mogućnosti da ih koristi za **izvršavanje komandi** na MSSQL hostu (ako se pokreće kao SA), **ukrade** NetNTLM **hash** ili čak izvrši **relay** **napad**.\
Takođe, ako je MSSQL instanca poverena (veza baze podataka) od strane druge MSSQL instance. Ako korisnik ima privilegije nad poverenom bazom podataka, moći će da **iskoristi odnos poverenja za izvršavanje upita i u drugoj instanci**. Ove veze se mogu povezivati i u nekom trenutku korisnik bi mogao da pronađe pogrešno konfigurisanu bazu podataka gde može izvršavati komande.\
**Veze između baza podataka funkcionišu čak i preko šuma poverenja.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji objekat računara sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate privilegije domena na računaru, moći ćete da dump-ujete TGT-ove iz memorije svih korisnika koji se prijavljuju na računar.\
Dakle, ako se **Domain Admin prijavi na računar**, moći ćete da dump-ujete njegov TGT i da se pretvarate da je on koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući ograničenoj delegaciji, mogli biste čak i **automatski kompromitovati Print Server** (nadamo se da će to biti DC).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljena "Ograničena delegacija", moći će da **se pretvara u bilo kog korisnika kako bi pristupio nekim uslugama na računaru**.\
Tada, ako **kompromitujete hash** ovog korisnika/računara, moći ćete da **se pretvarate u bilo kog korisnika** (čak i domenskih administratora) kako biste pristupili nekim uslugama.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju na objektu Active Directory-a udaljenog računara omogućava postizanje izvršenja koda sa **povišenim privilegijama**:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### ACLs Abuse

Kompromitovani korisnik mogao bi imati neke **zanimljive privilegije nad nekim objektima domena** koje bi vam mogle omogućiti **lateralno kretanje**/**eskalaciju** privilegija.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Otkriće **Spool servisa koji sluša** unutar domena može se **iskoristiti** za **sticanje novih kredencijala** i **eskalaciju privilegija**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ako **drugi korisnici** **pristupaju** **kompromitovanoj** mašini, moguće je **prikupiti kredencijale iz memorije** i čak **ubaciti beacon-e u njihove procese** da bi se pretvarali da su oni.\
Obično korisnici pristupaju sistemu putem RDP-a, pa ovde imate kako da izvršite nekoliko napada na RDP sesije trećih strana:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** pruža sistem za upravljanje **lokalnom lozinkom administratora** na računarima pridruženim domenu, osiguravajući da je **nasumična**, jedinstvena i često **menjana**. Ove lozinke se čuvaju u Active Directory-u, a pristup se kontroliše putem ACL-a samo za ovlašćene korisnike. Sa dovoljnim dozvolama za pristup ovim lozinkama, prelazak na druge računare postaje moguć.

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Prikupljanje sertifikata** sa kompromitovane mašine može biti način za eskalaciju privilegija unutar okruženja:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ako su **ranjivi šabloni** konfigurisani, moguće ih je iskoristiti za eskalaciju privilegija:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Kada dobijete **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možete **dump-ovati** **domen bazu podataka**: _ntds.dit_.

[**Više informacija o DCSync napadu možete pronaći ovde**](dcsync.md).

[**Više informacija o tome kako ukrasti NTDS.dit možete pronaći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Neke od tehnika o kojima se ranije govorilo mogu se koristiti za postizanje postojanosti.\
Na primer, mogli biste:

- Učiniti korisnike ranjivim na [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Učiniti korisnike ranjivim na [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Dodeliti [**DCSync**](#dcsync) privilegije korisniku

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket napad** kreira **legitimni Ticket Granting Service (TGS) tiket** za specifičnu uslugu koristeći **NTLM hash** (na primer, **hash PC naloga**). Ova metoda se koristi za **pristup privilegijama usluge**.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket napad** uključuje napadača koji dobija pristup **NTLM hash-u krbtgt naloga** u Active Directory (AD) okruženju. Ovaj nalog je poseban jer se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su ključni za autentifikaciju unutar AD mreže.

Kada napadač dobije ovaj hash, može kreirati **TGT-ove** za bilo koji nalog koji izabere (Silver ticket napad).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovi su poput zlatnih karata, ali su krivotvoreni na način koji **zaobilazi uobičajene mehanizme za otkrivanje zlatnih karata.**

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Imati sertifikate naloga ili biti u mogućnosti da ih zatražite** je veoma dobar način da se zadržite u korisničkom nalogu (čak i ako promeni lozinku):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenje sertifikata je takođe moguće za postizanje visoke privilegije unutar domena:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

**AdminSDHolder** objekat u Active Directory-u osigurava bezbednost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardnog **Access Control List (ACL)** na ovim grupama kako bi se sprečile neovlašćene promene. Međutim, ova funkcija se može iskoristiti; ako napadač izmeni ACL AdminSDHolder-a da bi dao potpuni pristup običnom korisniku, taj korisnik dobija opsežnu kontrolu nad svim privilegovanim grupama. Ova mera bezbednosti, koja je zamišljena da zaštiti, može se tako obrnuti, omogućavajući neovlašćen pristup osim ako se ne prati pažljivo.

[**Više informacija o AdminDSHolder grupi ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller (DC)**, postoji **lokalni administratorski** nalog. Dobijanjem administratorskih prava na takvoj mašini, lokalni Administrator hash može se izvući koristeći **mimikatz**. Nakon toga, potrebna je modifikacija registra da bi se **omogućila upotreba ove lozinke**, što omogućava daljinski pristup lokalnom administratorskom nalogu.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dati** neke **posebne dozvole** **korisniku** nad nekim specifičnim objektima domena koje će omogućiti korisniku **eskalaciju privilegija u budućnosti**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Bezbednosni deskriptori** se koriste za **čuvanje** **privilegija** koje **objekat** ima **nad** **objektom**. Ako možete samo **napraviti** **malo promene** u **bezbednosnom deskriptoru** objekta, možete dobiti veoma zanimljive privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da uspostavite **univerzalnu lozinku**, koja omogućava pristup svim domena nalozima.

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Saaznajte šta je SSP (Security Support Provider) ovde.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati svoj **vlastiti SSP** da **prikupite** u **čistom tekstu** **kredencijale** korišćene za pristup mašini.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD i koristi ga za **guranjem atributa** (SIDHistory, SPNs...) na specificiranim objektima **bez** ostavljanja bilo kakvih **logova** u vezi sa **modifikacijama**. Potrebne su **DA** privilegije i biti unutar **root domena**.\
Imajte na umu da ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo razgovarali o tome kako eskalirati privilegije ako imate **dovoljno dozvola za čitanje LAPS lozinki**. Međutim, ove lozinke se takođe mogu koristiti za **održavanje postojanosti**.\
Proverite:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft gleda na **Forest** kao na bezbednosnu granicu. To implicira da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja celog Forest-a**.

### Basic Information

[**Domen poverenja**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. Suštinski, stvara vezu između autentifikacionih sistema dva domena, omogućavajući nesmetano proticanje verifikacija autentifikacije. Kada domeni postave poverenje, razmenjuju i zadržavaju specifične **ključeve** unutar svojih **Domain Controllers (DCs)**, koji su ključni za integritet poverenja.

U tipičnom scenariju, ako korisnik želi da pristupi usluzi u **poverenom domenu**, prvo mora zatražiti poseban tiket poznat kao **inter-realm TGT** od svog domena DC. Ovaj TGT je enkriptovan sa zajedničkim **ključem** na kojem su se oba domena dogovorila. Korisnik zatim predstavlja ovaj TGT **DC-u poverenog domena** da bi dobio servisni tiket (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a poverenog domena, izdaje TGS, dajući korisniku pristup usluzi.

**Koraci**:

1. **Klijentski računar** u **Domenu 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim traži **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domenu 2**.
4. Inter-realm TGT je enkriptovan sa **ključem poverenja** koji je deljen između DC1 i DC2 kao deo dvosmernog poverenja domena.
5. Klijent uzima inter-realm TGT do **Domain Controller-a Domene 2 (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći svoj zajednički ključ poverenja i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domenu 2 kojem klijent želi pristupiti.
7. Na kraju, klijent predstavlja ovaj TGS serveru, koji je enkriptovan sa hash-om naloga servera, da bi dobio pristup usluzi u Domenu 2.

### Different trusts

Važno je primetiti da **poverenje može biti jednostrano ili dvostrano**. U dvostranoj opciji, oba domena će se međusobno poveravati, ali u **jednostranom** odnosu poverenja jedan od domena će biti **povereni**, a drugi **pouzdani** domen. U poslednjem slučaju, **moći ćete da pristupite resursima unutar pouzdanog domena samo iz poverenog**.

Ako Domen A poverava Domenu B, A je pouzdani domen, a B je povereni. Štaviše, u **Domenu A**, ovo bi bilo **Outbound trust**; a u **Domenu B**, ovo bi bilo **Inbound trust**.

**Različiti odnosi poverenja**

- **Parent-Child Trusts**: Ovo je uobičajena postavka unutar iste šume, gde dete domen automatski ima dvosmerno tranzitivno poverenje sa svojim roditeljskim domenom. Suštinski, to znači da zahtevi za autentifikaciju mogu nesmetano teći između roditelja i deteta.
- **Cross-link Trusts**: Poznate kao "prečice poverenja", ove se uspostavljaju između domena dece kako bi se ubrzali procesi upućivanja. U složenim šumama, upućivanja za autentifikaciju obično moraju putovati do korena šume, a zatim do ciljnog domena. Kreiranjem prečica, putovanje se skraćuje, što je posebno korisno u geografski rasprostranjenim okruženjima.
- **External Trusts**: Ove se postavljaju između različitih, nepovezanih domena i po prirodi su netransitivne. Prema [Microsoftovoj dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), eksterni trustovi su korisni za pristup resursima u domenu izvan trenutne šume koji nije povezan šumskim poverenjem. Bezbednost se pojačava filtriranjem SID-a sa spoljnim poverenjima.
- **Tree-root Trusts**: Ova poverenja se automatski uspostavljaju između korenskog domena šume i novododatog korena drveta. Iako se ne susreću često, poverenja korena drveta su važna za dodavanje novih domena drveća u šumu, omogućavajući im da zadrže jedinstveno ime domena i osiguravajući dvosmernu tranzitivnost. Više informacija može se naći u [Microsoftovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ova vrsta poverenja je dvosmerno tranzitivno poverenje između dva korenska domena šume, takođe primenjujući filtriranje SID-a kako bi se poboljšale mere bezbednosti.
- **MIT Trusts**: Ova poverenja se uspostavljaju sa ne-Windows, [RFC4120-kompatibilnim](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT poverenja su malo specijalizovanija i prilagođena su okruženjima koja zahtevaju integraciju sa Kerberos-baziranim sistemima van Windows ekosistema.

#### Other differences in **trusting relationships**

- Odnos poverenja može biti **tranzitivan** (A poverava B, B poverava C, onda A poverava C) ili **netransitivan**.
- Odnos poverenja može biti postavljen kao **bidirekcionalno poverenje** (oba se međusobno poveravaju) ili kao **jednostrano poverenje** (samo jedan od njih poverava drugog).

### Attack Path

1. **Enumerate** odnose poverenja
2. Proverite da li bilo koji **bezbednosni princip** (korisnik/grupa/računar) ima **pristup** resursima **drugog domena**, možda putem ACE unosa ili tako što je u grupama drugog domena. Potražite **odnose preko domena** (poverenje je verovatno stvoreno za ovo).
1. Kerberoast u ovom slučaju bi mogao biti još jedna opcija.
3. **Kompromitujte** **naloge** koji mogu **preći** između domena.

Napadači bi mogli pristupiti resursima u drugom domenu putem tri osnovna mehanizma:

- **Članstvo u lokalnoj grupi**: Principi mogu biti dodati lokalnim grupama na mašinama, kao što je grupa "Administratori" na serveru, što im daje značajnu kontrolu nad tom mašinom.
- **Članstvo u grupi stranog domena**: Principi takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode poverenja i obima grupe.
- **Access Control Lists (ACLs)**: Principi mogu biti navedeni u **ACL**, posebno kao entiteti u **ACEs** unutar **DACL**, pružajući im pristup specifičnim resursima. Za one koji žele dublje da istraže mehaniku ACL-a, DACL-a i ACE-a, beleška pod nazivom “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Child-to-Parent forest privilege escalation
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
> [!WARNING]
> Postoje **2 poverena ključa**, jedan za _Child --> Parent_ i drugi za _Parent_ --> _Child_.\
> Možete koristiti onaj koji koristi trenutna domena sa:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Povećajte privilegije kao Enterprise admin na child/parent domeni zloupotrebom poverenja sa SID-History injekcijom:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Iskoristite pisanu Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može iskoristiti je ključno. Configuration NC služi kao centralni repozitorijum za konfiguracione podatke širom šume u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar šume, pri čemu pisani DC-ovi održavaju pisanu kopiju Configuration NC. Da bi se to iskoristilo, potrebno je imati **SYSTEM privilegije na DC-u**, po mogućstvu na child DC-u.

**Povežite GPO sa root DC lokacijom**

Kontejner lokacija Configuration NC uključuje informacije o svim računarima pridruženim domeni unutar AD šume. Operišući sa SYSTEM privilegijama na bilo kojem DC-u, napadači mogu povezati GPO-ove sa root DC lokacijama. Ova akcija potencijalno kompromituje root domen tako što manipuliše politikama primenjenim na ovim lokacijama.

Za detaljne informacije, može se istražiti istraživanje o [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Kompromitujte bilo koji gMSA u šumi**

Vektor napada uključuje ciljanje privilegovanih gMSA unutar domena. KDS Root ključ, koji je ključan za izračunavanje lozinki gMSA, čuva se unutar Configuration NC. Sa SYSTEM privilegijama na bilo kojem DC-u, moguće je pristupiti KDS Root ključu i izračunati lozinke za bilo koji gMSA širom šume.

Detaljna analiza može se naći u diskusiji o [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Napad na promenu šeme**

Ova metoda zahteva strpljenje, čekajući na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD šemu kako bi dodelio bilo kojem korisniku potpunu kontrolu nad svim klasama. To bi moglo dovesti do neovlašćenog pristupa i kontrole nad novokreiranim AD objektima.

Dalje čitanje je dostupno o [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Od DA do EA sa ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad objektima javne infrastrukture ključeva (PKI) kako bi se kreirala šablon sertifikata koji omogućava autentifikaciju kao bilo koji korisnik unutar šume. Kako PKI objekti borave u Configuration NC, kompromitovanje pisanog child DC-a omogućava izvršenje ESC5 napada.

Više detalja o ovome može se pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS, napadač ima mogućnost da postavi potrebne komponente, kao što je diskutovano u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Eksterna šuma domena - Jednosmerno (ulazno) ili dvostrano
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
U ovom scenariju **vaša domena je poverena** spoljašnjoj, što vam daje **neodređene dozvole** nad njom. Moraćete da pronađete **koji principi vaše domene imaju koji pristup spoljašnjoj domeni** i zatim pokušati da to iskoristite:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Spoljašnja šuma domena - Jednosmerno (izlazno)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
U ovom scenariju **vaša domena** **pouzdava** neke **privilegije** principalu iz **drugih domena**.

Međutim, kada je **domena poverena** od strane poverene domene, poverena domena **kreira korisnika** sa **predvidivim imenom** koji koristi **lozinku poverene lozinke**. Što znači da je moguće **pristupiti korisniku iz poverene domene kako bi se ušlo u poverenu** da bi se enumerisalo i pokušalo da se eskaliraju dodatne privilegije:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način da se kompromituje poverena domena je da se pronađe [**SQL poverena veza**](abusing-ad-mssql.md#mssql-trusted-links) kreirana u **suprotnoj pravcu** od poverenja domena (što nije vrlo uobičajeno).

Još jedan način da se kompromituje poverena domena je da se čeka na mašini na kojoj **korisnik iz poverene domene može pristupiti** da se prijavi putem **RDP**. Tada bi napadač mogao da ubaci kod u proces RDP sesije i **pristupi izvornoj domeni žrtve** odatle.\
Štaviše, ako je **žrtva montirala svoj hard disk**, iz **RDP sesije** proces napadača mogao bi da sačuva **backdoor-e** u **folderu za pokretanje hard diska**. Ova tehnika se naziva **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe poverenja domena

### **SID filtriranje:**

- Rizik od napada koji koriste SID istorijski atribut preko šuma poverenja je umanjen SID filtriranjem, koje je podrazumevano aktivirano na svim međušumskim poverenjima. Ovo se zasniva na pretpostavci da su unutrašnja poverenja šuma sigurna, smatrajući šumu, a ne domenu, kao bezbednosnu granicu prema stavu Microsoft-a.
- Međutim, postoji caka: SID filtriranje može ometati aplikacije i pristup korisnicima, što dovodi do povremene deaktivacije.

### **Selektivna autentifikacija:**

- Za međušumska poverenja, korišćenje selektivne autentifikacije osigurava da korisnici iz dve šume nisu automatski autentifikovani. Umesto toga, potrebne su eksplicitne dozvole za korisnike da pristupe domenama i serverima unutar poverene domene ili šume.
- Važno je napomenuti da ove mere ne štite od eksploatacije zapisivog Konfiguracionog Nazivnog Konteksta (NC) ili napada na račun poverenja.

[**Više informacija o poverenjima domena na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Neke Opšte Odbrane

[**Saznajte više o tome kako zaštititi kredencijale ovde.**](../stealing-credentials/credentials-protections.md)

### **Defanzivne mere za zaštitu kredencijala**

- **Ograničenja za Administratore Domeni**: Preporučuje se da Administratori Domeni mogu da se prijave samo na Kontrolere Domeni, izbegavajući njihovu upotrebu na drugim hostovima.
- **Privilegije Servisnog Računa**: Servisi ne bi trebali da se pokreću sa privilegijama Administratora Domeni (DA) kako bi se održala bezbednost.
- **Temporalno Ograničenje Privilegija**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje bi trebalo da bude ograničeno. Ovo se može postići: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementacija Tehnika Obmane**

- Implementacija obmane uključuje postavljanje zamki, poput mamac korisnika ili računara, sa karakteristikama kao što su lozinke koje ne isteknu ili su označene kao Poverene za Delegaciju. Detaljan pristup uključuje kreiranje korisnika sa specifičnim pravima ili dodavanje u grupe sa visokim privilegijama.
- Praktičan primer uključuje korišćenje alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o implementaciji tehnika obmane može se naći na [Deploy-Deception na GitHub-u](https://github.com/samratashok/Deploy-Deception).

### **Identifikacija Obmane**

- **Za Korisničke Objekte**: Sumnjivi indikatori uključuju atipični ObjectSID, retke prijave, datume kreiranja i nizak broj loših lozinki.
- **Opšti Indikatori**: Upoređivanje atributa potencijalnih mamac objekata sa onima pravih može otkriti neslaganja. Alati poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikaciji takvih obmana.

### **Obilaženje Sistema Detekcije**

- **Obilaženje Microsoft ATA Detekcije**:
- **Enumeracija Korisnika**: Izbegavanje enumeracije sesija na Kontrolerima Domeni kako bi se sprečila ATA detekcija.
- **Impersonacija Tiketa**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže u izbegavanju detekcije ne prebacujući se na NTLM.
- **DCSync Napadi**: Preporučuje se izvršavanje sa non-Domain Controller-a kako bi se izbegla ATA detekcija, jer direktno izvršavanje sa Kontrolera Domeni će pokrenuti upozorenja.

## Reference

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
