# Active Directory Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja omogućava **mrežnim administratorima** da efikasno kreiraju i upravljaju **domenima**, **korisnicima** i **objektima** unutar mreže. Dizajniran je da bude skalabilan, omogućavajući organizovanje velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura **Active Directory** se sastoji od tri primarna sloja: **domeni**, **stabla** i **šume**. **Domen** obuhvata skup objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** su grupe ovih domena povezane zajedničkom hijerarhijom, a **šuma** predstavlja kolekciju više stabala međusobno povezanih putem **trust relationships**, formirajući najviši nivo organizacione strukture. Specifična **prava pristupa** i **komunikaciona prava** mogu se dodeliti na svakom od ovih nivoa.

Ključni koncepti unutar **Active Directory** uključuju:

1. **Direktorijum** – Sadrži sve informacije vezane za Active Directory objekte.
2. **Objekat** – Označava entitete u direktorijumu, uključujući **korisnike**, **grupe**, ili **deljene foldere**.
3. **Domen** – Služi kao kontejner za direktorijumske objekte; moguće je imati više domena unutar **šume**, svaki sa sopstvenom kolekcijom objekata.
4. **Stablo** – Grupisanje domena koja dele zajednički root domen.
5. **Šuma** – Najviši nivo organizacione strukture u Active Directory, sastavljena od više stabala sa međusobnim **trust relationships**.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa kritičnih za centralizovano upravljanje i komunikaciju unutar mreže. Ti servisi uključuju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući **autentifikaciju** i **pretragu**.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje sigurnim **digitalnim sertifikatima**.
3. **Lightweight Directory Services** – Podržava aplikacije koje koriste direktorijum preko **LDAP protocol**.
4. **Directory Federation Services** – Pruža **single-sign-on** mogućnosti za autentifikaciju korisnika preko više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti autorskih materijala regulisanjem neovlašćene distribucije i upotrebe.
6. **DNS Service** – Ključno za rezoluciju **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Da biste naučili kako da napadnete AD, morate zaista dobro razumeti **Kerberos autentifikacioni proces**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Kratki pregled

Možete posetiti [https://wadcoms.github.io/](https://wadcoms.github.io) da brzo vidite koje komande možete pokrenuti za enumeraciju/eksploataciju AD.

> [!WARNING]
> Kerberos komunikacija **zahteva punu kvalifikovanu domenu (FQDN)** za izvođenje akcija. Ako pokušate da pristupite mašini preko IP adrese, **koristiće NTLM umesto Kerberos-a**.

## Recon Active Directory (No creds/sessions)

Ako imate pristup AD okruženju ali nemate kredencijale/sesije, možete:

- **Pentest the network:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **eksploatišete ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracija DNS-a može dati informacije o ključnim serverima u domenu kao što su web, printers, shares, vpn, media, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako ovo raditi.
- **Proverite null i Guest pristup na smb servisima** (ovo neće raditi na modernim verzijama Windows-a):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič za enumeraciju SMB servera možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič za enumeraciju LDAP-a možete naći ovde (obratite **posebnu pažnju na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sakupite kredencijale [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite hostu [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sakupite kredencijale **eksponiranjem** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Ekstrahujte korisnička imena/ime i prezime iz internih dokumenata, društvenih mreža, servisa (pre svega web) unutar domen okruženja, kao i iz javno dostupnih izvora.
- Ako pronađete kompletna imena zaposlenih, možete pokušati različite AD **username conventions** (**[read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Proverite [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) stranice.
- **Kerbrute enum**: Kada se zahteva nevažeće korisničko ime server će odgovoriti koristeći **Kerberos error** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da ustanovimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili **TGT u AS-REP** odgovoru ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da je korisnik obavezan da izvrši pre-autentifikaciju.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controller-ima. Metod poziva funkciju `DsrGetDcNameEx2` nakon binding-a na MS-NRPC interfejs da proveri da li korisnik ili računar postoji bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovaj tip enumeracije. Istraživanje se može pronaći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ако сте пронашли један од ових сервера у мрежи, такође можете извршити **user enumeration** против њега. На пример, можете користити алат [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Možete pronaći liste usernames u [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  i u ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena osoba koje rade u kompaniji** iz recon koraka koji ste trebali izvršiti ranije. Sa imenom i prezimenom možete koristiti skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalno validne usernames.

### Knowing one or several usernames

U redu, dakle već imate validan username ali nemate passwords... Probajte:

- [**ASREPRoast**](asreproast.md): Ako user **nema** atribut _DONT_REQ_PREAUTH_ možete **request-ovati AS_REP message** za tog user-a koji će sadržati neke podatke šifrovane derivatom user password-a.
- [**Password Spraying**](password-spraying.md): Pokušajte najčešće passwords sa svakim od otkrivenih users, možda neki user koristi loš password (imajte na umu password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **obtain** neke challenge hashes koje možete crack-ovati trovanjem (poisoning) nekih protokola u network-u:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerate-ujete Active Directory imaćete **više emails i bolje razumevanje network-a**. Možda ćete moći da forsirate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) da biste dobili pristup AD env.

### Steal NTLM Creds

Ako možete pristupiti drugim PCs ili shares koristeći **null or guest user** možete **place files** (npr. SCF file) koji, ako budu accessed, će **trigger-ovati NTLM authentication protiv vas** tako da možete **steal-ovati** **NTLM challenge** da ga crack-ujete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Za ovu fazu morate imati **compromised credentials ili session valjanog domain account-a.** Ako imate valid credentials ili shell kao domain user, **zapamtite da opcije date ranije i dalje predstavljaju načine da kompromitujete druge users**.

Pre nego što započnete authenticated enumeration, treba da znate šta je **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitovanje account-a je **veliki korak ka kompromitovanju celog domena**, jer ćete moći da započnete **Active Directory Enumeration:**

Što se tiče [**ASREPRoast**](asreproast.md) sada možete naći sve moguće vulnerable users, a što se tiče [**Password Spraying**](password-spraying.md) možete dobiti **listu svih usernames** i probati password kompromitovanog account-a, empty passwords i nove obećavajuće passwords.

- Možete koristiti [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Takođe možete koristiti [**powershell for recon**](../basic-powershell-for-pentesters/index.html) koji će biti diskretnije
- Takođe možete [**use powerview**](../basic-powershell-for-pentesters/powerview.md) da izvučete detaljnije informacije
- Još jedan odličan alat za recon u Active Directory je [**BloodHound**](bloodhound.md). Nije **veoma stealthy** (zavisi od metoda kolekcije koje koristite), ali **ako vam to nije bitno**, svakako ga probajte. Pronađite gde users mogu RDP-ovati, pronađite put do drugih grupa, itd.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) jer mogu sadržavati zanimljive informacije.
- Alat sa **GUI** koji možete koristiti za enumeraciju direktorijuma je **AdExplorer.exe** iz **SysInternal** Suite.
- Takođe možete pretražiti LDAP bazu koristeći **ldapsearch** da tražite credentials u poljima _userPassword_ & _unixUserPassword_, ili čak u _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristite **Linux**, možete takođe enumerisati domen koristeći [**pywerview**](https://github.com/the-useless-one/pywerview).
- Takođe možete probati automatizovane alate kao:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Vrlo je lako dobiti sve domain usernames iz Windows-a (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ova Enumeration sekcija izgleda kratko, ovo je najvažniji deo. Posetite linkove (pre svega one za cmd, powershell, powerview i BloodHound), naučite kako enumerisati domain i vežbajte dok ne budete sigurni. Tokom assessment-a, ovo će biti ključni trenutak da nađete put do DA ili da odlučite da se ništa ne može uraditi.

### Kerberoast

Kerberoasting podrazumeva dobijanje **TGS tickets** koje koriste servisi vezani za user accounts i crack-ovanje njihove enkripcije — koja je zasnovana na user passwords — **offline**.

Više o ovome u:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Kada dobijete credentials, možete proveriti da li imate access na bilo koju **machine**. Za to možete koristiti **CrackMapExec** da pokušate konekciju na više servera koristeći različite protokole, u skladu sa port scans.

### Local Privilege Escalation

Ako imate compromised credentials ili session kao regular domain user i imate **access** tim userom na **bilo koji machine u domen-u**, treba pokušati naći put do **escalate-ovanja privilegija lokalno i loot-ovanja credentials**. To je zato što samo sa lokalnim administrator privilegijama možete **dump-ovati hashes drugih users** iz memorije (LSASS) i lokalno (SAM).

Postoji kompletna stranica u ovoj knjizi o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) i [**checklist**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Veoma je malo verovatno da ćete pronaći tickets u current user-u koji vam daju permission da pristupite neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više email adresa i bolje razumevanje mreže**. Možda ćete uspeti da izvedete NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sada kada imate neke osnovne credentials trebalo bi da proverite da li možete **pronaći** bilo koje **zanimljive fajlove koji se dele unutar AD-a**. To možete raditi ručno, ali je veoma dosadan i ponavljajući zadatak (još gore ako nađete stotine dokumenata koje treba pregledati).

[**Pratite ovaj link da saznate o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete **pristupiti drugim PCs ili shares** možete **postaviti fajlove** (npr. SCF file) koji, ako se na neki način otvore, će **pokrenuti NTLM authentication prema vama** tako da možete **ukrasti** **NTLM challenge** i pokušati da ga crack-ujete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala bilo kom autentifikovanom korisniku da **kompromituje domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Za sledeće tehnike običan domain user nije dovoljan, potrebne su specijalne privilegije/credentials da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **kompromitujete neki local admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da dump-ujete sve hash-e iz memorije i lokalno.\
[**Pročitajte ovu stranicu o različitim načinima dobijanja hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga iskoristiti da ga **impersonirate**.\
Treba da koristite neki **tool** koji će **izvršiti NTLM authentication koristeći** taj **hash**, **ili** možete kreirati novi **sessionlogon** i **inject-ovati** taj **hash** u **LSASS**, tako da kada se izvrši bilo koja **NTLM authentication**, taj **hash bude korišćen.** Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **iskoristi korisnikov NTLM hash za zahtevanje Kerberos tiketa**, kao alternativa uobičajenom Pass The Hash preko NTLM protokola. Dakle, ovo može biti posebno **korisno u mrežama gde je NTLM protocol onemogućen** i gde je dozvoljen samo **Kerberos** kao protokol autentifikacije.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **ukradu korisnikov authentication ticket** umesto njegove lozinke ili hash vrednosti. Ovaj ukradeni ticket se potom koristi za **impersonaciju korisnika**, omogućavajući neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **password** lokalnog **administrator**a trebalo bi da pokušate da se **loginujete lokalno** na druge **PCs** koristeći njega.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi **LAPS** to **umanjio**.

### MSSQL Abuse & Trusted Links

Ako korisnik ima privilegije za **access MSSQL instances**, mogao bi ga iskoristiti za **execute commands** na MSSQL hostu (ako se izvršava kao SA), **steal** NetNTLM **hash** ili čak izvršiti **relay** **attack**.\
Takođe, ako je MSSQL instance trusted (database link) od strane druge MSSQL instance. Ako korisnik ima privilegije nad trusted bazom, moći će **use the trust relationship to execute queries also in the other instance**. Ova poverenja se mogu lančati i u nekom trenutku korisnik može pronaći pogrešno konfigurisanu bazu gde može izvršavati komande.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Sistemi trećih strana za inventar i deployment često izlažu moćne puteve do kredencijala i izvršavanja koda. Vidi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer object sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domain privilegije na tom računaru, bićete u mogućnosti da dump-ujete TGT-ove iz memorije svih korisnika koji se prijave na računar.\
Dakle, ako se **Domain Admin logins onto the computer**, moći ćete da dump-ujete njegov TGT i impersonate ga koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation možete čak i **automatski kompromitovati Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljeno "Constrained Delegation" moći će da **impersonate any user to access some services in a computer**.\
Zatim, ako **compromise the hash** tog korisnika/računara bićete u stanju da **impersonate any user** (čak i domain admins) da pristupite nekim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju na Active Directory objektu udaljenog računara omogućava ostvarivanje izvršavanja koda sa **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Kompromitovani korisnik može imati neke **zanimljive privilegije nad određenim domain objektima** koje bi vam omogućile da **move** lateralno/**escalate** privilegije.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Otkrivanje **Spool service listening** unutar domena može se **abuse** za **acquire new credentials** i **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ako **other users** **access** kompromitovani računar, moguće je **gather credentials from memory** i čak **inject beacons in their processes** da biste ih impersonate-ovali.\
Obično korisnici pristupaju sistemu preko RDP-a, pa ovde imate kako izvesti par napada nad sesijama trećih lica preko RDP-a:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **local Administrator password** na računarima priključenim na domen, osiguravajući da je **randomized**, jedinstvena i često **changed**. Ove lozinke se čuvaju u Active Directory i pristup je kontrolisan kroz ACLs samo za autorizovane korisnike. Sa dovoljnim permisijama za pristup ovim lozinkama, pivotanje na druge računare postaje moguće.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** sa kompromitovanog računara može biti način za eskalaciju privilegija unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ako su konfigurirani **vulnerable templates**, moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Kada dobijete **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možete **dump** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Neke od tehnika prethodno opisanih mogu se koristiti za održavanje pristupa.\
Na primer, možete:

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

The **Silver Ticket attack** kreira **legitiman Ticket Granting Service (TGS) ticket** za specifičan servis koristeći **NTLM hash** (na primer, **hash PC account**). Ova metoda se koristi za **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** podrazumeva da napadač dobije pristup **NTLM hash-u krbtgt account-a** u Active Directory okruženju. Ovaj nalog je specijalan zato što se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su ključni za autentifikaciju unutar AD mreže.

Kada napadač dobije ovaj hash, može kreirati **TGTs** za bilo koji nalog po izboru (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su slični golden tickets, lažirani na način koji **zaobilazi uobičajene mehanizme detekcije golden tickets**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posedovanje sertifikata naloga ili mogućnost da ih zahtevaš** je vrlo dobar način da se zadrži pristup korisničkom nalogu (čak i ako promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenjem sertifikata takođe je moguće održavati perzistenciju sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory obezbeđuje sigurnost **privileged groups** (kao što su Domain Admins i Enterprise Admins) primenom standardnog **Access Control List (ACL)** preko ovih grupa kako bi se sprečile neautorizovane izmene. Međutim, ova funkcija se može zloupotrebiti; ako napadač izmeni AdminSDHolder-ov ACL i dodeli potpuni pristup običnom korisniku, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova mera koja bi trebalo da štiti može se tako obrnuti i omogućiti neovlašćeni pristup ukoliko se ne prati pažljivo.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

U svakom **Domain Controller (DC)** postoji lokalni administrator nalog. Dobijanjem admin prava na takvom mašini, lokalni Administrator hash može se izvući korišćenjem **mimikatz**. Nakon toga potrebno je izmeniti registry da bi se **enable the use of this password**, omogućavajući daljinski pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** neke **specijalne permisije** korisniku nad određenim domain objektima koje će tom korisniku omogućiti da **eskalira privilegije u budućnosti**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje permisija** koje objekat ima nad nekim resursom. Ako možete napraviti i malu izmenu u **security descriptor-u** nekog objekta, možete dobiti vrlo interesantne privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da uspostavite **univerzalnu lozinku**, čime dobijate pristup svim nalozima domena.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati sopstveni **SSP** da **capture** u **clear text** kredencijale koje se koriste za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD i koristi ga da **push attributes** (SIDHistory, SPNs...) na određene objekte **bez** ostavljanja bilo kakvih **logova** o tim **izmenama**. Potrebne su vam **DA** privilegije i morate biti unutar **root domain**.\
Napomena: ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo objasnili kako eskalirati privilegije ako imate **dovoljne permisije da pročitate LAPS passwords**. Međutim, ove lozinke se takođe mogu koristiti za **održavanje perzistencije**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft smatra **Forest** kao sigurnosnu granicu. To implicira da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja cele Foreste**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je sigurnosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. U suštini, uspostavlja vezu između sistema za autentifikaciju ta dva domena, dopuštajući protok verifikacija autentifikacije. Kada domeni podese poverenje, razmenjuju i čuvaju određene **keys** unutar svojih **Domain Controller-a (DCs)**, koji su ključni za integritet poverenja.

U tipičnom scenariju, ako korisnik želi pristupiti servisu u **trusted domain**, prvo mora zatražiti poseban tiket poznat kao **inter-realm TGT** od svog domaćeg DC. Taj TGT je enkriptovan sa zajedničkim **key-om** koji su oba domena dogovorila. Korisnik zatim predaje ovaj TGT **DC-u trusted domena** da dobije service ticket (**TGS**). Po uspešnoj verifikaciji inter-realm TGT-a od strane DC-a trusted domena, izdaje se TGS, dajući korisniku pristup servisu.

**Koraci**:

1. Klijent kompjuter u **Domain 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan sa **trust key-om** koji dele DC1 i DC2 kao deo dvosmernog domain trust-a.
5. Klijent odnosi inter-realm TGT na **Domain 2's Domain Controller (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći svoj shared trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kojem klijent želi pristupiti.
7. Na kraju, klijent predaje ovaj TGS serveru, koji je enkriptovan sa hash-om server naloga, da bi dobio pristup servisu u Domain 2.

### Different trusts

Važno je primetiti da **a trust can be 1 way or 2 ways**. U opciji sa dve strane, oba domena će verovati jedan drugom, ali u **one way** trust relaciji jedan od domena će biti **trusted**, a drugi **trusting** domen. U tom poslednjem slučaju, **moći ćete pristupiti resursima unutar trusting domena iz trusted domena**.

Ako Domain A trusts Domain B, A je trusting domain i B je trusted domain. Štaviše, u **Domain A**, ovo bi bio **Outbound trust**; a u **Domain B**, ovo bi bio **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Ovo je uobičajena konfiguracija unutar iste foreste, gde child domain automatski ima dvosmerni transitive trust sa svojim parent domain-om. U suštini, to znači da autentifikacioni zahtevi mogu slobodno teći između parent-a i child-a.
- **Cross-link Trusts**: Poznati i kao "shortcut trusts", uspostavljaju se između child domena kako bi ubrzali procese referisanja. U kompleksnim forestama, autentifikaciona referenca obično mora putovati do korena foreste pa zatim do ciljnog domena. Kreiranjem cross-link-ova, put je skraćen, što je posebno korisno u geografski rasprostranjenim okruženjima.
- **External Trusts**: Usmerene su između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft-ovoj dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust-ovi su korisni za pristup resursima u domenu van trenutne foreste koji nije povezan forest trust-om. Bezbednost se pojačava kroz SID filtering kod external trust-ova.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domain-a i novo dodatog tree root-a. Iako se ne sreću često, tree-root trust-ovi su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i osiguravaju dvosmernu tranzitivnost. Više informacija možete naći u [Microsoft-ovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ova vrsta trust-a je dvosmerni transitive trust između dva forest root domain-a, takođe primenjujući SID filtering radi poboljšanja bezbednosti.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa ne-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trust-ovi su specijalizovaniji i namenjeni okruženjima koja zahtevaju integraciju sa Kerberos sistemima van Windows ekosistema.

#### Other differences in **trusting relationships**

- Trust relacija može biti i **transitive** (A trusts B, B trusts C, onda A trusts C) ili **non-transitive**.
- Trust relacija može biti postavljena kao **bidirectional trust** (oba veruju jedno drugom) ili kao **one-way trust** (samo jedan veruje drugom).

### Attack Path

1. **Enumerate** trusting relationships
2. Proveriti da li neki **security principal** (user/group/computer) ima **access** na resurse **drugog domena**, možda preko ACE unosa ili članstva u grupama drugog domena. Tražite **relationships across domains** (trust je verovatno kreiran zbog toga).
1. kerberoast u ovom slučaju bi mogao biti još jedna opcija.
3. **Compromise** naloge koji mogu **pivot** kroz domene.

Napadači mogu dobiti pristup resursima u drugom domenu kroz tri primarna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao npr. grupu “Administrators” na serveru, što im daje značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti navedeni u **ACL-u**, posebno kao entiteti u **ACE-ovima** unutar **DACL-a**, dajući im pristup određenim resursima. Za dublje razumevanje mehanike ACL-ova, DACL-ova i ACE-ova, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je veoma koristan resurs.

### Find external users/groups with permissions

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da pronađete foreign security principals u domenu. To će biti user/group iz **an external domain/forest**.

Ovo možete proveriti u **Bloodhound** ili koristeći **powerview**:
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
> Postoje **2 pouzdana ključa**, jedan za _Child --> Parent_ i drugi za _Parent_ --> _Child_.\
> Možete proveriti koji ključ koristi trenutni domen pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalirajte do Enterprise admin privilegija u child/parent domenu zloupotrebom trust-a pomoću SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Eksploatacija zapisivog Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može iskoristiti je ključno. Configuration NC služi kao centralno skladište konfiguracionih podataka kroz forest u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar foresta, pri čemu zapisivi DC-i održavaju zapisivu kopiju Configuration NC. Za eksploataciju je neophodno imati **SYSTEM privileges on a DC**, po mogućstvu child DC.

**Link GPO to root DC site**

Sites kontejner Configuration NC sadrži informacije o site-ovima svih računara koji su članovi domena unutar AD foresta. Radeći sa SYSTEM privilegijama na bilo kojem DC-u, napadači mogu povezati GPO-ove sa root DC site-ovima. Ova akcija potencijalno kompromituje root domen manipulacijom politika primenjenih na tim site-ovima.

Za detaljnije informacije, može se proučiti istraživanje o [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan vektor napada je ciljanje privilegovanih gMSA-a unutar domena. KDS Root key, koji je neophodan za izračunavanje lozinki gMSA-a, smešten je unutar Configuration NC. Sa SYSTEM privilegijama na bilo kojem DC-u, moguće je pristupiti KDS Root key i izračunati lozinke za bilo koji gMSA kroz ceo forest.

Detaljna analiza i korak-po-korak uputstva mogu se naći u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarni delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatna spoljna istraživanja: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ova metoda zahteva strpljenje i čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema da dodeli bilo kom korisniku potpunu kontrolu nad svim klasama. To može dovesti do neautorizovanog pristupa i kontrole nad novokreiranim AD objektima.

Dalje čitanje dostupno je na [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Ranljivost ADCS ESC5 cilja kontrolu nad PKI objektima kako bi se kreirao template sertifikata koji omogućava autentifikaciju kao bilo koji korisnik unutar foresta. Pošto PKI objekti žive u Configuration NC, kompromitovanje zapisivog child DC-a omogućava izvođenje ESC5 napada.

Više detalja može se pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS-a, napadač ima mogućnost da postavi potrebne komponente, kao što je razmotreno u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Eksterni forest domen - jednosmeran (Inbound) ili dvosmeran
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
U ovom scenariju **vaš domen je poveren** od strane eksternog, dajući vam **neodređene dozvole** nad njim. Moraćete da otkrijete **koji subjekti vašeg domena imaju koji pristup nad eksternim domenom** i potom pokušate da ih iskoristite:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni forest domen - Jednosmerno (Outbound)
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

Međutim, kada **domen bude poveren** od strane poveravajućeg domena, povereni domen **kreira korisnika** sa **predvidivim imenom** koji koristi kao **lozinku poverenu lozinku**. To znači da je moguće **pristupiti korisniku iz poveravajućeg domena da bi se ušlo u povereni** i enumerisalo ga i pokušalo eskalirati dodatne privilegije:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način da se kompromituje povereni domen je pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnoj smeru** od domain trust-a (što nije vrlo često).

Drugi način da se kompromituje povereni domen je da se sačeka na mašini kojoj **korisnik iz poverenog domena može pristupiti** da se prijavi putem **RDP-a**. Zatim bi napadač mogao injektovati kod u proces RDP sesije i **pristupiti origin domen-u žrtve** odatle.\
Štaviše, ako je **žrtva montirala svoj hard drive**, iz procesa **RDP session** napadač bi mogao postaviti **backdoors** u **startup folder hard drive-a**. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe poverenja domena

### **SID Filtering:**

- Rizik od napada koji koriste SID history atribut preko forest trust-ova se ublažava pomoću SID Filtering, koji je po defaultu aktiviran na svim inter-forest trust-ovima. Ovo se zasniva na pretpostavci da su intra-forest trust-ovi sigurni, tretirajući forest, a ne domen, kao granicu bezbednosti u skladu sa Microsoft-ovim stavom.
- Međutim, postoji problem: SID filtering može poremetiti aplikacije i pristup korisnika, zbog čega se ponekad isključuje.

### **Selective Authentication:**

- Za inter-forest trust-ove, korišćenje Selective Authentication osigurava da korisnici iz dva foresta nisu automatski autentifikovani. Umesto toga, potrebna su eksplicitna dopuštenja da bi korisnici pristupili domenima i serverima unutar poveravajućeg domena ili foresta.
- Važno je napomenuti da ove mere ne štite od zloupotrebe writable Configuration Naming Context (NC) ili napada na trust account.

[**Više informacija o domain trusts na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Neke opšte odbrambene mere

[**Saznajte više o zaštiti kredencijala ovde.**](../stealing-credentials/credentials-protections.md)

### **Defanzivne mere za zaštitu kredencijala**

- **Ograničenja Domain Admins**: Preporučuje se da Domain Admins mogu da se prijavljuju samo na Domain Controllers, izbegavajući njihovu upotrebu na drugim hostovima.
- **Privilegije servisnih naloga**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi održavanja bezbednosti.
- **Vremensko ograničenje privilegija**: Za zadatke koji zahtevaju DA privilegije, trebalo bi ograničiti njihovo trajanje. Ovo se može postići komandama poput: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementacija tehnika zavaravanja (Deception)**

- Implementacija deception uključuje postavljanje zamki, kao što su lažni korisnici ili računari, sa karakteristikama poput lozinki koje ne ističu ili su označeni kao Trusted for Delegation. Detaljan pristup uključuje kreiranje korisnika sa specifičnim pravima ili dodavanje u grupe visokih privilegija.
- Praktičan primer uključuje korišćenje alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o deploy-ovanju deception tehnika možete naći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifikovanje zavaravanja**

- **Za User objekte**: Sumnjivi indikatori uključuju netipičan ObjectSID, retke prijave, datume kreiranja i nizak broj pogrešnih lozinki.
- **Opšti indikatori**: Poređenje atributa potencijalnih decoy objekata sa onima kod stvarnih može otkriti nedoslednosti. Alati poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikaciji takvih zavaravanja.

### **Zaobilaženje detekcionih sistema**

- **Microsoft ATA Detection Bypass**:
- **Enumeracija korisnika**: Izbegavanje enumeracije sesija na Domain Controller-ima da se spreči ATA detekcija.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje ticket-a pomaže da se izbegne detekcija ne padajući na NTLM.
- **DCSync napadi**: Izvođenje sa mašine koja nije Domain Controller kako bi se izbegla ATA detekcija se savetuje, jer direktno izvođenje sa Domain Controller-a izaziva alarme.

## Reference

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
