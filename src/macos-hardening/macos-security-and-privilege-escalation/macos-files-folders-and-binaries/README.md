# macOS datoteke, fascikle, binarni fajlovi i memorija

{{#include ../../../banners/hacktricks-training.md}}

## Hijerarhijski raspored datoteka

- **/Applications**: Instalirane aplikacije bi trebalo da se nalaze ovde. Svi korisnici će moći da im pristupe.
- **/bin**: Binarni fajlovi komandne linije
- **/cores**: Ako postoji, koristi se za čuvanje core dump-ova
- **/dev**: Sve se tretira kao datoteka, pa ovde možete videti sačuvane hardverske uređaje.
- **/etc**: Konfiguracione datoteke
- **/Library**: Ovde se može pronaći veliki broj poddirektorijuma i datoteka povezanih sa podešavanjima, kešom i logovima. Library fascikla postoji u root direktorijumu i u direktorijumu svakog korisnika.
- **/private**: Nije dokumentovan, ali veliki broj prethodno pomenutih fascikli predstavljaju simboličke linkove ka private direktorijumu.
- **/sbin**: Osnovni sistemski binarni fajlovi (povezani sa administracijom)
- **/System**: Datoteke potrebne za pokretanje OS X-a. Ovde bi uglavnom trebalo da se nalaze samo datoteke specifične za Apple (ne third-party datoteke).
- **/tmp**: Datoteke se brišu nakon 3 dana (ovo je soft link ka /private/tmp)
- **/Users**: Home direktorijum korisnika.
- **/usr**: Konfiguracioni i sistemski binarni fajlovi
- **/var**: Log datoteke
- **/Volumes**: Ovde će se prikazati montirani diskovi.
- **/.vol**: Pokretanjem `stat a.txt` dobijate nešto poput `16777223 7545753 -rw-r--r-- 1 username wheel ...`, gde je prvi broj ID broj volumena na kom se datoteka nalazi, a drugi je inode broj. Sadržaju ove datoteke možete pristupiti kroz /.vol/ sa tim informacijama, pokretanjem komande `cat /.vol/16777223/7545753`

### Applications fascikle

- **System aplikacije** se nalaze u `/System/Applications`
- **Instalirane** aplikacije se obično instaliraju u `/Applications` ili u `~/Applications`
- **Podaci aplikacija** mogu se pronaći u `/Library/Application Support` za aplikacije koje se pokreću kao root i u `~/Library/Application Support` za aplikacije koje se pokreću kao korisnik.
- Third-party aplikacioni **daemoni** koji **moraju da se pokreću kao root** obično se nalaze u `/Library/PrivilegedHelperTools/`
- **Sandboxed** aplikacije su mapirane u fasciklu `~/Library/Containers`. Svaka aplikacija ima fasciklu imenovanu prema bundle ID-u aplikacije (`com.apple.Safari`).
- **Kernel** se nalazi u `/System/Library/Kernels/kernel`
- **Apple kernel ekstenzije** nalaze se u `/System/Library/Extensions`
- **Third-party kernel ekstenzije** čuvaju se u `/Library/Extensions`

### Datoteke sa osetljivim informacijama

MacOS čuva informacije kao što su lozinke na nekoliko mesta:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Ranjivi pkg installer-i


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Specifične OS X ekstenzije

- **`.dmg`**: Apple Disk Image datoteke su veoma česte za installere.
- **`.kext`**: Mora da prati specifičnu strukturu i predstavlja OS X verziju driver-a. (bundle je)
- **`.plist`**: Takođe poznat kao property list, čuva informacije u XML ili binarnom formatu.
- Može biti XML ili binarni format. Binarne datoteke mogu se čitati pomoću:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple aplikacije koje prate strukturu direktorijuma (bundle).
- **`.dylib`**: Dinamičke biblioteke (poput Windows DLL datoteka)
- **`.pkg`**: Iste su kao xar (eXtensible Archive format). Installer komanda može da se koristi za instaliranje sadržaja ovih datoteka.
- **`.DS_Store`**: Ova datoteka postoji u svakom direktorijumu i čuva atribute i prilagođavanja direktorijuma.
- **`.Spotlight-V100`**: Ova fascikla se pojavljuje u root direktorijumu svakog volumena na sistemu.
- **`.metadata_never_index`**: Ako se ova datoteka nalazi u root direktorijumu volumena, Spotlight neće indeksirati taj volumen.
- **`.noindex`**: Datoteke i fascikle sa ovom ekstenzijom neće biti indeksirane pomoću Spotlight-a.
- **`.sdef`**: Datoteke unutar bundle-ova koje određuju kako je moguće komunicirati sa aplikacijom iz AppleScript-a.

### macOS Bundle-ovi

Bundle je **direktorijum** koji u Finder-u **izgleda kao objekat** (Primer bundle-a su `*.app` datoteke).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Na macOS-u (i iOS-u) sve sistemske shared biblioteke, kao što su framework-ovi i dylib-ovi, **kombinuju se u jednu datoteku**, koja se naziva **dyld shared cache**. Ovo poboljšava performanse, jer se kod može brže učitati.

Na macOS-u se nalazi u `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, a u starijim verzijama **shared cache** možete pronaći u **`/System/Library/dyld/`**.\
Na iOS-u ih možete pronaći u **`/System/Library/Caches/com.apple.dyld/`**.

Slično dyld shared cache-u, kernel i kernel ekstenzije se takođe kompajliraju u kernel cache, koji se učitava prilikom pokretanja sistema.

Da bi se biblioteke izdvojile iz jedne datoteke dylib shared cache-a, bilo je moguće koristiti binarni fajl [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), koji možda danas više ne radi, ali možete koristiti i [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Imajte na umu da čak i ako alat `dyld_shared_cache_util` ne radi, možete proslediti **shared dyld binary u Hopper** i Hopper će moći da identifikuje sve biblioteke i omogući vam da **izaberete onu koju želite da istražite**:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Neki extractors neće raditi jer su dylibs prelinkovani sa hardkodiranim adresama, pa mogu skakati na nepoznate adrese

> [!TIP]
> Takođe je moguće preuzeti Shared Library Cache drugih \*OS uređaja u macOS-u korišćenjem emulatora u Xcode-u. Oni će biti preuzeti u: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, kao što je:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapiranje SLC-a

**`dyld`** koristi syscall **`shared_region_check_np`** da bi utvrdio da li je SLC mapiran (što vraća adresu) i **`shared_region_map_and_slide_np`** za mapiranje SLC-a.

Imajte na umu da čak i kada se SLC pomeri pri prvom korišćenju, svi **procesi** koriste **istu kopiju**, čime se **uklanja ASLR** zaštita ako je napadač mogao da pokreće procese na sistemu. Ovo je zapravo ranije bilo iskorišćeno i rešeno pomoću shared region pager-a.

Branch pools su male Mach-O dylibs koje stvaraju male prostore između mapiranja image-a, čime onemogućavaju interponovanje funkcija.

### Override SLC-ova

Korišćenjem env promenljivih:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Ovo će omogućiti učitavanje novog shared library cache-a
- **`DYLD_SHARED_CACHE_DIR=avoid`** i ručna zamena biblioteka symlinkovima ka shared cache-u sa stvarnim bibliotekama (moraćete da ih ekstraktujete)

## Posebne dozvole fajlova

### Dozvole foldera

U **folderu**, **read** omogućava njegovo **izlistavanje**, **write** omogućava **brisanje** i **upisivanje** fajlova u njega, a **execute** omogućava **prolazak** kroz direktorijum. Na primer, korisnik sa **read dozvolom nad fajlom** unutar direktorijuma nad kojim **nema execute** dozvolu **neće moći da pročita** fajl.

### Modifikatori flagova

Postoje flagovi koji mogu biti postavljeni na fajlovima i zbog kojih će se fajl ponašati drugačije. Možete **proveriti flagove** fajlova unutar direktorijuma pomoću `ls -lO /path/directory`

- **`uchg`**: Poznat kao **uchange** flag, sprečiće bilo koju radnju koja menja ili briše **fajl**. Da biste ga postavili, koristite: `chflags uchg file.txt`
- root korisnik može **ukloniti flag** i izmeniti fajl
- **`restricted`**: Ovaj flag čini fajl **zaštićenim pomoću SIP-a** (ne možete dodati ovaj flag fajlu).
- **`Sticky bit`**: Ako direktorijum ima sticky bit, samo **vlasnik direktorijuma ili root mogu preimenovati ili obrisati** fajlove. Ovo se obično postavlja na direktorijum /tmp kako bi se sprečilo da obični korisnici brišu ili premeštaju fajlove drugih korisnika.

Svi flagovi se mogu pronaći u fajlu `sys/stat.h` (pronađite ga pomoću `mdfind stat.h | grep stat.h`) i jesu:

- `UF_SETTABLE` 0x0000ffff: Maska flagova koje vlasnik može menjati.
- `UF_NODUMP` 0x00000001: Ne dumpovati fajl.
- `UF_IMMUTABLE` 0x00000002: Fajl se ne može menjati.
- `UF_APPEND` 0x00000004: Upisivanje u fajl može biti samo dodavanje.
- `UF_OPAQUE` 0x00000008: Direktorijum je opaque u odnosu na union.
- `UF_COMPRESSED` 0x00000020: Fajl je kompresovan (neki fajl-sistemi).
- `UF_TRACKED` 0x00000040: Nema obaveštenja o brisanjima/preimenovanjima za fajlove sa ovim flagom.
- `UF_DATAVAULT` 0x00000080: Za čitanje i upisivanje je potreban entitlement.
- `UF_HIDDEN` 0x00008000: Nagoveštaj da ovu stavku ne treba prikazivati u GUI-ju.
- `SF_SUPPORTED` 0x009f0000: Maska flagova koje podržava superuser.
- `SF_SETTABLE` 0x3fff0000: Maska flagova koje superuser može menjati.
- `SF_SYNTHETIC` 0xc0000000: Maska sistemskih synthetic flagova samo za čitanje.
- `SF_ARCHIVED` 0x00010000: Fajl je arhiviran.
- `SF_IMMUTABLE` 0x00020000: Fajl se ne može menjati.
- `SF_APPEND` 0x00040000: Upisivanje u fajl može biti samo dodavanje.
- `SF_RESTRICTED` 0x00080000: Za upisivanje je potreban entitlement.
- `SF_NOUNLINK` 0x00100000: Stavka se ne može ukloniti, preimenovati ili montirati.
- `SF_FIRMLINK` 0x00800000: Fajl je firmlink.
- `SF_DATALESS` 0x40000000: Fajl je dataless objekat.

### **ACL-ovi fajlova**

ACL-ovi fajlova sadrže **ACE** (Access Control Entries), gde se mogu dodeliti **preciznije dozvole** različitim korisnicima.

Direktorijumu je moguće dodeliti sledeće dozvole: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
A fajlu: `read`, `write`, `append`, `execute`.

Kada fajl sadrži ACL-ove, videćete **„+“ prilikom izlistavanja dozvola, kao u**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Možete **pročitati ACL-ove** datoteke pomoću:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Možete pronaći **sve datoteke sa ACL-ovima** pomoću (ovo je veoma sporo):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Prošireni atributi

Prošireni atributi imaju naziv i proizvoljnu vrednost, a mogu se videti pomoću `ls -@` i menjati pomoću komande `xattr`. Neki uobičajeni prošireni atributi su:

- `com.apple.resourceFork`: Kompatibilnost sa Resource fork-om. Takođe vidljivo kao `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS: Gatekeeper mehanizam karantina (III/6)
- `metadata:*`: macOS: različiti metapodaci, kao što su `_backup_excludeItem` ili `kMD*`
- `com.apple.lastuseddate` (#PS): Datum poslednje upotrebe fajla
- `com.apple.FinderInfo`: macOS: Finder informacije (npr. Tags u boji)
- `com.apple.TextEncoding`: Navodi kodiranje teksta ASCII tekstualnih fajlova
- `com.apple.logd.metadata`: Koristi ga logd za fajlove u `/var/db/diagnostics`
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` u root-u filesystem-a)
- `com.apple.rootless`: macOS: Koristi ga System Integrity Protection za označavanje fajla (III/10)
- `com.apple.uuidb.boot-uuid`: logd oznake epoha pokretanja sistema sa jedinstvenim UUID-om
- `com.apple.decmpfs`: macOS: Transparentna kompresija fajlova (II/7)
- `com.apple.cprotect`: \*OS: Podaci o enkripciji po fajlu (III/11)
- `com.apple.installd.*`: \*OS: Metapodaci koje koristi installd, npr. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Ovo je način za dobijanje **Alternate Data Streams na MacOS** mašinama. Sadržaj možete sačuvati unutar proširenog atributa pod nazivom **com.apple.ResourceFork** u fajlu tako što ćete ga sačuvati u **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Možete **pronaći sve datoteke koje sadrže ovaj prošireni atribut** pomoću:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Prošireni atribut `com.apple.decmpfs` ukazuje da je datoteka sačuvana šifrovano, `ls -l` će prijaviti **veličinu 0**, a kompresovani podaci se nalaze unutar ovog atributa. Kada se datoteci pristupi, ona će biti dešifrovana u memoriji.

Ovaj atribut se može videti pomoću `ls -lO`, gde je označen kao kompresovan, jer su kompresovane datoteke takođe označene zastavicom `UF_COMPRESSED`. Ako se kod kompresovane datoteke ukloni ova zastavica pomoću `chflags nocompressed </path/to/file>`, sistem neće znati da je datoteka bila kompresovana i zato neće moći da dekompresuje i pristupi podacima (misliće da je datoteka zapravo prazna).

Alat afscexpand može da se koristi za prinudnu dekompresiju datoteke.


### Zanimljive lokacije konfiguracije (macOS)

| Path / Lokacija | Namena / Šta konfiguriše | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Čuva Apple-ove plist datoteke sa feature flagovima koji kontrolišu opcionalna ili eksperimentalna ponašanja u system daemonima / frameworkovima | Ako attacker može da zaobiđe SIP ili stekne privilege, menjanje ovih datoteka može omogućiti skrivene code pathove ili onemogućiti safeguards |
| `/System/Library/CoreServices/systemVersion.plist` | Sadrži metapodatke o macOS verziji (ProductVersion, BuildVersion) koje koriste aplikacije / installeri za ograničavanje ponašanja | Izmena može prevariti aplikacije ili installere da prihvate nepodržane verzije OS-a ili otključaju features |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Application / system-wide preferences | Ako su writable, attackeri mogu ubaciti settings za usmeravanje ponašanja aplikacije, onemogućavanje protections ili izazivanje misconfiguration-a |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist definicije za background daemon-e i agente | Ubacivanje ili menjanje malicious plist datoteka (ako permissions to dozvoljavaju) omogućava persistence ili privilege escalations |
| `/etc/hosts` | Mapiranja Hostname ↔ IP koja koristi system DNS resolver | Preusmeravanje domain name-ova, interception traffic-a, spoofing services pod lokalnom kontrolom |
| `/etc/sudoers` | Definiše ko može da izvršava commands pomoću `sudo` i pod kojim uslovima | Oštećena sudoers datoteka može attacker account-ima dodeliti root ili neodgovarajuće privileges |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist definicije lokalnih user account-a | Tampering omogućava kreiranje ili menjanje user account-a, password hash-ova ili user metadata |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Instaliranje ili menjanje kext-ova može dovesti do kernel-level control-a; SIP / signature policies ih strogo štite |
| `/private/var/db/SystemPolicyConfiguration/` | Čuva konfiguraciju za enforcement system policy-ja (npr. Gatekeeper, notarization) | Tampering ovih datoteka može omogućiti zaobilaženje policy checks ili trust rules |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries i config datoteke | Misconfiguration dovodi do slabe SSH security, unauthorized access-a ili insecure algorithms |
| `/System/Library/Sandbox/Profiles` | System sandbox profiles (SBPL) koji se koriste za ograničavanje akcija process-a | Zamena ili izmena profila može otvoriti sandbox escape vektore ili oslabiti containment |

> **Napomena**: Mnoge od ovih putanja nalaze se u SIP-protected direktorijumima (npr. `/System`) i zaštićene su od upisivanja, osim ako je SIP disabled ili bypassovan.


## **Universal binaries &** Mach-o Format

Mac OS binaries se obično kompajliraju kao **universal binaries**. **Universal binary** može da **podržava više architecture-a u istoj datoteci**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

Direktorijum `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` je mesto gde se čuvaju informacije o **riziku povezanom sa različitim ekstenzijama datoteka**. Ovaj direktorijum klasifikuje datoteke u različite nivoe rizika, što utiče na način na koji Safari postupa sa ovim datotekama nakon preuzimanja. Kategorije su sledeće:

- **LSRiskCategorySafe**: Datoteke u ovoj kategoriji smatraju se **potpuno bezbednim**. Safari će automatski otvoriti ove datoteke nakon preuzimanja.
- **LSRiskCategoryNeutral**: Ove datoteke ne prikazuju upozorenja i Safari ih **ne otvara automatski**.
- **LSRiskCategoryUnsafeExecutable**: Datoteke u ovoj kategoriji **pokreću upozorenje** koje ukazuje da je datoteka aplikacija. Ovo služi kao security measure za upozoravanje user-a.
- **LSRiskCategoryMayContainUnsafeExecutable**: Ova kategorija je namenjena datotekama, kao što su arhive, koje mogu sadržati executable. Safari će **prikazati upozorenje**, osim ako ne može da potvrdi da je sav sadržaj bezbedan ili neutralan.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Sadrži informacije o preuzetim datotekama, kao što je URL sa kog su preuzete.
- **`/var/log/system.log`**: Glavni log OSX sistema. com.apple.syslogd.plist je odgovoran za izvršavanje syslogging-a (možete proveriti da li je disabled tako što ćete u `launchctl list` potražiti "com.apple.syslogd".
- **`/private/var/log/asl/*.asl`**: Ovo su Apple System Logs koji mogu sadržati zanimljive informacije.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Čuva nedavno pristupane datoteke i aplikacije kroz "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Čuva items za pokretanje prilikom startup-a sistema
- **`$HOME/Library/Logs/DiskUtility.log`**: Log datoteka za DiskUtility App (informacije o drive-ovima, uključujući USB uređaje)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Podaci o wireless access point-ovima.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista deactivated daemon-a.

{{#include ../../../banners/hacktricks-training.md}}
