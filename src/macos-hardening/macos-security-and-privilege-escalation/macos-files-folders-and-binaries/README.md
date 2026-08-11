# macOS fajlovi, fascikle, binarni fajlovi i memorija

{{#include ../../../banners/hacktricks-training.md}}

## Hijerarhijski raspored fajl sistema

Apple dokumentuje macOS fajl sistem kao hijerarhiju sistemskih, lokalnih, mrežnih i korisničkih domena. Tačan sadržaj se razlikuje u zavisnosti od izdanja OS-a, a sistemske lokacije su sve češće zaštićene ili sintetizovane. <sup>[[1]](#references)</sup>

- **/Applications**: Instalirane aplikacije bi trebalo da se nalaze ovde. Svi korisnici će moći da im pristupe.
- **/bin**: Binarni fajlovi komandne linije
- **/cores**: Ako postoji, koristi se za čuvanje core dump-ova
- **/dev**: Sve se tretira kao fajl, pa ovde možete videti sačuvane hardverske uređaje.
- **/etc**: Konfiguracioni fajlovi
- **/Library**: Ovde se mogu pronaći brojni poddirektorijumi i fajlovi povezani sa preferencama, keš memorijom i logovima. Library fascikla postoji u root direktorijumu i u direktorijumu svakog korisnika.
- **/private**: Nije dokumentovan, ali su mnoge pomenute fascikle simboličke veze ka private direktorijumu.
- **/sbin**: Osnovni sistemski binarni fajlovi (povezani sa administracijom)
- **/System**: Fajlovi potrebni macOS-u; ovo stablo prvenstveno sadrži komponente koje obezbeđuje Apple.
- **/tmp**: Privremeni fajlovi (simbolička veza ka `/private/tmp`). Istorijske instalacije su često periodično brisale stare privremene fajlove, ponekad uz period od tri dana, ali trenutno vreme čišćenja zavisi od sistema i politike; nemojte se oslanjati na to da će podaci ovde opstati.
- **/Users**: Matični direktorijum korisnika.
- **/usr**: Konfiguracioni i sistemski binarni fajlovi
- **/var**: Log fajlovi
- **/Volumes**: Ovde se pojavljuju montirani volumeni.
- **/.vol**: Pokretanjem `stat a.txt` dobijate nešto poput `16777223 7545753 -rw-r--r-- 1 username wheel ...`, pri čemu je prvi broj ID broj volumena na kojem fajl postoji, a drugi broj inode broj. Sadržaju ovog fajla možete pristupiti preko /.vol/ koristeći te informacije i pokretanjem komande `cat /.vol/16777223/7545753`

### Fascikle aplikacija

- **Sistemske aplikacije** se nalaze u `/System/Applications`
- **Instalirane** aplikacije se obično instaliraju u `/Applications` ili u `~/Applications`
- **Podaci aplikacija** mogu se pronaći u `/Library/Application Support` za aplikacije koje rade kao root i u `~/Library/Application Support` za aplikacije koje rade kao korisnik.
- **Daemoni** aplikacija trećih strana koji **moraju da rade kao root** obično se nalaze u `/Library/PrivilegedHelperTools/`.
- **Sandboxed** aplikacije su mapirane u fasciklu `~/Library/Containers`. Svaka aplikacija ima fasciklu imenovanu prema ID-u bundle-a aplikacije (`com.apple.Safari`).
- **kernel** se nalazi u `/System/Library/Kernels/kernel`
- **Apple kernel ekstenzije** nalaze se u `/System/Library/Extensions`
- **Kernel ekstenzije trećih strana** čuvaju se u `/Library/Extensions`

### Fajlovi sa osetljivim informacijama

macOS čuva osetljive informacije, uključujući credentials, na nekoliko lokacija:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Vulnerable pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Specifične OS X ekstenzije

- **`.dmg`**: Apple Disk Image fajlovi su veoma česti kod instalera.
- **`.kext`**: Mora da prati određenu strukturu i predstavlja OS X verziju driver-a. (bundle je)
- **`.plist`**: Property list čuva strukturisane informacije u XML ili binarnom formatu.
- Može biti XML ili binarni. Binarni fajlovi mogu se pročitati pomoću:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Application bundle koji prati standardnu macOS strukturu direktorijuma.
- **`.dylib`**: Dynamic libraries (poput Windows DLL fajlova)
- **`.pkg`**: Isti su kao xar (eXtensible Archive format). Installer komanda može da se koristi za instaliranje sadržaja ovih fajlova.
- **`.DS_Store`**: Ovaj fajl se nalazi u svakom direktorijumu i čuva atribute i prilagođavanja direktorijuma.
- **`.Spotlight-V100`**: Ova fascikla se pojavljuje u root direktorijumu svakog volumena na sistemu.
- **`.metadata_never_index`**: Ako se ovaj fajl nalazi u root direktorijumu volumena, Spotlight neće indeksirati taj volumen.
- **`.noindex`**: Fajlovi i fascikle sa ovom ekstenzijom neće biti indeksirani pomoću Spotlight-a.
- **`.sdef`**: Scripting definition fajl koji opisuje kako AppleScript može da komunicira sa aplikacijom.

### macOS Bundles

Bundle je direktorijum sa standardizovanom hijerarhijom koji Finder može da prikaže kao jedan objekat; application bundles koriste ekstenziju `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Na macOS-u i iOS-u, često korišćene sistemske biblioteke i framework-ovi unapred se povezuju u **dyld shared cache**, čime se poboljšavaju performanse pokretanja aplikacija. Iako se tretira kao jedan logički keš, aktuelna izdanja mogu da ga čuvaju kao glavni keš i više subcache fajlova, umesto bukvalno u jednom fajlu. Njegov format i lokacija predstavljaju detalje implementacije koji se menjaju kroz izdanja OS-a. <sup>[[3]](#references)</sup>

Na macOS-u se nalazi u `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, a u starijim verzijama možda ćete moći da pronađete **shared cache** u **`/System/Library/dyld/`**.\
Na iOS-u ih možete pronaći u **`/System/Library/Caches/com.apple.dyld/`**.

Slično kao dyld shared cache, kernel i kernel ekstenzije se takođe kompajliraju u kernel cache, koji se učitava prilikom boot-a.

Starija izdanja mogla su se ekstrahovati pomoću alata [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Ta verzija možda ne podržava aktuelne formate keša; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) je druga opcija:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Imajte na umu da, čak i ako alat `dyld_shared_cache_util` ne radi, možete proslediti **shared dyld binary alatu Hopper** i Hopper će moći da identifikuje sve biblioteke i omogući vam da **izaberete onu** koju želite da istražite:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Neki extractors neće raditi jer su dylibs unapred povezane sa hard-coded adresama, pa mogu skakati na nepoznate adrese

> [!TIP]
> Takođe je moguće preuzeti Shared Library Cache drugih \*OS uređaja u macOS-u korišćenjem emulatora u Xcode-u. Biće preuzeti unutar: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, kao što je:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapiranje SLC

**`dyld`** koristi syscall **`shared_region_check_np`** da proveri da li je SLC mapiran (što vraća adresu), a **`shared_region_map_and_slide_np`** za mapiranje SLC-a.

Imajte na umu da, čak i ako se SLC sliduje pri prvom korišćenju, svi **procesi** koriste **istu kopiju**, čime se **uklanja ASLR** zaštita ako je attacker uspeo da pokreće procese na sistemu. Ovo je ranije zaista bilo iskorišćeno i rešeno pomoću shared region pager-a.

Branch pools su male Mach-O dylibs koje stvaraju male prostore između image mapping-a, čime interpose funkcija postaje nemoguć.

### Override SLCs

Korišćenjem env variables:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Ovo će omogućiti učitavanje novog shared library cache-a
- **`DYLD_SHARED_CACHE_DIR=avoid`** i ručno zamenite biblioteke symlink-ovima ka shared cache-u sa stvarnim bibliotekama (moraćete da ih extract-ujete)

## Posebne dozvole datoteka

### Dozvole foldera

Za directory, **read** omogućava izlistavanje entries, **write** omogućava kreiranje ili uklanjanje entries, a **execute** omogućava traversal. Shodno tome, korisnik koji može da čita file, ali ne može da izvrši traversal kroz parent directory, ne može da pristupi tom file-u putem putanje. <sup>[[4]](#references)</sup>

### Modifikatori flag-ova

Files mogu imati flag-ove koji menjaju njihovo ponašanje. Inspect-ujte flag-ove u directory-ju pomoću `ls -lO /path/directory`.

- **`uchg`**: Poznat kao **uchange** flag, onemogućava bilo koju akciju koja menja ili briše **file**. Za njegovo postavljanje koristite: `chflags uchg file.txt`
- Root user može **ukloniti flag** i izmeniti file
- **`restricted`**: Ovaj flag čini file **zaštićenim pomoću SIP-a** (ne možete dodati ovaj flag file-u).
- **`Sticky bit`**: U directory-ju sa postavljenim sticky bit-om, samo vlasnik file-a, vlasnik directory-ja ili root mogu preimenovati ili obrisati entry. Ovo se obično omogućava na `/tmp`, kako bi se sprečilo da users brišu ili premeštaju files drugih users.

Svi flag-ovi se mogu pronaći u file-u `sys/stat.h` (pronađite ga pomoću `mdfind stat.h | grep stat.h`) i to su:

- `UF_SETTABLE` 0x0000ffff: Maska flag-ova koje owner može da menja.
- `UF_NODUMP` 0x00000001: Ne dump-ovati file.
- `UF_IMMUTABLE` 0x00000002: File se ne može menjati.
- `UF_APPEND` 0x00000004: Upis u file može biti samo append.
- `UF_OPAQUE` 0x00000008: Directory je opaque u odnosu na union.
- `UF_COMPRESSED` 0x00000020: File je kompresovan (neki file sistemi).
- `UF_TRACKED` 0x00000040: Nema notifications za brisanja/preimenovanja files sa ovim flag-om.
- `UF_DATAVAULT` 0x00000080: Potreban je entitlement za čitanje i upis.
- `UF_HIDDEN` 0x00008000: Hint da ovu stavku ne treba prikazivati u GUI-ju.
- `SF_SUPPORTED` 0x009f0000: Maska flag-ova koje podržava superuser.
- `SF_SETTABLE` 0x3fff0000: Maska flag-ova koje superuser može da menja.
- `SF_SYNTHETIC` 0xc0000000: Maska system read-only synthetic flag-ova.
- `SF_ARCHIVED` 0x00010000: File je arhiviran.
- `SF_IMMUTABLE` 0x00020000: File se ne može menjati.
- `SF_APPEND` 0x00040000: Upis u file može biti samo append.
- `SF_RESTRICTED` 0x00080000: Potreban je entitlement za upis.
- `SF_NOUNLINK` 0x00100000: Stavka se ne može ukloniti, preimenovati ili montirati na nju.
- `SF_FIRMLINK` 0x00800000: File je firmlink.
- `SF_DATALESS` 0x40000000: File je dataless object.

### **File ACL-ovi**

File **ACL-ovi** sadrže **ACE** (Access Control Entries), gde se različitim users mogu dodeliti **granularnije dozvole**.

Directory-ju je moguće dodeliti sledeće dozvole: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Za **file**: `read`, `write`, `append` i `execute`.

Kada file sadrži ACL-ove, prilikom izlistavanja dozvola **videćete znak „+" kao u**:
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
Sve datoteke sa ACL-ovima možete pronaći pomoću sledeće komande (ovo je veoma sporo):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Prošireni atributi

Prošireni atributi su imenovane vrednosti metapodataka koje se čuvaju odvojeno od uobičajenih atributa datoteke. Izlistajte ih pomoću `ls -l@`, a pregledajte ili izmenite pomoću `xattr`. <sup>[[5]](#references)</sup> Neki uobičajeni prošireni atributi su:

- `com.apple.resourceFork`: Kompatibilnost resource fork-a. Takođe vidljivo kao `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS Gatekeeper metapodaci karantina
- `metadata:*`: macOS metapodaci, kao što su `_backup_excludeItem` ili `kMD*`
- `com.apple.lastuseddate` (#PS): Datum poslednjeg korišćenja datoteke
- `com.apple.FinderInfo`: Informacije macOS Finder-a, kao što su oznake u boji
- `com.apple.TextEncoding`: Određuje kodiranje teksta ASCII datoteka
- `com.apple.logd.metadata`: Koristi ga logd za datoteke u `/var/db/diagnostics`
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` u root-u filesystem-a)
- `com.apple.rootless`: macOS metapodaci povezani sa System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Oznake logd-a za epohe pokretanja sa jedinstvenim UUID-om
- `com.apple.decmpfs`: macOS metapodaci transparentne kompresije datoteka
- `com.apple.cprotect`: \*OS: Podaci o enkripciji po datoteci (III/11)
- `com.apple.installd.*`: \*OS: Metapodaci koje koristi installd, npr. `installType`, `uniqueInstallID`

### Resource Fork-ovi | macOS ADS

Resource fork-ovi obezbeđuju alternativni tok podataka na macOS-u. Sadržaj može biti sačuvan u proširenom atributu `com.apple.ResourceFork` i pristupljen kroz `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Možete **pronaći sve datoteke koje sadrže ovaj prošireni atribut** pomoću:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Prošireni atribut `com.apple.decmpfs` čuva metapodatke za transparentnu kompresiju; ne ukazuje na enkripciju. U zavisnosti od formata kompresije, kompresovani podaci mogu biti sačuvani u atributu ili u resource fork-u i transparentno se dekompresuju prilikom čitanja.

Zastavica `UF_COMPRESSED` prikazuje se kao `compressed` u `ls -lO`. Nemojte je ručno uklanjati: time sistem može početi da neispravno tumači kompresovanu reprezentaciju.

Komanda koja uklanja zastavicu prikazana je ovde jer je korisna tokom forenzičkog pregleda, ali njeno pokretanje nad kompresovanim fajlom može učiniti da fajl izgleda prazno ili da mu se ne može pristupiti dok se njegovi metapodaci ne poprave:
```bash
chflags nocompressed /path/to/file
```
Ugrađeni uslužni program `/usr/bin/afscexpand` može prinudno da proširi transparentno kompresovane datoteke. Zaseban third-party uslužni program `afsctool` takođe može da pregleda ili dekompresuje Apple filesystem compression, ali ga ne treba mešati sa ugrađenom komandom. <sup>[[8]](#references)</sup>


### Zanimljive lokacije konfiguracije (macOS)

| Putanja / lokacija | Svrha / šta konfiguriše | Bezbednosni / napadački potencijal |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Čuva Apple-ove feature-flag plist datoteke koje kontrolišu opcionalna ili eksperimentalna ponašanja u system daemons / frameworks | Ako napadač može da zaobiđe SIP ili dobije privilegije, menjanje ovih datoteka može da omogući skrivene code paths ili onemogući zaštitne mehanizme |
| `/System/Library/CoreServices/systemVersion.plist` | Sadrži macOS metapodatke o verziji (ProductVersion, BuildVersion) koje aplikacije / installers koriste za ograničavanje ponašanja | Izmena može navesti aplikacije ili installers da prihvate nepodržane verzije OS-a ili otključaju funkcije |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Podešavanja aplikacija / sistema | Ako su writable, napadači mogu ubaciti podešavanja koja usmeravaju ponašanje aplikacija, onemogućavaju zaštite ili izazivaju pogrešnu konfiguraciju |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist definicije za background daemons i agents | Ubacivanje ili izmena zlonamernog plist-a (ako permissions to dozvoljavaju) omogućava persistence ili privilege escalations |
| `/etc/hosts` | Mapiranja hostname ↔ IP koja koristi system DNS resolver | Preusmeravanje imena domena, presretanje saobraćaja, spoofing servisa pod lokalnom kontrolom |
| `/etc/sudoers` | Definiše ko može da izvršava komande sa `sudo` i pod kojim uslovima | Oštećen sudoers fajl može nalozima napadača dodeliti root ili neodgovarajuće privilegije |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist definicije lokalnih korisničkih naloga | Menjanje omogućava kreiranje ili izmenu korisničkih naloga, password hashes ili korisničkih metapodataka |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Instaliranje ili izmena kext-ova može dovesti do kontrole na nivou kernela; SIP / signature policies ih strogo štite |
| `/private/var/db/SystemPolicyConfiguration/` | Čuva konfiguraciju za sprovođenje system policy-ja (npr. Gatekeeper, notarization) | Menjanje ovih datoteka može omogućiti zaobilaženje policy checks ili trust rules |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries i config fajlovi | Pogrešna konfiguracija dovodi do slabe SSH bezbednosti, neovlašćenog pristupa ili nesigurnih algoritama |
| `/System/Library/Sandbox/Profiles` | System sandbox profiles (SBPL) koji se koriste za ograničavanje radnji procesa | Zamena ili izmena profila može otvoriti sandbox escape vektore ili oslabiti containment |

> **Napomena**: Mnoge od ovih putanja nalaze se u SIP-protected direktorijumima (npr. `/System`) i zaštićene su od upisivanja, osim ako je SIP disabled ili bypassed.


## Universal Binaries i Mach-O format

Mach-O je native executable format na macOS-u. Universal, odnosno fat, binary objedinjuje više architecture-specific Mach-O slices u jednoj datoteci; posebna stranica objašnjava oba formata:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Dumping macOS memorije

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Rizik datoteka i metapodaci handler-a

LaunchServices, file quarantine i Gatekeeper zajedno utiču na to kako macOS obrađuje preuzete datoteke i bira aplikacije za ekstenzije i URL schemes. Njihove baze podataka i interne resource datoteke menjaju se između izdanja; koristite posebne stranice umesto da privatnu CoreTypes putanju tretirate kao stabilan policy interface:

Na izdanjima koja izlažu legacy CoreTypes risk metadata pod `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, najčešće kategorije su:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: sadržaj koji se smatra dovoljno bezbednim za automatsko otvaranje u okviru odgovarajuće application policy.
- **`LSRiskCategoryNeutral`**: sadržaj koji obično ne pokreće upozorenje i ne otvara se automatski.
- **`LSRiskCategoryUnsafeExecutable`**: izvršni sadržaj za koji korisnik treba da dobije application warning.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: containers, kao što su archives, koji mogu sadržati izvršni sadržaj i zahtevaju dodatnu proveru.

Ovo su implementation details, a ne stabilan public policy API; proverite stvarne metapodatke i Safari/Gatekeeper ponašanje na macOS verziji koja se testira.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log fajlovi

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Sadrži informacije o preuzetim datotekama, kao što je URL sa kojeg su preuzete.
- **Unified log**: Na aktuelnim verzijama macOS-a, sistemske i aplikacione događaje možete upitati pomoću `log show` i `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** i **`/private/var/log/asl/*.asl`**: Legacy logging artifacts koji mogu i dalje biti relevantni na starijim sistemima. Na tim izdanjima, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` konfiguriše `syslogd`; `launchctl list | grep com.apple.syslogd` može pomoći pri utvrđivanju da li je servis učitan.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Čuva nedavno pristupane datoteke i aplikacije kroz "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Legacy preference path povezan sa login items; moderne verzije macOS-a koriste dodatne mehanizme.
- **`$HOME/Library/Logs/DiskUtility.log`**: Legacy Disk Utility log koji može sadržati informacije o diskovima, uključujući USB uređaje.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Podaci o wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy launchd override podaci.

## References

- [1] [Apple - Vodič za programiranje file system-a](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Vodič za programiranje bundle-ova](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - pregled dyld shared cache-a](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Vodič za programiranje file system-a: macOS bezbednost file system-a](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS man stranica](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS man stranica](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS man stranica](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
