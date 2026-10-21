# macOS fajlovi, fascikle, binarni fajlovi i memorija

{{#include ../../../banners/hacktricks-training.md}}

## Hijerarhijski raspored fajl sistema

Apple dokumentuje macOS fajl sistem kao hijerarhiju sistemskih, lokalnih, mrežnih i korisničkih domena. Tačan sadržaj se razlikuje u zavisnosti od izdanja OS-a, a sistemske lokacije su sve češće zaštićene ili sintetički generisane. <sup>[[1]](#references)</sup>

- **/Applications**: Ovde bi trebalo da se nalaze instalirane aplikacije. Svi korisnici mogu da im pristupe.
- **/bin**: Binarni fajlovi komandne linije
- **/cores**: Ako postoji, koristi se za čuvanje core dump-ova
- **/dev**: Sve se tretira kao fajl, pa ovde možete videti uređaje hardvera.
- **/etc**: Konfiguracioni fajlovi
- **/Library**: Ovde se nalazi mnogo poddirektorijuma i fajlova povezanih sa podešavanjima, kešom i logovima. Fascikla Library postoji u korenom direktorijumu i u direktorijumu svakog korisnika.
- **/private**: Nije dokumentovana, ali mnoge pomenute fascikle su simboličke veze ka direktorijumu private.
- **/sbin**: Osnovni sistemski binarni fajlovi (povezani sa administracijom)
- **/System**: Fajlovi potrebni za macOS; ovo stablo prvenstveno sadrži komponente koje obezbeđuje Apple.
- **/tmp**: Privremeni fajlovi (simbolička veza ka `/private/tmp`). Istorijski gledano, stare privremene fajlove su obično periodično brisala instalirana izdanja sistema, što se ponekad opisivalo kao brisanje na svaka tri dana. Trenutni interval čišćenja zavisi od sistema i smernica; ne oslanjajte se na to da će podaci tamo ostati sačuvani.
- **/Users**: Početni direktorijum korisnika.
- **/usr**: Konfiguracioni i sistemski binarni fajlovi
- **/var**: Fajlovi logova
- **/Volumes**: Ovde se pojavljuju montirani volumeni.
- **/.vol**: Pokretanjem `stat a.txt` dobijate nešto poput `16777223 7545753 -rw-r--r-- 1 username wheel ...`, gde je prvi broj ID volumena na kom se fajl nalazi, a drugi broj inode. Sadržaju ovog fajla možete pristupiti preko /.vol/ koristeći te informacije i pokretanjem `cat /.vol/16777223/7545753`

### Fascikle aplikacija

- **Sistemske aplikacije** se nalaze u `/System/Applications`
- **Instalirane** aplikacije se obično instaliraju u `/Applications` ili `~/Applications`
- **Podaci aplikacija** mogu se naći u `/Library/Application Support` za aplikacije koje rade kao root i u `~/Library/Application Support` za aplikacije koje rade kao korisnik.
- **Daemoni** aplikacija trećih strana koji **moraju da rade kao root** obično se nalaze u `/Library/PrivilegedHelperTools/`.
- **Sandboxed** aplikacije su mapirane u fasciklu `~/Library/Containers`. Svaka aplikacija ima fasciklu čiji naziv odgovara bundle ID-u aplikacije (`com.apple.Safari`).
- **Kernel** se nalazi u `/System/Library/Kernels/kernel`
- **Apple-ova kernel extensions** nalaze se u `/System/Library/Extensions`
- **Kernel extensions** trećih strana čuvaju se u `/Library/Extensions`

### Fajlovi sa osetljivim informacijama

macOS čuva osetljive informacije, uključujući akreditive, na nekoliko lokacija:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Ranjivi pkg instaleri


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Za razliku između Data volumena koji se može menjati i zapečaćenog System volumena vidljivog u ovoj hijerarhiji, pogledajte [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Ekstenzije specifične za OS X

- **`.dmg`**: Apple Disk Image fajlovi su veoma česti za instalere.
- **`.kext`**: Mora da prati određenu strukturu i predstavlja OS X verziju drajvera. (to je bundle)
- **`.plist`**: Property list čuva strukturisane informacije u XML ili binarnom formatu.
  - Može biti u XML ili binarnom formatu. Binarni fajlovi mogu se čitati pomoću:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Application bundle koji prati standardnu strukturu direktorijuma macOS-a.
- **`.dylib`**: Dinamičke biblioteke (kao Windows DLL fajlovi)
- **`.pkg`**: Moderni flat paketi za instalaciju su XAR arhive, ali `.pkg` je format instalera, a ne sinonim za XAR. Stariji instalacioni paketi u bundle formatu su direktorijumi. Pogledajte [macOS installers](macos-installers-abuse.md) za strukturu paketa i njihovu proveru. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Ovaj fajl se nalazi u svakoj fascikli i čuva atribute i prilagođavanja te fascikle.
- **`.Spotlight-V100`**: Ova fascikla se pojavljuje u korenom direktorijumu svakog volumena na sistemu.
- **`.metadata_never_index`**: Ako se ovaj fajl nalazi u korenom direktorijumu volumena, Spotlight neće indeksirati taj volumen.
- **`.noindex`**: Fajlovi i fascikle sa ovom ekstenzijom neće biti indeksirani pomoću Spotlight-a.
- **`.sdef`**: Fajl definicije skriptovanja koji opisuje kako AppleScript može da komunicira sa aplikacijom.

### macOS Bundles

Bundle je direktorijum sa standardizovanom hijerarhijom koji Finder može da prikaže kao jedan objekat; application bundle-ovi koriste ekstenziju `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Deljeni keš biblioteka dyld (SLC)

U macOS-u i iOS-u, često korišćene sistemske biblioteke i framework-ovi se unapred povezuju u **dyld shared cache**, čime se poboljšavaju performanse pokretanja aplikacija. Iako se tretira kao jedan logički keš, aktuelna izdanja mogu da ga čuvaju kao glavni keš zajedno sa više datoteka podkeša, umesto kao doslovno jednu datoteku. Njegov format i lokacija su detalji implementacije koji se menjaju između izdanja OS-a. <sup>[[3]](#references)</sup>

U macOS-u se nalazi u `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, a u starijim verzijama možda ćete moći da pronađete **shared cache** u **`/System/Library/dyld/`**.\
U iOS-u se nalazi u **`/System/Library/Caches/com.apple.dyld/`**.

Slično dyld shared cache-u, kernel i kernel extensions se takođe kompajliraju u kernel cache, koji se učitava prilikom pokretanja sistema.

Starija izdanja mogla su se izdvojiti pomoću [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Ta verzija možda ne podržava aktuelne formate keša; druga mogućnost je [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Imajte na umu da, čak i ako alat `dyld_shared_cache_util` ne radi, možete proslediti **deljeni dyld binary alatu Hopper**, koji će moći da prepozna sve biblioteke i omogući vam da **izaberete koju** želite da istražite:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Neki alati za izdvajanje neće raditi jer su dylib-ovi unapred povezani sa hardkodiranim adresama, pa zato možda skaču na nepoznate adrese.

> [!TIP]
> Shared Library Cache drugih uređaja sa \*OS-ovima takođe možete preuzeti u macOS-u pomoću emulatora u Xcode-u. Biće preuzeti u direktorijum: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, kao što je:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapiranje SLC-a

**`dyld`** koristi syscall **`shared_region_check_np`** da proveri da li je SLC mapiran (što vraća adresu), a **`shared_region_map_and_slide_np`** da mapira SLC.

Imajte na umu da, čak i ako se SLC pomeri pri prvom korišćenju, svi **procesi** koriste **istu kopiju**, čime se **ukida zaštita ASLR-a** ako je napadač mogao da pokreće procese u sistemu. Ovo je ranije iskorišćeno i potom ispravljeno pomoću shared region pager-a.

Branch pools su mali Mach-O dylib-ovi koji stvaraju male prostore između mapiranja slika i onemogućavaju interponovanje funkcija.

### Ograničenja okruženja shared cache-a

`DYLD_SHARED_CACHE_DIR` označava direktorijum keša, dok `DYLD_SHARED_REGION` bira režim shared region-a. Ranije navođenje `DYLD_DHARED_REGION` bilo je nevažeće, a `avoid` nije dozvoljena vrednost za `DYLD_SHARED_CACHE_DIR`. Trenutni dyld dozvoljava režim `private` samo uz AMFI dozvolu za korišćenje prilagođenih shared cache-ova, tako da samo postavljanje promenljivih okruženja ne znači da proces može da učita zamenski keš. <sup>[[10]](#references)</sup>

## Posebne dozvole za datoteke

### Dozvole za direktorijume

Za direktorijum, dozvola **read** omogućava prikazivanje unosa, **write** omogućava kreiranje ili uklanjanje unosa, a **execute** omogućava pristupanje kroz direktorijum. Zato korisnik koji može da čita datoteku, ali ne može da pristupi nekom nadređenom direktorijumu, ne može da pristupi toj datoteci pomoću putanje. <sup>[[4]](#references)</sup>

### Modifikatori zastavica

Datoteke mogu imati zastavice koje menjaju njihovo ponašanje. Zastavice u direktorijumu možete pregledati pomoću `ls -lO /path/directory`.

- **`uchg`**: Poznata kao zastavica **uchange**, ona **sprečava svaku radnju** kojom se menja ili briše **datoteka**. Postavite je ovako: `chflags uchg file.txt`
  - Vlasnik datoteke ili root mogu da uklone ovu **korisničku** zastavicu pomoću `chflags nouchg file.txt`; ona ne štiti od njih. Odvojena nepromenljiva **sistemska** zastavica (`schg`) dostupna je samo root korisniku. <sup>[[11]](#references)</sup>
- **`restricted`**: Ova zastavica štiti datoteku pomoću **SIP-a** (ne možete da dodate ovu zastavicu datoteci).
- **`Sticky bit`**: U direktorijumu sa postavljenim sticky bit-om samo vlasnik datoteke, vlasnik direktorijuma ili root mogu da preimenuju ili obrišu unos. Obično je omogućen za `/tmp` kako bi sprečio korisnike da brišu ili premeštaju datoteke drugih korisnika.

Sve zastavice možete pronaći u datoteci `sys/stat.h` (pronađite je pomoću `mdfind stat.h | grep stat.h`):

- `UF_SETTABLE` 0x0000ffff: Maska zastavica koje vlasnik može da menja.
- `UF_NODUMP` 0x00000001: Ne uključivati datoteku u dump.
- `UF_IMMUTABLE` 0x00000002: Datoteka se ne može menjati.
- `UF_APPEND` 0x00000004: U datoteku se može samo dodavati sadržaj.
- `UF_OPAQUE` 0x00000008: Direktorijum je neproziran u odnosu na union.
- `UF_COMPRESSED` 0x00000020: Datoteka je kompresovana (na nekim sistemima datoteka).
- `UF_TRACKED` 0x00000040: Za datoteke sa ovom zastavicom nema obaveštenja o brisanju/preimenovanju.
- `UF_DATAVAULT` 0x00000080: Za čitanje i pisanje potrebna je entitlement dozvola.
- `UF_HIDDEN` 0x00008000: Nagoveštaj da ovu stavku ne treba prikazivati u grafičkom interfejsu.
- `SF_SUPPORTED` 0x009f0000: Maska zastavica koje podržava superuser.
- `SF_SETTABLE` 0x3fff0000: Maska zastavica koje superuser može da menja.
- `SF_SYNTHETIC` 0xc0000000: Maska sintetičkih zastavica sistema, koje su samo za čitanje.
- `SF_ARCHIVED` 0x00010000: Datoteka je arhivirana.
- `SF_IMMUTABLE` 0x00020000: Datoteka se ne može menjati.
- `SF_APPEND` 0x00040000: U datoteku se može samo dodavati sadržaj.
- `SF_RESTRICTED` 0x00080000: Za pisanje je potrebna entitlement dozvola.
- `SF_NOUNLINK` 0x00100000: Stavka se ne može ukloniti, preimenovati niti montirati preko nje.
- `SF_FIRMLINK` 0x00800000: Datoteka je firmlink.
- `SF_DATALESS` 0x40000000: Datoteka je objekat bez lokalnih podataka.

### **ACL-ovi datoteka**

**ACL-ovi** datoteka sadrže **ACE** (stavke za kontrolu pristupa) kojima se različitim korisnicima mogu dodeliti **preciznije dozvole**.

Direktorijumu je moguće dodeliti sledeće dozvole: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Datoteci se mogu dodeliti: `read`, `write`, `append` i `execute`.

Kada datoteka sadrži ACL-ove, prilikom prikazivanja dozvola videćete **znak „+“, kao u primeru**:

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

Prošireni atributi su imenovane vrednosti metapodataka koje se čuvaju odvojeno od običnih atributa datoteke. Prikažite ih pomoću `ls -l@`, a pregledajte ili izmenite pomoću `xattr`. <sup>[[5]](#references)</sup> Neki uobičajeni prošireni atributi su:

- `com.apple.resourceFork`: Kompatibilnost sa resource fork-om. Vidljiv je i kao `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS Gatekeeper metapodaci o karantinu
- `metadata:*`: macOS metapodaci, kao što su `_backup_excludeItem` ili `kMD*`
- `com.apple.lastuseddate` (#PS): Datum poslednje upotrebe datoteke
- `com.apple.FinderInfo`: macOS Finder informacije, kao što su oznake u boji
- `com.apple.TextEncoding`: Određuje kodiranje teksta ASCII tekstualnih datoteka
- `com.apple.logd.metadata`: Koristi ga logd za datoteke u `/var/db/diagnostics`
- `com.apple.genstore.*`: Generaciono skladištenje (`/.DocumentRevisions-V100` u korenu sistema datoteka)
- `com.apple.rootless`: macOS metapodaci povezani sa zaštitom System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Oznake programa logd za epohe pokretanja, sa jedinstvenim UUID-om
- `com.apple.decmpfs`: macOS metapodaci za transparentnu kompresiju datoteka
- `com.apple.cprotect`: \*OS: Podaci o šifrovanju po datoteci (III/11)
- `com.apple.installd.*`: \*OS: Metapodaci koje koristi installd, npr. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource fork-ovi pružaju alternativni tok podataka u macOS-u. Sadržaj se može čuvati u proširenom atributu `com.apple.ResourceFork` i pristupati mu preko `file/..namedfork/rsrc`.

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

Prošireni atribut `com.apple.decmpfs` čuva metapodatke za transparentnu kompresiju; ne ukazuje na šifrovanje. U zavisnosti od formata kompresije, komprimovani podaci mogu biti sačuvani u atributu ili u resource forku i transparentno se dekompresuju prilikom čitanja.

Zastavica `UF_COMPRESSED` prikazuje se kao `compressed` u izlazu komande `ls -lO`. Nemojte je ručno uklanjati: sistem bi zbog toga mogao pogrešno da protumači komprimovani prikaz.

Komanda koja uklanja zastavicu prikazana je ovde jer je korisna tokom forenzičke analize, ali njeno pokretanje nad komprimovanom datotekom može učiniti da datoteka izgleda prazno ili da joj se ne može pristupiti dok se njeni metapodaci ne poprave:

```bash
chflags nocompressed /path/to/file
```

Ugrađeni uslužni program `/usr/bin/afscexpand` može da nametne dekompresiju transparentno kompresovanih datoteka. Zasebni uslužni program treće strane `afsctool` takođe može da pregleda ili dekompresuje kompresiju Apple filesystema, ali ne treba ga mešati sa ugrađenom komandom. <sup>[[8]](#references)</sup>


### Zanimljive lokacije konfiguracije (macOS)

| Putanja / lokacija | Namena / šta konfiguriše | Bezbednost / potencijal za napad |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Čuva Appleove plist datoteke sa oznakama funkcija koje kontrolišu opcionalna ili eksperimentalna ponašanja sistemskih daemona / frameworkova | Ako napadač može da zaobiđe SIP ili stekne privilegije, izmenom ovih datoteka može da omogući skrivene putanje izvršavanja koda ili onemogući zaštitne mere |
| `/System/Library/CoreServices/systemVersion.plist` | Sadrži metapodatke o verziji macOS-a (ProductVersion, BuildVersion) koje aplikacije / instalacioni programi koriste za određivanje ponašanja | Izmena može da navede aplikacije ili instalacione programe da prihvate nepodržane verzije OS-a ili otključaju funkcije |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Podešavanja za aplikacije / ceo sistem | Ako napadači imaju dozvolu za upis, mogu da ubace podešavanja koja usmeravaju ponašanje aplikacija, onemogućavaju zaštite ili izazivaju pogrešnu konfiguraciju |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist definicije pozadinskih daemona i agenata | Ubacivanje ili izmena zlonamernog plist-a (ako dozvole to omogućavaju) pruža mogućnost za održavanje pristupa ili eskalaciju privilegija |
| `/etc/hosts` | Mapiranja imena hostova ↔ IP adresa koja koristi sistemski DNS razrešivač | Preusmeravanje naziva domena, presretanje saobraćaja i lažiranje usluga pod lokalnom kontrolom |
| `/etc/sudoers` | Definiše ko može da pokreće komande pomoću `sudo` i pod kojim uslovima | Oštećena sudoers datoteka može napadačkim nalozima da dodeli root ili neprimerene privilegije |
| `/private/var/db/dslocal/nodes/Default/users/` | Plist definicije lokalnih korisničkih naloga | Izmenama se mogu kreirati ili menjati korisnički nalozi, hash vrednosti lozinki ili metapodaci korisnika |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel ekstenzije / upravljački programi | Instalacija ili izmena kext-ova može dovesti do kontrole na nivou kernela; SIP / pravila za potpisivanje ih snažno štite |
| `/private/var/db/SystemPolicyConfiguration/` | Čuva konfiguraciju za sprovođenje sistemskih pravila (npr. Gatekeeper, notarizacija) | Izmene ovih datoteka mogu omogućiti zaobilaženje provera pravila ili pravila poverenja |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Pomoćni SSH binarni fajlovi i konfiguracione datoteke | Pogrešna konfiguracija dovodi do slabe SSH bezbednosti, neovlašćenog pristupa ili nesigurnih algoritama |
| `/System/Library/Sandbox/Profiles` | Sistemski sandbox profili (SBPL) koji se koriste za ograničavanje radnji procesa | Zamena ili izmena profila može stvoriti mogućnosti za bekstvo iz sandboxa ili oslabiti izolaciju |

> **Napomena**: Mnoge od ovih putanja nalaze se u direktorijumima zaštićenim SIP-om (npr. `/System`), a upis u njih nije dozvoljen osim ako SIP nije onemogućen ili zaobiđen.  


## Univerzalni binarni fajlovi i Mach-O format

Mach-O je izvorni format izvršnih fajlova u macOS-u. Univerzalni, odnosno fat binarni fajl objedinjuje više Mach-O isečaka specifičnih za različite arhitekture u jednoj datoteci; posebna stranica objašnjava oba formata:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Ispisivanje memorije macOS-a

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Rizik datoteka i metapodaci rukovalaca

LaunchServices, karantin datoteka i Gatekeeper zajedno utiču na to kako macOS obrađuje preuzete datoteke i bira aplikacije za ekstenzije i URL šeme. Njihove baze podataka i interne datoteke resursa menjaju se između izdanja; koristite posebne stranice umesto da privatnu putanju CoreTypes tretirate kao stabilan interfejs za pravila:

U izdanjima koja izlažu zastarele metapodatke o riziku CoreTypes-a u putanji `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, najčešće kategorije su:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: sadržaj koji se smatra dovoljno bezbednim za automatsko otvaranje u okviru važećih pravila aplikacije.
- **`LSRiskCategoryNeutral`**: sadržaj koji obično ne pokreće upozorenje i ne otvara se automatski.
- **`LSRiskCategoryUnsafeExecutable`**: izvršni sadržaj za koji korisniku treba prikazati upozorenje aplikacije.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: kontejneri, poput arhiva, koji mogu sadržati izvršni sadržaj i zahtevaju dodatnu proveru.

Ovo su detalji implementacije, a ne stabilan javni API za pravila; proverite stvarne metapodatke i ponašanje Safarija/Gatekeeper-a u verziji macOS-a koja se testira.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Datoteke evidencije

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Sadrži informacije o preuzetim datotekama, kao što je URL sa kog su preuzete.
- **Unified log**: U aktuelnim verzijama macOS-a sistemske događaje i događaje aplikacija pretražujte komandama `log show` i `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** i **`/private/var/log/asl/*.asl`**: Zastareli artefakti evidencije koji mogu biti relevantni na starijim sistemima. U tim izdanjima, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` konfiguriše `syslogd`; komanda `launchctl list | grep com.apple.syslogd` može pomoći da se utvrdi da li je usluga učitana.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Čuva podatke o nedavno pristupanim datotekama i aplikacijama preko „Finder“-a.
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Zastarela putanja za podešavanja povezana sa stavkama za prijavu; novije verzije macOS-a koriste dodatne mehanizme.
- **`$HOME/Library/Logs/DiskUtility.log`**: Zastarela evidencija Disk Utility-ja koja može sadržati informacije o diskovima, uključujući USB uređaje.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Podaci o bežičnim pristupnim tačkama.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Zastareli podaci o launchd override-ima.



## References

- [1] [Apple - Vodič za programiranje sistema datoteka](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Vodič za programiranje bundle-ova](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - Pregled deljenog dyld keša](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Vodič za programiranje sistema datoteka: bezbednost sistema datoteka macOS-a](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - stranica priručnika za macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - stranica priručnika za macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - stranica priručnika za macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums - Raspakivanje Apple arhiva](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Bezbednost shell skripti: posebne oznake dozvola za datoteke](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Zadaci potpisivanja koda: instalacioni paketi](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
