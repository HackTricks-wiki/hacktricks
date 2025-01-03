# macOS Datoteke, Fascikle, Binarni & Memorija

{{#include ../../../banners/hacktricks-training.md}}

## Raspored hijerarhije datoteka

- **/Applications**: Instalirane aplikacije bi trebale biti ovde. Svi korisnici će moći da im pristupe.
- **/bin**: Binarne datoteke komandne linije
- **/cores**: Ako postoji, koristi se za čuvanje core dump-ova
- **/dev**: Sve se tretira kao datoteka, tako da ovde možete videti hardverske uređaje.
- **/etc**: Konfiguracione datoteke
- **/Library**: Ovdje se može naći mnogo poddirektorijuma i datoteka povezanih sa preferencama, kešom i logovima. Fascikla Library postoji u root-u i u direktorijumu svakog korisnika.
- **/private**: Nedokumentovano, ali mnoge od pomenutih fascikala su simboličke veze ka privatnom direktorijumu.
- **/sbin**: Osnovne sistemske binarne datoteke (vezane za administraciju)
- **/System**: Datoteka za pokretanje OS X-a. Ovde bi trebali pronaći uglavnom samo Apple specifične datoteke (ne treće strane).
- **/tmp**: Datoteke se brišu nakon 3 dana (to je softverska veza ka /private/tmp)
- **/Users**: Kućni direktorijum za korisnike.
- **/usr**: Konfiguracione i sistemske binarne datoteke
- **/var**: Log datoteke
- **/Volumes**: Montirani diskovi će se ovde pojaviti.
- **/.vol**: Pokretanjem `stat a.txt` dobijate nešto poput `16777223 7545753 -rw-r--r-- 1 username wheel ...` gde je prvi broj ID broj volumena gde datoteka postoji, a drugi je inode broj. Možete pristupiti sadržaju ove datoteke kroz /.vol/ sa tom informacijom pokretanjem `cat /.vol/16777223/7545753`

### Fascikle aplikacija

- **Sistemske aplikacije** se nalaze pod `/System/Applications`
- **Instalirane** aplikacije se obično instaliraju u `/Applications` ili u `~/Applications`
- **Podaci aplikacija** mogu se naći u `/Library/Application Support` za aplikacije koje se pokreću kao root i `~/Library/Application Support` za aplikacije koje se pokreću kao korisnik.
- Daemons **trećih strana** koji **moraju da se pokreću kao root** obično se nalaze u `/Library/PrivilegedHelperTools/`
- **Sandboxed** aplikacije su mapirane u fasciklu `~/Library/Containers`. Svaka aplikacija ima fasciklu nazvanu prema ID-u paketa aplikacije (`com.apple.Safari`).
- **Kernel** se nalazi u `/System/Library/Kernels/kernel`
- **Apple-ove kernel ekstenzije** se nalaze u `/System/Library/Extensions`
- **Kernel ekstenzije trećih strana** se čuvaju u `/Library/Extensions`

### Datoteke sa osetljivim informacijama

MacOS čuva informacije kao što su lozinke na nekoliko mesta:

{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Ranjivi pkg instalateri

{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X Specifične Ekstenzije

- **`.dmg`**: Apple Disk Image datoteke su vrlo česte za instalatere.
- **`.kext`**: Mora da prati specifičnu strukturu i to je OS X verzija drajvera. (to je paket)
- **`.plist`**: Takođe poznat kao property list, čuva informacije u XML ili binarnom formatu.
- Može biti XML ili binarni. Binarne se mogu čitati sa:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple aplikacije koje prate strukturu direktorijuma (to je paket).
- **`.dylib`**: Dinamičke biblioteke (kao Windows DLL datoteke)
- **`.pkg`**: Iste su kao xar (eXtensible Archive format). Komanda za instalaciju može se koristiti za instalaciju sadržaja ovih datoteka.
- **`.DS_Store`**: Ova datoteka se nalazi u svakoj fascikli, čuva atribute i prilagođavanja fascikle.
- **`.Spotlight-V100`**: Ova fascikla se pojavljuje u root direktorijumu svakog volumena na sistemu.
- **`.metadata_never_index`**: Ako se ova datoteka nalazi u root-u volumena, Spotlight neće indeksirati taj volumen.
- **`.noindex`**: Datoteke i fascikle sa ovom ekstenzijom neće biti indeksirane od strane Spotlight-a.
- **`.sdef`**: Datoteke unutar paketa koje specificiraju kako je moguće interagovati sa aplikacijom iz AppleScript-a.

### macOS Paketi

Paket je **direktorijum** koji **izgleda kao objekat u Finder-u** (primer paketa su `*.app` datoteke).

{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Na macOS-u (i iOS-u) sve sistemske deljene biblioteke, kao što su framework-i i dylibs, su **kombinovane u jednu datoteku**, nazvanu **dyld shared cache**. Ovo poboljšava performanse, jer se kod može učitati brže.

Ovo se nalazi u macOS-u u `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` i u starijim verzijama možda ćete moći da pronađete **deljenu keš memoriju** u **`/System/Library/dyld/`**.\
U iOS-u ih možete pronaći u **`/System/Library/Caches/com.apple.dyld/`**.

Slično dyld shared cache-u, kernel i kernel ekstenzije su takođe kompajlirani u kernel keš, koji se učitava prilikom pokretanja.

Da biste izvukli biblioteke iz jedne datoteke dylib shared cache, bilo je moguće koristiti binarni [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) koji možda više ne radi, ali možete koristiti i [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Imajte na umu da čak i ako `dyld_shared_cache_util` alat ne radi, možete proslediti **deljeni dyld binarni fajl Hopper-u** i Hopper će moći da identifikuje sve biblioteke i omogućiti vam da **izaberete koju želite da istražujete**:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Neki ekstraktori neće raditi jer su dylibs prelinkovani sa hardkodiranim adresama, pa bi mogli skakati na nepoznate adrese.

> [!TIP]
> Takođe je moguće preuzeti Shared Library Cache drugih \*OS uređaja u macos-u koristeći emulator u Xcode-u. Biće preuzeti unutar: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, kao: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** koristi syscall **`shared_region_check_np`** da zna da li je SLC mapiran (što vraća adresu) i **`shared_region_map_and_slide_np`** da mapira SLC.

Imajte na umu da čak i ako je SLC pomeren pri prvom korišćenju, svi **procesi** koriste **istu kopiju**, što **eliminiše ASLR** zaštitu ako je napadač mogao da pokrene procese u sistemu. Ovo je zapravo iskorišćeno u prošlosti i ispravljeno sa shared region pager-om.

Branch pools su mali Mach-O dylibs koji kreiraju male prostore između mapiranja slika, što onemogućava interpoziciju funkcija.

### Override SLCs

Korišćenjem env varijabli:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Ovo će omogućiti učitavanje novog shared library cache-a.
- **`DYLD_SHARED_CACHE_DIR=avoid`** i ručno zameniti biblioteke sa symlinkovima na shared cache sa pravim (biće potrebno da ih ekstraktujete).

## Special File Permissions

### Folder permissions

U **folderu**, **read** omogućava **listanje**, **write** omogućava **brisanje** i **pisanje** fajlova u njemu, a **execute** omogućava **prolazak** kroz direktorijum. Dakle, na primer, korisnik sa **read dozvolom nad fajlom** unutar direktorijuma gde **nema execute** dozvolu **neće moći da pročita** fajl.

### Flag modifiers

Postoje neki flagovi koji se mogu postaviti na fajlovima koji će učiniti da se fajl ponaša drugačije. Možete **proveriti flagove** fajlova unutar direktorijuma sa `ls -lO /path/directory`

- **`uchg`**: Poznat kao **uchange** flag će **sprečiti bilo koju akciju** promene ili brisanja **fajla**. Da biste ga postavili, uradite: `chflags uchg file.txt`
- Root korisnik može **ukloniti flag** i izmeniti fajl.
- **`restricted`**: Ovaj flag čini da fajl bude **zaštićen SIP-om** (ne možete dodati ovaj flag na fajl).
- **`Sticky bit`**: Ako direktorijum ima sticky bit, **samo** **vlasnik direktorijuma ili root može preimenovati ili obrisati** fajlove. Obično se postavlja na /tmp direktorijum da bi se sprečilo običnim korisnicima da brišu ili premeste fajlove drugih korisnika.

Svi flagovi se mogu naći u fajlu `sys/stat.h` (pronađite ga koristeći `mdfind stat.h | grep stat.h`) i su:

- `UF_SETTABLE` 0x0000ffff: Mask of owner changeable flags.
- `UF_NODUMP` 0x00000001: Do not dump file.
- `UF_IMMUTABLE` 0x00000002: File may not be changed.
- `UF_APPEND` 0x00000004: Writes to file may only append.
- `UF_OPAQUE` 0x00000008: Directory is opaque wrt. union.
- `UF_COMPRESSED` 0x00000020: File is compressed (some file-systems).
- `UF_TRACKED` 0x00000040: No notifications for deletes/renames for files with this set.
- `UF_DATAVAULT` 0x00000080: Entitlement required for reading and writing.
- `UF_HIDDEN` 0x00008000: Hint that this item should not be displayed in a GUI.
- `SF_SUPPORTED` 0x009f0000: Mask of superuser supported flags.
- `SF_SETTABLE` 0x3fff0000: Mask of superuser changeable flags.
- `SF_SYNTHETIC` 0xc0000000: Mask of system read-only synthetic flags.
- `SF_ARCHIVED` 0x00010000: File is archived.
- `SF_IMMUTABLE` 0x00020000: File may not be changed.
- `SF_APPEND` 0x00040000: Writes to file may only append.
- `SF_RESTRICTED` 0x00080000: Entitlement required for writing.
- `SF_NOUNLINK` 0x00100000: Item may not be removed, renamed or mounted on.
- `SF_FIRMLINK` 0x00800000: File is a firmlink.
- `SF_DATALESS` 0x40000000: File is dataless object.

### **File ACLs**

File **ACLs** sadrže **ACE** (Access Control Entries) gde se mogu dodeliti **granularne dozvole** različitim korisnicima.

Moguće je dodeliti **direktorijumu** ove dozvole: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
A za **fajl**: `read`, `write`, `append`, `execute`.

Kada fajl sadrži ACLs, naći ćete **"+" kada listate dozvole kao u**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Možete **pročitati ACL-ove** datoteke sa:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Možete pronaći **sve datoteke sa ACL-ovima** sa (ovo je veoma sporo):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Proširene Atributi

Prošireni atributi imaju ime i bilo koju željenu vrednost, a mogu se videti koristeći `ls -@` i manipulisati koristeći komandu `xattr`. Neki uobičajeni prošireni atributi su:

- `com.apple.resourceFork`: Kompatibilnost sa resursnim fork-ovima. Takođe vidljivo kao `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Mehanizam karantina Gatekeeper-a (III/6)
- `metadata:*`: MacOS: razni metapodaci, kao što su `_backup_excludeItem`, ili `kMD*`
- `com.apple.lastuseddate` (#PS): Datum poslednje upotrebe datoteke
- `com.apple.FinderInfo`: MacOS: Informacije o Finder-u (npr., boje oznaka)
- `com.apple.TextEncoding`: Određuje kodiranje teksta ASCII datoteka
- `com.apple.logd.metadata`: Koristi se od strane logd na datotekama u `/var/db/diagnostics`
- `com.apple.genstore.*`: Generacijsko skladištenje (`/.DocumentRevisions-V100` u korenu datotečnog sistema)
- `com.apple.rootless`: MacOS: Koristi se od strane System Integrity Protection za označavanje datoteke (III/10)
- `com.apple.uuidb.boot-uuid`: logd oznake boot epoha sa jedinstvenim UUID
- `com.apple.decmpfs`: MacOS: Transparentna kompresija datoteka (II/7)
- `com.apple.cprotect`: \*OS: Podaci o enkripciji po datoteci (III/11)
- `com.apple.installd.*`: \*OS: Metapodaci koje koristi installd, npr., `installType`, `uniqueInstallID`

### Resursni Fork-ovi | macOS ADS

Ovo je način da se dobiju **Alternativni Podaci Strimovi u MacOS** mašinama. Možete sačuvati sadržaj unutar proširenog atributa pod nazivom **com.apple.ResourceFork** unutar datoteke tako što ćete ga sačuvati u **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Možete **pronaći sve datoteke koje sadrže ovu proširenu atribut** sa:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Proširena atribut `com.apple.decmpfs` označava da je datoteka pohranjena enkriptovana, `ls -l` će prijaviti **veličinu 0** i kompresovani podaci su unutar ovog atributa. Kada god se datoteka pristupi, biće dekriptovana u memoriji.

Ovaj atribut se može videti sa `ls -lO` označen kao kompresovan jer su kompresovane datoteke takođe označene oznakom `UF_COMPRESSED`. Ako se kompresovana datoteka ukloni sa ovom oznakom `chflags nocompressed </path/to/file>`, sistem neće znati da je datoteka bila kompresovana i stoga neće moći da dekompresuje i pristupi podacima (misliće da je zapravo prazna).

Alat afscexpand može se koristiti za prisilno dekompresovanje datoteke.

## **Univerzalne binarne datoteke &** Mach-o Format

Mac OS binarne datoteke obično se kompajliraju kao **univerzalne binarne datoteke**. **Univerzalna binarna datoteka** može **podržavati više arhitektura u istoj datoteci**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}

## macOS Procesna Memorija

## macOS iskopavanje memorije

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Kategorija Rizika Datoteka Mac OS

Direktorij `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` je mesto gde se čuva informacija o **riziku povezanom sa različitim ekstenzijama datoteka**. Ovaj direktorij kategorizuje datoteke u različite nivoe rizika, utičući na to kako Safari obrađuje ove datoteke prilikom preuzimanja. Kategorije su sledeće:

- **LSRiskCategorySafe**: Datoteke u ovoj kategoriji se smatraju **potpuno sigurnim**. Safari će automatski otvoriti ove datoteke nakon što budu preuzete.
- **LSRiskCategoryNeutral**: Ove datoteke dolaze bez upozorenja i **ne otvaraju se automatski** od strane Safarija.
- **LSRiskCategoryUnsafeExecutable**: Datoteke pod ovom kategorijom **pokreću upozorenje** koje ukazuje da je datoteka aplikacija. Ovo služi kao mera bezbednosti da upozori korisnika.
- **LSRiskCategoryMayContainUnsafeExecutable**: Ova kategorija je za datoteke, kao što su arhive, koje mogu sadržati izvršnu datoteku. Safari će **pokrenuti upozorenje** osim ako ne može da potvrdi da su svi sadržaji sigurni ili neutralni.

## Log datoteke

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Sadrži informacije o preuzetim datotekama, kao što je URL sa kojeg su preuzete.
- **`/var/log/system.log`**: Glavni log OSX sistema. com.apple.syslogd.plist je odgovoran za izvršavanje syslogging-a (možete proveriti da li je on onemogućen tražeći "com.apple.syslogd" u `launchctl list`).
- **`/private/var/log/asl/*.asl`**: Ovo su Apple sistemski logovi koji mogu sadržati zanimljive informacije.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Čuva nedavno pristupane datoteke i aplikacije kroz "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Čuva stavke koje se pokreću prilikom pokretanja sistema.
- **`$HOME/Library/Logs/DiskUtility.log`**: Log datoteka za DiskUtility aplikaciju (informacije o diskovima, uključujući USB).
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Podaci o bežičnim pristupnim tačkama.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista deaktiviranih demona.

{{#include ../../../banners/hacktricks-training.md}}
