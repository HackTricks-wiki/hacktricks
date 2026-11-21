# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**directory** के लिए, तीन permission bits का अर्थ regular file से अलग होता है। `chmod(1)` directory पर लागू होने पर execute bit को "**search**" कहता है:<sup>[[2]](#references)</sup>

> `0100` Files के लिए, owner को execution की अनुमति देता है। Directories के लिए, owner को directory में **search** करने की अनुमति देता है।

- **read** - आप directory entries को **enumerate** कर सकते हैं (नामों की सूची देख सकते हैं)।
- **write** - आप directory में entries **create, rename और delete** कर सकते हैं। ध्यान दें कि यह *containing* directory का गुण है, file का नहीं: आप ऐसी file delete कर सकते हैं जिसे आप पढ़ या लिख नहीं सकते, बशर्ते उसकी parent directory में write करने की अनुमति हो।
  - **subdirectory** को delete करने के लिए उसका खाली होना ज़रूरी है, जिसके लिए उसके अंदर की हर चीज़ हटाने के पर्याप्त अधिकार भी चाहिए।
  - अगर directory में **sticky bit** (`S_ISVTX`, जैसे `/tmp`) है, तो यह प्रतिबंधित होता है — POSIX के अनुसार, कोई process उसमें files को केवल तभी remove या rename कर सकती है, जब वह file की owner हो, directory की owner हो, या उसके पास उपयुक्त privileges हों।<sup>[[1]](#references)</sup>
- **execute / search** - आपको directory को **traverse** करने की अनुमति होती है। Pathname resolution हर component को "उस directory में ढूँढ़ता है जिसे उसका predecessor निर्दिष्ट करता है", इसलिए path prefix के किसी भी एक component पर search अधिकार खोने से उसके नीचे की हर चीज़ path के ज़रिए पहुँच से बाहर हो जाती है, भले ही leaf file world-readable हो।<sup>[[1]](#references)</sup>

### खतरनाक Combinations

**root के स्वामित्व वाली file/folder को overwrite करने के लिए**, लेकिन:

- Path में एक parent **directory owner** user है
- Path में एक parent **directory owner**, **write access** वाला **users group** है
- किसी users **group** को **file** पर **write** access है

ऊपर दिए गए किसी भी combination में, attacker expected path पर **sym/hard link** **inject** करके privileged arbitrary write हासिल कर सकता है।

### Folder root R+X का विशेष मामला

यह ऊपर दिए गए pathname-resolution नियम का सीधा परिणाम है। अगर किसी **directory में केवल root को R+X की अनुमति** है, तो उसमें मौजूद files बाकी सभी के लिए *path* के ज़रिए पहुँच से बाहर होती हैं — लेकिन **files के अपने permission bits फिर भी permissive हो सकते हैं**। रास्ते में केवल directory ही बाधा होती है।

इसलिए, कोई भी primitive जो file को उस directory से **बाहर निकालने** देता है — जैसे कोई privileged process, जो attacker द्वारा चुने गए path को ऐसी जगह **move/rename/copy** करती है जहाँ तक आप traverse कर सकते हैं — arbitrary read में बदल जाता है, और file के अपने mode को हराने की कभी ज़रूरत नहीं पड़ती:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

ऐसे privileged file movers (installers, log rotators, crash/diagnostic collectors, backup और "export" features) ढूँढें, जो कम privileges वाले user से source path स्वीकार करते हैं।

## Symbolic Link / Hard Link

### Permissive file/folder

अगर कोई privileged process ऐसे **file** में data लिख रहा है जिसे **कम privileges वाला user नियंत्रित** कर सकता है, या जिसे पहले **कम privileges वाले user ने बनाया** हो, तो user उसे Symbolic या Hard link के ज़रिए किसी दूसरी file की ओर **point** कर सकता है और privileged process उस file में लिखेगा।

दूसरे sections में देखें कि attacker privileges escalate करने के लिए **arbitrary write का दुरुपयोग** कहाँ कर सकता है।

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) के अनुसार: *"अगर mask में `O_NOFOLLOW` का इस्तेमाल किया गया है और `open()` को दी गई target file एक symbolic link है, तो `open()` fail हो जाएगा।"* सिर्फ **अंतिम** component की जाँच होती है — हर **बीच के** component को अब भी resolve और follow किया जाता है। इसलिए `O_NOFOLLOW` से write को "protect" करने वाला developer, target path की किसी भी **parent directory** में symlink लगाकर अब भी हमले का शिकार हो सकता है।<sup>[[3]](#references)</sup>

इसी man page में उन flags का दस्तावेज़ है जो इस कमी को सचमुच दूर करते हैं:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"अगर ... `open()` को दिए गए path का कोई भी component symbolic link है, तो `open()` fail हो जाएगा।"*
- **`O_RESOLVE_BENEATH`** — *"अगर ... path resolution, fd से जुड़ी directory से बाहर निकलती है, तो `openat()` fail हो जाएगा।"*

अन्यथा, पहले से validate किए गए directory FD के सापेक्ष `openat()` का इस्तेमाल करना, या `realpath()` के बाद दोबारा validation करना, path के बीच में symlink बदलने से रोकने के बाकी तरीके हैं।

## .fileloc

**`.fileloc`** extension वाली files दूसरी applications या binaries की ओर point कर सकती हैं, इसलिए उन्हें खोलने पर वही application/binary execute होगी।\
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

अगर `open` को कॉल करते समय `O_CLOEXEC` फ़्लैग नहीं दिया जाता, तो फ़ाइल डिस्क्रिप्टर child process को विरासत में मिलता है। इसलिए, अगर कोई privileged process privileged फ़ाइल खोलता है और attacker के नियंत्रण वाला process execute करता है, तो attacker को **privileged फ़ाइल का FD विरासत में मिलेगा**।

इसका canonical example **OS X 10.10 में `DYLD_PRINT_TO_FILE` LPE** है ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` ने **restricted (suid root) binaries** में भी `DYLD_PRINT_TO_FILE=/path` को स्वीकार किया, क्योंकि उस विशेष variable को `processDyldEnvironmentVariable()` के बाहर parse किया गया था।
- इसने `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` चलाया, इसलिए इसने **किसी भी मनमाने path पर root-owned फ़ाइल बनाई**।
- FD को **कभी बंद नहीं किया गया और उसमें close-on-exec फ़्लैग भी नहीं था**, इसलिए suid binary के हर child को **root-owned फ़ाइल का writable FD विरासत में मिला**।
- उदाहरण के लिए, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` चलाने और फिर child में विरासत में मिले FD नंबर को पढ़ने से मनमाने root-owned writes संभव हुए; `fcntl(fd, F_SETFL, 0)` ने `O_APPEND` को भी साफ़ कर दिया, जिससे append करने के बजाय overwrite किया जा सकता था।

यही तरीका उन सभी स्थितियों में दिखता है जहाँ कोई privileged process आपके नियंत्रण वाली चीज़ को `exec` करने **से पहले** फ़ाइल खोलता है (helper tools, `$EDITOR` के ज़रिए चलाए गए `crontab`-style editors, env-var path से खोली गई log/debug फ़ाइलें...)। विरासत में मिले FDs की सूची इस तरह बनाएँ:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

`2` से ऊपर की कोई भी चीज़, जो ऐसी फ़ाइल की ओर संकेत करती है जिसे आप स्वयं नहीं खोल सकते, एक arbitrary-write (या arbitrary-read) primitive है।

## quarantine xattrs tricks से बचें

### इसे हटाएँ

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable flag

यदि किसी file/folder में यह immutable attribute हो, तो उस पर xattr लगाना संभव नहीं होगा.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### xattr support के बिना फ़ाइल सिस्टम

macOS जिन फ़ाइल सिस्टम को mount कर सकता है, उनमें से हर एक **extended attributes** को मूल रूप से store नहीं करता। HFS+ और APFS ऐसा करते हैं; **FAT32, exFAT और (अधिकांश) NFS mounts ऐसा नहीं करते** — macOS इन्हें `._<filename>` नाम की **AppleDouble** side file लिखकर emulate करता है ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

quarantine के लिए यह मायने रखता है, क्योंकि xattr तभी बना रहता है जब उसे उसी volume से वास्तव में **लिखा और वापस पढ़ा** जा सके:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

यदि volume को बाद में ऐसे path पर पढ़ा जाता है जो `._` companion को अनदेखा करता है (या companion को हटाया/डिलीट कर दिया जाता है), तो फ़ाइल **quarantine flag के बिना** आती है — और एक unquarantined `.app` ही App Sandbox से बाहर निकलने के लिए पर्याप्त है, जैसा कि [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) में बताया गया है।

### writeextattr ACL और AppleDouble quarantine व्यवहार

`writeextattr` ACL उदाहरण, `com.apple.acl.text` AppleDouble mechanism, और sidecar बनाने व उसे validate करने के चरणों के लिए, [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md) देखें।

## Signature checks को bypass करना

### Platform binaries checks को bypass करना

कुछ security checks यह जाँचते हैं कि binary एक **platform binary** है या नहीं, उदाहरण के लिए, XPC service से connect करने की अनुमति देने के लिए। हालाँकि, जैसा कि https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ में bypass के बारे में बताया गया है, platform binary (जैसे /bin/ls) प्राप्त करके और `DYLD_INSERT_LIBRARIES` env variable का उपयोग करके dyld के ज़रिए exploit inject करके इस check को bypass करना संभव है।<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` और `CS_FORCED_LV` flags को bypass करना

किसी executing binary के लिए इस तरह के code का उपयोग करके checks bypass करने हेतु अपने flags को modify करना संभव है:<sup>[[7]](#references)</sup>

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

Bundles में **`_CodeSignature/CodeResources`** फ़ाइल होती है, जिसमें **bundle** की हर **file** का **hash** होता है। ध्यान दें कि CodeResources का hash executable में भी **embedded** होता है, इसलिए हम उसके साथ भी छेड़छाड़ नहीं कर सकते।

हालाँकि, कुछ files की signature जाँची नहीं जाएगी। इनके plist में omit key होती है, जैसे:

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

CLI से किसी resource का signature calculate करना संभव है:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## DMG माउंट करना

उपयोगकर्ता कुछ मौजूदा फ़ोल्डरों के ऊपर भी बनाया गया कस्टम DMG माउंट कर सकता है। इस तरह आप कस्टम कंटेंट वाला कस्टम DMG पैकेज बना सकते हैं:

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

आमतौर पर macOS, `com.apple.DiskArbitrarion.diskarbitrariond` Mach service (जो `/usr/libexec/diskarbitrationd` द्वारा प्रदान की जाती है) से बात करके disk mount करता है। यदि LaunchDaemons plist file में `-d` param जोड़कर उसे restart किया जाए, तो यह logs को `/var/log/diskarbitrationd.log` में store करेगा।\
हालाँकि, `hdik` और `hdiutil` जैसे tools का उपयोग करके सीधे `com.apple.driver.DiskImages` kext से communicate करना संभव है।

## Arbitrary Writes

### Periodic sh scripts

यदि आपकी script को **shell script** के रूप में interpret किया जा सकता है, तो आप **`/etc/periodic/daily/999.local`** shell script को overwrite कर सकते हैं, जो हर दिन trigger होगी।

आप इस script के execution को **fake** कर सकते हैं: **`sudo periodic daily`**

### Daemons

एक arbitrary **LaunchDaemon** लिखें, जैसे **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, जिसमें किसी arbitrary script को execute करने वाली plist हो, जैसे:

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

बस `/Applications/Scripts/privesc.sh` script बनाएँ, जिसमें वे **commands** हों जिन्हें आप root के रूप में चलाना चाहते हैं।

### Sudoers फ़ाइल

अगर आपके पास **arbitrary write** है, तो आप **`/etc/sudoers.d/`** फ़ोल्डर के अंदर एक फ़ाइल बना सकते हैं, जो आपको **sudo** privileges देगी।

### PATH फ़ाइलें

फ़ाइल **`/etc/paths`** उन मुख्य जगहों में से एक है जहाँ से PATH env variable में entries जोड़ी जाती हैं। इसे overwrite करने के लिए root होना ज़रूरी है, लेकिन अगर कोई **privileged process** script में किसी **command** को उसका पूरा path दिए बिना चला रहा है, तो आप इस फ़ाइल में बदलाव करके उसे **hijack** कर सकते हैं।

आप **`/etc/paths.d`** में भी फ़ाइलें लिख सकते हैं, ताकि नए folders PATH env variable में जोड़े जा सकें।

### cups-files.conf

यह technique [इस writeup](https://www.kandji.io/blog/macos-audit-story-part1) में इस्तेमाल की गई थी।<sup>[[8]](#references)</sup>

यह content वाली फ़ाइल `/etc/cups/cups-files.conf` बनाएँ:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

इससे permissions 777 वाली `/etc/sudoers.d/lpe` फ़ाइल बनेगी। अंत में जो अतिरिक्त junk है, वह error log को बनवाने के लिए है।

फिर, privileges escalate करने के लिए `/etc/sudoers.d/lpe` में ज़रूरी config लिखें, जैसे `%staff ALL=(ALL) NOPASSWD:ALL`।

इसके बाद, `cupsctl` चलाकर नई sudoers फ़ाइल को valid बनाने के लिए `/etc/cups/cups-files.conf` को फिर से बदलें और उसमें `LogFilePerm 700` सेट करें।

### Sandbox Escape

FS arbitrary write से macOS sandbox से escape करना संभव है। कुछ उदाहरणों के लिए [macOS Auto Start](../../../../macos-auto-start-locations.md) पेज देखें। एक आम तरीका है `~/Library/Preferences/com.apple.Terminal.plist` में Terminal preferences फ़ाइल लिखना, जो startup पर कोई command चलाए, और फिर उसे `open` से call करना।

## अन्य users के रूप में writable files बनाना

एक बहुत आम privesc primitive है **privileged process से आपके लिए किसी ऐसी directory में फ़ाइल बनवाना जिसे आप control करते हैं**, और फिर उस फ़ाइल पर **write access** बनाए रखना। इसके लिए दो चीज़ें चाहिए:

1. ऐसी directory जिसका मालिक आप हों (या जहाँ आप **inheritable ACL** सेट कर सकें), ताकि उसके अंदर बनने वाली हर चीज़ को आपकी permissions विरासत में मिलें।
2. ऐसा privileged/`suid` process जिसे यह बताया जा सके कि फ़ाइल **कहाँ** बनानी है — आम तौर पर किसी debug/logging environment variable, config file या helper के XPC API के ज़रिए।

**Inheritable ACL** की वजह से बनी हुई फ़ाइल आपके लिए writable रहती है, भले ही उसका मालिक कोई दूसरा user हो। `file_inherit` / `directory_inherit` inheritance flags [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) में documented हैं:<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

अब `$DIRNAME` के अंदर कोई भी privileged process जो फ़ाइल बनाता है, वह **आपके द्वारा लिखने योग्य** होती है। अगर वह डायरेक्टरी ऐसी जगह भी है जहाँ बाद में **root के रूप में execution** होता है (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, कोई LaunchDaemon डायरेक्टरी...), तो यह सीधे root escalation का रास्ता है। फ़ाइल मिलने के बाद उसमें क्या लिखना है, इसके लिए ऊपर दिए गए [Sudoers File](#sudoers-file) और [cups-files.conf](#cups-filesconf) सेक्शन देखें।

“env variable से root process फ़ाइल बनाता है और FD आपके पास leak हो जाता है” वाली पूरी worked example के लिए ऊपर [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) देखें।

## POSIX Shared Memory

**POSIX shared memory** POSIX-compliant operating systems में processes को एक साझा memory area तक पहुँचने देती है, जिससे अन्य inter-process communication methods की तुलना में तेज़ communication संभव होता है। इसमें `shm_open()` की मदद से shared memory object बनाया या खोला जाता है, `ftruncate()` से उसका आकार तय किया जाता है, और `mmap()` का उपयोग करके उसे process के address space में map किया जाता है। इसके बाद processes इस memory area से सीधे data पढ़ और लिख सकती हैं। Concurrent access को manage करने और data corruption रोकने के लिए अक्सर mutexes या semaphores जैसे synchronization mechanisms का उपयोग किया जाता है। अंत में, processes `munmap()` और `close()` की मदद से shared memory को unmap और close करती हैं, और वैकल्पिक रूप से `shm_unlink()` की मदद से memory object हटा सकती हैं। यह system उन environments में कुशल और तेज़ IPC के लिए विशेष रूप से प्रभावी है जहाँ कई processes को साझा data तक तेज़ी से पहुँचने की आवश्यकता होती है।

<details>

<summary>Producer Code का उदाहरण</summary>

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

<summary>उपभोक्ता Code उदाहरण</summary>

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

**macOSCguarded descriptors** macOS में user applications में **file descriptor operations** की सुरक्षा और विश्वसनीयता बढ़ाने के लिए शुरू किया गया एक security feature है। ये guarded descriptors, file descriptors के साथ विशिष्ट प्रतिबंध या "guards" जोड़ने का तरीका देते हैं, जिन्हें kernel लागू करता है।

यह feature **अनधिकृत file access** या **race conditions** जैसी कुछ प्रकार की security vulnerabilities को रोकने में विशेष रूप से उपयोगी है। ये vulnerabilities तब होती हैं, उदाहरण के लिए, जब कोई thread किसी file description को access कर रहा हो और **किसी अन्य vulnerable thread को उस पर access दे रहा हो**, या जब कोई file descriptor किसी vulnerable child process को **inherit** हो जाए। इस functionality से संबंधित कुछ functions हैं:

- `guarded_open_np`: guard के साथ file descriptor खोलता है
- `guarded_close_np`: इसे बंद करता है
- `change_fdguard_np`: descriptor पर guard flags बदलता है (guard protection हटाना भी संभव है)

## References

- [1] [POSIX.1-2024 — आधार परिभाषाएँ, अध्याय 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - कौन-से file systems और cloud services extended attributes को सुरक्षित रखते हैं?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - macOS Sandbox Escapes का एक नया युग](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Apple Vulnerabilities का खुलासा: diskarbitrationd और storagekitd Audit Story, भाग 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
