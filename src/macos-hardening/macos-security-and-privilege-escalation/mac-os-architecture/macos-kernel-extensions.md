# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) **पैकेज** हैं जिनका **`.kext`** एक्सटेंशन होता है जो **macOS कर्नेल स्पेस में सीधे लोड** होते हैं, मुख्य ऑपरेटिंग सिस्टम को अतिरिक्त कार्यक्षमता प्रदान करते हैं।

### Deprecation status & DriverKit / System Extensions
**macOS Catalina (10.15)** से शुरू होकर Apple ने अधिकांश पुराने KPI को *deprecated* के रूप में चिह्नित किया और **System Extensions & DriverKit** ढांचे को पेश किया जो **यूजर-स्पेस** में चलते हैं। **macOS Big Sur (11)** से ऑपरेटिंग सिस्टम *तीसरे पक्ष के kexts को लोड करने से इनकार करेगा* जो deprecated KPI पर निर्भर करते हैं जब तक कि मशीन **Reduced Security** मोड में बूट न हो। Apple Silicon पर, kexts को सक्षम करने के लिए उपयोगकर्ता को अतिरिक्त रूप से:

1. **Recovery** में पुनः बूट करें → *Startup Security Utility*।
2. **Reduced Security** का चयन करें और **“Allow user management of kernel extensions from identified developers”** को टिक करें।
3. पुनः बूट करें और **System Settings → Privacy & Security** से kext को स्वीकृत करें।

DriverKit/System Extensions के साथ लिखे गए यूजर-लैंड ड्राइवर **हमले की सतह को काफी कम** करते हैं क्योंकि क्रैश या मेमोरी भ्रष्टाचार एक सैंडबॉक्स प्रक्रिया तक सीमित होते हैं न कि कर्नेल स्पेस तक।

> 📝 macOS Sequoia (15) से Apple ने कई पुराने नेटवर्किंग और USB KPI को पूरी तरह से हटा दिया है - विक्रेताओं के लिए एकमात्र आगे-संगत समाधान System Extensions में माइग्रेट करना है।

### Requirements

स्पष्ट रूप से, यह इतना शक्तिशाली है कि **कर्नेल एक्सटेंशन लोड करना जटिल है**। ये **आवश्यकताएँ** हैं जो एक कर्नेल एक्सटेंशन को लोड करने के लिए पूरी करनी चाहिए:

- जब **रिकवरी मोड में प्रवेश करते हैं**, कर्नेल **एक्सटेंशन को लोड करने की अनुमति होनी चाहिए**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- कर्नेल एक्सटेंशन को **कर्नेल कोड साइनिंग सर्टिफिकेट** के साथ **साइन** किया जाना चाहिए, जो केवल **Apple द्वारा** दिया जा सकता है। जो कंपनी और इसके आवश्यक होने के कारणों की विस्तार से समीक्षा करेगा।
- कर्नेल एक्सटेंशन को **नोटराइज** भी किया जाना चाहिए, Apple इसे मैलवेयर के लिए जांच सकेगा।
- फिर, **root** उपयोगकर्ता ही **कर्नेल एक्सटेंशन को लोड** कर सकता है और पैकेज के अंदर की फ़ाइलें **root** की होनी चाहिए।
- अपलोड प्रक्रिया के दौरान, पैकेज को **संरक्षित नॉन-रूट स्थान** में तैयार किया जाना चाहिए: `/Library/StagedExtensions` (इसके लिए `com.apple.rootless.storage.KernelExtensionManagement` ग्रांट की आवश्यकता होती है)।
- अंत में, जब इसे लोड करने का प्रयास किया जाता है, तो उपयोगकर्ता [**एक पुष्टि अनुरोध प्राप्त करेगा**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) और, यदि स्वीकार किया गया, तो कंप्यूटर को इसे लोड करने के लिए **पुनः प्रारंभ** करना होगा।

### Loading process

Catalina में यह इस प्रकार था: यह ध्यान देने योग्य है कि **सत्यापन** प्रक्रिया **यूजरलैंड** में होती है। हालाँकि, केवल **`com.apple.private.security.kext-management`** ग्रांट वाले एप्लिकेशन ही **कर्नेल से एक्सटेंशन लोड करने का अनुरोध कर सकते हैं**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **एक्सटेंशन लोड करने के लिए सत्यापन** प्रक्रिया शुरू करता है
- यह **`kextd`** से **Mach सेवा** का उपयोग करके बात करेगा।
2. **`kextd`** कई चीजों की जांच करेगा, जैसे **हस्ताक्षर**
- यह **`syspolicyd`** से बात करेगा ताकि यह **जांच सके** कि क्या एक्सटेंशन को **लोड** किया जा सकता है।
3. **`syspolicyd`** **उपयोगकर्ता** से **प्रॉम्प्ट** करेगा यदि एक्सटेंशन पहले लोड नहीं किया गया है।
- **`syspolicyd`** परिणाम को **`kextd`** को रिपोर्ट करेगा
4. अंततः **`kextd`** कर्नेल को एक्सटेंशन को लोड करने के लिए **बताने** में सक्षम होगा

यदि **`kextd`** उपलब्ध नहीं है, तो **`kextutil`** वही जांच कर सकता है।

### Enumeration & management (loaded kexts)

`kextstat` ऐतिहासिक उपकरण था लेकिन यह हाल के macOS रिलीज़ में **deprecated** है। आधुनिक इंटरफ़ेस **`kmutil`** है:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
पुरानी सिंटैक्स अभी भी संदर्भ के लिए उपलब्ध है:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` का उपयोग **Kernel Collection (KC)** की सामग्री को **dump** करने या यह सत्यापित करने के लिए भी किया जा सकता है कि एक kext सभी प्रतीक निर्भरताओं को हल करता है:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> हालांकि कर्नेल एक्सटेंशन `/System/Library/Extensions/` में होने की उम्मीद है, यदि आप इस फ़ोल्डर में जाते हैं तो आपको **कोई बाइनरी नहीं मिलेगी**। इसका कारण **कर्नेलकैश** है और एक `.kext` को रिवर्स करने के लिए आपको इसे प्राप्त करने का एक तरीका खोजना होगा।

**कर्नेलकैश** **XNU कर्नेल** का एक **पूर्व-संकलित और पूर्व-लिंक किया गया संस्करण** है, साथ ही आवश्यक डिवाइस **ड्राइवर** और **कर्नेल एक्सटेंशन** भी। इसे **संकुचित** प्रारूप में संग्रहीत किया जाता है और बूट-अप प्रक्रिया के दौरान मेमोरी में अनसंकुचित किया जाता है। कर्नेलकैश एक **तेज़ बूट समय** को सुविधाजनक बनाता है क्योंकि इसमें कर्नेल और महत्वपूर्ण ड्राइवरों का एक तैयार-से-चलाने वाला संस्करण उपलब्ध होता है, जिससे बूट समय पर इन घटकों को गतिशील रूप से लोड और लिंक करने में लगने वाले समय और संसाधनों की बचत होती है।

### Local Kerlnelcache

iOS में यह **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** में स्थित है, macOS में आप इसे इस कमांड से खोज सकते हैं: **`find / -name "kernelcache" 2>/dev/null`** \
मेरे मामले में macOS में मैंने इसे निम्नलिखित स्थान पर पाया:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 फ़ाइल प्रारूप एक कंटेनर प्रारूप है जिसका उपयोग Apple अपने iOS और macOS उपकरणों में **फर्मवेयर** घटकों (जैसे **कर्नेलकैश**) को सुरक्षित रूप से **स्टोर और सत्यापित** करने के लिए करता है। IMG4 प्रारूप में एक हेडर और कई टैग होते हैं जो विभिन्न डेटा के टुकड़ों को संलग्न करते हैं, जिसमें वास्तविक पेलोड (जैसे कर्नेल या बूटलोडर), एक हस्ताक्षर, और एक सेट मैनिफेस्ट प्रॉपर्टीज शामिल हैं। यह प्रारूप क्रिप्टोग्राफिक सत्यापन का समर्थन करता है, जिससे डिवाइस फर्मवेयर घटक को निष्पादित करने से पहले उसकी प्रामाणिकता और अखंडता की पुष्टि कर सकता है।

यह आमतौर पर निम्नलिखित घटकों से बना होता है:

- **Payload (IM4P)**:
- अक्सर संकुचित (LZFSE4, LZSS, …)
- वैकल्पिक रूप से एन्क्रिप्टेड
- **Manifest (IM4M)**:
- हस्ताक्षर शामिल है
- अतिरिक्त कुंजी/मान शब्दकोश
- **Restore Info (IM4R)**:
- APNonce के रूप में भी जाना जाता है
- कुछ अपडेट के पुनः खेलने से रोकता है
- वैकल्पिक: आमतौर पर यह नहीं पाया जाता

कर्नेलकैश को अनसंकुचित करें:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### डाउनलोड

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) पर सभी कर्नेल डिबग किट्स मिल सकते हैं। आप इसे डाउनलोड कर सकते हैं, माउंट कर सकते हैं, [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) टूल के साथ खोल सकते हैं, **`.kext`** फ़ोल्डर तक पहुँच सकते हैं और **निकाल सकते हैं**।

सिंबॉल के लिए जांचें:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

कभी-कभी Apple **kernelcache** को **symbols** के साथ जारी करता है। आप उन पृष्ठों पर दिए गए लिंक का पालन करके कुछ firmware को symbols के साथ डाउनलोड कर सकते हैं। firmware में अन्य फ़ाइलों के साथ **kernelcache** शामिल होगा।

फ़ाइलों को **extract** करने के लिए, पहले `.ipsw` से `.zip` में एक्सटेंशन बदलें और फिर **unzip** करें।

Firmware को extract करने के बाद आपको एक फ़ाइल मिलेगी जैसे: **`kernelcache.release.iphone14`**। यह **IMG4** प्रारूप में है, आप इसमें से दिलचस्प जानकारी को निकाल सकते हैं:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecting kernelcache

जांचें कि क्या kernelcache में प्रतीक हैं
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
इसके साथ, हम अब **सभी एक्सटेंशन निकाल सकते हैं** या **वह जो आपको रुचिकर है:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## हाल की कमजोरियाँ और शोषण तकनीकें

| वर्ष | CVE | सारांश |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | **`storagekitd`** में लॉजिक दोष ने *root* हमलावर को एक दुर्भावनापूर्ण फ़ाइल-प्रणाली बंडल पंजीकृत करने की अनुमति दी, जिसने अंततः एक **unsigned kext** लोड किया, **System Integrity Protection (SIP)** को बायपास किया और स्थायी रूटकिट सक्षम किया। macOS 14.2 / 15.2 में पैच किया गया। |
| 2021 | **CVE-2021-30892** (*Shrootless*) | `com.apple.rootless.install` अधिकार के साथ स्थापना डेमन का दुरुपयोग किया जा सकता है ताकि मनमाने पोस्ट-इंस्टॉल स्क्रिप्ट को निष्पादित किया जा सके, SIP को निष्क्रिय किया जा सके और मनमाने kexts को लोड किया जा सके। |

**रेड-टीमर्स के लिए सीखने योग्य बातें**

1. **Disk Arbitration, Installer या Kext Management के साथ इंटरैक्ट करने वाले अधिकार प्राप्त डेमन्स (`codesign -dvv /path/bin | grep entitlements`) की तलाश करें।**
2. **SIP बायपास का दुरुपयोग लगभग हमेशा एक kext लोड करने की क्षमता प्रदान करता है → कर्नेल कोड निष्पादन**।

**रक्षा संबंधी सुझाव**

*SIP को सक्षम रखें*, गैर-Apple बाइनरी से आने वाले `kmutil load`/`kmutil create -n aux` कॉल्स की निगरानी करें और `/Library/Extensions` में किसी भी लेखन पर अलर्ट करें। एंडपॉइंट सुरक्षा घटनाएँ `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` लगभग वास्तविक समय की दृश्यता प्रदान करती हैं।

## macOS कर्नेल और kexts का डिबगिंग

Apple की अनुशंसित कार्यप्रणाली एक **Kernel Debug Kit (KDK)** बनाने की है जो चल रहे निर्माण से मेल खाती है और फिर **KDP (Kernel Debugging Protocol)** नेटवर्क सत्र के माध्यम से **LLDB** को संलग्न करती है।

### एक बार का स्थानीय पैनिक डिबगिंग
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Live remote debugging from another Mac

1. डाउनलोड करें + लक्ष्य मशीन के लिए सही **KDK** संस्करण स्थापित करें।
2. लक्ष्य Mac और होस्ट Mac को **USB-C या Thunderbolt केबल** से कनेक्ट करें।
3. **लक्ष्य** पर:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. **होस्ट** पर:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### एक विशेष लोड किए गए kext के लिए LLDB को संलग्न करना
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP केवल एक **पढ़ने-के लिए** इंटरफ़ेस प्रदान करता है। गतिशील इंस्ट्रुमेंटेशन के लिए, आपको बाइनरी को डिस्क पर पैच करना होगा, **कर्नेल फ़ंक्शन हुकिंग** (जैसे `mach_override`) का उपयोग करना होगा या पूर्ण पढ़ने/लिखने के लिए ड्राइवर को **हाइपरवाइज़र** में माइग्रेट करना होगा।

## संदर्भ

- DriverKit सुरक्षा – Apple प्लेटफ़ॉर्म सुरक्षा गाइड
- Microsoft सुरक्षा ब्लॉग – *CVE-2024-44243 SIP बायपास का विश्लेषण*

{{#include ../../../banners/hacktricks-training.md}}
