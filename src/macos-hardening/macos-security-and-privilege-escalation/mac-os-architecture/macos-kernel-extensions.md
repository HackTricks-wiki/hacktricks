# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) **पैकेज** हैं जिनका **`.kext`** एक्सटेंशन होता है जो **macOS कर्नेल स्पेस में सीधे लोड** किए जाते हैं, मुख्य ऑपरेटिंग सिस्टम को अतिरिक्त कार्यक्षमता प्रदान करते हैं।

### Requirements

स्पष्ट रूप से, यह इतना शक्तिशाली है कि **कर्नेल एक्सटेंशन लोड करना जटिल है**। ये **आवश्यकताएँ** हैं जो एक कर्नेल एक्सटेंशन को लोड करने के लिए पूरी करनी चाहिए:

- जब **रिकवरी मोड में प्रवेश करते हैं**, कर्नेल **एक्सटेंशन को लोड करने की अनुमति होनी चाहिए**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- कर्नेल एक्सटेंशन को **कर्नेल कोड साइनिंग सर्टिफिकेट** के साथ **साइन** किया जाना चाहिए, जो केवल **Apple द्वारा दिया जा सकता है**। जो कंपनी और इसकी आवश्यकता के कारणों की विस्तार से समीक्षा करेगा।
- कर्नेल एक्सटेंशन को **नोटराइज** भी किया जाना चाहिए, Apple इसे मैलवेयर के लिए जांच सकेगा।
- फिर, **रूट** उपयोगकर्ता ही **कर्नेल एक्सटेंशन को लोड** कर सकता है और पैकेज के अंदर की फ़ाइलें **रूट की होनी चाहिए**।
- अपलोड प्रक्रिया के दौरान, पैकेज को **संरक्षित नॉन-रूट स्थान** में तैयार किया जाना चाहिए: `/Library/StagedExtensions` (इसके लिए `com.apple.rootless.storage.KernelExtensionManagement` ग्रांट की आवश्यकता होती है)।
- अंत में, जब इसे लोड करने का प्रयास किया जाता है, तो उपयोगकर्ता [**एक पुष्टि अनुरोध प्राप्त करेगा**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) और, यदि स्वीकार किया गया, तो कंप्यूटर को इसे लोड करने के लिए **रीस्टार्ट** करना होगा।

### Loading process

कैटालिना में यह इस तरह था: यह ध्यान देने योग्य है कि **सत्यापन** प्रक्रिया **यूजरलैंड** में होती है। हालाँकि, केवल वे एप्लिकेशन जिनके पास **`com.apple.private.security.kext-management`** ग्रांट है, वे **कर्नेल से एक्सटेंशन लोड करने का अनुरोध कर सकते हैं**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **एक्सटेंशन लोड करने के लिए सत्यापन** प्रक्रिया **शुरू करता है**
- यह **`kextd`** से **Mach सेवा** का उपयोग करके बात करेगा।
2. **`kextd`** कई चीजों की जांच करेगा, जैसे **हस्ताक्षर**
- यह **`syspolicyd`** से **जांच** करेगा कि क्या एक्सटेंशन को **लोड** किया जा सकता है।
3. **`syspolicyd`** उपयोगकर्ता को **प्रॉम्प्ट** करेगा यदि एक्सटेंशन पहले लोड नहीं किया गया है।
- **`syspolicyd`** परिणाम को **`kextd`** को रिपोर्ट करेगा
4. अंततः **`kextd`** कर्नेल को एक्सटेंशन लोड करने के लिए **बताने** में सक्षम होगा

यदि **`kextd`** उपलब्ध नहीं है, तो **`kextutil`** वही जांच कर सकता है।

### Enumeration (loaded kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> हालांकि कर्नेल एक्सटेंशन `/System/Library/Extensions/` में होने की उम्मीद है, यदि आप इस फ़ोल्डर में जाते हैं तो आप **कोई बाइनरी नहीं पाएंगे**। इसका कारण **कर्नेलकैश** है और एक `.kext` को रिवर्स करने के लिए आपको इसे प्राप्त करने का एक तरीका खोजना होगा।

**कर्नेलकैश** **XNU कर्नेल** का एक **पूर्व-संकलित और पूर्व-लिंक किया गया संस्करण** है, साथ ही आवश्यक डिवाइस **ड्राइवर** और **कर्नेल एक्सटेंशन** भी। इसे एक **संकुचित** प्रारूप में संग्रहीत किया जाता है और बूट-अप प्रक्रिया के दौरान मेमोरी में अनसंकुचित किया जाता है। कर्नेलकैश एक **तेज़ बूट समय** को सुविधाजनक बनाता है क्योंकि इसमें कर्नेल और महत्वपूर्ण ड्राइवरों का एक तैयार-से-चलाने वाला संस्करण उपलब्ध होता है, जिससे बूट समय पर इन घटकों को गतिशील रूप से लोड और लिंक करने में लगने वाले समय और संसाधनों की बचत होती है।

### Local Kerlnelcache

iOS में यह **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** में स्थित है, macOS में आप इसे इस कमांड से खोज सकते हैं: **`find / -name "kernelcache" 2>/dev/null`** \
मेरे मामले में macOS में मैंने इसे निम्नलिखित स्थान पर पाया:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 फ़ाइल प्रारूप एक कंटेनर प्रारूप है जिसका उपयोग Apple अपने iOS और macOS उपकरणों में **फर्मवेयर** घटकों (जैसे **कर्नेलकैश**) को सुरक्षित रूप से **स्टोर और सत्यापित** करने के लिए करता है। IMG4 प्रारूप में एक हेडर और कई टैग शामिल होते हैं जो विभिन्न डेटा के टुकड़ों को संलग्न करते हैं, जिसमें वास्तविक पेलोड (जैसे कर्नेल या बूटलोडर), एक हस्ताक्षर, और एक सेट मैनिफेस्ट प्रॉपर्टीज शामिल हैं। यह प्रारूप क्रिप्टोग्राफिक सत्यापन का समर्थन करता है, जिससे डिवाइस फर्मवेयर घटक की प्रामाणिकता और अखंडता की पुष्टि कर सकता है इससे पहले कि इसे निष्पादित किया जाए।

यह आमतौर पर निम्नलिखित घटकों से बना होता है:

- **Payload (IM4P)**:
- अक्सर संकुचित (LZFSE4, LZSS, …)
- वैकल्पिक रूप से एन्क्रिप्टेड
- **Manifest (IM4M)**:
- हस्ताक्षर शामिल है
- अतिरिक्त कुंजी/मान शब्दकोश
- **Restore Info (IM4R)**:
- जिसे APNonce के रूप में भी जाना जाता है
- कुछ अपडेट के पुनः खेलने से रोकता है
- वैकल्पिक: आमतौर पर यह नहीं पाया जाता

कर्नेलकैश को अनसंकुचित करें:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### डाउनलोड&#x20;

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) पर सभी कर्नेल डिबग किट्स मिल सकते हैं। आप इसे डाउनलोड कर सकते हैं, माउंट कर सकते हैं, [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) टूल के साथ खोल सकते हैं, **`.kext`** फ़ोल्डर तक पहुँच सकते हैं और **निकाल सकते हैं**।

सिंबॉल के लिए जांचें:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

कभी-कभी Apple **kernelcache** को **symbols** के साथ जारी करता है। आप उन पृष्ठों पर लिंक का पालन करके कुछ firmware को symbols के साथ डाउनलोड कर सकते हैं। firmware में अन्य फ़ाइलों के साथ **kernelcache** शामिल होगा।

फ़ाइलों को **extract** करने के लिए `.ipsw` से `.zip` में एक्सटेंशन बदलकर शुरू करें और **unzip** करें।

Firmware को extract करने के बाद आपको एक फ़ाइल मिलेगी जैसे: **`kernelcache.release.iphone14`**। यह **IMG4** प्रारूप में है, आप इसे दिलचस्प जानकारी निकालने के लिए उपयोग कर सकते हैं:

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
## डिबगिंग

## संदर्भ

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
