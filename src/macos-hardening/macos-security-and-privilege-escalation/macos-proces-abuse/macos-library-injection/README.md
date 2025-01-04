# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld का कोड ओपन सोर्स है** और [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) पर पाया जा सकता है और इसे **URL जैसे** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) का उपयोग करके एक tar के रूप में डाउनलोड किया जा सकता है।

## **Dyld Process**

देखें कि Dyld बाइनरी के अंदर लाइब्रेरी कैसे लोड करता है:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

यह [**LD_PRELOAD on Linux**](../../../../linux-hardening/privilege-escalation/index.html#ld_preload) के समान है। यह एक प्रक्रिया को इंगित करने की अनुमति देता है जो चलने वाली है कि एक विशेष लाइब्रेरी को एक पथ से लोड किया जाए (यदि env var सक्षम है)।

यह तकनीक **ASEP तकनीक के रूप में भी उपयोग की जा सकती है** क्योंकि हर स्थापित एप्लिकेशन में "Info.plist" नामक एक plist होती है जो एक कुंजी `LSEnvironmental` का उपयोग करके **पर्यावरणीय चर असाइन करने** की अनुमति देती है।

> [!NOTE]
> 2012 से **Apple ने `DYLD_INSERT_LIBRARIES`** की **शक्ति को काफी कम कर दिया है**।
>
> कोड पर जाएं और **`src/dyld.cpp`** की जांच करें। फ़ंक्शन **`pruneEnvironmentVariables`** में आप देख सकते हैं कि **`DYLD_*`** चर हटा दिए गए हैं।
>
> फ़ंक्शन **`processRestricted`** में प्रतिबंध का कारण सेट किया गया है। उस कोड की जांच करने पर आप देख सकते हैं कि कारण हैं:
>
> - बाइनरी `setuid/setgid` है
> - macho बाइनरी में `__RESTRICT/__restrict` अनुभाग का अस्तित्व।
> - सॉफ़्टवेयर में अधिकार हैं (हर्डनड रनटाइम) बिना [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) अधिकार के
>   - बाइनरी के **अधिकार** की जांच करें: `codesign -dv --entitlements :- </path/to/bin>`
>
> अधिक अपडेटेड संस्करणों में आप इस तर्क को फ़ंक्शन **`configureProcessRestrictions`** के दूसरे भाग में पा सकते हैं। हालाँकि, जो नए संस्करणों में निष्पादित होता है वह फ़ंक्शन के **शुरुआती जांच** हैं (आप iOS या सिमुलेशन से संबंधित ifs को हटा सकते हैं क्योंकि वे macOS में उपयोग नहीं किए जाएंगे)।

### लाइब्रेरी मान्यता

यहां तक कि यदि बाइनरी **`DYLD_INSERT_LIBRARIES`** env चर का उपयोग करने की अनुमति देती है, यदि बाइनरी लोड करने के लिए लाइब्रेरी के हस्ताक्षर की जांच करती है, तो यह एक कस्टम को लोड नहीं करेगी।

कस्टम लाइब्रेरी को लोड करने के लिए, बाइनरी में **निम्नलिखित अधिकारों में से एक होना चाहिए**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

या बाइनरी में **हर्डनड रनटाइम फ्लैग** या **लाइब्रेरी मान्यता फ्लैग** **नहीं होना चाहिए**।

आप यह जांच सकते हैं कि क्या बाइनरी में **हर्डनड रनटाइम** है: `codesign --display --verbose <bin>` **`CodeDirectory`** में फ्लैग रनटाइम की जांच करते हुए जैसे: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

आप एक लाइब्रेरी को भी लोड कर सकते हैं यदि यह **बाइनरी के समान प्रमाणपत्र से हस्ताक्षरित है**।

इसका (दुरुपयोग) करने का एक उदाहरण खोजें और प्रतिबंधों की जांच करें:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> याद रखें कि **पिछले लाइब्रेरी मान्यता प्रतिबंध भी लागू होते हैं** Dylib हाइजैकिंग हमलों को करने के लिए।

Windows की तरह, MacOS में आप भी **dylibs को हाइजैक** कर सकते हैं ताकि **एप्लिकेशन** **मनमाने** **कोड** को **निष्पादित** कर सकें (ठीक है, वास्तव में एक सामान्य उपयोगकर्ता के लिए यह संभव नहीं हो सकता क्योंकि आपको एक `.app` बंडल के अंदर लिखने के लिए TCC अनुमति की आवश्यकता हो सकती है और एक लाइब्रेरी को हाइजैक करना)।\
हालांकि, **MacOS** एप्लिकेशन **लाइब्रेरी** को लोड करने का तरीका **Windows की तुलना में अधिक प्रतिबंधित** है। इसका मतलब है कि **मैलवेयर** डेवलपर्स अभी भी **स्टेल्थ** के लिए इस तकनीक का उपयोग कर सकते हैं, लेकिन **अधिकारों को बढ़ाने के लिए इसका दुरुपयोग करने की संभावना बहुत कम है**।

सबसे पहले, यह **अधिक सामान्य** है कि **MacOS बाइनरी लाइब्रेरी को लोड करने के लिए पूर्ण पथ** को इंगित करती हैं। और दूसरा, **MacOS कभी भी लाइब्रेरी के लिए **$PATH** के फ़ोल्डरों में खोज नहीं करता है।

इस कार्यक्षमता से संबंधित **कोड** का **मुख्य** भाग **`ImageLoader::recursiveLoadLibraries`** में है `ImageLoader.cpp`।

एक macho बाइनरी लाइब्रेरी लोड करने के लिए **4 विभिन्न हेडर कमांड** का उपयोग कर सकती है:

- **`LC_LOAD_DYLIB`** कमांड एक dylib लोड करने के लिए सामान्य कमांड है।
- **`LC_LOAD_WEAK_DYLIB`** कमांड पिछले वाले की तरह काम करता है, लेकिन यदि dylib नहीं पाया जाता है, तो निष्पादन बिना किसी त्रुटि के जारी रहता है।
- **`LC_REEXPORT_DYLIB`** कमांड यह प्रतीक को एक अलग लाइब्रेरी से प्रॉक्सी (या फिर से निर्यात) करता है।
- **`LC_LOAD_UPWARD_DYLIB`** कमांड का उपयोग तब किया जाता है जब दो लाइब्रेरी एक-दूसरे पर निर्भर करती हैं (इसे _upward dependency_ कहा जाता है)।

हालांकि, **dylib हाइजैकिंग** के **2 प्रकार** हैं:

- **गायब कमजोर लिंक की गई लाइब्रेरी**: इसका मतलब है कि एप्लिकेशन एक लाइब्रेरी लोड करने की कोशिश करेगा जो **LC_LOAD_WEAK_DYLIB** के साथ कॉन्फ़िगर की गई नहीं है। फिर, **यदि एक हमलावर एक dylib को उस स्थान पर रखता है जहां इसे लोड करने की उम्मीद है**।
- लिंक "कमजोर" होने का मतलब है कि एप्लिकेशन तब भी चलना जारी रखेगा जब लाइब्रेरी नहीं पाई जाती।
- इस से संबंधित **कोड** `ImageLoaderMachO::doGetDependentLibraries` फ़ंक्शन में है `ImageLoaderMachO.cpp` जहां `lib->required` केवल तब `false` है जब `LC_LOAD_WEAK_DYLIB` सत्य है।
- बाइनरी में **कमजोर लिंक की गई लाइब्रेरी** खोजें (आपके पास बाद में हाइजैकिंग लाइब्रेरी बनाने का एक उदाहरण है):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath के साथ कॉन्फ़िगर किया गया**: Mach-O बाइनरी में **`LC_RPATH`** और **`LC_LOAD_DYLIB`** कमांड हो सकते हैं। उन कमांड के **मानों** के आधार पर, **लाइब्रेरी** **विभिन्न निर्देशिकाओं** से **लोड** की जाएगी।
- **`LC_RPATH`** में कुछ फ़ोल्डरों के पथ होते हैं जो बाइनरी द्वारा लाइब्रेरी लोड करने के लिए उपयोग किए जाते हैं।
- **`LC_LOAD_DYLIB`** में लोड करने के लिए विशिष्ट लाइब्रेरी का पथ होता है। ये पथ **`@rpath`** को शामिल कर सकते हैं, जिसे **`LC_RPATH`** में मानों द्वारा **बदल दिया जाएगा**। यदि **`LC_RPATH`** में कई पथ हैं, तो सभी का उपयोग लाइब्रेरी को लोड करने के लिए किया जाएगा। उदाहरण:
- यदि **`LC_LOAD_DYLIB`** में `@rpath/library.dylib` है और **`LC_RPATH`** में `/application/app.app/Contents/Framework/v1/` और `/application/app.app/Contents/Framework/v2/` है। दोनों फ़ोल्डर `library.dylib` को लोड करने के लिए उपयोग किए जाएंगे। यदि लाइब्रेरी `[...]/v1/` में मौजूद नहीं है और हमलावर इसे वहां रख सकता है ताकि `[...]/v2/` में लाइब्रेरी के लोड को हाइजैक किया जा सके क्योंकि **`LC_LOAD_DYLIB`** में पथों का क्रम का पालन किया जाता है।
- बाइनरी में **rpath पथ और लाइब्रेरी** खोजें: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: यह **मुख्य निष्पादन फ़ाइल** को समाहित करने वाले **निर्देशिका** का **पथ** है।
>
> **`@loader_path`**: यह **लोड कमांड** को समाहित करने वाले **Mach-O बाइनरी** के **निर्देशिका** का **पथ** है।
>
> - जब एक निष्पादन योग्य में उपयोग किया जाता है, तो **`@loader_path`** प्रभावी रूप से **`@executable_path`** के समान है।
> - जब एक **dylib** में उपयोग किया जाता है, तो **`@loader_path`** **dylib** का **पथ** देता है।

इस कार्यक्षमता का दुरुपयोग करके **अधिकारों को बढ़ाने** का तरीका दुर्लभ मामले में होगा जब एक **एप्लिकेशन** जो **रूट** द्वारा **निष्पादित** किया जा रहा है, किसी **निर्देशिका में किसी लाइब्रेरी की तलाश कर रहा है जहां हमलावर के पास लिखने की अनुमति है।**

> [!TIP]
> अनुप्रयोगों में **गायब लाइब्रेरी** खोजने के लिए एक अच्छा **स्कैनर** [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) या [**CLI संस्करण**](https://github.com/pandazheng/DylibHijack) है।\
> इस तकनीक के बारे में **तकनीकी विवरण** के साथ एक अच्छा **रिपोर्ट** [**यहां**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) पाया जा सकता है।

**उदाहरण**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> याद रखें कि **पिछले लाइब्रेरी मान्यता प्रतिबंध भी लागू होते हैं** Dlopen हाइजैकिंग हमलों को करने के लिए।

**`man dlopen`** से:

- जब पथ **स्लैश वर्ण** को शामिल नहीं करता है (यानी यह केवल एक पत्ते का नाम है), **dlopen() खोज करेगा**। यदि **`$DYLD_LIBRARY_PATH`** लॉन्च पर सेट किया गया था, तो dyld पहले **उस निर्देशिका में देखेगा**। अगला, यदि कॉलिंग mach-o फ़ाइल या मुख्य निष्पादन फ़ाइल **`LC_RPATH`** निर्दिष्ट करती है, तो dyld **उन** निर्देशिकाओं में देखेगा। अगला, यदि प्रक्रिया **अप्रतिबंधित** है, तो dyld **वर्तमान कार्यशील निर्देशिका** में खोज करेगा। अंत में, पुराने बाइनरी के लिए, dyld कुछ फॉलबैक का प्रयास करेगा। यदि **`$DYLD_FALLBACK_LIBRARY_PATH`** लॉन्च पर सेट किया गया था, तो dyld उन निर्देशिकाओं में खोज करेगा, अन्यथा, dyld **`/usr/local/lib/`** में देखेगा (यदि प्रक्रिया अप्रतिबंधित है), और फिर **`/usr/lib/`** में (यह जानकारी **`man dlopen`** से ली गई थी)।
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(यदि अप्रतिबंधित)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (यदि अप्रतिबंधित)
6. `/usr/lib/`

> [!CAUTION]
> यदि नाम में कोई स्लैश नहीं है, तो हाइजैकिंग करने के लिए 2 तरीके होंगे:
>
> - यदि कोई **`LC_RPATH`** **लिखने योग्य** है (लेकिन हस्ताक्षर की जांच की जाती है, इसलिए इसके लिए आपको बाइनरी को भी अप्रतिबंधित होना चाहिए)
> - यदि बाइनरी **अप्रतिबंधित** है और फिर CWD से कुछ लोड करना संभव है (या उल्लेखित env चर में से एक का दुरुपयोग करना)

- जब पथ **फ्रेमवर्क** पथ की तरह दिखता है (जैसे `/stuff/foo.framework/foo`), यदि **`$DYLD_FRAMEWORK_PATH`** लॉन्च पर सेट किया गया था, तो dyld पहले उस निर्देशिका में **फ्रेमवर्क आंशिक पथ** (जैसे `foo.framework/foo`) के लिए देखेगा। अगला, dyld **प्रदान किए गए पथ को जैसा है** (सापेक्ष पथों के लिए वर्तमान कार्यशील निर्देशिका का उपयोग करते हुए) का प्रयास करेगा। अंत में, पुराने बाइनरी के लिए, dyld कुछ फॉलबैक का प्रयास करेगा। यदि **`$DYLD_FALLBACK_FRAMEWORK_PATH`** लॉन्च पर सेट किया गया था, तो dyld उन निर्देशिकाओं में खोज करेगा। अन्यथा, यह **`/Library/Frameworks`** (macOS पर यदि प्रक्रिया अप्रतिबंधित है), फिर **`/System/Library/Frameworks`** में खोज करेगा।
1. `$DYLD_FRAMEWORK_PATH`
2. प्रदान किया गया पथ (यदि अप्रतिबंधित है तो सापेक्ष पथों के लिए वर्तमान कार्यशील निर्देशिका का उपयोग करना)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (यदि अप्रतिबंधित)
5. `/System/Library/Frameworks`

> [!CAUTION]
> यदि एक फ्रेमवर्क पथ है, तो इसे हाइजैक करने का तरीका होगा:
>
> - यदि प्रक्रिया **अप्रतिबंधित** है, तो CWD से **सापेक्ष पथ** का दुरुपयोग करते हुए उल्लेखित env चर (यहां तक कि यदि यह दस्तावेज़ में नहीं कहा गया है यदि प्रक्रिया प्रतिबंधित है तो DYLD\_\* env vars हटा दिए जाते हैं)

- जब पथ **स्लैश को शामिल करता है लेकिन फ्रेमवर्क पथ नहीं है** (यानी एक पूर्ण पथ या dylib के लिए आंशिक पथ), dlopen() पहले (यदि सेट है) **`$DYLD_LIBRARY_PATH`** में देखता है (पथ से पत्ते का भाग)। अगला, dyld **प्रदान किए गए पथ** का प्रयास करता है (सापेक्ष पथों के लिए वर्तमान कार्यशील निर्देशिका का उपयोग करते हुए (लेकिन केवल अप्रतिबंधित प्रक्रियाओं के लिए))। अंत में, पुराने बाइनरी के लिए, dyld फॉलबैक का प्रयास करेगा। यदि **`$DYLD_FALLBACK_LIBRARY_PATH`** लॉन्च पर सेट किया गया था, तो dyld उन निर्देशिकाओं में खोज करेगा, अन्यथा, dyld **`/usr/local/lib/`** में देखेगा (यदि प्रक्रिया अप्रतिबंधित है), और फिर **`/usr/lib/`** में।
1. `$DYLD_LIBRARY_PATH`
2. प्रदान किया गया पथ (यदि अप्रतिबंधित है तो सापेक्ष पथों के लिए वर्तमान कार्यशील निर्देशिका का उपयोग करना)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (यदि अप्रतिबंधित)
5. `/usr/lib/`

> [!CAUTION]
> यदि नाम में स्लैश हैं और फ्रेमवर्क नहीं है, तो इसे हाइजैक करने का तरीका होगा:
>
> - यदि बाइनरी **अप्रतिबंधित** है और फिर CWD या `/usr/local/lib` से कुछ लोड करना संभव है (या उल्लेखित env चर में से एक का दुरुपयोग करना)

> [!NOTE]
> नोट: **dlopen खोज** को **नियंत्रित करने** के लिए कोई कॉन्फ़िगरेशन फ़ाइलें नहीं हैं।
>
> नोट: यदि मुख्य निष्पादन योग्य एक **set\[ug]id बाइनरी या अधिकारों के साथ कोडसाइन किया गया है**, तो **सभी पर्यावरण चर अनदेखा कर दिए जाते हैं**, और केवल एक पूर्ण पथ का उपयोग किया जा सकता है ([DYLD_INSERT_LIBRARIES प्रतिबंधों की जांच करें](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) अधिक विस्तृत जानकारी के लिए)
>
> नोट: Apple प्लेटफार्म "यूनिवर्सल" फ़ाइलों का उपयोग करते हैं ताकि 32-बिट और 64-बिट लाइब्रेरी को संयोजित किया जा सके। इसका मतलब है कि **कोई अलग 32-बिट और 64-बिट खोज पथ नहीं हैं**।
>
> नोट: Apple प्लेटफार्मों पर अधिकांश OS dylibs **dyld कैश में संयोजित** होते हैं और डिस्क पर मौजूद नहीं होते हैं। इसलिए, यदि एक OS dylib मौजूद है तो **`stat()`** को पूर्व-फ्लाइट करने के लिए **काम नहीं करेगा**। हालाँकि, **`dlopen_preflight()`** एक संगत mach-o फ़ाइल खोजने के लिए **`dlopen()`** के समान चरणों का उपयोग करता है।

**पथों की जांच करें**

आइए निम्नलिखित कोड के साथ सभी विकल्पों की जांच करें:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
यदि आप इसे संकलित और निष्पादित करते हैं, तो आप देख सकते हैं **कि प्रत्येक पुस्तकालय के लिए कहाँ असफलता से खोज की गई**। इसके अलावा, आप **FS लॉग को फ़िल्टर कर सकते हैं**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

यदि एक **privileged binary/app** (जैसे SUID या कुछ बाइनरी जिसमें शक्तिशाली अधिकार हैं) एक **relative path** लाइब्रेरी को **लोड कर रहा है** (उदाहरण के लिए `@executable_path` या `@loader_path` का उपयोग करके) और **Library Validation अक्षम** है, तो यह संभव हो सकता है कि बाइनरी को एक स्थान पर ले जाया जाए जहाँ हमलावर **relative path लोड की गई लाइब्रेरी** को **संशोधित** कर सके, और इसे प्रक्रिया में कोड इंजेक्ट करने के लिए दुरुपयोग कर सके।

## Prune `DYLD_*` और `LD_LIBRARY_PATH` env variables

फाइल `dyld-dyld-832.7.1/src/dyld2.cpp` में **`pruneEnvironmentVariables`** नामक फ़ंक्शन पाया जा सकता है, जो किसी भी env वेरिएबल को हटा देगा जो **`DYLD_`** और **`LD_LIBRARY_PATH=`** से **शुरू होता है**।

यह विशेष रूप से **suid** और **sgid** बाइनरी के लिए env वेरिएबल **`DYLD_FALLBACK_FRAMEWORK_PATH`** और **`DYLD_FALLBACK_LIBRARY_PATH`** को **null** पर सेट करेगा।

यह फ़ंक्शन उसी फ़ाइल के **`_main`** फ़ंक्शन से इस तरह से कॉल किया जाता है यदि OSX को लक्षित किया गया हो:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
और उन बूलियन फ्लैग्स को कोड में उसी फ़ाइल में सेट किया गया है:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
जो मूल रूप से यह मतलब है कि यदि बाइनरी **suid** या **sgid** है, या इसके हेडर में **RESTRICT** खंड है या इसे **CS_RESTRICT** ध्वज के साथ साइन किया गया है, तो **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** सत्य है और पर्यावरण चर हटा दिए जाते हैं।

ध्यान दें कि यदि CS_REQUIRE_LV सत्य है, तो चर हटा नहीं जाएंगे लेकिन पुस्तकालय मान्यता यह जांचेगी कि वे मूल बाइनरी के समान प्रमाणपत्र का उपयोग कर रहे हैं।

## प्रतिबंधों की जांच करें

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Section `__RESTRICT` with segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Keychain में एक नया प्रमाणपत्र बनाएं और इसका उपयोग बाइनरी पर हस्ताक्षर करने के लिए करें:
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
> [!CAUTION]
> ध्यान दें कि भले ही कुछ बाइनरीज़ **`0x0(none)`** फ्लैग के साथ साइन की गई हों, वे निष्पादित होने पर **`CS_RESTRICT`** फ्लैग को गतिशील रूप से प्राप्त कर सकती हैं और इसलिए यह तकनीक उन पर काम नहीं करेगी।
>
> आप यह जांच सकते हैं कि किसी प्रक्रिया में यह फ्लैग है या नहीं (get [**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> और फिर जांचें कि क्या फ्लैग 0x800 सक्षम है।

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
