# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MacOS Sandbox (शुरुआत में Seatbelt कहा जाता था) **ऐप्लिकेशनों को सीमित करता है** जो सैंडबॉक्स के अंदर चल रही हैं **सैंडबॉक्स प्रोफ़ाइल में निर्दिष्ट अनुमत क्रियाओं** तक। यह सुनिश्चित करने में मदद करता है कि **ऐप्लिकेशन केवल अपेक्षित संसाधनों तक पहुंच प्राप्त करेगा**।

कोई भी ऐप जिसमें **अधिकार** **`com.apple.security.app-sandbox`** है, सैंडबॉक्स के अंदर निष्पादित किया जाएगा। **एप्पल बाइनरीज़** आमतौर पर सैंडबॉक्स के अंदर निष्पादित होती हैं, और **ऐप स्टोर** से सभी ऐप्लिकेशनों के पास वह अधिकार होता है। इसलिए कई ऐप्लिकेशनों को सैंडबॉक्स के अंदर निष्पादित किया जाएगा।

यह नियंत्रित करने के लिए कि एक प्रक्रिया क्या कर सकती है या नहीं, **सैंडबॉक्स में लगभग किसी भी ऑपरेशन में हुक होते हैं** जो एक प्रक्रिया कोशिश कर सकती है (अधिकांश syscalls सहित) **MACF** का उपयोग करते हुए। हालाँकि, ऐप के **अधिकारों** के आधार पर सैंडबॉक्स प्रक्रिया के साथ अधिक उदार हो सकता है।

सैंडबॉक्स के कुछ महत्वपूर्ण घटक हैं:

- **कर्नेल एक्सटेंशन** `/System/Library/Extensions/Sandbox.kext`
- **निजी ढांचा** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- उपयोगकर्ता भूमि में चलने वाला एक **डेमन** `/usr/libexec/sandboxd`
- **कंटेनर** `~/Library/Containers`

### Containers

हर सैंडबॉक्स की गई ऐप्लिकेशन का अपना कंटेनर होगा `~/Library/Containers/{CFBundleIdentifier}` :
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
प्रत्येक बंडल आईडी फ़ोल्डर के अंदर आप **plist** और ऐप का **Data directory** पा सकते हैं, जिसकी संरचना होम फ़ोल्डर की नकल करती है:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> ध्यान दें कि भले ही symlinks "Sandbox" से "escape" करने और अन्य फ़ोल्डरों तक पहुँचने के लिए वहाँ हैं, ऐप को अभी भी **अनुमतियाँ** होनी चाहिए ताकि वह उन्हें एक्सेस कर सके। ये अनुमतियाँ **`.plist`** में `RedirectablePaths` के अंदर हैं।

**`SandboxProfileData`** संकलित सैंडबॉक्स प्रोफ़ाइल CFData है जिसे B64 में एस्केप किया गया है।
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> एक Sandboxed एप्लिकेशन द्वारा बनाई गई/संशोधित हर चीज़ को **quarantine attribute** मिलेगा। यदि सैंडबॉक्स ऐप कुछ **`open`** के साथ निष्पादित करने की कोशिश करता है, तो यह Gatekeeper को ट्रिगर करके एक सैंडबॉक्स स्थान को रोक देगा।

## Sandbox Profiles

Sandbox प्रोफाइल कॉन्फ़िगरेशन फ़ाइलें हैं जो यह संकेत देती हैं कि उस **Sandbox** में क्या **अनुमति/प्रतिबंधित** होगा। यह **Sandbox Profile Language (SBPL)** का उपयोग करता है, जो [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) प्रोग्रामिंग भाषा का उपयोग करता है।

यहाँ एक उदाहरण है:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> इस [**शोध**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **को अधिक क्रियाओं की जांच करने के लिए देखें जो अनुमति दी जा सकती हैं या अस्वीकृत की जा सकती हैं।**
>
> ध्यान दें कि एक प्रोफ़ाइल के संकलित संस्करण में संचालन के नाम को एक ऐरे में उनके प्रविष्टियों द्वारा प्रतिस्थापित किया जाता है जिसे dylib और kext द्वारा जाना जाता है, जिससे संकलित संस्करण छोटा और पढ़ने में अधिक कठिन हो जाता है।

महत्वपूर्ण **सिस्टम सेवाएँ** अपने स्वयं के कस्टम **सैंडबॉक्स** के अंदर चलती हैं जैसे कि `mdnsresponder` सेवा। आप इन कस्टम **सैंडबॉक्स प्रोफाइल** को देख सकते हैं:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- अन्य सैंडबॉक्स प्रोफाइल की जांच [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) में की जा सकती है।

**ऐप स्टोर** ऐप्स **प्रोफ़ाइल** **`/System/Library/Sandbox/Profiles/application.sb`** का उपयोग करते हैं। आप इस प्रोफ़ाइल में देख सकते हैं कि कैसे अधिकार जैसे **`com.apple.security.network.server`** एक प्रक्रिया को नेटवर्क का उपयोग करने की अनुमति देते हैं।

SIP एक सैंडबॉक्स प्रोफ़ाइल है जिसे /System/Library/Sandbox/rootless.conf में platform_profile कहा जाता है।

### सैंडबॉक्स प्रोफ़ाइल उदाहरण

एक **विशिष्ट सैंडबॉक्स प्रोफ़ाइल** के साथ एक एप्लिकेशन शुरू करने के लिए आप उपयोग कर सकते हैं:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!NOTE]
> ध्यान दें कि **Apple द्वारा लिखित** **सॉफ़्टवेयर** जो **Windows** पर चलता है, उसमें **अतिरिक्त सुरक्षा उपाय** नहीं हैं, जैसे कि एप्लिकेशन सैंडबॉक्सिंग।

बायपास के उदाहरण:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (वे `~$` से शुरू होने वाले फ़ाइलों को सैंडबॉक्स के बाहर लिखने में सक्षम हैं)।

### सैंडबॉक्स ट्रेसिंग

#### प्रोफ़ाइल के माध्यम से

यह संभव है कि हर बार जब कोई क्रिया जांची जाती है, तो सैंडबॉक्स द्वारा किए गए सभी चेक को ट्रेस किया जा सके। इसके लिए बस निम्नलिखित प्रोफ़ाइल बनाएं:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
फिर उस प्रोफ़ाइल का उपयोग करके कुछ निष्पादित करें:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` में आप देख सकेंगे कि हर बार जब इसे कॉल किया गया, तो प्रत्येक सैंडबॉक्स चेक कैसे किया गया (तो, बहुत सारे डुप्लिकेट हैं)।

सैंडबॉक्स को **`-t`** पैरामीटर का उपयोग करके ट्रेस करना भी संभव है: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API के माध्यम से

`libsystem_sandbox.dylib` द्वारा निर्यातित `sandbox_set_trace_path` फ़ंक्शन एक ट्रेस फ़ाइल नाम निर्दिष्ट करने की अनुमति देता है जहाँ सैंडबॉक्स चेक लिखे जाएंगे।\
यह कुछ समान करने के लिए `sandbox_vtrace_enable()` को कॉल करके और फिर बफर से लॉग त्रुटियों को प्राप्त करने के लिए `sandbox_vtrace_report()` को कॉल करके भी संभव है।

### सैंडबॉक्स निरीक्षण

`libsandbox.dylib` एक फ़ंक्शन निर्यात करता है जिसे sandbox_inspect_pid कहा जाता है, जो एक प्रक्रिया की सैंडबॉक्स स्थिति की सूची देता है (जिसमें एक्सटेंशन शामिल हैं)। हालाँकि, केवल प्लेटफ़ॉर्म बाइनरी इस फ़ंक्शन का उपयोग कर सकती हैं।

### MacOS और iOS सैंडबॉक्स प्रोफाइल

MacOS सिस्टम सैंडबॉक्स प्रोफाइल को दो स्थानों पर संग्रहीत करता है: **/usr/share/sandbox/** और **/System/Library/Sandbox/Profiles**।

और यदि कोई तृतीय-पक्ष एप्लिकेशन _**com.apple.security.app-sandbox**_ अधिकार लेता है, तो सिस्टम उस प्रक्रिया पर **/System/Library/Sandbox/Profiles/application.sb** प्रोफाइल लागू करता है।

iOS में, डिफ़ॉल्ट प्रोफाइल को **container** कहा जाता है और हमारे पास SBPL पाठ प्रतिनिधित्व नहीं है। मेमोरी में, इस सैंडबॉक्स को सैंडबॉक्स से प्रत्येक अनुमतियों के लिए अनुमति/निषेध बाइनरी ट्री के रूप में दर्शाया गया है।

### ऐप स्टोर ऐप्स में कस्टम SBPL

कंपनियों के लिए अपने ऐप्स को **कस्टम सैंडबॉक्स प्रोफाइल** के साथ चलाना संभव हो सकता है (डिफ़ॉल्ट के बजाय)। उन्हें अधिकार **`com.apple.security.temporary-exception.sbpl`** का उपयोग करना होगा जिसे Apple द्वारा अधिकृत किया जाना चाहिए।

इस अधिकार की परिभाषा की जांच करना संभव है **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
यह **इस अधिकार के बाद के स्ट्रिंग को** एक Sandbox प्रोफ़ाइल के रूप में **eval** करेगा।

### Sandbox प्रोफ़ाइल को संकलित और डीकंपाइल करना

**`sandbox-exec`** उपकरण `libsandbox.dylib` से `sandbox_compile_*` कार्यों का उपयोग करता है। मुख्य निर्यातित कार्य हैं: `sandbox_compile_file` (एक फ़ाइल पथ की अपेक्षा करता है, पैरामीटर `-f`), `sandbox_compile_string` (एक स्ट्रिंग की अपेक्षा करता है, पैरामीटर `-p`), `sandbox_compile_name` (एक कंटेनर का नाम अपेक्षित है, पैरामीटर `-n`), `sandbox_compile_entitlements` (अधिकार plist की अपेक्षा करता है)।

इसका उलटा और [**उद्घाटन स्रोत संस्करण उपकरण sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) **`sandbox-exec`** को संकलित Sandbox प्रोफ़ाइल को फ़ाइल में लिखने की अनुमति देता है।

इसके अलावा, एक प्रक्रिया को एक कंटेनर के अंदर सीमित करने के लिए यह `sandbox_spawnattrs_set[container/profilename]` को कॉल कर सकता है और एक कंटेनर या पूर्व-निर्मित प्रोफ़ाइल पास कर सकता है।

## Sandbox को डिबग और बायपास करना

macOS पर, iOS के विपरीत जहां प्रक्रियाएँ शुरू से ही कर्नेल द्वारा Sandbox की गई होती हैं, **प्रक्रियाओं को स्वयं Sandbox में शामिल होना चाहिए**। इसका मतलब है कि macOS पर, एक प्रक्रिया Sandbox द्वारा प्रतिबंधित नहीं होती है जब तक कि वह सक्रिय रूप से इसमें प्रवेश करने का निर्णय नहीं लेती, हालांकि App Store ऐप्स हमेशा Sandbox में होते हैं।

यदि प्रक्रियाओं के पास अधिकार है: `com.apple.security.app-sandbox`, तो वे उपयोगकर्ता भूमि से स्वचालित रूप से Sandbox में होती हैं जब वे शुरू होती हैं। इस प्रक्रिया के विस्तृत विवरण के लिए देखें:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox एक्सटेंशन**

एक्सटेंशन किसी वस्तु को और अधिक विशेषाधिकार देने की अनुमति देते हैं और इनमें से किसी एक कार्य को कॉल करते हैं:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

एक्सटेंशन दूसरे MACF लेबल स्लॉट में संग्रहीत होते हैं जो प्रक्रिया क्रेडेंशियल्स से सुलभ होते हैं। निम्नलिखित **`sbtool`** इस जानकारी तक पहुँच सकता है।

ध्यान दें कि एक्सटेंशन आमतौर पर अनुमत प्रक्रियाओं द्वारा दिए जाते हैं, उदाहरण के लिए, `tccd` उस प्रक्रिया को `com.apple.tcc.kTCCServicePhotos` का एक्सटेंशन टोकन देगा जब एक प्रक्रिया फ़ोटो तक पहुँचने की कोशिश करती है और उसे XPC संदेश में अनुमति दी जाती है। फिर, प्रक्रिया को एक्सटेंशन टोकन का उपभोग करने की आवश्यकता होगी ताकि इसे जोड़ा जा सके।\
ध्यान दें कि एक्सटेंशन टोकन लंबे हेक्साडेसिमल होते हैं जो दिए गए अनुमतियों को एन्कोड करते हैं। हालाँकि, इनमें अनुमत PID हार्डकोडेड नहीं होता है, जिसका अर्थ है कि किसी भी प्रक्रिया के पास टोकन तक पहुँच होने पर इसे **कई प्रक्रियाओं द्वारा उपभोग किया जा सकता है**।

ध्यान दें कि एक्सटेंशन भी अधिकारों से बहुत संबंधित होते हैं, इसलिए कुछ अधिकार होने से स्वचालित रूप से कुछ एक्सटेंशन मिल सकते हैं।

### **PID विशेषाधिकार की जाँच करें**

[**इसके अनुसार**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), **`sandbox_check`** कार्य (यह एक `__mac_syscall` है), यह जाँच कर सकते हैं **क्या एक ऑपरेशन को एक निश्चित PID, ऑडिट टोकन या अद्वितीय ID द्वारा Sandbox में अनुमति दी गई है या नहीं**।

[**उपकरण sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (इसे [यहाँ संकलित किया गया है](https://newosxbook.com/articles/hitsb.html)) यह जाँच कर सकता है कि क्या एक PID कुछ निश्चित क्रियाएँ कर सकता है:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

यह संभव है कि `libsystem_sandbox.dylib` से `sandbox_suspend` और `sandbox_unsuspend` फ़ंक्शंस का उपयोग करके सैंडबॉक्स को निलंबित और पुनः सक्रिय किया जाए।

ध्यान दें कि निलंबित फ़ंक्शन को कॉल करने के लिए कुछ अधिकारों की जांच की जाती है ताकि कॉलर को इसे कॉल करने के लिए अधिकृत किया जा सके जैसे:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

यह सिस्टम कॉल (#381) पहले तर्क के रूप में एक स्ट्रिंग की अपेक्षा करता है जो चलाने के लिए मॉड्यूल को इंगित करेगा, और फिर दूसरे तर्क में एक कोड जो चलाने के लिए फ़ंक्शन को इंगित करेगा। फिर तीसरा तर्क उस फ़ंक्शन पर निर्भर करेगा जो निष्पादित किया गया है।

फ़ंक्शन `___sandbox_ms` कॉल `mac_syscall` को लपेटता है जो पहले तर्क में `"Sandbox"` को इंगित करता है ठीक वैसे ही जैसे `___sandbox_msp` `mac_set_proc` (#387) का एक लपेटन है। फिर, `___sandbox_ms` द्वारा समर्थित कुछ कोड इस तालिका में पाए जा सकते हैं:

- **set_profile (#0)**: एक प्रक्रिया पर एक संकलित या नामित प्रोफ़ाइल लागू करें।
- **platform_policy (#1)**: प्लेटफ़ॉर्म-विशिष्ट नीति जांच लागू करें (macOS और iOS के बीच भिन्नता होती है)।
- **check_sandbox (#2)**: एक विशिष्ट सैंडबॉक्स ऑपरेशन की मैनुअल जांच करें।
- **note (#3)**: एक सैंडबॉक्स में एक नोटेशन जोड़ें।
- **container (#4)**: एक सैंडबॉक्स में एक एनोटेशन संलग्न करें, आमतौर पर डिबगिंग या पहचान के लिए।
- **extension_issue (#5)**: एक प्रक्रिया के लिए एक नया एक्सटेंशन उत्पन्न करें।
- **extension_consume (#6)**: एक दिए गए एक्सटेंशन का उपभोग करें।
- **extension_release (#7)**: एक उपभोग किए गए एक्सटेंशन से संबंधित मेमोरी को मुक्त करें।
- **extension_update_file (#8)**: सैंडबॉक्स के भीतर एक मौजूदा फ़ाइल एक्सटेंशन के पैरामीटर को संशोधित करें।
- **extension_twiddle (#9)**: एक मौजूदा फ़ाइल एक्सटेंशन को समायोजित या संशोधित करें (जैसे, TextEdit, rtf, rtfd)।
- **suspend (#10)**: सभी सैंडबॉक्स जांचों को अस्थायी रूप से निलंबित करें (उचित अधिकारों की आवश्यकता होती है)।
- **unsuspend (#11)**: सभी पूर्व में निलंबित सैंडबॉक्स जांचों को फिर से शुरू करें।
- **passthrough_access (#12)**: एक संसाधन के लिए सीधे पासथ्रू एक्सेस की अनुमति दें, सैंडबॉक्स जांचों को बायपास करते हुए।
- **set_container_path (#13)**: (iOS केवल) एक ऐप समूह या साइनिंग आईडी के लिए एक कंटेनर पथ सेट करें।
- **container_map (#14)**: (iOS केवल) `containermanagerd` से एक कंटेनर पथ प्राप्त करें।
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) सैंडबॉक्स में उपयोगकर्ता मोड मेटाडेटा सेट करें।
- **inspect (#16)**: एक सैंडबॉक्स की गई प्रक्रिया के बारे में डिबग जानकारी प्रदान करें।
- **dump (#18)**: (macOS 11) विश्लेषण के लिए एक सैंडबॉक्स की वर्तमान प्रोफ़ाइल को डंप करें।
- **vtrace (#19)**: निगरानी या डिबगिंग के लिए सैंडबॉक्स संचालन का पता लगाएं।
- **builtin_profile_deactivate (#20)**: (macOS < 11) नामित प्रोफ़ाइलों को निष्क्रिय करें (जैसे, `pe_i_can_has_debugger`)।
- **check_bulk (#21)**: एक ही कॉल में कई `sandbox_check` संचालन करें।
- **reference_retain_by_audit_token (#28)**: सैंडबॉक्स जांचों में उपयोग के लिए एक ऑडिट टोकन के लिए एक संदर्भ बनाएं।
- **reference_release (#29)**: पहले से रखे गए ऑडिट टोकन संदर्भ को मुक्त करें।
- **rootless_allows_task_for_pid (#30)**: सत्यापित करें कि `task_for_pid` की अनुमति है या नहीं (जो `csr` जांचों के समान है)।
- **rootless_whitelist_push (#31)**: (macOS) एक सिस्टम इंटीग्रिटी प्रोटेक्शन (SIP) मैनिफेस्ट फ़ाइल लागू करें।
- **rootless_whitelist_check (preflight) (#32)**: निष्पादन से पहले SIP मैनिफेस्ट फ़ाइल की जांच करें।
- **rootless_protected_volume (#33)**: (macOS) एक डिस्क या विभाजन पर SIP सुरक्षा लागू करें।
- **rootless_mkdir_protected (#34)**: एक निर्देशिका निर्माण प्रक्रिया पर SIP/DataVault सुरक्षा लागू करें।

## Sandbox.kext

ध्यान दें कि iOS में कर्नेल एक्सटेंशन में **सभी प्रोफ़ाइल हार्डकोडेड** होती हैं जो `__TEXT.__const` खंड के भीतर होती हैं ताकि उन्हें संशोधित नहीं किया जा सके। कर्नेल एक्सटेंशन से कुछ दिलचस्प फ़ंक्शंस निम्नलिखित हैं:

- **`hook_policy_init`**: यह `mpo_policy_init` को हुक करता है और इसे `mac_policy_register` के बाद कॉल किया जाता है। यह सैंडबॉक्स के अधिकांश प्रारंभिककरण करता है। यह SIP को भी प्रारंभ करता है।
- **`hook_policy_initbsd`**: यह `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` और `security.mac.sandbox.debug_mode` को पंजीकृत करते हुए sysctl इंटरफ़ेस सेट करता है (यदि `PE_i_can_has_debugger` के साथ बूट किया गया हो)।
- **`hook_policy_syscall`**: इसे `mac_syscall` द्वारा "Sandbox" के पहले तर्क के रूप में और दूसरे में ऑपरेशन को इंगित करने वाले कोड के साथ कॉल किया जाता है। एक स्विच का उपयोग अनुरोधित कोड के अनुसार चलाने के लिए कोड खोजने के लिए किया जाता है।

### MACF Hooks

**`Sandbox.kext`** MACF के माध्यम से एक सौ से अधिक हुक का उपयोग करता है। अधिकांश हुक कुछ तुच्छ मामलों की जांच करेंगे जो कार्रवाई करने की अनुमति देते हैं, यदि नहीं, तो वे **`cred_sb_evalutate`** को MACF से **क्रेडेंशियल्स** और एक संख्या के साथ कॉल करेंगे जो **ऑपरेशन** को करने के लिए है और एक **बफर** आउटपुट के लिए है।

इसका एक अच्छा उदाहरण फ़ंक्शन **`_mpo_file_check_mmap`** है जो **`mmap`** को हुक करता है और यह जांचना शुरू करेगा कि क्या नई मेमोरी लिखने योग्य होने जा रही है (और यदि नहीं तो निष्पादन की अनुमति नहीं देगा), फिर यह जांचेगा कि क्या इसका उपयोग dyld साझा कैश के लिए किया जा रहा है और यदि हां तो निष्पादन की अनुमति देगा, और अंततः यह **`sb_evaluate_internal`** (या इसके लपेटनों में से एक) को आगे की अनुमति जांच करने के लिए कॉल करेगा।

इसके अलावा, सैंडबॉक्स द्वारा उपयोग किए जाने वाले सौ(ओं) हुक में से, 3 विशेष रूप से बहुत दिलचस्प हैं:

- `mpo_proc_check_for`: यदि आवश्यक हो तो प्रोफ़ाइल लागू करता है और यदि इसे पहले लागू नहीं किया गया था।
- `mpo_vnode_check_exec`: जब एक प्रक्रिया संबंधित बाइनरी को लोड करती है, तो एक प्रोफ़ाइल जांच की जाती है और SUID/SGID निष्पादनों को प्रतिबंधित करने के लिए भी एक जांच की जाती है।
- `mpo_cred_label_update_execve`: यह तब कॉल किया जाता है जब लेबल असाइन किया जाता है। यह सबसे लंबा होता है क्योंकि इसे तब कॉल किया जाता है जब बाइनरी पूरी तरह से लोड हो जाती है लेकिन अभी तक निष्पादित नहीं होती है। यह सैंडबॉक्स ऑब्जेक्ट बनाने, kauth क्रेडेंशियल्स से सैंडबॉक्स संरचना संलग्न करने, mach पोर्ट्स तक पहुंच को हटाने जैसी क्रियाएँ करेगा...

ध्यान दें कि **`_cred_sb_evalutate`** **`sb_evaluate_internal`** का एक लपेटन है और यह फ़ंक्शन पास किए गए क्रेडेंशियल्स को प्राप्त करता है और फिर **`eval`** फ़ंक्शन का उपयोग करके मूल्यांकन करता है जो आमतौर पर **प्लेटफ़ॉर्म प्रोफ़ाइल** का मूल्यांकन करता है जो डिफ़ॉल्ट रूप से सभी प्रक्रियाओं पर लागू होता है और फिर **विशिष्ट प्रक्रिया प्रोफ़ाइल**। ध्यान दें कि प्लेटफ़ॉर्म प्रोफ़ाइल macOS में **SIP** के मुख्य घटकों में से एक है।

## Sandboxd

सैंडबॉक्स में एक उपयोगकर्ता डेमन भी चल रहा है जो XPC Mach सेवा `com.apple.sandboxd` को उजागर करता है और विशेष पोर्ट 14 (`HOST_SEATBELT_PORT`) को बाइंड करता है जिसका उपयोग कर्नेल एक्सटेंशन इसके साथ संवाद करने के लिए करता है। यह MIG का उपयोग करके कुछ फ़ंक्शंस को उजागर करता है।

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
