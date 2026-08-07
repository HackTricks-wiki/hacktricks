# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## मूल जानकारी

MacOS Sandbox (जिसे शुरू में Seatbelt कहा जाता था) Sandbox के अंदर चलने वाले **applications को सीमित करता है**, ताकि वे केवल उन **अनुमत actions** को कर सकें जो उस Sandbox profile में निर्दिष्ट हैं जिसके साथ app चल रहा है। इससे यह सुनिश्चित करने में मदद मिलती है कि **application केवल अपेक्षित resources तक ही पहुंच बनाएगा**।

जिस भी app में **entitlement** **`com.apple.security.app-sandbox`** होता है, वह Sandbox के अंदर execute किया जाएगा। **Apple binaries** आमतौर पर Sandbox के अंदर execute की जाती हैं, और **App Store से आने वाले सभी applications में यह entitlement होता है**। इसलिए कई applications Sandbox के अंदर execute किए जाएंगे।<sup>[[4]](#references)</sup>

किसी process के लिए क्या करना संभव है या नहीं, इसे नियंत्रित करने के लिए **Sandbox में hooks होते हैं** जो किसी process द्वारा किए जा सकने वाले लगभग हर operation (अधिकांश syscalls सहित) में **MACF** का उपयोग करते हैं। हालांकि, app के **entitlements** के आधार पर Sandbox process के लिए अधिक permissive हो सकता है।

Sandbox के कुछ महत्वपूर्ण components हैं:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- userland में चलने वाला एक **daemon** `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

हर sandboxed application का अपना container `~/Library/Containers/{CFBundleIdentifier}` में होगा:
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
प्रत्येक bundle id फ़ोल्डर के अंदर आपको App का **plist** और **Data directory** मिल सकता है, जिसकी संरचना Home फ़ोल्डर जैसी होती है:
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
> ध्यान दें कि भले ही Sandbox से "escape" करने और अन्य folders तक access करने के लिए symlinks मौजूद हों, App के पास उन तक access करने की **permissions** होना आवश्यक है। ये permissions **`.plist`** में `RedirectablePaths` के अंदर होती हैं।

**`SandboxProfileData`** compiled sandbox profile CFData है, जिसे B64 में escaped किया गया है।
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
> किसी Sandboxed application द्वारा बनाई/संशोधित की गई हर चीज़ को **quarantine attribute** मिल जाएगा। यह sandbox app द्वारा **`open`** का उपयोग करके किसी चीज़ को execute करने का प्रयास करने पर Gatekeeper को trigger करके sandbox space को रोक देगा।

## Sandbox Profiles

Sandbox profiles वे configuration files हैं जो बताती हैं कि उस **Sandbox** में क्या **allowed/forbidden** होगा। इसमें **Sandbox Profile Language (SBPL)** का उपयोग किया जाता है, जो [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) programming language का उपयोग करती है।

यहाँ आपको एक example मिल सकता है:
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
> अधिक actions जिन्हें allow या deny किया जा सकता है, उन्हें देखने के लिए इस [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) को देखें।<sup>[[5]](#references)</sup>
>
> ध्यान दें कि किसी profile के compiled version में operations के नामों को dylib और kext द्वारा ज्ञात array में उनकी entries से substitude कर दिया जाता है, जिससे compiled version छोटा और पढ़ने में अधिक कठिन हो जाता है।

महत्वपूर्ण **system services** भी अपने custom **sandbox** के अंदर run होती हैं, जैसे `mdnsresponder` service। आप इन custom **sandbox profiles** को यहां देख सकते हैं:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- अन्य sandbox profiles को [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) में check किया जा सकता है।
- iOS में platform profile, sandbox `.kext` के अंदर binary में मौजूद `_platform_profile_data` के अंदर होती है।

**App Store** apps **profile** **`/System/Library/Sandbox/Profiles/application.sb`** का उपयोग करती हैं। आप इस profile में check कर सकते हैं कि **`com.apple.security.network.server`** जैसे entitlements किसी process को network का उपयोग करने की अनुमति कैसे देते हैं।

इसके बाद, कुछ **Apple daemon services** `/System/Library/Sandbox/Profiles/*.sb` या `/usr/share/sandbox/*.sb` में स्थित अलग-अलग profiles का उपयोग करती हैं। ये sandboxes API `sandbox_init_XXX` को call करने वाले main function में लागू की जाती हैं।<sup>[[3]](#references)</sup>

**SIP** एक Sandbox profile है जिसे `/System/Library/Sandbox/rootless.conf` में platform_profile कहा जाता है।

### Sandbox Profile के उदाहरण

किसी application को **specific sandbox profile** के साथ start करने के लिए आप इसका उपयोग कर सकते हैं:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
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

> [!TIP]
> ध्यान दें कि **Windows** पर चलने वाले **Apple-authored** **software** में application sandboxing जैसी कोई अतिरिक्त security precautions नहीं होती हैं।

Bypasses के उदाहरण:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (वे sandbox के बाहर ऐसी files लिखने में सक्षम हैं जिनका नाम `~$` से शुरू होता है।)<sup>[[7]](#references)</sup>

### Sandbox Tracing

#### Via profile

हर बार किसी action की जांच होने पर sandbox द्वारा किए जाने वाले सभी checks को trace करना संभव है। इसके लिए बस निम्नलिखित profile बनाएं:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
और फिर बस उस profile का उपयोग करके कुछ execute करें:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` में आप हर बार किए गए प्रत्येक sandbox check को देख सकेंगे (इसलिए, बहुत सारे duplicates होंगे)।

**`-t`** parameter का उपयोग करके sandbox को trace करना भी संभव है: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

`libsystem_sandbox.dylib` द्वारा exported `sandbox_set_trace_path` function एक trace filename निर्दिष्ट करने की सुविधा देता है, जिसमें sandbox checks लिखे जाएंगे।\
`समान कार्य` `sandbox_vtrace_enable()` को call करके और फिर buffer से error logs प्राप्त करने के लिए `sandbox_vtrace_report()` को call करके भी किया जा सकता है।

### Sandbox Inspection

`libsandbox.dylib` एक `sandbox_inspect_pid` function export करता है, जो किसी process की sandbox state (extensions सहित) की list देता है। हालांकि, केवल platform binaries ही इस function का उपयोग कर सकते हैं।

### MacOS & iOS Sandbox Profiles

MacOS system sandbox profiles को दो locations में store करता है: **/usr/share/sandbox/** और **/System/Library/Sandbox/Profiles**।

और यदि किसी third-party application में _**com.apple.security.app-sandbox**_ entitlement मौजूद हो, तो system उस process पर **/System/Library/Sandbox/Profiles/application.sb** profile लागू करता है।

iOS में, default profile को **container** कहा जाता है और हमारे पास SBPL text representation नहीं है। Memory में, यह sandbox प्रत्येक sandbox permission के लिए Allow/Deny binary tree के रूप में represented होता है।

### Custom SBPL in App Store apps

Companies के लिए अपने apps को **custom Sandbox profiles** के साथ (default profile के बजाय) run करना संभव हो सकता है। उन्हें **`com.apple.security.temporary-exception.sbpl`** entitlement का उपयोग करना होगा, जिसे Apple द्वारा authorize किया जाना आवश्यक है।

इस entitlement की definition को **`/System/Library/Sandbox/Profiles/application.sb:`** में check करना संभव है।
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
यह **इस entitlement के बाद वाली string को** Sandbox profile के रूप में `eval` करेगा।

### Sandbox Profile को Compiling और decompiling करना

**`sandbox-exec`** tool `libsandbox.dylib` से `sandbox_compile_*` functions का उपयोग करता है। Export किए गए मुख्य functions हैं: `sandbox_compile_file` (एक file path की अपेक्षा करता है, param `-f`), `sandbox_compile_string` (एक string की अपेक्षा करता है, param `-p`), `sandbox_compile_name` (एक container के name की अपेक्षा करता है, param `-n`), `sandbox_compile_entitlements` (entitlements plist की अपेक्षा करता है)।

यह reversed और [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) **`sandbox-exec`** को compiled sandbox profile को एक file में लिखने की अनुमति देता है।

इसके अलावा, किसी process को किसी container के अंदर सीमित करने के लिए वह `sandbox_spawnattrs_set[container/profilename]` को call कर सकता है और कोई container या पहले से मौजूद profile pass कर सकता है।

## Debug और Bypass Sandbox

macOS पर, iOS के विपरीत जहां processes को शुरुआत से ही kernel द्वारा sandbox किया जाता है, **processes को स्वयं Sandbox में opt-in करना पड़ता है**। इसका अर्थ है कि macOS पर कोई process तब तक Sandbox द्वारा restricted नहीं होता जब तक वह सक्रिय रूप से उसमें enter करने का निर्णय न ले, हालांकि App Store apps हमेशा sandboxed होते हैं।

यदि उनके पास entitlement: `com.apple.security.app-sandbox` हो, तो processes userland से start होते समय automatically Sandboxed हो जाते हैं। इस process की विस्तृत explanation के लिए देखें:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions किसी object को अतिरिक्त privileges देने की अनुमति देते हैं और निम्न में से किसी एक function को call करके दिए जाते हैं:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions को process credentials से accessible दूसरे MACF label slot में store किया जाता है। निम्नलिखित **`sbtool`** इस information को access कर सकता है।

ध्यान दें कि extensions आमतौर पर allowed processes द्वारा grant किए जाते हैं, उदाहरण के लिए, जब किसी process ने photos access करने का प्रयास किया और XPC message में उसे अनुमति दी गई, तो `tccd` `com.apple.tcc.kTCCServicePhotos` का extension token grant करेगा। इसके बाद process को extension token consume करना होगा, ताकि वह उसमें add हो जाए।\
ध्यान दें कि extension tokens लंबे hexadecimal होते हैं, जो granted permissions को encode करते हैं। हालांकि उनमें allowed PID hardcoded नहीं होता, जिसका अर्थ है कि token तक access रखने वाला कोई भी process इसे **multiple processes द्वारा consumed** करवा सकता है।

ध्यान दें कि extensions entitlements से भी बहुत closely related होते हैं, इसलिए कुछ entitlements होने पर कुछ extensions automatically grant हो सकते हैं।

### **PID Privileges को Check करना**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), **`sandbox_check`** functions (यह एक `__mac_syscall` है), किसी निश्चित PID, audit token या unique ID में कोई operation Sandbox द्वारा allowed है या नहीं, यह check कर सकते हैं।<sup>[[8]](#references)</sup>

[**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) ([यहां compiled रूप में खोजें](https://newosxbook.com/articles/hitsb.html)) यह check कर सकता है कि कोई PID कोई निश्चित action perform कर सकता है या नहीं:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

`libsystem_sandbox.dylib` से `sandbox_suspend` और `sandbox_unsuspend` functions का उपयोग करके sandbox को suspend और unsuspend करना भी संभव है।

ध्यान दें कि suspend function को call करने के लिए caller को इसे call करने की अनुमति देने हेतु कुछ entitlements की जाँच की जाती है, जैसे:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

यह system call (#381) पहले argument के रूप में एक string की अपेक्षा करता है, जो चलाए जाने वाले module को दर्शाएगी, और फिर दूसरे argument में एक code होगा, जो चलाए जाने वाले function को दर्शाएगा। इसके बाद तीसरा argument executed function पर निर्भर करेगा।<sup>[[2]](#references)</sup>

`___sandbox_ms` function `mac_syscall` को wrap करता है और पहले argument में `"Sandbox"` दर्शाता है, ठीक उसी तरह जैसे `___sandbox_msp`, `mac_set_proc` (#387) का wrapper है। इसके बाद, `___sandbox_ms` द्वारा समर्थित कुछ codes इस table में पाए जा सकते हैं:

- **set_profile (#0)**: किसी process पर compiled या named profile लागू करता है।
- **platform_policy (#1)**: platform-specific policy checks लागू करता है (macOS और iOS के बीच अलग-अलग)।
- **check_sandbox (#2)**: किसी विशिष्ट sandbox operation की manual जाँच करता है।
- **note (#3)**: Sandbox में एक annotation जोड़ता है।
- **container (#4)**: sandbox से एक annotation जोड़ता है, सामान्यतः debugging या identification के लिए।
- **extension_issue (#5)**: किसी process के लिए एक नया extension generate करता है।
- **extension_consume (#6)**: दिए गए extension को consume करता है।
- **extension_release (#7)**: consumed extension से जुड़ी memory release करता है।
- **extension_update_file (#8)**: sandbox के भीतर किसी existing file extension के parameters को modify करता है।
- **extension_twiddle (#9)**: किसी existing file extension को adjust या modify करता है (जैसे, TextEdit, rtf, rtfd)।
- **suspend (#10)**: सभी sandbox checks को अस्थायी रूप से suspend करता है (उपयुक्त entitlements आवश्यक हैं)।
- **unsuspend (#11)**: पहले suspend किए गए सभी sandbox checks को resume करता है।
- **passthrough_access (#12)**: sandbox checks को bypass करते हुए किसी resource तक direct passthrough access की अनुमति देता है।
- **set_container_path (#13)**: (केवल iOS) किसी app group या signing ID के लिए container path सेट करता है।
- **container_map (#14)**: `containermanagerd` से container path retrieve करता है।
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) sandbox में user mode metadata सेट करता है।
- **inspect (#16)**: किसी sandboxed process के बारे में debug information प्रदान करता है।
- **dump (#18)**: (macOS 11) analysis के लिए sandbox का current profile dump करता है।
- **vtrace (#19)**: monitoring या debugging के लिए sandbox operations को trace करता है।
- **builtin_profile_deactivate (#20)**: (macOS < 11) named profiles को deactivate करता है (जैसे, `pe_i_can_has_debugger`)।
- **check_bulk (#21)**: एक ही call में कई `sandbox_check` operations करता है।
- **reference_retain_by_audit_token (#28)**: sandbox checks में उपयोग के लिए audit token का reference बनाता है।
- **reference_release (#29)**: पहले से retained audit token reference को release करता है।
- **rootless_allows_task_for_pid (#30)**: जाँचता है कि `task_for_pid` की अनुमति है या नहीं (`csr` checks के समान)।
- **rootless_whitelist_push (#31)**: (macOS) System Integrity Protection (SIP) manifest file लागू करता है।
- **rootless_whitelist_check (preflight) (#32)**: execution से पहले SIP manifest file की जाँच करता है।
- **rootless_protected_volume (#33)**: (macOS) किसी disk या partition पर SIP protections लागू करता है।
- **rootless_mkdir_protected (#34)**: किसी directory creation process पर SIP/DataVault protection लागू करता है।

## Sandbox.kext

ध्यान दें कि iOS में kernel extension में **सभी profiles hardcoded** रूप से `__TEXT.__const` segment के अंदर मौजूद होते हैं, ताकि उन्हें modify न किया जा सके। kernel extension के कुछ interesting functions निम्नलिखित हैं:

- **`hook_policy_init`**: यह `mpo_policy_init` को hook करता है और `mac_policy_register` के बाद call किया जाता है। यह Sandbox के अधिकांश initializations करता है। यह SIP को भी initialize करता है।
- **`hook_policy_initbsd`**: यह `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` और `security.mac.sandbox.debug_mode` को register करके sysctl interface सेट करता है (`PE_i_can_has_debugger` के साथ boot होने पर)।
- **`hook_policy_syscall`**: इसे `mac_syscall` द्वारा पहले argument के रूप में `"Sandbox"` और दूसरे argument में operation दर्शाने वाले code के साथ call किया जाता है। मांगे गए code के अनुसार चलाए जाने वाले code को खोजने के लिए switch का उपयोग किया जाता है।

### MACF Hooks

**`Sandbox.kext`** MACF के माध्यम से सौ से अधिक hooks का उपयोग करता है। अधिकांश hooks केवल कुछ trivial cases की जाँच करेंगे, जो action की अनुमति देते हैं; अन्यथा वे MACF से प्राप्त **credentials**, perform किए जाने वाले **operation** के अनुरूप एक number और output के लिए एक **buffer** के साथ **`cred_sb_evalutate`** को call करेंगे।<sup>[[1]](#references)</sup>

इसका एक अच्छा उदाहरण function **`_mpo_file_check_mmap`** है, जो `mmap` को hook करता है और पहले यह जाँचना शुरू करता है कि नई memory writable होगी या नहीं (और यदि नहीं, तो execution की अनुमति देता है), फिर यह जाँचता है कि इसका उपयोग dyld shared cache के लिए किया जा रहा है या नहीं; यदि ऐसा हो, तो execution की अनुमति देता है। अंत में, यह आगे की allowance checks करने के लिए **`sb_evaluate_internal`** (या इसके किसी wrapper) को call करता है।

इसके अलावा, Sandbox द्वारा उपयोग किए जाने वाले सौ से अधिक hooks में से 3 विशेष रूप से बहुत interesting हैं:

- `mpo_proc_check_for`: यदि आवश्यक हो और profile पहले लागू न किया गया हो, तो इसे लागू करता है।
- `mpo_vnode_check_exec`: इसे तब call किया जाता है जब कोई process संबंधित binary load करता है; इसके बाद profile check किया जाता है और SUID/SGID executions को रोकने वाली जाँच भी की जाती है।
- `mpo_cred_label_update_execve`: इसे तब call किया जाता है जब label assign किया जाता है। यह सबसे लंबा function है, क्योंकि इसे binary के पूरी तरह load होने पर, लेकिन उसके execute होने से पहले call किया जाता है। यह sandbox object बनाने, sandbox struct को kauth credentials से attach करने, mach ports तक access हटाने जैसी actions करता है।

ध्यान दें कि **`_cred_sb_evalutate`**, **`sb_evaluate_internal`** के ऊपर एक wrapper है और यह function दिए गए credentials प्राप्त करने के बाद **`eval`** function का उपयोग करके evaluation करता है। **`eval`** सामान्यतः **platform profile** का evaluation करता है, जो default रूप से सभी processes पर लागू होता है, और फिर **specific process profile** का। ध्यान दें कि macOS में platform profile **SIP** के मुख्य components में से एक है।

## Sandboxd

Sandbox में एक user daemon भी चलता है, जो XPC Mach service `com.apple.sandboxd` expose करता है और special port 14 (`HOST_SEATBELT_PORT`) से bind होता है; kernel extension इसके साथ communicate करने के लिए इसका उपयोग करता है। यह MIG का उपयोग करके कुछ functions expose करता है।

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
