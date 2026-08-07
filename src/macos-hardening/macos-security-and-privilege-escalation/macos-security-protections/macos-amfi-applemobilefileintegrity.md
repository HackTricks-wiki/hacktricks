# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext और amfid

यह system पर चल रहे code की integrity लागू करने पर केंद्रित है और XNU के code signature verification के पीछे का logic प्रदान करता है। यह entitlements की जाँच करने और debugging की अनुमति देने या task ports प्राप्त करने जैसे अन्य sensitive tasks को handle करने में भी सक्षम है।

इसके अलावा, कुछ operations के लिए kext user space में चल रहे daemon `/usr/libexec/amfid` से संपर्क करना पसंद करता है। इस trust relationship का कई jailbreaks में दुरुपयोग किया गया है।

Recent macOS versions में, AMFI अब standalone on-disk kext के रूप में conveniently exposed नहीं है, इसलिए reversing का अर्थ आमतौर पर `/System/Library/Extensions` को browse करने के बजाय **kernelcache** या **KDK** से काम करना होता है।

AMFI **MACF** policies का उपयोग करता है और start होते ही अपने hooks register करता है। इसके loading को रोकना या इसे unload करना kernel panic trigger कर सकता है। हालांकि, कुछ boot arguments हैं जो AMFI को debilitate करने की अनुमति देते हैं:

- `amfi_unrestricted_task_for_pid`: आवश्यक entitlements के बिना task_for_pid को allow करता है
- `amfi_allow_any_signature`: किसी भी code signature को allow करता है
- `cs_enforcement_disable`: code signing enforcement को disable करने के लिए system-wide argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements वाले platform binaries को void करता है
- `amfi_get_out_of_my_way`: amfi को पूरी तरह disable करता है

ये कुछ MACF policies हैं जिन्हें यह register करता है:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Label update किया जाएगा और 1 return करेगा
- **`cred_label_associate`**: AMFI के mac label slot को label के साथ update करता है
- **`cred_label_destroy`**: AMFI का mac label slot remove करता है
- **`cred_label_init`**: AMFI के mac label slot में 0 move करता है
- **`cred_label_update_execve:`**: यह process के entitlements check करता है ताकि पता लगाया जा सके कि उसे labels modify करने की अनुमति होनी चाहिए या नहीं।
- **`file_check_mmap:`**: यह check करता है कि mmap memory acquire करके उसे executable के रूप में set कर रहा है या नहीं। ऐसी स्थिति में यह check करता है कि library validation आवश्यक है या नहीं और यदि आवश्यक हो, तो library validation function call करता है।
- **`file_check_library_validation`**: यह library validation function call करता है, जो अन्य बातों के साथ यह check करता है कि कोई platform binary किसी अन्य platform binary को load कर रही है या नहीं, अथवा process और नई loaded file का TeamID समान है या नहीं। कुछ entitlements किसी भी library को load करने की अनुमति भी देंगे।
- **`policy_initbsd`**: Trusted NVRAM Keys set up करता है
- **`policy_syscall`**: यह DYLD policies check करता है, जैसे कि binary में unrestricted segments हैं या नहीं, env vars को allow करना चाहिए या नहीं... इसे तब भी call किया जाता है जब कोई process `amfi_check_dyld_policy_self()` के माध्यम से start होता है।
- **`proc_check_inherit_ipc_ports`**: यह check करता है कि जब कोई process नई binary execute करता है, तो क्या process के task port पर SEND rights रखने वाले अन्य processes को वे rights बनाए रखने चाहिए या नहीं। Platform binaries को allow किया जाता है, `get-task-allow` entitled इसे allow करता है, `task_for_pid-allow` entitles को allow किया जाता है और समान TeamID वाली binaries को भी allow किया जाता है।
- **`proc_check_expose_task`**: entitlements enforce करता है
- **`amfi_exc_action_check_exception_send`**: Debugger को exception message भेजा जाता है
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Exception handling (debugging) के दौरान Label lifecycle
- **`proc_check_get_task`**: `get-task-allow` जैसे entitlements check करता है, जो अन्य processes को process का task port प्राप्त करने की अनुमति देता है, और `task_for_pid-allow`, जो process को अन्य processes के task ports प्राप्त करने की अनुमति देता है। यदि इनमें से कोई भी मौजूद नहीं है, तो यह `amfid permitunrestricteddebugging` को call करके check करता है कि इसकी अनुमति है या नहीं।
- **`proc_check_mprotect`**: यदि `mprotect` को `VM_PROT_TRUSTED` flag के साथ call किया जाता है, तो deny करता है; यह flag दर्शाता है कि region को valid code signature वाले region की तरह treat किया जाना चाहिए।
- **`vnode_check_exec`**: Executable files को memory में load किए जाने पर call किया जाता है और `cs_hard | cs_kill` set करता है, जो किसी भी page के invalid होने पर process को kill कर देगा<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` और `isVnodeQuarantined()` check करता है
- **`vnode_check_setextattr`**: `get` के समान + `com.apple.private.allow-bless` और internal-installer-equivalent entitlement
- **`vnode_check_signature`**: वह code जो entitlements, trust cache और `amfid` का उपयोग करके code signature check करने के लिए XNU को call करता है<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: यह `ptrace()` calls (`PT_ATTACH` और `PT_TRACE_ME`) को intercept करता है। यह `get-task-allow`, `run-invalid-allow` और `run-unsigned-code` में से किसी भी entitlement को check करता है और यदि कोई भी नहीं है, तो check करता है कि debugging permitted है या नहीं।
- **`proc_check_map_anon`**: यदि mmap को **`MAP_JIT`** flag के साथ call किया जाता है, तो AMFI `dynamic-codesigning` entitlement check करेगा।

`AMFI.kext` अन्य kernel extensions के लिए एक API भी expose करता है, और इसकी dependencies को इस प्रकार find करना संभव है:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

यह user mode में चलने वाला daemon है, जिसका उपयोग `AMFI.kext` user mode में code signatures की जाँच करने के लिए करता है।\
`AMFI.kext` के लिए daemon के साथ communicate करने हेतु यह `HOST_AMFID_PORT` port पर mach messages का उपयोग करता है, जो special port `18` है।

ध्यान दें कि macOS में अब root processes के लिए special ports को hijack करना संभव नहीं है, क्योंकि वे `SIP` द्वारा protected हैं और केवल launchd ही उन्हें प्राप्त कर सकता है। iOS में यह जाँचा जाता है कि response वापस भेजने वाले process के पास `amfid` का hardcoded CDHash है।

`amfid` से किसी binary की जाँच करने का request किए जाने और उसके response को debugging करके तथा `mach_msg` में breakpoint सेट करके देखना संभव है।

जब special port के माध्यम से कोई message प्राप्त होता है, तो प्रत्येक function को उस function तक भेजने के लिए MIG का उपयोग किया जाता है जिसे वह call कर रहा है। मुख्य functions को reverse किया गया और book में समझाया गया है।

### DYLD policy और library validation

Recent `dyld` versions `configureProcessRestrictions()` से बहुत पहले `amfi_check_dyld_policy_self()` को call करते हैं, ताकि AMFI से पूछा जा सके कि process `DYLD_*` path variables, interposing, fallback paths और embedded variables का उपयोग कर सकता है या failed library insertion को tolerate कर सकता है। इसलिए, injection surface का triage करते समय केवल Mach-O load commands को inspect करना पर्याप्त नहीं है: आपको उन entitlements और runtime flags को भी inspect करना होगा जिन्हें AMFI `dyld` policy में translate करेगा।

एक practical triage loop इस प्रकार है:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
आधुनिक macOS पर कई Apple binaries अब सीधे `com.apple.security.cs.disable-library-validation` नहीं रखते, बल्कि `com.apple.private.security.clear-library-validation` के साथ ship होते हैं। ऐसी स्थिति में `execve` के समय library validation disabled नहीं होती: process को स्वयं पर `csops(..., CS_OPS_CLEAR_LV, ...)` call करना होता है, और XNU calling process पर इस operation की अनुमति केवल तभी देता है जब entitlement मौजूद हो। Offensive perspective से यह महत्वपूर्ण है, क्योंकि target केवल **तभी injectable** बन सकता है जब वह उस code path तक पहुंच जाए जो स्पष्ट रूप से LV clear करता है (उदाहरण के लिए, optional plugins load करने से कुछ समय पहले)।<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

एक provisioning profile का उपयोग code sign करने के लिए किया जा सकता है। **Developer** profiles होते हैं जिनका उपयोग code sign करके उसे test करने के लिए किया जा सकता है, और **Enterprise** profiles होते हैं जिनका उपयोग सभी devices में किया जा सकता है।

किसी App को Apple Store पर submit करने के बाद, यदि वह approved हो जाता है, तो Apple उसे sign करता है और provisioning profile की आवश्यकता नहीं रहती।

Profile में आमतौर पर `.mobileprovision` या `.provisionprofile` extension होती है और इसे इस command से dump किया जा सकता है:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
हालांकि इन्हें कभी-कभी certificated कहा जाता है, इन provisioning profiles में केवल certificate से अधिक जानकारी होती है:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: इसे Apple Internal profile के रूप में निर्दिष्ट करता है
- **ApplicationIdentifierPrefix**: AppIDName के आगे जोड़ा जाता है (TeamIdentifier के समान)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` format में दिनांक
- **DeveloperCertificates**: Base64 data के रूप में encoded certificate(s) की array (आमतौर पर एक)
- **Entitlements**: इस profile के साथ अनुमत entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` format में समाप्ति दिनांक
- **Name**: Application Name, जो AppIDName के समान है
- **ProvisionedDevices**: UDIDs की array (developer certificates के लिए) जिनके लिए यह profile valid है
- **ProvisionsAllDevices**: एक boolean (enterprise certificates के लिए true)
- **TeamIdentifier**: inter-app interaction उद्देश्यों के लिए developer की पहचान करने वाली alphanumeric string(s) की array (आमतौर पर एक)
- **TeamName**: developer की पहचान करने के लिए उपयोग किया जाने वाला human-readable नाम
- **TimeToLive**: certificate की validity (दिनों में)
- **UUID**: इस profile के लिए Universally Unique Identifier
- **Version**: वर्तमान में 1 पर सेट

ध्यान दें कि entitlements entry में entitlements का restricted set होगा और provisioning profile केवल उन्हीं specific entitlements को दे सकेगा, ताकि Apple private entitlements प्रदान न किए जा सकें।

ध्यान दें कि profiles आमतौर पर `/var/MobileDeviceProvisioningProfiles` में स्थित होते हैं और इन्हें **`security cms -D -i /path/to/profile`** से check किया जा सकता है।

## **libmis.dylib**

यह external library है जिसे `amfid` किसी चीज़ को allow करना है या नहीं, यह पूछने के लिए call करता है। इसका backdoored version चलाकर, जो सब कुछ allow करता था, historically jailbreaking में इसका abuse किया गया है।

macOS में यह `MobileDevice.framework` के अंदर होता है।

## AMFI Trust Caches

Trust caches केवल iOS concept नहीं हैं। Modern macOS में, विशेष रूप से **Apple silicon** पर, static trust cache और loadable trust caches Secure Boot chain का हिस्सा हैं। जब किसी Mach-O का **CodeDirectory hash** वहां मौजूद होता है, तो AMFI launch time पर further authenticity checks किए बिना उसे **platform privilege** दे सकता है। इसका अर्थ यह भी है कि Apple platform binaries को किसी specific OS version से lock कर सकता है और पुराने Apple-signed binaries को नए systems पर replay होने से रोक सकता है।<sup>[[6]](#references)</sup>

Recent macOS releases में, trust-cache metadata को **launch constraints** से भी जोड़ा गया है, इसलिए गलत parent/location से शुरू किए गए copied system apps और binaries को AMFI reject कर सकता है, भले ही वे अभी भी Apple-signed हों। Detailed extraction और reversing workflow यहां covered है:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS और jailbreak research में आपको traditional model of **loadable trust caches** अभी भी ad-hoc signed binaries को whitelist करने के लिए उपयोग होता हुआ मिलेगा।

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
