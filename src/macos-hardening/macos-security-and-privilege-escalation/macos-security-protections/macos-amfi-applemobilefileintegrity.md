# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

यह system पर चल रहे code की integrity लागू करने पर केंद्रित है और XNU के code signature verification के पीछे की logic प्रदान करता है। यह entitlements की जांच करने और debugging की अनुमति देने या task ports प्राप्त करने जैसे अन्य संवेदनशील कार्यों को संभालने में भी सक्षम है।

इसके अलावा, कुछ operations के लिए, kext user space में चल रहे daemon `/usr/libexec/amfid` से संपर्क करना पसंद करता है। इस trust relationship का कई jailbreaks में दुरुपयोग किया गया है।

हाल के macOS versions में, AMFI अब standalone on-disk kext के रूप में सुविधाजनक रूप से exposed नहीं है, इसलिए reversing का अर्थ आमतौर पर `/System/Library/Extensions` को browse करने के बजाय **kernelcache** या **KDK** से काम करना होता है।

AMFI **MACF** policies का उपयोग करता है और start होते ही अपने hooks register करता है। साथ ही, इसके loading को रोकना या इसे unload करना kernel panic को trigger कर सकता है। हालांकि, कुछ boot arguments हैं जो AMFI को disable करने की अनुमति देते हैं:

- `amfi_unrestricted_task_for_pid`: आवश्यक entitlements के बिना task_for_pid की अनुमति देता है
- `amfi_allow_any_signature`: किसी भी code signature की अनुमति देता है
- `cs_enforcement_disable`: code signing enforcement को disable करने के लिए system-wide argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements वाले platform binaries को void करता है
- `amfi_get_out_of_my_way`: amfi को पूरी तरह disable करता है

ये कुछ MACF policies हैं जिन्हें यह register करता है:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Label update किया जाएगा और 1 return किया जाएगा
- **`cred_label_associate`**: AMFI के mac label slot को label के साथ update करता है
- **`cred_label_destroy`**: AMFI का mac label slot remove करता है
- **`cred_label_init`**: AMFI के mac label slot में 0 move करता है
- **`cred_label_update_execve`:** यह process के entitlements की जांच करता है ताकि पता चले कि उसे labels modify करने की अनुमति होनी चाहिए या नहीं।
- **`file_check_mmap`:** यह जांच करता है कि mmap memory acquire करके उसे executable के रूप में set कर रहा है या नहीं। यदि ऐसा है, तो यह जांच करता है कि library validation आवश्यक है या नहीं और यदि आवश्यक हो, तो library validation function को call करता है।
- **`file_check_library_validation`**: यह library validation function को call करता है, जो अन्य बातों के साथ यह जांचता है कि कोई platform binary दूसरी platform binary load कर रही है या नहीं, अथवा process और नई loaded file का TeamID समान है या नहीं। कुछ entitlements किसी भी library को load करने की अनुमति भी देंगे।
- **`policy_initbsd`**: Trusted NVRAM Keys set करता है
- **`policy_syscall`**: यह DYLD policies की जांच करता है, जैसे कि binary में unrestricted segments हैं या नहीं, env vars की अनुमति होनी चाहिए या नहीं... इसे तब भी call किया जाता है जब कोई process `amfi_check_dyld_policy_self()` के माध्यम से start किया जाता है।
- **`proc_check_inherit_ipc_ports`**: यह जांच करता है कि जब कोई process नई binary execute करता है, तो process के task port पर SEND rights रखने वाले अन्य processes को वे rights रखने चाहिए या नहीं। Platform binaries को अनुमति है, `get-task-allow` entitled processes को अनुमति है, `task_for_pid-allow` entitlements को अनुमति है और समान TeamID वाली binaries को भी अनुमति है।
- **`proc_check_expose_task`**: entitlements लागू करता है
- **`amfi_exc_action_check_exception_send`**: Debugger को exception message भेजा जाता है
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Exception handling (debugging) के दौरान label lifecycle
- **`proc_check_get_task`**: `get-task-allow` जैसे entitlements की जांच करता है, जो अन्य processes को process का task port प्राप्त करने की अनुमति देता है, और `task_for_pid-allow`, जो process को अन्य processes के task ports प्राप्त करने की अनुमति देता है। यदि इनमें से कोई भी मौजूद नहीं है, तो यह `amfid permitunrestricteddebugging` को call करके जांच करता है कि इसकी अनुमति है या नहीं।
- **`proc_check_mprotect`**: यदि `mprotect` को `VM_PROT_TRUSTED` flag के साथ call किया जाता है, तो deny करता है। यह flag दर्शाता है कि region को ऐसे treat किया जाना चाहिए जैसे उसके पास valid code signature हो।
- **`vnode_check_exec`**: जब executable files memory में load की जाती हैं, तब call किया जाता है और `cs_hard | cs_kill` set करता है, जो किसी page के invalid होने पर process को kill कर देगा<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` और `isVnodeQuarantined()` की जांच करता है
- **`vnode_check_setextattr`**: `get` के समान + `com.apple.private.allow-bless` और internal-installer-equivalent entitlement
- **`vnode_check_signature`**: वह code जो entitlements, trust cache और `amfid` का उपयोग करके code signature check करने के लिए XNU को call करता है<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: यह `ptrace()` calls (`PT_ATTACH` और `PT_TRACE_ME`) को intercept करता है। यह `get-task-allow`, `run-invalid-allow` और `run-unsigned-code` में से किसी entitlement की जांच करता है और यदि कोई भी मौजूद नहीं है, तो जांच करता है कि debugging की अनुमति है या नहीं।
- **`proc_check_map_anon`**: यदि mmap को **`MAP_JIT`** flag के साथ call किया जाता है, तो AMFI `dynamic-codesigning` entitlement की जांच करेगा।

`AMFI.kext` अन्य kernel extensions के लिए एक API भी expose करता है, और इसकी dependencies इस command से find की जा सकती हैं:
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

यह user mode में चलने वाला daemon है, जिसका उपयोग `AMFI.kext` user mode में code signatures की जांच करने के लिए करता है।\
`AMFI.kext` के daemon के साथ communication करने के लिए `HOST_AMFID_PORT` port पर mach messages का उपयोग करता है, जो special port `18` है।

ध्यान दें कि macOS में अब root processes के लिए special ports को hijack करना संभव नहीं है, क्योंकि वे `SIP` द्वारा protected होते हैं और केवल launchd ही उन्हें प्राप्त कर सकता है। iOS में यह जांचा जाता है कि response वापस भेजने वाले process के पास `amfid` का hardcoded CDHash है।

`amfid` से किसी binary की जांच करने का अनुरोध कब किया जाता है और उसका response क्या होता है, यह debugging करके और `mach_msg` में breakpoint set करके देखा जा सकता है।

जब special port के माध्यम से कोई message प्राप्त होता है, तो प्रत्येक function को उस function तक भेजने के लिए जिसे वह call कर रहा है, **MIG** का उपयोग किया जाता है। मुख्य functions को reverse किया गया और book में समझाया गया है।

### DYLD policy और library validation

Recent `dyld` versions `configureProcessRestrictions()` से बहुत पहले `amfi_check_dyld_policy_self()` call करते हैं, ताकि AMFI से पूछा जा सके कि process `DYLD_*` path variables, interposing, fallback paths और embedded variables का उपयोग कर सकता है या नहीं, अथवा failed library insertion को tolerate कर सकता है या नहीं। इसलिए, injection surface का triage करते समय केवल Mach-O load commands की जांच करना पर्याप्त नहीं है: आपको उन entitlements और runtime flags की भी जांच करनी होगी, जिन्हें AMFI `dyld` policy में translate करेगा।

एक practical triage loop इस प्रकार है:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
आधुनिक macOS पर कई Apple binaries अब सीधे `com.apple.security.cs.disable-library-validation` नहीं रखतीं और इसके बजाय `com.apple.private.security.clear-library-validation` के साथ ship होती हैं। इस स्थिति में library validation `execve` के समय disabled नहीं होती: process को स्वयं पर `csops(..., CS_OPS_CLEAR_LV, ...)` call करना पड़ता है, और XNU calling process पर इस operation की अनुमति केवल तभी देता है जब entitlement मौजूद हो। Offensive perspective से यह महत्वपूर्ण है क्योंकि target केवल **तभी injectable बन सकता है** जब वह उस code path तक पहुंच जाए जो स्पष्ट रूप से LV को clear करता है (उदाहरण के लिए, optional plugins load करने से कुछ समय पहले)।<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profile का उपयोग code sign करने के लिए किया जा सकता है। **Developer** profiles का उपयोग code sign करके उसे test करने के लिए किया जा सकता है, जबकि **Enterprise** profiles का उपयोग सभी devices में किया जा सकता है।

Apple Store पर App submit किए जाने के बाद, यदि वह approve हो जाता है, तो Apple उसे sign करता है और provisioning profile की आवश्यकता नहीं रहती।

Profile में आमतौर पर `.mobileprovision` या `.provisionprofile` extension होती है और इसे इस command से dump किया जा सकता है:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
हालांकि इन्हें कभी-कभी certificated कहा जाता है, इन provisioning profiles में certificate से अधिक जानकारी होती है:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: इसे Apple Internal profile के रूप में निर्दिष्ट करता है
- **ApplicationIdentifierPrefix**: AppIDName के आगे जोड़ा जाता है (TeamIdentifier के समान)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` format में date
- **DeveloperCertificates**: Base64 data के रूप में encoded certificate(s) का एक array (आमतौर पर एक)
- **Entitlements**: इस profile के साथ allowed entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` format में expiration date
- **Name**: Application Name, जो AppIDName के समान है
- **ProvisionedDevices**: UDIDs का एक array (developer certificates के लिए), जिनके लिए यह profile valid है
- **ProvisionsAllDevices**: एक boolean (enterprise certificates के लिए true)
- **TeamIdentifier**: inter-app interaction purposes के लिए developer की पहचान करने वाली alphanumeric string(s) का एक array (आमतौर पर एक)
- **TeamName**: developer की पहचान करने के लिए उपयोग किया जाने वाला human-readable name
- **TimeToLive**: certificate की validity (days में)
- **UUID**: इस profile के लिए एक Universally Unique Identifier
- **Version**: वर्तमान में 1 पर set है

ध्यान दें कि entitlements entry में entitlements का एक restricted set होगा और provisioning profile केवल उन्हीं specific entitlements को प्रदान कर सकेगा, ताकि Apple private entitlements प्रदान करने से रोका जा सके।

ध्यान दें कि profiles आमतौर पर `/var/MobileDeviceProvisioningProfiles` में स्थित होती हैं और इन्हें **`security cms -D -i /path/to/profile`** से check करना संभव है।

## **libmis.dylib**

यह external library है जिसे `amfid` यह पूछने के लिए call करता है कि उसे किसी चीज़ को allow करना चाहिए या नहीं। इसका ऐतिहासिक रूप से jailbreaking में backdoored version चलाकर दुरुपयोग किया गया है, जो हर चीज़ को allow करता था।

macOS में यह `MobileDevice.framework` के अंदर होती है।

## AMFI Trust Caches

Trust caches केवल iOS की concept नहीं हैं। Modern macOS में, विशेष रूप से **Apple silicon** पर, static trust cache और loadable trust caches Secure Boot chain का हिस्सा हैं। जब किसी Mach-O का **CodeDirectory hash** वहां मौजूद होता है, तो AMFI launch के समय आगे authenticity checks किए बिना उसे **platform privilege** प्रदान कर सकता है। इसका अर्थ यह भी है कि Apple platform binaries को किसी specific OS version से lock कर सकता है और पुराने Apple-signed binaries को newer systems पर replay होने से रोक सकता है।<sup>[[6]](#references)</sup>

Recent macOS releases में trust-cache metadata को **launch constraints** से भी जोड़ा गया है। इसलिए गलत parent/location से शुरू किए गए copied system apps और binaries को AMFI reject कर सकता है, भले ही वे अभी भी Apple-signed हों। Detailed extraction और reversing workflow यहां covered है:

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
