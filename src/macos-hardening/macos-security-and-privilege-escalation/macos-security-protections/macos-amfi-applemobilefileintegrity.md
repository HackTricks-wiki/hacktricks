# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

यह सिस्टम पर चल रहे code की integrity enforce करने पर केंद्रित है, और XNU के code signature verification के पीछे की logic प्रदान करता है। यह entitlements को भी check कर सकता है और debugging allow करना या task ports obtain करना जैसी अन्य sensitive tasks handle कर सकता है।

इसके अलावा, कुछ operations के लिए, kext user space में चल रहे daemon `/usr/libexec/amfid` से contact करना prefer करता है। इस trust relationship का कई jailbreaks में abuse किया गया है।

Recent macOS versions में, AMFI अब standalone on-disk kext के रूप में conveniently exposed नहीं है, इसलिए reversing आमतौर पर `/System/Library/Extensions` browse करने के बजाय **kernelcache** या **KDK** के साथ काम करने का मतलब होता है।

AMFI **MACF** policies use करता है और start होते ही अपने hooks register कर देता है। साथ ही, इसे load होने से रोकना या unload करना kernel panic trigger कर सकता है। हालांकि, कुछ boot arguments हैं जो AMFI को कमजोर करने की allow करते हैं:

- `amfi_unrestricted_task_for_pid`: task_for_pid को required entitlements के बिना allow होने देता है
- `amfi_allow_any_signature`: कोई भी code signature allow करता है
- `cs_enforcement_disable`: code signing enforcement disable करने के लिए system-wide argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements वाले platform binaries को void करता है
- `amfi_get_out_of_my_way`: amfi को पूरी तरह disable करता है

ये कुछ MACF policies हैं जिन्हें यह register करता है:

- **`cred_check_label_update_execve:`** Label update perform किया जाएगा और 1 return करेगा
- **`cred_label_associate`**: AMFI के mac label slot को label के साथ update करता है
- **`cred_label_destroy`**: AMFI के mac label slot को remove करता है
- **`cred_label_init`**: AMFI के mac label slot में 0 move करता है
- **`cred_label_update_execve`:** यह process के entitlements check करता है ताकि देख सके कि labels modify करने की अनुमति होनी चाहिए या नहीं।
- **`file_check_mmap`:** यह check करता है कि mmap memory acquire कर रहा है और उसे executable set कर रहा है या नहीं। उस स्थिति में यह check करता है कि library validation की जरूरत है या नहीं, और अगर हो, तो library validation function call करता है।
- **`file_check_library_validation`**: library validation function call करता है, जो अन्य चीज़ों के साथ check करता है कि क्या एक platform binary दूसरा platform binary load कर रहा है या process और नया loaded file same TeamID रखते हैं। कुछ entitlements किसी भी library को load करने की अनुमति भी देंगे।
- **`policy_initbsd`**: trusted NVRAM Keys set up करता है
- **`policy_syscall`**: यह DYLD policies check करता है, जैसे binary के पास unrestricted segments हैं या नहीं, क्या इसे env vars allow करने चाहिए... यह तब भी call होता है जब कोई process `amfi_check_dyld_policy_self()` के जरिए शुरू होता है।
- **`proc_check_inherit_ipc_ports`**: यह check करता है कि जब कोई process नया binary execute करता है, तो process के task port पर SEND rights वाले दूसरे processes उन्हें keep करें या नहीं। Platform binaries allowed हैं, `get-task-allow` entitlement इसे allow करता है, `task_for_pid-allow` entitles allowed हैं, और same TeamID वाले binaries भी।
- **`proc_check_expose_task`**: entitlements enforce करता है
- **`amfi_exc_action_check_exception_send`**: debugger को exception message send की जाती है
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: exception handling के दौरान label lifecycle (debugging)
- **`proc_check_get_task`**: `get-task-allow` जैसे entitlements check करता है, जो दूसरे processes को task port प्राप्त करने की अनुमति देता है, और `task_for_pid-allow`, जो process को दूसरे processes के task ports प्राप्त करने की अनुमति देता है। अगर इनमें से कोई भी नहीं है, तो यह अनुमति है या नहीं check करने के लिए `amfid permitunrestricteddebugging` तक जाता है।
- **`proc_check_mprotect`**: अगर `mprotect` को `VM_PROT_TRUSTED` flag के साथ call किया जाता है, तो deny करता है, जो indicate करता है कि region को valid code signature की तरह treat किया जाना चाहिए।
- **`vnode_check_exec`**: executable files memory में load होने पर call होता है और `cs_hard | cs_kill` set करता है, जो process को kill कर देगा अगर pages में से कोई भी invalid हो जाए
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` और `isVnodeQuarantined()` check करता है
- **`vnode_check_setextattr`**: get + `com.apple.private.allow-bless` और internal-installer-equivalent entitlement
- **`vnode_check_signature`**: ऐसा code जो entitlements, trust cache और `amfid` का उपयोग करके code signature check करने के लिए XNU को call करता है
- **`proc_check_run_cs_invalid`**: यह `ptrace()` calls (`PT_ATTACH` और `PT_TRACE_ME`) intercept करता है। यह `get-task-allow`, `run-invalid-allow` और `run-unsigned-code` entitlements में से किसी के लिए check करता है, और अगर कोई नहीं है, तो यह check करता है कि debugging permitted है या नहीं।
- **`proc_check_map_anon`**: अगर `mmap` को **`MAP_JIT`** flag के साथ call किया जाता है, तो AMFI `dynamic-codesigning` entitlement check करेगा।

`AMFI.kext` अन्य kernel extensions के लिए भी एक API expose करता है, और इसकी dependencies यहाँ से find की जा सकती हैं:
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

यह user mode running daemon है जिसका उपयोग `AMFI.kext` user mode में code signatures check करने के लिए करता है।\
`AMFI.kext` के daemon से communicate करने के लिए यह `HOST_AMFID_PORT` special port पर mach messages का उपयोग करता है, जो special port `18` है।

ध्यान दें कि macOS में अब root processes के लिए special ports को hijack करना संभव नहीं है क्योंकि वे `SIP` द्वारा protected हैं और केवल `launchd` ही उन्हें प्राप्त कर सकता है। iOS में यह check किया जाता है कि response वापस भेजने वाला process का CDHash hardcoded `amfid` का है।

यह देखना संभव है कि कब `amfid` से किसी binary को check करने के लिए request की गई है और उसका response क्या है, इसे debug करके और `mach_msg` में breakpoint सेट करके।

जब special port के माध्यम से एक message receive हो जाता है, तो **MIG** का उपयोग प्रत्येक function को उस function तक भेजने के लिए किया जाता है जिसे वह call कर रहा है। मुख्य functions को reverse किया गया था और book के अंदर explained किया गया था।

### DYLD policy and library validation

Recent `dyld` versions `configureProcessRestrictions()` से बहुत early `amfi_check_dyld_policy_self()` call करती हैं ताकि AMFI से पूछा जा सके कि process `DYLD_*` path variables, interposing, fallback paths, embedded variables, या failed library insertion को tolerate कर सकता है या नहीं। इसलिए, जब किसी injection surface की triage की जा रही हो, तो केवल Mach-O load commands inspect करना पर्याप्त नहीं है: आपको entitlements और runtime flags भी inspect करने होंगे जिन्हें AMFI `dyld` policy में translate करेगा।

एक practical triage loop है:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
आधुनिक macOS पर कई Apple binaries अब सीधे `com.apple.security.cs.disable-library-validation` नहीं रखते और इसके बजाय `com.apple.private.security.clear-library-validation` के साथ ship करते हैं। उस स्थिति में library validation `execve` समय पर disabled नहीं होती: process को खुद पर `csops(..., CS_OPS_CLEAR_LV, ...)` call करना पड़ता है, और XNU केवल calling process पर यह operation तब allow करता है जब entitlement present हो। offensive perspective से यह इसलिए important है क्योंकि target केवल तब injectable हो सकता है जब वह उस code path तक पहुंचे जो explicitly LV clear करता है (उदाहरण के लिए, optional plugins load करने से ठीक पहले)।

## Provisioning Profiles

एक provisioning profile को code sign करने के लिए use किया जा सकता है। **Developer** profiles होते हैं जिनका use code sign करने और test करने के लिए किया जा सकता है, और **Enterprise** profiles होते हैं जिनका use सभी devices में किया जा सकता है।

जब एक App Apple Store में submit की जाती है, अगर वह approved हो जाए, तो उसे Apple sign करता है और provisioning profile की फिर जरूरत नहीं रहती।

एक profile आमतौर पर `.mobileprovision` या `.provisionprofile` extension use करती है और इसे इससे dump किया जा सकता है:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
हालाँकि कभी-कभी certificated कहा जाता है, इन provisioning profiles में certificate से अधिक चीज़ें होती हैं:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: इसे Apple Internal profile के रूप में दर्शाता है
- **ApplicationIdentifierPrefix**: AppIDName के आगे जोड़ा जाता है (TeamIdentifier के समान)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` format में तारीख
- **DeveloperCertificates**: (आमतौर पर एक) certificate(s) का array, Base64 data के रूप में encoded
- **Entitlements**: इस profile के लिए अनुमति प्राप्त entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` format में expiration date
- **Name**: Application Name, वही जो AppIDName है
- **ProvisionedDevices**: (developer certificates के लिए) UDIDs का array, जिनके लिए यह profile valid है
- **ProvisionsAllDevices**: एक boolean (enterprise certificates के लिए true)
- **TeamIdentifier**: (आमतौर पर एक) alphanumeric string(s) का array, जो inter-app interaction purposes के लिए developer की पहचान करने में इस्तेमाल होता है
- **TeamName**: developer की पहचान के लिए इस्तेमाल होने वाला human-readable name
- **TimeToLive**: certificate की validity (दिनों में)
- **UUID**: इस profile के लिए Universally Unique Identifier
- **Version**: वर्तमान में 1 पर set

ध्यान दें कि entitlements entry में entitlements का एक restricted set होगा और provisioning profile केवल उन specific entitlements को ही दे पाएगा, ताकि Apple private entitlements देने से रोका जा सके।

ध्यान दें कि profiles आमतौर पर `/var/MobileDeviceProvisioningProfiles` में located होते हैं और उन्हें **`security cms -D -i /path/to/profile`** से check करना संभव है

## **libmis.dylib**

यह external library है जिसे `amfid` call करता है यह पूछने के लिए कि उसे किसी चीज़ को allow करना चाहिए या नहीं। इसे historically jailbreaking में एक backdoored version चलाकर abuse किया गया है, जो सब कुछ allow कर देता था।

macOS में यह `MobileDevice.framework` के अंदर होता है।

## AMFI Trust Caches

Trust caches सिर्फ iOS का concept नहीं हैं। modern macOS पर, खासकर **Apple silicon** पर, static trust cache और loadable trust caches Secure Boot chain का हिस्सा हैं। जब किसी Mach-O का **CodeDirectory hash** वहाँ present होता है, तो AMFI launch time पर आगे की authenticity checks किए बिना उसे **platform privilege** दे सकता है। इसका मतलब यह भी है कि Apple platform binaries को एक specific OS version से lock कर सकता है और पुराने Apple-signed binaries को नए systems पर replay होने से रोक सकता है।

recent macOS releases पर, trust-cache metadata को **launch constraints** से भी जोड़ा जाता है, इसलिए copied system apps और binaries जो गलत parent/location से start होते हैं, AMFI द्वारा reject किए जा सकते हैं, भले ही वे अभी भी Apple-signed हों। detailed extraction और reversing workflow यहाँ covered है:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS और jailbreak research में आपको अभी भी **loadable trust caches** का traditional model मिलेगा, जिसका इस्तेमाल ad-hoc signed binaries को whitelist करने के लिए किया जाता है।

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
