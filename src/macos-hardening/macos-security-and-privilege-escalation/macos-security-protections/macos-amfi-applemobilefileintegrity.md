# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext और amfid

यह सिस्टम पर चल रहे कोड की अखंडता को लागू करने पर केंद्रित है, जो XNU के कोड सिग्नेचर सत्यापन के पीछे की तर्क प्रदान करता है। यह अधिकारों की जांच करने और अन्य संवेदनशील कार्यों को संभालने में भी सक्षम है, जैसे कि डिबगिंग की अनुमति देना या कार्य पोर्ट प्राप्त करना।

इसके अलावा, कुछ संचालन के लिए, kext उपयोगकर्ता स्थान पर चल रहे डेमन `/usr/libexec/amfid` से संपर्क करना पसंद करता है। इस विश्वास संबंध का कई जेलब्रेक में दुरुपयोग किया गया है।

AMFI **MACF** नीतियों का उपयोग करता है और यह शुरू होते ही अपने हुक पंजीकृत करता है। इसके लोडिंग या अनलोडिंग को रोकने से कर्नेल पैनिक हो सकता है। हालाँकि, कुछ बूट तर्क हैं जो AMFI को कमजोर करने की अनुमति देते हैं:

- `amfi_unrestricted_task_for_pid`: आवश्यक अधिकारों के बिना task_for_pid की अनुमति दें
- `amfi_allow_any_signature`: किसी भी कोड सिग्नेचर की अनुमति दें
- `cs_enforcement_disable`: कोड साइनिंग प्रवर्तन को निष्क्रिय करने के लिए सिस्टम-व्यापी तर्क
- `amfi_prevent_old_entitled_platform_binaries`: अधिकारों के साथ प्लेटफ़ॉर्म बाइनरी को अमान्य करें
- `amfi_get_out_of_my_way`: amfi को पूरी तरह से निष्क्रिय करता है

यहाँ कुछ MACF नीतियाँ हैं जो यह पंजीकृत करता है:

- **`cred_check_label_update_execve:`** लेबल अपडेट किया जाएगा और 1 लौटाएगा
- **`cred_label_associate`**: AMFI के मैक लेबल स्लॉट को लेबल के साथ अपडेट करें
- **`cred_label_destroy`**: AMFI का मैक लेबल स्लॉट हटा दें
- **`cred_label_init`**: AMFI के मैक लेबल स्लॉट में 0 डालें
- **`cred_label_update_execve`:** यह प्रक्रिया के अधिकारों की जांच करता है कि क्या इसे लेबल को संशोधित करने की अनुमति दी जानी चाहिए।
- **`file_check_mmap`:** यह जांचता है कि क्या mmap मेमोरी प्राप्त कर रहा है और इसे निष्पादन योग्य के रूप में सेट कर रहा है। इस मामले में यह जांचता है कि क्या पुस्तकालय सत्यापन की आवश्यकता है और यदि हाँ, तो यह पुस्तकालय सत्यापन फ़ंक्शन को कॉल करता है।
- **`file_check_library_validation`**: पुस्तकालय सत्यापन फ़ंक्शन को कॉल करता है जो अन्य चीजों के बीच यह जांचता है कि क्या एक प्लेटफ़ॉर्म बाइनरी दूसरी प्लेटफ़ॉर्म बाइनरी को लोड कर रही है या यदि प्रक्रिया और नया लोड किया गया फ़ाइल का एक ही TeamID है। कुछ अधिकार किसी भी पुस्तकालय को लोड करने की अनुमति भी देंगे।
- **`policy_initbsd`**: विश्वसनीय NVRAM कुंजी सेट करता है
- **`policy_syscall`**: यह DYLD नीतियों की जांच करता है जैसे कि क्या बाइनरी के पास अनियंत्रित खंड हैं, क्या इसे env vars की अनुमति देनी चाहिए... यह तब भी कॉल किया जाता है जब एक प्रक्रिया `amfi_check_dyld_policy_self()` के माध्यम से शुरू होती है।
- **`proc_check_inherit_ipc_ports`**: यह जांचता है कि जब एक प्रक्रिया एक नया बाइनरी निष्पादित करती है तो क्या अन्य प्रक्रियाएँ प्रक्रिया के कार्य पोर्ट पर SEND अधिकारों के साथ उन्हें बनाए रखनी चाहिए या नहीं। प्लेटफ़ॉर्म बाइनरी की अनुमति है, `get-task-allow` अधिकार इसे अनुमति देता है, `task_for_pid-allow` अधिकार की अनुमति है और एक ही TeamID के साथ बाइनरी।
- **`proc_check_expose_task`**: अधिकारों को लागू करें
- **`amfi_exc_action_check_exception_send`**: डिबगर को एक अपवाद संदेश भेजा जाता है
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: अपवाद हैंडलिंग (डिबगिंग) के दौरान लेबल जीवनचक्र
- **`proc_check_get_task`**: अधिकारों की जांच करता है जैसे `get-task-allow` जो अन्य प्रक्रियाओं को कार्य पोर्ट प्राप्त करने की अनुमति देता है और `task_for_pid-allow`, जो प्रक्रिया को अन्य प्रक्रियाओं के कार्य पोर्ट प्राप्त करने की अनुमति देता है। यदि इनमें से कोई भी नहीं है, तो यह `amfid permitunrestricteddebugging` को कॉल करता है यह जांचने के लिए कि क्या इसकी अनुमति है।
- **`proc_check_mprotect`**: यदि `mprotect` को `VM_PROT_TRUSTED` ध्वज के साथ कॉल किया जाता है तो अस्वीकार करें, जो इंगित करता है कि क्षेत्र को इस तरह से माना जाना चाहिए जैसे कि इसका एक मान्य कोड सिग्नेचर है।
- **`vnode_check_exec`**: जब निष्पादन योग्य फ़ाइलें मेमोरी में लोड होती हैं तो इसे कॉल किया जाता है और `cs_hard | cs_kill` सेट करता है जो प्रक्रिया को मार देगा यदि कोई भी पृष्ठ अमान्य हो जाता है
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` और `isVnodeQuarantined()` की जांच करें
- **`vnode_check_setextattr`**: जैसे प्राप्त + com.apple.private.allow-bless और आंतरिक-इंस्टॉलर-समान अधिकार
- **`vnode_check_signature`**: कोड जो XNU को अधिकारों, ट्रस्ट कैश और `amfid` का उपयोग करके कोड सिग्नेचर की जांच करने के लिए कॉल करता है
- **`proc_check_run_cs_invalid`**: यह `ptrace()` कॉल्स (`PT_ATTACH` और `PT_TRACE_ME`) को इंटरसेप्ट करता है। यह किसी भी अधिकारों की जांच करता है `get-task-allow`, `run-invalid-allow` और `run-unsigned-code` और यदि कोई नहीं है, तो यह जांचता है कि क्या डिबगिंग की अनुमति है।
- **`proc_check_map_anon`**: यदि mmap को **`MAP_JIT`** ध्वज के साथ कॉल किया जाता है, तो AMFI `dynamic-codesigning` अधिकार की जांच करेगा।

`AMFI.kext` अन्य कर्नेल एक्सटेंशन के लिए एक API भी उजागर करता है, और इसके निर्भरताओं को खोजने के लिए यह संभव है:
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

यह उपयोगकर्ता मोड चलाने वाला डेमन है जो `AMFI.kext` को उपयोगकर्ता मोड में कोड हस्ताक्षरों की जांच करने के लिए उपयोग करेगा।\
`AMFI.kext` डेमन के साथ संवाद करने के लिए `HOST_AMFID_PORT` पोर्ट पर मच संदेशों का उपयोग करता है, जो विशेष पोर्ट `18` है।

ध्यान दें कि macOS में अब रूट प्रक्रियाओं के लिए विशेष पोर्ट को हाईजैक करना संभव नहीं है क्योंकि उन्हें `SIP` द्वारा सुरक्षित किया गया है और केवल launchd उन्हें प्राप्त कर सकता है। iOS में यह जांचा जाता है कि प्रतिक्रिया वापस भेजने वाली प्रक्रिया में `amfid` का CDHash हार्डकोडेड है।

जब `amfid` को एक बाइनरी की जांच करने के लिए अनुरोध किया जाता है और इसका उत्तर प्राप्त होता है, तो इसे डिबग करके और `mach_msg` में एक ब्रेकपॉइंट सेट करके देखा जा सकता है।

एक बार जब विशेष पोर्ट के माध्यम से एक संदेश प्राप्त होता है, तो **MIG** का उपयोग प्रत्येक फ़ंक्शन को उस फ़ंक्शन को भेजने के लिए किया जाता है जिसे यह कॉल कर रहा है। मुख्य फ़ंक्शंस को उलटकर और पुस्तक के अंदर समझाया गया है।

## Provisioning Profiles

एक प्रोविजनिंग प्रोफ़ाइल कोड पर हस्ताक्षर करने के लिए उपयोग की जा सकती है। **Developer** प्रोफाइल हैं जो कोड पर हस्ताक्षर करने और इसे परीक्षण करने के लिए उपयोग की जा सकती हैं, और **Enterprise** प्रोफाइल हैं जो सभी उपकरणों में उपयोग की जा सकती हैं।

एक ऐप को Apple Store में सबमिट करने के बाद, यदि स्वीकृत हो जाता है, तो इसे Apple द्वारा हस्ताक्षरित किया जाता है और प्रोविजनिंग प्रोफ़ाइल की अब आवश्यकता नहीं होती है।

एक प्रोफ़ाइल आमतौर पर `.mobileprovision` या `.provisionprofile` एक्सटेंशन का उपयोग करती है और इसे डंप किया जा सकता है:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
हालाँकि कभी-कभी इन्हें प्रमाणित कहा जाता है, ये प्रोविजनिंग प्रोफाइल एक प्रमाणपत्र से अधिक होते हैं:

- **AppIDName:** एप्लिकेशन पहचानकर्ता
- **AppleInternalProfile**: इसे एक Apple आंतरिक प्रोफाइल के रूप में निर्दिष्ट करता है
- **ApplicationIdentifierPrefix**: AppIDName के आगे जोड़ा गया (TeamIdentifier के समान)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` प्रारूप में तिथि
- **DeveloperCertificates**: (आमतौर पर एक) प्रमाणपत्रों का एक ऐरे, जो Base64 डेटा के रूप में एन्कोडेड होता है
- **Entitlements**: इस प्रोफाइल के लिए अनुमत अधिकार
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` प्रारूप में समाप्ति तिथि
- **Name**: एप्लिकेशन का नाम, जो AppIDName के समान है
- **ProvisionedDevices**: UDIDs का एक ऐरे (डेवलपर प्रमाणपत्रों के लिए) जिसके लिए यह प्रोफाइल मान्य है
- **ProvisionsAllDevices**: एक बूलियन (एंटरप्राइज प्रमाणपत्रों के लिए सत्य)
- **TeamIdentifier**: (आमतौर पर एक) अल्फ़ान्यूमेरिक स्ट्रिंग(s) का एक ऐरे जिसका उपयोग डेवलपर की पहचान के लिए किया जाता है
- **TeamName**: डेवलपर की पहचान के लिए उपयोग किया जाने वाला मानव-पठनीय नाम
- **TimeToLive**: प्रमाणपत्र की वैधता (दिनों में)
- **UUID**: इस प्रोफाइल के लिए एक यूनिवर्सली यूनिक आइडेंटिफायर
- **Version**: वर्तमान में 1 पर सेट

ध्यान दें कि अधिकार प्रविष्टि में अधिकारों का एक सीमित सेट होगा और प्रोविजनिंग प्रोफाइल केवल उन विशिष्ट अधिकारों को देने में सक्षम होगा ताकि Apple के निजी अधिकार न दिए जा सकें।

ध्यान दें कि प्रोफाइल आमतौर पर `/var/MobileDeviceProvisioningProfiles` में स्थित होते हैं और इन्हें **`security cms -D -i /path/to/profile`** के साथ चेक करना संभव है।

## **libmis.dyld**

यह बाहरी पुस्तकालय है जिसे `amfid` यह पूछने के लिए कॉल करता है कि क्या इसे कुछ अनुमति देनी चाहिए या नहीं। इसका ऐतिहासिक रूप से जेलब्रेकिंग में दुरुपयोग किया गया है, जिसमें इसका एक बैकडोर संस्करण चलाया गया था जो सब कुछ अनुमति देता था।

macOS में यह `MobileDevice.framework` के अंदर है।

## AMFI Trust Caches

iOS AMFI ज्ञात हैश का एक सूची बनाए रखता है जो कि ऐड-हॉक पर हस्ताक्षरित होते हैं, जिसे **Trust Cache** कहा जाता है और kext के `__TEXT.__const` अनुभाग में पाया जाता है। ध्यान दें कि बहुत विशिष्ट और संवेदनशील संचालन में, इस Trust Cache को एक बाहरी फ़ाइल के साथ बढ़ाना संभव है।

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
