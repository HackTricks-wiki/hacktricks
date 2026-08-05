# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Kernel Extensions के विपरीत, **System Extensions kernel space के बजाय user space में run होते हैं**, जिससे extension में खराबी के कारण system crash होने का risk कम हो जाता है।

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

System extensions तीन प्रकार के होते हैं: **DriverKit** Extensions, **Network** Extensions, और **Endpoint Security** Extensions।

### **DriverKit Extensions**

DriverKit, kernel extensions का replacement है जो **hardware support प्रदान करते हैं**। यह device drivers (जैसे USB, Serial, NIC, और HID drivers) को kernel space के बजाय user space में run करने की अनुमति देता है। DriverKit framework में **कुछ I/O Kit classes के user space versions** शामिल होते हैं, और kernel सामान्य I/O Kit events को user space में forward करता है, जिससे इन drivers के run करने के लिए अधिक सुरक्षित environment मिलता है।<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions network behaviors को customize करने की क्षमता प्रदान करते हैं। Network Extensions के कई प्रकार हैं:

- **App Proxy**: इसका उपयोग ऐसा VPN client बनाने के लिए किया जाता है जो flow-oriented, custom VPN protocol implement करता है। इसका अर्थ है कि यह individual packets के बजाय connections (या flows) के आधार पर network traffic को handle करता है।
- **Packet Tunnel**: इसका उपयोग ऐसा VPN client बनाने के लिए किया जाता है जो packet-oriented, custom VPN protocol implement करता है। इसका अर्थ है कि यह individual packets के आधार पर network traffic को handle करता है।
- **Filter Data**: इसका उपयोग network "flows" को filter करने के लिए किया जाता है। यह flow level पर network data को monitor या modify कर सकता है।
- **Filter Packet**: इसका उपयोग individual network packets को filter करने के लिए किया जाता है। यह packet level पर network data को monitor या modify कर सकता है।
- **DNS Proxy**: इसका उपयोग custom DNS provider बनाने के लिए किया जाता है। इसका उपयोग DNS requests और responses को monitor या modify करने के लिए किया जा सकता है।<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security, Apple द्वारा macOS में प्रदान किया गया एक framework है, जो system security के लिए APIs का एक set प्रदान करता है। इसका उद्देश्य **security vendors और developers द्वारा ऐसे products बनाने के लिए किया जाना है जो system activity को monitor और control कर सकें**, ताकि malicious activity की पहचान की जा सके और उससे सुरक्षा की जा सके।

यह framework **system activity को monitor और control करने के लिए APIs का collection** प्रदान करता है, जैसे process executions, file system events, network और kernel events।

इस framework का core kernel में Kernel Extension (KEXT) के रूप में implement किया गया है, जो **`/System/Library/Extensions/EndpointSecurity.kext`** पर स्थित है।<sup>[[2]](#references)</sup> यह KEXT कई प्रमुख components से बना है:

- **EndpointSecurityDriver**: यह kernel extension के "entry point" के रूप में कार्य करता है। यह OS और Endpoint Security framework के बीच interaction का मुख्य point है।
- **EndpointSecurityEventManager**: यह component kernel hooks implement करने के लिए responsible है। Kernel hooks system calls को intercept करके framework को system events monitor करने की अनुमति देते हैं।
- **EndpointSecurityClientManager**: यह user space clients के साथ communication manage करता है और track रखता है कि कौन से clients connected हैं और किन्हें event notifications प्राप्त करनी हैं।
- **EndpointSecurityMessageManager**: यह user space clients को messages और event notifications भेजता है।

Endpoint Security framework जिन events को monitor कर सकता है, उन्हें इन categories में विभाजित किया गया है:

- File events
- Process events
- Socket events
- Kernel events (जैसे kernel extension को load/unload करना या I/O Kit device खोलना)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security framework के साथ **User-space communication** IOUserClient class के माध्यम से होता है। Caller के type के आधार पर दो अलग-अलग subclasses का उपयोग किया जाता है:

- **EndpointSecurityDriverClient**: इसके लिए `com.apple.private.endpoint-security.manager` entitlement आवश्यक है, जो केवल system process `endpointsecurityd` के पास होता है।
- **EndpointSecurityExternalClient**: इसके लिए `com.apple.developer.endpoint-security.client` entitlement आवश्यक है। आमतौर पर इसका उपयोग third-party security software द्वारा किया जाता है, जिसे Endpoint Security framework के साथ interact करने की आवश्यकता होती है।<sup>[[1]](#references)</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** वह C library है जिसका उपयोग system extensions kernel के साथ communicate करने के लिए करते हैं। यह library Endpoint Security KEXT के साथ communicate करने के लिए I/O Kit (`IOKit`) का उपयोग करती है।<sup>[[2]](#references)</sup>

**`endpointsecurityd`** endpoint security system extensions को manage और launch करने में शामिल एक प्रमुख system daemon है, विशेष रूप से early boot process के दौरान। केवल वे **system extensions** जिन्हें उनकी `Info.plist` file में **`NSEndpointSecurityEarlyBoot`** से mark किया गया है, यह early boot treatment प्राप्त करते हैं।<sup>[[2]](#references)</sup>

एक अन्य system daemon, **`sysextd`**, **system extensions को validate करता है** और उन्हें उचित system locations में move करता है। इसके बाद यह relevant daemon से extension को load करने के लिए कहता है। **`SystemExtensions.framework`** system extensions को activate और deactivate करने के लिए responsible है।<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF का उपयोग security tools द्वारा किया जाता है, जो red teamer का पता लगाने का प्रयास करेंगे, इसलिए इससे बचने के तरीकों से संबंधित कोई भी information interesting लगती है।

### CVE-2021-30965

समस्या यह है कि security application के पास **Full Disk Access permissions** होना आवश्यक है। इसलिए यदि attacker इसे remove कर सके, तो वह software को run होने से रोक सकता है:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
इस bypass और इससे संबंधित अन्य bypasses के बारे में **अधिक जानकारी** के लिए यह talk देखें: [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

अंत में, इसे ठीक करने के लिए **`kTCCServiceEndpointSecurityClient`** नई permission को **`tccd`** द्वारा managed security app को दिया गया, ताकि `tccutil` उसकी permissions को clear न कर सके और उसे चलने से रोक न सके।<sup>[[3]](#references)</sup>

## संदर्भ

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
