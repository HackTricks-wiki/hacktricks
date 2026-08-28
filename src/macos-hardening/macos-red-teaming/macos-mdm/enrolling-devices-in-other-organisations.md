# अन्य Organisations में Devices Enroll करना

{{#include ../../../banners/hacktricks-training.md}}

## परिचय

Apple Automated Device Enrollment (पूर्व में DEP) किसी Organisation को असाइन किए गए Device की पहचान करके शुरू होता है। यहां संक्षेपित 2018 के Research से पता चला कि असाइन किए गए Serial Number की जानकारी कुछ Organisations के Enrollment Profiles प्राप्त करने के लिए पर्याप्त थी, क्योंकि उन Organisations को पर्याप्त अतिरिक्त Authentication की आवश्यकता नहीं थी। यह एक ऐतिहासिक निष्कर्ष है, यह दावा नहीं कि हर वर्तमान MDM में केवल Serial Number से Join किया जा सकता है। Profiles में Certificates, Applications, Wi-Fi Secrets, VPN Settings और अन्य संवेदनशील Configuration हो सकती हैं।<sup>[[1]](#references)[[2]](#references)</sup>

**निम्नलिखित Research का सारांश है [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)। अधिक Technical Details के लिए इसे देखें!**<sup>[[1]](#references)</sup>

## DEP और MDM Binary Analysis का Overview

Research में उस समय के वर्तमान macOS Versions पर DEP और MDM से संबंधित Binaries का Analysis किया गया। Releases के अनुसार Component Names और Responsibilities बदल सकती हैं:

- **`mdmclient`**: MDM Servers के साथ Communicate करता है और 10.13.4 से पहले के macOS Versions पर DEP Check-ins Trigger करता है।
- **`profiles`**: Configuration Profiles को Manage करता है और macOS Versions 10.13.4 और बाद के Versions पर DEP Check-ins Trigger करता है।
- **`cloudconfigurationd`**: DEP API Communications को Manage करता है और Device Enrollment Profiles प्राप्त करता है।

DEP Check-ins, private Configuration Profiles Framework के `CPFetchActivationRecord` और `CPGetActivationRecord` Functions का उपयोग करके Activation Record Fetch करते हैं। इसमें `CPFetchActivationRecord`, XPC के माध्यम से `cloudconfigurationd` के साथ Coordinate करता है।<sup>[[1]](#references)</sup>

## Tesla Protocol और Absinthe Scheme की Reverse Engineering

DEP Check-in में `cloudconfigurationd`, _iprofiles.apple.com/macProfile_ को एक Encrypted और Signed JSON Payload भेजता है। Payload में Device का Serial Number और `"RequestProfileConfiguration"` Action शामिल होता है। उपयोग की गई Encryption Scheme को Internally "Absinthe" कहा जाता है। इस Scheme को समझना Complex है और इसमें कई Steps शामिल हैं, जिसके कारण Activation Record Request में Arbitrary Serial Numbers Insert करने के Alternative Methods तलाशे गए।<sup>[[1]](#references)</sup>

## DEP Requests को Proxy करना

Charles Proxy जैसे Tools का उपयोग करके _iprofiles.apple.com_ को भेजे गए DEP Requests को Intercept और Modify करने के प्रयास Payload Encryption और SSL/TLS Security Measures के कारण बाधित हुए। हालांकि, `MCCloudConfigAcceptAnyHTTPSCertificate` Configuration Enable करने से Server Certificate Validation को Bypass किया जा सकता है, लेकिन Payload की Encrypted प्रकृति अभी भी Decryption Key के बिना Serial Number को Modify करने से रोकती है।<sup>[[1]](#references)</sup>

## DEP के साथ Interact करने वाले System Binaries को Instrument करना

`cloudconfigurationd` जैसे System Binaries को Instrument करने के लिए macOS पर System Integrity Protection (SIP) Disable करना आवश्यक है। SIP Disable होने पर LLDB जैसे Tools का उपयोग System Processes से Attach करने और DEP API Interactions में उपयोग किए गए Serial Number को संभावित रूप से Modify करने के लिए किया जा सकता है। यह Method बेहतर है क्योंकि इससे Entitlements और Code Signing की जटिलताएं दूर हो जाती हैं।<sup>[[1]](#references)</sup>

**Binary Instrumentation का Exploitation:**
`cloudconfigurationd` में JSON Serialization से पहले DEP Request Payload को Modify करना प्रभावी सिद्ध हुआ। Process में ये Steps शामिल थे:

1. `cloudconfigurationd` से LLDB Attach करना।
2. उस Point का पता लगाना जहां System Serial Number Fetch किया जाता है।
3. Payload के Encrypted और Sent होने से पहले Memory में एक Arbitrary Serial Number Inject करना।

इस Method से Researchers को दिए गए, Organisation को Assigned Serial Numbers के लिए DEP Profiles प्राप्त करने की सुविधा मिली। इससे किसी Unassigned Arbitrary Serial Number को Valid नहीं बनाया जा सका।<sup>[[1]](#references)</sup>

### Python के साथ Instrumentation को Automate करना

Exploitation Process को LLDB API के साथ Python का उपयोग करके Automate किया गया, जिससे Arbitrary Serial Numbers को Programmatically Inject करना और संबंधित DEP Profiles प्राप्त करना संभव हुआ।<sup>[[1]](#references)</sup>

## 2025 का Revisit: VM से Rogue Enrollment

Black Hat Asia 2025 Research ने प्रदर्शित किया कि मूल Trust-Boundary Problem अभी भी **MDM Layer** पर महत्वपूर्ण हो सकता है: `cloudconfigurationd` को LLDB से Patch करने के बजाय, Researchers ने OpenCore के साथ QEMU/KVM के अंतर्गत macOS चलाया और VM के SMBIOS के माध्यम से Candidate Identity प्रदान की। इसके बाद Unmodified macOS Enrollment Stack ने Encrypted Apple Exchange किया। इसलिए Publicly Leaked Serials और Valid-Looking Candidates को संबंधित Physical Mac के बिना Test किया जा सकता है; फिर भी सफल परिणाम के लिए आवश्यक है कि Serial किसी Organisation को Assigned हो और Organisation का Enrollment Path अपर्याप्त रूप से Authenticated हो।<sup>[[3]](#references)</sup>

Authorized Lab Device के लिए, संबंधित OpenCore `PlatformInfo` Values में Product Model और Serial शामिल होते हैं (Real Deployments में ROM और UUID को भी Internally Consistent रखा जाता है):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
उसी research में private file `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck` में `CheckProfilesFetchRateLimit` state की पहचान की गई। चूँकि check client पर maintained था, stored time values को modify करने से यह निष्प्रभावी हो गया। ये paths undocumented और version-dependent हैं, लेकिन current macOS build का assessment करते समय reversing pivots के रूप में उपयोगी हैं:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
दूसरा artifact cached activation record को disclose कर सकता है, जिसमें यह शामिल होता है कि flow direct `ConfigurationURL` या authenticated `ConfigurationWebURL` का उपयोग करता है। Advertised flow और किसी भी MDM-specific legacy enrollment endpoints—दोनों का test करें: केवल main web flow पर SSO enable करने से parallel direct endpoint सुरक्षित नहीं होता। Complete protocol sequence के लिए [macOS MDM overview](README.md) देखें।<sup>[[3]](#references)</sup>

### Enrollment के बाद Secret Hunting

Rogue enrollment केवल entry point है। Enrollment के बाद, हर delivered profile, bootstrap policy, package-repository configuration, agent installation script और self-service item का inspection करें। 2025 research में Wi-Fi credentials, shared local-administrator passwords, signed cloud-storage URLs, webhook URLs, security-agent activation data और MDM/API credentials के उदाहरण recovered किए गए। Delivered script में मौजूद tenant API credential एक rogue endpoint को अन्य managed devices पर control में बदल सकता है, इसलिए live filesystem और downloaded/cached policy content—दोनों में search करें।<sup>[[3]](#references)</sup>

उपयोगी review targets में शामिल हैं:<sup>[[3]](#references)</sup>

- Installed `.mobileconfig` payloads और Configuration Profiles database।
- PreStage/bootstrap scripts और वे packages जो accounts create करते हैं या EDR/VPN agents install करते हैं।
- Munki या अन्य package repository URLs, विशेष रूप से वे query strings जिनमें bearer/SAS-style signatures हों।
- Self-service catalogs और उनके backing policy APIs, जिनमें legacy routes भी शामिल हैं जो enrollment SSO policy लागू नहीं कर सकते।
- `password`, `token`, `secret`, `Authorization`, webhook hostnames और vendor API endpoints के लिए shell history और cached policy output।

### Trust Boundary को Harden करना

Serial number को inventory/routing attribute मानें, **possession का proof नहीं**। Enrollment और self service के लिए user authentication आवश्यक करें, प्रति-device unique local administrator passwords generate करें, और profiles या scripts में tenant API credentials या reusable infrastructure secrets कभी embed न करें। किसी भी unavoidable bootstrap token को short-lived रखें और उसे केवल provision किए जा रहे single action और device तक restricted रखें।<sup>[[3]](#references)</sup>

macOS 14 या उसके बाद के versions चला रहे Apple-silicon Macs पर Managed Device Attestation identity को cryptographically Secure Enclave से bind कर सकता है। इसका Apple-rooted attestation fresh nonce के साथ serial number, UDID, OS version, SIP state और secure-boot state carry कर सकता है; इसके बाद ACME hardware-bound client identity issue कर सकता है। MDM channel को protect करने और high-value certificates, VPN access तथा अन्य resources को gate करने के लिए उस identity का उपयोग करें, जबकि separate user authentication बनाए रखें, क्योंकि device attestation operator के बजाय device को prove करता है।<sup>[[4]](#references)</sup>

## DEP और MDM Vulnerabilities के संभावित प्रभाव

Research ने महत्वपूर्ण security concerns को उजागर किया:

1. **Information Disclosure**: DEP-registered serial number प्रदान करके, DEP profile में मौजूद sensitive organizational information retrieve की जा सकती है।<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking Apple MDMs Using Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
