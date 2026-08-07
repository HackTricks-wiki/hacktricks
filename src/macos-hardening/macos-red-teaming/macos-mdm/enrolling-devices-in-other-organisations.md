# अन्य Organisations में Devices Enroll करना

{{#include ../../../banners/hacktricks-training.md}}

## Intro

जैसा कि [**पहले बताया गया है**](#what-is-mdm-mobile-device-management)**,** किसी device को किसी organization में enroll करने के लिए **उस Organization से संबंधित केवल एक Serial Number की आवश्यकता होती है**। Device के enroll हो जाने के बाद, कई organizations नए device पर sensitive data install करेंगी: certificates, applications, WiFi passwords, VPN configurations [और इसी तरह](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)।\
इसलिए, यदि enrolment process सही तरीके से protected न हो, तो यह attackers के लिए एक खतरनाक entrypoint हो सकता है।

**निम्नलिखित research [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe) का summary है। आगे के technical details के लिए इसे देखें!**<sup>[[1]](#references)</sup>

## DEP और MDM Binary Analysis का Overview

यह research macOS पर Device Enrollment Program (DEP) और Mobile Device Management (MDM) से संबंधित binaries का analysis करती है। मुख्य components में शामिल हैं:

- **`mdmclient`**: MDM servers के साथ communicate करता है और 10.13.4 से पहले के macOS versions पर DEP check-ins trigger करता है।
- **`profiles`**: Configuration Profiles को manage करता है और macOS versions 10.13.4 और बाद के versions पर DEP check-ins trigger करता है।
- **`cloudconfigurationd`**: DEP API communications को manage करता है और Device Enrollment profiles retrieve करता है।

DEP check-ins private Configuration Profiles framework के `CPFetchActivationRecord` और `CPGetActivationRecord` functions का उपयोग करके Activation Record fetch करते हैं, जिसमें `CPFetchActivationRecord`, XPC के माध्यम से `cloudconfigurationd` के साथ coordination करता है।<sup>[[1]](#references)</sup>

## Tesla Protocol और Absinthe Scheme Reverse Engineering

DEP check-in में `cloudconfigurationd`, _iprofiles.apple.com/macProfile_ को एक encrypted, signed JSON payload भेजता है। Payload में device का serial number और action `"RequestProfileConfiguration"` शामिल होते हैं। इस्तेमाल की गई encryption scheme को internally "Absinthe" कहा जाता है। इस scheme को समझना complex है और इसमें कई steps शामिल हैं, जिसके कारण Activation Record request में arbitrary serial numbers insert करने के alternative methods explore किए गए।<sup>[[1]](#references)</sup>

## DEP Requests को Proxy करना

Charles Proxy जैसे tools का उपयोग करके _iprofiles.apple.com_ को भेजे जाने वाले DEP requests को intercept और modify करने के attempts payload encryption और SSL/TLS security measures के कारण बाधित हुए। हालांकि, `MCCloudConfigAcceptAnyHTTPSCertificate` configuration enable करने से server certificate validation को bypass किया जा सकता है, लेकिन payload की encrypted nature अभी भी decryption key के बिना serial number को modify करने से रोकती है।<sup>[[1]](#references)</sup>

## DEP के साथ Interact करने वाली System Binaries को Instrument करना

`cloudconfigurationd` जैसी system binaries को instrument करने के लिए macOS पर System Integrity Protection (SIP) को disable करना आवश्यक है। SIP disabled होने पर, LLDB जैसे tools का उपयोग system processes से attach करने और DEP API interactions में उपयोग किए जाने वाले serial number को potentially modify करने के लिए किया जा सकता है। यह method entitlements और code signing की complexities से बचने के कारण preferable है।<sup>[[1]](#references)</sup>

**Binary Instrumentation का Exploitation:**
`cloudconfigurationd` में JSON serialization से पहले DEP request payload को modify करना effective साबित हुआ। Process में ये steps शामिल थे:

1. `cloudconfigurationd` से LLDB attach करना।
2. उस point को locate करना जहां system serial number fetch किया जाता है।
3. Payload के encrypted होकर भेजे जाने से पहले memory में एक arbitrary serial number inject करना।

इस method ने arbitrary serial numbers के लिए complete DEP profiles retrieve करना संभव बनाया, जो एक potential vulnerability को demonstrate करता है।<sup>[[1]](#references)</sup>

### Python के साथ Instrumentation को Automate करना

Exploitation process को LLDB API के साथ Python का उपयोग करके automate किया गया, जिससे arbitrary serial numbers को programmatically inject करना और corresponding DEP profiles retrieve करना feasible हो गया।<sup>[[1]](#references)</sup>

### DEP और MDM Vulnerabilities के Potential Impacts

Research ने महत्वपूर्ण security concerns को highlight किया:

1. **Information Disclosure**: DEP-registered serial number provide करके, DEP profile में मौजूद sensitive organizational information retrieve की जा सकती है।<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
