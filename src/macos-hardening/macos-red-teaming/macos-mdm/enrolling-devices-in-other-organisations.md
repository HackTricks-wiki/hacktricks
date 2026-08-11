# अन्य Organisations में Devices Enroll करना

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Apple Automated Device Enrollment (पहले DEP) किसी organization को assigned device की पहचान करके शुरू होता है। यहां संक्षेपित 2018 के research से पता चला कि assigned serial number की जानकारी कुछ organizations के enrollment profiles प्राप्त करने के लिए पर्याप्त थी, क्योंकि उन organizations को पर्याप्त अतिरिक्त authentication की आवश्यकता नहीं थी। यह एक historical finding है, यह दावा नहीं कि हर वर्तमान MDM को केवल serial number से join किया जा सकता है। Profiles में certificates, applications, Wi-Fi secrets, VPN settings और अन्य sensitive configuration शामिल हो सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

**यह निम्नलिखित research [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe) का summary है। अधिक technical details के लिए इसे देखें!**<sup>[[1]](#references)</sup>

## DEP और MDM Binary Analysis का Overview

Research ने उस समय के current macOS versions पर DEP और MDM से जुड़े binaries का analysis किया। Component names और responsibilities अलग-अलग releases में बदल सकते हैं:

- **`mdmclient`**: MDM servers के साथ communicate करता है और 10.13.4 से पहले के macOS versions पर DEP check-ins trigger करता है।
- **`profiles`**: Configuration Profiles को manage करता है और macOS versions 10.13.4 और बाद के versions पर DEP check-ins trigger करता है।
- **`cloudconfigurationd`**: DEP API communications को manage करता है और Device Enrollment profiles retrieve करता है।

DEP check-ins private Configuration Profiles framework के `CPFetchActivationRecord` और `CPGetActivationRecord` functions का उपयोग करके Activation Record fetch करते हैं, जिसमें `CPFetchActivationRecord`, XPC के माध्यम से `cloudconfigurationd` के साथ coordinate करता है।<sup>[[1]](#references)</sup>

## Tesla Protocol और Absinthe Scheme Reverse Engineering

DEP check-in में `cloudconfigurationd`, _iprofiles.apple.com/macProfile_ को एक encrypted, signed JSON payload भेजता है। Payload में device का serial number और action "RequestProfileConfiguration" शामिल होते हैं। उपयोग की गई encryption scheme को internally "Absinthe" कहा जाता है। इस scheme को unravel करना complex है और इसमें कई steps शामिल हैं, जिसके कारण Activation Record request में arbitrary serial numbers insert करने के alternative methods की खोज की गई।<sup>[[1]](#references)</sup>

## DEP Requests को Proxy करना

Charles Proxy जैसे tools का उपयोग करके _iprofiles.apple.com_ को भेजी गई DEP requests को intercept और modify करने के प्रयास payload encryption और SSL/TLS security measures के कारण बाधित हुए। हालांकि, `MCCloudConfigAcceptAnyHTTPSCertificate` configuration enable करने से server certificate validation को bypass किया जा सकता है, लेकिन payload की encrypted nature के कारण decryption key के बिना serial number को modify करना अब भी संभव नहीं होता।<sup>[[1]](#references)</sup>

## DEP के साथ Interact करने वाले System Binaries को Instrument करना

`cloudconfigurationd` जैसे system binaries को instrument करने के लिए macOS पर System Integrity Protection (SIP) disable करना आवश्यक है। SIP disabled होने पर, LLDB जैसे tools का उपयोग system processes से attach करने और DEP API interactions में उपयोग किए जाने वाले serial number को संभावित रूप से modify करने के लिए किया जा सकता है। यह method entitlements और code signing की complexities से बचने के कारण preferable है।<sup>[[1]](#references)</sup>

**Binary Instrumentation का Exploitation:**
`cloudconfigurationd` में JSON serialization से पहले DEP request payload को modify करना effective साबित हुआ। इस process में शामिल थे:

1. `cloudconfigurationd` से LLDB attach करना।
2. उस point को locate करना जहां system serial number fetch किया जाता है।
3. Payload के encrypted और sent होने से पहले memory में arbitrary serial number inject करना।

इस method ने researchers को supplied, assigned serial numbers के लिए DEP profiles retrieve करने की अनुमति दी। इससे किसी unassigned arbitrary serial number को valid नहीं बनाया जा सका।<sup>[[1]](#references)</sup>

### Python के साथ Instrumentation को Automate करना

Exploitation process को LLDB API के साथ Python का उपयोग करके automate किया गया, जिससे arbitrary serial numbers को programmatically inject करना और corresponding DEP profiles retrieve करना feasible हो गया।<sup>[[1]](#references)</sup>

### DEP और MDM Vulnerabilities के संभावित Impacts

Research ने significant security concerns को उजागर किया:

1. **Information Disclosure**: DEP-registered serial number provide करके DEP profile में मौजूद sensitive organizational information retrieve की जा सकती है।<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
