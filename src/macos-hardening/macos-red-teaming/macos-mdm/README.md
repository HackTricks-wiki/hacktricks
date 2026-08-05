# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDMs के बारे में जानने के लिए देखें:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Basics

### **MDM (Mobile Device Management) का अवलोकन**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) का उपयोग smartphones, laptops और tablets जैसे विभिन्न end-user devices की निगरानी के लिए किया जाता है। विशेष रूप से Apple के platforms (iOS, macOS, tvOS) के लिए, इसमें specialized features, APIs और practices का एक समूह शामिल होता है। MDM का संचालन एक compatible MDM server पर निर्भर करता है, जो commercial या open-source हो सकता है और [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) को support करना आवश्यक है। मुख्य बिंदु:

- Devices पर centralized control।
- MDM protocol का पालन करने वाले MDM server पर निर्भरता।
- MDM server की devices को विभिन्न commands भेजने की क्षमता, जैसे remote data erasure या configuration installation।

### **DEP (Device Enrollment Program) का Basics**

Apple द्वारा दिया गया [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), iOS, macOS और tvOS devices के लिए zero-touch configuration की सुविधा देकर Mobile Device Management (MDM) के integration को सरल बनाता है। DEP enrollment process को automate करता है, जिससे devices box से बाहर निकलते ही operational हो सकते हैं और user या administrator के न्यूनतम intervention की आवश्यकता होती है। आवश्यक पहलू:

- Initial activation पर devices को pre-defined MDM server के साथ autonomously register करने में सक्षम बनाता है।
- मुख्य रूप से brand-new devices के लिए उपयोगी है, लेकिन reconfiguration से गुजर रहे devices पर भी लागू होता है।
- सरल setup की सुविधा देता है, जिससे devices शीघ्रता से organizational use के लिए तैयार हो जाते हैं।

### **Security Consideration**

यह ध्यान रखना महत्वपूर्ण है कि DEP द्वारा दी गई enrollment की सुविधा, लाभदायक होने के बावजूद, security risks भी उत्पन्न कर सकती है। यदि MDM enrollment के लिए protective measures पर्याप्त रूप से लागू नहीं किए गए हों, तो attackers इस streamlined process का दुरुपयोग करके अपने device को organization के MDM server पर corporate device के रूप में register कर सकते हैं।<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Security Alert**: सरल DEP enrollment, यदि उचित safeguards मौजूद न हों, तो organization के MDM server पर unauthorized device registration की अनुमति दे सकता है।

### Basics SCEP (Simple Certificate Enrolment Protocol) क्या है?

- यह एक relatively old protocol है, जिसे TLS और HTTPS के व्यापक रूप से उपयोग होने से पहले बनाया गया था।
- यह clients को **Certificate Signing Request** (CSR) भेजने का standardized तरीका देता है, ताकि उन्हें certificate प्रदान किया जा सके। Client server से अपने लिए signed certificate देने का अनुरोध करता है।

### Configuration Profiles (जिन्हें mobileconfigs भी कहा जाता है) क्या हैं?

- **System configuration सेट/enforce करने का Apple का official तरीका।**
- ऐसा file format जिसमें multiple payloads हो सकते हैं।
- Property lists (XML वाली) पर आधारित।
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers) का combination
- **Communication** एक **device** और **device** **management** **product** से जुड़े server के बीच होती है
- **Commands**, MDM से device तक **plist-encoded dictionaries** में भेजे जाते हैं
- सब कुछ **HTTPS** पर। MDM servers को pin किया जा सकता है (और आमतौर पर किया जाता है)।
- Apple authentication के लिए MDM vendor को एक **APNs certificate** प्रदान करता है

### DEP

- **3 APIs**: 1 resellers के लिए, 1 MDM vendors के लिए, 1 device identity के लिए (undocumented):
- तथाकथित [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)। इसका उपयोग MDM servers द्वारा DEP profiles को specific devices के साथ associate करने के लिए किया जाता है।
- [Apple Authorized Resellers द्वारा उपयोग की जाने वाली DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), जिसका उपयोग devices को enroll करने, enrollment status check करने और transaction status check करने के लिए किया जाता है।
- Undocumented private DEP API। इसका उपयोग Apple Devices द्वारा अपने DEP profile का अनुरोध करने के लिए किया जाता है। macOS पर, `cloudconfigurationd` binary इस API के माध्यम से communication के लिए जिम्मेदार होती है।
- अधिक modern और **JSON** आधारित (plist के विपरीत)
- Apple MDM vendor को एक **OAuth token** प्रदान करता है

**DEP "cloud service" API**

- RESTful
- Apple से device records को MDM server पर sync करना
- MDM server से “DEP profiles” को Apple पर sync करना (बाद में Apple द्वारा device तक पहुंचाए जाते हैं)
- DEP “profile” में शामिल होते हैं:
- MDM vendor server URL
- Server URL के लिए additional trusted certificates (optional pinning)
- Extra settings (जैसे Setup Assistant में किन screens को skip करना है)

## Serial Number

2010 के बाद निर्मित Apple devices में सामान्यतः **12-character alphanumeric** serial numbers होते हैं। इनमें **पहले तीन digits manufacturing location**, अगले **दो digits manufacture के year** और **week**, अगले **तीन digits** एक **unique** **identifier**, और **अंतिम चार digits** **model number** दर्शाते हैं।


{{#ref}}
macos-serial-number.md
{{#endref}}

## Enrolment और management के Steps

1. Device record creation (Reseller, Apple): नए device का record बनाया जाता है
2. Device record assignment (Customer): device को एक MDM server assign किया जाता है
3. Device record sync (MDM vendor): MDM device records को sync करता है और DEP profiles को Apple पर push करता है
4. DEP check-in (Device): Device अपना DEP profile प्राप्त करता है
5. Profile retrieval (Device)
6. Profile installation (Device) a. जिसमें MDM, SCEP और root CA payloads शामिल होते हैं
7. MDM command issuance (Device)

![Serial Number - Enrolment और management के Steps: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

File `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` ऐसे functions export करती है जिन्हें enrolment process के **high-level "steps"** माना जा सकता है।

### Step 4: DEP check-in - Activation Record प्राप्त करना

Process का यह भाग तब होता है जब **user पहली बार Mac boot करता है** (या complete wipe के बाद)

![Enrolment और management के Steps - Step 4: DEP check-in - Activation Record प्राप्त करना: Process का यह भाग तब होता है जब user पहली बार Mac boot करता है (या complete...](<../../../images/image (1044).png>)

या `sudo profiles show -type enrollment` execute करते समय

- यह निर्धारित करना कि **device DEP enabled है या नहीं**
- Activation Record, **DEP “profile”** का internal name है
- Device के Internet से connect होते ही शुरू होता है
- **`CPFetchActivationRecord`** द्वारा driven
- XPC के माध्यम से **`cloudconfigurationd`** द्वारा implemented। **"Setup Assistant**" (जब device पहली बार boot होता है) या **`profiles`** command activation record प्राप्त करने के लिए **इस daemon से contact** करते हैं।
- LaunchDaemon (हमेशा root के रूप में चलता है)

Activation Record प्राप्त करने के लिए कुछ steps follow किए जाते हैं, जिन्हें **`MCTeslaConfigurationFetcher`** perform करता है। यह process **Absinthe** नामक encryption का उपयोग करता है।<sup>[[1]](#references)</sup>

1. **certificate** retrieve करना
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Certificate से state **initialize** करना (**`NACInit`**)
1. Various device-specific data का उपयोग करता है (अर्थात **`IOKit` के माध्यम से Serial Number**)
3. **session key** retrieve करना
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Session establish करना (**`NACKeyEstablishment`**)
5. Request करना
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) पर POST करके `{ "action": "RequestProfileConfiguration", "sn": "" }` data भेजना
2. JSON payload को Absinthe (**`NACSign`**) का उपयोग करके encrypted किया जाता है
3. सभी requests HTTPs पर होती हैं, built-in root certificates का उपयोग किया जाता है

![Enrolment और management के Steps - Step 4: DEP check-in - Activation Record प्राप्त करना: 3. सभी requests HTTPs पर होती हैं, built-in root certificates का उपयोग किया जाता है](<../../../images/image (566) (1).png>)

Response एक JSON dictionary होती है जिसमें कुछ महत्वपूर्ण data होता है, जैसे:

- **url**: Activation profile के लिए MDM vendor host का URL
- **anchor-certs**: Trusted anchors के रूप में उपयोग किए जाने वाले DER certificates की Array

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Activation Record प्राप्त करना - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- Request **DEP profile में दिए गए url** पर भेजी जाती है।
- यदि उपलब्ध हों, तो **Anchor certificates** का उपयोग **trust evaluate** करने के लिए किया जाता है।
- Reminder: DEP profile की **anchor_certs** property
- **Request एक simple .plist** होती है जिसमें device identification होती है
- Examples: **UDID, OS version**।
- CMS-signed, DER-encoded
- **APNS से प्राप्त device identity certificate** का उपयोग करके signed
- **Certificate chain** में expired **Apple iPhone Device CA** शामिल होता है

![Step 4: DEP check-in - Activation Record प्राप्त करना - Step 5: Profile Retrieval: APNS से प्राप्त device identity certificate का उपयोग करके signed](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- Retrieve होने के बाद **profile system पर store** की जाती है
- यह step automatically शुरू होता है (यदि **setup assistant** में हो)
- **`CPInstallActivationProfile`** द्वारा driven
- XPC के माध्यम से mdmclient द्वारा implemented
- Context के आधार पर LaunchDaemon (root के रूप में) या LaunchAgent (user के रूप में)
- Configuration profiles में install करने के लिए multiple payloads होते हैं
- Framework profiles install करने के लिए plugin-based architecture का उपयोग करता है
- प्रत्येक payload type एक plugin से associated होता है
- यह XPC (framework में) या classic Cocoa (ManagedClient.app में) हो सकता है
- Example:
- Certificate Payloads, CertificateService.xpc का उपयोग करते हैं

आमतौर पर, MDM vendor द्वारा प्रदान किए गए **activation profile** में निम्नलिखित payloads शामिल होते हैं:

- `com.apple.mdm`: device को MDM में **enroll** करने के लिए
- `com.apple.security.scep`: device को सुरक्षित रूप से **client certificate** प्रदान करने के लिए
- `com.apple.security.pem`: device के System Keychain में trusted CA certificates **install** करने के लिए
- MDM payload install करना documentation में बताए गए **MDM check-in** के equivalent है
- Payload में **key properties** होती हैं:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + इसे trigger करने के लिए APNs topic
- MDM payload install करने के लिए request **`CheckInURL`** पर भेजी जाती है
- **`mdmclient`** में implemented
- MDM payload अन्य payloads पर depend कर सकता है
- **Requests को specific certificates पर pin** करने की अनुमति देता है:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- PEM payload के माध्यम से delivered
- Device को identity certificate के साथ attribute करने की अनुमति देता है:
- Property: IdentityCertificateUUID
- SCEP payload के माध्यम से delivered

### **Step 7: MDM commands के लिए Listening**

- MDM check-in complete होने के बाद, vendor **APNs का उपयोग करके push notifications issue** कर सकता है
- प्राप्त होने पर, इसे **`mdmclient`** handle करता है
- MDM commands के लिए poll करने हेतु request ServerURL पर भेजी जाती है
- पहले से installed MDM payload का उपयोग करता है:
- Pinning request के लिए **`ServerURLPinningCertificateUUIDs`**
- TLS client certificate के लिए **`IdentityCertificateUUID`**

## Attacks

### अन्य Organisations में Devices Enroll करना

जैसा कि पहले बताया गया है, किसी device को किसी organization में enroll करने का प्रयास करने के लिए **उस Organization से संबंधित केवल एक Serial Number आवश्यक है**। Device के enroll हो जाने के बाद, कई organizations नए device पर sensitive data install करेंगी: certificates, applications, WiFi passwords, VPN configurations [और इसी तरह](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)।\
इसलिए, यदि enrolment process सही तरीके से protected न हो, तो यह attackers के लिए एक dangerous entrypoint हो सकता है:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [macOS MDM में Deep Dive (और इसे कैसे Compromise किया जा सकता है)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
