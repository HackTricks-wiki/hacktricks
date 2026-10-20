# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM के बारे में जानने के लिए देखें:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Basics

### **MDM (Mobile Device Management) का अवलोकन**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) का उपयोग स्मार्टफ़ोन, लैपटॉप और टैबलेट जैसे विभिन्न end-user उपकरणों के प्रबंधन के लिए किया जाता है। खास तौर पर Apple के प्लेटफ़ॉर्म (iOS, macOS, tvOS) के लिए, इसमें विशेष सुविधाओं, APIs और प्रक्रियाओं का एक सेट शामिल होता है। MDM का संचालन एक संगत MDM server पर निर्भर करता है, जो व्यावसायिक रूप से उपलब्ध या open-source हो सकता है और उसे [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) का समर्थन करना चाहिए। मुख्य बिंदु:

- उपकरणों पर केंद्रीकृत नियंत्रण।
- MDM protocol का पालन करने वाले MDM server पर निर्भरता।
- MDM server द्वारा उपकरणों को विभिन्न commands भेजने की क्षमता, उदाहरण के लिए दूरस्थ रूप से डेटा मिटाना या configuration इंस्टॉल करना।

### **DEP (Device Enrollment Program) की मूल बातें**

Apple का [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), iOS, macOS और tvOS उपकरणों के लिए zero-touch configuration की सुविधा देकर Mobile Device Management (MDM) के एकीकरण को सरल बनाता है। DEP enrollment प्रक्रिया को स्वचालित करता है, जिससे उपकरण बॉक्स से बाहर निकलते ही काम करने के लिए तैयार होते हैं और उपयोगकर्ता या व्यवस्थापक के न्यूनतम हस्तक्षेप की आवश्यकता होती है। मुख्य बातें:

- पहली बार सक्रिय होने पर उपकरणों को पहले से तय MDM server पर स्वयं पंजीकृत होने की सुविधा देता है।
- मुख्य रूप से नए उपकरणों के लिए उपयोगी है, लेकिन दोबारा configuration किए जा रहे उपकरणों पर भी लागू होता है।
- सरल setup की सुविधा देता है, जिससे उपकरण संगठन में तेज़ी से उपयोग के लिए तैयार हो जाते हैं।

### **सुरक्षा संबंधी विचार**

यह ध्यान रखना महत्वपूर्ण है कि DEP द्वारा दी जाने वाली आसान enrollment सुविधा लाभदायक होने के साथ-साथ सुरक्षा जोखिम भी पैदा कर सकती है। यदि MDM enrollment के लिए पर्याप्त सुरक्षा उपाय लागू नहीं किए गए हैं, तो हमलावर इस सरल प्रक्रिया का दुरुपयोग करके अपने उपकरण को संगठन के MDM server पर पंजीकृत कर सकते हैं और उसे कॉर्पोरेट उपकरण के रूप में दिखा सकते हैं।<sup>[[2]](#references)</sup>

> [!CAUTION]
> **सुरक्षा चेतावनी**: यदि उचित सुरक्षा उपाय लागू न हों, तो सरल DEP enrollment के कारण अनधिकृत उपकरण संगठन के MDM server पर पंजीकृत हो सकते हैं।

### SCEP (Simple Certificate Enrolment Protocol) क्या है?

- अपेक्षाकृत पुराना protocol, जिसे TLS और HTTPS के व्यापक रूप से इस्तेमाल होने से पहले बनाया गया था।
- Clients को **Certificate Signing Request** (CSR) भेजने का मानकीकृत तरीका देता है, ताकि उन्हें certificate दिया जा सके। Client server से अपने लिए signed certificate जारी करने का अनुरोध करता है।

### Configuration Profiles (जिन्हें mobileconfigs भी कहते हैं) क्या हैं?

- **System configuration सेट/लागू करने का** Apple का आधिकारिक तरीका।
- ऐसा file format जिसमें कई payloads हो सकते हैं।
- Property lists (XML वाला प्रकार) पर आधारित।
- “उनके स्रोत को सत्यापित करने, उनकी अखंडता सुनिश्चित करने और उनकी सामग्री सुरक्षित रखने के लिए उन्हें sign और encrypt किया जा सकता है।” Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- APNs (**Apple server**) + RESTful API (**MDM** **vendor** servers) का संयोजन
- **Communication**, एक **device** और **device** **management** **product** से जुड़े server के बीच होती है।
- MDM से device पर भेजे जाने वाले **Commands**, **plist-encoded dictionaries** में होते हैं।
- सब कुछ **HTTPS** पर होता है। MDM servers को pin किया जा सकता है (और आमतौर पर किया जाता है)।
- Apple, authentication के लिए MDM vendor को **APNs certificate** देता है।

### DEP

- **3 APIs**: resellers के लिए 1, MDM vendors के लिए 1, और device identity के लिए 1 (undocumented):
  - तथाकथित [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)। MDM servers इसका उपयोग DEP profiles को विशिष्ट उपकरणों से जोड़ने के लिए करते हैं।
  - [Apple Authorized Resellers द्वारा उपयोग किया जाने वाला DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), जिसका उपयोग उपकरणों को enroll करने, enrollment status जाँचने और transaction status जाँचने के लिए होता है।
  - Undocumented private DEP API। Apple Devices इसका उपयोग अपना DEP profile माँगने के लिए करते हैं। macOS पर, `cloudconfigurationd` binary इस API के ज़रिए communication के लिए ज़िम्मेदार है।
- अधिक आधुनिक और **JSON** आधारित (plist के बजाय)
- Apple, MDM vendor को **OAuth token** देता है।

**DEP "cloud service" API**

- RESTful
- Apple से MDM server तक device records sync करता है।
- MDM server से Apple तक “DEP profiles” sync करता है (जिन्हें Apple बाद में device तक पहुँचाता है)।
- DEP “profile” में ये शामिल होते हैं:
  - MDM vendor server URL
  - Server URL के लिए अतिरिक्त trusted certificates (वैकल्पिक pinning)
  - अतिरिक्त settings (जैसे Setup Assistant में किन screens को छोड़ना है)

## Serial Number

2010 के बाद निर्मित Apple उपकरणों के serial numbers में आम तौर पर **12 alphanumeric characters** होते हैं। इनमें **पहले तीन अंक निर्माण स्थान**, अगले **दो** निर्माण का **वर्ष** और **सप्ताह**, अगले **तीन अंक** एक **unique identifier**, और **अंतिम** **चार अंक** **model number** दर्शाते हैं।

{{#ref}}
macos-serial-number.md
{{#endref}}

## Enrollment और management के चरण

1. Device record बनाना (Reseller, Apple): नए device का record बनाया जाता है।
2. Device record असाइन करना (Customer): device को MDM server असाइन किया जाता है।
3. Device record sync करना (MDM vendor): MDM device records sync करता है और DEP profiles Apple को भेजता है।
4. DEP check-in (Device): device को अपना DEP profile मिलता है।
5. Profile प्राप्त करना (Device)
6. Profile इंस्टॉल करना (Device), जिसमें MDM, SCEP और root CA payloads शामिल हैं।
7. MDM command जारी करना (Device)

![Serial Number - Enrollment और management के चरण: 7. MDM command जारी करना (Device)](<../../../images/image (694).png>)

फ़ाइल `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` ऐसे functions export करती है जिन्हें enrollment प्रक्रिया के high-level "steps" माना जा सकता है।

### Step 4: DEP check-in - Activation Record प्राप्त करना

यह प्रक्रिया तब होती है जब कोई **user पहली बार Mac boot करता है** (या पूरा wipe करने के बाद)।

![Enrollment और management के चरण - Step 4: DEP check-in - Activation Record प्राप्त करना: यह प्रक्रिया तब होती है जब कोई user पहली बार Mac boot करता है (या पूरा wipe करने के बाद)](<../../../images/image (1044).png>)

या जब `sudo profiles show -type enrollment` चलाया जाता है।

- निर्धारित करें कि **device DEP enabled है या नहीं**
- Activation Record, **DEP “profile”** का आंतरिक नाम है।
- Device के Internet से जुड़ते ही प्रक्रिया शुरू हो जाती है।
- इसे **`CPFetchActivationRecord`** संचालित करता है।
- इसे XPC के ज़रिए **`cloudconfigurationd`** लागू करता है। **"Setup Assistant**" (device को पहली बार boot करने पर) या **`profiles`** command, activation record पाने के लिए इस **daemon से संपर्क करते हैं**।
  - LaunchDaemon (हमेशा root के रूप में चलता है)

**`MCTeslaConfigurationFetcher`** Activation Record पाने के लिए कुछ चरण पूरे करता है। यह प्रक्रिया **Absinthe** नामक encryption का उपयोग करती है।<sup>[[1]](#references)</sup>

1. **Certificate** प्राप्त करें।
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Certificate से state **initialize** करें (**`NACInit`**)
   1. Device-विशिष्ट विभिन्न डेटा का उपयोग करता है (यानी **`IOKit` के ज़रिए Serial Number**)
3. **Session key** प्राप्त करें।
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Session स्थापित करें (**`NACKeyEstablishment`**)।
5. Request भेजें।
   1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) पर POST करें और `{ "action": "RequestProfileConfiguration", "sn": "" }` डेटा भेजें।
   2. JSON payload को Absinthe से encrypt किया जाता है (**`NACSign`**)।
   3. सभी requests HTTPS पर होती हैं और built-in root certificates का उपयोग करती हैं।

![Enrollment और management के चरण - Step 4: DEP check-in - Activation Record प्राप्त करना: 3. सभी requests HTTPS पर होती हैं और built-in root certificates का उपयोग करती हैं](<../../../images/image (566) (1).png>)

Response एक JSON dictionary होती है, जिसमें कुछ महत्वपूर्ण डेटा होता है, जैसे:

- **url**: Activation profile के लिए MDM vendor host का URL
- **anchor-certs**: Trusted anchors के रूप में उपयोग किए जाने वाले DER certificates की array

### **Step 5: Profile प्राप्त करना**

![Step 4: DEP check-in - Activation Record प्राप्त करना - Step 5: Profile प्राप्त करना: Step 5: Profile प्राप्त करना](<../../../images/image (444).png>)

- Request, **DEP profile में दिए गए url** पर भेजी जाती है।
- यदि दिए गए हों, तो **trust का मूल्यांकन** करने के लिए **Anchor certificates** उपयोग किए जाते हैं।
  - याद रखें: DEP profile की **anchor_certs** property
- **Request एक साधारण .plist** होती है, जिसमें device की पहचान होती है।
  - उदाहरण: **UDID, OS version**।
- CMS-signed, DER-encoded
- **Device identity certificate (APNS से)** का उपयोग करके signed
- **Certificate chain** में expired **Apple iPhone Device CA** शामिल है।

![Step 4: DEP check-in - Activation Record प्राप्त करना - Step 5: Profile प्राप्त करना: Device identity certificate (APNS से) का उपयोग करके signed](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile इंस्टॉल करना

- प्राप्त होने के बाद, **profile को system पर store किया जाता है**।
- यह चरण अपने आप शुरू होता है (यदि **Setup Assistant** में हों)।
- इसे **`CPInstallActivationProfile`** संचालित करता है।
- इसे XPC के ज़रिए mdmclient लागू करता है।
  - Context के अनुसार LaunchDaemon (root के रूप में) या LaunchAgent (user के रूप में)
- Configuration profiles में इंस्टॉल करने के लिए कई payloads होते हैं।
- Profiles इंस्टॉल करने के लिए framework में plugin-based architecture है।
- हर payload type एक plugin से जुड़ा होता है।
  - यह XPC (framework में) या classic Cocoa (ManagedClient.app में) हो सकता है।
- उदाहरण:
  - Certificate Payloads, CertificateService.xpc का उपयोग करते हैं।

आमतौर पर, MDM vendor द्वारा दिया गया **activation profile** इन payloads को **शामिल करता है**:

- `com.apple.mdm`: device को MDM में **enroll** करने के लिए
- `com.apple.security.scep`: device को सुरक्षित रूप से **client certificate** देने के लिए।
- `com.apple.security.pem`: device के System Keychain में **trusted CA certificates इंस्टॉल** करने के लिए।
- MDM payload इंस्टॉल करना, documentation में **MDM check-in** के बराबर है।
- Payload में **मुख्य properties** होती हैं:
- - MDM Check-In URL (**`CheckInURL`**)
  - MDM Command Polling URL (**`ServerURL`**) + इसे trigger करने के लिए APNs topic
- MDM payload इंस्टॉल करने के लिए **`CheckInURL`** पर request भेजी जाती है।
- इसे **`mdmclient`** में लागू किया गया है।
- MDM payload, दूसरे payloads पर निर्भर हो सकता है।
- **Requests को विशिष्ट certificates पर pin** करने की सुविधा देता है:
  - Property: **`CheckInURLPinningCertificateUUIDs`**
  - Property: **`ServerURLPinningCertificateUUIDs`**
  - PEM payload के ज़रिए दिया जाता है।
- Device को identity certificate देने की सुविधा देता है:
  - Property: IdentityCertificateUUID
  - SCEP payload के ज़रिए दिया जाता है।

### **Step 7: MDM commands सुनना**

- MDM check-in पूरा होने के बाद, vendor **APNs का उपयोग करके push notifications भेज सकता है**।
- Notification मिलने पर, उसे **`mdmclient`** संभालता है।
- MDM commands के लिए poll करने हेतु, ServerURL पर request भेजी जाती है।
- पहले से इंस्टॉल किए गए MDM payload का उपयोग होता है:
  - Request को pin करने के लिए **`ServerURLPinningCertificateUUIDs`**
  - TLS client certificate के लिए **`IdentityCertificateUUID`**

## Attacks

### दूसरे संगठनों में Devices Enroll करना

असाइन किया गया serial number संगठन का enrollment path पहचानने में मदद कर सकता है, लेकिन यह **MDM enrollment की गारंटी नहीं देता**। Enrollment profile लौटाने से पहले server, `configuration_web_url` के ज़रिए user authentication की माँग कर सकता है। यह मानने के बजाय कि हर असाइन किया गया serial fleet में शामिल हो सकता है, जाँचें कि क्या किसी वैकल्पिक enrollment path में यह जाँच नहीं होती।<sup>[[3]](#references)</sup>

Rogue-enrollment workflow के लिए नीचे दिया गया linked page देखें। Compromise के बाद MDM control और package delivery के लिए [macOS Red Teaming](../) देखें।

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [macOS MDM की गहन पड़ताल (और इससे कैसे समझौता किया जा सकता है)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Web views के ज़रिए authentication](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
