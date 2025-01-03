# Certificates

{{#include ../banners/hacktricks-training.md}}

## What is a Certificate

A **public key certificate** एक डिजिटल आईडी है जिसका उपयोग क्रिप्टोग्राफी में किसी के सार्वजनिक कुंजी के स्वामित्व को साबित करने के लिए किया जाता है। इसमें कुंजी के विवरण, मालिक की पहचान (विषय), और एक विश्वसनीय प्राधिकरण (जारीकर्ता) से डिजिटल हस्ताक्षर शामिल होता है। यदि सॉफ़्टवेयर जारीकर्ता पर भरोसा करता है और हस्ताक्षर मान्य है, तो कुंजी के मालिक के साथ सुरक्षित संचार संभव है।

Certificates ज्यादातर [certificate authorities](https://en.wikipedia.org/wiki/Certificate_authority) (CAs) द्वारा [public-key infrastructure](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI) सेटअप में जारी किए जाते हैं। एक अन्य विधि [web of trust](https://en.wikipedia.org/wiki/Web_of_trust) है, जहां उपयोगकर्ता सीधे एक-दूसरे की कुंजी की पुष्टि करते हैं। Certificates के लिए सामान्य प्रारूप [X.509](https://en.wikipedia.org/wiki/X.509) है, जिसे RFC 5280 में वर्णित विशिष्ट आवश्यकताओं के लिए अनुकूलित किया जा सकता है।

## x509 Common Fields

### **Common Fields in x509 Certificates**

x509 certificates में, कई **fields** प्रमाणपत्र की वैधता और सुरक्षा सुनिश्चित करने में महत्वपूर्ण भूमिका निभाते हैं। इन fields का विवरण इस प्रकार है:

- **Version Number** x509 प्रारूप के संस्करण को दर्शाता है।
- **Serial Number** प्रमाणपत्र को एक Certificate Authority (CA) प्रणाली के भीतर अद्वितीय रूप से पहचानता है, मुख्य रूप से रद्दीकरण ट्रैकिंग के लिए।
- **Subject** field प्रमाणपत्र के मालिक का प्रतिनिधित्व करता है, जो एक मशीन, एक व्यक्ति, या एक संगठन हो सकता है। इसमें विस्तृत पहचान शामिल है जैसे:
- **Common Name (CN)**: प्रमाणपत्र द्वारा कवर किए गए डोमेन।
- **Country (C)**, **Locality (L)**, **State or Province (ST, S, or P)**, **Organization (O)**, और **Organizational Unit (OU)** भौगोलिक और संगठनात्मक विवरण प्रदान करते हैं।
- **Distinguished Name (DN)** पूर्ण विषय पहचान को संक्षिप्त करता है।
- **Issuer** विवरण देता है कि किसने प्रमाणपत्र की पुष्टि और हस्ताक्षर किया, जिसमें CA के लिए विषय के समान उपक्षेत्र शामिल हैं।
- **Validity Period** को **Not Before** और **Not After** टाइमस्टैम्प द्वारा चिह्नित किया जाता है, यह सुनिश्चित करते हुए कि प्रमाणपत्र को किसी निश्चित तिथि से पहले या बाद में उपयोग नहीं किया जाता है।
- **Public Key** अनुभाग, जो प्रमाणपत्र की सुरक्षा के लिए महत्वपूर्ण है, सार्वजनिक कुंजी के एल्गोरिदम, आकार, और अन्य तकनीकी विवरण निर्दिष्ट करता है।
- **x509v3 extensions** प्रमाणपत्र की कार्यक्षमता को बढ़ाते हैं, **Key Usage**, **Extended Key Usage**, **Subject Alternative Name**, और अन्य गुणों को निर्दिष्ट करते हैं ताकि प्रमाणपत्र के आवेदन को ठीक से समायोजित किया जा सके।

#### **Key Usage and Extensions**

- **Key Usage** सार्वजनिक कुंजी के क्रिप्टोग्राफिक अनुप्रयोगों की पहचान करता है, जैसे डिजिटल हस्ताक्षर या कुंजी एन्क्रिप्शन।
- **Extended Key Usage** प्रमाणपत्र के उपयोग के मामलों को और संकीर्ण करता है, जैसे कि TLS सर्वर प्रमाणीकरण के लिए।
- **Subject Alternative Name** और **Basic Constraint** प्रमाणपत्र द्वारा कवर किए गए अतिरिक्त होस्ट नामों और यह कि क्या यह एक CA या अंत-इकाई प्रमाणपत्र है, को परिभाषित करते हैं।
- **Subject Key Identifier** और **Authority Key Identifier** जैसे पहचानकर्ता कुंजी की अद्वितीयता और ट्रेसबिलिटी सुनिश्चित करते हैं।
- **Authority Information Access** और **CRL Distribution Points** जारीकर्ता CA की पुष्टि करने और प्रमाणपत्र रद्दीकरण स्थिति की जांच करने के लिए पथ प्रदान करते हैं।
- **CT Precertificate SCTs** पारदर्शिता लॉग प्रदान करते हैं, जो प्रमाणपत्र में सार्वजनिक विश्वास के लिए महत्वपूर्ण हैं।
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **OCSP और CRL वितरण बिंदुओं के बीच का अंतर**

**OCSP** (**RFC 2560**) में एक क्लाइंट और एक रिस्पॉन्डर मिलकर काम करते हैं यह जांचने के लिए कि क्या एक डिजिटल सार्वजनिक कुंजी प्रमाणपत्र को रद्द किया गया है, बिना पूर्ण **CRL** डाउनलोड किए। यह विधि पारंपरिक **CRL** की तुलना में अधिक कुशल है, जो रद्द किए गए प्रमाणपत्रों के अनुक्रमणिका नंबरों की एक सूची प्रदान करती है लेकिन एक संभावित बड़े फ़ाइल को डाउनलोड करने की आवश्यकता होती है। CRLs में 512 प्रविष्टियाँ तक हो सकती हैं। अधिक विवरण [यहाँ](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm) उपलब्ध हैं।

### **प्रमाणपत्र पारदर्शिता क्या है**

प्रमाणपत्र पारदर्शिता प्रमाणपत्र से संबंधित खतरों से लड़ने में मदद करती है यह सुनिश्चित करके कि SSL प्रमाणपत्रों का जारी होना और अस्तित्व डोमेन मालिकों, CAs, और उपयोगकर्ताओं के लिए दृश्य है। इसके उद्देश्य हैं:

- CAs को डोमेन मालिक की जानकारी के बिना एक डोमेन के लिए SSL प्रमाणपत्र जारी करने से रोकना।
- गलती से या दुर्भावनापूर्ण तरीके से जारी किए गए प्रमाणपत्रों को ट्रैक करने के लिए एक खुला ऑडिटिंग सिस्टम स्थापित करना।
- उपयोगकर्ताओं को धोखाधड़ी वाले प्रमाणपत्रों से सुरक्षित रखना।

#### **प्रमाणपत्र लॉग**

प्रमाणपत्र लॉग सार्वजनिक रूप से ऑडिट करने योग्य, केवल जोड़ने वाले रिकॉर्ड होते हैं, जो नेटवर्क सेवाओं द्वारा बनाए रखे जाते हैं। ये लॉग ऑडिटिंग उद्देश्यों के लिए क्रिप्टोग्राफिक प्रमाण प्रदान करते हैं। जारी करने वाली प्राधिकरण और जनता दोनों इन लॉग में प्रमाणपत्र जमा कर सकते हैं या सत्यापन के लिए उन्हें क्वेरी कर सकते हैं। जबकि लॉग सर्वरों की सटीक संख्या निश्चित नहीं है, यह अपेक्षित है कि यह वैश्विक स्तर पर एक हजार से कम हो। ये सर्वर CAs, ISPs, या किसी भी इच्छुक इकाई द्वारा स्वतंत्र रूप से प्रबंधित किए जा सकते हैं।

#### **क्वेरी**

किसी भी डोमेन के लिए प्रमाणपत्र पारदर्शिता लॉग का अन्वेषण करने के लिए, [https://crt.sh/](https://crt.sh) पर जाएँ।

प्रमाणपत्रों को संग्रहीत करने के लिए विभिन्न प्रारूप मौजूद हैं, प्रत्येक के अपने उपयोग के मामले और संगतता होती है। यह सारांश मुख्य प्रारूपों को कवर करता है और उनके बीच रूपांतरण के लिए मार्गदर्शन प्रदान करता है।

## **प्रारूप**

### **PEM प्रारूप**

- प्रमाणपत्रों के लिए सबसे व्यापक रूप से उपयोग किया जाने वाला प्रारूप।
- प्रमाणपत्रों और निजी कुंजियों के लिए अलग फ़ाइलों की आवश्यकता होती है, जो Base64 ASCII में एन्कोडेड होती हैं।
- सामान्य एक्सटेंशन: .cer, .crt, .pem, .key।
- मुख्य रूप से Apache और समान सर्वरों द्वारा उपयोग किया जाता है।

### **DER प्रारूप**

- प्रमाणपत्रों का एक बाइनरी प्रारूप।
- PEM फ़ाइलों में पाए जाने वाले "BEGIN/END CERTIFICATE" बयानों की कमी है।
- सामान्य एक्सटेंशन: .cer, .der।
- अक्सर Java प्लेटफार्मों के साथ उपयोग किया जाता है।

### **P7B/PKCS#7 प्रारूप**

- Base64 ASCII में संग्रहीत, एक्सटेंशन .p7b या .p7c के साथ।
- केवल प्रमाणपत्र और श्रृंखला प्रमाणपत्र होते हैं, निजी कुंजी को छोड़कर।
- Microsoft Windows और Java Tomcat द्वारा समर्थित।

### **PFX/P12/PKCS#12 प्रारूप**

- एक बाइनरी प्रारूप जो सर्वर प्रमाणपत्रों, मध्यवर्ती प्रमाणपत्रों, और निजी कुंजियों को एक फ़ाइल में संलग्न करता है।
- एक्सटेंशन: .pfx, .p12।
- मुख्य रूप से Windows पर प्रमाणपत्र आयात और निर्यात के लिए उपयोग किया जाता है।

### **प्रारूपों का रूपांतरण**

**PEM रूपांतरण** संगतता के लिए आवश्यक हैं:

- **x509 से PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM से DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER से PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM से P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 से PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX रूपांतरण** विंडोज़ पर प्रमाणपत्रों का प्रबंधन करने के लिए महत्वपूर्ण हैं:

- **PFX से PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX से PKCS#8** में दो चरण शामिल हैं:
1. PFX को PEM में परिवर्तित करें
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. PEM को PKCS8 में परिवर्तित करें
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B to PFX** के लिए भी दो कमांड की आवश्यकता होती है:
1. P7B को CER में परिवर्तित करें
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. CER और प्राइवेट की को PFX में परिवर्तित करें
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
---

{{#include ../banners/hacktricks-training.md}}
