# TLS & Certificates

{{#include ../../banners/hacktricks-training.md}}

यह क्षेत्र **X.509 पार्सिंग, फ़ॉर्मैट्स, रूपांतरण, और सामान्य गलतियों** के बारे में है।

## X.509: पार्सिंग, फ़ॉर्मैट्स & सामान्य गलतियाँ

### त्वरित पार्सिंग
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
निरीक्षण के लिए उपयोगी फ़ील्ड:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (क्या यह CA है?)
- वैधता अवधि (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### फ़ॉर्मैट्स और रूपांतरण

- PEM (Base64, BEGIN/END हेडर के साथ)
- DER (बाइनरी)
- PKCS#7 (`.p7b`) (cert chain, कोई private key नहीं)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

रूपांतरण:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### सामान्य आक्रामक दृष्टिकोण

- उपयोगकर्ता द्वारा प्रदान किए गए रूट्स पर भरोसा / चेन सत्यापन की कमी
- कमजोर हस्ताक्षर एल्गोरिदम (legacy)
- नाम प्रतिबंध / SAN पार्सिंग बग (implementation-specific)
- Confused deputy मुद्दे और client-certificate authentication misbinding

### CT logs

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
