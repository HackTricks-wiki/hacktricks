# TLS & Certificates

{{#include ../../banners/hacktricks-training.md}}

यह क्षेत्र **X.509 पार्सिंग, फ़ॉर्मैट, रूपांतरण, और सामान्य गलतियाँ** के बारे में है।

## X.509: पार्सिंग, फ़ॉर्मैट & सामान्य गलतियाँ

### त्वरित पार्सिंग
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
निरीक्षण के लिए उपयोगी फ़ील्ड:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (क्या यह एक CA है?)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### फॉर्मैट्स और रूपांतरण

- PEM (Base64 जिसमें BEGIN/END headers)
- DER (binary)
- PKCS#7 (`.p7b`) (cert chain, कोई private key नहीं)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

रूपांतरण:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### सामान्य offensive दृष्टिकोण

- उपयोगकर्ता-प्रदान किए गए roots पर भरोसा करना / chain validation का अभाव
- कमजोर signature algorithms (legacy)
- Name constraints / SAN parsing bugs (implementation-specific)
- Confused deputy issues और client-certificate authentication misbinding

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
