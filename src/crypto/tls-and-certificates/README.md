# TLS और Certificates

{{#include ../../banners/hacktricks-training.md}}


यह अनुभाग **X.509 parsing, formats और सामान्य गलतियों** के बारे में है।

## X.509: parsing, formats और सामान्य गलतियाँ

### त्वरित parsing
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
निरीक्षण करने के लिए उपयोगी fields:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (क्या यह CA है?)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Formats और conversion

- PEM (BEGIN/END headers के साथ Base64)
- DER (binary)
- PKCS#7 (`.p7b`) (cert chain, private key के बिना)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Conversions:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Common offensive angles

- User-provided roots पर भरोसा करना / missing chain validation
- Weak signature algorithms (legacy)
- Name constraints / SAN parsing bugs (implementation-specific)
- Client-certificate authentication misbinding से जुड़े confused deputy issues

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
