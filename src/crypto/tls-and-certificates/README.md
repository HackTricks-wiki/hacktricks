# TLS 与 Certificates

{{#include ../../banners/hacktricks-training.md}}


本节介绍 **X.509 解析、格式、转换以及常见错误**。

## X.509：解析、格式与常见错误

### 快速解析
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
可检查的有用字段：

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints（是否为 CA？）
- Validity window（NotBefore/NotAfter）
- Signature algorithm（MD5？SHA1？）

### Formats & conversion

- PEM（带有 BEGIN/END headers 的 Base64）
- DER（二进制）
- PKCS#7（`.p7b`）（cert chain，不含 private key）
- PKCS#12（`.pfx/.p12`）（cert + private key + chain）

Conversions:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### 常见 offensive angles

- 信任用户提供的 roots / 缺少 chain validation
- 弱签名算法（legacy）
- Name constraints / SAN parsing bugs（implementation-specific）
- client-certificate authentication misbinding 导致的 confused deputy issues

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
