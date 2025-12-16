# TLS & 证书

{{#include ../../banners/hacktricks-training.md}}

本节涉及 **X.509 解析、格式、转换和常见错误**。

## X.509：解析、格式与常见错误

### 快速解析
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
有用的字段（需检查）：

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints（是否为 CA？）
- 有效期窗口（NotBefore/NotAfter）
- 签名算法（MD5？SHA1？）

### 格式与转换

- PEM（Base64，带 BEGIN/END 头）
- DER（二进制）
- PKCS#7（`.p7b`）（证书链，不含私钥）
- PKCS#12（`.pfx/.p12`）（证书 + 私钥 + 链）

转换：
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### 常见攻击面

- 信任用户提供的根证书 / 缺少链验证
- 弱签名算法（遗留）
- 名称约束 / SAN 解析漏洞（与实现相关）
- 与 client-certificate authentication misbinding 相关的 Confused deputy 问题

### CT 日志

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
