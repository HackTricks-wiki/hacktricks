# TLS 和 Certificates

{{#include ../../banners/hacktricks-training.md}}

本节介绍 X.509 检查、编码、转换以及与安全相关的验证错误。

## X.509 解析

OpenSSL 可以打印证书的解码字段，而 `asn1parse` 则显示底层的 ASN.1 结构。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
检查至少以下内容：

- subject、issuer 和 Subject Alternative Name (SAN)；
- key usage 和 extended key usage；
- basic constraints 和 path-length constraints；
- `notBefore` 和 `notAfter` 有效时间；
- public-key 参数和 signature algorithm。

MD5 或 SHA-1 等旧式 signature 使用的 certificate signatures 尤其值得关注，尽管具体的接受情况和影响取决于 validator 和 trust context。<sup>[[3]](#references)</sup>

RFC 5280 定义了 Internet X.509 profile，以及 SAN、key usage、name constraints 和 basic constraints 等 extensions 的处理规则。<sup>[[3]](#references)</sup>

## 编码和容器

- **PEM-style textual encoding：** 位于 `BEGIN` 和 `END` 边界之间的 Base64 数据。
- **DER：** 二进制 Distinguished Encoding Rules 表示形式。
- **PKCS#7/CMS (`.p7b`)：** 通常包含 certificates 和 certificate chain，但不包含 private keys。
- **PKCS#12 (`.p12` 或 `.pfx`)：** 可以包含 private keys、certificates 和 supporting certificates。

RFC 7468 规定了 PKIX、PKCS 和 CMS structures 使用的 textual encodings；OpenSSL 的 `pkcs12` command 用于创建和解析 PKCS#12 files。<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
将 `out.pem` 视为敏感文件：除非使用 `-nokeys` 等选项，否则输出可能包含私钥材料。<sup>[[5]](#references)</sup>

## Security Review Checklist

审查 validator 或 trust decision 时，应用 RFC 5280 中的证书处理要求。<sup>[[3]](#references)</sup>

- 验证到显式受信任锚点的完整链；不要隐式信任用户提供的根证书。
- 根据 SAN 值确认主机名或服务身份。<sup>[[8]](#references)</sup>
- 强制执行基本约束、名称约束、密钥用法和扩展密钥用法。
- 拒绝已过期或尚未生效的证书，以及不允许的密钥或签名算法。
- 将 client-certificate 身份绑定到正确的应用程序账户和授权上下文。

## Certificate Transparency Logs

Certificate Transparency 提供已签发证书的公开可审计日志。<sup>[[6]](#references)</sup>在授权的资产发现过程中，使用 crt.sh 搜索域名。<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL 文档 - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL 文档 - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 公钥基础设施证书和 CRL 配置文件](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - PKIX、PKCS 和 CMS 结构的文本编码](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL 文档 - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency 2.0 版](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - 证书搜索](https://crt.sh/)
- [8] [RFC 9525 - TLS 中的服务身份](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
