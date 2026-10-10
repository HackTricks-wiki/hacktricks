# TLS 与证书

{{#include ../../banners/hacktricks-training.md}}

本节介绍 X.509 检查、编码、转换，以及与安全相关的验证错误。

## X.509 解析

OpenSSL 可以打印证书解码后的字段，而 `asn1parse` 则会显示底层 ASN.1 结构。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

至少检查以下内容：

- subject、issuer 和 Subject Alternative Name (SAN)；
- key usage 和 extended key usage；
- basic constraints 和 path-length constraints；
- `notBefore` 和 `notAfter` 有效时间；
- 公钥参数和签名算法。

基于 MD5 或 SHA-1 等算法的旧式签名尤其值得关注，但具体是否会被接受及其影响取决于验证器和信任上下文。<sup>[[3]](#references)</sup>

RFC 5280 定义了 Internet X.509 配置文件，以及 SAN、key usage、name constraints 和 basic constraints 等扩展的处理规则。<sup>[[3]](#references)</sup>

## 编码和容器

- **PEM-style 文本编码：** 位于 `BEGIN` 和 `END` 边界之间的 Base64 数据。
- **DER：** 二进制 Distinguished Encoding Rules 表示形式。
- **PKCS#7/CMS (`.p7b`)：** 通常包含证书和证书链，但不包含私钥。
- **PKCS#12 (`.p12` 或 `.pfx`)：** 可以包含私钥、证书和支持证书。

RFC 7468 规定了 PKIX、PKCS 和 CMS 结构使用的文本编码；OpenSSL 的 `pkcs12` 命令可创建和解析 PKCS#12 文件。<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

将 `out.pem` 视为敏感文件：除非使用 `-nokeys` 等选项，否则输出可能包含私钥材料。<sup>[[5]](#references)</sup>

## 安全审查清单

审查验证器或信任决策时，应用 RFC 5280 中的证书处理要求。<sup>[[3]](#references)</sup>

- 验证完整证书链直至明确受信任的锚；不要默认信任用户提供的根证书。
- 根据 SAN 值确认主机名或服务身份。<sup>[[8]](#references)</sup>
- 强制执行基本约束、名称约束、密钥用途和扩展密钥用途。
- 拒绝已过期或尚未生效的证书，以及不允许使用的密钥或签名算法。
- 将客户端证书身份绑定到正确的应用账户和授权上下文。

## 证书透明度日志

证书透明度提供可公开审计的已颁发证书日志。<sup>[[6]](#references)</sup> 在经授权的资产发现过程中，使用 crt.sh 搜索域名。<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL 文档 - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL 文档 - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 公钥基础设施证书和 CRL 配置文件](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - PKIX、PKCS 和 CMS 结构的文本编码](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL 文档 - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - 证书透明度 2.0 版](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - 证书搜索](https://crt.sh/)
- [8] [RFC 9525 - TLS 中的服务身份](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
