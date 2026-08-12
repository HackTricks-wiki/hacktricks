# TLS और Certificates

{{#include ../../banners/hacktricks-training.md}}

यह section X.509 inspection, encodings, conversions और security-relevant validation mistakes को cover करता है।

## X.509 Parsing

OpenSSL certificate के decoded fields को print कर सकता है, जबकि `asn1parse` underlying ASN.1 structure दिखाता है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
कम से कम इनकी समीक्षा करें:

- subject, issuer, और Subject Alternative Name (SAN);
- key usage और extended key usage;
- basic constraints और path-length constraints;
- `notBefore` और `notAfter` validity times;
- public-key parameters और signature algorithm।

MD5- या SHA-1-आधारित certificate signatures जैसे Legacy signatures विशेष रूप से महत्वपूर्ण findings हैं, हालांकि उनका सटीक acceptance और impact validator और trust context पर निर्भर करता है।<sup>[[3]](#references)</sup>

RFC 5280 Internet X.509 profile और SAN, key usage, name constraints, तथा basic constraints जैसे extensions के processing rules को परिभाषित करता है।<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM-style textual encoding:** `BEGIN` और `END` boundaries के बीच Base64 data।
- **DER:** binary Distinguished Encoding Rules representation।
- **PKCS#7/CMS (`.p7b`):** आमतौर पर certificates और certificate chain को carry करता है, लेकिन private keys को नहीं।
- **PKCS#12 (`.p12` या `.pfx`):** private keys, certificates, और supporting certificates को carry कर सकता है।

RFC 7468 PKIX, PKCS, और CMS structures के लिए उपयोग की जाने वाली textual encodings को specify करता है; OpenSSL का `pkcs12` command PKCS#12 files को create और parse करता है।<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
`out.pem` को संवेदनशील मानें: जब तक `-nokeys` जैसे विकल्पों का उपयोग न किया जाए, आउटपुट में private-key सामग्री हो सकती है।<sup>[[5]](#references)</sup>

## Security Review Checklist

किसी validator या trust decision की समीक्षा करते समय RFC 5280 में दी गई certificate-processing requirements लागू करें।<sup>[[3]](#references)</sup>

- किसी स्पष्ट रूप से trusted anchor तक complete chain सत्यापित करें; user-supplied roots पर implicit रूप से trust न करें।
- SAN values के विरुद्ध hostname या service identity की पुष्टि करें।<sup>[[8]](#references)</sup>
- basic constraints, name constraints, key usage और extended key usage लागू करें।
- expired या not-yet-valid certificates तथा disallowed key या signature algorithms को reject करें।
- client-certificate identities को सही application account और authorization context से bind करें।

## Certificate Transparency Logs

Certificate Transparency जारी किए गए certificates के publicly auditable logs उपलब्ध कराता है।<sup>[[6]](#references)</sup> authorized asset discovery के दौरान crt.sh से किसी domain को search करें।<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL दस्तावेज़ - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL दस्तावेज़ - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate और CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - PKIX, PKCS और CMS Structures की Textual Encodings](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL दस्तावेज़ - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Certificate Search](https://crt.sh/)
- [8] [RFC 9525 - TLS में Service Identity](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
