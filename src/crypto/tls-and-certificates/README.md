# TLS और Certificates

{{#include ../../banners/hacktricks-training.md}}

इस section में X.509 inspection, encodings, conversions और security से जुड़ी validation की गलतियों को शामिल किया गया है।

## X.509 Parsing

OpenSSL किसी certificate के decoded fields प्रिंट कर सकता है, जबकि `asn1parse` अंतर्निहित ASN.1 structure दिखाता है।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

कम-से-कम इनकी जाँच करें:

- subject, issuer और Subject Alternative Name (SAN);
- key usage और extended key usage;
- basic constraints और path-length constraints;
- `notBefore` और `notAfter` validity times;
- public-key parameters और signature algorithm।

MD5 या SHA-1 पर आधारित certificate signatures जैसे legacy signatures विशेष रूप से महत्वपूर्ण findings हैं, हालाँकि validator और trust context के आधार पर उनकी स्वीकृति और प्रभाव अलग-अलग हो सकते हैं।<sup>[[3]](#references)</sup>

RFC 5280, Internet X.509 profile और SAN, key usage, name constraints तथा basic constraints जैसे extensions के processing rules परिभाषित करता है।<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM-style textual encoding:** `BEGIN` और `END` boundaries के बीच Base64 data।
- **DER:** binary Distinguished Encoding Rules representation।
- **PKCS#7/CMS (`.p7b`):** आम तौर पर certificates और certificate chain रखता है, लेकिन private keys नहीं।
- **PKCS#12 (`.p12` या `.pfx`):** private keys, certificates और supporting certificates रख सकता है।

RFC 7468, PKIX, PKCS और CMS structures के लिए उपयोग होने वाली textual encodings निर्दिष्ट करता है; OpenSSL का `pkcs12` command, PKCS#12 files बनाता और parse करता है।<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

`out.pem` को संवेदनशील मानें: `-nokeys` जैसे विकल्पों का उपयोग न करने पर, आउटपुट में private-key सामग्री हो सकती है।<sup>[[5]](#references)</sup>

## Security Review Checklist

किसी validator या trust decision की समीक्षा करते समय RFC 5280 में दी गई certificate-processing requirements लागू करें।<sup>[[3]](#references)</sup>

- स्पष्ट रूप से trusted anchor तक पूरी chain सत्यापित करें; user-supplied roots पर स्वतः भरोसा न करें।
- SAN values के आधार पर hostname या service identity की पुष्टि करें।<sup>[[8]](#references)</sup>
- basic constraints, name constraints, key usage और extended key usage लागू करें।
- expired या अभी तक valid न हुए certificates और अस्वीकृत key या signature algorithms को अस्वीकार करें।
- client-certificate identities को सही application account और authorization context से जोड़ें।

## Certificate Transparency Logs

Certificate Transparency, जारी किए गए certificates के publicly auditable logs उपलब्ध कराता है।<sup>[[6]](#references)</sup> अधिकृत asset discovery के दौरान crt.sh से किसी domain को खोजें।<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL documentation - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL documentation - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate और CRL प्रोफ़ाइल](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - PKIX, PKCS और CMS संरचनाओं की पाठ्य encoding](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL documentation - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency संस्करण 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Certificate खोज](https://crt.sh/)
- [8] [RFC 9525 - TLS में Service Identity](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
