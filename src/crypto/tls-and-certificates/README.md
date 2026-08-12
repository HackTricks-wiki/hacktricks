# TLS na Certificates

{{#include ../../banners/hacktricks-training.md}}

Sehemu hii inahusu ukaguzi wa X.509, encodings, conversions, na makosa ya validation yanayohusiana na usalama.

## Uchambuzi wa X.509

OpenSSL inaweza kuchapisha fields zilizodecode za certificate, huku `asn1parse` ikionyesha muundo wa msingi wa ASN.1.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Kagua angalau:

- `subject`, `issuer`, na Subject Alternative Name (SAN);
- key usage na extended key usage;
- basic constraints na path-length constraints;
- nyakati za uhalali za `notBefore` na `notAfter`;
- vigezo vya public key na signature algorithm.

Legacy signatures kama saini za certificate zinazotumia MD5 au SHA-1 ni findings muhimu hasa, ingawa acceptance na impact halisi hutegemea validator na trust context.<sup>[[3]](#references)</sup>

RFC 5280 inafafanua Internet X.509 profile na kanuni za kuchakata extensions kama SAN, key usage, name constraints, na basic constraints.<sup>[[3]](#references)</sup>

## Usimbaji na Containers

- **PEM-style textual encoding:** Data ya Base64 kati ya mipaka ya `BEGIN` na `END`.
- **DER:** Uwakilishi wa binary wa Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** Kwa kawaida hubeba certificates na certificate chain, lakini si private keys.
- **PKCS#12 (`.p12` au `.pfx`):** Inaweza kubeba private keys, certificates, na supporting certificates.

RFC 7468 inabainisha textual encodings zinazotumiwa na miundo ya PKIX, PKCS, na CMS; amri ya OpenSSL ya `pkcs12` huunda na kuchanganua files za PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
Chukulia `out.pem` kuwa nyeti: isipokuwa chaguo kama `-nokeys` zitumike, matokeo yanaweza kuwa na taarifa za private key.<sup>[[5]](#references)</sup>

## Security Review Checklist

Tumia mahitaji ya uchakataji wa certificate katika RFC 5280 unapokagua validator au uamuzi wa trust.<sup>[[3]](#references)</sup>

- Thibitisha chain kamili hadi kwenye trust anchor iliyoaminika waziwazi; usiamini roots zinazotolewa na mtumiaji moja kwa moja.
- Thibitisha hostname au service identity dhidi ya thamani za SAN.<sup>[[8]](#references)</sup>
- Tekeleza basic constraints, name constraints, key usage, na extended key usage.
- Kataa certificates zilizo-expire au ambazo muda wake wa uhalali bado haujaanza, pamoja na key au signature algorithms zisizoruhusiwa.
- Husisha identities za client-certificate na account sahihi ya application pamoja na muktadha wa authorization.

## Certificate Transparency Logs

Certificate Transparency hutoa logs zinazoweza kukaguliwa hadharani za certificates zilizotolewa.<sup>[[6]](#references)</sup> Tafuta domain kwa kutumia crt.sh wakati wa authorized asset discovery.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL documentation - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL documentation - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Textual Encodings of PKIX, PKCS, and CMS Structures](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL documentation - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Certificate Search](https://crt.sh/)
- [8] [RFC 9525 - Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
