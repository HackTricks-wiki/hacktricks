# TLS na Vyeti

{{#include ../../banners/hacktricks-training.md}}

Sehemu hii inahusu ukaguzi wa X.509, mifumo ya usimbaji, ubadilishaji na makosa ya uthibitishaji yanayohusu usalama.

## Uchambuzi wa X.509

OpenSSL inaweza kuonyesha sehemu zilizofasiriwa za cheti, huku `asn1parse` ikionyesha muundo wa msingi wa ASN.1.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

Kagua angalau:

- subject, issuer, na Subject Alternative Name (SAN);
- matumizi ya key na extended key usage;
- basic constraints na path-length constraints;
- muda wa uhalali wa `notBefore` na `notAfter`;
- vigezo vya public key na algorithm ya saini.

Saini za zamani kama saini za vyeti zinazotumia MD5 au SHA-1 ni matokeo muhimu hasa, ingawa kukubaliwa kwake na athari zake halisi hutegemea validator na muktadha wa uaminifu.<sup>[[3]](#references)</sup>

RFC 5280 hufafanua wasifu wa Internet X.509 na sheria za uchakataji wa extensions kama SAN, key usage, name constraints, na basic constraints.<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM-style textual encoding:** data ya Base64 kati ya mipaka ya `BEGIN` na `END`.
- **DER:** uwakilishi wa binary wa Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** kwa kawaida huwa na vyeti na certificate chain, lakini si private keys.
- **PKCS#12 (`.p12` au `.pfx`):** inaweza kuwa na private keys, vyeti, na vyeti saidizi.

RFC 7468 hubainisha textual encodings zinazotumiwa na miundo ya PKIX, PKCS, na CMS; amri ya `pkcs12` ya OpenSSL huunda na kuchanganua faili za PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

Ichukulie `out.pem` kuwa nyeti: isipokuwa utumie chaguo kama `-nokeys`, matokeo yanaweza kuwa na taarifa za private key.<sup>[[5]](#references)</sup>

## Orodha ya Ukaguzi wa Usalama

Tumia mahitaji ya uchakataji wa vyeti katika RFC 5280 unapokagua validator au uamuzi wa uaminifu.<sup>[[3]](#references)</sup>

- Thibitisha mnyororo mzima hadi kwenye anchor inayoaminika waziwazi; usiamini kiotomatiki roots zinazotolewa na mtumiaji.
- Linganisha hostname au utambulisho wa huduma na thamani za SAN.<sup>[[8]](#references)</sup>
- Tekeleza masharti ya msingi, vizuizi vya majina, matumizi ya key, na matumizi yaliyoongezwa ya key.
- Kataa vyeti vilivyoisha muda wake au ambavyo muda wake bado haujaanza, pamoja na algorithms zisizoruhusiwa za key au signature.
- Unganisha utambulisho wa vyeti vya mteja na akaunti sahihi ya programu pamoja na muktadha wa idhini.

## Rekodi za Certificate Transparency

Certificate Transparency hutoa rekodi za vyeti vilivyotolewa ambazo zinaweza kukaguliwa na umma.<sup>[[6]](#references)</sup> Tafuta domain kwa kutumia crt.sh wakati wa ugunduzi wa rasilimali ulioidhinishwa.<sup>[[7]](#references)</sup>

## References

- [1] [Nyaraka za OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Nyaraka za OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Wasifu wa Miundombinu ya Ufunguo wa Umma ya X.509 ya Intaneti kwa Vyeti na CRL](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Miundo ya PKIX, PKCS na CMS katika Usimbaji wa Maandishi](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Nyaraka za OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Toleo la 2.0 la Certificate Transparency](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Utafutaji wa Vyeti](https://crt.sh/)
- [8] [RFC 9525 - Utambulisho wa Huduma katika TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
