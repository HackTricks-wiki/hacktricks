# TLS і сертифікати

{{#include ../../banners/hacktricks-training.md}}

У цьому розділі розглядаються перевірка X.509, кодування, перетворення та помилки валідації, пов’язані з безпекою.

## Розбір X.509

OpenSSL може вивести декодовані поля сертифіката, тоді як `asn1parse` показує базову структуру ASN.1.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Перевірте щонайменше:

- subject, issuer і Subject Alternative Name (SAN);
- key usage і extended key usage;
- basic constraints і path-length constraints;
- час чинності `notBefore` і `notAfter`;
- параметри public key і signature algorithm.

Legacy signatures, такі як signatures сертифікатів на основі MD5 або SHA-1, є особливо важливими знахідками, хоча точне прийняття та вплив залежать від validator і trust context.<sup>[[3]](#references)</sup>

RFC 5280 визначає Internet X.509 profile і правила обробки таких extensions, як SAN, key usage, name constraints і basic constraints.<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM-style textual encoding:** Base64-дані між межами `BEGIN` і `END`.
- **DER:** бінарне представлення Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** зазвичай містить certificates і certificate chain, але не private keys.
- **PKCS#12 (`.p12` або `.pfx`):** може містити private keys, certificates і supporting certificates.

RFC 7468 визначає текстові encodings, що використовуються для структур PKIX, PKCS і CMS; команда OpenSSL `pkcs12` створює та аналізує файли PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
Ставтеся до `out.pem` як до конфіденційного файлу: якщо не використано такі параметри, як `-nokeys`, результат може містити матеріал приватного ключа.<sup>[[5]](#references)</sup>

## Security Review Checklist

Під час перевірки validator або рішення про довіру застосовуйте вимоги обробки сертифікатів, визначені в RFC 5280.<sup>[[3]](#references)</sup>

- Перевіряйте повний ланцюжок до явно довіреного anchor; не довіряйте кореневим сертифікатам, наданим користувачем, неявно.
- Підтверджуйте hostname або ідентичність service за значеннями SAN.<sup>[[8]](#references)</sup>
- Застосовуйте basic constraints, name constraints, key usage і extended key usage.
- Відхиляйте прострочені сертифікати або сертифікати, чинність яких ще не настала, а також заборонені алгоритми ключів або підпису.
- Пов’язуйте ідентичності client-certificate з правильним обліковим записом застосунку та контекстом авторизації.

## Certificate Transparency Logs

Certificate Transparency забезпечує публічно перевірювані журнали виданих сертифікатів.<sup>[[6]](#references)</sup> Під час авторизованого asset discovery здійснюйте пошук домену за допомогою crt.sh.<sup>[[7]](#references)</sup>

## References

- [1] [Документація OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Документація OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - профіль сертифікатів і CRL для інфраструктури відкритих ключів Internet X.509](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - текстові кодування структур PKIX, PKCS і CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Документація OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency версії 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - пошук сертифікатів](https://crt.sh/)
- [8] [RFC 9525 - ідентичність service у TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
