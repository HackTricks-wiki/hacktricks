# TLS i sertifikati

{{#include ../../banners/hacktricks-training.md}}

Ovaj odeljak obuhvata inspekciju X.509, enkodiranja, konverzije i greške u validaciji relevantne za bezbednost.

## Parsiranje X.509

OpenSSL može da prikaže dekodirana polja sertifikata, dok `asn1parse` prikazuje osnovnu ASN.1 strukturu.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Pregledajte najmanje:

- subject, issuer i Subject Alternative Name (SAN);
- key usage i extended key usage;
- basic constraints i path-length constraints;
- vremena važenja `notBefore` i `notAfter`;
- parametre javnog ključa i algoritam potpisa.

Legacy potpisi, kao što su potpisi sertifikata zasnovani na MD5 ili SHA-1, predstavljaju posebno važne nalaze, iako tačno prihvatanje i uticaj zavise od validatora i konteksta poverenja.<sup>[[3]](#references)</sup>

RFC 5280 definiše Internet X.509 profil i pravila obrade ekstenzija kao što su SAN, key usage, name constraints i basic constraints.<sup>[[3]](#references)</sup>

## Kodiranja i kontejneri

- **PEM-style textual encoding:** Base64 podaci između `BEGIN` i `END` granica.
- **DER:** binarna reprezentacija Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** obično sadrži sertifikate i lanac sertifikata, ali ne i privatne ključeve.
- **PKCS#12 (`.p12` ili `.pfx`):** može sadržati privatne ključeve, sertifikate i prateće sertifikate.

RFC 7468 definiše tekstualna kodiranja koja se koriste za PKIX, PKCS i CMS strukture; OpenSSL-ova komanda `pkcs12` kreira i parsira PKCS#12 datoteke.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
Tretirajte `out.pem` kao osetljiv: osim ako se ne koriste opcije kao što je `-nokeys`, izlaz može sadržati materijal privatnog ključa.<sup>[[5]](#references)</sup>

## Security Review Checklist

Primenite zahteve za obradu sertifikata iz RFC 5280 prilikom pregleda validatora ili odluke o poverenju.<sup>[[3]](#references)</sup>

- Proverite kompletan lanac do eksplicitno pouzdane sidrene tačke; nemojte implicitno verovati root sertifikatima koje je dostavio korisnik.
- Potvrdite hostname ili identitet servisa u odnosu na SAN vrednosti.<sup>[[8]](#references)</sup>
- Primenite ograničenja osnovnih svojstava, ograničenja imena, upotrebu ključa i proširenu upotrebu ključa.
- Odbijte istekle ili još nevažeće sertifikate, kao i nedozvoljene algoritme ključa ili potpisa.
- Povežite identitete klijentskih sertifikata sa odgovarajućim nalogom aplikacije i kontekstom autorizacije.

## Certificate Transparency Logs

Certificate Transparency obezbeđuje javno proverljive logove izdatih sertifikata.<sup>[[6]](#references)</sup> Pretražite domen pomoću crt.sh tokom autorizovanog otkrivanja asseta.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL dokumentacija - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL dokumentacija - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Profil sertifikata i CRL-ova Internet X.509 infrastrukture javnih ključeva](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Tekstualna kodiranja PKIX, PKCS i CMS struktura](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL dokumentacija - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency verzija 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Pretraga sertifikata](https://crt.sh/)
- [8] [RFC 9525 - Identitet servisa u TLS-u](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
