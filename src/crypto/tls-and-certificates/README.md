# TLS i sertifikati

{{#include ../../banners/hacktricks-training.md}}

Ovaj odeljak obrađuje pregled X.509 sertifikata, kodiranja, konverzije i bezbednosno relevantne greške pri validaciji.

## X.509 parsiranje

OpenSSL može da prikaže dekodirana polja sertifikata, dok `asn1parse` prikazuje osnovnu ASN.1 strukturu.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

Proverite najmanje:

- predmet, izdavaoca i Subject Alternative Name (SAN);
- upotrebu ključa i proširenu upotrebu ključa;
- osnovna ograničenja i ograničenja dužine putanje;
- vremena važenja `notBefore` i `notAfter`;
- parametre javnog ključa i algoritam potpisa.

Zastareli potpisi, kao što su potpisi sertifikata zasnovani na MD5 ili SHA-1, predstavljaju naročito važne nalaze, mada tačno prihvatanje i uticaj zavise od validatora i konteksta poverenja.<sup>[[3]](#references)</sup>

RFC 5280 definiše Internet X.509 profil i pravila obrade ekstenzija kao što su SAN, upotreba ključa, ograničenja imena i osnovna ograničenja.<sup>[[3]](#references)</sup>

## Encodings and Containers

- **Tekstualno kodiranje u PEM stilu:** Base64 podaci između granica `BEGIN` i `END`.
- **DER:** binarni prikaz Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** obično sadrži sertifikate i lanac sertifikata, ali ne i privatne ključeve.
- **PKCS#12 (`.p12` ili `.pfx`):** može sadržati privatne ključeve, sertifikate i pomoćne sertifikate.

RFC 7468 definiše tekstualna kodiranja koja se koriste za PKIX, PKCS i CMS strukture; OpenSSL-ova komanda `pkcs12` kreira i parsira PKCS#12 datoteke.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

Tretirajte `out.pem` kao osetljiv: osim ako se koriste opcije kao što je `-nokeys`, izlaz može da sadrži materijal privatnog ključa.<sup>[[5]](#references)</sup>

## Kontrolna lista za bezbednosnu proveru

Prilikom provere validatora ili odluke o poverenju primenite zahteve za obradu sertifikata iz RFC 5280.<sup>[[3]](#references)</sup>

- Proverite ceo lanac do eksplicitno pouzdanog sidra; nemojte podrazumevano verovati korenima koje dostavi korisnik.
- Proverite hostname ili identitet usluge prema vrednostima SAN-a.<sup>[[8]](#references)</sup>
- Sprovodite ograničenja osnovnih svojstava, ograničenja imena, upotrebu ključa i proširenu upotrebu ključa.
- Odbacite istekle sertifikate ili sertifikate koji još nisu važeći, kao i nedozvoljene algoritme ključa ili potpisa.
- Povežite identitete iz klijentskih sertifikata sa odgovarajućim nalozima aplikacije i kontekstom autorizacije.

## Certificate Transparency Logs

Certificate Transparency obezbeđuje javno proverljive evidencije izdatih sertifikata.<sup>[[6]](#references)</sup> Tokom ovlašćenog otkrivanja resursa pretražite domen pomoću crt.sh.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL dokumentacija - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL dokumentacija - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Profil infrastrukture javnih ključeva X.509 za Internet: sertifikati i CRL-ovi](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Tekstualna kodiranja struktura PKIX, PKCS i CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL dokumentacija - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency, verzija 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Pretraga sertifikata](https://crt.sh/)
- [8] [RFC 9525 - Identitet usluge u TLS-u](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
