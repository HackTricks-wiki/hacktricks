# TLS en Sertifikate

{{#include ../../banners/hacktricks-training.md}}

Hierdie afdeling dek X.509-inspeksie, enkoderings, omskakelings en sekuriteitsrelevante valideringsfoute.

## X.509-ontleding

OpenSSL kan ’n sertifikaat se gedekodeerde velde druk, terwyl `asn1parse` die onderliggende ASN.1-struktuur wys.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

Hersien ten minste:

- die onderwerp, uitreiker en Subject Alternative Name (SAN);
- sleutelgebruik en uitgebreide sleutelgebruik;
- basiese beperkings en padlengtebeperkings;
- die geldigheidstye `notBefore` en `notAfter`;
- die publieke-sleutelparameters en handtekeningalgoritme.

Verouderde handtekeninge, soos sertifikaathandtekeninge wat op MD5 of SHA-1 gebaseer is, is besonder belangrike bevindings, hoewel die presiese aanvaarding en impak van die valideerder en vertrouenskonteks afhang.<sup>[[3]](#references)</sup>

RFC 5280 definieer die Internet X.509-profiel en die verwerkingsreëls vir uitbreidings soos SAN, sleutelgebruik, naambeperkings en basiese beperkings.<sup>[[3]](#references)</sup>

## Enkoderinge en houers

- **PEM-styl teksenkodering:** Base64-data tussen `BEGIN`- en `END`-grensmerkers.
- **DER:** die binêre Distinguished Encoding Rules-voorstelling.
- **PKCS#7/CMS (`.p7b`):** bevat gewoonlik sertifikate en 'n sertifikaatketting, maar nie private sleutels nie.
- **PKCS#12 (`.p12` of `.pfx`):** kan private sleutels, sertifikate en ondersteunende sertifikate bevat.

RFC 7468 spesifiseer die teksenkoderinge wat vir PKIX-, PKCS- en CMS-strukture gebruik word; OpenSSL se `pkcs12`-opdrag skep en ontleed PKCS#12-lêers.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

Behandel `out.pem` as sensitief: tensy opsies soos `-nokeys` gebruik word, kan die uitvoer private-sleutelmateriaal bevat.<sup>[[5]](#references)</sup>

## Kontrolelys vir sekuriteitsoorsig

Pas die sertifikaatverwerkingsvereistes in RFC 5280 toe wanneer ’n valideerder of vertrouensbesluit nagegaan word.<sup>[[3]](#references)</sup>

- Verifieer die volledige ketting tot by ’n uitdruklik vertroude anker; moenie wortels wat deur gebruikers verskaf is, implisiet vertrou nie.
- Bevestig die gasheernaam of diensidentiteit aan die hand van SAN-waardes.<sup>[[8]](#references)</sup>
- Dwing basiese beperkings, naambeperkings, sleutelgebruik en uitgebreide sleutelgebruik af.
- Verwerp sertifikate wat verval het of nog nie geldig is nie, asook sleutel- of handtekeningalgoritmes wat nie toegelaat word nie.
- Koppel kliëntsertifikaat-identiteite aan die korrekte toepassingrekening en magtigingskonteks.

## Certificate Transparency-logboeke

Certificate Transparency verskaf publiek ouditbare logboeke van uitgereikte sertifikate.<sup>[[6]](#references)</sup> Soek na ’n domein met crt.sh tydens gemagtigde bate-ontdekking.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL-dokumentasie - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL-dokumentasie - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 Public Key Infrastructure-sertifikaat- en CRL-profiel](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Tekskoderings van PKIX-, PKCS- en CMS-strukture](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL-dokumentasie - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency-weergawe 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Sertifikaatsoektog](https://crt.sh/)
- [8] [RFC 9525 - Diensidentiteit in TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
