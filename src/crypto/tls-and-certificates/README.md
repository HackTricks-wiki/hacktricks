# TLS und Zertifikate

{{#include ../../banners/hacktricks-training.md}}

Dieser Abschnitt behandelt die Inspektion von X.509, Encodings, Konvertierungen und sicherheitsrelevante Validierungsfehler.

## X.509-Analyse

OpenSSL kann die decodierten Felder eines Zertifikats ausgeben, während `asn1parse` die zugrunde liegende ASN.1-Struktur anzeigt.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Überprüfe mindestens:

- den Subject, Issuer und den Subject Alternative Name (SAN);
- die Key Usage und Extended Key Usage;
- die Basic Constraints und Path-Length Constraints;
- die Gültigkeitszeiten `notBefore` und `notAfter`;
- die Parameter des Public Key und den Signaturalgorithmus.

Legacy-Signaturen wie auf MD5 oder SHA-1 basierende Zertifikatssignaturen sind besonders wichtige Befunde, obwohl die genaue Akzeptanz und Auswirkung vom Validator und dem Trust-Kontext abhängen.<sup>[[3]](#references)</sup>

RFC 5280 definiert das Internet-X.509-Profil und die Verarbeitungsregeln für Erweiterungen wie SAN, Key Usage, Name Constraints und Basic Constraints.<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM-style textual encoding:** Base64-Daten zwischen `BEGIN`- und `END`-Begrenzungen.
- **DER:** die binäre Darstellung nach den Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** enthält üblicherweise Zertifikate und eine Zertifikatskette, aber keine Private Keys.
- **PKCS#12 (`.p12` oder `.pfx`):** kann Private Keys, Zertifikate und unterstützende Zertifikate enthalten.

RFC 7468 spezifiziert die textuellen Encodings für PKIX-, PKCS- und CMS-Strukturen; OpenSSLs `pkcs12`-Befehl erstellt und verarbeitet PKCS#12-Dateien.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
Behandle `out.pem` als vertraulich: Sofern keine Optionen wie `-nokeys` verwendet werden, kann die Ausgabe Material privater Schlüssel enthalten.<sup>[[5]](#references)</sup>

## Checkliste für die Sicherheitsüberprüfung

Wende bei der Überprüfung eines Validators oder einer Vertrauensentscheidung die Anforderungen zur Zertifikatsverarbeitung aus RFC 5280 an.<sup>[[3]](#references)</sup>

- Überprüfe die vollständige Kette bis zu einem ausdrücklich vertrauenswürdigen Anker; vertraue nicht implizit auf vom Benutzer bereitgestellte Root-Zertifikate.
- Bestätige den Hostnamen oder die Service-Identität anhand der SAN-Werte.<sup>[[8]](#references)</sup>
- Erzwinge die Prüfung von Basic Constraints, Name Constraints, Key Usage und Extended Key Usage.
- Lehne abgelaufene oder noch nicht gültige Zertifikate sowie nicht zulässige Schlüssel- oder Signaturalgorithmen ab.
- Verknüpfe Client-Zertifikatidentitäten mit dem korrekten Anwendungskonto und Autorisierungskontext.

## Certificate-Transparency-Logs

Certificate Transparency stellt öffentlich überprüfbare Logs ausgestellter Zertifikate bereit.<sup>[[6]](#references)</sup> Suche während der autorisierten Asset Discovery mit crt.sh nach einer Domain.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL-Dokumentation - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL-Dokumentation - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Profil der Internet X.509 Public Key Infrastructure für Zertifikate und CRLs](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Textuelle Kodierungen von PKIX-, PKCS- und CMS-Strukturen](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL-Dokumentation - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Zertifikatssuche](https://crt.sh/)
- [8] [RFC 9525 - Service-Identität in TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
