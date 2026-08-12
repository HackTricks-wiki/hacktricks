# TLS i certyfikaty

{{#include ../../banners/hacktricks-training.md}}

Ta sekcja obejmuje inspekcję X.509, kodowania, konwersje oraz błędy walidacji istotne z punktu widzenia bezpieczeństwa.

## Parsowanie X.509

OpenSSL może wyświetlić zdekodowane pola certyfikatu, podczas gdy `asn1parse` pokazuje podstawową strukturę ASN.1.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Przejrzyj co najmniej:

- subject, issuer oraz Subject Alternative Name (SAN);
- key usage i extended key usage;
- basic constraints oraz path-length constraints;
- czasy ważności `notBefore` i `notAfter`;
- parametry klucza publicznego oraz algorytm podpisu.

Szczególnie istotnymi ustaleniami są legacy signatures, takie jak podpisy certyfikatów oparte na MD5 lub SHA-1, chociaż dokładna akceptacja i wpływ zależą od walidatora oraz kontekstu zaufania.<sup>[[3]](#references)</sup>

RFC 5280 definiuje profil Internet X.509 oraz zasady przetwarzania rozszerzeń, takich jak SAN, key usage, name constraints i basic constraints.<sup>[[3]](#references)</sup>

## Kodowania i kontenery

- **Kodowanie tekstowe w stylu PEM:** dane Base64 pomiędzy granicami `BEGIN` i `END`.
- **DER:** binarna reprezentacja Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** zwykle zawiera certyfikaty oraz certificate chain, ale nie klucze prywatne.
- **PKCS#12 (`.p12` lub `.pfx`):** może zawierać klucze prywatne, certyfikaty oraz supporting certificates.

RFC 7468 określa kodowania tekstowe używane dla struktur PKIX, PKCS i CMS; polecenie OpenSSL `pkcs12` tworzy i analizuje pliki PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
Traktuj `out.pem` jako dane wrażliwe: jeśli nie zostaną użyte opcje takie jak `-nokeys`, dane wyjściowe mogą zawierać materiał klucza prywatnego.<sup>[[5]](#references)</sup>

## Lista kontrolna przeglądu bezpieczeństwa

Podczas przeglądu walidatora lub decyzji dotyczącej zaufania stosuj wymagania dotyczące przetwarzania certyfikatów określone w RFC 5280.<sup>[[3]](#references)</sup>

- Zweryfikuj kompletny łańcuch względem jawnie zaufanego kotwicy; nie ufaj domyślnie rootom dostarczonym przez użytkownika.
- Potwierdź nazwę hosta lub tożsamość usługi na podstawie wartości SAN.<sup>[[8]](#references)</sup>
- Wymuś stosowanie basic constraints, name constraints, key usage oraz extended key usage.
- Odrzucaj wygasłe lub jeszcze nieważne certyfikaty oraz niedozwolone algorytmy kluczy lub podpisów.
- Powiąż tożsamości certyfikatów klienta z właściwym kontem aplikacji i kontekstem autoryzacji.

## Certificate Transparency Logs

Certificate Transparency zapewnia publicznie audytowalne logi wydanych certyfikatów.<sup>[[6]](#references)</sup> Podczas autoryzowanego rozpoznawania zasobów wyszukuj domenę za pomocą crt.sh.<sup>[[7]](#references)</sup>

## References

- [1] [Dokumentacja OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Dokumentacja OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Profil certyfikatów i list CRL infrastruktury klucza publicznego Internetu X.509](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Tekstowe kodowania struktur PKIX, PKCS i CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Dokumentacja OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency w wersji 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Wyszukiwanie certyfikatów](https://crt.sh/)
- [8] [RFC 9525 - Tożsamość usługi w TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
