# TLS i certyfikaty

{{#include ../../banners/hacktricks-training.md}}

W tej sekcji omówiono inspekcję X.509, kodowania, konwersje oraz błędy walidacji istotne z punktu widzenia bezpieczeństwa.

## Parsowanie X.509

OpenSSL może wyświetlić zdekodowane pola certyfikatu, a `asn1parse` pokazuje bazową strukturę ASN.1.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

Sprawdź co najmniej:

- podmiot, wystawcę i Subject Alternative Name (SAN);
- key usage i extended key usage;
- basic constraints i ograniczenia długości ścieżki;
- czasy ważności `notBefore` i `notAfter`;
- parametry klucza publicznego i algorytm podpisu.

Podpisy oparte na przestarzałych algorytmach, takich jak MD5 lub SHA-1, są szczególnie istotnym znaleziskiem, choć dokładna akceptacja i wpływ zależą od walidatora i kontekstu zaufania.<sup>[[3]](#references)</sup>

RFC 5280 definiuje profil Internet X.509 oraz reguły przetwarzania rozszerzeń, takich jak SAN, key usage, name constraints i basic constraints.<sup>[[3]](#references)</sup>

## Kodowania i kontenery

- **Kodowanie tekstowe w stylu PEM:** dane Base64 między znacznikami `BEGIN` i `END`.
- **DER:** binarna reprezentacja Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** zwykle zawiera certyfikaty i łańcuch certyfikatów, ale nie klucze prywatne.
- **PKCS#12 (`.p12` lub `.pfx`):** może zawierać klucze prywatne, certyfikaty i certyfikaty pomocnicze.

RFC 7468 określa kodowania tekstowe używane dla struktur PKIX, PKCS i CMS; polecenie `pkcs12` w OpenSSL tworzy i parsuje pliki PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

Traktuj `out.pem` jako dane wrażliwe: o ile nie użyto opcji takich jak `-nokeys`, dane wyjściowe mogą zawierać materiał klucza prywatnego.<sup>[[5]](#references)</sup>

## Lista kontrolna przeglądu bezpieczeństwa

Podczas przeglądu walidatora lub decyzji o zaufaniu stosuj wymagania dotyczące przetwarzania certyfikatów określone w RFC 5280.<sup>[[3]](#references)</sup>

- Zweryfikuj cały łańcuch aż do jawnie zaufanego kotwicy; nie ufaj domyślnie certyfikatom głównym dostarczonym przez użytkownika.
- Sprawdź nazwę hosta lub tożsamość usługi względem wartości SAN.<sup>[[8]](#references)</sup>
- Egzekwuj ograniczenia podstawowe, ograniczenia nazw, przeznaczenie klucza oraz rozszerzone przeznaczenie klucza.
- Odrzucaj certyfikaty, które wygasły lub jeszcze nie są ważne, oraz niedozwolone algorytmy kluczy lub podpisów.
- Powiąż tożsamości certyfikatów klienta z właściwym kontem aplikacji i kontekstem autoryzacji.

## Dzienniki Certificate Transparency

Certificate Transparency udostępnia publicznie audytowalne dzienniki wystawionych certyfikatów.<sup>[[6]](#references)</sup> Podczas autoryzowanego rozpoznania zasobów wyszukaj domenę w crt.sh.<sup>[[7]](#references)</sup>

## References

- [1] [Dokumentacja OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Dokumentacja OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Infrastruktura klucza publicznego Internetu X.509: profil certyfikatów i list CRL](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Tekstowe kodowania struktur PKIX, PKCS i CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Dokumentacja OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency w wersji 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Wyszukiwanie certyfikatów](https://crt.sh/)
- [8] [RFC 9525 - Tożsamość usługi w TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
