# TLS i certyfikaty

{{#include ../../banners/hacktricks-training.md}}

Ta sekcja dotyczy **X.509: parsowanie, formaty, konwersje i typowe błędy**.

## X.509: parsowanie, formaty i typowe błędy

### Szybkie parsowanie
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Przydatne pola do sprawdzenia:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (czy to CA?)
- Okres ważności (NotBefore/NotAfter)
- Algorytm podpisu (MD5? SHA1?)

### Formaty i konwersja

- PEM (Base64 z nagłówkami BEGIN/END)
- DER (binarny)
- PKCS#7 (`.p7b`) (łańcuch certyfikatów, bez klucza prywatnego)
- PKCS#12 (`.pfx/.p12`) (certyfikat + klucz prywatny + łańcuch)

Konwersje:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Powszechne wektory ataku

- Ufanie rootom dostarczonym przez użytkownika / brak walidacji łańcucha
- Słabe algorytmy podpisu (przestarzałe)
- Ograniczenia nazw / błędy parsowania SAN (specyficzne dla implementacji)
- Problemy typu Confused deputy związane z błędnym powiązaniem uwierzytelniania client-certificate

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
