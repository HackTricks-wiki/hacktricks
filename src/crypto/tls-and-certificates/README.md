# TLS i certyfikaty

{{#include ../../banners/hacktricks-training.md}}


Ten obszar dotyczy **parsowania X.509, formatów, konwersji i typowych błędów**.

## X.509: parsowanie, formaty i typowe błędy

### Szybkie parsowanie
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Przydatne pola do sprawdzenia:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (czy jest CA?)
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
### Typowe kąty ataku

- Zaufanie do rootów dostarczonych przez użytkownika / brak walidacji łańcucha
- Słabe algorytmy podpisu (legacy)
- Ograniczenia nazw / błędy parsowania SAN (zależne od implementacji)
- Problemy typu confused deputy związane z nieprawidłowym powiązaniem uwierzytelniania za pomocą certyfikatu klienta

### Logi CT

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
