# TLS & Certificates

{{#include ../../banners/hacktricks-training.md}}

Ta sekcja dotyczy **parsowania X.509, formatów, konwersji i typowych błędów**.

## X.509: parsowanie, formaty & typowe błędy

### Szybkie parsowanie
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Przydatne pola do sprawdzenia:

- Subject / Issuer / SAN
- Zastosowanie klucza / EKU
- Basic Constraints (czy to CA?)
- Okres ważności (NotBefore/NotAfter)
- Algorytm podpisu (MD5? SHA1?)

### Formaty i konwersje

- PEM (Base64 z nagłówkami BEGIN/END)
- DER (binarny)
- PKCS#7 (`.p7b`) (łańcuch certyfikatów, bez klucza prywatnego)
- PKCS#12 (`.pfx/.p12`) (cert + klucz prywatny + łańcuch)

Konwersje:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Typowe wektory ataku

- Ufanie rootom dostarczonym przez użytkownika / brak walidacji łańcucha certyfikatów
- Słabe algorytmy podpisu (przestarzałe)
- Ograniczenia nazw / błędy parsowania SAN (zależne od implementacji)
- Problemy Confused deputy związane z błędnym powiązaniem uwierzytelniania certyfikatem klienta

### Dzienniki CT

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
