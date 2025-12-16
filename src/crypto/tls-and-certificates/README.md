# TLS & Сертифікати

{{#include ../../banners/hacktricks-training.md}}

Цей розділ присвячений **розбору X.509, форматів, перетворень та поширених помилок**.

## X.509: розбір, формати & поширені помилки

### Швидкий розбір
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Корисні поля для перевірки:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (чи це CA?)
- Термін дії (NotBefore/NotAfter)
- Алгоритм підпису (MD5? SHA1?)

### Формати та конвертація

- PEM (Base64 з заголовками BEGIN/END)
- DER (бінарний)
- PKCS#7 (`.p7b`) (ланцюг сертифікатів, без приватного ключа)
- PKCS#12 (`.pfx/.p12`) (сертифікат + приватний ключ + ланцюг)

Конвертації:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Поширені вектори атак

- Довіра кореневим сертифікатам, наданим користувачем / відсутня перевірка ланцюга
- Слабкі алгоритми підпису (застарілі)
- Обмеження імен / помилки парсингу SAN (специфічні для реалізації)
- Проблеми Confused deputy через misbinding автентифікації клієнтських сертифікатів

### Журнали CT

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
