# TLS і сертифікати

{{#include ../../banners/hacktricks-training.md}}


Цей розділ присвячений **аналізу X.509, форматам, конвертаціям і поширеним помилкам**.

## X.509: аналіз, формати та поширені помилки

### Швидкий аналіз
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Корисні поля для перевірки:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (чи є це CA?)
- Період дії (NotBefore/NotAfter)
- Алгоритм підпису (MD5? SHA1?)

### Формати та конвертація

- PEM (Base64 із заголовками BEGIN/END)
- DER (бінарний)
- PKCS#7 (`.p7b`) (ланцюжок сертифікатів, без приватного ключа)
- PKCS#12 (`.pfx/.p12`) (сертифікат + приватний ключ + ланцюжок)

Конвертація:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Поширені наступальні вектори

- Довіра до кореневих сертифікатів, наданих користувачем / відсутність перевірки ланцюжка
- Слабкі алгоритми підпису (legacy)
- Обмеження імен / помилки парсингу SAN (залежать від реалізації)
- Проблеми confused deputy через неправильне прив’язування автентифікації за клієнтським сертифікатом

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
