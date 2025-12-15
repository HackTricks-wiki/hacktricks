# TLS & сертифікати

{{#include ../../banners/hacktricks-training.md}}

Цей розділ присвячений **розбору X.509, форматам, конвертаціям та поширеним помилкам**.

## X.509: розбір, формати та поширені помилки

### Швидкий розбір
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Корисні поля для перевірки:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (чи є це CA?)
- Проміжок дії (NotBefore/NotAfter)
- Алгоритм підпису (MD5? SHA1?)

### Формати та конвертація

- PEM (Base64 з заголовками BEGIN/END)
- DER (бінарний)
- PKCS#7 (`.p7b`) (ланцюжок сертифікатів, без приватного ключа)
- PKCS#12 (`.pfx/.p12`) (сертифікат + приватний ключ + ланцюжок)

Перетворення:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Типові вектори атак

- Довіра до кореневих кореневих сертифікатів, наданих користувачем / відсутня валідація ланцюга
- Слабкі алгоритми підпису (застарілі)
- Обмеження імен / помилки парсингу SAN (залежить від реалізації)
- Confused deputy issues with client-certificate authentication misbinding

### CT logs

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
