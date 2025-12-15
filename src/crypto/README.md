# Crypto

{{#include ../banners/hacktricks-training.md}}

Цей розділ зосереджений на **практичній криптографії для hacking/CTFs**: як швидко розпізнати типові шаблони, обрати потрібні інструменти та застосувати відомі атаки.

Якщо ви шукаєте приховування даних у файлах, переходьте до розділу **Stego**.

## How to use this section

Crypto-завдання вимагають швидкості: класифікуйте примітив, визначте, що ви контролюєте (oracle/leak/nonce reuse), а потім застосуйте відомий шаблон атаки.

### Робочий процес CTF
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Симетрична криптографія
{{#ref}}
symmetric/README.md
{{#endref}}

### Хеші, MAC та KDF
{{#ref}}
hashes/README.md
{{#endref}}

### Криптографія з відкритим ключем
{{#ref}}
public-key/README.md
{{#endref}}

### TLS та сертифікати
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto у malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Різне
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Швидке налаштування

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (часто необхідний для lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
