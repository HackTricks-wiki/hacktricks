# Криптографія

{{#include ../banners/hacktricks-training.md}}

Цей розділ присвячений **практичній криптографії для hacking/CTFs**: швидкому розпізнаванню поширених шаблонів, вибору правильних інструментів і застосуванню відомих атак.

Якщо ви шукаєте інформацію про приховування даних у файлах, перейдіть до розділу **Stego**.

## Як використовувати цей розділ

Crypto challenges винагороджують швидкість: класифікуйте примітив, визначте, що ви контролюєте (oracle/leak/повторне використання nonce), а потім застосуйте відомий шаблон атаки.

### Робочий процес CTF
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Симетрична криптографія
{{#ref}}
symmetric/README.md
{{#endref}}

### Хеші, MAC і KDF
{{#ref}}
hashes/README.md
{{#endref}}

### Криптографія з відкритим ключем
{{#ref}}
public-key/README.md
{{#endref}}

### TLS і сертифікати
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Криптографія у malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Різне
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Швидке налаштування

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Бібліотеки: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (часто необхідний для lattice/RSA/ECC): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
