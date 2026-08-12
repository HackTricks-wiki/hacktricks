# Криптографія

{{#include ../banners/hacktricks-training.md}}

Цей розділ присвячений практичній криптографії для security testing і CTF: розпізнаванню поширених шаблонів, вибору відповідних інструментів і застосуванню відомих атак.

Щодо технік приховування даних усередині файлів дивіться розділ **Stego**.

## Як використовувати цей розділ

Почніть з визначення примітиву та його параметрів. Потім визначте, що контролює або спостерігає атакер, наприклад oracle, leaked value або повторне використання nonce, перш ніж обирати атаку.

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

Створіть ізольоване Python-середовище та встановіть поширені пакети. Документація PyCryptodome рекомендує встановлювати `pycryptodome` за допомогою `pip`; SageMath містить окремі інструкції зі встановлення для кожної підтримуваної платформи.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath часто корисний для алгебраїчних обчислень, обчислень у ґратках, RSA та еліптичних кривих.<sup>[[2]](#references)</sup>

## References

- [1] [Документація PyCryptodome - Встановлення](https://www.pycryptodome.org/src/installation)
- [2] [Документація SageMath - Посібник зі встановлення](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
