# Криптографія

{{#include ../banners/hacktricks-training.md}}

У цьому розділі розглядається практична криптографія для тестування безпеки та CTF: розпізнавання поширених шаблонів, вибір відповідних інструментів і застосування відомих атак.

Техніки приховування даних у файлах описано в розділі **Stego**.

## Як користуватися цим розділом

Спочатку визначте криптографічний примітив і його параметри. Потім з’ясуйте, чим керує атакувальник або що він може спостерігати, наприклад оракул, значення, що потрапило в leak, або повторне використання nonce, перш ніж вибирати атаку.

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

### Криптографія у шкідливому ПЗ

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Різне

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Швидке налаштування

Створіть ізольоване середовище Python і встановіть поширені пакети. У документації PyCryptodome рекомендовано встановлювати `pycryptodome` за допомогою `pip`; SageMath містить окремі інструкції зі встановлення для кожної підтримуваної платформи.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath часто корисний для алгебраїчних обчислень, обчислень із ґратками, RSA та еліптичними кривими.<sup>[[2]](#references)</sup>

## References

- [1] [Документація PyCryptodome — встановлення](https://www.pycryptodome.org/src/installation)
- [2] [Документація SageMath — посібник зі встановлення](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
