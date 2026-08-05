# Хеші, MAC і KDF

{{#include ../../banners/hacktricks-training.md}}

## Поширені шаблони CTF

- "Signature" насправді є `hash(secret || message)` → length extension.
- Хеші паролів без salt → тривіальний cracking / пошук у lookup-таблицях.
- Плутання hash із MAC (hash != authentication).

## Атака розширення довжини хешу

### Technique

Цим часто можна скористатися, якщо сервер обчислює "signature" на кшталт:

`sig = HASH(secret || message)`

і використовує хеш Merkle–Damgård (класичні приклади: MD5, SHA-1, SHA-256).

Якщо ви знаєте:

- `message`
- `sig`
- hash function
- (або можете brute-force) `len(secret)`

тоді можна обчислити дійсний signature для:

`message || padding || appended_data`

не знаючи secret.<sup>[[1]](#references)</sup>

### Важливе обмеження: HMAC не вразливий

Атаки розширення довжини застосовуються до конструкцій на кшталт `HASH(secret || message)` для хешів Merkle–Damgård. Вони не застосовуються до **HMAC** (наприклад, HMAC-SHA256), який спеціально розроблений для захисту від цього класу проблем.<sup>[[1]](#references)</sup>

### Tools

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Хороше пояснення

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Хешування та cracking паролів

### Перші запитання

- Чи використовується **salt**? (шукайте формати `salt$hash`)
- Це **швидкий hash** (MD5/SHA1/SHA256) чи **повільний KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Чи маєте ви **підказку щодо формату** (режим hashcat / формат John)?

### Практичний workflow

1. Визначте hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Якщо hash не має salt і є поширеним: спробуйте online DB та інструменти ідентифікації з розділу crypto workflow.
3. В іншому разі виконайте cracking:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Поширені помилки, які можна використати

- Повторне використання одного пароля різними користувачами → crack одного, pivot.
- Обрізані хеші / custom transforms → нормалізуйте та повторіть спробу.
- Слабкі параметри KDF (наприклад, мала кількість ітерацій PBKDF2) → усе ще піддаються cracking.

## References

- [1] [Все, що потрібно знати про атаки розширення довжини хешу](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
