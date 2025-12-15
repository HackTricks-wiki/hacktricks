# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Поширені шаблони CTF

- "Signature" насправді `hash(secret || message)` → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- Плутати hash із MAC (hash != authentication).

## Hash length extension attack

### Техніка

Ви часто можете скористатися цим, якщо сервер обчислює "signature" так:

`sig = HASH(secret || message)`

і використовує Merkle–Damgård hash (класичні приклади: MD5, SHA-1, SHA-256).

Якщо ви знаєте:

- `message`
- `sig`
- hash function
- (or can brute-force) `len(secret)`

Тоді ви можете обчислити валідний signature для:

`message || padding || appended_data`

не знаючи секрету.

### Важливе обмеження: HMAC не зачіпається

Length extension attacks застосовні до конструкцій типу `HASH(secret || message)` для Merkle–Damgård hashes. Вони не застосовуються до **HMAC** (наприклад, HMAC-SHA256), який спеціально спроектований, щоб уникнути цього класу проблем.

### Інструменти

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Детальне пояснення

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### Початкові питання

- Чи є воно **salted**? (шукайте формати `salt$hash`)
- Це **fast hash** (MD5/SHA1/SHA256) чи **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Чи маєте ви підказку щодо **format** (hashcat mode / John format)?

### Практичний робочий процес

1. Ідентифікуйте hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Якщо unsalted і поширений: спробуйте онлайн DBs та інструменти ідентифікації з розділу crypto workflow.
3. Інакше crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Поширені помилки, якими можна скористатися

- Same password reused across users → crack one, pivot.
- Truncated hashes / custom transforms → normalize and retry.
- Weak KDF parameters (e.g., low PBKDF2 iterations) → still crackable.

{{#include ../../banners/hacktricks-training.md}}
