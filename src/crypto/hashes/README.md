# Хеші, MAC і KDF

{{#include ../../banners/hacktricks-training.md}}

## Поширені CTF-патерни

- «Підпис» насправді є `hash(secret || message)` → length extension.
- Хеші паролів без salt → швидший повторний cracking і атаки з попередньо обчисленими таблицями.
- Плутанина між hash і MAC (hash != authentication).

## Атака length extension для hash

### Техніка

Length-extension attack може бути можливою, коли сервер обчислює «підпис» на кшталт:

`sig = HASH(secret || message)`

і використовує hash Merkle-Damgård, наприклад MD5, SHA-1 або SHA-256.

Якщо вам відомі:

- `message`
- `sig`
- hash function
- (або ви можете brute-force) `len(secret)`

Тоді можна обчислити дійсний підпис для:

`message || padding || appended_data`

не знаючи secret.<sup>[[1]](#references)</sup>

### Важливе обмеження: HMAC не вразливий

Length-extension attacks застосовуються до вразливих prefix constructions, таких як `HASH(secret || message)`. Вони не розкривають HMAC construction (наприклад, HMAC-SHA256), яка поєднує key з окремими inner і outer hash operations.<sup>[[1]](#references)[[2]](#references)</sup>

### Інструменти

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings для HashPump length-extension tool<sup>[[7]](#references)</sup>

### Хороше пояснення

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Хешування та cracking паролів

### Перші запитання<sup>[[4]](#references)</sup>

- Чи використовується **salt**? (шукайте формати `salt$hash`)
- Це **fast hash** (MD5/SHA1/SHA256) чи **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Чи маєте ви **format hint** (hashcat mode / John format)?

### Практичний workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Визначте hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Якщо hash без salt і поширений: спробуйте online DBs та identification tooling із crypto workflow section.
3. В іншому разі виконайте cracking:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Поширені помилки, які можна використати

- Той самий пароль повторно використовується різними користувачами → зламайте один і виконайте pivot.
- Обрізані hashes / custom transforms → нормалізуйте й повторіть спробу.
- Слабкі KDF parameters (наприклад, мала кількість PBKDF2 iterations) → усе ще піддаються cracking.

## References

- [1] [SkullSecurity - Усе, що потрібно знати про hash length-extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Пам’ятка зі зберігання паролів](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - приклади hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - параметри командного рядка](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings для HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
