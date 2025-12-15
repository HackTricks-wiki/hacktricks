# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Typowe wzorce CTF

- "Signature" jest w rzeczywistości `hash(secret || message)` → length extension.
- Hashe haseł bez soli → trywialne łamanie / wyszukiwanie.
- Mylą hash z MAC (hash != authentication).

## Hash length extension attack

### Technika

Często można to wykorzystać, jeśli serwer oblicza „signature” w postaci:

`sig = HASH(secret || message)`

i używa hashów Merkle–Damgård (klasyczne przykłady: MD5, SHA-1, SHA-256).

Jeśli znasz:

- `message`
- `sig`
- hash function
- (or can brute-force) `len(secret)`

Wtedy możesz obliczyć prawidłowy podpis dla:

`message || padding || appended_data`

bez znajomości sekretu.

### Ważne ograniczenie: HMAC nie jest podatne

Ataki length extension dotyczą konstrukcji takich jak `HASH(secret || message)` dla hashy Merkle–Damgård. Nie dotyczą **HMAC** (np. HMAC-SHA256), które zostało zaprojektowane specjalnie, aby zapobiegać tej klasie problemów.

### Narzędzia

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Dobre wyjaśnienie

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Haszowanie haseł i łamanie

### Pierwsze pytania

- Czy jest **zasolone**? (szukaj `salt$hash` formats)
- Czy to **szybki hash** (MD5/SHA1/SHA256) czy **wolny KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Czy masz **wskazówkę formatu** (hashcat mode / John format)?

### Praktyczny workflow

1. Zidentyfikuj hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Jeśli brak soli i powszechny: spróbuj baz online i narzędzi identyfikacyjnych z sekcji crypto workflow.
3. W przeciwnym razie złam:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Typowe błędy, które możesz wykorzystać

- To samo hasło użyte przez wielu użytkowników → crack one, pivot.
- Obcięte hashe / niestandardowe transformacje → znormalizuj i spróbuj ponownie.
- Słabe parametry KDF (np. mała liczba iteracji PBKDF2) → nadal możliwe do złamania.

{{#include ../../banners/hacktricks-training.md}}
