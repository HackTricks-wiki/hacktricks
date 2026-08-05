# Hashe, MAC i KDF-y

{{#include ../../banners/hacktricks-training.md}}

## Popularne wzorce CTF

- „Signature” to tak naprawdę `hash(secret || message)` → length extension.
- Niesolone hashe haseł → trywialne crackowanie / wyszukiwanie.
- Mylenie hasha z MAC (hash != authentication).

## Atak length extension dla hashy

### Technique

Często można to wykorzystać, jeśli serwer oblicza „signature” w sposób podobny do:

`sig = HASH(secret || message)`

i używa hasha Merkle–Damgård (klasyczne przykłady: MD5, SHA-1, SHA-256).

Jeśli znasz:

- `message`
- `sig`
- funkcję haszującą
- (lub możesz brute-force'ować) `len(secret)`

wtedy możesz obliczyć poprawny signature dla:

`message || padding || appended_data`

bez znajomości secret.<sup>[[1]](#references)</sup>

### Ważne ograniczenie: HMAC nie jest podatny

Ataki length extension dotyczą konstrukcji takich jak `HASH(secret || message)` dla hashy Merkle–Damgård. Nie dotyczą **HMAC** (np. HMAC-SHA256), który został zaprojektowany specjalnie w celu uniknięcia tej klasy problemów.<sup>[[1]](#references)</sup>

### Tools

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

## Haszowanie i crackowanie haseł

### Pierwsze pytania

- Czy jest **solony**? (szukaj formatów `salt$hash`)
- Czy jest to **szybki hash** (MD5/SHA1/SHA256), czy **wolny KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Czy masz **format hint** (tryb hashcat / format John)?

### Praktyczny workflow

1. Zidentyfikuj hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Jeśli hash jest niesolony i popularny: wypróbuj internetowe DB oraz narzędzia do identyfikacji z sekcji crypto workflow.
3. W przeciwnym razie crackuj:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Typowe błędy, które można wykorzystać

- To samo hasło używane przez wielu użytkowników → cracknij jedno i wykonaj pivot.
- Skrócone hashe / custom transforms → znormalizuj i spróbuj ponownie.
- Słabe parametry KDF (np. mała liczba iteracji PBKDF2) → nadal możliwe do crackowania.

## References

- [1] [Wszystko, co musisz wiedzieć o atakach length extension na hashe](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
