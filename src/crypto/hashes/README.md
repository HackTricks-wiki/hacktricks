# Hashes, MACs i KDFs

{{#include ../../banners/hacktricks-training.md}}

## Typowe wzorce CTF

- „Signature” to w rzeczywistości `hash(secret || message)` → length extension.
- Hashy haseł bez salt → szybsze wielokrotne crackowanie i ataki z użyciem precomputed lookup.
- Mylenie hash z MAC (hash != authentication).

## Atak length extension dla hashy

### Technika

Atak length extension może być możliwy, gdy serwer oblicza „signature” w rodzaju:

`sig = HASH(secret || message)`

i używa hash Merkle-Damgård, takiego jak MD5, SHA-1 lub SHA-256.

Jeśli znasz:

- `message`
- `sig`
- funkcję hash
- (lub możesz brute-force) `len(secret)`

wtedy możesz obliczyć poprawny signature dla:

`message || padding || appended_data`

bez znajomości secret.<sup>[[1]](#references)</sup>

### Ważne ograniczenie: HMAC nie jest podatny

Ataki length extension dotyczą podatnych konstrukcji prefix, takich jak `HASH(secret || message)`. Nie ujawniają konstrukcji HMAC (na przykład HMAC-SHA256), która łączy key z oddzielnymi wewnętrznymi i zewnętrznymi operacjami hash.<sup>[[1]](#references)[[2]](#references)</sup>

### Narzędzia

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings dla narzędzia HashPump do length extension<sup>[[7]](#references)</sup>

### Dobre wyjaśnienie

[Wszystko, co musisz wiedzieć o atakach hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashowanie i crackowanie haseł

### Pierwsze pytania<sup>[[4]](#references)</sup>

- Czy użyto **salt**? (szukaj formatów `salt$hash`)
- Czy jest to **fast hash** (MD5/SHA1/SHA256), czy **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Czy masz **format hint** (tryb hashcat / format John)?

### Praktyczny workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Zidentyfikuj hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Jeśli hash nie ma salt i jest popularny: wypróbuj online DB oraz narzędzia do identyfikacji z sekcji crypto workflow.
3. W przeciwnym razie crackuj:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Typowe błędy, które można wykorzystać

- To samo password jest używane przez wielu users → crack one, pivot.
- Obcięte hashe / custom transforms → normalizuj i spróbuj ponownie.
- Słabe parametry KDF (np. niska liczba iteracji PBKDF2) → nadal możliwe do crackowania.

## References

- [1] [SkullSecurity - Wszystko, co musisz wiedzieć o atakach hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Uwierzytelniający kod wiadomości oparty na kluczowanym hashu](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [Ściągawka OWASP dotycząca przechowywania haseł](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Przykładowe hashe Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opcje wiersza poleceń John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: wiązania Python dla HashPump — `hashpumpy`](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
