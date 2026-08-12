# Hash, MAC e KDF

{{#include ../../banners/hacktricks-training.md}}

## Pattern CTF comuni

- "Signature" è in realtà `hash(secret || message)` → length extension.
- Password hash senza salt → cracking ripetuto più veloce e attacchi di lookup precomputati.
- Confondere hash con MAC (hash != autenticazione).

## Attacco di hash length extension

### Tecnica

Un attacco di length extension può essere possibile quando un server calcola una "signature" come:

`sig = HASH(secret || message)`

e usa un hash Merkle-Damgård come MD5, SHA-1 o SHA-256.

Se conosci:

- `message`
- `sig`
- funzione hash
- (oppure puoi fare brute-force di) `len(secret)`

allora puoi calcolare una signature valida per:

`message || padding || appended_data`

senza conoscere il secret.<sup>[[1]](#references)</sup>

### Limitazione importante: HMAC non è interessato

Gli attacchi di length extension si applicano a costruzioni prefix vulnerabili come `HASH(secret || message)`. Non espongono la costruzione HMAC (ad esempio, HMAC-SHA256), che combina una key con applicazioni hash inner e outer separate.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings per il tool di length extension HashPump<sup>[[7]](#references)</sup>

### Buona spiegazione

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing e cracking

### Prime domande<sup>[[4]](#references)</sup>

- È **salted**? (cerca formati `salt$hash`)
- È un **fast hash** (MD5/SHA1/SHA256) o una **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Hai un **format hint** (hashcat mode / John format)?

### Workflow pratico<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifica l'hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Se non è salted ed è comune: prova online DB e tool di identificazione dalla sezione crypto workflow.
3. Altrimenti esegui il cracking:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errori comuni che puoi sfruttare

- La stessa password viene riutilizzata tra gli utenti → crackane una, fai pivot.
- Hash troncati / custom transforms → normalizza e riprova.
- Parametri KDF deboli (ad esempio, poche iterazioni PBKDF2) → ancora crackable.

## References

- [1] [SkullSecurity - Tutto ciò che devi sapere sugli attacchi di hash length-extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Il Message Authentication Code con hash keyed](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings for HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
