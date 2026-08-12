# Hash-evi, MAC-ovi i KDF-ovi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni CTF obrasci

- „Potpis“ je zapravo `hash(secret || message)` → length extension.
- Hash-evi lozinki bez salt-a → brže ponovljeno crackovanje i napadi pretraživanjem unapred izračunatih tabela.
- Mešanje hash-a sa MAC-om (hash != autentifikacija).

## Napad produženja dužine hash-a

### Tehnika

length-extension attack može biti moguć kada server računa „potpis“ poput:

`sig = HASH(secret || message)`

i koristi Merkle-Damgård hash kao što su MD5, SHA-1 ili SHA-256.

Ako znaš:

- `message`
- `sig`
- hash funkciju
- (ili možeš brute-force-ovati) `len(secret)`

onda možeš izračunati validan potpis za:

`message || padding || appended_data`

bez poznavanja secret-a.<sup>[[1]](#references)</sup>

### Važno ograničenje: HMAC nije pogođen

length-extension attacks se primenjuju na ranjive prefix konstrukcije kao što je `HASH(secret || message)`. One ne otkrivaju HMAC konstrukciju (na primer, HMAC-SHA256), koja kombinuje ključ sa odvojenim unutrašnjim i spoljašnjim primenama hash-a.<sup>[[1]](#references)[[2]](#references)</sup>

### Alati

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings za HashPump length-extension alat<sup>[[7]](#references)</sup>

### Dobro objašnjenje

[Sve što treba da znaš o length-extension napadima na hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashovanje i crackovanje lozinki

### Prva pitanja<sup>[[4]](#references)</sup>

- Da li koristi **salt**? (potraži formate `salt$hash`)
- Da li je u pitanju **brz hash** (MD5/SHA1/SHA256) ili **spor KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Da li imaš **naznaku formata** (hashcat mode / John format)?

### Praktični workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifikuj hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Ako nema salt i hash je uobičajen: isprobaj online DB-ove i alate za identifikaciju iz odeljka o crypto workflow-u.
3. U suprotnom crackuj:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Uobičajene greške koje možeš da iskoristiš

- Ista lozinka se ponovo koristi kod više korisnika → crackuj jednu, pa uradi pivot.
- Skraćeni hash-evi / prilagođene transformacije → normalizuj i pokušaj ponovo.
- Slabi KDF parametri (npr. mali broj PBKDF2 iteracija) → i dalje mogu da se crackuju.

## References

- [1] [SkullSecurity - Sve što treba da znaš o length-extension napadima na hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Kod autentifikacije poruka zasnovan na ključanom hash-u](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Cheat Sheet za čuvanje lozinki](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat primeri hash-eva](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper opcije komandne linije](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings za HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
