# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Miundo ya kawaida ya CTF

- "Signature" kwa kweli ni `hash(secret || message)` → length extension.
- Password hashes zisizo na salt → cracking ya haraka zaidi na mashambulizi ya precomputed lookup.
- Kuchanganya hash na MAC (hash != authentication).

## Hash length extension attack

### Technique

Length-extension attack inaweza kuwezekana wakati server inakokotoa "signature" kama:

`sig = HASH(secret || message)`

na inatumia Merkle-Damgård hash kama MD5, SHA-1, au SHA-256.

Ikiwa unajua:

- `message`
- `sig`
- hash function
- (au unaweza kubrute-force) `len(secret)`

Basi unaweza kukokotoa signature halali ya:

`message || padding || appended_data`

bila kujua secret.<sup>[[1]](#references)</sup>

### Kizuizi muhimu: HMAC haiathiriwi

Length-extension attacks hutumika kwa vulnerable prefix constructions kama `HASH(secret || message)`. Hazifichui HMAC construction (kwa mfano, HMAC-SHA256), ambayo huunganisha key na matumizi tofauti ya inner na outer hash.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings za HashPump length-extension tool<sup>[[7]](#references)</sup>

### Maelezo mazuri

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing and cracking

### Maswali ya kwanza<sup>[[4]](#references)</sup>

- Je, ina **salt**? (tafuta formats za `salt$hash`)
- Je, ni **fast hash** (MD5/SHA1/SHA256) au **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Je, una **format hint** (hashcat mode / John format)?

### Practical workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Tambua hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Ikiwa haina salt na ni ya kawaida: jaribu online DBs na identification tooling kutoka crypto workflow section.
3. Vinginevyo crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Makosa ya kawaida unayoweza kutumia

- Password ileile imetumika tena na users → crack moja, pivot.
- Truncated hashes / custom transforms → normalize na ujaribu tena.
- Weak KDF parameters (kwa mfano, PBKDF2 iterations chache) → bado zinaweza ku-crackiwa.

## References

- [1] [SkullSecurity - Kila kitu unachohitaji kujua kuhusu hash length-extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings za HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
