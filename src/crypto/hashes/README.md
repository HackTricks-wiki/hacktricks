# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Mifumo ya kawaida ya CTF

- "Signature" kwa hakika ni `hash(secret || message)` → length extension.
- Password hashes zisizo na salt → cracking / lookup rahisi.
- Kuchanganya hash na MAC (hash != authentication).

## Hash length extension attack

### Technique

Mara nyingi unaweza kutumia hili ikiwa server inakokotoa "signature" kama:

`sig = HASH(secret || message)`

na inatumia Merkle–Damgård hash (mifano ya kawaida: MD5, SHA-1, SHA-256).

Ikiwa unajua:

- `message`
- `sig`
- hash function
- (au unaweza kubrute-force) `len(secret)`

Basi unaweza kukokotoa signature halali kwa:

`message || padding || appended_data`

bila kujua secret.<sup>[[1]](#references)</sup>

### Limitation muhimu: HMAC haiathiriki

Length extension attacks hutumika kwa constructions kama `HASH(secret || message)` za Merkle–Damgård hashes. Hazitumiki kwa **HMAC** (kwa mfano, HMAC-SHA256), ambayo iliundwa mahsusi kuzuia aina hii ya tatizo.<sup>[[1]](#references)</sup>

### Tools

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Maelezo mazuri

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing na cracking

### Maswali ya kwanza

- Je, ina **salt**? (tafuta formats za `salt$hash`)
- Je, ni **fast hash** (MD5/SHA1/SHA256) au **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Je, una **format hint** (hashcat mode / John format)?

### Practical workflow

1. Tambua hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Ikiwa haina salt na ni ya kawaida: jaribu online DBs na identification tooling kutoka crypto workflow section.
3. Vinginevyo crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Makosa ya kawaida unayoweza kutumia

- Password ileile inatumiwa tena na users → crack moja, pivot.
- Hashes zilizokatwa / custom transforms → normalize na ujaribu tena.
- Weak KDF parameters (kwa mfano, PBKDF2 iterations chache) → bado zinaweza ku-crackiwa.

## References

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
