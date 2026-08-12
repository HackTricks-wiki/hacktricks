# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Algemene CTF-patrone

- "Signature" is eintlik `hash(secret || message)` → length extension.
- Ongesoute wagwoordhashes → vinniger herhaalde cracking en voorafberekende lookup-aanvalle.
- Hash word met MAC verwar (hash != authentication).

## Hash length extension attack

### Tegniek

'n Length-extension-aanval kan moontlik wees wanneer 'n server 'n "signature" soos die volgende bereken:

`sig = HASH(secret || message)`

en 'n Merkle-Damgård-hash soos MD5, SHA-1 of SHA-256 gebruik.

As jy die volgende ken:

- `message`
- `sig`
- hash-funksie
- (of `len(secret)` kan brute-force)

Dan kan jy 'n geldige signature vir die volgende bereken:

`message || padding || appended_data`

sonder om die secret te ken.<sup>[[1]](#references)</sup>

### Belangrike beperking: HMAC word nie geraak nie

Length-extension-aanvalle is van toepassing op kwesbare prefix-konstruksies soos `HASH(secret || message)`. Hulle stel nie die HMAC-konstruksie (byvoorbeeld HMAC-SHA256) bloot nie, wat 'n key met afsonderlike inner- en outer-hash-toepassings kombineer.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-bindings vir die HashPump length-extension-tool<sup>[[7]](#references)</sup>

### Goeie verduideliking

[Alles wat jy oor hash length extension attacks moet weet](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Wagwoord-hashing en cracking

### Eerste vrae<sup>[[4]](#references)</sup>

- Is dit **gesout**? (soek na `salt$hash`-formate)
- Is dit 'n **vinnige hash** (MD5/SHA1/SHA256) of 'n **stadige KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Het jy 'n **formaatwenk** (hashcat-modus / John-formaat)?

### Praktiese workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiseer die hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. As dit ongesout en algemeen is: probeer aanlyn databasisse en identifikasie-tooling uit die crypto-workflow-afdeling.
3. Andersins, crack dit:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Algemene foute wat jy kan uitbuit

- Dieselfde wagwoord word oor gebruikers hergebruik → crack een, pivot.
- Afgekapte hashes / custom transforms → normaliseer en probeer weer.
- Swak KDF-parameters (bv. lae PBKDF2-iterations) → steeds crackbaar.

## References

- [1] [SkullSecurity - Alles wat jy oor hash length-extension-aanvalle moet weet](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Die Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Cheat Sheet vir wagwoordberging](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat-voorbeeldhashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper-opdragreëlopsies](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python-bindings vir HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
