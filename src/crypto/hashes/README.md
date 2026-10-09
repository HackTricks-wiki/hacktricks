# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Common CTF patterns

- "Signature" is actually `hash(secret || message)` → length extension.
- Unsalted password hashes → faster repeated cracking and precomputed lookup attacks.
- Confusing hash with MAC (hash != authentication).

## Hash length extension attack

### Technique

A length-extension attack may be possible when a server computes a "signature" like:

`sig = HASH(secret || message)`

and uses a Merkle-Damgård hash such as MD5, SHA-1, or SHA-256.

If you know:

- `message`
- `sig`
- hash function
- (or can brute-force) `len(secret)`

Then you can compute a valid signature for:

`message || padding || appended_data`

without knowing the secret.<sup>[[1]](#references)</sup>

### Important limitation: HMAC is not affected

Length-extension attacks apply to vulnerable prefix constructions such as `HASH(secret || message)`. They do not expose the HMAC construction (for example, HMAC-SHA256), which combines a key with separate inner and outer hash applications.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings for the HashPump length-extension tool<sup>[[7]](#references)</sup>

### Good explanation

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing and cracking

### First questions<sup>[[4]](#references)</sup>

- Is it **salted**? (look for `salt$hash` formats)
- Is it a **fast hash** (MD5/SHA1/SHA256) or a **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Do you have a **format hint** (hashcat mode / John format)?

### Practical workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Identify the hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. If unsalted and common: try online DBs and identification tooling from the crypto workflow section.
3. Otherwise crack:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Common mistakes you can exploit

- Same password reused across users → crack one, pivot.
- Truncated hashes / custom transforms → normalize and retry.
- Weak KDF parameters (e.g., low PBKDF2 iterations) → still crackable.

### Chosen-input bcrypt oracle with an appended secret

A callable helper that returns `bcrypt(user_input || secret)` can expose information about an appended secret if its bcrypt implementation silently truncates input after 72 **bytes**. A character-count limit before UTF-8 encoding does not enforce that byte limit: multibyte characters can fill the bcrypt input while leaving room for just a small prefix of the secret. Chosen inputs and their returned hashes may then allow offline checks of candidate suffix bytes. This requires control of the helper's input, knowledge of its exact transform and encoding, and an implementation that actually truncates; a callable helper or a bcrypt hash alone does not establish the chain. [pyca/bcrypt documents](https://github.com/pyca/bcrypt#maximum-password-length) that current `hashpw` raises an error for inputs over 72 bytes, whereas earlier behavior silently truncated them. Other wrappers may prehash or reject long inputs, so verify the installed implementation rather than assuming truncation.

Using a recovered secret against a different account also requires evidence that its exposed hash was generated with the **same** secret and transform, plus a separate credential or login path. A root-run hashing helper should be reviewed as an oracle only if the lower-privileged user can invoke it under the effective policy; passive host enumeration need not call it or submit chosen passwords.

## References

- [1] [SkullSecurity - Everything you need to know about hash length-extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - The Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings for HashPump](https://pypi.org/project/hashpumpy/)

{{#include ../../banners/hacktricks-training.md}}
