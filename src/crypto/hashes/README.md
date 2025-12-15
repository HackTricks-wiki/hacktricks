# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Common CTF patterns

- "Signature" is actually `hash(secret || message)` → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- Confusing hash with MAC (hash != authentication).

## Hash length extension attack

### Technique

You can often exploit this if a server computes a "signature" like:

`sig = HASH(secret || message)`

and uses a Merkle–Damgård hash (classic examples: MD5, SHA-1, SHA-256).

If you know:

- `message`
- `sig`
- hash function
- (or can brute-force) `len(secret)`

Then you can compute a valid signature for:

`message || padding || appended_data`

without knowing the secret.

### Important limitation: HMAC is not affected

Length extension attacks apply to constructions like `HASH(secret || message)` for Merkle–Damgård hashes. They do not apply to **HMAC** (e.g., HMAC-SHA256), which is specifically designed to avoid this class of problem.

### Tools

- hash_extender:
  {{#ref}}
  https://github.com/iagox86/hash_extender
  {{#endref}}
- hashpump:
  {{#ref}}
  https://github.com/bwall/HashPump
  {{#endref}}

### Good explanation

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### First questions

- Is it **salted**? (look for `salt$hash` formats)
- Is it a **fast hash** (MD5/SHA1/SHA256) or a **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Do you have a **format hint** (hashcat mode / John format)?

### Practical workflow

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

{{#include ../../banners/hacktricks-training.md}}
