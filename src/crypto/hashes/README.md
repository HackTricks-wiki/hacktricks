# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Common CTF patterns

- "Signature" est en fait `hash(secret || message)` → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- Confusing hash with MAC (hash != authentication).

## Hash length extension attack

### Technique

Vous pouvez souvent exploiter cela si un serveur calcule une "signature" comme :

`sig = HASH(secret || message)`

et utilise un hash de type Merkle–Damgård (exemples classiques : MD5, SHA-1, SHA-256).

Si vous connaissez :

- `message`
- `sig`
- hash function
- (or can brute-force) `len(secret)`

Alors vous pouvez calculer une signature valide pour :

`message || padding || appended_data`

sans connaître le secret.

### Limite importante : HMAC n'est pas affecté

Les length extension attacks s'appliquent aux constructions comme `HASH(secret || message)` pour les Merkle–Damgård hashes. Elles ne s'appliquent pas à **HMAC** (e.g., HMAC-SHA256), qui est spécifiquement conçu pour éviter cette classe de problèmes.

### Outils

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Bonne explication

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### Premières questions

- Is it **salted**? (look for `salt$hash` formats)
- Is it a **fast hash** (MD5/SHA1/SHA256) or a **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Do you have a **format hint** (hashcat mode / John format)?

### Workflow pratique

1. Identifier le hash :
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. If unsalted and common: try online DBs and identification tooling from the crypto workflow section.
3. Otherwise crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erreurs courantes exploitables

- Same password reused across users → crack one, pivot.
- Truncated hashes / custom transforms → normalize and retry.
- Weak KDF parameters (e.g., low PBKDF2 iterations) → still crackable.

{{#include ../../banners/hacktricks-training.md}}
