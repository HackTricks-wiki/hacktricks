# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Συνηθισμένα μοτίβα CTF

- "Signature" στην πραγματικότητα είναι `hash(secret || message)` → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- Σύγχυση του hash με το MAC (hash != authentication).

## Hash length extension attack

### Τεχνική

Μπορείς συχνά να εκμεταλλευτείς αυτό αν ένας server υπολογίζει μια "signature" όπως:

`sig = HASH(secret || message)`

και χρησιμοποιεί ένα Merkle–Damgård hash (κλασικά παραδείγματα: MD5, SHA-1, SHA-256).

Αν γνωρίζεις:

- `message`
- `sig`
- hash function
- (ή μπορείς να brute-force) `len(secret)`

Τότε μπορείς να υπολογίσεις μια έγκυρη υπογραφή για:

`message || padding || appended_data`

χωρίς να γνωρίζεις το secret.

### Important limitation: HMAC is not affected

Length extension attacks apply to constructions like `HASH(secret || message)` for Merkle–Damgård hashes. They do not apply to **HMAC** (e.g., HMAC-SHA256), which is specifically designed to avoid this class of problem.

### Εργαλεία

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Καλή εξήγηση

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### Πρώτες ερωτήσεις

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

### Συνηθισμένα λάθη που μπορείς να εκμεταλλευτείς

- Same password reused across users → crack one, pivot.
- Truncated hashes / custom transforms → normalize and retry.
- Weak KDF parameters (e.g., low PBKDF2 iterations) → still crackable.

{{#include ../../banners/hacktricks-training.md}}
