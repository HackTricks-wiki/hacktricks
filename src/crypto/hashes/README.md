# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Συνηθισμένα CTF patterns

- Το "Signature" είναι στην πραγματικότητα `hash(secret || message)` → length extension.
- Unsalted password hashes → ταχύτερο repeated cracking και precomputed lookup attacks.
- Σύγχυση μεταξύ hash και MAC (hash != authentication).

## Hash length extension attack

### Technique

Ένα length-extension attack μπορεί να είναι εφικτό όταν ένας server υπολογίζει ένα "signature" όπως:

`sig = HASH(secret || message)`

και χρησιμοποιεί ένα Merkle-Damgård hash όπως τα MD5, SHA-1 ή SHA-256.

Αν γνωρίζεις:

- `message`
- `sig`
- τη hash function
- (ή μπορείς να κάνεις brute-force) το `len(secret)`

τότε μπορείς να υπολογίσεις ένα έγκυρο signature για:

`message || padding || appended_data`

χωρίς να γνωρίζεις το secret.<sup>[[1]](#references)</sup>

### Σημαντικός περιορισμός: το HMAC δεν επηρεάζεται

Τα length-extension attacks εφαρμόζονται σε ευάλωτες prefix constructions όπως `HASH(secret || message)`. Δεν εκθέτουν την HMAC construction (για παράδειγμα, HMAC-SHA256), η οποία συνδυάζει ένα key με ξεχωριστές inner και outer hash εφαρμογές.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings για το HashPump length-extension tool<sup>[[7]](#references)</sup>

### Καλή εξήγηση

[Όλα όσα χρειάζεται να γνωρίζεις για τα hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing και cracking

### Πρώτες ερωτήσεις<sup>[[4]](#references)</sup>

- Είναι **salted**; (αναζήτησε formats τύπου `salt$hash`)
- Είναι **fast hash** (MD5/SHA1/SHA256) ή **slow KDF** (bcrypt/scrypt/argon2/PBKDF2);
- Έχεις κάποιο **format hint** (hashcat mode / John format);

### Practical workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Εντόπισε το hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Αν είναι unsalted και common: δοκίμασε online DBs και identification tooling από την ενότητα crypto workflow.
3. Διαφορετικά, κάνε crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Συνηθισμένα λάθη που μπορείς να εκμεταλλευτείς

- Το ίδιο password επαναχρησιμοποιείται από διαφορετικούς users → κάνε crack σε έναν και κάνε pivot.
- Truncated hashes / custom transforms → κάνε normalize και retry.
- Weak KDF parameters (π.χ. χαμηλές PBKDF2 iterations) → παραμένουν crackable.

## References

- [1] [SkullSecurity - Όλα όσα χρειάζεται να γνωρίζεις για τα hash length-extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Ο Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Cheat Sheet για την αποθήκευση passwords](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - επιλογές command line](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings για το HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
