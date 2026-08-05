# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Common CTF patterns

- Η "υπογραφή" είναι στην πραγματικότητα `hash(secret || message)` → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- Σύγχυση μεταξύ hash και MAC (hash != authentication).

## Hash length extension attack

### Technique

Μπορείτε συχνά να το εκμεταλλευτείτε αυτό αν ένας server υπολογίζει μια "υπογραφή" όπως:

`sig = HASH(secret || message)`

και χρησιμοποιεί ένα Merkle–Damgård hash (κλασικά παραδείγματα: MD5, SHA-1, SHA-256).

Αν γνωρίζετε:

- `message`
- `sig`
- hash function
- (ή μπορείτε να κάνετε brute-force) το `len(secret)`

Τότε μπορείτε να υπολογίσετε μια έγκυρη υπογραφή για:

`message || padding || appended_data`

χωρίς να γνωρίζετε το secret.<sup>[[1]](#references)</sup>

### Important limitation: HMAC is not affected

Οι length extension attacks εφαρμόζονται σε constructions όπως `HASH(secret || message)` για Merkle–Damgård hashes. Δεν εφαρμόζονται σε **HMAC** (π.χ. HMAC-SHA256), το οποίο είναι ειδικά σχεδιασμένο ώστε να αποφεύγει αυτή την κατηγορία προβλημάτων.<sup>[[1]](#references)</sup>

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

- Είναι **salted**; (αναζητήστε formats τύπου `salt$hash`)
- Είναι **fast hash** (MD5/SHA1/SHA256) ή **slow KDF** (bcrypt/scrypt/argon2/PBKDF2);
- Έχετε κάποιο **format hint** (hashcat mode / John format);

### Practical workflow

1. Αναγνωρίστε το hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Αν είναι unsalted και common: δοκιμάστε online DBs και identification tooling από την ενότητα crypto workflow.
3. Διαφορετικά κάντε crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Common mistakes you can exploit

- Ίδιο password reused μεταξύ χρηστών → κάντε crack ένα και pivot.
- Truncated hashes / custom transforms → κάντε normalize και δοκιμάστε ξανά.
- Weak KDF parameters (π.χ. χαμηλός αριθμός PBKDF2 iterations) → παραμένουν crackable.

## References

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
