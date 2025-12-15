# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Gängige CTF-Muster

- "Signature" ist tatsächlich `hash(secret || message)` → length extension.
- Passwort-Hashes ohne Salt → trivial cracking / lookup.
- Hash mit MAC verwechseln (hash != authentication).

## Hash length extension attack

### Technik

Oft kann man das ausnutzen, wenn ein Server eine "Signature" berechnet wie:

`sig = HASH(secret || message)`

und einen Merkle–Damgård-Hash verwendet (klassische Beispiele: MD5, SHA-1, SHA-256).

Wenn du weißt:

- `message`
- `sig`
- hash function
- (oder per Brute-Force bestimmbar) `len(secret)`

Dann kannst du eine gültige Signatur für:

`message || padding || appended_data`

berechnen, ohne das secret zu kennen.

### Wichtige Einschränkung: HMAC ist nicht betroffen

Length extension attacks gelten für Konstruktionen wie `HASH(secret || message)` bei Merkle–Damgård-Hashes. Sie gelten nicht für **HMAC** (z.B. HMAC-SHA256), das speziell entwickelt wurde, um diese Problemklasse zu vermeiden.

### Tools

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Gute Erklärung

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Passwort-Hashing und Cracking

### Erste Fragen

- Ist es **salted**? (achte auf `salt$hash`-Formate)
- Ist es ein **fast hash** (MD5/SHA1/SHA256) oder ein **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Hast du einen **format hint** (hashcat mode / John format)?

### Praktische Vorgehensweise

1. Hash identifizieren:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Ist es unsalted und häufig: probiere Online-DBs und Identifikationstools aus dem Crypto-Workflow-Abschnitt.
3. Andernfalls cracken:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Häufige Fehler, die du ausnutzen kannst

- Gleiches Passwort bei mehreren Nutzern wiederverwendet → crack one, pivot.
- Abgeschnittene Hashes / benutzerdefinierte Transformationen → normalisieren und erneut versuchen.
- Schwache KDF-Parameter (z.B. geringe PBKDF2-Iterationen) → weiterhin crackbar.

{{#include ../../banners/hacktricks-training.md}}
