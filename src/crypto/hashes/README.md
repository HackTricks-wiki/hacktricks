# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Häufige CTF-Muster

- „Signature“ ist tatsächlich `hash(secret || message)` → Length Extension.
- Nicht gesalzte Passwort-Hashes → triviales Cracking / Lookup.
- Hash mit MAC verwechselt (Hash != Authentifizierung).

## Hash Length Extension Attack

### Technik

Dies lässt sich häufig ausnutzen, wenn ein Server eine „Signature“ wie diese berechnet:

`sig = HASH(secret || message)`

und einen Merkle–Damgård-Hash verwendet (klassische Beispiele: MD5, SHA-1, SHA-256).

Wenn du Folgendes kennst:

- `message`
- `sig`
- Hash-Funktion
- (oder per Brute-Force ermitteln kannst) `len(secret)`

Dann kannst du eine gültige Signature für Folgendes berechnen:

`message || padding || appended_data`

ohne das Secret zu kennen.<sup>[[1]](#references)</sup>

### Wichtige Einschränkung: HMAC ist nicht betroffen

Length Extension Angriffe gelten für Konstruktionen wie `HASH(secret || message)` bei Merkle–Damgård-Hashes. Sie gelten nicht für **HMAC** (z. B. HMAC-SHA256), das speziell entwickelt wurde, um diese Problemklasse zu vermeiden.<sup>[[1]](#references)</sup>

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

- Ist der Hash **gesalzen**? (Suche nach Formaten wie `salt$hash`.)
- Handelt es sich um einen **schnellen Hash** (MD5/SHA1/SHA256) oder eine **langsame KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Gibt es einen **Format-Hinweis** (hashcat mode / John format)?

### Praktischer Workflow

1. Identifiziere den Hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Wenn er nicht gesalzen und häufig verwendet wird: Probiere Online-Datenbanken und Tools zur Identifikation aus dem Abschnitt zum Crypto-Workflow.
3. Andernfalls führe Cracking durch:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Häufige Fehler, die du ausnutzen kannst

- Dasselbe Passwort wird für mehrere Benutzer wiederverwendet → einen Account cracken, pivotieren.
- Gekürzte Hashes / benutzerdefinierte Transformationen → normalisieren und erneut versuchen.
- Schwache KDF-Parameter (z. B. wenige PBKDF2-Iterationen) → weiterhin crackbar.

## Referenzen

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
