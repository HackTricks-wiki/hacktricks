# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Häufige CTF-Muster

- „Signature“ ist tatsächlich `hash(secret || message)` → length extension.
- Ungesaltete Passwort-Hashes → schnelleres wiederholtes Cracking und vorberechnete Lookup-Angriffe.
- Hash mit MAC verwechseln (Hash != Authentifizierung).

## Hash length extension attack

### Technik

Ein length-extension attack kann möglich sein, wenn ein Server eine „Signatur“ wie folgt berechnet:

`sig = HASH(secret || message)`

und einen Merkle-Damgård-Hash wie MD5, SHA-1 oder SHA-256 verwendet.

Wenn du Folgendes kennst:

- `message`
- `sig`
- Hashfunktion
- (oder durch Brute-Force ermitteln kannst) `len(secret)`

kannst du eine gültige Signatur für Folgendes berechnen:

`message || padding || appended_data`

ohne das Secret zu kennen.<sup>[[1]](#references)</sup>

### Wichtige Einschränkung: HMAC ist nicht betroffen

Length-extension attacks gelten für anfällige Prefix-Konstruktionen wie `HASH(secret || message)`. Sie legen die HMAC-Konstruktion nicht offen (zum Beispiel HMAC-SHA256), die einen Schlüssel mit getrennten inneren und äußeren Hash-Anwendungen kombiniert.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-Bindings für das HashPump length-extension tool<sup>[[7]](#references)</sup>

### Gute Erklärung

[Alles, was du über Hash length extension attacks wissen musst](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Passwort-Hashing und Cracking

### Erste Fragen<sup>[[4]](#references)</sup>

- Ist es **gesalzen**? (Achte auf Formate wie `salt$hash`.)
- Ist es ein **schneller Hash** (MD5/SHA1/SHA256) oder ein **langsamer KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Hast du einen **Format-Hinweis** (Hashcat-Modus / John-Format)?

### Praktischer Workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiziere den Hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Wenn er ungesalzen und verbreitet ist: Probiere Online-Datenbanken und Tools zur Identifizierung aus dem Abschnitt zum Crypto-Workflow.
3. Andernfalls führe Cracking durch:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Häufige Fehler, die du ausnutzen kannst

- Dasselbe Passwort wird von mehreren Benutzern wiederverwendet → einen knacken, pivotieren.
- Gekürzte Hashes / benutzerdefinierte Transformationen → normalisieren und erneut versuchen.
- Schwache KDF-Parameter (z. B. niedrige PBKDF2-Iterationszahl) → weiterhin knackbar.

## References

- [1] [SkullSecurity - Alles, was du über Hash length-extension attacks wissen musst](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Der Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat-Beispiel-Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper-Befehlszeilenoptionen](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python-Bindings für HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
