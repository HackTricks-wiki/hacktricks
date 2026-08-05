# Heševi, MAC-ovi i KDF-ovi

{{#include ../../banners/hacktricks-training.md}}

## Uobičajeni CTF obrasci

- „Signature“ je zapravo `hash(secret || message)` → proširenje dužine.
- Heševi lozinki bez salt-a → trivijalno crackovanje / pretraga.
- Mešanje heša i MAC-a (hash != authentication).

## Napad proširenja dužine heša

### Tehnika

Ovo često možete da iskoristite ako server računa „signature“ poput:

`sig = HASH(secret || message)`

i koristi Merkle–Damgård heš (klasični primeri: MD5, SHA-1, SHA-256).

Ako znate:

- `message`
- `sig`
- hash function
- (ili možete brute-force-ovati) `len(secret)`

onda možete izračunati validan signature za:

`message || padding || appended_data`

bez poznavanja secret-a.<sup>[[1]](#references)</sup>

### Važno ograničenje: HMAC nije pogođen

Napadi proširenja dužine primenjuju se na konstrukcije poput `HASH(secret || message)` za Merkle–Damgård heševe. Ne primenjuju se na **HMAC** (npr. HMAC-SHA256), koji je posebno dizajniran da izbegne ovu klasu problema.<sup>[[1]](#references)</sup>

### Alati

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Dobro objašnjenje

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Hešovanje i crackovanje lozinki

### Prva pitanja

- Da li je **salt-ovan**? (potražite formate `salt$hash`)
- Da li je u pitanju **brzi heš** (MD5/SHA1/SHA256) ili **spori KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Da li imate **format hint** (hashcat mode / John format)?

### Praktični workflow

1. Identifikujte heš:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Ako nema salt i heš je uobičajen: pokušajte sa online DB-ovima i alatima za identifikaciju iz crypto workflow sekcije.
3. U suprotnom ga crack-ujte:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Uobičajene greške koje možete iskoristiti

- Ista lozinka se koristi kod više korisnika → crack-ujte jednu, pa napravite pivot.
- Skraćeni heševi / custom transforms → normalizujte ih i pokušajte ponovo.
- Slabi KDF parametri (npr. mali broj PBKDF2 iteracija) → i dalje mogu da se crack-uju.

## Reference

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
