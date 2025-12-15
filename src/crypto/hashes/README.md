# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Česti CTF obrasci

- "Signature" je zapravo `hash(secret || message)` → length extension.
- Nezasoljeni hashovi lozinki → trivijalno cracking / pretraga.
- Mešanje hasha i MAC-a (hash != authentication).

## Hash length extension attack

### Tehnika

Ovo često možete iskoristiti ako server izračunava "signature" kao:

`sig = HASH(secret || message)`

i koristi Merkle–Damgård hash (klasični primeri: MD5, SHA-1, SHA-256).

Ako znate:

- `message`
- `sig`
- hash funkciju
- (ili možete bruteforce-ovati) `len(secret)`

Tada možete izračunati važeći signature za:

`message || padding || appended_data`

bez poznavanja tajne.

### Važno ograničenje: HMAC nije pogođen

Length extension attacks se primenjuju na konstrukcije poput `HASH(secret || message)` za Merkle–Damgård hasheve. Ne primenjuju se na **HMAC** (npr. HMAC-SHA256), koji je posebno dizajniran da izbegne ovu klasu problema.

### Alati

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Dobar članak

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Hashiranje lozinki i probijanje

### Prva pitanja

- Da li je **salted**? (pogledajte formate `salt$hash`)
- Da li je to **brzi hash** (MD5/SHA1/SHA256) ili **spori KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Imate li **naznaku formata** (hashcat mode / John format)?

### Praktični tok rada

1. Identifikujte hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Ako je nezasoljen i čest: pokušajte online DBs i alate za identifikaciju iz sekcije crypto workflow.
3. U suprotnom crack-ujte:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Uobičajene greške koje možete iskoristiti

- Ista lozinka korišćena kod više korisnika → crack one, pivot.
- Skraćeni hashovi / prilagođene transformacije → normalizujte i pokušajte ponovo.
- Slabi KDF parametri (npr. mali broj PBKDF2 iteracija) → i dalje mogu biti probijeni.

{{#include ../../banners/hacktricks-training.md}}
