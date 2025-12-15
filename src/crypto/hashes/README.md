# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Pattern comuni nei CTF

- "Signature" è in realtà `hash(secret || message)` → length extension.
- Hash di password non salati → trivial cracking / lookup.
- Confondere hash con MAC (hash != autenticazione).

## Hash length extension attack

### Tecnica

Spesso puoi sfruttare questo se un server calcola una "signature" come:

`sig = HASH(secret || message)`

e usa un hash Merkle–Damgård (esempi classici: MD5, SHA-1, SHA-256).

Se conosci:

- `message`
- `sig`
- funzione di hash
- (o puoi brute-force) `len(secret)`

Allora puoi calcolare una signature valida per:

`message || padding || appended_data`

senza conoscere il secret.

### Limitazione importante: HMAC non è vulnerabile

Gli attacchi di length extension si applicano a costruzioni come `HASH(secret || message)` per hash Merkle–Damgård. Non si applicano a **HMAC** (es. HMAC-SHA256), che è progettato specificamente per evitare questa classe di problemi.

### Strumenti

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Spiegazione utile

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Hashing delle password e cracking

### Prime domande

- È **salted**? (cerca formati `salt$hash`)
- È un **fast hash** (MD5/SHA1/SHA256) o un **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Hai un **format hint** (hashcat mode / John format)?

### Flusso di lavoro pratico

1. Identifica l'hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Se unsalted e comune: prova DB online e tooling di identificazione dalla sezione crypto workflow.
3. Altrimenti crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errori comuni che puoi sfruttare

- Stessa password riutilizzata tra utenti → crackane una, pivot.
- Hash troncati / trasformazioni custom → normalizza e riprova.
- Parametri KDF deboli (es. poche iterazioni PBKDF2) → ancora crackabile.

{{#include ../../banners/hacktricks-training.md}}
