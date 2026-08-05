# Hash, MAC e KDF

{{#include ../../banners/hacktricks-training.md}}

## Pattern comuni nei CTF

- "Signature" è in realtà `hash(secret || message)` → length extension.
- Password hash senza salt → cracking / lookup banali.
- Confondere hash e MAC (hash != autenticazione).

## Attacco di length extension degli hash

### Tecnica

Spesso puoi sfruttare questa situazione se un server calcola una "signature" come:

`sig = HASH(secret || message)`

e usa un hash Merkle–Damgård (esempi classici: MD5, SHA-1, SHA-256).

Se conosci:

- `message`
- `sig`
- la funzione di hash
- (oppure puoi fare brute-force di) `len(secret)`

allora puoi calcolare una signature valida per:

`message || padding || appended_data`

senza conoscere il secret.<sup>[[1]](#references)</sup>

### Limitazione importante: HMAC non è interessato

Gli attacchi di length extension si applicano a costruzioni come `HASH(secret || message)` per gli hash Merkle–Damgård. Non si applicano a **HMAC** (ad esempio, HMAC-SHA256), che è stato progettato specificamente per evitare questo tipo di problema.<sup>[[1]](#references)</sup>

### Tool

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Una buona spiegazione

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing e cracking

### Prime domande

- È **salted**? (cerca formati `salt$hash`)
- È un **fast hash** (MD5/SHA1/SHA256) o una **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Hai un **format hint** (modalità hashcat / formato John)?

### Workflow pratico

1. Identifica l'hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Se non è salted ed è comune: prova i DB online e gli strumenti di identificazione dalla sezione crypto workflow.
3. Altrimenti esegui il cracking:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errori comuni che puoi sfruttare

- La stessa password viene riutilizzata tra più utenti → crackane una e fai pivot.
- Hash troncati / trasformazioni custom → normalizza e riprova.
- Parametri KDF deboli (ad esempio, poche iterazioni PBKDF2) → ancora crackabili.

## Riferimenti

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
