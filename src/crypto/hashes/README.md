# Hash, MAC e KDF

{{#include ../../banners/hacktricks-training.md}}

## Pattern comuni nei CTF

- Una “signature” è in realtà `hash(secret || message)` → length extension.
- Hash delle password senza salt → cracking ripetuto più rapido e attacchi di ricerca precomputata.
- Confondere hash e MAC (hash != autenticazione).

## Attacco di estensione della lunghezza dell'hash

### Tecnica

Un attacco di length extension può essere possibile quando un server calcola una “signature” come:

`sig = HASH(secret || message)`

e usa un hash Merkle-Damgård come MD5, SHA-1 o SHA-256.

Se conosci:

- `message`
- `sig`
- la funzione hash
- (oppure puoi brute-force) `len(secret)`

puoi calcolare una signature valida per:

`message || padding || appended_data`

senza conoscere il secret.<sup>[[1]](#references)</sup>

### Limitazione importante: HMAC non è vulnerabile

Gli attacchi di length extension si applicano a costruzioni vulnerabili con prefisso, come `HASH(secret || message)`. Non compromettono la costruzione HMAC (ad esempio, HMAC-SHA256), che combina una chiave con applicazioni hash interne ed esterne separate.<sup>[[1]](#references)[[2]](#references)</sup>

### Strumenti

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), binding Python per lo strumento di length extension HashPump<sup>[[7]](#references)</sup>

### Una buona spiegazione

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing e cracking delle password

### Domande iniziali<sup>[[4]](#references)</sup>

- È **salted**? (cerca formati `salt$hash`)
- È un **fast hash** (MD5/SHA1/SHA256) o una **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Hai un **indizio sul formato** (modalità hashcat / formato John)?

### Workflow pratico<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifica l'hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Se non è salted ed è comune: prova i DB online e gli strumenti di identificazione della sezione sul workflow crypto.
3. Altrimenti, esegui il cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errori comuni che puoi sfruttare

- Stessa password riutilizzata da più utenti → crackane una e fai pivot.
- Hash troncati / trasformazioni custom → normalizza e riprova.
- Parametri KDF deboli (ad esempio, poche iterazioni PBKDF2) → sono comunque crackabili.

### Oracle bcrypt con input scelto e secret aggiunto

Un helper invocabile che restituisce `bcrypt(user_input || secret)` può esporre informazioni su un secret aggiunto se la sua implementazione di bcrypt tronca silenziosamente l'input dopo 72 **byte**. Un limite sul numero di caratteri applicato prima della codifica UTF-8 non impone quel limite in byte: i caratteri multibyte possono riempire l'input di bcrypt lasciando spazio solo per un piccolo prefisso del secret. Gli input scelti e gli hash restituiti possono quindi consentire verifiche offline di byte candidati del suffisso. Ciò richiede il controllo dell'input dell'helper, la conoscenza della sua trasformazione e codifica esatte e un'implementazione che tronchi davvero; il solo fatto che l'helper sia invocabile o che si disponga di un hash bcrypt non dimostra che questa catena sia possibile. [La documentazione di pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) specifica che `hashpw` nelle versioni attuali genera un errore per input superiori a 72 byte, mentre le versioni precedenti li troncavano silenziosamente. Altri wrapper potrebbero applicare un prehash o rifiutare input lunghi: verifica quindi l'implementazione installata invece di dare per scontato il troncamento.

Usare un secret recuperato contro un altro account richiede inoltre prove che il suo hash esposto sia stato generato con lo **stesso** secret e la stessa trasformazione, oltre a un percorso di autenticazione o di accesso separato. Un helper di hashing eseguito come root va considerato un oracle solo se l'utente con privilegi inferiori può invocarlo secondo la policy effettiva; l'enumerazione passiva dell'host non deve necessariamente chiamarlo né inviargli password scelte.

## References

- [1] [SkullSecurity - Tutto quello che devi sapere sugli attacchi di hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Codice di autenticazione dei messaggi basato su hash con chiave](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Scheda di riferimento sulla memorizzazione delle password](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - Hash di esempio](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Opzioni della riga di comando](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: binding Python `hashpumpy` per HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
