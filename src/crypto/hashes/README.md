# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Schemi comuni dei CTF

- La "firma" è in realtà `hash(secret || message)` → length extension.
- Hash di password senza salt → cracking ripetuto più rapido e attacchi con lookup precomputati.
- Confondere hash e MAC (hash != autenticazione).

## Ricerche di hash MD5 con input scelto

Questi esempi Python cercano due diversi schemi di output: un suffisso MD5 scelto e un valore MD5 che inizia con `0e` seguito solo da cifre. Il secondo schema è rilevante quando un'applicazione confronta stringhe numeriche in modo permissivo; consulta il comportamento specifico di PHP e le avvertenze sulle versioni in [confronti permissivi in PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force del suffisso dell'hash MD5

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Generazione di hash MD5 0e per confronti permissivi

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Tecnica

Un attacco di length extension può essere possibile quando un server calcola una "firma" come:

`sig = HASH(secret || message)`

e usa un hash Merkle-Damgård come MD5, SHA-1 o SHA-256.

Se conosci:

- `message`
- `sig`
- la funzione hash
- (oppure riesci a forzare con brute force) `len(secret)`

puoi calcolare una firma valida per:

`message || padding || appended_data`

senza conoscere il secret.<sup>[[1]](#references)</sup>

### Limite importante: HMAC non è vulnerabile

Gli attacchi di length extension si applicano a costruzioni vulnerabili con prefisso, come `HASH(secret || message)`. Non compromettono la costruzione HMAC (per esempio, HMAC-SHA256), che combina una chiave con applicazioni separate dell'hash interno ed esterno.<sup>[[1]](#references)[[2]](#references)</sup>

Per sapere come individuare e testare queste firme nelle web API, consulta [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Strumenti

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), binding Python per lo strumento HashPump per gli attacchi di length extension<sup>[[7]](#references)</sup>

### Buona spiegazione

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing ambiguo di tuple e MAC

### Boundary-confusion attack

Le API per l'hashing incrementale non autenticano i confini tra le chiamate. `update(A); update(B)` calcola l'hash della stessa stringa di byte di `update(A + B)`. Di conseguenza, l'hashing o il calcolo di un MAC su una concatenazione grezza non autentica una tupla. Se i campi adiacenti hanno lunghezza variabile, un attacker può suddividere i byte in modo diverso per ottenere una tupla differente, senza trovare una collisione nell'hash sottostante:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Questo diventa sfruttabile quando il verificatore ritiene che il digest leghi il significato dei campi, ma un input controllato dall’attaccante può raggiungere un parser o una fase del protocollo diversi, che assegnano confini differenti. Le commitment possono ammettere aperture alternative e i transcript Fiat-Shamir possono essere interpretati come enunciati diversi. HMAC impedisce [hash length extension](#hash-length-extension-attack), ma `HMAC(K, A || B)` presenta comunque questa ambiguità di codifica delle tuple, perché entrambe le tuple producono gli stessi byte del messaggio.<sup>[[8]](#references)[[9]](#references)</sup>

Usa questa procedura di audit per verificare se una codifica ambigua delle tuple oltrepassa un confine di sicurezza.<sup>[[8]](#references)[[9]](#references)</sup>

1. Individua `HASH(A || B)`, `HMAC(K, A || B)` e le chiamate consecutive a `update()`/`Write()` su due o più campi.
2. Segna ogni campo controllato dall’attaccante o di lunghezza variabile. Prova a spostare byte oltre ogni confine mantenendo invariata la concatenazione completa. Includi i campi vuoti.
3. Verifica gli schemi con delimitatori per individuare byte delimitatori che gli input possono contenere, disaccordi nell’escaping e implementazioni che codificano la lunghezza solo di alcuni campi.
4. Traccia il modo in cui ogni consumer analizza i byte autenticati. Un caso è significativo solo se una partizione alternativa modifica una decisione di sicurezza, un enunciato di prova, un record, una transazione o un’apertura della commitment. I campi a larghezza fissa o una serializzazione canonica e iniettiva impediscono questo specifico attacco.
5. Verifica se lo stesso digest codificato viene accettato in un’altra versione del protocollo, tipo di messaggio, round o applicazione. Associa esplicitamente questi contesti invece di affidarti ai chiamanti perché li tengano separati.

### SequenceHash e SequenceMAC

SequenceHash è una costruzione indipendente dall’hash per sequenze di stringhe di byte. Ogni operazione `add()` è atomica: aggiunge il valore e un suffisso di lunghezza fisso di 16 byte in little-endian all’hash interno. I valori vuoti restano oggetti distinti. Un hash esterno impedisce l’esposizione di uno stato interno soggetto a length extension, mentre una stringa di personalizzazione opzionale fornisce la separazione di dominio. Non sostituire `add()` con le normali scritture dell’API dell’hash sottostante.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Scegliete il customizer come parte della definizione del protocollo, includendo informazioni sufficienti a distinguere l’applicazione, la versione del protocollo, il tipo di messaggio e il round. SequenceHash richiede comunque che tutte le parti concordino sull’ordine dei campi, sulla codifica dei byte e sulla serializzazione canonica, e non può proteggere un campo omesso. Le implementazioni dovrebbero essere verificate con i vettori di test intermedi e finali C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Per l’autenticazione, SequenceMAC fornisce la stessa codifica atomica e la stessa interfaccia di personalizzazione. Richiede una chiave di almeno 32 byte. A differenza del pretrattamento delle chiavi HMAC, i suoi header includono un impegno alla lunghezza esatta della chiave: una chiave grezza lunga non equivale al suo prehash e aggiungere byte zero modifica la chiave. Questa distinzione è importante quando i componenti accettano rappresentazioni diverse della chiave o metadati sulla sua lunghezza.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

L'API Python e le implementazioni equivalenti in Go e Rust sono disponibili come riferimenti, ma le implementazioni del protocollo dovrebbero seguire la specifica C2SP aggiornata, anziché ricreare la codifica a partire da questo riepilogo.<sup>[[8]](#references)[[10]](#references)</sup>

## Hashing e cracking delle password

### Prime domande<sup>[[4]](#references)</sup>

- È **salted**? (cerca formati `salt$hash`)
- È un **fast hash** (MD5/SHA1/SHA256) o una **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Hai un **indizio sul formato** (modalità hashcat / formato John)?

### Flusso di lavoro pratico<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifica l'hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Se non è salted ed è comune: prova database online e strumenti di identificazione della sezione sul flusso di lavoro crypto.
3. Altrimenti, esegui il cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errori comuni che puoi sfruttare

- La stessa password è riutilizzata da più utenti → crackane una, poi fai pivot.
- Hash troncati / trasformazioni personalizzate → normalizza e riprova.
- Parametri KDF deboli (ad esempio, poche iterazioni PBKDF2) → l'hash è comunque crackabile.

### Oracle bcrypt con input scelto e secret aggiunto

Un helper richiamabile che restituisce `bcrypt(user_input || secret)` può esporre informazioni sul secret aggiunto se la sua implementazione bcrypt tronca silenziosamente l'input dopo 72 **byte**. Un limite sul numero di caratteri applicato prima della codifica UTF-8 non garantisce il rispetto di quel limite in byte: i caratteri multibyte possono occupare lo spazio disponibile nell'input bcrypt, lasciando posto solo a un piccolo prefisso del secret. Gli input scelti e gli hash restituiti possono quindi consentire verifiche offline dei byte candidati del suffisso. Questo richiede il controllo dell'input dell'helper, la conoscenza della trasformazione e della codifica esatte e un'implementazione che tronchi davvero; un helper richiamabile o un hash bcrypt, da soli, non dimostrano l'intera catena. [pyca/bcrypt documenta](https://github.com/pyca/bcrypt#maximum-password-length) che l'attuale `hashpw` genera un errore per input superiori a 72 byte, mentre il comportamento precedente li troncava silenziosamente. Altri wrapper potrebbero eseguire un prehash o rifiutare gli input lunghi, quindi verifica l'implementazione installata anziché presumere che avvenga il troncamento.

Usare un secret recuperato per accedere a un account diverso richiede anche prove che l'hash esposto sia stato generato con lo **stesso** secret e la stessa trasformazione, oltre a un percorso di autenticazione o credenziali separati. Un helper di hashing eseguito come root dovrebbe essere considerato un oracle solo se l'utente con privilegi inferiori può invocarlo secondo le policy effettive; l'enumerazione passiva dell'host non deve necessariamente invocarlo né inviare password scelte.

## References

- [1] [SkullSecurity - Tutto ciò che devi sapere sugli attacchi di estensione della lunghezza degli hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Codice di autenticazione dei messaggi con hash con chiave](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Scheda di riferimento per la memorizzazione delle password](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - Hash di esempio](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Opzioni della riga di comando](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` - Binding Python per HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Specifica di SequenceHash e SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multi-hashing per tutti](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Implementazione Python di SequenceHash](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Vettori di test di SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
