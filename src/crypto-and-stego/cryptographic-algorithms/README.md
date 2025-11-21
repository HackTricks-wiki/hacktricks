# Cryptographic/Compression Algorithms

{{#include ../../banners/hacktricks-training.md}}

## Identifying Algorithms

Se ti imbatti in un codice **che utilizza shift a destra e a sinistra, xors e varie operazioni aritmetiche** è altamente probabile che si tratti dell'implementazione di un **algoritmo crittografico**. Qui verranno mostrate alcune modalità per **identificare l'algoritmo usato senza dover reverse-engineerare ogni singolo passo**.

### API functions

**CryptDeriveKey**

Se viene usata questa funzione, puoi trovare quale **algoritmo è usato** controllando il valore del secondo parametro:

![](<../../images/image (156).png>)

Controlla qui la tabella degli algoritmi possibili e dei valori assegnati: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime e decomprime un buffer di dati dato.

**CryptAcquireContext**

Dalla [documentazione](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): la funzione **CryptAcquireContext** viene usata per ottenere un handle a un particolare key container all'interno di un particolare cryptographic service provider (CSP). **Questo handle restituito è usato nelle chiamate alle funzioni CryptoAPI** che utilizzano il CSP selezionato.

**CryptCreateHash**

Inizia l'hashing di uno stream di dati. Se viene usata questa funzione, puoi trovare quale **algoritmo è usato** controllando il valore del secondo parametro:

![](<../../images/image (549).png>)

\
Controlla qui la tabella degli algoritmi possibili e dei valori assegnati: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

A volte è molto facile identificare un algoritmo grazie al fatto che richiede l'uso di un valore speciale e unico.

![](<../../images/image (833).png>)

Se cerchi la prima costante su Google questo è ciò che ottieni:

![](<../../images/image (529).png>)

Quindi, puoi presumere che la funzione decompilata sia un **calcolatore sha256.**\
Puoi cercare qualsiasi altra costante e otterrai (probabilmente) lo stesso risultato.

### data info

Se il codice non ha costanti significative potrebbe **caricare informazioni dalla sezione .data**.\
Puoi accedere a quei dati, **raggruppare il primo dword** e cercarlo su Google come abbiamo fatto nella sezione precedente:

![](<../../images/image (531).png>)

In questo caso, se cerchi **0xA56363C6** puoi trovare che è correlato alle **tabelle dell'algoritmo AES**.

## RC4 **(Crittografia simmetrica)**

### Characteristics

È composto da 3 parti principali:

- **Initialization stage/**: Crea una **tabella di valori da 0x00 a 0xFF** (256 byte in totale, 0x100). Questa tabella è comunemente chiamata **Substitution Box** (o SBox).
- **Scrambling stage**: Scorrerà la tabella creata prima (loop di 0x100 iterazioni, ancora) modificando ogni valore con byte **semi-casuali**. Per creare questi byte semi-casuali viene usata la **key di RC4**. Le RC4 **keys** possono essere **tra 1 e 256 byte di lunghezza**, tuttavia solitamente si raccomanda che siano oltre i 5 byte. Comunemente, le RC4 keys sono lunghe 16 byte.
- **XOR stage**: Infine, il plaintext o ciphertext viene **XORato con i valori creati precedentemente**. La funzione per cifrare e decifrare è la stessa. Per questo, verrà eseguito un **loop attraverso i 256 byte creati** tante volte quanto necessario. Questo è solitamente riconoscibile in codice decompilato con un **%256 (mod 256)**.

> [!TIP]
> **Per identificare una RC4 in una disassembly/decompiled code puoi cercare 2 loop di dimensione 0x100 (con l'uso di una key) e poi un XOR dell'input data con i 256 valori creati prima nei 2 loop probabilmente usando un %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Nota il numero 256 usato come contatore e come viene scritto uno 0 in ogni posizione dei 256 caratteri)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Crittografia simmetrica)**

### **Characteristics**

- Uso di **substitution boxes e lookup tables**
- È possibile **distinguere AES grazie all'uso di specifici valori nelle lookup table** (costanti). _Nota che la **costante** può essere **memorizzata** nel binario **o creata** _**dinamicamente**._
- La **encryption key** deve essere **divisibile** per **16** (solitamente 32B) e di solito viene usato un **IV** di 16B.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Crittografia simmetrica)**

### Characteristics

- È raro trovare malware che lo usino ma ci sono esempi (Ursnif)
- Semplice determinare se un algoritmo è Serpent o meno basandosi sulla sua lunghezza (funzione estremamente lunga)

### Identifying

Nell'immagine seguente nota come la costante **0x9E3779B9** viene usata (nota che questa costante è usata anche da altri algoritmi crypto come **TEA** - Tiny Encryption Algorithm).\
Nota anche la **dimensione del loop** (**132**) e il **numero di operazioni XOR** nelle istruzioni di **disassembly** e nell'esempio di **codice**:

![](<../../images/image (547).png>)

Come menzionato prima, questo codice può essere visualizzato in qualsiasi decompiler come una **funzione molto lunga** poiché **non ci sono jump** al suo interno. Il codice decompilato può apparire come il seguente:

![](<../../images/image (513).png>)

Pertanto, è possibile identificare questo algoritmo controllando il **magic number** e gli **XOR iniziali**, osservando una **funzione molto lunga** e **comparando** alcune **istruzioni** della funzione lunga **con una implementazione** (come lo shift left di 7 e la rotate left di 22).

## RSA **(Crittografia asimmetrica)**

### Characteristics

- Più complesso rispetto agli algoritmi simmetrici
- Non ci sono costanti! (implementazioni custom sono difficili da determinare)
- KANAL (un crypto analyzer) non mostra indizi su RSA poiché si basa sulle costanti.

### Identifying by comparisons

![](<../../images/image (1113).png>)

- In linea 11 (sinistra) c'è un `+7) >> 3` che è lo stesso della linea 35 (destra): `+7) / 8`
- La linea 12 (sinistra) sta controllando se `modulus_len < 0x040` e nella linea 36 (destra) sta controllando se `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Characteristics

- 3 funzioni: Init, Update, Final
- Funzioni di inizializzazione simili

### Identify

**Init**

Puoi identificare entrambi controllando le costanti. Nota che sha_init ha 1 costante che MD5 non ha:

![](<../../images/image (406).png>)

**MD5 Transform**

Nota l'uso di più costanti

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Più piccolo ed efficiente poiché la sua funzione è trovare cambiamenti accidentali nei dati
- Usa lookup tables (quindi puoi identificare costanti)

### Identify

Controlla le **lookup table constants**:

![](<../../images/image (508).png>)

Un algoritmo CRC somiglia a:

![](<../../images/image (391).png>)

## APLib (Compression)

### Characteristics

- Costanti non riconoscibili
- Puoi provare a scrivere l'algoritmo in python e cercare cose simili online

### Identify

Il grafo è abbastanza grande:

![](<../../images/image (207) (2) (1).png>)

Controlla **3 confronti per riconoscerlo**:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 richiede ai verificatori HashEdDSA di dividere una signature `sig = R || s` e rifiutare qualsiasi scalare con `s \geq n`, dove `n` è l'ordine del gruppo. La libreria `elliptic` JS ha saltato quel controllo del bound, quindi qualsiasi attacker che conosca una coppia valida `(msg, R || s)` può forgiare signature alternative `s' = s + k·n` e continuare a re-encodare `sig' = R || s'`.
- Le routine di verifica consumano solo `s mod n`, quindi tutti gli `s'` congruenti a `s` sono accettati anche se sono diversi come stringhe di byte. I sistemi che trattano le signature come token canonici (blockchain consensus, replay caches, DB keys, ecc.) possono desincronizzarsi perché implementazioni rigorose rifiuteranno `s'`.
- Quando auditi altri codici HashEdDSA, assicurati che il parser validi sia il punto `R` sia la lunghezza dello scalare; prova ad appendere multipli di `n` a un `s` noto-buono per confermare che il verificatore fallisca chiudendo (fail closed).

### ECDSA truncation vs. leading-zero hashes

- I verificatori ECDSA devono usare solo i bit più a sinistra `log2(n)` dell'hash del messaggio `H`. In `elliptic`, l'helper di truncation calcolava `delta = (BN(msg).byteLength()*8) - bitlen(n)`; il costruttore `BN` elimina gli octet con zeri di testa, quindi qualsiasi hash che inizi con ≥4 byte nulli su curve come secp192r1 (ordine a 192-bit) appariva come lungo solo 224 bit invece di 256.
- Il verificatore shiftava a destra di 32 bit invece di 64, producendo una `E` che non corrisponde al valore usato dal signer. Signature valide su quegli hash quindi falliscono con probabilità ≈`2^-32` per input SHA-256.
- Dai sia il vettore “tutto a posto” sia le varianti con leading-zero (es., il caso Wycheproof `ecdsa_secp192r1_sha256_test.json` `tc296`) a un'implementazione target; se il verificatore è in disaccordo con il signer, hai trovato un bug di truncation sfruttabile.

### Exercising Wycheproof vectors against libraries
- Wycheproof fornisce set di test JSON che codificano punti malformati, scalari malleabili, hash insoliti e altri corner case. Costruire un harness attorno a `elliptic` (o qualsiasi crypto library) è semplice: carica il JSON, deserializza ogni test case, e asserisci che l'implementazione corrisponda al flag `result` previsto.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Le failure dovrebbero essere sottoposte a triage per distinguere violazioni della spec da falsi positivi. Per i due bug sopra, i casi Wycheproof falliti indicavano immediatamente la mancanza di controlli sull'intervallo degli scalari (EdDSA) e un troncamento errato dell'hash (ECDSA).
- Integrare il harness nella CI in modo che regressioni nel parsing degli scalari, nella gestione dell'hash o nella validità delle coordinate attivino i test non appena vengono introdotte. Questo è particolarmente utile per linguaggi di alto livello (JS, Python, Go) dove conversioni sottili di bignum sono facili da sbagliare.

## Riferimenti

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
