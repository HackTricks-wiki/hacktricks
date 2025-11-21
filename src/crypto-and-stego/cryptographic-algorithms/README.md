# Algoritmi crittografici/di compressione

{{#include ../../banners/hacktricks-training.md}}

## Identificazione degli algoritmi

Se ti imbatti in del codice **using shift rights and lefts, xors and several arithmetic operations** è molto probabile che sia l'implementazione di un **algoritmo crittografico**. Qui verranno mostrati alcuni modi per **identificare l'algoritmo utilizzato senza dover reverseare ogni passo**.

### Funzioni API

**CryptDeriveKey**

Se questa funzione è usata, puoi scoprire quale **algoritmo viene usato** controllando il valore del secondo parametro:

![](<../../images/image (156).png>)

Consulta la tabella degli algoritmi possibili e dei valori assegnati qui: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime e decomprime un dato buffer di dati.

**CryptAcquireContext**

Dalla [documentazione](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): La funzione **CryptAcquireContext** viene utilizzata per ottenere un handle a un particolare key container all'interno di un particolare cryptographic service provider (CSP). **Questo handle restituito è usato nelle chiamate alle funzioni CryptoAPI** che utilizzano il CSP selezionato.

**CryptCreateHash**

Inizia l'hashing di uno stream di dati. Se questa funzione è usata, puoi scoprire quale **algoritmo viene usato** controllando il valore del secondo parametro:

![](<../../images/image (549).png>)

\
Consulta la tabella degli algoritmi possibili e dei valori assegnati qui: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Costanti nel codice

A volte è davvero facile identificare un algoritmo grazie al fatto che utilizza un valore speciale e unico.

![](<../../images/image (833).png>)

Se cerchi la prima costante su Google ottieni questo:

![](<../../images/image (529).png>)

Pertanto, puoi assumere che la funzione decompilata sia un **sha256 calculator.**\
Puoi cercare qualsiasi altra costante e probabilmente otterrai lo stesso risultato.

### Informazioni dai dati

Se il codice non contiene costanti significative potrebbe essere **caricare informazioni dalla sezione .data**.\
Puoi accedere a quei dati, **raggruppare il primo dword** e cercarlo su Google come abbiamo fatto nella sezione precedente:

![](<../../images/image (531).png>)

In questo caso, se cerchi **0xA56363C6** potrai trovare che è correlato alle **tabelle dell'algoritmo AES**.

## RC4 **(Crittografia simmetrica)**

### Caratteristiche

È composto da 3 parti principali:

- **Initialization stage/**: Crea una **tabella di valori da 0x00 a 0xFF** (256 byte in totale, 0x100). Questa tabella è comunemente chiamata **Substitution Box** (o SBox).
- **Scrambling stage**: Scorrerà la **tabella** creata prima (loop di 0x100 iterazioni, ancora una volta) modificando ogni valore con byte **semi-random**. Per creare questi byte semi-random viene usata la **key** di RC4. Le **keys** di RC4 possono essere **tra 1 e 256 byte** di lunghezza, tuttavia di solito si raccomanda che siano più di 5 byte. Comunemente, le keys RC4 sono lunghe 16 byte.
- **XOR stage**: Infine, il plain-text o il cyphertext viene **XORed con i valori creati prima**. La funzione per cifrare e decifrare è la stessa. Per questo motivo viene effettuato un **loop attraverso i 256 byte creati** tante volte quanto necessario. Questo è solitamente riconoscibile in un codice decompilato con un **%256 (mod 256)**.

> [!TIP]
> **Per identificare RC4 in un disassembly/decompiled code puoi cercare 2 loop di dimensione 0x100 (con l'uso di una key) e poi un XOR dei dati di input con i 256 valori creati prima nei 2 loop, probabilmente usando un %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Nota il numero 256 usato come contatore e come viene scritto uno 0 in ogni posizione dei 256 caratteri)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Crittografia simmetrica)**

### **Caratteristiche**

- Uso di **substitution boxes e lookup tables**
- È possibile **distinguere AES grazie all'uso di specifici valori nelle lookup table** (costanti). _Nota che la **costante** può essere **memorizzata** nel binario **o creata**_ _**dinamicamente**._
- La **encryption key** deve essere **divisibile** per **16** (di solito 32B) e di solito viene usato un **IV** di 16B.

### Costanti SBox

![](<../../images/image (208).png>)

## Serpent **(Crittografia simmetrica)**

### Caratteristiche

- È raro trovare malware che lo usino ma ci sono esempi (Ursnif)
- È semplice determinare se un algoritmo è Serpent o meno in base alla sua lunghezza (funzione estremamente lunga)

### Identificazione

Nell'immagine seguente nota come viene usata la costante **0x9E3779B9** (nota che questa costante è usata anche da altri algoritmi crypto come **TEA** - Tiny Encryption Algorithm).\
Nota anche la **dimensione del loop** (**132**) e il **numero di operazioni XOR** nelle istruzioni di **disassembly** e nell'esempio di **codice**:

![](<../../images/image (547).png>)

Come menzionato prima, questo codice può essere visualizzato in qualsiasi decompiler come una **funzione molto lunga** poiché **non ci sono salti** al suo interno. Il codice decompilato può apparire come il seguente:

![](<../../images/image (513).png>)

Pertanto, è possibile identificare questo algoritmo controllando il **magic number** e gli **XOR iniziali**, osservando una **funzione molto lunga** e **comparando** alcune **istruzioni** della funzione lunga **con un'implementazione** (come lo shift left di 7 e la rotate left di 22).

## RSA **(Crittografia asimmetrica)**

### Caratteristiche

- Più complesso rispetto agli algoritmi simmetrici
- Non ci sono costanti! (implementazioni custom sono difficili da determinare)
- KANAL (un crypto analyzer) non riesce a mostrare indizi su RSA poiché si basa sulle costanti.

### Identificazione tramite confronti

![](<../../images/image (1113).png>)

- Nella riga 11 (a sinistra) c'è `+7) >> 3` che è lo stesso che nella riga 35 (a destra): `+7) / 8`
- La riga 12 (a sinistra) verifica se `modulus_len < 0x040` e nella riga 36 (a destra) verifica se `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Caratteristiche

- 3 funzioni: Init, Update, Final
- Funzioni di inizializzazione simili

### Identificare

**Init**

Puoi identificare entrambi controllando le costanti. Nota che sha_init ha 1 costante che MD5 non ha:

![](<../../images/image (406).png>)

**MD5 Transform**

Nota l'uso di più costanti

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Più piccolo e più efficiente in quanto la sua funzione è trovare cambiamenti accidentali nei dati
- Usa lookup tables (quindi puoi identificare costanti)

### Identificare

Controlla le **costanti delle lookup table**:

![](<../../images/image (508).png>)

Un algoritmo hash CRC appare così:

![](<../../images/image (391).png>)

## APLib (Compressione)

### Caratteristiche

- Costanti non riconoscibili
- Puoi provare a implementare l'algoritmo in python e cercare cose simili online

### Identificare

Il grafo è piuttosto grande:

![](<../../images/image (207) (2) (1).png>)

Controlla **3 confronti per riconoscerlo**:

![](<../../images/image (430).png>)

## Bug nelle implementazioni di firme su curve ellittiche

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 richiede ai verificatori HashEdDSA di dividere una signature `sig = R || s` e rifiutare qualsiasi scalare con `s \geq n`, dove `n` è l'ordine del gruppo. La libreria JS `elliptic` ha saltato quel controllo del bound, quindi qualsiasi attacker che conosca una coppia valida `(msg, R || s)` può forgiare signature alternative `s' = s + k·n` e continuare a ricodificare `sig' = R || s'`.
- Le routine di verifica consumano solo `s mod n`, quindi tutti gli `s'` congruenti a `s` vengono accettati anche se sono diverse stringhe di byte. I sistemi che trattano le signature come token canonici (consenso blockchain, replay caches, chiavi DB, ecc.) possono desincronizzarsi perché implementazioni rigorose respingeranno `s'`.
- Quando auditi altri codici HashEdDSA, assicurati che il parser validi sia il punto `R` sia la lunghezza dello scalare; prova ad appendere multipli di `n` a un `s` noto-buono per confermare che il verificatore fallisca chiudendo (fails closed).

### ECDSA truncation vs. leading-zero hashes

- I verificatori ECDSA devono usare solo i bit più a sinistra `log2(n)` dell'hash del messaggio `H`. In `elliptic`, l'helper di truncation calcolava `delta = (BN(msg).byteLength()*8) - bitlen(n)`; il costruttore `BN` scarta gli octet con zeri iniziali, quindi qualsiasi hash che cominci con ≥4 zero byte su curve come secp192r1 (ordine a 192 bit) appariva essere solo 224 bit invece di 256.
- Il verificatore ha effettuato un right-shift di 32 bit invece di 64, producendo una `E` che non corrisponde al valore usato dal signer. Le signature valide su quegli hash quindi falliscono con probabilità ≈`2^-32` per input SHA-256.
- Fornisci sia il vettore “all good” sia le varianti con leading-zero (per esempio, il caso Wycheproof `ecdsa_secp192r1_sha256_test.json` `tc296`) a un'implementazione target; se il verificatore non concorda con il signer, hai trovato un bug di truncation sfruttabile.

### Exercising Wycheproof vectors against libraries
- Wycheproof distribuisce set di test JSON che codificano punti malformati, scalari malleabili, hash non usuali e altri corner case. Costruire un harness attorno a `elliptic` (o qualsiasi crypto library) è semplice: carica il JSON, deserializza ogni test case e asserisci che l'implementazione corrisponda al flag `result` atteso.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- I fallimenti devono essere classificati per distinguere le violazioni della specifica dai falsi positivi. Per i due bug sopra citati, i casi Wycheproof falliti hanno immediatamente indicato la mancanza di controlli sull'intervallo degli scalari (EdDSA) e un troncamento errato dell'hash (ECDSA).
- Integrare il test harness nella CI in modo che regressioni nel parsing degli scalari, nella gestione degli hash o nella validità delle coordinate attivino i test non appena vengono introdotte. Questo è particolarmente utile per i linguaggi di alto livello (JS, Python, Go) dove è facile sbagliare sottili conversioni di bignum.

## Riferimenti

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
