# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Cosa cercare nelle CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: errori/tempi diversi per PKCS#7 padding non valido.
- **MAC confusion**: using CBC-MAC with variable-length messages, or MAC-then-encrypt mistakes.
- **XOR everywhere**: stream ciphers and custom constructions often reduce to XOR with a keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Questo permette:

- Cut-and-paste / block reordering
- Block deletion (se il formato rimane valido)

Se puoi controllare il plaintext e osservare il ciphertext (o i cookie), prova a creare blocchi ripetuti (es., molti `A`s) e cerca ripetizioni.

### CBC: Cipher Block Chaining

- CBC è **malleabile**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Se il sistema espone padding valido vs padding non valido, potresti avere un **padding oracle**.

### CTR

CTR trasforma AES in uno stream cipher: `C = P XOR keystream`.

Se un nonce/IV viene riutilizzato con la stessa chiave:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Con plaintext noto, puoi recuperare il keystream e decifrare altri.

### GCM

GCM si rompe male con il nonce reuse. Se la stessa key+nonce viene usata più volte, normalmente ottieni:

- Keystream reuse per l'encryption (come CTR), permettendo il recupero del plaintext quando qualsiasi plaintext è noto.
- Perdita delle garanzie di integrità. A seconda di cosa è esposto (più coppie message/tag sotto lo stesso nonce), un attaccante può essere in grado di forgiare tag.

Linee guida operative:

- Tratta "nonce reuse" in AEAD come una vulnerabilità critica.
- Se hai più ciphertext sotto lo stesso nonce, inizia controllando relazioni tipo `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) cifra ogni blocco indipendentemente:

- equal plaintext blocks → equal ciphertext blocks
- questo leaks la struttura e permette attacchi in stile cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea di detection: pattern token/cookie

Se effettui il login più volte e **ricevi sempre lo stesso cookie**, il ciphertext potrebbe essere deterministico (ECB o IV fisso).

Se crei due utenti con layout di plaintext per lo più identici (es., lunghi caratteri ripetuti) e vedi blocchi di ciphertext ripetuti agli stessi offset, ECB è il sospetto principale.

### Exploitation patterns

#### Removing entire blocks

Se il formato del token è qualcosa come `<username>|<password>` e il boundary del blocco si allinea, a volte puoi creare un utente in modo che il blocco `admin` appaia allineato, poi rimuovere i blocchi precedenti per ottenere un token valido per `admin`.

#### Moving blocks

Se il backend tollera padding/spazi extra (`admin` vs `admin    `), puoi:

- Allineare un blocco che contiene `admin   `
- Swap/reuse quel blocco di ciphertext in un altro token

## Padding Oracle

### Cos'è

In modalità CBC, se il server rivela (direttamente o indirettamente) se il plaintext decifrato ha **valid PKCS#7 padding**, spesso puoi:

- Decifrare ciphertext senza la chiave
- Cifrare plaintext scelto (forgiare ciphertext)

L'oracolo può essere:

- Un messaggio di errore specifico
- Un diverso status HTTP / dimensione della risposta
- Una differenza di timing

### Sfruttamento pratico

PadBuster è lo strumento classico:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Esempio:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Note:

- La dimensione del blocco è spesso `16` per AES.
- `-encoding 0` significa Base64.
- Usa `-error` se l'oracle è una stringa specifica.

### Perché funziona

La decrittazione CBC calcola `P[i] = D(C[i]) XOR C[i-1]`. Modificando i byte in `C[i-1]` e osservando se il padding è valido, puoi recuperare `P[i]` byte per byte.

## Bit-flipping in CBC

Anche senza un padding oracle, CBC è malleabile. Se puoi modificare i blocchi di ciphertext e l'applicazione usa il plaintext decrittato come dati strutturati (es., `role=user`), puoi modificare bit specifici per cambiare byte selezionati del plaintext in una posizione scelta nel blocco successivo.

Schema tipico nei CTF:

- Token = `IV || C1 || C2 || ...`
- Controlli i byte in `C[i]`
- Miri ai byte del plaintext in `P[i+1]` perché `P[i+1] = D(C[i+1]) XOR C[i]`

Questo non è una violazione della riservatezza di per sé, ma è una primitiva comune per l'elevazione di privilegi quando manca l'integrità.

## CBC-MAC

CBC-MAC è sicuro solo in condizioni specifiche (in particolare **messaggi a lunghezza fissa** e corretta separazione dei domini).

### Schema classico di forgery per lunghezza variabile

CBC-MAC viene solitamente calcolato come:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se puoi ottenere tag per messaggi scelti, spesso puoi creare un tag per una concatenazione (o costruzione correlata) senza conoscere la chiave, sfruttando come CBC concatena i blocchi.

Questo appare frequentemente in cookie/token nei CTF che applicano un MAC a username o role con CBC-MAC.

### Alternative più sicure

- Usa HMAC (SHA-256/512)
- Usa CMAC (AES-CMAC) correttamente
- Includi la lunghezza del messaggio / separazione dei domini

## Cifrari a flusso: XOR e RC4

### Modello mentale

La maggior parte delle situazioni con stream cipher si riduce a:

`ciphertext = plaintext XOR keystream`

Quindi:

- Se conosci il plaintext, ricavi il keystream.
- Se il keystream viene riutilizzato (stessa key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Crittografia basata su XOR

Se conosci un segmento di plaintext alla posizione `i`, puoi ricavare i byte del keystream e decriptare altri ciphertext in quelle posizioni.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 è un stream cipher; encrypt/decrypt sono la stessa operazione.

Se puoi ottenere una encryption RC4 di plaintext noto con la stessa key, puoi recuperare il keystream e decriptare altri messaggi della stessa lunghezza/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
