# Crittografia simmetrica

{{#include ../../banners/hacktricks-training.md}}

## Cosa cercare nei CTF

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: errori/tempi differenti per bad padding.
- **MAC confusion**: usare CBC-MAC con messaggi di lunghezza variabile, o errori MAC-then-encrypt.
- **XOR everywhere**: stream ciphers e costruzioni custom spesso si riducono a XOR con un keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Questo permette:

- Cut-and-paste / block reordering
- Block deletion (se il formato rimane valido)

Se puoi controllare il plaintext e osservare il ciphertext (o cookies), prova a creare blocchi ripetuti (es., molte `A`) e cerca ripetizioni.

### CBC: Cipher Block Chaining

- CBC è **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Se il sistema espone padding valido vs padding non valido, potresti avere un **padding oracle**.

### CTR

CTR trasforma AES in uno stream cipher: `C = P XOR keystream`.

Se un nonce/IV viene riutilizzato con la stessa chiave:

- `C1 XOR C2 = P1 XOR P2` (classico riuso del keystream)
- Con plaintext noto, puoi recuperare il keystream e decifrare altri messaggi.

### GCM

GCM si rompe male con nonce reuse. Se la stessa key+nonce è usata più di una volta, di solito ottieni:

- Riuso del keystream per la cifratura (come CTR), permettendo il recupero del plaintext quando un qualsiasi plaintext è noto.
- Perdita delle garanzie di integrità. A seconda di cosa è esposto (più coppie message/tag con lo stesso nonce), un attaccante può riuscire a forgiare tag.

Indicazioni operative:

- Considera "nonce reuse" in AEAD come una vulnerabilità critica.
- Se hai più ciphertext con lo stesso nonce, inizia controllando relazioni del tipo `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef per esperimenti veloci: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` per scripting

## Pattern di sfruttamento ECB

ECB (Electronic Code Book) cifra ogni blocco in modo indipendente:

- equal plaintext blocks → equal ciphertext blocks
- questo leaks la struttura e abilita attacchi di tipo cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Se effettui il login più volte e **ottieni sempre lo stesso cookie**, il ciphertext potrebbe essere deterministico (ECB o IV fisso).

Se crei due utenti con layout di plaintext per lo più identici (es., lunghe sequenze ripetute) e vedi blocchi di ciphertext ripetuti alle stesse posizioni, ECB è il sospetto principale.

### Exploitation patterns

#### Removing entire blocks

Se il formato del token è qualcosa come `<username>|<password>` e il confine dei blocchi è allineato, a volte puoi creare un utente in modo che il blocco `admin` appaia allineato, poi rimuovere i blocchi precedenti per ottenere un token valido per `admin`.

#### Moving blocks

Se il backend tollera padding/spazi extra (`admin` vs `admin    `), puoi:

- Allineare un blocco che contiene `admin   `
- Scambiare/riusare quel blocco di ciphertext in un altro token

## Padding Oracle

### Che cos'è

In modalità CBC, se il server rivela (direttamente o indirettamente) se il plaintext decifrato ha **valid PKCS#7 padding**, puoi spesso:

- Decifrare ciphertext senza la chiave
- Cifrare plaintext scelto (forgiare ciphertext)

L'oracolo può essere:

- Un messaggio di errore specifico
- Un diverso HTTP status / dimensione della risposta
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

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Perché funziona

La decrittazione CBC calcola `P[i] = D(C[i]) XOR C[i-1]`. Modificando byte in `C[i-1]` e osservando se il padding è valido, puoi recuperare `P[i]` byte per byte.

## Bit-flipping in CBC

Anche senza un padding oracle, CBC è malleabile. Se puoi modificare blocchi di ciphertext e l'applicazione usa il plaintext decrittato come dati strutturati (es., `role=user`), puoi flipparе bit specifici per cambiare byte selezionati del plaintext in una posizione scelta nel blocco successivo.

Schema tipico in CTF:

- Token = `IV || C1 || C2 || ...`
- Controlli i byte in `C[i]`
- Miri ai byte del plaintext in `P[i+1]` perché `P[i+1] = D(C[i+1]) XOR C[i]`

Questo non è di per sé una violazione della riservatezza, ma è una primitiva comune di privilege-escalation quando manca l'integrità.

## CBC-MAC

CBC-MAC è sicuro solo in condizioni specifiche (in particolare **messaggi a lunghezza fissa** e corretta separazione dei domini).

### Pattern classico di variable-length forgery

CBC-MAC viene solitamente calcolato come:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se puoi ottenere tag per messaggi scelti, spesso puoi creare un tag per una concatenazione (o costruzione correlata) senza conoscere la key, sfruttando il modo in cui CBC concatena i blocchi.

Questo si presenta frequentemente in cookie/token CTF che MAC username o role con CBC-MAC.

### Alternative più sicure

- Usare HMAC (SHA-256/512)
- Usare CMAC (AES-CMAC) correttamente
- Includere la lunghezza del messaggio / separazione dei domini

## Cifrari a flusso: XOR and RC4

### Modello mentale

La maggior parte delle situazioni con stream cipher si riduce a: `ciphertext = plaintext XOR keystream`

Quindi:

- Se conosci il plaintext, recuperi il keystream.
- Se il keystream è riutilizzato (stessa key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Se conosci un segmento di plaintext alla posizione `i`, puoi recuperare i byte del keystream e decrittare altri ciphertext in quelle posizioni.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 è un stream cipher; encrypt/decrypt sono la stessa operazione.

Se puoi ottenere la cifratura RC4 di plaintext noto con la stessa key, puoi recuperare il keystream e decrittare altri messaggi della stessa lunghezza/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
