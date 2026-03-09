# Crittografia simmetrica

{{#include ../../banners/hacktricks-training.md}}

## Cosa cercare nei CTF

- **Abuso delle modalità**: schemi ECB, malliabilità CBC, riuso del nonce in CTR/GCM.
- **Padding oracles**: errori/tempi diversi per padding non valido.
- **MAC confusion**: usare CBC-MAC con messaggi a lunghezza variabile, o errori MAC-then-encrypt.
- **XOR ovunque**: i cifrari a flusso e le costruzioni custom spesso si riducono a XOR con un keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: blocchi di testo in chiaro uguali → blocchi di testo cifrato uguali. Questo permette:

- Cut-and-paste / riorganizzazione dei blocchi
- Cancellazione di blocchi (se il formato rimane valido)

Se puoi controllare il testo in chiaro e osservare il testo cifrato (o i cookie), prova a generare blocchi ripetuti (es., molti `A`) e cerca ripetizioni.

### CBC: Cipher Block Chaining

- CBC è **malleabile**: modificare bit in `C[i-1]` modifica bit prevedibili in `P[i]`.
- Se il sistema espone padding valido vs padding non valido, potresti avere un **padding oracle**.

### CTR

CTR trasforma AES in un cifrario a flusso: `C = P XOR keystream`.

Se un nonce/IV viene riutilizzato con la stessa chiave:

- `C1 XOR C2 = P1 XOR P2` (classico riuso del keystream)
- Con plaintext noto, puoi recuperare il keystream e decifrare gli altri.

**Nonce/IV reuse exploitation patterns**

- Recupera il keystream ovunque il plaintext sia noto/indovinabile:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Applica i byte di keystream recuperati per decifrare qualsiasi altro ciphertext prodotto con la stessa key+IV agli stessi offset.
- Dati altamente strutturati (es., ASN.1/X.509 certificates, header di file, JSON/CBOR) forniscono grandi regioni di plaintext prevedibile. Spesso puoi XORare il ciphertext del certificato con il corpo prevedibile per ricavare il keystream, poi decifrare altri segreti cifrati sotto lo stesso IV riutilizzato. Vedi anche [TLS & Certificates](../tls-and-certificates/README.md) per layout tipici dei certificati.
- Quando più segreti dello **stesso formato/size serializzato** sono cifrati sotto la stessa key+IV, l'allineamento dei campi leaks anche senza plaintext completamente noto. Esempio: chiavi PKCS#8 RSA dello stesso size di modulo collocano i fattori primi agli stessi offset (~99.6% di allineamento per 2048-bit). XORando due ciphertext sotto lo stesso keystream si isola `p ⊕ p'` / `q ⊕ q'`, che può essere recuperato con brute-force in pochi secondi.
- IV di default nelle librerie (es., costante `000...01`) sono una trappola critica: ogni cifratura ripete lo stesso keystream, trasformando CTR in un one-time pad riutilizzato.

**CTR malleability**

- CTR fornisce solo confidenzialità: invertire bit nel ciphertext cambia in modo deterministico gli stessi bit nel plaintext. Senza un authentication tag, un attacker può manomettere i dati (es., modificare chiavi, flag o messaggi) senza essere rilevato.
- Usa AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, ecc.) e verifica sempre il tag per rilevare bit-flip.

### GCM

GCM si rompe anch'esso in modo grave con il riuso del nonce. Se la stessa key+nonce è usata più volte, tipicamente ottieni:

- Riuso del keystream per la cifratura (come CTR), permettendo il recupero del plaintext quando qualsiasi plaintext è noto.
- Perdita delle garanzie di integrità. A seconda di cosa è esposto (più coppie message/tag sotto lo stesso nonce), gli attacker possono essere in grado di forgiare tag.

Linee guida operative:

- Tratta il "riuso del nonce" in AEAD come una vulnerabilità critica.
- AEAD resistenti al misuse (es., GCM-SIV) riducono l'impatto del nonce-misuse ma richiedono comunque nonces/IV unici.
- Se hai più ciphertext sotto lo stesso nonce, inizia controllando relazioni del tipo `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef per esperimenti rapidi: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` per scripting

## ECB exploitation patterns

ECB (Electronic Code Book) cifra ogni blocco indipendentemente:

- blocchi di testo in chiaro uguali → blocchi di testo cifrato uguali
- questo leaks la struttura e permette attacchi in stile cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Se effettui il login più volte e **ricevi sempre lo stesso cookie**, il testo cifrato potrebbe essere deterministico (ECB o IV fisso).

Se crei due utenti con layout del plaintext per lo più identici (es., caratteri ripetuti lunghi) e vedi blocchi di ciphertext ripetuti agli stessi offset, ECB è il principale sospetto.

### Exploitation patterns

#### Removing entire blocks

Se il formato del token è qualcosa come `<username>|<password>` e il confine dei blocchi è allineato, a volte puoi creare un utente in modo che il blocco `admin` appaia allineato, poi rimuovere i blocchi precedenti per ottenere un token valido per `admin`.

#### Moving blocks

Se il backend tollera padding/spazi extra (`admin` vs `admin    `), puoi:

- Allineare un blocco che contiene `admin   `
- Scambiare/riutilizzare quel blocco di ciphertext in un altro token

## Padding Oracle

### What it is

In CBC mode, se il server rivela (direttamente o indirettamente) se il plaintext decrittato ha padding PKCS#7 valido, spesso puoi:

- Decifrare ciphertext senza la chiave
- Cifrare plaintext scelto (forgiare ciphertext)

L'oracolo può essere:

- Un messaggio di errore specifico
- Un diverso status HTTP / dimensione della risposta
- Una differenza di timing

### Practical exploitation

PadBuster è lo strumento classico:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- La dimensione del blocco è spesso `16` per AES.
- `-encoding 0` significa Base64.
- Usa `-error` se l'oracolo è una stringa specifica.

### Perché funziona

La decrittazione CBC calcola `P[i] = D(C[i]) XOR C[i-1]`. Modificando i byte in `C[i-1]` e osservando se il padding è valido, puoi recuperare `P[i]` byte per byte.

## Bit-flipping in CBC

Anche senza un padding oracle, CBC è malleabile. Se puoi modificare blocchi di ciphertext e l'applicazione usa il plaintext decriptato come dati strutturati (es., `role=user`), puoi modificare bit specifici per cambiare byte selezionati del plaintext in una posizione scelta del blocco successivo.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

Questo non è di per sé una violazione della riservatezza, ma è una primitiva comune per privilege-escalation quando manca l'integrità.

## CBC-MAC

CBC-MAC è sicuro solo in condizioni specifiche (in particolare **messaggi a lunghezza fissa** e corretta separazione dei domini).

### Pattern classico di forgery a lunghezza variabile

CBC-MAC viene solitamente calcolato come:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se puoi ottenere tag per messaggi scelti, spesso puoi costruire un tag per una concatenazione (o una costruzione correlata) senza conoscere la chiave, sfruttando il modo in cui CBC concatena i blocchi.

Questo appare frequentemente in CTF cookies/tokens che applicano un MAC a username o role con CBC-MAC.

### Safer alternatives

- Usa HMAC (SHA-256/512)
- Usa CMAC (AES-CMAC) correttamente
- Includi la lunghezza del messaggio / separazione dei domini

## Cifrari a flusso: XOR and RC4

### Il modello mentale

La maggior parte dei casi con cifrari a flusso si riduce a:

`ciphertext = plaintext XOR keystream`

Quindi:

- Se conosci il plaintext, recuperi il keystream.
- Se il keystream è riutilizzato (stessa key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Se conosci qualsiasi segmento di plaintext alla posizione `i`, puoi recuperare i byte del keystream e decriptare altri ciphertext in quelle posizioni.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 è un stream cipher; encrypt/decrypt sono la stessa operazione.

Se puoi ottenere l'encryption RC4 di plaintext noto sotto la stessa key, puoi recuperare il keystream e decriptare altri messaggi della stessa lunghezza/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
