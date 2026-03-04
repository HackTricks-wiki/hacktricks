# Crittografia simmetrica

{{#include ../../banners/hacktricks-training.md}}

## Cosa cercare nei CTF

- **Uso scorretto delle modalità**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: errori/tempi differenti per padding non valido.
- **MAC confusion**: uso di CBC-MAC con messaggi a lunghezza variabile, o errori MAC-then-encrypt.
- **XOR everywhere**: stream ciphers e costruzioni custom spesso si riducono a XOR con un keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Questo consente:

- Cut-and-paste / block reordering
- Block deletion (se il formato rimane valido)

Se puoi controllare il plaintext e osservare il ciphertext (o i cookie), prova a creare blocchi ripetuti (es., molte `A`) e cerca ripetizioni.

### CBC: Cipher Block Chaining

- CBC è **malleable**: modificando bit in `C[i-1]` si alterano bit prevedibili in `P[i]`.
- Se il sistema espone padding valido vs padding non valido, potresti avere una **padding oracle**.

### CTR

CTR trasforma AES in uno stream cipher: `C = P XOR keystream`.

Se un nonce/IV viene riutilizzato con la stessa key:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Con plaintext noto, puoi recuperare il keystream e decrittare gli altri.

**Nonce/IV reuse exploitation patterns**

- Recupera il keystream ovunque il plaintext sia conosciuto/indovinabile:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Applica i byte del keystream recuperato per decrittare qualsiasi altro ciphertext prodotto con la stessa key+IV agli stessi offset.
- Dati altamente strutturati (es., ASN.1/X.509 certificates, file headers, JSON/CBOR) forniscono ampie regioni di known-plaintext. Spesso puoi XORare il ciphertext del certificato con il corpo prevedibile per derivare il keystream, poi decrittare altri segreti cifrati con lo stesso IV. Vedi anche [TLS & Certificates](../tls-and-certificates/README.md) per i layout tipici dei certificati.
- Quando più segreti dello **stesso formato/size serializzato** sono cifrati con la stessa key+IV, l'allineamento dei campi leaks anche senza full known-plaintext. Esempio: PKCS#8 RSA keys della stessa modulus size posizionano i prime factors agli stessi offset (~99.6% alignment per 2048-bit). XORing due ciphertext sotto il keystream riutilizzato isola `p ⊕ p'` / `q ⊕ q'`, che possono essere brute-recovered in pochi secondi.
- Default IVs nelle librerie (es., constant `000...01`) sono una trappola critica: ogni cifratura ripete lo stesso keystream, trasformando CTR in un one-time pad riutilizzato.

**CTR malleability**

- CTR fornisce solo confidenzialità: modificare bit nel ciphertext fa cambiare determinatamente gli stessi bit nel plaintext. Senza un authentication tag, gli attacker possono manomettere i dati (es., tweakare keys, flag, o messaggi) senza essere rilevati.
- Usa AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) e applica la verifica del tag per rilevare bit-flip.

### GCM

GCM si compromette gravemente in caso di riuso del nonce. Se la stessa key+nonce viene usata più di una volta, tipicamente ottieni:

- Keystream reuse per la cifratura (come CTR), che permette il recupero del plaintext quando qualsiasi plaintext è noto.
- Perdita delle garanzie di integrity. A seconda di cosa viene esposto (più coppie message/tag sotto lo stesso nonce), gli attacker possono essere in grado di forgiare tag.

Indicazioni operative:

- Considera il "nonce reuse" in AEAD una vulnerabilità critica.
- AEAD misuse-resistant (es., GCM-SIV) riducono le conseguenze del nonce-misuse ma richiedono comunque nonces/IV unici.
- Se hai più ciphertext sotto lo stesso nonce, inizia controllando relazioni del tipo `C1 XOR C2 = P1 XOR P2`.

### Strumenti

- CyberChef per esperimenti veloci: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` per scripting

## Pattern di sfruttamento ECB

ECB (Electronic Code Book) cifra ogni blocco in modo indipendente:

- blocchi di plaintext uguali → blocchi di ciphertext uguali
- this leaks structure e permette attacchi in stile cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea per la rilevazione: token/cookie pattern

Se effettui il login più volte e **ricevi sempre lo stesso cookie**, il ciphertext potrebbe essere deterministico (ECB o IV fisso).

Se crei due utenti con layout di plaintext per lo più identici (es., caratteri ripetuti lunghi) e vedi blocchi di ciphertext ripetuti agli stessi offset, ECB è il sospetto principale.

### Pattern di sfruttamento

#### Rimozione di interi blocchi

Se il formato del token è qualcosa come `<username>|<password>` e il boundary dei blocchi si allinea, a volte puoi creare un utente in modo che il blocco `admin` appaia allineato, poi rimuovere i blocchi precedenti per ottenere un token valido per `admin`.

#### Spostamento di blocchi

Se il backend tollera padding/spazi extra (`admin` vs `admin    `), puoi:

- Allinea un blocco che contiene `admin   `
- Scambia/riusa quel blocco di ciphertext in un altro token

## Padding Oracle

### Cos'è

In CBC mode, se il server rivela (direttamente o indirettamente) se il plaintext decriptato ha **valid PKCS#7 padding**, spesso puoi:

- Decriptare ciphertext senza la key
- Cifrare plaintext scelto (forgiare ciphertext)

L'oracolo può essere:

- Un messaggio di errore specifico
- Un diverso HTTP status / dimensione della response
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
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Perché funziona

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Modificando i byte in `C[i-1]` e osservando se il padding è valido, puoi recuperare `P[i]` byte per byte.

## Bit-flipping in CBC

Even without a padding oracle, CBC is malleable. Se puoi modificare i blocchi di ciphertext e l'applicazione usa il plaintext decrittato come dati strutturati (e.g., `role=user`), puoi flipare bit specifici per cambiare byte selezionati del plaintext in una posizione scelta nel blocco successivo.

Schema tipico CTF:

- Token = `IV || C1 || C2 || ...`
- Controlli i byte in `C[i]`
- Miri ai byte del plaintext in `P[i+1]` perché `P[i+1] = D(C[i+1]) XOR C[i]`

Questo non è di per sé una violazione della riservatezza, ma è una primitiva comune di escalation di privilegi quando manca l'integrità.

## CBC-MAC

CBC-MAC è sicuro solo sotto condizioni specifiche (notably **fixed-length messages** e corretta separazione dei domini).

### Schema classico di forgery a lunghezza variabile

CBC-MAC è solitamente calcolato come:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se puoi ottenere tag per messaggi scelti, spesso puoi creare un tag per una concatenazione (o costruzione correlata) senza conoscere la chiave, sfruttando come CBC concatena i blocchi.

Questo appare frequentemente in cookie/token CTF che MAC-ano username o role con CBC-MAC.

### Alternative più sicure

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Cifrari a flusso: XOR and RC4

### Modello mentale

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

Quindi:

- Se conosci il plaintext, recuperi il keystream.
- Se il keystream viene riutilizzato (stessa key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Crittografia basata su XOR

Se conosci qualsiasi segmento di plaintext alla posizione `i`, puoi recuperare i byte del keystream e decrittare altri ciphertext in quelle posizioni.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 è un cifrario a flusso; encrypt/decrypt sono la stessa operazione.

Se puoi ottenere la cifratura RC4 di plaintext conosciuto con la stessa key, puoi recuperare il keystream e decrittare altri messaggi della stessa lunghezza/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Riferimenti

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
