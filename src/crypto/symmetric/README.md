# Crypto Simmetrica

{{#include ../../banners/hacktricks-training.md}}

## Cosa cercare nei CTF

- **Uso improprio della modalità**: pattern ECB, malleabilità CBC, riutilizzo del nonce in CTR/GCM.
- **Padding oracle**: errori/tempi diversi per padding non valido.
- **Confusione MAC**: utilizzo di CBC-MAC con messaggi di lunghezza variabile o errori nell'uso di MAC-then-encrypt.
- **XOR ovunque**: gli stream cipher e le costruzioni personalizzate spesso si riducono a un XOR con un keystream.

## Modalità AES e uso improprio

### ECB: Electronic Codebook

ECB fa trapelare i pattern: blocchi di plaintext uguali → blocchi di ciphertext uguali. Questo consente:

- Cut-and-paste / riordinamento dei blocchi
- Eliminazione di blocchi (se il formato rimane valido)

Se puoi controllare il plaintext e osservare il ciphertext (o i cookie), prova a creare blocchi ripetuti (ad esempio, molte `A`) e cerca le ripetizioni.

### CBC: Cipher Block Chaining

- CBC è **malleabile**: invertire bit in `C[i-1]` inverte bit prevedibili in `P[i]`.
- Se il sistema espone padding valido rispetto a padding non valido, potresti avere un **padding oracle**.

### CTR

CTR trasforma AES in uno stream cipher: `C = P XOR keystream`.

Se un nonce/IV viene riutilizzato con la stessa chiave:

- `C1 XOR C2 = P1 XOR P2` (classico riutilizzo del keystream)
- Con un plaintext noto, puoi recuperare il keystream e decrittare gli altri.

**Pattern di exploit del riutilizzo del nonce/IV**

- Recupera il keystream ovunque il plaintext sia noto o prevedibile:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Applica i byte del keystream recuperato per decrittare qualsiasi altro ciphertext prodotto con la stessa chiave+IV alle stesse posizioni.
- I dati altamente strutturati (ad esempio certificati ASN.1/X.509, header di file, JSON/CBOR) forniscono ampie regioni di plaintext noto. Spesso puoi fare XOR tra il ciphertext del certificato e il corpo prevedibile del certificato per derivare il keystream, quindi decrittare altri segreti cifrati usando l'IV riutilizzato. Vedi anche [TLS & Certificates](../tls-and-certificates/README.md) per i layout tipici dei certificati.<sup>[[1]](#references)</sup>
- Quando più segreti dello **stesso formato/dimensione serializzato** sono cifrati usando la stessa chiave+IV, l'allineamento dei campi fa trapelare informazioni anche senza un plaintext completamente noto. Esempio: le chiavi RSA PKCS#8 con moduli della stessa dimensione collocano i fattori primi agli stessi offset (allineamento di circa il 99,6% per 2048 bit). Eseguendo lo XOR di due ciphertext sotto il keystream riutilizzato si isola `p ⊕ p'` / `q ⊕ q'`, che può essere recuperato con brute force in pochi secondi.<sup>[[1]](#references)</sup>
- Gli IV predefiniti nelle librerie (ad esempio, il valore costante `000...01`) sono un errore critico: ogni cifratura ripete lo stesso keystream, trasformando CTR in un one-time pad riutilizzato.<sup>[[1]](#references)</sup>

**Malleabilità CTR**

- CTR fornisce solo confidenzialità: invertire bit nel ciphertext inverte deterministicamente gli stessi bit nel plaintext. Senza un authentication tag, gli attacker possono manomettere i dati (ad esempio modificare chiavi, flag o messaggi) senza essere rilevati.
- Usa AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, ecc.) e applica la verifica del tag per rilevare i bit-flip.

### GCM

Anche GCM si rompe gravemente in caso di riutilizzo del nonce. Se la stessa chiave+nonce viene utilizzata più di una volta, in genere ottieni:

- Riutilizzo del keystream per la cifratura (come in CTR), che consente il recupero del plaintext quando un qualsiasi plaintext è noto.
- Perdita delle garanzie di integrità. A seconda di ciò che viene esposto (più coppie messaggio/tag sotto lo stesso nonce), gli attacker potrebbero essere in grado di forgiare i tag.

Indicazioni operative:

- Considera il "riutilizzo del nonce" in AEAD una vulnerabilità critica.
- Gli AEAD resistenti al misuse (ad esempio GCM-SIV) riducono le conseguenze dell'uso improprio del nonce, ma richiedono comunque nonce/IV univoci.
- Se hai più ciphertext sotto lo stesso nonce, inizia verificando relazioni del tipo `C1 XOR C2 = P1 XOR P2`.

### Tool

- CyberChef per esperimenti rapidi: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` per lo scripting

## Pattern di exploit ECB

ECB (Electronic Code Book) cifra ogni blocco indipendentemente:

- blocchi di plaintext uguali → blocchi di ciphertext uguali
- questo fa trapelare la struttura e consente attacchi di tipo cut-and-paste

![Diagramma a blocchi della decrittazione in modalità ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea per il rilevamento: pattern di token/cookie

Se effettui il login diverse volte e **ottieni sempre lo stesso cookie**, il ciphertext potrebbe essere deterministico (ECB o IV fisso).

Se crei due utenti con layout del plaintext per lo più identici (ad esempio, lunghi caratteri ripetuti) e osservi blocchi di ciphertext ripetuti agli stessi offset, ECB è il principale sospettato.

### Pattern di exploit

#### Rimozione di blocchi interi

Se il formato del token è qualcosa come `<username>|<password>` e il confine del blocco è allineato, a volte puoi creare un utente in modo che il blocco `admin` risulti allineato, quindi rimuovere i blocchi precedenti per ottenere un token valido per `admin`.

#### Spostamento dei blocchi

Se il backend tollera padding/spazi extra (`admin` vs `admin    `), puoi:

- Allineare un blocco che contiene `admin   `
- Scambiare/riutilizzare quel blocco di ciphertext in un altro token

## Padding Oracle

### Cos'è

In modalità CBC, se il server rivela (direttamente o indirettamente) se il plaintext decrittato presenta un **padding PKCS#7 valido**, spesso puoi:

- Decrittare il ciphertext senza la chiave
- Cifrare un plaintext scelto (forgiare il ciphertext)

L'oracle può essere:

- Un messaggio di errore specifico
- Uno status HTTP / una dimensione della risposta diversi
- Una differenza nei tempi

### Exploit pratico

PadBuster è il tool classico:

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

Anche senza un padding oracle, CBC è malleabile. Se puoi modificare i blocchi di ciphertext e l'applicazione usa il plaintext decrittato come dati strutturati (ad esempio, `role=user`), puoi invertire bit specifici per modificare determinati byte del plaintext in una posizione scelta del blocco successivo.

Pattern tipico dei CTF:

- Token = `IV || C1 || C2 || ...`
- Controlli i byte in `C[i]`
- Prendi di mira i byte del plaintext in `P[i+1]` perché `P[i+1] = D(C[i+1]) XOR C[i]`

Questo non costituisce di per sé una violazione della confidenzialità, ma è una primitiva comune di privilege escalation quando manca l'integrità.

## CBC-MAC

CBC-MAC è sicuro solo in condizioni specifiche (in particolare **messaggi di lunghezza fissa** e una corretta separazione dei domini).

### Pattern classico di forgery con lunghezza variabile

CBC-MAC viene solitamente calcolato come:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se puoi ottenere tag per messaggi scelti, spesso puoi creare un tag per una concatenazione (o una costruzione correlata) senza conoscere la chiave, sfruttando il modo in cui CBC concatena i blocchi.

Questo compare spesso nei cookie/token dei CTF che applicano CBC-MAC a username o role.

### Alternative più sicure

- Usa HMAC (SHA-256/512)
- Usa CMAC (AES-CMAC) correttamente
- Includi la lunghezza del messaggio / la separazione dei domini

## Cifrari a flusso: XOR e RC4

### Il modello mentale

La maggior parte degli scenari con cifrari a flusso si riduce a:

`ciphertext = plaintext XOR keystream`

Quindi:

- Se conosci il plaintext, recuperi il keystream.
- Se il keystream viene riutilizzato (stessa chiave+nonce), `C1 XOR C2 = P1 XOR P2`.

### Crittografia basata su XOR

Se conosci un segmento di plaintext nella posizione `i`, puoi recuperare i byte del keystream e decrittare altri ciphertext nelle stesse posizioni.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 è un cifrario a flusso; encrypt/decrypt sono la stessa operazione.

Se puoi ottenere la crittografia RC4 di un plaintext noto usando la stessa chiave, puoi recuperare il keystream e decrittare altri messaggi della stessa lunghezza/offset.

Writeup di riferimento (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Riferimenti

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
