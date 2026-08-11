# Crittografia simmetrica

{{#include ../../banners/hacktricks-training.md}}

## Cosa cercare nei CTF

- **Uso improprio delle modalità**: pattern ECB, malleabilità CBC, riutilizzo del nonce in CTR/GCM.
- **Padding oracle**: errori o timing diversi per padding errato.
- **Confusione MAC**: uso di CBC-MAC con messaggi di lunghezza variabile o errori nel modello MAC-then-encrypt.
- **XOR ovunque**: gli stream cipher e le costruzioni personalizzate spesso si riducono a un XOR con un keystream.

## Modalità AES e uso improprio

NIST specifica le modalità di riservatezza ECB, CBC e CTR in SP 800-38A e la authenticated encryption GCM in SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB fa trapelare i pattern: blocchi di plaintext uguali → blocchi di ciphertext uguali. Questo consente:

- Cut-and-paste / riordinamento dei blocchi
- Eliminazione dei blocchi (se il formato rimane valido)

Se puoi controllare il plaintext e osservare il ciphertext (o i cookie), prova a creare blocchi ripetuti (ad esempio molte `A`) e cerca le ripetizioni.

### CBC: Cipher Block Chaining

- CBC è **malleable**: invertire bit in `C[i-1]` inverte bit prevedibili in `P[i]`, corrompendo anche `P[i-1]`. Modificare l'IV permette di mirare al primo blocco di plaintext senza corrompere un blocco di plaintext precedente.
- Se il sistema espone la differenza tra padding valido e non valido, potresti avere un **padding oracle**.

### CTR

CTR trasforma AES in uno stream cipher: `C = P XOR keystream`.

Se un nonce/IV viene riutilizzato con la stessa chiave:

- `C1 XOR C2 = P1 XOR P2` (classico riutilizzo del keystream)
- Con plaintext noto, puoi recuperare il keystream e decrittografare gli altri dati.

**Pattern di sfruttamento del riutilizzo del nonce/IV**

- Recupera il keystream ovunque il plaintext sia noto o prevedibile:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Applica i byte del keystream recuperati per decrittografare qualsiasi altro ciphertext prodotto con la stessa chiave+IV alle stesse posizioni.
- I dati altamente strutturati (ad esempio certificati ASN.1/X.509, intestazioni di file, JSON/CBOR) forniscono ampie regioni di plaintext noto. Spesso puoi eseguire l'XOR tra il ciphertext del certificato e il corpo prevedibile del certificato per derivare il keystream, quindi decrittografare altri segreti cifrati con l'IV riutilizzato. Vedi anche [TLS & Certificates](../tls-and-certificates/README.md) per i layout tipici dei certificati.<sup>[[1]](#references)</sup>
- Quando più segreti dello **stesso formato/dimensione serializzato** vengono cifrati con la stessa chiave+IV, l'allineamento dei campi fa trapelare informazioni anche senza un plaintext completamente noto. Esempio: le chiavi RSA PKCS#8 con moduli della stessa dimensione collocano i fattori primi agli stessi offset (allineamento di circa il 99,6% per chiavi a 2048 bit). Eseguendo l'XOR di due ciphertext sotto il keystream riutilizzato si isola `p ⊕ p'` / `q ⊕ q'`, che può essere recuperato con brute force in pochi secondi.<sup>[[1]](#references)</sup>
- Gli IV predefiniti nelle librerie (ad esempio la costante `000...01`) sono un grave footgun: ogni cifratura ripete lo stesso keystream, trasformando CTR in un one-time pad riutilizzato.<sup>[[1]](#references)</sup>

**Malleabilità CTR**

- CTR fornisce solo riservatezza: invertire bit nel ciphertext inverte deterministicamente gli stessi bit nel plaintext. Senza un authentication tag, gli attaccanti possono manomettere i dati (ad esempio modificare chiavi, flag o messaggi) senza essere rilevati.
- Usa AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, ecc.) e applica la verifica del tag per rilevare i bit-flip.

### GCM

GCM si rompe gravemente anche in caso di riutilizzo del nonce. Se la stessa chiave+nonce viene usata più di una volta, in genere si ottiene:

- Riutilizzo del keystream per la cifratura (come in CTR), che consente di recuperare il plaintext quando un qualsiasi plaintext è noto.
- Perdita delle garanzie di integrità. A seconda di ciò che viene esposto (più coppie messaggio/tag sotto lo stesso nonce), gli attaccanti potrebbero essere in grado di falsificare i tag.

Indicazioni operative:

- Considera il "riutilizzo del nonce" in AEAD una vulnerabilità critica.
- Gli AEAD resistenti agli errori d'uso, come AES-GCM-SIV, riducono le conseguenze del riutilizzo del nonce. I chiamanti devono comunque fornire nonce unici come richiesto dall'interfaccia della costruzione; il riutilizzo accidentale ha conseguenze limitate rispetto al GCM ordinario.<sup>[[3]](#references)[[4]](#references)</sup>
- Se hai più ciphertext con lo stesso nonce, inizia controllando relazioni del tipo `C1 XOR C2 = P1 XOR P2`.

### Strumenti

- [CyberChef](https://gchq.github.io/CyberChef/) per esperimenti rapidi.<sup>[[8]](#references)</sup>
- Il package Python [PyCryptodome](https://www.pycryptodome.org/) per lo scripting.<sup>[[9]](#references)</sup>

## Pattern di sfruttamento ECB

ECB (Electronic Code Book) cifra ogni blocco indipendentemente:

- blocchi di plaintext uguali → blocchi di ciphertext uguali
- questo fa trapelare la struttura e consente attacchi di tipo cut-and-paste

![Diagramma a blocchi della decrittografia in modalità ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea per il rilevamento: pattern di token/cookie

Se effettui il login diverse volte e **ottieni sempre lo stesso cookie**, il ciphertext potrebbe essere deterministico (ECB o IV fisso).

Se crei due utenti con layout del plaintext per lo più identici (ad esempio con caratteri ripetuti per una lunghezza elevata) e osservi blocchi di ciphertext ripetuti agli stessi offset, ECB è il principale sospettato.

### Pattern di sfruttamento

#### Rimozione di interi blocchi

Se il formato del token è qualcosa come `<username>|<password>` e il confine del blocco è allineato, a volte puoi creare un utente in modo che il blocco `admin` sia allineato, quindi rimuovere i blocchi precedenti per ottenere un token valido per `admin`.

#### Spostamento dei blocchi

Se il backend tollera il padding/spazi aggiuntivi (`admin` vs `admin    `), puoi:

- Allineare un blocco che contiene `admin   `
- Scambiare/riutilizzare quel blocco di ciphertext in un altro token

## Padding Oracle

### Cos'è

In modalità CBC, se il server rivela (direttamente o indirettamente) se il plaintext decrittografato ha un **padding PKCS#7 valido**, spesso puoi:<sup>[[7]](#references)</sup>

- Decrittografare il ciphertext senza la chiave
- Costruire un ciphertext che viene decrittografato in un plaintext scelto, quando puoi inviare blocchi precedenti o IV creati ad hoc e l'applicazione accetta il messaggio risultante con padding valido

L'oracle può essere:

- Un messaggio di errore specifico
- Uno status HTTP / una dimensione della risposta diversi
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

Anche senza un padding oracle, CBC è malleabile. Se puoi modificare i blocchi di ciphertext e l'applicazione usa il plaintext decrittato come dati strutturati (ad esempio, `role=user`), puoi invertire bit specifici per modificare determinati byte del plaintext in una posizione scelta del blocco successivo.

Pattern tipico nei CTF:

- Token = `IV || C1 || C2 || ...`
- Controlli i byte in `C[i]`
- Prendi di mira i byte del plaintext in `P[i+1]` perché `P[i+1] = D(C[i+1]) XOR C[i]`

Questo di per sé non costituisce una violazione della confidenzialità, ma è una primitiva comune per l'escalation dei privilegi quando manca l'integrità.

## CBC-MAC

CBC-MAC è sicuro solo in condizioni specifiche (in particolare **messaggi di lunghezza fissa** e corretta separazione del dominio). AES-CMAC è una costruzione standardizzata che gestisce in modo sicuro gli input di lunghezza variabile.<sup>[[5]](#references)</sup>

### Pattern classico di forgery con lunghezza variabile

CBC-MAC viene generalmente calcolato come:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se puoi ottenere tag per messaggi scelti, spesso puoi creare un tag per una concatenazione (o una costruzione correlata) senza conoscere la key, sfruttando il modo in cui CBC concatena i blocchi.

Questo compare frequentemente nei cookie/token dei CTF che applicano CBC-MAC a username o role.

### Alternative più sicure

- Usa HMAC (SHA-256/512)
- Usa CMAC (AES-CMAC) correttamente
- Includi la lunghezza del messaggio / la separazione del dominio

## Stream ciphers: XOR e RC4

### Il modello mentale

La maggior parte delle situazioni con stream cipher si riduce a:

`ciphertext = plaintext XOR keystream`

Quindi:

- Se conosci il plaintext, recuperi il keystream.
- Se il keystream viene riutilizzato (stessa key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Crittografia basata su XOR

Se conosci un segmento di plaintext nella posizione `i`, puoi recuperare i byte del keystream e decrittare altri ciphertext nelle stesse posizioni.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 è uno stream cipher legacy; cifratura e decifratura sono la stessa operazione XOR. I suoi bias noti lo rendono inadatto ai nuovi sistemi e TLS ne vieta esplicitamente le cipher suite.<sup>[[6]](#references)</sup>

Se riesci a ottenere la cifratura RC4 di un plaintext noto usando la stessa key, puoi recuperare il keystream e decrittare altri messaggi della stessa lunghezza/offset.

Writeup di riferimento (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Negligenza versus perizia nella crittografia](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Raccomandazione per le modalità operative dei cifrari a blocchi](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Raccomandazione per la modalità Galois/Counter (GCM) e GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Cifratura autenticata resistente all'uso improprio dei nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - L'algoritmo AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Proibizione delle cipher suite RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Test del Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Documentazione di PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
