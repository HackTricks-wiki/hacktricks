# Crypto simmetrica

{{#include ../../banners/hacktricks-training.md}}

## Cosa cercare nei CTF

- **Uso improprio delle modalità**: pattern ECB, malleabilità CBC, riutilizzo dei nonce in CTR/GCM.
- **Padding oracle**: errori o tempi diversi in caso di padding non valido.
- **Confusione sui MAC**: uso di CBC-MAC con messaggi di lunghezza variabile o errori nel metodo MAC-then-encrypt.
- **XOR ovunque**: i cifrari a flusso e le costruzioni personalizzate spesso si riducono a uno XOR con un keystream.

## Modalità AES e uso improprio

NIST specifica le modalità di cifratura ECB, CBC e CTR in SP 800-38A e la cifratura autenticata GCM in SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB rivela i pattern: blocchi di testo in chiaro uguali → blocchi di testo cifrato uguali. Questo consente di:

- Tagliare e incollare / riordinare i blocchi
- Eliminare blocchi (se il formato rimane valido)

Se puoi controllare il testo in chiaro e osservare il testo cifrato (o i cookie), prova a creare blocchi ripetuti (ad esempio, molte `A`) e cerca le ripetizioni.

### CBC: Cipher Block Chaining

- CBC è **malleabile**: invertire dei bit in `C[i-1]` inverte bit prevedibili in `P[i]`, alterando però anche `P[i-1]`. Modificare l'IV permette di intervenire sul primo blocco di testo in chiaro senza alterare un blocco di testo in chiaro precedente.
- Se il sistema distingue tra padding valido e non valido, potresti avere un **padding oracle**.

### CTR

CTR trasforma AES in un cifrario a flusso: `C = P XOR keystream`.

Se un nonce/IV viene riutilizzato con la stessa chiave:

- `C1 XOR C2 = P1 XOR P2` (il classico riutilizzo del keystream)
- Con testo in chiaro noto, puoi recuperare il keystream e decifrare altri messaggi.

**Pattern di sfruttamento del riutilizzo del nonce/IV**

- Recupera il keystream nei punti in cui il testo in chiaro è noto o prevedibile:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Applica i byte del keystream recuperati per decrittare qualsiasi altro ciphertext prodotto con la stessa key+IV agli stessi offset.
- I dati altamente strutturati (ad es. certificati ASN.1/X.509, header di file, JSON/CBOR) offrono ampie porzioni di plaintext noto. Spesso puoi fare XOR tra il ciphertext del certificato e il corpo prevedibile del certificato per ricavare il keystream, quindi decrittare altri segreti cifrati con l’IV riutilizzato. Vedi anche [TLS & Certificates](../tls-and-certificates/README.md) per gli schemi tipici dei certificati.<sup>[[1]](#references)</sup>
- Quando più segreti con lo **stesso formato/dimensione di serializzazione** sono cifrati con la stessa key+IV, l’allineamento dei campi provoca leak anche senza conoscere tutto il plaintext. Ad esempio, le chiavi RSA PKCS#8 con la stessa dimensione del modulo collocano i fattori primi a offset corrispondenti (allineamento di circa il 99,6% per chiavi a 2048 bit). Fare XOR tra due ciphertext cifrati con il keystream riutilizzato isola `p ⊕ p'` / `q ⊕ q'`, che si possono recuperare con brute force in pochi secondi.<sup>[[1]](#references)</sup>
- Gli IV predefiniti nelle librerie (ad es. la costante `000...01`) sono una trappola critica: ogni cifratura riutilizza lo stesso keystream, trasformando CTR in un one-time pad riutilizzato.<sup>[[1]](#references)</sup>

**Malleabilità di CTR**

- CTR offre solo riservatezza: invertendo bit nel ciphertext, gli stessi bit vengono invertiti deterministicamente nel plaintext. Senza un tag di autenticazione, gli attaccanti possono modificare i dati (ad es. alterare chiavi, flag o messaggi) senza essere rilevati.
- Usa AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 ecc.) e verifica il tag per rilevare le modifiche ai bit.

### GCM

Anche GCM si compromette gravemente se si riutilizza il nonce. Se la stessa key+nonce viene usata più di una volta, in genere si ottiene:

- Riutilizzo del keystream per la cifratura (come in CTR), che permette di recuperare il plaintext quando se ne conosce una parte.
- Perdita delle garanzie di integrità. A seconda di ciò che viene esposto (più coppie messaggio/tag con lo stesso nonce), gli attaccanti potrebbero riuscire a falsificare i tag.

Indicazioni operative:

- Considera il "riutilizzo del nonce" in AEAD una vulnerabilità critica.
- Le AEAD resistenti all’uso improprio, come AES-GCM-SIV, riducono le conseguenze del riutilizzo del nonce. I chiamanti devono comunque fornire nonce univoci, come richiesto dall’interfaccia della costruzione; il riutilizzo accidentale ha conseguenze limitate rispetto al GCM standard.<sup>[[3]](#references)[[4]](#references)</sup>
- Se hai più ciphertext con lo stesso nonce, inizia verificando relazioni del tipo `C1 XOR C2 = P1 XOR P2`.

### Strumenti

- [CyberChef](https://gchq.github.io/CyberChef/) per esperimenti rapidi.<sup>[[8]](#references)</sup>
- Il pacchetto [PyCryptodome](https://www.pycryptodome.org/) di Python per scrivere script.<sup>[[9]](#references)</sup>

## Schemi di sfruttamento ECB

ECB (Electronic Code Book) cifra ogni blocco in modo indipendente:

- blocchi di plaintext uguali → ciphertext uguali
- questo rivela la struttura e permette attacchi di tipo cut-and-paste

![Diagramma a blocchi della decrittazione in modalità ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea per il rilevamento: schema di token/cookie

Se effettui il login più volte e **ottieni sempre lo stesso cookie**, il ciphertext potrebbe essere deterministico (ECB o IV fisso).

Se crei due utenti con layout del plaintext quasi identici (ad es. lunghe sequenze di caratteri ripetuti) e noti blocchi di ciphertext ripetuti agli stessi offset, ECB è un forte sospettato.

### Schemi di sfruttamento

#### Rimozione di blocchi interi

Se il formato del token è qualcosa come `<username>|<password>` e il confine del blocco è allineato, a volte puoi creare un utente in modo che il blocco `admin` risulti allineato, quindi rimuovere i blocchi precedenti per ottenere un token valido per `admin`.

#### Spostamento di blocchi

Se il backend accetta padding/spazi aggiuntivi (`admin` vs `admin    `), puoi:

- Allineare un blocco contenente `admin   `
- Scambiare/riutilizzare quel blocco di ciphertext in un altro token

## Padding Oracle

### Cos’è

In modalità CBC, se il server rivela (direttamente o indirettamente) se il plaintext decrittato ha un **padding PKCS#7 valido**, spesso puoi:<sup>[[7]](#references)</sup>

- Decrittare ciphertext senza la chiave
- Costruire un ciphertext che venga decrittato in un plaintext scelto, quando puoi inviare blocchi precedenti o IV creati ad hoc e l’applicazione accetta il messaggio risultante con padding valido

L’oracle può manifestarsi come:

- Un messaggio di errore specifico
- Uno status HTTP o una dimensione della risposta diversi
- Una differenza nei tempi di risposta

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
- Usa `-error` se l’oracle restituisce una stringa specifica.

### Perché funziona

La decrittazione CBC calcola `P[i] = D(C[i]) XOR C[i-1]`. Modificando i byte in `C[i-1]` e osservando se il padding è valido, puoi recuperare `P[i]` un byte alla volta.

## Bit-flipping in CBC

Anche senza un padding oracle, CBC è malleabile. Se puoi modificare i blocchi di ciphertext e l’applicazione usa il plaintext decrittato come dato strutturato (ad es. `role=user`), puoi invertire specifici bit per cambiare determinati byte del plaintext in una posizione scelta del blocco successivo.

Schema tipico dei CTF:

- Token = `IV || C1 || C2 || ...`
- Controlli i byte in `C[i]`
- Modifichi i byte del plaintext in `P[i+1]` perché `P[i+1] = D(C[i+1]) XOR C[i]`

Questo, di per sé, non compromette la riservatezza, ma è una tecnica comune per l’escalation dei privilegi quando manca l’integrità.

## CBC-MAC

CBC-MAC è sicuro solo in condizioni specifiche (in particolare, **messaggi di lunghezza fissa** e corretta separazione dei domini). AES-CMAC è una costruzione standardizzata che gestisce in sicurezza input di lunghezza variabile.<sup>[[5]](#references)</sup>

### Schema classico di forgery con lunghezza variabile

CBC-MAC viene solitamente calcolato così:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se riesci a ottenere i tag di messaggi scelti, spesso puoi creare un tag per una concatenazione (o una costruzione correlata) senza conoscere la chiave, sfruttando il modo in cui CBC concatena i blocchi.

Questo schema si presenta spesso nei cookie/token dei CTF che applicano CBC-MAC a username o ruolo.

### Alternative più sicure

- Usa HMAC (SHA-256/512)
- Usa correttamente CMAC (AES-CMAC)
- Includi la lunghezza del messaggio / la separazione dei domini

## Cifrari a flusso: XOR e RC4

### Il modello mentale

La maggior parte dei casi con cifrari a flusso si riduce a:

`ciphertext = plaintext XOR keystream`

Quindi:

- Se conosci il plaintext, recuperi il keystream.
- Se il keystream viene riutilizzato (stessa chiave+nonce), `C1 XOR C2 = P1 XOR P2`.

### Cifratura basata su XOR

Se conosci un segmento di plaintext alla posizione `i`, puoi recuperare i byte del keystream e decrittare altri ciphertext nelle stesse posizioni.

Autosolver:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 è un cifrario a flusso obsoleto; cifratura e decifratura consistono nella stessa operazione XOR. I bias noti lo rendono inadatto ai nuovi sistemi e TLS vieta esplicitamente le sue suite di cifratura.<sup>[[6]](#references)</sup>

Se riesci a ottenere la cifratura RC4 di un plaintext noto usando la stessa chiave, puoi recuperare il keystream e decrittare altri messaggi della stessa lunghezza/allo stesso offset.

Writeup di riferimento (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Disattenzione versus perizia in crittografia](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Raccomandazione per le modalità operative dei cifrari a blocchi](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Raccomandazione per Galois/Counter Mode (GCM) e GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: cifratura autenticata resistente al riutilizzo improprio del nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - L’algoritmo AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Divieto delle suite di cifratura RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Test per il padding oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Documentazione PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
