{{#include ../banners/hacktricks-training.md}}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

# CBC - Cipher Block Chaining

In modalità CBC, il **blocco crittografato precedente viene utilizzato come IV** per XORare con il blocco successivo:

![https://defuse.ca/images/cbc_encryption.png](https://defuse.ca/images/cbc_encryption.png)

Per decrittografare CBC, vengono eseguite le **operazioni** **opposte**:

![https://defuse.ca/images/cbc_decryption.png](https://defuse.ca/images/cbc_decryption.png)

Nota come sia necessario utilizzare una **chiave** di **crittografia** e un **IV**.

# Messaggio Padding

Poiché la crittografia viene eseguita in **blocchi** di **dimensione** **fissa**, è solitamente necessario un **padding** nell'**ultimo** **blocco** per completarne la lunghezza.\
Di solito si utilizza **PKCS7**, che genera un padding **ripetendo** il **numero** di **byte** **necessari** per **completare** il blocco. Ad esempio, se l'ultimo blocco manca di 3 byte, il padding sarà `\x03\x03\x03`.

Esaminiamo più esempi con **2 blocchi di lunghezza 8byte**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Nota come nell'ultimo esempio l'**ultimo blocco era pieno, quindi ne è stato generato un altro solo con padding**.

# Padding Oracle

Quando un'applicazione decrittografa dati crittografati, prima decrittografa i dati; poi rimuove il padding. Durante la pulizia del padding, se un **padding non valido attiva un comportamento rilevabile**, hai una **vulnerabilità di padding oracle**. Il comportamento rilevabile può essere un **errore**, una **mancanza di risultati** o una **risposta più lenta**.

Se rilevi questo comportamento, puoi **decrittografare i dati crittografati** e persino **crittografare qualsiasi testo in chiaro**.

## Come sfruttare

Potresti utilizzare [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) per sfruttare questo tipo di vulnerabilità o semplicemente fare
```
sudo apt-get install padbuster
```
Per testare se il cookie di un sito è vulnerabile, potresti provare:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** significa che **base64** è utilizzato (ma sono disponibili altri, controlla il menu di aiuto).

Potresti anche **sfruttare questa vulnerabilità per crittografare nuovi dati. Ad esempio, immagina che il contenuto del cookie sia "**_**user=MyUsername**_**", quindi potresti cambiarlo in "\_user=administrator\_" e ottenere privilegi elevati all'interno dell'applicazione. Potresti anche farlo usando `paduster` specificando il parametro -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Se il sito è vulnerabile, `padbuster` proverà automaticamente a trovare quando si verifica l'errore di padding, ma puoi anche indicare il messaggio di errore utilizzando il parametro **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## La teoria

In **sintesi**, puoi iniziare a decrittare i dati crittografati indovinando i valori corretti che possono essere utilizzati per creare tutti i **diversi padding**. Poi, l'attacco padding oracle inizierà a decrittare i byte dalla fine all'inizio indovinando quale sarà il valore corretto che **crea un padding di 1, 2, 3, ecc**.

![](<../images/image (629) (1) (1).png>)

Immagina di avere del testo crittografato che occupa **2 blocchi** formati dai byte da **E0 a E15**.\
Per **decrittare** l'**ultimo** **blocco** (**E8** a **E15**), l'intero blocco passa attraverso la "decrittazione del blocco" generando i **byte intermedi I0 a I15**.\
Infine, ogni byte intermedio è **XORato** con i byte crittografati precedenti (E0 a E7). Quindi:

- `C15 = D(E15) ^ E7 = I15 ^ E7`
- `C14 = I14 ^ E6`
- `C13 = I13 ^ E5`
- `C12 = I12 ^ E4`
- ...

Ora, è possibile **modificare `E7` fino a quando `C15` è `0x01`**, che sarà anche un padding corretto. Quindi, in questo caso: `\x01 = I15 ^ E'7`

Quindi, trovando E'7, è **possibile calcolare I15**: `I15 = 0x01 ^ E'7`

Il che ci permette di **calcolare C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Sapendo **C15**, ora è possibile **calcolare C14**, ma questa volta forzando il padding `\x02\x02`.

Questo BF è complesso quanto il precedente poiché è possibile calcolare il `E''15` il cui valore è 0x02: `E''7 = \x02 ^ I15` quindi è solo necessario trovare il **`E'14`** che genera un **`C14` uguale a `0x02`**.\
Poi, segui gli stessi passaggi per decrittare C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Segui questa catena fino a decrittare l'intero testo crittografato.**

## Rilevamento della vulnerabilità

Registrati e accedi con questo account.\
Se **accedi molte volte** e ricevi sempre lo **stesso cookie**, probabilmente c'è **qualcosa** **sbagliato** nell'applicazione. Il **cookie restituito dovrebbe essere unico** ogni volta che accedi. Se il cookie è **sempre** lo **stesso**, probabilmente sarà sempre valido e non **ci sarà modo di invalidarlo**.

Ora, se provi a **modificare** il **cookie**, puoi vedere che ricevi un **errore** dall'applicazione.\
Ma se forzi il padding (usando padbuster per esempio) riesci a ottenere un altro cookie valido per un utente diverso. Questo scenario è altamente probabile che sia vulnerabile a padbuster.

## Riferimenti

- [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{{#include ../banners/hacktricks-training.md}}
