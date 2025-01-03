{{#include ../banners/hacktricks-training.md}}

# ECB

(ECB) Electronic Code Book - schema di crittografia simmetrica che **sostituisce ogni blocco del testo in chiaro** con il **blocco di testo cifrato**. È il **schema di crittografia più semplice**. L'idea principale è di **dividere** il testo in chiaro in **blocchi di N bit** (dipende dalla dimensione del blocco di dati in input, algoritmo di crittografia) e poi crittografare (decrittografare) ogni blocco di testo in chiaro utilizzando l'unica chiave.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

L'uso di ECB ha molteplici implicazioni di sicurezza:

- **I blocchi del messaggio crittografato possono essere rimossi**
- **I blocchi del messaggio crittografato possono essere spostati**

# Rilevamento della vulnerabilità

Immagina di accedere a un'applicazione più volte e di **ricevere sempre lo stesso cookie**. Questo perché il cookie dell'applicazione è **`<username>|<password>`**.\
Poi, generi due nuovi utenti, entrambi con la **stessa lunga password** e **quasi** lo **stesso** **username**.\
Scopri che i **blocchi di 8B** dove le **info di entrambi gli utenti** sono le stesse sono **uguali**. Poi, immagini che questo potrebbe essere dovuto al fatto che **si sta utilizzando ECB**.

Come nel seguente esempio. Osserva come questi **2 cookie decodificati** hanno più volte il blocco **`\x23U\xE45K\xCB\x21\xC8`**.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Questo è perché il **nome utente e la password di quei cookie contenevano diverse volte la lettera "a"** (per esempio). I **blocchi** che sono **diversi** sono blocchi che contenevano **almeno 1 carattere diverso** (forse il delimitatore "|" o qualche differenza necessaria nel nome utente).

Ora, l'attaccante deve solo scoprire se il formato è `<username><delimiter><password>` o `<password><delimiter><username>`. Per farlo, può semplicemente **generare diversi nomi utente** con **nomi utente e password simili e lunghi fino a trovare il formato e la lunghezza del delimitatore:**

| Lunghezza nome utente: | Lunghezza password: | Lunghezza Nome Utente+Password: | Lunghezza cookie (dopo decodifica): |
| ---------------------- | ------------------- | ------------------------------- | ----------------------------------- |
| 2                      | 2                   | 4                               | 8                                   |
| 3                      | 3                   | 6                               | 8                                   |
| 3                      | 4                   | 7                               | 8                                   |
| 4                      | 4                   | 8                               | 16                                  |
| 7                      | 7                   | 14                              | 16                                  |

# Sfruttamento della vulnerabilità

## Rimozione di interi blocchi

Conoscendo il formato del cookie (`<username>|<password>`), per impersonare il nome utente `admin`, crea un nuovo utente chiamato `aaaaaaaaadmin` e ottieni il cookie e decodificalo:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Possiamo vedere il modello `\x23U\xE45K\xCB\x21\xC8` creato in precedenza con il nome utente che conteneva solo `a`.\
Poi, puoi rimuovere il primo blocco di 8B e otterrai un cookie valido per il nome utente `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Spostare blocchi

In molti database è lo stesso cercare `WHERE username='admin';` o `WHERE username='admin    ';` _(Nota gli spazi extra)_

Quindi, un altro modo per impersonare l'utente `admin` sarebbe:

- Generare un nome utente che: `len(<username>) + len(<delimiter) % len(block)`. Con una dimensione del blocco di `8B` puoi generare un nome utente chiamato: `username       `, con il delimitatore `|` il chunk `<username><delimiter>` genererà 2 blocchi di 8Bs.
- Poi, generare una password che riempirà un numero esatto di blocchi contenenti il nome utente che vogliamo impersonare e spazi, come: `admin   `

Il cookie di questo utente sarà composto da 3 blocchi: i primi 2 sono i blocchi del nome utente + delimitatore e il terzo è della password (che sta fingendo il nome utente): `username       |admin   `

**Poi, basta sostituire il primo blocco con l'ultimo e si impersonerà l'utente `admin`: `admin          |username`**

## Riferimenti

- [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](<http://cryptowiki.net/index.php?title=Electronic_Code_Book_(ECB)>)

{{#include ../banners/hacktricks-training.md}}
