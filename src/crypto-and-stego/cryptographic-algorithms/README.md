# Algoritmi di Crittografia/Compressione

## Algoritmi di Crittografia/Compressione

{{#include ../../banners/hacktricks-training.md}}

## Identificazione degli Algoritmi

Se si termina in un codice **che utilizza shift a destra e a sinistra, xors e diverse operazioni aritmetiche** è altamente probabile che sia l'implementazione di un **algoritmo crittografico**. Qui verranno mostrati alcuni modi per **identificare l'algoritmo utilizzato senza dover invertire ogni passaggio**.

### Funzioni API

**CryptDeriveKey**

Se questa funzione è utilizzata, puoi scoprire quale **algoritmo è in uso** controllando il valore del secondo parametro:

![](<../../images/image (156).png>)

Controlla qui la tabella degli algoritmi possibili e i loro valori assegnati: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprimi e decomprimi un dato buffer.

**CryptAcquireContext**

Dai [documenti](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): La funzione **CryptAcquireContext** è utilizzata per acquisire un handle a un particolare contenitore di chiavi all'interno di un particolare fornitore di servizi crittografici (CSP). **Questo handle restituito è utilizzato nelle chiamate alle funzioni CryptoAPI** che utilizzano il CSP selezionato.

**CryptCreateHash**

Inizia l'hashing di un flusso di dati. Se questa funzione è utilizzata, puoi scoprire quale **algoritmo è in uso** controllando il valore del secondo parametro:

![](<../../images/image (549).png>)

\
Controlla qui la tabella degli algoritmi possibili e i loro valori assegnati: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Costanti di codice

A volte è davvero facile identificare un algoritmo grazie al fatto che deve utilizzare un valore speciale e unico.

![](<../../images/image (833).png>)

Se cerchi la prima costante su Google, questo è ciò che ottieni:

![](<../../images/image (529).png>)

Pertanto, puoi assumere che la funzione decompilata sia un **calcolatore sha256.**\
Puoi cercare qualsiasi altra costante e otterrai (probabilmente) lo stesso risultato.

### info sui dati

Se il codice non ha alcuna costante significativa, potrebbe essere **in caricamento di informazioni dalla sezione .data**.\
Puoi accedere a quei dati, **raggruppare il primo dword** e cercarlo su Google come abbiamo fatto nella sezione precedente:

![](<../../images/image (531).png>)

In questo caso, se cerchi **0xA56363C6** puoi scoprire che è correlato alle **tabelle dell'algoritmo AES**.

## RC4 **(Crittografia Simmetrica)**

### Caratteristiche

È composto da 3 parti principali:

- **Fase di inizializzazione/**: Crea una **tabella di valori da 0x00 a 0xFF** (256 byte in totale, 0x100). Questa tabella è comunemente chiamata **Substitution Box** (o SBox).
- **Fase di mescolamento**: Eseguirà un **ciclo attraverso la tabella** creata prima (ciclo di 0x100 iterazioni, di nuovo) modificando ciascun valore con byte **semi-casuali**. Per creare questi byte semi-casuali, viene utilizzata la **chiave RC4**. Le **chiavi RC4** possono essere **tra 1 e 256 byte di lunghezza**, tuttavia di solito si raccomanda che siano superiori a 5 byte. Comunemente, le chiavi RC4 sono lunghe 16 byte.
- **Fase XOR**: Infine, il testo in chiaro o il testo cifrato è **XORato con i valori creati prima**. La funzione per crittografare e decrittografare è la stessa. Per questo, verrà eseguito un **ciclo attraverso i 256 byte creati** tante volte quanto necessario. Questo è solitamente riconosciuto in un codice decompilato con un **%256 (mod 256)**.

> [!NOTE]
> **Per identificare un RC4 in un codice disassemblato/decompilato puoi controllare 2 cicli di dimensione 0x100 (con l'uso di una chiave) e poi un XOR dei dati di input con i 256 valori creati prima nei 2 cicli probabilmente usando un %256 (mod 256)**

### **Fase di Inizializzazione/Substitution Box:** (Nota il numero 256 usato come contatore e come uno 0 è scritto in ciascun posto dei 256 caratteri)

![](<../../images/image (584).png>)

### **Fase di Mescolamento:**

![](<../../images/image (835).png>)

### **Fase XOR:**

![](<../../images/image (904).png>)

## **AES (Crittografia Simmetrica)**

### **Caratteristiche**

- Uso di **scatole di sostituzione e tabelle di ricerca**
- È possibile **distinguere AES grazie all'uso di valori specifici delle tabelle di ricerca** (costanti). _Nota che la **costante** può essere **memorizzata** nel binario **o creata** _**dinamicamente**._
- La **chiave di crittografia** deve essere **divisibile** per **16** (di solito 32B) e di solito viene utilizzato un **IV** di 16B.

### Costanti SBox

![](<../../images/image (208).png>)

## Serpent **(Crittografia Simmetrica)**

### Caratteristiche

- È raro trovare malware che lo utilizzi, ma ci sono esempi (Ursnif)
- Facile determinare se un algoritmo è Serpent o meno in base alla sua lunghezza (funzione estremamente lunga)

### Identificazione

Nell'immagine seguente nota come la costante **0x9E3779B9** è utilizzata (nota che questa costante è utilizzata anche da altri algoritmi crittografici come **TEA** -Tiny Encryption Algorithm).\
Nota anche la **dimensione del ciclo** (**132**) e il **numero di operazioni XOR** nelle **istruzioni di disassemblaggio** e nell'**esempio di codice**:

![](<../../images/image (547).png>)

Come accennato in precedenza, questo codice può essere visualizzato all'interno di qualsiasi decompilatore come una **funzione molto lunga** poiché **non ci sono salti** al suo interno. Il codice decompilato può apparire come segue:

![](<../../images/image (513).png>)

Pertanto, è possibile identificare questo algoritmo controllando il **numero magico** e i **XOR iniziali**, vedendo una **funzione molto lunga** e **confrontando** alcune **istruzioni** della lunga funzione **con un'implementazione** (come lo shift a sinistra di 7 e la rotazione a sinistra di 22).

## RSA **(Crittografia Asimmetrica)**

### Caratteristiche

- Più complesso degli algoritmi simmetrici
- Non ci sono costanti! (le implementazioni personalizzate sono difficili da determinare)
- KANAL (un analizzatore crittografico) non riesce a mostrare indizi su RSA poiché si basa su costanti.

### Identificazione per confronti

![](<../../images/image (1113).png>)

- Nella riga 11 (sinistra) c'è un `+7) >> 3` che è lo stesso della riga 35 (destra): `+7) / 8`
- La riga 12 (sinistra) controlla se `modulus_len < 0x040` e nella riga 36 (destra) controlla se `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Caratteristiche

- 3 funzioni: Init, Update, Final
- Funzioni di inizializzazione simili

### Identificazione

**Init**

Puoi identificare entrambi controllando le costanti. Nota che sha_init ha 1 costante che MD5 non ha:

![](<../../images/image (406).png>)

**MD5 Transform**

Nota l'uso di più costanti

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Più piccolo e più efficiente poiché la sua funzione è trovare cambiamenti accidentali nei dati
- Usa tabelle di ricerca (quindi puoi identificare costanti)

### Identificazione

Controlla **costanti della tabella di ricerca**:

![](<../../images/image (508).png>)

Un algoritmo hash CRC appare come:

![](<../../images/image (391).png>)

## APLib (Compressione)

### Caratteristiche

- Costanti non riconoscibili
- Puoi provare a scrivere l'algoritmo in python e cercare cose simili online

### Identificazione

Il grafico è piuttosto grande:

![](<../../images/image (207) (2) (1).png>)

Controlla **3 confronti per riconoscerlo**:

![](<../../images/image (430).png>)

{{#include ../../banners/hacktricks-training.md}}
