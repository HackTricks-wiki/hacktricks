# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Introduzione

Per maggiori informazioni sul funzionamento dei tag a 125kHz, consultare:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Azioni

Per maggiori informazioni su questi tipi di tag, [**leggi questa introduzione**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Leggi

Tenta di **leggere** le informazioni della card. Dopodiché può **emularla**.<sup>[[1]](#references)</sup>

> [!WARNING]
> Nota che alcuni citofoni cercano di proteggersi dalla duplicazione delle chiavi inviando un comando di scrittura prima della lettura. Se la scrittura va a buon fine, il tag viene considerato falso. Quando Flipper emula l'RFID, non c'è modo per il reader di distinguerlo da quello originale, quindi questi problemi non si verificano.

### Aggiungi manualmente

Puoi creare **card false in Flipper Zero indicando manualmente i dati** e poi emularle.

#### ID sulle card

A volte, quando si riceve una card, si trova l'ID (o una parte di esso) scritto e visibile sulla card.

- **EM Marin**

Ad esempio, in questa card EM-Marin fisica è possibile **leggere in chiaro gli ultimi 3 di 5 byte**.\
Gli altri 2 possono essere sottoposti a brute-force se non è possibile leggerli dalla card.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Lo stesso accade in questa card HID, in cui è possibile trovare stampati sulla card solo 2 byte su 3.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emula/Scrivi

Dopo aver **copiato** una card o aver **inserito** manualmente l'ID, è possibile **emularla** con Flipper Zero o **scriverla** su una card reale.<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
