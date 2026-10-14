# FZ - RFID a 125 kHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Per informazioni di base sul funzionamento dei tag a 125 kHz, consulta:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

L'[introduzione agli RFID a bassa frequenza](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) spiega le famiglie di tag più comuni e i relativi formati di dati.

## Azioni

### Leggi

Usa **Leggi** per acquisire i dati del tag. Dopo una lettura riuscita, Flipper Zero può emulare il tag salvato.<sup>[[1]](#references)</sup>

> [!WARNING]
> Alcuni lettori per citofoni tentano di rilevare i tag duplicati riscrivibili inviando un comando di scrittura prima della lettura. L'emulazione di Flipper Zero non espone la memoria del tag riscrivibile allo stesso modo.<sup>[[1]](#references)</sup>

### Aggiungi manualmente

Puoi inserire manualmente i dati del tag in Flipper Zero, salvarli e poi emularlo.<sup>[[1]](#references)</sup>

#### ID sulle schede

A volte una scheda riporta tutto o parte del proprio ID sulla superficie esterna.

- **EM Marin**

Ad esempio, la scheda EM-Marin raffigurata mostra gli ultimi tre dei suoi cinque byte dell'ID. Se non è possibile leggere il tag, è possibile effettuare un brute-force sui due byte mancanti.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Allo stesso modo, la scheda HID raffigurata riporta solo due dei tre byte dell'ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emula/Scrivi

Dopo aver letto un tag o aver inserito manualmente il suo ID, Flipper Zero può emulare la credenziale salvata. Per i tag riscrivibili supportati, può anche scrivere i dati salvati su una scheda compatibile.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Approfondimento sui protocolli RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
