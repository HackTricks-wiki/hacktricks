# FZ - RFID a 125 kHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Per informazioni di base sul funzionamento dei tag a 125 kHz, vedere:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

L'[introduzione all'RFID a bassa frequenza](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) spiega le famiglie di tag più comuni e i relativi formati dei dati.

## Azioni

### Lettura

Usa **Read** per acquisire i dati del tag. Dopo una lettura riuscita, Flipper Zero può emulare il tag salvato.<sup>[[1]](#references)</sup>

> [!WARNING]
> Alcuni lettori di citofoni tentano di rilevare i tag duplicati scrivibili inviando un comando di scrittura prima della lettura. Un'emulazione di Flipper Zero non espone la memoria scrivibile del tag nello stesso modo.<sup>[[1]](#references)</sup>

### Aggiunta manuale

Puoi inserire manualmente i dati del tag in Flipper Zero, salvarli e quindi emularli.<sup>[[1]](#references)</sup>

#### ID sulle schede

A volte una scheda presenta tutto o parte del proprio ID stampato sulla superficie esterna.

- **EM Marin**

Ad esempio, la scheda EM-Marin mostrata espone gli ultimi tre dei suoi cinque byte dell'ID. Se non è possibile leggere il tag, i due byte mancanti possono essere sottoposti a brute-force.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Analogamente, la scheda HID mostrata riporta solo due dei tre byte dell'ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulazione/Scrittura

Dopo aver letto un tag o aver inserito manualmente il suo ID, Flipper Zero può emulare la credenziale salvata. Per i tag scrivibili supportati, può anche scrivere i dati salvati su una scheda compatibile.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Immersione nei protocolli RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
