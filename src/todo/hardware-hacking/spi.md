# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

SPI (Serial Peripheral Interface) è un bus seriale sincrono comunemente utilizzato per la comunicazione a breve distanza tra circuiti integrati. Un controller fornisce il clock e seleziona una periferica, come una EEPROM, un sensore o un dispositivo di controllo, usando un segnale chip-select.<sup>[[1]](#references)</sup>

Più periferiche possono condividere le linee di clock e dati, normalmente con un chip-select separato per ogni periferica. Il controller orchestra i trasferimenti; normalmente le periferiche non comunicano direttamente tra loro attraverso il bus SPI. La polarità e il timing del chip-select dipendono dal dispositivo; la selezione active-low è comune, ma non universale. SPI non definisce discovery, indirizzamento, comandi o una singola lunghezza massima di trasferimento, quindi consultare sempre il datasheet del target.<sup>[[1]](#references)</sup>

MOSI/COPI trasporta i dati dal controller alla periferica, mentre MISO/CIPO trasporta i dati dalla periferica al controller. Entrambe le direzioni possono effettuare lo shift simultaneamente. La relazione tra un comando, un indirizzo, i dummy cycles e i dati restituiti è definita dalla periferica, non da SPI, e dipende dalla polarità e dalla fase del clock (modalità 0–3). Non bisogna presumere che l'output inizi esattamente un clock dopo la fine dell'input.<sup>[[1]](#references)</sup>

## Dump del Firmware dalle EEPROM

Il dumping del firmware può essere utile per analizzarlo e individuare vulnerabilità. L'immagine corretta potrebbe non essere disponibile online oppure potrebbe differire in base al modello, alla revisione hardware o alla versione; estrarla direttamente dal dispositivo fisico fornisce un target di assessment esatto.

Una console seriale può essere utile, ma il suo filesystem potrebbe essere read-only e il target potrebbe non disporre degli strumenti di analisi, incluse le utility necessarie per inviare/ricevere traffico di test o estrarre comodamente i binari. Un'immagine offline conserva il layout completo della flash e consente l'estrazione del filesystem e il reverse engineering senza modificare il target in esecuzione.

Durante un assessment fisico autorizzato, un dump verificato può inoltre supportare test controllati di modifica e reflash. Ciò include la modifica di file o l'iniezione di un payload/backdoor di test per dimostrare la persistenza a livello firmware. Conservare più letture corrispondenti e l'immagine originale prima di qualsiasi scrittura: una tensione, una selezione del chip, un layout o un'immagine errati possono brickare il dispositivo.

### CH341A EEPROM Programmer and Reader

Questo strumento USB economico può effettuare il dump e il reflash di dispositivi EEPROM seriali e SPI flash compatibili. Viene comunemente utilizzato con i chip SPI NOR flash che memorizzano il firmware BIOS/UEFI dei PC ed è pratico durante un accesso fisico con tempo limitato.

![disegno](../../images/board_image_ch341a.jpg)

Collegare la memoria flash al CH341A e quindi collegare il programmer al computer. Se il programmer stesso non viene rilevato, controllare il cavo USB, i permessi del sistema operativo e il driver CH341A appropriato prima di eseguire il troubleshooting del chip target. Verificare la tensione del chip, il pin 1, il cablaggio dell'adattatore e l'output del programmer tramite i datasheet o un multimetro: **non** affidarsi a una regola come quella di posizionare VCC sul lato opposto al connettore USB. Un orientamento errato o l'applicazione di 5 V a un componente da 3,3/1,8 V possono distruggerlo. Le letture in-circuit possono inoltre fallire perché il resto della scheda carica o alimenta il bus.<sup>[[2]](#references)</sup>

![disegno](../../images/connect_wires_ch341a.jpg) ![disegno](../../images/eeprom_plugged_ch341a.jpg)

Utilizzare software come `flashrom` o G-Flash per leggere il chip. G-Flash è una GUI minimale e può rilevare automaticamente i dispositivi compatibili, caratteristica utile durante una rapida acquisizione, ma è necessario confermare autonomamente il modello rilevato e la tensione. Specificare il programmer esatto e, quando necessario, il modello esatto del chip; eseguire almeno due letture e confrontare i relativi hash prima di considerare affidabile un dump.<sup>[[2]](#references)</sup>

![disegno](../../images/connected_status_ch341a.jpg)

Dopo il dumping del firmware, l'analisi può essere eseguita sui file binari. Strumenti come strings, hexdump, xxd, binwalk, ecc. possono essere utilizzati per estrarre molte informazioni dal firmware e anche dall'intero filesystem.

Per il triage iniziale, Binwalk può eseguire la scansione alla ricerca di signature note ed estrarre i contenuti embedded supportati:
```
binwalk -e <filename>
```
L’estensione del file di output può essere `.bin`, `.rom` o un’altra; l’estensione non stabilisce il formato.

> [!CAUTION]
> Nota che l’estrazione del firmware è un processo delicato e richiede molta pazienza. Qualsiasi gestione impropria può potenzialmente corrompere il firmware o persino cancellarlo completamente, rendendo il dispositivo inutilizzabile. Si consiglia di studiare il dispositivo specifico prima di tentare di estrarre il firmware.

### Bus Pirate + flashrom

![Programmatore e lettore EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Alcuni datasheet indicano i pin di destinazione come `DI` e `DO`: per una connessione flash convenzionale con una singola linea dati, il controller **MOSI/COPI si collega a DI** e il controller **MISO/CIPO si collega a DO**. Verifica il datasheet del dispositivo di destinazione, perché i componenti con I/O dual/quad riutilizzano i pin in altre modalità.

![Programmatore e lettore EEPROM CH341A - Bus Pirate + flashrom: Nota che, anche se il PINOUT del Bus Pirate indica i pin MOSI e MISO da collegare a SPI, alcuni SPI possono...](<../../images/image (360).png>)

In Windows o Linux puoi usare il programma [**`flashrom`**](https://www.flashrom.org/Flashrom) per eseguire il dump del contenuto della memoria flash eseguendo un comando simile a:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
La documentazione recente di Bus Pirate mostra anche i parametri opzionali `serialspeed` e `spispeed`. Inizia in modo conservativo se i cavi lunghi o il carico del circuito rendono instabili le letture.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Introduzione all'interfaccia SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [manuale di flashrom — programmatore SPI CH341A e opzioni di lettura/scrittura](https://flashrom.org/classic_cli_manpage.html)
- [3] [documentazione di Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
