# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

SPI (Serial Peripheral Interface) è un bus seriale sincrono comunemente usato per la comunicazione a breve distanza tra circuiti integrati. Un controller fornisce il clock e seleziona una periferica, come una EEPROM, un sensore o un dispositivo di controllo, tramite un segnale chip-select.<sup>[[1]](#references)</sup>

Più periferiche possono condividere le linee di clock e dati, normalmente con un chip-select separato per ciascuna periferica. Il controller coordina i trasferimenti; normalmente le periferiche non comunicano direttamente tra loro tramite il bus SPI. La polarità e la temporizzazione del chip-select dipendono dal dispositivo; la selezione active-low è comune, ma non universale. SPI non definisce il rilevamento dei dispositivi, l'indirizzamento, i comandi o una lunghezza massima unica per i trasferimenti, quindi consulta sempre la datasheet del dispositivo target.<sup>[[1]](#references)</sup>

MOSI/COPI trasporta i dati dal controller alla periferica e MISO/CIPO trasporta i dati dalla periferica al controller. Entrambe le direzioni possono trasmettere contemporaneamente. La relazione tra un comando, un indirizzo, i cicli dummy e i dati restituiti è definita dalla periferica, non da SPI, e dipende dalla polarità e dalla fase del clock (modalità 0–3). Non presumere che l'output inizi esattamente un ciclo di clock dopo la fine dell'input.<sup>[[1]](#references)</sup>

## Dump del firmware da EEPROM

Il dump del firmware può essere utile per analizzarlo e individuare vulnerabilità. L'immagine corretta potrebbe non essere disponibile online o potrebbe differire in base al modello, alla revisione hardware o alla versione; estrarla direttamente dal dispositivo fisico fornisce quindi un target di valutazione esatto.

Una console seriale può essere utile, ma il suo filesystem potrebbe essere di sola lettura e il target potrebbe non disporre di strumenti di analisi, incluse le utility necessarie per inviare/ricevere traffico di test o estrarre comodamente i binari. Un'immagine offline conserva l'intero layout della flash e consente l'estrazione del filesystem e il reverse engineering senza modificare il target in esecuzione.

Durante una valutazione fisica autorizzata, un dump verificato può anche essere utile per test controllati di modifica e reflashing. Questo include la modifica di file o l'iniezione di un payload/backdoor di test per dimostrare la persistenza a livello di firmware. Conserva più letture corrispondenti e l'immagine originale prima di qualsiasi scrittura: una tensione, una selezione del chip, un layout o un'immagine errati possono rendere inutilizzabile il dispositivo.

### Programmatore e lettore EEPROM CH341A

Questo economico strumento USB può eseguire il dump e il reflash di dispositivi compatibili con EEPROM seriale e flash SPI. È comunemente usato con i chip flash SPI NOR che memorizzano il firmware BIOS/UEFI dei PC ed è pratico in caso di accesso fisico limitato nel tempo.

![drawing](../../images/board_image_ch341a.jpg)

Collega la memoria flash al CH341A, quindi collega il programmatore al computer. Se il programmatore non viene rilevato, controlla il cavo USB, i permessi del sistema operativo e il driver CH341A appropriato prima di eseguire la diagnosi del chip target. Verifica la tensione del chip, il pin 1, il cablaggio dell'adattatore e l'uscita del programmatore consultando le datasheet o usando un multimetro: **non** affidarti a regole come posizionare VCC sul lato opposto al connettore USB. Un orientamento errato o l'applicazione di 5 V a un componente da 3,3/1,8 V può danneggiarlo. Le letture in-circuit possono inoltre non riuscire perché il resto della scheda carica o alimenta il bus.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Usa software come `flashrom` o G-Flash per leggere il chip. G-Flash è una GUI minimale e può rilevare automaticamente i dispositivi compatibili, una funzione comoda durante un'acquisizione rapida; verifica comunque personalmente il modello rilevato e la tensione. Specifica il programmatore esatto e, se necessario, il modello esatto del chip; esegui almeno due letture e confrontane gli hash prima di considerare affidabile un dump.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Dopo aver eseguito il dump del firmware, l'analisi può essere effettuata sui file binari. Strumenti come strings, hexdump, xxd, binwalk, ecc. possono essere usati per estrarre molte informazioni sul firmware e sull'intero filesystem.

Per il triage iniziale, Binwalk può cercare firme note ed estrarre i contenuti incorporati supportati:

```
binwalk -e <filename>
```

Il file di output può usare l'estensione `.bin`, `.rom` o un'altra; l'estensione non ne determina il formato.

> [!CAUTION]
> Nota che l'estrazione del firmware è un processo delicato e richiede molta pazienza. Qualsiasi errore di manipolazione può potenzialmente corrompere il firmware o persino cancellarlo completamente, rendendo inutilizzabile il dispositivo. Si consiglia di studiare il dispositivo specifico prima di tentare di estrarre il firmware.

### Bus Pirate + flashrom

![Programmatore e lettore EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Alcuni datasheet indicano i pin target come `DI` e `DO`: per una connessione flash convenzionale con una singola linea dati, il controller **MOSI/COPI si collega a DI** e il controller **MISO/CIPO si collega a DO**. Verifica il datasheet del target, perché i componenti con I/O duali o quadri riutilizzano i pin in altre modalità.

![Programmatore e lettore EEPROM CH341A - Bus Pirate + flashrom: Nota che, anche se il PINOUT del Bus Pirate indica i pin MOSI e MISO da collegare allo SPI, alcuni SPI potrebbero...](<../../images/image (360).png>)

Su Windows o Linux puoi usare il programma [**`flashrom`**](https://www.flashrom.org/Flashrom) per scaricare il contenuto della memoria flash eseguendo qualcosa del tipo:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

La documentazione recente di Bus Pirate mostra anche i parametri opzionali `serialspeed` e `spispeed`. Inizia con valori prudenti se i cavi lunghi o il carico del circuito rendono instabili le letture.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Introduzione all'interfaccia SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manuale di flashrom — Programmatore SPI CH341A e opzioni di lettura/scrittura](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentazione di Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
