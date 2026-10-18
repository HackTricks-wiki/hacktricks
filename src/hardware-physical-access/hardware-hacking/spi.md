# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

SPI (Serial Peripheral Interface) è un bus seriale sincrono comunemente usato per la comunicazione a breve distanza tra circuiti integrati. Un controller fornisce il clock e seleziona una periferica, come una EEPROM, un sensore o un dispositivo di controllo, tramite un segnale chip-select.<sup>[[1]](#references)</sup>

Più periferiche possono condividere le linee di clock e dati, normalmente con un chip-select separato per ciascuna periferica. Il controller orchestra i trasferimenti; normalmente, le periferiche non comunicano direttamente tra loro sul bus SPI. La polarità e la temporizzazione del chip-select dipendono dal dispositivo; la selezione attiva bassa è comune, ma non universale. SPI non definisce il rilevamento dei dispositivi, l'indirizzamento, i comandi o una lunghezza massima di trasferimento unica: consultare sempre il datasheet del dispositivo target.<sup>[[1]](#references)</sup>

MOSI/COPI trasporta i dati dal controller alla periferica, mentre MISO/CIPO trasporta i dati dalla periferica al controller. Entrambe le direzioni possono trasmettere simultaneamente. La relazione tra un comando, un indirizzo, i cicli dummy e i dati restituiti è definita dalla periferica, non da SPI, e dipende dalla polarità e dalla fase del clock (modalità 0–3). Non presumere che l'output inizi esattamente un ciclo di clock dopo la fine dell'input.<sup>[[1]](#references)</sup>

## Dump del firmware dalle EEPROM

Il dump del firmware può essere utile per analizzarlo e individuare vulnerabilità. L'immagine corretta potrebbe non essere disponibile online o potrebbe essere diversa a seconda del modello, della revisione hardware o della versione; estrarla direttamente dal dispositivo fisico fornisce quindi un target di valutazione esatto.

Una console seriale può essere utile, ma il suo filesystem potrebbe essere in sola lettura e il target potrebbe non disporre di strumenti di analisi, comprese le utilità necessarie per inviare/ricevere traffico di test o estrarre comodamente i binari. Un'immagine offline conserva l'intero layout della flash e consente di estrarre il filesystem e svolgere reverse engineering senza modificare il target in esecuzione.

Durante una valutazione fisica autorizzata, un dump verificato può anche supportare test controllati di modifica e riflash. Questo include la modifica di file o l'iniezione di un payload/backdoor di test per dimostrare la persistenza a livello firmware. Conserva più letture corrispondenti e l'immagine originale prima di qualsiasi scrittura: una tensione, una selezione del chip, un layout o un'immagine errati possono rendere inutilizzabile il dispositivo.

### Programmatore e lettore EEPROM CH341A

Questo economico strumento USB può eseguire il dump e il reflash di dispositivi compatibili con EEPROM seriale e flash SPI. Viene comunemente usato con i chip flash SPI NOR che memorizzano il firmware BIOS/UEFI dei PC ed è pratico quando l'accesso fisico è limitato nel tempo.

![drawing](../../images/board_image_ch341a.jpg)

Collega la memoria flash al CH341A, quindi collega il programmatore al computer. Se il programmatore non viene rilevato, controlla il cavo USB, i permessi del sistema operativo e il driver CH341A appropriato prima di procedere alla risoluzione dei problemi del chip target. Verifica la tensione del chip, il pin 1, il cablaggio dell'adattatore e l'uscita del programmatore consultando i datasheet o usando un multimetro: **non** fare affidamento su una regola come posizionare VCC sul lato opposto rispetto al connettore USB. Un orientamento errato o l'applicazione di 5 V a un componente da 3,3/1,8 V può distruggerlo. Anche le letture in-circuit possono fallire perché il resto della scheda carica o alimenta il bus.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Usa software come `flashrom` o G-Flash per leggere il chip. G-Flash è una GUI minimale e può rilevare automaticamente i dispositivi compatibili, una funzione pratica durante un'acquisizione rapida; verifica comunque personalmente il modello rilevato e la tensione. Specifica il programmatore esatto e, quando necessario, il modello esatto del chip; esegui almeno due letture e confrontane gli hash prima di considerare affidabile un dump.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Dopo aver eseguito il dump del firmware, è possibile analizzare i file binari. Si possono usare strumenti come strings, hexdump, xxd, binwalk, ecc. per estrarre molte informazioni sul firmware e sull'intero filesystem.

Per il triage iniziale, Binwalk può cercare firme note ed estrarre i contenuti incorporati supportati:

```
binwalk -e <filename>
```

Il file di output può usare l’estensione `.bin`, `.rom` o un’altra; l’estensione non determina il formato.

> [!CAUTION]
> Tieni presente che l’estrazione del firmware è un processo delicato e richiede molta pazienza. Qualsiasi errore di manipolazione può potenzialmente corrompere il firmware o persino cancellarlo completamente, rendendo inutilizzabile il dispositivo. Si consiglia di studiare il dispositivo specifico prima di tentare di estrarre il firmware.

### Bus Pirate + flashrom

![Programmatore e lettore EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Alcuni datasheet indicano i pin di destinazione come `DI` e `DO`: per una connessione flash convenzionale con una singola linea dati, **MOSI/COPI del controller si collega a DI** e **MISO/CIPO del controller si collega a DO**. Verifica il datasheet del componente di destinazione, poiché i componenti con I/O duale/quadruplo riutilizzano i pin in altre modalità.

![Programmatore e lettore EEPROM CH341A - Bus Pirate + flashrom: Tieni presente che, anche se il PINOUT del Bus Pirate indica i pin per MOSI e MISO da collegare a SPI, alcuni SPI potrebbero...](<../../images/image (360).png>)

Su Windows o Linux puoi usare il programma [**`flashrom`**](https://www.flashrom.org/Flashrom) per scaricare il contenuto della memoria flash eseguendo un comando simile a:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

La documentazione più recente di Bus Pirate mostra anche i parametri opzionali `serialspeed` e `spispeed`. Inizia con impostazioni conservative se i cavi lunghi o il carico del circuito rendono instabili le letture.<sup>[[3]](#references)</sup>

### Letture in-circuit quando il controller condivide il bus della flash

Una clip SOIC può alimentare la flash e il resto del PCB. Se l’MCU è quindi alimentato e accede allo stesso chip, i suoi trasferimenti SPI possono collidere con quelli del programmatore esterno. Un risultato `No EEPROM/flash device found` non dimostra quindi che la flash sia assente o non supportata. Controlla prima piedinatura, tensione e contatti, poi verifica se il controller integrato è attivo.<sup>[[4]](#references)</sup>

Se è disponibile un pad di test per il reset, verifica con un multimetro la polarità e la tensione prima di attivarlo. Tenere l’MCU in reset può lasciare la flash accessibile, impedendo al contempo all’host SPI di interferire. In alternativa, si può dissaldare il chip o registrare passivamente le letture dell’MCU; quest’ultima opzione non consente di accedere alle aree non lette né di scrivere sul chip, e i cavi aggiuntivi della sonda possono disturbare un bus veloce. Intervenire sull’oscillatore o sulla modalità di avvio dipende dal target e non sostituisce la verifica dello schema e dei segnali.<sup>[[4]](#references)</sup>

Con l’MCU inattivo, un Raspberry Pi con interfaccia `spidev` abilitata può leggere tramite il programmatore `linux_spi` di flashrom. Modifica `-p` per usare un adattatore diverso. Ripeti la lettura e confronta gli hash prima di considerarla affidabile; il rilevamento automatico SFDP e una lettura riuscita **non** dimostrano che le operazioni di cancellazione, scrittura o protezione da scrittura funzionino su un componente altrimenti non supportato.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Ricostruire le letture della memoria flash SPI con un analizzatore logico

Quando non è possibile effettuare una lettura attiva, acquisisci i segnali chip select, clock, dati dal controller alla flash e dati dalla flash al controller durante l'avvio o un'azione UI scelta. In PulseView, individua prima l'intervallo attivo del chip select e il clock, quindi configura i canali dati del decoder SPI in base al pinout della flash e verifica che ci siano un comando e un indirizzo plausibili seguiti dai byte restituiti. Esporta i byte **MISO/output della flash** con Binary Decoder Output View e conserva gli indirizzi di lettura decodificati, così da poter collocare ogni risposta all'offset corrispondente nella flash. Acquisire solo le letture avviate dai menu fornisce solo le regioni richieste, non un'immagine completa della flash; non concatenare le risposte come se fossero contigue senza aver verificato gli indirizzi.<sup>[[4]](#references)</sup>

Se un dump sembra contenere grafica anziché codice eseguibile, prosegui con il [triage delle risorse grafiche grezze](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — Introduzione all'interfaccia SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manuale di flashrom — programmatore CH341A SPI e opzioni di lettura/scrittura](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentazione di Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Ripasso dell'hardware hacking, parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
