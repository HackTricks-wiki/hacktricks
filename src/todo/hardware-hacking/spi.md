# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

SPI (Serial Peripheral Interface) è un Protocollo di comunicazione seriale sincrono utilizzato nei sistemi embedded per la comunicazione a breve distanza tra IC (Integrated Circuits). Il Protocollo di comunicazione SPI utilizza l'architettura master-slave, orchestrata dal Clock e dal Chip Select Signal. Un'architettura master-slave è composta da un master (solitamente un microprocessore) che gestisce periferiche esterne come EEPROM, sensori, dispositivi di controllo, ecc., considerate slave.

È possibile collegare più slave a un master, ma gli slave non possono comunicare tra loro. Gli slave sono amministrati tramite due pin: clock e chip select. Poiché SPI è un protocollo di comunicazione sincrono, i pin di input e output seguono i segnali di clock. Il chip select viene utilizzato dal master per selezionare uno slave e interagire con esso. Quando il chip select è alto, il dispositivo slave non è selezionato, mentre quando è basso, il chip è selezionato e il master interagisce con lo slave.

MOSI (Master Out, Slave In) e MISO (Master In, Slave Out) sono responsabili rispettivamente dell'invio e della ricezione dei dati. I dati vengono inviati al dispositivo slave tramite il pin MOSI mentre il chip select è mantenuto basso. I dati di input contengono istruzioni, indirizzi di memoria o dati, in base al datasheet del dispositivo slave fornito dal vendor. In presenza di un input valido, il pin MISO è responsabile della trasmissione dei dati al master. I dati di output vengono inviati esattamente nel ciclo di clock successivo alla fine dell'input. I pin MISO trasmettono i dati fino a quando la trasmissione non è completata o il master imposta il pin chip select su alto (in tal caso, lo slave interrompe la trasmissione e il master non ascolta più dopo quel ciclo di clock).

## Dumping del Firmware dalle EEPROM

Il dumping del firmware può essere utile per analizzare il firmware e individuare vulnerabilità al suo interno. Spesso il firmware non è disponibile su Internet oppure è irrilevante a causa di variazioni di fattori come numero del modello, versione, ecc. Pertanto, estrarre il firmware direttamente dal dispositivo fisico può essere utile per essere specifici durante la ricerca di minacce.

Ottenere una Serial Console può essere utile, ma spesso i file sono di sola lettura. Ciò limita l'analisi per diversi motivi. Ad esempio, gli strumenti necessari per inviare e ricevere pacchetti potrebbero non essere presenti nel firmware. Di conseguenza, estrarre i binari per sottoporli a reverse engineering non è fattibile. Pertanto, avere l'intero firmware scaricato sul sistema ed estrarre i binari per l'analisi può essere molto utile.

Inoltre, durante il red teaming e dopo aver ottenuto accesso fisico ai dispositivi, il dumping del firmware può aiutare a modificare i file o a iniettare file malevoli e quindi a riflasharli nella memoria, cosa che potrebbe essere utile per impiantare una backdoor nel dispositivo. Pertanto, il dumping del firmware può sbloccare numerose possibilità.

### CH341A EEPROM Programmer and Reader

Questo dispositivo è uno strumento economico per eseguire il dumping dei firmware dalle EEPROM e anche per riflasharle con file firmware. È una scelta popolare per lavorare con i chip BIOS dei computer (che sono semplicemente EEPROM). Questo dispositivo si collega tramite USB e richiede pochi strumenti per iniziare. Inoltre, di solito completa rapidamente il lavoro, quindi può essere utile anche durante l'accesso fisico ai dispositivi.

![drawing](../../images/board_image_ch341a.jpg)

Collega la memoria EEPROM al CH341A Programmer e collega il dispositivo al computer. Nel caso in cui il dispositivo non venga rilevato, prova a installare i driver sul computer. Assicurati inoltre che l'EEPROM sia collegata con l'orientamento corretto (solitamente, posiziona il pin VCC in direzione opposta rispetto al connettore USB), altrimenti il software non sarà in grado di rilevare il chip. Consulta il diagramma, se necessario:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Infine, utilizza software come flashrom, G-Flash (GUI), ecc. per eseguire il dumping del firmware. G-Flash è uno strumento GUI minimale e veloce che rileva automaticamente l'EEPROM. Può essere utile quando è necessario estrarre rapidamente il firmware, senza dover consultare eccessivamente la documentazione.

![drawing](../../images/connected_status_ch341a.jpg)

Dopo aver eseguito il dumping del firmware, è possibile analizzare i file binari. Strumenti come strings, hexdump, xxd, binwalk, ecc. possono essere utilizzati per estrarre molte informazioni sul firmware e anche sull'intero file system.

Per estrarre i contenuti dal firmware, è possibile utilizzare binwalk. Binwalk analizza le firme esadecimali, identifica i file nel file binario ed è in grado di estrarli.
```
binwalk -e <filename>
```
Può essere `.bin` o `.rom` a seconda degli strumenti e delle configurazioni utilizzati.

> [!CAUTION]
> Tieni presente che l'estrazione del firmware è un processo delicato e richiede molta pazienza. Qualsiasi manipolazione errata può potenzialmente corrompere il firmware o persino cancellarlo completamente, rendendo inutilizzabile il dispositivo. È consigliabile studiare il dispositivo specifico prima di tentare di estrarre il firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Nota che, anche se il PINOUT del Bus Pirate indica i pin **MOSI** e **MISO** per la connessione a SPI, alcuni SPI possono indicare i pin come DI e DO. **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

In Windows o Linux puoi utilizzare il programma [**`flashrom`**](https://www.flashrom.org/Flashrom) per eseguire il dump del contenuto della memoria flash eseguendo un comando simile al seguente:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
