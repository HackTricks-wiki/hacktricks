# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di Base

SPI (Serial Peripheral Interface) è un protocollo di comunicazione seriale sincrono utilizzato nei sistemi embedded per la comunicazione a breve distanza tra IC (Circuiti Integrati). Il protocollo di comunicazione SPI utilizza un'architettura master-slave orchestrata dal segnale di clock e dal segnale di selezione del chip. Un'architettura master-slave consiste in un master (di solito un microprocessore) che gestisce periferiche esterne come EEPROM, sensori, dispositivi di controllo, ecc., considerati come schiavi.

Più schiavi possono essere collegati a un master, ma gli schiavi non possono comunicare tra loro. Gli schiavi sono gestiti da due pin, clock e chip select. Poiché SPI è un protocollo di comunicazione sincrono, i pin di input e output seguono i segnali di clock. Il chip select è utilizzato dal master per selezionare uno schiavo e interagire con esso. Quando il chip select è alto, il dispositivo schiavo non è selezionato, mentre quando è basso, il chip è stato selezionato e il master interagirà con lo schiavo.

Il MOSI (Master Out, Slave In) e il MISO (Master In, Slave Out) sono responsabili dell'invio e della ricezione dei dati. I dati vengono inviati al dispositivo schiavo tramite il pin MOSI mentre il chip select è mantenuto basso. I dati di input contengono istruzioni, indirizzi di memoria o dati secondo il datasheet del fornitore del dispositivo schiavo. A fronte di un input valido, il pin MISO è responsabile della trasmissione dei dati al master. I dati di output vengono inviati esattamente al ciclo di clock successivo dopo la fine dell'input. I pin MISO trasmettono i dati fino a quando i dati non sono completamente trasmessi o il master imposta il pin di selezione del chip alto (in tal caso, lo schiavo smetterebbe di trasmettere e il master non ascolterebbe dopo quel ciclo di clock).

## Dumping del Firmware da EEPROM

Dumping del firmware può essere utile per analizzare il firmware e trovare vulnerabilità in esso. Spesso, il firmware non è disponibile su Internet o è irrilevante a causa di variazioni di fattori come numero di modello, versione, ecc. Pertanto, estrarre il firmware direttamente dal dispositivo fisico può essere utile per essere specifici nella ricerca di minacce.

Ottenere la console seriale può essere utile, ma spesso accade che i file siano di sola lettura. Questo limita l'analisi per vari motivi. Ad esempio, gli strumenti necessari per inviare e ricevere pacchetti potrebbero non essere presenti nel firmware. Quindi, estrarre i binari per reverse engineerizzarli non è fattibile. Pertanto, avere l'intero firmware dumpato sul sistema ed estrarre i binari per l'analisi può essere molto utile.

Inoltre, durante il red teaming e l'accesso fisico ai dispositivi, dumpare il firmware può aiutare a modificare i file o iniettare file dannosi e poi riflasharli nella memoria, il che potrebbe essere utile per impiantare una backdoor nel dispositivo. Pertanto, ci sono numerose possibilità che possono essere sbloccate con il dumping del firmware.

### Programmatore e Lettore EEPROM CH341A

Questo dispositivo è uno strumento economico per dumpare firmware da EEPROM e anche riflasharli con file di firmware. È stata una scelta popolare per lavorare con chip BIOS dei computer (che sono semplicemente EEPROM). Questo dispositivo si collega tramite USB e richiede strumenti minimi per iniziare. Inoltre, di solito completa il compito rapidamente, quindi può essere utile anche per l'accesso fisico ai dispositivi.

![drawing](../../images/board_image_ch341a.jpg)

Collegare la memoria EEPROM con il programmatore CH341a e collegare il dispositivo al computer. Nel caso in cui il dispositivo non venga rilevato, provare a installare i driver nel computer. Inoltre, assicurarsi che l'EEPROM sia collegata nella giusta orientazione (di solito, posizionare il pin VCC in orientazione inversa rispetto al connettore USB) altrimenti il software non sarà in grado di rilevare il chip. Fare riferimento al diagramma se necessario:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Infine, utilizzare software come flashrom, G-Flash (GUI), ecc. per dumpare il firmware. G-Flash è uno strumento GUI minimale, veloce e rileva automaticamente l'EEPROM. Questo può essere utile se il firmware deve essere estratto rapidamente, senza troppa manipolazione con la documentazione.

![drawing](../../images/connected_status_ch341a.jpg)

Dopo aver dumpato il firmware, l'analisi può essere effettuata sui file binari. Strumenti come strings, hexdump, xxd, binwalk, ecc. possono essere utilizzati per estrarre molte informazioni sul firmware e sull'intero file system.

Per estrarre i contenuti dal firmware, può essere utilizzato binwalk. Binwalk analizza le firme esadecimali e identifica i file nel file binario ed è in grado di estrarli.
```
binwalk -e <filename>
```
I file possono essere .bin o .rom a seconda degli strumenti e delle configurazioni utilizzate.

> [!CAUTION]
> Nota che l'estrazione del firmware è un processo delicato e richiede molta pazienza. Qualsiasi maneggiamento errato può potenzialmente corrompere il firmware o addirittura cancellarlo completamente, rendendo il dispositivo inutilizzabile. Si consiglia di studiare il dispositivo specifico prima di tentare di estrarre il firmware.

### Bus Pirate + flashrom

![](<../../images/image (910).png>)

Nota che anche se il PINOUT del Pirate Bus indica pin per **MOSI** e **MISO** da collegare a SPI, alcuni SPI possono indicare pin come DI e DO. **MOSI -> DI, MISO -> DO**

![](<../../images/image (360).png>)

In Windows o Linux puoi utilizzare il programma [**`flashrom`**](https://www.flashrom.org/Flashrom) per dumpare il contenuto della memoria flash eseguendo qualcosa come:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
