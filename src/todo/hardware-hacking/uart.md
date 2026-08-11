# UART

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

UART è un'interfaccia seriale asincrona che trasferisce un flusso di bit strutturato senza un clock condiviso. Non bisogna confondere UART a livello logico con RS-232: RS-232 utilizza livelli di tensione differenti, spesso negativi, e richiede un transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

In genere, la linea viene mantenuta alta (con valore logico 1) mentre UART è nello stato inattivo. Per segnalare l'inizio di un trasferimento dati, il trasmettitore invia quindi un bit di start al ricevitore, durante il quale il segnale viene mantenuto basso (con valore logico 0). Successivamente, il trasmettitore invia da cinque a otto bit di dati contenenti il messaggio effettivo, seguiti da un bit di parità opzionale e da uno o due bit di stop (con valore logico 1), a seconda della configurazione. Il bit di parità, utilizzato per il controllo degli errori, si vede raramente nella pratica. Il bit (o i bit) di stop indicano la fine della trasmissione.

La configurazione più comune è 8N1: otto bit di dati, nessuna parità e un bit di stop. UART invia prima il bit di dati meno significativo, quindi ASCII `C` (`0x43`) viene trasmesso come: start `0`; dati `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: la configurazione più comune è 8N1: otto bit di dati, nessuna parità e un bit di stop. Ad esempio, per inviare il carattere C, ovvero 0x43 in ASCII, tramite UART 8N1](<../../images/image (764).png>)

Strumenti hardware per comunicare con UART:

- Adattatore da USB a seriale
- Adattatori con chip CP2102 o PL2303
- Strumenti multipurpose come: Bus Pirate, Adafruit FT232H, Shikra o Attify Badge

### Identificare le porte UART

Un tipico header di debug espone **TX**, **RX** e **GND**; può anche esporre un pin **Vcc/Vref**, reset o pin di controllo del flusso. Vcc non è un segnale UART e normalmente dovrebbe essere utilizzato solo come riferimento di tensione, non collegato come fonte di alimentazione, a meno che lo schema della scheda e i requisiti di corrente siano noti.<sup>[[2]](#references)[[3]](#references)</sup>

Inizia con il dispositivo **spento** e scollegato:

- Identifica **GND** in modalità continuità rispetto a un piano di massa noto, alla schermatura di un connettore o alla massa dell'alimentazione. Non usare mai la modalità continuità/resistenza su una scheda alimentata.
- Passa alla modalità tensione continua prima di alimentare il target. Misura i pin candidati rispetto alla massa per identificare la tensione logica. Un rail stabile potrebbe essere Vcc/Vref; non presumere che sia sicuro collegarlo.
- Osserva i candidati con un logic analyzer o un oscilloscopio durante il boot. **TX** normalmente è inattivo a livello alto e mostra raffiche di dati strutturati. Un multimetro può mostrare una variazione media, ma non può verificare il framing o il baud rate.
- **RX** potrebbe rimanere inattivo e non può essere identificato in sicurezza solo perché è adiacente a TX. Traccia il PCB, consulta il datasheet del SoC oppure usa un analyzer ad alta impedenza prima di pilotarlo.

Lo scambio tra TX e RX normalmente non produce alcuna comunicazione; confondere alimentazione, massa o livelli del segnale può danneggiare permanentemente il target o l'adattatore. Collega prima la massa e inizia in modalità **sola ricezione** (TX del target verso RX dell'adattatore).

I produttori possono omettere l'header, lasciare non popolati i resistori in serie, disabilitare la console nel firmware oppure esporre solo TX. Traccia i test pad e le piazzole dei resistori vicini fino al SoC e aggiungi una connessione temporanea ad alta impedenza solo dopo aver confermato il livello elettrico. La presenza di una garanzia non implica necessariamente l'esistenza di una UART accessibile.

### Identificare il baud rate UART

Il modo più semplice per identificare il baud rate corretto è osservare l'**output del pin TX e provare a leggere i dati**. Se i dati ricevuti non sono leggibili, passa al baud rate successivo possibile finché i dati non diventano leggibili. Per farlo puoi utilizzare un adattatore da USB a seriale oppure un dispositivo multipurpose come Bus Pirate, insieme a uno script di supporto come [baudrate.py](https://github.com/devttys0/baudrate/). I baud rate più comuni sono 9600, 38400, 19200, 57600 e 115200.

> [!CAUTION]
> È importante notare che in questo protocollo devi collegare il TX di un dispositivo all'RX dell'altro!

## Adattatore da CP210X UART a TTY

I bridge da USB a UART CP210x sono presenti su molte schede per prototipazione e su adattatori economici. I moduli comuni espongono i pin di alimentazione insieme a GND, RXD e TXD, ma gli header e i livelli di I/O variano. Conferma la tensione effettiva dal design della scheda o dal datasheet. Di solito collega solo GND, RX dell'adattatore a TX del target e, dopo la validazione in sola ricezione, TX dell'adattatore a RX del target. Non collegare il pin di alimentazione da 5 V/3,3 V dell'adattatore, a meno che tu non stia alimentando intenzionalmente un target noto per supportarlo.<sup>[[3]](#references)</sup>

Nel caso in cui l'adattatore non venga rilevato, assicurati che i driver CP210X siano installati nel sistema host. Una volta rilevato e collegato l'adattatore, puoi utilizzare strumenti come picocom, minicom o screen.

Per elencare i dispositivi collegati ai sistemi Linux/MacOS:
```
ls /dev/
```
Per l'interazione di base con l'interfaccia UART, usa il seguente comando:
```
picocom /dev/<adapter> --baud <baudrate>
```
Per minicom, usa il seguente comando per configurarlo:
```
minicom -s
```
Configura le impostazioni, come baudrate e nome del dispositivo, nell'opzione `Serial port setup`.

Dopo la configurazione, esegui `minicom` per aprire la console UART.

## UART tramite Arduino UNO R3 (schede con chip Atmel 328p rimovibile)

Nel caso in cui gli adattatori da UART seriale a USB non siano disponibili, è possibile utilizzare Arduino UNO R3 con un rapido hack. Poiché Arduino UNO R3 è solitamente disponibile ovunque, questo può far risparmiare molto tempo.

Arduino UNO R3 dispone di un adattatore da USB a seriale integrato sulla scheda. Per ottenere una connessione UART, è sufficiente rimuovere il microcontrollore Atmel 328p dalla scheda. Questo hack funziona sulle varianti di Arduino UNO R3 in cui l'Atmel 328p non è saldato sulla scheda (in questa versione viene utilizzato il modello SMD). Collega il pin RX di Arduino (pin digitale 0) al pin TX dell'interfaccia UART e il pin TX di Arduino (pin digitale 1) al pin RX dell'interfaccia UART.

Utilizza il **Serial Monitor** dell'Arduino IDE oppure un terminale dedicato con il baudrate target. I segnali seriali dell'Uno R3 classico utilizzano una logica a 5 V; pertanto, usa un level shifter o un partitore prima di collegarli a un target a 3,3 V o a una tensione inferiore.

## Bus Pirate

La seguente trascrizione utilizza l'interfaccia del firmware legacy di Bus Pirate per monitorare l'output UART. Il firmware più recente di Bus Pirate utilizza comandi come `m uart`, `{`/`}`, `monitor` o `bridge`; consulta la documentazione relativa alla versione installata.<sup>[[2]](#references)</sup>
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Dumping del firmware con la console UART

Una console UART fornisce accesso runtime ai log di avvio e, talvolta, a una shell del bootloader o del sistema operativo. Anche una console di sola lettura rivela mappe di memoria, driver flash, argomenti di avvio, layout delle partizioni e versioni del firmware. Il firmware può risiedere in SPI NOR/NAND, eMMC o in un altro dispositivo; in genere non viene eseguito da una EEPROM e i file scritti su un filesystem persistente montato non necessariamente scompaiono al riavvio.

Esistono diversi metodi di acquisizione e la sezione SPI tratta le letture dirette dalla flash esterna. L'acquisizione assistita dalla console può essere meno invasiva quando il bootloader fornisce già un comando di lettura sicuro, ma qualsiasi interruzione dell'avvio o comando flash può influire sulla disponibilità, quindi registra lo stato originale ed evita operazioni di scrittura/cancellazione.

Il dumping del firmware assistito dalla console inizia spesso interrompendo un bootloader. Molti dispositivi Linux embedded usano **Das U-Boot**, ma altri utilizzano bootloader proprietari o disabilitano la console interattiva.

Per verificare la presenza di un bootloader interattivo, collega il percorso di ricezione UART e il terminale mentre il target è spento, avvia la registrazione e accendilo. Segui il prompt autoboot visualizzato; a seconda della build, l'interruzione può richiedere un tasto, una breve sequenza oppure può essere completamente disabilitata.

Se l'interruzione riesce, usa `help`, `printenv` e comandi di discovery di sola lettura per comprendere il layout della memoria e dello storage di quel vendor prima di accedere agli indirizzi.

In U-Boot, `md` visualizza la **memoria indirizzabile**, non automaticamente “la EEPROM”. Usa innanzitutto comandi specifici della scheda come `mtd list`, `sf probe`, `mmc info`, `part list`, le variabili d'ambiente e i log di avvio per identificare l'indirizzo mappato corretto o caricare una regione flash nella RAM. Quindi visualizza un intervallo noto byte per byte:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Registra l'output seriale prima di iniziare. L'output di `md.b` contiene indirizzi e una colonna ASCII, quindi è una rappresentazione testuale anziché un'immagine ROM grezza.

Rimuovi le colonne degli indirizzi e ASCII, concatena solo i campi dei byte esadecimali e decodificali in formato binario (ad esempio con `xxd -r -p`). Verifica il numero di byte previsto e registra un hash prima dell'analisi:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk identifica quindi le signature note nel binario ricostruito. Una lettura diretta della flash tramite l'interfaccia SPI/eMMC/NAND appropriata è solitamente più rapida e meno soggetta a errori quando la console non riesce a trasferire i dati in modo affidabile.

U-Boot potrebbe disabilitare l'interruzione, richiedere una sequenza di tasti specifica del vendor oppure bloccare i comandi di memoria/flash. Segui il prompt di autoboot e il boot log invece di trasmettere caratteri alla cieca. Se la console non può essere interrotta, conserva il boot log e passa a un metodo non invasivo di acquisizione del firmware.

## References

- [1] [Manuale di riferimento della famiglia Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentazione Bus Pirate - modalità UART e limiti elettrici](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - scheda tecnica CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentazione U-Boot - comando `md` per la visualizzazione della memoria](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
