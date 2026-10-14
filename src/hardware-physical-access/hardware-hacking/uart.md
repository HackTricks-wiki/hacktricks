# UART

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

UART è un'interfaccia seriale asincrona che trasferisce un flusso di bit incorniciato senza un clock condiviso. Non confondere UART a livello logico con RS-232: RS-232 usa livelli di tensione diversi, spesso negativi, e richiede un transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

In genere, quando UART è in stato di inattività, la linea viene mantenuta alta (valore logico 1). Per segnalare l'inizio di un trasferimento di dati, il trasmettitore invia quindi un bit di start al ricevitore, durante il quale il segnale viene mantenuto basso (valore logico 0). Il trasmettitore invia poi da cinque a otto bit di dati che contengono il messaggio effettivo, seguiti da un bit di parità facoltativo e da uno o due bit di stop (con valore logico 1), a seconda della configurazione. Il bit di parità, usato per il controllo degli errori, si vede raramente nella pratica. Il bit (o i bit) di stop indicano la fine della trasmissione.

La configurazione più comune è 8N1: otto bit di dati, nessuna parità e un bit di stop. UART invia per primo il bit meno significativo, quindi il carattere ASCII `C` (`0x43`) viene trasmesso così: start `0`; dati `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: la configurazione più comune si chiama 8N1: otto bit di dati, nessuna parità e un bit di stop. Ad esempio, se volessimo inviare il carattere C, ovvero 0x43 in ASCII, tramite UART 8N1](<../../images/image (764).png>)

Strumenti hardware per comunicare tramite UART:

- Adattatore USB-seriale
- Adattatori con chip CP2102 o PL2303
- Strumento multiuso, come Bus Pirate, Adafruit FT232H, Shikra o Attify Badge

### Identificare le porte UART

Un tipico header di debug espone **TX**, **RX** e **GND**; può esporre anche un pin **Vcc/Vref**, reset o pin di flow control. Vcc non è un segnale UART e normalmente dovrebbe essere usato solo come riferimento di tensione, non collegato come fonte di alimentazione, a meno che non si conoscano lo schema della scheda e i requisiti di corrente.<sup>[[2]](#references)[[3]](#references)</sup>

Inizia con il dispositivo **spento** e scollegato:

- Identifica **GND** in modalità continuità, verificandolo rispetto a un piano di massa noto, alla schermatura di un connettore o alla massa dell'alimentazione. Non usare mai la modalità continuità/resistenza su una scheda alimentata.
- Passa alla modalità tensione CC prima di alimentare il target. Misura i pin candidati rispetto a GND per identificare la tensione logica. Una linea di alimentazione stabile potrebbe essere Vcc/Vref; non dare per scontato che sia sicuro collegarla.
- Osserva i pin candidati con un logic analyzer o un oscilloscopio durante l'avvio. **TX** è comunemente inattivo a livello alto e mostra raffiche di dati incorniciati. Un multimetro può rilevare una fluttuazione media, ma non può verificare il framing né il baud rate.
- **RX** potrebbe rimanere inattivo e non può essere identificato in sicurezza solo perché si trova vicino a TX. Segui le piste del PCB, consulta il datasheet del SoC o usa un analyzer ad alta impedenza prima di pilotarlo.

Invertire TX e RX normalmente impedisce la comunicazione; confondere alimentazione, massa o livelli del segnale può danneggiare permanentemente il target o l'adattatore. Collega prima la massa e inizia in modalità **solo ricezione** (TX del target verso RX dell'adattatore).

I produttori potrebbero omettere l'header, non popolare le resistenze in serie, disabilitare la console nel firmware o esporre solo TX. Segui le piste dei test pad e degli alloggiamenti per resistenze vicini fino al SoC e aggiungi una connessione temporanea ad alta impedenza solo dopo aver verificato il livello elettrico. La presenza di una garanzia non implica che debba essere disponibile una UART accessibile.

### Identificare il baud rate UART

Il modo più semplice per identificare il baud rate corretto consiste nell'osservare l'output del pin **TX** e provare a leggere i dati. Se i dati ricevuti non sono leggibili, prova il baud rate possibile successivo finché i dati non diventano leggibili. Puoi usare un adattatore USB-seriale o un dispositivo multiuso come Bus Pirate, insieme a uno script di supporto, ad esempio [baudrate.py](https://github.com/devttys0/baudrate/). I baud rate più comuni sono 9600, 38400, 19200, 57600 e 115200.

> [!CAUTION]
> È importante notare che, in questo protocollo, devi collegare il TX di un dispositivo all'RX dell'altro!

## Adattatore CP210X UART-TTY

I bridge USB-UART CP210x si trovano su molte schede di prototipazione e adattatori economici. I moduli più comuni espongono i pin di alimentazione insieme a GND, RXD e TXD, ma gli header e i livelli di I/O variano. Verifica la tensione effettiva in base al progetto della scheda o al datasheet. Di solito collega solo GND e RX dell'adattatore a TX del target; dopo la verifica in sola ricezione, collega anche TX dell'adattatore a RX del target. Non collegare il pin di alimentazione a 5 V/3,3 V dell'adattatore, a meno che tu non voglia alimentare intenzionalmente un target di cui sai che può tollerare tale tensione.<sup>[[3]](#references)</sup>

Se l'adattatore non viene rilevato, assicurati che i driver CP210X siano installati nel sistema host. Una volta rilevato e collegato l'adattatore, puoi usare strumenti come picocom, minicom o screen.

Per elencare i dispositivi collegati ai sistemi Linux/MacOS:

```
ls /dev/
```

Per interagire in modo basilare con l’interfaccia UART, usa il seguente comando:

```
picocom /dev/<adapter> --baud <baudrate>
```

Per configurare minicom, usa il seguente comando:

```
minicom -s
```

Configura impostazioni come il baud rate e il nome del dispositivo nell'opzione `Serial port setup`.

Dopo la configurazione, esegui `minicom` per aprire la console UART.

## UART tramite Arduino UNO R3 (schede con chip Atmel 328p rimovibile)

Se non sono disponibili adattatori seriale-USB UART, è possibile usare Arduino UNO R3 con un rapido hack. Poiché Arduino UNO R3 è solitamente disponibile ovunque, può far risparmiare molto tempo.

Arduino UNO R3 ha un adattatore USB-seriale integrato nella scheda. Per ottenere una connessione UART, basta rimuovere il chip microcontrollore Atmel 328p dalla scheda. Questo hack funziona con le varianti di Arduino UNO R3 in cui l'Atmel 328p non è saldato alla scheda (viene usata la versione SMD). Collega il pin RX di Arduino (pin digitale 0) al pin TX dell'interfaccia UART e il pin TX di Arduino (pin digitale 1) al pin RX dell'interfaccia UART.

Usa il **Serial Monitor** dell'IDE Arduino o un terminale dedicato impostato sul baud rate del dispositivo target. I segnali seriali dell'Uno R3 classico usano una logica a 5 V: usa quindi un level shifter o un partitore prima di collegarli a un dispositivo target a 3,3 V o con tensione inferiore.

## Bus Pirate

La trascrizione seguente usa l'interfaccia legacy del firmware Bus Pirate per monitorare l'output UART. Le versioni più recenti del firmware Bus Pirate usano comandi come `m uart`, `{`/`}`, `monitor` o `bridge`; consulta la documentazione relativa alla versione installata.<sup>[[2]](#references)</sup>

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

## Dumping del firmware con console UART

Una console UART fornisce accesso in fase di esecuzione ai log di avvio e, a volte, a una shell del bootloader o del sistema operativo. Anche una console di sola lettura rivela mappe di memoria, driver flash, argomenti di avvio, layout delle partizioni e versioni del firmware. Il firmware può risiedere in SPI NOR/NAND, eMMC o un altro dispositivo; in genere non viene eseguito da una EEPROM, e i file scritti su un filesystem persistente montato non necessariamente scompaiono al riavvio.

Esistono diversi metodi di acquisizione; la sezione SPI tratta le letture dirette dalla flash esterna. L’acquisizione assistita da console può essere meno invasiva quando il bootloader mette già a disposizione un comando di lettura sicuro, ma qualsiasi interruzione dell’avvio o comando flash può compromettere la disponibilità: registra quindi lo stato originale ed evita operazioni di scrittura/cancellazione.

Il dump del firmware assistito da console spesso inizia interrompendo un bootloader. Molti dispositivi Linux embedded usano **Das U-Boot**, ma altri usano bootloader proprietari o disabilitano la console interattiva.

Per verificare la presenza di un bootloader interattivo, collega il percorso di ricezione UART e il terminale mentre il target è spento, avvia la registrazione e accendilo. Segui il prompt di autoboot visualizzato; a seconda della build, l’interruzione può richiedere un tasto, una breve sequenza oppure essere del tutto disabilitata.

Se l’interruzione riesce, usa `help`, `printenv` e i comandi di ricognizione in sola lettura per capire il layout di memoria e storage specifico del vendor prima di accedere agli indirizzi.

In U-Boot, `md` mostra la **memoria indirizzabile**, non automaticamente “l’EEPROM”. Per prima cosa, usa comandi specifici della scheda, come `mtd list`, `sf probe`, `mmc info`, `part list`, le variabili d’ambiente e i log di avvio, per identificare l’indirizzo mappato corretto o caricare una regione flash nella RAM. Quindi visualizza un intervallo noto byte per byte:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Registra l'output seriale prima di iniziare. L'output di `md.b` contiene indirizzi e una colonna ASCII, quindi è una rappresentazione testuale e non un'immagine ROM grezza.

Rimuovi le colonne degli indirizzi e ASCII, concatena solo i campi dei byte esadecimali e decodificali in formato binario (ad esempio con `xxd -r -p`). Verifica il numero di byte previsto e registra un hash prima dell'analisi:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifica quindi le firme note nel binario ricostruito. Una lettura diretta della flash tramite l’interfaccia SPI/eMMC/NAND appropriata è solitamente più rapida e meno soggetta a errori quando la console non riesce a trasferire i dati in modo affidabile.

U-Boot potrebbe disabilitare l’interruzione, richiedere una sequenza di tasti specifica del vendor o bloccare i comandi di memoria/flash. Segui il prompt di autoboot e il log di avvio invece di trasmettere caratteri alla cieca. Se non è possibile interrompere la console, conserva il log di avvio e passa a un metodo non invasivo per acquisire il firmware.

## References

- [1] [Manuale di riferimento della famiglia Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentazione Bus Pirate - modalità UART e limiti elettrici](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - scheda tecnica CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentazione U-Boot - comando `md` per visualizzare la memoria](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
