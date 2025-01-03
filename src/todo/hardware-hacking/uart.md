# UART

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

UART è un protocollo seriale, il che significa che trasferisce dati tra componenti un bit alla volta. Al contrario, i protocolli di comunicazione parallela trasmettono dati simultaneamente attraverso più canali. I protocolli seriali comuni includono RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express e USB.

In generale, la linea è mantenuta alta (a un valore logico di 1) mentre UART è nello stato inattivo. Poi, per segnalare l'inizio di un trasferimento di dati, il trasmettitore invia un bit di avvio al ricevitore, durante il quale il segnale è mantenuto basso (a un valore logico di 0). Successivamente, il trasmettitore invia da cinque a otto bit di dati contenenti il messaggio reale, seguiti da un bit di parità opzionale e uno o due bit di stop (con un valore logico di 1), a seconda della configurazione. Il bit di parità, utilizzato per il controllo degli errori, è raramente visto in pratica. Il bit di stop (o i bit) segnalano la fine della trasmissione.

Chiamiamo la configurazione più comune 8N1: otto bit di dati, nessun bit di parità e un bit di stop. Ad esempio, se volessimo inviare il carattere C, o 0x43 in ASCII, in una configurazione UART 8N1, invieremmo i seguenti bit: 0 (il bit di avvio); 0, 1, 0, 0, 0, 0, 1, 1 (il valore di 0x43 in binario), e 0 (il bit di stop).

![](<../../images/image (764).png>)

Strumenti hardware per comunicare con UART:

- Adattatore USB-seriale
- Adattatori con i chip CP2102 o PL2303
- Strumento multifunzione come: Bus Pirate, l'Adafruit FT232H, lo Shikra o l'Attify Badge

### Identificazione delle porte UART

UART ha 4 porte: **TX**(Trasmetti), **RX**(Ricevi), **Vcc**(Tensione) e **GND**(Terra). Potresti essere in grado di trovare 4 porte con le lettere **`TX`** e **`RX`** **scritte** nel PCB. Ma se non c'è alcuna indicazione, potresti dover provare a trovarle tu stesso usando un **multimetro** o un **analizzatore logico**.

Con un **multimetro** e il dispositivo spento:

- Per identificare il pin **GND**, usa la modalità **Test di Continuità**, posiziona il cavo di massa nel terreno e prova con quello rosso finché non senti un suono dal multimetro. Diversi pin GND possono essere trovati nel PCB, quindi potresti aver trovato o meno quello appartenente a UART.
- Per identificare la **porta VCC**, imposta la **modalità di tensione DC** e impostala su 20 V di tensione. Sonda nera a terra e sonda rossa sul pin. Accendi il dispositivo. Se il multimetro misura una tensione costante di 3.3 V o 5 V, hai trovato il pin Vcc. Se ottieni altre tensioni, riprova con altre porte.
- Per identificare la **porta TX**, imposta la **modalità di tensione DC** fino a 20 V di tensione, sonda nera a terra e sonda rossa sul pin, e accendi il dispositivo. Se trovi che la tensione fluttua per alcuni secondi e poi si stabilizza al valore Vcc, hai molto probabilmente trovato la porta TX. Questo perché all'accensione, invia alcuni dati di debug.
- La porta **RX** sarebbe la più vicina alle altre 3, ha la fluttuazione di tensione più bassa e il valore complessivo più basso di tutti i pin UART.

Puoi confondere le porte TX e RX e non succederebbe nulla, ma se confondi la porta GND e la porta VCC potresti danneggiare il circuito.

In alcuni dispositivi target, la porta UART è disabilitata dal produttore disabilitando RX o TX o anche entrambi. In tal caso, può essere utile tracciare le connessioni nel circuito stampato e trovare qualche punto di breakout. Un forte indizio per confermare la mancata rilevazione di UART e la rottura del circuito è controllare la garanzia del dispositivo. Se il dispositivo è stato spedito con una garanzia, il produttore lascia alcune interfacce di debug (in questo caso, UART) e quindi, deve aver disconnesso l'UART e lo ricollegherà durante il debug. Questi pin di breakout possono essere collegati saldando o utilizzando fili jumper.

### Identificazione della velocità di baud UART

Il modo più semplice per identificare la corretta velocità di baud è guardare l'**uscita del pin TX e provare a leggere i dati**. Se i dati che ricevi non sono leggibili, passa alla successiva possibile velocità di baud finché i dati non diventano leggibili. Puoi usare un adattatore USB-seriale o un dispositivo multifunzione come Bus Pirate per farlo, abbinato a uno script di aiuto, come [baudrate.py](https://github.com/devttys0/baudrate/). Le velocità di baud più comuni sono 9600, 38400, 19200, 57600 e 115200.

> [!CAUTION]
> È importante notare che in questo protocollo è necessario collegare il TX di un dispositivo all'RX dell'altro!

## Adattatore CP210X UART a TTY

Il chip CP210X è utilizzato in molte schede di prototipazione come NodeMCU (con esp8266) per la comunicazione seriale. Questi adattatori sono relativamente economici e possono essere utilizzati per collegarsi all'interfaccia UART del target. Il dispositivo ha 5 pin: 5V, GND, RXD, TXD, 3.3V. Assicurati di collegare la tensione come supportata dal target per evitare danni. Infine, collega il pin RXD dell'adattatore al TXD del target e il pin TXD dell'adattatore all'RXD del target.

Nel caso in cui l'adattatore non venga rilevato, assicurati che i driver CP210X siano installati nel sistema host. Una volta che l'adattatore è stato rilevato e connesso, strumenti come picocom, minicom o screen possono essere utilizzati.

Per elencare i dispositivi connessi ai sistemi Linux/MacOS:
```
ls /dev/
```
Per un'interazione di base con l'interfaccia UART, usa il seguente comando:
```
picocom /dev/<adapter> --baud <baudrate>
```
Per minicom, usa il seguente comando per configurarlo:
```
minicom -s
```
Configura le impostazioni come baudrate e nome del dispositivo nell'opzione `Serial port setup`.

Dopo la configurazione, usa il comando `minicom` per avviare la Console UART.

## UART Via Arduino UNO R3 (Schede con Chip Atmel 328p Rimovibile)

Nel caso in cui gli adattatori UART Serial to USB non siano disponibili, l'Arduino UNO R3 può essere utilizzato con un rapido hack. Poiché l'Arduino UNO R3 è solitamente disponibile ovunque, questo può far risparmiare molto tempo.

L'Arduino UNO R3 ha un adattatore USB to Serial integrato sulla scheda stessa. Per ottenere la connessione UART, basta estrarre il chip microcontrollore Atmel 328p dalla scheda. Questo hack funziona sulle varianti di Arduino UNO R3 che hanno l'Atmel 328p non saldato sulla scheda (viene utilizzata la versione SMD). Collega il pin RX dell'Arduino (Pin Digitale 0) al pin TX dell'interfaccia UART e il pin TX dell'Arduino (Pin Digitale 1) al pin RX dell'interfaccia UART.

Infine, si consiglia di utilizzare l'Arduino IDE per ottenere la Console Serial. Nella sezione `tools` del menu, seleziona l'opzione `Serial Console` e imposta il baud rate secondo l'interfaccia UART.

## Bus Pirate

In questo scenario andremo a sniffare la comunicazione UART dell'Arduino che sta inviando tutte le stampe del programma al Serial Monitor.
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
## Dumping Firmware with UART Console

La Console UART offre un ottimo modo per lavorare con il firmware sottostante nell'ambiente di runtime. Ma quando l'accesso alla Console UART è in sola lettura, potrebbe introdurre molte limitazioni. In molti dispositivi embedded, il firmware è memorizzato in EEPROM e viene eseguito in processori che hanno memoria volatile. Pertanto, il firmware è mantenuto in sola lettura poiché il firmware originale durante la produzione è all'interno dell'EEPROM stessa e eventuali nuovi file andrebbero persi a causa della memoria volatile. Pertanto, il dumping del firmware è uno sforzo prezioso quando si lavora con firmware embedded.

Ci sono molti modi per farlo e la sezione SPI copre metodi per estrarre il firmware direttamente dall'EEPROM con vari dispositivi. Tuttavia, si consiglia di provare prima a fare il dumping del firmware con UART poiché il dumping del firmware con dispositivi fisici e interazioni esterne può essere rischioso.

Il dumping del firmware dalla Console UART richiede prima di ottenere accesso ai bootloader. Molti fornitori popolari utilizzano uboot (Universal Bootloader) come loro bootloader per caricare Linux. Pertanto, è necessario ottenere accesso a uboot.

Per ottenere accesso al bootloader, collegare la porta UART al computer e utilizzare uno qualsiasi degli strumenti della Console Seriale e mantenere l'alimentazione del dispositivo disconnessa. Una volta che la configurazione è pronta, premere il tasto Invio e tenerlo premuto. Infine, collegare l'alimentazione al dispositivo e lasciarlo avviarsi.

Fare questo interromperà il caricamento di uboot e fornirà un menu. Si consiglia di comprendere i comandi di uboot e utilizzare il menu di aiuto per elencarli. Questo potrebbe essere il comando `help`. Poiché diversi fornitori utilizzano configurazioni diverse, è necessario comprendere ciascuna di esse separatamente.

Di solito, il comando per fare il dumping del firmware è:
```
md
```
che sta per "memory dump". Questo dump sarà il contenuto della memoria (EEPROM) sullo schermo. Si consiglia di registrare l'output della Console Seriale prima di iniziare la procedura per catturare il memory dump.

Infine, rimuovi tutti i dati non necessari dal file di log e salva il file come `filename.rom` e usa binwalk per estrarre i contenuti:
```
binwalk -e <filename.rom>
```
Questo elencherà i possibili contenuti dell'EEPROM in base alle firme trovate nel file hex.

Tuttavia, è necessario notare che non è sempre il caso che il uboot sia sbloccato anche se viene utilizzato. Se il tasto Enter non fa nulla, controlla altri tasti come il tasto Spazio, ecc. Se il bootloader è bloccato e non viene interrotto, questo metodo non funzionerebbe. Per verificare se uboot è il bootloader per il dispositivo, controlla l'output sulla Console UART durante l'avvio del dispositivo. Potrebbe menzionare uboot durante l'avvio.

{{#include ../../banners/hacktricks-training.md}}
