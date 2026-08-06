# UART

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

UART è un protocollo seriale, ovvero trasferisce i dati tra i componenti un bit alla volta. Al contrario, i protocolli di comunicazione parallela trasmettono i dati simultaneamente attraverso più canali. I protocolli seriali comuni includono RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express e USB.

Generalmente, la linea viene mantenuta alta (con valore logico 1) mentre UART si trova nello stato inattivo. Quindi, per segnalare l'inizio di un trasferimento dati, il trasmettitore invia un bit di start al ricevitore, durante il quale il segnale viene mantenuto basso (con valore logico 0). Successivamente, il trasmettitore invia da cinque a otto bit di dati contenenti il messaggio effettivo, seguiti da un bit di parità opzionale e da uno o due bit di stop (con valore logico 1), a seconda della configurazione. Il bit di parità, utilizzato per il controllo degli errori, viene raramente utilizzato nella pratica. Il bit (o i bit) di stop indicano la fine della trasmissione.

La configurazione più comune è chiamata 8N1: otto bit di dati, nessuna parità e un bit di stop. Ad esempio, se volessimo inviare il carattere C, ovvero 0x43 in ASCII, in una configurazione UART 8N1, invieremmo i seguenti bit: 0 (il bit di start); 0, 1, 0, 0, 0, 0, 1, 1 (il valore di 0x43 in binario) e 0 (il bit di stop).

![UART: La configurazione più comune è chiamata 8N1: otto bit di dati, nessuna parità e un bit di stop. Ad esempio, se volessimo inviare il carattere C, ovvero 0x43 in ASCII, in una configurazione UART 8N1](<../../images/image (764).png>)

Strumenti hardware per comunicare con UART:

- Adattatore da USB a seriale
- Adattatori con i chip CP2102 o PL2303
- Strumento multiuso come: Bus Pirate, Adafruit FT232H, Shikra o Attify Badge

### Identificazione delle porte UART

UART ha 4 porte: **TX** (Transmit), **RX** (Receive), **Vcc** (Voltage) e **GND** (Ground). Potresti riuscire a trovare 4 porte con le lettere **`TX`** e **`RX`** **scritte** sul PCB. Tuttavia, se non è presente alcuna indicazione, potresti doverle individuare autonomamente utilizzando un **multimetro** o un **logic analyzer**.

Con un **multimetro** e il dispositivo spento:

- Per identificare il pin **GND**, utilizza la modalità **Continuity Test**, posiziona il puntale nero sulla massa e verifica con quello rosso finché non senti un suono provenire dal multimetro. Sul PCB possono essere presenti diversi pin GND, quindi potresti aver trovato oppure no quello appartenente a UART.
- Per identificare la porta **VCC**, imposta la **modalità tensione CC** e seleziona un intervallo fino a 20 V. Posiziona il puntale nero sulla massa e quello rosso sul pin. Accendi il dispositivo. Se il multimetro misura una tensione costante di 3,3 V o 5 V, hai trovato il pin Vcc. Se ottieni altre tensioni, riprova con altre porte.
- Per identificare la porta **TX**, imposta la **modalità tensione CC** fino a 20 V, posiziona il puntale nero sulla massa e quello rosso sul pin, quindi accendi il dispositivo. Se la tensione varia per alcuni secondi e poi si stabilizza al valore Vcc, molto probabilmente hai trovato la porta TX. Questo accade perché, all'accensione, il dispositivo invia alcuni dati di debug.
- La **porta RX** dovrebbe essere quella più vicina alle altre 3; presenta la variazione di tensione e il valore complessivo più bassi tra tutti i pin UART.

È possibile confondere le porte TX e RX senza che accada nulla, ma se confondi GND e VCC potresti bruciare il circuito.

In alcuni dispositivi target, la porta UART viene disabilitata dal produttore disabilitando RX o TX, oppure entrambi. In tal caso, può essere utile seguire le connessioni sulla scheda del circuito e individuare un breakout point. Un forte indizio per confermare l'assenza di rilevamento di UART e l'interruzione del circuito consiste nel controllare la garanzia del dispositivo. Se il dispositivo è stato fornito con una garanzia, il produttore lascia alcune interfacce di debug (in questo caso UART) e quindi deve aver disconnesso UART, per poi ricollegarla durante il debug. Questi breakout pin possono essere collegati mediante saldatura o jumper wire.

### Identificazione del baud rate UART

Il modo più semplice per identificare il baud rate corretto consiste nell'osservare l'**output del pin TX e provare a leggere i dati**. Se i dati ricevuti non sono leggibili, passa al baud rate possibile successivo finché i dati non diventano leggibili. Per farlo, puoi utilizzare un adattatore da USB a seriale oppure un dispositivo multiuso come Bus Pirate, insieme a uno script di supporto, come [baudrate.py](https://github.com/devttys0/baudrate/). I baud rate più comuni sono 9600, 38400, 19200, 57600 e 115200.

> [!CAUTION]
> È importante notare che in questo protocollo è necessario collegare il TX di un dispositivo all'RX dell'altro!

## Adattatore da UART CP210X a TTY

Il chip CP210X viene utilizzato in molte schede di prototipazione, come NodeMCU (con esp8266), per la comunicazione seriale. Questi adattatori sono relativamente economici e possono essere utilizzati per connettersi all'interfaccia UART del target. Il dispositivo dispone di 5 pin: 5V, GND, RXD, TXD, 3.3V. Assicurati di collegare una tensione supportata dal target per evitare danni. Infine, collega il pin RXD dell'adattatore al TXD del target e il pin TXD dell'adattatore all'RXD del target.

Se l'adattatore non viene rilevato, assicurati che i driver CP210X siano installati nel sistema host. Una volta rilevato e collegato l'adattatore, è possibile utilizzare strumenti come picocom, minicom o screen.

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
Configura le impostazioni come baudrate e nome del dispositivo nell'opzione `Serial port setup`.

Dopo la configurazione, usa il comando `minicom` per avviare la UART Console.

## UART Tramite Arduino UNO R3 (Schede con chip Atmel 328p rimovibile)

Nel caso in cui gli adattatori UART Serial to USB non siano disponibili, è possibile usare Arduino UNO R3 con un quick hack. Poiché Arduino UNO R3 è generalmente disponibile ovunque, questo può far risparmiare molto tempo.

Arduino UNO R3 dispone di un adattatore USB to Serial integrato direttamente sulla scheda. Per ottenere una connessione UART, è sufficiente rimuovere dalla scheda il chip microcontroller Atmel 328p. Questo hack funziona sulle varianti di Arduino UNO R3 in cui l'Atmel 328p non è saldato sulla scheda (in questa versione viene usata la variante SMD). Collega il pin RX di Arduino (Digital Pin 0) al pin TX dell'interfaccia UART e il pin TX di Arduino (Digital Pin 1) al pin RX dell'interfaccia UART.

Infine, è consigliato usare Arduino IDE per ottenere la Serial Console. Nella sezione `tools` del menu, seleziona l'opzione `Serial Console` e imposta il baud rate in base all'interfaccia UART.

## Bus Pirate

In questo scenario andremo a sniffare la comunicazione UART di Arduino, che invia tutte le stampe del programma al Serial Monitor.
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
## Dumping del Firmware con la Console UART

La Console UART offre un ottimo modo per lavorare con il firmware sottostante nell'ambiente di runtime. Tuttavia, quando l'accesso alla Console UART è in sola lettura, può introdurre molte limitazioni. In molti dispositivi embedded, il firmware è memorizzato nelle EEPROM ed eseguito su processori dotati di memoria volatile. Di conseguenza, il firmware viene mantenuto in sola lettura, poiché il firmware originale presente durante la produzione si trova nella EEPROM e qualsiasi nuovo file andrebbe perso a causa della memoria volatile. Pertanto, il dumping del firmware è un'attività preziosa quando si lavora con firmware embedded.

Esistono molti modi per farlo e la sezione SPI illustra i metodi per estrarre direttamente il firmware dalla EEPROM utilizzando vari dispositivi. Tuttavia, è consigliabile provare prima a eseguire il dumping del firmware tramite UART, poiché il dumping del firmware con dispositivi fisici e interazioni esterne può essere rischioso.

Il dumping del firmware dalla Console UART richiede innanzitutto di ottenere l'accesso ai bootloader. Molti vendor popolari utilizzano uboot (Universal Bootloader) come bootloader per caricare Linux. Pertanto, è necessario ottenere l'accesso a uboot.

Per accedere al bootloader, collega la porta UART al computer e utilizza uno qualsiasi degli strumenti per Serial Console, mantenendo scollegata l'alimentazione del dispositivo. Quando la configurazione è pronta, premi e tieni premuto il tasto Invio. Infine, collega l'alimentazione al dispositivo e lascia che esegua il boot.

In questo modo interromperai il caricamento di uboot e verrà visualizzato un menu. È consigliabile comprendere i comandi di uboot e utilizzare il menu `help` per elencarli. Questo potrebbe essere il comando `help`. Poiché vendor diversi utilizzano configurazioni diverse, è necessario comprenderle separatamente.

Di solito, il comando per eseguire il dumping del firmware è:
```
md
```
che sta per "memory dump". Questo scaricherà la memoria (contenuto EEPROM) sullo schermo. È consigliabile registrare l'output della Serial Console prima di avviare la procedura, per acquisire il memory dump.

Infine, rimuovi semplicemente tutti i dati non necessari dal file di log, salva il file come `filename.rom` e usa binwalk per estrarne i contenuti:
```
binwalk -e <filename.rom>
```
Questo elencherà i possibili contenuti della EEPROM in base alle signature trovate nel file hex.

Tuttavia, è necessario notare che non è sempre vero che uboot sia sbloccato, anche se viene utilizzato. Se il tasto Enter non produce alcun effetto, prova tasti diversi, come il tasto Space, ecc. Se il bootloader è bloccato e non viene interrotto, questo metodo non funzionerà. Per verificare se uboot è il bootloader del dispositivo, controlla l'output sulla UART Console durante l'avvio del dispositivo. Potrebbe menzionare uboot durante l'avvio.

{{#include ../../banners/hacktricks-training.md}}
