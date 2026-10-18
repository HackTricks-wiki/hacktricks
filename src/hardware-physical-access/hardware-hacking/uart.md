# UART

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

UART è un'interfaccia seriale asincrona che trasferisce un flusso di bit incapsulato in frame senza un clock condiviso. Non confondere UART a livello logico con RS-232: RS-232 usa livelli di tensione diversi, spesso negativi, e richiede un transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

In genere, quando UART è nello stato di idle, la linea viene mantenuta alta (valore logico 1). Per segnalare l'inizio di un trasferimento dati, il trasmettitore invia al ricevitore un bit di start, durante il quale il segnale viene mantenuto basso (valore logico 0). Poi, il trasmettitore invia da cinque a otto bit di dati contenenti il messaggio effettivo, seguiti da un bit di parità facoltativo e da uno o due bit di stop (con valore logico 1), a seconda della configurazione. Il bit di parità, usato per il controllo degli errori, si incontra raramente nella pratica. Il bit (o i bit) di stop indicano la fine della trasmissione.

La configurazione più comune è 8N1: otto bit di dati, nessuna parità e un bit di stop. UART invia per primo il bit meno significativo dei dati, quindi il carattere ASCII `C` (`0x43`) viene trasmesso come: start `0`; dati `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: La configurazione più comune è 8N1: otto bit di dati, nessuna parità e un bit di stop. Per esempio, per inviare il carattere C, ovvero 0x43 in ASCII, con UART 8N1](<../../images/image (764).png>)

Strumenti hardware per comunicare tramite UART:

- Adattatore da USB a seriale
- Adattatori con chip CP2102 o PL2303
- Strumenti multiuso come Bus Pirate, Adafruit FT232H, Shikra o Attify Badge

### Identificazione delle porte UART

Un tipico header di debug espone **TX**, **RX** e **GND**; può anche esporre un pin **Vcc/Vref**, reset o pin di controllo del flusso. Vcc non è un segnale UART e normalmente va usato solo come riferimento di tensione, non collegato come sorgente di alimentazione, a meno che non si conoscano lo schema della scheda e i requisiti di corrente.<sup>[[2]](#references)[[3]](#references)</sup>

Inizia con il dispositivo **spento** e scollegato:

- Identifica **GND** in modalità continuità, confrontandolo con un piano di massa noto, la schermatura di un connettore o la massa dell'alimentazione. Non usare mai la modalità continuità/resistenza su una scheda alimentata.
- Prima di alimentare il target, passa alla modalità tensione continua. Misura i pin candidati rispetto alla massa per identificare la tensione logica. Un'alimentazione stabile potrebbe essere Vcc/Vref; non dare per scontato che sia sicura da collegare.
- Osserva i pin candidati con un analizzatore logico o un oscilloscopio durante l'avvio. **TX** è comunemente in idle alto e mostra raffiche di dati incapsulati in frame. Un multimetro potrebbe mostrare una fluttuazione media, ma non può verificare il framing o il baud rate.
- **RX** potrebbe rimanere in idle e non può essere identificato in sicurezza solo perché si trova accanto a TX. Segui le piste del PCB, consulta il datasheet del SoC o usa un analizzatore ad alta impedenza prima di applicare un segnale.

Scambiare TX e RX normalmente non produce comunicazione; confondere alimentazione, massa o livelli del segnale può danneggiare in modo permanente il target o l'adattatore. Collega prima la massa e inizia in modalità **solo ricezione** (TX del target verso RX dell'adattatore).

I produttori possono omettere l'header, non montare le resistenze in serie, disabilitare la console nel firmware o esporre solo TX. Segui le piazzole di test e le impronte delle resistenze vicine fino al SoC e aggiungi una connessione temporanea ad alta impedenza solo dopo aver verificato il livello elettrico. La presenza di una garanzia non implica che debba esistere una UART accessibile.

### Identificazione del baud rate UART

Il modo più semplice per identificare il baud rate corretto è osservare l'uscita del pin **TX** e provare a leggere i dati. Se i dati ricevuti non sono leggibili, passa al baud rate successivo possibile finché i dati non diventano leggibili. Puoi usare un adattatore da USB a seriale o uno strumento multiuso come Bus Pirate, insieme a uno script helper, come [baudrate.py](https://github.com/devttys0/baudrate/). I baud rate più comuni sono 9600, 38400, 19200, 57600 e 115200.

> [!CAUTION]
> È importante ricordare che, con questo protocollo, devi collegare il TX di un dispositivo all'RX dell'altro!

### Acquisizione automatizzata dell'output UART all'avvio con SCPI

Se l'output di avvio è breve o la piazzola TX non è ancora stata identificata, automatizza i riavvii ripetuti invece di azionare manualmente l'alimentatore e l'oscilloscopio. Collega un alimentatore programmabile con limitazione di corrente all'ingresso di alimentazione verificato del target. Usa un ingresso dell'oscilloscopio ad alta impedenza e una massa condivisa per sondare ogni piazzola TX candidata; non applicare segnali alla piazzola.<sup>[[5]](#references)</sup>

VISA apre sessioni con strumenti seriali o Ethernet, mentre SCPI controlla l'uscita, il trigger e la lettura della forma d'onda.<sup>[[5]](#references)[[6]](#references)</sup> Installa `pyvisa` e `pyvisa-py` (oltre a `pyserial` per le risorse VISA seriali); `ResourceManager('@py')` seleziona esplicitamente il backend Python.<sup>[[5]](#references)[[7]](#references)</sup> Sostituisci le stringhe delle risorse e i comandi con quelli supportati dagli strumenti in uso.<sup>[[5]](#references)</sup>

Nell'esempio con Rigol MSO5000, attiva un trigger singolo sul fronte di discesa prima di alimentare la scheda: il pin TX UART, normalmente alto in idle, scende per primo durante il bit di start.<sup>[[5]](#references)</sup> Imposta la soglia del trigger tra i livelli misurati di idle e basso e imposta la base dei tempi in modo da coprire l'intervallo di avvio desiderato.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` può sopprimere i fronti ripetuti nelle acquisizioni continue, ma non sostituisce la verifica che un'acquisizione a colpo singolo sia effettivamente completata.<sup>[[5]](#references)</sup> Il codice seguente acquisisce un avvio e salva sia i campioni come byte senza segno sia i metadati di scalatura; in caso di timeout, spegne il target invece di attendere all'infinito.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>Acquisizione della forma d'onda UART a colpo singolo all'accensione con PyVISA</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

Per un pad survey, ripeti l'acquisizione singola dopo aver spostato la sonda, oppure lascia aperta la sessione dell'alimentatore e cicla la sua uscita con un intervallo di avvio e uno di spegnimento. Riattiva l'oscilloscopio prima di ogni accensione, così ogni file corrisponde a un avvio e a un pad.<sup>[[5]](#references)</sup>

Il preambolo Rigol è `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> Il **terzo** valore è il numero di punti, non la frequenza di campionamento come affermato nell'articolo.<sup>[[5]](#references)[[6]](#references)</sup> Nell'esempio, `25,000,000` punti e `xincrement = 2e-8` secondi implicano `1 / xincrement = 50,000,000` campioni/secondo, non 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Conserva il preambolo insieme al file binario e verifica che la lunghezza letta corrisponda a `<points>`; la guida documenta letture segmentate/a batch per record di grandi dimensioni.<sup>[[6]](#references)</sup>

Per decodificare il segnale acquisito, importa `capture.bin` in PulseView come **Raw Analog Data Without Header**, seleziona valori unsigned a 8 bit (`U8`) e inserisci la frequenza di campionamento calcolata da `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Applica **Logic via Threshold** al canale analogico, scegliendo una soglia tra i valori di campionamento basso e alto.<sup>[[5]](#references)</sup> Misura la durata di un bit di start pulito per stimare il baud rate (circa 17.36 µs per 57,600 baud), poi applica il decoder UART di PulseView e verifica che diversi frame vengano decodificati in modo coerente.<sup>[[5]](#references)</sup> Un singolo fronte di discesa non dimostra che un pad sia UART.

## Adattatore CP210X UART-to-TTY

I bridge CP210x USB-to-UART sono presenti su molte schede di prototipazione e adattatori economici. I moduli più comuni espongono i pin di alimentazione insieme a GND, RXD e TXD, ma i connettori e i livelli I/O variano. Verifica la tensione effettiva consultando il progetto della scheda o la scheda tecnica. Di solito collega solo GND e l'RX dell'adattatore al TX del target; dopo aver verificato la sola ricezione, collega anche il TX dell'adattatore all'RX del target. Non collegare il pin di alimentazione a 5 V/3.3 V dell'adattatore, a meno che tu non voglia alimentare intenzionalmente un target di cui sai che tollera tale tensione.<sup>[[3]](#references)</sup>

Se l'adattatore non viene rilevato, verifica che i driver CP210X siano installati sul sistema host. Una volta rilevato e collegato l'adattatore, puoi usare strumenti come picocom, minicom o screen.

Per elencare i dispositivi collegati ai sistemi Linux/MacOS:

```
ls /dev/
```

Per interagire in modo basilare con l'interfaccia UART, usa il seguente comando:

```
picocom /dev/<adapter> --baud <baudrate>
```

Per minicom, usa il seguente comando per configurarlo:

```
minicom -s
```

Configura le impostazioni, come il baud rate e il nome del dispositivo, nell'opzione `Serial port setup`.

Dopo la configurazione, esegui `minicom` per aprire la console UART.

## UART tramite Arduino UNO R3 (schede con chip Atmel 328p rimovibile)

Nel caso in cui non siano disponibili adattatori seriale-USB UART, è possibile usare Arduino UNO R3 con un rapido hack. Poiché Arduino UNO R3 è solitamente disponibile ovunque, può far risparmiare molto tempo.

Arduino UNO R3 ha un adattatore USB-seriale integrato nella scheda. Per ottenere una connessione UART, basta estrarre il microcontrollore Atmel 328p dalla scheda. Questo hack funziona con le varianti di Arduino UNO R3 in cui l'Atmel 328p non è saldato alla scheda (viene usata la versione SMD). Collega il pin RX di Arduino (pin digitale 0) al pin TX dell'interfaccia UART e il pin TX di Arduino (pin digitale 1) al pin RX dell'interfaccia UART.

Usa il **Serial Monitor** dell'Arduino IDE o un terminale dedicato con il baud rate di destinazione. I segnali seriali del classico Uno R3 usano una logica a 5 V, quindi usa un level shifter o un partitore prima di collegarli a un dispositivo di destinazione a 3,3 V o con tensione inferiore.

## Bus Pirate

La trascrizione seguente usa l'interfaccia del firmware legacy di Bus Pirate per monitorare l'output UART. Le versioni più recenti del firmware Bus Pirate usano comandi come `m uart`, `{`/`}`, `monitor` o `bridge`; consulta la documentazione della versione installata.<sup>[[2]](#references)</sup>

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

Una console UART fornisce accesso in runtime ai log di avvio e, talvolta, a una shell del bootloader o del sistema operativo. Anche una console in sola lettura può rivelare mappe di memoria, driver flash, argomenti di avvio, layout delle partizioni e versioni del firmware. Il firmware può risiedere in SPI NOR/NAND, eMMC o un altro dispositivo; in genere non viene eseguito da una EEPROM e i file scritti su un filesystem persistente montato non necessariamente scompaiono al riavvio.

Esistono diversi metodi di acquisizione; la sezione SPI tratta le letture dirette dalla flash esterna. L’acquisizione assistita dalla console può essere meno invasiva quando il bootloader offre già un comando di lettura sicuro, ma qualsiasi interruzione dell’avvio o comando flash può influire sulla disponibilità: registra lo stato originale ed evita le operazioni di scrittura/cancellazione.

Il dumping del firmware assistito dalla console spesso inizia interrompendo un bootloader. Molti dispositivi Linux embedded usano **Das U-Boot**, ma altri usano bootloader proprietari oppure disabilitano la console interattiva.

Per verificare la presenza di un bootloader interattivo, collega il percorso di ricezione UART e il terminale mentre il target è spento, avvia la registrazione e accendilo. Segui il prompt di autoboot visualizzato; a seconda della build, per interromperlo potrebbe essere necessario premere un tasto, eseguire una breve sequenza oppure l’interruzione potrebbe essere completamente disabilitata.

Se l’interruzione riesce, usa `help`, `printenv` e i comandi di ricognizione in sola lettura per comprendere il layout di memoria e archiviazione specifico del vendor prima di accedere agli indirizzi.

In U-Boot, `md` mostra la **memoria indirizzabile**, non automaticamente “la EEPROM”. Prima usa comandi specifici della scheda, come `mtd list`, `sf probe`, `mmc info`, `part list`, le variabili d’ambiente e i log di avvio, per individuare l’indirizzo mappato corretto oppure caricare una regione flash nella RAM. Poi visualizza un intervallo noto byte per byte:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Registra l’output seriale prima di iniziare. L’output di `md.b` contiene indirizzi e una colonna ASCII, quindi è una rappresentazione testuale, non un’immagine ROM grezza.

Rimuovi le colonne degli indirizzi e ASCII, concatena solo i campi esadecimali dei byte e decodificali in formato binario (ad esempio con `xxd -r -p`). Verifica il numero di byte atteso e registra un hash prima dell’analisi:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifica quindi le firme note nel binario ricostruito. Una lettura diretta della flash tramite l’interfaccia SPI/eMMC/NAND appropriata è solitamente più rapida e meno soggetta a errori quando la console non riesce a trasferire i dati in modo affidabile.

U-Boot potrebbe disabilitare l’interruzione, richiedere una sequenza di tasti specifica del vendor o bloccare i comandi per la memoria/flash. Segui il prompt di autoboot e il log di avvio invece di trasmettere caratteri alla cieca. Se non è possibile interrompere la console, conserva il log di avvio e passa a un metodo non invasivo di acquisizione del firmware.

## References

- [1] [Manuale di riferimento della famiglia Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentazione Bus Pirate - modalità UART e limiti elettrici](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - scheda tecnica CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentazione U-Boot - comando `md` per visualizzare la memoria](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI e strumentazione hardware per reverse engineer, parte 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Guida alla programmazione Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Configurazione del backend](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
