# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Prima di collegare un Bus Pirate, verifica la tensione target, il pinout, la configurazione dei pull-up e la massa comune. Non abilitare gli alimentatori del Bus Pirate su un bus alimentato dal dispositivo target solo per intercettarlo: i due alimentatori potrebbero entrare in conflitto e danneggiare l'hardware. La trascrizione seguente è un esempio specifico per Bus Pirate v3/firmware community, non una procedura di cablaggio universale.<sup>[[1]](#references)[[2]](#references)</sup>

Per verificare che un Bus Pirate funzioni, collega +5V a VPU e 3.3V ad ADC, accedi al Bus Pirate (ad esempio usando Tera Term) e usa il comando `~`:

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

Come puoi vedere nella riga di comando precedente, ha indicato di aver trovato 0 errori. È molto utile per verificare che funzioni dopo averlo acquistato o dopo aver flashato un firmware.

Per connetterti al Bus Pirate, puoi seguire la documentazione:

![Usa il comando - Premi spazio: per connetterti al Bus Pirate, puoi seguire la documentazione](<../../images/image (484).png>)

In questo caso, il target è una EEPROM I²C della famiglia 24C256. Verifica il suffisso esatto e il datasheet, perché la tensione di alimentazione supportata varia in base al componente.<sup>[[3]](#references)</sup>

![Usa il comando - Premi spazio: in questo caso mi collegherò a una EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Per comunicare con il Bus Pirate, ho usato Tera Term, connesso alla porta COM del Bus Pirate e con Setup --> Serial Port --> Speed impostato su 115200.\
Nella comunicazione seguente puoi vedere come preparare il Bus Pirate per usare I2C e come scrivere e leggere dalla memoria (i commenti iniziano con "#"; non aspettarti di trovare quella parte nella comunicazione):

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
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

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

In questo scenario intercetteremo la comunicazione I2C tra Arduino e la EPROM precedente. Devi solo far comunicare i due dispositivi e poi collegare il Bus Pirate ai pin SCL, SDA e GND:

![Read 20B from address 0x69 configured before - Sniffer: In this scenario we are going to sniff the I2C communication between the arduino and the previous EPROM, you just need to...](<../../images/image (166).png>)

```bash
I2C>m
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

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## Ricostruzione black-box del protocollo I2C

### Identificare il bus dai pin attivi

Quando la periferica non ha un pinout né una scheda tecnica, inizia in modo passivo con un analizzatore logico ad alta impedenza mentre l'host originale è in funzione. Dopo aver stabilito una massa comune e un livello logico sicuro, classifica i pin costanti come probabili alimentazioni, masse o segnali con pull-up, quindi confronta le linee attive con i bus più comuni: UART ha TX/RX asincroni e direzioni indipendenti; la SPI convenzionale espone normalmente clock, chip select e linee dati separate per le due direzioni; I2C ha un clock regolare e una linea dati bidirezionale. La decodifica I2C dovrebbe quindi mostrare indirizzi target a 7 bit, direzione di lettura/scrittura, ACK/NACK e payload ricorrenti.<sup>[[2]](#references)[[4]](#references)</sup>

Acquisisci diversi scambi legittimi e conserva sia i byte decodificati sia i timing grezzi. I frame ripetuti sono utili come test con risposta nota per i serializer usati in seguito, mentre le variazioni tra richieste possono rivelare probabili campi opcode, indice, offset, lunghezza, sequenza o checksum.<sup>[[4]](#references)</sup>

### Ricostruire il framing dal firmware dell'host

Se il firmware della periferica non è accessibile, estrai il firmware dell'**host** e individua il componente che apre il dispositivo I2C. Cerca stringhe e simboli relativi al nome della periferica, a `/dev/i2c-`, ai costruttori di comandi, ai parser delle risposte, alle routine di reset/inizializzazione e alle funzioni checksum. Per ogni costruttore, annota gli offset esatti dei campi, le costanti, le dimensioni degli argomenti accettate, la lunghezza del payload, i dati coperti dal checksum, l'ordine dei byte del checksum e la lunghezza del frame restituito, invece di dedurre il formato dai nomi delle funzioni.<sup>[[4]](#references)</sup>

Il nome di una funzione checksum come `crc16_ccitt` non basta per scegliere un preset. Determina la direzione dello shift, il byte dell'indice della tabella, il polinomio rappresentato dalla tabella, il registro iniziale, la riflessione in input/output, lo XOR/inversione finale e l'endianness usata dal serializer sul bus. Per esempio, una tabella per il byte meno significativo con shift a destra, basata sul polinomio invertito `0x8408`, inizializzata con `0xFFFF` e complementata alla fine, identifica **CRC-16/X-25 (IBM-SDLC)**. Un checksum corretto è spesso necessario per superare la validazione dell'integrità e raggiungere il parser dei comandi.<sup>[[4]](#references)</sup>

Dopo aver ricostruito il formato, cerca nomi di simboli e costanti distintivi nel codice pubblico. Nel caso MJA1, un wrapper SDK individuato indipendentemente ha confermato gli ID dei comandi, la validazione degli argomenti, le definizioni delle risposte e l'implementazione CRC speculare; usa codice di questo tipo come verifica, non come sostituto del controllo dell'esatto binario target e dell'ordine dei byte sul bus.<sup>[[4]](#references)[[5]](#references)</sup>

### Inviare frame da un host Linux con root

Un host Linux embedded compromesso può interagire con la periferica senza aggiungere un altro controller del bus. Apri l'adattatore pertinente, seleziona l'indirizzo a 7 bit con `I2C_SLAVE` e invia un frame prodotto da un serializer dedicato; mantieni una modalità raw-frame per le mutazioni e il fuzzing.<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

Compila in cross-compilazione con una toolchain compatibile con la CPU e la libc del target e confronta le tracce dell’analizzatore del client di test con il traffico legittimo. I confini delle transazioni, l’ordine delle operazioni di scrittura e lettura, i ritardi e lo stato delle periferiche possono essere importanti anche quando i byte visibili corrispondono.<sup>[[4]](#references)</sup>

### Enumerazione degli opcode guidata dalle risposte

Una volta individuati il frame valido più breve e il checksum, enumera l’intera larghezza dell’opcode e usa la risposta esplicita del protocollo per i **comandi non supportati** come baseline negativa. Un risultato diverso, come argomenti non validi, stato non valido o uno status non documentato, suggerisce che la decodifica abbia raggiunto un handler implementato o parzialmente implementato. Questo **non** dimostra che il sistema sia sfruttabile; assegna priorità al candidato per il fuzzing strutturato di lunghezze, argomenti, stati e sequenze di comandi.<sup>[[4]](#references)</sup>

Se un test blocca la periferica, automatizza un singolo caso isolato per ogni avvio, usando un controller esterno: connettiti via SSH, esegui il caso, salva la richiesta e la risposta grezze con i relativi tempi, riavvia o interrompi e ripristina l’alimentazione, attendi che i controlli di integrità vengano superati e poi continua. In seguito, spostare il componente su un fixture controllato da microcontrollore può consentire reset deterministici, controllo diretto dell’alimentazione e fuzzing più rapido.<sup>[[4]](#references)</sup>

## References

- [1] [Documentazione di Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Specifica del bus I²C e manuale utente](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Scheda tecnica della EEPROM seriale I²C AT24C256C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Black Box Probing: un’analisi di sicurezza del chip sicuro MJA1 di Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Wrapper crittografico MJA1 dell’SDK Mijia BLE](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
