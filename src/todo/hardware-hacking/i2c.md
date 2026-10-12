# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Überprüfe Zielspannung, Pinbelegung, Pull-up-Beschaltung und gemeinsame Masse, bevor du einen Bus Pirate anschließt. Aktiviere nicht die Stromversorgung des Bus Pirate an einem aktiven, vom Zielgerät versorgten Bus, nur um ihn abzuhören; zwei Stromversorgungen können gegeneinander arbeiten und Hardware beschädigen. Das folgende Transkript ist ein gerätespezifisches Beispiel für einen Bus Pirate v3 mit Community-Firmware und keine universelle Verdrahtungsanleitung.<sup>[[1]](#references)[[2]](#references)</sup>

Um zu prüfen, ob ein Bus Pirate funktioniert, verbinde +5V mit VPU und 3.3V mit ADC, greife auf den Bus Pirate zu (zum Beispiel mit Tera Term) und verwende den Befehl `~`:

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

Wie du in der vorherigen Befehlszeile sehen kannst, wurden 0 Fehler gefunden. Das ist sehr nützlich, um nach dem Kauf oder dem Flashen einer Firmware sicherzustellen, dass alles funktioniert.

Um eine Verbindung mit dem Bus Pirate herzustellen, kannst du der Dokumentation folgen:

![Befehl verwenden – Leertaste drücken: Um eine Verbindung mit dem Bus Pirate herzustellen, kannst du der Dokumentation folgen](<../../images/image (484).png>)

In diesem Fall ist das Ziel ein I²C-EEPROM der 24C256-Familie. Prüfe die genaue Endung und das Datenblatt, da die unterstützte Versorgungsspannung je nach Bauteil variiert.<sup>[[3]](#references)</sup>

![Befehl verwenden – Leertaste drücken: In diesem Fall verbinde ich mich mit einem EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Um mit dem Bus Pirate zu kommunizieren, habe ich Tera Term verwendet, das mit dem COM-Port des Bus Pirate verbunden war. Unter Setup --> Serial Port habe ich eine Geschwindigkeit von 115200 eingestellt.\
In der folgenden Kommunikation siehst du, wie du den Bus Pirate für die I²C-Kommunikation vorbereitest und Daten in den Speicher schreibst und daraus liest (Kommentare beginnen mit „#“; erwarte diesen Teil nicht in der Kommunikation):

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

In diesem Szenario werden wir die I2C-Kommunikation zwischen dem Arduino und dem vorherigen EPROM sniffen. Du musst nur mit beiden Geräten kommunizieren und anschließend den Bus Pirate mit den Pins SCL, SDA und GND verbinden:

![20 B von der zuvor konfigurierten Adresse 0x69 lesen – Sniffer: In diesem Szenario werden wir die I2C-Kommunikation zwischen dem Arduino und dem vorherigen EPROM sniffen. Du musst nur...](<../../images/image (166).png>)

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

## Black-box-I2C-Protokollrekonstruktion

### Bus anhand aktiver Pins identifizieren

Wenn das Peripheriegerät weder Pinout noch Datenblatt hat, beginne passiv mit einem hochohmigen Logic Analyzer, während der ursprüngliche Host in Betrieb ist. Stelle eine gemeinsame Masse und einen sicheren Logikpegel her, ordne dann konstante Pins wahrscheinlich Versorgungsschienen, Masse oder Pull-up-Signalen zu und vergleiche die aktiven Leitungen mit gängigen Bussen: UART hat asynchrone, unabhängig gerichtete TX/RX-Leitungen; konventionelles SPI verfügt normalerweise über Takt, Chip Select und getrennte Datenrichtungen; I2C hat einen regelmäßigen Takt und eine bidirektionale Datenleitung. Ein I2C-Decode sollte dann 7-Bit-Zieladressen, Lese-/Schreibrichtung, ACK/NACKs und wiederkehrende Payloads sichtbar machen.<sup>[[2]](#references)[[4]](#references)</sup>

Zeichne mehrere legitime Übertragungen auf und bewahre sowohl die decodierten Bytes als auch die Rohzeitdaten auf. Wiederholte Frames eignen sich als bekannte Testvektoren für spätere Serialisierer, während Unterschiede zwischen Anfragen wahrscheinliche Opcode-, Index-, Offset-, Längen-, Sequenz- oder Prüfsummenfelder erkennen lassen können.<sup>[[4]](#references)</sup>

### Framing aus der Host-Firmware rekonstruieren

Wenn die Firmware des Peripheriegeräts nicht zugänglich ist, extrahiere die Firmware des **Hosts** und finde die Komponente, die das I2C-Gerät öffnet. Suche nach Zeichenfolgen und Symbolen zum Namen des Peripheriegeräts, nach `/dev/i2c-`, Command-Buildern, Response-Parsern, Reset-/Initialisierungsroutinen und Prüfsummenfunktionen. Halte für jeden Builder die genauen Feld-Offsets, Konstanten, akzeptierten Argumentgrößen, Payload-Länge, Prüfsummenabdeckung, Byte-Reihenfolge der Prüfsumme und zurückgegebene Frame-Länge fest, statt das Format anhand von Funktionsnamen abzuleiten.<sup>[[4]](#references)</sup>

Eine Prüfsummenfunktion namens `crc16_ccitt` reicht nicht aus, um ein Preset auszuwählen. Ermittle die Schieberichtung, das Tabellenindex-Byte, das durch die Tabelle repräsentierte Polynom, das Initialregister, die Ein-/Ausgabereflexion, das abschließende XOR/die Invertierung und die Wire-Endianness des Serialisierers. Eine rechts schiebende Low-Byte-Tabelle auf Basis des umgekehrten Polynoms `0x8408`, initialisiert mit `0xFFFF` und am Ende komplementiert, identifiziert beispielsweise **CRC-16/X-25 (IBM-SDLC)**. Eine korrekte Prüfsumme ist häufig nötig, damit Testfälle die Integritätsprüfung bestehen und den Command-Parser erreichen.<sup>[[4]](#references)</sup>

Suche nach der Rekonstruktion des Formats in öffentlichem Code nach markanten Symbolnamen und Konstanten. Im Fall von MJA1 bestätigte ein unabhängig gefundener SDK-Wrapper Command-IDs, Argumentvalidierung, Response-Definitionen und die gespiegelte CRC-Implementierung; verwende solchen Quellcode zur Validierung und nicht als Ersatz dafür, das genaue Zielbinary und die Byte-Reihenfolge auf der Leitung zu prüfen.<sup>[[4]](#references)[[5]](#references)</sup>

### Frames von einem gerooteten Linux-Host senden

Ein kompromittierter Embedded-Linux-Host kann das Peripheriegerät ansprechen, ohne einen weiteren Bus-Controller hinzuzufügen. Öffne den relevanten Adapter, wähle die 7-Bit-Adresse mit `I2C_SLAVE` aus und sende einen von einem dedizierten Serialisierer erzeugten Frame; behalte einen Roh-Frame-Modus für Mutation und Fuzzing bei.<sup>[[4]](#references)</sup>

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

Kompiliere mit einer Toolchain, die mit der Ziel-CPU und libc kompatibel ist, und vergleiche die Analyzer-Traces des Testclients mit legitimem Datenverkehr. Transaktionsgrenzen, Schreib-/Lese-Reihenfolge, Verzögerungen und Peripheriezustand können relevant sein, selbst wenn die sichtbaren Bytes übereinstimmen.<sup>[[4]](#references)</sup>

### Antwortgesteuerte Opcode-Aufzählung

Sobald der kürzeste gültige Frame und die Prüfsumme bekannt sind, ermittle den vollständigen Opcode-Umfang und verwende die explizite Antwort des Protokolls auf einen **nicht unterstützten Befehl** als negative Basislinie. Ein abweichendes Ergebnis – etwa ungültige Argumente, ungültiger Zustand oder ein undokumentierter Status – deutet darauf hin, dass die Decodierung einen implementierten oder teilweise implementierten Handler erreicht hat. Es belegt **nicht**, dass die Eingabe ausnutzbar ist; priorisiere den Kandidaten für Fuzzing mit strukturierten Längen, Argumenten, Zuständen und Befehlsfolgen.<sup>[[4]](#references)</sup>

Wenn ein Test die Peripherie aufhängt, automatisiere von einem externen Controller aus einen isolierten Testfall pro Boot: per SSH verbinden, den Testfall ausführen, die Rohdaten der Anfrage und Antwort sowie das Timing speichern, neu starten oder aus- und wieder einschalten, auf die Wiederherstellung der Healthchecks warten und fortfahren. Die Komponente später in eine mikrocontrollergesteuerte Testvorrichtung einzubauen, kann deterministische Resets, direkte Stromsteuerung und schnelleres Fuzzing ermöglichen.<sup>[[4]](#references)</sup>

## References

- [1] [Bus-Pirate-Dokumentation — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-Bus-Spezifikation und Benutzerhandbuch](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Datenblatt des seriellen I²C-EEPROMs AT24C256C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Black-Box-Probing: Sicherheitsanalyse von Xiaomis sicherem MJA1-Chip](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1-Kryptografie-Wrapper](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
