# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Überprüfe vor dem Anschließen eines Bus Pirate die Zielspannung, die Pinbelegung, die Pull-up-Beschaltung und die gemeinsame Masse. Aktiviere die Stromversorgung des Bus Pirate nicht auf einem aktiven, vom Zielgerät versorgten Bus, nur um ihn mitzuschneiden: Zwei Stromversorgungen können gegeneinander arbeiten und Hardware beschädigen. Das folgende Transkript ist ein gerätespezifisches Beispiel für Bus Pirate v3/Community-Firmware und keine universelle Anschlussanleitung.<sup>[[1]](#references)[[2]](#references)</sup>

Um zu testen, ob ein Bus Pirate funktioniert, verbinde +5V mit VPU und 3.3V mit ADC, verbinde dich mit dem Bus Pirate (zum Beispiel mit Tera Term) und verwende den Befehl `~`:

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

Wie Sie in der vorherigen Befehlszeile sehen können, wurden 0 Fehler gefunden. Das ist sehr nützlich, um nach dem Kauf oder dem Flashen einer Firmware zu überprüfen, ob alles funktioniert.

Um eine Verbindung mit dem Bus Pirate herzustellen, können Sie der Dokumentation folgen:

![Befehl verwenden – Leertaste drücken: Um eine Verbindung mit dem Bus Pirate herzustellen, können Sie der Dokumentation folgen](<../../images/image (484).png>)

In diesem Fall ist das Ziel ein I²C-EEPROM der Familie 24C256. Prüfen Sie die genaue Suffixbezeichnung und das Datenblatt, da die unterstützte Versorgungsspannung je nach Bauteil variiert.<sup>[[3]](#references)</sup>

![Befehl verwenden – Leertaste drücken: In diesem Fall werde ich eine Verbindung zu einem EPROM herstellen: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Um mit dem Bus Pirate zu kommunizieren, habe ich Tera Term verwendet, das mit dem COM-Port des Bus Pirate verbunden war. Unter Setup --> Serial Port habe ich eine Geschwindigkeit von 115200 eingestellt.\
In der folgenden Kommunikation sehen Sie, wie Sie den Bus Pirate für die I2C-Kommunikation vorbereiten und aus dem Speicher schreiben und lesen (Kommentare beginnen mit „#“; dieser Teil ist in der Kommunikation nicht zu erwarten):

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

In diesem Szenario schnüffeln wir die I2C-Kommunikation zwischen dem Arduino und dem zuvor verwendeten EPROM mit. Dazu musst du nur mit beiden Geräten kommunizieren und anschließend den Bus Pirate mit den SCL-, SDA- und GND-Pins verbinden:

![Read 20B from address 0x69 configured before - Sniffer: In diesem Szenario schnüffeln wir die I2C-Kommunikation zwischen dem Arduino und dem zuvor verwendeten EPROM mit. Dazu musst du nur...](<../../images/image (166).png>)

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

Wenn das Peripheriegerät weder Pinout noch Datenblatt hat, beginne passiv mit einem hochohmigen Logikanalysator, während der ursprüngliche Host läuft. Stelle zuerst eine gemeinsame Masse und einen sicheren Logikpegel her. Ordne dann konstante Pins wahrscheinlich Versorgungsschienen, Masse oder Pull-up-Signalen zu und vergleiche die aktiven Leitungen mit gängigen Bussen: UART hat asynchrone, unabhängig gerichtete TX-/RX-Leitungen; bei herkömmlichem SPI gibt es normalerweise Takt, Chip-Select und separate Datenrichtungen; I2C hat einen regelmäßigen Takt und eine bidirektionale Datenleitung. Eine I2C-Decodierung sollte dann 7-Bit-Zieladressen, Lese-/Schreibrichtung, ACK/NACKs und wiederkehrende Nutzdaten sichtbar machen.<sup>[[2]](#references)[[4]](#references)</sup>

Zeichne mehrere legitime Datenaustausche auf und bewahre sowohl die decodierten Bytes als auch die Roh-Timingdaten auf. Wiederholte Frames eignen sich als bekannte Referenztests für spätere Serialisierer, während Änderungen zwischen Anfragen wahrscheinlich Opcode-, Index-, Offset-, Längen-, Sequenz- oder Prüfsummenfelder offenlegen können.<sup>[[4]](#references)</sup>

### Framing aus der Host-Firmware rekonstruieren

Wenn die Firmware des Peripheriegeräts nicht zugänglich ist, extrahiere die **Host**-Firmware und suche die Komponente, die das I2C-Gerät öffnet. Suche nach Zeichenketten und Symbolen für den Namen des Peripheriegeräts, `/dev/i2c-`, Befehls-Builder, Antwort-Parser, Reset-/Initialisierungsroutinen und Prüfsummenfunktionen. Notiere für jeden Builder die exakten Feld-Offsets, Konstanten, zulässigen Argumentgrößen, Nutzdatenlängen, den Umfang der Prüfsummenberechnung, die Byte-Reihenfolge der Prüfsumme und die Länge des zurückgegebenen Frames, statt das Format anhand von Funktionsnamen abzuleiten.<sup>[[4]](#references)</sup>

Der Name `crc16_ccitt` einer Prüfsummenfunktion reicht nicht aus, um ein Preset auszuwählen. Ermittle die Schieberichtung, das Tabellenindex-Byte, das durch die Tabelle dargestellte Polynom, das Anfangsregister, die Eingabe-/Ausgabespiegelung, das abschließende XOR beziehungsweise die Invertierung und die Byte-Reihenfolge des Serialisierers auf dem Bus. Beispielsweise weist eine nach rechts schiebende Low-Byte-Tabelle auf Basis des umgekehrten Polynoms `0x8408`, initialisiert mit `0xFFFF` und am Ende komplementiert, auf **CRC-16/X-25 (IBM-SDLC)** hin. Eine korrekte Prüfsumme ist oft nötig, damit Testfälle die Integritätsprüfung bestehen und den Befehls-Parser erreichen.<sup>[[4]](#references)</sup>

Suche nach der Rekonstruktion des Formats in öffentlichem Code nach markanten Symbolnamen und Konstanten. Im MJA1-Fall bestätigte ein unabhängig gefundenes SDK-Wrapper-Modul Befehls-IDs, Argumentvalidierung, Antwortdefinitionen und die gespiegelte CRC-Implementierung. Verwende solchen Quellcode zur Validierung, nicht als Ersatz für die Prüfung des exakten Ziel-Binaries und der Byte-Reihenfolge auf dem Bus.<sup>[[4]](#references)[[5]](#references)</sup>

### Frames von einem gerooteten Linux-Host senden

Ein kompromittierter Embedded-Linux-Host kann das Peripheriegerät ansteuern, ohne einen weiteren Bus-Controller hinzuzufügen. Öffne den relevanten Adapter, wähle mit `I2C_SLAVE` die 7-Bit-Adresse aus und sende einen von einem dedizierten Serialisierer erzeugten Frame. Behalte einen Roh-Frame-Modus für Mutationen und Fuzzing bei.<sup>[[4]](#references)</sup>

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

Cross-compile mit einer Toolchain, die mit der Ziel-CPU und libc kompatibel ist, und vergleiche die Analyzer-Traces des Testclients mit legitimen Datenverkehr. Transaktionsgrenzen, Schreib-/Lesereihenfolge, Verzögerungen und der Zustand des Peripheriegeräts können eine Rolle spielen, selbst wenn die sichtbaren Bytes übereinstimmen.<sup>[[4]](#references)</sup>

### Antwortgesteuerte Opcode-Aufzählung

Sobald der kürzeste gültige Frame und die Prüfsumme bekannt sind, ermittle den vollständigen Opcode-Umfang und verwende die explizite Antwort **unsupported-command** des Protokolls als negative Basislinie. Ein anderes Ergebnis – etwa ungültige Argumente, ein ungültiger Zustand oder ein undokumentierter Status – deutet darauf hin, dass die Dekodierung einen implementierten oder teilweise implementierten Handler erreicht hat. Das belegt **nicht** die Ausnutzbarkeit; priorisiere den Kandidaten für strukturiertes Fuzzing von Längen, Argumenten, Zuständen und Befehlssequenzen.<sup>[[4]](#references)</sup>

Wenn ein Test das Peripheriegerät blockiert, automatisiere über einen externen Controller jeweils einen isolierten Fall pro Boot: Verbinde dich über SSH, führe den Fall aus, speichere die rohe Anfrage/Antwort und das Timing, starte das Gerät neu oder schalte es aus und wieder ein, warte, bis die Zustandsprüfungen wieder erfolgreich sind, und fahre fort. Die spätere Verlagerung der Komponente auf ein mikrocontrollergesteuertes Test-Setup ermöglicht deterministische Resets, direkte Stromsteuerung und schnelleres Fuzzing.<sup>[[4]](#references)</sup>

## References

- [1] [Bus-Pirate-Dokumentation — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-Bus-Spezifikation und Benutzerhandbuch](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Datenblatt zum seriellen I²C-EEPROM AT24C256C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Black-Box-Probing: Sicherheitsanalyse von Xiaomis Secure Chip MJA1](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia-BLE-SDK-Kryptografie-Wrapper für MJA1](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
