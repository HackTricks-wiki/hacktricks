# UART

{{#include ../../banners/hacktricks-training.md}}

## Grundinformationen

UART ist ein serielles Protokoll, was bedeutet, dass es Daten zwischen Komponenten bitweise überträgt. Im Gegensatz dazu übertragen parallele Kommunikationsprotokolle Daten gleichzeitig über mehrere Kanäle. Zu den gängigen seriellen Protokollen gehören RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express und USB.

Im Allgemeinen wird die Leitung hoch gehalten (bei einem logischen Wert von 1), während sich UART im Leerlaufzustand befindet. Um den Beginn einer Datenübertragung zu signalisieren, sendet der Sender ein Startbit an den Empfänger, während das Signal niedrig gehalten wird (bei einem logischen Wert von 0). Anschließend sendet der Sender fünf bis acht Datenbits, die die eigentliche Nachricht enthalten, gefolgt von einem optionalen Paritätsbit und einem oder zwei Stoppbits (mit einem logischen Wert von 1), abhängig von der Konfiguration. Das Paritätsbit, das zur Fehlerüberprüfung verwendet wird, ist in der Praxis selten zu sehen. Das Stoppbit (oder die Stoppbits) signalisiert das Ende der Übertragung.

Wir nennen die gängigste Konfiguration 8N1: acht Datenbits, keine Parität und ein Stoppbit. Wenn wir beispielsweise das Zeichen C oder 0x43 in ASCII in einer 8N1 UART-Konfiguration senden wollten, würden wir die folgenden Bits senden: 0 (das Startbit); 0, 1, 0, 0, 0, 0, 1, 1 (der Wert von 0x43 in binär) und 0 (das Stoppbit).

![](<../../images/image (764).png>)

Hardware-Tools zur Kommunikation mit UART:

- USB-zu-Seriell-Adapter
- Adapter mit den Chips CP2102 oder PL2303
- Multifunktionswerkzeuge wie: Bus Pirate, der Adafruit FT232H, der Shikra oder das Attify Badge

### Identifizierung von UART-Ports

UART hat 4 Ports: **TX**(Transmit), **RX**(Receive), **Vcc**(Spannung) und **GND**(Masse). Möglicherweise können Sie 4 Ports mit den Buchstaben **`TX`** und **`RX`** **auf** der PCB **finden**. Wenn es jedoch keine Hinweise gibt, müssen Sie möglicherweise versuchen, sie selbst mit einem **Multimeter** oder einem **Logikanalysator** zu finden.

Mit einem **Multimeter** und dem Gerät, das ausgeschaltet ist:

- Um den **GND**-Pin zu identifizieren, verwenden Sie den **Durchgangstestmodus**, legen Sie die schwarze Sonde auf Masse und testen Sie mit der roten, bis Sie einen Ton vom Multimeter hören. Mehrere GND-Pins können auf der PCB gefunden werden, sodass Sie möglicherweise den zu UART gehörenden gefunden haben oder nicht.
- Um den **VCC-Port** zu identifizieren, stellen Sie den **Gleichspannungsmodus** ein und setzen Sie ihn auf 20 V. Schwarze Sonde auf Masse und rote Sonde auf den Pin. Schalten Sie das Gerät ein. Wenn das Multimeter eine konstante Spannung von entweder 3,3 V oder 5 V misst, haben Sie den Vcc-Pin gefunden. Wenn Sie andere Spannungen erhalten, versuchen Sie es mit anderen Ports erneut.
- Um den **TX**-**Port** zu identifizieren, stellen Sie den **Gleichspannungsmodus** auf bis zu 20 V ein, schwarze Sonde auf Masse und rote Sonde auf den Pin, und schalten Sie das Gerät ein. Wenn Sie feststellen, dass die Spannung für einige Sekunden schwankt und dann auf den Vcc-Wert stabilisiert, haben Sie höchstwahrscheinlich den TX-Port gefunden. Dies liegt daran, dass beim Einschalten einige Debug-Daten gesendet werden.
- Der **RX-Port** wäre der nächstgelegene zu den anderen 3, er hat die niedrigste Spannungsfluktuation und den niedrigsten Gesamtwert aller UART-Pins.

Sie können die TX- und RX-Ports verwechseln und es würde nichts passieren, aber wenn Sie den GND- und den VCC-Port verwechseln, könnten Sie die Schaltung beschädigen.

In einigen Zielgeräten ist der UART-Port vom Hersteller deaktiviert, indem RX oder TX oder sogar beide deaktiviert werden. In diesem Fall kann es hilfreich sein, die Verbindungen auf der Leiterplatte nachzuvollziehen und einen Breakout-Punkt zu finden. Ein starker Hinweis darauf, dass kein UART erkannt wird und die Schaltung unterbrochen ist, besteht darin, die Gerätezulassung zu überprüfen. Wenn das Gerät mit einer Garantie geliefert wurde, lässt der Hersteller einige Debug-Schnittstellen (in diesem Fall UART) und hat daher den UART wahrscheinlich getrennt und würde ihn während des Debuggens wieder anschließen. Diese Breakout-Pins können durch Löten oder Jumperdrähte verbunden werden.

### Identifizierung der UART-Baudrate

Der einfachste Weg, die richtige Baudrate zu identifizieren, besteht darin, den **TX-Pin-Ausgang zu betrachten und die Daten zu lesen**. Wenn die Daten, die Sie erhalten, nicht lesbar sind, wechseln Sie zur nächsten möglichen Baudrate, bis die Daten lesbar werden. Sie können einen USB-zu-Seriell-Adapter oder ein Multifunktionsgerät wie Bus Pirate verwenden, um dies zu tun, zusammen mit einem Hilfsskript wie [baudrate.py](https://github.com/devttys0/baudrate/). Die gängigsten Baudraten sind 9600, 38400, 19200, 57600 und 115200.

> [!CAUTION]
> Es ist wichtig zu beachten, dass Sie in diesem Protokoll den TX eines Geräts mit dem RX des anderen verbinden müssen!

## CP210X UART zu TTY-Adapter

Der CP210X-Chip wird in vielen Prototyping-Boards wie NodeMCU (mit esp8266) für die serielle Kommunikation verwendet. Diese Adapter sind relativ kostengünstig und können verwendet werden, um sich mit der UART-Schnittstelle des Ziels zu verbinden. Das Gerät hat 5 Pins: 5V, GND, RXD, TXD, 3.3V. Stellen Sie sicher, dass Sie die Spannung entsprechend den Anforderungen des Ziels anschließen, um Schäden zu vermeiden. Schließen Sie schließlich den RXD-Pin des Adapters an TXD des Ziels und den TXD-Pin des Adapters an RXD des Ziels an.

Falls der Adapter nicht erkannt wird, stellen Sie sicher, dass die CP210X-Treiber im Hostsystem installiert sind. Sobald der Adapter erkannt und verbunden ist, können Tools wie picocom, minicom oder screen verwendet werden.

Um die an Linux/MacOS-Systeme angeschlossenen Geräte aufzulisten:
```
ls /dev/
```
Für die grundlegende Interaktion mit der UART-Schnittstelle verwenden Sie den folgenden Befehl:
```
picocom /dev/<adapter> --baud <baudrate>
```
Für minicom verwenden Sie den folgenden Befehl, um es zu konfigurieren:
```
minicom -s
```
Konfigurieren Sie die Einstellungen wie Baudrate und Gerätename in der `Serial port setup`-Option.

Nach der Konfiguration verwenden Sie den Befehl `minicom`, um die UART-Konsole zu starten.

## UART über Arduino UNO R3 (entfernbarer Atmel 328p-Chip)

Falls UART-Serial-zu-USB-Adapter nicht verfügbar sind, kann Arduino UNO R3 mit einem schnellen Hack verwendet werden. Da Arduino UNO R3 normalerweise überall erhältlich ist, kann dies viel Zeit sparen.

Arduino UNO R3 hat einen USB-zu-Serial-Adapter, der auf der Platine selbst integriert ist. Um eine UART-Verbindung herzustellen, ziehen Sie einfach den Atmel 328p-Mikrocontroller-Chip von der Platine ab. Dieser Hack funktioniert bei Arduino UNO R3-Varianten, bei denen der Atmel 328p nicht auf der Platine verlötet ist (SMD-Version wird verwendet). Verbinden Sie den RX-Pin des Arduino (Digital Pin 0) mit dem TX-Pin der UART-Schnittstelle und den TX-Pin des Arduino (Digital Pin 1) mit dem RX-Pin der UART-Schnittstelle.

Schließlich wird empfohlen, die Arduino IDE zu verwenden, um die serielle Konsole zu erhalten. Wählen Sie im Menü im Abschnitt `tools` die Option `Serial Console` und setzen Sie die Baudrate gemäß der UART-Schnittstelle.

## Bus Pirate

In diesem Szenario werden wir die UART-Kommunikation des Arduino sniffen, der alle Ausgaben des Programms an den Serial Monitor sendet.
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
## Dumping Firmware mit UART-Konsole

Die UART-Konsole bietet eine großartige Möglichkeit, mit der zugrunde liegenden Firmware in einer Laufzeitumgebung zu arbeiten. Wenn der Zugriff auf die UART-Konsole jedoch schreibgeschützt ist, kann dies viele Einschränkungen mit sich bringen. In vielen eingebetteten Geräten wird die Firmware in EEPROMs gespeichert und in Prozessoren mit flüchtigem Speicher ausgeführt. Daher bleibt die Firmware schreibgeschützt, da die ursprüngliche Firmware während der Herstellung im EEPROM selbst gespeichert ist und neue Dateien aufgrund des flüchtigen Speichers verloren gehen würden. Daher ist das Dumpen der Firmware eine wertvolle Anstrengung, wenn man mit eingebetteten Firmwares arbeitet.

Es gibt viele Möglichkeiten, dies zu tun, und der SPI-Abschnitt behandelt Methoden, um Firmware direkt aus dem EEPROM mit verschiedenen Geräten zu extrahieren. Es wird jedoch empfohlen, zuerst zu versuchen, die Firmware mit UART zu dumpen, da das Dumpen der Firmware mit physischen Geräten und externen Interaktionen riskant sein kann.

Das Dumpen der Firmware von der UART-Konsole erfordert zunächst den Zugriff auf Bootloader. Viele beliebte Anbieter verwenden uboot (Universal Bootloader) als ihren Bootloader, um Linux zu laden. Daher ist der Zugriff auf uboot notwendig.

Um Zugriff auf den Bootloader zu erhalten, verbinden Sie den UART-Port mit dem Computer und verwenden Sie eines der Serial Console-Tools und halten Sie die Stromversorgung des Geräts getrennt. Sobald die Einrichtung bereit ist, drücken und halten Sie die Eingabetaste. Schließen Sie schließlich die Stromversorgung des Geräts an und lassen Sie es booten.

Durch diese Vorgehensweise wird das Laden von uboot unterbrochen und ein Menü angezeigt. Es wird empfohlen, die uboot-Befehle zu verstehen und das Hilfemenü zu verwenden, um sie aufzulisten. Dies könnte der Befehl `help` sein. Da verschiedene Anbieter unterschiedliche Konfigurationen verwenden, ist es notwendig, jede von ihnen separat zu verstehen.

In der Regel lautet der Befehl zum Dumpen der Firmware:
```
md
```
was für "Speicherabbild" steht. Dies wird den Speicher (EEPROM-Inhalt) auf dem Bildschirm ausgeben. Es wird empfohlen, die Ausgabe der seriellen Konsole zu protokollieren, bevor Sie das Verfahren starten, um das Speicherabbild zu erfassen.

Schließlich entfernen Sie einfach alle unnötigen Daten aus der Protokolldatei und speichern Sie die Datei als `filename.rom` und verwenden Sie binwalk, um den Inhalt zu extrahieren:
```
binwalk -e <filename.rom>
```
Dies listet die möglichen Inhalte des EEPROM gemäß den in der Hex-Datei gefundenen Signaturen auf.

Es ist jedoch zu beachten, dass es nicht immer der Fall ist, dass der uboot entsperrt ist, selbst wenn er verwendet wird. Wenn die Eingabetaste nichts bewirkt, überprüfen Sie andere Tasten wie die Leertaste usw. Wenn der Bootloader gesperrt ist und nicht unterbrochen wird, funktioniert diese Methode nicht. Um zu überprüfen, ob uboot der Bootloader für das Gerät ist, überprüfen Sie die Ausgabe auf der UART-Konsole während des Bootvorgangs des Geräts. Es könnte während des Bootens uboot erwähnen.

{{#include ../../banners/hacktricks-training.md}}
