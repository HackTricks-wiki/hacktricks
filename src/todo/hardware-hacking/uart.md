# UART

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

UART ist ein serielles Protokoll, was bedeutet, dass es Daten bitweise zwischen Komponenten überträgt. Im Gegensatz dazu übertragen parallele Kommunikationsprotokolle Daten gleichzeitig über mehrere Kanäle. Zu den gängigen seriellen Protokollen gehören RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express und USB.

Im Allgemeinen wird die Leitung auf High (auf einem logischen Wert von 1) gehalten, während sich UART im Leerlaufzustand befindet. Um den Beginn einer Datenübertragung zu signalisieren, sendet der Transmitter anschließend ein Startbit an den Receiver, währenddessen das Signal auf Low (auf einem logischen Wert von 0) gehalten wird. Danach sendet der Transmitter fünf bis acht Datenbits, die die eigentliche Nachricht enthalten, gefolgt von einem optionalen Paritätsbit und einem oder zwei Stoppbits (mit einem logischen Wert von 1), abhängig von der Konfiguration. Das zur Fehlerprüfung verwendete Paritätsbit ist in der Praxis selten anzutreffen. Das Stoppbit (oder die Stoppbits) signalisiert das Ende der Übertragung.

Die gängigste Konfiguration nennen wir 8N1: acht Datenbits, keine Parität und ein Stoppbit. Wenn wir beispielsweise das Zeichen C oder 0x43 in ASCII in einer 8N1-UART-Konfiguration senden wollten, würden wir die folgenden Bits senden: 0 (das Startbit); 0, 1, 0, 0, 0, 0, 1, 1 (der Binärwert von 0x43) und 0 (das Stoppbit).

![UART: Die gängigste Konfiguration nennen wir 8N1: acht Datenbits, keine Parität und ein Stoppbit. Wenn wir beispielsweise das Zeichen C oder 0x43 in ASCII in einer 8N1-UART-Konfiguration senden wollten](<../../images/image (764).png>)

Hardwaretools zur Kommunikation mit UART:

- USB-zu-Seriell-Adapter
- Adapter mit den Chips CP2102 oder PL2303
- Multifunktionstool wie: Bus Pirate, der Adafruit FT232H, der Shikra oder das Attify Badge

### Identifizieren von UART-Ports

UART hat 4 Ports: **TX** (Transmit), **RX** (Receive), **Vcc** (Voltage) und **GND** (Ground). Möglicherweise findest du 4 Ports mit den auf der Platine **aufgedruckten** Buchstaben **`TX`** und **`RX`**. Wenn es jedoch keine Kennzeichnung gibt, musst du sie möglicherweise selbst mit einem **Multimeter** oder einem **Logic Analyzer** identifizieren.

Mit einem **Multimeter** und ausgeschaltetem Gerät:

- Um den **GND**-Pin zu identifizieren, verwende den Modus **Durchgangsprüfung**, lege die schwarze Messspitze an Ground und teste die Pins mit der roten, bis du einen Ton vom Multimeter hörst. Auf der Platine können mehrere GND-Pins vorhanden sein, daher hast du möglicherweise den UART-Pin gefunden oder auch nicht.
- Um den **VCC-Port** zu identifizieren, stelle den **Gleichspannungsmodus** ein und wähle einen Messbereich bis 20 V. Schwarze Messspitze an Ground und rote Messspitze an den Pin. Schalte das Gerät ein. Wenn das Multimeter eine konstante Spannung von entweder 3,3 V oder 5 V misst, hast du den Vcc-Pin gefunden. Wenn du andere Spannungen erhältst, versuche es erneut mit anderen Ports.
- Um den **TX**-**Port** zu identifizieren, stelle den **Gleichspannungsmodus** mit einem Messbereich bis 20 V ein, verbinde die schwarze Messspitze mit Ground und die rote mit dem Pin und schalte das Gerät ein. Wenn die Spannung einige Sekunden lang schwankt und sich anschließend beim Vcc-Wert stabilisiert, hast du höchstwahrscheinlich den TX-Port gefunden. Beim Einschalten sendet das Gerät einige Debug-Daten.
- Der **RX-Port** ist wahrscheinlich derjenige, der den anderen 3 am nächsten liegt. Er weist die geringsten Spannungsschwankungen und den niedrigsten Gesamtwert aller UART-Pins auf.

Du kannst die TX- und RX-Ports verwechseln, ohne dass etwas passiert. Wenn du jedoch den GND- und den VCC-Port verwechselst, könntest du die Schaltung beschädigen.

Bei einigen Zielgeräten ist der UART-Port vom Hersteller deaktiviert worden, indem RX oder TX oder sogar beide deaktiviert wurden. In diesem Fall kann es hilfreich sein, die Verbindungen auf der Platine nachzuverfolgen und einen Breakout-Punkt zu finden. Ein starker Hinweis darauf, dass UART nicht erkannt wird und die Verbindung unterbrochen wurde, ist die Überprüfung der Gerätegarantie. Wenn das Gerät mit einer Garantie ausgeliefert wurde, lässt der Hersteller einige Debug-Schnittstellen (in diesem Fall UART) bestehen und muss daher UART getrennt haben, um es beim Debugging wieder anzuschließen. Diese Breakout-Pins können durch Löten oder Jumper-Kabel verbunden werden.

### Ermitteln der UART-Baudrate

Die einfachste Möglichkeit, die korrekte Baudrate zu ermitteln, besteht darin, die Ausgabe des **TX-Pins** anzusehen und zu versuchen, die Daten zu lesen. Wenn die empfangenen Daten nicht lesbar sind, wechsle zur nächsten möglichen Baudrate, bis die Daten lesbar werden. Du kannst dafür einen USB-zu-Seriell-Adapter oder ein Multifunktionsgerät wie Bus Pirate zusammen mit einem Hilfsskript wie [baudrate.py](https://github.com/devttys0/baudrate/) verwenden. Die gängigsten Baudraten sind 9600, 38400, 19200, 57600 und 115200.

> [!CAUTION]
> Es ist wichtig zu beachten, dass du bei diesem Protokoll den TX eines Geräts mit dem RX des anderen verbinden musst!

## CP210X UART-zu-TTY-Adapter

Der CP210X-Chip wird in vielen Prototyping-Boards wie NodeMCU (mit esp8266) für die serielle Kommunikation verwendet. Diese Adapter sind relativ günstig und können verwendet werden, um eine Verbindung zur UART-Schnittstelle des Ziels herzustellen. Das Gerät verfügt über 5 Pins: 5V, GND, RXD, TXD und 3,3V. Achte darauf, die vom Ziel unterstützte Spannung anzuschließen, um Schäden zu vermeiden. Verbinde schließlich den RXD-Pin des Adapters mit TXD des Ziels und den TXD-Pin des Adapters mit RXD des Ziels.

Falls der Adapter nicht erkannt wird, stelle sicher, dass die CP210X-Treiber auf dem Hostsystem installiert sind. Sobald der Adapter erkannt und verbunden wurde, können Tools wie picocom, minicom oder screen verwendet werden.

Um die mit Linux-/MacOS-Systemen verbundenen Geräte aufzulisten:
```
ls /dev/
```
Für die grundlegende Interaktion mit der UART-Schnittstelle verwenden Sie den folgenden Befehl:
```
picocom /dev/<adapter> --baud <baudrate>
```
Verwende für minicom den folgenden Befehl, um es zu konfigurieren:
```
minicom -s
```
Konfiguriere die Einstellungen wie Baudrate und Gerätenamen in der Option `Serial port setup`.

Starte nach der Konfiguration mit dem Befehl `minicom` die UART Console.

## UART über Arduino UNO R3 (Boards mit herausnehmbarem Atmel-328p-Chip)

Falls keine UART Serial-to-USB-Adapter verfügbar sind, kann ein Arduino UNO R3 mit einem schnellen Hack verwendet werden. Da ein Arduino UNO R3 normalerweise überall verfügbar ist, kann dies viel Zeit sparen.

Der Arduino UNO R3 verfügt über einen integrierten USB-to-Serial-Adapter. Um eine UART-Verbindung herzustellen, muss lediglich der Atmel-328p-Mikrocontroller-Chip vom Board entfernt werden. Dieser Hack funktioniert bei Arduino-UNO-R3-Varianten, bei denen der Atmel 328p nicht auf dem Board verlötet ist (bei dieser Variante wird die SMD-Version verwendet). Verbinde den RX-Pin des Arduino (Digital Pin 0) mit dem TX-Pin des UART Interface und den TX-Pin des Arduino (Digital Pin 1) mit dem RX-Pin des UART Interface.

Schließlich wird empfohlen, die Arduino IDE zu verwenden, um die Serial Console zu öffnen. Wähle im Menü im Abschnitt `tools` die Option `Serial Console` aus und stelle die Baudrate entsprechend dem UART Interface ein.

## Bus Pirate

In diesem Szenario werden wir die UART-Kommunikation des Arduino sniffen, der alle Programmausgaben an den Serial Monitor sendet.
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
## Firmware mit UART Console dumpen

Die UART Console bietet eine hervorragende Möglichkeit, mit der zugrunde liegenden Firmware in der Laufzeitumgebung zu arbeiten. Wenn der Zugriff auf die UART Console jedoch nur lesend möglich ist, kann dies viele Einschränkungen mit sich bringen. In vielen Embedded-Geräten wird die Firmware in EEPROMs gespeichert und auf Prozessoren ausgeführt, die über flüchtigen Speicher verfügen. Daher bleibt die Firmware schreibgeschützt, da sich die ursprüngliche Firmware während der Herstellung im EEPROM selbst befindet und alle neuen Dateien aufgrund des flüchtigen Speichers verloren gehen würden. Das Dumpen der Firmware ist daher bei der Arbeit mit Embedded-Firmware besonders wertvoll.

Es gibt viele Möglichkeiten, dies zu tun, und der SPI-Abschnitt behandelt Methoden zum direkten Extrahieren der Firmware aus dem EEPROM mit verschiedenen Geräten. Es wird jedoch empfohlen, zunächst zu versuchen, die Firmware über UART zu dumpen, da das Dumpen der Firmware mit physischen Geräten und externen Interaktionen riskant sein kann.

Das Dumpen der Firmware über die UART Console erfordert zunächst Zugriff auf Bootloader. Viele bekannte Anbieter verwenden uboot (Universal Bootloader) als Bootloader zum Laden von Linux. Daher ist der Zugriff auf uboot erforderlich.

Um Zugriff auf den Bootloader zu erhalten, verbinde den UART-Port mit dem Computer und verwende eines der Serial-Console-Tools. Lass dabei die Stromversorgung des Geräts getrennt. Sobald das Setup bereit ist, drücke die Eingabetaste und halte sie gedrückt. Verbinde anschließend die Stromversorgung mit dem Gerät und lass es booten.

Dadurch wird das Laden von uboot unterbrochen und ein Menü angezeigt. Es wird empfohlen, die uboot-Befehle zu verstehen und das help-Menü zu verwenden, um sie aufzulisten. Dies könnte der Befehl `help` sein. Da verschiedene Anbieter unterschiedliche Konfigurationen verwenden, ist es notwendig, jede davon separat zu verstehen.

Üblicherweise lautet der Befehl zum Dumpen der Firmware:
```
md
```
was für „memory dump“ steht. Dadurch wird der Speicher (EEPROM-Inhalt) auf dem Bildschirm ausgegeben. Es wird empfohlen, die Ausgabe der Serial Console zu protokollieren, bevor du mit dem Vorgang beginnst, um den memory dump zu erfassen.

Entferne schließlich alle unnötigen Daten aus der Logdatei, speichere die Datei als `filename.rom` und verwende binwalk, um den Inhalt zu extrahieren:
```
binwalk -e <filename.rom>
```
Dies listet die möglichen Inhalte des EEPROM anhand der in der Hex-Datei gefundenen Signaturen auf.

Allerdings ist zu beachten, dass uboot nicht immer entsperrt ist, selbst wenn es verwendet wird. Wenn die Enter-Taste keine Wirkung zeigt, sollten andere Tasten wie die Leertaste usw. ausprobiert werden. Wenn der Bootloader gesperrt ist und nicht unterbrochen werden kann, funktioniert diese Methode nicht. Um zu überprüfen, ob uboot der Bootloader des Geräts ist, sollte die Ausgabe in der UART-Konsole während des Bootvorgangs des Geräts geprüft werden. Möglicherweise wird während des Bootvorgangs uboot erwähnt.

{{#include ../../banners/hacktricks-training.md}}
