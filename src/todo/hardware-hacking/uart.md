# UART

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

UART ist eine asynchrone serielle Schnittstelle, die einen gerahmten Bitstrom ohne gemeinsamen Takt überträgt. Logic-Level-UART darf nicht mit RS-232 verwechselt werden: RS-232 verwendet andere, oft negative Spannungsebenen und benötigt einen Transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Im Allgemeinen wird die Leitung auf High (logischer Wert 1) gehalten, während sich UART im Ruhezustand befindet. Um den Beginn einer Datenübertragung zu signalisieren, sendet der Transmitter anschließend ein Startbit an den Receiver, während dessen das Signal auf Low (logischer Wert 0) gehalten wird. Danach sendet der Transmitter fünf bis acht Datenbits mit der eigentlichen Nachricht, gefolgt von einem optionalen Paritätsbit und einem oder zwei Stoppbits (mit dem logischen Wert 1), abhängig von der Konfiguration. Das zur Fehlerprüfung verwendete Paritätsbit ist in der Praxis selten anzutreffen. Das Stoppbit (oder die Stoppbits) kennzeichnet das Ende der Übertragung.

Die häufigste Konfiguration ist 8N1: acht Datenbits, keine Parität und ein Stoppbit. UART sendet das niederwertigste Datenbit zuerst. Daher wird ASCII `C` (`0x43`) als Folgendes übertragen: Start `0`; Daten `1, 1, 0, 0, 0, 0, 1, 0`; Stopp `1`.<sup>[[1]](#references)</sup>

![UART: Die häufigste Konfiguration wird als 8N1 bezeichnet: acht Datenbits, keine Parität und ein Stoppbit. Wenn wir beispielsweise das Zeichen C oder 0x43 in ASCII senden möchten, wird es über eine 8N1-UART übertragen](<../../images/image (764).png>)

Hardware-Tools zur Kommunikation mit UART:

- USB-zu-Seriell-Adapter
- Adapter mit den Chips CP2102 oder PL2303
- Multifunktions-Tools wie: Bus Pirate, der Adafruit FT232H, der Shikra oder das Attify Badge

### UART-Ports identifizieren

Ein typischer Debug-Header stellt **TX**, **RX** und **GND** bereit. Er kann außerdem einen **Vcc/Vref**-Pin, Reset- oder Flow-Control-Pins besitzen. Vcc ist kein UART-Signal und sollte normalerweise nur als Spannungsreferenz verwendet werden – nicht als Stromquelle angeschlossen werden –, sofern Schaltplan und Stromanforderungen des Boards nicht bekannt sind.<sup>[[2]](#references)[[3]](#references)</sup>

Beginne mit dem **ausgeschalteten** und nicht verbundenen Gerät:

- Identifiziere **GND** im Durchgangsprüfmodus anhand einer bekannten Massefläche, der Abschirmung eines Anschlusses oder der Versorgungserde. Verwende den Durchgangs-/Widerstandsmodus niemals an einem mit Strom versorgten Board.
- Wechsle vor dem Einschalten des Targets in den Gleichspannungsmodus. Messe mögliche Pins relativ zu GND, um die Logikspannung zu bestimmen. Eine konstante Versorgungsschiene kann Vcc/Vref sein; gehe nicht davon aus, dass sie sicher angeschlossen werden kann.
- Beobachte mögliche Kandidaten während des Bootvorgangs mit einem Logic Analyzer oder Oszilloskop. **TX** befindet sich üblicherweise im Ruhezustand auf High und zeigt Bursts gerahmter Daten. Ein Multimeter kann eine durchschnittliche Schwankung anzeigen, aber die Framing- oder Baudrate nicht validieren.
- **RX** kann im Ruhezustand bleiben und darf nicht allein deshalb sicher identifiziert werden, weil es neben TX liegt. Verfolge die Leiterbahnen auf der Platine, konsultiere das SoC-Datenblatt oder verwende einen hochohmigen Analyzer, bevor du den Pin ansteuerst.

Das Vertauschen von TX und RX führt normalerweise zu keiner Kommunikation. Eine Verwechslung von Stromversorgung, Masse oder Signalpegeln kann das Target oder den Adapter dauerhaft beschädigen. Verbinde zuerst die Masse und beginne im **Nur-Empfang-Modus** (Target-TX mit Adapter-RX).

Hersteller lassen den Header möglicherweise weg, bestücken Serienwiderstände nicht, deaktivieren die Konsole in der Firmware oder führen nur TX heraus. Verfolge nahegelegene Testpads und Widerstandsfootprints bis zum SoC und füge erst dann eine temporäre hochohmige Verbindung hinzu, wenn der elektrische Pegel bestätigt wurde. Das Vorhandensein einer Garantie bedeutet nicht, dass ein zugänglicher UART vorhanden sein muss.

### UART-Baudrate identifizieren

Die einfachste Möglichkeit, die korrekte Baudrate zu identifizieren, besteht darin, die Ausgabe des **TX-Pins** anzusehen und zu versuchen, die Daten zu lesen. Wenn die empfangenen Daten nicht lesbar sind, wechsle zur nächsten möglichen Baudrate, bis die Daten lesbar werden. Du kannst dafür einen USB-zu-Seriell-Adapter oder ein Multifunktionsgerät wie Bus Pirate zusammen mit einem Hilfsskript wie [baudrate.py](https://github.com/devttys0/baudrate/) verwenden. Die häufigsten Baudraten sind 9600, 38400, 19200, 57600 und 115200.

> [!CAUTION]
> Es ist wichtig zu beachten, dass du bei diesem Protokoll den TX eines Geräts mit dem RX des anderen Geräts verbinden musst!

## CP210X UART-zu-TTY-Adapter

CP210x-USB-zu-UART-Bridges sind auf vielen Prototyping-Boards und preisgünstigen Adaptern zu finden. Übliche Module führen neben GND, RXD und TXD auch Versorgungspins heraus, aber Header und I/O-Pegel unterscheiden sich. Bestätige die tatsächliche Spannung anhand des Board-Designs oder des Datenblatts. Normalerweise werden nur GND, Adapter-RX mit Target-TX und – nach der Validierung im Nur-Empfang-Modus – Adapter-TX mit Target-RX verbunden. Verbinde den 5-V-/3,3-V-Versorgungspin des Adapters nicht, außer du versorgst absichtlich ein Target mit Strom, das nachweislich dafür geeignet ist.<sup>[[3]](#references)</sup>

Falls der Adapter nicht erkannt wird, stelle sicher, dass die CP210X-Treiber im Hostsystem installiert sind. Sobald der Adapter erkannt und verbunden ist, können Tools wie picocom, minicom oder screen verwendet werden.

So listest du die mit Linux-/MacOS-Systemen verbundenen Geräte auf:
```
ls /dev/
```
Für die grundlegende Interaktion mit der UART-Schnittstelle verwenden Sie folgenden Befehl:
```
picocom /dev/<adapter> --baud <baudrate>
```
Verwende für minicom den folgenden Befehl, um es zu konfigurieren:
```
minicom -s
```
Konfigurieren Sie die Einstellungen wie Baudrate und Gerätenamen in der Option `Serial port setup`.

Führen Sie nach der Konfiguration `minicom` aus, um die UART-Konsole zu öffnen.

## UART über Arduino UNO R3 (Boards mit entfernbaren Atmel-328p-Chips)

Falls keine UART-zu-USB-Adapter verfügbar sind, kann Arduino UNO R3 mit einem schnellen Hack verwendet werden. Da Arduino UNO R3 normalerweise überall verfügbar ist, kann dies viel Zeit sparen.

Arduino UNO R3 verfügt über einen auf dem Board integrierten USB-zu-Serial-Adapter. Um eine UART-Verbindung herzustellen, ziehen Sie einfach den Atmel-328p-Mikrocontroller-Chip vom Board ab. Dieser Hack funktioniert mit Arduino-UNO-R3-Varianten, bei denen der Atmel 328p nicht auf das Board gelötet ist (darin wird die SMD-Version verwendet). Verbinden Sie den RX-Pin des Arduino (Digital Pin 0) mit dem TX-Pin des UART-Interface und den TX-Pin des Arduino (Digital Pin 1) mit dem RX-Pin des UART-Interface.

Verwenden Sie den **Serial Monitor** der Arduino IDE oder ein dediziertes Terminal mit der Baudrate des Ziels. Klassische Uno-R3-Ser сигnale verwenden eine 5-V-Logik. Verwenden Sie daher einen Pegelwandler oder Spannungsteiler, bevor Sie sie mit einem Zielgerät mit 3,3 V oder einer niedrigeren Spannung verbinden.

## Bus Pirate

Das folgende Transkript verwendet das ältere Bus-Pirate-Firmware-Interface, um die UART-Ausgabe zu überwachen. Neuere Bus-Pirate-Firmware verwendet Befehle wie `m uart`, `{`/`}`, `monitor` oder `bridge`; konsultieren Sie die Dokumentation der installierten Version.<sup>[[2]](#references)</sup>
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
## Firmware mit UART-Konsole auslesen

Eine UART-Konsole ermöglicht den Laufzeitzugriff auf Boot-Protokolle und manchmal auf eine Bootloader- oder Betriebssystem-Shell. Selbst eine schreibgeschützte Konsole gibt Einblick in Memory Maps, Flash-Treiber, Boot-Argumente, Partitionslayouts und Firmware-Versionen. Firmware kann in SPI-NOR/NAND, eMMC oder einem anderen Gerät gespeichert sein; sie wird im Allgemeinen nicht aus einem EEPROM ausgeführt, und in ein eingebundenes persistentes Dateisystem geschriebene Dateien verschwinden nach einem Neustart nicht unbedingt.

Es gibt mehrere Wege zur Beschaffung, und der SPI-Abschnitt behandelt direkte Lesevorgänge aus externem Flash. Eine über die Konsole unterstützte Beschaffung kann weniger invasiv sein, wenn der Bootloader bereits einen sicheren Lesebefehl bereitstellt. Jede Unterbrechung des Bootvorgangs oder jeder Flash-Befehl kann jedoch die Verfügbarkeit beeinträchtigen. Daher sollte der ursprüngliche Zustand dokumentiert und auf Schreib-/Löschvorgänge verzichtet werden.

Das Auslesen von Firmware über die Konsole beginnt häufig mit der Unterbrechung eines Bootloaders. Viele Embedded-Linux-Geräte verwenden **Das U-Boot**, andere jedoch proprietäre Bootloader oder deaktivieren die interaktive Konsole.

Um einen interaktiven Bootloader zu testen, verbinde den UART-Empfangspfad und das Terminal, während das Zielgerät ausgeschaltet ist, starte die Protokollierung und schalte es ein. Folge der angezeigten Autoboot-Eingabeaufforderung. Je nach Build kann die Unterbrechung eine Taste, eine kurze Sequenz erfordern oder vollständig deaktiviert sein.

Wenn die Unterbrechung erfolgreich ist, verwende `help`, `printenv` und schreibgeschützte Erkundungsbefehle, um das Speicher- und Storage-Layout des jeweiligen Herstellers zu verstehen, bevor du auf Adressen zugreifst.

In U-Boot zeigt `md` **adressierbaren Speicher** an, nicht automatisch „das EEPROM“. Verwende zunächst boardspezifische Befehle wie `mtd list`, `sf probe`, `mmc info`, `part list`, Umgebungsvariablen und Boot-Protokolle, um die korrekte gemappte Adresse zu ermitteln oder einen Flash-Bereich in den RAM zu laden. Zeige anschließend einen bekannten Bereich Byte für Byte an:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Protokolliere die serielle Ausgabe, bevor du beginnst. Die Ausgabe von `md.b` enthält Adressen und eine ASCII-Spalte und ist daher eine textuelle Darstellung statt eines rohen ROM-Abbilds.

Entferne die Adress- und ASCII-Spalten, füge nur die hexadezimalen Bytefelder zusammen und dekodiere sie in Binärdaten (zum Beispiel mit `xxd -r -p`). Überprüfe die erwartete Byteanzahl und erfasse vor der Analyse einen Hash:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk identifiziert anschließend bekannte Signaturen in der rekonstruierten Binärdatei. Ein direkter Flash-Lesevorgang über die entsprechende SPI-/eMMC-/NAND-Schnittstelle ist in der Regel schneller und weniger fehleranfällig, wenn die Konsole Daten nicht zuverlässig übertragen kann.

U-Boot deaktiviert möglicherweise die Unterbrechung, erfordert eine herstellerspezifische Tastensequenz oder sperrt Speicher-/Flash-Befehle. Orientiere dich an der Autoboot-Eingabeaufforderung und dem Boot-Log, anstatt blind Zeichen zu übertragen. Wenn der Vorgang nicht über die Konsole unterbrochen werden kann, bewahre das Boot-Log auf und wechsle zu einem nicht-invasiven Verfahren zur Firmware-Erfassung.

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate-Dokumentation - UART-Modus und elektrische Grenzwerte](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - Datenblatt für CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot-Dokumentation - `md`-Befehl zur Speicheranzeige](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
