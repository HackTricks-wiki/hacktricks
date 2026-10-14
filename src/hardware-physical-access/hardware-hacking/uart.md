# UART

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

UART ist eine asynchrone serielle Schnittstelle, die einen gerahmten Bitstrom ohne gemeinsamen Takt überträgt. Verwechseln Sie UART mit Logikpegeln nicht mit RS-232: RS-232 verwendet andere, oft negative Spannungspegel und benötigt einen Transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Im Allgemeinen wird die Leitung im Ruhezustand von UART auf High (logischer Wert 1) gehalten. Um die Übertragung von Daten zu signalisieren, sendet der Transmitter ein Startbit an den Receiver, während dessen das Signal auf Low (logischer Wert 0) gehalten wird. Anschließend sendet der Transmitter fünf bis acht Datenbits mit der eigentlichen Nachricht, gefolgt von einem optionalen Paritätsbit und je nach Konfiguration einem oder zwei Stopbits (mit dem logischen Wert 1). Das zur Fehlerprüfung verwendete Paritätsbit ist in der Praxis selten anzutreffen. Das Stopbit (oder die Stopbits) kennzeichnet das Ende der Übertragung.

Die häufigste Konfiguration ist 8N1: acht Datenbits, keine Parität und ein Stopbit. UART sendet zuerst das niederwertigste Datenbit. Daher wird ASCII `C` (`0x43`) wie folgt übertragen: Start `0`; Daten `1, 1, 0, 0, 0, 0, 1, 0`; Stop `1`.<sup>[[1]](#references)</sup>

![UART: Die häufigste Konfiguration nennen wir 8N1: acht Datenbits, keine Parität und ein Stopbit. Wenn wir beispielsweise das Zeichen C oder 0x43 in ASCII mit 8N1-UART senden möchten](<../../images/image (764).png>)

Hardware-Tools für die Kommunikation über UART:

- USB-zu-Seriell-Adapter
- Adapter mit CP2102- oder PL2303-Chips
- Multifunktionstool wie Bus Pirate, Adafruit FT232H, Shikra oder Attify Badge

### UART-Ports identifizieren

Ein typischer Debug-Header stellt **TX**, **RX** und **GND** bereit. Möglicherweise bietet er auch einen **Vcc/Vref**-Pin, Reset- oder Flow-Control-Pins. Vcc ist kein UART-Signal und sollte normalerweise nur als Spannungsreferenz verwendet werden – nicht als Stromversorgung –, sofern Schaltplan und Strombedarf der Platine nicht bekannt sind.<sup>[[2]](#references)[[3]](#references)</sup>

Beginnen Sie mit **ausgeschaltetem** und getrenntem Gerät:

- Identifizieren Sie **GND** im Durchgangsprüfmodus anhand einer bekannten Massefläche, einer Steckerabschirmung oder der Versorgungsmasse. Verwenden Sie den Durchgangs-/Widerstandsprüfmodus niemals bei einer eingeschalteten Platine.
- Wechseln Sie in den DC-Spannungsmodus, bevor Sie das Zielgerät einschalten. Messen Sie mögliche Pins relativ zu GND, um die Logikspannung zu bestimmen. Eine stabile Spannungsschiene kann Vcc/Vref sein; gehen Sie nicht davon aus, dass sie gefahrlos angeschlossen werden kann.
- Beobachten Sie mögliche Pins während des Bootvorgangs mit einem Logikanalysator oder Oszilloskop. **TX** befindet sich im Ruhezustand häufig auf High und zeigt Datenpakete. Ein Multimeter kann Schwankungen im Mittelwert anzeigen, aber weder die Rahmenstruktur noch die Baudrate bestätigen.
- **RX** bleibt möglicherweise im Ruhezustand und lässt sich nicht sicher allein dadurch identifizieren, dass er neben TX liegt. Verfolgen Sie die Leiterbahnen auf der Platine, konsultieren Sie das SoC-Datenblatt oder verwenden Sie einen hochohmigen Analysator, bevor Sie ein Signal anlegen.

Das Vertauschen von TX und RX führt normalerweise dazu, dass keine Kommunikation stattfindet. Eine Verwechslung von Stromversorgung, Masse oder Signalpegeln kann das Zielgerät oder den Adapter dauerhaft beschädigen. Verbinden Sie zuerst GND und beginnen Sie mit einem reinen **Empfangsbetrieb** (TX des Zielgeräts mit RX des Adapters verbinden).

Hersteller lassen den Header möglicherweise weg, bestücken Serienwiderstände nicht, deaktivieren die Konsole in der Firmware oder stellen nur TX bereit. Verfolgen Sie nahegelegene Testpads und Widerstandsflächen bis zum SoC und stellen Sie erst dann eine temporäre hochohmige Verbindung her, wenn der elektrische Pegel bestätigt wurde. Eine Garantie bedeutet nicht, dass zwingend ein zugänglicher UART vorhanden ist.

### UART-Baudrate bestimmen

Am einfachsten lässt sich die richtige Baudrate ermitteln, indem Sie die Ausgabe des **TX-Pins ansehen und versuchen, die Daten zu lesen**. Wenn die empfangenen Daten nicht lesbar sind, wechseln Sie zur nächsten möglichen Baudrate, bis die Daten lesbar werden. Dazu können Sie einen USB-zu-Seriell-Adapter oder ein Multifunktionstool wie Bus Pirate zusammen mit einem Hilfsskript wie [baudrate.py](https://github.com/devttys0/baudrate/) verwenden. Die häufigsten Baudraten sind 9600, 38400, 19200, 57600 und 115200.

> [!CAUTION]
> Beachten Sie, dass Sie bei diesem Protokoll den TX-Pin eines Geräts mit dem RX-Pin des anderen verbinden müssen!

## CP210X-UART-zu-TTY-Adapter

CP210x-USB-zu-UART-Bridges kommen auf vielen Prototyping-Platinen und preiswerten Adaptern zum Einsatz. Gängige Module stellen neben GND, RXD und TXD auch Versorgungspins bereit, aber Header und I/O-Pegel unterscheiden sich. Prüfen Sie die tatsächliche Spannung anhand des Platinenlayouts oder Datenblatts. Verbinden Sie in der Regel nur GND und den Adapter-RX mit dem TX des Zielgeräts. Verbinden Sie den Adapter-TX erst nach erfolgreicher Validierung im reinen Empfangsbetrieb mit dem RX des Zielgeräts. Verbinden Sie den 5-V-/3,3-V-Versorgungspin des Adapters nicht, außer Sie möchten ein Zielgerät versorgen, dessen Verträglichkeit mit dieser Spannung bekannt ist.<sup>[[3]](#references)</sup>

Falls der Adapter nicht erkannt wird, stellen Sie sicher, dass die CP210X-Treiber auf dem Hostsystem installiert sind. Sobald der Adapter erkannt und verbunden ist, können Tools wie picocom, minicom oder screen verwendet werden.

So listen Sie die mit Linux-/MacOS-Systemen verbundenen Geräte auf:

```
ls /dev/
```

Für die grundlegende Interaktion mit der UART-Schnittstelle verwenden Sie folgenden Befehl:

```
picocom /dev/<adapter> --baud <baudrate>
```

Verwenden Sie für minicom den folgenden Befehl, um es zu konfigurieren:

```
minicom -s
```

Konfiguriere Einstellungen wie Baudrate und Gerätename unter der Option `Serial port setup`.

Führe nach der Konfiguration `minicom` aus, um die UART-Konsole zu öffnen.

## UART über Arduino UNO R3 (Boards mit herausnehmbarem Atmel-328p-Chip)

Falls keine UART-zu-USB-Adapter verfügbar sind, kann ein Arduino UNO R3 mit einem schnellen Hack verwendet werden. Da ein Arduino UNO R3 fast überall verfügbar ist, kann das viel Zeit sparen.

Der Arduino UNO R3 hat einen USB-zu-Serial-Adapter direkt auf der Platine. Um eine UART-Verbindung herzustellen, ziehe einfach den Atmel-328p-Mikrocontroller-Chip aus der Platine. Dieser Hack funktioniert mit Arduino-UNO-R3-Varianten, bei denen der Atmel 328p nicht auf die Platine gelötet ist (darin wird die SMD-Version verwendet). Verbinde den RX-Pin des Arduino (Digital Pin 0) mit dem TX-Pin der UART-Schnittstelle und den TX-Pin des Arduino (Digital Pin 1) mit dem RX-Pin der UART-Schnittstelle.

Verwende den **Serial Monitor** der Arduino IDE oder ein spezielles Terminal mit der Baudrate des Zielgeräts. Die seriellen Signale eines klassischen Uno R3 verwenden eine Logikspannung von 5 V. Verwende daher einen Pegelwandler oder Spannungsteiler, bevor du sie mit einem Zielgerät verbindest, das 3,3 V oder eine niedrigere Spannung verwendet.

## Bus Pirate

Das folgende Transkript verwendet die Legacy-Firmware-Schnittstelle von Bus Pirate, um UART-Ausgaben zu überwachen. Neuere Bus-Pirate-Firmware verwendet Befehle wie `m uart`, `{`/`}`, `monitor` oder `bridge`. Sieh in der Dokumentation der installierten Version nach.<sup>[[2]](#references)</sup>

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

Eine UART-Konsole bietet zur Laufzeit Zugriff auf Boot-Logs und manchmal auf eine Bootloader- oder Betriebssystem-Shell. Selbst eine schreibgeschützte Konsole gibt Einblick in Memory Maps, Flash-Treiber, Boot-Argumente, Partitionslayouts und Firmware-Versionen. Firmware kann auf SPI NOR/NAND, eMMC oder einem anderen Gerät gespeichert sein; sie wird nicht generell von einem EEPROM ausgeführt, und Dateien, die auf ein eingehängtes persistentes Dateisystem geschrieben werden, verschwinden beim Neustart nicht unbedingt.

Es gibt mehrere Möglichkeiten zur Datenerfassung; der SPI-Abschnitt behandelt direktes Auslesen von externem Flash. Eine konsolengestützte Datenerfassung ist möglicherweise weniger invasiv, wenn der Bootloader bereits einen sicheren Lesebefehl bereitstellt. Allerdings können eine Unterbrechung des Bootvorgangs oder Flash-Befehle die Verfügbarkeit beeinträchtigen. Daher sollte der ursprüngliche Zustand dokumentiert und auf Schreib- oder Löschvorgänge verzichtet werden.

Das Auslesen von Firmware über die Konsole beginnt oft damit, den Bootloader zu unterbrechen. Viele Embedded-Linux-Geräte verwenden **Das U-Boot**, andere jedoch proprietäre Bootloader oder deaktivieren die interaktive Konsole.

Um zu prüfen, ob ein interaktiver Bootloader vorhanden ist, verbinde den UART-Empfangspfad und das Terminal, während das Zielgerät ausgeschaltet ist, starte die Protokollierung und schalte es ein. Folge der angezeigten Autoboot-Aufforderung. Je nach Build ist zum Unterbrechen möglicherweise eine Taste oder eine kurze Tastenkombination erforderlich; unter Umständen ist es auch vollständig deaktiviert.

Wenn die Unterbrechung gelingt, verwende `help`, `printenv` und schreibgeschützte Erkundungsbefehle, um das Speicher- und Storage-Layout des jeweiligen Herstellers zu verstehen, bevor du auf Adressen zugreifst.

In U-Boot zeigt `md` **adressierbaren Speicher** an, nicht automatisch „das EEPROM“. Verwende zunächst boardspezifische Befehle wie `mtd list`, `sf probe`, `mmc info`, `part list`, Umgebungsvariablen und Boot-Logs, um die richtige gemappte Adresse zu ermitteln oder einen Flash-Bereich in den RAM zu laden. Zeige dann einen bekannten Bereich byteweise an:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Protokolliere die serielle Ausgabe, bevor du startest. Die Ausgabe von `md.b` enthält Adressen und eine ASCII-Spalte und ist daher eine Textdarstellung, kein rohes ROM-Abbild.

Entferne die Adress- und ASCII-Spalten, füge nur die hexadezimalen Byte-Felder zusammen und dekodiere sie in Binärdaten (zum Beispiel mit `xxd -r -p`). Überprüfe die erwartete Byteanzahl und erfasse vor der Analyse einen Hash:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifiziert anschließend bekannte Signaturen in der rekonstruierten Binärdatei. Ein direktes Auslesen des Flash-Speichers über die entsprechende SPI-/eMMC-/NAND-Schnittstelle ist in der Regel schneller und weniger fehleranfällig, wenn die Konsole Daten nicht zuverlässig übertragen kann.

U-Boot kann das Unterbrechen des Bootvorgangs deaktivieren, eine herstellerspezifische Tastenkombination erfordern oder Speicher-/Flash-Befehle sperren. Orientiere dich an der Autoboot-Eingabeaufforderung und dem Boot-Log, statt blind Zeichen zu übertragen. Lässt sich die Konsole nicht unterbrechen, sichere das Boot-Log und wechsle zu einem nicht-invasiven Verfahren zur Firmware-Beschaffung.

## References

- [1] [Microchip PIC32-Familien-Referenzhandbuch – UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate-Dokumentation – UART-Modus und elektrische Grenzwerte](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs – Datenblatt zum CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot-Dokumentation – Speicheranzeigebefehl `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
