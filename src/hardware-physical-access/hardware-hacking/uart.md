# UART

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

UART ist eine asynchrone serielle Schnittstelle, die einen gerahmten Bitstrom ohne gemeinsamen Takt überträgt. Logikpegel-UART darf nicht mit RS-232 verwechselt werden: RS-232 verwendet andere, oft negative Spannungspegel und benötigt einen Transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Im Allgemeinen liegt die Leitung im Ruhezustand von UART auf High (logischer Wert 1). Um die Übertragung von Daten zu signalisieren, sendet der Sender zunächst ein Startbit an den Empfänger. Währenddessen liegt das Signal auf Low (logischer Wert 0). Anschließend sendet der Sender fünf bis acht Datenbits mit der eigentlichen Nachricht, gefolgt von einem optionalen Paritätsbit und je nach Konfiguration einem oder zwei Stopbits (mit logischem Wert 1). Das zur Fehlerprüfung verwendete Paritätsbit ist in der Praxis selten anzutreffen. Das Stopbit (oder die Stopbits) signalisiert das Ende der Übertragung.

Die häufigste Konfiguration ist 8N1: acht Datenbits, keine Parität und ein Stopbit. UART sendet das niederwertigste Datenbit zuerst. Daher wird ASCII `C` (`0x43`) wie folgt übertragen: Start `0`; Daten `1, 1, 0, 0, 0, 0, 1, 0`; Stop `1`.<sup>[[1]](#references)</sup>

![UART: Die häufigste Konfiguration nennen wir 8N1: acht Datenbits, keine Parität und ein Stopbit. Wenn wir zum Beispiel das Zeichen C oder 0x43 in ASCII mit 8N1-UART senden möchten](<../../images/image (764).png>)

Hardware-Tools für die Kommunikation mit UART:

- USB-zu-Seriell-Adapter
- Adapter mit CP2102- oder PL2303-Chips
- Multipurpose-Tool wie Bus Pirate, Adafruit FT232H, Shikra oder Attify Badge

### UART-Ports identifizieren

Ein typischer Debug-Header stellt **TX**, **RX** und **GND** bereit. Möglicherweise gibt es auch einen **Vcc/Vref**-Pin, einen Reset-Pin oder Pins für die Flusssteuerung. Vcc ist kein UART-Signal und sollte normalerweise nur als Spannungsreferenz dienen – nicht als Stromquelle angeschlossen werden –, sofern Schaltplan und Strombedarf der Platine nicht bekannt sind.<sup>[[2]](#references)[[3]](#references)</sup>

Beginne mit ausgeschaltetem und getrenntem Gerät:

- Identifiziere **GND** im Durchgangsprüfungsmodus anhand einer bekannten Massefläche, einer Steckverbinderabschirmung oder der Versorgungsmasse. Verwende niemals den Durchgangs- oder Widerstandsmodus an einer eingeschalteten Platine.
- Wechsle vor dem Einschalten des Zielgeräts in den Gleichspannungsmodus. Miss mögliche Pins relativ zu Masse, um die Logikspannung zu bestimmen. Eine stabile Spannung kann Vcc/Vref sein; gehe nicht davon aus, dass ein Anschluss sicher verbunden werden kann.
- Beobachte mögliche Pins während des Bootvorgangs mit einem Logikanalysator oder Oszilloskop. **TX** liegt im Ruhezustand normalerweise auf High und zeigt Impulse gerahmter Daten. Ein Multimeter kann Schwankungen des Mittelwerts anzeigen, aber weder das Framing noch die Baudrate bestätigen.
- **RX** kann im Ruhezustand bleiben und lässt sich nicht sicher allein dadurch identifizieren, dass er neben TX liegt. Verfolge die Leiterbahnen auf der Platine, sieh im Datenblatt des SoC nach oder verwende einen hochohmigen Analysator, bevor du den Pin ansteuerst.

Das Vertauschen von TX und RX führt normalerweise dazu, dass keine Kommunikation zustande kommt. Eine Verwechslung von Stromversorgung, Masse oder Signalpegeln kann das Zielgerät oder den Adapter dauerhaft beschädigen. Verbinde zuerst die Masse und beginne mit reinem **Empfang** (TX des Zielgeräts an RX des Adapters).

Hersteller lassen den Header möglicherweise weg, bestücken Serienwiderstände nicht, deaktivieren die Konsole in der Firmware oder stellen nur TX bereit. Verfolge nahegelegene Testpads und Widerstands-Footprints bis zum SoC und stelle erst dann eine temporäre hochohmige Verbindung her, wenn der elektrische Pegel bestätigt wurde. Eine Garantie bedeutet nicht, dass UART zugänglich sein muss.

### UART-Baudrate bestimmen

Am einfachsten bestimmst du die richtige Baudrate, indem du die Ausgabe des **TX-Pins ansiehst und versuchst, die Daten zu lesen**. Wenn die empfangenen Daten nicht lesbar sind, wechsle zur nächsten möglichen Baudrate, bis die Daten lesbar werden. Dafür kannst du einen USB-zu-Seriell-Adapter oder ein Multipurpose-Gerät wie Bus Pirate zusammen mit einem Hilfsskript wie [baudrate.py](https://github.com/devttys0/baudrate/) verwenden. Die häufigsten Baudraten sind 9600, 38400, 19200, 57600 und 115200.

> [!CAUTION]
> Wichtig ist, dass du bei diesem Protokoll TX eines Geräts mit RX des anderen verbindest!

### Boot-Ausgabe über UART mit SCPI automatisiert erfassen

Wenn die Boot-Ausgabe kurz ist oder das TX-Pad noch nicht bekannt ist, automatisiere wiederholte Neustarts, statt Netzteil und Oszilloskop von Hand zu bedienen. Verbinde ein strombegrenztes, programmierbares Netzteil mit dem bestätigten Stromversorgungseingang des Zielgeräts. Prüfe jedes mögliche TX-Pad mit einem hochohmigen Oszilloskopeingang und gemeinsamer Masse; steuere das Pad nicht an.<sup>[[5]](#references)</sup>

VISA öffnet serielle oder Ethernet-Instrumentensitzungen, während SCPI Ausgang, Trigger und Wellenformauslesung steuert.<sup>[[5]](#references)[[6]](#references)</sup> Installiere `pyvisa` und `pyvisa-py` (sowie `pyserial` für serielle VISA-Ressourcen); `ResourceManager('@py')` wählt ausdrücklich das Python-Backend aus.<sup>[[5]](#references)[[7]](#references)</sup> Ersetze die Ressourcen-Strings und Befehle durch die von den verwendeten Instrumenten unterstützten Werte.<sup>[[5]](#references)</sup>

Im Beispiel mit dem Rigol MSO5000 aktiviere vor dem Einschalten der Platine einen Trigger auf die fallende Flanke: Ein im Ruhezustand auf High liegender UART-TX-Pin fällt beim Startbit zuerst ab.<sup>[[5]](#references)</sup> Stelle den Triggerschwellenwert zwischen den gemessenen High- und Low-Pegeln ein und wähle eine Zeitbasis, die das gewünschte Boot-Intervall abdeckt.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` kann bei kontinuierlichen Aufnahmen wiederholte Flanken unterdrücken, ersetzt aber nicht die Prüfung, ob eine Einzelaufnahme tatsächlich abgeschlossen wurde.<sup>[[5]](#references)</sup> Das folgende Beispiel erfasst einen Bootvorgang und speichert sowohl die Samples als vorzeichenlose Bytes als auch ihre Skalierungsmetadaten. Bei einer Zeitüberschreitung wird das Zielgerät ausgeschaltet, statt endlos zu warten.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA: Einschalten und UART-Wellenform als Einzelaufnahme erfassen</summary>

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

Für eine Pad-Untersuchung wiederholen Sie die Einzelaufnahme nach dem Versetzen der Probe oder lassen Sie die Versorgungssitzung geöffnet und schalten Sie den Ausgang mit einer Boot-Verweildauer und einer Ausschaltpause ein und aus. Aktivieren Sie das Oszilloskop vor jedem Einschalten erneut, damit jede Datei einem Bootvorgang und einem Pad entspricht.<sup>[[5]](#references)</sup>

Die Rigol-Präambel lautet `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> Der **dritte** Wert ist die Anzahl der Punkte, nicht wie im Artikel angegeben die Abtastrate.<sup>[[5]](#references)[[6]](#references)</sup> Im Beispiel entsprechen `25,000,000` Punkte und `xincrement = 2e-8` Sekunden einer Abtastrate von `1 / xincrement = 50,000,000` Samples/Sekunde, nicht 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Bewahren Sie die Präambel zusammen mit der Binärdatei auf und prüfen Sie, ob die Leselänge mit `<points>` übereinstimmt; die Anleitung beschreibt segmentierte/gebündelte Lesevorgänge für große Aufzeichnungen.<sup>[[6]](#references)</sup>

Um das aufgezeichnete Signal zu dekodieren, importieren Sie `capture.bin` in PulseView als **Raw Analog Data Without Header**, wählen Sie vorzeichenlose 8-Bit-Werte (`U8`) und geben Sie die aus `xincrement` berechnete Abtastrate ein.<sup>[[5]](#references)[[6]](#references)</sup> Wenden Sie **Logic via Threshold** auf den analogen Kanal an und wählen Sie einen Schwellenwert zwischen den niedrigen und hohen Sample-Werten.<sup>[[5]](#references)</sup> Messen Sie die Breite eines sauberen Startbits, um die Baudrate zu schätzen (etwa 17,36 µs bei 57.600 Baud), wenden Sie dann den UART-Decoder von PulseView an und überprüfen Sie, ob mehrere Frames konsistent dekodiert werden.<sup>[[5]](#references)</sup> Eine fallende Flanke allein beweist nicht, dass ein Pad UART ist.

## CP210X UART-zu-TTY-Adapter

CP210x-USB-zu-UART-Bridges finden sich auf vielen Prototyping-Boards und preisgünstigen Adaptern. Gängige Module stellen neben GND, RXD und TXD auch Versorgungspins bereit, doch Pinleisten und I/O-Pegel unterscheiden sich. Prüfen Sie die tatsächliche Spannung anhand des Board-Designs oder des Datenblatts. Üblicherweise verbinden Sie nur GND und den Adapter-RX mit dem Ziel-TX sowie – nach erfolgreicher Nur-Empfangsprüfung – den Adapter-TX mit dem Ziel-RX. Verbinden Sie den 5-V-/3,3-V-Versorgungspin des Adapters nicht, es sei denn, Sie möchten ein Zielgerät versorgen, von dem bekannt ist, dass es diese Spannung verträgt.<sup>[[3]](#references)</sup>

Falls der Adapter nicht erkannt wird, stellen Sie sicher, dass die CP210X-Treiber auf dem Hostsystem installiert sind. Sobald der Adapter erkannt und verbunden ist, können Tools wie picocom, minicom oder screen verwendet werden.

So listen Sie die mit Linux-/MacOS-Systemen verbundenen Geräte auf:

```
ls /dev/
```

Für die grundlegende Interaktion mit der UART-Schnittstelle verwenden Sie den folgenden Befehl:

```
picocom /dev/<adapter> --baud <baudrate>
```

Verwenden Sie für minicom den folgenden Befehl zur Konfiguration:

```
minicom -s
```

Konfiguriere Einstellungen wie Baudrate und Gerätenamen in der Option `Serial port setup`.

Führe nach der Konfiguration `minicom` aus, um die UART-Konsole zu öffnen.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

Falls keine UART-Serial-to-USB-Adapter verfügbar sind, kann ein Arduino UNO R3 mit einem schnellen Hack verwendet werden. Da ein Arduino UNO R3 normalerweise überall verfügbar ist, kann das viel Zeit sparen.

Der Arduino UNO R3 hat einen USB-zu-Serial-Adapter direkt auf der Platine. Um eine UART-Verbindung herzustellen, ziehe einfach den Atmel-328p-Mikrocontroller-Chip aus der Platine. Dieser Hack funktioniert mit Arduino-UNO-R3-Varianten, bei denen der Atmel 328p nicht auf die Platine gelötet ist (bei dieser Variante wird die SMD-Version verwendet). Verbinde den RX-Pin des Arduino (Digital Pin 0) mit dem TX-Pin der UART-Schnittstelle und den TX-Pin des Arduino (Digital Pin 1) mit dem RX-Pin der UART-Schnittstelle.

Verwende den **Serial Monitor** der Arduino IDE oder ein separates Terminal mit der Baudrate des Zielgeräts. Die seriellen Signale eines klassischen Uno R3 verwenden eine Logikspannung von 5 V. Verwende daher einen Pegelwandler oder Spannungsteiler, bevor du sie mit einem Zielgerät mit 3,3 V oder einer niedrigeren Spannung verbindest.

## Bus Pirate

Das folgende Transkript verwendet die ältere Bus-Pirate-Firmware-Schnittstelle, um die UART-Ausgabe zu überwachen. Neuere Bus-Pirate-Firmware verwendet Befehle wie `m uart`, `{`/`}`, `monitor` oder `bridge`; lies die Dokumentation für die installierte Version.<sup>[[2]](#references)</sup>

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

## Firmware-Dump über die UART-Konsole

Eine UART-Konsole ermöglicht zur Laufzeit den Zugriff auf Boot-Logs und manchmal auf eine Bootloader- oder Betriebssystem-Shell. Selbst eine schreibgeschützte Konsole gibt Einblick in Speicherabbilder, Flash-Treiber, Boot-Argumente, Partitionslayouts und Firmware-Versionen. Die Firmware kann auf SPI NOR/NAND, eMMC oder einem anderen Gerät liegen; sie wird im Allgemeinen nicht von einem EEPROM ausgeführt, und Dateien, die auf ein eingehängtes persistentes Dateisystem geschrieben werden, verschwinden nach einem Neustart nicht zwangsläufig.

Es gibt mehrere Möglichkeiten zur Datenerfassung; der SPI-Abschnitt behandelt das direkte Auslesen von externem Flash. Eine konsolengestützte Erfassung kann weniger invasiv sein, wenn der Bootloader bereits einen sicheren Lesebefehl bereitstellt. Allerdings können jede Unterbrechung des Bootvorgangs und jeder Flash-Befehl die Verfügbarkeit beeinträchtigen. Halte daher den ursprünglichen Zustand fest und vermeide Schreib- und Löschoperationen.

Das Auslesen der Firmware über die Konsole beginnt oft damit, den Bootloader zu unterbrechen. Viele Embedded-Linux-Geräte verwenden **Das U-Boot**, andere jedoch proprietäre Bootloader oder deaktivieren die interaktive Konsole.

Um zu prüfen, ob ein interaktiver Bootloader verfügbar ist, verbinde bei ausgeschaltetem Zielgerät den UART-Empfangspfad und das Terminal, starte die Protokollierung und schalte das Gerät ein. Folge der angezeigten Aufforderung zum automatischen Booten. Je nach Build ist zum Unterbrechen eine Taste oder eine kurze Tastenfolge erforderlich, oder die Unterbrechung ist vollständig deaktiviert.

Wenn die Unterbrechung gelingt, verwende `help`, `printenv` und schreibgeschützte Erkundungsbefehle, um das Speicher- und Speichergeräte-Layout des jeweiligen Herstellers zu verstehen, bevor du auf Adressen zugreifst.

In U-Boot zeigt `md` **adressierbaren Speicher** an, nicht automatisch das „EEPROM“. Verwende zuerst boardspezifische Befehle wie `mtd list`, `sf probe`, `mmc info`, `part list`, Umgebungsvariablen und Boot-Logs, um die richtige Speicheradresse zu ermitteln oder einen Flash-Bereich in den RAM zu laden. Zeige anschließend einen bekannten Bereich Byte für Byte an:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Protokollieren Sie die serielle Ausgabe vor dem Start. Die Ausgabe von `md.b` enthält Adressen und eine ASCII-Spalte und ist daher eine textuelle Darstellung statt eines rohen ROM-Abbilds.

Entfernen Sie die Adress- und ASCII-Spalten, verketten Sie ausschließlich die hexadezimalen Bytefelder und dekodieren Sie sie in Binärdaten (zum Beispiel mit `xxd -r -p`). Überprüfen Sie die erwartete Byteanzahl und erfassen Sie vor der Analyse einen Hash:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifiziert anschließend bekannte Signaturen in der rekonstruierten Binärdatei. Ein direkter Flash-Auslesevorgang über die passende SPI-/eMMC-/NAND-Schnittstelle ist in der Regel schneller und weniger fehleranfällig, wenn die Konsole Daten nicht zuverlässig übertragen kann.

U-Boot kann die Unterbrechung deaktivieren, eine herstellerspezifische Tastenkombination erfordern oder Speicher-/Flash-Befehle sperren. Orientiere dich an der Autostart-Eingabeaufforderung und dem Boot-Log, statt blind Zeichen zu senden. Wenn sich die Konsole nicht unterbrechen lässt, sichere das Boot-Log und wechsle zu einem nicht-invasiven Verfahren zur Firmware-Beschaffung.

## References

- [1] [Referenzhandbuch zur Microchip-PIC32-Familie - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate-Dokumentation - UART-Modus und elektrische Grenzwerte](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C-Datenblatt](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot-Dokumentation - `md`-Befehl zur Speicheranzeige](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI und Hardware-Instrumentierung für Reverse Engineers, Teil 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000-Programmierhandbuch](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Backend konfigurieren](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
