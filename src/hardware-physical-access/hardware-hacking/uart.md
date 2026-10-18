# UART

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

UART ist eine asynchrone serielle Schnittstelle, die einen gerahmten Bitstrom ohne gemeinsamen Takt überträgt. Logikpegel-UART darf nicht mit RS-232 verwechselt werden: RS-232 verwendet andere, oft negative Spannungspegel und benötigt einen Transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Im Allgemeinen liegt die Leitung im Ruhezustand von UART auf High (logischer Wert 1). Um eine Datenübertragung zu starten, sendet der Sender ein Startbit an den Empfänger; dabei liegt das Signal auf Low (logischer Wert 0). Anschließend sendet der Sender fünf bis acht Datenbits mit der eigentlichen Nachricht, gefolgt von einem optionalen Paritätsbit und je nach Konfiguration einem oder zwei Stoppbits (mit dem logischen Wert 1). Das zur Fehlerprüfung verwendete Paritätsbit kommt in der Praxis selten vor. Das oder die Stoppbits kennzeichnen das Ende der Übertragung.

Die häufigste Konfiguration ist 8N1: acht Datenbits, keine Parität und ein Stoppbit. UART sendet das niederwertigste Datenbit zuerst. Daher wird ASCII-`C` (`0x43`) wie folgt übertragen: Start `0`; Daten `1, 1, 0, 0, 0, 0, 1, 0`; Stopp `1`.<sup>[[1]](#references)</sup>

![UART: Die häufigste Konfiguration heißt 8N1: acht Datenbits, keine Parität und ein Stoppbit. Wenn wir beispielsweise das Zeichen C oder 0x43 in ASCII als 8N1-UART senden möchten](<../../images/image (764).png>)

Hardwaretools zur Kommunikation über UART:

- USB-zu-Seriell-Adapter
- Adapter mit CP2102- oder PL2303-Chips
- Multifunktionswerkzeuge wie Bus Pirate, Adafruit FT232H, Shikra oder Attify Badge

### UART-Ports identifizieren

Ein typischer Debug-Header stellt **TX**, **RX** und **GND** bereit; außerdem kann er einen **Vcc/Vref**-Pin, Reset- oder Flusssteuerungs-Pins besitzen. Vcc ist kein UART-Signal und sollte normalerweise nur als Spannungsreferenz verwendet werden – nicht als Stromversorgung –, sofern Schaltplan und Strombedarf der Platine nicht bekannt sind.<sup>[[2]](#references)[[3]](#references)</sup>

Beginne mit dem **ausgeschalteten** und getrennten Gerät:

- Identifiziere **GND** im Durchgangsprüfmodus anhand einer bekannten Massefläche, der Abschirmung eines Anschlusses oder der Versorgungsmasse. Verwende den Durchgangsprüf- oder Widerstandsmodus niemals an einer eingeschalteten Platine.
- Wechsle vor dem Einschalten des Ziels in den Gleichspannungsmodus. Miss mögliche Pins relativ zur Masse, um die Logikspannung zu bestimmen. Eine konstante Spannungsschiene könnte Vcc/Vref sein; gehe nicht davon aus, dass der Anschluss sicher ist.
- Beobachte mögliche Pins während des Bootvorgangs mit einem Logikanalysator oder Oszilloskop. **TX** liegt im Ruhezustand üblicherweise auf High und zeigt Bursts gerahmter Daten. Ein Multimeter kann eine durchschnittliche Schwankung anzeigen, aber weder das Framing noch die Baudrate überprüfen.
- **RX** kann im Ruhezustand bleiben und lässt sich nicht sicher allein dadurch identifizieren, dass es neben TX liegt. Verfolge die Leiterbahnen auf der Platine, lies das SoC-Datenblatt oder verwende einen hochohmigen Analysator, bevor du den Pin ansteuerst.

Das Vertauschen von TX und RX führt normalerweise zu keiner Kommunikation; eine Verwechslung von Stromversorgung, Masse oder Signalpegeln kann das Zielgerät oder den Adapter dauerhaft beschädigen. Verbinde zuerst die Masse und beginne im **reinen Empfangsmodus** (TX des Zielgeräts an RX des Adapters).

Hersteller lassen den Header möglicherweise weg, bestücken Serienwiderstände nicht, deaktivieren die Konsole in der Firmware oder stellen nur TX bereit. Verfolge nahegelegene Testpads und Widerstands-Footprints bis zum SoC und stelle erst dann eine temporäre hochohmige Verbindung her, wenn der elektrische Pegel bestätigt wurde. Eine vorhandene Garantie bedeutet nicht, dass ein zugänglicher UART vorhanden sein muss.

### Ein scheinbar dauerhaft niedriges TX-Pad wiederherstellen

Ein beschriftetes TX-Pad, das bei einer ersten Oszilloskopaufnahme dauerhaft Low bleibt, reicht nicht aus, um UART auszuschließen. Nachdem die Logikspannung des Zielgeräts und eine gemeinsame Masse bestätigt wurden, versuche es mit einem schwachen Pull-up (im dokumentierten Beispiel **10 kΩ an 3,3 V**) und wiederhole die Aufnahme, während du Tasten betätigst oder das Gerät bootest. Verwende nur die bestätigte Logikversorgung des Zielgeräts. Verbinde einen Pull-up nicht mit einem unbekannten oder aktiv angesteuerten Signal. Wenn gerahmte Übergänge sichtbar werden, miss die kürzeste saubere Bitdauer, um die Baudrate zu schätzen, bevor du das Pad im reinen Empfangsmodus mit einem Serielladapter verbindest. Im Beispiel konnten so Ereignisprotokolle von Tastendrücken mit 115200 Baud ausgelesen werden, ein Firmware-Dump wurde jedoch nicht offengelegt.<sup>[[8]](#references)</sup>

### UART-Baudrate identifizieren

Am einfachsten lässt sich die korrekte Baudrate ermitteln, indem du die Ausgabe des **TX-Pins ansiehst und versuchst, die Daten auszulesen**. Wenn die empfangenen Daten nicht lesbar sind, probiere die nächste mögliche Baudrate, bis die Daten lesbar werden. Dafür kannst du einen USB-zu-Seriell-Adapter oder ein Multifunktionsgerät wie Bus Pirate verwenden, zusammen mit einem Hilfsskript wie [baudrate.py](https://github.com/devttys0/baudrate/). Die häufigsten Baudraten sind 9600, 38400, 19200, 57600 und 115200.

> [!CAUTION]
> Beachte, dass du bei diesem Protokoll TX eines Geräts mit RX des anderen verbinden musst!

### Boot-UART-Aufnahmen mit SCPI automatisieren

Wenn die Boot-Ausgabe kurz ist oder der TX-Pin noch nicht bekannt ist, automatisiere wiederholte Starts, anstatt Netzteil und Oszilloskop von Hand zu bedienen. Verbinde ein strombegrenztes programmierbares Netzteil mit dem bestätigten Stromversorgungseingang des Zielgeräts. Prüfe jedes mögliche TX-Pad mit einem hochohmigen Oszilloskopeingang und gemeinsamer Masse; steuere das Pad nicht an.<sup>[[5]](#references)</sup>

VISA öffnet serielle oder Ethernet-Instrumentensitzungen, während SCPI die Ausgabe, Trigger und das Auslesen von Wellenformen steuert.<sup>[[5]](#references)[[6]](#references)</sup> Installiere `pyvisa` und `pyvisa-py` (sowie `pyserial` für serielle VISA-Ressourcen); `ResourceManager('@py')` wählt ausdrücklich das Python-Backend aus.<sup>[[5]](#references)[[7]](#references)</sup> Ersetze die Ressourcenzeichenfolgen und Befehle durch die von den verwendeten Instrumenten unterstützten Werte.<sup>[[5]](#references)</sup>

Im Beispiel mit dem Rigol MSO5000 wird vor dem Einschalten der Platine ein Single-Shot-Trigger auf die fallende Flanke gesetzt: Ein im Ruhezustand auf High liegender UART-TX-Pin fällt für sein Startbit zunächst ab.<sup>[[5]](#references)</sup> Stelle den Triggerschwellenwert zwischen den gemessenen High- und Low-Pegeln ein und wähle eine Zeitbasis, die das gewünschte Bootintervall abdeckt.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` kann bei kontinuierlichen Aufnahmen wiederholte Flanken unterdrücken, ersetzt aber nicht die Überprüfung, ob eine Single-Shot-Aufnahme tatsächlich abgeschlossen wurde.<sup>[[5]](#references)</sup> Das folgende Beispiel zeichnet einen Bootvorgang auf und speichert sowohl die Samples als vorzeichenlose Bytes als auch die zugehörigen Skalierungsmetadaten; bei einer Zeitüberschreitung wird das Zielgerät ausgeschaltet, anstatt unbegrenzt zu warten.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA-Aufnahme einer UART-Wellenform beim Einschalten mit Single-Shot-Trigger</summary>

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

Für eine Pad-Erfassung wiederholen Sie die Einzelaufnahme nach dem Versetzen der Sonde oder lassen Sie die Versorgungssitzung geöffnet und schalten Sie den Ausgang mit einer Boot-Verweildauer und einer Ausschaltpause ein und aus. Aktivieren Sie das Oszilloskop vor jedem Einschalten erneut, damit jede Datei einem Bootvorgang und einem Pad entspricht.<sup>[[5]](#references)</sup>

Die Rigol-Präambel lautet `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> Der **dritte** Wert gibt die Anzahl der Punkte an, nicht wie im Artikel angegeben die Abtastrate.<sup>[[5]](#references)[[6]](#references)</sup> Im Beispiel entsprechen `25,000,000` Punkte und `xincrement = 2e-8` Sekunden einer Abtastrate von `1 / xincrement = 50,000,000` Samples/Sekunde, nicht 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Bewahren Sie die Präambel zusammen mit der Binärdatei auf und prüfen Sie, ob die Leselänge `<points>` entspricht; die Anleitung beschreibt segmentierte/gebündelte Lesevorgänge für große Aufzeichnungen.<sup>[[6]](#references)</sup>

Um das aufgezeichnete Signal zu dekodieren, importieren Sie `capture.bin` in PulseView als **Raw Analog Data Without Header**, wählen Sie vorzeichenlose 8-Bit-Werte (`U8`) und geben Sie die anhand von `xincrement` berechnete Abtastrate ein.<sup>[[5]](#references)[[6]](#references)</sup> Wenden Sie **Logic via Threshold** auf den Analogkanal an und wählen Sie einen Schwellenwert zwischen den niedrigen und hohen Samplewerten.<sup>[[5]](#references)</sup> Messen Sie die Breite eines sauberen Startbits, um die Baudrate zu schätzen (etwa 17,36 µs bei 57.600 Baud). Wenden Sie anschließend den UART-Decoder von PulseView an und prüfen Sie, ob mehrere Frames konsistent dekodiert werden.<sup>[[5]](#references)</sup> Eine fallende Flanke allein beweist nicht, dass ein Pad UART ist.

## CP210X UART-zu-TTY-Adapter

CP210x-USB-zu-UART-Bridges finden sich auf vielen Prototyping-Boards und günstigen Adaptern. Übliche Module bieten neben GND, RXD und TXD auch Versorgungspins, doch ihre Header und I/O-Pegel variieren. Prüfen Sie die tatsächliche Spannung anhand des Board-Designs oder des Datenblatts. Verbinden Sie normalerweise nur GND und den Adapter-RX mit dem Ziel-TX sowie – nach erfolgreicher Validierung des Empfangs – den Adapter-TX mit dem Ziel-RX. Schließen Sie den 5-V-/3,3-V-Versorgungspin des Adapters nicht an, es sei denn, Sie wollen gezielt ein Zielgerät mit Strom versorgen, von dem bekannt ist, dass es diese Spannung verträgt.<sup>[[3]](#references)</sup>

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

Konfiguriere Einstellungen wie Baudrate und Gerätenamen in der Option `Serial port setup`.

Führe nach der Konfiguration `minicom` aus, um die UART-Konsole zu öffnen.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

Falls keine UART-Serial-to-USB-Adapter verfügbar sind, lässt sich ein Arduino UNO R3 mit einem schnellen Hack verwenden. Da ein Arduino UNO R3 fast überall verfügbar ist, kann das viel Zeit sparen.

Der Arduino UNO R3 hat einen USB-to-Serial-Adapter direkt auf der Platine. Um eine UART-Verbindung herzustellen, ziehe einfach den Atmel-328p-Mikrocontrollerchip von der Platine ab. Dieser Hack funktioniert mit Arduino-UNO-R3-Varianten, bei denen der Atmel 328p nicht auf die Platine gelötet ist (in dieser Variante wird eine SMD-Version verwendet). Verbinde den RX-Pin des Arduino (Digital Pin 0) mit dem TX-Pin der UART-Schnittstelle und den TX-Pin des Arduino (Digital Pin 1) mit dem RX-Pin der UART-Schnittstelle.

Verwende den **Serial Monitor** der Arduino IDE oder ein dediziertes Terminal mit der Baudrate des Zielgeräts. Die seriellen Signale eines klassischen Uno R3 verwenden eine Logikspannung von 5 V. Verwende daher einen Pegelwandler oder Spannungsteiler, bevor du sie mit einem Zielgerät verbindest, das mit 3,3 V oder einer niedrigeren Spannung arbeitet.

## Bus Pirate

Das folgende Transkript verwendet die ältere Bus-Pirate-Firmware-Schnittstelle, um die UART-Ausgabe zu überwachen. Neuere Bus-Pirate-Firmware verwendet Befehle wie `m uart`, `{`/`}`, `monitor` oder `bridge`; ziehe die Dokumentation für die installierte Version zu Rate.<sup>[[2]](#references)</sup>

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

## Firmware mit der UART-Konsole auslesen

Eine UART-Konsole ermöglicht den Zugriff zur Laufzeit auf Boot-Logs und manchmal auf eine Bootloader- oder Betriebssystem-Shell. Selbst eine schreibgeschützte Konsole gibt Einblicke in Memory Maps, Flash-Treiber, Boot-Argumente, Partitionslayouts und Firmware-Versionen. Firmware kann in SPI NOR/NAND, eMMC oder einem anderen Gerät gespeichert sein. Sie wird im Allgemeinen nicht von einem EEPROM ausgeführt, und Dateien, die auf ein eingebundenes persistentes Dateisystem geschrieben werden, verschwinden beim Neustart nicht unbedingt.

Es gibt mehrere Möglichkeiten zur Datenerfassung. Im SPI-Abschnitt wird das direkte Auslesen von externem Flash behandelt. Die Erfassung über die Konsole kann weniger invasiv sein, wenn der Bootloader bereits einen sicheren Lesebefehl bereitstellt. Eine Unterbrechung des Bootvorgangs oder ein Flash-Befehl kann jedoch die Verfügbarkeit beeinträchtigen. Halte daher den ursprünglichen Zustand fest und vermeide Schreib- oder Löschvorgänge.

Das Auslesen der Firmware über die Konsole beginnt häufig damit, den Bootloader zu unterbrechen. Viele Embedded-Linux-Geräte verwenden **Das U-Boot**, andere jedoch proprietäre Bootloader oder deaktivieren die interaktive Konsole.

Um zu prüfen, ob ein interaktiver Bootloader verfügbar ist, verbinde bei ausgeschaltetem Zielgerät den UART-Empfangspfad und das Terminal, starte die Protokollierung und schalte das Gerät ein. Folge der angezeigten Autoboot-Aufforderung. Je nach Build ist zum Unterbrechen eine Taste oder eine kurze Tastenkombination nötig; die Funktion kann auch vollständig deaktiviert sein.

Wenn die Unterbrechung gelingt, verwende `help`, `printenv` und schreibgeschützte Erkundungsbefehle, um das Speicher- und Speichergeräte-Layout des Herstellers zu verstehen, bevor du auf Adressen zugreifst.

In U-Boot zeigt `md` **adressierbaren Speicher** an, nicht automatisch „das EEPROM“. Verwende zuerst boardspezifische Befehle wie `mtd list`, `sf probe`, `mmc info`, `part list`, Umgebungsvariablen und Boot-Logs, um die richtige zugeordnete Adresse zu ermitteln oder einen Flash-Bereich in den RAM zu laden. Zeige dann einen bekannten Bereich Byte für Byte an:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Protokolliere die serielle Ausgabe, bevor du startest. Die Ausgabe von `md.b` enthält Adressen und eine ASCII-Spalte und ist daher eine Textdarstellung und kein rohes ROM-Image.

Entferne die Adress- und ASCII-Spalten, füge nur die hexadezimalen Byte-Felder zusammen und dekodiere sie in Binärdaten (zum Beispiel mit `xxd -r -p`). Überprüfe die erwartete Byteanzahl und erfasse vor der Analyse einen Hash:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk erkennt anschließend bekannte Signaturen in der rekonstruierten Binärdatei. Ein direktes Auslesen des Flash-Speichers über die passende SPI-/eMMC-/NAND-Schnittstelle ist normalerweise schneller und weniger fehleranfällig, wenn die Konsole Daten nicht zuverlässig übertragen kann.

U-Boot kann das Unterbrechen des Bootvorgangs deaktivieren, eine herstellerspezifische Tastenkombination erfordern oder Speicher-/Flash-Befehle sperren. Orientiere dich an der Autoboot-Eingabeaufforderung und dem Boot-Log, anstatt blind Zeichen zu senden. Wenn sich die Konsole nicht unterbrechen lässt, sichere das Boot-Log und wechsle zu einem nicht-invasiven Verfahren zur Firmware-Erfassung.

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate-Dokumentation - UART-Modus und elektrische Grenzwerte](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - Datenblatt des CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot-Dokumentation - Speicheranzeigebefehl `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI und Hardware-Instrumentierung für Reverse Engineers, Teil 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000-Programmierhandbuch](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Backend konfigurieren](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — Hardware Hacking auffrischen, Teil 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
