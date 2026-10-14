# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

Bei einem Gerät mit physischem Zugriff solltest du mit den Schnittstellen beginnen, die seine Platine oder Signale bereitstellen: [UART-Seriellkonsolen](uart.md), [JTAG/SWD-Debug-Zugriff](jtag.md), [I²C](i2c.md) und [SPI-Flash](spi.md)-Busse. [Side-Channel-Analyse](side_channel_analysis.md) und [Fault Injection](fault_injection_attacks.md) befassen sich mit anderen Mess- und Glitching-Aufgaben; die [Analyse von Funksignalen](radio.md) behandelt einen drahtlosen Einstiegspunkt. Für zielgerätespezifische Verfahren zu RFID/NFC, Sub-GHz, Infrarot, BLE, LoRaWAN und iButton siehe [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Prüfe die elektrischen Pegel des Ziels und die Einschränkungen im jeweiligen Kapitel, bevor du Werkzeuge anschließt.

## JTAG

JTAG (IEEE 1149.1) unterstützt Boundary-Scan-Tests mithilfe von Zellen, die um die I/O-Pins eines Geräts angeordnet sind. Viele Prozessoren stellen über denselben Test Access Port (TAP) außerdem herstellerspezifische Debug-Funktionen bereit; Boundary Scan und CPU-Debugging sind verwandte Einsatzbereiche von JTAG, aber keine Synonyme.<sup>[[1]](#references)</sup>

Der JTAG-Standard definiert **spezielle Befehle zur Durchführung von Boundary Scans**, darunter:

- **BYPASS** wählt ein ein Bit breites Bypass-Register aus, sodass andere Geräte in einer Scan-Kette mit minimalem Zusatzaufwand erreicht werden können.
- **SAMPLE/PRELOAD** erfasst Pin-Werte während des normalen Betriebs und kann das Boundary-Scan-Register vor einer anderen Anweisung vorladen.
- **EXTEST** setzt und liest Pin-Zustände.

Außerdem werden weitere Befehle unterstützt, zum Beispiel:

- **IDCODE** zur Identifizierung eines Geräts
- **INTEST** zum internen Testen des Geräts

Diese Anweisungen können dir bei der Verwendung eines Tools wie dem JTAGulator begegnen.

### Der Test Access Port

Der **Test Access Port (TAP)** ermöglicht den Zugriff auf die JTAG-Testlogik einer Komponente. Vier Signale sind erforderlich, `TRST` ist optional:<sup>[[1]](#references)</sup>

- Takteingang (**TCK**) TCK ist der **Takt**, der festlegt, wie oft der TAP-Controller eine Aktion ausführt (also zum nächsten Zustand in der Zustandsmaschine wechselt).
- Eingang zur Auswahl des Testmodus (**TMS**) TMS steuert die **endliche Zustandsmaschine**. Bei jedem Taktschlag prüft der JTAG-TAP-Controller des Geräts die Spannung am TMS-Pin. Liegt die Spannung unter einem bestimmten Schwellenwert, gilt das Signal als Low und wird als 0 interpretiert. Liegt sie über einem bestimmten Schwellenwert, gilt es als High und wird als 1 interpretiert.
- Testdateneingang (**TDI**) Über TDI werden serielle Anweisungen oder Testdaten in das ausgewählte TAP-Register geschoben. IEEE 1149.1 definiert das Übertragungsverhalten des TAP; optionale Anweisungen und Debug-Register werden von den Herstellern festgelegt.
- Testdatenausgang (**TDO**) TDO ist der Pin, über den **Daten aus dem Chip ausgegeben werden**.
- Test-Reset-Eingang (**TRST**) Der optionale TRST setzt die endliche Zustandsmaschine **auf einen bekannten, funktionsfähigen Zustand** zurück. Alternativ wird ein Reset ausgelöst, wenn TMS fünf aufeinanderfolgende Taktzyklen lang auf 1 gehalten wird. Das funktioniert wie ein Reset über den TRST-Pin, weshalb TRST optional ist.

Manchmal sind diese Pins auf der Platine markiert. In anderen Fällen musst du sie **finden**.

### JTAG-Pins identifizieren

Eine schnelle, speziell dafür entwickelte, aber vergleichsweise teure Möglichkeit, JTAG-Ports zu erkennen, ist der **JTAGulator**, der auch UART-Pinbelegungen identifizieren kann.<sup>[[2]](#references)</sup>

Er verfügt über **24 Kanäle**, die mit Testpunkten auf der Platine verbunden werden können. Er prüft mögliche Pin-Kombinationen mithilfe von **IDCODE**- und **BYPASS**-Scans und meldet die Kanäle, die den erkannten JTAG-Signalen entsprechen.

Eine günstigere, aber deutlich langsamere Methode zur Identifizierung von JTAG-Pinbelegungen ist die Verwendung von [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) auf einem Arduino-kompatiblen Mikrocontroller.

Bei **JTAGenum** legst du zunächst die Pins des Probe-Mikrocontrollers fest, die für die Erkennung verwendet werden. Sieh dir dessen Pinbelegung an und verbinde diese Pins anschließend mit möglichen Testpunkten auf der Zielplatine.<sup>[[3]](#references)</sup>

Eine **dritte Möglichkeit**, JTAG-Pins zu identifizieren, ist die **Untersuchung der Platine** auf einen bekannten Footprint. Manche Platinen haben einen **Tag-Connect**-Footprint. Tag-Connect ist jedoch ein Steckverbindersystem, das JTAG, SWD, UART oder eine andere Schnittstelle übertragen kann – der Footprint allein beweist also nicht, dass es sich um JTAG-Pins handelt. Datenblätter der Komponenten und Durchgangsmessungen können anschließend helfen, die tatsächlichen Signale zu identifizieren.<sup>[[5]](#references)</sup>

## SDW

SWD ist Arm's zweipolige, paketbasierte Debug-Schnittstelle.<sup>[[4]](#references)</sup>

Die Schnittstelle verwendet **SWDIO** bidirektional für Daten und **SWCLK** für den Takt. Viele Geräte implementieren einen **Serial Wire/JTAG Debug Port (SWJ-DP)**, über den zwischen SWD und JTAG auf gemeinsam genutzten Pins gewählt werden kann.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1-Arbeitsgruppe — JTAG und Boundary Scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator-Dokumentation](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Ermittlung der Arduino-JTAG-Pins](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug-Schnittstellen mit wenigen Pins für Systeme mit mehreren Geräten](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints für Debug- und Programmierkabel](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
