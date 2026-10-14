# Hardware-Hacking

{{#include ../../banners/hacktricks-training.md}}

Bei einem Gerät, auf das du physischen Zugriff hast, solltest du mit den Schnittstellen beginnen, die über die Platine oder Signale zugänglich sind: [serielle UART-Konsolen](uart.md), [JTAG/SWD-Debug-Zugriff](jtag.md), [I²C](i2c.md) und [SPI-Flash](spi.md)-Busse. [Side-Channel-Analyse](side_channel_analysis.md) und [Fault Injection](fault_injection_attacks.md) dienen anderen Mess- und Glitching-Aufgaben; die [Analyse von Funksignalen](radio.md) behandelt einen drahtlosen Einstiegspunkt. Prüfe die elektrischen Pegel des Ziels und die Einschränkungen im jeweiligen Kapitel, bevor du Tools anschließt.

## JTAG

JTAG (IEEE 1149.1) unterstützt Boundary-Scan-Tests mithilfe von Zellen, die um die I/O-Pins eines Geräts angeordnet sind. Viele Prozessoren stellen über denselben Test Access Port (TAP) außerdem herstellerspezifische Debug-Funktionen bereit; Boundary Scan und CPU-Debugging sind verwandte Anwendungen von JTAG, aber keine Synonyme.<sup>[[1]](#references)</sup>

Der JTAG-Standard definiert **spezielle Befehle zur Durchführung von Boundary Scans**, darunter:

- **BYPASS** wählt ein ein Bit breites Bypass-Register aus, sodass andere Geräte in einer Scan-Kette mit minimalem Aufwand erreicht werden können.
- **SAMPLE/PRELOAD** erfasst während des normalen Betriebs Pin-Werte und kann das Boundary-Scan-Register vor einer anderen Anweisung vorladen.
- **EXTEST** setzt Pin-Zustände und liest sie aus.

JTAG kann auch andere Befehle unterstützen, zum Beispiel:

- **IDCODE** zur Identifizierung eines Geräts
- **INTEST** zum internen Testen des Geräts

Diese Anweisungen können dir begegnen, wenn du ein Tool wie den JTAGulator verwendest.

### Der Test Access Port

Der **Test Access Port (TAP)** ermöglicht den Zugriff auf die JTAG-Testlogik einer Komponente. Vier Signale sind erforderlich; `TRST` ist optional:<sup>[[1]](#references)</sup>

- Takteingang (**TCK**) TCK ist der **Takt**, der festlegt, wie oft der TAP-Controller eine Aktion ausführt (mit anderen Worten: zum nächsten Zustand in der Zustandsmaschine springt).
- Eingang zur Auswahl des Testmodus (**TMS**) TMS steuert die **endliche Zustandsmaschine**. Bei jedem Taktschlag prüft der JTAG-TAP-Controller des Geräts die Spannung am TMS-Pin. Liegt die Spannung unter einem bestimmten Schwellenwert, gilt das Signal als niedrig und wird als 0 interpretiert. Liegt sie über einem bestimmten Schwellenwert, gilt das Signal als hoch und wird als 1 interpretiert.
- Testdateneingang (**TDI**) Über TDI werden serielle Anweisungen oder Testdaten in das ausgewählte TAP-Register geschoben. IEEE 1149.1 definiert das TAP-Übertragungsverhalten, während Hersteller optionale Anweisungen und Debug-Register festlegen.
- Testdatenausgang (**TDO**) TDO ist der Pin, über den **Daten aus dem Chip ausgegeben werden**.
- Test-Reset-Eingang (**TRST**) Der optionale TRST setzt die endliche Zustandsmaschine **auf einen bekannten, sicheren Zustand** zurück. Alternativ löst TMS einen Reset aus, wenn es fünf aufeinanderfolgende Taktzyklen lang auf 1 gehalten wird. Das funktioniert genauso wie über den TRST-Pin, weshalb TRST optional ist.

Manchmal sind diese Pins auf der Platine gekennzeichnet. In anderen Fällen musst du sie **finden**.

### JTAG-Pins identifizieren

Eine schnelle, speziell dafür entwickelte, aber vergleichsweise teure Möglichkeit, JTAG-Ports zu erkennen, ist der **JTAGulator**, der auch UART-Pinbelegungen identifizieren kann.<sup>[[2]](#references)</sup>

Er verfügt über **24 Kanäle**, die mit Testpunkten auf der Platine verbunden werden können. Er zählt mögliche Pin-Kombinationen mithilfe von **IDCODE**- und **BYPASS**-Scans auf und meldet die Kanäle, die den erkannten JTAG-Signalen entsprechen.

Eine günstigere, aber deutlich langsamere Methode, JTAG-Pinbelegungen zu identifizieren, ist die Verwendung von [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) auf einem Arduino-kompatiblen Mikrocontroller.

Bei **JTAGenum** musst du zunächst die Pins des abfragenden Mikrocontrollers festlegen, die für die Aufzählung verwendet werden. Sieh dir dessen Pinbelegung an und verbinde die Pins anschließend mit möglichen Testpunkten auf der Zielplatine.<sup>[[3]](#references)</sup>

Eine **dritte Möglichkeit**, JTAG-Pins zu identifizieren, besteht darin, die **Platine auf einen bekannten Footprint zu untersuchen**. Manche Platinen verfügen über einen **Tag-Connect**-Footprint. Tag-Connect ist jedoch ein Verbindungssystem, über das JTAG, SWD, UART oder eine andere Schnittstelle übertragen werden kann – der Footprint allein beweist also nicht, dass es sich bei den Pins um JTAG handelt. Die tatsächlichen Signale lassen sich anschließend anhand von Komponentendatenblättern und Durchgangsmessungen ermitteln.<sup>[[5]](#references)</sup>

## SDW

SWD ist die paketbasierte Debug-Schnittstelle von Arm mit zwei Pins.<sup>[[4]](#references)</sup>

Die Schnittstelle verwendet **SWDIO** bidirektional für Daten und **SWCLK** für den Takt. Viele Geräte implementieren einen **Serial Wire/JTAG Debug Port (SWJ-DP)**, der die Auswahl zwischen SWD und JTAG auf gemeinsam genutzten Pins ermöglicht.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE-1149.1-Arbeitsgruppe — JTAG und Boundary Scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator-Dokumentation](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino-JTAG-Pin-Aufzählung](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug-Schnittstellen mit geringer Pin-Anzahl für Systeme mit mehreren Geräten](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints für Debug- und Programmierschnittstellenkabel](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
