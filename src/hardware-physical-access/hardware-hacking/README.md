# Hardware-Hacking

{{#include ../../banners/hacktricks-training.md}}

Bei einem Gerät, auf das physischer Zugriff besteht, solltest du mit den Schnittstellen beginnen, die über die Platine oder Signale zugänglich sind: [serielle UART-Konsolen](uart.md), [JTAG/SWD-Debug-Zugriff](jtag.md), [CoreSight-Instruktionstracing](arm-coresight-instruction-tracing.md), [I²C](i2c.md) und [SPI-Flash](spi.md)-Busse. [Seitenkanalanalyse](side_channel_analysis.md) und [Fault Injection](fault_injection_attacks.md) betreffen andere Mess- und Glitching-Aufgaben; [Funksignalanalyse](radio.md) behandelt einen Einstiegspunkt über Funk. Für zielgerätespezifische Verfahren zu RFID/NFC, Sub-GHz, Infrarot, BLE, LoRaWAN und iButton verwende [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Prüfe die elektrischen Pegel des Ziels und die Einschränkungen im jeweiligen Kapitel, bevor du Tools anschließt.

## JTAG

JTAG (IEEE 1149.1) unterstützt Boundary-Scan-Tests mithilfe von Zellen, die um die I/O-Pins eines Geräts angeordnet sind. Viele Prozessoren stellen über denselben Test Access Port (TAP) auch herstellerspezifische Debug-Funktionen bereit; Boundary Scan und CPU-Debugging sind verwandte Einsatzmöglichkeiten von JTAG, aber keine Synonyme.<sup>[[1]](#references)</sup>

Der JTAG-Standard definiert **spezifische Befehle zur Durchführung von Boundary-Scans**, darunter:

- **BYPASS** wählt ein ein Bit breites Bypass-Register aus, damit andere Geräte in einer Scan-Kette mit minimalem Aufwand erreicht werden können.
- **SAMPLE/PRELOAD** erfasst während des normalen Betriebs Pin-Werte und kann das Boundary-Scan-Register vor einer anderen Instruktion vorladen.
- **EXTEST** setzt und liest Pin-Zustände aus.

Außerdem können weitere Befehle unterstützt werden, etwa:

- **IDCODE** zur Identifizierung eines Geräts
- **INTEST** zum internen Testen des Geräts

Auf diese Instruktionen kannst du bei der Verwendung eines Tools wie dem JTAGulator stoßen.

### Der Test Access Port

Der **Test Access Port (TAP)** ermöglicht den Zugriff auf die JTAG-Testlogik einer Komponente. Vier Signale sind erforderlich, `TRST` ist optional:<sup>[[1]](#references)</sup>

- Takteingang (**TCK**) TCK ist der **Takt**, der festlegt, wie oft der TAP-Controller eine einzelne Aktion ausführt (also zum nächsten Zustand im Zustandsautomaten wechselt).
- Eingang zur Auswahl des Testmodus (**TMS**) TMS steuert den **Zustandsautomaten**. Bei jedem Taktimpuls prüft der JTAG-TAP-Controller des Geräts die Spannung am TMS-Pin. Liegt die Spannung unter einem bestimmten Schwellenwert, gilt das Signal als Low und wird als 0 interpretiert. Liegt sie über einem bestimmten Schwellenwert, gilt das Signal als High und wird als 1 interpretiert.
- Testdateneingang (**TDI**) Über TDI werden serielle Instruktionen oder Testdaten in das ausgewählte TAP-Register eingeschoben. IEEE 1149.1 definiert das Übertragungsverhalten des TAP, während Hersteller optionale Instruktionen und Debug-Register definieren.
- Testdatenausgang (**TDO**) TDO ist der Pin, über den **Daten aus dem Chip ausgegeben werden**.
- Test-Reset-Eingang (**TRST**) Der optionale TRST setzt den Zustandsautomaten **auf einen bekannten, funktionsfähigen Zustand** zurück. Alternativ löst TMS, wenn es fünf aufeinanderfolgende Taktzyklen lang auf 1 gehalten wird, einen Reset aus – genauso wie der TRST-Pin. Deshalb ist TRST optional.

Manchmal sind diese Pins auf der Platine beschriftet. Andernfalls musst du sie möglicherweise **finden**.

### JTAG-Pins identifizieren

Eine schnelle, speziell dafür entwickelte, aber vergleichsweise teure Möglichkeit, JTAG-Ports zu erkennen, ist der **JTAGulator**, der auch UART-Pinbelegungen identifizieren kann.<sup>[[2]](#references)</sup>

Er verfügt über **24 Kanäle**, die mit Testpunkten auf der Platine verbunden werden können. Er probiert mögliche Pin-Kombinationen mithilfe von **IDCODE**- und **BYPASS**-Scans aus und meldet die Kanäle, die den erkannten JTAG-Signalen entsprechen.

Eine günstigere, aber deutlich langsamere Möglichkeit, JTAG-Pinbelegungen zu identifizieren, ist **JTAGenum** auf einem Arduino-kompatiblen Mikrocontroller.

Bei **JTAGenum** legst du zuerst die Pins des Mikrocontrollers fest, die zur Enumeration verwendet werden. Sieh dir dessen Pinbelegung an und verbinde diese Pins anschließend mit möglichen Testpunkten auf der Zielplatine.<sup>[[3]](#references)</sup>

Eine **dritte Möglichkeit**, JTAG-Pins zu identifizieren, besteht darin, die **Platine** auf einen bekannten Footprint zu untersuchen. Einige Platinen verfügen über einen **Tag-Connect**-Footprint. Tag-Connect ist jedoch ein Steckverbindersystem, das JTAG, SWD, UART oder eine andere Schnittstelle übertragen kann – der Footprint allein beweist also nicht, dass es sich bei den Pins um JTAG handelt. Datenblätter der Komponenten und Durchgangsmessungen können anschließend helfen, die tatsächlichen Signale zu identifizieren.<sup>[[5]](#references)</sup>

## SDW

SWD ist die paketbasierte Debug-Schnittstelle von Arm mit zwei Pins.<sup>[[4]](#references)</sup>

Die Schnittstelle verwendet **SWDIO** bidirektional für Daten und **SWCLK** für den Takt. Viele Geräte implementieren einen **Serial Wire/JTAG Debug Port (SWJ-DP)**, der die Auswahl zwischen SWD und JTAG auf gemeinsam genutzten Pins ermöglicht.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE-1149.1-Arbeitsgruppe — JTAG und Boundary-Scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator-Dokumentation](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino-JTAG-Pin-Enumeration](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug-Schnittstellen mit geringer Pin-Anzahl für Systeme mit mehreren Geräten](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints für Debug- und Programmierkabel](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
