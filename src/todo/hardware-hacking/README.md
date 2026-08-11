# Hardware-Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) unterstützt Boundary-Scan-Tests durch Zellen, die um die I/O-Pins eines Geräts angeordnet sind. Viele Prozessoren stellen über denselben Test Access Port (TAP) außerdem herstellerspezifische Debug-Funktionen bereit; Boundary Scan und CPU-Debugging sind verwandte Anwendungsbereiche von JTAG, aber keine Synonyme.<sup>[[1]](#references)</sup>

Der JTAG-Standard definiert **spezifische Befehle zur Durchführung von Boundary Scans**, darunter:

- **BYPASS** wählt ein Ein-Bit-Bypass-Register aus, sodass andere Geräte in einer Scan-Kette mit minimalem Overhead erreicht werden können.
- **SAMPLE/PRELOAD** erfasst Pin-Werte während des normalen Betriebs und kann das Boundary-Scan-Register vor einer anderen Instruktion vorladen.
- **EXTEST** setzt Pin-Zustände und liest sie aus.

Außerdem werden weitere Befehle unterstützt, zum Beispiel:

- **IDCODE** zur Identifizierung eines Geräts
- **INTEST** zum internen Testen des Geräts

Diese Instruktionen können dir begegnen, wenn du ein Tool wie den JTAGulator verwendest.

### Der Test Access Port

Der **Test Access Port (TAP)** ermöglicht den Zugriff auf die JTAG-Testlogik einer Komponente. Vier Signale sind erforderlich, und `TRST` ist optional:<sup>[[1]](#references)</sup>

- Eingang für den Testtakt (**TCK**) TCK ist der **Takt**, der festlegt, wie oft der TAP-Controller eine einzelne Aktion ausführt (also zum nächsten Zustand in der Zustandsmaschine wechselt).
- Eingang für die Auswahl des Testmodus (**TMS**) TMS steuert die **endliche Zustandsmaschine**. Bei jedem Taktsignal prüft der JTAG-TAP-Controller des Geräts die Spannung am TMS-Pin. Liegt die Spannung unter einem bestimmten Schwellenwert, wird das Signal als Low betrachtet und als 0 interpretiert. Liegt die Spannung über einem bestimmten Schwellenwert, wird das Signal als High betrachtet und als 1 interpretiert.
- Eingang für Testdaten (**TDI**) verschiebt serielle Instruktionen oder Testdaten in das ausgewählte TAP-Register. IEEE 1149.1 definiert das TAP-Übertragungsverhalten, während die Hersteller optionale Instruktionen und Debug-Register definieren.
- Ausgang für Testdaten (**TDO**) TDO ist der Pin, der **Daten aus dem Chip heraus** sendet.
- Eingang für den Test-Reset (**TRST**) Der optionale TRST setzt die endliche Zustandsmaschine **auf einen bekannten, funktionierenden Zustand** zurück. Alternativ löst das Halten von TMS auf 1 für fünf aufeinanderfolgende Taktzyklen einen Reset aus, genauso wie der TRST-Pin. Deshalb ist TRST optional.

Manchmal findest du diese Pins markiert auf der PCB. In anderen Fällen musst du sie **finden**.

### JTAG-Pins identifizieren

Eine schnelle, speziell dafür entwickelte, aber vergleichsweise teure Option zur Erkennung von JTAG-Ports ist der **JTAGulator**, der auch UART-Pinouts identifizieren kann.<sup>[[2]](#references)</sup>

Er verfügt über **24 Kanäle**, die mit Testpunkten auf der Platine verbunden werden können. Er listet mögliche Pin-Kombinationen mithilfe von **IDCODE**- und **BYPASS**-Scans auf und meldet die Kanäle, die den erkannten JTAG-Signalen entsprechen.

Eine günstigere, aber deutlich langsamere Methode zur Identifizierung von JTAG-Pinouts ist die Verwendung von [**JTAGenum**](https://github.com/cyphunk/JTAGenum/), das auf einem Arduino-kompatiblen Mikrocontroller geladen wird.

Mit **JTAGenum** definierst du zunächst die Pins des sondierenden Mikrocontrollers, die für die Enumeration verwendet werden. Orientiere dich an dessen Pinout und verbinde diese Pins anschließend mit möglichen Testpunkten auf der Zielplatine.<sup>[[3]](#references)</sup>

Eine **dritte Möglichkeit**, JTAG-Pins zu identifizieren, besteht darin, die **PCB** auf ein bekanntes Footprint zu untersuchen. Einige Platinen verfügen über ein **Tag-Connect**-Footprint. Tag-Connect ist jedoch ein Steckverbindersystem, das JTAG, SWD, UART oder eine andere Schnittstelle übertragen kann – allein daraus folgt nicht, dass es sich bei den Pins um JTAG handelt. Datenblätter der Komponenten und Durchgangsmessungen können anschließend die tatsächlichen Signale identifizieren.<sup>[[5]](#references)</sup>

## SDW

SWD ist Arm's zweipolige, paketbasierte Debug-Schnittstelle.<sup>[[4]](#references)</sup>

Die Schnittstelle verwendet **SWDIO** bidirektional für Daten und **SWCLK** für den Takt. Viele Geräte implementieren einen **Serial Wire/JTAG Debug Port (SWJ-DP)**, der die Auswahl zwischen SWD und JTAG über gemeinsam genutzte Pins ermöglicht.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1-Arbeitsgruppe — JTAG und Boundary Scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator-Dokumentation](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino-JTAG-Pin-Enumeration](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug-Schnittstellen mit geringer Pin-Anzahl für Systeme mit mehreren Geräten](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints für Debugging- und Programmierkabel](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
