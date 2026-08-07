# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG ermöglicht die Durchführung eines Boundary-Scans. Der Boundary-Scan analysiert bestimmte Schaltungen, einschließlich eingebetteter Boundary-Scan-Zellen und Register für jeden Pin.

Der JTAG-Standard definiert **spezifische Befehle zur Durchführung von Boundary-Scans**, darunter:

- **BYPASS** ermöglicht es, einen bestimmten Chip zu testen, ohne den Overhead zu haben, andere Chips zu durchlaufen.
- **SAMPLE/PRELOAD** erstellt eine Stichprobe der Daten, die das Gerät im normalen Betriebsmodus erreichen und verlassen.
- **EXTEST** setzt Pin-Zustände und liest sie aus.

Außerdem können weitere Befehle unterstützt werden, beispielsweise:

- **IDCODE** zur Identifizierung eines Geräts
- **INTEST** zum internen Testen des Geräts

Diese Anweisungen können dir begegnen, wenn du ein Tool wie den JTAGulator verwendest.

### Der Test Access Port

Boundary-Scans umfassen Tests des vieradrigen **Test Access Port (TAP)**, eines universell einsetzbaren Ports, der **Zugriff auf die in einer Komponente integrierten JTAG-Testunterstützungsfunktionen** ermöglicht. TAP verwendet die folgenden fünf Signale:

- Test clock input (**TCK**) TCK ist der **Takt**, der festlegt, wie oft der TAP-Controller eine einzelne Aktion ausführt (also zum nächsten Zustand in der Zustandsmaschine springt).
- Test mode select (**TMS**) input TMS steuert die **finite state machine**. Bei jedem Takt prüft der JTAG-TAP-Controller des Geräts die Spannung am TMS-Pin. Liegt die Spannung unter einem bestimmten Schwellenwert, wird das Signal als niedrig betrachtet und als 0 interpretiert. Liegt die Spannung über einem bestimmten Schwellenwert, wird das Signal als hoch betrachtet und als 1 interpretiert.
- Test data input (**TDI**) TDI ist der Pin, der **Daten über die Scan-Zellen in den Chip sendet**. Jeder Hersteller ist dafür verantwortlich, das Kommunikationsprotokoll über diesen Pin zu definieren, da JTAG dies nicht festlegt.
- Test data output (**TDO**) TDO ist der Pin, der **Daten aus dem Chip heraus sendet**.
- Test reset (**TRST**) input Der optionale TRST setzt die finite state machine **auf einen bekannten, funktionierenden Zustand** zurück. Alternativ wird ein Reset ausgelöst, wenn TMS fünf aufeinanderfolgende Taktzyklen lang auf 1 gehalten wird, und zwar auf dieselbe Weise wie über den TRST-Pin. Daher ist TRST optional.

Manchmal findest du diese Pins auf der PCB markiert. In anderen Fällen musst du sie **finden**.

### JTAG-Pins identifizieren

Die schnellste, aber teuerste Möglichkeit, JTAG-Ports zu erkennen, besteht in der Verwendung des **JTAGulator**, eines speziell für diesen Zweck entwickelten Geräts (das **auch UART-Pinouts erkennen kann**).

Es verfügt über **24 Kanäle**, die du mit den Pins der Platine verbinden kannst. Anschließend führt es einen **BF-Angriff** auf alle möglichen Kombinationen durch und sendet Boundary-Scan-Befehle wie **IDCODE** und **BYPASS**. Wenn es eine Antwort erhält, zeigt es den Kanal an, der jedem JTAG-Signal entspricht.

Eine günstigere, aber deutlich langsamere Möglichkeit, JTAG-Pinouts zu identifizieren, besteht darin, [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) auf einem Arduino-kompatiblen Mikrocontroller zu laden.

Mit **JTAGenum** würdest du zunächst **die Pins des für die Enumeration verwendeten** Probe-Geräts **definieren**. Du müsstest den Pinout-Schaltplan des Geräts heranziehen und diese Pins anschließend mit den Testpunkten deines Zielgeräts verbinden.

Eine **dritte Möglichkeit**, JTAG-Pins zu identifizieren, besteht darin, die **PCB** auf eines der Pinouts zu untersuchen. In manchen Fällen verfügen PCBs praktischerweise über das **Tag-Connect interface**, was eindeutig darauf hindeutet, dass die Platine ebenfalls über einen JTAG-Anschluss verfügt. Unter [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) kannst du sehen, wie dieses Interface aussieht. Außerdem können bei der Untersuchung der **Datenblätter der auf der PCB befindlichen Chipsätze** Pinout-Diagramme gefunden werden, die auf JTAG-Interfaces hinweisen.

## SDW

SWD ist ein ARM-spezifisches Protokoll, das für Debugging entwickelt wurde.

Das SWD-Interface benötigt **zwei Pins**: ein bidirektionales **SWDIO**-Signal, das dem **TDI- und TDO-Pin sowie dem Takt** von JTAG entspricht, und **SWCLK**, das dem **TCK** bei JTAG entspricht. Viele Geräte unterstützen den **Serial Wire or JTAG Debug Port (SWJ-DP)**, ein kombiniertes JTAG- und SWD-Interface, über das du entweder einen SWD- oder einen JTAG-Probe mit dem Zielgerät verbinden kannst.

{{#include ../../banners/hacktricks-training.md}}
