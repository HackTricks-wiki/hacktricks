# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG ermöglicht einen Boundary-Scan. Der Boundary-Scan analysiert bestimmte Schaltungen, einschließlich eingebetteter Boundary-Scan-Zellen und Register für jeden Pin.

Der JTAG-Standard definiert **spezifische Befehle für die Durchführung von Boundary-Scans**, einschließlich der folgenden:

- **BYPASS** ermöglicht es Ihnen, einen bestimmten Chip zu testen, ohne die anderen Chips zu durchlaufen.
- **SAMPLE/PRELOAD** nimmt eine Probe der Daten auf, die das Gerät im normalen Betriebsmodus betreten und verlassen.
- **EXTEST** setzt und liest den Zustand der Pins.

Es kann auch andere Befehle unterstützen, wie:

- **IDCODE** zur Identifizierung eines Geräts
- **INTEST** für die interne Prüfung des Geräts

Sie könnten auf diese Anweisungen stoßen, wenn Sie ein Tool wie den JTAGulator verwenden.

### Der Testzugangspunkt

Boundary-Scans umfassen Tests des vieradrigen **Test Access Port (TAP)**, einem universellen Port, der **Zugriff auf die JTAG-Testunterstützungs**funktionen bietet, die in ein Bauteil integriert sind. TAP verwendet die folgenden fünf Signale:

- Testtakt-Eingang (**TCK**) Der TCK ist der **Takt**, der definiert, wie oft der TAP-Controller eine einzelne Aktion ausführt (mit anderen Worten, zum nächsten Zustand in der Zustandsmaschine springt).
- Testmodus-Auswahl (**TMS**) Eingang TMS steuert die **endliche Zustandsmaschine**. Bei jedem Taktimpuls überprüft der JTAG TAP-Controller des Geräts die Spannung am TMS-Pin. Wenn die Spannung unter einem bestimmten Schwellenwert liegt, wird das Signal als niedrig betrachtet und als 0 interpretiert, während das Signal als hoch betrachtet und als 1 interpretiert wird, wenn die Spannung über einem bestimmten Schwellenwert liegt.
- Testdaten-Eingang (**TDI**) TDI ist der Pin, der **Daten in den Chip über die Scan-Zellen** sendet. Jeder Anbieter ist dafür verantwortlich, das Kommunikationsprotokoll über diesen Pin zu definieren, da JTAG dies nicht definiert.
- Testdaten-Ausgang (**TDO**) TDO ist der Pin, der **Daten aus dem Chip** sendet.
- Test-Reset (**TRST**) Eingang Der optionale TRST setzt die endliche Zustandsmaschine **in einen bekannten guten Zustand** zurück. Alternativ, wenn der TMS fünf aufeinanderfolgende Taktzyklen lang auf 1 gehalten wird, wird ein Reset ausgelöst, ähnlich wie es der TRST-Pin tun würde, weshalb TRST optional ist.

Manchmal können Sie diese Pins auf der PCB markiert finden. In anderen Fällen müssen Sie sie **finden**.

### Identifizierung von JTAG-Pins

Der schnellste, aber teuerste Weg, JTAG-Ports zu erkennen, ist die Verwendung des **JTAGulator**, eines Geräts, das speziell für diesen Zweck entwickelt wurde (obwohl es **auch UART-Pinouts erkennen kann**).

Es hat **24 Kanäle**, die Sie mit den Pins der Platine verbinden können. Dann führt es einen **BF-Angriff** auf alle möglichen Kombinationen durch, indem es **IDCODE** und **BYPASS** Boundary-Scan-Befehle sendet. Wenn es eine Antwort erhält, zeigt es den Kanal an, der jedem JTAG-Signal entspricht.

Ein günstigerer, aber viel langsamerer Weg zur Identifizierung von JTAG-Pinouts ist die Verwendung von [**JTAGenum**](https://github.com/cyphunk/JTAGenum/), das auf einem Arduino-kompatiblen Mikrocontroller geladen ist.

Mit **JTAGenum** würden Sie zuerst **die Pins des Prüfgeräts definieren**, das Sie für die Enumeration verwenden werden. Sie müssten das Pinout-Diagramm des Geräts konsultieren und dann diese Pins mit den Testpunkten Ihres Zielgeräts verbinden.

Ein **dritter Weg**, um JTAG-Pins zu identifizieren, besteht darin, die **PCB zu inspizieren** und nach einem der Pinouts zu suchen. In einigen Fällen bieten PCBs möglicherweise bequem die **Tag-Connect-Schnittstelle**, was ein klarer Hinweis darauf ist, dass die Platine auch einen JTAG-Anschluss hat. Sie können sehen, wie diese Schnittstelle aussieht unter [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Darüber hinaus könnte die Inspektion der **Datenblätter der Chipsätze auf der PCB** Pinout-Diagramme offenbaren, die auf JTAG-Schnittstellen hinweisen.

## SDW

SWD ist ein ARM-spezifisches Protokoll, das für das Debugging entwickelt wurde.

Die SWD-Schnittstelle benötigt **zwei Pins**: ein bidirektionales **SWDIO**-Signal, das dem JTAG-**TDI- und TDO-Pin** entspricht, und einen Takt, **SWCLK**, der dem **TCK** in JTAG entspricht. Viele Geräte unterstützen den **Serial Wire oder JTAG Debug Port (SWJ-DP)**, eine kombinierte JTAG- und SWD-Schnittstelle, die es Ihnen ermöglicht, entweder eine SWD- oder JTAG-Sonde mit dem Ziel zu verbinden.

{{#include ../../banners/hacktricks-training.md}}
