# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Einführung <a href="#introduction" id="introduction"></a>

Flipper Zero kann mit seinem integrierten Modul **Funkfrequenzen im Bereich von 300-928 MHz empfangen und übertragen**, vorbehaltlich der Frequenzbeschränkungen für die konfigurierte Region. Es kann kompatible Fernbedienungen für Tore, Schranken, Funkschlösser, Schalter, kabellose Türklingeln, intelligente Leuchten und andere Geräte auslesen, speichern und emulieren.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz-Hardware <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero verfügt über ein integriertes Sub-1-GHz-Modul auf Basis eines CC1101-Transceivers und einer Funkantenne. Die tatsächliche Reichweite hängt von der Frequenz, der Antenne, der Umgebung und dem Sender ab. Flipper dokumentiert unter günstigen Bedingungen eine Reichweite von etwa 50 Metern. Die Hardware deckt 300-348 MHz, 387-464 MHz und 779-928 MHz ab, während Firmware und regionale Vorschriften die Übertragung zusätzlich einschränken.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Frequenzanalysator

> [!TIP]
> So findest du heraus, welche Frequenz die Fernbedienung verwendet

Bei der Analyse scannt Flipper Zero die Signalstärke (RSSI) auf allen in der Frequenzkonfiguration verfügbaren Frequenzen. Flipper Zero zeigt die Frequenz mit dem höchsten RSSI-Wert und einer Signalstärke von mehr als -90 [dBm](https://en.wikipedia.org/wiki/DBm) an.<sup>[[1]](#references)</sup>

Gehe wie folgt vor, um die Frequenz der Fernbedienung zu bestimmen:

1. Platziere die Fernbedienung sehr nah links neben Flipper Zero.
2. Gehe zu **Main Menu** **→ Sub-GHz**.
3. Wähle **Frequency Analyzer** und halte anschließend die Taste der zu analysierenden Fernbedienung gedrückt.
4. Überprüfe den Frequenzwert auf dem Bildschirm.

### Read

> [!TIP]
> Informationen über die verwendete Frequenz finden (auch eine weitere Möglichkeit, die verwendete Frequenz zu bestimmen)

Die Option **Read** hört auf der konfigurierten Frequenz und Modulation (standardmäßig 433.92 MHz AM). Wenn ein unterstütztes Signal erkannt wird, zeigt der Bildschirm Informationen an, die später gespeichert und wiedergegeben werden können.<sup>[[1]](#references)</sup>

Während **Read** verwendet wird, kann die **linke Taste** gedrückt und die Konfiguration **angepasst** werden.\
Derzeit stehen **4 Modulationen** (AM270, AM650, FM328 und FM476) sowie **mehrere relevante Frequenzen** zur Verfügung:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Du kannst jede zulässige Frequenz auswählen. Wenn du nicht sicher bist, welche Frequenz die Fernbedienung verwendet, aktiviere **Hopping** (standardmäßig deaktiviert) und drücke die Taste der Fernbedienung mehrmals, bis Flipper das Signal erfasst und die Frequenz meldet.

> [!CAUTION]
> Das Umschalten zwischen Frequenzen benötigt etwas Zeit. Daher können während des Umschaltens übertragene Signale verpasst werden. Für einen besseren Signalempfang solltest du eine feste, mit dem Frequency Analyzer bestimmte Frequenz einstellen.

### **Read Raw**

> [!TIP]
> Ein Signal auf der konfigurierten Frequenz stehlen (und wiedergeben)

Die Option **Read Raw** zeichnet auf der ausgewählten Frequenz gesendete Signale auf. Dies kann dazu verwendet werden, ein Signal während autorisierter Tests zu erfassen und wiederzugeben.<sup>[[1]](#references)</sup>

Standardmäßig verwendet **Read Raw ebenfalls 433.92 MHz mit AM650**. Wenn die Option Read ein Signal auf einer anderen Frequenz oder mit einer anderen Modulation gefunden hat, drücke innerhalb von Read Raw die linke Taste, um diese Einstellungen zu ändern.

### Brute-Force

Wenn du das von einem Gerät, beispielsweise einem Garagentor, verwendete Protokoll kennst, ist es möglicherweise möglich, **Kandidaten-Codes zu generieren und sie mit Flipper Zero zu übertragen**. Das Projekt `flipperzero-bruteforce` unterstützt mehrere verbreitete Protokolle mit statischen Codes.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Signale aus einer konfigurierten Protokollliste hinzufügen

#### Liste der unterstützten Protokolle <a href="#id-3iglu" id="id-3iglu"></a>

Das Menü Add Manually stellt die von Flipper Zero dokumentierten Protokollvoreinstellungen bereit.<sup>[[4]](#references)</sup>

| Princeton_433 (funktioniert mit der Mehrheit der Systeme mit statischen Codes) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Unterstützte Sub-GHz-Anbieter

Sieh dir die Liste der von Flipper Zero unterstützten Anbieter an.<sup>[[5]](#references)</sup>

### Unterstützte Frequenzen nach Region

Überprüfe vor der Übertragung die offizielle Liste der regionalen Frequenzen.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> dBm-Werte der gespeicherten Frequenzen abrufen

## References

- [1] [Sub-GHz - Benutzer documentation von Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Datenblatt Texas Instruments CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Eine manuell erstellte Fernbedienung hinzufügen](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Unterstützte Sub-GHz-Anbieter](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regionale Sub-GHz-Frequenzen](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
