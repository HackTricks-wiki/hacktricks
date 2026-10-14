# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Einführung <a href="#introduction" id="introduction"></a>

Flipper Zero kann mit seinem integrierten Modul **Radiofrequenzen im Bereich von 300–928 MHz empfangen und senden**. Dabei gelten die Frequenzbeschränkungen der konfigurierten Region. Das Gerät kann kompatible Fernbedienungen für Tore, Schranken, Funkschlösser, Schalter, drahtlose Türklingeln, intelligente Beleuchtung und andere Geräte auslesen, speichern und emulieren.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz-Hardware <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero verfügt über ein integriertes Sub-1-GHz-Modul mit einem CC1101-Transceiver und einer Funkantenne. Die tatsächliche Reichweite hängt von Frequenz, Antenne, Umgebung und Sender ab. Flipper gibt unter günstigen Bedingungen eine Reichweite von bis zu etwa 50 Metern an. Die Hardware deckt 300–348 MHz, 387–464 MHz und 779–928 MHz ab; Firmware und regionale Vorschriften schränken die Übertragung zusätzlich ein.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Frequency Analyzer

> [!TIP]
> So findest du heraus, welche Frequenz die Fernbedienung verwendet

Bei der Analyse scannt Flipper Zero die Signalstärke (RSSI) auf allen Frequenzen, die in der Frequenzkonfiguration verfügbar sind. Flipper Zero zeigt die Frequenz mit dem höchsten RSSI-Wert an, sofern die Signalstärke über -90 [dBm](https://en.wikipedia.org/wiki/DBm) liegt.<sup>[[1]](#references)</sup>

So bestimmst du die Frequenz der Fernbedienung:

1. Halte die Fernbedienung sehr nah an die linke Seite des Flipper Zero.
2. Gehe zu **Main Menu** **→ Sub-GHz**.
3. Wähle **Frequency Analyzer** und halte dann die Taste auf der Fernbedienung gedrückt, die du analysieren möchtest.
4. Lies den Frequenzwert auf dem Bildschirm ab.

### Read

> [!TIP]
> Finde Informationen zur verwendeten Frequenz (oder ermittle sie auf andere Weise)

Die Option **Read** lauscht auf der konfigurierten Frequenz und Modulation (standardmäßig 433,92 MHz AM). Wenn ein unterstütztes Signal erkannt wird, zeigt der Bildschirm Informationen an, die gespeichert und später erneut abgespielt werden können.<sup>[[1]](#references)</sup>

Während Read aktiv ist, kannst du die **linke Taste** drücken und die Einstellungen **konfigurieren**.\
Derzeit gibt es **4 Modulationen** (AM270, AM650, FM328 und FM476) sowie **mehrere relevante Frequenzen**:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Du kannst jede zulässige Frequenz auswählen. Wenn du nicht weißt, welche Frequenz die Fernbedienung verwendet, aktiviere **Hopping** (standardmäßig deaktiviert) und drücke dann mehrmals die Taste der Fernbedienung, bis Flipper das Signal erfasst und die Frequenz anzeigt.

> [!CAUTION]
> Der Wechsel zwischen Frequenzen dauert eine gewisse Zeit. Daher können Signale verpasst werden, die während des Wechsels gesendet werden. Für einen besseren Signalempfang solltest du eine mit Frequency Analyzer ermittelte feste Frequenz einstellen.

### **Read Raw**

> [!TIP]
> Ein Signal auf der konfigurierten Frequenz abfangen (und erneut abspielen)

Die Option **Read Raw** zeichnet Signale auf, die auf der ausgewählten Frequenz gesendet werden. Damit kann bei autorisierten Tests ein Signal aufgezeichnet und erneut abgespielt werden.<sup>[[1]](#references)</sup>

Standardmäßig verwendet **Read Raw ebenfalls 433,92 MHz mit AM650**. Wenn die Option Read ein Signal auf einer anderen Frequenz oder mit einer anderen Modulation gefunden hat, drücke in Read Raw die linke Taste, um diese Einstellungen zu ändern.

### Brute-Force

Wenn du das von einem Gerät wie einem Garagentor verwendete Protokoll kennst, kannst du möglicherweise **Kandidatencodes erzeugen und mit Flipper Zero übertragen**. Das Projekt `flipperzero-bruteforce` unterstützt mehrere verbreitete Protokolle mit statischen Codes.<sup>[[3]](#references)</sup>

### Manuell hinzufügen

> [!TIP]
> Signale aus einer konfigurierten Protokollliste hinzufügen

#### Liste unterstützter Protokolle <a href="#id-3iglu" id="id-3iglu"></a>

Das Menü „Add Manually“ zeigt die von Flipper Zero dokumentierten Protokollvoreinstellungen an.<sup>[[4]](#references)</sup>

| Princeton_433 (funktioniert mit den meisten Systemen mit statischem Code) | 433.92 | Statisch |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Statisch |
| Nice Flo 24bit_433                                             | 433.92 | Statisch |
| CAME 12bit_433                                                 | 433.92 | Statisch |
| CAME 24bit_433                                                 | 433.92 | Statisch |
| Linear_300                                                     | 300.00 | Statisch |
| CAME TWEE                                                      | 433.92 | Statisch |
| Gate TX_433                                                    | 433.92 | Statisch |
| DoorHan_315                                                    | 315.00 | Dynamisch |
| DoorHan_433                                                    | 433.92 | Dynamisch |
| LiftMaster_315                                                 | 315.00 | Dynamisch |
| LiftMaster_390                                                 | 390.00 | Dynamisch |
| Security+2.0_310                                               | 310.00 | Dynamisch |
| Security+2.0_315                                               | 315.00 | Dynamisch |
| Security+2.0_390                                               | 390.00 | Dynamisch |

### Unterstützte Sub-GHz-Anbieter

Siehe die Liste der von Flipper Zero unterstützten Anbieter.<sup>[[5]](#references)</sup>

### Unterstützte Frequenzen nach Region

Prüfe vor dem Senden die offizielle Liste der regionalen Frequenzen.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> dBm-Werte der gespeicherten Frequenzen anzeigen

## References

- [1] [Sub-GHz – Benutzerhandbuch für Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Datenblatt zum Texas Instruments CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero – Eine manuell erstellte Fernbedienung hinzufügen](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero – Unterstützte Sub-GHz-Anbieter](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero – Regionale Sub-GHz-Frequenzen](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
