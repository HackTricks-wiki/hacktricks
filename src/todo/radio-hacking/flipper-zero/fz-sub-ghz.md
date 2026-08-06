# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Einführung <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero kann mit seinem integrierten Modul **Funkfrequenzen im Bereich von 300-928 MHz empfangen und senden**. Damit lassen sich Fernbedienungen auslesen, speichern und emulieren. Diese Fernbedienungen werden zur Interaktion mit Toren, Schranken, Funkschlössern, ferngesteuerten Schaltern, drahtlosen Türklingeln, Smart Lights und vielem mehr verwendet. Flipper Zero kann dir dabei helfen herauszufinden, ob deine Sicherheit kompromittiert wurde.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz-Hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero verfügt über ein integriertes Sub-1-GHz-Modul auf Basis eines [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101-Chips](https://www.ti.com/lit/ds/symlink/cc1101.pdf) sowie über eine Funkantenne (die maximale Reichweite beträgt 50 Meter). Sowohl der CC1101-Chip als auch die Antenne sind für den Betrieb in den Frequenzbändern 300-348 MHz, 387-464 MHz und 779-928 MHz ausgelegt.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Frequency Analyser

> [!TIP]
> So findest du heraus, welche Frequenz die Fernbedienung verwendet

Bei der Analyse scannt Flipper Zero die Signalstärke (RSSI) auf allen in der Frequenzkonfiguration verfügbaren Frequenzen. Flipper Zero zeigt die Frequenz mit dem höchsten RSSI-Wert und einer Signalstärke von mehr als -90 [dBm](https://en.wikipedia.org/wiki/DBm) an.<sup>[[1]](#references)</sup>

Gehe wie folgt vor, um die Frequenz der Fernbedienung zu bestimmen:

1. Halte die Fernbedienung ganz nah links neben Flipper Zero.
2. Gehe zu **Main Menu** **→ Sub-GHz**.
3. Wähle **Frequency Analyzer** und halte anschließend die Taste auf der zu analysierenden Fernbedienung gedrückt.
4. Überprüfe den Frequenzwert auf dem Bildschirm.

### Read

> [!TIP]
> Informationen über die verwendete Frequenz finden (auch eine weitere Möglichkeit, die verwendete Frequenz zu bestimmen)

Die Option **Read** **lauscht auf der konfigurierten Frequenz** mit der angegebenen Modulation: standardmäßig 433.92 AM. Wenn beim Auslesen **etwas gefunden wird**, werden **Informationen** auf dem Bildschirm angezeigt. Diese Informationen können verwendet werden, um das Signal später zu replizieren.<sup>[[1]](#references)</sup>

Während **Read** verwendet wird, kann die **linke Taste** gedrückt und die Option **konfiguriert** werden.\
Derzeit stehen **4 Modulationen** (AM270, AM650, FM328 und FM476) sowie **mehrere relevante Frequenzen** zur Verfügung:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Du kannst **eine beliebige passende Option auswählen**. Wenn du jedoch **nicht sicher bist, welche Frequenz** von deiner Fernbedienung verwendet wird, aktiviere **Hopping** (standardmäßig deaktiviert) und drücke die Taste mehrmals, bis Flipper das Signal erfasst und dir die benötigten Informationen zum Einstellen der Frequenz liefert.

> [!CAUTION]
> Das Wechseln zwischen Frequenzen benötigt etwas Zeit. Daher können während des Wechsels übertragene Signale verpasst werden. Für einen besseren Signalempfang solltest du eine von Frequency Analyzer bestimmte feste Frequenz einstellen.

### **Read Raw**

> [!TIP]
> Ein Signal auf der konfigurierten Frequenz stehlen (und wiedergeben)

Die Option **Read Raw** **zeichnet Signale** auf, die auf der überwachten Frequenz gesendet werden. Damit kann ein Signal **gestohlen** und **wiederholt** werden.<sup>[[1]](#references)</sup>

Standardmäßig befindet sich **Read Raw ebenfalls auf 433.92 in AM650**. Wenn du jedoch mit der Option **Read** festgestellt hast, dass sich das gewünschte Signal auf einer **anderen Frequenz/Modulation befindet, kannst du dies ebenfalls ändern**, indem du innerhalb der Option **Read Raw** die linke Taste drückst.

### Brute-Force

Wenn du das von einem Garagentor verwendete Protokoll kennst, ist es beispielsweise möglich, **alle Codes zu generieren und mit Flipper Zero zu senden.** Dies ist ein Beispiel, das allgemeine gängige Garagentortypen unterstützt: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Signale aus einer konfigurierten Protokollliste hinzufügen

#### Liste der [unterstützten Protokolle](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (funktioniert mit der Mehrheit der Static-Code-Systeme) | 433.92 | Static  |
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

Überprüfe die Liste unter [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Unterstützte Frequenzen nach Region

Überprüfe die Liste unter [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!TIP]
> dBm-Werte der gespeicherten Frequenzen abrufen

## Referenzen

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
