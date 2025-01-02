# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero kann **Funkfrequenzen im Bereich von 300-928 MHz empfangen und übertragen** mit seinem integrierten Modul, das Fernbedienungen lesen, speichern und emulieren kann. Diese Steuerungen werden zur Interaktion mit Toren, Barrieren, Funk-Schlössern, Fernbedienungsschaltern, drahtlosen Türklingeln, smarten Lichtern und mehr verwendet. Flipper Zero kann Ihnen helfen zu lernen, ob Ihre Sicherheit gefährdet ist.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero verfügt über ein integriertes Sub-1 GHz Modul, das auf einem [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 Chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) basiert und eine Funkantenne hat (die maximale Reichweite beträgt 50 Meter). Sowohl der CC1101 Chip als auch die Antenne sind dafür ausgelegt, bei Frequenzen in den Bändern 300-348 MHz, 387-464 MHz und 779-928 MHz zu arbeiten.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Frequenzanalysator

> [!NOTE]
> Wie man herausfindet, welche Frequenz die Fernbedienung verwendet

Beim Analysieren scannt Flipper Zero die Signalstärke (RSSI) an allen in der Frequenzkonfiguration verfügbaren Frequenzen. Flipper Zero zeigt die Frequenz mit dem höchsten RSSI-Wert an, mit einer Signalstärke höher als -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Um die Frequenz der Fernbedienung zu bestimmen, gehen Sie wie folgt vor:

1. Platzieren Sie die Fernbedienung sehr nah links von Flipper Zero.
2. Gehen Sie zu **Hauptmenü** **→ Sub-GHz**.
3. Wählen Sie **Frequenzanalysator**, und drücken und halten Sie die Taste auf der Fernbedienung, die Sie analysieren möchten.
4. Überprüfen Sie den Frequenzwert auf dem Bildschirm.

### Lesen

> [!NOTE]
> Informationen über die verwendete Frequenz finden (auch eine andere Möglichkeit, um herauszufinden, welche Frequenz verwendet wird)

Die **Lesen**-Option **lauscht auf der konfigurierten Frequenz** bei der angegebenen Modulation: standardmäßig 433,92 AM. Wenn **etwas gefunden wird**, während gelesen wird, **werden Informationen auf dem Bildschirm angezeigt**. Diese Informationen können verwendet werden, um das Signal in der Zukunft zu replizieren.

Während Lesen verwendet wird, ist es möglich, die **linke Taste** zu drücken und **es zu konfigurieren**.\
Im Moment hat es **4 Modulationen** (AM270, AM650, FM328 und FM476) und **mehrere relevante Frequenzen** gespeichert:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Sie können **jede, die Sie interessiert**, einstellen, jedoch, wenn Sie **nicht sicher sind, welche Frequenz** die von Ihrer Fernbedienung verwendete sein könnte, **stellen Sie Hopping auf EIN** (standardmäßig AUS) und drücken Sie die Taste mehrmals, bis Flipper sie erfasst und Ihnen die Informationen gibt, die Sie benötigen, um die Frequenz einzustellen.

> [!CAUTION]
> Der Wechsel zwischen Frequenzen benötigt etwas Zeit, daher können Signale, die zum Zeitpunkt des Wechsels übertragen werden, verpasst werden. Für eine bessere Signalempfang stellen Sie eine feste Frequenz ein, die vom Frequenzanalysator bestimmt wird.

### **Raw Lesen**

> [!NOTE]
> Ein Signal in der konfigurierten Frequenz stehlen (und wiederholen)

Die **Raw Lesen**-Option **zeichnet Signale** auf, die in der Lauscherfrequenz gesendet werden. Dies kann verwendet werden, um ein Signal zu **stehlen** und es **zu wiederholen**.

Standardmäßig ist **Raw Lesen auch in 433,92 in AM650**, aber wenn Sie mit der Lesen-Option festgestellt haben, dass das Signal, das Sie interessiert, in einer **anderen Frequenz/Modulation ist, können Sie das auch** ändern, indem Sie links drücken (während Sie sich in der Raw Lesen-Option befinden).

### Brute-Force

Wenn Sie das Protokoll kennen, das beispielsweise vom Garagentor verwendet wird, ist es möglich, **alle Codes zu generieren und sie mit dem Flipper Zero zu senden.** Dies ist ein Beispiel, das allgemeine gängige Arten von Garagen unterstützt: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Manuell hinzufügen

> [!NOTE]
> Signale aus einer konfigurierten Liste von Protokollen hinzufügen

#### Liste der [unterstützten Protokolle](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (funktioniert mit der Mehrheit der statischen Codesysteme) | 433.92 | Statisch  |
| ------------------------------------------------------------------------- | ------ | -------- |
| Nice Flo 12bit_433                                                       | 433.92 | Statisch  |
| Nice Flo 24bit_433                                                       | 433.92 | Statisch  |
| CAME 12bit_433                                                           | 433.92 | Statisch  |
| CAME 24bit_433                                                           | 433.92 | Statisch  |
| Linear_300                                                               | 300.00 | Statisch  |
| CAME TWEE                                                                | 433.92 | Statisch  |
| Gate TX_433                                                              | 433.92 | Statisch  |
| DoorHan_315                                                              | 315.00 | Dynamisch |
| DoorHan_433                                                              | 433.92 | Dynamisch |
| LiftMaster_315                                                           | 315.00 | Dynamisch |
| LiftMaster_390                                                           | 390.00 | Dynamisch |
| Security+2.0_310                                                         | 310.00 | Dynamisch |
| Security+2.0_315                                                         | 315.00 | Dynamisch |
| Security+2.0_390                                                         | 390.00 | Dynamisch |

### Unterstützte Sub-GHz-Anbieter

Überprüfen Sie die Liste in [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Unterstützte Frequenzen nach Region

Überprüfen Sie die Liste in [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!NOTE]
> Erhalten Sie dBms der gespeicherten Frequenzen

## Referenz

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
