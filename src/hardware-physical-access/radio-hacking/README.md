# Radio-Hacking

{{#include ../../banners/hacktricks-training.md}}

Bei Sicherheitstests für Funk wird untersucht, wie ein Gerät drahtlose Signale sendet, empfängt und interpretiert. Ein softwaredefiniertes Radio (SDR) kann dabei helfen, ein Signal zu lokalisieren, In-Phase-/Quadratur-Samples (I/Q) aufzuzeichnen und Demodulation und Decodierung ohne spezielle protokollspezifische Hardware zu testen.<sup>[[1]](#references)</sup>

Ein praktischer Ablauf besteht darin, das Frequenzband und die Kanalbreite zu bestimmen, mehrere bekannte Geräteaktionen aufzuzeichnen, die resultierenden Signale zu vergleichen und anschließend Modulation und Paketstruktur zu ermitteln. Replay oder Übertragung sollten nur in einer isolierten Umgebung und auf Frequenzen sowie mit Geräten getestet werden, für die Sie eine Genehmigung haben. Die Seiten in diesem Abschnitt behandeln RFID, NFC, Sub-GHz-Funk, Infrarot, BLE und verwandte Tools.<sup>[[1]](#references)</sup>

## Relevante Schnittstelle finden

- Für einen Zutrittsausweis oder Kontaktschlüssel beginnen Sie mit [RFID/NFC-Tag-Typen und Angriffe](pentesting-rfid.md), [Proxmark3-Abläufen](proxmark-3.md) oder [iButton- und 1-Wire-Schlüsseln](ibutton.md). Der [Flipper-Zero-Leitfaden](flipper-zero/README.md) verweist auf die zugehörigen Schnittstellenaktionen.
- Für ein Fernbedienungssignal verwenden Sie [Sub-GHz-RF und Rolling Codes](sub-ghz-rf.md) oder [Infrarotprotokolle und Angriffe](infrared.md).
- Für Geräte und Sensoren in der Nähe verwenden Sie [BLE-Werbung, GATT und Mesh-Tests](pentesting-ble-bluetooth-low-energy.md) oder [LPWAN-/LoRaWAN-Sicherheit](low-power-wide-area-network.md).
- Für aufgezeichnete oder unbekannte RF-Signale verwenden Sie die [SigDigger-Signalanalyse](../hardware-hacking/radio.md#sigdigger) oder das [FISSURE-Framework](fissure-the-rf-framework.md).
- Informationen zu Satellitenterminal-Downlinks finden Sie unter [VSAT-Forward-Link-Signalinjektion](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets – Softwaredefiniertes Radio mit HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
