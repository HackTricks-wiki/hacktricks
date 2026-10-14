# Funk-Hacking

{{#include ../../banners/hacktricks-training.md}}

Bei Sicherheitstests für Funk wird untersucht, wie ein Gerät drahtlose Signale sendet, empfängt und interpretiert. Ein Software Defined Radio (SDR) kann dabei helfen, ein Signal zu lokalisieren, In-Phase-/Quadratur-Samples (I/Q) aufzuzeichnen und Demodulation sowie Decodierung zu testen, ohne sich auf protokollspezifische Hardware festlegen zu müssen.<sup>[[1]](#references)</sup>

Ein praktischer Ablauf besteht darin, Frequenzband und Kanalbreite zu ermitteln, mehrere bekannte Geräteaktionen aufzuzeichnen, die resultierenden Signale zu vergleichen und anschließend Modulation sowie Paketstruktur zu bestimmen. Replay oder Übertragung sollte nur in einer isolierten Umgebung und auf Frequenzen sowie mit Geräten getestet werden, für die eine Autorisierung vorliegt. Die Seiten in diesem Abschnitt behandeln RFID, NFC, Sub-GHz-Funk, Infrarot, BLE und zugehörige Tools.<sup>[[1]](#references)</sup>

## Die passende Schnittstelle finden

- Bei einem Zugangsausweis oder Kontaktschlüssel kannst du mit [RFID/NFC-Tag-Typen und Angriffen](pentesting-rfid.md), [Proxmark3-Workflows](proxmark-3.md) oder [iButton- und 1-Wire-Schlüsseln](ibutton.md) beginnen. Der [Flipper-Zero-Leitfaden](flipper-zero/README.md) verweist auf die jeweiligen Schnittstellenaktionen.
- Für ein Fernbedienungssignal verwende [Sub-GHz-Funk und Rolling Codes](sub-ghz-rf.md) oder [Infrarotprotokolle und Angriffe](infrared.md).
- Für Geräte und Sensoren in der Nähe verwende [BLE-Advertising-, GATT- und Mesh-Tests](pentesting-ble-bluetooth-low-energy.md) oder [LPWAN/LoRaWAN-Sicherheit](low-power-wide-area-network.md).
- Für aufgezeichnete oder unbekannte Funksignale verwende die [SigDigger-Signalanalyse](../hardware-hacking/radio.md#sigdigger) oder das [FISSURE-Framework](fissure-the-rf-framework.md).

## References

- [1] [Great Scott Gadgets – Software Defined Radio mit HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
