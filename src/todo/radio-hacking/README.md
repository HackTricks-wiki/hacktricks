# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Funk-Sicherheitstests untersuchen, wie ein Gerät drahtlose Signale überträgt, empfängt und interpretiert. Ein Software Defined Radio (SDR) kann dabei helfen, ein Signal zu lokalisieren, In-Phase/Quadratur-(I/Q-)Samples aufzuzeichnen und Demodulation sowie Dekodierung zu testen, ohne auf protokollspezifische Hardware angewiesen zu sein.<sup>[[1]](#references)</sup>

Ein praktischer Workflow besteht darin, das Frequenzband und die Kanalbreite zu bestimmen, mehrere bekannte Geräteaktionen aufzuzeichnen, die daraus resultierenden Signale zu vergleichen und anschließend die Modulation sowie die Paketstruktur zu bestimmen. Test-Replay oder Übertragungen sollten nur in einer isolierten Umgebung und auf Frequenzen sowie mit Geräten durchgeführt werden, für die eine Genehmigung vorliegt. Die Seiten in diesem Abschnitt behandeln RFID, NFC, Sub-GHz-Funk, Infrarot, BLE und verwandte Tools.<sup>[[1]](#references)</sup>

## References

- [1] [Great Scott Gadgets - Software Defined Radio mit HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
