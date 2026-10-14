# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Hintergrundinformationen zur Funktionsweise von 125-kHz-Tags finden Sie hier:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

Die [Einführung in RFID-Tags mit niedriger Frequenz](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) erläutert die gängigen Tag-Familien und ihre Datenformate.

## Aktionen

### Lesen

Verwenden Sie **Lesen**, um die Tag-Daten zu erfassen. Nach einem erfolgreichen Lesevorgang kann Flipper Zero den gespeicherten Tag emulieren.<sup>[[1]](#references)</sup>

> [!WARNING]
> Einige Gegensprechanlagen versuchen, beschreibbare Duplikat-Tags zu erkennen, indem sie vor dem Lesen einen Schreibbefehl ausgeben. Eine Flipper-Zero-Emulation stellt den beschreibbaren Tag-Speicher nicht auf dieselbe Weise bereit.<sup>[[1]](#references)</sup>

### Manuell hinzufügen

Sie können Tag-Daten manuell in Flipper Zero eingeben, speichern und anschließend emulieren.<sup>[[1]](#references)</sup>

#### IDs auf Karten

Manchmal ist die ID einer Karte ganz oder teilweise auf ihrer Außenseite aufgedruckt.

- **EM Marin**

Die abgebildete EM-Marin-Karte gibt beispielsweise die letzten drei ihrer fünf ID-Bytes preis. Wenn der Tag nicht gelesen werden kann, können die zwei fehlenden Bytes per Brute-Force ermittelt werden.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Auf der abgebildeten HID-Karte sind ebenfalls nur zwei der drei ID-Bytes aufgedruckt.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulieren/Schreiben

Nach dem Lesen eines Tags oder der manuellen Eingabe seiner ID kann Flipper Zero die gespeicherten Zugangsdaten emulieren. Bei unterstützten beschreibbaren Tags kann das Gerät die gespeicherten Daten auch auf eine kompatible Karte schreiben.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Ein tiefer Einblick in RFID-Protokolle](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
