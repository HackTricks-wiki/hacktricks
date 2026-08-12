# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Hintergrundinformationen zur Funktionsweise von 125-kHz-Tags findest du hier:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

Die [Einführung in RFID mit niedriger Frequenz](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) erklärt die gängigen Tag-Familien und ihre Datenformate.

## Aktionen

### Lesen

Verwende **Lesen**, um die Tag-Daten zu erfassen. Nach einem erfolgreichen Lesevorgang kann Flipper Zero den gespeicherten Tag emulieren.<sup>[[1]](#references)</sup>

> [!WARNING]
> Einige Lesegeräte von Gegensprechanlagen versuchen, beschreibbare Duplikat-Tags zu erkennen, indem sie vor dem Lesen einen Schreibbefehl ausführen. Eine Emulation durch Flipper Zero stellt den beschreibbaren Tag-Speicher nicht auf dieselbe Weise bereit.<sup>[[1]](#references)</sup>

### Manuell hinzufügen

Du kannst Tag-Daten manuell in Flipper Zero eingeben, speichern und anschließend emulieren.<sup>[[1]](#references)</sup>

#### IDs auf Karten

Manchmal ist die ID einer Karte ganz oder teilweise auf ihrer Außenseite aufgedruckt.

- **EM Marin**

Die abgebildete EM-Marin-Karte zeigt beispielsweise die letzten drei ihrer fünf ID-Bytes. Wenn der Tag nicht gelesen werden kann, können die beiden fehlenden Bytes per Brute-Force ermittelt werden.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Auf der abgebildeten HID-Karte sind dagegen nur zwei der drei ID-Bytes aufgedruckt.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulieren/Schreiben

Nach dem Lesen eines Tags oder der manuellen Eingabe seiner ID kann Flipper Zero die gespeicherten Zugangsdaten emulieren. Bei unterstützten beschreibbaren Tags kann das Gerät die gespeicherten Daten außerdem auf eine kompatible Karte schreiben.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Einblick in RFID-Protokolle](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
