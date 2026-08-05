# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Einführung

Weitere Informationen zur Funktionsweise von 125-kHz-Tags findest du hier:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Aktionen

Weitere Informationen zu diesen Tag-Typen findest du in [**dieser Einführung**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lesen

Versucht, die Karteninformationen zu **lesen**. Anschließend können sie **emuliert** werden.<sup>[[1]](#references)</sup>

> [!WARNING]
> Beachte, dass einige Gegensprechanlagen versuchen, sich durch das Senden eines Schreibbefehls vor dem Duplizieren von Schlüsseln zu schützen. Wenn der Schreibvorgang erfolgreich ist, wird der Tag als gefälscht betrachtet. Wenn Flipper RFID emuliert, gibt es für das Lesegerät keine Möglichkeit, ihn vom Original zu unterscheiden, sodass solche Probleme nicht auftreten.

### Manuell hinzufügen

Du kannst **gefälschte Karten in Flipper Zero erstellen, indem du die Daten manuell angibst**, und sie anschließend emulieren.

#### IDs auf Karten

Manchmal findest du beim Erhalten einer Karte die ID (oder einen Teil davon) sichtbar auf der Karte aufgedruckt.

- **EM Marin**

Bei dieser EM-Marin-Karte ist es beispielsweise möglich, die **letzten 3 von 5 Bytes im Klartext zu lesen**.\
Die anderen 2 können per Brute-Force ermittelt werden, wenn du sie nicht von der Karte ablesen kannst.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Dasselbe gilt für diese HID-Karte, bei der nur 2 von 3 Bytes auf der Karte aufgedruckt sind.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulieren/Schreiben

Nach dem **Kopieren** einer Karte oder dem **manuellen Eingeben** der ID ist es möglich, sie mit Flipper Zero zu **emulieren** oder sie auf eine echte Karte zu **schreiben**.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
