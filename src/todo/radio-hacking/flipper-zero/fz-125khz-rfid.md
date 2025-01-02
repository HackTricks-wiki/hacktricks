# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Intro

Für weitere Informationen darüber, wie 125kHz-Tags funktionieren, siehe:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Aktionen

Für weitere Informationen über diese Arten von Tags [**lesen Sie diese Einführung**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lesen

Versucht, die **Karteninformationen** zu **lesen**. Dann kann sie **emuliert** werden.

> [!WARNING]
> Beachten Sie, dass einige Gegensprechanlagen versuchen, sich vor Schlüsselduplikationen zu schützen, indem sie einen Schreibbefehl vor dem Lesen senden. Wenn das Schreiben erfolgreich ist, wird dieses Tag als gefälscht betrachtet. Wenn Flipper RFID emuliert, gibt es keine Möglichkeit für den Leser, es vom Original zu unterscheiden, sodass keine solchen Probleme auftreten.

### Manuell hinzufügen

Sie können **gefälschte Karten in Flipper Zero erstellen, indem Sie die Daten** manuell angeben und sie dann emulieren.

#### IDs auf Karten

Manchmal, wenn Sie eine Karte erhalten, finden Sie die ID (oder einen Teil davon) sichtbar auf der Karte geschrieben.

- **EM Marin**

Zum Beispiel ist es bei dieser EM-Marin-Karte möglich, die **letzten 3 von 5 Bytes im Klartext zu lesen**.\
Die anderen 2 können brute-forced werden, wenn Sie sie nicht von der Karte lesen können.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Das gleiche passiert bei dieser HID-Karte, wo nur 2 von 3 Bytes auf der Karte gedruckt gefunden werden können.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulieren/Schreiben

Nach dem **Kopieren** einer Karte oder dem **manuellen Eingeben** der ID ist es möglich, sie mit Flipper Zero zu **emulieren** oder sie auf eine echte Karte zu **schreiben**.

## Referenzen

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
