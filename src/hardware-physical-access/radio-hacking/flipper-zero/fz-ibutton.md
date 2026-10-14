# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Hintergrundinformationen zur iButton-Technologie findest du hier:

{{#ref}}
../ibutton.md
{{#endref}}

## Aufbau

Im folgenden Bild zeigt der **blaue** Bereich, wie ein physischer iButton zum Auslesen an die Kontakte des Flipper Zero gehalten wird. Der **grüne** Bereich zeigt, welche Kontakte während der Emulation ein Lesegerät berühren sollten.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Auslesen

Im Lesemodus wartet der Flipper Zero darauf, dass ein Schlüssel seine Kontakte berührt, erkennt das Protokoll und zeigt es über der Schlüssel-ID an. Die integrierte Anwendung unterstützt Dallas-, Cyfral- und Metakom-Zugangskontrollschlüssel.<sup>[[2]](#references)</sup>

### Manuell hinzufügen

Du kannst Schlüsseldaten für die Protokolle Dallas, Cyfral und Metakom manuell eingeben.<sup>[[2]](#references)</sup>

### Emulieren

Du kannst einen gespeicherten Schlüssel emulieren, unabhängig davon, ob er von einem physischen Schlüssel ausgelesen oder manuell eingegeben wurde.<sup>[[2]](#references)</sup>

> [!TIP]
> Wenn die integrierten Kontakte das Lesegerät nicht erreichen, verbinde die Daten- und Massekontakte über die GPIO-Pins.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [iButton-Schlüssel mit dem Flipper Zero zähmen](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero-Dokumentation – iButton-Schlüssel auslesen](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

