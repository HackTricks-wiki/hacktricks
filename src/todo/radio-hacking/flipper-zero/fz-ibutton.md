# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Hintergrundinformationen zur iButton-Technologie finden Sie hier:

{{#ref}}
../ibutton.md
{{#endref}}

## Aufbau

Im folgenden Bild zeigt der **blaue** Bereich, wie ein physischer iButton zum Lesen an den Kontakten des Flipper Zero positioniert wird. Der **grüne** Bereich zeigt, welche Kontakte bei der Emulation einen Leser berühren sollten.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Lesen

Im Lesemodus wartet der Flipper Zero darauf, dass ein Schlüssel seine Kontakte berührt, erkennt das Protokoll und zeigt das Protokoll über der Schlüssel-ID an. Die integrierte Anwendung unterstützt Dallas-, Cyfral- und Metakom-Zugangskontrollschlüssel.<sup>[[2]](#references)</sup>

### Manuell hinzufügen

Sie können Schlüsseldaten für die Dallas-, Cyfral- und Metakom-Protokolle manuell eingeben.<sup>[[2]](#references)</sup>

### Emulieren

Sie können einen gespeicherten Schlüssel emulieren, unabhängig davon, ob er von einem physischen Schlüssel gelesen oder manuell eingegeben wurde.<sup>[[2]](#references)</sup>

> [!TIP]
> Wenn die integrierten Kontakte den Leser nicht erreichen können, verbinden Sie die Daten- und Massekontakte über die GPIO-Pins.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [iButton-Schlüssel mit Flipper Zero bändigen](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper-Zero-Dokumentation - iButton-Schlüssel lesen](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
