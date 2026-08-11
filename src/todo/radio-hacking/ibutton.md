# iButton

{{#include ../../banners/hacktricks-training.md}}

## Einleitung

iButton ist eine allgemeine Bezeichnung für einen elektronischen Identifikationsschlüssel in einem **münzförmigen Metallgehäuse**. Er wird auch als **Dallas Touch** Memory oder Contact Memory bezeichnet. Obwohl er oft fälschlicherweise als „magnetischer“ Schlüssel bezeichnet wird, ist darin **nichts magnetisch**. Tatsächlich befindet sich darin ein vollwertiger **Mikrochip**, der über ein digitales Protokoll arbeitet.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Was ist iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Der Name iButton beschreibt das robuste münzförmige Gehäuse und die Anordnung der Kontakte. Zu den Halterungen gehören Kunststoffanhänger, Ringe und Anhänger.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Wenn beide Kontakte den Leser berühren, erhält das Gerät Strom und tauscht Daten aus. Wenn die vertiefte Kontaktgeometrie verhindert, dass die äußeren Massekontakte eine Verbindung herstellen, kann das Neigen des Schlüssels gegen die Leserwand den Kontakt wiederherstellen.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-Protokoll** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim-Schlüssel verwenden das 1-Wire-Protokoll: Ein Datenkontakt überträgt bidirektionalen Datenverkehr und kann auch parasitäre Stromversorgung bereitstellen, während das Metallgehäuse als Rückkontakt dient. Der Controller initiiert Transaktionen und das Gerät antwortet.<sup>[[2]](#references)</sup>

Wenn der Schlüssel (Slave) die Gegensprechanlage (Master) berührt, wird der Chip im Schlüssel von der Gegensprechanlage mit Strom versorgt, eingeschaltet und initialisiert. Anschließend fordert die Gegensprechanlage die ID des Schlüssels an. Im Folgenden sehen wir uns diesen Prozess genauer an.

Flipper kann beim Lesen eines Schlüssels als Controller und beim Präsentieren einer gespeicherten Kennung gegenüber einem Leser als emuliertes Gerät fungieren.<sup>[[1]](#references)</sup>

### Dallas-, Cyfral- und Metakom-Schlüssel

Informationen zur Funktionsweise dieser Schlüssel findest du auf der Seite [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Angriffe

iButtons können mit Flipper Zero angegriffen werden:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [iButton mit Flipper Zero bändigen](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 1-Wire-Kommunikation per Software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
