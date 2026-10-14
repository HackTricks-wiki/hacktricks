# iButton

{{#include ../../banners/hacktricks-training.md}}

## Einführung

iButton ist ein allgemeiner Name für einen elektronischen Identifikationsschlüssel in einem **münzförmigen Metallgehäuse**. Er wird auch als Dallas Touch Memory oder Kontakt-Speicher bezeichnet. Obwohl er oft fälschlicherweise als „magnetischer“ Schlüssel bezeichnet wird, ist **nichts daran magnetisch**. Tatsächlich verbirgt sich darin ein vollwertiger **Mikrochip**, der über ein digitales Protokoll kommuniziert.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Was ist iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Der Name iButton beschreibt das robuste, münzförmige Gehäuse und die Anordnung der Kontakte. Als Halterungen gibt es Kunststoffanhänger, Ringe und Anhänger.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Wenn beide Kontakte das Lesegerät berühren, wird das Gerät mit Strom versorgt und tauscht Daten aus. Verhindert die vertiefte Kontaktgeometrie, dass die äußeren Massekontakte sich berühren, kann das Neigen des Schlüssels gegen die Wand des Lesegeräts den Kontakt wiederherstellen.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-Protokoll** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas-/Maxim-Schlüssel verwenden das 1-Wire-Protokoll: Ein Datenkontakt überträgt Daten in beide Richtungen und kann zugleich als parasitäre Stromversorgung dienen, während das Metallgehäuse als Rückkontakt fungiert. Der Controller initiiert Transaktionen, auf die das Gerät antwortet.<sup>[[2]](#references)</sup>

Wenn der Schlüssel (Slave) die Gegensprechanlage (Master) berührt, schaltet sich der Chip im Schlüssel ein, wird von der Gegensprechanlage mit Strom versorgt und der Schlüssel wird initialisiert. Anschließend fragt die Gegensprechanlage die ID des Schlüssels ab. Im Folgenden sehen wir uns diesen Vorgang genauer an.

Flipper kann beim Auslesen eines Schlüssels als Controller und beim Präsentieren einer gespeicherten Kennung gegenüber einem Lesegerät als emuliertes Gerät fungieren.<sup>[[1]](#references)</sup>

### Dallas-, Cyfral- und Metakom-Schlüssel

Informationen zur Funktionsweise dieser Schlüssel findest du auf der Seite [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Angriffe

iButtons können mit Flipper Zero angegriffen werden:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [iButton mit Flipper Zero zähmen](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 1-Wire-Kommunikation per Software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
