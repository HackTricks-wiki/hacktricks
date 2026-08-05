# iButton

{{#include ../../banners/hacktricks-training.md}}

## Einführung

iButton ist eine allgemeine Bezeichnung für einen elektronischen Identifikationsschlüssel, der in einem **münzförmigen Metallgehäuse** untergebracht ist. Er wird auch als **Dallas Touch** Memory oder Kontakt-Memory bezeichnet. Obwohl er häufig fälschlicherweise als „magnetischer“ Schlüssel bezeichnet wird, befindet sich darin **nichts Magnetisches**. Tatsächlich ist darin ein vollwertiger **Mikrochip** verborgen, der mit einem digitalen Protokoll arbeitet.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Was ist iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Üblicherweise bezeichnet iButton die physische Form des Schlüssels und Lesers – eine runde Münze mit zwei Kontakten. Für die Halterung gibt es zahlreiche Varianten, vom häufigsten Kunststoffhalter mit einer Öffnung bis hin zu Ringen, Anhängern usw.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Wenn der Schlüssel den Leser erreicht, **berühren sich die Kontakte** und der Schlüssel wird mit Strom versorgt, um seine ID zu **übertragen**. Manchmal wird der Schlüssel nicht sofort **gelesen**, weil die **Kontakt-PSD einer Gegensprechanlage größer** ist als vorgesehen. Dadurch konnten die Außenkonturen des Schlüssels und des Lesers einander nicht berühren. In diesem Fall müssen Sie den Schlüssel gegen eine der Wände des Lesers drücken.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-Protokoll** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas-Schlüssel tauschen Daten über das 1-Wire-Protokoll aus. Dabei gibt es in beiden Richtungen, vom Master zum Slave und umgekehrt, nur einen Kontakt für die Datenübertragung (!!). Das 1-Wire-Protokoll arbeitet nach dem Master-Slave-Modell. In dieser Topologie initiiert der Master immer die Kommunikation, und der Slave folgt seinen Anweisungen.

Wenn der Schlüssel (Slave) die Gegensprechanlage (Master) kontaktiert, schaltet sich der Chip im Schlüssel ein, wird von der Gegensprechanlage mit Strom versorgt und der Schlüssel wird initialisiert. Anschließend fordert die Gegensprechanlage die ID des Schlüssels an. Im Folgenden betrachten wir diesen Prozess genauer.

Flipper kann sowohl im Master- als auch im Slave-Modus arbeiten. Im Schlüssel-Lesemodus fungiert Flipper als Leser, das heißt, er arbeitet als Master. Im Schlüssel-Emulationsmodus gibt Flipper vor, ein Schlüssel zu sein, und befindet sich im Slave-Modus.

### Dallas-, Cyfral- und Metakom-Schlüssel

Informationen zur Funktionsweise dieser Schlüssel finden Sie auf der Seite [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Angriffe

iButtons können mit Flipper Zero angegriffen werden:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Referenzen

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
