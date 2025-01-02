# Infrarot

{{#include ../../banners/hacktricks-training.md}}

## Wie das Infrarot funktioniert <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarotlicht ist für Menschen unsichtbar**. Die IR-Wellenlänge reicht von **0,7 bis 1000 Mikrometer**. Haushaltsfernbedienungen verwenden ein IR-Signal zur Datenübertragung und arbeiten im Wellenlängenbereich von 0,75..1,4 Mikrometer. Ein Mikrocontroller in der Fernbedienung lässt eine Infrarot-LED mit einer bestimmten Frequenz blinken, wodurch das digitale Signal in ein IR-Signal umgewandelt wird.

Um IR-Signale zu empfangen, wird ein **Fotoreceiver** verwendet. Er **wandelt IR-Licht in Spannungspulse um**, die bereits **digitale Signale** sind. In der Regel gibt es einen **Dunkellichtfilter im Empfänger**, der **nur die gewünschte Wellenlänge durchlässt** und Rauschen herausfiltert.

### Vielfalt der IR-Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-Protokolle unterscheiden sich in 3 Faktoren:

- Bitkodierung
- Datenstruktur
- Trägerfrequenz — oft im Bereich von 36..38 kHz

#### Bitkodierungsarten <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulsabstandskodierung**

Bits werden durch Modulation der Dauer des Abstands zwischen den Pulsen kodiert. Die Breite des Pulses selbst ist konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulsbreitenkodierung**

Bits werden durch Modulation der Pulsbreite kodiert. Die Breite des Abstands nach dem Pulsstoß ist konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phasenkodierung**

Es ist auch als Manchester-Kodierung bekannt. Der logische Wert wird durch die Polarität des Übergangs zwischen Pulsstoß und Raum definiert. "Raum zu Pulsstoß" bezeichnet Logik "0", "Pulsstoß zu Raum" bezeichnet Logik "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombination der vorherigen und anderer exotischer Methoden**

> [!NOTE]
> Es gibt IR-Protokolle, die **versuchen, universell** für mehrere Gerätetypen zu werden. Die bekanntesten sind RC5 und NEC. Leider bedeutet das bekannteste **nicht das häufigste**. In meiner Umgebung habe ich nur zwei NEC-Fernbedienungen und keine RC5 gesehen.
>
> Hersteller verwenden gerne ihre eigenen einzigartigen IR-Protokolle, selbst innerhalb derselben Geräteserie (zum Beispiel TV-Boxen). Daher können Fernbedienungen von verschiedenen Unternehmen und manchmal von verschiedenen Modellen desselben Unternehmens nicht mit anderen Geräten desselben Typs arbeiten.

### Erforschung eines IR-Signals

Der zuverlässigste Weg, um zu sehen, wie das IR-Signal der Fernbedienung aussieht, ist die Verwendung eines Oszilloskops. Es demoduliert oder invertiert das empfangene Signal nicht, es wird einfach "so wie es ist" angezeigt. Dies ist nützlich für Tests und Debugging. Ich werde das erwartete Signal am Beispiel des NEC-IR-Protokolls zeigen.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

In der Regel gibt es ein Preamble zu Beginn eines kodierten Pakets. Dies ermöglicht es dem Empfänger, den Verstärkungsgrad und den Hintergrund zu bestimmen. Es gibt auch Protokolle ohne Preamble, zum Beispiel Sharp.

Dann werden die Daten übertragen. Die Struktur, das Preamble und die Bitkodierungsmethode werden durch das spezifische Protokoll bestimmt.

**NEC-IR-Protokoll** enthält einen kurzen Befehl und einen Wiederholcode, der gesendet wird, solange die Taste gedrückt wird. Sowohl der Befehl als auch der Wiederholcode haben am Anfang dasselbe Preamble.

Der **Befehl** von NEC besteht neben dem Preamble aus einem Adressbyte und einem Befehlsnummernbyte, durch das das Gerät versteht, was ausgeführt werden muss. Adress- und Befehlsnummernbytes werden mit inversen Werten dupliziert, um die Integrität der Übertragung zu überprüfen. Am Ende des Befehls gibt es ein zusätzliches Stoppbit.

Der **Wiederholcode** hat eine "1" nach dem Preamble, das ein Stoppbit ist.

Für **Logik "0" und "1"** verwendet NEC die Pulsabstandskodierung: Zuerst wird ein Pulsstoß übertragen, nach dem eine Pause folgt, deren Länge den Wert des Bits festlegt.

### Klimaanlagen

Im Gegensatz zu anderen Fernbedienungen **übertragen Klimaanlagen nicht nur den Code der gedrückten Taste**. Sie **übertragen auch alle Informationen**, wenn eine Taste gedrückt wird, um sicherzustellen, dass die **Klimaanlage und die Fernbedienung synchronisiert sind**.\
Dies verhindert, dass eine auf 20ºC eingestellte Maschine auf 21ºC erhöht wird, wenn eine Fernbedienung verwendet wird, und dann, wenn eine andere Fernbedienung, die immer noch die Temperatur von 20ºC hat, verwendet wird, um die Temperatur weiter zu erhöhen, sie auf 21ºC "erhöht" (und nicht auf 22ºC, weil sie denkt, dass sie auf 21ºC ist).

### Angriffe

Sie können Infrarot mit Flipper Zero angreifen:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

## Referenzen

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../banners/hacktricks-training.md}}
