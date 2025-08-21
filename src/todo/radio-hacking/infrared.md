# Infrarot

{{#include ../../banners/hacktricks-training.md}}

## Wie das Infrarot funktioniert <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarotlicht ist für Menschen unsichtbar**. Die IR-Wellenlänge reicht von **0,7 bis 1000 Mikrometer**. Haushaltsfernbedienungen verwenden ein IR-Signal zur Datenübertragung und arbeiten im Wellenlängenbereich von 0,75 bis 1,4 Mikrometer. Ein Mikrocontroller in der Fernbedienung lässt eine Infrarot-LED mit einer bestimmten Frequenz blinken, wodurch das digitale Signal in ein IR-Signal umgewandelt wird.

Um IR-Signale zu empfangen, wird ein **Fotoreceiver** verwendet. Er **wandelt IR-Licht in Spannungspulse um**, die bereits **digitale Signale** sind. In der Regel gibt es einen **Dunkellichtfilter im Empfänger**, der **nur die gewünschte Wellenlänge durchlässt** und Rauschen herausfiltert.

### Vielfalt der IR-Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-Protokolle unterscheiden sich in 3 Faktoren:

- Bitkodierung
- Datenstruktur
- Trägerfrequenz — oft im Bereich von 36 bis 38 kHz

#### Bitkodierungsarten <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulsabstandskodierung**

Bits werden kodiert, indem die Dauer des Abstands zwischen den Pulsen moduliert wird. Die Breite des Pulses selbst ist konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulsbreitenkodierung**

Bits werden durch Modulation der Pulsbreite kodiert. Die Breite des Abstands nach dem Pulsstoß ist konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phasenkodierung**

Es ist auch als Manchester-Kodierung bekannt. Der logische Wert wird durch die Polarität des Übergangs zwischen Pulsstoß und Raum definiert. "Raum zu Pulsstoß" bezeichnet Logik "0", "Pulsstoß zu Raum" bezeichnet Logik "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombination der vorherigen und anderer exotischer Methoden**

> [!TIP]
> Es gibt IR-Protokolle, die **versuchen, universell** für mehrere Gerätetypen zu werden. Die bekanntesten sind RC5 und NEC. Leider bedeutet das bekannteste **nicht das häufigste**. In meiner Umgebung habe ich nur zwei NEC-Fernbedienungen und keine RC5 gesehen.
>
> Hersteller verwenden gerne ihre eigenen einzigartigen IR-Protokolle, selbst innerhalb derselben Geräteserie (zum Beispiel TV-Boxen). Daher können Fernbedienungen von verschiedenen Unternehmen und manchmal von verschiedenen Modellen desselben Unternehmens nicht mit anderen Geräten desselben Typs arbeiten.

### Erforschung eines IR-Signals

Der zuverlässigste Weg, um zu sehen, wie das IR-Signal der Fernbedienung aussieht, ist die Verwendung eines Oszilloskops. Es demoduliert oder invertiert das empfangene Signal nicht, es wird einfach "so wie es ist" angezeigt. Dies ist nützlich für Tests und Debugging. Ich werde das erwartete Signal am Beispiel des NEC-IR-Protokolls zeigen.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

In der Regel gibt es ein Preamble zu Beginn eines kodierten Pakets. Dies ermöglicht es dem Empfänger, den Verstärkungsgrad und den Hintergrund zu bestimmen. Es gibt auch Protokolle ohne Preamble, zum Beispiel Sharp.

Dann werden die Daten übertragen. Die Struktur, Preamble und Bitkodierungsmethode werden durch das spezifische Protokoll bestimmt.

**NEC-IR-Protokoll** enthält einen kurzen Befehl und einen Wiederholcode, der gesendet wird, solange die Taste gedrückt wird. Sowohl der Befehl als auch der Wiederholcode haben zu Beginn die gleiche Preamble.

Der **Befehl** von NEC besteht neben der Preamble aus einem Adressbyte und einem Befehlsnummernbyte, durch das das Gerät versteht, was ausgeführt werden muss. Adress- und Befehlsnummernbytes werden mit inversen Werten dupliziert, um die Integrität der Übertragung zu überprüfen. Am Ende des Befehls gibt es ein zusätzliches Stoppbit.

Der **Wiederholcode** hat nach der Preamble eine "1", die ein Stoppbit ist.

Für **Logik "0" und "1"** verwendet NEC die Pulsabstandskodierung: Zuerst wird ein Pulsstoß übertragen, nach dem eine Pause folgt, deren Länge den Wert des Bits festlegt.

### Klimaanlagen

Im Gegensatz zu anderen Fernbedienungen **übertragen Klimaanlagen nicht nur den Code der gedrückten Taste**. Sie **übertragen auch alle Informationen**, wenn eine Taste gedrückt wird, um sicherzustellen, dass die **Klimaanlage und die Fernbedienung synchronisiert sind**.\
Dies verhindert, dass eine auf 20ºC eingestellte Maschine mit einer Fernbedienung auf 21ºC erhöht wird und dann, wenn eine andere Fernbedienung, die immer noch die Temperatur von 20ºC hat, verwendet wird, um die Temperatur weiter zu erhöhen, sie auf 21ºC "erhöht" wird (und nicht auf 22ºC, weil sie denkt, dass sie auf 21ºC ist).

---

## Angriffe & Offensive Forschung <a href="#attacks" id="attacks"></a>

Sie können Infrarot mit Flipper Zero angreifen:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-Top-Box Übernahme (EvilScreen)

Jüngste akademische Arbeiten (EvilScreen, 2022) haben gezeigt, dass **Multikanalfernbedienungen, die Infrarot mit Bluetooth oder Wi-Fi kombinieren, missbraucht werden können, um moderne Smart-TVs vollständig zu übernehmen**. Die Angriffsstränge kombinieren hochprivilegierte IR-Dienstcodes mit authentifizierten Bluetooth-Paketen, umgehen die Kanaltrennung und ermöglichen beliebige App-Starts, Mikrofonaktivierung oder Werkseinstellungen ohne physischen Zugriff. Acht gängige Fernseher von verschiedenen Anbietern — darunter ein Samsung-Modell, das die ISO/IEC 27001-Konformität beansprucht — wurden als anfällig bestätigt. Die Minderung erfordert Firmware-Updates des Herstellers oder das vollständige Deaktivieren ungenutzter IR-Empfänger.

### Datenexfiltration über IR-LEDs (aIR-Jumper-Familie)

Sicherheitskameras, Router oder sogar bösartige USB-Sticks enthalten oft **Nachtsicht-IR-LEDs**. Forschungen zeigen, dass Malware diese LEDs modulieren kann (<10–20 kbit/s mit einfachem OOK), um **Geheimnisse durch Wände und Fenster** zu exfiltrieren, zu einer externen Kamera, die mehrere Meter entfernt platziert ist. Da das Licht außerhalb des sichtbaren Spektrums liegt, bemerken die Betreiber es selten. Gegenmaßnahmen:

* Physisch IR-LEDs in sensiblen Bereichen abschirmen oder entfernen
* Überwachen Sie den Duty-Cycle der Kamera-LED und die Firmware-Integrität
* IR-Cut-Filter an Fenstern und Überwachungskameras einsetzen

Ein Angreifer kann auch starke IR-Projektoren verwenden, um **Befehle** in das Netzwerk einzuschleusen, indem er Daten an unsichere Kameras zurückblitzt.

### Langstrecken-Brute-Force & Erweiterte Protokolle mit Flipper Zero 1.0

Die Firmware 1.0 (September 2024) fügte **Dutzende zusätzlicher IR-Protokolle und optionale externe Verstärkermodule** hinzu. In Kombination mit dem Brute-Force-Modus der Universalfernbedienung kann ein Flipper die meisten öffentlichen Fernseher/Klimaanlagen aus bis zu 30 m mit einer Hochleistungsdiode deaktivieren oder neu konfigurieren.

---

## Werkzeuge & Praktische Beispiele <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – tragbarer Transceiver mit Lern-, Wiederhol- und Wörterbuch-Brute-Force-Modi (siehe oben).
* **Arduino / ESP32** + IR-LED / TSOP38xx-Empfänger – günstiger DIY-Analysator/Transmitter. Kombinieren Sie es mit der `Arduino-IRremote`-Bibliothek (v4.x unterstützt >40 Protokolle).
* **Logikanalysatoren** (Saleae/FX2) – erfassen Sie rohe Zeitmessungen, wenn das Protokoll unbekannt ist.
* **Smartphones mit IR-Blaster** (z. B. Xiaomi) – schneller Feldtest, aber begrenzte Reichweite.

### Software

* **`Arduino-IRremote`** – aktiv gewartete C++-Bibliothek:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI-Dekodierer, die rohe Aufnahmen importieren und Protokolle automatisch identifizieren + Pronto/Arduino-Code generieren.
* **LIRC / ir-keytable (Linux)** – empfangen und injizieren Sie IR über die Befehlszeile:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump dekodierte Scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Verteidigungsmaßnahmen <a href="#defense" id="defense"></a>

* Deaktivieren oder abdecken Sie IR-Empfänger an Geräten, die in öffentlichen Räumen eingesetzt werden, wenn sie nicht benötigt werden.
* Erzwingen Sie *Pairing* oder kryptografische Überprüfungen zwischen Smart-TVs und Fernbedienungen; isolieren Sie privilegierte „Dienst“-Codes.
* Setzen Sie IR-Cut-Filter oder kontinuierliche Wellen-Detektoren in klassifizierten Bereichen ein, um optische verdeckte Kanäle zu unterbrechen.
* Überwachen Sie die Firmware-Integrität von Kameras/IoT-Geräten, die steuerbare IR-LEDs exponieren.

## Referenzen

- [Flipper Zero Infrarot-Blogbeitrag](https://blog.flipperzero.one/infrared/)
- EvilScreen: Smart-TV-Hijacking durch Nachahmung der Fernbedienung (arXiv 2210.03014)

{{#include ../../banners/hacktricks-training.md}}
