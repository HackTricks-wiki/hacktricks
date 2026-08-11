# Infrarot

{{#include ../../banners/hacktricks-training.md}}

## Funktionsweise von Infrarot <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarotlicht ist für Menschen unsichtbar**. Die IR-Wellenlänge reicht von **0,7 bis 1000 Mikrometern**. Haushaltsfernbedienungen verwenden ein IR-Signal zur Datenübertragung und arbeiten im Wellenlängenbereich von 0,75..1,4 Mikrometern. Ein Mikrocontroller in der Fernbedienung lässt eine Infrarot-LED mit einer bestimmten Frequenz blinken und wandelt das digitale Signal in ein IR-Signal um.

Zum Empfang von IR-Signalen wird ein **Fotodetektor** verwendet. Er **wandelt IR-Licht in Spannungsimpulse um**, bei denen es sich bereits um **digitale Signale** handelt. Normalerweise befindet sich im Empfänger ein **Dunkellichtfilter**, der **nur die gewünschte Wellenlänge durchlässt** und Rauschen herausfiltert.<sup>[[1]](#references)</sup>

### Vielfalt der IR-Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-Protokolle unterscheiden sich in drei Faktoren:<sup>[[1]](#references)</sup>

- Bitkodierung
- Datenstruktur
- Trägerfrequenz — häufig im Bereich von 36..38 kHz

#### Arten der Bitkodierung <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits werden durch die Modulation der Dauer des Abstands zwischen den Impulsen kodiert. Die Breite des Impulses selbst bleibt konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits werden durch die Modulation der Impulsbreite kodiert. Die Breite des Abstands nach dem Impuls-Burst bleibt konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Diese Methode ist auch als Manchester encoding bekannt. Der logische Wert wird durch die Polarität des Übergangs zwischen Impuls-Burst und Abstand bestimmt. „Abstand zu Impuls-Burst“ bedeutet logisch „0“, „Impuls-Burst zu Abstand“ bedeutet logisch „1“.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombination der vorherigen Verfahren und andere exotische Verfahren**

> [!TIP]
> Es gibt IR-Protokolle, die **versuchen, für mehrere Gerätetypen universell zu werden**. Die bekanntesten sind RC5 und NEC. Leider bedeutet **am bekanntesten nicht am weitesten verbreitet**. In meiner Umgebung sind mir nur zwei NEC-Fernbedienungen und keine RC5-Fernbedienung begegnet.
>
> Hersteller verwenden gerne ihre eigenen, einzigartigen IR-Protokolle, sogar innerhalb desselben Gerätebereichs (zum Beispiel TV-Boxen). Daher können Fernbedienungen verschiedener Unternehmen und manchmal sogar verschiedener Modelle desselben Unternehmens nicht mit anderen Geräten desselben Typs verwendet werden.

### Untersuchung eines IR-Signals

Die zuverlässigste Methode, zu sehen, wie das IR-Signal einer Fernbedienung aussieht, ist die Verwendung eines Oszilloskops. Es demoduliert oder invertiert das empfangene Signal nicht, sondern zeigt es einfach „wie empfangen“ an. Dies ist zum Testen und Debuggen hilfreich. Ich zeige das erwartete Signal am Beispiel des NEC-IR-Protokolls.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalerweise befindet sich am Anfang eines kodierten Pakets eine Präambel. Dadurch kann der Empfänger die Verstärkung und den Hintergrund bestimmen. Es gibt auch Protokolle ohne Präambel, zum Beispiel Sharp.

Anschließend werden die Daten übertragen. Struktur, Präambel und Bitkodierungsmethode werden durch das jeweilige Protokoll bestimmt.

Das **NEC-IR-Protokoll** enthält einen kurzen Befehl und einen Repeat-Code, der gesendet wird, solange die Taste gedrückt wird. Sowohl der Befehl als auch der Repeat-Code haben am Anfang dieselbe Präambel.

Der NEC-**Befehl** besteht zusätzlich zur Präambel aus einem Adressbyte und einem Befehlsnummernbyte, anhand derer das Gerät versteht, was ausgeführt werden soll. Adress- und Befehlsnummernbytes werden mit invertierten Werten dupliziert, um die Integrität der Übertragung zu prüfen. Am Ende des Befehls befindet sich ein zusätzliches Stopbit.

Der **Repeat-Code** enthält nach der Präambel eine „1“, bei der es sich um ein Stopbit handelt.

Für **logisch „0“ und „1“** verwendet NEC Pulse Distance Encoding: Zuerst wird ein Impuls-Burst übertragen, auf den eine Pause folgt. Ihre Länge bestimmt den Wert des Bits.

### Klimaanlagen

Im Gegensatz zu anderen Fernbedienungen **übertragen Klimaanlagen nicht nur den Code der gedrückten Taste**. Sie **übertragen außerdem alle Informationen**, wenn eine Taste gedrückt wird, um sicherzustellen, dass **Klimaanlage und Fernbedienung synchronisiert sind**.\
Dadurch wird verhindert, dass eine auf 20 °C eingestellte Anlage mit einer Fernbedienung auf 21 °C erhöht wird und anschließend eine andere Fernbedienung verwendet wird, die weiterhin 20 °C anzeigt und die Temperatur weiter erhöhen soll. Sie würde sie auf 21 °C (und nicht auf 22 °C) „erhöhen“, da sie davon ausgeht, dass bereits 21 °C eingestellt sind.<sup>[[1]](#references)</sup>

---

## Angriffe & Offensive Research <a href="#attacks" id="attacks"></a>

Du kannst Infrarot mit Flipper Zero angreifen:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

Aktuelle akademische Forschung (EvilScreen, 2022) hat gezeigt, dass **Multi-Channel-Fernbedienungen, die Infrarot mit Bluetooth oder Wi-Fi kombinieren, dazu missbraucht werden können, moderne Smart-TVs vollständig zu hijacken**. Der Angriff kombiniert privilegierte IR-Service-Codes mit authentifizierten Bluetooth-Paketen, umgeht die Kanalisolierung und ermöglicht das Starten beliebiger Apps, die Aktivierung des Mikrofons oder das Zurücksetzen auf Werkseinstellungen ohne physischen Zugriff. Acht Mainstream-TVs verschiedener Hersteller — darunter ein Samsung-Modell, das die Einhaltung von ISO/IEC 27001 angibt — wurden als verwundbar bestätigt. Zur Abwehr sind Firmware-Fixes des Herstellers oder die vollständige Deaktivierung ungenutzter IR-Empfänger erforderlich.<sup>[[2]](#references)</sup>

### Air-Gapped Data Exfiltration via IR LEDs (aIR-Jumper family)

Sicherheitskameras enthalten häufig **IR-LEDs für Nachtsicht**. Der aIR-Jumper-Prototyp zeigte, dass Malware, die diese LEDs kontrolliert, Geheimnisse durch Fenster an eine externe Kamera **exfiltrieren** kann — mit bis zu **20 Bit/s pro Überwachungskamera** über Distanzen von mehreren Dutzend Metern. In umgekehrter Richtung demonstrierten die Forscher eine Infiltration mit mehr als **100 Bit/s** über Entfernungen von mehreren Hundert Metern bis zu Kilometern.<sup>[[3]](#references)</sup> Da sich das Licht außerhalb des sichtbaren Spektrums befindet, bemerken Betreiber es möglicherweise nicht. Zu den Gegenmaßnahmen gehören:

* IR-LEDs in sensiblen Bereichen physisch abschirmen oder entfernen
* LED-Tastverhältnis und Firmware-Integrität der Kamera überwachen
* IR-Cut-Filter an Fenstern und Überwachungskameras einsetzen

Ein Angreifer kann außerdem starke IR-Projektoren verwenden, um Befehle durch das Zurückblinken von Daten in unsichere Kameras in das Netzwerk zu **infiltrieren**.

### Long-Range Brute-Force & Extended Protocols with Flipper Zero 1.0

Firmware 1.0 (September 2024) erweiterte die Bibliothek für Universal-Fernbedienungen und fügte das dynamische Laden von Infrarot-Asset-Dateien von microSD hinzu.<sup>[[4]](#references)</sup> Die Lern- und Universal-Fernbedienungsfunktionen können bekannte Befehle gegen nahegelegene Fernseher und Klimaanlagen wiedergeben oder ausprobieren. Die Reichweite hängt stark vom Emitter, der Optik, dem Umgebungslicht und dem Empfänger ab; externe IR-Hardware kann sie erhöhen, eine feste Entfernung sollte jedoch nicht angenommen werden.

---

## Tooling & Praktische Beispiele <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – tragbarer Transceiver mit Lern-, Replay- und Dictionary-Bruteforce-Modi (siehe oben).
* **Arduino / ESP32** + IR-LED / TSOP38xx-Empfänger – günstiger DIY-Analyser/Transmitter. Kombiniere ihn mit der `Arduino-IRremote`-Bibliothek (v4.x unterstützt mehr als 40 Protokolle).
* **Logikanalysatoren** (Saleae/FX2) – erfassen Roh-Timings, wenn das Protokoll unbekannt ist.
* **Smartphones mit IR-Blaster** (z. B. Xiaomi) – schneller Field-Test, aber mit begrenzter Reichweite.

### Software

* **`Arduino-IRremote`** – aktiv gepflegte C++-Bibliothek:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI-Decoder, die Rohaufzeichnungen importieren, das Protokoll automatisch identifizieren und Pronto-/Arduino-Code erzeugen.
* **LIRC / ir-keytable (Linux)** – IR über die Kommandozeile empfangen und injizieren:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Maßnahmen <a href="#defense" id="defense"></a>

* IR-Empfänger an Geräten deaktivieren oder abdecken, die an öffentlichen Orten eingesetzt werden, sofern sie nicht benötigt werden.
* *Pairing* oder kryptografische Prüfungen zwischen Smart-TVs und Fernbedienungen erzwingen; privilegierte „Service“-Codes isolieren.
* IR-Cut-Filter oder Continuous-Wave-Detektoren in der Umgebung klassifizierter Bereiche einsetzen, um optische Covert Channels zu unterbrechen.
* Die Firmware-Integrität von Kameras/IoT-Geräten überwachen, die steuerbare IR-LEDs bereitstellen.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero Blog - Firmware 1.0 Released](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - usage and protocol documentation](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
