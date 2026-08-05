# Infrarot

{{#include ../../banners/hacktricks-training.md}}

## Wie Infrarot funktioniert <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarotlicht ist für Menschen unsichtbar**. Die IR-Wellenlänge reicht von **0,7 bis 1000 Mikrometern**. Haushaltsfernbedienungen verwenden ein IR-Signal zur Datenübertragung und arbeiten im Wellenlängenbereich von 0,75..1,4 Mikrometern. Ein Mikrocontroller in der Fernbedienung lässt eine Infrarot-LED mit einer bestimmten Frequenz blinken und wandelt das digitale Signal in ein IR-Signal um.<sup>[[1]](#references)</sup>

Zum Empfangen von IR-Signalen wird ein **Fotodetektor** verwendet. Er **wandelt IR-Licht in Spannungspulse um**, bei denen es sich bereits um **digitale Signale** handelt. Normalerweise befindet sich im Empfänger ein **Filter für dunkles Licht**, der **nur die gewünschte Wellenlänge durchlässt** und Störungen herausfiltert.

### Vielfalt der IR-Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-Protokolle unterscheiden sich in drei Faktoren:

- Bit-Codierung
- Datenstruktur
- Trägerfrequenz — häufig im Bereich von 36..38 kHz

#### Arten der Bit-Codierung <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits werden durch die Modulation der Dauer des Zwischenraums zwischen den Pulsen codiert. Die Breite des Pulses selbst bleibt konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits werden durch die Modulation der Pulsbreite codiert. Die Breite des Zwischenraums nach dem Puls-Burst bleibt konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Dies ist auch als Manchester-Codierung bekannt. Der logische Wert wird durch die Polarität des Übergangs zwischen Puls-Burst und Zwischenraum definiert. „Zwischenraum zu Puls-Burst“ steht für logisch „0“, „Puls-Burst zu Zwischenraum“ steht für logisch „1“.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombination der vorherigen Verfahren und andere Exoten**

> [!TIP]
> Es gibt IR-Protokolle, die **versuchen, für mehrere Gerätetypen universell zu werden**. Die bekanntesten sind RC5 und NEC. Leider bedeutet **am bekanntesten nicht am weitesten verbreitet**. In meiner Umgebung bin ich nur zwei NEC-Fernbedienungen und keiner für RC5 begegnet.
>
> Hersteller verwenden gerne ihre eigenen, einzigartigen IR-Protokolle, sogar innerhalb desselben Gerätesortiments (zum Beispiel TV-Boxen). Daher können Fernbedienungen verschiedener Unternehmen und manchmal auch verschiedener Modelle desselben Unternehmens nicht mit anderen Geräten desselben Typs verwendet werden.

### Untersuchung eines IR-Signals

Die zuverlässigste Methode, zu sehen, wie das IR-Signal einer Fernbedienung aussieht, ist die Verwendung eines Oszilloskops. Es demoduliert oder invertiert das empfangene Signal nicht, sondern zeigt es einfach „wie es ist“ an. Dies ist zum Testen und Debugging nützlich. Ich werde das erwartete Signal am Beispiel des NEC-IR-Protokolls zeigen.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalerweise gibt es am Anfang eines codierten Pakets eine Präambel. Dadurch kann der Empfänger Verstärkungspegel und Hintergrund bestimmen. Es gibt auch Protokolle ohne Präambel, zum Beispiel Sharp.

Anschließend werden die Daten übertragen. Struktur, Präambel und Bit-Codierungsmethode werden durch das jeweilige Protokoll bestimmt.

Das **NEC-IR-Protokoll** enthält einen kurzen Befehl und einen Wiederholungscode, der gesendet wird, solange die Taste gedrückt wird. Sowohl der Befehl als auch der Wiederholungscode haben am Anfang dieselbe Präambel.

Der NEC-**Befehl** besteht zusätzlich zur Präambel aus einem Adressbyte und einem Befehlsnummern-Byte, anhand derer das Gerät versteht, was ausgeführt werden soll. Adress- und Befehlsnummern-Bytes werden mit invertierten Werten dupliziert, um die Integrität der Übertragung zu prüfen. Am Ende des Befehls gibt es ein zusätzliches Stoppbit.

Der **Wiederholungscode** enthält nach der Präambel eine „1“, bei der es sich um ein Stoppbit handelt.

Für **logisch „0“ und „1“** verwendet NEC Pulse Distance Encoding: Zuerst wird ein Puls-Burst übertragen, auf den eine Pause folgt. Ihre Länge bestimmt den Wert des Bits.

### Klimaanlagen

Im Gegensatz zu anderen Fernbedienungen übertragen **Klimaanlagen nicht nur den Code der gedrückten Taste**. Sie **übertragen auch sämtliche Informationen**, wenn eine Taste gedrückt wird, um sicherzustellen, dass **Klimaanlage und Fernbedienung synchronisiert sind**.\
Dadurch wird verhindert, dass eine auf 20 ºC eingestellte Klimaanlage mit einer Fernbedienung auf 21 ºC erhöht wird und anschließend mit einer anderen Fernbedienung, die weiterhin 20 ºC anzeigt, die Temperatur erneut auf 21 ºC statt auf 22 ºC „erhöht“ wird, da sie von 21 ºC ausgeht.

---

## Angriffe & Offensive Research <a href="#attacks" id="attacks"></a>

Du kannst Infrarot mit Flipper Zero angreifen:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Übernahme von Smart-TVs / Set-top-Boxen (EvilScreen)

Aktuelle akademische Forschung (EvilScreen, 2022) hat gezeigt, dass **Mehrkanal-Fernbedienungen, die Infrarot mit Bluetooth oder Wi-Fi kombinieren, missbraucht werden können, um moderne Smart-TVs vollständig zu hijacken**. Der Angriff kombiniert hochprivilegierte IR-Service-Codes mit authentifizierten Bluetooth-Paketen, umgeht die Kanalisolierung und ermöglicht das Starten beliebiger Apps, das Aktivieren des Mikrofons oder einen Factory-Reset ohne physischen Zugriff. Acht gängige Fernseher verschiedener Hersteller — darunter ein Samsung-Modell, das die Einhaltung von ISO/IEC 27001 angibt — wurden als verwundbar bestätigt. Zur Abwehr sind Firmware-Fixes der Hersteller oder die vollständige Deaktivierung nicht verwendeter IR-Empfänger erforderlich.<sup>[[2]](#references)</sup>

### Daten-Exfiltration aus Air-Gapped-Systemen über IR-LEDs (aIR-Jumper-Familie)

Sicherheitskameras, Router oder sogar bösartige USB-Sticks enthalten häufig **IR-LEDs für Nachtsicht**. Untersuchungen zeigen, dass Malware diese LEDs (<10–20 kbit/s mit einfachem OOK) modulieren kann, um **Geheimnisse durch Wände und Fenster hindurch zu exfiltrieren** und an eine externe Kamera zu übertragen, die sich mehrere Dutzend Meter entfernt befindet. Da sich das Licht außerhalb des sichtbaren Spektrums befindet, bemerken Betreiber es nur selten. Gegenmaßnahmen:

* IR-LEDs in sensiblen Bereichen physisch abschirmen oder entfernen
* LED-Tastverhältnis und Firmware-Integrität der Kameras überwachen
* IR-Sperrfilter an Fenstern und Überwachungskameras einsetzen

Ein Angreifer kann außerdem starke IR-Projektoren verwenden, um durch das Blinken von Daten Befehle in das Netzwerk **einzuschleusen**, und zwar über unsichere Kameras.

### Brute-Force über große Entfernungen & erweiterte Protokolle mit Flipper Zero 1.0

Firmware 1.0 (September 2024) fügte **Dutzende zusätzlicher IR-Protokolle und optionale externe Verstärkermodule** hinzu. In Kombination mit dem Universal-Remote-Brute-Force-Modus kann ein Flipper die meisten öffentlichen Fernseher und Klimaanlagen aus bis zu 30 m Entfernung mithilfe einer Hochleistungsdiode deaktivieren oder neu konfigurieren.

---

## Tooling & praktische Beispiele <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – tragbarer Transceiver mit Lern-, Replay- und Dictionary-Brute-Force-Modi (siehe oben).
* **Arduino / ESP32** + IR-LED / TSOP38xx-Empfänger – günstiger DIY-Analyzer/Transmitter. In Kombination mit der `Arduino-IRremote`-Bibliothek verwenden (v4.x unterstützt >40 Protokolle).
* **Logic Analyzer** (Saleae/FX2) – erfasst rohe Zeitmessungen, wenn das Protokoll unbekannt ist.
* **Smartphones mit IR-Blaster** (z. B. Xiaomi) – schneller Feldtest, aber begrenzte Reichweite.

### Software

* **`Arduino-IRremote`** – aktiv gepflegte C++-Bibliothek:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI-Decoder, die rohe Mitschnitte importieren, das Protokoll automatisch identifizieren und Pronto-/Arduino-Code generieren.
* **LIRC / ir-keytable (Linux)** – IR über die Kommandozeile empfangen und injizieren:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Schutzmaßnahmen <a href="#defense" id="defense"></a>

* IR-Empfänger an Geräten deaktivieren oder abdecken, die in öffentlichen Bereichen eingesetzt werden, sofern sie nicht benötigt werden.
* *Pairing* oder kryptografische Prüfungen zwischen Smart-TVs und Fernbedienungen erzwingen; privilegierte „Service“-Codes isolieren.
* IR-Sperrfilter oder Detektoren für kontinuierliche Wellen rund um klassifizierte Bereiche einsetzen, um optische Covert Channels zu unterbrechen.
* Die Firmware-Integrität von Kameras/IoT-Geräten überwachen, die steuerbare IR-LEDs bereitstellen.

## Referenzen

- [1] [Flipper Zero Infrarot-Blogbeitrag](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: Hijacking von Smart-TVs durch Nachahmung von Fernbedienungen](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
