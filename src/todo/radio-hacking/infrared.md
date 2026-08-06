# Infrarot

{{#include ../../banners/hacktricks-training.md}}

## Funktionsweise von Infrarot <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarotlicht ist für Menschen unsichtbar**. Die IR-Wellenlänge reicht von **0,7 bis 1000 Mikrometern**. Haushaltsfernbedienungen verwenden ein IR-Signal zur Datenübertragung und arbeiten in einem Wellenlängenbereich von 0,75 bis 1,4 Mikrometern. Ein Mikrocontroller in der Fernbedienung lässt eine Infrarot-LED mit einer bestimmten Frequenz blinken und wandelt dadurch das digitale Signal in ein IR-Signal um.

Zum Empfangen von IR-Signalen wird ein **Fotodetektor** verwendet. Er **wandelt IR-Licht in Spannungspulse um**, die bereits **digitale Signale** sind. Normalerweise befindet sich im Empfänger ein **Filter für sichtbares Licht**, der **nur die gewünschte Wellenlänge durchlässt** und Störungen herausfiltert.<sup>[[1]](#references)</sup>

### Vielfalt der IR-Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-Protokolle unterscheiden sich in 3 Faktoren:<sup>[[1]](#references)</sup>

- Bitkodierung
- Datenstruktur
- Trägerfrequenz — häufig im Bereich von 36 bis 38 kHz

#### Methoden der Bitkodierung <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits werden durch die Modulation der Dauer des Abstands zwischen den Pulsen kodiert. Die Breite des Pulses selbst bleibt konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits werden durch die Modulation der Pulsbreite kodiert. Die Breite des Abstands nach dem Puls-Burst bleibt konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Dies ist auch als Manchester-Kodierung bekannt. Der logische Wert wird durch die Polarität des Übergangs zwischen Puls-Burst und Abstand bestimmt. „Abstand zu Puls-Burst“ steht für die logische „0“, „Puls-Burst zu Abstand“ steht für die logische „1“.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombination der vorherigen Methoden und andere exotische Varianten**

> [!TIP]
> Es gibt IR-Protokolle, die **versuchen, für mehrere Gerätetypen universell** zu werden. Die bekanntesten sind RC5 und NEC. Leider bedeutet **am bekanntesten nicht am weitesten verbreitet**. In meiner Umgebung bin ich nur zwei NEC-Fernbedienungen und keiner mit RC5 begegnet.
>
> Hersteller verwenden gerne ihre eigenen, einzigartigen IR-Protokolle, sogar innerhalb derselben Geräteklasse (beispielsweise TV-Boxen). Daher können Fernbedienungen verschiedener Unternehmen und manchmal sogar verschiedener Modelle desselben Unternehmens nicht mit anderen Geräten desselben Typs verwendet werden.

### Untersuchung eines IR-Signals

Die zuverlässigste Methode, um zu sehen, wie das IR-Signal einer Fernbedienung aussieht, ist die Verwendung eines Oszilloskops. Es demoduliert oder invertiert das empfangene Signal nicht, sondern zeigt es einfach „so wie es ist“ an. Dies ist zum Testen und Debuggen nützlich. Ich zeige das erwartete Signal am Beispiel des NEC-IR-Protokolls.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalerweise gibt es am Anfang eines kodierten Pakets eine Präambel. Dadurch kann der Empfänger den Verstärkungsgrad und den Hintergrund bestimmen. Es gibt auch Protokolle ohne Präambel, beispielsweise Sharp.

Anschließend werden die Daten übertragen. Struktur, Präambel und Bitkodierungsmethode werden durch das jeweilige Protokoll bestimmt.

Das **NEC-IR-Protokoll** enthält einen kurzen Befehl und einen Wiederholungscode, der gesendet wird, solange die Taste gedrückt bleibt. Sowohl der Befehl als auch der Wiederholungscode besitzen am Anfang dieselbe Präambel.

Der NEC-**Befehl** besteht zusätzlich zur Präambel aus einem Adressbyte und einem Befehlsnummernbyte, anhand derer das Gerät versteht, was ausgeführt werden soll. Adress- und Befehlsnummernbytes werden mit invertierten Werten dupliziert, um die Integrität der Übertragung zu prüfen. Am Ende des Befehls gibt es ein zusätzliches Stoppbit.

Der **Wiederholungscode** enthält nach der Präambel eine „1“, bei der es sich um ein Stoppbit handelt.

Für die **Logik „0“ und „1“** verwendet NEC Pulse Distance Encoding: Zuerst wird ein Puls-Burst übertragen, auf den eine Pause folgt. Ihre Länge legt den Wert des Bits fest.

### Klimaanlagen

Im Gegensatz zu anderen Fernbedienungen übertragen **Klimaanlagen nicht nur den Code der gedrückten Taste**. Sie **übertragen außerdem sämtliche Informationen**, wenn eine Taste gedrückt wird, um sicherzustellen, dass **Klimaanlage und Fernbedienung synchronisiert** sind.\
Dadurch wird verhindert, dass eine auf 20 °C eingestellte Klimaanlage mit einer Fernbedienung auf 21 °C erhöht wird und anschließend eine andere Fernbedienung, die weiterhin eine Temperatur von 20 °C anzeigt, die Temperatur erneut auf 21 °C „erhöht“ (statt auf 22 °C, weil sie davon ausgeht, dass bereits 21 °C eingestellt sind).<sup>[[1]](#references)</sup>

---

## Angriffe und offensive Forschung <a href="#attacks" id="attacks"></a>

Du kannst Infrarot mit Flipper Zero angreifen:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Übernahme von Smart-TVs / Set-top-Boxen (EvilScreen)

Jüngere akademische Forschung (EvilScreen, 2022) hat gezeigt, dass **Mehrkanal-Fernbedienungen, die Infrarot mit Bluetooth oder Wi-Fi kombinieren, missbraucht werden können, um moderne Smart-TVs vollständig zu hijacken**. Der Angriff kombiniert privilegierte IR-Servicecodes mit authentifizierten Bluetooth-Paketen, umgeht die Kanalisolierung und ermöglicht das Starten beliebiger Apps, die Aktivierung des Mikrofons oder das Zurücksetzen auf Werkseinstellungen ohne physischen Zugriff. Acht gängige TVs verschiedener Hersteller — darunter ein Samsung-Modell, das die Konformität mit ISO/IEC 27001 angab — wurden als verwundbar bestätigt. Zur Abwehr sind Firmware-Fixes der Hersteller oder die vollständige Deaktivierung nicht benötigter IR-Empfänger erforderlich.<sup>[[2]](#references)</sup>

### Exfiltration von Daten aus Air-Gapped-Systemen über IR-LEDs (aIR-Jumper-Familie)

Sicherheitskameras, Router oder sogar schädliche USB-Sticks enthalten häufig **IR-LEDs für Nachtsicht**. Untersuchungen zeigen, dass Malware diese LEDs modulieren kann (<10–20 kbit/s mit einfachem OOK), um **Geheimnisse durch Wände und Fenster** an eine externe Kamera zu **exfiltrieren**, die sich in einer Entfernung von mehreren Dutzend Metern befindet.<sup>[[3]](#references)</sup> Da das Licht außerhalb des sichtbaren Spektrums liegt, bemerken Bediener dies nur selten. Gegenmaßnahmen:

* IR-LEDs in sensiblen Bereichen physisch abschirmen oder entfernen
* LED-Tastverhältnis und Firmware-Integrität der Kameras überwachen
* IR-Sperrfilter an Fenstern und Überwachungskameras einsetzen

Ein Angreifer kann außerdem starke IR-Projektoren verwenden, um durch das Aufblitzen von Daten Befehle in das Netzwerk **einzuschleusen**, und zwar über unsichere Kameras.

### Brute-Force über große Entfernungen und erweiterte Protokolle mit Flipper Zero 1.0

Firmware 1.0 (September 2024) fügte **Dutzende zusätzlicher IR-Protokolle und optionale externe Verstärkermodule** hinzu. In Kombination mit dem Universal-Fernbedienungs-Brute-Force-Modus kann ein Flipper die meisten öffentlichen TVs und Klimaanlagen aus bis zu 30 m Entfernung mit einer Hochleistungsdiode deaktivieren oder neu konfigurieren.

---

## Tools und praktische Beispiele <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – tragbarer Transceiver mit Lern-, Replay- und Dictionary-Brute-Force-Modi (siehe oben).
* **Arduino / ESP32** + IR-LED / TSOP38xx-Empfänger – günstiger DIY-Analysator/-Sender. Mit der Bibliothek `Arduino-IRremote` kombinieren (v4.x unterstützt mehr als 40 Protokolle).
* **Logikanalysatoren** (Saleae/FX2) – erfassen Roh-Timings, wenn das Protokoll unbekannt ist.
* **Smartphones mit IR-Blaster** (z. B. Xiaomi) – schneller Test im Feld, jedoch mit begrenzter Reichweite.

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
* **IRscrutinizer / AnalysIR** – GUI-Decoder, die Rohaufzeichnungen importieren, das Protokoll automatisch identifizieren und Pronto-/Arduino-Code generieren.
* **LIRC / ir-keytable (Linux)** – IR über die Kommandozeile empfangen und einschleusen:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Maßnahmen <a href="#defense" id="defense"></a>

* IR-Empfänger an Geräten deaktivieren oder abdecken, die in öffentlichen Bereichen eingesetzt werden, wenn sie nicht benötigt werden.
* *Pairing* oder kryptografische Prüfungen zwischen Smart-TVs und Fernbedienungen erzwingen; privilegierte „Service“-Codes isolieren.
* IR-Sperrfilter oder Detektoren für kontinuierliche Wellen rund um vertrauliche Bereiche einsetzen, um optische verdeckte Kanäle zu unterbrechen.
* Die Firmware-Integrität von Kameras und IoT-Geräten überwachen, die steuerbare IR-LEDs bereitstellen.

## Referenzen

- [1] [Flipper Zero Infrarot-Blogbeitrag](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
