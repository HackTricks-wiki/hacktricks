# Infrarot

{{#include ../../banners/hacktricks-training.md}}

## So funktioniert Infrarot <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarotlicht ist für Menschen unsichtbar**. Die IR-Wellenlänge reicht von **0,7 bis 1000 Mikrometern**. Haushaltsfernbedienungen verwenden ein IR-Signal zur Datenübertragung und arbeiten im Wellenlängenbereich von 0,75..1,4 Mikrometern. Ein Mikrocontroller in der Fernbedienung lässt eine Infrarot-LED mit einer bestimmten Frequenz blinken und wandelt so das digitale Signal in ein IR-Signal um.

Zum Empfang von IR-Signalen wird ein **Fotoreceiver** verwendet. Er **wandelt IR-Licht in Spannungsimpulse um**, die bereits **digitale Signale** sind. Normalerweise befindet sich im Receiver ein **Dunkellichtfilter**, der **nur die gewünschte Wellenlänge durchlässt** und Störungen herausfiltert.<sup>[[1]](#references)</sup>

### Vielfalt der IR-Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-Protokolle unterscheiden sich in 3 Faktoren:<sup>[[1]](#references)</sup>

- Bitcodierung
- Datenstruktur
- Trägerfrequenz — häufig im Bereich von 36..38 kHz

#### Verfahren zur Bitcodierung <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulsabstandsmodulation**

Bits werden durch Modulation der Dauer des Abstands zwischen den Impulsen codiert. Die Breite des Impulses selbst bleibt konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulsbreitenmodulation**

Bits werden durch Modulation der Impulsbreite codiert. Die Länge des Abstands nach dem Impulsburst bleibt konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phasencodierung**

Sie ist auch als Manchester-Codierung bekannt. Der logische Wert wird durch die Polarität des Übergangs zwischen Impulsburst und Pause bestimmt. „Pause zu Impulsburst“ steht für die Logik „0“, „Impulsburst zu Pause“ für die Logik „1“.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombination der vorherigen Verfahren und anderer Exoten**

> [!TIP]
> Es gibt IR-Protokolle, die **universell für mehrere Gerätetypen werden sollen**. Die bekanntesten sind RC5 und NEC. Leider bedeutet **am bekanntesten nicht am weitesten verbreitet**. In meinem Umfeld bin ich nur auf zwei NEC-Fernbedienungen und keine RC5-Fernbedienung gestoßen.
>
> Hersteller verwenden gern eigene, einzigartige IR-Protokolle, sogar innerhalb derselben Gerätekategorie (zum Beispiel TV-Boxen). Deshalb können Fernbedienungen verschiedener Hersteller und manchmal sogar verschiedener Modelle desselben Herstellers nicht mit anderen Geräten desselben Typs funktionieren.

### Ein IR-Signal untersuchen

Am zuverlässigsten lässt sich das IR-Signal einer Fernbedienung mit einem Oszilloskop anzeigen. Es demoduliert oder invertiert das empfangene Signal nicht, sondern zeigt es einfach „unverändert“ an. Das ist für Tests und Debugging nützlich. Das erwartete Signal zeige ich am Beispiel des NEC-IR-Protokolls.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Am Anfang eines codierten Pakets befindet sich normalerweise eine Präambel. Dadurch kann der Receiver die Verstärkung und den Hintergrundpegel bestimmen. Es gibt auch Protokolle ohne Präambel, zum Beispiel Sharp.

Danach werden Daten übertragen. Struktur, Präambel und Bitcodierungsverfahren hängen vom jeweiligen Protokoll ab.

Das **NEC-IR-Protokoll** enthält einen kurzen Befehl und einen Wiederholungscode, der gesendet wird, solange die Taste gedrückt ist. Sowohl der Befehl als auch der Wiederholungscode haben dieselbe Präambel am Anfang.

Der **NEC-Befehl** besteht zusätzlich zur Präambel aus einem Adressbyte und einem Befehlsnummernbyte, anhand derer das Gerät erkennt, was ausgeführt werden soll. Adress- und Befehlsnummernbytes werden mit inversen Werten dupliziert, um die Integrität der Übertragung zu prüfen. Am Ende des Befehls befindet sich ein zusätzliches Stoppbit.

Der **Wiederholungscode** enthält nach der Präambel eine „1“, die als Stoppbit dient.

Für die **Logik „0“ und „1“** verwendet NEC die Pulsabstandsmodulation: Zuerst wird ein Impulsburst übertragen, auf den eine Pause folgt. Ihre Länge bestimmt den Wert des Bits.

### Klimaanlagen

Im Gegensatz zu anderen Fernbedienungen übertragen **Klimaanlagen nicht nur den Code der gedrückten Taste**. Bei einem Tastendruck **übertragen sie auch alle Informationen**, damit **Klimaanlage und Fernbedienung synchronisiert bleiben**.\
So wird verhindert, dass eine auf 20 ºC eingestellte Klimaanlage mit einer Fernbedienung auf 21 ºC erhöht wird und dann bei Verwendung einer anderen Fernbedienung, die noch auf 20 ºC eingestellt ist, die Temperatur ebenfalls auf 21 ºC „erhöht“ wird (anstatt sie auf 22 ºC zu setzen, weil die Fernbedienung von 21 ºC ausgeht).<sup>[[1]](#references)</sup>

---

## Angriffe & offensive Forschung <a href="#attacks" id="attacks"></a>

Mit Flipper Zero kannst du Infrarot angreifen:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Übernahme von Smart-TVs und Set-Top-Boxen (EvilScreen)

Aktuelle akademische Arbeiten (EvilScreen, 2022) zeigten, dass **Mehrkanal-Fernbedienungen, die Infrarot mit Bluetooth oder Wi-Fi kombinieren, missbraucht werden können, um moderne Smart-TVs vollständig zu übernehmen**. Der Angriff verkettet IR-Servicecodes mit hohen Berechtigungen mit authentifizierten Bluetooth-Paketen, umgeht die Kanalisolierung und ermöglicht das Starten beliebiger Apps, die Aktivierung des Mikrofons oder ein Zurücksetzen auf Werkseinstellungen – ohne physischen Zugriff. Acht gängige Fernseher verschiedener Hersteller – darunter ein Samsung-Modell, das die Konformität mit ISO/IEC 27001 angibt – erwiesen sich als verwundbar. Zur Abhilfe sind Firmware-Updates der Hersteller oder die vollständige Deaktivierung ungenutzter IR-Receiver erforderlich.<sup>[[2]](#references)</sup>

### Datenexfiltration über IR-LEDs bei Air-Gapped-Systemen (aIR-Jumper-Familie)

Überwachungskameras verfügen häufig über **IR-LEDs für Nachtsicht**. Der aIR-Jumper-Prototyp zeigte, dass Malware, die diese LEDs steuert, **Geheimnisse durch Fenster an eine externe Kamera exfiltrieren kann** – mit bis zu **20 Bit/s pro Überwachungskamera** über mehrere zehn Meter. In umgekehrter Richtung demonstrierten die Forschenden eine Infiltration mit mehr als **100 Bit/s** über Entfernungen von mehreren hundert Metern bis hin zu Kilometern.<sup>[[3]](#references)</sup> Da das Licht außerhalb des sichtbaren Spektrums liegt, bemerken Bediener es möglicherweise nicht. Zu den Gegenmaßnahmen gehören:

* IR-LEDs in sensiblen Bereichen physisch abschirmen oder entfernen
* Einschaltdauer der Kamera-LEDs und Firmware-Integrität überwachen
* IR-Sperrfilter an Fenstern und Überwachungskameras anbringen

Ein Angreifer kann auch leistungsstarke IR-Projektoren verwenden, um Befehle ins Netzwerk **einzuschleusen**, indem er Daten an unsichere Kameras zurückblinken lässt.

### Brute-Force-Angriffe über große Entfernungen und erweiterte Protokolle mit Flipper Zero 1.0

Firmware 1.0 (September 2024) erweiterte die Bibliothek der Universalfernbedienungen und fügte das dynamische Laden von Infrarot-Asset-Dateien von microSD hinzu.<sup>[[4]](#references)</sup> Mit den Lern- und Universalfernbedienungsfunktionen lassen sich bekannte Befehle an nahegelegene Fernseher und Klimaanlagen erneut senden oder ausprobieren. Die Reichweite hängt stark vom Emitter, der Optik, dem Umgebungslicht und dem Receiver ab. Externe IR-Hardware kann die Reichweite erhöhen, aber man sollte nicht von einer festen Entfernung ausgehen.

---

## Tools & praktische Beispiele <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – tragbarer Transceiver mit Lern-, Replay- und Dictionary-Brute-Force-Modi (siehe oben).
* **Arduino / ESP32** + IR-LED / TSOP38xx-Receiver – günstiger DIY-Analysator/Transmitter. Kombinierbar mit der `Arduino-IRremote`-Bibliothek (v4.x unterstützt >40 Protokolle).
* **Logikanalysatoren** (Saleae/FX2) – erfassen Rohdaten-Timings, wenn das Protokoll unbekannt ist.
* **Smartphones mit IR-Blaster** (z. B. Xiaomi) – schneller Test vor Ort, aber mit begrenzter Reichweite.

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
* **IRscrutinizer / AnalysIR** – GUI-Decoder, die Rohaufzeichnungen importieren, Protokolle automatisch identifizieren und Pronto-/Arduino-Code generieren.
* **LIRC / ir-keytable (Linux)** – IR über die Kommandozeile empfangen und einspeisen:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Abwehrmaßnahmen <a href="#defense" id="defense"></a>

* Deaktivieren oder verdecken Sie IR-Empfänger an Geräten in öffentlichen Bereichen, wenn diese nicht benötigt werden.
* Erzwingen Sie *Pairing* oder kryptografische Prüfungen zwischen Smart-TVs und Fernbedienungen; isolieren Sie privilegierte „Service“-Codes.
* Installieren Sie IR-Sperrfilter oder Dauerstrahlungsdetektoren in der Nähe von klassifizierten Bereichen, um optische verdeckte Kanäle zu unterbrechen.
* Überwachen Sie die Firmware-Integrität von Kameras und IoT-Geräten mit steuerbaren IR-LEDs.

## References

- [1] [Flipper Zero-Infrarot-Blogbeitrag](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen-Angriff: Übernahme von Smart-TVs durch Nachahmung einer Mehrkanal-Fernbedienung (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Verdeckte Exfiltration/Infiltration über Air-Gaps mittels Überwachungskameras und Infrarot (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero Blog – Firmware 1.0 veröffentlicht](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote – Verwendung und Protokolldokumentation](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
