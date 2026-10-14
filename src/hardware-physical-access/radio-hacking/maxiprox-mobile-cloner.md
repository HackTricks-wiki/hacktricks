# Bau eines tragbaren HID MaxiProx 125-kHz-Mobile-Cloners

{{#include ../../banners/hacktricks-training.md}}

## Ziel
Einen netzbetriebenen HID MaxiProx 5375-Langstreckenleser mit 125 kHz in einen vor Ort einsetzbaren, batteriebetriebenen Badge-Cloner umbauen, der bei physischen Sicherheitsprüfungen unauffällig Proximity-Karten erfasst.

Der hier beschriebene Umbau basiert auf TrustedSecs Forschungsreihe „Let’s Clone a Cloner – Part 3: Putting It All Together“ und vereint mechanische, elektrische und HF-Aspekte, damit das fertige Gerät im Rucksack transportiert und vor Ort sofort eingesetzt werden kann.<sup>[[1]](#references)</sup>

> [!warning]
> Der Umgang mit netzbetriebenen Geräten und Lithium-Ionen-Powerbanks kann gefährlich sein. Prüfe jede Verbindung **vor** dem Einschalten der Schaltung und belasse Antennen, Koaxialkabel und Masseflächen exakt wie im Werksdesign, um eine Verstimmung des Lesers zu vermeiden.

## Stückliste (BOM)

* HID MaxiProx 5375-Leser (oder ein beliebiger HID Prox®-Langstreckenleser mit 12 V)
* ESP RFID Tool v2.2 (Wiegand-Sniffer/Logger auf ESP32-Basis)
* USB-PD-Trigger-Modul, das 12 V bei ≥3 A aushandeln kann
* 100-W-USB-C-Powerbank (gibt ein 12-V-PD-Profil aus)
* Anschlussdraht mit Silikonisolierung, 26 AWG – rot/weiß
* SPST-Kippschalter zur Panelmontage (für den Beeper-Kill-Switch)
* NKK AT4072-Schalterschutz / Schutzkappe gegen versehentliches Betätigen
* Lötkolben, Entlötlitze und Entlötpumpe
* Für ABS geeignete Handwerkzeuge: Laubsäge, Cuttermesser, Flach- und Halbrundfeilen
* Bohrer 1/16″ (1,5 mm) und 1/8″ (3 mm)
* Doppelseitiges 3 M VHB-Klebeband und Kabelbinder

## 1. Stromversorgung

1. Die werkseitige Buck-Converter-Tochterplatine, die 5 V für die Logikplatine erzeugt, auslöten und entfernen.
2. Einen USB-PD-Trigger neben dem ESP RFID Tool montieren und dessen USB-C-Buchse nach außen aus dem Gehäuse führen.
3. Der PD-Trigger handelt 12 V von der Powerbank aus und speist sie direkt in den MaxiProx ein (der Leser benötigt nativ 10–14 V). Eine zusätzliche 5-V-Schiene wird von der ESP-Platine abgegriffen, um Zubehör mit Strom zu versorgen.
4. Das 100-W-Akkupack bündig an der internen Abstandsstütze positionieren, sodass **keine** Stromkabel über die Ferritantenne verlaufen und die HF-Leistung erhalten bleibt.

## 2. Beeper-Kill-Switch – geräuschloser Betrieb

1. Die beiden Lautsprecherpads auf der MaxiProx-Logikplatine lokalisieren.
2. *Beide* Pads sauber entlöten und anschließend nur das **negative** Pad wieder anlöten.
3. 26-AWG-Drähte (weiß = negativ, rot = positiv) an die Beeper-Pads löten und durch einen neu geschnittenen Schlitz zu einem SPST-Schalter für die Panelmontage führen.
4. Ist der Schalter geöffnet, ist der Beeper-Stromkreis unterbrochen und der Leser arbeitet völlig geräuschlos – ideal für das unauffällige Erfassen von Badges.
5. Eine federbelastete NKK AT4072-Sicherheitskappe über dem Kippschalter anbringen. Die Bohrung vorsichtig mit Laubsäge und Feile vergrößern, bis die Kappe über den Schalterkörper einrastet. Die Abdeckung verhindert ein versehentliches Einschalten im Rucksack.

## 3. Gehäuse und mechanische Arbeiten

• Den internen ABS-„Vorsprung“ mit einem Seitenschneider und anschließend Messer und Feile *entfernen*, damit die große USB-C-Batterie flach auf der Abstandsstütze aufliegt.
• Zwei parallele Kanäle in die Gehäusewand für das USB-C-Kabel schneiden. Dadurch wird die Batterie fixiert und Bewegung bzw. Vibration werden verhindert.
• Eine rechteckige Öffnung für den **Power**-Knopf der Batterie anfertigen:
  1. Eine Papierschablone über die Stelle kleben.
  2. In alle vier Ecken 1/16″-Führungslöcher bohren.
  3. Mit einem 1/8″-Bohrer vergrößern.
  4. Die Löcher mit einer Laubsäge verbinden und die Kanten mit einer Feile glätten.  
  ✱ Ein rotierendes Dremel-Werkzeug wurde *nicht verwendet* – der Hochgeschwindigkeitsbohrer schmilzt dickes ABS und hinterlässt eine unsaubere Kante.

## 4. Endmontage

1. Die MaxiProx-Logikplatine wieder einsetzen und den SMA-Pigtail wieder an das Massepad der Leserplatine löten.
2. Das ESP RFID Tool und den USB-PD-Trigger mit 3 M VHB befestigen.
3. Alle Kabel mit Kabelbindern ordentlich verlegen und die Stromleitungen **weit** von der Antennenschleife entfernt halten.
4. Die Gehäuseschrauben festziehen, bis die Batterie leicht zusammengedrückt wird; die interne Reibung verhindert, dass sich das Akkupack verschiebt, wenn das Gerät nach jedem Kartenauslesen zurückfedert.

## 5. Reichweiten- und Abschirmungstests

* Mit einer 125-kHz-**Pupa**-Testkarte erreichte der tragbare Cloner im Freifeld konstant **≈ 8 cm** – genauso viel wie im Netzbetrieb.<sup>[[1]](#references)</sup>
* Wurde der Leser in eine dünnwandige Metallkassette gelegt (als Simulation eines Bankschaltertischs), sank die Reichweite auf ≤ 2 cm. Das bestätigt, dass größere Metallgehäuse als wirksame HF-Abschirmung dienen.<sup>[[1]](#references)</sup>

## Nutzung

1. Die USB-C-Batterie laden, anschließen und den Hauptschalter umlegen.
2. (Optional) Die Beeper-Abdeckung öffnen und bei Tests am Arbeitstisch akustisches Feedback einschalten; vor dem unauffälligen Einsatz vor Ort wieder sichern.
3. Am Ziel-Badge-Inhaber vorbeigehen – der MaxiProx aktiviert die Karte und das ESP RFID Tool erfasst den Wiegand-Datenstrom.
4. Erfasste Zugangsdaten per Wi-Fi oder USB-UART auslesen und bei Bedarf replayen/klonen.

## Fehlerbehebung

| Symptom | Wahrscheinliche Ursache | Lösung |
|---------|------------------------------|------|
| Leser startet beim Vorhalten einer Karte neu | PD-Trigger hat 9 V statt 12 V ausgehandelt | Trigger-Jumper prüfen / ein leistungsfähigeres USB-C-Kabel ausprobieren |
| Keine Lesereichweite | Batterie oder Kabel liegen *auf* der Antenne | Kabel neu verlegen und 2 cm Abstand zur Ferritschleife einhalten |
| Beeper gibt weiterhin Töne aus | Schalter ist statt in die negative Leitung in die positive Leitung eingebaut | Kill-Switch so verlegen, dass die **negative** Lautsprecherleitung unterbrochen wird |

## References

- [1] [Einen Cloner klonen – Teil 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)
{{#include ../../banners/hacktricks-training.md}}