# Aufbau eines tragbaren HID MaxiProx 125 kHz Mobile Cloners

{{#include ../../banners/hacktricks-training.md}}

## Ziel
Einen netzbetriebenen HID MaxiProx 5375 Long-Range-125-kHz-Reader in einen vor Ort einsetzbaren, batteriebetriebenen Badge-Cloner verwandeln, der während physischer Sicherheitsprüfungen unauffällig Proximity-Karten sammelt.

Die hier beschriebene Umrüstung basiert auf der Forschungsreihe „Let’s Clone a Cloner – Part 3: Putting It All Together“ von TrustedSec und berücksichtigt mechanische, elektrische und HF-Aspekte, sodass das fertige Gerät in einen Rucksack passt und sofort vor Ort eingesetzt werden kann.<sup>[[1]](#references)</sup>

> [!warning]
> Der Umgang mit netzbetriebenen Geräten und Lithium-Ionen-Powerbanks kann gefährlich sein. Überprüfe **jede Verbindung**, bevor du den Stromkreis unter Spannung setzt, und belasse Antennen, Koaxialkabel und Masseflächen exakt wie im werkseitigen Design, um eine Verstimmung des Readers zu vermeiden.

## Materialliste (BOM)

* HID MaxiProx 5375 Reader (oder ein beliebiger 12-V-HID-Prox®-Long-Range-Reader)
* ESP RFID Tool v2.2 (Wiegand-Sniffer/Logger auf ESP32-Basis)
* USB-PD-(Power-Delivery-)Trigger-Modul, das 12 V bei ≥3 A aushandeln kann
* 100-W-USB-C-Powerbank (gibt ein 12-V-PD-Profil aus)
* 26-AWG-Silikon-Anschlussdraht – rot/weiß
* SPST-Kippschalter für Panelmontage (zum Abschalten des Beepers)
* NKK AT4072 Schalterabdeckung / Schutzkappe gegen unbeabsichtigte Betätigung
* Lötkolben, Entlötlitze und Entlötpumpe
* ABS-geeignete Handwerkzeuge: Stichsäge, Cuttermesser, Flach- und Halbrundfeilen
* Bohrer 1/16″ (1,5 mm) und 1/8″ (3 mm)
* 3 M VHB-Doppelklebeband und Kabelbinder

## 1. Stromversorgung

1. Entlöte und entferne die werkseitige Buck-Converter-Tochterplatine, die zur Erzeugung von 5 V für die Logikplatine verwendet wird.
2. Montiere einen USB-PD-Trigger neben dem ESP RFID Tool und führe dessen USB-C-Buchse nach außen aus dem Gehäuse.
3. Der PD-Trigger handelt 12 V von der Powerbank aus und speist diese direkt in den MaxiProx ein (der Reader erwartet nativ 10–14 V). Eine sekundäre 5-V-Schiene wird von der ESP-Platine abgegriffen, um Zubehör zu versorgen.
4. Der 100-W-Akku wird bündig an der internen Abstandhalterung positioniert, sodass **keine** Stromkabel über der Ferritantenne verlaufen und die HF-Leistung erhalten bleibt.

## 2. Beeper-Abschaltung – geräuschloser Betrieb

1. Suche die beiden Lautsprecher-Pads auf der MaxiProx-Logikplatine.
2. Entferne das Lot von *beiden* Pads vollständig und verlöte anschließend nur das **negative** Pad erneut.
3. Löte 26-AWG-Kabel (weiß = negativ, rot = positiv) an die Beeper-Pads und führe sie durch einen neu geschnittenen Schlitz zu einem SPST-Schalter für Panelmontage.
4. Wenn der Schalter geöffnet ist, wird der Beeper-Stromkreis unterbrochen und der Reader arbeitet vollständig geräuschlos – ideal zum unauffälligen Sammeln von Badges.
5. Setze eine federbelastete NKK-AT4072-Sicherheitskappe über den Kippschalter. Vergrößere die Öffnung vorsichtig mit einer Stichsäge bzw. Feile, bis sie über den Schalterkörper einrastet. Die Abdeckung verhindert eine versehentliche Aktivierung im Rucksack.

## 3. Gehäuse und mechanische Arbeiten

• Verwende zunächst einen Seitenschneider und anschließend Messer und Feile, um den internen ABS-„Vorsprung“ zu *entfernen*, damit der große USB-C-Akku flach auf der Abstandhalterung aufliegt.
• Schneide zwei parallele Kanäle in die Gehäusewand für das USB-C-Kabel; dadurch wird der Akku fixiert und Bewegung bzw. Vibration werden verhindert.
• Erzeuge eine rechteckige Öffnung für den **Power**-Knopf des Akkus:
1. Klebe eine Papierschablone über die vorgesehene Stelle.
2. Bohre in alle vier Ecken 1/16″-Pilotlöcher.
3. Vergrößere sie mit einem 1/8″-Bohrer.
4. Verbinde die Löcher mit einer Stichsäge und bearbeite die Kanten anschließend mit einer Feile.
✱  Ein rotierendes Dremel wurde *vermieden* – der Hochgeschwindigkeitsfräser schmilzt dicken ABS-Kunststoff und hinterlässt eine unsaubere Kante.

## 4. Endmontage

1. Setze die MaxiProx-Logikplatine wieder ein und verlöte den SMA-Pigtail erneut mit dem Masse-Pad der Reader-PCB.
2. Befestige das ESP RFID Tool und den USB-PD-Trigger mit 3 M VHB.
3. Bündele alle Kabel mit Kabelbindern und halte Stromleitungen **weit** von der Antennenschleife entfernt.
4. Ziehe die Gehäuseschrauben fest, bis der Akku leicht zusammengedrückt wird; die interne Reibung verhindert, dass sich der Akku verschiebt, wenn das Gerät nach jedem Kartenlesen zurückschnellt.

## 5. Tests zu Reichweite und Abschirmung

* Mit einer 125-kHz-**Pupa**-Testkarte erzielte der tragbare Cloner im freien Raum konsistente Lesungen bei **ca. 8 cm** – identisch zum netzbetriebenen Betrieb.<sup>[[1]](#references)</sup>
* Wenn der Reader in eine dünnwandige Metallkassette gelegt wurde (zur Simulation eines Bankschalters), verringerte sich die Reichweite auf ≤ 2 cm. Dies bestätigt, dass umfangreiche Metallgehäuse als wirksame HF-Abschirmungen wirken.<sup>[[1]](#references)</sup>

## Anwendungsablauf

1. Lade den USB-C-Akku, schließe ihn an und betätige den Hauptschalter.
2. (Optional) Öffne die Beeper-Abdeckung und aktiviere beim Testen auf der Werkbank die akustische Rückmeldung; verriegle sie vor dem unauffälligen Einsatz vor Ort.
3. Gehe am Träger des Ziel-Badges vorbei – der MaxiProx aktiviert die Karte und das ESP RFID Tool erfasst den Wiegand-Datenstrom.
4. Übertrage die erfassten Zugangsdaten per Wi-Fi oder USB-UART und spiele sie bei Bedarf erneut ab bzw. klone sie.

## Fehlerbehebung

| Symptom | Wahrscheinliche Ursache | Lösung |
|---------|-------------------------|--------|
| Reader startet neu, wenn eine Karte präsentiert wird | PD-Trigger hat 9 V statt 12 V ausgehandelt | Trigger-Jumper überprüfen bzw. ein leistungsfähigeres USB-C-Kabel verwenden |
| Keine Lesereichweite | Akku oder Verkabelung liegt *auf* der Antenne | Kabel neu verlegen und einen Abstand von 2 cm um die Ferritschleife einhalten |
| Beeper piept weiterhin | Schalter wurde in die positive Leitung eingebaut statt in die negative | Abschalter in die **negative** Lautsprecherleitung verlegen |

## Referenzen

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
