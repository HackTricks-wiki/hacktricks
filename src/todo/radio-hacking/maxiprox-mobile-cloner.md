# Bau eines tragbaren HID MaxiProx 125 kHz Mobile Cloners

{{#include ../../banners/hacktricks-training.md}}

## Ziel
Verwandeln Sie einen netzbetriebenen HID MaxiProx 5375 Langstrecken-125 kHz-Leser in einen vor Ort einsetzbaren, batteriebetriebenen Badge-Clone, der während physischer Sicherheitsbewertungen still Proximitätskarten erntet.

Die hier behandelte Umwandlung basiert auf der Forschungsreihe von TrustedSec „Let’s Clone a Cloner – Part 3: Putting It All Together“ und kombiniert mechanische, elektrische und RF-Überlegungen, sodass das endgültige Gerät in einen Rucksack geworfen und sofort vor Ort verwendet werden kann.

> [!warning]
> Die Manipulation von netzbetriebenen Geräten und Lithium-Ionen-Powerbanks kann gefährlich sein. Überprüfen Sie jede Verbindung **vor** dem Energisieren des Stromkreises und halten Sie die Antennen, Koaxialkabel und Erdungsflächen genau so, wie sie im Werksdesign waren, um eine Entstimmung des Lesers zu vermeiden.

## Stückliste (BOM)

* HID MaxiProx 5375 Leser (oder jeder 12 V HID Prox® Langstreckenleser)
* ESP RFID Tool v2.2 (ESP32-basierter Wiegand-Sniffer/Logger)
* USB-PD (Power-Delivery) Trigger-Modul, das in der Lage ist, 12 V @ ≥3 A zu verhandeln
* 100 W USB-C Powerbank (gibt 12 V PD-Profil aus)
* 26 AWG silikonisolierte Anschlussdrähte – rot/weiß
* Panel-Montage SPST Kippschalter (für den Beeper-Killschalter)
* NKK AT4072 Schalter-Schutz / unfallgeschützter Deckel
* Lötkolben, Entlötgewebe & Entlötpumpe
* ABS-zugelassene Handwerkzeuge: Laubsäge, Universalmesser, flache & halbrunde Feilen
* Bohrer 1/16″ (1,5 mm) und 1/8″ (3 mm)
* 3 M VHB doppelseitiges Klebeband & Kabelbinder

## 1. Stromversorgung Unter-System

1. Löten Sie die werkseitige Buck-Converter-Tochterplatine ab und entfernen Sie sie, die zur Erzeugung von 5 V für die Logik-PCB verwendet wird.
2. Montieren Sie einen USB-PD-Trigger neben dem ESP RFID Tool und führen Sie den USB-C-Anschluss des Triggers nach außen aus dem Gehäuse.
3. Der PD-Trigger verhandelt 12 V von der Powerbank und speist sie direkt an den MaxiProx (der Leser erwartet nativ 10–14 V). Eine sekundäre 5 V-Schiene wird von der ESP-Platine entnommen, um Zubehör mit Strom zu versorgen.
4. Der 100 W Akku wird bündig gegen den internen Abstandshalter positioniert, sodass **keine** Stromkabel über die Ferritantenne hängen, um die RF-Leistung zu erhalten.

## 2. Beeper-Killschalter – Stiller Betrieb

1. Lokalisieren Sie die beiden Lautsprecher-Pads auf der MaxiProx-Logikplatine.
2. Wickeln Sie *beide* Pads sauber ab und löten Sie dann nur das **negative** Pad wieder an.
3. Löten Sie 26 AWG Drähte (weiß = negativ, rot = positiv) an die Beeper-Pads und führen Sie sie durch einen neu geschnittenen Schlitz zu einem Panel-Montage SPST-Schalter.
4. Wenn der Schalter geöffnet ist, wird der Beeper-Kreis unterbrochen und der Leser arbeitet völlig geräuschlos – ideal für geheime Badge-Ernte.
5. Setzen Sie eine NKK AT4072 federbelastete Sicherheitskappe über den Kippschalter. Vergrößern Sie vorsichtig das Bohrloch mit einer Laubsäge / Feile, bis es über den Schalterkörper einrastet. Der Schutz verhindert eine versehentliche Aktivierung im Rucksack.

## 3. Gehäuse & Mechanische Arbeiten

• Verwenden Sie Abisolierer und dann ein Messer & eine Feile, um das interne ABS „Bump-out“ *zu entfernen*, damit der große USB-C-Akku flach auf dem Abstandshalter sitzt.
• Schneiden Sie zwei parallele Kanäle in die Gehäusewand für das USB-C-Kabel; dies fixiert den Akku und eliminiert Bewegung/Vibration.
• Erstellen Sie eine rechteckige Öffnung für die **Strom**-Taste des Akkus:
1. Kleben Sie eine Papier-Schablone über den Standort.
2. Bohren Sie 1/16″ Pilotlöcher in alle vier Ecken.
3. Vergrößern Sie mit einem 1/8″ Bohrer.
4. Verbinden Sie die Löcher mit einer Laubsäge; beenden Sie die Kanten mit einer Feile.
✱ Ein rotierender Dremel wurde *vermeidet* – der Hochgeschwindigkeitsbohrer schmilzt dickes ABS und hinterlässt eine unschöne Kante.

## 4. Endmontage

1. Installieren Sie die MaxiProx-Logikplatine erneut und löten Sie den SMA-Pigtail an die PCB-Massefläche des Lesers.
2. Montieren Sie das ESP RFID Tool und den USB-PD-Trigger mit 3 M VHB.
3. Befestigen Sie alle Kabel mit Kabelbindern und halten Sie die Stromleitungen **weit** von der Antennen-Schleife entfernt.
4. Ziehen Sie die Gehäuseschrauben fest, bis der Akku leicht komprimiert ist; die interne Reibung verhindert, dass sich das Paket verschiebt, wenn das Gerät nach jedem Kartenlesen zurückschlägt.

## 5. Reichweiten- & Abschirmungstests

* Mit einer 125 kHz **Pupa** Testkarte erreichte der tragbare Cloner konsistente Lesungen bei **≈ 8 cm** in freier Luft – identisch mit dem netzbetriebenen Betrieb.
* Das Platzieren des Lesers in einer dünnwandigen Metallkassette (um einen Banklobby-Schreibtisch zu simulieren) reduzierte die Reichweite auf ≤ 2 cm und bestätigte, dass erhebliche Metallgehäuse als effektive RF-Abschirmungen wirken.

## Nutzung Workflow

1. Laden Sie den USB-C-Akku, schließen Sie ihn an und schalten Sie den Hauptschalter ein.
2. (Optional) Öffnen Sie den Beeper-Schutz und aktivieren Sie akustisches Feedback beim Bench-Test; schließen Sie ihn vor der geheimen Nutzung im Feld.
3. Gehen Sie am Ziel-Badge-Träger vorbei – der MaxiProx wird die Karte aktivieren und das ESP RFID Tool erfasst den Wiegand-Stream.
4. Übertragen Sie die erfassten Anmeldeinformationen über Wi-Fi oder USB-UART und wiederholen/klonen Sie sie nach Bedarf.

## Fehlersuche

| Symptom | Wahrscheinliche Ursache | Lösung |
|---------|------------------------|--------|
| Leser startet neu, wenn Karte präsentiert wird | PD-Trigger verhandelte 9 V statt 12 V | Überprüfen Sie die Trigger-Jumper / versuchen Sie ein leistungsstärkeres USB-C-Kabel |
| Keine Reichweite | Akku oder Verkabelung sitzt *auf* der Antenne | Kabel umleiten & 2 cm Abstand um die Ferritschleife halten |
| Beeper piept weiterhin | Schalter ist am positiven Draht statt am negativen angeschlossen | Killschalter verschieben, um die **negative** Lautsprecher-Leitung zu unterbrechen |

## Referenzen

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
