# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Gehen Sie nicht davon aus, dass jeder Mac eine decodierbare 12-stellige Seriennummer besitzt. Apples älteres Format codierte Informationen zur Herstellung und Konfiguration, aber Apple begann 2021 mit der Einführung randomisierter Seriennummern bei neuen Produkten. Das randomisierte Format gibt keine Details zur Herstellung oder Konfiguration preis.<sup>[[1]](#references)</sup>

### Älteres 12-stelliges Format

Bei vielen Geräten, die von 2010 bis zum Übergang zur Randomisierung hergestellt wurden, kann das 12-stellige Format weiterhin nützliche Hinweise zur Inventarisierung liefern:<sup>[[3]](#references)</sup>

- Die Zeichen 1–3 identifizieren den Herstellungsort.
- Die Zeichen 4–5 codieren das Produktionshalbjahr und die Produktionswoche.
- Die Zeichen 6–8 unterscheiden Einheiten, die am selben Ort und zur selben Zeit hergestellt wurden.
- Die Zeichen 9–12 identifizieren den Modell- oder Konfigurationscode.

Beispielsweise folgt `C02L13ECF8J2` dieser älteren Struktur. Von der Community gepflegte Zuordnungen von Werken umfassen Präfixe wie `FC`, `F`, `XA`, `XB`, `QP` und `G8` für Standorte in den Vereinigten Staaten; `RN` für Mexiko; `CK` für Cork; `VM` für einen Foxconn-Standort in der Tschechischen Republik; `SG` oder `E` für Singapur; `MB` für Malaysia; `PT` oder `CY` für Korea sowie `EE`, `QT` oder `UV` für Taiwan. Zahlreiche Präfixe – darunter `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` und `C7` – wurden chinesischen Produktionsstätten zugeordnet; `RM` wurde generalüberholten Geräten zugeordnet.<sup>[[3]](#references)</sup>

Die Datumsangaben im vierten Zeichen reichen von `C` (erste Hälfte des Jahres 2010) bis `Z` (zweite Hälfte des Jahres 2019), wobei die Sequenz danach wiederverwendet wurde. Beim fünften Zeichen stehen die Ziffern `1`–`9` für die Wochen 1–9, während die Buchstaben `C`–`Y` mit Ausnahme der Vokale und von `S` für die Wochen 10–27 stehen; addieren Sie 26, wenn das vierte Zeichen die zweite Hälfte eines Jahres bezeichnet.<sup>[[3]](#references)</sup>

Diese Zuordnungen sind für die Triage älterer Geräte nützlich, stellen jedoch keinen maßgeblichen Nachweis über Herkunft, Alter oder Echtheit dar. Bestätigen Sie das Ergebnis anhand der Inventardaten von Apple.

Für eine zuverlässige Identifizierung rufen Sie die Seriennummer vom Gerät ab und verwenden Sie Apples Abfrage zur Abdeckung oder zu den technischen Daten, anstatt zu versuchen, das Modell anhand der Zeichenpositionen abzuleiten.<sup>[[2]](#references)</sup>

### Seriennummer abrufen

Die grafische Benutzeroberfläche zeigt sie unter **Apple-Menü > Über diesen Mac** an.<sup>[[2]](#references)</sup> Über eine Shell liest einer der folgenden Befehle die Seriennummer der Plattform aus:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Behandle eine Seriennummer als Identifikator, nicht als Authentifizierungsmerkmal: Bestätige das Gerät über den relevanten Apple- oder MDM-Inventar-Workflow, bevor du Entscheidungen zur Registrierung oder zum Besitz triffst.

## References

- [1] [MacRumors - Apple beginnt mit der Umstellung auf randomisierte Seriennummern](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Den Modellnamen und die Seriennummer deines Mac finden](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Die Bedeutung hinter einer Apple-Seriennummer entschlüsseln](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
