# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Basic Payloads

- **Simple List:** Eine Liste, die in jeder Zeile einen Eintrag enthält
- **Runtime File:** Eine Liste, die zur Laufzeit gelesen wird (nicht in den Speicher geladen). Zur Unterstützung großer Listen.
- **Case Modification:** Wendet Änderungen auf eine Liste von Zeichenfolgen an (Keine Änderung, in Kleinbuchstaben, in GROSSBUCHSTABEN, als Eigenname - erster Buchstabe groß und der Rest klein -, als Eigenname - erster Buchstabe groß und der Rest unverändert -).
- **Numbers:** Generiert Zahlen von X bis Y mit der Schrittweite Z oder zufällig.
- **Brute Forcer:** Zeichensatz, minimale und maximale Länge.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator): Payload zum Ausführen von Befehlen und Abrufen der Ausgabe über DNS requests an burpcollab.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
