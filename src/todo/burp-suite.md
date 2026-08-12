# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder-Payload-Typen

Burp Intruder umfasst die folgenden integrierten Payload-Generatoren und Transformationen:<sup>[[1]](#references)</sup>

- **Einfache Liste:** Eine konfigurierte Liste von Strings als Payloads verwenden.
- **Laufzeitdatei:** Zur Laufzeit einen Payload pro Zeile einlesen. Dies ist für große Listen nützlich, da Burp nicht die gesamte Datei in den Speicher lädt.
- **Groß-/Kleinschreibung ändern:** Den unveränderten Wert, die Klein- und Großschreibung, `Propername` (erster Buchstabe groß und der Rest klein) oder `ProperName` (erster Buchstabe groß, die verbleibenden Zeichen unverändert) generieren. Burp verwirft doppelte Ergebnisse.
- **Zahlen:** Sequenzielle oder zufällige Zahlen innerhalb eines konfigurierten Bereichs generieren.
- **Brute forcer:** Jede Permutation für einen ausgewählten Zeichensatz sowie eine minimale und maximale Länge generieren.

## Extensions und begleitende Tools

- **Collabfiltrator** generiert Payloads, die Befehle ausführen und deren Ausgabe über DNS-Abfragen an Burp Collaborator exfiltrieren.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exportiert Burp-Ergebnisse zur Verwendung in anderen Reporting-Workflows.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** konvertiert HTTP-Anfragen in Scripts für mehrere Sprachen.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger-Dokumentation - Burp Intruder-Payload-Typen](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
