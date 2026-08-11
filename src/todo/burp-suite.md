# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder-Payload-Typen

- **Simple list:** Verwende eine konfigurierte Liste von Zeichenfolgen als Payloads.
- **Runtime file:** Lies zur Laufzeit einen Payload pro Zeile ein. Dies ist für große Listen nützlich, da Burp nicht die gesamte Datei in den Speicher lädt.
- **Case modification:** Ändere die Groß- und Kleinschreibung einer Eingabezeichenfolge, beispielsweise in Kleinbuchstaben, Großbuchstaben, Satzschreibung oder Titelschreibung.
- **Numbers:** Generiere fortlaufende oder zufällige Zahlen innerhalb eines konfigurierten Bereichs.
- **Brute forcer:** Generiere jede Permutation für einen ausgewählten Zeichensatz sowie eine minimale und maximale Länge.<sup>[[1]](#references)</sup>

## Extensions und Begleittools

- **Collabfiltrator** generiert Payloads, die Befehle ausführen und deren Ausgabe über DNS-Abfragen an Burp Collaborator exfiltrieren.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exportiert Burp-Ergebnisse zur Verwendung in anderen Reporting-Workflows.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** konvertiert HTTP-Anfragen in Scripts in mehreren Sprachen.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger-Dokumentation - Burp Intruder-Payload-Typen](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
