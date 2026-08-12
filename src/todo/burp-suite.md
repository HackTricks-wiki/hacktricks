# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

Burp Intruder sluit die volgende ingeboude payload generators en transformasies in:<sup>[[1]](#references)</sup>

- **Simple list:** Gebruik 'n gekonfigureerde lys stringe as payloads.
- **Runtime file:** Lees een payload per reël tydens runtime. Dit is nuttig vir groot lyste omdat Burp nie die hele lêer in die geheue laai nie.
- **Case modification:** Genereer die onveranderde waarde, kleinletters- en hooflettersvorme, `Propername` (eerste letter hoofletter en die res kleinletters), of `ProperName` (eerste letter hoofletter met die oorblywende karakters onveranderd). Burp verwyder duplikaatresultate.
- **Numbers:** Genereer opeenvolgende of ewekansige getalle binne 'n gekonfigureerde reeks.
- **Brute forcer:** Genereer elke permutasie vir 'n gekose karakterstel en minimum-/maksimumlengte.

## Extensions and companion tools

- **Collabfiltrator** genereer payloads wat opdragte uitvoer en hul uitvoer deur DNS-navrae na Burp Collaborator eksfiltreer.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** voer Burp-bevindings uit vir gebruik in ander verslagdoeningswerkvloeie.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** skakel HTTP-navrae om na scripts in verskeie tale.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger-dokumentasie - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
