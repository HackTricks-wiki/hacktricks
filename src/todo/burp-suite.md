# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

- **Eenvoudige lys:** Gebruik 'n gekonfigureerde lys stringe as payloads.
- **Runtime-lêer:** Lees een payload per reël tydens runtime. Dit is nuttig vir groot lyste omdat Burp nie die hele lêer in die geheue laai nie.
- **Hoofletterwysiging:** Verander die hooflettergebruik van 'n invoerstring, byvoorbeeld na kleinletters, hoofletters, sinkas of titelkas.
- **Getalle:** Genereer opeenvolgende of ewekansige getalle binne 'n gekonfigureerde reeks.
- **Brute forcer:** Genereer elke permutasie vir 'n gekose karakterstel en minimum-/maksimumlengte.<sup>[[1]](#references)</sup>

## Extensions and companion tools

- **Collabfiltrator** genereer payloads wat commands uitvoer en hul uitvoer deur DNS-navrae na Burp Collaborator eksfiltreer.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exporteer Burp-bevindings vir gebruik in ander verslagdoeningsworkflows.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** skakel HTTP-versoeke om na scripts in verskeie tale.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger-dokumentasie - Burp Intruder-payloadtipes](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
