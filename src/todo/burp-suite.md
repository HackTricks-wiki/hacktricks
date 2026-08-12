# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Typy payloadów Intruder

Burp Intruder zawiera następujące wbudowane generatory i transformacje payloadów:<sup>[[1]](#references)</sup>

- **Simple list:** Używa skonfigurowanej listy ciągów znaków jako payloadów.
- **Runtime file:** Odczytuje jeden payload na wiersz w czasie działania. Jest to przydatne w przypadku dużych list, ponieważ Burp nie ładuje całego pliku do pamięci.
- **Case modification:** Generuje niezmodyfikowaną wartość, formę z małymi lub wielkimi literami, `Propername` (pierwsza litera wielka, a pozostałe małe) albo `ProperName` (pierwsza litera wielka, a pozostałe znaki bez zmian). Burp odrzuca zduplikowane wyniki.
- **Numbers:** Generuje sekwencyjne lub losowe liczby w skonfigurowanym zakresie.
- **Brute forcer:** Generuje każdą permutację dla wybranego zestawu znaków oraz minimalnej i maksymalnej długości.

## Rozszerzenia i narzędzia towarzyszące

- **Collabfiltrator** generuje payloady, które wykonują polecenia i eksfiltrują ich dane wyjściowe za pośrednictwem zapytań DNS do Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** eksportuje wyniki Burp na potrzeby innych procesów raportowania.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** konwertuje żądania HTTP na skrypty w kilku językach.<sup>[[4]](#references)</sup>

## References

- [1] [Dokumentacja PortSwigger - Typy payloadów Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
