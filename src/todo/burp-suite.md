# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Typy payloadów Intruder

- **Prosta lista:** Używa skonfigurowanej listy ciągów jako payloadów.
- **Plik runtime:** Odczytuje jeden payload na wiersz w czasie wykonywania. Jest to przydatne w przypadku dużych list, ponieważ Burp nie ładuje całego pliku do pamięci.
- **Modyfikacja wielkości liter:** Zmienia wielkość liter w ciągu wejściowym, na przykład na małe litery, wielkie litery, wielkość jak w zdaniu lub wielkość jak w tytule.
- **Liczby:** Generuje sekwencyjne lub losowe liczby w skonfigurowanym zakresie.
- **Brute forcer:** Generuje każdą permutację dla wybranego zestawu znaków oraz minimalnej i maksymalnej długości.<sup>[[1]](#references)</sup>

## Rozszerzenia i narzędzia towarzyszące

- **Collabfiltrator** generuje payloady, które wykonują polecenia i eksfiltrują ich dane wyjściowe za pośrednictwem zapytań DNS do Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** eksportuje ustalenia Burp do użycia w innych procesach raportowania.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** konwertuje żądania HTTP na skrypty w kilku językach.<sup>[[4]](#references)</sup>

## References

- [1] [Dokumentacja PortSwigger - typy payloadów Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
