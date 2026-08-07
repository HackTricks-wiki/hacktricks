# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Basic Payloads

- **Simple List:** Po prostu lista zawierająca jeden wpis w każdym wierszu
- **Runtime File:** Lista odczytywana w runtime (nieładowana do pamięci). Do obsługi dużych list.
- **Case Modification:** Zastosuj zmiany do listy ciągów znaków (bez zmian, na małe litery, na WIELKIE LITERY, na Proper name - pierwsza litera wielka, a pozostałe małe-, na Proper Name - pierwsza litera wielka, a pozostałe pozostają bez zmian-.
- **Numbers:** Generuj liczby od X do Y z krokiem Z lub losowo.
- **Brute Forcer:** Zestaw znaków, minimalna i maksymalna długość.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload do wykonywania poleceń i pobierania ich wyników za pomocą żądań DNS do burpcollab.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
