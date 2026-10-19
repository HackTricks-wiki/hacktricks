# Wstrzykiwanie sygnału w łączu dosyłowym VSAT

{{#include ../../banners/hacktricks-training.md}}

Terminal VSAT zwykle traktuje odbierany z satelity sygnał jako ruch pochodzący z huba operatora. W systemie DVB-RCS łącze dosyłowe może przenosić zarówno pakiety IP użytkowników, jak i komunikaty sterujące modemem. Jeśli odbiornik przetwarza komunikat bez uprzedniego uwierzytelnienia, sygnał wstrzyknięty lokalnie może przekroczyć granicę zaufania między warstwą radiową a płaszczyzną sterowania. Jest to **wstrzykiwanie sygnału na terminalu**, a nie transmisja do satelity ani pasywne przechwytywanie sygnału z łącza dosyłowego. Wynik demonstracji zależy od implementacji protokołu i uwierzytelniania komunikatów przez modem, a nie od samego DVB-RCS.<sup>[[1]](#references)[[2]](#references)</sup>

## Test w laboratorium z izolacją RF

Użyj własnego terminala, jego firmware'u oraz SDR podłączonego do wejścia odbiorczego modemu przez odpowiednie tłumiki albo skorzystaj z ekranowanego stanowiska RF. Nie nadawaj na aktywnym kanale satelitarnym. Najpierw zapisz skonfigurowane parametry terminala: nośną startową, szybkość transmisji symboli i identyfikator populacji; pomagają one w synchronizacji z łączem dosyłowym.<sup>[[1]](#references)[[3]](#references)</sup> Łańcuch synchronizacji DVB-RCS używa Network Information Table (NIT) do odnalezienia RCS Map Table (RMT), a następnie Program Association Table (PAT) i Program Map Table (PMT), aby zlokalizować strumienie sygnalizacyjne łącza dosyłowego. Terminal może przestrajać się przez wiele nośnych strumienia transportowego, zanim dotrze do strumienia danych.<sup>[[3]](#references)</sup>

1. Zdekoduj lub odtwórz startowy strumień transportowy celu i sprawdź jego NIT, RMT, identyfikatory usług, identyfikatory pakietów (PID) oraz obsługę referencji zegara. Porównaj standard z parserem i logami urządzenia docelowego; specyficzna dla producenta kolejność lub deskryptory mogą uniemożliwić akceptację strumienia, który poza tym jest prawidłowy.
2. W laboratoryjnym nadajniku opakuj nieszkodliwą sondę UDP w format `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` i prześlij ją przez wyjście SDR do odizolowanej ścieżki odbiorczej. Utrzymuj zgodność Program Clock Reference (PCR) strumienia transportowego z szybkością transmisji bajtów, bo w przeciwnym razie modem może utracić synchronizację, zanim przetworzy sondę.
3. Potwierdź zarówno **synchronizację demodulatora**, jak i odbiór sondy na należącym do ciebie wewnętrznym punkcie końcowym. Sama synchronizacja dowodzi jedynie, że warstwa fizyczna zaakceptowała przebieg sygnału. Następnie sprawdź, czy dostępne są nieuwierzytelnione komunikaty zarządzające lub sygnalizacja aktualizacji, nie instalując obrazu ani nie zmieniając konfiguracji usługi.

W opublikowanym przypadku MDM2200 użyto modułu źródłowego GNU Radio dla DVB-RCS/MPE/MPEG-TS oraz `gr-dtv` do modulacji DVB-S2. Modem wymagał szczegółów inicjalizacji specyficznych dla celu: SDT przed PAT/PMT, deskryptora zawartości RCS z identyfikatorem tabeli `0x3E` oraz prywatnego bajtu RMT o wartości `0x01` dla trybu GSE/4CPM. Nie zakładaj, że te wartości zadziałają na innym terminalu.<sup>[[1]](#references)</sup> Badacze zaobserwowali również, że w ich konfiguracji pakiety MPE multicast docierały do odbierających modemów, więc kierowanie ruchu nie ograniczało się do znanego unicastowego adresu MAC.<sup>[[1]](#references)</sup> W odrębnej analizie wykryto niezabezpieczoną sygnalizację sterującą i sygnalizację aktualizacji oprogramowania w badanym systemie, ale ten wynik należy zweryfikować dla każdej implementacji.<sup>[[2]](#references)</sup>

Tunel IPsec lub VPN dla ruchu użytkowników nie uwierzytelnia wcześniejszej sygnalizacji DVB-RCS ani parsera aktualizacji samego modemu. Podczas autoryzowanej oceny rozróżniaj ochronę kryptograficzną **adresowego ruchu IP użytkowników**, **sterowania łączem dosyłowym** oraz ruchu **serwisowego i odzyskiwania systemu**; nie traktuj bezpiecznego tunelu użytkownika jako dowodu, że wstrzykiwanie sygnału radiowego jest blokowane.<sup>[[1]](#references)[[2]](#references)</sup>

Wprowadzenie do analizy I/Q znajdziesz w sekcji [analiza sygnałów radiowych](../hardware-hacking/radio.md). Informacje o analizie firmware'u i parserów po stronie płytki znajdziesz w sekcji [analiza firmware'u](../firmware-analysis/). Wróć do [przeglądu Radio Hacking](./), aby poznać inne interfejsy.

## References

- [1] [Bisping i in. — Ataki polegające na wstrzykiwaniu sygnału bezprzewodowego na modemy satelitarne VSAT (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold i in. — VSAsTer: Ujawnienie nieodłącznych problemów bezpieczeństwa w obecnych praktykach dotyczących systemów VSAT (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 — Kanał interakcji DVB dla satelitarnych systemów dystrybucji](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
