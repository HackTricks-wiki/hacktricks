# Protokół Modbus

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie do Modbus

Modbus to otwarty protokół warstwy aplikacji, szeroko stosowany przez PLC, czujniki, elementy wykonawcze i inne urządzenia przemysłowe. Jego model żądanie/odpowiedź udostępnia cewki i rejestry za pomocą kodów funkcji. Testy bezpieczeństwa koncentrują się więc na nieautoryzowanych odczytach/zapisach, obserwacji ruchu, replay oraz niebezpiecznym zachowaniu urządzeń — a nie tylko na znalezieniu portu TCP 502.<sup>[[1]](#references)</sup>

Wiele wdrożeń nadal korzysta ze starszych urządzeń szeregowych, ponieważ modernizacja wymaga przestoju, ponownej certyfikacji lub wymiany urządzeń obiektowych. Tradycyjny Modbus nie zapewnia ani poufności, ani uwierzytelniania peerów; Modbus Security to osobny profil oparty na TLS, wykorzystujący certyfikaty X.509 i port TCP 802. Ponieważ specyfikacja jest publiczna i może być implementowana niezależnie, zachowanie dostawców oraz obsługa opcjonalnych funkcji różnią się i należy je fingerprintować, zamiast przyjmować je za pewnik.<sup>[[1]](#references)[[2]](#references)</sup>

## Architektura klient-serwer

W obecnej terminologii **klient** inicjuje transakcję, a **serwer** zwraca odpowiedź. Starsza dokumentacja używa określeń **master/slave**. Nie należy mylić tej relacji na poziomie aplikacji z SPI ani I2C: są to różne protokoły magistrali.<sup>[[1]](#references)</sup>

## Transport szeregowy i Ethernet

Te same dane aplikacyjne Modbus mogą być przesyłane przez warianty szeregowe (ramkowanie RTU lub ASCII) oraz przez Modbus TCP. Modbus TCP dodaje nagłówek MBAP i zwykle korzysta z portu TCP 502; szeregowy RTU używa zwartego binarnego ramkowania i CRC, natomiast szeregowy ASCII reprezentuje bajty jako znaki szesnastkowe i wykorzystuje LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Reprezentacja danych

Model danych składa się z jednobitowych cewek/wejść dyskretnych oraz 16-bitowych rejestrów wejściowych/podtrzymujących. Wartości obejmujące wiele rejestrów, kolejność bajtów, skalowanie i znaczenie semantyczne są specyficzne dla urządzenia i muszą zostać potwierdzone na podstawie mapy rejestrów dostawcy.<sup>[[1]](#references)</sup>

## Kody funkcji

Kody funkcji wybierają operacje takie jak odczyt cewek (`0x01`), odczyt rejestrów podtrzymujących (`0x03`), zapis pojedynczej cewki/rejestru (`0x05`/`0x06`) oraz zapis wielu cewek/rejestrów (`0x0F`/`0x10`). Przechwycone żądanie zapisu może nadawać się do replay, gdy wdrożenie nie ma dodatkowego uwierzytelniania ani kontroli stanu procesu. Przy autoryzowanym dostępie fizycznym do długich przewodów szeregowych assessor może również przechwytywać lub wstrzykiwać ramki bezpośrednio w okablowanie po zidentyfikowaniu interfejsu elektrycznego, terminacji i bezpiecznej metody podłączenia. Każde z tych działań może wpłynąć na proces fizyczny, dlatego należy korzystać ze środowiska laboratoryjnego lub uzyskać wyraźną autoryzację operacyjną.<sup>[[1]](#references)[[3]](#references)</sup>

## Adresowanie

Urządzenia szeregowe używają adresu jednostki. Modbus TCP wykorzystuje adresowanie IP oraz Unit Identifier w nagłówku MBAP, co ma szczególne znaczenie, gdy gateway TCP-to-serial przekazuje żądania do jednostek downstream. Odwołania do rejestrów przedstawiane w dokumentacji produktu mogą być jednobazowe (`40001`), podczas gdy adresy protokołu są zerobazowe, co często prowadzi do błędów off-by-one.<sup>[[1]](#references)[[3]](#references)</sup>

Ramkowanie szeregowe obejmuje kontrole błędów transmisji (CRC dla RTU i LRC dla ASCII), a TCP zapewnia swój standardowy checksum transportowy. Mechanizmy te wykrywają przypadkowe uszkodzenia; nie zapewniają kryptograficznej integralności ani uwierzytelniania źródła.<sup>[[3]](#references)</sup>

Podczas autoryzowanego assessmentu należy testować ekspozycję, dozwolone kody funkcji, zakresy adresów zapisywalnych, obsługę wyjątków, limity szybkości oraz to, czy segmentacja sieci lub firewall rozpoznający Modbus ogranicza klientów. Istotne zagrożenia obejmują pasywne ujawnienie informacji, nieautoryzowane wstrzykiwanie poleceń, replay, fałszowanie danych i denial of service. Wszystkie aktywne testy należy koordynować z właścicielami procesu, ponieważ pozornie niewielkie zmiany rejestrów mogą zmienić proces fizyczny.

## References

- [1] [Organizacja Modbus — Specyfikacja protokołu aplikacyjnego Modbus V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Organizacja Modbus — Protokół Modbus Security i przewodniki implementacyjne](https://www.modbus.org/modbus-specifications)
- [3] [Organizacja Modbus — Specyfikacja i przewodnik implementacji Modbus over Serial Line V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
