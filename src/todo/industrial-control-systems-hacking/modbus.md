# Protokół Modbus

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie do protokołu Modbus

Protokół Modbus jest powszechnie używany w systemach automatyki przemysłowej i systemach sterowania. Modbus umożliwia komunikację między różnymi urządzeniami, takimi jak programowalne sterowniki logiczne (PLC), czujniki, elementy wykonawcze oraz inne urządzenia przemysłowe. Zrozumienie protokołu Modbus jest istotne, ponieważ jest to najczęściej używany protokół komunikacyjny w ICS i zapewnia duży attack surface do sniffingu, a nawet wstrzykiwania poleceń do PLC.

Poniżej przedstawiono poszczególne koncepcje wraz z kontekstem dotyczącym protokołu i sposobu jego działania. Największym wyzwaniem w zakresie bezpieczeństwa systemów ICS są koszty wdrożenia i modernizacji. Protokoły i standardy te zostały zaprojektowane na początku lat 80. i 90. i nadal są powszechnie używane. Ponieważ przemysł wykorzystuje wiele urządzeń i połączeń, ich modernizacja jest bardzo trudna, co daje hackerom przewagę wynikającą z możliwości wykorzystania przestarzałych protokołów. Ataki na Modbus są praktycznie nieuniknione, ponieważ będzie on używany bez modernizacji, jeśli jego działanie ma kluczowe znaczenie dla przemysłu.

## Architektura klient-serwer

Protokół Modbus jest zazwyczaj używany w architekturze klient-serwer, w której urządzenie nadrzędne (klient) inicjuje komunikację z jednym lub większą liczbą urządzeń podrzędnych (serwerów). Jest to również określane jako architektura master-slave, powszechnie stosowana w elektronice i IoT, między innymi w SPI i I2C.

## Wersje szeregowe i Ethernet

Protokół Modbus został zaprojektowany zarówno do komunikacji szeregowej, jak i komunikacji Ethernet. Komunikacja szeregowa jest powszechnie używana w starszych systemach, natomiast nowoczesne urządzenia obsługują Ethernet, który zapewnia wyższe szybkości transmisji danych i jest bardziej odpowiedni dla współczesnych sieci przemysłowych.

## Reprezentacja danych

Dane są przesyłane w protokole Modbus w formacie ASCII lub binarnym, jednak format binarny jest używany ze względu na jego kompaktowość i zgodność ze starszymi urządzeniami.

## Kody funkcji

Protokół Modbus działa poprzez przesyłanie określonych kodów funkcji, które służą do obsługi PLC i różnych urządzeń sterujących. Ta część jest ważna do zrozumienia, ponieważ można przeprowadzać replay attacks poprzez ponowne przesyłanie kodów funkcji. Starsze urządzenia nie obsługują szyfrowania transmisji danych i zazwyczaj są połączone długimi przewodami, co umożliwia manipulowanie tymi przewodami oraz przechwytywanie lub wstrzykiwanie danych.

## Adresowanie w Modbus

Każde urządzenie w sieci ma unikalny adres, który jest niezbędny do komunikacji między urządzeniami. Protokoły takie jak Modbus RTU i Modbus TCP służą do implementacji adresowania oraz pełnią funkcję warstwy transportowej dla transmisji danych. Przesyłane dane mają format protokołu Modbus i zawierają wiadomość.

Ponadto Modbus implementuje mechanizmy sprawdzania błędów, aby zapewnić integralność przesyłanych danych. Przede wszystkim Modbus jest jednak otwartym standardem i każdy może zaimplementować go w swoich urządzeniach. Dzięki temu protokół ten stał się globalnym standardem i jest powszechnie stosowany w branży automatyki przemysłowej.

Ze względu na szerokie zastosowanie i brak modernizacji atakowanie Modbus zapewnia znaczną przewagę dzięki jego attack surface. ICS jest w dużym stopniu zależny od komunikacji między urządzeniami, a wszelkie ataki na te urządzenia mogą być niebezpieczne dla działania systemów przemysłowych. Jeśli medium transmisyjne zostanie zidentyfikowane przez attackera, można przeprowadzać ataki takie jak replay, wstrzykiwanie danych, sniffing i data leak, Denial of Service, fałszowanie danych itp.

{{#include ../../banners/hacktricks-training.md}}
