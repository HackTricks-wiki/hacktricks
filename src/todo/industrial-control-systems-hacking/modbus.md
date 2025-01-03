# Protokół Modbus

## Wprowadzenie do protokołu Modbus

Protokół Modbus jest powszechnie stosowanym protokołem w automatyce przemysłowej i systemach kontrolnych. Modbus umożliwia komunikację między różnymi urządzeniami, takimi jak programowalne sterowniki logiczne (PLC), czujniki, siłowniki i inne urządzenia przemysłowe. Zrozumienie protokołu Modbus jest kluczowe, ponieważ jest to najczęściej używany protokół komunikacyjny w ICS i ma wiele potencjalnych powierzchni ataku do podsłuchiwania, a nawet wstrzykiwania poleceń do PLC.

Tutaj koncepcje są przedstawione punktowo, dostarczając kontekstu dotyczącego protokołu i jego charakterystyki działania. Największym wyzwaniem w bezpieczeństwie systemów ICS jest koszt wdrożenia i modernizacji. Protokóły i standardy te zostały zaprojektowane na początku lat 80. i 90., które są nadal szeroko stosowane. Ponieważ w przemyśle jest wiele urządzeń i połączeń, modernizacja urządzeń jest bardzo trudna, co daje hakerom przewagę w radzeniu sobie z przestarzałymi protokołami. Ataki na Modbus są praktycznie nieuniknione, ponieważ będzie on używany bez modernizacji, a jego działanie jest krytyczne dla przemysłu.

## Architektura klient-serwer

Protokół Modbus jest zazwyczaj używany w architekturze klient-serwer, gdzie urządzenie nadrzędne (klient) inicjuje komunikację z jednym lub więcej urządzeniami podrzędnymi (serwery). Jest to również określane jako architektura Master-Slave, która jest szeroko stosowana w elektronice i IoT z SPI, I2C itp.

## Wersje szeregowe i Ethernetowe

Protokół Modbus jest zaprojektowany zarówno do komunikacji szeregowej, jak i komunikacji Ethernetowej. Komunikacja szeregowa jest szeroko stosowana w systemach dziedzictwa, podczas gdy nowoczesne urządzenia obsługują Ethernet, który oferuje wysokie prędkości transmisji danych i jest bardziej odpowiedni dla nowoczesnych sieci przemysłowych.

## Reprezentacja danych

Dane są przesyłane w protokole Modbus w formacie ASCII lub binarnym, chociaż format binarny jest używany ze względu na jego kompaktowość z starszymi urządzeniami.

## Kody funkcji

Protokół ModBus działa na podstawie przesyłania specyficznych kodów funkcji, które są używane do obsługi PLC i różnych urządzeń kontrolnych. Ta część jest ważna do zrozumienia, ponieważ ataki powtórzeniowe mogą być przeprowadzane przez retransmisję kodów funkcji. Urządzenia dziedzictwa nie obsługują żadnego szyfrowania transmisji danych i zazwyczaj mają długie przewody, które je łączą, co prowadzi do manipulacji tymi przewodami i przechwytywania/wstrzykiwania danych.

## Adresowanie Modbus

Każde urządzenie w sieci ma unikalny adres, który jest niezbędny do komunikacji między urządzeniami. Protokóły takie jak Modbus RTU, Modbus TCP itp. są używane do implementacji adresowania i służą jako warstwa transportowa dla transmisji danych. Dane, które są przesyłane, są w formacie protokołu Modbus, który zawiera wiadomość.

Ponadto, Modbus implementuje również kontrole błędów, aby zapewnić integralność przesyłanych danych. Ale przede wszystkim, Modbus jest otwartym standardem i każdy może go wdrożyć w swoich urządzeniach. To sprawiło, że protokół ten stał się globalnym standardem i jest szeroko stosowany w przemyśle automatyki przemysłowej.

Ze względu na jego szerokie zastosowanie i brak modernizacji, atakowanie Modbus daje znaczną przewagę z jego powierzchnią ataku. ICS jest w dużym stopniu zależne od komunikacji między urządzeniami, a wszelkie ataki na nie mogą być niebezpieczne dla działania systemów przemysłowych. Ataki takie jak powtórzenie, wstrzykiwanie danych, podsłuchiwanie danych i wycieki, Denial of Service, fałszowanie danych itp. mogą być przeprowadzane, jeśli medium transmisji zostanie zidentyfikowane przez atakującego.
