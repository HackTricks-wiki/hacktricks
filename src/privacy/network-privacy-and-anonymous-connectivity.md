# Prywatność sieciowa i anonimowa łączność

{{#include ../banners/hacktricks-training.md}}

Prywatność sieciowa to decyzja dotycząca routingu, a nie pełna tożsamość. Wybierz ścieżkę, pytając, kto nie powinien być w stanie powiązać **źródła**, **celu**, **treści** i **czasu**.

Aby zapoznać się ze znormalizowanym zestawieniem — `Pros`, `Cons`, `Procedure` krok po kroku oraz `Detection` dla każdej rodziny ścieżek dostępu — zacznij od [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Ta strona rozszerza informacje o typowych wdrażalnych opcjach.

## Co zwykle może zobaczyć każdy obserwator

| Ścieżka | Sieć lokalna / ISP | Pośrednik | Cel | Główne ograniczenie | Względna szybkość |
|---|---|---|---|---|---|
| Bezpośredni HTTPS | Metadane źródła, celu, czasu | Hosting/CDN widzi połączenie | Adres IP źródła, dane przeglądarki/aplikacji | Brak prywatności adresu IP źródła | Najszybsza |
| Komercyjny VPN | Połączenie źródła z VPN; zwykle nie metadane celu | VPN widzi metadane źródła i celu | Adres IP wyjściowego VPN | Jeden dostawca staje się punktem korelacji | Zwykle szybka |
| Samodzielnie hostowany VPN/VPS | Połączenie źródła z VPS | Logi hosta/konta/płatności/control-plane | Adres IP wyjściowy VPS | Łatwe przypisanie do wynajętego serwera/konta | Zwykle szybka |
| Tor Browser | Połączenie źródła z Tor/bridge; czas i ilość danych | Każdy relay widzi ograniczoną część | Wyjście Tor, dane przeglądarki | Wolniejsza; ryzyko związane z kontem/endpointem/korelacją | Umiarkowana/wolna |
| Tails/Whonix | Podobna ścieżka Tor, z silniejszymi granicami routingu | Te same ograniczenia Tor | Wyjście Tor/dane aplikacji | Błędy operacyjne oraz host/sprzęt pozostają | Umiarkowana/wolna |
| Publiczne Wi-Fi dla gości + HTTPS | Lokalny sprzęt/czas oraz cele widoczne dla obiektu | ISP obiektu widzi metadane | Publiczny adres IP gościa | Korelacja fizyczna/captive portal/urządzenie | Szybka/zmienna |
| Hotspot komórkowy | Operator widzi abonenta, urządzenie, lokalizację i cele | VPN/Tor, jeśli używane | Adres IP wyjściowy operatora, VPN lub Tor | Abonament komórkowy i lokalizacja są trwałymi identyfikatorami | Szybka/zmienna |
| Mixnet | Dostęp widzi użycie mixnetu, czas i ilość danych | Wiele mixing nodes | Gateway/egress | Rozwijający się ekosystem; koszt opóźnienia i przepustowości | Najwolniejsza |

HTTPS chroni treść podczas przesyłania, ale nie wszystkie metadane. EFF wskazuje, że domena, czas i rozmiar ruchu mogą pozostać widoczne dla pośredników, nawet gdy ścieżki stron, dane uwierzytelniające i wiadomości są zaszyfrowane.<sup>[[1]](#references)</sup>

## VPN-y: szybka prywatność ze skoncentrowanym zaufaniem

VPN jest przydatny do ukrywania metadanych celu przed ISP zapewniającym dostęp, ochrony pierwszego hopu w niezaufanej sieci, prezentowania stabilnego adresu egress podczas engagementu lub uzyskiwania dostępu do sieci prywatnej. **Nie** zapewnia anonimowości użytkownika. VPN widzi połączenie źródłowe i może obserwować metadane celu; konta, cookies, GPS, fingerprinty i informacje o płatnościach nadal pozostają.<sup>[[1]](#references)</sup>

### Lista kontrolna oceny dostawcy

1. **Własność i jurysdykcja:** ustal podmiot prawny, spółkę nadrzędną, kraje prowadzenia działalności, podwykonawców infrastruktury oraz obowiązujące procedury prawne.
2. **Zbierane dane:** rozróżnij dane konta/płatności, źródłowy adres IP, znaczniki czasu połączeń, przepustowość, telemetrię awarii, zapytania DNS i logi celu. „Brak logów przeglądania” nie oznacza „braku danych”.
3. **Przechowywanie i usuwanie:** znajdź dokładne okresy przechowywania oraz sprawdź, czy kopie zapasowe, systemy antyfraudowe i podmioty przetwarzające stosują ten sam harmonogram.
4. **Dowody:** preferuj publiczne audyty z określonym zakresem, datą, ustaleniami i działaniami naprawczymi; odtwarzalne/otwarte klienty; raporty przejrzystości oraz udokumentowane incydenty.
5. **Protokół i klient:** utrzymywany WireGuard, OpenVPN lub inny sprawdzony protokół; automatyczne aktualizacje; obsługa DNS i IPv6; kill switch oraz testy leak dla każdej platformy.
6. **Model biznesowy:** zrozum, jak finansowana jest bezpłatna lub subsydiowana usługa. Sama obecność w sklepie z aplikacjami nie jest dowodem godnego zaufania działania.
7. **Dopasowanie płatności:** alternatywna metoda płatności może ograniczyć ujawnienie danych rozliczeniowych VPN-owi, ale nie usuwa źródłowego adresu IP obserwowanego przy każdym połączeniu.

### Konfiguracja i weryfikacja VPN

1. Zainstaluj podpisanego klienta dostawcy/organizacji z jego oficjalnego źródła.
2. Wybierz **full tunnel**, chyba że udokumentowana trasa musi go omijać. Split tunneling tworzy ścieżki korelacji i leak.
3. Włącz działanie fail-closed/always-on oraz blokowanie ruchu podczas ponownego łączenia.
4. Przesyłaj DNS przez tunel i przetestuj zarówno IPv4, jak i IPv6. Wyłącz protokół tylko wtedy, gdy nie można go bezpiecznie tunelować, a utrata funkcjonalności jest zaakceptowana.
5. Przetestuj usypianie/wybudzanie, przełączanie sieci, logowanie do captive portalu, awarię tunelu i tethering hotspotu. NCSC ostrzega, że na niektórych platformach klienci podłączeni przez tethering mogą omijać VPN telefonu.<sup>[[2]](#references)</sup>
6. Użyj kontrolowanego przez organizację testowego endpointu do zarejestrowania obserwowanych adresów IPv4, IPv6, resolvera DNS i czasu połączenia. Nie ujawniaj wrażliwego engagementu losowym stronom „leak test”.
7. Powtórz testy po zmianach klienta, systemu operacyjnego, sieci lub polityki.

### Ominięcia routingu w wrogiej sieci LAN

VPN może pozostawać widoczny jako „połączony”, podczas gdy wybrane pakiety omijają go, ponieważ system operacyjny wybiera trasę **przed** zaszyfrowaniem pakietu przez VPN. TunnelCrack pokazał dwa sposoby wykorzystania typowych wyjątków routingu: **LocalNet** sprawia, że cel internetowy wygląda jak urządzenie w bezpośrednio podłączonej podsieci, natomiast **ServerIP** fałszuje rozwiązywanie adresu VPN gateway, aby adres celu odziedziczył wyjątek clear-network wymagany przez transport VPN. Są to błędy klienta/routingu, a nie złamania WireGuard, OpenVPN, IPsec lub TLS; payloady HTTPS nadal są szyfrowane end-to-end, ale lokalny obserwator może odzyskać metadane celu/czasu oraz dane dowolnego protokołu przesyłane cleartextem.<sup>[[18]](#references)</sup>

TunnelVision wykorzystuje ten sam prymityw przed szyfrowaniem za pośrednictwem DHCP option 121. Złośliwy lub przejęty serwer DHCP może zainstalować trasę klasową bardziej szczegółową niż catch-all route VPN, wybierając fizyczny interfejs dla dowolnego hosta lub zakresu. Kanał control VPN może pozostać aktywny, więc kill switch uruchamiany wyłącznie po rozłączeniu tunelu może się nie aktywować, a pojedyncza publiczna kontrola „IP leak” może nie wykryć selektywnego ominięcia.<sup>[[19]](#references)</sup>

Kill switch oparty na filtrowaniu pakietów, który na fizycznym interfejsie zezwala wyłącznie na DHCP i uwierzytelniony transport VPN, powinien zmienić to w zachowanie fail-closed, ale ukierunkowane wstrzyknięcie trasy nadal może utworzyć selektywny kanał side-channel typu denial. W przypadku obciążeń Linux o wysokich konsekwencjach preferuj silniejszy [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), w którym namespace aplikacji nie ma fizycznego interfejsu ani domyślnej trasy clear-network.<sup>[[19]](#references)</sup>

#### Weryfikacja w kontrolowanym laboratorium

Przetestuj dokładną kombinację klienta/systemu operacyjnego/wersji na kontrolowanym AP, serwerze DHCP, endpoincie VPN i celu; twierdzenia dotyczące całego produktu szybko się dezaktualizują, ponieważ implementacje routingu i filtrowania pakietów zależą od platformy. Wykonuj przechwytywanie również na samym endpoincie, a nie tylko na serwerze testowym — sama strona pokazująca egress IP nie dowodzi, że każdy cel podąża przez tunel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Połącz VPN, zarejestruj adres serwera VPN i zapisz każdą tablicę routingu IPv4/IPv6 oraz regułę policy routingu. W Windows użyj `route print`; w macOS użyj `netstat -rn`; w Linux użyj poniższych poleceń.
2. Sprawdź wybraną trasę dla kilku należących do Ciebie docelowych adresów IP. Następny hop/interfejs musi być tunelem, z wyjątkiem udokumentowanego endpointu transportu VPN.
3. W przypadku TunnelVision odśwież dzierżawę w kontrolowanej sieci DHCP i zainstaluj trasę option 121 **wyłącznie dla należącego do Ciebie testowego celu**. Wynik pozytywny oznacza, że ruch nadal jest tunelowany lub blokowany — nigdy nie jest wysyłany jako ruch celu przez fizyczny interfejs.
4. W przypadku LocalNet przypisz klientowi przeznaczoną wyłącznie do laboratorium publiczną podsieć dokumentacyjną, taką jak `203.0.113.0/24`, i umieść należący do Ciebie cel w jej obrębie. Sprawdź, czy włączenie dostępu do LAN nie powoduje omijania tunelu przez cele klasy internetowej.
5. W przypadku ServerIP przed połączeniem VPN spraw, aby kontrolowany DNS rozwiązywał nazwę hosta VPN należącym do Ciebie celem testowym, podczas gdy gateway laboratorium przekazywał transport VPN do rzeczywistego, należącego do Ciebie endpointu VPN. Klient nie może wyłączać ochrony dla niezwiązanych z tym ruchem aplikacji kierowanym do sfałszowanego adresu.
6. Powtórz test z włączonym i wyłączonym „local network access”, po ponownym połączeniu, uśpieniu/wybudzeniu, przełączeniu sieci oraz awarii procesu VPN. Testuj niezależnie IPv4, IPv6 i DNS.
7. Sprawdź przechwytywanie na fizycznym interfejsie. Powinno zawierać DHCP i zaszyfrowane pakiety do serwera VPN, a nie pakiety adresowane bezpośrednio do należącego do Ciebie celu testowego. Potwierdź również, że odrzucone ominięcie nie może po cichu zadziałać ponownie po monitach użytkownika lub naprawie łączności.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: silniejsze rozdzielanie aktywności w sieci

Tor tworzy obwód przez wiele przekaźników, dzięki czemu żaden pojedynczy przekaźnik zwykle nie zna jednocześnie źródła i celu. Cel widzi węzeł wyjściowy Tor, a nie adres IP użytkownika; sieć lokalna zwykle widzi połączenie z Tor.<sup>[[3]](#references)</sup> Tor jest zaprojektowany dla aplikacji TCP o małych opóźnieniach, dlatego działa wolniej i nie może zagwarantować ochrony przed przeciwnikiem zdolnym do korelowania obu końców połączenia.<sup>[[4]](#references)</sup>

### Bezpieczny workflow Tor Browser

1. Pobieraj Tor Browser wyłącznie z Tor Project lub oficjalnego mirroru i, gdy to możliwe, weryfikuj podpis.
2. Używaj **Tor Browser**, a nie zwykłej przeglądarki wskazującej na port SOCKS Tor. Zwykłe przeglądarki mogą ujawniać DNS/WebRTC oraz identyfikujący stan przeglądarki.<sup>[[5]](#references)</sup>
3. Zachowaj domyślny rozmiar, czcionki, rozszerzenia i ustawienia prywatności. Dodatkowe add-ony mogą uczynić przeglądarkę bardziej unikalną.<sup>[[6]](#references)</sup>
4. Wybierz poziom bezpieczeństwa **Safer** lub **Safest**, jeśli akceptujesz większą liczbę problemów ze zgodnością.
5. Użyj bridge, gdy bezpośredni Tor jest blokowany lub gdy zwykłe adresy IP przekaźników powodowałyby niedopuszczalną widoczność lokalną. Bridge utrudniają łatwe rozpoznanie, ale nie eliminują analizy ruchu.<sup>[[7]](#references)</sup>
6. Nie loguj się na konto umożliwiające identyfikację, nie podawaj informacji umożliwiających identyfikację i nie otwieraj pobranych aktywnych dokumentów w zewnętrznej aplikacji korzystającej z sieci.
7. Używaj oddzielnej sesji/kontekstu dla każdej tożsamości. „New circuit” nie oznacza wymazania tożsamości przeglądarki/aplikacji; użyj **New Identity** lub, odpowiednio, uruchom ponownie odizolowane środowisko.
8. Preferuj uwierzytelniony HTTPS lub uwierzytelnioną usługę onion. Węzeł wyjściowy Tor może obserwować niezaszyfrowany ruch HTTP.

### Tor plus VPN

Łączenie tych technologii nie jest automatycznie bezpieczniejsze. VPN przed Tor może ukryć bezpośrednie połączenia z przekaźnikami Tor przed ISP, podczas gdy VPN widzi źródło; Tor przed VPN daje VPN stabilny obraz aktywności po Tor i może zmniejszyć zbiór anonimowości. Błędna konfiguracja może wprowadzić leaks. Tor Project zaleca takie połączenia wyłącznie w przypadku zaawansowanych, jasno określonych modeli zagrożeń.<sup>[[8]](#references)</sup>

## Publiczne i gościnne Wi-Fi

Nowoczesne HTTPS oznacza, że pasywni sąsiedzi zazwyczaj nie mogą odczytać prawidłowo zaszyfrowanej treści stron, ale gościnne Wi-Fi nie zapewnia anonimowości. Właściciel sieci może rejestrować czasy dołączenia, identyfikatory urządzeń, dane captive portalu, cele połączeń i szczegóły DHCP; kamery, zakupy, transport oraz obserwacja fizyczna mogą zidentyfikować użytkownika. Fałszywy hotspot o podobnej nazwie może również przechwytywać dane uwierzytelniające portalu lub modyfikować niezaszyfrowany ruch.<sup>[[9]](#references)</sup>

### Zgodny z prawem workflow sieci gościnnej

1. Korzystaj wyłącznie z sieci oferowanej gościom lub z sieci, do której właściciel udzielił wyraźnej zgody. Poproś personel o dokładny SSID i procedurę korzystania z portalu.
2. Zaktualizuj endpoint i travel router przed przybyciem. Wyłącz udostępnianie plików/drukarek, wykrywanie przychodzące, automatyczne dołączanie oraz odpytywanie o zapamiętane sieci.
3. Włącz prywatny/losowy adres Wi-Fi systemu operacyjnego. Aktualne systemy Apple mogą używać rotacyjnych adresów w sieciach otwartych/słabo zabezpieczonych; współczesna randomizacja w Androidzie jest zwykle trwała dla danego SSID. Ogranicza to tylko jeden lokalny identyfikator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Preferuj kontrolowany przez organizację travel router lub urządzenie bridge o niskim poziomie zaufania między uprzywilejowaną stacją roboczą a siecią gościnną. Centralizuje to politykę firewalla/VPN, ale nie ukrywa routera przed właścicielem sieci.<sup>[[12]](#references)</sup>
5. Obsługuj captive portal wyłącznie za pomocą wskazanego urządzenia/przeglądarki o niskim poziomie zaufania. Nigdy nie wprowadzaj osobistych ani ponownie używanych danych uwierzytelniających w rzekomo anonimowym kontekście. Zamknij przeglądarkę portalu po uzyskaniu połączenia.
6. Uruchom VPN z pełnym tunelem lub Tor przed wrażliwą aktywnością i potwierdź działanie w trybie fail-closed.
7. Po użyciu zapomnij sieć i sprawdź politykę konta portalu oraz przechowywania danych.

{% hint style="danger" %}
Włamywanie się do Wi-Fi sąsiada, omijanie portalu, używanie leaked danych uwierzytelniających gości, klonowanie dostępu innego gościa lub ukrywanie Raspberry Pi w kawiarni to działania nieuprawnione, a nie technika ochrony prywatności. Bezpiecznymi odpowiednikami są zgodna z prawem sieć gościnna, zatwierdzona przez klienta lokalizacja albo udokumentowany drop node umieszczony i odzyskany za pisemną zgodą właściciela obiektu.
{% endhint %}

## Travel routery

Travel router może odizolować stację roboczą od wrogich lokalnych broadcastów, wymuszać działanie firewalla, zapewniać spójny wewnętrzny SSID i automatycznie ponownie nawiązywać połączenie VPN. **Nie** zapewnia anonimowości: sieć nadrzędna widzi jego tożsamość radiową i czasy ruchu, a dostawca VPN widzi źródło tunelu.

- Używaj obsługiwanego firmware OpenWrt/vendor i usuń nieużywane usługi.
- Administruj przez Ethernet lub dedykowany SSID zarządzania z unikalnym hasłem.
- Wyłącz administrację od strony WAN, UPnP, WPS, udostępnianie plików i niezamówiony ruch przychodzący.
- Używaj losowego/prywatnego WAN MAC tylko wtedy, gdy jest obsługiwany i dozwolony.
- Wymuś politykę VPN na routerze, w tym DNS i IPv6, oraz blokuj ruch wychodzący, gdy tunel przestanie działać.
- Nie zakładaj, że hotspot telefonu przesyła urządzenia tetherowane przez VPN telefonu; przetestuj to.

## Sieć komórkowa, SIM i eSIM

Sieć komórkowa jest wygodna, ale nie zapewnia anonimowości. Operatorzy przechowują identyfikatory abonenta/urządzenia oraz lokalizację wywnioskowaną z dołączenia do sieci; eSIM nadal jest abonamentem komórkowym. Prepaid nie oznacza niezawodnie braku rejestracji — wymagania różnią się w zależności od kraju i ulegają zmianom.<sup>[[13]](#references)</sup>

Operacyjnie:

- Używaj oddzielnego, obsługiwanego urządzenia, aby ograniczyć ujawnianie danych osobowych, a nie w celu stworzenia fikcyjnego abonenta.
- Nie noś stale „oddzielnego” urządzenia razem z osobistym telefonem, jeśli współlokalizacja znajduje się w modelu zagrożeń.
- Wyłącz nieużywaną sieć komórkową, Wi-Fi, Bluetooth i dostęp do lokalizacji; wyłączenie zasilania stanowi silniejszą granicę radiową niż przełączniki w interfejsie.
- Umieszczaj wrażliwy ruch wewnątrz zatwierdzonej ścieżki VPN/Tor, pamiętając, że operator nadal zna lokalizację abonamentu/urządzenia oraz endpoint tunelu.
- Sprawdzaj aktualne zasady rejestracji i przechowywania danych u krajowego regulatora lub lokalnego prawnika; nie polegaj na internetowych listach „anonimowych krajów SIM”.

## Metadane DNS i TLS

- **DoH/DoT/DoQ** szyfrują DNS między klientem a resolverem, uniemożliwiając proste lokalne odczytanie lub modyfikację, ale resolver nadal widzi zapytania i identyfikatory transportowe. Przenoszą zaufanie, lecz nie zapewniają anonimowości.<sup>[[14]](#references)</sup>
- **ODoH** dodaje proxy, dzięki czemu resolver nie musi poznawać adresu IP klienta, zakładając, że proxy i cel nie współpracują. Analiza ruchu jest wyraźnie poza zakresem.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** może chronić wewnętrzną nazwę serwera w handshake TLS, gdy obsługują ją klient, DNS i serwer. Adres docelowy IP, czas, objętość ruchu oraz endpoint pozostają widoczne.<sup>[[16]](#references)</sup>
- W prawidłowo skonfigurowanym środowisku VPN lub Tor DNS powinien korzystać z obsługiwanej przez to środowisko trasy. Dodanie oddzielnego resolvera może utworzyć nowego obserwatora lub fingerprint.

### Workflow weryfikacji szyfrowanego DNS/ECH

1. Ustal, czy DNS jest kontrolowany przez środowisko VPN/Tor, system operacyjny czy aplikację. Skonfiguruj go w **jednej** zamierzonej warstwie zamiast łączyć niepowiązane resolvery.
2. Wybierz resolver na podstawie opublikowanej polityki prywatności/przechowywania danych i włącz ścisły tryb szyfrowany, jeśli platforma go obsługuje. Fallback oportunistyczny może po cichu powrócić do tekstu jawnego.
3. Wykonaj zapytanie do unikalnej subdomeny w autorytatywnej strefie testowej, którą kontrolujesz; potwierdź, że log autorytatywny widzi zamierzony rekurencyjny resolver.
4. Za zgodą przechwyć wyłącznie ruch urządzenia testowego. Potwierdź, że sieć dostępowa nie może odczytać DNS w tekście jawnym, pamiętając, że może widzieć zaszyfrowany endpoint resolvera/tunelu.
5. Przetestuj zablokowany/niedostępny szyfrowany resolver. Warunkiem zaliczenia jest wybrane zachowanie fail-closed lub udokumentowany fallback, a nie przypadkowe zapytanie jawnym tekstem.
6. W przypadku ECH użyj kontrolowanego hosta z obsługą ECH i przeanalizuj diagnostykę klienta/serwera, aby potwierdzić, że **wewnętrzny** ClientHello został zaakceptowany. Samo oferowanie rekordu HTTPS nie dowodzi, że ECH zadziałało.
7. Powtórz test po zmianach sieci, captive portalach, aktualizacjach przeglądarki i ponownym łączeniu VPN. Zapisz, który komponent kontroluje DNS/ECH, aby późniejsi administratorzy nie utworzyli obejścia.

## Mixnety

Mixnety, takie jak Nym lub Katzenpost, dodają pakiety o stałym rozmiarze, opóźnienia, zmianę kolejności i ruch pozorny, aby utrudnić korelację czasową. Właściwości te wiążą się z kosztami w postaci opóźnień i przepustowości, a niezależne dowody dotyczące wdrożeń na dużą skalę są ograniczone. Obecne konsumenckie mixnety traktuj jako **wschodzące/opóźnione opcje**, a nie szybsze lub gwarantowane zamienniki Tor/VPN.<sup>[[17]](#references)</sup>

### Workflow oceny

1. Zidentyfikuj utrzymywanego klienta i dokładnie obsługiwaną aplikację; nie wymuszaj przesyłania dowolnego ruchu przeglądarki/systemu przez nieudokumentowane proxy.
2. Przeczytaj aktualny model zagrożeń dotyczący założeń dla wejścia, mix nodes, gateway, celu i współpracy.
3. Zainstaluj oprogramowanie z oficjalnego podpisanego źródła w oddzielnym środowisku testowym i używaj wyłącznie niegroźnego, należącego do Ciebie endpointu.
4. Zmierz opóźnienie dostarczania, limity rozmiaru wiadomości, niezawodność, retransmisję oraz zachowanie w przypadku niedostępności gateway.
5. Przeanalizuj lokalny ruch i należący do Ciebie endpoint, aby potwierdzić zamierzoną ścieżkę i źródło. Sprawdź, czy odpowiedzi korzystają z tego samego modelu prywatności.
6. Przetestuj zamknięcie/awarię: aplikacja nie może po cichu powrócić do bezpośredniego dostępu do Internetu.
7. Nie wyłączaj ruchu pozornego, nie skracaj opóźnień ani nie wybieraj nietypowych stałych tras wyłącznie dla szybkości; zmiany te mogą unieważnić deklarowany model anonimowości.
8. Pozostaw rozwiązanie eksperymentalne, dopóki konkretne wdrożenie, niezależna analiza i niezawodność operacyjna nie będą odpowiadały poziomowi konsekwencji.

## Lista kontrolna preflight sieci

- [ ] Autoryzacja obejmuje sieć dostępową, cel, daty i infrastrukturę źródłową.
- [ ] Endpoint nie zawiera niepowiązanych tożsamości ani aktywnych sesji synchronizacji.
- [ ] Zachowanie IPv4, IPv6, DNS i ponownego łączenia jest zgodne z planem.
- [ ] Kontrolowane wstrzykiwanie tras DHCP/podsieci lokalnej nie może przenieść ruchu testowego na interfejs fizyczny.
- [ ] Cel widzi wyłącznie oczekiwany egress.
- [ ] Działanie captive portalu i hotspotu zostało przetestowane bez wrażliwego ruchu.
- [ ] Lokalne udostępnianie/wykrywanie oraz automatyczne dołączanie do sieci są wyłączone.
- [ ] Tabela obserwatorów i pozostałe ryzyko korelacji ruchu są zaakceptowane.
- [ ] Polityka dostawcy, przechowywanie danych i kontakt awaryjny są aktualne.

Informacje o relayach z podziałem wiedzy, workloadach wymuszających trasę, pluggable transports, usługach onion, I2P i jednorazowych zdalnych przeglądarkach znajdziesz w [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Wybór odpowiedniego dla Ciebie VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Wytyczne dotyczące bezpieczeństwa urządzeń: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Ochrona prywatności i anonimowości oferowana przez Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Krótkie wprowadzenie do Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Używanie Tor z innymi przeglądarkami](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Wtyczki i add-ony w Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Odblokowywanie Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Używanie Tor Browser z VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Czy publiczne sieci Wi-Fi są bezpieczne?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Prywatność Wi-Fi na urządzeniach Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementowanie randomizacji MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Zasady bezpiecznych uprzywilejowanych stacji roboczych](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Obowiązkowa rejestracja SIM: perspektywy polityczne i regulacyjne](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Zalecenia dla operatorów usług ochrony prywatności DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Model zagrożeń](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Omijanie tuneli: ujawnianie ruchu klienta VPN przez nadużywanie tablic routingu](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: jak napastnicy mogą usunąć ukrycie routowanych VPN w celu całkowitego VPN Leak](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
