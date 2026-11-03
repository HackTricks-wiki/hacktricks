# Prywatność sieciowa i anonimowa łączność

{{#include ../banners/hacktricks-training.md}}

Prywatność sieciowa to decyzja o routingu, a nie pełna tożsamość. Wybierając ścieżkę, zastanów się, kto nie powinien móc powiązać **źródła**, **celu**, **treści** i **czasu**.

Znormalizowany wykaz — `Pros`, `Cons`, krok po kroku `Procedure` oraz `Detection` dla każdej rodziny ścieżek dostępu — znajdziesz w [Katalogu technik anonimowego dostępu do Internetu](anonymous-internet-access-techniques.md). Ta strona rozwija najczęściej wdrażane opcje.

## Co zwykle widzi każdy obserwator

| Ścieżka | Sieć lokalna / ISP | Pośrednik | Cel | Główne ograniczenie | Względna szybkość |
|---|---|---|---|---|---|
| Bezpośrednie HTTPS | Źródło, metadane celu, czas i wielkość ruchu | Hosting/CDN widzi połączenie | Adres IP źródła, dane przeglądarki/aplikacji | Brak prywatności adresu IP źródła | Najszybsza |
| Komercyjny VPN | Źródło połączone z VPN; zwykle bez metadanych celu | VPN widzi źródło i metadane celu | Adres IP wyjściowy VPN | Jeden dostawca staje się punktem korelacji | Zwykle szybka |
| Samodzielnie hostowany VPN/VPS | Źródło połączone z VPS | Logi hosta/konta/płatności/płaszczyzny sterowania | Adres IP wyjściowy VPS | Łatwo powiązać z wynajętym serwerem/kontem | Zwykle szybka |
| Tor Browser | Źródło połączone z Tor/bridge; czas i wielkość ruchu | Każdy przekaźnik widzi tylko ograniczoną część | Węzeł wyjściowy Tor, dane przeglądarki | Wolniejsza; ryzyko związane z kontem/urządzeniem końcowym/korelacją | Średnia/wolna |
| Tails/Whonix | Podobna ścieżka Tor, z silniejszymi granicami routingu | Te same ograniczenia Tor | Węzeł wyjściowy Tor/dane aplikacji | Błędy operacyjne oraz host/sprzęt nadal mają znaczenie | Średnia/wolna |
| Publiczne gościnne Wi-Fi + HTTPS | Obiekt widzi lokalne urządzenie/czas i cele | ISP obiektu widzi metadane | Publiczny adres IP gościa | Korelacja fizycznej lokalizacji/portalu captive/device | Szybka/zmienna |
| Hotspot komórkowy | Operator widzi abonenta/urządzenie/lokalizację i cele | VPN/Tor, jeśli używane | Adres IP wyjściowy operatora, VPN lub Tor | Abonament komórkowy i lokalizacja to trwałe identyfikatory | Szybka/zmienna |
| Mixnet | Dostawca dostępu widzi użycie mixnetu; czas i wielkość ruchu | Wiele węzłów miksujących | Brama/wyjście | Rozwijający się ekosystem; koszt opóźnienia i przepustowości | Najwolniejsza |

HTTPS chroni treść przesyłaną przez sieć, ale nie wszystkie metadane. EFF zauważa, że domena, czas i wielkość ruchu mogą pozostać widoczne dla pośredników, nawet gdy ścieżki stron, dane logowania i wiadomości są szyfrowane.<sup>[[1]](#references)</sup>

Szyfrowana nakładka sieciowa nie staje się automatycznie siecią anonimową: bezpośredni peering Yggdrasil pozwala każdej ze stron zobaczyć adres IP drugiej.<sup>[[20]](#references)</sup> [Przekazywanie w przestrzeni użytkownika i transport SOCKS](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) to opcja tunelowania, a nie warstwa anonimizująca źródło.<sup>[[20]](#references)[[21]](#references)</sup>

## VPN-y: szybka prywatność oparta na skoncentrowanym zaufaniu

VPN przydaje się do ukrywania metadanych celu przed ISP zapewniającym dostęp, ochrony pierwszego przeskoku w niezaufanej sieci, zapewnienia stabilnego adresu wyjściowego na potrzeby zaangażowania lub uzyskania dostępu do sieci prywatnej. **Nie** zapewnia anonimowości. VPN widzi połączenie źródłowe i może obserwować metadane celu; konta, cookies, GPS, fingerprints i dane płatnicze nadal pozostają widoczne.<sup>[[1]](#references)</sup>

### Lista kontrolna oceny dostawcy

1. **Własność i jurysdykcja:** ustal tożsamość podmiotu prawnego, spółkę dominującą, kraje prowadzenia działalności, podwykonawców infrastruktury oraz obowiązujące procedury prawne.
2. **Gromadzone dane:** rozróżnij dane konta/rozliczeń, źródłowy adres IP, znaczniki czasu połączeń, przepustowość, telemetrię awarii, zapytania DNS i logi celów. „Brak logów przeglądania” nie oznacza „braku danych”.
3. **Przechowywanie i usuwanie:** sprawdź dokładne okresy przechowywania oraz to, czy kopie zapasowe, systemy antyfraudowe i podmioty przetwarzające stosują ten sam harmonogram.
4. **Dowody:** preferuj publiczne audyty z określonym zakresem, datą, ustaleniami i działaniami naprawczymi; odtwarzalne/otwarte klienty; raporty przejrzystości; oraz udokumentowane incydenty.
5. **Protokół i klient:** aktualizowany WireGuard, OpenVPN lub inny sprawdzony protokół; automatyczne aktualizacje; obsługa DNS i IPv6; kill switch; oraz testy leak dla każdej platformy.
6. **Model biznesowy:** dowiedz się, skąd pochodzą środki na bezpłatną lub subsydiowaną usługę. Sama obecność w sklepie z aplikacjami nie świadczy o wiarygodności usługi.
7. **Opcje płatności:** alternatywna metoda płatności może ograniczyć ujawnianie danych rozliczeniowych VPN-owi, ale nie usuwa źródłowego adresu IP, który jest widoczny przy każdym połączeniu.

### Konfiguracja i weryfikacja VPN

1. Zainstaluj podpisanego klienta dostawcy/organizacji z oficjalnego źródła.
2. Wybierz **full tunnel**, chyba że udokumentowana trasa musi go omijać. Split tunneling tworzy ścieżki korelacji i leak.
3. Włącz tryb fail-closed/always-on i blokuj ruch podczas ponownego łączenia.
4. Przesyłaj DNS przez tunel i testuj zarówno IPv4, jak i IPv6. Wyłącz protokół tylko wtedy, gdy nie można go bezpiecznie tunelować, a utrata funkcjonalności jest akceptowalna.
5. Przetestuj usypianie/wznawianie, przełączanie sieci, logowanie do portalu captive, awarię tunelu i tethering hotspotu. NCSC ostrzega, że na niektórych platformach klienci podłączeni przez tethering mogą omijać VPN telefonu.<sup>[[2]](#references)</sup>
6. Użyj testowego endpointu kontrolowanego przez organizację, aby rejestrować widoczne adresy IPv4 i IPv6, resolver DNS oraz czas połączeń. Nie ujawniaj informacji o wrażliwym zaangażowaniu przypadkowym serwisom do testowania leak.
7. Powtórz testy po zmianach klienta, systemu operacyjnego, sieci lub zasad.

### Ominięcie routingu w niezaufanej sieci LAN

VPN może nadal wyglądać na „połączony”, mimo że wybrane pakiety go omijają, ponieważ system operacyjny wybiera trasę **przed** zaszyfrowaniem pakietu przez VPN. TunnelCrack wykazał dwa sposoby wykorzystania typowych wyjątków routingu: **LocalNet** sprawia, że cel internetowy wygląda na znajdujący się w bezpośrednio połączonej podsieci, natomiast **ServerIP** fałszuje rozpoznawanie adresu bramy VPN, przez co adres docelowy dziedziczy wyjątek sieci jawnej wymagany przez transport VPN. Są to błędy klienta/routingu, a nie przełamanie WireGuard, OpenVPN, IPsec lub TLS; ładunki HTTPS pozostają szyfrowane end-to-end, ale lokalny obserwator może odzyskać metadane celu/czasu oraz wszelkie dane protokołu przesyłane jawnym tekstem.<sup>[[18]](#references)</sup>

TunnelVision wykorzystuje tę samą prymitywną technikę przed szyfrowaniem za pośrednictwem opcji DHCP 121. Złośliwy lub przejęty serwer DHCP może zainstalować trasę bezklasową bardziej szczegółową niż ogólna trasa VPN, kierując ruch do dowolnego hosta lub zakresu przez interfejs fizyczny. Kanał sterowania VPN może pozostać aktywny, więc kill switch uruchamiany wyłącznie po rozłączeniu tunelu może się nie aktywować, a pojedynczy publiczny test „leak adresu IP” może nie wykryć selektywnego omijania tunelu.<sup>[[19]](#references)</sup>

Kill switch oparty na filtrowaniu pakietów, który na interfejsie fizycznym zezwala wyłącznie na DHCP i uwierzytelniony transport VPN, powinien wymusić tryb fail-closed. Ukierunkowane wstrzyknięcie trasy nadal może jednak utworzyć selektywny kanał boczny odmowy usługi. W przypadku obciążeń Linux o wysokich konsekwencjach preferuj mocniejszy [wzorzec przestrzeni nazw sieciowych z wymuszaniem tras](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), w którym przestrzeń nazw aplikacji nie ma interfejsu fizycznego ani domyślnej trasy do sieci jawnej.<sup>[[19]](#references)</sup>

#### Weryfikacja w kontrolowanym laboratorium

Testuj dokładnie używanego klienta/system operacyjny/wersję na własnym AP, serwerze DHCP, endpointcie VPN i celu. Uogólnione twierdzenia o produktach szybko się dezaktualizują, ponieważ implementacje routingu i filtrowania pakietów różnią się w zależności od platformy. Przechwytuj ruch zarówno na samym endpoincie, jak i na serwerze testowym — sama strona pokazująca egress IP nie dowodzi, że każdy cel jest osiągany przez tunel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Połącz się z VPN, zanotuj adres serwera VPN i zapisz wszystkie tabele routingu IPv4/IPv6 oraz reguły routingu według zasad. W Windows użyj `route print`; w macOS — `netstat -rn`; w Linux — poniższych poleceń.
2. Sprawdź wybraną trasę dla kilku należących do Ciebie adresów IP celu. Następny przeskok/interfejs musi wskazywać tunel, z wyjątkiem udokumentowanego endpointu transportu VPN.
3. W przypadku TunnelVision odnów dzierżawę w kontrolowanej sieci DHCP i skonfiguruj trasę opcji 121 **wyłącznie dla należącego do Ciebie celu testowego**. Test zalicza się, jeśli ruch nadal jest tunelowany lub blokowany — nigdy nie jest wysyłany jako ruch do celu przez interfejs fizyczny.
4. W przypadku LocalNet przydziel klientowi używaną wyłącznie w laboratorium publiczną podsieć dokumentacyjną, taką jak `203.0.113.0/24`, i umieść w niej należący do Ciebie cel testowy. Sprawdź, czy włączenie dostępu do LAN nie powoduje omijania tunelu przez cele z Internetu.
5. W przypadku ServerIP, przed połączeniem VPN skonfiguruj kontrolowany DNS tak, aby rozpoznawał należącą do Ciebie nazwę hosta VPN jako należący do Ciebie cel testowy, podczas gdy brama laboratoryjna przekazuje transport VPN do właściwego, należącego do Ciebie endpointu VPN. Klient nie może wyłączać z tunelowania niezwiąznego ruchu aplikacji kierowanego na sfałszowany adres.
6. Powtórz testy z włączonym i wyłączonym ustawieniem „dostęp do sieci lokalnej”, po ponownym połączeniu, usypianiu/wznawianiu, przełączaniu sieci i awarii procesu VPN. Testuj niezależnie IPv4, IPv6 i DNS.
7. Sprawdź przechwycony ruch na interfejsie fizycznym. Powinien zawierać DHCP i zaszyfrowane pakiety kierowane do serwera VPN, a nie pakiety adresowane bezpośrednio do należącego do Ciebie celu testowego. Upewnij się też, że odrzucone ominięcie tunelu nie powoduje po cichu przełączenia na trasę awaryjną po wyświetleniu monitów użytkownikowi lub naprawieniu łączności.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: większa niepowiązywalność aktywności w sieci

Tor tworzy obwód przez wiele przekaźników, dzięki czemu żaden pojedynczy przekaźnik zwykle nie zna jednocześnie źródła i celu. Cel widzi przekaźnik wyjściowy Tor zamiast adresu IP użytkownika; sieć lokalna zazwyczaj widzi połączenie z Tor.<sup>[[3]](#references)</sup> Tor zaprojektowano z myślą o aplikacjach TCP o niskim opóźnieniu, dlatego działa wolniej i nie może zagwarantować ochrony przed przeciwnikiem zdolnym do korelowania obu końców połączenia.<sup>[[4]](#references)</sup>

### Bezpieczny sposób korzystania z Tor Browser

1. Pobieraj Tor Browser wyłącznie z Tor Project lub oficjalnego mirroru i, jeśli to możliwe, weryfikuj podpis.
2. Korzystaj z **Tor Browser**, a nie ze zwykłej przeglądarki skonfigurowanej do korzystania z portu SOCKS Tor. Zwykłe przeglądarki mogą powodować wycieki DNS/WebRTC i ujawniać dane identyfikujące.<sup>[[5]](#references)</sup>
3. Zachowaj domyślny rozmiar okna, czcionki, rozszerzenia i ustawienia prywatności. Dodatkowe dodatki mogą sprawić, że przeglądarka będzie bardziej unikatowa.<sup>[[6]](#references)</sup>
4. Wybierz poziom zabezpieczeń **Safer** lub **Safest**, jeśli akceptujesz wynikające z niego problemy z działaniem stron.
5. Użyj bridge, gdy bezpośredni dostęp do Tor jest blokowany lub gdy zwykłe adresy IP przekaźników byłyby zbyt widoczne w sieci lokalnej. Bridge utrudniają łatwe rozpoznanie ruchu, ale nie eliminują analizy ruchu.<sup>[[7]](#references)</sup>
6. Nie loguj się na konto pozwalające cię zidentyfikować, nie podawaj danych identyfikujących ani nie otwieraj pobranych aktywnych dokumentów w zewnętrznej aplikacji mającej dostęp do sieci.
7. Używaj osobnej sesji/kontekstu dla każdej tożsamości. „New circuit” nie oznacza tego samego co wymazanie tożsamości przeglądarki/aplikacji; w razie potrzeby użyj **New Identity** lub uruchom ponownie odizolowane środowisko.
8. Preferuj uwierzytelnione połączenie HTTPS lub uwierzytelnioną usługę onion. Przekaźnik wyjściowy Tor może obserwować niezaszyfrowany ruch HTTP.

### Tor i VPN

Łączenie ich nie jest automatycznie bezpieczniejsze. VPN przed Tor może ukryć bezpośrednie połączenia z przekaźnikami Tor przed ISP, ale sam VPN widzi źródło; Tor przed VPN daje VPN-owi stabilny podgląd aktywności po Tor i może zmniejszyć zbiór anonimowości. Błędna konfiguracja może powodować wycieki. Tor Project zaleca takie połączenia wyłącznie zaawansowanym użytkownikom, którzy mają jasno określony model zagrożeń.<sup>[[8]](#references)</sup>

## Publiczne i gościnne sieci Wi-Fi

Współczesny HTTPS oznacza, że pasywni użytkownicy w pobliżu zwykle nie mogą odczytać prawidłowo zaszyfrowanej treści stron, ale gościnne Wi-Fi nie zapewnia anonimowości. Lokal może rejestrować godziny połączeń, identyfikatory urządzeń, dane z portalu logowania, odwiedzane cele i szczegóły DHCP; użytkownika mogą zidentyfikować kamery, zakupy, transport i obserwacja fizyczna. Fałszywy hotspot o podobnej nazwie może też przechwytywać dane logowania do portalu lub modyfikować niezaszyfrowany ruch.<sup>[[9]](#references)</sup>

### Zgodne z prawem korzystanie z sieci gościnnej

1. Korzystaj wyłącznie z sieci udostępnionej gościom lub takiej, na którą właściciel wyraźnie zezwolił. Poproś obsługę o dokładną nazwę SSID i instrukcję korzystania z portalu.
2. Zaktualizuj urządzenie końcowe i router podróżny przed przyjazdem. Wyłącz udostępnianie plików/drukarek, wykrywanie urządzeń przychodzących, automatyczne łączenie i wyszukiwanie zapamiętanych sieci.
3. Włącz w systemie operacyjnym prywatny/losowy adres Wi-Fi. Aktualne systemy Apple mogą używać rotujących adresów w otwartych/słabo zabezpieczonych sieciach; współczesna randomizacja w Androidzie jest zwykle trwała dla danego SSID. Ogranicza to tylko jeden lokalny identyfikator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Preferuj kontrolowany przez organizację router podróżny lub urządzenie pomostowe o niskim poziomie zaufania między uprzywilejowaną stacją roboczą a siecią gościnną. Ułatwia to centralne zarządzanie polityką zapory/VPN, ale nie ukrywa routera przed lokalem.<sup>[[12]](#references)</sup>
5. Korzystaj z portalu logowania wyłącznie przez wyznaczone urządzenie/przeglądarkę o niskim poziomie zaufania. Nigdy nie podawaj danych osobowych ani używanych ponownie haseł w kontekście, który ma być anonimowy. Po uzyskaniu połączenia zamknij przeglądarkę portalu.
6. Przed wrażliwą aktywnością uruchom VPN z pełnym tunelowaniem lub Tor i potwierdź działanie mechanizmu blokowania ruchu w razie awarii.
7. Po użyciu zapomnij sieć i sprawdź zasady dotyczące konta portalowego i przechowywania danych.

{% hint style="danger" %}
Łamanie zabezpieczeń Wi-Fi sąsiada, omijanie portalu, używanie wyciekłych danych logowania gości, klonowanie dostępu innego gościa lub ukrywanie Raspberry Pi w kawiarni to działania bez zezwolenia — nie techniki ochrony prywatności. Bezpieczne odpowiedniki to zgodna z prawem sieć gościnna, lokal zatwierdzony przez klienta lub udokumentowany drop node, umieszczony i odzyskany za pisemną zgodą właściciela nieruchomości.
{% endhint %}

## Routery podróżne

Router podróżny może odizolować stację roboczą od niezaufanych lokalnych rozgłoszeń, wymuszać działanie zapory, udostępniać niezmienny wewnętrzny SSID i automatycznie ponownie łączyć VPN. **Nie** zapewnia anonimowości: sieć nadrzędna widzi jego tożsamość radiową i czas ruchu, a dostawca VPN widzi źródło tunelu.

- Korzystaj z obsługiwanego firmware OpenWrt/dostawcy i usuń nieużywane usługi.
- Zarządzaj routerem przez Ethernet lub dedykowany SSID do zarządzania z unikatowym hasłem.
- Wyłącz zarządzanie od strony WAN, UPnP, WPS, udostępnianie plików i niezamówiony ruch przychodzący.
- Używaj losowego/prywatnego adresu MAC WAN tylko wtedy, gdy jest to obsługiwane i dozwolone.
- Wymuś politykę VPN na routerze, w tym DNS i IPv6, oraz blokuj ruch wychodzący w razie awarii tunelu.
- Nie zakładaj, że hotspot telefonu tuneluje urządzenia podłączone przez tethering przez VPN telefonu — przetestuj to.

## Sieci komórkowe, karty SIM i eSIM

Sieć komórkowa jest wygodna, ale nie zapewnia anonimowości. Operatorzy przechowują identyfikatory abonenta/urządzenia oraz dane lokalizacyjne wynikające z połączenia z siecią; eSIM nadal jest abonamentem komórkowym. Prepaid nie oznacza niezarejestrowanej karty — wymagania różnią się w zależności od kraju i ulegają zmianom.<sup>[[13]](#references)</sup>

W praktyce:

- Używaj osobnego, obsługiwanego urządzenia, aby ograniczyć ujawnianie danych osobowych, a nie tworzyć fikcyjnego abonenta.
- Jeśli model zagrożeń uwzględnia współlokalizację, nie noś stale „osobnego” urządzenia razem z prywatnym telefonem.
- Wyłącz nieużywane sieci komórkowe, Wi-Fi, Bluetooth i dostęp do lokalizacji; wyłączenie urządzenia zapewnia silniejszą izolację radiową niż przełączniki w interfejsie.
- Przesyłaj wrażliwy ruch zatwierdzoną ścieżką VPN/Tor, pamiętając, że operator nadal zna abonament, lokalizację urządzenia i punkt końcowy tunelu.
- Sprawdź aktualne zasady rejestracji i przechowywania danych u krajowego regulatora lub lokalnego prawnika; nie polegaj na internetowych listach „krajów z anonimowymi kartami SIM”.

## Metadane DNS i TLS

- **DoH/DoT/DoQ** szyfrują DNS między klientem a resolverem, uniemożliwiając proste odczytanie lub modyfikację w sieci lokalnej, ale resolver nadal widzi zapytania i identyfikatory transportowe. Zmieniają podmiot, któremu ufasz; nie zapewniają anonimowości.<sup>[[14]](#references)</sup>
- **ODoH** dodaje proxy, dzięki czemu resolver nie musi poznawać adresu IP klienta, zakładając, że proxy i serwer docelowy nie współpracują. Analiza ruchu jest wyraźnie poza zakresem ochrony.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** może chronić wewnętrzną nazwę serwera w uzgadnianiu TLS, jeśli obsługują je klient, DNS i serwer. Adres IP celu, czas, ilość ruchu i punkt końcowy pozostają widoczne.<sup>[[16]](#references)</sup>
- W prawidłowo skonfigurowanym środowisku VPN lub Tor DNS powinien korzystać z obsługiwanej przez to środowisko ścieżki. Dodanie osobnego resolvera może wprowadzić nowego obserwatora lub cechę identyfikującą.

### Procedura weryfikacji szyfrowanego DNS/ECH

1. Zdecyduj, czy DNS jest kontrolowany przez środowisko VPN/Tor, system operacyjny czy aplikację. Skonfiguruj go w **jednej** wybranej warstwie zamiast łączyć niezależne resolvery.
2. Wybierz resolver na podstawie opublikowanych zasad prywatności/przechowywania danych i włącz ścisły tryb szyfrowany, jeśli platforma go obsługuje. Tryb oportunistyczny może po cichu wrócić do tekstu jawnego.
3. Wykonaj zapytanie o unikatową subdomenę w autorytatywnej testowej strefie, którą kontrolujesz; potwierdź, że log autorytatywny wskazuje zamierzony rekurencyjny resolver.
4. Za zgodą przechwyć wyłącznie ruch urządzenia testowego. Potwierdź, że sieć dostępowa nie może odczytać niezaszyfrowanego DNS, pamiętając, że widzi zaszyfrowany punkt końcowy resolvera/tunelu.
5. Przetestuj zablokowany/niedostępny szyfrowany resolver. Warunkiem zaliczenia jest wybrana blokada w razie awarii lub udokumentowane zachowanie awaryjne — a nie przypadkowe zapytanie w postaci jawnej.
6. W przypadku ECH użyj kontrolowanego hosta z obsługą ECH i sprawdź diagnostykę klienta/serwera, aby potwierdzić, że zaakceptowano **wewnętrzny** ClientHello. Samo udostępnienie rekordu HTTPS nie dowodzi, że ECH zadziałało.
7. Powtórz test po zmianie sieci, użyciu portali logowania, aktualizacji przeglądarki i ponownym połączeniu VPN. Zapisz, który komponent odpowiada za DNS/ECH, aby późniejsi administratorzy nie utworzyli obejścia.

## Mixnety

Mixnety, takie jak Nym lub Katzenpost, dodają pakiety o stałym rozmiarze, opóźnienia, zmianę kolejności i ruch maskujący, aby utrudnić korelację czasową. Te właściwości zwiększają opóźnienia i zużycie pasma, a niezależnych dowodów dotyczących wdrożeń na dużą skalę jest niewiele. Traktuj obecne mixnety konsumenckie jako **rozwijające się opcje o dużych opóźnieniach**, a nie szybsze lub gwarantowane zamienniki Tor/VPN.<sup>[[17]](#references)</sup>

### Procedura oceny

1. Znajdź utrzymywanego klienta i dokładnie określoną obsługiwaną aplikację; nie wymuszaj przesyłania dowolnego ruchu przeglądarki/systemu przez nieudokumentowane proxy.
2. Zapoznaj się z aktualnym modelem zagrożeń dotyczącym założeń o wejściu, węzłach mixnetu, bramie, celu i współpracy podmiotów.
3. Zainstaluj oprogramowanie z oficjalnego, podpisanego źródła w osobnym środowisku testowym i korzystaj wyłącznie z nieszkodliwego, należącego do ciebie punktu końcowego.
4. Zmierz opóźnienie dostarczenia, limity rozmiaru wiadomości, niezawodność, ponowne transmisje i zachowanie w przypadku niedostępności bramy.
5. Sprawdź lokalny ruch i należący do ciebie punkt końcowy, aby potwierdzić zamierzoną ścieżkę i źródło. Ustal, czy odpowiedzi korzystają z tego samego modelu prywatności.
6. Przetestuj zamknięcie/awarię: aplikacja nie może po cichu przełączać się na bezpośredni dostęp do Internetu.
7. Nie wyłączaj ruchu maskującego, nie skracaj opóźnień ani nie wybieraj nietypowych stałych tras wyłącznie dla szybkości; takie zmiany mogą unieważnić deklarowany model anonimowości.
8. Pozostaw rozwiązanie w fazie eksperymentalnej, dopóki konkretne wdrożenie, niezależne analizy i niezawodność operacyjna nie będą adekwatne do poziomu potencjalnych konsekwencji.

## Lista kontrolna przed połączeniem z siecią

- [ ] Zgoda obejmuje sieć dostępową, cel, daty i infrastrukturę źródłową.
- [ ] Urządzenie końcowe nie zawiera niezwiązanych tożsamości ani aktywnych sesji synchronizacji.
- [ ] IPv4, IPv6, DNS i zachowanie przy ponownym połączeniu są zgodne z planem.
- [ ] Kontrolowane wstrzykiwanie tras DHCP/do podsieci lokalnej nie może skierować testowego ruchu przez fizyczny interfejs.
- [ ] Cel widzi wyłącznie oczekiwany punkt wyjścia.
- [ ] Zachowanie portalu logowania i hotspotu zostało przetestowane bez wrażliwego ruchu.
- [ ] Udostępnianie/wykrywanie lokalne i automatyczne łączenie z sieciami są wyłączone.
- [ ] Tabela obserwatorów i pozostałe ryzyko korelacji ruchu są zaakceptowane.
- [ ] Zasady dostawcy, okres przechowywania danych i kontakt alarmowy są aktualne.

Informacje o przekaźnikach rozdzielających wiedzę, obciążeniach z wymuszanym trasowaniem, transportach wtykowych, usługach onion, I2P i tymczasowych zdalnych przeglądarkach znajdziesz w [Zaawansowane architektury prywatności sieciowej](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Wybór odpowiedniej sieci VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Wskazówki dotyczące bezpieczeństwa urządzeń: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Ochrona prywatności i anonimowości oferowana przez Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Specyfikacje Tor — Krótkie wprowadzenie do Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Korzystanie z Tor w innych przeglądarkach](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Wtyczki i dodatki w Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Odblokowanie Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Korzystanie z Tor Browser z VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Czy publiczne sieci Wi-Fi są bezpieczne?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Prywatność Wi-Fi na urządzeniach Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementacja randomizacji MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Zasady dotyczące bezpiecznych stacji roboczych z uprzywilejowanym dostępem](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Obowiązkowa rejestracja kart SIM: perspektywy polityczne i regulacyjne](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Zalecenia dla operatorów usług ochrony prywatności DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Model zagrożeń](https://katzenpost.network/docs/threat_model/)
- [18] [Xue i in. — Omijanie tuneli: wyciek ruchu klienta VPN przez nadużywanie tablic routingu](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: jak atakujący mogą zdemaskować VPN-y oparte na routingu i spowodować całkowity VPN leak](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [FAQ Yggdrasil: Czy Yggdrasil zapewnia anonimowość?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [README Yggstack](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
