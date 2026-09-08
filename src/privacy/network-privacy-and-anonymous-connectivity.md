# Prywatność sieciowa i anonimowa łączność

Prywatność sieciowa to decyzja dotycząca routingu, a nie kompletna tożsamość. Wybieraj ścieżkę, pytając, kto nie powinien móc połączyć **źródła**, **celu**, **treści** i **czasu**.

Dla ustandaryzowanego zestawienia — `Pros`, `Cons`, kroków `Procedure` i sekcji `Detection` dla każdej rodziny ścieżek dostępu — zacznij od [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Ta strona rozszerza opis typowych, możliwych do wdrożenia opcji.

## Co zwykle może zobaczyć każdy obserwator

| Ścieżka | Sieć lokalna / ISP | Pośrednik | Cel | Główne ograniczenie | Względna prędkość |
|---|---|---|---|---|---|
| Bezpośredni HTTPS | Metadane źródła, celu, czasu i ilości danych | Hosting/CDN widzi połączenie | Źródłowy adres IP, dane przeglądarki/aplikacji | Brak prywatności adresu źródłowego IP | Najszybsza |
| Komercyjny VPN | Źródło połączone z VPN; zwykle nie widzi metadanych celu | VPN widzi metadane źródła i celu | Adres IP wyjścia VPN | Jeden dostawca staje się punktem korelacji | Zwykle szybka |
| Samodzielnie hostowany VPN/VPS | Źródło połączone z VPS | Logi hosta/konta/płatności/control-plane | Adres IP wyjścia VPS | Łatwo przypisać połączenie do wynajętego serwera/konta | Zwykle szybka |
| Tor Browser | Źródło połączone z Tor/bridge; czas i ilość danych | Każdy relay widzi ograniczoną część informacji | Wyjście Tor, dane przeglądarki | Wolniejszy; ryzyko związane z kontem/endpointem/korelacją | Umiarkowana/wolna |
| Tails/Whonix | Podobna ścieżka Tor, z silniejszymi granicami routingu | Te same ograniczenia Tor | Wyjście Tor/dane aplikacji | Błędy operacyjne oraz host/sprzęt pozostają istotne | Umiarkowana/wolna |
| Publiczne Wi-Fi dla gości + HTTPS | Lokalnie widzi urządzenie/czas oraz cele | ISP obiektu widzi metadane | Publiczny adres IP gościa | Korelacja fizyczna, captive portal i urządzenie | Szybka/zmienna |
| Hotspot komórkowy | Operator widzi abonenta/urządzenie/lokalizację oraz cele | Użyty VPN/Tor | Operator, VPN lub adres IP wyjścia Tor | Subskrypcja komórkowa i lokalizacja są trwałymi identyfikatorami | Szybka/zmienna |
| Mixnet | Dostęp widzi użycie mixnetu, czas i ilość danych | Wiele mixing nodes | Gateway/wyjście | Rozwijający się ekosystem; koszt opóźnień i przepustowości | Najwolniejsza |

HTTPS chroni treść podczas transmisji, ale nie wszystkie metadane. EFF wskazuje, że domena, czas i rozmiar ruchu mogą pozostać widoczne dla pośredników, nawet gdy ścieżki stron, dane uwierzytelniające i wiadomości są zaszyfrowane.<sup>[[1]](#references)</sup>

## VPN: szybka prywatność ze skoncentrowanym zaufaniem

VPN jest przydatny do ukrywania metadanych celu przed ISP zapewniającym dostęp, ochrony pierwszego hopu w niezaufanej sieci, prezentowania stabilnego adresu wyjściowego podczas engagementu lub uzyskiwania dostępu do sieci prywatnej. **Nie** zapewnia anonimowości użytkownika. VPN widzi połączenie źródłowe i może obserwować metadane celu; konta, cookies, GPS, fingerprinty i dane płatnicze pozostają.<sup>[[1]](#references)</sup>

### Lista kontrolna oceny dostawcy

1. **Własność i jurysdykcja:** ustal osobę prawną, spółkę dominującą, kraje prowadzenia działalności, podwykonawców infrastruktury oraz obowiązujące procedury prawne.
2. **Gromadzone dane:** rozróżnij dane konta/płatności, źródłowy adres IP, znaczniki czasu połączeń, przepustowość, telemetrykę awarii, zapytania DNS i logi celów. „Brak logów przeglądania” nie oznacza „braku danych”.
3. **Przechowywanie i usuwanie:** znajdź dokładne okresy oraz sprawdź, czy kopie zapasowe, systemy antyfraudowe i podmioty przetwarzające stosują ten sam harmonogram.
4. **Dowody:** preferuj publiczne audyty zawierające zakres, datę, ustalenia i działania naprawcze; odtwarzalne/otwarte klienty; raporty przejrzystości oraz udokumentowane incydenty.
5. **Protokół i klient:** utrzymywany WireGuard, OpenVPN lub inny sprawdzony protokół; automatyczne aktualizacje; obsługa DNS i IPv6; kill switch oraz testy leak dla każdej platformy.
6. **Model biznesowy:** zrozum, jak finansowana jest bezpłatna lub subsydiowana usługa. Sama obecność w app store nie jest dowodem godnego zaufania działania.
7. **Dopasowanie płatności:** alternatywna płatność może ograniczyć ujawnienie danych rozliczeniowych VPN, ale nie usuwa źródłowego adresu IP obserwowanego przy każdym połączeniu.

### Konfiguracja i weryfikacja VPN

1. Zainstaluj podpisanego klienta dostawcy/organizacji z oficjalnego źródła.
2. Wybierz **full tunnel**, chyba że udokumentowana trasa musi go omijać. Split tunneling tworzy ścieżki korelacji i leak.
3. Włącz tryb fail-closed/always-on i blokuj ruch podczas ponownego łączenia.
4. Przesyłaj DNS przez tunel i przetestuj IPv4 oraz IPv6. Wyłącz protokół tylko wtedy, gdy nie można go bezpiecznie tunelować, a utrata funkcjonalności jest zaakceptowana.
5. Przetestuj usypianie/wybudzanie, przełączanie sieci, logowanie do captive portalu, awarię tunelu i tethering hotspotu. NCSC ostrzega, że na niektórych platformach klienci korzystający z tetheringu mogą omijać VPN telefonu.<sup>[[2]](#references)</sup>
6. Użyj kontrolowanego przez organizację testowego endpointu do rejestrowania obserwowanych IPv4, IPv6, resolvera DNS i czasu połączenia. Nie udostępniaj wrażliwego engagementu losowym witrynom „leak test”.
7. Powtórz testy po zmianach klienta, systemu operacyjnego, sieci lub polityki.

## Tor Browser: silniejsza niepowiązywalność w sieci Web

Tor buduje circuit przez wiele relayów, dzięki czemu żaden pojedynczy relay zwykle nie zna jednocześnie źródła i celu. Cel widzi wyjście Tor zamiast adresu IP użytkownika, a sieć lokalna zwykle widzi połączenie Tor.<sup>[[3]](#references)</sup> Tor został zaprojektowany dla aplikacji TCP o niskich opóźnieniach, dlatego jest wolniejszy i nie może zagwarantować ochrony przed przeciwnikiem zdolnym do korelowania obu końców.<sup>[[4]](#references)</sup>

### Bezpieczny workflow Tor Browser

1. Pobieraj Tor Browser wyłącznie z Tor Project lub oficjalnego mirroru i, jeśli to możliwe, weryfikuj podpis.
2. Używaj **Tor Browser**, a nie zwykłej przeglądarki wskazanej na port SOCKS Tor. Zwykłe przeglądarki mogą ujawniać DNS/WebRTC i stan identyfikujący.<sup>[[5]](#references)</sup>
3. Zachowaj domyślny rozmiar, fonty, rozszerzenia i ustawienia prywatności. Dodatkowe add-ons mogą uczynić przeglądarkę bardziej unikalną.<sup>[[6]](#references)</sup>
4. Wybierz poziom bezpieczeństwa **Safer** lub **Safest**, gdy zwiększona liczba problemów ze zgodnością jest akceptowalna.
5. Użyj bridge, gdy bezpośredni Tor jest blokowany lub zwykłe adresy IP relayów powodowałyby niedopuszczalną widoczność lokalną. Bridges ograniczają łatwe rozpoznanie, ale nie eliminują traffic analysis.<sup>[[7]](#references)</sup>
6. Nie loguj się do identyfikującego konta, nie podawaj informacji identyfikujących ani nie otwieraj pobranych aktywnych dokumentów w zewnętrznej aplikacji korzystającej z sieci.
7. Używaj oddzielnego session/context dla każdej tożsamości. „New circuit” nie jest równoznaczne z usunięciem tożsamości przeglądarki/aplikacji; użyj **New Identity** lub odpowiednio uruchom ponownie izolowane środowisko.
8. Preferuj uwierzytelniony HTTPS lub uwierzytelnioną usługę onion. Wyjście Tor może obserwować niezaszyfrowany ruch HTTP.

### Tor z VPN

Połączenie obu rozwiązań nie jest automatycznie bezpieczniejsze. VPN przed Tor może ukrywać bezpośrednie połączenia z relayami Tor przed ISP, podczas gdy VPN widzi źródło; Tor przed VPN daje VPN stabilny obraz aktywności po Tor i może zmniejszyć zbiór anonimowości. Błędna konfiguracja może wprowadzać leak. Tor Project zaleca takie połączenia wyłącznie dla zaawansowanych, jasno określonych modeli zagrożeń.<sup>[[8]](#references)</sup>

## Publiczne i gościnne Wi-Fi

Współczesny HTTPS oznacza, że pasywni sąsiedzi zwykle nie mogą odczytać prawidłowo zaszyfrowanej treści stron, ale gościnne Wi-Fi nie zapewnia anonimowości. Obiekt może rejestrować czasy dołączenia, identyfikatory urządzeń, dane captive portalu, cele i szczegóły DHCP; kamery, zakupy, transport i obserwacja fizyczna mogą zidentyfikować użytkownika. Fałszywy hotspot o podobnej nazwie może również przechwytywać dane logowania do portalu lub manipulować niezaszyfrowanym ruchem.<sup>[[9]](#references)</sup>

### Zgodny z prawem workflow sieci gościnnej

1. Korzystaj wyłącznie z sieci oferowanej gościom lub takiej, na którą właściciel udzielił wyraźnej zgody. Poproś personel o dokładny SSID i procedurę portalu.
2. Zaktualizuj endpoint i travel router przed przybyciem. Wyłącz udostępnianie plików/drukarek, wykrywanie przychodzące, automatyczne dołączanie i wyszukiwanie zapamiętanych sieci.
3. Włącz prywatny/losowy adres Wi-Fi systemu operacyjnego. Aktualne systemy Apple mogą używać rotujących adresów w sieciach otwartych/słabych; współczesne mechanizmy randomizacji Androida są zwykle trwałe dla danego SSID. Ogranicza to tylko jeden lokalny identyfikator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Preferuj kontrolowany przez organizację travel router lub urządzenie bridge o niskim poziomie zaufania między uprzywilejowaną stacją roboczą a siecią gościnną. Centralizuje to politykę firewall/VPN, ale nie ukrywa routera przed obiektem.<sup>[[12]](#references)</sup>
5. Ukończ captive portal wyłącznie przez wskazane urządzenie/przeglądarkę o niskim poziomie zaufania. Nigdy nie wprowadzaj osobistych ani ponownie używanych danych uwierzytelniających w rzekomo anonimowym kontekście. Zamknij przeglądarkę portalu po uzyskaniu łączności.
6. Uruchom full-tunnel VPN lub Tor przed wrażliwą aktywnością i potwierdź działanie fail-closed.
7. Usuń sieć po użyciu i przejrzyj politykę konta portalu oraz przechowywania danych.

{% hint style="danger" %}
Łamanie zabezpieczeń Wi-Fi sąsiada, omijanie portalu, używanie wyciekłych danych dostępowych gościa, klonowanie dostępu innego gościa lub ukrywanie Raspberry Pi w kawiarni to działania nieautoryzowane — nie technika prywatności. Bezpieczne odpowiedniki to zgodna z prawem sieć gościnna, zatwierdzona przez klienta lokalizacja lub udokumentowany drop node umieszczony i odzyskany za pisemną zgodą właściciela obiektu.
{% endhint %}

## Travel routers

Travel router może odizolować stację roboczą od wrogich lokalnych broadcastów, wymuszać firewall, zapewniać spójny wewnętrzny SSID i automatycznie ponownie łączyć VPN. **Nie** zapewnia anonimowości: upstream widzi jego tożsamość radiową i czas ruchu, a dostawca VPN widzi źródło tunelu.

- Używaj obsługiwanego firmware OpenWrt/vendor i usuń nieużywane usługi.
- Administruj przez Ethernet lub dedykowany SSID zarządzania z unikalnym hasłem.
- Wyłącz administrację po stronie WAN, UPnP, WPS, udostępnianie plików i niezamawiany ruch przychodzący.
- Używaj losowego/prywatnego WAN MAC tylko wtedy, gdy jest obsługiwany i dozwolony.
- Wymuś politykę VPN na routerze, w tym DNS i IPv6, oraz blokuj egress po awarii tunelu.
- Nie zakładaj, że hotspot telefonu tuneluje urządzenia tetherowane przez VPN telefonu — przetestuj to.

## Sieć komórkowa, SIM i eSIM

Sieć komórkowa jest wygodna, ale nie anonimowa. Operatorzy przechowują identyfikatory abonenta/urządzenia oraz lokalizację wynikającą z dołączenia do sieci; eSIM nadal jest subskrypcją komórkową. Prepaid nie oznacza niezawodnie braku rejestracji — wymagania różnią się między krajami i zmieniają się.<sup>[[13]](#references)</sup>

Operacyjnie:

- Używaj oddzielnego, obsługiwanego urządzenia, aby ograniczyć ujawnienie danych osobowych, a nie aby tworzyć fikcyjnego abonenta.
- Nie noś stale „oddzielnego” urządzenia razem z osobistym telefonem, jeśli współlokacja znajduje się w modelu zagrożeń.
- Wyłącz nieużywaną sieć komórkową, Wi-Fi, Bluetooth i dostęp do lokalizacji; wyłączenie zasilania zapewnia silniejszą granicę radiową niż przełączniki w interfejsie.
- Umieść wrażliwy ruch w zatwierdzonej ścieżce VPN/Tor, pamiętając, że operator nadal zna lokalizację subskrypcji/urządzenia i endpoint tunelu.
- Zweryfikuj aktualne zasady rejestracji i przechowywania danych u krajowego regulatora lub lokalnego prawnika; nie polegaj na internetowych listach „anonimowych krajów SIM”.

## Metadane DNS i TLS

- **DoH/DoT/DoQ** szyfrują DNS między klientem a resolverem, uniemożliwiając proste lokalne odczytanie lub modyfikację, ale resolver nadal widzi zapytania i identyfikatory transportowe. Przenoszą zaufanie, lecz nie zapewniają anonimowości.<sup>[[14]](#references)</sup>
- **ODoH** dodaje proxy, dzięki czemu resolver nie musi poznawać adresu IP klienta, zakładając, że proxy i cel nie współpracują. Traffic analysis jest jawnie poza zakresem.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** może chronić wewnętrzną nazwę serwera w handshake TLS, gdy klient, DNS i serwer ją obsługują. Adres IP celu, czas, ilość danych i endpoint pozostają widoczne.<sup>[[16]](#references)</sup>
- W prawidłowo skonfigurowanym środowisku VPN lub Tor DNS powinien podążać obsługiwaną trasą tego środowiska. Dodanie oddzielnego resolvera może utworzyć nowego obserwatora lub fingerprint.

### Workflow weryfikacji zaszyfrowanego DNS/ECH

1. Ustal, czy DNS jest kontrolowany przez środowisko VPN/Tor, system operacyjny czy aplikację. Skonfiguruj go w **jednej** zamierzonej warstwie zamiast łączyć niezależne resolvery.
2. Wybierz resolver na podstawie opublikowanej polityki prywatności/przechowywania danych i włącz ścisły tryb szyfrowany, jeśli platforma go obsługuje. Opportunistic fallback może po cichu powrócić do plaintext.
3. Wykonaj zapytanie do unikalnej subdomeny w autorytatywnej strefie testowej, którą kontrolujesz; potwierdź, że log autorytatywny widzi zamierzony recursive resolver.
4. Przechwytuj wyłącznie ruch testowego urządzenia i tylko za zgodą. Potwierdź, że sieć dostępu nie może odczytać plaintext DNS, pamiętając, że może widzieć zaszyfrowany resolver/endpoint tunelu.
5. Przetestuj zablokowany/niedostępny szyfrowany resolver. Warunkiem powodzenia jest wybrane zachowanie fail-closed lub udokumentowany fallback, a nie przypadkowe jawne zapytanie.
6. Dla ECH użyj kontrolowanego hosta z obsługą ECH i sprawdź diagnostykę klienta/serwera, aby potwierdzić akceptację **wewnętrznego** ClientHello. Samo oferowanie rekordu HTTPS nie dowodzi powodzenia ECH.
7. Powtórz testy po zmianach sieci, captive portalach, aktualizacjach przeglądarki i ponownym łączeniu VPN. Zapisz, który komponent kontroluje DNS/ECH, aby późniejsi administratorzy nie utworzyli obejścia.

## Mixnets

Mixnets, takie jak Nym lub Katzenpost, dodają pakiety o stałym rozmiarze, opóźnienia, zmianę kolejności i cover traffic, aby przeciwdziałać korelacji czasowej. Te właściwości kosztują opóźnienie i przepustowość, a niezależne dowody dotyczące wdrożeń na dużą skalę są ograniczone. Obecne konsumenckie mixnets traktuj jako **rozwijające się opcje o wysokich opóźnieniach**, a nie szybsze lub gwarantowane zamienniki Tor/VPN.<sup>[[17]](#references)</sup>

### Workflow oceny

1. Zidentyfikuj utrzymywanego klienta i dokładnie obsługiwaną aplikację; nie wymuszaj przesyłania dowolnego ruchu przeglądarki/systemu przez nieudokumentowane proxy.
2. Przeczytaj aktualny model zagrożeń dotyczący założeń dla entry, mix nodes, gateway, celu i współpracy.
3. Zainstaluj oprogramowanie z oficjalnego podpisanego źródła w oddzielnym środowisku testowym i używaj wyłącznie nieszkodliwego, należącego do Ciebie endpointu.
4. Zmierz opóźnienie dostarczenia, limity rozmiaru wiadomości, niezawodność, retransmisję oraz zachowanie przy niedostępności gateway.
5. Sprawdź lokalny ruch i należący do Ciebie endpoint, aby potwierdzić zamierzoną ścieżkę i źródło. Zweryfikuj, czy odpowiedzi używają tego samego mechanizmu prywatności.
6. Przetestuj zamknięcie/awarię: aplikacja nie może po cichu powrócić do bezpośredniego dostępu do Internetu.
7. Nie wyłączaj cover traffic, nie zmniejszaj opóźnień ani nie wybieraj nietypowych stałych tras wyłącznie dla szybkości; zmiany te mogą unieważnić deklarowany model anonimowości.
8. Utrzymuj rozwiązanie w fazie eksperymentalnej, dopóki konkretne wdrożenie, niezależna analiza i niezawodność operacyjna nie odpowiadają poziomowi konsekwencji.

## Lista kontrolna przed użyciem sieci

- [ ] Autoryzacja obejmuje sieć dostępu, cel, daty i infrastrukturę źródłową.
- [ ] Endpoint nie zawiera niezwiązanych tożsamości ani aktywnych sesji synchronizacji.
- [ ] Zachowanie IPv4, IPv6, DNS i ponownego łączenia odpowiada planowi.
- [ ] Cel widzi wyłącznie oczekiwane wyjście.
- [ ] Zachowanie captive portalu i hotspotu przetestowano bez wrażliwego ruchu.
- [ ] Lokalne udostępnianie/wykrywanie i automatyczne dołączanie do sieci są wyłączone.
- [ ] Tabela obserwatorów i pozostałe ryzyko korelacji ruchu są zaakceptowane.
- [ ] Polityka dostawcy, przechowywanie danych i kontakt awaryjny są aktualne.

Dla relayów z podziałem wiedzy, workloads wymuszanych przez routing, pluggable transports, usług onion, I2P i jednorazowych zdalnych przeglądarek przejdź do [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Wybór odpowiedniego dla Ciebie VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Wytyczne dotyczące bezpieczeństwa urządzeń: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Ochrona prywatności i anonimowości oferowana przez Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Krótkie wprowadzenie do Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Używanie Tor z innymi przeglądarkami](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Wtyczki i add-ons w Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Odblokowywanie Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Używanie Tor Browser z VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Czy publiczne sieci Wi-Fi są bezpieczne?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Prywatność Wi-Fi na urządzeniach Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementacja randomizacji MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Zasady bezpiecznych uprzywilejowanych stacji roboczych](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Obowiązkowa rejestracja SIM: perspektywy polityczne i regulacyjne](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Zalecenia dla operatorów usług prywatności DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Model zagrożeń](https://katzenpost.network/docs/threat_model/)
