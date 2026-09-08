# Prywatność sieciowa i anonimowa łączność

{{#include ../banners/hacktricks-training.md}}

Prywatność sieciowa to decyzja dotycząca routingu, a nie pełna tożsamość. Wybierz ścieżkę, pytając, kto nie powinien móc połączyć **źródła**, **miejsca docelowego**, **treści** i **czasu**.

Aby zapoznać się ze znormalizowanym wykazem — `Pros`, `Cons`, krok po kroku `Procedure` oraz `Detection` dla każdej rodziny ścieżek dostępu — zacznij od [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Ta strona rozwija najczęściej wdrażane opcje.

## Co zwykle może zobaczyć każdy obserwator

| Ścieżka | Sieć lokalna / ISP | Pośrednik | Miejsce docelowe | Główne ograniczenie | Względna szybkość |
|---|---|---|---|---|---|
| Direct HTTPS | Metadane źródła i miejsca docelowego, czas/ilość ruchu | Hosting/CDN widzi połączenie | Source IP, dane przeglądarki/aplikacji | Brak prywatności Source IP | Najszybsza |
| Commercial VPN | Źródło połączone z VPN; zwykle brak metadanych miejsca docelowego | VPN widzi metadane źródła i miejsca docelowego | VPN egress IP | Jeden dostawca staje się punktem korelacji | Zwykle szybka |
| Self-hosted VPN/VPS | Źródło połączone z VPS | Logi hosta/konta/płatności/control-plane | VPS egress IP | Łatwo przypisać do wynajętego serwera/konta | Zwykle szybka |
| Tor Browser | Źródło połączone z Tor/bridge; czas/ilość ruchu | Każdy relay widzi ograniczoną część | Tor exit, dane przeglądarki | Wolniejsza; ryzyko związane z kontem/endpointem/korelacją | Umiarkowana/wolna |
| Tails/Whonix | Podobna ścieżka Tor, z silniejszymi granicami routingu | Te same ograniczenia Tor | Tor exit/dane aplikacji | Błędy operacyjne oraz host/sprzęt nadal pozostają | Umiarkowana/wolna |
| Public guest Wi-Fi + HTTPS | Lokalna widoczność urządzenia/czasu oraz miejsc docelowych | ISP obiektu widzi metadane | Guest public IP | Korelacja fizyczna/captive-portal/urządzenia | Szybka/zmienna |
| Cellular hotspot | Operator widzi abonenta/urządzenie/lokalizację oraz miejsca docelowe | VPN/Tor, jeśli używany | Carrier, VPN lub Tor egress IP | Abonament mobilny i lokalizacja są trwałymi identyfikatorami | Szybka/zmienna |
| Mixnet | Dostęp widzi użycie mixnetu; czas/ilość ruchu | Wiele mixing nodes | Gateway/egress | Rozwijający się ekosystem; koszt opóźnienia i przepustowości | Najwolniejsza |

HTTPS chroni treść podczas transmisji, ale nie wszystkie metadane. EFF zauważa, że domena, czas i rozmiar ruchu mogą pozostać widoczne dla pośredników, nawet gdy ścieżki stron, dane uwierzytelniające i wiadomości są zaszyfrowane.<sup>[[1]](#references)</sup>

## VPN: szybka prywatność ze skoncentrowanym zaufaniem

VPN jest przydatny do ukrywania metadanych miejsca docelowego przed ISP zapewniającym dostęp, ochrony pierwszego odcinka w niezaufanej sieci, prezentowania stabilnego adresu engagement egress lub uzyskiwania dostępu do sieci prywatnej. **Nie** zapewnia anonimowości użytkownika. VPN widzi połączenie źródłowe i może obserwować metadane miejsca docelowego; konta, cookies, GPS, fingerprints oraz informacje o płatności nadal pozostają.<sup>[[1]](#references)</sup>

### Lista kontrolna oceny dostawcy

1. **Własność i jurysdykcja:** zidentyfikuj podmiot prawny, spółkę dominującą, kraje działalności, podwykonawców infrastruktury oraz obowiązujące procedury prawne.
2. **Gromadzone dane:** rozróżnij dane konta/płatności, Source IP, znaczniki czasu połączeń, bandwidth, crash telemetry, zapytania DNS oraz logi miejsc docelowych. „Brak logów przeglądania” nie oznacza „braku danych”.
3. **Retencja i usuwanie:** ustal dokładne okresy oraz to, czy kopie zapasowe, systemy antyfraudowe i procesorzy danych stosują ten sam harmonogram.
4. **Dowody:** preferuj publiczne audyty określające zakres, datę, ustalenia i działania naprawcze; reproducible/open clients; raporty przejrzystości oraz udokumentowane incydenty.
5. **Protokół i klient:** utrzymywany WireGuard, OpenVPN lub inny zweryfikowany protokół; automatyczne aktualizacje; obsługa DNS i IPv6; kill switch oraz testy leak dla każdej platformy.
6. **Model biznesowy:** zrozum, w jaki sposób finansowana jest bezpłatna lub dotowana usługa. Sama obecność w app store nie jest dowodem godnego zaufania działania.
7. **Dopasowanie płatności:** alternatywna płatność może ograniczyć ujawnienie danych rozliczeniowych VPN, ale nie usuwa Source IP obserwowanego przy każdym połączeniu.

### Konfiguracja i weryfikacja VPN

1. Zainstaluj podpisanego klienta dostawcy/organizacji z jej oficjalnego źródła.
2. Wybierz **full tunnel**, chyba że udokumentowana trasa musi go omijać. Split tunneling tworzy ścieżki korelacji i leak.
3. Włącz tryb fail-closed/always-on i blokuj ruch podczas ponownego łączenia.
4. Przesyłaj DNS przez tunnel i przetestuj IPv4 oraz IPv6. Wyłącz protokół tylko wtedy, gdy nie może być bezpiecznie tunelowany, a utrata funkcjonalności jest zaakceptowana.
5. Przetestuj uśpienie/wybudzenie, przełączanie sieci, logowanie do captive portalu, awarię tunelu oraz tethering hotspotu. NCSC ostrzega, że tethered clients mogą na niektórych platformach omijać VPN telefonu.<sup>[[2]](#references)</sup>
6. Użyj kontrolowanego przez organizację endpointu testowego do zarejestrowania obserwowanych IPv4, IPv6, resolvera DNS oraz czasu połączenia. Nie ujawniaj wrażliwego engagement losowym witrynom „leak test”.
7. Powtórz test po zmianach klienta, systemu operacyjnego, sieci lub zasad.

## Tor Browser: silniejsza unlinkability w sieci Web

Tor buduje circuit przez wiele relayów, dzięki czemu żaden pojedynczy relay zwykle nie zna jednocześnie źródła i miejsca docelowego. Miejsce docelowe widzi Tor exit zamiast IP użytkownika; sieć lokalna zwykle widzi połączenie Tor.<sup>[[3]](#references)</sup> Tor jest przeznaczony dla aplikacji TCP o niskim opóźnieniu, dlatego działa wolniej i nie może zagwarantować ochrony przed przeciwnikiem zdolnym do korelacji obu końców.<sup>[[4]](#references)</sup>

### Bezpieczny workflow Tor Browser

1. Pobieraj Tor Browser wyłącznie z Tor Project lub oficjalnego mirroru i, jeśli to możliwe, weryfikuj podpis.
2. Używaj **Tor Browser**, a nie zwykłej przeglądarki skierowanej do portu Tor SOCKS. Zwykłe przeglądarki mogą powodować leak DNS/WebRTC i ujawniać stan identyfikujący.<sup>[[5]](#references)</sup>
3. Zachowaj domyślny rozmiar, fonts, extensions i ustawienia prywatności. Dodatkowe add-ons mogą sprawić, że przeglądarka stanie się bardziej unikalna.<sup>[[6]](#references)</sup>
4. Wybierz poziom bezpieczeństwa **Safer** lub **Safest**, gdy akceptowalne jest większe ryzyko niezgodności.
5. Użyj bridge, gdy bezpośredni Tor jest blokowany lub gdy zwykłe adresy IP relayów powodowałyby niedopuszczalną lokalną widoczność. Bridges utrudniają łatwe rozpoznanie; nie eliminują traffic analysis.<sup>[[7]](#references)</sup>
6. Nie loguj się na konto identyfikujące, nie podawaj informacji identyfikujących ani nie otwieraj pobranych aktywnych dokumentów w zewnętrznej aplikacji sieciowej.
7. Używaj oddzielnej sesji/kontekstu dla każdej tożsamości. „New circuit” nie jest tym samym co usunięcie tożsamości przeglądarki/aplikacji; użyj **New Identity** lub odpowiednio uruchom ponownie izolowane środowisko.
8. Preferuj uwierzytelnione HTTPS lub uwierzytelnioną usługę onion. Tor exit może obserwować niezaszyfrowany ruch HTTP.

### Tor wraz z VPN

Łączenie ich nie jest automatycznie bezpieczniejsze. VPN przed Tor może ukrywać bezpośrednie połączenia z relayami Tor przed ISP, podczas gdy VPN widzi źródło; Tor przed VPN daje VPN stabilny widok aktywności po Tor i może zmniejszyć anonymity set. Błędna konfiguracja może wprowadzić leak. Tor Project zaleca takie połączenia wyłącznie zaawansowanym użytkownikom, dla jednoznacznych modeli zagrożeń.<sup>[[8]](#references)</sup>

## Publiczne i gościnne Wi-Fi

Współczesne HTTPS oznacza, że bierni sąsiedzi zwykle nie mogą odczytać prawidłowo zaszyfrowanej treści Web, ale gościnne Wi-Fi nie zapewnia anonimowości. Obiekt może rejestrować czasy połączeń, identyfikatory urządzeń, dane captive portalu, miejsca docelowe i dane DHCP; kamery, zakupy, transport oraz obserwacja fizyczna mogą zidentyfikować użytkownika. Fałszywy hotspot o podobnej nazwie może także przechwytywać dane uwierzytelniające portalu lub modyfikować niezaszyfrowany ruch.<sup>[[9]](#references)</sup>

### Zgodny z prawem workflow sieci gościnnej

1. Korzystaj wyłącznie z sieci oferowanej gościom lub takiej, na którą właściciel udzielił wyraźnej zgody. Poproś personel o dokładny SSID i procedurę portalu.
2. Zaktualizuj endpoint i travel router przed przybyciem. Wyłącz udostępnianie plików/drukarek, inbound discovery, automatyczne dołączanie i wyszukiwanie zapamiętanych sieci.
3. Włącz prywatny/losowy adres Wi-Fi systemu operacyjnego. Obecne systemy Apple mogą używać zmiennych adresów w otwartych/słabych sieciach; współczesne randomization w Androidzie jest zwykle trwałe dla każdego SSID. Ogranicza to tylko jeden lokalny identyfikator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Preferuj kontrolowany przez organizację travel router lub bridge device o niskim poziomie zaufania między uprzywilejowaną stacją roboczą a siecią gościnną. Centralizuje to zasady firewall/VPN, ale nie ukrywa routera przed obiektem.<sup>[[12]](#references)</sup>
5. Obsługuj captive portal wyłącznie przez wyznaczone urządzenie/przeglądarkę o niskim poziomie zaufania. Nigdy nie wprowadzaj osobistych ani ponownie używanych danych uwierzytelniających w rzekomo anonimowym kontekście. Zamknij przeglądarkę portalu po ustanowieniu łączności.
6. Uruchom full-tunnel VPN lub Tor przed wrażliwą aktywnością i potwierdź działanie fail-closed.
7. Usuń sieć po użyciu i sprawdź zasady dotyczące konta portalu oraz retencji danych.

{% hint style="danger" %}
Cracking Wi-Fi sąsiada, omijanie portalu, używanie wyciekłych danych uwierzytelniających gości, klonowanie dostępu innego gościa lub ukrywanie Raspberry Pi w kawiarni to działania nieautoryzowane — nie technika prywatności. Bezpieczne odpowiedniki to zgodna z prawem sieć gościnna, witryna zatwierdzona przez klienta lub udokumentowany drop node umieszczony i odzyskany za pisemną zgodą właściciela obiektu.
{% endhint %}

## Travel routers

Travel router może odizolować stację roboczą od wrogich lokalnych broadcasts, wymusić firewall, zapewnić spójny wewnętrzny SSID i automatycznie ponownie połączyć VPN. **Nie** zapewnia anonimowości: upstream widzi jego radio identity i czas ruchu, a dostawca VPN widzi źródło tunelu.

- Używaj obsługiwanego firmware OpenWrt/vendor i usuń nieużywane usługi.
- Administruj przez Ethernet lub dedykowany management SSID z unikalnym hasłem.
- Wyłącz administrację od strony WAN, UPnP, WPS, udostępnianie plików i niezamawiany ruch przychodzący.
- Używaj losowego/prywatnego WAN MAC tylko tam, gdzie jest obsługiwany i dozwolony.
- Wymuś zasady VPN na routerze, w tym DNS i IPv6, oraz blokuj egress w przypadku awarii tunelu.
- Nie zakładaj, że hotspot telefonu tuneluje tethered devices przez VPN telefonu; przetestuj to.

## Sieci komórkowe, SIM i eSIM

Sieć komórkowa jest wygodna, ale nie zapewnia anonimowości. Operatorzy utrzymują identyfikatory abonenta/urządzenia oraz lokalizację wynikającą z dołączenia do sieci; eSIM nadal jest abonamentem mobilnym. Prepaid nie oznacza niezawodnie braku rejestracji — wymagania różnią się w zależności od kraju i zmieniają się.<sup>[[13]](#references)</sup>

Operacyjnie:

- Używaj oddzielnego, obsługiwanego urządzenia, aby ograniczyć ujawnienie danych osobowych, a nie w celu utworzenia fikcyjnego abonenta.
- Nie noś stale „oddzielnego” urządzenia obok osobistego telefonu, jeśli współlokalizacja jest częścią modelu zagrożeń.
- Wyłącz nieużywane sieci komórkowe, Wi-Fi, Bluetooth i dostęp do lokalizacji; wyłączenie zasilania zapewnia silniejszą granicę radiową niż przełączniki w interfejsie.
- Umieszczaj wrażliwy ruch w zatwierdzonej ścieżce VPN/Tor, pamiętając, że operator nadal zna lokalizację abonamentu/urządzenia oraz endpoint tunelu.
- Zweryfikuj aktualne zasady rejestracji i retencji u krajowego regulatora lub lokalnego prawnika; nie polegaj na internetowych listach „anonimowych krajów SIM”.

## Metadane DNS i TLS

- **DoH/DoT/DoQ** szyfrują DNS między klientem a resolverem, uniemożliwiając proste lokalne odczytanie lub modyfikację, ale resolver nadal widzi zapytania i identyfikatory transportu. Przenoszą zaufanie; nie zapewniają anonimowości.<sup>[[14]](#references)</sup>
- **ODoH** dodaje proxy, dzięki czemu resolver nie musi poznawać IP klienta, zakładając, że proxy i cel nie współpracują. Traffic analysis jest wyraźnie poza zakresem.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** może chronić wewnętrzną nazwę serwera w handshake TLS, gdy klient, DNS i serwer ją obsługują. Destination IP, czas, ilość ruchu i endpoint pozostają widoczne.<sup>[[16]](#references)</sup>
- W prawidłowo skonfigurowanym środowisku VPN lub Tor DNS powinien korzystać z obsługiwanej przez to środowisko ścieżki. Dodanie oddzielnego resolvera może utworzyć nowego obserwatora lub fingerprint.

### Workflow weryfikacji Encrypted-DNS/ECH

1. Ustal, czy DNS jest kontrolowany przez środowisko VPN/Tor, system operacyjny czy aplikację. Skonfiguruj go w **jednej** zamierzonej warstwie zamiast łączyć niezależne resolvery.
2. Wybierz resolver na podstawie jego opublikowanej polityki prywatności/retencji i włącz tryb strict encrypted, jeśli platforma go obsługuje. Opportunistic fallback może po cichu powrócić do plaintext.
3. Wykonaj zapytanie do unikalnej subdomeny w autorytatywnej strefie testowej, którą kontrolujesz; potwierdź, że log autorytatywny widzi zamierzony recursive resolver.
4. Przechwytuj wyłącznie ruch urządzenia testowego i tylko za zgodą. Potwierdź, że sieć dostępowa nie może odczytać plaintext DNS, pamiętając, że może widzieć endpoint zaszyfrowanego resolvera/tunelu.
5. Przetestuj zablokowany/niedostępny encrypted resolver. Warunkiem powodzenia jest wybrane zachowanie fail-closed lub udokumentowany fallback, a nie przypadkowe clear query.
6. W przypadku ECH użyj kontrolowanego hosta z obsługą ECH i sprawdź diagnostykę klienta/serwera, aby potwierdzić, że **inner** ClientHello zostało zaakceptowane. Samo oferowanie rekordu HTTPS nie dowodzi powodzenia ECH.
7. Powtórz test po zmianach sieci, captive portalach, aktualizacjach przeglądarki i ponownym połączeniu VPN. Zapisz, który komponent zarządza DNS/ECH, aby późniejsi administratorzy nie utworzyli obejścia.

## Mixnets

Mixnets, takie jak Nym lub Katzenpost, dodają pakiety o stałym rozmiarze, opóźnienia, zmianę kolejności i cover traffic, aby przeciwdziałać korelacji czasowej. Te właściwości kosztują opóźnienie i przepustowość, a niezależne dowody dotyczące wdrożeń na dużą skalę są ograniczone. Obecne konsumenckie mixnets traktuj jako **emerging/high-latency options**, a nie szybsze lub gwarantowane zamienniki Tor/VPN.<sup>[[17]](#references)</sup>

### Workflow oceny

1. Zidentyfikuj utrzymywanego klienta i dokładnie obsługiwaną aplikację; nie wymuszaj przesyłania arbitralnego ruchu przeglądarki/systemu przez nieudokumentowane proxy.
2. Przeczytaj aktualny threat model dotyczący entry, mix nodes, gateway, destination oraz założeń koluzji.
3. Zainstaluj oprogramowanie z oficjalnego podpisanego źródła w oddzielnym test compartment i używaj wyłącznie nieszkodliwego, należącego do Ciebie endpointu.
4. Zmierz latency dostarczania, limity rozmiaru wiadomości, niezawodność, retransmisję oraz zachowanie w przypadku niedostępności gateway.
5. Sprawdź lokalny ruch i należący do Ciebie endpoint, aby potwierdzić zamierzoną ścieżkę i źródło. Zweryfikuj, czy odpowiedzi korzystają z tego samego modelu prywatności.
6. Przetestuj zamknięcie/awarię: aplikacja nie może po cichu powrócić do bezpośredniego dostępu do Internetu.
7. Nie wyłączaj cover traffic, nie skracaj opóźnień ani nie wybieraj nietypowych fixed routes wyłącznie dla szybkości; takie zmiany mogą unieważnić określony model anonimowości.
8. Pozostaw rozwiązanie eksperymentalne, dopóki konkretne wdrożenie, niezależna analiza i niezawodność operacyjna nie będą odpowiadały poziomowi konsekwencji.

## Lista kontrolna przed użyciem sieci

- [ ] Autoryzacja obejmuje sieć dostępową, cel, daty i infrastrukturę źródłową.
- [ ] Endpoint nie zawiera niezwiązanych tożsamości ani aktywnych sesji synchronizacji.
- [ ] Zachowanie IPv4, IPv6, DNS i reconnect odpowiada planowi.
- [ ] Miejsce docelowe widzi wyłącznie oczekiwany egress.
- [ ] Zachowanie captive portalu i hotspotu przetestowano bez wrażliwego ruchu.
- [ ] Lokalne udostępnianie/discovery oraz automatyczne dołączanie do sieci są wyłączone.
- [ ] Tabela obserwatorów i pozostałe ryzyko korelacji ruchu są zaakceptowane.
- [ ] Polityka dostawcy, retencja i kontakt awaryjny są aktualne.

Informacje o split-knowledge relays, route-enforced workloads, pluggable transports, usługach onion, I2P i disposable remote browsers znajdziesz w [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Wybór odpowiedniego dla Ciebie VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Wytyczne dotyczące bezpieczeństwa urządzeń: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Ochrona prywatności i anonimowości oferowana przez Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Krótkie wprowadzenie do Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Używanie Tor z innymi przeglądarkami](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins i add-ons w Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Odblokowywanie Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Używanie Tor Browser z VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Czy publiczne sieci Wi-Fi są bezpieczne?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Prywatność Wi-Fi na urządzeniach Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementacja randomizacji MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Zasady bezpiecznych uprzywilejowanych stacji roboczych](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Obowiązkowa rejestracja SIM: perspektywy polityczne i regulacyjne](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Zalecenia dla operatorów usług DNS Privacy](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
