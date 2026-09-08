# Katalog technik anonimowego dostępu do Internetu

To kanoniczny wykaz ścieżek dostępu. Obejmuje **rodziny** protokołów i działań operacyjnych, a nie nazwy wszystkich vendorów. Żadna ścieżka Internetowa nie gwarantuje anonimowości: dowody dotyczące konta, przeglądarki, endpointu, czasu, płatności, cloud-control-plane i fizyczne mogą ujawnić użytkownika nawet przy pozornie idealnej trasie.

Każdy wpis używa tych samych pól. „Procedura” oznacza zgodne z prawem wdrożenie lub emulację we własnym laboratorium. Gdy rzeczywista technika wymaga kompromitacji routera, kradzieży dostępu lub nadużycia niechętnego pośrednika, reprodukcja zastępuje je systemami należącymi do uczestników ćwiczenia.

## Macierz pokrycia

| Rodzina | Co widzi cel | Najsilniejsza właściwość | Szybkość | Status |
|---|---|---|---|---|
| Współdzielony NAT/CGNAT | współdzielony publiczny adres | niejednoznaczność między abonentami | wysoka | wdrażalne |
| VPN, VPS, proxy SOCKS/HTTP/SSH | adres relay | szybkie oddzielenie adresu źródłowego | wysoka | wdrażalne |
| Multi-hop/split relay, MASQUE | końcowy proxy | podział wiedzy lub pełny tunel IP | wysoka/umiarkowana | wdrażalne z zaufanymi relayami |
| Tor, bridge, onion service | exit lub tożsamość onion | ścieżka wielostronna i wspólna przeglądarka | umiarkowana | wdrażalne |
| I2P, GNUnet, mixnet | peer/gateway overlay | overlay lub odporność na analizę czasu | niska/zmienna | zależne od aplikacji |
| OHTTP/ODoH, Private Relay | gateway/egress | podział źródła i żądania | wysoka | tylko obsługiwane aplikacje |
| Publiczne Wi-Fi, travel router | adres obiektu/tunelu | zmiana lokalizacji/ścieżki dostępu | wysoka | wymagana zgoda |
| Sieć komórkowa/eSIM, satelita | adres operatora/dostawcy | niezależne fizyczne łącze | wysoka/zmienna | operator widzi subskrypcję |
| Zdalna przeglądarka/jump host | zdalny workspace | oddzielenie endpointu i egressu | wysoka | wdrażalne |
| Residential/mobile proxy | adres konsumencki/operatora | wygląd sieci konsumenckiej | wysoka | krytyczna zgoda i proweniencja |
| ORB/skompromitowany relay | adres innej ofiary | ukrycie źródła i pożyczona reputacja | wysoka | tylko reprodukcja w laboratorium |
| CDN/fronting/redirector | adres CDN/front | ochrona infrastruktury back-end | wysoka | wymagana zgoda dostawcy/właściciela |
| Fast flux/DGA/dead drop | zmienny node/service | odporność na rozpoznanie infrastruktury | zmienna | tylko reprodukcja w laboratorium |
| Drop/nearest-neighbor | adres sąsiadujący z celem | przekroczenie granicy geograficznej/sieciowej | wysoka | tylko laboratorium własnych lokalizacji |
| Store-and-forward/offline | gateway lub odbiorca fizyczny | mniejsze powiązanie czasowe interakcji | niska | zależne od aplikacji |
| Pluggable/refraction transport | wejście Tor lub współpracujący proxy | odporność na cenzurę | zmienna | obsługiwany klient lub laboratorium |
| IPFS gateway/PIR/remote fetcher | gateway lub service aplikacji | podział publisher/query/request | zmienna | tylko ograniczone aplikacje |
| Anycast/QUIC/MPTCP | stabilny broker lub wiele subflow | rendezvous i ciągłość sesji | wysoka | dostępność, nie anonimowość |
| Runner CI/CD | adres hosted runnera | rozliczalny, jednorazowy egress | wysoka | tylko własny workflow |
| Lokalny pierwszy hop non-IP | gateway organizacji | usunięcie stosu Internet z sensora | niska | wdrożenie za zgodą właściciela |

## Bezpośredni współdzielony NAT i carrier-grade NAT

**Mechanika:** wielu użytkowników współdzieli publiczny adres; dostawca mapuje adresy i porty abonentów na publiczną krotkę.

**Zalety:** szybkość; brak specjalnego klienta; sam adres IP po stronie celu może wskazywać wyłącznie gospodarstwo domowe, obiekt lub pulę operatora.

**Wady:** dostawca może przechowywać mapowania abonent/port/czas; konta i fingerprinty pozostają; inni użytkownicy mogą pogorszyć reputację adresu.

**Procedura:** (1) potwierdź, czy autoryzowany dostęp używa NAT/CGNAT; (2) zapisz dokładny publiczny IP i port źródłowy na własnym endpointcie; (3) oddziel tożsamości aplikacji; (4) nie traktuj współdzielenia adresu jako kontroli prywatności; (5) użyj silniejszej ścieżki, jeśli ISP nie może znać celów.

**Wykrywanie:** cele powinny przechowywać port źródłowy i dokładny czas, nie tylko IP. Dostawcy korelują logi alokacji NAT; śledczy łączą dowody kont, urządzeń i przeglądarek.

## Commercial VPN

**Mechanika:** zaszyfrowane połączenie full-tunnel kończy się w VPN; cele widzą jego egress. VPN zwykle może powiązać źródło, czas i cele.

**Zalety:** szybkość; prostota; ochrona przed lokalną obserwacją pasywną; stabilne lub współdzielone exit; dobry egress dla kontrolowanego red-team.

**Wady:** skoncentrowane zaufanie; telemetryka płatności/logowania; awarie kill-switch/DNS/IPv6; współdzielone exit są często blokowane przez reputację.

**Procedura:** (1) ustal dostawcę, właściciela, jurysdykcję, retencję i politykę testów; (2) zainstaluj podpisanego oficjalnego klienta; (3) włącz full tunnel, always-on i fail-closed; (4) świadomie skieruj DNS i IPv6; (5) zweryfikuj IPv4/IPv6/DNS na własnym endpointcie; (6) zatrzymaj i ponownie połącz tunel, potwierdzając brak jawnego fallbacku.<sup>[[1]](#references)</sup>

**Wykrywanie:** sieci lokalne widzą długi zaszyfrowany przepływ do infrastruktury VPN; dostawcy mają logi uwierzytelniania i połączeń; cele używają ASN/reputacji oraz korelacji konta, TLS, przeglądarki i zachowania.

## Self-hosted VPN lub egress z wynajętego VPS

**Mechanika:** operator kontroluje gateway WireGuard/OpenVPN lub przekazuje ruch przez wynajęty serwer.

**Zalety:** przewidywalna szybkość; stały adres możliwy do umieszczenia na allowliście; własne logowanie i firewall; dobra kontrola incydentów.

**Wady:** mały zbiór anonimowości; tenant cloud, płatność, logowanie źródłowe, API i historia image łączą operatora; nowy charakterystyczny serwer łatwo grupować.

**Procedura:** (1) utwórz projekt organizacji przeznaczony dla jednego engagementu; (2) wdroż obsługiwany image i stały adres; (3) ogranicz administrację do MFA/kluczy; (4) skonfiguruj full-tunnel egress i DNS; (5) ogranicz cele do zakresu, gdy to możliwe; (6) przetestuj leak i zachowanie awaryjne; (7) zachowaj audyt kontrolera; (8) zniszcz dane uwierzytelniające i zasoby przy zamknięciu.

**Wykrywanie:** koreluj ASN hostingu, adres first-seen, fingerprint certyfikatu/usługi i skanowanie; właściciele cloud używają logów control-plane, konsoli, płatności i przepływów.

## HTTP CONNECT, SOCKS i forwarding SSH

**Mechanika:** aplikacja prosi proxy o otwarcie strumienia TCP; SOCKS może również przekazywać rozwiązywanie nazw i UDP, zależnie od wersji; SSH przekazuje strumienie wewnątrz jednej zaszyfrowanej sesji.

**Zalety:** lekkość; per-aplikacja; szybkość; przydatność do łańcuchów i sieci segmentowanych.

**Wady:** aplikacje mogą go ominąć; DNS może wyciec; proxy widzi sąsiednie endpointy; stan przeglądarki pozostaje; otwarte proxy mogą być pułapkami lub systemami skompromitowanymi.

**Procedura:** (1) wdroż proxy na własnym hoście; (2) wymagaj uwierzytelniania i ogranicz źródło/cel; (3) skonfiguruj jeden jednorazowy profil aplikacji; (4) zapewnij zdalne rozwiązywanie DNS, gdy potrzebne; (5) zweryfikuj je przez własny endpoint DNS/HTTP; (6) zablokuj bezpośredni egress workloadu; (7) sprawdź i rotuj dane proxy.

**Wykrywanie:** identyfikuj procesy obsługujące tunele, negocjację CONNECT/SOCKS, długie sesje SSH i cele niezgodne z aplikacją; logi proxy odtwarzają strumienie.

## Web proxy z przepisywaniem URL i rozszerzenie proxy przeglądarki

**Mechanika:** strona pobiera cel i przepisuje linki/formularze przez własny origin albo rozszerzenie kieruje żądania przeglądarki do proxy. Cel widzi usługę, natomiast usługa może widzieć plaintext po zakończeniu TLS oraz wstrzykiwać lub przechowywać treść.

**Zalety:** brak klienta systemowego; szybkość przy prostym przeglądaniu; działa tam, gdzie nie można zainstalować VPN.

**Wady:** proxy może czytać dane logowania/treść, przepisywać downloady i fingerprintować użytkowników; skrypty/WebSocket/downloady mogą omijać proxy; rozszerzenie ma szerokie uprawnienia; mały zbiór anonimowości i częste blokady.

**Procedura:** (1) używaj wyłącznie proxy organizacji do autoryzowanych testów; (2) izoluj je w jednorazowej przeglądarce bez kont osobistych; (3) zabroń wpisywania haseł i wrażliwych downloadów; (4) zweryfikuj na własnej stronie każdy subresource; (5) przetestuj WebSocket, download i formularze; (6) usuń rozszerzenie/profil po użyciu.

**Wykrywanie:** cel loguje proxy; proxy enterprise/DNS i inwentarz rozszerzeń identyfikują usługę; subresource canary ujawniają bezpośredni bypass; logi proxy mapują sesję użytkownika na cele.

## Multi-hop proxy lub multi-hop VPN dostawcy

**Mechanika:** wejście widzi źródło, a jeden lub więcej relayów oddziela je od exit, który widzi cel.

**Zalety:** zwykły relay nie musi znać obu końców; awaria lub przejęcie jednego noda ujawnia mniej; elastyczna geografia.

**Wady:** wspólna administracja/logi niwelują podział; opóźnienia; korelacja czasowa; więcej awarii i tras DNS; to samo konto/płatność może połączyć wszystkie hopy.

**Procedura:** (1) określ, którego obserwatora usuwa każdy hop; (2) używaj niezależnie administrowanych, własnych lub zatwierdzonych relayów; (3) wymuś dostęp wyłącznie do wejścia; (4) ogranicz każdy relay do następnego hopu; (5) zweryfikuj logi każdej warstwy; (6) zatrzymaj każdy hop i potwierdź fail-closed. Odtwórz przez [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Wykrywanie:** koreluj czas/objętość NetFlow, powtarzające się handshake proxy i wspólną infrastrukturę kontrolera; nie wnioskuj o geografii operatora z exit.

## Relay aplikacyjny z podziałem wiedzy i OHTTP

**Mechanika:** klient szyfruje bezstanową wiadomość HTTP do gateway i wysyła ją przez relay. Relay widzi IP klienta, ale nie żądanie; gateway widzi żądanie, lecz zwykle tylko IP relay.

**Zalety:** silny, audytowalny podział prywatności dla obsługiwanych żądań; mniejszy narzut niż w ogólnych sieciach anonimowych.

**Wady:** brak dowolnego przeglądania; cookies/uwierzytelnianie mogą ponownie połączyć żądania; koluzja relay/gateway i analiza ruchu pozostają; aplikacja musi to implementować.

**Procedura:** (1) wybierz aplikację jawnie obsługującą RFC 9458; (2) zweryfikuj klucze gateway oficjalną konfiguracją; (3) unikaj stabilnych pól per-user; (4) wysyłaj wyłącznie obsługiwane żądania bezstanowe; (5) porównaj logi relay, gateway i celu; (6) przetestuj rotację kluczy/awarię bez bezpośredniego fallbacku.<sup>[[2]](#references)</sup>

**Wykrywanie:** endpointy ujawniają proces inicjujący i relay OHTTP; gateway wykrywa zniekształcony lub powtórzony ruch; czas i stabilne pola payloadu/konta mogą korelować żądania.

## MASQUE CONNECT-UDP/CONNECT-IP i HTTP privacy proxies

**Mechanika:** HTTP Extended CONNECT przez TLS/QUIC przenosi pakiety UDP lub IP przez proxy. Może implementować nowoczesny tunel podobny do VPN i mieszać transport z HTTP/3, ale proxy pozostaje obserwatorem.<sup>[[3]](#references)</sup>

**Zalety:** wydajne multipleksowanie i roaming; obsługa UDP lub pełnego IP; wdrożenie przez nowoczesną infrastrukturę HTTP.

**Wady:** to nie jest sieć anonimowa; proxy/konto widzi źródło i cele; fingerprinty QUIC/HTTP i znane ścieżki są widoczne dla endpointów i dostawców.

**Procedura:** (1) użyj klienta/usługi dokumentującej RFC 9298/9484; (2) uwierzytelnij certyfikat/konfigurację proxy; (3) zdefiniuj dozwolone trasy celu; (4) włącz szyfrowany DNS wewnątrz ścieżki; (5) zweryfikuj UDP, TCP, IPv6 i failover na własnych endpointach; (6) sprawdź logi żądań i przepływów proxy.

**Wykrywanie:** endpointy widzą proces klienta i interfejs wirtualny; sieci klasyfikują trwały QUIC/TLS do proxy; logi proxy ujawniają cel/ścieżkę CONNECT i przypisane trasy.

## Tor Browser

**Mechanika:** Tor wybiera guard, middle i exit; szyfrowanie warstwowe ogranicza widok każdego relay. Tor Browser dodaje ustandaryzowaną przeglądarkę odporną na fingerprinting.

**Zalety:** duży publiczny zbiór anonimowości; żaden zwykły relay nie zna obu końców; nie wymaga własnych serwerów.

**Wady:** mniejsza szybkość; ukierunkowanie na TCP; blokady i reputacja exit; logowania i ujawnienia identyfikują użytkownika; pozostaje korelacja czasowa end-to-end.

**Procedura:** (1) pobierz i zweryfikuj Tor Browser z projektu; (2) pozostaw domyślne ustawienia i unikaj rozszerzeń; (3) wybierz właściwy poziom bezpieczeństwa; (4) utwórz oddzielną tożsamość/sesję; (5) unikaj identyfikujących kont i zewnętrznych aktywnych dokumentów; (6) używaj HTTPS lub uwierzytelnionych onion services; (7) zweryfikuj exit wyłącznie przez własny endpoint.<sup>[[4]](#references)</sup>

**Wykrywanie:** sieci lokalne mogą rozpoznać znany ruch do guard, jeśli nie użyto bridge/transportu; cele widzą exit i zachowanie Tor Browser; obserwatorzy end-to-end korelują czas i objętość.

## Tor bridges i pluggable transports

**Mechanika:** niepubliczny bridge zastępuje publiczny guard; obfs4, Snowflake lub WebTunnel zmieniają transport pierwszego hopu, aby utrudnić blokowanie i probing.

**Zalety:** omijanie cenzury i ukrycie oczywistych celów publicznych relayów; po wejściu zachowany jest obwód Tor.

**Wady:** możliwe rozpoznanie wzorców transportu i odkrycie bridge; zmienna wydajność; brak dodatkowej ochrony przed kontami lub globalną korelacją czasu.

**Procedura:** (1) najpierw spróbuj bezpośredniego Tor; (2) w ustawieniach Connection Tor Browser wybierz wbudowany transport lub poproś o oficjalny bridge; (3) nie używaj losowych binariów/list; (4) połącz się i wykonaj bezpieczny test; (5) przetestuj ponowne połączenie i zegar; (6) pozostaw pozostałe ustawienia standardowe.<sup>[[5]](#references)</sup>

**Wykrywanie:** cenzorzy używają discovery celu, klasyfikacji protokołu/przepływu i aktywnego probingu; obrońcy powinni odróżniać użycie obejścia od kompromitacji i opierać się na kontekście procesu endpointu.

## VPN przed Torem i Tor przed VPN

**Mechanika:** VPN-before-Tor ukrywa bezpośrednie użycie Tor przed ISP, ale ujawnia źródło VPN. Tor-before-VPN daje VPN ruch po Tor i często stabilną tożsamość klienta/tunelu.

**Zalety:** usuwa konkretnego obserwatora przy poprawnym projekcie; może docierać do sieci blokujących jedną warstwę.

**Wady:** złożoność, nietypowy fingerprint, wycieki, mniejszy zbiór anonimowości i fałszywa pewność; Tor Project traktuje kombinacje jako zaawansowane.<sup>[[6]](#references)</sup>

**Procedura:** (1) zapisz usuwanego i nowego obserwatora; (2) użyj jednorazowego środowiska; (3) ustanów wyłącznie zamierzoną ścieżkę zewnętrzną; (4) wymuś trasy firewalla; (5) zweryfikuj DNS/IPv4/IPv6 i kolejność awarii; (6) porównaj widoczność obu dostawców; (7) porzuć stos, jeśli nie daje mierzalnej korzyści.

**Wykrywanie:** obserwatorzy lokalni/VPN/Tor widzą różne sąsiednie warstwy; czas pozostaje end-to-end; nietypowe fingerprinty zagnieżdżonych tuneli i konta dostawców mogą łączyć sesje.

## Onion service

**Mechanika:** klient i service budują obwody Tor do rendezvous, ukrywając IP service i omijając exit.

**Zalety:** ochrona lokalizacji źródła i service; uwierzytelnianie onion end-to-end; brak publicznego portu przychodzącego; opcjonalna autoryzacja klienta.

**Wady:** aktualizacje/analityka/błędy mogą ujawnić origin; klucz onion jest krytyczny; pozostają tożsamość aplikacji, czas i kompromitacja hosta.

**Procedura:** (1) odizoluj aplikację i przypnij ją wyłącznie do loopback/socket; (2) zainstaluj obsługiwany Tor; (3) skonfiguruj v3 onion service zgodnie z instrukcją; (4) chroń i twórz kopię klucza tylko przy wymaganej stałej tożsamości; (5) dodaj autoryzację klienta do użycia zamkniętego; (6) usuń pobieranie zasobów stron trzecich; (7) zewnętrznie potwierdź niedostępność origin.<sup>[[7]](#references)</sup>

**Wykrywanie:** obrońcy hosta/sieci znajdują proces/konfigurację Tor i obwody wychodzące; błędy aplikacji, DNS, certyfikaty lub zasoby zewnętrzne mogą ujawnić origin.

## Usługi wewnętrzne I2P

**Mechanika:** I2P używa osobnych jednokierunkowych tuneli przychodzących i wychodzących do destynacji wewnątrz overlay; outproxy do publicznego Internetu dodaje punkt zaufania.

**Zalety:** zdecentralizowane publikowanie wewnętrzne; brak zależności od oficjalnego exit; rozdzielone ścieżki wejścia/wyjścia.

**Wady:** nie jest zastępstwem zwykłej sieci Web; mniejszy ekosystem; długotrwałe zachowanie peerów; outproxy może obserwować publiczne przeglądanie.

**Procedura:** (1) zainstaluj z oficjalnego źródła; (2) użyj dedykowanego kontekstu; (3) pozwól na stabilizację integracji/przepustowości; (4) odwiedź własny service I2P; (5) unikaj outproxy, chyba że jest wymagany; (6) zweryfikuj brak bezpośredniego fallbacku po zamknięciu; (7) sprawdź lokalne logi peerów i service.<sup>[[8]](#references)</sup>

**Wykrywanie:** sieci lokalne widzą długotrwały ruch peerów i bootstrap; endpointy ujawniają procesy routera/aplikacji; outproxy logują exit.

## Mixnet

**Mechanika:** pakiety o stałym rozmiarze, batching, opóźnienia, zmiana kolejności i cover traffic ograniczają korelację czasu; gateway łączą aplikacje.

**Zalety:** większa odporność na analizę czasu niż proxy low-latency; przydatność do asynchronicznych wiadomości/transakcji.

**Wady:** opóźnienie, narzut przepustowości, mniejsze wdrożenie i ograniczenia aplikacji; metadane gateway/konta mogą pozostać.

**Procedura:** (1) wybierz utrzymywanego klienta i obsługiwaną aplikację; (2) przeczytaj rzeczywisty threat model; (3) zainstaluj w oddzielnym compartmencie; (4) wyślij nieszkodliwe dane do własnego endpointu; (5) zmierz opóźnienie, niezawodność i drogę odpowiedzi; (6) przetestuj awarię gateway; (7) nigdy nie wyłączaj opóźnień/cover traffic wyłącznie dla szybkości.<sup>[[9]](#references)</sup>

**Wykrywanie:** endpointy rozpoznają klienta; sieci klasyfikują gateway i rytm pakietów; gateway/exit widzą role sąsiednie, a szersza korelacja wymaga dłuższych okien statystycznych.

## Anonimowe udostępnianie plików GNUnet

**Mechanika:** GNUnet może kierować żądania publikacji/wyszukiwania/pobierania przez peerów i dodawać cover traffic zgodnie z poziomem anonimowości. Dokumentacja ostrzega, że domyślny poziom 1 nie wymaga cover traffic, a silna analiza może wskazać źródło.<sup>[[10]](#references)</sup>

**Zalety:** zdecentralizowane, natywne dla aplikacji anonimowe udostępnianie; regulowany wymóg cover traffic.

**Wady:** nie jest zwykłym anonimowym dostępem Web; koszt wydajności i storage; ograniczenia peerów i analizy ruchu; dokumentacja GNUnet VPN mówi, że jego overlay IP nie zapewnia dobrej anonimowości.

**Procedura:** (1) zainstaluj utrzymywaną oficjalną wersję; (2) odizoluj testowego peera; (3) ogranicz bandwidth/storage; (4) opublikuj nieszkodliwy unikalny plik testowy z wybranym poziomem anonimowości; (5) pobierz go z innego własnego peera; (6) zapisz cover traffic i opóźnienia; (7) nie twierdź, że komponent IP VPN zapewnia równoważną anonimowość.

**Wykrywanie:** bootstrap peera, ruch overlay, lokalny datastore/proces i identyfikatory plików; szeroki obserwator może analizować objętość względem cover traffic.

## Encrypted DNS, ODoH i ECH

**Mechanika:** DoH/DoT/DoQ szyfrują połączenie z resolverem; ODoH dzieli adres klienta i zapytanie między proxy a resolverem; ECH szyfruje wewnętrzny TLS ClientHello/nazwę serwera.

**Zalety:** usuwa plaintext DNS/SNI przed niektórymi lokalnymi obserwatorami; ODoH dzieli wiedzę o źródle i zapytaniu.

**Wady:** nie jest ścieżką anonimowości IP; resolver/proxy/server zachowują swoje role; IP celu, czas, objętość i endpoint pozostają; fallback może ujawnić zapytania.

**Procedura:** (1) wybierz, czy DNS kontroluje OS, aplikacja czy tunel; (2) włącz ścisły tryb szyfrowany lub obsługiwany ODoH; (3) przetestuj unikalną własną domenę; (4) przechwyć lokalnie i potwierdź brak jawnego zapytania; (5) wyłącz resolver i zweryfikuj zachowanie; (6) dla ECH potwierdź w diagnostyce serwera akceptację wewnętrznego ClientHello.<sup>[[11]](#references)</sup>

**Wykrywanie:** logi endpointu/resolvera ujawniają zapytania; sieci identyfikują endpointy szyfrowanych resolverów i przepływy do celów; stan ECH jest widoczny dla endpointów/CDN, nawet jeśli nie dla ścieżki.

## Privacy relay wielu dostawców

**Mechanika:** produkty takie jak iCloud Private Relay używają ingress znającego klienta oraz niezależnie obsługiwanego egress znającego cel, z obsługą przybliżonego regionu.

**Zalety:** łatwy podział wiedzy; szybkość; zintegrowana ochrona DNS/Web dla obsługiwanego ruchu.

**Wady:** ograniczony zakres produktu/aplikacji; dostawca platformy nadal identyfikuje klienta; brak dowolnej anonimowości systemowej; ryzyko koluzji, prawa i korelacji czasu.

**Procedura:** (1) potwierdź dokładne obsługiwane aplikacje i rodzaje ruchu; (2) włącz funkcję w dedykowanym kontekście platformy; (3) wybierz zachowanie regionu; (4) osobno przetestuj Safari/DNS i nieobsługiwane aplikacje; (5) sprawdź adres celu; (6) przetestuj zmianę sieci i awarię.<sup>[[12]](#references)</sup>

**Wykrywanie:** dostęp widzi ingress; cel widzi egress; logi platformy/relay i konto obejmują odpowiednie warstwy; nieobsługiwane aplikacje ujawniają zwykłe ścieżki.

## Zdalna przeglądarka, VDI, RDP lub organization jump host

**Mechanika:** przeglądanie i wykonywanie narzędzi odbywa się na zdalnym systemie; cel widzi jego egress, a dostawca workspace widzi połączenie operatora i control-plane.

**Zalety:** szybkość; izolacja ryzykownej treści; stabilny kontrolowany egress; jednorazowy stan i silny audyt organizacji.

**Wady:** dostawca/admin może obserwować sesję/konto; kanały ekranu, clipboardu i plików mogą wyciec; fingerprint zdalnej przeglądarki może być unikalny; brak anonimowości wobec właściciela workspace.

**Procedura:** (1) utwórz jeden workspace organizacji na engagement; (2) wymagaj MFA i ogranicz administrację; (3) wyłącz lub ogranicz clipboard/upload/download; (4) skieruj ruch przez zatwierdzony stały egress; (5) nie używaj osobistego IdP/synchronizacji; (6) eksportuj tylko sprawdzone dowody; (7) zniszcz workspace i dane uwierzytelniające zgodnie z harmonogramem.

**Wykrywanie:** logi dostawcy i IdP mapują użytkownika na sesję; cele grupują egress/workspace/przeglądarkę; obrońcy enterprise identyfikują protokoły zdalnego sterowania i anomalne sesje cloud.

## Publiczne lub gościnne Wi-Fi

**Mechanika:** ruch wychodzi przez NAT obiektu lub tunel uruchomiony w tym miejscu.

**Zalety:** duża szybkość i współdzielony adres spoza domu; brak własnej infrastruktury.

**Wady:** dowody obiektu/DHCP/portalu, kamer, zakupów i lokalizacji; wrogie peery/AP; regulaminy; ryzyko fizyczne.

**Procedura:** (1) uzyskaj dostęp oferowany gościom i potwierdź SSID z personelem; (2) użyj załatanego urządzenia niskiego zaufania; (3) wyłącz udostępnianie/auto-join i włącz prywatny MAC; (4) przejdź portal bez ponownie używanej tożsamości; (5) uruchom fail-closed VPN/Tor; (6) zweryfikuj ruch tetherowany; (7) zapomnij sieć.

**Wykrywanie:** obiekt koreluje AP, MAC, DHCP, portal i czas; cel widzi obiekt/tunel; śledczy łączą dowody fizyczne i urządzeniowe. Nigdy nie omijaj kontroli dostępu.

## Travel router

**Mechanika:** router należący do operatora łączy się z Wi-Fi/Ethernet obiektu i zapewnia izolowaną sieć wewnętrzną z wymuszoną polityką tunelu.

**Zalety:** izoluje stacje robocze; centralny kill switch/DNS; spójna sieć klienta; chroni uprzywilejowane endpointy przed lokalnymi broadcastami.

**Wady:** router staje się stałym fingerprintem radiowym/DHCP; zwiększa powierzchnię ataku; captive portal i tethering mogą ominąć tunel.

**Procedura:** (1) zaktualizuj obsługiwany firmware; (2) ustaw unikalne dane administracyjne i wyłącz WAN admin/WPS/UPnP; (3) skonfiguruj prywatny MAC upstream, gdy dozwolony; (4) utwórz oddzielny SSID; (5) wymuś full-tunnel oraz politykę firewall DNS/IPv6; (6) przetestuj portal, reconnect i awarię tunelu.

**Wykrywanie:** obiekt widzi skojarzenie routera i kształt ruchu; fingerprint RF/DHCP identyfikuje urządzenie; dostawca VPN widzi źródło obiektu.

## Sieć komórkowa, prepaid SIM i eSIM

**Mechanika:** modem używa radiowej sieci operatora i zwykle NAT operatora; warstwa VPN/Tor może zmienić exit widoczny dla celu.

**Zalety:** niezależność od lokalnej sieci przewodowej/Wi-Fi; mobilność; szybkość; przydatny backhaul dla autoryzowanych dropów.

**Wady:** operator zna abonenta/eSIM, IMSI, IMEI, komórki, czas i przypisane porty; przepisy rejestracyjne są różne; współlokalizacja z osobistym telefonem łączy urządzenia.

**Procedura:** (1) uzyskaj usługę zgodnie z prawem i podaj wymagane prawdziwe dane; (2) użyj oddzielnego modemu/urządzenia organizacji; (3) zarejestruj je u kontrolera ćwiczenia; (4) wyłącz niepowiązane radia/konta; (5) ustanów zatwierdzony tunel; (6) sprawdź, czy klienci tetherowani rzeczywiście go używają; (7) przed podróżą zweryfikuj założenia dostawcy i retencji.<sup>[[13]](#references)</sup>

**Wykrywanie:** logi operatora i lokalizacja RF; inwentarz USB/PCI/MDM oraz badania rogue-hotspot; czas celu/tunelu.

## Internet satelitarny i nadużycie downlinku satelitarnego

**Mechanika:** zwykła usługa korzysta z zarejestrowanego terminala/dostawcy. Dawne jednokierunkowe nadużycie DVB-S pozwalało odbiornikowi w wiązce obserwować niezaszyfrowany downlink skierowany do legalnego abonenta, przy użyciu innej ścieżki do żądań wychodzących.

**Zalety:** szeroki zasięg; niezależny last mile; historyczne nadużycie jednokierunkowe mogło przypisać C2 geografii abonenta.

**Wady:** dowody sprzętu/RF/dostawcy; opóźnienia i zasięg; współczesne systemy dwukierunkowe różnią się; ścieżka outbound i routing asymetryczny pozostają dowodem.

**Procedura:** dla legalnego dostępu zarejestruj własny terminal i tuneluj ruch zgodnie z potrzebą. Aby emulować historyczne zachowanie Turla, odtwórz syntetyczne capture jednokierunkowych pakietów w laboratorium bez RF i sprawdź, czy analityka wykrywa odpowiedź hosta, który nie wysłał żądania; nie przechwytuj ruchu satelitarnego na żywo.<sup>[[14]](#references)</sup>

**Wykrywanie:** telemetryka dostawcy/terminala, radiolokacja, niemożliwy/asymetryczny przepływ, niespójność RTT/routingu i konfiguracja malware.

## Residential/mobile proxy lub proxyware za zgodą

**Mechanika:** gateway backconnect przydziela konsumenckie exit broadband/mobile, stałe albo rotacyjne. Źródło może być dobrowolne, zwodniczo dołączone lub złośliwe.

**Zalety:** szybkość; wybór geografii; ASN konsumencki omija część blokad hostingu; duże pule.

**Wady:** ryzyko prawne i proweniencji/zgody; broker widzi klienta; zainfekowane exit szkodzą ofiarom; rotacja tworzy anomalie; koszt i zawodność.

**Procedura:** do emulacji używaj tylko udokumentowanych agentów organizacji za świadomą zgodą: (1) zarejestruj endpointy testowe; (2) zinwentaryzuj właścicieli/IP; (3) skonfiguruj gateway; (4) rotuj tryb stały/per-request; (5) wysyłaj wyłącznie do własnego celu; (6) porównaj logi gateway/exit/celu; (7) usuń każdego agenta.

**Wykrywanie:** niemożliwa podróż, ten sam browser/account przy szybkiej zmianie IP/ASN, protokoły backconnect, artefakty procesu/sieci proxyware i relacje brokera/kontrolera.

## ORB, botnet i relaye skompromitowanych urządzeń brzegowych

**Mechanika:** wynajęte lub skompromitowane routery/IoT/serwery tworzą role dostępu, tranzytu i exit zarządzane jako flota. Może współdzielić je wielu klientów APT.

**Zalety:** pożyczona reputacja/geografia; krótkotrwałe exit; odporna siatka multi-hop; słabe bezpośrednie powiązanie aktora z IP.

**Wady:** wiktymizacja kryminalna; wzorce implantu/kontrolera/floty; przejęcie pośrednika; niestabilność; zapisy operatora/klienta.

**Procedura:** nigdy nie kompromituj prawdziwych urządzeń. Użyj [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) utwórz odizolowane sieci wejścia/tranzytu/celu; (2) dołącz własne dwuhomed relay containers; (3) przekazuj tylko jeden port testowy; (4) wyślij nieszkodliwe żądanie; (5) potwierdź, że cel widzi wyłącznie exit; (6) zmień exit; (7) usuń wszystkie nazwane zasoby.<sup>[[15]](#references)</sup>

**Wykrywanie:** śledź topologię, porty/usługi, relacje kontrolera, fingerprinty implantu i cykl życia nodów; centralizuj telemetrię konfiguracji/flow/integralności; nie utożsamiaj IP exit z aktorem.

## CDN redirector, domain fronting i domainless fronting

**Mechanika:** publiczny edge przekazuje wyłącznie ruch zgodny z gramatyką; fronting używa nieszkodliwego zewnętrznego SNI i innego wewnętrznego HTTP authority albo pustego SNI, gdy pośrednik na to pozwala.

**Zalety:** ukrywa/chroni back-end; szybki globalny edge; miesza cel ze współdzieloną usługą; szybkie przełączenie.

**Wady:** CDN widzi cały routing i tenant; wielu dostawców zabrania frontingu między tenantami; artefakty SNI/Host/process/flow/account; ponowne użycie konfiguracji grupuje kampanie.

**Procedura:** reprodukuj wyłącznie na własnym reverse proxy z [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): utwórz lokalny certyfikat/edge, skieruj jeden niezgodny Host do własnego celu, loguj SNI i Host, wyślij zwykłe i niezgodne żądania, następnie usuń kontenery.<sup>[[16]](#references)</sup>

**Wykrywanie:** porównuj SNI/ECH/Host/`:authority` na endpointcie lub kończącym edge; łącz proces inicjujący, tenant/origin, gramatykę żądań i rytm przepływu.

## Dynamic DNS, DGA, fast flux i double flux

**Mechanika:** DDNS aktualizuje stałą nazwę; DGA tworzy zmienne nazwy kandydackie; fast flux rotuje adresy usługi z niskim TTL; double flux rotuje również nameservery.

**Zalety:** odporność discovery; szybka wymiana infrastruktury; kontroler ukryty za wieloma nodami.

**Wady:** DNS tworzy scentralizowaną telemetrię; entropy/NXDOMAIN/churn; niski TTL i szerokie wzorce ASN; rejestracja i infrastruktura authoritative pozostają.

**Procedura:** użyj [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): obsłuż własną strefę zwracającą adresy RFC 5737 z TTL pięciu sekund, odpytywaną wielokrotnie, zmień syntetyczną epokę i sprawdź analitykę. Nigdy nie kieruj rekordów testowych do stron trzecich.<sup>[[17]](#references)</sup>

**Wykrywanie:** unikalne odpowiedzi/ASN w oknie, mediana TTL, geografia, churn authoritative, klastry NXDOMAIN/leksykalne/czasowe DGA i następstwa procesu; wykluczaj legalne CDN z uwzględnieniem kontekstu.

## Legalna usługa Web, dead-drop resolver i one-way tasking

**Mechanika:** publiczny post, repository, dokument, obiekt lub feed zawiera zakodowany bieżący endpoint albo zadanie. Klient może zwracać wyniki innym kanałem.

**Zalety:** usługa o dobrej reputacji; TLS; rotacja endpointu bez zmiany binary; asymetryczne tasking utrudnia prostą korelację przepływu.

**Wady:** stałe identyfikatory obiektu/konta/API; logi dostawcy; sekwencja decode/follow-on; treść może zostać przejęta lub zmieniona.

**Procedura:** użyj [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): umieść zakodowany wskaźnik w jednym własnym kontenerze, pobierz/odkoduj z krótkotrwałego klienta, połącz się z drugim własnym service, zachowaj oba logi, a następnie usuń środowisko.

**Wykrywanie:** koreluj nietypowe `process -> odczyt stałego obiektu -> decode -> nowy cel`; haszuj/zachowuj treść i pełne ścieżki obiektów, nie tylko domenę.

## Serverless, ephemeral container i egress cloud-NAT

**Mechanika:** funkcje/krótkotrwałe joby działają za NAT dostawcy lub frontem; usługa logiczna pozostaje stała, a instancje/adresy rotują.

**Zalety:** szybkie wdrożenie/usunięcie; współdzielony egress dostawcy; mało lokalnego dysku; elastyczny routing regionalny.

**Wady:** tenant, role, API, image, secret, invocation, płatność i logi front-origin są trwałe; fingerprint cold-start/platformy; polityka dostawcy.

**Procedura:** (1) użyj własnego tenant organizacji; (2) wdroż nieszkodliwą funkcję żądającą wyłącznie własnego endpointu; (3) zapisz project/role/image/config; (4) uruchom kilka instancji; (5) porównaj IP celu z audit/request ID; (6) przetestuj retencję logów; (7) usuń funkcję, role i sekrety.

**Wykrywanie:** logi cloud audit/invocation, nietypowe tworzenie ról, wspólny egress ze stałą gramatyką żądań, ponowne użycie image/layer/secret oraz korelacja front-origin.

## Autoryzowany drop na miejscu

**Mechanika:** zinwentaryzowany mały komputer używa lokalnego wired/Wi-Fi oraz outbound VPN/cellular rendezvous, prezentując lokalne źródło.

**Zalety:** realistyczne testy pochodzenia wewnętrznego; szybkość; testy NAC, inwentarza fizycznego i kontroli egress.

**Wady:** wykrycie/kradzież; dowody serial/MAC/USB/DHCP/PoE/RF i kamer; utrata może ujawnić dane.

**Procedura:** postępuj zgodnie z [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) uzyskaj dokładną pisemną zgodę na umieszczenie; (2) zapisz serial, MAC, zdjęcie, lokalizację i czas odbioru; (3) użyj podpisanego minimalnego image i krótkotrwałych wzajemnych danych uwierzytelniających; (4) ogranicz wyjście do dozwolonych celów/możliwości; (5) dodaj serwerową kwarantannę i limity bandwidth; (6) przetestuj widoczność SOC i reakcję na utratę; (7) odbierz, zachowaj wymagane dowody, a następnie wyczyść zgodnie z polityką cyklu życia. Nigdy nie ukrywaj go w miejscu bez zgody.

**Wykrywanie:** NAC/802.1X, switchport/PoE/DHCP, inwentarz USB, badanie RF, powtarzający się tunel, odbiór/kamery i inspekcja fizyczna.

## Pivot bezprzewodowy nearest-neighbor

**Mechanika:** aktor kontroluje host w zasięgu radiowym celu, a następnie używa danych Wi-Fi celu, aby zdalnie przekroczyć granicę. APT28 używało w ten sposób pobliskich skompromitowanych organizacji.<sup>[[18]](#references)</sup>

**Zalety:** brak podróży operatora; cel widzi lokalne źródło radiowe; omijanie kontroli stosowanych wyłącznie do wejścia z Internetu.

**Wady:** wymagany pobliski skompromitowany/własny host z dwoma radiami i poprawnym dostępem; dowody RADIUS/NAC/AP i sąsiedniego endpointu; anomalie sygnału/urządzenia.

**Procedura:** reprodukuj wyłącznie przez [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): dołącz własny pivot do SSID sąsiada i celu, przekaż tylko jedną usługę, zbierz logi obu AP/pivotu, następnie włącz EAP-TLS/posture urządzenia i potwierdź odrzucenie drugiej próby.

**Wykrywanie:** koreluj tożsamość RADIUS, certyfikat/posture, urządzenie first-seen, krawędź/sygnał AP, równoczesne logowanie i obecność fizyczną; szukaj w pobliżu endpointów z jednoczesnymi radiami, forwardingiem i tunelami.

## Community mesh, delay-tolerant i offline store-and-forward

**Mechanika:** ruch przechodzi przez lokalne peery, asynchroniczne gateway, nośniki wymienne lub zaplanowane kolejki zamiast jednej interaktywnej sesji Internet.

**Zalety:** działa podczas zakłóceń/cenzury; opóźnione i batchowane dostarczanie osłabia prostą korelację czasu; brak centralnego last mile przy komunikacji lokalnej.

**Wady:** wysokie opóźnienie; mały zbiór anonimowości; metadane custody/fizyczne; złośliwe peery; dane ostatecznie trafiają do gateway obserwującego je.

**Procedura:** (1) zbuduj odizolowany własny mesh trzech nodów lub kolejkę plików; (2) szyfruj i uwierzytelniaj treść end-to-end; (3) usuń bezpośrednie trasy Internet z origin; (4) przekaż nieszkodliwy plik po kontrolowanym opóźnieniu; (5) potwierdź, że tylko gateway kontaktuje się z własnym celem; (6) porównaj custody i timestampy; (7) zachowaj wymagane dowody, a następnie wyczyść tymczasowe nośniki/kolejki.

**Wykrywanie:** aktywność plików/procesów endpointu, łącza radiowe peerów, audyt nośników, okresowość kolejki/gateway i identyfikatory treści. Dłuższe okna korelacji zastępują analizę interaktywnego przepływu.

## Relay TURN i WebRTC z wymuszonym relay

**Mechanika:** Traversal Using Relays around NAT (TURN) przydziela publiczny adres relay i przenosi ruch UDP, TCP lub TLS między klientem i peerami. Polityka ICE może wymusić użycie relay zamiast bezpośredniego kandydata. TURN rozwiązuje osiągalność, nie ogólną anonimowość: serwer uwierzytelnia klienta i widzi alokacje, peery, czas i objętość.<sup>[[19]](#references)</sup>

**Zalety:** szeroka implementacja; obsługa restrykcyjnego NAT; mobile WebRTC; peer nie otrzymuje bezpośredniego adresu transportowego klienta przy poprawnej polityce relay-only.

**Wady:** operator TURN widzi obie strony; tożsamość aplikacji, fingerprint mediów i signaling pozostają; relay-only kosztuje bandwidth i opóźnienie; błędna konfiguracja może ujawnić kandydatów host/server-reflexive.

**Procedura:** (1) wdroż własny TURN z TLS i krótkotrwałymi danymi; (2) ogranicz realm, peerów, porty, quota i wygaśnięcie; (3) ustaw relay-only ICE; (4) połącz własnego peera; (5) sprawdź `getStats()` i capture, potwierdzając, że media przenosili wyłącznie relay candidates; (6) wyłącz relay i potwierdź brak fallbacku; (7) zachowaj logi alokacji.

**Wykrywanie:** signaling, proces przeglądarki i alokacje TURN łączą sesję z relay; sieci widzą trwałe przepływy do portów TURN lub endpointów TLS; peer widzi przydzielony relay. **Przejęty node:** stan aplikacji i krótkotrwałe dane TURN mogą ujawnić realm i service rendezvous. Minimalizuj ekspozycję przez krótkotrwałe dane per-device, a uwierzytelnianie operatora trzymaj wyłącznie w kontrolerze.

## Outbound-only rendezvous lub reverse overlay

**Mechanika:** node za NAT inicjuje uwierzytelnione połączenie do kontrolowanego przez organizację brokera. Operator uwierzytelnia się osobno; broker autoryzuje wąski kanał zarządzania. Nie potrzeba inbound port forwarding ani bezpośredniej trasy operator-node.

**Zalety:** stabilność za NAT i captive last mile; centralne unieważnianie i audyt; zmiana adresu field-node nie wymaga discovery; czyste oddzielenie tożsamości operatora od credential node.

**Wady:** broker jest cennym punktem korelacji; keepalive są rozpoznawalne; szeroki tunel może stać się niebezpiecznym pivotem; awaria brokera kończy zarządzanie.

**Procedura:** postępuj zgodnie z [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): wydaj jedną ograniczoną tożsamość urządzenia, zezwól wyłącznie na własny broker i usługę zarządzania, użyj uwierzytelnionego keepalive, wymuś fail-closed, przetestuj zmiany adresu/reboot i unieważnij tożsamość podczas ćwiczenia utraty. WireGuard opisuje 25-sekundowy persistent keepalive jako przydatny interwał NAT, gdy jest rzeczywiście potrzebny.<sup>[[20]](#references)</sup>

**Wykrywanie:** logi brokera i IdP mapują obie strony; sieć dostępu widzi powtarzalny zaszyfrowany cel/rytm; inwentarz endpointu pokazuje agenta overlay. **Przejęty node:** zakładaj ujawnienie klucza urządzenia, nazwy brokera, adresów tunelu i cache zadań. Nie może zawierać prywatnego klucza operatora, konta osobistego ani wielokrotnego tokena kontrolera.

## Pull mailbox, message queue lub object-store rendezvous

**Mechanika:** workload polowy odpytuje uwierzytelnioną skrzynkę o podpisane, zatwierdzone zadania i wysyła ograniczone wyniki. Operator zapisuje do kolejki przez osobny control-plane; brak interaktywnego socketu między nimi.

**Zalety:** toleruje przerywane łącza; oddziela czas i adresowanie; quota i schema ograniczają możliwości; łatwy centralny audyt i revocation.

**Wady:** rytm odpytywania i stałe nazwy obiektów/kolejek fingerprintują system; logi dostawcy łączą producenta i konsumenta; opóźnione sterowanie; przejęte dane kolejki mogą ujawnić ćwiczenie.

**Procedura:** (1) utwórz jedną kolejkę engagementu i jedną tożsamość urządzenia; (2) zdefiniuj podpisaną schemę nieszkodliwych zadań; (3) ustaw TTL wiadomości, maksymalny wynik i rate; (4) pozwól node pobierać wyłącznie własną kolejkę i zapisywać tylko własny prefix; (5) przetestuj offline accumulation, duplikaty i revocation; (6) centralizuj niezmienne logi dostępu; (7) usuń kolejkę po spełnieniu retencji.

**Wykrywanie:** szukaj okresowych API calls nietypowego procesu, stałych ścieżek bucket/object/queue, identycznego user-agenta/TLS oraz sekwencji fetch-then-new-connection. **Przejęty node:** cache może ujawnić zadania i nazwy obiektów; szyfruj, ograniczaj i usuwaj cache, zachowując autorytatywne logi kontrolera.

## Dual-uplink failover i migracja połączenia

**Mechanika:** zatwierdzony field node ma dwa niezależne uplinki, np. Ethernet/Wi-Fi obiektu i cellular organizacji, i utrzymuje sesję control przez overlay lub broker przy zmianie tras. To inżynieria dostępności, nie anonimowość.

**Zalety:** przetrwanie awarii jednego dostawcy/AP/captive portal; planowana konserwacja; szybka izolacja podejrzanej ścieżki.

**Wady:** dwóch dostawców tworzy dwa rekordy lokalizacji/konta; równoczesne użycie ułatwia korelację; wycieki tras/DNS podczas failover; pozostaje dowód współlokalizacji z cellular.

**Procedura:** (1) zarejestruj oba interfejsy i dostawców organizacji; (2) ustaw deterministyczny priorytet tras i health checks do własnych endpointów; (3) zwiąż DNS i zarządzanie z overlay; (4) zablokuj inbound na ścieżce dodatkowej; (5) odłącz każdą ścieżkę i sprawdź odzyskanie sesji, politykę źródła i brak bezpośredniego dostępu do celu; (6) alarmuj przy nieplanowanej zmianie; (7) udokumentuj użycie danych i roaming.

**Wykrywanie:** koreluj ten sam certyfikat urządzenia, gramatykę żądań i czas między ASN; inwentarz lokalny widzi oba radia; carrier/obiekt zachowują własne dane. **Przejęty node:** widoczne mogą być oba identyfikatory SIM/urządzenia i znane SSID; używaj zasobów organizacji i nie łącz node z urządzeniami osobistymi.

## Prywatny APN organizacji lub zarządzany tunel komórkowy

**Mechanika:** prywatny APN operatora umieszcza zarejestrowane SIM w prywatnej domenie routowanej lub tuneluje ruch do gateway enterprise. Oddziela urządzenie od publicznego Internetu mobilnego, ale nie ukrywa go przed operatorem ani organizacją.

**Zalety:** stabilne prywatne adresowanie; polityka ruchu i enrollment na poziomie operatora; brak publicznej ekspozycji inbound; użyteczność dla autoryzowanych urządzeń zdalnych.

**Wady:** silne przypisanie abonenta, IMSI/IMEI, komórki i płatności; czas i koszt zakupu; awaria operatora/gateway; brak anonimowości wobec operatora.

**Procedura:** (1) zamów APN na nazwę organizacji assessmentu; (2) allowlistuj zarejestrowane SIM i prefixy gateway; (3) dodaj wzajemne uwierzytelnianie warstwy aplikacji; (4) ogranicz trasę APN do rendezvous i aktualizacji; (5) przetestuj usunięcie SIM, roaming, public breakout i revocation; (6) monitoruj rekordy operatora/gateway; (7) anuluj lub poddaj kwarantannie każdą SIM przy zamknięciu.

**Wykrywanie:** inwentarz operatora i telemetria komórek, przepływy gateway APN, niezgodność SIM/IMEI i rekordy zasobów. **Przejęty node:** SIM i modem identyfikują kontrakt nawet przy szyfrowanym storage; odporność oznacza szybkie zawieszenie i wąską autoryzację, nie zaprzeczalność.

## Dalekosiężny most radiowy point-to-point

**Mechanika:** kierunkowe Wi-Fi lub inne licencjonowane/nielicencjonowane radio point-to-point łączy dwie zatwierdzone lokalizacje właściciela, z egress Internet w lokalizacji zdalnej. Może zmienić pozorną lokalizację IP bez commercial proxy.

**Zalety:** duża przepustowość; niezależność od pośrednich operatorów przewodowych; kontrola RF i routingu; testy segmentacji i monitoringu lokalizacji zdalnej.

**Wady:** line-of-sight, spectrum, landlord i ograniczenia prawne; charakterystyczna emisja RF i sprzęt; oba endpointy są dowodem fizycznym; pogoda/zasilanie/ustawienie wpływają na stabilność.

**Procedura:** (1) uzyskaj pisemną zgodę obu lokalizacji i sprawdź zasady spectrum/power; (2) zbadaj ścieżkę bez transmisji poza zatwierdzonymi parametrami; (3) użyj szyfrowania i management VLAN; (4) ogranicz bridge do własnego rendezvous/test subnet; (5) przetestuj failover, alignment, odzyskanie zasilania i containment RF; (6) oznacz i zinwentaryzuj oba radia; (7) usuń je i sprawdź reset konfiguracji.

**Wykrywanie:** badanie RF/spectrum, inspekcja dachu/lokalizacji, MAC/OUI bridge, ruch zarządzający i logi egress lokalizacji zdalnej. **Przejęty node:** konfiguracja ujawnia peer i domenę zarządzania; używaj unikalnych danych ćwiczenia, bez osobistych kont administracyjnych, z szybką revocation klucza peera.

## Współpracujący lub społecznościowy exit za zgodą

**Mechanika:** wolontariusze lub partnerzy świadomie uruchamiają relay z opublikowaną polityką. Ruch wychodzi ze współdzielonej puli, a warstwa koordynacji obsługuje nadużycia i revocation.

**Zalety:** różnorodne sieci non-cloud; jawna zgoda jest bezpieczniejsza niż proxyware; wspólne zarządzanie rozkłada zaufanie; użyteczne w badaniach i odporności na cenzurę.

**Wady:** małe pule i rejestry członków zmniejszają anonimowość; operatorzy exit otrzymują skargi i widzą metadane; złośliwi uczestnicy, zmienna dostępność i różne jurysdykcje.

**Procedura:** (1) opublikuj politykę acceptable-use/logging; (2) uzyskaj świadomą zgodę każdego operatora; (3) wydaj unikalną tożsamość relay i ogranicz cele/rate; (4) zapewnij obsługę nadużyć i jednorazową revocation; (5) podczas testów wysyłaj wyłącznie autoryzowany ruch do własnych endpointów; (6) zmierz churn i ekspozycję korelacji; (7) usuń relay po wycofaniu zgody.

**Wykrywanie:** rekordy członkostwa/control-plane, certyfikaty relay, wspólny fingerprint software i zachowanie exit identyfikują pulę. **Przejęty node:** konfiguracja może ujawnić kooperanta, ale nie powinna zawierać tożsamości klientów; odpowiedzialność klient-sesja przechowuj w autoryzowanym kontrolerze z kontrolą dostępu.

## Tymczasowe adresy IPv6 i rotacja prefixu

**Mechanika:** rozszerzenia prywatności IPv6 tworzą tymczasowe identyfikatory interfejsu, aby stały adres nie był używany dla każdego połączenia. Zmiana prefixu może dodać rotację, ale delegated prefix, rekord abonenta i fingerprint wyższych warstw pozostają.<sup>[[21]](#references)</sup>

**Zalety:** ogranicza długotrwałe śledzenie po stabilnym identyfikatorze interfejsu; dostępne w popularnych OS; brak narzutu relay.

**Wady:** brak anonimowości źródła; ISP i sieć lokalna nadal znają prefix/urządzenie; DNS, konta i stan przeglądarki łączą sesje; churn utrudnia allowlisty i logowanie.

**Procedura:** (1) sprawdź bieżące adresy stałe i tymczasowe na własnym kliencie; (2) włącz obsługiwany domyślny mechanizm OS zamiast spoofingu; (3) wielokrotnie żądaj własnego endpointu IPv6 w różnych okresach życia adresu; (4) potwierdź, że usługi inbound wiążą się tylko z zamierzonymi adresami stałymi; (5) zachowaj logi DHCPv6/RA/neighbor i endpointu; (6) przetestuj VPN/firewall dla każdego adresu IPv6.

**Wykrywanie:** koreluj delegated prefix, tożsamość warstwy 2, neighbor discovery, konto i telemetrykę endpointu, zamiast traktować adres jako urządzenie. **Przejęty node:** profile sieci i identyfikatory interfejsu pozostają; adresowanie tymczasowe zapobiega jednemu pasywnemu identyfikatorowi, nie atrybucji kryminalistycznej.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 i meek

**Mechanika:** pluggable transport zmienia wygląd pierwszego połączenia Tor lub sposób dotarcia do bridge. Snowflake używa krótkotrwałych ochotniczych proxy WebRTC, WebTunnel przypomina zwykły HTTPS, obfs4 utrudnia prostą identyfikację i aktywne probing, a meek korzysta z obsługiwanej infrastruktury Web. Są to transporty obejścia cenzury do Tor, nie dodatkowe warstwy anonimowości end-to-end.<sup>[[22]](#references)</sup>

**Zalety:** użyteczne przy blokadzie bezpośredniego Tor lub znanych relayów; Snowflake unika stałego publicznego adresu bridge; integracja z utrzymywanymi klientami Tor; cel nadal otrzymuje właściwości Tor.

**Wady:** niższa lub zmienna wydajność; broker/front/bridge i sieć lokalna widzą różne metadane; fingerprinty i blokady pozostają; ochotniczy proxy nie zastępuje Tor i nie powinien być zaufany z plaintextem aplikacji.

**Procedura:** (1) zainstaluj i zweryfikuj oficjalny Tor Browser lub obsługiwany klient Tor; (2) wybierz wbudowany transport w Connection/Bridges; (3) łącz się wyłącznie z własną stroną diagnostyczną; (4) potwierdź, że strona widzi Tor exit, nie peer Snowflake/WebTunnel; (5) porównaj bootstrap i wydajność; (6) wyłącz transport i potwierdź brak cichego połączenia bezpośredniego; (7) wróć do standardowej konfiguracji.

**Wykrywanie:** cenzor może łączyć allowlisty celu, zachowanie TLS/WebRTC, discovery brokera i analizę przepływu; endpointy ujawniają Tor i konfigurację transportu. **Capture-resilient OPSEC:** używaj standardowego klienta, nie kopiuj osobistego stanu przeglądarki i zakładaj możliwość odzyskania historii bridge/brokera. **Monitoring:** obserwuj logi bootstrap, nieoczekiwane próby bezpośredniego DNS/połączeń i obserwacje własnej strony; awaria transportu nie dowodzi discovery.

## Refraction networking lub decoy routing

**Mechanika:** współpracujący operator sieci wykrywa ukryty sygnał w ruchu pozornie skierowanym do dozwolonego decoy i przekierowuje go do proxy obejścia. Wdrożenie wymaga infrastruktury w ścieżce; klient nie może tego utworzyć wyłącznie przez wybór niewinnej strony.<sup>[[23]](#references)</sup>

**Zalety:** pozorny cel może być trudny do zablokowania bez szkód ubocznych; nie trzeba dystrybuować publicznego adresu bridge; użyteczny model badawczy.

**Wady:** specjalistyczny udział ISP/transit; wdrażalność i wydajność zależą od routingu; przepływ klient-decoy i aktywność proxy pozostają; obserwator globalny/współpracujący może korelować czas.

**Procedura:** nie sygnalizuj przez niezaangażowane sieci. Odtwórz architekturę w izolowanym laboratorium: (1) utwórz własne namespace klienta, routera, decoy i proxy; (2) użyj nieszkodliwego oznaczonego żądania; (3) pozwól własnemu routerowi przekierować wyłącznie ten znacznik; (4) loguj krotki przed/po routingu i request ID; (5) porównaj przepływy zwykłe i sygnalizowane; (6) przetestuj false positives i usunięcie; (7) zniszcz trasy laboratoryjne.

**Wykrywanie:** operatorzy autoryzowanej sieci mogą sprawdzać rozbieżność routingu, nietypowy ClientHello/tag i różnice przepływu decoy-back-end. **Capture-resilient OPSEC:** klient badawczy powinien mieć wyłącznie klucze testowe i adresy dokumentacyjne. **Monitoring:** porównuj podpisane decyzje routera laboratoryjnego z przybyciem do proxy; nie sonduj produkcyjnych dostawców transit.

## Gateway content-addressed lub pobieranie z cache peera

**Mechanika:** gateway HTTP pobiera content identifier IPFS (CID), z cache lub peerów, i zwraca weryfikowalną treść klientowi. Oryginalny publisher może widzieć gateway lub innych peerów zamiast czytelnika; gateway widzi IP czytelnika i żądany CID. Natywne pobieranie P2P ujawnia klienta peerom i uczestnikom DHT/routingu.<sup>[[24]](#references)</sup>

**Zalety:** cache oddziela publishera i czytelnika; niezmienna treść jest weryfikowalna hashem; replikacja przeżywa awarię hosta; klient HTTP nie wymaga natywnego stosu peer.

**Wady:** publiczne CID i logi gateway ujawniają zainteresowanie; czas pierwszego pobrania może korelować publishera z czytelnikiem; złośliwa treść i zagrożenia same-origin path; publiczne gateway są best-effort i zabraniają nadużyć.

**Procedura:** (1) opublikuj nieszkodliwy plik w prywatnym własnym swarmie IPFS lub własnym gateway; (2) zapisz CID; (3) pobierz przez oddzielny własny gateway HTTP z izolacją subdomeny; (4) zweryfikuj bajty względem CID; (5) powtórz po cache; (6) porównaj logi publishera, peera i gateway; (7) odpinaj i usuń treść po zakończeniu retencji.

**Wykrywanie:** gateway loguje źródło/CID; połączenia DHT i peer ujawniają pobranie; historia endpointu i hashe plików identyfikują treść. **Capture-resilient OPSEC:** nie przechowuj prywatnego klucza publishing na kliencie read-only; szyfruj wrażliwą treść przed content addressing. **Monitoring:** alarmuj przy nieoczekiwanym pinning, zmianie zbioru peerów, CID poza allowlistą lub powiadomieniu gateway.

## Usługa Private Information Retrieval

**Mechanika:** Private Information Retrieval (PIR) pozwala pobrać jeden rekord z bazy przy kryptograficznym ukryciu wybranego indeksu przed serwerem, w określonym modelu single- lub multi-server. Chroni wybór zapytania dla ograniczonego zbioru; nie jest ogólnym Web ani anonimowością IP.<sup>[[25]](#references)</sup>

**Zalety:** silna prywatność zapytań aplikacyjnych; mierzalny model wycieku; przydatność dla katalogów kluczy, blocklist i małych publicznych baz; mniejsza potrzeba ujawniania dokładnego terminu.

**Wady:** narzut obliczeń/bandwidth; serwer zna czas/IP połączenia, jeśli brak relay; wersja zbioru, rozmiar odpowiedzi i stan aplikacji mogą dzielić użytkowników; różna dojrzałość implementacji.

**Procedura:** (1) wdroż audytowany PIR na syntetycznej własnej bazie; (2) opublikuj wersję i parametry; (3) pobierz kilka indeksów z identycznymi rozmiarami żądań; (4) lokalnie zweryfikuj poprawność; (5) porównaj logi serwera i potwierdź brak indeksu; (6) przetestuj złośliwe/ucięte odpowiedzi i niezgodność wersji; (7) opisz dokładne założenie prywatności zamiast nazywać to anonimowym browsingiem.

**Wykrywanie:** sieci widzą użycie service i objętość; telemetryka endpointu ujawnia klienta i użycie rekordu; skompromitowany serwer może manipulować bazą/czasem. **Capture-resilient OPSEC:** przechowuj na kliencie tylko publiczne parametry i ograniczony cache. **Monitoring:** weryfikuj podpisane roots zbioru, stały kształt żądań, zmiany error rate i rotację kluczy serwera.

## Ograniczony fetcher, preview lub rendering po stronie serwera

**Mechanika:** zdalna usługa pobiera lub renderuje URL i zwraca screenshot, metadane albo oczyszczoną treść. Cel widzi adres fetchera; service widzi requestera, URL i wynik. Nadużywanie botów preview, scannerów security lub zewnętrznych fetcherów nie jest autoryzowanym użyciem proxy.

**Zalety:** izolacja aktywnej treści od workstation; kontrolowany fingerprint fetchera; limity typu pliku, rozmiaru, celu i renderowania; jednorazowe środowisko.

**Wady:** service zna pełne żądanie; rekordy konta/API/płatności; ryzyko SSRF i exfiltration; skrypty, uwierzytelnianie i interaktywne strony mogą nie działać; unikalne URL korelują requestera z fetchem.

**Procedura:** (1) wdroż własny fetcher z allowlistą własnych domen testowych; (2) zablokuj private, link-local, metadata i redirect do niezatwierdzonych adresów; (3) ogranicz metody, redirecty, bajty i czas renderowania; (4) usuń credential/cookie; (5) prześlij własny URL; (6) porównaj logi requestera, fetchera i celu; (7) zniszcz instancję i zachowaj centralny audyt.

**Wykrywanie:** cel widzi ASN/fingerprint service; logi dostawcy i kontrolera mapują requestera na URL; proces/API endpointu pokazują submission. **Capture-resilient OPSEC:** użyj jednego krótkotrwałego tokena projektu bez dowolnego wyboru celu. **Monitoring:** alarmuj przy blokadach allowlisty, naruszeniach redirect, fetchach bez job ID i powiadomieniach o nadużyciu.

## Pula rendezvous Anycast

**Mechanika:** wiele kontrolowanych przez organizację nodów reklamuje lub frontuje jeden stabilny adres service, a routing wybiera najbliższą instancję. Anycast poprawia dostępność i ukrywa indywidualny back-end, ale operator nadal kontroluje wszystkie instancje, a adres pozostaje stały.<sup>[[26]](#references)</sup>

**Zalety:** odporny regionalny ingress; brak rekonfiguracji field node po awarii instancji; dystrybucja DDoS/load; centralna polityka może przenosić sesje między znanymi nodami.

**Wady:** rekordy BGP/CDN/dostawcy identyfikują organizację; zmiana ścieżki może zerwać sesje stanowe; monitoring zależy od lokalizacji klienta; jeden adres łatwo blokować i grupować po reputacji.

**Procedura:** użyj obsługiwanego projektu organizacji lub izolowanego laboratorium routingu: (1) wdroż dwa identyczne uwierzytelnione health endpointy; (2) wystaw jeden udokumentowany adres; (3) trzymaj stan sesji w brokerze, nie na edge; (4) wycofaj jeden node i sprawdź reconnect; (5) przetestuj certyfikat, politykę i spójność logów; (6) alarmuj przy nieautoryzowanym origin/regionie; (7) usuń reklamy i credential przy zamknięciu.

**Wykrywanie:** BGP/RPKI/historia, tenant dostawcy, certyfikaty i identyczne zachowanie service identyfikują pulę. **Capture-resilient OPSEC:** edge przechowuje tylko regionalną tożsamość service, bez klucza operatora lub enrollmentu floty. **Monitoring:** sonduj każdy region z autoryzowanych monitorów, porównuj origin trasy i digest konfiguracji, traktuj nieoczekiwany origin jako incydent.

## Migracja QUIC i ciągłość Multipath TCP

**Mechanika:** connection ID QUIC może utrzymać sesję przez rebinding NAT lub zmianę adresu; Multipath TCP przenosi jeden strumień przez wiele subflow. Poprawiają ciągłość przy przełączaniu Wi-Fi/cellular, lecz ujawniają stare i nowe ścieżki wspólnemu peerowi i ułatwiają korelację między ścieżkami.<sup>[[27]](#references)</sup>

**Zalety:** szybsze odzyskiwanie po zmianie uplinku; brak restartu sesji aplikacji; MPTCP łączy odporność i przepustowość; użyteczne dla zatwierdzonych field node.

**Wady:** brak anonimowości; peer widzi migrację/subflow; connection ID i równoczesny ruch łączą ścieżki; różne wsparcie middlebox/carrier; dodatkowe rekordy dostawców zwiększają ekspozycję.

**Procedura:** (1) włącz obsługiwany transport wyłącznie między własnym klientem polowym a rendezvous; (2) uwierzytelnij aplikację niezależnie od IP; (3) rozpocznij ograniczony transfer przez zatwierdzone Wi-Fi; (4) przełącz na cellular organizacji; (5) potwierdź validation ścieżki, integralność danych i brak jawnego/direct fallback; (6) przetestuj timeout i powrót; (7) zachowaj w brokerze każdą zmianę ścieżki.

**Wykrywanie:** peer bezpośrednio obserwuje migrację adresu/subflow MPTCP; dostawcy widzą swoje części; connection ID, tożsamość TLS i czas łączą obie ścieżki. **Capture-resilient OPSEC:** przechowuj tylko materiał sesji per-device i szybko wygaszaj resumable state. **Monitoring:** alarmuj przy niemożliwych zmianach ścieżki, jednoczesnych niezatwierdzonych sieciach, migration storms i wznowieniu po revocation.

## Egress zarządzanego CI/CD lub ephemeral automation runner

**Mechanika:** własny workflow organizacji wykonuje ograniczony check sieciowy na hosted runnerze. Cel widzi adres cloud runnera, a platforma zachowuje repozytorium, aktora, workflow, token, logi i płatność. To zdalne wykonanie z rozliczalnym egress, nie anonimowość wobec dostawcy.<sup>[[28]](#references)</sup>

**Zalety:** czyste jednorazowe środowisko; powtarzalna definicja joba; brak połączenia inbound; geograficznie rozproszone testy dostępności; silny audyt kontrolera.

**Wady:** platforma i organizacja identyfikują inicjatora; szerokie tokeny workflow i niezaufane pull requesty są niebezpieczne; współdzielona reputacja IP; logi/artifacts mogą przechowywać sekrety lub dane celu.

**Procedura:** (1) utwórz prywatne repozytorium i środowisko organizacji; (2) zezwól tylko na ręcznie zatwierdzone, stałe nieszkodliwe joby wobec własnych endpointów; (3) użyj minimalnych read-only uprawnień workflow i bez sekretów produkcyjnych; (4) uruchom check; (5) porównaj workflow, provider i target records; (6) sprawdź brak credential w artifacts; (7) usuń token środowiska i zachowaj wymagany audyt.

**Wykrywanie:** audyt dostawcy i logi workflow zapewniają atrybucję; cele identyfikują ASN/ranges runnerów i stałą gramatykę żądań. **Capture-resilient OPSEC:** nigdy nie umieszczaj sekretów field-device, signing, wallet ani cloud-admin w zmiennych runnera. **Monitoring:** wymagaj zatwierdzenia branch/environment i alarmuj przy edycji workflow, wykonaniu fork, odczycie sekretów i nieoczekiwanych celach.

## Lokalny pierwszy hop non-IP do własnego gateway

**Mechanika:** Bluetooth mesh, Wi-Fi Aware/Direct, radio low-power lub łącze serial/optical przenosi ograniczone wiadomości z pobliskiego sensora do zatwierdzonego gateway Internet. Field device nie ma trasy Internet; gateway jest jedynym egress. Zasięg i ograniczenia radia czynią z tego telemetrię/store-and-forward, nie interaktywny anonimowy Internet.

**Zalety:** usunięcie stosu Internet i credential z najmniejszego urządzenia; niski pobór energii; centralna polityka gateway; możliwość przejścia przez czasowe martwe strefy.

**Wady:** RF/fizyczne discovery, pairing i identyfikatory urządzeń; mały bandwidth/zasięg; gateway nadal łączy wszystkie wiadomości; ograniczenia spectrum/szyfrowania; przejęcie może ujawnić kolejkę.

**Procedura:** (1) uzyskaj zgodę lokalizacji i spectrum; (2) sparuj jeden własny sensor z jednym gateway przez unikalne klucze; (3) zdefiniuj podpisane wiadomości o stałym rozmiarze, TTL i rate; (4) nie dawaj sensorowi domyślnej trasy IP; (5) pozwól gateway przekazywać wyłącznie do własnego collectora; (6) przetestuj replay, utratę zasięgu i awarię gateway; (7) zinwentaryzuj i odbierz oba urządzenia.

**Wykrywanie:** badanie RF, baza pairing, inspekcja fizyczna i logi procesu/flow gateway ujawniają ścieżkę. **Capture-resilient OPSEC:** sensor przechowuje wyłącznie klucz pairwise i ograniczoną szyfrowaną kolejkę, nigdy credential operatora, Wi-Fi, cellular ani kontrolera. **Monitoring:** alarmuj przy nowych peerach, cofnięciu sequence, błędzie klucza, nietypowym rate RF i wiadomościach przez niezarejestrowany gateway.

## Macierz ekspozycji na przejęcie/kompromitację

Tabela stosuje kontrolę capture-resilience do każdej powyższej rodziny. „Minimalizuj” oznacza ograniczenie sekretów i blast radius na autoryzowanych zasobach; nigdy nie oznacza usuwania dowodów ani ukrywania się przed dochodzeniem.

| Rodzina technik | Co może ujawnić przejęty endpoint/relay | Minimalna kontrola autoryzowana |
|---|---|---|
| NAT/CGNAT, publiczne Wi-Fi, travel router | znane sieci, historia DHCP/portalu, MAC, peer tunelu | oddzielne urządzenie organizacji; prywatny MAC; brak kont osobistych; inwentarz kontrolera |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | dostawcy/hostnames, klucze, trasy, logi i sąsiedni hop | jedna tożsamość na engagement; krótki TTL; wąskie trasy; revocation w brokerze; brak kluczy master |
| OHTTP/ODoH, MASQUE, split-provider relay | konfiguracja relay/gateway, identyfikatory aplikacji i cache żądań | minimalne identyfikatory payloadu; pin zatwierdzonej konfiguracji; ograniczony cache; ścisły brak fallbacku |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | software, bridge/onion material, stan lokalny i historia peerów | standardowy klient; oddzielne klucze service; minimalny szyfrowany stan; rotacja kompromitowanej tożsamości |
| Remote browser/VDI/jump host | token workspace, clipboard/pliki i tenant zdalny | phishing-resistant MFA; wyłączone kanały transferu; szybka revocation sesji |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/tożsamość terminala, dostawca i przybliżona lokalizacja | kontrakt organizacji; brak współlokalizacji osobistej; wąska polityka APN/overlay; runbook zawieszenia |
| Residential/cooperative proxy, ORB lab | tożsamość agenta, kontroler/następny hop, cache ruchu | wyłącznie węzły własne/za zgodą; podpisany agent; credential per-node; mapowanie uczestników u kontrolera |
| CDN/fronting, fast flux, serverless | tenant/origin/config, tokeny API, wdrożenie i płatność | dedykowany projekt; least-privilege role; krótkotrwały deploy token; centralnie zachowany audyt |
| Dead drop, pull mailbox, store-and-forward | nazwy obiektów, kolejka, cache zadań/wyników i custody | podpisane ograniczone zadania; TTL; szyfrowany cache; oddzielna tożsamość producenta; niezmienne logi |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, klucz urządzenia, ślady fizyczne | pisemna zgoda; unikalna tożsamość; brak sekretu operatora; telemetryka; revoke i odzyskanie |
| TURN, reverse overlay, dual-uplink | realm/broker, credential urządzenia, peer/trasa i profile uplink | wąska usługa outbound-only; krótkotrwały credential; oddzielne logowanie operatora; ścieżki fail-closed |
| Tymczasowe adresy IPv6 | profile, historia prefixu i stan endpointu/aplikacji | traktuj jako anti-tracking; zachowaj logi sieci; dodaj compartmentation endpointu |
| Pluggable transport/refraction lab | ustawienia bridge/brokera/decoy, stan Tor i klucze badawcze | standardowy klient lub izolowane laboratorium; brak osobistego stanu przeglądarki; brak production signaling |
| IPFS/PIR/fetcher | żądany CID/query, cache treści, token gateway/service | szyfrowany ograniczony cache; wyłącznie publiczne parametry; krótkotrwały token allowlisted service |
| Anycast/QUIC/MPTCP | węzły service, connection ID, resumable state i znane ścieżki | tylko tożsamość regionalna; krótka resumption lifetime; centralne route/session revocation |
| Managed CI/CD runner | repository, workflow, token dostawcy, logi i artifacts | least-privilege workflow; brak sekretów produkcyjnych/field/wallet; zatwierdzenie środowiska |
| Lokalny hop non-IP | radio peer, klucz pairwise, kolejka i tożsamość gateway | unikalny klucz pairwise; stała schema wiadomości; brak credential Wi-Fi/cellular/operatora |

## Monitoring możliwego discovery dla każdej rodziny dostępu

Żaden test po stronie klienta nie dowodzi, że obserwuje go obrońca lub śledczy. Monitoruj zmiany w systemach należących do engagementu, potwierdzaj je przez kontroler/klienta i zatrzymuj działanie zamiast sondować obserwatorów. Poniższe wiersze obejmują wszystkie techniki; łącz je z [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Objęte techniki | Bezpieczne sygnały po stronie kontrolera | Warunek kwarantanny/zatrzymania |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | sesja lease/portal/carrier, public tuple, zmiana BSSID/komórki/ścieżki, powiadomienie dostawcy | niezatwierdzona sieć/SIM/urządzenie, niewyjaśniona relokacja lub eskalacja dostawcy/SOC |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | uwierzytelnienie peera, stan tunelu, wycieki route/DNS, nowe zdarzenie admin/API, skarga | zduplikowany/skradziony credential, nieznany administrator, direct fallback lub egress poza zakresem |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | alokacja relay/gateway, wersja klucza/config, nieobsługiwane połączenie bezpośrednie, error/replay rate | niezgodność klucza, direct fallback, nieznany realm/peer lub notice nadużycia |
| Tor Browser, bridge, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | stan bootstrap, awaria circuit, descriptor onion/service health i własna strona canary | crossover konta osobistego, połączenie nietorowe lub przejęty klucz service |
| I2P, mixnet, GNUnet, mesh/store-forward, lokalny hop non-IP | zbiór peerów, wiek/sequence kolejki, przybycie gateway, radio association i hash treści | nieznany peer/gateway, rollback sequence, nieautoryzowana treść lub brak custody |
| Remote browser/VDI/jump host, CI/CD runner, serverless | sesja IdP, zmiana workflow/image/config, użycie tokena, artifacts/export i cloud audit | nieznane logowanie/edycja workflow, odczyt sekretu, nieoczekiwany cel lub eskalacja roli |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | inwentarz własnych nodów, DNS/edge/object access, graf kontrolera, podpis zadania i TTL | nieznany node/origin/writer, niepodpisane/powtórzone zadanie, ucieczka topologii poza lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | podpisany heartbeat, hash boot/config, stan obudowy, kontekst AP/switch, zduplikowana tożsamość | przeniesiony/otwarty node, nieoczekiwany boot/hash/path, użycie sentinel lub raport lokalizacji |
| IPv6 temporary, QUIC migration, MPTCP | delegated prefix, connection ID/subflow, validation ścieżki i sesja brokera | niemożliwa migracja, jednoczesne niezatwierdzone ścieżki lub wznowienie po revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, zmiana peer/gateway, redirect/allowlist denial | nieoczekiwany pin/query/cel, niepodpisany root zbioru lub notice dostawcy |
| Refraction/decoy lab, anycast rendezvous | własna decyzja diversion, przybycie proxy, origin BGP/RPKI, regionalny digest konfiguracji | sygnał przez production path, nieznany origin trasy, niespójność regionu/config |

## Wybór i testowanie ścieżki

1. Nazwij obserwatora, którego chcesz usunąć, oraz dane, które chcesz ukryć.
2. Wybierz najmniej złożoną rodzinę usuwającą tego obserwatora.
3. Narysuj obserwatorów źródła, wejścia, tranzytu, wyjścia, DNS, konta i płatności.
4. Użyj oddzielnej tożsamości endpointu/aplikacji.
5. Zweryfikuj IPv4, IPv6, DNS, WebRTC/bypass aplikacji i widok celu.
6. Zerwij każdy hop i potwierdź zamkniętą awarię.
7. Porównaj logi każdego kontrolowanego komponentu.
8. Zapisz pozostałe powiązania czasowe, dostawcy, endpointu i fizyczne.

## References

- [1] [EFF — Wybór odpowiedniego dla Ciebie VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Ochrona Tor](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Odblokowywanie Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Używanie Tor Browser z VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Przegląd onion services](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Model zagrożeń](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Model zagrożeń](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonimowe udostępnianie plików](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — Bezpieczeństwo iCloud Private Relay](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Obowiązkowa rejestracja SIM](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — Aktorzy szpiegowscy powiązani z Chinami używają sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — Atak Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: Persistence NAT i Firewall Traversal](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Rozszerzenia adresów tymczasowych dla bezstanowej autokonfiguracji adresów IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports i bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — badania projektu i wdrożenia](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — Koncepcje HTTP Gateway i cykl życia żądania](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Przegląd Private Information Retrieval](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Działanie usług Anycast](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — Migracja połączenia QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — Dokumentacja GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
