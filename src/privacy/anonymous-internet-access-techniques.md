# Katalog technik anonimowego dostępu do Internetu

{{#include ../banners/hacktricks-training.md}}

To kanoniczny katalog ścieżek dostępu. Obejmuje **rodziny** protokołów i działań operacyjnych, a nie nazwy wszystkich dostawców. Żadna ścieżka internetowa nie gwarantuje anonimowości: dane konta, przeglądarka, endpoint, czas, płatności, cloud-control-plane i dowody fizyczne mogą ujawnić użytkownika nawet przy pozornie idealnej trasie.

Każdy wpis używa tych samych pól. „Procedura” oznacza zgodne z prawem wdrożenie lub emulację we własnym laboratorium. Gdy rzeczywista technika zależy od przejęcia routera, kradzieży dostępu lub wykorzystania niechętnego pośrednika, reprodukcja zastępuje te elementy systemami należącymi do ćwiczenia.

## Macierz pokrycia

| Rodzina | Co widzi cel | Najsilniejsza właściwość | Szybkość | Sposób użycia |
|---|---|---|---|---|
| Współdzielony NAT/CGNAT | współdzielony adres publiczny | niejednoznaczność między abonentami | wysoka | możliwe do wdrożenia |
| VPN, VPS, SOCKS/HTTP/SSH proxy | adres przekaźnika | szybkie oddzielenie adresu źródłowego | wysoka | możliwe do wdrożenia |
| Multi-hop/split relay, MASQUE | końcowy proxy | podział wiedzy lub pełny tunel IP | wysoka/umiarkowana | możliwe z zaufanymi przekaźnikami |
| Tor, bridge, onion service | exit lub tożsamość onion | ścieżka wielostronna i wspólna przeglądarka | umiarkowana | możliwe do wdrożenia |
| I2P, GNUnet, mixnet | peer/gateway overlay | overlay lub odporność na analizę czasu | niska/zmienna | zależne od aplikacji |
| OHTTP/ODoH, Private Relay | gateway/egress | podział źródła i żądania | wysoka | tylko obsługiwane aplikacje |
| Publiczne Wi-Fi, travel router | adres lokacji/tunelu | zmiana lokalizacji/ścieżki dostępu | wysoka | wymagana zgoda |
| Cellular/eSIM, satellite | adres operatora/dostawcy | niezależne fizyczne łącze | wysoka/zmienna | operator widzi subskrypcję |
| Remote browser/jump host | zdalne workspace | oddzielenie endpointu i egress | wysoka | możliwe do wdrożenia |
| Residential/mobile proxy | adres sieci konsumenckiej/operatora | wygląd sieci konsumenckiej | wysoka | kluczowa zgoda/proweniencja |
| ORB/compromised relay | adres innej ofiary | ukrycie źródła i pożyczona reputacja | wysoka | tylko reprodukcja w laboratorium |
| CDN/fronting/redirector | adres CDN/front | ochrona infrastruktury back-end | wysoka | wymagana zgoda dostawcy/właściciela |
| Fast flux/DGA/dead drop | zmienny węzeł/usługa | odporność na rozpoznanie infrastruktury | zmienna | tylko reprodukcja we własnym laboratorium |
| Drop/nearest-neighbor | adres sąsiadujący z celem | przekroczenie granicy geograficznej/sieciowej | wysoka | tylko laboratorium właściciela |
| Store-and-forward/offline | gateway lub odbiorca fizyczny | ograniczenie interaktywnego powiązania czasowego | niska | zależne od aplikacji |
| Pluggable/refraction transport | wejście Tor lub współpracujący proxy | dostęp odporny na cenzurę | zmienna | obsługiwany klient lub laboratorium badawcze |
| IPFS gateway/PIR/remote fetcher | gateway lub usługa aplikacji | podział wydawcy/zapytania/żądania | zmienna | tylko ograniczone zastosowania |
| Anycast/QUIC/MPTCP | stabilny broker lub wiele podstrumieni | rendezvous i ciągłość sesji | wysoka | dostępność, nie anonimowość |
| CI/CD automation runner | adres hosted runnera | rozliczalny, jednorazowy egress | wysoka | tylko własny workflow |
| Non-IP local first hop | gateway organizacji | usunięcie stosu Internetu z sensora | niska | wdrożenie za zgodą właściciela |

## Bezpośredni współdzielony NAT i carrier-grade NAT

**Mechanika:** wielu użytkowników współdzieli jeden adres publiczny; dostawca mapuje adresy i porty abonentów na publiczną krotkę.

**Zalety:** szybkość; brak specjalnego klienta; sam adres IP po stronie celu może wskazywać tylko gospodarstwo domowe, lokal lub pulę operatora.

**Wady:** dostawca może zachowywać mapowania abonenta/portu/czasu; konta i fingerprinty pozostają; inni użytkownicy mogą pogorszyć reputację adresu.

**Procedura:** (1) potwierdź, czy autoryzowany dostęp używa NAT/CGNAT; (2) zapisz dokładny publiczny IP i port źródłowy w posiadanym endpoint; (3) oddziel tożsamości aplikacji; (4) nie traktuj współdzielenia adresu jako mechanizmu prywatności; (5) użyj silniejszej ścieżki, jeśli ISP nie powinien znać celów.

**Wykrywanie:** cele powinny zachowywać port źródłowy i dokładny czas, nie tylko IP. Dostawcy korelują logi alokacji NAT; śledczy łączą dane kont, urządzeń i przeglądarek.

## Commercial VPN

**Mechanika:** zaszyfrowane połączenie full-tunnel kończy się w VPN; cele widzą jego egress. VPN zwykle może powiązać źródło, czas i cele.

**Zalety:** szybkość; prostota; ochrona przed lokalną obserwacją pasywną; stabilne lub współdzielone exit; dobre dla kontrolowanego egress red-team.

**Wady:** skoncentrowane zaufanie; telemetria płatności/logowania; awarie kill-switch/DNS/IPv6; współdzielone exit są często blokowane przez reputację.

**Procedura:** (1) ustal dostawcę, właściciela, jurysdykcję, retencję i politykę oceny; (2) zainstaluj podpisanego oficjalnego klienta; (3) włącz full tunnel, always-on i fail-closed; (4) świadomie skonfiguruj DNS i IPv6; (5) sprawdź obserwowane IPv4/IPv6/DNS w posiadanym endpoint; (6) zatrzymaj/połącz ponownie tunel i potwierdź brak jawnego fallbacku.<sup>[[1]](#references)</sup>

**Wykrywanie:** sieci lokalne widzą długi zaszyfrowany przepływ do infrastruktury VPN; dostawcy mają logi uwierzytelniania i połączeń; cele używają ASN/reputacji oraz korelacji konta, TLS, przeglądarki i zachowania.

## Self-hosted VPN lub egress z wynajętego VPS

**Mechanika:** operator kontroluje gateway WireGuard/OpenVPN lub przekazuje ruch przez wynajęty serwer.

**Zalety:** przewidywalna szybkość; stały adres do allowlisty; własne logowanie/firewall; dobra kontrola incydentów.

**Wady:** mały zbiór anonimowości; tenant cloud, płatności, logowanie źródłowe, API i historia obrazu wiążą operatora; nowy, charakterystyczny serwer łatwo grupować.

**Procedura:** (1) utwórz projekt organizacji dla konkretnego engagement; (2) uruchom obsługiwany image i stały adres; (3) ogranicz administrację do MFA/kluczy; (4) skonfiguruj full-tunnel egress i DNS; (5) ogranicz cele do zakresu, gdy praktyczne; (6) przetestuj leak i zachowanie przy awarii; (7) zachowaj audit controller; (8) usuń dane uwierzytelniające i zasoby podczas teardown.

**Wykrywanie:** koreluj ASN hostingu, adres first-seen, fingerprint certyfikatu/usługi i skanowanie; właściciele cloud używają logów control-plane, konsoli, płatności i przepływów.

## HTTP CONNECT, SOCKS i przekierowanie SSH

**Mechanika:** aplikacja prosi proxy o otwarcie strumienia TCP; SOCKS może także przekazywać rozwiązywanie nazw i UDP zależnie od wersji; SSH przekazuje strumienie w jednej zaszyfrowanej sesji.

**Zalety:** lekkość; per-application; szybkość; przydatność do łańcuchów i sieci segmentowanych.

**Wady:** aplikacje mogą go ominąć; DNS może leak; proxy widzi sąsiednie endpointy; stan przeglądarki pozostaje; otwarte proxy mogą być pułapkami lub przejętymi systemami.

**Procedura:** (1) wdroż proxy na własnym hoście; (2) wymagaj uwierzytelniania i ogranicz źródło/cel; (3) skonfiguruj jeden jednorazowy profil aplikacji; (4) zapewnij zdalne rozwiązywanie DNS, gdy potrzebne; (5) zweryfikuj je przez własny endpoint DNS/HTTP; (6) zablokuj bezpośredni egress workloadu; (7) sprawdź i rotuj dane proxy.

**Wykrywanie:** identyfikuj procesy obsługujące tunele, negocjację CONNECT/SOCKS, długie sesje SSH i cele niezgodne z aplikacją; logi proxy odtwarzają strumienie.

## Web proxy przepisujący URL i browser proxy extension

**Mechanika:** witryna pobiera cel i przepisuje linki/formularze przez własne origin albo extension kieruje żądania przeglądarki do proxy. Cel widzi usługę, która może widzieć plaintext po zakończeniu TLS oraz wstrzykiwać lub zachowywać treści.

**Zalety:** brak klienta systemowego; szybkość prostego przeglądania; działa, gdy instalacja VPN jest niemożliwa.

**Wady:** proxy może czytać dane logowania/treści, przepisywać downloady i fingerprintować użytkowników; skrypty/WebSockets/downloady mogą omijać proxy; extension ma szerokie uprawnienia; mały zbiór anonimowości i częste blokady.

**Procedura:** (1) używaj wyłącznie proxy organizacji do autoryzowanych testów; (2) odizoluj je w jednorazowej przeglądarce bez kont osobistych; (3) zabroń wpisywania haseł i wrażliwych downloadów; (4) sprawdź, czy każdy subresource na własnej stronie przechodzi przez proxy; (5) przetestuj WebSocket, download i formularze; (6) usuń extension/profil po użyciu.

**Wykrywanie:** cel loguje proxy; proxy/DNS przedsiębiorstwa i inwentarz extension identyfikują usługę; CSP/reporting lub własne canary subresources ujawniają bezpośredni bypass; logi proxy mapują sesję użytkownika na cele.

## Multi-hop proxy lub multi-hop VPN dostawcy

**Mechanika:** wejście widzi źródło, a jeden lub więcej relay oddziela je od exit widzącego cel.

**Zalety:** zwykły relay nie musi znać obu końców; awaria/przejęcie jednego węzła ujawnia mniej; elastyczna geografia.

**Wady:** wspólna administracja/logi niwelują podział; opóźnienia; korelacja czasowa; więcej awarii i tras DNS; to samo konto/płatność może połączyć każdy hop.

**Procedura:** (1) określ, którego obserwatora usuwa każdy hop; (2) użyj niezależnie zarządzanych, własnych/zatwierdzonych relay, gdy separacja ma znaczenie; (3) wymuś dostęp tylko do wejścia z workloadu; (4) zapewnij, że każdy relay dociera tylko do następnego; (5) sprawdź logi na każdej warstwie; (6) zatrzymaj każdy hop i potwierdź fail-closed. Odtwórz przez [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Wykrywanie:** koreluj czas/objętość sąsiednich NetFlow, powtarzające się handshake proxy i wspólną infrastrukturę controller; nie wyciągaj geografii operatora z exit.

## Relay aplikacyjny z podziałem wiedzy i OHTTP

**Mechanika:** klient szyfruje bezstanową wiadomość HTTP do gateway i wysyła ją przez relay. Relay widzi IP klienta, ale nie żądanie; gateway widzi żądanie, lecz zwykle tylko IP relay.

**Zalety:** silny, audytowalny podział prywatności dla obsługiwanych żądań; mniejszy narzut niż ogólne sieci anonimowe.

**Wady:** nie obsługuje dowolnego przeglądania; cookies/authentication mogą ponownie wiązać; koluzja relay/gateway i analiza ruchu pozostają; aplikacja musi to implementować.

**Procedura:** (1) wybierz aplikację jawnie obsługującą RFC 9458; (2) zweryfikuj klucze gateway przez oficjalną konfigurację; (3) unikaj stabilnych pól użytkownika; (4) wysyłaj tylko obsługiwane żądanie bezstanowe; (5) porównaj logi relay, gateway i celu; (6) przetestuj rotację kluczy/awarię bez bezpośredniego fallbacku.<sup>[[2]](#references)</sup>

**Wykrywanie:** endpointy ujawniają proces inicjujący i OHTTP relay; gateway wykrywa uszkodzony/replayowany ruch; czas oraz stabilne pola payload/account mogą korelować żądania.

## MASQUE CONNECT-UDP/CONNECT-IP i HTTP privacy proxies

**Mechanika:** HTTP Extended CONNECT przez TLS/QUIC przenosi pakiety UDP lub IP przez proxy. Może realizować nowoczesny tunel podobny do VPN i mieszać transport z HTTP/3, lecz proxy pozostaje obserwatorem.<sup>[[3]](#references)</sup>

**Zalety:** wydajne multiplexing/roaming; obsługa UDP lub pełnego IP; wdrożenie przez nowoczesną infrastrukturę HTTP.

**Wady:** nie jest siecią anonimową; proxy/konto widzi źródło i cele; fingerprinty QUIC/HTTP i znane ścieżki są widoczne dla endpointów/dostawców.

**Procedura:** (1) użyj klienta/usługi dokumentujących RFC 9298/9484; (2) uwierzytelnij certyfikat/konfigurację proxy; (3) zdefiniuj dozwolone trasy celów; (4) włącz encrypted DNS wewnątrz ścieżki; (5) zweryfikuj UDP, TCP, IPv6 i failover wobec własnych endpointów; (6) sprawdź logi żądań i przepływów proxy.

**Wykrywanie:** endpointy widzą proces klienta i virtual interface; sieci mogą klasyfikować stały QUIC/TLS do proxy; logi proxy ujawniają cel/ścieżkę CONNECT i przydzielone trasy.

## Tor Browser

**Mechanika:** Tor wybiera guard, middle i exit relay; warstwowe szyfrowanie ogranicza widok każdego relay. Tor Browser dodaje ustandaryzowaną przeglądarkę odporną na fingerprinting.

**Zalety:** duży publiczny zbiór anonimowości; żaden zwykły relay nie zna obu końców; unlinkability celu bez prowadzenia serwerów.

**Wady:** wolniejszy; głównie TCP; reputacja/blokady exit; logowania i ujawnienia identyfikują użytkownika; pozostaje korelacja czasowa low-latency.

**Procedura:** (1) pobierz i zweryfikuj Tor Browser z projektu; (2) pozostaw ustawienia domyślne i unikaj extension; (3) wybierz właściwy security level; (4) utwórz oddzielną tożsamość/sesję; (5) unikaj identyfikujących kont i zewnętrznych aktywnych dokumentów; (6) używaj HTTPS lub uwierzytelnionych onion services; (7) weryfikuj exit tylko własnym endpointem.<sup>[[4]](#references)</sup>

**Wykrywanie:** sieci lokalne mogą rozpoznać znany ruch guard, jeśli nie użyto bridge/transport; cele widzą exit i zachowanie Tor Browser; obserwatorzy end-to-end korelują czas/objętość.

## Tor bridges i pluggable transports

**Mechanika:** niepubliczny bridge zastępuje publiczny guard; obfs4, Snowflake lub WebTunnel zmieniają transport pierwszego hopu, aby utrudnić proste blokowanie/sondowanie.

**Zalety:** omija cenzurę i ukrywa oczywiste cele publicznych relay; po wejściu zachowuje circuit Tor.

**Wady:** możliwe rozpoznanie wzorców transportu/bridge; zmienna wydajność; nie chroni przed kontami ani globalną analizą czasu.

**Procedura:** (1) najpierw spróbuj bezpośredniego Tor; (2) w ustawieniach Connection Tor Browser wybierz wbudowany obsługiwany transport lub poproś o oficjalny bridge; (3) nie używaj przypadkowych binariów/list; (4) połącz się i wykonaj benign test; (5) przetestuj ponowne połączenie i zegar; (6) pozostaw pozostałe ustawienia przeglądarki standardowe.<sup>[[5]](#references)</sup>

**Wykrywanie:** cenzorzy używają rozpoznania celu, klasyfikacji protokołu/przepływu i aktywnego sondowania; obrońcy powinni odróżniać użycie obejścia od kompromitacji i opierać się na procesie/kontekście endpointu.

## VPN przed Tor i Tor przed VPN

**Mechanika:** VPN-before-Tor ukrywa bezpośrednie użycie Tor przed ISP dostępu, lecz ujawnia źródło VPN. Tor-before-VPN daje VPN ruch po Tor i często stabilną tożsamość klienta/tunelu.

**Zalety:** usuwa określonego obserwatora, jeśli jest poprawnie zaprojektowane; może docierać do sieci blokujących jedną warstwę.

**Wady:** złożoność, nietypowy fingerprint, leaki, mniejszy zbiór anonimowości i fałszywa pewność; Tor Project traktuje te kombinacje jako zaawansowane.<sup>[[6]](#references)</sup>

**Procedura:** (1) zapisz usuwanego i wprowadzanego obserwatora; (2) użyj jednorazowego środowiska; (3) ustanów tylko zamierzoną ścieżkę zewnętrzną; (4) wymuś trasy firewall; (5) zweryfikuj DNS/IPv4/IPv6 i kolejność każdej awarii; (6) porównaj widoczność obu dostawców; (7) porzuć stos, jeśli nie daje mierzalnej korzyści.

**Wykrywanie:** obserwatorzy lokalny/VPN/Tor widzą różne sąsiednie warstwy; czas pozostaje end-to-end; nietypowe fingerprinty zagnieżdżonych tuneli i konta dostawców mogą łączyć sesje.

## Onion service

**Mechanika:** klient i usługa budują circuits Tor do rendezvous, ukrywając IP usługi i unikając exit.

**Zalety:** ochrona źródła i lokalizacji usługi; uwierzytelnianie onion end-to-end; brak publicznego portu wejściowego; opcjonalna autoryzacja klienta.

**Wady:** origin może leak przez aktualizacje/analytics/błędy; klucz onion jest krytyczny; tożsamość aplikacji, czas i kompromitacja hosta pozostają.

**Procedura:** (1) odizoluj aplikację i zwiąż ją tylko z loopback/socket; (2) zainstaluj obsługiwany Tor; (3) skonfiguruj v3 onion service według oficjalnych instrukcji; (4) chroń/backupuj klucz tylko, jeśli potrzebna jest stała tożsamość; (5) dodaj autoryzację klienta do użycia zamkniętego; (6) usuń third-party fetches; (7) zewnętrznie potwierdź brak dostępności origin.<sup>[[7]](#references)</sup>

**Wykrywanie:** obrońcy hosta/sieci znajdują proces/konfigurację Tor i outbound circuits; błędy aplikacji, DNS, certyfikaty lub zasoby zewnętrzne mogą ujawnić origin.

## I2P internal services

**Mechanika:** I2P używa osobnych jednokierunkowych tuneli wejściowych/wyjściowych dla destination wewnątrz overlay; outproxy do publicznego Internetu dodaje punkt zaufania.

**Zalety:** zdecentralizowane publikowanie wewnętrzne; brak zależności od oficjalnego exit; oddzielne ścieżki wejścia/wyjścia.

**Wady:** nie zastępuje ogólnej sieci web; mniejszy ekosystem; długotrwałe zachowanie peerów; outproxy może obserwować publiczne przeglądanie.

**Procedura:** (1) zainstaluj z oficjalnego źródła; (2) użyj odrębnego kontekstu; (3) pozwól na stabilizację integracji/przepustowości; (4) uzyskaj dostęp do własnej usługi I2P; (5) unikaj outproxy, chyba że jest wymagany; (6) sprawdź, czy shutdown nie daje bezpośredniego fallbacku; (7) sprawdź lokalne logi peer/service.<sup>[[8]](#references)</sup>

**Wykrywanie:** sieci lokalne widzą długotrwały ruch peer i bootstrap; endpointy ujawniają procesy router/application; outproxy logują exit.

## Mixnets

**Mechanika:** pakiety o stałym rozmiarze, batching, opóźnienia, zmiana kolejności i cover traffic ograniczają korelację czasową; gateway łączą aplikacje.

**Zalety:** większa odporność na analizę czasu niż proxy low-latency; przydatne dla asynchronicznych wiadomości/transakcji.

**Wady:** opóźnienia, narzut przepustowości, mniejsze wdrożenie i ograniczenia aplikacji; metadane gateway/account mogą zostać.

**Procedura:** (1) wybierz utrzymywanego klienta i obsługiwaną aplikację; (2) przeczytaj rzeczywisty threat model; (3) zainstaluj w osobnym compartment; (4) wyślij benign dane do własnego endpointu; (5) zmierz opóźnienie/niezawodność i ścieżkę odpowiedzi; (6) przetestuj awarię gateway; (7) nigdy nie wyłączaj opóźnień/cover traffic wyłącznie dla szybkości.<sup>[[9]](#references)</sup>

**Wykrywanie:** endpointy identyfikują klienta; sieci dostępu mogą klasyfikować gateway/rytm pakietów; gateway i exit widzą role sąsiednie, a szersza korelacja wymaga dłuższych okien statystycznych.

## GNUnet anonymous file sharing

**Mechanika:** GNUnet może kierować żądania publikacji/wyszukiwania/pobierania przez peer i dodawać cover traffic zgodnie z poziomem anonimowości. Dokumentacja ostrzega, że domyślny poziom 1 nie wymaga cover traffic, a silna analiza ruchu może wskazać źródło.<sup>[[10]](#references)</sup>

**Zalety:** zdecentralizowane, natywne dla aplikacji anonimowe udostępnianie; regulowany wymóg cover traffic.

**Wady:** nie jest zwykłym anonimowym dostępem web; koszt wydajności/pamięci; ograniczenia peerów i analizy ruchu; dokumentacja GNUnet VPN mówi, że overlay IP nie zapewnia dobrej anonimowości.

**Procedura:** (1) zainstaluj utrzymywaną oficjalną wersję; (2) odizoluj testowego peer; (3) ogranicz bandwidth/storage; (4) opublikuj nieszkodliwy, unikalny plik testowy z wybranym poziomem anonimowości; (5) pobierz go z innego własnego peer; (6) zapisz cover traffic i opóźnienie; (7) nie twierdź, że komponent IP VPN zapewnia równoważną anonimowość.

**Wykrywanie:** bootstrap peer, ruch overlay, lokalny datastore/proces i identyfikatory plików; szeroki obserwator może analizować objętość względem cover traffic.

## Encrypted DNS, ODoH i ECH

**Mechanika:** DoH/DoT/DoQ szyfrują połączenie z resolverem; ODoH dzieli adres klienta i query między proxy a resolverem; ECH szyfruje wewnętrzny TLS ClientHello/nazwę serwera.

**Zalety:** usuwa plaintext DNS/SNI przed częścią lokalnych obserwatorów; ODoH dzieli wiedzę o źródle i query.

**Wady:** nie jest ścieżką anonimowości IP; resolver/proxy/server zachowują swoje role; IP celu, czas, objętość i endpoint pozostają; fallback może leak.

**Procedura:** (1) wybierz, czy DNS kontroluje OS, aplikacja czy tunel; (2) włącz strict encrypted mode lub obsługiwany ODoH; (3) przetestuj unikalną własną domenę; (4) wykonaj lokalny capture, aby potwierdzić brak jawnego query; (5) wyłącz resolver i sprawdź zamierzone zachowanie; (6) dla ECH potwierdź w diagnostyce serwera akceptację inner ClientHello.<sup>[[11]](#references)</sup>

**Wykrywanie:** logi endpointu/resolvera ujawniają query; sieci identyfikują endpointy encrypted resolver i przepływy celu; stan ECH jest widoczny na endpointach/CDN, nawet gdy jest ukryty na ścieżce.

## Split-provider privacy relay

**Mechanika:** produkty takie jak iCloud Private Relay używają ingress znającego klienta i niezależnie obsługiwanego egress znającego cel, z przybliżonym regionem.

**Zalety:** łatwy podział wiedzy; szybkość; zintegrowana ochrona DNS/web dla obsługiwanego ruchu.

**Wady:** ograniczony zakres produktu/aplikacji; dostawca platformy nadal identyfikuje klienta; brak ogólnej anonimowości systemowej; ryzyko koluzji/prawne i czasowe.

**Procedura:** (1) potwierdź dokładne obsługiwane aplikacje i typy ruchu; (2) włącz funkcję w dedykowanym kontekście platformy, jeśli właściwe; (3) wybierz zachowanie regionu; (4) osobno przetestuj Safari/DNS i nieobsługiwane aplikacje; (5) sprawdź adres celu; (6) przetestuj zmianę sieci/awarię.<sup>[[12]](#references)</sup>

**Wykrywanie:** dostęp widzi ingress; cel widzi egress; logi platformy/relay i dane kont obejmują odpowiednie warstwy; nieobsługiwane aplikacje ujawniają zwykłe ścieżki.

## Remote browser, VDI, RDP lub organization jump host

**Mechanika:** przeglądanie/wykonywanie narzędzi odbywa się w systemie zdalnym; cel widzi jego egress, a dostawca workspace widzi połączenie operatora i control plane.

**Zalety:** szybkość; izolacja ryzykownych treści; stabilny kontrolowany egress; jednorazowy stan i silny audyt organizacji.

**Wady:** dostawca/admin może obserwować sesję/konto; kanały ekranu/schowka/plików mogą leak; fingerprint zdalnej przeglądarki może być unikalny; brak anonimowości wobec właściciela workspace.

**Procedura:** (1) utwórz jeden workspace należący do organizacji dla każdego engagement; (2) wymagaj MFA i ogranicz administrację; (3) wyłącz lub ogranicz clipboard/upload/download; (4) kieruj ruch przez zatwierdzony stały egress; (5) nie używaj osobistego IdP/sync; (6) eksportuj tylko sprawdzone dowody; (7) usuń workspace i dane uwierzytelniające zgodnie z harmonogramem.

**Wykrywanie:** logi dostawcy i IdP mapują użytkownika na sesję; cele grupują egress/workspace/browser; obrońcy przedsiębiorstwa identyfikują remote-control protocols i anomalne sesje cloud.

## Publiczne lub gościnne Wi-Fi

**Mechanika:** ruch wychodzi przez NAT lokalu albo tunel uruchomiony w tym miejscu.

**Zalety:** duża szybkość i współdzielony adres spoza domu; brak dedykowanej infrastruktury.

**Wady:** dowody lokalu/DHCP/portalu, kamer, zakupu i lokalizacji; wrogie peer/AP; regulaminy; ryzyko fizyczne.

**Procedura:** (1) uzyskaj dostęp oferowany gościom i potwierdź SSID z personelem; (2) użyj zaktualizowanego urządzenia low-trust; (3) wyłącz sharing/auto-join i włącz private MAC; (4) ukończ portal bez ponownie używanej tożsamości; (5) uruchom fail-closed VPN/Tor; (6) sprawdź ruch tethered; (7) zapomnij sieć.

**Wykrywanie:** lokal koreluje AP, MAC, DHCP, portal i czas; cel widzi lokal/tunel; śledczy łączą dowody fizyczne i urządzenie. Nigdy nie omijaj kontroli dostępu.

## Travel router

**Mechanika:** należący do operatora router łączy się z Wi-Fi/Ethernet lokalu i zapewnia izolowaną sieć wewnętrzną z wymuszoną polityką tunelu.

**Zalety:** izoluje workstations; centralny kill switch/DNS; spójna sieć klienta; chroni uprzywilejowane endpointy przed lokalnymi broadcastami.

**Wady:** router staje się stabilnym fingerprintem radiowym/DHCP; dodaje powierzchnię ataku; captive portal i tethering mogą ominąć tunel.

**Procedura:** (1) zaktualizuj obsługiwany firmware; (2) ustaw unikalne dane administracyjne i wyłącz WAN admin/WPS/UPnP; (3) skonfiguruj prywatny upstream MAC, jeśli dozwolony; (4) utwórz osobne SSID wewnętrzne; (5) wymuś full-tunnel DNS/IPv6 firewall policy; (6) przetestuj portal, reconnect i awarię tunelu.

**Wykrywanie:** lokal widzi skojarzenie routera i kształt ruchu; fingerprinting RF/DHCP identyfikuje urządzenie; dostawca VPN widzi źródło lokalu.

## Cellular, prepaid SIM i eSIM

**Mechanika:** modem używa dostępu radiowego operatora i zwykle carrier NAT; warstwa VPN/Tor może zmienić exit widziany przez cel.

**Zalety:** niezależność od lokalnej sieci przewodowej/Wi-Fi; mobilność; szybkość; przydatny backhaul dla autoryzowanych dropów.

**Wady:** operator zna abonenta/eSIM, IMSI, IMEI, komórki, czas i przydzielone porty; przepisy rejestracyjne są różne; współlokacja z osobistym telefonem wiąże urządzenia.

**Procedura:** (1) uzyskaj usługę zgodnie z prawem i podaj wymagane prawdziwe dane; (2) użyj osobnego modemu/urządzenia organizacji; (3) zarejestruj je u controller ćwiczenia; (4) wyłącz niepowiązane radia/konta; (5) ustanów zatwierdzony tunel; (6) sprawdź, czy klienci tethered faktycznie z niego korzystają; (7) przed podróżą zweryfikuj założenia dostawcy i retencji.<sup>[[13]](#references)</sup>

**Wykrywanie:** logi operatora i lokalizacja RF; inwentarz USB/PCI/MDM przedsiębiorstwa i skany rogue-hotspot; czas tunelu/celu.

## Satellite Internet i nadużycie satellite downlink

**Mechanika:** zwykła usługa używa zarejestrowanego terminala/operatora. Dawne nadużycie jednokierunkowego DVB-S pozwalało odbiornikowi w wiązce obserwować niezaszyfrowany downlink skierowany do prawidłowego abonenta, przy użyciu innej ścieżki dla żądań wychodzących.

**Zalety:** szeroki zasięg; niezależny last mile; historyczne nadużycie jednokierunkowe mogło przypisać C2 geografii abonenta.

**Wady:** sprzęt/RF/logi dostawcy; opóźnienia i zasięg; współczesne systemy bidirectional są inne; ścieżka outbound i asymetryczny routing pozostają dowodem.

**Procedura:** dla zgodnego z prawem dostępu zarejestruj własny terminal i tuneluj ruch zgodnie z wymaganiami. Aby emulować historyczne zachowanie Turla, odtwórz syntetyczne packet captures jednokierunkowo w laboratorium bez RF i sprawdź, czy analitycy wykryją odpowiedź hosta, który nie wysłał żądania; nie przechwytuj transmisji satelitarnych na żywo.<sup>[[14]](#references)</sup>

**Wykrywanie:** telemetria dostawcy/terminala, lokalizacja RF, niemożliwy/asymetryczny przepływ, niespójność RTT/routingu i konfiguracja malware.

## Residential/mobile proxy lub consented proxyware

**Mechanika:** backconnect gateway przydziela konsumenckie wyjścia broadband/mobile, stałe lub rotowane. Podaż może być zgodna ze zgodą, oszukańczo dołączona lub złośliwa.

**Zalety:** szybkość; wybór geograficzny; ASN konsumencki omija część blokad hostingu; duże pule.

**Wady:** ryzyko proweniencji/zgody/prawne; broker widzi klienta; zainfekowane exit szkodzą ofiarom; rotacja tworzy anomalie; rozwiązanie jest drogie i zawodne.

**Procedura:** używaj wyłącznie udokumentowanych agentów organizacji z informed consent: (1) zarejestruj testowe endpointy; (2) zinwentaryzuj właścicieli/IP; (3) skonfiguruj gateway; (4) rotuj tryby sticky/per-request; (5) wysyłaj tylko do własnego celu; (6) porównaj logi gateway/exit/celu; (7) usuń każdy agent.

**Wykrywanie:** niemożliwa podróż, stabilna przeglądarka/konto przy szybkich zmianach IP/ASN, protokoły backconnect, artefakty procesu/sieci proxyware i relacje broker/controller.

## ORB, botnet i przekaźniki przejętych urządzeń brzegowych

**Mechanika:** wynajęte lub przejęte routery/IoT/serwery tworzą role access, traversal i exit zarządzane jako flota. Może współdzielić je wielu klientów APT.

**Zalety:** pożyczona reputacja/geografia; krótkotrwałe exit; odporna siatka multi-hop; słabe bezpośrednie powiązanie actor-IP.

**Wady:** przestępcze krzywdzenie ofiar; wzorce implant/controller/floty; przejęcie pośrednika; niestabilność; dane operatora/klienta.

**Procedura:** nigdy nie przejmuj prawdziwych urządzeń. Użyj [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) utwórz izolowane sieci entry/transit/target; (2) podłącz własne dual-homed relay containers; (3) przekazuj tylko jeden testowy port; (4) wyślij benign request; (5) sprawdź, czy cel widzi tylko exit; (6) rotuj exit; (7) usuń wszystkie nazwane zasoby.<sup>[[15]](#references)</sup>

**Wykrywanie:** śledź topologię, porty/usługi, relacje controller, fingerprinty implantów i cykl życia węzłów; centralizuj telemetrię konfiguracji/przepływów/integralności; nie utożsamiaj exit IP z aktorem.

## CDN redirector, domain fronting i domainless fronting

**Mechanika:** publiczny edge przekazuje tylko ruch pasujący do gramatyki; fronting używa benign outer SNI i innego inner HTTP authority albo pustego SNI, gdy intermediary na to pozwala.

**Zalety:** ukrywa/chroni back-end; szybki globalny edge; miesza cel ze współdzieloną usługą; szybki cutover.

**Wady:** CDN widzi cały routing i tenant; wielu dostawców zakazuje cross-tenant fronting; artefakty SNI/Host/process/flow/account; ponowne użycie konfiguracji grupuje kampanie.

**Procedura:** reprodukuj wyłącznie na własnym reverse proxy przez [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): utwórz lokalny certyfikat/edge, skieruj jeden niezgodny Host do własnego celu, loguj SNI i Host, wyślij zwykłe/niezgodne żądania, następnie usuń containers.<sup>[[16]](#references)</sup>

**Wykrywanie:** porównuj SNI/ECH/Host/`:authority` na endpoint lub terminującym edge; łącz proces inicjujący, tenant/origin, gramatykę żądania i rytm przepływu.

## Dynamic DNS, DGA, fast flux i double flux

**Mechanika:** DDNS aktualizuje stałą nazwę; DGA tworzy zmienne nazwy kandydatów; fast flux rotuje adresy usług przy niskim TTL; double flux rotuje również name servers.

**Zalety:** odporność discovery; szybka wymiana infrastruktury; controller ukryty za wieloma węzłami.

**Wady:** DNS tworzy centralną telemetrię; entropy/NXDOMAIN/churn; niskie TTL i szerokie wzorce ASN; rejestracja i infrastruktura authoritative pozostają.

**Procedura:** użyj [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): obsłuż własną strefę zwracającą adresy RFC 5737 z TTL pięciu sekund, odpytuj ją wielokrotnie, zmień syntetyczną epokę i sprawdź analytics. Nigdy nie kieruj rekordów testowych do stron trzecich.<sup>[[17]](#references)</sup>

**Wykrywanie:** unikalne odpowiedzi/ASN w oknie, median TTL, geografia, churn authoritative, klastry NXDOMAIN/leksykalne/czasowe DGA i follow-on procesu; wyklucz legalne CDN z kontekstem.

## Legalna usługa web, dead-drop resolver i one-way tasking

**Mechanika:** publiczny post, repository, dokument, object lub feed zawiera zakodowany aktualny endpoint albo task. Klient może zwracać wyniki innym kanałem.

**Zalety:** dozwolona usługa o dobrej reputacji; TLS; rotacja endpointu bez zmiany binarium; asymetryczne tasking utrudnia prostą korelację przepływu.

**Wady:** stałe identyfikatory object/account/API; logi dostawcy; sekwencja decode/follow-on endpointu; treść może zostać przejęta lub zmieniona.

**Procedura:** użyj [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): umieść zakodowany pointer w jednym własnym container, pobierz/odkoduj z krótkotrwałego klienta, połącz się z drugą własną usługą, zachowaj oba logi, następnie usuń środowisko.

**Wykrywanie:** koreluj nietypowe process → odczyt stałego object → decode → nowy destination; hashuj/zachowuj treść i pełne ścieżki object, nie tylko domenę.

## Serverless, ephemeral container i cloud-NAT egress

**Mechanika:** functions/krótkotrwałe jobs działają za provider NAT lub front; logiczna usługa pozostaje stała, a instancje i adresy rotują.

**Zalety:** szybkie wdrażanie/usuwanie; współdzielony egress skali dostawcy; mało lokalnego dysku; elastyczny routing regionalny.

**Wady:** tenant, role, API, image, secret, invocation, billing i front-to-origin logs pozostają; fingerprint cold-start/platform; polityka dostawcy.

**Procedura:** (1) użyj własnego tenant organizacji; (2) wdroż benign function wykonującą żądania tylko do własnego endpointu; (3) zapisz project/role/image/config; (4) uruchom kilka instancji; (5) porównaj IP celów z audit/request IDs; (6) przetestuj retencję logów; (7) usuń function, role i secrets.

**Wykrywanie:** logi cloud audit/invocation, nietypowe tworzenie ról, współdzielony egress ze stałą gramatyką żądania, ponowne użycie image/layer/secret i korelacja front-origin.

## Authorized on-site drop

**Mechanika:** zinwentaryzowany mały komputer używa lokalnego wired/Wi-Fi i outbound VPN/cellular rendezvous, prezentując lokalne źródło.

**Zalety:** realistyczne testy origin wewnętrznego; szybkość; testowanie NAC, inwentarza fizycznego i kontroli egress.

**Wady:** wykrycie/kradzież fizyczna; dowody serial/MAC/USB/DHCP/PoE/RF i kamer; utrata może ujawnić dane logowania.

**Procedura:** postępuj według [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) uzyskaj dokładną pisemną zgodę na umieszczenie; (2) zapisz serial, MAC, zdjęcie, lokalizację i czas odbioru; (3) użyj podpisanego minimalnego image i krótkotrwałych mutual credentials; (4) ogranicz outbound do dozwolonych celów/możliwości; (5) dodaj server-side quarantine i limity bandwidth; (6) przetestuj widoczność SOC i reakcję na utratę; (7) odbierz urządzenie, zachowaj wymagane dowody i wyczyść zgodnie z polityką cyklu życia. Nigdy nie ukrywaj urządzenia w miejscu bez zgody.

**Wykrywanie:** NAC/802.1X, switchport/PoE/DHCP, inwentarz USB, RF survey, powtarzający się tunel, monitoring odbioru/kamery i inspekcja fizyczna.

## Nearest-neighbor wireless pivot

**Mechanika:** aktor kontroluje hosta w zasięgu radiowym celu, a następnie używa danych Wi-Fi celu, aby zdalnie przekroczyć granicę. APT28 używał w ten sposób pobliskich przejętych organizacji.<sup>[[18]](#references)</sup>

**Zalety:** brak podróży operatora; cel widzi lokalne źródło radiowe; omija kontrole stosowane wyłącznie przy wejściu z Internetu.

**Wady:** wymaga pobliskiego przejętego/własnego dual-radio hosta i prawidłowego dostępu; dowody RADIUS/NAC/AP i endpointu sąsiada; anomalie sygnału/urządzenia.

**Procedura:** reprodukuj wyłącznie za pomocą [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): połącz własny pivot z SSID sąsiada i celu w laboratorium, przekazuj tylko jedną usługę, zbierz logi obu AP/pivot, następnie włącz EAP-TLS/device posture i potwierdź odrzucenie drugiej próby.

**Wykrywanie:** koreluj tożsamość RADIUS, certyfikat/posture, first-seen device, krawędź/sygnał AP, równoczesne logowanie i obecność fizyczną; szukaj pobliskich endpointów z jednoczesnymi radiami, forwardingiem i tunelami.

## Community mesh, delay-tolerant i offline store-and-forward

**Mechanika:** ruch przechodzi przez lokalne peer, asynchroniczne gateway, removable media lub planowane kolejki zamiast jednej interaktywnej sesji Internet.

**Zalety:** działa podczas zakłóceń/cenzury; opóźnione/batchowane dostarczanie osłabia prostą analizę czasu; brak centralnego last mile dla komunikacji lokalnej.

**Wady:** duże opóźnienia; mały zbiór anonimowości; metadane custody/fizyczne; złośliwe peer; dane ostatecznie trafiają do gateway obserwującego je.

**Procedura:** (1) zbuduj izolowaną własną trójwęzłową mesh lub kolejkę plików; (2) szyfruj/uwierzytelniaj treść end-to-end; (3) usuń bezpośrednie trasy Internet z origin; (4) przekaż benign plik po kontrolowanym opóźnieniu; (5) sprawdź, czy tylko gateway kontaktuje się z własnym celem; (6) porównaj custody/timestamps; (7) zachowaj wymagane dowody, następnie wyczyść tymczasowe media/kolejki zgodnie z procedurą.

**Wykrywanie:** aktywność plików/procesów endpointu, linki radiowe peer, audit removable media, okresowość queue/gateway i identyfikatory treści. Dłuższe okna korelacji zastępują analizę interaktywnych przepływów.

## TURN relay i forced-relay WebRTC

**Mechanika:** Traversal Using Relays around NAT (TURN) przydziela publiczny adres relay i przenosi ruch UDP, TCP lub TLS między klientem a peerami. Polityka ICE może wymusić użycie relay zamiast ujawniania bezpośredniego kandydata. TURN rozwiązuje osiągalność, nie ogólną anonimowość: serwer uwierzytelnia klienta i obserwuje allocations, peer, czas oraz objętość.<sup>[[19]](#references)</sup>

**Zalety:** szeroka implementacja; obsługa restrykcyjnego NAT; wsparcie mobilnego WebRTC; peer nie otrzymuje bezpośredniego adresu transportowego klienta, gdy polityka relay-only działa poprawnie.

**Wady:** operator TURN widzi obie strony; tożsamość aplikacji, fingerprint mediów i signaling pozostają; relay-only kosztuje bandwidth i latency; błędna konfiguracja może ujawnić host lub server-reflexive candidates.

**Procedura:** (1) wdroż własną usługę TURN z TLS i krótkotrwałymi credentials; (2) ogranicz realms, peer, porty, quotas i expiration; (3) ustaw relay-only ICE; (4) połącz się z własnym peer; (5) sprawdź `getStats()` i packet capture, aby potwierdzić, że media przenoszą wyłącznie relay candidates; (6) wyłącz relay i potwierdź brak bezpośredniego fallbacku; (7) zachowaj logi allocation dla engagement.

**Wykrywanie:** signaling, proces przeglądarki i allocations TURN łączą sesję z relay; sieci widzą stałe przepływy do portów TURN lub endpointów TLS; peer widzi przydzielony relay. **Captured node:** stan aplikacji i efemeryczne credentials TURN mogą ujawnić realm i usługę rendezvous. Ogranicz ekspozycję przez krótkotrwałe credentials per-device i trzymaj uwierzytelnianie operatora tylko w controller.

## Outbound-only rendezvous lub reverse overlay

**Mechanika:** node za NAT inicjuje uwierzytelnione połączenie do kontrolowanego przez organizację broker. Operator uwierzytelnia się osobno, a broker autoryzuje wąski kanał zarządzania; nie potrzeba inbound port forwarding ani bezpośredniej trasy operator-node.

**Zalety:** stabilność za NAT i captive last mile; centralne odwoływanie i audyt; zmiana adresu field-node nie wymaga discovery; czyste oddzielenie tożsamości operatora od credential node.

**Wady:** broker jest cennym punktem korelacji; okresowe keepalive są rozpoznawalne; szeroki tunel może stać się niebezpiecznym pivotem; utrata brokera kończy zarządzanie.

**Procedura:** postępuj według [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): wydaj jedną ograniczoną tożsamość urządzenia, zezwól tylko na własny broker i zatwierdzoną usługę zarządzania, użyj uwierzytelnionego keepalive, wymuś routing fail-closed, przetestuj zmianę adresu i recovery po restarcie, a podczas ćwiczenia utraty odwołaj tożsamość. WireGuard opisuje persistent keepalive 25 sekund jako ogólnie użyteczny interwał NAT, gdy jest faktycznie potrzebny.<sup>[[20]](#references)</sup>

**Wykrywanie:** logi brokera i IdP mapują obie strony; sieć dostępu widzi powtarzalny zaszyfrowany destination/cadence; inwentarz endpointu pokazuje overlay agent. **Captured node:** załóż ujawnienie device key, nazwy brokera, adresów tunelu i cache tasków. Node nie może zawierać prywatnego klucza operatora, osobistego konta ani ponownie używanego tokena controller.

## Pull mailbox, message queue lub object-store rendezvous

**Mechanika:** workload terenowy odpytuje uwierzytelnioną skrzynkę o podpisane, zatwierdzone jobs i publikuje ograniczone wyniki. Operator zapisuje do kolejki przez osobny control plane; nie ma interaktywnego socketu między nimi.

**Zalety:** toleruje przerywane łącza; oddziela czas i adresowanie; quotas/schemas ograniczają możliwości; łatwy centralny audyt i revocation.

**Wady:** cadence odpytywania i stałe nazwy object/queue fingerprintują system; logi dostawcy łączą producer/consumer; opóźnione sterowanie; przechwycone dane kolejki mogą ujawnić ćwiczenie.

**Procedura:** (1) utwórz jedną kolejkę engagement i jedną tożsamość urządzenia; (2) zdefiniuj podpisany schema benign, ograniczonych jobs; (3) ustaw message TTL, maksymalny rozmiar wyniku i rate; (4) pozwól node pobierać tylko własną kolejkę i zapisywać tylko własny prefix wyników; (5) przetestuj offline accumulation, duplicate delivery i revocation; (6) centralizuj niezmienne access logs; (7) usuń kolejkę po wymaganej retencji.

**Wykrywanie:** szukaj okresowych API calls nietypowego procesu, stałych bucket/object/queue paths, identycznego user-agenta/TLS i sekwencji fetch-then-new-connection. **Captured node:** lokalny cache może ujawnić oczekujące jobs i nazwy obiektów; szyfruj, ograniczaj i usuwaj cache, zachowując autorytatywne logi controller.

## Dual-uplink failover i connection migration

**Mechanika:** zatwierdzony field node ma dwa niezależne uplinks — np. Ethernet/Wi-Fi lokalu i cellular organizacji — i utrzymuje control session przez overlay lub message broker przy zmianie tras. To inżynieria dostępności, nie anonimowość.

**Zalety:** przeżywa awarię dostawcy, AP lub captive portal; obsługuje planowane prace; pozwala szybko odizolować podejrzaną ścieżkę.

**Wady:** dwóch dostawców tworzy dwa rekordy lokalizacji/konta; jednoczesne użycie ułatwia korelację; wycieki route/DNS podczas failover; pozostają dowody współlokacji cellular.

**Procedura:** (1) zarejestruj oba interfejsy i dostawców organizacji; (2) przypisz deterministyczne priorytety tras i health checks do własnych endpointów; (3) zwiąż DNS i management z overlay; (4) uniemożliw secondary path przyjmowanie ruchu inbound; (5) odłącz każdą ścieżkę i sprawdź recovery sesji, politykę źródła i brak bezpośredniego dostępu do celu; (6) alarmuj przy nieplanowanej zmianie ścieżki; (7) udokumentuj wykorzystanie danych i limity roaming.

**Wykrywanie:** koreluj ten sam certyfikat urządzenia, gramatykę żądań i czas między ASN; lokalny inwentarz widzi oba radia; operatorzy/lokale zachowują własne rekordy. **Captured node:** mogą być widoczne oba identyfikatory SIM/urządzenia i znane SSID; używaj zasobów organizacji i nie łącz node z urządzeniami osobistymi.

## Organization private APN lub managed cellular tunnel

**Mechanika:** prywatny APN operatora umieszcza zarejestrowane SIM w prywatnej domenie routowanej lub tuneluje ruch do enterprise gateway. Oddziela urządzenie od publicznego mobile Internet, lecz nie ukrywa go przed operatorem ani organizacją zamawiającą.

**Zalety:** stabilne prywatne adresowanie; polityka ruchu i enrollment na poziomie operatora; brak publicznej ekspozycji inbound; przydatne dla autoryzowanych appliance zdalnych.

**Wady:** abonent, IMSI/IMEI, komórka i billing dają silną atrybucję; czas i koszt procurement; awaria operatora/gateway; brak anonimowości wobec operatora.

**Procedura:** (1) zawrzyj umowę APN na nazwę organizacji oceniającej; (2) allowlistuj wyłącznie zarejestrowane SIM i prefiksy gateway; (3) dodaj application-layer mutual authentication; (4) ogranicz trasę APN do rendezvous i usług aktualizacji; (5) przetestuj usunięcie SIM, roaming, public-Internet breakout i revocation; (6) monitoruj rekordy operatora/gateway; (7) anuluj lub quarantine każdą SIM podczas closeout.

**Wykrywanie:** inwentarz operatora i telemetria komórek, przepływy APN gateway, mismatch SIM/IMEI i rekordy zasobów przedsiębiorstwa. **Captured node:** SIM i modem identyfikują kontrakt nawet przy szyfrowanym storage; capture resilience oznacza szybkie zawieszenie i wąską autoryzację, nie deniability.

## Long-range point-to-point wireless bridge

**Mechanika:** kierunkowy Wi-Fi lub inne licencjonowane/nielicencjonowane radio point-to-point łączy dwie zatwierdzone lokalizacje właściciela, z egress Internet w lokalizacji zdalnej. Może przenieść pozorną lokalizację IP bez komercyjnego proxy.

**Zalety:** wysoka przepustowość; niezależność od pośrednich operatorów przewodowych; kontrolowane RF i routing; przydatne do testowania segmentacji i monitoringu lokalizacji zdalnej.

**Wady:** line-of-sight, spectrum, landlord i ograniczenia prawne; charakterystyczne emisje RF/sprzęt; oba endpointy są dowodami fizycznymi; pogoda/zasilanie/alignment wpływają na stabilność.

**Procedura:** (1) uzyskaj pisemną zgodę obu lokalizacji i sprawdź przepisy spectrum/power; (2) zbadaj trasę bez transmisji poza zatwierdzonymi parametrami; (3) użyj authenticated encryption i management VLAN; (4) ogranicz bridge do własnego rendezvous/test subnet; (5) przetestuj failover, alignment, power recovery i containment RF; (6) oznacz i zinwentaryzuj oba radia; (7) usuń je i sprawdź reset konfiguracji po ćwiczeniu.

**Wykrywanie:** RF surveys, analiza spectrum, inspekcja rooftop/site, bridge MAC/OUI, management traffic i logi egress lokalizacji zdalnej. **Captured node:** konfiguracja ujawnia peer i domenę zarządzania; używaj unikalnych credentials ćwiczenia, bez osobistych kont i z szybkim odwołaniem peer key.

## Consented cooperative lub community exit

**Mechanika:** wolontariusze lub organizacje partnerskie świadomie uruchamiają relay według opublikowanej polityki. Ruch wychodzi ze współdzielonej puli community, a warstwa koordynacji obsługuje abuse i revocation.

**Zalety:** różnorodne sieci non-cloud; jawna zgoda jest bezpieczniejsza niż proxyware; shared governance może rozdzielać zaufanie; przydatne do badań i odporności na cenzurę.

**Wady:** małe pule i rekordy członkostwa zmniejszają anonimowość; operatorzy exit otrzymują skargi i widzą metadane ruchu; złośliwi uczestnicy, zmienna dostępność i różne jurysdykcje.

**Procedura:** (1) opublikuj acceptable-use i logging policy; (2) uzyskaj informed opt-in każdego operatora; (3) wydaj unikalną tożsamość relay i ogranicz cele/rate; (4) zapewnij abuse handling i jednoetapową revocation; (5) podczas testów wysyłaj tylko autoryzowany ruch do własnych endpointów; (6) zmierz churn i ekspozycję na korelację; (7) poprawnie usuń relay po zakończeniu zgody.

**Wykrywanie:** rekordy członkostwa/control-plane, certyfikaty relay, wspólny fingerprint software i zachowanie exit identyfikują pulę. **Captured node:** konfiguracja relay może identyfikować cooperative, ale nie powinna zawierać tożsamości klientów; odpowiedzialność client-to-session przechowuj w autoryzowanym controller z kontrolą dostępu.

## IPv6 temporary addresses i rotacja prefix

**Mechanika:** rozszerzenia prywatności IPv6 tworzą tymczasowe identyfikatory interfejsu, aby stały adres nie był używany dla każdego połączenia outbound. Zmiana prefix dostawcy może zwiększać rotację, lecz delegated prefix, rekord abonenta i fingerprint wyższych warstw pozostają.<sup>[[21]](#references)</sup>

**Zalety:** ogranicza długoterminowe śledzenie pasywne przez stały identyfikator interfejsu; wbudowane w popularne systemy; brak narzutu relay.

**Wady:** nie zapewnia anonimowości źródła; ISP i sieć lokalna nadal znają prefix/urządzenie; DNS, konta i stan przeglądarki łączą sesje; churn adresów komplikuje allowlisty i logi.

**Procedura:** (1) sprawdź stabilne i tymczasowe adresy na własnym kliencie; (2) włącz wspierany przez OS default privacy address zamiast spoofingu third-party; (3) wielokrotnie wywołaj własny endpoint IPv6 w różnych lifetimes; (4) potwierdź, że usługi inbound wiążą się tylko z zamierzonymi stabilnymi adresami; (5) zachowaj logi DHCPv6/RA/neighbor i dokładne logi endpointu; (6) przetestuj VPN/firewall dla każdego adresu IPv6.

**Wykrywanie:** koreluj delegated prefix, tożsamość layer-2, neighbor discovery, konto i telemetrię endpointu zamiast traktować jeden adres jako jedno urządzenie. **Captured node:** profile sieciowe i identyfikatory interfejsu pozostają; tymczasowe adresy blokują jeden pasywny identyfikator, nie atrybucję forensic.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 i meek

**Mechanika:** pluggable transport zmienia wygląd pierwszego połączenia Tor lub sposób dotarcia do bridge. Snowflake używa krótkotrwałych ochotniczych proxy WebRTC, WebTunnel przypomina zwykły HTTPS, obfs4 odpiera prostą identyfikację protokołu i active probing, a meek przekazuje przez obsługiwaną infrastrukturę web. Są to transporty obejścia cenzury do Tor, nie dodatkowe warstwy anonimowości end-to-end.<sup>[[22]](#references)</sup>

**Zalety:** przydatne, gdy bezpośredni Tor lub znane relay są blokowane; Snowflake unika stałego publicznego adresu bridge; integracja z utrzymywanymi klientami Tor; cel nadal otrzymuje zwykłe właściwości Tor.

**Wady:** niższa/zmienna wydajność; broker/front/bridge i sieć lokalna widzą różne metadane; możliwe fingerprinty i blokowanie; volunteer proxy nie zastępuje Tor i nie powinno być zaufane z plaintextem aplikacji.

**Procedura:** (1) zainstaluj i zweryfikuj oficjalny Tor Browser lub obsługiwany klient Tor; (2) wybierz wbudowany transport w Connection/Bridges; (3) łącz się tylko z własną stroną diagnostyczną; (4) potwierdź, że strona widzi Tor exit, a nie peer Snowflake/WebTunnel; (5) porównaj bootstrap i wydajność; (6) wyłącz transport i potwierdź brak cichego połączenia bezpośredniego; (7) po teście wróć do standardowej konfiguracji.

**Wykrywanie:** cenzor może łączyć allowlisty celów, TLS/WebRTC, discovery brokera i analizę przepływu; endpointy ujawniają Tor i konfigurację transportu. **Capture-resilient OPSEC:** używaj standardowego klienta, nie kopiuj osobistego stanu przeglądarki i zakładaj możliwość odzyskania historii bridge/broker. **Monitoring:** obserwuj logi bootstrap Tor, nieoczekiwane bezpośrednie próby DNS/połączeń i obserwacje własnej strony; awaria transportu nie dowodzi wykrycia.

## Refraction networking lub decoy routing

**Mechanika:** współpracujący operator sieci wykrywa ukryty sygnał w ruchu pozornie kierowanym do dozwolonego decoy i przekierowuje przepływ do proxy obejścia. Wdrożenie wymaga infrastruktury w ścieżce sieciowej; klient nie może tego stworzyć wyłącznie przez wybór niewinnej strony.<sup>[[23]](#references)</sup>

**Zalety:** pozorny cel może być trudny do zablokowania bez collateral damage; nie trzeba dystrybuować publicznego adresu bridge; przydatny model badań on-path-assisted circumvention.

**Wady:** udział specjalistycznego ISP/transit; wdrażalność i wydajność zależą od routingu; przepływ klient-decoy i aktywność proxy pozostają; globalny lub współpracujący obserwator może korelować czas.

**Procedura:** nie sygnalizuj przez niezaangażowane sieci. Odtwórz architekturę w izolowanym laboratorium: (1) utwórz własne namespaces client/router/decoy/proxy; (2) użyj benign tagged test request; (3) pozwól własnemu routerowi przekierować tylko ten tag do proxy; (4) loguj krotki pre/post-routing i request IDs; (5) porównaj zwykłe i sygnalizowane przepływy; (6) przetestuj false positives i usunięcie; (7) usuń trasy laboratoryjne.

**Wykrywanie:** autoryzowani operatorzy sieci mogą sprawdzać rozbieżność routingu, nietypowe zachowanie client hello/tag i różnice przepływu decoy-versus-back-end. **Capture-resilient OPSEC:** klient badawczy powinien zawierać tylko klucze testowe i adresy dokumentacyjne. **Monitoring:** porównuj podpisane decyzje routera laboratoryjnego z przybyciem do proxy; nie sonduj produkcyjnych transit providers, aby ustalić, czy wykryły sygnał.

## Content-addressed gateway lub cached peer retrieval

**Mechanika:** HTTP gateway pobiera content identifier IPFS (CID), z cache lub peerów, i zwraca klientowi weryfikowalną treść. Oryginalny publisher może widzieć gateway lub inne peer zamiast końcowego readera; gateway widzi IP readera i żądany CID. Natywne peer-to-peer retrieval ujawnia klienta peerom i uczestnikom DHT/routingu.<sup>[[24]](#references)</sup>

**Zalety:** cache oddziela publishera i readera; niezmienna treść jest weryfikowalna hashem; replikacja przeżywa jeden host; klienci HTTP nie wymagają natywnego stosu peer.

**Wady:** publiczne CID i logi gateway ujawniają zainteresowania; czas pierwszego pobrania może korelować publishera z readerem; złośliwa treść web i zagrożenia same-origin path; publiczne gateway są best-effort i zabraniają nadużyć.

**Procedura:** (1) opublikuj nieszkodliwy plik testowy w prywatnym swarm IPFS lub gateway organizacji; (2) zapisz CID; (3) pobierz przez osobny własny HTTP gateway z izolacją subdomain; (4) sprawdź bytes względem CID; (5) powtórz po cache; (6) porównaj logi publisher/peer/gateway; (7) unpin i usuń treść po końcu retencji.

**Wykrywanie:** gateway loguje source/CID; DHT i połączenia peer ujawniają retrieval; historia endpointu i file hashes identyfikują treść. **Capture-resilient OPSEC:** nie przechowuj prywatnego klucza publishing na field client read-only i szyfruj wrażliwą treść przed content addressing. **Monitoring:** alarmuj przy nieoczekiwanym pinning, zmianie peer-set, żądaniach CID poza allowlistą lub notice dostawcy.

## Private information retrieval service

**Mechanika:** Private Information Retrieval (PIR) pozwala klientowi pobrać jeden rekord z bazy, kryptograficznie ukrywając wybrany indeks przed serwerem w określonym modelu single- lub multi-server. Chroni wybór query dla ograniczonego datasetu; nie jest ogólnym dostępem web ani anonimowością IP.<sup>[[25]](#references)</sup>

**Zalety:** silna, specyficzna dla aplikacji prywatność query; mierzalny model leak; użyteczne dla key directories, blocklists lub małych publicznych baz; ogranicza potrzebę ujawniania dokładnych terminów.

**Wady:** narzut obliczeń/bandwidth; serwer zna czas/IP połączenia, chyba że użyto relay; wersja datasetu, rozmiar odpowiedzi i stan aplikacji dzielą użytkowników; różna dojrzałość implementacji.

**Procedura:** (1) wdroż audytowaną implementację PIR na syntetycznej własnej bazie; (2) opublikuj wersję i parametry datasetu; (3) pobierz kilka indeksów przez żądania o identycznym rozmiarze; (4) lokalnie zweryfikuj poprawność; (5) porównaj logi serwera i potwierdź brak indeksu; (6) przetestuj złośliwe/ucięte odpowiedzi i mismatch wersji; (7) opisz dokładne założenie prywatności, zamiast nazywać to anonimowym browsingiem.

**Wykrywanie:** sieci widzą użycie usługi i objętość; telemetria endpointu ujawnia klienta i użycie rekordu; przejęty serwer może manipulować datasetem lub czasem. **Capture-resilient OPSEC:** na kliencie przechowuj tylko publiczne parametry bazy i ograniczony cache. **Monitoring:** waliduj podpisane roots datasetu, stałe request shapes, zmiany error-rate i rotacje kluczy serwera.

## Constrained server-side fetcher, preview lub rendering service

**Mechanika:** zdalna usługa pobiera/renderuje URL i zwraca screenshot, metadata lub oczyszczoną treść. Cel widzi adres fetchera; usługa widzi requester, URL i wynik. Nadużywanie link-preview botów, security scannerów lub third-party URL fetcherów nie jest autoryzowanym użyciem proxy.

**Zalety:** izoluje aktywną treść od workstation; cel otrzymuje kontrolowany fingerprint fetchera; można wymuszać ograniczenia typu pliku, rozmiaru, celu i renderowania; jednorazowe środowisko wykonawcze.

**Wady:** usługa zna całe żądanie; rekordy account/API/billing; ryzyko SSRF i eksfiltracji; skrypty, uwierzytelnianie i interaktywne strony mogą nie działać; unikalne URL korelują requester i fetch.

**Procedura:** (1) wdroż własny fetcher z restrykcyjną allowlistą własnych domen testowych; (2) blokuj private, link-local, metadata i redirect do niezatwierdzonych adresów; (3) ogranicz methods, redirects, bytes i render time; (4) usuń credentials/cookies; (5) wyślij własny URL; (6) porównaj logi requester/fetcher/cel; (7) usuń render instance i zachowaj centralny audit zgodnie z polityką.

**Wykrywanie:** cel widzi ASN/fingerprint usługi; logi dostawcy/controller mapują requester na URL; proces endpointu/API calls pokazują submission. **Capture-resilient OPSEC:** użyj jednego krótkotrwałego project token bez prawa do arbitralnych celów. **Monitoring:** alarmuj przy odrzuceniach allowlisty, naruszeniach redirect, fetchach bez controller job ID i notice dostawcy.

## Anycast rendezvous pool

**Mechanika:** wiele kontrolowanych przez organizację nodes reklamuje lub frontuje jeden stabilny adres usługi, a routing wybiera pobliską instancję. Anycast poprawia dostępność i ukrywa pojedynczy back-end przed klientem, lecz operator nadal kontroluje wszystkie instancje, a adres usługi jest stały.<sup>[[26]](#references)</sup>

**Zalety:** odporny regionalny ingress; brak reconfig field przy awarii instancji; dystrybucja DDoS/load; centralna polityka może przenosić sesje między znanymi węzłami.

**Wady:** rekordy BGP/CDN i dostawcy identyfikują organizację; zmiany ścieżki mogą przerwać stateful sessions; monitoring różni się położeniem klienta; jeden stały adres łatwo zablokować lub grupować reputacyjnie.

**Procedura:** użyj wspieranego przez dostawcę projektu organizacji lub izolowanego laboratorium routingu: (1) wdroż dwa identyczne authenticated health endpoints; (2) wystaw jeden udokumentowany adres usługi; (3) trzymaj session state w brokerze, nie na edge; (4) wycofaj jeden node i sprawdź reconnect; (5) przetestuj spójność certyfikatu, polityki i logów; (6) alarmuj przy nieautoryzowanym origin/region; (7) usuń advertisements i credentials podczas closeout.

**Wykrywanie:** BGP/RPKI/history, tenancy dostawcy, certyfikaty i identyczne zachowanie usługi identyfikują pulę. **Capture-resilient OPSEC:** edge przechowuje tylko regional service identity, bez klucza operatora lub enrollment floty. **Monitoring:** sonduj każdy region z autoryzowanych monitorów, porównuj route origin i configuration digest, a nieoczekiwany origin traktuj jako incydent.

## QUIC migration i ciągłość Multipath TCP

**Mechanika:** connection IDs QUIC mogą utrzymać sesję klienta przy rebinding NAT lub zmianie adresu; Multipath TCP przenosi jeden niezawodny strumień przez wiele subflows. Poprawiają ciągłość między Wi-Fi/cellular, lecz wspólny peer widzi stare i nowe ścieżki, co może ułatwiać korelację między nimi.<sup>[[27]](#references)</sup>

**Zalety:** szybsze recovery podczas zmiany uplink; sesja aplikacji nie musi się restartować; MPTCP łączy odporność i throughput; wartościowe dla zatwierdzonych field nodes.

**Wady:** brak anonimowości; peer widzi migration/subflows; connection IDs i jednoczesny ruch łączą ścieżki; wsparcie middlebox/operatora jest różne; dodatkowe rekordy dostawców zwiększają ekspozycję.

**Procedura:** (1) włącz obsługiwany transport tylko między własnym field client i rendezvous; (2) uwierzytelnij aplikację niezależnie od IP; (3) rozpocznij ograniczony transfer przez zatwierdzone Wi-Fi; (4) przełącz na cellular organizacji; (5) potwierdź path validation, integralność danych i brak clear/direct fallback; (6) przetestuj idle timeout i powrót; (7) zachowaj rekordy brokera każdej zmiany ścieżki.

**Wykrywanie:** peer bezpośrednio obserwuje address migration lub subflows MPTCP; dostawcy dostępu widzą własną część; connection IDs, TLS identity i czas łączą oba połączenia. **Capture-resilient OPSEC:** przechowuj tylko device-scoped session material i szybko wygaszaj resumable state. **Monitoring:** alarmuj przy niemożliwych zmianach ścieżki, jednoczesnych niezatwierdzonych sieciach, migration storms i resumption po quarantine.

## Managed CI/CD lub ephemeral automation runner egress

**Mechanika:** własny workflow organizacji wykonuje ograniczony network check na hosted runner. Cel widzi adres cloud runner, a platforma zachowuje atrybucję repository, actor, workflow, token, log i billing. To zdalne wykonanie z rozliczalnym egress, nie anonimowość wobec dostawcy.<sup>[[28]](#references)</sup>

**Zalety:** jednorazowe czyste środowisko; powtarzalna definicja job; brak połączenia inbound; przydatne dla rozproszonych geograficznie availability checks; silny audit controller.

**Wady:** platforma i organizacja identyfikują inicjatora; szerokie workflow tokens i niezaufane pull requests są niebezpieczne; współdzielona reputacja IP; logi/artifacts mogą zachowywać sekrety lub dane celu.

**Procedura:** (1) utwórz prywatne repository i environment organizacji dla oceny; (2) zezwól tylko na ręcznie zatwierdzone, stałe benign jobs wobec własnych endpointów; (3) użyj minimalnych, read-only workflow permissions i bez production secrets; (4) uruchom check; (5) porównaj rekordy workflow, dostawcy i celu; (6) sprawdź, czy artifacts nie zawierają credentials; (7) usuń environment token i zachowaj wymagany audit.

**Wykrywanie:** audit dostawcy i workflow logs zapewniają bezpośrednią atrybucję; cele identyfikują ASN/range runnera i stałą gramatykę żądań. **Capture-resilient OPSEC:** nigdy nie umieszczaj sekretów field-device, signing, wallet ani cloud-administrator w runner variables. **Monitoring:** wymagaj branch/environment approval i alarmuj przy zmianach workflow, fork execution, odczycie sekretów i nieoczekiwanych celach.

## Non-IP local first hop do własnego gateway

**Mechanika:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio lub serial/optical link przenosi ograniczone wiadomości z pobliskiego sensora do zatwierdzonego Internet gateway właściciela. Sam field device nie ma trasy Internet; jedynym egress jest gateway. Zasięg radiowy i ograniczenia protokołu tworzą projekt telemetry/store-and-forward, nie interaktywny anonimowy Internet.

**Zalety:** usuwa stos Internet i credentials z najmniejszego field device; niski pobór energii; gateway centralizuje politykę; może przełączać tymczasowe dead zones.

**Wady:** RF/fizyczne discovery, pairing i device identifiers; mały bandwidth/zasięg; gateway nadal łączy wszystkie wiadomości; ograniczenia spectrum i szyfrowania są różne; przejęcie może ujawnić queued data.

**Procedura:** (1) uzyskaj zgodę lokacji i spectrum; (2) sparuj jeden własny sensor z jednym gateway przez unikalne keys; (3) zdefiniuj podpisane komunikaty stałego rozmiaru, TTL i rate; (4) nie dawaj sensorowi domyślnej trasy IP; (5) pozwól gateway przekazywać tylko do własnego collectora; (6) przetestuj replay, utratę zasięgu i awarię gateway; (7) zinwentaryzuj i odbierz oba urządzenia.

**Wykrywanie:** RF survey, pairing database, inspekcja fizyczna i logi procesu/przepływu gateway ujawniają ścieżkę. **Capture-resilient OPSEC:** sensor przechowuje wyłącznie pairwise key i ograniczoną zaszyfrowaną kolejkę, nigdy credentials operatora, Wi-Fi, cellular ani controller. **Monitoring:** alarmuj przy nowych peerach, rollback sequence, awarii klucza, nietypowym RF rate i wiadomościach z niezarejestrowanego gateway.

## Macierz ekspozycji na capture/compromise

Ta tabela stosuje kontrolę capture resilience do każdej powyższej rodziny. „Ogranicz” oznacza redukcję sekretów i blast radius na autoryzowanych zasobach; nigdy nie oznacza usuwania dowodów ani ukrywania się przed dochodzeniem.

| Rodzina technik | Co może ujawnić przejęty endpoint/relay | Minimalna autoryzowana kontrola |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | znane sieci, historia DHCP/portalu, MAC, peer tunelu | osobne urządzenie organizacji; private MAC, gdy obsługiwany; brak kont osobistych; inwentarz controller |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | dostawcy/hostnames, klucze, trasy, logi i sąsiedni hop | jedna tożsamość per engagement; krótki TTL; wąskie trasy; revocation po stronie brokera; brak master keys |
| OHTTP/ODoH, MASQUE, split-provider relay | konfiguracja relay/gateway, identyfikatory aplikacji i cache żądań | minimalne identyfikatory payload; pin zatwierdzonej konfiguracji; ograniczony cache; ścisły brak direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | zainstalowane software, bridge/onion material, stan lokalny i historia peer | standardowy klient; osobne service keys; zaszyfrowany minimalny stan; rotacja przejętej tożsamości usługi |
| Remote browser/VDI/jump host | workspace token, clipboard/pliki i remote tenant | phishing-resistant MFA na gateway; wyłączone kanały transferu; szybka revocation sesji |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/tożsamość terminala, dostawca i przybliżona lokalizacja | kontrakt organizacji; brak współlokacji osobistej; wąska polityka APN/overlay; procedura zawieszenia u dostawcy |
| Residential/cooperative proxy, ORB lab | tożsamość agenta, controller/next hop, cache ruchu | tylko węzły consented/owned; podpisany agent; credentials per node; mapowanie uczestników w controller |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment i billing references | dedykowany projekt; least-privilege role; krótkotrwały deploy token; centralnie zachowany audit dostawcy |
| Dead drop, pull mailbox, store-and-forward | nazwy obiektów, queue, cache jobs/results i dane custody | podpisane ograniczone jobs; TTL; zaszyfrowany cache; osobna tożsamość producer; niezmienne logi serwera |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, artefakty lokalizacji | pisemna zgoda; unikalna tożsamość urządzenia; brak sekretu operatora; telemetry stanu/tamper; revoke i recovery |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route i profile uplink | wąska usługa outbound-only; krótkotrwałe device credential; niezależne logowanie operatora; ścieżki fail-closed |
| IPv6 temporary addressing | profile, historia prefix i stan endpointu/aplikacji | traktuj wyłącznie jako anti-tracking; zachowaj logi sieciowe; połącz z compartmentation endpointu |
| Pluggable transport/refraction lab | ustawienia bridge/broker/decoy, stan Tor i klucze badawcze | standardowy klient lub izolowane laboratorium; brak osobistego stanu przeglądarki; brak production signaling |
| IPFS/PIR/fetcher | żądany CID/query, cache treści, gateway lub service token | zaszyfrowany ograniczony cache; tylko publiczne parametry; krótkotrwały allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state i wszystkie znane ścieżki | wyłącznie regional identity; krótki resumption lifetime; centralna revocation route/session |
| Managed CI/CD runner | repository, workflow, provider token, logi i artifacts | least-privilege workflow; bez production/field/wallet secrets; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages i gateway identity | unikalny pairwise key; stały message schema; bez credentials Wi-Fi/cellular/operator |

## Monitoring możliwego rozpoznania dla każdej rodziny dostępu

Żaden test po stronie klienta nie dowodzi, że obserwuje go śledczy lub obrońca. Monitoruj zmiany w systemach należących do engagement, potwierdzaj je przez controller/client i zatrzymaj działanie zamiast sondować obserwatorów. Poniższe wiersze obejmują wszystkie powyższe techniki; łącz je z [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Objęte techniki | Bezpieczne sygnały po stronie controller | Warunek quarantine/stop |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, zmiana BSSID/cell/path, notice dostawcy | niezatwierdzona sieć/SIM/urządzenie, niewyjaśniona relokacja lub eskalacja dostawcy/SOC |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, stan tunelu, route/DNS leaks, nowy event admin/API, complaint | duplikat/skradzione credentials, nieznany administrator, direct fallback lub egress poza zakresem |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | allocation relay/gateway, wersja klucza/config, nieobsługiwane direct connection, error/replay rate | key mismatch, direct fallback, nieznany realm/peer lub provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health i własna canary page | crossover konta osobistego, nieoczekiwane połączenie non-Tor lub przejęty service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association i content hash | nieznany peer/gateway, rollback sequence, nieautoryzowana treść lub brak custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, nowe użycie tokena, artifact/export i cloud audit | nieznane logowanie/edycja workflow, odczyt sekretu, nieoczekiwany cel lub eskalacja project-role |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | inwentarz własnych node, DNS/edge/object access, graf controller, job signature i TTL | nieznany node/origin/object writer, unsigned/replayed job, ucieczka topologii z laboratorium |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, kontekst AP/switch, duplicate identity | przeniesiony/otwarty node, nieoczekiwany boot/hash/path, użycie sentinel lub raport lokacji |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation i broker session | niemożliwa migracja, jednoczesne niezatwierdzone ścieżki lub resumption po revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, zmiana peer/gateway, redirect/allowlist denial | nieoczekiwany pin/query/destination, unsigned dataset root lub provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | własna decyzja diversion, proxy arrival, BGP/RPKI origin, regional config digest | sygnał w ścieżce produkcyjnej, nieznany route origin, niespójność region/config |

## Wybór i testowanie ścieżki

1. Nazwij obserwatora, którego chcesz usunąć, oraz dane, które chcesz ukryć.
2. Wybierz najmniej złożoną rodzinę usuwającą ten problem.
3. Narysuj obserwatorów source, entry, traversal, exit, DNS, account i payment.
4. Użyj osobnej tożsamości endpointu/aplikacji.
5. Zweryfikuj IPv4, IPv6, DNS, WebRTC/application bypass i widok celu.
6. Przerwij każdy hop i potwierdź zamknięcie połączenia.
7. Porównaj logi każdego kontrolowanego komponentu.
8. Zapisz pozostałe powiązania czasowe, dostawcy, endpointu i fizyczne.

## References

- [1] [EFF — Choosing the VPN that is right for you](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
{{#include ../banners/hacktricks-training.md}}
