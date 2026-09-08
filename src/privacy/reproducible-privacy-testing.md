# Powtarzalne testowanie prywatności

{{#include ../banners/hacktricks-training.md}}

Konfiguracja prywatności nie jest ukończona w momencie nawiązania połączenia. Jest ukończona dopiero wtedy, gdy zadeklarowana granica została przetestowana podczas normalnego użytkowania, awarii, odzyskiwania i demontażu. Testuj wyłącznie infrastrukturę, której jesteś właścicielem lub do której kontroli masz upoważnienie; publiczne witryny typu „leak test” stają się kolejnym obserwatorem.

## Zbuduj małe autoryzowane środowisko testowe

Użyj trzech ról, najlepiej w oddzielnych dostawcach/sieciach:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Zarejestruj przed każdym testem:

- identyfikator testu, czas rozpoczęcia/zakończenia w UTC, operatora i autoryzację;
- endpoint, system operacyjny, wersje klienta i hash konfiguracji;
- oczekiwane obserwacje dotyczące IPv4, IPv6, DNS, TLS, konta, płatności i warstwy fizycznej;
- które logi zostaną sprawdzone oraz ich zegary/strefy czasowe;
- regułę zaliczenia/niezaliczenia i czas teardown.

Nigdy nie testuj najpierw wrażliwej tożsamości. Używaj syntetycznego konta oraz nieszkodliwych, unikalnych wartości canary należących do testera.

## Test ścieżki sieciowej

### 1. Zarejestruj baseline

Przed włączeniem ścieżki prywatności zarejestruj lokalne trasy i resolvery:
```bash
ip route
ip -6 route
resolvectl status
```
Na macOS użyj `route -n get default`, `netstat -rn -f inet6` oraz `scutil --dns`. Zapisuj dane wyjściowe wyłącznie w kontrolowanym magazynie dowodów; mogą one zawierać lokalne identyfikatory.

### 2. Nawiąż połączenie i sprawdź routing

Włącz przestrzeń nazw VPN/Tor/workload, a następnie sprawdź trasę wybraną dla kontrolowanych publicznych adresów:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Zastąp adresy dokumentacji adresami serwerów testowych. Potwierdź, że wybrany interfejs/tabela odpowiada projektowi.

### 3. Obserwacja z obu stron

Ustaw URL kontrolowanego endpointu, a następnie wyślij żądanie do unikalnej, nieszkodliwej ścieżki:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Użyj domeny kontrolowanej przez testera, uwierzytelnionego TLS oraz niewrażliwego tokenu w ścieżce. Sprawdź log serwera pod kątem:

- adresu źródłowego/ASN i oczekiwanego egressu;
- IPv4 versus IPv6;
- zachowania Host/SNI widocznego w endpointcie;
- user agenta i nagłówków aplikacji;
- dokładnego czasu i ponownego użycia żądania.

Nie dodawaj `X-Forwarded-For`, unikalnych nagłówków debugowania ani plików cookie zawierających dane identyfikacyjne do żądania, które rzekomo jest odseparowane.

### 4. Testuj DNS za pomocą własnego canary

Skonfiguruj autorytatywną strefę testową, której logi zapytań kontrolujesz. Wykonaj zapytanie dotyczące unikalnej losowej etykiety przez compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Sprawdź authoritative log. Zwykle widzi recursive resolver, a niekoniecznie klienta. Porównaj ten resolver z zamierzoną konfiguracją DNS dla VPN/Tor/aplikacji. Losowa publiczna strona do wykrywania DNS leak nie jest wymagana.

### 5. Testowanie zachowania fail-closed

Utrzymuj benign request loop skierowaną do należącego do Ciebie endpointu, a następnie zatrzymaj ścieżkę ochrony prywatności. Obciążenie musi zakończyć się błędem, zamiast przełączyć się na fizyczny interfejs. Sprawdź obie rodziny adresów oraz DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Powtórz podczas:

- awarii procesu tunnel;
- przełączania z Wi-Fi na Ethernet lub hotspot;
- usypiania i wybudzania;
- odnowienia DHCP;
- zmiany stanu captive portal;
- ponownego połączenia dostawcy lub wygaśnięcia klucza.

W przypadku Linux namespace/container zatrzymaj jego tunnel i sprawdź, czy nie ma żadnej innej domyślnej trasy ani resolvera:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Nazwy i polecenia różnią się w zależności od wdrożenia. Nie wklejaj ich do zdalnego hosta produkcyjnego bez możliwości odzyskania dostępu przez konsolę.

### 6. Sprawdź lokalne gniazda i pakiety

Za zgodą sprawdź, który proces/interfejs faktycznie się komunikuje:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Zastąp `TEST_SERVER_IP` jawnym, należącym do Ciebie adresem; unikaj szerokiego przechwytywania danych niezwiązanych użytkowników. Interfejs fizyczny powinien widzieć peer tunelu/bridge, a ruch do jawnego celu powinien istnieć wyłącznie na zamierzonej warstwie.

## Test Tor i onion service

1. W Tor Browser odwiedź stronę Tor Project do sprawdzania połączenia i potwierdź użycie Tor. Nie traktuj tego jako dowodu tożsamości.<sup>[[1]](#references)</sup>
2. Odwiedź należący do Ciebie endpoint HTTPS z unikalnym canary i potwierdź, że widzi wyjście Tor, nie ma identyfikujących cookies oraz używany jest standardowy kontekst przeglądarki.
3. Wybierz **New Identity**, odwiedź stronę ponownie z innym canary i sprawdź, czy lokalny stan został wyczyszczony zgodnie z oczekiwaniami. Zmiana exit IP nie jest gwarantowana ani nie jest celem funkcji New Identity.
4. W przypadku onion service uzyskuj do niego dostęp wyłącznie przez Tor Browser. Potwierdź za pomocą autoryzowanego zewnętrznego skanu, że host usługi nie ma publicznego listenera oraz że odpowiedzi aplikacji nie zawierają publicznego hostname/IP.
5. Sprawdź wychodzący DNS/HTTP originu, templates, strony błędów, email/webhooks oraz zasoby stron trzecich. Każde bezpośrednie pobranie może ujawnić origin lub konto operatora.
6. Jeśli włączono client authorization, potwierdź, że nieuwierzytelniony, czysty Tor Browser nie może się połączyć, a uwierzytelniony może.
7. Zrotuj testowy klucz autoryzacyjny i potwierdź, że odwołany klient traci dostęp bez zmiany onion identity.

## Test separacji przeglądarki

Utwórz kontrolowaną stronę, która rejestruje wyłącznie pola potrzebne do testu, z krótkim okresem retencji. Porównaj osobisty compartment i privacy compartment pod kątem:

- cookies/local storage/service workers i cache;
- stanu browser sync/login;
- języka, strefy czasowej, wymiarów ekranu/okna i fonts;
- kandydatów WebRTC/network;
- uprawnień i modyfikacji widocznych dla extensions;
- danych user-agent TLS/HTTP po stronie serwera.

Nie próbuj czynić Tor Browser „bardziej losowym”. Warunkiem zaliczenia jest podobieństwo do jego standardowego anonymity set oraz brak osobistego stanu, a nie maksymalna różnica względem osobistej przeglądarki.

Przetestuj kopiowanie/wklejanie, przeciąganie i upuszczanie, otwieranie pobranych plików, sugestie password managera oraz przyciski identity providera. Są to częste mosty między compartmentami.

## Test izolacji systemu operacyjnego

### Tails

1. Rozpocznij od nieszkodliwego pliku/canary w sesji bez Persistent Storage.
2. Całkowicie wyłącz system, uruchom go ponownie i potwierdź, że plik zniknął.
3. Włącz tylko jedną wymaganą kategorię persistence, powtórz test i potwierdź, że niezwiązany stan przeglądarki/aplikacji nie jest zachowywany.
4. Zweryfikuj, że Unsafe Browser nie może być używany po zalogowaniu do portalu do wrażliwych działań oraz że aplikacje Tor łączą się ponownie normalnie.

### Whonix/Qubes

1. Zatrzymaj Gateway/net qube i udowodnij, że Workstation/app qube nie może uzyskać dostępu do IPv4, IPv6 ani DNS.
2. Podejmij próbę użycia wyłącznie jawnie skonfigurowanej ścieżki clipboard/file między qubes i potwierdź, że inne ścieżki shared-folder/device są nieobecne.
3. Otwórz nieszkodliwy dokument testowy w disposable qube, zamknij go i potwierdź, że jego stan znika.
4. Sprawdź, czy vault qube nie ma NetVM i nie może go uzyskać przez zmianę template/default.
5. Wykonaj snapshot/restore testowej maszyny VM i sprawdź, czy stan zawierający tożsamość nie powraca niespodziewanie.

## Test metadanych komunikacji

Dla każdego wybranego messengera:

1. Utwórz uczestników przeznaczonych wyłącznie do testów na kontrolowanych urządzeniach.
2. Zapisz, czego wymaga rejestracja: telefonu, konta app-store, IP, usługi push, username lub invitation.
3. Wyślij jedną nieszkodliwą wiadomość, sprawdzając podglądy powiadomień, połączone desktopy, wearables i backupy.
4. Zweryfikuj kody safety/security niezależną ścieżką.
5. Wyłącz receipts/push lub włącz Tor/local transports pojedynczo i obserwuj zmiany niezawodności/metadanych.
6. Wyeksportuj lub przywróć testowy backup i dokładnie udokumentuj, jaki profil, kontakty i historię zawiera.
7. Utrać/odwołaj testowe urządzenie i potwierdź, że pozostali uczestnicy widzą oczekiwaną zmianę klucza/urządzenia.

Nie przeprowadzaj testów, kontaktując się z niezaangażowanymi osobami ani generując abusive traffic.

## Test sanitization plików

1. Oblicz hash i zachowaj oryginał w zaszyfrowanym magazynie dowodów:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Utwórz oczyszczoną kopię, korzystając z procesu właściwego dla formatu w [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md).
3. Porównaj inwentarze metadanych:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Wyrenderuj/otwórz kopię w disposable context. Sprawdź ukrytą zawartość, załączniki, linki, formularze, warstwy, miniatury i wizualne identyfikatory.
5. Wyszukuj znane ciągi canary author/email/path wyłącznie w staged copy.
6. Oblicz hash final output i poproś drugą osobę o weryfikację dokładnego pliku przeznaczonego do publikacji.

Brak danych w output ExifTool nie jest dowodem anonimowości; wewnętrzne elementy formatu, piksele, treść prozatorska i rejestry dystrybucji nadal pozostają.

## Test prywatności płatności

Użyj najmniejszej dozwolonej kwoty albo oficjalnej sieci testowej/sandbox:

1. Zapisz oczekiwany widok dla płatnika, odbiorcy/sprzedawcy, emitenta/exchange, sieci/węzła, public ledger oraz księgowego/inspektora.
2. Utwórz unikalny kontekst testowej faktury/sprzedawcy bez fałszywej tożsamości.
3. Zapłać raz, a następnie zbierz **własne** potwierdzenie, wyciąg, dashboard sprzedawcy, log wallet/node oraz widok publicznego łańcucha, jeśli ma zastosowanie.
4. Sprawdź, czy kwota, znacznik czasu, adres/token, konto, IP/urządzenie, dostawa i ścieżka zwrotu odpowiadają tabeli obserwatora.
5. W przypadku Bitcoina sprawdź ponowne użycie adresu, wybrane wejścia, resztę oraz późniejszą konsolidację w widoku coin-control wallet.
6. W przypadku shielded protocols zweryfikuj rzeczywisty pool/path oraz to, co ujawnia viewing key; nie wnioskuj o prywatności na podstawie brandingu wallet.
7. W przypadku e-cash/Taler przetestuj backup/recovery, zwrot i redemption przy użyciu małej wartości; udokumentuj rejestry granic mint/exchange/federation.
8. Unieważnij virtual card/test credential i potwierdź, że późniejsza autoryzacja kończy się niepowodzeniem, przy jednoczesnym zachowaniu zrozumienia prawidłowej obsługi zwrotu.
9. Uzgodnij i zachowaj wymagane dowody podatkowe/autoryzacyjne w formie zaszyfrowanej.

Nigdy nie twórz transferów kołowych, dzielenia kwot progowych, fałszywych zakupów ani podejrzanych zwrotów jako „testu prywatności”.

## Ćwiczenie rozliczalności autoryzowanego red teamu

Przed ćwiczeniem przeprowadź ćwiczenie tabletop i drill techniczny:

1. Operator uruchamia benign canary z każdej zatwierdzonej source path.
2. Docelowy SOC rejestruje to, co wykrywa, bez otrzymywania tożsamości operatora, jeśli planowane jest blind testing.
3. Kontroler ćwiczenia ustala source → engagement → operator na podstawie escrowed map i podpisanego job record.
4. Kontroler wysyła emergency stop; operator i właściciel infrastruktury demonstrują shutdown w czasie określonym w ROE.
5. Provider abuse otrzymuje właściwy kontakt 24/7 i authorization reference.
6. Dowody wskazują target, czas, tool/job i operatora bez przechowywania zbędnej zawartości payloadu.
7. Drugi operator weryfikuje credential revocation i resource teardown.

Odrzuć ocenę gotowości, jeśli SOC może w prosty sposób zobaczyć osobistą/domową infrastrukturę **LUB** jeśli kontroler nie może szybko przypisać źródła do odpowiedzialnego podmiotu i je zatrzymać.

## Szablon rejestru testu
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Kontrola połączenia](https://check.torproject.org/)
- [2] [WireGuard — Routing i przestrzenie nazw sieciowych](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ i wskazówki dotyczące metadanych](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Techniczny przewodnik po testowaniu i ocenie bezpieczeństwa informacji](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
