# Testowanie prywatności, które można odtworzyć

Konfiguracja prywatności nie jest ukończona, gdy nawiązuje połączenie. Jest ukończona dopiero wtedy, gdy jej deklarowana granica została przetestowana podczas normalnego użytkowania, awarii, odzyskiwania i usuwania. Testuj wyłącznie infrastrukturę, której jesteś właścicielem lub do której kontroli masz upoważnienie; publiczne strony „leak test” stają się kolejnym obserwatorem.

## Zbuduj małe autoryzowane środowisko testowe

Użyj trzech ról, najlepiej w oddzielnych providerach/sieciach:
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

Nigdy nie testuj najpierw wrażliwej tożsamości. Użyj syntetycznego konta i nieszkodliwych, unikalnych wartości canary należących do testera.

## Test ścieżki sieciowej

### 1. Zarejestruj stan bazowy

Przed włączeniem ścieżki prywatności zarejestruj lokalne trasy i resolvery:
```bash
ip route
ip -6 route
resolvectl status
```
W systemie macOS użyj poleceń `route -n get default`, `netstat -rn -f inet6` oraz `scutil --dns`. Zapisuj dane wyjściowe wyłącznie w kontrolowanym magazynie dowodów; mogą zawierać lokalne identyfikatory.

### 2. Połącz się i sprawdź routing

Włącz VPN/Tor/workload namespace, a następnie sprawdź trasę wybraną dla kontrolowanych adresów publicznych:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Zastąp adresy dokumentacji adresami serwera testowego. Potwierdź, że wybrany interfejs/tabela odpowiada projektowi.

### 3. Obserwacja z obu końców

Ustaw URL kontrolowanego endpointu, a następnie zażądaj unikalnej, nieszkodliwej ścieżki:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Użyj domeny kontrolowanej przez testera, uwierzytelnionego TLS i nietrażliwej ścieżki z tokenem. Sprawdź log serwera pod kątem:

- adresu źródłowego/ASN i oczekiwanego egress;
- IPv4 versus IPv6;
- zachowania Host/SNI widocznego w endpoint;
- user agenta i nagłówków aplikacji;
- dokładnego czasu i ponownego użycia requestu.

Nie dodawaj `X-Forwarded-For`, unikalnych nagłówków debugowania ani cookies zawierających tożsamość do rzekomo odseparowanego requestu.

### 4. Test DNS z użyciem własnego canary

Skonfiguruj autorytatywną testową strefę, której query logi kontrolujesz. Wykonaj zapytanie o unikalną losową etykietę przez compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Sprawdź autorytatywny log. Zwykle widzi on recursive resolver, a niekoniecznie klienta. Porównaj ten resolver z zamierzoną architekturą DNS dla VPN/Tor/aplikacji. Losowa publiczna strona do wykrywania DNS leak nie jest wymagana.

### 5. Testowanie zachowania fail-closed

Utrzymuj benign request loop skierowaną do należącego do Ciebie endpointu, a następnie zatrzymaj ścieżkę prywatności. Obciążenie musi zakończyć się błędem, zamiast przełączyć się na interfejs fizyczny. Sprawdź obie rodziny adresów oraz DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Powtórz podczas:

- awarii procesu tunelu;
- przełączenia z Wi-Fi na Ethernet lub hotspot;
- uśpienia/wybudzenia;
- odnowienia DHCP;
- zmiany stanu captive portalu;
- ponownego połączenia z providerem/wygaśnięcia klucza.

W przypadku Linux namespace/container zatrzymaj jego tunel i sprawdź, czy nie ma on innej domyślnej trasy ani resolvera:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Nazwy i polecenia różnią się w zależności od deploymentu. Nie wklejaj ich na zdalny production host bez możliwości odzyskania dostępu przez konsolę.

### 6. Inspekcja lokalnych socketów i pakietów

Za autoryzacją sprawdź, który proces/interfejs faktycznie się komunikuje:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Zastąp `TEST_SERVER_IP` jawnym, należącym do Ciebie adresem; unikaj szerokiego przechwytywania danych niezwiązanych użytkowników. Interfejs fizyczny powinien widzieć peer tunelu/bridge, a ruch z jawnym adresem docelowym powinien występować wyłącznie na zamierzonej warstwie.

## Test Tor i onion-service

1. W Tor Browser odwiedź stronę sprawdzania połączenia Tor Project i potwierdź użycie Tor. Nie traktuj tego jako dowodu tożsamości.<sup>[[1]](#references)</sup>
2. Odwiedź należący do Ciebie endpoint HTTPS z unikalnym canary i potwierdź, że widzi wyjście Tor, brak identyfikujących cookies oraz standardowy kontekst przeglądarki.
3. Wybierz **New Identity**, odwiedź stronę ponownie z innym canary i sprawdź, czy lokalny stan został wyczyszczony zgodnie z oczekiwaniami. Zmiana exit IP nie jest gwarantowana ani nie stanowi celu funkcji New Identity.
4. W przypadku onion service uzyskuj do niego dostęp wyłącznie przez Tor Browser. Potwierdź autoryzowanym skanem zewnętrznym, że host usługi nie ma publicznego listenera, oraz że odpowiedzi aplikacji nie zawierają publicznej nazwy hosta/IP.
5. Sprawdź wychodzący DNS/HTTP originu, templates, strony błędów, e-maile/webhooki oraz zasoby third-party. Każde bezpośrednie pobranie może ujawnić origin lub konto operatora.
6. Jeśli włączono autoryzację klienta, potwierdź, że niezalogowany, czysty Tor Browser nie może się połączyć, a zalogowany może.
7. Zmień testowy klucz autoryzacyjny i potwierdź, że cofnięcie dostępu pozbawia klienta dostępu bez zmiany tożsamości onion.

## Test separacji przeglądarek

Utwórz kontrolowaną stronę, która rejestruje wyłącznie pola potrzebne do testu, z krótkim okresem przechowywania. Porównaj osobiste i prywatnościowe compartments pod kątem:

- cookies/local storage/service workers i cache;
- stanu synchronizacji/logowania przeglądarki;
- języka, strefy czasowej, wymiarów ekranu/okna i fonts;
- kandydatów WebRTC/network;
- uprawnień i modyfikacji widocznych dla extensions;
- danych user-agent TLS/HTTP na serwerze.

Nie próbuj sprawiać, aby Tor Browser był „bardziej losowy”. Warunkiem zaliczenia jest podobieństwo do jego standardowego anonymity set oraz brak osobistego stanu, a nie maksymalna różnica względem osobistej przeglądarki.

Przetestuj kopiowanie/wklejanie, przeciąganie i upuszczanie, otwieranie pobranych plików, sugestie password-managera oraz przyciski identity-providerów. Są to częste bridges między compartments.

## Test izolacji systemu operacyjnego

### Tails

1. Rozpocznij od nieszkodliwego pliku/canary w sesji bez Persistent Storage.
2. Całkowicie zamknij system, uruchom go ponownie i potwierdź, że plik zniknął.
3. Włącz tylko jedną wymaganą kategorię persistence, powtórz test i potwierdź, że niezwiązany stan przeglądarki/aplikacji nie jest zachowywany.
4. Sprawdź, czy Unsafe Browser nie może być używany po zalogowaniu do portalu w celu wykonywania wrażliwych działań oraz czy aplikacje Tor łączą się ponownie prawidłowo.

### Whonix/Qubes

1. Zatrzymaj Gateway/net qube i udowodnij, że Workstation/app qube nie może uzyskać dostępu do IPv4, IPv6 ani DNS.
2. Podejmij próbę użycia wyłącznie jawnie skonfigurowanej ścieżki clipboard/file między qubes i potwierdź, że inne ścieżki współdzielonych folderów/urządzeń są niedostępne.
3. Otwórz nieszkodliwy dokument testowy w disposable qube, zamknij go i potwierdź, że jego stan znika.
4. Sprawdź, czy vault qube nie ma NetVM i nie może go uzyskać poprzez zmianę template/default.
5. Utwórz snapshot/przywróć testową VM i sprawdź, czy stan zawierający tożsamość nie powraca nieoczekiwanie.

## Test metadanych komunikacji

Dla każdego wybranego messengera:

1. Utwórz przeznaczonych wyłącznie do testów uczestników na kontrolowanych urządzeniach.
2. Zapisz, czego wymaga rejestracja: telefonu, konta app-store, IP, usługi push, username lub invitation.
3. Wyślij jedną nieszkodliwą wiadomość, sprawdzając previews powiadomień, połączone desktopy, wearables i backupy.
4. Zweryfikuj kody safety/security niezależną ścieżką.
5. Wyłącz receipts/push lub włącz transporty Tor/local pojedynczo i obserwuj zmiany niezawodności/metadanych.
6. Wyeksportuj lub przywróć testowy backup i dokładnie udokumentuj, jaki profil, kontakty oraz historię zawiera.
7. Utrać/cofnij dostęp testowego urządzenia i potwierdź, że pozostali uczestnicy widzą oczekiwaną zmianę klucza/urządzenia.

Nie testuj poprzez kontaktowanie się z osobami niezwiązanymi z testem ani generowanie abusive traffic.

## Test sanitizacji plików

1. Oblicz hash i zachowaj oryginał w zaszyfrowanym magazynie dowodów:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Utwórz oczyszczoną kopię, korzystając z procesu specyficznego dla danego formatu opisanego w [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md).
3. Porównaj inwentarze metadanych:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Wyrenderuj/otwórz kopię w jednorazowym środowisku. Sprawdź ukrytą zawartość, załączniki, linki, formularze, warstwy, miniatury i identyfikatory wizualne.
5. Przeszukaj wyłącznie kopię przygotowaną do publikacji pod kątem znanych ciągów canary autora/adresu e-mail/ścieżki.
6. Oblicz hash finalnego wyniku i poproś drugą osobę o zweryfikowanie dokładnego pliku przeznaczonego do publikacji.

Brak danych w wyjściu ExifTool nie jest dowodem anonimowości; wewnętrzne struktury formatu, piksele, treść prozą i rejestry dystrybucji nadal pozostają.

## Test prywatności płatności

Użyj najmniejszej dozwolonej kwoty lub oficjalnej sieci testowej/sandboxa:

1. Zapisz oczekiwany widok dla płatnika, odbiorcy/sprzedawcy, emitenta/giełdy, sieci/węzła, publicznego rejestru i księgowego/administratora.
2. Utwórz unikalny kontekst testowej faktury/sprzedawcy bez fałszywej tożsamości.
3. Zapłać raz, a następnie zbierz **własne** potwierdzenie, wyciąg, panel sprzedawcy, log portfela/węzła oraz widok publicznego łańcucha, jeśli ma zastosowanie.
4. Sprawdź, czy kwota, znacznik czasu, adres/token, konto, IP/urządzenie, dostawa i ścieżka zwrotu odpowiadają tabeli obserwatorów.
5. W przypadku Bitcoin sprawdź ponowne użycie adresu, wybrane wejścia, resztę oraz późniejszą konsolidację w widoku coin-control portfela.
6. W przypadku protokołów shielded zweryfikuj faktyczną pulę/ścieżkę oraz to, co ujawnia viewing key; nie wnioskuj o prywatności na podstawie brandingu portfela.
7. W przypadku e-cash/Taler przetestuj backup/odzyskiwanie, zwrot i realizację przy niewielkiej wartości; udokumentuj rejestry granic mint/exchange/federation.
8. Unieważnij wirtualną kartę/testowe dane uwierzytelniające i potwierdź, że późniejsza autoryzacja kończy się niepowodzeniem, jednocześnie upewniając się, że prawidłowa obsługa zwrotu pozostaje zrozumiała.
9. Uzgodnij i zachowaj wymagane dowody podatkowe/autoryzacyjne w formie zaszyfrowanej.

Nigdy nie twórz transferów cyrkularnych, dzielenia transakcji w celu obejścia progów, fałszywych zakupów ani podejrzanych zwrotów jako „testu prywatności”.

## Ćwiczenie rozliczalności autoryzowanego red-team

Przed ćwiczeniem przeprowadź ćwiczenie tabletop i drill techniczny:

1. Operator uruchamia nieszkodliwy canary z każdej zatwierdzonej ścieżki źródłowej.
2. Docelowy SOC rejestruje to, co wykrywa, bez otrzymywania tożsamości operatora, jeśli planowane jest blind testing.
3. Kontroler ćwiczenia ustala źródło → zaangażowanie → operatora na podstawie mapy przechowywanej w escrow oraz podpisanego rekordu zadania.
4. Kontroler wysyła polecenie awaryjnego zatrzymania; operator i właściciel infrastruktury demonstrują wyłączenie w czasie określonym w ROE.
5. Dział abuse dostawcy otrzymuje właściwy kontakt 24/7 oraz numer referencyjny autoryzacji.
6. Dowody wskazują cel, czas, narzędzie/zadanie i operatora bez przechowywania zbędnej treści payloadu.
7. Drugi operator weryfikuje unieważnienie danych uwierzytelniających i usunięcie zasobów.

Nie zaliczaj przeglądu gotowości, jeśli SOC może z łatwością zobaczyć osobistą/domową infrastrukturę **LUB** jeśli kontroler nie może szybko przypisać źródła do odpowiedzialnej osoby i je zatrzymać.

## Szablon rekordu testu
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

- [1] [Tor Project — Sprawdzanie połączenia](https://check.torproject.org/)
- [2] [WireGuard — Routing i przestrzenie nazw sieci](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ i wytyczne dotyczące metadanych](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Przewodnik techniczny po testowaniu i ocenie bezpieczeństwa informacji](https://csrc.nist.gov/pubs/sp/800/115/final)
