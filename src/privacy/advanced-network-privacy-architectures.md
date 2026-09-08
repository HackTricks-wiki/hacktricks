# Zaawansowane architektury prywatności sieciowej

{{#include ../banners/hacktricks-training.md}}

Złożoność jest użyteczna tylko wtedy, gdy eliminuje konkretnego obserwatora lub tryb awarii. Unikalny stos tuneli, niestandardowy kształt pakietów, rzadki user agent lub często zmieniająca się infrastruktura mogą stać się silniejszym fingerprintem niż standardowa konfiguracja używana przez tysiące osób.

Katalog [technik anonimowego dostępu do Internetu](anonymous-internet-access-techniques.md) dostarcza wspólny schemat `Pros`/`Cons`/`Procedure`/`Detection`. Ta strona rozwija bardziej złożone architektury i granice zaufania.

Zaawansowanym celem jest zatem **rozdzielenie wiedzy**: żaden zwykły komponent nie powinien jednocześnie posiadać tożsamości użytkownika, celu, plaintextu i długoterminowej historii aktywności. Nie zapewnia to niewidoczności, a koluzja, procedury prawne, compromise endpointu lub korelacja ruchu end-to-end nadal mogą odtworzyć ścieżkę.

## Wybór architektury

| Wzorzec | Uzyskana właściwość | Nowe zaufanie/awaria | Odpowiednie zastosowanie |
|---|---|---|---|
| Standardowy Tor Browser | Wspólny fingerprint przeglądarki i ścieżka przez wiele relayów | Niskie opóźnienia umożliwiają korelację ruchu | Ogólne anonimowe przeglądanie sieci |
| Tor bridge + pluggable transport | Utrudnia bezpośrednie blokowanie/klasyfikowanie Tor | Bridge/transport nadal może zostać wykryty; bridge poznaje źródło | Sieci objęte cenzurą |
| Onion service | Ukrywa IP usługi; eliminuje exit; uwierzytelnia tożsamość onion | Klucz onion i endpoint serwera stają się krytycznymi zasobami | Prywatne publikowanie, przyjmowanie danych lub administracja |
| Niezależne relay’e ingress + egress | Żaden pojedynczy relay zazwyczaj nie widzi źródła i celu | Operatorzy mogą współpracować; timing obejmuje oba elementy | Wspierane aplikacje o wysokiej wydajności |
| Oblivious HTTP | Oddziela źródłowy adres IP od zaszyfrowanego bezstanowego żądania HTTP | Wymaga wsparcia aplikacji, relaya i gatewaya | Telemetria, zapytania, przesyłanie danych bez stanu sesji |
| Namespace workloadu tylko przez VPN | Wymuszany przez kernel brak trasy do clear-network | VPN nadal widzi oba końce; host/root pozostaje zaufany | Narzędzia do autoryzowanych działań i stały egress |
| Jednorazowa zdalna przeglądarka | Cel jest odizolowany od lokalnej przeglądarki/endpointu | Dostawca workspace widzi aktywność i tożsamość logowania | Niezaufane witryny/pliki i kontrolowane badania |
| Wewnętrzna usługa I2P | Oddzielne tunele overlay dla ruchu przychodzącego/wychodzącego; brak oficjalnych exitów | Mniejszy/odmienny ekosystem; zachowanie peerów działających długoterminowo | Usługi natywne dla I2P, a nie zamiennik zwykłej sieci |
| Mixnet/asynchroniczne dostarczanie | Opóźnienia, batchowanie i cover traffic utrudniają analizę timingu | Wysokie opóźnienia, ograniczona liczba aplikacji i dojrzałość | Wiadomości/zadania, które nie wymagają interakcji |

## Relaye z podzieloną wiedzą

Wzorzec relayów obsługiwanych przez dwóch operatorów może przewyższać pojedynczy VPN w przypadku wąskiej aplikacji:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay jest wdrożonym przykładem: Apple obsługuje ingress, a inny dostawca treści obsługuje egress, dlatego żaden z nich zwykle nie widzi jednocześnie adresu IP klienta i celu przeglądania.<sup>[[1]](#references)</sup> Jest to usługa prywatności Safari/DNS specyficzna dla produktu, a nie działająca na wszystkich urządzeniach sieć anonimowa; celowo zachowuje przybliżony region.

Oblivious HTTP (OHTTP) standaryzuje węższy wzorzec aplikacyjny. Relay widzi klienta i zaszyfrowany ruch do gatewaya; gateway odszyfrowuje wiadomość HTTP, ale widzi relay, a nie klienta. RFC 9458 ostrzega, że rozwiązanie wymaga obsługi po stronie relay/gateway, najlepiej nadaje się do żądań bez cookies, uwierzytelniania i stanu sesji oraz nie obejmuje analizy ruchu swoimi gwarancjami.<sup>[[2]](#references)</sup>

### Lista kontrolna projektu

1. Zdefiniuj dokładne komunikaty aplikacji, które mają być chronione; nie proxyuj po cichu dowolnych uwierzytelnionych sesji webowych.
2. W miarę możliwości używaj niezależnie zarządzanych organizacji ingress i egress, z oddzielną administracją, poświadczeniami, logowaniem i kontrolą prawną.
3. Szyfruj żądanie aplikacji do gatewaya, aby ingress nie mógł go odczytać.
4. Usuń pochodzące od klienta nagłówki przekazywania, identyfikatory TLS i stabilne tokeny użytkownika na odpowiedniej warstwie.
5. Unikaj unikalnych kluczy, cookies lub pól payloadu, które pozwalają gatewayowi ponownie powiązać żądania mimo separacji transportu.
6. Agreguj, minimalizuj i wygaszaj logi po obu stronach; udokumentuj ryzyko koluzji i wymuszonego ujawnienia.
7. Stosuj padding lub batching wyłącznie zgodnie z przejrzanym protokołem. Własnoręczne kształtowanie ruchu może utworzyć unikalny podpis bez zatrzymania korelacji.
8. Testuj za pomocą kontrolowanych żądań canary i porównuj, co rejestrują klient, ingress, gateway i cel.

Do zwykłego interaktywnego przeglądania używaj Tor Browser zamiast tworzyć własne prywatne proxy OHTTP. OHTTP chroni obsługiwaną transakcję aplikacyjną, a nie pełną tożsamość przeglądarki.

## Wymuszanie trasy dla workloadu

Kill switch oparty wyłącznie na zmiennych trasach hosta może zawieść podczas odnowienia DHCP, uśpienia/wybudzenia, zmian IPv6 lub awarii tunelu. Silniejszy wzorzec Linux zapewnia kontenerowi lub network namespace wyłącznie interfejs loopback i interfejs tunelu. WireGuard dokumentuje, że interfejs można utworzyć w fizycznym namespace, przenieść do namespace workloadu i zachować jego zaszyfrowany socket UDP w oryginalnym namespace.<sup>[[3]](#references)</sup>

### Wzorzec wdrożenia

1. Najpierw zbuduj to na jednorazowym hoście lub hoście z lokalną konsolą; błędy w namespace mogą usunąć zdalny dostęp.
2. Umieść fizyczny interfejs Ethernet/Wi-Fi oraz DHCP/supplicant w namespace **physical**.
3. Utwórz tam interfejs WireGuard, aby jego zaszyfrowany socket transportowy miał dostęp do sieci fizycznej.
4. Przenieś wyłącznie interfejs WireGuard do namespace **workload** i ustaw go jako jedyną trasę domyślną.
5. Przydziel workloadowi resolver specyficzny dla namespace, osiągalny wyłącznie przez tunel. Uwzględnij jawnie IPv6.
6. Uruchom kontener przeglądarki/narzędzia w tym namespace, bez host networking, uprzywilejowanych capabilities, współdzielonego katalogu przeglądarki lub osobistego agenta poświadczeń.
7. Zatrzymaj tunel i sprawdź, czy workload nie może rozwiązać nazwy ani połączyć się z kontrolowanym endpointem IPv4 lub IPv6.
8. Przetestuj roaming endpointu, odnowienie DHCP, suspend/resume i obsługę captive portalu poza namespace workloadu.
9. Loguj hash konfiguracji namespace/tunelu oraz zatwierdzony adres egress na potrzeby rozliczalności engagementu.

Zapewnia to **wymuszanie trasy**, a nie anonimowość wobec VPN lub bastionu engagementu. Zaatakowany host/root może sprawdzać lub zmieniać namespaces.

## Mosty Tor i pluggable transports

Bridges to niepubliczne relay wejściowe Tor. Pluggable transports zmieniają ruch pierwszego skoku, przez co proste blokowanie lub klasyfikacja protokołu stają się trudniejsze. Nie dodają anonimowych warstw relay po wejściu i nie pokonują obserwatora zdolnego do szerszej korelacji czasowej.

| Transport | Podejście dla pierwszego skoku | Praktyczny kompromis |
|---|---|---|
| **obfs4** | Sprawia, że ruch wygląda losowo, i jest odporny na aktywne sondowanie | Znany adres bridge nadal może zostać zablokowany |
| **Snowflake** | Używa krótkotrwałych, ochotniczych proxy WebRTC do dotarcia do bridge | Wydajność się zmienia; występują wzorce brokera/STUN/WebRTC |
| **WebTunnel** | Przenosi ruch bridge w tunelu WebSocket podobnym do HTTPS | Zależy od osiągalnego web frontu i nadal może być klasyfikowany |

Tor Project opisuje Snowflake i WebTunnel jako transporty do omijania cenzury, a nie jako rozwiązania zapewniające idealną nieodróżnialność.<sup>[[4]](#references)</sup>

### Bezpieczny workflow

1. Zacznij od bezpośredniego połączenia Tor Browser. Dodaj bridge tylko wtedy, gdy blokowanie lub widoczność w modelu lokalnego obserwatora to uzasadniają.
2. Używaj wbudowanych transportów lub linii bridge uzyskanych kanałami Tor Project. Nie pobieraj losowych binariów transportów ani publicznych list bridge z forów.
3. Wypróbuj najmniej złożoną obsługiwaną opcję, która łączy się niezawodnie; zapisz powód jej wyboru.
4. Pozostaw Tor Browser poza tym w standardowej konfiguracji. Bridge nie sprawia, że niestandardowe rozszerzenia, logowanie do kont lub nietypowe ustawienia przeglądarki stają się bezpieczne.
5. Przetestuj ponowne połączenie i poprawność zegara. Nie przełączaj wielokrotnie transportów w sposób wysyłający charakterystyczną sekwencję do tego samego lokalnego obserwatora.
6. Ponownie oceń sytuację, jeśli zmieni się cenzor lub polityka sieci; użycie może być w niektórych lokalizacjach wrażliwe lub ograniczone.

## Onion services jako prywatny punkt spotkania

Onion service tworzy wychodzące obwody Tor do punktów introdukcji i relay rendezvous, dlatego nie potrzebuje publicznego portu przychodzącego i nie ujawnia adresu IP serwera przez protokół onion. Ruch klient-usługa pozostaje wewnątrz Tor, a adres onion uwierzytelnia klucz usługi.<sup>[[5]](#references)</sup>

Dla zgodnego z prawem portalu przyjmowania danych, prywatnego repozytorium, interfejsu administracyjnego lub miejsca przekazywania dowodów z engagementu:

1. Uruchom aplikację na dedykowanym hoście/VM i przypisz ją do loopback lub izolowanego socketu Unix.
2. Zainstaluj Tor z oficjalnego repozytorium i postępuj zgodnie z oficjalną konfiguracją usługi onion v3; nigdy nie używaj przestarzałych instrukcji v2.
3. Chroń prywatny klucz usługi onion jak klucz TLS/signing. Twórz jego kopię zapasową tylko wtedy, gdy wymagana jest stabilna tożsamość.
4. Dodaj autoryzację klienta usługi onion dla zamkniętej grupy i przekaż poświadczenia niezależnie uwierzytelnionym kanałem.<sup>[[6]](#references)</sup>
5. Nie pozwól originowi pobierać zewnętrznych fontów, analytics, aktualizacji ani webhooków, które ujawniają jego publiczny adres IP lub konto operatora.
6. Dodaj uwierzytelnianie i autoryzację również w aplikacji; posiadanie adresu onion nie jest kontrolą dostępu.
7. Aktualizuj, ograniczaj rate i monitoruj usługę bez osadzania telemetryki stron trzecich.
8. Z oddzielnego kontekstu testowego potwierdź, że DNS, email, strony błędów, metadane plików i nagłówki odpowiedzi nie ujawniają originu.
9. Na potrzeby red team umieść usługę, właściciela, cel i czas wyłączenia w ROE. Nie używaj jej do ukrywania C2 poza zakresem.

## Zdalna przeglądarka i jednorazowy workspace

Zdalna przeglądarka przenosi renderowanie i ryzykowną treść poza lokalny endpoint oraz może udostępniać egress chmurowy specyficzny dla engagementu. Chroni lokalne urządzenie przed częścią treści i utrwaleniem, ale nie czyni operatora anonimowym wobec dostawcy workspace. AWS na przykład dokumentuje zbieranie danych portalu, tożsamości, polityk, preferencji i logów sesji, nawet jeśli jednorazowa instancja przeglądarki jest usuwana po zakończeniu sesji.<sup>[[7]](#references)</sup>

Używaj jednego workspace kontrolowanego przez organizację na engagement, ograniczaj pobieranie/wysyłanie i schowek, wyłącz osobistych dostawców tożsamości, kieruj jego stały egress przez zatwierdzony bastion i wygaszaj workspace po eksporcie dowodów. Traktuj konsolę dostawcy, IdP i administratora jako obserwatorów.

## I2P i wewnętrzne overlay

I2P tworzy oddzielne jednokierunkowe tunele przychodzące i wychodzące oraz nie ma oficjalnych exitów na poziomie sieci; jest przeznaczone głównie dla usług wewnątrz I2P.<sup>[[8]](#references)</sup> Nie jest szybszym rozwiązaniem typu drop-in do przeglądania publicznego Internetu. Outproxy wprowadzają punkt zaufania, a oficjalny model zagrożeń wyraźnie wymaga dalszych badań i nie twierdzi, że zapewniają idealną anonimowość.

Używaj I2P tylko wtedy, gdy oba końce celowo je obsługują, izoluj jego długotrwały router od osobistych aplikacji i rozumiej, że peery/lokalne sieci mogą obserwować uczestnictwo w I2P. Nie zwiększaj liczby hopów ani nie dostrajaj wyboru peerów bez dowodów: nietypowe ustawienia mogą obniżyć wydajność i zmniejszyć zbiór anonimowości.

## Operacje odporne na korelację

- Preferuj wspólną, obsługiwaną konfigurację klienta zamiast unikalnego buildu.
- Oddzielaj tożsamości na endpointcie; żadna topologia routingu nie naprawi ponownego użycia konta, płatności, odzyskiwania ani treści.
- W zadaniach nieinteraktywnych preferuj przejrzany protokół asynchroniczny/mixnet zamiast ręcznego dodawania opóźnień lub sztucznego ruchu.
- Unikaj prowadzenia rzekomo oddzielnych tożsamości w zsynchronizowany sposób z tego samego kontekstu fizycznego.
- Używaj jednokierunkowej bramki eksportu: niezaufana treść trafia do jednorazowego renderera; na zewnątrz wychodzi tylko przejrzany, oczyszczony rezultat.
- Utrzymuj poprawny czas na potrzeby bezpieczeństwa protokołu, ale usuwaj niepotrzebnie precyzyjne znaczniki czasu z publikowanych artefaktów.
- Minimalizuj czas trwania sesji i przestarzałą infrastrukturę bez szybkiej rotacji typu „fast-flux”, która jest zauważalna i szkodzi rozliczalności.

## Techniki, które nie mogą wykorzystywać niezaangażowanych stron trzecich

Są to rzeczywiste techniki adversary, a nie wyimaginowane lub nieistotne. Ich mechanika i wykrywanie zostały opisane w [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) oraz [APT case studies](government-and-apt-case-studies.md). Podczas autoryzowanego ćwiczenia odtwarzaj ich obserwowalne zachowanie za pomocą posiadanych substytutów:

- modeluj rotację residential/mobile exit za pomocą kontrolowanych pul relay, nigdy za pomocą rynków o niejasnej zgodzie;
- modeluj open proxy, przejęte routery i botnety za pomocą posiadanych VM/routerów;
- modeluj skradzione konta chmurowe za pomocą wyznaczonego tenanta ćwiczeniowego i syntetycznej tożsamości ofiary;
- modeluj domain fronting na posiadanym reverse proxy zamiast na niechętnym CDN;
- modeluj zewnętrzne Wi-Fi za pomocą dwóch izolowanych AP należących do laboratorium;
- traktuj własne szyfrowanie, łańcuchy multi-VPN i rotację identyfikatorów jako hipotezy testowe, których przepływ oraz artefakty konta i endpointu pozostają wykrywalne.

W przypadku autoryzowanego red team każda próba zmniejszenia rozpoznawalności ruchu musi być wyraźnym celem detekcji w ROE, mieć mapę atrybucji przechowywaną przez kontrolera oraz obejmować mechanizm zatrzymania/dekonflikcji.

## Macierz weryfikacji

| Test | Oczekiwany rezultat | Znaczenie niepowodzenia |
|---|---|---|
| Zatrzymanie tunelu/bridge | Workload nie ma bezpośredniej ścieżki IPv4/IPv6/DNS | Wymuszanie trasy jest niepełne |
| Sprawdzenie logu celu | Pojawia się wyłącznie zaplanowana tożsamość egress/aplikacji | Header, route lub account leak |
| Sprawdzenie logu ingress | Źródło jest obecne; brak jawnego celu/żądania | Podział zaufania nie zadziałał na ingress |
| Sprawdzenie logu egress | Relay/żądanie jest obecne; brak tożsamości źródła | Podział zaufania nie zadziałał na egress |
| Zewnętrzne skanowanie originu onion | Nie można osiągnąć ani powiązać publicznej usługi originu | Origin został ujawniony lub jest dual-homed |
| Zakończenie jednorazowej sesji | Stan instancji zniknął; zatwierdzone dowody zachowano oddzielnie | Granica utrwalania nie zadziałała |
| Wykonanie wyszukania u kontrolera | Działanie jest szybko mapowane do engagementu/operatora | Rozliczalność red team nie zadziałała |

## References

- [1] [Apple Platform Security — bezpieczeństwo iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing i Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake i pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Jak działają Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Zaawansowane ustawienia Onion Service i autoryzacja klienta](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Szyfrowanie danych w Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Model zagrożeń](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
