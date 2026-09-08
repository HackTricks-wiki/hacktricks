# Zaawansowane architektury prywatności sieciowej

Złożoność jest użyteczna tylko wtedy, gdy eliminuje konkretnego obserwatora lub tryb awarii. Unikalny stack tuneli, niestandardowy kształt pakietów, rzadki user agent lub często zmieniająca się infrastruktura mogą stać się silniejszym fingerprintem niż standardowa konfiguracja używana przez tysiące osób.

[Katalog technik anonimowego dostępu do Internetu](anonymous-internet-access-techniques.md) zapewnia wspólny schemat `Pros`/`Cons`/`Procedure`/`Detection`. Ta strona rozwija bardziej złożone architektury i granice zaufania.

Zaawansowanym celem jest zatem **rozdzielenie wiedzy**: żaden zwykły komponent nie powinien jednocześnie posiadać tożsamości użytkownika, celu, plaintextu i długoterminowej historii aktywności. Nie zapewnia to niewidoczności, a zmowa, postępowanie prawne, kompromitacja endpointu lub korelacja ruchu end-to-end nadal mogą odtworzyć ścieżkę.

## Wybór architektury

| Wzorzec | Uzyskana właściwość | Nowe zaufanie/awaria | Odpowiednie zastosowanie |
|---|---|---|---|
| Standard Tor Browser | Wspólny fingerprint przeglądarki i ścieżka przez wiele relayów | Niskie opóźnienia umożliwiają korelację ruchu | Ogólne anonimowe przeglądanie sieci |
| Tor bridge + pluggable transport | Utrudnia bezpośrednie blokowanie/klasyfikowanie Tor | Bridge/transport nadal może zostać wykryty; bridge zna źródło | Sieci objęte cenzurą |
| Onion service | Ukrywa IP usługi; unika exit; uwierzytelnia tożsamość onion | Klucz onion i endpoint serwera stają się krytycznymi zasobami | Prywatne publikowanie, przyjmowanie danych lub administracja |
| Niezależne relay'e ingress + egress | Żaden pojedynczy relay zwykle nie widzi jednocześnie źródła i celu | Operatorzy mogą współpracować; timing przechodzi przez oba | Wspierane aplikacje o wysokiej wydajności |
| Oblivious HTTP | Oddziela źródłowy adres IP od zaszyfrowanego bezstanowego żądania HTTP | Wymaga wsparcia aplikacji, relaya i gatewaya | Telemetria, zapytania i przesyłanie danych bez stanu sesji |
| Przestrzeń nazw workloadu wyłącznie przez VPN | Wymuszony przez kernel brak trasy do clear-network | VPN nadal widzi oba końce; host/root pozostaje zaufany | Autoryzowane narzędzia do engagementów i stały egress |
| Disposable remote browser | Cel jest odizolowany od lokalnej przeglądarki/endpointu | Provider workspace widzi aktywność i tożsamość logowania | Niezaufane witryny/pliki i kontrolowane badania |
| Wewnętrzna usługa I2P | Oddzielne tunele overlay dla ruchu przychodzącego/wychodzącego; brak oficjalnych exitów | Mniejszy/inny ekosystem; zachowanie peerów utrzymywane przez długi czas | Usługi natywne dla I2P, a nie zamiennik zwykłego webu |
| Mixnet/asynchroniczne dostarczanie | Opóźnienia, batching i cover traffic utrudniają analizę timingu | Wysokie opóźnienia, ograniczona liczba aplikacji i dojrzałość | Wiadomości/zadania, które nie wymagają interakcji |

## Relay'e z podzieloną wiedzą

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
Apple Private Relay jest wdrożonym przykładem: Apple obsługuje ingress, podczas gdy inny dostawca treści obsługuje egress, więc żaden z nich zazwyczaj nie widzi jednocześnie adresu IP klienta i miejsca docelowego przeglądania.<sup>[[1]](#references)</sup> Jest to usługa prywatności Safari/DNS specyficzna dla produktu, a nie działająca na wszystkich urządzeniach sieć anonymity, i celowo zachowuje przybliżony region.

Oblivious HTTP (OHTTP) standaryzuje węższy wzorzec aplikacyjny. Relay widzi klienta i zaszyfrowany ruch do gatewaya; gateway odszyfrowuje komunikat HTTP, ale widzi relay, a nie klienta. RFC 9458 ostrzega, że rozwiązanie wymaga obsługi po stronie relay/gateway, najlepiej nadaje się do żądań bez cookies, authentication i session state oraz nie obejmuje traffic analysis swoimi gwarancjami.<sup>[[2]](#references)</sup>

### Lista kontrolna projektu

1. Zdefiniuj dokładne komunikaty aplikacji, które mają być chronione; nie proxyuj po cichu dowolnych uwierzytelnionych sesji webowych.
2. W miarę możliwości używaj niezależnie zarządzanych organizacji ingress i egress, z oddzielną administracją, credentials, loggingiem i kontrolą prawną.
3. Szyfruj żądanie aplikacji do gatewaya, aby ingress nie mógł go odczytać.
4. Usuń pochodne od klienta nagłówki przekierowania, identyfikatory TLS i stabilne tokeny per-user na odpowiedniej warstwie.
5. Unikaj unikalnych kluczy, cookies lub pól payloadu, które pozwalałyby gatewayowi ponownie powiązać żądania pomimo separacji transportu.
6. Agreguj, minimalizuj i wygaszaj logi po obu stronach; udokumentuj ryzyko koluzji i wymuszonego ujawnienia danych.
7. Wykonuj padding lub batching wyłącznie zgodnie z przeanalizowanym protokołem. Własnoręczne traffic shaping może utworzyć unikalny signature bez zatrzymania korelacji.
8. Testuj za pomocą kontrolowanych żądań canary i porównuj, co rejestrują klient, ingress, gateway i target.

Do zwykłego interaktywnego przeglądania używaj Tor Browser zamiast tworzyć własny prywatny proxy OHTTP. OHTTP chroni obsługiwaną transakcję aplikacyjną, a nie pełną tożsamość przeglądarki.

## Wymuszanie trasy per workload

Kill switch oparty wyłącznie na zmiennych trasach hosta może zawieść podczas odnowienia DHCP, uśpienia/wybudzenia, zmian IPv6 lub awarii tunelu. Silniejszy wzorzec dla Linux zapewnia kontenerowi lub network namespace wyłącznie interfejs loopback i interfejs tunelu. WireGuard dokumentuje, że interfejs można utworzyć w physical namespace, przenieść do workload namespace i zachować jego zaszyfrowane UDP socket w pierwotnym namespace.<sup>[[3]](#references)</sup>

### Wzorzec wdrożenia

1. Najpierw zbuduj to na disposable/local-console hoście; błędy w namespace mogą usunąć zdalny dostęp.
2. Umieść fizyczny interfejs Ethernet/Wi-Fi oraz DHCP/supplicant w **physical** namespace.
3. Utwórz tam interfejs WireGuard, aby jego zaszyfrowany socket transportowy miał dostęp do sieci fizycznej.
4. Przenieś wyłącznie interfejs WireGuard do **workload** namespace i ustaw go jako jedyną trasę domyślną.
5. Przydziel workloadowi resolver właściwy dla namespace, osiągalny wyłącznie przez tunel. Uwzględnij jawnie IPv6.
6. Uruchom kontener browser/tool w tym namespace bez host networking, privileged capability, współdzielonego katalogu przeglądarki ani personal credential agenta.
7. Zatrzymaj tunel i sprawdź, czy workload nie może rozwiązać ani połączyć się z kontrolowanym endpointem IPv4 lub IPv6.
8. Przetestuj roaming endpointu, odnowienie DHCP, suspend/resume i obsługę captive portalu poza workload namespace.
9. Loguj hash konfiguracji namespace/tunelu oraz zatwierdzony adres egress na potrzeby rozliczalności engagementu.

Zapewnia to **wymuszanie trasy**, a nie anonymity wobec VPN lub bastionu engagementu. Zaatakowany host/root może sprawdzać lub zmieniać namespaces.

## Bridges Tor i pluggable transports

Bridges to niepubliczne relays wejściowe Tor. Pluggable transports modyfikują ruch pierwszego skoku, aby utrudnić proste blokowanie lub klasyfikację protokołu. Nie dodają anonimowych warstw relay po wejściu i nie pokonują obserwatora zdolnego do szerszej korelacji czasowej.

| Transport | Podejście pierwszego skoku | Praktyczny kompromis |
|---|---|---|
| **obfs4** | Sprawia, że ruch wygląda losowo i odpiera aktywne sondowanie | Znany adres bridge nadal może zostać zablokowany |
| **Snowflake** | Używa krótkotrwałych ochotniczych proxy WebRTC do dotarcia do bridge | Wydajność się zmienia; występują wzorce brokera/STUN/WebRTC |
| **WebTunnel** | Przenosi ruch bridge w tunelu WebSocket podobnym do HTTPS | Zależy od osiągalnego web frontu i nadal może być klasyfikowany |

Tor Project opisuje Snowflake i WebTunnel jako transporty do omijania cenzury, a nie jako rozwiązania zapewniające idealną nieodróżnialność.<sup>[[4]](#references)</sup>

### Bezpieczny workflow

1. Zacznij od bezpośredniego połączenia Tor Browser. Dodaj bridge tylko wtedy, gdy blokowanie lub widoczność w lokalnym modelu obserwatora to uzasadnia.
2. Używaj wbudowanych transportów lub linii bridge uzyskanych kanałami Tor Project. Nie pobieraj losowych binariów transportów ani publicznych list bridge z forów.
3. Wypróbuj najmniej złożoną obsługiwaną opcję, która łączy się niezawodnie; zapisz powód jej wyboru.
4. Poza tym pozostaw Tor Browser w standardowej konfiguracji. Bridge nie sprawia, że custom extensions, logowania do kont ani nietypowe ustawienia przeglądarki stają się bezpieczne.
5. Przetestuj ponowne połączenie i poprawność zegara. Nie przełączaj wielokrotnie transportów w sposób wysyłający charakterystyczną sekwencję do tego samego lokalnego obserwatora.
6. Ponownie oceń sytuację, jeśli zmienią się cenzor lub polityka sieci; użycie może być w niektórych miejscach wrażliwe lub ograniczone.

## Onion services jako prywatny punkt rendezvous

Onion service tworzy wychodzące obwody Tor do introduction points i relay rendezvous, więc nie potrzebuje publicznego portu przychodzącego i nie ujawnia adresu IP serwera przez protokół onion. Ruch klient–usługa pozostaje wewnątrz Tor, a adres onion uwierzytelnia klucz usługi.<sup>[[5]](#references)</sup>

Dla zgodnego z prawem portalu intake, prywatnego repozytorium, interfejsu administracyjnego lub miejsca przekazywania dowodów z engagementu:

1. Uruchom aplikację na dedykowanym hoście/VM i powiąż ją z loopbackiem lub izolowanym Unix socket.
2. Zainstaluj Tor z oficjalnego repozytorium i postępuj zgodnie z oficjalną konfiguracją v3 onion service; nigdy nie używaj nieaktualnych instrukcji v2.
3. Chroń prywatny klucz onion service tak jak klucz TLS/signing. Wykonuj jego backup tylko wtedy, gdy wymagana jest stabilna tożsamość.
4. Dodaj client authorization onion service dla zamkniętej grupy i dostarcz credentials niezależnie uwierzytelnionym kanałem.<sup>[[6]](#references)</sup>
5. Nie pozwól originowi pobierać third-party fonts, analytics, updates ani webhooków, które ujawniają jego publiczny adres IP lub konto operatora.
6. Dodaj authentication i authorization również w aplikacji; posiadanie adresu onion nie jest kontrolą dostępu.
7. Patchuj, ograniczaj rate i monitoruj usługę bez osadzania third-party telemetry.
8. Z oddzielnego kontekstu testowego potwierdź, że DNS, email, strony błędów, metadata plików i nagłówki odpowiedzi nie ujawniają originu.
9. W przypadku użycia red-team wymień usługę, właściciela, cel i czas wyłączenia w ROE. Nie używaj jej do ukrywania C2 poza zakresem.

## Zdalna przeglądarka i disposable workspace

Zdalna przeglądarka przenosi rendering i ryzykowne treści z dala od lokalnego endpointu oraz może zapewnić egress cloud właściwy dla engagementu. Chroni lokalne urządzenie przed niektórymi treściami i persistence; nie czyni jednak operatora anonimowym wobec dostawcy workspace. AWS na przykład dokumentuje zbieranie danych portalu, tożsamości, zasad, preferencji i logów sesji, mimo że instancja disposable browser jest usuwana po zakończeniu sesji.<sup>[[7]](#references)</sup>

Używaj jednego workspace kontrolowanego przez organizację na każdy engagement, ogranicz downloads/uploads/clipboard, wyłącz personal identity providers, kieruj jego stały egress przez zatwierdzony bastion i wygaszaj workspace po eksporcie dowodów. Traktuj konsolę dostawcy, IdP i administratora jako obserwatorów.

## I2P i overlays wewnętrzne

I2P tworzy oddzielne jednokierunkowe tunele przychodzące i wychodzące oraz nie ma oficjalnych exits na poziomie sieci; służy przede wszystkim do usług wewnątrz I2P.<sup>[[8]](#references)</sup> Nie jest to szybszy drop-in sposób przeglądania publicznego Internetu. Outproxies wprowadzają punkt zaufania, a oficjalny threat model wyraźnie wymaga dalszych badań i nie twierdzi, że zapewnia idealną anonymity.

Używaj I2P wyłącznie wtedy, gdy oba końce celowo je obsługują, izoluj jego długotrwały router od personal applications i pamiętaj, że peers/local networks mogą obserwować uczestnictwo w I2P. Nie zwiększaj liczby hopów ani nie dostrajaj wyboru peers bez dowodów: nietypowe ustawienia mogą obniżyć wydajność i zmniejszyć anonymity set.

## Operacje odporne na korelację

- Preferuj typową, obsługiwaną konfigurację klienta zamiast unikalnego builda.
- Oddzielaj tożsamości na endpoincie; żadna topologia routingu nie naprawi ponownego użycia konta, płatności, recovery ani treści.
- W przypadku zadań nieinteraktywnych preferuj przeanalizowany asynchronous protocol/mixnet zamiast ręcznego dodawania opóźnień lub fałszywego ruchu.
- Unikaj obsługi rzekomo oddzielnych tożsamości według zsynchronizowanego wzorca z tego samego kontekstu fizycznego.
- Używaj jednokierunkowej bramy eksportu: niezaufana treść trafia do disposable renderera; na zewnątrz wychodzi wyłącznie przejrzany, oczyszczony wynik.
- Utrzymuj poprawny czas na potrzeby bezpieczeństwa protokołu, ale usuwaj niepotrzebnie precyzyjne timestampy z publikowanych artefaktów.
- Minimalizuj czas sesji i przestarzałą infrastrukturę bez szybkiej rotacji „fast-flux”, która jest charakterystyczna i szkodzi rozliczalności.

## Techniki, które nie mogą używać niezwiązanych stron trzecich

Są to rzeczywiste techniki adversary, a nie wymyślone lub nieistotne. Ich mechanika i wykrywanie zostały omówione w [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) oraz [APT case studies](government-and-apt-case-studies.md). Podczas autoryzowanego ćwiczenia odtwarzaj ich obserwowalne zachowanie za pomocą posiadanych substytutów:

- modeluj rotację residential/mobile exit za pomocą kontrolowanych pul relay, nigdy rynków o niejasnej zgodzie;
- modeluj open proxies, zaatakowane routery i botnety za pomocą posiadanych VM/routerów;
- modeluj skradzione konta cloud za pomocą wyznaczonego tenant i syntetycznej tożsamości ofiary;
- modeluj domain fronting na posiadanym reverse proxy zamiast na niechętnym CDN;
- modeluj third-party Wi-Fi za pomocą dwóch izolowanych AP należących do laboratorium;
- traktuj custom encryption, multi-VPN chains i rotację identyfikatorów jako hipotezy testowe, których flow, account i endpoint artifacts pozostają wykrywalne.

W przypadku autoryzowanego red teamu każda próba zmniejszenia rozpoznawalności ruchu musi być wyraźnym celem detekcji w ROE, posiadać mapę atrybucji przechowywaną przez kontrolera oraz obejmować mechanizm zatrzymania/dekonflikcji.

## Macierz weryfikacji

| Test | Oczekiwany rezultat | Znaczenie awarii |
|---|---|---|
| Zatrzymano tunnel/bridge | Workload nie ma bezpośredniej ścieżki IPv4/IPv6/DNS | Wymuszanie trasy jest niekompletne |
| Sprawdzono log targetu | Pojawia się wyłącznie zaplanowana tożsamość egress/aplikacji | Header, route lub account leak |
| Sprawdzono log ingress | Obecne źródło; brak jawnego target/request | Trust split zawiódł na ingress |
| Sprawdzono log egress | Obecny relay/request; brak tożsamości źródła | Trust split zawiódł na egress |
| Zeskanowano onion origin z zewnątrz | Żadna publiczna usługa origin nie jest osiągalna/powiązana | Origin został ujawniony lub jest dual-homed |
| Zakończono disposable session | Stan instancji zniknął; zatwierdzone dowody zachowano oddzielnie | Granica persistence zawiodła |
| Wykonano controller lookup | Aktywność szybko mapuje się na engagement/operatora | Rozliczalność red-team zawiodła |

## References

- [1] [Apple Platform Security — bezpieczeństwo iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — routing i Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake i pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — jak działają Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — zaawansowane ustawienia Onion Service i client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — szyfrowanie danych w Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
