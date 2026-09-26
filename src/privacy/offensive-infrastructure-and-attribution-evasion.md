# Infrastruktura ofensywna i unikanie atrybucji

{{#include ../banners/hacktricks-training.md}}

Operator rzadko uzyskuje znaczącą anonimowość dzięki pojedynczemu proxy. Prawdziwe kampanie budują **graf separacji**: operator dociera do węzła dostępowego, węzły tranzytowe ukrywają ten węzeł przed węzłem wyjściowym, redirectory chronią rzeczywisty C2, a jednorazowe nazwy wskazują na publiczną krawędź.

Użyj [Katalogu technik anonimowego dostępu do Internetu](anonymous-internet-access-techniques.md), aby uzyskać ujednolicony widok zalet i wad, wdrażania oraz wykrywania każdej ścieżki. Ta strona zawiera bardziej szczegółowe informacje na temat komponowania infrastruktury przeciwnika.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Ostatni adres widziany przez cel jest zatem dowodem istnienia ścieżki, a nie dowodem na to, kto kontrolował klawiaturę. MITRE mapuje główne komponenty do Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) oraz Web Service (T1102).<sup>[[1]](#references)</sup>

## Klasy infrastruktury

| Klasa | Dlaczego actor jej używa | Trwała ekspozycja | Najlepszy punkt pivotu dla obrońcy |
|---|---|---|---|
| Rented VPS/cloud | Szybkie, przewidywalne, routowalne i łatwe do odbudowy | tenant, billing, konsola, logowanie źródłowe i historia obrazów | zdarzenia konta/control plane oraz powtarzający się fingerprint serwera |
| Commercial VPN/Tor | Duży współdzielony zestaw wyjściowy; brak administracji serwerem | widoczność providera/guarda oraz timing end-to-end | zachowanie celu, dowody na endpointach i korelacja przepływów |
| Residential/mobile proxy | ASN konsumencki i wiarygodność geograficzna | dane brokera/klienta; zachowanie proxyware lub zainfekowanego hosta | impossible travel, protokoły proxy i zmienność adresów w ramach sesji |
| Compromised server/router/IoT | Pożycza reputację i jurysdykcję ofiary | implant, przepływ zarządzania i powtarzający się upstream controller | telemetria urządzenia i topologia ORB, a nie pojedynczy exit IP |
| CDN/redirector | Oddziela publiczny edge od back-end C2 | gramatyka TLS/HTTP, certyfikat, routing i artefakty konta cloud | korelacja edge-to-origin i klastrowanie kształtu żądań |
| Legitimate web service | Wtapia się w dozwolony ruch GitHub/cloud/social | API token, identyfikatory tenant/object i nietypowe pochodzenie procesu | proces na endpoint oraz semantyka usługi/API |
| Physical/cellular/satellite path | Zmienia pozorne źródło fizyczne | dane RF, operatora, abonenta, urządzenia i lokalizacji | połączone dowody radiowe/fizyczne i sieciowe |

## Sieci operacyjnych relay boxów

**Sieć ORB** to zarządzana flota proxy używana jako usługa pośrednia. Mandiant dzieli je na sieci provisioned, złożone z dzierżawionych serwerów, sieci non-provisioned, złożone ze zcompromitowanych routerów/urządzeń IoT, oraz hybrydy. Dojrzała topologia ma cztery logiczne role:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** utrzymuje inwentarz, dane uwierzytelniające, stan oraz politykę routingu.
2. **Access/relay node:** uwierzytelnia klientów lub operatorów; jest stabilnym wejściem do zmiennej siatki.
3. **Traversal nodes:** jeden lub więcej dzierżawionych albo zcompromitowanych systemów przekazuje nieprzejrzyste połączenia.
4. **Exit/staging node:** prezentuje końcowy adres źródłowy podczas rekonesansu, exploitation lub wobec celów C2.

Mesh może wybierać exity według kraju, ASN, opóźnienia lub dostępności oraz wymieniać niesprawne węzły. Wiele threat groups może wynajmować tę samą sieć. Mandiant zaobserwował, że adres IPv4 pozostawał powiązany z niektórymi ORB zaledwie przez 31 dni; dlatego zaleca traktowanie **sieci jako zmieniającej się encji przypominającej actora**, zamiast blokowania nieaktualnej listy adresów IP.<sup>[[2]](#references)</sup>

### Co to zapewnia — i co ujawnia

- Cel widzi exit, który może znajdować się geograficznie blisko i wyglądać na residential.
- Exit widzi cel oraz poprzedni hop, ale niekoniecznie operatora.
- Usługa access widzi klienta i żądanie trasy. Niezależnie zarządzany mesh może oddzielać klienta od exitów, ale tworzy potężny rekord kontrahenta.
- Powtarzające się porty, kolejność handshake, bannery serwerów, certyfikaty, okna dostępności oraz relacje z controllerem mogą ujawnić flotę nawet podczas rotacji adresów IP.
- Zcompromitowany router często nie ma telemetrii endpointu, ale jego ISP nadal posiada dane abonenta i przepływów; przejęcie urządzenia ujawnia artefakty implantu/konfiguracji.

{% hint style="info" %}
W ramach autoryzowanego ćwiczenia odtwórz topologię przy użyciu należących do organizacji VM lub routerów i zachowaj mapę attribution controllera. Nie rekrutuj open proxies ani urządzeń stron trzecich. [Przewodnik laboratorium](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) tworzy taką samą widoczną dla obrońcy strukturę hopów bez krzywdzenia pośrednika.
{% endhint %}

## Residential i mobile proxy networks

Usługi residential proxy przypisują sesje do adresów konsumenckich łączy szerokopasmowych; mobile proxies wychodzą przez pule carrier NAT. Źródłem mogą być jawnie zapisane urządzenia, SDK/proxyware dołączone do aplikacji konsumenckich, resellerzy lub malware. Te źródła nie są równoważne: brak świadomej zgody zmienia usługę privacy w compromised infrastructure.

Tryby rotacji wpływają na detekcję:

- **per-request rotation** powoduje szybkie nieciągłości IP oraz ASN/geografii, podczas gdy tożsamość na wyższych warstwach pozostaje stabilna;
- **sticky sessions** utrzymują exit przez minuty lub godziny, przypominając zwykłego abonenta;
- **backconnect gateways** udostępniają klientowi jeden endpoint brokera i wewnętrznie wybierają exity;
- **mobile pools** umieszczają wielu autentycznych abonentów za niewielkim zestawem adresów carrier NAT, przez co blokada IP może być kosztowna.

Obrońcy powinni korelować IP z uwierzytelnioną sesją, fingerprintem TLS/client, kolejnością HTTP, cookie urządzenia i zachowaniem. Pozornie lokalne logowanie residential, po którym następuje logowanie z innego kraju, przy identycznych wszystkich cechach wyższych warstw, stanowi silniejszy sygnał niż sama reputacja. Z drugiej strony współdzielenie adresów i przełączanie między stacjami mobile powodują uzasadnioną zmienność, dlatego nigdy nie traktuj klasyfikacji residential/proxy jako werdyktu.

### Proxyware control planes i nakładanie się resellerów

Nie modeluj puli residential jako płaskiej listy exitów. Analiza ekosystemu IPIDEA ujawniła możliwy do ponownego wykorzystania **dwupoziomowy control plane**: embedded SDK najpierw raportuje metadane urządzenia/rejestracji do domeny Tier One, a następnie otrzymuje harmonogram oraz pary adresów IP:port Tier Two `connect`/`proxy`. Węzeł okresowo odpytuje port Tier Two connect o zakodowane zadanie, otwiera drugie połączenie z odpowiadającym mu portem proxy i przekazuje dostarczone bajty do żądanego celu. Pozornie różne SDK i marki proxy miały oddzielne domeny discovery, ale zbiegały się w ramach wspólnej infrastruktury Tier Two oraz nakładających się pul exitów poprzez wspólną własność i relacje resellerów.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Daje to trwalsze punkty zaczepienia do huntingu niż blok adresów residential IP:<sup>[[13]](#references)</sup>

- nieoczekiwany proces narzędzia, VPN, gry lub urządzenia wbudowanego wysyła stały identyfikator urządzenia/klucza klienta i otrzymuje zmieniającą się listę serwerów;
- endpoint odpytuje bezpośredni adres IP na nietypowym porcie, a następnie natychmiast łączy się z innym portem pod tym samym adresem, zanim otworzy socket do nowego celu;
- kilka pozornie różnych marek współdzieli adresy Tier Two, składnię protokołu, kod SDK lub nakładanie się exit nodes;
- odrębne aplikacje kontaktujące się z różnymi domenami Tier One otrzymują adresy z tej samej puli Tier Two.

To nakładanie się również ogranicza atrybucję: zobaczenie adresu IP w reklamowanej puli jednego dostawcy nie dowodzi, który reseller, klient lub threat actor używał go w danym czasie. Zachowaj timestampy przepływów, pochodzenie procesów, treści odpowiedzi Tier One oraz identyfikatory zadań Tier Two.<sup>[[13]](#references)</sup> W ramach autoryzowanego ćwiczenia emuluj tę hierarchię wyłącznie przy użyciu endpointów należących do organizacji; nigdy nie rejestruj urządzeń konsumenckich ani proxyware stron trzecich.

## Łańcuchy multi-hop proxies

MITRE rozróżnia external proxies od **multi-hop proxies (T1090.003)**. Istotną właściwością nie jest liczba hopów, lecz rozdzielenie wiedzy i administracji.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Jeśli jedna strona obsługuje A i B, współdzielone logi lub analiza czasu przepływu mogą umożliwić odtworzenie obwodu. Dodanie kolejnych komercyjnych VPN-ów z tego samego endpointu/konta może zwiększyć opóźnienie, jednocześnie pozostawiając wspólne dane tożsamości, płatności i synchronizacji czasowej. Tor ogranicza ten problem dzięki niezależnie wybieranym relayom i wspólnej konstrukcji klienta, ale interaktywna sieć o małych opóźnieniach nie może zagwarantować odporności na obserwatora mierzącego oba końce.

Typowe awarie obejmują wyciek przez DNS lub IPv6, aplikacje otwierające własne sockety, ruch zarządzający docierający bezpośrednio do relayów, zsynchronizowaną aktywność, ponownie użyte klucze SSH oraz logowanie do kont umożliwiających identyfikację. Prawidłowa weryfikacja to test awarii: zatrzymuj każdy relay po kolei i potwierdź, że workload nie może przełączyć się na jawną ścieżkę.

### Załamanie tunelu i wyciek upstream

Architektura relayów jest często najbardziej podatna na identyfikację właśnie w momencie awarii. Unit 42 udokumentowało wielopoziomową ścieżkę szpiegowską wykorzystującą VPS-y skierowane do ofiar, VPS-y relayów, residential proxies, Tor i inne usługi proxy; gdy tunel został pominięty lub uległ załamaniu, ukryta infrastruktura upstream łączyła się bezpośrednio z systemami relayów i systemami skierowanymi do ofiar. W ramach tego samego dochodzenia wykorzystano również certyfikat X.509, który na krótko ujawniono w infrastrukturze upstream, jako punkt przejścia między poziomami.<sup>[[14]](#references)</sup>

Utrzymuj oddzielnie **data plane** (`victim <-> exit`) i **control plane** (`operator/upstream -> relay administration`). Zachowuj logi wejściowe i uwierzytelniania na każdym kontrolowanym poziomie, historię certyfikatów oraz krótkie nieudane połączenia — nie tylko udane sesje C2. Źródło pojawiające się wyłącznie podczas awarii relayów lub bezpośrednio administrujące wieloma węzłami skierowanymi do ofiar jest silniejszym kandydatem na upstream niż zwykły exit, ale jego ASN/geolokalizacja nadal stanowi hipotezę, a nie dowód tożsamości operatora.

Autoryzowane laboratorium powinno sprawić, aby workload kończył działanie bezpiecznie w razie awarii. W przypadku workloadu odizolowanego w linuxowym network namespace pierwsza trasa musi korzystać z tunelu; po jego usunięciu zarówno żądanie, jak i wyszukiwanie trasy muszą zakończyć się niepowodzeniem, zamiast wybrać fizyczne łącze uplink:
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
Powtórz test dla DNS i IPv6 oraz na każdej granicy między relayami. Jeśli którakolwiek sonda zakończy się powodzeniem, zapisz rzeczywisty interfejs/adres źródłowy przed naprawą routingu zasad lub firewalla; ta obserwacja stanowi wyciek atrybucji, który zobaczyłby analityk.

## Warstwy redirectorów i kształtowanie ruchu

Publiczny **redirector** akceptuje ruch zgodny z gramatyką właściwą dla danej operacji i przekazuje go do chronionego serwera zespołu. Całą resztę można odrzucić lub obsłużyć nieszkodliwą treścią.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Wiele warstw ogranicza ekspozycję: spalenie public domain nie musi ujawniać team servera. CDN-y zapewniają przepustowość anycast i wiarygodną domenę zewnętrzną, ale konto CDN oraz logi edge stają się punktami atrybucji. Odciski TLS, historia certyfikatów, charakterystyczne ścieżki/kolejność nagłówków, rozmiary odpowiedzi, sposób przekierowań oraz allowlisty originów mogą grupować pozornie niezależne fronty.

Na potrzeby detekcji rejestruj pola reverse proxy przed normalizacją, porównuj SNI/Host/authority, analizuj rzadkie kombinacje nagłówków, grupuj treści odpowiedzi i odciski TLS oraz przeszukuj logi audytowe cloud/CDN pod kątem nakładania się konfiguracji. W przypadku autoryzowanych red teams unikaj kopiowania prawdziwej marki lub umieszczania zbierania poświadczeń za niezwiązanym z operacją podmiotem trzecim.

## Domain fronting and domainless fronting

W klasycznym **domain fronting (T1090.004)** połączenie TLS reklamuje dozwoloną domenę frontową w SNI, podczas gdy zaszyfrowane żądanie HTTP `Host` lub HTTP/2 `:authority` wskazuje inną domenę back-endu. Współpracujący CDN routuje na podstawie wewnętrznej wartości. Obserwator sieci bez deszyfrowania TLS widzi front; CDN widzi obie wartości oraz origin. W wariantach domainless SNI może być puste, podczas gdy inne pole routingu wybiera miejsce docelowe.<sup>[[4]](#references)</sup>

Nie jest to magiczne podszywanie się: działa tylko wtedy, gdy pośrednik celowo lub przypadkowo zezwala na niezgodność i wie, jak routować wewnętrzną nazwę. Najwięksi dostawcy ograniczyli cross-account fronting. Encrypted ClientHello (ECH) zmienia to, co może zobaczyć obserwator na ścieżce, ale nie usuwa zapisów CDN, endpointu ani aplikacji.

Punkty detekcji obejmują:

- pochodzenie procesu endpointu i miejsce docelowe nieoczekiwane dla danej aplikacji;
- niezgodność SNI i HTTP authority, gdy inspekcja TLS jest zgodna z prawem i dostępna;
- logi CDN pokazujące routing jednego tenanta/frontu do innego authority/origin;
- nietypowe, długo utrzymywane lub okresowe sesje do usługi zwykle używanej interaktywnie;
- stabilne rozmiary i rytm zaszyfrowanego przepływu przy zmieniających się domenach frontowych.

Bezpieczne laboratorium symuluje niezgodność routingu na należącym do zespołu reverse proxy; nie wykorzystuje publicznego CDN.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution oddziela logiczną usługę od stałej infrastruktury:

- **DDNS:** uwierzytelniony klient aktualizuje stabilną nazwę po zmianie adresu.
- **DGA:** endpoint i kontroler wyprowadzają kandydackie nazwy domen na podstawie ziarna czasu/klucza; operator rejestruje tylko niewielki podzbiór.
- **Fast flux:** nazwa zwraca szybko zmieniający się zestaw przejętych adresów/proxy, często z krótkimi TTL.
- **Double flux:** rotują zarówno adresy usług, jak i adresy autorytatywnych name serverów, ukrywając również warstwę sterowania.

Fast flux to wzorzec dystrybucji obciążenia wykorzystywany przeciwnikowo, a nie po prostu „wiele odpowiedzi DNS”. Silniejsze dowody łączą krótki TTL, dużą liczbę unikalnych adresów, szerokie rozproszenie ASN/geograficzne, krótki czas życia węzłów, powtarzalne zachowanie aplikacji i podejrzaną historię rejestracji. CDN-y legalnie wykazują kilka z tych właściwości. MITRE zaleca korelowanie zachowania DNS z procesem i późniejszymi połączeniami.<sup>[[5]](#references)</sup>

DGA można wykrywać na podstawie entropii leksykalnej, wzorców spółgłosek/cyfr, serii NXDOMAIN, zsynchronizowanych domen zaobserwowanych po raz pierwszy oraz kontekstu procesu. Wordlist DGA i modele generatywne pokonują proste reguły entropii, przez co ważniejsze stają się czasowe grupowanie w całej flocie i lineage endpointów.

## Compromised domains and domain shadowing

Aktor może przejąć konto registrar/DNS, przejąć osieroconą subdomenę lub dodać rekordy pod skądinąd wiarygodną domeną. **Domain shadowing** zachowuje legalny apex, podczas gdy duża liczba subdomen kontrolowanych przez atakującego wskazuje na zmieniające się hosty delivery lub C2. Wykorzystuje wiek i reputację domeny oraz może omijać blokowanie obejmujące całą domenę.<sup>[[6]](#references)</sup>

Obrońcy potrzebują logów audytowych registrar i autorytatywnego DNS, MFA, blokad registry/registrar, alertów dotyczących nowych delegacji/tokenów API/name serverów, monitorowania certificate transparency oraz inwentaryzacji zasobów cloud wskazywanych przez DNS. Rozdzielnie badaj resolution i historię certyfikatów subdomeny, niezależnie od reputacji apexu.

## Web services and dead-drop resolvers

**Dead-drop resolver (T1102.001)** przechowuje zakodowany wskaźnik do bieżącego C2 wewnątrz legalnego posta, profilu, dokumentu, repozytorium, obiektu cloud lub pola blockchain. Malware pobiera publiczny obiekt, dekoduje domenę/IP i kontaktuje się z kolejnym etapem. Warianty dwukierunkowe wymieniają polecenia lub pliki za pośrednictwem API usług.<sup>[[7]](#references)</sup>

Zapewnia to odporność i ukrywa back-end C2 przed statyczną analizą binarną. Tworzy jednak również stabilne identyfikatory obiektów, tenantów, repozytoriów, API i wzorców dostępu. Obrońcy powinni połączyć:

1. proces, który skontaktował się z usługą;
2. dokładną ścieżkę API/obiekt oraz hash odpowiedzi;
3. aktywność dekodowania lub przetwarzania stringów;
4. nowe połączenie wychodzące krótko potem; oraz
5. identyczne zachowanie w innych miejscach floty.

Blokowanie całego GitHub, cloud storage lub social media rzadko jest wykonalne. Polityka egress uwzględniająca usługi i korelacja na poziomie procesu przewyższają blokowanie wyłącznie domen.

## Personas, accounts and procurement compartments

Anonimowość infrastruktury zawodzi, gdy persona, recovery email, telefon, płatność, przeglądarka lub admin IP łączy różne segmenty. Operacje powiązane z państwami rozwijały profile społecznościowe, tożsamości email i konta cloud długo przed ich użyciem; ATT&CK rejestruje to jako Establish Accounts (T1585), w tym podtechniki social, email i cloud.<sup>[[8]](#references)</sup>

Obrońca lub śledczy buduje graf na podstawie:

- czasu utworzenia i pierwszego logowania, lokalizacji, strefy czasowej oraz harmonogramu pracy;
- pól odzyskiwania, urządzeń MFA, dokumentów tożsamości i instrumentów płatniczych;
- odcisków przeglądarki/TLS i historii sieci źródłowej;
- ponownego użycia awatara, pochodzenia obrazu, stylu pisania i rozwoju grafu społecznego;
- wspólnego registranta domeny, name servera, certyfikatu, analytics ID lub commita w repozytorium;
- działań na płaszczyźnie zarządzania, które omijają publiczną architekturę relay.

W przypadku autoryzowanego red teamu syntetyczne persony powinny być udokumentowane u kontrolera ćwiczenia, korzystać z należących do organizacji kanałów odzyskiwania/płatności, unikać podszywania się pod prawdziwe, niezaangażowane osoby i mieć zaplanowane wycofanie. SOC może pozostać nieświadomy; operacja nie może stać się pozbawiona odpowiedzialności.

## Emerging compound patterns to threat-model

Poniższe przykłady to **kompozycje tworzone z perspektywy obrońcy**, a nie twierdzenia, że nazwany aktor wdrożył każdy dokładnie taki projekt. Łączą już zaobserwowane prymitywy i są użytecznymi hipotezami dla purple teamów.

### Asymmetric one-way tasking

Polecenia przychodzą przez publiczne, broadcastowe lub append-only źródło, podczas gdy wyniki opuszczają system innym kanałem z opóźnieniem. Przykłady prymitywów obejmują one-way communication przez web service i dead drops. Rozdzielenie uniemożliwia, by pojedynczy przepływ wyglądał na dwukierunkowy, i utrudnia prostą korelację request/response.<sup>[[9]](#references)</sup>

**Detection:** zachowuj odczyty na poziomie obiektów, a następnie koreluj zmiany stanu procesu i późniejsze transfery wychodzące w szerszym przedziale czasowym. Szukaj rzadkiego procesu odczytującego ten sam publiczny obiekt, nawet gdy nie następuje natychmiastowa odpowiedź.

### Multi-stage channel promotion

Cichy pierwszy etap wykonuje inwentaryzację i promuje tylko wybrane systemy do niezwiązanego kanału drugiego etapu. Drugi endpoint, protokół i proces mogą nie dzielić infrastruktury z pierwszym. Ogranicza to ekspozycję infrastruktury o większych możliwościach i jest jawnie modelowane jako ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** połącz `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; nie zamykaj incydentu po zablokowaniu pierwszej domeny.

### Cross-protocol relay translation

Różne hop-y tłumaczą HTTPS, QUIC, WebSocket, DNS, SSH lub API message-queue, zamiast transparentnie przekazywać pakiety. Tłumaczenie usuwa pojedynczy, end-to-endowy odcisk protokołu, ale tworzy gatewaye o charakterystycznym taktowaniu, buforowaniu i konwersji semantycznej. Protocol tunneling (T1572) można łączyć z proxy i service impersonation.<sup>[[11]](#references)</sup>

**Detection:** szukaj hostów gateway, które odbierają jeden protokół i inicjują inny, przy ściśle powiązanym zachowaniu bajtowym/czasowym; porównuj intencję endpointu z faktycznie przenoszonym protokołem.

### Passive activation on edge devices

Zamiast beaconowania implant monitoruje ruch docierający już do routera/VPN i aktywuje się tylko po magic value, wzorcu portu źródłowego lub uwierzytelnionym tokenie. Normalny ruch nadal trafia do prawdziwej usługi. ATT&CK nazywa to Traffic Signaling (T1205), z udokumentowanymi przykładami dotyczącymi urządzeń sieciowych i APT.<sup>[[12]](#references)</sup>

**Detection:** integralność firmware/plików, raw packet capture podczas autoryzowanego huntu, nieoczekiwane filtry socketów i różnice w zachowaniu usługi. Brak okresowego beaconu nie dowodzi, że urządzenie edge jest czyste.

### Serverless and ephemeral origin rotation

Front utrzymuje stabilną tożsamość logiczną, podczas gdy krótkotrwałe funkcje/kontenery obsługują poszczególne etapy w kilku regionach/kontach. Ogranicza to czas życia na dysku i stałe IP originów, ale utworzenie na płaszczyźnie sterowania, obraz/warstwa, rola, sekret, request ID i telemetria billingowa stają się trwałym grafem.

**Detection:** zachowuj logi audytowe cloud i logi invocation poza workloadem; grupuj template deploymentu, role, klucze środowiskowe oraz relacje front-to-origin.

### Privacy-layer diversity

Operacja może celowo unikać jednorodnego łańcucha: na przykład jeden kanał korzysta z dzierżawionego relay, tasking używa publicznego obiektu, exit pochodzi z należącego do zespołu laboratoryjnego łącza cellular, a administracja wykorzystuje oddzielną sieć organizacji. Zmniejsza to wartość przejęcia jednego dostawcy, ale zwiększa ryzyko korelacji czasowej między warstwami i błędów operacyjnych.

**Detection:** buduj osie czasu kampanii obejmujące sensory identity, DNS, SaaS, sieciowe i cloud. Szukaj zsynchronizowanych zmian stanu, a nie identycznych wskaźników.

### Decentralized or transparency-log dead drops

Aktor może umieścić mały zaszyfrowany wskaźnik w dowolnym trwałym publicznym systemie append-only, magazynie content-addressed lub feedzie podobnym do transparency log. Publiczny obiekt jest odporny, ale jego dokładny indeks/hash treści oraz zachowanie klienta polegające na odpytywaniu stają się stabilnymi identyfikatorami.

**Detection:** rejestruj pełne identyfikatory API/obiektów i hashe odpowiedzi; alarmuj na niestandardowe procesy odpytujące niezmienne obiekty, po których następuje dekodowanie lub nowe połączenia.

### Delayed store-and-forward operations

Interaktywny C2 tworzy silną korelację czasową. Projekt store-and-forward grupuje zaszyfrowane zadania i zwraca wyniki po minutach lub godzinach przez inną kolejkę albo transfer fizyczny. Poświęca responsywność na rzecz słabszej korelacji czasowej end-to-end.

**Detection:** wydłużaj okna korelacji, modeluj okresowy dostęp do kolejek i analizuj staging na endpointach. Grupowanie przenosi sygnał z taktowania pakietów do zaplanowanego zachowania procesów/plików; nie usuwa go.

## Design review: think in observers

Dla każdej ścieżki wypełnij tę tabelę przed wdrożeniem i po zebraniu danych:

| Warstwa | Widzi źródło? | Widzi cel? | Widzi treść? | Stabilne identyfikatory | Właściciel retencji/prawny |
|---|---:|---:|---:|---|---|
| sieć lokalna/carrier | | | | | |
| usługa wejścia/dostępu | | | | | |
| operator(y) traversal | | | | | |
| exit/redirector/CDN | | | | | |
| autorytatywny DNS/registrar | | | | | |
| cel | | | | | |
| dostawca konta/płatności | | | | | |

Jeśli jeden zwykły dostawca może wypełnić każdą kolumnę, architektura zapewnia ukrycie przed celem, ale nie zapewnia solidnego rozdzielenia. Jeśli żaden wewnętrzny kontroler nie może powiązać aktywności z konkretnym engagementem, architektura nie nadaje się do profesjonalnego red teamingu.

## References

- [1] [MITRE ATT&CK — Pozyskiwanie infrastruktury (T1583), Compromise Infrastructure (T1584) i Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Aktorzy szpiegowscy powiązani z Chinami wykorzystują sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Zakłócenie działania największej na świecie sieci residential proxy](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Kampanie Shadow: ujawnianie globalnego szpiegostwa](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
