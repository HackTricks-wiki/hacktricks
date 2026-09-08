# Infrastruktura ofensywna i unikanie atrybucji

Operator rzadko uzyskuje znaczącą anonimowość za pośrednictwem pojedynczego proxy. Rzeczywiste kampanie budują **graf separacji**: operator dociera do węzła dostępowego, węzły tranzytowe ukrywają ten węzeł przed wyjściem, redirectory chronią rzeczywisty C2, a jednorazowe nazwy wskazują na publiczną krawędź.

Skorzystaj z [Katalogu technik anonimowego dostępu do Internetu](anonymous-internet-access-techniques.md), aby uzyskać ujednolicony przegląd zalet i wad, wdrażania oraz wykrywania każdej ścieżki. Ta strona bardziej szczegółowo omawia składanie adversarial infrastructure.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Ostatni adres zaobserwowany przez cel jest zatem dowodem istnienia ścieżki, a nie dowodem na to, kto kontrolował klawiaturę. MITRE mapuje główne komponenty na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klasy infrastruktury

| Klasa | Dlaczego actor jej używa | Trwała ekspozycja | Najlepszy punkt zaczepienia dla obrońcy |
|---|---|---|---|
| Wynajęty VPS/cloud | Szybki, przewidywalny, routowalny, łatwy do odbudowy | tenant, billing, konsola, logowanie źródłowe i historia image | zdarzenia konta/control plane oraz powtarzalny fingerprint serwera |
| Komercyjny VPN/Tor | Duży współdzielony zestaw egress; brak administracji serwerem | widoczność providera/guarda i timing end-to-end | zachowanie celu, dowody z endpointów i korelacja przepływów |
| Residential/mobile proxy | ASN konsumencki i wiarygodność geograficzna | dane brokera/klienta; zachowanie proxyware lub zainfekowanego hosta | impossible travel, protokoły proxy i zmienność adresów w ramach sesji |
| Zaatakowany serwer/router/IoT | Korzysta z reputacji i jurysdykcji ofiary | implant, przepływ zarządzania i powtarzający się upstream controller | telemetryka urządzenia i topologia ORB, a nie pojedynczy exit IP |
| CDN/redirector | Oddziela publiczny edge od back-endowego C2 | gramatyka TLS/HTTP, certyfikat, routing i artefakty konta cloud | korelacja edge-origin i klasteryzacja kształtu żądań |
| Legalny web service | Wtapia się w dozwolony ruch GitHub/cloud/social | token API, identyfikatory tenant/object i nietypowe pochodzenie procesu | proces endpointu oraz semantyka usługi/API |
| Ścieżka fizyczna/komórkowa/satelitarna | Zmienia pozorne źródło fizyczne | dane RF, operatora, abonenta, urządzenia i lokalizacji | połączone dowody radiowe/fizyczne i sieciowe |

## Sieci operacyjnych relay boxów

**Sieć ORB** to zarządzana flota proxy używana jako usługa pośrednia. Mandiant dzieli je na sieci provisioned, złożone z dzierżawionych serwerów, sieci non-provisioned, złożone ze zainfekowanych routerów/urządzeń IoT, oraz hybrydy. Dojrzała topologia ma cztery role logiczne:<sup>[[2]](#references)</sup>

1. **Serwer administracyjny (ACOS):** utrzymuje inwentarz, dane uwierzytelniające, stan zdrowia i zasady routingu.
2. **Węzeł dostępu/relay:** uwierzytelnia klientów lub operatorów; jest stabilnym wejściem do zmiennej sieci mesh.
3. **Węzły traversal:** jeden lub więcej dzierżawionych albo zaatakowanych systemów przekazuje niejawne połączenia.
4. **Węzeł exit/staging:** prezentuje końcowy adres źródłowy podczas rekonesansu, exploitation lub połączeń C2.

Sieć mesh może wybierać exity według kraju, ASN, opóźnienia lub dostępności oraz wymieniać niesprawne węzły. Wiele threat groups może wynajmować tę samą sieć. Mandiant zaobserwował, że adres IPv4 pozostawał powiązany z niektórymi ORB zaledwie przez 31 dni; dlatego zaleca traktowanie **sieci jako ewoluującej jednostki podobnej do actora**, zamiast blokowania nieaktualnej listy adresów IP.<sup>[[2]](#references)</sup>

### Co to zapewnia — i co leak

- Cel widzi exit, który może znajdować się geograficznie blisko i pozornie należeć do sieci residential.
- Exit widzi cel i poprzedni hop, ale niekoniecznie operatora.
- Usługa dostępu widzi klienta i żądanie trasy. Niezależnie zarządzana sieć mesh może oddzielać klienta od exitów, ale tworzy potężny zapis po stronie kontrahenta.
- Powtarzające się porty, kolejność handshake, bannery serwerów, certyfikaty, okna dostępności i relacje z controllerem mogą ujawnić flotę, nawet gdy adresy IP się zmieniają.
- Zaatakowany router często nie zapewnia telemetryki endpointu, ale jego ISP nadal posiada dane abonenta i przepływów; przejęcie urządzenia ujawnia artefakty implantu/konfiguracji.

{% hint style="info" %}
W ramach autoryzowanego ćwiczenia odtwórz topologię za pomocą należących do organizacji VM lub routerów i zachowaj mapę atrybucji controllera. Nie rekrutuj otwartych proxy ani urządzeń stron trzecich. [Lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) tworzy tę samą widoczną dla obrońcy strukturę hopów bez krzywdzenia pośrednika.
{% endhint %}

## Sieci residential i mobile proxy

Usługi residential proxy przypisują sesje do adresów konsumenckich łączy szerokopasmowych; mobile proxy wykonują egress przez pule NAT operatorów. Źródłem mogą być celowo zapisane urządzenia, SDK/proxyware dołączone do aplikacji konsumenckich, resellerzy lub malware. Te źródła nie są równoważne: brak świadomej zgody zmienia usługę ochrony prywatności w skompromitowaną infrastrukturę.

Tryby rotacji wpływają na wykrywanie:

- **rotacja per-request** powoduje szybkie nieciągłości IP oraz ASN/geografii, podczas gdy tożsamość na wyższych warstwach pozostaje stabilna;
- **sticky sessions** utrzymują exit przez minuty lub godziny, przypominając zwykłego abonenta;
- **backconnect gateways** udostępniają klientowi jeden endpoint brokera i wewnętrznie wybierają exity;
- **mobile pools** umieszczają wielu prawdziwych abonentów za niewielkim zestawem adresów NAT operatora, przez co blokada IP jest kosztowna.

Obrońcy powinni korelować IP z uwierzytelnioną sesją, fingerprintem TLS/klienta, kolejnością HTTP, cookie urządzenia i zachowaniem. Pozornie lokalne logowanie residential, po którym następuje logowanie z innego kraju, przy identycznych wszystkich cechach wyższych warstw, jest silniejszym sygnałem niż sama reputacja. Z drugiej strony współdzielenie adresów i przełączanie się między stacjami mobilnymi powodują uzasadnioną zmienność, dlatego nigdy nie traktuj klasyfikacji residential/proxy jako werdyktu.

## Łańcuchy proxy multi-hop

MITRE odróżnia zewnętrzne proxy od **proxy multi-hop (T1090.003)**. Kluczową właściwością nie jest liczba hopów, lecz rozdzielenie wiedzy i administracji.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Jeśli jedna strona obsługuje A i B, współdzielone logi lub analiza czasu przepływu mogą odtworzyć obwód. Dodanie kolejnych komercyjnych VPN-ów z tego samego endpointu lub konta może zwiększyć opóźnienia, jednocześnie pozostawiając wspólne ślady tożsamości, płatności i synchronizacji czasowej. Tor ogranicza ten problem dzięki niezależnie wybieranym przekaźnikom i współdzielonej architekturze klienta, ale interaktywna sieć o niskich opóźnieniach nie może zagwarantować odporności na obserwatora mierzącego oba końce.

Częstymi błędami są wycieki przez DNS lub IPv6, aplikacje otwierające własne sockety, ruch zarządzający docierający bezpośrednio do przekaźników, zsynchronizowana aktywność, ponownie używane klucze SSH oraz logowanie do kont umożliwiających identyfikację. Prawidłowa weryfikacja to test awarii: zatrzymuj każdy przekaźnik po kolei i sprawdź, czy workload nie może przełączyć się na jawną ścieżkę.

## Warstwy redirectorów i kształtowanie ruchu

Publiczny **redirector** akceptuje ruch zgodny z gramatyką właściwą dla danej operacji i przekazuje go do chronionego serwera zespołu. Cała reszta może zostać odrzucona lub otrzymać nieszkodliwą treść.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Wiele warstw ogranicza ekspozycję: spalenie publicznej domeny nie musi ujawniać team servera. CDN-y zapewniają anycast capacity i renomowaną domenę zewnętrzną, ale konto CDN i logi edge stają się punktami atrybucji. Odciski TLS, historia certyfikatów, charakterystyczne ścieżki/kolejność nagłówków, rozmiary odpowiedzi, sposób przekierowywania i allowlisty originów mogą grupować pozornie niezależne fronty.

Na potrzeby detekcji rejestruj pola reverse proxy przed normalizacją, porównuj SNI/Host/authority, analizuj rzadkie kombinacje nagłówków, grupuj body odpowiedzi i odciski TLS oraz przeszukuj logi audytowe cloud/CDN pod kątem nakładania się konfiguracji. W przypadku autoryzowanych red teamów unikaj kopiowania prawdziwej marki lub umieszczania credential collection za niezwiązanym z nią podmiotem trzecim.

## Domain fronting i domainless fronting

W przypadku klasycznego **domain fronting (T1090.004)** połączenie TLS reklamuje dozwoloną domenę frontową w SNI, podczas gdy zaszyfrowane żądanie HTTP `Host` lub HTTP/2 `:authority` wskazuje inną domenę back-endową. Współpracujący CDN routuje na podstawie wewnętrznej wartości. Obserwator sieciowy bez deszyfrowania TLS widzi front, natomiast CDN widzi obie wartości oraz origin. W wariantach domainless SNI może być puste, podczas gdy inne pole routingu wybiera miejsce docelowe.<sup>[[4]](#references)</sup>

Nie jest to magiczne podszywanie się: działa tylko wtedy, gdy intermediary celowo lub przypadkowo zezwala na niezgodność i wie, jak routować wewnętrzną nazwę. Główni dostawcy ograniczyli fronting między kontami. Encrypted ClientHello (ECH) zmienia to, co może zobaczyć obserwator on-path, ale nie usuwa logów CDN, endpointu ani aplikacji.

Punkty detekcji obejmują:

- ancestry procesu na endpoincie i destination nieoczekiwane dla danej aplikacji;
- niezgodność SNI i HTTP authority, gdy inspekcja TLS jest zgodna z prawem i dostępna;
- logi CDN pokazujące routing jednego tenanta/frontu do innego authority/origin;
- nietypowe, długo utrzymywane lub okresowe sesje do zwykle interaktywnej usługi;
- stabilne rozmiary i cadence zaszyfrowanego flow przy zmieniających się domenach frontowych.

Bezpieczne laboratorium symuluje niezgodność routingu na własnym reverse proxy; nie wykorzystuje publicznego CDN.

## Dynamic resolution: DDNS, DGA i fast flux

Dynamic resolution oddziela logiczną usługę od stałej infrastruktury:

- **DDNS:** uwierzytelniony klient aktualizuje stabilną nazwę po zmianie adresu.
- **DGA:** endpoint i controller wyprowadzają potencjalne nazwy domen z seeda czasu/klucza; operator rejestruje niewielki podzbiór.
- **Fast flux:** nazwa zwraca szybko zmieniający się zestaw adresów przejętych/proxy, często z niskimi TTL.
- **Double flux:** rotują zarówno adresy usług, jak i adresy authoritative name serverów, ukrywając również warstwę control.

Fast flux to wzorzec dystrybucji obciążenia wykorzystywany adversarialnie, a nie po prostu „wiele odpowiedzi DNS”. Silniejsze dowody łączą niski TTL, dużą liczbę unikalnych adresów, szerokie rozproszenie ASN/geograficzne, krótki czas życia node’a, powtarzalne zachowanie aplikacji i podejrzaną historię rejestracji. CDN-y legalnie mają kilka z tych właściwości. MITRE zaleca korelowanie zachowania DNS z procesem i późniejszymi połączeniami.<sup>[[5]](#references)</sup>

DGA można wykrywać na podstawie entropii leksykalnej, wzorców spółgłosek/cyfr, burstów NXDOMAIN, zsynchronizowanych domen first-seen i kontekstu procesu. Wordlist DGA i modele generatywne omijają proste reguły entropii, przez co ważniejsze stają się temporal clustering w całej flocie i lineage endpointów.

## Compromised domains i domain shadowing

Actor może przejąć konto registrara/DNS, przejąć dangling subdomain lub dodać rekordy pod istniejącą, renomowaną domeną. **Domain shadowing** zachowuje legalny apex, podczas gdy duża liczba subdomen kontrolowanych przez attackera wskazuje na zmieniające się hosty delivery lub C2. Wykorzystuje wiek i reputację domeny oraz może omijać blokowanie całej domeny.<sup>[[6]](#references)</sup>

Defenders potrzebują logów audytowych registrara i authoritative DNS, MFA, blokad registry/registrara, alertów dotyczących nowych delegacji/API tokenów/name serverów, monitorowania certificate transparency oraz inwentaryzacji cloud resources wskazywanych przez DNS. Rozdzielnie analizuj resolution i historię certyfikatów subdomeny, niezależnie od reputacji apexu.

## Web services i dead-drop resolvers

**Dead-drop resolver (T1102.001)** przechowuje zakodowany pointer do bieżącego C2 w legalnym poście, profilu, dokumencie, repository, cloud object lub polu blockchaina. Malware pobiera publiczny obiekt, dekoduje domenę/IP i kontaktuje się z kolejnym stage’em. Warianty bidirectional wymieniają commands lub files za pośrednictwem service APIs.<sup>[[7]](#references)</sup>

Zapewnia to resilience i ukrywa back-end C2 przed statyczną analizą binary. Tworzy jednak również stabilne identyfikatory obiektu, tenanta, repository, API i wzorców dostępu. Defenders powinni łączyć:

1. proces, który skontaktował się z usługą;
2. dokładną ścieżkę API/obiekt i hash odpowiedzi;
3. aktywność dekodowania lub przetwarzania strings;
4. nowe połączenie outbound krótko potem; oraz
5. identyczne zachowanie w innych miejscach floty.

Blokowanie całego GitHub, cloud storage lub social media rzadko jest wykonalne. Service-aware egress policy i korelacja na poziomie procesu są skuteczniejsze niż blokowanie wyłącznie domen.

## Persony, konta i compartmentalization procurement

Anonymity infrastruktury zawodzi, gdy persona, recovery email, telefon, płatność, browser lub admin IP łączy compartmenty. Operacje powiązane z państwami rozwijały profile społecznościowe, tożsamości email i konta cloud na długo przed ich użyciem; ATT&CK rejestruje to jako Establish Accounts (T1585), w tym podtechniki social, email i cloud.<sup>[[8]](#references)</sup>

Defender lub investigator buduje graph na podstawie:

- czasu utworzenia i pierwszego logowania, locale, strefy czasowej oraz harmonogramu pracy;
- pól recovery, urządzeń MFA, dokumentów tożsamości i instrumentów płatniczych;
- odcisków browser/TLS i historii sieci źródłowych;
- ponownego użycia avatara, pochodzenia obrazów, stylu pisania i rozwoju social graphu;
- wspólnego registrara domeny, name servera, certyfikatu, analytics ID lub commita repository;
- działań management plane omijających architekturę public relay.

W przypadku autoryzowanego red teamu synthetic personas powinny być udokumentowane u exercise controllera, korzystać z należących do organizacji kanałów recovery/payment, unikać podszywania się pod prawdziwe, niezaangażowane osoby i mieć zaplanowane wycofanie. SOC może pozostać ślepy, ale operacja nie może stać się nieodpowiedzialna.

## Emerging compound patterns do threat-modelowania

Poniższe przykłady to **defender-driven compositions**, a nie twierdzenia, że nazwany actor wdrożył każdy dokładnie taki design. Łączą już obserwowane primitives i są użytecznymi hipotezami purple-team.

### Asymmetric one-way tasking

Commands docierają przez publiczne, broadcastowe lub append-only źródło, natomiast results wychodzą innym kanałem z opóźnieniem. Przykłady primitive obejmują web-service one-way communication i dead drops. Separacja uniemożliwia, by pojedynczy flow wyglądał na bidirectional, oraz utrudnia prostą korelację request/response.<sup>[[9]](#references)</sup>

**Detection:** zachowuj odczyty na poziomie obiektów, a następnie koreluj zmiany stanu procesu i późniejsze transfery outbound w szerszym oknie czasowym. Szukaj rzadkiego procesu odczytującego ten sam publiczny obiekt, nawet gdy nie następuje natychmiastowa odpowiedź.

### Multi-stage channel promotion

Cichy pierwszy stage wykonuje inventory i promuje tylko wybrane systemy do niezwiązanego kanału second-stage. Drugi endpoint, protocol i process mogą nie dzielić żadnej infrastruktury z pierwszym. Ogranicza to ekspozycję capable infrastructure i jest jawnie modelowane jako ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** łącz `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; nie zamykaj incidentu po zablokowaniu pierwszej domeny.

### Cross-protocol relay translation

Różne hops tłumaczą HTTPS, QUIC, WebSocket, DNS, SSH lub message-queue API zamiast transparentnie forwardować packets. Translation usuwa pojedynczy end-to-end protocol fingerprint, ale tworzy gateways o charakterystycznym timingu, bufferingu i semantic conversion. Protocol tunneling (T1572) można łączyć z proxies i service impersonation.<sup>[[11]](#references)</sup>

**Detection:** szukaj gateway hosts, które odbierają jeden protocol i inicjują inny, przy ściśle powiązanym zachowaniu byte/time; porównuj intent endpointu z faktycznie przenoszonym protokołem.

### Passive activation on edge devices

Zamiast beaconingu implant monitoruje ruch docierający już do routera/VPN i aktywuje się wyłącznie po magic value, wzorcu source-port lub uwierzytelnionym tokenie. Normalny traffic nadal trafia do prawdziwej usługi. ATT&CK nazywa to Traffic Signaling (T1205), z udokumentowanymi przykładami dotyczącymi network devices i APT.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture podczas autoryzowanego huntu, nieoczekiwane socket filters i różnicowe zachowanie usługi. Brak okresowego beacona nie dowodzi, że edge device jest czysty.

### Serverless and ephemeral origin rotation

Front utrzymuje stabilną logiczną tożsamość, podczas gdy krótkotrwałe functions/containers obsługują poszczególne stages w wielu regionach/kontach. Ogranicza to czas życia na dysku i stałe origin IPs, ale tworzenie w control plane, image/layer, role, secret, request ID i billing telemetry stają się trwałym graphem.

**Detection:** przechowuj cloud audit i invocation logs poza workloadem; grupuj deployment templates, roles, environment keys oraz relacje front-to-origin.

### Privacy-layer diversity

Operacja może celowo unikać jednego homogenicznego chainu: na przykład jeden kanał korzysta z leased relay, tasking używa public object, exit pochodzi z należącego do organizacji lab cellular link, a administration korzysta z oddzielnej sieci organizacji. Zmniejsza to wartość przejęcia jednego providera, ale zwiększa ryzyko korelacji timingowej między warstwami i błędów operacyjnych.

**Detection:** buduj timelines kampanii obejmujące sensory identity, DNS, SaaS, network i cloud. Szukaj zsynchronizowanych zmian stanu, a nie identycznych indicators.

### Decentralized or transparency-log dead drops

Actor może umieścić mały zaszyfrowany pointer w dowolnym trwałym publicznym systemie append-only, content-addressed store lub transparency-like feed. Publiczny obiekt jest odporny, ale jego dokładny index/content hash i zachowanie klienta podczas pollingu stają się stabilnymi identyfikatorami.

**Detection:** rejestruj pełne identyfikatory API/obiektów i hashe odpowiedzi; alertuj o niestandardowych procesach odpytujących immutable objects, po których następuje dekodowanie lub nowe połączenie.

### Delayed store-and-forward operations

Interactive C2 tworzy silną korelację czasową. Design store-and-forward grupuje zaszyfrowane jobs i zwraca results po minutach lub godzinach przez inną queue albo transfer fizyczny. Poświęca responsywność na rzecz słabszej korelacji end-to-end timing.

**Detection:** wydłuż okna korelacji, modeluj okresowy dostęp do queue i analizuj endpoint staging. Batching przenosi sygnał z packet timingu do zaplanowanego zachowania procesów/plików; nie usuwa go.

## Design review: myśl w kategoriach obserwatorów

Dla każdej ścieżki wypełnij tę tabelę przed deploymentem i po zebraniu danych:

| Warstwa | Widzi source? | Widzi destination? | Widzi content? | Stabilne identyfikatory | Właściciel retencji/legalny |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Jeśli jeden zwykły provider może wypełnić każdą kolumnę, architektura zapewnia concealment przed targetem, ale nie zapewnia solidnej separacji. Jeśli żaden wewnętrzny controller nie może powiązać activity z engagementem, rozwiązanie nie nadaje się do profesjonalnego red teamingu.

## References

- [1] [MITRE ATT&CK — Pozyskiwanie infrastruktury (T1583), przejmowanie infrastruktury (T1584) i proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Aktorzy szpiegowscy powiązani z Chinami wykorzystują sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Przejmowanie infrastruktury: domeny (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
