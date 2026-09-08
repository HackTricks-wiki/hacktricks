# Infrastruktura ofensywna i unikanie atrybucji

{{#include ../banners/hacktricks-training.md}}

Operator rzadko uzyskuje znaczącą anonimowość za pomocą pojedynczego proxy. Rzeczywiste kampanie budują **graf separacji**: operator dociera do węzła dostępowego, węzły tranzytowe ukrywają ten węzeł przed wyjściem, redirectory chronią prawdziwy C2, a jednorazowe nazwy wskazują na publiczną krawędź.

Skorzystaj z [Katalogu technik anonimowego dostępu do Internetu](anonymous-internet-access-techniques.md), aby uzyskać ujednolicony przegląd zalet, wad, wdrażania i wykrywania każdej ścieżki. Ta strona dokładniej omawia składanie infrastruktury przeciwnika.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Ostatni adres zaobserwowany przez cel jest zatem dowodem istnienia ścieżki, a nie dowodem na to, kto kontrolował klawiaturę. MITRE mapuje główne komponenty na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klasy infrastruktury

| Klasa | Dlaczego actor jej używa | Trwała ekspozycja | Najlepszy punkt zaczepienia dla defendera |
|---|---|---|---|
| Wynajęty VPS/cloud | Szybki, przewidywalny, routowalny, łatwy do odbudowy | tenant, billing, konsola, historia logowania do source i obrazów | zdarzenia konta/control plane oraz powtarzający się fingerprint serwera |
| Commercial VPN/Tor | Duży współdzielony zestaw adresów wyjściowych; brak administracji serwerem | widoczność providera/guarda i timing end-to-end | zachowanie celu, dane z endpointu i korelacja przepływów |
| Residential/mobile proxy | ASN konsumencki i wiarygodność geograficzna | dane brokera/klienta; zachowanie proxyware lub zainfekowanego hosta | impossible travel, protokoły proxy i zmienność adresów w ramach sesji |
| Compromised server/router/IoT | Wykorzystuje reputację i jurysdykcję ofiary | implant, przepływ zarządzania i powtarzający się upstream controller | telemetria urządzenia i topologia ORB, a nie pojedynczy exit IP |
| CDN/redirector | Oddziela publiczny edge od back-end C2 | gramatyka TLS/HTTP, certyfikat, routing i artefakty konta cloud | korelacja edge-to-origin i klastrowanie kształtu żądań |
| Legitimate web service | Wtapia się w dozwolony ruch GitHub/cloud/social | token API, identyfikatory tenant/object i nietypowa lineage procesu | proces endpointu oraz semantyka usługi/API |
| Ścieżka fizyczna/komórkowa/satelitarna | Zmienia pozorne źródło fizyczne | dane RF, operatora, abonenta, urządzenia i lokalizacji | połączone dowody radiowe/fizyczne i sieciowe |

## Operational relay box networks

**ORB network** to zarządzana flota proxy używana jako usługa pośrednia. Mandiant dzieli je na provisioned networks złożone z wynajętych serwerów, non-provisioned networks złożone z przejętych routerów/IoT oraz hybrydy. Dojrzała topologia ma cztery role logiczne:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** utrzymuje inwentarz, poświadczenia, stan i politykę routingu.
2. **Access/relay node:** uwierzytelnia klientów lub operatorów; jest stabilnym wejściem do zmieniającej się siatki.
3. **Traversal nodes:** jeden lub więcej wynajętych lub przejętych systemów przekazuje niejawne połączenia.
4. **Exit/staging node:** przedstawia końcowy adres źródłowy podczas reconnaissance, exploitation lub wobec celów C2.

Mesh może wybierać exity według kraju, ASN, opóźnienia lub dostępności i rotować niesprawne węzły. Wiele threat groups może wynajmować tę samą sieć. Mandiant zaobserwował, że adres IPv4 pozostawał powiązany z niektórymi ORB przez zaledwie 31 dni; dlatego zaleca traktowanie **sieci jako ewoluującej encji podobnej do actora**, zamiast blokowania nieaktualnej listy IP.<sup>[[2]](#references)</sup>

### Co to zapewnia — i co ujawnia

- Cel widzi exit, który może być geograficznie blisko i wyglądać na residential.
- Exit widzi cel oraz poprzedni hop, ale niekoniecznie operatora.
- Usługa access widzi klienta i żądanie trasy. Niezależnie zarządzany mesh może oddzielać klienta od exitów, ale tworzy potężny zapis u counterparty.
- Powtarzające się porty, kolejność handshake, bannery serwerów, certyfikaty, okna uptime i relacje z controllerem mogą ujawnić flotę, nawet gdy IP się zmieniają.
- Przejęty router często nie ma telemetrii endpointu, ale jego ISP nadal posiada dane abonenta i przepływów; przejęcie urządzenia ujawnia artefakty implantu/konfiguracji.

{% hint style="info" %}
W ramach autoryzowanego ćwiczenia odtwórz topologię za pomocą należących do organizacji VM lub routerów i zachowaj mapę atrybucji controllera. Nie pozyskuj otwartych proxy ani urządzeń stron trzecich. [Przewodnik po labie](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) tworzy tę samą strukturę hopów widoczną dla defendera bez krzywdzenia pośrednika.
{% endhint %}

## Residential i mobile proxy networks

Residential proxy services przypisują sesje do konsumenckich adresów szerokopasmowych; mobile proxies wychodzą przez pule carrier NAT. Źródłem mogą być jawnie zapisane urządzenia, SDK/proxyware dołączone do aplikacji konsumenckich, resellerzy lub malware. Te źródła nie są równoważne: brak świadomej zgody zmienia usługę prywatności w compromised infrastructure.

Tryby rotacji wpływają na detection:

- **per-request rotation** powoduje szybkie nieciągłości IP oraz ASN/geografii, podczas gdy tożsamość wyższych warstw pozostaje stabilna;
- **sticky sessions** utrzymują exit przez minuty lub godziny, przypominając zwykłego abonenta;
- **backconnect gateways** udostępniają klientowi jeden endpoint brokera i wewnętrznie wybierają exity;
- **mobile pools** umieszczają wielu prawdziwych abonentów za niewielkim zestawem adresów carrier NAT, przez co blokada IP jest kosztowna.

Defenderzy powinni korelować IP z uwierzytelnioną sesją, fingerprintem TLS/client, kolejnością HTTP, cookie urządzenia i zachowaniem. Pozornie lokalne logowanie residential, po którym następuje logowanie z innego kraju, przy identycznych wszystkich cechach wyższych warstw, jest silniejszym sygnałem niż sama reputacja. Z drugiej strony współdzielenie adresów i przełączanie między stacjami mobilnymi powodują uzasadnioną zmienność, dlatego nigdy nie traktuj klasyfikacji residential/proxy jako werdyktu.

## Multi-hop proxy chains

MITRE odróżnia external proxies od **multi-hop proxies (T1090.003)**. Istotną właściwością nie jest liczba hopów, lecz rozdzielenie wiedzy i administracji.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Jeśli jedna strona obsługuje A i B, współdzielone logi lub analiza czasów przepływu mogą odtworzyć obwód. Dodanie kolejnych komercyjnych VPN z tego samego endpointu lub konta może zwiększyć opóźnienia, jednocześnie pozostawiając wspólną tożsamość oraz ślady płatności i synchronizacji czasowej. Tor ogranicza ten problem dzięki niezależnie wybieranym relayom i współdzielonej architekturze klienta, ale interaktywna sieć o niskich opóźnieniach nie może zagwarantować odporności na obserwatora mierzącego oba końce.

Częstymi awariami są obejścia DNS lub IPv6, aplikacje otwierające własne sockety, ruch zarządzający docierający bezpośrednio do relayów, zsynchronizowana aktywność, ponownie używane klucze SSH oraz logowanie się do kont ujawniających tożsamość. Prawidłowa weryfikacja polega na teście awarii: zatrzymaj kolejno każdy relay i pokaż, że workload nie może przełączyć się na jawną ścieżkę.

## Warstwy redirectorów i kształtowanie ruchu

Publiczny **redirector** akceptuje ruch zgodny z gramatyką specyficzną dla danej operacji i przekazuje go do chronionego serwera zespołu. Wszystko inne może zostać odrzucone lub obsłużone za pomocą nieszkodliwej treści.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Wiele warstw ogranicza ekspozycję: spalenie publicznej domeny nie musi ujawniać serwera zespołu. CDN-y zapewniają przepustowość anycast i wiarygodną domenę zewnętrzną, ale konto CDN i logi edge stają się punktami atrybucji. Odciski TLS, historia certyfikatów, charakterystyczne ścieżki/kolejność nagłówków, rozmiary odpowiedzi, zachowanie przekierowań i allowlisty origin mogą grupować pozornie niezależne fronty.

Na potrzeby wykrywania rejestruj pola reverse proxy przed normalizacją, porównuj SNI/Host/authority, analizuj rzadkie kombinacje nagłówków, grupuj treści odpowiedzi i odciski TLS oraz przeszukuj logi audytowe cloud/CDN pod kątem nakładania się konfiguracji. W przypadku autoryzowanych red teamów unikaj kopiowania prawdziwej marki lub umieszczania zbierania danych uwierzytelniających za niezwiązanym z tym podmiotem trzecim.

## Domain fronting i domainless fronting

W przypadku klasycznego **domain fronting (T1090.004)** połączenie TLS reklamuje dozwoloną domenę frontową w SNI, podczas gdy zaszyfrowany nagłówek HTTP `Host` lub HTTP/2 `:authority` żąda innej domeny back-endu. Współpracujący CDN routuje na podstawie wewnętrznej wartości. Obserwator sieci bez deszyfrowania TLS widzi front; CDN widzi obie wartości oraz origin. W wariantach domainless SNI może być puste, a miejsce docelowe wybiera inne pole routingu.<sup>[[4]](#references)</sup>

To nie jest magiczne podszywanie się: działa wyłącznie wtedy, gdy pośrednik celowo lub przypadkowo zezwala na niezgodność i wie, jak routować wewnętrzną nazwę. Najwięksi dostawcy ograniczyli fronting między kontami. Encrypted ClientHello (ECH) zmienia to, co może zobaczyć obserwator znajdujący się na ścieżce, ale nie usuwa zapisów CDN, endpointu ani aplikacji.

Punkty wykrywania obejmują:

- drzewo procesów endpointu i miejsce docelowe nieoczekiwane dla danej aplikacji;
- niezgodność SNI i HTTP authority tam, gdzie inspekcja TLS jest zgodna z prawem i dostępna;
- logi CDN pokazujące routing jednego tenanta/frontu do innego authority/origin;
- nietypowe, długo utrzymywane lub okresowe sesje do usługi zwykle interaktywnej;
- stabilne rozmiary i częstotliwość zaszyfrowanego ruchu przy zmieniających się domenach frontowych.

Bezpieczne laboratorium symuluje niezgodność routingu na należącym do nas reverse proxy; nie nadużywa publicznego CDN.

## Dynamic resolution: DDNS, DGA i fast flux

Dynamic resolution oddziela usługę logiczną od stałej infrastruktury:

- **DDNS:** uwierzytelniony klient aktualizuje stabilną nazwę po zmianie adresu.
- **DGA:** endpoint i kontroler wyprowadzają kandydackie nazwy domen z ziarna czasu/klucza; operator rejestruje niewielki podzbiór.
- **Fast flux:** nazwa zwraca szybko zmieniający się zestaw zaatakowanych/adresów proxy, często z niskimi wartościami TTL.
- **Double flux:** obracają się zarówno adresy usług, jak i adresy autorytatywnych serwerów nazw, co dodatkowo ukrywa warstwę kontroli.

Fast flux to wzorzec dystrybucji obciążenia wykorzystywany w celach adversarial, a nie po prostu „wiele odpowiedzi DNS”. Silniejsze dowody łączą niskie TTL, dużą liczbę unikalnych adresów, szerokie rozproszenie ASN/geograficzne, krótki czas życia węzłów, powtarzalne zachowanie aplikacji i podejrzaną historię rejestracji. CDN-y legalnie mają kilka z tych właściwości. MITRE zaleca korelowanie zachowania DNS z procesem i kolejnymi połączeniami.<sup>[[5]](#references)</sup>

DGA można wykrywać na podstawie entropii leksykalnej, wzorców spółgłosek/cyfr, serii NXDOMAIN, zsynchronizowanych domen zaobserwowanych po raz pierwszy oraz kontekstu procesu. DGA oparte na wordlistach i modele generatywne omijają proste reguły entropii, przez co większe znaczenie zyskuje klastrowanie czasowe w całej flocie i lineage endpointów.

## Compromised domains i domain shadowing

Aktor może przejąć konto rejestratora/DNS, przejąć osieroconą subdomenę lub dodać rekordy pod skądinąd wiarygodną domeną. **Domain shadowing** zachowuje legalny apex, podczas gdy duża liczba kontrolowanych przez atakującego subdomen wskazuje na zmieniające się hosty delivery lub C2. Wykorzystuje wiek i reputację domeny oraz może omijać blokowanie na poziomie całej domeny.<sup>[[6]](#references)</sup>

Obrońcy potrzebują logów audytowych rejestratora i autorytatywnego DNS, MFA, blokad registry/registrar, alertów dotyczących nowych delegacji/tokenów API/serwerów nazw, monitorowania certificate transparency oraz inwentaryzacji zasobów cloud wskazywanych przez DNS. Rozdzielnie badaj rozwiązywanie subdomeny i historię jej certyfikatów, niezależnie od reputacji apexu.

## Web services i dead-drop resolvers

**Dead-drop resolver (T1102.001)** przechowuje zakodowany wskaźnik do bieżącego C2 wewnątrz legalnego posta, profilu, dokumentu, repozytorium, obiektu cloud lub pola blockchain. Malware pobiera publiczny obiekt, dekoduje domenę/IP i kontaktuje się z kolejnym etapem. Warianty dwukierunkowe wymieniają polecenia lub pliki za pośrednictwem API usług.<sup>[[7]](#references)</sup>

Zapewnia to odporność i ukrywa back-end C2 przed statyczną analizą binarną. Tworzy jednak stabilne identyfikatory obiektów, tenantów, repozytoriów, API i wzorców dostępu. Obrońcy powinni powiązać:

1. proces, który skontaktował się z usługą;
2. dokładną ścieżkę API/obiekt i hash odpowiedzi;
3. aktywność dekodowania lub przetwarzania ciągów;
4. nowe połączenie wychodzące wkrótce potem; oraz
5. identyczne zachowanie w innych miejscach floty.

Blokowanie całego GitHub, cloud storage lub social media rzadko jest wykonalne. Polityka egress uwzględniająca usługi i korelacja na poziomie procesu są skuteczniejsze niż blokowanie wyłącznie domen.

## Persony, konta i segmentacja procurement

Anonimowość infrastruktury zawodzi, gdy persona, recovery email, telefon, płatność, przeglądarka lub IP administratora łączy segmenty. Operacje powiązane z państwami rozwijały profile społecznościowe, tożsamości e-mail i konta cloud na długo przed ich użyciem; ATT&CK rejestruje to jako Establish Accounts (T1585), w tym podtechniki dotyczące kont social, e-mail i cloud.<sup>[[8]](#references)</sup>

Obrońca lub śledczy buduje graf na podstawie:

- czasu utworzenia i pierwszego logowania, lokalizacji, strefy czasowej i harmonogramu pracy;
- pól odzyskiwania konta, urządzeń MFA, dokumentów tożsamości i instrumentów płatniczych;
- odcisków przeglądarki/TLS i historii sieci źródłowych;
- ponownego użycia awatarów, pochodzenia obrazów, stylu pisania i rozwoju grafu społecznościowego;
- wspólnego rejestranta domeny, serwera nazw, certyfikatu, identyfikatora analitycznego lub commita w repozytorium;
- działań na płaszczyźnie zarządzania, które omijają publiczną architekturę relay.

W przypadku autoryzowanego red teamu syntetyczne persony powinny być udokumentowane u kontrolera ćwiczenia, korzystać z należących do organizacji kanałów odzyskiwania/płatności, unikać podszywania się pod prawdziwe, niezwiązane osoby i mieć zaplanowane wycofanie. SOC może pozostać nieświadomy; operacja nie może stać się pozbawiona odpowiedzialności.

## Emerging compound patterns to threat-model

Poniższe przykłady to **kompozycje tworzone z perspektywy obrońcy**, a nie twierdzenia, że nazwany aktor wdrożył każdy dokładnie taki projekt. Łączą już zaobserwowane prymitywy i są przydatnymi hipotezami purple-team.

### Asymmetric one-way tasking

Polecenia docierają przez publiczne, rozgłaszane lub append-only źródło, podczas gdy wyniki opuszczają środowisko innym kanałem z opóźnieniem. Przykłady prymitywów obejmują jednokierunkową komunikację przez web service i dead dropy. Rozdzielenie uniemożliwia pojedynczemu przepływowi wyglądanie na dwukierunkowy i utrudnia prostą korelację request/response.<sup>[[9]](#references)</sup>

**Detection:** zachowuj odczyty na poziomie obiektów, a następnie koreluj zmiany stanu procesu i późniejsze transfery wychodzące w szerszym oknie czasowym. Wyszukuj rzadki proces odczytujący ten sam publiczny obiekt, nawet gdy nie następuje natychmiastowa odpowiedź.

### Multi-stage channel promotion

Cichy pierwszy etap przeprowadza inwentaryzację i promuje do niezależnego kanału drugiego etapu tylko wybrane systemy. Drugi endpoint, protokół i proces mogą nie dzielić żadnej infrastruktury z pierwszym. Ogranicza to ekspozycję infrastruktury zdolnej do działania i jest jawnie modelowane jako ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** łącz `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; nie zamykaj incydentu po zablokowaniu pierwszej domeny.

### Cross-protocol relay translation

Różne hopy tłumaczą HTTPS, QUIC, WebSocket, DNS, SSH lub API message queue, zamiast transparentnie przekazywać pakiety. Tłumaczenie usuwa pojedynczy, end-to-end odcisk protokołu, ale tworzy gatewaye o charakterystycznym taktowaniu, buforowaniu i konwersji semantycznej. Protocol tunneling (T1572) można łączyć z proxy i service impersonation.<sup>[[11]](#references)</sup>

**Detection:** szukaj hostów gateway, które odbierają jeden protokół i inicjują inny, przy ściśle powiązanym zachowaniu pod względem bajtów/czasu; porównuj intencję endpointu z faktycznie przenoszonym protokołem.

### Passive activation on edge devices

Zamiast beaconowania implant monitoruje ruch docierający już do routera/VPN i aktywuje się wyłącznie po wartości magicznej, wzorcu portu źródłowego lub uwierzytelnionym tokenie. Normalny ruch nadal trafia do prawdziwej usługi. ATT&CK nazywa to Traffic Signaling (T1205), z udokumentowanymi przykładami dotyczącymi urządzeń sieciowych i APT.<sup>[[12]](#references)</sup>

**Detection:** integralność firmware/plików, przechwytywanie surowych pakietów podczas autoryzowanego huntu, nieoczekiwane filtry socketów i różnicowe zachowanie usługi. Brak okresowego beaconu nie dowodzi, że urządzenie edge jest czyste.

### Serverless i rotacja ephemeral origin

Front utrzymuje stabilną tożsamość logiczną, podczas gdy krótkotrwałe funkcje/kontenery obsługują poszczególne etapy w kilku regionach/kontach. Ogranicza to czas życia na dysku i stałe IP origin, ale tworzenie na płaszczyźnie sterowania, obraz/warstwa, rola, sekret, identyfikator żądania i telemetria billing stają się trwałym grafem.

**Detection:** przechowuj logi audytowe cloud i logi invocation poza workloadem; grupuj szablony wdrożeń, role, klucze środowiskowe oraz relacje front-to-origin.

### Różnorodność warstw prywatności

Operacja może celowo unikać jednego homogenicznego łańcucha: na przykład jeden kanał wykorzystuje dzierżawiony relay, tasking używa publicznego obiektu, exit pochodzi z należącego do organizacji laboratoryjnego łącza komórkowego, a administracja korzysta z odrębnej sieci organizacji. Zmniejsza to wartość przejęcia jednego dostawcy, ale zwiększa ryzyko korelacji czasowej między warstwami i błędów operacyjnych.

**Detection:** twórz osie czasu kampanii obejmujące sensory tożsamości, DNS, SaaS, sieci i cloud. Szukaj zsynchronizowanych zmian stanu, a nie identycznych wskaźników.

### Zdecentralizowane dead dropy lub dead dropy w logach przejrzystości

Aktor może umieścić mały zaszyfrowany wskaźnik w dowolnym trwałym publicznym systemie append-only, magazynie content-addressed lub kanale przypominającym transparency log. Publiczny obiekt jest odporny, ale jego dokładny indeks/hash treści oraz zachowanie klienta podczas odpytywania stają się stabilnymi identyfikatorami.

**Detection:** rejestruj pełne identyfikatory API/obiektów i hashe odpowiedzi; generuj alerty dotyczące niestandardowych procesów odpytujących niezmienne obiekty, po czym następuje dekodowanie lub nowe połączenie.

### Opóźnione operacje store-and-forward

Interaktywne C2 tworzy silną korelację czasową. Projekt store-and-forward grupuje zaszyfrowane zadania i zwraca wyniki po kilku minutach lub godzinach przez inną kolejkę albo transfer fizyczny. Poświęca responsywność na rzecz słabszej korelacji czasowej end-to-end.

**Detection:** wydłużaj okna korelacji, modeluj okresowy dostęp do kolejki i analizuj staging na endpointach. Grupowanie przenosi sygnał z taktowania pakietów na zaplanowane zachowanie procesów/plików; nie usuwa go.

## Design review: think in observers

Dla każdej ścieżki wypełnij tę tabelę przed wdrożeniem i po zebraniu danych:

| Warstwa | Widzi źródło? | Widzi miejsce docelowe? | Widzi treść? | Stabilne identyfikatory | Właściciel retencji/prawny |
|---|---:|---:|---:|---|---|
| sieć lokalna/operator | | | | | |
| usługa wejściowa/dostępowa | | | | | |
| operator(y) traversal | | | | | |
| exit/redirector/CDN | | | | | |
| autorytatywny DNS/rejestrator | | | | | |
| cel | | | | | |
| dostawca konta/płatności | | | | | |

Jeśli jeden zwykły dostawca może wypełnić każdą kolumnę, architektura zapewnia ukrycie przed celem, ale nie zapewnia solidnej separacji. Jeśli żaden wewnętrzny kontroler nie może powiązać aktywności z konkretnym zleceniem, rozwiązanie nie nadaje się do profesjonalnego red teamingu.

## References

- [1] [MITRE ATT&CK — Pozyskiwanie infrastruktury (T1583), kompromitowanie infrastruktury (T1584) i Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Aktorzy szpiegowscy powiązani z Chinami używają sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
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
{{#include ../banners/hacktricks-training.md}}
