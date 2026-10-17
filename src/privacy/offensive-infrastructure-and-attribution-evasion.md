# Infrastruktura ofensywna i unikanie atrybucji

{{#include ../banners/hacktricks-training.md}}

Operator rzadko uzyskuje znaczącą anonimowość, korzystając z pojedynczego proxy. Rzeczywiste kampanie tworzą **graf separacji**: operator łączy się z węzłem dostępu, węzły tranzytowe ukrywają ten węzeł przed węzłem wyjściowym, redirectory chronią właściwe C2, a jednorazowe nazwy wskazują na publiczny punkt brzegowy.

Skorzystaj z [katalogu technik anonimowego dostępu do Internetu](anonymous-internet-access-techniques.md), aby zapoznać się ze znormalizowanym przeglądem zalet i wad, wdrożenia oraz wykrywania każdej ze ścieżek. Ta strona dokładniej omawia komponowanie infrastruktury przeciwnika.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Ostatni adres widziany przez cel jest więc dowodem na istnienie ścieżki, a nie dowodem na to, kto kontrolował klawiaturę. MITRE mapuje główne komponenty na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klasy infrastruktury

| Klasa | Dlaczego aktor jej używa | Trwałe ślady | Najlepszy punkt zaczepienia dla obrońcy |
|---|---|---|---|
| Wynajęty VPS/cloud | Szybki, przewidywalny, routowalny, łatwy do odtworzenia | dzierżawca, rozliczenia, konsola, historia logowań źródłowych i obrazów | zdarzenia na koncie/płaszczyźnie sterowania i powtarzające się odciski serwera |
| Komercyjny VPN/Tor | Duży współdzielony zestaw adresów wyjściowych; brak konieczności administrowania serwerem | widoczność dostawcy/nadzoru i korelacja czasowa od końca do końca | zachowanie celu, dowody z punktu końcowego i korelacja przepływów |
| Proxy residential/mobile | ASN konsumencki i wiarygodność geograficzna | dane brokera/klienta; proxyware lub zachowanie zainfekowanego hosta | niemożliwa podróż, protokoły proxy i zmiany adresu w ramach sesji |
| Przejęty serwer/router/IoT | Wykorzystuje reputację i jurysdykcję ofiary | implant, przepływ zarządzający i powtarzający się upstreamowy kontroler | telemetria urządzenia i topologia ORB, a nie pojedynczy adres wyjściowy |
| CDN/redirector | Oddziela publiczną warstwę brzegową od back-endowego C2 | gramatyka TLS/HTTP, certyfikat, routing i artefakty konta cloud | korelacja warstwy brzegowej z originem i grupowanie kształtu żądań |
| Legalna usługa webowa | Wtapia się w dozwolony ruch GitHub/cloud/social | token API, identyfikatory dzierżawcy/obiektu i nietypowe pochodzenie procesu | proces punktu końcowego oraz semantyka usługi/API |
| Ścieżka fizyczna/komórkowa/satelitarna | Zmienia pozorne fizyczne źródło | dane radiowe, operatora, abonenta, urządzenia i lokalizacji | łączne dowody radiowe/fizyczne i sieciowe |

## Sieci węzłów przekaźnikowych ORB

**Sieć ORB** to zarządzana flota proxy używana jako usługa pośrednicząca. Mandiant dzieli je na sieci udostępniane z dzierżawionych serwerów, sieci nieudostępniane z przejętych routerów/IoT oraz rozwiązania hybrydowe. Dojrzała topologia ma cztery logiczne role:<sup>[[2]](#references)</sup>

1. **Serwer administracyjny (ACOS):** przechowuje spis zasobów, poświadczenia, stan i zasady routingu.
2. **Węzeł dostępowy/przekaźnikowy:** uwierzytelnia klientów lub operatorów; jest stabilnym wejściem do zmieniającej się siatki.
3. **Węzły pośredniczące:** jeden lub więcej dzierżawionych lub przejętych systemów przekazuje nieprzezroczyste połączenia.
4. **Węzeł wyjściowy/stagingowy:** prezentuje końcowy adres źródłowy celom rozpoznania, eksploatacji lub C2.

Siatka może wybierać węzły wyjściowe według kraju, ASN, opóźnienia lub dostępności, a także wymieniać niesprawne węzły. Kilka grup zagrożeń może wynajmować tę samą sieć. Mandiant zaobserwował, że niektóre adresy IPv4 pozostawały powiązane z wybranymi ORB zaledwie przez 31 dni; dlatego zaleca traktować **sieć jako ewoluujący byt przypominający aktora**, zamiast blokować nieaktualną listę adresów IP.<sup>[[2]](#references)</sup>

### Co to zapewnia — i co ujawnia

- Cel widzi węzeł wyjściowy, który może znajdować się geograficznie blisko i pozornie być łączem residential.
- Węzeł wyjściowy widzi cel i poprzedni hop, ale niekoniecznie operatora.
- Usługa dostępowa widzi klienta i żądanie trasy. Niezależnie zarządzana siatka może oddzielać klienta od węzłów wyjściowych, ale tworzy wartościowy zapis po stronie kontrahenta.
- Powtarzające się porty, kolejność uzgadniania, banery serwera, certyfikaty, okresy dostępności i powiązania kontrolerów mogą ujawnić flotę, nawet gdy adresy IP się zmieniają.
- Przejęty router często nie udostępnia telemetrii punktu końcowego, ale jego ISP nadal ma dane abonenta i przepływów; przejęcie urządzenia ujawnia artefakty implantu/konfiguracji.

{% hint style="info" %}
W ramach autoryzowanego ćwiczenia odtwórz topologię przy użyciu należących do organizacji maszyn wirtualnych lub routerów i zachowaj mapę atrybucji kontrolera. Nie używaj otwartych proxy ani urządzeń stron trzecich. [Przewodnik po laboratorium](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) tworzy tę samą strukturę hopów widoczną dla obrońcy, nie narażając pośrednika na szkodę.
{% endhint %}

## Sieci proxy residential i mobile

Usługi proxy residential przydzielają sesjom adresy łączy szerokopasmowych konsumentów; proxy mobile wychodzą przez pule NAT operatorów. Źródłem mogą być urządzenia zapisane do usługi za wyraźną zgodą, SDK/proxyware dołączone do aplikacji konsumenckich, resellerzy lub malware. Te źródła nie są równoważne: brak świadomej zgody zmienia usługę prywatności w przejętą infrastrukturę.

Tryby rotacji wpływają na wykrywanie:

- **rotacja dla każdego żądania** powoduje szybkie zmiany adresów IP i ASN/geografii, podczas gdy tożsamość na wyższych warstwach pozostaje stabilna;
- **sesje sticky** utrzymują węzeł wyjściowy przez minuty lub godziny, przypominając zwykłego abonenta;
- **bramy backconnect** udostępniają klientowi jeden punkt końcowy brokera, a wybór węzła wyjściowego odbywa się wewnętrznie;
- **pule mobile** umieszczają wielu rzeczywistych abonentów za niewielką liczbą adresów NAT operatora, przez co blokada IP może być kosztowna.

Obrońcy powinni korelować IP z uwierzytelnioną sesją, odciskiem TLS/klienta, kolejnością HTTP, cookie urządzenia i zachowaniem. Rzekomo lokalne logowanie residential, po którym następuje logowanie z innego kraju przy identycznych cechach na wyższych warstwach, jest silniejszym sygnałem niż sama reputacja. Z drugiej strony współdzielenie adresów i przełączanie się między komórkami powodują uzasadnione zmiany, więc nigdy nie traktuj klasyfikacji residential/proxy jako werdyktu.

### Płaszczyzny sterowania proxyware i nakładanie się resellerów

Nie modeluj puli residential jako płaskiej listy węzłów wyjściowych. Analiza ekosystemu IPIDEA ujawniła wielokrotnie wykorzystywaną **dwupoziomową płaszczyznę sterowania**: osadzone SDK najpierw zgłasza metadane urządzenia/rejestracji do domeny Tier One, a następnie otrzymuje pary IP:port dla planowania oraz Tier Two `connect`/`proxy`. Węzeł okresowo odpytuje port Tier Two connect o zakodowane zadanie, otwiera drugie połączenie z powiązanym portem proxy i przekazuje dostarczone bajty do żądanego celu. SDK i marki proxy, które nominalnie wyglądały na odrębne, miały osobne domeny wykrywania, ale zbiegały się na wspólnej infrastrukturze Tier Two i nakładających się pulach wyjściowych wskutek wspólnego właścicielstwa i relacji resellerów.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Daje to trwalsze punkty zaczepienia do huntowania niż blok adresów residential IP:<sup>[[13]](#references)</sup>

- nieoczekiwany proces narzędzia użytkowego, VPN-a, gry lub urządzenia wbudowanego wysyła stabilny identyfikator urządzenia/klucz klienta i otrzymuje zmienną listę serwerów;
- endpoint odpytuje bezpośredni adres IP na nietypowym porcie, a następnie — tuż przed otwarciem nowego gniazda do innego celu — łączy się z innym portem pod tym samym adresem;
- kilka pozornie niezależnych marek korzysta z tych samych adresów Tier Two, gramatyki protokołu, kodu SDK lub nakładających się węzłów wyjściowych;
- różne aplikacje łączące się z różnymi domenami Tier One otrzymują adresy z tej samej puli Tier Two.

To nakładanie się ogranicza również możliwość przypisania działań do konkretnego podmiotu: obecność adresu IP w reklamowanej puli dostawcy nie dowodzi, który reseller, klient lub threat actor używał go w danym czasie. Zachowaj znaczniki czasu przepływów, pochodzenie procesów, treści odpowiedzi Tier One i identyfikatory zadań Tier Two.<sup>[[13]](#references)</sup> W ramach autoryzowanego ćwiczenia emuluj tę hierarchię wyłącznie przy użyciu endpointów należących do organizacji; nigdy nie rejestruj urządzeń konsumenckich ani oprogramowania proxy stron trzecich.

## Łańcuchy proxy wieloskokowe

MITRE odróżnia proxy zewnętrzne od **proxy wieloskokowych (T1090.003)**. Istotna jest nie liczba skoków, lecz rozdzielenie wiedzy i administracji.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Jeśli jedna strona obsługuje A i B, współdzielone logi lub czas przepływu mogą pozwolić odtworzyć obwód. Dodanie kolejnych komercyjnych VPN-ów z tego samego punktu końcowego lub konta może zwiększyć opóźnienie, ale nie eliminuje wspólnych śladów dotyczących tożsamości, płatności i czasu. Tor ogranicza ten problem dzięki niezależnie wybieranym relayom i wspólnemu projektowi klienta, ale sieć interaktywna o niskich opóźnieniach nie może zagwarantować odporności na obserwatora mierzącego ruch na obu końcach.

Typowe błędy to wycieki DNS lub IPv6, aplikacje otwierające własne gniazda, ruch zarządzający docierający bezpośrednio do relayów, zsynchronizowana aktywność, ponownie używane klucze SSH i logowanie do kont ujawniających tożsamość. Weryfikacja powinna polegać na teście awarii: wyłączaj kolejno każdy relay i sprawdź, czy obciążenie nie może przejść na bezpośrednią, niezaszyfrowaną ścieżkę.

### Załamanie tunelu i wycieki do infrastruktury upstream

Architektura relayów jest często najbardziej podatna na atrybucję w razie awarii. Unit 42 udokumentowało wielopoziomową ścieżkę szpiegowską wykorzystującą VPS-y widoczne dla ofiar, VPS-y pełniące rolę relayów, residential proxies, Tor i inne usługi proxy; gdy pominięto tunel lub doszło do jego załamania, ukryta infrastruktura upstream łączyła się bezpośrednio z relayami i systemami widocznymi dla ofiar. W tym samym śledztwie wykorzystano też certyfikat X.509, który przez krótki czas był ujawniony w infrastrukturze upstream, jako punkt zaczepienia do korelacji między poziomami.<sup>[[14]](#references)</sup>

Oddziel **data plane** (`victim <-> exit`) od **control plane** (`operator/upstream -> relay administration`). Zachowuj logi połączeń przychodzących i uwierzytelniania na każdym kontrolowanym poziomie, historię certyfikatów i krótkie, nieudane połączenia — nie tylko udane sesje C2. Źródło widoczne wyłącznie podczas awarii relayów lub bezpośrednio administrujące wieloma węzłami widocznymi dla ofiar jest mocniejszym kandydatem na infrastrukturę upstream niż zwykły exit, ale jego ASN/geolokalizacja to nadal hipoteza, a nie dowód tożsamości operatora.

Autoryzowane laboratorium powinno skonfigurować obciążenie tak, by w razie awarii nie przechodziło na niezabezpieczoną ścieżkę. W przypadku obciążenia odizolowanego w przestrzeni nazw sieci Linux pierwsza trasa musi prowadzić przez tunel; po jego usunięciu zarówno żądanie, jak i wyszukiwanie trasy muszą zakończyć się niepowodzeniem, zamiast wybrać fizyczne łącze uplink:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Powtórz test dla DNS i IPv6 oraz na każdej granicy przekaźnika. Jeśli któraś sonda zadziała, zapisz rzeczywisty interfejs/adres źródłowy, zanim naprawisz routing zasad lub firewall; ta obserwacja to attribution leak, który zobaczyłby śledczy.

## Warstwy redirectorów i kształtowanie ruchu

Publiczny **redirector** akceptuje ruch zgodny z gramatyką specyficzną dla operacji i przekazuje go do chronionego serwera zespołu. Wszystko inne można odrzucić lub obsłużyć, serwując nieszkodliwą zawartość.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Wiele warstw ogranicza ekspozycję: spalenie domeny publicznej nie musi ujawnić serwera zespołu. CDN-y zapewniają przepustowość anycast i wiarygodną domenę zewnętrzną, ale konto CDN i logi edge stają się punktami atrybucji. Odciski TLS, historia certyfikatów, charakterystyczne ścieżki/kolejność nagłówków, rozmiary odpowiedzi, zachowanie przekierowań i listy dozwolonych originów mogą pozwolić powiązać pozornie niepowiązane fronty.

Na potrzeby wykrywania zapisuj pola reverse proxy przed normalizacją, porównuj SNI/Host/authority, sprawdzaj rzadkie kombinacje nagłówków, grupuj treści odpowiedzi i odciski TLS oraz szukaj nakładania się konfiguracji w logach audytowych chmury/CDN. Podczas autoryzowanych ćwiczeń red team nie kopiuj prawdziwej marki ani nie umieszczaj zbierania poświadczeń za pośrednictwem niepowiązanej strony trzeciej.

## Domain fronting i domainless fronting

W klasycznym **domain fronting (T1090.004)** połączenie TLS reklamuje w SNI dozwoloną domenę frontową, podczas gdy zaszyfrowane żądanie HTTP `Host` lub HTTP/2 `:authority` wskazuje inną domenę back-endu. Współpracujący CDN kieruje ruch na podstawie wartości wewnętrznej. Obserwator sieci bez deszyfrowania TLS widzi front; CDN widzi obie wartości i origin. W wariantach domainless SNI może być puste, podczas gdy inne pole routingu wybiera cel.<sup>[[4]](#references)</sup>

To nie jest magiczne podszywanie się: działa tylko wtedy, gdy pośrednik celowo lub przypadkowo dopuszcza taką niezgodność i potrafi kierować ruch na podstawie wewnętrznej nazwy. Główni dostawcy ograniczyli fronting między kontami. Encrypted ClientHello (ECH) zmienia to, co może zobaczyć obserwator na ścieżce, ale nie usuwa zapisów CDN, endpointu ani aplikacji.

Punkty wykrywania obejmują:

- drzewo procesów endpointu i cel, którego dana aplikacja nie powinna oczekiwać;
- niezgodność SNI i HTTP authority, gdy inspekcja TLS jest zgodna z prawem i dostępna;
- logi CDN wskazujące, że jeden tenant/front kieruje ruch do innego authority/origin;
- nietypowe, długo trwające lub cykliczne sesje z usługą, która zwykle służy do interakcji;
- stabilne rozmiary i częstotliwość zaszyfrowanego ruchu przy zmieniających się domenach frontowych.

Bezpieczne laboratorium symuluje niezgodność routingu na należącym do nas reverse proxy; nie nadużywa publicznego CDN.

## Dynamiczne rozwiązywanie nazw: DDNS, DGA i fast flux

Dynamiczne rozwiązywanie nazw oddziela logiczną usługę od stałej infrastruktury:

- **DDNS:** uwierzytelniony klient aktualizuje stabilną nazwę po zmianie adresu.
- **DGA:** endpoint i kontroler generują kandydackie nazwy domen na podstawie ziarna czasu/klucza; operator rejestruje niewielką ich część.
- **Fast flux:** nazwa zwraca szybko zmieniający się zestaw przejętych adresów/proxy, często z krótkimi TTL.
- **Double flux:** zmieniają się zarówno adresy usług, jak i adresy autorytatywnych serwerów nazw, co ukrywa także warstwę kontroli.

Fast flux to wzorzec dystrybucji obciążenia wykorzystywany przez adwersarzy, a nie po prostu „wiele odpowiedzi DNS”. Mocniejsze dowody łączą krótki TTL, dużą liczbę unikalnych adresów, szerokie rozproszenie ASN/geograficzne, krótki czas życia węzłów, powtarzające się zachowanie aplikacji i podejrzaną historię rejestracji. CDN-y legalnie wykazują kilka z tych samych cech. MITRE zaleca korelowanie zachowania DNS z procesem i późniejszymi połączeniami.<sup>[[5]](#references)</sup>

DGA można wykrywać na podstawie entropii leksykalnej, wzorców spółgłosek/cyfr, serii NXDOMAIN, zsynchronizowanych domen wykrytych po raz pierwszy oraz kontekstu procesu. DGA oparte na listach słów i modele generatywne omijają proste reguły entropii, przez co ważniejsze stają się klastrowanie czasowe w całej flocie i pochodzenie procesów na endpointach.

## Przejęte domeny i domain shadowing

Podmiot może przejąć konto rejestratora/DNS, przejąć osieroconą subdomenę albo dodać rekordy w obrębie skądinąd wiarygodnej domeny. **Domain shadowing** pozostawia legalną domenę główną, a jednocześnie kieruje dużą liczbę subdomen kontrolowanych przez atakującego do zmieniających się hostów delivery lub C2. Wykorzystuje wiek i reputację domeny, przez co może uniknąć blokowania całej domeny.<sup>[[6]](#references)</sup>

Obrońcy potrzebują logów audytowych rejestratora i autorytatywnego DNS, MFA, blokad rejestru/rejestratora, alertów o nowych delegacjach/tokenach API/serwerach nazw, monitorowania certificate transparency oraz spisu zasobów chmurowych wskazanych przez DNS. Rozwiązanie nazwy i historię certyfikatów subdomeny analizuj niezależnie od reputacji domeny głównej.

## Usługi webowe i dead-drop resolvers

**Dead-drop resolver (T1102.001)** przechowuje zakodowany wskaźnik do aktualnego C2 w legalnym poście, profilu, dokumencie, repozytorium, obiekcie w chmurze lub polu blockchaina. Malware pobiera publiczny obiekt, dekoduje domenę/IP i łączy się z kolejnym etapem. Warianty dwukierunkowe wymieniają polecenia lub pliki za pośrednictwem API usług.<sup>[[7]](#references)</sup>

Jeden wariant resolvera specyficzny dla GitHub używa Issues Search API tylko wtedy, gdy uwierzytelniony kanał repozytorium zawiedzie. Klient wyszukuje zgłoszenia pasujące do bieżącej daty, repozytorium i typu zgłoszenia, przechodzi do adresu URL komentarzy każdego zgłoszenia i wyodrębnia szyfrogram znajdujący się między znacznikami `<!--` i `-->`. Po deszyfrowaniu zależnym od hosta i daty pola takie jak `Owner`, `LicRepo` i `LicToken` zastępują głównego właściciela repozytorium, ścieżkę i token. Dzięki temu operator może zmieniać poświadczenia i endpointy bez wymiany klienta; komentarz do zgłoszenia pełni rolę resolvera, a pliki repozytorium pozostają kanałem taskingu.<sup>[[15]](#references)</sup>

Wariant dla Androida przy uruchomieniu wybiera jedną z dwóch publicznych stron Telegrama i wyodrębnia szyfrogram znajdujący się między dwoma wystąpieniami znacznika osadzonego w APK. Dekoduje wartość w Base64URL i odszyfrowuje ją za pomocą AES-128-CBC: pierwsze 16 bajtów `SHA-256(marker)` stanowi klucz, a pozostałe 16 bajtów — IV. Tekst jawny to właściwy bazowy URL C2, a nie URL strony Telegrama. Przy odtwarzaniu rozwiązywania zachowaj treść strony i dokładny znacznik; zmiana publicznej strony pozwala zmienić endpoint bez ponownej kompilacji APK.<sup>[[16]](#references)</sup>

Zapewnia to odporność i ukrywa back-end C2 przed statyczną analizą binarną. Tworzy też stabilne identyfikatory obiektów, tenantów, repozytoriów, API i wzorców dostępu. Obrońcy powinni łączyć:

1. proces, który połączył się z usługą;
2. dokładną ścieżkę API/obiekt i hash odpowiedzi;
3. aktywność dekodowania lub przetwarzania ciągów;
4. nowe połączenie wychodzące krótko potem; oraz
5. identyczne zachowanie w innych miejscach floty.

Blokowanie całego GitHub, magazynów w chmurze lub mediów społecznościowych rzadko jest wykonalne. Polityka egress uwzględniająca usługi i korelacja na poziomie procesów są skuteczniejsze niż blokowanie wyłącznie na podstawie domen.

## Persony, konta i segmentacja zakupów

Anonimowość infrastruktury zawodzi, gdy persona, e-mail odzyskiwania, telefon, płatność, przeglądarka lub adres IP administratora łączy różne segmenty. Operacje powiązane z państwami przez długi czas rozwijały profile społecznościowe, tożsamości e-mailowe i konta w chmurze, zanim zaczęły ich używać; ATT&CK odnotowuje to jako Establish Accounts (T1585), obejmujące podtechniki związane z mediami społecznościowymi, pocztą e-mail i chmurą.<sup>[[8]](#references)</sup>

Obrońca lub śledczy buduje graf na podstawie:

- czasu utworzenia i pierwszego logowania, ustawień regionalnych, strefy czasowej i harmonogramu pracy;
- danych odzyskiwania konta, urządzeń MFA, dokumentów tożsamości i instrumentów płatniczych;
- odcisków przeglądarki/TLS i historii sieci źródłowej;
- ponownego użycia awatarów, pochodzenia obrazów, stylu pisania i rozwoju grafu społecznościowego;
- wspólnego rejestrującego domenę, serwera nazw, certyfikatu, identyfikatora analitycznego lub commitu repozytorium;
- działań w plane zarządzania, które omijają architekturę publicznych relayów.

Na potrzeby autoryzowanego red team syntetyczne persony należy udokumentować u kontrolera ćwiczenia, używać kanałów odzyskiwania/płatności należących do organizacji, unikać podszywania się pod prawdziwe, niezaangażowane osoby i zaplanować ich wycofanie. SOC może nie wiedzieć o ćwiczeniu; operacja nie może jednak pozostać bez rozliczalności.

## Nowe złożone wzorce do modelowania zagrożeń

Poniższe przykłady to **kompozycje opracowane z perspektywy obrońcy**, a nie twierdzenia, że wskazany aktor wdrożył dokładnie każdy z tych projektów. Łączą zaobserwowane już prymitywy i mogą służyć jako hipotezy dla purple team.

### Asymetryczny, jednokierunkowy tasking

Polecenia przychodzą przez publiczne źródło, broadcast lub źródło append-only, a wyniki wychodzą opóźnione przez niezależny kanał. Przykłady prymitywów obejmują jednokierunkową komunikację przez usługi webowe i dead dropy. Rozdzielenie kanałów sprawia, że pojedynczy przepływ nie wygląda na dwukierunkowy, i utrudnia prostą korelację żądanie/odpowiedź.<sup>[[9]](#references)</sup>

**Wykrywanie:** zachowuj informacje o odczytach na poziomie obiektów, a następnie koreluj zmiany stanu procesu z późniejszymi transferami wychodzącymi w szerszym przedziale czasu. Szukaj rzadkiego procesu odczytującego ten sam obiekt publiczny, nawet jeśli nie następuje po tym natychmiastowa odpowiedź.

### Promowanie kanału wieloetapowego

Cichy pierwszy etap przeprowadza inwentaryzację i przenosi wybrane systemy do niezależnego kanału drugiego etapu. Drugi endpoint, protokół i proces mogą nie współdzielić żadnej infrastruktury z pierwszym. Ogranicza to ekspozycję infrastruktury o większych możliwościach i jest jawnie ujęte w ATT&CK jako T1104.<sup>[[10]](#references)</sup>

**Wykrywanie:** łącz `pierwszy proces sieciowy -> pobrany/skonfigurowany stan -> nowy proces lub injection -> niezależny cel`; nie zamykaj incydentu po zablokowaniu pierwszej domeny.

### Translacja relayów między protokołami

Różne przeskoki tłumaczą HTTPS, QUIC, WebSocket, DNS, SSH lub API kolejki komunikatów, zamiast przezroczysto przekazywać pakiety. Translacja eliminuje pojedynczy odcisk protokołu end-to-end, ale tworzy bramy o charakterystycznym timingu, buforowaniu i konwersji semantycznej. Protocol tunneling (T1572) można łączyć z proxy i podszywaniem się pod usługi.<sup>[[11]](#references)</sup>

**Wykrywanie:** szukaj hostów-bram, które odbierają jeden protokół i inicjują inny, przy ściśle skorelowanym zachowaniu pod względem bajtów/czasu; porównuj intencję endpointu z faktycznie przenoszonym protokołem.

### Pasywna aktywacja na urządzeniach brzegowych

Zamiast wysyłać beacon, implant monitoruje ruch docierający już do routera/VPN i aktywuje się tylko po otrzymaniu magicznej wartości, wzorca portu źródłowego lub uwierzytelnionego tokena. Zwykły ruch nadal trafia do prawdziwej usługi. ATT&CK nazywa to Traffic Signaling (T1205), a udokumentowane przykłady dotyczą urządzeń sieciowych i APT.<sup>[[12]](#references)</sup>

**Wykrywanie:** integralność firmware/plików, przechwytywanie surowych pakietów podczas autoryzowanego huntu, nieoczekiwane filtry gniazd i różnice w zachowaniu usługi. Brak cyklicznego beacona nie dowodzi, że urządzenie brzegowe jest czyste.

### Rotacja originów serverless i efemerycznych

Front zachowuje stabilną tożsamość logiczną, podczas gdy krótkotrwałe funkcje/kontenery obsługują poszczególne etapy w kilku regionach/kontach. Ogranicza to czas życia danych na dysku i eliminuje stałe adresy IP originów, ale telemetria tworzenia zasobów w plane zarządzania, obrazy/warstwy, role, sekrety, identyfikatory żądań i rozliczenia tworzą trwały graf.

**Wykrywanie:** przechowuj logi audytowe i wywołań chmurowych poza obciążeniem; grupuj szablony wdrożeń, role, klucze środowiskowe i relacje front-origin.

### Różnorodność warstw prywatności

Operacja może celowo unikać jednorodnego łańcucha: na przykład jeden kanał korzysta z wynajętego relaya, tasking z publicznego obiektu, wyjście z należącego do organizacji laboratoryjnego łącza komórkowego, a administracja z oddzielnej sieci organizacji. Ogranicza to wartość przejęcia jednego dostawcy, ale zwiększa ryzyko korelacji czasowej między warstwami i błędów operacyjnych.

**Wykrywanie:** twórz osie czasu kampanii obejmujące czujniki tożsamości, DNS, SaaS, sieci i chmury. Szukaj zsynchronizowanych zmian stanu zamiast identycznych wskaźników.

### Zdecentralizowane dead dropy lub oparte na logach przejrzystości

Podmiot może umieścić mały zaszyfrowany wskaźnik w dowolnym trwałym publicznym systemie append-only, magazynie adresowanym treścią lub kanale podobnym do logu przejrzystości. Publiczny obiekt jest odporny, ale jego dokładny indeks/hash treści i zachowanie klienta podczas odpytywania stają się stabilnymi identyfikatorami.

**Wykrywanie:** zapisuj pełne identyfikatory API/obiektów i hashe odpowiedzi; generuj alerty, gdy nietypowe procesy odpytują niezmienne obiekty, a następnie dekodują dane lub nawiązują nowe połączenia.

### Opóźnione operacje store-and-forward

Interaktywne C2 tworzy silną korelację czasową. Projekt store-and-forward grupuje zaszyfrowane zadania, a wyniki zwraca po minutach lub godzinach przez inną kolejkę albo fizyczny transfer. W zamian za słabszą korelację czasową end-to-end ogranicza responsywność.

**Wykrywanie:** wydłużaj okna korelacji, modeluj cykliczny dostęp do kolejki i sprawdzaj staging na endpointach. Grupowanie przenosi sygnał z timingu pakietów na zaplanowane zachowanie procesów/plików; nie usuwa go.

## Przegląd projektu: myśl kategoriami obserwatorów

Dla każdej ścieżki wypełnij tę tabelę przed wdrożeniem i po zebraniu danych:

| Warstwa | Widzi źródło? | Widzi cel? | Widzi treść? | Stabilne identyfikatory | Retencja/właściciel prawny |
|---|---:|---:|---:|---|---|
| sieć lokalna/operator | | | | | |
| usługa wejściowa/dostępowa | | | | | |
| operator(zy) tranzytowy(i) | | | | | |
| exit/redirector/CDN | | | | | |
| autorytatywny DNS/rejestrator | | | | | |
| cel | | | | | |
| dostawca konta/płatności | | | | | |

Jeśli jeden zwykły dostawca może wypełnić każdą kolumnę, architektura zapewnia ukrycie przed celem, ale nie solidne rozdzielenie. Jeśli żaden wewnętrzny kontroler nie może powiązać aktywności z konkretnym ćwiczeniem, rozwiązanie nie nadaje się do profesjonalnych ćwiczeń red team.

## References

- [1] [MITRE ATT&CK — Pozyskiwanie infrastruktury (T1583), kompromitowanie infrastruktury (T1584) i proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Aktorzy szpiegowscy powiązani z Chinami wykorzystują sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Kompromitowanie infrastruktury: domeny (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Usługa webowa: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Zakładanie kont (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Usługa webowa: komunikacja jednokierunkowa (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Kanały wieloetapowe (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Tunelowanie protokołu (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Sygnalizacja ruchu (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Zakłócenie działania największej na świecie sieci residential proxy](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Kampanie Shadow: odkrywanie globalnego szpiegostwa](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Kampania Blinder Tunnel wymierzona w infrastrukturę Iraku](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI stworzyła nakładki. Ofiary tracą swoje PIN-y](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
