# Infrastruktura ofensywna i unikanie atrybucji

{{#include ../banners/hacktricks-training.md}}

Operator rzadko uzyskuje znaczącą anonimowość dzięki pojedynczemu proxy. W prawdziwych kampaniach buduje się **graf separacji**: operator łączy się z węzłem dostępowym, węzły tranzytowe ukrywają go przed węzłem wyjściowym, redirectory chronią właściwe C2, a tymczasowe nazwy wskazują na publiczny punkt brzegowy.

Skorzystaj z [katalogu technik anonimowego dostępu do Internetu](anonymous-internet-access-techniques.md), aby zapoznać się ze znormalizowanym zestawieniem zalet i wad, wdrażania oraz wykrywania każdej ścieżki. Ta strona dokładniej omawia komponowanie infrastruktury w warunkach działań przeciwnika.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Ostatni adres widziany przez cel jest więc dowodem na przebytą ścieżkę, a nie dowodem na to, kto kontrolował klawiaturę. MITRE mapuje główne komponenty na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klasy infrastruktury

| Klasa | Dlaczego aktor z niej korzysta | Trwała ekspozycja | Najlepszy punkt zaczepienia dla obrońcy |
|---|---|---|---|
| Wynajęty VPS/cloud | Szybki, przewidywalny, routowalny, łatwy do odtworzenia | dzierżawca, rozliczenia, konsola, historia logowań źródłowych i obrazów | zdarzenia konta/płaszczyzny sterowania oraz powtarzający się fingerprint serwera |
| Komercyjny VPN/Tor | Duży współdzielony zestaw wyjściowy; brak konieczności administrowania serwerem | widoczność dostawcy/strażnika i korelacja czasowa end-to-end | zachowanie celu, dowody z endpointu i korelacja przepływów |
| Residential/mobile proxy | ASN konsumencki i wiarygodność geograficzna | dane brokera/klienta; zachowanie proxyware lub zainfekowanego hosta | niemożliwe podróże, protokoły proxy i zmiany adresu w ramach sesji |
| Zhakowany serwer/router/IoT | Wykorzystuje reputację i jurysdykcję ofiary | implant, przepływ zarządzania i powtarzający się kontroler upstream | telemetria urządzenia i topologia ORB, a nie pojedynczy wyjściowy adres IP |
| CDN/redirector | Oddziela publiczną krawędź od back-endowego C2 | gramatyka TLS/HTTP, certyfikat, routing i artefakty konta cloud | korelacja krawędzi z originem i grupowanie kształtu żądań |
| Legalna usługa internetowa | Wtapia się w dozwolony ruch GitHub/cloud/social | token API, identyfikatory dzierżawcy/obiektu i nietypowe pochodzenie procesu | proces na endpoincie oraz semantyka usługi/API |
| Trasa fizyczna/komórkowa/satelitarna | Zmienia pozorne fizyczne źródło | dane RF, operatora, abonenta, urządzenia i lokalizacji | łączne dowody radiowe/fizyczne i sieciowe |

## Sieci przekaźników operacyjnych

**Sieć ORB** to zarządzana flota proxy używana jako usługa pośrednicząca. Mandiant dzieli je na sieci provisioned, złożone z wynajętych serwerów, sieci non-provisioned, złożone ze zhakowanych routerów/urządzeń IoT, oraz hybrydy. Dojrzała topologia ma cztery logiczne role:<sup>[[2]](#references)</sup>

1. **Serwer administracyjny (ACOS):** utrzymuje inwentarz, dane uwierzytelniające, stan i politykę routingu.
2. **Węzeł dostępu/przekaźnikowy:** uwierzytelnia klientów lub operatorów; jest stabilnym punktem wejścia do zmieniającej się siatki.
3. **Węzły tranzytowe:** jeden lub więcej wynajętych albo zhakowanych systemów przekazuje niejawne połączenia.
4. **Węzeł wyjściowy/stagingowy:** przedstawia końcowy adres źródłowy celom rozpoznania, eksploatacji lub C2.

Siatka może wybierać węzły wyjściowe według kraju, ASN, opóźnienia lub dostępności oraz wymieniać węzły działające nieprawidłowo. Te same sieci mogą być wynajmowane przez wiele grup zagrożeń. Mandiant zaobserwował, że niektóre adresy IPv4 pozostawały powiązane z ORB zaledwie przez 31 dni; dlatego zaleca traktować **sieć jako zmieniający się podmiot przypominający aktora**, zamiast blokować nieaktualną listę adresów IP.<sup>[[2]](#references)</sup>

### Co to zapewnia — i co wycieka

- Cel widzi węzeł wyjściowy, który może znajdować się w pobliżu geograficznym i pozornie należeć do sieci domowej.
- Węzeł wyjściowy widzi cel i poprzedni przeskok, ale niekoniecznie operatora.
- Usługa dostępu widzi klienta i żądanie trasy. Niezależnie zarządzana siatka może oddzielać klienta od węzłów wyjściowych, ale tworzy cenne zapisy po stronie kontrahenta.
- Powtarzające się porty, kolejność uzgadniania połączenia, banery serwera, certyfikaty, okna dostępności i relacje z kontrolerami mogą ujawnić flotę nawet przy rotacji adresów IP.
- Zhakowanemu routerowi często brakuje telemetrii endpointu, ale jego ISP nadal ma dane abonenta i przepływów; przejęcie urządzenia ujawnia artefakty implantu/konfiguracji.

{% hint style="info" %}
W ramach autoryzowanego ćwiczenia odtwórz topologię na maszynach wirtualnych lub routerach należących do organizacji i zachowaj mapę atrybucji kontrolera. Nie wykorzystuj otwartych proxy ani urządzeń stron trzecich. [Przewodnik laboratoryjny](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) tworzy tę samą strukturę przeskoków widoczną dla obrońcy, nie narażając pośrednika.
{% endhint %}

## Sieci residential i mobile proxy

Usługi residential proxy przypisują sesje do adresów konsumenckich łączy szerokopasmowych; mobile proxy wychodzą przez pule NAT operatorów. Źródłem mogą być jawnie zarejestrowane urządzenia, SDK/proxyware dołączone do aplikacji konsumenckich, resellerzy lub malware. Te źródła nie są równoważne: brak świadomej zgody zmienia usługę ochrony prywatności w zhakowaną infrastrukturę.

Tryby rotacji wpływają na wykrywanie:

- **rotacja przy każdym żądaniu** powoduje szybkie zmiany IP oraz ASN/lokalizacji geograficznej, podczas gdy tożsamość w wyższych warstwach pozostaje stabilna;
- **sesje sticky** utrzymują węzeł wyjściowy przez minuty lub godziny, przypominając zwykłego abonenta;
- **bramy backconnect** udostępniają klientowi jeden punkt końcowy brokera, który wewnętrznie wybiera węzły wyjściowe;
- **pule mobile** umieszczają wielu rzeczywistych abonentów za niewielką liczbą adresów NAT operatora, przez co blokada IP jest kosztowna.

Obrońcy powinni korelować adres IP z uwierzytelnioną sesją, fingerprintem TLS/klienta, kolejnością HTTP, cookie urządzenia i zachowaniem. Logowanie z rzekomo lokalnej sieci residential, po którym następuje logowanie z innego kraju przy identycznych cechach wyższych warstw, jest mocniejszym dowodem niż sama reputacja. Z drugiej strony współdzielenie adresów i przełączanie się między stacjami komórkowymi powodują uzasadnione zmiany, dlatego nigdy nie należy traktować klasyfikacji residential/proxy jako werdyktu.

### Płaszczyzny sterowania proxyware i nakładanie się resellerów

Nie modeluj puli residential jako płaskiej listy węzłów wyjściowych. Analiza ekosystemu IPIDEA ujawniła możliwą do ponownego wykorzystania **dwupoziomową płaszczyznę sterowania**: osadzone SDK najpierw zgłasza metadane urządzenia/rejestracji do domeny Tier One i otrzymuje pary IP:port Tier Two `connect`/`proxy` wraz z informacjami o harmonogramie. Węzeł okresowo odpytuje port connect Tier Two o zakodowane zadanie, otwiera drugie połączenie z przypisanym portem proxy i przekazuje dostarczone bajty do żądanego celu. SDK i marki proxy, nominalnie różne, korzystały z osobnych domen wykrywania, ale zbiegały się we wspólnej infrastrukturze Tier Two i nakładających się pulach węzłów wyjściowych dzięki wspólnym właścicielom i relacjom resellerów.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Daje to trwalsze punkty zaczepienia do huntingu niż blok adresów IP rezydencyjnych:<sup>[[13]](#references)</sup>

- nieoczekiwany proces narzędzia użytkowego, VPN, gry lub urządzenia wbudowanego wysyła stabilny identyfikator urządzenia/klucza klienta i otrzymuje zmienną listę serwerów;
- endpoint odpytuje bezpośredni adres IP na nietypowym porcie, a następnie łączy się z innym portem pod tym samym adresem tuż przed otwarciem gniazda do nowego miejsca docelowego;
- kilka pozornie odrębnych marek korzysta z tych samych adresów Tier Two, gramatyki protokołu, kodu SDK lub nakładających się węzłów wyjściowych;
- różne aplikacje kontaktujące się z różnymi domenami Tier One otrzymują adresy z tej samej puli Tier Two.

To nakładanie się ogranicza również możliwości atrybucji: obecność adresu IP w reklamowanej puli jednego dostawcy nie dowodzi, który reseller, klient lub aktor zagrożeń używał go w danym czasie. Zachowaj znaczniki czasu przepływów, pochodzenie procesów, treści odpowiedzi Tier One i identyfikatory zadań Tier Two.<sup>[[13]](#references)</sup> W autoryzowanym ćwiczeniu emuluj tę hierarchię wyłącznie przy użyciu endpointów należących do organizacji; nigdy nie rejestruj urządzeń konsumenckich ani proxyware stron trzecich.

## Łańcuchy proxy multi-hop

MITRE odróżnia proxy zewnętrzne od **multi-hop proxies (T1090.003)**. Kluczową cechą nie jest liczba przeskoków, lecz rozdzielenie wiedzy i administracji.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Jeśli jedna strona obsługuje A i B, wspólne logi lub analiza czasu przepływu mogą pozwolić odtworzyć obwód. Dodanie kolejnych komercyjnych VPN-ów z tego samego endpointu/konta może zwiększyć opóźnienie, ale nie usuwa wspólnych danych o tożsamości, płatności i czasie. Tor ogranicza ten problem dzięki niezależnie wybieranym relayom i wspólnej konstrukcji klienta, ale sieć interaktywna o niskim opóźnieniu nie może zagwarantować odporności na obserwatora mierzącego oba końce.

Do częstych błędów należą obejście DNS lub IPv6, aplikacje otwierające własne sockety, ruch zarządzający docierający bezpośrednio do relayów, zsynchronizowana aktywność, ponowne użycie kluczy SSH i logowanie się na konta pozwalające ustalić tożsamość. Prawidłowa weryfikacja polega na teście awarii: zatrzymaj po kolei każdy relay i sprawdź, czy workload nie może przełączyć się na połączenie bez szyfrowania.

### Awaria tunelu i upstream leakage

Architektura relayów często najbardziej ułatwia przypisanie aktywności, gdy ulega awarii. Unit 42 opisało wielopoziomową ścieżkę szpiegowską wykorzystującą VPS-y skierowane do ofiar, VPS-y relay, residential proxy, Tor i inne usługi proxy; gdy pominięto tunel lub doszło do jego awarii, ukryta infrastruktura upstream łączyła się bezpośrednio z systemami relay i systemami skierowanymi do ofiar. W ramach tego samego śledztwa wykorzystano też certyfikat X.509, który przez krótki czas był ujawniony w infrastrukturze upstream, jako punkt odniesienia łączący różne poziomy.<sup>[[14]](#references)</sup>

Oddziel **data plane** (`victim <-> exit`) od **control plane** (`operator/upstream -> relay administration`). Zachowuj logi ruchu przychodzącego i uwierzytelniania na każdym posiadanym poziomie, historię certyfikatów oraz krótkie, nieudane połączenia — nie tylko udane sesje C2. Źródło, które pojawia się wyłącznie podczas awarii relayów lub bezpośrednio administruje wieloma węzłami skierowanymi do ofiar, jest bardziej prawdopodobnym kandydatem na upstream niż zwykły exit, ale jego ASN/geolokalizacja to nadal hipoteza, a nie dowód tożsamości operatora.

Autoryzowane laboratorium powinno skonfigurować workload tak, by działał zgodnie z zasadą fail closed. W przypadku workloadu odizolowanego w network namespace systemu Linux pierwsza trasa musi prowadzić przez tunel; po jego usunięciu zarówno żądanie, jak i wyszukiwanie trasy muszą zakończyć się niepowodzeniem, zamiast korzystać z fizycznego łącza:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Powtórz test dla DNS i IPv6 oraz na każdej granicy między przekaźnikami. Jeśli którakolwiek sonda zakończy się powodzeniem, zapisz rzeczywisty interfejs/adres źródłowy przed naprawieniem routingu opartego na zasadach lub firewalla; ta obserwacja to attribution leak, który zobaczyłby śledczy.

## Warstwy redirectorów i kształtowanie ruchu

Publiczny **redirector** akceptuje ruch zgodny z gramatyką specyficzną dla danej operacji i przekazuje go do chronionego serwera zespołu. Całą resztę można odrzucić lub odpowiedzieć na nią nieszkodliwą treścią.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Wiele warstw ogranicza ekspozycję: spalenie domeny publicznej nie musi ujawnić serwera zespołu. CDN-y zapewniają pojemność anycast i wiarygodną domenę zewnętrzną, ale konto CDN i logi edge stają się punktami umożliwiającymi atrybucję. Fingerprinty TLS, historia certyfikatów, charakterystyczne ścieżki/kolejność nagłówków, rozmiary odpowiedzi, zachowanie przekierowań i listy dozwolonych originów mogą łączyć pozornie niezwiązane fronty.

Na potrzeby detekcji zapisuj pola reverse proxy przed normalizacją, porównuj SNI/Host/authority, sprawdzaj rzadkie kombinacje nagłówków, grupuj treści odpowiedzi i fingerprinty TLS oraz przeszukuj logi audytowe chmury/CDN pod kątem nakładających się konfiguracji. W ramach autoryzowanych red teamów nie kopiuj prawdziwej marki ani nie umieszczaj mechanizmu zbierania poświadczeń za pośrednictwem niezwiązanego podmiotu trzeciego.

## Domain fronting i domainless fronting

W klasycznym **domain fronting (T1090.004)** połączenie TLS reklamuje dozwoloną domenę frontową w SNI, podczas gdy zaszyfrowany nagłówek HTTP `Host` lub `:authority` w HTTP/2 żąda innej domeny back-endu. Współpracujący CDN kieruje ruch na podstawie wartości wewnętrznej. Obserwator sieciowy bez deszyfrowania TLS widzi front; CDN widzi obie wartości i origin. W wariantach domainless SNI może być pusty, a miejsce docelowe wybiera inne pole routingu.<sup>[[4]](#references)</sup>

To nie jest magiczne podszywanie się pod kogoś: działa tylko wtedy, gdy pośrednik celowo lub przypadkowo dopuszcza tę niezgodność i wie, jak kierować ruch na podstawie wewnętrznej nazwy. Główni dostawcy ograniczyli fronting między kontami. Encrypted ClientHello (ECH) zmienia to, co może zobaczyć obserwator na trasie, ale nie usuwa zapisów CDN, endpointu ani aplikacji.

Punkty detekcji obejmują:

- pochodzenie procesu na endpoincie i miejsce docelowe nieoczekiwane dla tej aplikacji;
- niezgodność SNI i HTTP authority, gdy inspekcja TLS jest zgodna z prawem i dostępna;
- logi CDN wskazujące, że jeden tenant/front kieruje ruch do innego authority/originu;
- nietypowe, długo utrzymywane lub okresowe sesje do usługi, która zwykle jest używana interaktywnie;
- stabilne rozmiary i rytm zaszyfrowanych przepływów mimo zmieniających się domen frontowych.

Bezpieczne laboratorium symuluje niezgodność routingu na własnym reverse proxy; nie nadużywa publicznego CDN-a.

## Dynamiczne rozwiązywanie nazw: DDNS, DGA i fast flux

Dynamiczne rozwiązywanie nazw oddziela logiczną usługę od stałej infrastruktury:

- **DDNS:** uwierzytelniony klient aktualizuje stabilną nazwę po zmianie adresu.
- **DGA:** endpoint i kontroler wyznaczają potencjalne nazwy domen na podstawie ziarna czasu/klucza; operator rejestruje niewielką ich część.
- **Fast flux:** nazwa zwraca szybko zmieniający się zestaw przejętych adresów/proxy, często z niskimi wartościami TTL.
- **Double flux:** rotują zarówno adresy usług, jak i adresy autorytatywnych serwerów nazw, co ukrywa również warstwę sterowania.

Fast flux to wzorzec dystrybucji obciążenia wykorzystywany przez przeciwników, a nie po prostu „wiele odpowiedzi DNS”. Mocniejsze dowody łączą niski TTL, dużą liczbę unikalnych adresów, szerokie rozproszenie ASN/geograficzne, krótki czas życia węzłów, powtarzalne zachowanie aplikacji i podejrzaną historię rejestracji. CDN-y legalnie wykazują kilka z tych cech. MITRE zaleca korelowanie zachowania DNS z procesem i późniejszymi połączeniami.<sup>[[5]](#references)</sup>

DGA można wykrywać na podstawie entropii leksykalnej, wzorców spółgłosek/cyfr, serii NXDOMAIN, zsynchronizowanych domen widzianych po raz pierwszy oraz kontekstu procesu. DGA oparte na listach słów i modele generatywne omijają proste reguły entropii, przez co ważniejsze stają się klastrowanie czasowe w całej flocie i powiązania z endpointami.

## Przejęte domeny i domain shadowing

Podmiot może przejąć konto rejestratora/DNS, przejąć osieroconą subdomenę lub dodać rekordy w obrębie skądinąd wiarygodnej domeny. **Domain shadowing** zachowuje legalną domenę apex, a jednocześnie pozwala kierować dużą liczbę subdomen kontrolowanych przez atakującego do zmieniających się hostów dostarczających payload lub obsługujących C2. Wykorzystuje wiek i reputację domeny i może omijać blokowanie obejmujące całą domenę.<sup>[[6]](#references)</sup>

Obrońcy potrzebują logów audytowych rejestratora i autorytatywnego DNS, MFA, blokad rejestru/rejestratora, alertów o nowych delegacjach/tokenach API/serwerach nazw, monitorowania Certificate Transparency oraz inwentaryzacji zasobów chmurowych wskazanych przez DNS. Historię rozwiązywania nazw i certyfikatów subdomeny sprawdzaj niezależnie od reputacji domeny apex.

## Usługi webowe i dead-drop resolvers

**Dead-drop resolver (T1102.001)** przechowuje zakodowany wskaźnik do aktualnego C2 w legalnym poście, profilu, dokumencie, repozytorium, obiekcie chmurowym lub polu blockchaina. Malware pobiera publiczny obiekt, dekoduje domenę/IP i łączy się z kolejnym etapem. Warianty dwukierunkowe wymieniają polecenia lub pliki za pośrednictwem API usług.<sup>[[7]](#references)</sup>

Jeden wariant resolvera specyficzny dla GitHub korzysta z Issues Search API wyłącznie wtedy, gdy uwierzytelniony kanał repozytorium zawiedzie. Klient wyszukuje issues pasujące do bieżącej daty, repozytorium i typu issue, przechodzi do adresu URL komentarzy każdego issue i wyodrębnia szyfrogram znajdujący się między znacznikami `<!--` i `-->`. Po deszyfrowaniu zależnym od hosta i daty pola takie jak `Owner`, `LicRepo` i `LicToken` zastępują głównego właściciela repozytorium, ścieżkę i token. Pozwala to operatorowi rotować poświadczenia i endpointy bez wymiany klienta; komentarz issue pełni rolę resolvera, a pliki repozytorium pozostają kanałem taskingu.<sup>[[15]](#references)</sup>

Zapewnia to odporność i ukrywa back-end C2 przed statyczną analizą binarną. Tworzy też stabilne identyfikatory obiektów, tenantów, repozytoriów, API i wzorców dostępu. Obrońcy powinni łączyć:

1. proces, który nawiązał połączenie z usługą;
2. dokładną ścieżkę API/obiekt i hash odpowiedzi;
3. aktywność dekodowania lub przetwarzania ciągów znaków;
4. nowe połączenie wychodzące krótko potem; oraz
5. identyczne zachowanie w innych miejscach floty.

Blokowanie całego GitHub, cloud storage lub social media rzadko jest wykonalne. Polityka egress uwzględniająca usługi i korelacja na poziomie procesu są skuteczniejsze niż blokowanie wyłącznie domen.

## Persony, konta i przedziały zakupowe

Anonimowość infrastruktury zawodzi, gdy persona, adres e-mail do odzyskiwania konta, telefon, płatność, przeglądarka lub IP administratora łączy różne przedziały. Operacje powiązane z państwami od dawna przed użyciem tworzą profile społecznościowe, tożsamości e-mail i konta chmurowe; ATT&CK odnotowuje to jako Establish Accounts (T1585), w tym podtechniki dotyczące mediów społecznościowych, poczty e-mail i chmury.<sup>[[8]](#references)</sup>

Obrońca lub śledczy buduje graf na podstawie:

- czasu utworzenia i pierwszego logowania, ustawień regionalnych, strefy czasowej i harmonogramu pracy;
- pól odzyskiwania konta, urządzeń MFA, dokumentów tożsamości i instrumentów płatniczych;
- fingerprintów przeglądarki/TLS i historii sieci źródłowej;
- ponownego użycia awatarów, pochodzenia obrazów, stylu pisania i rozwoju grafu społecznościowego;
- wspólnego rejestrującego domenę, serwera nazw, certyfikatu, identyfikatora analytics lub commitu repozytorium;
- działań w płaszczyźnie zarządzania omijających architekturę publicznych przekaźników.

W autoryzowanym red teamie syntetyczne persony należy udokumentować u kontrolera ćwiczenia, korzystać z kanałów odzyskiwania kont i płatności należących do organizacji, unikać podszywania się pod prawdziwe, niezwiązane z ćwiczeniem osoby i zaplanować wycofanie person. SOC może pozostać nieświadomy; operacja nie może jednak stać się pozbawiona odpowiedzialności.

## Nowe złożone wzorce do modelowania zagrożeń

Poniższe przykłady to **kompozycje tworzone z perspektywy obrońcy**, a nie twierdzenia, że konkretny nazwany podmiot wdrożył każdy z tych dokładnych projektów. Łączą już zaobserwowane prymitywy i mogą służyć jako hipotezy do ćwiczeń purple-team.

### Asymetryczny, jednokierunkowy tasking

Polecenia docierają przez publiczne, rozgłoszeniowe lub append-only źródło, a wyniki są wysyłane z opóźnieniem innym kanałem. Przykłady prymitywów obejmują jednokierunkową komunikację przez web service i dead dropy. Rozdzielenie kanałów sprawia, że pojedynczy przepływ nie wygląda na dwukierunkowy i utrudnia prostą korelację żądanie/odpowiedź.<sup>[[9]](#references)</sup>

**Detekcja:** zachowuj zapisy odczytów obiektów, a następnie koreluj zmiany stanu procesu i późniejsze transfery wychodzące w szerszym oknie czasowym. Szukaj rzadkiego procesu odczytującego ten sam publiczny obiekt, nawet jeśli nie następuje natychmiastowa odpowiedź.

### Awans do kanału wieloetapowego

Cichy pierwszy etap przeprowadza inwentaryzację i przenosi wybrane systemy do niezwiązanego kanału drugiego etapu. Drugi endpoint, protokół i proces mogą nie mieć wspólnej infrastruktury z pierwszym etapem. Ogranicza to ekspozycję zaawansowanej infrastruktury i jest jawnie ujęte w ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detekcja:** łącz `pierwszy proces sieciowy -> pobrany/skonfigurowany stan -> nowy proces lub injection -> niezwiązane miejsce docelowe`; nie zamykaj incydentu po zablokowaniu pierwszej domeny.

### Tłumaczenie przekaźników między protokołami

Różne przeskoki tłumaczą HTTPS, QUIC, WebSocket, DNS, SSH lub API kolejki wiadomości, zamiast transparentnie przekazywać pakiety. Tłumaczenie eliminuje pojedynczy fingerprint protokołu end-to-end, ale tworzy bramy o charakterystycznym taktowaniu, buforowaniu i konwersji semantycznej. Protocol tunneling (T1572) można łączyć z proxy i podszywaniem się pod usługi.<sup>[[11]](#references)</sup>

**Detekcja:** szukaj hostów-bram, które odbierają jeden protokół i inicjują inny, wykazując ściśle powiązane zachowanie pod względem bajtów/czasu; porównuj zamierzone działanie endpointu z faktycznie przenoszonym protokołem.

### Pasywna aktywacja na urządzeniach brzegowych

Zamiast wysyłać beacon, implant monitoruje ruch docierający już do routera/VPN i aktywuje się wyłącznie po otrzymaniu magicznej wartości, wzorca portu źródłowego lub uwierzytelnionego tokena. Zwykły ruch nadal trafia do prawdziwej usługi. ATT&CK nazywa to Traffic Signaling (T1205) i opisuje udokumentowane przykłady dotyczące urządzeń sieciowych oraz APT.<sup>[[12]](#references)</sup>

**Detekcja:** integralność firmware/plików, przechwytywanie surowych pakietów podczas autoryzowanego huntowania, nieoczekiwane filtry gniazd i różnice w zachowaniu usługi. Brak okresowego beaconu nie dowodzi, że urządzenie brzegowe jest czyste.

### Serverless i rotacja efemerycznych originów

Front zachowuje stabilną tożsamość logiczną, a krótkotrwałe funkcje/kontenery obsługują poszczególne etapy w kilku regionach/kontach. Ogranicza to czas życia danych na dysku i obecność stałych adresów IP originów, ale telemetria dotycząca tworzenia w płaszczyźnie sterowania, obrazu/warstwy, roli, sekretu, identyfikatora żądania i rozliczeń staje się trwałym grafem.

**Detekcja:** przechowuj logi audytowe chmury i wywołań poza obciążeniem; grupuj szablony wdrożeń, role, klucze środowiskowe i relacje front-origin.

### Różnorodność warstw prywatności

Operacja może celowo unikać jednorodnego łańcucha: przykładowo jeden kanał korzysta z dzierżawionego przekaźnika, tasking z publicznego obiektu, wyjście z należącego do organizacji laboratoryjnego łącza komórkowego, a administracja z oddzielnej sieci organizacji. Ogranicza to wartość przejęcia jednego dostawcy, ale zwiększa ryzyko korelacji czasowej między warstwami i błędów operacyjnych.

**Detekcja:** twórz osie czasu kampanii na podstawie sensorów tożsamości, DNS, SaaS, sieci i chmury. Szukaj zsynchronizowanych zmian stanu, a nie identycznych wskaźników.

### Zdecentralizowane dead dropy lub dead dropy w logach transparentności

Podmiot może umieścić niewielki zaszyfrowany wskaźnik w dowolnym trwałym, publicznym systemie append-only, magazynie adresowanym zawartością lub strumieniu podobnym do logu transparentności. Publiczny obiekt jest odporny, ale jego dokładny indeks/hash zawartości i zachowanie klienta odpytującego ten obiekt stają się stabilnymi identyfikatorami.

**Detekcja:** zapisuj pełne identyfikatory API/obiektów i hashe odpowiedzi; generuj alerty, gdy niestandardowe procesy odpytują niezmienne obiekty, a następnie wykonują dekodowanie lub nawiązują nowe połączenia.

### Operacje z opóźnionym przekazywaniem danych

Interaktywny C2 tworzy silną korelację czasową. Projekt store-and-forward grupuje zaszyfrowane zadania i zwraca wyniki po minutach lub godzinach przez inną kolejkę lub transfer fizyczny. W zamian za słabszą korelację czasową end-to-end ogranicza responsywność.

**Detekcja:** wydłużaj okna korelacji, modeluj okresowy dostęp do kolejek i analizuj staging na endpointach. Grupowanie przesuwa sygnał z taktowania pakietów na zaplanowane zachowanie procesów/plików; nie usuwa go.

## Przegląd projektu: myśl kategoriami obserwatorów

Dla każdej ścieżki wypełnij tę tabelę przed wdrożeniem i po zebraniu danych:

| Warstwa | Widzi źródło? | Widzi miejsce docelowe? | Widzi treść? | Stabilne identyfikatory | Retencja/właściciel prawny |
|---|---:|---:|---:|---|---|
| sieć lokalna/operator | | | | | |
| usługa wejściowa/dostępowa | | | | | |
| operatorzy tranzytowi | | | | | |
| wyjście/redirector/CDN | | | | | |
| autorytatywny DNS/rejestrator | | | | | |
| cel | | | | | |
| dostawca konta/płatności | | | | | |

Jeśli jeden zwykły dostawca może wypełnić każdą kolumnę, architektura zapewnia ukrycie przed celem, ale nie solidne rozdzielenie. Jeśli żaden wewnętrzny kontroler nie może powiązać aktywności z ćwiczeniem, architektura nie nadaje się do profesjonalnego red teamingu.

## References

- [1] [MITRE ATT&CK — Pozyskiwanie infrastruktury (T1583), kompromitowanie infrastruktury (T1584) i Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Chińscy aktorzy szpiegowscy wykorzystują sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Kompromitowanie infrastruktury: domeny (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Zakładanie kont (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: komunikacja jednokierunkowa (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Kanały wieloetapowe (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Tunelowanie protokołów (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Sygnalizowanie ruchu (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Zakłócenie działania największej na świecie sieci proxy rezydenckich](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Kampanie Shadow: odkrywanie globalnego szpiegostwa](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Kampania Blinder Tunnel wymierzona w iracką infrastrukturę](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
