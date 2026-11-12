# Infrastruktura ofensywna i unikanie atrybucji

{{#include ../banners/hacktricks-training.md}}

Operator rzadko uzyskuje znaczącą anonimowość, korzystając z pojedynczego proxy. Prawdziwe kampanie tworzą **graf separacji**: operator łączy się z węzłem dostępowym, węzły tranzytowe ukrywają go przed węzłem wyjściowym, redirectory chronią rzeczywisty C2, a jednorazowe domeny wskazują na publiczny węzeł brzegowy.

Skorzystaj z [katalogu technik anonimowego dostępu do Internetu](anonymous-internet-access-techniques.md), aby zapoznać się ze znormalizowanym zestawieniem zalet, wad, wdrożenia i wykrywania każdej ścieżki. Ta strona dokładniej omawia komponowanie infrastruktury w warunkach działań przeciwnika.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Ostatni adres widziany przez cel jest więc dowodem na istnienie ścieżki, a nie dowodem na to, kto kontrolował klawiaturę. MITRE przypisuje główne elementy do Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klasy infrastruktury

| Klasa | Dlaczego aktor z niej korzysta | Trwały ślad | Najlepszy pivot dla obrońcy |
|---|---|---|---|
| Wynajęty VPS/cloud | Szybki, przewidywalny, routowalny, łatwy do odtworzenia | najemca, rozliczenia, konsola, historia logowań źródłowych i obrazów | zdarzenia na koncie/płaszczyźnie sterowania oraz powtarzający się fingerprint serwera |
| Komercyjny VPN/Tor | Duża współdzielona pula adresów wyjściowych; brak konieczności administrowania serwerem | widoczność dostawcy/nadzoru i korelacja czasu od końca do końca | zachowanie wobec celu, ślady na endpointach i korelacja przepływów |
| Residential/mobile proxy | ASN konsumencki i wiarygodność geograficzna | dane brokera/klienta; zachowanie proxyware lub zainfekowanego hosta | niemożliwa podróż, protokoły proxy i zmienność adresów w ramach sesji |
| Skompromitowany serwer/router/IoT | Wykorzystuje reputację i jurysdykcję ofiary | implant, przepływ zarządzający i powtarzający się upstreamowy kontroler | telemetria urządzenia i topologia ORB, a nie pojedynczy adres wyjściowy |
| CDN/redirector | Oddziela publiczny edge od back-endowego C2 | gramatyka TLS/HTTP, certyfikat, routing i artefakty konta cloud | korelacja edge-origin i klasteryzacja kształtu żądań |
| Legalna usługa webowa | Wtapia się w dozwolony ruch GitHub/cloud/social | token API, identyfikatory najemcy/obiektu i nietypowe pochodzenie procesu | proces na endpoincie oraz semantyka usługi/API |
| Ścieżka fizyczna/komórkowa/satelitarna | Zmienia pozorne fizyczne źródło | dane RF, operatora, abonenta, urządzenia i lokalizacji | połączone dowody radiowe/fizyczne i sieciowe |

## Sieci operacyjnych węzłów przekaźnikowych

**Sieć ORB** to zarządzana pula proxy używana jako usługa pośrednicząca. Mandiant dzieli je na sieci provisioned z wynajętych serwerów, sieci non-provisioned ze skompromitowanych routerów/IoT oraz hybrydy. Dojrzała topologia ma cztery logiczne role:<sup>[[2]](#references)</sup>

1. **Serwer administracyjny (ACOS):** utrzymuje inwentarz, dane uwierzytelniające, stan i politykę routingu.
2. **Węzeł dostępu/przekaźnikowy:** uwierzytelnia klientów lub operatorów; stanowi stabilny punkt wejścia do zmieniającej się siatki.
3. **Węzły tranzytowe:** jeden lub więcej wynajętych albo skompromitowanych systemów przekazuje niejawne połączenia.
4. **Węzeł wyjściowy/stagingowy:** prezentuje końcowy adres źródłowy podczas rozpoznania, exploitation lub komunikacji C2 z celami.

Siatka może wybierać węzły wyjściowe według kraju, ASN, opóźnienia lub dostępności oraz wymieniać węzły, które przestały działać prawidłowo. Z tej samej sieci może wynajmować zasoby wiele grup zagrożeń. Mandiant zaobserwował, że adres IPv4 pozostawał powiązany z niektórymi ORB zaledwie przez 31 dni; dlatego zaleca traktować **sieć jako ewoluujący byt przypominający aktora**, zamiast blokować nieaktualną listę adresów IP.<sup>[[2]](#references)</sup>

### Co to daje — i co ujawnia

- Cel widzi węzeł wyjściowy, który może znajdować się geograficznie blisko i sprawiać wrażenie łącza domowego.
- Węzeł wyjściowy widzi cel i poprzedni skok, ale niekoniecznie operatora.
- Usługa dostępu widzi klienta i żądanie trasy. Niezależnie zarządzana siatka może oddzielać klienta od węzłów wyjściowych, ale tworzy cenne dane u strony trzeciej.
- Powtarzające się porty, kolejność uzgadniania połączenia, banery serwera, certyfikaty, okresy dostępności i powiązania z kontrolerami mogą ujawnić pulę węzłów, nawet gdy adresy IP się zmieniają.
- Skompromitowany router często nie ma telemetrii endpointa, ale jego ISP nadal dysponuje danymi abonenta i przepływów; przejęcie urządzenia ujawnia artefakty implantu/konfiguracji.

{% hint style="info" %}
W ramach autoryzowanego ćwiczenia odtwórz topologię przy użyciu maszyn wirtualnych lub routerów należących do organizacji i zachowaj mapę atrybucji kontrolera. Nie wykorzystuj otwartych proxy ani urządzeń stron trzecich. [Przewodnik po laboratorium](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) tworzy taką samą strukturę przeskoków widoczną dla obrońcy, nie krzywdząc pośrednika.
{% endhint %}

## Residential i mobile proxy

Usługi residential proxy przypisują sesje do adresów łączy konsumenckich; mobile proxy korzystają z pul NAT operatorów komórkowych. Źródłem mogą być urządzenia zapisane do usługi za wyraźną zgodą, SDK/proxyware dołączone do aplikacji konsumenckich, resellerzy lub malware. Te źródła nie są równoważne: brak świadomej zgody zmienia usługę ochrony prywatności w skompromitowaną infrastrukturę.

Tryby rotacji wpływają na wykrywanie:

- **rotacja przy każdym żądaniu** powoduje szybką zmienność IP oraz ASN/lokalizacji, podczas gdy tożsamość na wyższych warstwach pozostaje stabilna;
- **sesje sticky** utrzymują węzeł wyjściowy przez kilka minut lub godzin, przypominając zwykłego abonenta;
- **bramy backconnect** udostępniają klientowi jeden endpoint brokera, który sam wybiera węzły wyjściowe;
- **pule mobile** umieszczają wielu rzeczywistych abonentów za niewielką liczbą adresów NAT operatora, przez co blokowanie IP może być kosztowne.

Obrońcy powinni korelować IP z uwierzytelnioną sesją, fingerprintem TLS/klienta, kolejnością HTTP, cookie urządzenia i zachowaniem. Rzekome logowanie lokalne przez residential proxy, po którym następuje logowanie z innego kraju przy niezmienionych cechach wyższych warstw, stanowi mocniejszy sygnał niż sama reputacja. Z drugiej strony współdzielenie adresów i przełączanie między stacjami komórkowymi powodują uzasadnioną zmienność, więc nigdy nie traktuj klasyfikacji residential/proxy jako rozstrzygającego dowodu.

### Płaszczyzny sterowania proxyware i nakładanie się resellerów

Nie modeluj puli residential jako płaskiej listy węzłów wyjściowych. Analiza ekosystemu IPIDEA ujawniła możliwą do ponownego wykorzystania **dwupoziomową płaszczyznę sterowania**: wbudowane SDK najpierw zgłasza metadane urządzenia/rejestracji do domeny Tier One, a następnie otrzymuje pary IP:port `connect`/`proxy` z Tier Two wraz z informacjami o planowaniu. Węzeł okresowo odpytuje port connect Tier Two o zakodowane zadanie, otwiera drugie połączenie z odpowiadającym mu portem proxy i przekazuje dostarczone bajty do żądanego celu. SDK i marki proxy, które formalnie wyglądały na niezależne, miały osobne domeny wyszukiwania, ale zbiegały się na wspólnej infrastrukturze Tier Two i nakładających się pulach węzłów wyjściowych z powodu wspólnego właściciela i relacji resellerów.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Daje to trwalsze punkty zaczepienia do huntingu niż blok adresów IP z puli residential:<sup>[[13]](#references)</sup>

- nieoczekiwany proces narzędzia użytkowego, VPN, gry lub urządzenia wbudowanego wysyła stabilny identyfikator urządzenia/klucz klienta i otrzymuje zmienną listę serwerów;
- endpoint odpytuje bezpośredni adres IP na nietypowym porcie, a następnie łączy się z innym portem pod tym samym adresem tuż przed otwarciem socketu do nowego celu;
- kilka pozornie odrębnych marek korzysta z tych samych adresów Tier Two, gramatyki protokołu, kodu SDK lub nakładających się węzłów wyjściowych;
- różne aplikacje łączące się z różnymi domenami Tier One otrzymują adresy z tej samej puli Tier Two.

To nakładanie się ogranicza również możliwości atrybucji: wykrycie adresu IP w reklamowanej puli jednego dostawcy nie dowodzi, który reseller, klient ani aktor stanowiący zagrożenie używał go w danym czasie. Zachowaj znaczniki czasu przepływów, pochodzenie procesów, treść odpowiedzi Tier One i identyfikatory zadań Tier Two.<sup>[[13]](#references)</sup> W ramach autoryzowanego ćwiczenia emuluj tę hierarchię wyłącznie na endpointach należących do organizacji; nigdy nie rejestruj urządzeń konsumenckich ani proxyware stron trzecich.

## Łańcuchy proxy multi-hop

MITRE rozróżnia zewnętrzne proxy od **multi-hop proxies (T1090.003)**. Istotną cechą nie jest liczba hopów, lecz rozdzielenie wiedzy i administracji.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Jeśli jedna strona obsługuje A i B, współdzielone logi lub synchronizacja przepływów mogą pozwolić odtworzyć obwód. Dodanie kolejnych komercyjnych VPN-ów z tego samego endpointu/konta może zwiększyć opóźnienie, ale nie eliminuje wspólnych śladów tożsamości, płatności i synchronizacji. Tor ogranicza ten problem dzięki niezależnie wybieranym relayom i wspólnej konstrukcji klienta, ale sieć interaktywna o niskim opóźnieniu nie może zagwarantować odporności na obserwatora mierzącego oba końce.

Do częstych błędów należą obejście przez DNS lub IPv6, aplikacje otwierające własne sockety, ruch zarządzający docierający bezpośrednio do relayów, zsynchronizowana aktywność, ponownie używane klucze SSH i logowanie do kont ujawniających tożsamość. Weryfikację należy przeprowadzić testem awarii: zatrzymać kolejno każdy relay i wykazać, że workload nie może przejść na bezpośrednią, niezaszyfrowaną trasę.

### Awaria tunelu i wyciek do infrastruktury upstream

Architektura relayów często najbardziej ułatwia przypisanie aktywności do źródła, gdy ulega awarii. Unit 42 udokumentowało wielowarstwową ścieżkę szpiegowską wykorzystującą VPS-y widoczne dla ofiar, VPS-y relay, residential proxies, Tor i inne usługi proxy; gdy pominięto tunel lub doszło do jego awarii, ukryta infrastruktura upstream łączyła się bezpośrednio z systemami relay i widocznymi dla ofiar. W ramach tego samego dochodzenia wykorzystano też krótko ujawniony na infrastrukturze upstream certyfikat X.509 jako punkt wyjścia do powiązania kolejnych warstw.<sup>[[14]](#references)</sup>

Oddziel **data plane** (`victim <-> exit`) od **control plane** (`operator/upstream -> relay administration`). Zachowuj logi połączeń przychodzących i uwierzytelniania z każdej kontrolowanej warstwy, historię certyfikatów oraz krótkie, nieudane połączenia — nie tylko udane sesje C2. Źródło widoczne wyłącznie podczas awarii relayów lub bezpośrednio administrujące wieloma węzłami widocznymi dla ofiar jest lepszym kandydatem na infrastrukturę upstream niż zwykły exit, ale jego ASN/geolokalizacja to nadal hipoteza, a nie dowód tożsamości operatora.

W autoryzowanym labie workload powinien działać w trybie fail-closed. W przypadku workloadu odizolowanego w network namespace systemu Linux pierwsza trasa musi prowadzić przez tunel; po jego usunięciu zarówno żądanie, jak i wyszukiwanie trasy powinny zakończyć się niepowodzeniem, zamiast wybrać fizyczne łącze uplink:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Powtórz test dla DNS i IPv6 oraz na każdej granicy przekaźnika. Jeśli jakakolwiek sonda zakończy się powodzeniem, zanotuj rzeczywisty interfejs/adres źródłowy przed naprawieniem routingu opartego na zasadach lub firewalla; ta obserwacja to attribution leak, który zobaczyłby śledczy.

## Warstwy redirectorów i kształtowanie ruchu

Publiczny **redirector** akceptuje ruch zgodny z gramatyką specyficzną dla operacji i przekazuje go do chronionego team servera. Całą pozostałą komunikację można odrzucić lub obsłużyć, zwracając nieszkodliwą treść.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Wiele warstw ogranicza ekspozycję: spalenie domeny publicznej nie musi ujawnić serwera zespołu. CDN-y zapewniają przepustowość anycast i wiarygodną domenę zewnętrzną, ale konto CDN i logi edge stają się punktami atrybucji. Fingerprinty TLS, historia certyfikatów, charakterystyczne ścieżki/kolejność nagłówków, rozmiary odpowiedzi, zachowanie przekierowań i listy dozwolonych originów mogą pozwolić grupować fronty uznawane za niepowiązane.

Na potrzeby wykrywania zapisuj pola reverse proxy przed normalizacją, porównuj SNI/Host/authority, sprawdzaj rzadkie kombinacje nagłówków, grupuj treści odpowiedzi i fingerprinty TLS oraz szukaj nakładających się konfiguracji w logach audytowych chmury/CDN. Podczas autoryzowanych red teamów nie kopiuj prawdziwej marki ani nie umieszczaj zbierania poświadczeń za pośrednictwem niepowiązanej strony trzeciej.

## Domain fronting i domainless fronting

W klasycznym **domain fronting (T1090.004)** połączenie TLS zawiera w SNI dozwoloną domenę frontową, podczas gdy zaszyfrowane żądanie HTTP `Host` lub HTTP/2 `:authority` wskazuje inną domenę back-endu. Współpracujący CDN przekierowuje ruch na podstawie wewnętrznej wartości. Obserwator sieci bez deszyfrowania TLS widzi front; CDN widzi obie wartości i origin. W wariantach domainless SNI może być pusty, a miejsce docelowe może wskazywać inne pole routingu.<sup>[[4]](#references)</sup>

To nie jest magiczne podszywanie się: działa tylko wtedy, gdy pośrednik celowo lub przypadkowo dopuszcza taką rozbieżność i wie, jak routować na podstawie wewnętrznej nazwy. Główni dostawcy ograniczyli fronting między kontami. Encrypted ClientHello (ECH) zmienia to, co może zobaczyć obserwator znajdujący się na ścieżce, ale nie usuwa zapisów CDN, endpointu ani aplikacji.

Punkty wykrywania obejmują:

- proces nadrzędny procesu na endpoincie i miejsce docelowe nieoczekiwane dla tej aplikacji;
- rozbieżność między SNI a HTTP authority, jeśli inspekcja TLS jest zgodna z prawem i dostępna;
- logi CDN pokazujące, że jeden tenant/front routuje ruch do innego authority/origin;
- nietypowe, długotrwałe lub okresowe sesje z usługą, która zwykle działa interaktywnie;
- stabilne rozmiary i częstotliwość zaszyfrowanych przepływów przy zmieniających się domenach frontowych.

Bezpieczne laboratorium symuluje rozbieżność routingu na własnym reverse proxy; nie wykorzystuje publicznego CDN bez zgody.

## Dynamiczne rozwiązywanie nazw: DDNS, DGA i fast flux

Dynamiczne rozwiązywanie nazw oddziela usługę logiczną od stałej infrastruktury:

- **DDNS:** uwierzytelniony klient aktualizuje stabilną nazwę po zmianie adresu.
- **DGA:** endpoint wyprowadza nazwy domen z ziarna, często czasu lub klucza, ale czasem także zmiennej treści publicznej; operator konfiguruje DNS dla aktywnej nazwy.<sup>[[17]](#references)</sup>
- **Fast flux:** nazwa zwraca szybko zmieniający się zestaw przejętych adresów/proxy, często z niskimi wartościami TTL.
- **Double flux:** rotują zarówno adresy usług, jak i adresy autorytatywnych serwerów nazw, co ukrywa również warstwę kontrolną.

Fast flux to wzorzec dystrybucji obciążenia wykorzystywany w działaniach adwersarialnych, a nie po prostu „wiele odpowiedzi DNS”. Mocniejsze dowody łączą niski TTL, dużą liczbę unikalnych adresów, szerokie rozproszenie ASN/geograficzne, krótki czas życia węzłów, powtarzające się zachowanie aplikacji i podejrzaną historię rejestracji. CDN-y legalnie wykazują kilka z tych cech. MITRE zaleca korelowanie zachowania DNS z procesem i późniejszymi połączeniami.<sup>[[5]](#references)</sup>

DGA można wykrywać na podstawie entropii leksykalnej, wzorców spółgłosek/cyfr, serii odpowiedzi NXDOMAIN, zsynchronizowanych domen wykrytych po raz pierwszy i kontekstu procesu. DGA oparte na listach słów i modele generatywne omijają proste reguły entropii, przez co ważniejsze stają się klastrowanie czasowe w całej flocie i pochodzenie procesu na endpoincie.

### Zmienne ziarno obrazu dla DGA opartego na liście słów

DGA nie musi zależeć od czasu. Jeden loader pobiera stronę publicznego kanału Telegrama, odczytuje `src` elementu `tgme_page_photo_image`, pobiera zdjęcie profilowe i oblicza hash **ostatnich 50 bajtów pliku**, a nie zdekodowanych pikseli. Cztery ziarna hasha wybierają przymiotnik, rzeczownik, czasownik i liczbę. Zmiana obrazu zmienia wyprowadzoną nazwę DNS bez konieczności dostarczania nowego klienta. Po obu stronach zachowaj dokładnie te same pobrane bajty obrazu i tę samą kolejność słów na listach; ponowne zakodowanie obrazu lub zmiana kolejności na liście spowoduje wygenerowanie innych nazw.<sup>[[17]](#references)</sup>

Mając odzyskane z klienta listy słów, można odtworzyć etap wyboru nazwy. Hash źródła liczony bajt po bajcie używa 64-bitowego akumulatora, mnożnika `0x1000193` i osobnych ziaren dla każdego składnika:<sup>[[17]](#references)</sup>

<details>
<summary>Odtwórz wybór nazwy z listy słów z ziarnem opartym na obrazie</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

W przeciwieństwie do [dead-drop resolver](#web-services-and-dead-drop-resolvers), który publikuje sam endpoint, publiczny obiekt dostarcza tu jedynie zmienny seed; klient lokalnie wyznacza endpoint.

Następnie pod wygenerowaną nazwą wyszukiwany jest rekord DNS TXT pod adresem `https://dns.google/resolve?name=<domain>&type=TXT`. Klient dekoduje z Base64 pole `data` odpowiedzi JSON, weryfikuje podpis Ed25519 za pomocą osadzonego klucza publicznego i dopiero wtedy odszyfrowuje polecenie za pomocą AES-ECB. Zaobserwowany tekst jawny zaczyna się od selektora metody i URL zaszyfrowanego payloadu. Weryfikacja podpisu oznacza, że sam rozwiązywalny rekord TXT nie wystarczy, by dostarczyć zaakceptowane zadania.<sup>[[17]](#references)</sup>

## Przejęte domeny i domain shadowing

Aktor może przejąć konto u rejestratora lub w DNS, przejąć porzuconą subdomenę albo dodać rekordy w obrębie domeny cieszącej się dobrą reputacją. **Domain shadowing** pozwala zachować legalną domenę główną, podczas gdy duża liczba subdomen kontrolowanych przez atakującego wskazuje na zmieniające się hosty dostarczające payload lub C2. Wykorzystuje wiek i reputację domeny, co może pomóc uniknąć blokowania całej domeny.<sup>[[6]](#references)</sup>

Obrońcy potrzebują logów audytowych rejestratora i autorytatywnego DNS, MFA, blokad rejestru/rejestratora, alertów dotyczących nowych delegacji, tokenów API i serwerów nazw, monitorowania Certificate Transparency oraz wykazu zasobów chmurowych wskazywanych przez DNS. Historię rozwiązywania subdomeny i jej certyfikatów należy badać niezależnie od reputacji domeny głównej.

## Usługi webowe i dead-drop resolvers

**Dead-drop resolver (T1102.001)** przechowuje zakodowany wskaźnik do bieżącego C2 w legalnym poście, profilu, dokumencie, repozytorium, obiekcie chmurowym lub polu blockchain. Malware pobiera publiczny obiekt, dekoduje domenę/IP i łączy się z kolejnym etapem. Warianty dwukierunkowe wymieniają polecenia lub pliki za pośrednictwem API usług.<sup>[[7]](#references)</sup>

Jeden wariant resolvera specyficzny dla GitHub korzysta z Issues Search API tylko wtedy, gdy uwierzytelniony kanał repozytorium zawiedzie. Klient wyszukuje zgłoszenia pasujące do bieżącej daty, repozytorium i typu zgłoszenia, przechodzi do adresu URL komentarzy każdego zgłoszenia i wyodrębnia szyfrogram między znacznikami `<!--` i `-->`. Po odszyfrowaniu zależnym od hosta i daty pola takie jak `Owner`, `LicRepo` i `LicToken` zastępują głównego właściciela repozytorium, ścieżkę i token. Pozwala to operatorowi rotować dane uwierzytelniające i endpointy bez wymiany klienta; komentarz w zgłoszeniu pełni funkcję resolvera, a pliki repozytorium pozostają kanałem dostarczania zadań.<sup>[[15]](#references)</sup>

Wariant na Androida przy uruchomieniu wybiera jedną z dwóch publicznych stron Telegrama i wyodrębnia szyfrogram znajdujący się między dwoma wystąpieniami znacznika osadzonego w APK. Dekoduje wartość z Base64URL i odszyfrowuje ją za pomocą AES-128-CBC: pierwsze 16 bajtów `SHA-256(marker)` stanowi klucz, a pozostałe 16 bajtów — IV. Tekst jawny to właściwy bazowy URL C2, a nie URL strony Telegrama. Przy odtwarzaniu tego mechanizmu należy zachować zawartość strony i dokładny znacznik; zmiana publicznej strony pozwala zmienić endpoint bez ponownej kompilacji APK.<sup>[[16]](#references)</sup>

Zapewnia to odporność i ukrywa back-end C2 przed statyczną analizą binarną. Tworzy też stabilne identyfikatory obiektów, tenantów, repozytoriów, API i wzorców dostępu. Obrońcy powinni korelować:

1. proces, który nawiązał połączenie z usługą;
2. dokładną ścieżkę API/obiekt i hash odpowiedzi;
3. aktywność związaną z dekodowaniem lub przetwarzaniem ciągów;
4. nowe połączenie wychodzące krótko potem; oraz
5. identyczne zachowanie w innych miejscach floty.

Blokowanie całego GitHub, chmury do przechowywania danych lub mediów społecznościowych rzadko jest wykonalne. Polityka egress uwzględniająca usługi i korelacja na poziomie procesów są skuteczniejsze niż blokowanie wyłącznie domen.

## Persony, konta i podział zakupów

Anonimowość infrastruktury zawodzi, gdy persona, adres e-mail do odzyskiwania konta, telefon, płatność, przeglądarka lub administracyjny adres IP łączą odrębne obszary. Operacje powiązane z państwami rozwijały profile społecznościowe, tożsamości e-mail i konta chmurowe długo przed ich użyciem; ATT&CK opisuje to jako Establish Accounts (T1585), obejmujące podtechniki związane z mediami społecznościowymi, pocztą e-mail i chmurą.<sup>[[8]](#references)</sup>

Obrońca lub śledczy buduje graf na podstawie:

- czasu utworzenia i pierwszego logowania, ustawień regionalnych, strefy czasowej i harmonogramu pracy;
- pól odzyskiwania konta, urządzeń MFA, dokumentów tożsamości i instrumentów płatniczych;
- fingerprintów przeglądarki/TLS i historii sieci źródłowej;
- ponownego użycia awatarów, pochodzenia obrazów, stylu pisania i rozwoju sieci społecznościowej;
- wspólnego rejestrującego domenę, serwera nazw, certyfikatu, identyfikatora analitycznego lub commitu w repozytorium;
- działań w płaszczyźnie zarządzania, które omijają architekturę publicznych przekaźników.

W przypadku autoryzowanego red teamu syntetyczne persony należy udokumentować u kontrolera ćwiczenia, korzystać z należących do organizacji kanałów odzyskiwania kont i płatności, unikać podszywania się pod prawdziwe, niezaangażowane osoby oraz zaplanować ich wycofanie. SOC może pozostać nieświadomy operacji, ale nie może ona pozostać bez rozliczalności.

## Nowe złożone wzorce do modelowania zagrożeń

Poniższe przykłady to **kompozycje tworzone z perspektywy obrońcy**, a nie twierdzenia, że konkretny aktor wdrożył dokładnie każdy z tych projektów. Łączą już zaobserwowane prymitywy i mogą służyć jako hipotezy do ćwiczeń purple team.

### Asymetryczne, jednokierunkowe dostarczanie zadań

Polecenia przychodzą z publicznego, rozgłoszeniowego lub append-only źródła, a wyniki są wysyłane innym kanałem z opóźnieniem. Przykładami tych prymitywów są jednokierunkowa komunikacja przez usługi webowe i dead drops. Rozdzielenie kanałów sprawia, że pojedynczy przepływ nie wygląda na dwukierunkowy i utrudnia prostą korelację żądań z odpowiedziami.<sup>[[9]](#references)</sup>

**Wykrywanie:** zachowuj dane o odczytach na poziomie obiektów, a następnie koreluj zmiany stanu procesu i późniejsze transfery wychodzące w dłuższym oknie czasowym. Szukaj rzadko występujących procesów odczytujących ten sam publiczny obiekt, nawet jeśli nie następuje po tym natychmiastowa odpowiedź.

### Awansowanie kanału wieloetapowego

Pierwszy, dyskretny etap przeprowadza inwentaryzację i przenosi tylko wybrane systemy do niezwiązanego z nim kanału drugiego etapu. Drugi endpoint, protokół i proces mogą nie współdzielić z pierwszym żadnej infrastruktury. Ogranicza to ryzyko ujawnienia zaawansowanej infrastruktury i jest jawnie modelowane jako ATT&CK T1104.<sup>[[10]](#references)</sup>

**Wykrywanie:** koreluj `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; nie zamykaj incydentu po zablokowaniu pierwszej domeny.

### Translacja przekaźników między protokołami

Poszczególne węzły tłumaczą HTTPS, QUIC, WebSocket, DNS, SSH lub API kolejki wiadomości, zamiast przezroczysto przekazywać pakiety. Translacja usuwa pojedynczy fingerprint protokołu end-to-end, ale tworzy bramy o charakterystycznym czasie, buforowaniu i konwersji semantycznej. Protocol tunneling (T1572) można łączyć z proxy i podszywaniem się pod usługi.<sup>[[11]](#references)</sup>

**Wykrywanie:** szukaj hostów bramowych, które odbierają jeden protokół i inicjują inny, przy ściśle powiązanym przepływie bajtów i czasie; porównuj przeznaczenie endpointu z faktycznie przenoszonym protokołem.

### Pasywna aktywacja na urządzeniach brzegowych

Zamiast wysyłać beacon, implant monitoruje ruch docierający już do routera/VPN i aktywuje się wyłącznie po wykryciu magicznej wartości, wzorca portu źródłowego lub uwierzytelnionego tokenu. Zwykły ruch nadal trafia do prawdziwej usługi. ATT&CK nazywa tę technikę Traffic Signaling (T1205) i opisuje udokumentowane przykłady z urządzeń sieciowych oraz operacji APT.<sup>[[12]](#references)</sup>

**Wykrywanie:** sprawdzaj integralność firmware/plików, przeprowadzaj zrzut surowych pakietów w ramach autoryzowanego huntingu, szukaj nieoczekiwanych filtrów gniazd i różnic w zachowaniu usługi. Brak okresowego beacona nie dowodzi, że urządzenie brzegowe jest czyste.

### Serverless i rotacja efemerycznych originów

Front zachowuje stabilną tożsamość logiczną, podczas gdy krótkotrwałe funkcje/kontenery obsługują poszczególne etapy w wielu regionach/kontach. Skraca to czas obecności danych na dysku i eliminuje stałe adresy IP originów, ale trwały graf tworzą telemetria płaszczyzny zarządzania: utworzenie zasobu, obraz/warstwa, rola, sekret, identyfikator żądania i rozliczenia.

**Wykrywanie:** przechowuj logi audytowe chmury i wywołań poza workloadem; grupuj szablony wdrożeń, role, klucze środowiskowe i relacje front-origin.

### Różnorodność warstw prywatności

Operacja może celowo unikać jednorodnego łańcucha: na przykład jeden kanał korzysta z wynajętego przekaźnika, dostarczanie zadań odbywa się przez publiczny obiekt, wyjście prowadzi przez należące do operatora laboratoryjne łącze komórkowe, a administracja korzysta z odrębnej sieci organizacji. Ogranicza to korzyści z przejęcia jednego dostawcy, ale zwiększa ryzyko korelacji czasowej między warstwami i błędów operacyjnych.

**Wykrywanie:** buduj osie czasu kampanii na podstawie telemetrii tożsamości, DNS, SaaS, sieci i chmury. Szukaj zsynchronizowanych zmian stanu, a nie identycznych wskaźników.

### Zdecentralizowane dead drops lub dead drops w logach transparentności

Aktor może umieścić niewielki zaszyfrowany wskaźnik w dowolnym trwałym, publicznym systemie append-only, magazynie content-addressed lub feedzie podobnym do logu transparentności. Publiczny obiekt jest odporny na usunięcie, ale jego dokładny indeks/hash treści oraz zachowanie klienta podczas odpytywania stają się stabilnymi identyfikatorami.

**Wykrywanie:** rejestruj pełne identyfikatory API/obiektów i hashe odpowiedzi; generuj alerty, gdy niestandardowe procesy odpytują niezmienne obiekty, po czym następuje dekodowanie lub nawiązywane są nowe połączenia.

### Opóźnione operacje store-and-forward

Interaktywne C2 tworzy silną korelację czasową. Projekt store-and-forward grupuje zaszyfrowane zadania i zwraca wyniki po kilku minutach lub godzinach, inną kolejką lub przez fizyczny transfer. Poświęca szybkość reakcji w zamian za słabszą korelację czasową end-to-end.

**Wykrywanie:** wydłużaj okna korelacji, modeluj okresowy dostęp do kolejek i analizuj przygotowanie danych na endpointach. Grupowanie przenosi sygnał z czasu przesyłania pakietów na harmonogramy procesów/plików, ale go nie eliminuje.

## Przegląd projektu: myśl kategoriami obserwatorów

Dla każdej ścieżki wypełnij tę tabelę przed wdrożeniem i po zebraniu danych:

| Warstwa | Widzi źródło? | Widzi cel? | Widzi treść? | Stabilne identyfikatory | Retencja/właściciel prawny |
|---|---:|---:|---:|---|---|
| sieć lokalna/operator | | | | | |
| usługa wejściowa/dostępowa | | | | | |
| operator(y) tranzytowy(i) | | | | | |
| wyjście/redirector/CDN | | | | | |
| autorytatywny DNS/rejestrator | | | | | |
| cel | | | | | |
| dostawca konta/płatności | | | | | |

Jeśli jeden typowy dostawca może wypełnić każdą kolumnę, architektura zapewnia ukrycie przed celem, ale nie solidne rozdzielenie. Jeśli żaden wewnętrzny kontroler nie może powiązać aktywności z ćwiczeniem, taka architektura nie nadaje się do profesjonalnego red teamingu.

## References

- [1] [MITRE ATT&CK — Pozyskiwanie infrastruktury (T1583), kompromitowanie infrastruktury (T1584) i proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Aktorzy szpiegowscy powiązani z Chinami korzystają z sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Kompromitowanie infrastruktury: domeny (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Usługa webowa: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Tworzenie kont (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Usługa webowa: komunikacja jednokierunkowa (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Kanały wieloetapowe (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Tunelowanie protokołów (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Sygnalizowanie ruchu (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Zakłócenie działania największej na świecie sieci proxy residential](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Kampanie Shadow: odkrywanie globalnego szpiegostwa](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Kampania Blinder Tunnel wymierzona w iracką infrastrukturę](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI stworzyło nakładki. Ofiary tracą swoje PIN-y](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Sztuczki z przeszłości wykorzystane za pośrednictwem podpisanych plików binarnych ChatGPT i Claude](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
