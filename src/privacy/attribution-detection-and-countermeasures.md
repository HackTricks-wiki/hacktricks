# Atrybucja, wykrywanie i środki zaradcze

Infrastruktura służąca do unikania atrybucji jest projektowana tak, aby poszczególne wskaźniki można było łatwo wymieniać. Obrońcy powinni zachowywać surowe dowody, modelować zależności i wyszukiwać zachowania, które pozostają niezmienne mimo zmiany adresu IP, domeny lub persony.

## Hierarchia dowodów

| Dowód | Przydatność | Główne zastrzeżenie |
|---|---|---|
| Źródłowy adres IP/ASN/geolokalizacja | zlokalizowanie widocznego wyjścia i dostawcy | wyjście może być relayem, NAT-em lub ofiarą; geolokalizacja jest przybliżona |
| Pasywny DNS/rejestracja | historia infrastruktury i wspólne hostowanie | prywatność/redakcja danych i shared hosting tworzą luki |
| Fingerprint certyfikatu/TLS/HTTP | grupowanie powtarzających się wdrożeń | powszechne oprogramowanie i naśladowanie tworzą false positives |
| Czas i kształt pakietów | łączenie etapów relaya i powtarzających się beaconów | CDN/NAT oraz ograniczona widoczność zmniejszają pewność |
| Proces/tożsamość endpointu | wyjaśnienie, dlaczego doszło do połączenia | niedostępne na urządzeniach edge/IoT; atakujący może używać native tools |
| Audyt Cloud/CDN/API | identyfikacja tenanta i kontroli nad infrastrukturą | retencja oraz dostęp dostawcy i organów prawnych są różne |
| Płatność/konto/urządzenie | powiązanie zakupu z osobą/podmiotem | należy uwzględnić nominee, przejęcie i współdzielone urządzenia |
| Przejęty implant/konfiguracja | ujawnienie kluczy, peerów, kontrolerów i powiązań z buildami | istotne są integralność pozyskania i czas przejęcia |
| Dowody osobowe/fizyczne | powiązanie zdarzenia cyfrowego z miejscem/operatorem | inwazyjne, zależne od jurysdykcji i wymagające ścisłego postępowania |

Żaden pojedynczy wiersz nie powinien stanowić podstawy atrybucji państwowej o wysokiej pewności. Należy stosować konkurencyjne hipotezy i wskazywać, która obserwacja sfalsyfikowałaby każdą z nich.

## Minimalna telemetria

1. **DNS:** klient, zapytanie, typ, odpowiedzi, TTL, kod odpowiedzi, resolver i znacznik czasu.
2. **Przepływ sieciowy:** źródło/cel/port, początek/koniec, pakiety/bajty, flagi TCP i lokalizacja sensora.
3. **TLS/HTTP:** SNI, gdy jest widoczne, certyfikat, wynegocjowany protokół, fingerprint klienta/serwera, metoda, kategoria authority/path, status i liczba bajtów. Należy chronić wrażliwe pełne URL-e.
4. **Tożsamość:** wynik uwierzytelniania, czynnik/certyfikat/urządzenie, źródło, aplikacja, ID sesji i decyzja dotycząca ryzyka.
5. **Endpoint:** proces inicjujący, proces nadrzędny, użytkownik, sygnatura/hash pliku binarnego i cel.
6. **Urządzenie edge/sieciowe:** różnica konfiguracji, logowanie administratora, integralność procesu/pliku/firmware'u, logi interfejsów i przepływów.
7. **Cloud/SaaS/CDN:** aktor, tenant/projekt, akcja API, źródło, obiekt/zasób, token i wynik.
8. **Sieć bezprzewodowa/NAC:** stacja, flaga randomized-MAC, AP, sygnał, tożsamość/certyfikat EAP, przypisany VLAN/IP i stan zabezpieczeń.

Synchronizuj zegary, zachowuj oryginalne strefy czasowe, dokumentuj granice NAT/proxy i przechowuj wystarczającą historię, aby przetrwać dłużej niż 31-dniowy węzeł ORB.

## Budowanie grafu atrybucji

Reprezentuj obserwacje jako typowane węzły i krawędzie:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Przydatne nodes obejmują IP, prefix, ASN, domenę, konto DNS, certyfikat/klucz, fingerprint podobny do JA3/JA4, gramatykę HTTP, hash pliku/konfiguracji, tenant cloud, token API, e-mail, personę, instrument płatniczy i urządzenie fizyczne. Każda krawędź musi zawierać `first_seen`, `last_seen`, sensor/source, poziom pewności oraz informację, czy jest zaobserwowana, czy wywnioskowana.

Sama gęstość grafu jest myląca: CDN lub urząd certyfikacji łączy wielu niepowiązanych operatorów. Relacjom rzadkim i kontrolowanym przez operatora — temu samemu kontu API, kluczowi SSH, origin allowlist, unikalnemu response body lub protokołowi sterowania — należy nadawać większą wagę niż powszechnemu hostingowi.

## Polowanie na ORB i przejęte routery

### Na podstawie zaobserwowanego exit

1. Ustal, czy adres jest hostingiem, źródłem residential, mobile, edukacyjnym czy biznesowym; nie odrzucaj źródeł residential.
2. Pobierz historyczne dane DNS, informacje o usługach/certyfikatach, otwartych portach oraz zaobserwowane zachowania związane ze skanowaniem i exploitation dla określonego przedziału czasu.
3. Wyszukaj peers współdzielące rzadkie fingerprinty usług, destinations kontrolerów, materiały certyfikatów lub synchronizację rotacji.
4. Sklasyfikuj prawdopodobne role: access, traversal, exit/staging lub administration.
5. Sprawdź, czy wiele niepowiązanych klastrów intrusion korzystało z tej samej puli; multi-tenancy osłabia bezpośrednią atrybucję aktora, ale wzmacnia hipotezę ORB.
6. Śledź nowe nodes pasujące do profilu roli po zniknięciu starych adresów IP.

### U właściciela sieci

- Generuj alerty dotyczące nowego managementu wystawionego do Internetu oraz domyślnego/przestarzałego uwierzytelniania.
- Przesyłaj zmiany konfiguracji routerów/firewalli/VPN oraz uwierzytelnianie administratorów poza urządzenie.
- Ustal baseline połączeń wychodzących z infrastruktury, która zwykle inicjuje niewiele sesji.
- Wykrywaj nowe procesy proxy/listener, tunele, scheduled tasks, zmiany firmware oraz nieoczekiwany DNS.
- Wymieniaj urządzenia wycofane z eksploatacji; reboot, który usuwa volatile malware, nie eliminuje podatności.
- Ogranicz management do uwierzytelnionej płaszczyzny administracyjnej i znanych źródeł.

Mandiant zaleca śledzenie infrastruktury ORB jako ewoluującego obiektu, ponieważ krótkotrwałe blokowanie adresów IP nie odwzorowuje topologii ani cyklu życia.<sup>[[1]](#references)</sup>

## Analiza fast-flux i dynamic-DNS

Agreguj dane według zarejestrowanej domeny i ruchomego okna czasowego. Praktyczny score może łączyć:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Badaj domeny na podstawie kilku niezależnych cech, a nie jednego progu. Porównuj je z modelem dozwolonych domen CDN/anti-DDoS i sprawdzaj rotację autorytatywnych name serverów, aby odróżnić single flux od double flux. W przypadku DGA uwzględnij serie NXDOMAIN na klienta, rozkład długości i znaków, zsynchronizowane zapytania z wielu hostów oraz proces, który je generuje. Aktualne wytyczne MITRE również kładą nacisk na częste zmiany, niski TTL oraz korelację procesu z ruchem sieciowym.<sup>[[2]](#references)</sup>

## Wykrywanie domain-fronting

Jeśli endpoint przedsiębiorstwa lub autoryzowany punkt inspekcji ma dostęp do obu tożsamości, porównaj:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Zwiększaj poziom zaufania do wykrycia, gdy SNI i authority należą do niepowiązanych tenantów, proces nie jest zatwierdzonym klientem, sesja jest okresowa lub długotrwała, a wewnętrzne źródło jest rzadkie. Pusty SNI to cecha, którą należy rejestrować, a nie automatycznie uznawać za złośliwą. ECH może ukrywać SNI w transmisji, dlatego większego znaczenia nabierają logi endpointów, DNS i dostawców/CDN. MITRE opisuje zarówno warianty z niezgodnym SNI, jak i z pustym SNI.<sup>[[3]](#references)</sup>

## Wykrywanie sekwencji dead-drop resolver

Zachowanie o wysokiej wartości sygnałowej stanowi sekwencja, a nie zablokowana domena:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Przeszukuj całą flotę pod kątem identycznych ścieżek obiektów, hashy odpowiedzi, identyfikatorów API i docelowych adresów dalszych etapów. Zachowaj pobraną zawartość, ponieważ actor może ją edytować lub usunąć. Ogranicz zbędne service APIs i wymagaj, aby zatwierdzone aplikacje korzystały z enterprise proxies, uwzględniając jednak developer tools i automation. MITRE wymienia GitHub, fora, dokumenty oraz usługi social/web w rzeczywistych procedurach.<sup>[[4]](#references)</sup>

## Grupowanie redirectorów i wielokrotnie używanych wdrożeń

Nawet gdy domeny i adresy się zmieniają, operatorzy często ponownie wdrażają tę samą automation. Grupuj na podstawie kombinacji:

- pól certyfikatu, ponownego użycia kluczy i czasu wydania;
- wersji TLS, cipherów, kolejności extensionów i zachowania serwera;
- identycznego statusu HTTP, kolejności nagłówków, zachowania cache, ikony/body i strony błędu;
- nietypowych par portów i łańcuchów przekierowań;
- wzorca dostawcy DNS/name-server oraz harmonogramu TTL;
- czasu wdrożenia, uptime i okna maintenance;
- ujawnienia originu back-endu lub identycznych allowlist.

Pojedyncza generyczna strona Nginx jest słabym dowodem. Kilka rzadkich, niezależnych dopasowań wraz z ciągłością czasową może uzasadniać hipotezę o klastrze infrastruktury.

## Wykrywanie residential proxy i niemożliwych sesji

Utrzymuj tożsamość sesji powyżej warstwy IP. Oznaczaj kombinacje takie jak:

- jeden fingerprint sesji/urządzenia zmienia kraje/ASN-y szybciej, niż pozwala na to podróż;
- consumer IP zmienia się przy każdym żądaniu, podczas gdy cookies i tożsamość TLS/browser pozostają stałe;
- deklarowane urządzenie lokalne ma opóźnienie/strefę czasową/język niespójne z exitem;
- adres naprzemiennie obsługuje niepowiązane populacje kont lub wykazuje zachowanie backconnect proxy;
- uprzywilejowana sesja pojawia się z residential access bez certyfikatu urządzenia organizacji.

Carrier NAT, narzędzia ułatwień dostępu, corporate VPN-y i podróże powodują nieszkodliwe anomalie. Wymagaj step-up authentication lub przeprowadzenia dochodzenia zamiast nieodwracalnego blokowania wyłącznie na podstawie etykiet „residential proxy”.

## Wykrywanie urządzeń wireless i covert

Połącz RADIUS/NAC z kontekstem AP i lokalizacji fizycznej:

1. znajdź kombinacje konto–urządzenie–AP zaobserwowane po raz pierwszy;
2. zidentyfikuj dane uwierzytelniające użyte bez zarządzanego certyfikatu EAP/posture;
3. porównaj równoczesne sesje oraz obecność na podstawie badge/buildingu;
4. zbadaj wyjątkowo słaby/graniczny sygnał oraz przemieszczanie się między AP;
5. przeszukaj pobliskie zarządzane endpointy pod kątem wireless scanning, nowo włączonego bridge/NAT interfejsu, virtual adapters lub tunnels;
6. zinwentaryzuj nową aktywność switchport, DHCP, USB network i PoE;
7. przeprowadź autoryzowany RF/physical sweep, gdy dowody to uzasadniają.

Pozwala to wykryć zarówno ścieżkę nearest-neighbor w stylu APT28, jak i exercise drop. MAC randomization nie może być traktowana jako tożsamość ani dowód winy.

## Wykrywanie atrybucji finansowej

- Zachowaj dokładny chain, token, adres, transakcję i identyfikatory bloku.
- Śledź wartość przez change, peel chains, fan-out/in, mixers, bridges i deposits w usługach, oznaczając heurystyki.
- Koreluj czas, kwotę pomniejszoną o opłaty, contract event, płynność i wypłatę na łańcuchu docelowym.
- Uzyskaj lub zachowaj zgodne z prawem dane exchange, bridge, merchant, account, device i delivery.
- Sprawdzaj aktualne sankcjonowane podmioty/adresy oraz ich derivatives w ramach właściwego programu; nie polegaj na starej statycznej liście.
- Traktuj użycie privacy protocol jako dane wejściowe kontekstu ryzyka, a nie dowód naruszenia prawa.

Czerwone flagi FATF są jawnie kontekstowe: nietypowy wzorzec, kwota/częstotliwość, geografia, źródło środków i usługi zwiększające anonimowość nabierają znaczenia łącznie.<sup>[[5]](#references)</sup>

## Deception i canaries

Defenders mogą tworzyć sygnały o wysokiej pewności bez prób deanonymization zwykłych użytkowników:

- unikalne dane uwierzytelniające lub dokumenty, które nigdy nie powinny opuścić jednego systemu;
- fałszywe administrative endpoints i decoy shares;
- instrumentowane nazwy DNS osadzone wyłącznie w kontrolowanych artefaktach;
- canary cloud keys bez uzasadnionego zastosowania;
- decoy Wi-Fi identity, której nie posiada żadne zarządzane urządzenie.

Starannie określaj zakres i zarządzaj deception. Canary powinien identyfikować niewłaściwe użycie własnego zasobu defendera, a nie zbierać niepowiązanego ruchu stron trzecich.

## Priorytety countermeasures

1. Usuń nieobsługiwane routers, VPN-y i appliances wystawione do Internetu.
2. Wymagaj phishing-resistant MFA i device-bound certificates, w tym dla dostępu internal/wireless.
3. Scentralizuj wystarczająco immutable logi identity, endpoint, DNS, flow, proxy, cloud i network-device.
4. Ogranicz management i egress; zinwentaryzuj każdą usługę osiągalną z zewnątrz.
5. Monitoruj DNS, certificate transparency i konfigurację cloud pod kątem nieautoryzowanych zasobów.
6. Zachowaj widoczność process-to-network oraz object-level SaaS.
7. Ćwicz dochodzenia cross-layer i koordynację z sąsiednimi providerami.
8. Śledź klastry infrastruktury i zachowania, a nie tylko IP blocklists.

## Dyscyplina analityczna

Używaj języka określającego poziom pewności:

- **Zaobserwowane:** rekord sensora/providera bezpośrednio pokazuje daną relację.
- **Silnie potwierdzone:** wiele niezależnych obserwacji przemawia za nią bardziej niż za alternatywami.
- **Ocenione:** wniosek oparty na określonych założeniach i dowodach.
- **Nieznane:** brak widoczności uniemożliwia wyciągnięcie wniosku.

Zawsze utrzymuj co najmniej dwie hipotezy: infrastruktura obsługiwana przez actora versus przejęty/współdzielony intermediary; jeden actor versus usługa multi-tenant; celowe unikanie wykrycia versus uzasadnione zachowanie privacy/CDN. Umiejętność wyjaśnienia niepewności jest częścią poprawnego detection.

## References

- [1] [Google Cloud/Mandiant — Aktorzy prowadzący espionage powiązane z Chinami używają sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Wskaźniki czerwonych flag Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Aktorzy z ChRL uzyskują i utrzymują persistent access](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Wytyczne dotyczące zwiększonej widoczności i hardeningu infrastruktury komunikacyjnej](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
