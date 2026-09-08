# Atrybucja, detekcja i countermeasures

{{#include ../banners/hacktricks-training.md}}

Infrastruktura służąca do unikania atrybucji jest projektowana tak, aby poszczególne wskaźniki można było łatwo wymieniać. Defenders powinni zachowywać surowe dowody, modelować relacje i wyszukiwać zachowania, które przetrwają zmianę adresu IP, domeny lub persony.

## Hierarchia dowodów

| Dowód | Przydatny do | Główne zastrzeżenie |
|---|---|---|
| Source IP/ASN/geolocation | lokalizacji widocznego wyjścia i providera | wyjście może być relayem, NAT-em lub ofiarą; geolokalizacja jest przybliżona |
| Passive DNS/registration | historii infrastruktury i co-hostingu | prywatność/redakcja danych oraz shared hosting tworzą luki |
| Certificate/TLS/HTTP fingerprint | grupowania powtarzających się wdrożeń | popularne oprogramowanie i mimicry powodują false positives |
| Flow timing and byte shape | łączenia etapów relay i powtarzających się beaconów | CDN/NAT oraz ograniczona widoczność zmniejszają pewność |
| Endpoint process/identity | wyjaśnienia, dlaczego doszło do połączenia | niedostępne na edge/IoT; attacker może używać native tools |
| Cloud/CDN/API audit | identyfikacji tenanta i kontroli nad infrastrukturą | retencja oraz dostęp providera/legal access są różne |
| Payment/account/device | połączenia procurement z osobą/encją | należy uwzględnić nominee, compromise i współdzielone urządzenia |
| Seized implant/configuration | ujawnienia kluczy, peerów, kontrolerów i powiązań buildów | istotne są integralność pozyskania i czas seizure |
| Human/physical evidence | połączenia zdarzenia cyfrowego z miejscem/operatoriem | inwazyjne, zależne od jurysdykcji, wymaga ścisłego postępowania |

Żaden pojedynczy wiersz nie powinien stanowić podstawy do atrybucji państwowej o wysokim poziomie pewności. Stosuj konkurencyjne hipotezy i określaj, która obserwacja sfalsyfikowałaby każdą z nich.

## Minimum telemetry

1. **DNS:** klient, zapytanie, typ, odpowiedzi, TTL, kod odpowiedzi, resolver i timestamp.
2. **Network flow:** source/destination/port, początek/koniec, pakiety/bajty, flagi TCP i lokalizacja sensora.
3. **TLS/HTTP:** SNI, gdy jest widoczne, certyfikat, wynegocjowany protokół, fingerprint klienta/serwera, metoda, kategoria authority/path, status i liczba bajtów. Chroń pełne wrażliwe URL-e.
4. **Identity:** wynik uwierzytelniania, factor/certificate/device, source, aplikacja, session ID i decyzja risk.
5. **Endpoint:** proces inicjujący, parent, użytkownik, sygnatura/hash binary oraz destination.
6. **Edge/network device:** różnica konfiguracji, logowanie admina, integralność process/file/firmware, interfejs i flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, akcja API, source, obiekt/resource, token i wynik.
8. **Wireless/NAC:** stacja, flaga randomized-MAC, AP, sygnał, tożsamość/certyfikat EAP, przypisany VLAN/IP i posture.

Synchronizuj zegary, zachowuj oryginalne strefy czasowe, dokumentuj granice NAT/proxy i przechowuj wystarczającą historię, aby przetrwać dłużej niż 31-dniowy węzeł ORB.

## Zbuduj graf atrybucji

Reprezentuj obserwacje jako typowane węzły i krawędzie:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Przydatne węzły obejmują IP, prefiks, ASN, domenę, konto DNS, certyfikat/klucz, fingerprint podobny do JA3/JA4, gramatykę HTTP, hash pliku/konfiguracji, tenant cloud, token API, adres e-mail, personę, instrument płatniczy i urządzenie fizyczne. Każda krawędź musi zawierać `first_seen`, `last_seen`, sensor/źródło, poziom pewności oraz informację, czy jest zaobserwowana, czy wywnioskowana.

Sama gęstość grafu może wprowadzać w błąd: CDN lub urząd certyfikacji łączy wielu niepowiązanych operatorów. Relacjom rzadko kontrolowanym przez operatora — temu samemu kontu API, kluczowi SSH, liście dozwolonych adresów origin, unikatowej treści odpowiedzi lub protokołowi sterowania — należy nadawać większą wagę niż powszechnemu hostingowi.

## ORB i polowanie na przejęte routery

### Na podstawie zaobserwowanego wyjścia

1. Ustal, czy adres jest związany z hostingiem, siecią rezydencjalną, mobilną, edukacyjną czy biznesową; nie odrzucaj źródeł rezydencjalnych.
2. Pobierz historyczne dane DNS, usługi/certyfikaty, otwarte porty oraz zaobserwowane zachowania związane ze skanowaniem i exploitation w ograniczonym przedziale czasu.
3. Wyszukaj węzły powiązane przez rzadkie fingerprinty usług, adresy kontrolerów, materiały certyfikatów lub synchronizację rotacji.
4. Sklasyfikuj prawdopodobne role: dostęp, tranzyt, wyjście/staging lub administracja.
5. Sprawdź, czy wiele niepowiązanych klastrów intrusion korzystało z tej samej puli; multi-tenancy osłabia bezpośrednią atrybucję operatora, ale wzmacnia hipotezę ORB.
6. Śledź nowe węzły pasujące do profilu roli po zniknięciu starych adresów IP.

### U właściciela sieci

- Generuj alerty dotyczące nowo wystawionych do Internetu interfejsów zarządzania oraz domyślnego/legacy uwierzytelniania.
- Przesyłaj zmiany konfiguracji routerów/firewalli/VPN oraz uwierzytelnianie administratorów poza urządzenie.
- Ustal baseline połączeń wychodzących z infrastruktury, która zwykle inicjuje niewiele sesji.
- Wykrywaj nowe procesy proxy/listener, tunele, zadania zaplanowane, zmiany firmware oraz nieoczekiwany DNS.
- Wymieniaj urządzenia wycofane z eksploatacji; reboot usuwający malware z pamięci ulotnej nie usuwa podatności.
- Ogranicz zarządzanie do uwierzytelnionej płaszczyzny administracyjnej i znanych źródeł.

Mandiant zaleca śledzenie infrastruktury ORB jako ewoluującego podmiotu, ponieważ krótkotrwałe blokowanie adresów IP nie odzwierciedla topologii ani cyklu życia.<sup>[[1]](#references)</sup>

## Fast-flux i analityka dynamic-DNS

Agreguj dane według zarejestrowanej domeny i przesuwnego okna czasowego. Praktyczny wynik może łączyć:
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
Zbadaj domeny pod kątem kilku niezależnych cech, a nie jednego progu. Porównaj je z modelem dozwolonych zachowań CDN/anti-DDoS i sprawdź rotację autorytatywnych name serverów, aby odróżnić single flux od double flux. W przypadku DGA uwzględnij serie żądań NXDOMAIN per-client, rozkład długości i znaków, zsynchronizowane zapytania z wielu hostów oraz proces, który je generuje. Aktualne wytyczne MITRE również podkreślają znaczenie częstych zmian, niskiego TTL oraz korelacji procesów i sieci.<sup>[[2]](#references)</sup>

## Domain-fronting detection

Jeśli endpoint przedsiębiorstwa lub autoryzowany punkt inspekcji ma obie tożsamości, porównaj:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Zwiększ poziom pewności, gdy SNI i authority należą do niepowiązanych tenantów, proces nie jest zatwierdzonym klientem, sesja jest okresowa/długotrwała, a wewnętrzne origin jest rzadkie. Puste SNI to cecha, którą należy rejestrować, a nie automatycznie uznawać za złośliwą. ECH może ukrywać SNI w sieci, dlatego większego znaczenia nabierają logi endpointów, DNS i dostawców/CDN. MITRE opisuje zarówno warianty z niedopasowaniem, jak i z pustym SNI.<sup>[[3]](#references)</sup>

## Wykrywanie sekwencji Dead-drop resolver

Zachowanie o wysokiej wartości sygnału stanowi sekwencję, a nie zablokowaną domenę:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Przeszukuj całą flotę pod kątem identycznych ścieżek obiektów, hashy odpowiedzi, identyfikatorów API i docelowych adresów dalszych etapów. Zachowaj pobraną zawartość, ponieważ actor może ją edytować lub usunąć. Ogranicz niepotrzebne service APIs i wymagaj, aby zatwierdzone aplikacje korzystały z enterprise proxies, uwzględniając jednak narzędzia deweloperskie i automatyzację. MITRE wymienia GitHub, fora, dokumenty oraz usługi social/web w rzeczywistych procedurach.<sup>[[4]](#references)</sup>

## Klastrowanie Redirectorów i wdrożeń wielokrotnego użytku

Nawet gdy domeny i adresy się zmieniają, operatorzy często ponownie wdrażają tę samą automatyzację. Grupuj na podstawie kombinacji:

- pól certyfikatu/ponownego użycia klucza i czasu wystawienia;
- wersji TLS, szyfru, kolejności rozszerzeń i zachowania serwera;
- identycznego statusu HTTP, kolejności nagłówków, zachowania cache, ikony/treści i strony błędu;
- nietypowych par portów i łańcuchów przekierowań;
- wzorca dostawcy DNS/serwera nazw i harmonogramu TTL;
- czasu wdrożenia, czasu dostępności i okna konserwacji;
- ujawnienia back-endowego originu lub identycznych allowlist.

Pojedyncza generyczna strona Nginx jest słabym dowodem. Kilka rzadkich, niezależnych zgodności wraz z ciągłością czasową może uzasadniać hipotezę klastra infrastruktury.

## Wykrywanie Residential proxy i niemożliwych sesji

Utrzymuj tożsamość sesji powyżej warstwy IP. Oznaczaj kombinacje takie jak:

- jeden fingerprint sesji/urządzenia zmienia kraje/ASNy szybciej, niż pozwala na to podróż;
- konsumencki adres IP zmienia się przy każdym żądaniu, podczas gdy cookies i tożsamość TLS/przeglądarki pozostają stałe;
- deklarowane urządzenie lokalne ma opóźnienie/strefę czasową/język niespójne z wyjściem;
- adres naprzemiennie obsługuje niezwiązane populacje kont lub wykazuje zachowanie backconnect proxy;
- uprzywilejowana sesja pojawia się z residential access bez certyfikatu urządzenia organizacji.

Carrier NAT, narzędzia ułatwień dostępu, korporacyjne VPN-y i podróże powodują łagodne anomalie. Wymagaj step-up authentication lub analizy zamiast nieodwracalnego blokowania wyłącznie na podstawie etykiet „residential proxy”.

## Wykrywanie urządzeń bezprzewodowych i covert devices

Połącz RADIUS/NAC z kontekstem AP i fizycznym:

1. znajdź kombinacje konto–urządzenie–AP zaobserwowane po raz pierwszy;
2. zidentyfikuj poświadczenia użyte bez zarządzanego certyfikatu/posture EAP;
3. porównaj równoczesne sesje oraz obecność na podstawie identyfikatorów wejścia do budynku;
4. sprawdź nietypowo słaby/graniczny sygnał oraz przemieszczanie się między AP;
5. przeszukaj pobliskie zarządzane endpointy pod kątem wireless scanning, nowo włączonego bridge/NAT interfejsu, wirtualnych adapterów lub tuneli;
6. zinwentaryzuj nową aktywność switchportów, DHCP, sieci USB i PoE;
7. przeprowadź autoryzowany RF/physical sweep, gdy dowody to uzasadniają.

Pozwala to wykryć zarówno ścieżkę typu nearest-neighbor w stylu APT28, jak i urządzenie pozostawione podczas ćwiczeń. MAC randomization nie może być traktowane jako tożsamość ani dowód winy.

## Wykrywanie atrybucji finansowej

- Zachowaj dokładny łańcuch, token, adres, transakcję i identyfikatory bloków.
- Śledź wartość przez change, peel chains, fan-out/in, mixery, bridges i depozyty usług, oznaczając heurystyki.
- Koreluj czas, kwotę pomniejszoną o opłaty, zdarzenie kontraktu, płynność i wypłatę do docelowego łańcucha.
- Uzyskaj lub zachowaj zgodne z prawem rekordy giełd, bridges, merchantów, kont, urządzeń i dostaw.
- Sprawdzaj bieżące sankcjonowane podmioty/adresy oraz ich pochodne w ramach właściwego programu; nie polegaj na starej statycznej liście.
- Traktuj użycie privacy protocols jako dane kontekstowe ryzyka, a nie dowód naruszenia prawa.

Red flags FATF są jawnie kontekstowe: nietypowy wzorzec, kwota/częstotliwość, geografia, źródło środków i usługi zwiększające anonimowość nabierają znaczenia łącznie.<sup>[[5]](#references)</sup>

## Deception i canaries

Defenders mogą tworzyć sygnały o wysokiej pewności bez prób deanonymization zwykłych użytkowników:

- unikalne poświadczenia lub dokumenty, które nigdy nie powinny opuścić jednego systemu;
- fałszywe endpointy administracyjne i decoy shares;
- instrumentowane nazwy DNS osadzone wyłącznie w kontrolowanych artefaktach;
- canary cloud keys bez legalnego zastosowania;
- decoy Wi-Fi identity, której nie posiada żadne zarządzane urządzenie.

Starannie określ zakres i zasady deception. Canary powinien identyfikować niewłaściwe użycie własnego zasobu defensora, a nie zbierać niezwiązany ruch stron trzecich.

## Priorytety countermeasures

1. Usuń nieobsługiwane routery, VPN-y i appliances wystawione do Internetu.
2. Wymagaj phishing-resistant MFA i certyfikatów powiązanych z urządzeniem, w tym dla dostępu wewnętrznego/bezprzewodowego.
3. Scentralizuj wystarczająco niezmienne logi tożsamości, endpointów, DNS, przepływów, proxy, cloud i urządzeń sieciowych.
4. Ogranicz zarządzanie i egress; zinwentaryzuj każdą usługę dostępną z zewnątrz.
5. Monitoruj DNS, certificate transparency i konfigurację cloud pod kątem nieautoryzowanych zasobów.
6. Zachowaj widoczność process-to-network oraz na poziomie obiektów SaaS.
7. Ćwicz dochodzenia cross-layer i koordynację z sąsiednimi dostawcami.
8. Śledź klastry infrastruktury i zachowania, a nie tylko blocklisty IP.

## Dyscyplina analityczna

Używaj języka określającego poziom pewności:

- **Observed:** rekord sensora/dostawcy bezpośrednio pokazuje relację.
- **Strongly supported:** wiele niezależnych obserwacji przemawia za nią bardziej niż za alternatywami.
- **Assessed:** wnioskowanie oparte na określonych założeniach i dowodach.
- **Unknown:** brak widoczności uniemożliwia wyciągnięcie wniosku.

Zawsze utrzymuj co najmniej dwie hipotezy: infrastruktura obsługiwana przez actora versus przejęty/współdzielony intermediary; jeden actor versus usługa multi-tenant; celowe omijanie wykrywania versus uzasadnione zachowanie privacy/CDN. Umiejętność wyjaśnienia niepewności jest częścią poprawnego wykrywania.

## References

- [1] [Google Cloud/Mandiant — Aktorzy szpiegowscy powiązani z Chinami używają sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Wskaźniki czerwonych flag Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Aktorzy z ChRL uzyskują i utrzymują trwały dostęp](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Wytyczne dotyczące zwiększonej widoczności i hardeningu infrastruktury komunikacyjnej](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
