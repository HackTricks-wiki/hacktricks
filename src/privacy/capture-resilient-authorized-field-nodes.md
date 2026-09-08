# Odporne na przejęcie autoryzowane węzły terenowe

{{#include ../banners/hacktricks-training.md}}

Umieszczony na miejscu Raspberry Pi, mini-PC, travel router lub urządzenie cellular może zapewnić autoryzowanemu red teamowi trwały punkt obserwacyjny. Jest on również prawdopodobnym punktem wykrycia, kradzieży i atrybucji. Właściwym celem projektowym jest zatem **stabilny, kontrolowany dostęp przy niewielkich uprawnieniach węzła terenowego**, a nie niemożliwy do prześledzenia implant.

Ten przewodnik dotyczy wyłącznie sprzętu umieszczonego za pisemną zgodą właściciela obiektu. Kawiarnia, sąsiad, hotel lub współdzielony budynek nie wchodzą w zakres tylko dlatego, że ich sieć jest osiągalna. Nie ukrywaj sprzętu w miejscu, którego właściciel nie wyraził zgody, nie omijaj captive portal, nie używaj danych uwierzytelniających innej osoby, nie zakłócaj monitoringu ani nie próbuj usuwać dowodów po wykryciu.

{% hint style="warning" %}
Nie istnieje niezawodne ustawienie „nie pozostawiaj śladów”. Dane dotyczące asocjacji radiowej, DHCP/NAT, operatora, kamer, zakupu, urządzenia, dostawcy, kontrolera i miejsca docelowego mogą przetrwać po usunięciu urządzenia. Odpowiedzialny red team usuwa z węzła **osobiste i niezwiązane z nim sekrety**, zachowuje chronioną atrybucję po stronie kontrolera i sprawia, że przejęcie można tanio ograniczyć.
{% endhint %}

## Zalety i wady

**Zalety:** realistyczne źródło wewnętrzne lub znajdujące się blisko celu; stabilne testy o wysokiej przepustowości; weryfikacja NAC, egress, inwentaryzacji fizycznej i pokrycia SOC; możliwość kontynuowania pracy mimo zmian adresu operatora; dostęp o ograniczonym zakresie można centralnie unieważnić.

**Wady:** fizyczne umieszczenie tworzy silne dowody; utrata urządzenia może ujawnić dane uwierzytelniające urządzenia, profile sieci i zebrane dane; powtarzalny ruch control jest wykrywalny; zasilanie, portale i zmiany radiowe pogarszają niezawodność; szeroki tunel może stać się niekontrolowanym pivotem.

## Model zagrożeń i niezmienniki projektowe

Załóż, że znalazca może usunąć pamięć masową, przeanalizować firmware, skopiować każdy sekret przechowywany przez software, obserwować późniejsze zachowanie sieciowe i przekazać urządzenie klientowi lub organom ścigania. Szyfrowanie całego dysku chroni wyłączone urządzenie wyłącznie w ramach określonego modelu zagrożeń; uruchomiony i odblokowany węzeł oraz klucze zwolnione do pamięci to różne przypadki.

| Niezmiennik | Praktyczna konsekwencja |
|---|---|
| Brak bezpośredniej tożsamości operatora względem węzła | Operator loguje się do gateway organizacji; węzeł ma odrębną tożsamość urządzenia |
| Brak materiałów z osobistej stacji roboczej | Brak osobistego klucza SSH, profilu przeglądarki, poczty e-mail, password managera, parowania telefonu lub cache CLI cloud |
| Brak głównego sekretu kontrolera | Jeden węzeł nie może zarejestrować innego, zmienić policy ani odszyfrować danych innych engagementów |
| Tylko ruch wychodzący i wąski zakres | Sieć terenowa nie akceptuje żadnego listenera zarządzania; węzeł łączy się wyłącznie z nazwanymi usługami rendezvous/update/time |
| Krótkotrwałe uprawnienia o ograniczonym zakresie | Każde poświadczenie ma jedno urządzenie, audience, usługę, termin wygaśnięcia i natychmiastową ścieżkę revocation |
| Minimalna ilość danych lokalnych | Wyniki są przesyłane strumieniowo do kontrolera; cache są szyfrowane, a ich rozmiar i TTL są ograniczone oraz nie mają charakteru nadrzędnego |
| Odpowiedzialność kontrolera przetrwa przejęcie | Mapowanie zasobu do engagementu, zgody, dostęp operatora i polecenia są przechowywane centralnie i objęte kontrolą dostępu |
| Utrata zatrzymuje pracę | Wykrycie lub niewyjaśniona zmiana stanu uruchamia zatrzymanie, revoke, powiadomienie i zachowanie dowodów — nie zdalne niszczenie |

Baseline IoT firmy NIST grupuje identyfikację urządzenia, konfigurację, ochronę danych, dostęp logiczny, bezpieczne aktualizacje software oraz świadomość stanu cybersecurity jako podstawowe możliwości. W szczególności uznaje świadomość stanu i zdarzenia rejestrowane poza urządzeniem za wsparcie w badaniu kompromitacji.<sup>[[1]](#references)</sup>

## Architektura referencyjna
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
Brama musi wiedzieć, który nazwany operator dotarł do którego nazwanego urządzenia. Węzeł terenowy potrzebuje jedynie poświadczenia urządzenia na potrzeby rendezvous. Nigdy nie poznaje źródłowego adresu ani sekretu uwierzytelniającego operatora, a operator nigdy nie kopiuje do niego prywatnego klucza zarządzania. Ogranicza to możliwe do odzyskania powiązanie osobowe **z pamięci masowej urządzenia terenowego**, bez niszczenia rozliczalności ćwiczenia.

W przypadku większej floty system workload identity może wystawiać krótkotrwałe tożsamości X.509 i automatycznie rotować klucze. SPIFFE zaleca używanie X.509 SVID tam, gdzie to możliwe, oraz opisuje krótkie okresy ważności i częstą rotację jako metody ograniczania ekspozycji wynikającej z kompromitacji klucza.<sup>[[2]](#references)</sup> Mały zespół może zastosować te same właściwości za pomocą prywatnego CA i zautomatyzowanych certyfikatów dla poszczególnych urządzeń; instalowanie SPIRE nie jest wymagane wyłącznie po to, aby spełnić ten wzorzec.

## Krok 1: autoryzacja i rejestracja rozmieszczenia

1. Zapisz właściciela, lokalizację, dokładną dozwoloną strefę rozmieszczenia, dozwolone sieci, okno oceny, dozwolone miejsca docelowe/działania oraz kontakty awaryjne.
2. Zapisz model, numer seryjny, numer seryjny pamięci masowej, przewodowe/bezprzewodowe adresy MAC, IMEI modemu/eSIM lub ICCID karty SIM, zasilacz oraz aktualne zdjęcie.
3. Nadaj urządzeniu nieosobisty identyfikator zaangażowania, na przykład `E2026-014-DROP03`. Nie umieszczaj nazwy klienta w rozgłaszanych nazwach hostów ani SSID.
4. Poinformuj kontrolera ćwiczenia oraz najmniejszą niezbędną grupę odpowiedzialną za bezpieczeństwo fizyczne/SOC, co w ramach tego testu oznaczają pojęcia „zgubione”, „przemieszczone” i „odnalezione”.
5. Ustal z wyprzedzeniem, kto może je odebrać oraz w jaki sposób znalazca może to zgłosić. Etykieta bezpieczeństwa może pomijać poufne informacje o kliencie, jednocześnie podając kontrolowany numer kontaktowy.
6. Ustaw automatyczny termin wygaśnięcia autoryzacji. Dalsza łączność po zakończeniu zakresu nie może przedłużać uprawnień.

## Krok 2: budowa minimalnego obrazu możliwego do odzyskania

Użyj obsługiwanego obrazu systemu operacyjnego, zweryfikuj jego podpis/sumę kontrolną za pośrednictwem udokumentowanego kanału dostawcy, zainstaluj aktualizacje bezpieczeństwa i zachowaj odtwarzalny manifest kompilacji. Preferuj bazę tylko do odczytu lub immutable z niewielką zapisywalną partycją danych, jeśli oprogramowanie na to pozwala.

1. Usuń domyślne konta, usługi demonstracyjne, kompilatory i pakiety niepotrzebne dla autoryzowanego obciążenia.
2. Wyłącz lokalny GUI, Bluetooth, protokoły wykrywania, udostępnianie plików, Wi-Fi P2P oraz administrację przychodzącą, chyba że ćwiczenie wyraźnie wymaga któregoś z tych elementów.
3. Włącz secure boot oraz measured boot/zwalnianie kluczy oparte na TPM, jeśli sprzęt rzeczywiście je obsługuje; nie twierdź, że konfiguracja Raspberry Pi zapewnia measured boot klasy PC bez zweryfikowania dokładnego modelu.
4. Szyfruj lokalny stan zapisywalny i skonfiguruj ścisły maksymalny rozmiar oraz czas przechowywania. Szyfrowanie jest mechanizmem opóźniania/ograniczania skutków, a nie dowodem, że uruchomiony węzeł niczego nie ujawnia.
5. Wysyłaj ważne logi poza urządzenie. Ogranicz lokalne dzienniki, aby zapobiec wyczerpaniu pamięci masowej, ale nie konfiguruj czyszczenia logów ani usuwania anti-forensic.
6. Przechowuj manifest obrazu, wersje pakietów, hash konfiguracji oraz instrukcje odzyskiwania u kontrolera.
7. Odtwórz obraz zapasowego urządzenia na podstawie manifestu i uruchom ten sam test kondycji. Projekt, który może odzyskać wyłącznie jego twórca, nie jest gotowy do użycia w terenie.

## Krok 3: wydawanie tożsamości z jednokierunkowym zaufaniem

Utwórz trzy różne tożsamości:

- **tożsamość urządzenia**, akceptowaną wyłącznie przez rendezvous dla tego urządzenia;
- **tożsamość operatora**, akceptowaną przez bramę organizacji i chronioną za pomocą phishing-resistant MFA; oraz
- **tożsamość kontrolera/wdrożenia**, używaną do podpisywania zatwierdzonych zadań lub konfiguracji, przechowywaną poza operatorem i węzłem terenowym.

Węzeł powinien posiadać klucz publiczny potrzebny do weryfikowania podpisanych zadań, ale nigdy klucz podpisujący. Przechwycone poświadczenie urządzenia nie może służyć do uwierzytelniania w cloud consoles, source repositories, payment accounts, innych węzłach ani środowisku produkcyjnym klienta.

Używaj krótkich okresów ważności certyfikatów, jeśli automatyczne odnawianie jest niezawodne. Gdy długotrwały klucz WireGuard jest konieczny z powodów operacyjnych, traktuj jego klucz publiczny jako uchwyt unieważnienia i ograniczaj go za pomocą adresu tunelu przypisanego do konkretnego peera, polityki firewall oraz autoryzacji brokera. Utrzymuj przetestowaną akcję kontrolera, która natychmiast usuwa tego peera.

## Krok 4: stabilny outbound rendezvous

Poniższy wzorzec dla posiadanego laboratorium zapewnia stabilne zarządzanie przez NAT bez wystawiania usługi przychodzącej. Jest to zwykła sieć WireGuard, a nie ukryty reverse shell. Używaj adresów dokumentacyjnych i zastępuj je wyłącznie endpointami należącymi do organizacji.

W rendezvous organizacji przypisz `10.77.0.1/32`; węzłowi terenowemu przypisz `10.77.0.20/32`. Wpis peera bramy powinien akceptować wyłącznie pojedynczy adres węzła:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Węzeł nawiązuje połączenie wychodzące z rendezvous i utrzymuje mapowanie NAT tylko wtedy, gdy jest to wymagane:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard dokumentuje 25 sekund jako rozsądny interwał keepalive w wielu implementacjach NAT/firewall, gdy wymagana jest trwałość połączenia; pozostawienie tej funkcji wyłączonej jest preferowane, gdy nie jest potrzebna.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` celowo tworzy ścieżkę zarządzania, a nie pivot z użyciem trasy domyślnej.

Następnie zastosuj controls poza WireGuard:

1. Rozwiązuj `vpn.redteam.example` przez zatwierdzoną ścieżkę bootstrap DNS i przypisz oczekiwany endpoint organizacji w rekordach wdrożenia.
2. Na node zezwól na wychodzący DHCP/RA, wymagane DNS/NTP, endpoint rendezvous oraz minimalną zatwierdzoną ścieżkę aktualizacji. Odrzucaj niezamówiony ruch przychodzący na każdym uplinku.
3. Na rendezvous zezwól, aby `10.77.0.20` docierał wyłącznie do brokera/usługi health wymaganej podczas ćwiczenia. Nie przekazuj go ogólnie do client network.
4. Umieść interaktywny dostęp operatora za organization gateway. Unikaj udostępniania SSH z node przez tunnel, jeśli podpisany interfejs pull-job spełnia wymagania assessment.
5. Skonfiguruj service manager tak, aby uruchamiał tunnel po uruchomieniu networkingu, restartował go po awarii z ograniczonym backoffem i wysyłał alert po wielokrotnych awariach. Pętla restartów nie może przeciążać venue ani ukrywać podstawowego problemu.
6. Weryfikuj latest handshake peer, ale nie traktuj „handshake istnieje” jako dowodu, że device nie został skompromitowany.

TURN może zapewnić dostępność wyłącznie przez relay dla purpose-built WebRTC control plane, a message queue może tolerować okresowe przerwy w działaniu usługi. TURN jawnie zapewnia client publiczny adres relay za NAT; jego server pozostaje obserwatorem.<sup>[[4]](#references)</sup> Wybierz jedną architekturę control zamiast łączenia tunnelów bez określonej korzyści obserwacyjnej lub niezawodności.

## Krok 5: stabilność uplinku bez osobistych łączy

Dla autoryzowanego venue node preferuj następującą kolejność:

1. przewodowe łącze dostarczone przez clienta lub dedykowany test VLAN;
2. zatwierdzony przez właściciela profil enterprise/guest Wi-Fi;
3. zakontraktowany przez organizację fallback cellular/prywatny APN.

Nigdy nie konfiguruj personal phone hotspot, domowego SSID, personal eSIM, personal Apple/Google account ani profilu Wi-Fi wyeksportowanego z codziennego laptopa. To dokładnie te artifacts, z którymi połączy się capture.

Dla każdego zatwierdzonego uplinku:

- zapisz SSID/BSSID lub switch/VLAN oraz oczekiwane zachowanie captive portalu;
- ustaw deterministyczny priorytet i health check do kontrolowanego endpointu;
- zapewnij, aby failover zmieniał wyłącznie underlay; tożsamości device i operatora pozostają przy brokerze;
- upewnij się, że DNS, IPv6 i application traffic nie omijają rendezvous podczas przełączania;
- wysyłaj alert przy nieznanym SSID/BSSID, zmianie SIM, nowym default gateway, zmianie public IP/ASN lub jednoczesnych uplinkach;
- przed deployment przetestuj utratę zasilania, odnowienie DHCP, restart AP, zmianę public IP, 24-godzinną bezczynność, utratę tunnel oraz odzyskiwanie primary-to-secondary-to-primary.

Prywatne adresowanie MAC może ograniczyć przypadkowe śledzenie między networkami, ale stabilny MAC przypisany do network jest często wymagany przez autoryzowany NAC. Zapisz, jak faktycznie działa wybrany OS, i nie zmieniaj adresu w celu obejścia access control właściciela.

## Krok 6: ogranicz zakres pracy i danych

Bezpieczny field node nie powinien przyjmować dowolnego tekstu shell z mailboxa. Zdefiniuj podpisane typy jobów, takie jak `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` lub inne działanie wyraźnie wymienione w rules of engagement. Ponownie zweryfikuj destination, duration, rate, output size i scope na node.

1. Nadaj każdemu jobowi unikalny ID, device audience, issue time, expiry, scope reference i maximum output.
2. Podpisz go tożsamością controller/deployment.
3. Odrzucaj nieznane pola, wygasłe lub powtórnie użyte joby oraz joby przeznaczone dla innego device.
4. Strumieniuj wyniki do kontrolowanego collectora; zaszyfruj i ustaw TTL dla każdego nieuniknionego lokalnego spool.
5. Loguj w controllerze zaakceptowany/odrzucony job ID i hash wyniku. Nie umieszczaj w publicznym kanale monitoringu wrażliwych parametrów command.
6. Przerwij przetwarzanie po wygaśnięciu autoryzacji, nieudanej rotacji identity lub oznaczeniu device jako quarantined przez controller.

## Monitoring pod kątem wykrycia, utraty lub kompromitacji

Monitoring może poinformować controller, że zaobserwowany stan uległ zmianie. Nie może wiarygodnie potwierdzić, że „investigators znaleźli device”, a próby monitorowania responders lub sondowania ich systemów wykraczałyby poza autoryzowany assessment.

### Zbieraj stan poza device

Wysyłaj do controller podpisany, niskowolumenowy rekord health w losowym, ale ograniczonym przedziale operacyjnym. Uwzględniaj wyłącznie dane potrzebne controllerowi:

- device ID, boot ID/counter i monotonic uptime;
- hash konfiguracji/image oraz software version;
- serial device-certificate i stan odnowienia;
- uplink class, interface, BSSID lub switch context, jeśli autoryzowane, hash default gateway oraz public IP/ASN zaobserwowane przez kontrolowaną usługę;
- wiek tunnel handshake, packet counters i queue depth;
- stan enclosure switch lub hardware-tamper, jeśli właściciel zatwierdził sensor;
- disk pressure, temperature, szacowane clock offset i ID ostatniego pomyślnego joba;
- sequence number i signature ujawniające replay lub luki.

Centralnie przechowuj authentication gateway, decyzje policy, dostęp operatora, submission jobów, hashe wyników, provider audit events i alerty. CISA zaleca centralizowanie logów, ochronę przed usunięciem, ustalenie baseline normalnej aktywności oraz wyznaczenie kontaktów incident-response.<sup>[[5]](#references)</sup>

### Wskaźniki wykrycia/kompromitacji

| Sygnał | Możliwe wyjaśnienia | Działanie controller |
|---|---|---|
| Brak heartbeat | awaria zasilania/network, zmiana portalu, uszkodzenie, celowe blokowanie lub usunięcie | potwierdź stan providera/site; nie łącz ponownie przez niezatwierdzoną ścieżkę |
| Nieoczekiwana zmiana boot counter | odcięcie zasilania, crash, usunięcie lub maintenance | quarantine jobów; porównaj czas i zdarzenia site |
| Zmiana config/image hash | błąd aktualizacji, awaria storage lub tampering | zatrzymaj pracę; revoke, jeśli nie jest to release zatwierdzony przez controller |
| Nowy uplink/BSSID/gateway/ASN | wymiana AP, roaming, przeniesienie device lub interception | porównaj z zatwierdzonym inventory; quarantine niewyjaśnionej zmiany |
| Wielokrotnie odrzucony job/signature | corruption, replay lub unauthorized controller | zatrzymaj processing i zbadaj logi gateway/controller |
| Device credential użyty dwukrotnie lub z niezgodnych ścieżek | cloned key, ponowne użycie snapshotu lub zmiana network | natychmiast revoke; zachowaj oba rekordy sesji |
| Nieoczekiwany local login, interface, process lub privilege event | maintenance lub compromise | odizoluj przez broker policy; zachowaj evidence |
| Przejście stanu enclosure switch | service, przemieszczenie lub wykrycie | powiadom wskazany site contact; nie uruchamiaj destructive action |
| Provider abuse notice/account query lub SOC alert | detection, misconfiguration lub traffic poza scope | zatrzymaj aktywność i uruchom proces deconfliction/incident |
| Użycie sentinel credential | ktoś odczytał pozbawiony uprawnień decoy secret unikalny dla tego node | revoke real device identity i zachowaj ślad alertu |

Sentinel credential musi zapewniać **brak dostępu**, wywoływać wyłącznie należącą do organizacji usługę alertów i być ujawniony w rules of engagement. Jest tripwire’em wykrywającym nieautoryzowany odczyt, a nie beaconem do śledzenia osoby, która znalazła equipment.

### Progi alertów

Używaj reguł stanowych, a nie jednego dramatycznego alarmu „caught”:

- **warning:** jeden pominięty interwał, normalna zmiana adresu lub wzrost kolejki;
- **degraded:** trzy kolejne pominięcia, opóźnienie renewal, utrata primary uplink lub repeated restart;
- **quarantine:** niezatwierdzona zmiana hash/boot/uplink, duplicate credential, użycie sentinel lub nieoczekiwane privileged event;
- **confirmed discovery/loss:** raport site/controller, niezgodność physical inventory, odzyskanie device przez nieplanowaną osobę lub potwierdzona eskalacja providera/SOC.

Testuj dostarczanie alertów przez kanał niezależny od field node. Unikaj wysyłania wrażliwych danych client/device do personal messaging lub consumer push accounts.

## Runbook dla podejrzenia wykrycia lub capture

1. **Stop:** wstrzymaj nowe joby i sesje operatorów. Nie wysyłaj sondy „sprawdź, czy jesteśmy obserwowani”.
2. **Quarantine:** ustaw broker tak, aby odrzucał device identity i jej routes, zachowując istniejące logi.
3. **Revoke:** revoke device certificate/key, queue token, update credential i każdy single-purpose service token. Zawieś SIM organizacji, jeśli prawdopodobna jest fizyczna utrata.
4. **Preserve:** wykonaj snapshot rekordów controller, gateway, provider i alert; zapisz trusted time, osobę wykonującą działanie oraz ostatnią znaną konfigurację. Nie czyść ani nie wykonuj remote wipe node.
5. **Notify:** skontaktuj się z exercise controller, client incident contact oraz wskazanymi w autoryzacji kontaktami legal/privacy. Jeśli znalazła go strona trzecia, użyj wcześniej uzgodnionego procesu recovery.
6. **Assess:** załóż, że każdy secret i cached result na node został ujawniony. Dokładnie określ, do czego mógł służyć każdy secret i czy został użyty po podejrzanym zdarzeniu.
7. **Contain downstream:** zmień dane uwierzytelniające dotkniętych usług, unieważnij oczekujące joby i sprawdź logi należących do organizacji targetów/providerów pod kątem nieoczekiwanego działania.
8. **Recover safely:** odzyskaj device wyłącznie przez autoryzowaną osobę; sfotografuj i zapakuj go, zapisz chain of custody oraz pozyskaj forensic evidence zgodnie z instrukcjami clienta.
9. **Resume with a new identity:** nigdy po cichu nie włączaj ponownie przejętego credential. Odbuduj system z known manifest, napraw control failure i uzyskaj wyraźną zgodę.

Aktualne wytyczne NIST dotyczące incident-response integrują preparation, detection, response i recovery z zarządzaniem ryzykiem cyberbezpieczeństwa w całej organizacji; najpierw zachowaj dane, aby client mógł ustalić, co się stało, i wybrać odpowiednią reakcję.<sup>[[6]](#references)</sup>

## Capture drill przed deployment

Przekaż odblokowane urządzenie testowe lub kopię jego storage niezależnemu reviewerowi i poproś go o wyliczenie:

1. identyfikatorów device/site/engagement;
2. nazw operatorów, personal accounts, home/workstation networks i recovery contacts;
3. destinations i credentials controller/broker;
4. client network profiles i cached results;
5. innych devices/projects osiągalnych przy użyciu każdego secret;
6. credentials o wartości lub związanych z płatnościami;
7. tego, co controller może revoke i jak szybko;
8. tego, jaka aktywność pozostaje możliwa do przypisania na podstawie central logs.

Kryteria zaliczenia: zero personal accounts/workstation keys; zero cross-engagement lub enrollment authority; brak payment credential; ograniczony encrypted cache; jedno udokumentowane device-revocation action; pełna accountability po stronie controller. Każde nieoczekiwane osobiste powiązanie lub lateral capability traktuj jako release blocker.

## Zamknięcie

1. Zatrzymaj joby i wyłącz broker route po zakończeniu scope.
2. Odzyskaj i uzgodnij dokładny inventory; zgłoś wszystko, czego brakuje.
3. Zachowaj logs/results oraz, jeśli wymagane, forensic image zgodnie z engagement retention plan.
4. Revoke device, SIM, queue, update i service identities, nawet jeśli hardware odzyskano.
5. Dopiero po preservation/acceptance wyczyść lub zniszcz media zgodnie z zatwierdzonym przez właściciela procesem data disposal i zapisz wykonanie. To lifecycle management, nie concealment.
6. Usuń venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules i tymczasowe kontakty.
7. Udokumentuj zaobserwowane detection, brakującą telemetry, time to quarantine oraz każdy artifact ujawniony przez capture.

## References

- [1] [NIST — Katalog możliwości cyberbezpieczeństwa urządzeń IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Koncepcje i krótkotrwałe tożsamości workloadów](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Używanie loggingu w systemach biznesowych](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Zalecenia i uwagi dotyczące Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
