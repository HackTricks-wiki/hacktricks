# Odporne na przejęcie autoryzowane węzły terenowe

Umieszczony na miejscu Raspberry Pi, mini-PC, travel router lub urządzenie komórkowe może zapewnić autoryzowanemu red teamowi trwały punkt dostępu. Jest jednak również prawdopodobnym celem wykrycia, kradzieży i identyfikacji. Właściwym celem projektowym jest zatem **stabilny, kontrolowany dostęp przy niewielkich uprawnieniach węzła terenowego**, a nie nieidentyfikowalny implant.

Niniejszy przewodnik dotyczy wyłącznie sprzętu umieszczonego za pisemną zgodą właściciela obiektu. Kawiarnia, sąsiad, hotel lub współdzielony budynek nie są objęte zakresem tylko dlatego, że ich sieć jest osiągalna. Nie ukrywaj sprzętu w miejscu, którego właściciel nie wyraził zgody, nie omijaj captive portalu, nie używaj danych uwierzytelniających innej osoby, nie ingeruj w monitoring ani nie próbuj usuwać dowodów po wykryciu.

{% hint style="warning" %}
Nie istnieje niezawodne ustawienie „nie pozostawiaj śladów”. Informacje o asocjacji radiowej, DHCP/NAT, operatorze, kamerach, zakupie, urządzeniu, dostawcy, kontrolerze i miejscach docelowych mogą przetrwać po usunięciu urządzenia. Odpowiedzialny red team usuwa z węzła **osobiste i niezwiązane z zadaniem sekrety**, zachowuje chronione informacje umożliwiające identyfikację po stronie kontrolera i projektuje rozwiązanie tak, aby przejęcie było łatwe do opanowania.
{% endhint %}

## Zalety i wady

**Zalety:** realistyczne źródło wewnętrzne lub zlokalizowane w pobliżu celu; stabilne testy z dużą szybkością; weryfikacja NAC, egress, inwentaryzacji fizycznej i pokrycia SOC; możliwość działania mimo zmian adresu operatora; ograniczony dostęp można centralnie odwołać.

**Wady:** fizyczne umieszczenie tworzy silne dowody; utrata urządzenia może ujawnić dane uwierzytelniające urządzenia, profile sieciowe i zebrane dane; powtarzalny ruch sterujący jest wykrywalny; zmiany zasilania, portali i sieci radiowych pogarszają niezawodność; szeroki tunel może stać się niekontrolowanym punktem pivot.

## Model zagrożeń i niezmienniki projektowe

Załóż, że znalazca może wyjąć pamięć masową, przeanalizować firmware, skopiować każdy sekret przechowywany przez oprogramowanie, obserwować późniejsze zachowanie sieci oraz przekazać urządzenie klientowi lub organom ścigania. Szyfrowanie całego dysku chroni wyłączone urządzenie wyłącznie w ramach określonego modelu zagrożeń; działający, odblokowany węzeł i klucze zwolnione do pamięci to odrębne przypadki.

| Niezmiennik | Praktyczna konsekwencja |
|---|---|
| Brak bezpośredniej tożsamości operatora względem węzła | Operator loguje się do firmowego gatewaya; węzeł ma odrębną tożsamość urządzenia |
| Brak materiałów z osobistej stacji roboczej | Brak osobistego klucza SSH, profilu przeglądarki, poczty e-mail, menedżera haseł, parowania z telefonem lub cache CLI chmury |
| Brak głównego sekretu kontrolera | Jeden węzeł nie może rejestrować innego, zmieniać polityki ani odszyfrowywać innych zadań |
| Tylko połączenia wychodzące i wąski zakres | Sieć terenowa nie akceptuje listenera zarządzania; węzeł łączy się wyłącznie z nazwanymi usługami rendezvous, aktualizacji i czasu |
| Krótkotrwałe uprawnienia o ograniczonym zakresie | Każde poświadczenie dotyczy jednego urządzenia, odbiorcy, usługi i terminu ważności oraz ma natychmiastową ścieżkę odwołania |
| Minimalna ilość danych lokalnych | Wyniki są przesyłane strumieniowo do kontrolera; cache jest szyfrowany, a jego rozmiar i TTL są ograniczone oraz nie ma on charakteru nadrzędnego |
| Odpowiedzialność kontrolera przetrwa przejęcie | Mapowanie zasobu na zadanie, zatwierdzenia, dostęp operatorów i polecenia są przechowywane centralnie, z kontrolą dostępu |
| Utrata zatrzymuje działanie | Wykrycie lub niewyjaśniona zmiana stanu uruchamia zatrzymanie, odwołanie uprawnień, powiadomienie i zachowanie dowodów — nie zdalne niszczenie |

Bazowy model IoT firmy NIST grupuje identyfikację urządzenia, konfigurację, ochronę danych, dostęp logiczny, bezpieczne aktualizacje oprogramowania oraz świadomość stanu cyberbezpieczeństwa jako podstawowe możliwości. W szczególności uznaje świadomość stanu i rejestry zdarzeń przechowywane poza urządzeniem za wsparcie w badaniu kompromitacji.<sup>[[1]](#references)</sup>

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
Brama musi wiedzieć, który nazwany operator dotarł do którego nazwanego urządzenia. Węzeł terenowy potrzebuje jedynie poświadczenia urządzenia na potrzeby rendezvous. Nigdy nie poznaje źródłowego adresu ani sekretu uwierzytelniającego operatora, a operator nigdy nie kopiuje do niego prywatnego klucza zarządzania. Ogranicza to możliwe do odzyskania powiązanie z osobą **z pamięci masowej węzła terenowego**, nie niszcząc rozliczalności ćwiczenia.

W przypadku większej floty system workload identity może wydawać krótkotrwałe tożsamości X.509 i automatycznie rotować klucze. SPIFFE zaleca używanie X.509 SVID, gdy jest to możliwe, oraz opisuje krótkie okresy ważności i częstą rotację jako sposoby ograniczania ekspozycji wynikającej z kompromitacji klucza.<sup>[[2]](#references)</sup> Mały zespół może zastosować te same właściwości przy użyciu prywatnego CA i automatycznych certyfikatów dla poszczególnych urządzeń; instalowanie SPIRE nie jest wymagane tylko po to, aby spełnić ten wzorzec.

## Krok 1: autoryzacja i rejestracja rozmieszczenia

1. Zapisz właściciela, lokalizację, dokładnie dozwoloną strefę rozmieszczenia, dozwolone sieci, okno oceny, dozwolone miejsca docelowe/działania oraz kontakty awaryjne.
2. Zapisz model, numer seryjny, numer seryjny pamięci masowej, przewodowe/bezprzewodowe adresy MAC, IMEI modemu/eSIM lub ICCID karty SIM, zasilacz oraz aktualne zdjęcie.
3. Nadaj urządzeniu niezwiązaną z osobą identyfikację zaangażowania, na przykład `E2026-014-DROP03`. Nie umieszczaj nazwy klienta w rozgłaszanych nazwach hostów ani SSID.
4. Poinformuj kontrolera ćwiczenia oraz najmniejszą niezbędną grupę odpowiedzialną za bezpieczeństwo fizyczne/SOC, co w ramach tego testu oznaczają stany „zgubione”, „przeniesione” i „odnalezione”.
5. Ustal z wyprzedzeniem, kto może je odebrać oraz jak znalazca może to zgłosić. Etykieta bezpieczeństwa może pomijać poufne informacje o kliencie, jednocześnie udostępniając kontrolowany kontakt zwrotny.
6. Ustaw automatyczne wygaśnięcie autoryzacji. Dalsza łączność po zakończeniu zakresu nie może przedłużać uprawnień.

## Krok 2: utworzenie minimalnego obrazu możliwego do odzyskania

Użyj obsługiwanego obrazu systemu operacyjnego, zweryfikuj jego podpis/sumę kontrolną za pośrednictwem udokumentowanego kanału dostawcy, zainstaluj aktualizacje bezpieczeństwa i zachowaj odtwarzalny manifest kompilacji. Jeśli oprogramowanie na to pozwala, preferuj bazę tylko do odczytu lub immutable z małą zapisywalną partycją danych.

1. Usuń domyślne konta, usługi demonstracyjne, kompilatory i pakiety, które nie są potrzebne do autoryzowanego workload.
2. Wyłącz lokalny GUI, Bluetooth, protokoły wykrywania, udostępnianie plików, Wi-Fi P2P i administrację przychodzącą, chyba że ćwiczenie wyraźnie wymaga któregoś z tych elementów.
3. Włącz secure boot i measured boot/zwalnianie klucza oparte na TPM, jeśli sprzęt rzeczywiście je obsługuje; nie twierdź, że konfiguracja Raspberry Pi zapewnia measured boot klasy PC bez zweryfikowania dokładnego modelu.
4. Zaszyfruj lokalny stan zapisywalny oraz skonfiguruj ścisły maksymalny rozmiar i czas retencji. Szyfrowanie jest mechanizmem opóźniania/ograniczania skutków, a nie dowodem, że uruchomiony węzeł niczego nie ujawnia.
5. Wysyłaj ważne logi poza urządzenie. Ogranicz lokalne dzienniki, aby zapobiec wyczerpaniu pamięci masowej, ale nie konfiguruj czyszczenia logów ani usuwania antyforensic.
6. Przechowuj manifest obrazu, wersje pakietów, hash konfiguracji oraz instrukcje odzyskiwania u kontrolera.
7. Odtwórz obraz na urządzeniu zapasowym na podstawie manifestu i uruchom ten sam test sprawności. Projekt, który może odzyskać wyłącznie jego twórca, nie jest gotowy do użycia w terenie.

## Krok 3: wydawanie tożsamości z jednokierunkowym zaufaniem

Utwórz trzy różne tożsamości:

- **tożsamość urządzenia**, akceptowaną wyłącznie przez rendezvous dla tego urządzenia;
- **tożsamość operatora**, akceptowaną przez bramę organizacji i chronioną za pomocą odpornego na phishing MFA; oraz
- **tożsamość kontrolera/wdrożenia**, używaną do podpisywania zatwierdzonych zadań lub konfiguracji, przechowywaną poza operatorem i węzłem terenowym.

Węzeł powinien mieć klucz publiczny potrzebny do weryfikowania podpisanych zadań, nigdy klucz podpisujący. Przechwycone poświadczenie urządzenia nie może służyć do uwierzytelniania w cloud consoles, source repositories, kontach płatniczych, innych węzłach ani środowisku produkcyjnym klienta.

Używaj krótkich okresów ważności certyfikatów, jeśli automatyczne odnawianie jest niezawodne. Gdy długotrwały klucz WireGuard jest konieczny z przyczyn operacyjnych, traktuj jego klucz publiczny jako uchwyt revocation i ograniczaj go za pomocą adresu tunelu przypisanego do peera, polityki firewalla oraz autoryzacji brokera. Zachowaj przetestowaną akcję kontrolera, która natychmiast usuwa tego peera.

## Krok 4: stabilny outbound rendezvous

Poniższy wzorzec z własnego labu zapewnia stabilne zarządzanie przez NAT bez wystawiania usługi inbound. Jest to zwykła sieć WireGuard, a nie covert reverse shell. Używaj adresów dokumentacyjnych i zastępuj je wyłącznie endpointami należącymi do organizacji.

W organizacyjnym rendezvous przypisz `10.77.0.1/32`; węzłowi terenowemu przypisz `10.77.0.20/32`. Wpis peera bramy powinien akceptować wyłącznie pojedynczy adres węzła:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Węzeł nawiązuje połączenie wychodzące z punktem rendezvous i utrzymuje mapowanie NAT tylko wtedy, gdy jest to wymagane:
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
WireGuard dokumentuje 25 sekund jako rozsądny interwał keepalive w wielu implementacjach NAT/firewall, gdy wymagana jest ciągła dostępność; gdy nie jest potrzebny, lepiej pozostawić go wyłączonego.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` celowo sprawia, że jest to ścieżka zarządzania, a nie pivot przez trasę domyślną.

Następnie zastosuj kontrole poza WireGuard:

1. Rozwiązuj `vpn.redteam.example` przez zatwierdzoną ścieżkę bootstrap DNS i przypisz oczekiwany endpoint organizacji w rekordach wdrożenia.
2. Na węźle zezwól na wychodzący DHCP/RA, wymagane DNS/NTP, endpoint rendezvous oraz minimalną zatwierdzoną ścieżkę aktualizacji. Odrzucaj niezamówiony ruch przychodzący na każdym uplinku.
3. Na rendezvous zezwól `10.77.0.20` na dostęp wyłącznie do brokera/usługi health wymaganej podczas ćwiczenia. Nie przekazuj go ogólnie do sieci klienta.
4. Umieść interaktywny dostęp operatora za gatewayem organizacji. Unikaj udostępniania SSH z węzła przez tunnel, jeśli podpisany interfejs pull-job spełnia wymagania assessmentu.
5. Skonfiguruj service manager tak, aby uruchamiał tunnel po uzyskaniu łączności sieciowej, restartował go po awarii z ograniczonym backoffem i generował alert po powtarzających się awariach. Pętla restartów nie może przeciążać infrastruktury obiektu ani ukrywać przyczyny problemu.
6. Weryfikuj latest handshake peera, ale nie traktuj „istnieje handshake” jako dowodu, że urządzenie nie zostało skompromitowane.

TURN może zapewnić dostępność wyłącznie przez relay dla specjalnie zaprojektowanego control plane WebRTC, a message queue może tolerować okresowe przerwy w działaniu usługi. TURN jawnie przekazuje klientowi publiczny adres relay za NAT; jego serwer pozostaje obserwatorem.<sup>[[4]](#references)</sup> Wybierz jedną architekturę kontroli zamiast nakładania tunnelów bez określonego obserwatora lub uzasadnionej korzyści z niezawodności.

## Step 5: stabilność uplinku bez osobistych linków

Dla autoryzowanego węzła obiektowego preferuj następującą kolejność:

1. przewodowa sieć dostarczona przez klienta lub dedykowany VLAN testowy;
2. zatwierdzony przez właściciela profil enterprise/guest Wi-Fi;
3. zakontraktowany przez organizację fallback cellular/prywatny APN.

Nigdy nie konfiguruj osobistego hotspotu telefonu, domowego SSID, osobistego eSIM, osobistego konta Apple/Google ani profilu Wi-Fi wyeksportowanego z codziennego laptopa. To właśnie te artefakty zostaną powiązane z przechwyconym urządzeniem.

Dla każdego zatwierdzonego uplinku:

- zapisz SSID/BSSID albo switch/VLAN oraz oczekiwane zachowanie captive portalu;
- ustaw deterministyczny priorytet i health check do własnego endpointu;
- dopilnuj, aby failover zmieniał wyłącznie underlay; tożsamości urządzenia i operatora pozostają przy brokerze;
- upewnij się, że DNS, IPv6 i ruch aplikacyjny nie omijają rendezvous podczas przełączania;
- generuj alert przy nieznanym SSID/BSSID, zmianie SIM, nowym gatewayu domyślnym, zmianie publicznego IP/ASN lub jednoczesnych uplinkach;
- przed wdrożeniem przetestuj utratę zasilania, odnowienie DHCP, restart AP, zmianę publicznego IP, 24-godzinną bezczynność, utratę tunnelu oraz powrót primary-secondary-primary.

Prywatne adresowanie MAC może ograniczyć przypadkowe śledzenie między sieciami, ale stabilny MAC dla danej sieci jest często wymagany przez autoryzowany NAC. Zapisz, jak faktycznie działa wybrany OS, i nie zmieniaj adresu w sposób obchodzący kontrolę dostępu właściciela.

## Step 6: ograniczanie pracy i danych

Bezpieczny węzeł obiektowy nie powinien przyjmować dowolnego tekstu shell z mailboxa. Zdefiniuj podpisane typy jobów, takie jak `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` lub inną akcję wyraźnie określoną w rules of engagement. Ponownie zweryfikuj na węźle cel, czas trwania, rate, rozmiar danych wyjściowych i zakres.

1. Nadaj każdemu jobowi unikalny ID, odbiorców urządzenia, czas wystawienia, termin wygaśnięcia, odwołanie do zakresu i maksymalny rozmiar danych wyjściowych.
2. Podpisz go tożsamością kontrolera/wdrożenia.
3. Odrzucaj nieznane pola, wygasłe lub ponownie użyte joby oraz joby przeznaczone dla innego urządzenia.
4. Strumieniuj wyniki do własnego collectora; szyfruj i stosuj TTL dla każdego nieuniknionego lokalnego spoola.
5. Rejestruj w kontrolerze zaakceptowany/odrzucony ID joba i hash wyniku. Nie umieszczaj wrażliwych parametrów komend w publicznym kanale monitoringu.
6. Przerwij przetwarzanie po wygaśnięciu autoryzacji, nieudanej rotacji tożsamości lub oznaczeniu urządzenia jako quarantined przez kontroler.

## Monitoring pod kątem wykrycia, utraty lub kompromitacji

Monitoring może poinformować kontroler, że zaobserwowany stan się zmienił. Nie może wiarygodnie potwierdzić, że „śledczy znaleźli urządzenie”, a próby inwigilowania responderów lub sondowania ich systemów wykraczałyby poza autoryzowany assessment.

### Zbieraj stan poza urządzeniem

Wysyłaj do kontrolera podpisany, niskowolumenowy rekord health w losowym, ale ograniczonym operacyjnie interwale. Uwzględniaj wyłącznie informacje potrzebne kontrolerowi:

- ID urządzenia, boot ID/licznik i monotoniczny uptime;
- hash konfiguracji/image i wersję software;
- numer seryjny certyfikatu urządzenia oraz stan odnowienia;
- klasę uplinku, interfejs, BSSID lub kontekst switcha zgodnie z autoryzacją, hash gatewaya domyślnego oraz publiczny IP/ASN zaobserwowany przez własną usługę;
- wiek handshake tunnelu, liczniki pakietów i długość kolejki;
- stan switcha obudowy lub hardware-tamper, jeśli właściciel zatwierdził sensor;
- obciążenie dysku, temperaturę, szacowane odchylenie zegara i ID ostatniego pomyślnego joba;
- numer sekwencyjny i podpis ujawniające replay lub luki.

Centralnie przechowuj authentication gatewaya, decyzje policy, dostęp operatora, przesyłanie jobów, hashe wyników, zdarzenia audytowe providera i alerty. CISA zaleca centralizowanie logów, ochronę przed usunięciem, wyznaczanie baseline'u normalnej aktywności oraz wskazanie kontaktów incident response.<sup>[[5]](#references)</sup>

### Wskaźniki wykrycia/kompromitacji

| Sygnał | Możliwe wyjaśnienia | Działanie kontrolera |
|---|---|---|
| Brak heartbeat | awaria zasilania/sieci, zmiana portalu, uszkodzenie, celowe blokowanie lub usunięcie | potwierdź stan u providera/obiektu; nie łącz ponownie przez niezatwierdzoną ścieżkę |
| Nieoczekiwana zmiana licznika bootów | odcięcie zasilania, crash, usunięcie lub maintenance | wstrzymaj joby; porównaj czas i zdarzenia w obiekcie |
| Zmieniony hash konfiguracji/image | błąd aktualizacji, awaria storage lub tampering | zatrzymaj pracę; revoke, jeśli nie jest to release zatwierdzony przez kontroler |
| Nowy uplink/BSSID/gateway/ASN | wymiana AP, roaming, przeniesienie urządzenia lub interception | porównaj z zatwierdzonym inventory; quarantine niewyjaśnionej zmiany |
| Powtarzające się odrzucone joby/podpisy | uszkodzenie, replay lub nieautoryzowany kontroler | zatrzymaj przetwarzanie i zbadaj logi gatewaya/kontrolera |
| Credential urządzenia użyty dwukrotnie lub z niezgodnych ścieżek | sklonowany key, ponowne użycie snapshotu lub zmiana sieci | natychmiast revoke; zachowaj oba rekordy sesji |
| Nieoczekiwany lokalny login, interfejs, proces lub zdarzenie privilege | maintenance lub kompromitacja | odizoluj przez policy brokera; zachowaj evidence |
| Zmiana stanu switcha obudowy | service, przemieszczenie lub wykrycie | powiadom wskazany kontakt obiektu; nie uruchamiaj destrukcyjnego działania |
| Zawiadomienie providera o abuse, zapytanie dotyczące konta lub alert SOC | wykrycie, błędna konfiguracja lub ruch poza zakresem | zatrzymaj aktywność i uruchom proces deconfliction/incident |
| Użycie sentinel credential | ktoś odczytał pozbawiony uprawnień decoy secret unikalny dla tego węzła | revoke prawdziwą tożsamość urządzenia i zachowaj ślad alertu |

Sentinel credential musi zapewniać **brak dostępu**, wywoływać wyłącznie należącą do organizacji usługę alertową i być ujawniony w rules of engagement. Jest tripwire'em wykrywającym nieautoryzowany odczyt, a nie beaconem do śledzenia osoby, która znalazła sprzęt.

### Progi alertów

Używaj reguł stanowych, a nie jednego dramatycznego alarmu „caught”:

- **warning:** jeden pominięty interwał, normalna zmiana adresu lub wzrost kolejki;
- **degraded:** trzy kolejne pominięcia, opóźnienie odnowienia, utrata primary uplinku lub powtarzający się restart;
- **quarantine:** niezatwierdzona zmiana hasha/boot/uplinku, zduplikowany credential, użycie sentinel lub nieoczekiwane zdarzenie uprzywilejowane;
- **confirmed discovery/loss:** raport obiektu/kontrolera, niezgodność inventory fizycznego, odzyskanie urządzenia przez nieplanowaną osobę lub zweryfikowana eskalacja providera/SOC.

Testuj dostarczanie alertów przez kanał niezależny od węzła obiektowego. Unikaj wysyłania wrażliwych danych klienta/urządzenia na osobiste komunikatory lub konta konsumenckie push.

## Runbook podejrzenia wykrycia lub przechwycenia

1. **Stop:** wstrzymaj nowe joby i sesje operatorów. Nie wysyłaj sondy „sprawdź, czy jesteś obserwowany”.
2. **Quarantine:** skonfiguruj brokera tak, aby odrzucał tożsamość urządzenia i jego routes, zachowując istniejące logi.
3. **Revoke:** revoke certyfikat/key urządzenia, token kolejki, credential aktualizacji i każdy single-purpose service token. Zawieś SIM organizacji, jeśli prawdopodobna jest fizyczna utrata.
4. **Preserve:** wykonaj snapshot rekordów kontrolera, gatewaya, providera i alertów; zapisz zaufany czas, osobę podejmującą działanie i ostatnią znaną konfigurację. Nie czyść ani nie zdalnie wipe'uj węzła.
5. **Notify:** skontaktuj się z kontrolerem ćwiczenia, kontaktem incident po stronie klienta oraz kontaktami prawnymi/privacy określonymi w autoryzacji. Jeśli znalazła je osoba trzecia, użyj wcześniej uzgodnionego procesu odzyskiwania.
6. **Assess:** załóż, że każdy secret i cached result na węźle jest ujawniony. Dokładnie określ, do czego każdy secret mógł zapewnić dostęp i czy został użyty po podejrzanym zdarzeniu.
7. **Contain downstream:** obróć dotknięte service credentials, unieważnij oczekujące joby i sprawdź logi własnych targetów/providerów pod kątem nieoczekiwanego zachowania.
8. **Recover safely:** odzyskaj urządzenie wyłącznie przez autoryzowaną osobę; sfotografuj i zapakuj je, zapisz chain of custody oraz pozyskaj forensic evidence zgodnie z instrukcjami klienta.
9. **Resume with a new identity:** nigdy po cichu nie włączaj ponownie przechwyconego credentiala. Odbuduj urządzenie ze znanego manifestu, napraw błąd kontroli i uzyskaj wyraźną zgodę.

Aktualne wytyczne NIST dotyczące incident response integrują przygotowanie, wykrywanie, reakcję i odzyskiwanie w ramach zarządzania ryzykiem cyberbezpieczeństwa całej organizacji; najpierw zachowaj dane, aby klient mógł ustalić, co się stało, i wybrać odpowiednią reakcję.<sup>[[6]](#references)</sup>

## Capture drill przed wdrożeniem

Przekaż odblokowane urządzenie testowe lub kopię jego storage osobnemu reviewerowi i poproś go o zinwentaryzowanie:

1. identyfikatorów urządzenia/obiektu/engagementu;
2. nazw operatorów, kont osobistych, sieci domowych/stacji roboczych i kontaktów recovery;
3. destynacji oraz credentiali kontrolera/brokera;
4. profili sieci klienta i cached results;
5. innych urządzeń/projektów dostępnych przy użyciu każdego secreta;
6. credentiali wartości lub płatności;
7. tego, co kontroler może revoke i jak szybko;
8. tego, jaka aktywność pozostaje przypisywalna na podstawie centralnych logów.

Kryteria zaliczenia: zero kont osobistych/kluczy stacji roboczych; zero uprawnień cross-engagement lub enrollment authority; brak credentiala płatniczego; ograniczony szyfrowany cache; jedna udokumentowana akcja device-revocation; pełna accountability po stronie kontrolera. Każdy nieoczekiwany osobisty link lub capability lateral traktuj jako blocker wydania.

## Zamknięcie

1. Zatrzymaj joby i wyłącz route brokera po zakończeniu zakresu.
2. Odzyskaj i uzgodnij dokładne inventory; zgłoś każdy brak.
3. Zachowaj logi/wyniki oraz, jeśli wymagane, forensic image zgodnie z planem retencji engagementu.
4. Revoke tożsamości urządzenia, SIM, kolejki, aktualizacji i usług, nawet jeśli sprzęt został odzyskany.
5. Dopiero po zachowaniu danych i akceptacji wyczyść lub zniszcz media zgodnie z zatwierdzonym przez właściciela procesem utylizacji danych i zapisz wykonanie. To zarządzanie cyklem życia, a nie concealment.
6. Usuń rezerwacje NAC/DHCP obiektu, routes brokera, DNS, role cloud, reguły alertów i tymczasowe kontakty.
7. Udokumentuj zaobserwowane wykrycie, brakującą telemetrię, czas do quarantine oraz każdy artefakt ujawniony przez capture.

## References

- [1] [NIST — Katalog możliwości cyberbezpieczeństwa urządzeń IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Koncepcje i krótkotrwałe tożsamości workloadów](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Używanie logowania w systemach biznesowych](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Zalecenia i uwagi dotyczące Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
