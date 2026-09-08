# Ukryty dostęp fizyczny i bezprzewodowy

{{#include ../banners/hacktricks-training.md}}

Szczegółową, zatwierdzoną przez właściciela implementację obejmującą outbound rendezvous, odzyskiwanie zasilania/uplink, minimalną liczbę sekretów przechowywanych na urządzeniu, testy przechwytywania oraz monitoring pod kątem możliwego wykrycia opisano w [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Zmiana ścieżki sieciowej może również zmienić pozorne źródło fizyczne. Zaawansowany aktor może użyć pobliskiego skompromitowanego systemu, ukrytego urządzenia, publicznego dostępu, cellular backhaul lub odbiornika satelitarnego, aby logi celu wskazywały miejsce oddalone od operatora. Żadne z tych rozwiązań nie usuwa dowodów fizycznych, radiowych ani pochodzących od providera; przenosi atrybucję do innych zbiorów danych.

## Macierz technik

| Technika | Pozorne źródło | Niezbędny warunek | Dowody o wysokiej wartości |
|---|---|---|---|
| Pobliskie wireless pivot | firma/dom obok celu | skompromitowany host dual-homed i dostęp do Wi-Fi celu | logi endpointu sąsiedniego hosta, skojarzenie RF oraz RADIUS/DHCP celu |
| Sieć publiczna/gościnna | NAT obiektu lub wyjście tunelu | zgodny z prawem dostęp lub obejście kontroli dostępu | captive portal, DHCP, skojarzenie z AP, CCTV oraz dane płatności/lokalizacji |
| Ukryte urządzenie podrzucone | adres przewodowy, Wi-Fi lub komórkowy celu/pobliskiego obiektu | fizyczne umieszczenie lub dostarczenie | switchport/USB, RF, inwentaryzacja, zasilanie oraz telemetryka outbound tunnel |
| Router komórkowy/eSIM | NAT operatora lub dedykowany APN | modem/SIM/subskrypcja | IMEI/IMSI/eSIM, sektor komórkowy, konto operatora oraz synchronizacja czasowa ruchu |
| Nadużycie łącza satelitarnego | adres subskrybenta w zasięgu wiązki | słabość specyficzna dla protokołu i usługi | lokalizacja RF, przepływ uplink, niemożliwe RTT/routing oraz rejestry providera |

## Nearest-neighbor attack

Volexity udokumentowało w 2022 roku operację APT28/GRU, w której aktor znajdował się zdalnie względem ostatecznego celu. Wykorzystał password spraying przeciwko publicznej usłudze celu, aby uzyskać prawidłowe dane uwierzytelniające, ale MFA uniemożliwiło bezpośrednie logowanie z Internetu. Korporacyjne Wi-Fi celu akceptowało te dane bez MFA. Aktor skompromitował organizacje znajdujące się fizycznie blisko celu, znalazł system dual-homed z zasięgiem bezprzewodowym i użył go do uwierzytelnienia się w Wi-Fi celu. Volexity nazwało tę technikę **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Nowatorstwo polega na kompozycji. Żaden operator nie przemieszcza się do celu, a MFA usługi wystawionej do Internetu nadal działa. Przejęty system sąsiada zapewnia fizyczną bliskość; skradzione dane uwierzytelniające celu zapewniają dostęp logiczny; docelowa sieć Wi-Fi staje się ścieżką przekraczania granicy.

### Warunki wstępne i widoczność

- Pobliskim systemem musi dać się zdalnie sterować, a także musi on mieć kompatybilne radio lub dostęp do innego pobliskiego pivota.
- Docelowy SSID musi docierać do tego systemu, a dopuszczenie do Wi-Fi musi akceptować wielokrotnie używalne dane uwierzytelniające, certyfikat lub stan urządzenia.
- Pivot często potrzebuje dwóch jednoczesnych ścieżek: jednej z powrotem do operatora i jednej do docelowej sieci WLAN.
- Cel może zobaczyć nowy adres MAC stacji i prawidłową nazwę użytkownika, ale bez odpowiadającego certyfikatu zarządzanego urządzenia, informacji o posture, historii lub oczekiwanego wejścia do budynku.
- Logi endpointu sąsiada mogą rejestrować skanowanie sieci bezprzewodowych, nowe profile, zmiany interfejsów, tunneling oraz aktywność związaną ze zdalnym sterowaniem.

### Wykrywanie i zapobieganie

1. Wymagaj EAP-TLS opartego na certyfikatach oraz posture zarządzanego urządzenia dla firmowego Wi-Fi; nie uznawaj hasła, które nie przeszło MFA w Internecie, za wystarczające tylko dlatego, że dociera drogą radiową.
2. Koreluj uwierzytelnianie RADIUS z tożsamością MDM/NAC, historycznym powiązaniem stacji z urządzeniem, lokalizacją AP, zdarzeniami dostępu fizycznego oraz równoczesnymi sesjami.
3. Generuj alert, gdy konto łączy się po raz pierwszy, z nietypowej krawędzi AP, bez zarządzanego certyfikatu lub gdy ta sama tożsamość jest aktywna w innym miejscu.
4. Monitoruj endpointy zdolne do łączenia interfejsów. W systemach Windows, Linux i appliance'ach sieciowych analizuj nieoczekiwane profile WLAN, konfigurację forwarding/NAT, wirtualne adaptery oraz trwałe tunele.
5. Ograniczaj niepotrzebne rozprzestrzenianie sygnału poprzez rozsądne rozmieszczenie AP i planowanie mocy. Jest to kontrola wspierająca, a nie uwierzytelnianie.
6. Koordynuj incident response z sąsiednimi najemcami: końcowe źródło radiowe może samo być ofiarą.

[Owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) odtwarza te obserwowalne oznaki bez atakowania sąsiada.

## Publiczne miejsca i Wi-Fi stron trzecich

Korzystanie z Wi-Fi w kawiarni, hotelu, na lotnisku lub w sieci miejskiej zmienia adres IP widoczny dla celu. Nie zapewnia anonimowości. Miejsce lub jego dostawca może przechowywać informacje o powiązaniu z AP, adres MAC urządzenia, dzierżawę DHCP, konto captive portal, walidację SMS/email oraz logi przepływów. Dane o wejściu do obiektu, nagrania CCTV, zakup, lokalizacja telefonu komórkowego i rejestry podróży mogą połączyć zdarzenie cyfrowe z konkretną osobą.

Aktor może próbować ograniczyć jeden ze śladów, używając randomizowanych adresów MAC, oddzielnego urządzenia, gotówki lub tunelu. Korelacja między warstwami nadal jest możliwa na podstawie czasu przybycia, powtarzającego się schematu odwiedzania miejsca, fingerprintów radiowych, zachowania portalu, synchronizacji ruchu, nagrań z kamer i dostawcy tunelu. VPN przenosi również cel z logów miejsca do logów VPN; nie usuwa wiedzy miejsca o tym, że urządzenie było obecne.

Obrońcy publicznego dostępu powinni izolować klientów, blokować ruch lateralny, stosować WPA2/3-Enterprise lub klucze per-device, gdy jest to możliwe, przechowywać proporcjonalne logi DHCP/RADIUS/security, chronić captive portals oraz publikować procedurę obsługi nadużyć. Red teams powinny korzystać z takiego miejsca wyłącznie wtedy, gdy pozwalają na to jego warunki i zakres engagementu; omijanie portalu, kradzież dostępu lub atakowanie innych gości nie jest autoryzowanym skrótem testowym.

## Covert drop devices i warshipping

Drop to mały system umieszczony w obiekcie lub do niego dostarczony, a następnie kontrolowany za pośrednictwem wychodzącego Ethernetu, Wi-Fi lub sieci komórkowej. „Warshipping” pakuje urządzenie tak, aby zwykła dostawa przeniosła je do zasięgu radiowego. Możliwy sprzęt obejmuje zarówno komputer jednopłytkowy, jak i zmodyfikowaną ładowarkę, urządzenie peryferyjne USB, appliance sieciowy lub modem zasilany baterią.

Architektura operacyjna:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Urządzenie może zapewniać zdalny przyczółek, wykonywać pomiary bezprzewodowe, emulować autoryzowane urządzenie peryferyjne używane podczas ćwiczeń lub przekazywać ruch. Jego pozorne źródło znajduje się lokalnie, ale urządzenie pozostawia fizyczne artefakty: numery seryjne, opakowania, odciski palców, nagrania z kamer, logi dostępu, pobór energii, deskryptory USB, negocjację switchportu, fingerprinty DHCP, zachowanie OUI/randomizacji MAC, emisje RF i cykliczne połączenia rendezvous.

### Kontrole defensywne

- Utrzymuj procedury odbioru przesyłek i inwentaryzacji zasobów; sprawdzaj nieoczekiwaną elektronikę oraz paczki adresowane do nieistniejących pracowników.
- Używaj 802.1X/NAC dla dostępu przewodowego i bezprzewodowego, wyłączaj nieużywane porty, a nieznane urządzenia umieszczaj w ograniczonym VLAN-ie remediation.
- Generuj alerty dla nowych fingerprintów DHCP, lokalnie administrowanych adresów MAC, które pozostają aktywne, nowych urządzeń sieciowych/HID USB, nieautoryzowanych połączeń Wi-Fi Direct/Bluetooth oraz długotrwałych tuneli wychodzących.
- Ustal baseline zachowania switchportów, Power over Ethernet, DNS i TLS. Mały host bez wpisu w inwentaryzacji, nawiązujący okresowe szyfrowane połączenia, jest silniejszym sygnałem niż sam „Raspberry Pi OUI”.
- Podczas ćwiczeń zinwentaryzuj, oznacz, określ zakres, zaszyfruj, zapewnij zdalny kill, wyznacz termin zwrotu i upewnij się, że utrata urządzenia nie umożliwi ujawnienia danych uwierzytelniających nadających się do ponownego użycia.

## Łącze backhaul przez sieć komórkową i eSIM

Modem komórkowy omija bramę internetową celu i może utrzymywać dostępność dropa za NAT-em operatora poprzez wychodzące rendezvous. Adresy mobilne mogą się zmieniać lub być współdzielone; operator komórkowy nadal posiada silne dowody dotyczące abonenta i sieci: tożsamość SIM/eSIM, IMSI, przypisane adresy/porty, synchronizację z komórką/sektorem, a także dane konta/płatności i roamingu.

Z perspektywy przedsiębiorstwa nieoczekiwane modemy i osobiste hotspoty należy wykrywać za pomocą pomiarów bezprzewodowych/RF, inwentaryzacji USB/PCI endpointów, ograniczeń MDM, monitorowania rogue SSID oraz inspekcji fizycznej. Drop używający sieci komórkowej do sterowania nadal może zostać wykryty na podstawie lokalnego zachowania Ethernet/Wi-Fi i emisji radiowych.

W przypadku autoryzowanych ćwiczeń organizacja powinna być właścicielem subskrypcji i modemu, zarejestrować identyfikatory u kontrolera oraz sprawdzić, czy warunki operatora/dostawcy zezwalają na taki ruch. Etykieta prepaid lub zakup za pomocą kryptowaluty nie usuwa danych wież, urządzenia ani punktu sprzedaży.

## Randomizacja MAC i fingerprinting urządzeń

Współczesne systemy mogą używać lokalnie administrowanego, losowego adresu MAC dla każdej sieci. Ogranicza to pasywne długoterminowe śledzenie na podstawie stabilnego fabrycznego adresu MAC, ale nie ukrywa:

- czasu wysyłania probe/association oraz zestawu żądanych możliwości sieci;
- elementów informacji 802.11, obsługiwanych szybkości i zachowania specyficznego dla dostawcy;
- opcji/hostname DHCP, identyfikatorów IPv6 oraz fingerprintu captive portalu/przeglądarki;
- uwierzytelnionej tożsamości 802.1X lub certyfikatu;
- konta na wyższej warstwie, tunelu i wzorca ruchu; ani
- obserwacji fizycznej.

Obrońcy nie powinni używać allowlist MAC jako mechanizmu uwierzytelniania. Powiąż tożsamość radiową z certyfikatem/postawą urządzenia i traktuj zmieniające się adresy MAC jako normalne, chyba że inne elementy kontekstu są anomalne.

## Przejęcie łącza satelitarnego

Kaspersky udokumentował wykorzystywanie przez Turla słabości starszego, jednokierunkowego Internetu satelitarnego DVB-S. W opisanym modelu uprawniony zdalny abonent wysyłał żądania wychodzące przez łącze naziemne, ale odbierał dane downstream za pośrednictwem nieszyfrowanej, szerokopasmowej transmisji satelitarnej. Aktor znajdujący się w zasięgu satelity mógł obserwować downlink, wybrać adres IP aktywnego abonenta i doprowadzić do tego, aby odpowiedzi C2 były kierowane na ten adres IP. Zarówno uprawniony abonent, jak i aktor odbierali transmisję; aktor wyodrębniał ruch dla wybranego portu, podczas gdy uprawniony abonent odrzucał niezamówione pakiety. Operator C2 sprawiał wówczas wrażenie, jakby korzystał z adresu dostawcy usług satelitarnych w innej lokalizacji geograficznej.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Było to specyficzne dla danego protokołu/usługi, ograniczone przepustowością i nie było równoważne z przejęciem nowoczesnego, dwukierunkowego, szyfrowanego terminala satelitarnego. Nie ukrywało również ścieżki wychodzących żądań aktora przed odpowiednio kompetentnym obserwatorem. Możliwości wykrycia obejmują asymetryczny/niemożliwy routing, ruch do subskrybenta, który nie zainicjował przepływu, nietypowe porty docelowe, telemetrię dostawcy, ustalenie lokalizacji odbiornika/dochodzenie RF oraz konfigurację malware. Wykorzystaj ten przypadek do zakwestionowania założenia, że geolokalizacja adresu IP C2 wskazuje lokalizację jego operatora — nie jako instrukcję budowy.

## Arkusz korelacji fizyczno-cyfrowej

Gdy pozornie lokalne źródło budzi podejrzenia, utwórz jedną oś czasu:

1. ujednolić zegary AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, przełączników i systemów kontroli dostępu fizycznego;
2. zidentyfikować pierwsze skojarzenie radiowe lub zestawienie łącza, a nie tylko pierwszy alert;
3. powiązać stację z certyfikatem, posture urządzenia, fingerprintem DHCP oraz lokalizacją przełącznika/AP;
4. sprawdzić, czy na pobliskich systemach jednocześnie występowała aktywność zdalnego sterowania/tunelowania;
5. przeanalizować dostawy, odwiedzających, wyjątki magazynowe, kamery i ustalenia RF zgodnie z obowiązującymi zasadami/prawem;
6. zabezpieczyć podejrzane urządzenie i ulotny stan sieci; nie wyłączać go bez namysłu;
7. ustalić, czy pozorne źródło jest infrastrukturą kontrolowaną przez aktora, czy kolejną ofiarą.

## References

- [1] [Volexity — Atak najbliższego sąsiada: jak rosyjska APT uzbroiła pobliskie sieci Wi-Fi](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satelitarny Turla: command and control APT na niebie](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Dodawanie sprzętu (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Wytyczne dotyczące zabezpieczania bezprzewodowych sieci lokalnych](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
