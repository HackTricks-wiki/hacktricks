# Ukryty dostęp fizyczny i bezprzewodowy

Szczegółową, zatwierdzoną przez właściciela implementację obejmującą outbound rendezvous, odzyskiwanie zasilania/uplink, minimalną ilość sekretów przechowywanych na urządzeniu, testy przechwycenia oraz monitorowanie pod kątem możliwego wykrycia opisano w [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Zmiana ścieżki sieciowej może również zmienić pozorne źródło fizyczne. Wyrafinowany aktor może użyć pobliskiego przejętego systemu, ukrytego urządzenia, publicznego dostępu, cellular backhaul lub odbiornika satelitarnego, aby logi celu wskazywały lokalizację inną niż operatora. Żadne z tych rozwiązań nie usuwa dowodów fizycznych, radiowych ani pochodzących od providera; przenosi atrybucję do innych zbiorów danych.

## Macierz technik

| Technika | Pozorne źródło | Niezbędny warunek | Dowody o wysokiej wartości |
|---|---|---|---|
| Pobliskie wireless pivot | firma/dom obok celu | przejęty host dual-homed i dostęp do docelowej sieci Wi-Fi | logi endpointu sąsiedniego hosta, skojarzenia RF oraz RADIUS/DHCP celu |
| Sieć publiczna/gościnna | NAT obiektu lub wyjście tunelu | zgodny z prawem dostęp lub obejście kontroli dostępu | captive portal, DHCP, skojarzenie z AP, monitoring CCTV oraz dane płatności/lokalizacji |
| Ukryte urządzenie drop | przewodowy, Wi-Fi lub cellular adres celu/pobliskiej lokalizacji | fizyczne umieszczenie lub dostarczenie | switchport/USB, RF, inwentaryzacja, zasilanie oraz telemetryka outbound tunnel |
| Router cellular/eSIM | NAT operatora lub dedykowany APN | modem/SIM/subskrypcja | IMEI/IMSI/eSIM, sektor stacji bazowej, konto operatora oraz czasowa korelacja ruchu |
| Nadużycie łącza satelitarnego | adres subskrybenta w zasięgu wiązki | słabość specyficzna dla protokołu i usługi | lokalizacja RF, przepływ uplink, niemożliwe RTT/routing oraz rejestry providera |

## Nearest-neighbor attack

Volexity udokumentowało operację APT28/GRU z 2022 roku, w której aktor znajdował się zdalnie względem ostatecznego celu. Przeprowadził password spraying na publicznej usłudze celu, aby uzyskać prawidłowe dane uwierzytelniające, lecz MFA uniemożliwiło bezpośrednie logowanie z Internetu. Enterprise Wi-Fi celu akceptowała te dane bez MFA. Aktor przejął organizacje znajdujące się fizycznie blisko celu, znalazł system dual-homed z zasięgiem bezprzewodowym i użył go do uwierzytelnienia w docelowej sieci Wi-Fi. Volexity nazwało to **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Nowość polega na kompozycji. Żaden operator nie udaje się do celu, a MFA usługi dostępnej z Internetu nadal działa. Zaatakowany sąsiad zapewnia fizyczną bliskość; skradzione dane uwierzytelniające celu zapewniają dostęp logiczny; docelowa sieć Wi-Fi staje się ścieżką przekraczania granicy.

### Warunki wstępne i widoczność

- Pobliskim systemem musi dać się zdalnie sterować, a system ten musi mieć kompatybilne radio lub dostęp do innego pobliskiego punktu pośredniczącego.
- Docelowy SSID musi być osiągalny z tego systemu, a dopuszczenie do Wi-Fi musi akceptować wielokrotnie używalne dane uwierzytelniające, certyfikat lub stan urządzenia.
- Punkt pośredniczący często potrzebuje dwóch jednoczesnych ścieżek: jednej z powrotem do operatora i jednej do docelowej sieci WLAN.
- Cel może zobaczyć nowy adres MAC stacji i prawidłową nazwę użytkownika, ale bez odpowiadającego mu certyfikatu zarządzanego urządzenia, informacji o stanie, historii lub oczekiwanego wpisu do budynku.
- Logi endpointu sąsiada mogą wskazywać skanowanie sieci bezprzewodowych, nowe profile, zmiany interfejsów, tunelowanie i aktywność związaną ze zdalnym sterowaniem.

### Wykrywanie i zapobieganie

1. Wymagaj EAP-TLS opartego na certyfikatach oraz stanu zarządzanego urządzenia dla firmowej sieci Wi-Fi; nie uznawaj hasła, które nie przeszło MFA w Internecie, za wystarczające tylko dlatego, że dociera drogą radiową.
2. Koreluj uwierzytelnianie RADIUS z tożsamością MDM/NAC, historycznym powiązaniem stacji z urządzeniem, lokalizacją AP, zdarzeniami dostępu fizycznego i równoczesnymi sesjami.
3. Generuj alert, gdy konto łączy się po raz pierwszy, z nietypowego brzegu AP, bez zarządzanego certyfikatu lub gdy ta sama tożsamość jest aktywna w innym miejscu.
4. Monitoruj endpointy zdolne do mostkowania interfejsów. W systemach Windows, Linux i urządzeniach sieciowych analizuj nieoczekiwane profile WLAN, konfiguracje przekazywania/NAT, wirtualne adaptery i trwałe tunele.
5. Ograniczaj niepotrzebne rozchodzenie się sygnału dzięki rozsądnemu rozmieszczeniu AP i planowaniu mocy. Jest to środek pomocniczy, a nie uwierzytelnianie.
6. Koordynuj reagowanie na incydenty z sąsiednimi najemcami: ostateczne źródło radiowe może samo być ofiarą.

[Posiadane laboratorium dwóch organizacji](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) odtwarza te obserwowalne oznaki bez atakowania sąsiada.

## Publiczne obiekty i sieci Wi-Fi podmiotów trzecich

Korzystanie z sieci Wi-Fi w kawiarni, hotelu, na lotnisku lub udostępnianej przez gminę zmienia adres IP widoczny dla celu. Nie zapewnia jednak anonimowości. Obiekt lub jego dostawca może przechowywać informacje o połączeniu z AP, adres MAC urządzenia, dzierżawę DHCP, konto portalu captive portal, weryfikację SMS/e-mail oraz logi przepływów. Fizyczne wejście, monitoring CCTV, zakup, dane o lokalizacji telefonu komórkowego i rejestry podróży mogą połączyć zdarzenie cyfrowe z konkretną osobą.

Aktor może próbować ograniczyć jeden ze śladów, używając losowych adresów MAC, oddzielnego urządzenia, gotówki lub tunelu. Korelacja między warstwami nadal jest możliwa dzięki czasowi przybycia, powtarzającym się schematom odwiedzania obiektu, odciskom radiowym, zachowaniu portalu, synchronizacji ruchu, nagraniom z kamer i dostawcy tunelu. VPN również przenosi miejsce, w którym cel może być śledzony, z logów obiektu do logów VPN; nie usuwa wiedzy obiektu o obecności urządzenia.

Administratorzy publicznego dostępu powinni izolować klientów, blokować ruch boczny, stosować WPA2/3-Enterprise lub klucze per-device tam, gdzie jest to możliwe, przechowywać proporcjonalne logi DHCP/RADIUS/security, chronić captive portals i publikować procedurę zgłaszania nadużyć. Red teams powinni korzystać z takiego obiektu wyłącznie wtedy, gdy jego warunki i zakres engagementu na to pozwalają; omijanie portalu, kradzież dostępu lub atakowanie innych gości nie jest autoryzowanym skrótem w testach.

## Ukryte urządzenia drop i warshipping

Drop to niewielki system umieszczony w obiekcie lub dostarczony do niego, a następnie sterowany przez wychodzące połączenie Ethernet, Wi-Fi lub komórkowe. „Warshipping” polega na zapakowaniu urządzenia tak, aby zwykła dostawa przeniosła je do zasięgu radiowego. Możliwy sprzęt obejmuje zarówno komputer jednopłytkowy, jak i zmodyfikowaną ładowarkę, urządzenie peryferyjne USB, urządzenie sieciowe lub modem zasilany baterią.

Architektura operacyjna:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Urządzenie może zapewniać zdalny foothold, wykonywać pomiary bezprzewodowe, emulować autoryzowane urządzenie peryferyjne do ćwiczeń lub przekazywać ruch. Jego pozorne źródło znajduje się lokalnie, ale tworzy fizyczne artefakty: numery seryjne, opakowania, odciski palców, kamery, logi dostępu, pobór mocy, deskryptory USB, negocjację switchportu, fingerprinting DHCP, zachowanie OUI/randomizacji MAC, emisje RF i powtarzające się połączenia rendezvous.

### Kontrole defensywne

- Utrzymuj procedury odbioru przesyłek i ewidencji zasobów; sprawdzaj nieoczekiwaną elektronikę oraz paczki zaadresowane do nieistniejących pracowników.
- Stosuj 802.1X/NAC w sieciach przewodowych i bezprzewodowych, wyłączaj nieużywane porty, a nieznane urządzenia umieszczaj w ograniczonej sieci VLAN do działań naprawczych.
- Generuj alerty dotyczące nowych fingerprintów DHCP, trwale występujących lokalnie administrowanych adresów MAC, nowych urządzeń sieciowych USB/HID, nieautoryzowanego Wi-Fi Direct/Bluetooth oraz długotrwałych tuneli wychodzących.
- Ustal bazowe zachowanie switchportu, Power over Ethernet, DNS i TLS. Mały host bez wpisu w ewidencji, który nawiązuje okresowe szyfrowane połączenia, jest silniejszym sygnałem niż sam „Raspberry Pi OUI”.
- Podczas ćwiczeń zinwentaryzuj, oznacz, określ zakres, zaszyfruj, zapewnij zdalne wyłączenie, ustal termin odbioru i upewnij się, że utrata urządzenia nie umożliwi ujawnienia możliwych do ponownego użycia danych uwierzytelniających.

## Backhaul komórkowy i eSIM

Modem komórkowy omija bramę internetową celu i może utrzymywać dostępność implantu za NAT-em operatora za pośrednictwem wychodzącego rendezvous. Adresy mobilne mogą się zmieniać lub być współdzielone; operator komórkowy nadal ma silne dowody dotyczące abonenta i sieci: tożsamość SIM/eSIM, IMSI, przypisane adresy/porty, informacje o czasie obsługi komórki/sektora, dane konta/płatności oraz roamingu.

Z perspektywy przedsiębiorstwa nieoczekiwane modemy i osobiste hotspoty wykrywaj za pomocą pomiarów bezprzewodowych/RF, inwentaryzacji USB/PCI punktów końcowych, ograniczeń MDM, monitorowania rogue SSID i inspekcji fizycznych. Implant wykorzystujący łączność komórkową do sterowania nadal może zostać wykryty przez swoje lokalne zachowanie Ethernet/Wi-Fi i emisje radiowe.

W przypadku autoryzowanych ćwiczeń organizacja powinna być właścicielem subskrypcji i modemu, rejestrować identyfikatory u kontrolera oraz sprawdzić, czy warunki operatora/dostawcy zezwalają na taki ruch. Etykieta prepaid lub zakup za kryptowalutę nie usuwa rejestrów wież, urządzeń ani punktów sprzedaży.

## Randomizacja MAC i fingerprinting urządzeń

Nowoczesne systemy mogą używać lokalnie administrowanego losowego adresu MAC dla każdej sieci. Ogranicza to pasywne długoterminowe śledzenie za pomocą stałego fabrycznego adresu MAC; nie ukrywa jednak:

- czasu wysyłania sond i nawiązywania asocjacji oraz zestawu żądanych możliwości sieciowych;
- elementów informacyjnych 802.11, obsługiwanych szybkości i zachowania charakterystycznego dla dostawcy;
- opcji DHCP/nazwy hosta, identyfikatorów IPv6 oraz fingerprintu captive portalu/przeglądarki;
- uwierzytelnionej tożsamości 802.1X lub certyfikatu;
- konta wyższej warstwy, tunelu i wzorca ruchu; ani
- obserwacji fizycznej.

Obrońcy nie powinni używać list dozwolonych adresów MAC jako mechanizmu uwierzytelniania. Powiąż tożsamość radiową z certyfikatem i stanem urządzenia oraz traktuj zmieniające się adresy MAC jako normalne, chyba że inne dane kontekstowe są anomalne.

## Przejęcie łącza satelitarnego

Kaspersky udokumentował wykorzystanie przez Turla słabości starszego jednokierunkowego Internetu satelitarnego DVB-S. W opisanym modelu legalny zdalny abonent wysyłał żądania wychodzące przez łącze naziemne, ale odbierał dane downstream za pośrednictwem niezaszyfrowanej satelitarnej transmisji szerokopasmowej. Aktor znajdujący się w zasięgu satelity mógł obserwować downlink, wybrać adres IP aktywnego abonenta i doprowadzić do kierowania odpowiedzi C2 na ten adres IP. Zarówno legalny abonent, jak i aktor odbierali transmisję; aktor wydobywał ruch dla wybranego portu, podczas gdy legalny abonent odrzucał niezamówione pakiety. Operator C2 sprawiał wówczas wrażenie, jakby korzystał z adresu dostawcy satelitarnego znajdującego się w innej lokalizacji geograficznej.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Było to specyficzne dla danego protokołu/usługi, ograniczone przepustowością i nie było równoznaczne z przejęciem współczesnego dwukierunkowego, szyfrowanego terminala satelitarnego. Nie ukrywało również ścieżki wychodzących żądań aktora przed dostatecznie kompetentnym obserwatorem. Możliwości wykrycia obejmują asymetryczny/niemożliwy routing, ruch do subskrybenta, który nie zainicjował połączenia, nietypowe porty docelowe, telemetrię dostawcy, lokalizację odbiornika/dochodzenie RF oraz konfigurację malware. Wykorzystaj ten przypadek do zakwestionowania założenia, że geolokalizacja adresu IP C2 wskazuje lokalizację jego kontrolera — nie jako instrukcję budowy.

## Arkusz korelacji fizyczno-cyfrowej

Gdy pozornie lokalne źródło budzi podejrzenia, utwórz jedną oś czasu:

1. ujednolić zegary AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, przełączników i systemów kontroli dostępu fizycznego;
2. zidentyfikować pierwsze nawiązanie połączenia radiowego lub uruchomienie łącza, a nie tylko pierwszy alert;
3. powiązać stację z certyfikatem, stanem urządzenia, fingerprintem DHCP oraz lokalizacją przełącznika/AP;
4. poszukać jednoczesnej aktywności zdalnego sterowania/tunelowania na pobliskich systemach;
5. przeanalizować dostawy, odwiedzających, odstępstwa inwentaryzacyjne, nagrania z kamer i ustalenia RF zgodnie z obowiązującymi zasadami/prawem;
6. zabezpieczyć podejrzane urządzenie i ulotny stan sieci; nie wyłączać zasilania bez namysłu;
7. ustalić, czy pozorne źródło to infrastruktura kontrolowana przez aktora, czy inna ofiara.

## References

- [1] [Volexity — Atak Nearest Neighbor: jak rosyjska grupa APT uzbroiła pobliskie sieci Wi-Fi](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Turla satelitarna: command and control APT na niebie](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Dodawanie sprzętu (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Wytyczne dotyczące zabezpieczania bezprzewodowych sieci lokalnych](https://csrc.nist.gov/pubs/sp/800/153/final)
