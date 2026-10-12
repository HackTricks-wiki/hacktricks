# Ukryty dostęp fizyczny i bezprzewodowy

{{#include ../banners/hacktricks-training.md}}

Szczegółową, zatwierdzoną przez właściciela implementację obejmującą outbound rendezvous, przywracanie zasilania/łącza uplink, ograniczenie sekretów przechowywanych na urządzeniu do minimum, testy przechwytywania oraz monitorowanie pod kątem możliwego wykrycia opisano w artykule [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Zmiana ścieżki sieciowej może również zmienić pozorne fizyczne pochodzenie ruchu. Zaawansowany aktor może użyć pobliskiego przejętego systemu, ukrytego urządzenia, publicznego dostępu, łącza komórkowego lub odbiornika satelitarnego, aby logi celu wskazywały inny punkt niż operator. Żadna z tych metod nie eliminuje dowodów fizycznych, radiowych ani pochodzących od dostawców; przenosi atrybucję do innych zbiorów danych.

## Macierz technik

| Technika | Pozorne pochodzenie | Niezbędny warunek | Dowody o wysokiej wartości |
|---|---|---|---|
| Bezprzewodowy pivot z pobliskiej lokalizacji | firma/dom obok celu | przejęty host z dwoma interfejsami sieciowymi i dostęp do Wi-Fi celu | logi endpointu sąsiedniego hosta, asocjacja RF oraz RADIUS/DHCP celu |
| Sieć publiczna/gościnna | NAT lokalu lub wyjście tunelu | zgodny z prawem dostęp lub obejście kontroli dostępu | portal captive, DHCP, asocjacja z AP, monitoring CCTV oraz dane o płatności/lokalizacji |
| Ukryte urządzenie podrzucone w pobliżu | adres przewodowy, Wi-Fi lub komórkowy celu/pobliskiej lokalizacji | fizyczne umieszczenie lub dostarczenie | port przełącznika/USB, RF, inwentaryzacja, zasilanie oraz telemetria tunelu wychodzącego |
| Router komórkowy/eSIM | NAT operatora lub dedykowany APN | modem/SIM/subskrypcja | IMEI/IMSI/eSIM, sektor komórkowy, konto u operatora i czas ruchu |
| Nadużycie łącza satelitarnego | adres abonenta w zasięgu wiązki | słabość zależna od protokołu i usługi | lokalizacja RF, przepływ uplink, niemożliwe RTT/routing oraz dane dostawcy |

## Atak Nearest Neighbor

Volexity opisała operację APT28/GRU z 2022 roku, podczas której aktor znajdował się zdalnie względem swojego ostatecznego celu. Przeprowadził password spraying na publicznie dostępną usługę celu, aby uzyskać prawidłowe dane uwierzytelniające, ale MFA uniemożliwiło bezpośrednie logowanie przez Internet. Firmowa sieć Wi-Fi celu akceptowała te dane bez MFA. Aktor przejął organizacje znajdujące się fizycznie blisko celu, znalazł system z dwoma interfejsami sieciowymi i dostępem bezprzewodowym, a następnie użył go, by uwierzytelnić się w sieci Wi-Fi celu. Volexity nadała tej metodzie nazwę **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

Nowością jest połączenie tych elementów. Żaden operator nie dociera do celu, a MFA usługi dostępnej z Internetu nadal działa. Przejęty system sąsiada zapewnia bliskość fizyczną; skradzione poświadczenia celu zapewniają dostęp logiczny; docelowa sieć Wi-Fi staje się ścieżką przekroczenia granicy.

### Warunki wstępne i widoczność

- System znajdujący się w pobliżu musi dać się zdalnie kontrolować i mieć kompatybilne radio albo dostęp do innego pobliskiego punktu przesiadkowego.
- Docelowy SSID musi być dostępny z tego systemu, a dopuszczanie do sieci Wi-Fi musi akceptować poświadczenia, certyfikat lub stan urządzenia, których można użyć ponownie.
- Punkt przesiadkowy często wymaga dwóch jednoczesnych ścieżek: jednej z powrotem do operatora, a drugiej do docelowej sieci WLAN.
- Cel może zobaczyć nowy adres MAC stacji i prawidłową nazwę użytkownika, ale nie powiązany certyfikat zarządzanego urządzenia, stan zgodności, historię ani oczekiwane wejście do budynku.
- Dzienniki punktu końcowego sąsiada mogą wykazywać skanowanie sieci bezprzewodowych, nowe profile, zmiany interfejsów, tunelowanie i aktywność zdalnego sterowania.

### Wykrywanie i zapobieganie

1. Wymagaj EAP-TLS opartego na certyfikatach i zgodności zarządzanego urządzenia w firmowej sieci Wi-Fi. Nie uznawaj hasła, które nie przeszło MFA w Internecie, za wystarczające tylko dlatego, że użyto go przez radio.
2. Koreluj uwierzytelnianie RADIUS z tożsamością w MDM/NAC, historycznym powiązaniem stacji z urządzeniem, lokalizacją AP, zdarzeniami dostępu fizycznego i równoczesnymi sesjami.
3. Generuj alerty, gdy konto łączy się po raz pierwszy z nietypowego obszaru zasięgu AP, bez certyfikatu zarządzanego urządzenia lub gdy ta sama tożsamość jest aktywna w innym miejscu.
4. Monitoruj punkty końcowe, które mogą łączyć interfejsy. W systemach Windows, Linux i urządzeniach sieciowych sprawdzaj nieoczekiwane profile WLAN, konfigurację przekazywania ruchu/NAT, wirtualne adaptery i trwałe tunele.
5. Ogranicz niepotrzebny zasięg sygnału, odpowiednio rozmieszczając AP i planując ich moc. To środek pomocniczy, a nie metoda uwierzytelniania.
6. Koordynuj reagowanie na incydenty z sąsiednimi najemcami: ostateczne źródło sygnału radiowego może samo być ofiarą.

[Laboratorium dwóch kontrolowanych organizacji](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) odtwarza te obserwowalne ślady bez atakowania sąsiada.

### Weryfikacja ścieżki pivotu w systemie Windows

Host Windows z dwoma interfejsami sieciowymi nie łączy ich automatycznie w most. Najpierw zinwentaryzuj adaptery, trasy i stan WLAN, a następnie połącz się wyłącznie za pomocą zatwierdzonego profilu. Argument `name` polecenia `netsh wlan connect` wskazuje zainstalowany profil, a nie dowolny SSID i hasło. Porównaj tablicę tras przed połączeniem i po nim, aby upewnić się, że nowa trasa domyślna nie przerwie kanału sterowania ani nie unieważni wyniku. Kontynuuj, wykonując [kontrole po połączeniu](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md), dopiero po potwierdzeniu właściwego interfejsu i trasy.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Volexity opublikowało artefakt incydentu, który pokazuje inne przydatne rozróżnienie. Zawarty w nim kod C# otwiera WLAN API, wylicza interfejsy, odczytuje z dysku XML EAP i wywołuje `WlanSetProfileEapXmlUserData` dla nazwanego profilu na pierwszym interfejsie bezprzewodowym. API ustawia dane uwierzytelniające użytkownika EAP w istniejącym profilu 802.1X, ale opublikowany komponent nie zawiera ani `WlanConnect`, ani logiki wykrywania opisanej w raporcie. Należy traktować go jako narzędzie do konfigurowania profilu, a nie kompletny program do łączenia, i sprawdzić wynikowy profil w ramach [oceny klienta i suplikanta](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Miejsca publiczne i Wi-Fi stron trzecich

Korzystanie z Wi-Fi w kawiarni, hotelu, na lotnisku lub w sieci miejskiej zmienia adres IP widoczny dla serwera docelowego. Nie zapewnia jednak anonimowości. Miejsce lub jego dostawca mogą przechowywać logi dotyczące połączeń z AP, adresów MAC urządzeń, dzierżaw DHCP, kont w portalu logowania, weryfikacji SMS/e-mail i przepływów sieciowych. Dane o fizycznym wejściu, nagrania z monitoringu, zakupy, lokalizacja telefonu komórkowego i rejestry podróży mogą powiązać zdarzenie cyfrowe z konkretną osobą.

Aktor może próbować utrudnić powiązanie, używając losowych adresów MAC, osobnego urządzenia, gotówki lub tunelu. Korelacja między warstwami nadal jest możliwa na podstawie godziny przybycia, powtarzających się wzorców odwiedzin, sygnatur radiowych, zachowania w portalu, czasu transmisji, nagrań z kamer i dostawcy tunelu. VPN przenosi też punkt obserwacji z logów miejsca na logi VPN; nie usuwa wiedzy miejsca o obecności urządzenia.

Operatorzy publicznych sieci dostępowych powinni izolować klientów, blokować ruch boczny, w miarę możliwości używać WPA2/3-Enterprise lub kluczy przypisanych do poszczególnych urządzeń, przechowywać proporcjonalny zakres logów DHCP/RADIUS i logów bezpieczeństwa, chronić portale logowania oraz publikować procedurę zgłaszania nadużyć. Red teamy powinny korzystać z takich miejsc wyłącznie wtedy, gdy zezwalają na to ich regulamin i warunki zlecenia; omijanie portalu, kradzież dostępu lub atakowanie innych gości nie stanowią dozwolonego skrótu w testach.

## Ukryte urządzenia typu drop i warshipping

Drop to niewielki system umieszczony w obiekcie lub dostarczony do niego, a następnie kontrolowany przez wychodzące połączenie Ethernet, Wi-Fi lub komórkowe. „Warshipping” polega na zapakowaniu urządzenia tak, by zwykła przesyłka wniosła je w zasięg sieci radiowej. Możliwe rozwiązania sprzętowe obejmują komputery jednopłytkowe, zmodyfikowane ładowarki, urządzenia peryferyjne USB, sprzęt sieciowy lub modemy zasilane baterią.

Architektura operacyjna:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

Urządzenie może zapewniać zdalny przyczółek, wykonywać pomiary bezprzewodowe, emulować urządzenie peryferyjne używane w autoryzowanym ćwiczeniu lub przekazywać ruch. Pozornie znajduje się lokalnie, ale pozostawia fizyczne ślady: numery seryjne, opakowanie, odciski palców, nagrania z kamer, wpisy w logach dostępu, pobór mocy, deskryptory USB, negocjację switchportu, fingerprinty DHCP, zachowanie OUI/adresów MAC podlegających randomizacji, emisje RF i powtarzające się połączenia rendezvous.

### Zabezpieczenia

- Utrzymuj procedury dla pomieszczeń odbioru przesyłek i ewidencji zasobów; sprawdzaj nieoczekiwaną elektronikę oraz przesyłki zaadresowane do nieistniejących pracowników.
- Stosuj 802.1X/NAC w dostępie przewodowym i bezprzewodowym, wyłączaj nieużywane porty, a nieznane urządzenia umieszczaj w ograniczonej VLAN naprawczej.
- Ustawiaj alerty dotyczące nowych fingerprintów DHCP, lokalnie administrowanych adresów MAC, które pozostają aktywne, nowych urządzeń sieciowych/HID USB, nieautoryzowanych Wi-Fi Direct/Bluetooth i długotrwałych tuneli wychodzących.
- Ustal bazowe zachowanie switchportów, zasilania przez Ethernet, DNS i TLS. Mały host bez wpisu w ewidencji, który nawiązuje okresowe szyfrowane połączenia, jest silniejszym sygnałem niż sam „OUI Raspberry Pi”.
- Podczas ćwiczenia prowadź ewidencję urządzeń, oznaczaj je, określaj zakres, szyfruj, zapewnij zdalny kill switch, wyznacz termin odbioru i upewnij się, że utrata urządzenia nie ujawni danych uwierzytelniających nadających się do ponownego użycia.

## Łączność komórkowa i backhaul eSIM

Modem komórkowy omija bramę internetową celu i może zapewniać dostęp do dropa za NAT-em operatora dzięki wychodzącemu połączeniu rendezvous. Adresy mobilne mogą się zmieniać lub być współdzielone; operator komórkowy nadal dysponuje szczegółowymi danymi abonenta i sieci: tożsamością SIM/eSIM, IMSI, IMEI urządzenia, przydzielonymi adresami/portami, czasem połączenia ze stacją/komórką, danymi konta/płatności i roamingu.

Z perspektywy przedsiębiorstwa wykrywaj nieoczekiwane modemy i prywatne hotspoty za pomocą inspekcji sieci bezprzewodowych/RF, ewidencji USB/PCI punktów końcowych, ograniczeń MDM, monitorowania nieautoryzowanych SSID i fizycznej inspekcji. Drop wykorzystujący łączność komórkową do sterowania nadal można wykryć na podstawie jego lokalnego zachowania Ethernet/Wi-Fi i emisji radiowych.

W przypadku autoryzowanych ćwiczeń organizacja powinna być właścicielem abonamentu i modemu, zarejestrować identyfikatory u kontrolera oraz sprawdzić, czy warunki operatora/dostawcy zezwalają na taki ruch. Zakup za gotówkę karty prepaid lub płatność kryptowalutą nie usuwa zapisów stacji bazowych, urządzenia ani sprzedawcy.

## Randomizacja MAC i fingerprinting urządzeń

Nowoczesne systemy mogą używać lokalnie administrowanego, losowego adresu MAC dla każdej sieci. Ogranicza to długoterminowe śledzenie pasywne na podstawie stałego, fabrycznego adresu MAC; nie ukrywa jednak:

- czasu wysyłania sond i nawiązywania połączeń oraz zestawu żądanych możliwości sieciowych;
- elementów informacyjnych 802.11, obsługiwanych szybkości i zachowania specyficznego dla dostawcy;
- opcji/nazwy hosta DHCP, identyfikatorów IPv6 i fingerprintu przeglądarki/portalu captive;
- uwierzytelnionej tożsamości lub certyfikatu 802.1X;
- kont, tuneli i wzorców ruchu na wyższych warstwach; ani
- obserwacji fizycznej.

Obrońcy nie powinni używać list dozwolonych adresów MAC jako metody uwierzytelniania. Powiąż tożsamość radiową z certyfikatem/stanem urządzenia i traktuj zmieniające się adresy MAC jako normalne, chyba że inne okoliczności wskazują na anomalię.

## Przejęcie łącza satelitarnego

Kaspersky udokumentował wykorzystanie przez Turla słabości starszego, jednokierunkowego satelitarnego Internetu DVB-S. Według opisanego modelu uprawniony zdalny abonent wysyłał żądania wychodzące przez łącze naziemne, ale odbierał dane przychodzące przez nieszyfrowaną, szerokopasmową transmisję satelitarną. Podmiot działający w zasięgu satelity mógł obserwować transmisję przychodzącą, wybrać adres IP aktywnego abonenta i doprowadzić do tego, by odpowiedzi C2 były kierowane na ten adres IP. Transmisję odbierali zarówno uprawniony abonent, jak i atakujący; atakujący wyodrębniał ruch dla wybranego portu, podczas gdy uprawniony abonent odrzucał niezamówione pakiety. Operator C2 sprawiał wtedy wrażenie, jakby korzystał z adresu dostawcy satelitarnego przypisanego do innej lokalizacji geograficznej.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Było to specyficzne dla protokołu/usługi, ograniczone przepustowością i nie było równoznaczne z przejęciem nowoczesnego, dwukierunkowego, szyfrowanego terminala satelitarnego. Nie ukrywało też ścieżki żądań wychodzących aktora przed odpowiednio kompetentnym obserwatorem. Możliwości wykrycia obejmują asymetryczny/niemożliwy routing, ruch do abonenta, który nie zainicjował połączenia, nietypowe porty docelowe, telemetrię dostawcy, dochodzenie dotyczące lokalizacji odbiornika/RF oraz konfigurację malware. Wykorzystaj ten przypadek, by podważyć założenie, że geolokalizacja adresu IP C2 wskazuje lokalizację jego kontrolera — nie jako instrukcję budowy.

## Arkusz korelacji zdarzeń fizycznych i cyfrowych

Gdy podejrzane jest źródło pozornie lokalne, utwórz jedną oś czasu:

1. ujednolić zegary AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, przełączników i systemów kontroli dostępu fizycznego;
2. ustalić pierwsze połączenie radiowe lub aktywację łącza, a nie tylko pierwsze alerty;
3. powiązać stację z certyfikatem, stanem urządzenia, odciskiem DHCP i lokalizacją przełącznika/AP;
4. sprawdzić, czy w pobliżu nie występowała równoczesna aktywność zdalnego sterowania/tunelowania na innych systemach;
5. zgodnie z obowiązującymi zasadami/prawem przeanalizować dostawy, gości, wyjątki w ewidencji, nagrania z kamer i ustalenia RF;
6. zabezpieczyć podejrzane urządzenie i ulotny stan sieci; nie restartować go bez zastanowienia;
7. ustalić, czy pozorne źródło to infrastruktura kontrolowana przez aktora, czy inna ofiara.

## References

- [1] [Volexity — Atak Nearest Neighbor: jak rosyjska grupa APT wykorzystała pobliskie sieci Wi-Fi do uzyskania ukrytego dostępu](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: dowodzenie i kontrola APT na niebie](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Dodawanie sprzętu (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Wytyczne dotyczące zabezpieczania bezprzewodowych sieci lokalnych](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Zredagowany kod profilu WLAN w PowerShell/C#](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — Funkcja WlanSetProfileEapXmlUserData](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
