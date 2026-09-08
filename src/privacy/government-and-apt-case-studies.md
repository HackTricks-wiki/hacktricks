# Studium przypadków rządowych i APT

Te publicznie opisane przypadki pokazują, jak odrębne techniki ochrony prywatności są łączone w rzeczywistych operacjach. Etykiety atrybucji są tymi używanymi przez cytowanych badaczy lub rządy; sam adres IP, nakładanie się narzędzi lub zgodność geopolityczna nie stanowią rozstrzygającego dowodu atrybucji.

## APT28: zdalny dostęp Wi-Fi do najbliższego sąsiada

**Publiczne ustalenie.** Volexity przypisało włamanie z 2022 roku grupie GruesomeLarch/APT28. Po zablokowaniu dostępu do Internetu przy użyciu zweryfikowanych danych uwierzytelniających przez MFA aktor zaatakował organizacje znajdujące się blisko celu i uzyskał dostęp do firmowej sieci Wi-Fi celu z pobliskiego hosta dual-homed. Ścieżka Wi-Fi akceptowała dane uwierzytelniające bez wymaganego z zewnątrz MFA.<sup>[[1]](#references)</sup>

**Wpływ na prywatność.** Ostateczny dostęp pochodził z fizycznego zasięgu radiowego, a organizacje pośrednie były ofiarami. Operacja pozwoliła uniknąć podróży i sprawiła, że konwencjonalna geolokalizacja IP wskazywała sąsiada.

**Co ujawniło operację.** Alert celu, analiza hosta/sieci, aktywność związana z danymi uwierzytelniającymi, topologia interfejsów i fizyczna bliskość musiały zostać przeanalizowane jako jeden łańcuch. Anomalią nie był po prostu nowy adres IP; była nią prawidłowa tożsamość pojawiająca się w nietypowym kontekście Wi-Fi/urządzenia, podczas gdy pobliskie systemy były przejęte.

**Wniosek obronny.** Stosuj dostęp do Wi-Fi oparty na certyfikatach/urządzeniach, koreluj RADIUS z NAC/MDM i kontekstem fizycznym oraz badaj infrastrukturę sąsiednich organizacji, zamiast zakładać, że ostatni hop należy do operatora.

## APT28: infrastruktura kryminalnego Moobot ponownie wykorzystana przez GRU

**Publiczne ustalenie.** W lutym 2024 roku US Department of Justice opisał botnet złożony z setek routerów Ubiquiti EdgeOS. Aktorzy kryminalni zainstalowali Moobot na routerach, które nadal używały znanych domyślnych danych uwierzytelniających administratora; następnie GRU Unit 26165 dodała skrypty i pliki, przekształcając istniejący kryminalny botnet w platformę szpiegowską wykorzystywaną do spearphishingu i kradzieży danych uwierzytelniających.<sup>[[2]](#references)</sup>

**Wpływ na prywatność.** GRU nie zbudowała całej infrastruktury samodzielnie. Wykorzystanie już przejętej floty umieściło adresy niezwiązanych z operacją gospodarstw domowych i małych biur pomiędzy aktorem a celami, połączyło aktywność państwową z kryminalną i ograniczyło artefakty rejestracyjne charakterystyczne dla aktora.

**Co ujawniło operację.** Pliki routerów, zachowanie malware sterującego oraz informacje routingowe niezawierające treści wsparły dochodzenie. Działania zakłócające tymczasowo zmieniły reguły firewalla i usunęły złośliwe pliki, podczas gdy DOJ ostrzegł, że niezmienione domyślne dane uwierzytelniające mogą umożliwić ponowne zainfekowanie urządzeń.

**Wniosek obronny.** Wymieniaj routery bez wsparcia, usuń administrację wystawioną do Internetu, zmień wartości domyślne, instaluj poprawki, zbieraj dane o konfiguracji/przepływach urządzeń brzegowych i wyszukuj zachowania charakterystyczne dla całej floty. „Residential US IP” nie jest dowodem na operatora z USA.

## Volt Typhoon: KV Botnet plus living off the land

**Publiczne ustalenie.** DOJ oraz wspólny advisory CISA opisały sponsorowaną przez państwo ChRL grupę Volt Typhoon, która wykorzystywała KV Botnet, składający się głównie z przejętych routerów Cisco i NETGEAR SOHO będących u kresu cyklu życia, aby ukryć pochodzenie aktywności w ChRL wymierzonej w infrastrukturę krytyczną. W zaatakowanych organizacjach aktor preferował prawidłowe konta i wbudowane narzędzia administracyjne; agencje poinformowały, że w niektórych środowiskach dostęp utrzymywał się przez co najmniej pięć lat.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Wpływ na prywatność.** Ścieżka podobna do ORB ukrywała źródło, a wykorzystanie istniejących narzędzi systemowych ograniczało liczbę nowych plików binarnych i okazji do wykrycia sygnatur po uzyskaniu dostępu. Ukrywanie w sieci i na endpointach wzajemnie się wzmacniało.

**Co ujawniło atak.** Struktura routera/kontrolera, autoryzowane przez sąd pozyskiwanie danych technicznych, powtarzalna aktywność i analiza między ofiarami miały większe znaczenie niż pojedynczy IOC. Ponowne uruchomienie routera usuwało opisane malware KV działające w pamięci ulotnej, ale nie usuwało podstawowego narażenia urządzenia wynikającego z zakończenia jego cyklu życia.

**Wniosek obronny.** Zastąp urządzenia brzegowe EOL, scentralizuj logi uwierzytelniania i urządzeń sieciowych, ustal bazowy model zachowania administratorów, ogranicz łączność wychodzącą i wyszukuj sekwencje zachowań występujące jednocześnie w warstwach tożsamości, endpointów i sieci.

## China-nexus ORB networks: infrastructure as a service

**Ustalenia publiczne.** Mandiant opisał ekosystem sieci ORB wykorzystywanych przez wielu aktorów szpiegowskich powiązanych z Chinami. Sieci provisioned korzystały z dzierżawionych węzłów VPS; sieci non-provisioned wykorzystywały przejęte urządzenia IoT i routery; sieci hybrydowe łączyły oba typy. ORB3/SPACEHOP wspierał aktywność powiązaną z APT5/APT15. ORB2/FLORAHOX łączył serwer administracyjny, dzierżawione serwery, niestandardową warstwę Tor oraz przejęte urządzenia Cisco, ASUS i DrayTek. Mandiant ocenił, że niektóre sieci były niezależnie administrowane i wynajmowane wielu aktorom APT.<sup>[[5]](#references)</sup>

**Wpływ na prywatność.** Infrastruktura stała się granicą usługową. Jeden operator mógł uzyskiwać wyjścia geograficzne/rezydencjalne bez utrzymywania floty ofiar, a wielu klientów współdzielących tę infrastrukturę utrudniało proste powiązanie aktora z adresem IP. Szybka rotacja floty przyspieszała „wygasanie IOC”.

**Co ujawniło atak.** Topologia sieci, sklonowane obrazy serwerów, porty/usługi, relacje z kontrolerami, implanty routerów i wzorce cyklu życia nadal pozwalały grupować infrastrukturę. Mandiant poinformował, że niektóre adresy IP węzłów pozostawały w ORB zaledwie przez 31 dni.

**Wniosek obronny.** Śledź ORB jako zmieniający się obiekt: role węzłów, fingerprinty usług, relacje upstream, zachowanie podczas skanowania i rytm rotacji. Wygaśnięcie wskaźnika IP powinno aktualizować klaster, a nie usuwać sprawę.

## PRC global espionage system: routers, trusted links and traffic mirroring

**Ustalenia publiczne.** Wielonarodowe zalecenie z 2025 roku opisywało aktywność pokrywającą się z nazwami używanymi w raportach komercyjnych, w tym Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 i GhostEmperor. Agencje poinformowały o dzierżawionych VPS-ach i przejętych routerach pośredniczących, wykorzystywanych do uzyskiwania dostępu do dostawców usług telekomunikacyjnych i sieciowych. Aktorzy przemieszczali się przez zaufane połączenia dostawca/klient, zmieniali trasy, tworzyli tunele GRE/IPsec, używali kontenerów urządzeń oraz włączali SPAN/RSPAN/ERSPAN lub natywne przechwytywanie pakietów w celu pozyskiwania danych uwierzytelniających i ruchu klientów.<sup>[[13]](#references)</sup>

**Wpływ na prywatność.** Przejęty router jest jednocześnie przekaźnikiem, punktem obserwacji i zaufanym uczestnikiem sieci. Prywatne połączenia wzajemne mogą omijać mechanizmy kontroli projektowane z myślą o publicznym Internecie, a mirroring ruchu pozwala pozyskiwać dane uwierzytelniające bez wdrażania agenta na endpoincie.

**Co ujawnia atak.** Różnice w konfiguracji, nieoczekiwane zarządzanie przez SNMP/SSH/web, nowe trasy statyczne/tunele, sesje mirroringu, kontenery Guest Shell, pliki PCAP, zmiany miejsc docelowych TACACS+/RADIUS oraz wyłączone logowanie. Zalecenie podkreśla, że niektóre routery pośredniczące nie należały do wcześniej nazwanych publicznych botnetów, dlatego brak znanych wskaźników ORB nie świadczył o braku winy.

**Wniosek obronny.** Stosuj zarządzanie out-of-band, scentralizowane logi konfiguracji/uwierzytelniania, kontrole integralności podpisanych obrazów i środowiska uruchomieniowego, ograniczenia egressu interfejsów zarządzania oraz alerty dotyczące zmian tras/mirroringu/tuneli/AAA. Przed eksmisją obejmij zakresem podejrzanego przejęcia także zaufanych partnerów.

## UNC3886 RedPenguin: passive backdoors on ISP routers

**Ustalenia publiczne.** Mandiant przypisał UNC3886 niestandardowe backdoory wywodzące się z TINYSHELL, działające na routerach Juniper MX, których cykl życia dobiegł końca. Zestaw obejmował implanty aktywne i pasywne, nazwy naśladujące legalne demony, funkcje wyłączania logów, process injection do zaufanego procesu, możliwość działania jako proxy SOCKS oraz infrastrukturę ocenianą jako węzły stagingowe ORB. Warianty pasywne analizowały pakiety za pomocą `libpcap` i aktywowały się dopiero po wykryciu magicznego wzorca; jeden z nich mógł przełączyć się na aktywne połączenie zwrotne dostarczone w wyzwalaczu.<sup>[[14]](#references)</sup>

**Wpływ na prywatność.** Pasywny implant nie wysyła okresowego beaconu, który można łatwo wykryć. Dzieli porty/ruch z rzeczywistym urządzeniem sieciowym, aktywuje się na krótko i może przekazywać ruch przez ORB zamiast łączyć się bezpośrednio z ostatecznym kontrolerem.

**Co ujawnia atak.** Analiza pamięci, różnice między kodem zapisanym na dysku a kodem działającym, nieoczekiwane filtry przechwytywania pakietów/zachowanie gniazd, nazwy procesów/plików jedynie przybliżające nazwy legalnych demonów, administracja przez serwery terminalowe, brakujące logi oraz dwuetapowa relacja między węzłami stagingowymi a backendowym kontrolerem.

**Wniosek obronny.** Pozyskuj pamięć oraz dowody z systemu plików/konfiguracji, porównuj procesy/moduły ze znanym dobrym obrazem, monitoruj użycie przechwytywania pakietów/filtrów gniazdowych, zabezpieczaj serwery terminalowe zarządzania i wymieniaj sprzęt sieciowy EOL. Brak wykrytego beacona wychodzącego nie oznacza, że system jest bezpieczny.

## APT29: Tor domain fronting

**Ustalenia publiczne.** MITRE odnotowuje, że APT29 używa transportu pluggable `meek` sieci Tor do realizowania domain fronting dla ruchu C2. Zewnętrzna nazwa TLS wyglądała na dozwoloną domenę hostowaną przez CDN, podczas gdy wewnętrzny host HTTP wybierał właściwą trasę.<sup>[[6]](#references)</sup>

**Wpływ na prywatność.** Obserwator filtrujący mógł widzieć popularny front/CDN zamiast wewnętrznego miejsca docelowego, a jego blokowanie groziło szkodami ubocznymi.

**Co ujawnia atak.** CDN może obserwować niezgodność routingu, a obrońca dysponujący widocznością endpointa lub zgodnym z prawem wglądem w TLS może korelować proces, authority, czas trwania połączenia, wzorzec liczby bajtów i późniejszą aktywność. Zmiany zasad dostawcy mogą wyłączyć tę technikę.

**Wniosek obronny.** Nie polegaj wyłącznie na allowlistingu SNI. Wymuszaj egress świadomy aplikacji, porównuj tożsamości TLS i HTTP, gdy są widoczne, oraz łącz zdarzenie sieciowe z procesem, który je zainicjował.

## APT41 and other dead-drop resolvers

**Ustalenia publiczne.** MITRE dokumentuje, że APT41 używał legalnych serwisów, w tym GitHub, Pastebin, Microsoft TechNet, Cloudflare i forów społecznościowych, do publikowania lub pobierania informacji C2. Inne narzędzia powiązane z państwami również wykorzystywały w podobny sposób posty, dokumenty i media społecznościowe.<sup>[[7]](#references)</sup>

**Wpływ na prywatność.** Plik binarny zawiera legalną usługę/obiekt zamiast stabilnego adresu C2. Obiekt można edytować w celu rotacji infrastruktury, a początkowe żądanie wtapia się w typowy ruch TLS.

**Co ujawnia atak.** Identyfikator obiektu lub konta jest stabilny; rzadko spotykane procesy wielokrotnie go pobierają; zawartość jest dekodowana; po czym następuje drugie połączenie wychodzące. Dane konta dostawcy i API mogą powiązać publikację z operatorem.

**Wniosek obronny.** Zachowuj pełne ścieżki proxy/identyfikatory obiektów oraz pochodzenie procesu na endpointcie. Zdarzenie na poziomie domeny, takie jak „połączono z GitHub”, jest zbyt ogólne.

## Turla: satellite-address C2

**Ustalenia publiczne.** Kaspersky poinformował, że Turla nadużywała niezaszyfrowanych transmisji downstream z wcześniejszych jednokierunkowych usług Internetu DVB-S. Operator znajdujący się w zasięgu satelity mógł wybrać adres legalnego abonenta i odbierać odpowiedzi rozgłaszane do tego adresu, przez co C2 wyglądało na hostowane za pośrednictwem dostawcy satelitarnego w innym regionie.<sup>[[8]](#references)</sup>

**Wpływ na prywatność.** Pozorny adres serwera nie identyfikował odbiorcy, a konwencjonalne procesy przejmowania hostingu i zapytania WHOIS były mniej użyteczne.

**Co ujawnia atak.** Aktor nadal potrzebował ścieżki żądania wychodzącego, routing był asymetryczny, legalny abonent nie inicjował wymiany C2, a dochodzenie RF/dostawcy mogło zawęzić obszar odbioru.

**Wniosek obronny.** Traktuj geolokalizację jako jedną z hipotez. Weryfikuj symetrię ścieżki, RTT, właściciela routingu oraz to, czy rzekomy endpoint mógł faktycznie dostarczyć zaobserwowaną usługę.

## Cyclops Blink and VPNFilter: edge devices as durable cover

**Ustalenia publiczne.** Zalecenie NCSC/CISA/FBI/NSA z 2022 roku opisywało modułowe malware Cyclops Blink grupy Sandworm na urządzeniach WatchGuard, wdrażane trwale jako aktualizacja firmware’u i zdolne do dodawania modułów. DOJ osobno opisał wcześniejszy botnet APT28 VPNFilter obejmujący routery i urządzenia NAS jako zdolny do pozyskiwania danych wywiadowczych, działań destrukcyjnych i błędnego przypisywania aktywności.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Wpływ na prywatność.** Urządzenia brzegowe są stale online, cieszą się zaufaniem jako element infrastruktury i są słabo objęte przez EDR. Trwałość na poziomie firmware’u może przetrwać zwykłe ponowne uruchomienie i zmienić urządzenie ofiary w przekaźnik lub punkt sterowania.

**Co ujawnia atak.** Integralność firmware’u, charakterystyczny dla dostawcy protokół implantu, nieoczekiwaną ekspozycję interfejsu zarządzania, zmiany konfiguracji i wychodzące beacony. Urządzenia brzegowe muszą być przedmiotem analizy kryminalistycznej, a nie przezroczystą infrastrukturą.

## DPRK: identity, network and financial layering

**Ustalenia publiczne.** Sprawy DOJ opisują pracowników z DPRK uzyskujących zdalne zatrudnienie przy użyciu fałszywych lub skradzionych materiałów tożsamości i VPN-ów, otrzymujących kryptowaluty, dzielących transfery, zamieniających aktywa/łańcuchy, używających NFT i mieszających środki. Inne sprawy opisują traderów OTC i firmy fasadowe zamieniające skradzione kryptowaluty na zakupy. Treasury i FBI publicznie powiązały środki Lazarus/TraderTraitor z mixerami oraz zidentyfikowały adresy związane z dużymi kradzieżami.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Wpływ na prywatność.** To nie jest „prywatna moneta”. Jest to łańcuch obejmujący wiele domen: persona i zdalny dostęp ukrywają lokalizację pracownika; kryptowaluty przenoszą wartość; layering rozbija proste narracje transakcyjne; traderzy OTC i firmy fasadowe tworzą połączenie z towarami i walutą fiat.

**Co ujawnia atak.** Anomalie pracodawcy/urządzenia, ponownie wykorzystywani pośrednicy, ciągłość czasu i wartości na blockchainie, dane giełd/bridge’ów, adresy objęte sankcjami, tożsamość kont oraz dane przesyłek i firm ponownie łączą ten łańcuch.

**Wniosek obronny.** Zespoły ds. rekrutacji, IAM, endpointów, płac, blockchaina i sankcji potrzebują wspólnego modelu sprawy. Więcej szczegółów znajduje się w [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Cross-case patterns

| Wzorzec | Przykłady APT | Dostosowanie obrony |
|---|---|---|
| Wyjściem jest kolejna ofiara | APT28/Moobot, Volt Typhoon/KV, ORBs | zbadaj i napraw wyjście; nie utożsamiaj go z lokalizacją aktora |
| Mechanizmy kontroli różnią się w zależności od granicy | APT28 nearest neighbor | zapewnij dostępowi wewnętrznemu/bezprzewodowemu taki sam poziom zapewnienia tożsamości jak dostępowi z Internetu |
| Legalna usługa jest warstwą routingu | APT29, APT41 | zachowuj kontekst obiektu/ścieżki/procesu, a nie tylko domenę docelową |
| Urządzeniom brzegowym brakuje telemetrii | KV, Moobot, Cyclops Blink, ORBs | scentralizuj logi konfiguracji/uwierzytelniania/przepływów i weryfikuj firmware/inwentaryzację |
| Infrastruktura jest współdzielona i krótkotrwała | China-nexus ORBs | grupuj zachowania/topologię i śledź zmiany ról w czasie |
| Kilka słabych rozdzieleń tworzy całość | persony DPRK + VPN + crypto + OTC | łącz dowody dotyczące tożsamości, urządzenia, sieci, płatności i świata fizycznego |

## References

- [1] [Volexity — Atak Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Zakłócenie kontrolowanego przez GRU botnetu routerów Moobot](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Zakłócenie botnetu PRC KV](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Aktorzy z PRC przejmują i utrzymują trwały dostęp do krytycznej infrastruktury USA](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Aktorzy szpiegowscy powiązani z Chinami używają sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Zalecenie dotyczące Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Zakłócenie APT28 VPNFilter](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Przedstawiciel północnokoreańskiego Foreign Trade Bank oskarżony o udział w spiskach dotyczących prania kryptowalut](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sankcje wobec Blender.io i środki Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Przeciwdziałanie przejmowaniu sieci na całym świecie przez aktorów sponsorowanych przez Chiny](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 atakuje routery Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
