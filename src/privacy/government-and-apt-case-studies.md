# Studia przypadków dotyczące rządów i APT

{{#include ../banners/hacktricks-training.md}}

Te publicznie opisane przypadki pokazują, jak odrębne techniki ochrony prywatności są łączone w rzeczywistych operacjach. Etykiety przypisania są zgodne z określeniami użytymi przez cytowanych badaczy lub rządy; sam adres IP, podobieństwo narzędzi lub zgodność geopolityczna nie stanowią rozstrzygającego dowodu przypisania.

## APT28: zdalny dostęp Wi-Fi przez najbliższego sąsiada

**Ustalenia publiczne.** Volexity przypisało włamanie z 2022 roku grupie GruesomeLarch/APT28. Po zablokowaniu dostępu do Internetu przy użyciu zweryfikowanych danych uwierzytelniających przez MFA aktor zaatakował organizacje znajdujące się blisko celu i uzyskał dostęp do firmowej sieci Wi-Fi celu z pobliskiego hosta dual-homed. Ścieżka Wi-Fi akceptowała dane uwierzytelniające bez wymaganego z zewnątrz MFA.<sup>[[1]](#references)</sup>

**Wpływ na prywatność.** Końcowy dostęp pochodził z fizycznego zasięgu radiowego, a organizacje pośredniczące były ofiarami. Operacja pozwoliła uniknąć podróży i sprawiła, że konwencjonalna geolokalizacja IP wskazywała sąsiada.

**Co ujawniło operację.** Alert celu, analiza hosta/sieci, aktywność związana z danymi uwierzytelniającymi, topologia interfejsów i fizyczna bliskość musiały zostać przeanalizowane jako jeden łańcuch. Nietypowym faktem nie był jedynie nowy adres IP; była nim prawidłowa tożsamość pojawiająca się w nietypowym kontekście Wi-Fi/urządzenia, podczas gdy pobliskie systemy były przejęte.

**Wniosek obronny.** Stosuj dostęp do Wi-Fi oparty na certyfikatach/urządzeniach, koreluj RADIUS z NAC/MDM i kontekstem fizycznym oraz badaj infrastrukturę sąsiednich organizacji, zamiast zakładać, że ostatni hop wskazuje operatora.

## APT28: infrastruktura przestępczego Moobot przejęta przez GRU

**Ustalenia publiczne.** W lutym 2024 roku Departament Sprawiedliwości USA opisał botnet składający się z setek routerów Ubiquiti EdgeOS. Aktorzy przestępczy zainstalowali Moobot na routerach zachowujących znane domyślne dane uwierzytelniające administratora; następnie jednostka GRU 26165 dodała skrypty i pliki, przekształcając istniejący przestępczy botnet w platformę szpiegowską wykorzystywaną do spearphishingu i kradzieży danych uwierzytelniających.<sup>[[2]](#references)</sup>

**Wpływ na prywatność.** GRU nie zbudowało całej infrastruktury samodzielnie. Wykorzystanie już przejętej floty umieściło między aktorem a celami niezwiązane adresy domowe i małych biur, połączyło aktywność państwową z przestępczą i ograniczyło artefakty rejestracyjne charakterystyczne dla aktora.

**Co ujawniło operację.** Pliki routerów, zachowanie malware sterującego oraz nieobejmujące treści informacje routingu wsparły dochodzenie. Działania zakłócające tymczasowo zmieniły reguły firewalli i usunęły złośliwe pliki, podczas gdy DOJ ostrzegł, że niezmienione domyślne dane uwierzytelniające mogą umożliwić ponowne zainfekowanie urządzeń.

**Wniosek obronny.** Wymień niewspierane routery, usuń administrację wystawioną do Internetu, zmień wartości domyślne, instaluj poprawki, zbieraj dane o konfiguracji/przepływach urządzeń brzegowych i wyszukuj zachowania charakterystyczne dla całej floty. „Residential US IP” nie jest dowodem, że operator pochodzi z USA.

## Volt Typhoon: KV Botnet oraz living off the land

**Ustalenia publiczne.** DOJ i wspólny komunikat CISA opisały sponsorowaną przez państwo ChRL grupę Volt Typhoon wykorzystującą KV Botnet, składający się głównie z przejętych routerów SOHO Cisco i NETGEAR, które osiągnęły koniec okresu wsparcia, aby ukryć pochodzenie aktywności w ChRL wymierzonej w infrastrukturę krytyczną. W środowiskach ofiar aktor preferował prawidłowe konta i wbudowane narzędzia administracyjne; agencje poinformowały, że w niektórych środowiskach dostęp utrzymywał się przez co najmniej pięć lat.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Wpływ na prywatność.** Ścieżka podobna do ORB ukrywała źródło, a wykorzystanie natywnych narzędzi systemowych (living-off-the-land) ograniczało liczbę nowych binariów i możliwości wykrycia na podstawie sygnatur po uzyskaniu dostępu. Ukrywanie w sieci i na endpointach wzajemnie się wzmacniało.

**Co ujawniło tę aktywność.** Struktura routerów i kontrolerów, autoryzowane przez sąd pozyskiwanie danych technicznych, powtarzalna aktywność oraz analiza między ofiarami miały większe znaczenie niż pojedynczy IOC. Ponowne uruchomienie routera usuwało opisane malware KV działające w pamięci ulotnej, ale nie usuwało bazowego problemu urządzenia wycofanego z eksploatacji.

**Wniosek obronny.** Wymieniaj urządzenia brzegowe EOL, centralizuj logi uwierzytelniania i urządzeń sieciowych, twórz baseline zachowania administratorów, ograniczaj łączność wychodzącą i wyszukuj sekwencje zachowań w warstwach tożsamości, endpointów i sieci.

## Sieci ORB powiązane z Chinami: infrastructure as a service

**Ustalenia publiczne.** Mandiant opisał ekosystem sieci ORB wykorzystywanych przez wielu aktorów szpiegowskich powiązanych z Chinami. Sieci provisioned korzystały z dzierżawionych węzłów VPS; sieci non-provisioned wykorzystywały przejęte urządzenia IoT i routery; sieci hybrydowe łączyły oba typy. ORB3/SPACEHOP wspierał aktywność powiązaną z APT5/APT15. ORB2/FLORAHOX łączył serwer administracyjny, dzierżawione serwery, dostosowaną warstwę Tor oraz przejęte urządzenia Cisco, ASUS i DrayTek. Mandiant ocenił, że niektóre sieci były niezależnie administrowane i wynajmowane wielu aktorom APT.<sup>[[5]](#references)</sup>

**Wpływ na prywatność.** Infrastructure stała się granicą usługową. Jeden operator mógł uzyskiwać geograficzne i rezydencjalne wyjścia bez utrzymywania floty ofiar, a wielu klientów korzystających z tej samej infrastruktury utrudniało proste mapowanie aktora na adres IP. Szybka rotacja floty przyspieszała „wygaszanie IOC”.

**Co ujawniło tę aktywność.** Topologia sieci, sklonowane obrazy serwerów, porty i usługi, zależności między kontrolerami, implanty routerów oraz wzorce cyklu życia nadal pozwalały na grupowanie. Mandiant poinformował, że niektóre adresy IP węzłów pozostawały w ORB zaledwie przez 31 dni.

**Wniosek obronny.** Śledź ORB jako zmieniającą się jednostkę: role węzłów, fingerprints usług, relacje upstream, zachowanie skanujące i rytm rotacji. Wygaśnięcie wskaźnika IP powinno aktualizować klaster, a nie usuwać sprawę.

## Globalny system szpiegowski ChRL: routery, zaufane połączenia i mirroring ruchu

**Ustalenia publiczne.** Wielonarodowe ostrzeżenie z 2025 roku opisywało aktywność pokrywającą się z nazwami używanymi w raportach komercyjnych, w tym Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 i GhostEmperor. Agencje poinformowały o dzierżawionych VPS oraz przejętych routerach pośredniczących wykorzystywanych do uzyskiwania dostępu do dostawców usług telekomunikacyjnych i sieciowych. Aktorzy przechodzili przez zaufane połączenia dostawca/klient, modyfikowali trasy, tworzyli tunele GRE/IPsec, używali kontenerów urządzeń oraz włączali SPAN/RSPAN/ERSPAN lub natywne przechwytywanie pakietów w celu pozyskiwania danych uwierzytelniających i ruchu klientów.<sup>[[13]](#references)</sup>

**Wpływ na prywatność.** Przejęty router jest jednocześnie przekaźnikiem, punktem obserwacyjnym i zaufanym uczestnikiem sieci. Prywatne połączenia między sieciami mogą omijać mechanizmy kontroli zaprojektowane z myślą o publicznym Internecie, a mirroring ruchu umożliwia pozyskiwanie danych uwierzytelniających bez wdrażania agenta na endpointach.

**Co ujawnia tę aktywność.** Różnice w konfiguracji, nieoczekiwane administrowanie przez SNMP/SSH/web, nowe trasy statyczne i tunele, sesje mirroringu, kontenery Guest Shell, pliki PCAP, zmiany miejsc docelowych TACACS+/RADIUS oraz wyłączone logowanie. Ostrzeżenie podkreśla, że niektóre routery pośredniczące nie należały do wcześniej nazwanych publicznych botnetów, dlatego brak znanych wskaźników ORB nie świadczył o braku kompromitacji.

**Wniosek obronny.** Stosuj administrację out-of-band, centralne logi konfiguracji i uwierzytelniania, kontrole integralności podpisanych obrazów i środowiska uruchomieniowego, ograniczenia egressu interfejsów zarządzania oraz alerty dotyczące zmian tras, mirroringu, tuneli i AAA. Przed eksmisją obejmij zakresem podejrzanej kompromitacji zaufanych partnerów.

## UNC3886 RedPenguin: pasywne backdoory na routerach ISP

**Ustalenia publiczne.** Mandiant przypisał grupie UNC3886 niestandardowe backdoory wywodzące się z TINYSHELL na wycofanych z eksploatacji routerach Juniper MX. Zestaw obejmował implanty aktywne i pasywne, nazwy naśladujące legalne daemony, wyłączanie logów, process injection do zaufanego procesu, funkcję SOCKS proxy oraz infrastrukturę ocenianą jako węzły stagingowe ORB. Warianty pasywne analizowały pakiety za pomocą `libpcap` i aktywowały się dopiero po wykryciu magicznego wzorca; jeden z nich mógł przełączyć się na aktywne połączenie zwrotne podane w triggerze.<sup>[[14]](#references)</sup>

**Wpływ na prywatność.** Pasywny implant nie emituje okresowego beacona, który można wykryć. Dzieli porty i ruch z prawdziwym urządzeniem sieciowym, aktywuje się na krótko i może przekazywać ruch przez ORB zamiast łączyć się bezpośrednio z ostatecznym kontrolerem.

**Co ujawnia tę aktywność.** Analiza pamięci, różnice między kodem zapisanym na dysku a uruchomionym, nieoczekiwane filtry przechwytywania pakietów i zachowanie socketów, nazwy procesów i plików tylko przybliżenie naśladujące legalne daemony, administracja przez serwery terminalowe, brakujące logi oraz dwuetapowa relacja między węzłami stagingowymi a backendowym kontrolerem.

**Wniosek obronny.** Pozyskuj pamięć oraz dowody z systemu plików i konfiguracji, porównuj procesy i moduły ze znanym dobrym obrazem, monitoruj użycie przechwytywania pakietów i filtrów socketów, zabezpieczaj serwery terminalowe zarządzania oraz wymieniaj sprzęt sieciowy EOL. Brak wykrytego beacona wychodzącego nie oznacza, że środowisko jest bezpieczne.

## APT29: Tor domain fronting

**Ustalenia publiczne.** MITRE odnotowuje, że APT29 używa transportu pluggable `meek` w Tor do domain-frontingu ruchu C2. Zewnętrzna nazwa TLS wyglądała jak dozwolona domena hostowana przez CDN, podczas gdy wewnętrzny host HTTP wybierał właściwą trasę.<sup>[[6]](#references)</sup>

**Wpływ na prywatność.** Obserwator filtrujący mógł widzieć wspólny front/CDN zamiast wewnętrznego miejsca docelowego, a zablokowanie go groziło szkodami ubocznymi.

**Co ujawnia tę aktywność.** CDN może obserwować rozbieżność routingu, a obrońca dysponujący widocznością endpointu lub zgodnym z prawem wglądem w TLS może korelować proces, authority, czas trwania połączenia, wzorzec bajtów i późniejszą aktywność. Zmiany zasad dostawcy mogą wyłączyć tę technikę.

**Wniosek obronny.** Nie polegaj wyłącznie na allowliście SNI. Wymuszaj egress świadomy aplikacji, porównuj tożsamości TLS i HTTP tam, gdzie są widoczne, oraz łącz zdarzenie sieciowe z procesem, który je zainicjował.

## APT41 i inne dead-drop resolvers

**Ustalenia publiczne.** MITRE opisuje wykorzystywanie przez APT41 legalnych serwisów, w tym GitHub, Pastebin, Microsoft TechNet, Cloudflare i forów społecznościowych, do publikowania lub pobierania informacji C2. Inne narzędzia powiązane z aktorami państwowymi podobnie wykorzystywały posty, dokumenty i media społecznościowe.<sup>[[7]](#references)</sup>

**Wpływ na prywatność.** Binarne zawiera legalny serwis/obiekt zamiast stabilnego adresu C2. Obiekt można edytować w celu rotacji infrastruktury, a początkowe żądanie zlewa się z typowym ruchem TLS.

**Co ujawnia tę aktywność.** Identyfikator obiektu lub konta jest stabilny; rzadko używane procesy wielokrotnie go pobierają; zawartość jest dekodowana; następnie nawiązywane jest drugie połączenie wychodzące. Rekordy konta dostawcy i API mogą powiązać publikację z operatorem.

**Wniosek obronny.** Zachowuj pełne ścieżki proxy, identyfikatory obiektów i lineage procesów na endpointach. Zdarzenie na poziomie domeny, takie jak „połączono z GitHub”, jest zbyt ogólne.

## Turla: C2 z adresem satelitarnym

**Ustalenia publiczne.** Kaspersky poinformował, że Turla wykorzystywała niezaszyfrowane transmisje downstream ze starszych jednokierunkowych usług internetowych DVB-S. Operator znajdujący się w zasięgu satelity mógł wybrać adres legalnego abonenta i odbierać odpowiedzi transmitowane do tego adresu, przez co C2 wyglądało na hostowane za pośrednictwem dostawcy satelitarnego w innym regionie.<sup>[[8]](#references)</sup>

**Wpływ na prywatność.** Pozorny adres serwera nie identyfikował odbiorcy, a konwencjonalne procesy zajęcia hostingu i WHOIS były mniej użyteczne.

**Co ujawnia tę aktywność.** Aktor nadal potrzebował ścieżki żądania wychodzącego, routing był asymetryczny, legalny abonent nie inicjował wymiany C2, a dochodzenie RF i u dostawcy mogło zawęzić obszar odbioru.

**Wniosek obronny.** Traktuj geolokalizację jako jedną z hipotez. Weryfikuj symetrię ścieżki, RTT, właściciela routingu oraz to, czy rzekomy endpoint mógł faktycznie dostarczyć obserwowaną usługę.

## Cyclops Blink i VPNFilter: urządzenia brzegowe jako trwała osłona

**Ustalenia publiczne.** Ostrzeżenie NCSC/CISA/FBI/NSA z 2022 roku opisywało modularne malware Cyclops Blink grupy Sandworm na urządzeniach WatchGuard, wdrażane trwale jako aktualizacja firmware i zdolne do dodawania modułów. DOJ osobno opisał wcześniejszy botnet APT28 VPNFilter obejmujący routery i urządzenia NAS jako zdolny do gromadzenia danych wywiadowczych, działań destrukcyjnych i błędnego przypisywania aktywności.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Wpływ na prywatność.** Urządzenia brzegowe są stale online, zaufane jako infrastruktura i słabo objęte przez EDR. Trwałość w firmware może przetrwać zwykłe ponowne uruchomienie i przekształcić urządzenie ofiary w przekaźnik lub punkt kontroli.

**Co ujawnia tę aktywność.** Integralność firmware, protokół implantu specyficzny dla dostawcy, nieoczekiwana ekspozycja zarządzania, zmiany konfiguracji i beacony wychodzące. Urządzenia brzegowe muszą być traktowane jako obiekty badań forensycznych, a nie jako niewidoczna infrastruktura pośrednia.

## KRLD: warstwy tożsamości, sieci i finansów

**Ustalenia publiczne.** Sprawy DOJ opisują pracowników KRLD zdobywających zdalne zatrudnienie przy użyciu fałszywych lub skradzionych danych tożsamości i VPN, otrzymujących kryptowaluty, dzielących transfery, wymieniających aktywa i łańcuchy, używających NFT oraz mieszających środki. Inne sprawy opisują traderów OTC i firmy fasadowe zamieniające skradzione kryptowaluty na zakupy. Treasury i FBI publicznie powiązały środki Lazarus/TraderTraitor z mixerami oraz zidentyfikowały adresy pochodzące z dużych kradzieży.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Wpływ na prywatność.** Nie chodzi tu o „prywatną monetę”. Jest to łańcuch obejmujący wiele domen: persona i zdalny dostęp ukrywają lokalizację pracownika; kryptowaluty przenoszą wartość; layering rozbija proste narracje transakcyjne; traderzy OTC i firmy fasadowe tworzą połączenie z towarami i fiat.

**Co ujawnia tę aktywność.** Anomalie dotyczące pracodawcy i urządzenia, ponownie wykorzystywani pośrednicy, ciągłość czasu i wartości w blockchainie, rekordy giełd i bridge'ów, adresy objęte sankcjami, tożsamość konta oraz rekordy wysyłek i firm ponownie łączą cały łańcuch.

**Wniosek obronny.** Zespoły rekrutacji, IAM, endpointów, payroll, blockchain i sanctions potrzebują wspólnego modelu sprawy. Więcej informacji znajduje się w [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Wzorce wspólne dla przypadków

| Wzorzec | Przykłady APT | Adaptacja obrońcy |
|---|---|---|
| Wyjściem jest kolejna ofiara | APT28/Moobot, Volt Typhoon/KV, ORBs | zbadaj i napraw wyjście; nie utożsamiaj go z lokalizacją aktora |
| Mechanizmy kontroli różnią się w zależności od granicy | APT28 nearest neighbor | zapewnij dostępowi wewnętrznemu/bezprzewodowemu taki sam poziom zapewnienia tożsamości jak dostępowi z Internetu |
| Legalny serwis jest warstwą routingu | APT29, APT41 | zachowuj kontekst obiektu/ścieżki/procesu, a nie tylko domenę docelową |
| Urządzenia brzegowe nie mają telemetry | KV, Moobot, Cyclops Blink, ORBs | centralizuj logi konfiguracji/uwierzytelniania/przepływów i weryfikuj firmware/inwentarz |
| Infrastructure jest współdzielona i krótkotrwała | ORBs powiązane z Chinami | grupuj zachowania/topologię i śledź zmiany ról w czasie |
| Wiele słabych separacji składa się w całość | persony KRLD + VPN + crypto + OTC | łącz dowody dotyczące tożsamości, urządzenia, sieci, płatności i sfery fizycznej |

## References

- [1] [Volexity — Atak Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Zakłócenie działania botnetu routerów Moobot kontrolowanego przez GRU](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Zakłócenie działania botnetu PRC KV](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Aktorzy PRC przejmują i utrzymują trwały dostęp do krytycznej infrastruktury USA](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Aktorzy szpiegowscy powiązani z Chinami używają sieci ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satelitarna Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Ostrzeżenie dotyczące Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Zakłócenie działania VPNFilter grupy APT28](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Przedstawiciel Banku Handlu Zagranicznego KRLD oskarżony o spiski dotyczące prania kryptowalut](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sankcje wobec Blender.io i środki Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Przeciwdziałanie przejmowaniu sieci na całym świecie przez aktorów sponsorowanych przez Chiny](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 atakuje routery Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
