# Usługi sieciowe i protokoły macOS

{{#include ../../banners/hacktricks-training.md}}

## Usługi zdalnego dostępu

Są to typowe usługi macOS umożliwiające zdalny dostęp.\
Możesz włączać i wyłączać te usługi w `System Settings` --> `Sharing`

- **VNC**, znane jako „Screen Sharing” (tcp:5900)
- **SSH**, nazywane „Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), czyli „Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, znane jako „Remote Apple Event” (tcp:3031)

Sprawdź, czy któraś z nich jest włączona, uruchamiając:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Enumerowanie konfiguracji udostępniania lokalnie

Gdy masz już lokalne wykonanie kodu na Macu, **sprawdź skonfigurowany stan**, a nie tylko nasłuchujące gniazda. `systemsetup` i `launchctl` zwykle informują, czy usługa jest włączona administracyjnie, natomiast `kickstart` i `system_profiler` pomagają potwierdzić faktyczną konfigurację ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) to rozszerzona wersja [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) dostosowana do systemu macOS, oferująca dodatkowe funkcje. Istotna luka w ARD dotyczy metody uwierzytelniania hasła ekranu sterowania, która wykorzystuje tylko pierwsze 8 znaków hasła, przez co jest podatna na [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) z użyciem narzędzi takich jak Hydra lub [GoRedShell](https://github.com/ahhh/GoRedShell/), ponieważ nie ma domyślnych limitów liczby prób.<sup>[[3]](#references)</sup>

Podatne instancje można identyfikować za pomocą skryptu `vnc-info` programu **nmap**. Usługi obsługujące `VNC Authentication (2)` są szczególnie podatne na brute force attacks z powodu obcinania hasła do 8 znaków.

Aby włączyć ARD do różnych zadań administracyjnych, takich jak privilege escalation, dostęp do GUI lub monitorowanie użytkowników, użyj następującego polecenia:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD zapewnia wszechstronne poziomy kontroli, w tym obserwację, współdzieloną kontrolę i pełną kontrolę, a sesje pozostają aktywne nawet po zmianie hasła użytkownika. Umożliwia bezpośrednie wysyłanie poleceń Unix, wykonywanie ich jako root w przypadku użytkowników administracyjnych. Planowanie zadań i zdalne wyszukiwanie za pomocą Remote Spotlight to istotne funkcje, umożliwiające zdalne wyszukiwanie wrażliwych plików na wielu komputerach przy niewielkim wpływie na ich działanie.

Z perspektywy operatora **Monterey 12.1+ zmienił procesy zdalnego włączania funkcji** w zarządzanych flotach. Jeśli masz już kontrolę nad MDM ofiary, polecenie Apple `EnableRemoteDesktop` jest często najczystszym sposobem aktywowania funkcji zdalnego pulpitu w nowszych systemach. Jeśli masz już foothold na hoście, `kickstart` nadal jest przydatny do sprawdzania lub rekonfigurowania uprawnień ARD z poziomu wiersza poleceń.

#### Apple Screen Sharing (RFB 003.889 / security type 36) — nadużycie file-copy przed uwierzytelnieniem

Nowsze badania `screensharingd` wykazały, że Apple Screen Sharing nie zawsze korzysta wyłącznie z klasycznego uwierzytelniania VNC: nowsze buildy obsługują **RFB `003.889`** i reklamują **security type `36`**, w którym **SRP** najpierw przeprowadza uwierzytelnianie, a **ChaCha20-Poly1305** jest instalowany dopiero po pomyślnym wykonaniu `ccsrp_server_verify_session`. Opublikowany opis informuje, że błąd został naprawiony w **macOS Tahoe 26.6** (**27 lipca 2026 r.**).<sup>[[8]](#references)[[9]](#references)</sup>

Warto zapamiętać wzorzec **obejścia parsera nieaktualnego statusu**: po pomyślnym odczytaniu 4-bajtowej długości każda gałąź dotycząca zbyt dużego rozmiaru lub błędu musi zwracać nowy błąd. W podatnych buildach długość ramki SRP w kolejności big-endian **`>= 32768`** powoduje, że ścieżka odrzucenia ponownie wykorzystuje poprzedni pomyślny wynik `NetBufferRead` (`0`), więc wywołujący oznacza sesję jako uwierzytelnioną, mimo że nie przeprowadzono dowodu znajomości hasła i nie zainstalowano kryptografii transportowej. Ponieważ nieodczytane bajty pozostają we współdzielonym buforze gniazda, atakujący może **przesłać potokowo nieprawidłowe dane SRP i wiadomości RFB po uwierzytelnieniu w tym samym burstie TCP**, powodując ich parsowanie jako **jawny, uwierzytelniony ruch**.<sup>[[8]](#references)</sup>

Po obejściu autorskiego komunikatu Apple **file-copy** **`0x22`** staje się **prymitywem odczytu/zapisu plików jako root**, ponieważ `screensharingd` działa jako root:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: odczyt dowolnego pliku
- `kind=2` / `StartFileReceive`: zapis dowolnego pliku
- Różne wartości `sid` pozwalają potokowo wykonywać kilka transakcji w ramach jednego połączenia
- W `kind=101` (`NewItem`) ustaw bajt `14` / `arg[0]` na `0x01` dla zwykłego pliku, offset payloadu `+42` na **niezerowy** rozmiar pliku w kolejności big-endian, a offset payloadu `+0x5a` na żądany tryb Unix (`0600`, jeśli celem jest crontab)

Interesujące pivoty po zapisie na ścieżkach z prawem zapisu obejmują **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** oraz **`/var/root/.ssh/authorized_keys`**. **SIP nie powstrzymuje auth bypass ani odczytu plików jako root**, ale blokuje niektóre cele zapisu, takie jak **`/var/at`**, dlatego wykonywanie oparte na cron działa wyłącznie przy wyłączonym SIP. Na hostach z domyślnie włączonym SIP należy myśleć raczej o **„zapisie pliku jako root do uprzywilejowanych plików automatycznie odczytywanych przez system”** niż o natychmiastowym wykonywaniu kodu.<sup>[[8]](#references)</sup>

Kolejna pułapka SRP z tych samych badań: serwery muszą sprawdzać **`A mod N != 0`** (zgodnie z RFC 5054), a nie tylko `A > 0`. Akceptowanie **`A = N`** może wymusić wyzerowanie wspólnego sekretu i podważyć weryfikację hasła.<sup>[[8]](#references)[[10]](#references)</sup>

**Pomysły na detekcję**

- Sesje typu zabezpieczeń `36`, w których długość pierwszej ramki SRP wynosi **`>= 32768`**
- Sesje, które rozpoczynają przetwarzanie jawnego ruchu kopiowania plików **`0x22`** przed pomyślnym zakończeniem dowodu SRP / instalacją szyfru
- Wielokrotne krótkotrwałe próby połączenia z **TCP/5900** oraz wiele wartości `sid` kopiowania plików w jednym burst
- Nieoczekiwane utworzenie **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** lub **`/var/root/.ssh/authorized_keys`** po udostępnieniu Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Apple określa tę funkcję w nowszych ustawieniach systemowych jako **Remote Application Scripting**. W tle udostępnia ona zdalnie **Apple Event Manager** przez **EPPC** na **TCP/3031**, za pośrednictwem usługi `com.apple.AEServer`. Palo Alto Unit 42 ponownie zwróciło na nią uwagę jako na praktyczny mechanizm **macOS lateral movement**, ponieważ prawidłowe dane uwierzytelniające oraz włączona usługa RAE pozwalają operatorowi sterować aplikacjami obsługującymi skrypty na zdalnym Macu.<sup>[[6]](#references)</sup>

Przydatne testy:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Jeśli masz już uprawnienia administratora/root na celu i chcesz je włączyć:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Podstawowy test łączności z innego Maca:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
W praktyce przypadek nadużycia nie ogranicza się do Findera. Każda **scriptable application**, która akceptuje wymagane Apple events, staje się zdalną powierzchnią ataku, co sprawia, że RAE jest szczególnie interesujące po kradzieży danych uwierzytelniających w wewnętrznych sieciach macOS.

#### Najnowsze podatności Screen-Sharing / ARD (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Nieprawidłowe renderowanie sesji mogło spowodować transmisję *niewłaściwego* pulpitu lub okna, prowadząc do wycieku poufnych informacji|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Użytkownik z dostępem do screen sharing mógł być w stanie wyświetlić **ekran innego użytkownika** z powodu problemu z zarządzaniem stanem|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Wskazówki dotyczące hardeningu**

* Wyłącz *Screen Sharing*/*Remote Management*, gdy nie są bezwzględnie wymagane.
* Utrzymuj macOS w pełni zaktualizowany (Apple zazwyczaj publikuje poprawki bezpieczeństwa dla trzech ostatnich głównych wydań).
* Używaj **Strong Password** i, jeśli to możliwe, pozostaw opcję *“VNC viewers may control screen with password”* **wyłączoną**.
* Umieść usługę za VPN zamiast wystawiać TCP 5900/3283 do Internetu.
* Dodaj regułę Application Firewall ograniczającą `ARDAgent` do lokalnej podsieci:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Protokół Bonjour

Bonjour, technologia zaprojektowana przez Apple, umożliwia **urządzeniom w tej samej sieci wykrywanie oferowanych przez siebie usług**. Znany również jako Rendezvous, **Zero Configuration** lub Zeroconf, pozwala urządzeniu dołączyć do sieci TCP/IP, **automatycznie wybrać adres IP** i rozgłaszać swoje usługi innym urządzeniom sieciowym.

Zero Configuration Networking, zapewniane przez Bonjour, umożliwia urządzeniom:

- **Automatyczne uzyskanie adresu IP**, nawet przy braku serwera DHCP.
- Wykonywanie **tłumaczenia nazwy na adres** bez konieczności używania serwera DNS.
- **Wykrywanie usług** dostępnych w sieci.

Urządzenia korzystające z Bonjour przypisują sobie **adres IP z zakresu 169.254/16** i weryfikują jego unikalność w sieci. Maki utrzymują wpis w tablicy routingu dla tej podsieci, który można zweryfikować za pomocą `netstat -rn | grep 169`.

Do obsługi DNS Bonjour wykorzystuje **protokół Multicast DNS (mDNS)**. mDNS działa przez **port 5353/UDP**, używając **standardowych zapytań DNS**, ale kierując je na **adres multicastowy 224.0.0.251**. Dzięki temu wszystkie nasłuchujące urządzenia w sieci mogą odbierać zapytania i na nie odpowiadać, co ułatwia aktualizację ich rekordów.

Po dołączeniu do sieci każde urządzenie samodzielnie wybiera nazwę, zwykle kończącą się na **.local**, która może być wyprowadzona z hostname'u lub wygenerowana losowo.

Wykrywanie usług w sieci jest realizowane przez **DNS Service Discovery (DNS-SD)**. Wykorzystując format rekordów DNS SRV, DNS-SD używa **rekordów DNS PTR** do umożliwienia wyświetlania wielu usług. Klient poszukujący konkretnej usługi zażąda rekordu PTR dla `<Service>.<Domain>`, otrzymując w odpowiedzi listę rekordów PTR w formacie `<Instance>.<Service>.<Domain>`, jeśli usługa jest dostępna z wielu hostów.

Narzędzie `dns-sd` może służyć do **wykrywania i reklamowania usług sieciowych**. Oto kilka przykładów jego użycia:

### Wyszukiwanie usług SSH

Do wyszukania usług SSH w sieci służy następujące polecenie:
```bash
dns-sd -B _ssh._tcp
```
To polecenie inicjuje wyszukiwanie usług \_ssh.\_tcp i wyświetla szczegóły, takie jak znacznik czasu, flagi, interfejs, domena, typ usługi oraz nazwa instancji.

### Ogłaszanie usługi HTTP

Aby ogłosić usługę HTTP, możesz użyć:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
To polecenie rejestruje usługę HTTP o nazwie „Index” na porcie 80 ze ścieżką `/index.html`.

Aby następnie wyszukać usługi HTTP w sieci:
```bash
dns-sd -B _http._tcp
```
Gdy usługa jest uruchamiana, ogłasza swoją dostępność wszystkim urządzeniom w podsieci, rozsyłając multicastowo informacje o swojej obecności. Urządzenia zainteresowane tymi usługami nie muszą wysyłać żądań, lecz po prostu nasłuchują tych ogłoszeń.

Aby zapewnić bardziej przyjazny interfejs, aplikacja **Discovery - DNS-SD Browser** dostępna w Apple App Store może wizualizować usługi oferowane w sieci lokalnej.

Alternatywnie można napisać własne skrypty do przeglądania i wykrywania usług przy użyciu biblioteki `python-zeroconf`. Skrypt [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) pokazuje, jak utworzyć service browser dla usług `_http._tcp.local.`, wyświetlając dodane lub usunięte usługi:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Polowanie na Bonjour specyficzne dla macOS

W sieciach macOS Bonjour jest często najłatwiejszym sposobem na znalezienie **zdalnych powierzchni administracyjnych** bez bezpośredniego kontaktu z celem. Apple Remote Desktop może samodzielnie wykrywać klientów za pośrednictwem Bonjour, dlatego te same dane wykrywania są przydatne dla atakującego.
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
W przypadku szerszych technik **mDNS spoofing, impersonation i cross-subnet discovery** sprawdź dedykowaną stronę:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerowanie Bonjour w sieci

* **Nmap NSE** – wykrywanie usług reklamowanych przez pojedynczy host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Skrypt `dns-service-discovery` wysyła zapytanie `_services._dns-sd._udp.local`, a następnie enumeruje każdy reklamowany typ usługi.

* **mdns_recon** – narzędzie Python skanujące całe zakresy w poszukiwaniu *błędnie skonfigurowanych* responderów mDNS, które odpowiadają na zapytania unicast (przydatne do znajdowania urządzeń dostępnych między podsieciami/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Zwróci to hosty udostępniające SSH przez Bonjour poza lokalnym łączem.

### Kwestie bezpieczeństwa i najnowsze podatności (2024-2025)

| Rok | CVE | Poziom | Problem | Wersja z poprawką |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Średni|Błąd logiczny w *mDNSResponder* umożliwiał spreparowanemu pakietowi wywołanie **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (wrzesień 2024) |
|2025|CVE-2025-31222|Wysoki|Problem z poprawnością działania w *mDNSResponder* mógł zostać wykorzystany do **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (maj 2025) |

**Wskazówki dotyczące przeciwdziałania**

1. Ogranicz UDP 5353 do zakresu *link-local* – blokuj go lub ograniczaj jego szybkość na kontrolerach sieci bezprzewodowych, routerach i firewallach opartych na hoście.
2. Całkowicie wyłącz Bonjour w systemach, które nie wymagają service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. W środowiskach, w których Bonjour jest wymagany wewnętrznie, ale nie może przekraczać granic sieci, użyj ograniczeń profilu *AirPlay Receiver* (MDM) lub proxy mDNS.
4. Włącz **System Integrity Protection (SIP)** i aktualizuj macOS – obie powyższe podatności zostały szybko załatane, ale pełna ochrona wymagała włączonego SIP.

### Wyłączanie Bonjour

Jeśli istnieją obawy dotyczące bezpieczeństwa lub inne powody, aby wyłączyć Bonjour, można to zrobić za pomocą następującego polecenia:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Odnośniki

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Informacje o zawartości zabezpieczeń systemu macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Informacje o zawartości zabezpieczeń systemu macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Używanie protokołu Secure Remote Password (SRP) do uwierzytelniania TLS](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
