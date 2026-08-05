# Usługi sieciowe i protokoły macOS

{{#include ../../banners/hacktricks-training.md}}

## Usługi zdalnego dostępu

Oto typowe usługi macOS umożliwiające zdalny dostęp.\
Możesz włączać i wyłączać te usługi w `System Settings` --> `Sharing`

- **VNC**, znane jako „Screen Sharing” (tcp:5900)
- **SSH**, nazywane „Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD) lub „Remote Management” (tcp:3283, tcp:5900)
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
### Lokalne enumerowanie konfiguracji udostępniania

Gdy masz już lokalne wykonywanie kodu na Macu, **sprawdź skonfigurowany stan**, a nie tylko nasłuchujące gniazda. `systemsetup` i `launchctl` zwykle informują, czy usługa jest włączona administracyjnie, natomiast `kickstart` i `system_profiler` pomagają potwierdzić efektywną konfigurację ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) to rozszerzona wersja [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) dostosowana do systemu macOS i oferująca dodatkowe funkcje. Istotna podatność w ARD dotyczy metody uwierzytelniania hasła ekranu sterowania, która używa tylko pierwszych 8 znaków hasła, przez co jest podatna na [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) z użyciem narzędzi takich jak Hydra lub [GoRedShell](https://github.com/ahhh/GoRedShell/), ponieważ nie ma domyślnych limitów liczby prób.<sup>[3]</sup>

Podatne instancje można identyfikować za pomocą skryptu `vnc-info` programu **nmap**. Usługi obsługujące `VNC Authentication (2)` są szczególnie podatne na brute force attacks z powodu obcinania haseł do 8 znaków.

Aby włączyć ARD do różnych zadań administracyjnych, takich jak privilege escalation, dostęp do GUI lub monitorowanie użytkowników, użyj następującego polecenia:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD zapewnia wszechstronne poziomy kontroli, w tym obserwację, współdzieloną kontrolę i pełną kontrolę, a sesje pozostają aktywne nawet po zmianie hasła użytkownika. Umożliwia bezpośrednie wysyłanie poleceń Unix oraz wykonywanie ich jako root w przypadku użytkowników administracyjnych. Planowanie zadań i Remote Spotlight search to istotne funkcje, umożliwiające zdalne wyszukiwanie wrażliwych plików na wielu maszynach przy niewielkim wpływie na ich działanie.

Z perspektywy operatora **Monterey 12.1+ zmienił workflows zdalnego włączania** w zarządzanych flotach. Jeśli masz już kontrolę nad MDM ofiary, polecenie Apple `EnableRemoteDesktop` jest często najczystszym sposobem aktywowania funkcji zdalnego pulpitu w nowszych systemach. Jeśli masz już foothold na hoście, `kickstart` nadal jest przydatny do sprawdzania lub rekonfigurowania uprawnień ARD z poziomu command line.

#### Apple Screen Sharing (RFB 003.889 / security type 36) — pre-auth file-copy abuse

Najnowsze badania nad `screensharingd` wykazały, że Apple Screen Sharing nie zawsze korzysta wyłącznie z klasycznego uwierzytelniania VNC: nowsze buildy obsługują **RFB `003.889`** i reklamują **security type `36`**, w którym **SRP** najpierw uwierzytelnia sesję, a **ChaCha20-Poly1305** jest instalowany dopiero po pomyślnym wykonaniu `ccsrp_server_verify_session`. W publicznym opisie podano, że błąd został naprawiony w **macOS Tahoe 26.6** (**27 lipca 2026 r.**).<sup>[8][9]</sup>

Warto zapamiętać schemat **stale-status parser bypass**: po pomyślnym odczycie 4-bajtowej długości każda gałąź dotycząca zbyt dużego rozmiaru lub błędu musi zwrócić nowy błąd. W podatnych buildach długość ramki SRP w formacie big-endian **`>= 32768`** powoduje, że ścieżka odrzucenia ponownie wykorzystuje poprzedni status powodzenia `NetBufferRead` (`0`), przez co caller ustawia sesję jako uwierzytelnioną, mimo że nie wykonano proof hasła i nie zainstalowano transportowego szyfrowania. Ponieważ nieodczytane bajty pozostają we współdzielonym socket buffer, attacker może **spipeline'ować malformed dane SRP oraz wiadomości RFB po uwierzytelnieniu w tym samym TCP burst** i doprowadzić do ich sparsowania jako **cleartext authenticated traffic**.<sup>[8]</sup>

Po ominięciu mechanizmu Apple proprietary **file-copy** message **`0x22`** staje się **root file read/write primitive**, ponieważ `screensharingd` działa jako root:<sup>[8]</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: odczyt dowolnych plików
- `kind=2` / `StartFileReceive`: zapis dowolnych plików
- Różne wartości `sid` pozwalają potokować kilka transakcji w jednym połączeniu
- W `kind=101` (`NewItem`) ustaw bajt `14` / `arg[0]` na `0x01` dla zwykłego pliku, offset payloadu `+42` na **niezerowy** rozmiar pliku w formacie big-endian, a offset payloadu `+0x5a` na żądany tryb Unix (`0600`, jeśli celem jest crontab)

Interesujące pivots po zapisie w ścieżkach z prawem zapisu obejmują **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** oraz **`/var/root/.ssh/authorized_keys`**. **SIP nie zatrzymuje auth bypass ani odczytu plików jako root**, ale blokuje niektóre cele zapisu, takie jak **`/var/at`**, dlatego wykonanie oparte na cron działa tylko przy wyłączonym SIP. Na hostach z domyślnie włączonym SIP należy myśleć raczej o **„zapisie pliku jako root do uprzywilejowanych plików automatycznie przetwarzanych”** niż o natychmiastowym wykonaniu kodu.<sup>[8]</sup>

Kolejna pułapka SRP z tych samych badań: serwery muszą sprawdzać **`A mod N != 0`** (zgodnie z RFC 5054), a nie tylko `A > 0`. Akceptacja **`A = N`** może wymusić wyzerowanie shared secret i podważyć weryfikację hasła.<sup>[8][10]</sup>

**Pomysły na wykrywanie**

- Sesje typu Security `36`, w których długość pierwszej ramki SRP wynosi **`>= 32768`**
- Sesje, które zaczynają przetwarzać cleartextowy ruch kopiowania plików **`0x22`** przed pomyślnym przeprowadzeniem SRP proof / instalacją cipher
- Powtarzające się krótkotrwałe próby połączenia z **TCP/5900** oraz wiele wartości `sid` file-copy w jednym burst
- Nieoczekiwane utworzenie **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** lub **`/var/root/.ssh/authorized_keys`** po wystawieniu Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Apple nazywa tę funkcję **Remote Application Scripting** w nowoczesnych System Settings. W praktyce udostępnia ona zdalnie **Apple Event Manager** przez **EPPC** na **TCP/3031**, za pośrednictwem usługi `com.apple.AEServer`. Palo Alto Unit 42 ponownie zwróciło na nią uwagę jako na praktyczny prymityw **macOS lateral movement**, ponieważ prawidłowe credentials oraz włączona usługa RAE pozwalają operatorowi sterować skryptowalnymi aplikacjami na zdalnym Macu.<sup>[6]</sup>

Przydatne sprawdzenia:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Jeśli masz już uprawnienia admin/root na celu i chcesz je włączyć:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Podstawowy test łączności z innego Maca:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
W praktyce przypadek nadużycia nie ogranicza się do Findera. Każda **scriptable application**, która akceptuje wymagane Apple events, staje się zdalną powierzchnią ataku, co sprawia, że RAE jest szczególnie interesujące po kradzieży poświadczeń w wewnętrznych sieciach macOS.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Nieprawidłowe renderowanie sesji mogło spowodować przesyłanie *niewłaściwego* pulpitu lub okna, prowadząc do wycieku poufnych informacji|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Użytkownik z dostępem do Screen Sharing mógł być w stanie wyświetlić **ekran innego użytkownika** z powodu problemu z zarządzaniem stanem|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Wskazówki dotyczące hardeningu**

* Wyłącz *Screen Sharing*/*Remote Management*, gdy nie są bezwzględnie wymagane.
* Utrzymuj macOS w pełni zaktualizowany (Apple zazwyczaj udostępnia poprawki bezpieczeństwa dla trzech ostatnich głównych wersji).
* Używaj **Strong Password** i, gdy to możliwe, pozostaw wyłączoną opcję *“VNC viewers may control screen with password”*.
* Umieść usługę za VPN-em zamiast wystawiać TCP 5900/3283 do Internetu.
* Dodaj regułę Application Firewall ograniczającą `ARDAgent` do lokalnej podsieci:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Protokół Bonjour

Bonjour, technologia zaprojektowana przez Apple, umożliwia **urządzeniom w tej samej sieci wykrywanie oferowanych przez siebie usług**. Znany również jako Rendezvous, **Zero Configuration** lub Zeroconf, pozwala urządzeniu dołączyć do sieci TCP/IP, **automatycznie wybrać adres IP** i rozgłaszać swoje usługi innym urządzeniom sieciowym.

Zero Configuration Networking, zapewniany przez Bonjour, gwarantuje, że urządzenia mogą:

- **Automatycznie uzyskać adres IP**, nawet przy braku serwera DHCP.
- Wykonywać **tłumaczenie nazw na adresy** bez konieczności używania serwera DNS.
- **Wykrywać usługi** dostępne w sieci.

Urządzenia korzystające z Bonjour przypisują sobie **adres IP z zakresu 169.254/16** i sprawdzają jego unikalność w sieci. Maci utrzymują wpis w tabeli routingu dla tej podsieci, który można zweryfikować za pomocą `netstat -rn | grep 169`.

W przypadku DNS Bonjour wykorzystuje **protokół Multicast DNS (mDNS)**. mDNS działa przez **port 5353/UDP**, używając **standardowych zapytań DNS**, ale kierując je do **adresu multicast 224.0.0.251**. Dzięki temu wszystkie nasłuchujące urządzenia w sieci mogą odbierać zapytania i na nie odpowiadać, co ułatwia aktualizowanie ich rekordów.

Po dołączeniu do sieci każde urządzenie samodzielnie wybiera nazwę, zwykle kończącą się na **.local**, która może być utworzona na podstawie hostname'u lub wygenerowana losowo.

Wykrywanie usług w sieci jest realizowane za pomocą **DNS Service Discovery (DNS-SD)**. Wykorzystując format rekordów DNS SRV, DNS-SD używa **rekordów DNS PTR** do umożliwienia wyświetlania wielu usług. Klient poszukujący określonej usługi zażąda rekordu PTR dla `<Service>.<Domain>`, otrzymując w odpowiedzi listę rekordów PTR w formacie `<Instance>.<Service>.<Domain>`, jeśli usługa jest dostępna z wielu hostów.

Narzędzie `dns-sd` może być używane do **wykrywania i reklamowania usług sieciowych**. Oto kilka przykładów jego użycia:

### Wyszukiwanie usług SSH

Aby wyszukać usługi SSH w sieci, używa się następującego polecenia:
```bash
dns-sd -B _ssh._tcp
```
To polecenie inicjuje wyszukiwanie usług \_ssh.\_tcp i wyświetla szczegóły, takie jak znacznik czasu, flagi, interfejs, domena, typ usługi oraz nazwa instancji.

### Reklamowanie usługi HTTP

Aby zareklamować usługę HTTP, możesz użyć:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
To polecenie rejestruje usługę HTTP o nazwie „Index” na porcie 80 ze ścieżką `/index.html`.

Aby następnie wyszukać usługi HTTP w sieci:
```bash
dns-sd -B _http._tcp
```
Gdy usługa zostaje uruchomiona, ogłasza swoją dostępność wszystkim urządzeniom w podsieci, rozsyłając multicastem informacje o swojej obecności. Urządzenia zainteresowane tymi usługami nie muszą wysyłać żądań, lecz mogą po prostu nasłuchiwać tych ogłoszeń.

Aby zapewnić bardziej przyjazny interfejs, aplikacja **Discovery - DNS-SD Browser**, dostępna w Apple App Store, może wizualizować usługi oferowane w sieci lokalnej.

Alternatywnie można napisać własne skrypty do przeglądania i wykrywania usług za pomocą biblioteki `python-zeroconf`. Skrypt [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) pokazuje, jak utworzyć service browser dla usług `_http._tcp.local.`, wyświetlając dodane lub usunięte usługi:
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
### Wyszukiwanie usług Bonjour specyficzne dla macOS

W sieciach macOS Bonjour jest często najłatwiejszym sposobem na znalezienie **powierzchni zdalnej administracji** bez bezpośredniego kontaktu z celem. Sam Apple Remote Desktop może wykrywać klientów za pośrednictwem Bonjour, więc te same dane dotyczące wykrywania są przydatne dla attackera.
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

### Enumerating Bonjour przez sieć

* **Nmap NSE** – wykrywanie usług reklamowanych przez pojedynczy host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Skrypt `dns-service-discovery` wysyła zapytanie `_services._dns-sd._udp.local`, a następnie enumeruje każdy reklamowany typ usługi.

* **mdns_recon** – narzędzie Python skanujące całe zakresy w poszukiwaniu *misconfigured* responderów mDNS, które odpowiadają na zapytania unicast (przydatne do znajdowania urządzeń dostępnych across subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Zwróci to hosty udostępniające SSH przez Bonjour poza lokalnym łączem.

### Kwestie bezpieczeństwa i najnowsze vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|Błąd logiczny w *mDNSResponder* pozwalał spreparowanemu pakietowi wywołać **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|Problem z poprawnością działania *mDNSResponder* mógł zostać wykorzystany do **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Wskazówki dotyczące mitigation**

1. Ogranicz UDP 5353 do zakresu *link-local* – blokuj go lub ograniczaj jego rate na kontrolerach sieci bezprzewodowych, routerach i host-based firewallach.
2. Wyłącz Bonjour całkowicie w systemach, które nie wymagają service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. W środowiskach, w których Bonjour jest wymagany wewnętrznie, ale nie może przekraczać granic sieci, użyj ograniczeń profilu *AirPlay Receiver* (MDM) lub proxy mDNS.
4. Włącz **System Integrity Protection (SIP)** i aktualizuj macOS – obie powyższe vulnerabilities zostały szybko załatane, ale pełna ochrona zależała od włączenia SIP.

### Wyłączanie Bonjour

Jeśli istnieją obawy dotyczące bezpieczeństwa lub inne powody, aby wyłączyć Bonjour, można to zrobić za pomocą następującego polecenia:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referencje

- [1] [Podręcznik hakera Mac](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [Sztuka malware na Macu, tom I: Analiza - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Ruch boczny na macOS: unikalne i popularne techniki oraz przykłady z rzeczywistych ataków](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Wsparcie Apple - Informacje o zawartości zabezpieczeń systemu macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Wsparcie Apple - Informacje o zawartości zabezpieczeń systemu macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Używanie protokołu Secure Remote Password (SRP) do uwierzytelniania TLS](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
