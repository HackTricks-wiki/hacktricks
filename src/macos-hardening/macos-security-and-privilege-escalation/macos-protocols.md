# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Usługi zdalnego dostępu

To są popularne usługi macOS do zdalnego dostępu.\
Możesz włączyć/wyłączyć te usługi w `System Settings` --> `Sharing`

- **VNC**, znane jako “Screen Sharing” (tcp:5900)
- **SSH**, nazywane “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), lub “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, znane jako “Remote Apple Event” (tcp:3031)

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
### Wyliczanie lokalnej konfiguracji udostępniania

Gdy masz już lokalne wykonanie kodu na Macu, **sprawdź skonfigurowany stan**, a nie tylko nasłuchujące sockety. `systemsetup` i `launchctl` zwykle pokazują, czy usługa jest administracyjnie włączona, natomiast `kickstart` i `system_profiler` pomagają potwierdzić faktyczną konfigurację ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) to ulepszona wersja [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) dostosowana do macOS, oferująca dodatkowe funkcje. Istotną podatnością w ARD jest metoda uwierzytelniania dla hasła control screen password, która używa tylko pierwszych 8 znaków hasła, przez co jest podatna na [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) z użyciem narzędzi takich jak Hydra lub [GoRedShell](https://github.com/ahhh/GoRedShell/), ponieważ nie ma domyślnych limitów rate.

Podatne instancje można zidentyfikować za pomocą skryptu `vnc-info` z **nmap**. Usługi obsługujące `VNC Authentication (2)` są szczególnie podatne na brute force attacks z powodu 8-znakowego obcięcia hasła.

Aby włączyć ARD do różnych zadań administracyjnych, takich jak privilege escalation, dostęp do GUI lub monitorowanie użytkowników, użyj następującego polecenia:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD zapewnia wszechstronne poziomy kontroli, w tym observation, shared control i full control, a sesje utrzymują się nawet po zmianie hasła użytkownika. Umożliwia wysyłanie poleceń Unix bezpośrednio, wykonując je jako root dla użytkowników administracyjnych. Planowanie zadań i Remote Spotlight search to istotne funkcje, ułatwiające zdalne, mało inwazyjne wyszukiwanie wrażliwych plików na wielu maszynach.

Z perspektywy operatora, **Monterey 12.1+ zmieniło workflows zdalnego włączania** w zarządzanych fleetach. Jeśli już kontrolujesz MDM ofiary, polecenie Apple `EnableRemoteDesktop` jest często najczystszym sposobem aktywacji funkcji remote desktop na nowszych systemach. Jeśli masz już foothold na hoście, `kickstart` nadal jest przydatny do sprawdzenia lub ponownej konfiguracji uprawnień ARD z linii poleceń.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple nazywa tę funkcję **Remote Application Scripting** w nowoczesnym System Settings. Pod spodem udostępnia zdalnie **Apple Event Manager** przez **EPPC** na **TCP/3031** za pośrednictwem usługi `com.apple.AEServer`. Palo Alto Unit 42 ponownie wskazało to jako praktyczny mechanizm **macOS lateral movement**, ponieważ poprawne credentials plus włączona usługa RAE pozwalają operatorowi sterować aplikacjami obsługującymi skrypty na zdalnym Macu.

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Jeśli już masz admin/root na celu i chcesz to włączyć:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Podstawowy test łączności z innego Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
W praktyce ten przypadek nadużycia nie ogranicza się do Finder. Każda **scriptable application**, która akceptuje wymagane Apple events, staje się zdalną powierzchnią ataku, co czyni RAE szczególnie interesującym po kradzieży poświadczeń w wewnętrznych sieciach macOS.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Nieprawidłowe renderowanie sesji mogło spowodować przesłanie *niewłaściwego* pulpitu lub okna, co skutkowało wyciekiem wrażliwych informacji|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Użytkownik z dostępem do screen sharing mógł być w stanie zobaczyć **ekran innego użytkownika** z powodu problemu ze stanem aplikacji|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* Disable *Screen Sharing*/*Remote Management* when not strictly required.
* Keep macOS fully patched (Apple generally ships security fixes for the last three major releases).
* Use a **Strong Password** *and* enforce the *“VNC viewers may control screen with password”* option **disabled** when possible.
* Put the service behind a VPN instead of exposing TCP 5900/3283 to the Internet.
* Add an Application Firewall rule to limit `ARDAgent` to the local subnet:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, technologia zaprojektowana przez Apple, pozwala **urządzeniom w tej samej sieci wykrywać oferowane przez siebie usługi**. Znana także jako Rendezvous, **Zero Configuration** lub Zeroconf, umożliwia urządzeniu dołączenie do sieci TCP/IP, **automatyczne wybranie adresu IP** oraz rozgłaszanie swoich usług do innych urządzeń sieciowych.

Zero Configuration Networking, zapewniane przez Bonjour, gwarantuje, że urządzenia mogą:

- **Automatycznie uzyskać adres IP** nawet bez serwera DHCP.
- Wykonywać **tłumaczenie nazw na adresy** bez potrzeby serwera DNS.
- **Odkrywać usługi** dostępne w sieci.

Urządzenia używające Bonjour przypiszą sobie **adres IP z zakresu 169.254/16** i sprawdzą jego unikalność w sieci. Maci utrzymują wpis w tabeli routingu dla tej podsieci, co można zweryfikować przez `netstat -rn | grep 169`.

Do DNS, Bonjour wykorzystuje **Multicast DNS (mDNS) protocol**. mDNS działa na **porcie 5353/UDP**, używając **standardowych zapytań DNS**, ale kierując je na **adres multicast 224.0.0.251**. Takie podejście zapewnia, że wszystkie nasłuchujące urządzenia w sieci mogą otrzymywać i odpowiadać na zapytania, ułatwiając aktualizację ich rekordów.

Po dołączeniu do sieci każde urządzenie samo wybiera nazwę, zwykle kończącą się na **.local**, która może być wyprowadzona z hostname albo wygenerowana losowo.

Odnajdywanie usług w sieci jest realizowane przez **DNS Service Discovery (DNS-SD)**. Wykorzystując format rekordów DNS SRV, DNS-SD używa **rekordów DNS PTR** do umożliwienia listowania wielu usług. Klient szukający konkretnej usługi zażąda rekordu PTR dla `<Service>.<Domain>`, otrzymując w odpowiedzi listę rekordów PTR w formacie `<Instance>.<Service>.<Domain>`, jeśli usługa jest dostępna z wielu hostów.

Narzędzie `dns-sd` może być użyte do **odnajdywania i reklamowania usług sieciowych**. Oto kilka przykładów jego użycia:

### Searching for SSH Services

Aby wyszukać usługi SSH w sieci, używa się następującego polecenia:
```bash
dns-sd -B _ssh._tcp
```
To polecenie inicjuje wyszukiwanie usług \_ssh.\_tcp i wyświetla szczegóły takie jak znacznik czasu, flagi, interfejs, domena, typ usługi oraz nazwa instancji.

### Reklamowanie usługi HTTP

Aby reklamować usługę HTTP, możesz użyć:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
To polecenie rejestruje usługę HTTP o nazwie "Index" na porcie 80 ze ścieżką `/index.html`.

Aby następnie wyszukać usługi HTTP w sieci:
```bash
dns-sd -B _http._tcp
```
Gdy usługa startuje, ogłasza swoją dostępność wszystkim urządzeniom w podsieci, rozgłaszając swoją obecność za pomocą multicastu. Urządzenia zainteresowane tymi usługami nie muszą wysyłać żądań, a jedynie nasłuchują tych ogłoszeń.

Aby uzyskać bardziej przyjazny interfejs, aplikacja **Discovery - DNS-SD Browser** dostępna w Apple App Store może wizualizować usługi oferowane w Twojej lokalnej sieci.

Alternatywnie można napisać własne skrypty do przeglądania i wykrywania usług za pomocą biblioteki `python-zeroconf`. Skrypt [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) pokazuje tworzenie przeglądarki usług dla usług `_http._tcp.local.`, wypisując dodane lub usunięte usługi:
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
### macOS-specific Bonjour hunting

W sieciach macOS Bonjour często jest najłatwiejszym sposobem na znalezienie **remote administration surfaces** bez bezpośredniego dotykania celu. Sam Apple Remote Desktop może wykrywać klientów przez Bonjour, więc te same dane wykrywania są przydatne dla atakującego.
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
Dla szerszych technik **mDNS spoofing, impersonation i cross-subnet discovery**, sprawdź dedykowaną stronę:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerating Bonjour over the network

* **Nmap NSE** – discover services advertised by a single host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Skrypt `dns-service-discovery` wysyła zapytanie `_services._dns-sd._udp.local`, a następnie enumeruje każdy reklamowany typ usługi.

* **mdns_recon** – narzędzie Python, które skanuje całe zakresy w poszukiwaniu *misconfigured* mDNS responderów, które odpowiadają na zapytania unicast (przydatne do znajdowania urządzeń osiągalnych poza lokalnym linkiem, przez subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

To zwróci hosty udostępniające SSH przez Bonjour poza lokalnym linkiem.

### Security considerations & recent vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|Błąd logiczny w *mDNSResponder* pozwalał spreparowanemu pakietowi wywołać **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|Problem z poprawnością w *mDNSResponder* mógł zostać wykorzystany do **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. Ogranicz UDP 5353 do zakresu *link-local* – blokuj go lub stosuj rate limiting na kontrolerach wireless, routerach i w host-based firewalls.
2. Całkowicie wyłącz Bonjour na systemach, które nie wymagają service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. W środowiskach, gdzie Bonjour jest wymagany wewnętrznie, ale nigdy nie może przekraczać granic sieci, użyj ograniczeń profilu *AirPlay Receiver* (MDM) albo proxy mDNS.
4. Włącz **System Integrity Protection (SIP)** i aktualizuj macOS na bieżąco – obie powyższe podatności zostały szybko załatane, ale pełna ochrona zależała od włączonego SIP.

### Disabling Bonjour

Jeśli istnieją obawy dotyczące bezpieczeństwa lub inne powody, aby wyłączyć Bonjour, można to zrobić za pomocą następującego polecenia:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
