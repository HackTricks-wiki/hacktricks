# macOS Usługi sieciowe i protokoły

{{#include ../../banners/hacktricks-training.md}}

## Usługi zdalnego dostępu

To są powszechne usługi macOS, aby uzyskać do nich zdalny dostęp.\
Możesz włączyć/wyłączyć te usługi w `Ustawienia systemowe` --> `Udostępnianie`

- **VNC**, znane jako “Udostępnianie ekranu” (tcp:5900)
- **SSH**, nazywane “Zdalnym logowaniem” (tcp:22)
- **Apple Remote Desktop** (ARD), lub “Zarządzanie zdalne” (tcp:3283, tcp:5900)
- **AppleEvent**, znane jako “Zdalne zdarzenie Apple” (tcp:3031)

Sprawdź, czy którakolwiek z nich jest włączona, uruchamiając:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) to ulepszona wersja [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) dostosowana do macOS, oferująca dodatkowe funkcje. Znaczną podatnością w ARD jest metoda uwierzytelniania dla hasła ekranu kontrolnego, która wykorzystuje tylko pierwsze 8 znaków hasła, co czyni ją podatną na [atak siłowy](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) za pomocą narzędzi takich jak Hydra lub [GoRedShell](https://github.com/ahhh/GoRedShell/), ponieważ nie ma domyślnych limitów szybkości.

Podatne instancje można zidentyfikować za pomocą skryptu `vnc-info` w **nmap**. Usługi wspierające `VNC Authentication (2)` są szczególnie podatne na ataki siłowe z powodu skrócenia hasła do 8 znaków.

Aby włączyć ARD do różnych zadań administracyjnych, takich jak eskalacja uprawnień, dostęp GUI lub monitorowanie użytkowników, użyj następującego polecenia:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD zapewnia wszechstronne poziomy kontroli, w tym obserwację, wspólną kontrolę i pełną kontrolę, z sesjami utrzymującymi się nawet po zmianie hasła użytkownika. Umożliwia bezpośrednie wysyłanie poleceń Unix, wykonując je jako root dla użytkowników administracyjnych. Planowanie zadań i zdalne wyszukiwanie Spotlight to istotne funkcje, ułatwiające zdalne, niskoodpadowe wyszukiwania wrażliwych plików na wielu maszynach.

#### Ostatnie luki w Screen-Sharing / ARD (2023-2025)

| Rok | CVE | Komponent | Wpływ | Naprawione w |
|-----|-----|-----------|-------|--------------|
|2023|CVE-2023-42940|Screen Sharing|Nieprawidłowe renderowanie sesji mogło spowodować przesyłanie *niewłaściwego* pulpitu lub okna, co skutkowało wyciekiem wrażliwych informacji|macOS Sonoma 14.2.1 (grudzień 2023) |
|2024|CVE-2024-23296|launchservicesd / login|Obejście ochrony pamięci jądra, które można połączyć po udanym zdalnym logowaniu (aktywnie wykorzystywane w terenie)|macOS Ventura 13.6.4 / Sonoma 14.4 (marzec 2024) |

**Wskazówki dotyczące wzmocnienia bezpieczeństwa**

* Wyłącz *Screen Sharing*/*Remote Management*, gdy nie jest to ściśle wymagane.
* Utrzymuj macOS w pełni zaktualizowany (Apple zazwyczaj dostarcza poprawki bezpieczeństwa dla ostatnich trzech głównych wydań).
* Używaj **Silnego Hasła** *i* egzekwuj opcję *„VNC viewers may control screen with password”* **wyłączoną**, gdy to możliwe.
* Umieść usługę za VPN zamiast narażać TCP 5900/3283 na Internet.
* Dodaj regułę zapory aplikacji, aby ograniczyć `ARDAgent` do lokalnej podsieci:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Protokół Bonjour

Bonjour, technologia zaprojektowana przez Apple, umożliwia **urządzeniom w tej samej sieci wykrywanie oferowanych przez siebie usług**. Znana również jako Rendezvous, **Zero Configuration** lub Zeroconf, pozwala urządzeniu dołączyć do sieci TCP/IP, **automatycznie wybrać adres IP** i ogłaszać swoje usługi innym urządzeniom w sieci.

Zero Configuration Networking, zapewniane przez Bonjour, gwarantuje, że urządzenia mogą:

- **Automatycznie uzyskać adres IP** nawet w przypadku braku serwera DHCP.
- Wykonywać **tłumaczenie nazwy na adres** bez potrzeby posiadania serwera DNS.
- **Odkrywać usługi** dostępne w sieci.

Urządzenia korzystające z Bonjour przypisują sobie **adres IP z zakresu 169.254/16** i weryfikują jego unikalność w sieci. Maci utrzymują wpis w tabeli routingu dla tej podsieci, co można zweryfikować za pomocą `netstat -rn | grep 169`.

Dla DNS Bonjour wykorzystuje **protokół Multicast DNS (mDNS)**. mDNS działa na **porcie 5353/UDP**, stosując **standardowe zapytania DNS**, ale kierując je do **adresu multicast 224.0.0.251**. Takie podejście zapewnia, że wszystkie nasłuchujące urządzenia w sieci mogą odbierać i odpowiadać na zapytania, ułatwiając aktualizację swoich rekordów.

Po dołączeniu do sieci każde urządzenie samodzielnie wybiera nazwę, zazwyczaj kończącą się na **.local**, która może pochodzić z nazwy hosta lub być generowana losowo.

Odkrywanie usług w sieci ułatwia **DNS Service Discovery (DNS-SD)**. Wykorzystując format rekordów DNS SRV, DNS-SD używa **rekordów DNS PTR** do umożliwienia listowania wielu usług. Klient poszukujący konkretnej usługi zażąda rekordu PTR dla `<Service>.<Domain>`, otrzymując w zamian listę rekordów PTR sformatowanych jako `<Instance>.<Service>.<Domain>`, jeśli usługa jest dostępna z wielu hostów.

Narzędzie `dns-sd` może być używane do **odkrywania i ogłaszania usług sieciowych**. Oto kilka przykładów jego użycia:

### Wyszukiwanie usług SSH

Aby wyszukać usługi SSH w sieci, używa się następującego polecenia:
```bash
dns-sd -B _ssh._tcp
```
To polecenie inicjuje przeszukiwanie usług \_ssh.\_tcp i wyświetla szczegóły, takie jak znacznik czasu, flagi, interfejs, domena, typ usługi i nazwa instancji.

### Reklamowanie usługi HTTP

Aby zareklamować usługę HTTP, możesz użyć:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
To polecenie rejestruje usługę HTTP o nazwie "Index" na porcie 80 z ścieżką `/index.html`.

Aby następnie wyszukać usługi HTTP w sieci:
```bash
dns-sd -B _http._tcp
```
Kiedy usługa się uruchamia, ogłasza swoją dostępność wszystkim urządzeniom w podsieci, multicastując swoją obecność. Urządzenia zainteresowane tymi usługami nie muszą wysyłać żądań, wystarczy, że nasłuchują tych ogłoszeń.

Dla bardziej przyjaznego interfejsu, aplikacja **Discovery - DNS-SD Browser** dostępna w Apple App Store może wizualizować usługi oferowane w twojej lokalnej sieci.

Alternatywnie, można napisać niestandardowe skrypty do przeglądania i odkrywania usług za pomocą biblioteki `python-zeroconf`. Skrypt [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demonstruje tworzenie przeglądarki usług dla usług `_http._tcp.local.`, drukując dodane lub usunięte usługi:
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
### Enumerowanie Bonjour w sieci

* **Nmap NSE** – odkrywanie usług reklamowanych przez pojedynczy host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Skrypt `dns-service-discovery` wysyła zapytanie `_services._dns-sd._udp.local`, a następnie enumeruje każdy reklamowany typ usługi.

* **mdns_recon** – narzędzie Python, które skanuje całe zakresy w poszukiwaniu *błędnie skonfigurowanych* responderów mDNS, które odpowiadają na zapytania unicast (przydatne do znajdowania urządzeń dostępnych przez subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

To zwróci hosty udostępniające SSH przez Bonjour poza lokalnym łączem.

### Rozważania dotyczące bezpieczeństwa i ostatnie luki (2024-2025)

| Rok | CVE | Powaga | Problem | Poprawione w |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Średni|Błąd logiczny w *mDNSResponder* pozwalał na wyzwolenie **odmowy usługi** przez spreparowany pakiet|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (wrzesień 2024) |
|2025|CVE-2025-31222|Wysoki|Problem z poprawnością w *mDNSResponder* mógł być wykorzystany do **lokalnego podwyższenia uprawnień**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (maj 2025) |

**Wskazówki dotyczące łagodzenia**

1. Ogranicz UDP 5353 do *zakresu lokalnego* – zablokuj lub ogranicz jego przepustowość na kontrolerach bezprzewodowych, routerach i zaporach ogniowych na hoście.
2. Całkowicie wyłącz Bonjour na systemach, które nie wymagają odkrywania usług:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. W środowiskach, gdzie Bonjour jest wymagany wewnętrznie, ale nigdy nie powinien przekraczać granic sieci, użyj ograniczeń profilu *AirPlay Receiver* (MDM) lub proxy mDNS.
4. Włącz **Ochronę integralności systemu (SIP)** i utrzymuj macOS w aktualizacji – obie powyższe luki zostały szybko załatane, ale polegały na włączeniu SIP dla pełnej ochrony.

### Wyłączanie Bonjour

Jeśli istnieją obawy dotyczące bezpieczeństwa lub inne powody, aby wyłączyć Bonjour, można to zrobić za pomocą następującego polecenia:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Odniesienia

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
