# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Це поширені macOS services для віддаленого доступу до них.\
You can enable/disable these services in `System Settings` --> `Sharing`

- **VNC**, known as “Screen Sharing” (tcp:5900)
- **SSH**, called “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), or “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, known as “Remote Apple Event” (tcp:3031)

Check if any is enabled running:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Перелічення конфігурації спільного доступу локально

Коли ви вже маєте локальне виконання коду на Mac, **перевіряйте налаштований стан**, а не лише listening sockets. `systemsetup` і `launchctl` зазвичай показують, чи сервіс увімкнено адміністративно, тоді як `kickstart` і `system_profiler` допомагають підтвердити фактичну ARD/Sharing конфігурацію:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) — це покращена версія [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), адаптована для macOS, з додатковими можливостями. Помітна вразливість у ARD полягає в його методі автентифікації для пароля керування екраном, який використовує лише перші 8 символів пароля, що робить його вразливим до [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) за допомогою інструментів на кшталт Hydra або [GoRedShell](https://github.com/ahhh/GoRedShell/), оскільки немає стандартних лімітів на кількість спроб.

Уразливі екземпляри можна виявити за допомогою скрипта **nmap** `vnc-info`. Сервіси, що підтримують `VNC Authentication (2)`, особливо схильні до brute force attacks через обрізання пароля до 8 символів.

Щоб увімкнути ARD для різних адміністративних завдань, як-от privilege escalation, GUI access або моніторинг користувачів, використовуйте таку команду:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD забезпечує універсальні рівні керування, включно зі спостереженням, спільним керуванням і повним керуванням, причому сесії зберігаються навіть після зміни пароля користувача. Воно дає змогу надсилати Unix-команди напряму, виконуючи їх як root для адміністративних користувачів. Планування завдань і Remote Spotlight search є помітними можливостями, що полегшують віддалений, малопомітний пошук чутливих файлів на кількох машинах.

З точки зору оператора, **Monterey 12.1+ змінив workflows remote-enablement** у керованих fleet. Якщо ви вже контролюєте MDM жертви, команду Apple `EnableRemoteDesktop` часто є найчистішим способом активувати функціональність remote desktop на новіших системах. Якщо у вас уже є foothold на хості, `kickstart` і далі корисний для перевірки або переналаштування привілеїв ARD із командного рядка.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple називає цю функцію **Remote Application Scripting** у сучасному System Settings. Під капотом вона відкриває **Apple Event Manager** віддалено через **EPPC** на **TCP/3031** за допомогою сервісу `com.apple.AEServer`. Palo Alto Unit 42 знову звернула на це увагу як на практичний примітив **macOS lateral movement**, оскільки дійсні облікові дані плюс увімкнений сервіс RAE дають оператору змогу керувати скриптованими застосунками на віддаленому Mac.

Корисні перевірки:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Якщо у вас уже є admin/root на цілі й ви хочете це увімкнути:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Базовий тест з’єднання з іншого Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
На практиці випадок зловживання не обмежується Finder. Будь-яка **scriptable application**, яка приймає потрібні Apple events, стає віддаленою атакувальною поверхнею, що робить RAE особливо цікавою після крадіжки credentials в internal macOS networks.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Incorrect session rendering could cause the *wrong* desktop or window to be transmitted, resulting in leakage of sensitive information|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|A user with screen sharing access may be able to view **another user's screen** because of a state-management issue|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

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

Bonjour, технологія, створена Apple, дозволяє **devices on the same network to detect each other's offered services**. Також відома як Rendezvous, **Zero Configuration**, або Zeroconf, вона дає змогу пристрою приєднатися до TCP/IP network, **automatically choose an IP address**, і broadcast свої services іншим network devices.

Zero Configuration Networking, provided by Bonjour, ensures that devices can:

- **Automatically obtain an IP Address** even in the absence of a DHCP server.
- Perform **name-to-address translation** without requiring a DNS server.
- **Discover services** available on the network.

Devices using Bonjour will assign themselves an **IP address from the 169.254/16 range** and verify its uniqueness on the network. Macs maintain a routing table entry for this subnet, verifiable via `netstat -rn | grep 169`.

For DNS, Bonjour utilizes the **Multicast DNS (mDNS) protocol**. mDNS operates over **port 5353/UDP**, employing **standard DNS queries** but targeting the **multicast address 224.0.0.251**. This approach ensures that all listening devices on the network can receive and respond to the queries, facilitating the update of their records.

Upon joining the network, each device self-selects a name, typically ending in **.local**, which may be derived from the hostname or randomly generated.

Service discovery within the network is facilitated by **DNS Service Discovery (DNS-SD)**. Leveraging the format of DNS SRV records, DNS-SD uses **DNS PTR records** to enable the listing of multiple services. A client seeking a specific service will request a PTR record for `<Service>.<Domain>`, receiving in return a list of PTR records formatted as `<Instance>.<Service>.<Domain>` if the service is available from multiple hosts.

The `dns-sd` utility can be employed for **discovering and advertising network services**. Here are some examples of its usage:

### Searching for SSH Services

To search for SSH services on the network, the following command is used:
```bash
dns-sd -B _ssh._tcp
```
Ця команда ініціює пошук служб \_ssh.\_tcp і виводить такі деталі, як timestamp, flags, interface, domain, service type та instance name.

### Advertising an HTTP Service

Щоб advertise HTTP service, ви можете використати:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ця команда реєструє HTTP service під назвою "Index" на порту 80 з шляхом `/index.html`.

Щоб потім шукати HTTP services у мережі:
```bash
dns-sd -B _http._tcp
```
Коли service запускається, він оголошує свою доступність усім devices у subnet, multicasting свою присутність. Devices, які цікавляться цими services, не мають надсилати requests, а просто слухають ці оголошення.

Для більш зручного інтерфейсу, app **Discovery - DNS-SD Browser**, доступний в Apple App Store, може візуалізувати services, які пропонуються у вашій local network.

Альтернативно, можна написати custom scripts, щоб browsе та discover services за допомогою library `python-zeroconf`. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script демонструє створення service browser для services `_http._tcp.local.`, виводячи added або removed services:
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

У macOS-мережах Bonjour часто є найпростішим способом знайти **remote administration surfaces** без прямого контакту з ціллю. Apple Remote Desktop сам по собі може виявляти клієнтів через Bonjour, тож ті самі дані виявлення корисні й для attacker.
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
Для ширших технік **mDNS spoofing, impersonation, and cross-subnet discovery**, дивіться окрему сторінку:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Перерахування Bonjour у мережі

* **Nmap NSE** – виявляє сервіси, які рекламує один хост:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Скрипт `dns-service-discovery` надсилає запит `_services._dns-sd._udp.local`, а потім перераховує кожен тип сервісу, який рекламується.

* **mdns_recon** – Python tool, який сканує цілі діапазони в пошуках *misconfigured* mDNS responders, що відповідають на unicast-запити (корисно для пошуку пристроїв, доступних через subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Це поверне хости, які надають SSH через Bonjour поза локальним link.

### Міркування щодо безпеки та нещодавні вразливості (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Рекомендації щодо mitigation**

1. Обмежте UDP 5353 до *link-local* scope – блокуйте його або встановлюйте rate-limit на wireless controllers, routers, і host-based firewalls.
2. Повністю вимкніть Bonjour на системах, яким не потрібне service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Для середовищ, де Bonjour потрібен всередині, але ніколи не повинен виходити за межі network boundaries, використовуйте обмеження профілю *AirPlay Receiver* (MDM) або mDNS proxy.
4. Увімкніть **System Integrity Protection (SIP)** і тримайте macOS в актуальному стані – обидві вразливості вище були виправлені швидко, але для повного захисту покладалися на увімкнений SIP.

### Вимкнення Bonjour

Якщо є занепокоєння щодо безпеки або інші причини вимкнути Bonjour, його можна вимкнути за допомогою такої команди:
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
