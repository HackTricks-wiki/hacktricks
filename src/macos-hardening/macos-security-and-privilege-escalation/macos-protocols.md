# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Dies sind die gängigen macOS-Dienste, um remote auf sie zuzugreifen.\
Du kannst diese Dienste in `System Settings` --> `Sharing` aktivieren/deaktivieren

- **VNC**, bekannt als “Screen Sharing” (tcp:5900)
- **SSH**, genannt “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), oder “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, bekannt als “Remote Apple Event” (tcp:3031)

Prüfe, ob einer aktiviert ist, indem du Folgendes ausführst:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Lokales Auflisten der Sharing-Konfiguration

Wenn du bereits lokale Codeausführung auf einem Mac hast, **prüfe den konfigurierten Zustand**, nicht nur die lauschten Sockets. `systemsetup` und `launchctl` zeigen dir normalerweise, ob der Dienst administrativ aktiviert ist, während `kickstart` und `system_profiler` helfen, die effektive ARD/Sharing-Konfiguration zu bestätigen:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) ist eine erweiterte Version von [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), die auf macOS zugeschnitten ist und zusätzliche Funktionen bietet. Eine bemerkenswerte Schwachstelle in ARD ist die Authentifizierungsmethode für das control screen password, bei der nur die ersten 8 Zeichen des Passworts verwendet werden, was es anfällig für [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) mit Tools wie Hydra oder [GoRedShell](https://github.com/ahhh/GoRedShell/) macht, da es keine standardmäßigen Rate Limits gibt.

Verwundbare Instanzen können mit dem `vnc-info`-Script von **nmap** identifiziert werden. Dienste, die `VNC Authentication (2)` unterstützen, sind aufgrund der 8-Zeichen-Kürzung des Passworts besonders anfällig für brute force attacks.

Um ARD für verschiedene administrative Aufgaben wie privilege escalation, GUI access oder user monitoring zu aktivieren, verwende den folgenden Befehl:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bietet vielseitige Kontrollstufen, einschließlich Beobachtung, geteilte Kontrolle und volle Kontrolle, wobei Sitzungen selbst nach Passwortänderungen des Users bestehen bleiben. Es ermöglicht das direkte Senden von Unix-Befehlen und führt sie für administrative Users als root aus. Aufgabenplanung und die Remote Spotlight-Suche sind bemerkenswerte Features, die ferngesteuerte, wenig invasive Suchen nach sensiblen Dateien über mehrere Maschinen hinweg ermöglichen.

Aus Operator-Perspektive hat **Monterey 12.1+ die Workflows zur Remote-Aktivierung** in verwalteten Fleets geändert. Wenn du bereits das MDM des Opfers kontrollierst, ist Apples `EnableRemoteDesktop`-Befehl oft der sauberste Weg, um die Remote-Desktop-Funktionalität auf neueren Systemen zu aktivieren. Wenn du bereits einen foothold auf dem Host hast, ist `kickstart` weiterhin nützlich, um ARD-Privilegien über die Command Line zu prüfen oder neu zu konfigurieren.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple nennt dieses Feature in modernen System Settings **Remote Application Scripting**. Unter der Haube stellt es den **Apple Event Manager** remote über **EPPC** auf **TCP/3031** über den Dienst `com.apple.AEServer` bereit. Palo Alto Unit 42 hob es erneut als praktische **macOS lateral movement**-Primitive hervor, da gültige Credentials plus ein aktivierter RAE-Dienst es einem Operator ermöglichen, skriptfähige Anwendungen auf einem entfernten Mac zu steuern.

Nützliche Checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Wenn du bereits admin/root auf dem Zielsystem hast und es aktivieren möchtest:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Grundlegender Konnektivitätstest von einem anderen Mac aus:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
In der Praxis ist der Missbrauchsfall nicht auf Finder beschränkt. Jede **scriptable application**, die die erforderlichen Apple events akzeptiert, wird zu einer Remote-Angriffsfläche, was RAE besonders interessant nach Credential Theft in internen macOS-Netzwerken macht.

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

Bonjour, eine von Apple entwickelte Technologie, ermöglicht es **Geräten im selben Netzwerk, die angebotenen Dienste der jeweils anderen zu erkennen**. Auch bekannt als Rendezvous, **Zero Configuration** oder Zeroconf, erlaubt sie einem Gerät, sich einem TCP/IP-Netzwerk anzuschließen, **automatisch eine IP-Adresse zu wählen** und seine Dienste an andere Netzwerkgeräte zu senden.

Zero Configuration Networking, bereitgestellt durch Bonjour, stellt sicher, dass Geräte:

- **Automatisch eine IP Address erhalten** können, auch wenn kein DHCP server vorhanden ist.
- **Namens-zu-Adresse-Übersetzung** durchführen können, ohne einen DNS server zu benötigen.
- **Dienste entdecken** können, die im Netzwerk verfügbar sind.

Geräte, die Bonjour verwenden, weisen sich selbst eine **IP address aus dem 169.254/16-Bereich** zu und überprüfen deren Eindeutigkeit im Netzwerk. Macs behalten einen Routing-Table-Eintrag für dieses Subnetz bei, der mit `netstat -rn | grep 169` überprüft werden kann.

Für DNS nutzt Bonjour das **Multicast DNS (mDNS)-Protokoll**. mDNS läuft über **port 5353/UDP**, verwendet **standard DNS queries** und richtet sich an die **multicast address 224.0.0.251**. Dieser Ansatz stellt sicher, dass alle lauschenden Geräte im Netzwerk die Queries empfangen und beantworten können, wodurch die Aktualisierung ihrer Records erleichtert wird.

Nach dem Beitritt zum Netzwerk wählt sich jedes Gerät selbst einen Namen, typischerweise endend auf **.local**, der vom Hostname abgeleitet oder zufällig generiert sein kann.

Die Service Discovery innerhalb des Netzwerks wird durch **DNS Service Discovery (DNS-SD)** ermöglicht. Unter Nutzung des Formats von DNS SRV records verwendet DNS-SD **DNS PTR records**, um die Auflistung mehrerer Dienste zu ermöglichen. Ein Client, der einen bestimmten Dienst sucht, fragt einen PTR record für `<Service>.<Domain>` an und erhält im Gegenzug eine Liste von PTR records im Format `<Instance>.<Service>.<Domain>`, wenn der Dienst von mehreren Hosts bereitgestellt wird.

Das `dns-sd`-Tool kann zum **Entdecken und Bewerben von network services** verwendet werden. Hier sind einige Beispiele für seine Nutzung:

### Searching for SSH Services

Um nach SSH-Diensten im Netzwerk zu suchen, wird der folgende Befehl verwendet:
```bash
dns-sd -B _ssh._tcp
```
Dieser Befehl startet die Suche nach \_ssh.\_tcp-Diensten und gibt Details wie Zeitstempel, Flags, Schnittstelle, Domäne, Diensttyp und Instanzname aus.

### Einen HTTP-Service bewerben

Um einen HTTP-Service zu bewerben, kannst du Folgendes verwenden:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Dieser Befehl registriert einen HTTP-Dienst namens "Index" auf Port 80 mit einem Pfad von `/index.html`.

Um dann im Netzwerk nach HTTP-Diensten zu suchen:
```bash
dns-sd -B _http._tcp
```
Wenn ein Dienst startet, kündigt er seine Verfügbarkeit allen Geräten im Subnetz an, indem er seine Präsenz per Multicast sendet. Geräte, die an diesen Diensten interessiert sind, müssen keine Requests senden, sondern lauschen einfach auf diese Ankündigungen.

Für eine benutzerfreundlichere Oberfläche kann die App **Discovery - DNS-SD Browser** aus dem Apple App Store die auf deinem lokalen Netzwerk angebotenen Dienste visualisieren.

Alternativ können benutzerdefinierte Skripte geschrieben werden, um Dienste mit der `python-zeroconf`-Bibliothek zu durchsuchen und zu entdecken. Das [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) Skript zeigt das Erstellen eines Service-Browsers für `_http._tcp.local.` Dienste und gibt hinzugefügte oder entfernte Dienste aus:
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
### macOS-spezifische Bonjour-Suche

In macOS-Netzwerken ist Bonjour oft der einfachste Weg, um **Remote-Administrationsoberflächen** zu finden, ohne das Ziel direkt anzufassen. Apple Remote Desktop selbst kann Clients über Bonjour entdecken, daher sind dieselben Erkennungsdaten auch für einen Angreifer nützlich.
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
Für breitere **mDNS spoofing, impersonation, and cross-subnet discovery**-Techniken siehe die dedizierte Seite:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Bonjour im Netzwerk auflisten

* **Nmap NSE** – Services eines einzelnen Hosts entdecken:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Das `dns-service-discovery`-Script sendet eine `_services._dns-sd._udp.local`-Query und listet anschließend jeden angekündigten Service-Typ auf.

* **mdns_recon** – Python-Tool, das ganze Bereiche scannt und nach *misconfigured* mDNS-Respondern sucht, die Unicast-Queries beantworten (nützlich, um Geräte zu finden, die über Subnets/WAN erreichbar sind):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Dies gibt Hosts zurück, die SSH via Bonjour außerhalb des lokalen Links exponieren.

### Sicherheitsaspekte & aktuelle Schwachstellen (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. UDP 5353 auf *link-local* Scope beschränken – auf Wireless-Controllern, Routern und hostbasierten Firewalls blockieren oder rate-limiten.
2. Bonjour auf Systemen vollständig deaktivieren, die keine Service Discovery benötigen:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Für Umgebungen, in denen Bonjour intern benötigt wird, aber niemals Netzwerkgrenzen überschreiten darf, *AirPlay Receiver*-Profileinschränkungen (MDM) oder einen mDNS-Proxy verwenden.
4. **System Integrity Protection (SIP)** aktivieren und macOS aktuell halten – beide oben genannten Schwachstellen wurden schnell gepatcht, setzten für vollständigen Schutz aber darauf voraus, dass SIP aktiviert ist.

### Bonjour deaktivieren

Wenn es aus Sicherheitsgründen oder anderen Gründen nötig ist, Bonjour zu deaktivieren, kann es mit dem folgenden Befehl abgeschaltet werden:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referenzen

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
