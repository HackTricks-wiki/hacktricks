# macOS Netzwerkdienste & Protokolle

{{#include ../../banners/hacktricks-training.md}}

## Fernzugriffsservices

Dies sind die gängigen macOS-Dienste, um sie remote zuzugreifen.\
Sie können diese Dienste in `Systemeinstellungen` --> `Freigabe` aktivieren/deaktivieren.

- **VNC**, bekannt als „Bildschirmfreigabe“ (tcp:5900)
- **SSH**, genannt „Remote Login“ (tcp:22)
- **Apple Remote Desktop** (ARD), oder „Remote Management“ (tcp:3283, tcp:5900)
- **AppleEvent**, bekannt als „Remote Apple Event“ (tcp:3031)

Überprüfen Sie, ob einer aktiviert ist, indem Sie Folgendes ausführen:
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

Apple Remote Desktop (ARD) ist eine erweiterte Version von [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), die für macOS angepasst wurde und zusätzliche Funktionen bietet. Eine bemerkenswerte Schwachstelle in ARD ist die Authentifizierungsmethode für das Passwort des Steuerbildschirms, die nur die ersten 8 Zeichen des Passworts verwendet, was es anfällig für [Brute-Force-Angriffe](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) mit Tools wie Hydra oder [GoRedShell](https://github.com/ahhh/GoRedShell/) macht, da es keine standardmäßigen Ratenlimits gibt.

Anfällige Instanzen können mit dem `vnc-info`-Skript von **nmap** identifiziert werden. Dienste, die `VNC Authentication (2)` unterstützen, sind aufgrund der Truncation des Passworts auf 8 Zeichen besonders anfällig für Brute-Force-Angriffe.

Um ARD für verschiedene administrative Aufgaben wie Privilegieneskalation, GUI-Zugriff oder Benutzerüberwachung zu aktivieren, verwenden Sie den folgenden Befehl:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bietet vielseitige Kontrollstufen, einschließlich Beobachtung, gemeinsamer Kontrolle und vollständiger Kontrolle, wobei Sitzungen auch nach Änderungen des Benutzerpassworts bestehen bleiben. Es ermöglicht das direkte Senden von Unix-Befehlen und deren Ausführung als Root für administrative Benutzer. Die Aufgabenplanung und die Remote Spotlight-Suche sind bemerkenswerte Funktionen, die entfernte, ressourcenschonende Suchen nach sensiblen Dateien auf mehreren Maschinen erleichtern.

#### Aktuelle Screen-Sharing / ARD-Sicherheitsanfälligkeiten (2023-2025)

| Jahr | CVE | Komponente | Auswirkung | Behebt in |
|------|-----|-----------|------------|-----------|
|2023|CVE-2023-42940|Screen Sharing|Falsche Sitzungsdarstellung könnte dazu führen, dass der *falsche* Desktop oder das falsche Fenster übertragen wird, was zu einem Leck sensibler Informationen führt|macOS Sonoma 14.2.1 (Dez 2023) |
|2024|CVE-2024-23296|launchservicesd / login|Umgehung des Kernel-Speicherschutzes, die nach einem erfolgreichen Remote-Login verkettet werden kann (aktiv in der Wildnis ausgenutzt)|macOS Ventura 13.6.4 / Sonoma 14.4 (März 2024) |

**Härtungstipps**

* Deaktivieren Sie *Screen Sharing*/*Remote Management*, wenn es nicht unbedingt erforderlich ist.
* Halten Sie macOS vollständig gepatcht (Apple liefert in der Regel Sicherheitsupdates für die letzten drei Hauptversionen).
* Verwenden Sie ein **starkes Passwort** *und* setzen Sie die Option *„VNC-Viewer dürfen den Bildschirm mit Passwort steuern“* **möglichst auf deaktiviert**.
* Stellen Sie den Dienst hinter ein VPN, anstatt TCP 5900/3283 dem Internet auszusetzen.
* Fügen Sie eine Regel für die Anwendungsfirewall hinzu, um `ARDAgent` auf das lokale Subnetz zu beschränken:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour-Protokoll

Bonjour, eine von Apple entwickelte Technologie, ermöglicht es **Geräten im selben Netzwerk, die angebotenen Dienste des jeweils anderen zu erkennen**. Auch bekannt als Rendezvous, **Zero Configuration** oder Zeroconf, ermöglicht es einem Gerät, einem TCP/IP-Netzwerk beizutreten, **automatisch eine IP-Adresse auszuwählen** und seine Dienste an andere Netzwerkgeräte zu übertragen.

Zero Configuration Networking, bereitgestellt von Bonjour, stellt sicher, dass Geräte:

- **Automatisch eine IP-Adresse erhalten** können, selbst in Abwesenheit eines DHCP-Servers.
- **Namens-zu-Adresse-Übersetzung** durchführen können, ohne einen DNS-Server zu benötigen.
- **Dienste** im Netzwerk entdecken können.

Geräte, die Bonjour verwenden, weisen sich selbst eine **IP-Adresse aus dem Bereich 169.254/16** zu und überprüfen deren Einzigartigkeit im Netzwerk. Macs führen einen Routingtabelleneintrag für dieses Subnetz, der über `netstat -rn | grep 169` überprüft werden kann.

Für DNS verwendet Bonjour das **Multicast DNS (mDNS)-Protokoll**. mDNS arbeitet über **Port 5353/UDP** und verwendet **Standard-DNS-Abfragen**, die jedoch an die **Multicast-Adresse 224.0.0.251** gerichtet sind. Dieser Ansatz stellt sicher, dass alle hörenden Geräte im Netzwerk die Abfragen empfangen und darauf reagieren können, was die Aktualisierung ihrer Einträge erleichtert.

Beim Beitritt zum Netzwerk wählt sich jedes Gerät selbst einen Namen, der typischerweise mit **.local** endet und entweder vom Hostnamen abgeleitet oder zufällig generiert wird.

Die Dienstentdeckung im Netzwerk wird durch **DNS Service Discovery (DNS-SD)** erleichtert. Unter Verwendung des Formats von DNS SRV-Einträgen nutzt DNS-SD **DNS PTR-Einträge**, um die Auflistung mehrerer Dienste zu ermöglichen. Ein Client, der einen bestimmten Dienst sucht, fordert einen PTR-Eintrag für `<Service>.<Domain>` an und erhält im Gegenzug eine Liste von PTR-Einträgen im Format `<Instance>.<Service>.<Domain>`, wenn der Dienst von mehreren Hosts verfügbar ist.

Das `dns-sd`-Dienstprogramm kann verwendet werden, um **Netzwerkdienste zu entdecken und zu bewerben**. Hier sind einige Beispiele für seine Verwendung:

### Suche nach SSH-Diensten

Um nach SSH-Diensten im Netzwerk zu suchen, wird der folgende Befehl verwendet:
```bash
dns-sd -B _ssh._tcp
```
Dieser Befehl initiiert das Durchsuchen nach \_ssh.\_tcp-Diensten und gibt Details wie Zeitstempel, Flags, Schnittstelle, Domäne, Diensttyp und Instanznamen aus.

### Werbung für einen HTTP-Dienst

Um einen HTTP-Dienst zu bewerben, können Sie Folgendes verwenden:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Dieser Befehl registriert einen HTTP-Dienst mit dem Namen "Index" auf Port 80 mit einem Pfad von `/index.html`.

Um dann nach HTTP-Diensten im Netzwerk zu suchen:
```bash
dns-sd -B _http._tcp
```
Wenn ein Dienst startet, kündigt er seine Verfügbarkeit für alle Geräte im Subnetz an, indem er seine Präsenz multicastet. Geräte, die an diesen Diensten interessiert sind, müssen keine Anfragen senden, sondern hören einfach auf diese Ankündigungen.

Für eine benutzerfreundlichere Oberfläche kann die **Discovery - DNS-SD Browser** App, die im Apple App Store verfügbar ist, die angebotenen Dienste in Ihrem lokalen Netzwerk visualisieren.

Alternativ können benutzerdefinierte Skripte geschrieben werden, um Dienste mit der `python-zeroconf` Bibliothek zu durchsuchen und zu entdecken. Das [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) Skript demonstriert die Erstellung eines Dienstebrowsers für `_http._tcp.local.` Dienste, der hinzugefügte oder entfernte Dienste ausgibt:
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
### Auflisten von Bonjour über das Netzwerk

* **Nmap NSE** – Dienste entdecken, die von einem einzelnen Host beworben werden:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Das `dns-service-discovery`-Skript sendet eine `_services._dns-sd._udp.local`-Abfrage und listet dann jeden beworbenen Diensttyp auf.

* **mdns_recon** – Python-Tool, das gesamte Bereiche scannt, um *fehlerhaft konfigurierte* mDNS-Responder zu finden, die auf Unicast-Abfragen antworten (nützlich, um Geräte zu finden, die über Subnetze/WAN erreichbar sind):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Dies gibt Hosts zurück, die SSH über Bonjour außerhalb des lokalen Links bereitstellen.

### Sicherheitsüberlegungen & aktuelle Schwachstellen (2024-2025)

| Jahr | CVE | Schweregrad | Problem | Patch in |
|------|-----|-------------|---------|----------|
|2024|CVE-2024-44183|Mittel|Ein Logikfehler in *mDNSResponder* erlaubte es, ein manipuliertes Paket auszulösen, das eine **Dienstverweigerung** verursachte|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|Hoch|Ein Korrektheitsproblem in *mDNSResponder* könnte für **lokale Privilegieneskalation** ausgenutzt werden|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (Mai 2025) |

**Minderungsrichtlinien**

1. Beschränken Sie UDP 5353 auf *link-lokalen* Bereich – blockieren oder drosseln Sie es auf drahtlosen Controllern, Routern und hostbasierten Firewalls.
2. Deaktivieren Sie Bonjour vollständig auf Systemen, die keine Dienstentdeckung benötigen:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Für Umgebungen, in denen Bonjour intern erforderlich ist, aber niemals Netzwerkgrenzen überschreiten darf, verwenden Sie *AirPlay Receiver*-Profilbeschränkungen (MDM) oder einen mDNS-Proxy.
4. Aktivieren Sie **System Integrity Protection (SIP)** und halten Sie macOS auf dem neuesten Stand – beide oben genannten Schwachstellen wurden schnell gepatcht, waren jedoch auf die Aktivierung von SIP für den vollständigen Schutz angewiesen.

### Deaktivieren von Bonjour

Wenn Bedenken hinsichtlich der Sicherheit oder andere Gründe bestehen, Bonjour zu deaktivieren, kann es mit dem folgenden Befehl abgeschaltet werden:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referenzen

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
