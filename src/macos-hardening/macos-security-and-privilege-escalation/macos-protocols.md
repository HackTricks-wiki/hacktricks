# macOS Netzwerkdienste & Protokolle

{{#include ../../banners/hacktricks-training.md}}

## Fernzugriffsservices

Dies sind die gängigen macOS-Dienste, um sie aus der Ferne zuzugreifen.\
Sie können diese Dienste in `Systemeinstellungen` --> `Freigabe` aktivieren/deaktivieren.

- **VNC**, bekannt als „Bildschirmfreigabe“ (tcp:5900)
- **SSH**, genannt „Remote Login“ (tcp:22)
- **Apple Remote Desktop** (ARD), oder „Remote Management“ (tcp:3283, tcp:5900)
- **AppleEvent**, bekannt als „Remote Apple Event“ (tcp:3031)

Überprüfen Sie, ob einer aktiviert ist, indem Sie Folgendes ausführen:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) ist eine erweiterte Version von [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), die für macOS maßgeschneidert ist und zusätzliche Funktionen bietet. Eine bemerkenswerte Schwachstelle in ARD ist die Authentifizierungsmethode für das Passwort des Steuerbildschirms, die nur die ersten 8 Zeichen des Passworts verwendet, was es anfällig für [Brute-Force-Angriffe](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) mit Tools wie Hydra oder [GoRedShell](https://github.com/ahhh/GoRedShell/) macht, da es keine standardmäßigen Ratenlimits gibt.

Anfällige Instanzen können mit dem `vnc-info`-Skript von **nmap** identifiziert werden. Dienste, die `VNC Authentication (2)` unterstützen, sind aufgrund der Truncation des Passworts auf 8 Zeichen besonders anfällig für Brute-Force-Angriffe.

Um ARD für verschiedene administrative Aufgaben wie Privilegieneskalation, GUI-Zugriff oder Benutzerüberwachung zu aktivieren, verwenden Sie den folgenden Befehl:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bietet vielseitige Kontrollstufen, einschließlich Beobachtung, gemeinsamer Kontrolle und vollständiger Kontrolle, wobei Sitzungen auch nach Änderungen des Benutzerpassworts bestehen bleiben. Es ermöglicht das direkte Senden von Unix-Befehlen und deren Ausführung als Root für administrative Benutzer. Die Aufgabenplanung und die Remote Spotlight-Suche sind bemerkenswerte Funktionen, die entfernte, ressourcenschonende Suchen nach sensiblen Dateien auf mehreren Maschinen erleichtern.

## Bonjour-Protokoll

Bonjour, eine von Apple entwickelte Technologie, ermöglicht es **Geräten im selben Netzwerk, die angebotenen Dienste gegenseitig zu erkennen**. Auch bekannt als Rendezvous, **Zero Configuration** oder Zeroconf, ermöglicht es einem Gerät, einem TCP/IP-Netzwerk beizutreten, **automatisch eine IP-Adresse auszuwählen** und seine Dienste an andere Netzwerkgeräte zu übertragen.

Zero Configuration Networking, bereitgestellt von Bonjour, stellt sicher, dass Geräte:

- **Automatisch eine IP-Adresse erhalten** können, selbst in Abwesenheit eines DHCP-Servers.
- **Namens-zu-Adresse-Übersetzungen** durchführen können, ohne einen DNS-Server zu benötigen.
- **Dienste** im Netzwerk entdecken können.

Geräte, die Bonjour verwenden, weisen sich eine **IP-Adresse aus dem Bereich 169.254/16** zu und überprüfen deren Einzigartigkeit im Netzwerk. Macs führen einen Routingtabelleneintrag für dieses Subnetz, der über `netstat -rn | grep 169` überprüft werden kann.

Für DNS verwendet Bonjour das **Multicast DNS (mDNS)-Protokoll**. mDNS arbeitet über **Port 5353/UDP** und verwendet **Standard-DNS-Abfragen**, die jedoch an die **Multicast-Adresse 224.0.0.251** gerichtet sind. Dieser Ansatz stellt sicher, dass alle hörenden Geräte im Netzwerk die Abfragen empfangen und darauf reagieren können, was die Aktualisierung ihrer Einträge erleichtert.

Beim Beitritt zum Netzwerk wählt sich jedes Gerät selbst einen Namen, der typischerweise mit **.local** endet und entweder vom Hostnamen abgeleitet oder zufällig generiert wird.

Die Dienstentdeckung im Netzwerk wird durch **DNS Service Discovery (DNS-SD)** erleichtert. Unter Verwendung des Formats von DNS SRV-Einträgen nutzt DNS-SD **DNS PTR-Einträge**, um die Auflistung mehrerer Dienste zu ermöglichen. Ein Client, der einen bestimmten Dienst sucht, fordert einen PTR-Eintrag für `<Service>.<Domain>` an und erhält im Gegenzug eine Liste von PTR-Einträgen im Format `<Instance>.<Service>.<Domain>`, wenn der Dienst von mehreren Hosts verfügbar ist.

Das `dns-sd`-Dienstprogramm kann verwendet werden, um **Netzwerkdienste zu entdecken und zu bewerben**. Hier sind einige Beispiele für seine Verwendung:

### Suche nach SSH-Diensten

Um nach SSH-Diensten im Netzwerk zu suchen, wird der folgende Befehl verwendet:
```bash
dns-sd -B _ssh._tcp
```
Dieser Befehl initiiert das Browsen nach \_ssh.\_tcp-Diensten und gibt Details wie Zeitstempel, Flags, Schnittstelle, Domäne, Diensttyp und Instanznamen aus.

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
Wenn ein Dienst startet, kündigt er seine Verfügbarkeit für alle Geräte im Subnetz an, indem er seine Präsenz multicastet. Geräte, die an diesen Diensten interessiert sind, müssen keine Anfragen senden, sondern einfach nur auf diese Ankündigungen hören.

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
### Deaktivierung von Bonjour

Wenn Bedenken hinsichtlich der Sicherheit bestehen oder aus anderen Gründen Bonjour deaktiviert werden soll, kann es mit dem folgenden Befehl ausgeschaltet werden:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referenzen

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{{#include ../../banners/hacktricks-training.md}}
