# macOS-Netzwerkdienste und -protokolle

{{#include ../../banners/hacktricks-training.md}}

## Remote-Zugriffsdienste

Dies sind die gängigen macOS-Dienste für den Remote-Zugriff.\
Du kannst diese Dienste unter `System Settings` --> `Sharing` aktivieren/deaktivieren.

- **VNC**, bekannt als „Screen Sharing“ (tcp:5900)
- **SSH**, genannt „Remote Login“ (tcp:22)
- **Apple Remote Desktop** (ARD) oder „Remote Management“ (tcp:3283, tcp:5900)
- **AppleEvent**, bekannt als „Remote Apple Event“ (tcp:3031)

Prüfe, ob einer davon aktiviert ist, indem du Folgendes ausführst:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Sharing-Konfiguration lokal enumerieren

Wenn Sie bereits über lokale code execution auf einem Mac verfügen, **prüfen Sie den konfigurierten Zustand** und nicht nur die listening sockets. `systemsetup` und `launchctl` zeigen normalerweise, ob der Service administrativ aktiviert ist, während `kickstart` und `system_profiler` dabei helfen, die effektive ARD/Sharing-Konfiguration zu bestätigen:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) ist eine erweiterte Version von [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), die für macOS angepasst wurde und zusätzliche Funktionen bietet. Eine bemerkenswerte Schwachstelle in ARD ist die Authentifizierungsmethode für das Passwort des Kontrollbildschirms, bei der nur die ersten 8 Zeichen des Passworts verwendet werden. Dadurch ist sie anfällig für [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) mit Tools wie Hydra oder [GoRedShell](https://github.com/ahhh/GoRedShell/), da standardmäßig keine Rate-Limits vorhanden sind.<sup>[3]</sup>

Vulnerable Instanzen können mit dem `vnc-info`-Script von **nmap** identifiziert werden. Services, die `VNC Authentication (2)` unterstützen, sind aufgrund der Kürzung des Passworts auf 8 Zeichen besonders anfällig für brute force attacks.

Um ARD für verschiedene administrative Aufgaben wie Privilege Escalation, GUI-Zugriff oder die Überwachung von Usern zu aktivieren, verwenden Sie den folgenden Befehl:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bietet flexible Kontrollstufen, darunter Beobachtung, geteilte Kontrolle und vollständige Kontrolle, wobei Sitzungen auch nach Änderungen des Benutzerpassworts bestehen bleiben. Es ermöglicht das direkte Senden von Unix-Befehlen und deren Ausführung als root für administrative Benutzer. Aufgabenplanung und die Remote Spotlight-Suche sind bemerkenswerte Features, die Remote-Suchen mit geringer Auswirkung nach sensiblen Dateien auf mehreren Maschinen ermöglichen.

Aus Sicht eines Operators haben sich **Monterey 12.1+ workflows zur Aktivierung aus der Ferne** in verwalteten Flotten geändert. Wenn du bereits Kontrolle über das MDM des Opfers hast, ist Apples Befehl `EnableRemoteDesktop` oft der sauberste Weg, die Remote-Desktop-Funktion auf neueren Systemen zu aktivieren. Wenn du bereits einen foothold auf dem Host hast, ist `kickstart` weiterhin nützlich, um ARD-Berechtigungen über die command line zu überprüfen oder neu zu konfigurieren.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Aktuelle `screensharingd`-Forschung zeigte, dass Apple Screen Sharing nicht immer nur klassische VNC-Authentifizierung verwendet: Neuere Builds sprechen **RFB `003.889`** und kündigen **security type `36`** an, wobei **SRP** zuerst authentifiziert und **ChaCha20-Poly1305** erst installiert wird, nachdem `ccsrp_server_verify_session` erfolgreich war. Der öffentliche Bericht gibt an, dass der Bug in **macOS Tahoe 26.6** (**27. Juli 2026**) behoben wurde.<sup>[8][9]</sup>

Ein nützliches Muster, das man sich merken sollte, ist der **stale-status parser bypass**: Nach einem erfolgreichen Lesen der 4-Byte-Länge muss jeder oversized/error-Zweig einen neuen Fehler zurückgeben. In betroffenen Builds bewirkt eine Big-Endian-SRP-Frame-Länge von **`>= 32768`**, dass der rejection path den vorherigen Erfolg von `NetBufferRead` (`0`) wiederverwendet. Dadurch setzt der Caller die Sitzung als authentifiziert, obwohl kein Passwortnachweis ausgeführt und keine Transportverschlüsselung installiert wurde. Da ungelesene Bytes im gemeinsamen Socket-Puffer verbleiben, kann ein Angreifer **malformed SRP data und post-auth RFB messages im selben TCP burst pipeline'n** und sie als **cleartext authenticated traffic** parsen lassen.<sup>[8]</sup>

Nach dem bypass wird Apples proprietäre **file-copy**-Nachricht **`0x22`** zu einem **root file read/write primitive**, da `screensharingd` als root ausgeführt wird:<sup>[8]</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: beliebiges Auslesen von Dateien
- `kind=2` / `StartFileReceive`: beliebiges Schreiben von Dateien
- Unterschiedliche `sid`-Werte ermöglichen es, mehrere Transaktionen über eine Verbindung zu pipelinen
- Setze bei `kind=101` (`NewItem`) Byte `14` / `arg[0]` für eine reguläre Datei auf `0x01`, den Payload-Offset `+42` auf eine **ungleich null gesetzte** Dateigröße in Big-Endian und den Payload-Offset `+0x5a` auf den gewünschten Unix-Modus (`0600`, wenn eine Crontab als Ziel verwendet wird)

Interessante Post-Write-Pivots auf beschreibbaren Pfaden umfassen **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** und **`/var/root/.ssh/authorized_keys`**. **SIP verhindert weder den Auth-Bypass noch das Auslesen von Dateien als root**, blockiert jedoch einige Schreibziele wie **`/var/at`**, weshalb die Ausführung über Cron nur mit deaktiviertem SIP funktioniert. Auf Hosts mit standardmäßig aktiviertem SIP sollte man eher an **„root file write into privileged auto-consumed files“** als an eine sofortige Codeausführung denken.<sup>[8]</sup>

Ein weiterer SRP-Fallstrick aus derselben Forschung: Server müssen **`A mod N != 0`** (gemäß RFC 5054) validieren, nicht nur `A > 0`. Die Akzeptanz von **`A = N`** kann das gemeinsame Secret auf null setzen und die Passwortüberprüfung untergraben.<sup>[8][10]</sup>

**Detection-Ideen**

- Security-Type-`36`-Sessions, bei denen die Länge des ersten SRP-Frames **`>= 32768`** ist
- Sessions, die mit der Verarbeitung von unverschlüsseltem **`0x22`**-File-Copy-Traffic beginnen, bevor ein erfolgreicher SRP-Proof / eine Cipher-Installation stattgefunden hat
- Wiederholte kurzlebige Retries gegen **TCP/5900** sowie mehrere File-Copy-`sid`-Werte in einem Burst
- Unerwartete Erstellung von **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** oder **`/var/root/.ssh/authorized_keys`** nach einer Screen-Sharing-Exposition

### Pentesting Remote Apple Events (RAE / EPPC)

Apple bezeichnet diese Funktion in den modernen Systemeinstellungen als **Remote Application Scripting**. Unter der Haube stellt sie den **Apple Event Manager** remote über **EPPC** auf **TCP/3031** via dem Service `com.apple.AEServer` bereit. Palo Alto Unit 42 hob sie erneut als praktisches **macOS lateral movement**-Primitiv hervor, da gültige Credentials zusammen mit einem aktivierten RAE-Service es einem Operator ermöglichen, scriptbare Anwendungen auf einem remote Mac zu steuern.<sup>[6]</sup>

Nützliche Prüfungen:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Wenn du bereits über Admin-/Root-Rechte auf dem Zielsystem verfügst und es aktivieren möchtest:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Grundlegender Verbindungstest von einem anderen Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
In der Praxis ist der Missbrauchsfall nicht auf Finder beschränkt. Jede **scriptable application**, die die erforderlichen Apple events akzeptiert, wird zu einer Remote-Angriffsfläche. Dadurch ist RAE insbesondere nach dem Diebstahl von Zugangsdaten in internen macOS-Netzwerken interessant.

#### Aktuelle Screen-Sharing-/ARD-Schwachstellen (2023-2025)

| Jahr | CVE | Komponente | Auswirkung | Behoben in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Eine fehlerhafte Sitzungsdarstellung konnte dazu führen, dass der *falsche* Desktop oder das falsche Fenster übertragen wurde, wodurch vertrauliche Informationen geleakt werden konnten|macOS Sonoma 14.2.1 (Dezember 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Ein Benutzer mit Screen-Sharing-Zugriff konnte möglicherweise den **Bildschirm eines anderen Benutzers** sehen, verursacht durch ein Problem bei der Zustandsverwaltung|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oktober-Dezember 2024) |

**Hardening-Tipps**

* *Screen Sharing*/*Remote Management* deaktivieren, wenn diese Funktionen nicht unbedingt erforderlich sind.
* macOS vollständig patchen (Apple stellt Sicherheitsupdates im Allgemeinen für die letzten drei großen Releases bereit).
* Ein **Strong Password** verwenden und die Option *„VNC viewers may control screen with password“* nach Möglichkeit **deaktiviert** lassen.
* Den Service hinter einem VPN betreiben, anstatt TCP 5900/3283 dem Internet auszusetzen.
* Eine Application-Firewall-Regel hinzufügen, um `ARDAgent` auf das lokale Subnetz zu beschränken:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour-Protokoll

Bonjour, eine von Apple entwickelte Technologie, ermöglicht es **Geräten im selben Netzwerk, die von anderen Geräten angebotenen Services zu erkennen**. Bonjour ist auch als Rendezvous, **Zero Configuration** oder Zeroconf bekannt. Es ermöglicht einem Gerät, einem TCP/IP-Netzwerk beizutreten, **automatisch eine IP-Adresse auszuwählen** und seine Services an andere Netzwerkgeräte zu übertragen.

Zero Configuration Networking, das von Bonjour bereitgestellt wird, stellt sicher, dass Geräte Folgendes können:

- **Automatisch eine IP-Adresse beziehen**, selbst wenn kein DHCP-Server vorhanden ist.
- Eine **Namens-zu-Adress-Übersetzung** durchführen, ohne einen DNS-Server zu benötigen.
- Im Netzwerk verfügbare **Services erkennen**.

Geräte, die Bonjour verwenden, weisen sich selbst eine **IP-Adresse aus dem Bereich 169.254/16** zu und überprüfen deren Eindeutigkeit im Netzwerk. Macs führen für dieses Subnetz einen Routingtabelleneintrag, der sich mit `netstat -rn | grep 169` überprüfen lässt.

Für DNS verwendet Bonjour das **Multicast-DNS-(mDNS-)Protokoll**. mDNS arbeitet über **Port 5353/UDP** und verwendet **standardmäßige DNS-Abfragen**, die jedoch an die **Multicast-Adresse 224.0.0.251** gerichtet werden. Dadurch können alle lauschenden Geräte im Netzwerk die Abfragen empfangen und beantworten, was die Aktualisierung ihrer Einträge ermöglicht.

Beim Beitritt zum Netzwerk wählt jedes Gerät selbst einen Namen aus, der typischerweise auf **.local** endet und vom Hostnamen abgeleitet oder zufällig generiert werden kann.

Die Service-Erkennung innerhalb des Netzwerks wird durch **DNS Service Discovery (DNS-SD)** ermöglicht. Unter Verwendung des Formats von DNS-SRV-Records nutzt DNS-SD **DNS-PTR-Records**, um die Auflistung mehrerer Services zu ermöglichen. Ein Client, der nach einem bestimmten Service sucht, fordert einen PTR-Record für `<Service>.<Domain>` an und erhält als Antwort eine Liste von PTR-Records im Format `<Instance>.<Service>.<Domain>`, wenn der Service von mehreren Hosts verfügbar ist.

Das Dienstprogramm `dns-sd` kann zum **Erkennen und Anbieten von Netzwerkservices** verwendet werden. Hier sind einige Beispiele für seine Verwendung:

### Nach SSH-Services suchen

Um im Netzwerk nach SSH-Services zu suchen, wird der folgende Befehl verwendet:
```bash
dns-sd -B _ssh._tcp
```
Dieser Befehl startet das Browsing nach \_ssh.\_tcp-Diensten und gibt Details wie Zeitstempel, Flags, Schnittstelle, Domain, Diensttyp und Instanznamen aus.

### Ankündigen eines HTTP-Dienstes

Um einen HTTP-Dienst anzukündigen, kannst du Folgendes verwenden:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Dieser Befehl registriert einen HTTP-Dienst namens „Index“ auf Port 80 mit dem Pfad `/index.html`.

Um anschließend nach HTTP-Diensten im Netzwerk zu suchen:
```bash
dns-sd -B _http._tcp
```
Wenn ein Dienst gestartet wird, kündigt er seine Verfügbarkeit allen Geräten im Subnetz an, indem er seine Präsenz per Multicast überträgt. Geräte, die an diesen Diensten interessiert sind, müssen keine Anfragen senden, sondern lediglich auf diese Ankündigungen hören.

Für eine benutzerfreundlichere Oberfläche kann die im Apple App Store verfügbare App **Discovery - DNS-SD Browser** die in Ihrem lokalen Netzwerk angebotenen Dienste visualisieren.

Alternativ können benutzerdefinierte Scripts geschrieben werden, um Dienste mithilfe der Bibliothek `python-zeroconf` zu durchsuchen und zu entdecken. Das Script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) zeigt, wie ein Service-Browser für `_http._tcp.local.`-Dienste erstellt wird, der hinzugefügte oder entfernte Dienste ausgibt:
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

In macOS-Netzwerken ist Bonjour häufig der einfachste Weg, **Schnittstellen für die Fernadministration** zu finden, ohne das Ziel direkt zu berühren. Apple Remote Desktop kann Clients selbst über Bonjour entdecken, daher sind dieselben Discovery-Daten auch für einen Angreifer nützlich.
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
Für umfassendere Techniken zum **mDNS spoofing, zur Impersonation und zur subnetzübergreifenden Discovery** siehe die entsprechende Seite:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Bonjour über das Netzwerk enumerieren

* **Nmap NSE** – von einem einzelnen Host beworbene Services entdecken:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Das `dns-service-discovery`-Script sendet eine `_services._dns-sd._udp.local`-Abfrage und enumeriert anschließend jeden beworbenen Servicetyp.

* **mdns_recon** – Python-Tool, das gesamte Bereiche scannt und nach *falsch konfigurierten* mDNS-Responder sucht, die Unicast-Abfragen beantworten (nützlich, um Geräte zu finden, die subnetz- oder WAN-übergreifend erreichbar sind):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Dies gibt Hosts zurück, die SSH über Bonjour außerhalb des lokalen Links bereitstellen.

### Sicherheitsaspekte und aktuelle Schwachstellen (2024-2025)

| Jahr | CVE | Schweregrad | Problem | Gepatcht in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Mittel|Ein Logikfehler in *mDNSResponder* ermöglichte es, durch ein manipuliertes Paket einen **denial-of-service** auszulösen|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|Hoch|Ein Korrektheitsproblem in *mDNSResponder* konnte für eine **lokale Rechteausweitung** ausgenutzt werden|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (Mai 2025) |

**Hinweise zur Mitigation**

1. UDP 5353 auf den *link-local*-Bereich beschränken – auf Wireless-Controllern, Routern und hostbasierten Firewalls blockieren oder mit einem Rate-Limit versehen.
2. Bonjour auf Systemen, die keine Service-Discovery benötigen, vollständig deaktivieren:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Für Umgebungen, in denen Bonjour intern benötigt wird, aber niemals Netzwerkgrenzen überschreiten darf, *AirPlay Receiver*-Profilbeschränkungen (MDM) oder einen mDNS-Proxy verwenden.
4. **System Integrity Protection (SIP)** aktivieren und macOS aktuell halten – beide oben genannten Schwachstellen wurden schnell gepatcht, setzten für den vollständigen Schutz jedoch ein aktiviertes SIP voraus.

### Bonjour deaktivieren

Wenn Sicherheitsbedenken oder andere Gründe dafür sprechen, Bonjour zu deaktivieren, kann dies mit dem folgenden Befehl erfolgen:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referenzen

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Laterale Bewegung auf macOS: Einzigartige und beliebte Techniken sowie Beispiele aus der Praxis](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Informationen zu den Sicherheitsinhalten von macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Informationen zu den Sicherheitsinhalten von macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Verwendung des Secure Remote Password (SRP) Protocol zur TLS-Authentifizierung](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
