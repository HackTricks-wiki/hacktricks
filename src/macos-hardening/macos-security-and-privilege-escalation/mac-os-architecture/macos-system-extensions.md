# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Im Gegensatz zu Kernel Extensions laufen **System Extensions im User Space** statt im Kernel Space, wodurch das Risiko eines Systemabsturzes aufgrund einer Fehlfunktion der Extension reduziert wird.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Es gibt drei Arten von System Extensions: **DriverKit** Extensions, **Network** Extensions und **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit ist ein Ersatz für Kernel Extensions, die **Hardware-Unterstützung bereitstellen**. Es ermöglicht, dass Gerätetreiber (wie USB-, Serial-, NIC- und HID-Treiber) im User Space statt im Kernel Space ausgeführt werden. Das DriverKit Framework umfasst **User-Space-Versionen bestimmter I/O-Kit-Klassen**, und der Kernel leitet normale I/O-Kit-Ereignisse an den User Space weiter, wodurch eine sicherere Umgebung für die Ausführung dieser Treiber geschaffen wird.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions bieten die Möglichkeit, Netzwerkverhalten anzupassen. Es gibt verschiedene Arten von Network Extensions:

- **App Proxy**: Dies wird verwendet, um einen VPN-Client zu erstellen, der ein flow-orientiertes, benutzerdefiniertes VPN-Protokoll implementiert. Das bedeutet, dass er den Netzwerkverkehr auf Grundlage von Verbindungen (oder Flows) statt einzelner Pakete verarbeitet.
- **Packet Tunnel**: Dies wird verwendet, um einen VPN-Client zu erstellen, der ein paketorientiertes, benutzerdefiniertes VPN-Protokoll implementiert. Das bedeutet, dass er den Netzwerkverkehr auf Grundlage einzelner Pakete verarbeitet.
- **Filter Data**: Dies wird zum Filtern von Netzwerk-„Flows“ verwendet. Es kann Netzwerkdaten auf Flow-Ebene überwachen oder ändern.
- **Filter Packet**: Dies wird zum Filtern einzelner Netzwerkpakete verwendet. Es kann Netzwerkdaten auf Paketebene überwachen oder ändern.
- **DNS Proxy**: Dies wird zum Erstellen eines benutzerdefinierten DNS-Providers verwendet. Es kann zum Überwachen oder Ändern von DNS-Anfragen und -Antworten eingesetzt werden.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security ist ein von Apple in macOS bereitgestelltes Framework, das eine Reihe von APIs für die Systemsicherheit zur Verfügung stellt. Es ist für **Security Vendors und Entwickler vorgesehen, um Produkte zu erstellen, die Systemaktivitäten überwachen und steuern können**, um bösartige Aktivitäten zu erkennen und sich davor zu schützen.

Dieses Framework stellt eine **Sammlung von APIs zur Überwachung und Steuerung von Systemaktivitäten** bereit, beispielsweise von Prozessausführungen, Dateisystemereignissen sowie Netzwerk- und Kernel-Ereignissen.

Der Kern dieses Frameworks ist im Kernel als Kernel Extension (KEXT) implementiert und befindet sich unter **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Diese KEXT besteht aus mehreren wichtigen Komponenten:

- **EndpointSecurityDriver**: Dies dient als „Einstiegspunkt“ für die Kernel Extension. Es ist die zentrale Interaktionsstelle zwischen dem Betriebssystem und dem Endpoint Security Framework.
- **EndpointSecurityEventManager**: Diese Komponente ist für die Implementierung von Kernel Hooks zuständig. Kernel Hooks ermöglichen es dem Framework, Systemereignisse zu überwachen, indem Systemaufrufe abgefangen werden.
- **EndpointSecurityClientManager**: Diese Komponente verwaltet die Kommunikation mit Clients im User Space, verfolgt, welche Clients verbunden sind und Ereignisbenachrichtigungen empfangen müssen.
- **EndpointSecurityMessageManager**: Diese Komponente sendet Nachrichten und Ereignisbenachrichtigungen an Clients im User Space.

Die Ereignisse, die das Endpoint Security Framework überwachen kann, werden in folgende Kategorien eingeteilt:

- Dateiereignisse
- Prozessereignisse
- Socket-Ereignisse
- Kernel-Ereignisse (beispielsweise das Laden/Entladen einer Kernel Extension oder das Öffnen eines I/O-Kit-Geräts)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Die **Kommunikation im User Space** mit dem Endpoint Security Framework erfolgt über die IOUserClient-Klasse. Abhängig vom Typ des Aufrufers werden zwei verschiedene Subklassen verwendet:

- **EndpointSecurityDriverClient**: Dies erfordert das Entitlement `com.apple.private.endpoint-security.manager`, das nur der Systemprozess `endpointsecurityd` besitzt.
- **EndpointSecurityExternalClient**: Dies erfordert das Entitlement `com.apple.developer.endpoint-security.client`. Dies wird typischerweise von Security Software von Drittanbietern verwendet, die mit dem Endpoint Security Framework interagieren muss.<sup>[[1]](#references)</sup>

Die Endpoint Security Extensions:**`libEndpointSecurity.dylib`** ist die C-Bibliothek, die System Extensions zur Kommunikation mit dem Kernel verwenden. Diese Bibliothek nutzt das I/O Kit (`IOKit`), um mit der Endpoint Security KEXT zu kommunizieren.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** ist ein wichtiger System-Daemon, der an der Verwaltung und dem Starten von Endpoint Security System Extensions beteiligt ist, insbesondere während des frühen Boot-Prozesses. **Nur System Extensions**, die in ihrer `Info.plist`-Datei mit **`NSEndpointSecurityEarlyBoot`** gekennzeichnet sind, erhalten diese Behandlung während des frühen Boot-Prozesses.<sup>[[2]](#references)</sup>

Ein weiterer System-Daemon, **`sysextd`**, **validiert System Extensions** und verschiebt sie an die vorgesehenen Systempositionen. Anschließend weist er den zuständigen Daemon an, die Extension zu laden. Das **`SystemExtensions.framework`** ist für die Aktivierung und Deaktivierung von System Extensions zuständig.<sup>[[2]](#references)</sup>

## ESF umgehen

ESF wird von Security Tools verwendet, die versuchen, einen Red Teamer zu erkennen. Daher klingt jede Information darüber, wie dies vermieden werden könnte, interessant.

### CVE-2021-30965

Das Problem besteht darin, dass die Security-Anwendung **Full Disk Access-Berechtigungen** benötigt. Wenn ein Angreifer diese entfernen könnte, könnte er verhindern, dass die Software ausgeführt wird:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Für **weitere Informationen** zu diesem Bypass und verwandten Bypasses siehe den Vortrag [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)<sup>[[3]](#references)</sup>

Am Ende wurde dies behoben, indem der von **`tccd`** verwalteten Security-App die neue Berechtigung **`kTCCServiceEndpointSecurityClient`** erteilt wurde, sodass `tccutil` ihre Berechtigungen nicht löschen kann und sie weiterhin ausgeführt werden kann.<sup>[[3]](#references)</sup>

## Quellen

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
