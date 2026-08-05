# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Im Gegensatz zu Kernel Extensions laufen **System Extensions im User Space** statt im Kernel Space, wodurch das Risiko eines Systemabsturzes aufgrund einer fehlerhaften Extension reduziert wird.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Es gibt drei Arten von System Extensions: **DriverKit** Extensions, **Network** Extensions und **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit ist ein Ersatz für Kernel Extensions, die **Hardware-Unterstützung bereitstellen**. Es ermöglicht, dass Gerätetreiber (wie USB-, serielle, NIC- und HID-Treiber) im User Space statt im Kernel Space ausgeführt werden. Das DriverKit Framework enthält **User-Space-Versionen bestimmter I/O-Kit-Klassen**, und der Kernel leitet normale I/O-Kit-Ereignisse an den User Space weiter, wodurch eine sicherere Umgebung für die Ausführung dieser Treiber geschaffen wird.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions ermöglichen die Anpassung des Netzwerkverhaltens. Es gibt mehrere Arten von Network Extensions:

- **App Proxy**: Wird zum Erstellen eines VPN-Clients verwendet, der ein flow-orientiertes, benutzerdefiniertes VPN-Protokoll implementiert. Das bedeutet, dass er den Netzwerkverkehr anhand von Verbindungen (oder Flows) statt anhand einzelner Pakete verarbeitet.
- **Packet Tunnel**: Wird zum Erstellen eines VPN-Clients verwendet, der ein paketorientiertes, benutzerdefiniertes VPN-Protokoll implementiert. Das bedeutet, dass er den Netzwerkverkehr anhand einzelner Pakete verarbeitet.
- **Filter Data**: Wird zum Filtern von Netzwerk-„Flows“ verwendet. Damit können Netzwerkdaten auf Flow-Ebene überwacht oder verändert werden.
- **Filter Packet**: Wird zum Filtern einzelner Netzwerkpakete verwendet. Damit können Netzwerkdaten auf Paketebene überwacht oder verändert werden.
- **DNS Proxy**: Wird zum Erstellen eines benutzerdefinierten DNS-Providers verwendet. Damit können DNS-Anfragen und -Antworten überwacht oder verändert werden.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security ist ein von Apple in macOS bereitgestelltes Framework, das eine Reihe von APIs für die Systemsicherheit zur Verfügung stellt. Es ist für **Security-Anbieter und Entwickler gedacht, die Produkte erstellen, welche Systemaktivitäten überwachen und kontrollieren können**, um bösartige Aktivitäten zu erkennen und zu verhindern.

Dieses Framework stellt eine **Sammlung von APIs zur Überwachung und Kontrolle von Systemaktivitäten** bereit, beispielsweise von Prozessausführungen, Dateisystemereignissen sowie Netzwerk- und Kernel-Ereignissen.

Der Kern dieses Frameworks ist im Kernel als Kernel Extension (KEXT) unter **`/System/Library/Extensions/EndpointSecurity.kext`** implementiert.<sup>[[2]](#references)</sup> Diese KEXT besteht aus mehreren wichtigen Komponenten:

- **EndpointSecurityDriver**: Fungiert als „Einstiegspunkt“ für die Kernel Extension. Dies ist der zentrale Interaktionspunkt zwischen dem Betriebssystem und dem Endpoint Security Framework.
- **EndpointSecurityEventManager**: Diese Komponente ist für die Implementierung von Kernel Hooks zuständig. Kernel Hooks ermöglichen es dem Framework, Systemereignisse durch das Abfangen von Systemaufrufen zu überwachen.
- **EndpointSecurityClientManager**: Verwaltet die Kommunikation mit User-Space-Clients und verfolgt, welche Clients verbunden sind und Ereignisbenachrichtigungen erhalten müssen.
- **EndpointSecurityMessageManager**: Sendet Nachrichten und Ereignisbenachrichtigungen an User-Space-Clients.

Die Ereignisse, die das Endpoint Security Framework überwachen kann, werden in folgende Kategorien eingeteilt:

- Dateiereignisse
- Prozessereignisse
- Socket-Ereignisse
- Kernel-Ereignisse (beispielsweise das Laden/Entladen einer Kernel Extension oder das Öffnen eines I/O-Kit-Geräts)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Die **Kommunikation im User Space** mit dem Endpoint Security Framework erfolgt über die Klasse IOUserClient. Abhängig vom Typ des Aufrufers werden zwei verschiedene Subklassen verwendet:

- **EndpointSecurityDriverClient**: Erfordert das Entitlement `com.apple.private.endpoint-security.manager`, das nur vom Systemprozess `endpointsecurityd` gehalten wird.
- **EndpointSecurityExternalClient**: Erfordert das Entitlement `com.apple.developer.endpoint-security.client`. Dies wird typischerweise von Security-Software von Drittanbietern verwendet, die mit dem Endpoint Security Framework interagieren muss.<sup>[[1]](#references)</sup>

Die Endpoint Security Extensions:**`libEndpointSecurity.dylib`** ist die C-Bibliothek, die System Extensions zur Kommunikation mit dem Kernel verwenden. Diese Bibliothek nutzt das I/O Kit (`IOKit)`), um mit der Endpoint Security KEXT zu kommunizieren.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** ist ein wichtiger System-Daemon, der an der Verwaltung und dem Starten von Endpoint-Security-System-Extensions beteiligt ist, insbesondere während des frühen Bootvorgangs. **Nur System Extensions**, die in ihrer `Info.plist`-Datei mit **`NSEndpointSecurityEarlyBoot`** markiert sind, erhalten diese Behandlung während des frühen Bootvorgangs.<sup>[[2]](#references)</sup>

Ein weiterer System-Daemon, **`sysextd`**, **validiert System Extensions** und verschiebt sie an die vorgesehenen Systempfade. Anschließend weist er den zuständigen Daemon an, die Extension zu laden. Das **`SystemExtensions.framework`** ist für die Aktivierung und Deaktivierung von System Extensions zuständig.<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF wird von Security-Tools verwendet, die versuchen, einen red teamer zu erkennen. Daher klingt jede Information darüber, wie dies vermieden werden könnte, interessant.

### CVE-2021-30965

Das Problem besteht darin, dass die Security-Anwendung **Full Disk Access permissions** benötigt. Wenn ein Angreifer diese entfernen könnte, würde er dadurch verhindern, dass die Software ausgeführt wird:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Für **weitere Informationen** zu diesem Bypass und verwandten Bypasses siehe den Vortrag [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Letztendlich wurde dies behoben, indem der von **`tccd`** verwalteten Security-App die neue Berechtigung **`kTCCServiceEndpointSecurityClient`** erteilt wurde, sodass `tccutil` ihre Berechtigungen nicht löschen kann und sie weiterhin ausgeführt werden kann.<sup>[[3]](#references)</sup>

## Referenzen

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
