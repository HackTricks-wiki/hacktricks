# macOS-Kernel und System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU-Kernel

Der **Kern von macOS ist XNU**, was für „X is Not Unix“ steht. Dieser Kernel besteht im Wesentlichen aus dem **Mach-Microkernel** (wird später behandelt) **und** Elementen aus der Berkeley Software Distribution (**BSD**). XNU stellt außerdem eine Plattform für **Kernel-Treiber über ein System namens I/O Kit** bereit. Der XNU-Kernel ist Teil des Open-Source-Projekts Darwin, wodurch **sein Quellcode frei zugänglich** ist.

Aus der Perspektive eines Security-Researchers oder Unix-Developers kann sich **macOS** wie ein **FreeBSD**-System mit einer eleganten GUI und einer Vielzahl benutzerdefinierter Anwendungen anfühlen. Die meisten für BSD entwickelten Anwendungen lassen sich ohne Änderungen für macOS kompilieren und darauf ausführen, da die Unix-Benutzern vertrauten Command-Line-Tools in macOS vorhanden sind. Da der XNU-Kernel jedoch Mach integriert, gibt es einige wesentliche Unterschiede zwischen einem traditionellen Unix-ähnlichen System und macOS. Diese Unterschiede können potenzielle Probleme verursachen oder einzigartige Vorteile bieten.

Open-Source-Version von XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ist ein **Microkernel**, der **UNIX-kompatibel** konzipiert wurde. Eines seiner wichtigsten Designprinzipien bestand darin, die Menge an **Code**, der im **Kernel**-Bereich ausgeführt wird, zu **minimieren** und stattdessen viele typische Kernel-Funktionen wie Dateisysteme, Networking und I/O als **Tasks auf User-Ebene** auszuführen.

In XNU ist Mach für viele der kritischen Low-Level-Operationen verantwortlich, die ein Kernel typischerweise übernimmt, etwa Prozessor-Scheduling, Multitasking und die Verwaltung des virtuellen Speichers.

### BSD

Der XNU-**Kernel** enthält außerdem eine erhebliche Menge an Code, der aus dem **FreeBSD**-Projekt abgeleitet wurde. Dieser Code **läuft zusammen mit Mach als Teil des Kernels** im selben Adressraum. Der FreeBSD-Code innerhalb von XNU kann sich jedoch erheblich vom ursprünglichen FreeBSD-Code unterscheiden, da Änderungen erforderlich waren, um die Kompatibilität mit Mach sicherzustellen. FreeBSD trägt zu zahlreichen Kernel-Operationen bei, darunter:

- Prozessverwaltung
- Signalverarbeitung
- Grundlegende Security-Mechanismen, einschließlich Benutzer- und Gruppenverwaltung
- Infrastruktur für System-Calls
- TCP/IP-Stack und Sockets
- Firewall und Packet-Filtering

Das Zusammenspiel zwischen BSD und Mach zu verstehen, kann aufgrund ihrer unterschiedlichen konzeptionellen Frameworks komplex sein. BSD verwendet beispielsweise Prozesse als grundlegende Ausführungseinheit, während Mach auf Threads basiert. Diese Diskrepanz wird in XNU ausgeglichen, indem **jeder BSD-Prozess einer Mach-Task zugeordnet wird**, die genau einen Mach-Thread enthält. Wenn der BSD-System-Call fork() verwendet wird, nutzt der BSD-Code innerhalb des Kernels Mach-Funktionen, um eine Task- und eine Thread-Struktur zu erstellen.

Außerdem verfügen **Mach und BSD über jeweils unterschiedliche Security-Modelle**: Das **Security-Modell von Mach** basiert auf **Port-Rechten**, während das Security-Modell von BSD auf **Prozessbesitz** basiert. Unterschiede zwischen diesen beiden Modellen haben gelegentlich zu Local-Privilege-Escalation-Vulnerabilities geführt. Neben den üblichen System-Calls gibt es außerdem **Mach-Traps, die es User-Space-Programmen ermöglichen, mit dem Kernel zu interagieren**. Diese verschiedenen Elemente bilden zusammen die vielseitige, hybride Architektur des macOS-Kernels.

### I/O Kit - Treiber

Das I/O Kit ist ein Open-Source-, objektorientiertes **Device-Driver-Framework** im XNU-Kernel und verarbeitet **dynamisch geladene Device-Treiber**. Es ermöglicht, modularen Code spontan zum Kernel hinzuzufügen, und unterstützt so unterschiedliche Hardware.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in der macOS-Architektur

Apple-Plattformen verwenden mehrere Coprocessors, um latenzempfindliche Aufgaben von den Main-Cores fernzuhalten und sicherheitskritische Funktionen zu isolieren.

- **Secure Enclave Processor (SEP)**: Ein dedizierter ARM-Core mit eigenem Microkernel und eigener Secure-Boot-Chain, der typischerweise auf **EL3/in der Secure World** läuft. Die Interaktion erfolgt über Mailbox-Treiber in macOS auf EL1.
- Angriffsfläche: SEP-Firmware-Updates und die User-Space-Daemons (`seputil`, `securityd`), die als Proxy für Requests dienen.
- Auswirkungen einer Kompromittierung: Langfristige Keys leaken, biometrische Sperren umgehen und den Schutz von FileVault oder Apple Pay brechen.
- **System Management Controller (SMC)**: Führt proprietäre Firmware auf einem Microcontroller außerhalb der ARM-Exception-Levels aus. macOS (EL1) erreicht ihn über I/O-Kit-User-Clients.
- Angriffsfläche: USB-C-Power-Delivery-Nachrichten, Schnittstellen für Lüfter-/Batterieverwaltung und Firmware-Update-Pfade.
- Auswirkungen einer Kompromittierung: Thermische Grenzwerte überschreiben, gefälschte Sensordaten einschleusen, die Stromversorgung unterbrechen oder persistente NVRAM-Backdoors implantieren.
- **T1/T2 Security Chips**: Führen bridgeOS (von watchOS abgeleitet) größtenteils auf EL1/EL3 auf eigenen ARM-Cores aus. macOS kommuniziert über von IOKit vermittelte PCIe-/USB-ähnliche Kanäle.
- Angriffsfläche: DFU-/Restore-Pfade, von Diensten wie `tccd` bereitgestellte IPC-Endpunkte und Media-Pipelines, die mit dem T2 verbunden sind.
- Auswirkungen einer Kompromittierung: Secure Boot deaktivieren, SSD-Inhalte entschlüsseln, die Steuerung von Kamera-/Mikrofon-Sperren übernehmen oder HID-Input für eine unauffällige Persistenz emulieren.
- **Display Coprocessor (DCP)**: Führt Firmware auf EL1 in einem isolierten Adressraum aus, der durch DART (Apples IOMMU) geschützt wird.
- Angriffsfläche: `DCPAVService`-Schnittstellen, gemeinsam genutzte Descriptor-Buffer und das Parsen von Firmware-Images.
- Auswirkungen einer Kompromittierung: Beliebige Frames einschleusen, Framebuffer ausspähen oder die Display-Pipeline für DoS unbrauchbar machen.
- **Apple Neural Engine (ANE)**: Führt Microcode auf einem dedizierten ML-Cluster aus (keine ARM-EL-Levels). macOS plant die Verarbeitung über `ANECompilerService` und IOKit.
- Angriffsfläche: Kompilierte Model-Binaries (`.ane`), Core-ML-APIs, die benutzerdefinierte Kernels speisen, und Firmware-Loader.
- Auswirkungen einer Kompromittierung: ML-Modelle manipulieren oder exfiltrieren, verarbeitete Audio-/Vision-Daten leaken oder die On-Device-Inferenz sabotieren.
- **AGX GPU**: Firmware läuft auf benutzerdefinierten GPU-Cores mit einem Scheduler; EL0 übermittelt Metal-Commands, die von EL1 validiert werden.
- Angriffsfläche: Metal-Shader-Compiler, APIs für die Zuordnung gemeinsamer Buffer und `com.apple.AGXFirmware`-ioctl-Schnittstellen.
- Auswirkungen einer Kompromittierung: DMA-Zugriff auf den Systemspeicher, Sandbox-Escapes über GPU-Treiber oder persistente Firmware-Implants.
- **Apple Video Encoder (AVE)**: Firmware wird auf der Media Engine in einer EL1-ähnlichen Sandbox ausgeführt. macOS interagiert über VideoToolbox und `AppleAVE2`.
- Angriffsfläche: Codec-Bitstreams, Parameter-Sets, vom Benutzer bereitgestellte Buffer und Firmware-Update-Blobs.
- Auswirkungen einer Kompromittierung: Unkomprimierte Frames leaken, DRM umgehen oder Code Execution mit Zugriff auf DMA-Engines erlangen.
- **Image Signal Processor (ISP)**: Führt Secure Firmware im Media-Engine-Cluster aus; macOS-Kamera-Treiber laufen auf EL1.
- Angriffsfläche: Camera-HALs, RAW-Frame-Deskriptoren, ISP-Konfigurations-Queues und Firmware-Updates.
- Auswirkungen einer Kompromittierung: RAW-Kamera-Feeds unbemerkt aufnehmen, Privacy-Indikatoren deaktivieren oder manipulierte Bilder einschleusen.
- **AMX Matrix Cores**: Arbeiten als Coprocessor-Einheiten, die über neue Instructions auf EL0/EL1 bereitgestellt werden.
- Angriffsfläche: Kernel-Virtualisierung des AMX-Zustands (`thread_set_state`, Context-Switches) und Code-Generierung im User-Space.
- Auswirkungen einer Kompromittierung: Tile-Register anderer Prozesse leaken, Workloads fingerprinten oder über eine Kernel-Memory-Corruption eskalieren.

Modernes macOS behandelt diese Coprocessors als vertrauenswürdige Komponenten in der Chain of Trust. Die Firmware für SEP, SMC und T2 wird von Apple signiert, und Handshake-Protokolle (die häufig über Mailboxes oder I/O-Kit-Families implementiert werden) enthalten Challenge-Response-Prüfungen, sodass nur authentifizierte Firmware Requests bedienen kann.

### IPC - Inter-Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS-Kernel-Extensions

macOS ist aufgrund der hohen Privileges, mit denen dieser Code ausgeführt wird, **extrem restriktiv beim Laden von Kernel-Extensions** (.kext). Tatsächlich ist dies standardmäßig praktisch unmöglich (sofern kein Bypass gefunden wird).

Auf der folgenden Seite wird außerdem gezeigt, wie die `.kext`, die macOS in seinen **Kernelcache** lädt, wiederhergestellt werden kann:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS-System-Extensions

Anstatt Kernel-Extensions zu verwenden, hat macOS System-Extensions entwickelt, die APIs auf User-Ebene zur Interaktion mit dem Kernel bereitstellen. Auf diese Weise können Entwickler auf die Verwendung von Kernel-Extensions verzichten.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** steht für **CRYPTographically-sealed EXtension**. Dabei handelt es sich um ein versiegeltes Disk-Image (einen Container), das Apple verwendet, um Teile des OS (Frameworks, Shared Libraries, Apps) zu hosten, die sich zwischen größeren OS-Updates wahrscheinlich ändern.
- Unter macOS und iOS können Komponenten innerhalb von Cryptexes über RSR **gepatcht oder ersetzt** werden, ohne das gesamte System-Volume erneut zu versiegeln.
- Cryptexes befinden sich auf dem **Preboot-Volume** neben der Boot-Firmware und werden zur Laufzeit in das OS-Dateisystem eingehängt.
- Das Laden von Cryptex-Inhalten umfasst eine Validierung: Das System prüft File-Seals, Manifests und Root-Hashes und mountet oder „graftet“ anschließend die Cryptex-Inhalte, sodass Apps zur Laufzeit die Cryptex-Versionen verwenden, sofern diese vorhanden sind.
- In Boot-Logs erfolgt das Laden von Cryptexes nach der Kernel-Initialisierung, aber bevor die vollständigen System-Services gestartet wurden.


#### Rapid Security Response (RSR)

- **RSR** ist Apples Mechanismus zur Bereitstellung von **Security-Patches zwischen regulären OS-Updates**. Er zielt auf Cryptex-Inhalte ab, um verwundbare Teile (z. B. Libraries und Frameworks) zu aktualisieren, ohne das Core-System-Volume zu verändern.
- Beim Anwenden eines RSR-Updates fordert das Gerät von Apples Signing-Server ein **Cryptex1-Image4-Manifest** an. Dieses Manifest ist kryptografisch an das Gerät und die neuen Cryptex-Inhalte gebunden.
- Das bestehende AP-Boot-Ticket für das Base-System wird durch RSR **nicht verändert**. Der Patch wird additiv auf das versiegelte Base-OS angewendet.
- Unter macOS werden bestimmte gepatchte Komponenten (z. B. Safari) aktiv, sobald die App neu gestartet wird; ein vollständiger Systemneustart ist nicht immer erforderlich.
- RSRs sind **entfernbar**: Jede RSR enthält sowohl einen Patch als auch einen „Antipatch“, der auf die Base-OS-Version zurückrollen kann. Beim Entfernen werden die Cryptex-Inhalte zurückgesetzt.
- RSR-Updates sind im Allgemeinen deutlich kleiner als vollständige OS-Updates und erfordern für die Installation einen niedrigeren Batteriestand.


## Referenzen

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
