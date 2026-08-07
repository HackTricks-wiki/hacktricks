# macOS-Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU-Kernel

Der **Kern von macOS ist XNU**, was für „X is Not Unix“ steht. Dieser Kernel besteht im Wesentlichen aus dem **Mach-Microkernel** (der später behandelt wird) **und** Elementen aus der Berkeley Software Distribution (**BSD**). XNU bietet außerdem über ein System namens **I/O Kit** eine Plattform für **Kernel-Treiber**. Der XNU-Kernel ist Teil des Open-Source-Projekts Darwin, weshalb **sein Quellcode frei zugänglich** ist.

Aus der Perspektive eines Security Researchers oder Unix-Entwicklers kann sich **macOS** einem **FreeBSD**-System mit einer eleganten GUI und einer Vielzahl eigener Anwendungen sehr **ähnlich** anfühlen. Die meisten für BSD entwickelten Anwendungen lassen sich ohne Änderungen für macOS kompilieren und dort ausführen, da die Unix-Benutzern vertrauten Kommandozeilenwerkzeuge unter macOS vorhanden sind. Da der XNU-Kernel jedoch Mach integriert, gibt es einige wesentliche Unterschiede zwischen einem traditionellen Unix-ähnlichen System und macOS. Diese Unterschiede können potenzielle Probleme verursachen oder einzigartige Vorteile bieten.

Open-Source-Version von XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ist ein **Microkernel**, der **UNIX-kompatibel** entwickelt wurde. Eines seiner zentralen Designprinzipien bestand darin, die Menge an **Code**, der im **Kernel**-Bereich ausgeführt wird, zu **minimieren** und stattdessen viele typische Kernel-Funktionen, etwa Dateisysteme, Netzwerk und I/O, als **Tasks auf Benutzerebene** auszuführen.

In XNU ist Mach für viele der kritischen Low-Level-Operationen verantwortlich, die normalerweise von einem Kernel übernommen werden, etwa Prozessor-Scheduling, Multitasking und die Verwaltung des virtuellen Speichers.

### BSD

Der XNU-**Kernel** enthält außerdem einen erheblichen Anteil an Code, der aus dem **FreeBSD**-Projekt stammt. Dieser Code **läuft als Teil des Kernels zusammen mit Mach** im selben Adressraum. Der FreeBSD-Code innerhalb von XNU kann sich jedoch erheblich vom ursprünglichen FreeBSD-Code unterscheiden, da Änderungen erforderlich waren, um die Kompatibilität mit Mach sicherzustellen. FreeBSD trägt zu zahlreichen Kernel-Operationen bei, darunter:

- Prozessverwaltung
- Signalverarbeitung
- Grundlegende Sicherheitsmechanismen, einschließlich der Verwaltung von Benutzern und Gruppen
- Infrastruktur für Systemaufrufe
- TCP/IP-Stack und Sockets
- Firewall und Paketfilterung

Das Zusammenspiel zwischen BSD und Mach zu verstehen, kann aufgrund ihrer unterschiedlichen konzeptionellen Modelle komplex sein. BSD verwendet beispielsweise Prozesse als grundlegende Ausführungseinheit, während Mach auf Threads basiert. Diese Abweichung wird in XNU dadurch ausgeglichen, dass **jeder BSD-Prozess mit einem Mach-Task verknüpft wird**, der genau einen Mach-Thread enthält. Wenn der BSD-Systemaufruf fork() verwendet wird, nutzt der BSD-Code innerhalb des Kernels Mach-Funktionen, um eine Task- und eine Thread-Struktur zu erstellen.

Darüber hinaus verfügen **Mach und BSD jeweils über unterschiedliche Sicherheitsmodelle**: Das Sicherheitsmodell von **Mach** basiert auf **Port-Rechten**, während das Sicherheitsmodell von BSD auf dem **Besitz von Prozessen** beruht. Unterschiede zwischen diesen beiden Modellen haben gelegentlich zu Local-Privilege-Escalation-Schwachstellen geführt. Neben den üblichen Systemaufrufen gibt es auch **Mach-Traps, über die Programme im User-Space mit dem Kernel interagieren können**. Zusammen bilden diese unterschiedlichen Elemente die vielseitige, hybride Architektur des macOS-Kernels.<sup>[[1]](#references)</sup>

### I/O Kit - Treiber

Das I/O Kit ist ein Open-Source-, objektorientiertes **Device-Driver-Framework** im XNU-Kernel und verwaltet **dynamisch geladene Device-Treiber**. Es ermöglicht, modularen Code zur Laufzeit zum Kernel hinzuzufügen, und unterstützt verschiedenste Hardware.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprozessoren in der macOS-Architektur

Apple-Plattformen verwenden mehrere Coprozessoren, um latenzempfindliche Aufgaben von den Hauptkernen fernzuhalten und sicherheitskritische Funktionen zu isolieren.

- **Secure Enclave Processor (SEP)**: Ein dedizierter ARM-Kern mit eigenem Microkernel und eigener Secure-Boot-Kette, der typischerweise in **EL3/secure world** ausgeführt wird. Die Interaktion erfolgt über Mailbox-Treiber in macOS auf EL1.
- Attack surface: SEP-Firmware-Updates und die User-Space-Daemons (`seputil`, `securityd`), die als Proxy für Anfragen dienen.
- Impact of compromise: Langfristige Schlüssel leaken, biometrische Prüfungen umgehen sowie FileVault- oder Apple-Pay-Schutzmechanismen brechen.
- **System Management Controller (SMC)**: Führt proprietäre Firmware auf einem Mikrocontroller außerhalb der ARM-Exception-Levels aus. macOS (EL1) erreicht ihn über I/O-Kit-User-Clients.
- Attack surface: USB-C-Power-Delivery-Nachrichten, Schnittstellen zur Lüfter-/Batterieverwaltung und Firmware-Update-Pfade.
- Impact of compromise: Thermische Grenzwerte überschreiben, gefälschte Sensordaten einschleusen, die Stromversorgung unterbrechen oder persistente NVRAM-Backdoors implantieren.
- **T1/T2 Security Chips**: Führen bridgeOS (von watchOS abgeleitet) größtenteils auf EL1/EL3 auf eigenen ARM-Kernen aus. macOS kommuniziert über von IOKit vermittelte PCIe-/USB-ähnliche Kanäle.
- Attack surface: DFU-/Restore-Pfade, von Diensten wie `tccd` bereitgestellte IPC-Endpunkte und an den T2 angebundene Media-Pipelines.
- Impact of compromise: Secure Boot deaktivieren, SSD-Inhalte entschlüsseln, die Steuerung von Kamera- und Mikrofonzugriff übernehmen oder HID-Eingaben zur unauffälligen Persistenz emulieren.
- **Display Coprocessor (DCP)**: Führt Firmware auf EL1 innerhalb eines isolierten, durch DART (Apples IOMMU) geschützten Adressraums aus.
- Attack surface: `DCPAVService`-Schnittstellen, gemeinsam genutzte Descriptor-Buffer und das Parsen von Firmware-Images.
- Impact of compromise: Beliebige Frames einschleusen, Framebuffer ausspähen oder die Display-Pipeline für DoS lahmlegen.
- **Apple Neural Engine (ANE)**: Führt Microcode auf einem dedizierten ML-Cluster aus (keine ARM-EL-Levels). macOS plant die Aufgaben über `ANECompilerService` und IOKit.
- Attack surface: Kompilierte Model-Binaries (`.ane`), Core-ML-APIs, die benutzerdefinierte Kernel speisen, sowie Firmware-Loader.
- Impact of compromise: ML-Modelle manipulieren oder exfiltrieren, verarbeitete Audio-/Visionsdaten leaken oder die On-Device-Inferenz sabotieren.
- **AGX GPU**: Die Firmware läuft auf benutzerdefinierten GPU-Kernen mit einem Scheduler; EL0 übermittelt Metal-Befehle, die von EL1 validiert werden.
- Attack surface: Metal-Shader-Compiler, APIs zur Zuordnung gemeinsam genutzter Buffer und `com.apple.AGXFirmware`-ioctl-Schnittstellen.
- Impact of compromise: DMA-Zugriff auf den Systemspeicher, Sandbox-Escapes über GPU-Treiber oder persistente Firmware-Implants.
- **Apple Video Encoder (AVE)**: Die Firmware wird in einer EL1-ähnlichen Sandbox auf der Media Engine ausgeführt. macOS interagiert über VideoToolbox und `AppleAVE2`.
- Attack surface: Codec-Bitstreams, Parametersätze, benutzerbereitgestellte Buffer und Firmware-Update-Blobs.
- Impact of compromise: Unkomprimierte Frames leaken, DRM umgehen oder Code Execution mit Zugriff auf DMA-Engines erlangen.
- **Image Signal Processor (ISP)**: Führt Secure Firmware im Media-Engine-Cluster aus; die macOS-Kameratreiber laufen auf EL1.
- Attack surface: Camera-HALs, RAW-Frame-Deskriptoren, ISP-Konfigurationswarteschlangen und Firmware-Updates.
- Impact of compromise: Unbemerkt rohe Kamera-Feeds aufnehmen, Datenschutzindikatoren deaktivieren oder manipulierte Bilder einschleusen.
- **AMX Matrix Cores**: Arbeiten als Coprozessor-Einheiten, die über neue Instruktionen auf EL0/EL1 bereitgestellt werden.
- Attack surface: Kernel-Virtualisierung des AMX-Zustands (`thread_set_state`, Context Switches) und Codegenerierung im User-Space.
- Impact of compromise: Tile-Register anderer Prozesse leaken, Workloads fingerprinten oder sich über eine Beschädigung des Kernel-Speichers weiter privilegieren.

Modernes macOS behandelt diese Coprozessoren als vertrauenswürdige Komponenten in der Vertrauenskette. Die Firmware für SEP, SMC und T2 ist von Apple signiert, und Handshake-Protokolle (die häufig über Mailboxen oder I/O-Kit-Familien implementiert werden) enthalten Challenge-Response-Prüfungen, sodass nur authentifizierte Firmware Anfragen bearbeiten kann.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS-Kernel-Extensions

macOS ist beim Laden von Kernel Extensions (.kext) **äußerst restriktiv**, da der Code mit hohen Berechtigungen ausgeführt wird. Tatsächlich ist dies standardmäßig nahezu unmöglich (sofern kein Bypass gefunden wird).

Auf der folgenden Seite wird außerdem beschrieben, wie die von macOS in seinen **Kernelcache** geladenen `.kext` wiederhergestellt werden können:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Anstelle von Kernel Extensions hat macOS die System Extensions entwickelt, die APIs auf Benutzerebene zur Interaktion mit dem Kernel bereitstellen. Auf diese Weise können Entwickler auf Kernel Extensions verzichten.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** steht für **CRYPTographically-sealed EXtension**. Dabei handelt es sich um ein versiegeltes Disk-Image (einen Container), das Apple verwendet, um Teile des Betriebssystems (Frameworks, gemeinsam genutzte Bibliotheken und Apps) zu hosten, die sich zwischen größeren OS-Updates wahrscheinlich ändern.
- Unter macOS und iOS können Komponenten innerhalb von Cryptexes über RSR **gepatcht oder ersetzt** werden, ohne das gesamte System-Volume neu zu versiegeln.
- Cryptexes befinden sich auf dem **Preboot-Volume** neben der Boot-Firmware und werden zur Laufzeit in das OS-Dateisystem eingehängt.
- Das Laden von Cryptex-Inhalten umfasst eine Validierung: Das System überprüft File-Seals, Manifeste und Root-Hashes und mountet oder „graftet“ anschließend die Cryptex-Inhalte, sodass Apps zur Laufzeit die Cryptex-Versionen verwenden, sofern diese vorhanden sind.
- In Boot-Logs erfolgt das Laden von Cryptexes nach der Kernel-Initialisierung, aber bevor die vollständigen Systemdienste gestartet wurden.


#### Rapid Security Response (RSR)

- **RSR** ist Apples Mechanismus zur Bereitstellung von **Security-Patches zwischen regulären OS-Updates**. Dabei werden Cryptex-Inhalte aktualisiert, um verwundbare Komponenten (z. B. Bibliotheken und Frameworks) zu korrigieren, ohne das zentrale System-Volume zu verändern.
- Bei der Anwendung eines RSR-Updates fordert das Gerät von Apples Signing-Server ein **Cryptex1-Image4-Manifest** an. Dieses Manifest ist kryptografisch an das Gerät und die neuen Cryptex-Inhalte gebunden.
- Das vorhandene AP-Boot-Ticket für das Basissystem wird durch RSR **nicht verändert**. Der Patch wird additiv auf das versiegelte Basis-OS angewendet.
- Unter macOS werden bestimmte gepatchte Komponenten (z. B. Safari) aktiv, sobald die App neu gestartet wird; ein vollständiger Systemneustart ist nicht immer erforderlich.
- RSRs sind **entfernbar**: Jede RSR enthält sowohl einen Patch als auch einen „Antipatch“, der auf die Version des Basis-OS zurückrollen kann. Beim Entfernen werden die Cryptex-Inhalte zurückgesetzt.
- RSR-Updates sind im Allgemeinen deutlich kleiner als vollständige OS-Updates und erfordern für die Installation einen niedrigeren Akkustand.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
