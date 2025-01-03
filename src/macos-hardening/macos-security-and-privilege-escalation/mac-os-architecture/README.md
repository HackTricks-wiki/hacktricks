# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

Der **Kern von macOS ist XNU**, was für "X is Not Unix" steht. Dieser Kernel besteht grundlegend aus dem **Mach-Mikrokernel** (der später besprochen wird) **und** Elementen der Berkeley Software Distribution (**BSD**). XNU bietet auch eine Plattform für **Kernel-Treiber über ein System namens I/O Kit**. Der XNU-Kernel ist Teil des Darwin-Open-Source-Projekts, was bedeutet, dass **der Quellcode frei zugänglich ist**.

Aus der Perspektive eines Sicherheitsforschers oder Unix-Entwicklers kann **macOS** ziemlich **ähnlich** einem **FreeBSD**-System mit einer eleganten GUI und einer Vielzahl von benutzerdefinierten Anwendungen erscheinen. Die meisten Anwendungen, die für BSD entwickelt wurden, werden auf macOS ohne Änderungen kompiliert und ausgeführt, da die Befehlszeilenwerkzeuge, die Unix-Benutzern vertraut sind, alle in macOS vorhanden sind. Da der XNU-Kernel jedoch Mach integriert, gibt es einige wesentliche Unterschiede zwischen einem traditionellen Unix-ähnlichen System und macOS, und diese Unterschiede könnten potenzielle Probleme verursachen oder einzigartige Vorteile bieten.

Open-Source-Version von XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ist ein **Mikrokernel**, der **UNIX-kompatibel** sein soll. Eines seiner wichtigsten Entwurfsprinzipien war es, die Menge an **Code**, die im **Kernel**-Bereich ausgeführt wird, zu **minimieren** und stattdessen viele typische Kernel-Funktionen, wie Dateisystem, Netzwerk und I/O, als **Benutzerebene-Aufgaben** auszuführen.

In XNU ist Mach **verantwortlich für viele der kritischen Low-Level-Operationen**, die ein Kernel typischerweise behandelt, wie Prozessorplanung, Multitasking und Verwaltung des virtuellen Speichers.

### BSD

Der XNU **Kernel** **integriert** auch eine erhebliche Menge an Code, der aus dem **FreeBSD**-Projekt stammt. Dieser Code **läuft als Teil des Kernels zusammen mit Mach** im selben Adressraum. Der FreeBSD-Code innerhalb von XNU kann jedoch erheblich vom ursprünglichen FreeBSD-Code abweichen, da Änderungen erforderlich waren, um die Kompatibilität mit Mach sicherzustellen. FreeBSD trägt zu vielen Kernel-Operationen bei, einschließlich:

- Prozessmanagement
- Signalverarbeitung
- Grundlegende Sicherheitsmechanismen, einschließlich Benutzer- und Gruppenverwaltung
- Systemaufruf-Infrastruktur
- TCP/IP-Stack und Sockets
- Firewall und Paketfilterung

Das Verständnis der Interaktion zwischen BSD und Mach kann komplex sein, aufgrund ihrer unterschiedlichen konzeptionellen Rahmen. Zum Beispiel verwendet BSD Prozesse als seine grundlegende Ausführungseinheit, während Mach auf Threads basiert. Diese Diskrepanz wird in XNU durch **die Zuordnung jedes BSD-Prozesses zu einer Mach-Aufgabe** gelöst, die genau einen Mach-Thread enthält. Wenn der Fork()-Systemaufruf von BSD verwendet wird, nutzt der BSD-Code innerhalb des Kernels Mach-Funktionen, um eine Aufgabe und eine Thread-Struktur zu erstellen.

Darüber hinaus **pflegen Mach und BSD jeweils unterschiedliche Sicherheitsmodelle**: Das Sicherheitsmodell von **Mach** basiert auf **Port-Rechten**, während das Sicherheitsmodell von BSD auf **Prozesseigentum** basiert. Unterschiede zwischen diesen beiden Modellen haben gelegentlich zu lokalen Privilegieneskalationsanfälligkeiten geführt. Neben typischen Systemaufrufen gibt es auch **Mach-Traps, die es Benutzerspace-Programmen ermöglichen, mit dem Kernel zu interagieren**. Diese verschiedenen Elemente bilden zusammen die facettenreiche, hybride Architektur des macOS-Kernels.

### I/O Kit - Treiber

Das I/O Kit ist ein Open-Source, objektorientiertes **Gerätetreiber-Framework** im XNU-Kernel, das **dynamisch geladene Gerätetreiber** verwaltet. Es ermöglicht, modulare Codes zur Laufzeit zum Kernel hinzuzufügen und unterstützt verschiedene Hardware.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Interprozesskommunikation

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel-Erweiterungen

macOS ist **sehr restriktiv beim Laden von Kernel-Erweiterungen** (.kext), aufgrund der hohen Privilegien, mit denen der Code ausgeführt wird. Tatsächlich ist es standardmäßig nahezu unmöglich (es sei denn, es wird ein Bypass gefunden).

Auf der folgenden Seite können Sie auch sehen, wie Sie die `.kext` wiederherstellen können, die macOS in seinem **Kernelcache** lädt:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS Systemerweiterungen

Anstelle von Kernel-Erweiterungen hat macOS die Systemerweiterungen geschaffen, die in der Benutzerebene APIs bieten, um mit dem Kernel zu interagieren. Auf diese Weise können Entwickler auf die Verwendung von Kernel-Erweiterungen verzichten.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## Referenzen

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
