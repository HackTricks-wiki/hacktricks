# Windows Kernel-Rootkits und DKOM

{{#include ../../banners/hacktricks-training.md}}

## Umfang

Ein Implantat nach einer Kompromittierung kann einen signierten Kernel-Treiber als Dienst laden und über `IRP_MJ_DEVICE_CONTROL` eine Steuerungsebene im User Mode bereitstellen. Die Treibersignatur bestätigt lediglich, dass Windows das Image akzeptiert; sie macht weder die IOCTL-Autorisierung noch Speicheroperationen, Callbacks oder Hooks sicher. Ein analysiertes Rootkit verwendete im normalen Betrieb drei Handler, stellte aber Dutzende zusätzliche Post-Exploitation-Primitiven bereit. Beim Reverse Engineering muss daher der gesamte Dispatcher untersucht werden, nicht nur die Anfragen, die in einem Malware-Trace beobachtet wurden.<sup>[[1]](#references)</sup>

## Triage signierter Treiber und IOCTLs

Beginne bei `DriverEntry`, notiere Geräteobjekte und DOS-symbolische Links, finde die Routine `MajorFunction[IRP_MJ_DEVICE_CONTROL]` und erfasse alle Vergleiche und Tabelleneinträge, die zu einem Handler führen. Gleiche die Namen ab, die der User Mode öffnet, und die Namen, die der Treiber tatsächlich erstellt: Eine beobachtete Kette öffnete `\\.\msagent`, während der Treiber `\Device\ToolTool` und `\DosDevices\ToolTool` erstellte. Diese Abweichung kann auf ein anderes Sample/eine andere Konfiguration, fehlende Setup-Logik oder eine Inkonsistenz in der Analyse hinweisen.<sup>[[1]](#references)</sup>

Dekodiere jeden Control Code, bevor du die Eingabestruktur rekonstruierst.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

Diese drei Codes werden als `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` und `METHOD_BUFFERED` dekodiert. Das **beweist nicht**, dass ein nicht privilegierter Aufrufer sie erreichen kann: Untersuche auch die Geräte-DACL, die Create-/Open-Dispatch-Routinen, Caller-Prüfungen pro Anfrage, erwartete Pufferlängen, eingebettete Pointer, die PID-Lifetime-Behandlung und ob der Handler einer vom Aufrufer angegebenen PID oder einem Flag vertraut.<sup>[[1]](#references)</sup>

Wenn das Implantat nur eine Teilmenge der Befehle verwendet, gruppiere die übrigen Handler nach Primitive, statt sie als toten Code abzutun. Ein einzelner Multifunktions-Treiber hat alle folgenden Klassen offengelegt:<sup>[[1]](#references)</sup>

- **Steuerung/Konfiguration:** Rootkit-Status umschalten; geschützte Pfade, Prozesse und C2-Adressen hinzufügen, entfernen, abfragen oder löschen.
- **Prozessmanipulation:** eine PID beenden, ihr Image unmapen, mit `NtCreateThreadEx` injecten, Prozesse oder User-Module verbergen/wiederherstellen und den PPL-Schutz entfernen.
- **Kernel-Manipulation:** einen geladenen Treiber aus der Liste unlinken, Notification-Callbacks auflisten/deaktivieren/wiederherstellen, einen anderen Treiber manuell mappen und an eine beliebige Kernel-Adresse schreiben.
- **Objektmanipulation:** Dateien löschen/entschlüsseln und Registry-Werte erstellen oder ändern.

## Manuelles Kernel-Mapping über einen verwundbaren signierten Treiber

Ein signierter Treiber mit Kernel-Speicher-Lese-/Schreiboperationen kann als Loader für ein unsigniertes Treiber-Image dienen, ohne Windows aufzufordern, dieses Image als normalen Treiber zu laden.<sup>[[2]](#references)[[7]](#references)</sup> Das LocalStranger-Beispiel öffnet ein vorhandenes `\\.\WinNotify`-Gerät; sein Quellcode zeigt nicht, dass ein nicht privilegierter Benutzer den Treiber auf einem beliebigen Host installieren, starten oder öffnen kann.<sup>[[2]](#references)[[3]](#references)</sup> Der Mapper übernimmt einen Image-Pfad, fragt die Basisadresse des geladenen Kernels ab und verwendet die Virtual-Memory-Read/Write-IOCTLs des Geräts.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Um diesen Lese-/Schreibzugriff in einen Kernel-Aufruf umzuwandeln, liest der Mapper ein PTE-Base-Immediate aus `MmGetVirtualForPhysical` aus und durchläuft die Paging-Einträge, die `NtAddAtom` abdecken.<sup>[[5]](#references)[[7]](#references)</sup> Seine PTE-Berechnung lautet `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`; der Code prüft außerdem auf eine Large-Page-PDE.<sup>[[5]](#references)[[7]](#references)</sup> Er macht den abdeckenden Eintrag vorübergehend beschreibbar, ersetzt den Systemaufruf-Eintrag durch einen Sprung zur gewünschten Kernel-Funktion, ruft den User-Mode-Stub `NtAddAtom` auf und stellt anschließend sowohl die ursprünglichen Bytes als auch den Page-Eintrag wieder her.<sup>[[6]](#references)</sup>

Der Mapper verwendet diesen Aufrufpfad für `ExAllocatePool`, mappt PE-Sections, Imports und Relocations in das Image, schreibt es in die Allokation und ruft seinen Entry Point auf.<sup>[[7]](#references)[[8]](#references)</sup> Diese Implementierung akzeptiert nur relocatable PE-Images für x64; das Auslesen der PTE-Base setzt außerdem ein festes Layout bei `MmGetVirtualForPhysical + 34` voraus.<sup>[[5]](#references)[[8]](#references)</sup> Betrachte dies als buildabhängig, nicht als eigenständigen KASLR-Bypass oder Beweis dafür, dass HVCI oder PatchGuard das Mapping zulassen.<sup>[[5]](#references)[[8]](#references)</sup> Eine datenbasierte Verwendung von Kernel-R/W findest du unter [SYSTEM token theft](arbitrary-kernel-rw-token-theft.md).

## Ausnahmen für vertrauenswürdige Prozesse

Ein nützliches Designmuster ist ein IOCTL, das eine PID zusammen mit einem **trusted**-Flag registriert. Dieselbe Trust-Abfrage wird dann von Datei-, Registry-, Prozess- und Thread-Filtern verwendet: Nicht vertrauenswürdige Tools erhalten gefilterte Enumeration-Ergebnisse, eingeschränkte Handle-Rechte oder `STATUS_ACCESS_DENIED`, während das Implantat weiterhin seine eigenen verborgenen Objekte aktualisieren kann. Betrachte dies als Autorisierungsgrenze und überprüfe, wie Einträge authentifiziert, synchronisiert und nach Prozessende oder PID-Wiederverwendung entfernt werden.<sup>[[1]](#references)</sup>

Rootkits können Richtlinien in `REG_MULTI_SZ`-Werten speichern und Listen für Dateien, Verzeichnisse, Registry-Schlüssel, Registry-Werte, ignorierte Images, geschützte Images und verborgene Images in AVL-Bäume kompilieren. Verfolge bei der Analyse alle Leser und Schreiber dieser gemeinsam genutzten Bäume; sie verbinden Registry-Konfiguration, IOCTLs, Callbacks und Filterlogik, selbst wenn Funktionsnamen entfernt wurden.<sup>[[1]](#references)</sup>

## DKOM-Prozess- und Modulverstecken

### `EPROCESS.ActiveProcessLinks`

Die Offsets von `ActiveProcessLinks` variieren je nach Windows-Build. Ein versions-tolerantes Rootkit kann bekannte Kandidaten prüfen und anschließend `EPROCESS` nach einem konsistenten `LIST_ENTRY` durchsuchen, dessen Nachbarn auf den Kandidaten zurückverweisen. Es speichert den gefundenen Offset, verbirgt einen Prozess, indem es die `Flink`/`Blink`-Zeiger seiner Nachbarn neu verknüpft, und bewahrt den Zustand auf, um den Eintrag später wieder einzuhängen. Der Prozess läuft weiter, verschwindet aber aus Enumeratoren, die die Active-Process-Liste durchlaufen.<sup>[[1]](#references)</sup>

Das ist **DKOM**, keine Beendigung. Bei der Erkennung sollten listenbasierte Ergebnisse mit unabhängigen Indizien wie Pool-/Objekt-Scans, Thread-Zuordnung, Handle-Tabellen, Scheduler-Artefakten und Kernel-Speicherinspektion verglichen werden. Ein Prozess, der bei einem Scan sichtbar ist, aber in der kanonischen Liste fehlt, ist aussagekräftiger als jede der beiden Ansichten für sich allein.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Das entsprechende Modulversteck-Primitiv findet den Zieleintrag in `PsLoadedModuleList` und verändert benachbarte `Flink`/`Blink`-Zeiger. Der Treiber bleibt gemappt und ausführbar, aber listenbasierte Modulabfragen lassen ihn aus. Vergleiche die Loader-Liste mit ausführbaren Kernel-Mappings, Pool-Tags, Geräte-/Treiberobjekten, Service-Schlüsseln, Callback-Adressen und Dispatch-Pointern, die außerhalb eines gelisteten Images liegen.<sup>[[1]](#references)</sup>

## Callback-basierter Schutz und Cloaking

Ein Rootkit kann dokumentierte Callback-Frameworks mit DKOM und Hooks kombinieren:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks`-Pre-Operation-Handler für `PsProcessType` und `PsThreadType` entfernen Rechte, die für Beendigung, VM-Zugriff, Duplizierung oder Thread-Manipulation verwendet werden, wenn ein nicht vertrauenswürdiger Aufrufer ein geschütztes Ziel öffnet. Notiere die Callback-Altitude und ermittle, zu welchem Modul jede Callback-Adresse gehört.
- `PsSetCreateProcessNotifyRoutineEx` und `PsSetLoadImageNotifyRoutine` verwalten den Zustand geschützter/ignorierter/verborgener Prozesse, während Prozesse und Images erscheinen; ein einmaliger Prozessdurchlauf kann Objekte ergänzen, die bereits vor der Registrierung existierten.
- Ein Dateisystem-MiniFilter verweigert den Zugriff auf konfigurierte Pfade. Eine ungewöhnliche Implementierung kann ihren `Instances`-Schlüssel erstellen, dynamisch eine Altitude wählen und diese bei einer Kollision durch `FltRegisterFilter` erhöhen und den Vorgang wiederholen.
- Eine `CmRegisterCallbackEx`-Routine kann geschützte Namen aus der Enumeration ausblenden und direkte Open-, Rename-, Set- oder Delete-Operationen verweigern, während registrierte vertrauenswürdige Prozesse ausgenommen werden.

Stelle `ObRegisterCallbacks`-Registrierungen, Registry-Callback-Altitudes, die Ausgabe von `fltmc filters`, Service-`Instances`-Schlüsseln und Callback-Adressen zueinander in Beziehung. Wenn normale Tools gefiltert werden, untersuche diese Strukturen anhand eines Offline-Speicherabbilds oder über eine andere vertrauenswürdige Erfassungsebene.<sup>[[1]](#references)</sup>

## Nsiproxy-Ergebnisfilterung

Netzwerkverschleierung kann auf `\Driver\Nsiproxy` abzielen: das Driver-Objekt mit `ObReferenceObjectByName` abrufen, einen Handler-Pointer speichern, ihn durch einen Wrapper ersetzen und zurückgegebene IPv4-Datensätze, die mit einer IOCTL-verwalteten C2-Liste übereinstimmen, entfernen, bevor sie den User Mode erreichen. Anwendungen, die auf den gefilterten NSI-Daten basieren, zeigen die Verbindung dann möglicherweise nicht mehr an, obwohl der Datenverkehr weiterhin existiert.<sup>[[1]](#references)</sup>

Vergleiche die Verbindungsansichten des Hosts mit Packet Capture, WFP/ETW-Telemetrie und Netzwerkobjekten im Kernel-Speicher. Untersuche außerdem die Dispatch-/Handler-Pointer von `Nsiproxy` und bestätige, dass jeder auf ein erwartetes signiertes Modul verweist; ein Pointer auf ein nicht gelistetes Mapping kann die Netzwerkfilterung mit DKOM an `PsLoadedModuleList` verbinden.<sup>[[1]](#references)</sup>

## Checkliste für die Untersuchung

Das stärkste Signal ist eine Diskrepanz zwischen Ebenen, nicht ein einzelner Dateiname oder Hash. Setze Folgendes zueinander in Beziehung:<sup>[[1]](#references)</sup>

1. Die Erstellung eines Kernel-Service und ein signierter Treiber, dessen Zertifikatsalter, Herausgeber oder Pfad nicht zum installierten Produkt passt.
2. Geräteerstellung, DOS-Links und IOCTL-Datenverkehr, einschließlich nicht übereinstimmender Gerätebezeichnungen im User Mode und Kernel Mode.
3. Eine PID-Registrierungsanfrage, auf die Fehler anderer Prozesse folgen, wenn sie dieselben Objekte öffnen, enumerieren, ändern oder löschen.
4. Objekt-/Registry-/Prozess-/Image-Callbacks, MiniFilter-Instanzen und Hooks, deren Adressen nicht zu einem normal aufgelisteten Treiber gehören.
5. Unterschiede zwischen listenbasierten und scanbasierten Inventaren von Prozessen, Modulen, Callbacks und Netzwerken.

## References

- [1] [Kaspersky Securelist - HoneyMyte erweitert CoolClient um ein signiertes Windows-Kernel-Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [LocalStranger-README](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [LocalStranger-Treiberinitialisierung](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [LocalStranger-Mapper-Kommandozeile](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Auflösung von Kernel-Exporten und PTE-Base durch LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Kernel-Call-Trampolin von LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [LocalStranger-Mapper: Allokation und Aufruf des Entry Points](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [PE-Mapping durch LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Kernel- und Syscall-Kontext von LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Virtual-Memory-IOCTL-Wrapper von LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
