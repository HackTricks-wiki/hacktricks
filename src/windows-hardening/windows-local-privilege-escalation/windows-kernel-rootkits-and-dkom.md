# Windows-Kernel-Rootkits und DKOM

{{#include ../../banners/hacktricks-training.md}}

## Umfang

Ein Post-Compromise-Implant kann einen signierten Kernel-Treiber als Dienst laden und über `IRP_MJ_DEVICE_CONTROL` eine User-Mode-Control-Plane bereitstellen. Die Treibersignierung stellt lediglich sicher, dass Windows das Image akzeptiert; sie macht weder die IOCTL-Autorisierung noch Speicheroperationen, Callbacks oder Hooks sicher. Ein analysiertes Rootkit verwendete während des normalen Betriebs drei Handler, stellte jedoch Dutzende zusätzlicher Post-Exploitation-Primitives bereit. Daher muss das Reverse Engineering den vollständigen Dispatcher abdecken und darf sich nicht nur auf die Requests beschränken, die in einem Malware-Trace beobachtet wurden.<sup>[[1]](#references)</sup>

## Triage von signierten Treibern und IOCTLs

Beginne bei `DriverEntry`, dokumentiere Geräteobjekte und DOS-Symbolic-Links, lokalisiere die Routine `MajorFunction[IRP_MJ_DEVICE_CONTROL]` und erfasse jeden Vergleich bzw. Tabelleneintrag, der zu einem Handler führt. Gleiche die von User Mode geöffneten Namen mit den Namen ab, die der Treiber tatsächlich erstellt: Eine beobachtete Kette öffnete `\\.\msagent`, während ihr Treiber `\Device\ToolTool` und `\DosDevices\ToolTool` erstellte. Diese Abweichung kann auf ein anderes Sample/eine andere Konfiguration, fehlende Setup-Logik oder eine Inkonsistenz in der Analyse hinweisen.<sup>[[1]](#references)</sup>

Dekodiere jeden Control Code, bevor du seine Eingabestruktur rekonstruierst.<sup>[[1]](#references)</sup>
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
Diese drei Codes werden als `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` und `METHOD_BUFFERED` dekodiert. Das **beweist nicht**, dass ein unprivilegierter Aufrufer sie erreichen kann: Prüfe außerdem die Geräte-DACL, die Create/Open-Dispatch-Logik, Caller-Prüfungen pro Request, erwartete Buffer-Längen, eingebettete Pointer, die Behandlung der PID-Lebensdauer sowie, ob der Handler einer vom Caller bereitgestellten PID oder einem Flag vertraut.<sup>[[1]](#references)</sup>

Wenn das Implantat nur eine Teilmenge der Commands verwendet, gruppiere die übrigen Handler nach Primitive, anstatt sie als Dead Code abzutun. Ein einzelner Multifunktions-Treiber hat alle folgenden Klassen offengelegt:<sup>[[1]](#references)</sup>

- **Steuerung/Konfiguration:** Rootkit-Status umschalten; geschützte Pfade, Prozesse und C2-Adressen hinzufügen, entfernen, abfragen oder löschen.
- **Prozessmanipulation:** Eine PID beenden, ihr Image unmapen, mit `NtCreateThreadEx` injizieren, Prozesse oder User-Module verstecken/wiederherstellen und den PPL-Schutz entfernen.
- **Kernel-Manipulation:** Einen geladenen Treiber aus der Liste entfernen, Notification-Callbacks enumerieren/deaktivieren/wiederherstellen, einen weiteren Treiber manuell mappen und an eine beliebige Kernel-Adresse schreiben.
- **Objektmanipulation:** Dateien löschen/entschlüsseln und Registry-Werte erstellen oder ändern.

## Ausnahmen für vertrauenswürdige Prozesse

Ein nützliches Design-Pattern ist ein IOCTL, das eine PID zusammen mit einem **trusted**-Flag registriert. Dieselbe Trust-Abfrage wird anschließend von Datei-, Registry-, Prozess- und Thread-Filtern verwendet: Nicht vertrauenswürdige Tools erhalten gefilterte Enumeration-Ergebnisse, eingeschränkte Handle-Rechte oder `STATUS_ACCESS_DENIED`, während das Implantat weiterhin seine eigenen versteckten Objekte aktualisieren kann. Behandle dies als Autorisierungsgrenze und prüfe, wie Einträge authentifiziert, synchronisiert und nach dem Prozessende oder einer PID-Wiederverwendung entfernt werden.<sup>[[1]](#references)</sup>

Rootkits können Richtlinien in `REG_MULTI_SZ`-Werten persistieren und Listen für Dateien, Verzeichnisse, Registry-Keys, Registry-Werte, ignorierte Images, geschützte Images und versteckte Images in AVL-Bäume kompilieren. Verfolge während der Analyse jeden Reader und Writer dieser gemeinsam genutzten Bäume; dadurch lassen sich Registry-Konfiguration, IOCTLs, Callbacks und Filtering-Logik miteinander verknüpfen, selbst wenn Funktionsnamen entfernt wurden.<sup>[[1]](#references)</sup>

## DKOM-Prozess- und Modulverstecken

### `EPROCESS.ActiveProcessLinks`

Die Offsets von `ActiveProcessLinks` variieren je nach Windows-Build. Ein versionsrobustes Rootkit kann bekannte Kandidaten testen und anschließend `EPROCESS` nach einem konsistenten `LIST_ENTRY` durchsuchen, dessen Nachbarn auf den Kandidaten zurückverweisen. Es behält den gefundenen Offset bei, versteckt einen Prozess, indem es die `Flink`/`Blink`-Zeiger seiner Nachbarn neu verknüpft, und bewahrt den Zustand auf, um den Eintrag später wieder einzuhängen. Der Prozess läuft weiter, verschwindet jedoch aus Enumeratoren, die die Active-Process-Liste durchlaufen.<sup>[[1]](#references)</sup>

Dies ist **DKOM**, keine Terminierung. Die Erkennung sollte listenbasierte Ergebnisse mit unabhängigen Nachweisen vergleichen, etwa Pool-/Objekt-Scans, Thread-Zugehörigkeit, Handle-Tabellen, Scheduler-Artefakten und Kernel-Memory-Inspektion. Ein Prozess, der in einem Scan sichtbar, aber in der kanonischen Liste nicht vorhanden ist, ist aussagekräftiger als jede der beiden Ansichten allein.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Das entsprechende Modul-Hiding-Primitive findet den Zieleintrag in `PsLoadedModuleList` und patcht benachbarte `Flink`/`Blink`-Pointer. Der Treiber bleibt gemappt und ausführbar, wird jedoch von listenbasierten Modulabfragen ausgelassen. Vergleiche die Loader-Liste mit ausführbaren Kernel-Mappings, Pool-Tags, Device-/Driver-Objekten, Service-Keys, Callback-Adressen und Dispatch-Pointern, die außerhalb eines aufgelisteten Images liegen.<sup>[[1]](#references)</sup>

## Callback-basierter Schutz und Cloaking

Ein Rootkit kann dokumentierte Callback-Frameworks mit DKOM und Hooks kombinieren:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks`-Pre-Operation-Handler für `PsProcessType` und `PsThreadType` entfernen Rechte, die zum Beenden, für VM-Zugriff, Duplizieren oder Thread-Manipulation verwendet werden, wenn ein nicht vertrauenswürdiger Caller ein geschütztes Ziel öffnet. Erfasse die Callback-Altitude und löse jede Callback-Adresse zu ihrem besitzenden Modul auf.
- `PsSetCreateProcessNotifyRoutineEx` und `PsSetLoadImageNotifyRoutine` verwalten den Zustand geschützter/ignorierter/versteckter Prozesse, sobald Prozesse und Images erscheinen; ein einmaliger Process-Walk kann Objekte nachtragen, die bereits vor der Registrierung existierten.
- Ein Filesystem-Minifilter verweigert den Zugriff auf konfigurierte Pfade. Eine ungewöhnliche Implementierung kann ihren `Instances`-Key erstellen, dynamisch eine Altitude auswählen und diese erhöhen bzw. einen erneuten Versuch durchführen, wenn `FltRegisterFilter` eine Kollision meldet.
- Eine `CmRegisterCallbackEx`-Routine kann geschützte Namen aus Enumerationen unterdrücken und direkte Open-, Rename-, Set- oder Delete-Operationen verweigern, während registrierte vertrauenswürdige Prozesse ausgenommen werden.

Korrelieren Sie `ObRegisterCallbacks`-Registrierungen, Registry-Callback-Altitudes, die Ausgabe von `fltmc filters`, Service-`Instances`-Keys und Callback-Adressen. Wenn normale Tools gefiltert werden, untersuche diese Strukturen aus einem Offline-Memory-Image oder einer anderen vertrauenswürdigen Acquisition-Schicht.<sup>[[1]](#references)</sup>

## Nsiproxy-Ergebnisfilterung

Network Concealment kann auf `\Driver\Nsiproxy` abzielen: Beziehe das Driver-Objekt mit `ObReferenceObjectByName`, speichere einen Handler-Pointer, ersetze ihn durch einen Wrapper und entferne zurückgegebene IPv4-Records, die mit einer per IOCTL verwalteten C2-Liste übereinstimmen, bevor sie den User Mode erreichen. Anwendungen, die auf den gefilterten NSI-Daten basieren, zeigen die Verbindung möglicherweise nicht mehr an, obwohl der Traffic weiterhin vorhanden ist.<sup>[[1]](#references)</sup>

Vergleiche Host-Ansichten der Verbindungen mit Packet Capture, WFP/ETW-Telemetrie und Netzwerkobjekten aus dem Kernel-Memory. Untersuche außerdem Dispatch-/Handler-Pointer von `Nsiproxy` und bestätige, dass jeder innerhalb des erwarteten signierten Moduls aufgelöst wird; ein Pointer in ein nicht aufgelistetes Mapping kann Network Filtering mit `PsLoadedModuleList`-DKOM verbinden.<sup>[[1]](#references)</sup>

## Untersuchung-Checkliste

Das stärkste Signal ist eine Diskrepanz zwischen Schichten, nicht ein einzelner Dateiname oder Hash. Korrelieren Sie:<sup>[[1]](#references)</sup>

1. Die Erstellung eines Kernel-Service und eines signierten Treibers, dessen Zertifikatsalter, Publisher oder Pfad nicht zum installierten Produkt passt.
2. Die Erstellung von Devices, DOS-Links und IOCTL-Traffic, einschließlich nicht übereinstimmender Device-Namen im User Mode und Kernel.
3. Eine PID-Registrierungsanfrage, auf die Fehler anderer Prozesse folgen, wenn sie dieselben Objekte öffnen, enumerieren, ändern oder löschen wollen.
4. Objekt-/Registry-/Prozess-/Image-Callbacks, Minifilter-Instanzen und Hooks, deren Adressen nicht zu einem normal enumerierten Treiber gehören.
5. Unterschiede zwischen listenbasierten und scanbasierten Inventaren von Prozessen, Modulen, Callbacks und Netzwerken.

## References

- [1] [Kaspersky Securelist - HoneyMyte Enhances CoolClient with a Signed Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
