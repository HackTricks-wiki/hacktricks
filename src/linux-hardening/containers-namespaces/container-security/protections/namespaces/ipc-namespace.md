# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der IPC Namespace isoliert **System-V-IPC-Objekte** und **POSIX message queues**. Dazu gehören Shared-Memory-Segmente, Semaphoren und message queues, die andernfalls für voneinander unabhängige Prozesse auf dem Host sichtbar wären. In der Praxis verhindert dies, dass ein Container sich ohne Weiteres mit IPC-Objekten anderer Workloads oder des Hosts verbindet.

Im Vergleich zu mount-, PID- oder user-Namespaces wird der IPC Namespace oft weniger häufig behandelt, was jedoch nicht mit Irrelevanz verwechselt werden sollte. Shared Memory und verwandte IPC-Mechanismen können äußerst nützliche Zustände enthalten. Wenn der IPC Namespace des Hosts freigegeben ist, kann der Workload Einblick in Interprozess-Koordinationsobjekte oder Daten erhalten, die nie die Container-Grenze überschreiten sollten.

## Funktionsweise

Wenn die Runtime einen neuen IPC Namespace erstellt, erhält der Prozess einen eigenen isolierten Satz von IPC-IDs. Das bedeutet, dass Befehle wie `ipcs` nur die in diesem Namespace verfügbaren Objekte anzeigen. Wenn der Container stattdessen dem IPC Namespace des Hosts beitritt, werden diese Objekte Teil einer gemeinsam genutzten globalen Ansicht.

Dies ist besonders in Umgebungen relevant, in denen Anwendungen oder Services intensiv Shared Memory verwenden. Selbst wenn der Container allein über IPC keinen direkten Breakout durchführen kann, kann der Namespace Informationen leaken oder Cross-Process-Interference ermöglichen, die einen späteren Angriff erheblich unterstützt.

## Lab

Du kannst einen privaten IPC Namespace erstellen mit:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Und vergleichen Sie das Laufzeitverhalten mit:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Laufzeitverwendung

Docker und Podman isolieren IPC standardmäßig. Kubernetes weist dem Pod normalerweise einen eigenen IPC namespace zu, der von Containern im selben Pod gemeinsam genutzt wird, standardmäßig jedoch nicht vom Host. Die gemeinsame Nutzung der Host-IPC ist möglich, sollte aber als wesentliche Verringerung der Isolation und nicht als geringfügige Runtime-Option behandelt werden.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist `--ipc=host` oder `hostIPC: true`. Dies kann aus Kompatibilitätsgründen mit älterer Software oder aus Bequemlichkeit geschehen, verändert jedoch das Trust-Modell erheblich. Ein weiteres wiederkehrendes Problem besteht darin, IPC einfach zu übersehen, weil es weniger dramatisch wirkt als Host-PID oder Host-Networking. Wenn die Workload Browser, Datenbanken, wissenschaftliche Workloads oder andere Software verarbeitet, die Shared Memory intensiv nutzt, kann die IPC-Angriffsfläche in Wirklichkeit sehr relevant sein.

## Missbrauch

Bei gemeinsam genutzter Host-IPC kann ein Angreifer Shared-Memory-Objekte untersuchen oder manipulieren, neue Erkenntnisse über das Verhalten des Hosts oder benachbarter Workloads gewinnen oder die dort erlangten Informationen mit Process Visibility und ptrace-style capabilities kombinieren. Die gemeinsame Nutzung von IPC ist häufig eine unterstützende Schwachstelle und nicht der vollständige breakout path. Unterstützende Schwachstellen sind jedoch relevant, weil sie reale Angriffsketten verkürzen und stabilisieren.

Der erste nützliche Schritt besteht darin, zu enumerieren, welche IPC-Objekte überhaupt sichtbar sind:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Wenn der IPC-Namespace des Hosts gemeinsam genutzt wird, können große Shared-Memory-Segmente oder interessante Objektbesitzer das Anwendungsverhalten unmittelbar offenlegen:
```bash
ipcs -m -p
ipcs -q -p
```
In manchen Umgebungen leaken die Inhalte von `/dev/shm` selbst Dateinamen, Artefakte oder Tokens, die eine Überprüfung wert sind:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC führt allein nur selten sofort zu root auf dem Host, kann jedoch Daten- und Koordinationskanäle offenlegen, die spätere Prozessangriffe erheblich erleichtern.

### Vollständiges Beispiel: Wiederherstellung von Secrets aus `/dev/shm`

Der realistischste vollständige Missbrauchsfall ist Datendiebstahl statt eines direkten Escapes. Wenn Host-IPC oder ein weitreichendes Shared-Memory-Layout offengelegt ist, können sensible Artefakte manchmal direkt wiederhergestellt werden:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Auswirkungen:

- Extraktion von Secrets oder Session-Material, das im gemeinsam genutzten Speicher verblieben ist
- Einblicke in die aktuell auf dem Host aktiven Anwendungen
- Bessere Zielauswahl für spätere Angriffe auf PID-Namespaces oder über ptrace

Das Teilen von IPC sollte daher eher als **Angriffsverstärker** denn als eigenständiges Mittel zum Verlassen des Hosts verstanden werden.

## Überprüfungen

Diese Befehle sollen klären, ob die Workload eine private IPC-Sicht besitzt, ob relevante Shared-Memory- oder Message-Objekte sichtbar sind und ob `/dev/shm` selbst nützliche Artefakte offenlegt.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Was ist hier interessant:

- Wenn `ipcs -a` Objekte offenlegt, die unerwarteten Benutzern oder Services gehören, ist der Namespace möglicherweise nicht so isoliert wie erwartet.
- Große oder ungewöhnliche Shared-Memory-Segmente sind häufig eine weitere Untersuchung wert.
- Ein weitreichender `/dev/shm`-Mount ist nicht automatisch ein Bug, aber in einigen Umgebungen leakt er Dateinamen, Artefakte und kurzlebige Secrets.

IPC erhält selten so viel Aufmerksamkeit wie die größeren Namespace-Typen. In Umgebungen, die IPC intensiv nutzen, ist die gemeinsame Nutzung mit dem Host jedoch eindeutig eine Sicherheitsentscheidung.
{{#include ../../../../../banners/hacktricks-training.md}}
