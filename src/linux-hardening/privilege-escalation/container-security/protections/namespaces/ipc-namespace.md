# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der IPC namespace isoliert **System V IPC objects** und **POSIX message queues**. Dazu gehören shared memory segments, semaphores und message queues, die sonst für nicht verwandte Prozesse auf dem host sichtbar wären. Praktisch verhindert das, dass ein container sich einfach an IPC objects anderer Workloads oder des host anhängt.

Im Vergleich zu mount-, PID- oder user namespaces wird der IPC namespace oft weniger diskutiert, das heißt aber nicht, dass er irrelevant wäre. Shared memory und verwandte IPC-Mechanismen können sehr nützliche Zustände enthalten. Wenn der host IPC namespace exposed ist, kann der workload Einblick in inter-process coordination objects oder Daten erhalten, die nie dafür vorgesehen waren, die container-Grenze zu überschreiten.

## Funktionsweise

Wenn die runtime einen neuen IPC namespace erstellt, erhält der Prozess ein eigenes isoliertes Set von IPC identifiers. Das bedeutet, dass Befehle wie `ipcs` nur die Objekte anzeigen, die in diesem namespace verfügbar sind. Wenn der Container stattdessen dem host IPC namespace beitritt, werden diese Objekte Teil einer gemeinsamen globalen Ansicht.

Das ist besonders relevant in Umgebungen, in denen Anwendungen oder Services intensiv shared memory nutzen. Selbst wenn der Container nicht allein durch IPC direkt ausbrechen kann, kann der namespace Informationen leak oder prozessübergreifende Interferenzen ermöglichen, die einen späteren Angriff maßgeblich unterstützen.

## Labor

Sie können einen privaten IPC namespace erstellen mit:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Und vergleiche das Laufzeitverhalten mit:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Laufzeitnutzung

Docker und Podman isolieren IPC standardmäßig. Kubernetes gibt einem Pod typischerweise seinen eigenen IPC-Namespace, der von Containern im selben Pod geteilt wird, jedoch nicht standardmäßig mit dem Host. Host IPC sharing ist möglich, sollte aber als erhebliche Verringerung der Isolation und nicht als bloße Laufzeiteinstellung behandelt werden.

## Fehlkonfigurationen

Der offensichtliche Fehler ist `--ipc=host` oder `hostIPC: true`. Dies wird möglicherweise aus Kompatibilitätsgründen mit Legacy-Software oder aus Bequemlichkeit gemacht, ändert jedoch das Vertrauensmodell erheblich. Ein weiteres wiederkehrendes Problem ist, IPC einfach zu übersehen, weil es weniger dramatisch erscheint als host PID oder host networking. Tatsächlich kann die IPC-Oberfläche sehr relevant sein, wenn der Workload Browser, Datenbanken, wissenschaftliche Workloads oder andere Software verarbeitet, die stark gemeinsamen Speicher nutzt.

## Missbrauch

Wenn Host IPC geteilt wird, kann ein Angreifer gemeinsame Speicherobjekte inspizieren oder manipulieren, neue Einblicke in das Verhalten des Hosts oder benachbarter Workloads gewinnen oder die dort gewonnenen Informationen mit Prozesssichtbarkeit und ptrace‑ähnlichen Fähigkeiten kombinieren. IPC sharing ist oft eine unterstützende Schwachstelle und nicht der vollständige breakout path, aber unterstützende Schwachstellen sind wichtig, weil sie reale Angriffsketten verkürzen und stabilisieren.

Der erste nützliche Schritt ist, zu enumerieren, welche IPC-Objekte überhaupt sichtbar sind:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Wenn der IPC-Namespace des Hosts geteilt wird, können große Shared-Memory-Segmente oder interessante Objekt-Eigentümer das Verhalten von Anwendungen sofort offenbaren:
```bash
ipcs -m -p
ipcs -q -p
```
In einigen Umgebungen kann ein leak der Inhalte von `/dev/shm` selbst filenames, artifacts oder tokens offenbaren, die es wert sind, überprüft zu werden:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC-Freigabe verschafft selten von allein sofort Root auf dem Host, kann aber Daten und Koordinationskanäle offenlegen, die spätere Angriffe auf Prozesse deutlich erleichtern.

### Vollständiges Beispiel: Wiederherstellung von Secrets in `/dev/shm`

Der realistischste umfassende Missbrauchsfall ist Datendiebstahl statt direktem Escape. Wenn Host-IPC oder ein weitreichendes Shared-Memory-Layout exponiert sind, können sensible Artefakte manchmal direkt wiederhergestellt werden:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Auswirkungen:

- Extraktion von Geheimnissen oder Sitzungsmaterial, das im gemeinsam genutzten Speicher zurückgelassen wurde
- Einblick in die aktuell auf dem Host aktiven Anwendungen
- Bessere Zielauswahl für spätere PID-namespace- oder ptrace-basierte Angriffe

IPC-Sharing wird daher besser als ein **Angriffsverstärker** denn als ein eigenständiges Host-Escape-Primitive verstanden.

## Prüfungen

Diese Befehle sollen beantworten, ob die Workload eine private IPC-Ansicht hat, ob relevante gemeinsam genutzte Speicher- oder Nachrichtenobjekte sichtbar sind und ob `/dev/shm` selbst nützliche Artefakte offenbart.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Was hier interessant ist:

- Wenn `ipcs -a` Objekte anzeigt, die unerwartet Benutzern oder Diensten gehören, ist das Namespace möglicherweise nicht so isoliert, wie erwartet.
- Große oder ungewöhnliche Shared-Memory-Segmente sind oft eine Untersuchung wert.
- Ein breites `/dev/shm` Mount ist nicht automatisch ein Bug, aber in manchen Umgebungen leaks es Dateinamen, Artefakte und flüchtige Secrets.

IPC erhält selten so viel Aufmerksamkeit wie die größeren Namespace-Typen, aber in Umgebungen, die es stark nutzen, ist das Teilen mit dem Host sehr wohl eine Sicherheitsentscheidung.
