# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Die IPC namespace isoliert **System V IPC objects** und **POSIX message queues**. Dazu gehören shared memory segments, semaphores und message queues, die sonst für nicht zusammenhängende Prozesse auf dem host sichtbar wären. Praktisch verhindert das, dass sich ein container einfach an IPC-Objekte anhängt, die zu anderen workloads oder dem host gehören.

Im Vergleich zu mount-, PID- oder user namespaces wird die IPC namespace oft seltener diskutiert, das sollte jedoch nicht mit Irrelevanz verwechselt werden. Shared memory und verwandte IPC-Mechanismen können sehr nützlichen Zustand enthalten. Wenn die host IPC namespace exponiert ist, kann die workload Sichtbarkeit in inter-process coordination objects oder Daten erhalten, die nie dafür vorgesehen waren, die container-Grenze zu überschreiten.

## Funktionsweise

Wenn die runtime eine neue IPC namespace erstellt, erhält der Prozess einen eigenen isolierten Satz von IPC identifiers. Das bedeutet, Befehle wie `ipcs` zeigen nur die in dieser namespace verfügbaren Objekte. Wenn der container stattdessen der host IPC namespace beitritt, werden diese Objekte Teil einer geteilten globalen Ansicht.

Das ist besonders relevant in Umgebungen, in denen Anwendungen oder Services intensiv shared memory nutzen. Selbst wenn sich der container nicht direkt allein über IPC ausbrechen kann, kann die namespace Informationen leak oder cross-process interference ermöglichen, die einen späteren Angriff erheblich erleichtern.

## Lab

Du kannst eine private IPC namespace mit:
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

Docker und Podman isolieren IPC standardmäßig. Kubernetes gibt dem Pod typischerweise seinen eigenen IPC-Namespace, der von Containern im selben Pod geteilt wird, aber nicht standardmäßig mit dem Host. Das Teilen des Host-IPC ist möglich, sollte jedoch als eine erhebliche Verringerung der Isolation betrachtet werden und nicht als eine kleine Laufzeitoption.

## Fehlkonfigurationen

Der offensichtliche Fehler ist `--ipc=host` oder `hostIPC: true`. Dies kann aus Gründen der Kompatibilität mit Legacy-Software oder aus Bequemlichkeit erfolgen, ändert aber das Vertrauensmodell erheblich. Ein weiteres wiederkehrendes Problem ist, IPC einfach zu übersehen, weil es weniger dramatisch wirkt als host PID oder host networking. In Wirklichkeit kann die IPC-Oberfläche sehr relevant sein, wenn die Workload Browser, Datenbanken, wissenschaftliche Anwendungen oder andere Software verarbeitet, die intensiv shared memory nutzt.

## Missbrauch

Wenn Host-IPC geteilt wird, kann ein Angreifer shared memory objects inspizieren oder manipulieren, neue Einblicke in das Verhalten des Hosts oder benachbarter Workloads gewinnen oder die dort gewonnenen Informationen mit Prozesssichtbarkeit und ptrace-style Fähigkeiten kombinieren. IPC-Sharing ist oft eine unterstützende Schwäche statt des vollständigen Ausbruchswegs, aber unterstützende Schwächen sind wichtig, weil sie reale Angriffsvektoren verkürzen und stabilisieren.

Der erste nützliche Schritt ist, zu enumerieren, welche IPC-Objekte überhaupt sichtbar sind:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Wenn der Host IPC-Namespace geteilt wird, können große Shared-Memory-Segmente oder interessante Objektbesitzer das Anwendungsverhalten sofort offenbaren:
```bash
ipcs -m -p
ipcs -q -p
```
In einigen Umgebungen leaken die Inhalte von `/dev/shm` selbst Dateinamen, Artefakte oder Tokens, die es wert sind, überprüft zu werden:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC-Freigabe führt selten sofort zu Root-Rechten auf dem Host, kann aber Daten und Koordinationskanäle offenlegen, die spätere Prozessangriffe deutlich erleichtern.

### Vollständiges Beispiel: `/dev/shm` Wiederherstellung von Secrets

Der realistischste vollständige Missbrauchsfall ist Datenklau statt direktem Escape. Wenn Host-IPC oder ein breit angelegtes Shared-Memory-Layout offengelegt sind, können sensible Artefakte manchmal direkt wiederhergestellt werden:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Auswirkungen:

- Extraktion von Geheimnissen oder Sitzungsmaterial, das im shared memory zurückgelassen wurde
- Einblick in die derzeit auf dem Host aktiven Anwendungen
- Bessere Zielausrichtung für spätere PID-namespace- oder ptrace-basierte Angriffe

IPC-Sharing wird daher eher als ein **Angriffsverstärker** denn als eigenständige host-escape-Primitive verstanden.

## Prüfungen

Diese Befehle sollen beantworten, ob der Workload eine private IPC-Ansicht hat, ob aussagekräftige shared-memory- oder message-Objekte sichtbar sind und ob `/dev/shm` selbst nützliche Artefakte offenlegt.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Was hier interessant ist:

- Wenn `ipcs -a` Objekte anzeigt, die unerwarteten Benutzern oder Diensten gehören, ist der Namespace möglicherweise nicht so isoliert wie erwartet.
- Große oder ungewöhnliche shared memory segments sind oft eine nähere Untersuchung wert.
- Ein breit angelegter `/dev/shm`-Mount ist nicht automatisch ein Bug, aber in einigen Umgebungen leaks Dateinamen, Artefakte und transient secrets.

IPC erhält selten so viel Aufmerksamkeit wie die größeren Namespace-Typen, aber in Umgebungen, die es intensiv nutzen, ist das Teilen mit dem host sehr wohl eine Sicherheitsentscheidung.
{{#include ../../../../../banners/hacktricks-training.md}}
