# IPC-Namensraum

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der IPC-Namensraum isoliert **System V IPC objects** und **POSIX message queues**. Dazu gehören geteilte Speichersegmente, Semaphore und Message Queues, die sonst für voneinander unabhängige Prozesse auf dem Host sichtbar wären. Praktisch verhindert dies, dass sich ein container einfach an IPC-Objekte anheftet, die anderen Workloads oder dem Host gehören.

Im Vergleich zu mount-, PID- oder user-namespaces wird der IPC-Namensraum seltener diskutiert, was jedoch nicht mit Bedeutungslosigkeit verwechselt werden sollte. Shared memory und verwandte IPC-Mechanismen können hochgradig nützlichen Zustand enthalten. Wenn der Host-IPC-Namensraum exposed ist, kann die Workload Sichtbarkeit in Interprozess-Koordinationsobjekte oder Daten erlangen, die niemals dafür vorgesehen waren, die Container-Grenze zu überschreiten.

## Funktionsweise

Wenn die runtime einen neuen IPC-Namensraum erstellt, erhält der Prozess seinen eigenen isolierten Satz von IPC-Identifikatoren. Das bedeutet, dass Befehle wie `ipcs` nur die Objekte anzeigen, die in diesem Namensraum verfügbar sind. Wenn der Container stattdessen dem Host-IPC-Namensraum beitritt, werden diese Objekte Teil einer gemeinsamen globalen Ansicht.

Das ist besonders wichtig in Umgebungen, in denen Anwendungen oder Dienste stark shared memory verwenden. Selbst wenn der Container nicht allein durch IPC direkt ausbrechen kann, kann der Namensraum Informationen leak oder Interprozess-Interferenzen ermöglichen, die einen späteren Angriff wesentlich unterstützen.

## Labor

Sie können einen privaten IPC-Namensraum erstellen mit:
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

Docker und Podman isolieren IPC standardmäßig. Kubernetes weist dem Pod typischerweise seinen eigenen IPC-Namespace zu, der von Containern im gleichen Pod geteilt wird, aber nicht standardmäßig mit dem Host. Host-IPC-Sharing ist möglich, sollte aber als eine bedeutende Verringerung der Isolation betrachtet werden und nicht als eine kleine Laufzeitoption.

## Fehlkonfigurationen

Der offensichtliche Fehler ist `--ipc=host` oder `hostIPC: true`. Das wird vielleicht aus Kompatibilitätsgründen mit Legacy-Software oder aus Bequemlichkeit gemacht, verändert aber das Vertrauensmodell erheblich. Ein weiteres wiederkehrendes Problem ist, IPC einfach zu übersehen, weil es weniger dramatisch wirkt als host PID oder host networking. In Wirklichkeit, wenn die Workload Browser, Datenbanken, wissenschaftliche Workloads oder andere Software verarbeitet, die intensiven Gebrauch von shared memory macht, kann die IPC-Oberfläche sehr relevant sein.

## Missbrauch

Wenn host IPC geteilt wird, kann ein Angreifer shared memory objects inspizieren oder manipulieren, neue Einblicke in das Verhalten des Hosts oder benachbarter Workloads gewinnen oder die dort gewonnenen Informationen mit Prozesssichtbarkeit und ptrace-style Fähigkeiten kombinieren. IPC-Sharing ist oft eine unterstützende Schwachstelle und nicht der vollständige breakout path, aber unterstützende Schwachstellen sind wichtig, weil sie reale Angriffsketten verkürzen und stabilisieren.

Der erste nützliche Schritt ist, aufzulisten, welche IPC-Objekte überhaupt sichtbar sind:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Wenn der IPC-Namespace des Hosts geteilt wird, können große gemeinsame Speichersegmente oder Besitzer interessanter Objekte das Verhalten von Anwendungen sofort offenbaren:
```bash
ipcs -m -p
ipcs -q -p
```
In einigen Umgebungen enthalten die Inhalte von `/dev/shm` selbst einen leak von Dateinamen, Artefakten oder Tokens, die es wert sind, überprüft zu werden:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC-Sharing verschafft für sich genommen selten sofort root auf dem Host, kann aber Daten- und Koordinationskanäle offenlegen, die spätere Angriffe auf Prozesse deutlich erleichtern.

### Vollständiges Beispiel: `/dev/shm` Secret Recovery

Der realistischste vollständige Missbrauchsfall ist Datendiebstahl statt direktem Escape. Wenn host IPC oder ein breites shared-memory layout offengelegt ist, können sensible Artefakte manchmal direkt wiederhergestellt werden:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Auswirkungen:

- Extraktion von secrets oder Session-Material, das im shared memory zurückgelassen wurde
- Einblick in die Anwendungen, die derzeit auf dem Host aktiv sind
- Besseres Targeting für spätere PID-namespace- oder ptrace-basierte Angriffe

IPC sharing ist daher eher als **Angriffsverstärker** zu verstehen denn als eigenständige host-escape-Primitive.

## Prüfungen

Diese Befehle sollen beantworten, ob die Workload eine private IPC-Ansicht hat, ob aussagekräftige shared-memory- oder Message-Objekte sichtbar sind und ob `/dev/shm` selbst nützliche Artefakte preisgibt.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Was hier interessant ist:

- Wenn `ipcs -a` Objekte anzeigt, die unerwarteten Benutzern oder Diensten gehören, ist der namespace möglicherweise nicht so isoliert wie erwartet.
- Große oder ungewöhnliche geteilte Speichersegmente sind oft eine Untersuchung wert.
- Ein breites `/dev/shm` mount ist nicht automatisch ein bug, aber in einigen Umgebungen leaks es Dateinamen, Artefakte und transient secrets.

IPC erhält selten so viel Aufmerksamkeit wie die größeren namespace-Typen, doch in Umgebungen, die es intensiv nutzen, ist das Teilen mit dem host eine klare Sicherheitsentscheidung.
{{#include ../../../../../banners/hacktricks-training.md}}
