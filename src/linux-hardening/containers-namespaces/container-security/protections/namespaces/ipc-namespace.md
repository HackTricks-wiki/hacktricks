# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der IPC namespace isoliert **System V IPC objects** und **POSIX message queues**. Dazu gehören Shared-Memory-Segmente, Semaphoren und Message Queues, die ansonsten über nicht zusammengehörige Prozesse auf dem Host hinweg sichtbar wären. In der Praxis verhindert dies, dass sich ein Container ohne Weiteres mit IPC-Objekten anderer Workloads oder des Hosts verbindet.

Im Vergleich zu Mount-, PID- oder User namespaces wird der IPC namespace häufig weniger thematisiert. Das sollte jedoch nicht mit Bedeutungslosigkeit verwechselt werden. Shared Memory und verwandte IPC-Mechanismen können äußerst nützliche Zustände enthalten. Wenn der IPC namespace des Hosts offengelegt ist, erhält der Workload möglicherweise Einblick in Interprozess-Koordinationsobjekte oder Daten, die nie die Container-Grenze überschreiten sollten.

## Funktionsweise

Wenn die Runtime einen neuen IPC namespace erstellt, erhält der Prozess einen eigenen isolierten Satz von IPC identifiers. Das bedeutet, dass Befehle wie `ipcs` nur die in diesem namespace verfügbaren Objekte anzeigen. Tritt der Container stattdessen dem IPC namespace des Hosts bei, werden diese Objekte Teil einer gemeinsamen globalen Ansicht.

Dies ist besonders in Umgebungen relevant, in denen Anwendungen oder Services intensiv Shared Memory verwenden. Selbst wenn der Container allein über IPC keinen direkten Breakout durchführen kann, kann der namespace Informationen leaken oder Interferenzen zwischen Prozessen ermöglichen, die einen späteren Angriff wesentlich unterstützen.

## Lab

Du kannst einen privaten IPC namespace erstellen mit:
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

Docker und Podman isolieren IPC standardmäßig. Kubernetes gibt dem Pod typischerweise einen eigenen IPC-Namespace, der von Containern im selben Pod gemeinsam genutzt wird, standardmäßig jedoch nicht vom Host. Das Teilen des Host-IPC ist möglich, sollte aber als wesentliche Verringerung der Isolation und nicht als geringfügige Runtime-Option betrachtet werden.

## Fehlkonfigurationen

Der offensichtliche Fehler ist `--ipc=host` oder `hostIPC: true`. Dies kann aus Kompatibilitätsgründen mit Legacy-Software oder aus Bequemlichkeit erfolgen, verändert jedoch das Trust-Modell erheblich. Ein weiteres wiederkehrendes Problem ist, IPC einfach zu übersehen, weil es weniger dramatisch wirkt als Host-PID oder Host-Networking. Wenn die Workload jedoch Browser, Datenbanken, wissenschaftliche Workloads oder andere Software verarbeitet, die intensiv von Shared Memory Gebrauch macht, kann die IPC-Angriffsfläche sehr relevant sein.

## Missbrauch

Wenn Host-IPC geteilt wird, kann ein Angreifer Shared-Memory-Objekte untersuchen oder beeinflussen, neue Einblicke in das Verhalten des Hosts oder benachbarter Workloads gewinnen oder die dort erlangten Informationen mit Process Visibility und Ptrace-ähnlichen Fähigkeiten kombinieren. IPC-Sharing ist häufig eine unterstützende Schwachstelle und nicht der vollständige Breakout-Pfad, aber unterstützende Schwachstellen sind wichtig, weil sie reale Attack Chains verkürzen und stabilisieren.

Der erste nützliche Schritt besteht darin, zunächst alle sichtbaren IPC-Objekte aufzulisten:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Wenn der IPC-Namespace des Hosts gemeinsam genutzt wird, können große Shared-Memory-Segmente oder interessante Objektbesitzer das Anwendungsverhalten sofort offenlegen:
```bash
ipcs -m -p
ipcs -q -p
```
In einigen Umgebungen verraten die Inhalte von `/dev/shm` selbst Dateinamen, Artefakte oder Tokens, die eine Überprüfung wert sind:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC-Sharing führt selten allein sofort zu Host-root, kann aber Daten- und Koordinationskanäle offenlegen, die spätere Prozessangriffe erheblich erleichtern.

### Vollständiges Beispiel: Wiederherstellung von Secrets aus `/dev/shm`

Der realistischste vollständige Missbrauchsfall ist Datendiebstahl statt eines direkten Escapes. Wenn Host-IPC oder ein weitreichendes Shared-Memory-Layout offengelegt wird, können sensible Artefakte manchmal direkt wiederhergestellt werden:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Auswirkungen:

- Extraktion von Secrets oder Session-Material, das im Shared Memory zurückgelassen wurde
- Einblicke in die aktuell auf dem Host aktiven Anwendungen
- Besseres Targeting für spätere PID-namespace- oder ptrace-basierte Angriffe

Das Teilen von IPC sollte daher eher als **Angriffsverstärker** und nicht als eigenständige Host-Escape-Primitive verstanden werden.

## Prüfungen

Diese Befehle sollen klären, ob der Workload eine private IPC-Sicht besitzt, ob relevante Shared-Memory- oder Message-Objekte sichtbar sind und ob `/dev/shm` selbst nützliche Artefakte offenlegt.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Was hier interessant ist:

- Wenn `ipcs -a` Objekte offenlegt, die unerwarteten Benutzern oder Services gehören, ist der Namespace möglicherweise nicht so isoliert wie erwartet.
- Große oder ungewöhnliche Shared-Memory-Segmente sind häufig eine nähere Untersuchung wert.
- Ein weitreichender `/dev/shm`-Mount ist nicht automatisch ein Bug, aber in manchen Umgebungen leakt er Dateinamen, Artefakte und kurzlebige Secrets.

IPC erhält selten so viel Aufmerksamkeit wie die größeren Namespace-Typen. In Umgebungen, die es intensiv nutzen, ist die gemeinsame Nutzung mit dem Host jedoch eindeutig eine Sicherheitsentscheidung.

{{#include ../../../../../banners/hacktricks-training.md}}
