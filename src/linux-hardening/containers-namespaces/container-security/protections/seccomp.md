# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

**seccomp** è il meccanismo che consente al kernel di applicare un filtro alle syscalls che un processo può invocare. Negli ambienti containerizzati, seccomp viene normalmente utilizzato in modalità filter, in modo che il processo non venga semplicemente contrassegnato come "restricted" in senso vago, ma sia invece soggetto a una policy concreta sulle syscalls. Questo è importante perché molti container breakout richiedono di raggiungere interfacce del kernel molto specifiche. Se il processo non può invocare correttamente le syscalls rilevanti, un'ampia classe di attacchi scompare prima ancora che diventino rilevanti le sfumature relative a namespace o capability.

Il modello mentale fondamentale è semplice: i namespace determinano **cosa può vedere il processo**, le capability determinano **quali azioni privilegiate il processo è nominalmente autorizzato a tentare**, mentre seccomp determina **se il kernel accetterà persino l'entry point della syscall per l'azione tentata**. È per questo che seccomp impedisce spesso attacchi che, basandosi soltanto sulle capability, sembrerebbero altrimenti possibili.

## Impatto sulla sicurezza

Molte superfici pericolose del kernel sono raggiungibili soltanto tramite un insieme relativamente ristretto di syscalls. Tra gli esempi che ricorrono nell'hardening dei container ci sono `mount`, `unshare`, `clone` o `clone3` con flag specifici, `bpf`, `ptrace`, `keyctl` e `perf_event_open`. Un attaccante che riesca a raggiungere queste syscalls potrebbe essere in grado di creare nuovi namespace, manipolare sottosistemi del kernel o interagire con una superficie di attacco di cui un normale application container non ha affatto bisogno.

Per questo i profili seccomp predefiniti dei runtime sono così importanti. Non sono semplicemente una "difesa aggiuntiva". In molti ambienti rappresentano la differenza tra un container in grado di utilizzare un'ampia parte delle funzionalità del kernel e uno limitato a una superficie di syscalls più vicina a ciò di cui l'applicazione ha realmente bisogno.

## Modalità e costruzione dei filter

Storicamente seccomp disponeva di una modalità strict in cui rimaneva disponibile soltanto un insieme minimo di syscalls, ma la modalità rilevante per i moderni container runtime è la modalità seccomp filter, spesso chiamata **seccomp-bpf**. In questo modello, il kernel valuta un programma filter che decide se una syscall debba essere consentita, negata con un errno, intercettata, registrata nei log oppure se debba terminare il processo.<sup>[[1]](#references)</sup> I container runtime utilizzano questo meccanismo perché è sufficientemente espressivo da bloccare ampie classi di syscalls pericolose, consentendo al contempo il normale comportamento delle applicazioni.

Due esempi low-level sono utili perché rendono il meccanismo concreto anziché apparentemente magico. La modalità strict dimostra il vecchio modello secondo cui "sopravvive soltanto un insieme minimo di syscalls":
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
L’ultimo `open` causa l’uccisione del processo perché non fa parte dell’insieme minimo della strict mode.

Un esempio di filtro libseccomp mostra più chiaramente il moderno modello delle policy:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Questo è lo stile di policy che la maggior parte dei lettori dovrebbe immaginare quando pensa ai profili seccomp runtime.

## Laboratorio

Un modo semplice per confermare che seccomp è attivo in un container è:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Puoi anche provare un'operazione che i profili predefiniti comunemente limitano:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Se il container è in esecuzione con un normale profilo seccomp predefinito, le operazioni dello stile di `unshare` sono spesso bloccate. Questa è una dimostrazione utile perché mostra che, anche se lo strumento userspace è presente nell'immagine, il percorso del kernel di cui ha bisogno potrebbe comunque non essere disponibile.
Se il container è in esecuzione con un normale profilo seccomp predefinito, le operazioni dello stile di `unshare` sono spesso bloccate anche quando lo strumento userspace è presente nell'immagine.

Per esaminare più in generale lo stato del processo, esegui:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Utilizzo a runtime

Docker supporta profili seccomp predefiniti e personalizzati e consente agli amministratori di disabilitarli con `--security-opt seccomp=unconfined`.<sup>[[2]](#references)</sup> Podman offre un supporto simile e spesso abbina seccomp all'esecuzione rootless, con una configurazione predefinita molto sensata. Kubernetes espone seccomp tramite la configurazione del workload, dove `RuntimeDefault` è generalmente una baseline ragionevole, mentre `Unconfined` dovrebbe essere considerato un'eccezione che richiede una motivazione, non un semplice toggle per comodità.<sup>[[3]](#references)</sup>

Negli ambienti basati su containerd e CRI-O, il percorso esatto è più stratificato, ma il principio è lo stesso: il motore o l'orchestrator di livello superiore decide cosa debba accadere, mentre il runtime installa infine la policy seccomp risultante per il processo del container. Il risultato dipende comunque dalla configurazione finale del runtime che raggiunge il kernel.

### Esempio di policy personalizzata

Docker e motori simili possono caricare un profilo seccomp personalizzato da JSON. Un esempio minimo che nega `chmod` consentendo tutto il resto è il seguente:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Applicato con:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Il comando fallisce con `Operation not permitted`, dimostrando che la restrizione deriva dalla syscall policy e non soltanto dalle normali file permissions. In un hardening reale, le allowlist sono generalmente più solide rispetto a impostazioni predefinite permissive con una piccola blacklist.

## Misconfigurations

L'errore più grossolano consiste nell'impostare seccomp su **unconfined** perché un'applicazione non funzionava con la policy predefinita. Questo è comune durante il troubleshooting e molto pericoloso come soluzione permanente. Una volta rimosso il filtro, molte primitive di breakout basate su syscall diventano nuovamente raggiungibili, soprattutto quando sono presenti anche capabilities potenti o la condivisione dei namespace dell'host.

Un altro problema frequente è l'uso di un **custom permissive profile** copiato da qualche blog o workaround interno senza un'attenta revisione. A volte i team mantengono quasi tutte le syscall pericolose semplicemente perché il profilo è stato creato con l'obiettivo di "impedire che l'app si blocchi" invece di "concedere solo ciò di cui l'app ha realmente bisogno". Un terzo malinteso consiste nel ritenere seccomp meno importante per i container non-root. In realtà, una parte significativa dell'attack surface del kernel rimane rilevante anche quando il processo non ha UID 0.

## Abuse

Se seccomp è assente o fortemente indebolito, un attacker potrebbe essere in grado di invocare syscall per la creazione di namespace, ampliare l'attack surface del kernel raggiungibile tramite `bpf` o `perf_event_open`, abusare di `keyctl` oppure combinare questi percorsi basati su syscall con capabilities pericolose come `CAP_SYS_ADMIN`. In molti attacchi reali, seccomp non è l'unico controllo mancante, ma la sua assenza accorcia drasticamente il percorso di exploit perché rimuove una delle poche difese in grado di bloccare una syscall rischiosa prima ancora che entri in gioco il resto del modello dei privilegi.

Il test pratico più utile consiste nel provare le esatte famiglie di syscall che i profili predefiniti solitamente bloccano. Se improvvisamente funzionano, la postura di sicurezza del container è cambiata molto:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Se `CAP_SYS_ADMIN` o un'altra capability potente è presente, verifica se seccomp è l'unica barriera mancante prima di un abuso basato su mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Su alcuni target, l'obiettivo immediato non è una full escape, ma l'information gathering e l'espansione della attack surface del kernel. Questi comandi aiutano a determinare se sono raggiungibili percorsi di syscall particolarmente sensibili:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Se seccomp è assente e il container è inoltre privilegiato in altri modi, è allora che ha senso fare pivot verso le tecniche più specifiche di breakout già documentate nelle pagine legacy sul container-escape.

### Esempio completo: seccomp era l'unico elemento che bloccava `unshare`

Su molti target, l'effetto pratico della rimozione di seccomp è che le syscall per la creazione dei namespace o per il mount iniziano improvvisamente a funzionare. Se il container dispone anche di `CAP_SYS_ADMIN`, la seguente sequenza potrebbe diventare possibile:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Di per sé, questo non è ancora un host escape, ma dimostra che seccomp era la barriera che impediva lo sfruttamento relativo a mount.

### Esempio completo: seccomp disabilitato + cgroup v1 `release_agent`

Se seccomp è disabilitato e il container può montare gerarchie cgroup v1, la tecnica `release_agent` della sezione cgroups diventa raggiungibile:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Questo non è un exploit esclusivamente di seccomp. Il punto è che, una volta che seccomp è unconfined, le catene di breakout basate intensivamente sulle syscall, precedentemente bloccate, potrebbero iniziare a funzionare esattamente come sono state scritte.

## Verifiche

Lo scopo di queste verifiche è stabilire se seccomp è attivo, se `no_new_privs` lo accompagna e se la configurazione del runtime mostra che seccomp è stato disabilitato esplicitamente.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Cosa è interessante qui:

- Un valore `Seccomp` diverso da zero significa che il filtering è attivo; `0` di solito significa che non è presente alcuna protezione seccomp.
- Se le opzioni di sicurezza del runtime includono `seccomp=unconfined`, il workload ha perso una delle sue difese più utili a livello di syscall.
- `NoNewPrivs` non è seccomp in sé, ma la presenza di entrambi indica generalmente un approccio all'hardening più attento rispetto alla presenza di nessuno dei due.

Se un container presenta già mount sospetti, capabilities ampie o namespace dell'host condivisi, e seccomp è anch'esso unconfined, questa combinazione dovrebbe essere considerata un importante segnale di escalation. Il container potrebbe non essere ancora facilmente compromettibile, ma il numero di entry point del kernel disponibili all'attaccante è aumentato drasticamente.

## Default del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Di solito abilitato per impostazione predefinita | Utilizza il profilo seccomp predefinito integrato di Docker, salvo override | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Di solito abilitato per impostazione predefinita | Applica il profilo seccomp predefinito del runtime, salvo override | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Non garantito per impostazione predefinita** | Se `securityContext.seccompProfile` non è impostato, il valore predefinito è `Unconfined`, a meno che kubelet non abiliti `--seccomp-default`; altrimenti è necessario impostare esplicitamente `RuntimeDefault` o `Localhost` | `securityContext.seccompProfile.type: Unconfined`, lasciare seccomp non impostato nei cluster senza `seccompDefault`, `privileged: true` |
| containerd / CRI-O sotto Kubernetes | Segue le impostazioni del nodo e del Pod di Kubernetes | Il profilo del runtime viene utilizzato quando Kubernetes richiede `RuntimeDefault` o quando è abilitato il defaulting seccomp di kubelet | Come nella riga Kubernetes; la configurazione diretta CRI/OCI può anche omettere completamente seccomp |

Il comportamento di Kubernetes è quello che sorprende più spesso gli operatori. In molti cluster, seccomp è ancora assente a meno che il Pod non lo richieda o kubelet non sia configurato per usare `RuntimeDefault` come valore predefinito.<sup>[[3]](#references)</sup>

## References

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
