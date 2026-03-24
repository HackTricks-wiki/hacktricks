# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

**seccomp** è il meccanismo che permette al kernel di applicare un filtro ai syscalls che un processo può invocare. In ambienti containerizzati, seccomp è normalmente usato in modalità filter in modo che il processo non venga semplicemente etichettato "restricted" in senso vago, ma sia invece soggetto a una politica concreta sui syscall. Questo è importante perché molte container breakouts richiedono l'accesso a interfacce kernel molto specifiche. Se il processo non può invocare con successo i syscalls rilevanti, una vasta classe di attacchi scompare prima che qualsiasi sfumatura di namespaces o capabilities diventi rilevante.

Il modello mentale chiave è semplice: namespaces decidono **cosa il processo può vedere**, capabilities decidono **quali azioni privilegiate il processo è nominalmente autorizzato a tentare**, e seccomp decide **se il kernel accetterà anche il punto di ingresso del syscall per l'azione tentata**. Questo è il motivo per cui seccomp spesso impedisce attacchi che altrimenti sembrerebbero possibili basandosi solo sulle capabilities.

## Impatto sulla sicurezza

Una grande parte della superficie kernel pericolosa è raggiungibile solo tramite un insieme relativamente piccolo di syscalls. Esempi che ricorrono frequentemente nel container hardening includono `mount`, `unshare`, `clone` o `clone3` con particolari flag, `bpf`, `ptrace`, `keyctl` e `perf_event_open`. Un attaccante che può raggiungere quei syscalls potrebbe essere in grado di creare nuovi namespaces, manipolare sottosistemi del kernel o interagire con attack surface di cui un normale application container non ha affatto bisogno.

Per questo i profili seccomp runtime predefiniti sono così importanti. Non sono semplicemente una "extra defense". In molti ambienti fanno la differenza tra un container che può esercitare una vasta parte della funzionalità del kernel e uno che è vincolato a una superficie di syscall più vicina a ciò di cui l'applicazione ha realmente bisogno.

## Modalità e costruzione del filtro

seccomp storicamente aveva una strict mode in cui rimaneva disponibile solo un set minimo di syscall, ma la modalità rilevante per i modern container runtimes è la seccomp filter mode, spesso chiamata **seccomp-bpf**. In questo modello, il kernel valuta un programma di filtro che decide se un syscall debba essere consentito, negato restituendo un errno, intrappolato (trapped), registrato (logged) o causare la kill del processo. I container runtimes usano questo meccanismo perché è sufficientemente espressivo da bloccare ampie classi di syscalls pericolosi pur permettendo il normale comportamento dell'applicazione.

Due esempi a basso livello sono utili perché rendono il meccanismo concreto invece che magico. La strict mode dimostra il vecchio modello "only a minimal syscall set survives":
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
Il `open` finale fa sì che il processo venga terminato perché non fa parte del set minimo di strict mode.

Un esempio di filtro libseccomp mostra più chiaramente il moderno modello di policy:
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
Questo stile di policy è ciò che la maggior parte dei lettori dovrebbe immaginare quando pensa ai profili seccomp a runtime.

## Lab

Un modo semplice per confermare che seccomp è attivo in un container è:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Puoi anche provare un'operazione che i profili predefiniti tendono a limitare:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Se il container viene eseguito con un profilo seccomp predefinito normale, le operazioni in stile `unshare` sono spesso bloccate. Questa è una dimostrazione utile perché mostra che anche se il userspace tool esiste all'interno dell'immagine, il percorso del kernel di cui ha bisogno potrebbe comunque non essere disponibile.
Se il container viene eseguito con un profilo seccomp predefinito normale, le operazioni in stile `unshare` sono spesso bloccate anche quando il userspace tool esiste all'interno dell'immagine.

Per ispezionare lo stato del processo in modo più generale, esegui:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso a runtime

Docker supporta sia i profili seccomp predefiniti che quelli personalizzati e permette agli amministratori di disabilitarli con `--security-opt seccomp=unconfined`. Podman offre un supporto simile e spesso abbina seccomp all'esecuzione rootless in una postura predefinita molto sensata. Kubernetes espone seccomp tramite la configurazione dei workload, dove `RuntimeDefault` è di solito la baseline sensata e `Unconfined` dovrebbe essere trattato come un'eccezione che richiede una giustificazione, anziché come un interruttore di comodità.

Negli ambienti basati su containerd e CRI-O, il percorso preciso è più stratificato, ma il principio è lo stesso: il motore o orchestrator di livello superiore decide cosa deve accadere, e il runtime alla fine installa la policy seccomp risultante per il processo del container. Il risultato dipende comunque dalla configurazione finale del runtime che raggiunge il kernel.

### Esempio di policy personalizzata

Docker e motori simili possono caricare un profilo seccomp personalizzato da JSON. Un esempio minimale che nega `chmod` mentre permette tutto il resto è il seguente:
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
Il comando fallisce con `Operation not permitted`, dimostrando che la restrizione deriva dalla policy sui syscall piuttosto che dai normali permessi dei file. Nella pratica di hardening, le allowlists sono generalmente più efficaci dei valori predefiniti permissivi con una piccola blacklist.

## Configurazioni errate

L'errore più grossolano è impostare seccomp su **unconfined** perché un'applicazione ha fallito sotto la policy predefinita. Questo è comune durante il troubleshooting e molto pericoloso se adottato come soluzione permanente. Una volta che il filtro scompare, molte primitive di breakout basate su syscall diventano nuovamente raggiungibili, specialmente quando sono presenti capabilities potenti o la condivisione del namespace host.

Un altro problema frequente è l'uso di un **profilo permissivo personalizzato** copiato da qualche blog o da una soluzione interna senza una revisione accurata. I team a volte mantengono quasi tutti i syscall pericolosi semplicemente perché il profilo è stato costruito attorno a "impedire che l'app si rompa" piuttosto che a "concedere solo ciò di cui l'app ha effettivamente bisogno". Una terza concezione errata è assumere che seccomp sia meno importante per i container non-root. In realtà, una vasta superficie di attacco del kernel resta rilevante anche quando il processo non è UID 0.

## Abusi

Se seccomp è assente o gravemente indebolito, un attaccante potrebbe riuscire a invocare syscall per la creazione di namespace, ampliare la superficie di attacco del kernel raggiungibile tramite `bpf` o `perf_event_open`, abusare di `keyctl`, o combinare questi percorsi di syscall con capabilities pericolose come `CAP_SYS_ADMIN`. In molti attacchi reali, seccomp non è l'unico controllo mancante, ma la sua assenza accorcia drasticamente il percorso di exploit perché rimuove una delle poche difese che possono fermare una syscall rischiosa prima che il resto del modello di privilegi entri in gioco.

Il test pratico più utile è provare le esatte famiglie di syscall che i profili predefiniti solitamente bloccano. Se improvvisamente funzionano, la postura del container è cambiata molto:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Se `CAP_SYS_ADMIN` o un'altra strong capability è presente, verifica se seccomp è l'unica barriera mancante prima di mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Su alcuni target, l'obiettivo immediato non è ottenere un full escape, ma raccogliere informazioni e ampliare l'attack-surface del kernel. Questi comandi aiutano a determinare se percorsi di syscall particolarmente sensibili sono raggiungibili:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Se seccomp è assente e il container è anche privileged in altri modi, è in questi casi che conviene pivotare verso le breakout techniques più specifiche già documentate nelle pagine legacy container-escape.

### Full Example: seccomp Was The Only Thing Blocking `unshare`

Su molti target, l'effetto pratico della rimozione di seccomp è che namespace-creation o mount syscalls iniziano improvvisamente a funzionare. Se il container ha anche `CAP_SYS_ADMIN`, la seguente sequenza può diventare possibile:
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
Di per sé, questo non è ancora un host escape, ma dimostra che seccomp era la barriera che impediva lo sfruttamento relativo al mount.

### Esempio completo: seccomp disabilitato + cgroup v1 `release_agent`

Se seccomp è disabilitato e il container può montare gerarchie cgroup v1, la tecnica `release_agent` dalla sezione cgroups diventa raggiungibile:
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
Questo non è un exploit che riguarda solo seccomp. Il punto è che, una volta che seccomp non è confinato, syscall-heavy breakout chains che in precedenza erano bloccate possono cominciare a funzionare esattamente come scritte.

## Controlli

Lo scopo di questi controlli è stabilire se seccomp è attivo, se `no_new_privs` lo accompagna e se la configurazione del runtime mostra che seccomp è esplicitamente disabilitato.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Cosa è interessante qui:

- Un valore non-zero di `Seccomp` significa che il filtering è attivo; `0` di solito significa nessuna protezione seccomp.
- Se le runtime security options includono `seccomp=unconfined`, il workload ha perso una delle difese a livello di syscall più utili.
- `NoNewPrivs` non è seccomp in sé, ma vedere entrambi insieme di solito indica una postura di hardening più attenta rispetto a vedere nessuno dei due.

Se un container ha già mount sospetti, broad capabilities o namespace host condivisi, e seccomp è anche unconfined, quella combinazione va considerata un serio segnale di escalation. Il container potrebbe comunque non essere facilmente violabile, ma il numero di entry point del kernel disponibili all'attaccante è aumentato drasticamente.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Di solito abilitato per impostazione predefinita | Usa il profilo seccomp predefinito incluso in Docker salvo override | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Di solito abilitato per impostazione predefinita | Applica il profilo seccomp predefinito del runtime salvo override | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Non garantito per impostazione predefinita** | Se `securityContext.seccompProfile` non è impostato, il valore predefinito è `Unconfined` a meno che il kubelet non abiliti `--seccomp-default`; `RuntimeDefault` o `Localhost` devono altrimenti essere impostati esplicitamente | `securityContext.seccompProfile.type: Unconfined`, lasciare seccomp non impostato su cluster senza `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue le impostazioni del nodo e del Pod di Kubernetes | Il profilo runtime viene utilizzato quando Kubernetes richiede `RuntimeDefault` o quando il kubelet ha l'abbinamento di default seccomp abilitato | Stesso della riga Kubernetes; la configurazione CRI/OCI diretta può anche omettere del tutto seccomp |

Il comportamento di Kubernetes è quello che più spesso sorprende gli operatori. In molti cluster, seccomp è ancora assente a meno che il Pod non lo richieda o il kubelet non sia configurato per impostare `RuntimeDefault` come valore predefinito.
{{#include ../../../../banners/hacktricks-training.md}}
