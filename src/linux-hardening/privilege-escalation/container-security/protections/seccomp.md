# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

**seccomp** è il meccanismo che permette al kernel di applicare un filtro alle syscalls che un processo può invocare. Negli ambienti containerizzati, seccomp viene normalmente usato in modalità filtro in modo che il processo non venga semplicemente etichettato come "restricted" in senso vago, ma sia invece soggetto a una politica concreta sulle syscall. Questo è importante perché molti container breakouts richiedono l'accesso a interfacce kernel molto specifiche. Se il processo non può invocare con successo le syscalls rilevanti, una larga classe di attacchi scompare prima che qualsiasi sfumatura di namespace o capability diventi rilevante.

Il modello mentale chiave è semplice: namespaces decidono **cosa il processo può vedere**, capabilities decidono **quali azioni privilegiate il processo è nominalmente autorizzato a tentare**, e seccomp decide **se il kernel accetterà anche il punto d'ingresso della syscall per l'azione tentata**. Per questo seccomp previene frequentemente attacchi che altrimenti sembrerebbero possibili basandosi solo sulle capabilities.

## Impatto sulla sicurezza

Una gran parte della superficie kernel pericolosa è raggiungibile solo tramite un insieme relativamente piccolo di syscalls. Esempi che contano ripetutamente nell'hardening dei container includono `mount`, `unshare`, `clone` o `clone3` con flag particolari, `bpf`, `ptrace`, `keyctl` e `perf_event_open`. Un attaccante che può raggiungere quelle syscalls potrebbe essere in grado di creare nuovi namespaces, manipolare sottosistemi del kernel o interagire con superficie di attacco che un normale container applicativo non necessita affatto.

Per questo i profili seccomp del runtime predefiniti sono così importanti. Non sono semplicemente una "difesa aggiuntiva". In molti ambienti sono la differenza tra un container che può esercitare una larga porzione delle funzionalità del kernel e uno che è limitato a una superficie di syscall più vicina a ciò di cui l'applicazione ha effettivamente bisogno.

## Modalità e costruzione del filtro

seccomp storicamente aveva una strict mode in cui rimaneva disponibile solo un piccolo set di syscalls, ma la modalità rilevante per i moderni container runtimes è la seccomp filter mode, spesso chiamata **seccomp-bpf**. In questo modello, il kernel valuta un programma filtro che decide se una syscall dovrebbe essere consentita, negata con un errno, intercettata, registrata o terminare il processo. I container runtimes usano questo meccanismo perché è sufficientemente espressivo da bloccare ampie classi di syscalls pericolose pur consentendo il normale comportamento dell'applicazione.

Sono utili due esempi a basso livello perché rendono il meccanismo concreto anziché magico. La strict mode dimostra il vecchio modello "only a minimal syscall set survives":
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
L'ultimo `open` provoca la terminazione del processo perché non fa parte dell'insieme minimo della strict mode.

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
Puoi anche provare un'operazione che i profili predefiniti solitamente limitano:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Se il container è eseguito con un profilo seccomp predefinito normale, le operazioni in stile `unshare` sono spesso bloccate. Questa è una dimostrazione utile perché mostra che anche se lo strumento userspace esiste all'interno dell'immagine, il percorso kernel di cui ha bisogno potrebbe comunque non essere disponibile.
Se il container è eseguito con un profilo seccomp predefinito normale, le operazioni in stile `unshare` sono spesso bloccate anche quando lo strumento userspace esiste all'interno dell'immagine.

Per ispezionare lo stato del processo in modo più generale, esegui:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso a runtime

Docker supporta sia i profili seccomp predefiniti che quelli personalizzati e permette agli amministratori di disabilitarli con `--security-opt seccomp=unconfined`. Podman ha un supporto simile e spesso abbina seccomp all'esecuzione senza root in una postura predefinita molto sensata. Kubernetes espone seccomp tramite la configurazione del workload, dove `RuntimeDefault` è generalmente la baseline ragionevole e `Unconfined` dovrebbe essere trattato come un'eccezione che richiede giustificazione piuttosto che come un interruttore di comodo.

Negli ambienti basati su containerd e CRI-O il percorso è più stratificato, ma il principio è lo stesso: il motore o orchestrator di livello superiore decide cosa deve accadere, e il runtime alla fine installa la policy seccomp risultante per il processo del container. L'esito dipende comunque dalla configurazione runtime finale che raggiunge il kernel.

### Esempio di policy personalizzata

Docker e motori simili possono caricare un profilo seccomp personalizzato da JSON. Un esempio minimale che nega `chmod` pur permettendo tutto il resto è il seguente:
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
Il comando fallisce con `Operation not permitted`, dimostrando che la restrizione deriva dalla policy dei syscall piuttosto che dai normali permessi dei file. Nel hardening reale, le allowlists sono generalmente più efficaci dei default permissivi con una piccola blacklist.

## Configurazioni errate

L'errore più grossolano è impostare seccomp su **unconfined** perché un'applicazione è fallita con la policy di default. Questo è comune durante il troubleshooting ed è molto pericoloso se usato come soluzione permanente. Una volta rimosso il filtro, molte primitive di breakout basate sui syscall tornano raggiungibili, soprattutto quando sono presenti anche potenti capabilities o host namespace sharing.

Un altro problema frequente è l'uso di un **custom permissive profile** copiato da qualche blog o da una soluzione interna senza una revisione accurata. I team a volte mantengono quasi tutti i syscall pericolosi semplicemente perché il profilo è stato creato per "stop the app from breaking" invece che per "grant only what the app actually needs". Una terza idea sbagliata è presumere che seccomp sia meno importante per i container non-root. In realtà, molta superficie di attacco del kernel rimane rilevante anche quando il processo non è UID 0.

## Abuso

Se seccomp è assente o gravemente indebolito, un attaccante può invocare syscall per la creazione di namespace, espandere la kernel attack surface raggiungibile tramite `bpf` o `perf_event_open`, abusare di `keyctl`, o combinare quei percorsi di syscall con capabilities pericolose come `CAP_SYS_ADMIN`. In molti attacchi reali seccomp non è l'unico controllo mancante, ma la sua assenza accorcia drasticamente il percorso di exploit perché rimuove una delle poche difese che possono bloccare un syscall rischioso prima che entri in gioco il resto del modello di privilegi.

Il test pratico più utile è provare le esatte famiglie di syscall che i profili di default normalmente bloccano. Se improvvisamente funzionano, la postura del container è molto cambiata:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Se `CAP_SYS_ADMIN` o un'altra capability forte è presente, verifica se seccomp è l'unica barriera mancante prima di mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Su alcuni target, il valore immediato non è un completo escape, ma raccogliere informazioni e l'espansione della attack-surface del kernel. Questi comandi aiutano a determinare se percorsi syscall particolarmente sensibili sono raggiungibili:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Se seccomp è assente e il container è anche privilegiato in altri modi, è in quel caso che ha senso pivot into the more specific breakout techniques already documented in the legacy container-escape pages.

### Esempio completo: seccomp era l'unica cosa che bloccava `unshare`

Su molti target, l'effetto pratico della rimozione di seccomp è che namespace-creation o mount syscalls improvvisamente iniziano a funzionare. Se il container ha anche `CAP_SYS_ADMIN`, la seguente sequenza può diventare possibile:
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
Di per sé questo non è ancora un host escape, ma dimostra che seccomp era la barriera che impediva lo sfruttamento relativo al mount.

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
Questo non è un exploit esclusivamente basato su seccomp. Il punto è che, una volta che seccomp non è più confinato, le catene di breakout basate su syscall che prima erano bloccate possono iniziare a funzionare esattamente come scritte.

## Verifiche

Lo scopo di queste verifiche è stabilire se seccomp è attivo, se è accompagnato da `no_new_privs` e se la configurazione runtime mostra che seccomp è esplicitamente disabilitato.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Cosa è interessante qui:

- Un valore non zero di `Seccomp` significa che il filtraggio è attivo; `0` di solito indica assenza di protezione seccomp.
- Se le opzioni di sicurezza del runtime includono `seccomp=unconfined`, il workload ha perso una delle difese a livello di syscall più utili.
- `NoNewPrivs` non è seccomp in sé, ma vederli entrambi solitamente indica una postura di hardening più attenta rispetto a non vederne nessuno.

Se un container ha già mount sospetti, capability ampie, o namespace host condivisi, e seccomp è anche unconfined, quella combinazione dovrebbe essere considerata un segnale di escalation importante. Il container potrebbe comunque non essere immediatamente sfruttabile, ma il numero di punti di ingresso del kernel disponibili all'attaccante è aumentato notevolmente.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Di solito abilitato per impostazione predefinita | Usa il profilo seccomp predefinito integrato in Docker a meno che non venga sovrascritto | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Di solito abilitato per impostazione predefinita | Applica il profilo seccomp predefinito del runtime a meno che non venga sovrascritto | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Non garantito per impostazione predefinita** | Se `securityContext.seccompProfile` non è impostato, il valore predefinito è `Unconfined` a meno che il kubelet non abiliti `--seccomp-default`; `RuntimeDefault` o `Localhost` devono altrimenti essere impostati esplicitamente | `securityContext.seccompProfile.type: Unconfined`, lasciare seccomp non impostato su cluster senza `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue le impostazioni del nodo e dei Pod di Kubernetes | Il profilo del runtime viene usato quando Kubernetes richiede `RuntimeDefault` o quando il defaulting seccomp del kubelet è abilitato | Stesso della riga Kubernetes; la configurazione CRI/OCI diretta può anche omettere completamente seccomp |

Il comportamento di Kubernetes è quello che sorprende più spesso gli operatori. In molti cluster, seccomp è ancora assente a meno che il Pod non lo richieda o il kubelet non sia configurato per impostare `RuntimeDefault` come predefinito.
