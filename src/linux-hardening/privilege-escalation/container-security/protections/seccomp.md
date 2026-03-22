# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

**seccomp** è il meccanismo che permette al kernel di applicare un filtro alle syscall che un processo può invocare. In ambienti containerizzati, seccomp è normalmente usato in modalità filtro in modo che il processo non sia semplicemente etichettato come "restricted" in un senso vago, ma sia invece soggetto a una concreta policy di syscall. Questo è importante perché molte container breakouts richiedono l'accesso a interfacce kernel molto specifiche. Se il processo non può invocare con successo le syscall rilevanti, un'ampia classe di attacchi scompare prima che qualsiasi sfumatura di namespaces o capabilities diventi rilevante.

Il modello mentale chiave è semplice: namespaces decidono **ciò che il processo può vedere**, capabilities decidono **quali azioni privilegiate il processo è nominalmente autorizzato a tentare**, e seccomp decide **se il kernel accetterà anche il punto d'ingresso della syscall per l'azione tentata**. Per questo seccomp spesso impedisce attacchi che altrimenti sembrerebbero possibili basandosi solo sulle capabilities.

## Impatto sulla sicurezza

Una grande parte della superficie kernel pericolosa è raggiungibile solo tramite un insieme relativamente piccolo di syscall. Esempi che contano ripetutamente nel hardening dei container includono `mount`, `unshare`, `clone` o `clone3` con flag particolari, `bpf`, `ptrace`, `keyctl`, e `perf_event_open`. Un attacker che può raggiungere quelle syscall potrebbe essere in grado di creare nuovi namespaces, manipolare sottosistemi del kernel o interagire con superficie di attacco che un normale container applicativo non necessita affatto.

Questo è il motivo per cui i profili seccomp di runtime predefiniti sono così importanti. Non sono semplicemente una "difesa aggiuntiva". In molti ambienti fanno la differenza tra un container che può esercitare una vasta porzione di funzionalità del kernel e uno che è vincolato a una superficie di syscall più vicina a ciò di cui l'applicazione ha realmente bisogno.

## Modalità e costruzione del filtro

seccomp storicamente aveva una modalità strict in cui restava disponibile solo un insieme minimo di syscall, ma la modalità rilevante per i moderni runtime di container è la seccomp filter mode, spesso chiamata **seccomp-bpf**. In questo modello, il kernel valuta un programma di filtro che decide se una syscall debba essere consentita, negata restituendo un errno, generare una trap, registrata nei log, o terminare il processo. I runtime dei container usano questo meccanismo perché è sufficientemente espressivo da bloccare ampie classi di syscall pericolose pur permettendo il comportamento normale dell'applicazione.

Due esempi a basso livello sono utili perché rendono il meccanismo concreto anziché magico. La modalità strict dimostra il vecchio modello "only a minimal syscall set survives":
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
La chiamata finale `open` causa la terminazione del processo perché non fa parte del set minimo della strict mode.

Un esempio di filtro libseccomp mostra il modello di policy moderno in modo più chiaro:
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
Questo stile di policy è ciò che la maggior parte dei lettori dovrebbe immaginare quando pensa ai runtime seccomp profiles.

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
Se il container è eseguito con un normale profilo seccomp predefinito, le operazioni in stile `unshare` sono spesso bloccate. Questa è una dimostrazione utile perché mostra che, anche se lo userspace tool esiste all'interno dell'immagine, il percorso kernel di cui ha bisogno potrebbe comunque non essere disponibile.

Se il container è eseguito con un normale profilo seccomp predefinito, le operazioni in stile `unshare` sono spesso bloccate anche quando lo userspace tool esiste all'interno dell'immagine.

Per ispezionare lo stato del processo in modo più generale, eseguire:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso a runtime

Docker supporta sia i profili seccomp predefiniti che quelli personalizzati e permette agli amministratori di disabilitarli con `--security-opt seccomp=unconfined`. Podman offre un supporto simile e spesso associa seccomp all'esecuzione rootless in un'impostazione predefinita molto sensata. Kubernetes espone seccomp tramite la configurazione del carico di lavoro, dove `RuntimeDefault` è di solito la baseline sensata e `Unconfined` dovrebbe essere trattato come un'eccezione che richiede giustificazione piuttosto che come un'opzione di comodità.

Negli ambienti basati su containerd e CRI-O, il percorso esatto è più stratificato, ma il principio è lo stesso: il motore o orchestratore di livello superiore decide cosa deve accadere, e il runtime installa infine la policy seccomp risultante per il processo del container. L'esito dipende comunque dalla configurazione finale del runtime che arriva al kernel.

### Esempio di policy personalizzata

Docker e motori simili possono caricare un profilo seccomp personalizzato da JSON. Un esempio minimale che nega `chmod` consentendo tutto il resto è il seguente:
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
Il comando fallisce con `Operation not permitted`, dimostrando che la restrizione proviene dalla politica delle syscall piuttosto che dai normali permessi dei file. In un reale processo di hardening, le allowlists sono generalmente più robuste rispetto a default permissivi con una piccola blacklist.

## Errori di configurazione

L'errore più grossolano è impostare seccomp su **unconfined** perché un'applicazione ha fallito con la policy di default. Questo è comune durante il troubleshooting e molto pericoloso come soluzione permanente. Una volta che il filtro scompare, molte primitive di breakout basate su syscall diventano nuovamente raggiungibili, specialmente quando sono presenti capability potenti o la condivisione del namespace host.

Un altro problema frequente è l'uso di un **custom permissive profile** copiato da qualche blog o workaround interno senza essere revisionato con attenzione. I team a volte mantengono quasi tutte le syscall pericolose semplicemente perché il profilo è stato creato per "impedire che l'app si rompa" piuttosto che per "concedere solo ciò di cui l'app ha effettivamente bisogno". Una terza idea errata è presumere che seccomp sia meno importante per i container non-root. In realtà, gran parte della superficie d'attacco del kernel resta rilevante anche quando il processo non è UID 0.

## Abuso

Se seccomp è assente o notevolmente indebolito, un attaccante potrebbe essere in grado di invocare syscall per la creazione di namespace, espandere la superficie d'attacco del kernel raggiungibile tramite `bpf` o `perf_event_open`, abusare di `keyctl`, o combinare quei percorsi di syscall con capability pericolose come `CAP_SYS_ADMIN`. In molti attacchi reali, seccomp non è l'unico controllo mancante, ma la sua assenza accorcia drasticamente il percorso dell'exploit perché rimuove una delle poche difese che possono bloccare una syscall rischiosa prima che il resto del modello di privilegi entri in gioco.

Il test pratico più utile è provare le esatte famiglie di syscall che i profili di default solitamente bloccano. Se funzionano improvvisamente, la postura del container è cambiata notevolmente:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Se `CAP_SYS_ADMIN` o un'altra capability potente è presente, verifica se seccomp è l'unica barriera mancante prima di mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Su alcuni target, il valore immediato non è una fuga completa ma la raccolta di informazioni e l'espansione della superficie di attacco del kernel. Questi comandi aiutano a determinare se percorsi di syscall particolarmente sensibili sono raggiungibili:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Se seccomp è assente e il container è anche privilegiato in altri modi, è il momento giusto per pivotare verso le più specifiche breakout techniques già documentate nelle pagine legacy container-escape.

### Full Example: seccomp Was The Only Thing Blocking `unshare`

Su molti target, l'effetto pratico della rimozione di seccomp è che la creazione di namespace o le mount syscalls improvvisamente cominciano a funzionare. Se il contenitore ha anche `CAP_SYS_ADMIN`, la seguente sequenza potrebbe diventare possibile:
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
Di per sé questo non è ancora un host escape, ma dimostra che seccomp era la barriera che impediva lo sfruttamento legato al mount.

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
Questo non è un exploit esclusivamente basato su seccomp. Il punto è che, una volta che seccomp non è più confinato, syscall-heavy breakout chains che in precedenza erano bloccate possono iniziare a funzionare esattamente come scritte.

## Checks

Lo scopo di questi controlli è stabilire se seccomp è attivo, se è accompagnato da `no_new_privs`, e se la configurazione di runtime mostra che seccomp è disabilitato esplicitamente.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
What is interesting here:

- Un valore non zero di `Seccomp` indica che il filtraggio è attivo; `0` di solito significa nessuna protezione seccomp.
- Se le opzioni di sicurezza del runtime includono `seccomp=unconfined`, il workload ha perso una delle sue difese più utili a livello di syscall.
- `NoNewPrivs` non è seccomp di per sé, ma vedere entrambi insieme di solito indica una postura di hardening più accurata rispetto a non vedere nessuno dei due.

Se un container ha già mount sospetti, capacità ampie o namespace host condivisi, e anche seccomp è `unconfined`, quella combinazione dovrebbe essere trattata come un segnale di escalation importante. Il container potrebbe comunque non essere facilmente compromettibile, ma il numero di punti di ingresso del kernel disponibili per l'attaccante è aumentato bruscamente.

## Runtime Defaults

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Di solito abilitato per impostazione predefinita | Usa il profilo seccomp predefinito integrato di Docker a meno che non sia sovrascritto | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Di solito abilitato per impostazione predefinita | Applica il profilo seccomp predefinito del runtime a meno che non sia sovrascritto | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Non garantito per impostazione predefinita** | Se `securityContext.seccompProfile` non è impostato, il valore predefinito è `Unconfined` a meno che il kubelet non abiliti `--seccomp-default`; `RuntimeDefault` o `Localhost` devono altrimenti essere impostati esplicitamente | `securityContext.seccompProfile.type: Unconfined`, lasciare seccomp non impostato su cluster senza `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue le impostazioni del nodo e dei Pod di Kubernetes | Il profilo runtime viene usato quando Kubernetes richiede `RuntimeDefault` o quando il kubelet abilita il valore predefinito di seccomp | Stesso della riga Kubernetes; la configurazione CRI/OCI diretta può anche omettere completamente seccomp |

Il comportamento di Kubernetes è quello che sorprende di più gli operatori. In molti cluster, seccomp è ancora assente a meno che il Pod non lo richieda o il kubelet sia configurato per impostare di default `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
