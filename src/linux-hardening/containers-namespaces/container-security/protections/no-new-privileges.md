# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` è una funzionalità di hardening del kernel che impedisce a un processo di ottenere privilegi aggiuntivi tramite `execve()`. In termini pratici, una volta impostato il flag, l'esecuzione di un binario setuid, di un binario setgid o di un file con Linux file capabilities non concede privilegi aggiuntivi oltre a quelli già posseduti dal processo. Negli ambienti containerizzati, questo è importante perché molte catene di privilege escalation si basano sulla ricerca, all'interno dell'immagine, di un eseguibile che modifica i privilegi quando viene avviato.

Dal punto di vista difensivo, `no_new_privs` non sostituisce namespaces, seccomp o il dropping delle capabilities. È un ulteriore livello di protezione. Blocca una classe specifica di escalation successiva, dopo che è già stato ottenuto code execution. Questo lo rende particolarmente utile negli ambienti in cui le immagini contengono helper binaries, artefatti dei package manager o strumenti legacy che altrimenti sarebbero pericolosi se combinati con una compromissione parziale.

## Operatività

Il flag del kernel alla base di questo comportamento è `PR_SET_NO_NEW_PRIVS`. Una volta impostato per un processo, le successive chiamate a `execve()` non possono aumentare i privilegi. Il dettaglio importante è che il processo può comunque eseguire i binari; semplicemente non può utilizzarli per oltrepassare un privilege boundary che il kernel altrimenti riconoscerebbe.<sup>[[1]](#references)</sup>

Il comportamento del kernel è inoltre **ereditato e irreversibile**: una volta che un task imposta `no_new_privs`, il bit viene ereditato attraverso `fork()`, `clone()` ed `execve()`, e non può essere successivamente rimosso.<sup>[[1]](#references)</sup> Questo è utile durante gli assessment perché un singolo `NoNewPrivs: 1` sul processo del container generalmente significa che anche i processi discendenti dovrebbero rimanere in quella modalità, a meno che non si stia analizzando un process tree completamente diverso.

Negli ambienti orientati a Kubernetes, `allowPrivilegeEscalation: false` corrisponde a questo comportamento per il processo del container.<sup>[[2]](#references)</sup> Nei runtime in stile Docker e Podman, l'equivalente viene solitamente abilitato esplicitamente tramite una security option. A livello OCI, lo stesso concetto compare come `process.noNewPrivileges`.

## Nuance importanti

`no_new_privs` blocca l'acquisizione di privilegi **durante l'exec**, non ogni modifica dei privilegi.<sup>[[1]](#references)</sup> In particolare:

- le transizioni setuid e setgid smettono di funzionare attraverso `execve()`
- le file capabilities non vengono aggiunte al permitted set durante `execve()`
- gli LSM come AppArmor o SELinux non allentano i vincoli dopo `execve()`
- i privilegi già posseduti rimangono comunque già posseduti

Quest'ultimo punto è importante dal punto di vista operativo. Se il processo viene già eseguito come root, possiede già una capability pericolosa oppure ha già accesso a una potente runtime API o a un host mount scrivibile, l'impostazione di `no_new_privs` non neutralizza queste esposizioni. Rimuove soltanto un comune **passaggio successivo** in una catena di privilege escalation.

Si noti inoltre che il flag non blocca le modifiche dei privilegi che non dipendono da `execve()`.<sup>[[1]](#references)</sup> Ad esempio, un task che dispone già di privilegi sufficienti può ancora chiamare direttamente `setuid(2)` oppure ricevere un file descriptor privilegiato tramite un Unix socket. Per questo motivo, `no_new_privs` dovrebbe essere valutato insieme a [seccomp](seccomp.md), ai capability sets e all'esposizione dei namespaces, invece di essere considerato una soluzione autonoma.

## Laboratorio

Ispeziona lo stato del processo corrente:
```bash
grep NoNewPrivs /proc/self/status
```
Confrontalo con un container in cui il runtime abilita il flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Su un workload hardened, il risultato dovrebbe mostrare `NoNewPrivs: 1`.

Puoi anche dimostrare l'effetto effettivo su un binario setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Il punto del confronto non è che `su` sia universalmente exploitable. È che la stessa image può comportarsi in modo molto diverso a seconda che `execve()` possa ancora attraversare un confine di privilegio.

## Impatto sulla sicurezza

Se `no_new_privs` è assente, un foothold all'interno del container può ancora essere elevato tramite helper setuid o binary con file capabilities. Se è presente, tali cambiamenti di privilegio post-exec vengono bloccati. L'effetto è particolarmente rilevante nelle broad base images che includono molte utility di cui l'applicazione non aveva mai bisogno.

Esiste anche un'importante interazione con seccomp. I task non privilegiati generalmente devono avere `no_new_privs` impostato prima di poter installare un filtro seccomp in modalità filter.<sup>[[1]](#references)</sup> Questo è uno dei motivi per cui i container hardened mostrano spesso sia `Seccomp` sia `NoNewPrivs` abilitati. Dal punto di vista di un attacker, vedere entrambi di solito significa che l'ambiente è stato configurato deliberatamente e non accidentalmente.

## Misconfigurations

Il problema più comune è semplicemente non abilitare il controllo negli ambienti in cui sarebbe compatibile. In Kubernetes, lasciare `allowPrivilegeEscalation` abilitato è spesso l'errore operativo predefinito. In Docker e Podman, omettere la security option rilevante ha lo stesso effetto. Un altro failure mode ricorrente è presumere che, poiché un container è "not privileged", le transizioni di privilegio durante `exec` siano automaticamente irrilevanti.

Una pitfall Kubernetes più sottile è che `allowPrivilegeEscalation: false` **non** viene rispettato nel modo previsto quando il container è `privileged` o quando dispone di `CAP_SYS_ADMIN`. La documentazione dell'API Kubernetes specifica che in questi casi `allowPrivilegeEscalation` è effettivamente sempre true.<sup>[[2]](#references)</sup> In pratica, questo significa che il campo dovrebbe essere trattato come un segnale tra gli altri nella postura finale, non come una garanzia che il runtime sia terminato con `NoNewPrivs: 1`.

## Abuse

Se `no_new_privs` non è impostato, la prima domanda è se l'image contenga binary che possono ancora aumentare i privilegi:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
I risultati interessanti includono:

- `NoNewPrivs: 0`
- helper setuid come `su`, `mount`, `passwd` o strumenti di amministrazione specifici della distribuzione
- binari con file capabilities che concedono privilegi di rete o sul filesystem

In una valutazione reale, questi risultati non dimostrano di per sé un'escalation funzionante, ma identificano esattamente i binari che vale la pena testare successivamente.

In Kubernetes, verifica anche che l'intento dello YAML corrisponda alla realtà del kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Combinazioni interessanti includono:

- `allowPrivilegeEscalation: false` nella specifica del Pod ma `NoNewPrivs: 0` nel container
- `cap_sys_admin` presente, il che rende il campo Kubernetes molto meno affidabile
- `Seccomp: 0` e `NoNewPrivs: 0`, cosa che di solito indica una postura del runtime ampiamente indebolita invece di un singolo errore isolato

### Esempio completo: privilege escalation in-container tramite setuid

Questo controllo di solito previene la **privilege escalation in-container** piuttosto che direttamente l'escape dall'host. Se `NoNewPrivs` è `0` ed esiste un helper setuid, testalo esplicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se è presente e funzionante un binario setuid noto, prova ad avviarlo in modo da preservare la transizione dei privilegi:
```bash
/bin/su -c id 2>/dev/null
```
Questo non consente di per sé di evadere dal container, ma può trasformare un foothold con pochi privilegi all'interno del container in container-root, che spesso diventa il prerequisito per un successivo host escape tramite mounts, runtime sockets o interfacce rivolte al kernel.

## Checks

L'obiettivo di questi checks è stabilire se l'acquisizione di privilegi in fase di exec è bloccata e se l'immagine contiene ancora helper che sarebbero rilevanti qualora non lo fosse.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Cosa è interessante qui:

- `NoNewPrivs: 1` è solitamente il risultato più sicuro.
- `NoNewPrivs: 0` significa che i percorsi di escalation basati su setuid e file-cap rimangono rilevanti.
- `NoNewPrivs: 1` insieme a `Seccomp: 2` è un segnale comune di un approccio di hardening più intenzionale.
- Un manifest Kubernetes che indica `allowPrivilegeEscalation: false` è utile, ma lo stato del kernel è la fonte autorevole.
- Un'immagine minimale con pochi o nessun binario setuid/file-cap offre a un attacker meno opzioni di post-exploitation anche quando manca `no_new_privs`.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato per impostazione predefinita | Abilitato esplicitamente con `--security-opt no-new-privileges=true`; esiste anche un'impostazione predefinita globale del daemon tramite `dockerd --no-new-privileges` | omettere il flag, `--privileged` |
| Podman | Non abilitato per impostazione predefinita | Abilitato esplicitamente con `--security-opt no-new-privileges` o una configurazione di sicurezza equivalente | omettere l'opzione, `--privileged` |
| Kubernetes | Controllato dalla policy del workload | `allowPrivilegeEscalation: false` richiede questo effetto, ma `privileged: true` e `CAP_SYS_ADMIN` lo mantengono effettivamente abilitato | `allowPrivilegeEscalation: true`, `privileged: true`, aggiungere `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Segue le impostazioni del workload Kubernetes / `OCI process.noNewPrivileges` | Solitamente ereditato dal security context del Pod e tradotto nella configurazione del runtime OCI | come nella riga Kubernetes |

Questa protezione spesso è semplicemente assente perché nessuno l'ha abilitata, non perché il runtime non la supporti.

## Riferimenti

- [1] [Documentazione del kernel Linux: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Configurare un Security Context per un Pod o un Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
