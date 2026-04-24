# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` è una funzionalità di hardening del kernel che impedisce a un processo di ottenere più privilegi tramite `execve()`. In pratica, una volta impostato il flag, eseguire un binario setuid, un binario setgid o un file con Linux file capabilities non concede privilegi aggiuntivi oltre a quelli che il processo aveva già. In ambienti containerizzati, questo è importante perché molte catene di privilege-escalation si basano sul trovare un eseguibile dentro l'immagine che cambia privilegio quando viene avviato.

Dal punto di vista difensivo, `no_new_privs` non sostituisce namespaces, seccomp o il dropping delle capabilities. È uno strato di rinforzo. Blocca una specifica classe di escalation successiva dopo che il code execution è già stato ottenuto. Questo lo rende particolarmente utile in ambienti in cui le immagini contengono helper binaries, artefatti del package-manager o strumenti legacy che altrimenti sarebbero pericolosi se combinati con una compromissione parziale.

## Operation

Il flag del kernel dietro questo comportamento è `PR_SET_NO_NEW_PRIVS`. Una volta impostato per un processo, le successive chiamate `execve()` non possono aumentare i privilegi. Il dettaglio importante è che il processo può ancora eseguire binari; semplicemente non può usare quei binari per oltrepassare un confine di privilegio che il kernel altrimenti riconoscerebbe.

Il comportamento del kernel è anche **ereditato e irreversibile**: una volta che un task imposta `no_new_privs`, il bit viene ereditato attraverso `fork()`, `clone()` ed `execve()`, e non può essere disattivato in seguito. Questo è utile nelle assessment perché un singolo `NoNewPrivs: 1` sul processo del container di solito significa che anche i discendenti dovrebbero restare in quella modalità, a meno che tu non stia guardando un albero di processi completamente diverso.

Negli ambienti orientati a Kubernetes, `allowPrivilegeEscalation: false` si mappa su questo comportamento per il processo del container. In runtime stile Docker e Podman, l'equivalente viene di solito abilitato esplicitamente tramite un security option. A livello OCI, lo stesso concetto appare come `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` blocca l'aumento di privilegi **al momento di exec**, non ogni cambiamento di privilegio. In particolare:

- le transizioni setuid e setgid smettono di funzionare attraverso `execve()`
- le file capabilities non si aggiungono al permitted set su `execve()`
- i LSM come AppArmor o SELinux non allentano i vincoli dopo `execve()`
- il privilegio già posseduto resta comunque già posseduto

Quest'ultimo punto è importante operativamente. Se il processo gira già come root, ha già una capability pericolosa, oppure ha già accesso a una potente runtime API o a un host mount scrivibile, impostare `no_new_privs` non neutralizza queste esposizioni. Rimuove solo un comune **passo successivo** in una chain di privilege-escalation.

Nota anche che il flag non blocca i cambiamenti di privilegio che non dipendono da `execve()`. Per esempio, un task già sufficientemente privilegiato può ancora chiamare direttamente `setuid(2)` oppure ricevere un file descriptor privilegiato tramite un Unix socket. Per questo `no_new_privs` va letto insieme a [seccomp](seccomp.md), ai set di capabilities e all'esposizione dei namespace, invece che come risposta autonoma.

## Lab

Inspect the current process state:
```bash
grep NoNewPrivs /proc/self/status
```
Confrontalo con un container in cui il runtime abilita il flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Su un workload rafforzato, il risultato dovrebbe mostrare `NoNewPrivs: 1`.

Puoi anche dimostrare l'effetto reale contro un binario setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Il punto del confronto non è che `su` sia universalmente sfruttabile. È che la stessa image può comportarsi in modo molto diverso a seconda che `execve()` sia ancora consentito di attraversare un privilege boundary.

## Security Impact

Se `no_new_privs` è assente, un foothold dentro il container può ancora essere elevato tramite helper setuid o binary con file capabilities. Se è presente, quei cambi di privilegio post-`exec` vengono interrotti. L'effetto è particolarmente rilevante nelle broad base images che includono molte utility che l'applicazione non avrebbe mai avuto bisogno di avere in primo luogo.

C'è anche un'interazione importante con seccomp. I task non privilegiati in genere devono avere `no_new_privs` impostato prima di poter installare un seccomp filter in filter mode. Questo è uno dei motivi per cui i container hardenati spesso mostrano sia `Seccomp` sia `NoNewPrivs` abilitati insieme. Dal punto di vista di un attacker, vedere entrambi di solito significa che l'ambiente è stato configurato deliberatamente e non per errore.

## Misconfigurations

Il problema più comune è semplicemente non abilitare il controllo in ambienti in cui sarebbe compatibile. In Kubernetes, lasciare `allowPrivilegeEscalation` abilitato è spesso l'errore operativo di default. In Docker e Podman, omettere la security option rilevante ha lo stesso effetto. Un altro errore ricorrente è presumere che, poiché un container non è "privileged", le transizioni di privilegio al momento dell'exec siano automaticamente irrilevanti.

Una trappola più sottile in Kubernetes è che `allowPrivilegeEscalation: false` **non** viene rispettato nel modo in cui le persone si aspettano quando il container è `privileged` o quando ha `CAP_SYS_ADMIN`. La Kubernetes API documenta che `allowPrivilegeEscalation` è di fatto sempre true in quei casi. In pratica, questo significa che il campo dovrebbe essere trattato come un segnale nel posture finale, non come una garanzia che il runtime sia finito con `NoNewPrivs: 1`.

## Abuse

Se `no_new_privs` non è impostato, la prima domanda è se l'image contiene binary che possono ancora aumentare il privilegio:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
I risultati interessanti includono:

- `NoNewPrivs: 0`
- helper setuid come `su`, `mount`, `passwd`, o tool di amministrazione specifici della distribuzione
- binari con file capabilities che concedono privilegi di rete o filesystem

In una valutazione reale, questi risultati non provano da soli una escalation funzionante, ma identificano esattamente i binari che vale la pena testare successivamente.

In Kubernetes, verifica anche che l'intento del YAML corrisponda alla realtà del kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Combinazioni interessanti includono:

- `allowPrivilegeEscalation: false` nel Pod spec ma `NoNewPrivs: 0` nel container
- `cap_sys_admin` presente, il che rende il campo di Kubernetes molto meno affidabile
- `Seccomp: 0` e `NoNewPrivs: 0`, che di solito indica una postura runtime ampiamente indebolita piuttosto che un singolo errore isolato

### Full Example: In-Container Privilege Escalation Through setuid

Questo controllo di solito impedisce **in-container privilege escalation** invece di un host escape diretto. Se `NoNewPrivs` è `0` e esiste un helper setuid, testalo esplicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se è presente e funzionante un setuid binary noto, prova a lanciarlo in modo che preservi la transizione di privilegi:
```bash
/bin/su -c id 2>/dev/null
```
Questo da solo non consente di uscire dal container, ma può trasformare un foothold a privilegi bassi all'interno del container in container-root, che spesso diventa il prerequisito per un successivo host escape tramite mount, runtime sockets o interfacce rivolte al kernel.

## Checks

L'obiettivo di questi checks è stabilire se l'aumento di privilegi al momento dell'exec è bloccato e se l'immagine contiene ancora helper che sarebbero rilevanti se non lo fosse.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Quello che è interessante qui:

- `NoNewPrivs: 1` è di solito il risultato più sicuro.
- `NoNewPrivs: 0` significa che i percorsi di escalation basati su setuid e file-cap restano rilevanti.
- `NoNewPrivs: 1` più `Seccomp: 2` è un segnale comune di una postura di hardening più intenzionale.
- Un manifest di Kubernetes che dice `allowPrivilegeEscalation: false` è utile, ma lo stato del kernel è la verità di riferimento.
- Un'immagine minimale con pochi o nessun binario setuid/file-cap dà a un attacker meno opzioni di post-exploitation anche quando `no_new_privs` manca.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato di default | Abilitato esplicitamente con `--security-opt no-new-privileges=true`; esiste anche un default a livello di daemon tramite `dockerd --no-new-privileges` | omettendo il flag, `--privileged` |
| Podman | Non abilitato di default | Abilitato esplicitamente con `--security-opt no-new-privileges` o configurazione di sicurezza equivalente | omettendo l'opzione, `--privileged` |
| Kubernetes | Controllato dalla policy del workload | `allowPrivilegeEscalation: false` richiede l'effetto, ma `privileged: true` e `CAP_SYS_ADMIN` lo mantengono di fatto true | `allowPrivilegeEscalation: true`, `privileged: true`, aggiungendo `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Segue le impostazioni del workload di Kubernetes / OCI `process.noNewPrivileges` | Di solito ereditato dal security context del Pod e tradotto nella configurazione OCI del runtime | come nella riga di Kubernetes |

Questa protezione spesso manca semplicemente perché nessuno l'ha attivata, non perché il runtime non la supporti.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
