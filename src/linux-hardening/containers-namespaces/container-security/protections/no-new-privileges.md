# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` è una funzionalità di hardening del kernel che impedisce a un processo di ottenere privilegi aggiuntivi tramite `execve()`. In termini pratici, una volta impostato il flag, l'esecuzione di un binario setuid, di un binario setgid o di un file con file capabilities Linux non concede privilegi aggiuntivi oltre a quelli già posseduti dal processo. Negli ambienti containerizzati, questo è importante perché molte catene di privilege-escalation si basano sulla ricerca, all'interno dell'immagine, di un eseguibile che modifica i privilegi quando viene avviato.

Dal punto di vista difensivo, `no_new_privs` non sostituisce namespaces, seccomp o il dropping delle capabilities. È un livello di rinforzo. Blocca una specifica classe di escalation successiva, dopo che è già stato ottenuto il code execution. Questo lo rende particolarmente utile negli ambienti in cui le immagini contengono helper binaries, artifact dei package manager o strumenti legacy che altrimenti sarebbero pericolosi se combinati con una compromissione parziale.

## Funzionamento

Il flag del kernel alla base di questo comportamento è `PR_SET_NO_NEW_PRIVS`. Una volta impostato per un processo, le chiamate successive a `execve()` non possono aumentare i privilegi. Il dettaglio importante è che il processo può comunque eseguire i binari; semplicemente non può usare quei binari per oltrepassare un privilege boundary che il kernel altrimenti autorizzerebbe.

Il comportamento del kernel è inoltre **ereditato e irreversibile**: una volta che un task imposta `no_new_privs`, il bit viene ereditato tramite `fork()`, `clone()` ed `execve()`, e non può essere successivamente rimosso. Questo è utile negli assessment perché un singolo `NoNewPrivs: 1` sul processo del container di solito significa che anche i discendenti dovrebbero rimanere in quella modalità, a meno che non si stia analizzando un process tree completamente diverso.

Negli ambienti orientati a Kubernetes, `allowPrivilegeEscalation: false` corrisponde a questo comportamento per il processo del container. Nei runtime in stile Docker e Podman, l'equivalente viene solitamente abilitato esplicitamente tramite una security option. A livello OCI, lo stesso concetto appare come `process.noNewPrivileges`.

## Nuances importanti

`no_new_privs` blocca l'acquisizione di privilegi **al momento dell'exec**, non ogni modifica dei privilegi. In particolare:

- le transizioni setuid e setgid smettono di funzionare tramite `execve()`
- le file capabilities non vengono aggiunte al permitted set tramite `execve()`
- gli LSM come AppArmor o SELinux non allentano i vincoli dopo `execve()`
- i privilegi già posseduti rimangono comunque già posseduti

Quest'ultimo punto è importante dal punto di vista operativo. Se il processo è già in esecuzione come root, possiede già una capability pericolosa oppure ha già accesso a una potente runtime API o a un host mount scrivibile, l'impostazione di `no_new_privs` non neutralizza queste esposizioni. Rimuove soltanto un comune **passaggio successivo** in una catena di privilege-escalation.

È inoltre importante notare che il flag non blocca le modifiche dei privilegi che non dipendono da `execve()`. Ad esempio, un task che dispone già di privilegi sufficienti può ancora chiamare direttamente `setuid(2)` oppure ricevere un file descriptor privilegiato tramite un Unix socket. Per questo motivo, `no_new_privs` dovrebbe essere valutato insieme a [seccomp](seccomp.md), ai capability sets e all'esposizione dei namespaces, anziché essere considerato una soluzione autonoma.

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
Il punto del confronto non è che `su` sia universalmente exploitable. È che la stessa image può comportarsi in modo molto diverso a seconda che `execve()` possa ancora attraversare un privilege boundary.

## Impatto sulla sicurezza

Se `no_new_privs` è assente, un foothold all'interno del container può ancora essere elevato tramite helper setuid o binaries con file capabilities. Se è presente, questi privilege changes post-exec vengono bloccati. L'effetto è particolarmente rilevante nelle broad base images che includono molte utilities di cui l'application non ha mai avuto bisogno.

Esiste anche un'importante interazione con seccomp. I task non privilegiati generalmente devono avere `no_new_privs` impostato prima di poter installare un seccomp filter in filter mode. Questo è uno dei motivi per cui i container hardened mostrano spesso sia `Seccomp` sia `NoNewPrivs` abilitati. Dal punto di vista di un attacker, la presenza di entrambi solitamente indica che l'environment è stato configurato deliberatamente, anziché accidentalmente.

## Misconfigurations

Il problema più comune è semplicemente non abilitare il controllo negli environments in cui sarebbe compatibile. In Kubernetes, lasciare `allowPrivilegeEscalation` abilitato è spesso l'errore operativo predefinito. In Docker e Podman, omettere la security option pertinente ha lo stesso effetto. Un altro failure mode ricorrente consiste nel presumere che, poiché un container è "not privileged", le privilege transitions durante `exec` siano automaticamente irrilevanti.

Un pitfall Kubernetes più sottile è che `allowPrivilegeEscalation: false` **non** viene rispettato nel modo previsto quando il container è `privileged` o quando dispone di `CAP_SYS_ADMIN`. La Kubernetes API documenta che `allowPrivilegeEscalation` è effettivamente sempre true in questi casi. In pratica, questo significa che il campo dovrebbe essere considerato un solo segnale nella postura finale, non una garanzia che il runtime sia terminato con `NoNewPrivs: 1`.

## Abuse

Se `no_new_privs` non è impostato, la prima domanda è se la image contenga binaries che possono ancora aumentare i privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Risultati interessanti includono:

- `NoNewPrivs: 0`
- helper setuid come `su`, `mount`, `passwd` o strumenti di amministrazione specifici della distribuzione
- binari con file capabilities che concedono privilegi di rete o sul file system

In una valutazione reale, questi risultati non dimostrano da soli un’escalation funzionante, ma identificano esattamente i binari che vale la pena testare successivamente.

In Kubernetes, verifica anche che l’intento dello YAML corrisponda alla realtà del kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Combinazioni interessanti includono:

- `allowPrivilegeEscalation: false` nella Pod spec ma `NoNewPrivs: 0` nel container
- presenza di `cap_sys_admin`, che rende il campo Kubernetes molto meno affidabile
- `Seccomp: 0` e `NoNewPrivs: 0`, che di solito indica una runtime posture ampiamente indebolita, anziché un singolo errore isolato

### Esempio completo: Privilege Escalation in-Container tramite setuid

Questo controllo di solito impedisce la **privilege escalation in-container** anziché l'host escape direttamente. Se `NoNewPrivs` è `0` ed esiste un helper setuid, testalo esplicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se è presente e funzionante un binario setuid noto, prova ad avviarlo in modo da preservare la transizione dei privilegi:
```bash
/bin/su -c id 2>/dev/null
```
Questo, di per sé, non consente di evadere dal container, ma può trasformare un accesso iniziale con privilegi ridotti all'interno del container in container-root, spesso prerequisito per una successiva evasione verso l'host tramite mount, runtime socket o interfacce rivolte al kernel.

## Checks

L'obiettivo di questi checks è stabilire se l'acquisizione di privilegi al momento dell'exec è bloccata e se l'immagine contiene ancora helper rilevanti nel caso in cui non lo sia.
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
- `NoNewPrivs: 1` insieme a `Seccomp: 2` è un segno comune di una postura di hardening più intenzionale.
- Un manifest Kubernetes che indica `allowPrivilegeEscalation: false` è utile, ma lo stato del kernel è la fonte di verità.
- Un'immagine minimale con pochi o nessun binario setuid/file-cap offre a un attacker meno opzioni di post-exploitation anche quando manca `no_new_privs`.

## Default del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato per impostazione predefinita | Abilitato esplicitamente con `--security-opt no-new-privileges=true`; esiste anche un default a livello di daemon tramite `dockerd --no-new-privileges` | omettere il flag, `--privileged` |
| Podman | Non abilitato per impostazione predefinita | Abilitato esplicitamente con `--security-opt no-new-privileges` o una configurazione di sicurezza equivalente | omettere l'opzione, `--privileged` |
| Kubernetes | Controllato dalla policy del workload | `allowPrivilegeEscalation: false` richiede l'effetto, ma `privileged: true` e `CAP_SYS_ADMIN` lo mantengono di fatto abilitato | `allowPrivilegeEscalation: true`, `privileged: true`, aggiunta di `CAP_SYS_ADMIN` |
| containerd / CRI-O sotto Kubernetes | Segue le impostazioni del workload Kubernetes / `OCI process.noNewPrivileges` | Solitamente ereditato dal security context del Pod e tradotto nella configurazione del runtime OCI | come nella riga Kubernetes |

Questa protezione spesso è semplicemente assente perché nessuno l'ha abilitata, non perché il runtime non la supporti.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
