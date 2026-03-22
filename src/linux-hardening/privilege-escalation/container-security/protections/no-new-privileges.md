# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` è una funzionalità di hardening del kernel che impedisce a un processo di ottenere privilegi maggiori tramite `execve()`. In termini pratici, una volta che il flag è impostato, eseguire un setuid binary, un setgid binary, o un file con Linux file capabilities non concede privilegi aggiuntivi oltre a quelli che il processo aveva già. In ambienti containerizzati, questo è importante perché molte catene di privilege-escalation si basano sul trovare un eseguibile all'interno dell'immagine che cambi i privilegi quando viene avviato.

Dal punto di vista difensivo, `no_new_privs` non è un sostituto di namespaces, seccomp, o capability dropping. È uno strato di rinforzo. Blocca una classe specifica di escalation successiva dopo che è già stata ottenuta l'esecuzione di codice. Questo lo rende particolarmente prezioso in ambienti dove le immagini contengono helper binaries, package-manager artifacts, o legacy tools che altrimenti sarebbero pericolosi se combinati con una compromissione parziale.

## Operation

Il flag del kernel dietro questo comportamento è `PR_SET_NO_NEW_PRIVS`. Una volta impostato per un processo, le successive chiamate a `execve()` non possono aumentare i privilegi. Il dettaglio importante è che il processo può comunque eseguire binari; semplicemente non può usare quei binari per oltrepassare un confine di privilegi che il kernel altrimenti onorerebbe.

In ambienti orientati a Kubernetes, `allowPrivilegeEscalation: false` mappa questo comportamento per il processo del container. Nei runtime in stile Docker e Podman, l'equivalente è solitamente abilitato esplicitamente tramite un'opzione di security.

## Lab

Ispeziona lo stato del processo corrente:
```bash
grep NoNewPrivs /proc/self/status
```
Confrontalo con un container in cui il runtime abilita il flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Su un workload rafforzato, il risultato dovrebbe mostrare `NoNewPrivs: 1`.

## Security Impact

Se `no_new_privs` è assente, un foothold all'interno del container può ancora essere elevato tramite setuid helpers o binari con file capabilities. Se è presente, tali cambiamenti di privilegio post-exec vengono bloccati. L'effetto è particolarmente rilevante nelle immagini di base ampie che includono molte utility di cui l'applicazione non aveva bisogno.

## Misconfigurations

Il problema più comune è semplicemente non abilitare il controllo in ambienti in cui sarebbe compatibile. In Kubernetes, lasciare `allowPrivilegeEscalation` abilitato è spesso l'errore operativo predefinito. In Docker e Podman, omettere l'opzione di sicurezza rilevante ha lo stesso effetto. Un altro modo di fallimento ricorrente è presumere che, perché un container è "not privileged", le transizioni di privilegi al momento dell'esecuzione siano automaticamente irrilevanti.

## Abuse

Se `no_new_privs` non è impostato, la prima domanda è se l'immagine contiene binari che possono ancora elevare i privilegi:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Risultati interessanti includono:

- `NoNewPrivs: 0`
- helper setuid come `su`, `mount`, `passwd`, o strumenti di amministrazione specifici della distribuzione
- binari con file capabilities che concedono privilegi di rete o del filesystem

In una valutazione reale, questi risultati di per sé non dimostrano un'escalation funzionante, ma identificano esattamente i binari che vale la pena testare successivamente.

### Esempio completo: In-Container Privilege Escalation Through setuid

Questo controllo solitamente previene **in-container privilege escalation** piuttosto che un host escape diretto. Se `NoNewPrivs` è `0` e è presente un helper setuid, testalo esplicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se è presente un binario setuid noto e funzionante, prova ad avviarlo in modo da preservare la transizione dei privilegi:
```bash
/bin/su -c id 2>/dev/null
```
Questo non permette di per sé di evadere dal container, ma può convertire un low-privilege foothold all'interno del container in container-root, che spesso diventa il prerequisito per una successiva host escape tramite mounts, runtime sockets o kernel-facing interfaces.

## Checks

L'obiettivo di questi controlli è stabilire se exec-time privilege gain è bloccato e se l'image contiene ancora helpers che sarebbero rilevanti se non lo fosse.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Cosa è interessante qui:

- `NoNewPrivs: 1` è di solito il risultato più sicuro.
- `NoNewPrivs: 0` significa che i percorsi di escalation basati su setuid e file-cap restano rilevanti.
- Un'immagine minimale con pochi o nessun binario setuid/file-cap offre a un attacker meno opzioni di post-exploitation anche quando `no_new_privs` manca.

## Valori predefiniti del runtime

| Runtime / platform | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato per impostazione predefinita | Abilitato esplicitamente con `--security-opt no-new-privileges=true` | omettendo il flag, `--privileged` |
| Podman | Non abilitato per impostazione predefinita | Abilitato esplicitamente con `--security-opt no-new-privileges` o configurazione di sicurezza equivalente | omettendo l'opzione, `--privileged` |
| Kubernetes | Controllato dalla policy del workload | `allowPrivilegeEscalation: false` abilita l'effetto; molti workload lo lasciano ancora abilitato | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue le impostazioni del workload di Kubernetes | Di solito ereditato dal Pod security context | come nella riga Kubernetes |

Questa protezione è spesso assente semplicemente perché nessuno l'ha attivata, non perché il runtime non la supporti.
{{#include ../../../../banners/hacktricks-training.md}}
