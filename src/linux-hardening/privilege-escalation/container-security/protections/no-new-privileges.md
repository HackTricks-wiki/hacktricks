# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` è una funzionalità di hardening del kernel che impedisce a un processo di ottenere privilegi maggiori attraverso `execve()`. In termini pratici, una volta che il flag è impostato, l'esecuzione di un binario setuid, di un binario setgid o di un file con Linux file capabilities non concede privilegi aggiuntivi oltre a quelli che il processo possedeva già. In ambienti containerizzati, questo è importante perché molte catene di privilege-escalation si basano sulla presenza di un eseguibile all'interno dell'immagine che modifica i privilegi al lancio.

Dal punto di vista difensivo, `no_new_privs` non è un sostituto di namespaces, seccomp, o capability dropping. È uno strato di rinforzo. Blocca una specifica classe di escalation successiva dopo che l'esecuzione di codice è già stata ottenuta. Questo lo rende particolarmente prezioso in ambienti in cui le immagini contengono helper binaries, package-manager artifacts, o legacy tools che altrimenti sarebbero pericolosi se combinati con una compromissione parziale.

## Operation

Il flag del kernel dietro questo comportamento è `PR_SET_NO_NEW_PRIVS`. Una volta impostato per un processo, le successive chiamate `execve()` non possono aumentare i privilegi. Il dettaglio importante è che il processo può comunque eseguire binari; semplicemente non può usare quei binari per oltrepassare un confine di privilegi che il kernel altrimenti rispetterebbe.

In ambienti orientati a Kubernetes, `allowPrivilegeEscalation: false` mappa questo comportamento per il processo del container. Nei runtime in stile Docker e Podman, l'equivalente è solitamente abilitato esplicitamente tramite un'opzione di sicurezza.

## Lab

Ispeziona lo stato del processo corrente:
```bash
grep NoNewPrivs /proc/self/status
```
Confrontalo con un container in cui il runtime abilita il flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
On a hardened workload, il risultato dovrebbe mostrare `NoNewPrivs: 1`.

## Impatto sulla sicurezza

Se `no_new_privs` è assente, un foothold all'interno del container può ancora essere elevato tramite helper setuid o binari con file capabilities. Se è presente, quei cambiamenti di privilegi post-exec vengono interrotti. L'effetto è particolarmente rilevante nelle broad base images che includono molte utilities che l'applicazione non ha mai richiesto.

## Misconfigurazioni

Il problema più comune è semplicemente non abilitare il controllo in ambienti dove sarebbe compatibile. In Kubernetes, lasciare `allowPrivilegeEscalation` abilitato è spesso l'errore operativo di default. In Docker e Podman, omettere l'opzione di sicurezza pertinente ha lo stesso effetto. Un altro modo di fallimento ricorrente è presumere che, dato che un container è "not privileged", le transizioni di privilegi in fase di exec siano automaticamente irrilevanti.

## Abuso

Se `no_new_privs` non è impostato, la prima domanda è se l'immagine contiene binari che possono comunque elevare i privilegi:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Risultati interessanti includono:

- `NoNewPrivs: 0`
- setuid helpers come `su`, `mount`, `passwd` o strumenti di amministrazione specifici della distribuzione
- binari con file capabilities che concedono privilegi di rete o del filesystem

### Esempio completo: In-Container Privilege Escalation Through setuid

Questo controllo solitamente previene **in-container privilege escalation** piuttosto che host escape diretto. Se `NoNewPrivs` è `0` e esiste un setuid helper, testalo esplicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se un binario setuid noto è presente e funzionante, prova ad avviarlo in modo da preservare la transizione di privilegi:
```bash
/bin/su -c id 2>/dev/null
```
Questo, di per sé, non evade il container, ma può convertire un low-privilege foothold all'interno del container in container-root, il che spesso diventa il prerequisito per una successiva host escape tramite mounts, runtime sockets o kernel-facing interfaces.

## Controlli

L'obiettivo di questi controlli è stabilire se l'exec-time privilege gain è bloccato e se l'image contiene ancora helper che sarebbero rilevanti qualora non lo fosse.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Cosa è interessante qui:

- `NoNewPrivs: 1` è normalmente il risultato più sicuro.
- `NoNewPrivs: 0` significa che setuid e file-cap based escalation paths rimangono rilevanti.
- Un'immagine minimale con pochi o nessun setuid/file-cap binaries offre a un attacker meno opzioni di post-exploitation anche quando `no_new_privs` manca.

## Valori predefiniti a runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato di default | Abilitato esplicitamente con `--security-opt no-new-privileges=true` | omettendo il flag, `--privileged` |
| Podman | Non abilitato di default | Abilitato esplicitamente con `--security-opt no-new-privileges` o con una configurazione di sicurezza equivalente | omettendo l'opzione, `--privileged` |
| Kubernetes | Controllato dalla policy del workload | `allowPrivilegeEscalation: false` abilita l'effetto; molti workload lo lasciano ancora abilitato | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue le impostazioni del workload di Kubernetes | Generalmente ereditato dal Pod security context | come nella riga Kubernetes |

Questa protezione è spesso assente semplicemente perché nessuno l'ha attivata, non perché il runtime non la supporti.
{{#include ../../../../banners/hacktricks-training.md}}
