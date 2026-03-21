# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` è una funzionalità di hardening del kernel che impedisce a un processo di acquisire privilegi aggiuntivi tramite `execve()`. In termini pratici, una volta impostato il flag, l'esecuzione di un setuid binary, un setgid binary, o di un file con Linux file capabilities non concede privilegi oltre a quelli che il processo possedeva già. Negli ambienti containerizzati questo è importante perché molte catene di privilege-escalation si basano sulla presenza, nell'image, di un eseguibile che cambia privilegio quando lanciato.

Dal punto di vista difensivo, `no_new_privs` non è un sostituto per namespaces, seccomp, o capability dropping. È uno strato di rinforzo. Blocca una specifica classe di escalation successiva dopo che l'esecuzione di codice è già stata ottenuta. Questo lo rende particolarmente prezioso in ambienti dove le immagini contengono helper binaries, artefatti del package-manager, o tool legacy che altrimenti sarebbero pericolosi se combinati con una compromissione parziale.

## Operation

Il flag del kernel dietro questo comportamento è `PR_SET_NO_NEW_PRIVS`. Una volta impostato per un processo, le successive chiamate `execve()` non possono aumentare i privilegi. Il dettaglio importante è che il processo può comunque eseguire binaries; semplicemente non può usare quegli binaries per superare un confine di privilegi che il kernel altrimenti rispetterebbe.

Negli ambienti orientati a Kubernetes, `allowPrivilegeEscalation: false` mappa questo comportamento per il processo del container. Nei runtime in stile Docker e Podman, l'equivalente è solitamente abilitato esplicitamente tramite un'opzione di sicurezza.

## Lab

Ispeziona lo stato del processo corrente:
```bash
grep NoNewPrivs /proc/self/status
```
Confrontalo con un container in cui il runtime abilita la flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Su un carico di lavoro rafforzato, il risultato dovrebbe mostrare `NoNewPrivs: 1`.

## Impatto sulla sicurezza

Se `no_new_privs` è assente, una presenza all'interno del container può comunque essere elevata tramite setuid helpers o binari con file capabilities. Se è presente, quei cambi di privilegio post-exec vengono interrotti. L'effetto è particolarmente rilevante nelle immagini base ampie che includono molte utility di cui l'applicazione non aveva mai bisogno.

## Misconfigurazioni

Il problema più comune è semplicemente non abilitare il controllo in ambienti dove sarebbe compatibile. In Kubernetes, lasciare `allowPrivilegeEscalation` abilitato è spesso l'errore operativo predefinito. In Docker e Podman, omettere l'opzione di sicurezza pertinente ha lo stesso effetto. Un altro modo ricorrente di fallimento è assumere che poiché un container è "not privileged", le transizioni di privilegio a runtime (exec-time) siano automaticamente irrilevanti.

## Abuso

Se `no_new_privs` non è impostato, la prima domanda è se l'immagine contiene binari che possono comunque aumentare i privilegi:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Risultati interessanti includono:

- `NoNewPrivs: 0`
- helper setuid come `su`, `mount`, `passwd` o strumenti amministrativi specifici della distribuzione
- binari con file capabilities che concedono privilegi di rete o sul filesystem

In una valutazione reale, questi ritrovamenti non dimostrano da soli un'escalation funzionante, ma identificano esattamente i binari che vale la pena testare successivamente.

### Esempio completo: In-Container Privilege Escalation Through setuid

Questo controllo solitamente previene **in-container privilege escalation** piuttosto che host escape direttamente. Se `NoNewPrivs` è `0` e esiste un setuid helper, testalo esplicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se è presente e funzionante un noto setuid binary, prova ad avviarlo in modo da preservare la transizione dei privilegi:
```bash
/bin/su -c id 2>/dev/null
```
Questo, di per sé, non effettua l'escape del container, ma può trasformare un foothold a basso privilegio all'interno del container in container-root, che spesso diventa il prerequisito per un successivo host escape tramite mounts, runtime sockets o kernel-facing interfaces.

## Controlli

L'obiettivo di questi controlli è stabilire se l'exec-time privilege gain è bloccato e se l'image contiene ancora helper che sarebbero rilevanti in caso contrario.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Cosa è interessante qui:

- `NoNewPrivs: 1` è di solito il risultato più sicuro.
- `NoNewPrivs: 0` significa che i percorsi di escalation basati su setuid e file-cap rimangono rilevanti.
- Un'immagine minimale con pochi o nessun binario setuid/file-cap offre a un attaccante meno opzioni di post-exploitation anche quando `no_new_privs` manca.

## Impostazioni predefinite di runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato per impostazione predefinita | Abilitato esplicitamente con `--security-opt no-new-privileges=true` | omettendo il flag, `--privileged` |
| Podman | Non abilitato per impostazione predefinita | Abilitato esplicitamente con `--security-opt no-new-privileges` o configurazione di sicurezza equivalente | omettendo l'opzione, `--privileged` |
| Kubernetes | Controllato dalla policy del workload | `allowPrivilegeEscalation: false` abilita l'effetto; molti workload lo lasciano comunque abilitato | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue le impostazioni del workload di Kubernetes | Solitamente ereditato dal Pod security context | stesso della riga Kubernetes |

Questa protezione è spesso assente semplicemente perché nessuno l'ha attivata, non perché il runtime non la supporti.
