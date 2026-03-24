# Percorsi mascherati

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi mascherati sono protezioni a runtime che nascondono posizioni di filesystem particolarmente sensibili rivolte al kernel dal container, tramite bind-mounting sopra di esse o rendendole altrimenti inaccessibili. Lo scopo è impedire a un workload di interagire direttamente con interfacce che le normali applicazioni non necessitano, specialmente dentro procfs.

Questo è importante perché molte container escapes e trucchi che impattano l'host iniziano leggendo o scrivendo file speciali sotto `/proc` o `/sys`. Se quelle posizioni sono mascherate, l'attaccante perde l'accesso diretto a una parte utile della superficie di controllo del kernel anche dopo aver ottenuto l'esecuzione di codice all'interno del container.

## Funzionamento

I runtime comunemente mascherano percorsi selezionati come:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La lista esatta dipende dal runtime e dalla configurazione dell'host. La proprietà importante è che il percorso diventi inaccessibile o venga sostituito dal punto di vista del container anche se esiste ancora sull'host.

## Lab

Ispeziona la configurazione masked-path esposta da Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Ispeziona il comportamento effettivo dei mount all'interno del workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impatto sulla sicurezza

Il masking non crea il principale confine di isolamento, ma rimuove diversi target di post-exploitation ad alto valore. Senza masking, un container compromesso potrebbe essere in grado di ispezionare lo stato del kernel, leggere informazioni sensibili sui processi o sulle chiavi, o interagire con oggetti procfs/sysfs che non avrebbero mai dovuto essere visibili all'applicazione.

## Misconfigurazioni

Il principale errore è l'unmasking di ampie classi di percorsi per comodità o debugging. In Podman questo può presentarsi come `--security-opt unmask=ALL` o come un unmasking mirato. In Kubernetes, un'esposizione troppo ampia di proc può manifestarsi tramite `procMount: Unmasked`. Un altro problema serio è esporre l'host `/proc` o `/sys` tramite un bind mount, che aggira completamente l'idea di una vista ridotta del container.

## Abuso

Se il masking è debole o assente, inizia identificando quali percorsi sensibili procfs/sysfs sono direttamente raggiungibili:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Se un percorso apparentemente mascherato è accessibile, ispezionalo attentamente:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` can expose host timer and scheduler data. This is mostly a reconnaissance primitive, but it confirms that the container can read kernel-facing information that is normally hidden.
- `/proc/keys` is much more sensitive. Depending on the host configuration, it may reveal keyring entries, key descriptions, and relationships between host services using the kernel keyring subsystem.
- `/sys/firmware` helps identify boot mode, firmware interfaces, and platform details that are useful for host fingerprinting and for understanding whether the workload is seeing host-level state.
- `/proc/config.gz` may reveal the running kernel configuration, which is valuable for matching public kernel exploit prerequisites or understanding why a specific feature is reachable.
- `/proc/sched_debug` exposes scheduler state and often bypasses the intuitive expectation that the PID namespace should hide unrelated process information completely.

Interesting results include direct reads from those files, evidence that the data belongs to the host rather than to a constrained container view, or access to other procfs/sysfs locations that are commonly masked by default.

## Controlli

Lo scopo di questi controlli è determinare quali percorsi il runtime ha intenzionalmente nascosto e se l'attuale workload vede ancora un filesystem rivolto al kernel ridotto.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Cosa c'è di interessante qui:

- Una lunga lista di percorsi mascherati è normale nei runtime rinforzati.
- La mancanza di mascheramento su voci sensibili di procfs merita un'ispezione più approfondita.
- Se un percorso sensibile è accessibile e il container ha anche capabilities elevate o mount ampi, l'esposizione è più rilevante.

## Impostazioni predefinite del runtime

| Runtime / platform | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | Docker definisce una lista predefinita di percorsi mascherati | esposizione dei mount host proc/sys, `--privileged` |
| Podman | Abilitato per impostazione predefinita | Podman applica percorsi mascherati predefiniti a meno che non vengano rimossi manualmente dal mascheramento | `--security-opt unmask=ALL`, rimozione mirata del mascheramento, `--privileged` |
| Kubernetes | Eredita le impostazioni predefinite del runtime | Usa il comportamento di masking del runtime sottostante a meno che le impostazioni del Pod indeboliscano l'esposizione di proc | `procMount: Unmasked`, pattern di workload privilegiati, ampi mount host |
| containerd / CRI-O under Kubernetes | Predefinito del runtime | Solitamente applica i percorsi mascherati OCI/runtime a meno che non venga sovrascritto | modifiche dirette alla config del runtime, stessi percorsi di indebolimento di Kubernetes |

I percorsi mascherati sono solitamente presenti per impostazione predefinita. Il problema operativo principale non è l'assenza nel runtime, ma la rimozione deliberata del mascheramento o i bind mount host che annullano la protezione.
{{#include ../../../../banners/hacktricks-training.md}}
