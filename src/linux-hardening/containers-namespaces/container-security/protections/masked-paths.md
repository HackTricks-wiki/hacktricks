# Percorsi mascherati

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi mascherati sono protezioni runtime che nascondono al container posizioni del filesystem particolarmente sensibili e rivolte al kernel, montandovi sopra dei bind-mount oppure rendendole in altro modo inaccessibili. Lo scopo è impedire a un workload di interagire direttamente con interfacce di cui le applicazioni ordinarie non hanno bisogno, soprattutto all'interno di procfs.

Questo è importante perché molti container escapes e trucchi con impatto sull'host iniziano leggendo o scrivendo file speciali sotto `/proc` o `/sys`. Se queste posizioni sono mascherate, l'attacker perde l'accesso diretto a una parte utile della superficie di controllo del kernel anche dopo aver ottenuto la code execution all'interno del container.

## Funzionamento

I runtime mascherano comunemente percorsi selezionati come:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

L'elenco esatto dipende dal runtime e dalla configurazione dell'host. La proprietà importante è che il percorso diventa inaccessibile o viene sostituito dal punto di vista del container, anche se continua a esistere sull'host.

## Lab

Esamina la configurazione dei percorsi mascherati esposta da Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Esamina il comportamento effettivo dei mount all'interno del workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impatto sulla sicurezza

Il masking non crea il principale confine di isolamento, ma rimuove diversi target di post-exploitation di alto valore. Senza masking, un container compromesso potrebbe essere in grado di esaminare lo stato del kernel, leggere informazioni sensibili sui processi o sulle chiavi, oppure interagire con oggetti procfs/sysfs che non dovrebbero mai essere visibili all'applicazione.

## Misconfigurations

L'errore principale consiste nel rimuovere il masking da classi estese di path per comodità o debugging. In Podman questo può apparire come `--security-opt unmask=ALL` o come rimozione mirata del masking. In Kubernetes, un'esposizione eccessivamente ampia di proc può apparire tramite `procMount: Unmasked`. Un altro problema grave consiste nell'esporre l'host `/proc` o `/sys` tramite un bind mount, aggirando completamente l'idea di una vista ridotta del container.

## Abuse

Se il masking è debole o assente, inizia identificando quali path procfs/sysfs sensibili sono direttamente raggiungibili:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Se un percorso che dovrebbe essere mascherato è accessibile, esaminalo attentamente:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Cosa possono rivelare questi comandi:

- `/proc/timer_list` può esporre dati relativi ai timer e allo scheduler dell'host. Si tratta principalmente di una primitive di reconnaissance, ma conferma che il container può leggere informazioni rivolte al kernel che normalmente sono nascoste.
- `/proc/keys` è molto più sensibile. A seconda della configurazione dell'host, può rivelare voci del keyring, descrizioni delle chiavi e relazioni tra i servizi dell'host che utilizzano il sottosistema keyring del kernel.
- `/sys/firmware` aiuta a identificare la modalità di avvio, le interfacce del firmware e i dettagli della piattaforma utili per il fingerprinting dell'host e per comprendere se il workload sta visualizzando lo stato a livello di host.
- `/proc/config.gz` può rivelare la configurazione del kernel in esecuzione, utile per verificare i prerequisiti di exploit pubblici del kernel o per comprendere perché una funzionalità specifica sia raggiungibile.
- `/proc/sched_debug` espone lo stato dello scheduler e spesso contraddice l'aspettativa intuitiva secondo cui il PID namespace dovrebbe nascondere completamente le informazioni relative ai processi non correlati.

I risultati interessanti includono letture dirette da quei file, prove che i dati appartengono all'host anziché a una vista limitata del container, oppure l'accesso ad altre posizioni procfs/sysfs che normalmente sono mascherate per impostazione predefinita.

## Checks

Lo scopo di questi checks è determinare quali path il runtime ha nascosto intenzionalmente e verificare se il workload corrente vede ancora un filesystem rivolto al kernel ridotto.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Cosa è interessante in questo caso:

- Un lungo elenco di masked path è normale nei runtime hardened.
- L'assenza di masking su voci sensibili di procfs merita un'ispezione più approfondita.
- Se un path sensibile è accessibile e il container dispone anche di capabilities elevate o mount estesi, l'esposizione è più rilevante.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | Docker definisce un elenco predefinito di masked path | esposizione di mount proc/sys dell'host, `--privileged` |
| Podman | Abilitato per impostazione predefinita | Podman applica i masked path predefiniti, salvo rimozione manuale del masking | `--security-opt unmask=ALL`, rimozione mirata del masking, `--privileged` |
| Kubernetes | Eredita le impostazioni predefinite del runtime | Utilizza il comportamento di masking del runtime sottostante, salvo che le impostazioni del Pod riducano la protezione di proc | `procMount: Unmasked`, pattern di workload privilegiati, mount estesi dell'host |
| containerd / CRI-O under Kubernetes | Impostazione predefinita del runtime | Di solito applica i masked path OCI/runtime, salvo override | modifiche dirette alla configurazione del runtime, stessi percorsi di indebolimento di Kubernetes |

I masked path sono generalmente presenti per impostazione predefinita. Il problema operativo principale non è la loro assenza dal runtime, ma la rimozione deliberata del masking o i bind mount dell'host che annullano la protezione.
{{#include ../../../../banners/hacktricks-training.md}}
