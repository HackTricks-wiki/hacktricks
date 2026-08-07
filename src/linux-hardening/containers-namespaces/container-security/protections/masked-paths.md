# Percorsi mascherati

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi mascherati sono protezioni runtime che nascondono al container posizioni del filesystem particolarmente sensibili e a contatto con il kernel, effettuando il bind-mount su di esse o rendendole altrimenti inaccessibili. Lo scopo è impedire a un workload di interagire direttamente con interfacce che le applicazioni ordinarie non necessitano, soprattutto all'interno di procfs.

Questo è importante perché molte container escapes e tecniche con impatto sull'host iniziano leggendo o scrivendo file speciali sotto `/proc` o `/sys`. Se tali posizioni sono mascherate, l'attaccante perde l'accesso diretto a una parte utile della superficie di controllo del kernel anche dopo aver ottenuto code execution all'interno del container.

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
Ispeziona il comportamento effettivo dei mount all'interno del workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impatto sulla sicurezza

Il masking non crea il principale confine di isolamento, ma rimuove diversi target di alto valore per il post-exploitation. Senza masking, un container compromesso potrebbe essere in grado di ispezionare lo stato del kernel, leggere informazioni sensibili sui processi o sulle chiavi, oppure interagire con oggetti procfs/sysfs che non avrebbero mai dovuto essere visibili all'applicazione.

## Misconfigurations

L'errore principale consiste nel rimuovere il masking da classi ampie di path per comodità o debugging. In Podman questo può apparire come `--security-opt unmask=ALL` o come rimozione mirata del masking. In Kubernetes, un'esposizione eccessivamente ampia di proc può apparire tramite `procMount: Unmasked`. Un altro problema grave consiste nell'esporre `/proc` o `/sys` dell'host tramite un bind mount, aggirando completamente l'idea di una vista ridotta del container.

## Abuse

Se il masking è debole o assente, iniziare identificando quali path sensibili di procfs/sysfs sono direttamente raggiungibili:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Se un percorso presumibilmente mascherato è accessibile, esaminalo attentamente:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Cosa possono rivelare questi comandi:

- `/proc/timer_list` può esporre informazioni sui timer e sullo scheduler del host. È principalmente un primitive di reconnaissance, ma conferma che il container può leggere informazioni rivolte al kernel normalmente nascoste.
- `/proc/keys` è molto più sensibile. A seconda della configurazione del host, può rivelare voci del keyring, descrizioni delle chiavi e relazioni tra i servizi del host che usano il sottosistema kernel keyring.
- `/sys/firmware` aiuta a identificare la modalità di boot, le interfacce del firmware e i dettagli della piattaforma utili per il fingerprinting del host e per capire se il workload sta visualizzando uno stato a livello host.
- `/proc/config.gz` può rivelare la configurazione del kernel in esecuzione, utile per confrontarla con i prerequisiti di exploit pubblici del kernel o per capire perché una funzionalità specifica è raggiungibile.
- `/proc/sched_debug` espone lo stato dello scheduler e spesso contraddice l'aspettativa intuitiva secondo cui il PID namespace dovrebbe nascondere completamente le informazioni sui processi non correlati.

I risultati interessanti includono la lettura diretta di quei file, le prove che i dati appartengono al host anziché a una vista limitata del container oppure l'accesso ad altre posizioni procfs/sysfs normalmente mascherate per impostazione predefinita.

## Verifiche

Lo scopo di queste verifiche è determinare quali percorsi il runtime ha nascosto intenzionalmente e se il workload attuale vede ancora un filesystem rivolto al kernel ridotto.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Cosa è interessante qui:

- Un lungo elenco di percorsi mascherati è normale nei runtime hardened.
- L'assenza di mascheramento per voci sensibili di procfs merita un'ispezione più approfondita.
- Se un percorso sensibile è accessibile e il container dispone inoltre di capabilities elevate o di mount estesi, l'esposizione è più significativa.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | Docker definisce un elenco predefinito di percorsi mascherati | esposizione di mount proc/sys dell'host, `--privileged` |
| Podman | Abilitato per impostazione predefinita | Podman applica i percorsi mascherati predefiniti, salvo rimozione manuale del mascheramento | `--security-opt unmask=ALL`, rimozione mirata del mascheramento, `--privileged` |
| Kubernetes | Eredita le impostazioni predefinite del runtime | Usa il comportamento di mascheramento del runtime sottostante, a meno che le impostazioni del Pod non indeboliscano l'esposizione di proc | `procMount: Unmasked`, pattern di workload privilegiati, mount estesi dell'host |
| containerd / CRI-O sotto Kubernetes | Impostazione predefinita del runtime | Di solito applica i percorsi mascherati OCI/runtime, salvo override | modifiche dirette alla configurazione del runtime, stessi percorsi di indebolimento di Kubernetes |

I percorsi mascherati sono solitamente presenti per impostazione predefinita. Il problema operativo principale non è la loro assenza dal runtime, ma la rimozione deliberata del mascheramento o i bind mount dell'host che annullano la protezione.

{{#include ../../../../banners/hacktricks-training.md}}
