# Percorsi mascherati

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi mascherati sono protezioni a runtime che nascondono posizioni del filesystem particolarmente sensibili rivolte al kernel dal container, sovrascrivendole con bind-mount o rendendole altrimenti inaccessibili. Lo scopo è impedire a un workload di interagire direttamente con interfacce che le normali applicazioni non necessitano, specialmente all'interno di procfs.

Questo è importante perché molte container escapes e trucchi che impattano l'host iniziano leggendo o scrivendo file speciali sotto `/proc` o `/sys`. Se quelle posizioni sono mascherate, l'attaccante perde l'accesso diretto a una parte utile della superficie di controllo del kernel anche dopo aver ottenuto l'esecuzione di codice all'interno del container.

## Funzionamento

I runtime di solito mascherano percorsi selezionati come:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La lista esatta dipende dal runtime e dalla configurazione dell'host. La proprietà importante è che il percorso diventi inaccessibile o venga sostituito dal punto di vista del container anche se esiste ancora sull'host.

## Laboratorio

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

Masking non crea il principale confine di isolamento, ma rimuove diversi obiettivi di post-exploitation ad alto valore. Senza masking, un container compromesso può essere in grado di ispezionare lo stato del kernel, leggere informazioni sensibili di processo o di keying, o interagire con oggetti procfs/sysfs che non avrebbero mai dovuto essere visibili all'applicazione.

## Configurazioni errate

L'errore principale è l'unmasking di ampie classi di percorsi per comodità o debugging. In Podman questo può apparire come `--security-opt unmask=ALL` o un unmasking mirato. In Kubernetes, un'eccessiva esposizione di proc può manifestarsi tramite `procMount: Unmasked`. Un altro problema serio è esporre l'host `/proc` o `/sys` tramite un bind mount, che aggira completamente l'idea di una vista ridotta del container.

## Abuso

Se il masking è debole o assente, inizia identificando quali percorsi sensibili procfs/sysfs sono direttamente raggiungibili:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Se un percorso presumibilmente mascherato è accessibile, ispezionalo attentamente:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` può esporre dati del timer e dello scheduler dell'host. Questo è per lo più una primitiva di ricognizione, ma conferma che il container può leggere informazioni rivolte al kernel che normalmente sono nascoste.
- `/proc/keys` è molto più sensibile. A seconda della configurazione dell'host, può rivelare voci del keyring, descrizioni delle key e relazioni tra servizi dell'host che utilizzano il kernel keyring subsystem.
- `/sys/firmware` aiuta a identificare il boot mode, le interfacce firmware e i dettagli della piattaforma utili per l'host fingerprinting e per capire se il workload sta vedendo lo stato a livello host.
- `/proc/config.gz` può rivelare la configurazione del kernel in esecuzione, utile per abbinare i prerequisiti di public kernel exploit o per comprendere perché una specifica feature è raggiungibile.
- `/proc/sched_debug` espone lo stato dello scheduler e spesso bypassa l'aspettativa intuitiva che il PID namespace debba nascondere completamente le informazioni sui processi non correlati.

Risultati interessanti includono letture dirette di quei file, evidenze che i dati appartengono all'host piuttosto che a una vista container vincolata, o accesso ad altre posizioni procfs/sysfs comunemente mascherate per impostazione predefinita.

## Checks

Lo scopo di questi controlli è determinare quali percorsi il runtime ha intenzionalmente nascosto e se il workload corrente vede ancora un filesystem rivolto al kernel ridotto.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Cosa è interessante qui:

- Un lungo elenco di percorsi mascherati è normale nei runtime hardened.
- La mancanza di mascheratura su voci sensibili di procfs merita un'ispezione più approfondita.
- Se un percorso sensibile è accessibile e il container ha anche capabilities potenti o mount estesi, l'esposizione è più significativa.

## Impostazioni predefinite del runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | Docker definisce una lista predefinita di percorsi mascherati | esporre mount proc/sys dell'host, `--privileged` |
| Podman | Abilitato per impostazione predefinita | Podman applica percorsi mascherati predefiniti a meno che non vengano smascherati manualmente | `--security-opt unmask=ALL`, smascheramento mirato, `--privileged` |
| Kubernetes | Eredita i valori predefiniti del runtime | Usa il comportamento di mascheramento del runtime sottostante a meno che le impostazioni del Pod non indeboliscano l'esposizione di /proc | `procMount: Unmasked`, schemi di workload privilegiati, ampi mount dell'host |
| containerd / CRI-O under Kubernetes | Predefinito del runtime | Solitamente applica i percorsi mascherati OCI/runtime a meno che non venga sovrascritto | modifiche dirette alla configurazione del runtime, stessi percorsi di indebolimento di Kubernetes |

I percorsi mascherati sono solitamente presenti per impostazione predefinita. Il problema operativo principale non è l'assenza nel runtime, ma lo smascheramento deliberato o i bind mount dell'host che annullano la protezione.
{{#include ../../../../banners/hacktricks-training.md}}
