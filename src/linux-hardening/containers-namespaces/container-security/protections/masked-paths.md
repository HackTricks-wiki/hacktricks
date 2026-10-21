# Percorsi mascherati

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi mascherati sono protezioni runtime che nascondono al container posizioni del filesystem particolarmente sensibili e accessibili al kernel, montandovi sopra un bind mount o rendendole altrimenti inaccessibili. La specifica OCI Runtime definisce `maskedPaths` come percorsi assoluti che non devono essere leggibili all'interno del container. <sup>[[1]](#references)</sup>

Questo è importante perché molti container escape e trucchi che impattano l'host iniziano leggendo o scrivendo file speciali in `/proc` o `/sys`. Se queste posizioni sono mascherate, l'attaccante perde l'accesso diretto a una parte utile della superficie di controllo del kernel, anche dopo aver ottenuto l'esecuzione di codice all'interno del container.

## Funzionamento

I runtime mascherano comunemente percorsi selezionati, come:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

L'elenco esatto dipende dal runtime e dalla configurazione dell'host. La proprietà importante è che il percorso diventa inaccessibile o viene sostituito dal punto di vista del container, anche se continua a esistere sull'host.

## Laboratorio

Esamina la configurazione dei percorsi mascherati esposta da Docker:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Esamina il comportamento effettivo dei mount all'interno del workload:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Un percorso elencato non è necessariamente leggibile: runc può mascherare un file con un bind mount su `/dev/null` e una directory con un tmpfs vuoto in sola lettura. Controlla il mountpoint esatto, non limitarti a verificare se `ls` ha esito positivo. <sup>[[4]](#references)</sup>

## Security Impact

Il masking non crea il principale confine di isolamento, ma rimuove diversi obiettivi di post-exploitation di alto valore. Senza masking, un container compromesso potrebbe riuscire a ispezionare lo stato del kernel, leggere informazioni sensibili sui processi o sulle chiavi, oppure interagire con oggetti procfs/sysfs che non avrebbero mai dovuto essere visibili all'applicazione.

## Misconfigurations

L'errore principale consiste nel rimuovere il masking da intere classi di percorsi per comodità o per il debugging. In Podman, questo può apparire come `--security-opt unmask=ALL` o come rimozione mirata del masking. <sup>[[2]](#references)</sup> In Kubernetes, un'esposizione eccessivamente ampia di proc può essere configurata con `procMount: Unmasked`; nelle versioni attuali, Kubernetes richiede `spec.hostUsers: false` (un user namespace) per questa impostazione, mentre le versioni dalla 1.12 alla 1.29 non applicavano questo requisito. <sup>[[3]](#references)</sup> Un altro problema grave è esporre `/proc` o `/sys` dell'host tramite un bind mount, aggirando completamente l'idea di una vista ridotta del container.

## Abuse

Se il masking è debole o assente, inizia identificando quali percorsi sensibili di procfs/sysfs sono direttamente raggiungibili:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Se un percorso presumibilmente mascherato è accessibile, esaminalo attentamente:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Cosa possono rivelare questi comandi:

- `/proc/timer_list` può esporre dati del timer e dello scheduler dell'host. È soprattutto uno strumento di ricognizione, ma conferma che il container può leggere informazioni rivolte al kernel che normalmente sono nascoste.
- `/proc/keys` elenca solo i metadati delle chiavi per cui il lettore dispone del permesso **view**, fatte salve le verifiche LSM. Può rivelare i tipi e le descrizioni delle chiavi, ma non ne scarica i payload. <sup>[[6]](#references)</sup>
- `/sys/firmware` aiuta a identificare la modalità di avvio, le interfacce firmware e i dettagli della piattaforma, utili per identificare l'host e capire se il workload vede uno stato a livello host.
- `/proc/config.gz` può rivelare la configurazione del kernel in esecuzione, utile per verificare i prerequisiti di exploit pubblici per il kernel o capire perché una specifica funzionalità è raggiungibile.
- `/proc/sched_debug` espone lo stato dello scheduler e spesso smentisce l'aspettativa intuitiva che il PID namespace nasconda completamente le informazioni sui processi non correlati.

Tra i risultati interessanti ci sono la lettura diretta di questi file, la prova che i dati appartengono all'host anziché a una vista limitata del container, oppure l'accesso ad altre posizioni procfs/sysfs comunemente mascherate per impostazione predefinita.

### Race sulla sorgente del mascheramento durante l'avvio del container

Nelle implementazioni vulnerabili di runc, i mascheramenti dei file dipendono dall'inode di `/dev/null` del container. Un attacker che riesce ad avviare container concorrenti con mount condivisi, anche tramite passaggi BuildKit paralleli, può sfruttare una race durante l'avvio e rimuovere `/dev/null` prima che runc lo monti sui file procfs da mascherare. Il runtime interpreta quindi la sorgente **mancante** come se mancasse una destinazione del mascheramento e salta silenziosamente questi mascheramenti. Il problema dipende da una race durante la configurazione del runtime: rimuovere `/dev/null` dopo l'avvio non annulla un mascheramento già installato. <sup>[[4]](#references)</sup>

Dopo un test controllato, confronta l'elenco dei mascheramenti richiesti con i mountpoint esatti all'interno del nuovo container. <sup>[[4]](#references)</sup> `findmnt -M` controlla il mountpoint indicato, senza ripiegare su un mount padre; se `findmnt` non è disponibile, esamina `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> Un `ls` riuscito o un `cat` vuoto non dimostrano che il mascheramento sia assente. <sup>[[4]](#references)</sup>

Usa i [controlli qui sotto](#checks) per confrontare i mascheramenti richiesti con i mountpoint esatti nel nuovo container.

Un mascheramento dei file saltato può esporre dati procfs se i normali permessi e i criteri LSM lo consentono. **Non** rende di per sé scrivibile `/proc/sys`: è un controllo distinto, relativo ai [percorsi in sola lettura](read-only-paths.md). La distinta sostituzione del symlink `/dev/null`, che può reindirizzare un bind mount verso una destinazione procfs scrivibile, è trattata nella [race del runtime del PID namespace](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Controlli

Lo scopo di questi controlli è determinare quali percorsi il runtime ha nascosto intenzionalmente e se il workload attuale vede ancora un filesystem con accesso al kernel ridotto.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Usa un controllo del mount esatto, perché un file mascherato può comunque esistere e una lettura può restituire un risultato vuoto da `/dev/null`. L'assenza del mountpoint è un'anomalia da verificare, non una prova di per sé che i dati dell'host siano leggibili. <sup>[[4]](#references)[[5]](#references)</sup>

Aspetti interessanti:

- Un lungo elenco di percorsi mascherati è normale nei runtime hardenizzati.
- La mancanza di mascheramento su voci procfs sensibili merita un esame più approfondito.
- Se un percorso sensibile è accessibile e il container dispone anche di capability potenti o mount estesi, l'esposizione è più rilevante.

## Valori predefiniti del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | Docker definisce un elenco predefinito di percorsi mascherati | esposizione dei mount host proc/sys, `--privileged` |
| Podman | Abilitato per impostazione predefinita | Podman applica i percorsi mascherati predefiniti, a meno che non vengano rimossi manualmente dalla mascheratura | `--security-opt unmask=ALL`, rimozione mirata della mascheratura, `--privileged` |
| Kubernetes | Eredita le impostazioni predefinite del runtime | Usa il comportamento di mascheramento del runtime sottostante, a meno che le impostazioni del Pod non riducano la protezione di proc | `procMount: Unmasked` (nelle versioni attuali richiede `hostUsers: false`), pattern di workload privilegiati, mount host estesi |
| containerd / CRI-O sotto Kubernetes | Predefinito del runtime | Di solito applica i percorsi mascherati OCI/runtime, salvo override | modifiche dirette alla configurazione del runtime, stessi percorsi di indebolimento di Kubernetes |

I percorsi mascherati sono solitamente presenti per impostazione predefinita. Il problema operativo principale non è la loro assenza dal runtime, ma la rimozione deliberata della mascheratura o i bind mount dell'host che annullano la protezione.

## References

- [1] [Open Container Initiative - Configurazione dei container Linux: percorsi mascherati](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Documentazione Podman - opzioni di sicurezza di `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Documentazione Kubernetes - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [Avviso runc: race nella sorgente del mount dei percorsi mascherati](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Manuale di findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Manuale di keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
