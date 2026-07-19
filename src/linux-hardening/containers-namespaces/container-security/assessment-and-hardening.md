# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Una buona assessment di un container dovrebbe rispondere a due domande parallele. Primo, cosa può fare un attacker dal workload attuale? Secondo, quali scelte dell'operatore lo hanno reso possibile? Gli strumenti di enumeration aiutano con la prima domanda, mentre le indicazioni di hardening aiutano con la seconda. Mantenere entrambi gli aspetti nella stessa pagina rende questa sezione più utile come riferimento pratico sul campo, invece che come semplice catalogo di tecniche di escape.

Un aggiornamento pratico per gli ambienti moderni è che molti writeup più vecchi sui container presumono implicitamente un **rootful runtime**, nessun isolamento tramite user namespace e spesso **cgroup v1**. Queste assunzioni non sono più sicure. Prima di dedicare tempo alle vecchie primitive di escape, verifica innanzitutto se il workload è rootless o userns-remapped, se l'host utilizza cgroup v2 e se Kubernetes o il runtime stanno applicando profili predefiniti di seccomp e AppArmor. Questi dettagli spesso determinano se un breakout noto è ancora applicabile.

## Strumenti di Enumeration

Diversi strumenti restano utili per caratterizzare rapidamente un ambiente container:

- `linpeas` può identificare molti indicatori relativi ai container, socket montati, capability set, filesystem pericolosi e indizi di breakout.
- `CDK` è specificamente orientato agli ambienti container e include enumeration oltre ad alcuni controlli automatizzati per l'escape.
- `amicontained` è leggero e utile per identificare restrizioni dei container, capability, esposizione dei namespace e probabili classi di breakout.
- `deepce` è un altro enumerator focalizzato sui container, con controlli orientati al breakout.
- `grype` è utile quando l'assessment include la verifica delle vulnerabilità dei package nelle immagini, invece della sola analisi dell'escape a runtime.
- `Tracee` è utile quando servono **runtime evidence** e non soltanto una postura statica, soprattutto per l'esecuzione di processi sospetti, l'accesso ai file e la raccolta di eventi consapevole dei container.
- `Inspektor Gadget` è utile nelle analisi di Kubernetes e degli host Linux quando serve visibilità basata su eBPF associata a pod, container, namespace e altri concetti di livello superiore.

Il valore di questi strumenti consiste nella velocità e nella copertura, non nella certezza. Aiutano a rivelare rapidamente la postura generale, ma i risultati interessanti richiedono comunque un'interpretazione manuale basata sul runtime effettivo e sul modello di namespace, capability e mount.

## Priorità di Hardening

I principi più importanti di hardening sono concettualmente semplici, anche se la loro implementazione varia in base alla piattaforma. Evita i container privilegiati. Evita i runtime socket montati. Non fornire ai container path dell'host scrivibili, salvo una ragione molto specifica. Utilizza user namespace o un'esecuzione rootless quando possibile. Rimuovi tutte le capability e aggiungi nuovamente solo quelle realmente necessarie al workload. Mantieni seccomp, AppArmor e SELinux abilitati invece di disabilitarli per risolvere problemi di compatibilità delle applicazioni. Limita le risorse affinché un container compromesso non possa causare facilmente un denial of service all'host.

L'igiene delle immagini e delle build è importante quanto la postura a runtime. Utilizza immagini minimali, ricostruiscile frequentemente, esegui scansioni, richiedi la provenance quando possibile e mantieni i secret fuori dai layer. Un container eseguito come non-root, con un'immagine piccola e una superficie ridotta di syscall e capability, è molto più semplice da difendere rispetto a un'immagine di grandi dimensioni pensata per comodità, eseguita con privilegi root equivalenti a quelli dell'host e con strumenti di debugging preinstallati.

Per Kubernetes, gli attuali baseline di hardening sono più prescrittivi di quanto molti operatori presumano ancora. I **Pod Security Standards** integrati considerano `restricted` il profilo di "current best practice": `allowPrivilegeEscalation` dovrebbe essere `false`, i workload dovrebbero essere eseguiti come non-root, seccomp dovrebbe essere impostato esplicitamente su `RuntimeDefault` o `Localhost` e i capability set dovrebbero essere rimossi in modo aggressivo. Durante l'assessment, questo è importante perché un cluster che utilizza solo label `warn` o `audit` può sembrare hardenizzato sulla carta, pur continuando ad ammettere pod rischiosi nella pratica.

## Domande di Triage Moderne

Prima di consultare le pagine specifiche sull'escape, rispondi a queste domande rapide:

1. Il workload è **rootful**, **rootless** o **userns-remapped**?
2. Il nodo utilizza **cgroup v1** o **cgroup v2**?
3. **seccomp** e **AppArmor/SELinux** sono configurati esplicitamente o vengono soltanto ereditati quando disponibili?
4. In Kubernetes, il namespace sta effettivamente **enforcing** `baseline` o `restricted`, oppure si limita a generare warning/eseguire audit?

Controlli utili:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
Cosa è interessante qui:

- Se `/proc/self/uid_map` mostra il root del container mappato su un **intervallo di UID host elevati**, molti vecchi writeup sul write del root dell'host diventano meno rilevanti, perché il root nel container non equivale più al root dell'host.
- Se `/sys/fs/cgroup` è `cgroup2fs`, i vecchi writeup specifici di **cgroup v1**, come l'abuso di `release_agent`, non dovrebbero più essere la prima ipotesi.
- Se seccomp e AppArmor vengono ereditati solo implicitamente, la portabilità può essere più debole di quanto i defender si aspettino. In Kubernetes, impostare esplicitamente `RuntimeDefault` è spesso più sicuro che affidarsi silenziosamente ai default del nodo.
- Se `supplementalGroupsPolicy` è impostato su `Strict`, il pod dovrebbe evitare di ereditare silenziosamente ulteriori appartenenze a gruppi da `/etc/group` all'interno dell'immagine, rendendo più prevedibile il comportamento dell'accesso ai volumi e ai file basato sui gruppi.
- Vale la pena controllare direttamente le label dei namespace, come `pod-security.kubernetes.io/enforce=restricted`. `warn` e `audit` sono utili, ma non impediscono la creazione di un pod rischioso.

## Triage della baseline del runtime

Una baseline del runtime è il controllo rapido che permette di capire se un container appare come un normale workload isolato oppure come un punto d'appoggio nel control plane con impatto sull'host. Dovrebbe raccogliere informazioni sufficienti per stabilire quale sia la prossima pagina da consultare: abuso del runtime socket, mount dell'host, namespace, cgroup, capabilities oppure revisione dei secret dell'immagine.

Controlli utili dall'interno di un workload:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Interpretazione:

- Un `memory.max` / `pids.max` mancante o senza limiti indica controlli deboli sul raggio d'impatto anche senza un escape completo.
- Una root shell con `NoNewPrivs: 0`, capability estese e seccomp permissivo è molto più interessante di un workload ristretto non-root.
- I socket del runtime e i mount dell'host scrivibili hanno solitamente la precedenza sui kernel exploit, perché espongono già un percorso di controllo della gestione o del filesystem.
- I namespace PID, network, IPC o cgroup condivisi non costituiscono sempre da soli degli escape completi, ma facilitano l'individuazione del passaggio successivo.

## Esempi di esaurimento delle risorse

I controlli sulle risorse non sono glamour, ma fanno parte della container security perché limitano il raggio d'impatto di una compromissione. Senza limiti per memoria, CPU o PID, una semplice shell può bastare per degradare l'host o i workload adiacenti.

Esempi di test con impatto sull'host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Questi esempi sono utili perché mostrano che non tutti gli esiti pericolosi dei container sono un vero e proprio "escape". Limiti cgroup deboli possono comunque trasformare l'esecuzione di codice in un impatto operativo reale.

Negli ambienti basati su Kubernetes, verifica anche se i controlli sulle risorse esistono affatto prima di considerare il DoS teorico:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Strumenti di hardening

Per gli ambienti incentrati su Docker, `docker-bench-security` rimane una baseline utile per l'audit lato host, perché verifica i problemi di configurazione comuni rispetto a linee guida di benchmark ampiamente riconosciute:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Lo strumento non sostituisce il threat modeling, ma rimane utile per individuare configurazioni predefinite negligenti relative a daemon, mount, rete e runtime che si accumulano nel tempo.

Per Kubernetes e gli ambienti fortemente basati sul runtime, affianca i controlli statici alla visibilità runtime:

- `Tracee` è utile per il rilevamento runtime consapevole dei container e per una rapida analisi forense quando devi confermare cosa ha effettivamente toccato un workload compromesso.
- `Inspektor Gadget` è utile quando la valutazione richiede telemetria a livello kernel associata a pod, container, attività DNS, esecuzione di file o comportamento di rete.

## Controlli

Usa questi comandi come verifica preliminare durante la valutazione:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Cosa è interessante qui:

- Un processo root con capabilities estese e `Seccomp: 0` merita immediata attenzione.
- Un processo root che dispone anche di una **mappatura UID 1:1** è molto più interessante di "root" all'interno di uno user namespace correttamente isolato.
- `cgroup2fs` di solito indica che molte delle vecchie **catene di escape cgroup v1** non sono il miglior punto di partenza, mentre l'assenza di `memory.max` o `pids.max` indica comunque controlli deboli sul blast radius.
- Mount sospetti e runtime socket spesso offrono un percorso più rapido verso l'impatto rispetto a qualsiasi kernel exploit.
- La combinazione di una postura runtime debole e di limiti di risorse deboli indica generalmente un ambiente container permissivo, piuttosto che una singola configurazione errata.

## Riferimenti

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
