# Valutazione e Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Una buona valutazione di un container dovrebbe rispondere a due domande parallele. Primo, cosa può fare un attacker dal workload attuale? Secondo, quali scelte dell'operatore lo hanno reso possibile? Gli strumenti di enumeration aiutano con la prima domanda, mentre le indicazioni di hardening aiutano con la seconda. Tenere entrambi gli aspetti nella stessa pagina rende la sezione più utile come riferimento operativo, anziché come semplice catalogo di tecniche di escape.

Un aggiornamento pratico per gli ambienti moderni è che molti vecchi writeup sui container presumono implicitamente un **rootful runtime**, nessun isolamento tramite user namespace e spesso **cgroup v1**. Queste ipotesi non sono più sicure. Prima di dedicare tempo alle vecchie primitive di escape, verifica innanzitutto se il workload è rootless o userns-remapped, se l'host utilizza cgroup v2 e se Kubernetes o il runtime stanno applicando i profili predefiniti di seccomp e AppArmor. Questi dettagli spesso determinano se un famoso breakout è ancora applicabile.

## Strumenti di Enumeration

Diversi strumenti rimangono utili per caratterizzare rapidamente un ambiente container:

- `linpeas` è in grado di identificare molti indicatori relativi ai container, socket montati, set di capability, filesystem pericolosi e indizi di breakout.
- `CDK` è focalizzato specificamente sugli ambienti container e include enumeration oltre ad alcuni controlli automatizzati di escape.
- `amicontained` è leggero e utile per identificare restrizioni dei container, capability, esposizione dei namespace e probabili classi di breakout.
- `deepce` è un altro enumerator focalizzato sui container, con controlli orientati al breakout.
- `grype` è utile quando la valutazione include la revisione delle vulnerabilità dei package presenti nelle immagini, invece di limitarsi all'analisi degli escape a runtime.
- `Tracee` è utile quando servono **evidenze a runtime** anziché soltanto una valutazione statica della postura di sicurezza, soprattutto per l'esecuzione di processi sospetti, l'accesso ai file e la raccolta di eventi con consapevolezza dei container.
- `Inspektor Gadget` è utile nelle analisi di Kubernetes e degli host Linux quando serve visibilità basata su eBPF, collegata a pod, container, namespace e altri concetti di livello superiore.

Il valore di questi strumenti consiste nella velocità e nella copertura, non nella certezza. Aiutano a individuare rapidamente la postura generale, ma i risultati interessanti richiedono comunque un'interpretazione manuale in base al runtime effettivo, ai namespace, alle capability e al modello dei mount.

## Priorità di Hardening

I principi di hardening più importanti sono concettualmente semplici, anche se la loro implementazione varia in base alla piattaforma. Evita i container privilegiati. Evita di montare socket del runtime. Non assegnare ai container percorsi dell'host scrivibili, salvo una ragione molto specifica. Usa user namespace o un'esecuzione rootless quando possibile. Rimuovi tutte le capability e aggiungi soltanto quelle realmente necessarie al workload. Mantieni abilitati seccomp, AppArmor e SELinux invece di disabilitarli per risolvere problemi di compatibilità dell'applicazione. Limita le risorse, in modo che un container compromesso non possa causare facilmente un denial of service all'host.

L'igiene delle immagini e delle build è importante quanto la postura a runtime. Usa immagini minimali, ricostruiscile frequentemente, sottoponile a scansione, richiedi la provenienza quando possibile e mantieni i secrets fuori dai layer. Un container eseguito come non-root, con un'immagine ridotta e una superficie limitata di syscall e capability, è molto più facile da difendere rispetto a una grande immagine di comodo eseguita con privilegi root equivalenti a quelli dell'host e con strumenti di debugging preinstallati.

Per Kubernetes, gli attuali baseline di hardening sono più prescrittivi di quanto molti operatori presumano ancora. I **Pod Security Standards** integrati considerano `restricted` il profilo di "best practice attuale": `allowPrivilegeEscalation` dovrebbe essere `false`, i workload dovrebbero essere eseguiti come non-root, seccomp dovrebbe essere impostato esplicitamente su `RuntimeDefault` o `Localhost` e i set di capability dovrebbero essere ridotti in modo aggressivo. Durante la valutazione, questo è importante perché un cluster che utilizza soltanto label `warn` o `audit` può sembrare hardenizzato sulla carta, pur continuando ad ammettere pod rischiosi nella pratica.<sup>[[1]](#references)</sup>

## Domande di Triage Moderne

Prima di consultare le pagine specifiche sugli escape, rispondi a queste domande rapide:

1. Il workload è **rootful**, **rootless** o **userns-remapped**?
2. Il node utilizza **cgroup v1** o **cgroup v2**?
3. **seccomp** e **AppArmor/SELinux** sono configurati esplicitamente o vengono soltanto ereditati quando disponibili?
4. In Kubernetes, il namespace sta effettivamente applicando `baseline` o `restricted`, oppure si limita ad avvisare o registrare gli eventi?

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
Cosa c'è di interessante qui:

- Se `/proc/self/uid_map` mostra il root del container mappato su un **intervallo di UID host elevati**, molti vecchi writeup sul write access da host-root diventano meno rilevanti, perché il root nel container non è più equivalente al root dell'host.
- Se `/sys/fs/cgroup` è `cgroup2fs`, i vecchi writeup specifici di **cgroup v1**, come l'abuso di `release_agent`, non dovrebbero più essere la vostra prima ipotesi.
- Se seccomp e AppArmor sono ereditati solo implicitamente, la portabilità può essere più debole di quanto i defender si aspettino. In Kubernetes, impostare esplicitamente `RuntimeDefault` è spesso più efficace che affidarsi silenziosamente ai default del nodo.
- Se `supplementalGroupsPolicy` è impostato su `Strict`, il pod dovrebbe evitare di ereditare silenziosamente membership aggiuntive dei gruppi da `/etc/group` all'interno dell'immagine, rendendo più prevedibile il comportamento dell'accesso ai volumi e ai file basato sui gruppi.
- Vale la pena controllare direttamente label del namespace come `pod-security.kubernetes.io/enforce=restricted`. `warn` e `audit` sono utili, ma non impediscono la creazione di un pod rischioso.

## Triage della Baseline del Runtime

Una baseline del runtime è il controllo rapido che indica se un container appare come un normale workload isolato o come un foothold nel control plane con impatto sull'host. Dovrebbe raccogliere informazioni sufficienti per stabilire quale sia la prossima pagina da consultare: abuso del runtime socket, mount dell'host, namespace, cgroup, capabilities o revisione dei secret dell'immagine.

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

- Un `memory.max` / `pids.max` mancante o illimitato indica controlli deboli del blast radius anche senza un escape completo.
- Una root shell con `NoNewPrivs: 0`, capabilities ampie e seccomp permissivo è molto più interessante di un workload ristretto non-root.
- I runtime socket e i mount dell'host scrivibili hanno generalmente la precedenza sui kernel exploit, perché espongono già un percorso di controllo della gestione o del filesystem.
- I namespace PID, network, IPC o cgroup condivisi non costituiscono sempre degli escape completi di per sé, ma rendono più semplice trovare il passaggio successivo.

## Esempi di resource-exhaustion

I controlli delle risorse non sono glamour, ma fanno parte della container security perché limitano il blast radius di una compromissione. Senza limiti di memoria, CPU o PID, una semplice shell può essere sufficiente per degradare l'host o i workload adiacenti.

Esempi di test con impatto sull'host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Questi esempi sono utili perché mostrano che non ogni risultato pericoloso di un container è un vero e proprio "escape". Limiti cgroup deboli possono comunque trasformare l'esecuzione di codice in un impatto operativo reale.

Negli ambienti basati su Kubernetes, verifica anche se esistono controlli sulle risorse prima di considerare il DoS teorico:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Strumenti di Hardening

Per gli ambienti incentrati su Docker, `docker-bench-security` rimane una baseline utile per l'audit lato host, poiché verifica i problemi di configurazione comuni rispetto a linee guida di benchmark ampiamente riconosciute:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Lo strumento non sostituisce il threat modeling, ma è comunque utile per individuare configurazioni predefinite negligenti relative a daemon, mount, rete e runtime che si accumulano nel tempo.

Per Kubernetes e gli ambienti che fanno ampio uso del runtime, affianca i controlli statici alla visibilità sul runtime:

- `Tracee` è utile per il rilevamento runtime dei container e per una rapida analisi forense, quando è necessario confermare cosa abbia effettivamente toccato un workload compromesso.
- `Inspektor Gadget` è utile quando la valutazione richiede telemetria a livello kernel associata a pod, container, attività DNS, esecuzione di file o comportamento di rete.

## Controlli

Usa questi comandi come prima verifica rapida durante la valutazione:
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

- Un processo root con ampie capabilities e `Seccomp: 0` merita un'attenzione immediata.
- Un processo root che ha anche una **mappatura UID 1:1** è molto più interessante di un processo "root" all'interno di un user namespace correttamente isolato.
- `cgroup2fs` di solito significa che molte vecchie catene di escape basate su **cgroup v1** non sono il miglior punto di partenza, mentre l'assenza di `memory.max` o `pids.max` indica comunque controlli deboli sul blast radius.
- Mount sospetti e runtime socket spesso offrono un percorso più rapido verso l'impatto rispetto a qualsiasi kernel exploit.
- La combinazione di una postura runtime debole e di limiti sulle risorse deboli indica generalmente un ambiente container permissivo, anziché un singolo errore isolato.

## Riferimenti

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
