# Valutazione e hardening

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Una buona valutazione dei container dovrebbe rispondere a due domande parallele. Primo: cosa può fare un attaccante dal workload attuale? Secondo: quali scelte dell’operatore lo hanno reso possibile? Gli strumenti di enumerazione aiutano a rispondere alla prima domanda, mentre le indicazioni per l’hardening aiutano con la seconda. Riunire entrambe in un’unica pagina la rende più utile come riferimento pratico, anziché come semplice catalogo di tecniche di escape.

Un aggiornamento pratico per gli ambienti moderni è che molti vecchi articoli sui container danno implicitamente per scontati un **runtime rootful**, **l’assenza di isolamento tramite user namespace** e spesso **cgroup v1**. Queste ipotesi non sono più sicure. Prima di dedicare tempo alle vecchie primitive di escape, verifica innanzitutto se il workload è rootless o userns-remapped, se l’host usa cgroup v2 e se Kubernetes o il runtime applicano ora profili seccomp e AppArmor predefiniti. Questi dettagli spesso determinano se un famoso breakout è ancora applicabile.

## Strumenti di enumerazione

Diversi strumenti restano utili per caratterizzare rapidamente un ambiente container:

- `linpeas` può individuare molti indicatori di container, socket montati, set di capability, filesystem pericolosi e indizi di breakout.
- `CDK` è specifico per gli ambienti container e include enumerazione e alcuni controlli automatici di escape.
- `amicontained` è leggero e utile per identificare restrizioni dei container, capability, esposizione dei namespace e probabili classi di breakout.
- `deepce` è un altro enumeratore specifico per i container, con controlli orientati al breakout.
- `grype` è utile quando la valutazione include l’analisi delle vulnerabilità dei pacchetti delle immagini, e non solo l’analisi degli escape a runtime.
- `Tracee` è utile quando servono **evidenze a runtime**, anziché solo una valutazione statica della postura di sicurezza, in particolare per l’esecuzione di processi sospetti, l’accesso ai file e la raccolta di eventi con consapevolezza dei container.
- `Inspektor Gadget` è utile nelle indagini su Kubernetes e sugli host Linux quando serve visibilità basata su eBPF, correlata a pod, container, namespace e altri concetti di livello superiore.

Il valore di questi strumenti sta nella rapidità e nella copertura, non nella certezza. Aiutano a individuare rapidamente la postura generale, ma i risultati rilevanti richiedono comunque un’interpretazione manuale alla luce del runtime, dei namespace, delle capability e del modello di mount effettivi.

## Priorità di hardening

I principi di hardening più importanti sono concettualmente semplici, anche se la loro implementazione varia a seconda della piattaforma. Evita i container privilegiati. Evita i socket del runtime montati. Non concedere ai container percorsi host scrivibili, a meno che non ci sia un motivo ben preciso. Usa user namespace o esecuzione rootless quando possibile. Rimuovi tutte le capability e aggiungi solo quelle realmente necessarie al workload. Mantieni abilitati seccomp, AppArmor e SELinux, invece di disabilitarli per risolvere problemi di compatibilità delle applicazioni. Limita le risorse, così che un container compromesso non possa causare facilmente un denial of service all’host.

L’igiene delle immagini e delle build conta quanto la postura a runtime. Usa immagini minimali, ricostruiscile frequentemente, analizzale, richiedi la provenienza ove pratico e non inserire segreti nei layer. Un container eseguito come non-root, con un’immagine piccola e una superficie ristretta di syscall e capability, è molto più facile da difendere di una grande immagine generica eseguita come root con privilegi equivalenti a quelli dell’host e strumenti di debug preinstallati.

Per Kubernetes, le baseline di hardening attuali sono più prescrittive di quanto molti operatori ancora suppongano. I **Pod Security Standards** integrati considerano `restricted` il profilo di “best practice attuale”: `allowPrivilegeEscalation` dovrebbe essere `false`, i workload dovrebbero essere eseguiti come non-root, seccomp dovrebbe essere impostato esplicitamente su `RuntimeDefault` o `Localhost` e i set di capability dovrebbero essere ridotti in modo aggressivo. In fase di valutazione, questo è importante perché un cluster che usa solo le etichette `warn` o `audit` può sembrare conforme sulla carta, pur continuando ad ammettere nella pratica pod rischiosi.<sup>[[1]](#references)</sup>

Quando un Pod ha montato un token di service account, valuta i suoi permessi **per ogni namespace di destinazione**. Una regola che elenca i Pod in un namespace non dimostra che l’autorizzazione valga anche in un altro; un token montato in un Pod diverso può avere permessi differenti. Usa `kubectl auth can-i list pods -n <target-namespace>` e `kubectl auth can-i list secrets -n <target-namespace>` con l’identità effettivamente in esame. L’autorizzazione a elencare i Secret è un indizio serio, perché la risposta a una richiesta di elenco può includere il contenuto dei Secret, ma non dimostra che sia presente un token privilegiato. Per accedere all’host servono inoltre un’autorizzazione utilizzabile per creare workload, l’ammissione del mount `hostPath` proposto e un contesto di sicurezza del nodo/pod che consenta l’operazione sui file prevista. Consulta i [controlli di autorizzazione](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) e le [indicazioni di Kubernetes sull’escalation dei privilegi RBAC](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

## Domande per il triage moderno

Prima di consultare le pagine specifiche sugli escape, rispondi a queste domande rapide:

1. Il workload è **rootful**, **rootless** o **userns-remapped**?
2. Il nodo usa **cgroup v1** o **cgroup v2**?
3. **seccomp** e **AppArmor/SELinux** sono configurati esplicitamente o solo ereditati, se disponibili?
4. In Kubernetes, il namespace applica effettivamente `baseline` o `restricted`, oppure si limita a generare avvisi o registrare eventi di audit?

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

- Se `/proc/self/uid_map` mostra che la root del container è mappata su un **intervallo di UID host elevato**, molte vecchie guide su come ottenere accesso in scrittura come root sull’host sono meno rilevanti, perché la root nel container non equivale più alla root sull’host.
- Se `/sys/fs/cgroup` è `cgroup2fs`, le vecchie guide specifiche per **cgroup v1**, come l’abuso di `release_agent`, non dovrebbero più essere la prima ipotesi.
- Se seccomp e AppArmor vengono ereditati solo implicitamente, la portabilità può essere più debole di quanto i difensori si aspettino. In Kubernetes, impostare esplicitamente `RuntimeDefault` è spesso più sicuro che affidarsi implicitamente alle impostazioni predefinite del nodo.
- Se `supplementalGroupsPolicy` è impostato su `Strict`, il pod dovrebbe evitare di ereditare silenziosamente altre appartenenze ai gruppi da `/etc/group` all’interno dell’immagine, rendendo più prevedibile il comportamento di accesso ai volumi e ai file basato sui gruppi.
- Vale la pena controllare direttamente le etichette dei namespace, come `pod-security.kubernetes.io/enforce=restricted`. `warn` e `audit` sono utili, ma non impediscono la creazione di un pod rischioso.

## Triage della baseline runtime

Una baseline runtime è una verifica rapida che permette di capire se un container sembra un normale workload isolato o un punto d’appoggio nel control plane con impatto sull’host. Dovrebbe raccogliere informazioni sufficienti per stabilire quale argomento leggere in seguito: abuso dei socket runtime, mount dell’host, namespace, cgroup, capability o revisione dei secret dell’immagine.

Controlli utili dall’interno di un workload:

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

- `memory.max` / `pids.max` mancanti o illimitati indicano controlli deboli sul raggio d'impatto, anche in assenza di una via di evasione evidente.
- Una root shell con `NoNewPrivs: 0`, capabilities ampie e seccomp permissivo è molto più interessante di un workload ristretto e non-root.
- I socket del runtime e i mount host scrivibili hanno in genere la precedenza sugli exploit del kernel, perché espongono già un percorso di controllo del filesystem o di gestione.
- Gli namespace PID, di rete, IPC o cgroup condivisi non costituiscono sempre, da soli, una via di evasione completa, ma facilitano l'individuazione del passo successivo.

## Esempi di esaurimento delle risorse

I controlli delle risorse non sono appariscenti, ma fanno parte della sicurezza dei container perché limitano il raggio d'impatto di una compromissione. Senza limiti per memoria, CPU o PID, può bastare una semplice shell per compromettere l'host o i workload vicini.

Esempi di test con impatto sull'host:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Questi esempi sono utili perché mostrano che non tutti gli esiti pericolosi nei container consistono in una vera e propria «evasione». Limiti cgroup deboli possono comunque trasformare l'esecuzione di codice in un impatto operativo concreto.

Negli ambienti basati su Kubernetes, verifica anche se esistono controlli delle risorse prima di considerare il DoS un rischio puramente teorico:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Strumenti di hardening

Negli ambienti incentrati su Docker, `docker-bench-security` rimane un utile riferimento di base per gli audit lato host, poiché verifica i problemi di configurazione più comuni rispetto a linee guida di benchmark ampiamente riconosciute. Gli avvisi relativi al runtime vanno esaminati separatamente, perché un benchmark di configurazione non può rilevare se il runtime installato è interessato da una vulnerabilità divulgata di recente. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Lo strumento non sostituisce il threat modeling, ma è comunque utile per individuare impostazioni predefinite poco attente di daemon, mount, rete e runtime che si accumulano nel tempo.

Per Kubernetes e gli ambienti incentrati sul runtime, affiancate i controlli statici alla visibilità runtime:

- `Tracee` è utile per il rilevamento runtime consapevole dei container e per analisi forensi rapide, quando serve confermare cosa ha effettivamente toccato un workload compromesso.
- `Inspektor Gadget` è utile quando la valutazione richiede telemetria a livello kernel ricondotta a pod, container, attività DNS, esecuzione di file o comportamento di rete.

## Controlli

Usate questi comandi come rapidi controlli iniziali durante la valutazione:

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

- Un processo root con capabilities ampie e `Seccomp: 0` merita attenzione immediata.
- Un processo root che ha anche una **mappatura UID 1:1** è molto più interessante di un processo "root" all'interno di uno user namespace correttamente isolato.
- `cgroup2fs` di solito significa che molte vecchie catene di escape **cgroup v1** non sono il punto di partenza migliore, mentre l'assenza di `memory.max` o `pids.max` indica comunque controlli deboli sul raggio d'impatto.
- Mount sospetti e socket runtime spesso offrono un percorso verso l'impatto più rapido di qualsiasi exploit del kernel.
- La combinazione di una configurazione runtime permissiva e limiti di risorse deboli indica solitamente un ambiente container generalmente permissivo, anziché un singolo errore isolato.

## References

- [1] [Standard di sicurezza dei Pod Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Avviso di sicurezza Docker: vulnerabilità multiple in runc, BuildKit e Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
