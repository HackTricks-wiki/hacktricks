# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Una buona assessment di container dovrebbe rispondere a due domande parallele. Primo, cosa può fare un attaccante dal workload attuale? Secondo, quali scelte dell’operatore hanno reso possibile ciò? Gli strumenti di enumeration aiutano con la prima domanda, e le linee guida di hardening aiutano con la seconda. Tenere entrambe sulla stessa pagina rende la sezione più utile come riferimento operativo invece che solo come catalogo di tecniche di escape.

Un aggiornamento pratico per gli ambienti moderni è che molti vecchi writeup sui container assumono in silenzio un **rootful runtime**, **nessuna isolamento user namespace**, e spesso **cgroup v1**. Queste assunzioni non sono più sicure. Prima di perdere tempo su vecchi primitive di escape, verifica prima se il workload è rootless o userns-remapped, se l’host usa cgroup v2, e se Kubernetes o il runtime stanno applicando i profili seccomp e AppArmor predefiniti. Questi dettagli spesso decidono se un famoso breakout sia ancora applicabile.

## Strumenti di Enumeration

Diversi strumenti restano utili per caratterizzare rapidamente un ambiente container:

- `linpeas` può identificare molti indicatori di container, socket montati, capability set, filesystem pericolosi e indizi di breakout.
- `CDK` si concentra specificamente sugli ambienti container e include enumeration più alcuni controlli automatici di escape.
- `amicontained` è leggero e utile per identificare restrizioni del container, capabilities, esposizione dei namespace e probabili classi di breakout.
- `deepce` è un altro enumeratore focalizzato sui container con controlli orientati al breakout.
- `grype` è utile quando l’assessment include la revisione delle vulnerabilità delle image-package invece della sola analisi degli escape in runtime.
- `Tracee` è utile quando servono **prove runtime** invece della sola postura statica, soprattutto per esecuzione sospetta di processi, accesso ai file e raccolta di eventi aware del container.
- `Inspektor Gadget` è utile in Kubernetes e nelle indagini su host Linux quando serve visibilità basata su eBPF collegata a pod, container, namespace e altri concetti di livello superiore.

Il valore di questi strumenti è la velocità e la copertura, non la certezza. Aiutano a rivelare rapidamente la postura generale, ma i risultati interessanti richiedono ancora interpretazione manuale rispetto al reale modello di runtime, namespace, capability e mount.

## Priorità di Hardening

I principi di hardening più importanti sono concettualmente semplici, anche se la loro implementazione varia a seconda della piattaforma. Evita i container privilegiati. Evita i socket del runtime montati. Non dare ai container percorsi host scrivibili, a meno che non ci sia una ragione molto specifica. Usa user namespaces o esecuzione rootless dove possibile. Rimuovi tutte le capabilities e aggiungi solo quelle realmente necessarie al workload. Mantieni attivi seccomp, AppArmor e SELinux invece di disabilitarli per risolvere problemi di compatibilità applicativa. Limita le risorse così che un container compromesso non possa negare facilmente il servizio all’host.

L’igiene di image e build conta quanto la postura runtime. Usa immagini minimali, ricostruiscile frequentemente, scansionale, richiedi provenance dove praticabile e tieni i secret fuori dai layer. Un container che gira come non-root, con una image piccola e una superficie syscall e capability ristretta, è molto più facile da difendere rispetto a una grande image di convenienza che gira come root equivalente dell’host con tool di debugging preinstallati.

Per Kubernetes, le baseline moderne di hardening sono più opinative di quanto molti operatori ancora assumano. I **Pod Security Standards** integrati trattano `restricted` come il profilo di "current best practice": `allowPrivilegeEscalation` dovrebbe essere `false`, i workload dovrebbero girare come non-root, seccomp dovrebbe essere impostato esplicitamente su `RuntimeDefault` o `Localhost`, e i capability set dovrebbero essere rimossi in modo aggressivo. Durante l’assessment, questo conta perché un cluster che usa solo label `warn` o `audit` può sembrare hardenizzato sulla carta, pur continuando ad accettare pod rischiosi nella pratica.

## Domande di Triage Moderne

Prima di immergerti nelle pagine specifiche sugli escape, rispondi a queste domande rapide:

1. Il workload è **rootful**, **rootless**, o **userns-remapped**?
2. Il nodo usa **cgroup v1** o **cgroup v2**?
3. **seccomp** e **AppArmor/SELinux** sono configurati esplicitamente, o semplicemente ereditati quando disponibili?
4. In Kubernetes, il namespace sta davvero **enforcing** `baseline` o `restricted`, oppure sta solo facendo warning/auditing?

Verifiche utili:
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

- Se `/proc/self/uid_map` mostra che root del container è mappato a un **high host UID range**, molte vecchie writeup su host-root diventano meno rilevanti perché root nel container non è più equivalente a host-root.
- Se `/sys/fs/cgroup` è `cgroup2fs`, le vecchie writeup specifiche di **cgroup v1**, come l’abuso di `release_agent`, non dovrebbero più essere la tua prima ipotesi.
- Se seccomp e AppArmor sono ereditati solo implicitamente, la portabilità può essere più debole di quanto i defender si aspettino. In Kubernetes, impostare esplicitamente `RuntimeDefault` è spesso più forte che affidarsi in silenzio ai default del node.
- Se `supplementalGroupsPolicy` è impostato su `Strict`, il pod dovrebbe evitare di ereditare in modo silenzioso membri aggiuntivi dei gruppi da `/etc/group` dentro l’immagine, rendendo il comportamento di accesso a volumi e file basato sui gruppi più prevedibile.
- Etichette di namespace come `pod-security.kubernetes.io/enforce=restricted` valgono la pena di essere controllate direttamente. `warn` e `audit` sono utili, ma non impediscono la creazione di un pod rischioso.

## Resource-Exhaustion Examples

I controlli sulle risorse non sono glamour, ma fanno parte della container security perché limitano il blast radius di una compromissione. Senza limiti di memoria, CPU o PID, una semplice shell può bastare per degradare l’host o i workload vicini.

Esempi di test con impatto sull’host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Questi esempi sono utili perché mostrano che non ogni esito pericoloso di un container è una "escape" pulita. Limiti cgroup deboli possono comunque trasformare l'esecuzione di codice in un impatto operativo reale.

Negli ambienti basati su Kubernetes, verifica anche se i controlli delle risorse esistono davvero prima di trattare il DoS come teorico:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Per ambienti centrati su Docker, `docker-bench-security` rimane una base utile per l'audit lato host perché verifica i comuni problemi di configurazione rispetto alle linee guida dei benchmark ampiamente riconosciute:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Lo strumento non sostituisce il threat modeling, ma è comunque prezioso per individuare default negligenti di daemon, mount, rete e runtime che si accumulano nel tempo.

Per ambienti Kubernetes e runtime-heavy, affianca i controlli statici con visibilità runtime:

- `Tracee` è utile per il rilevamento runtime container-aware e per quick forensics quando devi confermare cosa abbia effettivamente toccato un workload compromesso.
- `Inspektor Gadget` è utile quando l’assessment richiede telemetria a livello kernel mappata di nuovo su pod, container, attività DNS, esecuzione di file o comportamento di rete.

## Checks

Usali come comandi rapidi di primo passaggio durante l’assessment:
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

- Un processo root con ampie capability e `Seccomp: 0` merita attenzione immediata.
- Un processo root che ha anche una **mappa UID 1:1** è molto più interessante di un "root" all’interno di un user namespace correttamente isolato.
- `cgroup2fs` di solito significa che molte vecchie catene di escape **cgroup v1** non sono il tuo miglior punto di partenza, mentre `memory.max` o `pids.max` mancanti indicano comunque controlli deboli sul blast-radius.
- Mount sospetti e runtime socket spesso offrono una via più rapida all’impatto rispetto a qualsiasi kernel exploit.
- La combinazione di un runtime posture debole e limiti di risorse deboli indica di solito un ambiente container in generale permissivo, piuttosto che un singolo errore isolato.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
