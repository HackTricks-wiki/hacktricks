# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## Che cos'è realmente un container

Un modo pratico per definire un container è questo: un container è un albero di processi Linux normale che è stato avviato sotto una specifica configurazione in stile OCI in modo che veda un filesystem controllato, un insieme controllato di risorse del kernel e un modello di privilegi ristretto. Il processo può credere di essere PID 1, può credere di avere il proprio network stack, può credere di possedere il proprio hostname e risorse IPC, e può persino essere eseguito come root all'interno del proprio user namespace. Ma sotto il cofano è ancora un processo dell'host che il kernel schedula come qualsiasi altro.

Per questo motivo la security dei container è in realtà lo studio di come quella illusione viene costruita e di come fallisce. Se il mount namespace è debole, il processo può vedere il filesystem dell'host. Se l'user namespace è assente o disabilitato, root all'interno del container può mappare troppo strettamente a root sull'host. Se seccomp è non confinato e il set di capability è troppo ampio, il processo può raggiungere syscall e funzionalità privilegiate del kernel che avrebbero dovuto rimanere fuori portata. Se il runtime socket è montato all'interno del container, il container potrebbe non aver bisogno di un breakout del kernel perché può semplicemente chiedere al runtime di lanciare un container fratello più potente o montare direttamente il filesystem root dell'host.

## Come i container differiscono dalle macchine virtuali

Una VM normalmente porta con sé il proprio kernel e un confine di astrazione hardware. Questo significa che il kernel guest può crashare, andare in panic o essere sfruttato senza implicare automaticamente il controllo diretto del kernel dell'host. Nei container, il workload non ottiene un kernel separato. Invece ottiene una vista filtrata e namespacizzata dello stesso kernel che usa l'host. Di conseguenza, i container sono di solito più leggeri, più veloci da avviare, più facili da collocare densamente su una macchina e più adatti al deployment di applicazioni a breve durata. Il prezzo è che il confine di isolamento dipende molto più direttamente dalla corretta configurazione dell'host e del runtime.

Questo non significa che i container siano "insicuri" e le VM "sicure". Significa che il modello di sicurezza è diverso. Uno stack di container ben configurato con esecuzione rootless, user namespaces, seccomp di default, un set di capability restrittivo, nessuna condivisione di namespace dell'host e una forte enforcement di SELinux o AppArmor può essere molto robusto. Al contrario, un container avviato con `--privileged`, con condivisione di PID/network dell'host, il Docker socket montato al suo interno e un bind mount scrivibile di `/` è funzionalmente molto più vicino all'accesso root dell'host che a un sandbox applicativa isolata in modo sicuro. La differenza deriva dagli strati che sono stati abilitati o disabilitati.

Esiste anche un terreno intermedio che i lettori dovrebbero capire perché appare sempre più spesso negli ambienti reali. I "sandboxed container runtimes" come gVisor e Kata Containers induriscono intenzionalmente il confine oltre un classico container `runc`. gVisor inserisce uno strato di kernel in userspace tra il workload e molte interfacce del kernel host, mentre Kata lancia il workload all'interno di una macchina virtuale leggera. Questi sono comunque usati attraverso gli ecosistemi container e i workflow di orchestrazione, ma le loro proprietà di sicurezza differiscono dai runtime OCI plain e non dovrebbero essere mentalmente raggruppati con i "normali Docker containers" come se tutto si comportasse allo stesso modo.

## Lo stack dei container: diversi livelli, non uno solo

Quando qualcuno dice "questo container è insicuro", la domanda utile di follow-up è: quale layer lo ha reso insicuro? Un workload containerizzato è di solito il risultato di diversi componenti che lavorano insieme.

In cima, c'è spesso un layer di build dell'immagine come BuildKit, Buildah o Kaniko, che crea l'immagine OCI e i metadata. Sopra il runtime di basso livello, può esserci un engine o manager come Docker Engine, Podman, containerd, CRI-O, Incus o systemd-nspawn. Negli ambienti di cluster, può anche esserci un orchestrator come Kubernetes che decide la postura di sicurezza richiesta tramite la configurazione del workload. Infine, è il kernel che effettivamente applica namespaces, cgroups, seccomp e policy MAC.

Questo modello a strati è importante per comprendere i default. Una restrizione può essere richiesta da Kubernetes, tradotta tramite CRI da containerd o CRI-O, convertita in una spec OCI dal wrapper del runtime e solo allora applicata da `runc`, `crun`, `runsc` o un altro runtime contro il kernel. Quando i default differiscono tra gli ambienti, è spesso perché uno di questi layer ha cambiato la configurazione finale. Lo stesso meccanismo può quindi apparire in Docker o Podman come una flag CLI, in Kubernetes come un campo Pod o `securityContext`, e negli stack runtime di livello inferiore come configurazione OCI generata per il workload. Per questa ragione, gli esempi CLI in questa sezione dovrebbero essere letti come sintassi runtime-specific per un concetto generale di container, non come flag universali supportati da ogni strumento.

## Il vero confine di sicurezza del container

In pratica, la security dei container deriva da controlli sovrapposti, non da un singolo controllo perfetto. I namespaces isolano la visibilità. I cgroups governano e limitano l'uso delle risorse. Le capabilities riducono ciò che un processo dall'aspetto privilegiato può effettivamente fare. seccomp blocca syscall pericolose prima che raggiungano il kernel. AppArmor e SELinux aggiungono Mandatory Access Control sopra i normali controlli DAC. `no_new_privs`, i percorsi procfs mascherati e i percorsi di sistema in sola lettura rendono più difficili le catene comuni di abuso dei privilegi e di proc/sys. Anche il runtime stesso conta perché decide come vengono creati mount, socket, label e join ai namespace.

Per questo motivo molta documentazione sulla security dei container sembra ripetitiva. La stessa catena di escape spesso dipende da più meccanismi contemporaneamente. Per esempio, un bind mount scrivibile dell'host è male, ma diventa molto peggiore se il container esegue anche come root reale sull'host, ha `CAP_SYS_ADMIN`, non è confinato da seccomp e non è limitato da SELinux o AppArmor. Allo stesso modo, la condivisione di PID dell'host è un'esposizione seria, ma diventa dramaticamente più utile per un attaccante quando è combinata con `CAP_SYS_PTRACE`, protezioni procfs deboli o strumenti di ingresso nei namespace come `nsenter`. Il modo giusto di documentare l'argomento non è quindi ripetere lo stesso attacco in ogni pagina, ma spiegare cosa contribuisce ogni layer al confine finale.

## Come leggere questa sezione

La sezione è organizzata dai concetti più generali a quelli più specifici.

Inizia con l'overview del runtime e dell'ecosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Poi rivedi i control plane e le superfici della supply-chain che frequentemente decidono se un attaccante ha bisogno o meno di un kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Poi passa al modello di protezione:

{{#ref}}
protections/
{{#endref}}

Le pagine sui namespace spiegano i kernel isolation primitives individualmente:

{{#ref}}
protections/namespaces/
{{#endref}}

Le pagine su cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths e read-only system paths spiegano i meccanismi che sono solitamente stratificati sopra i namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Uno stato mentale utile per la prima enumerazione

Quando si valuta un target containerizzato, è molto più utile porsi un piccolo set di domande tecniche precise che saltare immediatamente ai PoC di escape famosi. Per prima cosa, identifica lo stack: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer o qualcosa di più specializzato. Poi identifica il runtime: `runc`, `crun`, `runsc`, `kata-runtime` o un'altra implementazione compatibile OCI. Dopodiché, verifica se l'ambiente è rootful o rootless, se gli user namespaces sono attivi, se qualche host namespace è condiviso, quali capabilities rimangono, se seccomp è abilitato, se una policy MAC sta effettivamente facendo enforcement, se sono presenti mount o socket pericolosi, e se il processo può interagire con l'API del container runtime.

Quelle risposte ti dicono molto di più sulla reale postura di sicurezza rispetto al solo nome dell'immagine di base. In molte valutazioni, puoi predire la famiglia di breakout probabile prima di leggere un qualsiasi file dell'applicazione semplicemente comprendendo la configurazione finale del container.

## Copertura

Questa sezione copre il vecchio materiale focalizzato su Docker sotto un'organizzazione orientata ai container: runtime e daemon exposure, authorization plugins, image trust e build secrets, sensitive host mounts, distroless workloads, privileged containers e le protezioni del kernel normalmente stratificate attorno all'esecuzione dei container.
