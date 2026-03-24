# Sicurezza dei container

{{#include ../../../banners/hacktricks-training.md}}

## Cos'è realmente un container

Un modo pratico per definire un container è questo: un container è un **normale albero di processi Linux** che è stato avviato sotto una specifica configurazione OCI-style in modo da vedere un filesystem controllato, un insieme controllato di risorse del kernel e un modello di privilegi ristretto. Il processo può credere di essere PID 1, può credere di avere il proprio stack di rete, può credere di possedere il proprio hostname e le risorse IPC, e può persino eseguire come root all'interno del proprio user namespace. Ma sotto il cofano è comunque un processo host che il kernel schedula come qualsiasi altro.

Questo è il motivo per cui la sicurezza dei container è davvero lo studio di come quell'illusione viene costruita e di come fallisce. Se il mount namespace è debole, il processo può vedere il filesystem dell'host. Se l'user namespace è assente o disabilitato, root all'interno del container può mappare troppo strettamente a root sull'host. Se seccomp è non confinato e il set di capability è troppo ampio, il processo può raggiungere syscalls e funzionalità privilegiate del kernel che avrebbero dovuto rimanere fuori portata. Se il runtime socket è montato all'interno del container, il container potrebbe non aver bisogno affatto di un kernel breakout perché può semplicemente chiedere al runtime di lanciare un container "fratello" più potente o montare direttamente il filesystem root dell'host.

## Come i container si differenziano dalle Virtual Machines

Una VM normalmente porta con sé il proprio kernel e il proprio confine di astrazione hardware. Questo significa che il kernel guest può crashare, andare in panic o essere sfruttato senza implicare automaticamente il controllo diretto del kernel dell'host. Nei container, il workload non ottiene un kernel separato. Invece, ottiene una vista accuratamente filtrata e namespaced dello stesso kernel che usa l'host. Di conseguenza, i container sono solitamente più leggeri, più veloci da avviare, più facili da impacchettare densamente su una macchina e più adatti al deployment di applicazioni di breve durata. Il prezzo è che il confine di isolamento dipende molto più direttamente da una corretta configurazione dell'host e del runtime.

Questo non significa che i container siano "insicuri" e le VM "sicure". Significa che il modello di sicurezza è diverso. Uno stack di container ben configurato con rootless execution, user namespaces, default seccomp, un set di capability rigoroso, nessuna condivisione di namespace dell'host e una forte applicazione di SELinux o AppArmor può essere molto robusto. Al contrario, un container avviato con `--privileged`, con condivisione host PID/network, il Docker socket montato al suo interno e una bind mount scrivibile di `/` è funzionalmente molto più vicino all'accesso root dell'host che a un sandbox applicativa isolata in modo sicuro. La differenza viene dagli strati che sono stati abilitati o disabilitati.

Esiste anche una via di mezzo che i lettori dovrebbero comprendere perché appare sempre più spesso negli ambienti reali. I **sandboxed container runtimes** come **gVisor** e **Kata Containers** induriscono intenzionalmente il confine oltre un classico container `runc`. gVisor inserisce uno strato di kernel in userspace tra il workload e molte interfacce del kernel host, mentre Kata lancia il workload all'interno di una macchina virtuale leggera. Questi vengono ancora usati tramite ecosistemi di container e workflow di orchestrazione, ma le loro proprietà di sicurezza differiscono dagli OCI runtimes "plain" e non dovrebbero essere mentalmente raggruppati con i "normal Docker containers" come se tutto si comportasse allo stesso modo.

## Lo stack dei container: diversi livelli, non uno solo

Quando qualcuno dice "questo container è insicuro", la domanda utile di follow-up è: **quale livello lo ha reso insicuro?** Un workload containerizzato è solitamente il risultato di diversi componenti che lavorano insieme.

In cima, c'è spesso un **image build layer** come BuildKit, Buildah o Kaniko, che crea l'immagine OCI e i metadata. Sopra il runtime low-level, può esserci un **engine o manager** come Docker Engine, Podman, containerd, CRI-O, Incus o systemd-nspawn. Negli ambienti cluster, può anche esserci un **orchestrator** come Kubernetes che decide la postura di sicurezza richiesta tramite la configurazione del workload. Infine, il **kernel** è ciò che effettivamente fa rispettare namespaces, cgroups, seccomp e la politica MAC.

Questo modello a strati è importante per capire i default. Una restrizione può essere richiesta da Kubernetes, tradotta tramite CRI da containerd o CRI-O, convertita in uno spec OCI dal wrapper del runtime e solo allora applicata da `runc`, `crun`, `runsc` o un altro runtime contro il kernel. Quando i default differiscono tra ambienti, spesso è perché uno di questi livelli ha cambiato la configurazione finale. Lo stesso meccanismo può quindi apparire in Docker o Podman come una flag CLI, in Kubernetes come un Pod o un campo `securityContext`, e negli stack runtime di livello inferiore come configurazione OCI generata per il workload. Per questa ragione, gli esempi CLI in questa sezione dovrebbero essere letti come **sintassi specifica del runtime per un concetto generale di container**, non come flag universali supportati da ogni strumento.

## Il vero confine di sicurezza dei container

In pratica, la sicurezza dei container viene da **controlli sovrapposti**, non da un singolo controllo perfetto. Namespaces isolano la visibilità. cgroups governano e limitano l'uso delle risorse. Le Capabilities riducono ciò che un processo che sembra privilegiato può effettivamente fare. seccomp blocca syscalls pericolose prima che raggiungano il kernel. AppArmor e SELinux aggiungono Mandatory Access Control sopra i normali controlli DAC. `no_new_privs`, percorsi procfs mascherati e percorsi di sistema in sola lettura rendono più difficili le catene comuni di abuso di privilegi e proc/sys. Anche il runtime conta perché decide come vengono creati mount, socket, label e join di namespace.

Ecco perché molta documentazione sulla sicurezza dei container sembra ripetitiva. La stessa catena di escape spesso dipende da più meccanismi contemporaneamente. Ad esempio, una bind mount dell'host scrivibile è pericolosa, ma diventa molto peggiore se il container gira anche come real root sull'host, ha `CAP_SYS_ADMIN`, non è confinato da seccomp e non è limitato da SELinux o AppArmor. Allo stesso modo, la condivisione host PID è un'esposizione seria, ma diventa drammaticamente più utile per un attaccante quando è combinata con `CAP_SYS_PTRACE`, protezioni procfs deboli o strumenti di ingresso nei namespace come `nsenter`. Il modo giusto di documentare l'argomento quindi non è ripetere lo stesso attacco in ogni pagina, ma spiegare cosa contribuisce ogni livello al confine finale.

## Come leggere questa sezione

La sezione è organizzata dai concetti più generali a quelli più specifici.

Start with the runtime and ecosystem overview:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Then review the control planes and supply-chain surfaces that frequently decide whether an attacker even needs a kernel escape:

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

Then move into the protection model:

{{#ref}}
protections/
{{#endref}}

The namespace pages explain the kernel isolation primitives individually:

{{#ref}}
protections/namespaces/
{{#endref}}

The pages on cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, and read-only system paths explain the mechanisms that are usually layered on top of namespaces:

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

## Una buona mentalità iniziale per l'enumerazione

Quando si valuta un target containerizzato, è molto più utile porsi un piccolo insieme di domande tecniche precise che saltare immediatamente ai famosi PoC di escape. Prima, identifica lo **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer o qualcosa di più specializzato. Poi identifica il **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` o un'altra implementazione compatibile OCI. Dopo, verifica se l'ambiente è **rootful or rootless**, se gli **user namespaces** sono attivi, se vengono condivisi **host namespaces**, quali **capabilities** rimangono, se **seccomp** è abilitato, se una **MAC policy** è effettivamente in enforcement, se sono presenti **mounts o socket pericolosi**, e se il processo può interagire con l'API del runtime del container.

Quelle risposte ti dicono molto più sulla reale postura di sicurezza di quanto potrà mai fare il nome dell'immagine base. In molte valutazioni, puoi prevedere la probabile famiglia di breakout prima di leggere un singolo file dell'applicazione semplicemente comprendendo la configurazione finale del container.

## Copertura

Questa sezione copre il materiale vecchio e focalizzato su Docker sotto un'organizzazione orientata ai container: runtime e daemon exposure, authorization plugins, image trust e build secrets, sensitive host mounts, distroless workloads, privileged containers e le protezioni del kernel normalmente stratificate attorno all'esecuzione dei container.
{{#include ../../../banners/hacktricks-training.md}}
