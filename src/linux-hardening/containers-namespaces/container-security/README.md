# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## Che Cos'è Effettivamente Un Container

Un modo pratico per definire un container è il seguente: un container è un **albero di processi Linux regolare** avviato secondo una configurazione specifica in stile OCI, in modo da vedere un filesystem controllato, un insieme controllato di risorse del kernel e un modello di privilegi limitato. Il processo può credere di essere il PID 1, può credere di avere il proprio network stack, può credere di possedere il proprio hostname e le proprie risorse IPC e può persino essere eseguito come root all'interno del proprio user namespace. Ma, sotto il cofano, rimane comunque un processo dell'host che il kernel pianifica come qualsiasi altro.

Per questo la container security è in realtà lo studio di come viene costruita questa illusione e di come può fallire. Se il mount namespace è debole, il processo può vedere il filesystem dell'host. Se lo user namespace è assente o disabilitato, root all'interno del container può essere mappato troppo direttamente a root sull'host. Se seccomp è unconfined e il capability set è troppo ampio, il processo può raggiungere syscall e funzionalità privilegiate del kernel che avrebbero dovuto rimanere inaccessibili. Se il runtime socket è montato all'interno del container, il container potrebbe non aver bisogno affatto di un kernel breakout, perché può semplicemente chiedere al runtime di avviare un container sibling più potente o di montare direttamente il root filesystem dell'host.

## In Che Modo I Container Differiscono Dalle Virtual Machines

Una VM normalmente include il proprio kernel e una propria hardware abstraction boundary. Ciò significa che il guest kernel può andare in crash, avere un panic o essere sfruttato senza implicare automaticamente il controllo diretto del kernel dell'host. Nei container, il workload non riceve un kernel separato. Riceve invece una vista attentamente filtrata e sottoposta a namespace dello stesso kernel utilizzato dall'host. Di conseguenza, i container sono solitamente più leggeri, si avviano più rapidamente, sono più facili da impacchettare in modo denso su una macchina e sono più adatti al deployment di applicazioni di breve durata. Il prezzo è che l'isolation boundary dipende molto più direttamente dalla corretta configurazione dell'host e del runtime.

Questo non significa che i container siano "insicuri" e le VM siano "sicure". Significa che il security model è diverso. Uno stack di container ben configurato con esecuzione rootless, user namespaces, seccomp predefinito, un capability set restrittivo, nessuna condivisione degli host namespaces e una forte applicazione di SELinux o AppArmor può essere molto robusto. Al contrario, un container avviato con `--privileged`, con condivisione dell'host PID/network, il Docker socket montato al suo interno e un bind mount scrivibile di `/` è funzionalmente molto più vicino all'accesso root sull'host che a un application sandbox isolato in modo sicuro. La differenza deriva dai layer che sono stati abilitati o disabilitati.

Esiste anche una via di mezzo che i lettori dovrebbero comprendere, perché compare sempre più spesso negli ambienti reali. I **sandboxed container runtimes**, come **gVisor** e **Kata Containers**, rafforzano intenzionalmente il boundary oltre quello di un container `runc` classico. gVisor inserisce un userspace kernel layer tra il workload e molte interfacce del kernel dell'host, mentre Kata avvia il workload all'interno di una lightweight virtual machine. Questi runtime vengono comunque utilizzati tramite gli ecosistemi dei container e i workflow di orchestration, ma le loro proprietà di security differiscono da quelle dei runtime OCI standard e non dovrebbero essere mentalmente raggruppati con i "normal Docker containers", come se tutto si comportasse allo stesso modo.

## Lo Stack Dei Container: Diversi Layer, Non Uno Solo

Quando qualcuno dice "questo container è insicuro", la domanda successiva utile è: **quale layer lo ha reso insicuro?** Un workload containerizzato è solitamente il risultato della collaborazione di diversi componenti.

In cima, spesso c'è un **image build layer**, come BuildKit, Buildah o Kaniko, che crea l'immagine OCI e i relativi metadata. Al di sopra del low-level runtime, può esserci un **engine o manager**, come Docker Engine, Podman, containerd, CRI-O, Incus o systemd-nspawn. Negli ambienti cluster, può esserci anche un **orchestrator**, come Kubernetes, che decide il security posture richiesto tramite la configurazione del workload. Infine, è il **kernel** a imporre effettivamente namespaces, cgroups, seccomp e la MAC policy.

Questo layered model è importante per comprendere i default. Una restriction può essere richiesta da Kubernetes, tradotta tramite CRI da containerd o CRI-O, convertita in una OCI spec dall'runtime wrapper e infine applicata da `runc`, `crun`, `runsc` o da un altro runtime tramite il kernel. Quando i default differiscono tra gli ambienti, spesso è perché uno di questi layer ha modificato la configurazione finale. Lo stesso meccanismo può quindi apparire in Docker o Podman come un CLI flag, in Kubernetes come un campo Pod o `securityContext` e negli stack di runtime di livello inferiore come una configurazione OCI generata per il workload. Per questo motivo, gli esempi CLI di questa sezione dovrebbero essere letti come **sintassi specifica del runtime per un concetto generale dei container**, non come flag universali supportati da ogni tool.

## Il Reale Container Security Boundary

In pratica, la container security deriva da **controlli sovrapposti**, non da un singolo controllo perfetto. I namespaces isolano la visibilità. I cgroups regolano e limitano l'uso delle risorse. Le capabilities riducono ciò che un processo dall'aspetto privilegiato può effettivamente fare. seccomp blocca le syscall pericolose prima che raggiungano il kernel. AppArmor e SELinux aggiungono il Mandatory Access Control ai normali controlli DAC. `no_new_privs`, i percorsi procfs masked e i system paths in sola lettura rendono più difficili le comuni catene di abuso dei privilegi e di proc/sys. Anche il runtime stesso è importante, perché decide come vengono creati mount, socket, label e namespace joins.

Per questo molta documentazione sulla container security sembra ripetitiva. La stessa escape chain spesso dipende contemporaneamente da più meccanismi. Per esempio, un host bind mount scrivibile è pericoloso, ma diventa molto peggiore se il container viene inoltre eseguito come root reale sull'host, dispone di `CAP_SYS_ADMIN`, è unconfined da seccomp e non è limitato da SELinux o AppArmor. Allo stesso modo, la condivisione dell'host PID è una seria esposizione, ma diventa significativamente più utile a un attacker quando è combinata con `CAP_SYS_PTRACE`, protezioni procfs deboli o namespace-entry tools come `nsenter`. Il modo corretto di documentare l'argomento non consiste quindi nel ripetere lo stesso attack su ogni pagina, ma nello spiegare ciò che ogni layer apporta al boundary finale.

## Come Leggere Questa Sezione

La sezione è organizzata dai concetti più generali a quelli più specifici.

Inizia con la panoramica del runtime e dell'ecosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Esamina poi i control planes e le supply-chain surfaces che spesso determinano se un attacker abbia persino bisogno di un kernel escape:

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

Passa quindi al protection model:

{{#ref}}
protections/
{{#endref}}

Le pagine sui namespaces spiegano singolarmente i kernel isolation primitives:

{{#ref}}
protections/namespaces/
{{#endref}}

Le pagine su cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths e read-only system paths spiegano i meccanismi che vengono solitamente sovrapposti ai namespaces:

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

## Una Buona Mentalità Per La Prima Enumeration

Durante la valutazione di un target containerizzato, è molto più utile porsi un piccolo insieme di domande tecniche precise che saltare immediatamente a famosi escape PoC. Per prima cosa, identifica lo **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer o qualcosa di più specializzato. Identifica quindi il **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` o un'altra implementazione compatibile con OCI. Dopodiché, verifica se l'ambiente è **rootful o rootless**, se gli **user namespaces** sono attivi, se vengono condivisi **host namespaces**, quali **capabilities** rimangono, se **seccomp** è abilitato, se una **MAC policy** è effettivamente enforcing, se sono presenti **mount o socket pericolosi** e se il processo può interagire con il container runtime API.

Queste risposte forniscono molte più informazioni sul reale security posture rispetto al nome della base image. In molte assessment, puoi prevedere la probabile famiglia di breakout prima ancora di leggere un singolo file dell'applicazione, semplicemente comprendendo la configurazione finale del container.

## Coverage

Questa sezione tratta il vecchio materiale focalizzato su Docker secondo un'organizzazione incentrata sui container: runtime e daemon exposure, authorization plugins, image trust e build secrets, sensitive host mounts, distroless workloads, privileged containers e le kernel protections normalmente sovrapposte all'esecuzione dei container.
{{#include ../../../banners/hacktricks-training.md}}
