# Container Security

## Cos'è realmente un container

Un modo pratico per definire un container è il seguente: un container è un **normale albero di processi Linux** avviato con una configurazione specifica in stile OCI, in modo che visualizzi un filesystem controllato, un insieme controllato di risorse del kernel e un modello di privilegi limitato. Il processo può credere di essere il PID 1, può credere di avere il proprio network stack, può credere di possedere il proprio hostname e le proprie risorse IPC e può persino essere eseguito come root all'interno del proprio user namespace. Ma, sotto il cofano, è comunque un processo dell'host che il kernel pianifica come qualsiasi altro.

Per questo la container security consiste realmente nello studio di come viene costruita questa illusione e di come può fallire. Se il mount namespace è debole, il processo può vedere il filesystem dell'host. Se lo user namespace è assente o disabilitato, root all'interno del container può corrispondere troppo direttamente a root sull'host. Se seccomp è unconfined e il capability set è troppo ampio, il processo può raggiungere syscall e funzionalità privilegiate del kernel che avrebbero dovuto rimanere inaccessibili. Se il runtime socket è montato all'interno del container, il container potrebbe non aver bisogno di un kernel breakout perché può semplicemente chiedere al runtime di avviare un container sibling più potente o di montare direttamente il filesystem root dell'host.

## In che modo i container differiscono dalle macchine virtuali

Una VM normalmente include il proprio kernel e il proprio confine di astrazione hardware. Ciò significa che il guest kernel può andare in crash, entrare in panic o essere compromesso senza implicare automaticamente il controllo diretto del kernel dell'host. Nei container, il workload non riceve un kernel separato. Riceve invece una vista attentamente filtrata e organizzata tramite namespace dello stesso kernel utilizzato dall'host. Di conseguenza, i container sono generalmente più leggeri, si avviano più velocemente, sono più semplici da impacchettare densamente su una macchina e sono più adatti al deployment di applicazioni di breve durata. Il prezzo è che il confine di isolamento dipende molto più direttamente dalla corretta configurazione dell'host e del runtime.

Questo non significa che i container siano "insecure" e le VM siano "secure". Significa che il security model è diverso. Uno stack di container ben configurato, con esecuzione rootless, user namespaces, seccomp predefinito, un capability set rigoroso, nessuna condivisione degli host namespace e un enforcement forte di SELinux o AppArmor, può essere molto robusto. Al contrario, un container avviato con `--privileged`, con condivisione del PID/network dell'host, con il Docker socket montato al suo interno e con un bind mount scrivibile di `/`, è funzionalmente molto più vicino all'accesso root sull'host che a un application sandbox isolato in modo sicuro. La differenza deriva dai layer che sono stati abilitati o disabilitati.

Esiste anche una via di mezzo che i lettori dovrebbero comprendere, perché compare sempre più spesso negli ambienti reali. I **sandboxed container runtimes**, come **gVisor** e **Kata Containers**, rafforzano intenzionalmente il confine oltre quello di un container `runc` classico. gVisor inserisce un layer kernel in userspace tra il workload e molte interfacce del kernel dell'host, mentre Kata avvia il workload all'interno di una macchina virtuale leggera. Questi runtime vengono comunque utilizzati tramite gli ecosistemi dei container e i workflow di orchestration, ma le loro proprietà di sicurezza differiscono da quelle dei runtime OCI standard e non dovrebbero essere raggruppate mentalmente con i "normal Docker containers", come se tutto si comportasse allo stesso modo.

## Lo stack dei container: diversi layer, non uno solo

Quando qualcuno dice "questo container è insecure", la domanda successiva utile è: **quale layer lo ha reso insecure?** Un workload containerizzato è solitamente il risultato di diversi componenti che lavorano insieme.

Al livello superiore c'è spesso un **image build layer**, come BuildKit, Buildah o Kaniko, che crea l'immagine OCI e i relativi metadata. Al di sopra del low-level runtime può esserci un **engine o manager**, come Docker Engine, Podman, containerd, CRI-O, Incus o systemd-nspawn. Negli ambienti cluster può inoltre esserci un **orchestrator**, come Kubernetes, che decide il security posture richiesto attraverso la configurazione del workload. Infine, il **kernel** è ciò che applica realmente namespaces, cgroups, seccomp e MAC policy.

Questo modello a layer è importante per comprendere i default. Una restrizione può essere richiesta da Kubernetes, tradotta tramite CRI da containerd o CRI-O, convertita in una OCI spec dal runtime wrapper e solo successivamente applicata da `runc`, `crun`, `runsc` o da un altro runtime tramite il kernel. Quando i default differiscono tra gli ambienti, spesso è perché uno di questi layer ha modificato la configurazione finale. Lo stesso meccanismo può quindi apparire in Docker o Podman come un flag CLI, in Kubernetes come un campo Pod o `securityContext` e negli stack di runtime di livello inferiore come una configurazione OCI generata per il workload. Per questo motivo, gli esempi CLI in questa sezione devono essere letti come **sintassi specifica del runtime per un concetto generale dei container**, non come flag universali supportati da ogni tool.

## Il reale confine di sicurezza dei container

In pratica, la container security deriva da **controlli sovrapposti**, non da un singolo controllo perfetto. I namespaces isolano la visibilità. I cgroups regolano e limitano l'utilizzo delle risorse. Le capabilities riducono ciò che un processo apparentemente privilegiato può effettivamente fare. seccomp blocca le syscall pericolose prima che raggiungano il kernel. AppArmor e SELinux aggiungono il Mandatory Access Control ai normali controlli DAC. `no_new_privs`, i percorsi procfs mascherati e i percorsi di sistema in sola lettura rendono più difficili le comuni catene di privilege abuse e di abuso di proc/sys. Anche il runtime è importante, perché decide come vengono creati mount, socket, label e namespace join.

Ecco perché molta documentazione sulla container security sembra ripetitiva. La stessa catena di escape spesso dipende contemporaneamente da più meccanismi. Ad esempio, un host bind mount scrivibile è pericoloso, ma diventa molto peggiore se il container viene inoltre eseguito come vero root sull'host, dispone di `CAP_SYS_ADMIN`, è unconfined da seccomp e non è limitato da SELinux o AppArmor. Allo stesso modo, la condivisione del PID dell'host è una grave esposizione, ma diventa molto più utile per un attacker quando è combinata con `CAP_SYS_PTRACE`, protezioni procfs deboli o strumenti per l'ingresso nei namespace come `nsenter`. Il modo corretto di documentare l'argomento non consiste quindi nel ripetere lo stesso attack in ogni pagina, ma nello spiegare il contributo di ciascun layer al confine finale.

## Come leggere questa sezione

La sezione è organizzata dai concetti più generali a quelli più specifici.

Inizia dalla panoramica del runtime e dell'ecosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Passa quindi in rassegna i control plane e le supply-chain surface che spesso determinano se un attacker abbia effettivamente bisogno di un kernel escape:

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

Passa quindi al modello di protezione:

{{#ref}}
protections/
{{#endref}}

Le pagine sui namespace spiegano singolarmente le primitive di isolamento del kernel:

{{#ref}}
protections/namespaces/
{{#endref}}

Le pagine su cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, percorsi mascherati e percorsi di sistema in sola lettura spiegano i meccanismi normalmente sovrapposti ai namespace:

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

## Un buon approccio iniziale all'enumeration

Quando si valuta un target containerizzato, è molto più utile porsi un piccolo insieme di domande tecniche precise invece di passare immediatamente a famosi escape PoC. Per prima cosa, identifica lo **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer o qualcosa di più specializzato. Poi identifica il **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` o un'altra implementazione compatibile con OCI. Dopodiché, verifica se l'ambiente è **rootful o rootless**, se gli **user namespaces** sono attivi, se sono condivisi degli **host namespaces**, quali **capabilities** rimangono, se **seccomp** è abilitato, se una **MAC policy** è realmente in enforcement, se sono presenti **mount o socket pericolosi** e se il processo può interagire con la container runtime API.

Queste risposte dicono molto di più sul reale security posture rispetto al nome della base image. In molte valutazioni, è possibile prevedere la probabile famiglia di breakout prima ancora di leggere un singolo file dell'applicazione, semplicemente comprendendo la configurazione finale del container.

## Copertura

Questa sezione copre il vecchio materiale focalizzato su Docker, organizzandolo in base ai container: esposizione del runtime e del daemon, authorization plugins, image trust e build secrets, host mounts sensibili, workload distroless, container privilegiati e le protezioni del kernel normalmente applicate all'esecuzione dei container.

{{#include ../../../banners/hacktricks-training.md}}
