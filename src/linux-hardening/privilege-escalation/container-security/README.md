# Sicurezza dei container

{{#include ../../../banners/hacktricks-training.md}}

## Cos'è realmente un container

Un modo pratico per definire un container è questo: un container è un **regular Linux process tree** avviato con una configurazione in stile OCI in modo che veda un filesystem controllato, un insieme controllato di risorse del kernel e un modello di privilegi limitato. Il processo può credere di essere PID 1, può credere di avere il proprio stack di rete, può credere di possedere il proprio hostname e le risorse IPC, e può perfino girare come root all'interno del proprio user namespace. Ma sotto il cofano è comunque un processo host che il kernel schedulea come gli altri.

Per questo la sicurezza dei container è lo studio di come quell'illusione viene costruita e di come fallisce. Se il mount namespace è debole, il processo può vedere il filesystem dell'host. Se l'user namespace è assente o disabilitato, root dentro il container può mappare troppo strettamente a root sull'host. Se seccomp non è confinato e il set di capability è troppo ampio, il processo può raggiungere syscall e funzionalità kernel privilegiate che avrebbero dovuto rimanere fuori portata. Se la socket del runtime è montata dentro il container, il container potrebbe non aver bisogno di un kernel breakout perché può semplicemente chiedere al runtime di lanciare un container fratello più potente o montare direttamente il filesystem root dell'host.

## Come i container differiscono dalle macchine virtuali

Una VM di solito porta con sé il proprio kernel e un confine di astrazione hardware. Questo significa che il kernel guest può crashare, andare in panic o essere sfruttato senza implicare automaticamente il controllo diretto del kernel host. Nei container, il workload non ottiene un kernel separato. Invece ottiene una vista accuratamente filtrata e namespacizzata dello stesso kernel che usa l'host. Di conseguenza, i container sono generalmente più leggeri, più veloci da avviare, più facili da impacchettare densamente su una macchina e più adatti a deployment di applicazioni a vita breve. Il prezzo è che il confine di isolamento dipende molto più direttamente dalla corretta configurazione dell'host e del runtime.

Questo non significa che i container siano "insicuri" e le VM "sicure". Significa che il modello di sicurezza è diverso. Uno stack di container ben configurato con esecuzione rootless, user namespaces, seccomp di default, un set di capability restrittivo, nessuna condivisione di namespace con l'host e un forte enforcement di SELinux o AppArmor può essere molto robusto. Al contrario, un container avviato con `--privileged`, con condivisione PID/rete con l'host, con la socket Docker montata dentro e con un bind mount scrivibile di `/` è funzionalmente molto più vicino all'accesso root dell'host che a un'applicazione isolata in modo sicuro. La differenza deriva dagli strati che sono stati abilitati o disabilitati.

Esiste anche un terreno intermedio che i lettori dovrebbero comprendere perché appare sempre più spesso negli ambienti reali. I runtime di container sandboxed come gVisor e Kata Containers induriscono intenzionalmente il confine oltre il classico container `runc`. gVisor inserisce un layer di kernel in userspace tra il workload e molte interfacce del kernel host, mentre Kata lancia il workload all'interno di una macchina virtuale leggera. Questi vengono comunque usati attraverso ecosistemi di container e workflow di orchestrazione, ma le loro proprietà di sicurezza differiscono dagli OCI runtime "puri" e non dovrebbero essere mentalmente raggruppati con i "normali Docker containers" come se tutto si comportasse allo stesso modo.

## Lo stack del container: diversi livelli, non uno solo

Quando qualcuno dice "questo container è insicuro", la domanda utile è: **quale livello l'ha reso insicuro?** Un workload containerizzato è di solito il risultato di più componenti che lavorano insieme.

In alto c'è spesso un **image build layer** come BuildKit, Buildah o Kaniko, che crea l'immagine OCI e i metadati. Al di sopra del runtime di basso livello, può esserci un **engine o manager** come Docker Engine, Podman, containerd, CRI-O, Incus o systemd-nspawn. Negli ambienti cluster può esserci anche un **orchestrator** come Kubernetes che decide la postura di sicurezza richiesta tramite la configurazione del workload. Infine, il **kernel** è ciò che effettivamente applica namespaces, cgroups, seccomp e le policy MAC.

Questo modello a strati è importante per capire i valori di default. Una restrizione può essere richiesta da Kubernetes, tradotta tramite CRI da containerd o CRI-O, convertita in uno spec OCI dal wrapper del runtime e solo allora applicata da `runc`, `crun`, `runsc` o un altro runtime contro il kernel. Quando i default differiscono tra ambienti, spesso è perché uno di questi livelli ha cambiato la configurazione finale. Lo stesso meccanismo può quindi apparire in Docker o Podman come un flag CLI, in Kubernetes come un campo di Pod o `securityContext`, e in stack di runtime di basso livello come configurazione OCI generata per il workload. Per questo motivo, gli esempi CLI in questa sezione vanno letti come **sintassi specifica del runtime per un concetto generale di container**, non come flag universali supportati da ogni strumento.

## Il vero confine di sicurezza del container

In pratica, la sicurezza dei container viene da **controlli sovrapposti**, non da un singolo controllo perfetto. Namespaces isolano la visibilità. cgroups governano e limitano l'uso delle risorse. Capabilities riducono ciò che un processo apparentemente privilegiato può effettivamente fare. seccomp blocca syscall pericolose prima che raggiungano il kernel. AppArmor e SELinux aggiungono Mandatory Access Control sopra i normali controlli DAC. `no_new_privs`, percorsi procfs mascherati e percorsi di sistema in sola lettura rendono più difficili comuni catene di abuso dei privilegi e di proc/sys. Anche il runtime conta perché decide come vengono creati mount, socket, label e join di namespace.

Per questo molta documentazione sulla sicurezza dei container sembra ripetitiva. La stessa catena di escape spesso dipende da meccanismi multipli contemporaneamente. Per esempio, un bind mount scrivibile dell'host è pericoloso, ma diventa molto peggiore se il container gira anche come root reale sull'host, ha `CAP_SYS_ADMIN`, non è confinato da seccomp e non è limitato da SELinux o AppArmor. Allo stesso modo, la condivisione del PID con l'host è un'esposizione seria, ma diventa molto più utile per un attaccante quando è combinata con `CAP_SYS_PTRACE`, protezioni procfs deboli o strumenti di ingresso nei namespace come `nsenter`. Il modo giusto di documentare l'argomento non è quindi ripetere lo stesso attacco in ogni pagina, ma spiegare cosa contribuisce ogni livello al confine finale.

## Come leggere questa sezione

La sezione è organizzata dai concetti più generali a quelli più specifici.

Inizia con la panoramica su runtime ed ecosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Poi rivedi i control plane e le superfici della supply-chain che frequentemente decidono se a un attacker serve o meno un kernel escape:

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

Le pagine sui namespace spiegano i primitivi di isolamento del kernel individualmente:

{{#ref}}
protections/namespaces/
{{#endref}}

Le pagine su cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, percorsi mascherati e percorsi di sistema in sola lettura spiegano i meccanismi che di solito vengono stratificati sopra i namespace:

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

## Una buona mentalità per l'enumerazione iniziale

Quando si valuta un target containerizzato, è molto più utile porsi un piccolo set di domande tecniche precise che saltare subito ai famosi PoC di escape. Prima, identifica lo **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, o qualcosa di più specializzato. Poi identifica il **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, o un'altra implementazione compatibile OCI. Dopo controlla se l'ambiente è **rootful o rootless**, se gli **user namespaces** sono attivi, se sono condivisi **host namespaces**, quali **capabilities** rimangono, se **seccomp** è abilitato, se una policy **MAC** è effettivamente in enforcement, se sono presenti **mount o socket pericolosi**, e se il processo può interagire con l'API del container runtime.

Quelle risposte dicono molto di più sulla postura di sicurezza reale di quanto farà mai il nome dell'immagine di base. In molte valutazioni puoi prevedere la famiglia di breakout probabile prima di leggere un singolo file dell'applicazione, semplicemente comprendendo la configurazione finale del container.

## Copertura

Questa sezione copre il vecchio materiale orientato a Docker sotto l'organizzazione per container: runtime e esposizione del daemon, authorization plugins, trust delle immagini e build secrets, mount sensibili dell'host, workload distroless, privileged containers e le protezioni kernel normalmente stratificate attorno all'esecuzione dei container.
{{#include ../../../banners/hacktricks-training.md}}
