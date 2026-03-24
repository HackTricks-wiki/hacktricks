# Panoramica sulle protezioni dei container

{{#include ../../../../banners/hacktricks-training.md}}

L'idea più importante nell'hardening dei container è che non esiste un singolo controllo chiamato "container security". Quello che la gente chiama container isolation è in realtà il risultato della collaborazione di diversi meccanismi Linux di sicurezza e di gestione delle risorse. Se la documentazione descrive solo uno di essi, i lettori tendono a sovrastimarne la robustezza. Se la documentazione elenca tutti senza spiegare come interagiscono, i lettori ottengono un catalogo di nomi ma nessun modello reale. Questa sezione cerca di evitare entrambi gli errori.

Al centro del modello ci sono **namespaces**, che isolano ciò che il workload può vedere. Forniscono al processo una vista privata o parzialmente privata dei mount del filesystem, dei PID, del networking, degli oggetti IPC, degli hostname, delle mappature user/group, dei percorsi cgroup e di alcuni clock. Ma i namespaces da soli non decidono cosa un processo è autorizzato a fare. È qui che entrano in gioco i livelli successivi.

**cgroups** governano l'uso delle risorse. Non sono principalmente un confine di isolamento nello stesso senso dei mount o dei PID namespaces, ma sono cruciali operativamente perché limitano memoria, CPU, PID, I/O e l'accesso ai device. Hanno anche rilevanza per la sicurezza perché tecniche storiche di breakout hanno abusato delle funzionalità scrivibili dei cgroup, specialmente negli ambienti con cgroup v1.

**Capabilities** suddividono il vecchio modello di root onnipotente in unità di privilegio più piccole. Questo è fondamentale per i container perché molti workload continuano a girare come UID 0 all'interno del container. La domanda quindi non è semplicemente "is the process root?", ma piuttosto "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" Per questo un processo root in un container può essere relativamente vincolato mentre un processo root in un altro container può, nella pratica, essere quasi indistinguibile dal root dell'host.

**seccomp** filtra le syscall e riduce la superficie di attacco del kernel esposta al workload. Spesso è il meccanismo che blocca chiamate ovviamente pericolose come `unshare`, `mount`, `keyctl` o altre syscall usate nelle catene di breakout. Anche se un processo possiede una capability che altrimenti permetterebbe un'operazione, seccomp può comunque bloccare il percorso della syscall prima che il kernel la processi completamente.

**AppArmor** e **SELinux** aggiungono il Mandatory Access Control oltre ai normali controlli su filesystem e privilegi. Questi sono particolarmente importanti perché continuano a fare la differenza anche quando un container ha più capabilities di quelle che dovrebbe. Un workload può possedere il privilegio teorico di tentare un'azione ma essere comunque impedito nel compierla perché la sua label o il suo profilo vietano l'accesso al percorso, all'oggetto o all'operazione rilevante.

Infine, ci sono ulteriori livelli di hardening che ricevono meno attenzione ma che contano spesso negli attacchi reali: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems e careful runtime defaults. Questi meccanismi spesso fermano la "last mile" di una compromissione, specialmente quando un attacker cerca di trasformare l'execution del codice in un guadagno di privilegi più ampio.

Il resto di questa cartella spiega ciascuno di questi meccanismi in maggiore dettaglio, incluso cosa fa effettivamente il primitivo del kernel, come osservarlo localmente, come lo utilizzano i runtime comuni e come gli operatori lo indeboliscono accidentalmente.

## Lettura successiva

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Molte fughe reali dipendono anche dal contenuto dell'host montato nel workload, quindi dopo aver letto le protezioni principali è utile proseguire con:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
