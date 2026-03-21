# Panoramica delle protezioni per i container

{{#include ../../../../banners/hacktricks-training.md}}

L'idea più importante nell'hardening dei container è che non esiste un singolo controllo chiamato "container security". Quello che viene chiamato isolamento dei container è in realtà il risultato della collaborazione di diversi meccanismi Linux di sicurezza e gestione delle risorse. Se la documentazione descrive solo uno di essi, i lettori tendono a sovrastimarne la forza. Se la documentazione elenca tutti i meccanismi senza spiegare come interagiscono, i lettori ottengono un catalogo di nomi ma nessun modello concreto. Questa sezione cerca di evitare entrambi gli errori.

Al centro del modello ci sono **namespaces**, che isolano ciò che il workload può vedere. Forniscono al processo una vista privata o parzialmente privata dei mount del filesystem, dei PID, del networking, degli oggetti IPC, degli hostname, delle mappature utente/gruppo, dei percorsi cgroup e di alcuni orologi. Ma le namespaces da sole non decidono cosa un processo è autorizzato a fare. È qui che entrano gli strati successivi.

**cgroups** governano l'uso delle risorse. Non sono principalmente un confine di isolamento nello stesso senso delle mount o delle PID namespaces, ma sono cruciali operativamente perché vincolano memoria, CPU, PID, I/O e l'accesso ai device. Hanno anche rilevanza per la sicurezza perché tecniche storiche di breakout hanno sfruttato funzionalità scrivibili dei cgroup, specialmente negli ambienti cgroup v1.

**Capabilities** suddividono il vecchio modello di root onnipotente in unità di privilegio più piccole. Questo è fondamentale per i container perché molti workload vengono ancora eseguiti come UID 0 all'interno del container. La domanda non è quindi semplicemente "is the process root?", ma piuttosto "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" Per questo un processo root in un container può essere relativamente vincolato mentre un processo root in un altro container può essere, nella pratica, quasi indistinguibile dal root dell'host.

**seccomp** filtra le syscall e riduce la superficie d'attacco del kernel esposta al workload. Spesso è il meccanismo che blocca chiamate chiaramente pericolose come `unshare`, `mount`, `keyctl` o altre syscall usate nelle catene di breakout. Anche se un processo possiede una capability che altrimenti permetterebbe un'operazione, seccomp può comunque bloccare il percorso della syscall prima che il kernel la processi completamente.

**AppArmor** e **SELinux** aggiungono Mandatory Access Control sopra i normali controlli su filesystem e privilegi. Sono particolarmente importanti perché continuano a influire anche quando un container ha più capabilities di quante dovrebbe avere. Un workload può possedere il privilegio teorico per tentare un'azione ma essere comunque impedito nell'eseguirla perché la sua etichetta o il suo profilo vietano l'accesso al percorso, all'oggetto o all'operazione rilevante.

Infine, ci sono ulteriori strati di hardening che ricevono meno attenzione ma che contano regolarmente negli attacchi reali: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems e default di runtime prudenti. Questi meccanismi spesso bloccano l'ultimo miglio di una compromissione, soprattutto quando un attaccante tenta di trasformare l'esecuzione di codice in un aumento più ampio dei privilegi.

Il resto di questa cartella spiega ciascuno di questi meccanismi in maggior dettaglio, incluso cosa fa effettivamente la primitiva del kernel, come osservarla localmente, come i runtime comuni la usano e come gli operatori la indeboliscono accidentalmente.

## Da leggere dopo

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

Molte fughe reali dipendono anche dal contenuto dell'host che è stato montato dentro il workload, quindi dopo aver letto le protezioni principali è utile continuare con:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
