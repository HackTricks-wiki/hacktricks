# Panoramica delle protezioni dei container

{{#include ../../../../banners/hacktricks-training.md}}

L'idea più importante nel hardening dei container è che non esiste un controllo unico chiamato "container security". Quello che la gente chiama isolamento dei container è in realtà il risultato della cooperazione di diversi meccanismi Linux di sicurezza e gestione delle risorse. Se la documentazione descrive solo uno di essi, i lettori tendono a sovrastimarne la robustezza. Se la documentazione elenca tutti i meccanismi senza spiegare come interagiscono, i lettori ottengono un catalogo di nomi senza un modello reale. Questa sezione cerca di evitare entrambi gli errori.

Al centro del modello ci sono **namespaces**, che isolano ciò che il carico di lavoro può vedere. Forniscono al processo una vista privata o parzialmente privata di mount del filesystem, PIDs, networking, oggetti IPC, hostname, mappature utente/gruppo, percorsi cgroup e alcuni clock. Ma i namespaces da soli non decidono cosa un processo è autorizzato a fare. È qui che entrano in gioco i livelli successivi.

**cgroups** governano l'uso delle risorse. Non sono principalmente un confine di isolamento nello stesso senso dei mount o dei PID namespaces, ma sono cruciali operativamente perché limitano memoria, CPU, PIDs, I/O e accesso ai dispositivi. Hanno anche rilevanza per la sicurezza perché tecniche storiche di breakout hanno abusato di funzionalità cgroup scrivibili, specialmente in ambienti cgroup v1.

**Capabilities** suddividono il vecchio modello di root onnipotente in unità di privilegio più piccole. Questo è fondamentale per i container perché molti carichi di lavoro continuano a girare come UID 0 all'interno del container. La domanda quindi non è semplicemente "il processo è root?", ma piuttosto "quali capabilities sono sopravvissute, dentro quali namespaces, sotto quali restrizioni seccomp e MAC?" Per questo motivo un processo root in un container può essere relativamente limitato mentre un root in un altro container può essere, nella pratica, quasi indistinguibile dal root host.

**seccomp** filtra le syscall e riduce la superficie d'attacco del kernel esposta al carico di lavoro. Questo è spesso il meccanismo che blocca chiamate ovviamente pericolose come `unshare`, `mount`, `keyctl` o altre syscall usate nelle catene di breakout. Anche se un processo dispone di una capability che altrimenti permetterebbe un'operazione, seccomp può comunque bloccare il percorso della syscall prima che il kernel lo elabori completamente.

**AppArmor** e **SELinux** aggiungono il Controllo di Accesso Obbligatorio sopra i normali controlli sul filesystem e sui privilegi. Questi sono particolarmente importanti perché continuano a influire anche quando un container ha più capabilities di quelle che dovrebbe avere. Un carico di lavoro può possedere il privilegio teorico di tentare un'azione ma essere comunque impedito nell'eseguirla perché la sua label o il suo profilo vietano l'accesso al percorso, oggetto o operazione rilevante.

Infine, ci sono ulteriori livelli di hardening che ricevono meno attenzione ma che contano regolarmente negli attacchi reali: `no_new_privs`, percorsi procfs mascherati, percorsi di sistema read-only, root filesystem in sola lettura e impostazioni runtime conservative. Questi meccanismi spesso fermano l'"ultimo miglio" di una compromissione, specialmente quando un attaccante cerca di trasformare l'esecuzione di codice in un guadagno di privilegi più ampio.

Il resto di questa cartella spiega ciascuno di questi meccanismi in maggiore dettaglio, incluso cosa fa realmente il primitivo del kernel, come osservarlo localmente, come i runtime comuni lo usano e come gli operatori lo indeboliscono accidentalmente.

## Da leggere

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

Molte fughe reali dipendono anche da quale contenuto dell'host è stato mountato nel carico di lavoro, quindi dopo aver letto le protezioni principali è utile continuare con:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
