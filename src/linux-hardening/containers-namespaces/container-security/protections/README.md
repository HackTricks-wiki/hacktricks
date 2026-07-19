# Panoramica delle protezioni dei container

{{#include ../../../../banners/hacktricks-training.md}}

L'idea più importante nel hardening dei container è che non esiste un singolo controllo chiamato "container security". Quella che viene definita container isolation è in realtà il risultato di diversi meccanismi Linux di sicurezza e gestione delle risorse che lavorano insieme. Se la documentazione descrive solo uno di questi meccanismi, i lettori tendono a sopravvalutarne la robustezza. Se invece la documentazione li elenca tutti senza spiegare come interagiscono, i lettori ottengono un catalogo di nomi ma nessun modello reale. Questa sezione cerca di evitare entrambi gli errori.

Al centro del modello ci sono i **namespaces**, che isolano ciò che il workload può vedere. Forniscono al processo una visione privata o parzialmente privata dei filesystem mounts, dei PID, del networking, degli oggetti IPC, degli hostname, delle mappature di utenti e gruppi, dei percorsi dei cgroup e di alcuni clock. Tuttavia, i namespaces da soli non stabiliscono cosa un processo possa fare. È qui che entrano in gioco i livelli successivi.

I **cgroups** regolano l'utilizzo delle risorse. Non sono principalmente un confine di isolamento nello stesso senso dei mount o dei PID namespaces, ma sono fondamentali dal punto di vista operativo perché limitano memoria, CPU, PID, I/O e accesso ai device. Hanno anche rilevanza per la sicurezza perché tecniche storiche di breakout hanno abusato di funzionalità cgroup scrivibili, soprattutto negli ambienti cgroup v1.

Le **capabilities** dividono il vecchio modello di root onnipotente in unità di privilegio più piccole. Questo è fondamentale per i container perché molti workload continuano a essere eseguiti come UID 0 all'interno del container. La domanda quindi non è semplicemente "il processo è root?", ma piuttosto "quali capabilities sono sopravvissute, all'interno di quali namespaces e sotto quali restrizioni seccomp e MAC?" Ecco perché un processo root in un container può essere relativamente limitato, mentre un processo root in un altro container può essere, nella pratica, quasi indistinguibile da root sull'host.

**seccomp** filtra le syscall e riduce la kernel attack surface esposta al workload. Questo è spesso il meccanismo che blocca chiamate evidentemente pericolose come `unshare`, `mount`, `keyctl` o altre syscall utilizzate nelle catene di breakout. Anche se un processo possiede una capability che altrimenti consentirebbe un'operazione, seccomp può comunque bloccare il percorso della syscall prima che il kernel la elabori completamente.

**AppArmor** e **SELinux** aggiungono Mandatory Access Control ai normali controlli sul filesystem e sui privilegi. Sono particolarmente importanti perché continuano ad avere effetto anche quando un container dispone di più capabilities del dovuto. Un workload può possedere il privilegio teorico per tentare un'azione, ma può comunque essere impedito dall'eseguirla perché la sua label o il suo profile vieta l'accesso al percorso, all'oggetto o all'operazione interessati.

Infine, esistono ulteriori livelli di hardening che ricevono meno attenzione ma che contano regolarmente negli attacchi reali: `no_new_privs`, i percorsi procfs masked, i percorsi di sistema read-only, i root filesystem read-only e impostazioni predefinite del runtime configurate con attenzione. Questi meccanismi spesso bloccano il "last mile" di una compromissione, soprattutto quando un attacker cerca di trasformare la code execution in un aumento più ampio dei privilegi.

Il resto di questa cartella spiega ciascuno di questi meccanismi in maggiore dettaglio, incluso ciò che fa realmente la kernel primitive, come osservarla localmente, come i runtime comuni la utilizzano e come gli operatori la indeboliscono accidentalmente.

## Read Next

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

Molti escape reali dipendono anche dal contenuto dell'host che è stato montato nel workload, quindi, dopo aver letto le protezioni fondamentali, è utile continuare con:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
