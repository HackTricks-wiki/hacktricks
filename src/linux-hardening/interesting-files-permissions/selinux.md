# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux è un sistema di **Mandatory Access Control (MAC) basato su etichette**. In pratica, ciò significa che anche se le autorizzazioni DAC, i gruppi o le Linux capabilities sembrano sufficienti per un'azione, il kernel può comunque negarla perché il **contesto sorgente** non è autorizzato ad accedere al **contesto di destinazione** con la classe/autorizzazione richiesta.<sup>[[1]](#references)</sup>

Un contesto in genere si presenta così:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Dal punto di vista del privesc, il campo `type` (domain per i processi, type per gli oggetti) è solitamente il più importante:<sup>[[1]](#references)</sup>

- Un processo viene eseguito in un **domain** come `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- File e socket hanno un **type** come `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy decide se un domain può leggere/scrivere/eseguire o effettuare una transizione verso l’altro

## Enumerazione rapida

Se SELinux è abilitato, enumeralo fin da subito: può spiegare perché i comuni percorsi di privesc su Linux non funzionano o perché un wrapper privilegiato attorno a uno strumento SELinux apparentemente "innocuo" è in realtà fondamentale:<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

Verifiche successive utili:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```

Risultati interessanti:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- La modalità `Disabled` o `Permissive` annulla gran parte del valore di SELinux come barriera.
- `unconfined_t` di solito significa che SELinux è presente, ma non limita in modo significativo quel processo.
- `default_t`, `file_t` o etichette palesemente errate sui percorsi personalizzati spesso indicano etichette non corrette o un deployment incompleto.
- Gli override locali in `file_contexts.local` hanno la precedenza sulle impostazioni predefinite dei criteri, quindi esaminali attentamente.

## Analisi dei criteri

SELinux è molto più facile da attaccare o aggirare quando sai rispondere a due domande:

1. **A cosa può accedere il mio dominio attuale?**
2. **In quali domini posso effettuare una transizione?**

Gli strumenti più utili a questo scopo sono `sepolicy` e **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>

```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```

Questo è particolarmente utile quando un host usa **utenti confinati** invece di mappare tutti su `unconfined_u`. In tal caso, cerca:<sup>[[3]](#references)</sup>

- le mappature degli utenti tramite `semanage login -l`
- i ruoli consentiti tramite `semanage user -l`
- i domini amministrativi raggiungibili, come `sysadm_t`, `secadm_t`, `webadm_t`
- le voci in `sudoers` che usano `ROLE=` o `TYPE=`

Se `sudo -l` contiene voci come questa, SELinux fa parte del confine dei privilegi:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Verifica anche se `newrole` è disponibile:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` e `newrole` non sono sfruttabili automaticamente, ma se un wrapper privilegiato o una regola `sudoers` consente di selezionare un ruolo/tipo più vantaggioso, diventano primitive di escalation di alto valore.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Verifica degli entrypoint di transizione scrivibili

Un grafo delle transizioni è solo un indizio per la policy. Per trasformarlo in un percorso di attacco, individua il tipo di eseguibile che consente di accedere a un domain più utile, poi verifica se puoi modificare un eseguibile con quell'etichetta o sostituirlo tramite la directory padre.<sup>[[9]](#references)[[20]](#references)</sup> Una transizione automatica di `execve` richiede una regola `type_transition` applicabile, l'accesso di esecuzione del domain di origine, l'accesso `entrypoint` del domain di destinazione e l'autorizzazione a effettuare la transizione tra i domain.<sup>[[20]](#references)</sup> Il domain di destinazione può ottenere accesso SELinux, ma l'esecuzione non modifica di per sé l'UID Linux; verifica separatamente [SUID/SGID e ACL](suid-sgid-and-acl-triage.md).<sup>[[20]](#references)[[21]](#references)</sup>

Usa il tipo `entrypoint` indicato per verificare le regole sottostanti, poi controlla i permessi di scrittura sul percorso e sulla directory padre.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Correla il tipo di entrypoint con un percorso eseguibile effettivo. Controlla DAC, ACL, i permessi di scrittura SELinux sul file o sulla directory padre, l'etichetta del file e qualsiasi boolean condizionale prima di considerare raggiungibile un edge della policy.<sup>[[20]](#references)[[22]](#references)</sup> Se un percorso viene sostituito anziché modificato sul posto, verifica il contesto del nuovo inode: le etichette del filesystem sono memorizzate come attributi estesi e la sostituzione potrebbe non mantenere il tipo di entrypoint.<sup>[[21]](#references)</sup> I programmi che supportano SELinux possono richiedere una transizione con `setexeccon`, quindi l'assenza di una regola automatica `type_transition` non esclude ogni transizione.<sup>[[20]](#references)</sup>

## File, rietichettatura e configurazioni errate di grande impatto

La differenza operativa più importante tra gli strumenti SELinux più comuni è:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: modifica temporanea dell'etichetta su un percorso specifico
- `semanage fcontext`: regola persistente di associazione tra percorso ed etichetta
- `restorecon` / `setfiles`: riapplicano l'etichetta della policy/predefinita

Questo è molto importante durante la privesc perché **la rietichettatura non è solo una questione estetica**. Può trasformare un file da "bloccato dalla policy" a "leggibile/eseguibile da un servizio privilegiato confinato".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Controlla la presenza di regole di rietichettatura locali e di deviazioni nelle etichette:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Un dettaglio sottile ma utile: `restorecon` semplice **non ripristina sempre completamente un'etichetta sospetta**. Se il tipo di destinazione è in `customizable_types`, potrebbe essere necessario usare `-F` per forzare un ripristino completo. Dal punto di vista offensivo, questo spiega perché un `chcon` insolito a volte può sopravvivere a una pulizia superficiale con «abbiamo già eseguito restorecon».<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Comandi di alto valore da cercare in `sudo -l`, wrapper root, script di automazione o capability dei file:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Se compare una delle due capability MAC, verifica anche la [pagina Linux capabilities](linux-capabilities.md); la documentazione Linux capabilities descrive `cap_mac_admin` e `cap_mac_override` come specifiche di Smack, quindi non presumere che i loro nomi da soli consentano di aggirare SELinux.<sup>[[5]](#references)</sup>

Particolarmente interessanti:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: modifica in modo persistente l'etichetta che dovrebbe essere assegnata a un percorso
- `restorecon` / `setfiles`: riapplica queste modifiche su larga scala
- `semodule -i`: carica un modulo di policy personalizzato
- `semanage permissive -a <domain_t>`: imposta un singolo dominio in modalità permissive senza modificare l'intero host
- `setsebool -P`: modifica in modo permanente i booleani della policy
- `load_policy`: ricarica la policy attiva

Spesso si tratta di **primitive ausiliarie**, non di exploit root autonomi. Sono utili perché permettono di:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- impostare il dominio di destinazione in modalità permissive
- ampliare l'accesso tra il tuo dominio e un tipo protetto
- rietichettare file controllati dall'attaccante, in modo che un servizio privilegiato possa leggerli o eseguirli
- indebolire un servizio confinato quanto basta perché un bug locale già esistente diventi sfruttabile

Esempi di verifiche:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Se puoi caricare un modulo di policy come root, di solito controlli il confine SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

Ecco perché `audit2allow`, `semodule` e `semanage permissive` dovrebbero essere considerati superfici amministrative sensibili durante il post-exploitation. Possono trasformare silenziosamente una catena bloccata in una funzionante senza modificare i permessi UNIX classici.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Dinieghi nascosti ed estrazione dei moduli

Una frustrazione offensiva molto comune è una catena che fallisce con un generico `EACCES`, mentre il previsto diniego AVC non compare mai. Le regole `dontaudit` potrebbero nascondere il permesso esatto di cui hai bisogno. Se puoi eseguire `semodule` tramite `sudo` o un altro wrapper con privilegi, disabilitare temporaneamente `dontaudit` può trasformare un errore silenzioso in un indizio preciso sulla policy:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Questo è utile anche per esaminare le modifiche già apportate dagli amministratori locali. Un piccolo modulo personalizzato o una regola permissiva per un singolo dominio sono spesso il motivo per cui un servizio target si comporta in modo molto più permissivo di quanto lascerebbe supporre la policy di base.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Indizi per l'audit

I dinieghi AVC sono spesso segnali utili per l'offensive, non semplice rumore difensivo. Ti indicano:<sup>[[1]](#references)[[15]](#references)</sup>

- quale oggetto/tipo target hai raggiunto
- quale permesso è stato negato
- quale dominio controlli attualmente
- se una piccola modifica alla policy renderebbe funzionante la catena

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Se un exploit locale o un tentativo di persistenza continua a fallire con `EACCES` o strani errori di «permission denied» nonostante i permessi DAC sembrino da root, di solito vale la pena controllare SELinux prima di scartare il vettore.<sup>[[1]](#references)</sup>

## Utenti SELinux

Oltre ai normali utenti Linux, esistono anche utenti SELinux. Ogni utente Linux viene associato a un utente SELinux nell'ambito della policy, consentendo al sistema di imporre ruoli e domini consentiti diversi per i vari account.<sup>[[3]](#references)</sup>

Controlli rapidi:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Su molti sistemi mainstream, gli utenti sono mappati a `unconfined_u`, il che riduce l'impatto pratico del confinamento degli utenti. Nelle distribuzioni hardened, tuttavia, gli utenti confinati possono rendere `sudo`, `su`, `newrole` e `runcon` molto più interessanti, perché **il percorso di escalation può dipendere dall'accesso a un ruolo/tipo SELinux più privilegiato, non solo dal diventare UID 0**. Ricorda inoltre che alcuni utenti confinati non possono invocare `sudo`/`su` a meno che la policy non consenta esplicitamente la transizione setuid sottostante, quindi un host che usa `staff_u` + `sysadm_r` può trasformare una regola apparentemente secondaria `sudo ROLE=` / `TYPE=` nel vero confine dei privilegi.<sup>[[3]](#references)</sup>

## SELinux nei container

I runtime dei container avviano comunemente i workload in un dominio confinato come `container_t` ed etichettano i contenuti del container come `container_file_t`. Se un processo del container evade ma continua a essere eseguito con l'etichetta del container, le scritture sull'host potrebbero comunque non riuscire perché il confine delle etichette è rimasto intatto.<sup>[[1]](#references)[[17]](#references)</sup>

Esempio rapido:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

La parte `c647,c780` non è decorativa. In molte distribuzioni di container, i runtime assegnano dinamicamente categorie MCS, così che due processi in esecuzione come `container_t` rimangano comunque separati. Se un escape ti porta in un namespace host ma mantiene il set di categorie originale, le incompatibilità tra categorie possono comunque spiegare perché alcuni percorsi host restano non leggibili o non scrivibili.<sup>[[17]](#references)</sup>

Operazioni moderne sui container da tenere presenti:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` disattiva la separazione delle etichette SELinux per il container
- i bind mount con `:z` / `:Z` attivano la rietichettatura del percorso host per l'uso condiviso o privato da parte del container
- la rietichettatura estesa dei contenuti host può diventare di per sé un problema di sicurezza

Questa pagina mantiene breve la parte sui container per evitare duplicazioni. Per i casi di abuso specifici dei container e gli esempi sui runtime, consulta:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Documentazione Red Hat: Uso di SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Strumenti di analisi delle policy per SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gestione degli utenti confinati e non confinati - Documentazione RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - pagina del manuale Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - pagina del manuale Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - pagina del manuale Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - pagina del manuale Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - pagina del manuale Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Documentazione di Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Perché dovresti usare Multi-Category Security per i tuoi container Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Documentazione di Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [Quaderno SELinux: transizioni di domini e oggetti](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: Uso di SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [Manuale di SETools sesearch(1)](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
