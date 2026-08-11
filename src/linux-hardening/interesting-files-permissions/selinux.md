# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux è un sistema di **Mandatory Access Control (MAC) basato su etichette**. In pratica, ciò significa che anche se i permessi DAC, i gruppi o le Linux capabilities sembrano sufficienti per un'azione, il kernel può comunque negarla perché il **contesto sorgente** non è autorizzato ad accedere al **contesto target** con la classe/autorizzazione richiesta.<sup>[[1]](#references)</sup>

Un contesto solitamente ha questo aspetto:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Dal punto di vista del `privesc`, il campo `type` (domain per i processi, type per gli oggetti) è solitamente il campo più importante:<sup>[[1]](#references)</sup>

- Un processo viene eseguito in un **domain** come `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- File e socket hanno un **type** come `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy decide se un domain può leggere/scrivere/eseguire/effettuare una transizione verso l'altro

## Enumerazione rapida

Se SELinux è abilitato, esegui l'enumerazione in una fase iniziale, perché può spiegare perché i comuni percorsi di privesc Linux falliscono o perché un wrapper privilegiato attorno a uno strumento SELinux "innocuo" è in realtà fondamentale:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Controlli di follow-up utili:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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

- La modalità `Disabled` o `Permissive` elimina gran parte del valore di SELinux come boundary.
- `unconfined_t` di solito indica che SELinux è presente, ma non limita in modo significativo quel processo.
- `default_t`, `file_t` o label palesemente errate sui custom paths spesso indicano un mislabeling o un deployment incompleto.
- Gli override locali in `file_contexts.local` hanno la precedenza sui default della policy, quindi devono essere esaminati attentamente.

## Analisi della policy

SELinux è molto più facile da attaccare o bypassare quando puoi rispondere a due domande:

1. **A cosa può accedere il mio dominio attuale?**
2. **In quali domini posso effettuare una transizione?**

Gli strumenti più utili per questo sono `sepolicy` e **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
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
Questo è particolarmente utile quando un host usa **confined users** invece di associare tutti a `unconfined_u`. In tal caso, cerca:<sup>[[3]](#references)</sup>

- associazioni degli utenti tramite `semanage login -l`
- ruoli consentiti tramite `semanage user -l`
- domini amministrativi raggiungibili come `sysadm_t`, `secadm_t`, `webadm_t`
- voci `sudoers` che usano `ROLE=` o `TYPE=`

Se `sudo -l` contiene voci come questa, SELinux fa parte del limite dei privilegi:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Verifica anche se `newrole` è disponibile:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` e `newrole` non sono automaticamente sfruttabili, ma se un wrapper con privilegi o una regola `sudoers` consente di selezionare un ruolo/tipo migliore, diventano primitive di escalation ad alto valore.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## File, rietichettatura e misconfigurazioni di alto valore

La differenza operativa più importante tra gli strumenti SELinux comuni è:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: modifica temporanea dell'etichetta su un percorso specifico
- `semanage fcontext`: regola persistente percorso-etichetta
- `restorecon` / `setfiles`: applicano nuovamente l'etichetta prevista dalla policy/predefinita

Questo è molto importante durante il privesc perché la **rietichettatura non è solo cosmetica**. Può trasformare un file da "bloccato dalla policy" a "leggibile/eseguibile da un servizio confinato con privilegi".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Controlla le regole locali di rietichettatura e le divergenze nelle etichette:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un dettaglio sottile ma utile: il semplice `restorecon` **non ripristina sempre completamente un'etichetta sospetta**. Se il tipo di destinazione è incluso in `customizable_types`, potrebbe essere necessario usare `-F` per forzare un ripristino completo. Dal punto di vista offensivo, questo spiega perché un `chcon` insolito può talvolta sopravvivere a una pulizia superficiale del tipo "abbiamo già eseguito restorecon".<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandi di alto valore da individuare in `sudo -l`, root wrappers, script di automazione o file capabilities:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Se compare una delle due capability MAC, controlla anche la [pagina sulle Linux capabilities](linux-capabilities.md); la documentazione sulle Linux capabilities descrive `cap_mac_admin` e `cap_mac_override` come specifiche di Smack, quindi non presumere che i loro nomi, da soli, consentano di aggirare SELinux.<sup>[[5]](#references)</sup>

Particolarmente interessanti:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: modifica in modo persistente l'etichetta che un path dovrebbe ricevere
- `restorecon` / `setfiles`: riapplica tali modifiche su larga scala
- `semodule -i`: carica un modulo di policy personalizzato
- `semanage permissive -a <domain_t>`: rende permissivo un singolo dominio senza modificare l'intero host
- `setsebool -P`: modifica permanentemente i booleani della policy
- `load_policy`: ricarica la policy attiva

Spesso sono **primitive di supporto**, non root exploit autonome. Il loro valore consiste nel permetterti di:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- rendere permissivo un dominio target
- ampliare l'accesso tra il proprio dominio e un tipo protetto
- rietichettare i file controllati dall'attacker in modo che un servizio privilegiato possa leggerli o eseguirli
- indebolire un servizio confinato quanto basta affinché un bug locale esistente diventi sfruttabile

Controlli di esempio:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
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
Ecco perché `audit2allow`, `semodule` e `semanage permissive` dovrebbero essere considerate superfici amministrative sensibili durante il post-exploitation. Possono convertire silenziosamente una catena bloccata in una funzionante senza modificare i permessi UNIX classici.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Hidden Denials and Module Extraction

Una frustrazione offensiva molto comune è una catena che fallisce con un generico `EACCES`, mentre il denial AVC previsto non compare mai. Le regole `dontaudit` potrebbero nascondere proprio il permesso necessario. Se puoi eseguire `semodule` tramite `sudo` o un altro wrapper privilegiato, disabilitare temporaneamente `dontaudit` può trasformare un errore silenzioso in un indizio preciso sulla policy:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Questo è utile anche per verificare cosa hanno già modificato gli amministratori locali. Un piccolo modulo personalizzato o una regola permissiva per un singolo dominio è spesso il motivo per cui un servizio target si comporta in modo molto più permissivo di quanto suggerirebbe la policy di base.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Indizi di audit

Le negazioni AVC sono spesso un segnale offensivo, non solo rumore difensivo. Indicano:<sup>[[1]](#references)[[15]](#references)</sup>

- quale oggetto/tipo target hai raggiunto
- quale permission è stata negata
- quale dominio controlli attualmente
- se una piccola modifica alla policy renderebbe funzionante la chain
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se un exploit locale o un tentativo di persistence continua a fallire con `EACCES` o strani errori di tipo "permission denied" nonostante permessi DAC apparentemente da root, di solito vale la pena controllare SELinux prima di scartare il vettore.<sup>[[1]](#references)</sup>

## Utenti SELinux

Oltre ai normali utenti Linux esistono anche utenti SELinux. Ogni utente Linux viene associato a un utente SELinux nell'ambito della policy, consentendo al sistema di imporre ruoli e domini autorizzati diversi per account differenti.<sup>[[3]](#references)</sup>

Controlli rapidi:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Su molti sistemi mainstream, gli utenti sono associati a `unconfined_u`, riducendo l'impatto pratico del confinamento degli utenti. Nei deployment hardened, tuttavia, gli utenti confinati possono rendere `sudo`, `su`, `newrole` e `runcon` molto più interessanti, perché **il percorso di escalation può dipendere dall'accesso a un ruolo/tipo SELinux più privilegiato, non solo dall'ottenimento dell'UID 0**. Ricorda inoltre che alcuni utenti confinati non possono invocare affatto `sudo`/`su`, a meno che la policy non consenta esplicitamente la transizione setuid sottostante; pertanto, un host che utilizza `staff_u` + `sysadm_r` può trasformare una regola apparentemente secondaria `sudo ROLE=` / `TYPE=` nel vero confine dei privilegi.<sup>[[3]](#references)</sup>

## SELinux nei container

I container runtime avviano comunemente i workload in un dominio confinato come `container_t` ed etichettano i contenuti del container come `container_file_t`. Se un processo del container evade, ma continua a essere eseguito con l'etichetta del container, le scritture sull'host potrebbero comunque fallire perché il confine delle etichette è rimasto intatto.<sup>[[1]](#references)[[17]](#references)</sup>

Esempio rapido:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La parte `c647,c780` non è decorativa. In molti deployment di container, i runtime assegnano dinamicamente categorie MCS in modo che due processi in esecuzione come `container_t` rimangano comunque separati. Se un escape porta in un namespace dell'host ma conserva il set di categorie originale, le discrepanze tra categorie possono ancora spiegare perché alcuni percorsi dell'host rimangano illeggibili o non modificabili.<sup>[[17]](#references)</sup>

Operazioni moderne sui container degne di nota:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` disattiva la separazione delle label SELinux per il container
- i bind mount con `:z` / `:Z` attivano il relabeling del percorso dell'host per l'uso condiviso/privato da parte dei container
- un relabeling esteso dei contenuti dell'host può diventare di per sé un problema di sicurezza

Questa pagina mantiene breve il contenuto sui container per evitare duplicazioni. Per i casi di abuso specifici dei container e gli esempi di runtime, consulta:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Documentazione Red Hat: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Strumenti di analisi delle policy per SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gestione degli utenti confinati e non confinati - Documentazione RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Documentazione Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Perché dovresti usare Multi-Category Security per i tuoi container Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Documentazione Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
