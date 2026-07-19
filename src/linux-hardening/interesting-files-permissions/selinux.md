# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux è un sistema di **Mandatory Access Control (MAC) basato sulle etichette**. In pratica, ciò significa che anche se i permessi DAC, i gruppi o le Linux capabilities sembrano sufficienti per un'azione, il kernel può comunque negarla perché il **contesto sorgente** non è autorizzato ad accedere al **contesto di destinazione** con la classe/permission richiesta.

Un contesto ha solitamente questo aspetto:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Dal punto di vista del `privesc`, il campo `type` (domain per i processi, type per gli oggetti) è solitamente il più importante:

- Un processo viene eseguito in un **domain** come `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- File e socket hanno un **type** come `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy decide se un domain può leggere/scrivere/eseguire/effettuare la transizione verso l'altro

## Enumerazione rapida

Se SELinux è abilitato, esegui l'enumerazione nelle prime fasi, perché può spiegare perché i comuni percorsi di privesc su Linux falliscono o perché un wrapper privilegiato attorno a uno strumento SELinux apparentemente "innocuo" è in realtà critico:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Verifiche successive utili:
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
Risultati interessanti:

- La modalità `Disabled` o `Permissive` elimina gran parte del valore di SELinux come boundary.
- `unconfined_t` di solito significa che SELinux è presente, ma non impone vincoli significativi a quel processo.
- `default_t`, `file_t` o etichette palesemente errate sui percorsi personalizzati spesso indicano un'assegnazione errata delle etichette o un deployment incompleto.
- Gli override locali in `file_contexts.local` hanno la precedenza sui valori predefiniti della policy, quindi esaminali attentamente.

## Analisi della policy

SELinux è molto più facile da attaccare o sottoporre a bypass quando puoi rispondere a due domande:

1. **A cosa può accedere il mio dominio corrente?**
2. **In quali domini posso effettuare una transizione?**

Gli strumenti più utili per questo sono `sepolicy` e **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Questo è particolarmente utile quando un host utilizza **utenti confinati** invece di mappare tutti a `unconfined_u`. In tal caso, cerca:

- mappature degli utenti tramite `semanage login -l`
- ruoli consentiti tramite `semanage user -l`
- domini amministrativi raggiungibili come `sysadm_t`, `secadm_t`, `webadm_t`
- voci `sudoers` che utilizzano `ROLE=` o `TYPE=`

Se `sudo -l` contiene voci come questa, SELinux fa parte del limite dei privilegi:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Controlla inoltre se `newrole` è disponibile:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` e `newrole` non sono automaticamente sfruttabili, ma se un wrapper privilegiato o una regola `sudoers` consente di selezionare un ruolo/tipo migliore, diventano primitive di escalation di alto valore.

## File, Rietichettatura e Misconfigurazioni di Alto Valore

La differenza operativa più importante tra i tool comuni di SELinux è:

- `chcon`: modifica temporanea dell'etichetta su un percorso specifico
- `semanage fcontext`: regola persistente percorso-etichetta
- `restorecon` / `setfiles`: applicano nuovamente l'etichetta secondo la policy/predefinita

Questo è molto importante durante il privesc perché **la rietichettatura non è solo cosmetica**. Può trasformare un file da "bloccato dalla policy" a "leggibile/eseguibile da un servizio confinato privilegiato".

Verifica la presenza di regole di rietichettatura locali e di eventuali deviazioni nelle etichette:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un dettaglio sottile ma utile: il semplice `restorecon` **non ripristina sempre completamente un'etichetta sospetta**. Se il tipo di destinazione si trova in `customizable_types`, potrebbe essere necessario usare `-F` per forzare un ripristino completo. Dal punto di vista offensivo, questo spiega perché un `chcon` insolito può talvolta sopravvivere a una pulizia superficiale con "abbiamo già eseguito restorecon".
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandi di alto valore da cercare in `sudo -l`, wrapper root, script di automazione o capability dei file:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Se compare una delle due capability MAC, verifica anche la [pagina sulle Linux capabilities](linux-capabilities.md); `cap_mac_admin` e `cap_mac_override` sono insolite, ma direttamente rilevanti quando SELinux fa parte del confine di sicurezza.

Particolarmente interessanti:

- `semanage fcontext`: modifica in modo persistente l'etichetta che un percorso dovrebbe ricevere
- `restorecon` / `setfiles`: riapplica tali modifiche su larga scala
- `semodule -i`: carica un modulo di policy personalizzato
- `semanage permissive -a <domain_t>`: rende permissivo un solo dominio senza modificare l'intero host
- `setsebool -P`: modifica permanentemente i booleani della policy
- `load_policy`: ricarica la policy attiva

Spesso si tratta di **primitive di supporto**, non di root exploit autonomi. Il loro valore consiste nel permettere di:

- rendere permissivo un dominio target
- ampliare l'accesso tra il proprio dominio e un tipo protetto
- rietichettare file controllati dall'attaccante in modo che un servizio privilegiato possa leggerli o eseguirli
- indebolire un servizio confinato quanto basta perché un bug locale esistente diventi sfruttabile

Controlli di esempio:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Se puoi caricare un modulo di policy come root, di solito controlli il confine SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Ecco perché `audit2allow`, `semodule` e `semanage permissive` dovrebbero essere trattati come superfici amministrative sensibili durante il post-exploitation. Possono convertire silenziosamente una catena bloccata in una funzionante senza modificare i permessi UNIX classici.

## Denial nascosti ed estrazione dei moduli

Una frustrazione offensiva molto comune è una catena che fallisce con un semplice `EACCES`, mentre l'AVC denial previsto non compare mai. Le regole `dontaudit` potrebbero nascondere proprio il permesso necessario. Se puoi eseguire `semodule` tramite `sudo` o un altro wrapper privilegiato, disabilitare temporaneamente `dontaudit` può trasformare un errore silenzioso in un indizio preciso sulla policy:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Questo è utile anche per verificare cosa hanno già modificato gli amministratori locali. Un piccolo custom module o una regola permissive per un solo dominio sono spesso il motivo per cui un target service si comporta in modo molto più permissivo di quanto suggerirebbe la policy di base.

## Indizi di audit

Le negazioni AVC sono spesso un segnale offensivo, non solo rumore difensivo. Ti indicano:

- quale oggetto/tipo target hai raggiunto
- quale permission è stata negata
- quale domain controlli attualmente
- se una piccola modifica alla policy renderebbe funzionante la chain
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se un exploit locale o un tentativo di persistence continua a fallire con `EACCES` o strani errori di tipo "permission denied" nonostante permessi DAC apparentemente da root, di solito vale la pena controllare SELinux prima di scartare il vettore.

## Utenti SELinux

Oltre ai normali utenti Linux, esistono gli utenti SELinux. Ogni utente Linux viene associato a un utente SELinux come parte della policy, permettendo al sistema di imporre ruoli e domini consentiti diversi per account differenti.

Controlli rapidi:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Su molti sistemi mainstream, gli utenti sono mappati su `unconfined_u`, riducendo l'impatto pratico del confinamento degli utenti. Tuttavia, nelle implementazioni hardened, gli utenti confinati possono rendere `sudo`, `su`, `newrole` e `runcon` molto più interessanti, perché **il percorso di escalation può dipendere dall'accesso a un ruolo/tipo SELinux più privilegiato, non solo dall'ottenimento dell'UID 0**. Ricorda inoltre che alcuni utenti confinati non possono invocare `sudo`/`su` se la policy non consente esplicitamente la transizione setuid sottostante; pertanto, un host che utilizza `staff_u` + `sysadm_r` può trasformare una regola apparentemente minore `sudo ROLE=` / `TYPE=` nel vero confine dei privilegi.

## SELinux nei Container

I container runtime avviano comunemente i workload in un dominio confinato come `container_t` ed etichettano il contenuto dei container come `container_file_t`. Se un processo del container evade, ma continua a essere eseguito con l'etichetta del container, le scritture sull'host potrebbero comunque fallire perché il confine delle etichette è rimasto intatto.

Esempio rapido:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La parte `c647,c780` non è decorativa. In molte deployment di container, i runtime assegnano dinamicamente categorie MCS in modo che due processi in esecuzione come `container_t` siano comunque separati l'uno dall'altro. Se un escape porta in un namespace dell'host ma mantiene il set di categorie originale, le discrepanze tra categorie possono ancora spiegare perché alcuni path dell'host rimangono non leggibili o non scrivibili.

Operazioni moderne sui container degne di nota:

- `--security-opt label=disable` può effettivamente spostare il workload a un tipo correlato ai container non confinato, come `spc_t`
- i bind mount con `:z` / `:Z` attivano il relabeling del path dell'host per l'uso condiviso/privato dei container
- un relabeling esteso dei contenuti dell'host può diventare di per sé un problema di sicurezza

Questa pagina mantiene breve il contenuto sui container per evitare duplicazioni. Per i casi di abuso specifici dei container e gli esempi dei runtime, consulta:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Riferimenti

- [Documentazione Red Hat: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Gestione degli utenti confinati e non confinati - Documentazione RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
