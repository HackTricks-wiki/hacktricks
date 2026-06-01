# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux è un sistema **label-based Mandatory Access Control (MAC)**. In pratica, questo significa che anche se i permessi DAC, i gruppi o le Linux capabilities sembrano sufficienti per un'azione, il kernel può comunque negarla perché il **source context** non è autorizzato ad accedere al **target context** con la class/permission richiesta.

Un context di solito appare così:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Dal punto di vista del privesc, il `type` (domain per i processi, type per gli oggetti) è di solito il campo più importante:

- Un processo gira in un **domain** come `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- File e socket hanno un **type** come `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy decide se un domain può leggere/scrivere/eseguire/transitare verso l'altro

## Fast Enumeration

Se SELinux è abilitato, enumeralo subito perché può spiegare perché i comuni percorsi di privesc su Linux falliscono o perché un wrapper privilegiato attorno a uno strumento SELinux "innocuo" è in realtà critico:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Controlli utili di follow-up:
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
Interessanti risultati:

- `Disabled` o `Permissive` mode rimuove la maggior parte del valore di SELinux come boundary.
- `unconfined_t` di solito significa che SELinux è presente ma non sta limitando in modo significativo quel processo.
- `default_t`, `file_t`, o label chiaramente errate su percorsi custom spesso indicano mislabeling o deployment incompleto.
- Gli override locali in `file_contexts.local` hanno precedenza sui default della policy, quindi controllali con attenzione.

## Policy Analysis

SELinux è molto più facile da attaccare o bypassare quando puoi rispondere a due domande:

1. **A cosa può accedere il mio current domain?**
2. **In quali domains posso fare transition?**

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
Questo è particolarmente utile quando un host usa **confined users** invece di mappare tutti a `unconfined_u`. In quel caso, cerca:

- mapping degli utenti tramite `semanage login -l`
- ruoli consentiti tramite `semanage user -l`
- domini admin raggiungibili come `sysadm_t`, `secadm_t`, `webadm_t`
- voci `sudoers` che usano `ROLE=` o `TYPE=`

Se `sudo -l` contiene voci come questa, SELinux fa parte del confine dei privilegi:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Controlla anche se `newrole` è disponibile:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` e `newrole` non sono automaticamente explotabili, ma se un wrapper privilegiato o una regola `sudoers` ti permette di selezionare un role/type migliore, diventano primitive di escalation ad alto valore.

## Files, Relabeling, and High-Value Misconfigurations

La differenza operativa più importante tra i comuni strumenti SELinux è:

- `chcon`: cambio temporaneo del label su un path specifico
- `semanage fcontext`: regola persistente path-to-label
- `restorecon` / `setfiles`: applica di nuovo il policy/default label

Questo conta molto durante la privesc perché **il relabeling non è solo cosmetico**. Può trasformare un file da "bloccato dalla policy" a "leggibile/eseguibile da un servizio confinato privilegiato".

Controlla le regole locali di relabel e il relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un dettaglio sottile ma utile: `restorecon` semplice **non sempre ripristina completamente un'etichetta sospetta**. Se il tipo di destinazione è in `customizable_types`, potresti aver bisogno di `-F` per forzare un reset completo. Dal punto di vista offensivo, questo spiega perché un `chcon` insolito può a volte sopravvivere a una pulizia superficiale del tipo "abbiamo già eseguito `restorecon`".
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandi di alto valore da cercare in `sudo -l`, root wrappers, script di automazione o capacità dei file:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Se una delle due capability MAC compare, controlla anche la [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` e `cap_mac_override` sono insolite ma direttamente rilevanti quando SELinux fa parte del perimetro.

Particolarmente interessanti:

- `semanage fcontext`: cambia in modo persistente quale label dovrebbe ricevere un path
- `restorecon` / `setfiles`: riapplica queste modifiche su scala
- `semodule -i`: carica un modulo di policy personalizzato
- `semanage permissive -a <domain_t>`: rende permissive una domain senza cambiare l'intero host
- `setsebool -P`: cambia in modo permanente i boolean di policy
- `load_policy`: ricarica la policy attiva

Questi sono spesso **helper primitives**, non exploit root autonomi. Il loro valore è che ti permettono di:

- rendere permissive una target domain
- ampliare l'accesso tra la tua domain e un tipo protetto
- rilabeling dei file controllati dall'attaccante in modo che un servizio privilegiato possa leggerli o eseguirli
- indebolire abbastanza un servizio confinato da rendere sfruttabile un bug locale già esistente

Example checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Se puoi caricare un policy module come root, di solito controlli il confine SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Ecco perché `audit2allow`, `semodule` e `semanage permissive` dovrebbero essere trattati come superfici admin sensibili durante il post-exploitation. Possono convertire silenziosamente una catena bloccata in una funzionante senza modificare i classici permessi UNIX.

## Hidden Denials and Module Extraction

Una frustrazione offensiva molto comune è una catena che fallisce con un banale `EACCES` mentre la denial AVC prevista non compare mai. Le regole `dontaudit` potrebbero nascondere esattamente il permesso di cui hai bisogno. Se puoi eseguire `semodule` tramite `sudo` o un altro wrapper privilegiato, disabilitare temporaneamente `dontaudit` può trasformare un fallimento silenzioso in un preciso indizio di policy:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Questo è utile anche per rivedere cosa gli admin locali hanno già modificato. Un piccolo module personalizzato o una permissive rule per un solo domain è spesso il motivo per cui un target service si comporta in modo molto più permissivo di quanto suggerirebbe la base policy.

## Audit Clues

Le AVC denials sono spesso un segnale offensivo, non solo rumore difensivo. Ti dicono:

- quale target object/type hai colpito
- quale permission è stata negata
- quale domain controlli attualmente
- se una piccola modifica alla policy renderebbe la chain funzionante
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se un local exploit o un tentativo di persistence continua a fallire con `EACCES` o strani errori di "permission denied" nonostante permessi DAC apparentemente da root, SELinux di solito vale la pena controllarlo prima di scartare il vettore.

## SELinux Users

Ci sono SELinux users oltre ai normali Linux users. Ogni Linux user è mappato a un SELinux user come parte della policy, il che permette al sistema di imporre diversi roles e domains consentiti su account diversi.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Su molti sistemi mainstream, gli utenti sono mappati a `unconfined_u`, il che riduce l'impatto pratico del confinement degli utenti. Su deployment hardened, però, gli utenti confined possono rendere `sudo`, `su`, `newrole` e `runcon` molto più interessanti perché **il percorso di escalation può dipendere dall'entrare in un ruolo/tipo SELinux migliore, non solo dal diventare UID 0**. Ricorda anche che alcuni utenti confined non possono invocare `sudo`/`su` affatto a meno che la policy non consenta esplicitamente la transizione setuid sottostante, quindi un host che usa `staff_u` + `sysadm_r` può trasformare una regola apparentemente minore `sudo ROLE=` / `TYPE=` nel vero confine dei privilegi.

## SELinux in Containers

I runtime dei container avviano comunemente i workload in un domain confined come `container_t` e etichettano il contenuto del container come `container_file_t`. Se un processo del container esce ma continua a girare con il label del container, le scritture sull'host potrebbero comunque fallire perché il confine del label è rimasto intatto.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La parte `c647,c780` non è decorativa. In molte distribuzioni container, i runtime assegnano dinamicamente categorie MCS in modo che due processi in esecuzione come `container_t` siano ancora separati tra loro. Se un escape ti porta in un namespace dell'host ma mantiene il set di categorie originale, i mismatch di categoria possono ancora spiegare perché alcuni path dell'host restano illeggibili o non scrivibili.

Operazioni moderne sui container da notare:

- `--security-opt label=disable` può effettivamente spostare il workload a un tipo container-related non confinato come `spc_t`
- i bind mount con `:z` / `:Z` attivano il relabeling del path dell'host per l'uso shared/private del container
- un relabeling troppo ampio del contenuto dell'host può diventare di per sé un problema di sicurezza

Questa pagina mantiene breve il contenuto sui container per evitare duplicazioni. Per i casi di abuso specifici dei container e gli esempi dei runtime, vedi:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
