# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux è un sistema **Mandatory Access Control (MAC) basato su etichette**. In pratica, questo significa che anche se i permessi DAC, i gruppi o le Linux capabilities sembrano sufficienti per un'azione, il kernel può comunque negarla perché il **source context** non è autorizzato ad accedere al **target context** con la classe/permesso richiesto.

Un context solitamente appare così:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Dal punto di vista del privesc, il `type` (domain per i processi, type per gli oggetti) è di solito il campo più importante:

- Un processo gira in un **domain** come `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- File e socket hanno un **type** come `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy decide se un domain può leggere, scrivere, eseguire o effettuare una transizione verso l'altro

## Enumerazione rapida

Se SELinux è abilitato, enumeralo presto perché può spiegare perché percorsi comuni di Linux privesc falliscono o perché un wrapper privilegiato intorno a uno strumento SELinux "innocuo" è in realtà critico:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Controlli successivi utili:
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
Osservazioni interessanti:

- La modalità `Disabled` o `Permissive` elimina gran parte dell'efficacia di SELinux come barriera.
- `unconfined_t` di solito significa che SELinux è presente ma non limita in modo significativo quel processo.
- `default_t`, `file_t`, o etichette chiaramente errate su percorsi personalizzati spesso indicano un'etichettatura errata o un'implementazione incompleta.
- Le sovrascritture locali in `file_contexts.local` hanno la precedenza sui valori predefiniti della policy, quindi rivedile attentamente.

## Analisi della policy

SELinux è molto più facile da attaccare o aggirare quando riesci a rispondere a due domande:

1. **A cosa può accedere il mio dominio corrente?**
2. **In quali domini posso transitare?**

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
Questo è particolarmente utile quando un host usa **utenti confinati** invece di mappare tutti su `unconfined_u`. In tal caso, cerca:

- mappature utenti tramite `semanage login -l`
- ruoli consentiti tramite `semanage user -l`
- domini admin raggiungibili come `sysadm_t`, `secadm_t`, `webadm_t`
- voci di sudoers che usano `ROLE=` o `TYPE=`

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
`runcon` e `newrole` non sono automaticamente sfruttabili, ma se un wrapper privilegiato o una regola `sudoers` ti permette di selezionare un ruolo/tipo migliore, diventano primitive per l'escalation di alto valore.

## File, Rietichettatura e Misconfigurazioni di Alto Valore

La differenza operativa più importante tra i comuni strumenti SELinux è:

- `chcon`: cambiamento temporaneo dell'etichetta su un percorso specifico
- `semanage fcontext`: regola persistente percorso->etichetta
- `restorecon` / `setfiles`: applica di nuovo la policy/etichetta di default

Questo è molto importante durante privesc perché **la rietichettatura non è solo cosmetica**. Può trasformare un file da "bloccato dalla policy" a "leggibile/eseguibile da un servizio confinato privilegiato".

Controlla regole locali di rietichettatura e deriva delle etichette:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Comandi di alto valore da cercare in `sudo -l`, root wrappers, script di automazione o file con capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Particolarmente interessanti:

- `semanage fcontext`: modifica in modo persistente quale etichetta deve ricevere un percorso
- `restorecon` / `setfiles`: riapplica tali modifiche su larga scala
- `semodule -i`: carica un modulo di policy personalizzato
- `semanage permissive -a <domain_t>`: rende permissivo un dominio senza cambiare l'intero host
- `setsebool -P`: modifica permanentemente i booleani della policy
- `load_policy`: ricarica la policy attiva

Queste sono spesso **primitive di supporto**, non exploit root autonomi. Il loro valore è che consentono di:

- rendere permissivo un dominio target
- ampliare l'accesso tra il tuo dominio e un tipo protetto
- riletichettare file controllati dall'attaccante in modo che un servizio privilegiato possa leggerli o eseguirli
- indebolire un servizio confinato a sufficienza perché un bug locale esistente diventi sfruttabile

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
È per questo che `audit2allow`, `semodule` e `semanage permissive` dovrebbero essere trattati come superfici amministrative sensibili durante la post-exploitation. Possono convertire silenziosamente una catena bloccata in una funzionante senza modificare i classici permessi UNIX.

## Indizi di Audit

Le AVC denials sono spesso un segnale offensivo, non solo rumore difensivo. Ti dicono:

- quale oggetto/tipo target hai colpito
- quale permesso è stato negato
- quale domain controlli attualmente
- se una piccola modifica alla policy renderebbe la catena funzionante
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se un exploit locale o un tentativo di persistenza continua a fallire con `EACCES` o strani errori "permission denied", nonostante permessi DAC che sembrano di root, conviene quasi sempre verificare SELinux prima di scartare il vettore.

## Utenti SELinux

Oltre ai normali utenti Linux, esistono utenti SELinux. Ogni utente Linux è mappato a un utente SELinux come parte della policy, permettendo al sistema di imporre ruoli e domini consentiti diversi sui vari account.

Controlli rapidi:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Su molti sistemi mainstream, gli utenti sono mappati su `unconfined_u`, il che riduce l'impatto pratico del confinamento degli utenti. Tuttavia, in installazioni rafforzate, gli utenti confinati possono rendere `sudo`, `su`, `newrole`, e `runcon` molto più interessanti perché **il percorso di escalation può dipendere dall'entrare in un ruolo/tipo SELinux migliore, non solo dal diventare UID 0**.

## SELinux nei container

I runtime per container comunemente avviano i workload in un dominio confinato come `container_t` e etichettano i contenuti del container come `container_file_t`. Se un processo del container evade ma continua a essere eseguito con l'etichetta del container, le scritture sull'host potrebbero comunque fallire perché il confine delle etichette è rimasto intatto.

Esempio rapido:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Operazioni moderne sui container da notare:

- `--security-opt label=disable` può effettivamente spostare il workload su un tipo correlato ai container non confinato come `spc_t`
- bind mounts con `:z` / `:Z` innescano il relabeling del percorso host per l'uso condiviso/privato del container
- un ampio relabeling del contenuto host può costituire di per sé un problema di sicurezza

Questa pagina mantiene il contenuto relativo ai container breve per evitare duplicazioni. Per i casi d'abuso specifici per i container e gli esempi runtime, consulta:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Riferimenti

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
