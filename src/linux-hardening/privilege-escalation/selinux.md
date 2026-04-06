# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux è un **controllo di accesso obbligatorio (MAC) basato su etichette**. In pratica, questo significa che anche se i permessi DAC, i gruppi o le Linux capabilities sembrano sufficienti per un'azione, il kernel può comunque negarla perché il **contesto di origine** non è autorizzato ad accedere al **contesto di destinazione** con la classe/permesso richiesto.

Un contesto di solito appare così:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Dal punto di vista della privesc, il `type` (dominio per i processi, tipo per gli oggetti) è solitamente il campo più importante:

- Un processo viene eseguito in un **dominio** come `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- File e socket hanno un **tipo** come `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy decide se un dominio può leggere/scrivere/eseguire/transitare nell'altro

## Enumerazione rapida

Se SELinux è abilitato, enumeralo presto perché può spiegare perché percorsi comuni di privesc su Linux falliscono o perché un wrapper privilegiato attorno a uno strumento SELinux "innocuo" è in realtà critico:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Controlli utili successivi:
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
Rilevamenti interessanti:

- `Disabled` o `Permissive` mode rimuovono la maggior parte del valore di SELinux come confine.
- `unconfined_t` di solito significa che SELinux è presente ma non limita in modo significativo quel processo.
- `default_t`, `file_t`, o etichette ovviamente errate su percorsi personalizzati spesso indicano mislabeling o deployment incompleto.
- Gli override locali in `file_contexts.local` hanno precedenza sui default di policy, quindi rivedili con attenzione.

## Analisi della policy

SELinux è molto più facile da attaccare o aggirare quando puoi rispondere a due domande:

1. **A cosa può accedere il dominio corrente?**
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

- mappature degli utenti tramite `semanage login -l`
- ruoli consentiti tramite `semanage user -l`
- domini amministrativi raggiungibili come `sysadm_t`, `secadm_t`, `webadm_t`
- voci di `sudoers` che usano `ROLE=` o `TYPE=`

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
`runcon` e `newrole` non sono automaticamente sfruttabili, ma se un wrapper privilegiato o una regola `sudoers` ti permette di selezionare un ruolo/tipo migliore, diventano escalation primitives di alto valore.

## File, Rietichettatura e Misconfigurazioni di alto valore

La differenza operativa più importante tra i comandi SELinux più comuni è:

- `chcon`: cambio temporaneo dell'etichetta su un percorso specifico
- `semanage fcontext`: regola persistente che associa un percorso a un'etichetta
- `restorecon` / `setfiles`: applicano nuovamente l'etichetta della policy / di default

Questo è molto rilevante durante privesc perché **la rietichettatura non è solo cosmetica**. Può trasformare un file da "bloccato dalla policy" in "leggibile/eseguibile da un servizio confinato privilegiato".

Controlla la presenza di regole locali di rietichettatura e una possibile deriva nelle etichettature:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Comandi ad alto valore da cercare in `sudo -l`, root wrappers, automation scripts o file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Particolarmente interessanti:

- `semanage fcontext`: cambia in modo persistente quale etichetta un percorso dovrebbe ricevere
- `restorecon` / `setfiles`: riapplica tali modifiche su larga scala
- `semodule -i`: carica un modulo di policy personalizzato
- `semanage permissive -a <domain_t>`: rende un dominio permissivo senza mettere l'intero host in modalità permissiva
- `setsebool -P`: cambia permanentemente i booleani della policy
- `load_policy`: ricarica la policy attiva

Spesso sono **primitive di supporto**, non exploit autonomi per ottenere root. Il loro valore è che ti permettono di:

- rendere un dominio di destinazione permissivo
- ampliare l'accesso tra il tuo dominio e un tipo protetto
- ri-etichettare i file controllati dall'attaccante in modo che un servizio privilegiato possa leggerli o eseguirli
- indebolire un servizio confinato a sufficienza da rendere sfruttabile un bug locale esistente

Controlli di esempio:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Se puoi caricare un modulo di policy come root, di solito controlli il confine di SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Per questo motivo `audit2allow`, `semodule` e `semanage permissive` dovrebbero essere trattati come superfici amministrative sensibili durante il post-exploitation. Possono convertire silenziosamente una catena bloccata in una funzionante senza modificare i permessi classici di UNIX.

## Indizi di Audit

I dinieghi AVC sono spesso segnali offensivi, non solo rumore difensivo. Ti indicano:

- quale oggetto/tipo target hai colpito
- quale permesso è stato negato
- quale dominio controlli attualmente
- se una piccola modifica alla policy renderebbe la catena funzionante
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se un exploit locale o un tentativo di persistence continua a fallire con `EACCES` o strani errori "permission denied" nonostante permessi DAC che sembrano di root, vale la pena controllare SELinux prima di scartare il vettore.

## Utenti SELinux

Esistono utenti SELinux oltre ai normali utenti Linux. Ciascun utente Linux è mappato a un utente SELinux come parte della policy, il che permette al sistema di imporre ruoli e domini consentiti differenti per i vari account.

Controlli rapidi:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Su molti sistemi mainstream, gli utenti sono mappati su `unconfined_u`, il che riduce l'impatto pratico del confinamento degli utenti. Tuttavia, in deployment più sicuri, utenti confinati possono rendere `sudo`, `su`, `newrole`, e `runcon` molto più interessanti perché **il percorso di escalation può dipendere dall'entrare in un ruolo/tipo SELinux migliore, non solo dal diventare UID 0**.

## SELinux nei container

I runtime dei container avviano comunemente i carichi di lavoro in un dominio confinato come `container_t` e etichettano il contenuto del container come `container_file_t`. Se un processo del container scappa ma continua a girare con l'etichetta del container, le scritture sull'host potrebbero comunque fallire perché il confine delle etichette è rimasto intatto.

Esempio rapido:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Operazioni moderne sui container da notare:

- `--security-opt label=disable` può effettivamente spostare il workload in un tipo relativo ai container non confinato come `spc_t`
- bind mounts con `:z` / `:Z` provocano il rilabeling del percorso host per l'uso condiviso/privato nei container
- un ampio rilabeling del contenuto dell'host può diventare un problema di sicurezza a sé stante

Questa pagina mantiene il contenuto sui container breve per evitare duplicazioni. Per i casi di abuso specifici per container e gli esempi di runtime, consulta:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Riferimenti

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
