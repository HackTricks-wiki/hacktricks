# Utenti, sessioni e artefatti delle credenziali

{{#include ../../banners/hacktricks-training.md}}

Inizia dall’identità proprietaria della shell corrente, quindi enumera gli altri utenti, i gruppi, le sessioni attive e gli archivi delle credenziali. La pagina [ID utente reale, effettivo e salvato](euid-ruid-suid.md) spiega perché i privilegi effettivi di un processo possono differire dall’account usato per l’accesso.

## Enumerare identità e accessi basati sui gruppi

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` include gli account basati su directory che una semplice lettura di `/etc/passwd` potrebbe non rilevare. Esamina gli account con UID 0, le shell di login, le directory home, i gruppi supplementari e gli account la cui configurazione consente inaspettatamente il login interattivo. La pagina dei [gruppi interessanti](interesting-groups-linux-pe/README.md) tratta gli accessi delegati, come `sudo`, `docker`, `disk` e `shadow`. Verifica gli ACL effettivi del filesystem e le policy locali prima di considerare privilegiato un nome di gruppo.

Se [NSS mappa le query `passwd`, `group` o `shadow](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) su un database, esamina il provider attivo e il relativo percorso di configurazione prima di valutare le identità basate su database. Nelle installazioni di PostgreSQL NSS, `/etc/nss-pgsql.conf` e `/etc/nss-pgsql-root.conf` sono indizi che forniscono solo percorsi, poiché le impostazioni di connessione potrebbero contenere credenziali. Un ruolo del database è rilevante solo se può modificare i record effettivamente restituiti dal provider NSS attivo e un account può autenticarsi usando tali record. Un GID primario pari a 0 conferisce l'appartenenza al gruppo root, non UID 0; una mappatura al gruppo sudo richiede una [regola di gruppo sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) effettiva e l'eventuale autenticazione richiesta. Una mappatura UID 0 costituisce un confine di identità diverso. Non stampare stringhe di connessione né modificare i record degli account durante l'enumerazione passiva.

Confronta inoltre gli UID numerici tra i nomi degli account locali. Due nomi in [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) possono riferirsi alla stessa identità di file Unix, mentre i relativi record di autenticazione per il login possono essere diversi. Un alias aggiunto di recente con un UID non-zero condiviso può quindi consentire l'accesso ai file o ai processi di un altro utente dopo un'autenticazione riuscita; non concede root, a meno che tale UID o un percorso di escalation dei privilegi separato non lo consenta. Gli UID condivisi possono essere intenzionali. Verifica la fonte degli account (`/etc/passwd` rispetto a NSS), la cronologia di creazione, la shell e la home, la policy di autenticazione effettiva e se gli account sono autorizzati a condividere l'identità. Un controllo dei duplicati limitato agli account locali non può escludere un alias basato su directory.

## Individuare le sessioni attive e recenti

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Un socket `screen` o `tmux` può esporre una shell esistente se i suoi permessi consentono all'utente corrente di collegarsi. Verifica il proprietario e i permessi del socket prima di tentare l'accesso; non è possibile collegarsi automaticamente alla sessione di un altro utente. Anche un timestamp sudo attivo o un socket dell'agent SSH possono essere rilevanti, ma il loro riutilizzo dipende dall'identità dell'utente, dai permessi e dalle policy. Per l'abuso dell'agent forwarding, vedi [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Un [OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) è distinto da `SSH_AUTH_SOCK`: `ControlMaster` e `ControlPath` consentono ai successivi client SSH di condividere una connessione autenticata esistente, mentre `ControlPersist` può mantenere disponibile il master dopo la chiusura della prima sessione. Esamina il file `.ssh/config` dell'utente corrente e i percorsi dei socket nella directory `.ssh`, verificandone anche il proprietario e i permessi. Il solo nome di un socket non dimostra che il master sia attivo, che l'utente corrente possa connettersi o quale account remoto venga utilizzato.

## Esamina gli artefatti utente

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

La cronologia della shell, i file di avvio, le chiavi SSH, la configurazione delle applicazioni, i keyring GPG e le cache Kerberos possono rivelare credenziali o punti di persistenza scrivibili. Un file `authorized_keys` o un file di avvio della shell scrivibile per un account con privilegi maggiori merita un controllo. La [pagina sul post-exploitation](../post-exploitation/README.md) tratta il trasferimento della directory home di GPG e la ricerca di credenziali; [Linux Active Directory](linux-active-directory.md) tratta il riutilizzo delle cache Kerberos e dei keytab. La [pagina PAM](../software-information/pam-pluggable-authentication-modules.md) illustra i rischi delle policy di autenticazione.
{{#include ../../banners/hacktricks-training.md}}
