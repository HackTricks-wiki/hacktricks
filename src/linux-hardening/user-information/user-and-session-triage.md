# Utenti, sessioni e artefatti delle credenziali

{{#include ../../banners/hacktricks-training.md}}

Inizia dall'identità proprietaria della shell corrente, poi enumera gli altri utenti, i gruppi, le sessioni attive e gli archivi delle credenziali. La pagina [real, effective, and saved user ID](euid-ruid-suid.md) spiega perché i privilegi effettivi di un processo possono differire da quelli dell'account usato per il login.

## Enumerare identità e accessi basati sui gruppi

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` include account supportati da directory che una semplice lettura di `/etc/passwd` potrebbe non rilevare. Esamina gli account con UID 0, le shell di login, le home directory, i gruppi supplementari e gli account la cui configurazione consente inaspettatamente il login interattivo. La pagina [interesting groups](interesting-groups-linux-pe/README.md) tratta gli accessi delegati, ad esempio tramite `sudo`, `docker`, `disk` e `shadow`. Controlla le ACL effettive del filesystem e i criteri locali prima di considerare privilegiato un gruppo solo in base al suo nome.

Se [NSS indirizza le ricerche di `passwd`, `group` o `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) a un database, esamina il provider attivo e il relativo percorso di configurazione prima di valutare le identità gestite dal database. Nelle installazioni di PostgreSQL NSS, `/etc/nss-pgsql.conf` e `/etc/nss-pgsql-root.conf` sono solo indizi sui percorsi, poiché le impostazioni di connessione potrebbero contenere credenziali. Un ruolo del database è rilevante solo se può modificare i record effettivamente restituiti dal provider NSS attivo e un account può autenticarsi utilizzandoli. Un GID primario pari a 0 conferisce l'appartenenza al gruppo root, non UID 0; una mappatura al gruppo sudo richiede una [regola di gruppo sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) effettiva e l'eventuale autenticazione richiesta. Una mappatura a UID 0 costituisce un confine di identità distinto. Durante l'enumerazione passiva, non stampare stringhe di connessione né modificare i record degli account.

Confronta anche gli UID numerici tra i nomi degli account locali. Due nomi in [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) possono riferirsi alla stessa identità Unix del filesystem, mentre i rispettivi record di autenticazione per il login possono essere diversi. Pertanto, dopo un'autenticazione riuscita, un alias aggiunto di recente con lo stesso UID non nullo può consentire di accedere ai file o ai processi di un altro utente; non conferisce privilegi root, a meno che quell'UID o un percorso di privilegio separato non li conceda. Gli UID condivisi possono essere intenzionali. Verifica la fonte degli account (`/etc/passwd` rispetto a NSS), la cronologia della creazione, la shell e la home, i criteri di autenticazione effettivi e l'autorizzazione degli account a condividere l'identità. Un controllo dei duplicati limitato agli account locali non può escludere la presenza di un alias supportato da directory.

## Trova le sessioni attive e recenti

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Un socket `screen` o `tmux` può esporre una shell esistente se i suoi permessi consentono all'utente corrente di collegarsi. Controlla il proprietario e i permessi del socket prima di tentare l'accesso: non è automatico poter collegarsi alla sessione di un altro utente. Può essere rilevante anche un timestamp sudo attivo o un socket SSH agent, ma il loro riutilizzo dipende dall'identità dell'utente, dai permessi e dalle policy. Per l'abuso di agent forwarding, vedi [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Un [socket di controllo multiplex di OpenSSH](https://man.openbsd.org/ssh_config#ControlMaster) è separato da `SSH_AUTH_SOCK`: `ControlMaster` e `ControlPath` consentono ai client SSH successivi di condividere una connessione autenticata esistente, mentre `ControlPersist` può mantenere disponibile il master dopo la fine della prima sessione. Esamina il file `.ssh/config` dell'utente corrente e i percorsi dei socket nelle directory `.ssh` non annidate in profondità, verificandone anche il proprietario e i permessi. Il solo nome del socket non dimostra che il master sia attivo, che l'utente corrente possa connettersi o quale account remoto utilizzi.

## Esaminare gli artefatti dell'utente

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

La cronologia della shell, i file di avvio, le chiavi SSH, la configurazione delle applicazioni, i keyring GPG e le cache Kerberos possono rivelare credenziali o punti di persistence scrivibili. Un file `authorized_keys` o un file di avvio della shell scrivibile appartenente a un account con privilegi superiori merita di essere esaminato. La [pagina sul post-exploitation](../post-exploitation/README.md) tratta il trasferimento della directory home di GPG e la ricerca di credenziali; [Linux Active Directory](linux-active-directory.md) tratta il riutilizzo delle cache Kerberos e dei keytab. La [pagina su PAM](../software-information/pam-pluggable-authentication-modules.md) spiega i rischi delle policy di autenticazione.
{{#include ../../banners/hacktricks-training.md}}
