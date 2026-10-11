# Utenti, sessioni e artefatti delle credenziali

{{#include ../../banners/hacktricks-training.md}}

Inizia dall'identità proprietaria della shell corrente, quindi enumera gli altri utenti, i gruppi, le sessioni attive e gli archivi delle credenziali. La pagina sugli [ID utente reale, effettivo e salvato](euid-ruid-suid.md) spiega perché i privilegi effettivi di un processo possono differire dall'account usato per il login.

## Enumerare identità e accessi basati sui gruppi

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` include account supportati da directory che una semplice lettura di `/etc/passwd` potrebbe non rilevare. Esamina gli account con UID 0, le shell di login, le directory home, i gruppi supplementari e gli account la cui configurazione consente inaspettatamente il login interattivo. La pagina [interesting groups](interesting-groups-linux-pe/README.md) illustra gli accessi delegati, ad esempio `sudo`, `docker`, `disk` e `shadow`. Verifica gli ACL effettivi del filesystem e i criteri locali prima di considerare privilegiato un nome di gruppo.

Se [NSS indirizza le ricerche di `passwd`, `group` o `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) a un database, esamina il provider attivo e il relativo percorso di configurazione prima di valutare le identità gestite dal database. Nelle installazioni PostgreSQL NSS, `/etc/nss-pgsql.conf` e `/etc/nss-pgsql-root.conf` sono solo percorsi da verificare, perché le impostazioni di connessione potrebbero contenere credenziali. Un ruolo del database è rilevante solo se può modificare i record effettivamente restituiti dal provider NSS attivo e un account può autenticarsi usando tali record. Un GID primario pari a 0 comporta l'appartenenza al gruppo root, non un UID 0; una mappatura al gruppo sudo richiede una [regola sudoers per il gruppo](https://man7.org/linux/man-pages/man5/sudoers.5.html) effettiva e l'eventuale autenticazione richiesta. Una mappatura con UID 0 costituisce un confine di identità diverso. Durante l'enumerazione passiva, non stampare stringhe di connessione né modificare i record degli account.

Confronta anche gli UID numerici tra i nomi degli account locali. Due nomi in [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) possono riferirsi alla stessa identità Unix dei file, mentre i relativi record di autenticazione per il login possono differire. Dopo un'autenticazione riuscita, un alias aggiunto di recente con un UID non zero condiviso può quindi consentire l'accesso ai file o ai processi di un altro utente; non concede privilegi root, a meno che tale UID o un percorso di privilegio separato non li conceda. Gli UID condivisi possono essere intenzionali. Verifica la fonte degli account (`/etc/passwd` rispetto a NSS), la cronologia della creazione, la shell e la home, i criteri di autenticazione effettivi e se gli account sono autorizzati a condividere l'identità. Un controllo dei duplicati limitato agli account locali non può escludere un alias gestito da una directory.

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

Un socket `screen` o `tmux` può esporre una shell esistente se i suoi permessi consentono all'utente corrente di collegarsi. Controlla il proprietario e i permessi del socket prima di tentare l'accesso; non è automatico potersi collegare alla sessione di un altro utente. Anche un timestamp sudo attivo o un socket dell'agent SSH possono essere rilevanti, ma il loro riutilizzo dipende dall'identità dell'utente, dai permessi e dai criteri. Per l'abuso dell'agent forwarding, vedi [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Un [socket di controllo multiplex OpenSSH](https://man.openbsd.org/ssh_config#ControlMaster) è distinto da `SSH_AUTH_SOCK`: `ControlMaster` e `ControlPath` consentono ai successivi client SSH di condividere una connessione autenticata esistente, mentre `ControlPersist` può mantenere disponibile il master dopo la chiusura della prima sessione. Esamina il `.ssh/config` dell'utente corrente e i percorsi dei socket in `.ssh`, verificandone anche il proprietario e i permessi. Il solo nome di un socket non prova che il master sia attivo, che l'utente corrente possa connettersi o quale account remoto utilizzi.

## Esamina gli artefatti utente

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

La cronologia della shell, i file di avvio, le chiavi SSH, la configurazione delle applicazioni, i keyring GPG e le cache Kerberos possono rivelare credenziali o punti di persistenza scrivibili. È opportuno esaminare un file `authorized_keys` o un file di avvio della shell scrivibile per un account con privilegi superiori. La [pagina sul post-exploitation](../post-exploitation/README.md) tratta il trasferimento della directory home di GPG e la ricerca di credenziali; [Linux Active Directory](linux-active-directory.md) tratta il riutilizzo delle cache Kerberos e dei keytab. La [pagina PAM](../software-information/pam-pluggable-authentication-modules.md) spiega i rischi delle policy di autenticazione.
{{#include ../../banners/hacktricks-training.md}}
