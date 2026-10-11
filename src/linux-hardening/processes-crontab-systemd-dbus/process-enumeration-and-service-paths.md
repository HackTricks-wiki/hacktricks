# Enumerazione dei processi e percorsi dei servizi

{{#include ../../banners/hacktricks-training.md}}

La domanda utile è: quale processo privilegiato utilizza dati o codice che un utente con privilegi inferiori può influenzare? Esamina l'albero dei processi, l'ambiente attivo, i file aperti e l'unità o lo script che ha avviato ciascun candidato.

## Mappare i processi e la proprietà

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Una relazione padre-figlio tra utenti diversi può essere normale, ma una transizione inattesa richiede di esaminare il comando padre, gli argomenti, l'eseguibile, la directory di lavoro e i file a cui fa riferimento. Usa [utenti e sessioni](../user-information/user-and-session-triage.md) per interpretare il proprietario e il contesto di accesso.

### Console di macchine virtuali locali

Esamina le opzioni `-spice` di un processo QEMU insieme al suo indirizzo di ascolto. [La documentazione di QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) specifica che `disable-ticketing` consente ai client SPICE di connettersi senza autenticazione. Anche un listener associato all'indirizzo di loopback può essere raggiungibile da altri utenti locali dell'host. Verifica il listener attivo, le opzioni di autenticazione e l'accesso locale prima di considerare la riga di comando una console esposta. Il controllo della console riguarda il **guest**; ottenere un account guest o modificarne lo stato di avvio richiede condizioni separate lato guest e non conferisce privilegi root sull'host di virtualizzazione. Durante l'enumerazione passiva, leggi gli argomenti del processo e i metadati dei socket senza connetterti al guest né riavviarlo.

Un'interfaccia web accessibile localmente può eseguire codice con l'account del servizio anche quando la shell iniziale non può accedere ai file di quell'account. Ad esempio, CVE-2023-0297 riguardava la gestione di `/flash/addcrypted2` in pyLoad, quando JavaScript non attendibile raggiungeva Js2Py con le importazioni Python abilitate; la [correzione upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) ha disabilitato `pyimport`. Metti in relazione il proprietario del processo in esecuzione, l'indirizzo di ascolto, l'esposizione dell'endpoint e la patch installata o il backport del fornitore prima di considerare un processo pyLoad come una possibile via di escalation. Il nome di un processo, una porta aperta o la sola versione del pacchetto non dimostrano l'esposizione; l'enumerazione passiva non dovrebbe inviare un payload di esecuzione.

### Shell di login privilegiate che condividono un terminale

Una shell interattiva privilegiata che esegue `su --login <user>` senza uno pseudo-terminale indipendente può lasciare il terminale condiviso con la shell di login dell'utente meno privilegiato. Se il file di avvio di quell'utente è modificabile e il codice al suo interno può usare `TIOCSTI` per iniettare input nel terminale, l'input potrebbe raggiungere la shell privilegiata quando riprende l'esecuzione. [Il manuale di `su` di util-linux](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) descrive il rischio del terminale condiviso e raccomanda `su --pty`/`-P` per l'uso interattivo; `su -c` avvia una sessione separata senza un terminale di controllo. Il rischio dipende dalla shell padre effettiva, dalla relazione tra i terminali, dal file di avvio dell'utente destinatario e dalle policy del kernel. Il solo nome di un processo o l'argomento `su -l` costituisce soltanto un indizio da approfondire.

Esamina l'albero dei processi osservato e le colonne TTY, quindi il launcher leggibile e la proprietà e i permessi del file di avvio. Su Linux, `/proc/sys/dev/tty/legacy_tiocsti` può aiutare a interpretare la policy, se presente; la sua assenza non dimostra che il sistema sia sicuro. [Il manuale Linux di `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) indica che, da Linux 6.2, l'operazione può richiedere `CAP_SYS_ADMIN` quando questo sysctl è impostato su false. Non invocare l'ioctl durante la sola enumerazione dell'host.

Talvolta un account di database può modificare il file di avvio dell'utente destinatario senza disporre di accesso diretto in scrittura al filesystem. `COPY ... TO 'filename'` lato server di PostgreSQL scrive usando l'account OS del server di database, ma [PostgreSQL limita](https://www.postgresql.org/docs/current/sql-copy.html) questa forma ai superuser del database o a ruoli come `pg_write_server_files`. Verifica sia il ruolo del database sia i permessi sui file dell'OS del server; una stringa di connessione dell'applicazione, da sola, non concede l'autorizzazione a scrivere file. Valuta separatamente il launcher privilegiato e le capacità dell'account di database quando esamini la catena.

## Inspect runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Gli eseguibili eliminati e i file eliminati ma ancora aperti restano referenziati finché non viene chiuso il loro ultimo descrittore. Possono conservare prove o segreti accessibili. Gli ambienti e la memoria dei processi possono contenere credenziali, ma la lettura di un altro processo è soggetta a limitazioni basate sulla proprietà, alle opzioni di mount di `/proc`, ai criteri Yama per `ptrace` e ad altri controlli di sicurezza. Per tecniche correlate, consulta [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) e [post-exploitation credential hunting](../post-exploitation/README.md).

Le tracce delle syscall salvate sono un altro limite imposto dai permessi dei file. [`strace` registra gli argomenti delle syscall in un file di output](https://man7.org/linux/man-pages/man1/strace.1.html), quindi una traccia leggibile di argomenti [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) potrebbe esporre una password passata da un job privilegiato sulla riga di comando. Verifica innanzitutto che l'utente corrente possa leggere quella specifica traccia e che l'argomento contenga davvero una credenziale; per dimostrare che la credenziale è accettata in un successivo passaggio a un altro account Unix servono verifiche separate. I metadati dei file sono un utile indizio passivo, senza dover esaminare ogni traccia o stamparne il contenuto durante la normale enumerazione.

## Socket privilegiati per l'automazione degli uffici

LibreOffice e OpenOffice possono esporre la propria API UNO tramite un argomento `--accept=socket,host=<host>,port=<port>;urp;`. Un processo per ufficio di proprietà di root con un endpoint raggiungibile potrebbe consentire a un utente locale con privilegi inferiori di invocare servizi API nel contesto di sicurezza di quel processo. Il servizio `SystemShellExecute` include un'operazione per avviare un comando di sistema. Il binding all'interfaccia loopback limita la raggiungibilità remota, ma lascia comunque il socket accessibile agli utenti locali, a meno che un altro controllo non ne impedisca l'accesso.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Correla il proprietario del processo, l’argomento esatto `--accept` e l’indirizzo e la porta attualmente in ascolto. Un acceptor configurato che non è riuscito ad associarsi a un indirizzo è solo un indizio: durante l’enumerazione passiva, non connetterti all’API né invocarla. Evita di avviare un’istanza office con privilegi elevati solo per verificare questa condizione.

## Memoria condivisa System V utilizzata da processi con privilegi elevati

Un helper di proprietà di root può creare un segmento di memoria condivisa System V su cui un altro utente può scrivere. Se in seguito l’helper si fida dei dati di quel segmento in un comando shell o in un’altra operazione sensibile, il segmento oltrepassa un confine di privilegi, anche se l’eseguibile e i suoi file sono protetti. `shmget()` ricava i permessi di accesso dai nove bit meno significativi dei suoi flag; la modalità `0666` consente agli altri utenti di scrivere, mentre il flag `IPC_CREAT` non restringe tali permessi. Esamina passivamente i segmenti attivi con `ipcs -m` e correla il proprietario, la modalità e la durata con il processo con privilegi elevati e la gestione dei suoi input. Un segmento scrivibile da tutti, da solo, non dimostra l’esecuzione di comandi.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

I segmenti System V sono distinti dai file di memoria condivisa POSIX in `/dev/shm`. Un segmento creato solo per un istante potrebbe non comparire in una singola acquisizione di `ipcs`, quindi un output vuoto non esclude la presenza di un helper che usa la memoria condivisa. Esamina il suo codice sorgente o il comportamento del binario e qualsiasi regola `sudo` che lo avvii; non eseguire l’helper privilegiato solo per far apparire un segmento durante l’enumerazione. La [guida ai namespace IPC](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) spiega come i namespace influiscono sulla visibilità.<sup>[[2]](#references)[[3]](#references)</sup>

## Controlli script dell'agent Consul

Consul può eseguire controlli di integrità tramite script con l’identità del sistema operativo del proprio agent. Se un agent viene eseguito come root, abilita `enable_script_checks` e consente a un utente con privilegi inferiori di registrare un servizio con un controllo tramite script attraverso l’API HTTP locale, tale utente potrebbe eseguire comandi come root. Associare l’API solo a `127.0.0.1` consente comunque agli utenti locali di raggiungerla. L’impostazione `enable_local_script_checks` è più restrittiva: esclude i controlli tramite script inviati con registrazioni tramite API HTTP. Quando sono abilitate le ACL di Consul, la registrazione di un servizio richiede `service:write`; la sola presenza di una riga `acl.default_policy=allow` non dimostra che un chiamante anonimo possa registrare un servizio. Esamina insieme l’identità effettiva dell’agent, le impostazioni caricate, l’associazione dell’API e l’autorizzazione.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Segui gli argomenti `-config-dir` e `-config-file` dell'agent in esecuzione per individuare la configurazione pertinente e controlla solo i nomi e le impostazioni dei campi relativi a script check e ACL. I file di configurazione possono contenere anche chiavi o token gossip: evita di copiarli nei log condivisi. Non registrare un servizio né eseguire un health check solo per enumerare questa condizione.

Esiste un percorso distinto tramite file locali quando un utente con privilegi inferiori può **scrivere nella directory** indicata da `-config-dir` dell'agent eseguito come root e **cercarla**: da tale directory potrebbe essere caricato un nuovo service definition `.hcl` o `.json`. I permessi di ricerca e scrittura della directory possono consentire di aggiungere un file anche quando è vietato elencarne il contenuto. Per l'esecuzione di comandi come root, verifica che l'agent carichi effettivamente quella directory, che l'impostazione **effettiva** di script check consenta definizioni locali, che la definizione venga caricata e che l'agent mantenga i privilegi di root. [Consul documents](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) quali impostazioni e definizioni di health check possono essere ricaricate; l'attivazione degli script check potrebbe richiedere un riavvio, quindi verifica il comportamento della versione installata. Se gli ACL proteggono l'agent, [`consul reload` requires `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); il solo permesso di scrittura KV non lo concede. Considera i metadati di una directory scrivibile un'indicazione da verificare, non una prova di un reload, riavvio o esecuzione di comandi autorizzati. Esamina percorsi, permessi e policy senza scrivere configurazioni né chiamare l'API.

## Segui la catena di esecuzione del servizio

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Controlla l'unit, i drop-in, `EnvironmentFile=`, gli script helper, i comandi relativi, le directory scrivibili e l'attivazione dei socket. Un'unit di proprietà di root può comunque essere insicura se legge una configurazione o uno script scrivibile dall'utente. La pagina [arbitrary file write](../interesting-files-permissions/write-to-root.md) illustra i comuni percorsi di abuso di servizi e unit. Monitora i job di breve durata con [pspy](https://github.com/DominicBreuker/pspy) o con la telemetria di audit/processi quando una singola esecuzione di `ps` non li rileva.

Per un servizio **xinetd** personalizzato, correla le direttive abilitate `server`, `user` e i controlli di accesso con il listener attivo e l'eseguibile esatto. L'impostazione [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) sceglie l'identità del processo avviato, mentre un bit set-user-ID sull'eseguibile può modificarne separatamente l'identità effettiva, se [`execve` consente la transizione](https://man7.org/linux/man-pages/man2/execve.2.html). Un binario privilegiato raggiungibile che accetta input non attendibili merita una revisione offline del sorgente o del disassemblato per individuare bug di memory safety, come una conversione stringa [`scanf` senza limiti](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) in un buffer di dimensione fissa. La mappatura del servizio e i metadati set-user-ID sono indizi, non prove dell'esistenza di un bug simile; durante l'enumerazione passiva, non inviare input che causino crash né eseguire il debug del servizio privilegiato attivo.

Per un listener privilegiato personalizzato con sorgente leggibile, esamina ogni lunghezza controllata dal chiamante usata in un'operazione di copia come [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Verificare solo che l'indice di scrittura corrente rientri in un buffer fisso non dimostra che la **lunghezza di copia** sia compatibile con lo spazio rimanente; verifica `copy_length <= capacity - index` dopo aver confermato che l'indice rientri nei limiti e controlla il segno e l'overflow aritmetico. Questo è solo un indizio di revisione se l'input raggiunge quell'operazione, il listener è accessibile all'utente con privilegi inferiori e il processo mantiene un'identità effettiva più elevata. Esamina offline il sorgente e i metadati del processo; durante l'enumerazione, non inviare input che causino crash al servizio attivo.

Nei sistemi che usano **Upstart**, le definizioni dei job di sistema possono trovarsi in `/etc/init/*.conf`. Un file di job scrivibile dall'utente corrente è rilevante se il demone init attivo carica proprio quel job, la sua direttiva `script` o `exec` viene eseguita con un'identità più privilegiata e l'utente può avviarlo tramite un comando `initctl` consentito o un altro trigger reale. Un'autorizzazione sudo per `initctl`, da sola, non dimostra che un file di job sia scrivibile o che un job modificato verrà eseguito. Controlla i permessi del file di job esatto, l'impostazione effettiva dell'utente di esecuzione, il demone attivo e il trigger, senza modificare né avviare il job durante l'enumerazione. Consulta i manuali di [configurazione dei job Upstart](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) e [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Un file di password autologin leggibile, come `/etc/autologin/passwd` nei sistemi in cui il [job di boot legge proprio quel percorso](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), è un indizio di esposizione di credenziali. Verifica che il job di boot sia installato e usi il file, poi controlla separatamente se la password è valida per un altro account o servizio locale. Il solo nome del file non dimostra il riutilizzo della password; registra il percorso e i metadati di accesso senza inserire la password nell'output condiviso dell'enumerazione.

La direttiva `ExecStart=` di un'unit o un comando pianificato può rivelare il percorso esatto di uno script all'interno di una directory non elencabile. Il [permesso di ricerca della directory](https://man7.org/linux/man-pages/man7/path_resolution.7.html) può comunque consentire all'identità corrente di attraversare quel percorso noto; verifica il permesso di ricerca su ogni directory padre e il permesso di lettura sul file, invece di presumere che un elenco della directory non riuscito lo protegga. Uno script leggibile può contenere una credenziale di trasferimento, ma per accedere a un altro account è necessario che la credenziale sia ancora valida e venga accettata separatamente da quell'account. Registra il percorso e le prove relative ai permessi senza stampare valori segreti nei log condivisi.

Per uno script Node.js CommonJS pianificato, esamina gli import senza percorso esplicito come `require('package')`, anche se lo script stesso è di sola lettura. [Node cerca `node_modules` accanto al file che esegue l'import e poi nelle directory antenate](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), prima di passare ai percorsi globali configurati. Un utente con privilegi inferiori che può **scrivere e cercare** in una di quelle directory antenate potrebbe creare un package che viene trovato prima. Verifica che l'import esatto venga raggiunto, che il package selezionato non sia un modulo incorporato, che il percorso pertinente possa essere creato o modificato, che il modulo venga risolto lì dal runtime installato e che un job con privilegi superiori lo carichi in un'esecuzione futura. I metadati di una directory padre scrivibile sono solo un indizio da approfondire; esamina passivamente lo script e lo scheduler senza installare un modulo né attivare il job.

Un indice privato di package Python costituisce un altro confine di fiducia quando un job automatizzato installa package con un'identità OS diversa. Correlazione il job esatto e l'account di esecuzione con l'indice configurato, i nomi dei package selezionati e la possibilità per un utente con privilegi inferiori di pubblicare o sostituire un package che il job installerà effettivamente. La creazione di una distribuzione sorgente può eseguire il backend di build o il vecchio `setup.py` con l'identità dell'installatore; l'importazione del package installato è un percorso di esecuzione separato. Un listener dell'indice, un hash leggibile della password di upload o il solo nome di un file di package non dimostrano questa catena. Esamina il job, le autorizzazioni dell'indice e la provenienza del package senza caricare né installare nulla durante l'enumerazione. Consulta l'[interfaccia di build di pip](https://pip.pypa.io/en/stable/reference/build-system/) e le [indicazioni per installazioni sicure](https://pip.pypa.io/en/stable/topics/secure-installs/).

Un agent privilegiato può interrogare una coda di task gestita da un servizio web o container separato. Se un'identità con minore fiducia può scrivere nel database dei task del servizio, determina se quelle righe vengono effettivamente fornite all'agent e se un task di comando viene eseguito con l'identità OS dell'agent. Verifica separatamente l'accesso in scrittura al database, la sessione di destinazione o la chiave di routing, l'interrogazione attiva, l'autorizzazione del task e l'utente effettivo dell'agent. Avere root all'interno di un container non implica di per sé l'accesso come root all'host; il confine viene superato solo se un consumer con privilegi sull'host esegue dati di task controllati dall'attaccante. Esamina i metadati dei processi, del file di database e del servizio senza modificare la coda né inviare un task durante l'enumerazione.

Un job ricorrente potrebbe invece leggere un comando da una riga di configurazione in un database applicativo. Verifica che il ruolo del database con privilegi inferiori possa modificare proprio quella riga, che il job attivo la legga dopo la modifica e che il valore raggiunga una shell o un esecutore di comandi equivalente con un'identità OS più privilegiata. L'accesso in scrittura al database o un valore che sembra un comando, da soli, non dimostrano l'esecuzione; esamina il job e i permessi senza modificare la riga durante l'enumerazione passiva.

Un messaggio in coda può contenere anche un URL anziché codice. Se un consumer privilegiato recupera quell'URL e carica la risposta come plugin Lua o di altro tipo eseguibile, verifica i permessi del publisher sull'exchange e sulla routing key esatti, il binding alla coda consumata, il percorso di recupero e caricamento del plugin e l'identità effettiva del worker. [RabbitMQ instrada i messaggi pubblicati attraverso gli exchange](https://www.rabbitmq.com/docs/exchanges); un listener del broker o un login valido, da soli, non dimostrano che il messaggio venga consegnato a questo worker. Le credenziali del broker in chiaro catturate sono un indizio separato che richiede un effettivo accesso alla cattura dei pacchetti e traffico leggibile; non dimostrano l'autorizzazione alla pubblicazione. Un plugin Lua può eseguire comandi shell tramite [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) solo se quell'API è disponibile nel suo runtime. Esamina la configurazione e il codice senza catturare traffico, pubblicare messaggi o recuperare un plugin durante l'enumerazione passiva.

Quando un servizio Python privilegiato espone un endpoint HTTP o socket locale, uno script leggibile può rivelare un percorso dall'input al codice anche se i suoi permessi impediscono di modificarlo. Correlazione il processo attivo e l'identità dell'unit con lo script esatto, il listener, l'autorizzazione della route e i campi controllati dal chiamante. Segui poi quei campi attraverso il parsing e la convalida fino a un sink dinamico `eval()` o `exec()`. In particolare, costruire un nuovo f-string a partire dal testo della richiesta e valutarlo può interpretare i campi di sostituzione forniti dall'attaccante come espressioni Python ([avvertenza di Python su `eval`](https://docs.python.org/3/library/functions.html#eval); [semantica degli f-string](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). La sola presenza di `eval` o un binding a loopback non dimostrano che un chiamante non attendibile raggiunga il sink; esamina il flusso effettivo dei dati e i controlli di accesso senza inviare un payload di test durante l'enumerazione.

Un controllo delle richieste firmate su quella route richiede una revisione separata. Se il sorgente leggibile ricava la chiave di firma da uno spazio di output dimostrabilmente piccolo o prevedibile e il servizio espone un esempio valido di richiesta firmata, la firma potrebbe non proteggere più un sink `eval()` privilegiato. Verifica la derivazione esatta della chiave e il verificatore, l'identità del servizio attivo e l'accesso dei chiamanti locali, nonché se il campo firmato raggiunge il sink; la sola importazione del modulo Python [`random`](https://docs.python.org/3/library/random.html) o una firma di esempio non dimostrano nessuna di queste condizioni. Python avverte inoltre che limitare `__builtins__` [non costituisce un confine di sicurezza per input non attendibili a `eval()`](https://docs.python.org/3/library/functions.html#eval). Analizza la chiave offline e non inviare richieste contraffatte durante l'enumerazione passiva.

Una directory `/etc/systemd/system/<unit>.service.d` vuota ma scrivibile è rilevante anche quando il file dell'unit e tutti i drop-in esistenti sono protetti: l'utente può creare un nuovo override `.conf`. Verifica che la directory sia scrivibile e ricercabile dall'identità corrente, che l'unit sia caricata ed eseguita come root e se avverrà un reload del demone seguito da un riavvio del servizio. Un'autorizzazione al reload o al riavvio, un timer o un successivo avvio del sistema possono rendere effettiva la modifica; il solo accesso in scrittura alla directory non la esegue immediatamente.

Per i servizi in esecuzione, segui i percorsi letterali `EnvironmentFile=` dalla sezione `[Service]` dell'unit, compresi i file i cui nomi non iniziano con `.env`. Se un utente con privilegi bassi può leggerne uno, elenca i nomi delle chiavi simili a credenziali, come `API_TOKEN` o `APP_SECRET_KEY`, senza stampare i valori nei log condivisi. Controlla gli override dei drop-in e i prefissi `-` opzionali quando valuti l'unit effettiva. La leggibilità è un indizio di esposizione di credenziali; perché porti a un'escalation, il valore deve comunque essere valido per un'azione privilegiata.

### Elaborazione privilegiata di upload non attendibili

Un file watcher eseguito come root può passare file da una directory di upload scrivibile dall'utente a un parser o estrattore di breve durata. Segui lo script padre o il servizio del watcher in esecuzione e verifica la directory esatta, chi può inserirvi file, il comando figlio e i suoi argomenti, nonché l'identità con cui viene eseguito il figlio. Uno snapshot dei processi può mostrare il watcher ma non rilevare l'estrattore tra un upload e l'altro. Durante l'enumerazione passiva, non inserire un payload di test né attivare il watcher.

Un esempio concreto è la modalità di estrazione (`-e`) di Binwalk, che elabora dati PFS controllati dall'attaccante. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) consentiva all'estrattore PFS di scrivere al di fuori della directory prevista, incluso un percorso di plugin che Binwalk avrebbe potuto caricare in seguito. Il progetto upstream ha incluso la correzione nella versione [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), ma i backport delle distribuzioni possono mantenere una versione visualizzata più vecchia; prima di valutare la pertinenza, controlla lo stato di sicurezza del package installato, ad esempio nel [tracker Debian](https://security-tracker.debian.org/tracker/CVE-2022-4510). La sola versione installata di Binwalk non dimostra un percorso di escalation dei privilegi: l'estrazione deve essere effettivamente avviata da un processo più privilegiato su input controllabile dall'utente con privilegi inferiori.

### Build pianificate con dipendenze locali

Un `cargo run` pianificato ricompila il sorgente con l'utente di esecuzione del job. Esamina le dipendenze locali `{ path = "..." }` del manifest e i permessi del sorgente e delle directory genitrici di ciascuna dipendenza, non solo del crate principale. Se un utente con privilegi inferiori può modificare una dipendenza compilata da Cargo e il job pianificato ne esegue il risultato, il codice compilato può essere eseguito con l'identità di esecuzione del job. Verifica il comando effettivo dello scheduler, la directory di lavoro, la risoluzione delle dipendenze e se avverrà una ricompilazione; un file sorgente Rust scrivibile altrove è solo un indizio. Per un triage passivo è sufficiente leggere il manifest e i metadati dei percorsi. Consulta la [documentazione di Cargo sulle dipendenze tramite percorso](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## File framebuffer di Xvfb

`Xvfb -fbdir <directory>` usa file memory-mapped chiamati `Xvfb_screen<n>` per i suoi schermi virtuali. Se il processo Xvfb in esecuzione di un altro utente specifica una directory i cui file degli schermi sono leggibili dall'utente corrente, il framebuffer può esporre i contenuti del desktop di quell'utente. Verifica insieme il processo, la proprietà dei file e i permessi; la sola leggibilità di un file non dimostra che sullo schermo siano presenti contenuti utili. Esamina prima i percorsi e i metadati, senza copiare dati immagine nell'output condiviso dell'enumerazione. Il [manuale di Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) documenta il comportamento di `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Manuale Linux `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Manuale Linux `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Manuale OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Configurazione dell’agent Consul: controlli script](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API di registrazione dei servizi dell’agent Consul](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Configurazione ACL di Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Guida di LibreOffice: apertura di un socket per client API esterni](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [SDK di LibreOffice: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
