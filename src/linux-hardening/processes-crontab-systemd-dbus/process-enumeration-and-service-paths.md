# Enumerazione dei processi e percorsi dei servizi

{{#include ../../banners/hacktricks-training.md}}

La domanda utile è quale processo con privilegi elevati consuma dati o codice che un utente con privilegi inferiori può influenzare. Esamina l'albero dei processi, l'ambiente attivo, i file aperti e l'unità o lo script che ha avviato ciascun candidato.

## Mappare i processi e la proprietà

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Una relazione padre-figlio tra utenti diversi può essere normale, ma una transizione inattesa richiede di esaminare il comando padre, gli argomenti, l'eseguibile, la directory di lavoro e i file citati. Usa [users and sessions](../user-information/user-and-session-triage.md) per interpretare il proprietario e il contesto di login.

### Console di macchine virtuali locali

Esamina le opzioni `-spice` di un processo QEMU insieme al suo indirizzo di ascolto. [La documentazione di QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) specifica che `disable-ticketing` consente ai client SPICE di connettersi senza autenticazione. Un listener associato a loopback può comunque essere raggiungibile da altri utenti locali dell'host. Verifica il listener attivo, le opzioni di autenticazione e l'accesso locale prima di considerare la riga di comando una console esposta. Il controllo della console riguarda il **guest**; ottenere un account guest o modificarne lo stato di avvio richiede condizioni separate all'interno del guest e non conferisce i privilegi root sull'host di virtualizzazione. Durante l'enumerazione passiva, leggi gli argomenti del processo e i metadati dei socket senza connetterti al guest né riavviarlo.

Un'interfaccia web raggiungibile localmente può eseguire codice con l'account del servizio anche quando la shell iniziale non può accedere ai file di tale account. Per esempio, CVE-2023-0297 riguardava la gestione di `/flash/addcrypted2` in pyLoad, quando JavaScript non attendibile raggiungeva Js2Py con le importazioni Python abilitate; la [correzione upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) ha disabilitato `pyimport`. Prima di considerare un processo pyLoad una possibile via di escalation, correla il proprietario del processo in esecuzione, l'indirizzo di ascolto, l'esposizione dell'endpoint e la patch installata o il backport del vendor. Il nome di un processo, una porta aperta o la sola versione del pacchetto non dimostrano l'esposizione; l'enumerazione passiva non dovrebbe inviare un payload di esecuzione.

### Shell di login privilegiate che condividono un terminale

Una shell interattiva privilegiata che esegue `su --login <user>` senza uno pseudo-terminale indipendente può lasciare il proprio terminale condiviso con la shell di login dell'utente meno privilegiato. Se il file di avvio di quell'utente è controllabile e il codice in esso contenuto può usare `TIOCSTI` per iniettare input nel terminale, l'input potrebbe raggiungere la shell privilegiata quando questa riprende l'esecuzione. [Il manuale di util-linux per `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) descrive il rischio del terminale condiviso e raccomanda `su --pty`/`-P` per l'uso interattivo; `su -c` avvia una sessione separata senza un terminale di controllo. Il rischio dipende dalla shell padre effettiva, dalla relazione con il terminale, dal file di avvio dell'utente target e dai criteri del kernel. Il solo nome del processo o l'argomento `su -l` costituiscono soltanto un indizio da approfondire.

Esamina l'albero dei processi osservato e le colonne TTY, quindi controlla il launcher leggibile e la proprietà e i permessi del file di avvio. Su Linux, `/proc/sys/dev/tty/legacy_tiocsti`, se presente, può aiutare a interpretare i criteri; la sua assenza non dimostra che il sistema sia sicuro. [Il manuale Linux di `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) segnala che, da Linux 6.2, l'operazione può richiedere `CAP_SYS_ADMIN` quando questo sysctl è impostato su false. Non invocare l'ioctl per la sola enumerazione dell'host.

A volte un account database può modificare il file di avvio dell'utente target senza disporre dell'accesso diretto in scrittura al filesystem. Il comando lato server di PostgreSQL `COPY ... TO 'filename'` scrive con l'account OS del server database, ma [PostgreSQL limita](https://www.postgresql.org/docs/current/sql-copy.html) questa forma di file ai superuser del database o a ruoli come `pg_write_server_files`. Verifica sia il ruolo del database sia i permessi sui file dell'OS del server; una stringa di connessione dell'applicazione, da sola, non concede l'autorizzazione a scrivere file. Valuta separatamente il launcher privilegiato e le capacità dell'account database quando analizzi la catena.

## Esamina gli artefatti di runtime

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Gli eseguibili eliminati e i file eliminati ma ancora aperti restano referenziati finché non viene chiuso il loro ultimo descrittore. Possono conservare prove o segreti accessibili. Gli ambienti e la memoria dei processi possono contenere credenziali, ma leggere un altro processo è soggetto a limitazioni basate sulla proprietà, sulle opzioni di mount di `/proc`, sulle policy ptrace di Yama e su altri controlli di sicurezza. Per tecniche correlate, consulta [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) e [post-exploitation credential hunting](../post-exploitation/README.md).

Le tracce syscall salvate costituiscono un altro limite imposto dai permessi dei file. [`strace` registra gli argomenti delle syscall in un file di output](https://man7.org/linux/man-pages/man1/strace.1.html), quindi una traccia leggibile degli [argomenti di `execve`](https://man7.org/linux/man-pages/man2/execve.2.html) potrebbe rivelare una password che un job privilegiato ha passato sulla riga di comando. Per prima cosa verifica che l'utente corrente possa leggere la traccia specifica e che l'argomento contenga davvero una credenziale; un successivo passaggio a un account Unix richiede una verifica separata che la credenziale sia accettata da quell'account. I metadati dei file sono un indizio passivo utile, senza dover esaminare ogni traccia o stamparne il contenuto durante la normale enumerazione.

## Socket di automazione per ufficio privilegiati

LibreOffice e OpenOffice possono esporre la loro API UNO tramite un argomento `--accept=socket,host=<host>,port=<port>;urp;`. Un processo office di proprietà di root con un endpoint raggiungibile potrebbe consentire a un utente locale con privilegi inferiori di invocare servizi API nel contesto di sicurezza di quel processo. Il servizio `SystemShellExecute` include un'operazione per l'avvio di un comando di sistema. Il binding su loopback limita la raggiungibilità remota, ma lascia comunque il socket raggiungibile dagli utenti locali, a meno che un altro controllo non ne impedisca l'accesso.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Correla il proprietario del processo, l’argomento esatto `--accept` e l’indirizzo e la porta attualmente in ascolto. Un acceptor configurato che non è riuscito a eseguire il bind è solo un indizio; durante l’enumerazione passiva, non connetterti all’API né invocarla. Evita di avviare un’istanza office con privilegi elevati solo per verificare questa condizione.

## Memoria condivisa System V utilizzata da processi privilegiati

Un helper di proprietà di root può creare un segmento di memoria condivisa System V scrivibile da un altro utente. Se in seguito l’helper si fida dei dati di quel segmento in un comando shell o in un’altra operazione sensibile, il segmento attraversa un confine di privilegi, anche se l’eseguibile e i relativi file sono protetti. `shmget()` ricava i permessi di accesso dai nove bit meno significativi dei flag; la modalità `0666` consente agli altri utenti di scrivere, mentre un flag `IPC_CREAT` non limita tali permessi. Esamina passivamente i segmenti attivi con `ipcs -m` e confronta proprietario, modalità e durata con il processo privilegiato e la gestione dei suoi input. Un segmento scrivibile da tutti, da solo, non dimostra l’esecuzione di comandi.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

I segmenti System V sono distinti dai file di memoria condivisa POSIX in `/dev/shm`. Un segmento creato solo per un istante potrebbe non comparire in un singolo snapshot di `ipcs`, quindi un output vuoto non esclude la presenza di un helper che usa la memoria condivisa. Esamina il comportamento del suo codice sorgente o del binario e qualsiasi regola `sudo` che lo avvii; non eseguire l’helper privilegiato solo per far comparire un segmento durante l’enumerazione. La [guida ai namespace IPC](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) spiega in che modo i namespace influiscono sulla visibilità.<sup>[[2]](#references)[[3]](#references)</sup>

## Controlli script dell’agent Consul

Consul può eseguire controlli di integrità tramite script con l’identità del sistema operativo del proprio agent. Se un agent viene eseguito come root, abilita `enable_script_checks` e consente a un utente con privilegi inferiori di registrare un servizio con un controllo script tramite l’API HTTP locale, tale utente potrebbe causare l’esecuzione di comandi come root. Associare l’API solo a `127.0.0.1` consente comunque agli utenti locali di raggiungerla. L’impostazione `enable_local_script_checks` è più restrittiva: esclude i controlli script inviati tramite registrazioni all’API HTTP. Quando sono abilitate le ACL di Consul, la registrazione dei servizi richiede `service:write`; una riga `acl.default_policy=allow`, da sola, non dimostra che un chiamante anonimo possa registrare un servizio. Esamina insieme l’identità effettiva dell’agent, le impostazioni caricate, l’associazione dell’API e le autorizzazioni.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Segui gli argomenti `-config-dir` e `-config-file` dell'agent in esecuzione per individuare la configurazione pertinente e ispeziona solo i nomi e le impostazioni dei campi relativi a script-check e ACL. I file di configurazione possono contenere anche chiavi o token gossip: evita di riportarli nei log condivisi. Non registrare un servizio né eseguire un health check soltanto per enumerare questa condizione.

Esiste un percorso separato tramite file locale quando un utente con privilegi inferiori può **scrivere nella directory indicata da `-config-dir` di un agent eseguito come root e cercarvi**: da tale directory potrebbe essere caricata una nuova definizione di servizio `.hcl` o `.json`. I permessi di ricerca e scrittura sulla directory possono consentire di aggiungere un file anche quando non è possibile elencarne il contenuto. Per l'esecuzione di comandi come root, verifica che l'agent carichi effettivamente quella directory, che l'impostazione **effettiva** di script-check consenta definizioni locali, che la definizione venga caricata e che l'agent mantenga i privilegi di root. La [documentazione di Consul](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) specifica quali impostazioni e definizioni di health check possono essere ricaricate; per abilitare gli script check potrebbe essere necessario riavviare l'agent, quindi verifica il comportamento della versione installata. Quando le ACL proteggono l'agent, [`consul reload` richiede `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); i soli permessi di scrittura KV non lo forniscono. Considera i metadati di una directory scrivibile un indizio da approfondire, non la prova di un reload autorizzato, di un riavvio o dell'esecuzione di comandi. Esamina percorsi, permessi e policy senza scrivere configurazioni né chiamare l'API.

## Segui la catena di esecuzione del servizio

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Controlla l’unità, i drop-in, `EnvironmentFile=`, gli script helper, i comandi relativi, le directory scrivibili e l’attivazione dei socket. Un’unità di proprietà di root può comunque essere insicura se legge un file di configurazione o uno script scrivibile da un utente. La pagina [arbitrary file write](../interesting-files-permissions/write-to-root.md) illustra i percorsi comuni di abuso di servizi e unità. Monitora i job di breve durata con [pspy](https://github.com/DominicBreuker/pspy) o con telemetria di audit/processo, quando un’unica istantanea di `ps` non li rileva.

Per un servizio **xinetd** personalizzato, confronta i campi `server`, `user` e i controlli di accesso della sezione abilitata con il listener attivo e l’eseguibile esatto. L’impostazione [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) seleziona l’identità del processo avviato, mentre un bit set-user-ID sull’eseguibile può modificarne separatamente l’identità effettiva se [`execve` consente la transizione](https://man7.org/linux/man-pages/man2/execve.2.html). Un binario privilegiato raggiungibile che accetta input non attendibili merita un’analisi offline del sorgente o del disassemblato alla ricerca di bug di memory safety, come una conversione di stringa [`scanf` non limitata](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) in un buffer di dimensione fissa. La mappatura del servizio e i metadati set-user-ID sono indizi, non prove della presenza di un bug; durante l’enumerazione passiva non inviare input che causino crash né eseguire il debug del servizio privilegiato attivo.

Per un listener privilegiato personalizzato con sorgente leggibile, esamina ogni lunghezza controllata dal chiamante usata da un’operazione di copia come [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Verificare soltanto che l’indice di scrittura corrente sia entro i limiti di un buffer fisso non dimostra che la **lunghezza della copia** rientri nello spazio residuo; dopo aver confermato che l’indice sia nell’intervallo valido, verifica `copy_length <= capacity - index` e controlla segno e overflow aritmetico. Questo è un indizio da approfondire solo se l’input raggiunge quell’operazione, il listener è accessibile all’utente con privilegi inferiori e il processo mantiene un’identità effettiva superiore. Esamina offline il sorgente e i metadati del processo; durante l’enumerazione non inviare input che causino crash al servizio attivo.

Nei sistemi che usano **Upstart**, le definizioni dei job di sistema possono trovarsi in `/etc/init/*.conf`. Un file di job scrivibile dall’utente corrente è rilevante se il demone init attivo carica proprio quel job, la sua sezione `script` o `exec` viene eseguita con un’identità più privilegiata e l’utente può avviarlo tramite un comando `initctl` consentito o un altro trigger effettivo. Il solo fatto che sudo consenta `initctl` non dimostra che un file di job sia scrivibile o che un job modificato verrà eseguito. Durante l’enumerazione, verifica i permessi del file di job esatto, l’impostazione effettiva dell’identità di esecuzione, il demone attivo e il trigger, senza modificare o avviare il job. Consulta i manuali di [configurazione dei job Upstart](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) e [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Un file di password per l’autologin leggibile, come `/etc/autologin/passwd` nei sistemi in cui il [job di avvio legge proprio quel percorso](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), è un indizio di esposizione di credenziali. Verifica che il job di avvio sia installato e usi il file, poi controlla separatamente se la password è valida per un altro account o servizio locale. Il solo nome del file non dimostra il riutilizzo della password; registra percorso e metadati di accesso senza inserire la password nell’output di enumerazione condiviso.

La voce `ExecStart=` di un’unità o un comando pianificato può rivelare il percorso esatto di uno script in una directory non elencabile. [Il permesso di ricerca di una directory](https://man7.org/linux/man-pages/man7/path_resolution.7.html) può comunque consentire all’identità corrente di attraversare quel percorso noto; verifica il permesso di ricerca su ogni directory padre e il permesso di lettura sul file, invece di presumere che l’impossibilità di elencare la directory lo protegga. Uno script leggibile può contenere una credenziale di trasferimento, ma l’accesso a un altro account richiede che la credenziale sia ancora valida e venga accettata separatamente. Registra il percorso e le prove relative ai permessi senza stampare valori segreti nei log condivisi.

Per uno script CommonJS Node.js pianificato, esamina gli import non relativi come `require('package')` anche se lo script stesso è di sola lettura. [Node cerca `node_modules` accanto al file che importa il modulo e poi nelle directory antenate](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), prima di ricorrere ai percorsi globali configurati. Un utente con privilegi inferiori che può **scrivere e cercare** in una di quelle directory antenate potrebbe riuscire a creare un pacchetto che ha precedenza nella risoluzione. Verifica che l’import esatto venga raggiunto, che il pacchetto selezionato non sia un modulo integrato, che il percorso pertinente possa essere creato o modificato, che il modulo venga risolto lì nel runtime installato e che un job con privilegi superiori lo carichi a una futura esecuzione. I metadati di una directory padre scrivibile sono solo un indizio da approfondire; esamina passivamente lo script e lo scheduler senza installare un modulo né attivare il job.

Un indice di pacchetti Python privato è un altro confine di fiducia quando un job automatizzato installa pacchetti con un’identità OS diversa. Confronta il job esatto e l’account con cui viene eseguito con l’indice configurato, i nomi dei pacchetti selezionati e la possibilità che un utente con privilegi inferiori pubblichi o sostituisca un pacchetto che il job installerà davvero. La compilazione di una distribuzione sorgente può eseguire il backend di build o il `setup.py` legacy con l’identità dell’installer; l’importazione del pacchetto installato è un percorso di esecuzione distinto. Un listener dell’indice, un hash di password di upload leggibile o il solo nome di un pacchetto non dimostrano l’esistenza di questa catena. Esamina il job, le autorizzazioni dell’indice e la provenienza del pacchetto senza caricare né installare nulla durante l’enumerazione. Consulta la [documentazione dell’interfaccia di build di pip](https://pip.pypa.io/en/stable/reference/build-system/) e le [indicazioni per installazioni sicure](https://pip.pypa.io/en/stable/topics/secure-installs/).

Un agente privilegiato potrebbe interrogare periodicamente una coda di task gestita da un servizio web o un container separato. Se un’identità con minore livello di fiducia può scrivere nel database dei task del servizio, determina se quelle righe vengono effettivamente servite all’agente e se un task di tipo command viene eseguito con l’identità OS dell’agente. Verifica separatamente l’accesso in scrittura al database, la sessione target o la chiave di routing, l’interrogazione attiva, l’autorizzazione dei task e l’utente effettivo dell’agente. Essere root all’interno di un container non implica di per sé l’accesso come root all’host; il confine viene superato solo se un consumer privilegiato sull’host esegue dati di task controllati dall’attaccante. Esamina i metadati di processi, file di database e servizi senza modificare la coda né inviare task durante l’enumerazione.

Un job ricorrente potrebbe invece leggere un comando da una riga di configurazione di un database applicativo. Verifica che il ruolo database con privilegi inferiori possa modificare proprio quella riga, che il job attivo la legga dopo la modifica e che il valore raggiunga una shell o un esecutore di comandi equivalente con un’identità OS superiore. L’accesso in scrittura al database o un valore che sembra un comando non dimostrano da soli l’esecuzione; esamina il job e i permessi senza modificare la riga durante l’enumerazione passiva.

Un messaggio in coda può contenere un URL invece del codice. Se un consumer privilegiato recupera quell’URL e carica la risposta come plugin Lua o altro plugin eseguibile, verifica i permessi del publisher sull’exchange e sulla routing key esatti, il binding alla coda consumata, il percorso di recupero e caricamento del plugin e l’identità effettiva del worker. [RabbitMQ instrada i messaggi pubblicati attraverso gli exchange](https://www.rabbitmq.com/docs/exchanges); un listener del broker o un login valido non dimostrano da soli che il messaggio venga consegnato a questo worker. Le credenziali del broker in chiaro intercettate sono un indizio distinto che richiede l’effettivo accesso alla cattura dei pacchetti e a traffico leggibile; non dimostrano l’autorizzazione alla pubblicazione. Un plugin Lua può invocare comandi shell tramite [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) solo se questa API è disponibile nel suo runtime. Esamina configurazione e codice senza intercettare traffico, pubblicare messaggi o recuperare plugin durante l’enumerazione passiva.

Quando un servizio Python privilegiato espone un endpoint HTTP locale o un socket, uno script leggibile può rivelare un percorso dall’input al codice anche se i permessi del file ne impediscono la modifica. Confronta il processo attivo e l’identità dell’unità con lo script esatto, il listener, l’autorizzazione della route e i campi controllabili dal chiamante. Poi segui questi campi attraverso parsing e validazione fino a un sink dinamico `eval()` o `exec()`. In particolare, costruire una nuova f-string a partire dal testo di una richiesta e valutarla può interpretare i campi di sostituzione forniti dall’attaccante come espressioni Python (avvertenza Python su [`eval`](https://docs.python.org/3/library/functions.html#eval); [semantica delle f-string](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). La semplice presenza di `eval` o il binding a loopback non dimostrano che un chiamante non attendibile raggiunga il sink; esamina il flusso effettivo dei dati e i controlli di accesso senza inviare un payload di prova durante l’enumerazione.

Un controllo delle richieste firmate su quella route richiede un’analisi a sé. Se il sorgente leggibile ricava la chiave di firma da uno spazio di output dimostrabilmente piccolo o prevedibile e il servizio espone un esempio valido firmato, la firma potrebbe non proteggere più un sink `eval()` privilegiato. Verifica l’esatta derivazione della chiave e il verificatore, l’identità del servizio attivo e l’accesso dei chiamanti locali, nonché se il campo firmato raggiunge il sink; la semplice importazione del modulo Python [`random`](https://docs.python.org/3/library/random.html) o la presenza di una firma di esempio non dimostrano nessuna di queste condizioni. Python avverte inoltre che limitare `__builtins__` [non costituisce un confine di sicurezza per input non attendibili a `eval()`](https://docs.python.org/3/library/functions.html#eval). Analizza la chiave offline e non inviare richieste contraffatte durante l’enumerazione passiva.

Una directory `/etc/systemd/system/<unit>.service.d` vuota ma scrivibile è rilevante anche se il file dell’unità e tutti i drop-in esistenti sono protetti: l’utente potrebbe creare un nuovo override `.conf`. Verifica che l’identità corrente possa scrivere e cercare nella directory, che l’unità sia caricata e venga eseguita come root, e che sia previsto un reload del daemon seguito da un riavvio. Un permesso di reload o riavvio, un timer o un successivo avvio del sistema possono rendere effettiva la modifica; il solo accesso in scrittura alla directory non la esegue immediatamente.

Per i servizi in esecuzione, segui i percorsi letterali di `EnvironmentFile=` dalla sezione `[Service]` dell’unità, compresi i file il cui nome non inizia con `.env`. Se un utente con privilegi inferiori può leggerne uno, elenca i nomi delle chiavi simili a credenziali, come `API_TOKEN` o `APP_SECRET_KEY`, senza stampare i valori nei log condivisi. Quando valuti l’unità effettiva, controlla gli override dei drop-in e i prefissi opzionali `-`. La leggibilità indica una possibile esposizione di credenziali; il valore deve comunque essere valido per consentire l’escalation tramite un’azione privilegiata.

### Elaborazione privilegiata di upload non attendibili

Un file watcher eseguito come root può passare file da una directory di upload scrivibile dagli utenti a un parser o estrattore di breve durata. Segui lo script padre o il servizio del watcher attivo e verifica la directory esatta, chi può inserirvi file, il comando figlio e i relativi argomenti, nonché l’identità con cui viene eseguito il processo figlio. Un’istantanea dei processi può mostrare il watcher senza rilevare l’estrattore tra un upload e l’altro. Durante l’enumerazione passiva non inserire payload di prova né attivare il watcher.

Un esempio concreto è la modalità di estrazione di Binwalk (`-e`) che elabora dati PFS controllati dall’attaccante. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) consentiva all’estrattore PFS di scrivere al di fuori della directory prevista, anche in un percorso di plugin che Binwalk avrebbe potuto caricare in seguito. Il progetto upstream ha incluso la correzione nella versione [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), ma i backport delle distribuzioni possono mantenere una versione visualizzata più vecchia; prima di valutarne la pertinenza, controlla lo stato di sicurezza del pacchetto installato, ad esempio nel [tracker Debian](https://security-tracker.debian.org/tracker/CVE-2022-4510). La sola versione di Binwalk installata non dimostra un percorso di escalation dei privilegi: l’estrazione deve essere effettivamente avviata da un processo con privilegi superiori su input controllabile dall’utente con privilegi inferiori.

### Build pianificate con dipendenze locali

Un `cargo run` pianificato ricompila il sorgente con l’utente con cui viene eseguito il job. Esamina le dipendenze locali `{ path = "..." }` del manifest e i permessi del sorgente e delle directory padre di ogni dipendenza, non solo quelli del crate principale. Se un utente con privilegi inferiori può modificare una dipendenza compilata da Cargo e il job pianificato esegue il risultato, il codice compilato può essere eseguito con l’identità usata dal job. Verifica il comando effettivo dello scheduler, la directory di lavoro, la risoluzione delle dipendenze e se avverrà una ricompilazione; un file sorgente Rust scrivibile altrove è solo un indizio. Per una valutazione passiva basta leggere il manifest e i metadati dei percorsi. Consulta la [documentazione di Cargo sulle dipendenze tramite percorso](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## File framebuffer di Xvfb

`Xvfb -fbdir <directory>` usa file memory-mapped chiamati `Xvfb_screen<n>` per gli schermi virtuali. Se il processo Xvfb attivo di un altro utente indica una directory in cui i file degli schermi sono leggibili dall’utente corrente, il framebuffer potrebbe esporre i contenuti del desktop di quell’utente. Verifica insieme processo, proprietà dei file e permessi; il solo fatto che un file sia leggibile non dimostra che sullo schermo ci siano contenuti utili. Esamina prima percorsi e metadati, senza copiare i dati delle immagini nell’output di enumerazione condiviso. Il [manuale di Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) documenta il comportamento di `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Manuale Linux `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Manuale Linux `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Manuale OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Configurazione dell'agent Consul: controlli script](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API di registrazione dei servizi dell'agent Consul](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Configurazione ACL di Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Guida di LibreOffice: apertura di un socket per client API esterni](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [SDK di LibreOffice: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
