# Enumerazione dei processi e percorsi dei servizi

{{#include ../../banners/hacktricks-training.md}}

La domanda utile è: quale processo privilegiato utilizza dati o codice che un utente con privilegi inferiori può influenzare? Esamina l'albero dei processi, l'ambiente attivo, i file aperti e l'unità o lo script che ha avviato ogni candidato.

## Mappare i processi e la proprietà dei file

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Una relazione padre-figlio tra utenti diversi può essere normale, ma una transizione inattesa richiede di esaminare il comando padre, gli argomenti, l'eseguibile, la directory di lavoro e i file a cui fa riferimento. Usa [utenti e sessioni](../user-information/user-and-session-triage.md) per interpretare il proprietario e il contesto di login.

### Console locali di macchine virtuali

Esamina le opzioni `-spice` di un processo QEMU insieme al suo indirizzo di ascolto. [La documentazione di QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) specifica che `disable-ticketing` consente ai client SPICE di connettersi senza autenticazione. Anche un listener associato all'indirizzo di loopback può essere raggiungibile da altri utenti locali dell'host. Verifica il listener attivo, le opzioni di autenticazione e l'accesso locale prima di considerare la riga di comando una console esposta. Il controllo della console riguarda il **guest**; ottenere un account guest o modificarne lo stato di avvio richiede condizioni separate all'interno del guest e non conferisce i privilegi di root sull'host di virtualizzazione. Durante l'enumerazione passiva, leggi gli argomenti del processo e i metadati del socket senza connetterti al guest né riavviarlo.

Un'interfaccia web raggiungibile localmente può eseguire codice con l'account del servizio anche quando la shell iniziale non può accedere ai file di quell'account. Ad esempio, CVE-2023-0297 riguardava la gestione di `/flash/addcrypted2` in pyLoad, quando JavaScript non attendibile raggiungeva Js2Py con le importazioni Python abilitate; la [correzione upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) ha disabilitato `pyimport`. Correlaziona il proprietario del processo in esecuzione, l'indirizzo di ascolto, l'esposizione dell'endpoint e la patch installata o il backport del vendor prima di considerare un processo pyLoad una possibile via di escalation. Il nome di un processo, una porta aperta o la sola versione del pacchetto non dimostrano che il sistema sia esposto; l'enumerazione passiva non dovrebbe inviare un payload di esecuzione.

### Shell di login privilegiate che condividono un terminale

Una shell interattiva privilegiata che esegue `su --login <user>` senza uno pseudo-terminale indipendente può lasciare il terminale condiviso con la shell di login dell'utente meno privilegiato. Se il file di startup di quell'utente è controllabile e il codice contenuto può usare `TIOCSTI` per iniettare input nel terminale, l'input può raggiungere la shell privilegiata quando riprende. [Il manuale di `su` di util-linux](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) descrive il rischio del terminale condiviso e raccomanda `su --pty`/`-P` per l'uso interattivo; `su -c` avvia una sessione separata senza un terminale di controllo. Il rischio dipende dalla shell padre effettiva, dalla relazione tra i terminali, dal file di startup di destinazione e dai criteri del kernel. Il solo nome di un processo o l'argomento `su -l` costituisce soltanto un'indicazione da approfondire.

Esamina l'albero dei processi osservato e le colonne TTY, quindi il launcher leggibile e la proprietà/i permessi del file di startup. Su Linux, se presente, `/proc/sys/dev/tty/legacy_tiocsti` può aiutare a interpretare i criteri; la sua assenza non dimostra che il sistema sia sicuro. [Il manuale Linux di `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) segnala che, da Linux 6.2, l'operazione può richiedere `CAP_SYS_ADMIN` quando questo sysctl è impostato su false. Non invocare l'ioctl durante l'enumerazione dell'host.

A volte un account del database può modificare il file di startup dell'utente di destinazione senza accesso diretto in scrittura al filesystem. Il comando server-side PostgreSQL `COPY ... TO 'filename'` scrive usando l'account OS del server del database, ma [PostgreSQL limita](https://www.postgresql.org/docs/current/sql-copy.html) questa forma del comando ai superuser del database o a ruoli come `pg_write_server_files`. Verifica sia il ruolo del database sia i permessi sui file dell'OS del server; una stringa di connessione dell'applicazione, da sola, non concede l'autorità di scrittura sui file. Nel valutare la catena, considera separatamente il launcher privilegiato e le capacità dell'account del database.

## Esamina gli artefatti di runtime

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Gli eseguibili eliminati e i file eliminati ma ancora aperti restano referenziati finché non viene chiuso il loro ultimo descrittore. Possono conservare prove o segreti accessibili. Gli ambienti e la memoria dei processi possono contenere credenziali, ma leggere un altro processo è soggetto a restrizioni legate alla proprietà, alle opzioni di mount di `/proc`, alla policy Yama ptrace e ad altri controlli di sicurezza. Consulta [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) e [post-exploitation credential hunting](../post-exploitation/README.md) per tecniche correlate.

Le tracce di syscall salvate costituiscono un altro confine di autorizzazione dei file. [`strace` registra gli argomenti delle syscall in un file di output](https://man7.org/linux/man-pages/man1/strace.1.html), quindi una traccia leggibile degli [argomenti di `execve`](https://man7.org/linux/man-pages/man2/execve.2.html) potrebbe rivelare una password passata sulla riga di comando da un job con privilegi elevati. Verifica innanzitutto che l'utente corrente possa leggere quella specifica traccia e che l'argomento contenga effettivamente una credenziale; per dimostrare in seguito che la credenziale è accettata nell'ambito di un altro account Unix servono verifiche separate. I metadati dei file sono un indizio passivo utile, senza dover esaminare ogni traccia o stamparne il contenuto durante l'enumerazione di routine.

## Socket di automazione per ufficio con privilegi elevati

LibreOffice e OpenOffice possono esporre la loro API UNO tramite un argomento `--accept=socket,host=<host>,port=<port>;urp;`. Un processo office di proprietà di root con un endpoint raggiungibile potrebbe consentire a un utente locale con privilegi inferiori di invocare servizi API nel contesto di sicurezza di quel processo. Il servizio `SystemShellExecute` include un'operazione per avviare un comando di sistema. Il binding all'interfaccia loopback limita la raggiungibilità remota, ma il socket resta comunque raggiungibile dagli utenti locali, a meno che un altro controllo non lo impedisca.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Correla il proprietario del processo, l’argomento `--accept` esatto e l’indirizzo e la porta di ascolto correnti. Un acceptor configurato che non è riuscito a eseguire il bind è solo un indizio; durante l’enumerazione passiva, non connetterti all’API né invocarla. Evita di avviare un’istanza di office con privilegi elevati solo per verificare questa condizione.

## Memoria condivisa System V utilizzata da processi privilegiati

Un helper di proprietà di root può creare un segmento di memoria condivisa System V su cui un altro utente può scrivere. Se in seguito l’helper si fida dei dati contenuti nel segmento per eseguire un comando shell o un’altra operazione sensibile, il segmento attraversa un confine di privilegi anche se l’eseguibile e i suoi file sono protetti. `shmget()` ricava i permessi di accesso dai nove bit meno significativi dei suoi flag; la modalità `0666` consente agli altri utenti di scrivere, mentre il flag `IPC_CREAT` non restringe tali permessi. Ispeziona passivamente i segmenti attivi con `ipcs -m` e correla il proprietario, la modalità e la durata con il processo privilegiato e la gestione dei suoi input. Un segmento scrivibile da tutti, da solo, non dimostra l’esecuzione di comandi.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

I segmenti System V sono distinti dai file di memoria condivisa POSIX in `/dev/shm`. Un segmento creato solo per un istante potrebbe non comparire in una singola acquisizione di `ipcs`, quindi un output vuoto non esclude la presenza di un helper che usa la memoria condivisa. Esamina il comportamento del suo codice sorgente o binario e qualsiasi regola `sudo` che lo avvii; non eseguire l'helper privilegiato solo per far comparire un segmento durante l'enumerazione. La [guida ai namespace IPC](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) spiega in che modo i namespace influiscono sulla visibilità.<sup>[[2]](#references)[[3]](#references)</sup>

## Controlli script dell'agent Consul

Consul può eseguire controlli di integrità tramite script con l'identità del sistema operativo del proprio agent. Se un agent viene eseguito come root, abilita `enable_script_checks` e consente a un utente con privilegi inferiori di registrare un servizio con un controllo script tramite l'API HTTP locale, tale utente potrebbe eseguire comandi come root. Limitare il binding dell'API a `127.0.0.1` consente comunque agli utenti locali di raggiungerla. L'impostazione `enable_local_script_checks` è più restrittiva: esclude i controlli script inviati tramite le registrazioni dell'API HTTP. Quando sono abilitate le ACL di Consul, la registrazione dei servizi richiede `service:write`; una riga `acl.default_policy=allow`, da sola, non dimostra che un chiamante anonimo possa registrare un servizio. Esamina nel loro insieme l'identità effettiva dell'agent, le impostazioni caricate, il binding dell'API e le autorizzazioni.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Segui gli argomenti `-config-dir` e `-config-file` dell’agent in esecuzione per individuare la configurazione pertinente e controlla solo i nomi dei campi e le impostazioni relativi a script-check e ACL. I file di configurazione possono contenere anche chiavi o token gossip: evita di copiarli nei log condivisi. Non registrare un servizio né eseguire un health check solo per enumerare questa condizione.

Esiste un percorso separato tramite file locale quando un utente con privilegi inferiori può **scrivere nella directory** indicata da `-config-dir` di un agent eseguito come root e **attraversarla**: da quella directory potrebbe essere caricato un nuovo file di definizione del servizio `.hcl` o `.json`. I permessi di attraversamento e scrittura della directory possono consentire di aggiungere un file anche quando non è consentito elencarne il contenuto. Per l’esecuzione di comandi come root, verifica che l’agent carichi effettivamente quella directory, che l’impostazione **effettiva** di script-check consenta le definizioni locali, che la definizione venga caricata e che l’agent mantenga i privilegi di root. La [documentazione di Consul](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) specifica quali impostazioni e definizioni di health check possono essere ricaricate; per abilitare gli script check potrebbe essere necessario riavviare l’agent, quindi verifica il comportamento della versione installata. Quando gli ACL proteggono l’agent, [`consul reload` richiede `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); il solo permesso di scrittura KV non lo concede. Considera i metadati di una directory scrivibile un motivo per approfondire, non una prova di un reload autorizzato, di un riavvio o dell’esecuzione di comandi. Esamina percorsi, permessi e policy senza scrivere configurazioni né chiamare l’API.

## Segui la catena di esecuzione del servizio

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Controlla l'unit, i drop-in, `EnvironmentFile=`, gli script helper, i comandi relativi, le directory scrivibili e l'attivazione dei socket. Un'unit di proprietà di root può comunque essere insicura se legge una configurazione o uno script scrivibile da un utente. La pagina [arbitrary file write](../interesting-files-permissions/write-to-root.md) illustra i percorsi comuni di abuso di servizi e unit. Monitora i job di breve durata con [pspy](https://github.com/DominicBreuker/pspy) o con audit/telemetria dei processi, quando una singola esecuzione di `ps` non riesce a rilevarli.

Per un servizio **xinetd** personalizzato, correla i campi `server`, `user` e i controlli di accesso dello stanza abilitata con il listener attivo e l'eseguibile esatto. L'impostazione [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) determina l'identità del processo avviato, mentre un bit set-user-ID sull'eseguibile può modificare separatamente la sua identità effettiva se [`execve` consente tale transizione](https://man7.org/linux/man-pages/man2/execve.2.html). Un binario privilegiato raggiungibile che accetta input non attendibile merita un'analisi offline del sorgente o del disassemblato per individuare bug di memory safety, come una conversione di stringa [`scanf` senza limiti](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) in un buffer di dimensione fissa. La mappatura del servizio e i metadati set-user-ID sono indizi, non prove di un bug del genere; durante l'enumerazione passiva, non inviare input che causino crash né fare debug del servizio privilegiato attivo.

Per un listener privilegiato personalizzato di cui è disponibile il sorgente, esamina ogni lunghezza controllata dal chiamante usata in un'operazione di copia come [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Verificare soltanto che l'indice di scrittura corrente rientri in un buffer di dimensione fissa non dimostra che la **lunghezza della copia** rientri nello spazio restante; verifica `copy_length <= capacity - index` dopo aver confermato che l'indice sia nel range, e controlla il segno e l'overflow aritmetico. Questo è un indizio da approfondire solo se l'input raggiunge quell'operazione, il listener è accessibile all'utente con privilegi inferiori e il processo mantiene un'identità effettiva superiore. Esamina offline il sorgente e i metadati del processo; durante l'enumerazione, non inviare input che causino crash al servizio attivo.

Sui sistemi che usano **Upstart**, le definizioni dei job di sistema possono trovarsi in `/etc/init/*.conf`. Un file di job scrivibile dall'utente corrente è rilevante se il demone init attivo carica proprio quel job, la sua sezione `script` o `exec` viene eseguita con un'identità più privilegiata e l'utente può avviarlo tramite un comando `initctl` consentito o un altro trigger effettivo. Un'autorizzazione sudo per `initctl`, da sola, non dimostra che un file di job sia scrivibile né che un job modificato verrà eseguito. Controlla le autorizzazioni del file di job esatto, l'impostazione effettiva di run-as, il demone attivo e il trigger, senza modificare né avviare il job durante l'enumerazione. Consulta i manuali [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) e [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Un file di password per l'autologin leggibile, come `/etc/autologin/passwd` sui sistemi in cui il [job di boot legge proprio quel percorso](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), è un indizio di esposizione di credenziali. Verifica che il job di boot sia installato e usi il file, poi controlla separatamente se la password è valida per un altro account o servizio locale. Il solo nome del file non dimostra il riutilizzo della password; registra il percorso e i metadati di accesso senza inserire la password nell'output condiviso dell'enumerazione.

La direttiva `ExecStart=` di un'unit o un comando pianificato può rivelare il percorso esatto di uno script in una directory non elencabile. Il [permesso di ricerca nelle directory](https://man7.org/linux/man-pages/man7/path_resolution.7.html) può comunque consentire all'identità corrente di attraversare quel percorso noto; verifica l'accesso in ricerca su ogni directory padre e il permesso di lettura sul file, invece di supporre che l'impossibilità di elencare la directory lo protegga. Uno script leggibile può contenere una credenziale di trasferimento, ma accedere a un altro account richiede che la credenziale sia ancora valida e venga accettata separatamente da quell'account. Registra il percorso e le evidenze sui permessi senza riportare valori segreti nei log condivisi.

Per uno script Node.js CommonJS pianificato, esamina gli import non relativi come `require('package')` anche se lo script è di sola lettura. [Node cerca `node_modules` accanto al file che importa il modulo e poi nelle directory antenate](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), prima di ripiegare sui percorsi globali configurati. Un utente con privilegi inferiori che può **scrivere e cercare** in una di quelle directory antenate potrebbe creare un package che corrisponde prima. Verifica che venga raggiunto l'import esatto, che il package selezionato non sia un modulo integrato, che il percorso pertinente possa essere creato o modificato, che il modulo venga risolto in quel percorso dal runtime installato e che un job con privilegi superiori lo carichi alla prossima esecuzione. I metadati di una directory padre scrivibile sono solo un'indicazione da approfondire; esamina lo script e lo scheduler passivamente, senza inserire un modulo né attivare il job.

Un indice di package Python privato è un altro confine di fiducia quando un job automatizzato installa package con un'identità OS diversa. Correlate il job esatto e l'account run-as con l'indice configurato, i nomi dei package selezionati e la possibilità che un utente con privilegi inferiori pubblichi o sostituisca un package che il job installerà davvero. La creazione di una distribuzione sorgente può eseguire il backend di build o il vecchio `setup.py` con l'identità dell'installer; l'importazione del package installato è un percorso di esecuzione separato. Un listener dell'indice, un hash di password di upload leggibile o il solo nome di un file package non dimostrano questa catena. Esamina il job, le autorizzazioni dell'indice e la provenienza del package senza caricare né installare nulla durante l'enumerazione. Consulta [pip's build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) e [secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/).

Un agent privilegiato può interrogare una coda di task gestita da un servizio web o container separato. Se un'identità con un livello di fiducia inferiore può scrivere nel database dei task del servizio, determina se quelle righe vengono effettivamente servite all'agent e se un task di comando viene eseguito con l'identità OS dell'agent. Verifica separatamente l'accesso in scrittura al database, la sessione o la chiave di routing di destinazione, l'interrogazione attiva, l'autorizzazione dei task e l'utente effettivo dell'agent. Essere root dentro un container non implica di per sé l'accesso come root sull'host; il confine viene superato solo se un consumer con privilegi sull'host esegue dati di task controllati dall'attaccante. Esamina i metadati dei processi, del file database e del servizio senza modificare la coda né inviare task durante l'enumerazione.

Un job ricorrente potrebbe invece leggere un comando da una riga di configurazione del database dell'applicazione. Verifica che il ruolo del database con privilegi inferiori possa modificare proprio quella riga, che il job attivo la legga dopo la modifica e che il valore raggiunga una shell o un runner di comandi equivalente con un'identità OS superiore. L'accesso in scrittura al database o un valore che sembra un comando, da soli, non dimostrano l'esecuzione; esamina il job e i permessi senza modificare la riga durante l'enumerazione passiva.

Un messaggio in coda può contenere anche un URL anziché codice. Se un consumer privilegiato recupera quell'URL e carica la risposta come plugin Lua o eseguibile di altro tipo, verifica i permessi del publisher sull'exchange e sulla routing key esatti, il binding alla coda consumata, il percorso di recupero e caricamento del plugin e l'identità effettiva del worker. [RabbitMQ instrada i messaggi pubblicati tramite gli exchange](https://www.rabbitmq.com/docs/exchanges); un listener del broker o un login valido, da soli, non dimostrano che il messaggio venga recapitato a questo worker. Credenziali del broker in chiaro catturate sono un indizio separato che richiede effettivo accesso alla packet capture e traffico leggibile; non dimostrano l'autorizzazione alla pubblicazione. Un plugin Lua può invocare comandi shell tramite [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) solo se quell'API è disponibile nel suo runtime. Esamina configurazione e codice senza catturare traffico, pubblicare messaggi o recuperare un plugin durante l'enumerazione passiva.

Quando un servizio Python privilegiato espone un endpoint HTTP o socket locale, uno script leggibile può rivelare un percorso dall'input al codice anche se i suoi permessi impediscono di modificarlo. Correlate il processo e l'identità dell'unit attivi con lo script esatto, il listener, l'autorizzazione delle route e i campi controllati dal chiamante. Poi segui quei campi attraverso parsing e convalida fino a un sink dinamico `eval()` o `exec()`. In particolare, costruire un nuovo f-string a partire dal testo di una richiesta e valutarlo può interpretare i campi di sostituzione forniti dall'attaccante come espressioni Python ([avviso Python su `eval`](https://docs.python.org/3/library/functions.html#eval); [semantica degli f-string](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). La semplice presenza di `eval` o il binding a loopback non dimostrano che un chiamante non attendibile raggiunga il sink; esamina il flusso effettivo dei dati e i controlli di accesso senza inviare un payload di test durante l'enumerazione.

Un controllo basato su richieste firmate su quella route richiede un'analisi separata. Se il sorgente leggibile deriva la chiave di firma da uno spazio di output dimostrabilmente piccolo o prevedibile e il servizio espone un campione firmato valido, la firma potrebbe non proteggere più un sink `eval()` privilegiato. Verifica la derivazione esatta della chiave e il verificatore, l'identità del servizio attivo e l'accesso dei chiamanti locali, nonché se il campo firmato raggiunga il sink; un import del modulo Python [`random`](https://docs.python.org/3/library/random.html) o una firma campione, da soli, non dimostrano nessuna di queste condizioni. Python avverte inoltre che limitare `__builtins__` [non costituisce un confine di sicurezza per input non attendibile a `eval()`](https://docs.python.org/3/library/functions.html#eval). Analizza la chiave offline e non inviare richieste contraffatte durante l'enumerazione passiva.

Una directory `/etc/systemd/system/<unit>.service.d` vuota ma scrivibile è rilevante anche quando il file dell'unit e tutti i drop-in esistenti sono protetti: l'utente potrebbe creare un nuovo override `.conf`. Verifica che la directory sia scrivibile e ricercabile dall'identità corrente, che l'unit sia caricata e venga eseguita come root e se avverranno un reload del demone seguito da un riavvio. Un'autorizzazione al reload o al riavvio, un timer o un successivo boot possono rendere effettiva la modifica; il solo accesso in scrittura alla directory non la esegue immediatamente.

Per i servizi in esecuzione, segui i percorsi letterali di `EnvironmentFile=` nella sezione `[Service]` dell'unit, compresi i file il cui nome non inizia con `.env`. Se un utente con privilegi bassi può leggerne uno, elenca i nomi delle chiavi simili a credenziali, come `API_TOKEN` o `APP_SECRET_KEY`, senza riportarne i valori nei log condivisi. Quando valuti l'unit effettiva, controlla gli override dei drop-in e i prefissi opzionali `-`. La leggibilità è un indizio di esposizione delle credenziali; il valore deve comunque essere valido per consentire un'escalation tramite un'azione privilegiata.

### Elaborazione privilegiata di upload non attendibili

Un file watcher eseguito come root può passare file da una directory di upload scrivibile dagli utenti a un parser o estrattore di breve durata. Segui lo script o il servizio genitore del watcher in esecuzione e verifica la directory esatta, chi può inserirvi file, il comando figlio e i suoi argomenti, nonché l'identità con cui viene eseguito il figlio. Uno snapshot dei processi può mostrare il watcher senza rilevare l'estrattore tra un upload e l'altro. Durante l'enumerazione passiva, non inserire un payload di test né attivare il watcher.

Un esempio concreto è la modalità di estrazione di Binwalk (`-e`) che elabora dati PFS controllati dall'attaccante. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) permetteva all'estrattore PFS di scrivere al di fuori della directory prevista, anche in un percorso di plugin che Binwalk avrebbe potuto caricare in seguito. Il progetto upstream ha incluso la correzione nella versione [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), ma i backport delle distribuzioni possono mantenere una versione visualizzata più vecchia; prima di valutarne l'applicabilità, controlla lo stato di sicurezza del package installato, ad esempio nel [tracker Debian](https://security-tracker.debian.org/tracker/CVE-2022-4510). La sola versione di Binwalk installata non dimostra un percorso di escalation dei privilegi: l'estrazione deve essere effettivamente invocata da un processo più privilegiato su input controllabile dall'utente con privilegi inferiori.

### Build pianificate con dipendenze locali

Un `cargo run` pianificato ricompila il sorgente con l'utente run-as del job. Esamina le dipendenze locali `{ path = "..." }` del manifest e i permessi del sorgente e delle directory antenate di ogni dipendenza, non solo quelli del crate principale. Se un utente con privilegi inferiori può modificare una dipendenza compilata da Cargo e il job pianificato ne esegue il risultato, il codice compilato può essere eseguito con l'utente run-as del job. Verifica il comando effettivo dello scheduler, la directory di lavoro, la risoluzione delle dipendenze e se avverrà una ricompilazione; un file sorgente Rust scrivibile in un altro percorso è solo un indizio. Per il triage passivo bastano la lettura del manifest e i metadati dei percorsi. Consulta la [documentazione di Cargo sulle dipendenze con percorso](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## File framebuffer di Xvfb

`Xvfb -fbdir <directory>` usa file mappati in memoria denominati `Xvfb_screen<n>` per gli schermi virtuali. Se il processo Xvfb in esecuzione di un altro utente specifica una directory i cui file degli schermi sono leggibili dall'utente corrente, il framebuffer può esporre il contenuto del desktop di quell'utente. Verifica insieme il processo, la proprietà dei file e i relativi permessi; il solo fatto che un file sia leggibile non dimostra che lo schermo contenga informazioni utili. Prima esamina i percorsi e i metadati, senza copiare dati immagine nell'output condiviso dell'enumerazione. Il [manuale di Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) documenta il comportamento di `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Manuale Linux `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Manuale Linux `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Manuale OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Configurazione dell'agente Consul: controlli script](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API di registrazione dei servizi dell'agente Consul](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Configurazione ACL di Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Guida di LibreOffice: apertura di un socket per client API esterni](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [SDK di LibreOffice: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
