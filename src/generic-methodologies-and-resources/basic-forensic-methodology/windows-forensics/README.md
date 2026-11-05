# Artefatti Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefatti Windows generici

### Notifiche di Windows 10

Il database delle notifiche per utente si trova in `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (ad esempio, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Le prime versioni di Windows 10 usavano `appdb.dat`; l’Anniversary Update (1607) ha introdotto `wpndatabase.db`. Il database SQLite include una tabella `Notification` con i payload delle notifiche e i campi temporali, anche se la conservazione e i dati disponibili variano in base alla versione e ai criteri di pulizia.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline è una funzionalità di cronologia delle attività che può contenere record relativi alle applicazioni supportate, ai documenti e ad altre attività dell’utente; la copertura dipende dall’applicazione e dalla versione di Windows.<sup>[[4]](#references)</sup>

Il database si trova in `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Può essere aperto con SQLite o analizzato con [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd); il relativo output può essere esaminato con [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### Snapshot di Windows Recall (PC Copilot+)

Recall è una funzionalità facoltativa sui PC Copilot+ supportati con Windows 11. Le build attuali crittografano gli snapshot e il relativo indice con chiavi associate a Windows Hello e a un enclave VBS. Non considerare una copia offline dell’archivio come un database SQLite in chiaro: l’anteprima del 2024 e il design rilasciato presentano caratteristiche di accesso diverse.<sup>[[77]](#references)</sup>

In una **sessione Recall attiva e abilitata**, il processo di rendering `AIXHost.exe` dello stesso utente costituisce una superficie di accesso diversa. La proof of concept TotalRecall Reloaded inietta una DLL in quel processo e richiama le interfacce COM di Recall. L’estrazione della cronologia completa richiede comunque che l’utente si autentichi con Windows Hello; non si tratta di una decrittazione offline né di un bypass di Hello. Il ricercatore ha documentato lo strumento su Windows 11 ARM64, quindi verifica la compatibilità con la build di destinazione prima di farvi affidamento.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` usa `GetRecentCaptureThumbnail` per richiedere una versione ad alta risoluzione dell'acquisizione più recente senza Hello. Dopo l'autorizzazione, `--wait` può estrarre screenshot, testo OCR e metadati per acquisizione, inclusi il contesto dell'applicazione e della finestra. L'output viene scritto in una directory `extraction_*` con timestamp. Questi risultati dipendono dalla build e provengono dalla proof of concept; non garantiscono che Recall sia abilitato o che siano state acquisite tutte le schermate.<sup>[[78]](#references)</sup>

### ADS (Alternate Data Streams)

I file scaricati dall'esterno del confine di attendibilità locale possono contenere l'**alternate data stream `Zone.Identifier`**, che registra informazioni sulla zona e può includere metadati di origine come un URL. La sua presenza e i suoi campi dipendono dal programma che lo crea e dai criteri di sistema.<sup>[[6]](#references)</sup>

## **Backup dei file**

### Cestino

Da Vista in poi, il **Cestino** si trova nella cartella **`$Recycle.bin`** nella radice dell'unità (ad esempio, `C:\$Recycle.bin`).\
Quando un file viene eliminato in questa cartella, vengono creati 2 file specifici:

- `$I{id}`: informazioni sul file, inclusi l'ora di eliminazione e il percorso originale
- `$R{id}`: contenuto del file

![Backup dei file - Cestino: $R{id}: contenuto del file](<../../../images/image (1029).png>)

Con questi file, puoi usare [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) per estrarre il percorso originale e l'ora di eliminazione (usa la versione appropriata per la release di Windows in uso).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Backup dei file - Cestino: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Copie shadow dei volumi

Volume Shadow Copy Service (VSS) può creare copie shadow dei volumi in un determinato istante mentre i file sono in uso; una copia shadow non sostituisce un'immagine forense.<sup>[[8]](#references)</sup>

I metadati della copia sono normalmente associati a `\System Volume Information` nella radice del volume, con identificatori che variano a seconda del sistema:

![Cestino - Copie shadow dei volumi: questi backup si trovano solitamente in System Volume Information, nella radice del file system, e il nome è composto da UID mostrati nell'immagine...](<../../../images/image (94).png>)

Dopo aver montato un'immagine con un apposito strumento forense, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) può enumerare gli snapshot VSS disponibili e permettere di esplorarne o copiarne i file.<sup>[[9]](#references)</sup>

![Cestino - Copie shadow dei volumi: dopo aver montato l'immagine forense con ArsenalImageMounter, è possibile usare lo strumento ShadowCopyView per esaminare una copia shadow ed estrarne i file...](<../../../images/image (576).png>)

La configurazione del writer del registro VSS include `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, che può specificare i file e le chiavi esclusi dal backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Cestino - Copie shadow dei volumi: la voce di registro HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contiene i file e le chiavi da escludere dal backup](<../../../images/image (254).png>)

La chiave `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contiene anche la configurazione del servizio VSS.<sup>[[8]](#references)</sup>

### File di Office salvati automaticamente

I percorsi di AutoRecover variano in base all'applicazione Office, alla versione e alla configurazione. Per Word, Microsoft documenta `%APPDATA%\Microsoft\Word` come percorso predefinito; controlla le impostazioni dell'applicazione per verificare il percorso attivo.<sup>[[12]](#references)</sup>

## Elementi shell

Un elemento shell contiene informazioni su come accedere a un altro file.

### Documenti recenti (LNK)

Windows crea comunemente collegamenti agli elementi recenti quando un utente apre o accede in altro modo a un elemento:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Anche l'accesso a una cartella può creare collegamenti alla cartella e alle relative cartelle principali.

Questi file di collegamento possono contenere il tipo di destinazione, i MAC times della destinazione, le informazioni sul volume e il percorso della destinazione. Questi metadati possono aiutare a identificare una destinazione rimossa, ma l'artefatto non dimostra di per sé che la destinazione sia stata aperta da un determinato utente.<sup>[[13]](#references)[[14]](#references)</sup>

I timestamp del file system del file LNK e i timestamp della destinazione incorporati sono distinti. Non interpretare la creazione del collegamento come il primo utilizzo, né la modifica del collegamento come l'ultimo utilizzo, senza artefatti di riscontro; il formato memorizza i timestamp della destinazione separatamente da quelli del file di collegamento.<sup>[[13]](#references)[[14]](#references)</sup>

Il collegamento a [**LinkParser**](http://4discovery.com/our-tools/) è mantenuto come opzione storica, ma la relativa documentazione non era disponibile durante la revisione. Per un parser a riga di comando documentato, usa [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Questi strumenti mostrano comunemente due gruppi di timestamp:

- **Timestamp della destinazione:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Timestamp del file di collegamento:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Il primo gruppo si riferisce alla destinazione; il secondo al file LNK stesso. Interpreta entrambi facendo riferimento alla documentazione del parser e al contesto del file system.<sup>[[14]](#references)[[15]](#references)</sup>

Puoi ottenere le stesse informazioni eseguendo lo strumento CLI di Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

In questo caso, le informazioni verranno salvate in un file CSV.

### Jumplists

Le Jump Lists sono elenchi specifici per applicazione di elementi recenti o relativi ad attività e possono essere automatiche o personalizzate.<sup>[[13]](#references)</sup>

Le Jump Lists automatiche sono archiviate in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` e usano nomi come `{id}.automaticDestinations-ms`, dove l'ID identifica l'applicazione.

Le Jump Lists personalizzate sono archiviate in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; l'applicazione controlla quali voci di attività o elementi crea.

Le date di creazione e modifica del file system descrivono il file Jump List e non corrispondono automaticamente al primo e all'ultimo accesso a ogni destinazione elencata. Correlate le voci analizzate con i timestamp del file e con altri artefatti.<sup>[[13]](#references)</sup>

È possibile esaminare le Jump Lists con [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Documenti recenti (LNK) - Jumplists: è possibile esaminare le jumplist con JumplistExplorer](<../../../images/image (168).png>)

(_Si noti che i timestamp forniti da JumplistExplorer si riferiscono al file jumplist stesso_)

### Shellbags

[**Segui questo link per scoprire cosa sono le shellbag.**](interesting-windows-registry-keys.md#shellbags)

## Uso di dispositivi USB in Windows

Talvolta, l'utilizzo di USB può essere corroborato da artefatti creati quando si accede a file da supporti rimovibili, tra cui:

- Cartella Recenti di Windows
- Cartella Recenti di Microsoft Office
- Jumplists

Strumenti come [**USBDetective**](https://usbdetective.com) correlano questi artefatti con i record dei dispositivi USB, ma la disponibilità degli artefatti dipende dalla versione di Windows e dall'applicazione.<sup>[[18]](#references)</sup>

Nei test documentati per i flussi di lavoro MTP di Windows XP e Windows 7, alcuni LNK puntavano a una cartella `WPDNSE` anziché al percorso originale.<sup>[[16]](#references)</sup>

![Shellbags - Uso di dispositivi USB in Windows: si noti che alcuni file LNK, invece di puntare al percorso originale, puntano alla cartella WPDNSE](<../../../images/image (218).png>)

Lo studio ha rilevato copie in `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; nei test, i contenuti temporanei non sono sopravvissuti a un riavvio e il GUID poteva essere correlato ai dati shellbag. Considerate questo comportamento dipendente da sistema operativo, dispositivo e applicazione, non una regola universale.<sup>[[16]](#references)</sup>

### Informazioni sul registro

[Consulta questa pagina per scoprire](interesting-windows-registry-keys.md#usb-information) quali chiavi del registro contengono informazioni utili sui dispositivi USB collegati.

### setupapi

In Vista e versioni successive, esaminate `C:\Windows\inf\setupapi.dev.log` per individuare le attività di installazione dei dispositivi. Le intestazioni di sezione includono timestamp `Section start`; documentano l'elaborazione dell'installazione e vanno correlate con altre prove di connessione, anziché essere considerate l'ora esatta dell'inserimento fisico.<sup>[[17]](#references)</sup>

![Informazioni sul registro - setupapi: controlla il file C: Windows inf setupapi.dev.log per ottenere i timestamp della connessione USB (cerca Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

È possibile usare [**USBDetective**](https://usbdetective.com) per ottenere informazioni sui dispositivi USB che sono stati collegati a un'immagine.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective può essere usato per ottenere informazioni sui dispositivi USB che sono stati collegati a un'immagine](<../../../images/image (452).png>)

### Pulizia Plug and Play

L'attività pianificata denominata `Plug and Play Cleanup` rimuove le versioni obsolete dei driver. Anche una definizione dell'attività di Windows 10 documentata da Adam Harrison prende di mira i driver inattivi da 30 giorni, pertanto le prove relative ai driver dei dispositivi rimovibili potrebbero essere eliminate; prima di generalizzare questo comportamento, verificate la definizione dell'attività locale e la build di Windows.<sup>[[1]](#references)</sup>

L'attività si trova nel percorso seguente: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Definizione XML dell'attività pianificata di Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componenti e impostazioni principali dell'attività:**

- **pnpclean.dll**: questa DLL è responsabile del processo di pulizia vero e proprio.
- **UseUnifiedSchedulingEngine**: impostato su `TRUE`, indica l'uso del motore generico di pianificazione delle attività.
- **MaintenanceSettings**:
  - **Period ('P1M')**: indica a Task Scheduler di avviare l'attività di pulizia ogni mese durante la manutenzione automatica ordinaria.
  - **Deadline ('P2M')**: indica a Task Scheduler che, se l'attività non riesce per due mesi consecutivi, deve eseguirla durante la manutenzione automatica di emergenza.

Questa configurazione pianifica la manutenzione ordinaria e riprova dopo errori consecutivi; l'XML esatto e il comportamento dipendono dalla versione.<sup>[[1]](#references)</sup>

**Per maggiori informazioni, consulta:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Email

Le email contengono **2 parti interessanti: le intestazioni e il contenuto**. Nelle **intestazioni** è possibile trovare informazioni come:

- **Chi** ha inviato le email (indirizzo email, IP, server di posta che hanno reindirizzato l'email)
- **Quando** è stata inviata l'email

Inoltre, le intestazioni `References` e `In-Reply-To` possono contenere ID dei messaggi utilizzati per associare le risposte a una conversazione.<sup>[[76]](#references)</sup>

![Pulizia Plug and Play - Email: quando è stata inviata l'email](<../../../images/image (593).png>)

### App Windows Mail

Questa applicazione salva il contenuto delle email in file di testo o HTML ausiliari in percorsi come `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; la cartella numerata esatta e la struttura dei file possono variare a seconda dell'artefatto.<sup>[[75]](#references)</sup>

I **metadati** delle email e i **contatti** si trovano nel **database ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` usa il formato Extensible Storage Engine (ESE). Lavorate su una copia e usate un parser ESE come [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); se uno strumento richiede l'estensione `.edb`, rinominate solo la copia e verificate lo schema delle tabelle prima di fare affidamento su una tabella `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Quando esaminate le proprietà MAPI di Outlook, le proprietà canoniche includono:

- `PidTagClientSubmitTime`: l'ora UTC in cui il client ha inviato il messaggio.
- `PidTagConversationIndex`: la posizione relativa del messaggio in una conversazione.
- `PidTagEntryId`: un identificatore dell'oggetto messaggio.
- `PidTagMessageFlags`: flag di stato, come inviato, letto, non letto o con allegati.
- `PidTagLastVerbExecuted`: l'ultima operazione registrata per il messaggio, come apertura, risposta o inoltro.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

I percorsi dei file di dati di Outlook variano in base alla versione e al tipo di account. Microsoft documenta i seguenti percorsi comuni per i file PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Il percorso del registro `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` può identificare il profilo di Outlook e la configurazione dei file di dati associati.

I file PST possono contenere messaggi, contatti, dati del calendario e altri elementi di Outlook. È possibile esaminare una copia con [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![App Windows Mail - Microsoft Outlook: è possibile aprire il file PST con lo strumento Kernel PST Viewer](<../../../images/image (498).png>)

### File OST di Microsoft Outlook

Un **file OST** è una cache locale per gli account Exchange o Microsoft 365; la modalità Cached Exchange non si applica agli account POP o IMAP. Il periodo offline è configurabile e spesso è impostato su 12 mesi per impostazione predefinita, mentre i limiti di dimensione PST/OST sono impostazioni configurabili separate. Per visualizzare un file OST, è possibile usare [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Recupero degli allegati

Gli allegati persi potrebbero essere recuperabili da:

- Per le configurazioni legacy di Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Per le configurazioni più recenti di Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### File MBOX di Thunderbird

**Thunderbird** archivia i dati del profilo in `%APPDATA%\Thunderbird\Profiles`; le cartelle di posta usano comunemente file mbox senza estensione, nelle directory `Mail` o `ImapMail` specifiche dell'account.<sup>[[29]](#references)[[30]](#references)</sup>

### Anteprime delle immagini

- **Windows XP**: le anteprime delle miniature erano comunemente archiviate in file `thumbs.db` specifici per cartella.
- **Cartelle di rete**: un file `thumbs.db` può ancora essere creato per una cartella UNC quando è abilitato il comportamento pertinente delle miniature; non presumete che ogni versione o criterio di Windows lo crei.
- **Windows Vista e versioni successive**: la cache delle miniature del sistema è centralizzata in `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, con file come **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) può analizzare i file legacy `Thumbs.db`, mentre [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) può analizzare i database moderni della cache delle miniature.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Informazioni sul registro di Windows

Il registro di Windows, che contiene i dati di configurazione del sistema e degli utenti, è conservato in file hive situati in:

- `%WINDIR%\System32\Config` per gli hive del computer alla base di varie sottochiavi `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` per l'hive `HKEY_CURRENT_USER` di un utente.
- Alcune installazioni meno recenti di Windows contengono copie in `%WINDIR%\System32\Config\RegBack\`; Windows 10 versione 1803 e successive non popolano automaticamente questa directory, a meno che non sia abilitato il backup periodico.<sup>[[34]](#references)[[35]](#references)</sup>
- Nei sistemi Windows moderni, i dati per utente relativi alla shell e alla registrazione delle classi sono comunemente archiviati anche in `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat`.<sup>[[34]](#references)[[66]](#references)</sup>

### Strumenti

Alcuni strumenti sono utili per analizzare gli hive del registro; prima di fare affidamento sui risultati, verificate i formati hive e le versioni supportati da ciascuno strumento:

- **Registry Editor**: è installato in Windows. È un'interfaccia GUI per esplorare il registro di Windows della sessione corrente.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): consente di caricare il file del registro e di esplorarlo tramite un'interfaccia GUI. Include anche segnalibri che evidenziano le chiavi contenenti informazioni interessanti.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): dispone di un'interfaccia GUI per esplorare il registro caricato e include anche plugin che evidenziano le informazioni interessanti al suo interno.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): un'altra applicazione GUI in grado di estrarre informazioni da un hive del registro caricato.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recupero di elementi eliminati

Le celle degli hive eliminate possono rimanere finché il relativo spazio non viene riutilizzato, ma il recupero dipende dallo stato dell'hive e dal parser; considerate le chiavi eliminate recuperate come prove da convalidare, non come record garantiti.

### Ora dell'ultima scrittura

Le chiavi del registro hanno un timestamp dell'ultima scrittura; Windows lo espone per la chiave o per una qualsiasi delle relative voci di valore, quindi un valore non ha necessariamente un proprio timestamp di modifica indipendente.<sup>[[69]](#references)</sup>

### SAM

L'hive **SAM** contiene i dati degli account utente e gruppo locali, inclusi gli hash delle password protetti dal materiale boot-key del sistema.<sup>[[38]](#references)[[39]](#references)</sup>

In `SAM\Domains\Account\Users` è possibile ottenere identificatori degli account e alcuni campi relativi all'accesso e ai criteri. Per estrarre gli hash offline è necessario anche l'hive `SYSTEM`, così da recuperare il materiale boot-key pertinente.<sup>[[38]](#references)[[39]](#references)</sup>

### Voci interessanti nel registro di Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programmi eseguiti

### Processi Windows di base

Un [articolo sui processi Windows comuni](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) esistente è mantenuto come lettura aggiuntiva; corroborate le affermazioni sul comportamento dei processi con la documentazione aggiornata di Windows e con prove locali.<sup>[[2]](#references)</sup>

### App recenti di Windows

Nelle versioni di Windows 10 in cui è disponibile, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` contiene sottochiavi specifiche per applicazione con campi come l'ora dell'ultimo utilizzo e il numero di avvii; l'artefatto è stato rimosso nelle versioni successive, quindi verificate la build di destinazione.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Nei sistemi in cui è disponibile Background Activity Moderator, esaminate il percorso `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` o quello più recente `...\bam\State\UserSettings\{SID}`. I valori sono associati al SID dell'utente e possono contenere percorsi di eseguibili tracciati e dati di esecuzione simili a FILETIME; l'artefatto dipende dalla versione e va corroborato con altre prove.<sup>[[63]](#references)</sup>

### Windows Prefetch

Il prefetch memorizza nella cache risorse e metadati di avvio affinché i programmi possano avviarsi più rapidamente.

I file Prefetch sono archiviati come file `.pf` in `C:\Windows\Prefetch`; formato, conservazione e limiti al numero di file variano in base alla versione di Windows. Microsoft documenta la conservazione degli ultimi otto orari di esecuzione e di un massimo di 1024 file in Windows 8 e versioni successive; pertanto, non si devono generalizzare le vecchie descrizioni con limiti fissi.<sup>[[13]](#references)</sup>

Il nome del file segue comunemente il formato `{program_name}-{hash}.pf`, dove l'hash deriva dal contesto di esecuzione, come il percorso e gli argomenti; Windows 10 e versioni successive possono comprimere il file. La presenza è un utile indizio di esecuzione, ma da sola non prova che un utente abbia eseguito il programma e va correlata con altri artefatti.<sup>[[13]](#references)</sup>

Per esaminare questi file è possibile usare [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), che documenta l'analisi delle directory, l'output CSV/HTML e il supporto alla decompressione per i file Prefetch applicabili di Windows 10.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** integra Prefetch utilizzando i modelli di utilizzo storici per migliorare il caricamento. Nei sistemi che li generano, i relativi file di database si trovano comunemente in `C:\Windows\Prefetch\Ag*.db`; il formato e la presenza dipendono dalla versione.<sup>[[41]](#references)</sup>

Questi database possono contenere nomi di applicazioni, conteggi di utilizzo, file o volumi a cui è stato effettuato l'accesso, percorsi e intervalli temporali, ma non devono essere considerati un registro esatto delle esecuzioni.<sup>[[41]](#references)</sup>

Il link esistente a [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) è mantenuto come possibile parser; prima dell'uso, verificane la disponibilità attuale e i formati di output supportati consultando la documentazione dello strumento.

### SRUM

**System Resource Usage Monitor** (SRUM) registra l'utilizzo delle risorse da parte di applicazioni e utenti. È stato introdotto in Windows 8 e archivia i dati nel database ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Fornisce le seguenti informazioni:

- AppID e percorso
- Utente/SID associato al record
- Byte inviati
- Byte ricevuti
- Interfaccia di rete
- Durata della connessione
- Durata del processo

La cadenza di raccolta e la conservazione dei dati dipendono dall'implementazione; non presumere che ogni record rappresenti un intervallo esatto di esecuzione di 60 minuti.<sup>[[13]](#references)</sup>

Puoi estrarre ed esaminare i dati con [**srum_dump**](https://github.com/MarkBaggett/srum-dump), utilizzando le opzioni documentate per la versione corrente dello strumento.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**, noto anche come **ShimCache**, fa parte dell'infrastruttura di compatibilità delle applicazioni di Windows e registra i metadati dei file per le decisioni di compatibilità. Il percorso dell'hive, il formato dei record, la capacità mantenuta e i campi variano in base alla versione di Windows; nelle versioni moderne di Windows, ShimCache da solo non può dimostrare che un utente abbia eseguito un file. Analizza l'hive `SYSTEM` pertinente con lo strumento [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) e confrontane l'output con gli artefatti di esecuzione.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Per analizzare le informazioni memorizzate, si consiglia di utilizzare lo strumento AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Il file **Amcache.hve** è un hive del Registro che inventaria le applicazioni e i file osservati da Windows. Si trova in genere in `C:\Windows\AppCompat\Programs\Amcache.hve`.

Può contenere voci di file associate e non associate, percorsi e valori SHA1, ma la sua presenza costituisce una prova di inventario e non dimostra di per sé che un processo sia stato eseguito.<sup>[[13]](#references)[[44]](#references)</sup>

Per estrarre e analizzare **Amcache.hve**, usa lo strumento [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Questo comando analizza l'hive e scrive l'output in formato CSV.<sup>[[44]](#references)</sup>

Ad esempio:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Tra i file CSV generati, `Amcache_Unassociated file entries` può essere utile quando si esaminano file non associati a un programma riconosciuto.<sup>[[44]](#references)</sup>

### RecentFileCache

Nei sistemi Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` può contenere informazioni sui binari osservati di recente; disponibilità e semantica dipendono dalla versione.

Puoi usare [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) per analizzare il file.<sup>[[45]](#references)</sup>

### Attività pianificate

Le tracce delle attività pianificate possono trovarsi in `C:\Windows\System32\Tasks` per le attività moderne e in `C:\Windows\Tasks`, con file `.job`, per quelle legacy; esamina il formato della definizione dell'attività appropriato per il sistema operativo.<sup>[[73]](#references)[[74]](#references)</sup>

### Servizi

Il database del Service Control Manager si trova in `SYSTEM\CurrentControlSet\Services` (per un hive SYSTEM offline, esamina la chiave del control set corrispondente); contiene configurazioni di servizi e driver, come percorsi degli eseguibili e tipi di avvio.<sup>[[72]](#references)</sup>

### **Windows Store**

Le applicazioni Windows Store installate possono essere rappresentate in `\ProgramData\Microsoft\Windows\AppRepository\`, incluso il database **`StateRepository-Machine.srd`**. Schema e percorsi variano in base alla versione di Windows.<sup>[[71]](#references)</sup>

Il database può contenere identificatori delle applicazioni, numeri dei pacchetti e nomi visualizzati. La presenza di lacune negli identificatori non dimostra, da sola, che un'applicazione sia stata disinstallata; verifica anche lo stato dei pacchetti e del registro.

Le registrazioni dei pacchetti possono comparire anche in `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft documenta una sottochiave `Deprovisioned`, specifica per versione, per le app con provisioning rimosso; non dare per scontato che la sottochiave `Deleted` sia presente in ogni build.<sup>[[70]](#references)</sup>

## Eventi di Windows

A seconda del provider, gli eventi di Windows possono contenere:

- Che cosa è successo
- Un timestamp `TimeCreated` da interpretare in base allo schema dell'evento e al contesto temporale dell'host
- Gli utenti coinvolti
- Gli host coinvolti (hostname, IP)
- Le risorse a cui si è avuto accesso (file, cartelle, stampanti o servizi).<sup>[[49]](#references)</sup>

Prima di Windows Vista, i log eventi usavano generalmente il formato binario legacy in `C:\Windows\System32\config`; Vista e versioni successive usano il formato Windows Event Log, normalmente in `C:\Windows\System32\winevt\Logs`, con file `.evtx` contenenti dati degli eventi visualizzati come XML.<sup>[[46]](#references)[[47]](#references)</sup>

Il registro SYSTEM memorizza la configurazione dei canali in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, inclusi il percorso del file configurato e le impostazioni di conservazione.<sup>[[47]](#references)</sup>

Possono essere visualizzati con Windows Event Viewer (**`eventvwr.msc`**) o con strumenti come [**Event Log Explorer**](https://eventlogxp.com) e [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Comprendere la registrazione degli eventi di sicurezza di Windows

In Vista e versioni successive, il canale Security è comunemente archiviato in `C:\Windows\System32\winevt\Logs\Security.evtx`. La dimensione massima e i criteri di conservazione sono configurabili; con la registrazione circolare, i record più vecchi possono essere sovrascritti quando il file raggiunge il limite. Il canale può registrare eventi di autenticazione, disconnessione, privilegi, criteri di controllo e accesso agli oggetti quando è abilitato il controllo pertinente.<sup>[[46]](#references)[[47]](#references)</sup>

### ID evento principali per l'autenticazione utente:

- **Event ID 4624**: accesso riuscito a un account.<sup>[[50]](#references)</sup>
- **Event ID 4625**: accesso non riuscito a un account.<sup>[[51]](#references)</sup>
- **Event ID 4634**: una sessione di accesso è stata terminata.<sup>[[52]](#references)</sup>
- **Event ID 4647**: un utente ha avviato la disconnessione.<sup>[[53]](#references)</sup>
- **Event ID 4672**: sono stati assegnati privilegi speciali a un nuovo accesso; è comune per gli account di sistema e amministratore, quindi non dimostra, da solo, un'attività malevola.<sup>[[54]](#references)</sup>

#### Tipi di accesso comunemente registrati in 4624, 4625, 4634 e 4647:

- **Interactive (2)**: accesso locale interattivo.
- **Network (3)**: accesso a una risorsa condivisa.
- **Batch (4)**: accesso di un processo batch.
- **Service (5)**: accesso di un servizio.
- **Unlock (7)**: sblocco di una workstation.
- **NetworkCleartext (8)**: accesso di rete che fornisce credenziali in testo in chiaro al pacchetto di autenticazione.
- **NewCredentials (9)**: accesso che usa credenziali alternative fornite per le connessioni in uscita.
- **RemoteInteractive (10)**: accesso tramite Remote Desktop o Terminal Services.
- **CachedInteractive (11)**: accesso interattivo che usa credenziali di dominio memorizzate nella cache.
- **CachedRemoteInteractive (12)**: accesso remoto interattivo memorizzato nella cache.
- **CachedUnlock (13)**: sblocco che usa credenziali memorizzate nella cache.<sup>[[50]](#references)[[51]](#references)</sup>

#### Codici Status e Sub Status per EventID 4625:

- **0xC0000064**: utente inesistente.
- **0xC000006A**: nome utente corretto, password errata.
- **0xC0000234**: account bloccato.
- **0xC0000072**: account disabilitato.
- **0xC000006F**: accesso al di fuori degli orari consentiti.
- **0xC0000070**: violazione delle restrizioni della workstation.
- **0xC0000193**: account scaduto.
- **0xC0000071**: password scaduta.
- **0xC0000133**: la differenza di orario tra client e server è eccessiva.
- **0xC0000224**: l'account deve cambiare la password.
- **0xC0000225**: `STATUS_NOT_FOUND`; il codice, da solo, non identifica un bug di sistema né un attacco.
- **0xC000015B**: il tipo di accesso richiesto non è concesso all'account.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Modifica dell'ora**: l'ora di sistema è stata modificata. Molti eventi riflettono una normale correzione del servizio orario; prima di considerarli manomissioni, correla l'autore e la sorgente temporale.<sup>[[56]](#references)</sup>

#### Event ID 12, 13, 1074, 6005, 6006, 6008 e 6009:

- **Contesto di alimentazione e servizi**: l'evento 12 registra l'avvio del sistema operativo, il 13 ne registra l'arresto, il 1074 registra un arresto o riavvio pianificato, il 6008 indica un arresto imprevisto e il 6009 registra la versione di Windows all'avvio. Gli eventi 6005 e 6006 indicano rispettivamente l'avvio e l'arresto del servizio Event Log; non dimostrano, da soli, l'avvio e l'arresto del sistema operativo.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Eliminazione del log**: l'evento 1102 registra che il log di controllo Security è stato cancellato; esamina l'autore e gli eventi circostanti senza presumere l'intento sulla base del solo evento.<sup>[[62]](#references)</sup>

#### EventID per il tracciamento dei dispositivi USB:

- **20001 / 20003**: eventi di installazione dei dispositivi `UserPnp` che possono aiutare a stabilire la prima attività d'uso o installazione.
- **10000 / 10100**: eventi `DriverFrameworks-UserMode` che possono accompagnare l'attività del dispositivo.
- **Event ID 112**: attività `DeviceSetupManager/Admin` che può fornire timestamp relativi all'inserimento.
- Provider, canale e semantica degli eventi variano in base alla versione di Windows; esamina il nome del provider e i dati dell'evento prima di attribuirgli un significato.<sup>[[59]](#references)</sup>

Per esempi pratici sui tipi di accesso e sui relativi dati delle credenziali, consulta la [guida dettagliata di Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

I dettagli dell'evento, tra cui tipo di accesso, status, substatus, indirizzo sorgente e campi del processo, forniscono contesto per Event ID 4625; un codice status o uno schema di errori ripetuti è un indizio investigativo, non una conclusione.<sup>[[51]](#references)[[55]](#references)</sup>

### Recupero degli eventi di Windows

Poiché i log eventi sono comunemente circolari, i record sovrascritti dal logger potrebbero non essere recuperabili. Conserva un'immagine forense o una copia di lavoro prima di interagire con un sistema attivo; usa un parser o un carver convalidato, come **Bulk_extractor**, solo dopo aver verificato che la versione dello strumento supporti i dati `.evtx` di destinazione; non scollegare un sistema in esecuzione solo per tentare di recuperare eventi.<sup>[[46]](#references)</sup>

### Identificazione degli attacchi comuni tramite gli eventi di Windows

Per un riferimento pratico agli ID evento, consulta il link esistente [Red Team Recipe](https://redteamrecipe.com/event-codes/) e verifica gli esempi rispetto alla documentazione dei provider riportata sopra.

#### Attacchi brute force

Correla i ripetuti tentativi non riusciti Event ID 4625 con un successivo accesso riuscito 4624, il tipo di accesso, lo status, la sorgente e il contesto dell'account; la sequenza è un indicatore da indagare, non la prova di un attacco.<sup>[[50]](#references)[[51]](#references)</sup>

#### Modifica dell'ora

Event ID 4616 registra le modifiche dell'ora di sistema, che possono complicare l'analisi della timeline; confrontalo con le tracce del servizio orario e dell'host.<sup>[[56]](#references)</sup>

#### Tracciamento dei dispositivi USB

Gli ID degli eventi USB dipendono dal provider; correla `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 e `DeviceSetupManager/Admin` 112 con gli artefatti di SetupAPI e del registro.<sup>[[17]](#references)[[59]](#references)</sup>

#### Eventi di alimentazione del sistema

Usa 12/13/1074/6008/6009 per il contesto di avvio, arresto, riavvio e interruzione imprevista dell'alimentazione del sistema operativo; 6005/6006 indicano l'avvio/arresto del servizio Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Eliminazione del log

Security Event ID 1102 registra che il log di controllo Security è stato cancellato e dovrebbe essere correlato con l'account e il processo responsabili.<sup>[[62]](#references)</sup>



## References

- [1] [Pulizia di Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Analisi dei processi comuni di Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Una prospettiva di digital forensics sulle notifiche di Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Strumenti forensi di Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier e Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operazioni di backup e ripristino del registro con VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Chiavi del registro per il backup e il ripristino](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problema di prestazioni di Word relativo al percorso di AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Manuale di risposta agli incidenti](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: formato binario dei file Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Analisi forense USB MTP: identificazione degli artefatti di esfiltrazione dei dati](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Voci del log di installazione dei dispositivi SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID e tipi correlati](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Trovare e trasferire file di dati di Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Attivare la modalità Cached Exchange](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Viene sincronizzato solo un sottoinsieme di elementi](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Configurare i limiti di dimensione per i file di dati di Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profili - Dove Thunderbird archivia i dati utente](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Impostazioni degli account Thunderbird e directory mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Interfaccia IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Hive del registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Il registro di sistema non viene salvato in RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Ripristino del registro di Windows](https://www.mitec.cz/wrr.html)
- [38] [Modificare il registro in remoto](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Panoramica tecnica delle password](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Tracce di Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Formato dei file Event Log](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Chiave del registro Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Proprietà dell'evento TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Evento 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Evento 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Evento 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Evento 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Evento 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: valori NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Evento 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Risoluzione dei riavvii imprevisti tramite i log eventi di sistema](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Risoluzione dei problemi di arresto in corso](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Analisi forense dei dispositivi di archiviazione USB per Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [I tipi di accesso di Windows](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Evento 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderatore delle attività in background](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registro - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print interrompe la stampa degli allegati PDF in Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [File del registro di Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Impedire che le app rimosse vengano reinstallate durante un aggiornamento](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: risultati dei test di FTK e Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database dei servizi installati](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Attività](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Le attività pianificate non riescono con l'errore "Il servizio Utilità di pianificazione non è disponibile"](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Esplorazione del database di Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: formato dei messaggi Internet](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Gestire Recall per i client Windows](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
