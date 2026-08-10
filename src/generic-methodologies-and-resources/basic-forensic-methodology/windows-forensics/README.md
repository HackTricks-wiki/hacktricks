# Artefatti Windows

## Artefatti Windows generici

### Notifiche di Windows 10

Il database delle notifiche per utente si trova in `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (ad esempio, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Le prime versioni di Windows 10 utilizzavano `appdb.dat`; l'Anniversary Update (1607) ha introdotto `wpndatabase.db`. Il database SQLite include una tabella `Notification` con i payload delle notifiche e i campi relativi alla temporizzazione, sebbene la conservazione e i dati disponibili varino in base alla versione e ai criteri di pulizia.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline è una funzionalità di cronologia delle attività che può contenere record relativi ad applicazioni supportate, documenti e altre attività dell'utente; la copertura dipende dall'applicazione e dalla versione di Windows.<sup>[[4]](#references)</sup>

Il database si trova in `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Può essere aperto con SQLite o analizzato con [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), il cui output può essere esaminato con [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Flussi di dati alternativi)

I file scaricati dall'esterno del perimetro di attendibilità locale possono contenere il **flusso di dati alternativo `Zone.Identifier`**, che registra le informazioni sulla zona e può includere metadati sull'origine, come un URL. La sua presenza e i relativi campi dipendono dal produttore e dai criteri di sistema.<sup>[[6]](#references)</sup>

## **Backup dei file**

### Cestino

Su Vista e versioni successive, il **Cestino** si trova nella cartella **`$Recycle.bin`** nella radice dell'unità (ad esempio, `C:\$Recycle.bin`).\
Quando un file viene eliminato in questa cartella, vengono creati 2 file specifici:

- `$I{id}`: Informazioni sul file, inclusi l'orario di eliminazione e il percorso originale
- `$R{id}`: Contenuto del file

![Backup dei file - Cestino: $R{id}: Contenuto del file](<../../../images/image (1029).png>)

Con questi file, è possibile utilizzare [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) per estrarre il percorso originale e l'orario di eliminazione (utilizzare la versione appropriata per la versione di Windows di destinazione).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Il Volume Shadow Copy Service (VSS) può creare shadow copy point-in-time dei volumi mentre i file sono in uso; una shadow copy non sostituisce un'immagine forense.<sup>[[8]](#references)</sup>

I metadati della copia sono normalmente associati a `\System Volume Information` nella root del volume, con identificatori che variano in base al sistema:

![Recycle Bin - Volume Shadow Copies: Questi backup si trovano solitamente in System Volume Information nella root del file system e il nome è composto dagli UID mostrati nell'immagine...](<../../../images/image (94).png>)

Dopo aver montato un'immagine con un forensic mounter appropriato, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) può enumerare gli snapshot VSS disponibili e sfogliare o copiare i file al loro interno.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Montando l'immagine forense con ArsenalImageMounter, lo strumento ShadowCopyView può essere utilizzato per esaminare una shadow copy e persino estrarre i file...](<../../../images/image (576).png>)

La configurazione del registry writer VSS include `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, che può specificare file e chiavi da escludere dal backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: La voce di registro HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contiene i file e le chiavi da non includere nel backup](<../../../images/image (254).png>)

La chiave `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contiene inoltre la configurazione del servizio VSS.<sup>[[8]](#references)</sup>

### File AutoSaved di Office

Le posizioni di AutoRecover variano in base all'applicazione Office, alla versione e alla configurazione. Per Word, Microsoft documenta `%APPDATA%\Microsoft\Word` come posizione predefinita; verifica le impostazioni dell'applicazione per conoscere il percorso attivo.<sup>[[12]](#references)</sup>

## Shell Items

Uno shell item è un elemento che contiene informazioni su come accedere a un altro file.

### Documenti recenti (LNK)

Windows crea comunemente collegamenti agli elementi recenti quando un utente apre o accede in altro modo a un elemento:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

L'accesso a una cartella può anche creare collegamenti per la cartella e per le relative cartelle parent.

Questi file di collegamento possono contenere il tipo della destinazione, i MAC times della destinazione, le informazioni sul volume e il percorso della destinazione. Questi metadati possono aiutare a identificare una destinazione rimossa, ma l'artefatto non costituisce di per sé una prova che la destinazione sia stata aperta da uno specifico utente.<sup>[[13]](#references)[[14]](#references)</sup>

I timestamp filesystem propri dell'LNK e i timestamp della destinazione incorporati sono distinti. Non interpretare la creazione del collegamento come il primo utilizzo o la modifica del collegamento come l'ultimo utilizzo senza artefatti di corroborazione; il formato memorizza i timestamp della destinazione separatamente dai timestamp del file di collegamento.<sup>[[13]](#references)[[14]](#references)</sup>

Il link esistente a [**LinkParser**](http://4discovery.com/our-tools/) viene mantenuto come opzione storica, ma la relativa documentazione non era disponibile durante la revisione. Per un parser da riga di comando documentato, usa [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Questi strumenti espongono comunemente due insiemi di timestamp:

- **Timestamp della destinazione:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Timestamp del file di collegamento:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Il primo insieme si riferisce alla destinazione; il secondo si riferisce al file LNK stesso. Interpreta entrambi in base alla documentazione del parser e al contesto del filesystem.<sup>[[14]](#references)[[15]](#references)</sup>

Puoi ottenere le stesse informazioni eseguendo lo strumento CLI di Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In questo caso, le informazioni verranno salvate all'interno di un file CSV.

### Jumplists

Le Jump Lists sono elenchi, specifici per applicazione, di elementi recenti o associati a determinate attività e possono essere automatici o personalizzati.<sup>[[13]](#references)</sup>

Le Jump Lists automatiche sono archiviate in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` e utilizzano nomi come `{id}.automaticDestinations-ms`, dove l'ID identifica l'applicazione.

Le Jump Lists personalizzate sono archiviate in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; l'applicazione controlla quali voci relative ad attività o elementi creare.

Le date di creazione e modifica del filesystem descrivono il file della Jump List e non indicano automaticamente il primo e l'ultimo accesso a ogni destinazione elencata. Correlare le voci analizzate con i timestamp del file e con altri artefatti.<sup>[[13]](#references)</sup>

È possibile esaminare le Jump Lists utilizzando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Documenti recenti (LNK) - Jumplists: è possibile esaminare le jumplist utilizzando JumplistExplorer](<../../../images/image (168).png>)

(_Si noti che i timestamp forniti da JumplistExplorer sono relativi al file della jumplist_)

### Shellbags

[**Seguire questo link per scoprire cosa sono gli shellbag.**](interesting-windows-registry-keys.md#shellbags)

## Uso delle USB di Windows

L'utilizzo di USB può talvolta essere corroborato dagli artefatti creati quando si accede ai file da supporti rimovibili, tra cui:

- Cartella Windows Recent
- Cartella Microsoft Office Recent
- Jumplists

Strumenti come [**USBDetective**](https://usbdetective.com) correlano questi artefatti con i record dei dispositivi USB, ma la disponibilità degli artefatti dipende dalla versione di Windows e dall'applicazione.<sup>[[18]](#references)</sup>

Nei test documentati per i workflow MTP di Windows XP e Windows 7, alcuni LNK puntavano a una cartella `WPDNSE` invece che al percorso originale.<sup>[[16]](#references)</sup>

![Shellbags - Uso delle USB di Windows: si noti che alcuni file LNK, invece di puntare al percorso originale, puntano alla cartella WPDNSE](<../../../images/image (218).png>)

Lo studio ha osservato copie in `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; nei test eseguiti, il contenuto temporaneo non è sopravvissuto a un riavvio e il GUID poteva essere correlato ai dati degli shellbag. Considerare questo comportamento dipendente dal sistema operativo, dal dispositivo e dall'applicazione, anziché una regola universale.<sup>[[16]](#references)</sup>

### Informazioni del Registry

[Consultare questa pagina](interesting-windows-registry-keys.md#usb-information) per scoprire quali chiavi del registry contengono informazioni interessanti sui dispositivi USB connessi.

### setupapi

Su Vista e versioni successive, esaminare `C:\Windows\inf\setupapi.dev.log` per individuare le attività di installazione dei dispositivi. Le intestazioni delle sezioni includono timestamp `Section start`; documentano l'elaborazione del setup e devono essere correlate con altre prove della connessione, anziché essere considerate l'orario esatto dell'inserimento fisico.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: controllare il file C: Windows inf setupapi.dev.log per ottenere i timestamp relativi a quando è stata effettuata la connessione USB (cercare Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) può essere utilizzato per ottenere informazioni sui dispositivi USB che sono stati connessi a un'immagine.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective può essere utilizzato per ottenere informazioni sui dispositivi USB che sono stati connessi a un'immagine](<../../../images/image (452).png>)

### Plug and Play Cleanup

L'attività pianificata nota come `Plug and Play Cleanup` rimuove le versioni obsolete dei driver. Una definizione dell'attività di Windows 10 documentata da Adam Harrison identifica inoltre i driver inattivi per 30 giorni, quindi le prove relative ai driver dei dispositivi rimovibili potrebbero essere eliminate; verificare la definizione dell'attività locale e la build di Windows prima di generalizzare questo comportamento.<sup>[[1]](#references)</sup>

L'attività si trova nel seguente percorso: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Componenti e impostazioni principali dell'attività:**

- **pnpclean.dll**: questa DLL è responsabile dell'effettivo processo di pulizia.
- **UseUnifiedSchedulingEngine**: impostato su `TRUE`, indica l'utilizzo del motore generico di pianificazione delle attività.
- **MaintenanceSettings**:
- **Period ('P1M')**: indica al Task Scheduler di avviare mensilmente l'attività di pulizia durante la manutenzione automatica ordinaria.
- **Deadline ('P2M')**: indica al Task Scheduler, se l'attività fallisce per due mesi consecutivi, di eseguirla durante la manutenzione automatica di emergenza.

Questa configurazione pianifica la manutenzione ordinaria e riprova dopo fallimenti consecutivi; l'XML e il comportamento esatti dipendono dalla versione.<sup>[[1]](#references)</sup>

**Per ulteriori informazioni, consultare:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Email

Le email contengono **2 parti interessanti: gli header e il contenuto** dell'email. Negli **header** è possibile trovare informazioni come:

- **Chi** ha inviato le email (indirizzo email, IP, mail server che hanno reindirizzato l'email)
- **Quando** è stata inviata l'email

Inoltre, gli header `References` e `In-Reply-To` possono contenere message ID utilizzati per associare le risposte a una conversazione.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Email: quando è stata inviata l'email](<../../../images/image (593).png>)

### Windows Mail App

Questa applicazione salva il contenuto delle email in file di testo o HTML ausiliari all'interno di percorsi come `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; la cartella numerata esatta e la struttura dei file possono variare in base all'artefatto.<sup>[[75]](#references)</sup>

I **metadati** delle email e i **contatti** si trovano all'interno del **database ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` utilizza il formato Extensible Storage Engine (ESE). Operare su una copia e utilizzare un parser ESE come [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); se uno strumento richiede il suffisso `.edb`, rinominare solo la copia e verificare lo schema delle tabelle prima di fare affidamento su una tabella `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Durante l'analisi delle proprietà MAPI di Outlook, le proprietà canoniche includono:

- `PidTagClientSubmitTime`: l'ora UTC in cui il client ha inviato il messaggio.
- `PidTagConversationIndex`: la posizione relativa del messaggio all'interno di un thread di conversazione.
- `PidTagEntryId`: un identificatore dell'oggetto messaggio.
- `PidTagMessageFlags`: flag di stato come inviato, letto, non letto o con allegati.
- `PidTagLastVerbExecuted`: l'ultima operazione registrata per il messaggio, come apertura, risposta o inoltro.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

I percorsi dei file di dati di Outlook variano in base alla versione e al tipo di account. Microsoft documenta questi percorsi comuni per i file PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Il percorso del registry `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` può identificare il profilo Outlook e la configurazione dei file di dati associati.

I file PST possono contenere messaggi, contatti, dati del calendario e altri elementi di Outlook. È possibile esaminare una copia con [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: è possibile aprire il file PST utilizzando lo strumento Kernel PST Viewer](<../../../images/image (498).png>)

### File OST di Microsoft Outlook

Un **file OST** è una cache locale per gli account Exchange o Microsoft 365; Cached Exchange Mode non si applica agli account POP o IMAP. Il periodo offline è configurabile ed è spesso impostato per impostazione predefinita su 12 mesi, mentre i limiti di dimensione PST/OST sono impostazioni configurabili separate. Per visualizzare un file OST, è possibile utilizzare [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Recupero degli allegati

Gli allegati persi potrebbero essere recuperabili da:

- Per le configurazioni Outlook/IE legacy: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Per le configurazioni Outlook/IE11 più recenti: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### File MBOX di Thunderbird

**Thunderbird** archivia i dati del profilo in `%APPDATA%\Thunderbird\Profiles`; le cartelle di posta utilizzano comunemente file mbox senza estensione nelle directory `Mail` o `ImapMail` specifiche dell'account.<sup>[[29]](#references)[[30]](#references)</sup>

### Miniature delle immagini

- **Windows XP**: le anteprime delle miniature erano comunemente archiviate in file `thumbs.db` specifici per cartella.
- **Cartelle di rete**: un file `thumbs.db` può ancora essere creato per una cartella UNC quando è abilitato il comportamento delle miniature pertinente; non presumere che ogni versione o policy di Windows ne crei uno.
- **Windows Vista e versioni successive**: la cache delle miniature del sistema è centralizzata in `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, con file come **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) può analizzare i file `Thumbs.db` legacy, mentre [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) può analizzare i moderni database della cache delle miniature.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Informazioni sul Windows Registry

Il Windows Registry, che archivia i dati di configurazione del sistema e degli utenti, è contenuto nei file hive in:

- `%WINDIR%\System32\Config` per gli hive della macchina alla base di varie sottochiavi `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` per l'hive `HKEY_CURRENT_USER` di un utente.
- Alcune installazioni meno recenti di Windows contengono copie in `%WINDIR%\System32\Config\RegBack\`; Windows 10 versione 1803 e successive non popolano automaticamente questa directory, a meno che non sia abilitato il backup periodico.<sup>[[34]](#references)[[35]](#references)</sup>
- I dati shell e di registrazione delle classi per utente sono comunemente archiviati anche in `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` nelle versioni moderne di Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Strumenti

Alcuni strumenti sono utili per analizzare gli hive del registry; verificare il formato degli hive supportato da ciascuno strumento e la versione prima di fare affidamento sull'output:

- **Registry Editor**: è installato in Windows. È una GUI per navigare nel registry di Windows della sessione corrente.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): consente di caricare il file del registry e navigare al suo interno tramite una GUI. Contiene inoltre Bookmark che evidenziano le chiavi con informazioni interessanti.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): anche questo strumento dispone di una GUI che consente di navigare nel registry caricato e contiene plugin che evidenziano informazioni interessanti all'interno del registry caricato.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): un'altra applicazione GUI in grado di estrarre informazioni da un hive del registry caricato.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recupero di elementi eliminati

Le celle eliminate degli hive possono rimanere fino a quando lo spazio non viene riutilizzato, ma il recupero dipende dallo stato dell'hive e dal parser; considerare le chiavi eliminate recuperate come prove che richiedono una convalida, non come record garantiti.

### Last Write Time

Le chiavi del registry contengono un timestamp di ultima scrittura; Windows lo espone per la chiave o per una qualsiasi delle sue voci di valore, quindi un valore non dispone necessariamente di un proprio timestamp indipendente di modifica.<sup>[[69]](#references)</sup>

### SAM

L'hive **SAM** contiene i dati degli account utente e gruppo locali, inclusi gli hash delle password protetti dal materiale della boot-key del sistema.<sup>[[38]](#references)[[39]](#references)</sup>

In `SAM\Domains\Account\Users` è possibile ottenere gli identificatori degli account e alcuni campi relativi al logon e alle policy. L'estrazione offline degli hash richiede inoltre l'hive `SYSTEM` per recuperare il materiale della boot-key pertinente.<sup>[[38]](#references)[[39]](#references)</sup>

### Voci interessanti nel Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programmi eseguiti

### Processi Windows di base

Un [post sui processi Windows comuni](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) è disponibile come lettura aggiuntiva; corroborare qualsiasi affermazione sul comportamento dei processi con la documentazione Windows aggiornata e con le prove locali.<sup>[[2]](#references)</sup>

### App recenti di Windows

Nelle versioni di Windows 10 che lo espongono, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` contiene sottochiavi specifiche per applicazione con campi come l'ora dell'ultimo utilizzo e il numero di avvii; l'artefatto è stato rimosso dalle versioni successive, quindi convalidare la build di destinazione.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Nei sistemi che espongono il Background Activity Moderator, esaminare il percorso `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` o il percorso più recente `...\bam\State\UserSettings\{SID}`. I valori sono associati al SID dell'utente e possono contenere percorsi di eseguibili monitorati e dati di esecuzione simili a FILETIME; l'artefatto dipende dalla versione e dovrebbe essere corroborato con altre prove.<sup>[[63]](#references)</sup>

### Windows Prefetch

Il prefetch memorizza nella cache le risorse e i metadati di avvio affinché i programmi possano avviarsi più rapidamente.

I file Prefetch sono archiviati come file `.pf` in `C:\Windows\Prefetch`; il formato, la conservazione e i limiti del numero di file variano in base alla versione di Windows. Microsoft documenta la conservazione degli ultimi otto orari di esecuzione e di un massimo di 1024 file su Windows 8 e versioni successive, quindi i precedenti riepiloghi basati su limiti fissi non devono essere generalizzati.<sup>[[13]](#references)</sup>

Il nome del file utilizza comunemente il formato `{program_name}-{hash}.pf`, dove l'hash deriva dal contesto di esecuzione, come percorso e argomenti; Windows 10 e versioni successive possono comprimere il file. La presenza è una prova utile dell'esecuzione, ma non dimostra da sola l'esecuzione da parte di un utente e deve essere correlata con altri artefatti.<sup>[[13]](#references)</sup>

Per esaminare questi file è possibile utilizzare [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), che documenta l'analisi delle directory, l'output CSV/HTML e il supporto alla decompressione per i file Prefetch applicabili di Windows 10.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** integra Prefetch utilizzando modelli storici di utilizzo per migliorare i tempi di caricamento. Nei sistemi che li generano, i relativi file di database si trovano comunemente in `C:\Windows\Prefetch\Ag*.db`; il formato e la presenza dipendono dalla versione.<sup>[[41]](#references)</sup>

Questi database possono contenere nomi delle applicazioni, conteggi di utilizzo, file o volumi consultati, percorsi e intervalli temporali, ma non devono essere considerati un registro di esecuzione preciso.<sup>[[41]](#references)</sup>

Il link esistente a [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) viene mantenuto come possibile parser; prima dell'uso, verificarne la disponibilità attuale e l'output supportato consultando la documentazione dello strumento.

### SRUM

**System Resource Usage Monitor** (SRUM) registra l'utilizzo delle risorse da parte di applicazioni e utenti. È stato introdotto in Windows 8 e memorizza i dati nel database ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Fornisce le seguenti informazioni:

- AppID e percorso
- Utente/SID associato al record
- Byte inviati
- Byte ricevuti
- Interfaccia di rete
- Durata della connessione
- Durata del processo

La frequenza di raccolta e la conservazione dei dati dipendono dall'implementazione; non bisogna presumere che ogni record rappresenti un intervallo di esecuzione esatto di 60 minuti.<sup>[[13]](#references)</sup>

È possibile estrarre e analizzare i dati con [**srum_dump**](https://github.com/MarkBaggett/srum-dump), utilizzando le opzioni documentate dalla versione corrente dello strumento.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

La **AppCompatCache**, nota anche come **ShimCache**, fa parte dell'infrastruttura di Windows per la compatibilità delle applicazioni e registra i metadati dei file per le decisioni di compatibilità. Il percorso dell'hive, il formato dei record, la capacità conservata e i campi variano a seconda della versione di Windows; nelle versioni moderne di Windows, la ShimCache da sola non può dimostrare che un utente abbia eseguito un file. Analizza l'hive `SYSTEM` pertinente con lo [**strumento AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) e confronta i risultati con gli artifact di esecuzione.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): per analizzare le informazioni memorizzate, si consiglia di utilizzare lo strumento AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Il file **Amcache.hve** è un registry hive che cataloga applicazioni e file osservati da Windows. Si trova generalmente in `C:\Windows\AppCompat\Programs\Amcache.hve`.

Può contenere voci di file associate e non associate, percorsi e valori SHA1, ma la sua presenza costituisce una prova di inventario e non dimostra di per sé che un processo sia stato eseguito.<sup>[[13]](#references)[[44]](#references)</sup>

Per estrarre e analizzare **Amcache.hve**, usa lo strumento [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Questo comando analizza l'hive e scrive l'output in formato CSV.<sup>[[44]](#references)</sup>

Ad esempio:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Tra i file CSV generati, `Amcache_Unassociated file entries` può essere utile durante l'analisi di file non associati a un programma riconosciuto.<sup>[[44]](#references)</sup>

### RecentFileCache

Nei sistemi Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` può contenere informazioni sui binari osservati di recente; disponibilità e semantica dipendono dalla versione.

È possibile utilizzare [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) per analizzare il file.<sup>[[45]](#references)</sup>

### Attività pianificate

Le evidenze delle attività pianificate possono trovarsi in `C:\Windows\System32\Tasks` per le attività moderne e in `C:\Windows\Tasks` con file `.job` per le attività legacy; analizzare il formato della definizione dell'attività appropriato per il sistema operativo.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Il database del Service Control Manager si trova in `SYSTEM\CurrentControlSet\Services` (per un hive SYSTEM offline, analizzare la chiave del control set corrispondente); contiene la configurazione dei servizi e dei driver, come i percorsi degli eseguibili e i tipi di avvio.<sup>[[72]](#references)</sup>

### **Windows Store**

Le applicazioni Windows Store installate possono essere rappresentate in `\ProgramData\Microsoft\Windows\AppRepository\`, incluso il database **`StateRepository-Machine.srd`**. Schema e percorsi variano in base alla release di Windows.<sup>[[71]](#references)</sup>

Il database può contenere identificatori delle applicazioni, numeri dei package e nomi visualizzati. Le lacune negli identificatori non costituiscono, da sole, una prova che un'applicazione sia stata disinstallata; verificare anche lo stato dei package e del registro.

Le registrazioni dei package possono comparire anche in `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft documenta una sottochiave `Deprovisioned` specifica per versione per le app provisioned rimosse; non presumere che una sottochiave `Deleted` esista in ogni build.<sup>[[70]](#references)</sup>

## Windows Events

A seconda del provider, gli eventi Windows possono contenere:

- Cosa è accaduto
- Un timestamp `TimeCreated` che deve essere interpretato in base allo schema dell'evento e al contesto temporale dell'host
- Gli utenti coinvolti
- Gli host coinvolti (hostname, IP)
- Gli asset a cui è stato effettuato l'accesso (file, cartelle, stampanti o servizi).<sup>[[49]](#references)</sup>

Prima di Windows Vista, i log degli eventi utilizzavano generalmente il formato binario legacy in `C:\Windows\System32\config`; Vista e versioni successive utilizzano il formato Windows Event Log, normalmente in `C:\Windows\System32\winevt\Logs`, con file `.evtx` contenenti dati degli eventi renderizzati in XML.<sup>[[46]](#references)[[47]](#references)</sup>

Il registro SYSTEM memorizza la configurazione dei canali in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, inclusi il percorso del file configurato e le impostazioni di conservazione.<sup>[[47]](#references)</sup>

Possono essere visualizzati con Windows Event Viewer (**`eventvwr.msc`**) o con strumenti come [**Event Log Explorer**](https://eventlogxp.com) e [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

In Vista e versioni successive, il canale Security è comunemente memorizzato in `C:\Windows\System32\winevt\Logs\Security.evtx`. Le dimensioni massime e i criteri di conservazione sono configurabili; con la registrazione circolare, i record meno recenti possono essere sovrascritti quando il file raggiunge il limite. Il canale può registrare eventi di autenticazione, disconnessione, privilegi, criteri di auditing e accesso agli oggetti quando l'auditing corrispondente è abilitato.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: accesso riuscito a un account.<sup>[[50]](#references)</sup>
- **Event ID 4625**: accesso non riuscito a un account.<sup>[[51]](#references)</sup>
- **Event ID 4634**: una sessione di accesso è stata terminata.<sup>[[52]](#references)</sup>
- **Event ID 4647**: un utente ha avviato una disconnessione.<sup>[[53]](#references)</sup>
- **Event ID 4672**: privilegi speciali assegnati a un nuovo accesso; è comune per gli account di sistema e amministratore, quindi non costituisce da solo una prova di attività malevola.<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: accesso locale interattivo.
- **Network (3)**: accesso a una risorsa condivisa.
- **Batch (4)**: accesso di un processo batch.
- **Service (5)**: accesso di un servizio.
- **Unlock (7)**: sblocco di una workstation.
- **NetworkCleartext (8)**: accesso di rete che fornisce credenziali in testo in chiaro al package di autenticazione.
- **NewCredentials (9)**: accesso che utilizza credenziali alternative fornite per le connessioni in uscita.
- **RemoteInteractive (10)**: accesso tramite Remote Desktop o Terminal Services.
- **CachedInteractive (11)**: accesso interattivo che utilizza credenziali di dominio memorizzate nella cache.
- **CachedRemoteInteractive (12)**: accesso remoto interattivo memorizzato nella cache.
- **CachedUnlock (13)**: sblocco che utilizza credenziali memorizzate nella cache.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: utente inesistente.
- **0xC000006A**: nome utente corretto, ma password errata.
- **0xC0000234**: account bloccato.
- **0xC0000072**: account disabilitato.
- **0xC000006F**: accesso al di fuori degli orari consentiti.
- **0xC0000070**: violazione della restrizione della workstation.
- **0xC0000193**: account scaduto.
- **0xC0000071**: password scaduta.
- **0xC0000133**: la differenza temporale tra client e server è troppo grande.
- **0xC0000224**: l'account deve cambiare la password.
- **0xC0000225**: `STATUS_NOT_FOUND`; il codice, da solo, non identifica un bug di sistema o un attacco.
- **0xC000015B**: il tipo di accesso richiesto non è concesso all'account.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: l'ora del sistema è stata modificata. Molti eventi riflettono una normale correzione del servizio di sincronizzazione dell'ora, quindi correlare l'autore e la sorgente temporale prima di considerarlo una manomissione.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: l'evento 12 registra l'avvio del sistema operativo, il 13 lo spegnimento del sistema operativo, il 1074 uno spegnimento o riavvio pianificato, il 6008 indica uno spegnimento imprevisto e il 6009 registra la versione di Windows all'avvio. Gli eventi 6005 e 6006 indicano rispettivamente l'avvio e l'arresto del servizio Event Log; non costituiscono di per sé una prova dell'avvio e dello spegnimento del sistema operativo.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: l'evento 1102 registra che il log di auditing Security è stato cancellato; analizzare l'autore e gli eventi circostanti invece di presumere l'intento basandosi solo su questo evento.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: eventi di installazione dei dispositivi `UserPnp` che possono aiutare a stabilire il primo utilizzo o l'attività di installazione.
- **10000 / 10100**: eventi `DriverFrameworks-UserMode` che possono accompagnare l'attività del dispositivo.
- **Event ID 112**: attività `DeviceSetupManager/Admin` che può fornire timestamp relativi all'inserimento.
- Provider, canale e semantica degli eventi variano in base alla versione di Windows; analizzare il nome del provider e il payload dell'evento prima di attribuirgli un significato.<sup>[[59]](#references)</sup>

Per esempi pratici sui tipi di accesso e sul relativo materiale delle credenziali, consultare la [guida dettagliata di Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

I dettagli degli eventi, inclusi il tipo di accesso, lo stato, il sottostato, l'indirizzo sorgente e i campi del processo, forniscono contesto per l'Event ID 4625; un codice di stato o uno schema di errori ripetuti costituisce una pista investigativa, non una conclusione.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Poiché i log degli eventi sono comunemente circolari, i record sovrascritti dal logger potrebbero non essere recuperabili. Conservare un'immagine forense o una copia di lavoro prima di interagire con un sistema live; utilizzare un parser o carver validato come **Bulk_extractor** solo dopo aver verificato che la versione dello strumento supporti i dati `.evtx` di destinazione e non scollegare un sistema in esecuzione esclusivamente per tentare di recuperare gli eventi.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Per un riferimento pratico agli event ID, consultare il link esistente [Red Team Recipe](https://redteamrecipe.com/event-codes/) e convalidare i relativi esempi rispetto alla documentazione dei provider riportata sopra.

#### Brute Force Attacks

Correlare i fallimenti ripetuti dell'Event ID 4625 con un successivo successo 4624, il tipo di accesso, lo stato, la sorgente e il contesto dell'account; la sequenza è un indicatore da analizzare, non una prova di attacco.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

L'Event ID 4616 registra le modifiche all'ora del sistema, che possono complicare l'analisi della timeline; confrontarlo con le evidenze del servizio di sincronizzazione dell'ora e dell'host.<sup>[[56]](#references)</sup>

#### USB Device Tracking

Gli ID degli eventi USB dipendono dal provider; correlare `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 e `DeviceSetupManager/Admin` 112 con gli artefatti SetupAPI e del registro.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Utilizzare 12/13/1074/6008/6009 per il contesto di avvio, spegnimento, riavvio e perdita imprevista di alimentazione del sistema operativo; 6005/6006 indicano l'avvio e l'arresto del servizio Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

L'Event ID 1102 di Security registra che il log di auditing Security è stato cancellato e deve essere correlato con l'account e il processo responsabili.<sup>[[62]](#references)</sup>

## References

- [1] [Pulizia di Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Analisi dei processi Windows comuni](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Una prospettiva di digital forensics sulle notifiche di Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Strumenti di digital forensics di Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier e Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operazioni di backup e ripristino del registro tramite VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Chiavi del registro per backup e ripristino](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problema di prestazioni di Word nella posizione AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Manuale di Incident Response](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: formato di file binario Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Digital forensics USB MTP: identificazione degli artefatti di esfiltrazione dei dati](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Voci del log di installazione dei dispositivi SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID e tipi correlati](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Individuare e trasferire i file di dati di Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Attivare la modalità Cached Exchange](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Viene sincronizzato solo un sottoinsieme di elementi](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Configurare i limiti delle dimensioni per i file di dati di Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profili - Dove Thunderbird memorizza i dati utente](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Impostazioni degli account Thunderbird e directory mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Interfaccia IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Hive del registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Registro di sistema non sottoposto a backup in RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Modificare il registro in remoto](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Panoramica tecnica delle password](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Evidenze di Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
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
- [57] [Risoluzione dei riavvii imprevisti tramite i log degli eventi di sistema](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Risoluzione del problema di spegnimento in corso](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Digital forensics dei dispositivi di archiviazione USB per Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Tipi di accesso Windows](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Evento 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderatore dell'attività in background](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registro - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print interrompe la stampa degli allegati PDF in Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [File del registro di Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Impedire il ritorno delle app rimosse durante un aggiornamento](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: risultati dei test di FTK e Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database dei servizi installati](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Attività](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Le attività pianificate non riescono con l'errore Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigazione nel database Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: formato dei messaggi Internet](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
