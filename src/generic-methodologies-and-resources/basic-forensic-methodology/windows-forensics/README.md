# Artefatti di Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefatti generici di Windows

### Notifiche di Windows 10

Nel percorso `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` è possibile trovare il database `appdb.dat` (prima di Windows anniversary) o `wpndatabase.db` (dopo Windows Anniversary).

All'interno di questo database SQLite è possibile trovare la tabella `Notification` con tutte le notifiche (in formato XML), che possono contenere dati interessanti.

### Timeline

Timeline è una funzionalità di Windows che fornisce la **cronologia** delle pagine web visitate, dei documenti modificati e delle applicazioni eseguite.

Il database si trova nel percorso `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Questo database può essere aperto con uno strumento SQLite o con lo strumento [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **che genera 2 file che possono essere aperti con lo strumento** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

I file scaricati possono contenere l'**ADS Zone.Identifier**, che indica **come** sono stati **scaricati** dalla intranet, da internet, ecc. Alcuni software (come i browser) inseriscono solitamente **ulteriori** **informazioni**, come l'**URL** da cui il file è stato scaricato.

## **Backup dei file**

### Cestino

In Vista/Win7/Win8/Win10 il **Cestino** si trova nella cartella **`$Recycle.bin`** nella root dell'unità (`C:\$Recycle.bin`).\
Quando un file viene eliminato in questa cartella, vengono creati 2 file specifici:

- `$I{id}`: Informazioni sul file (data in cui è stato eliminato}
- `$R{id}`: Contenuto del file

![Backup dei file - Cestino: $R{id}: Contenuto del file](<../../../images/image (1029).png>)

Con questi file è possibile utilizzare lo strumento [**Rifiuti**](https://github.com/abelcheung/rifiuti2) per ottenere il percorso originale dei file eliminati e la data in cui sono stati eliminati (utilizzare `rifiuti-vista.exe` per Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy è una tecnologia inclusa in Microsoft Windows che può creare **copie di backup** o snapshot di file o volumi del computer, anche quando sono in uso.

Questi backup si trovano generalmente in `\System Volume Information`, nella radice del file system, e il nome è composto da **UID**, come mostrato nell'immagine seguente:

![Recycle Bin - Volume Shadow Copies: Questi backup si trovano generalmente in System Volume Information, nella radice del file system, e il nome è composto da UID, come mostrato nell'immagine...](<../../../images/image (94).png>)

Montando l'immagine forense con **ArsenalImageMounter**, è possibile utilizzare lo strumento [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) per esaminare una shadow copy e persino **estrarre i file** dai backup della shadow copy.

![Recycle Bin - Volume Shadow Copies: Montando l'immagine forense con ArsenalImageMounter, è possibile utilizzare lo strumento ShadowCopyView per esaminare una shadow copy e persino estrarre i file...](<../../../images/image (576).png>)

La voce di registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contiene i file e le chiavi **da non sottoporre a backup**:

![Recycle Bin - Volume Shadow Copies: La voce di registro HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contiene i file e le chiavi da non sottoporre a backup](<../../../images/image (254).png>)

Il registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contiene inoltre informazioni di configurazione sulle `Volume Shadow Copies`.

### Office AutoSaved Files

È possibile trovare i file salvati automaticamente da Office in: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Un shell item è un elemento che contiene informazioni su come accedere a un altro file.

### Recent Documents (LNK)

Windows **crea** **automaticamente** queste **scorciatoie** quando l'utente **apre, utilizza o crea un file** in:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Quando viene creata una cartella, vengono creati anche un collegamento alla cartella, alla cartella padre e alla cartella nonna.

Questi file di collegamento creati automaticamente **contengono informazioni sull'origine**, come l'indicazione che si tratta di un **file** **o** di una **cartella**, gli orari **MAC** del file, le informazioni sul **volume** in cui è archiviato il file e la **cartella del file di destinazione**. Queste informazioni possono essere utili per recuperare tali file nel caso in cui siano stati rimossi.

Inoltre, la **data di creazione del collegamento** è il primo **momento** in cui il file originale è stato **utilizzato** per la **prima** volta, mentre la **data** di **modifica** del file di collegamento è l'ultimo **momento** in cui il file di origine è stato utilizzato.

Per esaminare questi file è possibile utilizzare [**LinkParser**](http://4discovery.com/our-tools/).

In questo strumento sono disponibili **2 gruppi** di timestamp:

- **First Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Second Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Il primo gruppo di timestamp fa riferimento ai **timestamp del file stesso**. Il secondo gruppo fa riferimento ai **timestamp del file collegato**.

È possibile ottenere le stesse informazioni eseguendo lo strumento CLI di Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In questo caso, le informazioni verranno salvate all'interno di un file CSV.

### Jumplists

Questi sono i file recenti indicati per ogni applicazione. È l'elenco dei **file recenti utilizzati da un'applicazione** a cui è possibile accedere da ogni applicazione. Possono essere creati **automaticamente o manualmente**.

I **jumplists** creati automaticamente sono memorizzati in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. I jumplists vengono denominati secondo il formato `{id}.autmaticDestinations-ms`, dove l'ID iniziale è l'ID dell'applicazione.

I jumplists personalizzati sono memorizzati in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` e vengono creati dall'applicazione, generalmente perché è accaduto qualcosa di **importante** al file (ad esempio, è stato contrassegnato come preferito).

Il **tempo di creazione** di qualsiasi jumplist indica la **prima volta in cui il file è stato utilizzato**, mentre il **tempo di modifica indica l'ultima volta**.

È possibile ispezionare i jumplists utilizzando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Recent Documents (LNK) - Jumplists: è possibile ispezionare i jumplists utilizzando JumplistExplorer](<../../../images/image (168).png>)

(_Nota: i timestamp forniti da JumplistExplorer sono relativi al file jumplist stesso_)

### Shellbags

[**Segui questo link per scoprire cosa sono gli shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilizzo di dispositivi USB su Windows

È possibile identificare se un dispositivo USB è stato utilizzato grazie alla creazione di:

- Cartella Windows Recent
- Cartella Microsoft Office Recent
- Jumplists

Nota che alcuni file LNK, invece di puntare al percorso originale, puntano alla cartella WPDNSE:

![Shellbags - Utilizzo di dispositivi USB su Windows: nota che alcuni file LNK, invece di puntare al percorso originale, puntano alla cartella WPDNSE](<../../../images/image (218).png>)

I file nella cartella WPDNSE sono copie degli originali, quindi non sopravvivono al riavvio del PC e il GUID viene ricavato da uno shellbag.

### Informazioni del Registry

[Consulta questa pagina per scoprire](interesting-windows-registry-keys.md#usb-information) quali chiavi del Registry contengono informazioni interessanti sui dispositivi USB collegati.

### setupapi

Controlla il file `C:\Windows\inf\setupapi.dev.log` per ottenere i timestamp relativi al momento in cui è stata stabilita la connessione USB (cerca `Section start`).

![Informazioni del Registry - setupapi: controlla il file C: Windows inf setupapi.dev.log per ottenere i timestamp relativi al momento in cui è stata stabilita la connessione USB (cerca Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) può essere utilizzato per ottenere informazioni sui dispositivi USB che sono stati collegati a un'immagine.

![setupapi - USB Detective: USBDetective può essere utilizzato per ottenere informazioni sui dispositivi USB che sono stati collegati a un'immagine](<../../../images/image (452).png>)

### Plug and Play Cleanup

L'attività pianificata denominata 'Plug and Play Cleanup' è progettata principalmente per la rimozione delle versioni obsolete dei driver. Contrariamente al suo scopo dichiarato di mantenere la versione più recente del pacchetto driver, fonti online suggeriscono che prenda di mira anche i driver rimasti inattivi per 30 giorni. Di conseguenza, i driver dei dispositivi rimovibili che non sono stati collegati negli ultimi 30 giorni potrebbero essere eliminati.<sup>[[1]](#references)</sup>

L'attività si trova nel seguente percorso: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Uno screenshot che mostra il contenuto dell'attività è disponibile qui: ![USB Detective - Plug and Play Cleanup: l'attività si trova nel seguente percorso: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componenti e impostazioni principali dell'attività:**

- **pnpclean.dll**: questa DLL è responsabile dell'effettivo processo di pulizia.
- **UseUnifiedSchedulingEngine**: impostato su `TRUE`, indica l'utilizzo del motore generico di pianificazione delle attività.
- **MaintenanceSettings**:
- **Period ('P1M')**: indica a Task Scheduler di avviare mensilmente l'attività di pulizia durante la manutenzione automatica ordinaria.
- **Deadline ('P2M')**: indica a Task Scheduler, se l'attività non riesce per due mesi consecutivi, di eseguirla durante la manutenzione automatica di emergenza.

Questa configurazione garantisce la manutenzione e la pulizia regolari dei driver, prevedendo nuovi tentativi di esecuzione dell'attività in caso di errori consecutivi.

**Per ulteriori informazioni consulta:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Email

Le email contengono **2 parti interessanti: gli header e il contenuto** dell'email. Negli **header** è possibile trovare informazioni come:

- **Chi** ha inviato le email (indirizzo email, IP, mail server che hanno reindirizzato l'email)
- **Quando** è stata inviata l'email

Inoltre, negli header `References` e `In-Reply-To` è possibile trovare l'ID dei messaggi:

![Plug and Play Cleanup - Email: quando è stata inviata l'email](<../../../images/image (593).png>)

### Windows Mail App

Questa applicazione salva le email in formato HTML o testo. È possibile trovare le email nelle sottocartelle di `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Le email vengono salvate con estensione `.dat`.

I **metadata** delle email e i **contatti** si trovano all'interno del **database EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Modifica l'estensione** del file da `.vol` a `.edb` e potrai utilizzare lo strumento [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) per aprirlo. All'interno della tabella `Message` puoi visualizzare le email.

### Microsoft Outlook

Quando vengono utilizzati Exchange server o client Outlook, sono presenti alcuni header MAPI:

- `Mapi-Client-Submit-Time`: ora del sistema in cui è stata inviata l'email
- `Mapi-Conversation-Index`: numero di messaggi figli del thread e timestamp di ogni messaggio del thread
- `Mapi-Entry-ID`: identificatore del messaggio.
- `Mappi-Message-Flags` e `Pr_last_Verb-Executed`: informazioni sul client MAPI (messaggio letto? non letto? risposta inviata? reindirizzato? fuori sede?)

Nel client Microsoft Outlook, tutti i messaggi inviati/ricevuti, i dati dei contatti e quelli del calendario sono memorizzati in un file PST nei percorsi:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Il percorso del Registry `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica il file in uso.

È possibile aprire il file PST utilizzando lo strumento [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: è possibile aprire il file PST utilizzando lo strumento Kernel PST Viewer](<../../../images/image (498).png>)

### File OST di Microsoft Outlook

Un **file OST** viene generato da Microsoft Outlook quando è configurato con un server **IMAP** o **Exchange** e memorizza informazioni simili a quelle di un file PST. Questo file viene sincronizzato con il server e conserva i dati degli **ultimi 12 mesi**, fino a una **dimensione massima di 50 GB**; si trova nella stessa directory del file PST. Per visualizzare un file OST è possibile utilizzare [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recupero degli allegati

Gli allegati persi potrebbero essere recuperabili da:

- Per **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Per **IE11 e versioni successive**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### File MBOX di Thunderbird

**Thunderbird** utilizza **file MBOX** per memorizzare i dati, situati in `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniature delle immagini

- **Windows XP e 8-8.1**: l'accesso a una cartella contenente miniature genera un file `thumbs.db` che memorizza le anteprime delle immagini, anche dopo la loro eliminazione.
- **Windows 7/10**: `thumbs.db` viene creato quando si accede alla cartella tramite una rete utilizzando un percorso UNC.
- **Windows Vista e versioni successive**: le anteprime delle miniature sono centralizzate in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, con file denominati **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) e [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sono strumenti per visualizzare questi file.

### Informazioni del Windows Registry

Il Windows Registry, che memorizza una grande quantità di dati sulle attività del sistema e degli utenti, è contenuto nei file situati in:

- `%windir%\System32\Config` per varie sottochiavi di `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` per `HKEY_CURRENT_USER`.
- Windows Vista e versioni successive eseguono il backup dei file del Registry di `HKEY_LOCAL_MACHINE` in `%Windir%\System32\Config\RegBack\`.
- Inoltre, le informazioni sull'esecuzione dei programmi sono memorizzate in `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` da Windows Vista e Windows 2008 Server in poi.

### Strumenti

Alcuni strumenti sono utili per analizzare i file del Registry:

- **Registry Editor**: è installato in Windows. È una GUI per navigare nel Registry Windows della sessione corrente.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): consente di caricare il file del Registry e navigare al suo interno tramite una GUI. Contiene inoltre Bookmark che evidenziano le chiavi con informazioni interessanti.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): dispone anch'esso di una GUI che consente di navigare nel Registry caricato e contiene anche plugin che evidenziano le informazioni interessanti presenti nel Registry caricato.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): un'altra applicazione GUI in grado di estrarre le informazioni importanti dal Registry caricato.

### Recupero degli elementi eliminati

Quando una chiave viene eliminata, viene contrassegnata come tale, ma finché lo spazio che occupa non è necessario, non viene rimossa. Pertanto, utilizzando strumenti come **Registry Explorer** è possibile recuperare queste chiavi eliminate.

### Last Write Time

Ogni coppia chiave-valore contiene un **timestamp** che indica l'ultima volta in cui è stata modificata.

### SAM

Il file/hive **SAM** contiene gli hash delle **password degli utenti e degli utenti appartenenti ai gruppi** del sistema.

In `SAM\Domains\Account\Users` è possibile ottenere il nome utente, il RID, l'ultimo accesso, l'ultimo accesso non riuscito, il contatore degli accessi, la policy delle password e la data di creazione dell'account. Per ottenere gli **hash** è inoltre **necessario** il file/hive **SYSTEM**.

### Voci interessanti nel Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programmi eseguiti

### Processi Windows di base

In [questo post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) puoi scoprire quali sono i processi Windows comuni da utilizzare per rilevare comportamenti sospetti.<sup>[[2]](#references)</sup>

### App recenti di Windows

Nel Registry `NTUSER.DAT`, al percorso `Software\Microsoft\Current Version\Search\RecentApps`, puoi trovare sottochiavi contenenti informazioni sull'**applicazione eseguita**, sull'**ultima volta** in cui è stata eseguita e sul **numero di volte** in cui è stata avviata.

### BAM (Background Activity Moderator)

Puoi aprire il file `SYSTEM` con un Registry editor e, all'interno del percorso `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, trovare informazioni sulle **applicazioni eseguite da ciascun utente** (nota `{SID}` nel percorso) e sull'**ora** in cui sono state eseguite (l'ora si trova nel valore Data del Registry).

### Windows Prefetch

Il prefetching è una tecnica che consente a un computer di **recuperare silenziosamente le risorse necessarie per visualizzare contenuti** a cui un utente **potrebbe accedere nel prossimo futuro**, in modo che le risorse possano essere accessibili più rapidamente.

Il prefetch di Windows consiste nella creazione di **cache dei programmi eseguiti** per poterli caricare più velocemente. Queste cache vengono create come file `.pf` nel percorso `C:\Windows\Prefetch`. Esiste un limite di 128 file in XP/VISTA/WIN7 e di 1024 file in Win8/Win10.

Il nome del file viene creato nel formato `{program_name}-{hash}.pf` (l'hash si basa sul percorso e sugli argomenti dell'eseguibile). In W10 questi file sono compressi. Nota che la semplice presenza del file indica che **il programma è stato eseguito** in un determinato momento.

Il file `C:\Windows\Prefetch\Layout.ini` contiene i **nomi delle cartelle dei file sottoposti a prefetch**. Questo file contiene **informazioni sul numero di esecuzioni**, sulle **date** di esecuzione e sui **file** **aperti** dal programma.

Per ispezionare questi file puoi utilizzare lo strumento [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** ha lo stesso obiettivo del prefetch: **caricare i programmi più velocemente** prevedendo cosa verrà caricato successivamente. Tuttavia, non sostituisce il servizio prefetch.\
Questo servizio genera file di database in `C:\Windows\Prefetch\Ag*.db`.

In questi database è possibile trovare il **nome** del **programma**, il **numero** di **esecuzioni**, i **file** **aperti**, il **volume** **accessed**, il **percorso** **completo**, gli **intervalli temporali** e i **timestamp**.

È possibile accedere a queste informazioni utilizzando lo strumento [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitora** le **risorse** **consumate** **da un processo**. È comparso in W8 e memorizza i dati in un database ESE situato in `C:\Windows\System32\sru\SRUDB.dat`.

Fornisce le seguenti informazioni:

- AppID e percorso
- Utente che ha eseguito il processo
- Byte inviati
- Byte ricevuti
- Interfaccia di rete
- Durata della connessione
- Durata del processo

Queste informazioni vengono aggiornate ogni 60 minuti.

È possibile ottenere la data da questo file utilizzando lo strumento [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, noto anche come **ShimCache**, fa parte dell'**Application Compatibility Database** sviluppato da **Microsoft** per affrontare i problemi di compatibilità delle applicazioni. Questo componente del sistema registra diversi dati sui metadati dei file, tra cui:

- Percorso completo del file
- Dimensioni del file
- Ora dell'ultima modifica in **$Standard_Information** (SI)
- Ora dell'ultimo aggiornamento della ShimCache
- Flag di esecuzione del processo

Questi dati vengono archiviati nel registro in posizioni specifiche in base alla versione del sistema operativo:

- Per XP, i dati sono archiviati in `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, con una capacità di 96 voci.
- Per Server 2003, così come per le versioni Windows 2008, 2012, 2016, 7, 8 e 10, il percorso di archiviazione è `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`, con una capacità rispettivamente di 512 e 1024 voci.

Per analizzare le informazioni archiviate, si consiglia di utilizzare lo [strumento **AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): per analizzare le informazioni archiviate, si consiglia di utilizzare lo strumento AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Il file **Amcache.hve** è essenzialmente un hive del registro che registra i dettagli sulle applicazioni eseguite su un sistema. Solitamente si trova in `C:\Windows\AppCompat\Programas\Amcache.hve`.

Questo file è importante perché archivia i record dei processi eseguiti di recente, inclusi i percorsi dei file eseguibili e i relativi hash SHA1. Queste informazioni sono preziose per tracciare l'attività delle applicazioni su un sistema.

Per estrarre e analizzare i dati da **Amcache.hve**, è possibile utilizzare lo strumento [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Il comando seguente mostra un esempio di utilizzo di AmcacheParser per analizzare il contenuto del file **Amcache.hve** e produrre i risultati in formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Tra i file CSV generati, `Amcache_Unassociated file entries` è particolarmente degno di nota per la ricchezza delle informazioni che fornisce sulle voci di file non associate.

Il file CSV generato più interessante è `Amcache_Unassociated file entries`.

### RecentFileCache

Questo artifact può essere trovato solo in W7, nel percorso `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, e contiene informazioni sull'esecuzione recente di alcuni binary.

È possibile utilizzare lo strumento [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) per analizzare il file.

### Scheduled tasks

È possibile estrarli da `C:\Windows\Tasks` o `C:\Windows\System32\Tasks` e leggerli come XML.

### Services

È possibile trovarli nel registry, in `SYSTEM\ControlSet001\Services`. È possibile verificare cosa verrà eseguito e quando.

### **Windows Store**

Le applicazioni installate possono essere trovate in `\ProgramData\Microsoft\Windows\AppRepository`\
Questo repository contiene un **log** con **ogni applicazione installata** nel sistema, all'interno del database **`StateRepository-Machine.srd`**.

All'interno della tabella Application di questo database è possibile trovare le colonne: "Application ID", "PackageNumber" e "Display Name". Queste colonne contengono informazioni sulle applicazioni preinstallate e installate; è possibile verificare se alcune applicazioni sono state disinstallate, poiché gli ID delle applicazioni installate dovrebbero essere sequenziali.

È inoltre possibile **trovare le applicazioni installate** nel percorso del registry: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`\
E le **applicazioni** **disinstallate** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventi di Windows

Le informazioni che compaiono negli eventi di Windows sono:

- Cosa è accaduto
- Timestamp (UTC + 0)
- Utenti coinvolti
- Host coinvolti (hostname, IP)
- Asset a cui è stato effettuato l'accesso (file, cartelle, stampanti, servizi)

I log si trovano in `C:\Windows\System32\config` prima di Windows Vista e in `C:\Windows\System32\winevt\Logs` dopo Windows Vista. Prima di Windows Vista, i log degli eventi erano in formato binario; successivamente sono in **formato XML** e utilizzano l'estensione **.evtx**.

La posizione dei file degli eventi può essere trovata nel registry SYSTEM, in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Possono essere visualizzati tramite Windows Event Viewer (**`eventvwr.msc`**) o con altri strumenti come [**Event Log Explorer**](https://eventlogxp.com) **o** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprendere la registrazione degli eventi di sicurezza di Windows

Gli eventi di accesso vengono registrati nel file di configurazione della sicurezza situato in `C:\Windows\System32\winevt\Security.evtx`. La dimensione di questo file è configurabile e, quando viene raggiunta la capacità massima, gli eventi più vecchi vengono sovrascritti. Gli eventi registrati includono login e logoff degli utenti, azioni degli utenti e modifiche alle impostazioni di sicurezza, nonché accessi a file, cartelle e asset condivisi.

### ID degli eventi principali per l'autenticazione degli utenti:

- **EventID 4624**: indica che un utente ha completato correttamente l'autenticazione.
- **EventID 4625**: segnala un'autenticazione non riuscita.
- **EventIDs 4634/4647**: rappresentano gli eventi di logoff degli utenti.
- **EventID 4672**: indica un login con privilegi amministrativi.

#### Sotto-tipi all'interno di EventID 4634/4647:

- **Interactive (2)**: login diretto dell'utente.
- **Network (3)**: accesso a cartelle condivise.
- **Batch (4)**: esecuzione di processi batch.
- **Service (5)**: avvio di servizi.
- **Proxy (6)**: autenticazione tramite proxy.
- **Unlock (7)**: schermata sbloccata con una password.
- **Network Cleartext (8)**: trasmissione della password in chiaro, spesso da IIS.
- **New Credentials (9)**: utilizzo di credenziali diverse per l'accesso.
- **Remote Interactive (10)**: login tramite remote desktop o terminal services.
- **Cache Interactive (11)**: login con credenziali memorizzate nella cache, senza contattare il domain controller.
- **Cache Remote Interactive (12)**: login remoto con credenziali memorizzate nella cache.
- **Cached Unlock (13)**: sblocco con credenziali memorizzate nella cache.

#### Codici di stato e sottostato per EventID 4625:

- **0xC0000064**: il nome utente non esiste - potrebbe indicare un username enumeration attack.
- **0xC000006A**: nome utente corretto ma password errata - possibile password guessing o tentativo di brute-force.
- **0xC0000234**: account utente bloccato - potrebbe verificarsi dopo un brute-force attack che ha causato numerosi login non riusciti.
- **0xC0000072**: account disabilitato - tentativi non autorizzati di accedere ad account disabilitati.
- **0xC000006F**: login al di fuori dell'orario consentito - indica tentativi di accesso al di fuori degli orari configurati, possibile segnale di accesso non autorizzato.
- **0xC0000070**: violazione delle restrizioni della workstation - potrebbe trattarsi di un tentativo di login da una posizione non autorizzata.
- **0xC0000193**: account scaduto - tentativi di accesso con account utente scaduti.
- **0xC0000071**: password scaduta - tentativi di login con password obsolete.
- **0xC0000133**: problemi di sincronizzazione dell'orario - differenze temporali elevate tra client e server possono indicare attack più sofisticati, come pass-the-ticket.
- **0xC0000224**: è obbligatorio modificare la password - modifiche obbligatorie frequenti potrebbero indicare un tentativo di destabilizzare la sicurezza dell'account.
- **0xC0000225**: indica un bug di sistema piuttosto che un problema di sicurezza.
- **0xC000015b**: tipo di login negato - tentativo di accesso con un tipo di login non autorizzato, ad esempio un utente che tenta di eseguire un login del servizio.

#### EventID 4616:

- **Time Change**: modifica dell'orario di sistema, che potrebbe oscurare la timeline degli eventi.

#### EventID 6005 e 6006:

- **System Startup and Shutdown**: EventID 6005 indica l'avvio del sistema, mentre EventID 6006 ne indica l'arresto.

#### EventID 1102:

- **Log Deletion**: cancellazione dei security log, spesso un chiaro segnale di tentativi di occultare attività illecite.

#### EventIDs per il tracking dei dispositivi USB:

- **20001 / 20003 / 10000**: prima connessione del dispositivo USB.
- **10100**: aggiornamento del driver USB.
- **EventID 112**: momento dell'inserimento del dispositivo USB.

Per esempi pratici sulla simulazione di questi tipi di login e sulle opportunità di credential dumping, consultare la guida dettagliata di [Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

I dettagli degli eventi, inclusi i codici di stato e sottostato, forniscono ulteriori informazioni sulle cause degli eventi, particolarmente utili nel caso dell'Event ID 4625.

### Recupero degli eventi di Windows

Per aumentare le probabilità di recuperare eventi di Windows eliminati, è consigliabile spegnere il computer sospetto scollegandolo direttamente dall'alimentazione. **Bulk_extractor**, uno strumento di recupero configurato per l'estensione `.evtx`, è consigliato per tentare di recuperare tali eventi.

### Identificare gli attack comuni tramite gli eventi di Windows

Per una guida completa sull'utilizzo degli Event ID di Windows nell'identificazione dei comuni cyber attack, visitare [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Identificabili dalla presenza di più record EventID 4625, seguiti da un EventID 4624 se l'attacco ha successo.

#### Time Change

Registrati da EventID 4616, i cambiamenti dell'orario di sistema possono complicare l'analisi forense.

#### USB Device Tracking

Gli EventID di sistema utili per il tracking dei dispositivi USB includono 20001/20003/10000 per il primo utilizzo, 10100 per gli aggiornamenti dei driver ed EventID 112 di DeviceSetupManager per i timestamp di inserimento.

#### System Power Events

EventID 6005 indica l'avvio del sistema, mentre EventID 6006 ne indica l'arresto.

#### Log Deletion

Il Security EventID 1102 segnala la cancellazione dei log, un evento critico per l'analisi forense.

## Riferimenti

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
