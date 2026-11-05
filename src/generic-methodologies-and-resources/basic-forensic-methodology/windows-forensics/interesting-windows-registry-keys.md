# Chiavi interessanti del registro di Windows

{{#include ../../../banners/hacktricks-training.md}}

Gli hive del registro di Windows sono uno dei modi più rapidi per passare da _che cosa è successo?_ a _quale utente, quando e da dove?_. Per l'analisi live, preferisci `CurrentControlSet`; per l'analisi offline degli hive, determina prima quale `ControlSet00x` era attivo invece di usare `ControlSet001` come valore fisso.

### Informazioni sulla versione di Windows e sul proprietario

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edizione/build di Windows, ora di installazione, proprietario registrato, nome del prodotto e altri metadati della build.
- `SYSTEM\Select`: associa `Current`, `Default` e `LastKnownGood` ai valori `ControlSet00x` effettivi usati dal sistema.

### Nome del computer

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname corrente.

### Impostazione del fuso orario

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: fuso orario configurato e valori relativi all'ora legale.

### Tracciamento degli orari di accesso

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indica se vengono aggiornati gli orari di ultimo accesso NTFS.
- Per abilitarlo, usa: `fsutil behavior set disablelastaccess 0`

### Dettagli di arresto

- `SYSTEM\CurrentControlSet\Control\Windows`: ora dell'ultimo arresto.
- Anche i sistemi meno recenti potrebbero esporre contatori di arresto in `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Configurazione di rete

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP delle interfacce, lease DHCP, dati di gateway e DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nome del profilo di rete/SSID e orari della prima e dell'ultima connessione.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` e `...\Unmanaged\{GUID}`: dati di correlazione dei profili, come l'indirizzo MAC del gateway e il suffisso DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: cartelle condivise locali pubblicate dall'host.

### Accesso remoto e cronologia delle condivisioni di rete

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: elenco MRU delle connessioni RDP in uscita (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: cronologia RDP in uscita per host. Le sottochiavi contengono comunemente `UsernameHint`; l'ora `LastWrite` della chiave è un utile punto di correlazione.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: unità di rete mappate, condivisioni UNC e punti di montaggio di supporti rimovibili associati a un utente specifico.

### Programmi avviati automaticamente e persistenza tramite attività pianificate

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` e `...\Tasks\{GUID}`: metadati delle attività pianificate. Se qui è presente un'attività ma manca il valore `SD` da `Tree\<TaskName>`, sospetta una manomissione dell'attività in stile Tarrask e confronta i dati con `C:\Windows\System32\Tasks\<TaskName>`.

### Ricerche, percorsi digitati e MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: termini di ricerca in Esplora file.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: percorsi di Esplora file digitati manualmente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: gli ultimi 26 comandi `Win + R`. `MRUList` ne conserva l'ordine.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documenti e cartelle aperti di recente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: file recenti di Office.

### Tracciamento dell'attività utente

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: cronologia delle esecuzioni avviate tramite GUI. I nomi dei valori sono codificati con ROT13 e i dati binari includono contatori di esecuzione e l'ora dell'ultima esecuzione.<sup>[[1]](#references)</sup>
- Considera `UserAssist` un riscontro a supporto di altri elementi, non una prova conclusiva: tiene traccia principalmente di app o file `.lnk` avviati tramite Esplora file e potrebbe non rilevare esecuzioni da riga di comando o tramite servizi. In Windows 10 e versioni successive, alcune voci non indicano necessariamente che il processo sia stato eseguito completamente.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` e `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: tracce di esecuzione nelle versioni moderne di Windows 10/11, con attribuzione SID e ora dell'ultima esecuzione. Sono particolarmente utili per i binari eseguiti localmente, ma le voci meno recenti possono essere eliminate rapidamente e le esecuzioni da condivisioni di rete o supporti rimovibili sono meno affidabili.
- Per artefatti di esecuzione più ampi, come Prefetch, Amcache, ShimCache e SRUM, consulta la [panoramica principale sull'analisi forense di Windows](./#programs-executed).

### Shellbag

- Gli shellbag sono archiviati sia in `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` sia in `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Le voci di `NTUSER.DAT` sono particolarmente utili per la navigazione UNC/di rete, mentre in `UsrClass.dat` Windows Vista e versioni successive archiviano comunemente gli shellbag delle cartelle locali/rimovibili.
- Possono indicare l'esistenza di cartelle, la navigazione al loro interno e le preferenze di visualizzazione, anche dopo l'eliminazione della cartella. L'accesso a file di archivio tramite Esplora file o strumenti simili può lasciare tracce negli shellbag.<sup>[[1]](#references)</sup>
- Non tutti gli shellbag dimostrano che una cartella sia stata aperta correttamente, quindi verifica con LNK, Jump List, timestamp o mappature dei volumi.
- Usa **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** o **SBECmd** per analizzarli.

### Informazioni sulle periferiche USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventario principale dei dispositivi USB di archiviazione di massa (produttore, prodotto, revisione, numero di serie/istanza del dispositivo).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventario più ampio dei dispositivi USB, compresi quelli non di archiviazione.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: nelle versioni recenti di Windows 10/11 è un punto di grande interesse per i timestamp del ciclo di vita del singolo dispositivo, come installazione, prima installazione, ultimo collegamento e ultima rimozione.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: associa volumi e identificatori dei dispositivi a lettere di unità / GUID di volume. Potrebbe sopravvivere solo l'ultima associazione per una determinata lettera di unità.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: utile per la correlazione con numeri di serie dei volumi e metadati dei supporti precedenti.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: cronologia delle interazioni specifica dell'utente con lettere di unità e condivisioni.<sup>[[2]](#references)</sup>
- Telefoni e tablet moderni collegati tramite MTP/PTP potrebbero **non** comparire in `USBSTOR`. Controlla anche `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` e `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Per associare un dispositivo a un utente, usa gli identificatori del dispositivo o del volume per risalire agli artefatti specifici dell'utente, come shellbag, LNK, Jump List, `RecentDocs` e `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Promemoria di analisi forense del registro di Windows 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Analisi forense dei dispositivi USB su Windows 10 e 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
