# Chiavi interessanti del Registro di Windows

Gli hive del Registro di Windows sono uno dei modi più rapidi per passare da _cosa è successo?_ a _quale utente, quando e da dove?_. Per l'analisi live preferire `CurrentControlSet`; per l'analisi offline degli hive, prima determinare quale `ControlSet00x` era attivo invece di codificare direttamente `ControlSet001`.

### Versione di Windows e informazioni sul proprietario

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edizione/build di Windows, data di installazione, proprietario registrato, nome del prodotto e altri metadati della build.
- `SYSTEM\Select`: associa `Current`, `Default` e `LastKnownGood` ai valori reali di `ControlSet00x` utilizzati dal sistema.

### Nome del computer

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname corrente.

### Impostazione del fuso orario

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: fuso orario configurato e valori relativi all'ora legale.

### Monitoraggio degli orari di accesso

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indica se i timestamp dell'ultimo accesso NTFS vengono aggiornati.
- Per abilitarlo, usare: `fsutil behavior set disablelastaccess 0`

### Dettagli sull'arresto

- `SYSTEM\CurrentControlSet\Control\Windows`: ultimo orario di arresto.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: i sistemi meno recenti possono esporre anche i contatori degli arresti.

### Configurazione di rete

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP delle interfacce, lease DHCP, dati del gateway e DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nome del profilo di rete/SSID, oltre agli orari della prima e dell'ultima connessione.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` e `...\Unmanaged\{GUID}`: dati di correlazione del profilo, come indirizzo MAC del gateway e suffisso DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: cartelle condivise locali pubblicate dall'host.

### Accesso remoto e cronologia delle condivisioni di rete

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: elenco MRU delle connessioni RDP in uscita (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: cronologia RDP in uscita per host. Le sottochiavi contengono comunemente `UsernameHint`, mentre l'orario `LastWrite` della chiave è un pivot utile.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: unità di rete mappate, condivisioni UNC e punti di montaggio di supporti rimovibili associati a un utente specifico.

### Programmi avviati automaticamente e persistenza tramite attività pianificate

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` e `...\Tasks\{GUID}`: metadati delle attività pianificate. Se qui esiste un'attività ma il valore `SD` manca da `Tree\<TaskName>`, sospettare una manomissione delle attività in stile Tarrask e correlarla con `C:\Windows\System32\Tasks\<TaskName>`.

### Ricerche, percorsi digitati e MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: termini di ricerca di File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: percorsi di Explorer digitati manualmente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: gli ultimi 26 comandi `Win + R`. `MRUList` ne conserva l'ordine.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documenti e cartelle aperti di recente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: file recenti di Office.

### Monitoraggio dell'attività dell'utente

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: cronologia delle esecuzioni avviate tramite GUI. I nomi dei valori sono codificati in ROT13 e i dati binari includono i contatori di esecuzione e l'ultimo orario di esecuzione.<sup>[[1]](#references)</sup>
- Considerare `UserAssist` come una solida evidenza di supporto, non come una prova autonoma: tiene traccia principalmente delle app o dei file `.lnk` avviati tramite Explorer e può non rilevare le esecuzioni da riga di comando o tramite servizi. Su Windows 10 e versioni successive, alcune voci non implicano necessariamente che il processo sia stato eseguito completamente.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` e `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: tracce delle esecuzioni moderne di Windows 10/11 con attribuzione al SID e ultimo orario di esecuzione. Sono particolarmente utili per i binari eseguiti localmente, ma le voci meno recenti possono essere eliminate rapidamente e le esecuzioni da condivisioni di rete/supporti rimovibili sono meno affidabili.
- Per artefatti di esecuzione più ampi, come Prefetch, Amcache, ShimCache e SRUM, consultare la [panoramica della computer forensics su Windows](README.md#programs-executed).

### Shellbags

- Gli Shellbags sono memorizzati sia in `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`, sia in `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Le voci di `NTUSER.DAT` sono particolarmente utili per la navigazione UNC/di rete, mentre `UsrClass.dat` è il percorso in cui Windows Vista e versioni successive memorizzano comunemente gli Shellbags delle cartelle locali/rimovibili.
- Possono mostrare l'esistenza e l'attraversamento delle cartelle, oltre alle preferenze di visualizzazione, anche dopo l'eliminazione della cartella. L'accesso a file archivio tramite Explorer può inoltre lasciare tracce negli Shellbags.<sup>[[1]](#references)</sup>
- Non tutti gli Shellbag dimostrano un accesso riuscito alla cartella; correlarli quindi con LNK, Jump Lists, timestamp o mappature dei volumi.
- Usare **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** o **SBECmd** per analizzarli.

### Informazioni sui dispositivi USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventario principale dei dispositivi USB di archiviazione di massa (vendor, prodotto, revisione, numero di serie/istanza del dispositivo).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventario USB più ampio, inclusi i dispositivi non di archiviazione.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: nelle build recenti di Windows 10/11, è un punto di grande valore per i timestamp del ciclo di vita del singolo dispositivo, come installazione, prima installazione, ultimo collegamento e ultima rimozione.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: associa volumi e identificatori dei dispositivi alle lettere delle unità / GUID dei volumi. Potrebbe rimanere solo l'ultima mappatura per una determinata lettera di unità.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivot utile per i numeri di serie dei volumi e i metadati dei supporti precedenti.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: cronologia specifica dell'utente relativa alle interazioni con lettere di unità e condivisioni.<sup>[[2]](#references)</sup>
- I telefoni e tablet moderni connessi tramite MTP/PTP potrebbero **non** comparire in `USBSTOR`. Controllare anche `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` e `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Per associare un dispositivo a un utente, eseguire un pivot dagli identificatori del dispositivo o del volume verso artefatti specifici dell'utente, come Shellbags, LNK, Jump Lists, `RecentDocs` e `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cheat Sheet di computer forensics del Registro di Windows 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - Computer forensics dei dispositivi USB su Windows 10 e 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
