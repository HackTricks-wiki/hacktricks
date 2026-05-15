# Chiavi interessanti del Windows Registry

{{#include ../../../banners/hacktricks-training.md}}

Gli hive del Windows Registry sono uno dei modi più rapidi per passare da _cosa è successo?_ a _quale user, quando, e da dove?_. Per l'analisi live preferisci `CurrentControlSet`; per l'analisi offline risolvi prima quale `ControlSet00x` era attivo invece di hardcodare `ControlSet001`.

### Versione di Windows e info sul proprietario

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edizione/build di Windows, install time, registered owner, product name e altri metadati della build.
- `SYSTEM\Select`: mappa `Current`, `Default` e `LastKnownGood` ai valori reali `ControlSet00x` usati dal sistema.

### Nome del computer

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname attuale.

### Impostazione del fuso orario

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: fuso orario configurato e valori legati al DST.

### Tracciamento dei tempi di accesso

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indica se gli timestamp dell'ultimo accesso di NTFS vengono aggiornati.
- Per abilitarlo, usa: `fsutil behavior set disablelastaccess 0`

### Dettagli di shutdown

- `SYSTEM\CurrentControlSet\Control\Windows`: ultimo time di shutdown.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: i sistemi più vecchi possono esporre anche contatori di shutdown.

### Configurazione di rete

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP dell'interfaccia, lease DHCP, gateway e dati DNS.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nome del network profile/SSID più i tempi del primo e dell'ultimo collegamento.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` e `...\Unmanaged\{GUID}`: dati di correlazione del profile come MAC address del gateway e DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: cartelle condivise locali pubblicate dall'host.

### Remote Access e cronologia delle network share

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: cronologia RDP outbound per host. Le subkey spesso memorizzano `UsernameHint`, e il tempo `LastWrite` della key è un pivot utile.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapped network drives, UNC shares e mount point di removable-media legati a un user specifico.

### Programmi che si avviano automaticamente e persistenza pianificata

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` e `...\Tasks\{GUID}`: metadati dei scheduled task. Se un task esiste qui ma il valore `SD` manca da `Tree\<TaskName>`, sospetta una modifica nascosta in stile Tarrask e correlala con `C:\Windows\System32\Tasks\<TaskName>`.

### Ricerche, Typed Paths e MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: termini di ricerca di File Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: percorsi inseriti manualmente in Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: gli ultimi 26 comandi `Win + R`. `MRUList` preserva il loro ordine.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documenti e cartelle aperti di recente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: file recenti di Office.

### Tracciamento dell'attività user

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: cronologia di esecuzione guidata dalla GUI. I nomi dei valori sono codificati in ROT13, e i dati binari includono contatori di esecuzione e last run time.
- Tratta `UserAssist` come forte evidenza di supporto, non come verdetto autonomo: traccia soprattutto app o file `.lnk` avviati tramite Explorer e può perdere esecuzioni da command-line o service. Su Windows 10+, alcune entry non significano necessariamente che il process sia stato eseguito بالكامل.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` e `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: tracce di esecuzione moderne di Windows 10/11 con attribuzione SID e last execution time. Sono particolarmente utili per binary eseguiti localmente, ma le entry più vecchie possono scadere rapidamente e le esecuzioni da network share/removable media sono meno affidabili.
- Per artifact di esecuzione più ampi come Prefetch, Amcache, ShimCache e SRUM, vedi la [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Le Shellbags sono memorizzate sia in `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` sia in `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- Le entry di `NTUSER.DAT` sono particolarmente utili per la navigazione UNC/network, mentre `UsrClass.dat` è dove Windows Vista+ normalmente memorizza le shellbags di cartelle locali/removable.
- Possono mostrare l'esistenza delle cartelle, la traversal e le preferenze di folder-view anche dopo che la cartella è stata cancellata. L'accesso in stile Explorer ai file archivio può anche lasciare tracce di shellbag.
- Non tutte le shellbag provano un accesso riuscito alla cartella, quindi corrobora con LNKs, Jump Lists, timestamps o volume mappings.
- Usa **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** o **SBECmd** per analizzarle.

### Informazioni USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventario principale dei dispositivi USB mass-storage (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventario USB più ampio, inclusi i dispositivi non-storage.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: su build recenti di Windows 10/11 è un punto ad alto valore per timestamp del lifecycle per-device come install, first install, last arrival e last removal.
- `HKLM\SYSTEM\MountedDevices`: mappa volumi e device identifier alle lettere di drive / volume GUID. Solo l'ultima mappatura per una data lettera di drive può sopravvivere.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivot utile per volume serial numbers e metadati dei media precedenti.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: cronologia specifica per user di interazione con drive-letter e share.
- Telefoni e tablet moderni connessi via MTP/PTP potrebbero **non** apparire sotto `USBSTOR`. Controlla anche `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` e `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
- Per collegare un dispositivo a un user, parti da device o volume identifiers e fai pivot verso artifact per-user come shellbags, LNKs, Jump Lists, `RecentDocs` e `MountPoints2`.



## Riferimenti

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
