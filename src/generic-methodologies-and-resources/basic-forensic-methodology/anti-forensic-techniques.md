# Tecniche Anti-Forensi

{{#include ../../banners/hacktricks-training.md}}

## Timestamp

Un attaccante potrebbe essere interessato a **cambiare i timestamp dei file** per evitare di essere rilevato.\
È possibile trovare i timestamp all'interno del MFT negli attributi `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Entrambi gli attributi hanno 4 timestamp: **Modifica**, **accesso**, **creazione** e **modifica del registro MFT** (MACE o MACB).

**Windows explorer** e altri strumenti mostrano le informazioni da **`$STANDARD_INFORMATION`**.

### TimeStomp - Strumento anti-forense

Questo strumento **modifica** le informazioni sui timestamp all'interno di **`$STANDARD_INFORMATION`** **ma** **non** le informazioni all'interno di **`$FILE_NAME`**. Pertanto, è possibile **identificare** **attività** **sospette**.

### Usnjrnl

Il **USN Journal** (Update Sequence Number Journal) è una funzionalità del NTFS (sistema di file Windows NT) che tiene traccia delle modifiche al volume. Lo strumento [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) consente di esaminare queste modifiche.

![](<../../images/image (801).png>)

L'immagine precedente è l'**output** mostrato dallo **strumento** dove si può osservare che alcune **modifiche sono state effettuate** al file.

### $LogFile

**Tutte le modifiche ai metadati di un file system sono registrate** in un processo noto come [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). I metadati registrati sono conservati in un file chiamato `**$LogFile**`, situato nella directory radice di un file system NTFS. Strumenti come [LogFileParser](https://github.com/jschicht/LogFileParser) possono essere utilizzati per analizzare questo file e identificare le modifiche.

![](<../../images/image (137).png>)

Ancora una volta, nell'output dello strumento è possibile vedere che **alcune modifiche sono state effettuate**.

Utilizzando lo stesso strumento è possibile identificare **a quale ora i timestamp sono stati modificati**:

![](<../../images/image (1089).png>)

- CTIME: Ora di creazione del file
- ATIME: Ora di modifica del file
- MTIME: Modifica del registro MFT del file
- RTIME: Ora di accesso del file

### Confronto tra `$STANDARD_INFORMATION` e `$FILE_NAME`

Un altro modo per identificare file modificati sospetti sarebbe confrontare il tempo su entrambi gli attributi cercando **discrepanze**.

### Nanosecondi

I timestamp **NTFS** hanno una **precisione** di **100 nanosecondi**. Quindi, trovare file con timestamp come 2010-10-10 10:10:**00.000:0000 è molto sospetto**.

### SetMace - Strumento anti-forense

Questo strumento può modificare entrambi gli attributi `$STARNDAR_INFORMATION` e `$FILE_NAME`. Tuttavia, a partire da Windows Vista, è necessario un OS live per modificare queste informazioni.

## Nascondere Dati

NFTS utilizza un cluster e la dimensione minima delle informazioni. Ciò significa che se un file occupa e utilizza un cluster e mezzo, il **mezzo rimanente non verrà mai utilizzato** fino a quando il file non viene eliminato. Quindi, è possibile **nascondere dati in questo spazio di slack**.

Ci sono strumenti come slacker che consentono di nascondere dati in questo spazio "nascosto". Tuttavia, un'analisi del `$logfile` e del `$usnjrnl` può mostrare che alcuni dati sono stati aggiunti:

![](<../../images/image (1060).png>)

Quindi, è possibile recuperare lo spazio di slack utilizzando strumenti come FTK Imager. Nota che questo tipo di strumento può salvare il contenuto offuscato o persino crittografato.

## UsbKill

Questo è uno strumento che **spegnerà il computer se viene rilevata qualsiasi modifica nelle porte USB**.\
Un modo per scoprirlo sarebbe ispezionare i processi in esecuzione e **rivedere ogni script python in esecuzione**.

## Distribuzioni Linux Live

Queste distro sono **eseguite all'interno della memoria RAM**. L'unico modo per rilevarle è **nel caso in cui il file system NTFS sia montato con permessi di scrittura**. Se è montato solo con permessi di lettura, non sarà possibile rilevare l'intrusione.

## Cancellazione Sicura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configurazione di Windows

È possibile disabilitare diversi metodi di registrazione di Windows per rendere l'indagine forense molto più difficile.

### Disabilitare Timestamp - UserAssist

Questa è una chiave di registro che mantiene date e ore in cui ciascun eseguibile è stato eseguito dall'utente.

Disabilitare UserAssist richiede due passaggi:

1. Impostare due chiavi di registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, entrambe a zero per segnalare che vogliamo disabilitare UserAssist.
2. Cancellare i tuoi sottoalberi di registro che sembrano `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disabilitare Timestamp - Prefetch

Questo salverà informazioni sulle applicazioni eseguite con l'obiettivo di migliorare le prestazioni del sistema Windows. Tuttavia, questo può essere utile anche per pratiche forensi.

- Eseguire `regedit`
- Selezionare il percorso del file `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Fare clic con il tasto destro su `EnablePrefetcher` e `EnableSuperfetch`
- Selezionare Modifica su ciascuno di questi per cambiare il valore da 1 (o 3) a 0
- Riavviare

### Disabilitare Timestamp - Ultimo Tempo di Accesso

Ogni volta che una cartella viene aperta da un volume NTFS su un server Windows NT, il sistema prende il tempo per **aggiornare un campo di timestamp su ciascuna cartella elencata**, chiamato ultimo tempo di accesso. Su un volume NTFS molto utilizzato, questo può influenzare le prestazioni.

1. Aprire l'Editor del Registro (Regedit.exe).
2. Navigare a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Cercare `NtfsDisableLastAccessUpdate`. Se non esiste, aggiungere questo DWORD e impostare il suo valore a 1, il che disabiliterà il processo.
4. Chiudere l'Editor del Registro e riavviare il server.

### Eliminare la Cronologia USB

Tutti gli **USB Device Entries** sono memorizzati nel Registro di Windows sotto la chiave di registro **USBSTOR** che contiene sottochiavi create ogni volta che si collega un dispositivo USB al PC o Laptop. Puoi trovare questa chiave qui `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Eliminando questo** eliminerai la cronologia USB.\
Puoi anche utilizzare lo strumento [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) per essere sicuro di averle eliminate (e per eliminarle).

Un altro file che salva informazioni sugli USB è il file `setupapi.dev.log` all'interno di `C:\Windows\INF`. Questo dovrebbe essere eliminato.

### Disabilitare le Copie Shadow

**Elenca** le copie shadow con `vssadmin list shadowstorage`\
**Eliminale** eseguendo `vssadmin delete shadow`

Puoi anche eliminarle tramite GUI seguendo i passaggi proposti in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Per disabilitare le copie shadow [passaggi da qui](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Aprire il programma Servizi digitando "servizi" nella casella di ricerca dopo aver cliccato sul pulsante di avvio di Windows.
2. Dall'elenco, trovare "Volume Shadow Copy", selezionarlo e quindi accedere alle Proprietà facendo clic con il tasto destro.
3. Scegliere Disabilitato dal menu a discesa "Tipo di avvio" e quindi confermare la modifica facendo clic su Applica e OK.

È anche possibile modificare la configurazione di quali file verranno copiati nella copia shadow nel registro `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sovrascrivere file eliminati

- Puoi utilizzare uno **strumento di Windows**: `cipher /w:C` Questo indicherà a cipher di rimuovere qualsiasi dato dallo spazio su disco inutilizzato disponibile all'interno dell'unità C.
- Puoi anche utilizzare strumenti come [**Eraser**](https://eraser.heidi.ie)

### Eliminare i registri eventi di Windows

- Windows + R --> eventvwr.msc --> Espandi "Registri di Windows" --> Fai clic con il tasto destro su ciascuna categoria e seleziona "Cancella registro"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disabilitare i registri eventi di Windows

- `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
- All'interno della sezione servizi disabilitare il servizio "Windows Event Log"
- `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

### Disabilitare $UsnJrnl

- `fsutil usn deletejournal /d c:`

{{#include ../../banners/hacktricks-training.md}}
