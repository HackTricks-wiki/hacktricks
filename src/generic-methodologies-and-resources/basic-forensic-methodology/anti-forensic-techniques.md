# Tecniche anti-forensi

{{#include ../../banners/hacktricks-training.md}}

## Timestamp

Un aggressore potrebbe voler **modificare i timestamp dei file** per evitare di essere rilevato.\
È possibile trovare i timestamp nell'MFT, negli attributi `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Entrambi gli attributi hanno 4 timestamp: **modifica**, **accesso**, **creazione** e **modifica del registro MFT** (MACE o MACB).

**Esplora file di Windows** e altri strumenti mostrano le informazioni di **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Questo strumento **modifica** le informazioni sui timestamp contenute in **`$STANDARD_INFORMATION`**, **ma non** quelle contenute in **`$FILE_NAME`**. È quindi possibile **identificare** **attività** **sospette**.

### Usnjrnl

L'**USN Journal** (Update Sequence Number Journal) è una funzionalità di NTFS (il file system di Windows NT) che tiene traccia delle modifiche al volume. Lo strumento [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) consente di esaminare queste modifiche.

![TimeStomp - Anti-forensic Tool - Usnjrnl: l'USN Journal (Update Sequence Number Journal) è una funzionalità di NTFS (il file system di Windows NT) che tiene traccia delle modifiche al volume. Lo...](<../../images/image (801).png>)

L'immagine precedente mostra l'**output** dello **strumento**, in cui si può osservare che sono state **apportate alcune modifiche** al file.

### $LogFile

**Tutte le modifiche ai metadati di un file system vengono registrate** tramite un processo noto come [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). I metadati registrati vengono conservati in un file denominato `**$LogFile**`, situato nella directory principale di un file system NTFS. È possibile usare strumenti come [LogFileParser](https://github.com/jschicht/LogFileParser) per analizzare questo file e identificare le modifiche.

![Usnjrnl - $LogFile: tutte le modifiche ai metadati di un file system vengono registrate tramite un processo noto come write-ahead logging. I metadati registrati vengono conservati in un file denominato $LogFile, situato nella directory principale...](<../../images/image (137).png>)

Anche in questo caso, dall'output dello strumento è possibile vedere che sono state **apportate alcune modifiche**.

Con lo stesso strumento è possibile identificare **a quale ora sono stati modificati i timestamp**:

![Usnjrnl - $LogFile: con lo stesso strumento è possibile identificare a quale ora sono stati modificati i timestamp](<../../images/image (1089).png>)

- CTIME: ora di creazione del file
- ATIME: ora di modifica del file
- MTIME: modifica del registro MFT del file
- RTIME: ora di accesso al file

### Confronto tra `$STANDARD_INFORMATION` e `$FILE_NAME`

Un altro modo per identificare file modificati in modo sospetto consiste nel confrontare gli orari presenti in entrambi gli attributi e cercare **incongruenze**.

### Nanosecondi

I timestamp **NTFS** hanno una **precisione** di **100 nanosecondi**. Pertanto, trovare file con timestamp come 2010-10-10 10:10:**00.000:0000 è molto sospetto**.

### SetMace - Anti-forensic Tool

Questo strumento può modificare entrambi gli attributi, `$STARNDAR_INFORMATION` e `$FILE_NAME`. Tuttavia, da Windows Vista, è necessario usare un sistema operativo attivo per modificare queste informazioni.

## Nascondere i dati

NFTS usa cluster e una dimensione minima per le informazioni. Ciò significa che, se un file occupa un cluster e mezzo, la **metà rimanente non verrà mai utilizzata** finché il file non viene eliminato. È quindi possibile **nascondere dati in questo spazio slack**.

Esistono strumenti come slacker che permettono di nascondere dati in questo spazio "nascosto". Tuttavia, un'analisi di `$logfile` e `$usnjrnl` può mostrare che sono stati aggiunti dei dati:

![SetMace - Anti-forensic Tool - Nascondere i dati: esistono strumenti come slacker che permettono di nascondere dati in questo spazio "nascosto". Tuttavia, un'analisi di $logfile e $usnjrnl può mostrare che...](<../../images/image (1060).png>)

È quindi possibile recuperare lo spazio slack con strumenti come FTK Imager. Nota che questo tipo di strumento può salvare il contenuto offuscato o persino crittografato.

## UsbKill

Questo strumento **spegne il computer se rileva una modifica alle porte USB**.\
Un modo per individuarlo consiste nell'esaminare i processi in esecuzione e **controllare ogni script Python in esecuzione**.

## Distribuzioni Linux live

Queste distribuzioni vengono **eseguite nella memoria RAM**. L'unico modo per rilevarle è **se il file system NTFS è montato con autorizzazioni di scrittura**. Se è montato solo con autorizzazioni di lettura, non sarà possibile rilevare l'intrusione.

## Cancellazione sicura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Autoeliminazione ritardata in Windows

Un'immagine di Windows in esecuzione può essere bloccata finché il relativo processo è attivo. Un processo può delegare l'eliminazione a un processo figlio `cmd.exe`, usare `choice` come timer e terminare prima che la shell esegua `del`. Il ritardo consente al processo originale di rilasciare il proprio handle sull'immagine; se il percorso completo contiene spazi, è necessario racchiuderlo tra virgolette.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Quando questa stringa viene passata direttamente come argomento a `cmd.exe` invece di essere digitata da un altro prompt interattivo di `cmd`, usa `&` al posto di `^&` e `>nul` al posto di `^>nul`. Questo rimuove la voce della directory; **non è una cancellazione sicura** e non rimuove le tracce di esecuzione, attività, journal del file system o altre tracce forensi. Cerca processi figlio di breve durata `cmd.exe` la cui riga di comando combina `choice /T`, `Del` e il percorso dell'immagine del processo padre.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Configurazione di Windows

È possibile disabilitare diversi metodi di logging di Windows per rendere molto più difficile l'indagine forense.

### Disabilitare i timestamp - UserAssist

Questa chiave del registro memorizza date e ore in cui l'utente ha eseguito ciascun eseguibile.

Per disabilitare UserAssist sono necessari due passaggi:

1. Imposta a zero entrambe le chiavi del registro `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, per indicare che vogliamo disabilitare UserAssist.
2. Elimina i sottoalberi del registro simili a `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disabilitare i timestamp - Prefetch

Questa funzione salva informazioni sulle applicazioni eseguite per migliorare le prestazioni del sistema Windows. Tuttavia, tali informazioni possono essere utili anche nelle indagini forensi.

- Esegui `regedit`
- Seleziona il percorso del file `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Fai clic con il tasto destro del mouse su `EnablePrefetcher` e `EnableSuperfetch`
- Seleziona Modifica per ciascuno e cambia il valore da 1 (o 3) a 0
- Riavvia

### Disabilitare i timestamp - Last Access Time

Ogni volta che una cartella viene aperta da un volume NTFS su un server Windows NT, il sistema aggiorna un campo timestamp in ogni cartella elencata, chiamato ora dell'ultimo accesso. Su un volume NTFS molto utilizzato, questo può influire sulle prestazioni.

1. Apri l'Editor del Registro di sistema (Regedit.exe).
2. Vai a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Cerca `NtfsDisableLastAccessUpdate`. Se non esiste, aggiungi questo DWORD e impostane il valore su 1 per disabilitare il processo.
4. Chiudi l'Editor del Registro di sistema e riavvia il server.

### Eliminare la cronologia USB

Tutte le **voci dei dispositivi USB** sono memorizzate nel Registro di sistema di Windows, nella chiave **USBSTOR**, che contiene sottochiavi create ogni volta che colleghi un dispositivo USB al PC o al laptop. Puoi trovare questa chiave qui: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Eliminandola**, eliminerai la cronologia USB.\
Puoi anche usare lo strumento [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) per verificare di averle eliminate (e per eliminarle).

Un altro file che salva informazioni sulle unità USB è `setupapi.dev.log`, che si trova in `C:\Windows\INF`. Anche questo dovrebbe essere eliminato.

### Disabilitare le Shadow Copies

**Elenca** le Shadow Copies con `vssadmin list shadowstorage`\
**Eliminale** eseguendo `vssadmin delete shadow`

Puoi anche eliminarle tramite GUI seguendo i passaggi indicati in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Per disabilitare le Shadow Copies [segui i passaggi indicati qui](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Apri il programma Servizi digitando "services" nella casella di ricerca del testo dopo aver fatto clic sul pulsante Start di Windows.
2. Nell'elenco, trova "Volume Shadow Copy", selezionalo e fai clic con il tasto destro per accedere a Proprietà.
3. Seleziona Disabilitato dal menu a discesa "Tipo di avvio", quindi conferma la modifica facendo clic su Applica e OK.

È anche possibile modificare nel registro la configurazione dei file da includere nella Shadow Copy: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sovrascrivere i file eliminati

- Puoi usare uno **strumento di Windows**: `cipher /w:C`. In questo modo cipher rimuoverà tutti i dati dallo spazio disponibile non utilizzato sul disco C.
- Puoi anche usare strumenti come [**Eraser**](https://eraser.heidi.ie)

### Eliminare i registri eventi di Windows

- Windows + R --> eventvwr.msc --> Espandi "Registri di Windows" --> Fai clic con il tasto destro su ciascuna categoria e seleziona "Cancella registro"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disabilitare i registri eventi di Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Nella sezione Servizi, disabilita il servizio "Windows Event Log"
- `WEvtUtil.exec clear-log` oppure `WEvtUtil.exe cl`

### Disabilitare $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Logging avanzato e manomissione delle tracce (2023-2025)

### Logging ScriptBlock/Module di PowerShell

Le versioni recenti di Windows 10/11 e Windows Server conservano **ricche tracce forensi di PowerShell** in
`Microsoft-Windows-PowerShell/Operational` (eventi 4104/4105/4106).  
Gli aggressori possono disabilitarle o cancellarle al volo:

```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
                 -Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
                 -Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
  Remove-WinEvent               # requires admin & Win11 23H2+
```

I difensori dovrebbero monitorare le modifiche a quelle chiavi del registro e la rimozione su larga scala degli eventi PowerShell.

### Patch ETW (Event Tracing for Windows)

I prodotti di sicurezza degli endpoint si affidano molto a ETW. Un metodo di evasione molto diffuso nel 2024 consiste nel patchare in memoria `ntdll!EtwEventWrite`/`EtwEventWriteFull`, così che ogni chiamata ETW restituisca `STATUS_SUCCESS` senza generare l’evento:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

PoC pubblici (ad es. `EtwTiSwallow`) implementano la stessa primitiva in PowerShell o C++.  
Poiché la patch è **locale al processo**, gli EDR in esecuzione all'interno di altri processi potrebbero non rilevarla.<sup>[[5]](#references)</sup>
Rilevamento: confrontare `ntdll` in memoria con quello su disco, oppure installare hook prima di entrare in user mode.

### Alternate Data Streams (ADS): rinascita

Nel 2023 sono state osservate campagne malware (ad es. i loader di **FIN12**) che preparavano i binari del secondo stadio all'interno di ADS per tenerli nascosti agli scanner tradizionali:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumera gli stream con `dir /R`, `Get-Item -Stream *` o Sysinternals `streams64.exe`.
La copia del file host su FAT/exFAT o tramite SMB rimuove lo stream nascosto e può essere usata
dagli investigatori per recuperare il payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver viene ormai usato regolarmente per l’**anti-forensics** nelle intrusioni ransomware.  
Lo strumento open-source **AuKill** carica un driver firmato ma vulnerabile (`procexp152.sys`) per
sospendere o terminare EDR e sensori forensi **prima della cifratura e della distruzione dei log**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Il driver viene quindi rimosso, lasciando tracce minime.<sup>[[1]](#references)</sup>  
Mitigazioni: abilitare la blocklist Microsoft dei driver vulnerabili (HVCI/SAC) e generare avvisi in caso di creazione di servizi kernel da percorsi scrivibili dall’utente.

---

## Anti-Forensics su Linux: Self-Patching e C2 cloud (2023–2025)

### Applicare patch autonomamente ai servizi compromessi per ridurre il rilevamento (Linux)
Gli avversari ricorrono sempre più spesso al “self-patching” di un servizio subito dopo averlo sfruttato, sia per impedire un nuovo exploit sia per sopprimere i rilevamenti basati sulle vulnerabilità. L’idea è sostituire i componenti vulnerabili con le versioni upstream legittime più recenti dei file binari/JAR, in modo che gli scanner segnalino l’host come aggiornato, mentre la persistenza e il C2 rimangono attivi.<sup>[[3]](#references)</sup>

Esempio: RCE di Apache ActiveMQ OpenWire (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Dopo lo sfruttamento, gli aggressori hanno scaricato JAR legittimi da Maven Central (repo1.maven.org), eliminato i JAR vulnerabili dall’installazione di ActiveMQ e riavviato il broker.
- In questo modo hanno chiuso la RCE iniziale mantenendo altri foothold (cron, modifiche alla configurazione SSH, impianti C2 separati).

Esempio operativo (illustrativo)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```

Suggerimenti per l'analisi forense e la ricerca di indicatori
- Esaminare le directory dei servizi per individuare sostituzioni non pianificate di binari/JAR:
  - Debian/Ubuntu: `dpkg -V activemq` e confrontare hash/percorso dei file con i mirror dei repository.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Cercare versioni dei JAR presenti su disco ma non gestite dal package manager, oppure link simbolici aggiornati al di fuori delle procedure previste.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` per correlare ctime/mtime con la finestra della compromissione.
- Cronologia della shell/telemetria dei processi: prove di `curl`/`wget` verso `repo1.maven.org` o altri CDN di artefatti subito dopo lo sfruttamento iniziale.
- Gestione delle modifiche: verificare chi ha applicato la “patch” e perché, non solo che sia presente una versione aggiornata.

### C2 tramite servizi cloud con bearer token e stager anti-analisi
Le tecniche osservate combinavano più percorsi C2 a lungo termine e tecniche di packaging anti-analisi:<sup>[[3]](#references)</sup>
- Loader ELF PyInstaller protetti da password per ostacolare il sandboxing e l'analisi statica (ad es. PYZ crittografato, estrazione temporanea in `/_MEI*`).
  - Indicatori: risultati di `strings` come `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefatti runtime: estrazione in `/tmp/_MEI*` o percorsi personalizzati `--runtime-tmpdir`.
- C2 basato su Dropbox con token Bearer OAuth hardcoded
  - Indicatori di rete: `api.dropboxapi.com` / `content.dropboxapi.com` con `Authorization: Bearer <token>`.
  - Cercare nei log di proxy/NetFlow/Zeek/Suricata connessioni HTTPS in uscita verso domini Dropbox da workload server che normalmente non sincronizzano file.
- C2 parallelo/di backup tramite tunneling (ad es. Cloudflare Tunnel `cloudflared`), per mantenere il controllo se un canale viene bloccato.
  - IOC host: processi/unità `cloudflared`, configurazione in `~/.cloudflared/*.json`, connessioni in uscita sulla porta 443 verso gli edge Cloudflare.

### Persistenza e “rollback dell'hardening” per mantenere l'accesso (esempi Linux)
Gli aggressori spesso abbinano l'applicazione di patch a sé stessi a percorsi di accesso persistenti:<sup>[[3]](#references)</sup>
- Cron/Anacron: modifiche allo stub `0anacron` in ogni directory `/etc/cron.*/` per l'esecuzione periodica.
  - Ricerca:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Ripristino delle misure di hardening della configurazione SSH: abilitazione degli accessi root e modifica delle shell predefinite per gli account con privilegi limitati.
  - Cerca l’abilitazione degli accessi root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Cercare shell interattive sospette negli account di sistema (ad es., `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Artefatti beacon casuali con nomi brevi (8 caratteri alfabetici), salvati su disco e che contattano anche un C2 cloud:
  - Ricerca:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

I difensori dovrebbero correlare questi artefatti con l’esposizione esterna e gli eventi di applicazione delle patch ai servizi per individuare attività di auto-remediation anti-forensic usate per nascondere lo sfruttamento iniziale.

## References

- [1] [Sophos X-Ops – AuKill: un driver vulnerabile weaponized per disabilitare EDR (marzo 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Applicare patch a EtwEventWrite per la furtività: rilevamento e threat hunting (giugno 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Applicare patch per la persistenza: come il malware Linux DripDropper si diffonde nel cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE tramite OpenWire di Apache ActiveMQ (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Nascondere il proprio .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Individuazione di una variante di SectopRAT incorporata in software legittimo](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – comando choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – comando del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
