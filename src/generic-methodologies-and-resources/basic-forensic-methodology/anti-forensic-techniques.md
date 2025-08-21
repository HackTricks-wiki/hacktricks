# Tecniche Anti-Forensi

{{#include ../../banners/hacktricks-training.md}}

## Timestamp

Un attaccante potrebbe essere interessato a **cambiare i timestamp dei file** per evitare di essere rilevato.\
È possibile trovare i timestamp all'interno del MFT negli attributi `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Entrambi gli attributi hanno 4 timestamp: **Modifica**, **accesso**, **creazione** e **modifica del registro MFT** (MACE o MACB).

**Esplora file di Windows** e altri strumenti mostrano le informazioni da **`$STANDARD_INFORMATION`**.

### TimeStomp - Strumento Anti-forense

Questo strumento **modifica** le informazioni sui timestamp all'interno di **`$STANDARD_INFORMATION`** **ma** **non** le informazioni all'interno di **`$FILE_NAME`**. Pertanto, è possibile **identificare** **attività** **sospette**.

### Usnjrnl

Il **USN Journal** (Registro del Numero di Sequenza di Aggiornamento) è una funzionalità del NTFS (sistema di file Windows NT) che tiene traccia delle modifiche al volume. Lo strumento [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) consente di esaminare queste modifiche.

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

### SetMace - Strumento Anti-forense

Questo strumento può modificare entrambi gli attributi `$STARNDAR_INFORMATION` e `$FILE_NAME`. Tuttavia, a partire da Windows Vista, è necessario un OS live per modificare queste informazioni.

## Nascondere Dati

NFTS utilizza un cluster e la dimensione minima delle informazioni. Ciò significa che se un file occupa e utilizza un cluster e mezzo, la **metà rimanente non verrà mai utilizzata** fino a quando il file non viene eliminato. Quindi, è possibile **nascondere dati in questo spazio di slack**.

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
2. Cancellare i sottotree di registro che sembrano `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disabilitare Timestamp - Prefetch

Questo salverà informazioni sulle applicazioni eseguite con l'obiettivo di migliorare le prestazioni del sistema Windows. Tuttavia, questo può essere utile anche per pratiche forensi.

- Eseguire `regedit`
- Selezionare il percorso del file `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Fare clic con il tasto destro su `EnablePrefetcher` e `EnableSuperfetch`
- Selezionare Modifica su ciascuno di questi per cambiare il valore da 1 (o 3) a 0
- Riavviare

### Disabilitare Timestamp - Ultimo Tempo di Accesso

Ogni volta che una cartella viene aperta da un volume NTFS su un server Windows NT, il sistema impiega tempo per **aggiornare un campo di timestamp su ciascuna cartella elencata**, chiamato ultimo tempo di accesso. Su un volume NTFS molto utilizzato, questo può influire sulle prestazioni.

1. Aprire l'Editor del Registro (Regedit.exe).
2. Navigare a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Cercare `NtfsDisableLastAccessUpdate`. Se non esiste, aggiungere questo DWORD e impostare il suo valore a 1, il che disabiliterà il processo.
4. Chiudere l'Editor del Registro e riavviare il server.

### Eliminare la Cronologia USB

Tutti i **USB Device Entries** sono memorizzati nel Registro di Windows sotto la chiave di registro **USBSTOR** che contiene sottochiavi create ogni volta che si collega un dispositivo USB al PC o Laptop. Puoi trovare questa chiave qui `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Eliminando questa** eliminerai la cronologia USB.\
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

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- All'interno della sezione servizi disabilitare il servizio "Windows Event Log"
- `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

### Disabilitare $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Logging Avanzato & Manomissione delle Tracce (2023-2025)

### Logging ScriptBlock/Modulo PowerShell

Le versioni recenti di Windows 10/11 e Windows Server mantengono **artifacts forensi PowerShell ricchi** sotto
`Microsoft-Windows-PowerShell/Operational` (eventi 4104/4105/4106).
Gli attaccanti possono disabilitarli o eliminarli al volo:
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

### Patch ETW (Event Tracing for Windows)

I prodotti di sicurezza degli endpoint si basano fortemente su ETW. Un metodo di evasione popolare del 2024 è quello di patchare `ntdll!EtwEventWrite`/`EtwEventWriteFull` in memoria in modo che ogni chiamata ETW restituisca `STATUS_SUCCESS` senza emettere l'evento:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) implementano la stessa primitiva in PowerShell o C++.  
Poiché la patch è **locale al processo**, gli EDR che girano all'interno di altri processi potrebbero non rilevarla.  
Rilevamento: confrontare `ntdll` in memoria rispetto a quello su disco, o hookare prima della modalità utente.

### Ripristino dei Flussi di Dati Alternativi (ADS)

Le campagne malware nel 2023 (e.g. **FIN12** loaders) sono state viste preparare binari di secondo stadio all'interno di ADS per rimanere fuori dalla vista degli scanner tradizionali:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerare i flussi con `dir /R`, `Get-Item -Stream *`, o Sysinternals `streams64.exe`. Copiare il file host su FAT/exFAT o tramite SMB rimuoverà il flusso nascosto e può essere utilizzato dagli investigatori per recuperare il payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver è ora comunemente usato per **anti-forensics** nelle intrusioni ransomware. Lo strumento open-source **AuKill** carica un driver firmato ma vulnerabile (`procexp152.sys`) per sospendere o terminare EDR e sensori forensi **prima della crittografia e della distruzione dei log**:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Il driver viene rimosso successivamente, lasciando artefatti minimi.  
Mitigazioni: abilitare la blocklist dei driver vulnerabili di Microsoft (HVCI/SAC) e segnalare la creazione di servizi del kernel da percorsi scrivibili dall'utente.

---

## Linux Anti-Forensics: Auto-patch e Cloud C2 (2023–2025)

### Auto-patching dei servizi compromessi per ridurre la rilevazione (Linux)  
Gli avversari "auto-patchano" sempre più spesso un servizio subito dopo averlo sfruttato per prevenire ulteriori sfruttamenti e sopprimere le rilevazioni basate su vulnerabilità. L'idea è di sostituire i componenti vulnerabili con gli ultimi binari/JAR legittimi upstream, in modo che gli scanner segnalino l'host come patchato mentre la persistenza e il C2 rimangono.

Esempio: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- Dopo lo sfruttamento, gli attaccanti hanno prelevato JAR legittimi da Maven Central (repo1.maven.org), eliminato i JAR vulnerabili nell'installazione di ActiveMQ e riavviato il broker.  
- Questo ha chiuso il RCE iniziale mantenendo altri punti di accesso (cron, modifiche alla configurazione SSH, impianti C2 separati).

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
Forensic/hunting tips
- Rivedere le directory di servizio per sostituzioni binarie/JAR non programmate:
- Debian/Ubuntu: `dpkg -V activemq` e confrontare gli hash/percorsi dei file con i mirror del repository.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Cercare versioni JAR presenti su disco che non sono di proprietà del gestore di pacchetti, o collegamenti simbolici aggiornati fuori banda.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` per correlare ctime/mtime con la finestra di compromissione.
- Cronologia della shell/telemetria dei processi: prove di `curl`/`wget` a `repo1.maven.org` o altri CDN di artefatti immediatamente dopo l'iniziale sfruttamento.
- Gestione delle modifiche: convalidare chi ha applicato la “patch” e perché, non solo che una versione patchata è presente.

### Cloud‑service C2 con bearer tokens e anti‑analysis stagers
Il tradecraft osservato ha combinato più percorsi C2 a lungo termine e imballaggi anti-analisi:
- Loader ELF PyInstaller protetti da password per ostacolare il sandboxing e l'analisi statica (ad es., PYZ crittografato, estrazione temporanea sotto `/_MEI*`).
- Indicatori: colpi di `strings` come `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefatti di runtime: estrazione in `/tmp/_MEI*` o percorsi personalizzati `--runtime-tmpdir`.
- C2 supportato da Dropbox utilizzando token OAuth Bearer hardcoded
- Marcatori di rete: `api.dropboxapi.com` / `content.dropboxapi.com` con `Authorization: Bearer <token>`.
- Caccia in proxy/NetFlow/Zeek/Suricata per HTTPS in uscita verso domini Dropbox da carichi di lavoro del server che normalmente non sincronizzano file.
- C2 parallelo/di backup tramite tunneling (ad es., Cloudflare Tunnel `cloudflared`), mantenendo il controllo se un canale è bloccato.
- IOCs dell'host: processi/unità `cloudflared`, configurazione in `~/.cloudflared/*.json`, uscita 443 verso gli edge di Cloudflare.

### Persistenza e “rollback di hardening” per mantenere l'accesso (esempi Linux)
Gli attaccanti abbinano frequentemente l'auto-patching con percorsi di accesso durevoli:
- Cron/Anacron: modifiche allo stub `0anacron` in ciascuna directory `/etc/cron.*/` per esecuzione periodica.
- Caccia:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Rollback dell'hardening della configurazione SSH: abilitazione degli accessi root e modifica delle shell predefinite per account a bassa privilegio.
- Caccia per l'abilitazione del login root:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# valori di flag come "yes" o impostazioni eccessivamente permissive
```
- Caccia per shell interattive sospette su account di sistema (ad es., `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artefatti beacon casuali e con nomi brevi (8 caratteri alfabetici) lasciati su disco che contattano anche C2 cloud:
- Caccia:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

I difensori dovrebbero correlare questi artefatti con l'esposizione esterna e gli eventi di patching del servizio per scoprire l'auto-remediazione anti-forense utilizzata per nascondere lo sfruttamento iniziale.

## References

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (March 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (June 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
